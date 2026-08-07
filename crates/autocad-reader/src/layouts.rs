//! Reader-owned layout, paper-space viewport, and plot-setting projections.

use std::io::Cursor;

use acadrust::entities::{EntityType, Viewport, ViewportRenderMode};
use acadrust::io::dwg::dwg_stream_readers::{
    handle_reader::read_handles,
    object_reader::{common::OBJ_LAYOUT, objects::read_layout as read_raw_layout, DwgObjectReader},
};
use acadrust::objects::{
    Layout, ObjectType, PlotPaperUnits as AcadPlotPaperUnits, PlotRotation as AcadPlotRotation,
    PlotSettings, PlotType as AcadPlotType, ScaledType as AcadScaledType,
    ShadePlotMode as AcadShadePlotMode, ShadePlotResolutionLevel as AcadShadePlotResolutionLevel,
};
use acadrust::types::{DxfVersion, Handle};
use acadrust::{CadDocument, DwgReader};

use super::{
    contract::{
        Bounds2, Bounds3, EmbeddedPlotSettingsRecord, LayoutInfo, LayoutRecord, LayoutSelector,
        LayoutUcsRecord, LayoutViewportRecord, LayoutViewportRenderMode,
        LayoutViewportResourceType, PaperMargins, PlotArea, PlotFlagsRecord, PlotPaperUnits,
        PlotRotation, PlotScaleType, PlotSettingRecord, PlotSettingSelector, PlotShadeMode,
        PlotShadeResolution, PlotWindowRecord, Point2, Point3,
    },
    entity_identity::{is_semantic_entity, validate_semantic_entity_handles},
    owners::{resolve_direct_owner, DirectOwnerContext, DirectOwnerType},
    DrawingFormat, DrawingSnapshot,
};

autocad_diagnostics::domain_error!(pub struct LayoutReadError, new = pub(super));

fn require_finite(value: f64, field: &str) -> Result<(), LayoutReadError> {
    if !value.is_finite() {
        return Err(LayoutReadError::new(
            "unsupported_layout_data",
            format!("{field} is not a finite number"),
        ));
    }
    Ok(())
}

fn require_finite_point2(point: Point2, field: &str) -> Result<(), LayoutReadError> {
    require_finite(point.x, &format!("{field}.x"))?;
    require_finite(point.y, &format!("{field}.y"))
}

fn require_finite_point3(point: Point3, field: &str) -> Result<(), LayoutReadError> {
    require_finite(point.x, &format!("{field}.x"))?;
    require_finite(point.y, &format!("{field}.y"))?;
    require_finite(point.z, &format!("{field}.z"))
}

fn require_ordered_bounds2(bounds: Bounds2, field: &str) -> Result<(), LayoutReadError> {
    if bounds.min.x > bounds.max.x || bounds.min.y > bounds.max.y {
        return Err(LayoutReadError::new(
            "unsupported_layout_data",
            format!("{field} contains inverted bounds"),
        ));
    }
    Ok(())
}

fn require_ordered_bounds3(bounds: Bounds3, field: &str) -> Result<(), LayoutReadError> {
    if bounds.min.x > bounds.max.x || bounds.min.y > bounds.max.y || bounds.min.z > bounds.max.z {
        return Err(LayoutReadError::new(
            "unsupported_layout_data",
            format!("{field} contains inverted bounds"),
        ));
    }
    Ok(())
}

fn layout_extents(
    min: (f64, f64, f64),
    max: (f64, f64, f64),
) -> Result<Option<Bounds3>, LayoutReadError> {
    let bounds = Bounds3 {
        min: tuple3(min),
        max: tuple3(max),
    };
    require_finite_point3(bounds.min, "layout extents.min")?;
    require_finite_point3(bounds.max, "layout extents.max")?;

    // AutoCAD uses these exact inverted bounds as the accumulator sentinel for
    // an empty layout. They mean "no extents", not malformed geometry.
    const EMPTY_MIN: Point3 = Point3 {
        x: 1.0e20,
        y: 1.0e20,
        z: 1.0e20,
    };
    const EMPTY_MAX: Point3 = Point3 {
        x: -1.0e20,
        y: -1.0e20,
        z: -1.0e20,
    };
    if bounds.min == EMPTY_MIN && bounds.max == EMPTY_MAX {
        return Ok(None);
    }

    require_ordered_bounds3(bounds, "layout extents")?;
    Ok(Some(bounds))
}

fn checked_positive_ratio(
    numerator: f64,
    denominator: f64,
    numerator_field: &str,
    denominator_field: &str,
    result_field: &str,
    minimum_denominator: f64,
) -> Result<f64, LayoutReadError> {
    require_finite(numerator, numerator_field)?;
    require_finite(denominator, denominator_field)?;
    if numerator <= 0.0 {
        return Err(LayoutReadError::new(
            "unsupported_layout_data",
            format!("{numerator_field} must be greater than zero"),
        ));
    }
    if denominator <= minimum_denominator {
        return Err(LayoutReadError::new(
            "unsupported_layout_data",
            format!("{denominator_field} is too small to derive {result_field}"),
        ));
    }
    let ratio = numerator / denominator;
    require_finite(ratio, result_field)?;
    Ok(ratio)
}

fn checked_optional_nonnegative_ratio(
    numerator: f64,
    denominator: f64,
    numerator_field: &str,
    denominator_field: &str,
    result_field: &str,
) -> Result<Option<f64>, LayoutReadError> {
    require_finite(numerator, numerator_field)?;
    require_finite(denominator, denominator_field)?;
    if numerator < 0.0 {
        return Err(LayoutReadError::new(
            "unsupported_layout_data",
            format!("{numerator_field} must not be negative"),
        ));
    }
    if denominator < 0.0 {
        return Err(LayoutReadError::new(
            "unsupported_layout_data",
            format!("{denominator_field} must not be negative"),
        ));
    }
    if numerator == 0.0 || denominator == 0.0 {
        return Ok(None);
    }
    let ratio = numerator / denominator;
    require_finite(ratio, result_field)?;
    Ok(Some(ratio))
}

fn validate_layout_record(record: &LayoutRecord) -> Result<(), LayoutReadError> {
    require_finite_point2(record.limits.min, "layout limits.min")?;
    require_finite_point2(record.limits.max, "layout limits.max")?;
    require_ordered_bounds2(record.limits, "layout limits")?;
    if let Some(extents) = record.extents {
        require_finite_point3(extents.min, "layout extents.min")?;
        require_finite_point3(extents.max, "layout extents.max")?;
        require_ordered_bounds3(extents, "layout extents")?;
    }
    require_finite_point3(record.insertion_base, "layout insertion_base")?;
    require_finite(record.elevation, "layout elevation")?;
    require_finite_point3(record.ucs.origin, "layout UCS origin")?;
    require_finite_point3(record.ucs.x_axis, "layout UCS x_axis")?;
    require_finite_point3(record.ucs.y_axis, "layout UCS y_axis")?;
    require_finite(
        record.plot_settings.paper_width_mm,
        "layout plot paper_width_mm",
    )?;
    require_finite(
        record.plot_settings.paper_height_mm,
        "layout plot paper_height_mm",
    )
}

fn validate_viewport_record(record: &LayoutViewportRecord) -> Result<(), LayoutReadError> {
    require_finite_point3(record.center, "viewport center")?;
    require_finite(record.width, "viewport width")?;
    require_finite(record.height, "viewport height")?;
    require_finite_point3(record.view_center, "viewport view_center")?;
    require_finite_point3(record.view_target, "viewport view_target")?;
    require_finite_point3(record.view_direction, "viewport view_direction")?;
    require_finite(record.view_height, "viewport view_height")?;
    require_finite(record.twist_angle_radians, "viewport twist_angle_radians")?;
    require_finite(record.lens_length_mm, "viewport lens_length_mm")?;
    if let Some(scale) = record.model_to_paper_scale {
        require_finite(scale, "viewport model_to_paper_scale")?;
    }
    if let Some(scale) = record.custom_scale {
        require_finite(scale, "viewport custom_scale")?;
    }
    Ok(())
}

fn validate_plot_setting_record(record: &PlotSettingRecord) -> Result<(), LayoutReadError> {
    require_finite(record.paper_width, "plot setting paper_width")?;
    require_finite(record.paper_height, "plot setting paper_height")?;
    require_finite(record.margins.left, "plot setting margin left")?;
    require_finite(record.margins.bottom, "plot setting margin bottom")?;
    require_finite(record.margins.right, "plot setting margin right")?;
    require_finite(record.margins.top, "plot setting margin top")?;
    require_finite_point2(record.origin, "plot setting origin")?;
    require_finite_point2(record.window.lower_left, "plot setting window lower_left")?;
    require_finite_point2(record.window.upper_right, "plot setting window upper_right")?;
    require_finite(record.scale_numerator, "plot setting scale_numerator")?;
    require_finite(record.scale_denominator, "plot setting scale_denominator")?;
    require_finite(record.scale_factor, "plot setting scale_factor")
}

fn name_key(name: &str) -> String {
    name.to_uppercase()
}

fn canonical_handle(
    handle: Handle,
    code: &'static str,
    description: &'static str,
) -> Result<String, LayoutReadError> {
    if !handle.is_valid() {
        return Err(LayoutReadError::new(
            code,
            format!("{description} has invalid handle 0"),
        ));
    }
    Ok(format!("{:X}", handle.value()))
}

fn canonical_optional_handle(handle: Handle) -> Option<String> {
    handle.is_valid().then(|| format!("{:X}", handle.value()))
}

fn parse_handle(
    input: &str,
    code: &'static str,
    description: &'static str,
) -> Result<Handle, LayoutReadError> {
    let trimmed = input.trim();
    if trimmed != input {
        return Err(LayoutReadError::new(
            code,
            format!("{description} handle must not contain surrounding whitespace"),
        ));
    }
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if without_prefix.is_empty() {
        return Err(LayoutReadError::new(
            code,
            format!("{description} handle is empty"),
        ));
    }
    let value = u64::from_str_radix(without_prefix, 16).map_err(|_| {
        LayoutReadError::new(code, format!("invalid {description} handle `{input}`"))
    })?;
    let handle = Handle::new(value);
    if !handle.is_valid() {
        return Err(LayoutReadError::new(
            code,
            format!("{description} handle 0 is invalid"),
        ));
    }
    Ok(handle)
}

fn legacy_is_model_layout(doc: &CadDocument, layout: &Layout) -> bool {
    let model_space_block = doc.header.model_space_block_handle;
    model_space_block.is_valid() && layout.block_record == model_space_block
}

fn expanded_layout_owner_type(
    doc: &CadDocument,
    layout: &Layout,
) -> Result<DirectOwnerType, LayoutReadError> {
    let owner_type = match resolve_direct_owner(doc, layout.block_record)
        .map_err(|error| LayoutReadError::new("unsupported_layout_data", error.message()))?
    {
        Some(DirectOwnerContext::Available {
            owner_type: DirectOwnerType::ModelSpace,
            ..
        }) => DirectOwnerType::ModelSpace,
        Some(DirectOwnerContext::Available {
            owner_type: DirectOwnerType::PaperSpace,
            ..
        }) => DirectOwnerType::PaperSpace,
        context => {
            return Err(LayoutReadError::new(
                "unsupported_layout_data",
                format!(
                    "layout `{}` has no coherent model/paper owner context: {context:?}",
                    layout.name
                ),
            ))
        }
    };

    let header_model = doc.header.model_space_block_handle;
    if header_model.is_valid()
        && ((owner_type == DirectOwnerType::ModelSpace && header_model != layout.block_record)
            || (owner_type == DirectOwnerType::PaperSpace && header_model == layout.block_record))
    {
        return Err(LayoutReadError::new(
            "unsupported_layout_data",
            format!(
                "layout `{}` owner {:X} contradicts header model-space handle {:X}",
                layout.name,
                layout.block_record.value(),
                header_model.value()
            ),
        ));
    }

    Ok(owner_type)
}

fn tuple2(value: (f64, f64)) -> Point2 {
    Point2 {
        x: value.0,
        y: value.1,
    }
}

fn tuple3(value: (f64, f64, f64)) -> Point3 {
    Point3 {
        x: value.0,
        y: value.1,
        z: value.2,
    }
}

fn vector3(value: acadrust::types::Vector3) -> Point3 {
    Point3 {
        x: value.x,
        y: value.y,
        z: value.z,
    }
}

fn embedded_rotation_degrees(rotation_code: i16) -> Option<i16> {
    match rotation_code {
        0 => Some(0),
        1 => Some(90),
        2 => Some(180),
        3 => Some(270),
        _ => None,
    }
}

const KNOWN_PLOT_FLAG_BITS: i32 = 0x7EFF;

fn plot_flags_from_bits(bits: i32) -> Result<PlotFlagsRecord, LayoutReadError> {
    if bits & !KNOWN_PLOT_FLAG_BITS != 0 {
        return Err(LayoutReadError::new(
            "embedded_plot_flags_unsupported",
            "the embedded plot flags contain unknown or reserved bits",
        ));
    }
    let flags = acadrust::objects::PlotFlags::from_bits(bits);
    Ok(PlotFlagsRecord {
        plot_viewport_borders: flags.plot_viewport_borders,
        show_plot_styles: flags.show_plot_styles,
        plot_centered: flags.plot_centered,
        plot_hidden: flags.plot_hidden,
        use_standard_scale: flags.use_standard_scale,
        plot_plot_styles: flags.plot_plot_styles,
        scale_lineweights: flags.scale_lineweights,
        print_lineweights: flags.print_lineweights,
        draw_viewports_first: flags.draw_viewports_first,
        model_type: flags.model_type,
        update_paper: flags.update_paper,
        zoom_to_paper_on_update: flags.zoom_to_paper_on_update,
        initializing: flags.initializing,
        previous_plot_initialized: flags.prev_plot_init,
    })
}

fn raw_dwg_layout_plot_flags(
    snapshot: &DrawingSnapshot,
    layout: &Layout,
) -> Result<PlotFlagsRecord, LayoutReadError> {
    let bytes = snapshot.bytes();
    let mut reader = DwgReader::from_stream(Cursor::new(bytes));
    let info = reader.read_file_header().map_err(|error| {
        LayoutReadError::new(
            "embedded_plot_flags_unavailable",
            format!("failed to read the DWG section map: {error}"),
        )
    })?;
    let dxf_version = DxfVersion::parse(&info.version_string).ok_or_else(|| {
        LayoutReadError::new(
            "embedded_plot_flags_unavailable",
            "the DWG version cannot be mapped to an object-stream version",
        )
    })?;
    let handles = reader
        .get_section_buffer("AcDb:Handles", &info)
        .and_then(|bytes| read_handles(&bytes))
        .map_err(|error| {
            LayoutReadError::new(
                "embedded_plot_flags_unavailable",
                format!("failed to read the DWG handle map: {error}"),
            )
        })?;
    let mut handles = handles;
    if info.objects_base_offset != 0 {
        for offset in handles.values_mut() {
            *offset = offset
                .checked_sub(info.objects_base_offset)
                .ok_or_else(|| {
                    LayoutReadError::new(
                        "embedded_plot_flags_unavailable",
                        "a DWG handle-map offset precedes the object-section base",
                    )
                })?;
        }
    }
    let objects = reader
        .get_section_buffer("AcDb:AcDbObjects", &info)
        .map_err(|error| {
            LayoutReadError::new(
                "embedded_plot_flags_unavailable",
                format!("failed to read the DWG object section: {error}"),
            )
        })?;
    let object_reader = DwgObjectReader::new(objects, dxf_version, handles).map_err(|error| {
        LayoutReadError::new(
            "embedded_plot_flags_unavailable",
            format!("failed to initialise the DWG object reader: {error}"),
        )
    })?;
    let offset = object_reader
        .offset_for(layout.handle.value())
        .filter(|offset| *offset >= 0)
        .ok_or_else(|| {
            LayoutReadError::new(
                "embedded_plot_flags_unavailable",
                "the selected layout handle is absent from the DWG handle map",
            )
        })?;
    let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (type_code, mut merged) = object_reader.read_record_at(offset as usize)?;
        if type_code != OBJ_LAYOUT {
            return Err(acadrust::DxfError::Parse(format!(
                "selected layout handle has DWG object type {type_code}, expected {OBJ_LAYOUT}"
            )));
        }
        let common = object_reader.read_common_non_entity_data(&mut merged, type_code);
        let raw = read_raw_layout(&mut merged, object_reader.version());
        Ok::<_, acadrust::DxfError>((common.common.handle, raw))
    }))
    .map_err(|_| {
        LayoutReadError::new(
            "embedded_plot_flags_unavailable",
            "the low-level reader panicked while decoding the selected layout",
        )
    })?
    .map_err(|error| {
        LayoutReadError::new(
            "embedded_plot_flags_unavailable",
            format!("failed to decode the selected layout object: {error}"),
        )
    })?;
    let (raw_handle, raw) = parsed;
    if raw_handle != layout.handle.value() || raw.name != layout.name {
        return Err(LayoutReadError::new(
            "embedded_plot_flags_contradictory",
            "the low-level layout identity contradicts the selected semantic layout",
        ));
    }
    if raw.plot_settings.paper_width != layout.paper_width
        || raw.plot_settings.paper_height != layout.paper_height
        || raw.plot_settings.rotation != layout.plot_rotation
    {
        return Err(LayoutReadError::new(
            "embedded_plot_settings_contradictory",
            "the low-level layout paper geometry contradicts the semantic layout",
        ));
    }
    plot_flags_from_bits(i32::from(raw.plot_settings.plot_flags))
}

pub(super) fn get_embedded_layout_plot_flags(
    doc: &CadDocument,
    snapshot: &DrawingSnapshot,
    selector: &LayoutSelector,
) -> Result<PlotFlagsRecord, LayoutReadError> {
    let layout = resolve_layout(doc, selector)?;
    match snapshot.format() {
        DrawingFormat::Dwg => raw_dwg_layout_plot_flags(snapshot, layout),
        DrawingFormat::Dxf => {
            let codes = layout.raw_plot_settings_codes.as_ref().ok_or_else(|| {
                LayoutReadError::new(
                    "embedded_plot_flags_unavailable",
                    "the DXF layout does not retain embedded plot-setting codes",
                )
            })?;
            let values = codes
                .iter()
                .filter(|(code, _)| *code == 70)
                .map(|(_, value)| value.parse::<i32>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| {
                    LayoutReadError::new(
                        "embedded_plot_flags_unavailable",
                        "the DXF embedded plot flags are not a valid integer",
                    )
                })?;
            let [bits] = values.as_slice() else {
                return Err(LayoutReadError::new(
                    "embedded_plot_flags_unavailable",
                    "the DXF layout does not contain exactly one embedded plot-flags value",
                ));
            };
            plot_flags_from_bits(*bits)
        }
    }
}

fn layout_record(doc: &CadDocument, layout: &Layout) -> Result<LayoutRecord, LayoutReadError> {
    let is_model = expanded_layout_owner_type(doc, layout)? == DirectOwnerType::ModelSpace;
    let record = LayoutRecord {
        handle: canonical_handle(layout.handle, "invalid_layout_handle", "layout object")?,
        name: layout.name.clone(),
        is_model,
        tab_order: layout.tab_order,
        block_record_handle: canonical_optional_handle(layout.block_record),
        last_active_viewport_handle: canonical_optional_handle(layout.viewport),
        limits: Bounds2 {
            min: tuple2(layout.min_limits),
            max: tuple2(layout.max_limits),
        },
        extents: layout_extents(layout.min_extents, layout.max_extents)?,
        insertion_base: tuple3(layout.insertion_base),
        elevation: layout.elevation,
        ucs: LayoutUcsRecord {
            origin: tuple3(layout.ucs_origin),
            x_axis: tuple3(layout.ucs_x_axis),
            y_axis: tuple3(layout.ucs_y_axis),
            orthographic_type: layout.ucs_ortho_type,
        },
        plot_settings: EmbeddedPlotSettingsRecord {
            paper_width_mm: layout.paper_width,
            paper_height_mm: layout.paper_height,
            rotation_code: layout.plot_rotation,
            rotation_degrees: embedded_rotation_degrees(layout.plot_rotation),
        },
    };
    validate_layout_record(&record)?;
    Ok(record)
}

fn validate_selector_name<'a>(
    name: Option<&'a String>,
    resource: &'static str,
    code: &'static str,
) -> Result<Option<&'a str>, LayoutReadError> {
    match name {
        Some(name) if name.trim().is_empty() => Err(LayoutReadError::new(
            code,
            format!("{resource} name must not be empty"),
        )),
        Some(name) if name.trim() != name => Err(LayoutReadError::new(
            code,
            format!("{resource} name must not contain surrounding whitespace"),
        )),
        Some(name) => Ok(Some(name)),
        None => Ok(None),
    }
}

fn resolve_layout<'a>(
    doc: &'a CadDocument,
    selector: &LayoutSelector,
) -> Result<&'a Layout, LayoutReadError> {
    let requested_handle = selector
        .handle
        .as_deref()
        .map(|handle| parse_handle(handle, "invalid_layout_handle", "layout"))
        .transpose()?;
    let requested_name =
        validate_selector_name(selector.name.as_ref(), "layout", "invalid_layout_name")?;

    if requested_handle.is_none() && requested_name.is_none() {
        return Err(LayoutReadError::new(
            "missing_layout_identity",
            "provide a layout handle or name",
        ));
    }

    if let Some(handle) = requested_handle {
        let mut matches = doc.objects.values().filter_map(|object| match object {
            ObjectType::Layout(layout) if layout.handle == handle => Some(layout),
            _ => None,
        });
        let layout = matches.next().ok_or_else(|| {
            LayoutReadError::new(
                "layout_not_found",
                format!("layout handle {:X} was not found", handle.value()),
            )
        })?;
        if matches.next().is_some() {
            return Err(LayoutReadError::new(
                "ambiguous_layout_handle",
                format!("more than one layout uses handle {:X}", handle.value()),
            ));
        }
        if let Some(name) = requested_name {
            if name_key(&layout.name) != name_key(name) {
                return Err(LayoutReadError::new(
                    "layout_identity_mismatch",
                    format!(
                        "layout handle {:X} is named `{}`, not `{name}`",
                        handle.value(),
                        layout.name
                    ),
                ));
            }
        }
        return Ok(layout);
    }

    let requested_name = requested_name.expect("validated selector has a name");
    let mut matches = doc.objects.values().filter_map(|object| match object {
        ObjectType::Layout(layout) if name_key(&layout.name) == name_key(requested_name) => {
            Some(layout)
        }
        _ => None,
    });
    let first = matches.next().ok_or_else(|| {
        LayoutReadError::new(
            "layout_not_found",
            format!("layout `{requested_name}` was not found"),
        )
    })?;
    if matches.next().is_some() {
        return Err(LayoutReadError::new(
            "ambiguous_layout_name",
            format!("more than one layout is named `{requested_name}`; use a handle"),
        ));
    }
    if doc
        .objects
        .values()
        .filter_map(|object| match object {
            ObjectType::Layout(layout) if layout.handle == first.handle => Some(layout),
            _ => None,
        })
        .nth(1)
        .is_some()
    {
        return Err(LayoutReadError::new(
            "ambiguous_layout_handle",
            format!(
                "more than one layout uses handle {:X}",
                first.handle.value()
            ),
        ));
    }
    Ok(first)
}

pub(super) fn get_layout(
    doc: &CadDocument,
    selector: &LayoutSelector,
) -> Result<LayoutRecord, LayoutReadError> {
    layout_record(doc, resolve_layout(doc, selector)?)
}

pub(super) fn list_layouts(doc: &CadDocument) -> Vec<LayoutInfo> {
    let mut layouts: Vec<LayoutInfo> = doc
        .objects
        .values()
        .filter_map(|obj| match obj {
            ObjectType::Layout(layout) => Some(LayoutInfo {
                name: layout.name.clone(),
                // Layout flags store current-layout PSLTSCALE/LIMCHECK state,
                // not model/paper-space identity. The backing block record is
                // the format-independent authority for that distinction.
                is_model: legacy_is_model_layout(doc, layout),
                tab_order: layout.tab_order,
                paper_width_mm: layout.paper_width,
                paper_height_mm: layout.paper_height,
            }),
            _ => None,
        })
        .collect();
    layouts.sort_by_key(|layout| layout.tab_order);
    layouts
}

fn paper_layout_for_owner(
    doc: &CadDocument,
    owner: Handle,
) -> Result<Option<&Layout>, LayoutReadError> {
    let mut layouts = Vec::new();
    for object in doc.objects.values() {
        if let ObjectType::Layout(layout) = object {
            if layout.block_record == owner
                && expanded_layout_owner_type(doc, layout)? == DirectOwnerType::PaperSpace
            {
                layouts.push(layout);
            }
        }
    }
    let first = layouts.first().copied();
    if layouts.len() > 1 {
        return Err(LayoutReadError::new(
            "ambiguous_viewport_layout",
            format!(
                "more than one paper-space layout uses block record {:X}",
                owner.value()
            ),
        ));
    }
    Ok(first)
}

fn viewport_render_mode(mode: ViewportRenderMode) -> LayoutViewportRenderMode {
    match mode {
        ViewportRenderMode::Wireframe2D => LayoutViewportRenderMode::Wireframe2d,
        ViewportRenderMode::Wireframe3D => LayoutViewportRenderMode::Wireframe3d,
        ViewportRenderMode::HiddenLine => LayoutViewportRenderMode::HiddenLine,
        ViewportRenderMode::FlatShaded => LayoutViewportRenderMode::FlatShaded,
        ViewportRenderMode::GouraudShaded => LayoutViewportRenderMode::GouraudShaded,
        ViewportRenderMode::FlatShadedWithEdges => LayoutViewportRenderMode::FlatShadedWithEdges,
        ViewportRenderMode::GouraudShadedWithEdges => {
            LayoutViewportRenderMode::GouraudShadedWithEdges
        }
    }
}

fn layout_viewport_record(
    layout: &Layout,
    viewport: &Viewport,
) -> Result<LayoutViewportRecord, LayoutReadError> {
    let handle = viewport.common.handle;
    let mut frozen_layers = viewport
        .frozen_layers
        .iter()
        .copied()
        .filter(Handle::is_valid)
        .collect::<Vec<_>>();
    frozen_layers.sort_by_key(Handle::value);
    frozen_layers.dedup();
    let model_to_paper_scale = checked_optional_nonnegative_ratio(
        viewport.height,
        viewport.view_height,
        "viewport height",
        "viewport view_height",
        "viewport model_to_paper_scale",
    )?;

    let record = LayoutViewportRecord {
        resource_type: LayoutViewportResourceType::PaperSpaceEntity,
        handle: canonical_handle(
            handle,
            "invalid_layout_viewport_handle",
            "paper-space viewport entity",
        )?,
        layout_handle: canonical_handle(layout.handle, "invalid_layout_handle", "layout object")?,
        layout_name: layout.name.clone(),
        owner_block_record_handle: canonical_handle(
            viewport.common.owner_handle,
            "invalid_layout_viewport_owner",
            "paper-space viewport owner block record",
        )?,
        is_last_active_for_layout: layout.viewport.is_valid() && layout.viewport == handle,
        viewport_id: viewport.id,
        layer: viewport.common.layer.clone(),
        center: vector3(viewport.center),
        width: viewport.width,
        height: viewport.height,
        // acadrust 0.4.1 retains the viewport on/off bit, but exposing it would
        // change the established public DTO and JSON. Preserve `None` until
        // that public change is qualified separately.
        is_on: None,
        perspective: viewport.status.perspective,
        front_clipping: viewport.status.front_clipping,
        back_clipping: viewport.status.back_clipping,
        locked: viewport.status.locked,
        view_center: vector3(viewport.view_center),
        view_target: vector3(viewport.view_target),
        view_direction: vector3(viewport.view_direction),
        view_height: viewport.view_height,
        twist_angle_radians: viewport.twist_angle,
        lens_length_mm: viewport.lens_length,
        model_to_paper_scale,
        // acadrust initializes this field but does not read it from DWG/DXF.
        custom_scale: None,
        render_mode: viewport_render_mode(viewport.render_mode),
        frozen_layer_handles: frozen_layers
            .into_iter()
            .map(|handle| format!("{:X}", handle.value()))
            .collect(),
    };
    validate_viewport_record(&record)?;
    Ok(record)
}

fn validate_viewport_handles(doc: &CadDocument) -> Result<(), LayoutReadError> {
    validate_semantic_entity_handles(doc)
        .map_err(|error| LayoutReadError::new(error.code().to_string(), error.message()))?;
    let mut handles = doc
        .entities()
        .filter_map(|entity| match entity {
            EntityType::Viewport(viewport) => Some(viewport.common.handle),
            _ => None,
        })
        .collect::<Vec<_>>();
    if handles.iter().any(|handle| !handle.is_valid()) {
        return Err(LayoutReadError::new(
            "invalid_layout_viewport_handle",
            "drawing contains a viewport entity with invalid handle 0",
        ));
    }
    handles.sort_by_key(Handle::value);
    if handles.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(LayoutReadError::new(
            "ambiguous_layout_viewport_handle",
            "more than one viewport entity uses the same handle",
        ));
    }
    Ok(())
}

pub(super) fn list_layout_viewports(
    doc: &CadDocument,
    layout_selector: Option<&LayoutSelector>,
) -> Result<Vec<LayoutViewportRecord>, LayoutReadError> {
    validate_viewport_handles(doc)?;
    let selected_layout = layout_selector
        .map(|selector| resolve_layout(doc, selector))
        .transpose()?;
    if let Some(layout) = selected_layout {
        expanded_layout_owner_type(doc, layout)?;
    }
    let selected_handle = selected_layout.map(|layout| layout.handle);

    let mut viewports = Vec::new();
    for entity in doc.entities() {
        let EntityType::Viewport(viewport) = entity else {
            continue;
        };
        let Some(layout) = paper_layout_for_owner(doc, viewport.common.owner_handle)? else {
            continue;
        };
        if selected_handle.is_some_and(|handle| layout.handle != handle) {
            continue;
        }
        viewports.push(layout_viewport_record(layout, viewport)?);
    }
    viewports.sort_by(|left, right| {
        let left_handle =
            u64::from_str_radix(&left.handle, 16).expect("canonical viewport handle is hex");
        let right_handle =
            u64::from_str_radix(&right.handle, 16).expect("canonical viewport handle is hex");
        left_handle.cmp(&right_handle)
    });
    if viewports
        .windows(2)
        .any(|pair| pair[0].handle == pair[1].handle)
    {
        return Err(LayoutReadError::new(
            "ambiguous_layout_viewport_handle",
            "more than one paper-space viewport uses the same handle",
        ));
    }
    Ok(viewports)
}

pub(super) fn get_layout_viewport(
    doc: &CadDocument,
    handle: &str,
) -> Result<LayoutViewportRecord, LayoutReadError> {
    let handle = parse_handle(
        handle,
        "invalid_layout_viewport_handle",
        "paper-space viewport",
    )?;
    let mut target_occurrences = doc
        .entities()
        .filter(|entity| is_semantic_entity(entity) && entity.common().handle == handle)
        .count();
    for entity in doc.entities() {
        if let EntityType::Insert(insert) = entity {
            target_occurrences += insert
                .attributes
                .iter()
                .filter(|attribute| attribute.common.handle == handle)
                .count();
        }
    }
    if target_occurrences > 1 {
        return Err(LayoutReadError::new(
            "duplicate_entity_handle",
            format!(
                "multiple public entities or attached attributes use handle {:X}",
                handle.value()
            ),
        ));
    }
    let matches = doc
        .entities()
        .filter_map(|entity| match entity {
            EntityType::Viewport(viewport) if viewport.common.handle == handle => Some(viewport),
            _ => None,
        })
        .collect::<Vec<_>>();
    let viewport = match matches.as_slice() {
        [] => {
            return Err(LayoutReadError::new(
                "layout_viewport_not_found",
                format!(
                    "paper-space viewport entity {:X} was not found",
                    handle.value()
                ),
            ))
        }
        [viewport] => *viewport,
        _ => {
            return Err(LayoutReadError::new(
                "ambiguous_layout_viewport_handle",
                format!(
                    "more than one paper-space viewport uses handle {:X}",
                    handle.value()
                ),
            ))
        }
    };
    let layout = paper_layout_for_owner(doc, viewport.common.owner_handle)?.ok_or_else(|| {
        LayoutReadError::new(
            "layout_viewport_not_owned_by_layout",
            format!(
                "viewport entity {:X} is not owned by a paper-space layout",
                handle.value()
            ),
        )
    })?;
    layout_viewport_record(layout, viewport)
}

fn plot_paper_units(units: AcadPlotPaperUnits) -> PlotPaperUnits {
    match units {
        AcadPlotPaperUnits::Inches => PlotPaperUnits::Inches,
        AcadPlotPaperUnits::Millimeters => PlotPaperUnits::Millimeters,
        AcadPlotPaperUnits::Pixels => PlotPaperUnits::Pixels,
    }
}

fn plot_rotation(rotation: AcadPlotRotation) -> PlotRotation {
    match rotation {
        AcadPlotRotation::None => PlotRotation::None,
        AcadPlotRotation::Degrees90 => PlotRotation::Degrees90,
        AcadPlotRotation::Degrees180 => PlotRotation::Degrees180,
        AcadPlotRotation::Degrees270 => PlotRotation::Degrees270,
    }
}

fn plot_area(plot_type: AcadPlotType) -> PlotArea {
    match plot_type {
        AcadPlotType::LastScreenDisplay => PlotArea::LastScreenDisplay,
        AcadPlotType::Extents => PlotArea::Extents,
        AcadPlotType::Limits => PlotArea::Limits,
        AcadPlotType::View => PlotArea::View,
        AcadPlotType::Window => PlotArea::Window,
        AcadPlotType::Layout => PlotArea::Layout,
    }
}

fn plot_scale_type(scale: AcadScaledType) -> PlotScaleType {
    match scale {
        AcadScaledType::ScaleToFit => PlotScaleType::ScaleToFit,
        AcadScaledType::CustomScale => PlotScaleType::CustomScale,
        AcadScaledType::OneToOne => PlotScaleType::OneToOne,
        AcadScaledType::OneToTwo => PlotScaleType::OneToTwo,
        AcadScaledType::OneToFour => PlotScaleType::OneToFour,
        AcadScaledType::OneToEight => PlotScaleType::OneToEight,
        AcadScaledType::OneToTen => PlotScaleType::OneToTen,
        AcadScaledType::OneToSixteen => PlotScaleType::OneToSixteen,
        AcadScaledType::OneToTwenty => PlotScaleType::OneToTwenty,
        AcadScaledType::OneToThirty => PlotScaleType::OneToThirty,
        AcadScaledType::OneToForty => PlotScaleType::OneToForty,
        AcadScaledType::OneToFifty => PlotScaleType::OneToFifty,
        AcadScaledType::OneToHundred => PlotScaleType::OneToHundred,
        AcadScaledType::TwoToOne => PlotScaleType::TwoToOne,
        AcadScaledType::FourToOne => PlotScaleType::FourToOne,
        AcadScaledType::EightToOne => PlotScaleType::EightToOne,
        AcadScaledType::TenToOne => PlotScaleType::TenToOne,
        AcadScaledType::HundredToOne => PlotScaleType::HundredToOne,
    }
}

fn plot_shade_mode(mode: AcadShadePlotMode) -> PlotShadeMode {
    match mode {
        AcadShadePlotMode::AsDisplayed => PlotShadeMode::AsDisplayed,
        AcadShadePlotMode::Wireframe => PlotShadeMode::Wireframe,
        AcadShadePlotMode::Hidden => PlotShadeMode::Hidden,
        AcadShadePlotMode::Rendered => PlotShadeMode::Rendered,
    }
}

fn plot_shade_resolution(resolution: AcadShadePlotResolutionLevel) -> PlotShadeResolution {
    match resolution {
        AcadShadePlotResolutionLevel::Draft => PlotShadeResolution::Draft,
        AcadShadePlotResolutionLevel::Preview => PlotShadeResolution::Preview,
        AcadShadePlotResolutionLevel::Normal => PlotShadeResolution::Normal,
        AcadShadePlotResolutionLevel::Presentation => PlotShadeResolution::Presentation,
        AcadShadePlotResolutionLevel::Maximum => PlotShadeResolution::Maximum,
        AcadShadePlotResolutionLevel::Custom => PlotShadeResolution::Custom,
    }
}

fn plot_setting_record(settings: &PlotSettings) -> Result<PlotSettingRecord, LayoutReadError> {
    let scale_factor = checked_positive_ratio(
        settings.scale_numerator,
        settings.scale_denominator,
        "plot setting scale_numerator",
        "plot setting scale_denominator",
        "plot setting scale_factor",
        0.0,
    )?;
    let record = PlotSettingRecord {
        handle: canonical_handle(
            settings.handle,
            "invalid_plot_setting_handle",
            "plot setting object",
        )?,
        owner_handle: canonical_optional_handle(settings.owner),
        name: settings.page_name.clone(),
        printer_name: settings.printer_name.clone(),
        paper_size: settings.paper_size.clone(),
        plot_view_name: settings.plot_view_name.clone(),
        style_sheet: settings.current_style_sheet.clone(),
        paper_width: settings.paper_width,
        paper_height: settings.paper_height,
        margins: PaperMargins {
            left: settings.margins.left,
            bottom: settings.margins.bottom,
            right: settings.margins.right,
            top: settings.margins.top,
        },
        origin: Point2 {
            x: settings.origin_x,
            y: settings.origin_y,
        },
        window: PlotWindowRecord {
            lower_left: Point2 {
                x: settings.plot_window.lower_left_x,
                y: settings.plot_window.lower_left_y,
            },
            upper_right: Point2 {
                x: settings.plot_window.upper_right_x,
                y: settings.plot_window.upper_right_y,
            },
        },
        scale_numerator: settings.scale_numerator,
        scale_denominator: settings.scale_denominator,
        scale_factor,
        paper_units: plot_paper_units(settings.paper_units),
        rotation: plot_rotation(settings.rotation),
        plot_area: plot_area(settings.plot_type),
        scale_type: plot_scale_type(settings.scale_type),
        shade_mode: plot_shade_mode(settings.shade_plot_mode),
        shade_resolution: plot_shade_resolution(settings.shade_plot_resolution),
        shade_dpi: settings.shade_plot_dpi,
        flags: PlotFlagsRecord {
            plot_viewport_borders: settings.flags.plot_viewport_borders,
            show_plot_styles: settings.flags.show_plot_styles,
            plot_centered: settings.flags.plot_centered,
            plot_hidden: settings.flags.plot_hidden,
            use_standard_scale: settings.flags.use_standard_scale,
            plot_plot_styles: settings.flags.plot_plot_styles,
            scale_lineweights: settings.flags.scale_lineweights,
            print_lineweights: settings.flags.print_lineweights,
            draw_viewports_first: settings.flags.draw_viewports_first,
            model_type: settings.flags.model_type,
            update_paper: settings.flags.update_paper,
            zoom_to_paper_on_update: settings.flags.zoom_to_paper_on_update,
            initializing: settings.flags.initializing,
            previous_plot_initialized: settings.flags.prev_plot_init,
        },
    };
    validate_plot_setting_record(&record)?;
    Ok(record)
}

pub(super) fn list_plot_settings(
    doc: &CadDocument,
) -> Result<Vec<PlotSettingRecord>, LayoutReadError> {
    let mut records = doc
        .objects
        .values()
        .filter_map(|object| match object {
            ObjectType::PlotSettings(settings) => Some(plot_setting_record(settings)),
            _ => None,
        })
        .collect::<Result<Vec<_>, _>>()?;
    records.sort_by(|left, right| {
        let left_handle = u64::from_str_radix(&left.handle, 16).expect("canonical handle is hex");
        let right_handle = u64::from_str_radix(&right.handle, 16).expect("canonical handle is hex");
        left_handle.cmp(&right_handle)
    });
    if records
        .windows(2)
        .any(|pair| pair[0].handle == pair[1].handle)
    {
        return Err(LayoutReadError::new(
            "ambiguous_plot_setting_handle",
            "more than one plot setting uses the same handle",
        ));
    }
    Ok(records)
}

fn resolve_plot_setting<'a>(
    doc: &'a CadDocument,
    selector: &PlotSettingSelector,
) -> Result<&'a PlotSettings, LayoutReadError> {
    let requested_handle = selector
        .handle
        .as_deref()
        .map(|handle| parse_handle(handle, "invalid_plot_setting_handle", "plot setting"))
        .transpose()?;
    let requested_name = validate_selector_name(
        selector.name.as_ref(),
        "plot setting",
        "invalid_plot_setting_name",
    )?;

    if requested_handle.is_none() && requested_name.is_none() {
        return Err(LayoutReadError::new(
            "missing_plot_setting_identity",
            "provide a plot setting handle or name",
        ));
    }

    if let Some(handle) = requested_handle {
        let mut matches = doc.objects.values().filter_map(|object| match object {
            ObjectType::PlotSettings(settings) if settings.handle == handle => Some(settings),
            _ => None,
        });
        let settings = matches.next().ok_or_else(|| {
            LayoutReadError::new(
                "plot_setting_not_found",
                format!("plot setting handle {:X} was not found", handle.value()),
            )
        })?;
        if matches.next().is_some() {
            return Err(LayoutReadError::new(
                "ambiguous_plot_setting_handle",
                format!(
                    "more than one plot setting uses handle {:X}",
                    handle.value()
                ),
            ));
        }
        if let Some(name) = requested_name {
            if name_key(&settings.page_name) != name_key(name) {
                return Err(LayoutReadError::new(
                    "plot_setting_identity_mismatch",
                    format!(
                        "plot setting handle {:X} is named `{}`, not `{name}`",
                        handle.value(),
                        settings.page_name
                    ),
                ));
            }
        }
        return Ok(settings);
    }

    let requested_name = requested_name.expect("validated selector has a name");
    let mut matches = doc.objects.values().filter_map(|object| match object {
        ObjectType::PlotSettings(settings)
            if name_key(&settings.page_name) == name_key(requested_name) =>
        {
            Some(settings)
        }
        _ => None,
    });
    let first = matches.next().ok_or_else(|| {
        LayoutReadError::new(
            "plot_setting_not_found",
            format!("plot setting `{requested_name}` was not found"),
        )
    })?;
    if matches.next().is_some() {
        return Err(LayoutReadError::new(
            "ambiguous_plot_setting_name",
            format!("more than one plot setting is named `{requested_name}`; use a handle"),
        ));
    }
    if doc
        .objects
        .values()
        .filter_map(|object| match object {
            ObjectType::PlotSettings(settings) if settings.handle == first.handle => Some(settings),
            _ => None,
        })
        .nth(1)
        .is_some()
    {
        return Err(LayoutReadError::new(
            "ambiguous_plot_setting_handle",
            format!(
                "more than one plot setting uses handle {:X}",
                first.handle.value()
            ),
        ));
    }
    Ok(first)
}

pub(super) fn get_plot_setting(
    doc: &CadDocument,
    selector: &PlotSettingSelector,
) -> Result<PlotSettingRecord, LayoutReadError> {
    plot_setting_record(resolve_plot_setting(doc, selector)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReadError, Reader};
    use acadrust::entities::{EntityType, Line, Viewport};
    use acadrust::objects::{ObjectType, PaperMargin, PlotSettings};
    use acadrust::types::{Handle, Vector3};
    use acadrust::{CadDocument, DwgWriter, DxfVersion};
    use std::path::{Path, PathBuf};

    fn fixture_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    fn open_drawing(path: &Path) -> Result<CadDocument, ReadError> {
        Ok(Reader::open_path(path)?.into_backend_document())
    }

    #[test]
    fn new_doc_has_model_and_layout1() {
        let doc = CadDocument::new();
        let layouts = list_layouts(&doc);
        assert!(
            layouts.iter().any(|l| l.name == "Model"),
            "expected 'Model' layout, got: {:?}",
            layouts.iter().map(|l| &l.name).collect::<Vec<_>>()
        );
        assert!(
            layouts.iter().any(|l| l.name == "Layout1"),
            "expected 'Layout1' layout, got: {:?}",
            layouts.iter().map(|l| &l.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn immutable_dwg_adapter_recovers_embedded_layout_plot_flags() {
        let document = CadDocument::new();
        let file = tempfile::Builder::new().suffix(".dwg").tempfile().unwrap();
        DwgWriter::write_to_file(file.path(), &document).unwrap();
        let bytes = std::fs::read(file.path()).unwrap();
        let session =
            Reader::open_snapshot(DrawingSnapshot::new(DrawingFormat::Dwg, bytes)).unwrap();

        let paper = session
            .get_embedded_layout_plot_flags(&LayoutSelector {
                name: Some("Layout1".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(paper, plot_flags_from_bits(0).unwrap());

        let model = session
            .get_embedded_layout_plot_flags(&LayoutSelector {
                name: Some("Model".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert!(model.model_type);
        assert_eq!(model, plot_flags_from_bits(0x400).unwrap());
    }

    #[test]
    fn embedded_layout_plot_flags_reject_unknown_or_reserved_bits() {
        for bits in [0x100, 0x8000, 0x1_0000, -1] {
            assert_eq!(
                plot_flags_from_bits(bits).unwrap_err().code(),
                "embedded_plot_flags_unsupported"
            );
        }
        let all_known = plot_flags_from_bits(KNOWN_PLOT_FLAG_BITS).unwrap();
        assert!(all_known.plot_viewport_borders);
        assert!(all_known.previous_plot_initialized);
    }

    #[test]
    fn model_layout_is_flagged() {
        let doc = CadDocument::new();
        let layouts = list_layouts(&doc);
        let model = layouts
            .iter()
            .find(|l| l.name == "Model")
            .expect("Model not found");
        assert!(model.is_model);
        let layout1 = layouts
            .iter()
            .find(|l| l.name == "Layout1")
            .expect("Layout1 not found");
        assert!(!layout1.is_model);
    }

    #[test]
    fn model_identity_uses_backing_block_record_not_layout_flags() {
        let mut doc = CadDocument::new();
        for object in doc.objects.values_mut() {
            let ObjectType::Layout(layout) = object else {
                continue;
            };
            layout.flags = if layout.name == "Model" { 0 } else { 1 };
        }

        let layouts = list_layouts(&doc);
        let model_layouts = layouts
            .iter()
            .filter(|layout| layout.is_model)
            .map(|layout| layout.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(model_layouts, ["Model"]);
    }

    #[test]
    fn invalid_model_space_handle_never_classifies_null_layout_handles_as_model() {
        let mut doc = CadDocument::new();
        doc.header.model_space_block_handle = acadrust::types::Handle::NULL;
        for object in doc.objects.values_mut() {
            if let ObjectType::Layout(layout) = object {
                layout.block_record = acadrust::types::Handle::NULL;
            }
        }

        assert!(list_layouts(&doc).iter().all(|layout| !layout.is_model));
    }

    #[test]
    fn expanded_layouts_use_semantic_ownership_when_the_header_handle_is_unavailable() {
        let mut doc = CadDocument::new();
        let model_block = doc
            .objects
            .values()
            .find_map(|object| match object {
                ObjectType::Layout(layout) if layout.name == "Model" => Some(layout.block_record),
                _ => None,
            })
            .unwrap();
        doc.header.model_space_block_handle = Handle::NULL;

        let model = get_layout(
            &doc,
            &LayoutSelector {
                name: Some("Model".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(model.is_model);

        let mut viewport = Viewport::new();
        viewport.common.handle = Handle::new(0xD00);
        viewport.common.owner_handle = model_block;
        doc.add_entity(EntityType::Viewport(viewport)).unwrap();
        assert_eq!(
            get_layout_viewport(&doc, "D00").unwrap_err().code(),
            "layout_viewport_not_owned_by_layout"
        );
    }

    #[test]
    fn expanded_layouts_reject_header_and_semantic_owner_contradictions() {
        let mut doc = CadDocument::new();
        let paper_block = doc
            .objects
            .values()
            .find_map(|object| match object {
                ObjectType::Layout(layout) if layout.name == "Layout1" => Some(layout.block_record),
                _ => None,
            })
            .unwrap();
        doc.header.model_space_block_handle = paper_block;

        for name in ["Model", "Layout1"] {
            let error = get_layout(
                &doc,
                &LayoutSelector {
                    name: Some(name.to_string()),
                    ..Default::default()
                },
            )
            .unwrap_err();
            assert_eq!(error.code(), "unsupported_layout_data");
            assert!(error.message().contains("header model-space handle"));
        }
        assert_eq!(
            list_layout_viewports(
                &doc,
                Some(&LayoutSelector {
                    name: Some("Layout1".to_string()),
                    ..Default::default()
                }),
            )
            .unwrap_err()
            .code(),
            "unsupported_layout_data"
        );
    }

    #[test]
    fn tier1_dwg_and_dxf_layout_metadata_match() {
        const PAPER_EPSILON_MM: f64 = 1e-4;
        let fixture_root = "tests/corpus/open/acadsharp/dynamic-blocks";
        let dwg = open_drawing(&fixture_path(&format!(
            "{fixture_root}/BLOCKVISIBILITYPARAMETER.dwg"
        )))
        .unwrap();
        let dxf = open_drawing(&fixture_path(&format!(
            "{fixture_root}/BLOCKVISIBILITYPARAMETER.dxf"
        )))
        .unwrap();

        let dwg_layouts = list_layouts(&dwg);
        let dxf_layouts = list_layouts(&dxf);
        assert_eq!(dwg_layouts.len(), dxf_layouts.len());
        for (dwg_layout, dxf_layout) in dwg_layouts.iter().zip(&dxf_layouts) {
            assert_eq!(dwg_layout.name, dxf_layout.name);
            assert_eq!(dwg_layout.is_model, dxf_layout.is_model);
            assert_eq!(dwg_layout.tab_order, dxf_layout.tab_order);
            assert!(
                (dwg_layout.paper_width_mm - dxf_layout.paper_width_mm).abs() < PAPER_EPSILON_MM,
                "paper width differs for {}: DWG={}, DXF={}",
                dwg_layout.name,
                dwg_layout.paper_width_mm,
                dxf_layout.paper_width_mm
            );
            assert!(
                (dwg_layout.paper_height_mm - dxf_layout.paper_height_mm).abs() < PAPER_EPSILON_MM,
                "paper height differs for {}: DWG={}, DXF={}",
                dwg_layout.name,
                dwg_layout.paper_height_mm,
                dxf_layout.paper_height_mm
            );
        }
        assert_eq!(
            dwg_layouts
                .iter()
                .filter(|layout| layout.is_model)
                .map(|layout| layout.name.as_str())
                .collect::<Vec<_>>(),
            ["Model"]
        );

        let model = dwg_layouts
            .iter()
            .find(|layout| layout.name == "Model")
            .unwrap();
        assert!((model.paper_width_mm - 215.9).abs() < PAPER_EPSILON_MM);
        assert!((model.paper_height_mm - 279.4).abs() < PAPER_EPSILON_MM);
        for paper_layout in dwg_layouts.iter().filter(|layout| layout.name != "Model") {
            assert_eq!(paper_layout.paper_width_mm, 0.0);
            assert_eq!(paper_layout.paper_height_mm, 0.0);
        }
    }

    #[test]
    fn generic_profile_fixture_preserves_unconfigured_paper_dimensions() {
        let document = open_drawing(&fixture_path(
            "tests/corpus/open/project/generic-title-block-ascii.dxf",
        ))
        .unwrap();
        let layouts = list_layouts(&document);

        assert_eq!(layouts.len(), 2);
        assert!(layouts
            .iter()
            .all(|layout| { layout.paper_width_mm == 0.0 && layout.paper_height_mm == 0.0 }));
    }

    #[test]
    fn added_layout_appears_in_list() {
        let mut doc = CadDocument::with_version(DxfVersion::AC1027);
        doc.add_layout("Sheet 1").unwrap();
        let layouts = list_layouts(&doc);
        assert!(
            layouts.iter().any(|l| l.name == "Sheet 1"),
            "expected 'Sheet 1', got: {:?}",
            layouts.iter().map(|l| &l.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn layouts_sorted_by_tab_order() {
        let doc = CadDocument::new();
        let layouts = list_layouts(&doc);
        // tab_order=0 is Model, tab_order=1 is Layout1
        let orders: Vec<i16> = layouts.iter().map(|l| l.tab_order).collect();
        assert!(
            orders.windows(2).all(|w| w[0] <= w[1]),
            "layouts not sorted by tab_order: {:?}",
            orders
        );
    }

    #[test]
    fn output_serializes_to_json_array() {
        let doc = CadDocument::new();
        let layouts = list_layouts(&doc);
        let json = serde_json::to_string(&layouts).unwrap();
        assert!(json.starts_with('['));
    }

    #[test]
    fn output_round_trips_through_json() {
        let layouts = list_layouts(&CadDocument::new());
        let json = serde_json::to_string(&layouts).unwrap();
        let parsed: Vec<LayoutInfo> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, layouts);
    }

    #[test]
    fn output_contract_rejects_unknown_fields() {
        let error = serde_json::from_str::<LayoutInfo>(
            r#"{
                "name": "Layout1",
                "is_model": false,
                "tab_order": 1,
                "paper_width_mm": 420.0,
                "paper_height_mm": 297.0,
                "unexpected": true
            }"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field `unexpected`"));
    }

    #[test]
    fn get_layout_supports_stable_handle_and_case_insensitive_name() {
        let doc = CadDocument::new();
        let by_name = get_layout(
            &doc,
            &LayoutSelector {
                name: Some("layout1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(by_name.name, "Layout1");
        assert!(!by_name.is_model);
        assert!(by_name.block_record_handle.is_some());

        let by_handle = get_layout(
            &doc,
            &LayoutSelector {
                handle: Some(format!("0x{}", by_name.handle.to_lowercase())),
                name: Some("LAYOUT1".to_string()),
            },
        )
        .unwrap();
        assert_eq!(by_handle, by_name);
    }

    #[test]
    fn get_layout_reports_missing_invalid_and_mismatched_identity() {
        let doc = CadDocument::new();
        assert_eq!(
            get_layout(&doc, &LayoutSelector::default())
                .unwrap_err()
                .code(),
            "missing_layout_identity"
        );
        assert_eq!(
            get_layout(
                &doc,
                &LayoutSelector {
                    handle: Some("not-hex".to_string()),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .code(),
            "invalid_layout_handle"
        );

        let layout = get_layout(
            &doc,
            &LayoutSelector {
                name: Some("Layout1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            get_layout(
                &doc,
                &LayoutSelector {
                    handle: Some(layout.handle),
                    name: Some("Model".to_string()),
                }
            )
            .unwrap_err()
            .code(),
            "layout_identity_mismatch"
        );
        let whitespace = get_layout(
            &doc,
            &LayoutSelector {
                name: Some(" Model".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(whitespace.code(), "invalid_layout_name");
        assert!(whitespace.message().contains("surrounding whitespace"));
    }

    #[test]
    fn get_layout_exposes_embedded_plot_rotation_without_guessing_unknown_codes() {
        let mut doc = CadDocument::new();
        for object in doc.objects.values_mut() {
            if let ObjectType::Layout(layout) = object {
                if layout.name == "Layout1" {
                    layout.paper_width = 420.0;
                    layout.paper_height = 297.0;
                    layout.plot_rotation = 1;
                } else {
                    layout.plot_rotation = 99;
                }
            }
        }

        let paper = get_layout(
            &doc,
            &LayoutSelector {
                name: Some("Layout1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(paper.plot_settings.paper_width_mm, 420.0);
        assert_eq!(paper.plot_settings.paper_height_mm, 297.0);
        assert_eq!(paper.plot_settings.rotation_degrees, Some(90));

        let model = get_layout(
            &doc,
            &LayoutSelector {
                name: Some("Model".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(model.plot_settings.rotation_code, 99);
        assert_eq!(model.plot_settings.rotation_degrees, None);
    }

    #[test]
    fn layout_record_round_trips_and_rejects_unknown_fields() {
        let record = get_layout(
            &CadDocument::new(),
            &LayoutSelector {
                name: Some("Model".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let json = serde_json::to_string(&record).unwrap();
        let parsed: LayoutRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, record);

        let mut value = serde_json::to_value(record).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::json!(true));
        let error = serde_json::from_value::<LayoutRecord>(value).unwrap_err();
        assert!(error.to_string().contains("unknown field `unexpected`"));
    }

    #[test]
    fn list_and_get_layout_viewports_use_paper_space_entity_handles() {
        let mut doc = CadDocument::new();
        let layout_handle = doc.add_layout("Sheet 1").unwrap();

        let mut detail = Viewport::with_size(Vector3::new(5.0, 7.0, 0.0), 200.0, 100.0);
        detail.id = 2;
        detail.status.locked = true;
        detail.view_height = 400.0;
        detail.custom_scale = 0.25;
        detail.frozen_layers = vec![Handle::new(0xCA), Handle::new(0xB0), Handle::new(0xCA)];
        let detail_handle = doc
            .add_entity_to_layout(EntityType::Viewport(detail), "Sheet 1")
            .unwrap();

        let records = list_layout_viewports(
            &doc,
            Some(&LayoutSelector {
                handle: Some(format!("{:X}", layout_handle.value())),
                ..Default::default()
            }),
        )
        .unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| {
            record.resource_type == LayoutViewportResourceType::PaperSpaceEntity
                && record.layout_name == "Sheet 1"
        }));
        assert_eq!(
            records
                .iter()
                .filter(|record| record.is_last_active_for_layout)
                .count(),
            1
        );

        let record = get_layout_viewport(&doc, &format!("0x{:x}", detail_handle.value())).unwrap();
        assert_eq!(record.handle, format!("{:X}", detail_handle.value()));
        assert_eq!(record.layout_handle, format!("{:X}", layout_handle.value()));
        assert_eq!(record.viewport_id, 2);
        assert!(record.locked);
        assert_eq!(record.is_on, None);
        assert_eq!(record.model_to_paper_scale, Some(0.25));
        assert_eq!(record.custom_scale, None);
        assert_eq!(record.frozen_layer_handles, ["B0", "CA"]);
    }

    #[test]
    fn viewport_status_projection_uses_corrected_backend_semantics() {
        let mut doc = CadDocument::new();
        doc.add_layout("Sheet 1").unwrap();
        let mut viewport = Viewport::new();
        viewport.status = acadrust::entities::viewport::ViewportStatusFlags::from_bits(0xC007);
        let handle = doc
            .add_entity_to_layout(EntityType::Viewport(viewport), "Sheet 1")
            .unwrap();

        let record = get_layout_viewport(&doc, &format!("{:X}", handle.value())).unwrap();
        assert_eq!(record.is_on, None);
        assert!(record.perspective);
        assert!(record.front_clipping);
        assert!(record.back_clipping);
        assert!(record.locked);

        let mut unrelated_iso_pair = Viewport::new();
        unrelated_iso_pair.status =
            acadrust::entities::viewport::ViewportStatusFlags::from_bits(0x2000);
        let shifted_handle = doc
            .add_entity_to_layout(EntityType::Viewport(unrelated_iso_pair), "Sheet 1")
            .unwrap();
        assert!(
            !get_layout_viewport(&doc, &format!("{:X}", shifted_handle.value()))
                .unwrap()
                .locked
        );
    }

    #[test]
    fn model_layout_scope_has_no_paper_space_viewport_entities() {
        let mut doc = CadDocument::new();
        doc.add_layout("Sheet 1").unwrap();
        let records = list_layout_viewports(
            &doc,
            Some(&LayoutSelector {
                name: Some("Model".to_string()),
                ..Default::default()
            }),
        )
        .unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn get_layout_viewport_rejects_non_viewport_and_model_owned_viewport() {
        let mut doc = CadDocument::new();
        let line_handle = doc
            .add_entity(EntityType::Line(Line::from_coords(
                0.0, 0.0, 0.0, 1.0, 1.0, 0.0,
            )))
            .unwrap();
        assert_eq!(
            get_layout_viewport(&doc, &format!("{:X}", line_handle.value()))
                .unwrap_err()
                .code(),
            "layout_viewport_not_found"
        );

        let viewport_handle = doc
            .add_entity(EntityType::Viewport(Viewport::new()))
            .unwrap();
        assert_eq!(
            get_layout_viewport(&doc, &format!("{:X}", viewport_handle.value()))
                .unwrap_err()
                .code(),
            "layout_viewport_not_owned_by_layout"
        );
    }

    #[test]
    fn layout_filter_cannot_hide_duplicate_viewport_handles() {
        let mut doc = CadDocument::new();
        doc.add_layout("Sheet 1").unwrap();
        let paper_handle = doc
            .add_entity_to_layout(EntityType::Viewport(Viewport::new()), "Sheet 1")
            .unwrap();
        let model_handle = doc
            .add_entity(EntityType::Viewport(Viewport::new()))
            .unwrap();
        doc.get_entity_mut(model_handle)
            .unwrap()
            .common_mut()
            .handle = paper_handle;

        let error = list_layout_viewports(
            &doc,
            Some(&LayoutSelector {
                name: Some("Sheet 1".to_string()),
                ..Default::default()
            }),
        )
        .unwrap_err();
        assert_eq!(error.code(), "duplicate_entity_handle");
        assert_eq!(
            get_layout_viewport(&doc, &format!("{:X}", paper_handle.value()))
                .unwrap_err()
                .code(),
            error.code()
        );
    }

    #[test]
    fn cross_type_handle_collisions_cannot_hide_behind_viewport_filtering() {
        let mut doc = CadDocument::new();
        doc.add_layout("Sheet 1").unwrap();
        let viewport_handle = doc
            .add_entity_to_layout(EntityType::Viewport(Viewport::new()), "Sheet 1")
            .unwrap();
        let mut line = Line::new();
        line.common.handle = viewport_handle;
        doc.add_entity(EntityType::Line(line)).unwrap();

        assert_eq!(
            list_layout_viewports(
                &doc,
                Some(&LayoutSelector {
                    name: Some("Sheet 1".to_string()),
                    ..Default::default()
                }),
            )
            .unwrap_err()
            .code(),
            "duplicate_entity_handle"
        );
        assert_eq!(
            get_layout_viewport(&doc, &format!("{:X}", viewport_handle.value()))
                .unwrap_err()
                .code(),
            "duplicate_entity_handle"
        );
    }

    #[test]
    fn unavailable_viewport_scale_is_null_while_invalid_operands_fail_closed() {
        let mut viewport_doc = CadDocument::new();
        viewport_doc.add_layout("Sheet 1").unwrap();
        let mut viewport = Viewport::new();
        viewport.view_height = 0.0;
        let viewport_handle = viewport_doc
            .add_entity_to_layout(EntityType::Viewport(viewport), "Sheet 1")
            .unwrap();
        assert_eq!(
            get_layout_viewport(&viewport_doc, &format!("{:X}", viewport_handle.value()))
                .unwrap()
                .model_to_paper_scale,
            None
        );

        for operands in [(0.0, 1.0), (1.0, 0.0), (0.0, 0.0)] {
            assert_eq!(
                checked_optional_nonnegative_ratio(
                    operands.0,
                    operands.1,
                    "numerator",
                    "denominator",
                    "ratio",
                )
                .unwrap(),
                None
            );
        }
        for operands in [(-1.0, 1.0), (1.0, -1.0)] {
            assert_eq!(
                checked_optional_nonnegative_ratio(
                    operands.0,
                    operands.1,
                    "numerator",
                    "denominator",
                    "ratio",
                )
                .unwrap_err()
                .code(),
                "unsupported_layout_data"
            );
        }
        assert_eq!(
            checked_optional_nonnegative_ratio(
                f64::INFINITY,
                1.0,
                "numerator",
                "denominator",
                "ratio",
            )
            .unwrap_err()
            .code(),
            "unsupported_layout_data"
        );

        let mut plot_doc = CadDocument::new();
        let mut settings = PlotSettings::new("Invalid Scale");
        settings.handle = Handle::new(0xBAD);
        settings.scale_denominator = 0.0;
        plot_doc
            .objects
            .insert(settings.handle, ObjectType::PlotSettings(settings));
        let plot_error = list_plot_settings(&plot_doc).unwrap_err();
        assert_eq!(plot_error.code(), "unsupported_layout_data");
        assert!(plot_error
            .message()
            .contains("plot setting scale_denominator"));

        for operands in [(-1.0, 1.0), (1.0, -1.0)] {
            assert_eq!(
                checked_positive_ratio(
                    operands.0,
                    operands.1,
                    "numerator",
                    "denominator",
                    "ratio",
                    0.0,
                )
                .unwrap_err()
                .code(),
                "unsupported_layout_data"
            );
        }
    }

    #[test]
    fn targeted_viewport_get_ignores_unrelated_document_handle_defects() {
        let mut doc = CadDocument::new();
        doc.add_layout("Sheet 1").unwrap();
        let target = doc
            .add_entity_to_layout(EntityType::Viewport(Viewport::new()), "Sheet 1")
            .unwrap();
        let duplicate = doc
            .add_entity_to_layout(EntityType::Viewport(Viewport::new()), "Sheet 1")
            .unwrap();
        let duplicate_copy = doc
            .add_entity_to_layout(EntityType::Viewport(Viewport::new()), "Sheet 1")
            .unwrap();
        doc.get_entity_mut(duplicate_copy)
            .unwrap()
            .common_mut()
            .handle = duplicate;
        let invalid = doc
            .add_entity_to_layout(EntityType::Viewport(Viewport::new()), "Sheet 1")
            .unwrap();
        doc.get_entity_mut(invalid).unwrap().common_mut().handle = Handle::NULL;

        let record = get_layout_viewport(&doc, &format!("{:X}", target.value())).unwrap();
        assert_eq!(record.handle, format!("{:X}", target.value()));
        assert!(list_layout_viewports(&doc, None).is_err());
    }

    #[test]
    fn plot_settings_are_deterministic_and_selectable_by_handle_or_name() {
        let mut doc = CadDocument::new();
        let mut a3 = PlotSettings::new("A3 Sheet");
        a3.handle = Handle::new(0xBED);
        a3.owner = doc.header.acad_plotsettings_dict_handle;
        a3.printer_name = "DWG To PDF.pc3".to_string();
        a3.paper_size = "ISO_A3".to_string();
        a3.paper_width = 420.0;
        a3.paper_height = 297.0;
        a3.margins = PaperMargin::new(5.0, 6.0, 7.0, 8.0);
        a3.set_custom_scale(1.0, 50.0);
        a3.flags.plot_centered = true;
        doc.objects
            .insert(a3.handle, ObjectType::PlotSettings(a3.clone()));

        let mut a1 = PlotSettings::new("A1 Sheet");
        a1.handle = Handle::new(0xBEE);
        doc.objects.insert(a1.handle, ObjectType::PlotSettings(a1));

        let records = list_plot_settings(&doc).unwrap();
        assert_eq!(
            records
                .iter()
                .map(|record| record.name.as_str())
                .collect::<Vec<_>>(),
            ["A3 Sheet", "A1 Sheet"]
        );

        let by_name = get_plot_setting(
            &doc,
            &PlotSettingSelector {
                name: Some("a3 sheet".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(by_name.handle, "BED");
        assert_eq!(
            by_name.owner_handle,
            Some(format!(
                "{:X}",
                doc.header.acad_plotsettings_dict_handle.value()
            ))
        );
        assert_eq!(by_name.paper_units, PlotPaperUnits::Inches);
        assert_eq!(by_name.scale_factor, 0.02);
        assert!(by_name.flags.plot_centered);

        let by_handle = get_plot_setting(
            &doc,
            &PlotSettingSelector {
                handle: Some("0xbEd".to_string()),
                name: Some("A3 SHEET".to_string()),
            },
        )
        .unwrap();
        assert_eq!(by_handle, by_name);
    }

    #[test]
    fn non_finite_layout_and_plot_setting_values_fail_closed() {
        let mut layout_doc = CadDocument::new();
        for object in layout_doc.objects.values_mut() {
            if let ObjectType::Layout(layout) = object {
                if layout.name == "Layout1" {
                    layout.elevation = f64::NAN;
                }
            }
        }
        let layout_error = get_layout(
            &layout_doc,
            &LayoutSelector {
                name: Some("Layout1".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(layout_error.code(), "unsupported_layout_data");
        assert!(layout_error.message().contains("layout elevation"));

        let mut plot_doc = CadDocument::new();
        let mut settings = PlotSettings::new("Invalid");
        settings.handle = Handle::new(0xBAD);
        settings.paper_width = f64::INFINITY;
        plot_doc
            .objects
            .insert(settings.handle, ObjectType::PlotSettings(settings));

        let plot_error = list_plot_settings(&plot_doc).unwrap_err();
        assert_eq!(plot_error.code(), "unsupported_layout_data");
        assert!(plot_error.message().contains("plot setting paper_width"));
    }

    #[test]
    fn inverted_layout_limits_and_extents_fail_closed() {
        let assert_inverted = |field: &str, mutate: fn(&mut Layout)| {
            let mut doc = CadDocument::new();
            for object in doc.objects.values_mut() {
                if let ObjectType::Layout(layout) = object {
                    if layout.name == "Layout1" {
                        mutate(layout);
                    }
                }
            }
            let error = get_layout(
                &doc,
                &LayoutSelector {
                    name: Some("Layout1".to_string()),
                    ..Default::default()
                },
            )
            .unwrap_err();
            assert_eq!(error.code(), "unsupported_layout_data");
            assert!(error.message().contains(field));
            assert!(error.message().contains("inverted bounds"));
        };

        assert_inverted("layout limits", |layout| {
            layout.min_limits = (2.0, 0.0);
            layout.max_limits = (1.0, 1.0);
        });
        assert_inverted("layout extents", |layout| {
            layout.min_extents = (0.0, 0.0, 2.0);
            layout.max_extents = (1.0, 1.0, 1.0);
        });
    }

    #[test]
    fn empty_layout_extent_sentinel_is_explicitly_unavailable() {
        let mut doc = CadDocument::new();
        for object in doc.objects.values_mut() {
            if let ObjectType::Layout(layout) = object {
                if layout.name == "Layout1" {
                    layout.min_extents = (1.0e20, 1.0e20, 1.0e20);
                    layout.max_extents = (-1.0e20, -1.0e20, -1.0e20);
                }
            }
        }

        let record = get_layout(
            &doc,
            &LayoutSelector {
                name: Some("Layout1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(record.extents, None);
        assert_eq!(
            serde_json::to_value(record).unwrap()["extents"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn plot_setting_errors_are_explicit_and_records_are_closed() {
        let doc = CadDocument::new();
        assert_eq!(
            get_plot_setting(&doc, &PlotSettingSelector::default())
                .unwrap_err()
                .code(),
            "missing_plot_setting_identity"
        );
        assert_eq!(
            get_plot_setting(
                &doc,
                &PlotSettingSelector {
                    handle: Some("0".to_string()),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .code(),
            "invalid_plot_setting_handle"
        );
        let whitespace = get_plot_setting(
            &doc,
            &PlotSettingSelector {
                name: Some(" A3".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(whitespace.code(), "invalid_plot_setting_name");
        assert!(whitespace.message().contains("surrounding whitespace"));

        let error =
            serde_json::from_str::<PlotSettingSelector>(r#"{"name":"A3","unexpected":true}"#)
                .unwrap_err();
        assert!(error.to_string().contains("unknown field `unexpected`"));
    }

    #[test]
    fn name_lookup_rejects_a_handle_shared_by_distinct_plot_settings() {
        let mut doc = CadDocument::new();
        let mut first = PlotSettings::new("FIRST");
        first.handle = Handle::new(0xA10);
        doc.objects
            .insert(Handle::new(0xA10), ObjectType::PlotSettings(first));
        let mut second = PlotSettings::new("SECOND");
        second.handle = Handle::new(0xA10);
        doc.objects
            .insert(Handle::new(0xA11), ObjectType::PlotSettings(second));

        let error = get_plot_setting(
            &doc,
            &PlotSettingSelector {
                name: Some("FIRST".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "ambiguous_plot_setting_handle");
        assert_eq!(list_plot_settings(&doc).unwrap_err().code(), error.code());
    }
}
