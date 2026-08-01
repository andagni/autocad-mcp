use std::collections::{BTreeMap, BTreeSet};
use std::f64::consts::{FRAC_PI_2, PI, TAU};

use acadrust::entities::{
    AttachmentPoint, AttributeDefinition, AttributeEntity, BoundaryEdge, Dimension,
    DrawingDirection, EntityCommon, EntityType, Face3D, Hatch, HatchStyleType,
    HorizontalAlignment as AttributeHorizontalAlignment, Insert, LwPolyline, MText, Polyline2D,
    Text, TextHorizontalAlignment, TextVerticalAlignment,
    VerticalAlignment as AttributeVerticalAlignment, Viewport, ViewportRenderMode, Wipeout,
    WipeoutClipMode,
};
use acadrust::objects::{Layout, ObjectType};
use acadrust::tables::TextStyle;
use acadrust::types::{Color, Handle, LineWeight, Vector3 as CadVector3};
use acadrust::CadDocument;
use autocad_reader::contract::{LayoutRecord, PlotFlagsRecord};

use crate::portable_plot::resources::{
    CompositeFontId, FontResolution, ShxCompositeFace, ShxCompositeFontResource, ShxStrokeCommand,
    ShxStrokeFontResource, ShxStrokeGlyph, StrokeFontId,
};
use crate::DrawingSnapshot;

use crate::portable_plot::{
    Affine2, Affine3, BlockInsertTransform3, ClipPath, DashPattern, DiagnosticLedger, DisplayList,
    DisplayListLimits, DisplayListUsage, DisplayNode, FidelityDisposition, FidelitySummary, Fill,
    FillRule, FontId, GlyphRun, InlineGroup, LineCap, LineJoin, OcsFrame, PageGeometry,
    PathCommand, PathNode, PlotCompleteness, PlotDiagnostic, PlotStyleResource, Point2, Point3,
    PortablePlotError, PortableResourceBundle, PositionedGlyph, ResourceDigest, SceneColor,
    ScenePath, SourceHandle, Stroke, Vector2, Vector3,
};

use super::{
    canonical_handle, cross_check_source, independent_inventories, inspect_portable_source,
    parse_backend_snapshot, BackendLimitation, PortableSourceInventory,
};

const POINTS_PER_MM: f64 = 72.0 / 25.4;
const DEFAULT_LINEWEIGHT_MM: f64 = 0.25;

/// Complete compiler and scene limits included in every development receipt.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PortablePlotLimits {
    pub display_list: DisplayListLimits,
    pub max_source_bytes: usize,
    pub max_source_entities: usize,
    pub max_insert_depth: usize,
    pub max_insert_instances: usize,
    pub max_curve_segments: usize,
    pub max_dependency_members: usize,
    pub max_dependency_bytes: usize,
    pub curve_tolerance_points: f64,
    pub representative_diagnostics: usize,
}

impl Default for PortablePlotLimits {
    fn default() -> Self {
        Self {
            display_list: DisplayListLimits::default(),
            max_source_bytes: 256 * 1024 * 1024,
            max_source_entities: 500_000,
            max_insert_depth: 64,
            max_insert_instances: 250_000,
            max_curve_segments: 1_000_000,
            max_dependency_members: 4_096,
            max_dependency_bytes: 512 * 1024 * 1024,
            curve_tolerance_points: 0.02,
            representative_diagnostics: 256,
        }
    }
}

impl PortablePlotLimits {
    fn validate(self) -> Result<Self, PortablePlotError> {
        if self.max_source_bytes == 0
            || self.max_source_entities == 0
            || self.max_insert_depth == 0
            || self.max_insert_instances == 0
            || self.max_curve_segments == 0
            || self.max_dependency_members == 0
            || self.max_dependency_bytes == 0
            || self.representative_diagnostics == 0
            || !self.curve_tolerance_points.is_finite()
            || self.curve_tolerance_points <= 0.0
            || self.curve_tolerance_points > 1.0
        {
            return Err(PortablePlotError::new(
                "portable_plot_limits_invalid",
                "portable plot limits must be positive and curve tolerance must be in (0, 1] points",
            ));
        }
        Ok(self)
    }
}

/// Development evidence for one semantic compilation.
#[derive(Debug, Clone)]
pub struct PortablePlotReceipt {
    profile: &'static str,
    renderer: &'static str,
    source: PortableSourceInventory,
    limits: PortablePlotLimits,
    fidelity: FidelitySummary,
    usage: Option<DisplayListUsage>,
    rendered_viewports: usize,
    resources: Vec<PortableResourceReceipt>,
}

/// One digest-bound resource actually consumed by semantic compilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableResourceReceipt {
    kind: &'static str,
    logical_identity: String,
    digest: ResourceDigest,
    source_format: Option<&'static str>,
    semantic_digest: Option<ResourceDigest>,
}

impl PortableResourceReceipt {
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    pub fn logical_identity(&self) -> &str {
        &self.logical_identity
    }

    pub fn digest(&self) -> ResourceDigest {
        self.digest
    }

    pub fn source_format(&self) -> Option<&'static str> {
        self.source_format
    }

    pub fn semantic_digest(&self) -> Option<ResourceDigest> {
        self.semantic_digest
    }
}

impl PortablePlotReceipt {
    pub fn profile(&self) -> &'static str {
        self.profile
    }

    pub fn renderer(&self) -> &'static str {
        self.renderer
    }

    pub fn source(&self) -> &PortableSourceInventory {
        &self.source
    }

    pub fn limits(&self) -> PortablePlotLimits {
        self.limits
    }

    pub fn fidelity(&self) -> &FidelitySummary {
        &self.fidelity
    }

    pub fn usage(&self) -> Option<DisplayListUsage> {
        self.usage
    }

    pub fn rendered_viewports(&self) -> usize {
        self.rendered_viewports
    }

    pub fn resources(&self) -> &[PortableResourceReceipt] {
        &self.resources
    }
}

/// A validated backend-neutral scene when fidelity did not reject the source.
#[derive(Debug, Clone)]
pub struct PortableSceneCompilation {
    display_list: Option<DisplayList>,
    receipt: PortablePlotReceipt,
}

impl PortableSceneCompilation {
    pub fn display_list(&self) -> Option<&DisplayList> {
        self.display_list.as_ref()
    }

    pub fn receipt(&self) -> &PortablePlotReceipt {
        &self.receipt
    }

    pub fn into_display_list(self) -> Option<DisplayList> {
        self.display_list
    }
}

/// Compile one selected paper layout into the backend-neutral display list.
///
/// Rejected semantics return a receipt with no encodable scene. Partial scenes
/// remain available solely as development evidence.
pub fn compile_portable_scene(
    snapshot: &DrawingSnapshot,
    layout_name: &str,
    limits: PortablePlotLimits,
) -> Result<PortableSceneCompilation, PortablePlotError> {
    compile_portable_scene_with_resources(
        snapshot,
        layout_name,
        &PortableResourceBundle::new(),
        limits,
    )
}

/// Compile with an explicit immutable font/image/plot-style/XREF resource bundle.
pub fn compile_portable_scene_with_resources(
    snapshot: &DrawingSnapshot,
    layout_name: &str,
    resources: &PortableResourceBundle,
    limits: PortablePlotLimits,
) -> Result<PortableSceneCompilation, PortablePlotError> {
    let limits = limits.validate()?;
    if snapshot.format() != crate::DrawingFormat::Dwg {
        return Err(PortablePlotError::new(
            "source_profile_not_admitted",
            "portable_2d_v1 admits only AC1032 DWG snapshots",
        ));
    }
    if snapshot.bytes().len() > limits.max_source_bytes {
        return Err(PortablePlotError::new(
            "source_byte_budget_exceeded",
            format!(
                "source snapshot exceeds the configured maximum of {} bytes",
                limits.max_source_bytes
            ),
        ));
    }
    let dependency_members = resources
        .font_count()
        .checked_add(resources.shx_stroke_font_count())
        .and_then(|count| count.checked_add(resources.shx_composite_font_count()))
        .and_then(|count| count.checked_add(resources.image_count()))
        .and_then(|count| count.checked_add(resources.plot_style_count()))
        .and_then(|count| count.checked_add(resources.xref_count()))
        .ok_or_else(|| {
            PortablePlotError::new(
                "resource_bundle_budget_exceeded",
                "resource member accounting overflowed",
            )
        })?;
    if dependency_members > limits.max_dependency_members
        || resources.total_bytes()? > limits.max_dependency_bytes
    {
        return Err(PortablePlotError::new(
            "resource_bundle_budget_exceeded",
            "resource bundle exceeds the configured member or byte limit",
        ));
    }
    let source = inspect_portable_source(snapshot, layout_name)?;
    source.admit_portable_2d_v1()?;
    if source.counts().entities > limits.max_source_entities {
        return Err(PortablePlotError::new(
            "source_entity_budget_exceeded",
            format!(
                "source entity count exceeds the configured maximum of {}",
                limits.max_source_entities
            ),
        ));
    }

    let independent = independent_inventories(snapshot, layout_name)?;
    let document = parse_backend_snapshot(snapshot)?;
    let cross_check = cross_check_source(&document, &independent)?;
    require_stable_source_cross_check(
        source
            .limitations()
            .contains(&BackendLimitation::StaleBlockInsertIndexIgnored),
        cross_check.stale_block_insert_index,
    )?;
    validate_block_graph(&document, limits.max_insert_depth)?;
    let raw_layout = selected_layout(&document, &independent.selected_layout)?;
    let page_context = PageContext::new(
        raw_layout,
        Some(&independent.selected_layout),
        &independent.selected_layout_plot_flags,
    )?;
    // Autodesk PSTYLEMODE=1 means color-dependent (CTB), despite the reversed
    // prose comment on acadrust 0.4.1's boolean field.
    let plot_style = if independent.selected_layout_plot_flags.plot_plot_styles
        && document.header.plotstyle_mode
        && !raw_layout.plot_style_sheet.is_empty()
    {
        resources.resolve_plot_style(&raw_layout.plot_style_sheet)?
    } else {
        None
    };
    let mut display_list = DisplayList::new(page_context.page);
    let mut ledger = DiagnosticLedger::new(limits.representative_diagnostics);
    let mut compiler = Compiler {
        document: &document,
        resources,
        plot_style,
        limits,
        ledger: &mut ledger,
        print_lineweights: independent.selected_layout_plot_flags.print_lineweights
            || independent.selected_layout_plot_flags.plot_plot_styles,
        lineweight_scale: if independent.selected_layout_plot_flags.scale_lineweights {
            page_context.plot_scale
        } else {
            1.0
        },
        plot_viewport_borders: independent.selected_layout_plot_flags.plot_viewport_borders,
        curve_segments: 0,
        insert_instances: 0,
        rendered_viewports: 0,
        used_fonts: BTreeSet::new(),
        used_stroke_fonts: BTreeSet::new(),
        used_composite_fonts: BTreeSet::new(),
        stroke_path_commands: 0,
    };

    compiler.record_global_limitations(
        raw_layout,
        &independent.selected_layout_plot_flags,
        plot_style.is_some(),
        page_context.plot_area_applied,
        page_context.plot_scale_applied,
    )?;
    let paper_projection = Projection::paper(page_context.paper_to_page, page_context.page)?;
    let paper_nodes = compiler.compile_owner(
        raw_layout.block_record,
        Affine3::identity(),
        None,
        &paper_projection,
        0,
    )?;
    let mut paper_group = Some(DisplayNode::InlineGroup(InlineGroup::new(
        Affine2::identity(),
        Some(ClipPath::new(
            page_context.paper_clip.path()?,
            FillRule::NonZero,
        )),
        255,
        paper_nodes,
    )));
    if !independent.selected_layout_plot_flags.draw_viewports_first {
        display_list.push(
            paper_group
                .take()
                .expect("paper group is present until its selected plot order"),
        );
    }

    let model_owner = document
        .block_records
        .iter()
        .find(|record| record.is_model_space())
        .map(|record| record.handle);
    for viewport in selected_viewports(&document, raw_layout) {
        if viewport.id <= 1 || !viewport.status.is_on {
            continue;
        }
        let Some(model_owner) = model_owner else {
            compiler.unsupported_layout(
                "model_space_owner_missing",
                "a visible viewport has no model-space block record",
                raw_layout,
            )?;
            continue;
        };
        match Projection::viewport(
            viewport,
            page_context.paper_to_page,
            page_context.page,
            page_context.paper_clip,
            &document,
        ) {
            Ok(projection) => {
                let nodes = compiler.compile_owner(
                    model_owner,
                    Affine3::identity(),
                    None,
                    &projection,
                    0,
                )?;
                display_list.push(DisplayNode::InlineGroup(InlineGroup::new(
                    Affine2::identity(),
                    Some(ClipPath::new(projection.clip_path()?, FillRule::NonZero)),
                    255,
                    nodes,
                )));
                compiler.rendered_viewports += 1;
                compiler
                    .ledger
                    .record_source("VIEWPORT", FidelityDisposition::Exact)?;
            }
            Err(error) => {
                compiler.diagnostic(
                    "viewport_semantics_unsupported",
                    "VIEWPORT",
                    source_handle(viewport.common.handle)?,
                    FidelityDisposition::Unsupported,
                    error.message(),
                )?;
            }
        }
    }
    if let Some(paper_group) = paper_group {
        display_list.push(paper_group);
    }
    let rendered_viewports = compiler.rendered_viewports;
    let used_fonts = std::mem::take(&mut compiler.used_fonts);
    let used_stroke_fonts = std::mem::take(&mut compiler.used_stroke_fonts);
    let used_composite_fonts = std::mem::take(&mut compiler.used_composite_fonts);
    let mut resource_receipts = Vec::with_capacity(
        used_fonts.len()
            + used_stroke_fonts.len()
            + used_composite_fonts.len()
            + usize::from(plot_style.is_some()),
    );
    for id in used_fonts {
        let resource = resources.font_by_id(id).ok_or_else(|| {
            PortablePlotError::new(
                "resource_bundle_contradictory",
                "compiler referenced an unknown font resource identifier",
            )
        })?;
        display_list.insert_font(id, resource.clone())?;
        resource_receipts.push(PortableResourceReceipt {
            kind: "font",
            logical_identity: resource.logical_identity().to_string(),
            digest: resource.digest(),
            source_format: None,
            semantic_digest: None,
        });
    }
    for id in used_stroke_fonts {
        let resource = resources.shx_stroke_font_by_id(id).ok_or_else(|| {
            PortablePlotError::new(
                "resource_bundle_contradictory",
                "compiler referenced an unknown SHX stroke-font resource identifier",
            )
        })?;
        resource_receipts.push(PortableResourceReceipt {
            kind: "stroke_font",
            logical_identity: resource.logical_identity().to_string(),
            digest: resource.digest(),
            source_format: Some(resource.source_format()),
            semantic_digest: Some(resource.semantic_digest()),
        });
    }
    for id in used_composite_fonts {
        let resource = resources.shx_composite_font_by_id(id).ok_or_else(|| {
            PortablePlotError::new(
                "resource_bundle_contradictory",
                "compiler referenced an unknown SHX composite-font resource identifier",
            )
        })?;
        resource_receipts.push(PortableResourceReceipt {
            kind: "stroke_font_composite",
            logical_identity: resource.logical_identity().to_string(),
            digest: resource.digest(),
            source_format: Some(resource.source_format()),
            semantic_digest: Some(resource.semantic_digest()),
        });
    }
    if let Some(resource) = plot_style {
        resource_receipts.push(PortableResourceReceipt {
            kind: "plot_style",
            logical_identity: resource.logical_identity().to_string(),
            digest: resource.digest(),
            source_format: Some(resource.source_format()),
            semantic_digest: Some(resource.semantic_digest()),
        });
    }

    let usage = match display_list.validate(limits.display_list) {
        Ok(usage) => Some(usage),
        Err(error) => {
            ledger.record(PlotDiagnostic::new(
                "display_list_validation_failed",
                "SCENE",
                None,
                FidelityDisposition::Invalid,
                error.message(),
            )?)?;
            None
        }
    };
    let fidelity = ledger.finish();
    let display_list = (fidelity.completeness() != PlotCompleteness::Rejected && usage.is_some())
        .then_some(display_list);
    Ok(PortableSceneCompilation {
        display_list,
        receipt: PortablePlotReceipt {
            profile: "portable_2d_v1",
            renderer: "autocad_writer_semantic_compiler_v1",
            source,
            limits,
            fidelity,
            usage,
            rendered_viewports,
            resources: resource_receipts,
        },
    })
}

fn selected_layout<'a>(
    document: &'a CadDocument,
    independent: &autocad_reader::contract::LayoutRecord,
) -> Result<&'a Layout, PortablePlotError> {
    let matches = document
        .objects
        .values()
        .filter_map(|object| match object {
            ObjectType::Layout(layout) if layout.name == independent.name => Some(layout),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [layout] = matches.as_slice() else {
        return Err(PortablePlotError::new(
            "layout_identity_contradictory",
            "selected layout is not unique in the backend projection",
        ));
    };
    Ok(layout)
}

fn selected_viewports<'a>(document: &'a CadDocument, layout: &Layout) -> Vec<&'a Viewport> {
    document
        .entities()
        .filter_map(|entity| match entity {
            EntityType::Viewport(viewport)
                if viewport.common.owner_handle == layout.block_record =>
            {
                Some(viewport)
            }
            _ => None,
        })
        .collect()
}

fn is_dimension_graphics_block(block: &acadrust::tables::BlockRecord) -> bool {
    block.is_anonymous() && block.name.starts_with("*D")
}

fn block_has_external_semantics(block: &acadrust::tables::BlockRecord) -> bool {
    block.flags.is_xref
        || block.flags.is_xref_overlay
        || block.flags.is_external
        || !block.xref_path.is_empty()
}

struct PageContext {
    page: PageGeometry,
    paper_to_page: Affine2,
    paper_clip: Rect,
    plot_scale: f64,
    plot_area_applied: bool,
    plot_scale_applied: bool,
}

impl PageContext {
    fn new(
        layout: &Layout,
        independent: Option<&LayoutRecord>,
        plot_flags: &PlotFlagsRecord,
    ) -> Result<Self, PortablePlotError> {
        if !finite_positive(layout.paper_width) || !finite_positive(layout.paper_height) {
            return Err(PortablePlotError::new(
                "layout_paper_geometry_invalid",
                "selected layout has no finite positive stored paper geometry",
            ));
        }
        let width = layout.paper_width * POINTS_PER_MM;
        let height = layout.paper_height * POINTS_PER_MM;
        let unit_scale = match layout.plot_paper_units {
            0 => 72.0,
            1 => POINTS_PER_MM,
            2 => {
                return Err(PortablePlotError::new(
                    "layout_paper_units_unsupported",
                    "pixel paper units are not admitted by portable_2d_v1",
                ));
            }
            _ => {
                return Err(PortablePlotError::new(
                    "layout_paper_units_invalid",
                    "selected layout contains an invalid paper-unit code",
                ));
            }
        };
        for (value, name) in [
            (layout.plot_margin_left, "left"),
            (layout.plot_margin_bottom, "bottom"),
            (layout.plot_margin_right, "right"),
            (layout.plot_margin_top, "top"),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(PortablePlotError::new(
                    "layout_plot_margin_invalid",
                    format!("selected layout {name} plot margin is invalid"),
                ));
            }
        }
        if !all_finite(&[layout.plot_origin_x, layout.plot_origin_y]) {
            return Err(PortablePlotError::new(
                "layout_plot_origin_invalid",
                "selected layout plot origin must be finite",
            ));
        }
        let printable_width_mm =
            layout.paper_width - layout.plot_margin_left - layout.plot_margin_right;
        let printable_height_mm =
            layout.paper_height - layout.plot_margin_bottom - layout.plot_margin_top;
        if !finite_positive(printable_width_mm) || !finite_positive(printable_height_mm) {
            return Err(PortablePlotError::new(
                "layout_printable_area_invalid",
                "selected layout margins leave no finite positive printable area",
            ));
        }
        let plot_area =
            plot_area_bounds(layout, independent, printable_width_mm, printable_height_mm)?;
        let (plot_scale, plot_scale_applied) = resolve_plot_scale(
            layout,
            plot_flags,
            plot_area,
            printable_width_mm,
            printable_height_mm,
        )?;
        let source_to_page_scale = plot_scale * unit_scale;
        let (to_top_left, plot_area_applied) = if let Some(area) = plot_area {
            let plotted_width = area.width() * source_to_page_scale;
            let plotted_height = area.height() * source_to_page_scale;
            let (offset_x, offset_y) = if plot_flags.plot_centered {
                (
                    layout.plot_margin_left * POINTS_PER_MM
                        + (printable_width_mm * POINTS_PER_MM - plotted_width) / 2.0,
                    layout.plot_margin_bottom * POINTS_PER_MM
                        + (printable_height_mm * POINTS_PER_MM - plotted_height) / 2.0,
                )
            } else {
                (
                    (layout.plot_margin_left + layout.plot_origin_x) * POINTS_PER_MM,
                    (layout.plot_margin_bottom + layout.plot_origin_y) * POINTS_PER_MM,
                )
            };
            if !all_finite(&[
                source_to_page_scale,
                plotted_width,
                plotted_height,
                offset_x,
                offset_y,
            ]) {
                return Err(PortablePlotError::new(
                    "layout_plot_transform_invalid",
                    "selected layout plot transform produced non-finite geometry",
                ));
            }
            (
                Affine2::translation(Vector2::new(-area.min_x, -area.min_y)?)
                    .then(Affine2::scale(source_to_page_scale, -source_to_page_scale)?)?
                    .then(Affine2::translation(Vector2::new(
                        offset_x,
                        height - offset_y,
                    )?))?,
                true,
            )
        } else {
            let offset_x = (layout.plot_margin_left + layout.plot_origin_x) * POINTS_PER_MM;
            let offset_y = (layout.plot_margin_bottom + layout.plot_origin_y) * POINTS_PER_MM;
            (
                Affine2::scale(source_to_page_scale, -source_to_page_scale)?.then(
                    Affine2::translation(Vector2::new(offset_x, height - offset_y)?),
                )?,
                false,
            )
        };
        let (page, rotation) = match layout.plot_rotation {
            0 => (PageGeometry::new(width, height)?, Affine2::identity()),
            1 => (
                PageGeometry::new(height, width)?,
                Affine2::rotation(FRAC_PI_2)?
                    .then(Affine2::translation(Vector2::new(height, 0.0)?))?,
            ),
            2 => (
                PageGeometry::new(width, height)?,
                Affine2::rotation(PI)?.then(Affine2::translation(Vector2::new(width, height)?))?,
            ),
            3 => (
                PageGeometry::new(height, width)?,
                Affine2::rotation(-FRAC_PI_2)?
                    .then(Affine2::translation(Vector2::new(0.0, width)?))?,
            ),
            _ => {
                return Err(PortablePlotError::new(
                    "layout_rotation_invalid",
                    "selected layout contains an invalid plot-rotation code",
                ));
            }
        };
        let paper_to_page = to_top_left.then(rotation)?;
        let printable_clip = Rect {
            left: layout.plot_margin_left * POINTS_PER_MM,
            top: layout.plot_margin_top * POINTS_PER_MM,
            right: width - layout.plot_margin_right * POINTS_PER_MM,
            bottom: height - layout.plot_margin_bottom * POINTS_PER_MM,
        }
        .transformed(rotation)?
        .intersection(Rect::page(page))
        .ok_or_else(|| {
            PortablePlotError::new(
                "layout_printable_area_invalid",
                "selected layout printable area is empty after page rotation",
            )
        })?;
        let paper_clip = match plot_area {
            Some(area) => Rect {
                left: area.min_x,
                top: area.min_y,
                right: area.max_x,
                bottom: area.max_y,
            }
            .transformed(paper_to_page)?
            .intersection(printable_clip)
            .ok_or_else(|| {
                PortablePlotError::new(
                    "layout_plot_area_outside_media",
                    "selected plot area does not intersect the printable media",
                )
            })?,
            None => printable_clip,
        };
        Ok(Self {
            page,
            paper_to_page,
            paper_clip,
            plot_scale,
            plot_area_applied,
            plot_scale_applied,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct PlotAreaBounds {
    min_x: f64,
    min_y: f64,
    max_x: f64,
    max_y: f64,
}

impl PlotAreaBounds {
    fn new(min_x: f64, min_y: f64, max_x: f64, max_y: f64) -> Option<Self> {
        all_finite(&[min_x, min_y, max_x, max_y])
            .then_some(Self {
                min_x,
                min_y,
                max_x,
                max_y,
            })
            .filter(|bounds| bounds.max_x > bounds.min_x && bounds.max_y > bounds.min_y)
    }

    fn width(self) -> f64 {
        self.max_x - self.min_x
    }

    fn height(self) -> f64 {
        self.max_y - self.min_y
    }
}

fn plot_area_bounds(
    layout: &Layout,
    independent: Option<&LayoutRecord>,
    printable_width_mm: f64,
    printable_height_mm: f64,
) -> Result<Option<PlotAreaBounds>, PortablePlotError> {
    let bounds = match layout.plot_type {
        1 => independent.and_then(|layout| {
            layout.extents.and_then(|extents| {
                PlotAreaBounds::new(extents.min.x, extents.min.y, extents.max.x, extents.max.y)
            })
        }),
        2 => match independent {
            Some(layout) => Some(require_plot_area_bounds(
                layout.limits.min.x,
                layout.limits.min.y,
                layout.limits.max.x,
                layout.limits.max.y,
            )?),
            None => None,
        },
        4 => Some(require_plot_area_bounds(
            layout.plot_window_min_x,
            layout.plot_window_min_y,
            layout.plot_window_max_x,
            layout.plot_window_max_y,
        )?),
        5 => {
            let source_units_per_mm = match layout.plot_paper_units {
                0 => 1.0 / 25.4,
                1 => 1.0,
                2 => return Ok(None),
                _ => {
                    return Err(PortablePlotError::new(
                        "layout_paper_units_invalid",
                        "selected layout contains an invalid paper-unit code",
                    ))
                }
            };
            Some(require_plot_area_bounds(
                0.0,
                0.0,
                printable_width_mm * source_units_per_mm,
                printable_height_mm * source_units_per_mm,
            )?)
        }
        0 | 3 => None,
        _ => {
            return Err(PortablePlotError::new(
                "layout_plot_area_invalid",
                "selected layout contains an invalid plot-area code",
            ))
        }
    };
    Ok(bounds)
}

fn resolve_plot_scale(
    layout: &Layout,
    plot_flags: &PlotFlagsRecord,
    plot_area: Option<PlotAreaBounds>,
    printable_width_mm: f64,
    printable_height_mm: f64,
) -> Result<(f64, bool), PortablePlotError> {
    if layout.plot_type == 5 {
        return Ok((1.0, true));
    }
    if !plot_flags.use_standard_scale {
        return Ok((custom_plot_scale(layout)?, true));
    }
    match layout.plot_scale_type {
        0 => {
            let Some(area) = plot_area else {
                return Ok((custom_plot_scale(layout)?, false));
            };
            let paper_units_per_mm = match layout.plot_paper_units {
                0 => 1.0 / 25.4,
                1 => 1.0,
                2 => {
                    return Err(PortablePlotError::new(
                        "layout_paper_units_unsupported",
                        "pixel paper units are not admitted by portable_2d_v1",
                    ));
                }
                _ => {
                    return Err(PortablePlotError::new(
                        "layout_paper_units_invalid",
                        "selected layout contains an invalid paper-unit code",
                    ));
                }
            };
            let scale = (printable_width_mm * paper_units_per_mm / area.width())
                .min(printable_height_mm * paper_units_per_mm / area.height());
            if !finite_positive(scale) {
                return Err(PortablePlotError::new(
                    "layout_plot_scale_invalid",
                    "scale-to-fit produced no finite positive plot scale",
                ));
            }
            Ok((scale, true))
        }
        code @ 1..=32 => {
            let expected = standard_plot_scale_factor(code).ok_or_else(|| {
                PortablePlotError::new(
                    "layout_plot_scale_invalid",
                    "selected layout contains an unsupported standard-scale type",
                )
            })?;
            let actual = layout.plot_scale_factor;
            if !finite_positive(actual)
                || (actual - expected).abs()
                    > actual.abs().max(expected.abs()) * f64::EPSILON * 64.0
            {
                return Err(PortablePlotError::new(
                    "layout_plot_scale_contradictory",
                    "stored standard-scale type and floating scale factor disagree",
                ));
            }
            Ok((actual, true))
        }
        _ => Err(PortablePlotError::new(
            "layout_plot_scale_invalid",
            "selected layout contains an unsupported standard-scale type",
        )),
    }
}

fn custom_plot_scale(layout: &Layout) -> Result<f64, PortablePlotError> {
    if !finite_positive(layout.plot_scale_numerator)
        || !finite_positive(layout.plot_scale_denominator)
    {
        return Err(PortablePlotError::new(
            "layout_plot_scale_invalid",
            "selected layout has no finite positive stored custom plot scale",
        ));
    }
    let scale = layout.plot_scale_numerator / layout.plot_scale_denominator;
    if !finite_positive(scale) {
        return Err(PortablePlotError::new(
            "layout_plot_scale_invalid",
            "selected layout custom plot scale produced no finite positive ratio",
        ));
    }
    Ok(scale)
}

fn standard_plot_scale_factor(code: i16) -> Option<f64> {
    Some(match code {
        1 => 1.0 / 1536.0,
        2 => 1.0 / 768.0,
        3 => 1.0 / 384.0,
        4 => 1.0 / 192.0,
        5 => 1.0 / 128.0,
        6 => 1.0 / 96.0,
        7 => 1.0 / 64.0,
        8 => 1.0 / 48.0,
        9 => 1.0 / 32.0,
        10 => 1.0 / 24.0,
        11 => 1.0 / 16.0,
        12 => 1.0 / 12.0,
        13 => 1.0 / 4.0,
        14 => 1.0 / 2.0,
        15 | 16 => 1.0,
        17 => 1.0 / 2.0,
        18 => 1.0 / 4.0,
        19 => 1.0 / 8.0,
        20 => 1.0 / 10.0,
        21 => 1.0 / 16.0,
        22 => 1.0 / 20.0,
        23 => 1.0 / 30.0,
        24 => 1.0 / 40.0,
        25 => 1.0 / 50.0,
        26 => 1.0 / 100.0,
        27 => 2.0,
        28 => 4.0,
        29 => 8.0,
        30 => 10.0,
        31 => 100.0,
        32 => 1000.0,
        _ => return None,
    })
}

fn require_plot_area_bounds(
    min_x: f64,
    min_y: f64,
    max_x: f64,
    max_y: f64,
) -> Result<PlotAreaBounds, PortablePlotError> {
    PlotAreaBounds::new(min_x, min_y, max_x, max_y).ok_or_else(|| {
        PortablePlotError::new(
            "layout_plot_area_invalid",
            "selected layout plot-area bounds must be finite, ordered, and positive",
        )
    })
}

#[derive(Debug, Clone, Copy)]
struct Rect {
    left: f64,
    top: f64,
    right: f64,
    bottom: f64,
}

impl Rect {
    fn page(page: PageGeometry) -> Self {
        Self {
            left: 0.0,
            top: 0.0,
            right: page.width(),
            bottom: page.height(),
        }
    }

    fn path(self) -> Result<ScenePath, PortablePlotError> {
        ScenePath::rectangle(self.left, self.top, self.right, self.bottom)
    }

    fn transformed(self, transform: Affine2) -> Result<Self, PortablePlotError> {
        let corners = [
            transform.transform_point(Point2::new(self.left, self.top)?)?,
            transform.transform_point(Point2::new(self.right, self.top)?)?,
            transform.transform_point(Point2::new(self.right, self.bottom)?)?,
            transform.transform_point(Point2::new(self.left, self.bottom)?)?,
        ];
        let left = corners
            .iter()
            .map(|point| point.x())
            .fold(f64::INFINITY, f64::min);
        let top = corners
            .iter()
            .map(|point| point.y())
            .fold(f64::INFINITY, f64::min);
        let right = corners
            .iter()
            .map(|point| point.x())
            .fold(f64::NEG_INFINITY, f64::max);
        let bottom = corners
            .iter()
            .map(|point| point.y())
            .fold(f64::NEG_INFINITY, f64::max);
        if !all_finite(&[left, top, right, bottom]) || right <= left || bottom <= top {
            return Err(PortablePlotError::new(
                "layout_plot_clip_invalid",
                "selected layout plot clip is not a finite positive rectangle",
            ));
        }
        Ok(Self {
            left,
            top,
            right,
            bottom,
        })
    }

    fn intersection(self, other: Self) -> Option<Self> {
        let intersection = Self {
            left: self.left.max(other.left),
            top: self.top.max(other.top),
            right: self.right.min(other.right),
            bottom: self.bottom.min(other.bottom),
        };
        (intersection.right > intersection.left && intersection.bottom > intersection.top)
            .then_some(intersection)
    }
}

#[derive(Debug, Clone, Copy)]
struct ViewProjection {
    target: Point3,
    x_axis: Vector3,
    y_axis: Vector3,
    view_center_x: f64,
    view_center_y: f64,
    scale: f64,
    twist: f64,
    paper_center_x: f64,
    paper_center_y: f64,
}

#[derive(Debug, Clone)]
struct Projection {
    paper_to_page: Affine2,
    view: Option<ViewProjection>,
    clip: Rect,
    page_units_per_source_unit: f64,
    frozen_layers: BTreeSet<Handle>,
}

impl Projection {
    fn paper(paper_to_page: Affine2, page: PageGeometry) -> Result<Self, PortablePlotError> {
        let origin = paper_to_page.transform_point(Point2::new(0.0, 0.0)?)?;
        let unit = paper_to_page.transform_point(Point2::new(1.0, 0.0)?)?;
        let scale = (unit.x() - origin.x()).hypot(unit.y() - origin.y());
        Ok(Self {
            paper_to_page,
            view: None,
            clip: Rect::page(page),
            page_units_per_source_unit: scale,
            frozen_layers: BTreeSet::new(),
        })
    }

    fn viewport(
        viewport: &Viewport,
        paper_to_page: Affine2,
        page: PageGeometry,
        output_clip: Rect,
        document: &CadDocument,
    ) -> Result<Self, PortablePlotError> {
        if viewport.status.perspective
            || viewport.status.front_clipping
            || viewport.status.back_clipping
        {
            return Err(PortablePlotError::new(
                "viewport_projection_unsupported",
                "perspective and front/back clipping are outside portable_2d_v1",
            ));
        }
        if !matches!(
            viewport.render_mode,
            ViewportRenderMode::Wireframe2D | ViewportRenderMode::Wireframe3D
        ) || viewport.status.hide_plot
        {
            return Err(PortablePlotError::new(
                "viewport_render_mode_unsupported",
                "only non-hidden wireframe viewports are admitted",
            ));
        }
        if !viewport.clip_boundary_handle.is_null() {
            return Err(PortablePlotError::new(
                "viewport_clip_unsupported",
                "non-rectangular viewport clipping is not yet admitted",
            ));
        }
        if !finite_positive(viewport.width)
            || !finite_positive(viewport.height)
            || !finite_positive(viewport.view_height)
            || !all_finite(&[
                viewport.center.x,
                viewport.center.y,
                viewport.view_center.x,
                viewport.view_center.y,
                viewport.view_target.x,
                viewport.view_target.y,
                viewport.view_target.z,
                viewport.view_direction.x,
                viewport.view_direction.y,
                viewport.view_direction.z,
                viewport.twist_angle,
            ])
        {
            return Err(PortablePlotError::new(
                "viewport_geometry_invalid",
                "viewport geometry must be finite with positive width, height, and view height",
            ));
        }
        for frozen in &viewport.frozen_layers {
            if !document.layers.iter().any(|layer| layer.handle == *frozen) {
                return Err(PortablePlotError::new(
                    "viewport_frozen_layer_invalid",
                    "viewport references an unknown frozen layer",
                ));
            }
        }
        let frame = OcsFrame::from_normal(portable_vector(viewport.view_direction)?)?;
        let scale = viewport.height / viewport.view_height;
        let view = ViewProjection {
            target: portable_point(viewport.view_target)?,
            x_axis: frame.x_axis(),
            y_axis: frame.y_axis(),
            view_center_x: viewport.view_center.x,
            view_center_y: viewport.view_center.y,
            scale,
            twist: viewport.twist_angle,
            paper_center_x: viewport.center.x,
            paper_center_y: viewport.center.y,
        };
        let paper_bounds = [
            Point2::new(
                viewport.center.x - viewport.width / 2.0,
                viewport.center.y - viewport.height / 2.0,
            )?,
            Point2::new(
                viewport.center.x + viewport.width / 2.0,
                viewport.center.y + viewport.height / 2.0,
            )?,
        ];
        let first = paper_to_page.transform_point(paper_bounds[0])?;
        let second = paper_to_page.transform_point(paper_bounds[1])?;
        let viewport_clip = Rect {
            left: first.x().min(second.x()).max(0.0),
            top: first.y().min(second.y()).max(0.0),
            right: first.x().max(second.x()).min(page.width()),
            bottom: first.y().max(second.y()).min(page.height()),
        };
        let clip = viewport_clip.intersection(output_clip).ok_or_else(|| {
            PortablePlotError::new(
                "viewport_geometry_invalid",
                "viewport clip rectangle is empty after plot-area clipping",
            )
        })?;
        let paper_origin = paper_to_page.transform_point(Point2::new(0.0, 0.0)?)?;
        let paper_unit = paper_to_page.transform_point(Point2::new(1.0, 0.0)?)?;
        let paper_scale =
            (paper_unit.x() - paper_origin.x()).hypot(paper_unit.y() - paper_origin.y());
        Ok(Self {
            paper_to_page,
            view: Some(view),
            clip,
            page_units_per_source_unit: scale.abs() * paper_scale,
            frozen_layers: viewport.frozen_layers.iter().copied().collect(),
        })
    }

    fn project(&self, parent: Affine3, point: CadVector3) -> Result<Point2, PortablePlotError> {
        let world = parent.transform_point(portable_point(point)?)?;
        let paper = if let Some(view) = self.view {
            let delta = Vector3::new(
                world.x() - view.target.x(),
                world.y() - view.target.y(),
                world.z() - view.target.z(),
            )?;
            let dcs_x = dot(delta, view.x_axis) - view.view_center_x;
            let dcs_y = dot(delta, view.y_axis) - view.view_center_y;
            let cosine = view.twist.cos();
            let sine = view.twist.sin();
            let twisted_x = cosine * dcs_x + sine * dcs_y;
            let twisted_y = -sine * dcs_x + cosine * dcs_y;
            Point2::new(
                view.paper_center_x + twisted_x * view.scale,
                view.paper_center_y + twisted_y * view.scale,
            )?
        } else {
            Point2::new(world.x(), world.y())?
        };
        self.paper_to_page.transform_point(paper)
    }

    fn clip_path(&self) -> Result<ScenePath, PortablePlotError> {
        self.clip.path()
    }
}

fn dot(left: Vector3, right: Vector3) -> f64 {
    left.x() * right.x() + left.y() * right.y() + left.z() * right.z()
}

fn project_ocs_offset(
    point: Point3,
    normal_x: f64,
    normal_y: f64,
    normal_scale: f64,
    ocs: OcsFrame,
    parent: Affine3,
    projection: &Projection,
) -> Result<Point2, PortablePlotError> {
    let offset = Point3::new(
        point.x() + normal_x * normal_scale,
        point.y() + normal_y * normal_scale,
        point.z(),
    )?;
    projection.project(parent, cad_point(ocs.point_to_wcs(offset)?))
}

#[derive(Debug, Clone)]
struct InsertStyle {
    layer: String,
    color: ConcreteColor,
    lineweight_points: f64,
    linetype: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextHAlign {
    Left,
    Center,
    Right,
    Aligned,
    Middle,
    Fit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextVAlign {
    Baseline,
    Bottom,
    Middle,
    Top,
}

struct TextSpec<'a> {
    value: &'a str,
    insertion_point: CadVector3,
    alignment_point: Option<CadVector3>,
    height: f64,
    rotation: f64,
    width_factor: f64,
    oblique_angle: f64,
    style: &'a str,
    horizontal: TextHAlign,
    vertical: TextVAlign,
    normal: CadVector3,
    generation_flags: i16,
}

#[derive(Default)]
struct TextRunOverrides<'a> {
    font_identity: Option<&'a str>,
    color: Option<SceneColor>,
    height: Option<f64>,
    width_factor: Option<f64>,
    oblique_angle: Option<f64>,
    normalized_text: bool,
}

struct CompiledTextRun {
    nodes: Vec<DisplayNode>,
    advance: f64,
    font: Option<CompiledTextFont>,
    normalization_error_points: f64,
    stroke_path_commands: usize,
}

#[derive(Debug, Clone)]
enum CompiledTextFont {
    Outline(FontId, FontResolution),
    Stroke {
        fonts: Vec<StrokeFontId>,
        composite: Option<CompositeFontId>,
    },
}

struct ResolvedShxGlyph<'a> {
    font: &'a ShxStrokeFontResource,
    glyph: &'a ShxStrokeGlyph,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MTextColorSpec {
    Inherit,
    Aci(u16),
    Rgb(u8, u8, u8),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum MTextHeightSpec {
    Factor(f64),
    Absolute(f64),
}

#[derive(Debug, Clone, PartialEq)]
struct MTextRunFormat {
    color: MTextColorSpec,
    font_identity: Option<String>,
    height: MTextHeightSpec,
    width_factor: f64,
    oblique_angle: Option<f64>,
}

impl Default for MTextRunFormat {
    fn default() -> Self {
        Self {
            color: MTextColorSpec::Inherit,
            font_identity: None,
            height: MTextHeightSpec::Factor(1.0),
            width_factor: 1.0,
            oblique_angle: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct MTextRunSpec {
    text: String,
    format: MTextRunFormat,
}

#[derive(Debug, Clone, PartialEq)]
struct ParsedMText {
    paragraphs: Vec<Vec<MTextRunSpec>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MTextParseFailureKind {
    Invalid,
    Omitted,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MTextParseFailure {
    kind: MTextParseFailureKind,
    code: &'static str,
    message: &'static str,
}

impl MTextParseFailure {
    const fn invalid(code: &'static str, message: &'static str) -> Self {
        Self {
            kind: MTextParseFailureKind::Invalid,
            code,
            message,
        }
    }

    const fn unsupported(code: &'static str, message: &'static str) -> Self {
        Self {
            kind: MTextParseFailureKind::Unsupported,
            code,
            message,
        }
    }

    const fn omitted(code: &'static str, message: &'static str) -> Self {
        Self {
            kind: MTextParseFailureKind::Omitted,
            code,
            message,
        }
    }

    const fn disposition(self) -> FidelityDisposition {
        match self.kind {
            MTextParseFailureKind::Invalid => FidelityDisposition::Invalid,
            MTextParseFailureKind::Omitted => FidelityDisposition::Omitted,
            MTextParseFailureKind::Unsupported => FidelityDisposition::Unsupported,
        }
    }
}

struct ClosedMTextParser {
    characters: Vec<char>,
    position: usize,
    contexts: Vec<MTextRunFormat>,
    paragraphs: Vec<Vec<MTextRunSpec>>,
    text: String,
    max_depth: usize,
    max_runs: usize,
    run_count: usize,
}

struct Compiler<'a, 'ledger> {
    document: &'a CadDocument,
    resources: &'a PortableResourceBundle,
    plot_style: Option<&'a PlotStyleResource>,
    limits: PortablePlotLimits,
    ledger: &'ledger mut DiagnosticLedger,
    print_lineweights: bool,
    lineweight_scale: f64,
    plot_viewport_borders: bool,
    curve_segments: usize,
    insert_instances: usize,
    rendered_viewports: usize,
    used_fonts: BTreeSet<FontId>,
    used_stroke_fonts: BTreeSet<StrokeFontId>,
    used_composite_fonts: BTreeSet<CompositeFontId>,
    stroke_path_commands: usize,
}

impl<'document, 'ledger> Compiler<'document, 'ledger> {
    fn record_global_limitations(
        &mut self,
        layout: &Layout,
        plot_flags: &PlotFlagsRecord,
        plot_style_bound: bool,
        plot_area_applied: bool,
        plot_scale_applied: bool,
    ) -> Result<(), PortablePlotError> {
        self.diagnostic(
            "transparency_inheritance_unavailable",
            "SOURCE_STYLE",
            None,
            FidelityDisposition::Omitted,
            "Acadrust 0.4.1 does not retain ByLayer versus ByBlock transparency mode",
        )?;
        if plot_flags.plot_plot_styles {
            let limitation = if !self.document.header.plotstyle_mode {
                Some((
                    "named_plot_style_application_omitted",
                    "the selected layout uses named STB plot styles, which portable_ctb_v1 does not implement",
                ))
            } else if layout.plot_style_sheet.is_empty() {
                Some((
                    "plot_style_identity_unavailable",
                    "the selected layout enables plot styles without a stored CTB identity",
                ))
            } else if !plot_style_bound {
                Some((
                    "plot_style_application_omitted",
                    "the selected layout requests a CTB resource absent from the immutable bundle",
                ))
            } else {
                None
            };
            if let Some((code, message)) = limitation {
                self.diagnostic(
                    code,
                    "LAYOUT",
                    source_handle(layout.handle)?,
                    FidelityDisposition::Omitted,
                    message,
                )?;
            }
        }
        if !plot_area_applied {
            self.diagnostic(
                "plot_area_substituted",
                "LAYOUT",
                source_handle(layout.handle)?,
                FidelityDisposition::Substituted,
                "the requested plot area lacks stable stored bounds and is replaced by the selected layout paper area",
            )?;
        }
        if !plot_scale_applied {
            self.diagnostic(
                "plot_scale_substituted",
                "LAYOUT",
                source_handle(layout.handle)?,
                FidelityDisposition::Substituted,
                "scale-to-fit cannot be derived from the selected plot-area semantics and uses the stored custom-scale ratio",
            )?;
        }
        if plot_flags.plot_hidden {
            self.diagnostic(
                "paper_space_hidden_line_omitted",
                "LAYOUT",
                source_handle(layout.handle)?,
                FidelityDisposition::Omitted,
                "the selected layout requests hidden-line processing for paper-space objects",
            )?;
        }
        Ok(())
    }

    fn compile_owner(
        &mut self,
        owner: Handle,
        parent: Affine3,
        insert_style: Option<InsertStyle>,
        projection: &Projection,
        depth: usize,
    ) -> Result<Vec<DisplayNode>, PortablePlotError> {
        let root_entities = self
            .document
            .entities()
            .filter(|entity| entity.common().owner_handle == owner)
            .collect::<Vec<_>>();
        let mut pending = root_entities
            .into_iter()
            .rev()
            .map(|entity| EntityTask {
                entity,
                parent,
                insert_style: insert_style.clone(),
                depth,
            })
            .collect::<Vec<_>>();
        let mut output = Vec::new();
        while let Some(task) = pending.pop() {
            let common = task.entity.common();
            let style = match self.resolve_style(common, task.insert_style.as_ref(), projection) {
                Ok(style) => style,
                Err(error) => {
                    self.invalid_entity(task.entity, error.message())?;
                    continue;
                }
            };
            if !style.visible {
                self.ledger.record_source(
                    task.entity.as_entity().entity_type(),
                    FidelityDisposition::Exact,
                )?;
                continue;
            }
            if let EntityType::Insert(insert) = task.entity {
                self.compile_insert(insert, task, style, projection, &mut pending, &mut output)?;
                continue;
            }
            if let EntityType::Dimension(dimension) = task.entity {
                self.compile_dimension(dimension, task, style, &mut pending)?;
                continue;
            }
            match self.compile_primitive(task.entity, task.parent, projection, &style) {
                Ok(Some(compiled)) => {
                    output.extend(compiled.nodes);
                    self.ledger.record_source(
                        task.entity.as_entity().entity_type(),
                        compiled.disposition,
                    )?;
                    if let Some((name, error)) = compiled.tolerance {
                        self.ledger.record_tolerance(name, error)?;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    self.invalid_entity(task.entity, error.message())?;
                }
            }
        }
        Ok(output)
    }

    fn compile_dimension(
        &mut self,
        dimension: &'document Dimension,
        task: EntityTask<'document>,
        style: ResolvedStyle,
        pending: &mut Vec<EntityTask<'document>>,
    ) -> Result<(), PortablePlotError> {
        let base = dimension.base();
        let source_type = task.entity.as_entity().entity_type();
        let source = source_handle(base.common.handle)?;
        if task.depth >= self.limits.max_insert_depth {
            return self.diagnostic(
                "dimension_graphics_depth_budget_exceeded",
                source_type,
                source,
                FidelityDisposition::Invalid,
                "generated dimension graphics exceed the configured block-expansion depth",
            );
        }
        if base.block_name.is_empty() {
            return self.diagnostic(
                "dimension_graphics_missing",
                source_type,
                source,
                FidelityDisposition::Omitted,
                "dimension has no stored anonymous graphics-block identity",
            );
        }
        let matches = self
            .document
            .block_records
            .iter()
            .filter(|block| block.name == base.block_name)
            .collect::<Vec<_>>();
        let [block] = matches.as_slice() else {
            return self.diagnostic(
                "dimension_graphics_ambiguous",
                source_type,
                source,
                FidelityDisposition::Invalid,
                "dimension graphics do not resolve to exactly one anonymous block definition",
            );
        };
        if !is_dimension_graphics_block(block) {
            return self.diagnostic(
                "dimension_graphics_not_anonymous",
                source_type,
                source,
                FidelityDisposition::Invalid,
                "dimension graphics must resolve to an anonymous *D block definition",
            );
        }
        if block_has_external_semantics(block) {
            return self.diagnostic(
                "dimension_graphics_external",
                source_type,
                source,
                FidelityDisposition::Unsupported,
                "dimension graphics must be an embedded anonymous block",
            );
        }
        if block.base_point != CadVector3::ZERO
            || base.insertion_point != CadVector3::ZERO
            || base.normal != CadVector3::new(0.0, 0.0, 1.0)
        {
            return self.diagnostic(
                "dimension_graphics_transform_unsupported",
                source_type,
                source,
                FidelityDisposition::Unsupported,
                "stored dimension graphics are admitted only at zero base and insertion with the world-Z normal",
            );
        }
        let children = self
            .document
            .entities()
            .filter(|entity| entity.common().owner_handle == block.handle)
            .collect::<Vec<_>>();
        if children.is_empty() {
            return self.diagnostic(
                "dimension_graphics_missing",
                source_type,
                source,
                FidelityDisposition::Omitted,
                "dimension anonymous graphics block contains no drawable entities",
            );
        }
        self.insert_instances = self.insert_instances.checked_add(1).ok_or_else(|| {
            PortablePlotError::new(
                "insert_instance_budget_exceeded",
                "generated annotation block-expansion count overflowed",
            )
        })?;
        if self.insert_instances > self.limits.max_insert_instances {
            return self.diagnostic(
                "insert_instance_budget_exceeded",
                source_type,
                source,
                FidelityDisposition::Invalid,
                "generated annotation block expansion exceeds the configured instance limit",
            );
        }
        let child_style = InsertStyle {
            layer: style.effective_layer,
            color: style.cad_color,
            lineweight_points: style.cad_lineweight_points,
            linetype: style.linetype_name,
        };
        pending.extend(children.iter().rev().map(|entity| EntityTask {
            entity,
            parent: task.parent,
            insert_style: Some(child_style.clone()),
            depth: task.depth + 1,
        }));
        self.ledger
            .record_source(source_type, FidelityDisposition::Exact)?;
        Ok(())
    }

    fn compile_insert(
        &mut self,
        insert: &'document Insert,
        task: EntityTask<'document>,
        style: ResolvedStyle,
        projection: &Projection,
        pending: &mut Vec<EntityTask<'document>>,
        output: &mut Vec<DisplayNode>,
    ) -> Result<(), PortablePlotError> {
        if task.depth >= self.limits.max_insert_depth {
            return self.diagnostic(
                "insert_depth_budget_exceeded",
                "INSERT",
                source_handle(insert.common.handle)?,
                FidelityDisposition::Invalid,
                "nested insert depth exceeds the configured compiler limit",
            );
        }
        let matches = self
            .document
            .block_records
            .iter()
            .filter(|block| block.name == insert.block_name)
            .collect::<Vec<_>>();
        let [block] = matches.as_slice() else {
            return self.diagnostic(
                "insert_definition_ambiguous",
                "INSERT",
                source_handle(insert.common.handle)?,
                FidelityDisposition::Invalid,
                "insert does not resolve to exactly one block definition",
            );
        };
        if block_has_external_semantics(block) {
            let bound = if block.xref_path.is_empty() {
                None
            } else {
                self.resources.resolve_xref(&block.xref_path)?
            };
            return self.diagnostic(
                if bound.is_some() {
                    "xref_semantic_expansion_deferred"
                } else {
                    "xref_dependency_unresolved"
                },
                "INSERT",
                source_handle(insert.common.handle)?,
                FidelityDisposition::Unsupported,
                if bound.is_some() {
                    "the XREF is digest-bound but cross-document semantic expansion is not yet admitted"
                } else {
                    "XREF insert requires a digest-bound dependency bundle"
                },
            );
        }
        if block.base_point != CadVector3::ZERO {
            return self.diagnostic(
                "block_base_point_unqualified",
                "INSERT",
                source_handle(insert.common.handle)?,
                FidelityDisposition::Unsupported,
                "nonzero block base points lack an independent modern-DWG oracle",
            );
        }
        let instances = usize::from(insert.column_count)
            .checked_mul(usize::from(insert.row_count))
            .ok_or_else(|| {
                PortablePlotError::new(
                    "insert_instance_budget_exceeded",
                    "insert array size overflowed",
                )
            })?;
        self.insert_instances = self
            .insert_instances
            .checked_add(instances)
            .ok_or_else(|| {
                PortablePlotError::new(
                    "insert_instance_budget_exceeded",
                    "insert expansion count overflowed",
                )
            })?;
        if instances == 0 || self.insert_instances > self.limits.max_insert_instances {
            return self.diagnostic(
                "insert_instance_budget_exceeded",
                "INSERT",
                source_handle(insert.common.handle)?,
                FidelityDisposition::Invalid,
                "insert expansion exceeds the configured compiler limit",
            );
        }
        let children = self
            .document
            .entities()
            .filter(|entity| entity.common().owner_handle == block.handle)
            .collect::<Vec<_>>();
        let child_style = InsertStyle {
            layer: style.effective_layer,
            color: style.cad_color,
            lineweight_points: style.cad_lineweight_points,
            linetype: style.linetype_name,
        };
        if instances > 1 && !insert.attributes.is_empty() {
            self.diagnostic(
                "array_insert_attributes_omitted",
                "ATTRIB",
                source_handle(insert.common.handle)?,
                FidelityDisposition::Omitted,
                "attribute text is omitted for array INSERT entities because its placement is ambiguous",
            )?;
        } else {
            for attribute in &insert.attributes {
                let attribute_style =
                    self.resolve_style(&attribute.common, Some(&child_style), projection)?;
                if !attribute_style.visible || attribute.flags.invisible {
                    self.ledger
                        .record_source("ATTRIB", FidelityDisposition::Exact)?;
                    continue;
                }
                if let Some(compiled) = self.compile_attribute(
                    attribute,
                    task.parent,
                    projection,
                    &attribute_style,
                    source_handle(attribute.common.handle)?,
                    "ATTRIB",
                )? {
                    output.extend(compiled.nodes);
                    self.ledger.record_source("ATTRIB", compiled.disposition)?;
                }
            }
        }
        let array_points = insert.array_points();
        for insertion_point in array_points.into_iter().rev() {
            let transform = BlockInsertTransform3::new(
                portable_point(block.base_point)?,
                portable_point(insertion_point)?,
                portable_vector(CadVector3::new(
                    insert.x_scale(),
                    insert.y_scale(),
                    insert.z_scale(),
                ))?,
                insert.rotation,
                portable_vector(insert.normal)?,
            )?
            .affine()
            .then(task.parent)?;
            pending.extend(children.iter().rev().map(|entity| EntityTask {
                entity,
                parent: transform,
                insert_style: Some(child_style.clone()),
                depth: task.depth + 1,
            }));
        }
        self.ledger
            .record_source("INSERT", FidelityDisposition::Exact)?;
        // Geometry compilation performs page-space style resolution; this
        // reference keeps the viewport context explicit for future per-insert
        // linetype scale work.
        let _ = projection;
        Ok(())
    }

    fn compile_primitive(
        &mut self,
        entity: &EntityType,
        parent: Affine3,
        projection: &Projection,
        style: &ResolvedStyle,
    ) -> Result<Option<CompiledPrimitive>, PortablePlotError> {
        let source = source_handle(entity.common().handle)?;
        let stroke = || style.stroke();
        match entity {
            EntityType::Line(line) => {
                let path = ScenePath::polyline(
                    [
                        projection.project(parent, line.start)?,
                        projection.project(parent, line.end)?,
                    ],
                    false,
                )?;
                Ok(Some(CompiledPrimitive::exact(vec![DisplayNode::Path(
                    PathNode::new(path, None, Some(stroke()?), source)?,
                )])))
            }
            EntityType::Point(point) => {
                let center = projection.project(parent, point.location)?;
                let half = 0.5;
                let path = ScenePath::new(vec![
                    PathCommand::MoveTo(Point2::new(center.x() - half, center.y())?),
                    PathCommand::LineTo(Point2::new(center.x() + half, center.y())?),
                    PathCommand::MoveTo(Point2::new(center.x(), center.y() - half)?),
                    PathCommand::LineTo(Point2::new(center.x(), center.y() + half)?),
                ])?;
                Ok(Some(CompiledPrimitive::tolerance(
                    vec![DisplayNode::Path(PathNode::new(
                        path,
                        None,
                        Some(stroke()?),
                        source,
                    )?)],
                    "point_marker",
                    0.5,
                )))
            }
            EntityType::Circle(circle) => {
                if !finite_positive(circle.radius) {
                    return Err(PortablePlotError::new(
                        "entity_geometry_invalid",
                        "circle radius must be finite and positive",
                    ));
                }
                let frame = OcsFrame::from_normal(portable_vector(circle.normal)?)?;
                let center = portable_point(circle.center)?;
                let path = self.elliptic_arc(
                    parent,
                    projection,
                    |parameter| {
                        let ocs = Point3::new(
                            center.x() + circle.radius * parameter.cos(),
                            center.y() + circle.radius * parameter.sin(),
                            center.z(),
                        )?;
                        frame.point_to_wcs(ocs)
                    },
                    0.0,
                    TAU,
                )?;
                Ok(Some(CompiledPrimitive::tolerance(
                    vec![DisplayNode::Path(PathNode::new(
                        path.path,
                        None,
                        Some(stroke()?),
                        source,
                    )?)],
                    "cubic_curve_flattening",
                    path.error,
                )))
            }
            EntityType::Arc(arc) => {
                if !finite_positive(arc.radius) || !all_finite(&[arc.start_angle, arc.end_angle]) {
                    return Err(PortablePlotError::new(
                        "entity_geometry_invalid",
                        "arc radius and angles must be finite and radius must be positive",
                    ));
                }
                let frame = OcsFrame::from_normal(portable_vector(arc.normal)?)?;
                let center = portable_point(arc.center)?;
                let mut sweep = arc.end_angle - arc.start_angle;
                while sweep <= 0.0 {
                    sweep += TAU;
                }
                let path = self.elliptic_arc(
                    parent,
                    projection,
                    |parameter| {
                        frame.point_to_wcs(Point3::new(
                            center.x() + arc.radius * parameter.cos(),
                            center.y() + arc.radius * parameter.sin(),
                            center.z(),
                        )?)
                    },
                    arc.start_angle,
                    arc.start_angle + sweep.min(TAU),
                )?;
                Ok(Some(CompiledPrimitive::tolerance(
                    vec![DisplayNode::Path(PathNode::new(
                        path.path,
                        None,
                        Some(stroke()?),
                        source,
                    )?)],
                    "cubic_curve_flattening",
                    path.error,
                )))
            }
            EntityType::Ellipse(ellipse) => {
                if !finite_positive(ellipse.minor_axis_ratio)
                    || ellipse.minor_axis_ratio > 1.0
                    || !all_finite(&[ellipse.start_parameter, ellipse.end_parameter])
                {
                    return Err(PortablePlotError::new(
                        "entity_geometry_invalid",
                        "ellipse ratio and parameters are outside the admitted finite range",
                    ));
                }
                let major = portable_vector(ellipse.major_axis)?;
                let major_length =
                    (major.x() * major.x() + major.y() * major.y() + major.z() * major.z()).sqrt();
                if !finite_positive(major_length) {
                    return Err(PortablePlotError::new(
                        "entity_geometry_invalid",
                        "ellipse major axis must be finite and nonzero",
                    ));
                }
                let normal = OcsFrame::from_normal(portable_vector(ellipse.normal)?)?.normal();
                if dot(normal, major).abs()
                    > 1.0e-10 * (major.x().abs() + major.y().abs() + major.z().abs()).max(1.0)
                {
                    return Err(PortablePlotError::new(
                        "entity_geometry_invalid",
                        "ellipse major axis must be perpendicular to its normal",
                    ));
                }
                let minor = cross(normal, major)?;
                let minor = scale_vector(minor, ellipse.minor_axis_ratio)?;
                let center = portable_point(ellipse.center)?;
                let mut sweep = ellipse.end_parameter - ellipse.start_parameter;
                while sweep <= 0.0 {
                    sweep += TAU;
                }
                let path = self.elliptic_arc(
                    parent,
                    projection,
                    |parameter| {
                        Point3::new(
                            center.x() + major.x() * parameter.cos() + minor.x() * parameter.sin(),
                            center.y() + major.y() * parameter.cos() + minor.y() * parameter.sin(),
                            center.z() + major.z() * parameter.cos() + minor.z() * parameter.sin(),
                        )
                    },
                    ellipse.start_parameter,
                    ellipse.start_parameter + sweep.min(TAU),
                )?;
                Ok(Some(CompiledPrimitive::tolerance(
                    vec![DisplayNode::Path(PathNode::new(
                        path.path,
                        None,
                        Some(stroke()?),
                        source,
                    )?)],
                    "cubic_curve_flattening",
                    path.error,
                )))
            }
            EntityType::LwPolyline(polyline) => self
                .compile_lwpolyline(polyline, parent, projection, style, source)
                .map(Some),
            EntityType::Polyline2D(polyline) => self
                .compile_polyline2d(polyline, parent, projection, style, source)
                .map(Some),
            EntityType::Solid(solid) => {
                let frame = OcsFrame::from_normal(portable_vector(solid.normal)?)?;
                let corners = solid
                    .corners()
                    .into_iter()
                    .map(|corner| {
                        frame
                            .point_to_wcs(portable_point(corner)?)
                            .and_then(|point| projection.project(parent, cad_point(point)))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let path = ScenePath::polyline(corners, true)?;
                Ok(Some(CompiledPrimitive::exact(vec![DisplayNode::Path(
                    PathNode::new(
                        path,
                        Some(Fill::new(style.color, FillRule::NonZero)),
                        Some(stroke()?),
                        source,
                    )?,
                )])))
            }
            EntityType::Face3D(face) => {
                let nodes = compile_face(face, parent, projection, style, source)?;
                Ok(Some(CompiledPrimitive::exact(nodes)))
            }
            EntityType::Ray(ray) => {
                let node = self.infinite_line(
                    ray.base_point,
                    ray.direction,
                    true,
                    parent,
                    projection,
                    style,
                    source,
                )?;
                Ok(Some(CompiledPrimitive::exact(node.into_iter().collect())))
            }
            EntityType::XLine(line) => {
                let node = self.infinite_line(
                    line.base_point,
                    line.direction,
                    false,
                    parent,
                    projection,
                    style,
                    source,
                )?;
                Ok(Some(CompiledPrimitive::exact(node.into_iter().collect())))
            }
            EntityType::Viewport(viewport) => {
                if self.plot_viewport_borders && viewport.id > 1 && viewport.status.is_on {
                    if !finite_positive(viewport.width)
                        || !finite_positive(viewport.height)
                        || !viewport.center.x.is_finite()
                        || !viewport.center.y.is_finite()
                    {
                        return Err(PortablePlotError::new(
                            "viewport_border_geometry_invalid",
                            "plotted viewport border geometry must be finite and positive",
                        ));
                    }
                    let half_width = viewport.width / 2.0;
                    let half_height = viewport.height / 2.0;
                    let corners = [
                        CadVector3::new(
                            viewport.center.x - half_width,
                            viewport.center.y - half_height,
                            viewport.center.z,
                        ),
                        CadVector3::new(
                            viewport.center.x + half_width,
                            viewport.center.y - half_height,
                            viewport.center.z,
                        ),
                        CadVector3::new(
                            viewport.center.x + half_width,
                            viewport.center.y + half_height,
                            viewport.center.z,
                        ),
                        CadVector3::new(
                            viewport.center.x - half_width,
                            viewport.center.y + half_height,
                            viewport.center.z,
                        ),
                    ];
                    let points = corners
                        .into_iter()
                        .map(|corner| projection.project(parent, corner))
                        .collect::<Result<Vec<_>, _>>()?;
                    let path = ScenePath::polyline(points, true)?;
                    return Ok(Some(CompiledPrimitive::exact(vec![DisplayNode::Path(
                        PathNode::new(path, None, Some(stroke()?), source)?,
                    )])));
                }
                self.ledger
                    .record_source(entity.as_entity().entity_type(), FidelityDisposition::Exact)?;
                Ok(None)
            }
            EntityType::Seqend(_) => {
                self.ledger
                    .record_source(entity.as_entity().entity_type(), FidelityDisposition::Exact)?;
                Ok(None)
            }
            EntityType::Text(text) => {
                self.compile_text(text, parent, projection, style, source, "TEXT")
            }
            EntityType::MText(text) => self.compile_mtext(text, parent, projection, style, source),
            EntityType::AttributeEntity(attribute) => {
                self.compile_attribute(attribute, parent, projection, style, source, "ATTRIB")
            }
            EntityType::AttributeDefinition(attribute) => {
                self.compile_attribute_definition(attribute, parent, projection, style, source)
            }
            EntityType::Hatch(hatch) => {
                self.compile_hatch(hatch, parent, projection, style, source)
            }
            EntityType::Wipeout(wipeout) => {
                self.compile_wipeout(wipeout, parent, projection, source)
            }
            EntityType::Spline(_) => {
                self.diagnostic(
                    "spline_omitted",
                    "SPLINE",
                    source,
                    FidelityDisposition::Omitted,
                    "spline geometry is deliberately omitted pending the bounded NURBS evaluator",
                )?;
                Ok(None)
            }
            EntityType::RasterImage(_) | EntityType::Underlay(_) => {
                self.unsupported_entity(
                    entity,
                    "external_resource_unresolved",
                    "visible external resources require digest-bound bundle members",
                )?;
                Ok(None)
            }
            _ => {
                self.unsupported_entity(
                    entity,
                    "entity_type_unsupported",
                    "visible entity family has no admitted portable semantic compiler",
                )?;
                Ok(None)
            }
        }
    }

    fn compile_hatch(
        &mut self,
        hatch: &Hatch,
        parent: Affine3,
        projection: &Projection,
        style: &ResolvedStyle,
        source: Option<SourceHandle>,
    ) -> Result<Option<CompiledPrimitive>, PortablePlotError> {
        if !hatch.is_solid || hatch.gradient_color.enabled || hatch.style != HatchStyleType::Normal
        {
            self.diagnostic(
                "patterned_hatch_omitted",
                "HATCH",
                source,
                FidelityDisposition::Omitted,
                "patterned, gradient, and non-normal island-style hatches are deliberately omitted",
            )?;
            return Ok(None);
        }
        if hatch.paths.is_empty() {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "solid hatch must contain at least one closed boundary",
            ));
        }
        let frame = OcsFrame::from_normal(portable_vector(hatch.normal)?)?;
        let mut commands = Vec::new();
        let mut maximum_error = 0.0_f64;
        for boundary in &hatch.paths {
            if boundary.flags.is_not_closed()
                || (boundary.flags.bits()
                    & (acadrust::entities::BoundaryPathFlags::SELF_INTERSECTING.bits()
                        | acadrust::entities::BoundaryPathFlags::DUPLICATE.bits()))
                    != 0
                || boundary.edges.is_empty()
            {
                return Err(PortablePlotError::new(
                    "entity_geometry_invalid",
                    "hatch boundaries must be nonempty, closed, and non-self-intersecting",
                ));
            }
            let mut started = false;
            for edge in &boundary.edges {
                match edge {
                    BoundaryEdge::Line(line) => {
                        let start = projection.project(
                            parent,
                            cad_point(frame.point_to_wcs(Point3::new(
                                line.start.x,
                                line.start.y,
                                hatch.elevation,
                            )?)?),
                        )?;
                        let end = projection.project(
                            parent,
                            cad_point(frame.point_to_wcs(Point3::new(
                                line.end.x,
                                line.end.y,
                                hatch.elevation,
                            )?)?),
                        )?;
                        if !started {
                            commands.push(PathCommand::MoveTo(start));
                            started = true;
                        }
                        commands.push(PathCommand::LineTo(end));
                    }
                    BoundaryEdge::CircularArc(arc) => {
                        if !finite_positive(arc.radius)
                            || !all_finite(&[arc.start_angle, arc.end_angle])
                        {
                            return Err(PortablePlotError::new(
                                "entity_geometry_invalid",
                                "hatch circular arc geometry is invalid",
                            ));
                        }
                        let sweep =
                            directed_sweep(arc.start_angle, arc.end_angle, arc.counter_clockwise)?;
                        let curve = self.elliptic_arc(
                            parent,
                            projection,
                            |parameter| {
                                frame.point_to_wcs(Point3::new(
                                    arc.center.x + arc.radius * parameter.cos(),
                                    arc.center.y + arc.radius * parameter.sin(),
                                    hatch.elevation,
                                )?)
                            },
                            arc.start_angle,
                            arc.start_angle + sweep,
                        )?;
                        append_curve_commands(&mut commands, &curve.path, &mut started);
                        maximum_error = maximum_error.max(curve.error);
                    }
                    BoundaryEdge::EllipticArc(arc) => {
                        let major_length =
                            arc.major_axis_endpoint.x.hypot(arc.major_axis_endpoint.y);
                        if !finite_positive(major_length)
                            || !finite_positive(arc.minor_axis_ratio)
                            || arc.minor_axis_ratio > 1.0
                            || !all_finite(&[arc.start_angle, arc.end_angle])
                        {
                            return Err(PortablePlotError::new(
                                "entity_geometry_invalid",
                                "hatch elliptic arc geometry is invalid",
                            ));
                        }
                        let minor_x = -arc.major_axis_endpoint.y * arc.minor_axis_ratio;
                        let minor_y = arc.major_axis_endpoint.x * arc.minor_axis_ratio;
                        let sweep =
                            directed_sweep(arc.start_angle, arc.end_angle, arc.counter_clockwise)?;
                        let curve = self.elliptic_arc(
                            parent,
                            projection,
                            |parameter| {
                                frame.point_to_wcs(Point3::new(
                                    arc.center.x
                                        + arc.major_axis_endpoint.x * parameter.cos()
                                        + minor_x * parameter.sin(),
                                    arc.center.y
                                        + arc.major_axis_endpoint.y * parameter.cos()
                                        + minor_y * parameter.sin(),
                                    hatch.elevation,
                                )?)
                            },
                            arc.start_angle,
                            arc.start_angle + sweep,
                        )?;
                        append_curve_commands(&mut commands, &curve.path, &mut started);
                        maximum_error = maximum_error.max(curve.error);
                    }
                    BoundaryEdge::Polyline(polyline) => {
                        if !polyline.is_closed || polyline.vertices.len() < 3 {
                            return Err(PortablePlotError::new(
                                "entity_geometry_invalid",
                                "hatch polyline boundaries must contain a closed polygon",
                            ));
                        }
                        if polyline.has_bulge() {
                            self.diagnostic(
                                "hatch_polyline_bulge_omitted",
                                "HATCH",
                                source,
                                FidelityDisposition::Omitted,
                                "a solid hatch with bulged polyline boundaries is deliberately omitted",
                            )?;
                            return Ok(None);
                        }
                        for (index, vertex) in polyline.vertices.iter().enumerate() {
                            let point = projection.project(
                                parent,
                                cad_point(frame.point_to_wcs(Point3::new(
                                    vertex.x,
                                    vertex.y,
                                    hatch.elevation,
                                )?)?),
                            )?;
                            if index == 0 && !started {
                                commands.push(PathCommand::MoveTo(point));
                                started = true;
                            } else {
                                commands.push(PathCommand::LineTo(point));
                            }
                        }
                    }
                    BoundaryEdge::Spline(_) => {
                        self.diagnostic(
                            "hatch_spline_boundary_omitted",
                            "HATCH",
                            source,
                            FidelityDisposition::Omitted,
                            "a solid hatch with spline boundaries is deliberately omitted",
                        )?;
                        return Ok(None);
                    }
                }
            }
            if !started {
                return Err(PortablePlotError::new(
                    "entity_geometry_invalid",
                    "hatch boundary did not produce geometry",
                ));
            }
            commands.push(PathCommand::Close);
        }
        let node = DisplayNode::Path(PathNode::new(
            ScenePath::new(commands)?,
            Some(Fill::new(style.color, FillRule::EvenOdd)),
            None,
            source,
        )?);
        if maximum_error > 0.0 {
            Ok(Some(CompiledPrimitive::tolerance(
                vec![node],
                "cubic_curve_flattening",
                maximum_error,
            )))
        } else {
            Ok(Some(CompiledPrimitive::exact(vec![node])))
        }
    }

    fn compile_wipeout(
        &mut self,
        wipeout: &Wipeout,
        parent: Affine3,
        projection: &Projection,
        source: Option<SourceHandle>,
    ) -> Result<Option<CompiledPrimitive>, PortablePlotError> {
        if !wipeout.clipping_enabled || wipeout.clip_mode != WipeoutClipMode::Outside {
            self.diagnostic(
                "wipeout_clip_mode_unsupported",
                "WIPEOUT",
                source,
                FidelityDisposition::Unsupported,
                "disabled or inverse wipeout clipping is not admitted",
            )?;
            return Ok(None);
        }
        let world = if wipeout.is_rectangular() {
            wipeout.corners().to_vec()
        } else {
            wipeout.world_boundary_vertices()
        };
        if world.len() < 3 {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "wipeout clipping boundary must contain at least three vertices",
            ));
        }
        let points = world
            .into_iter()
            .map(|point| projection.project(parent, point))
            .collect::<Result<Vec<_>, _>>()?;
        let path = ScenePath::polyline(points, true)?;
        Ok(Some(CompiledPrimitive::exact(vec![DisplayNode::Path(
            PathNode::new(
                path,
                Some(Fill::new(SceneColor::WHITE, FillRule::NonZero)),
                None,
                source,
            )?,
        )])))
    }

    fn compile_text(
        &mut self,
        text: &Text,
        parent: Affine3,
        projection: &Projection,
        style: &ResolvedStyle,
        source: Option<SourceHandle>,
        source_type: &'static str,
    ) -> Result<Option<CompiledPrimitive>, PortablePlotError> {
        self.compile_text_spec(
            TextSpec {
                value: &text.value,
                insertion_point: text.insertion_point,
                alignment_point: text.alignment_point,
                height: text.height,
                rotation: text.rotation,
                width_factor: text.width_factor,
                oblique_angle: text.oblique_angle,
                style: &text.style,
                horizontal: text_horizontal(text.horizontal_alignment),
                vertical: text_vertical(text.vertical_alignment),
                normal: text.normal,
                generation_flags: text.generation_flags,
            },
            parent,
            projection,
            style,
            source,
            source_type,
        )
    }

    fn compile_attribute(
        &mut self,
        attribute: &AttributeEntity,
        parent: Affine3,
        projection: &Projection,
        style: &ResolvedStyle,
        source: Option<SourceHandle>,
        source_type: &'static str,
    ) -> Result<Option<CompiledPrimitive>, PortablePlotError> {
        if attribute.flags.invisible {
            return Ok(Some(CompiledPrimitive::exact(Vec::new())));
        }
        if attribute.is_multiline {
            self.diagnostic(
                "multiline_attribute_unsupported",
                source_type,
                source,
                FidelityDisposition::Unsupported,
                "multiline attributes require the MTEXT paragraph pipeline",
            )?;
            return Ok(None);
        }
        self.compile_text_spec(
            TextSpec {
                value: &attribute.value,
                insertion_point: attribute.insertion_point,
                alignment_point: Some(attribute.alignment_point),
                height: attribute.height,
                rotation: attribute.rotation,
                width_factor: attribute.width_factor,
                oblique_angle: attribute.oblique_angle,
                style: &attribute.text_style,
                horizontal: attribute_horizontal(attribute.horizontal_alignment),
                vertical: attribute_vertical(attribute.vertical_alignment),
                normal: attribute.normal,
                generation_flags: attribute.text_generation_flags,
            },
            parent,
            projection,
            style,
            source,
            source_type,
        )
    }

    fn compile_attribute_definition(
        &mut self,
        attribute: &AttributeDefinition,
        parent: Affine3,
        projection: &Projection,
        style: &ResolvedStyle,
        source: Option<SourceHandle>,
    ) -> Result<Option<CompiledPrimitive>, PortablePlotError> {
        if attribute.flags.invisible || !attribute.flags.constant {
            return Ok(Some(CompiledPrimitive::exact(Vec::new())));
        }
        if attribute.is_multiline {
            self.diagnostic(
                "multiline_attribute_unsupported",
                "ATTDEF",
                source,
                FidelityDisposition::Unsupported,
                "multiline constant attributes require the MTEXT paragraph pipeline",
            )?;
            return Ok(None);
        }
        self.compile_text_spec(
            TextSpec {
                value: &attribute.default_value,
                insertion_point: attribute.insertion_point,
                alignment_point: Some(attribute.alignment_point),
                height: attribute.height,
                rotation: attribute.rotation,
                width_factor: attribute.width_factor,
                oblique_angle: attribute.oblique_angle,
                style: &attribute.text_style,
                horizontal: attribute_horizontal(attribute.horizontal_alignment),
                vertical: attribute_vertical(attribute.vertical_alignment),
                normal: attribute.normal,
                generation_flags: attribute.text_generation_flags,
            },
            parent,
            projection,
            style,
            source,
            "ATTDEF",
        )
    }

    fn compile_mtext(
        &mut self,
        text: &MText,
        parent: Affine3,
        projection: &Projection,
        style: &ResolvedStyle,
        source: Option<SourceHandle>,
    ) -> Result<Option<CompiledPrimitive>, PortablePlotError> {
        if !matches!(text.drawing_direction, DrawingDirection::LeftToRight)
            || text.background_fill_flags != 0
            || text.column_data.column_type != 0
        {
            self.diagnostic(
                "mtext_layout_omitted",
                "MTEXT",
                source,
                FidelityDisposition::Omitted,
                "MTEXT with columns, background masks, or non-left-to-right flow is deliberately omitted",
            )?;
            return Ok(None);
        }
        let parsed = match parse_closed_mtext(
            &text.value,
            self.limits.display_list.max_text_bytes,
            self.limits.display_list.max_graphics_state_depth,
            self.limits.display_list.max_nodes,
        ) {
            Ok(parsed) => parsed,
            Err(failure) => {
                self.diagnostic(
                    failure.code,
                    "MTEXT",
                    source,
                    failure.disposition(),
                    failure.message,
                )?;
                return Ok(None);
            }
        };
        if parsed.paragraphs.iter().all(Vec::is_empty) {
            return Ok(Some(CompiledPrimitive::exact(Vec::new())));
        }
        if !finite_positive(text.line_spacing_factor)
            || !finite_positive(text.height)
            || !text.rotation.is_finite()
            || !text.rectangle_width.is_finite()
            || text.rectangle_width < 0.0
        {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "MTEXT height and spacing must be positive and its rotation and rectangle width must be finite",
            ));
        }
        let text_styles = self
            .document
            .text_styles
            .iter()
            .filter(|style| style.name.eq_ignore_ascii_case(&text.style))
            .collect::<Vec<_>>();
        let [text_style] = text_styles.as_slice() else {
            self.diagnostic(
                "text_style_unresolved",
                "MTEXT",
                source,
                FidelityDisposition::Invalid,
                "MTEXT style does not resolve to exactly one drawing table entry",
            )?;
            return Ok(None);
        };
        let base_height = if text_style.height > 0.0 {
            text_style.height
        } else {
            text.height
        };
        if !finite_positive(base_height)
            || !finite_positive(text_style.width_factor)
            || !text_style.oblique_angle.is_finite()
            || text_style.oblique_angle.abs() >= FRAC_PI_2
        {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "effective MTEXT style metrics are invalid",
            ));
        }
        let line_advance = text.height * text.line_spacing_factor;
        let total_height =
            line_advance * parsed.paragraphs.len().saturating_sub(1) as f64 + text.height;
        if !finite_positive(line_advance) || !finite_positive(total_height) {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "MTEXT line layout overflowed",
            ));
        }
        let (horizontal, vertical_anchor) = mtext_attachment(text.attachment_point);
        let mut anchor = portable_point(text.insertion_point)?;
        let rotation_x = Vector3::new(text.rotation.cos(), text.rotation.sin(), 0.0)?;
        let rotation_y = Vector3::new(-text.rotation.sin(), text.rotation.cos(), 0.0)?;
        let horizontal_shift = match horizontal {
            TextHAlign::Left => 0.0,
            TextHAlign::Center => -text.rectangle_width / 2.0,
            TextHAlign::Right => -text.rectangle_width,
            _ => unreachable!("MTEXT attachment only produces left, center, or right"),
        };
        let vertical_shift = match vertical_anchor {
            TextVAlign::Top => 0.0,
            TextVAlign::Middle => total_height / 2.0,
            TextVAlign::Bottom => total_height,
            TextVAlign::Baseline => 0.0,
        };
        anchor = add_vectors_to_point(
            anchor,
            rotation_x,
            horizontal_shift,
            rotation_y,
            vertical_shift,
        )?;

        let mut compiled_runs = Vec::new();
        let mut pending_stroke_commands = 0_usize;
        for (index, paragraph) in parsed.paragraphs.iter().enumerate() {
            let line_anchor = Point3::new(
                anchor.x() - rotation_y.x() * line_advance * index as f64,
                anchor.y() - rotation_y.y() * line_advance * index as f64,
                anchor.z() - rotation_y.z() * line_advance * index as f64,
            )?;
            let mut run_advance = 0.0_f64;
            for run in paragraph {
                let run_height = match run.format.height {
                    MTextHeightSpec::Factor(factor) => base_height * factor,
                    MTextHeightSpec::Absolute(height) => height,
                };
                let run_width = text_style.width_factor * run.format.width_factor;
                let run_oblique = run.format.oblique_angle.unwrap_or(text_style.oblique_angle);
                if !finite_positive(run_height)
                    || !finite_positive(run_width)
                    || !run_oblique.is_finite()
                    || run_oblique.abs() >= FRAC_PI_2
                {
                    return Err(PortablePlotError::new(
                        "entity_geometry_invalid",
                        "scoped MTEXT metrics are invalid",
                    ));
                }
                let run_anchor =
                    add_vectors_to_point(line_anchor, rotation_x, run_advance, rotation_y, 0.0)?;
                let color = self.resolve_mtext_color(run.format.color, style.color)?;
                let compiled = self.compile_text_run(
                    TextSpec {
                        value: &run.text,
                        insertion_point: cad_point(run_anchor),
                        alignment_point: None,
                        height: text.height,
                        rotation: text.rotation,
                        width_factor: 1.0,
                        oblique_angle: 0.0,
                        style: &text.style,
                        horizontal: TextHAlign::Left,
                        vertical: TextVAlign::Top,
                        normal: text.normal,
                        generation_flags: 0,
                    },
                    TextRunOverrides {
                        font_identity: run.format.font_identity.as_deref(),
                        color: Some(color),
                        height: Some(run_height),
                        width_factor: Some(run_width),
                        oblique_angle: Some(run_oblique),
                        normalized_text: true,
                    },
                    parent,
                    projection,
                    style,
                    source.clone(),
                    "MTEXT",
                )?;
                let Some(compiled) = compiled else {
                    return Ok(None);
                };
                let direction = if text_style.flags.backward { -1.0 } else { 1.0 };
                run_advance += direction * compiled.advance;
                if !run_advance.is_finite() {
                    return Err(PortablePlotError::new(
                        "entity_geometry_invalid",
                        "MTEXT run positioning overflowed",
                    ));
                }
                pending_stroke_commands = pending_stroke_commands
                    .checked_add(compiled.stroke_path_commands)
                    .ok_or_else(|| {
                        PortablePlotError::new(
                            "stroke_font_expansion_budget_exceeded",
                            "SHX path-command accounting overflowed",
                        )
                    })?;
                let total_stroke_commands = self
                    .stroke_path_commands
                    .checked_add(pending_stroke_commands)
                    .ok_or_else(|| {
                        PortablePlotError::new(
                            "stroke_font_expansion_budget_exceeded",
                            "SHX path-command accounting overflowed",
                        )
                    })?;
                if total_stroke_commands > self.limits.display_list.max_path_commands {
                    return Err(PortablePlotError::new(
                        "stroke_font_expansion_budget_exceeded",
                        "SHX text expansion exceeds the configured path-command budget",
                    ));
                }
                compiled_runs.push(compiled);
            }
        }
        self.commit_text_runs(&compiled_runs, "MTEXT", source.clone())?;
        let normalization_error_points = compiled_runs
            .iter()
            .map(|run| run.normalization_error_points)
            .fold(0.0_f64, f64::max);
        if normalization_error_points > 0.0 {
            self.ledger
                .record_tolerance("shx_stroke_normalization", normalization_error_points)?;
        }
        let nodes = compiled_runs
            .into_iter()
            .flat_map(|run| run.nodes)
            .collect();
        self.diagnostic(
            "mtext_layout_substituted",
            "MTEXT",
            source,
            FidelityDisposition::Substituted,
            "MTEXT paragraph layout is deterministic but does not yet implement AutoCAD-equivalent wrapping and mixed-run line boxes",
        )?;
        Ok(Some(CompiledPrimitive::substituted(nodes)))
    }

    fn resolve_mtext_color(
        &self,
        color: MTextColorSpec,
        inherited: SceneColor,
    ) -> Result<SceneColor, PortablePlotError> {
        let MTextColorSpec::Aci(index) = color else {
            return Ok(match color {
                MTextColorSpec::Inherit => inherited,
                MTextColorSpec::Rgb(red, green, blue) => SceneColor::rgb(red, green, blue),
                MTextColorSpec::Aci(_) => unreachable!(),
            });
        };
        let index = u8::try_from(index).map_err(|_| {
            PortablePlotError::new(
                "mtext_color_invalid",
                "MTEXT ACI color is outside the supported byte domain",
            )
        })?;
        let concrete = concrete_color(Color::Index(index))?;
        if let Some(plot_style) = self.plot_style {
            let rule = plot_style.style(u16::from(index)).ok_or_else(|| {
                PortablePlotError::new(
                    "plot_style_resource_contradictory",
                    "the admitted CTB resource has no rule for an MTEXT ACI color",
                )
            })?;
            Ok(apply_plot_style_color(concrete.color, rule))
        } else {
            Ok(concrete.color)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_text_spec(
        &mut self,
        spec: TextSpec<'_>,
        parent: Affine3,
        projection: &Projection,
        resolved_style: &ResolvedStyle,
        source: Option<SourceHandle>,
        source_type: &'static str,
    ) -> Result<Option<CompiledPrimitive>, PortablePlotError> {
        let Some(run) = self.compile_text_run(
            spec,
            TextRunOverrides::default(),
            parent,
            projection,
            resolved_style,
            source.clone(),
            source_type,
        )?
        else {
            return Ok(None);
        };
        self.commit_text_runs(std::slice::from_ref(&run), source_type, source)?;
        if run.normalization_error_points > 0.0 {
            Ok(Some(CompiledPrimitive::tolerance(
                run.nodes,
                "shx_stroke_normalization",
                run.normalization_error_points,
            )))
        } else {
            Ok(Some(CompiledPrimitive::exact(run.nodes)))
        }
    }

    fn commit_text_runs(
        &mut self,
        runs: &[CompiledTextRun],
        source_type: &'static str,
        source: Option<SourceHandle>,
    ) -> Result<(), PortablePlotError> {
        let pending_commands = runs.iter().try_fold(0_usize, |total, run| {
            total.checked_add(run.stroke_path_commands).ok_or_else(|| {
                PortablePlotError::new(
                    "stroke_font_expansion_budget_exceeded",
                    "SHX path-command accounting overflowed",
                )
            })
        })?;
        let expanded_commands = self
            .stroke_path_commands
            .checked_add(pending_commands)
            .ok_or_else(|| {
                PortablePlotError::new(
                    "stroke_font_expansion_budget_exceeded",
                    "SHX path-command accounting overflowed",
                )
            })?;
        if expanded_commands > self.limits.display_list.max_path_commands {
            return Err(PortablePlotError::new(
                "stroke_font_expansion_budget_exceeded",
                "SHX text expansion exceeds the configured path-command budget",
            ));
        }
        if runs.iter().any(|run| {
            matches!(
                &run.font,
                Some(CompiledTextFont::Outline(_, FontResolution::Fallback))
            )
        }) {
            self.diagnostic(
                "font_substituted",
                source_type,
                source,
                FidelityDisposition::Substituted,
                "text uses the caller-authorized fallback because no exact drawing font binding was supplied",
            )?;
        }
        self.used_fonts.extend(runs.iter().filter_map(|run| {
            if let Some(CompiledTextFont::Outline(font_id, _)) = &run.font {
                Some(*font_id)
            } else {
                None
            }
        }));
        self.used_stroke_fonts
            .extend(runs.iter().flat_map(|run| match &run.font {
                Some(CompiledTextFont::Stroke { fonts, .. }) => fonts.iter().copied(),
                _ => [].iter().copied(),
            }));
        self.used_composite_fonts
            .extend(runs.iter().filter_map(|run| match &run.font {
                Some(CompiledTextFont::Stroke { composite, .. }) => *composite,
                _ => None,
            }));
        self.stroke_path_commands = expanded_commands;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_text_run(
        &mut self,
        spec: TextSpec<'_>,
        overrides: TextRunOverrides<'_>,
        parent: Affine3,
        projection: &Projection,
        resolved_style: &ResolvedStyle,
        source: Option<SourceHandle>,
        source_type: &'static str,
    ) -> Result<Option<CompiledTextRun>, PortablePlotError> {
        if spec.value.is_empty() {
            return Ok(Some(CompiledTextRun {
                nodes: Vec::new(),
                advance: 0.0,
                font: None,
                normalization_error_points: 0.0,
                stroke_path_commands: 0,
            }));
        }
        if spec.value.contains("%<") {
            self.diagnostic(
                "text_field_omitted",
                source_type,
                source,
                FidelityDisposition::Omitted,
                "field text is deliberately omitted because expressions are not executed and no explicitly fresh stored value was supplied",
            )?;
            return Ok(None);
        }
        if !finite_positive(spec.height)
            || !finite_positive(spec.width_factor)
            || !all_finite(&[spec.rotation, spec.oblique_angle])
            || spec.oblique_angle.abs() >= FRAC_PI_2
        {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "text height and width must be positive and text angles must be finite and nonsingular",
            ));
        }
        if matches!(spec.horizontal, TextHAlign::Aligned | TextHAlign::Fit) {
            self.diagnostic(
                "text_fit_alignment_unsupported",
                source_type,
                source,
                FidelityDisposition::Unsupported,
                "aligned and fit text require two-point font-metric scaling",
            )?;
            return Ok(None);
        }
        let matches = self
            .document
            .text_styles
            .iter()
            .filter(|style| style.name.eq_ignore_ascii_case(spec.style))
            .collect::<Vec<_>>();
        let [text_style] = matches.as_slice() else {
            self.diagnostic(
                "text_style_unresolved",
                source_type,
                source,
                FidelityDisposition::Invalid,
                "text style does not resolve to exactly one drawing table entry",
            )?;
            return Ok(None);
        };
        let uses_style_font = overrides.font_identity.is_none();
        let requested_font = overrides
            .font_identity
            .or_else(|| font_identity(text_style));
        let Some(font_identity) = requested_font else {
            self.diagnostic(
                "font_text_omitted",
                source_type,
                source,
                FidelityDisposition::Omitted,
                "text is deliberately omitted because its drawing style has no font identity",
            )?;
            return Ok(None);
        };
        let big_font_identity = uses_style_font
            .then(|| text_style.big_font_file.trim())
            .filter(|identity| !identity.is_empty());
        let normalized_text = if overrides.normalized_text {
            spec.value.to_string()
        } else {
            match normalize_cad_text(spec.value) {
                Ok(text) => text,
                Err(message) => {
                    self.diagnostic(
                        "text_control_unsupported",
                        source_type,
                        source,
                        FidelityDisposition::Unsupported,
                        message,
                    )?;
                    return Ok(None);
                }
            }
        };
        let height = overrides.height.unwrap_or({
            if text_style.height > 0.0 {
                text_style.height
            } else {
                spec.height
            }
        });
        let width_factor = overrides
            .width_factor
            .unwrap_or(spec.width_factor * text_style.width_factor);
        let oblique = overrides.oblique_angle.unwrap_or({
            if spec.oblique_angle != 0.0 {
                spec.oblique_angle
            } else {
                text_style.oblique_angle
            }
        });
        if !finite_positive(height)
            || !finite_positive(width_factor)
            || !oblique.is_finite()
            || oblique.abs() >= FRAC_PI_2
        {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "effective text style metrics are invalid",
            ));
        }
        let backward = (spec.generation_flags & 2) != 0 || text_style.flags.backward;
        let upside_down = (spec.generation_flags & 4) != 0 || text_style.flags.upside_down;
        let frame = OcsFrame::from_normal(portable_vector(spec.normal)?)?;
        let anchor = if spec.horizontal != TextHAlign::Left || spec.vertical != TextVAlign::Baseline
        {
            spec.alignment_point.unwrap_or(spec.insertion_point)
        } else {
            spec.insertion_point
        };
        let anchor = portable_point(anchor)?;
        let cosine = spec.rotation.cos();
        let sine = spec.rotation.sin();
        let x_sign = if backward { -1.0 } else { 1.0 };
        let y_sign = if upside_down { -1.0 } else { 1.0 };
        let x_axis = Vector3::new(cosine * x_sign, sine * x_sign, 0.0)?;
        let y_axis = Vector3::new(-sine * y_sign, cosine * y_sign, 0.0)?;
        let origin_page = projection.project(parent, cad_point(frame.point_to_wcs(anchor)?))?;
        let x_endpoint = add_vectors_to_point(anchor, x_axis, height * width_factor, y_axis, 0.0)?;
        let y_endpoint =
            add_vectors_to_point(anchor, x_axis, height * oblique.tan(), y_axis, height)?;
        let x_page = projection.project(parent, cad_point(frame.point_to_wcs(x_endpoint)?))?;
        let y_page = projection.project(parent, cad_point(frame.point_to_wcs(y_endpoint)?))?;
        let transform = Affine2::from_components(
            x_page.x() - origin_page.x(),
            y_page.x() - origin_page.x(),
            x_page.y() - origin_page.y(),
            y_page.y() - origin_page.y(),
            origin_page.x(),
            origin_page.y(),
        )?;
        if font_identity_is_shx(font_identity) {
            if let Some(big_font_identity) = big_font_identity {
                if !font_identity_is_shx(big_font_identity) {
                    self.diagnostic(
                        "shx_composite_font_omitted",
                        source_type,
                        source,
                        FidelityDisposition::Omitted,
                        "an SHX composite style requires its big-font identity to name an SHX resource",
                    )?;
                    return Ok(None);
                }
                let composite = self
                    .resources
                    .resolve_shx_composite_font(font_identity, big_font_identity)?;
                let primary = self.resources.resolve_shx_stroke_font(font_identity)?;
                let big = self.resources.resolve_shx_stroke_font(big_font_identity)?;
                let (
                    Some((composite_id, composite_resource)),
                    Some((primary_id, primary_resource)),
                    Some((big_id, big_resource)),
                ) = (composite, primary, big)
                else {
                    self.diagnostic(
                        "shx_composite_font_omitted",
                        source_type,
                        source,
                        FidelityDisposition::Omitted,
                        "an SHX composite style requires an exact pair mapping and exact primary and big-font stroke resources",
                    )?;
                    return Ok(None);
                };
                return self.compile_shx_composite_text_run(
                    &normalized_text,
                    composite_id,
                    composite_resource,
                    primary_id,
                    primary_resource,
                    big_id,
                    big_resource,
                    transform,
                    height,
                    width_factor,
                    spec.horizontal,
                    spec.vertical,
                    overrides.color.unwrap_or(resolved_style.color),
                    resolved_style,
                    source,
                    source_type,
                );
            }
            let Some((font_id, font_resource)) =
                self.resources.resolve_shx_stroke_font(font_identity)?
            else {
                self.diagnostic(
                    "shx_text_omitted",
                    source_type,
                    source,
                    FidelityDisposition::Omitted,
                    "text using SHX or shape fonts requires an exact normalized stroke-font binding",
                )?;
                return Ok(None);
            };
            return self.compile_shx_text_run(
                &normalized_text,
                font_id,
                font_resource,
                transform,
                height,
                width_factor,
                spec.horizontal,
                spec.vertical,
                overrides.color.unwrap_or(resolved_style.color),
                resolved_style,
                source,
                source_type,
            );
        }
        let Some((font_id, font_resource, font_resolution)) =
            self.resources.resolve_font(font_identity)?
        else {
            self.diagnostic(
                "font_text_omitted",
                source_type,
                source,
                FidelityDisposition::Omitted,
                "text is deliberately omitted because its font identity is absent from the immutable resource bundle",
            )?;
            return Ok(None);
        };
        let face = rustybuzz::Face::from_slice(font_resource.bytes(), font_resource.face_index())
            .ok_or_else(|| {
            PortablePlotError::new(
                "font_resource_invalid",
                "a digest-bound font resource could not be parsed as TrueType/OpenType",
            )
        })?;
        let (glyphs, advance, ascender, descender) = match shape_text(&face, &normalized_text) {
            Ok(shaped) => shaped,
            Err(error) if error.code() == "font_glyph_missing" => {
                self.diagnostic(
                    "font_glyph_missing",
                    source_type,
                    source,
                    FidelityDisposition::Unsupported,
                    "the bound font does not cover every character in the text run",
                )?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let local_x = match spec.horizontal {
            TextHAlign::Left => 0.0,
            TextHAlign::Center | TextHAlign::Middle => -advance / 2.0,
            TextHAlign::Right => -advance,
            TextHAlign::Aligned | TextHAlign::Fit => unreachable!(),
        };
        let local_y = match spec.vertical {
            TextVAlign::Baseline => 0.0,
            TextVAlign::Bottom => -descender,
            TextVAlign::Middle => -(ascender + descender) / 2.0,
            TextVAlign::Top => -ascender,
        };
        let run = GlyphRun::new(
            font_id,
            1.0,
            Point2::new(local_x, local_y)?,
            transform,
            normalized_text,
            glyphs,
            Fill::new(
                overrides.color.unwrap_or(resolved_style.color),
                FillRule::NonZero,
            ),
            source,
        )?;
        let advance = advance * height * width_factor;
        if !advance.is_finite() {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "text advance overflowed after applying effective height and width",
            ));
        }
        Ok(Some(CompiledTextRun {
            nodes: vec![DisplayNode::GlyphRun(run)],
            advance,
            font: Some(CompiledTextFont::Outline(font_id, font_resolution)),
            normalization_error_points: 0.0,
            stroke_path_commands: 0,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_shx_text_run(
        &mut self,
        text: &str,
        font_id: StrokeFontId,
        font: &ShxStrokeFontResource,
        transform: Affine2,
        height: f64,
        width_factor: f64,
        horizontal: TextHAlign,
        vertical: TextVAlign,
        color: SceneColor,
        resolved_style: &ResolvedStyle,
        source: Option<SourceHandle>,
        source_type: &'static str,
    ) -> Result<Option<CompiledTextRun>, PortablePlotError> {
        let mut glyphs = Vec::with_capacity(text.chars().count());
        for character in text.chars() {
            let Some(glyph) = font.glyph(character) else {
                self.diagnostic(
                    "shx_glyph_missing",
                    source_type,
                    source,
                    FidelityDisposition::Unsupported,
                    "the bound normalized SHX resource does not cover every character in the text run",
                )?;
                return Ok(None);
            };
            glyphs.push(ResolvedShxGlyph { font, glyph });
        }
        self.compile_resolved_shx_text_run(
            glyphs,
            vec![font_id],
            None,
            transform,
            height,
            width_factor,
            horizontal,
            vertical,
            color,
            resolved_style,
            source,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_shx_composite_text_run(
        &mut self,
        text: &str,
        composite_id: CompositeFontId,
        composite: &ShxCompositeFontResource,
        primary_id: StrokeFontId,
        primary: &ShxStrokeFontResource,
        big_id: StrokeFontId,
        big: &ShxStrokeFontResource,
        transform: Affine2,
        height: f64,
        width_factor: f64,
        horizontal: TextHAlign,
        vertical: TextVAlign,
        color: SceneColor,
        resolved_style: &ResolvedStyle,
        source: Option<SourceHandle>,
        source_type: &'static str,
    ) -> Result<Option<CompiledTextRun>, PortablePlotError> {
        let mut glyphs = Vec::with_capacity(text.chars().count());
        let mut font_ids = BTreeSet::new();
        for character in text.chars() {
            let selection = composite.selection(character);
            let (font_id, font) = match selection.face() {
                ShxCompositeFace::Primary => (primary_id, primary),
                ShxCompositeFace::Big => (big_id, big),
            };
            let Some(glyph) = font.glyph(selection.glyph()) else {
                self.diagnostic(
                    "shx_composite_glyph_missing",
                    source_type,
                    source,
                    FidelityDisposition::Unsupported,
                    "the SHX composite mapping selects a glyph absent from its exact face resource",
                )?;
                return Ok(None);
            };
            font_ids.insert(font_id);
            glyphs.push(ResolvedShxGlyph { font, glyph });
        }
        self.compile_resolved_shx_text_run(
            glyphs,
            font_ids.into_iter().collect(),
            Some(composite_id),
            transform,
            height,
            width_factor,
            horizontal,
            vertical,
            color,
            resolved_style,
            source,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_resolved_shx_text_run(
        &self,
        glyphs: Vec<ResolvedShxGlyph<'_>>,
        font_ids: Vec<StrokeFontId>,
        composite_id: Option<CompositeFontId>,
        transform: Affine2,
        height: f64,
        width_factor: f64,
        horizontal: TextHAlign,
        vertical: TextVAlign,
        color: SceneColor,
        resolved_style: &ResolvedStyle,
        source: Option<SourceHandle>,
    ) -> Result<Option<CompiledTextRun>, PortablePlotError> {
        let mut advance = 0.0_f64;
        let mut maximum_error = 0.0_f64;
        let mut maximum_descent = 0.0_f64;
        let mut command_count = 0_usize;
        for resolved in &glyphs {
            let cap_height = resolved.font.cap_height();
            advance += resolved.glyph.advance() / cap_height;
            maximum_error = maximum_error.max(resolved.glyph.maximum_error() / cap_height);
            maximum_descent = maximum_descent.max(resolved.font.descent() / cap_height);
            command_count = command_count
                .checked_add(resolved.glyph.commands().len())
                .ok_or_else(|| {
                    PortablePlotError::new(
                        "stroke_font_expansion_budget_exceeded",
                        "SHX path-command accounting overflowed",
                    )
                })?;
        }
        if command_count > self.limits.display_list.max_path_commands {
            return Err(PortablePlotError::new(
                "stroke_font_expansion_budget_exceeded",
                "SHX text expansion exceeds the configured path-command budget",
            ));
        }
        let descender = -maximum_descent;
        let local_x = match horizontal {
            TextHAlign::Left => 0.0,
            TextHAlign::Center | TextHAlign::Middle => -advance / 2.0,
            TextHAlign::Right => -advance,
            TextHAlign::Aligned | TextHAlign::Fit => unreachable!(),
        };
        let local_y = match vertical {
            TextVAlign::Baseline => 0.0,
            TextVAlign::Bottom => -descender,
            TextVAlign::Middle => -(1.0 + descender) / 2.0,
            TextVAlign::Top => -1.0,
        };
        if !all_finite(&[advance, descender, local_x, local_y]) {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "normalized SHX metrics overflowed",
            ));
        }

        let mut commands = Vec::with_capacity(command_count);
        let mut pen_x = 0.0_f64;
        for resolved in glyphs {
            let cap_height = resolved.font.cap_height();
            for command in resolved.glyph.commands() {
                commands.push(match *command {
                    ShxStrokeCommand::MoveTo { x, y } => PathCommand::MoveTo(shx_page_point(
                        transform, cap_height, local_x, local_y, pen_x, x, y,
                    )?),
                    ShxStrokeCommand::LineTo { x, y } => PathCommand::LineTo(shx_page_point(
                        transform, cap_height, local_x, local_y, pen_x, x, y,
                    )?),
                    ShxStrokeCommand::QuadTo { control, end } => PathCommand::QuadTo {
                        control: shx_page_point(
                            transform, cap_height, local_x, local_y, pen_x, control[0], control[1],
                        )?,
                        end: shx_page_point(
                            transform, cap_height, local_x, local_y, pen_x, end[0], end[1],
                        )?,
                    },
                    ShxStrokeCommand::CubicTo {
                        control_1,
                        control_2,
                        end,
                    } => PathCommand::CubicTo {
                        control_1: shx_page_point(
                            transform,
                            cap_height,
                            local_x,
                            local_y,
                            pen_x,
                            control_1[0],
                            control_1[1],
                        )?,
                        control_2: shx_page_point(
                            transform,
                            cap_height,
                            local_x,
                            local_y,
                            pen_x,
                            control_2[0],
                            control_2[1],
                        )?,
                        end: shx_page_point(
                            transform, cap_height, local_x, local_y, pen_x, end[0], end[1],
                        )?,
                    },
                    ShxStrokeCommand::Close => PathCommand::Close,
                });
            }
            pen_x += resolved.glyph.advance() / cap_height;
            if !pen_x.is_finite() {
                return Err(PortablePlotError::new(
                    "entity_geometry_invalid",
                    "SHX glyph positioning overflowed",
                ));
            }
        }
        let nodes = if commands.is_empty() {
            Vec::new()
        } else {
            vec![DisplayNode::Path(PathNode::new(
                ScenePath::new(commands)?,
                None,
                Some(resolved_style.text_stroke(color)?),
                source,
            )?)]
        };
        let [m11, m12, m21, m22, _, _] = transform.components();
        let transform_norm = m11.hypot(m12).hypot(m21).hypot(m22);
        let normalization_error_points = maximum_error * transform_norm;
        let advance = advance * height * width_factor;
        if !advance.is_finite() || !normalization_error_points.is_finite() {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "SHX page-space metrics overflowed",
            ));
        }
        Ok(Some(CompiledTextRun {
            nodes,
            advance,
            font: Some(CompiledTextFont::Stroke {
                fonts: font_ids,
                composite: composite_id,
            }),
            normalization_error_points,
            stroke_path_commands: command_count,
        }))
    }

    fn compile_lwpolyline(
        &mut self,
        polyline: &LwPolyline,
        parent: Affine3,
        projection: &Projection,
        style: &ResolvedStyle,
        source: Option<SourceHandle>,
    ) -> Result<CompiledPrimitive, PortablePlotError> {
        if polyline.vertices.is_empty() {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "LWPOLYLINE must contain at least one vertex",
            ));
        }
        let frame = OcsFrame::from_normal(portable_vector(polyline.normal)?)?;
        let vertices = polyline
            .vertices
            .iter()
            .map(|vertex| Point3::new(vertex.location.x, vertex.location.y, polyline.elevation))
            .collect::<Result<Vec<_>, _>>()?;
        let widths = polyline
            .vertices
            .iter()
            .map(|vertex| {
                let start = if vertex.start_width != 0.0 {
                    vertex.start_width
                } else {
                    polyline.constant_width
                };
                let end = if vertex.end_width != 0.0 {
                    vertex.end_width
                } else {
                    polyline.constant_width
                };
                (start, end)
            })
            .collect::<Vec<_>>();
        let bulges = polyline
            .vertices
            .iter()
            .map(|vertex| vertex.bulge)
            .collect::<Vec<_>>();
        self.compile_polyline_parts(
            &vertices,
            &bulges,
            &widths,
            polyline.is_closed,
            frame,
            parent,
            projection,
            style,
            source,
        )
    }

    fn compile_polyline2d(
        &mut self,
        polyline: &Polyline2D,
        parent: Affine3,
        projection: &Projection,
        style: &ResolvedStyle,
        source: Option<SourceHandle>,
    ) -> Result<CompiledPrimitive, PortablePlotError> {
        if polyline.vertices.is_empty() {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "2D POLYLINE must contain at least one vertex",
            ));
        }
        if polyline.flags.is_spline_fit() {
            return Err(PortablePlotError::new(
                "entity_geometry_unsupported",
                "spline-fit legacy polylines require the spline evaluator",
            ));
        }
        let frame = OcsFrame::from_normal(portable_vector(polyline.normal)?)?;
        let vertices = polyline
            .vertices
            .iter()
            .map(|vertex| {
                Point3::new(
                    vertex.location.x,
                    vertex.location.y,
                    polyline.elevation + vertex.location.z,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bulges = polyline
            .vertices
            .iter()
            .map(|vertex| vertex.bulge)
            .collect::<Vec<_>>();
        let widths = polyline
            .vertices
            .iter()
            .map(|vertex| {
                let start = if vertex.start_width != 0.0 {
                    vertex.start_width
                } else {
                    polyline.start_width
                };
                let end = if vertex.end_width != 0.0 {
                    vertex.end_width
                } else {
                    polyline.end_width
                };
                (start, end)
            })
            .collect::<Vec<_>>();
        self.compile_polyline_parts(
            &vertices,
            &bulges,
            &widths,
            polyline.flags.is_closed(),
            frame,
            parent,
            projection,
            style,
            source,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_polyline_parts(
        &mut self,
        vertices: &[Point3],
        bulges: &[f64],
        widths: &[(f64, f64)],
        closed: bool,
        ocs: OcsFrame,
        parent: Affine3,
        projection: &Projection,
        style: &ResolvedStyle,
        source: Option<SourceHandle>,
    ) -> Result<CompiledPrimitive, PortablePlotError> {
        let segment_count = if closed {
            vertices.len()
        } else {
            vertices.len().saturating_sub(1)
        };
        if segment_count == 0 {
            let point = projection.project(parent, cad_point(ocs.point_to_wcs(vertices[0])?))?;
            let path = ScenePath::polyline([point], false)?;
            return Ok(CompiledPrimitive::exact(vec![DisplayNode::Path(
                PathNode::new(path, None, Some(style.stroke()?), source)?,
            )]));
        }
        let has_width = widths
            .iter()
            .take(segment_count)
            .any(|(start, end)| *start != 0.0 || *end != 0.0);
        if has_width {
            if bulges.iter().take(segment_count).any(|bulge| *bulge != 0.0) {
                return Err(PortablePlotError::new(
                    "polyline_width_unsupported",
                    "variable-width bulged segments require offset-curve construction",
                ));
            }
            let mut nodes = Vec::new();
            let mut join_substitution = wide_polyline_has_nontrivial_join(vertices, widths, closed);
            for index in 0..segment_count {
                let next = (index + 1) % vertices.len();
                let dx = vertices[next].x() - vertices[index].x();
                let dy = vertices[next].y() - vertices[index].y();
                let ocs_length = dx.hypot(dy);
                if ocs_length == 0.0 {
                    if widths[index].0 != 0.0 || widths[index].1 != 0.0 {
                        join_substitution = true;
                    }
                    continue;
                }
                let (start_width, end_width) = widths[index];
                if !all_finite(&[start_width, end_width]) || start_width < 0.0 || end_width < 0.0 {
                    return Err(PortablePlotError::new(
                        "polyline_width_invalid",
                        "polyline widths must be finite and non-negative",
                    ));
                }
                if start_width == 0.0 && end_width == 0.0 {
                    let path = ScenePath::polyline(
                        [
                            projection
                                .project(parent, cad_point(ocs.point_to_wcs(vertices[index])?))?,
                            projection
                                .project(parent, cad_point(ocs.point_to_wcs(vertices[next])?))?,
                        ],
                        false,
                    )?;
                    nodes.push(DisplayNode::Path(PathNode::new(
                        path,
                        None,
                        Some(style.stroke()?),
                        source.clone(),
                    )?));
                    continue;
                }
                let nx = -dy / ocs_length;
                let ny = dx / ocs_length;
                let start_half = start_width / 2.0;
                let end_half = end_width / 2.0;
                let outline = ScenePath::polyline(
                    [
                        project_ocs_offset(
                            vertices[index],
                            nx,
                            ny,
                            start_half,
                            ocs,
                            parent,
                            projection,
                        )?,
                        project_ocs_offset(
                            vertices[next],
                            nx,
                            ny,
                            end_half,
                            ocs,
                            parent,
                            projection,
                        )?,
                        project_ocs_offset(
                            vertices[next],
                            nx,
                            ny,
                            -end_half,
                            ocs,
                            parent,
                            projection,
                        )?,
                        project_ocs_offset(
                            vertices[index],
                            nx,
                            ny,
                            -start_half,
                            ocs,
                            parent,
                            projection,
                        )?,
                    ],
                    true,
                )?;
                nodes.push(DisplayNode::Path(PathNode::new(
                    outline,
                    Some(Fill::new(style.color, FillRule::NonZero)),
                    None,
                    source.clone(),
                )?));
            }
            if join_substitution {
                self.diagnostic(
                    "polyline_width_segment_join",
                    "POLYLINE_WIDTH",
                    source,
                    FidelityDisposition::Substituted,
                    "separate transformed segment outlines substitute for exact non-collinear or width-discontinuous polyline joins",
                )?;
            }
            return Ok(CompiledPrimitive::exact(nodes));
        }

        let mut commands = vec![PathCommand::MoveTo(
            projection.project(parent, cad_point(ocs.point_to_wcs(vertices[0])?))?,
        )];
        let mut maximum_error = 0.0_f64;
        for index in 0..segment_count {
            let next = (index + 1) % vertices.len();
            let bulge = bulges[index];
            if !bulge.is_finite() {
                return Err(PortablePlotError::new(
                    "entity_geometry_invalid",
                    "polyline bulges must be finite",
                ));
            }
            if bulge == 0.0 {
                commands.push(PathCommand::LineTo(
                    projection.project(parent, cad_point(ocs.point_to_wcs(vertices[next])?))?,
                ));
                continue;
            }
            let start = vertices[index];
            let end = vertices[next];
            if start.z() != end.z() {
                return Err(PortablePlotError::new(
                    "entity_geometry_unsupported",
                    "bulged polyline segments must be planar in OCS",
                ));
            }
            let dx = end.x() - start.x();
            let dy = end.y() - start.y();
            let chord = dx.hypot(dy);
            if chord == 0.0 {
                return Err(PortablePlotError::new(
                    "entity_geometry_invalid",
                    "nonzero bulge cannot be attached to a zero-length segment",
                ));
            }
            let center_factor = (1.0 - bulge * bulge) / (4.0 * bulge);
            let center = Point3::new(
                (start.x() + end.x()) / 2.0 - dy * center_factor,
                (start.y() + end.y()) / 2.0 + dx * center_factor,
                start.z(),
            )?;
            let radius = chord * (1.0 + bulge * bulge) / (4.0 * bulge.abs());
            let start_angle = (start.y() - center.y()).atan2(start.x() - center.x());
            let sweep = 4.0 * bulge.atan();
            let arc = self.elliptic_arc(
                parent,
                projection,
                |parameter| {
                    ocs.point_to_wcs(Point3::new(
                        center.x() + radius * parameter.cos(),
                        center.y() + radius * parameter.sin(),
                        center.z(),
                    )?)
                },
                start_angle,
                start_angle + sweep,
            )?;
            commands.extend(arc.path.commands().iter().skip(1).cloned());
            maximum_error = maximum_error.max(arc.error);
        }
        if closed {
            commands.push(PathCommand::Close);
        }
        let path = ScenePath::new(commands)?;
        let nodes = vec![DisplayNode::Path(PathNode::new(
            path,
            None,
            Some(style.stroke()?),
            source,
        )?)];
        if maximum_error > 0.0 {
            Ok(CompiledPrimitive::tolerance(
                nodes,
                "cubic_curve_flattening",
                maximum_error,
            ))
        } else {
            Ok(CompiledPrimitive::exact(nodes))
        }
    }

    fn elliptic_arc(
        &mut self,
        parent: Affine3,
        projection: &Projection,
        point_at: impl Fn(f64) -> Result<Point3, PortablePlotError>,
        start: f64,
        end: f64,
    ) -> Result<CurvePath, PortablePlotError> {
        let sweep = end - start;
        if !sweep.is_finite() || sweep == 0.0 || sweep.abs() > TAU + f64::EPSILON * 16.0 {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "curve sweep must be finite, nonzero, and no greater than one turn",
            ));
        }
        let start_page = projection.project(parent, cad_point(point_at(start)?))?;
        // Every admitted caller supplies a trigonometric ellipse
        // `center + A*cos(t) + B*sin(t)`. Projection is affine, so recover its
        // exact page-space axes from four quarter-turn samples. The fourth
        // derivative has norm at most `|A| + |B|`; cubic Hermite interpolation
        // therefore has a conservative per-segment error bound M*h^4/384.
        let axis_sample_0 = projection.project(parent, cad_point(point_at(0.0)?))?;
        let axis_sample_pi = projection.project(parent, cad_point(point_at(PI)?))?;
        let axis_sample_half_pi = projection.project(parent, cad_point(point_at(FRAC_PI_2)?))?;
        let axis_sample_three_half_pi =
            projection.project(parent, cad_point(point_at(3.0 * FRAC_PI_2)?))?;
        let axis_a = (
            (axis_sample_0.x() - axis_sample_pi.x()) / 2.0,
            (axis_sample_0.y() - axis_sample_pi.y()) / 2.0,
        );
        let axis_b = (
            (axis_sample_half_pi.x() - axis_sample_three_half_pi.x()) / 2.0,
            (axis_sample_half_pi.y() - axis_sample_three_half_pi.y()) / 2.0,
        );
        let derivative_bound = axis_a.0.hypot(axis_a.1) + axis_b.0.hypot(axis_b.1);
        if !derivative_bound.is_finite() {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "projected curve magnitude is not finite",
            ));
        }
        let tolerance = self.limits.curve_tolerance_points;
        let segment_factor = (derivative_bound / (384.0 * tolerance)).max(0.0).powf(0.25);
        let mut segments = (sweep.abs() * segment_factor).ceil().max(1.0) as usize;
        let mut delta = sweep / segments as f64;
        let mut maximum_error = derivative_bound * delta.abs().powi(4) / 384.0;
        while maximum_error > tolerance {
            segments = segments.checked_add(1).ok_or_else(|| {
                PortablePlotError::new(
                    "curve_segment_budget_exceeded",
                    "curve segment accounting overflowed",
                )
            })?;
            delta = sweep / segments as f64;
            maximum_error = derivative_bound * delta.abs().powi(4) / 384.0;
        }
        self.curve_segments = self.curve_segments.checked_add(segments).ok_or_else(|| {
            PortablePlotError::new(
                "curve_segment_budget_exceeded",
                "curve segment accounting overflowed",
            )
        })?;
        if self.curve_segments > self.limits.max_curve_segments {
            return Err(PortablePlotError::new(
                "curve_segment_budget_exceeded",
                "curve compilation exceeds the configured segment limit",
            ));
        }
        let mut commands = Vec::with_capacity(segments + 1);
        commands.push(PathCommand::MoveTo(start_page));
        for segment in 0..segments {
            let a0 = start + delta * segment as f64;
            let a1 = a0 + delta;
            let p0 = projection.project(parent, cad_point(point_at(a0)?))?;
            let p1 = projection.project(parent, cad_point(point_at(a1)?))?;
            let derivative0 = (
                -axis_a.0 * a0.sin() + axis_b.0 * a0.cos(),
                -axis_a.1 * a0.sin() + axis_b.1 * a0.cos(),
            );
            let derivative1 = (
                -axis_a.0 * a1.sin() + axis_b.0 * a1.cos(),
                -axis_a.1 * a1.sin() + axis_b.1 * a1.cos(),
            );
            let control1 = Point2::new(
                p0.x() + derivative0.0 * delta / 3.0,
                p0.y() + derivative0.1 * delta / 3.0,
            )?;
            let control2 = Point2::new(
                p1.x() - derivative1.0 * delta / 3.0,
                p1.y() - derivative1.1 * delta / 3.0,
            )?;
            commands.push(PathCommand::CubicTo {
                control_1: control1,
                control_2: control2,
                end: p1,
            });
        }
        Ok(CurvePath {
            path: ScenePath::new(commands)?,
            error: maximum_error,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn infinite_line(
        &self,
        origin: CadVector3,
        direction: CadVector3,
        ray: bool,
        parent: Affine3,
        projection: &Projection,
        style: &ResolvedStyle,
        source: Option<SourceHandle>,
    ) -> Result<Option<DisplayNode>, PortablePlotError> {
        let start = projection.project(parent, origin)?;
        let through = projection.project(
            parent,
            CadVector3::new(
                origin.x + direction.x,
                origin.y + direction.y,
                origin.z + direction.z,
            ),
        )?;
        let dx = through.x() - start.x();
        let dy = through.y() - start.y();
        if !all_finite(&[dx, dy]) || (dx == 0.0 && dy == 0.0) {
            return Err(PortablePlotError::new(
                "entity_geometry_invalid",
                "projected construction-line direction must be finite and nonzero",
            ));
        }
        let Some((first, second)) = clip_parametric(start, dx, dy, projection.clip, ray) else {
            return Ok(None);
        };
        let path = ScenePath::polyline([first, second], false)?;
        Ok(Some(DisplayNode::Path(PathNode::new(
            path,
            None,
            Some(style.stroke()?),
            source,
        )?)))
    }

    fn resolve_style(
        &self,
        common: &EntityCommon,
        insert: Option<&InsertStyle>,
        projection: &Projection,
    ) -> Result<ResolvedStyle, PortablePlotError> {
        let effective_layer = if common.layer == "0" {
            insert
                .map(|context| context.layer.clone())
                .unwrap_or_else(|| "0".to_string())
        } else {
            common.layer.clone()
        };
        let layers = self
            .document
            .layers
            .iter()
            .filter(|layer| layer.name == effective_layer)
            .collect::<Vec<_>>();
        let [layer] = layers.as_slice() else {
            return Err(PortablePlotError::new(
                "entity_layer_ambiguous",
                "entity effective layer does not resolve uniquely",
            ));
        };
        let viewport_frozen = projection.frozen_layers.contains(&layer.handle);
        let visible = !common.invisible
            && !layer.flags.off
            && !layer.flags.frozen
            && layer.is_plottable
            && !viewport_frozen;
        let cad_color = match common.color {
            Color::ByLayer => concrete_color(layer.color)?,
            Color::ByBlock => insert.map(|context| context.color).ok_or_else(|| {
                PortablePlotError::new(
                    "by_block_context_missing",
                    "ByBlock colour has no immediate resolved insert context",
                )
            })?,
            explicit => concrete_color(explicit)?,
        };
        let cad_lineweight = match common.line_weight {
            LineWeight::ByLayer => concrete_lineweight(layer.line_weight)?,
            LineWeight::ByBlock => {
                insert
                    .map(|context| context.lineweight_points)
                    .ok_or_else(|| {
                        PortablePlotError::new(
                            "by_block_context_missing",
                            "ByBlock lineweight has no immediate resolved insert context",
                        )
                    })?
            }
            explicit => concrete_lineweight(explicit)?,
        };
        let mut lineweight = cad_lineweight;
        let mut color = cad_color.color;
        let mut line_cap = LineCap::Butt;
        let mut line_join = LineJoin::Miter;
        if let (Some(plot_style), Some(aci)) = (self.plot_style, cad_color.aci) {
            let rule = plot_style.style(aci).ok_or_else(|| {
                PortablePlotError::new(
                    "plot_style_resource_contradictory",
                    "the admitted CTB resource has no rule for an effective ACI colour",
                )
            })?;
            color = apply_plot_style_color(color, rule);
            if let Some(width) = rule.lineweight_points {
                lineweight = width;
            }
            if let Some(cap) = rule.line_cap {
                line_cap = cap;
            }
            if let Some(join) = rule.line_join {
                line_join = join;
            }
        }
        let lineweight = if self.print_lineweights {
            lineweight * self.lineweight_scale
        } else {
            0.0
        };
        if !lineweight.is_finite() || lineweight < 0.0 {
            return Err(PortablePlotError::new(
                "lineweight_invalid",
                "plot lineweight scaling produced an invalid page value",
            ));
        }
        let requested_linetype =
            if common.linetype.is_empty() || common.linetype.eq_ignore_ascii_case("BYLAYER") {
                layer.line_type.clone()
            } else if common.linetype.eq_ignore_ascii_case("BYBLOCK") {
                insert
                    .map(|context| context.linetype.clone())
                    .ok_or_else(|| {
                        PortablePlotError::new(
                            "by_block_context_missing",
                            "ByBlock linetype has no immediate resolved insert context",
                        )
                    })?
            } else {
                common.linetype.clone()
            };
        let dash = resolve_dash(
            self.document,
            &requested_linetype,
            common.linetype_scale,
            projection.page_units_per_source_unit,
        )?;
        Ok(ResolvedStyle {
            effective_layer,
            cad_color,
            cad_lineweight_points: cad_lineweight,
            color: SceneColor::rgba(
                color.red(),
                color.green(),
                color.blue(),
                255_u8.saturating_sub(common.transparency.alpha()),
            ),
            lineweight_points: lineweight,
            linetype_name: requested_linetype,
            dash,
            line_cap,
            line_join,
            visible,
        })
    }

    fn invalid_entity(
        &mut self,
        entity: &EntityType,
        message: &str,
    ) -> Result<(), PortablePlotError> {
        self.diagnostic(
            "entity_geometry_invalid",
            entity.as_entity().entity_type(),
            source_handle(entity.common().handle)?,
            FidelityDisposition::Invalid,
            message,
        )
    }

    fn unsupported_entity(
        &mut self,
        entity: &EntityType,
        code: &'static str,
        message: &'static str,
    ) -> Result<(), PortablePlotError> {
        self.diagnostic(
            code,
            entity.as_entity().entity_type(),
            source_handle(entity.common().handle)?,
            FidelityDisposition::Unsupported,
            message,
        )
    }

    fn unsupported_layout(
        &mut self,
        code: &'static str,
        message: &'static str,
        layout: &Layout,
    ) -> Result<(), PortablePlotError> {
        self.diagnostic(
            code,
            "LAYOUT",
            source_handle(layout.handle)?,
            FidelityDisposition::Unsupported,
            message,
        )
    }

    fn diagnostic(
        &mut self,
        code: &'static str,
        source_type: &str,
        handle: Option<SourceHandle>,
        disposition: FidelityDisposition,
        message: impl Into<String>,
    ) -> Result<(), PortablePlotError> {
        self.ledger.record(PlotDiagnostic::new(
            code,
            source_type,
            handle,
            disposition,
            message,
        )?)
    }
}

fn text_horizontal(value: TextHorizontalAlignment) -> TextHAlign {
    match value {
        TextHorizontalAlignment::Left => TextHAlign::Left,
        TextHorizontalAlignment::Center => TextHAlign::Center,
        TextHorizontalAlignment::Right => TextHAlign::Right,
        TextHorizontalAlignment::Aligned => TextHAlign::Aligned,
        TextHorizontalAlignment::Middle => TextHAlign::Middle,
        TextHorizontalAlignment::Fit => TextHAlign::Fit,
    }
}

fn text_vertical(value: TextVerticalAlignment) -> TextVAlign {
    match value {
        TextVerticalAlignment::Baseline => TextVAlign::Baseline,
        TextVerticalAlignment::Bottom => TextVAlign::Bottom,
        TextVerticalAlignment::Middle => TextVAlign::Middle,
        TextVerticalAlignment::Top => TextVAlign::Top,
    }
}

fn attribute_horizontal(value: AttributeHorizontalAlignment) -> TextHAlign {
    match value {
        AttributeHorizontalAlignment::Left => TextHAlign::Left,
        AttributeHorizontalAlignment::Center => TextHAlign::Center,
        AttributeHorizontalAlignment::Right => TextHAlign::Right,
        AttributeHorizontalAlignment::Aligned => TextHAlign::Aligned,
        AttributeHorizontalAlignment::Middle => TextHAlign::Middle,
        AttributeHorizontalAlignment::Fit => TextHAlign::Fit,
    }
}

fn attribute_vertical(value: AttributeVerticalAlignment) -> TextVAlign {
    match value {
        AttributeVerticalAlignment::Baseline => TextVAlign::Baseline,
        AttributeVerticalAlignment::Bottom => TextVAlign::Bottom,
        AttributeVerticalAlignment::Middle => TextVAlign::Middle,
        AttributeVerticalAlignment::Top => TextVAlign::Top,
    }
}

fn mtext_attachment(value: AttachmentPoint) -> (TextHAlign, TextVAlign) {
    match value {
        AttachmentPoint::TopLeft => (TextHAlign::Left, TextVAlign::Top),
        AttachmentPoint::TopCenter => (TextHAlign::Center, TextVAlign::Top),
        AttachmentPoint::TopRight => (TextHAlign::Right, TextVAlign::Top),
        AttachmentPoint::MiddleLeft => (TextHAlign::Left, TextVAlign::Middle),
        AttachmentPoint::MiddleCenter => (TextHAlign::Center, TextVAlign::Middle),
        AttachmentPoint::MiddleRight => (TextHAlign::Right, TextVAlign::Middle),
        AttachmentPoint::BottomLeft => (TextHAlign::Left, TextVAlign::Bottom),
        AttachmentPoint::BottomCenter => (TextHAlign::Center, TextVAlign::Bottom),
        AttachmentPoint::BottomRight => (TextHAlign::Right, TextVAlign::Bottom),
    }
}

fn parse_closed_mtext(
    value: &str,
    max_text_bytes: usize,
    max_depth: usize,
    max_runs: usize,
) -> Result<ParsedMText, MTextParseFailure> {
    if value.len() > max_text_bytes {
        return Err(MTextParseFailure::invalid(
            "mtext_format_budget_exceeded",
            "MTEXT formatting exceeds the configured text byte budget",
        ));
    }
    if max_depth == 0 {
        return Err(MTextParseFailure::invalid(
            "mtext_format_depth_exceeded",
            "MTEXT formatting has no available context depth",
        ));
    }
    if max_runs == 0 {
        return Err(MTextParseFailure::invalid(
            "mtext_format_budget_exceeded",
            "MTEXT formatting has no available run or paragraph budget",
        ));
    }
    ClosedMTextParser {
        characters: value.chars().collect(),
        position: 0,
        contexts: vec![MTextRunFormat::default()],
        paragraphs: vec![Vec::new()],
        text: String::new(),
        // AutoCAD admits at most eight nested format groups. The root context
        // is stored separately from those drawing-controlled groups.
        max_depth: max_depth.min(8) + 1,
        max_runs,
        run_count: 0,
    }
    .parse()
}

impl ClosedMTextParser {
    fn parse(mut self) -> Result<ParsedMText, MTextParseFailure> {
        while self.position < self.characters.len() {
            let character = self.characters[self.position];
            match character {
                '\\' => self.parse_control()?,
                '{' => {
                    self.flush()?;
                    if self.contexts.len() >= self.max_depth {
                        return Err(MTextParseFailure::invalid(
                            "mtext_format_depth_exceeded",
                            "MTEXT formatting exceeds the configured context depth",
                        ));
                    }
                    let context = self
                        .contexts
                        .last()
                        .expect("MTEXT always has a root context")
                        .clone();
                    self.contexts.push(context);
                    self.position += 1;
                }
                '}' => {
                    self.flush()?;
                    if self.contexts.len() == 1 {
                        return Err(MTextParseFailure::invalid(
                            "mtext_format_unbalanced",
                            "MTEXT contains an unmatched closing format group",
                        ));
                    }
                    self.contexts.pop();
                    self.position += 1;
                }
                '%' => self.parse_percent()?,
                '^' => self.parse_caret()?,
                '\t' => {
                    return Err(MTextParseFailure::omitted(
                        "mtext_control_omitted",
                        "MTEXT tab layout is outside the admitted portable formatting subset",
                    ));
                }
                '\r' | '\n' => {
                    return Err(MTextParseFailure::invalid(
                        "mtext_format_invalid",
                        "MTEXT contains a raw line separator instead of an admitted paragraph control",
                    ));
                }
                _ if character.is_control() => {
                    return Err(MTextParseFailure::invalid(
                        "mtext_format_invalid",
                        "MTEXT contains an unadmitted control character",
                    ));
                }
                _ => {
                    self.text.push(character);
                    self.position += 1;
                }
            }
        }
        self.flush()?;
        if self.contexts.len() != 1 {
            return Err(MTextParseFailure::invalid(
                "mtext_format_unbalanced",
                "MTEXT contains an unterminated format group",
            ));
        }
        Ok(ParsedMText {
            paragraphs: self.paragraphs,
        })
    }

    fn current_format(&self) -> &MTextRunFormat {
        self.contexts
            .last()
            .expect("MTEXT always has a root context")
    }

    fn current_format_mut(&mut self) -> &mut MTextRunFormat {
        self.contexts
            .last_mut()
            .expect("MTEXT always has a root context")
    }

    fn flush(&mut self) -> Result<(), MTextParseFailure> {
        if self.text.is_empty() {
            return Ok(());
        }
        let format = self.current_format().clone();
        let paragraph = self
            .paragraphs
            .last_mut()
            .expect("MTEXT always has a current paragraph");
        if let Some(previous) = paragraph.last_mut() {
            if previous.format == format {
                previous.text.push_str(&std::mem::take(&mut self.text));
                return Ok(());
            }
        }
        if self.run_count >= self.max_runs {
            return Err(MTextParseFailure::invalid(
                "mtext_format_budget_exceeded",
                "MTEXT formatting exceeds the configured run budget",
            ));
        }
        paragraph.push(MTextRunSpec {
            text: std::mem::take(&mut self.text),
            format,
        });
        self.run_count += 1;
        Ok(())
    }

    fn paragraph_break(&mut self) -> Result<(), MTextParseFailure> {
        self.flush()?;
        if self.paragraphs.len() >= self.max_runs {
            return Err(MTextParseFailure::invalid(
                "mtext_format_budget_exceeded",
                "MTEXT formatting exceeds the configured paragraph budget",
            ));
        }
        self.paragraphs.push(Vec::new());
        Ok(())
    }

    fn parse_control(&mut self) -> Result<(), MTextParseFailure> {
        self.position += 1;
        let Some(code) = self.characters.get(self.position).copied() else {
            return Err(MTextParseFailure::invalid(
                "mtext_control_incomplete",
                "MTEXT ends with an incomplete control",
            ));
        };
        match code {
            '\\' | '{' | '}' | ';' => {
                self.text.push(code);
                self.position += 1;
            }
            '~' => {
                self.text.push('\u{00a0}');
                self.position += 1;
            }
            'P' => {
                self.position += 1;
                self.paragraph_break()?;
            }
            'U' => self.parse_unicode_escape()?,
            'C' => {
                self.position += 1;
                let value = self.semicolon_value()?;
                let index = value.parse::<u16>().map_err(|_| {
                    MTextParseFailure::invalid(
                        "mtext_color_invalid",
                        "MTEXT ACI color must be a canonical integer",
                    )
                })?;
                let color = match index {
                    0 | 256 => MTextColorSpec::Inherit,
                    1..=255 => MTextColorSpec::Aci(index),
                    _ => {
                        return Err(MTextParseFailure::invalid(
                            "mtext_color_invalid",
                            "MTEXT ACI color must be inherited or in the range 1 through 255",
                        ));
                    }
                };
                self.flush()?;
                self.current_format_mut().color = color;
            }
            'c' => {
                self.position += 1;
                let value = self.semicolon_value()?;
                let packed = value.parse::<u32>().map_err(|_| {
                    MTextParseFailure::invalid(
                        "mtext_color_invalid",
                        "MTEXT packed RGB color must be a canonical integer",
                    )
                })?;
                if packed > 0x00ff_ffff {
                    return Err(MTextParseFailure::invalid(
                        "mtext_color_invalid",
                        "MTEXT packed RGB color must fit in 24 bits",
                    ));
                }
                self.flush()?;
                self.current_format_mut().color = MTextColorSpec::Rgb(
                    u8::try_from(packed & 0xff).expect("masked RGB component fits u8"),
                    u8::try_from((packed >> 8) & 0xff).expect("masked RGB component fits u8"),
                    u8::try_from((packed >> 16) & 0xff).expect("masked RGB component fits u8"),
                );
            }
            'H' => {
                self.position += 1;
                let (value, relative) = parse_mtext_number(&self.semicolon_value()?, true)?;
                if !finite_positive(value) {
                    return Err(MTextParseFailure::invalid(
                        "mtext_height_invalid",
                        "MTEXT height controls must be finite and positive",
                    ));
                }
                self.flush()?;
                let height = self.current_format().height;
                self.current_format_mut().height = if relative {
                    match height {
                        MTextHeightSpec::Factor(current) => {
                            MTextHeightSpec::Factor(checked_mtext_product(current, value)?)
                        }
                        MTextHeightSpec::Absolute(current) => {
                            MTextHeightSpec::Absolute(checked_mtext_product(current, value)?)
                        }
                    }
                } else {
                    MTextHeightSpec::Absolute(value)
                };
            }
            'W' | 'w' => {
                self.position += 1;
                let (value, relative) = parse_mtext_number(&self.semicolon_value()?, true)?;
                if !finite_positive(value) {
                    return Err(MTextParseFailure::invalid(
                        "mtext_width_invalid",
                        "MTEXT width controls must be finite and positive",
                    ));
                }
                self.flush()?;
                let width = if relative {
                    checked_mtext_product(self.current_format().width_factor, value)?
                } else {
                    value
                };
                self.current_format_mut().width_factor = width;
            }
            'Q' => {
                self.position += 1;
                let (degrees, relative) = parse_mtext_number(&self.semicolon_value()?, false)?;
                if relative || !degrees.is_finite() || degrees.abs() >= 90.0 {
                    return Err(MTextParseFailure::invalid(
                        "mtext_oblique_invalid",
                        "MTEXT oblique controls must be finite degrees strictly between -90 and 90",
                    ));
                }
                self.flush()?;
                self.current_format_mut().oblique_angle = Some(degrees.to_radians());
            }
            'f' | 'F' => {
                self.position += 1;
                let value = self.semicolon_value()?;
                let identity = parse_mtext_font_identity(&value)?;
                self.flush()?;
                self.current_format_mut().font_identity = Some(identity);
            }
            'p' | 'N' | 'X' | 'L' | 'l' | 'O' | 'o' | 'K' | 'k' | 'S' | 's' | 'T' | 'A' | 't'
            | 'B' | 'b' => {
                return Err(MTextParseFailure::omitted(
                    "mtext_control_omitted",
                    "MTEXT contains a recognized control outside the admitted portable formatting subset",
                ));
            }
            _ => {
                return Err(MTextParseFailure::unsupported(
                    "mtext_control_unsupported",
                    "MTEXT contains an unknown control outside the admitted portable formatting subset",
                ));
            }
        }
        Ok(())
    }

    fn parse_unicode_escape(&mut self) -> Result<(), MTextParseFailure> {
        if self.characters.get(self.position + 1) != Some(&'+') {
            return Err(MTextParseFailure::invalid(
                "mtext_unicode_invalid",
                "MTEXT Unicode controls must use exactly four hexadecimal digits",
            ));
        }
        let start = self.position + 2;
        let end = start.checked_add(4).ok_or_else(|| {
            MTextParseFailure::invalid(
                "mtext_unicode_invalid",
                "MTEXT Unicode control indexing overflowed",
            )
        })?;
        if end > self.characters.len()
            || self.characters[start..end]
                .iter()
                .any(|character| !character.is_ascii_hexdigit())
        {
            return Err(MTextParseFailure::invalid(
                "mtext_unicode_invalid",
                "MTEXT Unicode controls must use exactly four hexadecimal digits",
            ));
        }
        let digits = self.characters[start..end].iter().collect::<String>();
        let scalar = u32::from_str_radix(&digits, 16)
            .ok()
            .and_then(char::from_u32)
            .ok_or_else(|| {
                MTextParseFailure::invalid(
                    "mtext_unicode_invalid",
                    "MTEXT Unicode control does not identify a valid scalar value",
                )
            })?;
        self.text.push(scalar);
        self.position = end;
        Ok(())
    }

    fn parse_percent(&mut self) -> Result<(), MTextParseFailure> {
        if self.characters.get(self.position + 1) == Some(&'<') {
            return Err(MTextParseFailure::omitted(
                "text_field_omitted",
                "field text is not executed by the portable renderer",
            ));
        }
        if self.characters.get(self.position + 1) != Some(&'%') {
            self.text.push('%');
            self.position += 1;
            return Ok(());
        }
        if self.characters.get(self.position + 2) == Some(&'%')
            && self.characters.get(self.position + 3) == Some(&'%')
        {
            self.text.push('%');
            self.position += 4;
            return Ok(());
        }
        let Some(code) = self.characters.get(self.position + 2).copied() else {
            return Err(MTextParseFailure::invalid(
                "mtext_control_incomplete",
                "MTEXT ends with an incomplete percent control",
            ));
        };
        self.text.push(match code.to_ascii_lowercase() {
            'd' => '\u{00b0}',
            'p' => '\u{00b1}',
            'c' => '\u{00d8}',
            _ => {
                return Err(MTextParseFailure::unsupported(
                    "mtext_control_unsupported",
                    "MTEXT contains an unknown percent control",
                ));
            }
        });
        self.position += 3;
        Ok(())
    }

    fn parse_caret(&mut self) -> Result<(), MTextParseFailure> {
        let Some(code) = self.characters.get(self.position + 1).copied() else {
            return Err(MTextParseFailure::omitted(
                "mtext_control_omitted",
                "MTEXT ends with a caret control whose glyph substitution is not admitted",
            ));
        };
        match code {
            'J' => {
                self.position += 2;
                self.paragraph_break()?;
            }
            'M' => {
                self.position += 2;
            }
            ' ' => {
                self.text.push('^');
                self.position += 2;
            }
            'I' => {
                return Err(MTextParseFailure::omitted(
                    "mtext_control_omitted",
                    "MTEXT caret tab layout is outside the admitted portable formatting subset",
                ));
            }
            _ => {
                return Err(MTextParseFailure::omitted(
                    "mtext_control_omitted",
                    "MTEXT caret glyph substitution is outside the admitted portable formatting subset",
                ));
            }
        }
        Ok(())
    }

    fn semicolon_value(&mut self) -> Result<String, MTextParseFailure> {
        let start = self.position;
        while self.position < self.characters.len() && self.characters[self.position] != ';' {
            if matches!(
                self.characters[self.position],
                '\\' | '{' | '}' | '\r' | '\n'
            ) {
                return Err(MTextParseFailure::invalid(
                    "mtext_control_incomplete",
                    "MTEXT control value is not terminated by a semicolon",
                ));
            }
            self.position += 1;
        }
        if self.position == self.characters.len() {
            return Err(MTextParseFailure::invalid(
                "mtext_control_incomplete",
                "MTEXT control value is not terminated by a semicolon",
            ));
        }
        let value = self.characters[start..self.position]
            .iter()
            .collect::<String>();
        self.position += 1;
        if value.is_empty() {
            return Err(MTextParseFailure::invalid(
                "mtext_control_invalid",
                "MTEXT control values must not be empty",
            ));
        }
        Ok(value)
    }
}

fn parse_mtext_number(value: &str, allow_relative: bool) -> Result<(f64, bool), MTextParseFailure> {
    let (number, relative) = if let Some(number) = value.strip_suffix(['x', 'X']) {
        (number, true)
    } else {
        (value, false)
    };
    if relative && !allow_relative {
        return Err(MTextParseFailure::invalid(
            "mtext_control_invalid",
            "this MTEXT numeric control does not admit a relative suffix",
        ));
    }
    let parsed = number.parse::<f64>().map_err(|_| {
        MTextParseFailure::invalid(
            "mtext_control_invalid",
            "MTEXT numeric controls must contain a finite decimal value",
        )
    })?;
    if !parsed.is_finite() {
        return Err(MTextParseFailure::invalid(
            "mtext_control_invalid",
            "MTEXT numeric controls must contain a finite decimal value",
        ));
    }
    Ok((parsed, relative))
}

fn checked_mtext_product(left: f64, right: f64) -> Result<f64, MTextParseFailure> {
    let product = left * right;
    if !finite_positive(product) {
        return Err(MTextParseFailure::invalid(
            "mtext_control_invalid",
            "MTEXT scoped numeric controls overflowed or became non-positive",
        ));
    }
    Ok(product)
}

fn parse_mtext_font_identity(value: &str) -> Result<String, MTextParseFailure> {
    let mut components = value.split('|');
    let raw_identity = components.next().unwrap_or_default().trim();
    let identity = raw_identity
        .strip_prefix('N')
        .filter(|name| name.to_ascii_lowercase().ends_with(".shx"))
        .unwrap_or(raw_identity);
    if identity.is_empty()
        || identity.len() > 512
        || identity.contains(['\r', '\n', '\0'])
        || identity
            .split(['/', '\\'])
            .any(|component| component == "..")
    {
        return Err(MTextParseFailure::invalid(
            "mtext_font_invalid",
            "MTEXT font identity must be a bounded logical reference without traversal",
        ));
    }
    let mut bold = None;
    let mut italic = None;
    for component in components {
        match component {
            "b0" if bold.replace(false).is_none() => {}
            "i0" if italic.replace(false).is_none() => {}
            "b1" | "i1" => {
                return Err(MTextParseFailure::omitted(
                    "mtext_font_face_unsupported",
                    "MTEXT bold or italic selection requires an explicit face-binding contract",
                ));
            }
            _ => {
                return Err(MTextParseFailure::omitted(
                    "mtext_font_metadata_unsupported",
                    "MTEXT font metadata outside explicit disabled bold and italic flags is not admitted",
                ));
            }
        }
    }
    Ok(identity.to_string())
}

fn normalize_cad_text(value: &str) -> Result<String, &'static str> {
    if value.contains(['\r', '\n']) {
        return Err("single-line text contains a paragraph separator");
    }
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '%' && characters.peek() == Some(&'%') {
            characters.next();
            let Some(code) = characters.next() else {
                return Err("text ends with an incomplete percent control");
            };
            match code.to_ascii_lowercase() {
                'd' => output.push('\u{00b0}'),
                'p' => output.push('\u{00b1}'),
                'c' => output.push('\u{00d8}'),
                '%' => output.push('%'),
                _ => {
                    return Err("text contains an underline, overline, or unknown percent control")
                }
            }
        } else {
            output.push(character);
        }
    }
    Ok(output)
}

fn font_identity(style: &TextStyle) -> Option<&str> {
    let identity = if !style.true_type_font.trim().is_empty() {
        style.true_type_font.trim()
    } else {
        style.font_file.trim()
    };
    (!identity.is_empty()).then_some(identity)
}

fn font_identity_is_shx(identity: &str) -> bool {
    let lowercase = identity.trim().to_ascii_lowercase();
    lowercase.ends_with(".shx") || lowercase == "txt" || lowercase == "simplex"
}

#[allow(clippy::too_many_arguments)]
fn shx_page_point(
    transform: Affine2,
    cap_height: f64,
    local_x: f64,
    local_y: f64,
    pen_x: f64,
    x: f64,
    y: f64,
) -> Result<Point2, PortablePlotError> {
    transform.transform_point(Point2::new(
        local_x + pen_x + x / cap_height,
        local_y + y / cap_height,
    )?)
}

fn shape_text(
    face: &rustybuzz::Face<'_>,
    text: &str,
) -> Result<(Vec<PositionedGlyph>, f64, f64, f64), PortablePlotError> {
    let units_per_em = f64::from(face.units_per_em());
    if !finite_positive(units_per_em) {
        return Err(PortablePlotError::new(
            "font_resource_invalid",
            "font units-per-em must be positive",
        ));
    }
    let mut buffer = rustybuzz::UnicodeBuffer::new();
    buffer.push_str(text);
    buffer.guess_segment_properties();
    let shaped = rustybuzz::shape(face, &[], buffer);
    let infos = shaped.glyph_infos();
    let positions = shaped.glyph_positions();
    let cluster_starts = infos
        .iter()
        .map(|info| usize::try_from(info.cluster))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| {
            PortablePlotError::new(
                "font_shaping_invalid",
                "font shaping produced a cluster outside the addressable text range",
            )
        })?;
    if cluster_starts
        .iter()
        .any(|start| *start > text.len() || !text.is_char_boundary(*start))
    {
        return Err(PortablePlotError::new(
            "font_shaping_invalid",
            "font shaping produced a cluster outside UTF-8 boundaries",
        ));
    }
    let mut glyphs = Vec::with_capacity(infos.len());
    let mut advance = 0.0_f64;
    for (info, position) in infos.iter().zip(positions) {
        if info.glyph_id == 0 {
            return Err(PortablePlotError::new(
                "font_glyph_missing",
                "the bound font has no glyph for part of the shaped text",
            ));
        }
        let start = usize::try_from(info.cluster).map_err(|_| {
            PortablePlotError::new(
                "font_shaping_invalid",
                "font shaping cluster conversion overflowed",
            )
        })?;
        let end = cluster_starts
            .range((std::ops::Bound::Excluded(start), std::ops::Bound::Unbounded))
            .next()
            .copied()
            .unwrap_or(text.len());
        let x_advance = f64::from(position.x_advance) / units_per_em;
        let y_advance = f64::from(position.y_advance) / units_per_em;
        let x_offset = f64::from(position.x_offset) / units_per_em;
        let y_offset = f64::from(position.y_offset) / units_per_em;
        advance += x_advance;
        glyphs.push(PositionedGlyph::new(
            info.glyph_id,
            x_advance,
            y_advance,
            x_offset,
            y_offset,
            start..end,
        )?);
    }
    Ok((
        glyphs,
        advance,
        f64::from(face.ascender()) / units_per_em,
        f64::from(face.descender()) / units_per_em,
    ))
}

fn add_vectors_to_point(
    point: Point3,
    first: Vector3,
    first_scale: f64,
    second: Vector3,
    second_scale: f64,
) -> Result<Point3, PortablePlotError> {
    Point3::new(
        point.x() + first.x() * first_scale + second.x() * second_scale,
        point.y() + first.y() * first_scale + second.y() * second_scale,
        point.z() + first.z() * first_scale + second.z() * second_scale,
    )
}

fn directed_sweep(start: f64, end: f64, counter_clockwise: bool) -> Result<f64, PortablePlotError> {
    if !all_finite(&[start, end]) {
        return Err(PortablePlotError::new(
            "entity_geometry_invalid",
            "arc angles must be finite",
        ));
    }
    let mut sweep = end - start;
    if counter_clockwise {
        while sweep <= 0.0 {
            sweep += TAU;
        }
    } else {
        while sweep >= 0.0 {
            sweep -= TAU;
        }
    }
    if sweep.abs() > TAU + f64::EPSILON * 16.0 {
        return Err(PortablePlotError::new(
            "entity_geometry_invalid",
            "arc sweep exceeds one turn",
        ));
    }
    Ok(sweep)
}

fn append_curve_commands(output: &mut Vec<PathCommand>, curve: &ScenePath, started: &mut bool) {
    let skip = usize::from(*started);
    output.extend(curve.commands().iter().skip(skip).cloned());
    *started = true;
}

fn wide_polyline_has_nontrivial_join(
    vertices: &[Point3],
    widths: &[(f64, f64)],
    closed: bool,
) -> bool {
    let segment_count = if closed {
        vertices.len()
    } else {
        vertices.len().saturating_sub(1)
    };
    if segment_count <= 1 {
        return false;
    }
    let first_join = usize::from(!closed);
    let last_join = if closed {
        vertices.len()
    } else {
        vertices.len().saturating_sub(1)
    };
    for vertex in first_join..last_join {
        let previous_segment = if vertex == 0 {
            segment_count - 1
        } else {
            vertex - 1
        };
        let next_segment = vertex % segment_count;
        if widths[previous_segment].1 != widths[next_segment].0 {
            return true;
        }
        let previous = vertices[previous_segment];
        let shared = vertices[vertex % vertices.len()];
        let next = vertices[(vertex + 1) % vertices.len()];
        let incoming_x = shared.x() - previous.x();
        let incoming_y = shared.y() - previous.y();
        let outgoing_x = next.x() - shared.x();
        let outgoing_y = next.y() - shared.y();
        let incoming_length = incoming_x.hypot(incoming_y);
        let outgoing_length = outgoing_x.hypot(outgoing_y);
        if incoming_length == 0.0 || outgoing_length == 0.0 {
            return true;
        }
        let incoming_x = incoming_x / incoming_length;
        let incoming_y = incoming_y / incoming_length;
        let outgoing_x = outgoing_x / outgoing_length;
        let outgoing_y = outgoing_y / outgoing_length;
        let cross = incoming_x * outgoing_y - incoming_y * outgoing_x;
        let dot = incoming_x * outgoing_x + incoming_y * outgoing_y;
        if !all_finite(&[cross, dot]) || cross != 0.0 || dot <= 0.0 {
            return true;
        }
    }
    false
}

#[derive(Clone)]
struct EntityTask<'a> {
    entity: &'a EntityType,
    parent: Affine3,
    insert_style: Option<InsertStyle>,
    depth: usize,
}

struct ResolvedStyle {
    effective_layer: String,
    cad_color: ConcreteColor,
    cad_lineweight_points: f64,
    color: SceneColor,
    lineweight_points: f64,
    linetype_name: String,
    dash: Option<DashPattern>,
    line_cap: LineCap,
    line_join: LineJoin,
    visible: bool,
}

impl ResolvedStyle {
    fn stroke(&self) -> Result<Stroke, PortablePlotError> {
        Stroke::new(
            self.color,
            self.lineweight_points,
            10.0,
            self.line_cap,
            self.line_join,
            self.dash.clone(),
        )
    }

    fn text_stroke(&self, color: SceneColor) -> Result<Stroke, PortablePlotError> {
        Stroke::new(
            color,
            self.lineweight_points,
            10.0,
            self.line_cap,
            self.line_join,
            None,
        )
    }
}

struct CompiledPrimitive {
    nodes: Vec<DisplayNode>,
    disposition: FidelityDisposition,
    tolerance: Option<(&'static str, f64)>,
}

impl CompiledPrimitive {
    fn exact(nodes: Vec<DisplayNode>) -> Self {
        Self {
            nodes,
            disposition: FidelityDisposition::Exact,
            tolerance: None,
        }
    }

    fn tolerance(nodes: Vec<DisplayNode>, name: &'static str, error: f64) -> Self {
        Self {
            nodes,
            disposition: FidelityDisposition::ToleranceBounded,
            tolerance: Some((name, error)),
        }
    }

    fn substituted(nodes: Vec<DisplayNode>) -> Self {
        Self {
            nodes,
            disposition: FidelityDisposition::Substituted,
            tolerance: None,
        }
    }
}

struct CurvePath {
    path: ScenePath,
    error: f64,
}

#[derive(Debug, Clone, Copy)]
struct ConcreteColor {
    color: SceneColor,
    aci: Option<u16>,
}

fn concrete_color(color: Color) -> Result<ConcreteColor, PortablePlotError> {
    match color {
        Color::Index(7) => Ok(ConcreteColor {
            color: SceneColor::BLACK,
            aci: Some(7),
        }),
        Color::Index(index) => Color::Index(index)
            .rgb()
            .map(|(red, green, blue)| ConcreteColor {
                color: SceneColor::rgb(red, green, blue),
                aci: (index != 0).then_some(u16::from(index)),
            })
            .ok_or_else(|| {
                PortablePlotError::new(
                    "color_unresolved",
                    "ACI colour has no deterministic RGB table entry",
                )
            }),
        Color::Rgb { r, g, b } => Ok(ConcreteColor {
            color: SceneColor::rgb(r, g, b),
            aci: None,
        }),
        Color::ByLayer | Color::ByBlock => Err(PortablePlotError::new(
            "color_unresolved",
            "layer colour must be concrete before entity resolution",
        )),
    }
}

fn apply_plot_style_color(
    object_color: SceneColor,
    rule: crate::portable_plot::resources::PlotStyleRule,
) -> SceneColor {
    let mut color = rule.color.unwrap_or(object_color);
    if rule.grayscale {
        let gray = (299_u32 * u32::from(color.red())
            + 587_u32 * u32::from(color.green())
            + 114_u32 * u32::from(color.blue())
            + 500)
            / 1000;
        let gray = u8::try_from(gray).expect("weighted u8 channels remain within u8");
        color = SceneColor::rgb(gray, gray, gray);
    }
    let screening = u32::from(rule.screening_percent);
    let screen = |channel: u8| {
        let value = (255_u32 * (100 - screening) + u32::from(channel) * screening + 50) / 100;
        u8::try_from(value).expect("screened u8 channel remains within u8")
    };
    SceneColor::rgb(
        screen(color.red()),
        screen(color.green()),
        screen(color.blue()),
    )
}

fn concrete_lineweight(lineweight: LineWeight) -> Result<f64, PortablePlotError> {
    let millimeters = match lineweight {
        LineWeight::Value(value) if value >= 0 => f64::from(value) / 100.0,
        LineWeight::Default => DEFAULT_LINEWEIGHT_MM,
        LineWeight::Value(_) => {
            return Err(PortablePlotError::new(
                "lineweight_invalid",
                "negative explicit lineweight is invalid",
            ));
        }
        LineWeight::ByLayer | LineWeight::ByBlock => {
            return Err(PortablePlotError::new(
                "lineweight_unresolved",
                "layer lineweight must be concrete before entity resolution",
            ));
        }
    };
    let points = millimeters * POINTS_PER_MM;
    if !points.is_finite() {
        return Err(PortablePlotError::new(
            "lineweight_invalid",
            "lineweight conversion produced a non-finite page value",
        ));
    }
    Ok(points)
}

fn resolve_dash(
    document: &CadDocument,
    name: &str,
    entity_scale: f64,
    page_scale: f64,
) -> Result<Option<DashPattern>, PortablePlotError> {
    if !entity_scale.is_finite() || entity_scale <= 0.0 || !finite_positive(page_scale) {
        return Err(PortablePlotError::new(
            "linetype_scale_invalid",
            "linetype scales must be finite and positive",
        ));
    }
    let matches = document
        .line_types
        .iter()
        .filter(|linetype| linetype.name.eq_ignore_ascii_case(name))
        .collect::<Vec<_>>();
    let [linetype] = matches.as_slice() else {
        return Err(PortablePlotError::new(
            "linetype_unresolved",
            "effective linetype does not resolve uniquely",
        ));
    };
    if linetype.elements.is_empty() {
        return Ok(None);
    }
    if linetype
        .elements
        .iter()
        .any(|element| element.complex.is_some())
    {
        return Err(PortablePlotError::new(
            "complex_linetype_unsupported",
            "shape and text linetype elements require the font/shape resource pipeline",
        ));
    }
    let global_scale = document.header.linetype_scale;
    if !global_scale.is_finite() || global_scale <= 0.0 {
        return Err(PortablePlotError::new(
            "linetype_scale_invalid",
            "global linetype scale must be finite and positive",
        ));
    }
    let scale = global_scale * entity_scale * page_scale;
    if !scale.is_finite() || scale <= 0.0 {
        return Err(PortablePlotError::new(
            "linetype_scale_invalid",
            "combined linetype scale is outside the finite page-space range",
        ));
    }
    let mut elements = Vec::new();
    for element in &linetype.elements {
        let length = element.length.abs() * scale;
        if element.length < 0.0 {
            if elements.is_empty() {
                elements.push(0.0);
            }
            elements.push(length);
        } else {
            elements.push(length);
        }
    }
    Ok(Some(DashPattern::new(elements, 0.0)?))
}

fn compile_face(
    face: &Face3D,
    parent: Affine3,
    projection: &Projection,
    style: &ResolvedStyle,
    source: Option<SourceHandle>,
) -> Result<Vec<DisplayNode>, PortablePlotError> {
    let corners = [
        face.first_corner,
        face.second_corner,
        face.third_corner,
        face.fourth_corner,
    ];
    let projected = corners
        .into_iter()
        .map(|corner| projection.project(parent, corner))
        .collect::<Result<Vec<_>, _>>()?;
    let invisible = [
        face.invisible_edges.is_first_invisible(),
        face.invisible_edges.is_second_invisible(),
        face.invisible_edges.is_third_invisible(),
        face.invisible_edges.is_fourth_invisible(),
    ];
    let mut nodes = Vec::new();
    for index in 0..4 {
        if invisible[index] {
            continue;
        }
        let next = (index + 1) % 4;
        if projected[index] == projected[next] {
            continue;
        }
        nodes.push(DisplayNode::Path(PathNode::new(
            ScenePath::polyline([projected[index], projected[next]], false)?,
            None,
            Some(style.stroke()?),
            source.clone(),
        )?));
    }
    Ok(nodes)
}

fn clip_parametric(
    origin: Point2,
    dx: f64,
    dy: f64,
    bounds: Rect,
    ray: bool,
) -> Option<(Point2, Point2)> {
    let mut minimum = if ray { 0.0 } else { f64::NEG_INFINITY };
    let mut maximum = f64::INFINITY;
    for (coordinate, direction, low, high) in [
        (origin.x(), dx, bounds.left, bounds.right),
        (origin.y(), dy, bounds.top, bounds.bottom),
    ] {
        if direction == 0.0 {
            if coordinate < low || coordinate > high {
                return None;
            }
            continue;
        }
        let first = (low - coordinate) / direction;
        let second = (high - coordinate) / direction;
        minimum = minimum.max(first.min(second));
        maximum = maximum.min(first.max(second));
        if maximum < minimum {
            return None;
        }
    }
    Some((
        Point2::new(origin.x() + dx * minimum, origin.y() + dy * minimum).ok()?,
        Point2::new(origin.x() + dx * maximum, origin.y() + dy * maximum).ok()?,
    ))
}

fn validate_block_graph(
    document: &CadDocument,
    maximum_depth: usize,
) -> Result<(), PortablePlotError> {
    let blocks = document
        .block_records
        .iter()
        .map(|block| (block.name.clone(), block))
        .collect::<BTreeMap<_, _>>();
    let mut dependencies = BTreeMap::<String, BTreeSet<String>>::new();
    for block in document.block_records.iter() {
        let nested = document
            .entities()
            .filter(|entity| entity.common().owner_handle == block.handle)
            .filter_map(|entity| match entity {
                EntityType::Insert(insert) => Some(insert.block_name.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        dependencies.insert(block.name.clone(), nested);
    }
    let mut complete = BTreeSet::new();
    for root in blocks.keys() {
        if complete.contains(root) {
            continue;
        }
        let mut active = BTreeSet::new();
        let mut pending = vec![(root.clone(), false, 1_usize)];
        while let Some((block, exiting, depth)) = pending.pop() {
            if exiting {
                active.remove(&block);
                complete.insert(block);
                continue;
            }
            if complete.contains(&block) {
                continue;
            }
            if depth > maximum_depth {
                return Err(PortablePlotError::new(
                    "insert_depth_budget_exceeded",
                    "block dependency graph exceeds the configured depth limit",
                ));
            }
            if !active.insert(block.clone()) {
                return Err(PortablePlotError::new(
                    "block_cycle_detected",
                    "block dependency graph contains a cycle",
                ));
            }
            pending.push((block.clone(), true, depth));
            let nested = dependencies.get(&block).ok_or_else(|| {
                PortablePlotError::new(
                    "block_identity_contradictory",
                    "block dependency graph references an unknown definition",
                )
            })?;
            for dependency in nested.iter().rev() {
                if !blocks.contains_key(dependency) || active.contains(dependency) {
                    return Err(PortablePlotError::new(
                        "block_cycle_or_missing_definition",
                        "block dependency references a missing definition or creates a cycle",
                    ));
                }
                pending.push((dependency.clone(), false, depth + 1));
            }
        }
    }
    Ok(())
}

fn portable_point(value: CadVector3) -> Result<Point3, PortablePlotError> {
    Point3::new(value.x, value.y, value.z)
}

fn portable_vector(value: CadVector3) -> Result<Vector3, PortablePlotError> {
    Vector3::new(value.x, value.y, value.z)
}

fn cad_point(value: Point3) -> CadVector3 {
    CadVector3::new(value.x(), value.y(), value.z())
}

fn scale_vector(vector: Vector3, scale: f64) -> Result<Vector3, PortablePlotError> {
    Vector3::new(vector.x() * scale, vector.y() * scale, vector.z() * scale)
}

fn cross(left: Vector3, right: Vector3) -> Result<Vector3, PortablePlotError> {
    Vector3::new(
        left.y() * right.z() - left.z() * right.y(),
        left.z() * right.x() - left.x() * right.z(),
        left.x() * right.y() - left.y() * right.x(),
    )
}

fn source_handle(handle: Handle) -> Result<Option<SourceHandle>, PortablePlotError> {
    if handle.is_null() {
        Ok(None)
    } else {
        SourceHandle::new(canonical_handle(handle)).map(Some)
    }
}

fn all_finite(values: &[f64]) -> bool {
    values.iter().all(|value| value.is_finite())
}

fn finite_positive(value: f64) -> bool {
    value.is_finite() && value > 0.0
}

fn require_stable_source_cross_check(
    first_stale_block_insert_index: bool,
    second_stale_block_insert_index: bool,
) -> Result<(), PortablePlotError> {
    if first_stale_block_insert_index == second_stale_block_insert_index {
        Ok(())
    } else {
        Err(PortablePlotError::new(
            "source_cross_check_unstable",
            "repeated source parsing disagreed on the BLOCK_HEADER reverse INSERT index",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::portable_plot::test_font::qualification_font;

    fn qualification_shx_font(maximum_error: f64) -> ShxStrokeFontResource {
        let bytes: Arc<[u8]> = Arc::from(
            serde_json::to_vec(&json!({
                "schema": "portable_shx_v1",
                "cap_height": 10.0,
                "descent": 2.0,
                "glyphs": {
                    "0020": {
                        "advance": 4.0,
                        "maximum_error": 0.0,
                        "commands": []
                    },
                    "0041": {
                        "advance": 8.0,
                        "maximum_error": maximum_error,
                        "commands": [
                            { "op": "move_to", "x": 0.0, "y": 0.0 },
                            { "op": "line_to", "x": 4.0, "y": 10.0 },
                            { "op": "line_to", "x": 8.0, "y": 0.0 },
                            { "op": "move_to", "x": 2.0, "y": 4.0 },
                            { "op": "line_to", "x": 6.0, "y": 4.0 }
                        ]
                    }
                }
            }))
            .unwrap(),
        );
        ShxStrokeFontResource::new(
            "qualification/simplex.portable-shx.json",
            bytes.clone(),
            ResourceDigest::of(&bytes),
        )
        .unwrap()
    }

    fn qualification_shx_face(
        logical_identity: &str,
        cap_height: f64,
        descent: f64,
        glyphs: &[(char, f64)],
    ) -> ShxStrokeFontResource {
        let glyphs = glyphs
            .iter()
            .map(|(character, advance)| {
                (
                    format!("{:04X}", u32::from(*character)),
                    json!({
                        "advance": advance,
                        "maximum_error": 0.0,
                        "commands": [
                            { "op": "move_to", "x": 0.0, "y": 0.0 },
                            { "op": "line_to", "x": advance / 2.0, "y": cap_height }
                        ]
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let bytes: Arc<[u8]> = Arc::from(
            serde_json::to_vec(&json!({
                "schema": "portable_shx_v1",
                "cap_height": cap_height,
                "descent": descent,
                "glyphs": glyphs
            }))
            .unwrap(),
        );
        ShxStrokeFontResource::new(logical_identity, bytes.clone(), ResourceDigest::of(&bytes))
            .unwrap()
    }

    fn qualification_composite_font(
        logical_identity: &str,
        glyphs: serde_json::Value,
    ) -> ShxCompositeFontResource {
        let bytes: Arc<[u8]> = Arc::from(
            serde_json::to_vec(&json!({
                "schema": "portable_shx_composite_v1",
                "glyphs": glyphs
            }))
            .unwrap(),
        );
        ShxCompositeFontResource::new(logical_identity, bytes.clone(), ResourceDigest::of(&bytes))
            .unwrap()
    }

    fn qualification_raw_shx_font() -> ShxStrokeFontResource {
        let info = [b"Portable Test".as_slice(), &[0, 10, 2, 2, 0, 0, 0]].concat();
        let glyphs = [
            (0x20_u16, vec![0, 2, 8, 4, 0, 0]),
            (0x41_u16, vec![0, 0x42, 0x4a, 2, 8, 8, 0, 0]),
        ];
        let mut bytes = b"AutoCAD-86 unifont 1.0\r\n\x1a".to_vec();
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&u16::try_from(info.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&info);
        for (code, program) in glyphs {
            bytes.extend_from_slice(&code.to_le_bytes());
            bytes.extend_from_slice(&u16::try_from(program.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(&program);
        }
        let bytes: Arc<[u8]> = Arc::from(bytes);
        ShxStrokeFontResource::from_shx(
            "qualification/simplex.shx",
            bytes.clone(),
            ResourceDigest::of(&bytes),
            &crate::portable_plot::ShxAdmissionOptions::default(),
        )
        .unwrap()
    }

    #[test]
    fn page_rotation_swaps_geometry_for_quarter_turns() {
        let mut layout = Layout::new("Sheet");
        layout.paper_width = 297.0;
        layout.paper_height = 210.0;
        layout.plot_paper_units = 1;
        layout.plot_rotation = 1;
        let context = PageContext::new(&layout, None, &PlotFlagsRecord::default()).unwrap();
        assert!((context.page.width() - 210.0 * POINTS_PER_MM).abs() < 1.0e-9);
        assert!((context.page.height() - 297.0 * POINTS_PER_MM).abs() < 1.0e-9);
    }

    #[test]
    fn layout_plot_area_applies_margins_origin_and_physical_scale() {
        let mut layout = Layout::new("Sheet");
        layout.paper_width = 210.0;
        layout.paper_height = 297.0;
        layout.plot_paper_units = 1;
        layout.plot_type = 5;
        layout.plot_margin_left = 5.0;
        layout.plot_margin_bottom = 5.0;
        layout.plot_margin_right = 5.0;
        layout.plot_margin_top = 5.0;
        layout.plot_origin_x = -5.0;
        layout.plot_origin_y = -5.0;
        layout.plot_scale_numerator = 7.0;
        layout.plot_scale_denominator = 2.0;
        layout.plot_scale_type = 17;
        layout.plot_scale_factor = 0.5;
        let flags = PlotFlagsRecord {
            use_standard_scale: true,
            ..Default::default()
        };
        let context = PageContext::new(&layout, None, &flags).unwrap();
        assert!(context.plot_area_applied);
        assert!(context.plot_scale_applied);
        assert_eq!(context.plot_scale, 1.0);
        assert_eq!(
            context
                .paper_to_page
                .transform_point(Point2::new(0.0, 0.0).unwrap())
                .unwrap(),
            Point2::new(0.0, 297.0 * POINTS_PER_MM).unwrap()
        );
        let upper_right = context
            .paper_to_page
            .transform_point(Point2::new(200.0, 287.0).unwrap())
            .unwrap();
        assert!((upper_right.x() - 200.0 * POINTS_PER_MM).abs() < 1.0e-9);
        assert!((upper_right.y() - 10.0 * POINTS_PER_MM).abs() < 1.0e-9);
        assert!((context.paper_clip.left - 5.0 * POINTS_PER_MM).abs() < 1.0e-9);
        assert!((context.paper_clip.top - 10.0 * POINTS_PER_MM).abs() < 1.0e-9);
        assert!((context.paper_clip.right - 200.0 * POINTS_PER_MM).abs() < 1.0e-9);
        assert!((context.paper_clip.bottom - 292.0 * POINTS_PER_MM).abs() < 1.0e-9);
    }

    #[test]
    fn plot_origin_is_always_interpreted_in_millimeters() {
        let mut layout = Layout::new("Sheet");
        layout.paper_width = 215.9;
        layout.paper_height = 279.4;
        layout.plot_paper_units = 0;
        layout.plot_type = 4;
        layout.plot_window_min_x = 0.0;
        layout.plot_window_min_y = 0.0;
        layout.plot_window_max_x = 1.0;
        layout.plot_window_max_y = 1.0;
        layout.plot_origin_x = 25.4;
        layout.plot_scale_type = 1;
        let context = PageContext::new(&layout, None, &PlotFlagsRecord::default()).unwrap();
        let lower_left = context
            .paper_to_page
            .transform_point(Point2::new(0.0, 0.0).unwrap())
            .unwrap();
        assert!((lower_left.x() - 72.0).abs() < 1.0e-9);
    }

    #[test]
    fn window_plot_area_is_centered_inside_printable_media() {
        let mut layout = Layout::new("Sheet");
        layout.paper_width = 210.0;
        layout.paper_height = 297.0;
        layout.plot_paper_units = 1;
        layout.plot_type = 4;
        layout.plot_margin_left = 10.0;
        layout.plot_margin_bottom = 10.0;
        layout.plot_margin_right = 10.0;
        layout.plot_margin_top = 10.0;
        layout.plot_window_min_x = 20.0;
        layout.plot_window_min_y = 30.0;
        layout.plot_window_max_x = 120.0;
        layout.plot_window_max_y = 80.0;
        layout.plot_scale_type = 1;
        let flags = PlotFlagsRecord {
            plot_centered: true,
            ..Default::default()
        };
        let context = PageContext::new(&layout, None, &flags).unwrap();
        assert!(context.plot_area_applied);
        let lower_left = context
            .paper_to_page
            .transform_point(Point2::new(20.0, 30.0).unwrap())
            .unwrap();
        assert!((lower_left.x() - 55.0 * POINTS_PER_MM).abs() < 1.0e-9);
        assert!((lower_left.y() - 173.5 * POINTS_PER_MM).abs() < 1.0e-9);
    }

    #[test]
    fn window_output_is_clipped_to_the_transformed_requested_area() {
        let mut layout = Layout::new("Sheet");
        layout.paper_width = 200.0;
        layout.paper_height = 100.0;
        layout.plot_paper_units = 1;
        layout.plot_type = 4;
        layout.plot_window_max_x = 100.0;
        layout.plot_window_max_y = 20.0;
        layout.plot_scale_type = 1;
        layout.plot_scale_numerator = 1.0;
        layout.plot_scale_denominator = 2.0;
        let flags = PlotFlagsRecord {
            plot_centered: true,
            ..Default::default()
        };
        let context = PageContext::new(&layout, None, &flags).unwrap();
        assert!((context.paper_clip.left - 75.0 * POINTS_PER_MM).abs() < 1.0e-9);
        assert!((context.paper_clip.top - 45.0 * POINTS_PER_MM).abs() < 1.0e-9);
        assert!((context.paper_clip.right - 125.0 * POINTS_PER_MM).abs() < 1.0e-9);
        assert!((context.paper_clip.bottom - 55.0 * POINTS_PER_MM).abs() < 1.0e-9);
    }

    #[test]
    fn malformed_requested_window_does_not_fall_back_to_a_substitute() {
        let mut layout = Layout::new("Sheet");
        layout.paper_width = 210.0;
        layout.paper_height = 297.0;
        layout.plot_paper_units = 1;
        layout.plot_type = 4;
        let error = PageContext::new(&layout, None, &PlotFlagsRecord::default())
            .err()
            .unwrap();
        assert_eq!(error.code(), "layout_plot_area_invalid");
    }

    #[test]
    fn standard_scale_uses_type_and_factor_instead_of_custom_ratio() {
        let mut layout = Layout::new("Sheet");
        layout.paper_width = 210.0;
        layout.paper_height = 297.0;
        layout.plot_paper_units = 1;
        layout.plot_type = 4;
        layout.plot_window_max_x = 100.0;
        layout.plot_window_max_y = 100.0;
        layout.plot_scale_numerator = 7.0;
        layout.plot_scale_denominator = 1.0;
        layout.plot_scale_type = 17;
        layout.plot_scale_factor = 0.5;
        let flags = PlotFlagsRecord {
            use_standard_scale: true,
            ..Default::default()
        };
        let context = PageContext::new(&layout, None, &flags).unwrap();
        assert_eq!(context.plot_scale, 0.5);
        assert!(context.plot_scale_applied);

        layout.plot_scale_factor = 1.0;
        assert_eq!(
            PageContext::new(&layout, None, &flags)
                .err()
                .unwrap()
                .code(),
            "layout_plot_scale_contradictory"
        );
    }

    #[test]
    fn scale_to_fit_uses_bounds_when_standard_scale_is_active() {
        let mut layout = Layout::new("Sheet");
        layout.paper_width = 200.0;
        layout.paper_height = 100.0;
        layout.plot_paper_units = 1;
        layout.plot_type = 4;
        layout.plot_window_max_x = 100.0;
        layout.plot_window_max_y = 25.0;
        layout.plot_scale_type = 0;
        let flags = PlotFlagsRecord {
            use_standard_scale: true,
            ..Default::default()
        };
        let context = PageContext::new(&layout, None, &flags).unwrap();
        assert_eq!(context.plot_scale, 2.0);
        assert!(context.plot_scale_applied);
    }

    #[test]
    fn unavailable_fit_bounds_use_an_explicit_custom_scale_substitution() {
        let mut layout = Layout::new("Sheet");
        layout.paper_width = 200.0;
        layout.paper_height = 100.0;
        layout.plot_paper_units = 1;
        layout.plot_type = 1;
        layout.plot_scale_type = 0;
        layout.plot_scale_numerator = 1.0;
        layout.plot_scale_denominator = 4.0;
        let flags = PlotFlagsRecord {
            use_standard_scale: true,
            ..Default::default()
        };
        let context = PageContext::new(&layout, None, &flags).unwrap();
        assert_eq!(context.plot_scale, 0.25);
        assert!(!context.plot_area_applied);
        assert!(!context.plot_scale_applied);
    }

    #[test]
    fn disabled_standard_scale_uses_custom_ratio_despite_stale_standard_type() {
        let mut layout = Layout::new("Sheet");
        layout.paper_width = 200.0;
        layout.paper_height = 100.0;
        layout.plot_paper_units = 1;
        layout.plot_type = 4;
        layout.plot_window_max_x = 100.0;
        layout.plot_window_max_y = 25.0;
        layout.plot_scale_type = 17;
        layout.plot_scale_numerator = 3.0;
        layout.plot_scale_denominator = 4.0;
        let context = PageContext::new(&layout, None, &PlotFlagsRecord::default()).unwrap();
        assert_eq!(context.plot_scale, 0.75);
        assert!(context.plot_scale_applied);

        layout.plot_scale_type = 0;
        let context = PageContext::new(&layout, None, &PlotFlagsRecord::default()).unwrap();
        assert_eq!(context.plot_scale, 0.75);
        assert!(context.plot_scale_applied);
    }

    #[test]
    fn repeated_source_classification_must_be_stable() {
        require_stable_source_cross_check(false, false).unwrap();
        require_stable_source_cross_check(true, true).unwrap();
        assert_eq!(
            require_stable_source_cross_check(false, true)
                .unwrap_err()
                .code(),
            "source_cross_check_unstable"
        );
        assert_eq!(
            require_stable_source_cross_check(true, false)
                .unwrap_err()
                .code(),
            "source_cross_check_unstable"
        );
    }

    #[test]
    fn construction_lines_clip_to_page_without_finite_sentinels() {
        let bounds = Rect {
            left: 0.0,
            top: 0.0,
            right: 100.0,
            bottom: 50.0,
        };
        let (start, end) =
            clip_parametric(Point2::new(50.0, 25.0).unwrap(), 1.0, 0.0, bounds, false).unwrap();
        assert_eq!(start, Point2::new(0.0, 25.0).unwrap());
        assert_eq!(end, Point2::new(100.0, 25.0).unwrap());
    }

    #[test]
    fn aci_seven_is_plot_black_and_true_colour_is_preserved() {
        assert_eq!(
            concrete_color(Color::Index(7)).unwrap().color,
            SceneColor::BLACK
        );
        assert_eq!(concrete_color(Color::Index(7)).unwrap().aci, Some(7));
        assert_eq!(
            concrete_color(Color::Rgb { r: 1, g: 2, b: 3 })
                .unwrap()
                .color,
            SceneColor::rgb(1, 2, 3)
        );
        assert_eq!(
            concrete_color(Color::Rgb { r: 1, g: 2, b: 3 }).unwrap().aci,
            None
        );
    }

    #[test]
    fn lineweight_conversion_is_page_space_and_preserves_pdf_hairlines() {
        assert_eq!(
            concrete_lineweight(LineWeight::Value(25)).unwrap(),
            0.25 * POINTS_PER_MM
        );
        assert_eq!(concrete_lineweight(LineWeight::Value(0)).unwrap(), 0.0);
    }

    #[test]
    fn normalized_plot_style_applies_override_grayscale_and_screening() {
        let rule = crate::portable_plot::resources::PlotStyleRule {
            color: Some(SceneColor::rgb(200, 100, 0)),
            grayscale: true,
            screening_percent: 50,
            lineweight_points: None,
            line_cap: None,
            line_join: None,
        };
        assert_eq!(
            apply_plot_style_color(SceneColor::rgb(1, 2, 3), rule),
            SceneColor::rgb(187, 187, 187)
        );
    }

    #[test]
    fn polyline_width_offsets_receive_the_full_parent_insert_scale() {
        let page = PageGeometry::new(500.0, 500.0).unwrap();
        let projection = Projection::paper(Affine2::identity(), page).unwrap();
        let ocs = OcsFrame::from_normal(Vector3::new(0.0, 0.0, 1.0).unwrap()).unwrap();
        let parent = Affine3::scale(2.0, 3.0, 1.0).unwrap();
        let point = Point3::new(4.0, 5.0, 0.0).unwrap();
        let positive = project_ocs_offset(point, 0.0, 1.0, 2.0, ocs, parent, &projection).unwrap();
        let negative = project_ocs_offset(point, 0.0, 1.0, -2.0, ocs, parent, &projection).unwrap();
        assert_eq!(positive, Point2::new(8.0, 21.0).unwrap());
        assert_eq!(negative, Point2::new(8.0, 9.0).unwrap());
    }

    #[test]
    fn wide_polyline_join_partiality_is_usage_sensitive() {
        let straight = [
            Point3::new(0.0, 0.0, 0.0).unwrap(),
            Point3::new(1.0, 0.0, 0.0).unwrap(),
            Point3::new(2.0, 0.0, 0.0).unwrap(),
        ];
        assert!(!wide_polyline_has_nontrivial_join(
            &straight,
            &[(2.0, 2.0), (2.0, 2.0), (0.0, 0.0)],
            false
        ));
        assert!(wide_polyline_has_nontrivial_join(
            &straight,
            &[(2.0, 1.0), (2.0, 2.0), (0.0, 0.0)],
            false
        ));
        let corner = [
            Point3::new(0.0, 0.0, 0.0).unwrap(),
            Point3::new(1.0, 0.0, 0.0).unwrap(),
            Point3::new(1.0, 1.0, 0.0).unwrap(),
        ];
        assert!(wide_polyline_has_nontrivial_join(
            &corner,
            &[(2.0, 2.0), (2.0, 2.0), (0.0, 0.0)],
            false
        ));
        assert!(!wide_polyline_has_nontrivial_join(
            &corner[..2],
            &[(2.0, 2.0), (0.0, 0.0)],
            false
        ));
        let near_collinear = [
            Point3::new(0.0, 0.0, 0.0).unwrap(),
            Point3::new(1.0, 0.0, 0.0).unwrap(),
            Point3::new(2.0, f64::EPSILON, 0.0).unwrap(),
        ];
        assert!(wide_polyline_has_nontrivial_join(
            &near_collinear,
            &[(2.0, 2.0), (2.0, 2.0), (0.0, 0.0)],
            false
        ));
    }

    #[test]
    fn block_graph_cycle_is_detected_iteratively() {
        let mut document = CadDocument::new();
        let first_handle = Handle::new(0xA0);
        let second_handle = Handle::new(0xB0);
        let mut first_record = acadrust::tables::BlockRecord::new("A");
        first_record.handle = first_handle;
        document.block_records.add(first_record).unwrap();
        let mut second_record = acadrust::tables::BlockRecord::new("B");
        second_record.handle = second_handle;
        document.block_records.add(second_record).unwrap();
        let mut first = Insert::new("B", CadVector3::ZERO);
        first.common.owner_handle = first_handle;
        document.add_entity(EntityType::Insert(first)).unwrap();
        let mut second = Insert::new("A", CadVector3::ZERO);
        second.common.owner_handle = second_handle;
        document.add_entity(EntityType::Insert(second)).unwrap();
        assert_eq!(
            validate_block_graph(&document, 8).unwrap_err().code(),
            "block_cycle_or_missing_definition"
        );
    }

    #[test]
    fn stored_dimension_graphics_expand_through_the_anonymous_block() {
        let named = acadrust::tables::BlockRecord::new("DimensionGraphics");
        assert!(!is_dimension_graphics_block(&named));
        let mut external = acadrust::tables::BlockRecord::new("*D2");
        external.flags.is_external = true;
        assert!(is_dimension_graphics_block(&external));
        assert!(block_has_external_semantics(&external));

        let mut document = CadDocument::new();
        let generated_handle = document.allocate_handle();
        let mut generated = acadrust::tables::BlockRecord::new("*D1");
        generated.handle = generated_handle;
        document.block_records.add(generated).unwrap();

        let mut line = acadrust::entities::Line::new();
        line.start = CadVector3::new(10.0, 10.0, 0.0);
        line.end = CadVector3::new(20.0, 10.0, 0.0);
        line.common.owner_handle = generated_handle;
        document.add_entity(EntityType::Line(line)).unwrap();

        let mut dimension = acadrust::entities::DimensionLinear::new(
            CadVector3::new(10.0, 10.0, 0.0),
            CadVector3::new(20.0, 10.0, 0.0),
        );
        dimension.base.block_name = "*D1".to_string();
        document
            .add_entity_to_layout(
                EntityType::Dimension(Dimension::Linear(dimension)),
                "Layout1",
            )
            .unwrap();
        let paper_owner = document
            .objects
            .values()
            .find_map(|object| match object {
                ObjectType::Layout(layout) if layout.name == "Layout1" => Some(layout.block_record),
                _ => None,
            })
            .unwrap();

        let resources = PortableResourceBundle::new();
        let limits = PortablePlotLimits::default();
        let mut ledger = DiagnosticLedger::new(limits.representative_diagnostics);
        let mut compiler = Compiler {
            document: &document,
            resources: &resources,
            plot_style: None,
            limits,
            ledger: &mut ledger,
            print_lineweights: true,
            lineweight_scale: 1.0,
            plot_viewport_borders: false,
            curve_segments: 0,
            insert_instances: 0,
            rendered_viewports: 0,
            used_fonts: BTreeSet::new(),
            used_stroke_fonts: BTreeSet::new(),
            used_composite_fonts: BTreeSet::new(),
            stroke_path_commands: 0,
        };
        let projection = Projection::paper(
            Affine2::identity(),
            PageGeometry::new(100.0, 100.0).unwrap(),
        )
        .unwrap();
        let nodes = compiler
            .compile_owner(paper_owner, Affine3::identity(), None, &projection, 0)
            .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(compiler.insert_instances, 1);
        drop(compiler);
        let fidelity = ledger.finish();
        assert_eq!(fidelity.completeness(), PlotCompleteness::Complete);
        assert!(!fidelity
            .diagnostic_counts()
            .contains_key("entity_type_unsupported"));
    }

    #[test]
    fn exact_source_profile_rejects_non_dwg_before_compilation() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/xrefs/portable-evidence-ascii.dxf");
        let snapshot =
            DrawingSnapshot::new(crate::DrawingFormat::Dxf, std::fs::read(path).unwrap());
        let session = autocad_reader::Reader::open_snapshot(snapshot.reader_snapshot()).unwrap();
        let layout = session.list_layouts().unwrap().remove(0);
        assert_eq!(
            compile_portable_scene(&snapshot, &layout.name, PortablePlotLimits::default())
                .unwrap_err()
                .code(),
            "source_profile_not_admitted"
        );
    }

    #[test]
    fn normalized_shx_text_and_mtext_reach_stroked_deterministic_pdf() {
        let mut document = CadDocument::new();
        for object in document.objects.values_mut() {
            if let ObjectType::Layout(layout) = object {
                if layout.name == "Layout1" {
                    layout.paper_width = 64.0;
                    layout.paper_height = 48.0;
                }
            }
        }
        let mut style = TextStyle::with_truetype("Shape", "simplex.shx");
        style.handle = document.allocate_handle();
        style.font_file = "simplex.shx".to_owned();
        document.text_styles.add(style).unwrap();
        let mut text = Text::with_value("AA", CadVector3::new(8.0, 30.0, 0.0)).with_height(8.0);
        text.style = "Shape".to_owned();
        document
            .add_entity_to_layout(EntityType::Text(text), "Layout1")
            .unwrap();
        let mut mtext = MText::with_value(r"A\P A", CadVector3::new(8.0, 20.0, 0.0))
            .with_height(5.0)
            .with_width(30.0);
        mtext.style = "Shape".to_owned();
        document
            .add_entity_to_layout(EntityType::MText(mtext), "Layout1")
            .unwrap();
        let snapshot = DrawingSnapshot::new(
            crate::DrawingFormat::Dwg,
            acadrust::DwgWriter::write_to_vec(&document).unwrap(),
        );
        let mut resources = PortableResourceBundle::new();
        resources
            .bind_shx_stroke_font("simplex.shx", qualification_shx_font(0.01))
            .unwrap();

        let compilation = compile_portable_scene_with_resources(
            &snapshot,
            "Layout1",
            &resources,
            PortablePlotLimits::default(),
        )
        .unwrap();
        assert_eq!(
            compilation
                .receipt()
                .fidelity()
                .diagnostic_counts()
                .get("mtext_layout_substituted"),
            Some(&1)
        );
        assert!(!compilation
            .receipt()
            .fidelity()
            .diagnostic_counts()
            .contains_key("shx_text_omitted"));
        assert!(compilation
            .receipt()
            .fidelity()
            .tolerances()
            .iter()
            .any(|use_| use_.name() == "shx_stroke_normalization"
                && use_.maximum_error_points() > 0.0));
        assert_eq!(
            compilation.receipt().fidelity().source_counts()["TEXT"].tolerance_bounded,
            1
        );
        let [receipt] = compilation.receipt().resources() else {
            panic!("exactly one normalized stroke font must be receipted");
        };
        assert_eq!(receipt.kind(), "stroke_font");
        assert_eq!(receipt.source_format(), Some("portable_shx_v1"));
        assert!(receipt.semantic_digest().is_some());
        let scene = compilation.display_list().unwrap();
        let usage = scene.validate(DisplayListLimits::default()).unwrap();
        assert_eq!(usage.glyphs, 0);
        assert!(usage.path_commands >= 20);
        assert!(scene.fonts().is_empty());
        let first =
            crate::portable_plot::encode_portable_pdf(scene, DisplayListLimits::default()).unwrap();
        let second =
            crate::portable_plot::encode_portable_pdf(scene, DisplayListLimits::default()).unwrap();
        assert_eq!(first.bytes(), second.bytes());

        let bounded = compile_portable_scene_with_resources(
            &snapshot,
            "Layout1",
            &resources,
            PortablePlotLimits {
                display_list: DisplayListLimits {
                    max_path_commands: 4,
                    ..DisplayListLimits::default()
                },
                ..PortablePlotLimits::default()
            },
        )
        .unwrap();
        assert!(bounded.display_list().is_none());
        assert!(bounded.receipt().resources().is_empty());
        assert!(bounded
            .receipt()
            .fidelity()
            .diagnostic_counts()
            .contains_key("entity_geometry_invalid"));
    }

    #[test]
    fn raw_shx_resource_reaches_stroked_deterministic_pdf_with_exact_receipt() {
        let mut document = CadDocument::new();
        let mut style = TextStyle::with_truetype("Shape", "simplex.shx");
        style.handle = document.allocate_handle();
        style.font_file = "simplex.shx".to_owned();
        document.text_styles.add(style).unwrap();
        let mut text = Text::with_value("A A", CadVector3::new(8.0, 20.0, 0.0)).with_height(8.0);
        text.style = "Shape".to_owned();
        document
            .add_entity_to_layout(EntityType::Text(text), "Layout1")
            .unwrap();
        let snapshot = DrawingSnapshot::new(
            crate::DrawingFormat::Dwg,
            acadrust::DwgWriter::write_to_vec(&document).unwrap(),
        );
        let raw = qualification_raw_shx_font();
        let source_digest = raw.digest();
        let semantic_digest = raw.semantic_digest();
        let mut resources = PortableResourceBundle::new();
        resources.bind_shx_stroke_font("simplex.shx", raw).unwrap();

        let compilation = compile_portable_scene_with_resources(
            &snapshot,
            "Layout1",
            &resources,
            PortablePlotLimits::default(),
        )
        .unwrap();
        let [receipt] = compilation.receipt().resources() else {
            panic!("exactly one raw stroke font must be receipted");
        };
        assert_eq!(receipt.kind(), "stroke_font");
        assert_eq!(receipt.digest(), source_digest);
        assert_eq!(receipt.semantic_digest(), Some(semantic_digest));
        assert_eq!(receipt.source_format(), Some("autocad_shx_unifont_1_0"));
        let scene = compilation.display_list().unwrap();
        let usage = scene.validate(DisplayListLimits::default()).unwrap();
        assert_eq!(usage.glyphs, 0);
        assert!(usage.path_commands >= 6);
        let first =
            crate::portable_plot::encode_portable_pdf(scene, DisplayListLimits::default()).unwrap();
        let second =
            crate::portable_plot::encode_portable_pdf(scene, DisplayListLimits::default()).unwrap();
        assert_eq!(first.bytes(), second.bytes());
    }

    #[test]
    fn explicit_shx_composite_mapping_renders_mixed_faces_and_receipts_every_dependency() {
        let mut document = CadDocument::new();
        let mut style = TextStyle::with_truetype("Composite", "primary.shx");
        style.handle = document.allocate_handle();
        style.font_file = "primary.shx".to_owned();
        style.big_font_file = "big.shx".to_owned();
        document.text_styles.add(style).unwrap();
        let mut text = Text::with_value("A一A", CadVector3::new(8.0, 20.0, 0.0)).with_height(8.0);
        text.style = "Composite".to_owned();
        document
            .add_entity_to_layout(EntityType::Text(text), "Layout1")
            .unwrap();
        let snapshot = DrawingSnapshot::new(
            crate::DrawingFormat::Dwg,
            acadrust::DwgWriter::write_to_vec(&document).unwrap(),
        );
        let primary = qualification_shx_face("resources/primary.json", 10.0, 2.0, &[('A', 8.0)]);
        let big = qualification_shx_face("resources/big.json", 20.0, 8.0, &[('二', 20.0)]);
        let composite = qualification_composite_font(
            "resources/latin-cjk.json",
            json!({
                "4E00": { "font": "big", "glyph": "4E8C" }
            }),
        );
        let composite_digest = composite.digest();
        let mut resources = PortableResourceBundle::new();
        resources
            .bind_shx_stroke_font("primary.shx", primary)
            .unwrap();
        resources.bind_shx_stroke_font("big.shx", big).unwrap();
        resources
            .bind_shx_composite_font("primary.shx", "big.shx", composite)
            .unwrap();

        let compilation = compile_portable_scene_with_resources(
            &snapshot,
            "Layout1",
            &resources,
            PortablePlotLimits::default(),
        )
        .unwrap();
        assert!(!compilation
            .receipt()
            .fidelity()
            .diagnostic_counts()
            .contains_key("shx_composite_font_omitted"));
        assert!(!compilation
            .receipt()
            .fidelity()
            .diagnostic_counts()
            .contains_key("shx_composite_glyph_missing"));
        assert_eq!(
            compilation
                .receipt()
                .resources()
                .iter()
                .filter(|receipt| receipt.kind() == "stroke_font")
                .count(),
            2
        );
        let composite_receipt = compilation
            .receipt()
            .resources()
            .iter()
            .find(|receipt| receipt.kind() == "stroke_font_composite")
            .unwrap();
        assert_eq!(composite_receipt.digest(), composite_digest);
        assert_eq!(
            composite_receipt.source_format(),
            Some("portable_shx_composite_v1")
        );
        assert!(composite_receipt.semantic_digest().is_some());
        let scene = compilation.display_list().unwrap();
        let usage = scene.validate(DisplayListLimits::default()).unwrap();
        assert_eq!(usage.glyphs, 0);
        assert!(usage.path_commands >= 6);
        let first =
            crate::portable_plot::encode_portable_pdf(scene, DisplayListLimits::default()).unwrap();
        let second =
            crate::portable_plot::encode_portable_pdf(scene, DisplayListLimits::default()).unwrap();
        assert_eq!(first.bytes(), second.bytes());
    }

    #[test]
    fn shx_composite_never_falls_back_to_big_by_glyph_coverage() {
        let mut document = CadDocument::new();
        let mut style = TextStyle::with_truetype("Composite", "primary.shx");
        style.handle = document.allocate_handle();
        style.font_file = "primary.shx".to_owned();
        style.big_font_file = "big.shx".to_owned();
        document.text_styles.add(style).unwrap();
        let mut text = Text::with_value("一", CadVector3::new(8.0, 20.0, 0.0)).with_height(8.0);
        text.style = "Composite".to_owned();
        document
            .add_entity_to_layout(EntityType::Text(text), "Layout1")
            .unwrap();
        let snapshot = DrawingSnapshot::new(
            crate::DrawingFormat::Dwg,
            acadrust::DwgWriter::write_to_vec(&document).unwrap(),
        );
        let mut resources = PortableResourceBundle::new();
        resources
            .bind_shx_stroke_font(
                "primary.shx",
                qualification_shx_face("resources/primary.json", 10.0, 2.0, &[('A', 8.0)]),
            )
            .unwrap();
        resources
            .bind_shx_stroke_font(
                "big.shx",
                qualification_shx_face("resources/big.json", 20.0, 8.0, &[('一', 20.0)]),
            )
            .unwrap();
        resources
            .bind_shx_composite_font(
                "primary.shx",
                "big.shx",
                qualification_composite_font("resources/empty.json", json!({})),
            )
            .unwrap();

        let compilation = compile_portable_scene_with_resources(
            &snapshot,
            "Layout1",
            &resources,
            PortablePlotLimits::default(),
        )
        .unwrap();
        assert_eq!(
            compilation
                .receipt()
                .fidelity()
                .diagnostic_counts()
                .get("shx_composite_glyph_missing"),
            Some(&1)
        );
        assert!(compilation.receipt().resources().is_empty());
        assert!(compilation.display_list().is_none());
    }

    #[test]
    fn mtext_inline_shx_override_does_not_inherit_the_style_big_font_pair() {
        let mut document = CadDocument::new();
        let mut style = TextStyle::with_truetype("Composite", "primary.shx");
        style.handle = document.allocate_handle();
        style.font_file = "primary.shx".to_owned();
        style.big_font_file = "big.shx".to_owned();
        document.text_styles.add(style).unwrap();
        let mut text = MText::with_value(r"{\fprimary.shx;A}", CadVector3::new(8.0, 20.0, 0.0))
            .with_height(8.0)
            .with_width(30.0);
        text.style = "Composite".to_owned();
        document
            .add_entity_to_layout(EntityType::MText(text), "Layout1")
            .unwrap();
        let snapshot = DrawingSnapshot::new(
            crate::DrawingFormat::Dwg,
            acadrust::DwgWriter::write_to_vec(&document).unwrap(),
        );
        let mut resources = PortableResourceBundle::new();
        resources
            .bind_shx_stroke_font(
                "primary.shx",
                qualification_shx_face("resources/primary.json", 10.0, 2.0, &[('A', 8.0)]),
            )
            .unwrap();

        let compilation = compile_portable_scene_with_resources(
            &snapshot,
            "Layout1",
            &resources,
            PortablePlotLimits::default(),
        )
        .unwrap();
        assert!(!compilation
            .receipt()
            .fidelity()
            .diagnostic_counts()
            .contains_key("shx_composite_font_omitted"));
        assert_eq!(
            compilation
                .receipt()
                .resources()
                .iter()
                .filter(|receipt| receipt.kind() == "stroke_font")
                .count(),
            1
        );
        assert!(compilation.display_list().is_some());
    }

    #[test]
    fn missing_shx_glyph_does_not_commit_geometry_or_resource_use() {
        let mut document = CadDocument::new();
        let mut style = TextStyle::with_truetype("Shape", "simplex.shx");
        style.handle = document.allocate_handle();
        style.font_file = "simplex.shx".to_owned();
        document.text_styles.add(style).unwrap();
        let mut text = Text::with_value("B", CadVector3::new(8.0, 20.0, 0.0)).with_height(8.0);
        text.style = "Shape".to_owned();
        document
            .add_entity_to_layout(EntityType::Text(text), "Layout1")
            .unwrap();
        let mut composite_style = TextStyle::with_truetype("CompositeShape", "big.shx");
        composite_style.handle = document.allocate_handle();
        composite_style.font_file = "big.shx".to_owned();
        composite_style.big_font_file = "asian.shx".to_owned();
        document.text_styles.add(composite_style).unwrap();
        let mut composite_text =
            Text::with_value("A", CadVector3::new(16.0, 20.0, 0.0)).with_height(8.0);
        composite_text.style = "CompositeShape".to_owned();
        document
            .add_entity_to_layout(EntityType::Text(composite_text), "Layout1")
            .unwrap();
        let snapshot = DrawingSnapshot::new(
            crate::DrawingFormat::Dwg,
            acadrust::DwgWriter::write_to_vec(&document).unwrap(),
        );
        let mut resources = PortableResourceBundle::new();
        resources
            .bind_shx_stroke_font("simplex.shx", qualification_shx_font(0.0))
            .unwrap();
        resources
            .bind_shx_stroke_font("big.shx", qualification_shx_font(0.0))
            .unwrap();

        let compilation = compile_portable_scene_with_resources(
            &snapshot,
            "Layout1",
            &resources,
            PortablePlotLimits::default(),
        )
        .unwrap();
        assert_eq!(
            compilation
                .receipt()
                .fidelity()
                .diagnostic_counts()
                .get("shx_glyph_missing"),
            Some(&1)
        );
        assert_eq!(
            compilation
                .receipt()
                .fidelity()
                .diagnostic_counts()
                .get("shx_composite_font_omitted"),
            Some(&1)
        );
        assert!(compilation.receipt().resources().is_empty());
        assert!(compilation.display_list().is_none());
    }

    #[test]
    fn generated_font_resource_reaches_the_semantic_glyph_pipeline() {
        let mut document = CadDocument::new();
        for object in document.objects.values_mut() {
            if let ObjectType::Layout(layout) = object {
                if layout.name == "Layout1" {
                    layout.paper_width = 64.0;
                    layout.paper_height = 48.0;
                }
            }
        }
        let mut style = TextStyle::with_truetype("Qualification", "qualification.ttf");
        style.handle = document.allocate_handle();
        style.font_file = "qualification.ttf".to_owned();
        document.text_styles.add(style).unwrap();
        let mut text = Text::with_value("A", CadVector3::new(8.0, 24.0, 0.0)).with_height(12.0);
        text.style = "Qualification".to_owned();
        document
            .add_entity_to_layout(EntityType::Text(text), "Layout1")
            .unwrap();
        let snapshot = DrawingSnapshot::new(
            crate::DrawingFormat::Dwg,
            acadrust::DwgWriter::write_to_vec(&document).unwrap(),
        );
        let font = qualification_font();
        let digest = ResourceDigest::of(&font);
        let mut resources = PortableResourceBundle::new();
        resources
            .bind_font(
                "qualification.ttf",
                crate::portable_plot::FontResource::new("qualification/font.ttf", font, 0, digest)
                    .unwrap(),
            )
            .unwrap();

        let compilation = compile_portable_scene_with_resources(
            &snapshot,
            "Layout1",
            &resources,
            PortablePlotLimits::default(),
        )
        .unwrap();
        let scene = compilation.display_list().unwrap();
        assert_eq!(
            scene.validate(DisplayListLimits::default()).unwrap().glyphs,
            1,
            "{:?}",
            compilation.receipt().fidelity().diagnostic_counts()
        );
        assert_eq!(scene.fonts().len(), 1);
        assert_eq!(compilation.receipt().resources().len(), 1);
        assert_eq!(compilation.receipt().resources()[0].kind(), "font");
        assert_eq!(
            compilation.receipt().resources()[0].logical_identity(),
            "qualification/font.ttf"
        );
        assert_eq!(compilation.receipt().resources()[0].source_format(), None);
        assert_eq!(compilation.receipt().resources()[0].semantic_digest(), None);
        crate::portable_plot::encode_portable_pdf(scene, DisplayListLimits::default()).unwrap();
    }

    #[test]
    fn generated_scoped_mtext_reaches_positioned_glyph_runs() {
        let mut document = CadDocument::new();
        for object in document.objects.values_mut() {
            if let ObjectType::Layout(layout) = object {
                if layout.name == "Layout1" {
                    layout.paper_width = 64.0;
                    layout.paper_height = 48.0;
                }
            }
        }
        let mut style = TextStyle::with_truetype("Qualification", "qualification.ttf");
        style.handle = document.allocate_handle();
        style.font_file = "qualification.ttf".to_owned();
        document.text_styles.add(style).unwrap();
        let mut text =
            MText::with_value(r"A{\C1;\H2x;A}A\P\c255;A", CadVector3::new(8.0, 24.0, 0.0))
                .with_height(6.0)
                .with_width(40.0);
        text.style = "Qualification".to_owned();
        document
            .add_entity_to_layout(EntityType::MText(text), "Layout1")
            .unwrap();
        let snapshot = DrawingSnapshot::new(
            crate::DrawingFormat::Dwg,
            acadrust::DwgWriter::write_to_vec(&document).unwrap(),
        );
        let font = qualification_font();
        let digest = ResourceDigest::of(&font);
        let mut resources = PortableResourceBundle::new();
        resources
            .bind_font(
                "qualification.ttf",
                crate::portable_plot::FontResource::new("qualification/font.ttf", font, 0, digest)
                    .unwrap(),
            )
            .unwrap();

        let compilation = compile_portable_scene_with_resources(
            &snapshot,
            "Layout1",
            &resources,
            PortablePlotLimits::default(),
        )
        .unwrap();
        assert_eq!(
            compilation
                .receipt()
                .fidelity()
                .diagnostic_counts()
                .get("mtext_layout_substituted"),
            Some(&1)
        );
        let scene = compilation.display_list().unwrap();
        assert_eq!(
            scene.validate(DisplayListLimits::default()).unwrap().glyphs,
            4
        );
        assert_eq!(scene.fonts().len(), 1);
        let first =
            crate::portable_plot::encode_portable_pdf(scene, DisplayListLimits::default()).unwrap();
        let second =
            crate::portable_plot::encode_portable_pdf(scene, DisplayListLimits::default()).unwrap();
        assert_eq!(first.bytes(), second.bytes());
    }

    #[test]
    fn omitted_later_mtext_run_does_not_receipt_an_unemitted_font() {
        let mut document = CadDocument::new();
        for object in document.objects.values_mut() {
            if let ObjectType::Layout(layout) = object {
                if layout.name == "Layout1" {
                    layout.paper_width = 64.0;
                    layout.paper_height = 48.0;
                }
            }
        }
        let mut style = TextStyle::with_truetype("Qualification", "qualification.ttf");
        style.handle = document.allocate_handle();
        style.font_file = "qualification.ttf".to_owned();
        document.text_styles.add(style).unwrap();
        let mut text = MText::with_value(r"A{\fmissing.ttf;A}", CadVector3::new(8.0, 24.0, 0.0))
            .with_height(6.0)
            .with_width(40.0);
        text.style = "Qualification".to_owned();
        document
            .add_entity_to_layout(EntityType::MText(text), "Layout1")
            .unwrap();
        let mut line = acadrust::entities::Line::new();
        line.start = CadVector3::new(0.0, 0.0, 0.0);
        line.end = CadVector3::new(10.0, 10.0, 0.0);
        document
            .add_entity_to_layout(EntityType::Line(line), "Layout1")
            .unwrap();
        let snapshot = DrawingSnapshot::new(
            crate::DrawingFormat::Dwg,
            acadrust::DwgWriter::write_to_vec(&document).unwrap(),
        );
        let font = qualification_font();
        let digest = ResourceDigest::of(&font);
        let mut resources = PortableResourceBundle::new();
        resources
            .bind_font(
                "qualification.ttf",
                crate::portable_plot::FontResource::new("qualification/font.ttf", font, 0, digest)
                    .unwrap(),
            )
            .unwrap();

        let compilation = compile_portable_scene_with_resources(
            &snapshot,
            "Layout1",
            &resources,
            PortablePlotLimits::default(),
        )
        .unwrap();
        assert_eq!(
            compilation
                .receipt()
                .fidelity()
                .diagnostic_counts()
                .get("font_text_omitted"),
            Some(&1)
        );
        assert!(compilation.receipt().resources().is_empty());
        assert!(compilation.display_list().unwrap().fonts().is_empty());
    }

    #[test]
    fn caller_authorized_fallback_is_visible_in_fidelity_and_receipt() {
        let mut document = CadDocument::new();
        for object in document.objects.values_mut() {
            if let ObjectType::Layout(layout) = object {
                if layout.name == "Layout1" {
                    layout.paper_width = 64.0;
                    layout.paper_height = 48.0;
                }
            }
        }
        let mut style = TextStyle::with_truetype("Missing", "missing.ttf");
        style.handle = document.allocate_handle();
        style.font_file = "missing.ttf".to_owned();
        document.text_styles.add(style).unwrap();
        let mut text = Text::with_value("A", CadVector3::new(8.0, 24.0, 0.0)).with_height(12.0);
        text.style = "Missing".to_owned();
        document
            .add_entity_to_layout(EntityType::Text(text), "Layout1")
            .unwrap();
        let mut shape_style = TextStyle::with_truetype("Shape", "simplex.shx");
        shape_style.handle = document.allocate_handle();
        shape_style.font_file = "simplex.shx".to_owned();
        document.text_styles.add(shape_style).unwrap();
        let mut shape_text =
            Text::with_value("A", CadVector3::new(20.0, 24.0, 0.0)).with_height(12.0);
        shape_text.style = "Shape".to_owned();
        document
            .add_entity_to_layout(EntityType::Text(shape_text), "Layout1")
            .unwrap();
        let snapshot = DrawingSnapshot::new(
            crate::DrawingFormat::Dwg,
            acadrust::DwgWriter::write_to_vec(&document).unwrap(),
        );
        let font = qualification_font();
        let digest = ResourceDigest::of(&font);
        let mut resources = PortableResourceBundle::new();
        resources
            .bind_fallback_font(
                crate::portable_plot::FontResource::new(
                    "qualification/fallback.ttf",
                    font,
                    0,
                    digest,
                )
                .unwrap(),
            )
            .unwrap();

        let compilation = compile_portable_scene_with_resources(
            &snapshot,
            "Layout1",
            &resources,
            PortablePlotLimits::default(),
        )
        .unwrap();
        assert_eq!(
            compilation
                .receipt()
                .fidelity()
                .diagnostic_counts()
                .get("font_substituted"),
            Some(&1)
        );
        assert_eq!(
            compilation
                .receipt()
                .fidelity()
                .diagnostic_counts()
                .get("shx_text_omitted"),
            Some(&1)
        );
        let scene = compilation.display_list().unwrap();
        assert_eq!(
            scene.validate(DisplayListLimits::default()).unwrap().glyphs,
            1
        );
        assert_eq!(compilation.receipt().resources().len(), 1);
        assert_eq!(
            compilation.receipt().resources()[0].logical_identity(),
            "qualification/fallback.ttf"
        );
    }

    #[test]
    fn dot_linetype_resolves_with_positive_cycle_advance() {
        let document = CadDocument::new();
        let dash = resolve_dash(&document, "Continuous", 1.0, 1.0).unwrap();
        assert!(dash.is_none());
        let dotted = document
            .line_types
            .iter()
            .find(|linetype| linetype.name == "Dotted");
        if dotted.is_some() {
            assert!(resolve_dash(&document, "Dotted", 1.0, 1.0)
                .unwrap()
                .is_some());
        }
    }

    #[test]
    fn curve_limit_validation_rejects_unbounded_tolerance() {
        let limits = PortablePlotLimits {
            curve_tolerance_points: f64::INFINITY,
            ..PortablePlotLimits::default()
        };
        assert_eq!(
            limits.validate().unwrap_err().code(),
            "portable_plot_limits_invalid"
        );
    }

    #[test]
    fn cad_text_controls_are_normalized_without_executing_formatting() {
        assert_eq!(
            normalize_cad_text("45%%d %%p0.1 %%c10 %%%").unwrap(),
            "45° ±0.1 Ø10 %"
        );
        assert!(normalize_cad_text("under%%u").is_err());
        assert!(normalize_cad_text("line\nbreak").is_err());
    }

    #[test]
    fn closed_mtext_parser_preserves_scoped_run_semantics() {
        let parsed = parse_closed_mtext(
            r"A{\C1;\H2x;A}A\P\c255;\U+0041\\\{\}\~\;%%d%%c%%%%",
            1_024,
            8,
            1_024,
        )
        .unwrap();
        assert_eq!(parsed.paragraphs.len(), 2);
        assert_eq!(parsed.paragraphs[0].len(), 3);
        assert_eq!(parsed.paragraphs[0][0].text, "A");
        assert_eq!(parsed.paragraphs[0][0].format, MTextRunFormat::default());
        assert_eq!(parsed.paragraphs[0][1].text, "A");
        assert_eq!(parsed.paragraphs[0][1].format.color, MTextColorSpec::Aci(1));
        assert_eq!(
            parsed.paragraphs[0][1].format.height,
            MTextHeightSpec::Factor(2.0)
        );
        assert_eq!(parsed.paragraphs[0][2].text, "A");
        assert_eq!(parsed.paragraphs[1][0].text, "A\\{}\u{00a0};°Ø%");
        assert_eq!(
            parsed.paragraphs[1][0].format.color,
            MTextColorSpec::Rgb(255, 0, 0)
        );
        for (value, expected) in [
            (r"\c255;A", MTextColorSpec::Rgb(255, 0, 0)),
            (r"\c65280;A", MTextColorSpec::Rgb(0, 255, 0)),
            (r"\c16711680;A", MTextColorSpec::Rgb(0, 0, 255)),
        ] {
            let parsed = parse_closed_mtext(value, 1_024, 8, 1_024).unwrap();
            assert_eq!(parsed.paragraphs[0][0].format.color, expected);
        }
        let caret = parse_closed_mtext("A^JB^M^ C", 1_024, 8, 1_024).unwrap();
        assert_eq!(caret.paragraphs.len(), 2);
        assert_eq!(caret.paragraphs[0][0].text, "A");
        assert_eq!(caret.paragraphs[1][0].text, "B^C");
    }

    #[test]
    fn closed_mtext_parser_rejects_silently_lossy_controls_and_malformed_input() {
        for value in [
            r"\B1;A",
            r"\t4;A",
            r"%<field>%",
            r"\fArial|b1;A",
            "A\tB",
            "A^IB",
            "A^ZB",
        ] {
            assert_eq!(
                parse_closed_mtext(value, 1_024, 8, 1_024).unwrap_err().kind,
                MTextParseFailureKind::Omitted,
                "{value}"
            );
        }
        assert_eq!(
            parse_closed_mtext(r"\ZA", 1_024, 8, 1_024)
                .unwrap_err()
                .kind,
            MTextParseFailureKind::Unsupported
        );
        for value in [r"{A", r"A}", r"\C999;A", r"\Hnan;A", r"\U+D800"] {
            assert_eq!(
                parse_closed_mtext(value, 1_024, 8, 1_024).unwrap_err().kind,
                MTextParseFailureKind::Invalid,
                "{value}"
            );
        }
        assert_eq!(
            parse_closed_mtext("A\u{0001}B", 1_024, 8, 1_024)
                .unwrap_err()
                .kind,
            MTextParseFailureKind::Invalid
        );
        assert_eq!(
            parse_closed_mtext("AA", 1, 8, 1_024).unwrap_err().code,
            "mtext_format_budget_exceeded"
        );
        assert_eq!(
            parse_closed_mtext("{{A}}", 1_024, 1, 1_024)
                .unwrap_err()
                .code,
            "mtext_format_depth_exceeded"
        );
        let eight_groups = format!("{}A{}", "{".repeat(8), "}".repeat(8));
        assert!(parse_closed_mtext(&eight_groups, 1_024, 128, 1_024).is_ok());
        assert!(parse_closed_mtext(&eight_groups, 1_024, 8, 1_024).is_ok());
        assert_eq!(
            parse_closed_mtext(&eight_groups, 1_024, 7, 1_024)
                .unwrap_err()
                .code,
            "mtext_format_depth_exceeded"
        );
        let nine_groups = format!("{}A{}", "{".repeat(9), "}".repeat(9));
        assert_eq!(
            parse_closed_mtext(&nine_groups, 1_024, 128, 1_024)
                .unwrap_err()
                .code,
            "mtext_format_depth_exceeded"
        );
        assert_eq!(
            parse_closed_mtext(r"A{\C1;A}", 1_024, 8, 1)
                .unwrap_err()
                .code,
            "mtext_format_budget_exceeded"
        );
        assert_eq!(
            parse_closed_mtext(r"\P\P", 1_024, 8, 2).unwrap_err().code,
            "mtext_format_budget_exceeded"
        );
    }

    #[test]
    fn directed_hatch_arcs_are_bounded_to_one_turn() {
        assert!((directed_sweep(0.0, FRAC_PI_2, true).unwrap() - FRAC_PI_2).abs() < 1.0e-12);
        assert!((directed_sweep(0.0, FRAC_PI_2, false).unwrap() + 3.0 * FRAC_PI_2).abs() < 1.0e-12);
    }
}
