use std::cmp::Ordering;

use super::contract::{
    DimensionStyleRecord, LinetypeElementKind, LinetypeElementRecord, LinetypeRecord,
    NamedUcsRecord, NamedViewRecord, SymbolPoint3, SymbolSelector, TextStyleRecord,
};
use acadrust::tables::{DimStyle, LineType, Table, TableEntry, TextStyle, Ucs, View};
use acadrust::types::Handle;
use acadrust::CadDocument;

autocad_diagnostics::domain_error!(pub struct SymbolReadError, new = pub(crate));

#[derive(Clone, Copy)]
struct ResourceKind {
    key: &'static str,
    label: &'static str,
}

const LINETYPE: ResourceKind = ResourceKind {
    key: "linetype",
    label: "linetype",
};
const TEXT_STYLE: ResourceKind = ResourceKind {
    key: "text_style",
    label: "text style",
};
const DIMENSION_STYLE: ResourceKind = ResourceKind {
    key: "dimension_style",
    label: "dimension style",
};
const NAMED_VIEW: ResourceKind = ResourceKind {
    key: "named_view",
    label: "named view",
};
const NAMED_UCS: ResourceKind = ResourceKind {
    key: "named_ucs",
    label: "named UCS",
};

fn error_code(kind: ResourceKind, suffix: &str) -> String {
    format!("{}_{}", kind.key, suffix)
}

fn name_key(name: &str) -> String {
    name.to_uppercase()
}

fn canonical_handle(handle: Handle, kind: ResourceKind) -> Result<String, SymbolReadError> {
    if !handle.is_valid() {
        return Err(SymbolReadError::new(
            error_code(kind, "invalid_handle"),
            format!("{} has invalid handle 0", kind.label),
        ));
    }
    Ok(format!("{:X}", handle.value()))
}

fn canonical_optional_handle(handle: Handle) -> Option<String> {
    handle.is_valid().then(|| format!("{:X}", handle.value()))
}

fn parse_handle(input: &str, kind: ResourceKind) -> Result<Handle, SymbolReadError> {
    let trimmed = input.trim();
    if trimmed != input {
        return Err(SymbolReadError::new(
            error_code(kind, "invalid_handle"),
            format!(
                "{} handle must not contain surrounding whitespace",
                kind.label
            ),
        ));
    }
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if without_prefix.is_empty() {
        return Err(SymbolReadError::new(
            error_code(kind, "invalid_handle"),
            format!("{} handle is empty", kind.label),
        ));
    }
    let value = u64::from_str_radix(without_prefix, 16).map_err(|_| {
        SymbolReadError::new(
            error_code(kind, "invalid_handle"),
            format!("invalid {} handle `{input}`", kind.label),
        )
    })?;
    let handle = Handle::new(value);
    if !handle.is_valid() {
        return Err(SymbolReadError::new(
            error_code(kind, "invalid_handle"),
            format!("{} handle 0 is invalid", kind.label),
        ));
    }
    Ok(handle)
}

fn selector_name(
    selector: &SymbolSelector,
    kind: ResourceKind,
) -> Result<Option<&str>, SymbolReadError> {
    match selector.name.as_deref() {
        Some(name) if name.trim().is_empty() => Err(SymbolReadError::new(
            error_code(kind, "invalid_name"),
            format!("{} name must not be empty", kind.label),
        )),
        Some(name) if name.trim() != name => Err(SymbolReadError::new(
            error_code(kind, "invalid_name"),
            format!(
                "{} name must not contain surrounding whitespace",
                kind.label
            ),
        )),
        Some(name) => Ok(Some(name)),
        None => Ok(None),
    }
}

fn resolve_table_entry<'a, T: TableEntry>(
    table: &'a Table<T>,
    selector: &SymbolSelector,
    kind: ResourceKind,
) -> Result<&'a T, SymbolReadError> {
    let requested_handle = selector
        .handle
        .as_deref()
        .map(|handle| parse_handle(handle, kind))
        .transpose()?;
    let requested_name = selector_name(selector, kind)?;

    if requested_handle.is_none() && requested_name.is_none() {
        return Err(SymbolReadError::new(
            error_code(kind, "missing_identity"),
            format!("provide a {} handle or name", kind.label),
        ));
    }

    if let Some(handle) = requested_handle {
        let mut matches = table.iter().filter(|entry| entry.handle() == handle);
        let entry = matches.next().ok_or_else(|| {
            SymbolReadError::new(
                error_code(kind, "not_found"),
                format!("{} handle {:X} was not found", kind.label, handle.value()),
            )
        })?;
        if matches.next().is_some() {
            return Err(SymbolReadError::new(
                error_code(kind, "ambiguous_handle"),
                format!(
                    "more than one {} uses handle {:X}",
                    kind.label,
                    handle.value()
                ),
            ));
        }
        if let Some(name) = requested_name {
            if name_key(entry.name()) != name_key(name) {
                return Err(SymbolReadError::new(
                    error_code(kind, "identity_mismatch"),
                    format!(
                        "{} handle {:X} is named `{}`, not `{name}`",
                        kind.label,
                        handle.value(),
                        entry.name()
                    ),
                ));
            }
        }
        return Ok(entry);
    }

    let requested_name = requested_name.expect("validated selector has a name");
    let mut matches = table
        .iter()
        .filter(|entry| name_key(entry.name()) == name_key(requested_name));
    let entry = matches.next().ok_or_else(|| {
        SymbolReadError::new(
            error_code(kind, "not_found"),
            format!("{} `{requested_name}` was not found", kind.label),
        )
    })?;
    if matches.next().is_some() {
        return Err(SymbolReadError::new(
            error_code(kind, "ambiguous_name"),
            format!(
                "more than one {} is named `{requested_name}`; use a handle",
                kind.label
            ),
        ));
    }
    let handle = entry.handle();
    if table
        .iter()
        .filter(|candidate| candidate.handle() == handle)
        .nth(1)
        .is_some()
    {
        return Err(SymbolReadError::new(
            error_code(kind, "ambiguous_handle"),
            format!(
                "more than one {} uses handle {:X}",
                kind.label,
                handle.value()
            ),
        ));
    }
    Ok(entry)
}

fn compare_handles(left_handle: &str, right_handle: &str) -> Ordering {
    let left =
        u64::from_str_radix(left_handle, 16).expect("canonical symbol handle is hexadecimal");
    let right =
        u64::from_str_radix(right_handle, 16).expect("canonical symbol handle is hexadecimal");
    left.cmp(&right)
}

fn ensure_unique_handles<'a>(
    handles: impl IntoIterator<Item = &'a str>,
    kind: ResourceKind,
) -> Result<(), SymbolReadError> {
    let handles = handles.into_iter().collect::<Vec<_>>();
    if handles.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SymbolReadError::new(
            error_code(kind, "ambiguous_handle"),
            format!("more than one {} uses the same handle", kind.label),
        ));
    }
    Ok(())
}

fn finite_number(value: f64, kind: ResourceKind, field: &str) -> Result<f64, SymbolReadError> {
    value.is_finite().then_some(value).ok_or_else(|| {
        SymbolReadError::new(
            error_code(kind, "unsupported_data"),
            format!("{} {field} is not a finite number", kind.label),
        )
    })
}

fn current_table_entry<T: TableEntry>(
    table: &Table<T>,
    entry: &T,
    current_handle: Handle,
    current_name: &str,
) -> bool {
    if current_handle.is_valid()
        && table
            .iter()
            .any(|candidate| candidate.handle() == current_handle)
    {
        entry.handle() == current_handle
    } else {
        name_key(entry.name()) == name_key(current_name)
    }
}

fn linetype_record(
    doc: &CadDocument,
    linetype: &LineType,
) -> Result<LinetypeRecord, SymbolReadError> {
    Ok(LinetypeRecord {
        handle: canonical_handle(linetype.handle(), LINETYPE)?,
        name: linetype.name.clone(),
        description: linetype.description.clone(),
        pattern_length: finite_number(linetype.pattern_length, LINETYPE, "pattern_length")?,
        alignment: linetype.alignment,
        elements: linetype
            .elements
            .iter()
            .map(|element| {
                Ok(LinetypeElementRecord {
                    kind: if element.is_dash() {
                        LinetypeElementKind::Dash
                    } else if element.is_space() {
                        LinetypeElementKind::Space
                    } else {
                        LinetypeElementKind::Dot
                    },
                    signed_length: finite_number(
                        element.length,
                        LINETYPE,
                        "element signed_length",
                    )?,
                })
            })
            .collect::<Result<Vec<_>, SymbolReadError>>()?,
        is_continuous: linetype.is_continuous(),
        is_standard: linetype.is_standard(),
        is_current: current_table_entry(
            &doc.line_types,
            linetype,
            doc.header.current_linetype_handle,
            &doc.header.current_linetype_name,
        ),
        xref_dependent: linetype.xref_dependent,
    })
}

pub(super) fn list_linetypes(doc: &CadDocument) -> Result<Vec<LinetypeRecord>, SymbolReadError> {
    let mut records = doc
        .line_types
        .iter()
        .map(|linetype| linetype_record(doc, linetype))
        .collect::<Result<Vec<_>, _>>()?;
    records.sort_by(|left, right| compare_handles(&left.handle, &right.handle));
    ensure_unique_handles(
        records.iter().map(|record| record.handle.as_str()),
        LINETYPE,
    )?;
    Ok(records)
}

pub(super) fn get_linetype(
    doc: &CadDocument,
    selector: &SymbolSelector,
) -> Result<LinetypeRecord, SymbolReadError> {
    linetype_record(
        doc,
        resolve_table_entry(&doc.line_types, selector, LINETYPE)?,
    )
}

fn text_style_record(
    doc: &CadDocument,
    style: &TextStyle,
) -> Result<TextStyleRecord, SymbolReadError> {
    Ok(TextStyleRecord {
        handle: canonical_handle(style.handle(), TEXT_STYLE)?,
        name: style.name.clone(),
        fixed_height: finite_number(style.height, TEXT_STYLE, "fixed_height")?,
        width_factor: finite_number(style.width_factor, TEXT_STYLE, "width_factor")?,
        oblique_angle_radians: finite_number(
            style.oblique_angle,
            TEXT_STYLE,
            "oblique_angle_radians",
        )?,
        last_height: finite_number(style.last_height, TEXT_STYLE, "last_height")?,
        font_file: style.font_file.clone(),
        big_font_file: style.big_font_file.clone(),
        true_type_font: style.true_type_font.clone(),
        backward: style.flags.backward,
        upside_down: style.flags.upside_down,
        annotative: style.annotative,
        xref_dependent: style.xref_dependent,
        is_standard: style.is_standard(),
        is_current: current_table_entry(
            &doc.text_styles,
            style,
            doc.header.current_text_style_handle,
            &doc.header.current_text_style_name,
        ),
    })
}

pub(super) fn list_text_styles(doc: &CadDocument) -> Result<Vec<TextStyleRecord>, SymbolReadError> {
    let mut records = doc
        .text_styles
        .iter()
        .map(|style| text_style_record(doc, style))
        .collect::<Result<Vec<_>, _>>()?;
    records.sort_by(|left, right| compare_handles(&left.handle, &right.handle));
    ensure_unique_handles(
        records.iter().map(|record| record.handle.as_str()),
        TEXT_STYLE,
    )?;
    Ok(records)
}

pub(super) fn get_text_style(
    doc: &CadDocument,
    selector: &SymbolSelector,
) -> Result<TextStyleRecord, SymbolReadError> {
    text_style_record(
        doc,
        resolve_table_entry(&doc.text_styles, selector, TEXT_STYLE)?,
    )
}

fn decimal_separator(code: i16) -> Option<String> {
    u32::try_from(code)
        .ok()
        .and_then(char::from_u32)
        .map(|value| value.to_string())
}

fn dimension_style_record(
    doc: &CadDocument,
    style: &DimStyle,
) -> Result<DimensionStyleRecord, SymbolReadError> {
    Ok(DimensionStyleRecord {
        handle: canonical_handle(style.handle(), DIMENSION_STYLE)?,
        name: style.name.clone(),
        is_standard: style.is_standard(),
        is_current: current_table_entry(
            &doc.dim_styles,
            style,
            doc.header.current_dimstyle_handle,
            &doc.header.current_dimstyle_name,
        ),
        annotative: style.annotative,
        overall_scale: finite_number(style.dimscale, DIMENSION_STYLE, "overall_scale")?,
        arrow_size: finite_number(style.dimasz, DIMENSION_STYLE, "arrow_size")?,
        center_mark_size: finite_number(style.dimcen, DIMENSION_STYLE, "center_mark_size")?,
        tick_size: finite_number(style.dimtsz, DIMENSION_STYLE, "tick_size")?,
        arrow_block_handle: canonical_optional_handle(style.dimblk),
        first_arrow_block_handle: canonical_optional_handle(style.dimblk1),
        second_arrow_block_handle: canonical_optional_handle(style.dimblk2),
        leader_arrow_block_handle: canonical_optional_handle(style.dimldrblk),
        dimension_line_extension: finite_number(
            style.dimdle,
            DIMENSION_STYLE,
            "dimension_line_extension",
        )?,
        dimension_line_increment: finite_number(
            style.dimdli,
            DIMENSION_STYLE,
            "dimension_line_increment",
        )?,
        dimension_line_gap: finite_number(style.dimgap, DIMENSION_STYLE, "dimension_line_gap")?,
        suppress_first_dimension_line: style.dimsd1,
        suppress_second_dimension_line: style.dimsd2,
        extension_line_extension: finite_number(
            style.dimexe,
            DIMENSION_STYLE,
            "extension_line_extension",
        )?,
        extension_line_offset: finite_number(
            style.dimexo,
            DIMENSION_STYLE,
            "extension_line_offset",
        )?,
        suppress_first_extension_line: style.dimse1,
        suppress_second_extension_line: style.dimse2,
        text_height: finite_number(style.dimtxt, DIMENSION_STYLE, "text_height")?,
        text_style_handle: canonical_optional_handle(style.dimtxsty_handle),
        text_style_name: style.dimtxsty.clone(),
        text_horizontal_alignment: style.dimjust,
        text_vertical_alignment: style.dimtad,
        linear_scale_factor: finite_number(style.dimlfac, DIMENSION_STYLE, "linear_scale_factor")?,
        linear_unit_format: style.dimlunit,
        linear_decimal_places: style.dimdec,
        linear_rounding: finite_number(style.dimrnd, DIMENSION_STYLE, "linear_rounding")?,
        decimal_separator_code: style.dimdsep,
        decimal_separator: decimal_separator(style.dimdsep),
        angular_unit_format: style.dimaunit,
        angular_decimal_places: style.dimadec,
        alternate_units_enabled: style.dimalt,
        tolerances_enabled: style.dimtol,
        limits_enabled: style.dimlim,
        postfix: style.dimpost.clone(),
        dimension_linetype_handle: canonical_optional_handle(style.dimltex_handle),
        first_extension_linetype_handle: canonical_optional_handle(style.dimltex1_handle),
        second_extension_linetype_handle: canonical_optional_handle(style.dimltex2_handle),
    })
}

pub(super) fn list_dimension_styles(
    doc: &CadDocument,
) -> Result<Vec<DimensionStyleRecord>, SymbolReadError> {
    let mut records = doc
        .dim_styles
        .iter()
        .map(|style| dimension_style_record(doc, style))
        .collect::<Result<Vec<_>, _>>()?;
    records.sort_by(|left, right| compare_handles(&left.handle, &right.handle));
    ensure_unique_handles(
        records.iter().map(|record| record.handle.as_str()),
        DIMENSION_STYLE,
    )?;
    Ok(records)
}

pub(super) fn get_dimension_style(
    doc: &CadDocument,
    selector: &SymbolSelector,
) -> Result<DimensionStyleRecord, SymbolReadError> {
    dimension_style_record(
        doc,
        resolve_table_entry(&doc.dim_styles, selector, DIMENSION_STYLE)?,
    )
}

fn finite_point3(
    value: acadrust::types::Vector3,
    kind: ResourceKind,
    field: &str,
) -> Result<SymbolPoint3, SymbolReadError> {
    Ok(SymbolPoint3 {
        x: finite_number(value.x, kind, &format!("{field}.x"))?,
        y: finite_number(value.y, kind, &format!("{field}.y"))?,
        z: finite_number(value.z, kind, &format!("{field}.z"))?,
    })
}

fn named_view_record(view: &View) -> Result<NamedViewRecord, SymbolReadError> {
    Ok(NamedViewRecord {
        handle: canonical_handle(view.handle(), NAMED_VIEW)?,
        name: view.name.clone(),
        center: finite_point3(view.center, NAMED_VIEW, "center")?,
        height: finite_number(view.height, NAMED_VIEW, "height")?,
        width: finite_number(view.width, NAMED_VIEW, "width")?,
        direction: finite_point3(view.direction, NAMED_VIEW, "direction")?,
        target: finite_point3(view.target, NAMED_VIEW, "target")?,
        lens_length_mm: finite_number(view.lens_length, NAMED_VIEW, "lens_length_mm")?,
        front_clip: finite_number(view.front_clip, NAMED_VIEW, "front_clip")?,
        back_clip: finite_number(view.back_clip, NAMED_VIEW, "back_clip")?,
        twist_angle_radians: finite_number(view.twist_angle, NAMED_VIEW, "twist_angle_radians")?,
    })
}

pub(super) fn list_named_views(doc: &CadDocument) -> Result<Vec<NamedViewRecord>, SymbolReadError> {
    let mut records = doc
        .views
        .iter()
        .map(named_view_record)
        .collect::<Result<Vec<_>, _>>()?;
    records.sort_by(|left, right| compare_handles(&left.handle, &right.handle));
    ensure_unique_handles(
        records.iter().map(|record| record.handle.as_str()),
        NAMED_VIEW,
    )?;
    Ok(records)
}

pub(super) fn get_named_view(
    doc: &CadDocument,
    selector: &SymbolSelector,
) -> Result<NamedViewRecord, SymbolReadError> {
    named_view_record(resolve_table_entry(&doc.views, selector, NAMED_VIEW)?)
}

fn named_ucs_record(ucs: &Ucs) -> Result<NamedUcsRecord, SymbolReadError> {
    Ok(NamedUcsRecord {
        handle: canonical_handle(ucs.handle(), NAMED_UCS)?,
        name: ucs.name.clone(),
        origin: finite_point3(ucs.origin, NAMED_UCS, "origin")?,
        x_axis: finite_point3(ucs.x_axis, NAMED_UCS, "x_axis")?,
        y_axis: finite_point3(ucs.y_axis, NAMED_UCS, "y_axis")?,
        z_axis: finite_point3(ucs.z_axis(), NAMED_UCS, "z_axis")?,
    })
}

pub(super) fn list_named_ucs(doc: &CadDocument) -> Result<Vec<NamedUcsRecord>, SymbolReadError> {
    let mut records = doc
        .ucss
        .iter()
        .map(named_ucs_record)
        .collect::<Result<Vec<_>, _>>()?;
    records.sort_by(|left, right| compare_handles(&left.handle, &right.handle));
    ensure_unique_handles(
        records.iter().map(|record| record.handle.as_str()),
        NAMED_UCS,
    )?;
    Ok(records)
}

pub(super) fn get_named_ucs(
    doc: &CadDocument,
    selector: &SymbolSelector,
) -> Result<NamedUcsRecord, SymbolReadError> {
    named_ucs_record(resolve_table_entry(&doc.ucss, selector, NAMED_UCS)?)
}

#[cfg(test)]
mod tests {
    use super::super::Reader;
    use super::*;
    use acadrust::tables::{DimStyle, LineType, LineTypeElement, TextStyle, Ucs, View};
    use acadrust::types::{Handle, Vector3};
    use std::path::{Path, PathBuf};

    fn selector_name(name: &str) -> SymbolSelector {
        SymbolSelector {
            name: Some(name.to_string()),
            ..Default::default()
        }
    }

    fn fixture_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    #[test]
    fn default_core_symbol_tables_are_deterministic_and_current_is_explicit() {
        let doc = CadDocument::new();

        let linetypes = list_linetypes(&doc).unwrap();
        assert_eq!(
            linetypes
                .iter()
                .map(|record| record.name.as_str())
                .collect::<Vec<_>>(),
            ["Continuous", "ByLayer", "ByBlock"]
        );
        assert_eq!(
            linetypes
                .iter()
                .filter(|record| record.is_current)
                .map(|record| record.name.as_str())
                .collect::<Vec<_>>(),
            ["ByLayer"]
        );
        assert!(linetypes.iter().all(|record| !record.handle.is_empty()));

        let text_styles = list_text_styles(&doc).unwrap();
        assert_eq!(text_styles.len(), 1);
        assert_eq!(text_styles[0].name, "Standard");
        assert!(text_styles[0].is_current);

        let dimension_styles = list_dimension_styles(&doc).unwrap();
        assert_eq!(dimension_styles.len(), 1);
        assert_eq!(dimension_styles[0].name, "Standard");
        assert!(dimension_styles[0].is_current);
        assert_eq!(dimension_styles[0].decimal_separator.as_deref(), Some("."));
    }

    #[test]
    fn linetype_get_supports_handle_name_and_pattern_semantics() {
        let mut doc = CadDocument::new();
        let mut dashed = LineType::new("CENTER");
        dashed.set_handle(Handle::new(0xA01));
        dashed.description = "Center line".to_string();
        dashed.add_element(LineTypeElement::dash(1.25));
        dashed.add_element(LineTypeElement::space(0.25));
        dashed.add_element(LineTypeElement::dot());
        dashed.pattern_length = 1.5;
        doc.line_types.add(dashed).unwrap();

        let by_name = get_linetype(&doc, &selector_name("center")).unwrap();
        assert_eq!(by_name.handle, "A01");
        assert_eq!(
            by_name
                .elements
                .iter()
                .map(|element| element.kind)
                .collect::<Vec<_>>(),
            [
                LinetypeElementKind::Dash,
                LinetypeElementKind::Space,
                LinetypeElementKind::Dot
            ]
        );

        let by_handle = get_linetype(
            &doc,
            &SymbolSelector {
                handle: Some("0xa01".to_string()),
                name: Some("CENTER".to_string()),
            },
        )
        .unwrap();
        assert_eq!(by_handle, by_name);
    }

    #[test]
    fn symbol_lists_use_numeric_handle_order_not_name_order() {
        let mut doc = CadDocument::new();
        let mut lower_handle = LineType::new("Z_LOWER_HANDLE");
        lower_handle.set_handle(Handle::new(0x100));
        doc.line_types.add(lower_handle).unwrap();
        let mut higher_handle = LineType::new("A_HIGHER_HANDLE");
        higher_handle.set_handle(Handle::new(0x1000));
        doc.line_types.add(higher_handle).unwrap();

        let names = list_linetypes(&doc)
            .unwrap()
            .into_iter()
            .filter(|record| matches!(record.name.as_str(), "Z_LOWER_HANDLE" | "A_HIGHER_HANDLE"))
            .map(|record| record.name)
            .collect::<Vec<_>>();
        assert_eq!(names, ["Z_LOWER_HANDLE", "A_HIGHER_HANDLE"]);
    }

    #[test]
    fn text_and_dimension_style_records_expose_model_backed_properties() {
        let mut doc = CadDocument::new();

        let mut text = TextStyle::with_truetype("NOTES", "Arial");
        text.set_handle(Handle::new(0xA02));
        text.height = 2.5;
        text.width_factor = 0.8;
        text.annotative = true;
        text.set_backward(true);
        doc.text_styles.add(text).unwrap();

        let notes = get_text_style(&doc, &selector_name("notes")).unwrap();
        assert_eq!(notes.fixed_height, 2.5);
        assert_eq!(notes.true_type_font, "Arial");
        assert!(notes.annotative);
        assert!(notes.backward);

        let mut dimensions = DimStyle::new("ARCH");
        dimensions.set_handle(Handle::new(0xA03));
        dimensions.dimasz = 3.0;
        dimensions.dimtxt = 2.5;
        dimensions.dimtxsty_handle = Handle::new(0xA02);
        dimensions.dimtxsty = "NOTES".to_string();
        dimensions.dimlfac = 25.4;
        dimensions.dimdec = 3;
        dimensions.dimalt = true;
        dimensions.dimpost = "<> mm".to_string();
        doc.dim_styles.add(dimensions).unwrap();

        let arch = get_dimension_style(&doc, &selector_name("ARCH")).unwrap();
        assert_eq!(arch.arrow_size, 3.0);
        assert_eq!(arch.text_height, 2.5);
        assert_eq!(arch.text_style_handle.as_deref(), Some("A02"));
        assert_eq!(arch.linear_scale_factor, 25.4);
        assert_eq!(arch.linear_decimal_places, 3);
        assert!(arch.alternate_units_enabled);
        assert_eq!(arch.postfix, "<> mm");
    }

    #[test]
    fn symbol_selectors_report_missing_invalid_and_mismatched_identity() {
        let doc = CadDocument::new();
        assert_eq!(
            get_text_style(&doc, &SymbolSelector::default())
                .unwrap_err()
                .code(),
            "text_style_missing_identity"
        );
        assert_eq!(
            get_linetype(
                &doc,
                &SymbolSelector {
                    handle: Some("xyz".to_string()),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .code(),
            "linetype_invalid_handle"
        );

        let standard = get_text_style(&doc, &selector_name("Standard")).unwrap();
        assert_eq!(
            get_text_style(
                &doc,
                &SymbolSelector {
                    handle: Some(standard.handle),
                    name: Some("Other".to_string()),
                }
            )
            .unwrap_err()
            .code(),
            "text_style_identity_mismatch"
        );
        let whitespace = get_text_style(
            &doc,
            &SymbolSelector {
                name: Some(" Standard".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(whitespace.code(), "text_style_invalid_name");
        assert!(whitespace.message().contains("surrounding whitespace"));
    }

    #[test]
    fn name_lookup_rejects_a_handle_shared_by_distinct_symbols() {
        let mut doc = CadDocument::new();
        let continuous = doc
            .line_types
            .iter()
            .find(|linetype| linetype.name == "Continuous")
            .unwrap()
            .handle();
        let mut duplicate = LineType::new("DUPLICATE");
        duplicate.set_handle(continuous);
        doc.line_types.add(duplicate).unwrap();

        let error = get_linetype(&doc, &selector_name("Continuous")).unwrap_err();
        assert_eq!(error.code(), "linetype_ambiguous_handle");
        assert_eq!(list_linetypes(&doc).unwrap_err().code(), error.code());
    }

    #[test]
    fn invalid_table_entry_handles_fail_list_instead_of_emitting_unstable_identity() {
        let mut doc = CadDocument::new();
        let mut invalid = View::new("BROKEN");
        invalid.set_handle(Handle::NULL);
        doc.views.add(invalid).unwrap();

        let error = list_named_views(&doc).unwrap_err();
        assert_eq!(error.code(), "named_view_invalid_handle");
    }

    #[test]
    fn non_finite_symbol_values_fail_closed() {
        let mut doc = CadDocument::new();
        let mut invalid = LineType::new("BROKEN");
        invalid.set_handle(Handle::new(0xBAD));
        invalid.pattern_length = f64::NAN;
        doc.line_types.add(invalid).unwrap();

        let error = list_linetypes(&doc).unwrap_err();
        assert_eq!(error.code(), "linetype_unsupported_data");
        assert!(error.message().contains("pattern_length"));
        assert!(error.message().contains("not a finite number"));
    }

    #[test]
    fn named_views_and_ucs_are_handle_bearing_and_geometric() {
        let mut doc = CadDocument::new();

        let mut view = View::new("DETAIL");
        view.set_handle(Handle::new(0xB01));
        view.center = Vector3::new(2.0, 3.0, 0.0);
        view.target = Vector3::new(10.0, 20.0, 30.0);
        view.width = 12.0;
        view.height = 8.0;
        doc.views.add(view).unwrap();

        let detail = get_named_view(&doc, &selector_name("detail")).unwrap();
        assert_eq!(detail.handle, "B01");
        assert_eq!(detail.center.x, 2.0);
        assert_eq!(detail.target.z, 30.0);

        let mut ucs = Ucs::from_origin_axes(
            "SITE",
            Vector3::new(100.0, 200.0, 0.0),
            Vector3::UNIT_Y,
            Vector3::new(-1.0, 0.0, 0.0),
        );
        ucs.set_handle(Handle::new(0xB02));
        doc.ucss.add(ucs).unwrap();

        let site = get_named_ucs(&doc, &selector_name("site")).unwrap();
        assert_eq!(site.handle, "B02");
        assert_eq!(site.origin.x, 100.0);
        assert_eq!(site.z_axis.z, 1.0);
        assert_eq!(list_named_ucs(&doc).unwrap(), [site]);
    }

    #[test]
    fn output_contracts_round_trip_and_reject_unknown_fields() {
        let record = get_linetype(&CadDocument::new(), &selector_name("Continuous")).unwrap();
        let json = serde_json::to_string(&record).unwrap();
        let parsed: LinetypeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, record);

        let error =
            serde_json::from_str::<SymbolSelector>(r#"{"name":"Continuous","unexpected":true}"#)
                .unwrap_err();
        assert!(error.to_string().contains("unknown field `unexpected`"));
    }

    #[test]
    fn tier1_dwg_symbol_lists_and_gets_agree() {
        let fixture_root = "tests/corpus/open/acadsharp/dynamic-blocks";
        let session = Reader::open_path(&fixture_path(&format!(
            "{fixture_root}/BLOCKVISIBILITYPARAMETER.dwg"
        )))
        .unwrap();

        let linetypes = session.list_linetypes().unwrap();
        assert!(!linetypes.is_empty());
        for expected in &linetypes {
            assert_eq!(
                session
                    .get_linetype(&SymbolSelector {
                        handle: Some(expected.handle.clone()),
                        name: Some(expected.name.clone()),
                    })
                    .unwrap(),
                *expected
            );
        }

        let text_styles = session.list_text_styles().unwrap();
        assert!(!text_styles.is_empty());
        for expected in &text_styles {
            assert_eq!(
                session
                    .get_text_style(&SymbolSelector {
                        handle: Some(expected.handle.clone()),
                        name: Some(expected.name.clone()),
                    })
                    .unwrap(),
                *expected
            );
        }

        let dimension_styles = session.list_dimension_styles().unwrap();
        assert!(!dimension_styles.is_empty());
        for expected in &dimension_styles {
            assert_eq!(
                session
                    .get_dimension_style(&SymbolSelector {
                        handle: Some(expected.handle.clone()),
                        name: Some(expected.name.clone()),
                    })
                    .unwrap(),
                *expected
            );
        }

        for expected in session.list_named_views().unwrap() {
            assert_eq!(
                session
                    .get_named_view(&SymbolSelector {
                        handle: Some(expected.handle.clone()),
                        name: Some(expected.name.clone()),
                    })
                    .unwrap(),
                expected
            );
        }

        for expected in session.list_named_ucs().unwrap() {
            assert_eq!(
                session
                    .get_named_ucs(&SymbolSelector {
                        handle: Some(expected.handle.clone()),
                        name: Some(expected.name.clone()),
                    })
                    .unwrap(),
                expected
            );
        }
    }
}
