//! Reader-owned TEXT and MTEXT traversal and projection.

use acadrust::entities::{
    AttachmentPoint as AcadAttachmentPoint, DrawingDirection as AcadDrawingDirection, EntityType,
    MText, Text, TextHorizontalAlignment as AcadHorizontalAlignment,
    TextVerticalAlignment as AcadVerticalAlignment,
};
use acadrust::types::{Handle, Vector3};
use acadrust::CadDocument;
use serde::Serialize;

use super::{
    contract::{
        DirectOwnerContext, DirectOwnerType, MTextAttachmentPoint, MTextDrawingDirection,
        TextEntityKind, TextHorizontalAlignment, TextItem, TextListOptions, TextPoint3, TextRecord,
        TextSelector, TextVerticalAlignment,
    },
    entity_identity::{is_semantic_entity, validate_semantic_entity_handles},
    owners::{owner_name_eq, resolve_direct_owner},
};

/// The original text dump, preserved as a compatibility alias.
pub(super) fn dump_text(doc: &CadDocument) -> Vec<TextItem> {
    doc.entities()
        .filter_map(|e| match e {
            EntityType::Text(t) => Some(TextItem {
                text_type: "TEXT".to_string(),
                value: t.value.clone(),
                layer: t.common.layer.clone(),
                x: t.insertion_point.x,
                y: t.insertion_point.y,
            }),
            EntityType::MText(t) => Some(TextItem {
                text_type: "MTEXT".to_string(),
                value: t.value.clone(),
                layer: t.common.layer.clone(),
                x: t.insertion_point.x,
                y: t.insertion_point.y,
            }),
            _ => None,
        })
        .collect()
}

impl From<Vector3> for TextPoint3 {
    fn from(value: Vector3) -> Self {
        Self {
            x: value.x,
            y: value.y,
            z: value.z,
        }
    }
}

fn finite_number(value: f64, field: &str) -> Result<f64, TextReadError> {
    value.is_finite().then_some(value).ok_or_else(|| {
        TextReadError::new(
            "unsupported_text_data",
            format!("{field} is not a finite number"),
        )
    })
}

fn finite_point(value: Vector3, field: &str) -> Result<TextPoint3, TextReadError> {
    Ok(TextPoint3 {
        x: finite_number(value.x, &format!("{field}.x"))?,
        y: finite_number(value.y, &format!("{field}.y"))?,
        z: finite_number(value.z, &format!("{field}.z"))?,
    })
}

fn finite_optional_number(value: Option<f64>, field: &str) -> Result<Option<f64>, TextReadError> {
    value.map(|value| finite_number(value, field)).transpose()
}

fn finite_optional_point(
    value: Option<Vector3>,
    field: &str,
) -> Result<Option<TextPoint3>, TextReadError> {
    value.map(|value| finite_point(value, field)).transpose()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TextReadError {
    code: String,
    message: String,
}

impl TextReadError {
    pub(super) fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for TextReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "code={} {}", self.code, self.message)
    }
}

impl std::error::Error for TextReadError {}

fn canonical_handle(handle: Handle) -> Result<String, TextReadError> {
    if handle.is_null() {
        return Err(TextReadError::new(
            "invalid_handle",
            "text entity has null handle 0",
        ));
    }
    Ok(format!("{:X}", handle.value()))
}

fn canonical_optional_handle(handle: Handle) -> Option<String> {
    handle.is_valid().then(|| format!("{:X}", handle.value()))
}

fn parse_hex_handle(input: &str, resource: &str) -> Result<Handle, TextReadError> {
    if input.trim() != input {
        return Err(TextReadError::new(
            "invalid_handle",
            format!("invalid {resource} handle `{input}`"),
        ));
    }
    let digits = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(TextReadError::new(
            "invalid_handle",
            format!("invalid {resource} handle `{input}`"),
        ));
    }
    let value = u64::from_str_radix(digits, 16).map_err(|_| {
        TextReadError::new(
            "invalid_handle",
            format!("invalid {resource} handle `{input}`"),
        )
    })?;
    if value == 0 {
        return Err(TextReadError::new(
            "invalid_handle",
            format!("{resource} handle 0 is invalid"),
        ));
    }
    Ok(Handle::new(value))
}

fn parse_handle(input: &str) -> Result<Handle, TextReadError> {
    parse_hex_handle(input, "text")
}

struct TextFilters {
    text_types: Option<Vec<TextEntityKind>>,
    layer: Option<String>,
    owner_handle: Option<Handle>,
    owner_identity: Option<(DirectOwnerType, String)>,
}

impl TextFilters {
    fn is_scoped(&self) -> bool {
        self.text_types.is_some()
            || self.layer.is_some()
            || self.owner_handle.is_some()
            || self.owner_identity.is_some()
    }
}

fn validated_filters(
    doc: &CadDocument,
    options: &TextListOptions,
) -> Result<TextFilters, TextReadError> {
    let text_types = match &options.text_types {
        Some(text_types) if text_types.is_empty() => {
            return Err(TextReadError::new(
                "invalid_text_type_filter",
                "text_types cannot be empty when provided",
            ))
        }
        Some(text_types) => Some(text_types.clone()),
        None => None,
    };

    let layer = options
        .layer
        .as_deref()
        .map(|layer| {
            if layer.trim().is_empty() {
                Err(TextReadError::new(
                    "invalid_text_layer_filter",
                    "layer cannot be empty when provided",
                ))
            } else if layer.trim() != layer {
                Err(TextReadError::new(
                    "invalid_text_layer_filter",
                    "layer cannot contain surrounding whitespace",
                ))
            } else {
                Ok(layer.to_uppercase())
            }
        })
        .transpose()?;

    if !matches!(
        (
            options.owner_handle.is_some(),
            options.owner_type.is_some(),
            options.owner_name.is_some()
        ),
        (false, false, false) | (true, false, false) | (false, true, true) | (true, true, true)
    ) {
        return Err(TextReadError::new(
            "invalid_text_owner",
            "owner selection must use {}, {owner_handle}, {owner_type,owner_name}, or all three",
        ));
    }

    let owner_handle = options
        .owner_handle
        .as_deref()
        .map(|handle| parse_hex_handle(handle, "owner"))
        .transpose()?;
    let owner_identity = match (options.owner_type, options.owner_name.as_deref()) {
        (Some(owner_type), Some(owner_name)) => {
            if owner_name.trim().is_empty() {
                return Err(TextReadError::new(
                    "invalid_text_owner",
                    "owner_name cannot be empty when provided",
                ));
            }
            if owner_name.trim() != owner_name {
                return Err(TextReadError::new(
                    "invalid_text_owner",
                    "owner_name cannot contain surrounding whitespace",
                ));
            }
            Some((owner_type, owner_name.to_string()))
        }
        (None, None) => None,
        _ => unreachable!("owner selector shape was validated"),
    };

    if let (Some(owner_handle), Some((wanted_type, wanted_name))) =
        (owner_handle, owner_identity.as_ref())
    {
        let resolved = resolve_direct_owner(doc, owner_handle)
            .map_err(|error| TextReadError::new("unsupported_text_data", error.to_string()))?;
        let agrees = resolved
            .as_ref()
            .and_then(DirectOwnerContext::available_identity)
            .is_some_and(|(owner_type, owner_name)| {
                owner_type == *wanted_type && owner_name_eq(owner_name, wanted_name)
            });
        if !agrees {
            return Err(TextReadError::new(
                "contradictory_identity",
                "owner handle and semantic owner resolve differently",
            ));
        }
    }

    Ok(TextFilters {
        text_types,
        layer,
        owner_handle,
        owner_identity,
    })
}

fn entity_matches_scope(
    doc: &CadDocument,
    entity: &EntityType,
    filters: &TextFilters,
) -> Result<bool, TextReadError> {
    let text_type = match entity {
        EntityType::Text(_) => TextEntityKind::Text,
        EntityType::MText(_) => TextEntityKind::MText,
        _ => return Ok(false),
    };
    if filters
        .text_types
        .as_ref()
        .is_some_and(|types| !types.contains(&text_type))
    {
        return Ok(false);
    }

    let common = entity.common();
    if filters
        .layer
        .as_ref()
        .is_some_and(|layer| common.layer.to_uppercase() != *layer)
        || filters
            .owner_handle
            .is_some_and(|owner| common.owner_handle != owner)
    {
        return Ok(false);
    }

    let Some((wanted_type, wanted_name)) = filters.owner_identity.as_ref() else {
        return Ok(true);
    };
    let owner_context = resolve_direct_owner(doc, common.owner_handle)
        .map_err(|error| TextReadError::new("unsupported_text_data", error.to_string()))?;
    Ok(owner_context
        .as_ref()
        .and_then(DirectOwnerContext::available_identity)
        .is_some_and(|(owner_type, owner_name)| {
            owner_type == *wanted_type && owner_name_eq(owner_name, wanted_name)
        }))
}

fn selected_handle_collides(doc: &CadDocument, handle: Handle) -> bool {
    let entity_count = doc
        .entities()
        .filter(|entity| is_semantic_entity(entity) && entity.common().handle == handle)
        .count();
    let attribute_count = doc
        .entities()
        .filter_map(|entity| match entity {
            EntityType::Insert(insert) => Some(insert),
            _ => None,
        })
        .flat_map(|insert| &insert.attributes)
        .filter(|attribute| attribute.common.handle.is_valid())
        .filter(|attribute| attribute.common.handle == handle)
        .count();
    entity_count + attribute_count > 1
}

fn validate_selected_text_handles(
    doc: &CadDocument,
    entities: &[&EntityType],
) -> Result<(), TextReadError> {
    if entities
        .iter()
        .any(|entity| entity.common().handle.is_null())
    {
        return Err(TextReadError::new(
            "invalid_handle",
            "TEXT or MTEXT entity has null handle 0",
        ));
    }
    if let Some(handle) = entities
        .iter()
        .map(|entity| entity.common().handle)
        .find(|handle| selected_handle_collides(doc, *handle))
    {
        return Err(TextReadError::new(
            "duplicate_entity_handle",
            format!(
                "selected TEXT or MTEXT handle {:X} is shared by multiple public entities",
                handle.value()
            ),
        ));
    }
    Ok(())
}

fn horizontal_alignment(value: AcadHorizontalAlignment) -> TextHorizontalAlignment {
    match value {
        AcadHorizontalAlignment::Left => TextHorizontalAlignment::Left,
        AcadHorizontalAlignment::Center => TextHorizontalAlignment::Center,
        AcadHorizontalAlignment::Right => TextHorizontalAlignment::Right,
        AcadHorizontalAlignment::Aligned => TextHorizontalAlignment::Aligned,
        AcadHorizontalAlignment::Middle => TextHorizontalAlignment::Middle,
        AcadHorizontalAlignment::Fit => TextHorizontalAlignment::Fit,
    }
}

fn vertical_alignment(value: AcadVerticalAlignment) -> TextVerticalAlignment {
    match value {
        AcadVerticalAlignment::Baseline => TextVerticalAlignment::Baseline,
        AcadVerticalAlignment::Bottom => TextVerticalAlignment::Bottom,
        AcadVerticalAlignment::Middle => TextVerticalAlignment::Middle,
        AcadVerticalAlignment::Top => TextVerticalAlignment::Top,
    }
}

fn attachment_point(value: AcadAttachmentPoint) -> MTextAttachmentPoint {
    match value {
        AcadAttachmentPoint::TopLeft => MTextAttachmentPoint::TopLeft,
        AcadAttachmentPoint::TopCenter => MTextAttachmentPoint::TopCenter,
        AcadAttachmentPoint::TopRight => MTextAttachmentPoint::TopRight,
        AcadAttachmentPoint::MiddleLeft => MTextAttachmentPoint::MiddleLeft,
        AcadAttachmentPoint::MiddleCenter => MTextAttachmentPoint::MiddleCenter,
        AcadAttachmentPoint::MiddleRight => MTextAttachmentPoint::MiddleRight,
        AcadAttachmentPoint::BottomLeft => MTextAttachmentPoint::BottomLeft,
        AcadAttachmentPoint::BottomCenter => MTextAttachmentPoint::BottomCenter,
        AcadAttachmentPoint::BottomRight => MTextAttachmentPoint::BottomRight,
    }
}

fn drawing_direction(value: AcadDrawingDirection) -> MTextDrawingDirection {
    match value {
        AcadDrawingDirection::LeftToRight => MTextDrawingDirection::LeftToRight,
        AcadDrawingDirection::TopToBottom => MTextDrawingDirection::TopToBottom,
        AcadDrawingDirection::ByStyle => MTextDrawingDirection::ByStyle,
    }
}

fn text_record(doc: &CadDocument, text: &Text) -> Result<TextRecord, TextReadError> {
    let owner_context = resolve_direct_owner(doc, text.common.owner_handle)
        .map_err(|error| TextReadError::new("unsupported_text_data", error.to_string()))?;
    Ok(TextRecord {
        handle: canonical_handle(text.common.handle)?,
        text_type: TextEntityKind::Text,
        value: text.value.clone(),
        layer: text.common.layer.clone(),
        owner_handle: canonical_optional_handle(text.common.owner_handle),
        owner_context,
        insertion_point: finite_point(text.insertion_point, "TEXT insertion_point")?,
        height: finite_number(text.height, "TEXT height")?,
        rotation_radians: finite_number(text.rotation, "TEXT rotation_radians")?,
        style: text.style.clone(),
        normal: finite_point(text.normal, "TEXT normal")?,
        invisible: text.common.invisible,
        alignment_point: finite_optional_point(text.alignment_point, "TEXT alignment_point")?,
        width_factor: Some(finite_number(text.width_factor, "TEXT width_factor")?),
        oblique_angle_radians: Some(finite_number(
            text.oblique_angle,
            "TEXT oblique_angle_radians",
        )?),
        horizontal_alignment: Some(horizontal_alignment(text.horizontal_alignment)),
        vertical_alignment: Some(vertical_alignment(text.vertical_alignment)),
        rectangle_width: None,
        rectangle_height: None,
        attachment_point: None,
        drawing_direction: None,
        line_spacing_factor: None,
    })
}

fn mtext_record(doc: &CadDocument, text: &MText) -> Result<TextRecord, TextReadError> {
    let owner_context = resolve_direct_owner(doc, text.common.owner_handle)
        .map_err(|error| TextReadError::new("unsupported_text_data", error.to_string()))?;
    Ok(TextRecord {
        handle: canonical_handle(text.common.handle)?,
        text_type: TextEntityKind::MText,
        value: text.value.clone(),
        layer: text.common.layer.clone(),
        owner_handle: canonical_optional_handle(text.common.owner_handle),
        owner_context,
        insertion_point: finite_point(text.insertion_point, "MTEXT insertion_point")?,
        height: finite_number(text.height, "MTEXT height")?,
        rotation_radians: finite_number(text.rotation, "MTEXT rotation_radians")?,
        style: text.style.clone(),
        normal: finite_point(text.normal, "MTEXT normal")?,
        invisible: text.common.invisible,
        alignment_point: None,
        width_factor: None,
        oblique_angle_radians: None,
        horizontal_alignment: None,
        vertical_alignment: None,
        rectangle_width: Some(finite_number(
            text.rectangle_width,
            "MTEXT rectangle_width",
        )?),
        rectangle_height: finite_optional_number(text.rectangle_height, "MTEXT rectangle_height")?,
        attachment_point: Some(attachment_point(text.attachment_point)),
        drawing_direction: Some(drawing_direction(text.drawing_direction)),
        line_spacing_factor: Some(finite_number(
            text.line_spacing_factor,
            "MTEXT line_spacing_factor",
        )?),
    })
}

pub(super) fn list_text(
    doc: &CadDocument,
    options: &TextListOptions,
) -> Result<Vec<TextRecord>, TextReadError> {
    let filters = validated_filters(doc, options)?;
    if !filters.is_scoped() {
        validate_semantic_entity_handles(doc)
            .map_err(|error| TextReadError::new(error.code(), error.message()))?;
    }
    let mut text_entities = Vec::new();
    for entity in doc.entities() {
        if entity_matches_scope(doc, entity, &filters)? {
            text_entities.push(entity);
        }
    }
    text_entities.sort_by_key(|entity| entity.common().handle.value());
    if filters.is_scoped() {
        validate_selected_text_handles(doc, &text_entities)?;
    }
    text_entities
        .into_iter()
        .map(|entity| match entity {
            EntityType::Text(text) => text_record(doc, text),
            EntityType::MText(text) => mtext_record(doc, text),
            _ => unreachable!("filtered to TEXT and MTEXT"),
        })
        .collect()
}

pub(super) fn get_text(
    doc: &CadDocument,
    selector: &TextSelector,
) -> Result<TextRecord, TextReadError> {
    let wanted = parse_handle(&selector.handle)?;
    let matches = doc
        .entities()
        .filter(|entity| {
            entity.common().handle == wanted
                && matches!(entity, EntityType::Text(_) | EntityType::MText(_))
        })
        .collect::<Vec<_>>();
    let entity = match matches.as_slice() {
        [] => {
            return Err(TextReadError::new(
                "text_not_found",
                format!("TEXT or MTEXT entity {:X} was not found", wanted.value()),
            ))
        }
        [entity] => *entity,
        _ => {
            return Err(TextReadError::new(
                "unsupported_text_data",
                format!("multiple text entities share handle {:X}", wanted.value()),
            ))
        }
    };
    validate_selected_text_handles(doc, &[entity])?;
    match entity {
        EntityType::Text(text) => text_record(doc, text),
        EntityType::MText(text) => mtext_record(doc, text),
        _ => unreachable!("resolved only TEXT or MTEXT"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Reader;
    use acadrust::entities::{AttributeEntity, EntityType, Insert, Line, MText, Text};
    use acadrust::types::Vector3;
    use acadrust::CadDocument;
    use std::path::{Path, PathBuf};

    fn fixture_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    #[test]
    fn empty_doc_returns_empty() {
        let doc = CadDocument::new();
        assert_eq!(dump_text(&doc).len(), 0);
    }

    #[test]
    fn text_entity_extracted() {
        let mut doc = CadDocument::new();
        let t = Text::with_value("NORTH", Vector3::new(10.0, 20.0, 0.0));
        doc.add_entity(EntityType::Text(t)).unwrap();

        let items = dump_text(&doc);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].text_type, "TEXT");
        assert_eq!(items[0].value, "NORTH");
        assert!((items[0].x - 10.0).abs() < 1e-9);
        assert!((items[0].y - 20.0).abs() < 1e-9);
    }

    #[test]
    fn mtext_entity_extracted() {
        let mut doc = CadDocument::new();
        let mt = MText::with_value("Sheet Notes", Vector3::new(5.0, 15.0, 0.0));
        doc.add_entity(EntityType::MText(mt)).unwrap();

        let items = dump_text(&doc);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].text_type, "MTEXT");
        assert_eq!(items[0].value, "Sheet Notes");
    }

    #[test]
    fn mixed_entities_only_text_returned() {
        let mut doc = CadDocument::new();
        let t = Text::with_value("A", Vector3::new(0.0, 0.0, 0.0));
        let line = Line::from_coords(0.0, 0.0, 0.0, 1.0, 0.0, 0.0);
        let ins = Insert::new("BLOCK", Vector3::new(0.0, 0.0, 0.0));
        doc.add_entity(EntityType::Text(t)).unwrap();
        doc.add_entity(EntityType::Line(line)).unwrap();
        doc.add_entity(EntityType::Insert(ins)).unwrap();

        assert_eq!(dump_text(&doc).len(), 1);
    }

    #[test]
    fn rich_list_is_numeric_handle_sorted_and_exposes_text_fields() {
        let mut doc = CadDocument::new();
        let mut later = Text::with_value("Later", Vector3::new(1.0, 2.0, 3.0));
        later.common.handle = Handle::new(0x100);
        later.common.layer = "NOTES".to_string();
        later.common.invisible = true;
        later.height = 2.5;
        later.rotation = 0.25;
        later.width_factor = 0.8;
        later.oblique_angle = 0.1;
        later.style = "ROMANS".to_string();
        later.alignment_point = Some(Vector3::new(4.0, 5.0, 6.0));
        later.horizontal_alignment = AcadHorizontalAlignment::Center;
        later.vertical_alignment = AcadVerticalAlignment::Top;
        doc.add_entity(EntityType::Text(later)).unwrap();

        let mut earlier = Text::with_value("Earlier", Vector3::new(7.0, 8.0, 9.0));
        earlier.common.handle = Handle::new(0xF);
        doc.add_entity(EntityType::Text(earlier)).unwrap();

        let records = list_text(&doc, &TextListOptions::default()).unwrap();
        assert_eq!(
            records
                .iter()
                .map(|record| record.handle.as_str())
                .collect::<Vec<_>>(),
            ["F", "100"]
        );
        let record = &records[1];
        assert_eq!(record.text_type, TextEntityKind::Text);
        assert_eq!(record.layer, "NOTES");
        assert_eq!(
            record.insertion_point,
            TextPoint3 {
                x: 1.0,
                y: 2.0,
                z: 3.0
            }
        );
        assert_eq!(record.height, 2.5);
        assert_eq!(record.rotation_radians, 0.25);
        assert_eq!(record.width_factor, Some(0.8));
        assert_eq!(record.oblique_angle_radians, Some(0.1));
        assert_eq!(record.style, "ROMANS");
        assert_eq!(
            record.horizontal_alignment,
            Some(TextHorizontalAlignment::Center)
        );
        assert_eq!(record.vertical_alignment, Some(TextVerticalAlignment::Top));
        assert_eq!(
            record.alignment_point,
            Some(TextPoint3 {
                x: 4.0,
                y: 5.0,
                z: 6.0
            })
        );
        assert!(record.invisible);
        assert_eq!(
            record.owner_context,
            Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::ModelSpace,
                owner_name: "Model".to_string(),
            })
        );
    }

    #[test]
    fn rich_mtext_record_exposes_variant_specific_fields_and_raw_value() {
        let mut doc = CadDocument::new();
        let mut text = MText::with_value(r#"{\C1;Red}\PSecond line"#, Vector3::new(5.0, 6.0, 7.0));
        text.common.handle = Handle::new(0x2A);
        text.height = 3.0;
        text.rectangle_width = 40.0;
        text.rectangle_height = Some(12.0);
        text.rotation = 1.25;
        text.style = "ANNOTATIVE".to_string();
        text.attachment_point = AcadAttachmentPoint::BottomRight;
        text.drawing_direction = AcadDrawingDirection::TopToBottom;
        text.line_spacing_factor = 1.4;
        doc.add_entity(EntityType::MText(text)).unwrap();

        let record = get_text(
            &doc,
            &TextSelector {
                handle: "0x002a".to_string(),
            },
        )
        .unwrap();
        assert_eq!(record.handle, "2A");
        assert_eq!(record.text_type, TextEntityKind::MText);
        assert_eq!(record.value, r#"{\C1;Red}\PSecond line"#);
        assert_eq!(record.insertion_point.z, 7.0);
        assert_eq!(record.rectangle_width, Some(40.0));
        assert_eq!(record.rectangle_height, Some(12.0));
        assert_eq!(record.rotation_radians, 1.25);
        assert_eq!(record.style, "ANNOTATIVE");
        assert_eq!(
            record.attachment_point,
            Some(MTextAttachmentPoint::BottomRight)
        );
        assert_eq!(
            record.drawing_direction,
            Some(MTextDrawingDirection::TopToBottom)
        );
        assert_eq!(record.line_spacing_factor, Some(1.4));
        assert_eq!(record.width_factor, None);
        assert_eq!(record.horizontal_alignment, None);
    }

    #[test]
    fn rich_list_supports_exact_type_layer_and_owner_filters() {
        let mut doc = CadDocument::new();

        let mut notes = Text::with_value("Notes", Vector3::ZERO);
        notes.common.handle = Handle::new(0x20);
        notes.common.layer = "ANNO".to_string();
        doc.add_entity(EntityType::Text(notes)).unwrap();

        let mut mtext = MText::with_value("Detail", Vector3::ZERO);
        mtext.common.handle = Handle::new(0x21);
        mtext.common.layer = "DETAIL".to_string();
        doc.add_entity(EntityType::MText(mtext)).unwrap();

        let insert_handle = doc
            .add_entity(EntityType::Insert(Insert::new("OWNER", Vector3::ZERO)))
            .unwrap();
        let child_handle = doc
            .add_entity(EntityType::Text(Text::with_value("Child", Vector3::ZERO)))
            .unwrap();
        doc.get_entity_mut(child_handle)
            .unwrap()
            .common_mut()
            .owner_handle = insert_handle;

        let records = list_text(
            &doc,
            &TextListOptions {
                text_types: Some(vec![TextEntityKind::MText]),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].handle, "21");

        let records = list_text(
            &doc,
            &TextListOptions {
                layer: Some("anno".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].handle, "20");

        let model_handle = format!("{:X}", doc.header.model_space_block_handle.value());
        let records = list_text(
            &doc,
            &TextListOptions {
                owner_handle: Some(model_handle.clone()),
                owner_type: Some(DirectOwnerType::ModelSpace),
                owner_name: Some("model".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            records
                .iter()
                .map(|record| record.handle.as_str())
                .collect::<Vec<_>>(),
            ["20", "21"]
        );

        let records = list_text(
            &doc,
            &TextListOptions {
                owner_type: Some(DirectOwnerType::Entity),
                owner_name: Some("insert".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].handle, format!("{:X}", child_handle.value()));

        let error = list_text(
            &doc,
            &TextListOptions {
                owner_handle: Some(model_handle),
                owner_type: Some(DirectOwnerType::PaperSpace),
                owner_name: Some("Layout1".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "contradictory_identity");
    }

    #[test]
    fn scoped_lists_do_not_validate_excluded_malformed_text() {
        let mut type_doc = CadDocument::new();
        let mut selected = Text::with_value("Selected TEXT", Vector3::ZERO);
        selected.common.handle = Handle::new(0xA0);
        type_doc.add_entity(EntityType::Text(selected)).unwrap();
        let mut excluded = MText::with_value("Malformed MTEXT", Vector3::ZERO);
        excluded.common.handle = Handle::new(0xA1);
        excluded.rectangle_width = f64::NAN;
        type_doc.add_entity(EntityType::MText(excluded)).unwrap();

        let records = list_text(
            &type_doc,
            &TextListOptions {
                text_types: Some(vec![TextEntityKind::Text]),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].handle, "A0");

        let mut layer_doc = CadDocument::new();
        let mut selected = Text::with_value("Selected layer", Vector3::ZERO);
        selected.common.handle = Handle::new(0xB0);
        selected.common.layer = "KEEP".to_string();
        layer_doc.add_entity(EntityType::Text(selected)).unwrap();
        let mut excluded = Text::with_value("Malformed excluded layer", Vector3::ZERO);
        excluded.common.handle = Handle::new(0xB1);
        excluded.common.layer = "DROP".to_string();
        excluded.height = f64::NAN;
        let excluded_handle = layer_doc.add_entity(EntityType::Text(excluded)).unwrap();
        layer_doc
            .get_entity_mut(excluded_handle)
            .unwrap()
            .common_mut()
            .handle = Handle::NULL;
        for value in ["First duplicate", "Second duplicate"] {
            let mut duplicate = Text::with_value(value, Vector3::ZERO);
            duplicate.common.handle = Handle::new(0xBF);
            duplicate.common.layer = "DROP".to_string();
            layer_doc.add_entity(EntityType::Text(duplicate)).unwrap();
        }

        let records = list_text(
            &layer_doc,
            &TextListOptions {
                layer: Some("keep".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].handle, "B0");

        let mut owner_doc = CadDocument::new();
        let model_handle = owner_doc.header.model_space_block_handle;
        let mut selected = Text::with_value("Selected owner", Vector3::ZERO);
        selected.common.handle = Handle::new(0xC0);
        owner_doc.add_entity(EntityType::Text(selected)).unwrap();
        let mut insert = Insert::new("OTHER_OWNER", Vector3::ZERO);
        insert.common.handle = Handle::new(0xC8);
        let insert_handle = owner_doc.add_entity(EntityType::Insert(insert)).unwrap();
        let mut excluded = Text::with_value("Malformed other owner", Vector3::ZERO);
        excluded.common.handle = Handle::new(0xC1);
        excluded.height = f64::NAN;
        let excluded_handle = owner_doc.add_entity(EntityType::Text(excluded)).unwrap();
        owner_doc
            .get_entity_mut(excluded_handle)
            .unwrap()
            .common_mut()
            .owner_handle = insert_handle;

        for options in [
            TextListOptions {
                owner_handle: Some(format!("{:X}", model_handle.value())),
                ..Default::default()
            },
            TextListOptions {
                owner_type: Some(DirectOwnerType::ModelSpace),
                owner_name: Some("Model".to_string()),
                ..Default::default()
            },
        ] {
            let records = list_text(&owner_doc, &options).unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].handle, "C0");
        }
    }

    #[test]
    fn targeted_text_ignores_unrelated_invalid_and_duplicate_handles() {
        let mut doc = CadDocument::new();
        let mut selected = Text::with_value("Selected", Vector3::ZERO);
        selected.common.handle = Handle::new(0xD0);
        doc.add_entity(EntityType::Text(selected)).unwrap();

        let mut null = Text::with_value("Null identity", Vector3::ZERO);
        null.common.handle = Handle::new(0xD1);
        null.height = f64::NAN;
        let null_handle = doc.add_entity(EntityType::Text(null)).unwrap();
        doc.get_entity_mut(null_handle).unwrap().common_mut().handle = Handle::NULL;

        for value in ["First duplicate", "Second duplicate"] {
            let mut duplicate = MText::with_value(value, Vector3::ZERO);
            duplicate.common.handle = Handle::new(0xDF);
            duplicate.rectangle_width = f64::NAN;
            doc.add_entity(EntityType::MText(duplicate)).unwrap();
        }

        let record = get_text(
            &doc,
            &TextSelector {
                handle: "D0".to_string(),
            },
        )
        .unwrap();
        assert_eq!(record.handle, "D0");
        assert_eq!(record.value, "Selected");
    }

    #[test]
    fn rich_list_rejects_partial_owner_and_empty_collection_filters() {
        let doc = CadDocument::new();
        let partial_owner = list_text(
            &doc,
            &TextListOptions {
                owner_type: Some(DirectOwnerType::ModelSpace),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(partial_owner.code(), "invalid_text_owner");

        let empty_types = list_text(
            &doc,
            &TextListOptions {
                text_types: Some(Vec::new()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(empty_types.code(), "invalid_text_type_filter");

        for options in [
            TextListOptions {
                layer: Some(" ANNO".to_string()),
                ..Default::default()
            },
            TextListOptions {
                owner_type: Some(DirectOwnerType::ModelSpace),
                owner_name: Some("Model ".to_string()),
                ..Default::default()
            },
        ] {
            let error = list_text(&doc, &options).unwrap_err();
            assert!(
                matches!(
                    error.code(),
                    "invalid_text_layer_filter" | "invalid_text_owner"
                ),
                "unexpected code {}",
                error.code()
            );
            assert!(error.message().contains("surrounding whitespace"));
        }
    }

    #[test]
    fn targeted_text_errors_are_explicit() {
        let mut doc = CadDocument::new();
        let mut line = Line::from_coords(0.0, 0.0, 0.0, 1.0, 1.0, 0.0);
        line.common.handle = Handle::new(0x30);
        doc.add_entity(EntityType::Line(line)).unwrap();

        for (input, code) in [
            ("", "invalid_handle"),
            (" 30", "invalid_handle"),
            ("GG", "invalid_handle"),
            ("0", "invalid_handle"),
            ("30", "text_not_found"),
            ("31", "text_not_found"),
        ] {
            let error = get_text(
                &doc,
                &TextSelector {
                    handle: input.to_string(),
                },
            )
            .unwrap_err();
            assert_eq!(error.code(), code, "input={input}");
        }
    }

    #[test]
    fn rich_list_fails_closed_on_null_text_identity() {
        let mut doc = CadDocument::new();
        doc.add_entity(EntityType::Text(Text::with_value(
            "No identity",
            Vector3::ZERO,
        )))
        .unwrap();
        let entity = doc
            .entities_mut()
            .find(|entity| matches!(entity, EntityType::Text(_)))
            .unwrap();
        entity.common_mut().handle = Handle::NULL;

        let error = list_text(&doc, &TextListOptions::default()).unwrap_err();
        assert_eq!(error.code(), "invalid_entity_handle");
        assert!(error.message().contains("handle 0"));
    }

    #[test]
    fn cross_type_handle_collisions_cannot_hide_behind_text_filtering() {
        let mut doc = CadDocument::new();
        let mut text = Text::with_value("Collision", Vector3::ZERO);
        text.common.handle = Handle::new(0x80);
        doc.add_entity(EntityType::Text(text)).unwrap();
        let mut line = Line::new();
        line.common.handle = Handle::new(0x80);
        doc.add_entity(EntityType::Line(line)).unwrap();

        assert_eq!(
            list_text(&doc, &TextListOptions::default())
                .unwrap_err()
                .code(),
            "duplicate_entity_handle"
        );
        assert_eq!(
            get_text(
                &doc,
                &TextSelector {
                    handle: "80".to_string(),
                },
            )
            .unwrap_err()
            .code(),
            "duplicate_entity_handle"
        );
    }

    #[test]
    fn attached_attribute_handles_participate_in_text_identity_validation() {
        let mut doc = CadDocument::new();
        let mut insert = Insert::new("MARKER", Vector3::ZERO);
        insert.common.handle = Handle::new(0x100);
        let mut attribute = AttributeEntity::simple("TAG", "VALUE");
        attribute.common.handle = Handle::new(0x200);
        insert.attributes.push(attribute);
        doc.add_entity(EntityType::Insert(insert)).unwrap();

        let mut text = Text::with_value("Collision", Vector3::ZERO);
        text.common.handle = Handle::new(0x200);
        doc.add_entity(EntityType::Text(text)).unwrap();

        assert_eq!(
            list_text(&doc, &TextListOptions::default())
                .unwrap_err()
                .code(),
            "duplicate_entity_handle"
        );
        assert_eq!(
            get_text(
                &doc,
                &TextSelector {
                    handle: "200".to_string(),
                },
            )
            .unwrap_err()
            .code(),
            "duplicate_entity_handle"
        );
    }

    #[test]
    fn non_finite_rich_text_values_fail_closed() {
        let mut doc = CadDocument::new();
        let mut text = Text::with_value("Invalid height", Vector3::ZERO);
        text.common.handle = Handle::new(0x70);
        text.height = f64::NAN;
        doc.add_entity(EntityType::Text(text)).unwrap();

        let error = list_text(&doc, &TextListOptions::default()).unwrap_err();
        assert_eq!(error.code(), "unsupported_text_data");
        assert!(error.message().contains("TEXT height"));
        assert!(error.message().contains("not a finite number"));
    }

    #[test]
    fn tier1_dwg_supports_rich_text_reads() {
        let fixture_root = "tests/corpus/open/acadsharp/dynamic-blocks";
        let dwg = Reader::open_path(&fixture_path(&format!(
            "{fixture_root}/BLOCKVISIBILITYPARAMETER.dwg"
        )))
        .unwrap()
        .into_backend_document();

        let dwg_records = list_text(&dwg, &TextListOptions::default()).unwrap();
        serde_json::to_string(&dwg_records).unwrap();
        for expected in &dwg_records {
            assert_eq!(
                get_text(
                    &dwg,
                    &TextSelector {
                        handle: expected.handle.clone(),
                    },
                )
                .unwrap(),
                *expected
            );
        }
    }

    #[test]
    fn rich_output_contract_rejects_unknown_selector_fields() {
        let error = serde_json::from_str::<TextSelector>(r#"{"handle":"2A","unexpected":true}"#)
            .unwrap_err();
        assert!(error.to_string().contains("unknown field `unexpected`"));
    }
}
