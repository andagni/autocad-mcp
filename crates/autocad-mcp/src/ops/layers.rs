use acadrust::tables::TableEntry;
use acadrust::types::{Handle, LineWeight};
use acadrust::CadDocument;
use serde::{Deserialize, Serialize};

pub use crate::autocad_reader::contract::{LayerLineWeight, LayerRecord, LayerSelector};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LayerMutationProjectionFormat {
    Dxf,
    Dwg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LayerMutationProjectionContext {
    pub(crate) format: LayerMutationProjectionFormat,
}

impl LayerMutationProjectionContext {
    pub(crate) const DXF: Self = Self {
        format: LayerMutationProjectionFormat::Dxf,
    };

    pub(crate) const DWG: Self = Self {
        format: LayerMutationProjectionFormat::Dwg,
    };
}

impl Default for LayerMutationProjectionContext {
    fn default() -> Self {
        Self::DWG
    }
}

/// Mutation-only projection facts that the pinned document model does not
/// retain after native DXF preparation.
///
/// Public reads have an independent snapshot-derived projection beneath
/// `autocad_reader`; this compatibility state exists only so mutation results
/// and readback retain their established representation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LayerMutationProjectionMetadata {
    non_indexed_color_layers: Vec<LayerMutationProjectionIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LayerMutationProjectionIdentity {
    handle: Option<Handle>,
    name_key: String,
}

impl LayerMutationProjectionMetadata {
    /// Mark a layer whose persisted color is true-color or color-book data,
    /// rather than the fallback ACI value exposed by the document model.
    pub(crate) fn mark_non_indexed_color(&mut self, handle: Option<Handle>, name: &str) {
        let identity = LayerMutationProjectionIdentity {
            handle: handle.filter(Handle::is_valid),
            name_key: layer_name_key(name),
        };
        if !self.non_indexed_color_layers.contains(&identity) {
            self.non_indexed_color_layers.push(identity);
        }
    }

    fn has_non_indexed_color(&self, layer: &acadrust::tables::Layer) -> bool {
        self.non_indexed_color_layers
            .iter()
            .any(|identity| match identity.handle {
                Some(handle) => layer.handle() == handle,
                None => identity.name_key == layer_name_key(layer.name()),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletedLayer {
    pub handle: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerMutationResult {
    pub status: String,
    pub drawing: String,
    pub layer: LayerRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteLayerResult {
    pub status: String,
    pub drawing: String,
    pub layer: DeletedLayer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LayerError {
    code: String,
    message: String,
}

impl LayerError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn code(&self) -> &str {
        &self.code
    }
}

impl std::fmt::Display for LayerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "code={} {}", self.code, self.message)
    }
}

impl std::error::Error for LayerError {}

pub fn canonical_handle(handle: Handle) -> Result<String, LayerError> {
    if handle.is_null() {
        return Err(LayerError::new(
            "invalid_layer_handle",
            "layer handle 0 is invalid",
        ));
    }
    Ok(format!("{:X}", handle.value()))
}

fn canonical_optional_handle(handle: Handle) -> Result<Option<String>, LayerError> {
    if handle.is_null() {
        Ok(None)
    } else {
        canonical_handle(handle).map(Some)
    }
}

pub fn parse_handle(input: &str) -> Result<Handle, LayerError> {
    let trimmed = input.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if without_prefix.is_empty() {
        return Err(LayerError::new(
            "invalid_layer_handle",
            "empty layer handle",
        ));
    }

    let value = u64::from_str_radix(without_prefix, 16).map_err(|_| {
        LayerError::new(
            "invalid_layer_handle",
            format!("invalid layer handle `{input}`"),
        )
    })?;
    let handle = Handle::new(value);
    if handle.is_null() {
        return Err(LayerError::new(
            "invalid_layer_handle",
            "layer handle 0 is invalid",
        ));
    }
    Ok(handle)
}

fn layer_name_key(name: &str) -> String {
    name.to_uppercase()
}

fn name_eq(left: &str, right: &str) -> bool {
    layer_name_key(left) == layer_name_key(right)
}

fn resolved_current_layer_handle(doc: &CadDocument) -> Option<Handle> {
    let header_handle = doc.header.current_layer_handle;
    if !header_handle.is_null()
        && doc
            .layers
            .iter()
            .any(|layer| layer.handle() == header_handle)
    {
        return Some(header_handle);
    }
    doc.layers
        .iter()
        .find(|layer| name_eq(layer.name(), &doc.header.current_layer_name))
        .map(|layer| layer.handle())
}

fn is_current_layer(doc: &CadDocument, layer: &acadrust::tables::Layer) -> bool {
    resolved_current_layer_handle(doc)
        .map(|current| layer.handle() == current)
        .unwrap_or(false)
}

fn is_xref_dependent_layer(layer: &acadrust::tables::Layer) -> bool {
    layer.flags.xref_dependent || layer.name.contains('|')
}

fn color_index(layer: &acadrust::tables::Layer) -> Option<u16> {
    match layer.color.index() {
        Some(index @ 1..=255) => Some(index),
        _ => None,
    }
}

const STANDARD_LINE_WEIGHTS: &[i16] = &[
    0, 5, 9, 13, 15, 18, 20, 25, 30, 35, 40, 50, 53, 60, 70, 80, 90, 100, 106, 120, 140, 158, 200,
    211,
];

fn is_standard_line_weight(value: i16) -> bool {
    STANDARD_LINE_WEIGHTS.contains(&value)
}

fn layer_line_weight(line_weight: LineWeight) -> LayerLineWeight {
    match line_weight {
        LineWeight::ByLayer => LayerLineWeight::ByLayer,
        LineWeight::ByBlock => LayerLineWeight::ByBlock,
        LineWeight::Default => LayerLineWeight::Default,
        LineWeight::Value(value) if is_standard_line_weight(value) => LayerLineWeight::Value {
            hundredths_mm: value,
        },
        LineWeight::Value(value) => LayerLineWeight::Raw { raw_value: value },
    }
}

fn layer_xref_name(layer: &acadrust::tables::Layer) -> Option<String> {
    if !is_xref_dependent_layer(layer) {
        return None;
    }
    layer
        .name
        .split_once('|')
        .and_then(|(xref_name, _)| (!xref_name.is_empty()).then(|| xref_name.to_string()))
}

fn is_xref_definition(record: &acadrust::tables::BlockRecord) -> bool {
    record.flags.is_xref || record.flags.is_xref_overlay || !record.xref_path.is_empty()
}

fn xref_block_record_by_handle(
    doc: &CadDocument,
    handle: Handle,
) -> Option<&acadrust::tables::BlockRecord> {
    if handle.is_null() {
        return None;
    }
    doc.block_records
        .iter()
        .find(|record| record.handle() == handle && is_xref_definition(record))
}

fn xref_block_record_by_unique_name<'a>(
    doc: &'a CadDocument,
    xref_name: Option<&str>,
) -> Option<&'a acadrust::tables::BlockRecord> {
    let xref_name = xref_name?;
    let mut matches = doc
        .block_records
        .iter()
        .filter(|record| is_xref_definition(record) && name_eq(record.name(), xref_name));
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

type LayerMutationXrefContext = (Option<String>, Option<String>, Option<String>, Option<bool>);

fn mutation_xref_context(
    doc: &CadDocument,
    layer: &acadrust::tables::Layer,
    context: LayerMutationProjectionContext,
) -> Result<LayerMutationXrefContext, LayerError> {
    let xref_name = layer_xref_name(layer);
    let handle_match = match context.format {
        LayerMutationProjectionFormat::Dwg => {
            xref_block_record_by_handle(doc, layer.xref_block_record_handle)
        }
        LayerMutationProjectionFormat::Dxf => None,
    };
    let record =
        handle_match.or_else(|| xref_block_record_by_unique_name(doc, xref_name.as_deref()));
    let xref_block_record_handle = match context.format {
        LayerMutationProjectionFormat::Dwg => {
            canonical_optional_handle(layer.xref_block_record_handle)?
        }
        LayerMutationProjectionFormat::Dxf => None,
    };
    let xref_path =
        record.and_then(|record| (!record.xref_path.is_empty()).then(|| record.xref_path.clone()));
    let xref_is_overlay = match context.format {
        LayerMutationProjectionFormat::Dwg => record.map(|record| record.flags.is_xref_overlay),
        LayerMutationProjectionFormat::Dxf => None,
    };
    Ok((
        xref_block_record_handle,
        xref_name,
        xref_path,
        xref_is_overlay,
    ))
}

fn project_layer_record_for_mutation(
    doc: &CadDocument,
    layer: &acadrust::tables::Layer,
    context: LayerMutationProjectionContext,
    metadata: &LayerMutationProjectionMetadata,
) -> Result<LayerRecord, LayerError> {
    let (xref_block_record_handle, xref_name, xref_path, xref_is_overlay) =
        mutation_xref_context(doc, layer, context)?;
    let (material_handle, plotstyle_handle) = match context.format {
        LayerMutationProjectionFormat::Dwg => (
            canonical_optional_handle(layer.material)?,
            canonical_optional_handle(layer.plotstyle_handle)?,
        ),
        LayerMutationProjectionFormat::Dxf => (None, None),
    };
    Ok(LayerRecord {
        handle: canonical_handle(layer.handle())?,
        name: layer.name.clone(),
        color_index: if metadata.has_non_indexed_color(layer) {
            None
        } else {
            color_index(layer)
        },
        line_type: layer.line_type.clone(),
        line_weight: layer_line_weight(layer.line_weight),
        frozen: layer.flags.frozen,
        locked: layer.flags.locked,
        off: layer.flags.off,
        is_plottable: layer.is_plottable,
        xref_dependent: is_xref_dependent_layer(layer),
        xref_block_record_handle,
        xref_name,
        xref_path,
        xref_is_overlay,
        material_handle,
        plotstyle_handle,
        is_current: is_current_layer(doc, layer),
    })
}

#[cfg(test)]
pub(crate) fn list_layers_for_mutation_projection(
    doc: &CadDocument,
    context: LayerMutationProjectionContext,
) -> Result<Vec<LayerRecord>, LayerError> {
    list_layers_for_mutation_projection_with_metadata(
        doc,
        context,
        &LayerMutationProjectionMetadata::default(),
    )
}

#[cfg(test)]
pub(crate) fn list_layers_for_mutation_projection_with_metadata(
    doc: &CadDocument,
    context: LayerMutationProjectionContext,
    metadata: &LayerMutationProjectionMetadata,
) -> Result<Vec<LayerRecord>, LayerError> {
    doc.layers
        .iter()
        .map(|layer| project_layer_record_for_mutation(doc, layer, context, metadata))
        .collect()
}

#[cfg(test)]
fn list_layers_for_mutation_projection_default(
    doc: &CadDocument,
) -> Result<Vec<LayerRecord>, LayerError> {
    list_layers_for_mutation_projection(doc, LayerMutationProjectionContext::default())
}

fn resolve_layer_index_for_mutation(
    doc: &CadDocument,
    selector: &LayerSelector,
) -> Result<usize, LayerError> {
    if selector.handle.is_none() && selector.name.is_none() {
        return Err(LayerError::new(
            "layer_not_found",
            "missing layer handle or name",
        ));
    }

    let by_handle = selector
        .handle
        .as_deref()
        .map(parse_handle)
        .transpose()?
        .and_then(|wanted| {
            doc.layers
                .iter()
                .enumerate()
                .find(|(_, layer)| layer.handle() == wanted)
                .map(|(index, _)| index)
        });
    let by_name = selector.name.as_deref().and_then(|wanted| {
        doc.layers
            .iter()
            .enumerate()
            .find(|(_, layer)| name_eq(layer.name(), wanted))
            .map(|(index, _)| index)
    });

    if selector.handle.is_some() && selector.name.is_some() {
        match (by_handle, by_name) {
            (Some(handle_index), Some(name_index)) if handle_index == name_index => {}
            _ => {
                return Err(LayerError::new(
                    "layer_identity_mismatch",
                    "layer handle and name did not both resolve to the same layer",
                ));
            }
        }
    } else if selector.handle.is_some() && by_handle.is_none() {
        return Err(LayerError::new("layer_not_found", "layer handle not found"));
    } else if selector.name.is_some() && by_name.is_none() {
        return Err(LayerError::new("layer_not_found", "layer name not found"));
    }

    let resolved = by_handle
        .or(by_name)
        .ok_or_else(|| LayerError::new("layer_not_found", "layer not found"))?;
    let layer =
        doc.layers.iter().nth(resolved).ok_or_else(|| {
            LayerError::new("layer_not_found", "layer not found after resolution")
        })?;

    if let Some(expected) = &selector.expected_handle {
        let expected = canonical_handle(parse_handle(expected)?)?;
        let actual = canonical_handle(layer.handle())?;
        if expected != actual {
            return Err(LayerError::new(
                "expected_handle_mismatch",
                format!("expected handle {expected}, found {actual}"),
            ));
        }
    }

    if let Some(expected) = &selector.expected_name {
        if !name_eq(expected, layer.name()) {
            return Err(LayerError::new(
                "expected_name_mismatch",
                format!("expected name `{expected}`, found `{}`", layer.name()),
            ));
        }
    }

    Ok(resolved)
}

fn resolved_layer_for_mutation<'a>(
    doc: &'a CadDocument,
    selector: &LayerSelector,
) -> Result<&'a acadrust::tables::Layer, LayerError> {
    let index = resolve_layer_index_for_mutation(doc, selector)?;
    doc.layers
        .iter()
        .nth(index)
        .ok_or_else(|| LayerError::new("layer_not_found", "layer not found after resolution"))
}

pub(crate) fn project_layer_for_mutation(
    doc: &CadDocument,
    selector: &LayerSelector,
    context: LayerMutationProjectionContext,
) -> Result<LayerRecord, LayerError> {
    project_layer_for_mutation_with_metadata(
        doc,
        selector,
        context,
        &LayerMutationProjectionMetadata::default(),
    )
}

pub(crate) fn project_layer_for_mutation_with_metadata(
    doc: &CadDocument,
    selector: &LayerSelector,
    context: LayerMutationProjectionContext,
    metadata: &LayerMutationProjectionMetadata,
) -> Result<LayerRecord, LayerError> {
    project_layer_record_for_mutation(
        doc,
        resolved_layer_for_mutation(doc, selector)?,
        context,
        metadata,
    )
}

#[cfg(test)]
fn project_layer_for_mutation_default(
    doc: &CadDocument,
    selector: &LayerSelector,
) -> Result<LayerRecord, LayerError> {
    project_layer_for_mutation(doc, selector, LayerMutationProjectionContext::default())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LayerPatch {
    color_index: Option<u16>,
    line_type: Option<String>,
    line_weight: Option<LineWeight>,
    frozen: Option<bool>,
    locked: Option<bool>,
    off: Option<bool>,
    is_plottable: Option<bool>,
}

pub(crate) fn validate_layer_name(name: &str) -> Result<(), LayerError> {
    const RESERVED: &[char] = &['<', '>', '/', '\\', '"', ':', ';', '?', '*', '|', '=', '`'];

    if name.is_empty() || name.trim() != name {
        return Err(LayerError::new(
            "invalid_layer_name",
            "layer name is empty or padded",
        ));
    }
    if name.chars().count() > 255 {
        return Err(LayerError::new(
            "invalid_layer_name",
            "layer name exceeds 255 characters",
        ));
    }
    if name
        .chars()
        .any(|c| c.is_ascii_control() || RESERVED.contains(&c))
    {
        return Err(LayerError::new(
            "invalid_layer_name",
            format!("invalid layer name `{name}`"),
        ));
    }
    if name_eq(name, "0") || name_eq(name, "DEFPOINTS") {
        return Err(LayerError::new(
            "invalid_layer_name",
            format!("reserved layer name `{name}`"),
        ));
    }
    Ok(())
}

const UNSUPPORTED_LAYER_PROPERTIES: &[&str] = &[
    "handle",
    "name",
    "is_current",
    "xref_dependent",
    "xref_block_record_handle",
    "xref_name",
    "xref_path",
    "xref_is_overlay",
    "xref_resolved",
    "xref_loaded",
    "viewport_default_frozen",
    "true_color",
    "color_book",
    "color_name",
    "transparency",
    "plot_style",
    "plot_style_name",
    "material_handle",
    "plotstyle_handle",
    "description",
    "extension_dictionary",
    "reactors",
    "app_data",
    "xdata",
];

fn invalid_layer_property(message: impl Into<String>) -> LayerError {
    LayerError::new("invalid_layer_property", message)
}

fn invalid_line_weight(message: impl Into<String>) -> LayerError {
    LayerError::new("invalid_line_weight", message)
}

#[cfg(any(test, target_os = "windows"))]
pub(crate) fn is_unsupported_layer_property(property: &str) -> bool {
    UNSUPPORTED_LAYER_PROPERTIES.contains(&property)
}

pub(crate) fn unsupported_layer_property(property: &str) -> LayerError {
    LayerError::new(
        "unsupported_layer_property",
        format!(
            "layer property `{property}` is read-only or unsupported by the selected parser backend"
        ),
    )
}

fn parse_line_type_property(
    doc: &CadDocument,
    value: &serde_json::Value,
) -> Result<String, LayerError> {
    let Some(line_type) = value.as_str() else {
        return Err(invalid_layer_property("line_type must be a string"));
    };
    if line_type.is_empty() || line_type.trim() != line_type {
        return Err(invalid_layer_property(
            "line_type must not be empty or padded",
        ));
    }
    doc.line_types
        .iter()
        .find(|candidate| name_eq(candidate.name(), line_type))
        .map(|candidate| candidate.name().to_string())
        .ok_or_else(|| {
            LayerError::new(
                "line_type_not_found",
                format!("line_type `{line_type}` was not found in the drawing linetype table"),
            )
        })
}

pub(crate) fn parse_line_weight_property(
    value: &serde_json::Value,
) -> Result<LineWeight, LayerError> {
    let Some(object) = value.as_object() else {
        return Err(invalid_line_weight("line_weight must be an object"));
    };
    let Some(kind) = object.get("kind").and_then(|value| value.as_str()) else {
        return Err(invalid_line_weight("line_weight.kind must be a string"));
    };

    match kind {
        "by_layer" => {
            if object.len() == 1 {
                Ok(LineWeight::ByLayer)
            } else {
                Err(invalid_line_weight(
                    "by_layer line_weight must only include kind",
                ))
            }
        }
        "by_block" => {
            if object.len() == 1 {
                Ok(LineWeight::ByBlock)
            } else {
                Err(invalid_line_weight(
                    "by_block line_weight must only include kind",
                ))
            }
        }
        "default" => {
            if object.len() == 1 {
                Ok(LineWeight::Default)
            } else {
                Err(invalid_line_weight(
                    "default line_weight must only include kind",
                ))
            }
        }
        "value" => {
            if object.len() != 2 {
                return Err(invalid_line_weight(
                    "value line_weight must include kind and hundredths_mm",
                ));
            }
            let Some(raw) = object.get("hundredths_mm").and_then(|value| value.as_i64()) else {
                return Err(invalid_line_weight(
                    "line_weight.value requires integer hundredths_mm",
                ));
            };
            let Ok(value) = i16::try_from(raw) else {
                return Err(invalid_line_weight(
                    "line_weight.value is outside supported range",
                ));
            };
            if !is_standard_line_weight(value) {
                return Err(invalid_line_weight(format!(
                    "line_weight.value {value} is not a standard AutoCAD lineweight"
                )));
            }
            Ok(LineWeight::Value(value))
        }
        "raw" => Err(invalid_line_weight(
            "raw line_weight values are read-only and cannot be written",
        )),
        _ => Err(invalid_line_weight(format!(
            "unsupported line_weight kind `{kind}`"
        ))),
    }
}

fn parse_properties(
    doc: &CadDocument,
    properties: &serde_json::Map<String, serde_json::Value>,
    require_non_empty: bool,
) -> Result<LayerPatch, LayerError> {
    if require_non_empty && properties.is_empty() {
        return Err(LayerError::new(
            "empty_layer_update",
            "layer update properties are empty",
        ));
    }

    let mut patch = LayerPatch::default();
    for (key, value) in properties {
        match key.as_str() {
            "color_index" => {
                let Some(raw) = value.as_u64() else {
                    return Err(invalid_layer_property(
                        "color_index must be an integer from 1 to 255",
                    ));
                };
                if !(1..=255).contains(&raw) {
                    return Err(invalid_layer_property("color_index must be from 1 to 255"));
                }
                patch.color_index = Some(raw as u16);
            }
            "line_type" => {
                patch.line_type = Some(parse_line_type_property(doc, value)?);
            }
            "line_weight" => {
                patch.line_weight = Some(parse_line_weight_property(value)?);
            }
            "frozen" => {
                patch.frozen = Some(
                    value
                        .as_bool()
                        .ok_or_else(|| invalid_layer_property("frozen must be a boolean"))?,
                );
            }
            "locked" => {
                patch.locked = Some(
                    value
                        .as_bool()
                        .ok_or_else(|| invalid_layer_property("locked must be a boolean"))?,
                );
            }
            "off" => {
                patch.off = Some(
                    value
                        .as_bool()
                        .ok_or_else(|| invalid_layer_property("off must be a boolean"))?,
                );
            }
            "is_plottable" => {
                patch.is_plottable = Some(
                    value
                        .as_bool()
                        .ok_or_else(|| invalid_layer_property("is_plottable must be a boolean"))?,
                );
            }
            other if UNSUPPORTED_LAYER_PROPERTIES.contains(&other) => {
                return Err(unsupported_layer_property(other));
            }
            other => {
                return Err(invalid_layer_property(format!(
                    "unknown layer property `{other}`"
                )));
            }
        }
    }
    Ok(patch)
}

fn apply_layer_patch(layer: &mut acadrust::tables::Layer, patch: LayerPatch) {
    if let Some(color_index) = patch.color_index {
        layer.color = acadrust::types::Color::from_index(color_index as i16);
    }
    if let Some(line_type) = patch.line_type {
        layer.line_type = line_type;
    }
    if let Some(line_weight) = patch.line_weight {
        layer.line_weight = line_weight;
    }
    if let Some(frozen) = patch.frozen {
        layer.flags.frozen = frozen;
    }
    if let Some(locked) = patch.locked {
        layer.flags.locked = locked;
    }
    if let Some(off) = patch.off {
        layer.flags.off = off;
    }
    if let Some(is_plottable) = patch.is_plottable {
        layer.is_plottable = is_plottable;
    }
}

fn layer_name_exists(doc: &CadDocument, name: &str) -> bool {
    doc.layers.iter().any(|layer| name_eq(layer.name(), name))
}

pub fn create_layer(
    doc: &mut CadDocument,
    name: &str,
    properties: &serde_json::Map<String, serde_json::Value>,
) -> Result<LayerRecord, LayerError> {
    create_layer_with_mutation_projection(
        doc,
        name,
        properties,
        LayerMutationProjectionContext::default(),
    )
}

pub(crate) fn create_layer_with_mutation_projection(
    doc: &mut CadDocument,
    name: &str,
    properties: &serde_json::Map<String, serde_json::Value>,
    context: LayerMutationProjectionContext,
) -> Result<LayerRecord, LayerError> {
    validate_layer_name(name)?;
    if layer_name_exists(doc, name) {
        return Err(LayerError::new(
            "layer_name_collision",
            format!("layer `{name}` already exists"),
        ));
    }

    let patch = parse_properties(doc, properties, false)?;
    let mut layer = acadrust::tables::Layer::new(name);
    layer.set_handle(doc.allocate_handle());
    apply_layer_patch(&mut layer, patch);
    doc.layers
        .add(layer)
        .map_err(|err| LayerError::new("layer_name_collision", err.to_string()))?;

    project_layer_for_mutation(
        doc,
        &LayerSelector {
            name: Some(name.to_string()),
            ..Default::default()
        },
        context,
    )
}

pub fn update_layer(
    doc: &mut CadDocument,
    selector: &LayerSelector,
    properties: &serde_json::Map<String, serde_json::Value>,
) -> Result<LayerRecord, LayerError> {
    update_layer_with_mutation_projection(
        doc,
        selector,
        properties,
        LayerMutationProjectionContext::default(),
    )
}

pub(crate) fn update_layer_with_mutation_projection(
    doc: &mut CadDocument,
    selector: &LayerSelector,
    properties: &serde_json::Map<String, serde_json::Value>,
    context: LayerMutationProjectionContext,
) -> Result<LayerRecord, LayerError> {
    if properties.is_empty() {
        return Err(LayerError::new(
            "empty_layer_update",
            "layer update properties are empty",
        ));
    }
    let index = resolve_layer_index_for_mutation(doc, selector)?;
    let (current, xref_dependent) = {
        let layer = doc.layers.iter().nth(index).ok_or_else(|| {
            LayerError::new("layer_not_found", "layer not found after resolution")
        })?;
        (is_current_layer(doc, layer), is_xref_dependent_layer(layer))
    };
    if xref_dependent
        && context.format == LayerMutationProjectionFormat::Dxf
        && properties.contains_key("line_type")
    {
        return Err(unsupported_layer_property("line_type"));
    }
    let patch = parse_properties(doc, properties, false)?;
    if current && patch.frozen == Some(true) {
        return Err(LayerError::new(
            "cannot_freeze_current_layer",
            "cannot freeze the current layer",
        ));
    }

    let layer_name = doc
        .layers
        .iter()
        .nth(index)
        .ok_or_else(|| LayerError::new("layer_not_found", "layer not found after resolution"))?
        .name()
        .to_string();
    let layer = doc
        .layers
        .get_mut(&layer_name)
        .ok_or_else(|| LayerError::new("layer_not_found", "layer not found for mutation"))?;
    apply_layer_patch(layer, patch);
    project_layer_for_mutation(
        doc,
        &LayerSelector {
            name: Some(layer_name),
            ..Default::default()
        },
        context,
    )
}

fn is_protected_name(name: &str) -> bool {
    name_eq(name, "0") || name_eq(name, "DEFPOINTS")
}

fn entity_uses_layer_name(entity: &acadrust::entities::EntityType, name: &str) -> bool {
    if name_eq(entity.common().layer.as_str(), name) {
        return true;
    }
    match entity {
        acadrust::entities::EntityType::Insert(insert) => insert
            .attributes
            .iter()
            .any(|attribute| name_eq(attribute.common.layer.as_str(), name)),
        _ => false,
    }
}

fn entity_has_viewport_layer_handle(
    entity: &acadrust::entities::EntityType,
    handle: Handle,
) -> bool {
    match entity {
        acadrust::entities::EntityType::Viewport(viewport) => {
            viewport.frozen_layers.contains(&handle)
        }
        _ => false,
    }
}

fn assert_layer_has_no_delete_references(
    doc: &CadDocument,
    name: &str,
    handle: Handle,
) -> Result<(), LayerError> {
    for entity in doc.entities() {
        if entity_uses_layer_name(entity, name) {
            return Err(LayerError::new(
                "layer_has_content",
                format!("layer `{name}` has content"),
            ));
        }
        if entity_has_viewport_layer_handle(entity, handle) {
            return Err(LayerError::new(
                "layer_has_unverified_references",
                format!("layer `{name}` is referenced by a viewport frozen-layer handle"),
            ));
        }
    }
    Ok(())
}

fn rewrite_entity_layers(doc: &mut CadDocument, old_name: &str, new_name: &str) {
    for entity in doc.entities_mut() {
        if name_eq(entity.common().layer.as_str(), old_name) {
            entity.common_mut().layer = new_name.to_string();
        }
        if let acadrust::entities::EntityType::Insert(insert) = entity {
            for attribute in &mut insert.attributes {
                if name_eq(attribute.common.layer.as_str(), old_name) {
                    attribute.common.layer = new_name.to_string();
                }
            }
        }
    }
}

pub fn rename_layer(
    doc: &mut CadDocument,
    selector: &LayerSelector,
    new_name: &str,
) -> Result<LayerRecord, LayerError> {
    rename_layer_with_mutation_projection(
        doc,
        selector,
        new_name,
        LayerMutationProjectionContext::default(),
    )
}

pub(crate) fn rename_layer_with_mutation_projection(
    doc: &mut CadDocument,
    selector: &LayerSelector,
    new_name: &str,
    context: LayerMutationProjectionContext,
) -> Result<LayerRecord, LayerError> {
    let index = resolve_layer_index_for_mutation(doc, selector)?;
    let old_layer =
        doc.layers.iter().nth(index).ok_or_else(|| {
            LayerError::new("layer_not_found", "layer not found after resolution")
        })?;
    let old_name = old_layer.name().to_string();
    let old_handle = old_layer.handle();
    let was_current = is_current_layer(doc, old_layer);

    if is_protected_name(&old_name) {
        return Err(LayerError::new(
            "protected_layer",
            format!("cannot rename layer `{old_name}`"),
        ));
    }
    if is_xref_dependent_layer(old_layer) {
        return Err(LayerError::new(
            "xref_dependent_layer",
            "cannot rename xref-dependent layer",
        ));
    }
    validate_layer_name(new_name)?;
    if doc
        .layers
        .iter()
        .any(|layer| layer.handle() != old_handle && name_eq(layer.name(), new_name))
    {
        return Err(LayerError::new(
            "layer_name_collision",
            format!("layer `{new_name}` already exists"),
        ));
    }

    let mut renamed = doc
        .layers
        .remove(&old_name)
        .ok_or_else(|| LayerError::new("layer_not_found", "layer not found for rename"))?;
    let original = renamed.clone();
    renamed.set_name(new_name.to_string());
    if let Err(err) = doc.layers.add(renamed) {
        let _ = doc.layers.add(original);
        return Err(LayerError::new("layer_name_collision", err.to_string()));
    }
    rewrite_entity_layers(doc, &old_name, new_name);

    if was_current {
        doc.header.current_layer_name = new_name.to_string();
        doc.header.current_layer_handle = old_handle;
    }

    project_layer_for_mutation(
        doc,
        &LayerSelector {
            handle: Some(canonical_handle(old_handle)?),
            ..Default::default()
        },
        context,
    )
}

pub fn delete_layer(
    doc: &mut CadDocument,
    selector: &LayerSelector,
) -> Result<DeletedLayer, LayerError> {
    let index = resolve_layer_index_for_mutation(doc, selector)?;
    let layer =
        doc.layers.iter().nth(index).ok_or_else(|| {
            LayerError::new("layer_not_found", "layer not found after resolution")
        })?;
    let name = layer.name().to_string();
    let handle = layer.handle();

    if is_protected_name(&name) {
        return Err(LayerError::new(
            "protected_layer",
            format!("cannot delete layer `{name}`"),
        ));
    }
    if is_xref_dependent_layer(layer) {
        return Err(LayerError::new(
            "xref_dependent_layer",
            "cannot delete xref-dependent layer",
        ));
    }
    if is_current_layer(doc, layer) {
        return Err(LayerError::new(
            "cannot_delete_current_layer",
            "cannot delete current layer",
        ));
    }
    assert_layer_has_no_delete_references(doc, &name, handle)?;

    doc.layers
        .remove(&name)
        .ok_or_else(|| LayerError::new("layer_not_found", "layer not found for delete"))?;
    Ok(DeletedLayer {
        handle: canonical_handle(handle)?,
        name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::tables::{BlockRecord, Layer, LineType, TableEntry};
    use acadrust::types::{Color, Handle, LineWeight};
    use acadrust::CadDocument;

    fn layer0_handle(doc: &CadDocument) -> String {
        canonical_handle(doc.layers.get("0").unwrap().handle()).unwrap()
    }

    #[test]
    fn new_doc_has_layer_zero() {
        let doc = CadDocument::new();
        let layers = list_layers_for_mutation_projection_default(&doc).unwrap();
        assert!(
            layers.iter().any(|l| l.name == "0"),
            "expected layer '0' in {:?}",
            layers.iter().map(|l| &l.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn custom_layer_retains_color_and_flags() {
        let mut doc = CadDocument::new();
        let mut layer = Layer::new("ANNO");
        layer.set_handle(doc.allocate_handle());
        layer.color = Color::from_index(3);
        layer.flags.frozen = true;
        doc.layers.add(layer).unwrap();

        let layers = list_layers_for_mutation_projection_default(&doc).unwrap();
        let anno = layers
            .iter()
            .find(|l| l.name == "ANNO")
            .expect("ANNO layer not found");
        assert_eq!(anno.color_index, Some(3));
        assert!(anno.frozen);
        assert!(!anno.locked);
        assert!(!anno.off);
    }

    #[test]
    fn non_aci_layer_colors_project_null_in_dwg_and_dxf_contexts() {
        let mut doc = CadDocument::new();

        let mut indexed = Layer::new("INDEXED");
        indexed.set_handle(doc.allocate_handle());
        indexed.color = Color::from_index(150);
        doc.layers.add(indexed).unwrap();

        let mut true_color = Layer::new("TRUE_COLOR");
        true_color.set_handle(doc.allocate_handle());
        true_color.color = Color::from_rgb(17, 147, 238);
        doc.layers.add(true_color).unwrap();

        let mut color_book = Layer::new("COLOR_BOOK");
        color_book.set_handle(doc.allocate_handle());
        color_book.color = Color::from_rgb(252, 200, 7);
        doc.layers.add(color_book).unwrap();

        for context in [
            LayerMutationProjectionContext::DWG,
            LayerMutationProjectionContext::DXF,
        ] {
            let records = list_layers_for_mutation_projection(&doc, context).unwrap();
            assert_eq!(
                records
                    .iter()
                    .find(|layer| layer.name == "INDEXED")
                    .unwrap()
                    .color_index,
                Some(150)
            );
            for name in ["TRUE_COLOR", "COLOR_BOOK"] {
                assert_eq!(
                    records
                        .iter()
                        .find(|layer| layer.name == name)
                        .unwrap()
                        .color_index,
                    None,
                    "{name} must not expose its fallback ACI in {context:?}"
                );
            }
        }
    }

    #[test]
    fn raw_non_indexed_color_metadata_restores_cross_format_parity() {
        let mut dwg = CadDocument::new();
        let mut dwg_layer = Layer::new("TRUE_COLOR");
        dwg_layer.set_handle(Handle::new(0xAB));
        dwg_layer.color = Color::from_rgb(17, 147, 238);
        dwg.layers.add(dwg_layer).unwrap();

        let mut dxf = CadDocument::new();
        let mut dxf_layer = Layer::new("TRUE_COLOR");
        dxf_layer.set_handle(Handle::new(0xAB));
        dxf_layer.color = Color::from_index(150);
        dxf.layers.add(dxf_layer).unwrap();

        let selector = LayerSelector {
            name: Some("TRUE_COLOR".to_string()),
            ..Default::default()
        };
        let dwg_record =
            project_layer_for_mutation(&dwg, &selector, LayerMutationProjectionContext::DWG)
                .unwrap();
        assert_eq!(dwg_record.color_index, None);

        let mut metadata = LayerMutationProjectionMetadata::default();
        metadata.mark_non_indexed_color(Some(Handle::new(0xAB)), "TRUE_COLOR");
        let dxf_records = list_layers_for_mutation_projection_with_metadata(
            &dxf,
            LayerMutationProjectionContext::DXF,
            &metadata,
        )
        .unwrap();
        let dxf_record = dxf_records
            .iter()
            .find(|layer| layer.name == "TRUE_COLOR")
            .unwrap();

        assert_eq!(dxf_record.color_index, dwg_record.color_index);
    }

    #[test]
    fn non_indexed_color_metadata_prefers_handle_with_name_fallback() {
        let mut doc = CadDocument::new();
        let mut layer = Layer::new("TRUE_COLOR");
        layer.set_handle(Handle::new(0xAB));
        layer.color = Color::from_index(150);
        doc.layers.add(layer).unwrap();
        let selector = LayerSelector {
            name: Some("TRUE_COLOR".to_string()),
            ..Default::default()
        };

        let mut mismatched_handle = LayerMutationProjectionMetadata::default();
        mismatched_handle.mark_non_indexed_color(Some(Handle::new(0xAC)), "TRUE_COLOR");
        let record = project_layer_for_mutation_with_metadata(
            &doc,
            &selector,
            LayerMutationProjectionContext::DXF,
            &mismatched_handle,
        )
        .unwrap();
        assert_eq!(record.color_index, Some(150));

        let mut name_fallback = LayerMutationProjectionMetadata::default();
        name_fallback.mark_non_indexed_color(None, "true_color");
        let record = project_layer_for_mutation_with_metadata(
            &doc,
            &selector,
            LayerMutationProjectionContext::DXF,
            &name_fallback,
        )
        .unwrap();
        assert_eq!(record.color_index, None);
    }

    #[test]
    fn output_serializes_to_json_array() {
        let doc = CadDocument::new();
        let layers = list_layers_for_mutation_projection_default(&doc).unwrap();
        let json = serde_json::to_string(&layers).unwrap();
        assert!(json.starts_with('['));
    }

    #[test]
    fn list_layers_includes_handle_context_and_plot_fields() {
        let doc = CadDocument::new();
        let layers = list_layers_for_mutation_projection_default(&doc).unwrap();
        let layer0 = layers.iter().find(|layer| layer.name == "0").unwrap();
        assert_eq!(layer0.handle, layer0_handle(&doc));
        assert_eq!(layer0.color_index, Some(7));
        assert!(!layer0.frozen);
        assert!(!layer0.locked);
        assert!(!layer0.off);
        assert!(layer0.is_plottable);
        assert!(!layer0.xref_dependent);
        assert_eq!(layer0.line_type, "Continuous");
        assert_eq!(layer0.line_weight, LayerLineWeight::Default);
        assert_eq!(layer0.xref_block_record_handle, None);
        assert_eq!(layer0.xref_name, None);
        assert_eq!(layer0.xref_path, None);
        assert_eq!(layer0.xref_is_overlay, None);
        assert_eq!(layer0.material_handle, None);
        assert_eq!(layer0.plotstyle_handle, None);
        assert!(layer0.is_current);
    }

    #[test]
    fn get_layer_accepts_canonical_lowercase_and_prefixed_handles() {
        let mut doc = CadDocument::new();
        let mut anno = Layer::new("ANNO");
        anno.set_handle(Handle::new(0xAB));
        doc.layers.add(anno).unwrap();

        let canonical = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                handle: Some("AB".to_string()),
                name: None,
                expected_handle: None,
                expected_name: None,
            },
        )
        .unwrap();
        assert_eq!(canonical.name, "ANNO");

        let lowercase = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                handle: Some("ab".to_string()),
                name: None,
                expected_handle: None,
                expected_name: None,
            },
        )
        .unwrap();
        assert_eq!(lowercase.handle, canonical.handle);

        let prefixed = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                handle: Some("0xAB".to_string()),
                name: None,
                expected_handle: None,
                expected_name: None,
            },
        )
        .unwrap();
        assert_eq!(prefixed.handle, canonical.handle);
    }

    #[test]
    fn get_layer_accepts_case_insensitive_name_and_matching_handle_name() {
        let mut doc = CadDocument::new();
        let mut anno = Layer::new("ANNO");
        anno.set_handle(Handle::new(0xAB));
        doc.layers.add(anno).unwrap();

        let by_name = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                handle: None,
                name: Some("anno".to_string()),
                expected_handle: None,
                expected_name: None,
            },
        )
        .unwrap();
        assert_eq!(by_name.handle, "AB");
        assert_eq!(by_name.name, "ANNO");

        let by_handle_and_name = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                handle: Some("0xab".to_string()),
                name: Some("anno".to_string()),
                expected_handle: None,
                expected_name: None,
            },
        )
        .unwrap();
        assert_eq!(by_handle_and_name.handle, by_name.handle);
        assert_eq!(by_handle_and_name.name, by_name.name);
    }

    #[test]
    fn mismatched_handle_and_name_returns_reason_code() {
        let mut doc = CadDocument::new();
        let layer0_handle = layer0_handle(&doc);
        let mut anno = Layer::new("ANNO");
        anno.set_handle(doc.allocate_handle());
        doc.layers.add(anno).unwrap();

        let err = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                handle: Some(layer0_handle.clone()),
                name: Some("ANNO".to_string()),
                expected_handle: None,
                expected_name: None,
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "layer_identity_mismatch");
        assert!(err.to_string().contains("code=layer_identity_mismatch"));

        let err = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                handle: Some(layer0_handle),
                name: Some("MISSING".to_string()),
                expected_handle: None,
                expected_name: None,
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "layer_identity_mismatch");

        let err = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                handle: Some("FFFF".to_string()),
                name: Some("ANNO".to_string()),
                expected_handle: None,
                expected_name: None,
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "layer_identity_mismatch");
    }

    #[test]
    fn invalid_and_null_handles_use_invalid_layer_handle() {
        let doc = CadDocument::new();

        let err = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                handle: Some("0".to_string()),
                name: None,
                expected_handle: None,
                expected_name: None,
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "invalid_layer_handle");

        let err = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                handle: Some("not-a-handle".to_string()),
                name: None,
                expected_handle: None,
                expected_name: None,
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "invalid_layer_handle");
    }

    #[test]
    fn expected_guards_are_enforced_after_resolution() {
        let doc = CadDocument::new();
        let layer0_handle = layer0_handle(&doc);
        let mismatched_handle = if layer0_handle.eq_ignore_ascii_case("11") {
            "12"
        } else {
            "11"
        };

        let err = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                handle: Some(layer0_handle.clone()),
                name: None,
                expected_handle: Some(mismatched_handle.to_string()),
                expected_name: None,
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "expected_handle_mismatch");

        let err = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                handle: Some(layer0_handle),
                name: None,
                expected_handle: None,
                expected_name: Some("ANNO".to_string()),
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "expected_name_mismatch");
    }

    #[test]
    fn expected_guards_accept_matching_values_after_resolution() {
        let doc = CadDocument::new();
        let layer0_handle = layer0_handle(&doc);

        let layer = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                handle: Some(layer0_handle.clone()),
                name: None,
                expected_handle: Some(format!("0x{layer0_handle}")),
                expected_name: Some("0".to_string()),
            },
        )
        .unwrap();
        assert_eq!(layer.handle, layer0_handle);
        assert_eq!(layer.name, "0");
    }

    #[test]
    fn current_layer_prefers_valid_handle_over_stale_name() {
        let mut doc = CadDocument::new();
        let mut anno = Layer::new("ANNO");
        let anno_handle = doc.allocate_handle();
        anno.set_handle(anno_handle);
        doc.layers.add(anno).unwrap();
        doc.header.current_layer_handle = anno_handle;
        doc.header.current_layer_name = "0".to_string();

        let layers = list_layers_for_mutation_projection_default(&doc).unwrap();
        assert!(
            !layers
                .iter()
                .find(|layer| layer.name == "0")
                .unwrap()
                .is_current
        );
        assert!(
            layers
                .iter()
                .find(|layer| layer.name == "ANNO")
                .unwrap()
                .is_current
        );
    }

    #[test]
    fn current_layer_falls_back_to_name_when_header_handle_is_invalid() {
        let mut doc = CadDocument::new();
        let mut anno = Layer::new("ANNO");
        anno.set_handle(doc.allocate_handle());
        doc.layers.add(anno).unwrap();
        doc.header.current_layer_handle = Handle::new(0xFFFF);
        doc.header.current_layer_name = "ANNO".to_string();

        let layers = list_layers_for_mutation_projection_default(&doc).unwrap();
        assert!(
            !layers
                .iter()
                .find(|layer| layer.name == "0")
                .unwrap()
                .is_current
        );
        assert!(
            layers
                .iter()
                .find(|layer| layer.name == "ANNO")
                .unwrap()
                .is_current
        );
    }

    #[test]
    fn xref_dependent_includes_flag_or_name_marker() {
        let mut doc = CadDocument::new();

        let mut by_flag = Layer::new("XREF_FLAG");
        by_flag.set_handle(doc.allocate_handle());
        by_flag.flags.xref_dependent = true;
        doc.layers.add(by_flag).unwrap();

        let mut by_name = Layer::new("SITE|ANNO");
        by_name.set_handle(doc.allocate_handle());
        doc.layers.add(by_name).unwrap();

        let layers = list_layers_for_mutation_projection_default(&doc).unwrap();
        assert!(
            layers
                .iter()
                .find(|layer| layer.name == "XREF_FLAG")
                .unwrap()
                .xref_dependent
        );
        assert!(
            layers
                .iter()
                .find(|layer| layer.name == "SITE|ANNO")
                .unwrap()
                .xref_dependent
        );
    }

    #[test]
    fn list_layers_includes_expanded_record_fields_with_format_context() {
        let mut doc = CadDocument::new();
        let mut block = BlockRecord::new("SITE");
        block.set_handle(Handle::new(0x44));
        block.flags.is_xref_overlay = true;
        block.xref_path = "site.dwg".to_string();
        doc.block_records.add(block).unwrap();

        let mut layer = Layer::new("SITE|ANNO");
        layer.set_handle(doc.allocate_handle());
        layer.flags.xref_dependent = true;
        layer.line_weight = LineWeight::Value(25);
        layer.xref_block_record_handle = Handle::new(0x44);
        layer.material = Handle::new(0x55);
        layer.plotstyle_handle = Handle::new(0x66);
        doc.layers.add(layer).unwrap();

        let dwg = project_layer_for_mutation(
            &doc,
            &LayerSelector {
                name: Some("SITE|ANNO".to_string()),
                ..Default::default()
            },
            LayerMutationProjectionContext::DWG,
        )
        .unwrap();
        assert_eq!(dwg.line_type, "Continuous");
        assert_eq!(
            dwg.line_weight,
            LayerLineWeight::Value { hundredths_mm: 25 }
        );
        assert!(dwg.xref_dependent);
        assert_eq!(dwg.xref_name.as_deref(), Some("SITE"));
        assert_eq!(dwg.xref_block_record_handle.as_deref(), Some("44"));
        assert_eq!(dwg.xref_path.as_deref(), Some("site.dwg"));
        assert_eq!(dwg.xref_is_overlay, Some(true));
        assert_eq!(dwg.material_handle.as_deref(), Some("55"));
        assert_eq!(dwg.plotstyle_handle.as_deref(), Some("66"));

        let dxf = project_layer_for_mutation(
            &doc,
            &LayerSelector {
                name: Some("SITE|ANNO".to_string()),
                ..Default::default()
            },
            LayerMutationProjectionContext::DXF,
        )
        .unwrap();
        assert_eq!(dxf.xref_name.as_deref(), Some("SITE"));
        assert_eq!(dxf.xref_path.as_deref(), Some("site.dwg"));
        assert_eq!(dxf.xref_block_record_handle, None);
        assert_eq!(dxf.xref_is_overlay, None);
        assert_eq!(dxf.material_handle, None);
        assert_eq!(dxf.plotstyle_handle, None);
    }

    #[test]
    fn raw_lineweight_is_read_only_record_state() {
        let mut doc = CadDocument::new();
        let mut layer = Layer::new("ODD");
        layer.set_handle(doc.allocate_handle());
        layer.line_weight = LineWeight::Value(42);
        doc.layers.add(layer).unwrap();

        let record = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                name: Some("ODD".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(record.line_weight, LayerLineWeight::Raw { raw_value: 42 });
    }

    #[test]
    fn list_layers_rejects_null_public_handles() {
        let mut doc = CadDocument::new();
        let layer = Layer::new("BAD");
        doc.layers.add(layer).unwrap();

        let err = list_layers_for_mutation_projection_default(&doc).unwrap_err();
        assert_eq!(err.code(), "invalid_layer_handle");
        assert!(!err.to_string().contains("handle 0 is public"));
    }

    #[test]
    fn create_layer_rejects_invalid_names_and_color_values() {
        let mut doc = CadDocument::new();
        for name in ["", " ANNO", "ANNO ", "A|B", "0", "defpoints", "A<B"] {
            let err = create_layer(&mut doc, name, &serde_json::Map::new()).unwrap_err();
            assert_eq!(err.code(), "invalid_layer_name", "name={name:?}");
        }

        let mut properties = serde_json::Map::new();
        properties.insert("color_index".to_string(), serde_json::json!(0));
        let err = create_layer(&mut doc, "ANNO", &properties).unwrap_err();
        assert_eq!(err.code(), "invalid_layer_property");

        properties.insert("color_index".to_string(), serde_json::Value::Null);
        let err = create_layer(&mut doc, "ANNO", &properties).unwrap_err();
        assert_eq!(err.code(), "invalid_layer_property");
    }

    #[test]
    fn create_layer_adds_host_owned_layer_with_properties() {
        let mut doc = CadDocument::new();
        let mut dashed = LineType::new("Dashed");
        dashed.set_handle(doc.allocate_handle());
        doc.line_types.add(dashed).unwrap();
        let properties = serde_json::json!({
            "color_index": 3,
            "line_type": "dashed",
            "line_weight": {"kind": "value", "hundredths_mm": 25},
            "frozen": true,
            "locked": true,
            "off": true,
            "is_plottable": false
        })
        .as_object()
        .unwrap()
        .clone();

        let record = create_layer(&mut doc, "ANNO", &properties).unwrap();
        assert_eq!(record.name, "ANNO");
        assert_eq!(record.color_index, Some(3));
        assert_eq!(record.line_type, "Dashed");
        assert_eq!(
            record.line_weight,
            LayerLineWeight::Value { hundredths_mm: 25 }
        );
        assert!(record.frozen);
        assert!(record.locked);
        assert!(record.off);
        assert!(!record.is_plottable);
        assert!(!record.xref_dependent);
    }

    #[test]
    fn lineweight_write_accepts_supported_shapes() {
        let mut doc = CadDocument::new();
        create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();
        let selector = LayerSelector {
            name: Some("ANNO".to_string()),
            ..Default::default()
        };

        for (json, expected) in [
            (
                serde_json::json!({"line_weight": {"kind": "by_layer"}}),
                LayerLineWeight::ByLayer,
            ),
            (
                serde_json::json!({"line_weight": {"kind": "by_block"}}),
                LayerLineWeight::ByBlock,
            ),
            (
                serde_json::json!({"line_weight": {"kind": "default"}}),
                LayerLineWeight::Default,
            ),
            (
                serde_json::json!({"line_weight": {"kind": "value", "hundredths_mm": 25}}),
                LayerLineWeight::Value { hundredths_mm: 25 },
            ),
        ] {
            let record = update_layer(&mut doc, &selector, json.as_object().unwrap()).unwrap();
            assert_eq!(record.line_weight, expected);
        }
    }

    #[test]
    fn lineweight_write_rejects_malformed_and_raw_shapes() {
        let mut doc = CadDocument::new();
        create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();
        let selector = LayerSelector {
            name: Some("ANNO".to_string()),
            ..Default::default()
        };

        for value in [
            serde_json::json!(null),
            serde_json::json!({}),
            serde_json::json!({"kind": "value"}),
            serde_json::json!({"kind": "value", "hundredths_mm": "25"}),
            serde_json::json!({"kind": "value", "hundredths_mm": 42}),
            serde_json::json!({"kind": "raw", "raw_value": 42}),
        ] {
            let properties = serde_json::json!({"line_weight": value})
                .as_object()
                .unwrap()
                .clone();
            let err = update_layer(&mut doc, &selector, &properties).unwrap_err();
            assert_eq!(err.code(), "invalid_line_weight", "value={properties:?}");
        }
    }

    #[test]
    fn line_type_write_requires_existing_linetype() {
        let mut doc = CadDocument::new();
        create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();
        let selector = LayerSelector {
            name: Some("ANNO".to_string()),
            ..Default::default()
        };

        for line_type in [serde_json::json!(""), serde_json::json!(" Continuous")] {
            let properties = serde_json::json!({"line_type": line_type})
                .as_object()
                .unwrap()
                .clone();
            let err = update_layer(&mut doc, &selector, &properties).unwrap_err();
            assert_eq!(err.code(), "invalid_layer_property");
        }

        let missing = serde_json::json!({"line_type": "Missing"})
            .as_object()
            .unwrap()
            .clone();
        let err = update_layer(&mut doc, &selector, &missing).unwrap_err();
        assert_eq!(err.code(), "line_type_not_found");
    }

    #[test]
    fn unsupported_properties_are_distinct_from_unknown_properties() {
        let mut doc = CadDocument::new();
        create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();
        let selector = LayerSelector {
            name: Some("ANNO".to_string()),
            ..Default::default()
        };

        for key in UNSUPPORTED_LAYER_PROPERTIES {
            let mut properties = serde_json::Map::new();
            properties.insert((*key).to_string(), serde_json::json!(true));
            let err = update_layer(&mut doc, &selector, &properties).unwrap_err();
            assert_eq!(err.code(), "unsupported_layer_property", "property={key}");
        }

        let mut properties = serde_json::Map::new();
        properties.insert("not_a_layer_property".to_string(), serde_json::json!(true));
        let err = update_layer(&mut doc, &selector, &properties).unwrap_err();
        assert_eq!(err.code(), "invalid_layer_property");
    }

    #[test]
    fn update_layer_rejects_empty_and_current_freeze_but_allows_current_off_and_xref_overrides() {
        let mut doc = CadDocument::new();
        let selector = LayerSelector {
            name: Some("0".to_string()),
            ..Default::default()
        };

        let err = update_layer(&mut doc, &selector, &serde_json::Map::new()).unwrap_err();
        assert_eq!(err.code(), "empty_layer_update");

        let freeze = serde_json::json!({"frozen": true})
            .as_object()
            .unwrap()
            .clone();
        let err = update_layer(&mut doc, &selector, &freeze).unwrap_err();
        assert_eq!(err.code(), "cannot_freeze_current_layer");

        let off = serde_json::json!({"off": true})
            .as_object()
            .unwrap()
            .clone();
        let record = update_layer(&mut doc, &selector, &off).unwrap();
        assert!(record.off);

        let mut xref = acadrust::tables::Layer::new("XREF|A");
        xref.set_handle(doc.allocate_handle());
        xref.flags.xref_dependent = true;
        doc.layers.add(xref).unwrap();
        let record = update_layer(
            &mut doc,
            &LayerSelector {
                name: Some("XREF|A".to_string()),
                ..Default::default()
            },
            &serde_json::json!({"locked": true})
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap();
        assert!(record.locked);

        let err = update_layer_with_mutation_projection(
            &mut doc,
            &LayerSelector {
                name: Some("XREF|A".to_string()),
                ..Default::default()
            },
            serde_json::json!({"line_type": "Continuous"})
                .as_object()
                .unwrap(),
            LayerMutationProjectionContext::DXF,
        )
        .unwrap_err();
        assert_eq!(err.code(), "unsupported_layer_property");

        let err = update_layer_with_mutation_projection(
            &mut doc,
            &LayerSelector {
                name: Some("XREF|A".to_string()),
                ..Default::default()
            },
            serde_json::json!({"line_type": "NO_SUCH_LTYPE"})
                .as_object()
                .unwrap(),
            LayerMutationProjectionContext::DXF,
        )
        .unwrap_err();
        assert_eq!(err.code(), "unsupported_layer_property");
    }

    #[test]
    fn rename_layer_rewrites_entity_membership_and_current_layer_name() {
        let mut doc = CadDocument::new();
        create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();
        let mut line = acadrust::entities::Line::from_points(
            acadrust::types::Vector3::new(0.0, 0.0, 0.0),
            acadrust::types::Vector3::new(1.0, 0.0, 0.0),
        );
        line.common.layer = "ANNO".to_string();
        doc.add_entity(acadrust::entities::EntityType::Line(line))
            .unwrap();
        doc.header.current_layer_name = "ANNO".to_string();
        doc.header.current_layer_handle = resolved_layer_for_mutation(
            &doc,
            &LayerSelector {
                name: Some("ANNO".to_string()),
                ..Default::default()
            },
        )
        .unwrap()
        .handle();

        let renamed = rename_layer(
            &mut doc,
            &LayerSelector {
                name: Some("ANNO".to_string()),
                ..Default::default()
            },
            "NOTES",
        )
        .unwrap();
        assert_eq!(renamed.name, "NOTES");
        assert!(renamed.is_current);
        assert!(doc
            .entities()
            .any(|entity| entity.common().layer == "NOTES"));
    }

    #[test]
    fn rename_layer_does_not_make_stale_current_name_current() {
        let mut doc = CadDocument::new();
        create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();
        let current = create_layer(&mut doc, "CURRENT", &serde_json::Map::new()).unwrap();
        doc.header.current_layer_handle = parse_handle(&current.handle).unwrap();
        doc.header.current_layer_name = "ANNO".to_string();

        let renamed = rename_layer(
            &mut doc,
            &LayerSelector {
                name: Some("ANNO".to_string()),
                ..Default::default()
            },
            "NOTES",
        )
        .unwrap();

        assert!(!renamed.is_current);
        let current = project_layer_for_mutation_default(
            &doc,
            &LayerSelector {
                name: Some("CURRENT".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(current.is_current);
    }

    #[test]
    fn rename_layer_rejects_protected_xref_and_collisions() {
        let mut doc = CadDocument::new();
        create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();
        create_layer(&mut doc, "NOTES", &serde_json::Map::new()).unwrap();

        let err = rename_layer(
            &mut doc,
            &LayerSelector {
                name: Some("0".to_string()),
                ..Default::default()
            },
            "ZERO",
        )
        .unwrap_err();
        assert_eq!(err.code(), "protected_layer");

        let err = rename_layer(
            &mut doc,
            &LayerSelector {
                name: Some("ANNO".to_string()),
                ..Default::default()
            },
            "notes",
        )
        .unwrap_err();
        assert_eq!(err.code(), "layer_name_collision");

        let mut xref = Layer::new("XREF|A");
        xref.set_handle(doc.allocate_handle());
        xref.flags.xref_dependent = true;
        doc.layers.add(xref).unwrap();
        let err = rename_layer(
            &mut doc,
            &LayerSelector {
                name: Some("XREF|A".to_string()),
                ..Default::default()
            },
            "XREF_A",
        )
        .unwrap_err();
        assert_eq!(err.code(), "xref_dependent_layer");
    }

    #[test]
    fn rename_layer_rejects_unicode_table_key_collision_without_removing_source() {
        let mut doc = CadDocument::new();
        create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();
        create_layer(&mut doc, "SS", &serde_json::Map::new()).unwrap();

        let err = rename_layer(
            &mut doc,
            &LayerSelector {
                name: Some("ANNO".to_string()),
                ..Default::default()
            },
            "ß",
        )
        .unwrap_err();

        assert_eq!(err.code(), "layer_name_collision");
        assert!(doc.layers.get("ANNO").is_some());
        assert!(doc.layers.get("SS").is_some());
    }

    #[test]
    fn rename_layer_allows_case_only_self_rename() {
        let mut doc = CadDocument::new();
        let created = create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();

        let renamed = rename_layer(
            &mut doc,
            &LayerSelector {
                handle: Some(created.handle),
                expected_name: Some("ANNO".to_string()),
                ..Default::default()
            },
            "anno",
        )
        .unwrap();
        assert_eq!(renamed.name, "anno");
    }

    #[test]
    fn delete_layer_rejects_content_current_and_protected_layers() {
        let mut doc = CadDocument::new();
        create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();
        let mut line = acadrust::entities::Line::from_points(
            acadrust::types::Vector3::new(0.0, 0.0, 0.0),
            acadrust::types::Vector3::new(1.0, 0.0, 0.0),
        );
        line.common.layer = "ANNO".to_string();
        doc.add_entity(acadrust::entities::EntityType::Line(line))
            .unwrap();

        let err = delete_layer(
            &mut doc,
            &LayerSelector {
                name: Some("ANNO".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "layer_has_content");

        let err = delete_layer(
            &mut doc,
            &LayerSelector {
                name: Some("0".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "protected_layer");

        create_layer(&mut doc, "CURRENT", &serde_json::Map::new()).unwrap();
        let current_handle = resolved_layer_for_mutation(
            &doc,
            &LayerSelector {
                name: Some("CURRENT".to_string()),
                ..Default::default()
            },
        )
        .unwrap()
        .handle();
        doc.header.current_layer_name = "CURRENT".to_string();
        doc.header.current_layer_handle = current_handle;
        let err = delete_layer(
            &mut doc,
            &LayerSelector {
                name: Some("CURRENT".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "cannot_delete_current_layer");
    }

    #[test]
    fn delete_layer_removes_unused_layer() {
        let mut doc = CadDocument::new();
        let created = create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();
        let deleted = delete_layer(
            &mut doc,
            &LayerSelector {
                handle: Some(created.handle.clone()),
                expected_name: Some("ANNO".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(deleted.name, "ANNO");
        assert_eq!(deleted.handle, created.handle);
        assert!(doc.layers.get("ANNO").is_none());
    }

    #[test]
    fn delete_layer_rejects_xref_dependent_layer() {
        let mut doc = CadDocument::new();
        let mut xref = Layer::new("XREF|A");
        xref.set_handle(doc.allocate_handle());
        xref.flags.xref_dependent = true;
        doc.layers.add(xref).unwrap();

        let err = delete_layer(
            &mut doc,
            &LayerSelector {
                name: Some("XREF|A".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "xref_dependent_layer");
    }

    #[test]
    fn rename_layer_rewrites_insert_attribute_membership() {
        let mut doc = CadDocument::new();
        create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();
        let mut insert =
            acadrust::entities::Insert::new("TITLE", acadrust::types::Vector3::new(0.0, 0.0, 0.0));
        let mut attribute =
            acadrust::entities::AttributeEntity::new("SHEET".to_string(), "A101".to_string());
        attribute.common.layer = "ANNO".to_string();
        insert.attributes.push(attribute);
        doc.add_entity(acadrust::entities::EntityType::Insert(insert))
            .unwrap();

        rename_layer(
            &mut doc,
            &LayerSelector {
                name: Some("ANNO".to_string()),
                ..Default::default()
            },
            "NOTES",
        )
        .unwrap();

        let attribute_layer = doc
            .entities()
            .find_map(|entity| match entity {
                acadrust::entities::EntityType::Insert(insert) => insert
                    .attributes
                    .first()
                    .map(|attribute| attribute.common.layer.as_str()),
                _ => None,
            })
            .unwrap();
        assert_eq!(attribute_layer, "NOTES");
    }

    #[test]
    fn delete_layer_rejects_insert_attribute_membership() {
        let mut doc = CadDocument::new();
        let created = create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();
        let mut insert =
            acadrust::entities::Insert::new("TITLE", acadrust::types::Vector3::new(0.0, 0.0, 0.0));
        let mut attribute =
            acadrust::entities::AttributeEntity::new("SHEET".to_string(), "A101".to_string());
        attribute.common.layer = "ANNO".to_string();
        insert.attributes.push(attribute);
        doc.add_entity(acadrust::entities::EntityType::Insert(insert))
            .unwrap();

        let err = delete_layer(
            &mut doc,
            &LayerSelector {
                handle: Some(created.handle),
                expected_name: Some("ANNO".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "layer_has_content");
    }

    #[test]
    fn delete_layer_rejects_viewport_frozen_layer_handle_reference() {
        let mut doc = CadDocument::new();
        let created = create_layer(&mut doc, "ANNO", &serde_json::Map::new()).unwrap();
        let mut viewport = acadrust::entities::Viewport::new();
        viewport
            .frozen_layers
            .push(parse_handle(&created.handle).unwrap());
        doc.add_entity(acadrust::entities::EntityType::Viewport(viewport))
            .unwrap();

        let err = delete_layer(
            &mut doc,
            &LayerSelector {
                handle: Some(created.handle),
                expected_name: Some("ANNO".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "layer_has_unverified_references");
    }
}
