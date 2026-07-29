//! Reader-owned layer snapshot parsing, traversal, and projection.
//!
//! This module deliberately has no dependency on layer mutation. DXF direct
//! fields are recovered from the same immutable bytes supplied to the reader
//! backend, while mutation retains its separately named compatibility
//! projection in `ops::layers`.

use std::collections::BTreeSet;

use acadrust::tables::TableEntry;
use acadrust::types::{Color, Handle, LineWeight};
use acadrust::CadDocument;
use serde::Serialize;

use super::contract::{LayerLineWeight, LayerRecord, LayerSelector};
use super::owners::is_xref_definition;
use super::{DrawingFormat, DrawingSnapshot};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerReadError {
    code: String,
    message: String,
}

impl LayerReadError {
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

impl std::fmt::Display for LayerReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "code={} {}", self.code, self.message)
    }
}

impl std::error::Error for LayerReadError {}

fn canonical_handle(handle: Handle) -> Result<String, LayerReadError> {
    if handle.is_null() {
        return Err(LayerReadError::new(
            "invalid_layer_handle",
            "layer handle 0 is invalid",
        ));
    }
    Ok(format!("{:X}", handle.value()))
}

fn canonical_optional_handle(handle: Handle) -> Result<Option<String>, LayerReadError> {
    if handle.is_null() {
        Ok(None)
    } else {
        canonical_handle(handle).map(Some)
    }
}

fn parse_handle(input: &str) -> Result<Handle, LayerReadError> {
    let trimmed = input.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if without_prefix.is_empty() {
        return Err(LayerReadError::new(
            "invalid_layer_handle",
            "empty layer handle",
        ));
    }

    let value = u64::from_str_radix(without_prefix, 16).map_err(|_| {
        LayerReadError::new(
            "invalid_layer_handle",
            format!("invalid layer handle `{input}`"),
        )
    })?;
    let handle = Handle::new(value);
    if handle.is_null() {
        return Err(LayerReadError::new(
            "invalid_layer_handle",
            "layer handle 0 is invalid",
        ));
    }
    Ok(handle)
}

fn name_key(name: &str) -> String {
    name.to_uppercase()
}

fn name_eq(left: &str, right: &str) -> bool {
    name_key(left) == name_key(right)
}

fn resolved_current_layer_handle(document: &CadDocument) -> Option<Handle> {
    let header_handle = document.header.current_layer_handle;
    if !header_handle.is_null()
        && document
            .layers
            .iter()
            .any(|layer| layer.handle() == header_handle)
    {
        return Some(header_handle);
    }
    document
        .layers
        .iter()
        .find(|layer| name_eq(layer.name(), &document.header.current_layer_name))
        .map(|layer| layer.handle())
}

fn is_current_layer(document: &CadDocument, layer: &acadrust::tables::Layer) -> bool {
    resolved_current_layer_handle(document).is_some_and(|current| layer.handle() == current)
}

fn color_index(color: Color) -> Option<u16> {
    match color.index() {
        Some(index @ 1..=255) => Some(index),
        _ => None,
    }
}

const STANDARD_LINE_WEIGHTS: &[i16] = &[
    0, 5, 9, 13, 15, 18, 20, 25, 30, 35, 40, 50, 53, 60, 70, 80, 90, 100, 106, 120, 140, 158, 200,
    211,
];

fn layer_line_weight(line_weight: LineWeight) -> LayerLineWeight {
    match line_weight {
        LineWeight::ByLayer => LayerLineWeight::ByLayer,
        LineWeight::ByBlock => LayerLineWeight::ByBlock,
        LineWeight::Default => LayerLineWeight::Default,
        LineWeight::Value(value) if STANDARD_LINE_WEIGHTS.contains(&value) => {
            LayerLineWeight::Value {
                hundredths_mm: value,
            }
        }
        LineWeight::Value(value) => LayerLineWeight::Raw { raw_value: value },
    }
}

fn layer_xref_name(name: &str, xref_dependent: bool) -> Option<String> {
    if !xref_dependent {
        return None;
    }
    name.split_once('|')
        .and_then(|(xref_name, _)| (!xref_name.is_empty()).then(|| xref_name.to_string()))
}

fn xref_block_record_by_handle(
    document: &CadDocument,
    handle: Handle,
) -> Option<&acadrust::tables::BlockRecord> {
    if handle.is_null() {
        return None;
    }
    document
        .block_records
        .iter()
        .find(|record| record.handle() == handle && is_xref_definition(record))
}

fn xref_block_record_by_unique_name<'a>(
    document: &'a CadDocument,
    xref_name: Option<&str>,
) -> Option<&'a acadrust::tables::BlockRecord> {
    let xref_name = xref_name?;
    let mut matches = document
        .block_records
        .iter()
        .filter(|record| is_xref_definition(record) && name_eq(record.name(), xref_name));
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

#[derive(Debug, Clone)]
struct EffectiveLayerFields {
    color_index: Option<u16>,
    line_type: String,
    line_weight: LayerLineWeight,
    frozen: bool,
    locked: bool,
    off: bool,
    is_plottable: bool,
    xref_dependent: bool,
}

fn backend_fields(layer: &acadrust::tables::Layer) -> EffectiveLayerFields {
    EffectiveLayerFields {
        color_index: color_index(layer.color),
        line_type: layer.line_type.clone(),
        line_weight: layer_line_weight(layer.line_weight),
        frozen: layer.flags.frozen,
        locked: layer.flags.locked,
        off: layer.flags.off,
        is_plottable: layer.is_plottable,
        xref_dependent: layer.flags.xref_dependent || layer.name.contains('|'),
    }
}

fn raw_fields(
    entry: &RawLayerEntry,
    has_non_indexed_color: bool,
) -> Result<EffectiveLayerFields, LayerReadError> {
    let flags = pair_integer(entry, 70, 0)?;
    let raw_color = i16::try_from(pair_integer(entry, 62, 7)?).map_err(|_| {
        unsupported_layer_data(
            entry.name(),
            "group code 62 is outside the i16 value domain",
        )
    })?;
    let raw_line_weight = i16::try_from(pair_integer(entry, 370, -3)?).map_err(|_| {
        unsupported_layer_data(
            entry.name(),
            "group code 370 is outside the i16 value domain",
        )
    })?;
    Ok(EffectiveLayerFields {
        color_index: if has_non_indexed_color {
            None
        } else {
            color_index(Color::from_index(raw_color))
        },
        line_type: entry.value(6).unwrap_or("Continuous").to_string(),
        line_weight: layer_line_weight(LineWeight::from_value(raw_line_weight)),
        frozen: flags & 1 != 0,
        locked: flags & 4 != 0,
        off: raw_color < 0,
        is_plottable: pair_integer(entry, 290, 1)? != 0,
        xref_dependent: flags & 16 != 0 || entry.name().unwrap_or_default().contains('|'),
    })
}

fn project_layer(
    document: &CadDocument,
    layer: &acadrust::tables::Layer,
    format: DrawingFormat,
    raw_entry: Option<&RawLayerEntry>,
    raw_has_non_indexed_color: bool,
) -> Result<LayerRecord, LayerReadError> {
    let fields = match raw_entry {
        Some(entry) => raw_fields(entry, raw_has_non_indexed_color)?,
        None => backend_fields(layer),
    };
    let xref_name = layer_xref_name(&layer.name, fields.xref_dependent);
    let handle_match = match format {
        DrawingFormat::Dwg => xref_block_record_by_handle(document, layer.xref_block_record_handle),
        DrawingFormat::Dxf => None,
    };
    let xref_record =
        handle_match.or_else(|| xref_block_record_by_unique_name(document, xref_name.as_deref()));
    let (xref_block_record_handle, xref_is_overlay, material_handle, plotstyle_handle) =
        match format {
            DrawingFormat::Dwg => (
                canonical_optional_handle(layer.xref_block_record_handle)?,
                xref_record.map(|record| record.flags.is_xref_overlay),
                canonical_optional_handle(layer.material)?,
                canonical_optional_handle(layer.plotstyle_handle)?,
            ),
            DrawingFormat::Dxf => (None, None, None, None),
        };

    Ok(LayerRecord {
        handle: canonical_handle(layer.handle())?,
        name: layer.name.clone(),
        color_index: fields.color_index,
        line_type: fields.line_type,
        line_weight: fields.line_weight,
        frozen: fields.frozen,
        locked: fields.locked,
        off: fields.off,
        is_plottable: fields.is_plottable,
        xref_dependent: fields.xref_dependent,
        xref_block_record_handle,
        xref_name,
        xref_path: xref_record
            .and_then(|record| (!record.xref_path.is_empty()).then(|| record.xref_path.clone())),
        xref_is_overlay,
        material_handle,
        plotstyle_handle,
        is_current: is_current_layer(document, layer),
    })
}

fn resolve_layer_index(
    document: &CadDocument,
    selector: &LayerSelector,
) -> Result<usize, LayerReadError> {
    if selector.handle.is_none() && selector.name.is_none() {
        return Err(LayerReadError::new(
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
            document
                .layers
                .iter()
                .enumerate()
                .find(|(_, layer)| layer.handle() == wanted)
                .map(|(index, _)| index)
        });
    let by_name = selector.name.as_deref().and_then(|wanted| {
        document
            .layers
            .iter()
            .enumerate()
            .find(|(_, layer)| name_eq(layer.name(), wanted))
            .map(|(index, _)| index)
    });

    if selector.handle.is_some() && selector.name.is_some() {
        match (by_handle, by_name) {
            (Some(handle_index), Some(name_index)) if handle_index == name_index => {}
            _ => {
                return Err(LayerReadError::new(
                    "layer_identity_mismatch",
                    "layer handle and name did not both resolve to the same layer",
                ));
            }
        }
    } else if selector.handle.is_some() && by_handle.is_none() {
        return Err(LayerReadError::new(
            "layer_not_found",
            "layer handle not found",
        ));
    } else if selector.name.is_some() && by_name.is_none() {
        return Err(LayerReadError::new(
            "layer_not_found",
            "layer name not found",
        ));
    }

    let resolved = by_handle
        .or(by_name)
        .ok_or_else(|| LayerReadError::new("layer_not_found", "layer not found"))?;
    let layer = document.layers.iter().nth(resolved).ok_or_else(|| {
        LayerReadError::new("layer_not_found", "layer not found after resolution")
    })?;

    if let Some(expected) = &selector.expected_handle {
        let expected = canonical_handle(parse_handle(expected)?)?;
        let actual = canonical_handle(layer.handle())?;
        if expected != actual {
            return Err(LayerReadError::new(
                "expected_handle_mismatch",
                format!("expected handle {expected}, found {actual}"),
            ));
        }
    }

    if let Some(expected) = &selector.expected_name {
        if !name_eq(expected, layer.name()) {
            return Err(LayerReadError::new(
                "expected_name_mismatch",
                format!("expected name `{expected}`, found `{}`", layer.name()),
            ));
        }
    }

    Ok(resolved)
}

fn parsed_raw_table(snapshot: &DrawingSnapshot) -> Result<Option<RawLayerTable>, LayerReadError> {
    if snapshot.format() == DrawingFormat::Dwg {
        return Ok(None);
    }
    let bytes = snapshot.bytes();
    let text = std::str::from_utf8(bytes.as_ref()).map_err(|error| {
        LayerReadError::new(
            "drawing_unreadable",
            format!("failed to read DXF text for layer metadata: {error}"),
        )
    })?;
    parse_optional_raw_layer_table(text)
}

fn validate_raw_identities(
    table: Option<&RawLayerTable>,
    document: &CadDocument,
) -> Result<(), LayerReadError> {
    let Some(table) = table else {
        return Ok(());
    };
    for entry in &table.entries {
        let handle = entry
            .canonical_handle()
            .and_then(|value| u64::from_str_radix(&value, 16).ok())
            .map(Handle::new)
            .ok_or_else(|| {
                unsupported_layer_data(
                    entry.name(),
                    "missing or invalid handle prevents direct-field recovery",
                )
            })?;
        let layer = document
            .layers
            .iter()
            .find(|layer| layer.handle() == handle)
            .ok_or_else(|| {
                unsupported_layer_data(
                    entry.name(),
                    format!(
                        "decoded layer handle {:X} does not match the raw LAYER table",
                        handle.value()
                    ),
                )
            })?;
        if layer.name != entry.name().unwrap_or("0") {
            return Err(unsupported_layer_data(
                entry.name(),
                "application-group data changed decoded layer identity",
            ));
        }
    }
    Ok(())
}

fn raw_entry_for_layer<'a>(
    table: Option<&'a RawLayerTable>,
    layer: &acadrust::tables::Layer,
) -> Option<&'a RawLayerEntry> {
    let handle = canonical_handle(layer.handle()).ok()?;
    table?
        .entries
        .iter()
        .rev()
        .find(|entry| entry.canonical_handle().as_deref() == Some(handle.as_str()))
}

fn raw_has_non_indexed_color(
    table: Option<&RawLayerTable>,
    layer: &acadrust::tables::Layer,
) -> bool {
    let Ok(handle) = canonical_handle(layer.handle()) else {
        return false;
    };
    table.is_some_and(|table| {
        table.entries.iter().any(|entry| {
            entry.has_non_indexed_color()
                && entry.canonical_handle().as_deref() == Some(handle.as_str())
        })
    })
}

pub(super) fn list_layers(
    document: &CadDocument,
    snapshot: &DrawingSnapshot,
) -> Result<Vec<LayerRecord>, LayerReadError> {
    let table = parsed_raw_table(snapshot)?;
    validate_raw_identities(table.as_ref(), document)?;
    document
        .layers
        .iter()
        .map(|layer| {
            project_layer(
                document,
                layer,
                snapshot.format(),
                raw_entry_for_layer(table.as_ref(), layer),
                raw_has_non_indexed_color(table.as_ref(), layer),
            )
        })
        .collect()
}

pub(super) fn get_layer(
    document: &CadDocument,
    snapshot: &DrawingSnapshot,
    selector: &LayerSelector,
) -> Result<LayerRecord, LayerReadError> {
    let table = parsed_raw_table(snapshot)?;
    validate_raw_identities(table.as_ref(), document)?;
    let index = resolve_layer_index(document, selector)?;
    let layer = document.layers.iter().nth(index).ok_or_else(|| {
        LayerReadError::new("layer_not_found", "layer not found after resolution")
    })?;
    project_layer(
        document,
        layer,
        snapshot.format(),
        raw_entry_for_layer(table.as_ref(), layer),
        raw_has_non_indexed_color(table.as_ref(), layer),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawDxfPair {
    code: String,
    value: String,
}

impl RawDxfPair {
    fn is(&self, code: i32, value: &str) -> bool {
        self.code_number() == Some(code) && self.value.trim().eq_ignore_ascii_case(value)
    }

    fn code_number(&self) -> Option<i32> {
        self.code.trim().parse().ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawLayerEntry {
    pairs: Vec<RawDxfPair>,
}

impl RawLayerEntry {
    fn direct_pair_indices(&self) -> Vec<usize> {
        let mut depth = 0usize;
        let mut result = Vec::new();
        for (index, pair) in self.pairs.iter().enumerate() {
            let is_open = pair.code_number() == Some(102) && pair.value.trim().starts_with('{');
            let is_close = pair.code_number() == Some(102) && pair.value.trim() == "}";
            if depth == 0 && !is_open && !is_close {
                result.push(index);
            }
            if is_open {
                depth = depth.saturating_add(1);
            } else if is_close {
                depth = depth.saturating_sub(1);
            }
        }
        result
    }

    fn direct_pair(&self, code: i32) -> Option<&RawDxfPair> {
        self.direct_pair_indices()
            .into_iter()
            .map(|index| &self.pairs[index])
            .find(|pair| pair.code_number() == Some(code))
    }

    fn value(&self, code: i32) -> Option<&str> {
        self.direct_pair(code).map(|pair| pair.value.as_str())
    }

    fn name(&self) -> Option<&str> {
        self.value(2)
    }

    fn canonical_handle(&self) -> Option<String> {
        self.value(5).and_then(canonical_raw_handle)
    }

    fn has_non_indexed_color(&self) -> bool {
        self.direct_pair(420).is_some() || self.direct_pair(430).is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawLayerTable {
    header: Vec<RawDxfPair>,
    entries: Vec<RawLayerEntry>,
}

fn canonical_raw_handle(value: &str) -> Option<String> {
    let value = value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or(value.trim());
    let handle = u64::from_str_radix(value, 16).ok()?;
    (handle != 0).then(|| format!("{handle:X}"))
}

fn parse_raw_dxf_pairs(text: &str) -> Result<Vec<RawDxfPair>, String> {
    let lines = text
        .split_terminator('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect::<Vec<_>>();
    if lines.len() % 2 != 0 {
        return Err("DXF text contains an unmatched group-code line".to_string());
    }

    lines
        .chunks_exact(2)
        .map(|lines| {
            let code = lines[0].trim();
            code.parse::<i32>()
                .map_err(|_| format!("invalid DXF group code `{code}`"))?;
            Ok(RawDxfPair {
                code: lines[0].to_string(),
                value: lines[1].to_string(),
            })
        })
        .collect()
}

fn validate_application_groups(pairs: &[RawDxfPair]) -> Result<(), String> {
    let mut depth = 0usize;
    for pair in pairs {
        if pair.code_number() != Some(102) {
            continue;
        }
        if pair.value.trim().starts_with('{') {
            depth = depth
                .checked_add(1)
                .ok_or_else(|| "application-group nesting overflow".to_string())?;
        } else if pair.value.trim() == "}" {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| "unmatched application-group terminator".to_string())?;
        }
    }
    if depth == 0 {
        Ok(())
    } else {
        Err("unterminated application group".to_string())
    }
}

fn validate_direct_layer_singletons(table: &RawLayerTable) -> Result<(), LayerReadError> {
    const SINGLETON_CODES: [i32; 9] = [2, 5, 6, 62, 70, 290, 370, 420, 430];

    let header = RawLayerEntry {
        pairs: table.header.clone(),
    };
    for code in [2, 70] {
        let count = header
            .direct_pair_indices()
            .into_iter()
            .filter(|index| header.pairs[*index].code_number() == Some(code))
            .count();
        if count != 1 {
            return Err(unsupported_layer_data(
                Some("<LAYER table header>"),
                format!("expected exactly one direct group code {code}, found {count}"),
            ));
        }
    }
    if !header
        .value(2)
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("LAYER"))
    {
        return Err(unsupported_layer_data(
            Some("<LAYER table header>"),
            "direct group code 2 does not identify the LAYER table",
        ));
    }
    let declared_count = pair_integer(&header, 70, 0)?;
    let actual_count = i32::try_from(table.entries.len()).map_err(|_| {
        unsupported_layer_data(
            Some("<LAYER table header>"),
            "layer count exceeds the supported integer domain",
        )
    })?;
    if declared_count != actual_count {
        return Err(unsupported_layer_data(
            Some("<LAYER table header>"),
            format!(
                "declared group code 70 count {declared_count} does not match {actual_count} LAYER records"
            ),
        ));
    }
    let header_handles = header
        .direct_pair_indices()
        .into_iter()
        .filter(|index| header.pairs[*index].code_number() == Some(5))
        .count();
    if header_handles > 1 {
        return Err(unsupported_layer_data(
            Some("<LAYER table header>"),
            format!("ambiguous repeated direct group code 5 ({header_handles} occurrences)"),
        ));
    }

    for entry in &table.entries {
        for code in [2, 5] {
            let count = entry
                .direct_pair_indices()
                .into_iter()
                .filter(|index| entry.pairs[*index].code_number() == Some(code))
                .count();
            if count != 1 {
                return Err(unsupported_layer_data(
                    entry.name(),
                    format!("expected exactly one direct group code {code}, found {count}"),
                ));
            }
        }

        let mut seen = BTreeSet::new();
        for index in entry.direct_pair_indices() {
            let Some(code) = entry.pairs[index].code_number() else {
                continue;
            };
            if SINGLETON_CODES.contains(&code) && !seen.insert(code) {
                return Err(unsupported_layer_data(
                    entry.name(),
                    format!("ambiguous repeated direct group code {code}"),
                ));
            }
        }

        if entry.value(70).is_some() {
            let flags = pair_integer(entry, 70, 0)?;
            if !(0..=i16::MAX as i32).contains(&flags) {
                return Err(unsupported_layer_data(
                    entry.name(),
                    format!("group code 70 value {flags} is outside the layer-flag domain"),
                ));
            }
        }
        if entry.value(62).is_some() {
            let color = pair_integer(entry, 62, 7)?;
            if !(-255..=255).contains(&color) {
                return Err(unsupported_layer_data(
                    entry.name(),
                    format!(
                        "group code 62 value {color} is outside the round-trip-safe -255..=255 domain"
                    ),
                ));
            }
        }
        if entry.value(370).is_some() {
            let line_weight = pair_integer(entry, 370, -3)?;
            if i16::try_from(line_weight).is_err() {
                return Err(unsupported_layer_data(
                    entry.name(),
                    format!("group code 370 value {line_weight} is outside the i16 domain"),
                ));
            }
        }
        if entry.value(290).is_some() {
            let plot = pair_integer(entry, 290, 1)?;
            if !matches!(plot, 0 | 1) {
                return Err(unsupported_layer_data(
                    entry.name(),
                    format!("group code 290 value {plot} is not the required boolean 0 or 1"),
                ));
            }
        }
    }
    Ok(())
}

fn try_parse_raw_layer_table(pairs: &[RawDxfPair]) -> Result<Option<RawLayerTable>, String> {
    let mut found = None;
    let mut index = 0usize;
    while index < pairs.len() {
        if !pairs[index].is(0, "TABLE") {
            index += 1;
            continue;
        }

        let start = index;
        let endtab = (start + 1..pairs.len())
            .find(|candidate| pairs[*candidate].is(0, "ENDTAB"))
            .ok_or_else(|| "unterminated DXF TABLE section".to_string())?;
        let first_record = (start + 1..endtab)
            .find(|candidate| pairs[*candidate].code_number() == Some(0))
            .unwrap_or(endtab);
        let is_layer_table = pairs[start + 1..first_record]
            .iter()
            .any(|pair| pair.is(2, "LAYER"));

        if !is_layer_table {
            index = endtab + 1;
            continue;
        }
        if found.is_some() {
            return Err("DXF contains more than one LAYER table".to_string());
        }

        let mut entries = Vec::new();
        let mut cursor = first_record;
        while cursor < endtab {
            if !pairs[cursor].is(0, "LAYER") {
                return Err(format!(
                    "unexpected record `{}` inside LAYER table",
                    pairs[cursor].value
                ));
            }
            let entry_end = (cursor + 1..=endtab)
                .find(|candidate| pairs[*candidate].code_number() == Some(0))
                .unwrap_or(endtab);
            let entry_pairs = pairs[cursor..entry_end].to_vec();
            validate_application_groups(&entry_pairs)?;
            entries.push(RawLayerEntry { pairs: entry_pairs });
            cursor = entry_end;
        }

        let header = pairs[start..first_record].to_vec();
        validate_application_groups(&header)?;
        found = Some(RawLayerTable { header, entries });
        index = endtab + 1;
    }

    Ok(found)
}

fn parse_optional_raw_layer_table(text: &str) -> Result<Option<RawLayerTable>, LayerReadError> {
    let pairs = parse_raw_dxf_pairs(text).map_err(|message| {
        LayerReadError::new(
            "drawing_unreadable",
            format!("failed to parse DXF text for layer metadata: {message}"),
        )
    })?;
    let table = try_parse_raw_layer_table(&pairs).map_err(|message| {
        LayerReadError::new(
            "drawing_unreadable",
            format!("failed to parse DXF LAYER table: {message}"),
        )
    })?;
    if let Some(table) = &table {
        validate_direct_layer_singletons(table)?;
    }
    Ok(table)
}

fn pair_integer(entry: &RawLayerEntry, code: i32, default: i32) -> Result<i32, LayerReadError> {
    entry
        .value(code)
        .map(|value| {
            value.trim().parse::<i32>().map_err(|_| {
                unsupported_layer_data(
                    entry.name(),
                    format!("invalid value `{}` for group code {code}", value.trim()),
                )
            })
        })
        .unwrap_or(Ok(default))
}

fn unsupported_layer_data(layer_name: Option<&str>, message: impl Into<String>) -> LayerReadError {
    let layer = layer_name.unwrap_or("<unknown>");
    LayerReadError::new(
        "unsupported_layer_data",
        format!(
            "DXF layer `{layer}` cannot be interpreted faithfully: {}",
            message.into()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::tables::Layer;

    fn dxf_snapshot_with_layer(
        handle: &str,
        name: &str,
        direct_pairs: &[(&str, &str)],
    ) -> DrawingSnapshot {
        let mut text = format!(
            "0\nSECTION\n2\nTABLES\n0\nTABLE\n2\nLAYER\n70\n1\n0\nLAYER\n5\n{handle}\n2\n{name}\n"
        );
        for (code, value) in direct_pairs {
            text.push_str(code);
            text.push('\n');
            text.push_str(value);
            text.push('\n');
        }
        text.push_str("0\nENDTAB\n0\nENDSEC\n0\nEOF\n");
        DrawingSnapshot::new(DrawingFormat::Dxf, text.into_bytes())
    }

    #[test]
    fn dxf_projection_uses_direct_fields_from_the_immutable_snapshot() {
        let mut document = CadDocument::new();
        let handle = document.layers.get("0").unwrap().handle();
        document.layers.get_mut("0").unwrap().color = Color::from_index(7);
        let snapshot = dxf_snapshot_with_layer(
            &format!("{:X}", handle.value()),
            "0",
            &[
                ("70", "5"),
                ("62", "-3"),
                ("6", "DASHED"),
                ("290", "0"),
                ("370", "25"),
                ("420", "16711680"),
            ],
        );

        let record = get_layer(
            &document,
            &snapshot,
            &LayerSelector {
                name: Some("0".to_string()),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(record.color_index, None);
        assert_eq!(record.line_type, "DASHED");
        assert_eq!(
            record.line_weight,
            LayerLineWeight::Value { hundredths_mm: 25 }
        );
        assert!(record.frozen);
        assert!(record.locked);
        assert!(record.off);
        assert!(!record.is_plottable);
    }

    #[test]
    fn dxf_raw_identity_must_match_the_decoded_backend_layer() {
        let mut document = CadDocument::new();
        let mut layer = Layer::new("ANNO");
        layer.set_handle(Handle::new(0xAB));
        document.layers.add(layer).unwrap();
        let snapshot = dxf_snapshot_with_layer("AB", "WRONG", &[]);

        let error = list_layers(&document, &snapshot).unwrap_err();

        assert_eq!(error.code(), "unsupported_layer_data");
        assert!(error
            .message()
            .contains("application-group data changed decoded layer identity"));
    }

    #[test]
    fn selector_contract_preserves_identity_and_stale_state_errors() {
        let document = CadDocument::new();
        let snapshot = DrawingSnapshot::new(DrawingFormat::Dwg, Vec::<u8>::new());
        let layer = document.layers.get("0").unwrap();

        let error = get_layer(
            &document,
            &snapshot,
            &LayerSelector {
                handle: Some(format!("{:X}", layer.handle().value())),
                name: Some("WRONG".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "layer_identity_mismatch");
    }
}
