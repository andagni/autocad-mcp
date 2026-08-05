use std::collections::BTreeSet;

use acadrust::entities::{EntityCommon, EntityType};
use acadrust::objects::ObjectType;
use acadrust::tables::TableEntry;
use acadrust::types::{DxfVersion, Handle, LineWeight};
use acadrust::xdata::{ExtendedData, XDataValue};
use acadrust::CadDocument;
use autocad_reader::DrawingReadSession;

use super::contract::{
    CreateLayer, DeleteLayer, DeletedLayer, LayerLineWeight, LayerMutation, LayerProperties,
    LayerRecord, LayerSelector, RenameLayer, UpdateLayer,
};
use super::{DrawingFormat, WriteError};

const STANDARD_LINE_WEIGHTS: &[i16] = &[
    0, 5, 9, 13, 15, 18, 20, 25, 30, 35, 40, 50, 53, 60, 70, 80, 90, 100, 106, 120, 140, 158, 200,
    211,
];

fn name_key(name: &str) -> String {
    name.to_uppercase()
}

fn name_eq(left: &str, right: &str) -> bool {
    name_key(left) == name_key(right)
}

fn canonical_handle(handle: Handle) -> Result<String, WriteError> {
    if handle.is_null() {
        return Err(WriteError::unsupported_source(
            "invalid_layer_handle",
            "layer handle 0 cannot cross the writer boundary",
        ));
    }
    Ok(format!("{:X}", handle.value()))
}

fn optional_handle(handle: Handle) -> Result<Option<String>, WriteError> {
    if handle.is_null() {
        Ok(None)
    } else {
        canonical_handle(handle).map(Some)
    }
}

fn parse_handle(input: &str) -> Result<Handle, WriteError> {
    let trimmed = input.trim();
    let hexadecimal = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let value = u64::from_str_radix(hexadecimal, 16).map_err(|_| {
        WriteError::invalid_request(
            "invalid_layer_handle",
            format!("invalid layer handle `{input}`"),
        )
    })?;
    if value == 0 {
        return Err(WriteError::invalid_request(
            "invalid_layer_handle",
            "layer handle 0 is invalid",
        ));
    }
    Ok(Handle::new(value))
}

pub(super) fn current_layer_handle(document: &CadDocument) -> Option<Handle> {
    let handle = document.header.current_layer_handle;
    if !handle.is_null() && document.layers.iter().any(|layer| layer.handle() == handle) {
        return Some(handle);
    }
    document
        .layers
        .iter()
        .find(|layer| name_eq(layer.name(), &document.header.current_layer_name))
        .map(TableEntry::handle)
}

fn is_current(document: &CadDocument, layer: &acadrust::tables::Layer) -> bool {
    current_layer_handle(document) == Some(layer.handle())
}

pub(super) fn is_xref_dependent(layer: &acadrust::tables::Layer) -> bool {
    layer.flags.xref_dependent
        || !layer.xref_block_record_handle.is_null()
        || layer.name.contains('|')
}

fn line_weight_record(weight: LineWeight) -> LayerLineWeight {
    match weight {
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

fn writable_line_weight(weight: &LayerLineWeight) -> Result<LineWeight, WriteError> {
    match weight {
        LayerLineWeight::ByLayer => Ok(LineWeight::ByLayer),
        LayerLineWeight::ByBlock => Ok(LineWeight::ByBlock),
        LayerLineWeight::Default => Ok(LineWeight::Default),
        LayerLineWeight::Value { hundredths_mm }
            if STANDARD_LINE_WEIGHTS.contains(hundredths_mm) =>
        {
            Ok(LineWeight::Value(*hundredths_mm))
        }
        LayerLineWeight::Value { hundredths_mm } => Err(WriteError::invalid_request(
            "invalid_line_weight",
            format!("{hundredths_mm} is not a standard AutoCAD lineweight"),
        )),
        LayerLineWeight::Raw { .. } => Err(WriteError::invalid_request(
            "invalid_line_weight",
            "raw lineweight values are read-only",
        )),
    }
}

fn project(
    document: &CadDocument,
    layer: &acadrust::tables::Layer,
    format: DrawingFormat,
) -> Result<LayerRecord, WriteError> {
    let xref_name = is_xref_dependent(layer)
        .then(|| layer.name.split_once('|').map(|(name, _)| name.to_string()))
        .flatten();
    let xref_record = document.block_records.iter().find(|record| {
        (format == DrawingFormat::Dwg
            && !layer.xref_block_record_handle.is_null()
            && record.handle() == layer.xref_block_record_handle)
            || xref_name
                .as_deref()
                .is_some_and(|name| name_eq(record.name(), name))
    });

    Ok(LayerRecord {
        handle: canonical_handle(layer.handle())?,
        name: layer.name.clone(),
        color_index: layer
            .color
            .index()
            .and_then(|index| (1..=255).contains(&index).then_some(index)),
        line_type: layer.line_type.clone(),
        line_weight: line_weight_record(layer.line_weight),
        frozen: layer.flags.frozen,
        locked: layer.flags.locked,
        off: layer.flags.off,
        is_plottable: layer.is_plottable,
        xref_dependent: is_xref_dependent(layer),
        xref_block_record_handle: if format == DrawingFormat::Dwg {
            optional_handle(layer.xref_block_record_handle)?
        } else {
            None
        },
        xref_name,
        xref_path: xref_record
            .filter(|record| !record.xref_path.is_empty())
            .map(|record| record.xref_path.clone()),
        xref_is_overlay: (format == DrawingFormat::Dwg)
            .then(|| xref_record.map(|record| record.flags.is_xref_overlay))
            .flatten(),
        material_handle: if format == DrawingFormat::Dwg {
            optional_handle(layer.material)?
        } else {
            None
        },
        plotstyle_handle: if format == DrawingFormat::Dwg {
            optional_handle(layer.plotstyle_handle)?
        } else {
            None
        },
        is_current: is_current(document, layer),
    })
}

fn resolve_index(document: &CadDocument, selector: &LayerSelector) -> Result<usize, WriteError> {
    if selector.handle.is_none() && selector.name.is_none() {
        return Err(WriteError::target_not_found(
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
                .position(|layer| layer.handle() == wanted)
        });
    let by_name = selector.name.as_deref().and_then(|wanted| {
        document
            .layers
            .iter()
            .position(|layer| name_eq(layer.name(), wanted))
    });

    if selector.handle.is_some()
        && selector.name.is_some()
        && (by_handle.is_none() || by_handle != by_name)
    {
        return Err(WriteError::ambiguous_target(
            "layer_identity_mismatch",
            "layer handle and name do not resolve to the same layer",
        ));
    }
    let index = by_handle.or(by_name).ok_or_else(|| {
        WriteError::target_not_found("layer_not_found", "selected layer was not found")
    })?;
    let layer = document.layers.iter().nth(index).ok_or_else(|| {
        WriteError::target_not_found("layer_not_found", "selected layer disappeared")
    })?;

    if let Some(expected) = &selector.expected_handle {
        let expected = canonical_handle(parse_handle(expected)?)?;
        if expected != canonical_handle(layer.handle())? {
            return Err(WriteError::invalid_request(
                "expected_handle_mismatch",
                "selected layer handle does not match expected_handle",
            ));
        }
    }
    if selector
        .expected_name
        .as_deref()
        .is_some_and(|expected| !name_eq(expected, layer.name()))
    {
        return Err(WriteError::invalid_request(
            "expected_name_mismatch",
            "selected layer name does not match expected_name",
        ));
    }
    Ok(index)
}

fn validate_name(name: &str) -> Result<(), WriteError> {
    const RESERVED: &[char] = &['<', '>', '/', '\\', '"', ':', ';', '?', '*', '|', '=', '`'];
    if name.is_empty()
        || name.trim() != name
        || name.chars().count() > 255
        || name
            .chars()
            .any(|character| character.is_ascii_control() || RESERVED.contains(&character))
        || name_eq(name, "0")
        || name_eq(name, "DEFPOINTS")
    {
        return Err(WriteError::invalid_request(
            "invalid_layer_name",
            format!("invalid or reserved layer name `{name}`"),
        ));
    }
    Ok(())
}

fn validate_properties(
    document: &CadDocument,
    properties: &LayerProperties,
) -> Result<(), WriteError> {
    if properties
        .color_index
        .is_some_and(|index| !(1..=255).contains(&index))
    {
        return Err(WriteError::invalid_request(
            "invalid_layer_property",
            "color_index must be from 1 to 255",
        ));
    }
    if let Some(line_type) = &properties.line_type {
        if line_type.is_empty()
            || line_type.trim() != line_type
            || !document
                .line_types
                .iter()
                .any(|candidate| name_eq(candidate.name(), line_type))
        {
            return Err(WriteError::invalid_request(
                "line_type_not_found",
                format!("linetype `{line_type}` was not found"),
            ));
        }
    }
    if let Some(line_weight) = &properties.line_weight {
        let _ = writable_line_weight(line_weight)?;
    }
    Ok(())
}

fn apply_properties(
    layer: &mut acadrust::tables::Layer,
    properties: &LayerProperties,
) -> Result<(), WriteError> {
    if let Some(index) = properties.color_index {
        layer.color = acadrust::types::Color::from_index(index as i16);
    }
    if let Some(line_type) = &properties.line_type {
        layer.line_type = line_type.clone();
    }
    if let Some(line_weight) = &properties.line_weight {
        layer.line_weight = writable_line_weight(line_weight)?;
    }
    if let Some(frozen) = properties.frozen {
        layer.flags.frozen = frozen;
    }
    if let Some(locked) = properties.locked {
        layer.flags.locked = locked;
    }
    if let Some(off) = properties.off {
        layer.flags.off = off;
    }
    if let Some(is_plottable) = properties.is_plottable {
        layer.is_plottable = is_plottable;
    }
    Ok(())
}

pub(super) fn create(
    document: &mut CadDocument,
    format: DrawingFormat,
    request: &CreateLayer,
) -> Result<LayerMutation, WriteError> {
    validate_name(&request.name)?;
    if document
        .layers
        .iter()
        .any(|layer| name_eq(layer.name(), &request.name))
    {
        return Err(WriteError::invalid_request(
            "layer_name_collision",
            format!("layer `{}` already exists", request.name),
        ));
    }
    validate_properties(document, &request.properties)?;

    let mut layer = acadrust::tables::Layer::new(&request.name);
    layer.set_handle(document.allocate_handle());
    apply_properties(&mut layer, &request.properties)?;
    let handle = layer.handle();
    document.layers.add(layer).map_err(|detail| {
        WriteError::invalid_request("layer_name_collision", detail.to_string())
    })?;
    let layer = document
        .layers
        .iter()
        .find(|layer| layer.handle() == handle)
        .expect("new layer remains present");
    Ok(LayerMutation::Created {
        layer: project(document, layer, format)?,
    })
}

pub(super) fn update(
    document: &mut CadDocument,
    format: DrawingFormat,
    request: &UpdateLayer,
) -> Result<LayerMutation, WriteError> {
    if request.properties.is_empty() {
        return Err(WriteError::invalid_request(
            "empty_layer_update",
            "layer update properties are empty",
        ));
    }
    let index = resolve_index(document, &request.selector)?;
    let (name, handle, current, xref_dependent) = {
        let layer = document.layers.iter().nth(index).expect("resolved layer");
        (
            layer.name.clone(),
            layer.handle(),
            is_current(document, layer),
            is_xref_dependent(layer),
        )
    };
    if current && request.properties.frozen == Some(true) {
        return Err(WriteError::invalid_request(
            "cannot_freeze_current_layer",
            "cannot freeze the current layer",
        ));
    }
    if format == DrawingFormat::Dxf && xref_dependent && request.properties.line_type.is_some() {
        return Err(WriteError::invalid_request(
            "unsupported_layer_property",
            "DXF xref-dependent linetype overrides are not safely writable",
        ));
    }
    validate_properties(document, &request.properties)?;
    apply_properties(
        document
            .layers
            .get_mut(&name)
            .expect("resolved layer remains present"),
        &request.properties,
    )?;
    let layer = document
        .layers
        .iter()
        .find(|layer| layer.handle() == handle)
        .expect("updated layer remains present");
    Ok(LayerMutation::Updated {
        layer: project(document, layer, format)?,
    })
}

fn rewrite_xdata_layer_names(xdata: &mut ExtendedData, old_name: &str, new_name: &str) {
    let mut records = xdata.records().to_vec();
    let mut changed = false;
    for record in &mut records {
        for value in &mut record.values {
            if let XDataValue::LayerName(name) = value {
                if name_eq(name, old_name) {
                    *name = new_name.to_string();
                    changed = true;
                }
            }
        }
    }
    if changed {
        // ExtendedData::clear only clears structured records. Preserve any raw
        // DWG EED blobs, whose layer references are handle-based.
        xdata.clear();
        for record in records {
            xdata.add_record(record);
        }
    }
}

fn rewrite_common_layer(common: &mut EntityCommon, old_name: &str, new_name: &str) {
    if name_eq(&common.layer, old_name) {
        common.layer = new_name.to_string();
    }
    rewrite_xdata_layer_names(&mut common.extended_data, old_name, new_name);
}

pub(super) fn rewrite_entity_layer_references(
    entity: &mut EntityType,
    old_name: &str,
    new_name: &str,
) {
    rewrite_common_layer(entity.common_mut(), old_name, new_name);
    match entity {
        EntityType::Insert(insert) => {
            for attribute in &mut insert.attributes {
                rewrite_common_layer(&mut attribute.common, old_name, new_name);
            }
        }
        EntityType::Polyline3D(polyline) => {
            for vertex in &mut polyline.vertices {
                if name_eq(&vertex.layer, old_name) {
                    vertex.layer = new_name.to_string();
                }
            }
        }
        EntityType::PolygonMesh(mesh) => {
            for vertex in &mut mesh.vertices {
                rewrite_common_layer(&mut vertex.common, old_name, new_name);
            }
        }
        EntityType::PolyfaceMesh(mesh) => {
            for vertex in &mut mesh.vertices {
                rewrite_common_layer(&mut vertex.common, old_name, new_name);
            }
            for face in &mut mesh.faces {
                rewrite_common_layer(&mut face.common, old_name, new_name);
            }
        }
        _ => {}
    }
}

fn rewrite_entity_layers(document: &mut CadDocument, old_name: &str, new_name: &str) {
    for entity in document.entities_mut() {
        rewrite_entity_layer_references(entity, old_name, new_name);
    }
}

fn xdata_references_layer(xdata: &ExtendedData, name: &str, handle: Handle) -> bool {
    xdata.records().iter().any(|record| {
        record.values.iter().any(|value| match value {
            XDataValue::LayerName(candidate) => name_eq(candidate, name),
            XDataValue::Handle(candidate) => *candidate == handle,
            _ => false,
        })
    })
}

fn common_references_layer(common: &EntityCommon, name: &str, handle: Handle) -> bool {
    name_eq(&common.layer, name) || xdata_references_layer(&common.extended_data, name, handle)
}

fn common_has_raw_eed(common: &EntityCommon) -> bool {
    !common.extended_data.raw_dwg_eed.is_empty()
}

pub(super) fn entity_references_layer(entity: &EntityType, name: &str, handle: Handle) -> bool {
    if common_references_layer(entity.common(), name, handle) {
        return true;
    }
    match entity {
        EntityType::Insert(insert) => insert
            .attributes
            .iter()
            .any(|attribute| common_references_layer(&attribute.common, name, handle)),
        EntityType::Polyline3D(polyline) => polyline
            .vertices
            .iter()
            .any(|vertex| name_eq(&vertex.layer, name)),
        EntityType::PolygonMesh(mesh) => mesh
            .vertices
            .iter()
            .any(|vertex| common_references_layer(&vertex.common, name, handle)),
        EntityType::PolyfaceMesh(mesh) => {
            mesh.vertices
                .iter()
                .any(|vertex| common_references_layer(&vertex.common, name, handle))
                || mesh
                    .faces
                    .iter()
                    .any(|face| common_references_layer(&face.common, name, handle))
        }
        _ => false,
    }
}

pub(super) fn entity_has_opaque_layer_references(entity: &EntityType) -> bool {
    if common_has_raw_eed(entity.common()) {
        return true;
    }
    match entity {
        EntityType::Unknown(_) => true,
        EntityType::Surface(surface) => surface.raw_dwg_data.is_some(),
        EntityType::MultiLeader(multileader) => multileader.raw_dwg_data.is_some(),
        EntityType::Insert(insert) => insert
            .attributes
            .iter()
            .any(|attribute| common_has_raw_eed(&attribute.common)),
        EntityType::PolygonMesh(mesh) => mesh
            .vertices
            .iter()
            .any(|vertex| common_has_raw_eed(&vertex.common)),
        EntityType::PolyfaceMesh(mesh) => {
            mesh.vertices
                .iter()
                .any(|vertex| common_has_raw_eed(&vertex.common))
                || mesh
                    .faces
                    .iter()
                    .any(|face| common_has_raw_eed(&face.common))
        }
        _ => false,
    }
}

pub(super) fn has_opaque_layer_references(document: &CadDocument) -> bool {
    let has_any_version_locked_data = document.dwg_source_version.is_some_and(|source| {
        let other_family = if source >= DxfVersion::AC1021 {
            DxfVersion::AC1018
        } else {
            DxfVersion::AC1021
        };
        document.has_version_locked_data(other_family)
    });
    has_any_version_locked_data
        || document.entities().any(entity_has_opaque_layer_references)
        || document.objects.values().any(|object| match object {
            ObjectType::Unknown { .. } => true,
            ObjectType::XRecord(record) => !record.raw_data.is_empty(),
            _ => false,
        })
}

fn advance(offset: usize, count: usize, len: usize) -> Option<usize> {
    let end = offset.checked_add(count)?;
    (end <= len).then_some(end)
}

/// Decodes the handle-bearing sub-records (DXF group 1003 "layer table
/// reference" and 1005 "entity handle reference") out of one raw DWG EED
/// per-application data blob, per the Open Design Alliance `.dwg` format
/// spec §28 "Extended Entity Data": a flat sequence of `[1-byte type tag]
/// [type-specific value]` records with no bit-packing, running to the end
/// of the blob with no record count.
///
/// Returns `None` — "cannot be trusted" — the moment anything doesn't add
/// up: an unrecognized tag, or a declared length that runs past the end of
/// the blob, or (at the very end) leftover bytes that don't form another
/// record. The caller must then treat this blob as fully opaque, exactly as
/// before this function existed, rather than risk acting on a decode that
/// silently went out of sync partway through.
///
/// The two handle-bearing tags (3, 5) store an 8-byte raw value that the
/// spec only describes as "read it as hex, as usual for handles" — it does
/// not pin down byte order, and no other 8-byte-raw-handle field in this
/// format was found to cross-check against. Both byte-order readings are
/// returned for every such sub-record, so a caller checking "does this
/// blob reference handle X" can only become *more* likely to (correctly or
/// over-cautiously) say yes; it can never become less likely to catch a
/// real reference because of an endianness guess.
fn parse_eed_sub_record_handles(data: &[u8], unicode_strings: bool) -> Option<Vec<Handle>> {
    let mut handles = Vec::new();
    let mut i = 0usize;
    let len = data.len();
    while i < len {
        let tag = data[i];
        i = advance(i, 1, len)?;
        match tag {
            // String (1000): R13-R2004 = 1-byte length + 2-byte codepage +
            // N bytes; R2007+ = 2-byte length + N UTF-16 code units.
            0 => {
                if unicode_strings {
                    let low = *data.get(i)? as u16;
                    let high = *data.get(i + 1)? as u16;
                    let n = low | (high << 8);
                    i = advance(i, 2, len)?;
                    i = advance(i, (n as usize) * 2, len)?;
                } else {
                    let n = *data.get(i)? as usize;
                    i = advance(i, 1, len)?;
                    i = advance(i, 2, len)?; // codepage (RS), value unused
                    i = advance(i, n, len)?;
                }
            }
            // Control string '{' / '}' (1002): 1 byte.
            2 => i = advance(i, 1, len)?,
            // Layer handle (1003) / entity handle (1005): 8 raw bytes.
            3 | 5 => {
                let raw: [u8; 8] = data.get(i..i + 8)?.try_into().ok()?;
                handles.push(Handle::from(u64::from_be_bytes(raw)));
                handles.push(Handle::from(u64::from_le_bytes(raw)));
                i = advance(i, 8, len)?;
            }
            // Binary chunk (1004): 1-byte length + N bytes.
            4 => {
                let n = *data.get(i)? as usize;
                i = advance(i, 1, len)?;
                i = advance(i, n, len)?;
            }
            // Point (1010-1013): 3 doubles (XYZ), 24 bytes.
            10..=13 => i = advance(i, 24, len)?,
            // Real (1040-1042): 8 bytes.
            40..=42 => i = advance(i, 8, len)?,
            // Short int (1070): 2 bytes.
            70 => i = advance(i, 2, len)?,
            // Long int (1071): 4 bytes.
            71 => i = advance(i, 4, len)?,
            // Tag 1 is documented as never occurring, and anything else is
            // unspecified by the spec we verified against — fail closed.
            _ => return None,
        }
    }
    Some(handles)
}

/// The handles opaque (DWG-raw) EED data references, or `None` if any part
/// of the document's opaque data cannot be decoded with confidence — in
/// which case the caller must fall back to refusing unconditionally.
///
/// Scope, deliberately: this only proves the *structural* concern (would a
/// deletion leave a dangling handle reference behind, corrupting the
/// document's handle graph). It does not, and cannot, prove the *rename*
/// concern (an opaque XRECORD or EED string sub-record holding the XREF's
/// old name as literal text, which a rename cannot detect or fix) — that
/// risk is not a byte-format question, it's arbitrary third-party
/// application semantics no DWG-writing tool can fully see into, including
/// real AutoCAD itself. Callers concerned with renames must keep using
/// [`has_opaque_layer_references`] unscoped.
///
/// `XRecord.raw_data` and any `Unknown`-typed entity/object remain
/// unconditionally opaque here (not attempted): unlike EED, XRECORD's own
/// handle-typed group codes (320-369, 480-481) are documented as being
/// resolved from the object's separate handle stream, not stored inline in
/// the databytes this crate has access to — so there is no length to trust
/// for them, and guessing one risks silently desynchronizing every
/// subsequent record in the same XRECORD, which is the outcome this
/// function exists to avoid. This is a disclosed, structural gap, not a
/// relaxation.
///
/// `document.has_version_locked_data` is deliberately not consulted here:
/// it tests whether the document would be lossy if written to a *different*
/// DWG version family, which XREF mutation never does (routes always write
/// back the source's own family), and its only signal beyond what this
/// function already inspects directly (per-entity raw EED, covered above)
/// is acadrust's private `eed_by_handle` table-entry EED cache, which has no
/// public accessor — calling it would just re-introduce an unscoped, whole-
/// document trigger for data already accounted for precisely.
fn opaque_referenced_handles(document: &CadDocument) -> Option<BTreeSet<Handle>> {
    let unicode_strings = document
        .dwg_source_version
        .is_some_and(|version| version >= DxfVersion::AC1021);
    let mut handles = BTreeSet::new();

    let absorb_common = |common: &EntityCommon, handles: &mut BTreeSet<Handle>| -> Option<()> {
        for (_, data) in &common.extended_data.raw_dwg_eed {
            handles.extend(parse_eed_sub_record_handles(data, unicode_strings)?);
        }
        Some(())
    };

    for entity in document.entities() {
        if matches!(entity, EntityType::Unknown(_)) {
            return None;
        }
        if let EntityType::Surface(surface) = entity {
            if surface.raw_dwg_data.is_some() {
                return None;
            }
        }
        if let EntityType::MultiLeader(multileader) = entity {
            if multileader.raw_dwg_data.is_some() {
                return None;
            }
        }
        absorb_common(entity.common(), &mut handles)?;
        match entity {
            EntityType::Insert(insert) => {
                for attribute in &insert.attributes {
                    absorb_common(&attribute.common, &mut handles)?;
                }
            }
            EntityType::PolygonMesh(mesh) => {
                for vertex in &mesh.vertices {
                    absorb_common(&vertex.common, &mut handles)?;
                }
            }
            EntityType::PolyfaceMesh(mesh) => {
                for vertex in &mesh.vertices {
                    absorb_common(&vertex.common, &mut handles)?;
                }
                for face in &mesh.faces {
                    absorb_common(&face.common, &mut handles)?;
                }
            }
            _ => {}
        }
    }

    for object in document.objects.values() {
        match object {
            ObjectType::Unknown { .. } => return None,
            ObjectType::XRecord(record) if !record.raw_data.is_empty() => return None,
            _ => {}
        }
    }

    Some(handles)
}

/// Scoped replacement for [`has_opaque_layer_references`], usable only where
/// the concern is a dangling handle reference left behind by a deletion (see
/// [`opaque_referenced_handles`] for exactly what this does and does not
/// prove). Refuses if the document's opaque data cannot be decoded with
/// confidence, or if what was decoded references any handle in `protected`.
pub(super) fn has_opaque_references_to(
    document: &CadDocument,
    protected: &BTreeSet<Handle>,
) -> bool {
    match opaque_referenced_handles(document) {
        Some(handles) => handles.iter().any(|handle| protected.contains(handle)),
        None => true,
    }
}

pub(super) fn rename(
    document: &mut CadDocument,
    format: DrawingFormat,
    request: &RenameLayer,
) -> Result<LayerMutation, WriteError> {
    let index = resolve_index(document, &request.selector)?;
    let (old_name, handle, was_current, dependent) = {
        let layer = document.layers.iter().nth(index).expect("resolved layer");
        (
            layer.name.clone(),
            layer.handle(),
            is_current(document, layer),
            is_xref_dependent(layer),
        )
    };
    if name_eq(&old_name, "0") || name_eq(&old_name, "DEFPOINTS") {
        return Err(WriteError::invalid_request(
            "protected_layer",
            format!("cannot rename layer `{old_name}`"),
        ));
    }
    if dependent {
        return Err(WriteError::invalid_request(
            "xref_dependent_layer",
            "cannot rename an xref-dependent layer",
        ));
    }
    validate_name(&request.new_name)?;
    if document
        .layers
        .iter()
        .any(|layer| layer.handle() != handle && name_eq(layer.name(), &request.new_name))
    {
        return Err(WriteError::invalid_request(
            "layer_name_collision",
            format!("layer `{}` already exists", request.new_name),
        ));
    }
    if has_opaque_layer_references(document) {
        return Err(WriteError::invalid_request(
            "layer_has_unverified_references",
            "cannot rename a layer while opaque entity references are present",
        ));
    }

    let mut renamed = document
        .layers
        .remove(&old_name)
        .expect("resolved layer remains present");
    renamed.set_name(request.new_name.clone());
    document.layers.add(renamed).map_err(|detail| {
        WriteError::invalid_request("layer_name_collision", detail.to_string())
    })?;
    rewrite_entity_layers(document, &old_name, &request.new_name);
    if was_current {
        document.header.current_layer_name = request.new_name.clone();
        document.header.current_layer_handle = handle;
    }
    let layer = document
        .layers
        .iter()
        .find(|layer| layer.handle() == handle)
        .expect("renamed layer remains present");
    Ok(LayerMutation::Renamed {
        layer: project(document, layer, format)?,
    })
}

fn layer_is_referenced(document: &CadDocument, name: &str, handle: Handle) -> bool {
    document
        .entities()
        .any(|entity| entity_references_layer(entity, name, handle))
}

fn layer_has_unverified_references(document: &CadDocument, handle: Handle) -> bool {
    has_opaque_layer_references(document)
        || document.entities().any(
            |entity| matches!(entity, EntityType::Viewport(viewport) if viewport.frozen_layers.contains(&handle)),
        )
}

pub(super) fn delete(
    document: &mut CadDocument,
    request: &DeleteLayer,
) -> Result<LayerMutation, WriteError> {
    let index = resolve_index(document, &request.selector)?;
    let (name, handle, current, dependent) = {
        let layer = document.layers.iter().nth(index).expect("resolved layer");
        (
            layer.name.clone(),
            layer.handle(),
            is_current(document, layer),
            is_xref_dependent(layer),
        )
    };
    if name_eq(&name, "0") || name_eq(&name, "DEFPOINTS") {
        return Err(WriteError::invalid_request(
            "protected_layer",
            format!("cannot delete layer `{name}`"),
        ));
    }
    if dependent {
        return Err(WriteError::invalid_request(
            "xref_dependent_layer",
            "cannot delete an xref-dependent layer",
        ));
    }
    if current {
        return Err(WriteError::invalid_request(
            "cannot_delete_current_layer",
            "cannot delete the current layer",
        ));
    }
    if layer_is_referenced(document, &name, handle) {
        return Err(WriteError::invalid_request(
            "layer_has_content",
            format!("layer `{name}` has content"),
        ));
    }
    if layer_has_unverified_references(document, handle) {
        return Err(WriteError::invalid_request(
            "layer_has_unverified_references",
            format!("layer `{name}` has references that cannot be rewritten safely"),
        ));
    }
    document
        .layers
        .remove(&name)
        .expect("resolved layer remains present");
    Ok(LayerMutation::Deleted {
        layer: DeletedLayer {
            handle: canonical_handle(handle)?,
            name,
        },
    })
}

pub(super) fn verify_reader(
    reader: &DrawingReadSession,
    expected: &LayerMutation,
) -> Result<(), WriteError> {
    match expected {
        LayerMutation::Created { layer }
        | LayerMutation::Updated { layer }
        | LayerMutation::Renamed { layer } => {
            let actual = reader
                .get_layer(&LayerSelector {
                    handle: Some(layer.handle.clone()),
                    ..Default::default()
                })
                .map_err(|_| {
                    WriteError::verification(
                        "layer_postcondition_failed",
                        "independent reader projection did not contain the mutated layer",
                    )
                })?;
            if actual != *layer {
                return Err(WriteError::verification(
                    "layer_postcondition_failed",
                    "independent reader projection differs from the planned layer result",
                ));
            }
        }
        LayerMutation::Deleted { layer } => {
            let layers = reader.list_layers().map_err(|_| {
                WriteError::verification(
                    "candidate_layer_projection_failed",
                    "independent layer projection rejected the encoded candidate",
                )
            })?;
            if layers.iter().any(|candidate| {
                candidate.handle.eq_ignore_ascii_case(&layer.handle)
                    || name_eq(&candidate.name, &layer.name)
            }) {
                return Err(WriteError::verification(
                    "layer_postcondition_failed",
                    "independent reader projection still contains the deleted layer",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn verify(
    document: &CadDocument,
    format: DrawingFormat,
    expected: &LayerMutation,
) -> Result<(), WriteError> {
    match expected {
        LayerMutation::Created { layer }
        | LayerMutation::Updated { layer }
        | LayerMutation::Renamed { layer } => {
            let handle = parse_handle(&layer.handle)?;
            let actual = document
                .layers
                .iter()
                .find(|candidate| candidate.handle() == handle)
                .ok_or_else(|| {
                    WriteError::verification(
                        "layer_postcondition_failed",
                        "mutated layer is missing after candidate reopen",
                    )
                })?;
            if project(document, actual, format)? != *layer {
                return Err(WriteError::verification(
                    "layer_postcondition_failed",
                    "mutated layer differs after candidate reopen",
                ));
            }
        }
        LayerMutation::Deleted { layer } => {
            let handle = parse_handle(&layer.handle)?;
            if document
                .layers
                .iter()
                .any(|candidate| candidate.handle() == handle)
            {
                return Err(WriteError::verification(
                    "layer_postcondition_failed",
                    "deleted layer remains after candidate reopen",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::entities::{Line, Polyline3D, Vertex3DPolyline};
    use acadrust::tables::Layer;
    use acadrust::xdata::ExtendedDataRecord;

    #[test]
    fn rewrites_compound_child_and_structured_xdata_layer_references() {
        let mut polyline = Polyline3D::new();
        polyline.common.layer = "0".to_string();
        let mut vertex = Vertex3DPolyline::from_xyz(1.0, 2.0, 3.0);
        vertex.layer = "OLD".to_string();
        polyline.vertices.push(vertex);
        let mut record = ExtendedDataRecord::new("TEST");
        record.add_value(XDataValue::LayerName("OLD".to_string()));
        polyline.common.extended_data.add_record(record);

        let mut entity = EntityType::Polyline3D(polyline);
        rewrite_entity_layer_references(&mut entity, "OLD", "NEW");

        let EntityType::Polyline3D(polyline) = entity else {
            unreachable!();
        };
        assert_eq!(polyline.vertices[0].layer, "NEW");
        assert!(matches!(
            &polyline.common.extended_data.records()[0].values[0],
            XDataValue::LayerName(name) if name == "NEW"
        ));
    }

    #[test]
    fn delete_and_rename_fail_closed_for_xdata_references() {
        let mut document = CadDocument::new();
        let mut layer = Layer::new("TARGET");
        layer.set_handle(document.allocate_handle());
        document.layers.add(layer).unwrap();

        let mut line = Line::from_coords(0.0, 0.0, 0.0, 1.0, 1.0, 0.0);
        let mut record = ExtendedDataRecord::new("TEST");
        record.add_value(XDataValue::LayerName("TARGET".to_string()));
        line.common.extended_data.add_record(record);
        document.add_entity(EntityType::Line(line)).unwrap();

        let delete_error = delete(
            &mut document.clone(),
            &DeleteLayer {
                selector: LayerSelector {
                    name: Some("TARGET".to_string()),
                    ..Default::default()
                },
            },
        )
        .unwrap_err();
        assert_eq!(delete_error.code(), "layer_has_content");

        let line = document
            .entities_mut()
            .find_map(|entity| match entity {
                EntityType::Line(line) => Some(line),
                _ => None,
            })
            .unwrap();
        line.common
            .extended_data
            .raw_dwg_eed
            .push((1, vec![3, 0, 0, 0]));
        let rename_error = rename(
            &mut document,
            DrawingFormat::Dwg,
            &RenameLayer {
                selector: LayerSelector {
                    name: Some("TARGET".to_string()),
                    ..Default::default()
                },
                new_name: "RENAMED".to_string(),
            },
        )
        .unwrap_err();
        assert_eq!(rename_error.code(), "layer_has_unverified_references");
    }
}
