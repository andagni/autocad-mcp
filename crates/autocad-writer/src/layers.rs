use acadrust::entities::EntityType;
use acadrust::tables::TableEntry;
use acadrust::types::{Handle, LineWeight};
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

fn current_layer_handle(document: &CadDocument) -> Option<Handle> {
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

fn is_xref_dependent(layer: &acadrust::tables::Layer) -> bool {
    layer.flags.xref_dependent || layer.name.contains('|')
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

fn rewrite_entity_layers(document: &mut CadDocument, old_name: &str, new_name: &str) {
    for entity in document.entities_mut() {
        if name_eq(&entity.common().layer, old_name) {
            entity.common_mut().layer = new_name.to_string();
        }
        match entity {
            EntityType::Insert(insert) => {
                for attribute in &mut insert.attributes {
                    if name_eq(&attribute.common.layer, old_name) {
                        attribute.common.layer = new_name.to_string();
                    }
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
                    if name_eq(&vertex.common.layer, old_name) {
                        vertex.common.layer = new_name.to_string();
                    }
                }
            }
            EntityType::PolyfaceMesh(mesh) => {
                for vertex in &mut mesh.vertices {
                    if name_eq(&vertex.common.layer, old_name) {
                        vertex.common.layer = new_name.to_string();
                    }
                }
                for face in &mut mesh.faces {
                    if name_eq(&face.common.layer, old_name) {
                        face.common.layer = new_name.to_string();
                    }
                }
            }
            _ => {}
        }
    }
}

fn entity_child_uses_layer(entity: &EntityType, name: &str) -> bool {
    match entity {
        EntityType::Insert(insert) => insert
            .attributes
            .iter()
            .any(|attribute| name_eq(&attribute.common.layer, name)),
        EntityType::Polyline3D(polyline) => polyline
            .vertices
            .iter()
            .any(|vertex| name_eq(&vertex.layer, name)),
        EntityType::PolygonMesh(mesh) => mesh
            .vertices
            .iter()
            .any(|vertex| name_eq(&vertex.common.layer, name)),
        EntityType::PolyfaceMesh(mesh) => {
            mesh.vertices
                .iter()
                .any(|vertex| name_eq(&vertex.common.layer, name))
                || mesh
                    .faces
                    .iter()
                    .any(|face| name_eq(&face.common.layer, name))
        }
        _ => false,
    }
}

fn has_opaque_layer_references(document: &CadDocument) -> bool {
    document
        .entities()
        .any(|entity| matches!(entity, EntityType::Unknown(_)))
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

fn layer_is_referenced(document: &CadDocument, name: &str) -> bool {
    document.entities().any(|entity| {
        name_eq(&entity.common().layer, name) || entity_child_uses_layer(entity, name)
    })
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
    if layer_is_referenced(document, &name) {
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
