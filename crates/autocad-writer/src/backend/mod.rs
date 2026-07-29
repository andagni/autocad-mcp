use std::io::Cursor;

use acadrust::entities::EntityType;
use acadrust::notification::NotificationType;
use acadrust::{CadDocument, DxfReader, DxfWriter};

use super::{DrawingFormat, DrawingSnapshot, WriteError};

const BINARY_DXF_SENTINEL: &[u8] = b"AutoCAD Binary DXF\r\n\x1a\0";

pub(super) struct ParsedDrawing {
    pub(super) document: CadDocument,
}

pub(super) fn parse(snapshot: &DrawingSnapshot) -> Result<ParsedDrawing, WriteError> {
    if snapshot.format() == DrawingFormat::Dxf && snapshot.bytes().starts_with(BINARY_DXF_SENTINEL)
    {
        return Err(WriteError::unsupported_source(
            "binary_dxf_not_preserved",
            "binary DXF form cannot be preserved by the selected candidate writer",
        ));
    }
    if snapshot.format() == DrawingFormat::Dwg {
        return Err(WriteError::backend_capability(
            "dwg_candidate_preservation_unqualified",
            "DWG candidate generation is not admitted by the selected writer backend",
        )
        .with_internal_detail(
            "acadrust 0.4.1 has known silent DWG writer omissions; no source allowlist is certified",
        ));
    }
    ensure_ascii_dxf_source_bytes_admitted(snapshot.bytes().as_ref())?;

    // The reader boundary owns generic completeness policy. Parse again only
    // to obtain the private mutable backend model.
    autocad_reader::Reader::open_snapshot(snapshot.reader_snapshot())
        .map_err(WriteError::from_reader)?;

    let bytes = snapshot.bytes();
    let document = DxfReader::from_reader(Cursor::new(bytes))
        .and_then(DxfReader::read)
        .map_err(|error| WriteError::invalid_drawing(error.to_string()))?;

    let diagnostics = document
        .notifications
        .iter()
        .filter_map(|notification| {
            if notification.notification_type == NotificationType::Warning
                && is_proven_safe_telemetry_warning(&notification.message)
            {
                return None;
            }
            let severity = match notification.notification_type {
                NotificationType::NotImplemented => "not_implemented",
                NotificationType::NotSupported => "not_supported",
                NotificationType::Warning => "warning",
                NotificationType::Error => "error",
            };
            Some(format!("{severity}: {}", notification.message))
        })
        .collect::<Vec<_>>();
    if !diagnostics.is_empty() {
        return Err(WriteError::unsupported_source(
            "unsupported_source_diagnostics",
            "unclassified backend diagnostics make candidate generation unsafe",
        )
        .with_internal_detail(diagnostics.join("\n")));
    }
    ensure_candidate_source_admitted(&document)?;

    Ok(ParsedDrawing { document })
}

pub(super) fn ensure_ascii_dxf_source_bytes_admitted(bytes: &[u8]) -> Result<(), WriteError> {
    if ascii_dxf_contains_group_code(bytes, b"1001") {
        return Err(WriteError::backend_capability(
            "extended_data_not_preserved",
            "candidate generation is blocked when the source contains extended data",
        )
        .with_internal_detail(
            "acadrust 0.4.1 parses entity XDATA but its DXF writer does not emit it",
        ));
    }
    if ascii_dxf_contains_group_code(bytes, b"430") {
        return Err(WriteError::backend_capability(
            "color_book_not_preserved",
            "candidate generation is blocked when the source contains color-book data",
        )
        .with_internal_detail(
            "acadrust 0.4.1 consumes DXF group code 430 without retaining it in the entity model",
        ));
    }
    Ok(())
}

fn ascii_dxf_contains_group_code(bytes: &[u8], expected: &[u8]) -> bool {
    let mut lines = bytes.split(|byte| *byte == b'\n');
    while let Some(code_line) = lines.next() {
        if lines.next().is_none() {
            return false;
        }
        if code_line
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .eq(expected.iter().copied())
        {
            return true;
        }
    }
    false
}

fn is_proven_safe_telemetry_warning(message: &str) -> bool {
    [
        "Reading DWG file version:",
        "AC15 file header: 6 locator records,",
        "AC18 inner header:",
        "AC1021 header:",
        "AC1021 Header CRC-64 extracted:",
        "AC1021 CRC Seeds:",
        "AC1021 Pages Map CRC:",
        "AC1021 Sections Map CRC:",
        "  Section '",
        "AcDs: attached ",
    ]
    .iter()
    .any(|prefix| message.starts_with(prefix))
        || [
            ("AC18: Read ", " page records from page map"),
            ("AC18: Read ", " section descriptors from section map"),
            ("AC1021: Read ", " page records from page map"),
            ("AC1021: Read ", " section descriptors from section map"),
        ]
        .iter()
        .any(|(prefix, suffix)| message.starts_with(prefix) && message.ends_with(suffix))
}

pub(super) fn ensure_candidate_source_admitted(document: &CadDocument) -> Result<(), WriteError> {
    if has_xrefs(document) {
        return Err(WriteError::backend_capability(
            "xref_metadata_not_preserved",
            "candidate generation is blocked when the source contains an XREF",
        )
        .with_internal_detail(
            "acadrust 0.4.1 DXF serialization rewrites XREF membership metadata",
        ));
    }
    if document
        .layers
        .iter()
        .any(|layer| layer.color.is_true_color())
    {
        return Err(WriteError::backend_capability(
            "true_color_layer_not_preserved",
            "candidate generation is blocked when a source layer uses true color",
        )
        .with_internal_detail(
            "acadrust 0.4.1 DXF serialization converts true-color layers to ACI 7",
        ));
    }
    if document.entities().any(|entity| {
        !entity.common().extended_data.is_empty()
            || matches!(
                entity,
                EntityType::Insert(insert)
                    if insert
                        .attributes
                        .iter()
                        .any(|attribute| !attribute.common.extended_data.is_empty())
            )
    }) {
        return Err(WriteError::backend_capability(
            "extended_data_not_preserved",
            "candidate generation is blocked when the source contains extended data",
        )
        .with_internal_detail(
            "acadrust 0.4.1 parses entity XDATA but its DXF writer does not emit it",
        ));
    }
    if document.entities().any(|entity| {
        matches!(
            entity,
            EntityType::Surface(_)
                | EntityType::Unknown(_)
                | EntityType::Polyline3D(_)
                | EntityType::PolygonMesh(_)
                | EntityType::PolyfaceMesh(_)
        )
    }) {
        return Err(WriteError::backend_capability(
            "unsupported_entity_preservation",
            "candidate generation is blocked by an entity the selected writer cannot preserve",
        )
        .with_internal_detail(
            "acadrust 0.4.1 omits DXF Surface entities, cannot classify Unknown entity fidelity, \
             and does not round-trip compound child layer state",
        ));
    }
    Ok(())
}

pub(super) fn encode(format: DrawingFormat, document: &CadDocument) -> Result<Vec<u8>, WriteError> {
    if format == DrawingFormat::Dwg {
        return Err(WriteError::backend_capability(
            "dwg_candidate_preservation_unqualified",
            "DWG candidate generation is not admitted by the selected writer backend",
        )
        .with_internal_detail(
            "acadrust 0.4.1 has known silent DWG writer omissions; no source allowlist is certified",
        ));
    }
    ensure_candidate_source_admitted(document)?;
    DxfWriter::new(document)
        .write_to_vec()
        .map_err(|error| WriteError::encode(error.to_string()))
}

pub(super) fn has_xrefs(document: &CadDocument) -> bool {
    document.block_records.iter().any(|record| {
        record.flags.is_xref || record.flags.is_xref_overlay || !record.xref_path.is_empty()
    })
}
