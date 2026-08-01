use std::io::Cursor;

#[cfg(feature = "preview")]
use acadrust::entities::ClipMode;
use acadrust::entities::EntityType;
#[cfg(feature = "preview")]
use acadrust::io::dwg::crc::{crc16, CRC16_SEED};
use acadrust::notification::NotificationType;
#[cfg(feature = "preview")]
use acadrust::objects::ObjectType;
#[cfg(feature = "preview")]
use acadrust::types::DxfVersion;
use acadrust::{CadDocument, DxfReader, DxfWriter};
#[cfg(feature = "preview")]
use acadrust::{DwgReader, DwgWriter};
#[cfg(feature = "preview")]
use std::collections::{BTreeMap, BTreeSet};

use super::{DrawingFormat, DrawingSnapshot, WriteError};

const BINARY_DXF_SENTINEL: &[u8] = b"AutoCAD Binary DXF\r\n\x1a\0";

#[cfg(feature = "preview")]
const QUALIFIED_DWG_VERSION: &[u8; 6] = b"AC1032";

#[cfg(feature = "preview")]
const QUALIFIED_DWG_SECTIONS: &[&str] = &[
    "AcDb:AcDbObjects",
    "AcDb:AcDsPrototype_1b",
    "AcDb:AppInfo",
    "AcDb:AuxHeader",
    "AcDb:Classes",
    "AcDb:FileDepList",
    "AcDb:Handles",
    "AcDb:Header",
    "AcDb:ObjFreeSpace",
    "AcDb:Preview",
    "AcDb:RevHistory",
    "AcDb:SummaryInfo",
    "AcDb:Template",
];

#[cfg(feature = "preview")]
const TITLE_BLOCK_OBJECT_STREAM_SECTIONS: &[&str] = &["AcDb:AcDbObjects", "AcDb:Handles"];

#[cfg(feature = "preview")]
#[derive(Debug, Clone)]
pub(super) struct DwgPreservationSeal {
    section_names: BTreeSet<String>,
    preserved_sections: BTreeMap<String, Vec<u8>>,
}

pub(super) struct ParsedDrawing {
    pub(super) document: CadDocument,
    #[cfg(feature = "preview")]
    pub(super) dwg_preservation_seal: Option<DwgPreservationSeal>,
}

pub(super) fn parse(snapshot: &DrawingSnapshot) -> Result<ParsedDrawing, WriteError> {
    if snapshot.format() == DrawingFormat::Dxf && snapshot.bytes().starts_with(BINARY_DXF_SENTINEL)
    {
        return Err(WriteError::unsupported_source(
            "binary_dxf_not_preserved",
            "binary DXF form cannot be preserved by the selected candidate writer",
        ));
    }

    #[cfg(feature = "preview")]
    let dwg_preservation_seal = if snapshot.format() == DrawingFormat::Dwg {
        Some(capture_dwg_preservation_seal(snapshot.bytes().as_ref())?)
    } else {
        None
    };

    if snapshot.format() == DrawingFormat::Dwg {
        #[cfg(not(feature = "preview"))]
        return Err(dwg_preview_only_error());
    } else {
        ensure_ascii_dxf_source_bytes_admitted(snapshot.bytes().as_ref())?;
    }

    // The reader boundary owns generic completeness policy. Parse again only
    // to obtain the private mutable backend model.
    autocad_reader::Reader::open_snapshot(snapshot.reader_snapshot())
        .map_err(WriteError::from_reader)?;

    let bytes = snapshot.bytes();
    let document = match snapshot.format() {
        DrawingFormat::Dxf => DxfReader::from_reader(Cursor::new(bytes))
            .and_then(DxfReader::read)
            .map_err(|error| WriteError::invalid_drawing(error.to_string()))?,
        DrawingFormat::Dwg => {
            #[cfg(feature = "preview")]
            {
                let mut reader = DwgReader::from_stream(Cursor::new(bytes));
                reader
                    .read()
                    .map_err(|error| WriteError::invalid_drawing(error.to_string()))?
            }
            #[cfg(not(feature = "preview"))]
            unreachable!("DWG admission returned before parsing")
        }
    };

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
    #[cfg(feature = "preview")]
    if snapshot.format() == DrawingFormat::Dwg {
        admit_dwg_encode(&document)?;
    }

    Ok(ParsedDrawing {
        document,
        #[cfg(feature = "preview")]
        dwg_preservation_seal,
    })
}

#[cfg(not(feature = "preview"))]
fn dwg_preview_only_error() -> WriteError {
    WriteError::backend_capability(
        "dwg_candidate_preservation_unqualified",
        "DWG candidate generation is not admitted by the selected writer backend",
    )
    .with_internal_detail(
        "the bounded AC1032 title-block writer is compiled only into the Preview product",
    )
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
        .with_internal_detail("acadrust 0.4.1 serialization rewrites XREF membership metadata"));
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

#[cfg(feature = "preview")]
fn admit_dwg_encode(document: &CadDocument) -> Result<(), WriteError> {
    if document.version != DxfVersion::AC1032
        || document.dwg_source_version != Some(DxfVersion::AC1032)
    {
        return Err(WriteError::unsupported_source(
            "preview_dwg_version_not_qualified",
            "Preview title-block writes admit only native AC1032 DWG sources",
        ));
    }
    let unsupported_object = document.objects.values().find_map(|object| match object {
        ObjectType::GeoData(_) => Some(("dwg_geodata_not_writable", "GeoData")),
        ObjectType::VisualStyle(_) => Some(("dwg_visual_style_not_writable", "visual-style")),
        ObjectType::Material(_) => Some(("dwg_material_not_writable", "material")),
        ObjectType::TableStyle(_) => Some(("dwg_table_style_not_writable", "table-style")),
        ObjectType::Unknown { type_name, .. } if type_name.starts_with("DWG_OBJ_106") => {
            Some(("dwg_table_style_not_writable", "raw table-style"))
        }
        _ => None,
    });
    if let Some((code, family)) = unsupported_object {
        return Err(WriteError::unsupported_source(
            code,
            format!("DWG {family} objects are outside the Preview preservation oracle"),
        ));
    }
    if document
        .entities()
        .any(|entity| matches!(entity, EntityType::Table(_)))
    {
        return Err(WriteError::unsupported_source(
            "dwg_table_entity_not_writable",
            "DWG table entities are outside the Preview preservation oracle",
        ));
    }
    if document.entities().any(|entity| {
        matches!(
            entity,
            EntityType::RasterImage(image)
                if image.clipping_enabled && image.clip_boundary.clip_mode == ClipMode::Inside
        )
    }) {
        return Err(WriteError::unsupported_source(
            "dwg_inside_raster_clip_not_writable",
            "inside-clipped DWG raster images are outside the Preview preservation oracle",
        ));
    }
    Ok(())
}

pub(super) fn encode(format: DrawingFormat, document: &CadDocument) -> Result<Vec<u8>, WriteError> {
    match format {
        DrawingFormat::Dxf => {
            ensure_candidate_source_admitted(document)?;
            DxfWriter::new(document)
                .write_to_vec()
                .map_err(|error| WriteError::encode(error.to_string()))
        }
        DrawingFormat::Dwg => {
            #[cfg(feature = "preview")]
            {
                ensure_candidate_source_admitted(document)?;
                admit_dwg_encode(document)?;
                DwgWriter::write_to_vec(document)
                    .map_err(|error| WriteError::encode(error.to_string()))
            }
            #[cfg(not(feature = "preview"))]
            Err(dwg_preview_only_error())
        }
    }
}

#[cfg(feature = "preview")]
fn capture_dwg_preservation_seal(bytes: &[u8]) -> Result<DwgPreservationSeal, WriteError> {
    if bytes.len() < QUALIFIED_DWG_VERSION.len()
        || &bytes[..QUALIFIED_DWG_VERSION.len()] != QUALIFIED_DWG_VERSION
    {
        return Err(WriteError::unsupported_source(
            "preview_dwg_version_not_qualified",
            "Preview title-block writes admit only native AC1032 DWG sources",
        ));
    }
    let mut reader = DwgReader::from_stream(Cursor::new(bytes));
    let header = reader.read_file_header().map_err(|error| {
        WriteError::invalid_drawing(format!("read DWG section directory: {error}"))
    })?;
    if header.version_string.as_bytes() != QUALIFIED_DWG_VERSION {
        return Err(WriteError::unsupported_source(
            "preview_dwg_version_not_qualified",
            "Preview title-block writes admit only native AC1032 DWG sources",
        ));
    }

    let section_names = header
        .section_descriptors
        .iter()
        .map(|section| section.name.clone())
        .collect::<BTreeSet<_>>();
    if section_names.len() != header.section_descriptors.len() {
        return Err(WriteError::unsupported_source(
            "preview_dwg_duplicate_section_name",
            "duplicate DWG section names are outside the Preview preservation oracle",
        ));
    }
    for name in &section_names {
        if !QUALIFIED_DWG_SECTIONS.contains(&name.as_str()) {
            return Err(WriteError::unsupported_source(
                "preview_dwg_section_not_qualified",
                "the DWG contains a section outside the Preview preservation oracle",
            )
            .with_internal_detail(name.clone()));
        }
    }

    let mut preserved_sections = BTreeMap::new();
    for name in &section_names {
        if TITLE_BLOCK_OBJECT_STREAM_SECTIONS.contains(&name.as_str()) {
            continue;
        }
        let section = reader.get_section_buffer(name, &header).map_err(|error| {
            WriteError::unsupported_source(
                "preview_dwg_section_unreadable",
                "an invariant DWG section could not be captured for preservation proof",
            )
            .with_internal_detail(format!("{name}: {error}"))
        })?;
        preserved_sections.insert(name.clone(), section);
    }
    Ok(DwgPreservationSeal {
        section_names,
        preserved_sections,
    })
}

#[cfg(feature = "preview")]
pub(super) fn verify_dwg_title_block_preservation(
    source: &DwgPreservationSeal,
    expected_document: &CadDocument,
    candidate_snapshot: &DrawingSnapshot,
    candidate_document: &CadDocument,
) -> Result<(), WriteError> {
    let candidate = capture_dwg_preservation_seal(candidate_snapshot.bytes().as_ref())?;
    if source.section_names != candidate.section_names {
        return Err(WriteError::verification(
            "preview_dwg_section_set_changed",
            "candidate DWG section inventory differs from the locked source",
        ));
    }
    if source.preserved_sections.keys().collect::<Vec<_>>()
        != candidate.preserved_sections.keys().collect::<Vec<_>>()
    {
        return Err(WriteError::verification(
            "preview_dwg_preserved_section_set_changed",
            "candidate DWG preservation-section inventory differs from the locked source",
        ));
    }
    verify_dwg_bookkeeping_sections(source, &candidate, expected_document, candidate_document)?;
    for (name, source_bytes) in &source.preserved_sections {
        let candidate_bytes = candidate
            .preserved_sections
            .get(name)
            .expect("preservation-section key sets were compared above");
        match name.as_str() {
            "AcDb:Header" | "AcDb:AuxHeader" => {}
            _ if source_bytes != candidate_bytes => {
                return Err(WriteError::verification(
                    "preview_dwg_invariant_section_changed",
                    "candidate changed a DWG section outside the title-block object stream",
                )
                .with_internal_detail(name.clone()));
            }
            _ => {}
        }
    }

    let mut expected = expected_document.clone();
    expected.notifications = Default::default();
    let mut actual = candidate_document.clone();
    actual.notifications = Default::default();
    // acadrust's DWG writer seals HANDSEED one slot above the greatest
    // observed handle. The reader exposes that allocator cursor as document
    // state, so normalize this single writer-owned bookkeeping transition
    // before comparing every represented drawing field.
    if actual.header.handle_seed == expected.header.handle_seed.saturating_add(1) {
        let _ = expected.allocate_handle();
    }
    verify_complete_dwg_model(&mut expected, &mut actual)?;
    Ok(())
}

#[cfg(feature = "preview")]
fn verify_complete_dwg_model(
    expected: &mut CadDocument,
    actual: &mut CadDocument,
) -> Result<(), WriteError> {
    normalize_allocator_cursor_for_comparison(expected)?;
    normalize_allocator_cursor_for_comparison(actual)?;
    if expected != actual {
        return Err(WriteError::verification(
            "preview_dwg_complete_model_changed",
            "candidate differs from the exact in-memory title-block mutation plan",
        ));
    }
    Ok(())
}

#[cfg(feature = "preview")]
fn normalize_allocator_cursor_for_comparison(document: &mut CadDocument) -> Result<(), WriteError> {
    let handle_seed = document.header.handle_seed;
    if document.next_handle() > handle_seed {
        return Err(WriteError::verification(
            "preview_dwg_allocator_cursor_invalid",
            "the decoded allocator cursor exceeds the persisted DWG HANDSEED",
        ));
    }
    let _ = document.allocate_handle();
    document.header.handle_seed = handle_seed;
    Ok(())
}

#[cfg(feature = "preview")]
fn verify_dwg_bookkeeping_sections(
    source: &DwgPreservationSeal,
    candidate: &DwgPreservationSeal,
    expected_document: &CadDocument,
    candidate_document: &CadDocument,
) -> Result<(), WriteError> {
    const HEADER: &str = "AcDb:Header";
    const AUX_HEADER: &str = "AcDb:AuxHeader";
    const AUX_HANDSEED_OFFSET: usize = 79;
    const AUX_HANDSEED_LEN: usize = 4;
    const HEADER_START_SENTINEL_LEN: usize = 16;
    const HEADER_END_SENTINEL_LEN: usize = 16;
    const HEADER_TRAILING_ZERO_LEN: usize = 8;
    const HEADER_CRC_LEN: usize = 2;

    let source_header = required_preserved_section(source, HEADER)?;
    let candidate_header = required_preserved_section(candidate, HEADER)?;
    let source_aux = required_preserved_section(source, AUX_HEADER)?;
    let candidate_aux = required_preserved_section(candidate, AUX_HEADER)?;

    if source_aux.len() != candidate_aux.len()
        || source_aux.len() < AUX_HANDSEED_OFFSET + AUX_HANDSEED_LEN
        || source_aux[..AUX_HANDSEED_OFFSET] != candidate_aux[..AUX_HANDSEED_OFFSET]
        || source_aux[AUX_HANDSEED_OFFSET + AUX_HANDSEED_LEN..]
            != candidate_aux[AUX_HANDSEED_OFFSET + AUX_HANDSEED_LEN..]
    {
        return Err(WriteError::verification(
            "preview_dwg_aux_header_delta_failed",
            "candidate AuxHeader changed outside its exact HANDSEED field",
        ));
    }
    let source_seed = i32::from_le_bytes(
        source_aux[AUX_HANDSEED_OFFSET..AUX_HANDSEED_OFFSET + AUX_HANDSEED_LEN]
            .try_into()
            .expect("the AuxHeader HANDSEED slice has a fixed length"),
    );
    let candidate_seed = i32::from_le_bytes(
        candidate_aux[AUX_HANDSEED_OFFSET..AUX_HANDSEED_OFFSET + AUX_HANDSEED_LEN]
            .try_into()
            .expect("the AuxHeader HANDSEED slice has a fixed length"),
    );
    let (Ok(source_seed), Ok(candidate_seed)) =
        (u64::try_from(source_seed), u64::try_from(candidate_seed))
    else {
        return Err(WriteError::unsupported_source(
            "preview_dwg_handseed_not_qualified",
            "the DWG HANDSEED is outside the closed Preview writer oracle",
        ));
    };
    if source_seed == candidate_seed
        || source_seed > expected_document.header.handle_seed
        || candidate_seed != candidate_document.header.handle_seed
        || candidate_seed != expected_document.header.handle_seed.saturating_add(1)
    {
        return Err(WriteError::verification(
            "preview_dwg_handseed_transition_failed",
            "candidate DWG does not have the one admitted writer-owned HANDSEED transition",
        ));
    }

    if source_header.len() != candidate_header.len()
        || source_header.len()
            < HEADER_START_SENTINEL_LEN
                + HEADER_CRC_LEN
                + HEADER_END_SENTINEL_LEN
                + HEADER_TRAILING_ZERO_LEN
    {
        return Err(WriteError::verification(
            "preview_dwg_header_shape_changed",
            "candidate Header section shape differs from the locked source",
        ));
    }
    let crc_offset =
        source_header.len() - HEADER_TRAILING_ZERO_LEN - HEADER_END_SENTINEL_LEN - HEADER_CRC_LEN;
    verify_header_crc(source_header, crc_offset, HEADER_START_SENTINEL_LEN)?;
    verify_header_crc(candidate_header, crc_offset, HEADER_START_SENTINEL_LEN)?;

    let source_pattern = encoded_undefined_handle(source_seed);
    let candidate_pattern = encoded_undefined_handle(candidate_seed);
    if source_pattern.len() != candidate_pattern.len() {
        return Err(WriteError::unsupported_source(
            "preview_dwg_handseed_width_transition_not_qualified",
            "a HANDSEED encoding-width transition is outside the Preview writer oracle",
        ));
    }
    let pattern_bits = source_pattern.len() * 8;
    let search_end_bits = crc_offset * 8;
    let matching_offsets = (0..=search_end_bits.saturating_sub(pattern_bits))
        .filter(|bit_offset| {
            bits_match(source_header, *bit_offset, &source_pattern)
                && bits_match(candidate_header, *bit_offset, &candidate_pattern)
                && header_diff_is_only_handseed_and_crc(
                    source_header,
                    candidate_header,
                    *bit_offset,
                    pattern_bits,
                    crc_offset,
                )
        })
        .collect::<Vec<_>>();
    if matching_offsets.len() != 1 {
        return Err(WriteError::verification(
            "preview_dwg_header_handseed_delta_failed",
            "candidate Header changed outside one exact HANDSEED encoding and its CRC",
        )
        .with_internal_detail(format!("matching HANDSEED offsets: {matching_offsets:?}")));
    }
    Ok(())
}

#[cfg(feature = "preview")]
fn required_preserved_section<'a>(
    seal: &'a DwgPreservationSeal,
    name: &str,
) -> Result<&'a [u8], WriteError> {
    seal.preserved_sections
        .get(name)
        .map(Vec::as_slice)
        .ok_or_else(|| {
            WriteError::unsupported_source(
                "preview_dwg_required_section_missing",
                "the DWG is missing a section required by the Preview preservation oracle",
            )
            .with_internal_detail(name.to_owned())
        })
}

#[cfg(feature = "preview")]
fn verify_header_crc(
    section: &[u8],
    crc_offset: usize,
    crc_content_offset: usize,
) -> Result<(), WriteError> {
    let stored = u16::from_le_bytes(
        section[crc_offset..crc_offset + 2]
            .try_into()
            .expect("the Header CRC slice has a fixed length"),
    );
    let computed = crc16(CRC16_SEED, &section[crc_content_offset..crc_offset]);
    if stored != computed {
        return Err(WriteError::unsupported_source(
            "preview_dwg_header_crc_invalid",
            "the DWG Header CRC is invalid",
        ));
    }
    Ok(())
}

#[cfg(feature = "preview")]
fn encoded_undefined_handle(handle: u64) -> Vec<u8> {
    let byte_count = if handle == 0 {
        0
    } else {
        (u64::BITS - handle.leading_zeros()).div_ceil(8) as usize
    };
    let mut encoded = Vec::with_capacity(byte_count + 1);
    encoded.push(byte_count as u8);
    encoded.extend_from_slice(&handle.to_be_bytes()[8 - byte_count..]);
    encoded
}

#[cfg(feature = "preview")]
fn bits_match(bytes: &[u8], bit_offset: usize, pattern: &[u8]) -> bool {
    (0..pattern.len() * 8)
        .all(|pattern_bit| bit_at(bytes, bit_offset + pattern_bit) == bit_at(pattern, pattern_bit))
}

#[cfg(feature = "preview")]
fn header_diff_is_only_handseed_and_crc(
    source: &[u8],
    candidate: &[u8],
    handseed_bit_offset: usize,
    handseed_bit_len: usize,
    crc_offset: usize,
) -> bool {
    (0..source.len() * 8).all(|bit_offset| {
        bit_at(source, bit_offset) == bit_at(candidate, bit_offset)
            || (handseed_bit_offset..handseed_bit_offset + handseed_bit_len).contains(&bit_offset)
            || (crc_offset * 8..(crc_offset + 2) * 8).contains(&bit_offset)
    })
}

#[cfg(feature = "preview")]
fn bit_at(bytes: &[u8], bit_offset: usize) -> bool {
    let byte = bytes[bit_offset / 8];
    let shift = 7 - (bit_offset % 8);
    byte & (1 << shift) != 0
}

pub(super) fn has_xrefs(document: &CadDocument) -> bool {
    document.block_records.iter().any(|record| {
        record.flags.is_xref || record.flags.is_xref_overlay || !record.xref_path.is_empty()
    })
}

#[cfg(all(test, feature = "preview"))]
mod tests {
    use acadrust::entities::{EntityType, Line};

    use super::*;

    #[test]
    fn complete_model_oracle_includes_private_raw_entity_state() {
        let mut expected = CadDocument::new();
        let mut line = Line::from_coords(0.0, 0.0, 0.0, 1.0, 1.0, 0.0);
        line.common.handle = expected.allocate_handle();
        expected.add_entity(EntityType::Line(line)).unwrap();
        let mut actual = expected.clone();
        let EntityType::Line(line) = actual.entities_mut().next().unwrap() else {
            panic!("fixture entity changed type");
        };
        line.common.material_flags = 3;
        line.common.material_handle = Some(acadrust::types::Handle::new(0x77));

        let error = verify_complete_dwg_model(&mut expected, &mut actual).unwrap_err();
        assert_eq!(error.code(), "preview_dwg_complete_model_changed");
    }

    #[test]
    fn complete_model_oracle_fails_closed_for_non_finite_state() {
        let mut expected = CadDocument::new();
        expected.header.user_real1 = f64::NAN;
        let mut actual = expected.clone();

        let error = verify_complete_dwg_model(&mut expected, &mut actual).unwrap_err();
        assert_eq!(error.code(), "preview_dwg_complete_model_changed");
    }
}
