use std::io::Cursor;

use acadrust::io::dxf::GroupCodeValueType;
use acadrust::notification::NotificationType;
use acadrust::{CadDocument, DwgReader, DxfReader};

use super::{DrawingFormat, DrawingSnapshot, ReadError};

const BINARY_DXF_SENTINEL: &[u8] = b"AutoCAD Binary DXF\r\n\x1a\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadDiagnosticKind {
    NotImplemented,
    NotSupported,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReadDiagnostic {
    pub(super) kind: ReadDiagnosticKind,
    pub(super) message: String,
}

pub(super) struct ParsedDrawing {
    pub(super) document: CadDocument,
    pub(super) diagnostics: Vec<ReadDiagnostic>,
}

pub(super) fn parse(snapshot: &DrawingSnapshot) -> Result<ParsedDrawing, ReadError> {
    let bytes = snapshot.bytes();
    let document = match snapshot.format() {
        DrawingFormat::Dxf => {
            validate_dxf_backend_safety(bytes.as_ref())?;
            DxfReader::from_reader(Cursor::new(bytes))
                .and_then(DxfReader::read)
                .map_err(|error| ReadError::invalid_drawing(error.to_string()))?
        }
        DrawingFormat::Dwg => {
            let mut reader = DwgReader::from_stream(Cursor::new(bytes));
            reader
                .read()
                .map_err(|error| ReadError::invalid_drawing(error.to_string()))?
        }
    };
    validate_signature(snapshot)?;
    validate_document(document, snapshot.format())
}

fn validate_dxf_backend_safety(bytes: &[u8]) -> Result<(), ReadError> {
    let unsafe_color_index = if bytes.starts_with(BINARY_DXF_SENTINEL) {
        binary_dxf_contains_minimum_color_index(bytes)
    } else {
        ascii_dxf_contains_minimum_color_index(bytes)
    };
    if unsafe_color_index {
        return Err(ReadError::invalid_drawing(
            "DXF group code 62 contains i16::MIN, which the selected decoder cannot process safely",
        ));
    }
    Ok(())
}

fn ascii_dxf_contains_minimum_color_index(bytes: &[u8]) -> bool {
    let mut lines = bytes.split(|byte| *byte == b'\n');
    while let Some(code_line) = lines.next() {
        let Some(value_line) = lines.next() else {
            return false;
        };
        if parse_ascii_integer(code_line) == Some(62)
            && parse_ascii_integer(value_line) == Some(i64::from(i16::MIN))
        {
            return true;
        }
    }
    false
}

fn parse_ascii_integer(bytes: &[u8]) -> Option<i64> {
    std::str::from_utf8(bytes).ok()?.trim().parse::<i64>().ok()
}

fn binary_dxf_contains_minimum_color_index(bytes: &[u8]) -> bool {
    let Some(payload) = bytes.strip_prefix(BINARY_DXF_SENTINEL) else {
        return false;
    };
    if payload.len() < 2 {
        return false;
    }
    let single_byte_codes = payload[0] == 0 && payload[1] >= 0x20 && payload[1] < 0x7f;
    let mut offset = 0;
    while let Some((code, value)) = read_binary_pair(payload, &mut offset, single_byte_codes) {
        if code == 62 && value == i16::MIN.to_le_bytes() {
            return true;
        }
    }
    false
}

fn validate_signature(snapshot: &DrawingSnapshot) -> Result<(), ReadError> {
    let bytes = snapshot.bytes();
    let has_dwg_structure = has_dwg_structure(bytes.as_ref());
    match snapshot.format() {
        DrawingFormat::Dwg if has_dwg_structure => Ok(()),
        DrawingFormat::Dwg => Err(ReadError::invalid_drawing(
            "declared DWG snapshot has no supported DWG header and section structure",
        )),
        DrawingFormat::Dxf if has_dwg_structure => Err(ReadError::invalid_drawing(
            "declared DXF snapshot contains a DWG header and section structure",
        )),
        DrawingFormat::Dxf
            if has_binary_dxf_structure(bytes.as_ref())
                || has_ascii_dxf_structure(bytes.as_ref()) =>
        {
            Ok(())
        }
        DrawingFormat::Dxf => Err(ReadError::invalid_drawing(
            "declared DXF snapshot has no DXF section and end-of-file structure",
        )),
    }
}

fn has_dwg_structure(bytes: &[u8]) -> bool {
    const RECOGNIZED_HEADERS: [&[u8]; 16] = [
        b"AC1012", b"AC1014", b"AC1015", b"AC1018", b"AC1021", b"AC1024", b"AC1027", b"AC1032",
        b"AD1012", b"AD1014", b"AD1015", b"AD1018", b"AD1021", b"AD1024", b"AD1027", b"AD1032",
    ];
    let Some(header) = bytes.get(..6) else {
        return false;
    };
    if !RECOGNIZED_HEADERS.contains(&header) {
        return false;
    }

    // acadrust routes AC/AD 1012, 1014, and 1015 through the linear AC15
    // reader. That reader otherwise accepts a zero locator count as an empty
    // document, although the format requires six locator records.
    if matches!(
        header,
        b"AC1012" | b"AC1014" | b"AC1015" | b"AD1012" | b"AD1014" | b"AD1015"
    ) {
        return has_legacy_dwg_directory(bytes);
    }

    true
}

fn has_legacy_dwg_directory(bytes: &[u8]) -> bool {
    let Some(record_count) = bytes.get(0x15..0x19) else {
        return false;
    };
    if bytes.len() < 0x61
        || i32::from_le_bytes(
            record_count
                .try_into()
                .expect("four-byte DWG locator count"),
        ) != 6
    {
        return false;
    }

    let mut seen = [false; 6];
    let mut handles_start = None;
    let mut auxiliary_end = None;
    for index in 0..6 {
        let offset = 0x19 + index * 9;
        let Some(record) = bytes.get(offset..offset + 9) else {
            return false;
        };
        let number = usize::from(record[0]);
        if number >= seen.len() || std::mem::replace(&mut seen[number], true) {
            return false;
        }
        let seeker = i32::from_le_bytes(record[1..5].try_into().expect("four-byte DWG seeker"));
        let size = i32::from_le_bytes(record[5..9].try_into().expect("four-byte DWG section size"));
        let (Ok(seeker), Ok(size)) = (usize::try_from(seeker), usize::try_from(size)) else {
            return false;
        };
        let Some(end) = seeker.checked_add(size) else {
            return false;
        };
        if end > bytes.len() || (matches!(number, 0 | 2) && size == 0) {
            return false;
        }
        if number == 2 {
            handles_start = Some(seeker);
        } else if number == 5 {
            auxiliary_end = Some(end);
        }
    }
    seen.into_iter().all(std::convert::identity)
        && matches!(
            (handles_start, auxiliary_end),
            (Some(handles), Some(auxiliary)) if handles > auxiliary
        )
}

fn has_binary_dxf_structure(bytes: &[u8]) -> bool {
    let Some(payload) = bytes.strip_prefix(BINARY_DXF_SENTINEL) else {
        return false;
    };
    if payload.len() < 2 {
        return false;
    }

    let single_byte_codes = payload[0] == 0 && payload[1] >= 0x20 && payload[1] < 0x7f;
    let mut offset = 0;
    let mut structure = DxfStructure::default();
    while let Some((code, value)) = read_binary_pair(payload, &mut offset, single_byte_codes) {
        if let Some(result) = structure.observe(code, value) {
            return result;
        }
    }
    false
}

fn has_ascii_dxf_structure(bytes: &[u8]) -> bool {
    let mut lines = bytes.split(|byte| *byte == b'\n');
    let mut structure = DxfStructure::default();
    while let Some(code_line) = lines.next() {
        let Some(value_line) = lines.next() else {
            return false;
        };
        let code_line = code_line.strip_suffix(b"\r").unwrap_or(code_line);
        let value_line = value_line.strip_suffix(b"\r").unwrap_or(value_line);
        let Ok(code) = std::str::from_utf8(code_line)
            .map(str::trim)
            .unwrap_or_default()
            .parse::<i32>()
        else {
            return false;
        };
        if let Some(result) = structure.observe(code, value_line) {
            return result;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, Default)]
enum DxfStructureState {
    #[default]
    TopLevel,
    ExpectSectionName,
    InSection,
}

#[derive(Debug, Default)]
struct DxfStructure {
    state: DxfStructureState,
    completed_section: bool,
}

impl DxfStructure {
    fn observe(&mut self, code: i32, value: &[u8]) -> Option<bool> {
        match self.state {
            DxfStructureState::TopLevel if code == 0 && value == b"SECTION" => {
                self.state = DxfStructureState::ExpectSectionName;
                None
            }
            DxfStructureState::TopLevel if code == 0 && value == b"EOF" => {
                Some(self.completed_section)
            }
            DxfStructureState::TopLevel if code == 0 && value == b"ENDSEC" => Some(false),
            DxfStructureState::TopLevel => None,
            DxfStructureState::ExpectSectionName if code == 2 && !value.is_empty() => {
                self.state = DxfStructureState::InSection;
                None
            }
            DxfStructureState::ExpectSectionName => Some(false),
            DxfStructureState::InSection if code == 0 && value == b"ENDSEC" => {
                self.completed_section = true;
                self.state = DxfStructureState::TopLevel;
                None
            }
            DxfStructureState::InSection if code == 0 && matches!(value, b"SECTION" | b"EOF") => {
                Some(false)
            }
            DxfStructureState::InSection => None,
        }
    }
}

fn read_binary_pair<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    single_byte_codes: bool,
) -> Option<(i32, &'a [u8])> {
    let code = if single_byte_codes {
        let first = *take_bytes(bytes, offset, 1)?.first()?;
        if first == 255 {
            i16::from_le_bytes(take_bytes(bytes, offset, 2)?.try_into().ok()?) as i32
        } else {
            i32::from(first)
        }
    } else {
        i16::from_le_bytes(take_bytes(bytes, offset, 2)?.try_into().ok()?) as i32
    };

    let value = match GroupCodeValueType::from_raw_code(code) {
        GroupCodeValueType::String
        | GroupCodeValueType::Handle
        | GroupCodeValueType::None
        | GroupCodeValueType::Point3D => take_null_terminated(bytes, offset)?,
        GroupCodeValueType::Double | GroupCodeValueType::Int64 => take_bytes(bytes, offset, 8)?,
        GroupCodeValueType::Int16 | GroupCodeValueType::Byte => take_bytes(bytes, offset, 2)?,
        GroupCodeValueType::Int32 => take_bytes(bytes, offset, 4)?,
        GroupCodeValueType::Bool => take_bytes(bytes, offset, 1)?,
        GroupCodeValueType::BinaryData => {
            let length = usize::from(*take_bytes(bytes, offset, 1)?.first()?);
            take_bytes(bytes, offset, length)?
        }
    };
    Some((code, value))
}

fn take_bytes<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(length)?;
    let value = bytes.get(*offset..end)?;
    *offset = end;
    Some(value)
}

fn take_null_terminated<'a>(bytes: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let tail = bytes.get(*offset..)?;
    let length = tail.iter().position(|byte| *byte == 0)?;
    let value = &tail[..length];
    *offset = offset.checked_add(length + 1)?;
    Some(value)
}

fn validate_document(
    document: CadDocument,
    format: DrawingFormat,
) -> Result<ParsedDrawing, ReadError> {
    let errors = document
        .notifications
        .iter()
        .filter(|notification| notification.notification_type == NotificationType::Error)
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if !errors.is_empty() {
        return Err(ReadError::incomplete(format.name(), errors));
    }

    let diagnostics = document
        .notifications
        .iter()
        .filter_map(|notification| {
            let kind = match notification.notification_type {
                NotificationType::NotImplemented => ReadDiagnosticKind::NotImplemented,
                NotificationType::NotSupported => ReadDiagnosticKind::NotSupported,
                NotificationType::Warning => ReadDiagnosticKind::Warning,
                NotificationType::Error => return None,
            };
            Some(ReadDiagnostic {
                kind,
                message: notification.message.clone(),
            })
        })
        .collect();

    Ok(ParsedDrawing {
        document,
        diagnostics,
    })
}

#[cfg(test)]
mod tests {
    use acadrust::notification::NotificationType;

    use super::*;

    #[test]
    fn error_diagnostics_reject_the_whole_document() {
        let mut document = CadDocument::new();
        document
            .notifications
            .notify(NotificationType::Error, "record was skipped");

        let error = match validate_document(document, DrawingFormat::Dwg) {
            Ok(_) => panic!("Error diagnostics must reject the read"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), super::super::ReadErrorKind::IncompleteDrawing);
        assert!(error.message().contains("drawing projection is incomplete"));
        assert!(!error.message().contains("record was skipped"));
        assert_eq!(
            error.fatal_diagnostics(),
            &["[Error] record was skipped".to_string()]
        );
        assert_eq!(error.internal_detail(), None);
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn non_error_diagnostics_are_retained_for_family_policy() {
        let mut document = CadDocument::new();
        document
            .notifications
            .notify(NotificationType::Warning, "recoverable detail");
        document
            .notifications
            .notify(NotificationType::NotImplemented, "unmodeled record family");
        document
            .notifications
            .notify(NotificationType::NotSupported, "unsupported record detail");

        let parsed = validate_document(document, DrawingFormat::Dxf).unwrap();

        assert_eq!(
            parsed.diagnostics,
            vec![
                ReadDiagnostic {
                    kind: ReadDiagnosticKind::Warning,
                    message: "recoverable detail".to_string(),
                },
                ReadDiagnostic {
                    kind: ReadDiagnosticKind::NotImplemented,
                    message: "unmodeled record family".to_string(),
                },
                ReadDiagnostic {
                    kind: ReadDiagnosticKind::NotSupported,
                    message: "unsupported record detail".to_string(),
                },
            ]
        );
    }

    #[test]
    fn dxf_backend_safety_rejects_minimum_color_index_before_decode() {
        let ascii = b"0\nSECTION\n2\nTABLES\n0\nTABLE\n2\nLAYER\n70\n1\n0\nLAYER\n2\n0\n62\n-32768\n0\nENDTAB\n0\nENDSEC\n0\nEOF\n";
        let error = match parse(&DrawingSnapshot::new(DrawingFormat::Dxf, ascii.to_vec())) {
            Ok(_) => panic!("the decoder-unsafe color index must fail closed"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), super::super::ReadErrorKind::InvalidDrawing);
        assert_eq!(error.message(), "drawing could not be decoded");
        assert!(error
            .internal_detail()
            .is_some_and(|detail| detail.contains("i16::MIN")));
        assert!(!format!("{error:?}").contains("i16::MIN"));

        let mut binary = BINARY_DXF_SENTINEL.to_vec();
        push_binary_code(&mut binary, false, 62);
        binary.extend_from_slice(&i16::MIN.to_le_bytes());
        assert!(binary_dxf_contains_minimum_color_index(&binary));

        let mut legacy_binary = BINARY_DXF_SENTINEL.to_vec();
        push_binary_string(&mut legacy_binary, true, 0, b"SECTION");
        push_binary_code(&mut legacy_binary, true, 62);
        legacy_binary.extend_from_slice(&i16::MIN.to_le_bytes());
        assert!(binary_dxf_contains_minimum_color_index(&legacy_binary));
        assert!(!ascii_dxf_contains_minimum_color_index(b"62\n-32767\n"));
    }

    #[test]
    fn dxf_structure_requires_complete_exact_sections() {
        assert!(has_ascii_dxf_structure(
            b"0\nSECTION\n2\nHEADER\n0\nENDSEC\n0\nEOF\n"
        ));
        for malformed in [
            b"0\nSECTION\n0\nEOF\n".as_slice(),
            b"0\nsection\n2\nHEADER\n0\nENDSEC\n0\nEOF\n".as_slice(),
            b"0\nSECTION \n2\nHEADER\n0\nENDSEC\n0\nEOF\n".as_slice(),
            b"999\nSECTION EOF\n".as_slice(),
        ] {
            assert!(!has_ascii_dxf_structure(malformed));
        }

        for single_byte_codes in [true, false] {
            let mut valid = BINARY_DXF_SENTINEL.to_vec();
            push_binary_string(&mut valid, single_byte_codes, 0, b"SECTION");
            push_binary_string(&mut valid, single_byte_codes, 2, b"HEADER");
            push_binary_string(&mut valid, single_byte_codes, 0, b"ENDSEC");
            push_binary_string(&mut valid, single_byte_codes, 0, b"EOF");
            assert!(has_binary_dxf_structure(&valid));
            assert!(parse(&DrawingSnapshot::new(DrawingFormat::Dxf, valid.clone())).is_ok());

            let mut embedded_eof = BINARY_DXF_SENTINEL.to_vec();
            push_binary_string(&mut embedded_eof, single_byte_codes, 0, b"SECTION");
            push_binary_string(&mut embedded_eof, single_byte_codes, 2, b"HEADER");
            push_binary_code(&mut embedded_eof, single_byte_codes, 310);
            embedded_eof.extend_from_slice(&[6, 0, 0, b'E', b'O', b'F', 0]);
            assert!(!has_binary_dxf_structure(&embedded_eof));
        }
        assert!(!has_binary_dxf_structure(BINARY_DXF_SENTINEL));
    }

    #[test]
    fn dwg_structure_uses_the_backends_exact_header_set() {
        let mut legacy = vec![0; 0x200];
        legacy[..6].copy_from_slice(b"AD1015");
        legacy[0x15..0x19].copy_from_slice(&6_i32.to_le_bytes());
        for (index, (number, seeker)) in [
            (0_u8, 0x61_i32),
            (1, 0x71),
            (3, 0x81),
            (4, 0x91),
            (5, 0xa1),
            (2, 0xc1),
        ]
        .into_iter()
        .enumerate()
        {
            let offset = 0x19 + index * 9;
            legacy[offset] = number;
            legacy[offset + 1..offset + 5].copy_from_slice(&seeker.to_le_bytes());
            legacy[offset + 5..offset + 9].copy_from_slice(&0x10_i32.to_le_bytes());
        }
        assert!(has_dwg_structure(&legacy));

        legacy[0x15..0x19].copy_from_slice(&0_i32.to_le_bytes());
        assert!(!has_dwg_structure(&legacy));
        assert!(!has_dwg_structure(b"AC9999"));
    }

    fn push_binary_string(bytes: &mut Vec<u8>, single_byte_codes: bool, code: i16, value: &[u8]) {
        push_binary_code(bytes, single_byte_codes, code);
        bytes.extend_from_slice(value);
        bytes.push(0);
    }

    fn push_binary_code(bytes: &mut Vec<u8>, single_byte_codes: bool, code: i16) {
        if single_byte_codes && (0..255).contains(&code) {
            bytes.push(u8::try_from(code).expect("bounded one-byte group code"));
        } else if single_byte_codes {
            bytes.push(255);
            bytes.extend_from_slice(&code.to_le_bytes());
        } else {
            bytes.extend_from_slice(&code.to_le_bytes());
        }
    }
}
