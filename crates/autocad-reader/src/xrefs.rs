use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Cursor;

use acadrust::entities::EntityType;
use acadrust::io::dwg::dwg_stream_readers::handle_reader::read_handles;
use acadrust::io::dwg::dwg_stream_readers::object_reader::common::{
    OBJ_BLOCK, OBJ_BLOCK_CONTROL, OBJ_BLOCK_HEADER, OBJ_ENDBLK, OBJ_INSERT, OBJ_LAYER, OBJ_MINSERT,
};
use acadrust::io::dwg::dwg_stream_readers::object_reader::{entities, tables, DwgObjectReader};
use acadrust::io::dwg::DwgReader;
use acadrust::notification::NotificationType;
use acadrust::objects::ObjectType;
use acadrust::types::{DxfVersion, Vector3};
use acadrust::CadDocument;

use super::contract::xrefs::{
    self as xref_contract, Fact, InsertionUnit, LayerEvidence, LoadState, OwnerEvidence,
    PersistedInsertionUnits, ReferenceType, XrefAttachmentRecord, XrefDomainEvidence, XrefError,
    XrefInstanceListOptions, XrefInstanceRecord, XrefMembershipEvidence, XrefOwnerType,
    XrefPathMode, XrefPersistedInstanceEvidence, XrefPersistedPlacementEvidence, XrefPlacementKind,
    XrefPoint3, XrefPointAvailability, XrefPortableClipEvidence, XrefPortableLayerColor,
    XrefPortableLayerProperties, XrefRectangularArray, XrefScale3, XrefSelector,
    XrefSnapshotEvidence, XrefUnitBasis, XrefUnitScaling, XrefUnitValue, XrefVector3,
    XrefVisibility,
};
#[cfg(test)]
use super::Reader;
use super::{DrawingFormat, DrawingSnapshot, ReadError, ReadErrorKind};

const BINARY_DXF_SENTINEL: &[u8] = b"AutoCAD Binary DXF\r\n\x1a\0";

/// XREF projection and persisted evidence derived from one immutable capture.
///
/// Keeping both query layers in this session prevents mutation preparation
/// from combining a high-level projection from one file revision with
/// byte-level evidence from another.
#[derive(Debug, Clone)]
pub struct XrefReadSession {
    _snapshot: DrawingSnapshot,
    evidence: XrefSnapshotEvidence,
}

impl XrefReadSession {
    pub(super) fn from_drawing(
        snapshot: DrawingSnapshot,
        document: &CadDocument,
    ) -> Result<Self, XrefError> {
        let bytes = snapshot.bytes();
        let evidence = match snapshot.format() {
            DrawingFormat::Dxf => derive_dxf_snapshot(&bytes, document),
            DrawingFormat::Dwg => derive_dwg_snapshot(&bytes, document),
        }?;
        Ok(Self {
            _snapshot: snapshot,
            evidence,
        })
    }

    pub fn evidence(&self) -> &XrefSnapshotEvidence {
        &self.evidence
    }

    pub fn list_attachments(&self) -> Result<Vec<XrefAttachmentRecord>, XrefError> {
        list_attachments(&self.evidence)
    }

    pub fn get_attachment(
        &self,
        selector: &XrefSelector,
    ) -> Result<XrefAttachmentRecord, XrefError> {
        get_attachment(&self.evidence, selector)
    }

    pub fn list_instances(
        &self,
        options: &XrefInstanceListOptions,
    ) -> Result<Vec<XrefInstanceRecord>, XrefError> {
        list_instances(&self.evidence, options)
    }

    pub fn get_instance(&self, handle: &str) -> Result<XrefInstanceRecord, XrefError> {
        get_instance(&self.evidence, handle)
    }
}

pub fn map_open_error(error: ReadError) -> XrefError {
    let (code, message) = match error.kind() {
        ReadErrorKind::UnsupportedFormat => (
            "unsupported_format",
            "drawing format is not supported by the XREF reader",
        ),
        ReadErrorKind::NotFound => ("drawing_not_found", "drawing was not found"),
        ReadErrorKind::Unreadable => ("drawing_unreadable", "drawing could not be captured"),
        ReadErrorKind::InvalidDrawing => (
            "unsupported_xref_data",
            "drawing could not be decoded for XREF projection",
        ),
        ReadErrorKind::IncompleteDrawing => (
            "unsupported_xref_data",
            "drawing projection is incomplete for XREF interpretation",
        ),
    };
    XrefError::new(code, message)
}

#[derive(Debug, Clone)]
struct CodePair {
    code: i32,
    value: String,
}

#[derive(Debug, Clone)]
struct DxfObject {
    kind: String,
    pairs: Vec<CodePair>,
}

#[derive(Debug, Clone)]
struct RawBlockRecord {
    handle: Fact<String>,
    name: Fact<String>,
    insertion_units: Fact<PersistedInsertionUnits>,
}

#[derive(Debug, Clone)]
struct RawBlock {
    owner: Fact<String>,
    name: Fact<String>,
    flags: Fact<i64>,
    saved_path: Fact<String>,
    base_point: Fact<XrefPoint3>,
}

#[derive(Debug, Clone)]
struct RawInsert {
    handle: Fact<String>,
    block_name: Fact<String>,
    owner_handle: Fact<String>,
    layer_name: Fact<String>,
    insertion_point: Fact<XrefPoint3>,
    scale: Fact<XrefScale3>,
    rotation_degrees: Fact<f64>,
    normal: Fact<XrefVector3>,
    visibility: Fact<XrefVisibility>,
    placement: XrefPersistedPlacementEvidence,
    clip: XrefPortableClipEvidence,
}

#[derive(Debug, Clone)]
struct RawLayout {
    block_record_handle: Fact<String>,
    name: Fact<String>,
}

#[derive(Debug, Clone)]
struct DwgBlockHeader {
    handle: String,
    data: tables::BlockHeaderData,
    xref_dependent: bool,
    ownership: Result<(), String>,
}

struct DwgInstanceContext<'a> {
    reader: &'a DwgObjectReader,
    headers: &'a [DwgBlockHeader],
    owners: &'a [OwnerEvidence],
    layers: &'a [LayerEvidence],
    entity_owners: &'a HashMap<u64, Vec<u64>>,
    host_units: PersistedInsertionUnits,
}

type DwgInstanceRead = (
    u64,
    XrefPersistedInstanceEvidence,
    XrefPortableClipEvidence,
    Option<(String, String)>,
);

fn unsupported(message: impl Into<String>) -> XrefError {
    XrefError::new("unsupported_xref_data", message)
}

fn fact_reason<T>(fact: &Fact<T>) -> Option<&str> {
    match fact {
        Fact::Proven(_) => None,
        Fact::Unavailable(reason) | Fact::Unsupported(reason) | Fact::Contradictory(reason) => {
            Some(reason)
        }
    }
}

fn required<T: Clone>(fact: &Fact<T>, field: &str, identity: &str) -> Result<T, XrefError> {
    match fact {
        Fact::Proven(value) => Ok(value.clone()),
        Fact::Unavailable(reason) => Err(unsupported(format!(
            "{identity} has unavailable {field}: {reason}"
        ))),
        Fact::Unsupported(reason) => Err(unsupported(format!(
            "{identity} has unsupported {field}: {reason}"
        ))),
        Fact::Contradictory(reason) => Err(unsupported(format!(
            "{identity} has contradictory {field}: {reason}"
        ))),
    }
}

fn canonical_handle(raw: &str, field: &str) -> Result<String, String> {
    let canonical = xref_contract::canonical_input_handle(raw)
        .map_err(|_| format!("{field} `{raw}` is not hexadecimal"))?;
    if canonical == "0" {
        Err(format!("{field} is null"))
    } else {
        Ok(canonical)
    }
}

fn canonical_handle_fact(fact: Fact<String>, field: &str) -> Fact<String> {
    match fact {
        Fact::Proven(raw) => match canonical_handle(&raw, field) {
            Ok(handle) => Fact::Proven(handle),
            Err(reason) => Fact::Unsupported(reason),
        },
        other => other,
    }
}

fn canonical_acadrust_handle(value: u64, field: &str) -> Fact<String> {
    if value == 0 {
        Fact::Unsupported(format!("{field} is null"))
    } else {
        Fact::Proven(format!("{value:X}"))
    }
}

fn finite(value: f64, field: &str) -> Fact<f64> {
    if value.is_finite() {
        Fact::Proven(value)
    } else {
        Fact::Unsupported(format!("{field} is not finite"))
    }
}

fn vector3(value: Vector3, field: &str) -> Fact<XrefPoint3> {
    if value.x.is_finite() && value.y.is_finite() && value.z.is_finite() {
        Fact::Proven(XrefPoint3 {
            x: value.x,
            y: value.y,
            z: value.z,
        })
    } else {
        Fact::Unsupported(format!("{field} contains a non-finite component"))
    }
}

fn persisted_units(code: Option<i64>) -> PersistedInsertionUnits {
    match code {
        None => PersistedInsertionUnits::Unobservable,
        Some(0) => PersistedInsertionUnits::Unitless,
        Some(code) => match insertion_unit(code) {
            Some(value) => PersistedInsertionUnits::Known { value },
            None => PersistedInsertionUnits::UnknownCode { code },
        },
    }
}

fn insertion_unit(code: i64) -> Option<InsertionUnit> {
    Some(match code {
        1 => InsertionUnit::Inches,
        2 => InsertionUnit::Feet,
        3 => InsertionUnit::Miles,
        4 => InsertionUnit::Millimeters,
        5 => InsertionUnit::Centimeters,
        6 => InsertionUnit::Meters,
        7 => InsertionUnit::Kilometers,
        8 => InsertionUnit::Microinches,
        9 => InsertionUnit::Mils,
        10 => InsertionUnit::Yards,
        11 => InsertionUnit::Angstroms,
        12 => InsertionUnit::Nanometers,
        13 => InsertionUnit::Microns,
        14 => InsertionUnit::Decimeters,
        15 => InsertionUnit::Dekameters,
        16 => InsertionUnit::Hectometers,
        17 => InsertionUnit::Gigameters,
        18 => InsertionUnit::AstronomicalUnits,
        19 => InsertionUnit::LightYears,
        20 => InsertionUnit::Parsecs,
        21 => InsertionUnit::UsSurveyFeet,
        22 => InsertionUnit::UsSurveyInches,
        23 => InsertionUnit::UsSurveyYards,
        24 => InsertionUnit::UsSurveyMiles,
        _ => return None,
    })
}

fn metres_per_unit(unit: InsertionUnit) -> Option<f64> {
    Some(match unit {
        InsertionUnit::Unitless => return None,
        InsertionUnit::Inches => 0.0254,
        InsertionUnit::Feet => 0.3048,
        InsertionUnit::Miles => 1609.344,
        InsertionUnit::Millimeters => 0.001,
        InsertionUnit::Centimeters => 0.01,
        InsertionUnit::Meters => 1.0,
        InsertionUnit::Kilometers => 1000.0,
        InsertionUnit::Microinches => 0.000_000_025_4,
        InsertionUnit::Mils => 0.000_025_4,
        InsertionUnit::Yards => 0.9144,
        InsertionUnit::Angstroms => 1e-10,
        InsertionUnit::Nanometers => 1e-9,
        InsertionUnit::Microns => 1e-6,
        InsertionUnit::Decimeters => 0.1,
        InsertionUnit::Dekameters => 10.0,
        InsertionUnit::Hectometers => 100.0,
        InsertionUnit::Gigameters => 1e9,
        InsertionUnit::AstronomicalUnits => 149_597_870_700.0,
        InsertionUnit::LightYears => 9_460_730_472_580_800.0,
        InsertionUnit::Parsecs => 30_856_775_814_913_672.0,
        InsertionUnit::UsSurveyFeet => 1200.0 / 3937.0,
        InsertionUnit::UsSurveyInches => 100.0 / 3937.0,
        InsertionUnit::UsSurveyYards => 3600.0 / 3937.0,
        InsertionUnit::UsSurveyMiles => 6_336_000.0 / 3937.0,
    })
}

fn unit_scaling(
    source: &Fact<PersistedInsertionUnits>,
    host: PersistedInsertionUnits,
    explicit_scale: &Fact<XrefScale3>,
) -> Fact<XrefUnitScaling> {
    let Fact::Proven(PersistedInsertionUnits::Known { value: source }) = source else {
        return Fact::Unavailable("source insertion units do not prove a conversion".to_string());
    };
    let PersistedInsertionUnits::Known { value: host } = host else {
        return Fact::Unavailable("host insertion units do not prove a conversion".to_string());
    };
    let Fact::Proven(scale) = explicit_scale else {
        return Fact::Unavailable("explicit scale is not proven".to_string());
    };
    let (Some(source_metres), Some(host_metres)) =
        (metres_per_unit(*source), metres_per_unit(host))
    else {
        return Fact::Unavailable("unitless conversion requires assumptions".to_string());
    };
    let factor = source_metres / host_metres;
    let effective_scale = XrefScale3 {
        x: scale.x * factor,
        y: scale.y * factor,
        z: scale.z * factor,
    };
    if !factor.is_finite()
        || factor <= 0.0
        || !effective_scale.x.is_finite()
        || !effective_scale.y.is_finite()
        || !effective_scale.z.is_finite()
    {
        return Fact::Unsupported("derived insertion-unit scale is not finite and positive".into());
    }
    Fact::Proven(XrefUnitScaling::Available {
        source_units: XrefUnitValue {
            value: *source,
            basis: XrefUnitBasis::Drawing,
        },
        host_units: XrefUnitValue {
            value: host,
            basis: XrefUnitBasis::Drawing,
        },
        factor,
        effective_scale,
    })
}

fn reject_projection_errors(document: &CadDocument) -> Result<(), XrefError> {
    let has_errors = document
        .notifications
        .iter()
        .any(|notification| notification.notification_type == NotificationType::Error);
    if !has_errors {
        Ok(())
    } else {
        Err(unsupported(
            "drawing reader reported error diagnostics; XREF projection is incomplete",
        ))
    }
}

fn derive_dxf_snapshot(
    bytes: &[u8],
    document: &CadDocument,
) -> Result<XrefSnapshotEvidence, XrefError> {
    if bytes.starts_with(BINARY_DXF_SENTINEL) {
        read_binary_dxf_snapshot(document)
    } else {
        read_ascii_dxf_snapshot(bytes, document)
    }
}

fn read_binary_dxf_snapshot(document: &CadDocument) -> Result<XrefSnapshotEvidence, XrefError> {
    reject_projection_errors(document)?;

    let attachments = document
        .block_records
        .iter()
        .map(|record| {
            let xref_like = record.flags.is_xref
                || record.flags.is_xref_overlay
                || !record.xref_path.is_empty();
            XrefDomainEvidence {
                handle: canonical_acadrust_handle(
                    record.handle.value(),
                    "binary DXF BLOCK_RECORD handle",
                ),
                name: Fact::Proven(record.name.clone()),
                membership: if xref_like {
                    XrefMembershipEvidence::Unsupported(
                        "binary DXF XREF class and provenance are not exposed by the selected parser backend"
                            .to_string(),
                    )
                } else {
                    XrefMembershipEvidence::NotXref
                },
                saved_path: if record.xref_path.is_empty() {
                    Fact::Unsupported("binary DXF saved path provenance is unavailable".into())
                } else {
                    Fact::Proven(record.xref_path.clone())
                },
                load_state: Fact::Unavailable(
                    "binary DXF load state provenance is unavailable".into(),
                ),
                definition_base_point: Fact::Unavailable(
                    "binary DXF BLOCK provenance is unavailable".into(),
                ),
                insertion_units: Fact::Unavailable(
                    "binary DXF block units provenance is unavailable".into(),
                ),
                instances: if xref_like {
                    Fact::Unsupported(
                        "binary DXF INSERT provenance cannot be tied to a direct attachment".into(),
                    )
                } else {
                    Fact::Proven(Vec::new())
                },
            }
        })
        .collect();

    Ok(XrefSnapshotEvidence {
        attachments,
        owners: Vec::new(),
        layers: Vec::new(),
        host_units: Fact::Proven(persisted_units(Some(i64::from(
            document.header.insertion_units,
        )))),
        block_definitions_complete: false,
        owners_complete: false,
        layers_complete: false,
        block_references_complete: false,
        block_references: BTreeMap::new(),
        instance_clips: BTreeMap::new(),
        saved_visretain: Fact::Unavailable("binary DXF VISRETAIN provenance is unavailable".into()),
        saved_xrefoverride: Fact::Unavailable(
            "binary DXF XREFOVERRIDE provenance is unavailable".into(),
        ),
    })
}

fn raw_ascii_pairs(bytes: &[u8]) -> Result<Vec<(i32, Vec<u8>)>, XrefError> {
    let mut lines = bytes.split(|byte| *byte == b'\n');
    let mut pairs = Vec::new();
    while let Some(mut code_line) = lines.next() {
        if code_line.is_empty() && lines.clone().next().is_none() {
            break;
        }
        if code_line.last() == Some(&b'\r') {
            code_line = &code_line[..code_line.len() - 1];
        }
        let Some(mut value_line) = lines.next() else {
            return Err(unsupported(
                "ASCII DXF ends with an unmatched group-code line",
            ));
        };
        if value_line.last() == Some(&b'\r') {
            value_line = &value_line[..value_line.len() - 1];
        }
        let code_text = std::str::from_utf8(code_line)
            .map_err(|_| unsupported("ASCII DXF group code is not ASCII"))?;
        let code = code_text
            .trim()
            .parse::<i32>()
            .map_err(|_| unsupported(format!("invalid ASCII DXF group code `{code_text}`")))?;
        pairs.push((code, value_line.to_vec()));
    }
    Ok(pairs)
}

fn ascii_header_value(
    pairs: &[(i32, Vec<u8>)],
    variable: &[u8],
    value_code: i32,
) -> Result<Option<String>, XrefError> {
    let mut values = Vec::new();
    for window in pairs.windows(2) {
        if window[0].0 == 9 && window[0].1.as_slice() == variable && window[1].0 == value_code {
            let value = std::str::from_utf8(&window[1].1).map_err(|_| {
                unsupported(format!(
                    "{} declaration is not ASCII",
                    String::from_utf8_lossy(variable)
                ))
            })?;
            values.push(value.to_string());
        }
    }
    values.sort();
    values.dedup();
    match values.len() {
        0 => Ok(None),
        1 => Ok(values.pop()),
        _ => Err(unsupported(format!(
            "conflicting repeated {} declarations",
            String::from_utf8_lossy(variable)
        ))),
    }
}

fn known_code_page(label: &str) -> bool {
    matches!(
        label.to_ascii_lowercase().as_str(),
        "gb2312"
            | "ansi_936"
            | "big5"
            | "ansi_950"
            | "korean"
            | "ansi_949"
            | "johab"
            | "ansi_932"
            | "dos437"
            | "dos850"
            | "dos852"
            | "dos855"
            | "dos866"
            | "dos857"
            | "dos860"
            | "dos861"
            | "dos863"
            | "dos865"
            | "dos869"
            | "ansi_874"
            | "ansi_1250"
            | "ansi_1251"
            | "ansi_1252"
            | "ansi_1253"
            | "ansi_1254"
            | "ansi_1255"
            | "ansi_1256"
            | "ansi_1257"
            | "ansi_1258"
            | "iso8859-1"
            | "iso_8859-1"
            | "iso8859-2"
            | "iso_8859-2"
            | "iso8859-3"
            | "iso_8859-3"
            | "iso8859-4"
            | "iso_8859-4"
            | "iso8859-5"
            | "iso_8859-5"
            | "iso8859-6"
            | "iso_8859-6"
            | "iso8859-7"
            | "iso_8859-7"
            | "iso8859-8"
            | "iso_8859-8"
            | "iso8859-9"
            | "iso_8859-9"
            | "iso8859-10"
            | "iso_8859-10"
            | "iso8859-13"
            | "iso_8859-13"
            | "iso8859-14"
            | "iso_8859-14"
            | "iso8859-15"
            | "iso_8859-15"
            | "koi8-r"
            | "koi8-u"
            | "ascii"
            | "utf-8"
            | "utf8"
            | "unicode"
    )
}

fn decode_ascii_pairs(bytes: &[u8]) -> Result<Vec<CodePair>, XrefError> {
    let raw = raw_ascii_pairs(bytes)?;
    let version = ascii_header_value(&raw, b"$ACADVER", 1)?
        .ok_or_else(|| unsupported("ASCII DXF has no unique $ACADVER declaration"))?;
    let version_number = version
        .strip_prefix("AC")
        .and_then(|number| number.parse::<u32>().ok())
        .ok_or_else(|| unsupported(format!("unsupported DXF version declaration `{version}`")))?;
    let code_page = ascii_header_value(&raw, b"$DWGCODEPAGE", 3)?;

    let mut decoded = Vec::with_capacity(raw.len());
    for (code, value) in raw {
        let value = if version_number >= 1021 {
            std::str::from_utf8(&value)
                .map_err(|_| unsupported("AC1021+ ASCII DXF contains non-UTF-8 text"))?
                .to_string()
        } else if let Some(code_page) = code_page.as_deref() {
            if !known_code_page(code_page) {
                return Err(unsupported(format!(
                    "unsupported declared DXF code page `{code_page}`"
                )));
            }
            match code_page.to_ascii_lowercase().as_str() {
                "ascii" => {
                    if !value.iter().all(u8::is_ascii) {
                        return Err(unsupported(
                            "ASCII code page contains a non-ASCII persisted value",
                        ));
                    }
                    String::from_utf8(value).expect("ASCII is UTF-8")
                }
                "utf-8" | "utf8" | "unicode" => std::str::from_utf8(&value)
                    .map_err(|_| unsupported("declared UTF-8 DXF contains invalid UTF-8"))?
                    .to_string(),
                _ => {
                    let encoding = acadrust::io::dxf::code_page::encoding_from_code_page(code_page)
                        .ok_or_else(|| {
                            unsupported(format!("unsupported declared DXF code page `{code_page}`"))
                        })?;
                    let (value, _, malformed) = encoding.decode(&value);
                    if malformed {
                        return Err(unsupported(format!(
                            "persisted text is malformed for declared code page `{code_page}`"
                        )));
                    }
                    value.into_owned()
                }
            }
        } else if value.iter().all(u8::is_ascii) {
            String::from_utf8(value).expect("ASCII is UTF-8")
        } else {
            return Err(unsupported(
                "pre-AC1021 ASCII DXF contains non-ASCII text without $DWGCODEPAGE",
            ));
        };
        decoded.push(CodePair { code, value });
    }
    Ok(decoded)
}

fn collect_dxf_objects(pairs: &[CodePair]) -> Vec<DxfObject> {
    let mut section = String::new();
    let mut table = String::new();
    let mut pending_section = false;
    let mut pending_table = false;
    let mut current: Option<DxfObject> = None;
    let mut objects = Vec::new();

    let flush = |current: &mut Option<DxfObject>, objects: &mut Vec<DxfObject>| {
        if let Some(object) = current.take() {
            objects.push(object);
        }
    };

    for pair in pairs {
        if pair.code == 0 {
            flush(&mut current, &mut objects);
            match pair.value.as_str() {
                "SECTION" => {
                    section.clear();
                    table.clear();
                    pending_section = true;
                    pending_table = false;
                }
                "ENDSEC" => {
                    section.clear();
                    table.clear();
                    pending_section = false;
                    pending_table = false;
                }
                "TABLE" if section == "TABLES" => {
                    table.clear();
                    pending_table = true;
                }
                "ENDTAB" => {
                    table.clear();
                    pending_table = false;
                }
                kind if ((section == "TABLES" && matches!(kind, "BLOCK_RECORD" | "LAYER"))
                    || (section == "BLOCKS" && matches!(kind, "BLOCK" | "INSERT" | "MINSERT"))
                    || (section == "ENTITIES" && matches!(kind, "INSERT" | "MINSERT"))
                    || (section == "OBJECTS" && kind == "LAYOUT"))
                    && (section != "TABLES" || table == kind) =>
                {
                    current = Some(DxfObject {
                        kind: kind.to_string(),
                        pairs: Vec::new(),
                    });
                }
                _ => {}
            }
            continue;
        }

        if pending_section && pair.code == 2 {
            section = pair.value.clone();
            pending_section = false;
            continue;
        }
        if pending_table && pair.code == 2 {
            table = pair.value.clone();
            pending_table = false;
            continue;
        }
        if let Some(object) = &mut current {
            object.pairs.push(pair.clone());
        }
    }
    flush(&mut current, &mut objects);
    objects
}

fn persisted_pairs(object: &DxfObject) -> Result<Vec<&CodePair>, String> {
    let mut depth = 0usize;
    let mut result = Vec::new();
    for pair in &object.pairs {
        if pair.code == 102 {
            if pair.value.starts_with('{') {
                depth += 1;
            } else if pair.value.trim() == "}" {
                if depth == 0 {
                    return Err(format!("{} has an unmatched group 102 close", object.kind));
                }
                depth -= 1;
            }
            continue;
        }
        if depth == 0 {
            result.push(pair);
        }
    }
    if depth == 0 {
        Ok(result)
    } else {
        Err(format!("{} has an unclosed group 102 section", object.kind))
    }
}

fn unique_value<T: Clone + PartialEq>(
    values: impl IntoIterator<Item = Result<T, String>>,
    label: &str,
) -> Fact<T> {
    let mut unique = Vec::new();
    for value in values {
        let value = match value {
            Ok(value) => value,
            Err(reason) => return Fact::Unsupported(reason),
        };
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    match unique.len() {
        0 => Fact::Unavailable(format!("{label} is absent")),
        1 => Fact::Proven(unique.pop().expect("one value")),
        _ => Fact::Contradictory(format!("conflicting repeated {label} values")),
    }
}

fn strings(object: &DxfObject, code: i32, label: &str) -> Fact<String> {
    let pairs = match persisted_pairs(object) {
        Ok(pairs) => pairs,
        Err(reason) => return Fact::Unsupported(reason),
    };
    unique_value(
        pairs
            .into_iter()
            .filter(|pair| pair.code == code)
            .map(|pair| Ok(pair.value.clone())),
        label,
    )
}

fn integers(object: &DxfObject, code: i32, label: &str) -> Fact<i64> {
    let pairs = match persisted_pairs(object) {
        Ok(pairs) => pairs,
        Err(reason) => return Fact::Unsupported(reason),
    };
    unique_value(
        pairs
            .into_iter()
            .filter(|pair| pair.code == code)
            .map(|pair| {
                pair.value
                    .trim()
                    .parse::<i64>()
                    .map_err(|_| format!("{label} `{}` is not an integer", pair.value))
            }),
        label,
    )
}

fn doubles(object: &DxfObject, code: i32, label: &str) -> Fact<f64> {
    let pairs = match persisted_pairs(object) {
        Ok(pairs) => pairs,
        Err(reason) => return Fact::Unsupported(reason),
    };
    unique_value(
        pairs
            .into_iter()
            .filter(|pair| pair.code == code)
            .map(|pair| {
                pair.value
                    .trim()
                    .parse::<f64>()
                    .map_err(|_| format!("{label} `{}` is not numeric", pair.value))
                    .and_then(|value| {
                        value
                            .is_finite()
                            .then_some(value)
                            .ok_or_else(|| format!("{label} is not finite"))
                    })
            }),
        label,
    )
}

fn with_default<T>(fact: Fact<T>, default: T) -> Fact<T> {
    match fact {
        Fact::Unavailable(_) => Fact::Proven(default),
        other => other,
    }
}

fn point_from_codes(
    object: &DxfObject,
    codes: [i32; 3],
    label: &str,
    default_all: bool,
) -> Fact<XrefPoint3> {
    let x = doubles(object, codes[0], &format!("{label} X"));
    let y = doubles(object, codes[1], &format!("{label} Y"));
    let z = with_default(doubles(object, codes[2], &format!("{label} Z")), 0.0);
    let x = if default_all { with_default(x, 0.0) } else { x };
    let y = if default_all { with_default(y, 0.0) } else { y };
    match (x, y, z) {
        (Fact::Proven(x), Fact::Proven(y), Fact::Proven(z)) => Fact::Proven(XrefPoint3 { x, y, z }),
        (Fact::Contradictory(reason), _, _)
        | (_, Fact::Contradictory(reason), _)
        | (_, _, Fact::Contradictory(reason)) => Fact::Contradictory(reason),
        (Fact::Unsupported(reason), _, _)
        | (_, Fact::Unsupported(reason), _)
        | (_, _, Fact::Unsupported(reason)) => Fact::Unsupported(reason),
        (Fact::Unavailable(reason), _, _)
        | (_, Fact::Unavailable(reason), _)
        | (_, _, Fact::Unavailable(reason)) => Fact::Unavailable(reason),
    }
}

fn block_name(object: &DxfObject) -> Fact<String> {
    let primary = strings(object, 2, "BLOCK group 2 name");
    let alternate = strings(object, 3, "BLOCK group 3 name");
    match (primary, alternate) {
        (Fact::Proven(primary), Fact::Proven(alternate)) if primary == alternate => {
            Fact::Proven(primary)
        }
        (Fact::Proven(primary), Fact::Unavailable(_)) => Fact::Proven(primary),
        (Fact::Unavailable(_), Fact::Proven(alternate)) => Fact::Proven(alternate),
        (Fact::Proven(_), Fact::Proven(_)) => {
            Fact::Contradictory("BLOCK group 2 and group 3 names disagree".into())
        }
        (Fact::Contradictory(reason), _) | (_, Fact::Contradictory(reason)) => {
            Fact::Contradictory(reason)
        }
        (Fact::Unsupported(reason), _) | (_, Fact::Unsupported(reason)) => {
            Fact::Unsupported(reason)
        }
        (Fact::Unavailable(reason), Fact::Unavailable(_)) => Fact::Unavailable(reason),
    }
}

fn raw_block_record(object: &DxfObject) -> RawBlockRecord {
    let units = integers(object, 280, "BLOCK_RECORD group 280 units");
    RawBlockRecord {
        handle: canonical_handle_fact(
            strings(object, 5, "BLOCK_RECORD group 5 handle"),
            "BLOCK_RECORD handle",
        ),
        name: strings(object, 2, "BLOCK_RECORD group 2 name"),
        insertion_units: match units {
            Fact::Proven(code) => Fact::Proven(persisted_units(Some(code))),
            Fact::Unavailable(_) => Fact::Proven(PersistedInsertionUnits::Unobservable),
            Fact::Unsupported(reason) => Fact::Unsupported(reason),
            Fact::Contradictory(reason) => Fact::Contradictory(reason),
        },
    }
}

fn raw_block(object: &DxfObject) -> RawBlock {
    RawBlock {
        owner: canonical_handle_fact(strings(object, 330, "BLOCK group 330 owner"), "BLOCK owner"),
        name: block_name(object),
        flags: integers(object, 70, "BLOCK group 70 flags"),
        saved_path: strings(object, 1, "BLOCK group 1 saved path"),
        base_point: point_from_codes(object, [10, 20, 30], "BLOCK base point", true),
    }
}

fn raw_layout(object: &DxfObject) -> RawLayout {
    let pairs = match persisted_pairs(object) {
        Ok(pairs) => pairs,
        Err(reason) => {
            return RawLayout {
                block_record_handle: Fact::Unsupported(reason.clone()),
                name: Fact::Unsupported(reason),
            };
        }
    };
    let layout_start = pairs
        .iter()
        .position(|pair| pair.code == 100 && pair.value == "AcDbLayout");
    let Some(layout_start) = layout_start else {
        return RawLayout {
            block_record_handle: Fact::Unsupported("LAYOUT AcDbLayout subclass is absent".into()),
            name: Fact::Unsupported("LAYOUT AcDbLayout subclass is absent".into()),
        };
    };
    let subclass = &pairs[layout_start + 1..];
    RawLayout {
        block_record_handle: canonical_handle_fact(
            unique_value(
                subclass
                    .iter()
                    .filter(|pair| pair.code == 330)
                    .map(|pair| Ok(pair.value.clone())),
                "LAYOUT AcDbLayout group 330 block-record handle",
            ),
            "LAYOUT block-record handle",
        ),
        name: unique_value(
            subclass
                .iter()
                .filter(|pair| pair.code == 1)
                .map(|pair| Ok(pair.value.clone())),
            "LAYOUT AcDbLayout group 1 name",
        ),
    }
}

fn raw_layer(object: &DxfObject) -> LayerEvidence {
    let flags = with_default(integers(object, 70, "LAYER group 70 flags"), 0);
    let color = with_default(integers(object, 62, "LAYER group 62 color"), 7);
    let plottable = with_default(integers(object, 290, "LAYER group 290 plottable"), 1);
    let line_type = with_default(
        strings(object, 6, "LAYER group 6 linetype"),
        "Continuous".to_string(),
    );
    let line_weight = with_default(integers(object, 370, "LAYER group 370 lineweight"), -3);
    let xref_dependent = match &flags {
        Fact::Proven(flags) => Fact::Proven(flags & 16 != 0),
        Fact::Unavailable(reason) => Fact::Unavailable(reason.clone()),
        Fact::Unsupported(reason) => Fact::Unsupported(reason.clone()),
        Fact::Contradictory(reason) => Fact::Contradictory(reason.clone()),
    };
    let properties = match (flags, color, plottable, line_type, line_weight) {
        (
            Fact::Proven(flags),
            Fact::Proven(color),
            Fact::Proven(plottable),
            Fact::Proven(line_type),
            Fact::Proven(line_weight),
        ) if (-256..=256).contains(&color)
            && matches!(plottable, 0 | 1)
            && i16::try_from(color.unsigned_abs()).is_ok()
            && i16::try_from(line_weight).is_ok() =>
        {
            Fact::Proven(XrefPortableLayerProperties {
                off: color < 0,
                frozen: flags & 1 != 0,
                locked: flags & 4 != 0,
                is_plottable: plottable == 1,
                // DXF True Color (group 420) and Color Book (group 430) are
                // not read here yet — deliberately deferred, see memory
                // `project-xref-bridge-identity-mismatch-root-cause`. Group
                // 62 is always ACI on the wire for this reader today.
                color: XrefPortableLayerColor::Aci(color.unsigned_abs() as i16),
                line_type,
                line_weight: line_weight as i16,
            })
        }
        (Fact::Contradictory(reason), _, _, _, _)
        | (_, Fact::Contradictory(reason), _, _, _)
        | (_, _, Fact::Contradictory(reason), _, _)
        | (_, _, _, Fact::Contradictory(reason), _)
        | (_, _, _, _, Fact::Contradictory(reason)) => Fact::Contradictory(reason),
        (Fact::Unsupported(reason), _, _, _, _)
        | (_, Fact::Unsupported(reason), _, _, _)
        | (_, _, Fact::Unsupported(reason), _, _)
        | (_, _, _, Fact::Unsupported(reason), _)
        | (_, _, _, _, Fact::Unsupported(reason)) => Fact::Unsupported(reason),
        (Fact::Unavailable(reason), _, _, _, _)
        | (_, Fact::Unavailable(reason), _, _, _)
        | (_, _, Fact::Unavailable(reason), _, _)
        | (_, _, _, Fact::Unavailable(reason), _)
        | (_, _, _, _, Fact::Unavailable(reason)) => Fact::Unavailable(reason),
        _ => Fact::Unsupported("LAYER properties are outside supported persisted ranges".into()),
    };
    LayerEvidence {
        handle: canonical_handle_fact(strings(object, 5, "LAYER group 5 handle"), "LAYER handle"),
        name: strings(object, 2, "LAYER group 2 name"),
        xref_dependent,
        properties,
    }
}

fn raw_insert(object: &DxfObject) -> RawInsert {
    let scale = match (
        with_default(doubles(object, 41, "INSERT X scale"), 1.0),
        with_default(doubles(object, 42, "INSERT Y scale"), 1.0),
        with_default(doubles(object, 43, "INSERT Z scale"), 1.0),
    ) {
        (Fact::Proven(x), Fact::Proven(y), Fact::Proven(z)) => Fact::Proven(XrefScale3 { x, y, z }),
        (Fact::Contradictory(reason), _, _)
        | (_, Fact::Contradictory(reason), _)
        | (_, _, Fact::Contradictory(reason)) => Fact::Contradictory(reason),
        (Fact::Unsupported(reason), _, _)
        | (_, Fact::Unsupported(reason), _)
        | (_, _, Fact::Unsupported(reason)) => Fact::Unsupported(reason),
        (Fact::Unavailable(reason), _, _)
        | (_, Fact::Unavailable(reason), _)
        | (_, _, Fact::Unavailable(reason)) => Fact::Unavailable(reason),
    };
    let normal = match point_from_codes(object, [210, 220, 230], "INSERT normal", true) {
        Fact::Proven(XrefPoint3 {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        }) => Fact::Proven(XrefVector3 {
            x: 0.0,
            y: 0.0,
            z: 1.0,
        }),
        Fact::Proven(point) => Fact::Proven(XrefVector3 {
            x: point.x,
            y: point.y,
            z: point.z,
        }),
        Fact::Unavailable(reason) => Fact::Unavailable(reason),
        Fact::Unsupported(reason) => Fact::Unsupported(reason),
        Fact::Contradictory(reason) => Fact::Contradictory(reason),
    };
    let visibility = match with_default(integers(object, 60, "INSERT visibility"), 0) {
        Fact::Proven(0) => Fact::Proven(XrefVisibility::Visible),
        Fact::Proven(1) => Fact::Proven(XrefVisibility::Hidden),
        Fact::Proven(value) => {
            Fact::Unsupported(format!("INSERT visibility `{value}` is outside 0..=1"))
        }
        Fact::Unavailable(reason) => Fact::Unavailable(reason),
        Fact::Unsupported(reason) => Fact::Unsupported(reason),
        Fact::Contradictory(reason) => Fact::Contradictory(reason),
    };
    let array_codes_present = object.kind == "MINSERT"
        || object
            .pairs
            .iter()
            .any(|pair| matches!(pair.code, 70 | 71 | 44 | 45));
    let placement = if array_codes_present {
        let rows = with_default(integers(object, 71, "MINSERT row count"), 1);
        let columns = with_default(integers(object, 70, "MINSERT column count"), 1);
        let row_spacing = with_default(doubles(object, 45, "MINSERT row spacing"), 0.0);
        let column_spacing = with_default(doubles(object, 44, "MINSERT column spacing"), 0.0);
        let array = match (rows, columns, row_spacing, column_spacing) {
            (Fact::Contradictory(reason), _, _, _)
            | (_, Fact::Contradictory(reason), _, _)
            | (_, _, Fact::Contradictory(reason), _)
            | (_, _, _, Fact::Contradictory(reason)) => Fact::Contradictory(reason),
            (Fact::Unsupported(reason), _, _, _)
            | (_, Fact::Unsupported(reason), _, _)
            | (_, _, Fact::Unsupported(reason), _)
            | (_, _, _, Fact::Unsupported(reason)) => Fact::Unsupported(reason),
            (Fact::Unavailable(reason), _, _, _)
            | (_, Fact::Unavailable(reason), _, _)
            | (_, _, Fact::Unavailable(reason), _)
            | (_, _, _, Fact::Unavailable(reason)) => Fact::Unavailable(reason),
            (
                Fact::Proven(rows),
                Fact::Proven(columns),
                Fact::Proven(row_spacing),
                Fact::Proven(column_spacing),
            ) if (1..=65_535).contains(&rows) && (1..=65_535).contains(&columns) => {
                Fact::Proven(Some(XrefRectangularArray {
                    rows: rows as u32,
                    columns: columns as u32,
                    row_spacing,
                    column_spacing,
                }))
            }
            (Fact::Proven(rows), Fact::Proven(columns), Fact::Proven(_), Fact::Proven(_)) => {
                Fact::Unsupported(format!(
                    "MINSERT counts ({rows}, {columns}) are outside 1..=65535"
                ))
            }
        };
        XrefPersistedPlacementEvidence {
            placement_kind: Fact::Proven(XrefPlacementKind::RectangularArray),
            array,
        }
    } else {
        XrefPersistedPlacementEvidence {
            placement_kind: Fact::Proven(XrefPlacementKind::Single),
            array: Fact::Proven(None),
        }
    };

    RawInsert {
        handle: canonical_handle_fact(strings(object, 5, "INSERT group 5 handle"), "INSERT handle"),
        block_name: strings(object, 2, "INSERT group 2 block name"),
        owner_handle: canonical_handle_fact(
            strings(object, 330, "INSERT group 330 owner"),
            "INSERT owner",
        ),
        layer_name: with_default(strings(object, 8, "INSERT group 8 layer"), "0".to_string()),
        insertion_point: point_from_codes(object, [10, 20, 30], "INSERT point", false),
        scale,
        rotation_degrees: with_default(doubles(object, 50, "INSERT rotation"), 0.0),
        normal,
        visibility,
        placement,
        clip: insert_clip_evidence(object),
    }
}

fn insert_clip_evidence(object: &DxfObject) -> XrefPortableClipEvidence {
    if object
        .pairs
        .iter()
        .any(|pair| pair.code == 102 && pair.value.eq_ignore_ascii_case("{ACAD_XDICTIONARY"))
    {
        // The selected backend does not expose enough dictionary/SPATIAL_FILTER
        // linkage to distinguish a clip from unrelated extension data.
        XrefPortableClipEvidence::Unproven
    } else {
        XrefPortableClipEvidence::Absent
    }
}

fn reference_type_from_flags(is_xref: bool, is_xref_overlay: bool) -> Option<ReferenceType> {
    // XREF and overlay are combinable persisted flags.  The overlay flag
    // refines the XREF kind rather than contradicting the general XREF flag.
    if is_xref_overlay {
        Some(ReferenceType::Overlay)
    } else if is_xref {
        Some(ReferenceType::Attachment)
    } else {
        None
    }
}

fn membership_from_flags(flags: &Fact<i64>) -> XrefMembershipEvidence {
    let Fact::Proven(flags) = flags else {
        return match flags {
            Fact::Unavailable(reason) => XrefMembershipEvidence::Unavailable(reason.clone()),
            Fact::Unsupported(reason) => XrefMembershipEvidence::Unsupported(reason.clone()),
            Fact::Contradictory(reason) => XrefMembershipEvidence::Contradictory(reason.clone()),
            Fact::Proven(_) => unreachable!(),
        };
    };
    let reference = reference_type_from_flags(flags & 4 != 0, flags & 8 != 0);
    let external = flags & 16 != 0;
    match (reference, external) {
        (None, _) => XrefMembershipEvidence::NotXref,
        (Some(reference), false) => XrefMembershipEvidence::Direct(reference),
        (Some(reference), true) => XrefMembershipEvidence::External(reference),
    }
}

fn same_proven<T: PartialEq>(left: &Fact<T>, right: &Fact<T>) -> Option<bool> {
    match (left, right) {
        (Fact::Proven(left), Fact::Proven(right)) => Some(left == right),
        _ => None,
    }
}

fn owner_for_record<'a>(record: &RawBlockRecord, blocks: &'a [RawBlock]) -> Vec<&'a RawBlock> {
    let Fact::Proven(record_handle) = &record.handle else {
        return Vec::new();
    };
    blocks
        .iter()
        .filter(|block| matches!(&block.owner, Fact::Proven(owner) if owner == record_handle))
        .collect()
}

fn owner_catalog(records: &[RawBlockRecord], layouts: &[RawLayout]) -> Vec<OwnerEvidence> {
    records
        .iter()
        .map(|record| {
            let (owner_type, name) = match &record.name {
                Fact::Proven(name) if name.eq_ignore_ascii_case("*Model_Space") => (
                    Fact::Proven(XrefOwnerType::ModelSpace),
                    Fact::Proven("Model".to_string()),
                ),
                Fact::Proven(name) => {
                    let layout_matches = layouts
                        .iter()
                        .filter(|layout| {
                            same_proven(&layout.block_record_handle, &record.handle) == Some(true)
                        })
                        .collect::<Vec<_>>();
                    if layout_matches.len() == 1 {
                        (
                            Fact::Proven(XrefOwnerType::PaperSpace),
                            layout_matches[0].name.clone(),
                        )
                    } else if layout_matches.len() > 1 {
                        (
                            Fact::Proven(XrefOwnerType::PaperSpace),
                            Fact::Contradictory(
                                "more than one LAYOUT names the same block record".into(),
                            ),
                        )
                    } else if name.to_ascii_uppercase().starts_with("*PAPER_SPACE") {
                        (
                            Fact::Proven(XrefOwnerType::PaperSpace),
                            Fact::Unavailable("paper-space LAYOUT name is absent".into()),
                        )
                    } else {
                        (
                            Fact::Proven(XrefOwnerType::BlockDefinition),
                            Fact::Proven(name.clone()),
                        )
                    }
                }
                Fact::Unavailable(reason) => (
                    Fact::Unavailable(reason.clone()),
                    Fact::Unavailable(reason.clone()),
                ),
                Fact::Unsupported(reason) => (
                    Fact::Unsupported(reason.clone()),
                    Fact::Unsupported(reason.clone()),
                ),
                Fact::Contradictory(reason) => (
                    Fact::Contradictory(reason.clone()),
                    Fact::Contradictory(reason.clone()),
                ),
            };
            OwnerEvidence {
                handle: record.handle.clone(),
                owner_type,
                name,
            }
        })
        .collect()
}

fn resolve_fact_by_name<T: Clone>(
    wanted: &Fact<String>,
    candidates: &[(Fact<String>, T)],
    label: &str,
) -> Fact<T> {
    let Fact::Proven(wanted) = wanted else {
        return match wanted {
            Fact::Unavailable(reason) => Fact::Unavailable(reason.clone()),
            Fact::Unsupported(reason) => Fact::Unsupported(reason.clone()),
            Fact::Contradictory(reason) => Fact::Contradictory(reason.clone()),
            Fact::Proven(_) => unreachable!(),
        };
    };
    let matches = candidates
        .iter()
        .filter(|(name, _)| matches!(name, Fact::Proven(name) if xref_contract::xref_name_eq(name, wanted)))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [(_, value)] => Fact::Proven((*value).clone()),
        [] => Fact::Unsupported(format!("{label} `{wanted}` does not resolve")),
        _ => Fact::Contradictory(format!("{label} `{wanted}` resolves more than once")),
    }
}

fn instance_from_ascii(
    raw: RawInsert,
    attachment: &RawBlockRecord,
    owners: &[OwnerEvidence],
    layers: &[LayerEvidence],
    host_units: PersistedInsertionUnits,
) -> XrefPersistedInstanceEvidence {
    let owner = match &raw.owner_handle {
        Fact::Proven(handle) => owners
            .iter()
            .filter(|owner| matches!(&owner.handle, Fact::Proven(value) if value == handle))
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    let (owner_type, owner_name) = match owner.as_slice() {
        [owner] => (owner.owner_type.clone(), owner.name.clone()),
        [] => {
            let reason = fact_reason(&raw.owner_handle)
                .unwrap_or("INSERT owner does not resolve")
                .to_string();
            (Fact::Unsupported(reason.clone()), Fact::Unsupported(reason))
        }
        _ => (
            Fact::Contradictory("INSERT owner handle resolves more than once".into()),
            Fact::Contradictory("INSERT owner handle resolves more than once".into()),
        ),
    };
    let layer_candidates = layers
        .iter()
        .map(|layer| (layer.name.clone(), layer.handle.clone()))
        .collect::<Vec<_>>();
    let layer_handle = match resolve_fact_by_name(
        &raw.layer_name,
        &layer_candidates
            .iter()
            .map(|(name, handle)| (name.clone(), handle.clone()))
            .collect::<Vec<_>>(),
        "INSERT layer",
    ) {
        Fact::Proven(Fact::Proven(handle)) => Fact::Proven(handle),
        Fact::Proven(Fact::Unavailable(reason)) => Fact::Unavailable(reason),
        Fact::Proven(Fact::Unsupported(reason)) => Fact::Unsupported(reason),
        Fact::Proven(Fact::Contradictory(reason)) => Fact::Contradictory(reason),
        Fact::Unavailable(reason) => Fact::Unavailable(reason),
        Fact::Unsupported(reason) => Fact::Unsupported(reason),
        Fact::Contradictory(reason) => Fact::Contradictory(reason),
    };
    let unit_scaling = unit_scaling(&attachment.insertion_units, host_units, &raw.scale);

    XrefPersistedInstanceEvidence {
        handle: raw.handle,
        attachment_handle: attachment.handle.clone(),
        attachment_name: attachment.name.clone(),
        owner_handle: raw.owner_handle,
        owner_type,
        owner_name,
        layer_handle,
        layer_name: raw.layer_name,
        insertion_point: raw.insertion_point,
        scale: raw.scale,
        rotation_degrees: raw.rotation_degrees,
        normal: raw.normal,
        visibility: raw.visibility,
        placement: raw.placement,
        unit_scaling,
    }
}

fn read_ascii_dxf_snapshot(
    bytes: &[u8],
    document: &CadDocument,
) -> Result<XrefSnapshotEvidence, XrefError> {
    reject_projection_errors(document)?;
    let pairs = decode_ascii_pairs(bytes)?;
    let objects = collect_dxf_objects(&pairs);

    let records = objects
        .iter()
        .filter(|object| object.kind == "BLOCK_RECORD")
        .map(raw_block_record)
        .collect::<Vec<_>>();
    let blocks = objects
        .iter()
        .filter(|object| object.kind == "BLOCK")
        .map(raw_block)
        .collect::<Vec<_>>();
    let layouts = objects
        .iter()
        .filter(|object| object.kind == "LAYOUT")
        .map(raw_layout)
        .collect::<Vec<_>>();
    let owners = owner_catalog(&records, &layouts);
    let layers = objects
        .iter()
        .filter(|object| object.kind == "LAYER")
        .map(raw_layer)
        .collect::<Vec<_>>();
    let raw_instances = objects
        .iter()
        .filter(|object| matches!(object.kind.as_str(), "INSERT" | "MINSERT"))
        .map(raw_insert)
        .collect::<Vec<_>>();

    let host_units = header_variable_i64(&pairs, "$INSUNITS", 70)
        .map(|code| persisted_units(Some(code)))
        .unwrap_or(PersistedInsertionUnits::Unobservable);

    let mut block_references: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut instance_clips = BTreeMap::new();
    let mut block_references_complete = true;
    for insert in &raw_instances {
        let (Fact::Proven(handle), Fact::Proven(owner), Fact::Proven(block_name)) =
            (&insert.handle, &insert.owner_handle, &insert.block_name)
        else {
            block_references_complete = false;
            continue;
        };
        instance_clips.insert(handle.clone(), insert.clip);
        let matches = records
            .iter()
            .filter(|record| {
                matches!(&record.name, Fact::Proven(name) if xref_contract::xref_name_eq(name, block_name))
            })
            .collect::<Vec<_>>();
        let [record] = matches.as_slice() else {
            block_references_complete = false;
            continue;
        };
        let Fact::Proven(referenced) = &record.handle else {
            block_references_complete = false;
            continue;
        };
        block_references
            .entry(owner.clone())
            .or_default()
            .push(referenced.clone());
    }
    for references in block_references.values_mut() {
        references.sort_by(|left, right| {
            let left = u64::from_str_radix(left, 16).unwrap_or(u64::MAX);
            let right = u64::from_str_radix(right, 16).unwrap_or(u64::MAX);
            left.cmp(&right)
        });
        references.dedup();
    }

    let mut attachments = Vec::with_capacity(records.len());
    for record in &records {
        let owner_matches = owner_for_record(record, &blocks);
        let block = (owner_matches.len() == 1).then(|| owner_matches[0]);
        let mut membership = block
            .map(|block| membership_from_flags(&block.flags))
            .unwrap_or_else(|| {
                let projected_xref = match &record.name {
                    Fact::Proven(name) => document.block_records.iter().any(|candidate| {
                        xref_contract::xref_name_eq(&candidate.name, name)
                            && (candidate.flags.is_xref
                                || candidate.flags.is_xref_overlay
                                || !candidate.xref_path.is_empty())
                    }),
                    _ => false,
                };
                if projected_xref {
                    XrefMembershipEvidence::Unsupported(
                        "projected XREF has no unique owner-linked persisted BLOCK".into(),
                    )
                } else {
                    XrefMembershipEvidence::NotXref
                }
            });

        if owner_matches.len() > 1 {
            membership = XrefMembershipEvidence::Contradictory(
                "more than one BLOCK uses the same BLOCK_RECORD owner handle".into(),
            );
        }
        if let Some(block) = block {
            if same_proven(&record.name, &block.name) == Some(false) {
                membership = XrefMembershipEvidence::Contradictory(
                    "owner-linked BLOCK_RECORD and BLOCK names disagree".into(),
                );
            } else if fact_reason(&record.name).is_some()
                && !matches!(membership, XrefMembershipEvidence::NotXref)
            {
                membership = XrefMembershipEvidence::Unsupported(
                    "XREF BLOCK_RECORD name is not proven".into(),
                );
            }
        }

        let instances = match &record.name {
            Fact::Proven(name) => {
                let matching = raw_instances
                    .iter()
                    .filter(|instance| {
                        matches!(&instance.block_name, Fact::Proven(block_name) if xref_contract::xref_name_eq(block_name, name))
                    })
                    .cloned()
                    .map(|instance| instance_from_ascii(instance, record, &owners, &layers, host_units))
                    .collect::<Vec<_>>();
                Fact::Proven(matching)
            }
            Fact::Unavailable(reason) => Fact::Unavailable(reason.clone()),
            Fact::Unsupported(reason) => Fact::Unsupported(reason.clone()),
            Fact::Contradictory(reason) => Fact::Contradictory(reason.clone()),
        };

        attachments.push(XrefDomainEvidence {
            handle: record.handle.clone(),
            name: record.name.clone(),
            membership,
            saved_path: block
                .map(|block| block.saved_path.clone())
                .unwrap_or_else(|| Fact::Unavailable("owner-linked BLOCK is absent".into())),
            load_state: Fact::Unavailable(
                "portable DXF does not prove persisted loaded state".into(),
            ),
            definition_base_point: block
                .map(|block| block.base_point.clone())
                .unwrap_or_else(|| Fact::Unavailable("owner-linked BLOCK is absent".into())),
            insertion_units: record.insertion_units.clone(),
            instances,
        });
    }

    for block in &blocks {
        let membership = membership_from_flags(&block.flags);
        if matches!(membership, XrefMembershipEvidence::NotXref)
            || records
                .iter()
                .any(|record| same_proven(&record.handle, &block.owner) == Some(true))
        {
            continue;
        }
        attachments.push(XrefDomainEvidence {
            handle: Fact::Unsupported("DXF BLOCK has no persisted BLOCK_RECORD identity".into()),
            name: block.name.clone(),
            membership,
            saved_path: block.saved_path.clone(),
            load_state: Fact::Unavailable("portable DXF does not prove load state".into()),
            definition_base_point: block.base_point.clone(),
            insertion_units: Fact::Unavailable("BLOCK_RECORD units are unavailable".into()),
            instances: Fact::Unsupported("attachment identity is unavailable".into()),
        });
    }

    if raw_instances
        .iter()
        .any(|instance| !matches!(instance.block_name, Fact::Proven(_)))
    {
        for attachment in &mut attachments {
            if matches!(attachment.membership, XrefMembershipEvidence::Direct(_)) {
                attachment.instances = Fact::Unsupported(
                    "an INSERT block name is unproven, so direct XREF instance counts are incomplete"
                        .into(),
                );
            }
        }
    }

    mark_duplicate_attachment_handles(&mut attachments);
    mark_duplicate_instance_handles(&mut attachments);

    Ok(XrefSnapshotEvidence {
        attachments,
        owners,
        layers,
        host_units: Fact::Proven(host_units),
        block_definitions_complete: records.iter().all(|record| {
            matches!(record.handle, Fact::Proven(_)) && matches!(record.name, Fact::Proven(_))
        }),
        owners_complete: records.len() == document.block_records.len(),
        layers_complete: true,
        block_references_complete,
        block_references,
        instance_clips,
        saved_visretain: header_binary_variable_fact(&pairs, "$VISRETAIN"),
        saved_xrefoverride: header_binary_variable_fact(&pairs, "$XREFOVERRIDE"),
    })
}

fn header_variable_i64(pairs: &[CodePair], variable: &str, code: i32) -> Option<i64> {
    let mut result = None;
    for window in pairs.windows(2) {
        if window[0].code == 9 && window[0].value == variable && window[1].code == code {
            let value = window[1].value.trim().parse::<i64>().ok()?;
            match result {
                None => result = Some(value),
                Some(existing) if existing == value => {}
                Some(_) => return None,
            }
        }
    }
    result
}

fn header_binary_variable_fact(pairs: &[CodePair], variable: &str) -> Fact<i16> {
    let mut values = Vec::new();
    for window in pairs.windows(2) {
        if window[0].code == 9 && window[0].value == variable && window[1].code == 70 {
            let value = match window[1].value.trim().parse::<i16>() {
                Ok(value @ (0 | 1)) => value,
                Ok(value) => {
                    return Fact::Unsupported(format!("{variable} value {value} is outside 0..=1"))
                }
                Err(_) => return Fact::Unsupported(format!("{variable} is not an integer")),
            };
            if !values.contains(&value) {
                values.push(value);
            }
        }
    }
    match values.as_slice() {
        [value] => Fact::Proven(*value),
        [] => Fact::Unavailable(format!(
            "{variable} is absent from the persisted DXF header"
        )),
        _ => Fact::Contradictory(format!("{variable} has conflicting persisted values")),
    }
}

fn mark_duplicate_attachment_handles(attachments: &mut [XrefDomainEvidence]) {
    let mut counts = HashMap::new();
    for attachment in attachments.iter() {
        if let Fact::Proven(handle) = &attachment.handle {
            *counts.entry(handle.clone()).or_insert(0usize) += 1;
        }
    }
    for attachment in attachments {
        if let Fact::Proven(handle) = &attachment.handle {
            if counts.get(handle).copied().unwrap_or_default() > 1 {
                attachment.handle = Fact::Contradictory(format!(
                    "persisted attachment handle `{handle}` occurs more than once"
                ));
                attachment.membership = XrefMembershipEvidence::Contradictory(
                    "persisted attachment identity is duplicated".into(),
                );
            }
        }
    }
}

fn mark_duplicate_instance_handles(attachments: &mut [XrefDomainEvidence]) {
    let mut counts = HashMap::new();
    for attachment in attachments.iter() {
        if let Fact::Proven(instances) = &attachment.instances {
            for instance in instances {
                if let Fact::Proven(handle) = &instance.handle {
                    *counts.entry(handle.clone()).or_insert(0usize) += 1;
                }
            }
        }
    }
    for attachment in attachments {
        if let Fact::Proven(instances) = &mut attachment.instances {
            for instance in instances {
                if let Fact::Proven(handle) = &instance.handle {
                    if counts.get(handle).copied().unwrap_or_default() > 1 {
                        instance.handle = Fact::Contradictory(format!(
                            "persisted instance handle `{handle}` occurs more than once"
                        ));
                    }
                }
            }
        }
    }
}

fn low_level_dwg_reader(bytes: &[u8]) -> Result<DwgObjectReader, XrefError> {
    let mut reader = DwgReader::from_stream(Cursor::new(bytes.to_vec()));
    let info = reader
        .read_file_header()
        .map_err(|error| unsupported(format!("failed to read captured DWG header: {error}")))?;
    let dxf_version = DxfVersion::parse(&info.version_string)
        .ok_or_else(|| unsupported(format!("unsupported DWG version `{}`", info.version_string)))?;
    let handle_bytes = reader
        .get_section_buffer("AcDb:Handles", &info)
        .map_err(|error| unsupported(format!("failed to read DWG handle section: {error}")))?;
    let mut handles = read_handles(&handle_bytes)
        .map_err(|error| unsupported(format!("failed to decode DWG handle section: {error}")))?;
    if info.objects_base_offset != 0 {
        for offset in handles.values_mut() {
            *offset -= info.objects_base_offset;
        }
    }
    let objects = reader
        .get_section_buffer("AcDb:AcDbObjects", &info)
        .map_err(|error| unsupported(format!("failed to read DWG object section: {error}")))?;
    DwgObjectReader::new(objects, dxf_version, handles)
        .map_err(|error| unsupported(format!("failed to initialize DWG object reader: {error}")))
}

fn read_dwg_xref_dependent(
    reader: &DwgObjectReader,
    offset: usize,
) -> Result<(u64, String, bool), String> {
    let (type_code, mut record) = reader
        .read_record_at(offset)
        .map_err(|error| error.to_string())?;
    if type_code != OBJ_BLOCK_HEADER {
        return Err(format!("object type {type_code} is not BLOCK_HEADER"));
    }
    let common = reader.read_common_non_entity_data(&mut record, type_code);
    let name = record.read_variable_text();
    let xref_dependent = if reader.version().r2007_plus() {
        record.read_bit_short() & 0x100 != 0
    } else {
        let _xref_64 = record.read_bit();
        let _xref_index = record.read_bit_short();
        record.read_bit()
    };
    Ok((common.common.handle, name, xref_dependent))
}

fn verify_dwg_marker(
    reader: &DwgObjectReader,
    handle: u64,
    expected_type: i16,
    owner: u64,
    expected_name: Option<&str>,
) -> Result<(), String> {
    if handle == 0 {
        return Err("structural marker handle is null".into());
    }
    let offset = reader
        .offset_for(handle)
        .ok_or_else(|| format!("structural marker {handle:X} is absent from handle map"))?;
    let (type_code, mut record) = reader
        .read_record_at(offset as usize)
        .map_err(|error| error.to_string())?;
    if type_code != expected_type {
        return Err(format!(
            "structural marker {handle:X} has type {type_code}, expected {expected_type}"
        ));
    }
    let common = reader.read_common_entity_data(&mut record, type_code);
    if common.common.handle != handle || common.owner_handle != owner {
        return Err(format!(
            "structural marker {handle:X} handle/owner disagrees with BLOCK_HEADER {owner:X}"
        ));
    }
    if let Some(expected_name) = expected_name {
        let name = record.read_variable_text();
        if name != expected_name {
            return Err(format!(
                "BLOCK marker name `{name}` disagrees with BLOCK_HEADER `{expected_name}`"
            ));
        }
    }
    Ok(())
}

/// Independently locates the DWG BLOCK_CONTROL record and reads its
/// authoritative `*Model_Space` / `*Paper_Space` hard-owner handles. There is
/// exactly one BLOCK_CONTROL per file; returns `None` if it cannot be found
/// or decoded, in which case the caller falls back to the file header's
/// (less reliable) `model_space_block_handle` / `paper_space_block_handle`.
fn read_dwg_block_control(reader: &DwgObjectReader) -> Option<(u64, u64)> {
    for handle in reader.handles() {
        let offset = reader.offset_for(handle).filter(|offset| *offset >= 0)?;
        let Ok((type_code, mut record)) = reader.read_record_at(offset as usize) else {
            continue;
        };
        if type_code != OBJ_BLOCK_CONTROL {
            continue;
        }
        let _common = reader.read_common_non_entity_data(&mut record, type_code);
        let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tables::read_block_control(&mut record)
        }));
        if let Ok(data) = parsed {
            return Some((data.model_space_handle, data.paper_space_handle));
        }
    }
    None
}

/// Reproduces acadrust's own BLOCK_HEADER name-deduplication so the
/// independent reader's block-definition name evidence agrees, handle for
/// handle, with what ends up in acadrust's `document.block_records`.
///
/// The DWG binary format stores every paper-space block record on disk
/// under the literal name `*Paper_Space`, and anonymous blocks (dimensions,
/// hatches, …) share bases like `*D`, `*U`. Both acadrust and this reader
/// parse the same raw per-record name via `acadrust::tables::read_block_header`,
/// so without this step every duplicate-named handle here would carry the
/// bare on-disk name while acadrust's document model carries its
/// deduplicated name for all but one of them — see memory
/// `project-xref-bridge-identity-mismatch-root-cause`.
///
/// Matches acadrust's algorithm exactly: group headers by raw name in
/// ascending-handle order (the order `headers` is already in); a group of
/// one is left alone; a larger group picks the entry whose handle equals
/// the authoritative model/paper-space handle as canonical for the
/// `*Model_Space` / `*Paper_Space` bases (falling back to the first entry,
/// as for every other base), and suffixes every other member
/// `{base}{index}` with `index` counting up from 0 in that same order.
fn canonicalize_block_header_names(
    headers: &mut [DwgBlockHeader],
    model_space_handle: Option<u64>,
    paper_space_handle: Option<u64>,
) {
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (idx, header) in headers.iter().enumerate() {
        groups
            .entry(header.data.name.clone())
            .or_default()
            .push(idx);
    }
    for (base_name, indices) in groups {
        if indices.len() <= 1 {
            continue;
        }
        let active_handle = match base_name.as_str() {
            "*Model_Space" => model_space_handle,
            "*Paper_Space" => paper_space_handle,
            _ => None,
        };
        let canonical_idx = active_handle
            .and_then(|active| {
                indices
                    .iter()
                    .copied()
                    .find(|&idx| u64::from_str_radix(&headers[idx].handle, 16).ok() == Some(active))
            })
            .unwrap_or(indices[0]);
        let mut suffix = 0u32;
        for idx in indices {
            if idx == canonical_idx {
                continue;
            }
            headers[idx].data.name = format!("{base_name}{suffix}");
            suffix += 1;
        }
    }
}

fn read_dwg_headers(reader: &DwgObjectReader) -> Vec<DwgBlockHeader> {
    let mut result = Vec::new();
    let mut handles = reader.handles();
    handles.sort_unstable();
    for handle in handles {
        let Some(offset) = reader.offset_for(handle).filter(|offset| *offset >= 0) else {
            continue;
        };
        let Ok((type_code, mut record)) = reader.read_record_at(offset as usize) else {
            continue;
        };
        if type_code != OBJ_BLOCK_HEADER {
            continue;
        }
        let common = reader.read_common_non_entity_data(&mut record, type_code);
        let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tables::read_block_header(&mut record, reader.version())
        }));
        let Ok(data) = parsed else {
            continue;
        };
        let recovered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            read_dwg_xref_dependent(reader, offset as usize)
        }));
        let (recovered_handle, recovered_name, xref_dependent) = match recovered {
            Ok(Ok(value)) => value,
            Ok(Err(reason)) => {
                result.push(DwgBlockHeader {
                    handle: format!("{:X}", common.common.handle),
                    data,
                    xref_dependent: false,
                    ownership: Err(reason),
                });
                continue;
            }
            Err(_) => {
                result.push(DwgBlockHeader {
                    handle: format!("{:X}", common.common.handle),
                    data,
                    xref_dependent: false,
                    ownership: Err("DWG dependency-bit reread panicked".into()),
                });
                continue;
            }
        };
        let mut ownership = if common.common.handle == handle
            && recovered_handle == handle
            && recovered_name == data.name
        {
            Ok(())
        } else {
            Err("DWG BLOCK_HEADER handle/name rereads disagree".into())
        };
        if ownership.is_ok() {
            ownership = verify_dwg_marker(
                reader,
                data.block_entity_handle,
                OBJ_BLOCK,
                handle,
                Some(&data.name),
            )
            .and_then(|_| verify_dwg_marker(reader, data.endblk_handle, OBJ_ENDBLK, handle, None));
        }
        result.push(DwgBlockHeader {
            handle: format!("{handle:X}"),
            data,
            xref_dependent,
            ownership,
        });
    }
    result
}

fn read_dwg_layers(reader: &DwgObjectReader, document: &CadDocument) -> Vec<LayerEvidence> {
    let mut result = Vec::new();
    for handle in reader.handles() {
        let Some(offset) = reader.offset_for(handle).filter(|offset| *offset >= 0) else {
            continue;
        };
        let Ok((type_code, mut record)) = reader.read_record_at(offset as usize) else {
            continue;
        };
        if type_code != OBJ_LAYER {
            continue;
        }
        let common = reader.read_common_non_entity_data(&mut record, type_code);
        let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tables::read_layer(&mut record, reader.version(), reader.dxf_version())
        }));
        match parsed {
            Ok(data) => {
                let line_types = document
                    .line_types
                    .iter()
                    .filter(|line_type| line_type.handle.value() == data.linetype_handle)
                    .collect::<Vec<_>>();
                // AutoCAD Color Index and True Color (RGB) are both fully
                // round-trippable through the backend's own `Color` model —
                // only `ByLayer`/`ByBlock` on a *layer itself* would be a
                // genuinely nonsensical persisted value, which `index()`
                // still resolves (0/256) so this covers every real case.
                let color = if let acadrust::types::Color::Rgb { r, g, b } = data.color {
                    Some(XrefPortableLayerColor::TrueColor { r, g, b })
                } else {
                    data.color
                        .index()
                        .and_then(|index| i16::try_from(index).ok())
                        .map(XrefPortableLayerColor::Aci)
                };
                let properties = match (color, line_types.as_slice()) {
                    (Some(color), [line_type]) => Fact::Proven(XrefPortableLayerProperties {
                        off: data.off,
                        frozen: data.frozen,
                        locked: data.locked,
                        is_plottable: data.plottable,
                        color,
                        line_type: line_type.name.clone(),
                        line_weight: data.line_weight,
                    }),
                    (None, _) => Fact::Unsupported(
                        "DWG LAYER color is outside the persisted ranges this reader can prove"
                            .into(),
                    ),
                    (_, []) => {
                        Fact::Unsupported("DWG LAYER linetype handle does not resolve".into())
                    }
                    (_, _) => Fact::Contradictory(
                        "DWG LAYER linetype handle resolves more than once".into(),
                    ),
                };
                result.push(LayerEvidence {
                    handle: canonical_acadrust_handle(common.common.handle, "DWG LAYER handle"),
                    name: Fact::Proven(data.name),
                    xref_dependent: Fact::Proven(data.xref_dependent),
                    properties,
                });
            }
            Err(_) => result.push(LayerEvidence {
                handle: canonical_acadrust_handle(common.common.handle, "DWG LAYER handle"),
                name: Fact::Unsupported("DWG LAYER parser panicked".into()),
                xref_dependent: Fact::Unsupported("DWG LAYER parser panicked".into()),
                properties: Fact::Unsupported("DWG LAYER parser panicked".into()),
            }),
        }
    }
    result
}

fn dwg_owner_catalog(
    headers: &[DwgBlockHeader],
    document: &CadDocument,
    model_space_handle: Option<u64>,
) -> Vec<OwnerEvidence> {
    headers
        .iter()
        .map(|header| {
            let numeric_handle = u64::from_str_radix(&header.handle, 16).unwrap_or_default();
            let layout_names = document
                .objects
                .values()
                .filter_map(|object| match object {
                    ObjectType::Layout(layout) if layout.block_record.value() == numeric_handle => {
                        Some(layout.name.clone())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            // There is exactly one model space per document, and its
            // handle — independently derived from the DWG BLOCK_CONTROL
            // hard-owner reference, see `read_dwg_block_control` — is
            // authoritative ground truth. A name-only check (even
            // case-insensitive) trusts a convention a DGN-converted or
            // otherwise non-standard file need not follow; fall back to it
            // only when no independent handle was available at all.
            let is_model_space = match model_space_handle {
                Some(handle) => numeric_handle == handle,
                None => header.data.name.eq_ignore_ascii_case("*Model_Space"),
            };
            let (owner_type, name) = if is_model_space {
                (
                    Fact::Proven(XrefOwnerType::ModelSpace),
                    Fact::Proven("Model".into()),
                )
            } else if layout_names.len() == 1 {
                (
                    Fact::Proven(XrefOwnerType::PaperSpace),
                    Fact::Proven(layout_names[0].clone()),
                )
            } else if layout_names.len() > 1 {
                (
                    Fact::Proven(XrefOwnerType::PaperSpace),
                    Fact::Contradictory("multiple DWG layouts use one block record".into()),
                )
            } else if header
                .data
                .name
                .to_ascii_uppercase()
                .starts_with("*PAPER_SPACE")
            {
                (
                    Fact::Proven(XrefOwnerType::PaperSpace),
                    Fact::Unavailable("paper-space layout name is unavailable".into()),
                )
            } else {
                (
                    Fact::Proven(XrefOwnerType::BlockDefinition),
                    Fact::Proven(header.data.name.clone()),
                )
            };
            OwnerEvidence {
                handle: Fact::Proven(header.handle.clone()),
                owner_type,
                name,
            }
        })
        .collect()
}

fn dwg_entity_owner_map(headers: &[DwgBlockHeader]) -> HashMap<u64, Vec<u64>> {
    let mut result: HashMap<u64, Vec<u64>> = HashMap::new();
    for header in headers {
        let Ok(owner) = u64::from_str_radix(&header.handle, 16) else {
            continue;
        };
        for entity in &header.data.entity_handles {
            result.entry(*entity).or_default().push(owner);
        }
    }
    result
}

impl DwgInstanceContext<'_> {
    fn read(&self, handle: u64, type_code: i16) -> Option<DwgInstanceRead> {
        let reader = self.reader;
        let headers = self.headers;
        let owners = self.owners;
        let layers = self.layers;
        let entity_owners = self.entity_owners;
        let host_units = self.host_units;
        let offset = reader.offset_for(handle).filter(|offset| *offset >= 0)?;
        let (_, mut record) = reader.read_record_at(offset as usize).ok()?;
        let common = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reader.read_common_entity_data(&mut record, type_code)
        }))
        .ok()?;
        let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match type_code {
            OBJ_INSERT => {
                let insert = entities::read_insert(&mut record, reader.version());
                (insert, None)
            }
            OBJ_MINSERT => {
                let insert = entities::read_minsert(&mut record, reader.version());
                let array = XrefRectangularArray {
                    rows: u32::try_from(insert.row_count).unwrap_or_default(),
                    columns: u32::try_from(insert.column_count).unwrap_or_default(),
                    row_spacing: insert.row_spacing,
                    column_spacing: insert.column_spacing,
                };
                (insert.insert, Some(array))
            }
            _ => unreachable!(),
        }))
        .ok()?;
        let (insert, array) = parsed;

        let mapped_owners = entity_owners.get(&handle).cloned().unwrap_or_default();
        let owner_handle = if common.owner_handle != 0 {
            if !mapped_owners.is_empty() && !mapped_owners.contains(&common.owner_handle) {
                Fact::Contradictory(
                    "DWG entity owner and BLOCK_HEADER entity index disagree".into(),
                )
            } else {
                canonical_acadrust_handle(common.owner_handle, "DWG INSERT owner")
            }
        } else {
            match mapped_owners.as_slice() {
                [owner] => canonical_acadrust_handle(*owner, "DWG INSERT owner"),
                [] => Fact::Unavailable("DWG INSERT owner is not represented".into()),
                _ => Fact::Contradictory("DWG INSERT occurs in more than one owner index".into()),
            }
        };
        let owner_matches = match &owner_handle {
            Fact::Proven(handle) => owners
                .iter()
                .filter(|owner| matches!(&owner.handle, Fact::Proven(value) if value == handle))
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        let (owner_type, owner_name) = match owner_matches.as_slice() {
            [owner] => (owner.owner_type.clone(), owner.name.clone()),
            [] => (
                Fact::Unsupported("DWG INSERT owner does not resolve".into()),
                Fact::Unsupported("DWG INSERT owner does not resolve".into()),
            ),
            _ => (
                Fact::Contradictory("DWG INSERT owner resolves more than once".into()),
                Fact::Contradictory("DWG INSERT owner resolves more than once".into()),
            ),
        };
        let layer_handle = canonical_acadrust_handle(common.layer_handle, "DWG INSERT layer");
        let layer_matches = match &layer_handle {
            Fact::Proven(handle) => layers
                .iter()
                .filter(|layer| matches!(&layer.handle, Fact::Proven(value) if value == handle))
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        let layer_name = match layer_matches.as_slice() {
            [layer] => layer.name.clone(),
            [] => Fact::Unsupported("DWG INSERT layer does not resolve".into()),
            _ => Fact::Contradictory("DWG INSERT layer resolves more than once".into()),
        };
        let attachment = headers.iter().find(|header| {
            u64::from_str_radix(&header.handle, 16).ok() == Some(insert.block_handle)
        });
        let attachment_handle = canonical_acadrust_handle(insert.block_handle, "DWG INSERT block");
        let attachment_name = attachment
            .map(|header| Fact::Proven(header.data.name.clone()))
            .unwrap_or_else(|| Fact::Unsupported("DWG INSERT block does not resolve".into()));
        let source_units = attachment
            .map(|header| Fact::Proven(persisted_units(header.data.units.map(i64::from))))
            .unwrap_or_else(|| Fact::Unavailable("DWG XREF block units are unavailable".into()));
        let scale = if insert.x_scale.is_finite()
            && insert.y_scale.is_finite()
            && insert.z_scale.is_finite()
        {
            Fact::Proven(XrefScale3 {
                x: insert.x_scale,
                y: insert.y_scale,
                z: insert.z_scale,
            })
        } else {
            Fact::Unsupported("DWG INSERT scale is not finite".into())
        };
        let placement = match array {
            Some(array)
                if (1..=65_535).contains(&array.rows)
                    && (1..=65_535).contains(&array.columns)
                    && array.row_spacing.is_finite()
                    && array.column_spacing.is_finite() =>
            {
                XrefPersistedPlacementEvidence {
                    placement_kind: Fact::Proven(XrefPlacementKind::RectangularArray),
                    array: Fact::Proven(Some(array)),
                }
            }
            Some(_) => XrefPersistedPlacementEvidence {
                placement_kind: Fact::Proven(XrefPlacementKind::RectangularArray),
                array: Fact::Unsupported("DWG MINSERT array data is invalid".into()),
            },
            None => XrefPersistedPlacementEvidence {
                placement_kind: Fact::Proven(XrefPlacementKind::Single),
                array: Fact::Proven(None),
            },
        };

        let graph_edge = match (&owner_handle, &attachment_handle) {
            (Fact::Proven(owner), Fact::Proven(attachment)) => {
                Some((owner.clone(), attachment.clone()))
            }
            _ => None,
        };
        let clip = if common.xdictionary_handle.is_none() {
            XrefPortableClipEvidence::Absent
        } else {
            // A non-null extension dictionary can contain unrelated data;
            // The selected backend cannot prove the ACAD_FILTER/SPATIAL_FILTER link.
            XrefPortableClipEvidence::Unproven
        };
        Some((
            insert.block_handle,
            XrefPersistedInstanceEvidence {
                handle: canonical_acadrust_handle(common.common.handle, "DWG INSERT handle"),
                attachment_handle,
                attachment_name,
                owner_handle,
                owner_type,
                owner_name,
                layer_handle,
                layer_name,
                insertion_point: vector3(insert.insert_point, "DWG INSERT point"),
                scale: scale.clone(),
                rotation_degrees: finite(insert.rotation.to_degrees(), "DWG INSERT rotation"),
                normal: if insert.normal.x.is_finite()
                    && insert.normal.y.is_finite()
                    && insert.normal.z.is_finite()
                {
                    Fact::Proven(XrefVector3 {
                        x: insert.normal.x,
                        y: insert.normal.y,
                        z: insert.normal.z,
                    })
                } else {
                    Fact::Unsupported("DWG INSERT normal is not finite".into())
                },
                visibility: Fact::Proven(if common.invisible {
                    XrefVisibility::Hidden
                } else {
                    XrefVisibility::Visible
                }),
                placement,
                unit_scaling: unit_scaling(&source_units, host_units, &scale),
            },
            clip,
            graph_edge,
        ))
    }
}

fn derive_dwg_snapshot(
    bytes: &[u8],
    document: &CadDocument,
) -> Result<XrefSnapshotEvidence, XrefError> {
    reject_projection_errors(document)?;
    let reader = low_level_dwg_reader(bytes)?;
    let mut headers = read_dwg_headers(&reader);
    let (block_control_model, block_control_paper) =
        read_dwg_block_control(&reader).unwrap_or((0, 0));
    let model_space_handle = Some(block_control_model)
        .filter(|&handle| handle != 0)
        .or_else(|| {
            document
                .header
                .model_space_block_handle
                .is_valid()
                .then(|| document.header.model_space_block_handle.value())
        });
    let paper_space_handle = Some(block_control_paper)
        .filter(|&handle| handle != 0)
        .or_else(|| {
            document
                .header
                .paper_space_block_handle
                .is_valid()
                .then(|| document.header.paper_space_block_handle.value())
        });
    canonicalize_block_header_names(&mut headers, model_space_handle, paper_space_handle);
    let layers = read_dwg_layers(&reader, document);
    let owners = dwg_owner_catalog(&headers, document, model_space_handle);
    let entity_owners = dwg_entity_owner_map(&headers);
    let host_units = persisted_units(Some(i64::from(document.header.insertion_units)));
    let instance_context = DwgInstanceContext {
        reader: &reader,
        headers: &headers,
        owners: &owners,
        layers: &layers,
        entity_owners: &entity_owners,
        host_units,
    };
    let mut instances: HashMap<u64, Vec<XrefPersistedInstanceEvidence>> = HashMap::new();
    let mut instance_clips = BTreeMap::new();
    let mut block_references: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut block_references_complete = true;
    for handle in reader.handles() {
        let Some(offset) = reader.offset_for(handle).filter(|offset| *offset >= 0) else {
            continue;
        };
        let Ok((type_code, _)) = reader.read_record_at(offset as usize) else {
            continue;
        };
        if !matches!(type_code, OBJ_INSERT | OBJ_MINSERT) {
            continue;
        }
        if let Some((attachment, instance, clip, graph_edge)) =
            instance_context.read(handle, type_code)
        {
            if let Fact::Proven(instance_handle) = &instance.handle {
                instance_clips.insert(instance_handle.clone(), clip);
            } else {
                block_references_complete = false;
            }
            if let Some((owner, referenced)) = graph_edge {
                block_references.entry(owner).or_default().push(referenced);
            } else {
                block_references_complete = false;
            }
            instances.entry(attachment).or_default().push(instance);
        } else {
            block_references_complete = false;
        }
    }
    for references in block_references.values_mut() {
        references.sort_by(|left, right| {
            let left = u64::from_str_radix(left, 16).unwrap_or(u64::MAX);
            let right = u64::from_str_radix(right, 16).unwrap_or(u64::MAX);
            left.cmp(&right)
        });
        references.dedup();
    }

    let mut attachments = headers
        .iter()
        .map(|header| {
            let reference =
                reference_type_from_flags(header.data.is_xref, header.data.is_xref_overlay);
            let membership = match (reference, &header.ownership, header.xref_dependent) {
                (None, _, _) => XrefMembershipEvidence::NotXref,
                (Some(_), Err(reason), _) => XrefMembershipEvidence::Contradictory(reason.clone()),
                (Some(reference), Ok(()), false) => XrefMembershipEvidence::Direct(reference),
                (Some(reference), Ok(()), true) => XrefMembershipEvidence::External(reference),
            };
            let numeric_handle = u64::from_str_radix(&header.handle, 16).unwrap_or_default();
            XrefDomainEvidence {
                handle: canonical_handle_fact(
                    Fact::Proven(header.handle.clone()),
                    "DWG BLOCK_HEADER handle",
                ),
                name: Fact::Proven(header.data.name.clone()),
                membership,
                saved_path: Fact::Proven(header.data.xref_path.clone()),
                load_state: match header.data.is_loaded {
                    Some(true) => Fact::Proven(LoadState::Loaded),
                    Some(false) => Fact::Proven(LoadState::Unloaded),
                    None => {
                        Fact::Unavailable("this DWG version has no persisted load-state bit".into())
                    }
                },
                definition_base_point: vector3(
                    header.data.base_point,
                    "DWG BLOCK_HEADER base point",
                ),
                insertion_units: Fact::Proven(persisted_units(header.data.units.map(i64::from))),
                instances: Fact::Proven(instances.remove(&numeric_handle).unwrap_or_default()),
            }
        })
        .collect::<Vec<_>>();
    reconcile_dwg_projection(document, &headers, &mut attachments);
    mark_duplicate_attachment_handles(&mut attachments);
    mark_duplicate_instance_handles(&mut attachments);
    let block_definitions_complete = headers.len() == document.block_records.len()
        && headers.iter().all(|header| header.ownership.is_ok());
    let owners_complete = headers.len() == document.block_records.len();
    let layers_complete = layers.len() == document.layers.len()
        && layers.iter().all(|layer| {
            matches!(layer.handle, Fact::Proven(_))
                && matches!(layer.name, Fact::Proven(_))
                && matches!(layer.xref_dependent, Fact::Proven(_))
                && matches!(layer.properties, Fact::Proven(_))
        });

    Ok(XrefSnapshotEvidence {
        attachments,
        owners,
        layers,
        host_units: Fact::Proven(host_units),
        block_definitions_complete,
        owners_complete,
        layers_complete,
        block_references_complete,
        block_references,
        instance_clips,
        saved_visretain: Fact::Proven(i16::from(document.header.retain_xref_visibility)),
        saved_xrefoverride: Fact::Unavailable(
            "the selected parser backend does not expose persisted DWG XREFOVERRIDE".into(),
        ),
    })
}

#[cfg(test)]
fn read_test_snapshot(
    format: DrawingFormat,
    bytes: &[u8],
) -> Result<XrefSnapshotEvidence, XrefError> {
    let drawing = Reader::open_snapshot(DrawingSnapshot::new(format, bytes.to_vec()))
        .map_err(map_open_error)?;
    Ok(drawing.xref_session()?.evidence().clone())
}

#[cfg(test)]
fn read_dxf_snapshot(bytes: &[u8]) -> Result<XrefSnapshotEvidence, XrefError> {
    read_test_snapshot(DrawingFormat::Dxf, bytes)
}

#[cfg(test)]
fn read_dwg_snapshot(bytes: &[u8]) -> Result<XrefSnapshotEvidence, XrefError> {
    read_test_snapshot(DrawingFormat::Dwg, bytes)
}

fn reconcile_dwg_projection(
    document: &CadDocument,
    headers: &[DwgBlockHeader],
    attachments: &mut Vec<XrefDomainEvidence>,
) {
    for projected in document
        .block_records
        .iter()
        .filter(|record| record.flags.is_xref || record.flags.is_xref_overlay)
    {
        let handle = format!("{:X}", projected.handle.value());
        let Some(evidence) = attachments.iter_mut().find(
            |attachment| matches!(&attachment.handle, Fact::Proven(value) if value == &handle),
        ) else {
            attachments.push(XrefDomainEvidence {
                handle: canonical_acadrust_handle(
                    projected.handle.value(),
                    "projected DWG BLOCK_RECORD handle",
                ),
                name: Fact::Proven(projected.name.clone()),
                membership: XrefMembershipEvidence::Unsupported(
                    "projected DWG XREF has no matching low-level BLOCK_HEADER read".into(),
                ),
                saved_path: Fact::Unsupported(
                    "low-level DWG saved-path provenance is unavailable".into(),
                ),
                load_state: Fact::Unavailable(
                    "low-level DWG load-state provenance is unavailable".into(),
                ),
                definition_base_point: Fact::Unavailable(
                    "low-level DWG base-point provenance is unavailable".into(),
                ),
                insertion_units: Fact::Unavailable(
                    "low-level DWG block-unit provenance is unavailable".into(),
                ),
                instances: Fact::Unsupported(
                    "low-level DWG INSERT provenance is unavailable".into(),
                ),
            });
            continue;
        };
        let expected_reference =
            reference_type_from_flags(projected.flags.is_xref, projected.flags.is_xref_overlay);
        let low_level_reference = match evidence.membership {
            XrefMembershipEvidence::Direct(reference)
            | XrefMembershipEvidence::External(reference) => Some(reference),
            _ => None,
        };
        if expected_reference != low_level_reference
            || !matches!(&evidence.name, Fact::Proven(value) if value == &projected.name)
        {
            evidence.membership = XrefMembershipEvidence::Contradictory(
                "low-level and projected DWG XREF identity/type disagree".into(),
            );
        }
        if !matches!(&evidence.saved_path, Fact::Proven(value) if value == &projected.xref_path) {
            evidence.saved_path =
                Fact::Contradictory("low-level and projected DWG saved paths disagree".into());
        }
    }

    let mut projected_instances: HashMap<u64, HashSet<u64>> = HashMap::new();
    for entity in document.entities() {
        let EntityType::Insert(insert) = entity else {
            continue;
        };
        let matching_headers = headers
            .iter()
            .filter(|header| xref_contract::xref_name_eq(&header.data.name, &insert.block_name))
            .collect::<Vec<_>>();
        if matching_headers.len() != 1 {
            continue;
        }
        let Ok(attachment_handle) = u64::from_str_radix(&matching_headers[0].handle, 16) else {
            continue;
        };
        projected_instances
            .entry(attachment_handle)
            .or_default()
            .insert(insert.common.handle.value());
    }
    for attachment in attachments {
        if !matches!(attachment.membership, XrefMembershipEvidence::Direct(_)) {
            continue;
        }
        let Fact::Proven(attachment_handle) = &attachment.handle else {
            continue;
        };
        let Ok(attachment_handle) = u64::from_str_radix(attachment_handle, 16) else {
            continue;
        };
        let expected = projected_instances
            .get(&attachment_handle)
            .cloned()
            .unwrap_or_default();
        let actual = match &attachment.instances {
            Fact::Proven(instances) => instances
                .iter()
                .filter_map(|instance| match &instance.handle {
                    Fact::Proven(handle) => u64::from_str_radix(handle, 16).ok(),
                    _ => None,
                })
                .collect::<HashSet<_>>(),
            _ => continue,
        };
        if !expected.is_subset(&actual) {
            attachment.instances = Fact::Unsupported(
                "projected DWG INSERT is absent from the low-level instance evidence".into(),
            );
        }
    }
}

fn path_mode(path: &str) -> XrefPathMode {
    super::xref_path::parse_saved_path(path).mode()
}

fn unavailable_load_state(fact: &Fact<LoadState>, identity: &str) -> Result<LoadState, XrefError> {
    match fact {
        Fact::Proven(value) => Ok(*value),
        Fact::Unavailable(_) => Ok(LoadState::Unavailable),
        Fact::Unsupported(reason) => Err(unsupported(format!(
            "{identity} has unsupported load_state: {reason}"
        ))),
        Fact::Contradictory(reason) => Err(unsupported(format!(
            "{identity} has contradictory load_state: {reason}"
        ))),
    }
}

fn available_base_point(
    fact: &Fact<XrefPoint3>,
    identity: &str,
) -> Result<XrefPointAvailability, XrefError> {
    match fact {
        Fact::Proven(point) => Ok(XrefPointAvailability::Available { point: *point }),
        Fact::Unavailable(_) => Ok(XrefPointAvailability::Unavailable),
        Fact::Unsupported(reason) => Err(unsupported(format!(
            "{identity} has unsupported definition_base_point: {reason}"
        ))),
        Fact::Contradictory(reason) => Err(unsupported(format!(
            "{identity} has contradictory definition_base_point: {reason}"
        ))),
    }
}

fn direct_reference(
    membership: &XrefMembershipEvidence,
) -> Result<Option<ReferenceType>, XrefError> {
    match membership {
        XrefMembershipEvidence::NotXref | XrefMembershipEvidence::External(_) => Ok(None),
        XrefMembershipEvidence::Direct(reference) => Ok(Some(*reference)),
        XrefMembershipEvidence::Unavailable(reason) => Err(unsupported(format!(
            "XREF membership is unavailable: {reason}"
        ))),
        XrefMembershipEvidence::Unsupported(reason) => Err(unsupported(format!(
            "XREF membership is unsupported: {reason}"
        ))),
        XrefMembershipEvidence::Contradictory(reason) => Err(unsupported(format!(
            "XREF membership is contradictory: {reason}"
        ))),
    }
}

fn materialize_attachment(
    evidence: &XrefDomainEvidence,
) -> Result<Option<XrefAttachmentRecord>, XrefError> {
    let Some(reference_type) = direct_reference(&evidence.membership)? else {
        return Ok(None);
    };
    let name = required(&evidence.name, "name", "XREF attachment")?;
    let identity = format!("XREF attachment `{name}`");
    let handle = required(&evidence.handle, "handle", &identity)?;
    let saved_path = required(&evidence.saved_path, "saved_path", &identity)?;
    let instances = required(&evidence.instances, "instances", &identity)?;
    let mut unique = HashSet::new();
    for instance in &instances {
        let instance_handle = required(&instance.handle, "instance handle", &identity)?;
        let attachment_handle = required(
            &instance.attachment_handle,
            "instance attachment handle",
            &identity,
        )?;
        if attachment_handle != handle || !unique.insert(instance_handle) {
            return Err(unsupported(format!(
                "{identity} has contradictory persisted instance membership"
            )));
        }
    }
    let record = XrefAttachmentRecord {
        handle,
        name,
        path_mode: path_mode(&saved_path),
        saved_path,
        reference_type,
        load_state: unavailable_load_state(&evidence.load_state, &identity)?,
        instance_count: instances.len() as u64,
        definition_base_point: available_base_point(&evidence.definition_base_point, &identity)?,
    };
    record.validate()?;
    Ok(Some(record))
}

fn materialize_instance(
    evidence: &XrefPersistedInstanceEvidence,
) -> Result<XrefInstanceRecord, XrefError> {
    let identity = match &evidence.handle {
        Fact::Proven(handle) => format!("XREF instance `{handle}`"),
        _ => "XREF instance `<unknown>`".to_string(),
    };
    let unit_scaling = match &evidence.unit_scaling {
        Fact::Proven(value) => *value,
        Fact::Unavailable(_) => XrefUnitScaling::Unavailable,
        Fact::Unsupported(reason) => {
            return Err(unsupported(format!(
                "{identity} has unsupported unit_scaling: {reason}"
            )))
        }
        Fact::Contradictory(reason) => {
            return Err(unsupported(format!(
                "{identity} has contradictory unit_scaling: {reason}"
            )))
        }
    };
    XrefInstanceRecord {
        handle: required(&evidence.handle, "handle", &identity)?,
        attachment_handle: required(&evidence.attachment_handle, "attachment_handle", &identity)?,
        attachment_name: required(&evidence.attachment_name, "attachment_name", &identity)?,
        owner_handle: required(&evidence.owner_handle, "owner_handle", &identity)?,
        owner_type: required(&evidence.owner_type, "owner_type", &identity)?,
        owner_name: required(&evidence.owner_name, "owner_name", &identity)?,
        layer_handle: required(&evidence.layer_handle, "layer_handle", &identity)?,
        layer_name: required(&evidence.layer_name, "layer_name", &identity)?,
        insertion_point: required(&evidence.insertion_point, "insertion_point", &identity)?,
        scale: required(&evidence.scale, "scale", &identity)?,
        rotation_degrees: required(&evidence.rotation_degrees, "rotation_degrees", &identity)?,
        normal: required(&evidence.normal, "normal", &identity)?,
        visibility: required(&evidence.visibility, "visibility", &identity)?,
        placement_kind: required(
            &evidence.placement.placement_kind,
            "placement_kind",
            &identity,
        )?,
        array: required(&evidence.placement.array, "array", &identity)?,
        unit_scaling,
    }
    .canonicalized()
}

pub(crate) fn list_attachments(
    snapshot: &XrefSnapshotEvidence,
) -> Result<Vec<XrefAttachmentRecord>, XrefError> {
    let mut records = snapshot
        .attachments
        .iter()
        .map(materialize_attachment)
        .filter_map(Result::transpose)
        .collect::<Result<Vec<_>, _>>()?;
    records.sort_by(|left, right| {
        xref_contract::compare_numeric_handles(&left.handle, &right.handle)
            .expect("materialized handles are canonical")
    });
    Ok(records)
}

fn resolve_attachment_index(
    snapshot: &XrefSnapshotEvidence,
    selector: &XrefSelector,
) -> Result<usize, XrefError> {
    let handle = selector
        .handle
        .as_deref()
        .map(xref_contract::canonical_input_handle)
        .transpose()?;
    let name = match selector.name.as_deref() {
        Some(name) if name.trim().is_empty() && handle.is_some() => {
            return Err(XrefError::new(
                "xref_not_found",
                "XREF name selector is empty or whitespace-only",
            ));
        }
        Some(name) if name.trim().is_empty() => None,
        name => name,
    };
    if handle.is_none() && name.is_none() {
        return Err(XrefError::new(
            "missing_identity",
            "get_xref requires a handle or non-empty name",
        ));
    }

    let by_handle = handle
        .as_deref()
        .map(|wanted| {
            let matches = snapshot
                .attachments
                .iter()
                .enumerate()
                .filter(|(_, attachment)| {
                    matches!(&attachment.handle, Fact::Proven(handle) if handle == wanted)
                })
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [(index, attachment)] => match attachment.membership {
                    XrefMembershipEvidence::Direct(_) => Ok(*index),
                    XrefMembershipEvidence::NotXref | XrefMembershipEvidence::External(_) => Err(
                        XrefError::new("xref_not_found", "handle is not a direct XREF"),
                    ),
                    _ => Err(unsupported("selected XREF membership is not proven")),
                },
                [] => Err(XrefError::new(
                    "xref_not_found",
                    "XREF handle was not found",
                )),
                _ => Err(unsupported("persisted XREF handle is duplicated")),
            }
        })
        .transpose()?;

    let by_name = name
        .map(|wanted| {
            let mut matches = Vec::new();
            for (index, attachment) in snapshot.attachments.iter().enumerate() {
                match (&attachment.membership, &attachment.name) {
                    (XrefMembershipEvidence::Direct(_), Fact::Proven(name))
                        if xref_contract::xref_name_eq(name, wanted) =>
                    {
                        matches.push(index)
                    }
                    (XrefMembershipEvidence::Direct(_), Fact::Unavailable(reason))
                    | (XrefMembershipEvidence::Direct(_), Fact::Unsupported(reason))
                    | (XrefMembershipEvidence::Direct(_), Fact::Contradictory(reason)) => {
                        return Err(unsupported(format!(
                            "direct attachment name cannot be inspected for uniqueness: {reason}"
                        )))
                    }
                    (
                        XrefMembershipEvidence::Unavailable(_)
                        | XrefMembershipEvidence::Unsupported(_)
                        | XrefMembershipEvidence::Contradictory(_),
                        Fact::Proven(name),
                    ) if xref_contract::xref_name_eq(name, wanted) => {
                        return Err(unsupported(
                            "matching attachment has unproven direct membership",
                        ))
                    }
                    (
                        XrefMembershipEvidence::Unavailable(_)
                        | XrefMembershipEvidence::Unsupported(_)
                        | XrefMembershipEvidence::Contradictory(_),
                        Fact::Unavailable(_) | Fact::Unsupported(_) | Fact::Contradictory(_),
                    ) => {
                        return Err(unsupported(
                            "attachment name/direct-membership evidence cannot prove uniqueness",
                        ))
                    }
                    _ => {}
                }
            }
            match matches.as_slice() {
                [index] => Ok(*index),
                [] => Err(XrefError::new("xref_not_found", "XREF name was not found")),
                _ => Err(XrefError::new(
                    "ambiguous_identity",
                    "XREF name matches more than one direct attachment",
                )),
            }
        })
        .transpose()?;

    match (by_handle, by_name) {
        (Some(left), Some(right)) if left == right => Ok(left),
        (Some(_), Some(_)) => Err(XrefError::new(
            "contradictory_identity",
            "XREF handle and name resolve to different attachments",
        )),
        (Some(index), None) | (None, Some(index)) => Ok(index),
        (None, None) => unreachable!("identity was validated"),
    }
}

pub(crate) fn get_attachment(
    snapshot: &XrefSnapshotEvidence,
    selector: &XrefSelector,
) -> Result<XrefAttachmentRecord, XrefError> {
    let index = resolve_attachment_index(snapshot, selector)?;
    materialize_attachment(&snapshot.attachments[index])?
        .ok_or_else(|| XrefError::new("xref_not_found", "selected record is not a direct XREF"))
}

fn resolve_catalog_handle<T>(
    values: &[T],
    wanted: &str,
    handle: impl Fn(&T) -> &Fact<String>,
    not_found: &'static str,
) -> Result<usize, XrefError> {
    let wanted = xref_contract::canonical_input_handle(wanted)?;
    let matches = values
        .iter()
        .enumerate()
        .filter(|(_, value)| matches!(handle(value), Fact::Proven(handle) if handle == &wanted))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => Err(XrefError::new(not_found, "resource handle was not found")),
        _ => Err(unsupported("persisted resource handle is duplicated")),
    }
}

fn resolve_owner_filter(
    snapshot: &XrefSnapshotEvidence,
    request: &XrefInstanceListOptions,
) -> Result<Option<String>, XrefError> {
    if request.owner_name.is_some()
        && request.owner_type.is_none()
        && request.owner_handle.is_none()
    {
        return Err(XrefError::new(
            "invalid_xref_owner",
            "owner_name requires owner_type unless owner_handle is supplied",
        ));
    }
    let by_handle = request
        .owner_handle
        .as_deref()
        .map(|handle| {
            resolve_catalog_handle(
                &snapshot.owners,
                handle,
                |owner| &owner.handle,
                "xref_owner_not_found",
            )
        })
        .transpose()?;
    let by_semantic = match (request.owner_type, request.owner_name.as_deref()) {
        (Some(owner_type), Some(name)) => {
            let matches = snapshot
                .owners
                .iter()
                .enumerate()
                .filter(|(_, owner)| {
                    matches!(owner.owner_type, Fact::Proven(value) if value == owner_type)
                        && matches!(&owner.name, Fact::Proven(value) if xref_contract::xref_name_eq(value, name))
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [index] => Some(*index),
                [] => {
                    return Err(XrefError::new(
                        "xref_owner_not_found",
                        "semantic XREF owner was not found",
                    ))
                }
                _ => return Err(unsupported("semantic XREF owner is ambiguous")),
            }
        }
        _ => None,
    };
    if let (Some(left), Some(right)) = (by_handle, by_semantic) {
        if left != right {
            return Err(XrefError::new(
                "contradictory_identity",
                "owner handle and semantic owner resolve differently",
            ));
        }
    }
    let selected = by_handle.or(by_semantic);
    if let Some(index) = selected {
        let owner = &snapshot.owners[index];
        if request
            .owner_type
            .is_some_and(|wanted| !matches!(owner.owner_type, Fact::Proven(value) if value == wanted))
            || request.owner_name.as_deref().is_some_and(|wanted| {
                !matches!(&owner.name, Fact::Proven(value) if xref_contract::xref_name_eq(value, wanted))
            })
        {
            return Err(XrefError::new(
                "contradictory_identity",
                "owner filters disagree",
            ));
        }
        return Ok(Some(required(&owner.handle, "owner handle", "XREF owner")?));
    }
    Ok(None)
}

fn resolve_layer_filter(
    snapshot: &XrefSnapshotEvidence,
    request: &XrefInstanceListOptions,
) -> Result<Option<String>, XrefError> {
    let by_handle = request
        .layer_handle
        .as_deref()
        .map(|handle| {
            resolve_catalog_handle(
                &snapshot.layers,
                handle,
                |layer| &layer.handle,
                "layer_not_found",
            )
        })
        .transpose()?;
    let by_name = request
        .layer_name
        .as_deref()
        .map(|name| {
            let matches = snapshot
                .layers
                .iter()
                .enumerate()
                .filter(|(_, layer)| {
                    matches!(&layer.name, Fact::Proven(value) if xref_contract::xref_name_eq(value, name))
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [index] => Ok(*index),
                [] => Err(XrefError::new(
                    "layer_not_found",
                    "layer name was not found",
                )),
                _ => Err(unsupported("layer name is ambiguous")),
            }
        })
        .transpose()?;
    if let (Some(left), Some(right)) = (by_handle, by_name) {
        if left != right {
            return Err(XrefError::new(
                "contradictory_identity",
                "layer handle and name resolve differently",
            ));
        }
    }
    by_handle
        .or(by_name)
        .map(|index| required(&snapshot.layers[index].handle, "layer handle", "layer"))
        .transpose()
}

pub(crate) fn list_instances(
    snapshot: &XrefSnapshotEvidence,
    request: &XrefInstanceListOptions,
) -> Result<Vec<XrefInstanceRecord>, XrefError> {
    let attachment_index =
        if request.attachment_handle.is_some() || request.attachment_name.is_some() {
            Some(resolve_attachment_index(
                snapshot,
                &XrefSelector {
                    handle: request.attachment_handle.clone(),
                    name: request.attachment_name.clone(),
                },
            )?)
        } else {
            None
        };
    let owner_handle = resolve_owner_filter(snapshot, request)?;
    let layer_handle = resolve_layer_filter(snapshot, request)?;

    let attachments: Vec<&XrefDomainEvidence> = match attachment_index {
        Some(index) => vec![&snapshot.attachments[index]],
        None => {
            for attachment in &snapshot.attachments {
                direct_reference(&attachment.membership)?;
            }
            snapshot
                .attachments
                .iter()
                .filter(|attachment| {
                    matches!(attachment.membership, XrefMembershipEvidence::Direct(_))
                })
                .collect()
        }
    };
    let mut records = Vec::new();
    for attachment in attachments {
        let instances = required(&attachment.instances, "instances", "XREF attachment")?;
        for instance in &instances {
            let record = materialize_instance(instance)?;
            if owner_handle
                .as_ref()
                .is_some_and(|handle| &record.owner_handle != handle)
                || layer_handle
                    .as_ref()
                    .is_some_and(|handle| &record.layer_handle != handle)
                || request
                    .owner_type
                    .is_some_and(|owner_type| record.owner_type != owner_type)
                || request
                    .owner_name
                    .as_deref()
                    .is_some_and(|name| !xref_contract::xref_name_eq(&record.owner_name, name))
                || request
                    .visibility
                    .is_some_and(|visibility| record.visibility != visibility)
            {
                continue;
            }
            records.push(record);
        }
    }
    records.sort_by(|left, right| {
        xref_contract::compare_numeric_handles(&left.handle, &right.handle)
            .expect("materialized handles are canonical")
    });
    Ok(records)
}

pub(crate) fn get_instance(
    snapshot: &XrefSnapshotEvidence,
    handle: &str,
) -> Result<XrefInstanceRecord, XrefError> {
    let wanted = xref_contract::canonical_input_handle(handle)?;
    let mut matches = Vec::new();
    for attachment in &snapshot.attachments {
        let Fact::Proven(instances) = &attachment.instances else {
            continue;
        };
        for instance in instances {
            if matches!(&instance.handle, Fact::Proven(handle) if handle == &wanted) {
                match attachment.membership {
                    XrefMembershipEvidence::Direct(_) => matches.push(instance),
                    XrefMembershipEvidence::NotXref | XrefMembershipEvidence::External(_) => {}
                    XrefMembershipEvidence::Unavailable(_)
                    | XrefMembershipEvidence::Unsupported(_)
                    | XrefMembershipEvidence::Contradictory(_) => {
                        return Err(unsupported(
                            "selected instance attachment has unproven direct membership",
                        ));
                    }
                }
            }
        }
    }
    match matches.as_slice() {
        [instance] => materialize_instance(instance),
        [] => Err(XrefError::new(
            "xref_instance_not_found",
            "XREF instance handle was not found",
        )),
        _ => Err(unsupported("persisted XREF instance handle is duplicated")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::tables::BlockRecord;
    use acadrust::types::Handle;
    use acadrust::{DwgWriter, DxfWriter};
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("autocad-mcp should live under <repo>/crates")
            .join("tests/fixtures/xrefs")
            .join(name)
    }

    /// DWG stores every paper-space block record on disk under the literal
    /// name `*Paper_Space`; a document with two layouts has two such
    /// records that acadrust deduplicates on parse into `*Paper_Space` /
    /// `*Paper_Space0`. The independent reader's block-definition name
    /// evidence must assign the same name to the same handle acadrust does,
    /// or `XrefHandleBridge` refuses the drawing outright — see memory
    /// `project-xref-bridge-identity-mismatch-root-cause`.
    #[test]
    fn dwg_paper_space_block_names_match_acadrust_canonicalization_across_two_layouts() {
        let mut document = CadDocument::new();
        document.add_layout("Layout2").unwrap();
        let bytes = DwgWriter::write_to_vec(&document).unwrap();

        // Ground truth: reparse independently with acadrust and read the
        // canonical names it assigned per handle.
        let ground_truth = DwgReader::from_stream(Cursor::new(bytes.clone()))
            .read()
            .unwrap();
        let expected: BTreeMap<Handle, String> = ground_truth
            .block_records
            .iter()
            .filter(|record| record.name.starts_with("*Paper_Space"))
            .map(|record| (record.handle, record.name.clone()))
            .collect();
        assert_eq!(
            expected.len(),
            2,
            "expected two distinct paper-space block records in the ground truth"
        );

        let session =
            Reader::open_snapshot(DrawingSnapshot::new(DrawingFormat::Dwg, bytes)).unwrap();
        let xref_session = session.xref_session().unwrap();
        let actual: BTreeMap<Handle, String> = xref_session
            .evidence()
            .attachments
            .iter()
            .filter_map(|attachment| match (&attachment.handle, &attachment.name) {
                (Fact::Proven(handle), Fact::Proven(name)) if name.starts_with("*Paper_Space") => {
                    let handle = Handle::new(u64::from_str_radix(handle, 16).unwrap());
                    Some((handle, name.clone()))
                }
                _ => None,
            })
            .collect();

        assert_eq!(actual, expected);
    }

    /// True Color (RGB) layers are fully round-trippable through acadrust's
    /// own `Color` model — the reader must prove them rather than declaring
    /// layer evidence incomplete, or `XrefHandleBridge` refuses to open any
    /// drawing with such a layer at all. See memory
    /// `project-xref-bridge-identity-mismatch-root-cause`.
    #[test]
    fn dwg_true_color_layer_is_proven_not_unsupported() {
        use acadrust::tables::Layer;
        use acadrust::types::Color;
        use acadrust::TableEntry;

        let mut document = CadDocument::new();
        let mut layer = Layer::with_color("TRUE_COLOR", Color::from_rgb(10, 20, 30));
        layer.set_handle(document.allocate_handle());
        document.layers.add(layer).unwrap();
        let bytes = DwgWriter::write_to_vec(&document).unwrap();

        let session =
            Reader::open_snapshot(DrawingSnapshot::new(DrawingFormat::Dwg, bytes)).unwrap();
        let xref_session = session.xref_session().unwrap();
        let evidence = xref_session.evidence();
        assert!(
            evidence.layers_complete,
            "a True Color layer must not make layer evidence incomplete"
        );
        let layer = evidence
            .layers
            .iter()
            .find(|layer| layer.name == Fact::Proven("TRUE_COLOR".to_string()))
            .expect("the true-color layer must be present in layer evidence");
        let Fact::Proven(properties) = &layer.properties else {
            panic!(
                "true-color layer properties must be proven, got {:?}",
                layer.properties
            );
        };
        assert_eq!(
            properties.color,
            xref_contract::XrefPortableLayerColor::TrueColor {
                r: 10,
                g: 20,
                b: 30
            }
        );
        assert!(!properties.off);
        assert!(!properties.frozen);
        assert!(!properties.locked);
        assert!(properties.is_plottable);
        assert_eq!(properties.line_type, "Continuous");
    }

    #[test]
    fn session_queries_and_raw_evidence_share_one_snapshot() {
        let bytes = std::fs::read(fixture("portable-evidence-ascii.dxf")).unwrap();
        let drawing = Reader::open_snapshot(DrawingSnapshot::new(DrawingFormat::Dxf, bytes))
            .expect("ordinary reader session must admit the fixture");
        let session = drawing.xref_session().unwrap();

        let attachments = session.list_attachments().unwrap();
        let instances = session
            .list_instances(&XrefInstanceListOptions::default())
            .unwrap();
        assert_eq!(
            attachments
                .iter()
                .map(|attachment| attachment.handle.as_str())
                .collect::<Vec<_>>(),
            ["F", "10", "11"]
        );
        assert_eq!(
            instances
                .iter()
                .map(|instance| instance.attachment_handle.as_str())
                .collect::<BTreeSet<_>>(),
            ["F", "10", "11"].into_iter().collect()
        );
        assert_eq!(
            session
                .evidence()
                .attachments
                .iter()
                .filter_map(
                    |attachment| match (&attachment.membership, &attachment.handle) {
                        (XrefMembershipEvidence::Direct(_), Fact::Proven(handle)) => {
                            Some(handle.as_str())
                        }
                        _ => None,
                    }
                )
                .collect::<BTreeSet<_>>(),
            ["F", "10", "11"].into_iter().collect()
        );
    }

    #[test]
    fn fatal_reader_open_errors_map_to_stable_non_backend_xref_errors() {
        let error = match Reader::open_snapshot(DrawingSnapshot::new(
            DrawingFormat::Dwg,
            b"not a DWG".to_vec(),
        ))
        .map_err(map_open_error)
        {
            Ok(_) => panic!("invalid drawing must fail before family projection"),
            Err(error) => error,
        };

        assert_eq!(error.code(), "unsupported_xref_data");
        assert_eq!(
            error.to_string(),
            "code=unsupported_xref_data drawing could not be decoded for XREF projection"
        );
        assert!(!error.to_string().contains("acadrust"));
        assert!(!error.to_string().contains("Invalid file format"));
    }

    #[test]
    fn projection_error_diagnostics_do_not_cross_the_public_error_boundary() {
        let mut document = CadDocument::new();
        document.notifications.notify(
            NotificationType::Error,
            "backend-specific diagnostic must stay internal",
        );

        let error = reject_projection_errors(&document).unwrap_err();
        assert_eq!(error.code(), "unsupported_xref_data");
        assert!(error.to_string().contains("XREF projection is incomplete"));
        assert!(!error.to_string().contains("backend-specific diagnostic"));
        assert!(!error.to_string().contains("acadrust"));
    }

    #[test]
    fn portable_ascii_fixture_materializes_attachments_and_instances_numerically() {
        let bytes = std::fs::read(fixture("portable-evidence-ascii.dxf")).unwrap();
        let snapshot = read_dxf_snapshot(&bytes).unwrap();
        let attachments = list_attachments(&snapshot).unwrap();
        assert_eq!(
            attachments
                .iter()
                .map(|attachment| attachment.handle.as_str())
                .collect::<Vec<_>>(),
            ["F", "10", "11"]
        );
        assert_eq!(
            attachments[0].definition_base_point,
            XrefPointAvailability::Available {
                point: XrefPoint3 {
                    x: 1.0,
                    y: 2.0,
                    z: 3.0
                }
            }
        );
        assert_eq!(attachments[2].saved_path, "");
        assert_eq!(attachments[2].path_mode, XrefPathMode::Unsupported);

        let request = XrefInstanceListOptions {
            attachment_handle: None,
            attachment_name: None,
            owner_handle: None,
            owner_type: None,
            owner_name: None,
            layer_handle: None,
            layer_name: None,
            visibility: None,
        };
        let instances = list_instances(&snapshot, &request).unwrap();
        assert_eq!(
            instances
                .iter()
                .map(|instance| instance.handle.as_str())
                .collect::<Vec<_>>(),
            ["20", "30", "F0", "100"]
        );
        assert_eq!(instances[0].owner_type, XrefOwnerType::PaperSpace);
        assert_eq!(instances[0].owner_name, "Sheet A");
        assert_eq!(
            instances[0].placement_kind,
            XrefPlacementKind::RectangularArray
        );
        assert_eq!(instances[0].array.unwrap().rows, 2);
        assert_eq!(
            instances[2].placement_kind,
            XrefPlacementKind::RectangularArray
        );
        assert_eq!(instances[2].array.unwrap().rows, 1);
        assert_eq!(instances[3].owner_type, XrefOwnerType::ModelSpace);
        assert_eq!(instances[2].layer_handle, "8");
        assert_eq!(instances[2].layer_name, "XREF_LAYER");
        assert_eq!(instances[2].rotation_degrees, 45.0);
        assert_eq!(
            instances[2].scale,
            XrefScale3 {
                x: 2.0,
                y: 3.0,
                z: 4.0
            }
        );
        assert_eq!(
            instances[2].unit_scaling,
            XrefUnitScaling::Available {
                source_units: XrefUnitValue {
                    value: InsertionUnit::Millimeters,
                    basis: XrefUnitBasis::Drawing,
                },
                host_units: XrefUnitValue {
                    value: InsertionUnit::Meters,
                    basis: XrefUnitBasis::Drawing,
                },
                factor: 0.001,
                effective_scale: XrefScale3 {
                    x: 0.002,
                    y: 0.003,
                    z: 0.004,
                },
            }
        );
    }

    #[test]
    fn portable_ascii_mutation_facts_are_proven_only_when_structurally_observable() {
        let bytes = std::fs::read(fixture("portable-evidence-ascii.dxf")).unwrap();
        let snapshot = read_dxf_snapshot(&bytes).unwrap();

        assert_eq!(
            snapshot.host_units,
            Fact::Proven(PersistedInsertionUnits::Known {
                value: InsertionUnit::Meters,
            })
        );
        assert!(snapshot.block_definitions_complete);
        assert!(snapshot.owners_complete);
        assert!(snapshot.layers_complete);
        assert!(snapshot.block_references_complete);
        assert_eq!(snapshot.instance_clips.len(), 4);
        assert!(snapshot
            .instance_clips
            .values()
            .all(|clip| *clip == XrefPortableClipEvidence::Absent));
        assert!(matches!(snapshot.saved_visretain, Fact::Unavailable(_)));
        assert!(matches!(snapshot.saved_xrefoverride, Fact::Unavailable(_)));
        let layer = snapshot
            .layers
            .iter()
            .find(|layer| matches!(&layer.name, Fact::Proven(name) if name == "XREF_LAYER"))
            .unwrap();
        assert_eq!(layer.xref_dependent, Fact::Proven(false));
        assert!(matches!(layer.properties, Fact::Proven(_)));
    }

    #[test]
    fn external_and_path_only_blocks_are_not_direct_attachments() {
        let bytes = std::fs::read(fixture("portable-evidence-ascii.dxf")).unwrap();
        let snapshot = read_dxf_snapshot(&bytes).unwrap();
        assert!(snapshot.attachments.iter().any(|attachment| {
            matches!(
                attachment.membership,
                XrefMembershipEvidence::External(ReferenceType::Attachment)
            )
        }));
        let records = list_attachments(&snapshot).unwrap();
        assert!(!records.iter().any(|record| record.name == "NESTED_SITE"));
        assert!(!records.iter().any(|record| record.name == "PATH_ONLY"));
    }

    #[test]
    fn declared_non_utf8_code_page_preserves_exact_text() {
        let bytes = std::fs::read(fixture("non-utf8-ansi-1252.dxf")).unwrap();
        assert!(std::str::from_utf8(&bytes).is_err());
        let snapshot = read_dxf_snapshot(&bytes).unwrap();
        let records = list_attachments(&snapshot).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "CAF\u{c9}_SITE");
        assert_eq!(records[0].saved_path, "r\u{e9}fs/site.dwg");
    }

    #[test]
    fn target_local_get_ignores_unrelated_unsupported_materialization() {
        let bytes = std::fs::read(fixture("portable-evidence-ascii.dxf")).unwrap();
        let mut snapshot = read_dxf_snapshot(&bytes).unwrap();
        let unrelated = snapshot
            .attachments
            .iter_mut()
            .find(
                |attachment| matches!(&attachment.name, Fact::Proven(name) if name == "EMPTY_PATH"),
            )
            .unwrap();
        unrelated.saved_path = Fact::Unsupported("test-only unrelated failure".into());
        let selected = get_attachment(
            &snapshot,
            &XrefSelector {
                handle: Some("F".into()),
                name: None,
            },
        )
        .unwrap();
        assert_eq!(selected.name, "SITE_MODEL");
        assert_eq!(
            list_attachments(&snapshot).unwrap_err().code(),
            "unsupported_xref_data"
        );
    }

    #[test]
    fn combined_xref_and_overlay_flags_are_an_overlay() {
        let source = std::fs::read_to_string(fixture("portable-evidence-ascii.dxf")).unwrap();
        let combined = source.replacen("GRID_OVERLAY\n 70\n     8", "GRID_OVERLAY\n 70\n    12", 1);
        let snapshot = read_dxf_snapshot(combined.as_bytes()).unwrap();
        let records = list_attachments(&snapshot).unwrap();
        let overlay = records
            .iter()
            .find(|record| record.name == "GRID_OVERLAY")
            .unwrap();
        assert_eq!(overlay.reference_type, ReferenceType::Overlay);
    }

    #[test]
    fn contradictory_owner_and_repeated_path_facts_fail_closed() {
        let source = std::fs::read_to_string(fixture("portable-evidence-ascii.dxf")).unwrap();
        let variants = [
            source.replacen("BF\n330\nF", "BF\n330\n10", 1),
            source.replacen(
                "  1\nrefs/site.dwg\n  0\nENDBLK",
                "  1\nrefs/site.dwg\n  1\nrefs/other.dwg\n  0\nENDBLK",
                1,
            ),
        ];
        for variant in variants {
            let snapshot = read_dxf_snapshot(variant.as_bytes()).unwrap();
            assert_eq!(
                list_attachments(&snapshot).unwrap_err().code(),
                "unsupported_xref_data"
            );
        }
    }

    #[test]
    fn instance_filters_resolve_resources_before_scanning() {
        let bytes = std::fs::read(fixture("portable-evidence-ascii.dxf")).unwrap();
        let snapshot = read_dxf_snapshot(&bytes).unwrap();
        let mut request = XrefInstanceListOptions {
            attachment_handle: None,
            attachment_name: None,
            owner_handle: Some("A0".into()),
            owner_type: Some(XrefOwnerType::PaperSpace),
            owner_name: Some("Sheet A".into()),
            layer_handle: None,
            layer_name: None,
            visibility: None,
        };
        assert_eq!(
            list_instances(&snapshot, &request).unwrap_err().code(),
            "contradictory_identity"
        );

        request.owner_handle = None;
        request.owner_type = None;
        request.owner_name = None;
        request.layer_name = Some("MISSING".into());
        assert_eq!(
            list_instances(&snapshot, &request).unwrap_err().code(),
            "layer_not_found"
        );
    }

    #[test]
    fn binary_xref_projection_fails_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let rendered = temporary.path().join("unsupported-xref-binary.dxf");
        write_synthetic_binary_xref_fixture(&rendered);
        let bytes = std::fs::read(rendered).unwrap();
        assert!(bytes.starts_with(BINARY_DXF_SENTINEL));
        let snapshot = read_dxf_snapshot(&bytes).unwrap();
        assert_eq!(
            list_attachments(&snapshot).unwrap_err().code(),
            "unsupported_xref_data"
        );
    }

    fn synthetic_binary_xref_document() -> CadDocument {
        let mut document = CadDocument::new();
        let mut attachment = BlockRecord::new("BINARY_SITE");
        attachment.handle = Handle::new(0x20);
        attachment.block_entity_handle = Handle::new(0x21);
        attachment.block_end_handle = Handle::new(0x22);
        attachment.flags.is_xref = true;
        attachment.xref_path = "refs/binary-site.dwg".to_string();
        document.block_records.add(attachment).unwrap();
        document
    }

    fn write_synthetic_binary_xref_fixture(path: &Path) {
        DxfWriter::new_binary(&synthetic_binary_xref_document())
            .write_to_file(path)
            .unwrap();
    }

    #[test]
    fn path_modes_are_host_independent() {
        assert_eq!(path_mode(r"C:\refs\site.dwg"), XrefPathMode::Absolute);
        assert_eq!(
            path_mode(r"\\server\share\site.dwg"),
            XrefPathMode::Absolute
        );
        assert_eq!(path_mode("../refs/site.dwg"), XrefPathMode::Relative);
        assert_eq!(path_mode("site.dwg"), XrefPathMode::FilenameOnly);
        assert_eq!(path_mode("HTTPS://host/site.dwg"), XrefPathMode::Url);
        assert_eq!(path_mode("C:site.dwg"), XrefPathMode::Unsupported);
    }

    #[test]
    fn low_level_dwg_adapter_rereads_direct_membership_from_one_snapshot() {
        let mut document = CadDocument::new();
        let mut attachment = BlockRecord::new("DWG_SITE");
        attachment.handle = Handle::new(0xA1);
        attachment.block_entity_handle = Handle::new(0xB1);
        attachment.block_end_handle = Handle::new(0xC1);
        attachment.flags.is_xref = true;
        attachment.xref_path = "refs/dwg-site.dwg".to_string();
        document.block_records.add(attachment).unwrap();

        let mut overlay = BlockRecord::new("DWG_OVERLAY");
        overlay.handle = Handle::new(0xA2);
        overlay.block_entity_handle = Handle::new(0xB2);
        overlay.block_end_handle = Handle::new(0xC2);
        overlay.flags.is_xref = true;
        overlay.flags.is_xref_overlay = true;
        overlay.xref_path = "refs/dwg-overlay.dwg".to_string();
        document.block_records.add(overlay).unwrap();

        let file = tempfile::Builder::new().suffix(".dwg").tempfile().unwrap();
        DwgWriter::write_to_file(file.path(), &document).unwrap();
        let bytes = std::fs::read(file.path()).unwrap();
        let snapshot = read_dwg_snapshot(&bytes).unwrap();
        let records = list_attachments(&snapshot).unwrap();
        let record = records.iter().find(|record| record.handle == "A1").unwrap();
        assert_eq!(record.name, "DWG_SITE");
        assert_eq!(record.saved_path, "refs/dwg-site.dwg");
        assert_eq!(record.reference_type, ReferenceType::Attachment);
        assert!(matches!(
            record.definition_base_point,
            XrefPointAvailability::Available { .. }
        ));
        assert_ne!(record.load_state, LoadState::Unavailable);

        let overlay = records.iter().find(|record| record.handle == "A2").unwrap();
        assert_eq!(overlay.name, "DWG_OVERLAY");
        assert_eq!(overlay.saved_path, "refs/dwg-overlay.dwg");
        assert_eq!(overlay.reference_type, ReferenceType::Overlay);
    }
}
