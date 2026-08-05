use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use acadrust::entities::{Block, BlockEnd, EntityType, Insert};
use acadrust::objects::ObjectType;
use acadrust::tables::{BlockRecord, TableEntry};
use acadrust::types::{Handle, Vector3};
use acadrust::CadDocument;

use super::contract::{
    AttachXref, AttachXrefResult, BindXref, BindXrefResult, DeleteXrefInstance,
    DeleteXrefInstanceResult, DependencyStrategy, DetachXref, DetachXrefResult, InsertXrefInstance,
    InsertXrefInstanceResult, LayerReconciliation, LayerReconciliationEvidence,
    LayerReconciliationMode, LoadState, ReferenceType, ReloadXref, ReloadXrefResult,
    SymbolStrategy, UnloadXref, UnloadXrefResult, UpdateXref, UpdateXrefInstance,
    UpdateXrefInstanceResult, UpdateXrefResult, XrefAttachmentGuard, XrefAttachmentRecord,
    XrefBoundBlock, XrefDestructiveAttachmentGuard, XrefInstanceAttachmentGuard, XrefInstanceGuard,
    XrefInstancePlacement, XrefInstanceRecord, XrefOwnerType, XrefPathMode, XrefPlacement,
    XrefPlacementKind, XrefPoint3, XrefPointAvailability, XrefRectangularArray, XrefScale3,
    XrefUnitScaling, XrefVector3, XrefVisibility,
};
use super::layers::{
    current_layer_handle, entity_references_layer, has_opaque_layer_references,
    has_opaque_references_to, is_xref_dependent, rewrite_entity_layer_references,
};
use super::xref_handle_bridge::XrefHandleBridge;
use super::{DrawingFormat, WriteError};

#[derive(Debug, Clone)]
pub(super) enum XrefPostcondition {
    AttachmentPresent {
        handle: String,
        name: String,
        saved_path: String,
        reference_type: ReferenceType,
        instance_handles: Vec<String>,
    },
    AttachmentAbsent {
        handle: String,
        name: String,
    },
    InstancePresent {
        expected: Box<XrefInstanceRecord>,
    },
    InstanceAbsent {
        handle: String,
        attachment_handle: String,
        attachment_name: String,
    },
    // `reload`/`unload`/`bind` (below) build these, but `session.rs` keeps
    // those three routes hard-blocked rather than calling them: acadrust
    // 0.4.1 cannot materialize XREF load state or a real graph-import, so
    // routing through here would surface an unverifiable, best-effort
    // result instead of today's honest immediate refusal. Kept for the
    // follow-up that wires that up as its own disclosed-risk decision.
    #[allow(dead_code)]
    LoadState {
        handle: String,
        expected: LoadState,
    },
    #[allow(dead_code)]
    Unmaterialized {
        reason_code: String,
    },
}

#[derive(Debug, Clone)]
pub(super) struct Mutation<T> {
    pub(super) result: T,
    pub(super) postcondition: XrefPostcondition,
    pub(super) diagnostics: Vec<String>,
}

#[derive(Debug, Clone)]
struct ResolvedPlacement {
    owner_handle: Handle,
    layer_name: String,
    insertion_point: XrefPoint3,
    scale: XrefScale3,
    rotation_degrees: f64,
    normal: XrefVector3,
    visibility: XrefVisibility,
    array: Option<XrefRectangularArray>,
}

fn name_eq(left: &str, right: &str) -> bool {
    autocad_reader::contract::xrefs::xref_name_eq(left, right)
}

fn canonical_handle(handle: Handle) -> Result<String, WriteError> {
    if handle.is_null() {
        return Err(WriteError::unsupported_source(
            "invalid_xref_handle",
            "XREF handle 0 cannot cross the writer boundary",
        ));
    }
    Ok(format!("{:X}", handle.value()))
}

fn parse_handle(input: &str, code: &'static str) -> Result<Handle, WriteError> {
    let trimmed = input.trim();
    let hexadecimal = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let value = u64::from_str_radix(hexadecimal, 16).map_err(|_| {
        WriteError::invalid_request(code, format!("invalid hexadecimal handle `{input}`"))
    })?;
    if value == 0 {
        return Err(WriteError::invalid_request(code, "handle 0 is invalid"));
    }
    Ok(Handle::new(value))
}

fn validate_xref_name(name: &str) -> Result<(), WriteError> {
    const RESERVED: &[char] = &[
        '<', '>', '/', '\\', '"', ':', ';', '?', '*', '|', ',', '=', '`',
    ];
    if name.is_empty()
        || name.trim() != name
        || name.chars().count() > 255
        || name
            .chars()
            .any(|character| character.is_ascii_control() || RESERVED.contains(&character))
    {
        return Err(WriteError::invalid_request(
            "invalid_xref_name",
            format!("invalid XREF name `{name}`"),
        ));
    }
    Ok(())
}

fn validate_xref_path(path: &str) -> Result<(), WriteError> {
    use autocad_reader::xref_path::{parse_saved_path, XrefPathSyntax};

    let parsed = parse_saved_path(path);
    let is_local_path = matches!(
        parsed.syntax(),
        XrefPathSyntax::WindowsDriveAbsolute
            | XrefPathSyntax::WindowsUncAbsolute
            | XrefPathSyntax::PosixAbsolute
            | XrefPathSyntax::Relative
            | XrefPathSyntax::FilenameOnly
    );
    let has_dwg_filename = parsed
        .basename()
        .unwrap_or_default()
        .rsplit_once('.')
        .is_some_and(|(stem, extension)| !stem.is_empty() && extension.eq_ignore_ascii_case("dwg"));
    if !is_local_path || parsed.has_trailing_separator() || !has_dwg_filename {
        return Err(WriteError::invalid_request(
            "invalid_xref_path",
            "XREF source path must identify a .dwg file",
        ));
    }
    Ok(())
}

fn validate_search_paths(search_paths: Option<&[String]>) -> Result<(), WriteError> {
    use autocad_reader::xref_path::{parse_saved_path, XrefPathSyntax};

    for (index, path) in search_paths.unwrap_or_default().iter().enumerate() {
        if !matches!(
            parse_saved_path(path).syntax(),
            XrefPathSyntax::WindowsDriveAbsolute
                | XrefPathSyntax::WindowsUncAbsolute
                | XrefPathSyntax::PosixAbsolute
        ) {
            return Err(WriteError::invalid_request(
                "invalid_search_path",
                format!("search_paths[{index}] must be an absolute local directory path"),
            ));
        }
    }
    Ok(())
}

fn default_xref_name(path: &str) -> String {
    let without_query = path.split(['?', '#']).next().unwrap_or(path);
    let file_name = without_query
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(without_query);
    file_name
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .filter(|stem| !stem.is_empty())
        .unwrap_or("XREF")
        .to_string()
}

fn path_mode(path: &str) -> XrefPathMode {
    let lower = path.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        XrefPathMode::Url
    } else if Path::new(path).is_absolute()
        || path.as_bytes().get(1) == Some(&b':')
        || path.starts_with("\\\\")
    {
        XrefPathMode::Absolute
    } else if path.contains('/') || path.contains('\\') {
        XrefPathMode::Relative
    } else {
        XrefPathMode::FilenameOnly
    }
}

fn reference_type(record: &BlockRecord) -> ReferenceType {
    if record.flags.is_xref_overlay {
        ReferenceType::Overlay
    } else {
        ReferenceType::Attachment
    }
}

fn is_direct_xref(record: &BlockRecord) -> bool {
    (record.flags.is_xref || record.flags.is_xref_overlay)
        && !record.flags.is_external
        && !record.name.contains('|')
        && !record.handle.is_null()
        && !record.block_entity_handle.is_null()
        && !record.block_end_handle.is_null()
        && record.handle != record.block_entity_handle
        && record.handle != record.block_end_handle
        && record.block_entity_handle != record.block_end_handle
}

fn attachment_instance_handles(
    document: &CadDocument,
    attachment_name: &str,
) -> Result<Vec<String>, WriteError> {
    let mut handles = document
        .entities()
        .filter_map(|entity| match entity {
            EntityType::Insert(insert) if name_eq(&insert.block_name, attachment_name) => {
                Some(canonical_handle(insert.common.handle))
            }
            _ => None,
        })
        .collect::<Result<Vec<_>, _>>()?;
    handles.sort_by_key(|value| u64::from_str_radix(value, 16).unwrap_or(u64::MAX));
    Ok(handles)
}

fn live_attachment_insert_handles(document: &CadDocument, attachment_name: &str) -> Vec<Handle> {
    let mut handles = document
        .entities()
        .filter_map(|entity| match entity {
            EntityType::Insert(insert) if name_eq(&insert.block_name, attachment_name) => {
                Some(insert.common.handle)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    handles.sort_by_key(|handle| handle.value());
    handles
}

fn rebuild_attachment_reverse_handles(
    document: &mut CadDocument,
    attachment_handle: Handle,
    attachment_name: &str,
) -> Result<(), WriteError> {
    let handles = live_attachment_insert_handles(document, attachment_name);
    let record = document
        .block_records
        .iter_mut()
        .find(|record| record.handle == attachment_handle && is_direct_xref(record))
        .ok_or_else(|| {
            WriteError::target_not_found(
                "xref_not_found",
                "XREF vanished while rebuilding its reverse INSERT index",
            )
        })?;
    record.insert_handles = handles;
    record.insert_count_bytes = vec![1; record.insert_handles.len()];
    Ok(())
}

fn reverse_insert_index_matches(document: &CadDocument, record: &BlockRecord) -> bool {
    record.insert_handles == live_attachment_insert_handles(document, &record.name)
        && record.insert_count_bytes.len() == record.insert_handles.len()
        && record.insert_count_bytes.iter().all(|byte| *byte != 0)
}

fn project_attachment(
    document: &CadDocument,
    handle: Handle,
    _load_states: &BTreeMap<String, LoadState>,
) -> Result<XrefAttachmentRecord, WriteError> {
    let record = document
        .block_records
        .iter()
        .find(|record| record.handle == handle && is_direct_xref(record))
        .ok_or_else(|| {
            WriteError::target_not_found("xref_not_found", "selected XREF was not found")
        })?;
    let canonical = canonical_handle(handle)?;
    Ok(XrefAttachmentRecord {
        handle: canonical.clone(),
        name: record.name.clone(),
        saved_path: record.xref_path.clone(),
        path_mode: path_mode(&record.xref_path),
        reference_type: reference_type(record),
        // acadrust does not expose the parsed DWG loaded bit and its writer
        // currently encodes that bit as false. Do not report the in-session
        // requested state as an observation of candidate bytes.
        load_state: LoadState::Unavailable,
        instance_count: attachment_instance_handles(document, &record.name)?.len() as u64,
        // The DWG writer derives this from a BLOCK marker, not this record,
        // and preservation has not been established at this boundary.
        definition_base_point: XrefPointAvailability::Unavailable,
    })
}

fn resolve_attachment(
    document: &CadDocument,
    bridge: &XrefHandleBridge,
    handle: Option<&str>,
    name: Option<&str>,
    expected_handle: Option<&str>,
    expected_name: Option<&str>,
) -> Result<Handle, WriteError> {
    let handle = handle
        .map(|value| parse_handle(value, "invalid_xref_handle"))
        .transpose()?;
    if handle.is_none() && name.is_none_or(|value| value.trim().is_empty()) {
        return Err(WriteError::invalid_request(
            "missing_identity",
            "attachment mutation requires a handle or non-empty name",
        ));
    }
    let expected_handle = expected_handle
        .map(|value| parse_handle(value, "invalid_expected_xref_handle"))
        .transpose()?;
    let handle = handle
        .map(|handle| bridge.attachment_selector(handle))
        .transpose()?;
    let by_handle = handle
        .map(|wanted| {
            document
                .block_records
                .iter()
                .find(|record| record.handle == wanted && is_direct_xref(record))
                .map(|record| record.handle)
                .ok_or_else(|| {
                    WriteError::target_not_found(
                        "xref_not_found",
                        format!(
                            "direct XREF attachment handle `{:X}` was not found",
                            wanted.value()
                        ),
                    )
                })
        })
        .transpose()?;
    let by_name = name
        .map(|wanted| {
            if wanted.trim().is_empty() {
                return Err(WriteError::target_not_found(
                    "xref_not_found",
                    "empty attachment name selector was not found",
                ));
            }
            let matches = document
                .block_records
                .iter()
                .filter(|record| name_eq(&record.name, wanted) && is_direct_xref(record))
                .map(|record| record.handle)
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [record] => Ok(*record),
                [] => Err(WriteError::target_not_found(
                    "xref_not_found",
                    format!("direct XREF attachment name `{wanted}` was not found"),
                )),
                _ => Err(WriteError::ambiguous_target(
                    "ambiguous_identity",
                    format!("direct XREF attachment name `{wanted}` is ambiguous"),
                )),
            }
        })
        .transpose()?;
    if matches!((by_handle, by_name), (Some(left), Some(right)) if left != right) {
        return Err(WriteError::ambiguous_target(
            "contradictory_identity",
            "XREF handle and name do not resolve to the same attachment",
        ));
    }
    let selected = by_handle.or(by_name).ok_or_else(|| {
        WriteError::target_not_found("xref_not_found", "selected XREF was not found")
    })?;
    if !bridge.proves_attachment(selected) {
        return Err(WriteError::unsupported_source(
            "unproven_direct_xref_membership",
            "selected XREF is not proven to be a direct source attachment",
        ));
    }
    if let Some(expected) = expected_handle {
        if expected != selected {
            return Err(WriteError::invalid_request(
                "expected_handle_mismatch",
                "selected XREF handle does not match expected_handle",
            ));
        }
    }
    let selected_record = document
        .block_records
        .iter()
        .find(|record| record.handle == selected)
        .expect("resolved XREF remains present");
    if expected_name.is_some_and(|expected| !name_eq(expected, &selected_record.name)) {
        return Err(WriteError::invalid_request(
            "expected_name_mismatch",
            "selected XREF name does not match expected_name",
        ));
    }
    Ok(selected)
}

fn resolve_guard(
    document: &CadDocument,
    bridge: &XrefHandleBridge,
    guard: &XrefAttachmentGuard,
) -> Result<Handle, WriteError> {
    resolve_attachment(
        document,
        bridge,
        guard.handle.as_deref(),
        guard.name.as_deref(),
        guard.expected_handle.as_deref(),
        guard.expected_name.as_deref(),
    )
}

fn resolve_destructive_guard(
    document: &CadDocument,
    bridge: &XrefHandleBridge,
    guard: &XrefDestructiveAttachmentGuard,
) -> Result<Handle, WriteError> {
    // Mirror the live request-constructor precedence before consulting locked
    // drawing state: selector, selector shape, attachment guards, then the
    // destructive instance set.
    let _ = guard
        .handle
        .as_deref()
        .map(|value| parse_handle(value, "invalid_xref_handle"))
        .transpose()?;
    if guard.handle.is_none()
        && guard
            .name
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err(WriteError::invalid_request(
            "missing_identity",
            "attachment mutation requires a handle or non-empty name",
        ));
    }
    let _ = guard
        .expected_handle
        .as_deref()
        .map(|value| parse_handle(value, "invalid_expected_xref_handle"))
        .transpose()?;
    let expected_handles = guard
        .expected_instance_handles
        .as_ref()
        .map(|values| {
            let mut canonical = values
                .iter()
                .map(|value| {
                    parse_handle(value, "invalid_expected_instance_handle")
                        .and_then(canonical_handle)
                })
                .collect::<Result<Vec<_>, _>>()?;
            canonical.sort_by_key(|value| u64::from_str_radix(value, 16).unwrap_or(u64::MAX));
            if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(WriteError::invalid_request(
                    "invalid_expected_instance_handles",
                    "expected instance handles must be unique",
                ));
            }
            Ok(canonical)
        })
        .transpose()?;
    let selected = resolve_attachment(
        document,
        bridge,
        guard.handle.as_deref(),
        guard.name.as_deref(),
        guard.expected_handle.as_deref(),
        guard.expected_name.as_deref(),
    )?;
    let record = document
        .block_records
        .iter()
        .find(|record| record.handle == selected)
        .expect("resolved XREF remains present");
    let actual_handles = attachment_instance_handles(document, &record.name)?;
    if guard
        .expected_instance_count
        .is_some_and(|expected| expected != actual_handles.len() as u64)
    {
        return Err(WriteError::invalid_request(
            "expected_instance_count_mismatch",
            "XREF instance count does not match the destructive guard",
        ));
    }
    if let Some(expected) = expected_handles {
        if expected != actual_handles {
            return Err(WriteError::invalid_request(
                "expected_instance_handles_mismatch",
                "XREF instance handles do not match the destructive guard",
            ));
        }
    }
    Ok(selected)
}

fn resolve_instance_attachment(
    document: &CadDocument,
    bridge: &XrefHandleBridge,
    guard: &XrefInstanceAttachmentGuard,
) -> Result<Handle, WriteError> {
    let selected = resolve_attachment(
        document,
        bridge,
        guard.attachment_handle.as_deref(),
        guard.attachment_name.as_deref(),
        guard.expected_attachment_handle.as_deref(),
        None,
    )?;
    Ok(selected)
}

/// acadrust's `BlockRecord::is_model_space()`/`is_paper_space()` are exact
/// case-sensitive checks against `"*Model_Space"`/`"*Paper_Space"`. Real DWG
/// files — e.g. ones converted from DGN — can store these reserved names in
/// a different case (`"*PAPER_SPACE"`), which is still the same semantic
/// record; a name-based check, even a case-insensitive one, is trusting a
/// convention rather than the drawing's actual handle relationships. Prefer
/// handle-based ground truth wherever it exists:
/// - There is exactly one model space per document, and its handle is
///   authoritative in `document.header.model_space_block_handle` (acadrust
///   corrects this from the BLOCK_CONTROL hard-owner reference during
///   parse — it is not just the file header's own possibly-stale copy).
/// - There can be several paper-space layouts, so no single header field
///   covers all of them; a `Layout` object's hard-owner reference to a
///   block record is the equivalent per-record ground truth.
///
/// Name matching remains only as a last-resort fallback for records with
/// neither signal (e.g. an orphaned, un-owned paper-space table entry).
fn is_model_space_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("*Model_Space")
}

fn is_paper_space_name(name: &str) -> bool {
    name.to_ascii_uppercase().starts_with("*PAPER_SPACE")
}

fn is_model_space_record(document: &CadDocument, record: &BlockRecord) -> bool {
    let header_handle = document.header.model_space_block_handle;
    if header_handle.is_valid() {
        record.handle == header_handle
    } else {
        is_model_space_name(&record.name)
    }
}

/// The name of the `Layout` object that hard-owns this block record, if
/// any. This is a stronger, naming-convention-independent signal than
/// `is_paper_space_name` and is preferred wherever available — matching
/// `autocad-reader`'s own owner-classification priority.
fn layout_for_block_record(document: &CadDocument, handle: Handle) -> Option<&str> {
    document.objects.values().find_map(|object| match object {
        ObjectType::Layout(layout) if layout.block_record == handle => Some(layout.name.as_str()),
        _ => None,
    })
}

fn owner_type(document: &CadDocument, record: &BlockRecord) -> XrefOwnerType {
    if is_model_space_record(document, record) {
        XrefOwnerType::ModelSpace
    } else if layout_for_block_record(document, record.handle).is_some()
        || is_paper_space_name(&record.name)
    {
        XrefOwnerType::PaperSpace
    } else {
        XrefOwnerType::BlockDefinition
    }
}

fn owner_semantic_name(document: &CadDocument, record: &BlockRecord) -> String {
    if is_model_space_record(document, record) {
        return "Model".to_string();
    }
    if let Some(name) = layout_for_block_record(document, record.handle) {
        return name.to_string();
    }
    record.name.clone()
}

fn owner_is_unwritable(document: &CadDocument, record: &BlockRecord) -> bool {
    if is_direct_xref(record) {
        return true;
    }
    if !matches!(owner_type(document, record), XrefOwnerType::BlockDefinition) {
        return false;
    }
    record.is_anonymous()
        || record.flags.is_external
        || record.name.contains('|')
        || document
            .block_representations
            .values()
            .any(|definition| *definition == record.handle)
}

fn resolve_owner(
    document: &CadDocument,
    bridge: &XrefHandleBridge,
    requested_handle: Option<&str>,
    requested_type: Option<XrefOwnerType>,
    requested_name: Option<&str>,
) -> Result<(Handle, XrefOwnerType, String), WriteError> {
    if !matches!(
        (
            requested_handle.is_some(),
            requested_type.is_some(),
            requested_name.is_some()
        ),
        (false, false, false) | (true, false, false) | (false, true, true) | (true, true, true)
    ) {
        return Err(WriteError::invalid_request(
            "invalid_xref_owner",
            "owner selection must use {}, {owner_handle}, {owner_type,owner_name}, or all three",
        ));
    }
    let by_handle = requested_handle
        .map(|value| {
            let wanted = parse_handle(value, "invalid_xref_owner_handle")
                .and_then(|handle| bridge.owner_selector(handle))?;
            document
                .block_records
                .iter()
                .find(|record| record.handle == wanted)
                .ok_or_else(|| {
                    WriteError::target_not_found(
                        "xref_owner_not_found",
                        format!("XREF owner handle `{value}` was not found"),
                    )
                })
        })
        .transpose()?;
    let by_semantic = requested_type
        .zip(requested_name)
        .map(|(wanted_type, wanted_name)| {
            let matches = document
                .block_records
                .iter()
                .filter(|record| {
                    owner_type(document, record) == wanted_type
                        && name_eq(&owner_semantic_name(document, record), wanted_name)
                })
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [record] => Ok(*record),
                [] => Err(WriteError::target_not_found(
                    "xref_owner_not_found",
                    format!("semantic XREF owner `{wanted_name}` was not found"),
                )),
                _ => Err(WriteError::unsupported_source(
                    "unsupported_xref_owner",
                    format!("semantic XREF owner `{wanted_name}` is not unique"),
                )),
            }
        })
        .transpose()?;
    let default = document
        .block_records
        .iter()
        .find(|record| is_model_space_record(document, record));
    let selected = match (by_handle, by_semantic) {
        (Some(left), Some(right)) if left.handle != right.handle => {
            return Err(WriteError::ambiguous_target(
                "contradictory_identity",
                "owner handle and semantic selector resolve to different block records",
            ))
        }
        (Some(record), _) | (_, Some(record)) => record,
        (None, None) => default.ok_or_else(|| {
            WriteError::unsupported_source(
                "model_space_not_found",
                "drawing has no model-space block record",
            )
        })?,
    };
    let actual_type = owner_type(document, selected);
    if requested_type.is_some_and(|expected| expected != actual_type) {
        return Err(WriteError::invalid_request(
            "xref_owner_type_mismatch",
            "selected owner does not have the requested owner type",
        ));
    }
    if owner_is_unwritable(document, selected) {
        return Err(WriteError::invalid_request(
            "xref_owner_not_writable",
            "selected XREF instance owner is not a writable host block record",
        ));
    }
    Ok((
        selected.handle,
        actual_type,
        owner_semantic_name(document, selected),
    ))
}

fn resolve_layer(
    document: &CadDocument,
    bridge: &XrefHandleBridge,
    requested_handle: Option<&str>,
    requested_name: Option<&str>,
) -> Result<(Handle, String), WriteError> {
    let by_handle = requested_handle
        .map(|value| {
            let wanted = parse_handle(value, "invalid_xref_layer_handle")
                .and_then(|handle| bridge.layer_selector(handle))?;
            document
                .layers
                .iter()
                .find(|layer| layer.handle() == wanted)
                .ok_or_else(|| {
                    WriteError::target_not_found(
                        "layer_not_found",
                        format!("XREF destination layer handle `{value}` was not found"),
                    )
                })
        })
        .transpose()?;
    let by_name = requested_name
        .map(|wanted| {
            let matches = document
                .layers
                .iter()
                .filter(|layer| name_eq(&layer.name, wanted))
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [layer] => Ok(*layer),
                [] => Err(WriteError::target_not_found(
                    "layer_not_found",
                    format!("XREF destination layer name `{wanted}` was not found"),
                )),
                _ => Err(WriteError::ambiguous_target(
                    "ambiguous_identity",
                    format!("XREF destination layer name `{wanted}` is ambiguous"),
                )),
            }
        })
        .transpose()?;
    let default = document.layers.get("0");
    let selected = match (by_handle, by_name) {
        (Some(left), Some(right)) if left.handle() != right.handle() => {
            return Err(WriteError::ambiguous_target(
                "contradictory_identity",
                "layer handle and name do not resolve to the same layer",
            ))
        }
        (Some(layer), _) | (_, Some(layer)) => layer,
        (None, None) => default.ok_or_else(|| {
            WriteError::unsupported_source("layer_zero_not_found", "drawing has no layer 0")
        })?,
    };
    if is_xref_dependent(selected) {
        return Err(WriteError::invalid_request(
            "layer_not_host_owned",
            "selected XREF instance layer is not host-owned",
        ));
    }
    Ok((selected.handle(), selected.name.clone()))
}

fn validate_point(point: XrefPoint3) -> Result<XrefPoint3, WriteError> {
    if [point.x, point.y, point.z].into_iter().all(f64::is_finite) {
        Ok(point)
    } else {
        Err(WriteError::invalid_request(
            "invalid_xref_placement",
            "insertion point must contain finite values",
        ))
    }
}

fn validate_scale(scale: XrefScale3) -> Result<XrefScale3, WriteError> {
    let validated = scale.validate().map_err(|_| {
        WriteError::invalid_request(
            "invalid_xref_scale",
            "XREF scale must contain finite, non-zero values",
        )
    })?;
    // acadrust 0.4.1's INSERT setters silently replace every component below
    // this threshold with positive 1e-12. Reject the otherwise valid live
    // request instead of mutating its magnitude or sign.
    if [validated.x, validated.y, validated.z]
        .into_iter()
        .any(|value| value.abs() < 1e-12)
    {
        return Err(WriteError::backend_capability(
            "xref_scale_below_acadrust_minimum",
            "acadrust cannot represent an XREF scale component below 1e-12",
        ));
    }
    Ok(validated)
}

fn validate_normal(normal: XrefVector3) -> Result<XrefVector3, WriteError> {
    normal.canonical_normal().map_err(|_| {
        WriteError::invalid_request(
            "invalid_xref_normal",
            "XREF normal must be finite and unit length",
        )
    })
}

fn validate_array(
    array: Option<XrefRectangularArray>,
) -> Result<Option<XrefRectangularArray>, WriteError> {
    let Some(array) = array else {
        return Ok(None);
    };
    if array.rows == 0
        || array.columns == 0
        || array.rows > u16::MAX.into()
        || array.columns > u16::MAX.into()
        || !array.row_spacing.is_finite()
        || !array.column_spacing.is_finite()
    {
        return Err(WriteError::invalid_request(
            "invalid_xref_array",
            "XREF array counts and spacing are outside the writable, representable range",
        ));
    }
    Ok(Some(array))
}

fn resolve_placement(
    document: &CadDocument,
    bridge: &XrefHandleBridge,
    placement: Option<&XrefInstancePlacement>,
) -> Result<ResolvedPlacement, WriteError> {
    let insertion_point = validate_point(
        placement
            .and_then(|value| value.insertion_point)
            .unwrap_or(XrefPoint3 {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            }),
    )?;
    let scale = validate_scale(
        placement
            .and_then(|value| value.scale)
            .unwrap_or(XrefScale3 {
                x: 1.0,
                y: 1.0,
                z: 1.0,
            }),
    )?;
    let rotation_degrees = placement
        .and_then(|value| value.rotation_degrees)
        .unwrap_or(0.0);
    if !rotation_degrees.is_finite() {
        return Err(WriteError::invalid_request(
            "invalid_xref_rotation",
            "XREF rotation must be finite",
        ));
    }
    let normal = validate_normal(placement.and_then(|value| value.normal).unwrap_or(
        XrefVector3 {
            x: 0.0,
            y: 0.0,
            z: 1.0,
        },
    ))?;
    let array = validate_array(placement.and_then(|value| value.array))?;
    let (owner_handle, _, _) = resolve_owner(
        document,
        bridge,
        placement.and_then(|value| value.owner_handle.as_deref()),
        placement.and_then(|value| value.owner_type),
        placement.and_then(|value| value.owner_name.as_deref()),
    )?;
    let (_, layer_name) = resolve_layer(
        document,
        bridge,
        placement.and_then(|value| value.layer_handle.as_deref()),
        placement.and_then(|value| value.layer_name.as_deref()),
    )?;
    Ok(ResolvedPlacement {
        owner_handle,
        layer_name,
        insertion_point,
        scale,
        rotation_degrees: normalize_rotation(rotation_degrees),
        normal,
        visibility: placement
            .and_then(|value| value.visibility)
            .unwrap_or(XrefVisibility::Visible),
        array,
    })
}

fn normalize_rotation(rotation_degrees: f64) -> f64 {
    let normalized = rotation_degrees.rem_euclid(360.0);
    if normalized == 0.0 {
        0.0
    } else {
        normalized
    }
}

fn placement_from_attach(placement: Option<&XrefPlacement>) -> XrefInstancePlacement {
    let Some(placement) = placement else {
        return XrefInstancePlacement::default();
    };
    XrefInstancePlacement {
        owner_handle: placement.owner_handle.clone(),
        owner_type: placement.owner_type,
        owner_name: placement.owner_name.clone(),
        layer_handle: placement.layer_handle.clone(),
        layer_name: placement.layer_name.clone(),
        insertion_point: placement.insertion_point,
        scale: placement.scale,
        rotation_degrees: placement.rotation_degrees,
        normal: placement.normal,
        visibility: placement.visibility,
        array: None,
    }
}

fn add_instance(
    document: &mut CadDocument,
    attachment_handle: Handle,
    attachment_name: &str,
    placement: &ResolvedPlacement,
) -> Result<Handle, WriteError> {
    let mut insert = Insert::new(
        attachment_name,
        Vector3::new(
            placement.insertion_point.x,
            placement.insertion_point.y,
            placement.insertion_point.z,
        ),
    );
    insert.common.owner_handle = placement.owner_handle;
    insert.common.layer = placement.layer_name.clone();
    insert.common.invisible = placement.visibility == XrefVisibility::Hidden;
    insert.set_x_scale(placement.scale.x);
    insert.set_y_scale(placement.scale.y);
    insert.set_z_scale(placement.scale.z);
    insert.rotation = placement.rotation_degrees.to_radians();
    insert.normal = Vector3::new(placement.normal.x, placement.normal.y, placement.normal.z);
    if let Some(array) = placement.array {
        insert.row_count = array.rows as u16;
        insert.column_count = array.columns as u16;
        insert.row_spacing = array.row_spacing;
        insert.column_spacing = array.column_spacing;
    }
    let handle = document
        .add_entity(EntityType::Insert(insert))
        .map_err(|error| WriteError::invalid_drawing(error.to_string()))?;
    rebuild_attachment_reverse_handles(document, attachment_handle, attachment_name)?;
    Ok(handle)
}

fn project_instance(
    document: &CadDocument,
    handle: Handle,
) -> Result<XrefInstanceRecord, WriteError> {
    let insert = match document.get_entity(handle) {
        Some(EntityType::Insert(insert)) => insert,
        _ => {
            return Err(WriteError::target_not_found(
                "xref_instance_not_found",
                "selected XREF instance was not found",
            ))
        }
    };
    let attachment = document
        .block_records
        .iter()
        .find(|record| name_eq(&record.name, &insert.block_name) && is_direct_xref(record))
        .ok_or_else(|| {
            WriteError::target_not_found(
                "xref_instance_not_found",
                "selected INSERT is not a direct XREF instance",
            )
        })?;
    let owner = document
        .block_records
        .iter()
        .find(|record| record.handle == insert.common.owner_handle)
        .ok_or_else(|| {
            WriteError::unsupported_source(
                "xref_instance_owner_unavailable",
                "XREF instance owner block record is unavailable",
            )
        })?;
    let layer = document.layers.get(&insert.common.layer).ok_or_else(|| {
        WriteError::unsupported_source(
            "xref_instance_layer_unavailable",
            "XREF instance layer is unavailable",
        )
    })?;
    let array = insert.is_array().then_some(XrefRectangularArray {
        rows: u32::from(insert.row_count),
        columns: u32::from(insert.column_count),
        row_spacing: insert.row_spacing,
        column_spacing: insert.column_spacing,
    });
    Ok(XrefInstanceRecord {
        handle: canonical_handle(handle)?,
        attachment_handle: canonical_handle(attachment.handle)?,
        attachment_name: attachment.name.clone(),
        owner_handle: canonical_handle(owner.handle)?,
        owner_type: owner_type(document, owner),
        owner_name: owner_semantic_name(document, owner),
        layer_handle: canonical_handle(layer.handle())?,
        layer_name: layer.name.clone(),
        insertion_point: XrefPoint3 {
            x: insert.insert_point.x,
            y: insert.insert_point.y,
            z: insert.insert_point.z,
        },
        scale: XrefScale3 {
            x: insert.x_scale(),
            y: insert.y_scale(),
            z: insert.z_scale(),
        },
        rotation_degrees: normalize_rotation(insert.rotation.to_degrees()),
        normal: validate_normal(XrefVector3 {
            x: insert.normal.x,
            y: insert.normal.y,
            z: insert.normal.z,
        })?,
        visibility: if insert.common.invisible {
            XrefVisibility::Hidden
        } else {
            XrefVisibility::Visible
        },
        placement_kind: if array.is_some() {
            XrefPlacementKind::RectangularArray
        } else {
            XrefPlacementKind::Single
        },
        array,
        unit_scaling: XrefUnitScaling::Unavailable,
    })
}

fn resolve_instance_guard(
    document: &CadDocument,
    bridge: &XrefHandleBridge,
    guard: &XrefInstanceGuard,
) -> Result<Handle, WriteError> {
    let handle = parse_handle(&guard.handle, "invalid_xref_instance_handle")?;
    let expected_attachment = guard
        .expected_attachment_handle
        .as_deref()
        .map(|value| parse_handle(value, "invalid_expected_attachment_handle"))
        .transpose()?;
    let expected_owner = guard
        .expected_owner_handle
        .as_deref()
        .map(|value| parse_handle(value, "invalid_expected_owner_handle"))
        .transpose()?;
    let handle = bridge.instance_selector(handle)?;
    let insert = match document.get_entity(handle) {
        Some(EntityType::Insert(insert)) => insert,
        _ => {
            return Err(WriteError::target_not_found(
                "xref_instance_not_found",
                "selected XREF instance was not found",
            ))
        }
    };
    let attachment = document
        .block_records
        .iter()
        .find(|record| name_eq(&record.name, &insert.block_name) && is_direct_xref(record))
        .ok_or_else(|| {
            WriteError::target_not_found(
                "xref_instance_not_found",
                "selected INSERT is not a direct XREF instance",
            )
        })?;
    if !bridge.proves_attachment(attachment.handle) {
        return Err(WriteError::unsupported_source(
            "unproven_direct_xref_membership",
            "selected XREF instance parent is not proven to be a direct source attachment",
        ));
    }
    if let Some(expected) = expected_attachment {
        if attachment.handle != expected {
            return Err(WriteError::invalid_request(
                "expected_attachment_handle_mismatch",
                "XREF instance attachment does not match its guard",
            ));
        }
    }
    if let Some(expected) = expected_owner {
        if insert.common.owner_handle != expected {
            return Err(WriteError::invalid_request(
                "expected_owner_handle_mismatch",
                "XREF instance owner does not match its guard",
            ));
        }
    }
    Ok(handle)
}

fn clip_object_owner(object: &ObjectType) -> Option<Handle> {
    match object {
        ObjectType::Dictionary(value) => Some(value.owner),
        ObjectType::DictionaryWithDefault(value) => Some(value.owner),
        ObjectType::SpatialFilter(value) => Some(value.owner),
        ObjectType::Unknown { owner, .. } => Some(*owner),
        _ => None,
    }
}

fn object_owner_chain_reaches(document: &CadDocument, start: Handle, target: Handle) -> bool {
    let mut current = start;
    for _ in 0..16 {
        if current == target {
            return true;
        }
        let Some(next) = document.objects.get(&current).and_then(clip_object_owner) else {
            return false;
        };
        if next.is_null() || next == current {
            return false;
        }
        current = next;
    }
    current == target
}

fn instance_has_spatial_filter(document: &CadDocument, insert: &Insert) -> bool {
    let Some(extension_dictionary) = insert.common.xdictionary_handle else {
        return false;
    };
    document.objects.values().any(|object| {
        matches!(
            object,
            ObjectType::SpatialFilter(filter)
                if object_owner_chain_reaches(document, filter.owner, extension_dictionary)
        )
    })
}

fn validate_existing_instance_writable(
    document: &CadDocument,
    handle: Handle,
) -> Result<(), WriteError> {
    let insert = match document.get_entity(handle) {
        Some(EntityType::Insert(insert)) => insert,
        _ => unreachable!("instance guard resolved an INSERT"),
    };
    let owner = document
        .block_records
        .iter()
        .find(|record| record.handle == insert.common.owner_handle)
        .ok_or_else(|| {
            WriteError::unsupported_source(
                "unsupported_xref_owner",
                "existing XREF instance owner cannot be proven writable",
            )
        })?;
    if owner_is_unwritable(document, owner) {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_owner",
            "existing XREF instance owner is not a writable host block record",
        ));
    }
    let layer = document.layers.get(&insert.common.layer).ok_or_else(|| {
        WriteError::unsupported_source(
            "layer_not_found",
            "existing XREF instance layer is unavailable",
        )
    })?;
    if is_xref_dependent(layer) {
        return Err(WriteError::invalid_request(
            "layer_not_host_owned",
            "existing XREF instance layer is not host-owned",
        ));
    }
    if layer.flags.locked {
        return Err(WriteError::invalid_request(
            "xref_instance_locked",
            "existing XREF instance is on a locked layer",
        ));
    }
    if instance_has_spatial_filter(document, insert) {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_clip_data",
            "XREF instance clip mutation is not represented by the writer baseline",
        ));
    }
    Ok(())
}

fn validate_instance_deletion_writable(
    document: &CadDocument,
    handle: Handle,
) -> Result<(), WriteError> {
    validate_existing_instance_writable(document, handle)?;
    validate_entity_deletion_metadata(document, handle)
}

fn validate_entity_deletion_metadata(
    document: &CadDocument,
    handle: Handle,
) -> Result<(), WriteError> {
    let entity = document.get_entity(handle).ok_or_else(|| {
        WriteError::unsupported_source(
            "unsupported_xref_data",
            "an XREF-owned entity selected for deletion is unavailable",
        )
    })?;
    if entity.common().xdictionary_handle.is_some() || !entity.common().reactors.is_empty() {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_data",
            "XREF entity extension-dictionary or reactor ownership cannot be deleted safely",
        ));
    }
    Ok(())
}

fn would_create_recursive_ownership(
    document: &CadDocument,
    attachment_handle: Handle,
    owner_handle: Handle,
) -> Result<bool, WriteError> {
    let owner = document
        .block_records
        .iter()
        .find(|record| record.handle == owner_handle)
        .ok_or_else(|| {
            WriteError::unsupported_source(
                "unsupported_xref_owner",
                "selected XREF instance owner is unavailable",
            )
        })?;
    if !matches!(owner_type(document, owner), XrefOwnerType::BlockDefinition) {
        return Ok(false);
    }
    if attachment_handle == owner_handle {
        return Ok(true);
    }
    let attachment = document
        .block_records
        .iter()
        .find(|record| record.handle == attachment_handle && is_direct_xref(record))
        .expect("resolved attachment remains present");
    if attachment.entity_handles.is_empty() {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_data",
            "external block-reference graph is unavailable for recursive-ownership proof",
        ));
    }

    let mut pending = vec![attachment_handle];
    let mut visited = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !visited.insert(current) {
            continue;
        }
        if current == owner_handle {
            return Ok(true);
        }
        let record = document
            .block_records
            .iter()
            .find(|record| record.handle == current)
            .ok_or_else(|| {
                WriteError::unsupported_source(
                    "unsupported_xref_data",
                    "block-reference graph contains an unavailable definition",
                )
            })?;
        for entity_handle in &record.entity_handles {
            let entity = document.get_entity(*entity_handle).ok_or_else(|| {
                WriteError::unsupported_source(
                    "unsupported_xref_data",
                    "block-reference graph contains an unavailable owned entity",
                )
            })?;
            let EntityType::Insert(insert) = entity else {
                continue;
            };
            let referenced = document
                .block_records
                .iter()
                .find(|candidate| name_eq(&candidate.name, &insert.block_name))
                .ok_or_else(|| {
                    WriteError::unsupported_source(
                        "unsupported_xref_data",
                        "block-reference graph contains an unavailable referenced definition",
                    )
                })?;
            pending.push(referenced.handle);
        }
    }
    Ok(false)
}

fn remove_instance(document: &mut CadDocument, handle: Handle) -> Option<EntityType> {
    let entity = document.remove_entity(handle)?;
    for object in document.objects.values_mut() {
        match object {
            ObjectType::Group(group) => {
                group.entities.retain(|candidate| *candidate != handle);
            }
            ObjectType::SortEntitiesTable(table) => {
                let _ = table.remove_entry(handle);
            }
            _ => {}
        }
    }
    let owner = entity.common().owner_handle;
    let attachment = match &entity {
        EntityType::Insert(insert) => document
            .block_records
            .iter()
            .find(|record| name_eq(&record.name, &insert.block_name) && is_direct_xref(record))
            .map(|record| (record.handle, record.name.clone())),
        _ => None,
    };
    for record in document.block_records.iter_mut() {
        if record.handle == owner {
            record
                .entity_handles
                .retain(|candidate| *candidate != handle);
        }
    }
    if let Some((attachment_handle, attachment_name)) = attachment {
        // The attachment still exists for instance deletion and for the
        // first phase of detach. A rebuild prevents stale parsed reverse
        // handles from being carried into the candidate.
        let _ = rebuild_attachment_reverse_handles(document, attachment_handle, &attachment_name);
    }
    Some(entity)
}

fn validate_reconciliation(request: &LayerReconciliation) -> Result<(), WriteError> {
    let properties = request.properties.as_deref().unwrap_or_default();
    let mut unique = properties.to_vec();
    unique.sort();
    unique.dedup();
    let valid_shape = match request.mode {
        LayerReconciliationMode::Synchronize => !properties.is_empty(),
        _ => properties.is_empty(),
    };
    if unique.len() != properties.len() || !valid_shape {
        return Err(WriteError::invalid_request(
            "invalid_layer_reconciliation",
            "XREF layer reconciliation properties do not match the selected mode",
        ));
    }
    Ok(())
}

// Only `reload` (below) calls this; see the `#[allow(dead_code)]` note on
// `XrefPostcondition::LoadState` for why that route is currently unreachable
// from `session.rs`.
#[allow(dead_code)]
fn reconciliation_plan(request: Option<&LayerReconciliation>) -> LayerReconciliationEvidence {
    let requested_mode = request
        .map(|request| request.mode)
        .unwrap_or(LayerReconciliationMode::DrawingPolicy);
    LayerReconciliationEvidence {
        requested_mode,
        effective_mode: None,
        synchronized_properties: Vec::new(),
        materialized: false,
    }
}

fn candidate_diagnostics(
    format: DrawingFormat,
    has_units: bool,
    has_reconciliation: bool,
    has_search_paths: bool,
) -> Vec<String> {
    let mut diagnostics = vec![
        "xref_external_source_resolution_not_proven".to_string(),
        "xref_reverse_reference_preservation_requires_roundtrip_proof".to_string(),
    ];
    if format == DrawingFormat::Dxf {
        diagnostics.push("xref_load_state_unobservable_in_dxf".to_string());
    } else {
        diagnostics.push("acadrust_xref_load_state_not_modelled".to_string());
        diagnostics.push("acadrust_dwg_writer_forces_xref_loaded_false".to_string());
        diagnostics.push("xref_definition_base_point_roundtrip_unproven".to_string());
    }
    diagnostics.push("xref_non_layer_dependent_namespace_preservation_unproven".to_string());
    if has_units {
        diagnostics.push("xref_unit_scaling_assumptions_not_applied_by_acadrust".to_string());
    }
    if has_reconciliation {
        diagnostics.push("xref_layer_reconciliation_not_materialized_by_acadrust".to_string());
    }
    if has_search_paths {
        diagnostics.push("xref_search_paths_not_applied_by_acadrust".to_string());
    }
    diagnostics
}

fn is_dependent_name(name: &str, attachment_name: &str) -> bool {
    name.split_once('|')
        .is_some_and(|(prefix, _)| name_eq(prefix, attachment_name))
}

#[derive(Debug)]
struct AttachmentDependentLayer {
    name: String,
    handle: Handle,
    suffix: String,
}

fn attachment_dependent_layers(
    document: &CadDocument,
    format: DrawingFormat,
    attachment_handle: Handle,
    attachment_name: &str,
) -> Result<Vec<AttachmentDependentLayer>, WriteError> {
    let mut layers = Vec::new();
    for layer in document.layers.iter() {
        let name_parts = layer.name.split_once('|');
        let prefix_claims_attachment = name_parts
            .as_ref()
            .is_some_and(|(prefix, _)| name_eq(prefix, attachment_name));
        let canonical_suffix = name_parts
            .as_ref()
            .filter(|(prefix, suffix)| {
                !prefix.is_empty() && !suffix.is_empty() && name_eq(prefix, attachment_name)
            })
            .map(|(_, suffix)| (*suffix).to_string());
        let handle_claims_attachment = layer.xref_block_record_handle == attachment_handle;

        if !prefix_claims_attachment && !handle_claims_attachment {
            continue;
        }

        let handle_is_consistent = handle_claims_attachment
            || (format == DrawingFormat::Dxf && layer.xref_block_record_handle.is_null());
        let Some(suffix) = canonical_suffix else {
            return Err(WriteError::unsupported_source(
                "unsupported_xref_data",
                format!(
                    "layer `{}` is associated with XREF `{attachment_name}` by handle or prefix but has no canonical `{attachment_name}|...` name",
                    layer.name
                ),
            ));
        };
        if !layer.flags.xref_dependent || !handle_is_consistent {
            return Err(WriteError::unsupported_source(
                "unsupported_xref_data",
                format!(
                    "layer `{}` has contradictory dependency flag, XREF handle, and `{attachment_name}|` prefix ownership",
                    layer.name
                ),
            ));
        }

        layers.push(AttachmentDependentLayer {
            name: layer.name.clone(),
            handle: layer.handle(),
            suffix,
        });
    }
    Ok(layers)
}

fn plan_dependent_layer_renames(
    document: &CadDocument,
    layers: Vec<AttachmentDependentLayer>,
    new_attachment_name: &str,
) -> Result<Vec<(AttachmentDependentLayer, String)>, WriteError> {
    let mut plan: Vec<(AttachmentDependentLayer, String)> = Vec::with_capacity(layers.len());
    for layer in layers {
        let new_layer_name = format!("{new_attachment_name}|{}", layer.suffix);
        if plan
            .iter()
            .any(|(_, planned_name)| name_eq(planned_name, &new_layer_name))
            || document.layers.iter().any(|candidate| {
                candidate.handle() != layer.handle && name_eq(&candidate.name, &new_layer_name)
            })
        {
            return Err(WriteError::invalid_request(
                "xref_dependent_layer_collision",
                format!("renaming the XREF would collide with layer `{new_layer_name}`"),
            ));
        }
        plan.push((layer, new_layer_name));
    }
    Ok(plan)
}

#[derive(Debug)]
struct AttachmentDependentLineType {
    name: String,
    handle: Handle,
    suffix: String,
}

/// Mirrors `attachment_dependent_layers`, adapted to `LineType`'s narrower
/// persisted shape: DWG/DXF give linetypes only an `xref_dependent` bit, no
/// owner-handle back-reference to the XREF block record (that back-reference
/// is a `Layer`-only field). The `{attachment_name}|{suffix}` name prefix is
/// therefore the *only* ground truth AutoCAD itself persists for dependent
/// linetypes — this isn't a fallback shortcut, it's the whole signal that
/// exists for this table.
fn attachment_dependent_line_types(
    document: &CadDocument,
    attachment_name: &str,
) -> Result<Vec<AttachmentDependentLineType>, WriteError> {
    let mut line_types = Vec::new();
    for line_type in document.line_types.iter() {
        let name_parts = line_type.name.split_once('|');
        let prefix_claims_attachment = name_parts
            .as_ref()
            .is_some_and(|(prefix, _)| name_eq(prefix, attachment_name));
        if !prefix_claims_attachment {
            continue;
        }
        let canonical_suffix = name_parts
            .filter(|(prefix, suffix)| !prefix.is_empty() && !suffix.is_empty())
            .map(|(_, suffix)| suffix.to_string());
        let Some(suffix) = canonical_suffix else {
            return Err(WriteError::unsupported_source(
                "unsupported_xref_data",
                format!(
                    "linetype `{}` is associated with XREF `{attachment_name}` by prefix but has no canonical `{attachment_name}|...` name",
                    line_type.name
                ),
            ));
        };
        if !line_type.xref_dependent {
            return Err(WriteError::unsupported_source(
                "unsupported_xref_data",
                format!(
                    "linetype `{}` has a `{attachment_name}|` prefix but is not marked XREF-dependent",
                    line_type.name
                ),
            ));
        }
        line_types.push(AttachmentDependentLineType {
            name: line_type.name.clone(),
            handle: line_type.handle,
            suffix,
        });
    }
    Ok(line_types)
}

fn plan_dependent_line_type_renames(
    document: &CadDocument,
    line_types: Vec<AttachmentDependentLineType>,
    new_attachment_name: &str,
) -> Result<Vec<(AttachmentDependentLineType, String)>, WriteError> {
    let mut plan: Vec<(AttachmentDependentLineType, String)> = Vec::with_capacity(line_types.len());
    for line_type in line_types {
        let new_name = format!("{new_attachment_name}|{}", line_type.suffix);
        if plan
            .iter()
            .any(|(_, planned_name)| name_eq(planned_name, &new_name))
            || document.line_types.iter().any(|candidate| {
                candidate.handle != line_type.handle && name_eq(&candidate.name, &new_name)
            })
        {
            return Err(WriteError::invalid_request(
                "xref_dependent_line_type_collision",
                format!("renaming the XREF would collide with linetype `{new_name}`"),
            ));
        }
        plan.push((line_type, new_name));
    }
    Ok(plan)
}

fn entity_references_linetype(entity: &EntityType, name: &str) -> bool {
    if name_eq(&entity.common().linetype, name) {
        return true;
    }
    match entity {
        EntityType::Insert(insert) => insert
            .attributes
            .iter()
            .any(|attribute| name_eq(&attribute.common.linetype, name)),
        EntityType::PolygonMesh(mesh) => mesh
            .vertices
            .iter()
            .any(|vertex| name_eq(&vertex.common.linetype, name)),
        EntityType::PolyfaceMesh(mesh) => {
            mesh.vertices
                .iter()
                .any(|vertex| name_eq(&vertex.common.linetype, name))
                || mesh
                    .faces
                    .iter()
                    .any(|face| name_eq(&face.common.linetype, name))
        }
        _ => false,
    }
}

fn rewrite_entity_linetype_references(entity: &mut EntityType, old_name: &str, new_name: &str) {
    if name_eq(&entity.common().linetype, old_name) {
        entity.common_mut().linetype = new_name.to_string();
    }
    match entity {
        EntityType::Insert(insert) => {
            for attribute in &mut insert.attributes {
                if name_eq(&attribute.common.linetype, old_name) {
                    attribute.common.linetype = new_name.to_string();
                }
            }
        }
        EntityType::PolygonMesh(mesh) => {
            for vertex in &mut mesh.vertices {
                if name_eq(&vertex.common.linetype, old_name) {
                    vertex.common.linetype = new_name.to_string();
                }
            }
        }
        EntityType::PolyfaceMesh(mesh) => {
            for vertex in &mut mesh.vertices {
                if name_eq(&vertex.common.linetype, old_name) {
                    vertex.common.linetype = new_name.to_string();
                }
            }
            for face in &mut mesh.faces {
                if name_eq(&face.common.linetype, old_name) {
                    face.common.linetype = new_name.to_string();
                }
            }
        }
        _ => {}
    }
}

/// True if the document has non-layer, non-linetype dependent symbols for
/// `attachment_name` — the remaining categories the writer does not yet know
/// how to rename or remove safely (text/dim styles, app IDs, views, VPORTs,
/// UCSs, nested dependent blocks, table styles, multileader styles).
fn has_non_layer_dependent_symbols(document: &CadDocument, attachment_name: &str) -> bool {
    document
        .text_styles
        .names()
        .any(|name| is_dependent_name(name, attachment_name))
        || document
            .dim_styles
            .names()
            .any(|name| is_dependent_name(name, attachment_name))
        || document
            .app_ids
            .names()
            .any(|name| is_dependent_name(name, attachment_name))
        || document
            .views
            .names()
            .any(|name| is_dependent_name(name, attachment_name))
        || document
            .vports
            .names()
            .any(|name| is_dependent_name(name, attachment_name))
        || document
            .ucss
            .names()
            .any(|name| is_dependent_name(name, attachment_name))
        || document
            .block_records
            .names()
            .any(|name| is_dependent_name(name, attachment_name))
        || document.objects.values().any(|object| match object {
            ObjectType::TableStyle(style) => is_dependent_name(&style.name, attachment_name),
            ObjectType::MultiLeaderStyle(style) => is_dependent_name(&style.name, attachment_name),
            _ => false,
        })
}

pub(super) fn attach(
    document: &mut CadDocument,
    format: DrawingFormat,
    load_states: &mut BTreeMap<String, LoadState>,
    bridge: &XrefHandleBridge,
    request: &AttachXref,
) -> Result<Mutation<AttachXrefResult>, WriteError> {
    validate_xref_path(&request.xref_path)?;
    validate_search_paths(request.search_paths.as_deref())?;
    let name = request
        .name
        .clone()
        .unwrap_or_else(|| default_xref_name(&request.xref_path));
    validate_xref_name(&name)?;
    if document
        .block_records
        .iter()
        .any(|record| name_eq(&record.name, &name))
    {
        return Err(WriteError::invalid_request(
            "xref_name_collision",
            format!("block or XREF `{name}` already exists"),
        ));
    }
    let placement = resolve_placement(
        document,
        bridge,
        Some(&placement_from_attach(request.placement.as_ref())),
    )?;
    let mut record = BlockRecord::new(&name);
    record.handle = document.allocate_handle();
    record.block_entity_handle = document.allocate_handle();
    record.block_end_handle = document.allocate_handle();
    record.flags.is_xref = request.reference_type == ReferenceType::Attachment;
    record.flags.is_xref_overlay = request.reference_type == ReferenceType::Overlay;
    record.xref_path = request.xref_path.clone();
    let handle = record.handle;
    let block_handle = record.block_entity_handle;
    let block_end_handle = record.block_end_handle;
    document
        .block_records
        .add(record)
        .map_err(|detail| WriteError::invalid_request("xref_name_collision", detail.to_string()))?;
    let mut block = Block::new(&name, Vector3::ZERO).with_xref_path(&request.xref_path);
    block.common.handle = block_handle;
    block.common.owner_handle = handle;
    document
        .add_entity(EntityType::Block(block))
        .map_err(|error| WriteError::invalid_drawing(error.to_string()))?;
    let mut block_end = BlockEnd::new();
    block_end.common.handle = block_end_handle;
    block_end.common.owner_handle = handle;
    document
        .add_entity(EntityType::BlockEnd(block_end))
        .map_err(|error| WriteError::invalid_drawing(error.to_string()))?;
    let instance_handle = add_instance(document, handle, &name, &placement)?;
    let canonical = canonical_handle(handle)?;
    load_states.insert(canonical.clone(), LoadState::Loaded);
    let attachment = project_attachment(document, handle, load_states)?;
    let instance = project_instance(document, instance_handle)?;
    Ok(Mutation {
        postcondition: XrefPostcondition::AttachmentPresent {
            handle: canonical,
            name,
            saved_path: request.xref_path.clone(),
            reference_type: request.reference_type,
            instance_handles: vec![canonical_handle(instance_handle)?],
        },
        result: AttachXrefResult {
            attachment,
            instance,
        },
        diagnostics: candidate_diagnostics(
            format,
            request.unit_assumptions.is_some(),
            false,
            request.search_paths.is_some(),
        ),
    })
}

pub(super) fn update(
    document: &mut CadDocument,
    format: DrawingFormat,
    load_states: &mut BTreeMap<String, LoadState>,
    bridge: &XrefHandleBridge,
    request: &UpdateXref,
) -> Result<Mutation<UpdateXrefResult>, WriteError> {
    if request.properties.name.is_none()
        && request.properties.xref_path.is_none()
        && request.properties.reference_type.is_none()
    {
        return Err(WriteError::invalid_request(
            "empty_xref_update",
            "XREF update contains no properties",
        ));
    }
    if request.properties.xref_path.is_none()
        && (request.search_paths.is_some()
            || request.layer_reconciliation.is_some()
            || request.unit_assumptions.is_some())
    {
        return Err(WriteError::invalid_request(
            "invalid_parameters",
            "search_paths, layer_reconciliation, and unit_assumptions require xref_path",
        ));
    }
    if let Some(reconciliation) = &request.layer_reconciliation {
        validate_reconciliation(reconciliation)?;
    }
    let handle = resolve_guard(document, bridge, &request.attachment)?;
    let old_name = document
        .block_records
        .iter()
        .find(|record| record.handle == handle)
        .expect("resolved XREF remains present")
        .name
        .clone();
    if let Some(path) = &request.properties.xref_path {
        validate_xref_path(path)?;
    }
    validate_search_paths(request.search_paths.as_deref())?;
    if let Some(name) = &request.properties.name {
        validate_xref_name(name)?;
        if !name_eq(name, &old_name)
            && document
                .block_records
                .iter()
                .any(|record| name_eq(&record.name, name))
        {
            return Err(WriteError::invalid_request(
                "xref_name_collision",
                format!("block or XREF `{name}` already exists"),
            ));
        }
    }
    let new_name = request
        .properties
        .name
        .clone()
        .unwrap_or_else(|| old_name.clone());
    let name_changes = old_name != new_name;
    if name_changes && has_non_layer_dependent_symbols(document, &old_name) {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_dependent_symbols",
            "XREF rename requires dependent non-layer namespace rewrites not represented by acadrust",
        ));
    }
    let dependent_layer_renames = if !name_changes {
        Vec::new()
    } else {
        plan_dependent_layer_renames(
            document,
            attachment_dependent_layers(document, format, handle, &old_name)?,
            &new_name,
        )?
    };
    let dependent_line_type_renames = if !name_changes {
        Vec::new()
    } else {
        plan_dependent_line_type_renames(
            document,
            attachment_dependent_line_types(document, &old_name)?,
            &new_name,
        )?
    };
    if (!dependent_layer_renames.is_empty() || !dependent_line_type_renames.is_empty())
        && has_opaque_layer_references(document)
    {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_data",
            "cannot rename XREF-dependent layers or linetypes while opaque layer references are present",
        ));
    }
    let mut record = document
        .block_records
        .remove(&old_name)
        .expect("resolved XREF remains present");
    record.name = new_name.clone();
    if let Some(path) = &request.properties.xref_path {
        record.xref_path = path.clone();
    }
    if let Some(reference_type) = request.properties.reference_type {
        record.flags.is_xref = reference_type == ReferenceType::Attachment;
        record.flags.is_xref_overlay = reference_type == ReferenceType::Overlay;
    }
    let new_path = record.xref_path.clone();
    document
        .block_records
        .add(record)
        .expect("validated XREF replacement has a unique name");
    for entity in document.entities_mut() {
        match entity {
            EntityType::Insert(insert) if name_changes => {
                if name_eq(&insert.block_name, &old_name) {
                    insert.block_name = new_name.clone();
                }
            }
            EntityType::Block(block) if name_eq(&block.name, &old_name) => {
                block.name = new_name.clone();
                block.xref_path = new_path.clone();
            }
            _ => {}
        }
    }
    if name_changes {
        for (dependent_layer, new_layer_name) in dependent_layer_renames {
            let old_layer_name = dependent_layer.name;
            let mut layer = document
                .layers
                .remove(&old_layer_name)
                .expect("dependent layer remains present");
            debug_assert_eq!(layer.handle(), dependent_layer.handle);
            layer.name = new_layer_name.clone();
            document
                .layers
                .add(layer)
                .expect("dependent layer rename collisions were preflighted");
            for entity in document.entities_mut() {
                rewrite_entity_layer_references(entity, &old_layer_name, &new_layer_name);
            }
        }
        for (dependent_line_type, new_line_type_name) in dependent_line_type_renames {
            let old_line_type_name = dependent_line_type.name;
            let mut line_type = document
                .line_types
                .remove(&old_line_type_name)
                .expect("dependent linetype remains present");
            debug_assert_eq!(line_type.handle, dependent_line_type.handle);
            line_type.name = new_line_type_name.clone();
            document
                .line_types
                .add(line_type)
                .expect("dependent linetype rename collisions were preflighted");
            for entity in document.entities_mut() {
                rewrite_entity_linetype_references(
                    entity,
                    &old_line_type_name,
                    &new_line_type_name,
                );
            }
            for layer in document.layers.iter_mut() {
                if name_eq(&layer.line_type, &old_line_type_name) {
                    layer.line_type = new_line_type_name.clone();
                }
            }
        }
    }
    rebuild_attachment_reverse_handles(document, handle, &new_name)?;
    let attachment = project_attachment(document, handle, load_states)?;
    let instance_handles = attachment_instance_handles(document, &new_name)?;
    Ok(Mutation {
        postcondition: XrefPostcondition::AttachmentPresent {
            handle: attachment.handle.clone(),
            name: attachment.name.clone(),
            saved_path: attachment.saved_path.clone(),
            reference_type: attachment.reference_type,
            instance_handles,
        },
        result: UpdateXrefResult {
            attachment,
            // No persisted reconciliation is claimed. The receipt and
            // diagnostics retain the requested-but-unmaterialized boundary.
            layer_reconciliation: None,
        },
        diagnostics: candidate_diagnostics(
            format,
            request.unit_assumptions.is_some(),
            request.layer_reconciliation.is_some(),
            request.search_paths.is_some(),
        ),
    })
}

pub(super) fn detach(
    document: &mut CadDocument,
    format: DrawingFormat,
    load_states: &mut BTreeMap<String, LoadState>,
    bridge: &XrefHandleBridge,
    request: &DetachXref,
) -> Result<Mutation<DetachXrefResult>, WriteError> {
    let handle = resolve_destructive_guard(document, bridge, &request.attachment)?;
    let attachment = project_attachment(document, handle, load_states)?;
    if has_non_layer_dependent_symbols(document, &attachment.name) {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_dependent_symbols",
            "XREF detach cannot remove represented non-layer dependent symbols safely",
        ));
    }
    let deleted_instance_handles = attachment_instance_handles(document, &attachment.name)?;
    for instance_handle in &deleted_instance_handles {
        validate_instance_deletion_writable(
            document,
            parse_handle(instance_handle, "invalid_xref_instance_handle")?,
        )?;
    }
    let (mut owned_handles, definition_marker_handles) = {
        let record = document
            .block_records
            .iter()
            .find(|record| record.handle == handle)
            .expect("resolved XREF remains present");
        let mut handles = record.entity_handles.clone();
        let markers = [record.block_entity_handle, record.block_end_handle]
            .into_iter()
            .filter(|handle| !handle.is_null())
            .collect::<Vec<_>>();
        // acadrust's DXF reader intentionally retains BLOCK/ENDBLK only as
        // BlockRecord marker handles; they are not entities in its flat map.
        // DWG materializes those markers and therefore admits their metadata
        // to the same deletion checks as definition-owned body entities.
        if format == DrawingFormat::Dwg {
            handles.extend(markers.iter().copied());
        }
        (handles, markers)
    };
    owned_handles.sort_by_key(|handle| handle.value());
    owned_handles.dedup();
    for owned_handle in &owned_handles {
        let owned_entity = document.get_entity(*owned_handle).ok_or_else(|| {
            WriteError::unsupported_source(
                "unsupported_xref_data",
                "an XREF-owned entity selected for deletion is unavailable",
            )
        })?;
        if owned_entity.common().owner_handle != handle {
            return Err(WriteError::unsupported_source(
                "unsupported_xref_data",
                "the XREF definition ownership index contains a foreign-owned entity",
            ));
        }
        validate_entity_deletion_metadata(document, *owned_handle)?;
    }
    if document.entities().any(|entity| {
        entity.common().owner_handle == handle
            && owned_handles
                .binary_search_by_key(&entity.common().handle.value(), |candidate| {
                    candidate.value()
                })
                .is_err()
    }) {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_data",
            "the XREF definition ownership index omits an owned entity",
        ));
    }
    let dependent_layers = attachment_dependent_layers(document, format, handle, &attachment.name)?
        .into_iter()
        .map(|layer| (layer.name, layer.handle))
        .collect::<Vec<_>>();
    let dependent_line_types = attachment_dependent_line_types(document, &attachment.name)?;
    if current_layer_handle(document).is_some_and(|current_handle| {
        dependent_layers
            .iter()
            .any(|(_, dependent_handle)| *dependent_handle == current_handle)
    }) {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_data",
            "the current layer is XREF-dependent and cannot be removed during detach",
        ));
    }
    let mut removal_handles = owned_handles.iter().copied().collect::<BTreeSet<_>>();
    removal_handles.insert(handle);
    removal_handles.extend(definition_marker_handles);
    for instance_handle in &deleted_instance_handles {
        removal_handles.insert(parse_handle(
            instance_handle,
            "invalid_xref_instance_handle",
        )?);
    }
    for (_, layer_handle) in &dependent_layers {
        removal_handles.insert(*layer_handle);
    }
    for dependent_line_type in &dependent_line_types {
        removal_handles.insert(dependent_line_type.handle);
    }
    if has_opaque_references_to(document, &removal_handles) {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_data",
            "cannot detach an XREF while opaque data may reference something being removed",
        ));
    }
    if document.entities().any(|entity| {
        !removal_handles.contains(&entity.common().handle)
            && dependent_layers.iter().any(|(name, handle)| {
                entity_references_layer(entity, name, *handle)
                    || matches!(
                        entity,
                        EntityType::Viewport(viewport)
                            if viewport.frozen_layers.contains(handle)
                    )
            })
    }) {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_data",
            "a surviving host entity references an XREF-dependent layer selected for detach",
        ));
    }
    if document.entities().any(|entity| {
        !removal_handles.contains(&entity.common().handle)
            && dependent_line_types
                .iter()
                .any(|line_type| entity_references_linetype(entity, &line_type.name))
    }) {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_data",
            "a surviving host entity references an XREF-dependent linetype selected for detach",
        ));
    }
    if document.layers.iter().any(|layer| {
        !dependent_layers
            .iter()
            .any(|(name, _)| name_eq(name, &layer.name))
            && dependent_line_types
                .iter()
                .any(|line_type| name_eq(&layer.line_type, &line_type.name))
    }) {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_data",
            "a surviving layer's default linetype is XREF-dependent and selected for detach",
        ));
    }
    if document.objects.values().any(|object| {
        matches!(
            object,
            ObjectType::SortEntitiesTable(table)
                if removal_handles.contains(&table.block_owner_handle)
        )
    }) {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_data",
            "an entity sort table is owned by XREF data selected for detach",
        ));
    }
    for instance_handle in &deleted_instance_handles {
        let handle = parse_handle(instance_handle, "invalid_xref_instance_handle")?;
        let _ = remove_instance(document, handle);
    }
    for entity_handle in owned_handles {
        let _ = remove_instance(document, entity_handle);
    }
    for (layer, _) in dependent_layers {
        let _ = document.layers.remove(&layer);
    }
    for line_type in dependent_line_types {
        let _ = document.line_types.remove(&line_type.name);
    }
    let _ = document.block_records.remove(&attachment.name);
    load_states.remove(&attachment.handle);
    Ok(Mutation {
        postcondition: XrefPostcondition::AttachmentAbsent {
            handle: attachment.handle.clone(),
            name: attachment.name.clone(),
        },
        result: DetachXrefResult {
            attachment,
            deleted_instance_handles,
        },
        diagnostics: candidate_diagnostics(format, false, false, false),
    })
}

pub(super) fn insert_instance(
    document: &mut CadDocument,
    format: DrawingFormat,
    bridge: &XrefHandleBridge,
    request: &InsertXrefInstance,
) -> Result<Mutation<InsertXrefInstanceResult>, WriteError> {
    let attachment_handle = resolve_instance_attachment(document, bridge, &request.attachment)?;
    let attachment_name = document
        .block_records
        .iter()
        .find(|record| record.handle == attachment_handle)
        .expect("resolved XREF remains present")
        .name
        .clone();
    let placement = resolve_placement(document, bridge, request.placement.as_ref())?;
    if placement
        .array
        .is_some_and(|array| array.rows == 1 && array.columns == 1)
    {
        return Err(WriteError::unsupported_source(
            "xref_instance_kind_unrepresentable",
            "acadrust cannot preserve a rectangular-array identity for a 1x1 MINSERT",
        ));
    }
    if would_create_recursive_ownership(document, attachment_handle, placement.owner_handle)? {
        return Err(WriteError::invalid_request(
            "recursive_block_reference",
            "inserting the XREF into the selected owner would create recursive ownership",
        ));
    }
    let handle = add_instance(document, attachment_handle, &attachment_name, &placement)?;
    let instance = project_instance(document, handle)?;
    Ok(Mutation {
        postcondition: XrefPostcondition::InstancePresent {
            expected: Box::new(instance.clone()),
        },
        result: InsertXrefInstanceResult { instance },
        diagnostics: candidate_diagnostics(
            format,
            request.unit_assumptions.is_some(),
            false,
            false,
        ),
    })
}

pub(super) fn update_instance(
    document: &mut CadDocument,
    format: DrawingFormat,
    bridge: &XrefHandleBridge,
    request: &UpdateXrefInstance,
) -> Result<Mutation<UpdateXrefInstanceResult>, WriteError> {
    let properties = &request.properties;
    if properties.insertion_point.is_none()
        && properties.scale.is_none()
        && properties.rotation_degrees.is_none()
        && properties.normal.is_none()
        && properties.layer_handle.is_none()
        && properties.layer_name.is_none()
        && properties.visibility.is_none()
        && properties.array.is_none()
    {
        return Err(WriteError::invalid_request(
            "empty_xref_instance_update",
            "XREF instance update contains no properties",
        ));
    }
    let point = properties.insertion_point.map(validate_point).transpose()?;
    let scale = properties.scale.map(validate_scale).transpose()?;
    let normal = properties.normal.map(validate_normal).transpose()?;
    let array = validate_array(properties.array)?;
    if array.is_some_and(|array| array.rows == 1 && array.columns == 1) {
        return Err(WriteError::unsupported_source(
            "xref_instance_kind_change_unsupported",
            "acadrust cannot preserve a rectangular-array identity for a 1x1 MINSERT",
        ));
    }
    if properties
        .rotation_degrees
        .is_some_and(|value| !value.is_finite())
    {
        return Err(WriteError::invalid_request(
            "invalid_xref_rotation",
            "XREF rotation must be finite",
        ));
    }
    let rotation = properties.rotation_degrees.map(normalize_rotation);
    let handle = resolve_instance_guard(document, bridge, &request.instance)?;
    validate_existing_instance_writable(document, handle)?;
    let layer = if properties.layer_handle.is_some() || properties.layer_name.is_some() {
        Some(resolve_layer(
            document,
            bridge,
            properties.layer_handle.as_deref(),
            properties.layer_name.as_deref(),
        )?)
    } else {
        None
    };
    let insert = match document.get_entity_mut(handle) {
        Some(EntityType::Insert(insert)) => insert,
        _ => unreachable!("guard resolved an INSERT"),
    };
    if !insert.is_array() && array.is_some() {
        return Err(WriteError::invalid_request(
            "xref_instance_kind_change_unsupported",
            "a single INSERT cannot be converted to MINSERT by update",
        ));
    }
    if let Some(point) = point {
        insert.insert_point = Vector3::new(point.x, point.y, point.z);
    }
    if let Some(scale) = scale {
        insert.set_x_scale(scale.x);
        insert.set_y_scale(scale.y);
        insert.set_z_scale(scale.z);
    }
    if let Some(rotation) = rotation {
        insert.rotation = rotation.to_radians();
    }
    if let Some(normal) = normal {
        insert.normal = Vector3::new(normal.x, normal.y, normal.z);
    }
    if let Some((_, layer_name)) = layer {
        insert.common.layer = layer_name;
    }
    if let Some(visibility) = properties.visibility {
        insert.common.invisible = visibility == XrefVisibility::Hidden;
    }
    if let Some(array) = array {
        insert.row_count = array.rows as u16;
        insert.column_count = array.columns as u16;
        insert.row_spacing = array.row_spacing;
        insert.column_spacing = array.column_spacing;
    }
    let instance = project_instance(document, handle)?;
    Ok(Mutation {
        postcondition: XrefPostcondition::InstancePresent {
            expected: Box::new(instance.clone()),
        },
        result: UpdateXrefInstanceResult { instance },
        diagnostics: candidate_diagnostics(format, false, false, false),
    })
}

pub(super) fn delete_instance(
    document: &mut CadDocument,
    format: DrawingFormat,
    bridge: &XrefHandleBridge,
    request: &DeleteXrefInstance,
) -> Result<Mutation<DeleteXrefInstanceResult>, WriteError> {
    let handle = resolve_instance_guard(document, bridge, &request.instance)?;
    validate_instance_deletion_writable(document, handle)?;
    if has_opaque_references_to(document, &BTreeSet::from([handle])) {
        return Err(WriteError::unsupported_source(
            "unsupported_xref_data",
            "cannot delete an XREF instance while opaque data may reference it",
        ));
    }
    let instance = project_instance(document, handle)?;
    let removed = remove_instance(document, handle);
    debug_assert!(removed.is_some());
    Ok(Mutation {
        postcondition: XrefPostcondition::InstanceAbsent {
            handle: instance.handle.clone(),
            attachment_handle: instance.attachment_handle.clone(),
            attachment_name: instance.attachment_name.clone(),
        },
        result: DeleteXrefInstanceResult { instance },
        diagnostics: candidate_diagnostics(format, false, false, false),
    })
}

// `session.rs` keeps ReloadXref/UnloadXref/BindXref hard-blocked rather than
// calling `reload`/`unload`/`bind`; see the `#[allow(dead_code)]` note on
// `XrefPostcondition::LoadState` above.
#[allow(dead_code)]
pub(super) fn reload(
    document: &CadDocument,
    format: DrawingFormat,
    load_states: &mut BTreeMap<String, LoadState>,
    bridge: &XrefHandleBridge,
    request: &ReloadXref,
) -> Result<Mutation<ReloadXrefResult>, WriteError> {
    if let Some(reconciliation) = &request.layer_reconciliation {
        validate_reconciliation(reconciliation)?;
    }
    let handle = resolve_guard(document, bridge, &request.attachment)?;
    validate_search_paths(request.search_paths.as_deref())?;
    let canonical = canonical_handle(handle)?;
    load_states.insert(canonical.clone(), LoadState::Loaded);
    let attachment = project_attachment(document, handle, load_states)?;
    Ok(Mutation {
        postcondition: XrefPostcondition::LoadState {
            handle: canonical,
            expected: LoadState::Loaded,
        },
        result: ReloadXrefResult {
            attachment,
            layer_reconciliation: reconciliation_plan(request.layer_reconciliation.as_ref()),
            load_state_materialized: false,
        },
        diagnostics: candidate_diagnostics(
            format,
            request.unit_assumptions.is_some(),
            true,
            request.search_paths.is_some(),
        ),
    })
}

#[allow(dead_code)]
pub(super) fn unload(
    document: &CadDocument,
    format: DrawingFormat,
    load_states: &mut BTreeMap<String, LoadState>,
    bridge: &XrefHandleBridge,
    request: &UnloadXref,
) -> Result<Mutation<UnloadXrefResult>, WriteError> {
    let handle = resolve_guard(document, bridge, &request.attachment)?;
    let canonical = canonical_handle(handle)?;
    load_states.insert(canonical.clone(), LoadState::Unloaded);
    let attachment = project_attachment(document, handle, load_states)?;
    Ok(Mutation {
        postcondition: XrefPostcondition::LoadState {
            handle: canonical,
            expected: LoadState::Unloaded,
        },
        result: UnloadXrefResult {
            attachment,
            load_state_materialized: false,
        },
        diagnostics: candidate_diagnostics(format, false, false, false),
    })
}

#[allow(dead_code)]
pub(super) fn bind(
    document: &mut CadDocument,
    format: DrawingFormat,
    load_states: &mut BTreeMap<String, LoadState>,
    bridge: &XrefHandleBridge,
    request: &BindXref,
) -> Result<Mutation<BindXrefResult>, WriteError> {
    let handle = resolve_destructive_guard(document, bridge, &request.attachment)?;
    validate_search_paths(request.search_paths.as_deref())?;
    let attachment = project_attachment(document, handle, load_states)?;
    let mut diagnostics =
        candidate_diagnostics(format, false, false, request.search_paths.is_some());
    diagnostics.push(match request.dependency_strategy {
        DependencyStrategy::RejectNested => {
            "nested_xref_graph_not_inspected_by_acadrust".to_string()
        }
        DependencyStrategy::BindNested => {
            "nested_xref_binding_not_materialized_by_acadrust".to_string()
        }
    });
    diagnostics.push(match request.symbol_strategy {
        SymbolStrategy::Prefix => "bound_symbol_prefix_mapping_not_materialized".to_string(),
        SymbolStrategy::Merge => "bound_symbol_merge_mapping_not_materialized".to_string(),
    });
    diagnostics.push("bound_source_content_not_embedded_in_host_model".to_string());
    diagnostics.push("xref_bind_not_materialized_by_acadrust".to_string());
    let block = XrefBoundBlock {
        handle: attachment.handle.clone(),
        name: attachment.name.clone(),
    };
    Ok(Mutation {
        postcondition: XrefPostcondition::Unmaterialized {
            reason_code: "xref_bind_not_materialized_by_acadrust".to_string(),
        },
        result: BindXrefResult {
            materialized: false,
            symbol_strategy: request.symbol_strategy,
            dependency_strategy: request.dependency_strategy,
            attachment,
            block,
            instance_handle_mappings: Vec::new(),
            symbol_mappings: Vec::new(),
            bound_dependencies: Vec::new(),
            excluded_overlay_dependencies: Vec::new(),
        },
        diagnostics,
    })
}

fn same_float(left: f64, right: f64) -> bool {
    (left - right).abs() <= 1e-8
}

fn same_instance(left: &XrefInstanceRecord, right: &XrefInstanceRecord) -> bool {
    left.handle == right.handle
        && left.attachment_handle == right.attachment_handle
        && name_eq(&left.attachment_name, &right.attachment_name)
        && left.owner_handle == right.owner_handle
        && left.owner_type == right.owner_type
        && name_eq(&left.owner_name, &right.owner_name)
        && left.layer_handle == right.layer_handle
        && name_eq(&left.layer_name, &right.layer_name)
        && same_float(left.insertion_point.x, right.insertion_point.x)
        && same_float(left.insertion_point.y, right.insertion_point.y)
        && same_float(left.insertion_point.z, right.insertion_point.z)
        && same_float(left.scale.x, right.scale.x)
        && same_float(left.scale.y, right.scale.y)
        && same_float(left.scale.z, right.scale.z)
        && same_float(left.rotation_degrees, right.rotation_degrees)
        && same_float(left.normal.x, right.normal.x)
        && same_float(left.normal.y, right.normal.y)
        && same_float(left.normal.z, right.normal.z)
        && left.visibility == right.visibility
        && left.placement_kind == right.placement_kind
        && left.array == right.array
}

pub(super) fn verify(
    document: &CadDocument,
    postcondition: &XrefPostcondition,
) -> Result<(), String> {
    let empty_load_states = BTreeMap::new();
    match postcondition {
        XrefPostcondition::AttachmentPresent {
            handle,
            name,
            saved_path,
            reference_type: expected_type,
            instance_handles,
        } => {
            let handle = parse_handle(handle, "invalid_xref_handle")
                .map_err(|error| error.code().to_string())?;
            let record = project_attachment(document, handle, &empty_load_states)
                .map_err(|error| error.code().to_string())?;
            let raw_record = document
                .block_records
                .iter()
                .find(|candidate| candidate.handle == handle)
                .ok_or_else(|| "xref_attachment_postcondition_contradicted".to_string())?;
            let actual_instances = attachment_instance_handles(document, &record.name)
                .map_err(|error| error.code().to_string())?;
            if !name_eq(&record.name, name)
                || record.saved_path != *saved_path
                || record.reference_type != *expected_type
                || actual_instances != *instance_handles
                || !reverse_insert_index_matches(document, raw_record)
            {
                return Err("xref_attachment_postcondition_contradicted".to_string());
            }
            Ok(())
        }
        XrefPostcondition::AttachmentAbsent { handle, name } => {
            let handle = parse_handle(handle, "invalid_xref_handle")
                .map_err(|error| error.code().to_string())?;
            if document
                .block_records
                .iter()
                .any(|record| record.handle == handle && is_direct_xref(record))
                || document.entities().any(
                    |entity| matches!(entity, EntityType::Insert(insert) if name_eq(&insert.block_name, name)),
                )
            {
                Err("xref_attachment_still_present".to_string())
            } else {
                Ok(())
            }
        }
        XrefPostcondition::InstancePresent { expected } => {
            let handle = parse_handle(&expected.handle, "invalid_xref_instance_handle")
                .map_err(|error| error.code().to_string())?;
            let observed =
                project_instance(document, handle).map_err(|error| error.code().to_string())?;
            let attachment_handle = parse_handle(
                &expected.attachment_handle,
                "invalid_expected_attachment_handle",
            )
            .map_err(|error| error.code().to_string())?;
            let reverse_index_valid = document
                .block_records
                .iter()
                .find(|record| record.handle == attachment_handle && is_direct_xref(record))
                .is_some_and(|record| reverse_insert_index_matches(document, record));
            if same_instance(&observed, expected) && reverse_index_valid {
                Ok(())
            } else {
                Err("xref_instance_postcondition_contradicted".to_string())
            }
        }
        XrefPostcondition::InstanceAbsent {
            handle,
            attachment_handle,
            attachment_name,
        } => {
            let handle = parse_handle(handle, "invalid_xref_instance_handle")
                .map_err(|error| error.code().to_string())?;
            let attachment_handle =
                parse_handle(attachment_handle, "invalid_expected_attachment_handle")
                    .map_err(|error| error.code().to_string())?;
            let reverse_index_valid = document
                .block_records
                .iter()
                .find(|record| {
                    record.handle == attachment_handle
                        && name_eq(&record.name, attachment_name)
                        && is_direct_xref(record)
                })
                .is_some_and(|record| reverse_insert_index_matches(document, record));
            match document.get_entity(handle) {
                Some(EntityType::Insert(insert))
                    if document.block_records.iter().any(|record| {
                        is_direct_xref(record) && name_eq(&record.name, &insert.block_name)
                    }) =>
                {
                    Err("xref_instance_still_present".to_string())
                }
                _ if reverse_index_valid => Ok(()),
                _ => Err("xref_reverse_insert_index_contradicted".to_string()),
            }
        }
        XrefPostcondition::LoadState { handle, expected } => Err(format!(
            "xref_load_state_unobservable: handle={handle} expected={expected:?}"
        )),
        XrefPostcondition::Unmaterialized { reason_code } => Err(reason_code.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::UpdateXrefProperties;
    use acadrust::entities::{Line, Polyline3D, Vertex3DPolyline, Viewport};
    use acadrust::objects::{Group, SortEntitiesTable, XRecord};
    use acadrust::tables::Layer;
    use acadrust::xdata::{ExtendedDataRecord, XDataValue};

    struct DetachFixture {
        document: CadDocument,
        attachment_handle: Handle,
        dependent_layer_handle: Handle,
        block_handle: Handle,
        block_end_handle: Handle,
        owned_entity_handle: Handle,
    }

    fn detachable_xref_fixture() -> DetachFixture {
        let mut document = CadDocument::new();
        let mut attachment = BlockRecord::new("SITE");
        attachment.handle = document.allocate_handle();
        attachment.block_entity_handle = document.allocate_handle();
        attachment.block_end_handle = document.allocate_handle();
        attachment.flags.is_xref = true;
        attachment.xref_path = "site.dwg".to_string();
        let attachment_handle = attachment.handle;
        let block_handle = attachment.block_entity_handle;
        let block_end_handle = attachment.block_end_handle;
        document.block_records.add(attachment).unwrap();

        let mut block = Block::new("SITE", Vector3::ZERO).with_xref_path("site.dwg");
        block.common.handle = block_handle;
        block.common.owner_handle = attachment_handle;
        document.add_entity(EntityType::Block(block)).unwrap();

        let mut block_end = BlockEnd::new();
        block_end.common.handle = block_end_handle;
        block_end.common.owner_handle = attachment_handle;
        document
            .add_entity(EntityType::BlockEnd(block_end))
            .unwrap();

        let mut owned_line = Line::from_coords(0.0, 0.0, 0.0, 1.0, 1.0, 0.0);
        owned_line.common.owner_handle = attachment_handle;
        let owned_entity_handle = document.add_entity(EntityType::Line(owned_line)).unwrap();

        let mut dependent_layer = Layer::new("SITE|GRID");
        dependent_layer.set_handle(document.allocate_handle());
        dependent_layer.flags.xref_dependent = true;
        dependent_layer.xref_block_record_handle = attachment_handle;
        let dependent_layer_handle = dependent_layer.handle();
        document.layers.add(dependent_layer).unwrap();

        DetachFixture {
            document,
            attachment_handle,
            dependent_layer_handle,
            block_handle,
            block_end_handle,
            owned_entity_handle,
        }
    }

    fn detach_fixture(fixture: &mut DetachFixture) -> Result<DetachXrefResult, WriteError> {
        let bridge = XrefHandleBridge::identity(&fixture.document);
        detach(
            &mut fixture.document,
            DrawingFormat::Dwg,
            &mut BTreeMap::new(),
            &bridge,
            &DetachXref {
                attachment: XrefDestructiveAttachmentGuard {
                    handle: Some(format!("{:X}", fixture.attachment_handle.value())),
                    ..Default::default()
                },
            },
        )
        .map(|mutation| mutation.result)
    }

    fn assert_detach_was_atomic(fixture: &DetachFixture) {
        assert!(fixture
            .document
            .block_records
            .iter()
            .any(|record| record.handle == fixture.attachment_handle));
        assert!(fixture.document.layers.get("SITE|GRID").is_some());
        assert!(fixture.document.get_entity(fixture.block_handle).is_some());
        assert!(fixture
            .document
            .get_entity(fixture.block_end_handle)
            .is_some());
        assert!(fixture
            .document
            .get_entity(fixture.owned_entity_handle)
            .is_some());
    }

    #[test]
    fn removing_an_entity_cleans_group_and_sort_table_memberships() {
        let mut document = CadDocument::new();
        let entity_handle = document
            .add_entity(EntityType::Line(Line::from_coords(
                0.0, 0.0, 0.0, 1.0, 1.0, 0.0,
            )))
            .unwrap();

        let mut group = Group::new("TEST");
        group.handle = document.allocate_handle();
        group.add_entity(entity_handle);
        let group_handle = group.handle;
        document
            .objects
            .insert(group_handle, ObjectType::Group(group));

        let mut sort_table = SortEntitiesTable::new();
        sort_table.handle = document.allocate_handle();
        sort_table.add_entry(entity_handle, Handle::new(0xFEED));
        let sort_table_handle = sort_table.handle;
        document
            .objects
            .insert(sort_table_handle, ObjectType::SortEntitiesTable(sort_table));

        assert!(remove_instance(&mut document, entity_handle).is_some());
        let ObjectType::Group(group) = document.objects.get(&group_handle).unwrap() else {
            unreachable!();
        };
        assert!(group.entities.is_empty());
        let ObjectType::SortEntitiesTable(sort_table) =
            document.objects.get(&sort_table_handle).unwrap()
        else {
            unreachable!();
        };
        assert_eq!(sort_table.entries().count(), 0);
    }

    #[test]
    fn detach_rejects_a_surviving_viewport_with_a_dependent_frozen_layer() {
        let mut fixture = detachable_xref_fixture();
        let mut viewport = Viewport::new();
        viewport.frozen_layers.push(fixture.dependent_layer_handle);
        let viewport_handle = fixture
            .document
            .add_entity(EntityType::Viewport(viewport))
            .unwrap();

        let error = detach_fixture(&mut fixture).unwrap_err();

        assert_eq!(error.code(), "unsupported_xref_data");
        assert_detach_was_atomic(&fixture);
        assert!(fixture.document.get_entity(viewport_handle).is_some());
    }

    #[test]
    fn detach_rejects_an_xref_dependent_current_layer() {
        for stale_header_handle in [false, true] {
            let mut fixture = detachable_xref_fixture();
            fixture.document.header.current_layer_handle = if stale_header_handle {
                Handle::new(0xDEAD)
            } else {
                fixture.dependent_layer_handle
            };
            fixture.document.header.current_layer_name = "SITE|GRID".to_string();

            let error = detach_fixture(&mut fixture).unwrap_err();

            assert_eq!(error.code(), "unsupported_xref_data");
            assert_detach_was_atomic(&fixture);
            assert_eq!(
                current_layer_handle(&fixture.document),
                Some(fixture.dependent_layer_handle)
            );
        }
    }

    #[test]
    fn detach_rejects_metadata_on_every_owned_entity_selected_for_deletion() {
        for entity_kind in ["BLOCK", "ENDBLK", "entity"] {
            for metadata_kind in ["extension dictionary", "reactor"] {
                let mut fixture = detachable_xref_fixture();
                let target_handle = match entity_kind {
                    "BLOCK" => fixture.block_handle,
                    "ENDBLK" => fixture.block_end_handle,
                    "entity" => fixture.owned_entity_handle,
                    _ => unreachable!(),
                };
                let metadata_handle = fixture.document.allocate_handle();
                let common = fixture
                    .document
                    .get_entity_mut(target_handle)
                    .expect("fixture owns the selected entity")
                    .common_mut();
                match metadata_kind {
                    "extension dictionary" => {
                        common.xdictionary_handle = Some(metadata_handle);
                    }
                    "reactor" => common.reactors.push(metadata_handle),
                    _ => unreachable!(),
                }

                let error = detach_fixture(&mut fixture).unwrap_err();

                assert_eq!(
                    error.code(),
                    "unsupported_xref_data",
                    "{metadata_kind} on {entity_kind}"
                );
                assert_detach_was_atomic(&fixture);
                assert!(fixture.document.get_entity(target_handle).is_some());
            }
        }
    }

    #[test]
    fn detach_rejects_a_foreign_owned_entity_in_the_definition_index() {
        let mut fixture = detachable_xref_fixture();
        let model_space_handle = fixture.document.header.model_space_block_handle;
        fixture
            .document
            .get_entity_mut(fixture.owned_entity_handle)
            .expect("fixture owns the selected entity")
            .common_mut()
            .owner_handle = model_space_handle;

        let error = detach_fixture(&mut fixture).unwrap_err();

        assert_eq!(error.code(), "unsupported_xref_data");
        assert_detach_was_atomic(&fixture);
    }

    #[test]
    fn detach_rejects_an_owned_entity_omitted_from_the_definition_index() {
        let mut fixture = detachable_xref_fixture();
        fixture
            .document
            .block_records
            .iter_mut()
            .find(|record| record.handle == fixture.attachment_handle)
            .expect("fixture attachment remains present")
            .entity_handles
            .retain(|handle| *handle != fixture.owned_entity_handle);

        let error = detach_fixture(&mut fixture).unwrap_err();

        assert_eq!(error.code(), "unsupported_xref_data");
        assert_detach_was_atomic(&fixture);
    }

    #[test]
    fn detach_rejects_opaque_dwg_xrecord_handle_data() {
        let mut fixture = detachable_xref_fixture();
        let mut xrecord = XRecord::new();
        xrecord.handle = fixture.document.allocate_handle();
        xrecord.raw_data = vec![0xAA];
        fixture
            .document
            .objects
            .insert(xrecord.handle, ObjectType::XRecord(xrecord));

        let error = detach_fixture(&mut fixture).unwrap_err();

        assert_eq!(error.code(), "unsupported_xref_data");
        assert_detach_was_atomic(&fixture);
    }

    /// Builds one DWG raw-EED per-application blob containing a single
    /// group-1005 "entity handle" sub-record, per the ODA .dwg spec §28
    /// byte layout this crate's parser decodes.
    fn eed_handle_blob(app_handle: u64, referenced: Handle) -> (u64, Vec<u8>) {
        let mut data = vec![5u8];
        data.extend_from_slice(&referenced.value().to_be_bytes());
        (app_handle, data)
    }

    #[test]
    fn detach_succeeds_with_eed_referencing_a_handle_outside_the_removal_set() {
        let mut fixture = detachable_xref_fixture();
        let unrelated = fixture.document.allocate_handle();
        if let Some(EntityType::Line(line)) =
            fixture.document.get_entity_mut(fixture.owned_entity_handle)
        {
            line.common.extended_data.raw_dwg_eed = vec![eed_handle_blob(0x40, unrelated)];
        }

        detach_fixture(&mut fixture).unwrap();
    }

    #[test]
    fn detach_rejects_eed_referencing_a_handle_in_the_removal_set() {
        let mut fixture = detachable_xref_fixture();
        // The attachment's own block-record handle is always in the
        // removal set; reference it from an owned entity's EED.
        let removed_handle = fixture.attachment_handle;
        if let Some(EntityType::Line(line)) =
            fixture.document.get_entity_mut(fixture.owned_entity_handle)
        {
            line.common.extended_data.raw_dwg_eed = vec![eed_handle_blob(0x40, removed_handle)];
        }
        let original = fixture.document.clone();

        let error = detach_fixture(&mut fixture).unwrap_err();

        assert_eq!(error.code(), "unsupported_xref_data");
        assert_eq!(fixture.document, original);
    }

    #[test]
    fn detach_rejects_eed_with_an_unrecognized_sub_record_tag() {
        let mut fixture = detachable_xref_fixture();
        if let Some(EntityType::Line(line)) =
            fixture.document.get_entity_mut(fixture.owned_entity_handle)
        {
            // Tag 200 is not in the documented sub-record table -- the
            // parser must fail closed (treat as opaque) rather than guess.
            line.common.extended_data.raw_dwg_eed = vec![(0x40, vec![200u8, 0x00])];
        }
        let original = fixture.document.clone();

        let error = detach_fixture(&mut fixture).unwrap_err();

        assert_eq!(error.code(), "unsupported_xref_data");
        assert_eq!(fixture.document, original);
    }

    #[test]
    fn detach_succeeds_with_well_formed_eed_of_every_skippable_sub_record_type() {
        let mut fixture = detachable_xref_fixture();
        let unrelated = fixture.document.allocate_handle();
        let mut data = Vec::new();
        data.push(0u8); // string (R13-R2004: 1-byte length + 2-byte codepage + bytes)
        data.push(3u8); // length 3
        data.extend_from_slice(&[0u8, 0u8]); // codepage
        data.extend_from_slice(b"abc");
        data.push(2u8); // control string
        data.push(1u8); // '}'
        data.push(4u8); // binary chunk
        data.push(2u8); // length 2
        data.extend_from_slice(&[0xDE, 0xAD]);
        data.push(10u8); // point (24 bytes)
        data.extend_from_slice(&[0u8; 24]);
        data.push(40u8); // real (8 bytes)
        data.extend_from_slice(&[0u8; 8]);
        data.push(70u8); // short (2 bytes)
        data.extend_from_slice(&[0u8; 2]);
        data.push(71u8); // long (4 bytes)
        data.extend_from_slice(&[0u8; 4]);
        data.push(3u8); // layer handle, references something unrelated
        data.extend_from_slice(&unrelated.value().to_be_bytes());
        if let Some(EntityType::Line(line)) =
            fixture.document.get_entity_mut(fixture.owned_entity_handle)
        {
            line.common.extended_data.raw_dwg_eed = vec![(0x40, data)];
        }

        detach_fixture(&mut fixture).unwrap();
    }

    #[test]
    fn delete_xref_instance_rejects_eed_referencing_the_instance_handle() {
        let mut document = CadDocument::new();
        let mut attachment = BlockRecord::new("SITE");
        attachment.handle = document.allocate_handle();
        attachment.block_entity_handle = document.allocate_handle();
        attachment.block_end_handle = document.allocate_handle();
        attachment.flags.is_xref = true;
        attachment.xref_path = "site.dwg".to_string();
        let attachment_handle = attachment.handle;
        document.block_records.add(attachment).unwrap();

        let mut insert = Insert::new("SITE", Vector3::ZERO);
        insert.common.owner_handle = document.header.model_space_block_handle;
        let instance_handle = document.add_entity(EntityType::Insert(insert)).unwrap();

        let mut other = Line::from_coords(0.0, 0.0, 0.0, 1.0, 1.0, 0.0);
        other.common.extended_data.raw_dwg_eed = vec![eed_handle_blob(0x40, instance_handle)];
        document.add_entity(EntityType::Line(other)).unwrap();

        let bridge = XrefHandleBridge::identity(&document);
        let error = delete_instance(
            &mut document,
            DrawingFormat::Dwg,
            &bridge,
            &DeleteXrefInstance {
                instance: XrefInstanceGuard {
                    handle: format!("{:X}", instance_handle.value()),
                    expected_attachment_handle: Some(format!("{:X}", attachment_handle.value())),
                    expected_owner_handle: None,
                },
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "unsupported_xref_data");
    }

    #[test]
    fn contradictory_dependent_layer_ownership_fails_rename_and_detach_atomically() {
        for contradiction in [
            "handle-associated noncanonical name",
            "missing dependency flag",
            "missing DWG XREF handle",
            "different DWG XREF handle",
        ] {
            let mut fixture = detachable_xref_fixture();
            let mut layer = fixture.document.layers.remove("SITE|GRID").unwrap();
            match contradiction {
                "handle-associated noncanonical name" => {
                    layer.name = "LEGACY_GRID".to_string();
                }
                "missing dependency flag" => {
                    layer.flags.xref_dependent = false;
                }
                "missing DWG XREF handle" => {
                    layer.xref_block_record_handle = Handle::NULL;
                }
                "different DWG XREF handle" => {
                    layer.xref_block_record_handle = fixture.document.allocate_handle();
                }
                _ => unreachable!(),
            }
            fixture.document.layers.add(layer).unwrap();
            let original = fixture.document.clone();
            let bridge = XrefHandleBridge::identity(&fixture.document);

            let rename_error = update(
                &mut fixture.document,
                DrawingFormat::Dwg,
                &mut BTreeMap::new(),
                &bridge,
                &UpdateXref {
                    attachment: XrefAttachmentGuard {
                        handle: Some(format!("{:X}", fixture.attachment_handle.value())),
                        ..Default::default()
                    },
                    properties: UpdateXrefProperties {
                        name: Some("CAMPUS".to_string()),
                        ..Default::default()
                    },
                    search_paths: None,
                    layer_reconciliation: None,
                    unit_assumptions: None,
                },
            )
            .unwrap_err();

            assert_eq!(
                rename_error.code(),
                "unsupported_xref_data",
                "{contradiction}"
            );
            assert_eq!(fixture.document, original, "{contradiction}");

            let detach_error = detach_fixture(&mut fixture).unwrap_err();
            assert_eq!(
                detach_error.code(),
                "unsupported_xref_data",
                "{contradiction}"
            );
            assert_eq!(fixture.document, original, "{contradiction}");
        }
    }

    #[test]
    fn dependent_layer_rename_collision_is_preflighted_atomically() {
        let mut fixture = detachable_xref_fixture();
        let mut collision = Layer::new("CAMPUS|GRID");
        collision.set_handle(fixture.document.allocate_handle());
        fixture.document.layers.add(collision).unwrap();
        let original = fixture.document.clone();
        let bridge = XrefHandleBridge::identity(&fixture.document);

        let error = update(
            &mut fixture.document,
            DrawingFormat::Dwg,
            &mut BTreeMap::new(),
            &bridge,
            &UpdateXref {
                attachment: XrefAttachmentGuard {
                    handle: Some(format!("{:X}", fixture.attachment_handle.value())),
                    ..Default::default()
                },
                properties: UpdateXrefProperties {
                    name: Some("CAMPUS".to_string()),
                    ..Default::default()
                },
                search_paths: None,
                layer_reconciliation: None,
                unit_assumptions: None,
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "xref_dependent_layer_collision");
        assert_eq!(fixture.document, original);
    }

    #[test]
    fn xref_rename_rewrites_compound_and_xdata_dependent_layer_references() {
        let mut document = CadDocument::new();
        let mut attachment = BlockRecord::new("SITE");
        attachment.handle = document.allocate_handle();
        attachment.block_entity_handle = document.allocate_handle();
        attachment.block_end_handle = document.allocate_handle();
        attachment.flags.is_xref = true;
        attachment.xref_path = "site.dwg".to_string();
        let attachment_handle = attachment.handle;
        document.block_records.add(attachment).unwrap();

        let mut layer = Layer::new("SITE|GRID");
        layer.set_handle(document.allocate_handle());
        layer.flags.xref_dependent = true;
        layer.xref_block_record_handle = attachment_handle;
        document.layers.add(layer).unwrap();

        let mut polyline = Polyline3D::new();
        let mut vertex = Vertex3DPolyline::from_xyz(1.0, 2.0, 3.0);
        vertex.layer = "SITE|GRID".to_string();
        polyline.vertices.push(vertex);
        let mut record = ExtendedDataRecord::new("TEST");
        record.add_value(XDataValue::LayerName("SITE|GRID".to_string()));
        polyline.common.extended_data.add_record(record);
        let polyline_handle = document
            .add_entity(EntityType::Polyline3D(polyline))
            .unwrap();
        let bridge = XrefHandleBridge::identity(&document);

        update(
            &mut document,
            DrawingFormat::Dxf,
            &mut BTreeMap::new(),
            &bridge,
            &UpdateXref {
                attachment: XrefAttachmentGuard {
                    handle: Some(format!("{:X}", attachment_handle.value())),
                    ..Default::default()
                },
                properties: UpdateXrefProperties {
                    name: Some("CAMPUS".to_string()),
                    ..Default::default()
                },
                search_paths: None,
                layer_reconciliation: None,
                unit_assumptions: None,
            },
        )
        .unwrap();

        assert!(document.layers.get("CAMPUS|GRID").is_some());
        let EntityType::Polyline3D(polyline) = document
            .get_entity(polyline_handle)
            .expect("polyline survives")
        else {
            unreachable!();
        };
        assert_eq!(polyline.vertices[0].layer, "CAMPUS|GRID");
        assert!(matches!(
            &polyline.common.extended_data.records()[0].values[0],
            XDataValue::LayerName(name) if name == "CAMPUS|GRID"
        ));
    }

    #[test]
    fn xref_rename_rewrites_dependent_line_type_references() {
        use acadrust::tables::LineType;

        let mut document = CadDocument::new();
        let mut attachment = BlockRecord::new("SITE");
        attachment.handle = document.allocate_handle();
        attachment.block_entity_handle = document.allocate_handle();
        attachment.block_end_handle = document.allocate_handle();
        attachment.flags.is_xref = true;
        attachment.xref_path = "site.dwg".to_string();
        let attachment_handle = attachment.handle;
        document.block_records.add(attachment).unwrap();

        let mut line_type = LineType::new("SITE|HIDDEN");
        line_type.handle = document.allocate_handle();
        line_type.xref_dependent = true;
        document.line_types.add(line_type).unwrap();

        document.layers.get_mut("0").unwrap().line_type = "SITE|HIDDEN".to_string();

        let mut line = Line::from_coords(0.0, 0.0, 0.0, 1.0, 1.0, 0.0);
        line.common.linetype = "SITE|HIDDEN".to_string();
        let line_handle = document.add_entity(EntityType::Line(line)).unwrap();
        let bridge = XrefHandleBridge::identity(&document);

        update(
            &mut document,
            DrawingFormat::Dxf,
            &mut BTreeMap::new(),
            &bridge,
            &UpdateXref {
                attachment: XrefAttachmentGuard {
                    handle: Some(format!("{:X}", attachment_handle.value())),
                    ..Default::default()
                },
                properties: UpdateXrefProperties {
                    name: Some("CAMPUS".to_string()),
                    ..Default::default()
                },
                search_paths: None,
                layer_reconciliation: None,
                unit_assumptions: None,
            },
        )
        .unwrap();

        assert!(document.line_types.get("CAMPUS|HIDDEN").is_some());
        assert!(document.line_types.get("SITE|HIDDEN").is_none());
        let EntityType::Line(line) = document.get_entity(line_handle).expect("line survives")
        else {
            unreachable!();
        };
        assert_eq!(line.common.linetype, "CAMPUS|HIDDEN");
        assert_eq!(document.layers.get("0").unwrap().line_type, "CAMPUS|HIDDEN");
    }

    #[test]
    fn dependent_line_type_rename_collision_is_preflighted_atomically() {
        use acadrust::tables::LineType;

        let mut fixture = detachable_xref_fixture();
        let mut dependent = LineType::new("SITE|HIDDEN");
        dependent.handle = fixture.document.allocate_handle();
        dependent.xref_dependent = true;
        fixture.document.line_types.add(dependent).unwrap();
        let mut collision = LineType::new("CAMPUS|HIDDEN");
        collision.handle = fixture.document.allocate_handle();
        fixture.document.line_types.add(collision).unwrap();
        let original = fixture.document.clone();
        let bridge = XrefHandleBridge::identity(&fixture.document);

        let error = update(
            &mut fixture.document,
            DrawingFormat::Dwg,
            &mut BTreeMap::new(),
            &bridge,
            &UpdateXref {
                attachment: XrefAttachmentGuard {
                    handle: Some(format!("{:X}", fixture.attachment_handle.value())),
                    ..Default::default()
                },
                properties: UpdateXrefProperties {
                    name: Some("CAMPUS".to_string()),
                    ..Default::default()
                },
                search_paths: None,
                layer_reconciliation: None,
                unit_assumptions: None,
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "xref_dependent_line_type_collision");
        assert_eq!(fixture.document, original);
    }

    #[test]
    fn detach_removes_owned_dependent_line_type() {
        use acadrust::tables::LineType;

        let mut fixture = detachable_xref_fixture();
        let mut dependent = LineType::new("SITE|HIDDEN");
        dependent.handle = fixture.document.allocate_handle();
        dependent.xref_dependent = true;
        fixture.document.line_types.add(dependent).unwrap();
        if let Some(EntityType::Line(line)) =
            fixture.document.get_entity_mut(fixture.owned_entity_handle)
        {
            line.common.linetype = "SITE|HIDDEN".to_string();
        }

        detach_fixture(&mut fixture).unwrap();

        assert!(fixture.document.line_types.get("SITE|HIDDEN").is_none());
    }

    #[test]
    fn detach_rejects_a_surviving_entity_with_a_dependent_line_type() {
        use acadrust::tables::LineType;

        let mut fixture = detachable_xref_fixture();
        let mut dependent = LineType::new("SITE|HIDDEN");
        dependent.handle = fixture.document.allocate_handle();
        dependent.xref_dependent = true;
        fixture.document.line_types.add(dependent).unwrap();
        let mut surviving = Line::from_coords(0.0, 0.0, 0.0, 1.0, 1.0, 0.0);
        surviving.common.linetype = "SITE|HIDDEN".to_string();
        fixture
            .document
            .add_entity(EntityType::Line(surviving))
            .unwrap();
        let original = fixture.document.clone();

        let error = detach_fixture(&mut fixture).unwrap_err();

        assert_eq!(error.code(), "unsupported_xref_data");
        assert_eq!(fixture.document, original);
    }
}
