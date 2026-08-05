use std::collections::BTreeSet;

use acadrust::entities::EntityType;
use acadrust::objects::ObjectType;
use acadrust::tables::{BlockRecord, TableEntry};
use acadrust::types::Handle;
use acadrust::CadDocument;
use autocad_reader::contract::xrefs::{
    xref_name_eq, Fact, ReferenceType, XrefAttachmentRecord, XrefInstanceListOptions,
    XrefInstanceRecord, XrefMembershipEvidence, XrefOwnerType, XrefPlacementKind,
    XrefRectangularArray, XrefSnapshotEvidence,
};

use super::{DrawingSnapshot, WriteError};

const BINARY_DXF_SENTINEL: &[u8] = b"AutoCAD Binary DXF\r\n\x1a\0";

/// A same-snapshot proof that persisted handles exposed by `autocad-reader`
/// identify the same objects in acadrust's mutable projection.
///
/// ASCII DXF XREF membership is derived from BLOCK group 70 by the independent
/// reader. acadrust 0.4.1 retains the XREF path but drops those flags while
/// decoding, so this bridge restores only the independently proven membership
/// flags. Source sessions also repair acadrust's missing reverse INSERT index
/// from independently proven instances so mutations operate on a coherent
/// working model. Candidate verification never applies that repair. Handles
/// are never silently aliased: semantic identity must be unique and every
/// reader-visible handle must equal the backend handle.
#[derive(Debug, Clone)]
pub(super) struct XrefHandleBridge {
    attachment_handles: BTreeSet<Handle>,
    instance_handles: BTreeSet<Handle>,
    owner_handles: BTreeSet<Handle>,
    layer_handles: BTreeSet<Handle>,
}

impl XrefHandleBridge {
    pub(super) fn from_source(
        snapshot: &DrawingSnapshot,
        document: &mut CadDocument,
    ) -> Result<Self, WriteError> {
        Self::build(snapshot, document, true)
    }

    pub(super) fn verify_candidate(
        snapshot: &DrawingSnapshot,
        document: &mut CadDocument,
    ) -> Result<Self, WriteError> {
        Self::build(snapshot, document, false)
    }

    fn build(
        snapshot: &DrawingSnapshot,
        document: &mut CadDocument,
        repair_source_reverse_index: bool,
    ) -> Result<Self, WriteError> {
        // Binary DXF is not admitted by any live-route-shaped capability. The
        // session still needs a harmless bridge before a route is selected so
        // exact admission can reject it without depending on incomplete
        // binary owner/layer evidence.
        if snapshot.bytes().starts_with(BINARY_DXF_SENTINEL) {
            return Ok(Self::identity(document));
        }
        let reader =
            autocad_reader::Reader::open_snapshot(snapshot.reader_snapshot()).map_err(|error| {
                WriteError::unsupported_source(
                    "source_xref_bridge_projection_failed",
                    "independent reader could not establish the source XREF identity bridge",
                )
                .with_internal_detail(error.message().to_string())
            })?;
        let session = reader.xref_session().map_err(|error| {
            bridge_error(
                "source_xref_bridge_projection_failed",
                "independent reader could not project source XREF identities",
                error.to_string(),
            )
        })?;
        let attachments = session.list_attachments().map_err(|error| {
            bridge_error(
                "source_xref_bridge_projection_failed",
                "independent reader could not enumerate source XREF attachments",
                error.to_string(),
            )
        })?;

        let attachment_handles = overlay_attachments(document, &attachments, session.evidence())?;
        let owner_handles = prove_owner_handles(document, session.evidence())?;
        let layer_handles = prove_layer_handles(document, session.evidence())?;
        let instances = session
            .list_instances(&XrefInstanceListOptions::default())
            .map_err(|error| {
                bridge_error(
                    "source_xref_bridge_projection_failed",
                    "independent reader could not enumerate source XREF instances",
                    error.to_string(),
                )
            })?;
        let instance_handles = prove_instance_handles(
            document,
            &instances,
            &attachment_handles,
            &owner_handles,
            &layer_handles,
        )?;
        if repair_source_reverse_index {
            restore_reverse_instance_index(document, &attachments)?;
        } else {
            verify_candidate_reverse_instance_index(document, &instances)?;
        }

        Ok(Self {
            attachment_handles,
            instance_handles,
            owner_handles,
            layer_handles,
        })
    }

    pub(super) fn identity(document: &CadDocument) -> Self {
        let attachment_handles = document
            .block_records
            .iter()
            .filter(|record| is_direct_xref(record))
            .map(|record| record.handle)
            .collect();
        let instance_handles = document
            .entities()
            .filter_map(|entity| match entity {
                EntityType::Insert(insert)
                    if document.block_records.iter().any(|record| {
                        is_direct_xref(record) && xref_name_eq(&record.name, &insert.block_name)
                    }) =>
                {
                    Some(insert.common.handle)
                }
                _ => None,
            })
            .collect();
        let owner_handles = document
            .block_records
            .iter()
            .map(|record| record.handle)
            .collect();
        let layer_handles = document.layers.iter().map(TableEntry::handle).collect();
        Self {
            attachment_handles,
            instance_handles,
            owner_handles,
            layer_handles,
        }
    }

    pub(super) fn proves_attachment(&self, handle: Handle) -> bool {
        self.attachment_handles.contains(&handle)
    }

    pub(super) fn attachment_selector(&self, handle: Handle) -> Result<Handle, WriteError> {
        if self.attachment_handles.contains(&handle) {
            Ok(handle)
        } else {
            Err(WriteError::target_not_found(
                "xref_not_found",
                format!(
                    "direct XREF attachment handle `{:X}` was not found",
                    handle.value()
                ),
            ))
        }
    }

    pub(super) fn instance_selector(&self, handle: Handle) -> Result<Handle, WriteError> {
        if self.instance_handles.contains(&handle) {
            Ok(handle)
        } else {
            Err(WriteError::target_not_found(
                "xref_instance_not_found",
                "selected XREF instance was not found",
            ))
        }
    }

    pub(super) fn owner_selector(&self, handle: Handle) -> Result<Handle, WriteError> {
        if self.owner_handles.contains(&handle) {
            Ok(handle)
        } else {
            Err(WriteError::target_not_found(
                "xref_owner_not_found",
                "selected XREF owner handle was not found in the source snapshot",
            ))
        }
    }

    pub(super) fn layer_selector(&self, handle: Handle) -> Result<Handle, WriteError> {
        if self.layer_handles.contains(&handle) {
            Ok(handle)
        } else {
            Err(WriteError::target_not_found(
                "layer_not_found",
                "selected XREF destination layer handle was not found in the source snapshot",
            ))
        }
    }
}

fn bridge_error(
    code: &'static str,
    message: &'static str,
    detail: impl Into<String>,
) -> WriteError {
    WriteError::unsupported_source(code, message).with_internal_detail(detail)
}

fn persisted_handle(input: &str, field: &str) -> Result<Handle, WriteError> {
    let value = u64::from_str_radix(input, 16).map_err(|_| {
        bridge_error(
            "source_xref_bridge_incomplete",
            "independent XREF projection contains a non-canonical persisted handle",
            format!("{field} `{input}` is not hexadecimal"),
        )
    })?;
    if value == 0 {
        return Err(bridge_error(
            "source_xref_bridge_incomplete",
            "independent XREF projection contains a null persisted handle",
            format!("{field} is null"),
        ));
    }
    Ok(Handle::new(value))
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

fn overlay_attachments(
    document: &mut CadDocument,
    reader_attachments: &[XrefAttachmentRecord],
    evidence: &XrefSnapshotEvidence,
) -> Result<BTreeSet<Handle>, WriteError> {
    let mut materialized_direct = BTreeSet::new();
    for reader in reader_attachments {
        let reader_handle = persisted_handle(&reader.handle, "XREF attachment handle")?;
        let matches = document
            .block_records
            .iter()
            .filter(|record| record.handle == reader_handle)
            .collect::<Vec<_>>();
        let record = match matches.as_slice() {
            [record] => *record,
            [] => {
                return Err(bridge_error(
                    "source_xref_bridge_identity_mismatch",
                    "reader XREF attachment handle has no identical backend record",
                    format!(
                        "reader handle={:X} name={} path={}",
                        reader_handle.value(),
                        reader.name,
                        reader.saved_path
                    ),
                ))
            }
            _ => {
                return Err(bridge_error(
                    "source_xref_bridge_ambiguous",
                    "reader XREF attachment handle identifies more than one backend record",
                    format!("reader handle={:X}", reader_handle.value()),
                ))
            }
        };
        if !xref_name_eq(&record.name, &reader.name) || record.xref_path != reader.saved_path {
            return Err(bridge_error(
                "source_xref_bridge_identity_mismatch",
                "reader and backend XREF attachment semantic identities differ",
                format!(
                    "reader handle={:X} reader name={} backend name={} reader path={} backend path={}",
                    reader_handle.value(),
                    reader.name,
                    record.name,
                    reader.saved_path,
                    record.xref_path
                ),
            ));
        }
        if !materialized_direct.insert(reader_handle) {
            return Err(bridge_error(
                "source_xref_bridge_ambiguous",
                "more than one reader XREF identity maps to one backend attachment handle",
                format!("backend handle={:X}", reader_handle.value()),
            ));
        }
    }

    let mut proven_records = BTreeSet::new();
    let mut proven_direct = BTreeSet::new();
    let mut patches = Vec::with_capacity(evidence.attachments.len());
    for reader in &evidence.attachments {
        let (Fact::Proven(reader_handle), Fact::Proven(reader_name)) =
            (&reader.handle, &reader.name)
        else {
            return Err(bridge_error(
                "source_xref_bridge_incomplete",
                "independent reader block-definition identity is not fully proven",
                format!("{reader:?}"),
            ));
        };
        let handle = persisted_handle(reader_handle, "block-definition handle")?;
        if !proven_records.insert(handle) {
            return Err(bridge_error(
                "source_xref_bridge_ambiguous",
                "independent reader exposes a duplicate block-definition handle",
                format!("reader handle={:X}", handle.value()),
            ));
        }
        let matches = document
            .block_records
            .iter()
            .filter(|record| record.handle == handle)
            .collect::<Vec<_>>();
        let record = match matches.as_slice() {
            [record] => *record,
            [] => {
                return Err(bridge_error(
                    "source_xref_bridge_identity_mismatch",
                    "reader block-definition handle has no identical backend record",
                    format!("reader handle={:X} name={reader_name}", handle.value()),
                ))
            }
            _ => {
                return Err(bridge_error(
                    "source_xref_bridge_ambiguous",
                    "reader block-definition handle identifies more than one backend record",
                    format!("reader handle={:X}", handle.value()),
                ))
            }
        };
        if !xref_name_eq(&record.name, reader_name) {
            return Err(bridge_error(
                "source_xref_bridge_identity_mismatch",
                "reader and backend block-definition names differ",
                format!(
                    "reader handle={:X} reader name={} backend name={}",
                    handle.value(),
                    reader_name,
                    record.name
                ),
            ));
        }
        let (reference_type, external) = match &reader.membership {
            XrefMembershipEvidence::NotXref => (None, false),
            XrefMembershipEvidence::Direct(reference_type) => {
                if !proven_direct.insert(handle) {
                    return Err(bridge_error(
                        "source_xref_bridge_ambiguous",
                        "independent reader exposes duplicate direct XREF membership",
                        format!("reader handle={:X}", handle.value()),
                    ));
                }
                (Some(*reference_type), false)
            }
            XrefMembershipEvidence::External(reference_type) => (Some(*reference_type), true),
            XrefMembershipEvidence::Unavailable(reason) => {
                return Err(bridge_error(
                    "source_xref_bridge_incomplete",
                    "independent reader cannot observe block-definition XREF membership",
                    reason.clone(),
                ))
            }
            XrefMembershipEvidence::Unsupported(reason) => {
                return Err(bridge_error(
                    "source_xref_bridge_incomplete",
                    "independent reader does not support block-definition XREF membership",
                    reason.clone(),
                ))
            }
            XrefMembershipEvidence::Contradictory(reason) => {
                return Err(bridge_error(
                    "source_xref_bridge_identity_mismatch",
                    "independent reader found contradictory block-definition XREF membership",
                    reason.clone(),
                ))
            }
        };
        if reference_type.is_some() {
            let Fact::Proven(saved_path) = &reader.saved_path else {
                return Err(bridge_error(
                    "source_xref_bridge_incomplete",
                    "independent reader cannot prove an XREF saved path",
                    format!("reader handle={:X} name={reader_name}", handle.value()),
                ));
            };
            if record.xref_path != *saved_path {
                return Err(bridge_error(
                    "source_xref_bridge_identity_mismatch",
                    "reader and backend XREF saved paths differ",
                    format!(
                        "reader handle={:X} reader path={} backend path={}",
                        handle.value(),
                        saved_path,
                        record.xref_path
                    ),
                ));
            }
        } else if let Fact::Proven(saved_path) = &reader.saved_path {
            if record.xref_path != *saved_path {
                return Err(bridge_error(
                    "source_xref_bridge_identity_mismatch",
                    "reader and backend non-XREF block paths differ",
                    format!(
                        "reader handle={:X} reader path={} backend path={}",
                        handle.value(),
                        saved_path,
                        record.xref_path
                    ),
                ));
            }
        }
        patches.push((handle, reference_type, external));
    }

    if let Some(record) = document
        .block_records
        .iter()
        .find(|record| !proven_records.contains(&record.handle))
    {
        return Err(bridge_error(
            "source_xref_bridge_incomplete",
            "backend block-definition membership is absent from independent reader evidence",
            format!(
                "backend handle={:X} name={}",
                record.handle.value(),
                record.name
            ),
        ));
    }
    if materialized_direct != proven_direct {
        return Err(bridge_error(
            "source_xref_bridge_identity_mismatch",
            "materialized and raw reader projections disagree on direct XREF membership",
            format!("materialized={materialized_direct:?} raw={proven_direct:?}"),
        ));
    }

    for (handle, membership_reference, external) in patches {
        let record = document
            .block_records
            .iter_mut()
            .find(|record| record.handle == handle)
            .expect("exact source identity was proven");
        record.flags.is_xref = membership_reference == Some(ReferenceType::Attachment);
        record.flags.is_xref_overlay = membership_reference == Some(ReferenceType::Overlay);
        record.flags.is_external = external;
        if !external {
            if let Some(expected_reference) = membership_reference {
                if !is_direct_xref(record) || reference_type(record) != expected_reference {
                    return Err(bridge_error(
                        "source_xref_bridge_incomplete",
                        "backend XREF membership overlay did not produce a direct attachment",
                        format!("attachment handle={:X}", handle.value()),
                    ));
                }
            }
        }
    }
    Ok(proven_direct)
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

fn owner_name(document: &CadDocument, record: &BlockRecord) -> String {
    if is_model_space_record(document, record) {
        return "Model".to_string();
    }
    if let Some(name) = layout_for_block_record(document, record.handle) {
        return name.to_string();
    }
    record.name.clone()
}

fn prove_owner_handles(
    document: &CadDocument,
    evidence: &autocad_reader::contract::xrefs::XrefSnapshotEvidence,
) -> Result<BTreeSet<Handle>, WriteError> {
    if !evidence.owners_complete {
        return Err(bridge_error(
            "source_xref_bridge_incomplete",
            "independent reader owner identities are incomplete",
            "owners_complete=false",
        ));
    }
    let mut handles = BTreeSet::new();
    for owner in &evidence.owners {
        let (Fact::Proven(reader_handle), Fact::Proven(reader_type), Fact::Proven(reader_name)) =
            (&owner.handle, &owner.owner_type, &owner.name)
        else {
            return Err(bridge_error(
                "source_xref_bridge_incomplete",
                "independent reader owner identity is not fully proven",
                format!("{owner:?}"),
            ));
        };
        let matches = document
            .block_records
            .iter()
            .filter(|record| {
                owner_type(document, record) == *reader_type
                    && xref_name_eq(&owner_name(document, record), reader_name)
            })
            .map(|record| record.handle)
            .collect::<Vec<_>>();
        let backend_handle = match matches.as_slice() {
            [handle] => *handle,
            [] => {
                return Err(bridge_error(
                    "source_xref_bridge_incomplete",
                    "reader XREF owner has no backend semantic match",
                    format!("owner type={reader_type:?} name={reader_name}"),
                ))
            }
            _ => {
                return Err(bridge_error(
                    "source_xref_bridge_ambiguous",
                    "reader XREF owner has more than one backend semantic match",
                    format!("owner type={reader_type:?} name={reader_name}"),
                ))
            }
        };
        let reader_handle = persisted_handle(reader_handle, "XREF owner handle")?;
        if reader_handle != backend_handle {
            return Err(bridge_error(
                "source_xref_bridge_identity_mismatch",
                "reader and backend XREF owner handles differ",
                format!(
                    "reader handle={:X} backend handle={:X} owner={reader_name}",
                    reader_handle.value(),
                    backend_handle.value()
                ),
            ));
        }
        if !handles.insert(backend_handle) {
            return Err(bridge_error(
                "source_xref_bridge_ambiguous",
                "more than one reader owner identity maps to one backend handle",
                format!("owner handle={:X}", backend_handle.value()),
            ));
        }
    }
    Ok(handles)
}

fn prove_layer_handles(
    document: &CadDocument,
    evidence: &autocad_reader::contract::xrefs::XrefSnapshotEvidence,
) -> Result<BTreeSet<Handle>, WriteError> {
    if !evidence.layers_complete {
        return Err(bridge_error(
            "source_xref_bridge_incomplete",
            "independent reader layer identities are incomplete",
            "layers_complete=false",
        ));
    }
    let mut handles = BTreeSet::new();
    for layer in &evidence.layers {
        let (Fact::Proven(reader_handle), Fact::Proven(reader_name)) = (&layer.handle, &layer.name)
        else {
            return Err(bridge_error(
                "source_xref_bridge_incomplete",
                "independent reader layer identity is not fully proven",
                format!("{layer:?}"),
            ));
        };
        let matches = document
            .layers
            .iter()
            .filter(|candidate| xref_name_eq(&candidate.name, reader_name))
            .map(TableEntry::handle)
            .collect::<Vec<_>>();
        let backend_handle = match matches.as_slice() {
            [handle] => *handle,
            [] => {
                return Err(bridge_error(
                    "source_xref_bridge_incomplete",
                    "reader XREF layer has no backend semantic match",
                    format!("layer name={reader_name}"),
                ))
            }
            _ => {
                return Err(bridge_error(
                    "source_xref_bridge_ambiguous",
                    "reader XREF layer has more than one backend semantic match",
                    format!("layer name={reader_name}"),
                ))
            }
        };
        let reader_handle = persisted_handle(reader_handle, "XREF layer handle")?;
        if reader_handle != backend_handle {
            return Err(bridge_error(
                "source_xref_bridge_identity_mismatch",
                "reader and backend XREF layer handles differ",
                format!(
                    "reader handle={:X} backend handle={:X} layer={reader_name}",
                    reader_handle.value(),
                    backend_handle.value()
                ),
            ));
        }
        if !handles.insert(backend_handle) {
            return Err(bridge_error(
                "source_xref_bridge_ambiguous",
                "more than one reader layer identity maps to one backend handle",
                format!("layer handle={:X}", backend_handle.value()),
            ));
        }
    }
    Ok(handles)
}

fn prove_instance_handles(
    document: &CadDocument,
    reader_instances: &[XrefInstanceRecord],
    attachment_handles: &BTreeSet<Handle>,
    owner_handles: &BTreeSet<Handle>,
    layer_handles: &BTreeSet<Handle>,
) -> Result<BTreeSet<Handle>, WriteError> {
    let backend_handles = document
        .entities()
        .filter_map(|entity| match entity {
            EntityType::Insert(insert)
                if document.block_records.iter().any(|record| {
                    attachment_handles.contains(&record.handle)
                        && xref_name_eq(&record.name, &insert.block_name)
                }) =>
            {
                Some(insert.common.handle)
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if backend_handles.len() != reader_instances.len() {
        return Err(bridge_error(
            "source_xref_bridge_incomplete",
            "reader and backend disagree on the number of direct XREF instances",
            format!(
                "reader count={} backend count={}",
                reader_instances.len(),
                backend_handles.len()
            ),
        ));
    }

    let mut matched = BTreeSet::new();
    for reader in reader_instances {
        let handle = persisted_handle(&reader.handle, "XREF instance handle")?;
        if !backend_handles.contains(&handle) {
            return Err(bridge_error(
                "source_xref_bridge_identity_mismatch",
                "reader and backend XREF instance handles differ",
                format!("reader handle={:X}", handle.value()),
            ));
        }
        let attachment_handle =
            persisted_handle(&reader.attachment_handle, "XREF attachment handle")?;
        let owner_handle = persisted_handle(&reader.owner_handle, "XREF owner handle")?;
        let layer_handle = persisted_handle(&reader.layer_handle, "XREF layer handle")?;
        if !attachment_handles.contains(&attachment_handle)
            || !owner_handles.contains(&owner_handle)
            || !layer_handles.contains(&layer_handle)
        {
            return Err(bridge_error(
                "source_xref_bridge_incomplete",
                "XREF instance references an identity not proven by the source bridge",
                format!("instance handle={:X}", handle.value()),
            ));
        }
        let insert = match document.get_entity(handle) {
            Some(EntityType::Insert(insert)) => insert,
            _ => {
                return Err(bridge_error(
                    "source_xref_bridge_identity_mismatch",
                    "reader XREF instance handle does not identify a backend INSERT",
                    format!("instance handle={:X}", handle.value()),
                ))
            }
        };
        let attachment = document
            .block_records
            .iter()
            .find(|record| {
                record.handle == attachment_handle
                    && attachment_handles.contains(&record.handle)
                    && xref_name_eq(&record.name, &insert.block_name)
            })
            .ok_or_else(|| {
                bridge_error(
                    "source_xref_bridge_identity_mismatch",
                    "reader and backend XREF instance attachment identities differ",
                    format!("instance handle={:X}", handle.value()),
                )
            })?;
        let owner = document
            .block_records
            .iter()
            .find(|record| record.handle == owner_handle)
            .ok_or_else(|| {
                bridge_error(
                    "source_xref_bridge_identity_mismatch",
                    "reader and backend XREF instance owner identities differ",
                    format!("instance handle={:X}", handle.value()),
                )
            })?;
        let layer = document
            .layers
            .iter()
            .find(|layer| layer.handle() == layer_handle)
            .ok_or_else(|| {
                bridge_error(
                    "source_xref_bridge_identity_mismatch",
                    "reader and backend XREF instance layer identities differ",
                    format!("instance handle={:X}", handle.value()),
                )
            })?;
        if !xref_name_eq(&attachment.name, &reader.attachment_name)
            || insert.common.owner_handle != owner_handle
            || owner_type(document, owner) != reader.owner_type
            || !xref_name_eq(&owner_name(document, owner), &reader.owner_name)
            || !xref_name_eq(&insert.common.layer, &reader.layer_name)
            || !xref_name_eq(&layer.name, &reader.layer_name)
            || !same_point(insert.insert_point.x, reader.insertion_point.x)
            || !same_point(insert.insert_point.y, reader.insertion_point.y)
            || !same_point(insert.insert_point.z, reader.insertion_point.z)
            || !same_point(insert.x_scale(), reader.scale.x)
            || !same_point(insert.y_scale(), reader.scale.y)
            || !same_point(insert.z_scale(), reader.scale.z)
            || !same_point(
                normalize_rotation(insert.rotation.to_degrees()),
                reader.rotation_degrees,
            )
            || !same_point(insert.normal.x, reader.normal.x)
            || !same_point(insert.normal.y, reader.normal.y)
            || !same_point(insert.normal.z, reader.normal.z)
            || insert.common.invisible
                != matches!(
                    reader.visibility,
                    autocad_reader::contract::xrefs::XrefVisibility::Hidden
                )
            || backend_placement(insert) != (reader.placement_kind, reader.array)
        {
            return Err(bridge_error(
                "source_xref_bridge_identity_mismatch",
                "reader and backend XREF instance semantic identities differ",
                format!("instance handle={:X}", handle.value()),
            ));
        }
        if !matched.insert(handle) {
            return Err(bridge_error(
                "source_xref_bridge_ambiguous",
                "reader XREF instance identity is duplicated",
                format!("instance handle={:X}", handle.value()),
            ));
        }
    }
    Ok(matched)
}

fn restore_reverse_instance_index(
    document: &mut CadDocument,
    reader_attachments: &[XrefAttachmentRecord],
) -> Result<(), WriteError> {
    for reader in reader_attachments {
        let attachment_handle = persisted_handle(&reader.handle, "XREF attachment handle")?;
        let mut instance_handles = document
            .entities()
            .filter_map(|entity| match entity {
                EntityType::Insert(insert)
                    if xref_name_eq(&insert.block_name, &reader.name)
                        && document.block_records.iter().any(|record| {
                            record.handle == attachment_handle && is_direct_xref(record)
                        }) =>
                {
                    Some(insert.common.handle)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        instance_handles.sort_by_key(|handle| handle.value());
        if instance_handles.len() as u64 != reader.instance_count {
            return Err(bridge_error(
                "source_xref_bridge_incomplete",
                "reader and backend disagree on the XREF reverse instance count",
                format!(
                    "attachment handle={:X} reader count={} backend count={}",
                    attachment_handle.value(),
                    reader.instance_count,
                    instance_handles.len()
                ),
            ));
        }
        let record = document
            .block_records
            .iter_mut()
            .find(|record| record.handle == attachment_handle && is_direct_xref(record))
            .expect("attachment identity and membership were proven");
        record.insert_handles = instance_handles;
        record.insert_count_bytes = vec![1; record.insert_handles.len()];
    }
    Ok(())
}

fn verify_candidate_reverse_instance_index(
    document: &CadDocument,
    reader_instances: &[XrefInstanceRecord],
) -> Result<(), WriteError> {
    for record in document
        .block_records
        .iter()
        .filter(|record| is_direct_xref(record))
    {
        let mut expected = reader_instances
            .iter()
            .filter(|instance| {
                persisted_handle(&instance.attachment_handle, "XREF attachment handle")
                    .is_ok_and(|handle| handle == record.handle)
            })
            .map(|instance| persisted_handle(&instance.handle, "XREF instance handle"))
            .collect::<Result<Vec<_>, _>>()?;
        expected.sort_by_key(|handle| handle.value());
        if record.insert_handles != expected
            || record.insert_count_bytes.len() != expected.len()
            || record.insert_count_bytes.contains(&0)
        {
            return Err(WriteError::backend_capability(
                "candidate_xref_reverse_index_unobservable_by_acadrust",
                "acadrust candidate reparse does not expose the persisted XREF reverse INSERT index",
            ));
        }
    }
    Ok(())
}

fn same_point(left: f64, right: f64) -> bool {
    (left - right).abs() <= 1e-8
}

fn normalize_rotation(rotation_degrees: f64) -> f64 {
    let normalized = rotation_degrees.rem_euclid(360.0);
    if normalized == 0.0 {
        0.0
    } else {
        normalized
    }
}

fn backend_placement(
    insert: &acadrust::entities::Insert,
) -> (XrefPlacementKind, Option<XrefRectangularArray>) {
    if insert.is_array() {
        (
            XrefPlacementKind::RectangularArray,
            Some(XrefRectangularArray {
                rows: u32::from(insert.row_count),
                columns: u32::from(insert.column_count),
                row_spacing: insert.row_spacing,
                column_spacing: insert.column_spacing,
            }),
        )
    } else {
        (XrefPlacementKind::Single, None)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use acadrust::{CadDocument, DwgWriter, DxfWriter};

    use super::*;
    use crate::contract::{AttachXref, ReferenceType};
    use crate::xrefs;
    use crate::{DrawingFormat, DrawingSnapshot};

    fn attached_source() -> (DrawingSnapshot, CadDocument) {
        let mut document = CadDocument::new();
        let bridge = XrefHandleBridge::identity(&document);
        xrefs::attach(
            &mut document,
            DrawingFormat::Dxf,
            &mut BTreeMap::new(),
            &bridge,
            &AttachXref {
                xref_path: "site.dwg".to_string(),
                name: Some("SITE".to_string()),
                reference_type: ReferenceType::Attachment,
                search_paths: None,
                placement: None,
                unit_assumptions: None,
            },
        )
        .unwrap();
        let snapshot = DrawingSnapshot::new(
            DrawingFormat::Dxf,
            DxfWriter::new(&document).write_to_vec().unwrap(),
        );
        (snapshot, document)
    }

    #[test]
    fn reader_truth_overlay_restores_ascii_xref_membership_without_aliasing_handles() {
        let (snapshot, _) = attached_source();
        let mut parsed = crate::backend::parse(&snapshot).unwrap().document;
        let before = parsed.block_records.get("SITE").unwrap();
        assert!(!before.flags.is_xref);
        assert!(!before.flags.is_xref_overlay);

        let bridge = XrefHandleBridge::from_source(&snapshot, &mut parsed).unwrap();
        let after = parsed.block_records.get("SITE").unwrap();
        assert!(after.flags.is_xref);
        assert!(!after.flags.is_xref_overlay);
        assert!(bridge.proves_attachment(after.handle));
    }

    #[test]
    fn source_bridge_accepts_direct_membership_alongside_nested_and_path_only_records() {
        let (_, mut document) = attached_source();
        let direct_handle = document.block_records.get("SITE").unwrap().handle;
        let mut path_only = BlockRecord::new("PATH_ONLY");
        path_only.handle = document.allocate_handle();
        path_only.block_entity_handle = document.allocate_handle();
        path_only.block_end_handle = document.allocate_handle();
        path_only.xref_path = "path-only.dwg".to_string();
        document.block_records.add(path_only).unwrap();
        let mut external = BlockRecord::new("NESTED_SITE");
        external.handle = document.allocate_handle();
        external.block_entity_handle = document.allocate_handle();
        external.block_end_handle = document.allocate_handle();
        external.flags.is_xref = true;
        external.flags.is_external = true;
        external.xref_path = "nested.dwg".to_string();
        document.block_records.add(external).unwrap();
        let snapshot = DrawingSnapshot::new(
            DrawingFormat::Dxf,
            DxfWriter::new(&document).write_to_vec().unwrap(),
        );
        let mut parsed = crate::backend::parse(&snapshot).unwrap().document;

        let bridge = XrefHandleBridge::from_source(&snapshot, &mut parsed).unwrap();

        assert!(bridge.proves_attachment(direct_handle));
        assert!(!parsed.block_records.get("PATH_ONLY").unwrap().flags.is_xref);
        assert!(parsed
            .block_records
            .iter()
            .any(|record| record.flags.is_external && record.name == "NESTED_SITE"));
    }

    // DWG candidate generation is compiled only into the Preview product
    // (`backend::parse` returns `dwg_preview_only_error` for DWG outside
    // `preview`) -- unrelated to XREF, a pre-existing main-side constraint.
    #[cfg(feature = "preview")]
    #[test]
    fn dwg_source_bridge_accepts_direct_membership_alongside_a_path_only_record() {
        let (_, mut document) = attached_source();
        let direct_handle = document.block_records.get("SITE").unwrap().handle;
        let mut path_only = BlockRecord::new("PATH_ONLY");
        path_only.handle = document.allocate_handle();
        path_only.block_entity_handle = document.allocate_handle();
        path_only.block_end_handle = document.allocate_handle();
        path_only.xref_path = "path-only.dwg".to_string();
        document.block_records.add(path_only).unwrap();
        let snapshot = DrawingSnapshot::new(
            DrawingFormat::Dwg,
            DwgWriter::write_to_vec(&document).unwrap(),
        );
        let mut parsed = crate::backend::parse(&snapshot).unwrap().document;

        let bridge = XrefHandleBridge::from_source(&snapshot, &mut parsed).unwrap();

        assert!(bridge.proves_attachment(direct_handle));
        let path_only = parsed.block_records.get("PATH_ONLY").unwrap();
        assert!(!path_only.flags.is_xref);
        assert!(!path_only.flags.is_xref_overlay);
        assert_eq!(path_only.xref_path, "path-only.dwg");
    }

    #[cfg(feature = "preview")]
    #[test]
    fn dwg_bridge_restores_independently_proven_external_membership() {
        let (_, mut document) = attached_source();
        let mut external = BlockRecord::new("PARENT|CHILD");
        external.handle = document.allocate_handle();
        external.block_entity_handle = document.allocate_handle();
        external.block_end_handle = document.allocate_handle();
        external.flags.is_xref = true;
        external.flags.is_external = true;
        external.xref_path = "nested.dwg".to_string();
        let external_handle = external.handle;
        document.block_records.add(external).unwrap();
        let snapshot = DrawingSnapshot::new(
            DrawingFormat::Dwg,
            DwgWriter::write_to_vec(&document).unwrap(),
        );
        let reader = autocad_reader::Reader::open_snapshot(snapshot.reader_snapshot()).unwrap();
        let session = reader.xref_session().unwrap();
        let mut attachments = session.list_attachments().unwrap();
        attachments.retain(|attachment| attachment.name != "PARENT|CHILD");
        let mut evidence = session.evidence().clone();
        let external_evidence = evidence
            .attachments
            .iter_mut()
            .find(|attachment| {
                matches!(&attachment.name, Fact::Proven(name) if name == "PARENT|CHILD")
            })
            .unwrap();
        external_evidence.membership = XrefMembershipEvidence::External(ReferenceType::Attachment);
        let mut parsed = crate::backend::parse(&snapshot).unwrap().document;

        let bridge = overlay_attachments(&mut parsed, &attachments, &evidence).unwrap();

        assert!(!bridge.contains(&external_handle));
        let external = parsed.block_records.get("PARENT|CHILD").unwrap();
        assert!(external.flags.is_xref);
        assert!(external.flags.is_external);
        assert_eq!(external.xref_path, "nested.dwg");
    }

    #[test]
    fn semantic_attachment_ambiguity_is_rejected_without_applying_an_overlay() {
        let (snapshot, _) = attached_source();
        let reader = autocad_reader::Reader::open_snapshot(snapshot.reader_snapshot()).unwrap();
        let session = reader.xref_session().unwrap();
        let mut attachments = session.list_attachments().unwrap();
        attachments.push(attachments[0].clone());
        let mut parsed = crate::backend::parse(&snapshot).unwrap().document;

        let error = overlay_attachments(&mut parsed, &attachments, session.evidence()).unwrap_err();
        assert_eq!(error.code(), "source_xref_bridge_ambiguous");
        assert!(!parsed.block_records.get("SITE").unwrap().flags.is_xref);
    }

    #[test]
    fn unmatched_backend_direct_xref_is_rejected_before_overlay() {
        let (snapshot, _) = attached_source();
        let reader = autocad_reader::Reader::open_snapshot(snapshot.reader_snapshot()).unwrap();
        let session = reader.xref_session().unwrap();
        let attachments = session.list_attachments().unwrap();
        let mut parsed = crate::backend::parse(&snapshot).unwrap().document;
        let mut direct = BlockRecord::new("UNPROVEN_DIRECT");
        direct.handle = parsed.allocate_handle();
        direct.block_entity_handle = parsed.allocate_handle();
        direct.block_end_handle = parsed.allocate_handle();
        direct.flags.is_xref = true;
        direct.xref_path = "unproven.dwg".to_string();
        parsed.block_records.add(direct).unwrap();

        let error = overlay_attachments(&mut parsed, &attachments, session.evidence()).unwrap_err();
        assert_eq!(error.code(), "source_xref_bridge_incomplete");
        assert!(!parsed.block_records.get("SITE").unwrap().flags.is_xref);
    }

    #[test]
    fn matched_direct_xref_with_an_empty_saved_path_is_overlaid() {
        let (_, mut document) = attached_source();
        document
            .block_records
            .get_mut("SITE")
            .unwrap()
            .xref_path
            .clear();
        let snapshot = DrawingSnapshot::new(
            DrawingFormat::Dxf,
            DxfWriter::new(&document).write_to_vec().unwrap(),
        );
        let mut parsed = crate::backend::parse(&snapshot).unwrap().document;
        assert!(!parsed.block_records.get("SITE").unwrap().flags.is_xref);

        XrefHandleBridge::from_source(&snapshot, &mut parsed).unwrap();
        let record = parsed.block_records.get("SITE").unwrap();
        assert!(record.flags.is_xref);
        assert!(record.xref_path.is_empty());
    }

    #[test]
    fn duplicate_backend_attachment_handle_is_ambiguous() {
        let (snapshot, _) = attached_source();
        let reader = autocad_reader::Reader::open_snapshot(snapshot.reader_snapshot()).unwrap();
        let session = reader.xref_session().unwrap();
        let attachments = session.list_attachments().unwrap();
        let mut parsed = crate::backend::parse(&snapshot).unwrap().document;
        let original = parsed.block_records.get("SITE").unwrap().clone();
        let mut duplicate = original.clone();
        duplicate.name = "DUPLICATE_HANDLE".to_string();
        parsed.block_records.add(duplicate).unwrap();

        let error = overlay_attachments(&mut parsed, &attachments, session.evidence()).unwrap_err();
        assert_eq!(error.code(), "source_xref_bridge_ambiguous");
        assert!(!parsed.block_records.get("SITE").unwrap().flags.is_xref);
    }

    /// A True Color (RGB) layer must not make the bridge itself refuse —
    /// before this fix `layers_complete=false` refused every drawing with
    /// such a layer via `source_xref_bridge_incomplete`, regardless of
    /// whether it had any XREFs. See memory
    /// `project-xref-bridge-identity-mismatch-root-cause`.
    ///
    /// This calls `XrefHandleBridge::from_source` directly rather than
    /// going through `Writer::open_snapshot`: the full pipeline still
    /// refuses true-color layers for an unrelated, already-disclosed reason
    /// (`ensure_candidate_source_admitted`, "acadrust 0.4.1 DXF
    /// serialization converts true-color layers to ACI 7" -- a real,
    /// separate data-loss concern this integration deliberately left
    /// untouched). What this test proves is narrower and still true: the
    /// bridge itself adds no redundant block of its own.
    #[test]
    fn dwg_true_color_layer_does_not_block_the_bridge() {
        use acadrust::tables::Layer;
        use acadrust::types::Color;
        use acadrust::TableEntry;

        let mut document = CadDocument::new();
        let mut layer = Layer::with_color("TRUE_COLOR", Color::from_rgb(10, 20, 30));
        layer.set_handle(document.allocate_handle());
        document.layers.add(layer).unwrap();
        let bytes = DwgWriter::write_to_vec(&document).unwrap();
        let snapshot = DrawingSnapshot::new(DrawingFormat::Dwg, bytes);
        let mut reopened = acadrust::DwgReader::from_stream(std::io::Cursor::new(
            snapshot.bytes().as_ref().to_vec(),
        ))
        .read()
        .unwrap();

        XrefHandleBridge::from_source(&snapshot, &mut reopened)
            .expect("a True Color layer must not make the bridge itself refuse");
    }

    /// A DGN-converted (or otherwise non-Autodesk) drawing can store the
    /// reserved paper-space block name in a different case, e.g.
    /// `*PAPER_SPACE` instead of acadrust's own `*Paper_Space`.
    /// `owner_type`/`owner_name` must classify it correctly via the
    /// record's `Layout` hard-owner reference, not the literal spelling —
    /// and must do the same for model space via
    /// `document.header.model_space_block_handle`, not a name check at
    /// all. See memory `project-xref-bridge-identity-mismatch-root-cause`.
    #[test]
    fn owner_classification_is_case_and_spelling_independent() {
        let mut document = CadDocument::new();
        document.block_records.get_mut("*Paper_Space").unwrap().name = "*PAPER_SPACE".to_string();

        let model_space = document.block_records.get("*Model_Space").unwrap();
        assert_eq!(
            owner_type(&document, model_space),
            XrefOwnerType::ModelSpace
        );
        assert_eq!(owner_name(&document, model_space), "Model");

        let paper_space = document.block_records.get("*PAPER_SPACE").unwrap();
        assert_eq!(
            owner_type(&document, paper_space),
            XrefOwnerType::PaperSpace
        );
        assert_eq!(owner_name(&document, paper_space), "Layout1");
    }

    /// End-to-end: the same uppercased-paper-space drawing must open
    /// through the writer at all, not just classify correctly in
    /// isolation. DWG session open is Preview-only; see the comment on
    /// `dwg_source_bridge_accepts_direct_membership_alongside_a_path_only_record`.
    #[cfg(feature = "preview")]
    #[test]
    fn dwg_uppercased_paper_space_name_does_not_block_session_open() {
        let mut document = CadDocument::new();
        document.block_records.get_mut("*Paper_Space").unwrap().name = "*PAPER_SPACE".to_string();
        let bytes = DwgWriter::write_to_vec(&document).unwrap();

        crate::Writer::open_snapshot(DrawingSnapshot::new(DrawingFormat::Dwg, bytes))
            .expect("an uppercased *PAPER_SPACE record must not refuse writer session open");
    }
}
