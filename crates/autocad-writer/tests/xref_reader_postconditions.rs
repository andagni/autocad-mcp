// DWG candidate generation is compiled only into the Preview product
// (`backend::parse` returns `dwg_preview_only_error` for DWG outside
// `preview`) -- a pre-existing main-side constraint, unrelated to XREF. This
// whole file is DWG-only by design (ASCII DXF coverage lives in
// `xref_ascii_matrix.rs`), so it compiles to nothing outside `preview`
// rather than gating every test individually.
#![cfg(feature = "preview")]

use acadrust::{CadDocument, DwgWriter};
use autocad_writer::contract::{
    AttachXref, AttachXrefResult, BindXref, DeleteXrefInstance, DependencyStrategy, DetachXref,
    InsertXrefInstance, MutationRoute, ReferenceType, ReloadXref, SymbolStrategy, UnloadXref,
    UpdateXref, UpdateXrefInstance, UpdateXrefInstanceProperties, UpdateXrefProperties,
    XrefAttachmentGuard, XrefDestructiveAttachmentGuard, XrefInstanceAttachmentGuard,
    XrefInstanceGuard, XrefInstancePlacement, XrefPoint3, XrefVisibility,
};
use autocad_writer::{DrawingFormat, DrawingSnapshot, RoundtripCandidate, Writer};

fn empty_dwg() -> DrawingSnapshot {
    DrawingSnapshot::new(
        DrawingFormat::Dwg,
        DwgWriter::write_to_vec(&CadDocument::new()).unwrap(),
    )
}

fn open_dwg(bytes: &[u8]) -> autocad_writer::DrawingWriteSession {
    Writer::open_snapshot(DrawingSnapshot::new(DrawingFormat::Dwg, bytes.to_vec())).unwrap()
}

/// Asserts a successful, fully-verified DWG candidate for one of the six
/// real XREF mutation routes -- the independent reader postcondition
/// (`xref_reader_postconditions::verify`) and the backend reparse/handle
/// bridge (`XrefHandleBridge::verify_candidate`, `xrefs::verify`) both ran
/// and agreed, or `encode_candidate` would already have returned `Err`.
fn assert_verified_dwg_candidate(candidate: &RoundtripCandidate, route: MutationRoute) {
    assert_eq!(candidate.receipt().format, "DWG");
    assert_eq!(candidate.receipt().operations, [route]);
    assert!(candidate.receipt().reader_reopen_verified);
    assert!(candidate.receipt().operation_postconditions_verified);
}

fn attached_dwg() -> (Vec<u8>, AttachXrefResult) {
    let mut session = Writer::open_snapshot(empty_dwg()).unwrap();
    let attached = session
        .attach_xref(AttachXref {
            xref_path: "site.dwg".to_string(),
            name: Some("SITE".to_string()),
            reference_type: ReferenceType::Attachment,
            search_paths: None,
            placement: None,
            unit_assumptions: None,
        })
        .unwrap();
    let candidate = session.encode_candidate().unwrap();
    assert_verified_dwg_candidate(&candidate, MutationRoute::AttachXref);
    (candidate.into_bytes(), attached)
}

#[test]
fn dwg_attachment_routes_receive_independent_reader_postconditions() {
    let (source, attached) = attached_dwg();

    let mut update = open_dwg(&source);
    update
        .update_xref(UpdateXref {
            attachment: XrefAttachmentGuard {
                handle: Some(attached.attachment.handle.clone()),
                expected_handle: Some(attached.attachment.handle.clone()),
                expected_name: Some(attached.attachment.name.clone()),
                ..Default::default()
            },
            properties: UpdateXrefProperties {
                name: Some("CAMPUS".to_string()),
                xref_path: Some("campus.dwg".to_string()),
                reference_type: Some(ReferenceType::Overlay),
            },
            search_paths: None,
            layer_reconciliation: None,
            unit_assumptions: None,
        })
        .unwrap();
    let candidate = update.encode_candidate().unwrap();
    assert_verified_dwg_candidate(&candidate, MutationRoute::UpdateXref);

    let mut detach = open_dwg(&source);
    detach
        .detach_xref(DetachXref {
            attachment: XrefDestructiveAttachmentGuard {
                handle: Some(attached.attachment.handle.clone()),
                expected_handle: Some(attached.attachment.handle),
                expected_instance_count: Some(1),
                expected_instance_handles: Some(vec![attached.instance.handle]),
                ..Default::default()
            },
        })
        .unwrap();
    let candidate = detach.encode_candidate().unwrap();
    assert_verified_dwg_candidate(&candidate, MutationRoute::DetachXref);
}

#[test]
fn dwg_instance_routes_receive_independent_reader_postconditions() {
    let (source, attached) = attached_dwg();

    let mut insert = open_dwg(&source);
    insert
        .insert_xref_instance(InsertXrefInstance {
            attachment: XrefInstanceAttachmentGuard {
                attachment_handle: Some(attached.attachment.handle.clone()),
                expected_attachment_handle: Some(attached.attachment.handle.clone()),
                ..Default::default()
            },
            placement: Some(XrefInstancePlacement {
                insertion_point: Some(XrefPoint3 {
                    x: 12.0,
                    y: 34.0,
                    z: 0.0,
                }),
                ..Default::default()
            }),
            unit_assumptions: None,
        })
        .unwrap();
    let candidate = insert.encode_candidate().unwrap();
    assert_verified_dwg_candidate(&candidate, MutationRoute::InsertXrefInstance);

    let mut update = open_dwg(&source);
    update
        .update_xref_instance(UpdateXrefInstance {
            instance: XrefInstanceGuard {
                handle: attached.instance.handle.clone(),
                expected_attachment_handle: Some(attached.attachment.handle.clone()),
                expected_owner_handle: Some(attached.instance.owner_handle.clone()),
            },
            properties: UpdateXrefInstanceProperties {
                insertion_point: Some(XrefPoint3 {
                    x: 5.0,
                    y: 6.0,
                    z: 7.0,
                }),
                rotation_degrees: Some(90.0),
                visibility: Some(XrefVisibility::Hidden),
                ..Default::default()
            },
        })
        .unwrap();
    let candidate = update.encode_candidate().unwrap();
    assert_verified_dwg_candidate(&candidate, MutationRoute::UpdateXrefInstance);

    let mut delete = open_dwg(&source);
    delete
        .delete_xref_instance(DeleteXrefInstance {
            instance: XrefInstanceGuard {
                handle: attached.instance.handle,
                expected_attachment_handle: Some(attached.attachment.handle),
                expected_owner_handle: None,
            },
        })
        .unwrap();
    let candidate = delete.encode_candidate().unwrap();
    assert_verified_dwg_candidate(&candidate, MutationRoute::DeleteXrefInstance);
}

#[test]
fn dwg_unmaterializable_xref_routes_stay_hard_blocked() {
    // acadrust 0.4.1 has no primitive to materialize XREF load state or a
    // real graph-import (unlike the six routes above, proven safe through
    // the independent-reader postcondition and handle-bridge checks), so
    // these three routes are refused immediately rather than producing an
    // unverifiable, best-effort candidate -- on DWG exactly as on ASCII DXF.
    let (source, attached) = attached_dwg();

    let mut unload = open_dwg(&source);
    let error = unload
        .unload_xref(UnloadXref {
            attachment: XrefAttachmentGuard {
                handle: Some(attached.attachment.handle.clone()),
                ..Default::default()
            },
        })
        .unwrap_err();
    assert_eq!(error.code(), "xref_load_state_not_preserved");

    let mut reload = open_dwg(&source);
    let error = reload
        .reload_xref(ReloadXref {
            attachment: XrefAttachmentGuard {
                handle: Some(attached.attachment.handle.clone()),
                ..Default::default()
            },
            search_paths: None,
            layer_reconciliation: None,
            unit_assumptions: None,
        })
        .unwrap_err();
    assert_eq!(error.code(), "xref_load_state_not_preserved");

    let mut bind = open_dwg(&source);
    let error = bind
        .bind_xref(BindXref {
            attachment: XrefDestructiveAttachmentGuard {
                handle: Some(attached.attachment.handle.clone()),
                expected_handle: Some(attached.attachment.handle),
                expected_instance_count: Some(1),
                expected_instance_handles: Some(vec![attached.instance.handle]),
                ..Default::default()
            },
            symbol_strategy: SymbolStrategy::Prefix,
            dependency_strategy: DependencyStrategy::RejectNested,
            search_paths: None,
        })
        .unwrap_err();
    assert_eq!(error.code(), "xref_graph_import_unavailable");
}
