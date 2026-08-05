use acadrust::types::DxfVersion;
use acadrust::{CadDocument, DxfWriter};
use autocad_reader::contract::xrefs::{
    XrefAttachmentRecord, XrefInstanceListOptions, XrefInstanceRecord,
};
use autocad_writer::contract::{
    AttachXref, BindXref, DeleteXrefInstance, DependencyStrategy, DetachXref, InsertXrefInstance,
    MutationRoute, ReferenceType, ReloadXref, SymbolStrategy, UnloadXref, UpdateXref,
    UpdateXrefInstance, UpdateXrefInstanceProperties, UpdateXrefProperties, XrefAttachmentGuard,
    XrefDestructiveAttachmentGuard, XrefInstanceAttachmentGuard, XrefInstanceGuard,
    XrefInstancePlacement, XrefPoint3, XrefVisibility,
};
use autocad_writer::{DrawingFormat, DrawingSnapshot, RoundtripCandidate, Writer};

fn empty_ascii_dxf() -> DrawingSnapshot {
    DrawingSnapshot::new(
        DrawingFormat::Dxf,
        DxfWriter::new(&CadDocument::new()).write_to_vec().unwrap(),
    )
}

fn open_ascii(bytes: &[u8]) -> autocad_writer::DrawingWriteSession {
    Writer::open_snapshot(DrawingSnapshot::new(DrawingFormat::Dxf, bytes.to_vec())).unwrap()
}

fn reader_projection(bytes: &[u8]) -> (XrefAttachmentRecord, XrefInstanceRecord) {
    let reader = autocad_reader::Reader::open_snapshot(autocad_reader::DrawingSnapshot::new(
        autocad_reader::DrawingFormat::Dxf,
        bytes.to_vec(),
    ))
    .unwrap();
    let session = reader.xref_session().unwrap();
    let attachments = session.list_attachments().unwrap();
    let instances = session
        .list_instances(&XrefInstanceListOptions::default())
        .unwrap();
    assert_eq!(attachments.len(), 1);
    assert_eq!(instances.len(), 1);
    (attachments[0].clone(), instances[0].clone())
}

/// Asserts a successful candidate for one of the six real XREF mutation
/// routes: the independent-reader postcondition always holds (`?`-propagated
/// inside `encode_candidate` if not, so reaching this point already proves
/// it), but the second, backend-reparse proof (`operation_postconditions_
/// verified`) is only available for routes where acadrust's ASCII-DXF
/// writer reliably round-trips the affected XREF block record's reverse
/// INSERT-handle index -- true for the two routes that only ever shrink or
/// remove entries (Detach/DeleteInstance), not for the ones that add or
/// rename one (Attach/Update/Insert/UpdateInstance). See the matching
/// comment in `session.rs`'s `encode_candidate`.
fn assert_candidate(candidate: &RoundtripCandidate, route: MutationRoute, backend_verified: bool) {
    let receipt = candidate.receipt();
    assert_eq!(receipt.format, "DXF");
    assert_eq!(receipt.operations, [route]);
    assert!(receipt.reader_reopen_verified);
    assert_eq!(receipt.operation_postconditions_verified, backend_verified);
}

fn attached_ascii_candidate() -> (Vec<u8>, XrefAttachmentRecord, XrefInstanceRecord) {
    let mut writer = Writer::open_snapshot(empty_ascii_dxf()).unwrap();
    writer
        .attach_xref(AttachXref {
            xref_path: "site.dwg".to_string(),
            name: Some("SITE".to_string()),
            reference_type: ReferenceType::Attachment,
            search_paths: None,
            placement: None,
            unit_assumptions: None,
        })
        .unwrap();
    let candidate = writer.encode_candidate().unwrap();
    assert_candidate(&candidate, MutationRoute::AttachXref, false);
    let (attachment, instance) = reader_projection(candidate.bytes());
    (candidate.into_bytes(), attachment, instance)
}

#[test]
fn all_six_real_xref_routes_accept_ascii_dxf_and_emit_reader_visible_candidates() {
    let (source, attachment, instance) = attached_ascii_candidate();
    let attachment_handle = attachment.handle;
    let instance_handle = instance.handle;
    let owner_handle = instance.owner_handle;

    let mut update = open_ascii(&source);
    let updated = update
        .update_xref(UpdateXref {
            attachment: XrefAttachmentGuard {
                handle: Some(attachment_handle.clone()),
                name: Some("site".to_string()),
                expected_handle: Some(attachment_handle.clone()),
                expected_name: Some("SITE".to_string()),
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
    assert_eq!(updated.attachment.handle, attachment_handle);
    assert_eq!(updated.attachment.name, "CAMPUS");
    let candidate = update.encode_candidate().unwrap();
    assert_candidate(&candidate, MutationRoute::UpdateXref, false);

    let mut insert = open_ascii(&source);
    let inserted = insert
        .insert_xref_instance(InsertXrefInstance {
            attachment: XrefInstanceAttachmentGuard {
                attachment_handle: Some(attachment_handle.clone()),
                attachment_name: Some("SITE".to_string()),
                expected_attachment_handle: Some(attachment_handle.clone()),
            },
            placement: Some(XrefInstancePlacement {
                insertion_point: Some(XrefPoint3 {
                    x: 10.0,
                    y: 20.0,
                    z: 0.0,
                }),
                ..Default::default()
            }),
            unit_assumptions: None,
        })
        .unwrap();
    assert_ne!(inserted.instance.handle, instance_handle);
    let candidate = insert.encode_candidate().unwrap();
    assert_candidate(&candidate, MutationRoute::InsertXrefInstance, false);

    let mut update_instance = open_ascii(&source);
    let updated = update_instance
        .update_xref_instance(UpdateXrefInstance {
            instance: XrefInstanceGuard {
                handle: instance_handle.clone(),
                expected_attachment_handle: Some(attachment_handle.clone()),
                expected_owner_handle: Some(owner_handle),
            },
            properties: UpdateXrefInstanceProperties {
                insertion_point: Some(XrefPoint3 {
                    x: 5.0,
                    y: 6.0,
                    z: 7.0,
                }),
                rotation_degrees: Some(45.0),
                visibility: Some(XrefVisibility::Hidden),
                ..Default::default()
            },
        })
        .unwrap();
    assert_eq!(updated.instance.insertion_point.x, 5.0);
    let candidate = update_instance.encode_candidate().unwrap();
    assert_candidate(&candidate, MutationRoute::UpdateXrefInstance, false);

    let mut delete_instance = open_ascii(&source);
    delete_instance
        .delete_xref_instance(DeleteXrefInstance {
            instance: XrefInstanceGuard {
                handle: instance_handle.clone(),
                expected_attachment_handle: Some(attachment_handle.clone()),
                expected_owner_handle: None,
            },
        })
        .unwrap();
    let candidate = delete_instance.encode_candidate().unwrap();
    assert_candidate(&candidate, MutationRoute::DeleteXrefInstance, true);

    let mut detach = open_ascii(&source);
    let result = detach
        .detach_xref(DetachXref {
            attachment: XrefDestructiveAttachmentGuard {
                handle: Some(attachment_handle.clone()),
                expected_handle: Some(attachment_handle.clone()),
                expected_instance_count: Some(1),
                expected_instance_handles: Some(vec![instance_handle.clone()]),
                ..Default::default()
            },
        })
        .unwrap();
    assert_eq!(result.deleted_instance_handles.len(), 1);
    let candidate = detach.encode_candidate().unwrap();
    assert_candidate(&candidate, MutationRoute::DetachXref, true);

    // ReloadXref/UnloadXref/BindXref stay hard-blocked: acadrust 0.4.1 has
    // no primitive to materialize load state or a real graph-import, and
    // (unlike the six routes above) there is no dedicated postcondition or
    // handle-bridge verification story for them, so this integration keeps
    // main's existing immediate-refusal behavior rather than surfacing an
    // unverifiable, best-effort result.
    let mut unload = open_ascii(&source);
    let error = unload
        .unload_xref(UnloadXref {
            attachment: XrefAttachmentGuard {
                handle: Some(attachment_handle.clone()),
                ..Default::default()
            },
        })
        .unwrap_err();
    assert_eq!(error.code(), "xref_load_state_not_preserved");

    let mut reload = open_ascii(&source);
    let error = reload
        .reload_xref(ReloadXref {
            attachment: XrefAttachmentGuard {
                handle: Some(attachment_handle.clone()),
                ..Default::default()
            },
            search_paths: None,
            layer_reconciliation: None,
            unit_assumptions: None,
        })
        .unwrap_err();
    assert_eq!(error.code(), "xref_load_state_not_preserved");

    let mut bind = open_ascii(&source);
    let error = bind
        .bind_xref(BindXref {
            attachment: XrefDestructiveAttachmentGuard {
                handle: Some(attachment_handle.clone()),
                expected_handle: Some(attachment_handle.clone()),
                expected_instance_count: Some(1),
                expected_instance_handles: Some(vec![instance_handle.clone()]),
                ..Default::default()
            },
            symbol_strategy: SymbolStrategy::Prefix,
            dependency_strategy: DependencyStrategy::RejectNested,
            search_paths: None,
        })
        .unwrap_err();
    assert_eq!(error.code(), "xref_graph_import_unavailable");
}

#[test]
fn blocked_xref_route_is_refused_immediately_without_touching_the_document() {
    let (source, attachment, instance) = attached_ascii_candidate();
    let mut session = open_ascii(&source);
    let error = session
        .bind_xref(BindXref {
            attachment: XrefDestructiveAttachmentGuard {
                handle: Some(attachment.handle.clone()),
                expected_handle: Some(attachment.handle.clone()),
                expected_instance_count: Some(1),
                expected_instance_handles: Some(vec![instance.handle.clone()]),
                ..Default::default()
            },
            symbol_strategy: SymbolStrategy::Prefix,
            dependency_strategy: DependencyStrategy::RejectNested,
            search_paths: None,
        })
        .unwrap_err();
    assert_eq!(error.code(), "xref_graph_import_unavailable");
    // The session never recorded an operation, so a subsequent real mutation
    // still works -- `bind_xref` really did nothing to `self`.
    session
        .update_xref(UpdateXref {
            attachment: XrefAttachmentGuard {
                handle: Some(attachment.handle.clone()),
                name: Some("SITE".to_string()),
                expected_handle: Some(attachment.handle.clone()),
                expected_name: Some("SITE".to_string()),
            },
            properties: UpdateXrefProperties {
                xref_path: Some("moved.dwg".to_string()),
                ..Default::default()
            },
            search_paths: None,
            layer_reconciliation: None,
            unit_assumptions: None,
        })
        .unwrap();
    session.encode_candidate().unwrap();
}

#[test]
fn ascii_bridge_guard_contradiction_is_atomic_and_does_not_weaken_identity() {
    let (source, attachment, _) = attached_ascii_candidate();
    let mut writer = open_ascii(&source);
    let error = writer
        .update_xref(UpdateXref {
            attachment: XrefAttachmentGuard {
                handle: Some(attachment.handle.clone()),
                name: Some("OTHER".to_string()),
                expected_handle: Some(attachment.handle.clone()),
                expected_name: Some("SITE".to_string()),
            },
            properties: UpdateXrefProperties {
                xref_path: Some("wrong.dwg".to_string()),
                ..Default::default()
            },
            search_paths: None,
            layer_reconciliation: None,
            unit_assumptions: None,
        })
        .unwrap_err();
    assert_eq!(error.code(), "xref_not_found");

    writer
        .update_xref(UpdateXref {
            attachment: XrefAttachmentGuard {
                handle: Some(attachment.handle),
                name: Some("SITE".to_string()),
                expected_handle: None,
                expected_name: Some("SITE".to_string()),
            },
            properties: UpdateXrefProperties {
                xref_path: Some("safe.dwg".to_string()),
                ..Default::default()
            },
            search_paths: None,
            layer_reconciliation: None,
            unit_assumptions: None,
        })
        .unwrap();
    let candidate = writer.encode_candidate().unwrap();
    assert_candidate(&candidate, MutationRoute::UpdateXref, false);
    let (updated, _) = reader_projection(candidate.bytes());
    assert_eq!(updated.saved_path, "safe.dwg");
}

#[test]
fn off_qualification_ascii_dxf_is_rejected_before_xref_mutation() {
    // The handle-bridge and postcondition verification the six real XREF
    // routes rely on is proven only for AC1032/`ANSI_1252` ASCII DXF (the
    // DXF-side equivalent of the AC1032-only DWG admission
    // `backend::admit_dwg_encode` already enforces). A session still opens
    // -- an unrelated route like CreateLayer works fine on these documents
    // -- but the six XREF routes themselves refuse before touching anything.
    let mut wrong_version = CadDocument::with_version(DxfVersion::AC1027);
    wrong_version.header.code_page = "ANSI_1252".to_string();
    let mut wrong_code_page = CadDocument::new();
    wrong_code_page.header.code_page = "ANSI_1251".to_string();
    let snapshots = [
        DrawingSnapshot::new(
            DrawingFormat::Dxf,
            DxfWriter::new(&wrong_version).write_to_vec().unwrap(),
        ),
        DrawingSnapshot::new(
            DrawingFormat::Dxf,
            DxfWriter::new(&wrong_code_page).write_to_vec().unwrap(),
        ),
    ];

    for snapshot in snapshots {
        let mut writer = Writer::open_snapshot(snapshot).unwrap();
        let error = writer
            .attach_xref(AttachXref {
                xref_path: "site.dwg".to_string(),
                name: Some("SITE".to_string()),
                reference_type: ReferenceType::Attachment,
                search_paths: None,
                placement: None,
                unit_assumptions: None,
            })
            .unwrap_err();
        assert_eq!(error.code(), "unsupported_format");
        assert_eq!(
            writer.encode_candidate().unwrap_err().code(),
            "empty_mutation"
        );
    }
}

#[test]
fn binary_dxf_never_admits_a_writer_session_at_all() {
    let snapshot = DrawingSnapshot::new(
        DrawingFormat::Dxf,
        DxfWriter::new_binary(&CadDocument::new())
            .write_to_vec()
            .unwrap(),
    );
    let error = match Writer::open_snapshot(snapshot) {
        Ok(_) => panic!("binary DXF unexpectedly admitted a writer session"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "binary_dxf_not_preserved");
}
