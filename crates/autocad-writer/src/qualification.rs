use std::collections::BTreeMap;

use acadrust::entities::{
    AttributeEntity, EntityType, Insert, Line, Polyline3D, Surface, SurfaceKind, Vertex3DPolyline,
    Viewport,
};
use acadrust::tables::{BlockRecord, Layer, TableEntry};
use acadrust::types::{Color, Handle, Vector3};
use acadrust::xdata::{ExtendedDataRecord, XDataValue};
#[cfg(feature = "preview")]
use acadrust::DwgWriter;
use acadrust::{CadDocument, DxfWriter};

use super::contract::{
    AttachXref, CandidateFormat, CreateLayer, DeleteLayer, DetachXref, InsertXrefInstance,
    InsertionUnit, LayerLineWeight, LayerProperties, LayerReconciliationMode, LayerSelector,
    MutationRoute, MutationSupport, ReferenceType, RenameLayer, TitleBlockFingerprint,
    TitleBlockWrite, UnloadXref, UpdateLayer, UpdateXrefInstanceProperties, UpdateXrefProperties,
    XrefAttachmentGuard, XrefDestructiveAttachmentGuard, XrefInstanceAttachmentGuard,
    XrefInstancePlacement, XrefLayerProperty, XrefUnitAssumptions, ALL_MUTATION_ROUTES,
};
use super::{
    DrawingFormat, DrawingSnapshot, DrawingWriteSession, RoundtripClaimBoundary, WriteError,
    WriteErrorKind, Writer,
};

fn dxf_snapshot(document: &CadDocument) -> DrawingSnapshot {
    DrawingSnapshot::new(
        DrawingFormat::Dxf,
        DxfWriter::new(document).write_to_vec().unwrap(),
    )
}

#[cfg(feature = "preview")]
fn dwg_snapshot(document: &CadDocument) -> DrawingSnapshot {
    DrawingSnapshot::new(
        DrawingFormat::Dwg,
        DwgWriter::write_to_vec(document).unwrap(),
    )
}

fn document_with_layer(name: &str) -> CadDocument {
    let mut document = CadDocument::new();
    let mut layer = Layer::new(name);
    layer.set_handle(document.allocate_handle());
    document.layers.add(layer).unwrap();
    document
}

fn title_block_document() -> CadDocument {
    let mut document = CadDocument::new();
    let mut definition = BlockRecord::new("AUTOCAD_MCP_GENERIC");
    definition.handle = document.allocate_handle();
    definition.block_entity_handle = document.allocate_handle();
    definition.block_end_handle = document.allocate_handle();
    definition.flags.has_attributes = true;
    document.block_records.add(definition).unwrap();

    let mut insert = Insert::new("AUTOCAD_MCP_GENERIC", Vector3::ZERO);
    insert.common.handle = document.allocate_handle();
    insert
        .attributes
        .push(AttributeEntity::simple("DRAWING_NUMBER", "A-001"));
    insert
        .attributes
        .push(AttributeEntity::simple("REVISION", "P01"));
    for attribute in &mut insert.attributes {
        attribute.common.handle = document.allocate_handle();
        attribute.common.owner_handle = insert.common.handle;
    }
    let insert_handle = insert.common.handle;
    document.add_entity(EntityType::Insert(insert)).unwrap();
    let definition = document
        .block_records
        .get_mut("AUTOCAD_MCP_GENERIC")
        .unwrap();
    definition.insert_handles.push(insert_handle);
    definition.insert_count_bytes.push(1);
    document
}

#[test]
fn mutation_capability_inventory_is_exact_and_exhaustive() {
    let capabilities = Writer::mutation_capabilities();
    assert_eq!(capabilities.len(), ALL_MUTATION_ROUTES.len());
    assert_eq!(
        capabilities
            .iter()
            .map(|capability| capability.route)
            .collect::<Vec<_>>(),
        ALL_MUTATION_ROUTES
    );
    assert_eq!(
        capabilities
            .iter()
            .filter(|capability| capability.support == MutationSupport::CandidateGeneration)
            .count(),
        5
    );
    assert!(capabilities
        .iter()
        .filter(|capability| capability.support == MutationSupport::CandidateGeneration)
        .all(|capability| capability.source_admission_required));
    for capability in capabilities
        .iter()
        .filter(|capability| capability.support == MutationSupport::CandidateGeneration)
    {
        #[cfg(feature = "preview")]
        let expected = if capability.route == MutationRoute::WriteTitleBlock {
            vec![CandidateFormat::Dwg, CandidateFormat::AsciiDxf]
        } else {
            vec![CandidateFormat::AsciiDxf]
        };
        #[cfg(not(feature = "preview"))]
        let expected = vec![CandidateFormat::AsciiDxf];
        assert_eq!(capability.candidate_formats, expected);
    }
    assert_eq!(
        capabilities
            .iter()
            .filter(|capability| capability.support == MutationSupport::BackendBlocked)
            .count(),
        9
    );
    let plot = capabilities
        .iter()
        .find(|capability| capability.route == MutationRoute::PlotToPdf)
        .unwrap();
    assert!(!plot.mutates_drawing);
    assert_eq!(plot.support, MutationSupport::ExternalRenderer);
    assert_eq!(
        plot.blocker_code.as_deref(),
        Some("plot_renderer_unavailable")
    );
}

#[test]
fn layer_create_encodes_owned_dxf_candidate_and_reader_reopens_it() {
    let source = dxf_snapshot(&CadDocument::new());
    let source_bytes = source.bytes();
    let mut session = Writer::open_snapshot(source).unwrap();
    let mutation = session
        .create_layer(CreateLayer {
            name: "ANNO".to_string(),
            properties: LayerProperties {
                color_index: Some(3),
                locked: Some(true),
                ..Default::default()
            },
        })
        .unwrap();
    let candidate = session.encode_candidate().unwrap_or_else(|error| {
        panic!(
            "candidate failed: {error}; internal={:?}",
            error.internal_detail()
        )
    });

    assert_ne!(candidate.bytes(), source_bytes.as_ref());
    assert_eq!(candidate.receipt().format, "DXF");
    assert_eq!(
        candidate.receipt().claim_boundary,
        RoundtripClaimBoundary::DevelopmentEvidenceOnly
    );
    assert_eq!(candidate.receipt().operations, [MutationRoute::CreateLayer]);
    assert!(candidate.receipt().reader_reopen_verified);
    assert!(candidate.receipt().operation_postconditions_verified);
    assert!(!candidate.receipt().whole_document_preservation_verified);
    assert!(!candidate.receipt().native_host_verified);

    let reader = autocad_reader::Reader::open_snapshot(autocad_reader::DrawingSnapshot::new(
        autocad_reader::DrawingFormat::Dxf,
        candidate.bytes().to_vec(),
    ))
    .unwrap();
    let record = reader
        .get_layer(&LayerSelector {
            name: Some("ANNO".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(record.color_index, Some(3));
    assert!(record.locked);
    assert_eq!(
        mutation,
        super::contract::LayerMutation::Created { layer: record }
    );
}

#[test]
fn title_block_write_preflights_then_roundtrips_exact_attribute_state() {
    let mut session = Writer::open_snapshot(dxf_snapshot(&title_block_document())).unwrap();
    let fingerprint = TitleBlockFingerprint {
        block_name: "AUTOCAD_MCP_GENERIC".to_string(),
        attribute_tags: vec!["DRAWING_NUMBER".to_string(), "REVISION".to_string()],
    };

    let missing = session
        .write_title_block(TitleBlockWrite {
            fingerprint: fingerprint.clone(),
            tag_values: BTreeMap::from([("MISSING".to_string(), "x".to_string())]),
        })
        .unwrap_err();
    assert_eq!(missing.code(), "unknown_title_block_tag");

    let result = session
        .write_title_block(TitleBlockWrite {
            fingerprint,
            tag_values: BTreeMap::from([("revision".to_string(), "P02".to_string())]),
        })
        .unwrap();
    assert_eq!(result.target_inserts, 1);
    assert_eq!(result.fields_written, 1);
    assert_eq!(result.attributes_written, 1);

    let candidate = session.encode_candidate().unwrap();
    let reader = autocad_reader::Reader::open_snapshot(autocad_reader::DrawingSnapshot::new(
        autocad_reader::DrawingFormat::Dxf,
        candidate.bytes().to_vec(),
    ))
    .unwrap();
    let blocks = reader.read_title_blocks().unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].attributes["REVISION"], "P02");
    assert_eq!(blocks[0].attributes["DRAWING_NUMBER"], "A-001");
}

#[cfg(feature = "preview")]
#[test]
fn preview_ac1032_title_block_candidate_proves_bounded_whole_document_preservation() {
    let mut session = Writer::open_snapshot(dwg_snapshot(&title_block_document())).unwrap();
    session
        .write_title_block(TitleBlockWrite {
            fingerprint: TitleBlockFingerprint {
                block_name: "AUTOCAD_MCP_GENERIC".to_string(),
                attribute_tags: vec!["DRAWING_NUMBER".to_string(), "REVISION".to_string()],
            },
            tag_values: BTreeMap::from([
                ("DRAWING_NUMBER".to_string(), "A-002".to_string()),
                ("REVISION".to_string(), "P02".to_string()),
            ]),
        })
        .unwrap();

    let candidate = session.encode_candidate().unwrap_or_else(|error| {
        panic!(
            "candidate failed: {error}; internal={:?}",
            error.internal_detail()
        )
    });
    assert_eq!(
        candidate.receipt().claim_boundary,
        RoundtripClaimBoundary::PreviewQualified
    );
    assert!(candidate.receipt().reader_reopen_verified);
    assert!(candidate.receipt().operation_postconditions_verified);
    assert!(candidate.receipt().whole_document_preservation_verified);
    assert!(!candidate.receipt().native_host_verified);
    assert_eq!(&candidate.bytes()[..6], b"AC1032");
}

#[test]
fn title_block_write_rejects_extension_dictionary_backed_attributes() {
    let mut document = title_block_document();
    for entity in document.entities_mut() {
        let EntityType::Insert(insert) = entity else {
            continue;
        };
        insert.attributes[1].common.xdictionary_handle = Some(Handle::new(0xABC));
    }
    let mut session = DrawingWriteSession::from_document_for_test(DrawingFormat::Dxf, document);
    let error = session
        .write_title_block(TitleBlockWrite {
            fingerprint: TitleBlockFingerprint {
                block_name: "AUTOCAD_MCP_GENERIC".to_string(),
                attribute_tags: vec!["DRAWING_NUMBER".to_string(), "REVISION".to_string()],
            },
            tag_values: BTreeMap::from([("REVISION".to_string(), "P02".to_string())]),
        })
        .unwrap_err();
    assert_eq!(error.code(), "unsupported_title_block_attribute");
}

#[test]
fn known_lossy_dxf_source_shapes_fail_writer_admission() {
    let mut true_color = document_with_layer("RGB");
    true_color.layers.get_mut("RGB").unwrap().color = Color::from_rgb(12, 34, 56);
    let error = super::backend::ensure_candidate_source_admitted(&true_color).unwrap_err();
    assert_eq!(error.code(), "true_color_layer_not_preserved");

    let mut surface = CadDocument::new();
    surface
        .add_entity(EntityType::Surface(Surface::new(SurfaceKind::Generic)))
        .unwrap();
    let error = super::backend::ensure_candidate_source_admitted(&surface).unwrap_err();
    assert_eq!(error.code(), "unsupported_entity_preservation");

    let mut xdata = document_with_layer("XDATA");
    let mut line = Line::new();
    let mut record = ExtendedDataRecord::new("AUTOCAD_MCP_TEST");
    record.add_value(XDataValue::String("must survive".to_string()));
    line.common.extended_data.add_record(record);
    xdata.add_entity(EntityType::Line(line)).unwrap();
    let error = super::backend::ensure_candidate_source_admitted(&xdata).unwrap_err();
    assert_eq!(error.code(), "extended_data_not_preserved");

    let xdata_bytes = b"  0\r\nLINE\r\n1001\r\nAUTOCAD_MCP_TEST\r\n";
    let error = super::backend::ensure_ascii_dxf_source_bytes_admitted(xdata_bytes).unwrap_err();
    assert_eq!(error.code(), "extended_data_not_preserved");

    let color_book_bytes = b"  0\r\nLINE\r\n430\r\nPANTONE$Red\r\n";
    let error =
        super::backend::ensure_ascii_dxf_source_bytes_admitted(color_book_bytes).unwrap_err();
    assert_eq!(error.code(), "color_book_not_preserved");

    let code_as_value = b"  1\r\n430\r\n";
    super::backend::ensure_ascii_dxf_source_bytes_admitted(code_as_value).unwrap();
}

#[test]
fn xref_internal_plans_cover_live_route_semantics() {
    let attach = AttachXref {
        xref_path: "site.dwg".to_string(),
        name: Some("SITE".to_string()),
        reference_type: ReferenceType::Attachment,
        search_paths: None,
        placement: None,
        unit_assumptions: Some(XrefUnitAssumptions {
            source_units: Some(InsertionUnit::Meters),
            host_units: Some(InsertionUnit::Millimeters),
        }),
    };
    assert_eq!(
        serde_json::to_value(attach).unwrap()["unit_assumptions"]["source_units"],
        "meters"
    );

    for (mode, expected) in [
        (LayerReconciliationMode::DrawingPolicy, "drawing_policy"),
        (LayerReconciliationMode::PreserveHost, "preserve_host"),
        (
            LayerReconciliationMode::SourceAuthoritative,
            "source_authoritative",
        ),
        (LayerReconciliationMode::Synchronize, "synchronize"),
    ] {
        assert_eq!(serde_json::to_value(mode).unwrap(), expected);
    }
    assert_eq!(
        serde_json::to_value(XrefLayerProperty::LineWeight).unwrap(),
        "line_weight"
    );

    let destructive = DetachXref {
        attachment: XrefDestructiveAttachmentGuard {
            expected_instance_count: Some(2),
            expected_instance_handles: Some(vec!["10".to_string(), "11".to_string()]),
            ..Default::default()
        },
    };
    assert_eq!(
        serde_json::to_value(destructive).unwrap()["attachment"]["expected_instance_count"],
        2
    );
    let insert = InsertXrefInstance {
        attachment: XrefInstanceAttachmentGuard {
            attachment_name: Some("SITE".to_string()),
            ..Default::default()
        },
        placement: Some(XrefInstancePlacement {
            array: Some(super::contract::XrefRectangularArray {
                columns: 2,
                rows: 3,
                column_spacing: 100.0,
                row_spacing: 50.0,
            }),
            ..Default::default()
        }),
        unit_assumptions: None,
    };
    assert_eq!(
        serde_json::to_value(insert).unwrap()["placement"]["array"]["columns"],
        2
    );

    let attachment_update = UpdateXrefProperties {
        name: Some("CAMPUS".to_string()),
        xref_path: Some("campus.dwg".to_string()),
        reference_type: Some(ReferenceType::Overlay),
    };
    assert_eq!(
        serde_json::to_value(attachment_update).unwrap(),
        serde_json::json!({
            "name": "CAMPUS",
            "xref_path": "campus.dwg",
            "reference_type": "overlay"
        })
    );

    let instance_update = UpdateXrefInstanceProperties {
        visibility: Some(super::contract::XrefVisibility::Hidden),
        rotation_degrees: Some(90.0),
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_value(instance_update).unwrap(),
        serde_json::json!({
            "rotation_degrees": 90.0,
            "visibility": "hidden"
        })
    );

    let attach_with_array = serde_json::json!({
        "xref_path": "site.dwg",
        "reference_type": "attachment",
        "placement": {
            "array": {
                "columns": 2,
                "rows": 2,
                "column_spacing": 1.0,
                "row_spacing": 1.0
            }
        }
    });
    assert!(serde_json::from_value::<AttachXref>(attach_with_array).is_err());
}

#[test]
fn layer_update_rename_and_delete_each_roundtrip_as_one_candidate() {
    let mut update = Writer::open_snapshot(dxf_snapshot(&document_with_layer("ANNO"))).unwrap();
    update
        .update_layer(UpdateLayer {
            selector: LayerSelector {
                name: Some("ANNO".to_string()),
                expected_name: Some("anno".to_string()),
                ..Default::default()
            },
            properties: LayerProperties {
                frozen: Some(true),
                line_weight: Some(LayerLineWeight::Value { hundredths_mm: 25 }),
                ..Default::default()
            },
        })
        .unwrap();
    assert_eq!(
        update.encode_candidate().unwrap().receipt().operations,
        [MutationRoute::UpdateLayer]
    );

    let mut rename_document = document_with_layer("OLD");
    let mut line = Line::from_coords(0.0, 0.0, 0.0, 1.0, 1.0, 0.0);
    line.common.layer = "OLD".to_string();
    rename_document.add_entity(EntityType::Line(line)).unwrap();
    let mut rename = Writer::open_snapshot(dxf_snapshot(&rename_document)).unwrap();
    rename
        .rename_layer(RenameLayer {
            selector: LayerSelector {
                name: Some("old".to_string()),
                ..Default::default()
            },
            new_name: "NEW".to_string(),
        })
        .unwrap();
    assert_eq!(
        rename.encode_candidate().unwrap().receipt().operations,
        [MutationRoute::RenameLayer]
    );

    let mut delete = Writer::open_snapshot(dxf_snapshot(&document_with_layer("EMPTY"))).unwrap();
    delete
        .delete_layer(DeleteLayer {
            selector: LayerSelector {
                name: Some("EMPTY".to_string()),
                ..Default::default()
            },
        })
        .unwrap();
    assert_eq!(
        delete.encode_candidate().unwrap().receipt().operations,
        [MutationRoute::DeleteLayer]
    );
}

#[test]
fn compound_children_fail_admission_and_delete_reports_viewport_references() {
    let mut document = document_with_layer("OLD");
    let mut polyline = Polyline3D::new();
    polyline.common.layer = "0".to_string();
    let mut vertex = Vertex3DPolyline::from_xyz(1.0, 2.0, 3.0);
    vertex.layer = "OLD".to_string();
    polyline.vertices.push(vertex);
    document
        .add_entity(EntityType::Polyline3D(polyline))
        .unwrap();

    let error = super::backend::ensure_candidate_source_admitted(&document).unwrap_err();
    assert_eq!(error.code(), "unsupported_entity_preservation");

    let mut document = document_with_layer("VIEWPORT_LOCKED");
    let layer_handle = document.layers.get("VIEWPORT_LOCKED").unwrap().handle();
    let mut viewport = Viewport::new();
    viewport.frozen_layers.push(layer_handle);
    document.add_entity(EntityType::Viewport(viewport)).unwrap();
    let mut delete = Writer::open_snapshot(dxf_snapshot(&document)).unwrap();
    let error = delete
        .delete_layer(DeleteLayer {
            selector: LayerSelector {
                name: Some("VIEWPORT_LOCKED".to_string()),
                ..Default::default()
            },
        })
        .unwrap_err();
    assert_eq!(error.code(), "layer_has_unverified_references");
}

#[test]
fn one_operation_per_session_keeps_receipts_unambiguous() {
    let mut session = Writer::open_snapshot(dxf_snapshot(&CadDocument::new())).unwrap();
    session
        .create_layer(CreateLayer {
            name: "FIRST".to_string(),
            properties: LayerProperties::default(),
        })
        .unwrap();
    let error = session
        .create_layer(CreateLayer {
            name: "SECOND".to_string(),
            properties: LayerProperties::default(),
        })
        .unwrap_err();
    assert_eq!(error.code(), "multiple_mutations_unsupported");
}

#[test]
fn xref_entry_points_fail_before_mutating_the_session() {
    let mut session = Writer::open_snapshot(dxf_snapshot(&CadDocument::new())).unwrap();
    let error = session
        .unload_xref(UnloadXref {
            attachment: XrefAttachmentGuard {
                name: Some("SITE".to_string()),
                ..Default::default()
            },
        })
        .unwrap_err();
    assert_eq!(error.kind(), WriteErrorKind::BackendCapability);
    assert_eq!(error.code(), "xref_load_state_not_preserved");

    // A blocked attempt does not consume the one supported mutation slot.
    session
        .create_layer(CreateLayer {
            name: "AFTER_BLOCK".to_string(),
            properties: LayerProperties::default(),
        })
        .unwrap();
}

#[test]
fn dwg_candidates_are_unqualified_before_serialization() {
    let mut document = document_with_layer("HOST");
    let mut xref = BlockRecord::new("SITE");
    xref.handle = document.allocate_handle();
    xref.block_entity_handle = document.allocate_handle();
    xref.block_end_handle = document.allocate_handle();
    xref.flags.is_xref = true;
    xref.xref_path = "site.dwg".to_string();
    document.block_records.add(xref).unwrap();

    let mut session = DrawingWriteSession::from_document_for_test(DrawingFormat::Dwg, document);
    session
        .create_layer(CreateLayer {
            name: "UNRELATED".to_string(),
            properties: LayerProperties::default(),
        })
        .unwrap();
    let error = session.encode_candidate().unwrap_err();
    assert_eq!(error.kind(), WriteErrorKind::BackendCapability);
    #[cfg(feature = "preview")]
    assert_eq!(error.code(), "preview_dwg_route_not_qualified");
    #[cfg(not(feature = "preview"))]
    assert_eq!(error.code(), "dwg_candidate_preservation_unqualified");
}

#[test]
fn xref_bearing_dxf_is_rejected_before_a_mutation_session_is_returned() {
    let mut document = document_with_layer("HOST");
    let mut xref = BlockRecord::new("SITE");
    xref.handle = document.allocate_handle();
    xref.block_entity_handle = document.allocate_handle();
    xref.block_end_handle = document.allocate_handle();
    xref.flags.is_xref = true;
    xref.xref_path = "site.dwg".to_string();
    document.block_records.add(xref).unwrap();

    let error = match Writer::open_snapshot(dxf_snapshot(&document)) {
        Ok(_) => panic!("XREF-bearing DXF unexpectedly entered a mutation session"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), WriteErrorKind::BackendCapability);
    assert_eq!(error.code(), "xref_metadata_not_preserved");
}

#[test]
fn backend_details_are_not_exposed_by_error_display_or_debug() {
    let error = WriteError::invalid_drawing("backend-only marker");
    assert!(!error.to_string().contains("backend-only marker"));
    assert!(!format!("{error:?}").contains("backend-only marker"));
    assert_eq!(error.internal_detail(), Some("backend-only marker"));
}

#[test]
fn empty_candidate_generation_is_rejected() {
    let session = Writer::open_snapshot(dxf_snapshot(&CadDocument::new())).unwrap();
    let error = session.encode_candidate().unwrap_err();
    assert_eq!(error.code(), "empty_mutation");
}
