//! Backend-independent external-consumer smoke test for the candidate writer.
//!
//! This target deliberately uses no acadrust types or fixture writers. It
//! proves that the application package can consume the transport-neutral
//! writer dependency, that the route inventory remains exact, and that an
//! owned candidate can be generated without replacing the committed source
//! drawing. Production MCP routes are intentionally not migrated here.

use std::path::{Path, PathBuf};

use autocad_writer::contract::{
    CandidateFormat, CreateLayer, LayerMutation, LayerProperties, MutationRoute, MutationSupport,
    ALL_MUTATION_ROUTES,
};
use autocad_writer::{RoundtripClaimBoundary, RoundtripReceipt, WriteErrorKind, Writer};
use sha2::{Digest, Sha256};

const PROJECT_DXF: &str = "tests/corpus/open/project/generic-title-block-ascii.dxf";
const PROJECT_DXF_SHA256: &str = "36b87b71d61d8452cd257bb5028b8bb1d879cbda63c02c9951fb966ffa53a86f";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn route_capability_inventory_is_exact() {
    let capabilities = Writer::mutation_capabilities();
    assert_eq!(capabilities.len(), ALL_MUTATION_ROUTES.len());
    assert_eq!(
        capabilities
            .iter()
            .map(|capability| capability.route)
            .collect::<Vec<_>>(),
        ALL_MUTATION_ROUTES
    );

    let expected = [
        (
            MutationRoute::CreateLayer,
            true,
            MutationSupport::CandidateGeneration,
            None,
        ),
        (
            MutationRoute::UpdateLayer,
            true,
            MutationSupport::CandidateGeneration,
            None,
        ),
        (
            MutationRoute::RenameLayer,
            true,
            MutationSupport::CandidateGeneration,
            None,
        ),
        (
            MutationRoute::DeleteLayer,
            true,
            MutationSupport::CandidateGeneration,
            None,
        ),
        (
            MutationRoute::WriteTitleBlock,
            true,
            MutationSupport::CandidateGeneration,
            None,
        ),
        (
            MutationRoute::AttachXref,
            true,
            MutationSupport::BackendBlocked,
            Some("xref_graph_invariants_unavailable"),
        ),
        (
            MutationRoute::UpdateXref,
            true,
            MutationSupport::BackendBlocked,
            Some("xref_graph_invariants_unavailable"),
        ),
        (
            MutationRoute::DetachXref,
            true,
            MutationSupport::BackendBlocked,
            Some("xref_reverse_links_unavailable"),
        ),
        (
            MutationRoute::InsertXrefInstance,
            true,
            MutationSupport::BackendBlocked,
            Some("xref_reverse_links_unavailable"),
        ),
        (
            MutationRoute::UpdateXrefInstance,
            true,
            MutationSupport::BackendBlocked,
            Some("xref_reverse_links_unavailable"),
        ),
        (
            MutationRoute::DeleteXrefInstance,
            true,
            MutationSupport::BackendBlocked,
            Some("xref_reverse_links_unavailable"),
        ),
        (
            MutationRoute::ReloadXref,
            true,
            MutationSupport::BackendBlocked,
            Some("xref_load_state_not_preserved"),
        ),
        (
            MutationRoute::UnloadXref,
            true,
            MutationSupport::BackendBlocked,
            Some("xref_load_state_not_preserved"),
        ),
        (
            MutationRoute::BindXref,
            true,
            MutationSupport::BackendBlocked,
            Some("xref_graph_import_unavailable"),
        ),
        (
            MutationRoute::PlotToPdf,
            false,
            MutationSupport::ExternalRenderer,
            Some("plot_renderer_unavailable"),
        ),
    ];

    for (capability, (route, mutates_drawing, support, blocker_code)) in
        capabilities.iter().zip(expected)
    {
        assert_eq!(capability.route, route);
        assert_eq!(capability.mutates_drawing, mutates_drawing);
        assert_eq!(capability.support, support);
        assert_eq!(capability.blocker_code.as_deref(), blocker_code);
        if support == MutationSupport::CandidateGeneration {
            assert_eq!(capability.candidate_formats, [CandidateFormat::AsciiDxf]);
            assert!(capability.source_admission_required);
        } else {
            assert!(capability.candidate_formats.is_empty());
            assert!(!capability.source_admission_required);
        }
    }
}

#[test]
fn committed_dxf_generates_an_owned_verified_candidate_without_source_replacement() {
    let source_path = repository_root().join(PROJECT_DXF);
    let before = std::fs::read(&source_path).unwrap();
    assert_eq!(sha256(&before), PROJECT_DXF_SHA256);

    let mut session = Writer::open_path(&source_path).unwrap();
    let mutation = session
        .create_layer(CreateLayer {
            name: "AUTOCAD_WRITER_CONTRACT".to_string(),
            properties: LayerProperties {
                color_index: Some(3),
                locked: Some(true),
                ..Default::default()
            },
        })
        .unwrap();
    let LayerMutation::Created { layer } = mutation else {
        panic!("create_layer returned the wrong mutation record");
    };
    assert_eq!(layer.name, "AUTOCAD_WRITER_CONTRACT");
    assert_eq!(layer.color_index, Some(3));
    assert!(layer.locked);

    let candidate = session.encode_candidate().unwrap();
    let receipt: &RoundtripReceipt = candidate.receipt();
    assert_eq!(
        receipt.claim_boundary,
        RoundtripClaimBoundary::DevelopmentEvidenceOnly
    );
    assert_eq!(receipt.format, "DXF");
    assert_eq!(receipt.source_sha256, PROJECT_DXF_SHA256);
    assert_eq!(receipt.candidate_sha256, sha256(candidate.bytes()));
    assert_eq!(receipt.source_bytes, before.len());
    assert_eq!(receipt.candidate_bytes, candidate.bytes().len());
    assert_eq!(receipt.operations, [MutationRoute::CreateLayer]);
    assert!(receipt.reader_reopen_verified);
    assert!(receipt.operation_postconditions_verified);
    assert!(!receipt.whole_document_preservation_verified);
    assert!(!receipt.native_host_verified);
    assert_ne!(candidate.bytes(), before);

    let after = std::fs::read(&source_path).unwrap();
    assert_eq!(after, before, "candidate generation replaced its source");
}

#[test]
fn path_capture_errors_are_stable_and_backend_neutral() {
    let missing = repository_root().join("tests/does-not-exist/writer-contract.dwg");
    let error = match Writer::open_path(&missing) {
        Ok(_) => panic!("missing drawing unexpectedly opened"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), WriteErrorKind::NotFound);
    assert_eq!(error.code(), "drawing_not_found");
    assert_eq!(
        error.to_string(),
        "code=drawing_not_found drawing was not found"
    );
}
