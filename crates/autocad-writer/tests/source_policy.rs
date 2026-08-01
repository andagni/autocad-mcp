use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(feature = "preview")]
use autocad_writer::contract::MutationRoute;
use autocad_writer::contract::{mutation_capabilities, CandidateFormat, MutationSupport};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate must be inside the workspace")
        .to_path_buf()
}

fn cargo_metadata(repository: &Path) -> serde_json::Value {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(repository)
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .output()
        .expect("cargo metadata should run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata should emit JSON")
}

#[test]
fn writer_boundary_is_internal_backend_owned_and_application_independent() {
    let repository = repository_root();
    let metadata = cargo_metadata(&repository);
    let packages = metadata["packages"]
        .as_array()
        .expect("cargo metadata packages must be an array");
    let writer = packages
        .iter()
        .find(|package| package["name"] == "autocad-writer")
        .expect("autocad-writer package must exist");

    assert_eq!(
        writer["publish"],
        serde_json::json!([]),
        "autocad-writer must remain explicitly nonpublished"
    );
    let dependencies = writer["dependencies"]
        .as_array()
        .expect("writer dependencies must be an array");
    assert!(
        dependencies
            .iter()
            .all(|dependency| dependency["name"] != "autocad-mcp"),
        "writer must not depend on the application crate"
    );

    let backends = dependencies
        .iter()
        .filter(|dependency| dependency["name"] == "acadrust")
        .collect::<Vec<_>>();
    assert_eq!(
        backends.len(),
        1,
        "writer must retain exactly one selected mutable backend"
    );
    assert!(
        backends[0]["rename"].is_null(),
        "the mutable backend must not be renamed around source-boundary policy"
    );
    assert_eq!(
        backends[0]["req"].as_str(),
        Some("=0.4.1"),
        "writer must retain the reviewed exact acadrust requirement"
    );

    let expected_reader = repository.join("crates/autocad-reader");
    let readers = dependencies
        .iter()
        .filter(|dependency| dependency["name"] == "autocad-reader")
        .collect::<Vec<_>>();
    assert_eq!(
        readers.len(),
        1,
        "writer must depend on exactly one reader boundary"
    );
    assert_eq!(
        readers[0]["path"].as_str().map(Path::new),
        Some(expected_reader.as_path()),
        "writer must use the workspace reader boundary"
    );
}

#[test]
fn writer_candidate_contract_remains_narrow_and_noncertifying() {
    let capabilities = mutation_capabilities();
    assert_eq!(
        capabilities.len(),
        15,
        "every product mutation route must have one writer capability"
    );
    for capability in &capabilities {
        if capability.support == MutationSupport::CandidateGeneration {
            #[cfg(feature = "preview")]
            let expected_formats = if capability.route == MutationRoute::WriteTitleBlock {
                vec![CandidateFormat::Dwg, CandidateFormat::AsciiDxf]
            } else {
                vec![CandidateFormat::AsciiDxf]
            };
            #[cfg(not(feature = "preview"))]
            let expected_formats = vec![CandidateFormat::AsciiDxf];
            assert_eq!(
                capability.candidate_formats, expected_formats,
                "candidate generation must remain restricted to its admitted product formats"
            );
            assert!(
                capability.source_admission_required,
                "candidate generation must retain source admission"
            );
        } else {
            assert!(
                capability.candidate_formats.is_empty(),
                "blocked and external-renderer routes must not advertise candidate formats"
            );
        }
    }

    let repository = repository_root();
    let session = std::fs::read_to_string(repository.join("crates/autocad-writer/src/session.rs"))
        .expect("writer session source should be readable");
    assert!(
        !session.contains("write_to_file"),
        "writer sessions must return owned candidates rather than writing source paths"
    );
    for boundary in [
        "RoundtripClaimBoundary::DevelopmentEvidenceOnly",
        "RoundtripClaimBoundary::PreviewQualified",
        "verify_dwg_title_block_preservation",
        "native_host_verified: false",
    ] {
        assert!(
            session.contains(boundary),
            "writer receipt must retain its non-certifying boundary: {boundary}"
        );
    }

    let backend =
        std::fs::read_to_string(repository.join("crates/autocad-writer/src/backend/mod.rs"))
            .expect("writer backend source should be readable");
    for guard in [
        "dwg_candidate_preservation_unqualified",
        "xref_metadata_not_preserved",
        "extended_data_not_preserved",
        "color_book_not_preserved",
    ] {
        assert!(
            backend.contains(guard),
            "writer admission must retain the known unqualified-source guard: {guard}"
        );
    }
}
