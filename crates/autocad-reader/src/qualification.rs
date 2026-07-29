use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::backend::{ReadDiagnostic, ReadDiagnosticKind};
use super::{DrawingFormat, DrawingReadSession, DrawingSnapshot, ReadError, ReadErrorKind, Reader};

const FIXTURE_LEDGER_PATH: &str = "tests/fixture-provenance.json";
const TIER1_MANIFEST_PATH: &str = "tests/corpus/open/manifest.json";
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureLedger {
    schema_version: u32,
    scope_roots: Vec<String>,
    project_rights_holder: String,
    project_license: String,
    artifacts: Vec<FixtureArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureArtifact {
    path: String,
    sha256: String,
    artifact_class: String,
    license_expression: String,
    privacy_disposition: String,
    origin: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tier1Manifest {
    schema_version: u32,
    tier: u32,
    fixtures: Vec<Tier1Fixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tier1Fixture {
    path: String,
    sha256: String,
    format: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticBaseline {
    schema_version: u32,
    report_kind: &'static str,
    claim_boundary: &'static str,
    backend: BackendIdentity,
    fixture_authority: FixtureAuthority,
    fixtures: Vec<FixtureDiagnosticRecord>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BackendIdentity {
    package: &'static str,
    manifest_requirement: String,
    resolved_version: String,
    source: String,
    checksum_sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureAuthority {
    path: &'static str,
    selection: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureDiagnosticRecord {
    path: String,
    sha256: String,
    format: &'static str,
    tier1: bool,
    interpretation: FixtureInterpretation,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
// The flat success shape is the reviewed byte-exact qualification schema.
#[allow(clippy::large_enum_variant)]
enum FixtureInterpretation {
    Success {
        diagnostics: Vec<DiagnosticRecord>,
        block_diagnostic_gate: FamilyDiagnosticGateDisposition,
        entity_diagnostic_gate: FamilyDiagnosticGateDisposition,
        title_block_diagnostic_gate: FamilyDiagnosticGateDisposition,
        drawing_diagnostic_gate: FamilyDiagnosticGateDisposition,
        text_diagnostic_gate: FamilyDiagnosticGateDisposition,
        layout_diagnostic_gate: FamilyDiagnosticGateDisposition,
        symbol_diagnostic_gate: FamilyDiagnosticGateDisposition,
        layer_diagnostic_gate: FamilyDiagnosticGateDisposition,
        format_facts_diagnostic_gate: FamilyDiagnosticGateDisposition,
    },
    Error {
        error_kind: &'static str,
        message: String,
        diagnostics: Vec<DiagnosticRecord>,
    },
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticRecord {
    kind: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum FamilyDiagnosticGateDisposition {
    Accepted,
    Rejected { code: String, message: String },
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("autocad-reader must be inside the workspace")
        .to_path_buf()
}

fn primary_repository_root(root: &Path) -> PathBuf {
    let dot_git = root.join(".git");
    let metadata = std::fs::symlink_metadata(&dot_git)
        .unwrap_or_else(|error| panic!("inspect {}: {error}", dot_git.display()));
    assert!(
        !metadata.file_type().is_symlink(),
        "repository .git authority must not be a symlink"
    );
    if metadata.file_type().is_dir() {
        return root.to_path_buf();
    }
    assert!(
        metadata.file_type().is_file(),
        "linked worktree .git authority must be a regular file"
    );
    let pointer = std::fs::read_to_string(&dot_git)
        .unwrap_or_else(|error| panic!("read {}: {error}", dot_git.display()));
    let git_dir = pointer
        .trim()
        .strip_prefix("gitdir: ")
        .map(PathBuf::from)
        .expect("linked worktree .git file must contain one gitdir pointer");
    let git_dir = if git_dir.is_absolute() {
        git_dir
    } else {
        root.join(git_dir)
    };
    let worktrees_dir = git_dir
        .parent()
        .expect("linked worktree gitdir must have a worktrees parent");
    assert_eq!(
        worktrees_dir.file_name().and_then(|name| name.to_str()),
        Some("worktrees"),
        "linked worktree gitdir must be under the common .git/worktrees directory"
    );
    let common_git_dir = worktrees_dir
        .parent()
        .expect("linked worktree gitdir must have a common .git parent");
    assert_eq!(
        common_git_dir.file_name().and_then(|name| name.to_str()),
        Some(".git"),
        "linked worktree common directory must be .git"
    );
    common_git_dir
        .parent()
        .expect("common .git directory must have a repository parent")
        .to_path_buf()
}

fn read_json<T: for<'de> Deserialize<'de>>(root: &Path, relative: &str) -> T {
    let bytes = std::fs::read(root.join(relative))
        .unwrap_or_else(|error| panic!("read qualification input {relative}: {error}"));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse qualification input {relative}: {error}"))
}

fn validated_public_drawing_path(root: &Path, relative: &str) -> PathBuf {
    assert!(
        !relative.contains('\\'),
        "drawing provenance path must use repository-relative `/` separators: {relative}"
    );
    let relative_path = Path::new(relative);
    assert!(
        !relative_path.is_absolute(),
        "drawing provenance path must be relative: {relative}"
    );
    let parts = relative_path
        .components()
        .map(|component| match component {
            Component::Normal(part) => part,
            _ => panic!("drawing provenance path is not normalized: {relative}"),
        })
        .collect::<Vec<_>>();
    assert!(
        parts.len() >= 3
            && parts[0] == "tests"
            && matches!(parts[1].to_str(), Some("corpus" | "fixtures")),
        "drawing provenance path is outside the closed public fixture roots: {relative}"
    );

    let mut current = root.to_path_buf();
    for (index, part) in parts.iter().enumerate() {
        current.push(part);
        let metadata = std::fs::symlink_metadata(&current)
            .unwrap_or_else(|error| panic!("inspect drawing path {relative}: {error}"));
        assert!(
            !metadata.file_type().is_symlink(),
            "drawing provenance path must not traverse a symlink: {relative}"
        );
        if index + 1 == parts.len() {
            assert!(
                metadata.file_type().is_file(),
                "drawing provenance path must resolve to a regular file: {relative}"
            );
        } else {
            assert!(
                metadata.file_type().is_dir(),
                "drawing provenance path has a non-directory component: {relative}"
            );
        }
    }
    current
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn exact_manifest_requirement(root: &Path) -> String {
    let path = root.join("crates/autocad-reader/Cargo.toml");
    let manifest = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let mut in_dependencies = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_dependencies = line == "[dependencies]";
            continue;
        }
        if in_dependencies {
            if let Some(value) = line.strip_prefix("acadrust = \"") {
                let requirement = value
                    .strip_suffix('"')
                    .expect("acadrust requirement must be one quoted string");
                assert!(
                    requirement
                        .strip_prefix('=')
                        .is_some_and(|version| !version.is_empty()),
                    "qualification requires one exact acadrust manifest pin"
                );
                return requirement.to_string();
            }
        }
    }
    panic!("autocad-reader manifest has no selected acadrust dependency")
}

fn quoted_lock_value(section: &str, field: &str) -> String {
    let prefix = format!("{field} = \"");
    section
        .lines()
        .map(str::trim)
        .find_map(|line| {
            line.strip_prefix(&prefix)
                .and_then(|value| value.strip_suffix('"'))
        })
        .unwrap_or_else(|| panic!("acadrust lock section has no {field}"))
        .to_string()
}

fn backend_identity_from_lock(root: &Path, lock: &str) -> BackendIdentity {
    let sections = lock
        .split("[[package]]")
        .filter(|section| {
            section
                .lines()
                .map(str::trim)
                .any(|line| line == "name = \"acadrust\"")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        sections.len(),
        1,
        "Cargo.lock must contain exactly one acadrust package"
    );
    let section = sections[0];
    let identity = BackendIdentity {
        package: "acadrust",
        manifest_requirement: exact_manifest_requirement(root),
        resolved_version: quoted_lock_value(section, "version"),
        source: quoted_lock_value(section, "source"),
        checksum_sha256: quoted_lock_value(section, "checksum"),
    };
    assert_eq!(
        identity.manifest_requirement,
        format!("={}", identity.resolved_version),
        "manifest and lockfile must select the same exact backend version"
    );
    identity
}

fn backend_identity(root: &Path) -> BackendIdentity {
    let lock_path = root.join("Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", lock_path.display()));
    backend_identity_from_lock(root, &lock)
}

fn drawing_format(path: &str) -> DrawingFormat {
    match Path::new(path).extension().and_then(|value| value.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("dwg") => DrawingFormat::Dwg,
        Some(extension) if extension.eq_ignore_ascii_case("dxf") => DrawingFormat::Dxf,
        _ => panic!("drawing provenance row has unsupported format: {path}"),
    }
}

fn format_name(format: DrawingFormat) -> &'static str {
    match format {
        DrawingFormat::Dwg => "dwg",
        DrawingFormat::Dxf => "dxf",
    }
}

fn diagnostic_kind(kind: ReadDiagnosticKind) -> &'static str {
    match kind {
        ReadDiagnosticKind::NotImplemented => "not_implemented",
        ReadDiagnosticKind::NotSupported => "not_supported",
        ReadDiagnosticKind::Warning => "warning",
    }
}

fn diagnostic_record(diagnostic: &ReadDiagnostic) -> DiagnosticRecord {
    DiagnosticRecord {
        kind: diagnostic_kind(diagnostic.kind),
        message: diagnostic.message.clone(),
    }
}

fn error_kind(kind: ReadErrorKind) -> &'static str {
    match kind {
        ReadErrorKind::UnsupportedFormat => "unsupported_format",
        ReadErrorKind::NotFound => "not_found",
        ReadErrorKind::Unreadable => "unreadable",
        ReadErrorKind::InvalidDrawing => "invalid_drawing",
        ReadErrorKind::IncompleteDrawing => "incomplete_drawing",
    }
}

fn successful_interpretation(session: &DrawingReadSession) -> FixtureInterpretation {
    let diagnostics = session
        .diagnostics()
        .iter()
        .map(diagnostic_record)
        .collect();
    let block_diagnostic_gate = match session.list_blocks() {
        Ok(_) => FamilyDiagnosticGateDisposition::Accepted,
        Err(error) => FamilyDiagnosticGateDisposition::Rejected {
            code: error.code().to_string(),
            message: error.message().to_string(),
        },
    };
    let entity_diagnostic_gate = match session.ensure_entity_diagnostic_fidelity() {
        Ok(_) => FamilyDiagnosticGateDisposition::Accepted,
        Err(error) => FamilyDiagnosticGateDisposition::Rejected {
            code: error.code().to_string(),
            message: error.message().to_string(),
        },
    };
    let title_block_diagnostic_gate = match session.ensure_title_block_diagnostic_fidelity() {
        Ok(_) => FamilyDiagnosticGateDisposition::Accepted,
        Err(error) => FamilyDiagnosticGateDisposition::Rejected {
            code: error.code().to_string(),
            message: error.message().to_string(),
        },
    };
    let drawing_diagnostic_gate = match session.ensure_drawing_diagnostic_fidelity() {
        Ok(_) => FamilyDiagnosticGateDisposition::Accepted,
        Err(error) => FamilyDiagnosticGateDisposition::Rejected {
            code: error.code().to_string(),
            message: error.message().to_string(),
        },
    };
    let text_diagnostic_gate = match session.ensure_text_diagnostic_fidelity() {
        Ok(_) => FamilyDiagnosticGateDisposition::Accepted,
        Err(error) => FamilyDiagnosticGateDisposition::Rejected {
            code: error.code().to_string(),
            message: error.message().to_string(),
        },
    };
    let layout_diagnostic_gate = match session.ensure_layout_diagnostic_fidelity() {
        Ok(_) => FamilyDiagnosticGateDisposition::Accepted,
        Err(error) => FamilyDiagnosticGateDisposition::Rejected {
            code: error.code().to_string(),
            message: error.message().to_string(),
        },
    };
    let symbol_diagnostic_gate = match session.ensure_symbol_diagnostic_fidelity() {
        Ok(_) => FamilyDiagnosticGateDisposition::Accepted,
        Err(error) => FamilyDiagnosticGateDisposition::Rejected {
            code: error.code().to_string(),
            message: error.message().to_string(),
        },
    };
    let layer_diagnostic_gate = match session.ensure_layer_diagnostic_fidelity() {
        Ok(_) => FamilyDiagnosticGateDisposition::Accepted,
        Err(error) => FamilyDiagnosticGateDisposition::Rejected {
            code: error.code().to_string(),
            message: error.message().to_string(),
        },
    };
    let format_facts_diagnostic_gate = match session.ensure_format_facts_diagnostic_fidelity() {
        Ok(_) => FamilyDiagnosticGateDisposition::Accepted,
        Err(error) => FamilyDiagnosticGateDisposition::Rejected {
            code: error.code().to_string(),
            message: error.message().to_string(),
        },
    };
    FixtureInterpretation::Success {
        diagnostics,
        block_diagnostic_gate,
        entity_diagnostic_gate,
        title_block_diagnostic_gate,
        drawing_diagnostic_gate,
        text_diagnostic_gate,
        layout_diagnostic_gate,
        symbol_diagnostic_gate,
        layer_diagnostic_gate,
        format_facts_diagnostic_gate,
    }
}

fn failed_interpretation(error: ReadError) -> FixtureInterpretation {
    let diagnostics = error
        .fatal_diagnostics()
        .iter()
        .map(|diagnostic| {
            let message = diagnostic
                .strip_prefix("[Error] ")
                .unwrap_or_else(|| {
                    panic!(
                        "fatal backend diagnostic must retain the normalized error prefix: \
                         {diagnostic}"
                    )
                })
                .to_string();
            DiagnosticRecord {
                kind: "error",
                message,
            }
        })
        .collect();
    FixtureInterpretation::Error {
        error_kind: error_kind(error.kind()),
        message: error.message().to_string(),
        diagnostics,
    }
}

fn diagnostic_baseline() -> DiagnosticBaseline {
    let root = repository_root();
    let ledger: FixtureLedger = read_json(&root, FIXTURE_LEDGER_PATH);
    assert_eq!(ledger.schema_version, 1, "fixture ledger schema changed");
    assert_eq!(
        ledger.scope_roots,
        vec!["tests/corpus".to_string(), "tests/fixtures".to_string()],
        "fixture ledger scope changed"
    );
    assert!(
        !ledger.project_rights_holder.is_empty() && !ledger.project_license.is_empty(),
        "fixture ledger rights authority is incomplete"
    );
    let tier1: Tier1Manifest = read_json(&root, TIER1_MANIFEST_PATH);
    assert_eq!(tier1.schema_version, 1, "Tier-1 manifest schema changed");
    assert_eq!(tier1.tier, 1, "qualification Tier-1 authority changed");

    let mut tier1_fixtures = BTreeMap::new();
    for fixture in &tier1.fixtures {
        assert!(
            matches!(fixture.format.as_str(), "DWG" | "DXF"),
            "Tier-1 fixture has unsupported format"
        );
        assert!(
            tier1_fixtures
                .insert(
                    fixture.path.as_str(),
                    (fixture.sha256.as_str(), fixture.format.as_str()),
                )
                .is_none(),
            "Tier-1 manifest has a duplicate fixture path: {}",
            fixture.path
        );
    }
    assert_eq!(
        tier1_fixtures.len(),
        3,
        "qualification requires the closed Tier-1 fixture set"
    );

    let mut drawings = ledger
        .artifacts
        .into_iter()
        .filter(|artifact| artifact.artifact_class == "drawing")
        .collect::<Vec<_>>();
    drawings.sort_by(|left, right| left.path.cmp(&right.path));
    assert_eq!(
        drawings.len(),
        5,
        "qualification requires every provenance-ledger drawing"
    );
    let drawing_paths = drawings
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        drawing_paths.len(),
        drawings.len(),
        "fixture ledger has duplicate drawing paths"
    );
    let unmatched_tier1 = tier1_fixtures
        .keys()
        .filter(|path| !drawing_paths.contains(**path))
        .copied()
        .collect::<Vec<_>>();
    assert!(
        unmatched_tier1.is_empty(),
        "Tier-1 manifest contains drawings outside the provenance ledger: {unmatched_tier1:?}"
    );

    let fixtures = drawings
        .into_iter()
        .map(|artifact| {
            assert!(
                !artifact.license_expression.is_empty()
                    && artifact
                        .origin
                        .as_object()
                        .is_some_and(|origin| !origin.is_empty()),
                "drawing provenance is incomplete for {}",
                artifact.path
            );
            assert!(
                matches!(
                    artifact.privacy_disposition.as_str(),
                    "project_public_reviewed" | "upstream_public_metadata_reviewed"
                ),
                "drawing is not approved for public qualification evidence: {}",
                artifact.path
            );
            let drawing_path = validated_public_drawing_path(&root, &artifact.path);
            let bytes = std::fs::read(&drawing_path)
                .unwrap_or_else(|error| panic!("read {}: {error}", artifact.path));
            assert_eq!(
                sha256(&bytes),
                artifact.sha256,
                "drawing digest changed for {}",
                artifact.path
            );
            let format = drawing_format(&artifact.path);
            if let Some((tier1_sha256, tier1_format)) =
                tier1_fixtures.get(artifact.path.as_str()).copied()
            {
                assert_eq!(
                    artifact.sha256, tier1_sha256,
                    "Tier-1 and provenance digests differ for {}",
                    artifact.path
                );
                assert_eq!(
                    format_name(format).to_ascii_uppercase(),
                    tier1_format,
                    "Tier-1 and provenance formats differ for {}",
                    artifact.path
                );
            }
            let interpretation = match Reader::open_snapshot(DrawingSnapshot::new(format, bytes)) {
                Ok(session) => successful_interpretation(&session),
                Err(error) => failed_interpretation(error),
            };
            FixtureDiagnosticRecord {
                tier1: tier1_fixtures.contains_key(artifact.path.as_str()),
                path: artifact.path,
                sha256: artifact.sha256,
                format: format_name(format),
                interpretation,
            }
        })
        .collect();

    DiagnosticBaseline {
        schema_version: 6,
        report_kind: "reader_backend_diagnostic_report",
        claim_boundary: "development_evidence_only",
        backend: backend_identity(&root),
        fixture_authority: FixtureAuthority {
            path: FIXTURE_LEDGER_PATH,
            selection: "artifact_class=drawing",
        },
        fixtures,
    }
}

fn diagnostic_baseline_json() -> String {
    let mut json =
        serde_json::to_string_pretty(&diagnostic_baseline()).expect("serialize diagnostic report");
    json.push('\n');
    json
}

#[test]
fn acadrust_0_4_1_diagnostic_baseline_matches_all_provenance_drawings() {
    let actual = diagnostic_baseline_json();
    let expected =
        include_str!("../../../tests/reader-qualification/acadrust-0.4.1-diagnostic-baseline.json");
    assert!(
        !actual.contains(repository_root().to_string_lossy().as_ref()),
        "diagnostic baseline must not contain a machine-local repository path"
    );
    assert_eq!(
        actual, expected,
        "reader backend diagnostic baseline changed; inspect every dependency, fixture, \
         diagnostic, and family-disposition delta"
    );
}

#[test]
fn acadrust_0_4_1_preserves_the_0_4_0_fixture_interpretation() {
    let baseline: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reader-qualification/acadrust-0.4.0-diagnostic-baseline.json"
    ))
    .expect("parse acadrust 0.4.0 diagnostic baseline");
    let candidate: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reader-qualification/acadrust-0.4.1-on-0.4.0-fixtures.json"
    ))
    .expect("parse acadrust 0.4.1 same-fixture comparison");

    assert_eq!(
        baseline.pointer("/backend/resolved_version"),
        Some(&serde_json::json!("0.4.0"))
    );
    assert_eq!(
        candidate.pointer("/backend/resolved_version"),
        Some(&serde_json::json!("0.4.1"))
    );

    for field in [
        "schema_version",
        "report_kind",
        "claim_boundary",
        "fixture_authority",
        "fixtures",
    ] {
        assert_eq!(
            candidate.get(field),
            baseline.get(field),
            "acadrust 0.4.1 changed the reviewed {field} evidence"
        );
    }
}

#[test]
fn acadrust_0_4_1_current_fixture_diff_is_only_the_accepted_writer_bytes_and_current_family_gates()
{
    const PROJECT_FIXTURE: &str = "tests/corpus/open/project/generic-title-block-ascii.dxf";
    const OLD_SHA256: &str = "836f4733b1328dd9d72d5a35130d59b7570e329b76ad929c50bb73b26cf17d4d";
    const CURRENT_SHA256: &str = "36b87b71d61d8452cd257bb5028b8bb1d879cbda63c02c9951fb966ffa53a86f";

    let comparison: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reader-qualification/acadrust-0.4.1-on-0.4.0-fixtures.json"
    ))
    .expect("parse acadrust 0.4.1 same-fixture comparison");
    let mut current: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reader-qualification/acadrust-0.4.1-diagnostic-baseline.json"
    ))
    .expect("parse current acadrust 0.4.1 diagnostic baseline");

    assert_eq!(
        comparison.pointer("/backend/resolved_version"),
        Some(&serde_json::json!("0.4.1"))
    );
    assert_eq!(
        current.pointer("/backend/resolved_version"),
        Some(&serde_json::json!("0.4.1"))
    );
    assert_eq!(
        comparison.get("schema_version"),
        Some(&serde_json::json!(2)),
        "the same-fixture comparison retains its sealed schema-2 identity"
    );
    assert_eq!(
        current.get("schema_version"),
        Some(&serde_json::json!(6)),
        "the current report must identify all post-schema-2 family-gate additions"
    );
    current["schema_version"] = serde_json::json!(2);

    let fixtures = current
        .get_mut("fixtures")
        .and_then(serde_json::Value::as_array_mut)
        .expect("current diagnostic baseline must contain a fixture array");
    for fixture in fixtures.iter_mut() {
        let interpretation = fixture
            .get_mut("interpretation")
            .and_then(serde_json::Value::as_object_mut)
            .expect("current fixture must contain an interpretation object");
        assert!(
            interpretation.remove("entity_diagnostic_gate").is_some(),
            "every successful current interpretation must seal an entity diagnostic gate"
        );
        assert!(
            interpretation
                .remove("title_block_diagnostic_gate")
                .is_some(),
            "every successful current interpretation must seal a title-block diagnostic gate"
        );
        assert!(
            interpretation.remove("drawing_diagnostic_gate").is_some(),
            "every successful current interpretation must seal a drawing diagnostic gate"
        );
        assert!(
            interpretation.remove("text_diagnostic_gate").is_some(),
            "every successful current interpretation must seal a text diagnostic gate"
        );
        assert!(
            interpretation.remove("layout_diagnostic_gate").is_some(),
            "every successful current interpretation must seal a layout diagnostic gate"
        );
        assert!(
            interpretation.remove("symbol_diagnostic_gate").is_some(),
            "every successful current interpretation must seal a symbol diagnostic gate"
        );
        assert!(
            interpretation.remove("layer_diagnostic_gate").is_some(),
            "every successful current interpretation must seal a layer diagnostic gate"
        );
        assert!(
            interpretation
                .remove("format_facts_diagnostic_gate")
                .is_some(),
            "every successful current interpretation must seal a format-facts diagnostic gate"
        );
    }
    let matching = fixtures
        .iter_mut()
        .filter(|fixture| fixture.get("path") == Some(&serde_json::json!(PROJECT_FIXTURE)))
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "current baseline must contain exactly one project fixture"
    );
    let project = matching.into_iter().next().expect("one project fixture");
    assert_eq!(
        project.get("sha256"),
        Some(&serde_json::json!(CURRENT_SHA256))
    );
    project["sha256"] = serde_json::json!(OLD_SHA256);

    assert_eq!(
        current, comparison,
        "current 0.4.1 evidence may differ from the sealed schema-2 same-fixture comparison only by the accepted project-fixture writer bytes and the reviewed current family gates"
    );
}

#[test]
fn current_entity_diagnostic_gate_dispositions_are_exact() {
    const DIAGNOSTIC_DXF: &str =
        "tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dxf";
    let current: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reader-qualification/acadrust-0.4.1-diagnostic-baseline.json"
    ))
    .expect("parse current acadrust 0.4.1 diagnostic baseline");
    assert_eq!(current.get("schema_version"), Some(&serde_json::json!(6)));

    let fixtures = current
        .get("fixtures")
        .and_then(serde_json::Value::as_array)
        .expect("current diagnostic baseline must contain a fixture array");
    assert_eq!(fixtures.len(), 5);
    for fixture in fixtures {
        let path = fixture
            .get("path")
            .and_then(serde_json::Value::as_str)
            .expect("qualification fixture must contain a path");
        let gate = fixture
            .pointer("/interpretation/entity_diagnostic_gate")
            .unwrap_or_else(|| panic!("qualification fixture has no entity gate: {path}"));
        if path == DIAGNOSTIC_DXF {
            assert_eq!(
                gate,
                &serde_json::json!({
                    "status": "rejected",
                    "code": "unsupported_entity_data",
                    "message": "reader reported an unsupported diagnostic that may affect entity interpretation"
                })
            );
        } else {
            assert_eq!(gate, &serde_json::json!({"status": "accepted"}));
        }
    }
}

#[test]
fn current_title_block_diagnostic_gate_dispositions_are_exact() {
    const DIAGNOSTIC_DXF: &str =
        "tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dxf";
    let current: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reader-qualification/acadrust-0.4.1-diagnostic-baseline.json"
    ))
    .expect("parse current acadrust 0.4.1 diagnostic baseline");
    assert_eq!(current.get("schema_version"), Some(&serde_json::json!(6)));

    let fixtures = current
        .get("fixtures")
        .and_then(serde_json::Value::as_array)
        .expect("current diagnostic baseline must contain a fixture array");
    assert_eq!(fixtures.len(), 5);
    for fixture in fixtures {
        let path = fixture
            .get("path")
            .and_then(serde_json::Value::as_str)
            .expect("qualification fixture must contain a path");
        let gate = fixture
            .pointer("/interpretation/title_block_diagnostic_gate")
            .unwrap_or_else(|| panic!("qualification fixture has no title-block gate: {path}"));
        if path == DIAGNOSTIC_DXF {
            assert_eq!(
                gate,
                &serde_json::json!({
                    "status": "rejected",
                    "code": "unsupported_title_block_data",
                    "message": "reader reported an unsupported diagnostic that may affect title-block interpretation"
                })
            );
        } else {
            assert_eq!(gate, &serde_json::json!({"status": "accepted"}));
        }
    }
}

#[test]
fn current_drawing_diagnostic_gate_dispositions_are_exact() {
    assert_current_family_gate_dispositions(
        "drawing_diagnostic_gate",
        "unsupported_drawing_data",
        "reader reported an unsupported diagnostic that may affect drawing interpretation",
    );
}

#[test]
fn current_text_diagnostic_gate_dispositions_are_exact() {
    assert_current_family_gate_dispositions(
        "text_diagnostic_gate",
        "unsupported_text_data",
        "reader reported an unsupported diagnostic that may affect text interpretation",
    );
}

#[test]
fn current_layout_diagnostic_gate_dispositions_are_exact() {
    assert_current_family_gate_dispositions(
        "layout_diagnostic_gate",
        "unsupported_layout_data",
        "reader reported an unsupported diagnostic that may affect layout interpretation",
    );
}

#[test]
fn current_symbol_diagnostic_gate_dispositions_are_exact() {
    assert_current_family_gate_dispositions(
        "symbol_diagnostic_gate",
        "unsupported_symbol_data",
        "reader reported an unsupported diagnostic that may affect symbol interpretation",
    );
}

#[test]
fn current_layer_diagnostic_gate_dispositions_are_exact() {
    assert_current_family_gate_dispositions(
        "layer_diagnostic_gate",
        "unsupported_layer_data",
        "reader reported an unsupported diagnostic that may affect layer interpretation",
    );
}

#[test]
fn current_format_facts_diagnostic_gate_dispositions_are_exact() {
    assert_current_family_gate_dispositions(
        "format_facts_diagnostic_gate",
        "unsupported_format_facts_data",
        "reader reported an unsupported diagnostic that may affect drawing format facts",
    );
}

fn assert_current_family_gate_dispositions(field: &str, code: &str, message: &str) {
    const DIAGNOSTIC_DXF: &str =
        "tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dxf";
    let current: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reader-qualification/acadrust-0.4.1-diagnostic-baseline.json"
    ))
    .expect("parse current acadrust 0.4.1 diagnostic baseline");
    assert_eq!(current.get("schema_version"), Some(&serde_json::json!(6)));

    let fixtures = current
        .get("fixtures")
        .and_then(serde_json::Value::as_array)
        .expect("current diagnostic baseline must contain a fixture array");
    assert_eq!(fixtures.len(), 5);
    for fixture in fixtures {
        let path = fixture
            .get("path")
            .and_then(serde_json::Value::as_str)
            .expect("qualification fixture must contain a path");
        let gate = fixture
            .pointer(&format!("/interpretation/{field}"))
            .unwrap_or_else(|| panic!("qualification fixture has no {field}: {path}"));
        if path == DIAGNOSTIC_DXF {
            assert_eq!(
                gate,
                &serde_json::json!({
                    "status": "rejected",
                    "code": code,
                    "message": message,
                })
            );
        } else {
            assert_eq!(gate, &serde_json::json!({"status": "accepted"}));
        }
    }
}

#[test]
fn diagnostic_baseline_dependency_identity_matches_exact_manifest_and_selected_lock_package() {
    let identity = backend_identity(&repository_root());
    assert_eq!(identity.manifest_requirement, "=0.4.1");
    assert_eq!(identity.resolved_version, "0.4.1");
    assert_eq!(
        identity.source,
        "registry+https://github.com/rust-lang/crates.io-index"
    );
    assert_eq!(
        identity.checksum_sha256,
        "d96c49ac7520273f8fb65865995efca78f5d75fdaf11d3ba3c87114f6496b941"
    );
}

#[test]
fn diagnostic_baseline_dependency_identity_ignores_unrelated_lock_packages() {
    let root = repository_root();
    let lock_path = root.join("Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", lock_path.display()));
    let identity = backend_identity_from_lock(&root, &lock);
    let unrelated_package = r#"

[[package]]
name = "qualification-unrelated-package"
version = "1.0.0"
"#;
    assert_eq!(
        backend_identity_from_lock(&root, &format!("{lock}{unrelated_package}")),
        identity,
        "an unrelated workspace lock package must not invalidate reader qualification"
    );
}

#[test]
#[ignore = "writes a new reviewed report only to an explicit shared-target path"]
fn emit_diagnostic_report_for_review() {
    let root = repository_root();
    let approved_target = primary_repository_root(&root).join(".cargo-target");
    let target_metadata = std::fs::symlink_metadata(&approved_target).unwrap_or_else(|error| {
        panic!(
            "approved shared target {} must already exist: {error}",
            approved_target.display()
        )
    });
    assert!(
        target_metadata.file_type().is_dir() && !target_metadata.file_type().is_symlink(),
        "approved shared target must be a non-symlink directory"
    );

    let report_dir = approved_target.join("reader-qualification");
    match std::fs::create_dir(&report_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => panic!("create {}: {error}", report_dir.display()),
    }
    let report_dir_metadata = std::fs::symlink_metadata(&report_dir)
        .unwrap_or_else(|error| panic!("inspect {}: {error}", report_dir.display()));
    assert!(
        report_dir_metadata.file_type().is_dir() && !report_dir_metadata.file_type().is_symlink(),
        "qualification report directory must be a non-symlink directory"
    );

    let output = std::env::var_os("AUTOCAD_READER_QUALIFICATION_OUTPUT")
        .map(PathBuf::from)
        .expect("set AUTOCAD_READER_QUALIFICATION_OUTPUT to a new absolute report path");
    assert!(
        output.is_absolute()
            && output.parent() == Some(report_dir.as_path())
            && output.extension().and_then(|extension| extension.to_str()) == Some("json"),
        "qualification output must be one JSON file directly under {}",
        report_dir.display()
    );
    assert!(
        output.components().all(|component| matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::Normal(_)
        )),
        "qualification output path must be normalized"
    );

    let report = diagnostic_baseline_json();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .unwrap_or_else(|error| {
            panic!(
                "create new qualification report {} without overwriting: {error}",
                output.display()
            )
        });
    file.write_all(report.as_bytes())
        .unwrap_or_else(|error| panic!("write qualification report {}: {error}", output.display()));
    file.sync_all()
        .unwrap_or_else(|error| panic!("sync qualification report {}: {error}", output.display()));
}
