use acadrust::entities::{AttributeEntity, EntityType, Insert};
use acadrust::types::Vector3;
use acadrust::{DwgWriter, DxfWriter};
#[cfg(target_os = "windows")]
use autocad_mcp::engine;
use autocad_mcp::ops::{dxf_patch, profiles, survey, title_blocks};
use autocad_mcp::reader::open_drawing;
use autocad_mcp::server::{AutocadServer, ReadTitleBlocksParams, TitleBlockAttributeValueMode};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::RawContent;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

const TIER1_MANIFEST: &str = "tests/corpus/open/manifest.json";
const FIXTURE_PROVENANCE_LEDGER: &str = "tests/fixture-provenance.json";
const TITLE_BLOCK_DIAGNOSTIC_FIXTURE: &str =
    "tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dxf";
const PROJECT_PROFILE_FIXTURE: &str = "tests/corpus/open/project/generic-title-block-ascii.dxf";
const PROJECT_PROFILE_0_4_0_SHA256: &str =
    "836f4733b1328dd9d72d5a35130d59b7570e329b76ad929c50bb73b26cf17d4d";
const PROJECT_PROFILE_0_4_1_SHA256: &str =
    "36b87b71d61d8452cd257bb5028b8bb1d879cbda63c02c9951fb966ffa53a86f";
const PROJECT_PROFILE_ID: &str = "AUTOCAD_MCP_GENERIC";
const PROJECT_RIGHTS_HOLDER: &str = "andagni";
const PROJECT_LICENSE: &str = "GPL-3.0-or-later";
const ACADSHARP_REPOSITORY: &str = "https://github.com/DomCR/ACadSharp";
const ACADSHARP_REVISION: &str = "b7fa6a99c2399b71931d7591a3eded99f6a958ad";
const ACADSHARP_LICENSE_PATH: &str = "tests/corpus/open/acadsharp/LICENSE";
const ACADSHARP_LICENSE_SHA256: &str =
    "3ca5f3195b1f3056543596f7bb413bb143484c53ca9def699af8f7964f509190";
const PROJECT_AUTHORED_DOCUMENT_PATHS: [&str; 5] = [
    "tests/corpus/autodesk/SOURCES.md",
    "tests/corpus/civil3d/SOURCES.md",
    "tests/corpus/open/SOURCES.md",
    "tests/fixtures/xrefs/README.md",
    "tests/fixtures/xrefs/graph/README.md",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tier1Manifest {
    schema_version: u32,
    tier: usize,
    fixtures: Vec<Tier1Fixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tier1Fixture {
    path: String,
    sha256: String,
    format: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureProvenanceLedger {
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
    artifact_class: FixtureArtifactClass,
    license_expression: String,
    privacy_disposition: FixturePrivacyDisposition,
    origin: FixtureOrigin,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FixtureArtifactClass {
    Documentation,
    Drawing,
    LicenseNotice,
    MachineReadableContract,
    Schema,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FixturePrivacyDisposition {
    ProjectPublicReviewed,
    UpstreamPublicMetadataReviewed,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum FixtureOrigin {
    ProjectAuthored,
    HandAuthoredFromLocalContract {
        contract_path: String,
        contract_locator: String,
    },
    LocalSchemaProjection {
        source_path: String,
        source_locator: String,
    },
    GeneratedByCheckedInRecipe {
        recipe_path: String,
        recipe_id: String,
        exact_byte_test_path: String,
        exact_byte_test_id: String,
    },
    UpstreamExact {
        repository: String,
        revision: String,
        source_path: String,
        retained_license_path: String,
        retained_license_sha256: String,
    },
}

#[derive(Debug, Serialize)]
struct CorpusRecord {
    file: String,
    tier: usize,
    format: String,
    acadrust_read_ok: bool,
    acadrust_write_ok: bool,
    accoreconsole_audit: String, // "passed", "failed", "skipped"
    orig_entities: BTreeMap<String, usize>,
    rt_entities: BTreeMap<String, usize>,
    surviving_entities: Vec<String>,
    orig_layers: Vec<String>,
    rt_layers: Vec<String>,
    block_names: Vec<String>,
    title_block_attributes: BTreeMap<String, Vec<String>>,
    passed: bool,
    error_message: Option<String>,
}

fn get_entity_type_name(entity: &EntityType) -> String {
    let debug_str = format!("{:?}", entity);
    if let Some(pos) = debug_str.find('(') {
        debug_str[..pos].trim().to_string()
    } else if let Some(pos) = debug_str.find('{') {
        debug_str[..pos].trim().to_string()
    } else {
        debug_str
    }
}

fn count_entities(doc: &acadrust::CadDocument) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for ent in doc.entities() {
        let name = get_entity_type_name(ent);
        *counts.entry(name).or_insert(0) += 1;
    }
    counts
}

fn get_layers(doc: &acadrust::CadDocument) -> Vec<String> {
    let mut layers: Vec<String> = doc.layers.iter().map(|l| l.name.clone()).collect();
    layers.sort();
    layers
}

fn get_block_names(doc: &acadrust::CadDocument) -> Vec<String> {
    let mut blocks: Vec<String> = doc
        .block_records
        .iter()
        .filter(|br| !br.name.starts_with('*'))
        .map(|br| br.name.clone())
        .collect();
    blocks.sort();
    blocks
}

fn get_title_block_attributes(doc: &acadrust::CadDocument) -> BTreeMap<String, Vec<String>> {
    let mut title_blocks = BTreeMap::new();
    for e in doc.entities() {
        if let EntityType::Insert(ins) = e {
            if !ins.attributes.is_empty() {
                let mut tags: Vec<String> = ins
                    .attributes
                    .iter()
                    .map(|a| a.tag.to_uppercase())
                    .collect();
                tags.sort();
                tags.dedup();
                title_blocks.insert(ins.block_name.clone(), tags);
            }
        }
    }
    title_blocks
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate must be inside the workspace")
        .to_path_buf()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn is_exact_reviewed_acadsharp_mapping(artifact: &FixtureArtifact, source_path: &str) -> bool {
    match artifact.path.as_str() {
        "tests/corpus/open/acadsharp/LICENSE" => {
            artifact.sha256 == ACADSHARP_LICENSE_SHA256
                && artifact.artifact_class == FixtureArtifactClass::LicenseNotice
                && source_path == "LICENSE"
        }
        "tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dwg" => {
            artifact.sha256 == "be1e24ea0cd5194d0c57935b5018123b7cc981331172a1a2ca7cecc2d9a18e4f"
                && artifact.artifact_class == FixtureArtifactClass::Drawing
                && source_path == "samples/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dwg"
        }
        "tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dxf" => {
            artifact.sha256 == "c615664945db8ccc91b55f77e6359a15da4f7e6f30dbd8800d2d2b94029dffac"
                && artifact.artifact_class == FixtureArtifactClass::Drawing
                && source_path == "samples/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dxf"
        }
        _ => false,
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_normalized_relative_path(path: &str) -> bool {
    let candidate = Path::new(path);
    !candidate.is_absolute()
        && !path.contains('\\')
        && candidate
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn validate_evidence_locator(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > 256
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} must be nonempty, trimmed, control-free text of at most 256 bytes"
        ));
    }
    Ok(())
}

fn fixture_git_command(workspace_root: &Path) -> Command {
    let inherited_environment = [
        ("PATH", std::env::var_os("PATH")),
        ("SystemRoot", std::env::var_os("SystemRoot")),
        ("WINDIR", std::env::var_os("WINDIR")),
        ("TMPDIR", std::env::var_os("TMPDIR")),
        ("TMP", std::env::var_os("TMP")),
        ("TEMP", std::env::var_os("TEMP")),
    ];
    let mut command = Command::new("git");
    command.env_clear().current_dir(workspace_root);
    for (name, value) in inherited_environment {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
    command
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

fn publication_fixture_paths(workspace_root: &Path) -> Result<Vec<String>, String> {
    let output = fixture_git_command(workspace_root)
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "tests/corpus",
            "tests/fixtures",
        ])
        .output()
        .map_err(|error| format!("enumerate publication fixture paths: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files failed while enumerating publication fixtures: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let mut paths = BTreeSet::new();
    for bytes in output.stdout.split(|byte| *byte == 0) {
        if bytes.is_empty() {
            continue;
        }
        let relative = std::str::from_utf8(bytes)
            .map_err(|_| "publication fixture path is not UTF-8".to_string())?;
        let absolute = workspace_root.join(relative);
        let metadata = match std::fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "inspect publication fixture candidate '{relative}': {error}"
                ))
            }
        };
        if metadata.file_type().is_dir()
            || Path::new(relative)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
        {
            continue;
        }
        paths.insert(relative.to_string());
    }
    Ok(paths.into_iter().collect())
}

fn validate_fixture_provenance(
    workspace_root: &Path,
    ledger: &FixtureProvenanceLedger,
) -> Result<(), String> {
    if ledger.schema_version != 1 {
        return Err(format!(
            "unsupported fixture provenance schema_version {}; expected 1",
            ledger.schema_version
        ));
    }
    if ledger.scope_roots != ["tests/corpus", "tests/fixtures"] {
        return Err(format!(
            "fixture provenance scope_roots must be the exact closed pair tests/corpus and tests/fixtures: {:?}",
            ledger.scope_roots
        ));
    }
    if ledger.project_rights_holder != PROJECT_RIGHTS_HOLDER {
        return Err(format!(
            "fixture provenance project_rights_holder must be '{PROJECT_RIGHTS_HOLDER}'"
        ));
    }
    if ledger.project_license != PROJECT_LICENSE {
        return Err(format!(
            "fixture provenance project_license must be '{PROJECT_LICENSE}'"
        ));
    }
    if ledger.artifacts.is_empty() {
        return Err("fixture provenance ledger must not be empty".to_string());
    }

    let declared_paths: Vec<_> = ledger
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect();
    if !declared_paths.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(
            "fixture provenance artifact paths must be unique and strictly sorted".to_string(),
        );
    }
    let publication_paths = publication_fixture_paths(workspace_root)?;
    if declared_paths != publication_paths {
        return Err(format!(
            "fixture provenance inventory does not equal admitted non-Rust bytes below the closed roots: declared {declared_paths:?}, admitted {publication_paths:?}"
        ));
    }
    let project_authored_paths = ledger
        .artifacts
        .iter()
        .filter(|artifact| matches!(&artifact.origin, FixtureOrigin::ProjectAuthored))
        .map(|artifact| artifact.path.as_str())
        .collect::<Vec<_>>();
    if project_authored_paths != PROJECT_AUTHORED_DOCUMENT_PATHS {
        return Err(format!(
            "project_authored provenance must be used by the exact closed project documentation set: expected {PROJECT_AUTHORED_DOCUMENT_PATHS:?}, got {project_authored_paths:?}"
        ));
    }

    for artifact in &ledger.artifacts {
        if !is_normalized_relative_path(&artifact.path)
            || !(artifact.path.starts_with("tests/corpus/")
                || artifact.path.starts_with("tests/fixtures/"))
        {
            return Err(format!(
                "fixture provenance path is outside the closed normalized roots: '{}'",
                artifact.path
            ));
        }
        if !is_lowercase_sha256(&artifact.sha256) {
            return Err(format!(
                "fixture provenance SHA-256 is not canonical for '{}'",
                artifact.path
            ));
        }

        let absolute = workspace_root.join(&artifact.path);
        let metadata = std::fs::symlink_metadata(&absolute).map_err(|error| {
            format!(
                "fixture provenance artifact '{}' is missing or unreadable: {error}",
                artifact.path
            )
        })?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "fixture provenance artifact '{}' is not a regular file",
                artifact.path
            ));
        }
        let bytes = std::fs::read(&absolute)
            .map_err(|error| format!("read fixture artifact '{}': {error}", artifact.path))?;
        let actual_sha256 = sha256_hex(&bytes);
        if actual_sha256 != artifact.sha256 {
            return Err(format!(
                "fixture provenance SHA-256 mismatch for '{}': expected {}, got {actual_sha256}",
                artifact.path, artifact.sha256
            ));
        }
        match artifact.artifact_class {
            FixtureArtifactClass::Documentation if !artifact.path.ends_with(".md") => {
                return Err(format!(
                    "documentation fixture '{}' must have a .md extension",
                    artifact.path
                ));
            }
            FixtureArtifactClass::Drawing
                if !artifact.path.ends_with(".dwg") && !artifact.path.ends_with(".dxf") =>
            {
                return Err(format!(
                    "drawing fixture '{}' must have a lowercase .dwg or .dxf extension",
                    artifact.path
                ));
            }
            FixtureArtifactClass::LicenseNotice
                if Path::new(&artifact.path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    != Some("LICENSE") =>
            {
                return Err(format!(
                    "license-notice fixture '{}' must use the exact filename LICENSE",
                    artifact.path
                ));
            }
            FixtureArtifactClass::Schema
                if !artifact.path.ends_with(".schema.json")
                    && !artifact.path.ends_with(".schema.yaml") =>
            {
                return Err(format!(
                    "schema fixture '{}' must use .schema.json or .schema.yaml",
                    artifact.path
                ));
            }
            _ => {}
        }

        match &artifact.origin {
            FixtureOrigin::ProjectAuthored => {
                if artifact.artifact_class != FixtureArtifactClass::Documentation
                    || artifact.license_expression != PROJECT_LICENSE
                    || artifact.privacy_disposition
                        != FixturePrivacyDisposition::ProjectPublicReviewed
                    || !PROJECT_AUTHORED_DOCUMENT_PATHS.contains(&artifact.path.as_str())
                {
                    return Err(format!(
                        "project-authored fixture '{}' is outside the exact reviewed documentation boundary",
                        artifact.path
                    ));
                }
            }
            FixtureOrigin::HandAuthoredFromLocalContract {
                contract_path,
                contract_locator,
            } => {
                if artifact.license_expression != PROJECT_LICENSE
                    || artifact.privacy_disposition
                        != FixturePrivacyDisposition::ProjectPublicReviewed
                {
                    return Err(format!(
                        "project fixture '{}' must use the project licence and reviewed-project privacy disposition",
                        artifact.path
                    ));
                }
                validate_fixture_authority(
                    workspace_root,
                    contract_path,
                    contract_locator,
                    "local contract",
                )?;
            }
            FixtureOrigin::LocalSchemaProjection {
                source_path,
                source_locator,
            } => {
                if artifact.license_expression != PROJECT_LICENSE
                    || artifact.privacy_disposition
                        != FixturePrivacyDisposition::ProjectPublicReviewed
                {
                    return Err(format!(
                        "local schema projection '{}' must use the project licence and reviewed-project privacy disposition",
                        artifact.path
                    ));
                }
                validate_fixture_authority(
                    workspace_root,
                    source_path,
                    source_locator,
                    "local schema source",
                )?;
            }
            FixtureOrigin::GeneratedByCheckedInRecipe {
                recipe_path,
                recipe_id,
                exact_byte_test_path,
                exact_byte_test_id,
            } => {
                if artifact.license_expression != PROJECT_LICENSE
                    || artifact.privacy_disposition
                        != FixturePrivacyDisposition::ProjectPublicReviewed
                {
                    return Err(format!(
                        "generated fixture '{}' must use the project licence and reviewed-project privacy disposition",
                        artifact.path
                    ));
                }
                validate_fixture_authority(workspace_root, recipe_path, recipe_id, "recipe")?;
                validate_fixture_authority(
                    workspace_root,
                    exact_byte_test_path,
                    exact_byte_test_id,
                    "exact-byte recipe test",
                )?;
            }
            FixtureOrigin::UpstreamExact {
                repository,
                revision,
                source_path,
                retained_license_path,
                retained_license_sha256,
            } => {
                if artifact.license_expression != "MIT"
                    || artifact.privacy_disposition
                        != FixturePrivacyDisposition::UpstreamPublicMetadataReviewed
                    || repository != ACADSHARP_REPOSITORY
                    || revision != ACADSHARP_REVISION
                    || retained_license_path != ACADSHARP_LICENSE_PATH
                    || retained_license_sha256 != ACADSHARP_LICENSE_SHA256
                    || !is_exact_reviewed_acadsharp_mapping(artifact, source_path)
                {
                    return Err(format!(
                        "upstream fixture '{}' is outside the exact reviewed ACadSharp provenance boundary",
                        artifact.path
                    ));
                }
                let license_bytes = std::fs::read(workspace_root.join(retained_license_path))
                    .map_err(|error| {
                        format!("read retained upstream licence '{retained_license_path}': {error}")
                    })?;
                if sha256_hex(&license_bytes) != *retained_license_sha256 {
                    return Err(format!(
                        "retained upstream licence digest drifted for '{}'",
                        artifact.path
                    ));
                }
            }
        }
    }

    Ok(())
}

fn validate_fixture_authority(
    workspace_root: &Path,
    relative_path: &str,
    locator: &str,
    label: &str,
) -> Result<(), String> {
    if !is_normalized_relative_path(relative_path) {
        return Err(format!(
            "fixture {label} path must be normalized and repository-relative: '{relative_path}'"
        ));
    }
    let metadata =
        std::fs::symlink_metadata(workspace_root.join(relative_path)).map_err(|error| {
            format!("fixture {label} path '{relative_path}' is missing or unreadable: {error}")
        })?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "fixture {label} path '{relative_path}' is not a regular file"
        ));
    }
    validate_evidence_locator(&format!("fixture {label} locator"), locator)?;
    let bytes = std::fs::read(workspace_root.join(relative_path))
        .map_err(|error| format!("read fixture {label} path '{relative_path}': {error}"))?;
    if !bytes
        .windows(locator.len())
        .any(|window| window == locator.as_bytes())
    {
        return Err(format!(
            "fixture {label} locator '{locator}' is not present in '{relative_path}'"
        ));
    }
    Ok(())
}

fn load_fixture_provenance(workspace_root: &Path) -> Result<FixtureProvenanceLedger, String> {
    let ledger_path = workspace_root.join(FIXTURE_PROVENANCE_LEDGER);
    let bytes = std::fs::read(&ledger_path).map_err(|error| {
        format!(
            "required fixture provenance ledger '{}' is missing or unreadable: {error}",
            ledger_path.display()
        )
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid fixture provenance ledger: {error}"))
}

fn validate_tier1_manifest(
    workspace_root: &Path,
    manifest: &Tier1Manifest,
) -> Result<Vec<PathBuf>, String> {
    if manifest.schema_version != 1 {
        return Err(format!(
            "unsupported Tier-1 manifest schema_version {}; expected 1",
            manifest.schema_version
        ));
    }
    if manifest.tier != 1 {
        return Err(format!(
            "Tier-1 manifest declares tier {}; expected 1",
            manifest.tier
        ));
    }
    if manifest.fixtures.is_empty() {
        return Err("Tier-1 manifest must contain at least one fixture".to_string());
    }

    let declared_paths: Vec<_> = manifest
        .fixtures
        .iter()
        .map(|fixture| fixture.path.as_str())
        .collect();
    let mut sorted_paths = declared_paths.clone();
    sorted_paths.sort_unstable();
    if declared_paths != sorted_paths {
        return Err("Tier-1 manifest fixture paths must be sorted".to_string());
    }

    let mut seen = BTreeSet::new();
    let mut paths = Vec::with_capacity(manifest.fixtures.len());
    for fixture in &manifest.fixtures {
        if !seen.insert(fixture.path.as_str()) {
            return Err(format!(
                "Tier-1 manifest contains duplicate path '{}'",
                fixture.path
            ));
        }

        let relative = Path::new(&fixture.path);
        if relative.is_absolute()
            || !relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
            || !relative.starts_with("tests/corpus/open")
        {
            return Err(format!(
                "Tier-1 fixture path must be a normalized path below tests/corpus/open: '{}'",
                fixture.path
            ));
        }

        let extension = relative
            .extension()
            .and_then(|extension| extension.to_str())
            .ok_or_else(|| format!("Tier-1 fixture has no UTF-8 extension: '{}'", fixture.path))?;
        let expected_extension = fixture.format.to_ascii_lowercase();
        if !matches!(fixture.format.as_str(), "DWG" | "DXF") || extension != expected_extension {
            return Err(format!(
                "Tier-1 fixture '{}' has format '{}' inconsistent with its required lowercase extension",
                fixture.path, fixture.format
            ));
        }
        if fixture.sha256.len() != 64
            || !fixture
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!(
                "Tier-1 fixture '{}' has a malformed lowercase SHA-256 digest",
                fixture.path
            ));
        }

        let absolute = workspace_root.join(relative);
        let metadata = std::fs::symlink_metadata(&absolute).map_err(|error| {
            format!(
                "required Tier-1 fixture '{}' is missing or unreadable: {error}",
                fixture.path
            )
        })?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "required Tier-1 fixture '{}' is not a regular file",
                fixture.path
            ));
        }
        let bytes = std::fs::read(&absolute).map_err(|error| {
            format!(
                "required Tier-1 fixture '{}' cannot be read: {error}",
                fixture.path
            )
        })?;
        let actual = sha256_hex(&bytes);
        if actual != fixture.sha256 {
            return Err(format!(
                "required Tier-1 fixture '{}' SHA-256 mismatch: expected {}, got {actual}",
                fixture.path, fixture.sha256
            ));
        }
        paths.push(absolute);
    }

    Ok(paths)
}

fn load_tier1_fixture_paths(workspace_root: &Path) -> Result<Vec<PathBuf>, String> {
    let manifest_path = workspace_root.join(TIER1_MANIFEST);
    let text = std::fs::read_to_string(&manifest_path).map_err(|error| {
        format!(
            "required Tier-1 manifest '{}' is missing or unreadable: {error}",
            manifest_path.display()
        )
    })?;
    let manifest: Tier1Manifest =
        serde_json::from_str(&text).map_err(|error| format!("invalid Tier-1 manifest: {error}"))?;
    validate_tier1_manifest(workspace_root, &manifest)
}

fn discover_drawings(
    workspace_root: &Path,
    directory: &str,
    tier: usize,
) -> Result<Vec<PathBuf>, String> {
    let directory_path = workspace_root.join(directory);
    if !directory_path.exists() {
        return Ok(Vec::new());
    }
    if !directory_path.is_dir() {
        return Err(format!(
            "Tier {tier} corpus path {} is not a directory",
            directory_path.display()
        ));
    }

    let mut paths = Vec::new();
    for entry in WalkDir::new(&directory_path) {
        let entry = entry.map_err(|error| {
            format!(
                "failed to traverse Tier {tier} corpus directory {}: {error}",
                directory_path.display()
            )
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let extension = entry
            .path()
            .extension()
            .and_then(|extension| extension.to_str());
        if extension.is_some_and(|extension| {
            extension.eq_ignore_ascii_case("dwg") || extension.eq_ignore_ascii_case("dxf")
        }) {
            paths.push(entry.into_path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn run_audit_check(temp_path: &Path) -> Result<(), String> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = temp_path;
        Err("accoreconsole is Windows-only; not supported on this platform".to_string())
    }

    #[cfg(target_os = "windows")]
    {
        let exe = match engine::find_accoreconsole() {
            Ok(p) => p,
            Err(e) => return Err(format!("accoreconsole not found: {e}")),
        };
        let staging = match engine::create_staging_dir() {
            Ok(d) => d,
            Err(e) => return Err(format!("failed to create staging directory: {e}")),
        };
        let staging_path = staging.path();

        let scr_content = "(setvar \"SECURELOAD\" 0)\n\
                           (setvar \"FILEDIA\" 0)(setvar \"CMDDIA\" 0)\n\
                           _.AUDIT\n\
                           Y\n\
                           QUIT\n\
                           Y\n";
        let scr_path = staging_path.join("audit.scr");
        if let Err(e) = std::fs::write(&scr_path, scr_content) {
            return Err(format!("failed to write script: {e}"));
        }

        let output = match engine::run_accoreconsole(&exe, temp_path, &scr_path, staging_path) {
            Ok(out) => out,
            Err(e) => return Err(format!("failed to run accoreconsole: {e}")),
        };

        // Parse audit output
        let mut found_summary = false;
        let mut total_errors = 0;
        for line in output.lines() {
            let lower = line.to_lowercase();
            if lower.contains("errors found during audit") {
                found_summary = true;
                if let Some(audit_pos) = lower.find("audit") {
                    let rest = &line[audit_pos + 5..];
                    let num_str: String = rest
                        .chars()
                        .skip_while(|c| !c.is_numeric())
                        .take_while(|c| c.is_numeric())
                        .collect();
                    if let Ok(err_val) = num_str.parse::<usize>() {
                        total_errors = err_val;
                    } else {
                        // fallback search
                        let numbers: Vec<usize> = line
                            .split(|c: char| !c.is_numeric())
                            .filter_map(|w| w.parse().ok())
                            .collect();
                        if !numbers.is_empty() {
                            total_errors = numbers[0];
                        }
                    }
                }
            }
        }

        if total_errors > 0 {
            return Err(format!(
                "Audit failed with {} errors: {}",
                total_errors, output
            ));
        }

        Ok(())
    }
}

fn run_file_validation(file_path: &Path, record: &mut CorpusRecord) -> Result<(), String> {
    // 1. Read with acadrust
    let doc_orig = match open_drawing(file_path) {
        Ok(doc) => doc,
        Err(e) => return Err(format!("acadrust failed to read: {e:?}")),
    };
    record.acadrust_read_ok = true;

    // Collect original details
    record.orig_entities = count_entities(&doc_orig);
    record.orig_layers = get_layers(&doc_orig);
    record.block_names = get_block_names(&doc_orig);
    record.title_block_attributes = get_title_block_attributes(&doc_orig);

    // 2. Write back to a temp file
    let temp_dir = tempfile::tempdir().map_err(|e| format!("failed to create temp dir: {e}"))?;
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let temp_path = temp_dir.path().join(format!("roundtrip.{}", ext));

    if ext == "dxf" {
        DxfWriter::new(&doc_orig)
            .write_to_file(&temp_path)
            .map_err(|e| format!("DxfWriter failed to write: {e}"))?;
    } else if ext == "dwg" {
        DwgWriter::write_to_file(&temp_path, &doc_orig)
            .map_err(|e| format!("DwgWriter failed to write: {e}"))?;
    } else {
        return Err(format!("Unsupported format: {ext}"));
    }
    record.acadrust_write_ok = true;

    // Read the temp file back with acadrust to do the diff
    let doc_rt = match open_drawing(&temp_path) {
        Ok(doc) => doc,
        Err(e) => {
            return Err(format!(
                "acadrust failed to read back the round-tripped file: {e:?}"
            ))
        }
    };
    record.rt_entities = count_entities(&doc_rt);
    record.rt_layers = get_layers(&doc_rt);

    // Calculate surviving entities
    let mut surviving = Vec::new();
    for (k, v) in &record.orig_entities {
        let rt_count = record.rt_entities.get(k).copied().unwrap_or(0);
        if *v > 0 && rt_count > 0 {
            surviving.push(k.clone());
        }
    }
    surviving.sort();
    record.surviving_entities = surviving;

    // 3. Read the temp file with accoreconsole if supported/available
    match run_audit_check(&temp_path) {
        Ok(()) => {
            record.accoreconsole_audit = "passed".to_string();
        }
        Err(e) => {
            if e.contains("accoreconsole is Windows-only") || e.contains("accoreconsole not found")
            {
                record.accoreconsole_audit = "skipped".to_string();
            } else {
                record.accoreconsole_audit = "failed".to_string();
                return Err(format!("accoreconsole audit failed: {e}"));
            }
        }
    }

    // 4. Diff entity count and layer table between original and round-tripped file
    let mut diffs = Vec::new();
    // Entity diff
    for (k, v) in &record.orig_entities {
        let rt_v = record.rt_entities.get(k).copied().unwrap_or(0);
        if *v != rt_v {
            diffs.push(format!(
                "Entity type {}: original has {}, round-tripped has {}",
                k, v, rt_v
            ));
        }
    }
    for (k, v) in &record.rt_entities {
        if !record.orig_entities.contains_key(k) {
            diffs.push(format!(
                "Entity type {}: original has 0, round-tripped has {}",
                k, v
            ));
        }
    }

    // Layer diff
    let orig_layers_set: BTreeSet<&String> = record.orig_layers.iter().collect();
    let rt_layers_set: BTreeSet<&String> = record.rt_layers.iter().collect();
    for l in &record.orig_layers {
        if !rt_layers_set.contains(l) {
            diffs.push(format!(
                "Layer '{}' present in original but missing in round-tripped",
                l
            ));
        }
    }
    for l in &record.rt_layers {
        if !orig_layers_set.contains(l) {
            diffs.push(format!(
                "Layer '{}' present in round-tripped but missing in original",
                l
            ));
        }
    }

    if !diffs.is_empty() {
        return Err(format!("Round-trip diff failed:\n  {}", diffs.join("\n  ")));
    }

    Ok(())
}

fn validate_project_profile_fixture(workspace_root: &Path) -> Result<(), String> {
    let fixture_path = workspace_root.join(PROJECT_PROFILE_FIXTURE);
    let original_content = std::fs::read_to_string(&fixture_path)
        .map_err(|error| format!("read project Tier-1 profile fixture: {error}"))?;
    let original_candidates = read_title_block_candidates(&fixture_path)
        .map_err(|error| format!("open project Tier-1 profile fixture: {error}"))?;
    let profile = profiles::resolve_profile(&original_candidates)
        .map_err(|error| format!("resolve Tier-1 profile fixture: {error}"))?;
    if profile.profile_id != PROJECT_PROFILE_ID {
        return Err(format!(
            "Tier-1 profile fixture resolved to '{}', expected '{PROJECT_PROFILE_ID}'",
            profile.profile_id,
        ));
    }
    if profile.source_evidence != [PROJECT_PROFILE_FIXTURE] {
        return Err(format!(
            "{PROJECT_PROFILE_ID} source evidence is not bound to the committed fixture: {:?}",
            profile.source_evidence
        ));
    }

    let original_target = original_candidates
        .iter()
        .find(|candidate| candidate.block_name == PROJECT_PROFILE_ID)
        .ok_or_else(|| format!("Tier-1 fixture has no {PROJECT_PROFILE_ID} candidate"))?;
    let original_control = original_candidates
        .iter()
        .find(|candidate| candidate.block_name == "OTHER_TITLE_BLOCK")
        .ok_or_else(|| "Tier-1 fixture has no nonmatching control candidate".to_string())?;

    let replacements = HashMap::from([("revision".to_string(), "P02".to_string())]);
    let patched = dxf_patch::patch_dxf_attributes(
        &original_content,
        &profile.title_block_fingerprint(),
        &replacements,
    )
    .map_err(|error| format!("patch Tier-1 profile fixture: {error}"))?;
    if patched.target_inserts != 1 || patched.attributes_written != 1 {
        return Err(format!(
            "Tier-1 profile patch touched unexpected scope: {} INSERTs, {} attributes",
            patched.target_inserts, patched.attributes_written
        ));
    }
    let (original_revision_line, patched_revision_line) = if original_content.contains("\r\n") {
        ("\r\nP01\r\n", "\r\nP02\r\n")
    } else {
        ("\nP01\n", "\nP02\n")
    };
    if original_content.matches(original_revision_line).count() != 1 {
        return Err(
            "Tier-1 profile fixture must contain exactly one P01 revision value line".to_string(),
        );
    }
    let expected_content =
        original_content.replacen(original_revision_line, patched_revision_line, 1);
    if patched.content != expected_content {
        return Err(
            "Tier-1 profile patch changed bytes outside the unique REVISION value line".to_string(),
        );
    }

    let patched_file = tempfile::Builder::new()
        .suffix(".dxf")
        .tempfile()
        .map_err(|error| format!("create Tier-1 patch temp file: {error}"))?;
    std::fs::write(patched_file.path(), patched.content)
        .map_err(|error| format!("write Tier-1 patch temp file: {error}"))?;
    let patched_candidates = read_title_block_candidates(patched_file.path())
        .map_err(|error| format!("reopen patched Tier-1 profile fixture: {error}"))?;
    let patched_profile = profiles::resolve_profile(&patched_candidates)
        .map_err(|error| format!("resolve patched Tier-1 profile fixture: {error}"))?;
    if patched_profile.profile_id != PROJECT_PROFILE_ID {
        return Err(format!(
            "patched Tier-1 fixture resolved to '{}', expected '{PROJECT_PROFILE_ID}'",
            patched_profile.profile_id,
        ));
    }

    let patched_target = patched_candidates
        .iter()
        .find(|candidate| candidate.block_name == PROJECT_PROFILE_ID)
        .ok_or_else(|| format!("patched Tier-1 fixture lost {PROJECT_PROFILE_ID} candidate"))?;
    let patched_control = patched_candidates
        .iter()
        .find(|candidate| candidate.block_name == "OTHER_TITLE_BLOCK")
        .ok_or_else(|| "patched Tier-1 fixture lost control candidate".to_string())?;
    let mut expected_attributes = original_target.attributes.clone();
    expected_attributes.insert("REVISION".to_string(), "P02".to_string());
    if patched_target.attributes != expected_attributes {
        return Err(format!(
            "Tier-1 profile patch changed fields outside REVISION: expected {:?}, got {:?}",
            expected_attributes, patched_target.attributes
        ));
    }
    if patched_control.attributes != original_control.attributes {
        return Err("Tier-1 profile patch changed the nonmatching control INSERT".to_string());
    }

    Ok(())
}

fn read_title_block_candidates(path: &Path) -> Result<Vec<title_blocks::TitleBlockInfo>, String> {
    let result = AutocadServer::new()
        .read_title_blocks(Parameters(ReadTitleBlocksParams {
            drawing_path: path.to_string_lossy().into_owned(),
            attribute_value_mode: TitleBlockAttributeValueMode::Split,
        }))
        .map_err(|error| error.to_string())?;
    let is_error = result.is_error == Some(true);
    let text = result
        .content
        .into_iter()
        .find_map(|content| match content.raw {
            RawContent::Text(text) => Some(text.text),
            _ => None,
        })
        .ok_or_else(|| "title-block reader returned no text content".to_string())?;
    if is_error {
        return Err(text);
    }
    serde_json::from_str(&text)
        .map_err(|error| format!("parse title-block reader response: {error}"))
}

fn write_tier1_survey_artifact(
    workspace_root: &Path,
    tier1_paths: &[PathBuf],
) -> Result<(), String> {
    let diagnostic_path = workspace_root.join(TITLE_BLOCK_DIAGNOSTIC_FIXTURE);
    if !tier1_paths.contains(&diagnostic_path) {
        return Err(format!(
            "Tier-1 corpus omitted the title-block diagnostic fixture: {}",
            diagnostic_path.display()
        ));
    }
    let all_inputs: Vec<_> = tier1_paths
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    let diagnostic_error = match survey::survey_paths_jsonl(&all_inputs, 1, false) {
        Ok(_) => {
            return Err(format!(
                "production Tier-1 survey unexpectedly admitted {}",
                diagnostic_path.display()
            ));
        }
        Err(error) => error.to_string(),
    };
    let expected_diagnostic_error = format!(
        "failed to open drawing '{}': code=unsupported_title_block_data \
         reader reported an unsupported diagnostic that may affect title-block interpretation",
        diagnostic_path.display()
    );
    if diagnostic_error != expected_diagnostic_error {
        return Err(format!(
            "production Tier-1 survey rejected the diagnostic fixture incorrectly: \
             expected {expected_diagnostic_error:?}, got {diagnostic_error:?}"
        ));
    }

    let survey_paths: Vec<_> = tier1_paths
        .iter()
        .filter(|path| **path != diagnostic_path)
        .collect();
    let inputs: Vec<_> = survey_paths
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    let jsonl = survey::survey_paths_jsonl(&inputs, 1, false)
        .map_err(|error| format!("run production Tier-1 survey: {error}"))?;
    let mut records: Vec<serde_json::Value> = jsonl
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .map_err(|error| format!("parse production Tier-1 survey record: {error}"))
        })
        .collect::<Result<_, _>>()?;
    if records.len() != survey_paths.len() {
        return Err(format!(
            "production Tier-1 survey emitted {} records for {} fixtures",
            records.len(),
            survey_paths.len()
        ));
    }

    let actual_files: Vec<_> = records
        .iter()
        .map(|record| {
            record["file"]
                .as_str()
                .ok_or_else(|| "production Tier-1 survey record has no file string".to_string())
        })
        .collect::<Result<_, _>>()?;
    let expected_files: Vec<_> = inputs.iter().map(String::as_str).collect();
    if actual_files != expected_files {
        return Err(format!(
            "production Tier-1 survey order drifted: expected {expected_files:?}, got {actual_files:?}"
        ));
    }

    for record in &records {
        let candidates = record["title_block_candidates"]
            .as_array()
            .ok_or_else(|| "production Tier-1 survey candidates are not an array".to_string())?;
        for candidate in candidates {
            if candidate.get("observed_values").is_some() {
                return Err(format!(
                    "production Tier-1 survey leaked observed values: {candidate}"
                ));
            }
        }
    }

    let project_path = workspace_root
        .join(PROJECT_PROFILE_FIXTURE)
        .to_string_lossy()
        .into_owned();
    let project_record = records
        .iter()
        .find(|record| record["file"] == project_path)
        .ok_or_else(|| {
            "production Tier-1 survey omitted the project profile fixture".to_string()
        })?;
    let candidate_names: BTreeSet<_> = project_record["title_block_candidates"]
        .as_array()
        .ok_or_else(|| "project Tier-1 survey candidates are not an array".to_string())?
        .iter()
        .filter_map(|candidate| candidate["block_name"].as_str())
        .collect();
    if candidate_names != BTreeSet::from([PROJECT_PROFILE_ID, "OTHER_TITLE_BLOCK"]) {
        return Err(format!(
            "project Tier-1 survey candidates drifted: {candidate_names:?}"
        ));
    }

    let mut artifact_lines = Vec::with_capacity(records.len());
    for (record, path) in records.iter_mut().zip(survey_paths) {
        let relative = path.strip_prefix(workspace_root).map_err(|error| {
            format!(
                "Tier-1 survey path {} is outside the workspace: {error}",
                path.display()
            )
        })?;
        record["file"] = serde_json::Value::String(relative.to_string_lossy().into_owned());
        artifact_lines.push(
            serde_json::to_string(record)
                .map_err(|error| format!("serialize Tier-1 survey artifact: {error}"))?,
        );
    }
    let artifact_jsonl = artifact_lines.join("\n");

    let output_dir = workspace_root.join("target");
    std::fs::create_dir_all(&output_dir)
        .map_err(|error| format!("create Tier-1 survey output directory: {error}"))?;
    let output_path = output_dir.join("corpus_survey.jsonl");
    std::fs::write(&output_path, format!("{artifact_jsonl}\n"))
        .map_err(|error| format!("write {}: {error}", output_path.display()))?;
    println!(
        "Wrote Tier-1 production survey to {}",
        output_path.display()
    );
    Ok(())
}

#[test]
fn tier1_manifest_is_nonempty_and_all_bytes_match() {
    let paths = load_tier1_fixture_paths(&workspace_root())
        .unwrap_or_else(|error| panic!("Tier-1 corpus is not ready: {error}"));
    assert_eq!(paths.len(), 3, "unexpected Tier-1 fixture inventory");
}

#[test]
fn admitted_fixture_provenance_is_closed_and_exact_byte_bound() {
    let workspace_root = workspace_root();
    let ledger = load_fixture_provenance(&workspace_root)
        .unwrap_or_else(|error| panic!("fixture provenance is not ready: {error}"));
    validate_fixture_provenance(&workspace_root, &ledger)
        .unwrap_or_else(|error| panic!("fixture provenance failed: {error}"));
}

#[test]
fn fixture_provenance_rejects_any_broadened_upstream_mapping() {
    let workspace_root = workspace_root();
    for reviewed_path in [
        "tests/corpus/open/acadsharp/LICENSE",
        "tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dwg",
        "tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dxf",
    ] {
        let mut ledger = load_fixture_provenance(&workspace_root).unwrap();
        let artifact = ledger
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.path == reviewed_path)
            .expect("reviewed ACadSharp mapping must remain in the fixture ledger");
        let FixtureOrigin::UpstreamExact { source_path, .. } = &mut artifact.origin else {
            panic!("reviewed ACadSharp row must remain an upstream_exact origin");
        };
        *source_path = "samples/unreviewed/new-fixture.dxf".to_string();

        let error = validate_fixture_provenance(&workspace_root, &ledger).unwrap_err();
        assert!(
            error.contains("outside the exact reviewed ACadSharp provenance boundary"),
            "broadened upstream mapping for {reviewed_path} failed for the wrong reason: {error}"
        );
    }
}

#[test]
fn tier1_manifest_rejects_an_empty_inventory() {
    let manifest = Tier1Manifest {
        schema_version: 1,
        tier: 1,
        fixtures: Vec::new(),
    };
    let error = validate_tier1_manifest(&workspace_root(), &manifest).unwrap_err();
    assert!(error.contains("at least one fixture"), "got: {error}");
}

#[test]
fn tier1_manifest_rejects_missing_and_digest_drifted_fixtures() {
    let repository = tempfile::tempdir().expect("temporary repository should be creatable");
    let relative = "tests/corpus/open/project/test.dxf";
    let manifest = Tier1Manifest {
        schema_version: 1,
        tier: 1,
        fixtures: vec![Tier1Fixture {
            path: relative.to_string(),
            sha256: "0".repeat(64),
            format: "DXF".to_string(),
        }],
    };

    let missing = validate_tier1_manifest(repository.path(), &manifest).unwrap_err();
    assert!(missing.contains("missing or unreadable"), "got: {missing}");

    let fixture = repository.path().join(relative);
    std::fs::create_dir_all(fixture.parent().unwrap()).unwrap();
    std::fs::write(&fixture, b"project fixture bytes").unwrap();
    let drifted = validate_tier1_manifest(repository.path(), &manifest).unwrap_err();
    assert!(drifted.contains("SHA-256 mismatch"), "got: {drifted}");
}

#[test]
fn tier1_manifest_requires_lowercase_drawing_extensions() {
    let manifest = Tier1Manifest {
        schema_version: 1,
        tier: 1,
        fixtures: vec![Tier1Fixture {
            path: "tests/corpus/open/project/test.DXF".to_string(),
            sha256: "0".repeat(64),
            format: "DXF".to_string(),
        }],
    };
    let error = validate_tier1_manifest(&workspace_root(), &manifest).unwrap_err();
    assert!(error.contains("lowercase extension"), "got: {error}");
}

#[test]
fn tier1_project_fixture_resolves_and_patches_exactly() {
    validate_project_profile_fixture(&workspace_root())
        .unwrap_or_else(|error| panic!("Tier-1 project fixture failed: {error}"));
}

fn synthetic_project_profile_document() -> acadrust::CadDocument {
    let mut document = acadrust::CadDocument::new();

    let mut control = Insert::new("OTHER_TITLE_BLOCK", Vector3::new(0.0, 0.0, 0.0));
    control
        .attributes
        .push(AttributeEntity::simple("REVISION", "CONTROL"));
    control
        .attributes
        .push(AttributeEntity::simple("DRAWING_NUMBER", "CONTROL-001"));
    document.add_entity(EntityType::Insert(control)).unwrap();

    let mut target = Insert::new(PROJECT_PROFILE_ID, Vector3::new(0.0, 0.0, 0.0));
    for (tag, value) in [
        ("REVISION", "P01"),
        ("DRAWING_NUMBER", "SYNTHETIC-001"),
        ("REFERENCE", "REFERENCE-001"),
        ("TITLE_LINE_1", "Synthetic Fixture"),
        ("TITLE_LINE_2", "Example Sheet"),
        ("SHEET_NUMBER", "1"),
        ("SHEET_COUNT", "1"),
    ] {
        target.attributes.push(AttributeEntity::simple(tag, value));
    }
    document.add_entity(EntityType::Insert(target)).unwrap();
    document
}

fn find_byte_sequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty() && needle.len() <= haystack.len())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

fn dxf_object_record_handle(record: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(record)
        .map_err(|error| format!("generated ASCII DXF object is not UTF-8: {error}"))?;
    let mut lines = text.split("\r\n");
    while let Some(code) = lines.next() {
        let Some(value) = lines.next() else {
            break;
        };
        if code.trim() == "5" {
            return u64::from_str_radix(value.trim(), 16)
                .map_err(|error| format!("invalid generated DXF object handle: {error}"));
        }
    }
    Err("generated DXF object has no handle".to_string())
}

fn canonicalize_synthetic_ascii_dxf(mut bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    const OBJECTS_HEADER: &[u8] = b"  0\r\nSECTION\r\n  2\r\nOBJECTS\r\n";
    const RECORD_HEADER: &[u8] = b"  0\r\n";
    const END_SECTION: &[u8] = b"  0\r\nENDSEC\r\n";

    let objects_start = find_byte_sequence(&bytes, OBJECTS_HEADER)
        .ok_or_else(|| "generated ASCII DXF has no OBJECTS section".to_string())?
        + OBJECTS_HEADER.len();
    let objects_len = find_byte_sequence(&bytes[objects_start..], END_SECTION)
        .ok_or_else(|| "generated ASCII DXF OBJECTS section is not terminated".to_string())?;
    let objects_end = objects_start + objects_len;
    let body = &bytes[objects_start..objects_end];

    let mut line_offsets = Vec::new();
    let mut lines = Vec::new();
    let mut offset = 0;
    for line in body.split_inclusive(|byte| *byte == b'\n') {
        line_offsets.push(offset);
        lines.push(line);
        offset += line.len();
    }
    if lines.len() % 2 != 0 {
        return Err("generated ASCII DXF OBJECTS section has an incomplete group pair".to_string());
    }
    let starts: Vec<_> = (0..lines.len())
        .step_by(2)
        .filter_map(|line| (lines[line] == RECORD_HEADER).then_some(line_offsets[line]))
        .collect();
    if starts.first().copied() != Some(0) {
        return Err("generated ASCII DXF OBJECTS section has an invalid prefix".to_string());
    }

    let mut records = Vec::with_capacity(starts.len());
    for (index, start) in starts.iter().copied().enumerate() {
        let end = starts.get(index + 1).copied().unwrap_or(body.len());
        let record = body[start..end].to_vec();
        records.push((dxf_object_record_handle(&record)?, record));
    }
    records.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

    let mut canonical = Vec::with_capacity(bytes.len());
    canonical.extend_from_slice(&bytes[..objects_start]);
    for (_, record) in records {
        canonical.extend_from_slice(&record);
    }
    canonical.extend_from_slice(&bytes[objects_end..]);
    bytes.clear();
    Ok(canonical)
}

fn write_synthetic_project_profile_fixture(path: &Path) {
    let rendered = DxfWriter::new(&synthetic_project_profile_document())
        .write_to_vec()
        .unwrap_or_else(|error| panic!("render {}: {error}", path.display()));
    let canonical = canonicalize_synthetic_ascii_dxf(rendered)
        .unwrap_or_else(|error| panic!("canonicalize {}: {error}", path.display()));
    std::fs::write(path, canonical)
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
}

fn accepted_acadrust_0_4_1_class_records() -> Vec<u8> {
    let mut records = String::new();
    for (dxf_class, cpp_class, proxy_flags) in [
        ("PDFUNDERLAY", "AcDbPdfReference", 1),
        ("DWFUNDERLAY", "AcDbDwfReference", 1),
        ("DGNUNDERLAY", "AcDbDgnReference", 1),
        ("HELIX", "AcDbHelix", 0),
    ] {
        write!(
            records,
            "  0\r\nCLASS\r\n  1\r\n{dxf_class}\r\n  2\r\n{cpp_class}\r\n  3\r\nObjectDBX Classes\r\n 90\r\n{proxy_flags:>6}\r\n 91\r\n     0\r\n280\r\n0\r\n281\r\n1\r\n"
        )
        .expect("write accepted acadrust class record");
    }
    records.into_bytes()
}

#[test]
fn synthetic_project_profile_recipe_matches_committed_bytes() {
    let temporary = tempfile::tempdir().expect("create temporary fixture directory");
    let rendered = temporary.path().join("generic-title-block-ascii.dxf");
    write_synthetic_project_profile_fixture(&rendered);

    let committed = std::fs::read(workspace_root().join(PROJECT_PROFILE_FIXTURE))
        .expect("read committed generic project fixture");
    let actual = std::fs::read(&rendered).expect("read rendered generic project fixture");
    assert_eq!(
        sha256_hex(&actual),
        sha256_hex(&committed),
        "checked-in recipe output drifted from the committed generic project fixture"
    );
    assert_eq!(
        actual, committed,
        "checked-in recipe output must be byte-identical to the committed generic project fixture"
    );
}

#[test]
fn synthetic_project_profile_has_only_the_accepted_0_4_1_writer_delta() {
    const MULTILEADER_CLASS_START: &[u8] = b"  0\r\nCLASS\r\n  1\r\nMULTILEADER\r\n";

    let current = std::fs::read(workspace_root().join(PROJECT_PROFILE_FIXTURE))
        .expect("read committed generic project fixture");
    assert_eq!(sha256_hex(&current), PROJECT_PROFILE_0_4_1_SHA256);

    let accepted = accepted_acadrust_0_4_1_class_records();
    assert_eq!(accepted.len(), 463, "accepted writer delta byte count");
    assert_eq!(
        accepted.iter().filter(|byte| **byte == b'\n').count(),
        64,
        "four eight-pair CLASS records must occupy exactly 64 lines"
    );

    let matches = current
        .windows(accepted.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == accepted).then_some(offset))
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "the accepted four-record class-table delta must occur exactly once"
    );
    let start = matches[0];
    let end = start + accepted.len();
    assert!(
        current[end..].starts_with(MULTILEADER_CLASS_START),
        "the accepted class records must be contiguous and immediately precede MULTILEADER"
    );

    let mut prior_output = Vec::with_capacity(current.len() - accepted.len());
    prior_output.extend_from_slice(&current[..start]);
    prior_output.extend_from_slice(&current[end..]);
    assert_eq!(
        sha256_hex(&prior_output),
        PROJECT_PROFILE_0_4_0_SHA256,
        "removing only the accepted class records must recover the exact 0.4.0 recipe bytes"
    );
}

#[test]
#[ignore = "writes a fresh fixture only to an explicit review path"]
fn regenerate_synthetic_project_profile_fixture() {
    let output = std::env::var_os("AUTOCAD_SYNTHETIC_PROFILE_OUTPUT")
        .map(PathBuf::from)
        .expect("set AUTOCAD_SYNTHETIC_PROFILE_OUTPUT to a fresh absolute .dxf path");
    assert!(
        output.is_absolute()
            && output.extension().and_then(|extension| extension.to_str()) == Some("dxf")
            && output.components().all(|component| matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )),
        "synthetic profile output must be a normalized absolute .dxf path"
    );
    let parent = output
        .parent()
        .expect("absolute synthetic profile output must have a parent");
    let parent_metadata = std::fs::symlink_metadata(parent)
        .unwrap_or_else(|error| panic!("inspect {}: {error}", parent.display()));
    assert!(
        parent_metadata.file_type().is_dir() && !parent_metadata.file_type().is_symlink(),
        "synthetic profile output parent must be a non-symlink directory"
    );
    match std::fs::symlink_metadata(&output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => panic!(
            "synthetic profile output already exists: {}",
            output.display()
        ),
        Err(error) => panic!("inspect {}: {error}", output.display()),
    }
    write_synthetic_project_profile_fixture(&output);
}

fn validate_corpus_tiers(
    workspace_root: &Path,
    corpora: Vec<(usize, Vec<PathBuf>)>,
    report_name: &str,
) {
    let mut records = Vec::new();
    let mut failures = Vec::new();

    for (tier, drawing_paths) in corpora {
        for file_path in drawing_paths {
            let ext = file_path
                .extension()
                .and_then(|e| e.to_str())
                .expect("validated corpus drawing must have a UTF-8 extension")
                .to_lowercase();

            // Get a relative path for cleaner logging/records
            let file_rel = file_path.strip_prefix(workspace_root).unwrap_or(&file_path);
            let file_str = file_rel.to_string_lossy().to_string();
            let format = ext.to_uppercase();

            let mut record = CorpusRecord {
                file: file_str.clone(),
                tier,
                format: format.clone(),
                acadrust_read_ok: false,
                acadrust_write_ok: false,
                accoreconsole_audit: "skipped".to_string(),
                orig_entities: BTreeMap::new(),
                rt_entities: BTreeMap::new(),
                surviving_entities: Vec::new(),
                orig_layers: Vec::new(),
                rt_layers: Vec::new(),
                block_names: Vec::new(),
                title_block_attributes: BTreeMap::new(),
                passed: false,
                error_message: None,
            };

            // Run the contract steps:
            match run_file_validation(&file_path, &mut record) {
                Ok(()) => {
                    record.passed = true;
                }
                Err(e) => {
                    record.passed = false;
                    record.error_message = Some(e.clone());
                    let is_critical =
                        tier == 1 || !record.acadrust_read_ok || !record.acadrust_write_ok;
                    if is_critical {
                        failures.push((file_str, e));
                    } else {
                        println!(
                            "Warning: Tier {} file {} failed validation (non-critical): {}",
                            tier, file_str, e
                        );
                    }
                }
            }

            // Write/print structured log line
            let json_line =
                serde_json::to_string(&record).expect("corpus validation record must serialize");
            println!("VALIDATION_LOG: {}", json_line);
            records.push(record);
        }
    }

    // The detailed round-trip log is separate from the production survey schema.
    let output_dir = workspace_root.join("target");
    std::fs::create_dir_all(&output_dir)
        .unwrap_or_else(|error| panic!("create corpus validation output directory: {error}"));
    let output_path = output_dir.join(report_name);
    let mut output_content = String::new();
    for r in &records {
        output_content
            .push_str(&serde_json::to_string(r).expect("corpus validation record must serialize"));
        output_content.push('\n');
    }
    std::fs::write(&output_path, output_content)
        .unwrap_or_else(|error| panic!("write {}: {error}", output_path.display()));
    println!(
        "Wrote corpus validation results to {}",
        output_path.display()
    );

    // Report failures
    if !failures.is_empty() {
        eprintln!("\n=== CORPUS VALIDATION FAILED ===");
        for (f, err) in &failures {
            eprintln!("File: {}\nError: {}\n", f, err);
        }
        panic!("Corpus validation failed for {} drawings!", failures.len());
    } else {
        println!("All drawings parsed, written, and verified successfully!");
    }
}

#[test]
fn tier1_corpus_validation() {
    let workspace_root = workspace_root();
    let tier1_paths = load_tier1_fixture_paths(&workspace_root)
        .unwrap_or_else(|error| panic!("Tier-1 corpus is not ready: {error}"));
    write_tier1_survey_artifact(&workspace_root, &tier1_paths)
        .unwrap_or_else(|error| panic!("Tier-1 production survey failed: {error}"));

    validate_corpus_tiers(
        &workspace_root,
        vec![(1, tier1_paths)],
        "corpus_validation.jsonl",
    );
}

#[test]
#[ignore = "manual audit of untracked private Tier-2 and Tier-3 drawings"]
fn private_tier2_and_tier3_corpus_audit() {
    let workspace_root = workspace_root();
    let tier2_paths = discover_drawings(&workspace_root, "tests/corpus/autodesk", 2)
        .unwrap_or_else(|error| panic!("Tier-2 corpus discovery failed: {error}"));
    assert!(
        !tier2_paths.is_empty(),
        "private Tier-2 audit requires at least one drawing under tests/corpus/autodesk"
    );
    let tier3_paths = discover_drawings(&workspace_root, "tests/corpus/civil3d", 3)
        .unwrap_or_else(|error| panic!("Tier-3 corpus discovery failed: {error}"));
    if tier3_paths.is_empty() {
        println!("Optional Tier-3 corpus is absent; no Tier-3 evidence will be produced.");
    }
    let corpora = vec![(2, tier2_paths), (3, tier3_paths)];

    validate_corpus_tiers(&workspace_root, corpora, "private_corpus_validation.jsonl");
}
