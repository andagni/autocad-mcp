use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
use walkdir::WalkDir;

pub const DOCUMENTATION_PROVENANCE_PLUGIN_PATH: &str =
    "skills/autolisp/references/documentation-provenance.json";

const AUTOLISP_SKILL_PLUGIN_PATH: &str = "skills/autolisp";
const REFERENCE_ROOT_DECLARATION: &str = "plugin/skills/autolisp";
const REFERENCE_ROOT_PLUGIN_PATH: &str = "skills/autolisp/references";
const SKILL_ENTRYPOINT_PATH: &str = "SKILL.md";
const PROVENANCE_ARTIFACT_PATH: &str = "references/documentation-provenance.json";
const LSP_INDEX_PATH: &str = "references/autolisp-lsp-index.json";
const EXPECTED_SCHEMA_VERSION: u32 = 1;
const EXPECTED_COPYRIGHT_HOLDER: &str = "andagni";
const EXPECTED_LICENSE: &str = "GPL-3.0-or-later";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentationProvenance {
    schema_version: u32,
    reference_root: String,
    copyright_holder: String,
    license: String,
    sources: Vec<SourceRecord>,
    artifacts: Vec<ArtifactRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRecord {
    id: String,
    title: String,
    url: String,
    version: String,
    reviewed_on: String,
    rights_basis: RightsBasis,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RightsBasis {
    FactsOnlyNoSourceExpressionRedistributed,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRecord {
    path: String,
    sha256: String,
    kind: ArtifactKind,
    disposition: ArtifactDisposition,
    source_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ArtifactKind {
    Markdown,
    AutolispLspIndex,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ArtifactDisposition {
    FirstPartyFactualSynthesis,
    FirstPartyCuratedIndex,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LspIndex {
    schema_version: u32,
    symbols: Vec<LspSymbol>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LspSymbol {
    name: String,
    kind: LspSymbolKind,
    signature: String,
    summary: String,
    detail: serde_json::Value,
    source: String,
    completion: bool,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LspSymbolKind {
    Builtin,
    Command,
}

/// Validate the exact-byte provenance closure for the shipped AutoLISP
/// reference suite.
///
/// A plugin without `skills/autolisp` has no AutoLISP documentation boundary,
/// so this check is intentionally a no-op for generic plugin fixtures. Once
/// that skill exists, the reference root and its provenance ledger are
/// mandatory and fail closed. Any file below the AutoLISP skill that is not a
/// ledger artifact or a recognized local metadata exception is rejected. This
/// strict form is appropriate for a staged plugin or an extracted package.
pub fn validate_documentation_provenance(plugin_dir: &Path) -> Vec<String> {
    validate_documentation_provenance_with_scope(plugin_dir, true)
}

/// Validate the documentation that the package allowlist will project from a
/// plugin source tree.
///
/// Developer-only files whose path is not admitted by the packager are ignored
/// here; admitted Markdown and index files still require exact ledger closure.
/// The staged plugin is subsequently checked with the strict validator.
pub fn validate_documentation_provenance_for_package_source(plugin_dir: &Path) -> Vec<String> {
    validate_documentation_provenance_with_scope(plugin_dir, false)
}

fn validate_documentation_provenance_with_scope(
    plugin_dir: &Path,
    reject_unshipped_files: bool,
) -> Vec<String> {
    let skill_path = plugin_dir.join(AUTOLISP_SKILL_PLUGIN_PATH);
    let skill_metadata = match std::fs::symlink_metadata(&skill_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            return vec![provenance_error(format!(
                "cannot inspect AutoLISP skill {}: {error}",
                skill_path.display()
            ))]
        }
    };
    if !skill_metadata.is_dir() || skill_metadata.file_type().is_symlink() {
        return vec![provenance_error(format!(
            "AutoLISP skill must be a real directory: {}",
            skill_path.display()
        ))];
    }

    let reference_root = plugin_dir.join(REFERENCE_ROOT_PLUGIN_PATH);
    let mut errors = Vec::new();
    let reference_metadata = match std::fs::symlink_metadata(&reference_root) {
        Ok(metadata) => metadata,
        Err(error) => {
            errors.push(provenance_error(format!(
                "cannot inspect required reference root {}: {error}",
                reference_root.display()
            )));
            return errors;
        }
    };
    if !reference_metadata.is_dir() || reference_metadata.file_type().is_symlink() {
        errors.push(provenance_error(format!(
            "reference root must be a real directory: {}",
            reference_root.display()
        )));
        return errors;
    }

    let ledger_path = plugin_dir.join(DOCUMENTATION_PROVENANCE_PLUGIN_PATH);
    let ledger_metadata = match std::fs::symlink_metadata(&ledger_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            errors.push(provenance_error(format!(
                "cannot inspect required ledger {}: {error}",
                ledger_path.display()
            )));
            return errors;
        }
    };
    if !ledger_metadata.is_file() || ledger_metadata.file_type().is_symlink() {
        errors.push(provenance_error(format!(
            "ledger must be a regular file, not a symlink: {}",
            ledger_path.display()
        )));
        return errors;
    }

    let ledger_bytes = match std::fs::read(&ledger_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            errors.push(provenance_error(format!(
                "cannot read ledger {}: {error}",
                ledger_path.display()
            )));
            return errors;
        }
    };
    let ledger: DocumentationProvenance = match serde_json::from_slice(&ledger_bytes) {
        Ok(ledger) => ledger,
        Err(error) => {
            errors.push(provenance_error(format!(
                "ledger is not valid closed-schema JSON: {error}"
            )));
            return errors;
        }
    };

    validate_ledger_header(&ledger, &mut errors);
    let sources = validate_sources(&ledger.sources, &mut errors);
    let inventory =
        collect_shipped_reference_inventory(&skill_path, reject_unshipped_files, &mut errors);
    if !inventory.contains(SKILL_ENTRYPOINT_PATH) {
        errors.push(provenance_error(format!(
            "required AutoLISP skill entrypoint is missing: {SKILL_ENTRYPOINT_PATH:?}"
        )));
    }
    let artifacts = validate_artifacts(
        &ledger.artifacts,
        &sources,
        &inventory,
        &skill_path,
        &mut errors,
    );
    validate_source_usage(&ledger.sources, &ledger.artifacts, &mut errors);
    validate_lsp_index(&skill_path, &artifacts, &mut errors);
    errors
}

fn provenance_error(message: impl AsRef<str>) -> String {
    format!("AutoLISP documentation provenance: {}", message.as_ref())
}

fn validate_ledger_header(ledger: &DocumentationProvenance, errors: &mut Vec<String>) {
    if ledger.schema_version != EXPECTED_SCHEMA_VERSION {
        errors.push(provenance_error(format!(
            "schema_version must be {EXPECTED_SCHEMA_VERSION}; got {}",
            ledger.schema_version
        )));
    }
    if ledger.reference_root != REFERENCE_ROOT_DECLARATION {
        errors.push(provenance_error(format!(
            "reference_root must be {REFERENCE_ROOT_DECLARATION:?}; got {:?}",
            ledger.reference_root
        )));
    }
    if ledger.copyright_holder != EXPECTED_COPYRIGHT_HOLDER {
        errors.push(provenance_error(format!(
            "copyright_holder must be {EXPECTED_COPYRIGHT_HOLDER:?}; got {:?}",
            ledger.copyright_holder
        )));
    }
    if ledger.license != EXPECTED_LICENSE {
        errors.push(provenance_error(format!(
            "license must be {EXPECTED_LICENSE:?}; got {:?}",
            ledger.license
        )));
    }
}

fn validate_sources<'a>(
    sources: &'a [SourceRecord],
    errors: &mut Vec<String>,
) -> BTreeMap<&'a str, &'a SourceRecord> {
    let mut by_id = BTreeMap::new();
    let mut previous_id: Option<&str> = None;
    for source in sources {
        if !is_source_id(&source.id) {
            errors.push(provenance_error(format!(
                "source id must use lowercase ASCII letters, digits, and single hyphens: {:?}",
                source.id
            )));
        }
        if previous_id.is_some_and(|previous| previous >= source.id.as_str()) {
            errors.push(provenance_error(format!(
                "sources must be strictly sorted by id without duplicates; {:?} follows {:?}",
                source.id, previous_id
            )));
        }
        previous_id = Some(&source.id);
        if by_id.insert(source.id.as_str(), source).is_some() {
            errors.push(provenance_error(format!(
                "duplicate source id {:?}",
                source.id
            )));
        }
        if source.title.trim().is_empty() {
            errors.push(provenance_error(format!(
                "source {:?} title must be nonempty",
                source.id
            )));
        }
        if source.version.trim().is_empty() {
            errors.push(provenance_error(format!(
                "source {:?} version must be nonempty",
                source.id
            )));
        }
        if !source.url.starts_with("https://")
            || source.url.len() == "https://".len()
            || source.url.chars().any(char::is_whitespace)
        {
            errors.push(provenance_error(format!(
                "source {:?} url must be a nonempty HTTPS URL without whitespace",
                source.id
            )));
        }
        if !is_iso_date(&source.reviewed_on) {
            errors.push(provenance_error(format!(
                "source {:?} reviewed_on must be a YYYY-MM-DD date; got {:?}",
                source.id, source.reviewed_on
            )));
        }
        if source.rights_basis != RightsBasis::FactsOnlyNoSourceExpressionRedistributed {
            errors.push(provenance_error(format!(
                "source {:?} has an unsupported rights basis",
                source.id
            )));
        }
    }
    by_id
}

fn is_source_id(value: &str) -> bool {
    if value.is_empty() || value.starts_with('-') || value.ends_with('-') {
        return false;
    }
    let mut previous_hyphen = false;
    for byte in value.bytes() {
        let hyphen = byte == b'-';
        if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || hyphen)
            || (hyphen && previous_hyphen)
        {
            return false;
        }
        previous_hyphen = hyphen;
    }
    true
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(month) = value[5..7].parse::<u8>() else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u8>() else {
        return false;
    };
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

fn collect_shipped_reference_inventory(
    artifact_root: &Path,
    reject_unshipped_files: bool,
    errors: &mut Vec<String>,
) -> BTreeSet<String> {
    let mut inventory = BTreeSet::new();
    for result in WalkDir::new(artifact_root).follow_links(false) {
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(provenance_error(format!(
                    "cannot walk AutoLISP artifact root {}: {error}",
                    artifact_root.display()
                )));
                continue;
            }
        };
        if entry.path() == artifact_root || entry.file_type().is_dir() {
            continue;
        }
        let relative = match entry.path().strip_prefix(artifact_root) {
            Ok(relative) => relative,
            Err(error) => {
                errors.push(provenance_error(format!(
                    "cannot make reference path relative: {error}"
                )));
                continue;
            }
        };
        let Some(relative) = canonical_relative_path(relative) else {
            errors.push(provenance_error(format!(
                "reference path is not canonical UTF-8: {}",
                entry.path().display()
            )));
            continue;
        };
        if relative.split('/').next_back() == Some(".gitignore")
            || relative == PROVENANCE_ARTIFACT_PATH
        {
            continue;
        }
        let shipped_candidate = relative == "SKILL.md"
            || (relative.starts_with("references/") && relative.ends_with(".md"))
            || relative == LSP_INDEX_PATH;
        if !shipped_candidate {
            if reject_unshipped_files {
                errors.push(provenance_error(format!(
                    "unapproved file exists below the AutoLISP skill: {relative:?}"
                )));
            }
            continue;
        }
        if !entry.file_type().is_file() || entry.file_type().is_symlink() {
            errors.push(provenance_error(format!(
                "shipped reference candidate must be a regular file, not a symlink: {relative:?}"
            )));
            continue;
        }
        inventory.insert(relative);
    }
    inventory
}

fn canonical_relative_path(path: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?),
            _ => return None,
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

fn is_canonical_ledger_path(path: &str) -> bool {
    if path.is_empty() || path.contains('\\') {
        return false;
    }
    canonical_relative_path(Path::new(path)).is_some_and(|canonical| canonical == path)
}

fn validate_artifacts<'a>(
    artifacts: &'a [ArtifactRecord],
    sources: &BTreeMap<&str, &SourceRecord>,
    inventory: &BTreeSet<String>,
    artifact_root: &Path,
    errors: &mut Vec<String>,
) -> BTreeMap<&'a str, &'a ArtifactRecord> {
    let mut by_path = BTreeMap::new();
    let mut declared_paths = BTreeSet::new();
    let mut previous_path: Option<&str> = None;
    let mut index_count = 0_usize;

    for artifact in artifacts {
        if !is_canonical_ledger_path(&artifact.path) {
            errors.push(provenance_error(format!(
                "artifact path must be canonical, relative, slash-separated UTF-8: {:?}",
                artifact.path
            )));
        }
        if previous_path.is_some_and(|previous| previous >= artifact.path.as_str()) {
            errors.push(provenance_error(format!(
                "artifacts must be strictly sorted by path without duplicates; {:?} follows {:?}",
                artifact.path, previous_path
            )));
        }
        previous_path = Some(&artifact.path);
        if by_path.insert(artifact.path.as_str(), artifact).is_some() {
            errors.push(provenance_error(format!(
                "duplicate artifact path {:?}",
                artifact.path
            )));
        }
        declared_paths.insert(artifact.path.clone());

        validate_source_ids(artifact, sources, errors);
        match (artifact.kind, artifact.disposition) {
            (ArtifactKind::Markdown, ArtifactDisposition::FirstPartyFactualSynthesis) => {
                if !artifact.path.ends_with(".md") {
                    errors.push(provenance_error(format!(
                        "markdown artifact path must end in .md: {:?}",
                        artifact.path
                    )));
                }
                if artifact.source_ids.is_empty() {
                    errors.push(provenance_error(format!(
                        "factual-synthesis artifact {:?} requires at least one source id",
                        artifact.path
                    )));
                }
            }
            (ArtifactKind::AutolispLspIndex, ArtifactDisposition::FirstPartyCuratedIndex) => {
                index_count += 1;
                if artifact.path != LSP_INDEX_PATH {
                    errors.push(provenance_error(format!(
                        "the AutoLISP LSP index artifact path must be {LSP_INDEX_PATH:?}; got {:?}",
                        artifact.path
                    )));
                }
                if artifact.source_ids.is_empty() {
                    errors.push(provenance_error(format!(
                        "curated index {:?} requires external factual source ids; symbol source links provide local reader context",
                        artifact.path
                    )));
                }
            }
            _ => errors.push(provenance_error(format!(
                "artifact {:?} has an invalid kind/disposition combination",
                artifact.path
            ))),
        }

        if artifact.sha256.len() != 64
            || !artifact
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            errors.push(provenance_error(format!(
                "artifact {:?} sha256 must be 64 lowercase hexadecimal characters",
                artifact.path
            )));
        }

        let artifact_path = artifact_root.join(&artifact.path);
        let bytes = match std::fs::read(&artifact_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                errors.push(provenance_error(format!(
                    "cannot read declared artifact {:?}: {error}",
                    artifact.path
                )));
                continue;
            }
        };
        if artifact.kind == ArtifactKind::Markdown && std::str::from_utf8(&bytes).is_err() {
            errors.push(provenance_error(format!(
                "markdown artifact {:?} must be valid UTF-8",
                artifact.path
            )));
        }
        let actual_sha256 = sha256_bytes(&bytes);
        if actual_sha256 != artifact.sha256 {
            errors.push(provenance_error(format!(
                "artifact {:?} byte digest mismatch: expected {}, got {actual_sha256}",
                artifact.path, artifact.sha256
            )));
        }
    }

    if index_count != 1 {
        errors.push(provenance_error(format!(
            "artifacts must contain exactly one {LSP_INDEX_PATH:?} curated index; got {index_count}"
        )));
    }
    for missing in inventory.difference(&declared_paths) {
        errors.push(provenance_error(format!(
            "shipped reference is absent from the ledger: {missing:?}"
        )));
    }
    for extra in declared_paths.difference(inventory) {
        errors.push(provenance_error(format!(
            "ledger artifact is not a shipped reference file: {extra:?}"
        )));
    }
    by_path
}

fn validate_source_ids(
    artifact: &ArtifactRecord,
    sources: &BTreeMap<&str, &SourceRecord>,
    errors: &mut Vec<String>,
) {
    let mut previous_id: Option<&str> = None;
    for source_id in &artifact.source_ids {
        if previous_id.is_some_and(|previous| previous >= source_id.as_str()) {
            errors.push(provenance_error(format!(
                "artifact {:?} source_ids must be strictly sorted without duplicates; {:?} follows {:?}",
                artifact.path, source_id, previous_id
            )));
        }
        previous_id = Some(source_id);
        if !sources.contains_key(source_id.as_str()) {
            errors.push(provenance_error(format!(
                "artifact {:?} cites unknown source id {:?}",
                artifact.path, source_id
            )));
        }
    }
}

fn validate_source_usage(
    sources: &[SourceRecord],
    artifacts: &[ArtifactRecord],
    errors: &mut Vec<String>,
) {
    let used: BTreeSet<&str> = artifacts
        .iter()
        .flat_map(|artifact| artifact.source_ids.iter().map(String::as_str))
        .collect();
    for source in sources {
        if !used.contains(source.id.as_str()) {
            errors.push(provenance_error(format!(
                "declared source {:?} is not used by any artifact",
                source.id
            )));
        }
    }
}

fn validate_lsp_index(
    artifact_root: &Path,
    artifacts: &BTreeMap<&str, &ArtifactRecord>,
    errors: &mut Vec<String>,
) {
    let index_path = artifact_root.join(LSP_INDEX_PATH);
    let bytes = match std::fs::read(&index_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            errors.push(provenance_error(format!(
                "cannot read required LSP index {LSP_INDEX_PATH:?}: {error}"
            )));
            return;
        }
    };
    let index: LspIndex = match serde_json::from_slice(&bytes) {
        Ok(index) => index,
        Err(error) => {
            errors.push(provenance_error(format!(
                "LSP index is not valid closed-schema JSON: {error}"
            )));
            return;
        }
    };
    if index.schema_version != 1 {
        errors.push(provenance_error(format!(
            "LSP index schema_version must be 1; got {}",
            index.schema_version
        )));
    }
    if index.symbols.is_empty() {
        errors.push(provenance_error("LSP index symbols must not be empty"));
    }

    let source_prefix = format!("{REFERENCE_ROOT_DECLARATION}/");
    let mut names = BTreeSet::new();
    for (position, symbol) in index.symbols.iter().enumerate() {
        if symbol.name.trim().is_empty() {
            errors.push(provenance_error(format!(
                "LSP index symbol {position} name must be nonempty"
            )));
        }
        let folded_name = symbol.name.to_ascii_lowercase();
        if !names.insert(folded_name) {
            errors.push(provenance_error(format!(
                "LSP index contains duplicate case-insensitive symbol name {:?}",
                symbol.name
            )));
        }
        if symbol.signature.trim().is_empty() {
            errors.push(provenance_error(format!(
                "LSP index symbol {:?} signature must be nonempty",
                symbol.name
            )));
        }
        if symbol.summary.trim().is_empty() {
            errors.push(provenance_error(format!(
                "LSP index symbol {:?} summary must be nonempty",
                symbol.name
            )));
        }
        if !(symbol.detail.is_null() || symbol.detail.as_str().is_some()) {
            errors.push(provenance_error(format!(
                "LSP index symbol {:?} detail must be a string or null",
                symbol.name
            )));
        }
        let Some(relative_source) = symbol.source.strip_prefix(&source_prefix) else {
            errors.push(provenance_error(format!(
                "LSP index symbol {:?} source must begin with {source_prefix:?}; got {:?}",
                symbol.name, symbol.source
            )));
            continue;
        };
        if !is_canonical_ledger_path(relative_source) {
            errors.push(provenance_error(format!(
                "LSP index symbol {:?} source is not canonical: {:?}",
                symbol.name, symbol.source
            )));
            continue;
        }
        match artifacts.get(relative_source) {
            Some(artifact) if artifact.kind == ArtifactKind::Markdown => {}
            Some(_) => errors.push(provenance_error(format!(
                "LSP index symbol {:?} source does not resolve to a ledgered Markdown artifact: {:?}",
                symbol.name, symbol.source
            ))),
            None => errors.push(provenance_error(format!(
                "LSP index symbol {:?} source is not present in the provenance ledger: {:?}",
                symbol.name, symbol.source
            ))),
        }

        match symbol.kind {
            LspSymbolKind::Builtin | LspSymbolKind::Command => {}
        }
        let _completion_enabled = symbol.completion;
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::path::PathBuf;
    use tempfile::TempDir;

    struct Fixture {
        _directory: TempDir,
        plugin: PathBuf,
        ledger: Value,
    }

    fn valid_fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let plugin = directory.path().join("plugin");
        let skill = plugin.join(AUTOLISP_SKILL_PLUGIN_PATH);
        let references = plugin.join(REFERENCE_ROOT_PLUGIN_PATH);
        std::fs::create_dir_all(&references).unwrap();

        let skill_bytes = b"---\nname: autolisp\ndescription: Test\n---\n# Skill\n";
        std::fs::write(skill.join("SKILL.md"), skill_bytes).unwrap();
        let guide = b"# Test guide\n";
        std::fs::write(references.join("guide.md"), guide).unwrap();
        let index = serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "symbols": [{
                "name": "sample",
                "kind": "builtin",
                "signature": "(sample)",
                "summary": "A sample symbol.",
                "detail": null,
                "source": "plugin/skills/autolisp/references/guide.md",
                "completion": true
            }]
        }))
        .unwrap();
        std::fs::write(skill.join(LSP_INDEX_PATH), &index).unwrap();

        let ledger = json!({
            "schema_version": 1,
            "reference_root": "plugin/skills/autolisp",
            "copyright_holder": "andagni",
            "license": "GPL-3.0-or-later",
            "sources": [{
                "id": "official-factual-reference",
                "title": "Official factual reference",
                "url": "https://example.test/reference",
                "version": "reviewed snapshot 1",
                "reviewed_on": "2026-07-26",
                "rights_basis": "facts_only_no_source_expression_redistributed"
            }],
            "artifacts": [
                {
                    "path": "SKILL.md",
                    "sha256": sha256_bytes(skill_bytes),
                    "kind": "markdown",
                    "disposition": "first_party_factual_synthesis",
                    "source_ids": ["official-factual-reference"]
                },
                {
                    "path": "references/autolisp-lsp-index.json",
                    "sha256": sha256_bytes(&index),
                    "kind": "autolisp_lsp_index",
                    "disposition": "first_party_curated_index",
                    "source_ids": ["official-factual-reference"]
                },
                {
                    "path": "references/guide.md",
                    "sha256": sha256_bytes(guide),
                    "kind": "markdown",
                    "disposition": "first_party_factual_synthesis",
                    "source_ids": ["official-factual-reference"]
                }
            ]
        });
        write_ledger(&references, &ledger);
        Fixture {
            _directory: directory,
            plugin,
            ledger,
        }
    }

    fn write_ledger(references: &Path, ledger: &Value) {
        std::fs::write(
            references.join("documentation-provenance.json"),
            serde_json::to_vec_pretty(ledger).unwrap(),
        )
        .unwrap();
    }

    fn references(fixture: &Fixture) -> PathBuf {
        fixture.plugin.join(REFERENCE_ROOT_PLUGIN_PATH)
    }

    fn error_text(plugin: &Path) -> String {
        validate_documentation_provenance(plugin).join("\n")
    }

    #[test]
    fn generic_plugin_without_autolisp_skill_does_not_require_ledger() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join("plugin/skills/other")).unwrap();

        assert!(validate_documentation_provenance(&directory.path().join("plugin")).is_empty());
    }

    #[test]
    fn valid_closed_fixture_passes() {
        let fixture = valid_fixture();
        assert!(
            validate_documentation_provenance(&fixture.plugin).is_empty(),
            "{}",
            error_text(&fixture.plugin)
        );
    }

    #[test]
    fn autolisp_skill_requires_ledger() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join("plugin/skills/autolisp/references"))
            .unwrap();

        let errors = error_text(&directory.path().join("plugin"));
        assert!(errors.contains("required ledger"), "{errors}");
    }

    #[test]
    fn autolisp_skill_requires_skill_entrypoint() {
        let fixture = valid_fixture();
        std::fs::remove_file(
            fixture
                .plugin
                .join(AUTOLISP_SKILL_PLUGIN_PATH)
                .join(SKILL_ENTRYPOINT_PATH),
        )
        .unwrap();

        let errors = error_text(&fixture.plugin);
        assert!(
            errors.contains("required AutoLISP skill entrypoint is missing"),
            "{errors}"
        );
    }

    #[test]
    fn added_markdown_fails_inventory_closure() {
        let fixture = valid_fixture();
        std::fs::write(references(&fixture).join("unreviewed.md"), "# New\n").unwrap();

        let errors = error_text(&fixture.plugin);
        assert!(
            errors.contains(
                "shipped reference is absent from the ledger: \"references/unreviewed.md\""
            ),
            "{errors}"
        );
    }

    #[test]
    fn strict_validation_rejects_a_file_not_admitted_by_the_package_projection() {
        let fixture = valid_fixture();
        std::fs::write(references(&fixture).join("unreviewed.json"), b"{}\n").unwrap();

        let errors = error_text(&fixture.plugin);
        assert!(
            errors.contains(
                "unapproved file exists below the AutoLISP skill: \
                 \"references/unreviewed.json\""
            ),
            "{errors}"
        );
        assert!(
            validate_documentation_provenance_for_package_source(&fixture.plugin).is_empty(),
            "package-source validation should ignore files the copy allowlist will omit"
        );
    }

    #[test]
    fn changed_bytes_fail_digest_binding() {
        let fixture = valid_fixture();
        std::fs::write(references(&fixture).join("guide.md"), "# Changed\n").unwrap();

        let errors = error_text(&fixture.plugin);
        assert!(
            errors.contains("artifact \"references/guide.md\" byte digest mismatch"),
            "{errors}"
        );
    }

    #[test]
    fn missing_declared_file_fails_closed() {
        let fixture = valid_fixture();
        std::fs::remove_file(references(&fixture).join("guide.md")).unwrap();

        let errors = error_text(&fixture.plugin);
        assert!(
            errors.contains("cannot read declared artifact \"references/guide.md\""),
            "{errors}"
        );
        assert!(
            errors.contains(
                "ledger artifact is not a shipped reference file: \"references/guide.md\""
            ),
            "{errors}"
        );
    }

    #[test]
    fn index_source_must_resolve_to_ledgered_markdown() {
        let mut fixture = valid_fixture();
        let index = serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "symbols": [{
                "name": "sample",
                "kind": "builtin",
                "signature": "(sample)",
                "summary": "A sample symbol.",
                "detail": null,
                "source": "plugin/skills/autolisp/references/not-ledgered.md",
                "completion": true
            }]
        }))
        .unwrap();
        std::fs::write(
            fixture
                .plugin
                .join(AUTOLISP_SKILL_PLUGIN_PATH)
                .join(LSP_INDEX_PATH),
            &index,
        )
        .unwrap();
        fixture.ledger["artifacts"][1]["sha256"] = json!(sha256_bytes(&index));
        write_ledger(&references(&fixture), &fixture.ledger);

        let errors = error_text(&fixture.plugin);
        assert!(
            errors.contains("source is not present in the provenance ledger"),
            "{errors}"
        );
    }

    #[test]
    fn unknown_ledger_field_is_rejected() {
        let mut fixture = valid_fixture();
        fixture.ledger["unreviewed"] = json!(true);
        write_ledger(&references(&fixture), &fixture.ledger);

        let errors = error_text(&fixture.plugin);
        assert!(
            errors.contains("ledger is not valid closed-schema JSON"),
            "{errors}"
        );
        assert!(errors.contains("unknown field `unreviewed`"), "{errors}");
    }

    #[test]
    fn unknown_disposition_is_rejected() {
        let mut fixture = valid_fixture();
        fixture.ledger["artifacts"][2]["disposition"] = json!("pending");
        write_ledger(&references(&fixture), &fixture.ledger);

        let errors = error_text(&fixture.plugin);
        assert!(
            errors.contains("ledger is not valid closed-schema JSON"),
            "{errors}"
        );
        assert!(errors.contains("unknown variant `pending`"), "{errors}");
    }

    #[test]
    fn curated_index_requires_external_factual_sources() {
        let mut fixture = valid_fixture();
        fixture.ledger["artifacts"][1]["source_ids"] = json!([]);
        write_ledger(&references(&fixture), &fixture.ledger);

        let errors = error_text(&fixture.plugin);
        assert!(
            errors.contains("curated index") && errors.contains("requires external factual source"),
            "{errors}"
        );
    }
}
