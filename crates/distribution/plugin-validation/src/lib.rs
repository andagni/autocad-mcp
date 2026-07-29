mod documentation_provenance;

pub use documentation_provenance::{
    validate_documentation_provenance, validate_documentation_provenance_for_package_source,
    DOCUMENTATION_PROVENANCE_PLUGIN_PATH,
};

use std::collections::BTreeSet;
use std::path::Path;

/// Permitted top-level entries under a plugin directory, per the Claude Code
/// plugin layout accepted by the package source policy.
const PERMITTED_TOP_LEVEL: &[&str] = &[
    ".claude-plugin",
    "skills",
    "bin",
    ".mcp.json",
    ".lsp.json",
    "LICENSE",
    "THIRD_PARTY_LICENSES.txt",
    ".third-party",
    "owner-distribution-approval.schema.json",
    "CHANGELOG.md",
];

const MACHINE_EVIDENCE_DIRECTORY: &str = ".third-party";
const PERMITTED_MACHINE_EVIDENCE_FILES: &[&str] = &[
    "third-party-license-policy.json",
    "third-party-license-provenance.json",
    "source-lock.spdx.json",
    "source-closure-windows.spdx.json",
];
const SOURCE_ONLY_LICENSE_SUPPLEMENTS: &str = "license-supplements";
const PERMITTED_SOURCE_SUPPLEMENT_ENTRIES: &[&str] = &[".gitignore", "rmcp-1.7.0-LICENSE.txt"];
const PACKAGED_ONLY_RESOURCES: &str = "resources";

/// Reject any top-level entry under `plugin_dir` that is not part of the
/// permitted plugin layout.
pub fn validate_structure(plugin_dir: &Path) -> Vec<String> {
    validate_structure_with_scope(plugin_dir, true)
}

/// Reject entries which are not part of a finished packaged plugin.
///
/// Source-only third-party licence supplements are consumed into the bound
/// `THIRD_PARTY_LICENSES.txt` bundle and must not be copied into an MCPB.
pub fn validate_packaged_structure(plugin_dir: &Path) -> Vec<String> {
    validate_structure_with_scope(plugin_dir, false)
}

fn validate_structure_with_scope(plugin_dir: &Path, allow_source_supplements: bool) -> Vec<String> {
    let mut errs = Vec::new();
    let entries = match std::fs::read_dir(plugin_dir) {
        Ok(e) => e,
        Err(e) => {
            return vec![format!(
                "cannot read plugin dir {}: {e}",
                plugin_dir.display()
            )]
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errs.push(format!(
                    "cannot enumerate plugin dir {}: {error}",
                    plugin_dir.display()
                ));
                continue;
            }
        };
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(name) => {
                errs.push(format!(
                    "plugin top-level entry name is not UTF-8: {:?}",
                    name
                ));
                continue;
            }
        };
        if name == ".DS_Store" || name == ".gitignore" {
            continue;
        }
        if name == MACHINE_EVIDENCE_DIRECTORY {
            errs.extend(validate_machine_evidence(
                &entry.path(),
                allow_source_supplements,
            ));
            continue;
        }
        if name == PACKAGED_ONLY_RESOURCES {
            if allow_source_supplements {
                errs.push(format!(
                    "packaged-only top-level entry '{name}' must not be present in plugin source"
                ));
            }
            continue;
        }
        if !PERMITTED_TOP_LEVEL.contains(&name.as_str()) {
            errs.push(format!(
                "disallowed top-level entry '{name}' (not in the permitted plugin layout)"
            ));
        }
    }
    errs.extend(validate_no_owner_approval_instance(plugin_dir));
    errs
}

fn validate_machine_evidence(path: &Path, allow_source_supplements: bool) -> Vec<String> {
    let directory_metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return vec![format!(
                "cannot inspect machine evidence directory {}: {error}",
                path.display()
            )]
        }
    };
    if directory_metadata.file_type().is_symlink() || !directory_metadata.file_type().is_dir() {
        return vec![format!(
            "machine evidence path must be a non-symlink directory: {}",
            path.display()
        )];
    }

    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => {
            return vec![format!(
                "cannot read machine evidence directory {}: {error}",
                path.display()
            )]
        }
    };
    let mut errors = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!(
                    "cannot enumerate machine evidence directory {}: {error}",
                    path.display()
                ));
                continue;
            }
        };
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(name) => {
                errors.push(format!(
                    "machine evidence entry name is not UTF-8: {:?}",
                    name
                ));
                continue;
            }
        };
        if name == SOURCE_ONLY_LICENSE_SUPPLEMENTS {
            if allow_source_supplements {
                errors.extend(validate_source_supplements(&entry.path()));
            } else {
                errors.push(format!(
                    "source-only machine evidence entry '{name}' must not be present in a packaged plugin"
                ));
            }
            continue;
        }
        if name == ".gitignore" {
            if !allow_source_supplements {
                errors.push(
                    "source-only machine evidence entry '.gitignore' must not be present in a packaged plugin"
                        .to_owned(),
                );
            }
            continue;
        }
        if !PERMITTED_MACHINE_EVIDENCE_FILES.contains(&name.as_str()) {
            errors.push(format!(
                "disallowed machine evidence entry '{name}' (not in the exact evidence allowlist)"
            ));
            continue;
        }
        let metadata = match std::fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) => {
                errors.push(format!(
                    "cannot inspect machine evidence entry '{name}': {error}"
                ));
                continue;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            errors.push(format!(
                "machine evidence entry '{name}' must be a regular non-symlink file"
            ));
        }
    }
    errors
}

fn validate_source_supplements(path: &Path) -> Vec<String> {
    let directory_metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return vec![format!(
                "cannot inspect source-only third-party licence supplements {}: {error}",
                path.display()
            )]
        }
    };
    if directory_metadata.file_type().is_symlink() || !directory_metadata.file_type().is_dir() {
        return vec![format!(
            "source-only third-party licence supplements path must be a non-symlink directory: {}",
            path.display()
        )];
    }
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => {
            return vec![format!(
                "cannot read source-only third-party licence supplements {}: {error}",
                path.display()
            )]
        }
    };
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!(
                    "cannot enumerate source-only third-party licence supplements {}: {error}",
                    path.display()
                ));
                continue;
            }
        };
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(name) => {
                errors.push(format!(
                    "third-party licence supplement name is not UTF-8: {:?}",
                    name
                ));
                continue;
            }
        };
        if !PERMITTED_SOURCE_SUPPLEMENT_ENTRIES.contains(&name.as_str()) {
            errors.push(format!(
                "disallowed third-party licence supplement '{name}' (not in the exact source-evidence allowlist)"
            ));
            continue;
        }
        seen.insert(name.clone());
        let metadata = match std::fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) => {
                errors.push(format!(
                    "cannot inspect third-party licence supplement '{name}': {error}"
                ));
                continue;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            errors.push(format!(
                "third-party licence supplement '{name}' must be a regular non-symlink file"
            ));
        }
    }
    let expected = PERMITTED_SOURCE_SUPPLEMENT_ENTRIES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let actual = seen.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        errors.push(format!(
            "third-party licence supplement entries must exactly equal {:?}",
            PERMITTED_SOURCE_SUPPLEMENT_ENTRIES
        ));
    }
    errors
}

fn validate_no_owner_approval_instance(plugin_dir: &Path) -> Vec<String> {
    let mut errors = Vec::new();
    for entry in walkdir::WalkDir::new(plugin_dir).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!(
                    "cannot traverse plugin tree while excluding detached approvals: {error}"
                ));
                continue;
            }
        };
        if entry.file_type().is_symlink() {
            let relative = entry
                .path()
                .strip_prefix(plugin_dir)
                .unwrap_or_else(|_| entry.path());
            errors.push(format!(
                "plugin tree must not contain symlinks: {}",
                relative.display()
            ));
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let has_json_extension = entry
            .path()
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
        let bytes = match std::fs::read(entry.path()) {
            Ok(bytes) => bytes,
            Err(error) => {
                errors.push(format!(
                    "cannot read plugin file while excluding detached approvals {}: {error}",
                    entry.path().display()
                ));
                continue;
            }
        };
        let looks_like_json_object = bytes
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())
            == Some(b'{');
        if !has_json_extension && !looks_like_json_object {
            continue;
        }
        let value = match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(value) => value,
            Err(error) => {
                if has_json_extension {
                    errors.push(format!(
                        "cannot parse plugin JSON while excluding detached approvals {}: {error}",
                        entry.path().display()
                    ));
                }
                continue;
            }
        };
        if value.get("kind").and_then(serde_json::Value::as_str)
            == Some("owner_distribution_approval")
        {
            let relative = entry
                .path()
                .strip_prefix(plugin_dir)
                .unwrap_or_else(|_| entry.path());
            errors.push(format!(
                "detached owner-distribution approval instance must not be present in plugin tree: {}",
                relative.display()
            ));
        }
    }
    errors
}

/// Validate a plugin JSON file, deriving its relative path from `plugin_dir`.
pub fn validate_json_file(plugin_file: &Path, schema_root: &Path) -> Vec<String> {
    // Derive the plugin-relative path by stripping the leading "plugin/" segment
    // if present; otherwise use the file name. Callers with a known relative path
    // should use validate_json_file_rel.
    let rel = plugin_file
        .components()
        .skip_while(|c| c.as_os_str() != "plugin")
        .skip(1)
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    validate_json_file_rel(plugin_file, &rel, schema_root)
}

/// Validate a JSON file at `abs_path` whose plugin-relative path is `rel_path`.
pub fn validate_json_file_rel(abs_path: &Path, rel_path: &str, schema_root: &Path) -> Vec<String> {
    let Some(schema_rel) = schema_for_json(rel_path) else {
        return Vec::new(); // no governing schema → not our concern
    };
    let schema_path = schema_root.join(schema_rel);

    let schema_text = match std::fs::read_to_string(&schema_path) {
        Ok(t) => t,
        Err(e) => return vec![format!("{rel_path}: cannot read schema {schema_rel}: {e}")],
    };
    let schema: serde_json::Value = match serde_json::from_str(&schema_text) {
        Ok(v) => v,
        Err(e) => {
            return vec![format!(
                "{rel_path}: schema {schema_rel} is not valid JSON: {e}"
            )]
        }
    };
    let validator = match jsonschema::validator_for(&schema) {
        Ok(v) => v,
        Err(e) => {
            return vec![format!(
                "{rel_path}: cannot compile schema {schema_rel}: {e}"
            )]
        }
    };

    let doc_text = match std::fs::read_to_string(abs_path) {
        Ok(t) => t,
        Err(e) => return vec![format!("{rel_path}: cannot read file: {e}")],
    };
    let instance: serde_json::Value = match serde_json::from_str(&doc_text) {
        Ok(v) => v,
        Err(e) => return vec![format!("{rel_path}: not valid JSON: {e}")],
    };

    validator
        .iter_errors(&instance)
        .map(|e| {
            format!(
                "{rel_path}: schema violation at '{}': {e}",
                e.instance_path()
            )
        })
        .collect()
}

/// Result of validating a plugin tree.
#[derive(Default)]
pub struct Report {
    pub errors: usize,
}

/// Walk `plugin_dir` and validate every JSON document and markdown frontmatter
/// that has a governing schema. (Directory-structure checks are added in later tasks.)
pub fn validate_plugin(plugin_dir: &Path, schema_root: &Path) -> Report {
    validate_plugin_with_scope(plugin_dir, schema_root, true)
}

/// Validate the finished plugin tree which will be archived into an MCPB.
pub fn validate_packaged_plugin(plugin_dir: &Path, schema_root: &Path) -> Report {
    validate_plugin_with_scope(plugin_dir, schema_root, false)
}

fn validate_plugin_with_scope(
    plugin_dir: &Path,
    schema_root: &Path,
    allow_source_supplements: bool,
) -> Report {
    let mut report = Report::default();
    let structure_errors = if allow_source_supplements {
        validate_structure(plugin_dir)
    } else {
        validate_packaged_structure(plugin_dir)
    };
    for err in structure_errors {
        println!("ERROR: {err}");
        report.errors += 1;
    }
    for err in validate_documentation_provenance(plugin_dir) {
        println!("ERROR: {err}");
        report.errors += 1;
    }
    for entry in walkdir::WalkDir::new(plugin_dir) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                println!("ERROR: cannot traverse plugin tree for document validation: {error}");
                report.errors += 1;
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let rel = path
                .strip_prefix(plugin_dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            for err in validate_json_file_rel(path, &rel, schema_root) {
                println!("ERROR: {err}");
                report.errors += 1;
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("md") {
            let rel = path
                .strip_prefix(plugin_dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            for err in validate_markdown_file_rel(path, &rel, schema_root) {
                println!("ERROR: {err}");
                report.errors += 1;
            }
        }
    }
    report
}

/// Map a plugin-relative markdown path to the schema-root-relative
/// `.schema.yaml` governing its frontmatter, or `None`.
pub fn schema_for_markdown(rel_path: &str) -> Option<&'static str> {
    let norm = rel_path.replace('\\', "/");
    let segs: Vec<&str> = norm.split('/').collect();
    match segs.as_slice() {
        // skills/<name>/SKILL.md  (only the top-level SKILL.md, not references/*)
        ["skills", _name, "SKILL.md"] => Some("skills/skill/SKILL.schema.yaml"),
        _ => None,
    }
}

/// Extract the YAML frontmatter between leading `---` fences.
pub fn extract_frontmatter(md: &str) -> Option<String> {
    let rest = md
        .strip_prefix("---\n")
        .or_else(|| md.strip_prefix("---\r\n"))?;
    // Find the closing fence at the start of a line.
    // rest.find("\n---") returns the index of the '\n' before the closing fence;
    // we include that newline so the returned string ends with '\n'.
    let end = rest.find("\n---").map(|i| i + 1).or_else(|| {
        if rest.starts_with("---") {
            Some(0)
        } else {
            None
        }
    })?;
    Some(rest[..end].to_string())
}

/// Validate a markdown file's frontmatter at `abs_path` (plugin-relative `rel_path`).
pub fn validate_markdown_file_rel(
    abs_path: &Path,
    rel_path: &str,
    schema_root: &Path,
) -> Vec<String> {
    let Some(schema_rel) = schema_for_markdown(rel_path) else {
        return Vec::new();
    };
    let md = match std::fs::read_to_string(abs_path) {
        Ok(t) => t,
        Err(e) => return vec![format!("{rel_path}: cannot read file: {e}")],
    };
    let Some(fm) = extract_frontmatter(&md) else {
        return Vec::new(); // no frontmatter → nothing to validate
    };

    let schema_text = match std::fs::read_to_string(schema_root.join(schema_rel)) {
        Ok(t) => t,
        Err(e) => return vec![format!("{rel_path}: cannot read schema {schema_rel}: {e}")],
    };
    let schema: serde_json::Value = match serde_yaml::from_str(&schema_text) {
        Ok(v) => v,
        Err(e) => {
            return vec![format!(
                "{rel_path}: schema {schema_rel} is not valid YAML: {e}"
            )]
        }
    };
    let validator = match jsonschema::validator_for(&schema) {
        Ok(v) => v,
        Err(e) => {
            return vec![format!(
                "{rel_path}: cannot compile schema {schema_rel}: {e}"
            )]
        }
    };
    let instance: serde_json::Value = match serde_yaml::from_str(&fm) {
        Ok(v) => v,
        Err(e) => return vec![format!("{rel_path}: frontmatter is not valid YAML: {e}")],
    };

    validator
        .iter_errors(&instance)
        .map(|e| {
            format!(
                "{rel_path}: frontmatter violation at '{}': {e}",
                e.instance_path()
            )
        })
        .collect()
}

/// Map a plugin-relative JSON file path to the schema-root-relative
/// `.schema.json` that governs it, or `None` if no schema applies.
pub fn schema_for_json(rel_path: &str) -> Option<&'static str> {
    let norm = rel_path.replace('\\', "/");
    match norm.as_str() {
        ".claude-plugin/plugin.json" => Some(".claude-plugin/plugin.schema.json"),
        ".mcp.json" => Some(".mcp.schema.json"),
        ".lsp.json" => Some(".lsp.schema.json"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_skill_markdown() {
        assert_eq!(
            schema_for_markdown("skills/autocad-mcp/SKILL.md"),
            Some("skills/skill/SKILL.schema.yaml")
        );
        assert_eq!(
            schema_for_markdown("skills/autolisp/references/README.md"),
            None
        );
    }

    #[test]
    fn extracts_frontmatter_block() {
        let md = "---\nname: x\ndescription: y\n---\n\n# Body\n";
        assert_eq!(
            extract_frontmatter(md).as_deref(),
            Some("name: x\ndescription: y\n")
        );
        assert_eq!(extract_frontmatter("# no frontmatter\n"), None);
    }

    #[test]
    fn skill_frontmatter_with_version_is_rejected() {
        // SKILL.schema.yaml sets additionalProperties: false and has no `version`.
        let dir = std::env::temp_dir().join("plugin-validate-fm-test/skills/s");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("SKILL.md");
        std::fs::write(&f, "---\nname: s\nversion: 1.0.0\n---\n# body\n").unwrap();
        let schema_root = repo_root().join("tests/fixtures/plugin-example");
        let errs = validate_markdown_file_rel(&f, "skills/s/SKILL.md", &schema_root);
        assert!(
            errs.iter().any(|e| e.contains("version")),
            "expected a 'version' additionalProperties error, got: {errs:?}"
        );
    }

    #[test]
    fn maps_known_json_paths() {
        assert_eq!(
            schema_for_json(".claude-plugin/plugin.json"),
            Some(".claude-plugin/plugin.schema.json")
        );
        assert_eq!(schema_for_json(".mcp.json"), Some(".mcp.schema.json"));
        assert_eq!(schema_for_json(".lsp.json"), Some(".lsp.schema.json"));
    }

    #[test]
    fn removed_schema_surfaces_are_not_mapped() {
        assert_eq!(schema_for_json("themes/theme.json"), None);
        assert_eq!(schema_for_json("settings.json"), None);
        assert_eq!(schema_for_json("hooks/hooks.json"), None);
        assert_eq!(schema_for_markdown("commands/example.md"), None);
        assert_eq!(schema_for_markdown("agents/example.md"), None);
        assert_eq!(schema_for_markdown("output-styles/example.md"), None);
    }

    #[test]
    fn valid_plugin_json_has_no_errors() {
        let root = repo_root();
        let plugin_json = root.join("plugin/.claude-plugin/plugin.json");
        let schema_root = root.join("tests/fixtures/plugin-example");
        let errs = validate_json_file(&plugin_json, &schema_root);
        assert!(errs.is_empty(), "expected valid, got: {errs:?}");
    }

    #[test]
    fn repo_lsp_config_validates() {
        let root = repo_root();
        let lsp_json = root.join("plugin/.lsp.json");
        let schema_root = root.join("tests/fixtures/plugin-example");
        let errs = validate_json_file_rel(&lsp_json, ".lsp.json", &schema_root);
        assert!(errs.is_empty(), "expected valid .lsp.json, got: {errs:?}");
    }

    #[test]
    fn empty_json_file_reports_error() {
        let dir = std::env::temp_dir().join("plugin-validate-empty-test");
        std::fs::create_dir_all(dir.join(".claude-plugin")).unwrap();
        let f = dir.join(".claude-plugin/plugin.json");
        std::fs::write(&f, "").unwrap();
        let schema_root = repo_root().join("tests/fixtures/plugin-example");
        // Place the file under a fake plugin dir so the relative path resolves.
        let errs = validate_json_file_rel(&f, ".claude-plugin/plugin.json", &schema_root);
        assert!(!errs.is_empty(), "empty JSON must error");
    }

    #[test]
    fn rejects_unknown_top_level_entry() {
        let dir = std::env::temp_dir().join("plugin-validate-struct-test");
        std::fs::create_dir_all(dir.join("skils")).unwrap(); // deliberate typo
        std::fs::create_dir_all(dir.join("skills")).unwrap();
        let errs = validate_structure(&dir);
        assert!(errs.iter().any(|e| e.contains("skils")), "got: {errs:?}");
        assert!(!errs.iter().any(|e| e.contains("\"skills\"")));
    }

    #[test]
    fn rejects_unknown_machine_evidence_entry() {
        let dir = tempfile::tempdir().unwrap();
        let evidence = dir.path().join(MACHINE_EVIDENCE_DIRECTORY);
        std::fs::create_dir(&evidence).unwrap();
        std::fs::write(evidence.join("unreviewed.json"), "{}\n").unwrap();

        let errors = validate_structure(dir.path());
        assert!(
            errors.iter().any(|error| {
                error.contains("disallowed machine evidence entry 'unreviewed.json'")
            }),
            "{errors:?}"
        );
    }

    #[test]
    fn accepts_known_top_level_entries() {
        let dir = std::env::temp_dir().join("plugin-validate-struct-ok");
        let _ = std::fs::remove_dir_all(&dir);
        for d in [".claude-plugin", "skills", "bin"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::fs::write(dir.join(".mcp.json"), "{}").unwrap();
        std::fs::write(dir.join(".lsp.json"), "{}").unwrap();
        std::fs::write(dir.join("LICENSE"), "").unwrap();
        std::fs::create_dir_all(dir.join(".third-party/license-supplements")).unwrap();
        std::fs::write(dir.join(".third-party/.gitignore"), "*\n").unwrap();
        std::fs::write(
            dir.join(".third-party/third-party-license-policy.json"),
            "{}",
        )
        .unwrap();
        std::fs::write(
            dir.join(".third-party/third-party-license-provenance.json"),
            "{}",
        )
        .unwrap();
        std::fs::write(dir.join(".third-party/source-lock.spdx.json"), "{}").unwrap();
        std::fs::write(
            dir.join(".third-party/source-closure-windows.spdx.json"),
            "{}",
        )
        .unwrap();
        std::fs::write(
            dir.join(".third-party/license-supplements/.gitignore"),
            "*\n",
        )
        .unwrap();
        std::fs::write(
            dir.join(".third-party/license-supplements/rmcp-1.7.0-LICENSE.txt"),
            "licence\n",
        )
        .unwrap();
        std::fs::write(dir.join("owner-distribution-approval.schema.json"), "{}").unwrap();
        std::fs::write(dir.join("THIRD_PARTY_LICENSES.txt"), "").unwrap();
        let errs = validate_structure(&dir);
        assert!(errs.is_empty(), "expected clean, got: {errs:?}");
    }

    #[test]
    fn source_supplements_have_an_exact_allowlist_and_are_forbidden_in_packages() {
        let dir = tempfile::tempdir().unwrap();
        let supplements = dir
            .path()
            .join(MACHINE_EVIDENCE_DIRECTORY)
            .join(SOURCE_ONLY_LICENSE_SUPPLEMENTS);
        std::fs::create_dir_all(&supplements).unwrap();
        std::fs::write(supplements.join(".gitignore"), "*\n").unwrap();
        std::fs::write(supplements.join("rmcp-1.7.0-LICENSE.txt"), "licence\n").unwrap();
        assert!(validate_structure(dir.path()).is_empty());

        let package_errors = validate_packaged_structure(dir.path());
        assert!(
            package_errors
                .iter()
                .any(|error| error.contains("must not be present in a packaged plugin")),
            "{package_errors:?}"
        );

        std::fs::write(supplements.join("unreviewed.txt"), "no\n").unwrap();
        let source_errors = validate_structure(dir.path());
        assert!(
            source_errors
                .iter()
                .any(|error| error.contains("not in the exact source-evidence allowlist")),
            "{source_errors:?}"
        );

        std::fs::remove_file(supplements.join("unreviewed.txt")).unwrap();
        std::fs::remove_file(supplements.join(".gitignore")).unwrap();
        let missing_errors = validate_structure(dir.path());
        assert!(
            missing_errors
                .iter()
                .any(|error| error.contains("must exactly equal")),
            "{missing_errors:?}"
        );
    }

    #[test]
    fn packaged_resources_are_admitted_without_expanding_the_source_layout() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(PACKAGED_ONLY_RESOURCES)).unwrap();

        let source_errors = validate_structure(dir.path());
        assert!(
            source_errors
                .iter()
                .any(|error| { error.contains("packaged-only top-level entry 'resources'") }),
            "{source_errors:?}"
        );
        assert!(validate_packaged_structure(dir.path()).is_empty());
    }

    #[test]
    fn detached_owner_approval_instances_are_rejected_at_any_plugin_depth() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("skills/autocad-mcp");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("release-approval.JSON"),
            r#"{"schema_version":2,"kind":"owner_distribution_approval"}"#,
        )
        .unwrap();

        let errors = validate_packaged_structure(dir.path());
        assert!(
            errors
                .iter()
                .any(|error| error.contains("approval instance must not be present")),
            "{errors:?}"
        );
    }

    #[test]
    fn extensionless_detached_owner_approval_instance_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("skills/autolisp/references")).unwrap();
        std::fs::write(
            dir.path()
                .join("skills/autolisp/references/release-approval"),
            r#"{"schema_version":2,"kind":"owner_distribution_approval"}"#,
        )
        .unwrap();

        let errors = validate_no_owner_approval_instance(dir.path());
        assert!(
            errors
                .iter()
                .any(|error| error.contains("approval instance must not be present")),
            "{errors:?}"
        );
    }

    #[test]
    fn approval_scan_fails_closed_on_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(MACHINE_EVIDENCE_DIRECTORY)).unwrap();
        std::fs::write(
            dir.path()
                .join(".third-party/third-party-license-policy.json"),
            b"{",
        )
        .unwrap();
        let errors = validate_packaged_structure(dir.path());
        assert!(
            errors
                .iter()
                .any(|error| error.contains("cannot parse plugin JSON")),
            "{errors:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn approval_scan_and_supplement_contract_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        std::fs::write(&target, "{}\n").unwrap();
        std::fs::create_dir(dir.path().join(MACHINE_EVIDENCE_DIRECTORY)).unwrap();
        symlink(
            &target,
            dir.path()
                .join(".third-party/third-party-license-policy.json"),
        )
        .unwrap();
        let errors = validate_packaged_structure(dir.path());
        assert!(
            errors
                .iter()
                .any(|error| error.contains("must not contain symlinks")),
            "{errors:?}"
        );

        let source = tempfile::tempdir().unwrap();
        let supplements = source
            .path()
            .join(MACHINE_EVIDENCE_DIRECTORY)
            .join(SOURCE_ONLY_LICENSE_SUPPLEMENTS);
        std::fs::create_dir_all(&supplements).unwrap();
        std::fs::write(supplements.join(".gitignore"), "*\n").unwrap();
        symlink(&target, supplements.join("rmcp-1.7.0-LICENSE.txt")).unwrap();
        let errors = validate_structure(source.path());
        assert!(
            errors
                .iter()
                .any(|error| error.contains("regular non-symlink file")),
            "{errors:?}"
        );
    }

    #[test]
    fn removed_schema_tree_surfaces_are_rejected_structurally() {
        let dir = std::env::temp_dir().join("plugin-validate-removed-surfaces");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for entry in ["commands", "agents", "hooks", "scripts", "settings.json"] {
            let path = dir.join(entry);
            if entry.ends_with(".json") {
                std::fs::write(path, "{}").unwrap();
            } else {
                std::fs::create_dir(path).unwrap();
            }
        }
        let errs = validate_structure(&dir);
        assert_eq!(errs.len(), 5, "got: {errs:?}");
    }

    #[test]
    fn ignores_local_gitignore_at_plugin_root() {
        let dir = std::env::temp_dir().join("plugin-validate-gitignore-root");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".gitignore"), "*\n").unwrap();

        let errs = validate_structure(&dir);
        assert!(errs.is_empty(), "expected clean, got: {errs:?}");
    }

    #[test]
    fn command_line_validation_accepts_repo_plugin_with_local_gitignore() {
        let root = repo_root();
        let plugin_dir = root.join("plugin");
        let schema_root = root.join("tests/fixtures/plugin-example");
        let report = validate_plugin(&plugin_dir, &schema_root);
        assert_eq!(report.errors, 0);
    }

    fn repo_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .find(|candidate| {
                std::fs::read_to_string(candidate.join("Cargo.toml"))
                    .map(|manifest| manifest.lines().any(|line| line.trim() == "[workspace]"))
                    .unwrap_or(false)
            })
            .expect("plugin-validate must be contained by a Cargo workspace")
            .to_path_buf()
    }
}
