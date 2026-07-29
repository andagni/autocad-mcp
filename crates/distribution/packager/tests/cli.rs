use release_packager::manifest::{
    manifest_for, McpbManifest, PackageTarget, PluginMetadata, DEPENDENCY_LICENSE_POLICY,
    DEPENDENCY_LICENSE_PROVENANCE, DEPENDENCY_SOURCE_LOCK_SBOM,
    DEPENDENCY_WINDOWS_SOURCE_CLOSURE_SBOM, OWNER_DISTRIBUTION_APPROVAL_SCHEMA,
    PROJECT_LICENSE_TEXT, THIRD_PARTY_LICENSES,
};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use zip::write::SimpleFileOptions as FileOptions;
use zip::ZipArchive;

const TEST_AUTOLISP_SKILL: &[u8] = b"# Test AutoLISP skill\n";
const TEST_AUTOLISP_GUIDE: &[u8] = b"# Test guide\n";
const TEST_AUTOLISP_INDEX: &[u8] = br#"{"schema_version":1,"symbols":[{"name":"sample","kind":"builtin","signature":"(sample)","summary":"A sample symbol.","detail":null,"source":"plugin/skills/autolisp/references/guide.md","completion":true}]}"#;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_release-packager"))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|candidate| {
            std::fs::read_to_string(candidate.join("Cargo.toml"))
                .map(|manifest| manifest.lines().any(|line| line.trim() == "[workspace]"))
                .unwrap_or(false)
        })
        .expect("release-packager must be contained by a Cargo workspace")
        .to_path_buf()
}

fn metadata() -> PluginMetadata {
    PluginMetadata {
        name: "autocad-mcp".to_string(),
        version: "0.0.1".to_string(),
        description: "A rust-backed AutoLISP MCP".to_string(),
        license: "GPL-3.0-or-later".to_string(),
        author_name: "andagni".to_string(),
    }
}

#[cfg(unix)]
fn write_release_introspection_binary(path: &Path) {
    let build_identity = autocad_mcp::certification::xref_certification_build_identity();
    let certified_arg_sha256 =
        autocad_mcp::ops::xref_runtime::certified_arg_sha256_build_value().map(str::to_owned);
    let certified_arg_policy_id = (!build_identity.certified_arg_policy_id.is_empty())
        .then_some(build_identity.certified_arg_policy_id.clone());
    let certified_arg_policy_sha256 = (!build_identity.certified_arg_policy_sha256.is_empty())
        .then_some(build_identity.certified_arg_policy_sha256.clone());
    let activation_catalogue_sha256 =
        autocad_mcp::activation::activation_catalogue_sha256().unwrap();
    let info = serde_json::json!({
        "schema_version": 4,
        "experimental_support": false,
        "activation_catalogue_sha256": activation_catalogue_sha256,
        "certified_arg_sha256": certified_arg_sha256,
        "certified_arg_policy_id": certified_arg_policy_id,
        "certified_arg_policy_sha256": certified_arg_policy_sha256,
        "certification_failpoints_enabled":
            build_identity.certification_failpoints_enabled,
        "crt_linkage": autocad_mcp::certification::xref_certification_crt_linkage(),
        "artifact_sha256":
            autocad_mcp::certification::xref_embedded_artifact_sha256(),
        "title_block_profile_registry_sha256":
            autocad_mcp::ops::profiles::title_block_profile_registry_sha256(),
        "title_block_profiles":
            autocad_mcp::certification::embedded_certification_profile_definitions(),
        "build_identity": build_identity,
        "xref_mutation_tools": [
            "attach_xref",
            "bind_xref",
            "delete_xref_instance",
            "detach_xref",
            "insert_xref_instance",
            "reload_xref",
            "unload_xref",
            "update_xref",
            "update_xref_instance"
        ],
    });
    let tools = info["xref_mutation_tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| serde_json::json!({"name": name}))
        .collect::<Vec<_>>();
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\n  xref-certification-info) printf '%s\\n' '{}' ;;\n  list-tools) [ \"$2\" = \"--experimental\" ] && exit 2; printf '%s\\n' '{}' ;;\n  *) exit 2 ;;\nesac\n",
        serde_json::to_string(&info).unwrap(),
        serde_json::to_string(&tools).unwrap(),
    );
    std::fs::write(path, script).unwrap();
}

fn write_static_package(path: &Path, manifest: &McpbManifest) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);
    let executable_options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);

    let manifest_json = serde_json::to_vec_pretty(manifest).unwrap();
    zip.start_file("manifest.json", options).unwrap();
    zip.write_all(&manifest_json).unwrap();
    zip.start_file("plugin/.claude-plugin/plugin.json", options)
        .unwrap();
    zip.write_all(br#"{"name":"autocad-mcp","description":"A rust-backed AutoLISP MCP","version":"0.0.1","license":"GPL-3.0-or-later","author":{"name":"andagni"}}"#)
        .unwrap();
    zip.start_file("plugin/.mcp.json", options).unwrap();
    zip.write_all(
        br#"{"mcpServers":{"autocad-mcp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autocad-mcp","args":["serve"]}}}"#,
    )
    .unwrap();
    zip.start_file("plugin/skills/autocad-mcp/SKILL.md", options)
        .unwrap();
    zip.write_all(b"# Test\n").unwrap();
    zip.start_file("plugin/skills/autolisp/SKILL.md", options)
        .unwrap();
    zip.write_all(TEST_AUTOLISP_SKILL).unwrap();
    zip.start_file(
        "plugin/skills/autolisp/references/autolisp-lsp-index.json",
        options,
    )
    .unwrap();
    zip.write_all(TEST_AUTOLISP_INDEX).unwrap();
    zip.start_file("plugin/skills/autolisp/references/guide.md", options)
        .unwrap();
    zip.write_all(TEST_AUTOLISP_GUIDE).unwrap();
    let documentation_provenance = serde_json::json!({
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
                "sha256": "9c926f17931718c628fba1428e9a9814dc6c7d5bb992eedec1d0cc2fa291032e",
                "kind": "markdown",
                "disposition": "first_party_factual_synthesis",
                "source_ids": ["official-factual-reference"]
            },
            {
                "path": "references/autolisp-lsp-index.json",
                "sha256": "c82abc308084f214b4f52882e4d0bdd702670915eac8a5c199a3022969e6d7dd",
                "kind": "autolisp_lsp_index",
                "disposition": "first_party_curated_index",
                "source_ids": ["official-factual-reference"]
            },
            {
                "path": "references/guide.md",
                "sha256": "65a7324d7abb567701cb8630c2c3917c2bc4314ebbb1f65f78eb395a06e7f052",
                "kind": "markdown",
                "disposition": "first_party_factual_synthesis",
                "source_ids": ["official-factual-reference"]
            }
        ]
    });
    zip.start_file(
        "plugin/skills/autolisp/references/documentation-provenance.json",
        options,
    )
    .unwrap();
    zip.write_all(&serde_json::to_vec_pretty(&documentation_provenance).unwrap())
        .unwrap();
    write_test_dependency_evidence(&mut zip, options);
    zip.start_file("plugin/LICENSE", options).unwrap();
    zip.write_all(PROJECT_LICENSE_TEXT).unwrap();
    zip.start_file("plugin/CHANGELOG.md", options).unwrap();
    zip.write_all(b"# Changelog\n").unwrap();
    zip.start_file(&manifest.server.entry_point, executable_options)
        .unwrap();
    zip.write_all(b"fake binary\n").unwrap();
    zip.finish().unwrap();
}

fn write_test_dependency_evidence(zip: &mut zip::ZipWriter<std::fs::File>, options: FileOptions) {
    zip.start_file("plugin/dependency-license-policy.json", options)
        .unwrap();
    zip.write_all(DEPENDENCY_LICENSE_POLICY).unwrap();
    zip.start_file("plugin/dependency-source-lock.spdx.json", options)
        .unwrap();
    zip.write_all(DEPENDENCY_SOURCE_LOCK_SBOM).unwrap();
    zip.start_file(
        "plugin/dependency-windows-source-closure.spdx.json",
        options,
    )
    .unwrap();
    zip.write_all(DEPENDENCY_WINDOWS_SOURCE_CLOSURE_SBOM)
        .unwrap();
    zip.start_file("plugin/dependency-license-provenance.json", options)
        .unwrap();
    zip.write_all(DEPENDENCY_LICENSE_PROVENANCE).unwrap();
    zip.start_file("plugin/THIRD_PARTY_LICENSES.txt", options)
        .unwrap();
    zip.write_all(THIRD_PARTY_LICENSES).unwrap();
    zip.start_file("plugin/owner-distribution-approval.schema.json", options)
        .unwrap();
    zip.write_all(OWNER_DISTRIBUTION_APPROVAL_SCHEMA).unwrap();
}

fn zip_names(path: &Path) -> Vec<String> {
    let file = std::fs::File::open(path).unwrap();
    let mut archive = ZipArchive::new(file).unwrap();
    let mut names = Vec::new();
    for i in 0..archive.len() {
        names.push(archive.by_index(i).unwrap().name().to_string());
    }
    names.sort();
    names
}

#[test]
fn package_cli_sources_preview_activation_internally() {
    let output = Command::new(bin())
        .args(["package", "--help"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--preview"), "got: {help}");
    assert!(!help.contains("--preview-arg"), "got: {help}");
    assert!(!help.contains("--preview-arg-policy"), "got: {help}");
}

#[cfg(unix)]
#[test]
fn cli_packages_macos_mcpb_from_current_plugin_tree() {
    let temp = tempfile::tempdir().unwrap();
    let fake_binary = temp.path().join("autocad-mcp");
    let fake_lsp_binary = temp.path().join("autolisp-lsp");
    write_release_introspection_binary(&fake_binary);
    std::fs::write(&fake_lsp_binary, "fake lsp\n").unwrap();

    let output = Command::new(bin())
        .args([
            "package",
            "--target",
            "macos-arm64",
            "--binary",
            fake_binary.to_str().unwrap(),
            "--lsp-binary",
            fake_lsp_binary.to_str().unwrap(),
            "--out-dir",
            temp.path().to_str().unwrap(),
            "--plugin-dir",
            repo_root().join("plugin").to_str().unwrap(),
            "--schema-root",
            repo_root()
                .join("tests/fixtures/plugin-example")
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(temp.path().join("autocad-mcp-macos-arm64.mcpb").is_file());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("autocad-mcp-macos-arm64.mcpb"),
        "got: {stdout}"
    );
    let names = zip_names(&temp.path().join("autocad-mcp-macos-arm64.mcpb"));
    assert!(names.contains(&"plugin/.lsp.json".to_string()), "{names:?}");
    assert!(
        names.contains(&"plugin/bin/autolisp-lsp".to_string()),
        "{names:?}"
    );
    assert!(
        names.contains(
            &"plugin/skills/autolisp/references/documentation-provenance.json".to_string()
        ),
        "{names:?}"
    );
    for required in [
        "plugin/dependency-license-policy.json",
        "plugin/dependency-license-provenance.json",
        "plugin/dependency-source-lock.spdx.json",
        "plugin/dependency-windows-source-closure.spdx.json",
        "plugin/THIRD_PARTY_LICENSES.txt",
        "plugin/owner-distribution-approval.schema.json",
    ] {
        assert!(names.contains(&required.to_owned()), "{names:?}");
    }
    let package = std::fs::File::open(temp.path().join("autocad-mcp-macos-arm64.mcpb")).unwrap();
    let mut archive = ZipArchive::new(package).unwrap();
    let mut archived_license = Vec::new();
    archive
        .by_name("plugin/LICENSE")
        .unwrap()
        .read_to_end(&mut archived_license)
        .unwrap();
    assert_eq!(
        archived_license,
        std::fs::read(repo_root().join("LICENSE")).unwrap()
    );
    for relative in [
        "dependency-license-policy.json",
        "dependency-license-provenance.json",
        "dependency-source-lock.spdx.json",
        "dependency-windows-source-closure.spdx.json",
        "THIRD_PARTY_LICENSES.txt",
    ] {
        let mut archived = Vec::new();
        archive
            .by_name(&format!("plugin/{relative}"))
            .unwrap()
            .read_to_end(&mut archived)
            .unwrap();
        assert_eq!(
            archived,
            std::fs::read(repo_root().join("plugin").join(relative)).unwrap()
        );
    }
    let mut archived_schema = Vec::new();
    archive
        .by_name("plugin/owner-distribution-approval.schema.json")
        .unwrap()
        .read_to_end(&mut archived_schema)
        .unwrap();
    assert_eq!(
        archived_schema,
        std::fs::read(
            repo_root().join(
                "crates/distribution/approval/schemas/owner-distribution-approval.schema.json",
            ),
        )
        .unwrap()
    );
    let mut manifest = String::new();
    archive
        .by_name("manifest.json")
        .unwrap()
        .read_to_string(&mut manifest)
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    assert_eq!(manifest["license"], "GPL-3.0-or-later");
}

#[test]
fn cli_invalid_target_uses_error_exit_path() {
    let temp = tempfile::tempdir().unwrap();
    let fake_binary = temp.path().join("autocad-mcp");
    std::fs::write(&fake_binary, "fake binary\n").unwrap();

    let output = Command::new(bin())
        .args([
            "package",
            "--target",
            "invalid",
            "--binary",
            fake_binary.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ERROR:"), "got: {stderr}");
    assert!(
        stderr.contains("unsupported MVP package target 'invalid'"),
        "got: {stderr}"
    );
}

#[test]
fn cli_smoke_reports_static_passed_and_executable_skipped() {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("package.mcpb");
    let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
    write_static_package(&package, &manifest);

    let output = Command::new(bin())
        .args(["smoke", "--package", package.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "static smoke passed; executable smoke skipped\n"
    );
}

#[test]
fn cli_lsp_smoke_rejects_a_missing_binary() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing-lsp");
    let output = Command::new(bin())
        .args(["lsp-smoke", "--binary", missing.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must exist and be a file"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_verify_approval_rejects_a_non_strict_dynamic_sidecar_before_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let approval = temp.path().join("approval.json");
    let mcpb = temp.path().join("candidate.mcpb");
    let source = temp.path().join("source.zip");
    let sbom = temp.path().join("source-closure.spdx.json");
    let attestation = temp.path().join("build-attestation.json");
    std::fs::write(&approval, br#"{"schema_version":2,"schema_version":2}"#).unwrap();
    for path in [&mcpb, &source, &sbom, &attestation] {
        std::fs::write(path, b"dynamic test sidecar\n").unwrap();
    }

    let output = Command::new(bin())
        .args([
            "verify-approval",
            "--approval",
            approval.to_str().unwrap(),
            "--mcpb",
            mcpb.to_str().unwrap(),
            "--source-zip",
            source.to_str().unwrap(),
            "--source-closure-sbom",
            sbom.to_str().unwrap(),
            "--build-attestation",
            attestation.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ERROR:"), "stderr: {stderr}");
    assert!(
        stderr.contains("strict JSON") || stderr.contains("duplicate"),
        "stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn cli_lsp_smoke_runs_the_native_stdio_lifecycle() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("autolisp-lsp");
    std::fs::write(
        &binary,
        r#"#!/bin/sh
body='{"jsonrpc":"2.0","id":1,"result":{"capabilities":{},"serverInfo":{"name":"autolisp-lsp","version":"0.0.1"}}}'
printf 'Content-Length: %s\r\n\r\n%s' "${#body}" "$body"
cat >/dev/null
"#,
    )
    .unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new(bin())
        .args(["lsp-smoke", "--binary", binary.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "AutoLISP LSP stdio smoke passed\n"
    );
}
