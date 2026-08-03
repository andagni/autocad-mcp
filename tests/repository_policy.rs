use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use walkdir::WalkDir;

const PROJECT_LICENSE: &str = "GPL-3.0-or-later";
const CANONICAL_GPLV3_SHA256: &str =
    "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986";
const WINDOWS_XREF_WORKFLOW_SHA256: &str =
    "b5c7656cea16875179f11796ddaa303cc18397ba502a952bf92174390f7d2712";
const WINDOWS_NATIVE_HARNESS_WORKFLOW_SHA256: &str =
    "03b85fed84f9fbeb85cef3feb168a27f0a29550babb91d87dad2d767d05b164b";
const WINDOWS_PREVIEW_REVIEW_WORKFLOW_SHA256: &str =
    "ed97fac0c54175f4558b73847d2c4b2d140fec61e4700dceabce68acf190565f";
const MCPB_VALIDATOR_PACKAGE_SHA256: &str =
    "ff8efca13765d492da22711f73935d09f95871dfa30d2275844f6ec182956240";
const MCPB_VALIDATOR_LOCK_SHA256: &str =
    "a5a19b3a1c767ac109cf7deebf2a41fbf77810444d21bb09e6c6004cc36deefb";
const PUBLIC_DEVELOPMENT_ARG_SHA256: &str =
    "77c7bcf316b2a5bac231eef67c3acd52954a13bcd74b3eb10466ffd979443e95";
const PUBLIC_DEVELOPMENT_ARG_POLICY_SHA256: &str =
    "f937351b66e4fd2f421f8bdb8e58370e69d7a6e4f896352cf8da1f13209cb2a4";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate must be inside the workspace")
        .to_path_buf()
}

fn repository_relative_path(repository: &Path, path: &Path) -> String {
    path.strip_prefix(repository)
        .expect("path should be below the repository")
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn git_command(repository: &Path) -> Command {
    #[cfg(windows)]
    const NULL_DEVICE: &str = "NUL";
    #[cfg(not(windows))]
    const NULL_DEVICE: &str = "/dev/null";

    let inherited_environment = [
        ("PATH", std::env::var_os("PATH")),
        ("SystemRoot", std::env::var_os("SystemRoot")),
        ("WINDIR", std::env::var_os("WINDIR")),
        ("TMPDIR", std::env::var_os("TMPDIR")),
        ("TMP", std::env::var_os("TMP")),
        ("TEMP", std::env::var_os("TEMP")),
    ];
    let mut command = Command::new("git");
    command.env_clear().current_dir(repository);
    for (name, value) in inherited_environment {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
    command
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", NULL_DEVICE)
        .env("GIT_CONFIG_GLOBAL", NULL_DEVICE)
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

fn is_ignored(repository: &Path, path: &str) -> bool {
    let status = git_command(repository)
        .args(["check-ignore", "--quiet", "--no-index", "--", path])
        .status()
        .expect("git should be available for repository-policy tests");

    match status.code() {
        Some(0) => true,
        Some(1) => false,
        code => panic!("git check-ignore failed for {path} with status {code:?}"),
    }
}

fn tracked_paths(repository: &Path) -> Vec<String> {
    let output = git_command(repository)
        .args(["ls-files", "--cached", "-z", "--"])
        .output()
        .expect("git should enumerate tracked paths");
    assert!(
        output.status.success(),
        "git ls-files failed with status {:?}",
        output.status.code()
    );

    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| {
            std::str::from_utf8(path)
                .expect("tracked paths must be UTF-8")
                .to_owned()
        })
        .collect()
}

fn tracked_whitelist_violations(repository: &Path) -> Vec<String> {
    tracked_paths(repository)
        .into_iter()
        .filter(|path| is_ignored(repository, path))
        .collect()
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

fn run_git(repository: &Path, arguments: &[&str]) {
    let status = git_command(repository)
        .args(arguments)
        .status()
        .expect("git command should run");
    assert!(
        status.success(),
        "git {arguments:?} failed with status {:?}",
        status.code()
    );
}

#[test]
fn whitelist_admits_reviewed_shapes_and_denies_unreviewed_paths() {
    let repository = repository_root();
    for path in [
        ".gitattributes",
        ".githooks/pre-push",
        ".github/workflows/windows-native-harness.yml",
        ".github/workflows/windows-preview-review-candidate.yml",
        ".github/workflows/windows-xref-guarded-rename.yml",
        "README.md",
        "rust-toolchain.toml",
        "crates/autocad-reader/.gitignore",
        "crates/autocad-reader/Cargo.toml",
        "crates/autocad-reader/src/mod.rs",
        "crates/autocad-reader/src/contract/xrefs.rs",
        "crates/autocad-reader/src/xref_path.rs",
        "crates/autocad-writer/.gitignore",
        "crates/autocad-writer/Cargo.toml",
        "crates/autocad-writer/src/mod.rs",
        "crates/autocad-writer/src/contract/capability.rs",
        "crates/autocad-writer/src/session.rs",
        "crates/autocad-mcp/tests/writer_contract.rs",
        "crates/autocad-mcp/src/ops/new_operation.rs",
        "crates/distribution/.gitignore",
        "crates/distribution/approval/src/lib.rs",
        "crates/distribution/evidence/src/lib.rs",
        "crates/distribution/packager/src/lib.rs",
        "crates/distribution/plugin-validation/src/lib.rs",
        "crates/distribution/qualification/src/lib.rs",
        "crates/xtask/src/cargo_layout.rs",
        "crates/xtask/src/core_clean_dispatch.rs",
        "crates/xtask/src/local_release_dispatch.rs",
        "crates/xtask/src/main.rs",
        "crates/xtask/src/quality_dispatch.rs",
        "plugin/.lsp.json",
        "plugin/.third-party/.gitignore",
        "plugin/.third-party/third-party-license-policy.json",
        "plugin/.third-party/third-party-license-provenance.json",
        "plugin/.third-party/source-lock.spdx.json",
        "plugin/.third-party/license-supplements/.gitignore",
        "plugin/.third-party/license-supplements/rmcp-1.7.0-LICENSE.txt",
        "plugin/.third-party/source-closure-windows.spdx.json",
        "plugin/skills/autolisp/references/new-public-reference.md",
        "plugin/skills/autolisp/references/dcl/new-public-reference.md",
        "plugin/skills/autolisp/references/documentation-provenance.json",
        "tests/new_integration.rs",
        "crates/distribution/plugin-validation/schemas/.claude-plugin/plugin.schema.json",
        "crates/distribution/plugin-validation/schemas/.lsp.schema.json",
        "crates/distribution/plugin-validation/schemas/.mcp.schema.json",
        "crates/distribution/plugin-validation/schemas/skills/skill/SKILL.schema.yaml",
        "tests/fixtures/windows_certification/public-development-profile.arg",
        "tests/fixtures/windows_certification/public-development-arg-policy.json",
        "tests/fixtures/xrefs/portable-evidence-ascii.dxf",
        "tests/reader-qualification/acadrust-0.4.0-diagnostic-baseline.json",
        "tests/reader-qualification/acadrust-0.4.1-diagnostic-baseline.json",
        "tests/reader-qualification/acadrust-0.4.1-on-0.4.0-fixtures.json",
        "crates/distribution/approval/schemas/owner-distribution-approval.schema.json",
        "crates/distribution/approval/schemas/preview-clean-host-receipt.schema.json",
        "crates/distribution/approval/schemas/preview-publication-handoff.schema.json",
        "crates/distribution/approval/schemas/windows-preview-build-attestation.schema.json",
        "crates/distribution/packager/tools/.gitignore",
        "crates/distribution/packager/tools/mcpb-validator/.gitignore",
        "crates/distribution/packager/tools/mcpb-validator/package.json",
        "crates/distribution/packager/tools/mcpb-validator/package-lock.json",
    ] {
        assert!(!is_ignored(&repository, path), "{path} should be admitted");
    }

    for path in [
        "unreviewed-root-file",
        ".githooks/pre-commit",
        ".githooks/pre-push.sh",
        ".github/workflows/local-script.sh",
        "crates/unreviewed/Cargo.toml",
        "crates/autocad-reader/README.md",
        "crates/autocad-reader/tests/unreviewed.rs",
        "crates/autocad-reader/src/generated/table.json",
        "crates/autocad-reader/docs/2026-07-29-unreviewed-design.md",
        "crates/autocad-writer/README.md",
        "crates/autocad-writer/tests/unreviewed.rs",
        "crates/autocad-writer/src/generated/table.json",
        "crates/autocad-writer/docs/2026-07-29-unreviewed-design.md",
        "crates/autocad-mcp/docs/2026-07-29-unreviewed-design.md",
        "crates/autolisp-lsp/docs/2026-07-29-unreviewed-design.md",
        "crates/autolisp-validate/docs/2026-07-07-unreviewed-design.md",
        "crates/distribution/approval/docs/2026-07-29-unreviewed-design.md",
        "crates/distribution/evidence/docs/2026-07-29-unreviewed-design.md",
        "crates/distribution/packager/docs/2026-07-29-unreviewed-design.md",
        "crates/distribution/plugin-validation/docs/2026-07-29-unreviewed-design.md",
        "crates/distribution/qualification/docs/2026-07-28-unreviewed-design.md",
        "crates/distribution-approval/docs/2026-07-29-unreviewed-design.md",
        "crates/distribution-approval/src/unreviewed.json",
        "crates/distribution-evidence/docs/2026-07-29-unreviewed-design.md",
        "crates/distribution-evidence/src/unreviewed.json",
        "crates/plugin-validate/docs/2026-07-29-unreviewed-design.md",
        "crates/release-packager/docs/2026-07-29-unreviewed-design.md",
        "crates/release-qualification/docs/2026-07-28-unreviewed-design.md",
        "crates/release-qualification/src/unreviewed.json",
        "crates/autocad-mcp/src/generated/table.json",
        "crates/xtask/docs/2026-07-29-unreviewed-design.md",
        "crates/xtask/scripts/local-gate.sh",
        "docs/.gitignore",
        "docs/specs/unreviewed.md",
        "docs/plans/unreviewed.md",
        "plugin/README.md",
        "plugin/private/secret.md",
        "plugin/.third-party/private.json",
        "plugin/.third-party/license-supplements/unreviewed.txt",
        "plugin/dependency-license-policy.json",
        "plugin/dependency-license-provenance.json",
        "plugin/dependency-source-lock.spdx.json",
        "plugin/dependency-windows-source-closure.spdx.json",
        "plugin/dependency-license-supplements/rmcp-1.7.0-LICENSE.txt",
        "plugin/skills/autolisp/references/private.json",
        "tests/corpus/open/unreviewed.dwg",
        "tests/corpus/open/unreviewed.dxf",
        "crates/distribution/plugin-validation/schemas/nested/example.json",
        "crates/distribution/plugin-validation/schemas/nested/example.yaml",
        "crates/distribution/plugin-validation/schemas/nested/example.md",
        "crates/distribution/plugin-validation/schemas/source.bin",
        "crates/distribution/plugin-validation/schemas/scripts/unreviewed.js",
        "tests/fixtures/windows_certification/unreviewed.arg",
        "tests/fixtures/windows_certification/unreviewed-policy.json",
        "tests/reader-qualification/unreviewed.json",
        "crates/distribution/approval/schemas/unreviewed.schema.json",
        "schemas/release/unreviewed.schema.json",
        "schemas/unreviewed.schema.json",
        "tools/unreviewed.txt",
        "tools/mcpb-validator/unreviewed.json",
        "tools/unreviewed-validator/package.json",
        "crates/distribution/packager/tools/mcpb-validator/unreviewed.json",
        "crates/distribution/packager/tools/unreviewed-validator/package.json",
    ] {
        assert!(
            is_ignored(&repository, path),
            "{path} should remain ignored"
        );
    }
}

#[test]
fn tracked_tree_and_public_orientation_exclude_private_specifications() {
    let repository = repository_root();
    let tracked = tracked_paths(&repository);
    let tracked_specifications = tracked
        .iter()
        .filter(|path| {
            path.starts_with("docs/") || (path.starts_with("crates/") && path.contains("/docs/"))
        })
        .collect::<Vec<_>>();
    assert!(
        tracked_specifications.is_empty(),
        "root and crate specification directories must remain absent from the tracked tree: {tracked_specifications:?}"
    );

    let readme =
        std::fs::read_to_string(repository.join("README.md")).expect("README should be readable");
    let fixture_ledger = std::fs::read_to_string(repository.join("tests/fixture-provenance.json"))
        .expect("fixture provenance ledger should be readable");
    for (label, content) in [("README", readme), ("fixture provenance", fixture_ledger)] {
        for line in content.lines() {
            assert!(
                !(line.contains("crates/") && line.contains("/docs/"))
                    && !line.contains("docs/specs/")
                    && !line.contains("docs/plans/"),
                "{label} must not reference a removed private specification path: {line}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn local_pre_push_hook_is_executable() {
    use std::os::unix::fs::PermissionsExt;

    let hook = repository_root().join(".githooks/pre-push");
    let metadata = std::fs::metadata(&hook).expect("tracked pre-push hook should exist");
    assert!(metadata.is_file(), "pre-push hook must be a regular file");
    assert_ne!(
        metadata.permissions().mode() & 0o111,
        0,
        "pre-push hook must have an executable bit"
    );
}

#[cfg(unix)]
#[test]
fn local_pre_push_hook_has_valid_shell_syntax() {
    let hook = repository_root().join(".githooks/pre-push");
    let output = Command::new("/bin/sh")
        .args(["-n"])
        .arg(&hook)
        .output()
        .expect("POSIX sh should be available to validate the pre-push hook");
    assert!(
        output.status.success(),
        "pre-push hook must have valid POSIX shell syntax: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn local_pre_push_hook_scopes_sccache_compatible_incremental_compilation() {
    let hook = std::fs::read_to_string(repository_root().join(".githooks/pre-push"))
        .expect("tracked pre-push hook should be readable UTF-8");
    let incremental = hook.find("export CARGO_BUILD_INCREMENTAL=true").expect(
        "pre-push hook must opt its serial Cargo work into config-scoped incremental compilation",
    );
    let scrub = hook
        .find("unset CARGO_INCREMENTAL")
        .expect("pre-push hook must scrub the sccache-incompatible global override");
    let thin_command =
        "exec cargo run --locked -p xtask --no-default-features --bin pre-push-dispatch -- \"$@\"";
    let coordinator = hook
        .find(thin_command)
        .expect("pre-push hook must launch the tracked thin dispatcher");
    assert!(
        scrub < incremental && incremental < coordinator,
        "incremental compilation must be enabled before the coordinator and its child gates launch"
    );
    assert_eq!(
        hook.matches("CARGO_INCREMENTAL").count(),
        1,
        "the hook must scrub the legacy global incremental-compilation override exactly once"
    );
    assert_eq!(
        hook.matches("CARGO_BUILD_INCREMENTAL").count(),
        1,
        "the hook must have one config-scoped incremental-compilation override"
    );
    assert_eq!(
        hook.matches("cargo run").count(),
        1,
        "the hook must launch exactly one Cargo coordinator"
    );
    assert!(
        hook.contains("--no-default-features --bin pre-push-dispatch"),
        "the hook must exclude the full xtask and product dependency graph"
    );
    assert!(
        !hook.contains("-p xtask -- pre-push"),
        "the hook must not bootstrap pre-push through the full xtask binary"
    );
    assert!(
        !hook.contains("CARGO_TARGET_DIR"),
        "the hook must continue to use the repository-configured shared target"
    );
}

#[test]
fn xref_failpoint_clippy_is_scoped_to_the_instrumented_product_targets() {
    let repository = repository_root();
    let manifest = std::fs::read_to_string(repository.join("crates/autocad-mcp/Cargo.toml"))
        .expect("autocad-mcp manifest should be readable");
    let profile = concat!(
        "[[package.metadata.local-gate.profiles]]\n",
        "name = \"xref-certification-failpoints\"\n",
        "features = [\"xref-certification-failpoints\"]\n",
        "clippy = true\n",
        "test = false\n",
        "targets = [\"lib\", \"bin:autocad-mcp\"]\n",
        "candidate-only = true\n",
    );
    assert_eq!(
        manifest.matches(profile).count(),
        1,
        "XREF failpoint Clippy must cover only the instrumented library and product binary"
    );

    let coordinator = std::fs::read_to_string(repository.join("crates/xtask/src/main.rs"))
        .expect("xtask coordinator should be readable");
    for boundary in [
        "LocalGateProfileTarget::Lib => arguments.push(\"--lib\".to_owned())",
        "arguments.extend([\"--bin\".to_owned(), binary.clone()])",
        "arguments.push(\"--no-deps\".to_owned())",
    ] {
        assert!(
            coordinator.contains(boundary),
            "scoped feature-profile Clippy is missing boundary: {boundary}"
        );
    }
}

#[test]
fn source_validation_profile_partitions_source_candidate_and_preview_compilation() {
    let repository = repository_root();
    let workspace_manifest = std::fs::read_to_string(repository.join("Cargo.toml"))
        .expect("workspace manifest should be readable");
    assert_eq!(
        workspace_manifest
            .matches(concat!(
                "[profile.source-validation]\n",
                "inherits = \"test\"\n",
                "debug = 0\n",
                "incremental = true\n\n",
                "[profile.source-validation.package.\"*\"]\n",
                "opt-level = 3\n",
                "codegen-units = 16\n",
            ))
            .count(),
        1,
        "the source-validation profile must align test and Clippy while optimizing only dependency compilation"
    );
    assert_eq!(
        workspace_manifest
            .matches(concat!(
                "[workspace.metadata.cargo-core]\n",
                "schema-version = 2\n",
                "retained-workspace-packages = [\"autocad-reader\"]\n",
                "max-retained-bytes = 3221225472\n",
            ))
            .count(),
        1,
        "core must retain only the measured stable workspace admission under one Cargo-native list"
    );

    let product_manifest =
        std::fs::read_to_string(repository.join("crates/autocad-mcp/Cargo.toml"))
            .expect("autocad-mcp manifest should be readable");
    let preview_profile = concat!(
        "[[package.metadata.local-gate.profiles]]\n",
        "name = \"preview\"\n",
        "features = [\"preview\"]\n",
        "clippy = true\n",
        "test = true\n",
        "targets = [\"lib\", \"bin:autocad-mcp\", \"test:integration\", \"test:writer_contract\"]\n",
        "candidate-only = true\n",
    );
    assert_eq!(
        product_manifest.matches(preview_profile).count(),
        1,
        "Preview qualification must compile only the product surfaces that contain Preview code"
    );
    assert!(product_manifest.contains("autocad-writer = { path = \"../autocad-writer\" }"));
    assert!(!product_manifest.contains("autocad-writer/portable-plotting"));

    let writer_manifest =
        std::fs::read_to_string(repository.join("crates/autocad-writer/Cargo.toml"))
            .expect("autocad-writer manifest should be readable");
    for contract in [
        "portable-plotting = [\"dep:krilla\", \"dep:rustybuzz\", \"dep:write-fonts\"]",
        "portable-plot-qualification = [\"portable-plotting\", \"dep:hayro\", \"dep:lopdf\"]",
        "krilla = { version = \"=0.8.2\", default-features = false, optional = true }",
        "rustybuzz = { version = \"=0.20.1\", optional = true }",
        "write-fonts = { version = \"=0.48.1\", default-features = false, optional = true }",
        "candidate-only = true",
        "schema-version = 4",
        "cache = \"disposable\"",
    ] {
        assert!(
            writer_manifest.contains(contract),
            "portable plotting build isolation is missing contract: {contract}"
        );
    }
    assert_eq!(
        writer_manifest
            .matches("required-features = [\"portable-plotting\"]")
            .count(),
        2,
        "the portable worker binary and its process test must stay outside the default graph"
    );

    let integration_source =
        std::fs::read_to_string(repository.join("crates/autocad-mcp/tests/integration.rs"))
            .expect("Preview integration source should be readable");
    assert_eq!(
        integration_source.matches("feature = \"preview\"").count(),
        4
    );
    let writer_contract_source =
        std::fs::read_to_string(repository.join("crates/autocad-mcp/tests/writer_contract.rs"))
            .expect("Preview writer-contract source should be readable");
    assert_eq!(
        writer_contract_source
            .matches("feature = \"preview\"")
            .count(),
        2
    );
    for entry in WalkDir::new(repository.join("crates/autocad-mcp/tests"))
        .min_depth(1)
        .max_depth(1)
    {
        let entry = entry.expect("walk autocad-mcp external tests");
        if !entry.file_type().is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("rs")
            || entry.file_name() == "integration.rs"
            || entry.file_name() == "writer_contract.rs"
            || entry.file_name() == "reader_source_policy.rs"
        {
            continue;
        }
        let source = std::fs::read_to_string(entry.path())
            .unwrap_or_else(|error| panic!("read {}: {error}", entry.path().display()));
        assert!(
            !source.contains("feature = \"preview\""),
            "unregistered external test target contains Preview code: {}",
            entry.path().display()
        );
    }
    let reader_policy = std::fs::read_to_string(
        repository.join("crates/autocad-mcp/tests/reader_source_policy.rs"),
    )
    .expect("reader source-policy test should be readable");
    assert_eq!(
        reader_policy.matches("feature = \"preview\"").count(),
        1,
        "the reader source-policy parser fixture is the only admitted non-integration Preview text"
    );
}

#[test]
fn source_validation_storage_is_governed_and_core_is_not_a_default_clean_target() {
    let repository = repository_root();
    let layout = std::fs::read_to_string(repository.join("crates/xtask/src/cargo_layout.rs"))
        .expect("Cargo layout coordinator should be readable");
    for contract in [
        r#"cargo_root.join("scratch")"#,
        r#"cargo_root.join("release")"#,
        r#"cargo_root.join("core")"#,
        r#".env("CARGO_TARGET_DIR", &self.scratch)"#,
        r#".env("CARGO_BUILD_BUILD_DIR", &self.core)"#,
        r#".env_remove("CARGO_INCREMENTAL")"#,
        r#".env("CARGO_BUILD_INCREMENTAL", "true")"#,
        r#".env("CARGO_BUILD_INCREMENTAL", "false")"#,
        "acquire_governed_lock",
        "core_cleanup_command",
        r#"const DEFAULT_SCCACHE_CACHE_SIZE: &str = "512M";"#,
        "cargo-layout-v1:target=scratch;build=core;profile=source-validation",
        "cargo-layout-v1:target=scratch;build=scratch;profile=source-validation",
    ] {
        assert!(
            layout.contains(contract),
            "governed Cargo layout is missing contract: {contract}"
        );
    }
    for forbidden in ["10G", r#".env("CARGO_INCREMENTAL", "0")"#] {
        assert!(
            !layout.contains(forbidden),
            "retained-core design must not retain the rejected compiler-cache policy: {forbidden}"
        );
    }

    let dispatcher =
        std::fs::read_to_string(repository.join("crates/xtask/src/quality_dispatch.rs"))
            .expect("quality dispatcher should be readable");
    for contract in [
        "SOURCE_VALIDATION_PROFILE",
        "layout.configure_source_validation(&mut command)",
        "layout.acquire_governed_lock()",
        "pre-gate Cargo core cleanup",
        "post-gate Cargo core cleanup",
        "clean-core-workspace",
        "--dry-run",
    ] {
        assert!(
            dispatcher.contains(contract),
            "quality bootstrap is missing contract: {contract}"
        );
    }

    let coordinator =
        std::fs::read_to_string(repository.join("crates/xtask/src/core_clean_dispatch.rs"))
            .expect("core-clean dispatcher should be readable");
    for contract in [
        "fn core_cleanup_plan(",
        "workspace.metadata.cargo-core",
        "max-retained-bytes",
        "cache_epoch_sha256(",
        "retention_rejected",
        "EpochState::Rejected",
        "retained package manifest has no parent",
        "reset_governed_profiles(",
        "post-clean Cargo core retained",
        "arguments.push(\"--package\".to_owned())",
        "cargo_layout::SOURCE_VALIDATION_PROFILE",
        "[cargo_layout::SOURCE_VALIDATION_PROFILE, \"release\"]",
    ] {
        assert!(
            coordinator.contains(contract),
            "package-aware core cleanup is missing contract: {contract}"
        );
    }
    assert!(!coordinator.contains("remove_dir_all(&layout.core"));

    let release_dispatcher =
        std::fs::read_to_string(repository.join("crates/xtask/src/local_release_dispatch.rs"))
            .expect("local-release dispatcher should be readable");
    for contract in [
        "BuildMode::Release",
        "BuildMode::Preview",
        "autocad-mcp/preview",
        "layout.configure_release(&mut command",
        "local_development_only",
        "release_authority: false",
        "distribution_authority: false",
        "signing_authority: false",
        "native_host_authority: false",
        "remove_prior_artifacts(&target_directory)",
        "run_core_cleanup(&layout, &repository, \"pre-build\")",
        "run_core_cleanup(&layout, &repository, \"post-build\")",
    ] {
        assert!(
            release_dispatcher.contains(contract),
            "local-release dispatcher is missing contract: {contract}"
        );
    }
    assert!(!release_dispatcher.contains("BuildMode::Experimental"));
}

#[test]
fn thin_pre_push_dispatch_has_no_active_normal_or_build_dependencies() {
    let repository = repository_root();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(&repository)
        .args([
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--no-default-features",
        ])
        .output()
        .expect("no-default-features cargo metadata should run");
    assert!(
        output.status.success(),
        "no-default-features cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata should emit JSON");
    let xtask = metadata["packages"]
        .as_array()
        .expect("metadata packages should be an array")
        .iter()
        .find(|package| package["name"] == "xtask")
        .expect("metadata should contain xtask");
    let xtask_id = xtask["id"]
        .as_str()
        .expect("xtask package ID should be text");
    let xtask_node = metadata["resolve"]["nodes"]
        .as_array()
        .expect("metadata resolve nodes should be an array")
        .iter()
        .find(|node| node["id"] == xtask_id)
        .expect("metadata resolve should contain xtask");
    let active_non_dev_dependencies = xtask_node["deps"]
        .as_array()
        .expect("xtask dependency nodes should be an array")
        .iter()
        .filter(|dependency| {
            dependency["dep_kinds"]
                .as_array()
                .expect("dependency kinds should be an array")
                .iter()
                .any(|kind| kind["kind"].is_null() || kind["kind"] == "build")
        })
        .map(|dependency| dependency["name"].as_str().unwrap_or("<non-text>"))
        .collect::<Vec<_>>();
    assert!(
        active_non_dev_dependencies.is_empty(),
        "the no-default-features pre-push dispatcher must not activate normal or build dependencies: {active_non_dev_dependencies:?}"
    );

    let targets = xtask["targets"]
        .as_array()
        .expect("xtask targets should be an array");
    let dispatcher = targets
        .iter()
        .find(|target| target["name"] == "pre-push-dispatch")
        .expect("xtask must expose the thin pre-push dispatcher");
    assert!(
        dispatcher["required-features"].is_null(),
        "the thin dispatcher must remain available without the full feature"
    );
    let quality_dispatcher = targets
        .iter()
        .find(|target| target["name"] == "quality-dispatch")
        .expect("xtask must expose the thin quality dispatcher");
    assert!(
        quality_dispatcher["required-features"].is_null(),
        "the quality dispatcher must bootstrap without the full dependency graph"
    );
    let core_clean_dispatcher = targets
        .iter()
        .find(|target| target["name"] == "core-clean-dispatch")
        .expect("xtask must expose the bounded core-clean dispatcher");
    assert_eq!(
        core_clean_dispatcher["required-features"],
        serde_json::json!(["core-clean"]),
        "core cleanup must activate only its narrow metadata-parsing feature"
    );
    let local_release_dispatcher = targets
        .iter()
        .find(|target| target["name"] == "local-release-dispatch")
        .expect("xtask must expose the bounded local-release dispatcher");
    assert_eq!(
        local_release_dispatcher["required-features"],
        serde_json::json!(["local-release"]),
        "local optimized builds must activate only their narrow dispatch feature"
    );
    let full_xtask = targets
        .iter()
        .find(|target| target["name"] == "xtask")
        .expect("xtask must retain its full coordinator");
    assert_eq!(
        full_xtask["required-features"],
        serde_json::json!(["full"]),
        "the full coordinator must remain feature-gated away from rapid pre-push"
    );
}

#[test]
fn validation_receipts_are_durable_advisory_and_package_owned() {
    let repository = repository_root();
    let receipt_engine =
        std::fs::read_to_string(repository.join("crates/xtask/src/validation_receipt.rs"))
            .expect("validation receipt engine should be readable");
    for boundary in [
        r#"const RECEIPT_SCOPE: &str = "advisory_local_validation_only";"#,
        "release_authority: false,",
        "distribution_authority: false,",
        "signing_authority: false,",
        "native_host_authority: false,",
        r#"const DISABLE_RECEIPTS_ENVIRONMENT: &str = "AUTOCAD_MCP_DISABLE_VALIDATION_RECEIPTS";"#,
        r#"const CACHE_COMPONENTS: [&str; 3] = ["autocad-mcp", "validation-receipts", "v1"];"#,
        r#"const SUBJECTS_COMPONENT: &str = "subjects";"#,
        "fn plan_satisfies(",
        "fn git_common_directory(",
        "#[serde(deny_unknown_fields)]",
        r#"| "CARGO_BUILD_BUILD_DIR""#,
        r#"| "CARGO_BUILD_INCREMENTAL""#,
        r#"| "CARGO_BUILD_RUSTC_WRAPPER""#,
        r#"| "RUSTC_WORKSPACE_WRAPPER""#,
        r#"| "SCCACHE_CACHE_SIZE""#,
    ] {
        assert!(
            receipt_engine.contains(boundary),
            "validation receipts must retain their durable non-authoritative boundary: {boundary}"
        );
    }
    for forbidden in ["owner_distribution_approval", "publication_authority"] {
        assert!(
            !receipt_engine.contains(forbidden),
            "advisory validation receipts must not acquire {forbidden}"
        );
    }
    assert!(
        !repository
            .join("crates/xtask/src/content_receipt.rs")
            .exists()
            && !repository
                .join("crates/xtask/src/pre_push_receipt.rs")
                .exists(),
        "legacy receipt engines must be removed after migration"
    );

    let declarations = WalkDir::new(repository.join("crates"))
        .follow_links(false)
        .into_iter()
        .map(|entry| entry.expect("crate tree should be walkable"))
        .filter(|entry| entry.file_type().is_file() && entry.file_name() == "Cargo.toml")
        .filter_map(|entry| {
            let contents = std::fs::read_to_string(entry.path())
                .expect("Cargo manifest should be readable UTF-8");
            contents.contains("input-id-arguments").then(|| {
                entry
                    .path()
                    .strip_prefix(&repository)
                    .expect("manifest should be repository-relative")
                    .to_string_lossy()
                    .replace('\\', "/")
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        declarations,
        ["crates/distribution/evidence/Cargo.toml"],
        "input-id declarations must remain package-owned and explicit"
    );

    let evidence_manifest =
        std::fs::read_to_string(repository.join("crates/distribution/evidence/Cargo.toml"))
            .expect("distribution-evidence manifest should be readable");
    assert_eq!(
        evidence_manifest
            .matches(r#"input-id-arguments = ["input-id"]"#)
            .count(),
        1,
        "distribution evidence must own exactly one stable input-id subcommand"
    );
    assert!(evidence_manifest.contains("schema-version = 3"));
    assert!(evidence_manifest.contains("candidate-only = true"));
    let evidence_cli =
        std::fs::read_to_string(repository.join("crates/distribution/evidence/src/main.rs"))
            .expect("distribution-evidence CLI should be readable");
    assert!(
        evidence_cli.contains(r#"[command] if command == "input-id" => report_input_id(),"#),
        "the package-owned input-id declaration must resolve to a real CLI subcommand"
    );
}

#[test]
fn jsonschema_is_workspace_owned_without_resolver_or_tls_defaults() {
    let repository = repository_root();
    let root_manifest = std::fs::read_to_string(repository.join("Cargo.toml"))
        .expect("workspace manifest should be readable");
    assert_eq!(
        root_manifest
            .lines()
            .filter(|line| {
                line.trim() == "jsonschema = { version = \"0.46\", default-features = false }"
            })
            .count(),
        1,
        "the workspace must own one resolver-free jsonschema dependency policy"
    );

    let metadata = cargo_metadata(&repository);
    let mut consumers = metadata["packages"]
        .as_array()
        .expect("cargo metadata packages should be an array")
        .iter()
        .flat_map(|package| {
            let package_name = package["name"]
                .as_str()
                .expect("package name should be text");
            package["dependencies"]
                .as_array()
                .expect("package dependencies should be an array")
                .iter()
                .filter(|dependency| dependency["name"] == "jsonschema")
                .map(move |dependency| {
                    assert_eq!(
                        dependency["uses_default_features"], false,
                        "{package_name} must not enable jsonschema file, HTTP, or TLS resolver defaults"
                    );
                    (
                        package_name.to_owned(),
                        dependency["kind"]
                            .as_str()
                            .unwrap_or("normal")
                            .to_owned(),
                    )
                })
        })
        .collect::<Vec<_>>();
    consumers.sort();
    assert_eq!(
        consumers,
        [
            ("distribution-approval".to_owned(), "dev".to_owned()),
            ("plugin-validate".to_owned(), "normal".to_owned()),
            ("release-packager".to_owned(), "normal".to_owned()),
        ],
        "the reviewed jsonschema consumer set changed"
    );
}

#[test]
fn project_license_is_canonical_and_consistent() {
    let repository = repository_root();
    let root_license = std::fs::read(repository.join("LICENSE"))
        .expect("root LICENSE should be a readable regular file");
    let plugin_license = std::fs::read(repository.join("plugin/LICENSE"))
        .expect("plugin LICENSE should be a readable regular file");

    assert!(!root_license.is_empty(), "root LICENSE must be nonempty");
    assert_eq!(
        root_license, plugin_license,
        "license texts must be identical"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&root_license)),
        CANONICAL_GPLV3_SHA256,
        "LICENSE must remain the unmodified canonical GNU GPLv3 text"
    );

    let plugin_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repository.join("plugin/.claude-plugin/plugin.json"))
            .expect("plugin metadata should be readable"),
    )
    .expect("plugin metadata should be valid JSON");
    assert_eq!(plugin_json["license"], PROJECT_LICENSE);

    let metadata = cargo_metadata(&repository);
    let packages = metadata["packages"]
        .as_array()
        .expect("cargo metadata packages should be an array");
    assert!(
        !packages.is_empty(),
        "workspace must contain at least one Cargo package"
    );
    for package in packages {
        assert_eq!(
            package["license"], PROJECT_LICENSE,
            "Cargo package {} has inconsistent licensing",
            package["name"]
        );
    }
}

#[test]
fn supplemental_mcpb_validator_is_private_exact_and_lockfile_bound() {
    let repository = repository_root();
    let package_path =
        repository.join("crates/distribution/packager/tools/mcpb-validator/package.json");
    let lock_path =
        repository.join("crates/distribution/packager/tools/mcpb-validator/package-lock.json");
    let tracked = tracked_paths(&repository);
    for required in [
        "crates/distribution/packager/tools/mcpb-validator/package.json",
        "crates/distribution/packager/tools/mcpb-validator/package-lock.json",
    ] {
        assert!(
            tracked.iter().any(|path| path == required),
            "the sealed source must track the supplemental validator input: {required}"
        );
    }
    let package_bytes = std::fs::read(&package_path).expect("validator package should be readable");
    let lock_bytes = std::fs::read(&lock_path).expect("validator lockfile should be readable");
    assert_eq!(
        format!("{:x}", Sha256::digest(&package_bytes)),
        MCPB_VALIDATOR_PACKAGE_SHA256,
        "the reviewed supplemental MCPB validator package changed"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&lock_bytes)),
        MCPB_VALIDATOR_LOCK_SHA256,
        "the reviewed supplemental MCPB validator lockfile changed"
    );

    let package: serde_json::Value =
        serde_json::from_slice(&package_bytes).expect("validator package should be JSON");
    assert_eq!(
        package,
        serde_json::json!({
            "name": "autocad-mcp-mcpb-validator",
            "version": "0.0.0",
            "private": true,
            "description": "Pinned supplemental MCPB manifest validator for release review",
            "engines": {"node": "24.18.0"},
            "devDependencies": {"@anthropic-ai/mcpb": "2.1.2"},
            "overrides": {"tmp": "0.2.7"}
        }),
        "the supplemental validator package contract changed"
    );

    let lock: serde_json::Value =
        serde_json::from_slice(&lock_bytes).expect("validator lockfile should be JSON");
    assert_eq!(lock["lockfileVersion"], 3);
    assert_eq!(lock["requires"], true);
    let packages = lock["packages"]
        .as_object()
        .expect("validator lockfile packages should be an object");
    assert_eq!(
        packages.len(),
        55,
        "validator dependency closure changed without review"
    );
    assert_eq!(
        packages[""]["devDependencies"],
        serde_json::json!({"@anthropic-ai/mcpb": "2.1.2"})
    );
    assert_eq!(
        packages[""]["engines"],
        serde_json::json!({"node": "24.18.0"})
    );
    let mcpb = &packages["node_modules/@anthropic-ai/mcpb"];
    assert_eq!(mcpb["version"], "2.1.2");
    assert_eq!(
        mcpb["integrity"],
        "sha512-goRbBC8ySo7SWb7tRzr+tL6FxDc4JPTRCdgfD2omba7freofvjq5rom1lBnYHZHo6Mizs1jAHJeN53aZbDoy8A=="
    );
    assert_eq!(mcpb["license"], "MIT");
    assert_eq!(mcpb["bin"], serde_json::json!({"mcpb": "dist/cli/cli.js"}));
    let patched_tmp = &packages["node_modules/tmp"];
    assert_eq!(
        patched_tmp["version"], "0.2.7",
        "the reviewed tmp path-traversal fixes must not be regressed"
    );
    assert_eq!(
        patched_tmp["integrity"],
        "sha512-e0votIpp4Uo2AJYSzVHV6xCcawuiez3DzqDAbrTc3YxBkplN6e+dM13ZeIcZnDg/QpSuU2zfZ3rzwY8ukEnaXw=="
    );
    assert!(
        !packages.contains_key("node_modules/os-tmpdir"),
        "the obsolete vulnerable tmp closure must not return"
    );
    for (path, dependency) in packages {
        if path.is_empty() {
            continue;
        }
        assert_eq!(
            dependency["dev"], true,
            "validator dependency {path} must remain development-only"
        );
        assert!(
            dependency["resolved"]
                .as_str()
                .is_some_and(|value| value.starts_with("https://registry.npmjs.org/")),
            "validator dependency {path} must use the reviewed npm registry"
        );
        assert!(
            dependency["integrity"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha512-")),
            "validator dependency {path} must be integrity-bound"
        );
        assert!(
            dependency["license"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "validator dependency {path} must declare its package licence"
        );
    }
    assert!(
        !tracked.iter().any(|path| path.contains("/node_modules/")),
        "restored validator dependencies must never be tracked"
    );

    let attributes = std::fs::read_to_string(repository.join(".gitattributes"))
        .expect(".gitattributes should be readable");
    assert!(
        attributes.lines().any(|line| {
            line == "crates/distribution/packager/tools/mcpb-validator/*.json text eol=lf"
        }),
        "validator JSON line endings must remain stable"
    );
}

#[test]
fn autolisp_documentation_provenance_is_closed_and_line_endings_are_stable() {
    let repository = repository_root();
    for required in [
        "plugin/skills/autolisp/SKILL.md",
        "plugin/skills/autolisp/references/documentation-provenance.json",
    ] {
        assert!(
            repository.join(required).is_file(),
            "required documentation provenance boundary is missing: {required}"
        );
    }
    let errors = plugin_validate::validate_documentation_provenance(&repository.join("plugin"));
    assert!(
        errors.is_empty(),
        "AutoLISP documentation provenance failed: {errors:?}"
    );

    let attributes = std::fs::read_to_string(repository.join(".gitattributes"))
        .expect(".gitattributes should be readable");
    for expected in [
        "plugin/skills/autolisp/SKILL.md text eol=lf",
        "plugin/skills/autolisp/references/*.md text eol=lf",
        "plugin/skills/autolisp/references/**/*.md text eol=lf",
        "plugin/skills/autolisp/references/autolisp-lsp-index.json text eol=lf",
        "plugin/skills/autolisp/references/documentation-provenance.json text eol=lf",
    ] {
        assert!(
            attributes.lines().any(|line| line == expected),
            "documentation provenance line-ending rule is missing: {expected}"
        );
    }
}

#[test]
fn public_development_arg_is_exact_byte_bound_and_policy_closed() {
    let repository = repository_root();
    let arg_path =
        repository.join("tests/fixtures/windows_certification/public-development-profile.arg");
    let policy_path =
        repository.join("tests/fixtures/windows_certification/public-development-arg-policy.json");
    let arg_bytes = std::fs::read(&arg_path).expect("public development ARG should be readable");
    let policy_bytes =
        std::fs::read(&policy_path).expect("public development ARG policy should be readable");

    assert_eq!(
        format!("{:x}", Sha256::digest(&arg_bytes)),
        PUBLIC_DEVELOPMENT_ARG_SHA256,
        "the reviewed synthetic public ARG bytes changed"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&policy_bytes)),
        PUBLIC_DEVELOPMENT_ARG_POLICY_SHA256,
        "the reviewed synthetic public ARG policy bytes changed"
    );
    let inspection =
        autocad_mcp::certified_arg::validate_distribution_safe_arg(&arg_bytes, &policy_bytes)
            .expect("the reviewed synthetic public ARG should satisfy its closed policy");
    assert_eq!(inspection.raw_arg_sha256, PUBLIC_DEVELOPMENT_ARG_SHA256);
    assert_eq!(
        inspection.policy_sha256,
        PUBLIC_DEVELOPMENT_ARG_POLICY_SHA256
    );

    let attributes = std::fs::read_to_string(repository.join(".gitattributes"))
        .expect(".gitattributes should be readable");
    let first_rule = attributes
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'));
    assert_eq!(
        first_rule,
        Some("* text=auto eol=lf"),
        "all detected text must be materialized as LF before isolated Git checks; \
         exact-byte inputs remain protected by the later binary rules"
    );
    for expected in [
        "Cargo.lock text eol=lf",
        "rust-toolchain.toml text eol=lf",
        "crates/**/*.rs text eol=lf",
        "tests/**/*.rs text eol=lf",
        "crates/autocad-mcp/Cargo.toml text eol=lf",
        "crates/autocad-mcp/build.rs text eol=lf",
        "crates/autocad-mcp/src/**/*.rs text eol=lf",
        "crates/autocad-mcp/resources/*.json text eol=lf",
        "crates/autocad-mcp/profile-registry/*.json text eol=lf",
        "crates/distribution/approval/Cargo.toml text eol=lf",
        "crates/distribution/approval/src/**/*.rs text eol=lf",
        "crates/distribution/evidence/src/lib.rs text eol=lf",
        "crates/distribution/qualification/Cargo.toml text eol=lf",
        "crates/distribution/qualification/src/**/*.rs text eol=lf",
        "crates/xtask/src/source_bundle.rs text eol=lf",
        "plugin/.third-party/third-party-license-policy.json text eol=lf",
        "plugin/.third-party/third-party-license-provenance.json text eol=lf",
        "plugin/.third-party/source-lock.spdx.json text eol=lf",
        "plugin/.third-party/source-closure-windows.spdx.json text eol=lf",
        "plugin/.third-party/license-supplements/* binary",
        "crates/distribution/approval/schemas/owner-distribution-approval.schema.json text eol=lf",
        "crates/distribution/approval/schemas/preview-clean-host-receipt.schema.json text eol=lf",
        "crates/distribution/approval/schemas/preview-publication-handoff.schema.json text eol=lf",
        "crates/distribution/approval/schemas/windows-preview-build-attestation.schema.json text eol=lf",
        "tests/fixtures/windows_certification/public-development-arg-policy.json text eol=lf",
        "tests/fixtures/windows_certification/public-development-profile.arg binary",
        "tests/fixtures/xrefs/*.dxf binary",
        "tests/reader-qualification/*.json text eol=lf",
    ] {
        assert!(
            attributes.lines().any(|line| line == expected),
            "preflight exact-byte input attribute is missing: {expected}"
        );
    }
}

#[test]
fn preview_activation_profile_directory_matches_the_embedded_bundle_exactly() {
    const SOURCE_RESOURCE_PREFIX: &str = "crates/autocad-mcp/resources/";
    const PROFILE_PREFIX: &str = "activation-profiles/";

    let repository = repository_root();
    let profile_directory = repository.join("crates/autocad-mcp/resources/activation-profiles");
    let directory_metadata = std::fs::symlink_metadata(&profile_directory)
        .expect("Preview activation profile directory should be readable");
    assert!(
        directory_metadata.is_dir() && !directory_metadata.file_type().is_symlink(),
        "Preview activation profile directory must be one real directory"
    );

    let expected = autocad_mcp::activation::embedded_activation_bundle()
        .expect("embedded Preview activation bundle should be valid")
        .files
        .into_iter()
        .filter_map(|file| file.path.strip_prefix(PROFILE_PREFIX))
        .map(|path| format!("{SOURCE_RESOURCE_PREFIX}{PROFILE_PREFIX}{path}"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        expected.len(),
        20,
        "embedded Preview activation bundle must bind ten ARG/policy pairs"
    );

    let actual = std::fs::read_dir(&profile_directory)
        .expect("Preview activation profile directory should be enumerable")
        .map(|entry| {
            let entry = entry.expect("Preview activation profile entry should be readable");
            let file_type = entry
                .file_type()
                .expect("Preview activation profile entry type should be readable");
            assert!(
                file_type.is_file() && !file_type.is_symlink(),
                "Preview activation profile inventory admits regular files only"
            );
            repository_relative_path(&repository, &entry.path())
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(
        actual, expected,
        "Preview activation profile directory must equal the exact embedded ARG/policy inventory"
    );
}

#[test]
fn every_tracked_file_is_admitted_by_the_whitelist() {
    let violations = tracked_whitelist_violations(&repository_root());
    assert!(
        violations.is_empty(),
        "tracked paths bypass the whitelist policy: {violations:?}"
    );
}

#[test]
fn tracked_file_audit_detects_a_forced_add() {
    let repository = tempfile::tempdir().expect("temporary repository should be creatable");
    run_git(repository.path(), &["init", "--quiet"]);
    std::fs::write(
        repository.path().join(".gitignore"),
        "/*\n!/.gitignore\n!/tests/\n",
    )
    .unwrap();
    std::fs::create_dir(repository.path().join("tests")).unwrap();
    std::fs::write(
        repository.path().join("tests/.gitignore"),
        "/**\n!/.gitignore\n!/**/*.rs\n",
    )
    .unwrap();
    std::fs::write(
        repository.path().join("tests/accepted.rs"),
        "fn accepted() {}\n",
    )
    .unwrap();
    std::fs::write(
        repository.path().join("tests/unreviewed.dwg"),
        b"unreviewed",
    )
    .unwrap();

    run_git(
        repository.path(),
        &[
            "add",
            "--",
            ".gitignore",
            "tests/.gitignore",
            "tests/accepted.rs",
        ],
    );
    run_git(
        repository.path(),
        &["add", "--force", "--", "tests/unreviewed.dwg"],
    );

    assert_eq!(
        tracked_whitelist_violations(repository.path()),
        ["tests/unreviewed.dwg"]
    );
}

fn assert_windows_workflow_envelope(name: &str, workflow: &str) {
    assert!(
        workflow.contains("runs-on: windows-2025"),
        "{name} must use the reviewed GitHub-hosted Windows image"
    );
    assert!(
        workflow.contains("permissions:\n  contents: read"),
        "{name} must have a read-only token"
    );
    assert!(
        workflow.contains("persist-credentials: false"),
        "{name} must not persist checkout credentials"
    );
    assert!(
        workflow.contains("CARGO_INCREMENTAL: \"0\""),
        "{name} must disable incremental compilation"
    );

    for line in workflow.lines().map(str::trim) {
        let Some(action) = line
            .strip_prefix("uses: ")
            .or_else(|| line.strip_prefix("- uses: "))
        else {
            continue;
        };
        let (_, revision) = action
            .split_once('@')
            .expect("workflow actions must include an immutable revision");
        let revision = revision
            .split_whitespace()
            .next()
            .expect("workflow action revision must be present");
        assert_eq!(
            revision.len(),
            40,
            "{name} actions must use full commit SHAs"
        );
        assert!(
            revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{name} action revision is not hexadecimal"
        );
    }

    for forbidden in [
        "pull_request_target",
        "contents: write",
        "permissions: write-all",
        "secrets.",
        "secrets[",
        "environment:",
        "self-hosted",
        "write-all",
        "AUTOCAD_MCP_TIER2_MANIFEST",
        "AUTOCAD_MCP_XREF_CERT_MANIFEST",
        "AUTOCAD_MCP_CERT_OUTPUT_DIR",
        "AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH",
        "AUTOCAD_MCP_XREF_CERTIFIED_ARG_SHA256",
        "AUTOCAD_MCP_ACCORECONSOLE_PATH",
        "AUTOCAD_MCP_XREF_FAILPOINT",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "{name} contains forbidden scope: {forbidden}"
        );
    }
}

fn workflow_run_commands(workflow: &str) -> Vec<&str> {
    workflow
        .lines()
        .filter_map(|line| line.trim().strip_prefix("run: "))
        .collect()
}

fn assert_windows_development_cache_contract(
    name: &str,
    workflow: &str,
    dependency_cache_writer: bool,
    validation_receipt_cache: bool,
) {
    let restore = concat!(
        "uses: actions/cache/restore@",
        "caa296126883cff596d87d8935842f9db880ef25 # v5.1.0"
    );
    let save = concat!(
        "uses: actions/cache/save@",
        "caa296126883cff596d87d8935842f9db880ef25 # v5.1.0"
    );
    let sccache = concat!(
        "uses: mozilla-actions/sccache-action@",
        "9e7fa8a12102821edf02ca5dbea1acd0f89a2696 # v0.0.10"
    );
    let cache_key = concat!(
        "cargo-registry-v1-windows-2025-${{ runner.arch }}-",
        "${{ hashFiles('rust-toolchain.toml') }}-${{ hashFiles('Cargo.lock') }}"
    );

    assert_eq!(
        workflow.matches(restore).count(),
        1 + usize::from(validation_receipt_cache),
        "{name} cache-restore action inventory changed"
    );
    assert_eq!(
        workflow.matches(sccache).count(),
        1,
        "{name} must install the one reviewed compiler cache"
    );
    let sccache_install = workflow
        .find("- name: Install the pinned shared compiler cache")
        .expect("development workflow must install sccache");
    let first_cargo = workflow
        .find("run: cargo fetch --locked")
        .expect("development workflow must fetch locked dependencies");
    assert!(
        sccache_install < first_cargo,
        "{name} must install sccache before any Cargo command can inherit RUSTC_WRAPPER=sccache"
    );
    assert_eq!(
        workflow.matches("version: \"v0.15.0\"").count(),
        1,
        "{name} must pin the reviewed sccache binary version"
    );
    assert_eq!(
        workflow.matches("RUSTC_WRAPPER: sccache").count(),
        1,
        "{name} must configure sccache exactly once"
    );
    assert_eq!(
        workflow.matches("SCCACHE_GHA_ENABLED: \"true\"").count(),
        1,
        "{name} must use the shared GitHub Actions compiler cache"
    );
    assert_eq!(
        workflow.matches("SCCACHE_IDLE_TIMEOUT: \"0\"").count(),
        1,
        "{name} must preserve compiler-cache statistics for the complete job"
    );
    assert_eq!(
        workflow
            .matches("SCCACHE_BASEDIRS: ${{ github.workspace }}")
            .count(),
        1,
        "{name} must normalize the checkout root for cross-workflow hits"
    );
    let steps = workflow
        .find("    steps:\n")
        .expect("development workflow must have a steps block");
    for variable in [
        "RUSTC_WRAPPER: sccache",
        "SCCACHE_BASEDIRS: ${{ github.workspace }}",
        "SCCACHE_GHA_ENABLED: \"true\"",
        "SCCACHE_IDLE_TIMEOUT: \"0\"",
    ] {
        assert!(
            workflow
                .find(variable)
                .is_some_and(|position| position < steps),
            "{name} must configure {variable} at job scope so every Cargo step inherits it"
        );
    }
    assert!(
        workflow.contains(cache_key),
        "{name} dependency cache must bind the runner, toolchain, and Cargo.lock"
    );
    assert!(
        workflow.contains(
            "restore-keys: |\n            cargo-registry-v1-windows-2025-${{ runner.arch }}-"
        ),
        "{name} must use only the reviewed dependency-cache restore prefix"
    );
    for path in ["~/.cargo/registry/index", "~/.cargo/registry/cache"] {
        assert!(
            workflow.contains(path),
            "{name} dependency cache is missing {path}"
        );
    }
    for forbidden in [
        "~/.cargo/registry/src",
        "~/.cargo/git",
        "enableCrossOsArchive",
        "CARGO_INCREMENTAL: \"1\"",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "{name} cache contains forbidden state: {forbidden}"
        );
    }

    if dependency_cache_writer {
        assert_eq!(
            workflow.matches(save).count(),
            1 + usize::from(validation_receipt_cache),
            "{name} cache-save action inventory changed"
        );
        assert!(workflow.contains(
            "if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && steps.cargo-dependencies.outputs.cache-hit != 'true' }}"
        ));
    } else {
        assert!(
            !workflow.contains(save),
            "{name} must remain restore-only for dependency caching"
        );
    }
}

fn assert_windows_semantic_receipt_cache_contract(workflow: &str) {
    let path = "path: .git/autocad-mcp/validation-receipts/v1/subjects";
    let key = "key: windows-semantic-receipt-v2-windows-2025-${{ runner.arch }}-${{ steps.windows-receipt-context.outputs.sha256 }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', 'crates/**', 'tests/fixtures/**', '.github/workflows/windows-native-harness.yml') }}";
    assert_eq!(
        workflow.matches(path).count(),
        2,
        "Windows semantic receipt restore and save must use one exact path"
    );
    assert_eq!(
        workflow.matches(key).count(),
        2,
        "Windows semantic receipt restore and save must use one exact content key"
    );
    assert_eq!(
        workflow.matches("id: windows-semantic-receipt").count(),
        1,
        "Windows semantic receipt must have one cache-hit source"
    );
    assert_eq!(
        workflow.matches("id: windows-receipt-context").count(),
        1,
        "Windows semantic receipts must bind one hosted-image observation"
    );
    assert!(workflow.contains("$env:ImageOS`n$env:ImageVersion`n$env:RUNNER_OS`n$env:RUNNER_ARCH"));
    assert!(workflow.contains(
        "if: ${{ always() && steps.windows_semantic.outcome == 'success' && github.event_name == 'push' && github.ref == 'refs/heads/main' && steps.windows-semantic-receipt.outputs.cache-hit != 'true' }}"
    ));
    let semantic = workflow
        .find("- name: Run the repository-owned Windows semantic tests")
        .expect("Windows semantic step should exist");
    let save = workflow
        .find("- name: Save the trusted main Windows semantic receipt")
        .expect("Windows semantic receipt save should exist");
    let candidate = workflow
        .find("- name: Seal the deterministic Windows target source candidate")
        .expect("Windows candidate step should exist");
    let build = workflow
        .find("- name: Build and inspect the native Release, instrumented, and Preview binaries")
        .expect("Windows native binary build step should exist");
    let desktop = workflow
        .find("- name: Exercise the exact ARG-bound release binary through the Claude Desktop lifecycle")
        .expect("Windows release-binary smoke step should exist");
    let lsp = workflow
        .find("- name: Exercise the exact staged AutoLISP language server")
        .expect("Windows LSP smoke step should exist");
    let package = workflow
        .find("- name: Build the visibly marked Preview MCPB")
        .expect("Windows Preview package step should exist");
    let package_smoke = workflow
        .find("- name: Smoke the Preview package, LSP, and experimental tool surface")
        .expect("Windows Preview package smoke step should exist");
    let aggregate = workflow
        .find("- name: Require every runnable Windows validation")
        .expect("Windows validation aggregate should exist");
    assert!(
        semantic < save
            && save < candidate
            && candidate < build
            && build < desktop
            && desktop < lsp
            && lsp < package
            && package < package_smoke
            && package_smoke < aggregate,
        "the Windows stages and terminal aggregate are out of order"
    );
    assert_eq!(
        workflow.matches("continue-on-error: true").count(),
        9,
        "the two advisory cache saves and seven runnable Windows validations must defer failure appropriately"
    );
    let semantic_block = &workflow[semantic..save];
    assert!(semantic_block.contains("id: windows_semantic"));
    assert!(semantic_block.contains("continue-on-error: true"));
    let save_block = &workflow[save..candidate];
    assert!(
        save_block.contains("continue-on-error: true"),
        "semantic receipt publication must remain advisory"
    );
    let candidate_block = &workflow[candidate..build];
    assert!(candidate_block.contains("id: windows_source_candidate"));
    assert!(candidate_block.contains("continue-on-error: true"));
    let build_block = &workflow[build..desktop];
    assert!(build_block.contains("id: windows_build"));
    assert!(build_block.contains("continue-on-error: true"));
    assert!(
        !build_block.contains("\n        if:"),
        "the Windows build must run independently of semantic and source-candidate failures"
    );
    for (name, block, step_id) in [
        (
            "desktop smoke",
            &workflow[desktop..lsp],
            "id: desktop_smoke",
        ),
        ("LSP smoke", &workflow[lsp..package], "id: lsp_smoke"),
        (
            "Preview package",
            &workflow[package..package_smoke],
            "id: preview_package",
        ),
    ] {
        assert!(block.contains(step_id), "{name} step id changed");
        assert!(
            block.contains("if: ${{ always() && steps.windows_build.outcome == 'success' }}"),
            "{name} must run whenever the independent binary build succeeded"
        );
        assert!(
            block.contains("continue-on-error: true"),
            "{name} must defer failure to the terminal aggregate"
        );
    }
    let package_smoke_block = &workflow[package_smoke..aggregate];
    assert!(package_smoke_block.contains("id: preview_package_smoke"));
    assert!(package_smoke_block
        .contains("if: ${{ always() && steps.preview_package.outcome == 'success' }}"));
    assert!(package_smoke_block.contains("continue-on-error: true"));
    let aggregate_block = &workflow[aggregate..];
    for required in [
        "WINDOWS_SEMANTIC_OUTCOME: ${{ steps.windows_semantic.outcome }}",
        "WINDOWS_SOURCE_CANDIDATE_OUTCOME: ${{ steps.windows_source_candidate.outcome }}",
        "WINDOWS_BUILD_OUTCOME: ${{ steps.windows_build.outcome }}",
        "DESKTOP_SMOKE_OUTCOME: ${{ steps.desktop_smoke.outcome }}",
        "LSP_SMOKE_OUTCOME: ${{ steps.lsp_smoke.outcome }}",
        "PREVIEW_PACKAGE_OUTCOME: ${{ steps.preview_package.outcome }}",
        "PREVIEW_PACKAGE_SMOKE_OUTCOME: ${{ steps.preview_package_smoke.outcome }}",
        "$failures += \"Windows semantic validation\"",
        "$failures += \"Preview source-candidate sealing\"",
        "$failures += \"Release, instrumented, and Preview binary build\"",
        "$failures += \"Claude Desktop binary lifecycle smoke\"",
        "$failures += \"AutoLISP LSP lifecycle smoke\"",
        "$failures += \"Preview MCPB construction\"",
        "$failures += \"Preview MCPB smoke\"",
        "Write-Host \"::error title=Windows validation failure::$failure\"",
        "if ($failures.Count -ne 0)",
        "throw \"$($failures.Count) Windows validation stage(s) failed: $($failures -join '; ')\"",
    ] {
        assert!(
            aggregate_block.contains(required),
            "Windows validation aggregate is missing: {required}"
        );
    }
    assert!(
        aggregate_block.contains("if: ${{ always() }}"),
        "the Windows validation aggregate must run after every preceding outcome"
    );
    assert!(
        !aggregate_block.contains("continue-on-error: true"),
        "the terminal Windows validation aggregate must fail the job"
    );
    let receipt_restore = workflow
        .split("- name: Restore an exact main-authored Windows semantic receipt")
        .nth(1)
        .and_then(|tail| {
            tail.split("- name: Run the repository-owned Windows semantic tests")
                .next()
        })
        .expect("Windows semantic receipt restore block should be closed");
    assert!(
        !receipt_restore.contains("restore-keys:"),
        "validation receipts must restore only an exact content key"
    );
    assert!(
        !workflow.contains("path: target\n"),
        "the Windows workflow must never cache the full Cargo target"
    );
}

fn assert_workflow_path_routing(workflow: &str, expected_paths: &[&str]) {
    for path in expected_paths {
        assert_eq!(
            workflow.matches(&format!("      - {path}\n")).count(),
            2,
            "workflow path routing must include {path} for both pull requests and main pushes"
        );
    }
    assert_eq!(
        workflow.matches("    paths:\n").count(),
        2,
        "workflow must have one pull-request and one push path filter"
    );
}

fn assert_windows_only_test(source: &str, source_path: &str, test_name: &str) {
    let marker = format!("fn {test_name}(");
    let position = source.find(&marker).unwrap_or_else(|| {
        panic!("Windows workflow test is missing from {source_path}: {test_name}")
    });
    let attributes = source[..position].lines().rev().take(4).collect::<Vec<_>>();
    assert!(
        attributes.iter().any(|line| line.trim() == "#[test]"),
        "Windows workflow filter does not name a test in {source_path}: {test_name}"
    );
    assert!(
        attributes.iter().any(|line| {
            matches!(
                line.trim(),
                "#[cfg(windows)]" | "#[cfg(target_os = \"windows\")]"
            )
        }),
        "Windows workflow test is not explicitly Windows-only in {source_path}: {test_name}"
    );
}

#[test]
fn windows_workflows_are_narrow_read_only_and_immutable() {
    let repository = repository_root();
    let workflow_directory = repository.join(".github/workflows");
    let mut workflow_inventory = std::fs::read_dir(&workflow_directory)
        .expect("workflow directory should be readable")
        .filter_map(|entry| {
            let entry = entry.expect("workflow entry should be readable");
            matches!(
                entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str()),
                Some("yml" | "yaml")
            )
            .then(|| entry.file_name().to_string_lossy().into_owned())
        })
        .collect::<Vec<_>>();
    workflow_inventory.sort();
    assert_eq!(
        workflow_inventory,
        [
            "windows-native-harness.yml",
            "windows-preview-review-candidate.yml",
            "windows-xref-guarded-rename.yml"
        ],
        "the remote-Windows workflow inventory is closed"
    );
    let attributes = std::fs::read_to_string(repository.join(".gitattributes"))
        .expect(".gitattributes should be readable");
    for workflow in &workflow_inventory {
        let expected = format!(".github/workflows/{workflow} text eol=lf");
        assert!(
            attributes.lines().any(|line| line == expected),
            "digest-bound workflow is missing its exact LF attribute: {workflow}"
        );
    }

    let xref_path = workflow_directory.join("windows-xref-guarded-rename.yml");
    let xref_bytes = std::fs::read(&xref_path).expect("XREF workflow should be readable");
    assert_eq!(
        format!("{:x}", Sha256::digest(&xref_bytes)),
        WINDOWS_XREF_WORKFLOW_SHA256,
        "the reviewed one-job Windows workflow changed"
    );
    let xref_workflow =
        std::str::from_utf8(&xref_bytes).expect("XREF workflow should remain UTF-8");

    assert_windows_workflow_envelope("XREF feasibility workflow", xref_workflow);
    assert!(xref_workflow.contains(
        "run: $env:GIT_CONFIG_NOSYSTEM = \"1\"; $env:GIT_CONFIG_SYSTEM = \"NUL\"; \
         $env:GIT_CONFIG_GLOBAL = \"NUL\"; $env:GIT_ATTR_NOSYSTEM = \"1\"; \
         $status = @(git status --porcelain=v1 --untracked-files=all); \
         if ($LASTEXITCODE -ne 0) { throw \"isolated Git status failed\" }; \
         if ($status.Count -ne 0) { $status | Write-Error; \
         throw \"checkout bytes depend on ambient Git configuration\" }"
    ));
    assert!(xref_workflow.contains("name: Native filesystem feasibility characterization"));
    assert!(xref_workflow
        .contains("cargo run --locked -p xtask -- windows-native-tests --suite guarded-rename"));
    assert!(xref_workflow
        .contains("path: target/xref-windows-guarded-rename-feasibility-evidence.json"));
    assert_windows_development_cache_contract(
        "XREF feasibility workflow",
        xref_workflow,
        false,
        false,
    );
    assert_workflow_path_routing(
        xref_workflow,
        &[
            ".gitattributes",
            ".github/workflows/windows-xref-guarded-rename.yml",
            "Cargo.lock",
            "Cargo.toml",
            "crates/**",
            "rust-toolchain.toml",
        ],
    );
    assert_eq!(
        xref_workflow.matches("uses: ").count(),
        4,
        "XREF feasibility workflow may import only checkout, cache restore, sccache, and artifact upload"
    );
    let xref_source = std::fs::read_to_string(
        repository.join("crates/autocad-mcp/tests/windows_guarded_rename.rs"),
    )
    .expect("XREF guarded-rename source should be readable");
    assert!(
        xref_source.contains("#[cfg(target_os = \"windows\")]\nmod windows {"),
        "the remotely selected XREF test module must remain explicitly Windows-only"
    );
    assert!(
        xref_source.contains("fn windows_guarded_rename_feasibility_probe()"),
        "the remotely selected XREF test must remain in its reviewed source"
    );

    for forbidden in [
        "cargo clippy",
        "local-gate",
        "plugin-validate",
        "release-packager",
    ] {
        assert!(
            !xref_workflow.contains(forbidden),
            "XREF feasibility workflow contains forbidden scope: {forbidden}"
        );
    }

    let native_path = workflow_directory.join("windows-native-harness.yml");
    let native_bytes =
        std::fs::read(&native_path).expect("native Windows workflow should be readable");
    assert_eq!(
        format!("{:x}", Sha256::digest(&native_bytes)),
        WINDOWS_NATIVE_HARNESS_WORKFLOW_SHA256,
        "the reviewed native Windows workflow changed"
    );
    let native_workflow =
        std::str::from_utf8(&native_bytes).expect("native Windows workflow should remain UTF-8");

    assert_windows_workflow_envelope("native Windows workflow", native_workflow);
    assert!(native_workflow.contains("name: Windows-only non-AutoCAD evidence"));
    assert_windows_development_cache_contract(
        "native Windows workflow",
        native_workflow,
        true,
        true,
    );
    assert_windows_semantic_receipt_cache_contract(native_workflow);
    assert_workflow_path_routing(
        native_workflow,
        &[
            ".gitattributes",
            ".github/workflows/windows-native-harness.yml",
            "Cargo.lock",
            "Cargo.toml",
            "crates/**",
            "plugin/**",
            "rust-toolchain.toml",
            "tests/fixtures/**",
        ],
    );
    assert_eq!(
        native_workflow.matches("uses: ").count(),
        6,
        "native Windows workflow may import only checkout, two cache restores, two cache saves, and sccache"
    );
    let expected_native_commands = [
        "$env:GIT_CONFIG_NOSYSTEM = \"1\"; $env:GIT_CONFIG_SYSTEM = \"NUL\"; $env:GIT_CONFIG_GLOBAL = \"NUL\"; $env:GIT_ATTR_NOSYSTEM = \"1\"; $status = @(git status --porcelain=v1 --untracked-files=all); if ($LASTEXITCODE -ne 0) { throw \"isolated Git status failed\" }; if ($status.Count -ne 0) { $status | Write-Error; throw \"checkout bytes depend on ambient Git configuration\" }",
        "rustup toolchain install --no-self-update",
        "$bytes = [Text.Encoding]::UTF8.GetBytes(\"$env:ImageOS`n$env:ImageVersion`n$env:RUNNER_OS`n$env:RUNNER_ARCH\"); $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant(); \"sha256=$hash\" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append",
        "cargo fetch --locked",
        "cargo run --locked -p xtask -- windows-native-tests --suite semantic --validation-receipt",
        "cargo run --locked -p xtask -- source-candidate-seal --output-dir target/windows-source-candidate --mode preview",
        "cargo run --locked -p xtask -- windows-certification-build-preflight --arg tests/fixtures/windows_certification/public-development-profile.arg --arg-policy tests/fixtures/windows_certification/public-development-arg-policy.json --output-dir target/windows-certification-preflight --sccache",
        "cargo run --locked -p release-packager -- desktop-smoke --binary target/windows-certification-preflight/artifacts/release/autocad-mcp.exe --fixture tests/fixtures/xrefs/portable-evidence-ascii.dxf",
        "cargo run --locked -p release-packager -- lsp-smoke --binary target/windows-certification-preflight/artifacts/release/autolisp-lsp.exe",
        "cargo run --locked -p release-packager -- package --target windows-x64 --binary target/windows-certification-preflight/artifacts/preview/autocad-mcp.exe --lsp-binary target/windows-certification-preflight/artifacts/release/autolisp-lsp.exe --out-dir target/windows-preview-package --preview",
        "cargo run --locked -p release-packager -- smoke --package target/windows-preview-package/autocad-mcp-windows-x64-preview.mcpb --fixture tests/fixtures/xrefs/portable-evidence-ascii.dxf --require-executable --require-lsp-executable",
        "|",
    ];
    assert_eq!(
        workflow_run_commands(native_workflow),
        expected_native_commands,
        "native Windows workflow command inventory changed"
    );
    assert!(
        !native_workflow.contains("cargo run --locked -p distribution-evidence -- check"),
        "the Windows workflow must not duplicate the full evidence check performed by candidate sealing"
    );
    let candidate_seal_source =
        std::fs::read_to_string(repository.join("crates/xtask/src/candidate_seal.rs"))
            .expect("candidate seal source should be readable");
    assert!(
        candidate_seal_source.contains("distribution_evidence::check(repository)"),
        "source candidate sealing must retain its full distribution-evidence validation"
    );

    for (source_path, test_names) in [
        (
            "crates/autocad-mcp/src/engine.rs",
            &[
                "windows_native_semantic_accoreconsole_command_normalizes_only_autocad_path_arguments",
                "windows_native_semantic_certified_profile_guard_allows_compatible_reader_and_denies_mutation_or_replacement",
                "windows_native_semantic_certified_profile_guard_detects_transition_window_tampering",
                "windows_native_semantic_unique_xref_profile_registry_lifecycle_refuses_adoption_and_cleans_owned_root",
                "windows_native_semantic_bounded_probe_runner_drains_all_bytes_while_retaining_a_strict_cap",
                "windows_native_semantic_bounded_probe_runner_observes_pre_spawn_cancellation",
                "windows_native_semantic_bounded_probe_runner_linearizes_cancellation_before_resume",
                "windows_native_semantic_bounded_probe_runner_terminates_inherited_pipe_tree_on_timeout",
                "windows_native_semantic_bounded_probe_runner_cancels_and_joins_running_tree",
                "windows_native_semantic_activation_observation_requires_a_fixed_file_version_resource",
                "windows_native_semantic_activation_executable_launch_lease_guards_file_and_parent_through_spawn",
            ][..],
        ),
        (
            "crates/autocad-mcp/src/activation_platform.rs",
            &[
                "windows_native_semantic_activation_exact_override_rejects_unc_before_canonicalization",
                "windows_native_semantic_activation_fixed_local_volume_admission_rejects_unc",
                "windows_native_semantic_activation_registry_root_seam_reads_exact_language_and_location_and_cleans_up",
            ][..],
        ),
        (
            "crates/autocad-mcp/src/ops/xref_mutation.rs",
            &[
                "windows_native_semantic_transactional_install_is_atomic_and_guarded",
                "windows_native_semantic_source_snapshot_excludes_every_original_path_read",
            ][..],
        ),
        (
            "crates/autocad-mcp/tests/windows_certification.rs",
            &[
                "windows_native_semantic_certified_profile_registry_guard_owns_only_a_new_exact_subtree",
                "windows_native_semantic_exact_runtime_file_binding_denies_windows_write_delete_and_ancestor_rename",
                "windows_native_semantic_bounded_certification_runner_terminates_the_windows_process_tree",
                "windows_native_semantic_bounded_certification_runner_rejects_a_successful_parent_with_a_live_descendant",
            ][..],
        ),
        (
            "crates/distribution/packager/src/smoke.rs",
            &[
                "windows_native_semantic_run_with_timeout_rejects_oversized_stdout",
                "windows_native_semantic_run_with_timeout_terminates_process_tree_after_direct_child_exit",
            ][..],
        ),
    ] {
        let source = std::fs::read_to_string(repository.join(source_path))
            .unwrap_or_else(|error| panic!("read {source_path}: {error}"));
        assert_eq!(
            source.matches("fn windows_native_semantic_").count(),
            test_names.len(),
            "the prefix-selected Windows semantic inventory changed in {source_path}"
        );
        for test_name in test_names {
            assert_windows_only_test(&source, source_path, test_name);
        }
    }

    for forbidden in [
        "AUTOCAD_MCP_",
        "actions/upload-artifact",
        "--ignored",
        "--workspace",
        "--all-targets",
        "cargo clippy",
        "certification-manifest-preflight",
        "--bin autocad-mcp",
        "--lib --",
        "--test windows_certification --",
        "cargo test --locked -p release-packager -- --",
        "cargo test --locked -p xtask",
        "local-gate",
        "plugin-validate",
        "tests/corpus",
    ] {
        assert!(
            !native_workflow.contains(forbidden),
            "native Windows workflow contains forbidden scope: {forbidden}"
        );
    }
}

#[test]
fn non_product_contracts_are_owned_once_at_the_narrowest_boundary() {
    let repository = repository_root();
    let xtask_manifest = std::fs::read_to_string(repository.join("crates/xtask/Cargo.toml"))
        .expect("xtask manifest should be readable");
    for product_scanner_dependency in ["proc-macro2", "syn ="] {
        assert!(
            !xtask_manifest.contains(product_scanner_dependency),
            "xtask must not own product AST policy through {product_scanner_dependency}"
        );
    }
    let root_policy = std::fs::read_to_string(repository.join("tests/repository_policy.rs"))
        .expect("root repository policy should be readable");
    for product_policy in [
        "reader_boundary_backend_consumers_contracts_and_bridges_are_closed",
        "writer_boundary_is_internal_backend_owned_and_application_independent",
    ] {
        assert!(
            !root_policy.contains(&format!("fn {product_policy}")),
            "root policy must not retain product-owned assertion {product_policy}"
        );
    }
    for owned_policy in [
        "crates/autocad-mcp/tests/reader_source_policy.rs",
        "crates/autocad-writer/tests/source_policy.rs",
    ] {
        assert!(
            repository.join(owned_policy).is_file(),
            "product-owned source policy is missing: {owned_policy}"
        );
    }

    for schema in [
        "crates/distribution/plugin-validation/schemas/.claude-plugin/plugin.schema.json",
        "crates/distribution/plugin-validation/schemas/.lsp.schema.json",
        "crates/distribution/plugin-validation/schemas/.mcp.schema.json",
        "crates/distribution/plugin-validation/schemas/skills/skill/SKILL.schema.yaml",
    ] {
        assert!(
            repository.join(schema).is_file(),
            "plugin-validation-owned schema is missing: {schema}"
        );
        let former_fixture = schema.replacen(
            "crates/distribution/plugin-validation/schemas",
            "tests/fixtures/plugin-example",
            1,
        );
        assert!(
            !repository.join(former_fixture).exists(),
            "production schema must not remain owned by a test fixture: {schema}"
        );
    }

    let distribution_rust = WalkDir::new(repository.join("crates/distribution"))
        .follow_links(false)
        .into_iter()
        .map(|entry| entry.expect("distribution source tree should be readable"))
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("rs"))
        .map(|entry| {
            std::fs::read_to_string(entry.path()).unwrap_or_else(|error| {
                panic!(
                    "read distribution source {}: {error}",
                    entry.path().display()
                )
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        distribution_rust
            .iter()
            .map(|source| source.matches("struct StrictJsonVisitor").count())
            .sum::<usize>(),
        1,
        "strict JSON duplicate-key parsing must have one implementation"
    );

    let packager_rust = WalkDir::new(repository.join("crates/distribution/packager/src"))
        .follow_links(false)
        .into_iter()
        .map(|entry| entry.expect("packager source tree should be readable"))
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("rs"))
        .map(|entry| std::fs::read_to_string(entry.path()).expect("packager source should read"))
        .collect::<Vec<_>>();
    for helper in ["fn validate_archive_path(", "fn insert_archive_path("] {
        assert_eq!(
            packager_rust
                .iter()
                .map(|source| source.matches(helper).count())
                .sum::<usize>(),
            1,
            "portable archive-path primitive must have one implementation: {helper}"
        );
    }

    let source_contract = std::fs::read_to_string(
        repository.join("crates/distribution/approval/src/source_candidate.rs"),
    )
    .expect("shared source-candidate contract should be readable");
    assert!(
        source_contract.contains("pub struct SourceBundleManifest"),
        "distribution approval must own the declarative source-candidate contract"
    );
    for consumer in [
        "crates/xtask/src/source_bundle.rs",
        "crates/xtask/src/candidate_seal.rs",
        "crates/distribution/packager/src/approval.rs",
        "crates/distribution/packager/src/preview_build_attestation.rs",
    ] {
        let source = std::fs::read_to_string(repository.join(consumer))
            .unwrap_or_else(|error| panic!("read shared-contract consumer {consumer}: {error}"));
        assert!(
            source.contains("SourceBundleManifest"),
            "source-candidate consumer must use the shared contract: {consumer}"
        );
        assert!(
            !source.contains("struct SourceBundleManifest"),
            "source-candidate consumer must not redefine the shared contract: {consumer}"
        );
    }
}

#[test]
fn preview_review_workflow_is_signed_protected_and_non_publishing() {
    let repository = repository_root();
    let path = repository.join(".github/workflows/windows-preview-review-candidate.yml");
    let bytes = std::fs::read(&path).expect("Preview review workflow should be readable");
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        WINDOWS_PREVIEW_REVIEW_WORKFLOW_SHA256,
        "the reviewed Preview candidate workflow changed"
    );
    let workflow =
        std::str::from_utf8(&bytes).expect("Preview review workflow should remain UTF-8");

    assert!(workflow.starts_with("name: Windows Preview signed review candidate\n\n"));
    assert!(workflow.contains("on:\n  workflow_dispatch:\n"));
    assert!(!workflow.contains("\n  pull_request:"));
    assert!(!workflow.contains("\n  push:"));
    assert!(!workflow.contains("\n  schedule:"));
    assert!(workflow.contains("permissions:\n  contents: read"));
    assert_eq!(
        workflow.matches("permissions:").count(),
        4,
        "Preview candidate workflow must have the global envelope, two empty isolated envelopes, and the exact attestation envelope"
    );
    assert_eq!(
        workflow.matches("    permissions: {}").count(),
        2,
        "signing and supplemental MCPB validation must have empty permission envelopes"
    );
    assert_eq!(workflow.matches("      id-token: write").count(), 1);
    assert_eq!(workflow.matches("      attestations: write").count(), 1);
    assert_eq!(workflow.matches("      contents: read").count(), 1);
    assert!(!workflow.contains("artifact-metadata: write"));
    assert_eq!(
        workflow.matches("environment: preview-signing").count(),
        1,
        "only the isolated signing job may use the protected Environment"
    );
    assert_eq!(
        workflow.matches("runs-on: windows-2025").count(),
        5,
        "the Preview review path must remain a five-job Windows pipeline"
    );
    for job in [
        "  build-preview-inputs:",
        "  sign-preview-binaries:",
        "  package-preview-review:",
        "  validate-preview-mcpb:",
        "  attest-preview-review:",
    ] {
        assert!(
            workflow.contains(job),
            "Preview review workflow is missing job: {job}"
        );
    }
    assert!(workflow.contains("    needs: build-preview-inputs"));
    assert!(workflow
        .contains("    needs:\n      - build-preview-inputs\n      - sign-preview-binaries"));
    assert_eq!(
        workflow.matches("CARGO_INCREMENTAL: \"0\"").count(),
        2,
        "only the two Cargo-owning Preview jobs may configure compilation"
    );
    assert!(workflow.contains("persist-credentials: false"));
    assert!(workflow.contains("GITHUB_REF -cne \"refs/heads/main\""));
    assert!(workflow.contains("source_commit must exactly equal the checked-out main commit"));
    assert!(workflow.contains("signing_certificate_thumbprint:"));
    assert!(workflow.contains("protected_environment_configuration_reviewed:"));
    assert_eq!(
        workflow
            .matches("- name: Require the authorized GitHub execution context")
            .count(),
        5,
        "every Preview workflow job must begin with the origin and principal guard"
    );
    assert_eq!(
        workflow
            .matches("Preview candidate workflow context is not authorized")
            .count(),
        5,
        "every Preview workflow job must fail closed on an unauthorized rerun context"
    );

    let build_job_start = workflow
        .find("  build-preview-inputs:")
        .expect("build job should be present");
    let signing_job_start = workflow
        .find("  sign-preview-binaries:")
        .expect("signing job should be present");
    let package_job_start = workflow
        .find("  package-preview-review:")
        .expect("package job should be present");
    let validation_job_start = workflow
        .find("  validate-preview-mcpb:")
        .expect("supplemental MCPB validation job should be present");
    let attestation_job_start = workflow
        .find("  attest-preview-review:")
        .expect("supplemental attestation job should be present");
    assert!(
        build_job_start < signing_job_start
            && signing_job_start < package_job_start
            && package_job_start < validation_job_start
            && validation_job_start < attestation_job_start
    );
    let build_job = &workflow[build_job_start..signing_job_start];
    let signing_job = &workflow[signing_job_start..package_job_start];
    let package_job = &workflow[package_job_start..validation_job_start];
    let validation_job = &workflow[validation_job_start..attestation_job_start];
    let attestation_job = &workflow[attestation_job_start..];
    let cache_restore_action =
        "uses: actions/cache/restore@caa296126883cff596d87d8935842f9db880ef25 # v5.1.0";
    let cache_save_action =
        "uses: actions/cache/save@caa296126883cff596d87d8935842f9db880ef25 # v5.1.0";
    let sccache_action =
        "uses: mozilla-actions/sccache-action@9e7fa8a12102821edf02ca5dbea1acd0f89a2696 # v0.0.10";
    assert!(!build_job.contains("${{ secrets."));
    assert!(!build_job.contains("${{ vars."));
    assert!(!build_job.contains("environment:"));
    assert!(!package_job.contains("${{ secrets."));
    assert!(!package_job.contains("${{ vars."));
    assert!(!package_job.contains("environment:"));
    assert!(signing_job.contains("environment: preview-signing"));
    assert!(signing_job.contains("permissions: {}"));
    assert!(!signing_job.contains("actions/checkout"));
    assert!(!signing_job.contains("cargo "));
    assert!(!signing_job.contains("git "));
    assert!(validation_job.contains("permissions: {}"));
    assert!(!validation_job.contains("actions/checkout"));
    assert!(!validation_job.contains("${{ secrets."));
    assert!(!validation_job.contains("${{ vars."));
    assert!(!validation_job.contains("environment:"));
    assert!(!validation_job.contains("cargo "));
    assert!(!validation_job.contains("git "));
    assert!(!validation_job.contains("actions/attest"));
    assert!(!attestation_job.contains("actions/checkout"));
    assert!(!attestation_job.contains("${{ secrets."));
    assert!(!attestation_job.contains("${{ vars."));
    assert!(!attestation_job.contains("environment:"));
    assert!(!attestation_job.contains("cargo "));
    assert!(!attestation_job.contains("git "));
    assert!(!attestation_job.contains("npm "));

    for (name, job) in [
        ("Preview input build", build_job),
        ("Preview package review", package_job),
    ] {
        assert_eq!(
            job.matches("RUSTC_WRAPPER: sccache").count(),
            1,
            "{name} must configure one shared compiler cache"
        );
        assert_eq!(
            job.matches("SCCACHE_BASEDIRS: ${{ github.workspace }}")
                .count(),
            1,
            "{name} must normalize the checkout root for compiler-cache reuse"
        );
        assert_eq!(
            job.matches("SCCACHE_GHA_ENABLED: \"true\"").count(),
            1,
            "{name} must use the GitHub Actions compiler-cache backend"
        );
        assert_eq!(
            job.matches("SCCACHE_IDLE_TIMEOUT: \"0\"").count(),
            1,
            "{name} must preserve compiler-cache statistics for the complete job"
        );
        assert_eq!(
            job.matches(sccache_action).count(),
            1,
            "{name} must install the reviewed sccache action"
        );
        assert_eq!(
            job.matches("version: \"v0.15.0\"").count(),
            1,
            "{name} must pin the reviewed sccache binary"
        );
        assert_eq!(
            job.matches(cache_restore_action).count(),
            1,
            "{name} must restore the shared dependency cache"
        );
        let steps = job
            .find("    steps:\n")
            .expect("Cargo-owning Preview job should have a steps block");
        let sccache = job
            .find("- name: Install the pinned shared compiler cache")
            .expect("Cargo-owning Preview job should install sccache");
        let restore = job
            .find("- name: Restore the shared locked Cargo dependency cache")
            .expect("Cargo-owning Preview job should restore dependencies");
        let fetch = job
            .find("run: cargo fetch --locked")
            .expect("Cargo-owning Preview job should fetch locked dependencies");
        assert!(
            sccache < restore && restore < fetch,
            "{name} cache initialization must precede the first Cargo command"
        );
        for variable in [
            "RUSTC_WRAPPER: sccache",
            "SCCACHE_BASEDIRS: ${{ github.workspace }}",
            "SCCACHE_GHA_ENABLED: \"true\"",
            "SCCACHE_IDLE_TIMEOUT: \"0\"",
        ] {
            assert!(
                job.find(variable).is_some_and(|position| position < steps),
                "{name} must configure {variable} at job scope"
            );
        }
    }
    assert_eq!(
        build_job.matches(cache_save_action).count(),
        1,
        "the authorized unsigned-build job must own dependency-cache publication"
    );
    assert!(build_job
        .contains("if: ${{ steps.preview-build-cargo-dependencies.outputs.cache-hit != 'true' }}"));
    let dependency_cache_save = build_job
        .find("- name: Save the authorized Preview dependency cache")
        .expect("Preview input build should publish a missing dependency cache");
    let evidence_check = build_job
        .find("- name: Revalidate source-closure and third-party licence evidence")
        .expect("Preview input build should retain its evidence check");
    assert!(
        build_job[dependency_cache_save..evidence_check].contains("continue-on-error: true"),
        "dependency-cache publication must remain advisory"
    );
    assert!(
        !package_job.contains(cache_save_action),
        "the packaging job must remain restore-only for shared dependencies"
    );
    for (name, job) in [
        ("signing", signing_job),
        ("supplemental validation", validation_job),
        ("attestation", attestation_job),
    ] {
        for forbidden in [
            "RUSTC_WRAPPER",
            "SCCACHE_",
            sccache_action,
            cache_restore_action,
            cache_save_action,
            "cargo-registry-v1-",
        ] {
            assert!(
                !job.contains(forbidden),
                "{name} job must remain isolated from compilation caching: {forbidden}"
            );
        }
    }
    assert_eq!(
        workflow
            .matches("cargo-registry-v1-windows-2025-${{ runner.arch }}-")
            .count(),
        5,
        "Preview dependency-cache key and restore-prefix inventory changed"
    );
    assert_eq!(workflow.matches("~/.cargo/registry/index").count(), 3);
    assert_eq!(workflow.matches("~/.cargo/registry/cache").count(), 3);
    assert_eq!(workflow.matches("restore-keys:").count(), 2);
    for forbidden in [
        "~/.cargo/registry/src",
        "~/.cargo/git",
        "enableCrossOsArchive",
        "path: target\n",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "Preview workflow cache contains forbidden state: {forbidden}"
        );
    }

    assert_eq!(
        workflow.matches("uses: ").count(),
        17,
        "Preview candidate workflow may import only the reviewed checkout, cache, artifact, Node, and attestation actions"
    );
    for line in workflow.lines().map(str::trim) {
        let Some(action) = line
            .strip_prefix("uses: ")
            .or_else(|| line.strip_prefix("- uses: "))
        else {
            continue;
        };
        let (_, revision) = action
            .split_once('@')
            .expect("Preview candidate actions must include an immutable revision");
        let revision = revision
            .split_whitespace()
            .next()
            .expect("Preview candidate action revision must be present");
        assert_eq!(
            revision.len(),
            40,
            "Preview candidate actions must use full commit SHAs"
        );
        assert!(
            revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Preview candidate action revision is not hexadecimal"
        );
    }
    let checkout_action =
        "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1";
    let download_action =
        "uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1";
    let upload_action =
        "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1";
    let setup_node_action =
        "uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0";
    let attest_action = "uses: actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6 # v4.2.0";
    assert_eq!(workflow.matches(checkout_action).count(), 2);
    assert_eq!(workflow.matches(sccache_action).count(), 2);
    assert_eq!(workflow.matches(cache_restore_action).count(), 2);
    assert_eq!(workflow.matches(cache_save_action).count(), 1);
    assert_eq!(workflow.matches(download_action).count(), 5);
    assert_eq!(workflow.matches(upload_action).count(), 3);
    assert_eq!(workflow.matches(setup_node_action).count(), 1);
    assert_eq!(workflow.matches(attest_action).count(), 1);
    assert_eq!(
        workflow.matches("Compare-Object").count(),
        8,
        "every closed-inventory comparison must remain reviewable"
    );
    for line in workflow
        .lines()
        .filter(|line| line.contains("Compare-Object"))
    {
        assert!(
            line.contains("-CaseSensitive"),
            "closed-inventory comparison is not case-sensitive: {line}"
        );
    }
    assert_eq!(
        workflow.matches("[System.StringComparer]::Ordinal").count(),
        5,
        "every checksum inventory must use exact ordinal path keys"
    );
    for forbidden in [
        "$checksumMap = @{}",
        "$buildChecksumMap = @{}",
        "$signedChecksumMap = @{}",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "checksum inventory regressed to case-insensitive keys: {forbidden}"
        );
    }

    assert_eq!(
        workflow.matches("${{ secrets.").count(),
        2,
        "only the exact PFX and password secrets are admitted"
    );
    for secret in [
        "secrets.WINDOWS_SIGNING_CERTIFICATE_PFX_BASE64",
        "secrets.WINDOWS_SIGNING_CERTIFICATE_PASSWORD",
    ] {
        assert!(
            workflow.contains(secret),
            "missing signing secret: {secret}"
        );
    }
    for variable in [
        "vars.WINDOWS_SIGNING_CERTIFICATE_PFX_SHA256",
        "vars.WINDOWS_SIGNING_CERTIFICATE_THUMBPRINT",
        "vars.WINDOWS_SIGNING_TIMESTAMP_URL",
    ] {
        assert!(
            workflow.contains(variable),
            "missing protected signing variable: {variable}"
        );
    }
    assert_eq!(
        workflow.matches("${{ vars.").count(),
        3,
        "only the exact digest, signer, and timestamp variables are admitted"
    );

    let expected_commands = [
        "|",
        "|",
        "rustup toolchain install --no-self-update",
        "cargo fetch --locked",
        "cargo run --locked -p distribution-evidence -- check",
        "cargo run --locked -p xtask -- source-candidate-seal --output-dir target/windows-preview-source-candidate --mode preview",
        "|",
        "|",
        "|",
        "|",
        "|",
        "|",
        "|",
        "rustup toolchain install --no-self-update",
        "cargo fetch --locked",
        "|",
        "cargo run --locked -p xtask -- source-candidate-verify --candidate-dir target/windows-preview-build-input/source-candidate --mode preview",
        "cargo run --locked -p release-packager -- package --target windows-x64 --binary target/windows-preview-signed/autocad-mcp.exe --lsp-binary target/windows-preview-signed/autolisp-lsp.exe --out-dir target/windows-preview-package --preview",
        "|",
        "cargo run --locked -p release-packager -- smoke --package target/windows-preview-review/autocad-mcp-windows-x64-preview.mcpb --fixture tests/fixtures/xrefs/portable-evidence-ascii.dxf --require-executable --require-lsp-executable",
        "|",
        "|",
        "|",
        "|",
        "|",
        "|",
        "|",
        "|",
    ];
    assert_eq!(
        workflow_run_commands(workflow),
        expected_commands,
        "Preview candidate single-line command inventory changed"
    );
    assert!(workflow.contains(
        "cargo run --locked -p xtask -- windows-certification-build-preflight --arg tests/fixtures/windows_certification/public-development-profile.arg --arg-policy tests/fixtures/windows_certification/public-development-arg-policy.json --output-dir target/windows-preview-build-preflight --sccache"
    ));
    for contract in [
        "SIGNING_CERTIFICATE_PFX_SHA256 -cnotmatch '^[0-9a-f]{64}$'",
        "SIGNING_CERTIFICATE_THUMBPRINT -cnotmatch '^[0-9a-f]{40}$'",
        "PROTECTED_ENVIRONMENT_CONFIGURATION_REVIEWED -cne \"true\"",
        "DISPATCH_SIGNING_CERTIFICATE_THUMBPRINT -cne $env:SIGNING_CERTIFICATE_THUMBPRINT",
        "$timestamp.Scheme -cne \"https\"",
        "ConvertTo-SecureString",
        "Import-PfxCertificate",
        "Remove-Item Env:SIGNING_CERTIFICATE_PASSWORD",
        "Remove-Item Env:SIGNING_CERTIFICATE_PFX_BASE64",
        "sign /sha1 $expectedThumbprint /s My",
        "Remove-Item -LiteralPath $certificatePath -DeleteKey -Force",
        "signtool.exe",
        "Get-AuthenticodeSignature",
        "TimeStamperCertificate",
        "packaged executable bytes differ from the signed handoff",
        "source-candidate-verify --candidate-dir target/windows-preview-build-input/source-candidate --mode preview",
        "create-preview-build-attestation",
        "--github-repository \"$env:ATTESTATION_GITHUB_REPOSITORY\"",
        "--github-server-url \"$env:ATTESTATION_GITHUB_SERVER_URL\"",
        "--github-ref \"$env:ATTESTATION_GITHUB_REF\"",
        "--github-event-name \"$env:ATTESTATION_GITHUB_EVENT_NAME\"",
        "--github-actor \"$env:ATTESTATION_GITHUB_ACTOR\"",
        "--github-triggering-actor \"$env:ATTESTATION_GITHUB_TRIGGERING_ACTOR\"",
        "GITHUB_REPOSITORY -cne \"andagni/autocad-mcp\"",
        "GITHUB_SERVER_URL -cne \"https://github.com\"",
        "GITHUB_EVENT_NAME -cne \"workflow_dispatch\"",
        "GITHUB_ACTOR -cne \"andagni\"",
        "GITHUB_TRIGGERING_ACTOR -cne \"andagni\"",
        "Preview candidate workflow context is not authorized",
        "tar -xf $reviewMcpb -C $extractDirectory",
        "path: target/windows-preview-review/",
        "retention-days: 7",
        "if-no-files-found: error",
        "compression-level: 0",
        "overwrite: false",
        "include-hidden-files: false",
        "node-version: 24.18.0",
        "package-manager-cache: false",
        "npm ci --prefix $validatorRoot --include=dev --ignore-scripts --no-audit --no-fund",
        "node $cli validate $mcpbDirectory",
        "the official MCPB CLI version does not match the reviewed lock",
        "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
        "create-storage-record: false",
        "target/windows-preview-review/autocad-mcp-windows-x64-preview.mcpb",
        "target/windows-preview-review/autocad-mcp-windows-x64-preview-build-source.zip",
    ] {
        assert!(
            workflow.contains(contract),
            "Preview candidate workflow is missing contract: {contract}"
        );
    }
    assert!(
        !workflow.contains("/p $env:SIGNING_CERTIFICATE_PASSWORD"),
        "the PFX password must not be passed on a child-process command line"
    );
    assert_eq!(workflow.matches("retention-days: 1").count(), 2);
    for retained in [
        "autocad-mcp-windows-x64-preview.mcpb",
        "autocad-mcp-windows-x64-preview-build-source.zip",
        "distribution-evidence/windows-x64-preview-build.json",
        "distribution-evidence/windows-x64-preview-source-closure.spdx.json",
        "review-only/unsigned-development-preflight.json",
        "SHA256SUMS.txt",
    ] {
        assert!(
            workflow.contains(retained),
            "Preview review inventory is missing {retained}"
        );
    }
    let assemble_position = workflow
        .find("- name: Assemble the exact non-publishing review bytes")
        .expect("final review assembly step should be present");
    let smoke_position = workflow
        .find("- name: Smoke both signed executables from the exact review MCPB")
        .expect("exact final-path smoke should be present");
    let verify_position = workflow
        .find("- name: Verify the exact signed review inputs")
        .expect("exact signed-input verification should be present");
    let build_attestation_position = workflow
        .find("- name: Create the final post-signing Preview build attestation")
        .expect("final Preview build attestation step should be present");
    let checksum_position = workflow
        .find("- name: Checksum and close the exact upload inventory")
        .expect("exact upload checksum closure should be present");
    let upload_position = workflow
        .find("- name: Upload the signed non-publishing review candidate")
        .expect("final upload should be present");
    let supplemental_validation_position = workflow
        .find("  validate-preview-mcpb:")
        .expect("supplemental MCPB validation job should be present");
    let supplemental_attestation_position = workflow
        .find("  attest-preview-review:")
        .expect("supplemental attestation job should be present");
    assert!(
        assemble_position < smoke_position
            && smoke_position < verify_position
            && verify_position < build_attestation_position
            && build_attestation_position < checksum_position
            && checksum_position < upload_position
            && upload_position < supplemental_validation_position
            && supplemental_validation_position < supplemental_attestation_position,
        "final MCPB bytes must be assembled, smoked, verified, uploaded, independently validated, and only then attested"
    );

    for forbidden in [
        "pull_request_target",
        "contents: write",
        "permissions: write-all",
        "write-all",
        "gh release",
        "current-distribution-verify",
        "owner_distribution_approval",
        "OWNER_DISTRIBUTION_APPROVAL",
        "AUTOCAD_MCP_TIER2_MANIFEST",
        "AUTOCAD_MCP_XREF_CERT_MANIFEST",
        "AUTOCAD_MCP_CERT_OUTPUT_DIR",
        "AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH",
        "AUTOCAD_MCP_ACCORECONSOLE_PATH",
        "AUTOCAD_MCP_XREF_FAILPOINT",
        "--ignored",
        "tests/corpus",
        "self-hosted",
        "mcpb pack",
        "mcpb sign",
        "mcpb verify",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "Preview candidate workflow contains forbidden scope: {forbidden}"
        );
    }
}

#[test]
fn preview_publication_bridge_is_fixed_noninteractive_and_private_by_construction() {
    let repository = repository_root();
    let publisher = std::fs::read_to_string(
        repository.join("crates/distribution/packager/src/preview_publication.rs"),
    )
    .expect("Preview publisher source should be readable");
    let production = publisher
        .split_once("#[cfg(test)]")
        .map_or(publisher.as_str(), |(production, _)| production);

    for required in [
        "pub const PREVIEW_GITHUB_REPOSITORY: &str = \"andagni/autocad-mcp\";",
        "const GITHUB_API_VERSION: &str = \"2026-03-10\";",
        "repos/andagni/autocad-mcp/immutable-releases",
        "(\"GH_PROMPT_DISABLED\".to_owned(), \"1\".to_owned())",
        "\"--no-replace-objects\"",
        "\"ls-files\", \"-v\", \"-z\"",
        "make_latest: \"false\"",
        "each of the seven Preview assets must be smaller than 2 GiB",
        "remote_asset.state != \"uploaded\"",
        "source_authority_sha256",
        "source repository must be the primary common checkout",
        "owner-selected GitHub CLI executable changed during publication",
        "staged Preview public assets must be anonymous regular files",
        "execute_with_github_token_and_file_stdin",
        "GH_NO_EXTENSION_UPDATE_NOTIFIER",
        "branches?per_page={PAGE_SIZE}&page={page}",
        "exclusive_write_window_confirmed",
        "owner-enforced exclusive write window",
        "sealing is unsupported on Windows until owner-only private-key ACL admission is implemented",
        "verify immutable GitHub release",
    ] {
        assert!(
            production.contains(required),
            "Preview publisher is missing closed publication policy: {required}"
        );
    }
    for forbidden in [
        "--clobber",
        "\"delete\"",
        "release delete",
        "contents: write",
    ] {
        assert!(
            !production.contains(forbidden),
            "Preview publisher admits a forbidden mutation path: {forbidden}"
        );
    }

    let handoff_contract = std::fs::read_to_string(
        repository.join("crates/distribution/approval/src/preview_publication_handoff.rs"),
    )
    .expect("Preview handoff contract should be readable");
    for required in [
        "PREVIEW_PUBLICATION_HANDOFF_SCHEMA_VERSION: u32 = 2",
        "autocad-mcp.release/preview-publication-handoff/v2",
        "source_authority_sha256",
    ] {
        assert!(
            handoff_contract.contains(required),
            "Preview handoff is missing authenticated source-authority policy: {required}"
        );
    }
    let public_inventory_start = handoff_contract
        .find("pub const PREVIEW_PUBLICATION_PUBLIC_ASSET_PATHS")
        .expect("Preview handoff should declare the public asset inventory");
    let public_inventory_tail = &handoff_contract[public_inventory_start..];
    let public_inventory_end = public_inventory_tail
        .find("];")
        .expect("Preview public asset inventory should be closed");
    let public_inventory = &public_inventory_tail[..public_inventory_end];
    for public in [
        "PREVIEW_PUBLICATION_MCPB_PATH",
        "PREVIEW_PUBLICATION_SOURCE_ARCHIVE_PATH",
        "PREVIEW_PUBLICATION_SOURCE_CLOSURE_SBOM_PATH",
        "PREVIEW_PUBLICATION_BUILD_ATTESTATION_PATH",
        "PREVIEW_PUBLICATION_CLEAN_HOST_RECEIPT_PATH",
        "PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH",
    ] {
        assert!(
            public_inventory.contains(public),
            "Preview public inventory is missing {public}"
        );
    }
    for private in [
        "PREVIEW_PUBLICATION_PROJECTION_RECEIPT_PATH",
        "PREVIEW_PUBLICATION_CURRENT_DISTRIBUTION_RECEIPT_PATH",
        "PREVIEW_PUBLICATION_HANDOFF",
    ] {
        assert!(
            !public_inventory.contains(private),
            "private selection material entered the Preview public inventory: {private}"
        );
    }
}
