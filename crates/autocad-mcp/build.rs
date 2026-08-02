use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn main() {
    let manifest_dir = PathBuf::from(required_env("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir
        .ancestors()
        .nth(2)
        .expect("autocad-mcp must live under <workspace>/crates")
        .to_path_buf();
    let cargo_lock = workspace.join("Cargo.lock");
    let reader_manifest_dir = workspace.join("crates/autocad-reader");
    let writer_manifest_dir = workspace.join("crates/autocad-writer");

    let mut source_files = Vec::new();
    collect_files(&manifest_dir.join("src"), &mut source_files);
    collect_files(&manifest_dir.join("resources"), &mut source_files);
    collect_files(&manifest_dir.join("profile-registry"), &mut source_files);
    collect_files(&reader_manifest_dir.join("src"), &mut source_files);
    collect_files(&writer_manifest_dir.join("src"), &mut source_files);
    source_files.push(manifest_dir.join("Cargo.toml"));
    source_files.push(manifest_dir.join("build.rs"));
    source_files.push(reader_manifest_dir.join("Cargo.toml"));
    source_files.push(writer_manifest_dir.join("Cargo.toml"));

    let mut operation_files = vec![manifest_dir.join("src/engine.rs")];
    collect_files_matching(
        &manifest_dir.join("src/ops"),
        &mut operation_files,
        |path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("xref") && name.ends_with(".rs"))
        },
    );

    for path in source_files
        .iter()
        .chain(&operation_files)
        .chain([&cargo_lock])
    {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rerun-if-env-changed=AUTOCAD_MCP_XREF_CERTIFIED_ARG_SHA256");
    println!("cargo:rerun-if-env-changed=AUTOCAD_MCP_XREF_CERTIFIED_ARG_POLICY_ID");
    println!("cargo:rerun-if-env-changed=AUTOCAD_MCP_XREF_CERTIFIED_ARG_POLICY_SHA256");
    println!("cargo:rerun-if-env-changed=AUTOCAD_MCP_SOURCE_COMMIT");
    let source_commit = source_commit(&workspace);

    let certified_arg_sha256 =
        env::var("AUTOCAD_MCP_XREF_CERTIFIED_ARG_SHA256").unwrap_or_default();
    let certified_arg_policy_id =
        env::var("AUTOCAD_MCP_XREF_CERTIFIED_ARG_POLICY_ID").unwrap_or_default();
    let certified_arg_policy_sha256 =
        env::var("AUTOCAD_MCP_XREF_CERTIFIED_ARG_POLICY_SHA256").unwrap_or_default();
    validate_certified_arg_build_identity(
        &certified_arg_sha256,
        &certified_arg_policy_id,
        &certified_arg_policy_sha256,
    );

    let source_tree_sha256 = hash_file_set(&workspace, &source_files);
    let cargo_lock_sha256 = hash_file(&cargo_lock);
    let compiler = command_stdout(
        Command::new(required_env("RUSTC")).arg("-vV"),
        "inspect rustc",
    )
    .lines()
    .map(str::trim)
    .filter(|line| !line.is_empty())
    .collect::<Vec<_>>()
    .join("; ");
    let target = required_env("TARGET");
    let profile = required_env("PROFILE");
    let optimization = required_env("OPT_LEVEL");
    let target_features = required_env("CARGO_CFG_TARGET_FEATURE");
    let crt_linkage = if target.ends_with("-windows-msvc") {
        if target_features
            .split(',')
            .any(|feature| feature == "crt-static")
        {
            "static"
        } else {
            "dynamic"
        }
    } else {
        "not_applicable"
    };
    let shared_operation_source_sha256 = hash_file_set(&workspace, &operation_files);
    let preview_enabled = env::var_os("CARGO_FEATURE_PREVIEW").is_some();
    let failpoints_enabled = env::var_os("CARGO_FEATURE_XREF_CERTIFICATION_FAILPOINTS").is_some();
    assert!(
        !(preview_enabled && failpoints_enabled),
        "the preview and xref-certification-failpoints features are mutually exclusive"
    );
    let build_flavor = match (preview_enabled, failpoints_enabled) {
        (false, false) => "release",
        (true, false) => "preview",
        (false, true) => "xref-certification-failpoints",
        (true, true) => unreachable!("mutually exclusive build features were rejected"),
    };
    let build_id = hash_fields(&[
        &source_commit,
        &source_tree_sha256,
        &cargo_lock_sha256,
        &compiler,
        &target,
        &profile,
        &optimization,
        crt_linkage,
        &shared_operation_source_sha256,
        &certified_arg_sha256,
        &certified_arg_policy_id,
        &certified_arg_policy_sha256,
        build_flavor,
    ]);

    for (name, value) in [
        ("AUTOCAD_MCP_BUILD_SOURCE_COMMIT", source_commit.as_str()),
        (
            "AUTOCAD_MCP_BUILD_SOURCE_TREE_SHA256",
            source_tree_sha256.as_str(),
        ),
        (
            "AUTOCAD_MCP_BUILD_CARGO_LOCK_SHA256",
            cargo_lock_sha256.as_str(),
        ),
        ("AUTOCAD_MCP_BUILD_COMPILER", compiler.as_str()),
        ("AUTOCAD_MCP_BUILD_TARGET", target.as_str()),
        ("AUTOCAD_MCP_BUILD_PROFILE", profile.as_str()),
        ("AUTOCAD_MCP_BUILD_OPT_LEVEL", optimization.as_str()),
        ("AUTOCAD_MCP_BUILD_CRT_LINKAGE", crt_linkage),
        ("AUTOCAD_MCP_BUILD_ID", build_id.as_str()),
        (
            "AUTOCAD_MCP_BUILD_SHARED_OPERATION_SOURCE_SHA256",
            shared_operation_source_sha256.as_str(),
        ),
        (
            "AUTOCAD_MCP_BUILD_CERTIFIED_ARG_SHA256",
            certified_arg_sha256.as_str(),
        ),
        (
            "AUTOCAD_MCP_BUILD_CERTIFIED_ARG_POLICY_ID",
            certified_arg_policy_id.as_str(),
        ),
        (
            "AUTOCAD_MCP_BUILD_CERTIFIED_ARG_POLICY_SHA256",
            certified_arg_policy_sha256.as_str(),
        ),
    ] {
        println!("cargo:rustc-env={name}={value}");
    }
}

fn validate_certified_arg_build_identity(arg_sha256: &str, policy_id: &str, policy_sha256: &str) {
    let empty = [
        arg_sha256.is_empty(),
        policy_id.is_empty(),
        policy_sha256.is_empty(),
    ];
    if empty.iter().all(|value| *value) {
        return;
    }
    assert!(
        empty.iter().all(|value| !*value),
        "certified ARG build identity must provide ARG SHA-256, policy ID, and policy SHA-256 together"
    );
    for (label, digest) in [
        ("certified ARG", arg_sha256),
        ("certified ARG policy", policy_sha256),
    ] {
        assert!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "{label} SHA-256 must contain exactly 64 lowercase hexadecimal digits"
        );
    }
    assert!(
        policy_id == policy_id.trim()
            && !policy_id.is_empty()
            && policy_id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            }),
        "certified ARG policy ID must be canonical lowercase ASCII"
    );
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("build environment is missing {name}"))
}

fn source_commit(workspace: &Path) -> String {
    match env::var("AUTOCAD_MCP_SOURCE_COMMIT") {
        Ok(value) => {
            validate_source_commit(&value).unwrap_or_else(|error| panic!("{error}"));
            value
        }
        Err(env::VarError::NotPresent) => {
            emit_git_rerun_paths(workspace);
            let value = git_stdout(workspace, &["rev-parse", "HEAD"]);
            validate_source_commit(&value)
                .unwrap_or_else(|error| panic!("Git returned an invalid source commit: {error}"));
            value
        }
        Err(env::VarError::NotUnicode(_)) => {
            panic!("AUTOCAD_MCP_SOURCE_COMMIT must be valid UTF-8")
        }
    }
}

fn validate_source_commit(value: &str) -> Result<(), String> {
    if matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(format!(
            "AUTOCAD_MCP_SOURCE_COMMIT must be exactly 40 or 64 lowercase hexadecimal digits, got {value:?}"
        ))
    }
}

fn collect_files(directory: &Path, files: &mut Vec<PathBuf>) {
    collect_files_matching(directory, files, |_| true);
}

fn collect_files_matching(
    directory: &Path,
    files: &mut Vec<PathBuf>,
    include: impl Copy + Fn(&Path) -> bool,
) {
    let mut entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        .map(|entry| entry.expect("source entry must be readable").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_files_matching(&path, files, include);
        } else if path.is_file() && include(&path) {
            files.push(path);
        }
    }
}

fn hash_file(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    hex(Sha256::digest(bytes))
}

fn hash_file_set(root: &Path, paths: &[PathBuf]) -> String {
    let mut hasher = Sha256::new();
    for (relative, path) in canonical_file_set(root, paths) {
        let bytes =
            fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    hex(hasher.finalize())
}

fn canonical_file_set<'a>(root: &Path, paths: &'a [PathBuf]) -> Vec<(String, &'a Path)> {
    let mut files = paths
        .iter()
        .map(|path| {
            let relative = path
                .strip_prefix(root)
                .unwrap_or_else(|_| panic!("{} is outside {}", path.display(), root.display()))
                .to_string_lossy()
                .replace('\\', "/");
            (relative, path.as_path())
        })
        .collect::<Vec<_>>();
    // The verifier orders Git tree entries by canonical repository path. Native
    // Path ordering is component-based and differs for file/directory prefix
    // pairs such as `resources.rs` and `resources/ctb.rs`.
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn hash_fields(fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    hex(hasher.finalize())
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn git_stdout(workspace: &Path, args: &[&str]) -> String {
    command_stdout(
        Command::new("git").args(args).current_dir(workspace),
        "inspect Git",
    )
}

fn command_stdout(command: &mut Command, label: &str) -> String {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    if !output.status.success() {
        panic!("{label}: {}", String::from_utf8_lossy(&output.stderr));
    }
    String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("{label} output is not UTF-8: {error}"))
        .trim()
        .to_string()
}

fn emit_git_rerun_paths(workspace: &Path) {
    let head = git_stdout(workspace, &["rev-parse", "--git-path", "HEAD"]);
    let head = resolve_git_path(workspace, &head);
    println!("cargo:rerun-if-changed={}", head.display());
    let reference = Command::new("git")
        .args(["symbolic-ref", "-q", "HEAD"])
        .current_dir(workspace)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string());
    if let Some(reference) = reference.filter(|value| !value.is_empty()) {
        let reference = git_stdout(workspace, &["rev-parse", "--git-path", &reference]);
        println!(
            "cargo:rerun-if-changed={}",
            resolve_git_path(workspace, &reference).display()
        );
    }
}

fn resolve_git_path(workspace: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        workspace.join(path)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{canonical_file_set, validate_source_commit};

    #[test]
    fn file_set_hashing_uses_canonical_repository_path_order() {
        let root = Path::new("workspace");
        let paths = [
            "crates/autocad-writer/src/portable_plot/resources/ctb.rs",
            "crates/autocad-writer/src/portable_plot/adapter/compiler.rs",
            "crates/autocad-writer/src/portable_plot/resources.rs",
            "crates/autocad-writer/src/portable_plot/adapter.rs",
        ]
        .into_iter()
        .map(|path| root.join(path))
        .collect::<Vec<_>>();

        let ordered = canonical_file_set(root, &paths)
            .into_iter()
            .map(|(relative, _)| relative)
            .collect::<Vec<_>>();
        assert_eq!(
            ordered,
            [
                "crates/autocad-writer/src/portable_plot/adapter.rs",
                "crates/autocad-writer/src/portable_plot/adapter/compiler.rs",
                "crates/autocad-writer/src/portable_plot/resources.rs",
                "crates/autocad-writer/src/portable_plot/resources/ctb.rs",
            ]
        );
    }

    #[test]
    fn source_commit_override_requires_a_canonical_git_object_id() {
        assert!(validate_source_commit(&"a".repeat(40)).is_ok());
        assert!(validate_source_commit(&"b".repeat(64)).is_ok());
        assert!(validate_source_commit("").is_err());
        assert!(validate_source_commit(&"a".repeat(39)).is_err());
        assert!(validate_source_commit(&"A".repeat(40)).is_err());
        assert!(validate_source_commit(&format!("{}g", "a".repeat(39))).is_err());
    }
}
