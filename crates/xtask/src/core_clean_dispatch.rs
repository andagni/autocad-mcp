mod cargo_layout;

use cargo_layout::CargoStorageLayout;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicU64, Ordering};

const GOVERNED_CORE_PROFILES: [&str; 2] = [cargo_layout::SOURCE_VALIDATION_PROFILE, "release"];
const CACHE_POLICY_SOURCE_PATHS: [&str; 2] = [
    "crates/xtask/src/cargo_layout.rs",
    "crates/xtask/src/core_clean_dispatch.rs",
];
const EPOCH_FILE_NAME: &str = ".cargo-core-epoch-v1.json";
const EPOCH_SCHEMA_VERSION: u32 = 1;
const MAX_EPOCH_BYTES: u64 = 64 * 1024;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    #[serde(default)]
    metadata: serde_json::Value,
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
    workspace_root: PathBuf,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoCorePolicy {
    #[serde(rename = "schema-version")]
    schema_version: u32,
    #[serde(rename = "retained-workspace-packages")]
    retained_workspace_packages: Vec<String>,
    #[serde(rename = "max-retained-bytes")]
    max_retained_bytes: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct CoreCleanupPlan {
    cleanup_packages: Vec<String>,
    retained_workspace_packages: Vec<String>,
    max_retained_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CargoCoreEpoch {
    schema_version: u32,
    cache_epoch_sha256: String,
    max_retained_bytes: u64,
    retained_workspace_packages: Vec<String>,
    retention_rejected: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum EpochState {
    Missing,
    Matching,
    Mismatched,
    Rejected,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let dry_run = match arguments.as_slice() {
        [] => false,
        [argument] if argument == "--dry-run" => true,
        _ => {
            return Err(
                "usage: core-clean-dispatch [--dry-run]; invoke through quality-dispatch or local-release-dispatch"
                    .to_owned(),
            )
        }
    };
    let current = std::env::current_dir()
        .map_err(|error| format!("resolve core-clean working directory: {error}"))?;
    let repository = cargo_layout::repository_root_from(&current)?;
    let layout = CargoStorageLayout::discover(&repository)?;
    let metadata = load_cargo_metadata(&repository)?;
    let plan = core_cleanup_plan(&metadata)?;
    let epoch = CargoCoreEpoch {
        schema_version: EPOCH_SCHEMA_VERSION,
        cache_epoch_sha256: cache_epoch_sha256(&repository, &metadata, &plan)?,
        max_retained_bytes: plan.max_retained_bytes,
        retained_workspace_packages: plan.retained_workspace_packages.clone(),
        retention_rejected: false,
    };
    let epoch_state = inspect_epoch(&layout.core, &epoch)?;

    if dry_run {
        eprintln!("core cache epoch state: {epoch_state:?}");
        clean_workspace_profiles(&repository, &layout, &plan.cleanup_packages, true)?;
        eprintln!(
            "core currently contains {} logical byte(s); the post-clean retained ceiling is {} byte(s)",
            directory_size(&layout.core)?,
            plan.max_retained_bytes
        );
        return Ok(());
    }

    if epoch_state == EpochState::Rejected {
        return Err(format!(
            "this Cargo core epoch previously exceeded its reviewed {}-byte retained ceiling; change the dependency/admission closure or explicitly revise the budget before rebuilding",
            plan.max_retained_bytes
        ));
    }
    if epoch_state == EpochState::Mismatched {
        reset_governed_profiles(&repository, &layout)?;
        eprintln!("reset the prior Cargo core cache epoch before rebuilding");
    }
    clean_workspace_profiles(&repository, &layout, &plan.cleanup_packages, false)?;
    write_epoch(&layout.core, &epoch)?;

    let retained_bytes = directory_size(&layout.core)?;
    if retained_bytes > plan.max_retained_bytes {
        reset_governed_profiles(&repository, &layout)?;
        let mut rejected_epoch = epoch;
        rejected_epoch.retention_rejected = true;
        write_epoch(&layout.core, &rejected_epoch)?;
        let bytes_after_reset = directory_size(&layout.core)?;
        return Err(format!(
            "post-clean Cargo core retained {retained_bytes} logical bytes, exceeding the reviewed {}-byte ceiling; the governed profiles were cleared to {bytes_after_reset} logical bytes and this epoch was rejected until its closure or budget is explicitly revised",
            plan.max_retained_bytes,
        ));
    }
    eprintln!(
        "cleaned {} non-admitted workspace package(s) from {} Cargo core profile(s); retained {} logical byte(s) within the {}-byte ceiling",
        plan.cleanup_packages.len(),
        GOVERNED_CORE_PROFILES.len(),
        retained_bytes,
        plan.max_retained_bytes
    );
    Ok(())
}

fn load_cargo_metadata(root: &Path) -> Result<CargoMetadata, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .current_dir(root)
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
        ])
        .output()
        .map_err(|error| format!("launch cargo metadata for core cleanup: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata for core cleanup failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse cargo metadata for core cleanup: {error}"))
}

fn core_cleanup_plan(metadata: &CargoMetadata) -> Result<CoreCleanupPlan, String> {
    let policy_value = metadata.metadata.get("cargo-core").ok_or_else(|| {
        "workspace.metadata.cargo-core is required for governed core cleanup".to_owned()
    })?;
    let policy: CargoCorePolicy = serde_json::from_value(policy_value.clone())
        .map_err(|error| format!("parse workspace.metadata.cargo-core: {error}"))?;
    if policy.schema_version != 2 {
        return Err(format!(
            "workspace.metadata.cargo-core has schema-version {}, expected 2",
            policy.schema_version
        ));
    }
    if policy.max_retained_bytes == 0 {
        return Err("workspace.metadata.cargo-core max-retained-bytes must be positive".to_owned());
    }

    let workspace_members = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut workspace_packages = BTreeSet::new();
    for package in metadata
        .packages
        .iter()
        .filter(|package| workspace_members.contains(package.id.as_str()))
    {
        if !workspace_packages.insert(package.name.clone()) {
            return Err(format!(
                "workspace package name {} is not unique enough for cargo-core admission",
                package.name
            ));
        }
    }

    let mut retained = BTreeSet::new();
    for package_name in policy.retained_workspace_packages {
        if !retained.insert(package_name.clone()) {
            return Err(format!(
                "workspace.metadata.cargo-core repeats retained workspace package {package_name}"
            ));
        }
        if !workspace_packages.contains(&package_name) {
            return Err(format!(
                "workspace.metadata.cargo-core retains unknown workspace package {package_name}"
            ));
        }
    }

    Ok(CoreCleanupPlan {
        cleanup_packages: workspace_packages.difference(&retained).cloned().collect(),
        retained_workspace_packages: retained.into_iter().collect(),
        max_retained_bytes: policy.max_retained_bytes,
    })
}

fn clean_workspace_profiles(
    repository: &Path,
    layout: &CargoStorageLayout,
    packages: &[String],
    dry_run: bool,
) -> Result<(), String> {
    if packages.is_empty() {
        eprintln!("core cleanup has no non-admitted workspace packages");
        return Ok(());
    }
    for profile in GOVERNED_CORE_PROFILES {
        let mut arguments = vec![
            "clean".to_owned(),
            "--locked".to_owned(),
            "--offline".to_owned(),
            "--profile".to_owned(),
            profile.to_owned(),
        ];
        if dry_run {
            arguments.push("--dry-run".to_owned());
        }
        for package in packages {
            arguments.push("--package".to_owned());
            arguments.push(package.clone());
        }
        run_cargo_clean(repository, layout, &arguments, "workspace package cleanup")?;
    }
    Ok(())
}

fn reset_governed_profiles(repository: &Path, layout: &CargoStorageLayout) -> Result<(), String> {
    for profile in GOVERNED_CORE_PROFILES {
        let arguments = ["clean", "--locked", "--offline", "--profile", profile];
        run_cargo_clean(repository, layout, arguments, "cache-epoch reset")?;
    }
    Ok(())
}

fn run_cargo_clean<I, S>(
    repository: &Path,
    layout: &CargoStorageLayout,
    arguments: I,
    operation: &str,
) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command.current_dir(repository).args(arguments);
    layout.configure_source_validation(&mut command);
    let status = command
        .status()
        .map_err(|error| format!("launch governed Cargo core {operation}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "governed Cargo core {operation} failed with {status}"
        ))
    }
}

fn cache_epoch_sha256(
    repository: &Path,
    metadata: &CargoMetadata,
    plan: &CoreCleanupPlan,
) -> Result<String, String> {
    let metadata_root = fs::canonicalize(&metadata.workspace_root)
        .map_err(|error| format!("canonicalize Cargo metadata workspace root: {error}"))?;
    if metadata_root != repository {
        return Err(format!(
            "Cargo metadata workspace root {} does not match repository {}",
            metadata_root.display(),
            repository.display()
        ));
    }

    let mut digest = Sha256::new();
    hash_value(&mut digest, b"schema", b"cargo-core-cache-epoch-v1");
    hash_value(&mut digest, b"os", std::env::consts::OS.as_bytes());
    hash_value(&mut digest, b"arch", std::env::consts::ARCH.as_bytes());
    for profile in GOVERNED_CORE_PROFILES {
        hash_value(&mut digest, b"profile", profile.as_bytes());
    }
    let tools = [
        (
            "cargo",
            std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")),
        ),
        (
            "rustc",
            std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc")),
        ),
    ];
    for (label, tool) in tools {
        let output = Command::new(&tool)
            .args(["--version", "--verbose"])
            .output()
            .map_err(|error| format!("capture {label} cache-epoch identity: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "capture {label} cache-epoch identity failed with {}",
                output.status
            ));
        }
        hash_value(&mut digest, label.as_bytes(), &output.stdout);
        hash_value(&mut digest, b"tool-stderr", &output.stderr);
    }

    for relative in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
        hash_file(repository, &repository.join(relative), &mut digest)?;
    }
    let mut manifests = metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .map(|package| package.manifest_path.clone())
        .collect::<Vec<_>>();
    manifests.sort();
    manifests.dedup();
    for manifest in manifests {
        hash_file(repository, &manifest, &mut digest)?;
    }
    for relative in CACHE_POLICY_SOURCE_PATHS {
        hash_file(repository, &repository.join(relative), &mut digest)?;
    }

    for retained in &plan.retained_workspace_packages {
        let package = metadata
            .packages
            .iter()
            .find(|package| {
                package.name == *retained && metadata.workspace_members.contains(&package.id)
            })
            .ok_or_else(|| format!("retained workspace package disappeared: {retained}"))?;
        let directory = package.manifest_path.parent().ok_or_else(|| {
            format!(
                "retained package manifest has no parent: {}",
                package.manifest_path.display()
            )
        })?;
        hash_directory(repository, directory, &mut digest)?;
    }

    let mut relevant_environment = std::env::vars_os()
        .filter_map(|(name, value)| {
            let normalized = name.to_string_lossy().to_ascii_uppercase();
            (normalized == "RUSTC"
                || normalized == "RUSTFLAGS"
                || normalized == "RUSTC_WRAPPER"
                || normalized == "RUSTC_WORKSPACE_WRAPPER"
                || normalized == "CARGO_ENCODED_RUSTFLAGS"
                || normalized == "CARGO_BUILD_RUSTC"
                || normalized == "CARGO_BUILD_RUSTFLAGS"
                || normalized == "CARGO_BUILD_RUSTC_WRAPPER"
                || normalized == "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"
                || normalized == "CARGO_BUILD_TARGET"
                || (normalized.starts_with("CARGO_TARGET_") && normalized.ends_with("_RUSTFLAGS"))
                || normalized.starts_with("CARGO_PROFILE_"))
            .then(|| (normalized, value.to_string_lossy().into_owned()))
        })
        .collect::<Vec<_>>();
    relevant_environment.sort();
    for (name, value) in relevant_environment {
        hash_value(&mut digest, name.as_bytes(), value.as_bytes());
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn hash_directory(root: &Path, directory: &Path, digest: &mut Sha256) -> Result<(), String> {
    let directory = fs::canonicalize(directory).map_err(|error| {
        format!(
            "canonicalize cache-epoch directory {}: {error}",
            directory.display()
        )
    })?;
    if !directory.starts_with(root) {
        return Err(format!(
            "cache-epoch directory escapes repository: {}",
            directory.display()
        ));
    }
    let mut files = Vec::new();
    collect_regular_files(&directory, &mut files)?;
    files.sort();
    for file in files {
        hash_file(root, &file, digest)?;
    }
    Ok(())
}

fn collect_regular_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| {
            format!(
                "read cache-epoch directory {}: {error}",
                directory.display()
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            format!(
                "enumerate cache-epoch directory {}: {error}",
                directory.display()
            )
        })?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect cache-epoch path {}: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_regular_files(&path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        } else {
            return Err(format!(
                "cache-epoch source closure contains a non-regular path: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn hash_file(root: &Path, path: &Path, digest: &mut Sha256) -> Result<(), String> {
    let path = fs::canonicalize(path)
        .map_err(|error| format!("canonicalize cache-epoch file {}: {error}", path.display()))?;
    if !path.starts_with(root) {
        return Err(format!(
            "cache-epoch file escapes repository: {}",
            path.display()
        ));
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("inspect cache-epoch file {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "cache-epoch input is not a regular file: {}",
            path.display()
        ));
    }
    let relative = path
        .strip_prefix(root)
        .map_err(|error| format!("relativize cache-epoch file {}: {error}", path.display()))?;
    hash_value(digest, b"path", relative.to_string_lossy().as_bytes());
    hash_value(digest, b"bytes", &metadata.len().to_le_bytes());
    let mut file = fs::File::open(&path)
        .map_err(|error| format!("open cache-epoch file {}: {error}", path.display()))?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read cache-epoch file {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(())
}

fn hash_value(digest: &mut Sha256, label: &[u8], value: &[u8]) {
    digest.update((label.len() as u64).to_le_bytes());
    digest.update(label);
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value);
}

fn inspect_epoch(core: &Path, expected: &CargoCoreEpoch) -> Result<EpochState, String> {
    let path = core.join(EPOCH_FILE_NAME);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(EpochState::Missing)
        }
        Err(error) => {
            return Err(format!(
                "inspect Cargo core epoch {}: {error}",
                path.display()
            ))
        }
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_EPOCH_BYTES {
        return Ok(EpochState::Mismatched);
    }
    let bytes = fs::read(&path)
        .map_err(|error| format!("read Cargo core epoch {}: {error}", path.display()))?;
    let stored = match serde_json::from_slice::<CargoCoreEpoch>(&bytes) {
        Ok(stored) => stored,
        Err(_) => return Ok(EpochState::Mismatched),
    };
    Ok(classify_epoch(&stored, expected))
}

fn classify_epoch(stored: &CargoCoreEpoch, expected: &CargoCoreEpoch) -> EpochState {
    if stored.schema_version != expected.schema_version
        || stored.cache_epoch_sha256 != expected.cache_epoch_sha256
        || stored.max_retained_bytes != expected.max_retained_bytes
        || stored.retained_workspace_packages != expected.retained_workspace_packages
    {
        EpochState::Mismatched
    } else if stored.retention_rejected {
        EpochState::Rejected
    } else {
        EpochState::Matching
    }
}

fn write_epoch(core: &Path, epoch: &CargoCoreEpoch) -> Result<(), String> {
    fs::create_dir_all(core)
        .map_err(|error| format!("create Cargo core directory {}: {error}", core.display()))?;
    let final_path = core.join(EPOCH_FILE_NAME);
    if let Ok(metadata) = fs::symlink_metadata(&final_path) {
        if !metadata.file_type().is_file() {
            return Err(format!(
                "Cargo core epoch destination is not a regular file: {}",
                final_path.display()
            ));
        }
    }
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_path = core.join(format!(
        ".cargo-core-epoch-v1.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(&temporary_path).map_err(|error| {
        format!(
            "create temporary Cargo core epoch {}: {error}",
            temporary_path.display()
        )
    })?;
    let mut bytes = serde_json::to_vec_pretty(epoch)
        .map_err(|error| format!("serialize Cargo core epoch: {error}"))?;
    bytes.push(b'\n');
    file.write_all(&bytes)
        .map_err(|error| format!("write temporary Cargo core epoch: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync temporary Cargo core epoch: {error}"))?;
    drop(file);
    if final_path.exists() {
        fs::remove_file(&final_path)
            .map_err(|error| format!("replace prior Cargo core epoch: {error}"))?;
    }
    fs::rename(&temporary_path, &final_path).map_err(|error| {
        let _ = fs::remove_file(&temporary_path);
        format!("publish Cargo core epoch {}: {error}", final_path.display())
    })?;
    Ok(())
}

fn directory_size(root: &Path) -> Result<u64, String> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(format!(
                "Cargo core path is not a real directory: {}",
                root.display()
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(format!(
                "inspect Cargo core path {}: {error}",
                root.display()
            ))
        }
    }
    directory_contents_size(root)
}

fn directory_contents_size(directory: &Path) -> Result<u64, String> {
    let mut total = 0_u64;
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("read Cargo core directory {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| {
            format!(
                "enumerate Cargo core directory {}: {error}",
                directory.display()
            )
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect Cargo core entry {}: {error}", path.display()))?;
        let bytes = if metadata.file_type().is_dir() {
            directory_contents_size(&path)?
        } else if metadata.file_type().is_file() {
            metadata.len()
        } else {
            return Err(format!(
                "Cargo core contains a non-regular entry: {}",
                path.display()
            ));
        };
        total = total
            .checked_add(bytes)
            .ok_or_else(|| "Cargo core logical size overflowed u64".to_owned())?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(retained: serde_json::Value, max_retained_bytes: u64) -> CargoMetadata {
        serde_json::from_value(serde_json::json!({
            "metadata": {
                "cargo-core": {
                    "schema-version": 2,
                    "retained-workspace-packages": retained,
                    "max-retained-bytes": max_retained_bytes
                }
            },
            "workspace_root": "/repo",
            "workspace_members": [
                "path+file:///repo/a#a@1.0.0",
                "path+file:///repo/b#b@2.0.0"
            ],
            "packages": [
                {
                    "id": "path+file:///repo/a#a@1.0.0",
                    "name": "a",
                    "manifest_path": "/repo/a/Cargo.toml"
                },
                {
                    "id": "path+file:///repo/b#b@2.0.0",
                    "name": "b",
                    "manifest_path": "/repo/b/Cargo.toml"
                },
                {
                    "id": "registry+https://example.invalid#dependency@3.0.0",
                    "name": "dependency",
                    "manifest_path": "/registry/dependency/Cargo.toml"
                }
            ]
        }))
        .expect("synthetic cargo metadata")
    }

    #[test]
    fn cargo_core_starts_dependency_only_and_admits_named_workspace_packages() {
        assert_eq!(
            core_cleanup_plan(&metadata(serde_json::json!([]), 1024)).unwrap(),
            CoreCleanupPlan {
                cleanup_packages: vec!["a".to_owned(), "b".to_owned()],
                retained_workspace_packages: Vec::new(),
                max_retained_bytes: 1024,
            }
        );
        assert_eq!(
            core_cleanup_plan(&metadata(serde_json::json!(["a"]), 1024)).unwrap(),
            CoreCleanupPlan {
                cleanup_packages: vec!["b".to_owned()],
                retained_workspace_packages: vec!["a".to_owned()],
                max_retained_bytes: 1024,
            }
        );
        assert!(
            core_cleanup_plan(&metadata(serde_json::json!(["missing"]), 1024))
                .unwrap_err()
                .contains("retains unknown workspace package missing")
        );
        assert!(core_cleanup_plan(&metadata(serde_json::json!([]), 0))
            .unwrap_err()
            .contains("max-retained-bytes must be positive"));
    }

    #[test]
    fn epoch_equality_binds_admission_and_budget() {
        let first = CargoCoreEpoch {
            schema_version: EPOCH_SCHEMA_VERSION,
            cache_epoch_sha256: "a".repeat(64),
            max_retained_bytes: 1024,
            retained_workspace_packages: vec!["stable".to_owned()],
            retention_rejected: false,
        };
        assert_eq!(first, first.clone());
        assert_ne!(
            first,
            CargoCoreEpoch {
                retained_workspace_packages: vec!["other-stable".to_owned()],
                ..first.clone()
            }
        );
        assert_ne!(
            first,
            CargoCoreEpoch {
                max_retained_bytes: 2048,
                ..first.clone()
            }
        );
        assert_ne!(
            first,
            CargoCoreEpoch {
                retention_rejected: true,
                ..first.clone()
            }
        );
        let mut rejected = first.clone();
        rejected.retention_rejected = true;
        assert_eq!(classify_epoch(&first, &first), EpochState::Matching);
        assert_eq!(classify_epoch(&rejected, &first), EpochState::Rejected);
        let mut changed_budget = first.clone();
        changed_budget.max_retained_bytes += 1;
        assert_eq!(
            classify_epoch(&rejected, &changed_budget),
            EpochState::Mismatched
        );
    }
}
