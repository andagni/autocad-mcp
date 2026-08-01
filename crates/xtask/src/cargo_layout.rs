#![allow(dead_code)] // Each thin dispatcher uses a different subset of this shared module.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub(crate) const SOURCE_VALIDATION_PROFILE: &str = "source-validation";
#[allow(dead_code)]
pub(crate) const SOURCE_VALIDATION_LAYOUT_BINDING: &str =
    "cargo-layout-v1:target=scratch;build=core;profile=source-validation";
pub(crate) const DISPOSABLE_SOURCE_VALIDATION_LAYOUT_BINDING: &str =
    "cargo-layout-v1:target=scratch;build=scratch;profile=source-validation";
const DEFAULT_SCCACHE_CACHE_SIZE: &str = "512M";
const GOVERNED_OPERATION_LOCK: &str = ".governed-operation.lock";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CargoStorageLayout {
    pub(crate) shared_root: PathBuf,
    pub(crate) scratch: PathBuf,
    pub(crate) release: PathBuf,
    pub(crate) core: PathBuf,
}

pub(crate) struct CargoStorageLock {
    path: PathBuf,
}

impl Drop for CargoStorageLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl CargoStorageLayout {
    pub(crate) fn discover(repository: &Path) -> Result<Self, String> {
        let repository = fs::canonicalize(repository).map_err(|error| {
            format!(
                "canonicalize Cargo-layout repository {}: {error}",
                repository.display()
            )
        })?;
        let common_directory = git_path_output(
            &repository,
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
            "Git common directory",
        )?;
        let common_directory = fs::canonicalize(&common_directory).map_err(|error| {
            format!(
                "canonicalize Git common directory {}: {error}",
                common_directory.display()
            )
        })?;
        let shared_root = common_directory.parent().ok_or_else(|| {
            format!(
                "Git common directory has no parent for shared Cargo storage: {}",
                common_directory.display()
            )
        })?;
        let shared_root = shared_root.to_path_buf();
        let cargo_root = shared_root.join(".cargo-target");
        Ok(Self {
            shared_root,
            scratch: cargo_root.join("scratch"),
            release: cargo_root.join("release"),
            core: cargo_root.join("core"),
        })
    }

    pub(crate) fn acquire_governed_lock(&self) -> Result<CargoStorageLock, String> {
        match fs::symlink_metadata(&self.core) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(format!(
                    "Cargo core path must be a real directory: {}",
                    self.core.display()
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.core).map_err(|error| {
                    format!(
                        "create Cargo core directory {}: {error}",
                        self.core.display()
                    )
                })?;
            }
            Err(error) => {
                return Err(format!(
                    "inspect Cargo core directory {}: {error}",
                    self.core.display()
                ))
            }
        }
        let path = self.core.join(GOVERNED_OPERATION_LOCK);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "another governed Cargo operation owns {}; if no operation is active, remove this stale lock explicitly",
                    path.display()
                )
            } else {
                format!("create governed Cargo lock {}: {error}", path.display())
            }
        })?;
        writeln!(file, "pid={}", std::process::id())
            .map_err(|error| format!("write governed Cargo lock: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync governed Cargo lock: {error}"))?;
        Ok(CargoStorageLock { path })
    }

    pub(crate) fn configure_source_validation(&self, command: &mut Command) {
        self.configure_scratch(command);
        command.env("CARGO_BUILD_BUILD_DIR", &self.core);
    }

    pub(crate) fn configure_scratch(&self, command: &mut Command) {
        command
            .env("CARGO_TARGET_DIR", &self.scratch)
            .env_remove("CARGO_BUILD_TARGET_DIR")
            .env_remove("CARGO_BUILD_BUILD_DIR")
            .env_remove("CARGO_INCREMENTAL")
            .env("CARGO_BUILD_INCREMENTAL", "true");
        self.configure_sccache(command);
    }

    pub(crate) fn configure_release(&self, command: &mut Command, mode: &str) {
        command
            .env("CARGO_TARGET_DIR", self.release_target(mode))
            .env_remove("CARGO_BUILD_TARGET_DIR")
            .env("CARGO_BUILD_BUILD_DIR", &self.core)
            .env_remove("CARGO_INCREMENTAL")
            .env("CARGO_BUILD_INCREMENTAL", "false");
        self.configure_sccache(command);
    }

    pub(crate) fn release_target(&self, mode: &str) -> PathBuf {
        if mode == "release" {
            self.release.clone()
        } else {
            self.release.join(mode)
        }
    }

    pub(crate) fn core_cleanup_command(&self, repository: &Path, dry_run: bool) -> Command {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
        let mut command = Command::new(cargo);
        command.current_dir(repository).args([
            "run",
            "--locked",
            "--no-default-features",
            "--features",
            "core-clean",
            "-p",
            "xtask",
            "--bin",
            "core-clean-dispatch",
            "--",
        ]);
        if dry_run {
            command.arg("--dry-run");
        }
        self.configure_scratch(&mut command);
        command
    }

    fn configure_sccache(&self, command: &mut Command) {
        if selected_rustc_wrapper()
            .as_deref()
            .is_some_and(is_sccache_wrapper)
        {
            if std::env::var_os("SCCACHE_CACHE_SIZE").is_none() {
                command.env("SCCACHE_CACHE_SIZE", DEFAULT_SCCACHE_CACHE_SIZE);
            }
            if std::env::var_os("SCCACHE_BASEDIRS").is_none() {
                command.env("SCCACHE_BASEDIRS", &self.shared_root);
            }
        }
    }
}

#[allow(dead_code)]
pub(crate) fn repository_root_from(start: &Path) -> Result<PathBuf, String> {
    let start = fs::canonicalize(start).map_err(|error| {
        format!(
            "canonicalize repository-root discovery start {}: {error}",
            start.display()
        )
    })?;
    let root = git_path_output(&start, &["rev-parse", "--show-toplevel"], "repository root")?;
    let root = fs::canonicalize(&root).map_err(|error| {
        format!(
            "canonicalize discovered repository root {}: {error}",
            root.display()
        )
    })?;
    if !start.starts_with(&root) {
        return Err(format!(
            "discovered repository root {} does not contain runtime directory {}",
            root.display(),
            start.display()
        ));
    }
    Ok(root)
}

#[allow(dead_code)]
pub(crate) fn is_cargo_program(program: &OsStr) -> bool {
    Path::new(program)
        .file_stem()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.eq_ignore_ascii_case("cargo"))
}

fn selected_rustc_wrapper() -> Option<OsString> {
    [
        "RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    ]
    .into_iter()
    .find_map(std::env::var_os)
}

fn is_sccache_wrapper(wrapper: &OsStr) -> bool {
    Path::new(wrapper)
        .file_stem()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.eq_ignore_ascii_case("sccache"))
}

fn git_path_output(root: &Path, arguments: &[&str], label: &str) -> Result<PathBuf, String> {
    let output = isolated_git_command(root)
        .args(arguments)
        .output()
        .map_err(|error| format!("discover {label}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "discover {label} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("discovered {label} is not UTF-8: {error}"))?;
    let path = stdout
        .strip_suffix("\r\n")
        .or_else(|| stdout.strip_suffix('\n'))
        .unwrap_or(&stdout);
    if path.is_empty() || path.contains(['\r', '\n']) {
        return Err(format!("discovered {label} is invalid"));
    }
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(format!(
            "discovered {label} is not absolute: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn isolated_git_command(root: &Path) -> Command {
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
    command.env_clear().current_dir(root).stdin(Stdio::null());
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
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_and_sccache_program_detection_is_path_tolerant() {
        assert!(is_cargo_program(OsStr::new("cargo")));
        assert!(is_cargo_program(OsStr::new("/tools/cargo")));
        assert!(is_sccache_wrapper(OsStr::new("sccache")));
        assert!(is_sccache_wrapper(OsStr::new("/tools/sccache")));
        assert!(!is_cargo_program(OsStr::new("git")));
    }
}
