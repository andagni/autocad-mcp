mod cargo_layout;

use cargo_layout::CargoStorageLayout;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicU64, Ordering};

const MANIFEST_NAME: &str = "local-optimized-build.json";
const MANIFEST_SCHEMA_VERSION: u32 = 1;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BuildMode {
    Release,
    Preview,
}

impl BuildMode {
    fn name(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Preview => "preview",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct DispatchRequest {
    mode: BuildMode,
    timings: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalBuildManifest {
    schema_version: u32,
    artifact_kind: &'static str,
    claim_boundary: &'static str,
    release_authority: bool,
    distribution_authority: bool,
    signing_authority: bool,
    native_host_authority: bool,
    source_commit: String,
    source_tree_oid: String,
    mode: BuildMode,
    cargo_profile: &'static str,
    target_triple: String,
    cargo_version: String,
    rustc_version: String,
    command: Vec<String>,
    artifacts: Vec<LocalBuildArtifact>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalBuildArtifact {
    package: &'static str,
    relative_path: String,
    sha256: String,
    bytes: u64,
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
    let request = parse_arguments(&std::env::args_os().skip(1).collect::<Vec<_>>())?;
    let current = std::env::current_dir()
        .map_err(|error| format!("resolve local-release working directory: {error}"))?;
    let repository = cargo_layout::repository_root_from(&current)?;
    let layout = CargoStorageLayout::discover(&repository)?;
    let _lock = layout.acquire_governed_lock()?;
    let (source_commit, source_tree_oid) = clean_source_identity(&repository)?;
    let cargo = selected_program("CARGO", "cargo");
    let rustc = selected_program("RUSTC", "rustc");
    let target_triple = rustc_host_triple(&rustc)?;
    let cargo_version = tool_version(&cargo, "cargo")?;
    let rustc_version = tool_version(&rustc, "rustc")?;

    run_core_cleanup(&layout, &repository, "pre-build")?;
    let target_directory = layout.release_target(request.mode.name());
    let manifest_path = target_directory.join(MANIFEST_NAME);
    remove_prior_manifest(&manifest_path)?;
    remove_prior_artifacts(&target_directory)?;

    let arguments = build_arguments(request.mode, request.timings);
    let mut command = Command::new(cargo);
    command.current_dir(&repository).args(&arguments);
    layout.configure_release(&mut command, request.mode.name());
    let status = match command.status() {
        Ok(status) => status,
        Err(error) => {
            let cleanup = run_core_cleanup(&layout, &repository, "failed-build-launch");
            return Err(match cleanup {
                Ok(()) => format!("launch local optimized build: {error}"),
                Err(cleanup_error) => {
                    format!("launch local optimized build: {error}; {cleanup_error}")
                }
            });
        }
    };
    if !status.success() {
        let cleanup = run_core_cleanup(&layout, &repository, "failed-build");
        if let Err(cleanup_error) = cleanup {
            eprintln!("ERROR: {cleanup_error}");
        }
        return Err(format!("local optimized build failed with {status}"));
    }

    run_core_cleanup(&layout, &repository, "post-build")?;
    let (source_commit_after, source_tree_after) = clean_source_identity(&repository)?;
    if source_commit_after != source_commit || source_tree_after != source_tree_oid {
        return Err("source identity changed during the local optimized build".to_owned());
    }
    let artifacts = inspect_artifacts(&layout.shared_root, &target_directory)?;
    let manifest = LocalBuildManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        artifact_kind: "autocad-mcp-local-optimized-build",
        claim_boundary: "local_development_only",
        release_authority: false,
        distribution_authority: false,
        signing_authority: false,
        native_host_authority: false,
        source_commit,
        source_tree_oid,
        mode: request.mode,
        cargo_profile: "release",
        target_triple,
        cargo_version,
        rustc_version,
        command: arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect(),
        artifacts,
    };
    write_manifest(&manifest_path, &manifest)?;
    let final_source_identity = clean_source_identity(&repository);
    if !matches!(
        final_source_identity,
        Ok((ref commit, ref tree))
            if commit == &manifest.source_commit && tree == &manifest.source_tree_oid
    ) {
        remove_prior_manifest(&manifest_path)?;
        return Err("source identity changed while publishing the local build manifest".to_owned());
    }
    eprintln!(
        "local optimized {} build completed; manifest: {}",
        request.mode.name(),
        manifest_path.display()
    );
    Ok(())
}

fn parse_arguments(arguments: &[OsString]) -> Result<DispatchRequest, String> {
    let values = arguments
        .iter()
        .map(|argument| argument.to_str())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "local-release-dispatch arguments must be UTF-8".to_owned())?;
    match values.as_slice() {
        ["release"] => Ok(DispatchRequest {
            mode: BuildMode::Release,
            timings: false,
        }),
        ["release", "--timings"] => Ok(DispatchRequest {
            mode: BuildMode::Release,
            timings: true,
        }),
        ["preview"] => Ok(DispatchRequest {
            mode: BuildMode::Preview,
            timings: false,
        }),
        ["preview", "--timings"] => Ok(DispatchRequest {
            mode: BuildMode::Preview,
            timings: true,
        }),
        _ => Err(
            "usage: cargo run --locked -p xtask --no-default-features --features local-release --bin local-release-dispatch -- <release|preview> [--timings]"
                .to_owned(),
        ),
    }
}

fn build_arguments(mode: BuildMode, timings: bool) -> Vec<OsString> {
    let mut arguments = [
        "build",
        "--locked",
        "--release",
        "-p",
        "autocad-mcp",
        "--bin",
        "autocad-mcp",
        "--no-default-features",
        "-p",
        "autolisp-lsp",
        "--bin",
        "autolisp-lsp",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    if mode == BuildMode::Preview {
        arguments.extend(["--features", "autocad-mcp/preview"].map(OsString::from));
    }
    if timings {
        arguments.push(OsString::from("--timings"));
    }
    arguments
}

fn run_core_cleanup(
    layout: &CargoStorageLayout,
    repository: &Path,
    phase: &str,
) -> Result<(), String> {
    let status = layout
        .core_cleanup_command(repository, false)
        .status()
        .map_err(|error| format!("launch {phase} Cargo core cleanup: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{phase} Cargo core cleanup failed with {status}"))
    }
}

fn clean_source_identity(repository: &Path) -> Result<(String, String), String> {
    let status = git_output(
        repository,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err(format!(
            "local optimized builds require a clean checkout; commit or remove these paths:\n{status}"
        ));
    }
    Ok((
        git_output(repository, &["rev-parse", "--verify", "HEAD"])?,
        git_output(repository, &["rev-parse", "--verify", "HEAD^{tree}"])?,
    ))
}

fn git_output(repository: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(repository)
        .args(arguments)
        .output()
        .map_err(|error| format!("launch git {}: {error}", arguments.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed with {}: {}",
            arguments.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| {
            format!(
                "git {} returned non-UTF-8 output: {error}",
                arguments.join(" ")
            )
        })
}

fn inspect_artifacts(
    storage_root: &Path,
    target_directory: &Path,
) -> Result<Vec<LocalBuildArtifact>, String> {
    local_artifact_paths(target_directory)
        .into_iter()
        .map(|(package, path)| {
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                format!(
                    "inspect local optimized artifact {}: {error}",
                    path.display()
                )
            })?;
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "local optimized artifact is not a regular file: {}",
                    path.display()
                ));
            }
            Ok(LocalBuildArtifact {
                package,
                relative_path: path
                    .strip_prefix(storage_root)
                    .map_err(|error| {
                        format!(
                            "relativize local optimized artifact {}: {error}",
                            path.display()
                        )
                    })?
                    .to_string_lossy()
                    .replace('\\', "/"),
                sha256: sha256_file(&path)?,
                bytes: metadata.len(),
            })
        })
        .collect()
}

fn local_artifact_paths(target_directory: &Path) -> Vec<(&'static str, PathBuf)> {
    let executable_suffix = std::env::consts::EXE_SUFFIX;
    ["autocad-mcp", "autolisp-lsp"]
        .into_iter()
        .map(|package| {
            (
                package,
                target_directory
                    .join("release")
                    .join(format!("{package}{executable_suffix}")),
            )
        })
        .collect()
}

fn remove_prior_artifacts(target_directory: &Path) -> Result<(), String> {
    for (_, path) in local_artifact_paths(target_directory) {
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                fs::remove_file(&path).map_err(|error| {
                    format!("remove prior local artifact {}: {error}", path.display())
                })?
            }
            Ok(_) => {
                return Err(format!(
                    "prior local artifact path is not a regular file: {}",
                    path.display()
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "inspect prior local artifact {}: {error}",
                    path.display()
                ))
            }
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("open local optimized artifact {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            format!("read local optimized artifact {}: {error}", path.display())
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn selected_program(environment: &str, fallback: &str) -> OsString {
    std::env::var_os(environment).unwrap_or_else(|| OsString::from(fallback))
}

fn rustc_host_triple(rustc: &OsStr) -> Result<String, String> {
    let output = Command::new(rustc)
        .args(["--version", "--verbose"])
        .output()
        .map_err(|error| format!("capture rustc host triple: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "capture rustc host triple failed with {}",
            output.status
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("rustc verbose version is not UTF-8: {error}"))?;
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::to_owned))
        .ok_or_else(|| "rustc verbose version did not report a host triple".to_owned())
}

fn tool_version(tool: &OsStr, label: &str) -> Result<String, String> {
    let output = Command::new(tool)
        .arg("--version")
        .output()
        .map_err(|error| format!("capture {label} version: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "capture {label} version failed with {}",
            output.status
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("{label} version is not UTF-8: {error}"))
}

fn remove_prior_manifest(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => fs::remove_file(path).map_err(|error| {
            format!(
                "remove prior local build manifest {}: {error}",
                path.display()
            )
        }),
        Ok(_) => Err(format!(
            "local build manifest destination is not a regular file: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "inspect local build manifest {}: {error}",
            path.display()
        )),
    }
}

fn write_manifest(path: &Path, manifest: &LocalBuildManifest) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("local build manifest has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "create local build manifest directory {}: {error}",
            parent.display()
        )
    })?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{MANIFEST_NAME}.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(&temporary).map_err(|error| {
        format!(
            "create temporary local build manifest {}: {error}",
            temporary.display()
        )
    })?;
    let mut bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|error| format!("serialize local build manifest: {error}"))?;
    bytes.push(b'\n');
    file.write_all(&bytes)
        .map_err(|error| format!("write temporary local build manifest: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync temporary local build manifest: {error}"))?;
    drop(file);
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        format!("publish local build manifest {}: {error}", path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_surface_is_closed_to_release_and_preview() {
        assert_eq!(
            parse_arguments(&[OsString::from("release")]).unwrap(),
            DispatchRequest {
                mode: BuildMode::Release,
                timings: false,
            }
        );
        assert_eq!(
            parse_arguments(&[OsString::from("preview"), OsString::from("--timings")]).unwrap(),
            DispatchRequest {
                mode: BuildMode::Preview,
                timings: true,
            }
        );
        assert!(parse_arguments(&[OsString::from("experimental")]).is_err());
        assert!(
            parse_arguments(&[OsString::from("release"), OsString::from("--features")]).is_err()
        );
    }

    #[test]
    fn preview_build_uses_only_the_tracked_preview_feature() {
        let release = build_arguments(BuildMode::Release, false);
        let preview = build_arguments(BuildMode::Preview, true);
        assert!(!release.iter().any(|argument| argument == "--features"));
        assert!(preview
            .windows(2)
            .any(|pair| { pair[0] == "--features" && pair[1] == "autocad-mcp/preview" }));
        assert_eq!(preview.last(), Some(&OsString::from("--timings")));
    }

    #[test]
    fn local_artifacts_are_exactly_the_two_release_profile_binaries() {
        let target = Path::new("local-target");
        let artifacts = local_artifact_paths(target);
        assert_eq!(artifacts.len(), 2);
        assert_eq!(artifacts[0].0, "autocad-mcp");
        assert_eq!(artifacts[1].0, "autolisp-lsp");
        for (package, path) in artifacts {
            assert_eq!(
                path,
                target
                    .join("release")
                    .join(format!("{package}{}", std::env::consts::EXE_SUFFIX))
            );
        }
    }
}
