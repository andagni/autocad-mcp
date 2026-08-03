use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use autocad_mcp::certification::{
    embedded_certification_profile_definitions, xref_embedded_artifact_sha256,
    CertificationProfileDefinition, XrefCertificationBuildIdentity, XrefEmbeddedArtifactSha256,
    XREF_MUTATION_OPERATIONS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::pe_imports::{audit_x86_64_pe_import_bytes, PeImportAudit, PE_IMPORT_POLICY_ID};

const WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";
const RELEASE_PROFILE: &str = "release";
const RELEASE_OPTIMIZATION: &str = "3";
const REQUIRED_RUSTC_PREFIX: &str = "rustc 1.97.0 ";
const REQUIRED_RUSTC_HOST: &str = "host: x86_64-pc-windows-msvc";
const REQUIRED_CRT_LINKAGE: &str = "static";
const XREF_CERTIFICATION_INFO_SCHEMA_VERSION: u32 = 4;
const STATIC_CRT_ENCODED_RUSTFLAGS: &str = "-C\x1ftarget-feature=+crt-static";
const DISABLED_INCREMENTAL_COMPILATION: &str = "0";
const SCCACHE_RUSTC_WRAPPER: &str = "sccache";
const SOURCE_COMMIT_ENV: &str = "AUTOCAD_MCP_SOURCE_COMMIT";
const CERTIFIED_ARG_SHA256_ENV: &str = "AUTOCAD_MCP_XREF_CERTIFIED_ARG_SHA256";
const CERTIFIED_ARG_POLICY_ID_ENV: &str = "AUTOCAD_MCP_XREF_CERTIFIED_ARG_POLICY_ID";
const CERTIFIED_ARG_POLICY_SHA256_ENV: &str = "AUTOCAD_MCP_XREF_CERTIFIED_ARG_POLICY_SHA256";
const CERTIFIED_ARG_REPOSITORY_PATH: &str =
    "tests/fixtures/windows_certification/public-development-profile.arg";
const CERTIFIED_ARG_POLICY_REPOSITORY_PATH: &str =
    "tests/fixtures/windows_certification/public-development-arg-policy.json";

#[derive(Debug, Eq, PartialEq)]
struct BuildCommand {
    target_dir: PathBuf,
    arguments: Vec<OsString>,
    failpoints_enabled: bool,
    preview_enabled: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct HeadBuildInputs {
    source_commit: String,
    source_tree_sha256: String,
    cargo_lock_sha256: String,
    shared_operation_source_sha256: String,
}

#[derive(Debug, Eq, PartialEq)]
struct SharedBuildIdentity<'a> {
    source_commit: &'a str,
    source_tree_sha256: &'a str,
    cargo_lock_sha256: &'a str,
    certified_arg_sha256: &'a str,
    certified_arg_policy_id: &'a str,
    certified_arg_policy_sha256: &'a str,
    compiler: &'a str,
    target: &'a str,
    profile: &'a str,
    optimization: &'a str,
    shared_operation_source_sha256: &'a str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct CertifiedArgBuildIdentity {
    sha256: String,
    policy_id: String,
    policy_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct GitTreeFile {
    path: String,
    object_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CertificationInfo {
    schema_version: u32,
    experimental_support: bool,
    certified_arg_sha256: Option<String>,
    certified_arg_policy_id: Option<String>,
    certified_arg_policy_sha256: Option<String>,
    activation_catalogue_sha256: String,
    certification_failpoints_enabled: bool,
    crt_linkage: String,
    artifact_sha256: XrefEmbeddedArtifactSha256,
    title_block_profile_registry_sha256: String,
    title_block_profiles: Vec<CertificationProfileDefinition>,
    build_identity: XrefCertificationBuildIdentity,
    xref_mutation_tools: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsBuildPreflightSummary {
    evidence_class: &'static str,
    authority: &'static str,
    source_commit: String,
    source_tree_sha256: String,
    cargo_lock_sha256: String,
    target: &'static str,
    compiler: String,
    profile: &'static str,
    cargo_incremental: bool,
    rustc_wrapper: Option<&'static str>,
    release_build_command: String,
    instrumented_build_command: String,
    preview_build_command: String,
    certified_arg_sha256: String,
    certified_arg_policy_id: String,
    certified_arg_policy_sha256: String,
    release_binary_path: String,
    release_binary_sha256: String,
    release_build_id: String,
    lsp_binary_path: String,
    lsp_binary_sha256: String,
    crt_linkage: String,
    pe_import_policy_id: &'static str,
    pe_load_time_imports: Vec<String>,
    pe_delay_load_imports: Vec<String>,
    lsp_pe_load_time_imports: Vec<String>,
    lsp_pe_delay_load_imports: Vec<String>,
    instrumented_binary_path: String,
    instrumented_binary_sha256: String,
    instrumented_build_id: String,
    preview_binary_path: String,
    preview_binary_sha256: String,
    preview_build_id: String,
}

pub(crate) fn run_manifest_preflight(
    tier2_manifest: &Path,
    xref_manifest: &Path,
) -> Result<String, String> {
    let tier2_bytes = read_regular_file_once(tier2_manifest, "Tier 2 manifest")?;
    let xref_bytes = read_regular_file_once(xref_manifest, "strict XREF manifest")?;
    let summary = autocad_mcp::certification::validate_windows_certification_manifest_preflight(
        &tier2_bytes,
        &xref_bytes,
    )
    .map_err(|error| format!("certification manifest preflight failed: {error:#}"))?;
    serde_json::to_string(&summary)
        .map_err(|error| format!("serialize certification manifest preflight: {error}"))
}

pub(crate) fn run_windows_build_preflight(
    root: &Path,
    arg_path: &Path,
    arg_policy_path: &Path,
    output_dir: &Path,
    use_sccache: bool,
) -> Result<String, String> {
    if !cfg!(windows) {
        return Err(
            "windows-certification-build-preflight requires a native Windows host".to_owned(),
        );
    }

    validate_exact_repository_input_path(
        arg_path,
        CERTIFIED_ARG_REPOSITORY_PATH,
        "public development ARG",
    )?;
    validate_exact_repository_input_path(
        arg_policy_path,
        CERTIFIED_ARG_POLICY_REPOSITORY_PATH,
        "public development ARG policy",
    )?;
    let output_dir = validate_output_path(root, output_dir)?;
    let head_before = git_output(root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    ensure_clean_checkout(root, "Windows build preflight")?;
    ensure_plain_index(root)?;
    ensure_no_cargo_configuration(root)?;
    let arg_bytes = read_exact_head_input(
        root,
        &head_before,
        CERTIFIED_ARG_REPOSITORY_PATH,
        "public development ARG",
    )?;
    let policy_bytes = read_exact_head_input(
        root,
        &head_before,
        CERTIFIED_ARG_POLICY_REPOSITORY_PATH,
        "public development ARG policy",
    )?;
    let rust_toolchain_bytes = read_exact_head_input(
        root,
        &head_before,
        "rust-toolchain.toml",
        "Rust toolchain manifest",
    )?;
    let rust_toolchain = crate::source_bundle::rust_toolchain_channel(&rust_toolchain_bytes)?;
    let arg_inspection =
        autocad_mcp::certified_arg::validate_distribution_safe_arg(&arg_bytes, &policy_bytes)
            .map_err(|error| format!("public development ARG policy failed: {error:#}"))?;
    if arg_inspection.purpose
        != autocad_mcp::certified_arg::CertifiedArgPolicyPurpose::DevelopmentFixture
    {
        return Err("public development ARG policy purpose must be development_fixture".to_owned());
    }
    if arg_inspection.policy_id != autocad_mcp::certified_arg::PUBLIC_DEVELOPMENT_ARG_POLICY_ID {
        return Err(format!(
            "public development ARG policy_id must be {}",
            autocad_mcp::certified_arg::PUBLIC_DEVELOPMENT_ARG_POLICY_ID
        ));
    }
    let arg_identity = CertifiedArgBuildIdentity {
        sha256: arg_inspection.raw_arg_sha256,
        policy_id: arg_inspection.policy_id,
        policy_sha256: arg_inspection.policy_sha256,
    };
    let head_inputs = head_build_inputs(root, &head_before)?;
    fs::create_dir_all(&output_dir).map_err(|error| {
        format!(
            "create fresh preflight output directory {}: {error}",
            output_dir.display()
        )
    })?;

    let commands = build_commands(&output_dir);
    for command in &commands {
        run_build_command(
            root,
            command,
            &rust_toolchain,
            &head_inputs.source_commit,
            &arg_identity,
            use_sccache,
        )?;
    }

    let release_source = built_executable(&commands[0], "autocad-mcp.exe");
    let lsp_source = built_executable(&commands[0], "autolisp-lsp.exe");
    let instrumented_source = built_executable(&commands[1], "autocad-mcp.exe");
    let preview_source = built_executable(&commands[2], "autocad-mcp.exe");
    let release_binary = output_dir
        .join("artifacts")
        .join("release")
        .join("autocad-mcp.exe");
    let lsp_binary = output_dir
        .join("artifacts")
        .join("release")
        .join("autolisp-lsp.exe");
    let instrumented_binary = output_dir
        .join("artifacts")
        .join("xref-certification-failpoints")
        .join("autocad-mcp.exe");
    let preview_binary = output_dir
        .join("artifacts")
        .join("preview")
        .join("autocad-mcp.exe");
    stage_binary(&release_source, &release_binary)?;
    stage_binary(&lsp_source, &lsp_binary)?;
    stage_binary(&instrumented_source, &instrumented_binary)?;
    stage_binary(&preview_source, &preview_binary)?;

    let release_bytes = read_regular_file_once(&release_binary, "staged release executable")?;
    let lsp_bytes = read_regular_file_once(&lsp_binary, "staged AutoLISP LSP executable")?;
    let instrumented_bytes =
        read_regular_file_once(&instrumented_binary, "staged instrumented executable")?;
    let preview_bytes = read_regular_file_once(&preview_binary, "staged Preview executable")?;
    let release_imports = audit_x86_64_pe_import_bytes(&release_bytes)
        .map_err(|error| format!("release PE import audit failed: {error}"))?;
    let lsp_imports = audit_x86_64_pe_import_bytes(&lsp_bytes)
        .map_err(|error| format!("AutoLISP LSP PE import audit failed: {error}"))?;
    let instrumented_imports = audit_x86_64_pe_import_bytes(&instrumented_bytes)
        .map_err(|error| format!("instrumented PE import audit failed: {error}"))?;
    let preview_imports = audit_x86_64_pe_import_bytes(&preview_bytes)
        .map_err(|error| format!("Preview PE import audit failed: {error}"))?;
    validate_pe_import_pair(
        "release",
        &release_imports,
        "instrumented",
        &instrumented_imports,
    )?;
    validate_pe_import_pair("release", &release_imports, "Preview", &preview_imports)?;
    let release_sha256 = sha256_bytes(&release_bytes);
    let lsp_sha256 = sha256_bytes(&lsp_bytes);
    let instrumented_sha256 = sha256_bytes(&instrumented_bytes);
    let preview_sha256 = sha256_bytes(&preview_bytes);
    if [
        release_sha256.as_str(),
        instrumented_sha256.as_str(),
        preview_sha256.as_str(),
    ]
    .contains(&lsp_sha256.as_str())
    {
        return Err(
            "staged AutoLISP LSP executable must be byte-distinct from every MCP server build"
                .to_owned(),
        );
    }
    let release_info = read_certification_info(&release_binary)?;
    let instrumented_info = read_certification_info(&instrumented_binary)?;
    let preview_info = read_certification_info(&preview_binary)?;
    require_file_sha256(&release_binary, &release_sha256)?;
    require_file_sha256(&lsp_binary, &lsp_sha256)?;
    require_file_sha256(&instrumented_binary, &instrumented_sha256)?;
    require_file_sha256(&preview_binary, &preview_sha256)?;
    validate_build_pair(
        &release_info,
        &instrumented_info,
        &head_inputs,
        &arg_identity,
        &release_sha256,
        &instrumented_sha256,
    )?;
    validate_preview_build(
        &release_info,
        &instrumented_info,
        &preview_info,
        &head_inputs,
        &arg_identity,
        [
            release_sha256.as_str(),
            instrumented_sha256.as_str(),
            preview_sha256.as_str(),
        ],
    )?;

    let head_after = git_output(root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    if head_after != head_before {
        return Err(format!(
            "HEAD changed during Windows build preflight ({head_before} -> {head_after})"
        ));
    }
    ensure_clean_checkout(root, "Windows build preflight")?;
    ensure_plain_index(root)?;
    ensure_no_cargo_configuration(root)?;
    let head_inputs_after = head_build_inputs(root, &head_after)?;
    if head_inputs_after != head_inputs {
        return Err("HEAD build inputs changed during Windows build preflight".to_owned());
    }

    let summary = WindowsBuildPreflightSummary {
        evidence_class: "development_windows_build_preflight",
        authority: "development_only_not_certification_evidence",
        source_commit: head_inputs.source_commit,
        source_tree_sha256: head_inputs.source_tree_sha256,
        cargo_lock_sha256: head_inputs.cargo_lock_sha256,
        target: WINDOWS_TARGET,
        compiler: release_info.build_identity.compiler,
        profile: RELEASE_PROFILE,
        cargo_incremental: false,
        rustc_wrapper: use_sccache.then_some(SCCACHE_RUSTC_WRAPPER),
        release_build_command: format!("cargo {}", display_arguments(&commands[0].arguments)),
        instrumented_build_command: format!("cargo {}", display_arguments(&commands[1].arguments)),
        preview_build_command: format!("cargo {}", display_arguments(&commands[2].arguments)),
        certified_arg_sha256: arg_identity.sha256,
        certified_arg_policy_id: arg_identity.policy_id,
        certified_arg_policy_sha256: arg_identity.policy_sha256,
        release_binary_path: portable_repository_path(root, &release_binary)?,
        release_binary_sha256: release_sha256,
        release_build_id: release_info.build_identity.build_id,
        lsp_binary_path: portable_repository_path(root, &lsp_binary)?,
        lsp_binary_sha256: lsp_sha256,
        crt_linkage: release_info.crt_linkage,
        pe_import_policy_id: PE_IMPORT_POLICY_ID,
        pe_load_time_imports: release_imports.load_time_imports,
        pe_delay_load_imports: release_imports.delay_load_imports,
        lsp_pe_load_time_imports: lsp_imports.load_time_imports,
        lsp_pe_delay_load_imports: lsp_imports.delay_load_imports,
        instrumented_binary_path: portable_repository_path(root, &instrumented_binary)?,
        instrumented_binary_sha256: instrumented_sha256,
        instrumented_build_id: instrumented_info.build_identity.build_id,
        preview_binary_path: portable_repository_path(root, &preview_binary)?,
        preview_binary_sha256: preview_sha256,
        preview_build_id: preview_info.build_identity.build_id,
    };
    serde_json::to_string(&summary)
        .map_err(|error| format!("serialize Windows build preflight summary: {error}"))
}

fn read_regular_file_once(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if !before.file_type().is_file() {
        return Err(format!(
            "{label} must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("read {label} {}: {error}", path.display()))?;
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("reinspect {label} {}: {error}", path.display()))?;
    let byte_len = u64::try_from(bytes.len())
        .map_err(|_| format!("{label} is too large to inspect: {}", path.display()))?;
    if !after.file_type().is_file() || before.len() != byte_len || after.len() != byte_len {
        return Err(format!(
            "{label} changed file type or size while it was read: {}",
            path.display()
        ));
    }
    Ok(bytes)
}

fn validate_exact_repository_input_path(
    supplied: &Path,
    expected: &str,
    label: &str,
) -> Result<(), String> {
    let supplied_components = supplied.components().collect::<Vec<_>>();
    let expected_components = Path::new(expected).components().collect::<Vec<_>>();
    if supplied.is_absolute()
        || supplied_components != expected_components
        || supplied_components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "{label} must be the exact normalized repository path {expected}"
        ));
    }
    Ok(())
}

fn read_exact_head_input(
    root: &Path,
    source_commit: &str,
    repository_path: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    let files = git_tree_files(root, source_commit, &[repository_path])?;
    if files.len() != 1 || files[0].path != repository_path {
        return Err(format!(
            "snapshotted HEAD must contain exactly one ordinary {label} at {repository_path}"
        ));
    }
    let head_bytes = git_bytes(root, &["cat-file", "blob", &files[0].object_id])?;
    let working_bytes = read_regular_file_once(&root.join(repository_path), label)?;
    if working_bytes != head_bytes {
        return Err(format!(
            "{label} bytes do not match snapshotted HEAD at {repository_path}"
        ));
    }
    Ok(head_bytes)
}

fn validate_output_path(root: &Path, output_dir: &Path) -> Result<PathBuf, String> {
    if output_dir.is_absolute() {
        return Err("preflight output directory must be repository-relative".to_owned());
    }
    let components = output_dir.components().collect::<Vec<_>>();
    if components.len() < 2
        || components.first() != Some(&Component::Normal(OsStr::new("target")))
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(
            "preflight output directory must be a normalized child of repository target/"
                .to_owned(),
        );
    }
    let absolute = root.join(output_dir);
    let mut existing_parent = root.to_path_buf();
    for component in &components[..components.len() - 1] {
        let Component::Normal(name) = component else {
            unreachable!("components were restricted to normalized names");
        };
        existing_parent.push(name);
        match fs::symlink_metadata(&existing_parent) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(format!(
                "preflight output parent must be a regular directory, not a symlink or file: {}",
                existing_parent.display()
            ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(format!(
                    "inspect preflight output parent {}: {error}",
                    existing_parent.display()
                ))
            }
        }
    }
    match fs::symlink_metadata(&absolute) {
        Ok(_) => Err(format!(
            "preflight output directory must not already exist: {}",
            absolute.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(absolute),
        Err(error) => Err(format!(
            "inspect preflight output directory {}: {error}",
            absolute.display()
        )),
    }
}

fn build_commands(output_dir: &Path) -> [BuildCommand; 3] {
    [
        build_command(output_dir.join("cargo-release"), false, false),
        build_command(output_dir.join("cargo-instrumented"), true, false),
        build_command(output_dir.join("cargo-preview"), false, true),
    ]
}

fn build_command(
    target_dir: PathBuf,
    failpoints_enabled: bool,
    preview_enabled: bool,
) -> BuildCommand {
    assert!(
        !(failpoints_enabled && preview_enabled),
        "Preview and certification failpoint build flavors are mutually exclusive"
    );
    let mut arguments = [
        "build",
        "--locked",
        "--release",
        "--target",
        WINDOWS_TARGET,
        "--target-dir",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    arguments.push(target_dir.as_os_str().to_owned());
    arguments.extend(
        [
            "-p",
            "autocad-mcp",
            "--bin",
            "autocad-mcp",
            "--no-default-features",
        ]
        .into_iter()
        .map(OsString::from),
    );
    if !failpoints_enabled && !preview_enabled {
        arguments.extend(
            ["-p", "autolisp-lsp", "--bin", "autolisp-lsp"]
                .into_iter()
                .map(OsString::from),
        );
    }
    if failpoints_enabled {
        arguments.extend(
            ["--features", "xref-certification-failpoints"]
                .into_iter()
                .map(OsString::from),
        );
    } else if preview_enabled {
        arguments.extend(["--features", "preview"].into_iter().map(OsString::from));
    }
    BuildCommand {
        target_dir,
        arguments,
        failpoints_enabled,
        preview_enabled,
    }
}

fn run_build_command(
    root: &Path,
    spec: &BuildCommand,
    rust_toolchain: &str,
    source_commit: &str,
    arg_identity: &CertifiedArgBuildIdentity,
    use_sccache: bool,
) -> Result<(), String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = configured_build_process(
        root,
        spec,
        &cargo,
        rust_toolchain,
        source_commit,
        arg_identity,
        use_sccache,
    );
    let status = command.status().map_err(|error| {
        format!(
            "launch {} {}: {error}",
            Path::new(&cargo).display(),
            display_arguments(&spec.arguments)
        )
    })?;
    if !status.success() {
        let flavor = if spec.failpoints_enabled {
            "instrumented"
        } else if spec.preview_enabled {
            "Preview"
        } else {
            "release"
        };
        return Err(format!(
            "Windows {flavor} build failed with {status}: cargo {}",
            display_arguments(&spec.arguments)
        ));
    }
    Ok(())
}

fn configured_build_process(
    root: &Path,
    spec: &BuildCommand,
    cargo: &OsStr,
    rust_toolchain: &str,
    source_commit: &str,
    arg_identity: &CertifiedArgBuildIdentity,
    use_sccache: bool,
) -> Command {
    let mut command = Command::new(cargo);
    command.args(&spec.arguments).current_dir(root);
    remove_ambient_autocad_environment(&mut command);
    remove_ambient_build_overrides(&mut command);
    command
        // Cargo is launched from this xtask as a direct toolchain executable.
        // Without an explicit binding, its rustc proxy can resolve from a
        // dependency working directory and fall back to the mutable `stable`
        // toolchain instead of the clean-HEAD rust-toolchain.toml channel.
        .env("RUSTUP_TOOLCHAIN", rust_toolchain)
        .env("CARGO_ENCODED_RUSTFLAGS", STATIC_CRT_ENCODED_RUSTFLAGS)
        .env("CARGO_INCREMENTAL", DISABLED_INCREMENTAL_COMPILATION)
        .env(SOURCE_COMMIT_ENV, source_commit)
        .env(CERTIFIED_ARG_SHA256_ENV, &arg_identity.sha256)
        .env(CERTIFIED_ARG_POLICY_ID_ENV, &arg_identity.policy_id)
        .env(CERTIFIED_ARG_POLICY_SHA256_ENV, &arg_identity.policy_sha256);
    if use_sccache {
        // The caller must opt in through the closed CLI flag. Ambient wrappers
        // remain scrubbed above; the only wrapper this path can reintroduce is
        // the literal sccache name, which the workflows resolve through their
        // pinned setup action.
        command.env("RUSTC_WRAPPER", SCCACHE_RUSTC_WRAPPER);
    }
    command
}

fn built_executable(spec: &BuildCommand, executable_name: &str) -> PathBuf {
    spec.target_dir
        .join(WINDOWS_TARGET)
        .join(RELEASE_PROFILE)
        .join(executable_name)
}

fn stage_binary(source: &Path, destination: &Path) -> Result<(), String> {
    let source_path_metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("inspect built executable {}: {error}", source.display()))?;
    if !source_path_metadata.file_type().is_file() {
        return Err(format!(
            "built executable must be a regular non-symlink file: {}",
            source.display()
        ));
    }
    let mut source_file = File::open(source)
        .map_err(|error| format!("open built executable {}: {error}", source.display()))?;
    let source_metadata = source_file
        .metadata()
        .map_err(|error| format!("inspect opened executable {}: {error}", source.display()))?;
    if !source_metadata.is_file() {
        return Err(format!(
            "built executable must resolve to a regular file: {}",
            source.display()
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| format!("staged executable has no parent: {}", destination.display()))?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "create staged artifact directory {}: {error}",
            parent.display()
        )
    })?;
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            format!(
                "create staged executable without replacement {}: {error}",
                destination.display()
            )
        })?;
    io::copy(&mut source_file, &mut destination_file).map_err(|error| {
        format!(
            "copy built executable {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    destination_file.sync_all().map_err(|error| {
        format!(
            "synchronize staged executable {}: {error}",
            destination.display()
        )
    })?;
    Ok(())
}

fn read_certification_info(binary: &Path) -> Result<CertificationInfo, String> {
    let mut command = Command::new(binary);
    command.arg("xref-certification-info");
    remove_ambient_autocad_environment(&mut command);
    let output = command.output().map_err(|error| {
        format!(
            "launch staged executable introspection {}: {error}",
            binary.display()
        )
    })?;
    if !output.status.success() {
        return Err(format!(
            "staged executable introspection {} failed with {}: {}",
            binary.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if !output.stderr.is_empty() {
        return Err(format!(
            "staged executable introspection {} wrote stderr",
            binary.display()
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "parse closed staged executable introspection {}: {error}",
            binary.display()
        )
    })
}

fn remove_ambient_autocad_environment(command: &mut Command) {
    for (name, _) in std::env::vars_os() {
        if is_autocad_environment_name(&name) {
            command.env_remove(name);
        }
    }
}

fn remove_ambient_build_overrides(command: &mut Command) {
    for (name, _) in std::env::vars_os() {
        if is_build_override_environment_name(&name) {
            command.env_remove(name);
        }
    }
}

fn is_autocad_environment_name(name: &OsStr) -> bool {
    name.to_string_lossy()
        .get(..12)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("AUTOCAD_MCP_"))
}

fn is_build_override_environment_name(name: &OsStr) -> bool {
    let name = name.to_string_lossy().to_ascii_uppercase();
    matches!(
        name.as_str(),
        "AR" | "CC"
            | "CL"
            | "CFLAGS"
            | "CXX"
            | "CXXFLAGS"
            | "INCLUDE"
            | "LDFLAGS"
            | "LIB"
            | "LIBPATH"
            | "LINK"
            | "LLVM_CONFIG_PATH"
            | "RANLIB"
            | "RUSTC"
            | "RUSTC_BOOTSTRAP"
            | "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "RUSTFLAGS"
            | "RUSTUP_TOOLCHAIN"
            | "_CL_"
            | "_LINK_"
            | "CARGO_BUILD_INCREMENTAL"
            | "CARGO_BUILD_RUSTC"
            | "CARGO_BUILD_RUSTC_WRAPPER"
            | "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"
            | "CARGO_BUILD_RUSTFLAGS"
            | "CARGO_BUILD_TARGET"
            | "CARGO_BUILD_TARGET_DIR"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "CARGO_INCREMENTAL"
            | "CARGO_TARGET_DIR"
    ) || [
        "AR_",
        "CC_",
        "CFLAGS_",
        "CXX_",
        "CXXFLAGS_",
        "RANLIB_",
        "CARGO_PROFILE_",
        "CARGO_TARGET_",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
        || ["_AR", "_CC", "_CFLAGS", "_CXX", "_CXXFLAGS", "_RANLIB"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

fn validate_build_pair(
    release: &CertificationInfo,
    instrumented: &CertificationInfo,
    head_inputs: &HeadBuildInputs,
    arg_identity: &CertifiedArgBuildIdentity,
    release_binary_sha256: &str,
    instrumented_binary_sha256: &str,
) -> Result<(), String> {
    validate_info("release", release, false, false, head_inputs, arg_identity)?;
    validate_info(
        "instrumented",
        instrumented,
        true,
        false,
        head_inputs,
        arg_identity,
    )?;

    let release_shared = shared_build_identity(&release.build_identity);
    let instrumented_shared = shared_build_identity(&instrumented.build_identity);
    if release_shared != instrumented_shared {
        return Err("release and instrumented build provenance differ".to_owned());
    }
    if release.artifact_sha256 != instrumented.artifact_sha256
        || release.title_block_profile_registry_sha256
            != instrumented.title_block_profile_registry_sha256
        || release.title_block_profiles != instrumented.title_block_profiles
        || release.crt_linkage != instrumented.crt_linkage
        || release.xref_mutation_tools != instrumented.xref_mutation_tools
    {
        return Err(
            "release and instrumented executable inventories or embedded digests differ".to_owned(),
        );
    }
    if release.build_identity.build_id == instrumented.build_identity.build_id {
        return Err("release and instrumented build IDs must be distinct".to_owned());
    }
    if release_binary_sha256 == instrumented_binary_sha256 {
        return Err(
            "release and instrumented executable SHA-256 values must be distinct".to_owned(),
        );
    }
    Ok(())
}

fn validate_preview_build(
    release: &CertificationInfo,
    instrumented: &CertificationInfo,
    preview: &CertificationInfo,
    head_inputs: &HeadBuildInputs,
    arg_identity: &CertifiedArgBuildIdentity,
    binary_sha256s: [&str; 3],
) -> Result<(), String> {
    let [release_binary_sha256, instrumented_binary_sha256, preview_binary_sha256] = binary_sha256s;
    validate_info("Preview", preview, false, true, head_inputs, arg_identity)?;

    if shared_build_identity(&release.build_identity)
        != shared_build_identity(&preview.build_identity)
    {
        return Err("release and Preview build provenance differ".to_owned());
    }
    if release.artifact_sha256 != preview.artifact_sha256
        || release.title_block_profile_registry_sha256
            != preview.title_block_profile_registry_sha256
        || release.title_block_profiles != preview.title_block_profiles
        || release.crt_linkage != preview.crt_linkage
        || release.xref_mutation_tools != preview.xref_mutation_tools
    {
        return Err(
            "release and Preview executable inventories or embedded digests differ".to_owned(),
        );
    }
    if release.build_identity.build_id == preview.build_identity.build_id
        || instrumented.build_identity.build_id == preview.build_identity.build_id
    {
        return Err(
            "release, instrumented, and Preview build IDs must be pairwise distinct".to_owned(),
        );
    }
    if release_binary_sha256 == preview_binary_sha256
        || instrumented_binary_sha256 == preview_binary_sha256
    {
        return Err(
            "release, instrumented, and Preview executable SHA-256 values must be pairwise distinct"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_pe_import_pair(
    left_label: &str,
    left: &PeImportAudit,
    right_label: &str,
    right: &PeImportAudit,
) -> Result<(), String> {
    if left != right {
        return Err(format!(
            "{left_label} and {right_label} PE import inventories differ"
        ));
    }
    Ok(())
}

fn validate_info(
    label: &str,
    info: &CertificationInfo,
    expected_failpoints: bool,
    expected_experimental_support: bool,
    head_inputs: &HeadBuildInputs,
    arg_identity: &CertifiedArgBuildIdentity,
) -> Result<(), String> {
    if info.schema_version != XREF_CERTIFICATION_INFO_SCHEMA_VERSION {
        return Err(format!(
            "{label} introspection schema must be {XREF_CERTIFICATION_INFO_SCHEMA_VERSION}"
        ));
    }
    if info.certified_arg_sha256.as_deref() != Some(arg_identity.sha256.as_str()) {
        return Err(format!(
            "{label} introspection does not bind the exact public ARG digest"
        ));
    }
    if info.certified_arg_policy_id.as_deref() != Some(arg_identity.policy_id.as_str())
        || info.certified_arg_policy_sha256.as_deref() != Some(arg_identity.policy_sha256.as_str())
        || info.build_identity.certified_arg_sha256 != arg_identity.sha256
        || info.build_identity.certified_arg_policy_id != arg_identity.policy_id
        || info.build_identity.certified_arg_policy_sha256 != arg_identity.policy_sha256
    {
        return Err(format!(
            "{label} introspection does not bind the exact public ARG policy identity"
        ));
    }
    let expected_activation_catalogue = autocad_mcp::activation::activation_catalogue_sha256()
        .map_err(|error| format!("validate embedded activation catalogue: {error}"))?;
    if info.activation_catalogue_sha256 != expected_activation_catalogue {
        return Err(format!(
            "{label} introspection does not bind the exact activation catalogue digest"
        ));
    }
    if info.certification_failpoints_enabled != expected_failpoints
        || info.build_identity.certification_failpoints_enabled != expected_failpoints
        || info.certification_failpoints_enabled
            != info.build_identity.certification_failpoints_enabled
    {
        return Err(format!(
            "{label} introspection has the wrong failpoint flavor"
        ));
    }
    if info.experimental_support != expected_experimental_support {
        return Err(format!(
            "{label} introspection has the wrong experimental-support flavor"
        ));
    }
    if info.build_identity.source_commit != head_inputs.source_commit {
        return Err(format!(
            "{label} introspection source commit does not match snapshotted HEAD"
        ));
    }
    if info.build_identity.source_tree_sha256 != head_inputs.source_tree_sha256 {
        return Err(format!(
            "{label} introspection source-tree SHA-256 does not match snapshotted HEAD objects (embedded {}, expected {})",
            info.build_identity.source_tree_sha256, head_inputs.source_tree_sha256
        ));
    }
    if info.build_identity.cargo_lock_sha256 != head_inputs.cargo_lock_sha256 {
        return Err(format!(
            "{label} introspection Cargo.lock SHA-256 does not match snapshotted HEAD object (embedded {}, expected {})",
            info.build_identity.cargo_lock_sha256, head_inputs.cargo_lock_sha256
        ));
    }
    if info.build_identity.shared_operation_source_sha256
        != head_inputs.shared_operation_source_sha256
    {
        return Err(format!(
            "{label} introspection shared-operation SHA-256 does not match snapshotted HEAD objects (embedded {}, expected {})",
            info.build_identity.shared_operation_source_sha256,
            head_inputs.shared_operation_source_sha256
        ));
    }
    if info.build_identity.target != WINDOWS_TARGET
        || info.build_identity.profile != RELEASE_PROFILE
        || info.build_identity.optimization != RELEASE_OPTIMIZATION
        || info.crt_linkage != REQUIRED_CRT_LINKAGE
        || !info
            .build_identity
            .compiler
            .starts_with(REQUIRED_RUSTC_PREFIX)
        || !info.build_identity.compiler.contains(REQUIRED_RUSTC_HOST)
    {
        return Err(format!(
            "{label} introspection is not an optimized, static-CRT Rust 1.97.0 {WINDOWS_TARGET} release build"
        ));
    }

    let expected_artifacts = xref_embedded_artifact_sha256();
    let expected_registry = autocad_mcp::ops::profiles::title_block_profile_registry_sha256();
    let expected_profiles = embedded_certification_profile_definitions();
    let expected_tools = XREF_MUTATION_OPERATIONS
        .into_iter()
        .map(|operation| operation.as_str().to_owned())
        .collect::<Vec<_>>();
    if info.artifact_sha256 != expected_artifacts
        || info.title_block_profile_registry_sha256 != expected_registry
        || info.title_block_profiles != expected_profiles
        || info.xref_mutation_tools != expected_tools
    {
        return Err(format!(
            "{label} introspection does not match the current embedded inventories"
        ));
    }
    Ok(())
}

fn shared_build_identity(identity: &XrefCertificationBuildIdentity) -> SharedBuildIdentity<'_> {
    SharedBuildIdentity {
        source_commit: &identity.source_commit,
        source_tree_sha256: &identity.source_tree_sha256,
        cargo_lock_sha256: &identity.cargo_lock_sha256,
        certified_arg_sha256: &identity.certified_arg_sha256,
        certified_arg_policy_id: &identity.certified_arg_policy_id,
        certified_arg_policy_sha256: &identity.certified_arg_policy_sha256,
        compiler: &identity.compiler,
        target: &identity.target,
        profile: &identity.profile,
        optimization: &identity.optimization,
        shared_operation_source_sha256: &identity.shared_operation_source_sha256,
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn require_file_sha256(path: &Path, expected: &str) -> Result<(), String> {
    let bytes = read_regular_file_once(path, "staged executable")?;
    if sha256_bytes(&bytes) != expected {
        return Err(format!(
            "staged executable changed after PE import audit or introspection: {}",
            path.display()
        ));
    }
    Ok(())
}

fn head_build_inputs(root: &Path, source_commit: &str) -> Result<HeadBuildInputs, String> {
    if source_commit.len() != 40 || !source_commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("snapshotted HEAD is not a full SHA-1 commit object ID".to_owned());
    }
    let mut source_files = git_tree_files(
        root,
        source_commit,
        &[
            "crates/autocad-mcp/src",
            "crates/autocad-mcp/resources",
            "crates/autocad-mcp/profile-registry",
            "crates/autocad-mcp/Cargo.toml",
            "crates/autocad-mcp/build.rs",
            "crates/autocad-reader/src",
            "crates/autocad-reader/Cargo.toml",
            "crates/autocad-writer/src",
            "crates/autocad-writer/Cargo.toml",
        ],
    )?;
    source_files.sort_by(|left, right| left.path.cmp(&right.path));
    for required in [
        "crates/autocad-mcp/Cargo.toml",
        "crates/autocad-mcp/build.rs",
        "crates/autocad-mcp/src/engine.rs",
        "crates/autocad-reader/Cargo.toml",
        "crates/autocad-reader/src/mod.rs",
        "crates/autocad-writer/Cargo.toml",
        "crates/autocad-writer/src/mod.rs",
    ] {
        if !source_files.iter().any(|file| file.path == required) {
            return Err(format!(
                "snapshotted HEAD is missing required build input {required}"
            ));
        }
    }

    let operation_files = source_files
        .iter()
        .filter(|file| {
            file.path == "crates/autocad-mcp/src/engine.rs"
                || file
                    .path
                    .strip_prefix("crates/autocad-mcp/src/ops/")
                    .and_then(|relative| relative.rsplit('/').next())
                    .is_some_and(|name| name.starts_with("xref") && name.ends_with(".rs"))
        })
        .cloned()
        .collect::<Vec<_>>();
    if operation_files.len() < 2 {
        return Err("snapshotted HEAD has no complete XREF operation source inventory".to_owned());
    }

    let cargo_lock = git_bytes(root, &["show", &format!("{source_commit}:Cargo.lock")])?;
    Ok(HeadBuildInputs {
        source_commit: source_commit.to_owned(),
        source_tree_sha256: git_file_set_sha256(root, &source_files)?,
        cargo_lock_sha256: format!("{:x}", Sha256::digest(cargo_lock)),
        shared_operation_source_sha256: git_file_set_sha256(root, &operation_files)?,
    })
}

fn git_tree_files(root: &Path, revision: &str, paths: &[&str]) -> Result<Vec<GitTreeFile>, String> {
    let mut arguments = vec!["ls-tree", "-r", "-z", "--full-tree", revision, "--"];
    arguments.extend_from_slice(paths);
    let output = git_bytes(root, &arguments)?;
    let mut files = Vec::new();
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let separator = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| "git ls-tree returned a malformed record".to_owned())?;
        let metadata = &record[..separator];
        let path = &record[separator + 1..];
        let fields = metadata
            .split(|byte| *byte == b' ')
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        if fields.len() != 3
            || fields[0] != b"100644" && fields[0] != b"100755"
            || fields[1] != b"blob"
        {
            return Err("snapshotted build inputs must contain only ordinary Git blobs".to_owned());
        }
        let object_id = std::str::from_utf8(fields[2])
            .map_err(|error| format!("git ls-tree object ID is not UTF-8: {error}"))?;
        if object_id.len() != 40 || !object_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("git ls-tree returned an invalid object ID".to_owned());
        }
        let path = std::str::from_utf8(path)
            .map_err(|error| format!("snapshotted build path is not UTF-8: {error}"))?;
        let path_components = Path::new(path).components().collect::<Vec<_>>();
        if path_components.is_empty()
            || path_components
                .iter()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(format!("snapshotted build path is not normalized: {path}"));
        }
        files.push(GitTreeFile {
            path: path.to_owned(),
            object_id: object_id.to_owned(),
        });
    }
    if files.is_empty() {
        return Err("snapshotted HEAD contains no build inputs".to_owned());
    }
    Ok(files)
}

fn git_file_set_sha256(root: &Path, files: &[GitTreeFile]) -> Result<String, String> {
    let mut hasher = Sha256::new();
    for file in files {
        let bytes = git_bytes(root, &["cat-file", "blob", &file.object_id])?;
        hasher.update(file.path.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn ensure_plain_index(root: &Path) -> Result<(), String> {
    let output = git_bytes(root, &["ls-files", "-v", "-z", "--"])?;
    validate_plain_index_records(&output)
}

fn validate_plain_index_records(output: &[u8]) -> Result<(), String> {
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if record.len() < 3 || record[0] != b'H' || record[1] != b' ' {
            let path = record
                .get(2..)
                .and_then(|path| std::str::from_utf8(path).ok())
                .unwrap_or("<non-UTF-8 tracked path>");
            return Err(format!(
                "Windows build preflight rejects assume-unchanged, skip-worktree, or nonordinary index state: {path}"
            ));
        }
    }
    Ok(())
}

fn ensure_no_cargo_configuration(root: &Path) -> Result<(), String> {
    let mut cargo_directories = root
        .ancestors()
        .map(|ancestor| ancestor.join(".cargo"))
        .collect::<Vec<_>>();
    let configured_home = std::env::var_os("CARGO_HOME").map(PathBuf::from);
    let default_home = if cfg!(windows) {
        std::env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join(".cargo"))
    } else {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo"))
    };
    if let Some(cargo_home) = configured_home.or(default_home) {
        cargo_directories.push(if cargo_home.is_absolute() {
            cargo_home
        } else {
            root.join(cargo_home)
        });
    }
    cargo_directories.sort();
    cargo_directories.dedup();

    for directory in cargo_directories {
        for name in ["config", "config.toml"] {
            let path = directory.join(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    return Err(format!(
                        "Windows build preflight rejects ambient Cargo configuration: {}",
                        path.display()
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "inspect ambient Cargo configuration {}: {error}",
                        path.display()
                    ))
                }
            }
        }
    }
    Ok(())
}

fn git_output(root: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = git_command(root)
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
        .map(|stdout| stdout.trim().to_owned())
        .map_err(|error| {
            format!(
                "git {} returned non-UTF-8 output: {error}",
                arguments.join(" ")
            )
        })
}

fn git_bytes(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, String> {
    let output = git_command(root)
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
    Ok(output.stdout)
}

fn git_command(root: &Path) -> Command {
    let mut command = Command::new("git");
    command.current_dir(root);
    for name in [
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ] {
        command.env_remove(name);
    }
    command
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C");
    command
}

fn ensure_clean_checkout(root: &Path, label: &str) -> Result<(), String> {
    let status = git_output(root, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    if status.is_empty() {
        Ok(())
    } else {
        Err(format!("{label} requires a clean checkout:\n{status}"))
    }
}

fn portable_repository_path(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        format!(
            "preflight output {} is outside repository {}",
            path.display(),
            root.display()
        )
    })?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn display_arguments(arguments: &[OsString]) -> String {
    arguments
        .iter()
        .map(|argument| argument.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(failpoints: bool) -> CertificationInfo {
        let build_id = if failpoints {
            "instrumented-build"
        } else {
            "release-build"
        };
        CertificationInfo {
            schema_version: XREF_CERTIFICATION_INFO_SCHEMA_VERSION,
            experimental_support: false,
            certified_arg_sha256: Some("a".repeat(64)),
            certified_arg_policy_id: Some(
                autocad_mcp::certified_arg::PUBLIC_DEVELOPMENT_ARG_POLICY_ID.to_owned(),
            ),
            certified_arg_policy_sha256: Some("f".repeat(64)),
            activation_catalogue_sha256: autocad_mcp::activation::activation_catalogue_sha256()
                .unwrap()
                .to_owned(),
            certification_failpoints_enabled: failpoints,
            crt_linkage: REQUIRED_CRT_LINKAGE.to_owned(),
            artifact_sha256: xref_embedded_artifact_sha256(),
            title_block_profile_registry_sha256:
                autocad_mcp::ops::profiles::title_block_profile_registry_sha256(),
            title_block_profiles: embedded_certification_profile_definitions(),
            build_identity: XrefCertificationBuildIdentity {
                source_commit: "commit".to_owned(),
                source_tree_sha256: "b".repeat(64),
                cargo_lock_sha256: "c".repeat(64),
                certified_arg_sha256: "a".repeat(64),
                certified_arg_policy_id:
                    autocad_mcp::certified_arg::PUBLIC_DEVELOPMENT_ARG_POLICY_ID.to_owned(),
                certified_arg_policy_sha256: "f".repeat(64),
                compiler: "rustc 1.97.0 (test); host: x86_64-pc-windows-msvc".to_owned(),
                target: WINDOWS_TARGET.to_owned(),
                profile: RELEASE_PROFILE.to_owned(),
                optimization: RELEASE_OPTIMIZATION.to_owned(),
                build_id: build_id.to_owned(),
                shared_operation_source_sha256: "d".repeat(64),
                certification_failpoints_enabled: failpoints,
            },
            xref_mutation_tools: XREF_MUTATION_OPERATIONS
                .into_iter()
                .map(|operation| operation.as_str().to_owned())
                .collect(),
        }
    }

    fn expected_head_inputs() -> HeadBuildInputs {
        HeadBuildInputs {
            source_commit: "commit".to_owned(),
            source_tree_sha256: "b".repeat(64),
            cargo_lock_sha256: "c".repeat(64),
            shared_operation_source_sha256: "d".repeat(64),
        }
    }

    fn validate_build_pair(
        release: &CertificationInfo,
        instrumented: &CertificationInfo,
        head_inputs: &HeadBuildInputs,
        arg_sha256: &str,
        release_binary_sha256: &str,
        instrumented_binary_sha256: &str,
    ) -> Result<(), String> {
        super::validate_build_pair(
            release,
            instrumented,
            head_inputs,
            &CertifiedArgBuildIdentity {
                sha256: arg_sha256.to_owned(),
                policy_id: autocad_mcp::certified_arg::PUBLIC_DEVELOPMENT_ARG_POLICY_ID.to_owned(),
                policy_sha256: "f".repeat(64),
            },
            release_binary_sha256,
            instrumented_binary_sha256,
        )
    }

    #[test]
    fn build_command_inventory_is_exact_and_separates_outputs() {
        let commands = build_commands(Path::new("target/windows-certification-preflight"));
        assert_eq!(
            display_arguments(&commands[0].arguments),
            "build --locked --release --target x86_64-pc-windows-msvc --target-dir target/windows-certification-preflight/cargo-release -p autocad-mcp --bin autocad-mcp --no-default-features -p autolisp-lsp --bin autolisp-lsp"
        );
        assert_eq!(
            display_arguments(&commands[1].arguments),
            "build --locked --release --target x86_64-pc-windows-msvc --target-dir target/windows-certification-preflight/cargo-instrumented -p autocad-mcp --bin autocad-mcp --no-default-features --features xref-certification-failpoints"
        );
        assert_eq!(
            display_arguments(&commands[2].arguments),
            "build --locked --release --target x86_64-pc-windows-msvc --target-dir target/windows-certification-preflight/cargo-preview -p autocad-mcp --bin autocad-mcp --no-default-features --features preview"
        );
        assert!(!commands[0].failpoints_enabled);
        assert!(!commands[0].preview_enabled);
        assert!(commands[1].failpoints_enabled);
        assert!(!commands[1].preview_enabled);
        assert!(!commands[2].failpoints_enabled);
        assert!(commands[2].preview_enabled);
        assert_ne!(
            built_executable(&commands[0], "autocad-mcp.exe"),
            built_executable(&commands[1], "autocad-mcp.exe")
        );
        assert_ne!(
            built_executable(&commands[0], "autocad-mcp.exe"),
            built_executable(&commands[0], "autolisp-lsp.exe")
        );
        assert_ne!(
            built_executable(&commands[0], "autocad-mcp.exe"),
            built_executable(&commands[2], "autocad-mcp.exe")
        );
        assert_eq!(
            STATIC_CRT_ENCODED_RUSTFLAGS
                .split('\x1f')
                .collect::<Vec<_>>(),
            ["-C", "target-feature=+crt-static"]
        );
        assert_eq!(DISABLED_INCREMENTAL_COMPILATION, "0");
    }

    #[test]
    fn nested_build_process_is_bound_to_the_clean_head_toolchain() {
        let spec = build_command(PathBuf::from("target/preflight"), false, false);
        let identity = CertifiedArgBuildIdentity {
            sha256: "a".repeat(64),
            policy_id: "public-development".to_owned(),
            policy_sha256: "b".repeat(64),
        };
        let command = configured_build_process(
            Path::new("repository"),
            &spec,
            OsStr::new("cargo"),
            "1.97.0",
            "0123456789012345678901234567890123456789",
            &identity,
            false,
        );
        let rustup_toolchain = command
            .get_envs()
            .find(|(name, _)| *name == OsStr::new("RUSTUP_TOOLCHAIN"))
            .and_then(|(_, value)| value);
        assert_eq!(rustup_toolchain, Some(OsStr::new("1.97.0")));
    }

    #[test]
    fn nested_build_process_reintroduces_only_explicit_sccache() {
        let spec = build_command(PathBuf::from("target/preflight"), false, false);
        let identity = CertifiedArgBuildIdentity {
            sha256: "a".repeat(64),
            policy_id: "public-development".to_owned(),
            policy_sha256: "b".repeat(64),
        };
        let command = configured_build_process(
            Path::new("repository"),
            &spec,
            OsStr::new("cargo"),
            "1.97.0",
            "0123456789012345678901234567890123456789",
            &identity,
            true,
        );
        let rustc_wrapper = command
            .get_envs()
            .find(|(name, _)| *name == OsStr::new("RUSTC_WRAPPER"))
            .and_then(|(_, value)| value);
        assert_eq!(rustc_wrapper, Some(OsStr::new(SCCACHE_RUSTC_WRAPPER)));
        for name in [
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        ] {
            assert_ne!(
                command
                    .get_envs()
                    .find(|(configured, _)| *configured == OsStr::new(name))
                    .and_then(|(_, value)| value),
                Some(OsStr::new(SCCACHE_RUSTC_WRAPPER)),
                "{name} must not be reintroduced"
            );
        }
    }

    #[test]
    fn autocad_environment_filter_is_case_insensitive_and_prefix_exact() {
        for name in [
            "AUTOCAD_MCP_PRIVATE",
            "autocad_mcp_private",
            "AutoCad_Mcp_Private",
        ] {
            assert!(is_autocad_environment_name(OsStr::new(name)));
        }
        assert!(!is_autocad_environment_name(OsStr::new("AUTOCAD_MCP")));
        assert!(!is_autocad_environment_name(OsStr::new(
            "PREFIX_AUTOCAD_MCP_PRIVATE"
        )));
    }

    #[test]
    fn ambient_build_override_filter_is_closed_and_case_insensitive() {
        for name in [
            "RUSTFLAGS",
            "RUSTUP_TOOLCHAIN",
            "rustc_wrapper",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "CARGO_ENCODED_RUSTFLAGS",
            "cargo_profile_release_lto",
            "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER",
            "CC_x86_64_pc_windows_msvc",
            "CXXFLAGS",
            "CL",
            "_cl_",
            "_LINK_",
            "INCLUDE",
            "LIB",
            "LIBPATH",
            "LINK",
        ] {
            assert!(
                is_build_override_environment_name(OsStr::new(name)),
                "{name}"
            );
        }
        for allowed in [
            "CARGO",
            "CARGO_HOME",
            "CARGO_TERM_COLOR",
            "PATH",
            "SystemRoot",
        ] {
            assert!(
                !is_build_override_environment_name(OsStr::new(allowed)),
                "{allowed}"
            );
        }
    }

    #[test]
    fn output_path_is_closed_to_a_fresh_normalized_target_child() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            validate_output_path(root.path(), Path::new("target/preflight")).unwrap(),
            root.path().join("target/preflight")
        );
        assert!(validate_output_path(root.path(), Path::new("preflight")).is_err());
        assert!(validate_output_path(root.path(), Path::new("target/../preflight")).is_err());
        assert!(validate_output_path(root.path(), &root.path().join("target/preflight")).is_err());
        fs::create_dir_all(root.path().join("target/existing")).unwrap();
        assert!(validate_output_path(root.path(), Path::new("target/existing")).is_err());

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                root.path().join("outside"),
                root.path().join("target/link"),
            )
            .unwrap();
            assert!(validate_output_path(root.path(), Path::new("target/link/preflight")).is_err());
        }
    }

    #[test]
    fn certified_arg_inputs_are_fixed_to_exact_repository_paths() {
        validate_exact_repository_input_path(
            Path::new(CERTIFIED_ARG_REPOSITORY_PATH),
            CERTIFIED_ARG_REPOSITORY_PATH,
            "ARG",
        )
        .unwrap();
        validate_exact_repository_input_path(
            Path::new(CERTIFIED_ARG_POLICY_REPOSITORY_PATH),
            CERTIFIED_ARG_POLICY_REPOSITORY_PATH,
            "policy",
        )
        .unwrap();
        for substituted in [
            Path::new("tests/fixtures/windows_certification/alternate.arg"),
            Path::new("./tests/fixtures/windows_certification/public-development-profile.arg"),
            Path::new(CERTIFIED_ARG_POLICY_REPOSITORY_PATH),
        ] {
            assert!(validate_exact_repository_input_path(
                substituted,
                CERTIFIED_ARG_REPOSITORY_PATH,
                "ARG",
            )
            .is_err());
        }
    }

    #[test]
    fn certified_arg_inputs_are_read_from_exact_head_blobs() {
        let repository = tempfile::tempdir().unwrap();
        let root = repository.path();
        for (relative, bytes) in [
            (
                CERTIFIED_ARG_REPOSITORY_PATH,
                &include_bytes!(
                    "../../../tests/fixtures/windows_certification/public-development-profile.arg"
                )[..],
            ),
            (
                CERTIFIED_ARG_POLICY_REPOSITORY_PATH,
                &include_bytes!(
                    "../../../tests/fixtures/windows_certification/public-development-arg-policy.json"
                )[..],
            ),
        ] {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        git_output(root, &["init", "--quiet"]).unwrap();
        git_output(
            root,
            &[
                "add",
                "--",
                CERTIFIED_ARG_REPOSITORY_PATH,
                CERTIFIED_ARG_POLICY_REPOSITORY_PATH,
            ],
        )
        .unwrap();
        git_output(
            root,
            &[
                "-c",
                "user.name=AutoCAD-MCP Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        )
        .unwrap();
        let head = git_output(root, &["rev-parse", "--verify", "HEAD^{commit}"]).unwrap();
        let arg = read_exact_head_input(
            root,
            &head,
            CERTIFIED_ARG_REPOSITORY_PATH,
            "public development ARG",
        )
        .unwrap();
        let policy = read_exact_head_input(
            root,
            &head,
            CERTIFIED_ARG_POLICY_REPOSITORY_PATH,
            "public development ARG policy",
        )
        .unwrap();
        let inspection =
            autocad_mcp::certified_arg::validate_distribution_safe_arg(&arg, &policy).unwrap();
        assert_eq!(
            inspection.policy_id,
            autocad_mcp::certified_arg::PUBLIC_DEVELOPMENT_ARG_POLICY_ID
        );
        assert_eq!(
            inspection.purpose,
            autocad_mcp::certified_arg::CertifiedArgPolicyPurpose::DevelopmentFixture
        );

        fs::write(root.join(CERTIFIED_ARG_REPOSITORY_PATH), b"drift").unwrap();
        assert!(read_exact_head_input(
            root,
            &head,
            CERTIFIED_ARG_REPOSITORY_PATH,
            "public development ARG",
        )
        .unwrap_err()
        .contains("do not match snapshotted HEAD"));
    }

    #[test]
    fn head_build_inputs_are_read_from_ordinary_git_objects() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap();
        ensure_plain_index(root).unwrap();
        let head = git_output(root, &["rev-parse", "--verify", "HEAD^{commit}"]).unwrap();
        let boundary_inputs = git_tree_files(
            root,
            &head,
            &[
                "crates/autocad-reader/Cargo.toml",
                "crates/autocad-reader/src",
                "crates/autocad-writer/Cargo.toml",
                "crates/autocad-writer/src",
            ],
        )
        .unwrap();
        assert!(boundary_inputs
            .iter()
            .any(|file| file.path == "crates/autocad-reader/Cargo.toml"));
        assert!(boundary_inputs
            .iter()
            .any(|file| file.path == "crates/autocad-reader/src/mod.rs"));
        assert!(boundary_inputs
            .iter()
            .any(|file| file.path == "crates/autocad-writer/Cargo.toml"));
        assert!(boundary_inputs
            .iter()
            .any(|file| file.path == "crates/autocad-writer/src/mod.rs"));
        let inputs = head_build_inputs(root, &head).unwrap();
        assert_eq!(inputs.source_commit, head);
        for digest in [
            inputs.source_tree_sha256,
            inputs.cargo_lock_sha256,
            inputs.shared_operation_source_sha256,
        ] {
            assert_eq!(digest.len(), 64);
            assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn hidden_or_nonordinary_index_records_are_rejected() {
        validate_plain_index_records(b"H ordinary.rs\0H another.rs\0").unwrap();
        for record in [
            b"h assume-unchanged.rs\0".as_slice(),
            b"S skip-worktree.rs\0".as_slice(),
            b"M unmerged.rs\0".as_slice(),
            b"malformed\0".as_slice(),
        ] {
            assert!(validate_plain_index_records(record).is_err());
        }
    }

    #[test]
    fn ambient_cargo_configuration_is_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("checkout");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(root.join(".cargo")).unwrap();
        fs::write(root.join(".cargo/config.toml"), b"[build]\nrustflags=[]\n").unwrap();
        assert!(ensure_no_cargo_configuration(&root)
            .unwrap_err()
            .contains("ambient Cargo configuration"));
    }

    #[test]
    fn staged_binary_creation_is_atomic_and_never_replaces() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source.exe");
        let destination = temporary.path().join("artifacts/release/autocad-mcp.exe");
        fs::write(&source, b"release-bytes").unwrap();
        stage_binary(&source, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"release-bytes");
        assert!(stage_binary(&source, &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"release-bytes");

        #[cfg(unix)]
        {
            let planted = temporary.path().join("planted.exe");
            let external = temporary.path().join("external.exe");
            fs::write(&external, b"external").unwrap();
            std::os::unix::fs::symlink(&external, &planted).unwrap();
            assert!(stage_binary(&source, &planted).is_err());
            assert_eq!(fs::read(&external).unwrap(), b"external");

            let planted_source = temporary.path().join("planted-source.exe");
            std::os::unix::fs::symlink(&source, &planted_source).unwrap();
            let separate_destination = temporary.path().join("separate.exe");
            assert!(stage_binary(&planted_source, &separate_destination).is_err());
            assert!(!separate_destination.exists());
        }
    }

    #[test]
    fn staged_binary_hash_is_bound_before_and_after_introspection() {
        let temporary = tempfile::tempdir().unwrap();
        let binary = temporary.path().join("candidate.exe");
        fs::write(&binary, b"candidate-before").unwrap();
        let expected = sha256_bytes(b"candidate-before");
        require_file_sha256(&binary, &expected).unwrap();

        fs::write(&binary, b"candidate-after").unwrap();
        assert!(require_file_sha256(&binary, &expected)
            .unwrap_err()
            .contains("changed after PE import audit or introspection"));
    }

    #[test]
    fn build_pair_requires_exact_flavors_and_shared_provenance() {
        let release = info(false);
        let instrumented = info(true);
        validate_build_pair(
            &release,
            &instrumented,
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap();

        let mut wrong_target = info(true);
        wrong_target.build_identity.target = "i686-pc-windows-msvc".to_owned();
        assert!(validate_build_pair(
            &release,
            &wrong_target,
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap_err()
        .contains("not an optimized"));

        let mut wrong_flavor = info(true);
        wrong_flavor.certification_failpoints_enabled = false;
        assert!(validate_build_pair(
            &release,
            &wrong_flavor,
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap_err()
        .contains("wrong failpoint"));

        let mut wrong_schema = info(false);
        wrong_schema.schema_version = 1;
        assert!(validate_build_pair(
            &wrong_schema,
            &instrumented,
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap_err()
        .contains("schema must be 4"));

        let mut wrong_commit = info(false);
        wrong_commit.build_identity.source_commit = "other".to_owned();
        assert!(validate_build_pair(
            &wrong_commit,
            &instrumented,
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap_err()
        .contains("snapshotted HEAD"));
    }

    #[test]
    fn preview_build_requires_explicit_support_and_distinct_identity() {
        let release = info(false);
        let instrumented = info(true);
        let mut preview = info(false);
        preview.experimental_support = true;
        preview.build_identity.build_id = "preview-build".to_owned();
        let release_binary_sha256 = "1".repeat(64);
        let instrumented_binary_sha256 = "2".repeat(64);
        let preview_binary_sha256 = "3".repeat(64);
        let binary_sha256s = [
            release_binary_sha256.as_str(),
            instrumented_binary_sha256.as_str(),
            preview_binary_sha256.as_str(),
        ];

        validate_preview_build(
            &release,
            &instrumented,
            &preview,
            &expected_head_inputs(),
            &CertifiedArgBuildIdentity {
                sha256: "a".repeat(64),
                policy_id: autocad_mcp::certified_arg::PUBLIC_DEVELOPMENT_ARG_POLICY_ID.to_owned(),
                policy_sha256: "f".repeat(64),
            },
            binary_sha256s,
        )
        .unwrap();

        preview.experimental_support = false;
        assert!(validate_preview_build(
            &release,
            &instrumented,
            &preview,
            &expected_head_inputs(),
            &CertifiedArgBuildIdentity {
                sha256: "a".repeat(64),
                policy_id: autocad_mcp::certified_arg::PUBLIC_DEVELOPMENT_ARG_POLICY_ID.to_owned(),
                policy_sha256: "f".repeat(64),
            },
            binary_sha256s,
        )
        .unwrap_err()
        .contains("wrong experimental-support flavor"));

        preview.experimental_support = true;
        preview.build_identity.build_id = instrumented.build_identity.build_id.clone();
        assert!(validate_preview_build(
            &release,
            &instrumented,
            &preview,
            &expected_head_inputs(),
            &CertifiedArgBuildIdentity {
                sha256: "a".repeat(64),
                policy_id: autocad_mcp::certified_arg::PUBLIC_DEVELOPMENT_ARG_POLICY_ID.to_owned(),
                policy_sha256: "f".repeat(64),
            },
            binary_sha256s,
        )
        .unwrap_err()
        .contains("build IDs must be pairwise distinct"));

        preview.build_identity.build_id = "preview-build".to_owned();
        assert!(validate_preview_build(
            &release,
            &instrumented,
            &preview,
            &expected_head_inputs(),
            &CertifiedArgBuildIdentity {
                sha256: "a".repeat(64),
                policy_id: autocad_mcp::certified_arg::PUBLIC_DEVELOPMENT_ARG_POLICY_ID.to_owned(),
                policy_sha256: "f".repeat(64),
            },
            [
                release_binary_sha256.as_str(),
                instrumented_binary_sha256.as_str(),
                instrumented_binary_sha256.as_str(),
            ],
        )
        .unwrap_err()
        .contains("executable SHA-256 values must be pairwise distinct"));
    }

    #[test]
    fn pe_import_pair_requires_identical_external_artifact_observations() {
        let release = PeImportAudit {
            load_time_imports: vec!["kernel32.dll".to_owned()],
            delay_load_imports: Vec::new(),
        };
        validate_pe_import_pair("release", &release, "Preview", &release).unwrap();

        let instrumented = PeImportAudit {
            load_time_imports: vec!["kernel32.dll".to_owned(), "user32.dll".to_owned()],
            delay_load_imports: Vec::new(),
        };
        assert_eq!(
            validate_pe_import_pair("release", &release, "instrumented", &instrumented)
                .unwrap_err(),
            "release and instrumented PE import inventories differ"
        );
    }

    #[test]
    fn build_pair_rejects_arg_provenance_and_identity_mismatches() {
        let release = info(false);

        let mut wrong_arg = info(true);
        wrong_arg.certified_arg_sha256 = Some("e".repeat(64));
        assert!(validate_build_pair(
            &release,
            &wrong_arg,
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap_err()
        .contains("exact public ARG"));

        let mut wrong_policy = info(true);
        wrong_policy.certified_arg_policy_sha256 = Some("e".repeat(64));
        assert!(validate_build_pair(
            &release,
            &wrong_policy,
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap_err()
        .contains("exact public ARG policy"));

        let mut wrong_policy_identity = info(true);
        wrong_policy_identity.build_identity.certified_arg_policy_id =
            "substituted-policy".to_owned();
        assert!(validate_build_pair(
            &release,
            &wrong_policy_identity,
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap_err()
        .contains("exact public ARG policy"));

        let mut wrong_provenance = info(true);
        wrong_provenance.build_identity.cargo_lock_sha256 = "f".repeat(64);
        assert!(validate_build_pair(
            &release,
            &wrong_provenance,
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap_err()
        .contains("Cargo.lock SHA-256"));

        let mut divergent_compiler = info(true);
        divergent_compiler.build_identity.compiler =
            "rustc 1.97.0 (different); host: x86_64-pc-windows-msvc".to_owned();
        assert!(validate_build_pair(
            &release,
            &divergent_compiler,
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap_err()
        .contains("provenance differ"));

        let mut stale_artifact = info(true);
        stale_artifact.artifact_sha256.mutation_capabilities = "0".repeat(64);
        assert!(validate_build_pair(
            &release,
            &stale_artifact,
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap_err()
        .contains("current embedded inventories"));

        let mut same_build_id = info(true);
        same_build_id.build_identity.build_id = release.build_identity.build_id.clone();
        assert!(validate_build_pair(
            &release,
            &same_build_id,
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap_err()
        .contains("build IDs"));

        let mut dynamic_crt = info(false);
        dynamic_crt.crt_linkage = "dynamic".to_owned();
        assert!(validate_build_pair(
            &dynamic_crt,
            &info(true),
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap_err()
        .contains("static-CRT"));

        assert!(validate_build_pair(
            &release,
            &info(true),
            &expected_head_inputs(),
            &"a".repeat(64),
            &"1".repeat(64),
            &"1".repeat(64),
        )
        .unwrap_err()
        .contains("executable SHA-256"));
    }

    #[test]
    fn introspection_parser_is_closed() {
        let mut value = serde_json::to_value(info(false)).unwrap();
        value["unexpected"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<CertificationInfo>(value).is_err());
    }

    #[test]
    fn reported_artifact_paths_are_repository_relative() {
        let root = Path::new("C:/checkout");
        assert_eq!(
            portable_repository_path(
                root,
                Path::new("C:/checkout/target/preflight/artifacts/release/autocad-mcp.exe")
            )
            .unwrap(),
            "target/preflight/artifacts/release/autocad-mcp.exe"
        );
        assert!(portable_repository_path(root, Path::new("C:/other/autocad-mcp.exe")).is_err());
    }
}
