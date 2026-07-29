use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const RECEIPT_SCHEMA_VERSION: u32 = 2;
const INPUT_SCHEMA_VERSION: u32 = 2;
const RECEIPT_ARTIFACT_KIND: &str = "autocad-mcp-pre-push-receipt";
const RECEIPT_SCOPE: &str = "worktree_local_advisory_pre_push_only";
const RECEIPT_OUTCOME: &str = "complete_local_gate_passed";
const INPUT_DIGEST_DOMAIN: &[u8] = b"autocad-mcp-pre-push-input-v2\0";
const CACHE_COMPONENTS: [&str; 3] = ["target", "pre-push-receipts", "v2"];
const MAX_RECEIPT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOOL_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_COMMANDS: usize = 1024;
const MAX_COMMAND_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 4096;
const MAX_CARGO_CONFIGS: usize = 128;
const DISABLE_RECEIPT_ENVIRONMENT: &str = "AUTOCAD_MCP_DISABLE_PRE_PUSH_RECEIPT";

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrePushReceiptInputs {
    schema_version: u32,
    artifact_kind: String,
    candidate: CandidateBinding,
    rendered_commands: Vec<String>,
    cargo_lock: ContentDigest,
    rust_toolchain: ContentDigest,
    pre_push_hook: ContentDigest,
    current_executable: ContentDigest,
    cargo_version: ToolVersionBinding,
    rustc_version: ToolVersionBinding,
    git_version: ToolVersionBinding,
    rustfmt_version: ToolVersionBinding,
    clippy_version: ToolVersionBinding,
    environment: Vec<EnvironmentBinding>,
    platform: PlatformBinding,
    cargo_configurations: Vec<CargoConfigurationBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateBinding {
    git_object_format: String,
    source_commit: String,
    source_tree_oid: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ContentDigest {
    sha256: String,
    bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactBytes {
    sha256: String,
    bytes: u64,
    content_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeValue {
    encoding: String,
    content_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ToolVersionBinding {
    tool: String,
    program: NativeValue,
    arguments: Vec<String>,
    stdout: ExactBytes,
    stderr: ExactBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentBinding {
    name: NativeValue,
    value_sha256: String,
    value_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PlatformBinding {
    operating_system: String,
    architecture: String,
    family: String,
    pointer_width: u16,
    endian: String,
    executable_suffix: String,
    dynamic_library_prefix: String,
    dynamic_library_suffix: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CargoConfigurationBinding {
    discovery_order: u32,
    path: NativeValue,
    contents: ContentDigest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredReceipt {
    schema_version: u32,
    artifact_kind: String,
    scope: String,
    release_authority: bool,
    outcome: String,
    input_sha256: String,
    inputs: PrePushReceiptInputs,
}

struct RuntimeObservation {
    current_executable: PathBuf,
    cargo_version: ToolVersionBinding,
    rustc_version: ToolVersionBinding,
    git_version: ToolVersionBinding,
    rustfmt_version: ToolVersionBinding,
    clippy_version: ToolVersionBinding,
    environment: Vec<(OsString, OsString)>,
    platform: PlatformBinding,
}

/// Capture the local inputs that bind a completed local-gate result.
///
/// Capture failure means only that the advisory cache is unavailable. A caller
/// must run the full gate rather than turn a capture error into gate authority.
pub(crate) fn capture_pre_push_receipt_inputs(
    repository: &Path,
    git_object_format: &str,
    source_commit: &str,
    source_tree_oid: &str,
    rendered_commands: &[String],
) -> Result<PrePushReceiptInputs, String> {
    if !advisory_cache_allowed() {
        return Err(
            format!(
                "advisory pre-push receipts require a non-CI Unix host with implemented file safety and {DISABLE_RECEIPT_ENVIRONMENT} unset"
            ),
        );
    }
    let repository = canonical_real_directory(repository, "pre-push repository")?;
    let runtime = observe_runtime(&repository)?;
    capture_with_runtime(
        &repository,
        git_object_format,
        source_commit,
        source_tree_oid,
        rendered_commands,
        runtime,
    )
}

/// Return true only for an exact-commit, recorded-context, worktree-local receipt.
///
/// Missing, corrupt, oversized, replaced, symlinked, permission-unsafe, or
/// otherwise invalid cache state is deliberately indistinguishable from a
/// cache miss. This receipt is not release or distribution evidence and is not
/// a security boundary: the same user can replace untracked host tools, forge
/// the cache, or bypass a local hook. Set
/// `AUTOCAD_MCP_DISABLE_PRE_PUSH_RECEIPT=1` to force the complete local gate.
pub(crate) fn pre_push_receipt_hit(repository: &Path, expected: &PrePushReceiptInputs) -> bool {
    pre_push_receipt_hit_when_allowed(repository, expected, advisory_cache_allowed())
}

fn pre_push_receipt_hit_when_allowed(
    repository: &Path,
    expected: &PrePushReceiptInputs,
    allowed: bool,
) -> bool {
    allowed && lookup_receipt(repository, expected).unwrap_or(false)
}

/// Record a successful complete local-gate validation.
///
/// The caller invokes this only after the local gate and the separately
/// revalidated ephemeral source candidates have both succeeded. The receipt
/// reuses only the local gate: distribution evidence, registry archives, and
/// source candidates are checked afresh on every push. A write error is
/// advisory: report it if useful, but do not fail the completed gate.
pub(crate) fn record_pre_push_receipt(
    repository: &Path,
    inputs: &PrePushReceiptInputs,
) -> Result<PathBuf, String> {
    record_pre_push_receipt_when_allowed(repository, inputs, advisory_cache_allowed())
}

fn record_pre_push_receipt_when_allowed(
    repository: &Path,
    inputs: &PrePushReceiptInputs,
    allowed: bool,
) -> Result<PathBuf, String> {
    if !allowed {
        return Err(
            format!(
                "advisory pre-push receipts require a non-CI Unix host with implemented file safety and {DISABLE_RECEIPT_ENVIRONMENT} unset"
            ),
        );
    }
    validate_inputs(inputs)?;
    let input_sha256 = input_digest(inputs)?;
    let receipt = StoredReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION,
        artifact_kind: RECEIPT_ARTIFACT_KIND.to_owned(),
        scope: RECEIPT_SCOPE.to_owned(),
        release_authority: false,
        outcome: RECEIPT_OUTCOME.to_owned(),
        input_sha256: input_sha256.clone(),
        inputs: inputs.clone(),
    };
    let mut bytes = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| format!("serialize advisory pre-push receipt: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err("advisory pre-push receipt exceeds its closed size limit".to_owned());
    }

    let directory = cache_directory(repository, true)?;
    let directory_metadata = fs::symlink_metadata(&directory)
        .map_err(|error| format!("inspect advisory receipt directory: {error}"))?;
    let final_path = directory.join(format!("{input_sha256}.json"));

    match fs::symlink_metadata(&final_path) {
        Ok(_) if read_matching_receipt(&final_path, inputs, &input_sha256).unwrap_or(false) => {
            verify_named_directory(&directory, &directory_metadata)?;
            return Ok(final_path);
        }
        Ok(_) => {
            return Err(
                "an invalid or unsafe advisory receipt already occupies the recorded-context key"
                    .to_owned(),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "inspect advisory pre-push receipt {}: {error}",
                final_path.display()
            ))
        }
    }

    let (temporary_path, mut temporary_file) = create_temporary_receipt(&directory)?;
    let mut temporary = OwnedTemporaryFile::new(temporary_path.clone());
    temporary_file
        .write_all(&bytes)
        .and_then(|_| temporary_file.sync_all())
        .map_err(|error| format!("write advisory pre-push receipt: {error}"))?;
    let opened_metadata = temporary_file
        .metadata()
        .map_err(|error| format!("inspect written advisory pre-push receipt: {error}"))?;
    require_private_receipt_file(&opened_metadata)?;
    verify_opened_file_still_named(
        &temporary_path,
        &opened_metadata,
        "temporary advisory pre-push receipt",
    )?;
    verify_named_directory(&directory, &directory_metadata)?;

    match fs::hard_link(&temporary_path, &final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read_matching_receipt(&final_path, inputs, &input_sha256).unwrap_or(false) {
                temporary.cleanup()?;
                verify_named_directory(&directory, &directory_metadata)?;
                return Ok(final_path);
            }
            return Err(
                "a competing invalid advisory receipt occupied the recorded-context key".to_owned(),
            );
        }
        Err(error) => {
            return Err(format!(
                "atomically publish advisory pre-push receipt {}: {error}",
                final_path.display()
            ))
        }
    }
    temporary.cleanup()?;
    sync_directory(&directory)?;
    verify_named_directory(&directory, &directory_metadata)?;

    if !read_matching_receipt(&final_path, inputs, &input_sha256).unwrap_or(false) {
        return Err("published advisory pre-push receipt did not verify".to_owned());
    }
    Ok(final_path)
}

fn advisory_cache_allowed() -> bool {
    let disallowed_environment_present = [
        "CI",
        "GITHUB_ACTIONS",
        "TF_BUILD",
        "GITLAB_CI",
        "BUILDKITE",
        DISABLE_RECEIPT_ENVIRONMENT,
    ]
    .iter()
    .any(|name| env::var_os(name).is_some());
    advisory_cache_allowed_for_platform(cfg!(unix), disallowed_environment_present)
}

fn advisory_cache_allowed_for_platform(
    is_unix: bool,
    disallowed_environment_present: bool,
) -> bool {
    is_unix && !disallowed_environment_present
}

fn observe_runtime(repository: &Path) -> Result<RuntimeObservation, String> {
    let environment = env::vars_os().collect::<Vec<_>>();
    Ok(RuntimeObservation {
        current_executable: env::current_exe()
            .map_err(|error| format!("resolve current xtask executable: {error}"))?,
        cargo_version: observe_tool_version(
            repository,
            "cargo",
            OsStr::new("cargo"),
            &["--version", "--verbose"],
        )?,
        rustc_version: observe_tool_version(
            repository,
            "rustc",
            OsStr::new("rustc"),
            &["--version", "--verbose"],
        )?,
        git_version: observe_tool_version(repository, "git", OsStr::new("git"), &["--version"])?,
        rustfmt_version: observe_tool_version(
            repository,
            "cargo-fmt",
            OsStr::new("cargo"),
            &["fmt", "--version"],
        )?,
        clippy_version: observe_tool_version(
            repository,
            "cargo-clippy",
            OsStr::new("cargo"),
            &["clippy", "--version"],
        )?,
        environment,
        platform: current_platform(),
    })
}

fn observe_tool_version(
    repository: &Path,
    tool: &str,
    program: &OsStr,
    arguments: &[&str],
) -> Result<ToolVersionBinding, String> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(repository)
        .output()
        .map_err(|error| format!("launch {tool} {}: {error}", arguments.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "{tool} {} failed with {}: {}",
            arguments.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if output.stdout.len() > MAX_TOOL_OUTPUT_BYTES || output.stderr.len() > MAX_TOOL_OUTPUT_BYTES {
        return Err(format!(
            "{tool} version output exceeds its closed size limit"
        ));
    }
    Ok(ToolVersionBinding {
        tool: tool.to_owned(),
        program: encode_native_value(program),
        arguments: arguments.iter().map(|value| (*value).to_owned()).collect(),
        stdout: ExactBytes::from_bytes(&output.stdout),
        stderr: ExactBytes::from_bytes(&output.stderr),
    })
}

fn capture_with_runtime(
    repository: &Path,
    git_object_format: &str,
    source_commit: &str,
    source_tree_oid: &str,
    rendered_commands: &[String],
    runtime: RuntimeObservation,
) -> Result<PrePushReceiptInputs, String> {
    let candidate = CandidateBinding {
        git_object_format: git_object_format.to_owned(),
        source_commit: source_commit.to_owned(),
        source_tree_oid: source_tree_oid.to_owned(),
    };
    validate_candidate(&candidate)?;

    let environment = environment_bindings(&runtime.environment)?;
    let cargo_configurations_before =
        discover_cargo_configurations(repository, &runtime.environment)?;
    let cargo_configurations_after =
        discover_cargo_configurations(repository, &runtime.environment)?;
    if cargo_configurations_before != cargo_configurations_after {
        return Err("Cargo configuration changed while receipt inputs were captured".to_owned());
    }

    let inputs = PrePushReceiptInputs {
        schema_version: INPUT_SCHEMA_VERSION,
        artifact_kind: RECEIPT_ARTIFACT_KIND.to_owned(),
        candidate,
        rendered_commands: rendered_commands.to_vec(),
        cargo_lock: hash_regular_file(&repository.join("Cargo.lock"), "Cargo.lock")?,
        rust_toolchain: hash_regular_file(
            &repository.join("rust-toolchain.toml"),
            "rust-toolchain.toml",
        )?,
        pre_push_hook: hash_regular_file(
            &repository.join(".githooks").join("pre-push"),
            "tracked pre-push hook",
        )?,
        current_executable: hash_regular_file(
            &runtime.current_executable,
            "current xtask executable",
        )?,
        cargo_version: runtime.cargo_version,
        rustc_version: runtime.rustc_version,
        git_version: runtime.git_version,
        rustfmt_version: runtime.rustfmt_version,
        clippy_version: runtime.clippy_version,
        environment,
        platform: runtime.platform,
        cargo_configurations: cargo_configurations_before,
    };
    validate_inputs(&inputs)?;
    input_digest(&inputs)?;
    Ok(inputs)
}

fn lookup_receipt(repository: &Path, expected: &PrePushReceiptInputs) -> Result<bool, String> {
    validate_inputs(expected)?;
    let input_sha256 = input_digest(expected)?;
    let directory = cache_directory(repository, false)?;
    let metadata = fs::symlink_metadata(&directory)
        .map_err(|error| format!("inspect advisory receipt directory: {error}"))?;
    let path = directory.join(format!("{input_sha256}.json"));
    let matches = read_matching_receipt(&path, expected, &input_sha256)?;
    verify_named_directory(&directory, &metadata)?;
    Ok(matches)
}

fn read_matching_receipt(
    path: &Path,
    expected: &PrePushReceiptInputs,
    expected_digest: &str,
) -> Result<bool, String> {
    let (mut file, metadata) = open_stable_regular_file(path, "advisory pre-push receipt")?;
    require_private_receipt_file(&metadata)?;
    if metadata.len() > MAX_RECEIPT_BYTES {
        return Err("advisory pre-push receipt exceeds its closed size limit".to_owned());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read advisory pre-push receipt: {error}"))?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err("advisory pre-push receipt exceeds its closed size limit".to_owned());
    }
    verify_opened_file_still_named(path, &metadata, "advisory pre-push receipt")?;
    let receipt: StoredReceipt = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse strict advisory pre-push receipt: {error}"))?;
    validate_stored_receipt(&receipt)?;
    Ok(receipt.input_sha256 == expected_digest && receipt.inputs == *expected)
}

fn validate_stored_receipt(receipt: &StoredReceipt) -> Result<(), String> {
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION
        || receipt.artifact_kind != RECEIPT_ARTIFACT_KIND
        || receipt.scope != RECEIPT_SCOPE
        || receipt.release_authority
        || receipt.outcome != RECEIPT_OUTCOME
    {
        return Err("advisory pre-push receipt has unsupported authority or schema".to_owned());
    }
    validate_inputs(&receipt.inputs)?;
    require_sha256(&receipt.input_sha256, "receipt input")?;
    if input_digest(&receipt.inputs)? != receipt.input_sha256 {
        return Err("advisory pre-push receipt input digest is inconsistent".to_owned());
    }
    Ok(())
}

fn validate_inputs(inputs: &PrePushReceiptInputs) -> Result<(), String> {
    if inputs.schema_version != INPUT_SCHEMA_VERSION
        || inputs.artifact_kind != RECEIPT_ARTIFACT_KIND
    {
        return Err("unsupported advisory pre-push input schema".to_owned());
    }
    validate_candidate(&inputs.candidate)?;
    if inputs.rendered_commands.is_empty() || inputs.rendered_commands.len() > MAX_COMMANDS {
        return Err("pre-push command inventory must be non-empty and bounded".to_owned());
    }
    for command in &inputs.rendered_commands {
        if command.is_empty()
            || command.len() > MAX_COMMAND_BYTES
            || command.as_bytes().contains(&0)
        {
            return Err("pre-push command inventory contains an invalid command".to_owned());
        }
    }
    for (binding, label, require_nonempty) in [
        (&inputs.cargo_lock, "Cargo.lock", true),
        (&inputs.rust_toolchain, "rust-toolchain.toml", true),
        (&inputs.pre_push_hook, "pre-push hook", true),
        (&inputs.current_executable, "current executable", true),
    ] {
        validate_content_digest(binding, label, require_nonempty)?;
    }
    validate_tool_version(
        &inputs.cargo_version,
        "cargo",
        "cargo",
        &["--version", "--verbose"],
    )?;
    validate_tool_version(
        &inputs.rustc_version,
        "rustc",
        "rustc",
        &["--version", "--verbose"],
    )?;
    validate_tool_version(&inputs.git_version, "git", "git", &["--version"])?;
    validate_tool_version(
        &inputs.rustfmt_version,
        "cargo-fmt",
        "cargo",
        &["fmt", "--version"],
    )?;
    validate_tool_version(
        &inputs.clippy_version,
        "cargo-clippy",
        "cargo",
        &["clippy", "--version"],
    )?;
    if inputs.environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err("pre-push environment binding is too large".to_owned());
    }
    let mut prior_environment_name = None;
    for variable in &inputs.environment {
        validate_native_value(&variable.name)?;
        require_sha256(&variable.value_sha256, "environment value")?;
        if prior_environment_name
            .as_ref()
            .is_some_and(|prior: &NativeValue| prior >= &variable.name)
        {
            return Err("pre-push environment binding is not strictly ordered".to_owned());
        }
        prior_environment_name = Some(variable.name.clone());
    }
    validate_platform(&inputs.platform)?;
    if inputs.cargo_configurations.len() > MAX_CARGO_CONFIGS {
        return Err("too many Cargo configurations were discovered".to_owned());
    }
    let mut paths = BTreeSet::new();
    for (index, configuration) in inputs.cargo_configurations.iter().enumerate() {
        if configuration.discovery_order != index as u32 {
            return Err("Cargo configuration discovery order is not canonical".to_owned());
        }
        validate_native_value(&configuration.path)?;
        if !paths.insert(configuration.path.clone()) {
            return Err("Cargo configuration path is repeated".to_owned());
        }
        validate_content_digest(&configuration.contents, "Cargo configuration", false)?;
    }
    Ok(())
}

fn validate_candidate(candidate: &CandidateBinding) -> Result<(), String> {
    let oid_length = match candidate.git_object_format.as_str() {
        "sha1" => 40,
        "sha256" => 64,
        other => return Err(format!("unsupported Git object format {other:?}")),
    };
    require_oid(&candidate.source_commit, oid_length, "source commit")?;
    require_oid(&candidate.source_tree_oid, oid_length, "source tree")
}

fn validate_tool_version(
    binding: &ToolVersionBinding,
    expected_tool: &str,
    expected_program: &str,
    expected_arguments: &[&str],
) -> Result<(), String> {
    if binding.tool != expected_tool
        || binding.program != encode_native_value(OsStr::new(expected_program))
        || binding.arguments
            != expected_arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect::<Vec<_>>()
    {
        return Err(format!("{expected_tool} version binding is not canonical"));
    }
    binding.stdout.validate()?;
    binding.stderr.validate()?;
    if binding.stdout.bytes == 0 {
        return Err(format!("{expected_tool} version output is empty"));
    }
    Ok(())
}

fn validate_platform(platform: &PlatformBinding) -> Result<(), String> {
    if platform.operating_system.is_empty()
        || platform.architecture.is_empty()
        || platform.family.is_empty()
        || !matches!(platform.pointer_width, 16 | 32 | 64 | 128)
        || !matches!(platform.endian.as_str(), "little" | "big")
    {
        return Err("pre-push platform binding is invalid".to_owned());
    }
    Ok(())
}

fn validate_content_digest(
    binding: &ContentDigest,
    label: &str,
    require_nonempty: bool,
) -> Result<(), String> {
    require_sha256(&binding.sha256, label)?;
    if require_nonempty && binding.bytes == 0 {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn input_digest(inputs: &PrePushReceiptInputs) -> Result<String, String> {
    let bytes = serde_json::to_vec(inputs)
        .map_err(|error| format!("serialize pre-push receipt inputs: {error}"))?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err("pre-push receipt inputs exceed their closed size limit".to_owned());
    }
    let mut digest = Sha256::new();
    digest.update(INPUT_DIGEST_DOMAIN);
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}

fn hash_regular_file(path: &Path, label: &str) -> Result<ContentDigest, String> {
    let (mut file, metadata) = open_stable_regular_file(path, label)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek {label} before hashing: {error}"))?;
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("hash {label}: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| format!("{label} byte count overflow"))?;
    }
    if bytes != metadata.len() {
        return Err(format!("{label} changed size while being hashed"));
    }
    verify_opened_file_still_named(path, &metadata, label)?;
    Ok(ContentDigest {
        sha256: format!("{:x}", digest.finalize()),
        bytes,
    })
}

fn discover_cargo_configurations(
    repository: &Path,
    environment: &[(OsString, OsString)],
) -> Result<Vec<CargoConfigurationBinding>, String> {
    let mut directories = repository
        .ancestors()
        .map(|ancestor| ancestor.join(".cargo"))
        .collect::<Vec<_>>();
    if let Some(cargo_home) = cargo_home(repository, environment) {
        directories.push(cargo_home);
    }

    let mut seen = BTreeSet::new();
    let mut configurations = Vec::new();
    for directory in directories {
        let directory = match fs::symlink_metadata(&directory) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "Cargo configuration root must be a real directory: {}",
                        directory.display()
                    ));
                }
                fs::canonicalize(&directory).map_err(|error| {
                    format!(
                        "canonicalize Cargo configuration root {}: {error}",
                        directory.display()
                    )
                })?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "inspect Cargo configuration root {}: {error}",
                    directory.display()
                ))
            }
        };
        for name in ["config.toml", "config"] {
            let path = directory.join(name);
            let encoded_path = encode_native_value(path.as_os_str());
            if !seen.insert(encoded_path.clone()) {
                continue;
            }
            match fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        return Err(format!(
                            "Cargo configuration must be a regular non-symlink file: {}",
                            path.display()
                        ));
                    }
                    let contents = hash_regular_file(&path, "Cargo configuration")?;
                    configurations.push(CargoConfigurationBinding {
                        discovery_order: configurations.len() as u32,
                        path: encoded_path,
                        contents,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "inspect Cargo configuration {}: {error}",
                        path.display()
                    ))
                }
            }
        }
    }
    if configurations.len() > MAX_CARGO_CONFIGS {
        return Err("too many Cargo configurations were discovered".to_owned());
    }
    Ok(configurations)
}

fn cargo_home(repository: &Path, environment: &[(OsString, OsString)]) -> Option<PathBuf> {
    if let Some(configured) = environment_value(environment, "CARGO_HOME") {
        let path = PathBuf::from(configured);
        return Some(if path.is_absolute() {
            path
        } else {
            repository.join(path)
        });
    }
    let home_name = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    environment_value(environment, home_name).map(|home| PathBuf::from(home).join(".cargo"))
}

fn environment_bindings(
    environment: &[(OsString, OsString)],
) -> Result<Vec<EnvironmentBinding>, String> {
    let mut bindings = environment
        .iter()
        .map(|(name, value)| {
            let value_bytes = native_bytes(value);
            EnvironmentBinding {
                name: encode_native_value(name),
                value_sha256: sha256_bytes(&value_bytes),
                value_bytes: value_bytes.len() as u64,
            }
        })
        .collect::<Vec<_>>();
    bindings.sort();
    if bindings.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err("pre-push environment repeats a variable name".to_owned());
    }
    if bindings.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err("pre-push environment binding is too large".to_owned());
    }
    Ok(bindings)
}

fn environment_value(environment: &[(OsString, OsString)], expected: &str) -> Option<OsString> {
    environment.iter().find_map(|(name, value)| {
        let matches = if cfg!(windows) {
            name.to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(expected))
        } else {
            name == OsStr::new(expected)
        };
        matches.then(|| value.clone())
    })
}

fn current_platform() -> PlatformBinding {
    PlatformBinding {
        operating_system: env::consts::OS.to_owned(),
        architecture: env::consts::ARCH.to_owned(),
        family: env::consts::FAMILY.to_owned(),
        pointer_width: (std::mem::size_of::<usize>() * 8) as u16,
        endian: if cfg!(target_endian = "little") {
            "little".to_owned()
        } else {
            "big".to_owned()
        },
        executable_suffix: env::consts::EXE_SUFFIX.to_owned(),
        dynamic_library_prefix: env::consts::DLL_PREFIX.to_owned(),
        dynamic_library_suffix: env::consts::DLL_SUFFIX.to_owned(),
    }
}

fn cache_directory(repository: &Path, create: bool) -> Result<PathBuf, String> {
    let repository = canonical_real_directory(repository, "pre-push repository")?;
    let repository_metadata = fs::symlink_metadata(&repository)
        .map_err(|error| format!("inspect pre-push repository: {error}"))?;
    let mut current = repository.clone();
    for (index, component) in CACHE_COMPONENTS.iter().enumerate() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                require_real_directory(&current, &metadata)?;
                if index > 0 {
                    require_private_cache_directory(&repository_metadata, &metadata)?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                create_private_directory(&current)?;
                let metadata = fs::symlink_metadata(&current).map_err(|error| {
                    format!(
                        "inspect created advisory cache directory {}: {error}",
                        current.display()
                    )
                })?;
                require_real_directory(&current, &metadata)?;
                if index > 0 {
                    require_private_cache_directory(&repository_metadata, &metadata)?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err("advisory pre-push receipt cache is absent".to_owned())
            }
            Err(error) => {
                return Err(format!(
                    "inspect advisory cache directory {}: {error}",
                    current.display()
                ))
            }
        }
        let canonical = fs::canonicalize(&current).map_err(|error| {
            format!(
                "canonicalize advisory cache directory {}: {error}",
                current.display()
            )
        })?;
        if canonical != current {
            return Err("advisory cache directory resolved through an unsafe path".to_owned());
        }
    }
    if !current.starts_with(&repository) {
        return Err("advisory receipt cache resolved outside the worktree".to_owned());
    }
    Ok(current)
}

fn create_private_directory(path: &Path) -> Result<(), String> {
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        format!(
            "create advisory cache directory {}: {error}",
            path.display()
        )
    })
}

fn require_real_directory(path: &Path, metadata: &Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        Err(format!(
            "advisory cache path must be a real directory: {}",
            path.display()
        ))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn require_private_cache_directory(
    repository: &Metadata,
    directory: &Metadata,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    if repository.uid() != directory.uid() || directory.mode() & 0o022 != 0 {
        Err("advisory cache directory has unsafe ownership or permissions".to_owned())
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn require_private_cache_directory(
    _repository: &Metadata,
    _directory: &Metadata,
) -> Result<(), String> {
    Ok(())
}

fn create_temporary_receipt(directory: &Path) -> Result<(PathBuf, File), String> {
    for _ in 0..32 {
        let name = unique_temporary_name()?;
        let path = directory.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(error) =
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(format!("set advisory receipt permissions: {error}"));
                    }
                }
                return Ok((path, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "create temporary advisory receipt in {}: {error}",
                    directory.display()
                ))
            }
        }
    }
    Err("could not allocate a unique temporary advisory receipt".to_owned())
}

fn unique_temporary_name() -> Result<String, String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(format!(
        ".pre-push-receipt-{}-{}-{sequence}.tmp",
        std::process::id(),
        elapsed.as_nanos()
    ))
}

struct OwnedTemporaryFile {
    path: PathBuf,
    active: bool,
}

impl OwnedTemporaryFile {
    fn new(path: PathBuf) -> Self {
        Self { path, active: true }
    }

    fn cleanup(&mut self) -> Result<(), String> {
        fs::remove_file(&self.path)
            .map_err(|error| format!("remove temporary advisory receipt: {error}"))?;
        self.active = false;
        Ok(())
    }
}

impl Drop for OwnedTemporaryFile {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn open_stable_regular_file(path: &Path, label: &str) -> Result<(File, Metadata), String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(format!(
            "{label} must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    let file =
        File::open(path).map_err(|error| format!("open {label} {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("inspect opened {label} {}: {error}", path.display()))?;
    if !opened.is_file() {
        return Err(format!("{label} opened as a non-regular file"));
    }
    verify_metadata_identity(&before, &opened, label)?;
    verify_opened_file_still_named(path, &opened, label)?;
    Ok((file, opened))
}

fn verify_opened_file_still_named(
    path: &Path,
    opened: &Metadata,
    label: &str,
) -> Result<(), String> {
    let named = fs::symlink_metadata(path)
        .map_err(|error| format!("reinspect {label} {}: {error}", path.display()))?;
    if named.file_type().is_symlink() || !named.is_file() {
        return Err(format!("{label} path changed while open"));
    }
    verify_metadata_identity(opened, &named, label)
}

fn verify_named_directory(path: &Path, expected: &Metadata) -> Result<(), String> {
    let actual = fs::symlink_metadata(path)
        .map_err(|error| format!("reinspect advisory cache directory: {error}"))?;
    if actual.file_type().is_symlink() || !actual.is_dir() {
        return Err("advisory cache directory was replaced".to_owned());
    }
    verify_metadata_identity(expected, &actual, "advisory cache directory")
}

#[cfg(unix)]
fn verify_metadata_identity(
    expected: &Metadata,
    actual: &Metadata,
    label: &str,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    if expected.dev() == actual.dev() && expected.ino() == actual.ino() {
        Ok(())
    } else {
        Err(format!("{label} was replaced while being inspected"))
    }
}

#[cfg(not(unix))]
fn verify_metadata_identity(
    expected: &Metadata,
    actual: &Metadata,
    label: &str,
) -> Result<(), String> {
    if expected.len() == actual.len()
        && expected.created().ok() == actual.created().ok()
        && expected.modified().ok() == actual.modified().ok()
    {
        Ok(())
    } else {
        Err(format!("{label} was replaced while being inspected"))
    }
}

#[cfg(unix)]
fn require_private_receipt_file(metadata: &Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    if metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
        Err("advisory receipt must be mode 0600 with one link".to_owned())
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn require_private_receipt_file(_metadata: &Metadata) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync advisory receipt directory: {error}"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn canonical_real_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect {label}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} must be a real directory"));
    }
    fs::canonicalize(path).map_err(|error| format!("canonicalize {label}: {error}"))
}

impl ExactBytes {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            sha256: sha256_bytes(bytes),
            bytes: bytes.len() as u64,
            content_hex: hex_encode(bytes),
        }
    }

    fn validate(&self) -> Result<(), String> {
        require_sha256(&self.sha256, "exact bytes")?;
        if self.bytes > MAX_TOOL_OUTPUT_BYTES as u64 {
            return Err("exact byte binding exceeds its closed size limit".to_owned());
        }
        let bytes = hex_decode(&self.content_hex)?;
        if bytes.len() as u64 != self.bytes || sha256_bytes(&bytes) != self.sha256 {
            return Err("exact byte binding is inconsistent".to_owned());
        }
        Ok(())
    }
}

fn validate_native_value(value: &NativeValue) -> Result<(), String> {
    if !matches!(
        value.encoding.as_str(),
        "unix_bytes" | "windows_utf16le" | "utf8"
    ) {
        return Err("native value uses an unsupported encoding".to_owned());
    }
    let bytes = hex_decode(&value.content_hex)?;
    if value.encoding == "windows_utf16le" && !bytes.len().is_multiple_of(2) {
        return Err("Windows native value has an odd UTF-16 byte count".to_owned());
    }
    Ok(())
}

fn encode_native_value(value: &OsStr) -> NativeValue {
    let (encoding, bytes) = native_encoding_and_bytes(value);
    NativeValue {
        encoding: encoding.to_owned(),
        content_hex: hex_encode(&bytes),
    }
}

#[cfg(unix)]
fn native_encoding_and_bytes(value: &OsStr) -> (&'static str, Vec<u8>) {
    use std::os::unix::ffi::OsStrExt;

    ("unix_bytes", value.as_bytes().to_vec())
}

#[cfg(windows)]
fn native_encoding_and_bytes(value: &OsStr) -> (&'static str, Vec<u8>) {
    use std::os::windows::ffi::OsStrExt;

    let bytes = value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    ("windows_utf16le", bytes)
}

#[cfg(not(any(unix, windows)))]
fn native_encoding_and_bytes(value: &OsStr) -> (&'static str, Vec<u8>) {
    ("utf8", value.to_string_lossy().as_bytes().to_vec())
}

fn native_bytes(value: &OsStr) -> Vec<u8> {
    native_encoding_and_bytes(value).1
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn require_sha256(value: &str, label: &str) -> Result<(), String> {
    require_oid(value, 64, &format!("{label} SHA-256"))
}

fn require_oid(value: &str, length: usize, label: &str) -> Result<(), String> {
    if value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "{label} is not a lowercase {length}-digit hexadecimal value"
        ))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hexadecimal value has an odd length".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|digits| {
            let high = hex_digit(digits[0])?;
            let low = hex_digit(digits[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("hexadecimal value is not lowercase canonical hex".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _temporary: tempfile::TempDir,
        repository: PathBuf,
        executable: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let repository = temporary.path().join("repository");
            fs::create_dir(&repository).expect("create repository");
            fs::write(repository.join("Cargo.lock"), b"lock-v1\n").expect("write Cargo.lock");
            fs::write(
                repository.join("rust-toolchain.toml"),
                b"[toolchain]\nchannel = \"1.97.0\"\n",
            )
            .expect("write toolchain");
            fs::create_dir(repository.join(".githooks")).expect("create hooks");
            fs::write(
                repository.join(".githooks").join("pre-push"),
                b"#!/bin/sh\nexit 0\n",
            )
            .expect("write hook");
            fs::create_dir(repository.join(".cargo")).expect("create Cargo config");
            fs::write(
                repository.join(".cargo").join("config.toml"),
                b"[build]\nincremental = false\n",
            )
            .expect("write Cargo config");
            let executable = temporary.path().join("xtask-fixture");
            fs::write(&executable, b"standalone xtask fixture\n").expect("write executable");
            Self {
                _temporary: temporary,
                repository,
                executable,
            }
        }

        fn runtime(&self) -> RuntimeObservation {
            RuntimeObservation {
                current_executable: self.executable.clone(),
                cargo_version: ToolVersionBinding {
                    tool: "cargo".to_owned(),
                    program: encode_native_value(OsStr::new("cargo")),
                    arguments: vec!["--version".to_owned(), "--verbose".to_owned()],
                    stdout: ExactBytes::from_bytes(b"cargo 1.97.0\nhost: fixture\n"),
                    stderr: ExactBytes::from_bytes(b""),
                },
                rustc_version: ToolVersionBinding {
                    tool: "rustc".to_owned(),
                    program: encode_native_value(OsStr::new("rustc")),
                    arguments: vec!["--version".to_owned(), "--verbose".to_owned()],
                    stdout: ExactBytes::from_bytes(b"rustc 1.97.0\nhost: fixture\n"),
                    stderr: ExactBytes::from_bytes(b""),
                },
                git_version: ToolVersionBinding {
                    tool: "git".to_owned(),
                    program: encode_native_value(OsStr::new("git")),
                    arguments: vec!["--version".to_owned()],
                    stdout: ExactBytes::from_bytes(b"git version 2.50.0\n"),
                    stderr: ExactBytes::from_bytes(b""),
                },
                rustfmt_version: ToolVersionBinding {
                    tool: "cargo-fmt".to_owned(),
                    program: encode_native_value(OsStr::new("cargo")),
                    arguments: vec!["fmt".to_owned(), "--version".to_owned()],
                    stdout: ExactBytes::from_bytes(b"rustfmt 1.9.0-stable\n"),
                    stderr: ExactBytes::from_bytes(b""),
                },
                clippy_version: ToolVersionBinding {
                    tool: "cargo-clippy".to_owned(),
                    program: encode_native_value(OsStr::new("cargo")),
                    arguments: vec!["clippy".to_owned(), "--version".to_owned()],
                    stdout: ExactBytes::from_bytes(b"clippy 0.1.97\n"),
                    stderr: ExactBytes::from_bytes(b""),
                },
                environment: vec![
                    (OsString::from("CARGO_INCREMENTAL"), OsString::from("0")),
                    (
                        OsString::from("AUTOCAD_MCP_TEST_PROFILE"),
                        OsString::from("fixture"),
                    ),
                    (OsString::from("IGNORED_FIXTURE"), OsString::from("ignored")),
                ],
                platform: PlatformBinding {
                    operating_system: "fixture-os".to_owned(),
                    architecture: "fixture-arch".to_owned(),
                    family: "fixture-family".to_owned(),
                    pointer_width: 64,
                    endian: "little".to_owned(),
                    executable_suffix: String::new(),
                    dynamic_library_prefix: "lib".to_owned(),
                    dynamic_library_suffix: ".fixture".to_owned(),
                },
            }
        }

        fn inputs(&self) -> PrePushReceiptInputs {
            capture_with_runtime(
                &self.repository,
                "sha1",
                &"a".repeat(40),
                &"b".repeat(40),
                &[
                    "git [\"diff\",\"--check\"]".to_owned(),
                    "cargo [\"test\",\"--locked\"]".to_owned(),
                ],
                self.runtime(),
            )
            .expect("capture fixture inputs")
        }
    }

    #[test]
    fn recorded_context_round_trips_as_private_atomic_receipt() {
        let fixture = Fixture::new();
        let inputs = fixture.inputs();
        assert!(!pre_push_receipt_hit_when_allowed(
            &fixture.repository,
            &inputs,
            true
        ));

        let path = record_pre_push_receipt_when_allowed(&fixture.repository, &inputs, true)
            .expect("record receipt");
        assert!(pre_push_receipt_hit_when_allowed(
            &fixture.repository,
            &inputs,
            true
        ));
        assert_eq!(
            path.parent().unwrap(),
            fs::canonicalize(&fixture.repository)
                .unwrap()
                .join("target")
                .join("pre-push-receipts")
                .join(CACHE_COMPONENTS[2])
        );
        let entries = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, [path.file_name().unwrap()]);

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::symlink_metadata(path).unwrap().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn advisory_policy_requires_unix_and_rejects_disallowed_environments() {
        assert!(advisory_cache_allowed_for_platform(true, false));
        assert!(!advisory_cache_allowed_for_platform(true, true));
        assert!(!advisory_cache_allowed_for_platform(false, false));
        assert!(!advisory_cache_allowed_for_platform(false, true));
    }

    #[test]
    fn denied_policy_neither_reads_nor_records_a_receipt() {
        let fixture = Fixture::new();
        let inputs = fixture.inputs();
        assert!(!pre_push_receipt_hit_when_allowed(
            &fixture.repository,
            &inputs,
            false
        ));
        let error = record_pre_push_receipt_when_allowed(&fixture.repository, &inputs, false)
            .expect_err("denied policy must not record");
        assert!(error.contains("non-CI Unix host"));
        assert!(!fixture.repository.join("target").exists());
    }

    #[test]
    fn every_recorded_context_class_changes_the_receipt_key() {
        let fixture = Fixture::new();
        let baseline = fixture.inputs();
        let baseline_digest = input_digest(&baseline).unwrap();
        let changed_digest = |changed: PrePushReceiptInputs| {
            validate_inputs(&changed).unwrap();
            assert_ne!(input_digest(&changed).unwrap(), baseline_digest);
        };

        let mut changed = baseline.clone();
        changed.candidate.source_commit = "c".repeat(40);
        changed_digest(changed);

        let mut changed = baseline.clone();
        changed.rendered_commands.push("cargo [\"fmt\"]".to_owned());
        changed_digest(changed);

        let mut changed = baseline.clone();
        changed.cargo_lock.sha256 = "1".repeat(64);
        changed_digest(changed);

        let mut changed = baseline.clone();
        changed.rust_toolchain.sha256 = "2".repeat(64);
        changed_digest(changed);

        let mut changed = baseline.clone();
        changed.pre_push_hook.sha256 = "3".repeat(64);
        changed_digest(changed);

        let mut changed = baseline.clone();
        changed.current_executable.sha256 = "4".repeat(64);
        changed_digest(changed);

        let mut changed = baseline.clone();
        changed.cargo_version.stdout = ExactBytes::from_bytes(b"cargo changed\n");
        changed_digest(changed);

        let mut changed = baseline.clone();
        changed.rustc_version.stdout = ExactBytes::from_bytes(b"rustc changed\n");
        changed_digest(changed);

        let mut changed = baseline.clone();
        changed.git_version.stdout = ExactBytes::from_bytes(b"git changed\n");
        changed_digest(changed);

        let mut changed = baseline.clone();
        changed.rustfmt_version.stdout = ExactBytes::from_bytes(b"rustfmt changed\n");
        changed_digest(changed);

        let mut changed = baseline.clone();
        changed.clippy_version.stdout = ExactBytes::from_bytes(b"clippy changed\n");
        changed_digest(changed);

        let mut changed = baseline.clone();
        changed.environment[0].value_sha256 = "5".repeat(64);
        changed_digest(changed);

        let mut changed = baseline.clone();
        changed.platform.architecture = "changed-arch".to_owned();
        changed_digest(changed);

        let mut changed = baseline.clone();
        changed.cargo_configurations[0].contents.sha256 = "6".repeat(64);
        changed_digest(changed);
    }

    #[test]
    fn corrupt_unknown_or_missing_receipts_are_cache_misses() {
        let fixture = Fixture::new();
        let inputs = fixture.inputs();
        let path = record_pre_push_receipt_when_allowed(&fixture.repository, &inputs, true)
            .expect("record receipt");
        let original = fs::read(&path).unwrap();

        fs::write(&path, b"{not-json\n").unwrap();
        assert!(!pre_push_receipt_hit_when_allowed(
            &fixture.repository,
            &inputs,
            true
        ));

        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown_field".to_owned(), serde_json::Value::Bool(true));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(!pre_push_receipt_hit_when_allowed(
            &fixture.repository,
            &inputs,
            true
        ));

        fs::remove_file(path).unwrap();
        assert!(!pre_push_receipt_hit_when_allowed(
            &fixture.repository,
            &inputs,
            true
        ));
    }

    #[test]
    fn cargo_configuration_bytes_enter_the_recorded_context() {
        let fixture = Fixture::new();
        let before = fixture.inputs();
        fs::write(
            fixture.repository.join(".cargo").join("config.toml"),
            b"[build]\nincremental = true\n",
        )
        .unwrap();
        let after = fixture.inputs();
        assert_ne!(
            input_digest(&before).unwrap(),
            input_digest(&after).unwrap()
        );
        assert_ne!(before.cargo_configurations, after.cargo_configurations);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_receipt_or_cache_directory_is_never_followed() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let inputs = fixture.inputs();
        let path = record_pre_push_receipt_when_allowed(&fixture.repository, &inputs, true)
            .expect("record receipt");
        let detached = fixture.repository.join("detached-receipt");
        fs::rename(&path, &detached).unwrap();
        symlink(&detached, &path).unwrap();
        assert!(!pre_push_receipt_hit_when_allowed(
            &fixture.repository,
            &inputs,
            true
        ));

        fs::remove_file(&path).unwrap();
        let cache_parent = fixture.repository.join("target").join("pre-push-receipts");
        fs::remove_dir(cache_parent.join(CACHE_COMPONENTS[2])).unwrap();
        let external = fixture.repository.join("external-cache");
        fs::create_dir(&external).unwrap();
        symlink(&external, cache_parent.join(CACHE_COMPONENTS[2])).unwrap();
        assert!(!pre_push_receipt_hit_when_allowed(
            &fixture.repository,
            &inputs,
            true
        ));
        assert!(record_pre_push_receipt_when_allowed(&fixture.repository, &inputs, true).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_cargo_configuration_disables_receipts() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let config = fixture.repository.join(".cargo").join("config.toml");
        let detached = fixture.repository.join("detached-config.toml");
        fs::rename(&config, &detached).unwrap();
        symlink(&detached, &config).unwrap();
        let error = capture_with_runtime(
            &fixture.repository,
            "sha1",
            &"a".repeat(40),
            &"b".repeat(40),
            &["cargo [\"test\"]".to_owned()],
            fixture.runtime(),
        )
        .expect_err("symlinked config must disable receipt capture");
        assert!(error.contains("regular non-symlink file"));
    }

    #[test]
    fn every_ambient_environment_value_enters_the_recorded_context_as_a_digest() {
        let fixture = Fixture::new();
        let inputs = fixture.inputs();
        assert_eq!(inputs.environment.len(), 3);
        let name = encode_native_value(OsStr::new("IGNORED_FIXTURE"));
        let binding = inputs
            .environment
            .iter()
            .find(|variable| variable.name == name)
            .expect("all ambient variables must be represented");
        assert_eq!(binding.value_sha256, sha256_bytes(b"ignored"));
        assert_eq!(binding.value_bytes, b"ignored".len() as u64);
    }
}
