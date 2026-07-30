use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const RECEIPT_SCHEMA_VERSION: u32 = 1;
const RECEIPT_ARTIFACT_KIND: &str = "autocad-mcp-content-validation-receipt";
const RECEIPT_SCOPE: &str = "advisory_validation_cache_only";
const RECEIPT_OUTCOME: &str = "validation_passed";
const CACHE_COMPONENTS: [&str; 2] = ["local-ci-receipts", "v1"];
const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_TOOL_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_COMMAND_BYTES: usize = 64 * 1024;
const DISABLE_RECEIPTS_ENVIRONMENT: &str = "AUTOCAD_MCP_DISABLE_CONTENT_RECEIPTS";
const ENGINE_SOURCE: &[u8] = include_bytes!("content_receipt.rs");

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptInputs {
    schema_version: u32,
    target: String,
    input_sha256: String,
    command: String,
    engine_sha256: String,
    cargo_version: ExactToolOutput,
    rustc_version: ExactToolOutput,
    platform: PlatformBinding,
    environment: Vec<EnvironmentBinding>,
    cargo_configurations: Vec<ContentBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactToolOutput {
    program: String,
    arguments: Vec<String>,
    stdout_sha256: String,
    stdout_bytes: u64,
    stderr_sha256: String,
    stderr_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PlatformBinding {
    operating_system: String,
    architecture: String,
    family: String,
    pointer_width: u16,
    endian: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentBinding {
    name: String,
    value_sha256: String,
    value_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct ContentBinding {
    role: String,
    sha256: String,
    bytes: u64,
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
    inputs: ReceiptInputs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidationReceiptOutcome {
    pub input_sha256: Option<String>,
    pub receipt_key_sha256: Option<String>,
    pub reused: bool,
}

pub(crate) struct LocalCiLock {
    path: PathBuf,
}

impl Drop for LocalCiLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Run one validation target, reusing only an exact content/context receipt.
///
/// Receipt failures are cache misses. The validation itself remains
/// authoritative for this local operation, while the receipt never acquires
/// release, signing, native-host, or distribution authority.
pub(crate) fn validate_or_run<C, R>(
    repository: &Path,
    target: &str,
    command: &str,
    mut capture_input: C,
    mut run: R,
) -> Result<ValidationReceiptOutcome, String>
where
    C: FnMut() -> Result<String, String>,
    R: FnMut() -> Result<(), String>,
{
    require_target(target)?;
    require_command(command)?;

    let before_input = match capture_input() {
        Ok(input) => {
            require_sha256(&input, "content receipt target input")?;
            Some(input)
        }
        Err(error) => {
            eprintln!("content receipt unavailable for {target}; running validation: {error}");
            None
        }
    };
    let before_context = before_input.as_deref().and_then(|input| {
        match capture_context(repository, target, input, command) {
            Ok(context) => Some(context),
            Err(error) => {
                eprintln!(
                    "content receipt context unavailable for {target}; running validation: {error}"
                );
                None
            }
        }
    });

    if receipts_enabled() {
        if let Some(before) = before_context.as_ref() {
            if receipt_hit(repository, before) {
                let after_input = capture_input().map_err(|error| {
                    format!("{target} input could not be recaptured after a receipt hit: {error}")
                })?;
                require_sha256(&after_input, "recaptured content receipt target input")?;
                if after_input != before.input_sha256 {
                    return Err(format!(
                        "{target} input changed while its content receipt was being validated"
                    ));
                }
                let after = capture_context(repository, target, &after_input, command)?;
                if &after != before {
                    return Err(format!(
                        "{target} execution context changed while its content receipt was being validated"
                    ));
                }
                let receipt_key_sha256 = inputs_digest(before)?;
                eprintln!("reused content-scoped {target} receipt {receipt_key_sha256}");
                return Ok(ValidationReceiptOutcome {
                    input_sha256: Some(after_input),
                    receipt_key_sha256: Some(receipt_key_sha256),
                    reused: true,
                });
            }
        }
    }

    run()?;

    let Some(before_input) = before_input else {
        return Ok(ValidationReceiptOutcome {
            input_sha256: None,
            receipt_key_sha256: None,
            reused: false,
        });
    };
    let after_input = capture_input().map_err(|error| {
        format!("{target} input could not be recaptured after successful validation: {error}")
    })?;
    require_sha256(&after_input, "recaptured content receipt target input")?;
    if after_input != before_input {
        return Err(format!(
            "{target} input changed during successful validation; no result was recorded"
        ));
    }

    let Some(before_context) = before_context else {
        return Ok(ValidationReceiptOutcome {
            input_sha256: Some(after_input),
            receipt_key_sha256: None,
            reused: false,
        });
    };
    let after_context = match capture_context(repository, target, &after_input, command) {
        Ok(context) => context,
        Err(error) => {
            eprintln!(
                "content receipt was not recorded for {target} because its context could not be recaptured: {error}"
            );
            return Ok(ValidationReceiptOutcome {
                input_sha256: Some(after_input),
                receipt_key_sha256: None,
                reused: false,
            });
        }
    };
    if after_context != before_context {
        eprintln!(
            "content receipt was not recorded for {target} because its execution context changed"
        );
        return Ok(ValidationReceiptOutcome {
            input_sha256: Some(after_input),
            receipt_key_sha256: None,
            reused: false,
        });
    }

    let receipt_key_sha256 = inputs_digest(&after_context)?;
    if receipts_enabled() {
        match record_receipt(repository, &after_context) {
            Ok(path) => eprintln!(
                "recorded content-scoped {target} receipt {}",
                path.display()
            ),
            Err(error) => {
                eprintln!("content receipt was not recorded for {target}: {error}")
            }
        }
    }
    Ok(ValidationReceiptOutcome {
        input_sha256: Some(after_input),
        receipt_key_sha256: Some(receipt_key_sha256),
        reused: false,
    })
}

pub(crate) fn acquire_local_ci_lock(repository: &Path) -> Result<LocalCiLock, String> {
    let cache = cache_root(repository, true)?;
    let path = cache.join("source-quality.lock");
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
                "another local source-quality operation owns {}; if no operation is active, remove this stale lock explicitly",
                path.display()
            )
        } else {
            format!("create local source-quality lock {}: {error}", path.display())
        }
    })?;
    writeln!(file, "pid={}", std::process::id())
        .map_err(|error| format!("write local source-quality lock: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync local source-quality lock: {error}"))?;
    Ok(LocalCiLock { path })
}

pub(crate) fn tracked_paths_sha256(
    repository: &Path,
    selectors: &[&str],
) -> Result<String, String> {
    if selectors.is_empty() {
        return Err("tracked input selectors must not be empty".to_owned());
    }
    for selector in selectors {
        let path = Path::new(selector);
        if selector.is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        {
            return Err(format!("unsafe tracked input selector {selector:?}"));
        }
    }

    let mut command = isolated_git_command(repository);
    command.args(["ls-files", "--stage", "-z", "--"]);
    command.args(selectors);
    let output = command
        .output()
        .map_err(|error| format!("enumerate tracked receipt inputs: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "enumerate tracked receipt inputs failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let mut entries = Vec::new();
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        let separator = raw
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| "git ls-files emitted an invalid stage record".to_owned())?;
        let index = std::str::from_utf8(&raw[..separator])
            .map_err(|error| format!("git index metadata is not UTF-8: {error}"))?;
        let relative = std::str::from_utf8(&raw[separator + 1..])
            .map_err(|error| format!("tracked receipt path is not UTF-8: {error}"))?;
        let path = Path::new(relative);
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        {
            return Err(format!("git returned an unsafe tracked path {relative:?}"));
        }
        let bytes = read_regular_file(&repository.join(path), "tracked receipt input")?;
        entries.push((relative.to_owned(), index.to_owned(), bytes));
    }
    if entries.is_empty() {
        return Err("tracked input selectors resolved no files".to_owned());
    }
    if !entries.windows(2).all(|pair| pair[0].0 < pair[1].0) {
        return Err("tracked receipt inputs are not sorted and unique".to_owned());
    }

    let mut hasher = Sha256::new();
    hash_framed(
        &mut hasher,
        b"domain",
        b"autocad-mcp-tracked-content-closure-v1",
    );
    for selector in selectors {
        hash_framed(&mut hasher, b"selector", selector.as_bytes());
    }
    for (path, index, bytes) in entries {
        hash_framed(&mut hasher, b"path", path.as_bytes());
        hash_framed(&mut hasher, b"index", index.as_bytes());
        hash_framed(&mut hasher, b"contents", &bytes);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn capture_context(
    repository: &Path,
    target: &str,
    input_sha256: &str,
    command: &str,
) -> Result<ReceiptInputs, String> {
    let mut environment = env::vars_os()
        .filter_map(|(name, value)| {
            let name = name.into_string().ok()?;
            relevant_environment_name(&name).then(|| {
                let bytes = native_bytes(&value);
                EnvironmentBinding {
                    name,
                    value_sha256: sha256(&bytes),
                    value_bytes: bytes.len() as u64,
                }
            })
        })
        .collect::<Vec<_>>();
    environment.sort();
    if !environment
        .windows(2)
        .all(|pair| pair[0].name < pair[1].name)
    {
        return Err("content receipt environment names are not unique".to_owned());
    }

    Ok(ReceiptInputs {
        schema_version: RECEIPT_SCHEMA_VERSION,
        target: target.to_owned(),
        input_sha256: input_sha256.to_owned(),
        command: command.to_owned(),
        engine_sha256: sha256(ENGINE_SOURCE),
        cargo_version: configured_tool_output("CARGO", "cargo", &["--version", "--verbose"])?,
        rustc_version: configured_tool_output("RUSTC", "rustc", &["--version", "--verbose"])?,
        platform: PlatformBinding {
            operating_system: env::consts::OS.to_owned(),
            architecture: env::consts::ARCH.to_owned(),
            family: env::consts::FAMILY.to_owned(),
            pointer_width: usize::BITS as u16,
            endian: if cfg!(target_endian = "little") {
                "little"
            } else {
                "big"
            }
            .to_owned(),
        },
        environment,
        cargo_configurations: cargo_configuration_bindings(repository)?,
    })
}

fn relevant_environment_name(name: &str) -> bool {
    matches!(
        name,
        "AR" | "CC"
            | "CFLAGS"
            | "CXX"
            | "CXXFLAGS"
            | "CARGO"
            | "CARGO_BUILD_JOBS"
            | "CARGO_BUILD_RUSTC"
            | "CARGO_BUILD_RUSTFLAGS"
            | "CARGO_BUILD_TARGET"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "CARGO_HOME"
            | "CARGO_INCREMENTAL"
            | "CARGO_NET_OFFLINE"
            | "CARGO_TARGET_DIR"
            | "HOST"
            | "ImageOS"
            | "ImageVersion"
            | "LINK"
            | "PATH"
            | "RUNNER_ARCH"
            | "RUNNER_OS"
            | "RUSTC"
            | "RUSTC_WRAPPER"
            | "RUSTDOC"
            | "RUSTDOCFLAGS"
            | "RUSTFLAGS"
            | "TARGET"
    ) || name.starts_with("CARGO_PROFILE_")
        || (name.starts_with("CARGO_TARGET_") && name.ends_with("_LINKER"))
}

fn cargo_configuration_bindings(repository: &Path) -> Result<Vec<ContentBinding>, String> {
    let repository = fs::canonicalize(repository)
        .map_err(|error| format!("canonicalize content receipt repository: {error}"))?;
    let mut candidates = Vec::new();
    for ancestor in repository.ancestors() {
        for name in ["config.toml", "config"] {
            candidates.push(ancestor.join(".cargo").join(name));
        }
    }
    if let Some(cargo_home) = env::var_os("CARGO_HOME") {
        for name in ["config.toml", "config"] {
            candidates.push(PathBuf::from(&cargo_home).join(name));
        }
    } else if let Some(home) = env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }) {
        for name in ["config.toml", "config"] {
            candidates.push(PathBuf::from(&home).join(".cargo").join(name));
        }
    }

    let mut bindings = Vec::new();
    let mut seen = BTreeSet::new();
    for path in candidates {
        if !seen.insert(path.clone()) {
            continue;
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err(format!(
                        "Cargo configuration is not a regular file: {}",
                        path.display()
                    ));
                }
                let bytes = fs::read(&path).map_err(|error| {
                    format!("read Cargo configuration {}: {error}", path.display())
                })?;
                let path_bytes = native_bytes(&path.as_os_str().to_os_string());
                bindings.push(ContentBinding {
                    role: format!("cargo-config-{}", sha256(&path_bytes)),
                    sha256: sha256(&bytes),
                    bytes: bytes.len() as u64,
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
    bindings.sort();
    Ok(bindings)
}

fn configured_tool_output(
    environment_name: &str,
    fallback: &str,
    arguments: &[&str],
) -> Result<ExactToolOutput, String> {
    let program = env::var_os(environment_name).unwrap_or_else(|| OsString::from(fallback));
    let rendered_program = program
        .to_str()
        .ok_or_else(|| format!("{environment_name} selects a tool path that is not valid UTF-8"))?;
    let output = Command::new(&program)
        .args(arguments)
        .output()
        .map_err(|error| format!("launch {rendered_program} {}: {error}", arguments.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "{rendered_program} {} failed with {}",
            arguments.join(" "),
            output.status
        ));
    }
    if output.stdout.len() > MAX_TOOL_OUTPUT_BYTES || output.stderr.len() > MAX_TOOL_OUTPUT_BYTES {
        return Err(format!(
            "{rendered_program} version output exceeds its closed size limit"
        ));
    }
    Ok(ExactToolOutput {
        program: rendered_program.to_owned(),
        arguments: arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect(),
        stdout_sha256: sha256(&output.stdout),
        stdout_bytes: output.stdout.len() as u64,
        stderr_sha256: sha256(&output.stderr),
        stderr_bytes: output.stderr.len() as u64,
    })
}

fn receipt_hit(repository: &Path, inputs: &ReceiptInputs) -> bool {
    lookup_receipt(repository, inputs).unwrap_or(false)
}

fn lookup_receipt(repository: &Path, inputs: &ReceiptInputs) -> Result<bool, String> {
    let root = cache_root(repository, false)?;
    let path = receipt_path(&root, inputs)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => {
            return Err(format!(
                "content validation receipt is not a regular file: {}",
                path.display()
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!(
                "inspect content validation receipt {}: {error}",
                path.display()
            ))
        }
    }
    let bytes = read_regular_file(&path, "content validation receipt")?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Ok(false);
    }
    let receipt: StoredReceipt = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse content validation receipt: {error}"))?;
    validate_stored_receipt(&receipt)?;
    let expected = inputs_digest(inputs)?;
    Ok(receipt.input_sha256 == expected && receipt.inputs == *inputs)
}

fn record_receipt(repository: &Path, inputs: &ReceiptInputs) -> Result<PathBuf, String> {
    validate_inputs(inputs)?;
    let root = cache_root(repository, true)?;
    let target = root.join(&inputs.target);
    ensure_private_directory(&target)?;
    let final_path = receipt_path(&root, inputs)?;
    if lookup_receipt(repository, inputs).unwrap_or(false) {
        return Ok(final_path);
    }
    if fs::symlink_metadata(&final_path).is_ok() {
        return Err(format!(
            "invalid content receipt already occupies {}",
            final_path.display()
        ));
    }

    let digest = inputs_digest(inputs)?;
    let receipt = StoredReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION,
        artifact_kind: RECEIPT_ARTIFACT_KIND.to_owned(),
        scope: RECEIPT_SCOPE.to_owned(),
        release_authority: false,
        outcome: RECEIPT_OUTCOME.to_owned(),
        input_sha256: digest,
        inputs: inputs.clone(),
    };
    let mut bytes = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| format!("serialize content validation receipt: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err("content validation receipt exceeds its closed size limit".to_owned());
    }

    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = target.join(format!(
        ".receipt-{}-{}-{sequence}.tmp",
        std::process::id(),
        receipt.input_sha256
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("create temporary content receipt: {error}"))?;
    file.write_all(&bytes)
        .map_err(|error| format!("write temporary content receipt: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync temporary content receipt: {error}"))?;
    drop(file);
    match fs::rename(&temporary, &final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            if !lookup_receipt(repository, inputs).unwrap_or(false) {
                return Err(
                    "a competing invalid content receipt occupied the expected key".to_owned(),
                );
            }
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(format!(
                "publish content validation receipt {}: {error}",
                final_path.display()
            ));
        }
    }
    if !lookup_receipt(repository, inputs).unwrap_or(false) {
        return Err("published content validation receipt did not verify".to_owned());
    }
    Ok(final_path)
}

fn validate_stored_receipt(receipt: &StoredReceipt) -> Result<(), String> {
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION
        || receipt.artifact_kind != RECEIPT_ARTIFACT_KIND
        || receipt.scope != RECEIPT_SCOPE
        || receipt.release_authority
        || receipt.outcome != RECEIPT_OUTCOME
    {
        return Err("content receipt has unsupported authority or schema".to_owned());
    }
    validate_inputs(&receipt.inputs)?;
    require_sha256(&receipt.input_sha256, "content receipt input")?;
    if inputs_digest(&receipt.inputs)? != receipt.input_sha256 {
        return Err("content receipt input digest is inconsistent".to_owned());
    }
    Ok(())
}

fn validate_inputs(inputs: &ReceiptInputs) -> Result<(), String> {
    if inputs.schema_version != RECEIPT_SCHEMA_VERSION {
        return Err("unsupported content receipt input schema".to_owned());
    }
    require_target(&inputs.target)?;
    require_sha256(&inputs.input_sha256, "content receipt target input")?;
    require_command(&inputs.command)?;
    require_sha256(&inputs.engine_sha256, "content receipt engine")?;
    if !inputs
        .environment
        .windows(2)
        .all(|pair| pair[0].name < pair[1].name)
    {
        return Err("content receipt environment must be sorted and unique".to_owned());
    }
    if !inputs
        .cargo_configurations
        .windows(2)
        .all(|pair| pair[0] < pair[1])
    {
        return Err("Cargo configuration bindings must be sorted and unique".to_owned());
    }
    Ok(())
}

fn receipt_path(root: &Path, inputs: &ReceiptInputs) -> Result<PathBuf, String> {
    Ok(root
        .join(&inputs.target)
        .join(format!("{}.json", inputs_digest(inputs)?)))
}

fn inputs_digest(inputs: &ReceiptInputs) -> Result<String, String> {
    validate_inputs(inputs)?;
    let bytes = serde_json::to_vec(inputs)
        .map_err(|error| format!("serialize content receipt inputs: {error}"))?;
    let mut hasher = Sha256::new();
    hash_framed(
        &mut hasher,
        b"domain",
        b"autocad-mcp-content-validation-receipt-input-v1",
    );
    hash_framed(&mut hasher, b"inputs", &bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn cache_root(repository: &Path, create: bool) -> Result<PathBuf, String> {
    let target = cargo_target_directory(repository)?;
    if create {
        ensure_private_directory(&target)?;
    }
    let mut current = target;
    for component in CACHE_COMPONENTS {
        current.push(component);
        if create {
            ensure_private_directory(&current)?;
        } else {
            let metadata = fs::symlink_metadata(&current)
                .map_err(|error| format!("inspect content receipt cache: {error}"))?;
            if !metadata.file_type().is_dir() {
                return Err(format!(
                    "content receipt cache component is not a real directory: {}",
                    current.display()
                ));
            }
        }
    }
    Ok(current)
}

fn cargo_target_directory(repository: &Path) -> Result<PathBuf, String> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
        ])
        .current_dir(repository)
        .output()
        .map_err(|error| format!("discover Cargo target directory: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "discover Cargo target directory failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse Cargo target-directory metadata: {error}"))?;
    let target = metadata["target_directory"]
        .as_str()
        .ok_or_else(|| "Cargo metadata has no UTF-8 target_directory".to_owned())?;
    let target = PathBuf::from(target);
    if !target.is_absolute() {
        return Err("Cargo target_directory is not absolute".to_owned());
    }
    Ok(target)
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() {
                return Err(format!(
                    "content receipt cache path is not a real directory: {}",
                    path.display()
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| {
                format!(
                    "content receipt directory has no parent: {}",
                    path.display()
                )
            })?;
            if parent != path && fs::symlink_metadata(parent).is_err() {
                ensure_private_directory(parent)?;
            }
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(path).map_err(|inspect| {
                        format!("inspect concurrently created content receipt directory: {inspect}")
                    })?;
                    if !metadata.file_type().is_dir() {
                        return Err(format!(
                            "concurrent content receipt path is not a directory: {}",
                            path.display()
                        ));
                    }
                }
                Err(error) => {
                    return Err(format!(
                        "create content receipt directory {}: {error}",
                        path.display()
                    ))
                }
            }
        }
        Err(error) => {
            return Err(format!(
                "inspect content receipt directory {}: {error}",
                path.display()
            ))
        }
    }
    Ok(())
}

fn read_regular_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{label} is not a regular file: {}", path.display()));
    }
    if metadata.len() > MAX_RECEIPT_BYTES && label == "content validation receipt" {
        return Err("content validation receipt exceeds its closed size limit".to_owned());
    }
    let mut file =
        File::open(path).map_err(|error| format!("open {label} {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read {label} {}: {error}", path.display()))?;
    Ok(bytes)
}

fn isolated_git_command(repository: &Path) -> Command {
    #[cfg(windows)]
    const NULL_DEVICE: &str = "NUL";
    #[cfg(not(windows))]
    const NULL_DEVICE: &str = "/dev/null";

    let inherited_environment = [
        ("PATH", env::var_os("PATH")),
        ("SystemRoot", env::var_os("SystemRoot")),
        ("WINDIR", env::var_os("WINDIR")),
        ("TMPDIR", env::var_os("TMPDIR")),
        ("TMP", env::var_os("TMP")),
        ("TEMP", env::var_os("TEMP")),
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
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

#[cfg(unix)]
fn native_bytes(value: &OsString) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn native_bytes(value: &OsString) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

fn receipts_enabled() -> bool {
    env::var_os(DISABLE_RECEIPTS_ENVIRONMENT).is_none()
}

fn require_target(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        Err(format!("invalid content receipt target {value:?}"))
    } else {
        Ok(())
    }
}

fn require_command(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_COMMAND_BYTES || value.chars().any(char::is_control) {
        Err("content receipt command is empty, oversized, or control-bearing".to_owned())
    } else {
        Ok(())
    }
}

fn require_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{label} must be 64 lowercase hexadecimal digits"))
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hash_framed(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn receipt_repository() -> tempfile::TempDir {
        let repository = tempfile::tempdir().unwrap();
        fs::create_dir(repository.path().join("src")).unwrap();
        fs::write(
            repository.path().join("Cargo.toml"),
            "[package]\nname = \"receipt-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(repository.path().join("src/lib.rs"), "pub fn value() {}\n").unwrap();
        repository
    }

    fn synthetic_inputs(target: &str, input: &str) -> ReceiptInputs {
        ReceiptInputs {
            schema_version: RECEIPT_SCHEMA_VERSION,
            target: target.to_owned(),
            input_sha256: input.to_owned(),
            command: "cargo test --locked -p example".to_owned(),
            engine_sha256: sha256(ENGINE_SOURCE),
            cargo_version: ExactToolOutput {
                program: "cargo".to_owned(),
                arguments: vec!["--version".to_owned(), "--verbose".to_owned()],
                stdout_sha256: sha256(b"cargo fixture"),
                stdout_bytes: 13,
                stderr_sha256: sha256(b""),
                stderr_bytes: 0,
            },
            rustc_version: ExactToolOutput {
                program: "rustc".to_owned(),
                arguments: vec!["--version".to_owned(), "--verbose".to_owned()],
                stdout_sha256: sha256(b"rustc fixture"),
                stdout_bytes: 13,
                stderr_sha256: sha256(b""),
                stderr_bytes: 0,
            },
            platform: PlatformBinding {
                operating_system: "fixture".to_owned(),
                architecture: "fixture".to_owned(),
                family: "fixture".to_owned(),
                pointer_width: 64,
                endian: "little".to_owned(),
            },
            environment: Vec::new(),
            cargo_configurations: Vec::new(),
        }
    }

    #[test]
    fn every_content_or_context_change_changes_the_receipt_key() {
        let baseline = synthetic_inputs("distribution-evidence", &"1".repeat(64));
        let baseline_key = inputs_digest(&baseline).unwrap();
        let mut changed = baseline.clone();
        changed.input_sha256 = "2".repeat(64);
        assert_ne!(inputs_digest(&changed).unwrap(), baseline_key);
        let mut changed = baseline.clone();
        changed.command.push_str(" --all-targets");
        assert_ne!(inputs_digest(&changed).unwrap(), baseline_key);
        let mut changed = baseline.clone();
        changed.platform.operating_system = "other".to_owned();
        assert_ne!(inputs_digest(&changed).unwrap(), baseline_key);
        let mut changed = baseline;
        changed.environment.push(EnvironmentBinding {
            name: "RUSTFLAGS".to_owned(),
            value_sha256: sha256(b"-Ctarget-cpu=x"),
            value_bytes: 14,
        });
        assert_ne!(inputs_digest(&changed).unwrap(), baseline_key);
    }

    #[test]
    fn stored_receipt_is_strict_and_non_authoritative() {
        let inputs = synthetic_inputs("distribution-evidence", &"1".repeat(64));
        let receipt = StoredReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION,
            artifact_kind: RECEIPT_ARTIFACT_KIND.to_owned(),
            scope: RECEIPT_SCOPE.to_owned(),
            release_authority: false,
            outcome: RECEIPT_OUTCOME.to_owned(),
            input_sha256: inputs_digest(&inputs).unwrap(),
            inputs,
        };
        validate_stored_receipt(&receipt).unwrap();
        let mut elevated = receipt;
        elevated.release_authority = true;
        assert!(validate_stored_receipt(&elevated).is_err());
    }

    #[test]
    fn target_and_command_shapes_fail_closed() {
        for target in ["", "../escape", "Uppercase", "contains.dot"] {
            assert!(require_target(target).is_err());
        }
        assert!(require_target("windows-native-semantic").is_ok());
        assert!(require_command("").is_err());
        assert!(require_command("cargo test\nnext").is_err());
    }

    #[test]
    fn successful_validation_is_reused_only_for_the_same_content() {
        let repository = receipt_repository();
        let calls = Cell::new(0);
        let first_input = "1".repeat(64);
        let first = validate_or_run(
            repository.path(),
            "fixture",
            "cargo test --locked",
            || Ok(first_input.clone()),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert!(!first.reused);
        assert_eq!(calls.get(), 1);

        let second = validate_or_run(
            repository.path(),
            "fixture",
            "cargo test --locked",
            || Ok(first_input.clone()),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert!(second.reused);
        assert_eq!(calls.get(), 1);

        let changed_input = "2".repeat(64);
        let changed = validate_or_run(
            repository.path(),
            "fixture",
            "cargo test --locked",
            || Ok(changed_input.clone()),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert!(!changed.reused);
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn failed_validation_never_creates_a_reusable_receipt() {
        let repository = receipt_repository();
        let calls = Cell::new(0);
        let input = "1".repeat(64);
        let error = validate_or_run(
            repository.path(),
            "fixture",
            "cargo test --locked",
            || Ok(input.clone()),
            || {
                calls.set(calls.get() + 1);
                Err("fixture validation failed".to_owned())
            },
        )
        .unwrap_err();
        assert_eq!(error, "fixture validation failed");

        let passed = validate_or_run(
            repository.path(),
            "fixture",
            "cargo test --locked",
            || Ok(input.clone()),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert!(!passed.reused);
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn malformed_receipt_is_a_cache_miss_and_never_overrides_validation() {
        let repository = receipt_repository();
        let input = "1".repeat(64);
        let context =
            capture_context(repository.path(), "fixture", &input, "cargo test --locked").unwrap();
        let root = cache_root(repository.path(), true).unwrap();
        let target = root.join("fixture");
        ensure_private_directory(&target).unwrap();
        let path = receipt_path(&root, &context).unwrap();
        fs::write(&path, b"{\"release_authority\":true}\n").unwrap();

        let calls = Cell::new(0);
        let outcome = validate_or_run(
            repository.path(),
            "fixture",
            "cargo test --locked",
            || Ok(input.clone()),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert!(!outcome.reused);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn local_ci_lock_is_exclusive_and_released_on_drop() {
        let repository = receipt_repository();
        let first = acquire_local_ci_lock(repository.path()).unwrap();
        assert!(acquire_local_ci_lock(repository.path()).is_err());
        drop(first);
        acquire_local_ci_lock(repository.path()).unwrap();
    }
}
