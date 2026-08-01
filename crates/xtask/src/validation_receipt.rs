use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const RECEIPT_SCHEMA_VERSION: u32 = 1;
const REQUEST_SCHEMA_VERSION: u32 = 1;
const SUBJECT_SCHEMA_VERSION: u32 = 1;
const PLAN_SCHEMA_VERSION: u32 = 1;
const CONTEXT_SCHEMA_VERSION: u32 = 1;
const RECEIPT_ARTIFACT_KIND: &str = "autocad-mcp-advisory-validation-receipt";
const RECEIPT_SCOPE: &str = "advisory_local_validation_only";
const RECEIPT_OUTCOME: &str = "validation_passed";
const CACHE_COMPONENTS: [&str; 3] = ["autocad-mcp", "validation-receipts", "v1"];
const SUBJECTS_COMPONENT: &str = "subjects";
const LOCKS_COMPONENT: &str = "locks";
const MAX_RECEIPT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOOL_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_COMMAND_BYTES: usize = 64 * 1024;
const MAX_PLAN_STEPS: usize = 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 4096;
const MAX_CARGO_CONFIGURATIONS: usize = 128;
const MAX_RECEIPTS_PER_CONTEXT: usize = 1024;
const DISABLE_RECEIPTS_ENVIRONMENT: &str = "AUTOCAD_MCP_DISABLE_VALIDATION_RECEIPTS";
const LEGACY_DISABLE_ENVIRONMENTS: [&str; 2] = [
    "AUTOCAD_MCP_DISABLE_CONTENT_RECEIPTS",
    "AUTOCAD_MCP_DISABLE_PRE_PUSH_RECEIPT",
];
const RECEIPT_ENGINE_SOURCE: &[u8] = include_bytes!("validation_receipt.rs");
const ORCHESTRATOR_SOURCE: &[u8] = include_bytes!("main.rs");

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ValidationSubject {
    schema_version: u32,
    kind: String,
    namespace: String,
    git_object_format: Option<String>,
    source_commit: Option<String>,
    source_tree_oid: Option<String>,
    content_sha256: Option<String>,
}

impl ValidationSubject {
    pub(crate) fn git_commit_tree(
        namespace: &str,
        git_object_format: &str,
        source_commit: &str,
        source_tree_oid: &str,
    ) -> Result<Self, String> {
        let subject = Self {
            schema_version: SUBJECT_SCHEMA_VERSION,
            kind: "git_commit_tree".to_owned(),
            namespace: namespace.to_owned(),
            git_object_format: Some(git_object_format.to_owned()),
            source_commit: Some(source_commit.to_owned()),
            source_tree_oid: Some(source_tree_oid.to_owned()),
            content_sha256: None,
        };
        validate_subject(&subject)?;
        Ok(subject)
    }

    pub(crate) fn content_closure(namespace: &str, content_sha256: &str) -> Result<Self, String> {
        let subject = Self {
            schema_version: SUBJECT_SCHEMA_VERSION,
            kind: "content_closure".to_owned(),
            namespace: namespace.to_owned(),
            git_object_format: None,
            source_commit: None,
            source_tree_oid: None,
            content_sha256: Some(content_sha256.to_owned()),
        };
        validate_subject(&subject)?;
        Ok(subject)
    }

    pub(crate) fn content_sha256(&self) -> Option<&str> {
        self.content_sha256.as_deref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ValidationStep {
    id: String,
    command: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ValidationPlan {
    schema_version: u32,
    engine_sha256: String,
    steps: Vec<ValidationStep>,
}

impl ValidationPlan {
    pub(crate) fn new(steps: Vec<(String, String)>) -> Result<Self, String> {
        let mut steps = steps
            .into_iter()
            .map(|(id, command)| ValidationStep { id, command })
            .collect::<Vec<_>>();
        steps.sort();
        let plan = Self {
            schema_version: PLAN_SCHEMA_VERSION,
            engine_sha256: receipt_engine_sha256(),
            steps,
        };
        validate_plan(&plan)?;
        Ok(plan)
    }

    pub(crate) fn with_step(&self, id: &str, command: &str) -> Result<Self, String> {
        let mut steps = self
            .steps
            .iter()
            .map(|step| (step.id.clone(), step.command.clone()))
            .collect::<Vec<_>>();
        steps.push((id.to_owned(), command.to_owned()));
        Self::new(steps)
    }

    pub(crate) fn satisfies(&self, required: &Self) -> bool {
        plan_satisfies(self, required)
    }

    #[cfg(test)]
    fn step_count(&self) -> usize {
        self.steps.len()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapturedValidation {
    schema_version: u32,
    subject: ValidationSubject,
    plan: ValidationPlan,
    context: ValidationContext,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ValidationContext {
    schema_version: u32,
    repository_storage_sha256: String,
    cargo_version: ExactToolOutput,
    rustc_version: ExactToolOutput,
    git_version: ExactToolOutput,
    rustfmt_version: ExactToolOutput,
    clippy_version: ExactToolOutput,
    platform: PlatformBinding,
    environment: Vec<EnvironmentBinding>,
    cargo_configurations: Vec<ContentBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactToolOutput {
    tool: String,
    program: NativeValue,
    arguments: Vec<String>,
    stdout_sha256: String,
    stdout_bytes: u64,
    stderr_sha256: String,
    stderr_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeValue {
    encoding: String,
    content_hex: String,
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
    name: NativeValue,
    value_sha256: String,
    value_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct ContentBinding {
    role_sha256: String,
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
    distribution_authority: bool,
    signing_authority: bool,
    native_host_authority: bool,
    outcome: String,
    request_sha256: String,
    request: CapturedValidation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidationReceiptOutcome {
    pub subject: Option<ValidationSubject>,
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

/// Run one validation plan, reusing only an equal subject/context receipt whose
/// completed plan contains every requested step.
///
/// Receipts are advisory cache entries. They never acquire release,
/// distribution, signing, or native-host authority.
pub(crate) fn validate_or_run<C, R>(
    repository: &Path,
    plan: &ValidationPlan,
    capture_subject: C,
    run: R,
) -> Result<ValidationReceiptOutcome, String>
where
    C: FnMut() -> Result<ValidationSubject, String>,
    R: FnMut() -> Result<(), String>,
{
    validate_or_run_with_cache(
        repository,
        None,
        receipts_enabled(),
        plan,
        capture_subject,
        run,
    )
}

fn validate_or_run_with_cache<C, R>(
    repository: &Path,
    cache_override: Option<&Path>,
    receipt_cache_enabled: bool,
    plan: &ValidationPlan,
    mut capture_subject: C,
    mut run: R,
) -> Result<ValidationReceiptOutcome, String>
where
    C: FnMut() -> Result<ValidationSubject, String>,
    R: FnMut() -> Result<(), String>,
{
    validate_plan(plan)?;
    let before_subject = match capture_subject() {
        Ok(subject) => {
            validate_subject(&subject)?;
            Some(subject)
        }
        Err(error) => {
            eprintln!("validation receipt subject unavailable; running validation: {error}");
            None
        }
    };
    let before = before_subject.as_ref().and_then(|subject| {
        match capture_validation_with_cache(
            repository,
            cache_override,
            subject.clone(),
            plan.clone(),
        ) {
            Ok(captured) => Some(captured),
            Err(error) => {
                eprintln!("validation receipt context unavailable; running validation: {error}");
                None
            }
        }
    });

    if receipt_cache_enabled {
        if let Some(before) = before.as_ref() {
            if receipt_hit_with_cache(repository, cache_override, before) {
                let after_subject = capture_subject().map_err(|error| {
                    format!(
                        "validation subject could not be recaptured after a receipt hit: {error}"
                    )
                })?;
                if after_subject != before.subject {
                    return Err(
                        "validation subject changed while its receipt was being checked".to_owned(),
                    );
                }
                let after = capture_validation_with_cache(
                    repository,
                    cache_override,
                    after_subject,
                    plan.clone(),
                )?;
                if &after != before {
                    return Err(
                        "validation execution context changed while its receipt was being checked"
                            .to_owned(),
                    );
                }
                let receipt_key_sha256 = request_digest(before)?;
                eprintln!(
                    "reused advisory validation receipt {receipt_key_sha256} for {}",
                    before.subject.namespace
                );
                return Ok(ValidationReceiptOutcome {
                    subject: Some(after.subject),
                    receipt_key_sha256: Some(receipt_key_sha256),
                    reused: true,
                });
            }
        }
    }

    run()?;

    let Some(before_subject) = before_subject else {
        return Ok(ValidationReceiptOutcome {
            subject: None,
            receipt_key_sha256: None,
            reused: false,
        });
    };
    let after_subject = capture_subject().map_err(|error| {
        format!("validation subject could not be recaptured after successful validation: {error}")
    })?;
    if after_subject != before_subject {
        return Err(
            "validation subject changed during successful validation; no result was recorded"
                .to_owned(),
        );
    }
    let Some(before) = before else {
        return Ok(ValidationReceiptOutcome {
            subject: Some(after_subject),
            receipt_key_sha256: None,
            reused: false,
        });
    };
    let after = match capture_validation_with_cache(
        repository,
        cache_override,
        after_subject.clone(),
        plan.clone(),
    ) {
        Ok(captured) => captured,
        Err(error) => {
            eprintln!(
                "validation receipt was not recorded because its context could not be recaptured: {error}"
            );
            return Ok(ValidationReceiptOutcome {
                subject: Some(after_subject),
                receipt_key_sha256: None,
                reused: false,
            });
        }
    };
    if after != before {
        eprintln!("validation receipt was not recorded because its execution context changed");
        return Ok(ValidationReceiptOutcome {
            subject: Some(after_subject),
            receipt_key_sha256: None,
            reused: false,
        });
    }

    let receipt_key_sha256 = request_digest(&after)?;
    if receipt_cache_enabled {
        match record_receipt_with_cache(repository, cache_override, &after) {
            Ok(path) => eprintln!("recorded advisory validation receipt {}", path.display()),
            Err(error) => eprintln!("validation receipt was not recorded: {error}"),
        }
    }
    Ok(ValidationReceiptOutcome {
        subject: Some(after_subject),
        receipt_key_sha256: Some(receipt_key_sha256),
        reused: false,
    })
}

pub(crate) fn capture_validation(
    repository: &Path,
    subject: ValidationSubject,
    plan: ValidationPlan,
) -> Result<CapturedValidation, String> {
    capture_validation_with_cache(repository, None, subject, plan)
}

fn capture_validation_with_cache(
    repository: &Path,
    cache_override: Option<&Path>,
    subject: ValidationSubject,
    plan: ValidationPlan,
) -> Result<CapturedValidation, String> {
    validate_subject(&subject)?;
    validate_plan(&plan)?;
    let captured = CapturedValidation {
        schema_version: REQUEST_SCHEMA_VERSION,
        subject,
        plan,
        context: capture_context(repository, cache_override)?,
    };
    validate_captured_validation(&captured)?;
    request_digest(&captured)?;
    Ok(captured)
}

pub(crate) fn receipt_hit(repository: &Path, expected: &CapturedValidation) -> bool {
    receipts_enabled() && receipt_hit_with_cache(repository, None, expected)
}

fn receipt_hit_with_cache(
    repository: &Path,
    cache_override: Option<&Path>,
    expected: &CapturedValidation,
) -> bool {
    lookup_receipt(repository, cache_override, expected).unwrap_or(false)
}

pub(crate) fn record_receipt(
    repository: &Path,
    request: &CapturedValidation,
) -> Result<PathBuf, String> {
    if !receipts_enabled() {
        return Err(format!(
            "advisory validation receipts are disabled by {DISABLE_RECEIPTS_ENVIRONMENT}"
        ));
    }
    record_receipt_with_cache(repository, None, request)
}

fn record_receipt_with_cache(
    repository: &Path,
    cache_override: Option<&Path>,
    request: &CapturedValidation,
) -> Result<PathBuf, String> {
    validate_captured_validation(request)?;
    let request_sha256 = request_digest(request)?;
    let root = cache_root(repository, cache_override, true)?;
    let subject_directory = root
        .join(SUBJECTS_COMPONENT)
        .join(subject_digest(&request.subject)?);
    ensure_private_directory_tree(&root, &subject_directory)?;
    let context_directory = subject_directory.join(context_digest(&request.context)?);
    ensure_private_directory_tree(&root, &context_directory)?;
    let final_path = context_directory.join(format!("{request_sha256}.json"));

    match inspect_exact_receipt(&final_path, request, &request_sha256)? {
        ExactReceiptState::Matching => return Ok(final_path),
        ExactReceiptState::Invalid => {
            return Err(
                "an invalid validation receipt already occupies the exact request key".to_owned(),
            )
        }
        ExactReceiptState::Missing => {}
    }

    let receipt = StoredReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION,
        artifact_kind: RECEIPT_ARTIFACT_KIND.to_owned(),
        scope: RECEIPT_SCOPE.to_owned(),
        release_authority: false,
        distribution_authority: false,
        signing_authority: false,
        native_host_authority: false,
        outcome: RECEIPT_OUTCOME.to_owned(),
        request_sha256: request_sha256.clone(),
        request: request.clone(),
    };
    let mut bytes = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| format!("serialize advisory validation receipt: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err("advisory validation receipt exceeds its closed size limit".to_owned());
    }

    let temporary_path = context_directory.join(unique_temporary_name(&request_sha256));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temporary = options
        .open(&temporary_path)
        .map_err(|error| format!("create temporary validation receipt: {error}"))?;
    let write_result = temporary
        .write_all(&bytes)
        .and_then(|_| temporary.sync_all());
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(format!("write temporary validation receipt: {error}"));
    }
    drop(temporary);

    match fs::hard_link(&temporary_path, &final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary_path);
            if inspect_exact_receipt(&final_path, request, &request_sha256)
                .is_ok_and(|state| state == ExactReceiptState::Matching)
            {
                return Ok(final_path);
            }
            return Err(
                "a competing invalid validation receipt occupied the exact request key".to_owned(),
            );
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary_path);
            return Err(format!(
                "atomically publish validation receipt {}: {error}",
                final_path.display()
            ));
        }
    }
    fs::remove_file(&temporary_path)
        .map_err(|error| format!("remove temporary validation receipt: {error}"))?;
    sync_directory(&context_directory)?;
    if !inspect_exact_receipt(&final_path, request, &request_sha256)
        .is_ok_and(|state| state == ExactReceiptState::Matching)
    {
        return Err("published advisory validation receipt did not verify".to_owned());
    }
    Ok(final_path)
}

pub(crate) fn acquire_local_ci_lock(repository: &Path) -> Result<LocalCiLock, String> {
    acquire_local_ci_lock_with_cache(repository, None)
}

fn acquire_local_ci_lock_with_cache(
    repository: &Path,
    cache_override: Option<&Path>,
) -> Result<LocalCiLock, String> {
    let root = cache_root(repository, cache_override, true)?;
    let directory = root.join(LOCKS_COMPONENT);
    ensure_private_directory_tree(&root, &directory)?;
    let path = directory.join("local-source-quality.lock");
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
        .map_err(|error| format!("enumerate tracked validation inputs: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "enumerate tracked validation inputs failed with {}: {}",
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
            .map_err(|error| format!("tracked validation path is not UTF-8: {error}"))?;
        let path = Path::new(relative);
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        {
            return Err(format!("git returned an unsafe tracked path {relative:?}"));
        }
        let bytes = read_regular_file(&repository.join(path), "tracked validation input")?;
        entries.push((relative.to_owned(), index.to_owned(), bytes));
    }
    if entries.is_empty() {
        return Err("tracked input selectors resolved no files".to_owned());
    }
    if !entries.windows(2).all(|pair| pair[0].0 < pair[1].0) {
        return Err("tracked validation inputs are not sorted and unique".to_owned());
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
    cache_override: Option<&Path>,
) -> Result<ValidationContext, String> {
    let repository_storage = storage_base(repository, cache_override)?;
    let repository_storage_sha256 = sha256(&native_bytes(repository_storage.as_os_str()));
    let mut environment = env::vars_os()
        .filter_map(|(name, value)| {
            relevant_environment_name(&name).then(|| {
                let value_bytes = native_bytes(&value);
                EnvironmentBinding {
                    name: encode_native_value(&name),
                    value_sha256: sha256(&value_bytes),
                    value_bytes: value_bytes.len() as u64,
                }
            })
        })
        .collect::<Vec<_>>();
    environment.sort();
    if environment.len() > MAX_ENVIRONMENT_ENTRIES
        || environment
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
    {
        return Err("validation environment is oversized or repeats a name".to_owned());
    }

    let cargo_program = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let rustc_program = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let context = ValidationContext {
        schema_version: CONTEXT_SCHEMA_VERSION,
        repository_storage_sha256,
        cargo_version: configured_tool_output(
            repository,
            "cargo",
            &cargo_program,
            &["--version", "--verbose"],
        )?,
        rustc_version: configured_tool_output(
            repository,
            "rustc",
            &rustc_program,
            &["--version", "--verbose"],
        )?,
        git_version: configured_tool_output(repository, "git", OsStr::new("git"), &["--version"])?,
        rustfmt_version: configured_tool_output(
            repository,
            "cargo-fmt",
            &cargo_program,
            &["fmt", "--version"],
        )?,
        clippy_version: configured_tool_output(
            repository,
            "cargo-clippy",
            &cargo_program,
            &["clippy", "--version"],
        )?,
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
    };
    validate_context(&context)?;
    Ok(context)
}

fn relevant_environment_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let normalized = if cfg!(windows) {
        name.to_ascii_uppercase()
    } else {
        name.to_owned()
    };
    matches!(
        normalized.as_str(),
        "AR" | "CC"
            | "CFLAGS"
            | "CXX"
            | "CXXFLAGS"
            | "CARGO"
            | "CARGO_BUILD_JOBS"
            | "CARGO_BUILD_BUILD_DIR"
            | "CARGO_BUILD_INCREMENTAL"
            | "CARGO_BUILD_RUSTC"
            | "CARGO_BUILD_RUSTC_WRAPPER"
            | "CARGO_BUILD_RUSTFLAGS"
            | "CARGO_BUILD_TARGET"
            | "CARGO_BUILD_TARGET_DIR"
            | "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "CARGO_HOME"
            | "CARGO_NET_OFFLINE"
            | "CARGO_TARGET_DIR"
            | "GIT_CONFIG_COUNT"
            | "GIT_CONFIG_GLOBAL"
            | "GIT_CONFIG_NOSYSTEM"
            | "GIT_CONFIG_SYSTEM"
            | "GIT_DIR"
            | "GIT_INDEX_FILE"
            | "GIT_NO_REPLACE_OBJECTS"
            | "GIT_WORK_TREE"
            | "HOME"
            | "HOST"
            | "IMAGEOS"
            | "IMAGEVERSION"
            | "LANG"
            | "LC_ALL"
            | "LINK"
            | "PATH"
            | "RUNNER_ARCH"
            | "RUNNER_OS"
            | "RUSTC"
            | "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "RUSTDOC"
            | "RUSTDOCFLAGS"
            | "RUSTFLAGS"
            | "RUST_TEST_THREADS"
            | "SCCACHE_BASEDIRS"
            | "SCCACHE_CACHE_SIZE"
            | "TARGET"
            | "TZ"
            | "USERPROFILE"
    ) || normalized.starts_with("CARGO_PROFILE_")
        || (normalized.starts_with("CARGO_TARGET_") && normalized.ends_with("_LINKER"))
        || (normalized.starts_with("AUTOCAD_MCP_")
            && normalized != DISABLE_RECEIPTS_ENVIRONMENT
            && !LEGACY_DISABLE_ENVIRONMENTS.contains(&normalized.as_str()))
}

fn cargo_configuration_bindings(repository: &Path) -> Result<Vec<ContentBinding>, String> {
    let repository = canonical_real_directory(repository, "validation repository")?;
    let mut candidates = Vec::new();
    for ancestor in repository.ancestors() {
        for name in ["config.toml", "config"] {
            candidates.push(ancestor.join(".cargo").join(name));
        }
    }
    if let Some(cargo_home) = env::var_os("CARGO_HOME") {
        let cargo_home = PathBuf::from(cargo_home);
        let cargo_home = if cargo_home.is_absolute() {
            cargo_home
        } else {
            repository.join(cargo_home)
        };
        for name in ["config.toml", "config"] {
            candidates.push(cargo_home.join(name));
        }
    } else if let Some(home) = env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }) {
        let cargo_home = PathBuf::from(home).join(".cargo");
        for name in ["config.toml", "config"] {
            candidates.push(cargo_home.join(name));
        }
    }

    let mut bindings = Vec::new();
    let mut seen = BTreeSet::new();
    for path in candidates {
        let encoded = encode_native_value(path.as_os_str());
        if !seen.insert(encoded.clone()) {
            continue;
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(format!(
                        "Cargo configuration is not a regular non-symlink file: {}",
                        path.display()
                    ));
                }
                let bytes = read_regular_file(&path, "Cargo configuration")?;
                bindings.push(ContentBinding {
                    role_sha256: sha256(&native_bytes(path.as_os_str())),
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
    if bindings.len() > MAX_CARGO_CONFIGURATIONS {
        return Err("too many Cargo configurations were discovered".to_owned());
    }
    Ok(bindings)
}

fn configured_tool_output(
    repository: &Path,
    tool: &str,
    program: &OsStr,
    arguments: &[&str],
) -> Result<ExactToolOutput, String> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(repository)
        .output()
        .map_err(|error| format!("launch {tool} {}: {error}", arguments.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "{tool} {} failed with {}",
            arguments.join(" "),
            output.status
        ));
    }
    if output.stdout.len() > MAX_TOOL_OUTPUT_BYTES || output.stderr.len() > MAX_TOOL_OUTPUT_BYTES {
        return Err(format!(
            "{tool} version output exceeds its closed size limit"
        ));
    }
    Ok(ExactToolOutput {
        tool: tool.to_owned(),
        program: encode_native_value(program),
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

fn lookup_receipt(
    repository: &Path,
    cache_override: Option<&Path>,
    expected: &CapturedValidation,
) -> Result<bool, String> {
    validate_captured_validation(expected)?;
    let root = cache_root(repository, cache_override, false)?;
    let directory = root
        .join(SUBJECTS_COMPONENT)
        .join(subject_digest(&expected.subject)?)
        .join(context_digest(&expected.context)?);
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!(
                "inspect validation receipt directory {}: {error}",
                directory.display()
            ))
        }
    };
    require_real_private_directory(&directory, &metadata)?;
    let mut entries = fs::read_dir(&directory)
        .map_err(|error| format!("enumerate validation receipts: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("enumerate validation receipt entry: {error}"))?;
    entries.sort_by_key(|entry| entry.file_name());
    if entries.len() > MAX_RECEIPTS_PER_CONTEXT {
        return Err("validation receipt context contains too many entries".to_owned());
    }
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "validation receipt filename is not UTF-8".to_owned())?;
        let Some(digest) = name.strip_suffix(".json") else {
            continue;
        };
        if require_sha256(digest, "validation receipt filename").is_err() {
            continue;
        }
        let Ok(receipt) = read_stored_receipt(&entry.path()) else {
            continue;
        };
        if receipt.request.subject == expected.subject
            && receipt.request.context == expected.context
            && receipt.request.plan.satisfies(&expected.plan)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactReceiptState {
    Missing,
    Matching,
    Invalid,
}

fn inspect_exact_receipt(
    path: &Path,
    expected: &CapturedValidation,
    expected_digest: &str,
) -> Result<ExactReceiptState, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ExactReceiptState::Missing);
        }
        Err(error) => {
            return Err(format!(
                "inspect exact validation receipt {}: {error}",
                path.display()
            ));
        }
    }
    let receipt = match read_stored_receipt(path) {
        Ok(receipt) => receipt,
        Err(_) => return Ok(ExactReceiptState::Invalid),
    };
    if receipt.request_sha256 == expected_digest && receipt.request == *expected {
        Ok(ExactReceiptState::Matching)
    } else {
        Ok(ExactReceiptState::Invalid)
    }
}

fn read_stored_receipt(path: &Path) -> Result<StoredReceipt, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "validation receipt {} does not exist or is unsafe: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "validation receipt is not a regular non-symlink file: {}",
            path.display()
        ));
    }
    require_private_receipt_file(&metadata)?;
    if metadata.len() > MAX_RECEIPT_BYTES {
        return Err("validation receipt exceeds its closed size limit".to_owned());
    }
    let mut file = File::open(path)
        .map_err(|error| format!("open validation receipt {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read validation receipt {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err("validation receipt exceeds its closed size limit".to_owned());
    }
    let receipt: StoredReceipt = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse strict validation receipt: {error}"))?;
    validate_stored_receipt(&receipt)?;
    Ok(receipt)
}

fn validate_stored_receipt(receipt: &StoredReceipt) -> Result<(), String> {
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION
        || receipt.artifact_kind != RECEIPT_ARTIFACT_KIND
        || receipt.scope != RECEIPT_SCOPE
        || receipt.release_authority
        || receipt.distribution_authority
        || receipt.signing_authority
        || receipt.native_host_authority
        || receipt.outcome != RECEIPT_OUTCOME
    {
        return Err("validation receipt has unsupported authority or schema".to_owned());
    }
    validate_captured_validation(&receipt.request)?;
    require_sha256(&receipt.request_sha256, "validation receipt request")?;
    if request_digest(&receipt.request)? != receipt.request_sha256 {
        return Err("validation receipt request digest is inconsistent".to_owned());
    }
    Ok(())
}

fn validate_captured_validation(request: &CapturedValidation) -> Result<(), String> {
    if request.schema_version != REQUEST_SCHEMA_VERSION {
        return Err("unsupported validation request schema".to_owned());
    }
    validate_subject(&request.subject)?;
    validate_plan(&request.plan)?;
    validate_context(&request.context)
}

fn validate_subject(subject: &ValidationSubject) -> Result<(), String> {
    if subject.schema_version != SUBJECT_SCHEMA_VERSION {
        return Err("unsupported validation subject schema".to_owned());
    }
    require_token(&subject.namespace, "validation subject namespace")?;
    match subject.kind.as_str() {
        "git_commit_tree" => {
            let format = subject
                .git_object_format
                .as_deref()
                .ok_or_else(|| "Git validation subject has no object format".to_owned())?;
            let length = match format {
                "sha1" => 40,
                "sha256" => 64,
                other => return Err(format!("unsupported Git object format {other:?}")),
            };
            require_oid(
                subject
                    .source_commit
                    .as_deref()
                    .ok_or_else(|| "Git validation subject has no source commit".to_owned())?,
                length,
                "validation source commit",
            )?;
            require_oid(
                subject
                    .source_tree_oid
                    .as_deref()
                    .ok_or_else(|| "Git validation subject has no source tree".to_owned())?,
                length,
                "validation source tree",
            )?;
            if subject.content_sha256.is_some() {
                return Err("Git validation subject contains content-closure state".to_owned());
            }
        }
        "content_closure" => {
            require_sha256(
                subject.content_sha256.as_deref().ok_or_else(|| {
                    "content-closure validation subject has no SHA-256".to_owned()
                })?,
                "validation content closure",
            )?;
            if subject.git_object_format.is_some()
                || subject.source_commit.is_some()
                || subject.source_tree_oid.is_some()
            {
                return Err("content-closure subject contains Git identity state".to_owned());
            }
        }
        other => return Err(format!("unsupported validation subject kind {other:?}")),
    }
    Ok(())
}

fn validate_plan(plan: &ValidationPlan) -> Result<(), String> {
    if plan.schema_version != PLAN_SCHEMA_VERSION {
        return Err("unsupported validation plan schema".to_owned());
    }
    require_sha256(&plan.engine_sha256, "validation receipt engine")?;
    if plan.steps.is_empty() || plan.steps.len() > MAX_PLAN_STEPS {
        return Err("validation plan must be non-empty and bounded".to_owned());
    }
    for step in &plan.steps {
        require_step_id(&step.id)?;
        require_command(&step.command)?;
    }
    if !plan.steps.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err("validation plan steps must be sorted and unique".to_owned());
    }
    Ok(())
}

fn validate_context(context: &ValidationContext) -> Result<(), String> {
    if context.schema_version != CONTEXT_SCHEMA_VERSION {
        return Err("unsupported validation context schema".to_owned());
    }
    require_sha256(
        &context.repository_storage_sha256,
        "validation repository storage",
    )?;
    for tool in [
        &context.cargo_version,
        &context.rustc_version,
        &context.git_version,
        &context.rustfmt_version,
        &context.clippy_version,
    ] {
        validate_tool_output(tool)?;
    }
    if context.platform.operating_system.is_empty()
        || context.platform.architecture.is_empty()
        || context.platform.family.is_empty()
        || !matches!(context.platform.pointer_width, 16 | 32 | 64 | 128)
        || !matches!(context.platform.endian.as_str(), "little" | "big")
    {
        return Err("validation platform binding is invalid".to_owned());
    }
    if context.environment.len() > MAX_ENVIRONMENT_ENTRIES
        || !context.environment.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err("validation environment must be sorted, unique, and bounded".to_owned());
    }
    for binding in &context.environment {
        validate_native_value(&binding.name)?;
        require_sha256(&binding.value_sha256, "validation environment value")?;
    }
    if context.cargo_configurations.len() > MAX_CARGO_CONFIGURATIONS
        || !context
            .cargo_configurations
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err("Cargo configuration bindings must be sorted, unique, and bounded".to_owned());
    }
    for binding in &context.cargo_configurations {
        require_sha256(&binding.role_sha256, "Cargo configuration role")?;
        require_sha256(&binding.sha256, "Cargo configuration contents")?;
    }
    Ok(())
}

fn validate_tool_output(output: &ExactToolOutput) -> Result<(), String> {
    if output.tool.is_empty()
        || output.arguments.is_empty()
        || output.stdout_bytes > MAX_TOOL_OUTPUT_BYTES as u64
        || output.stderr_bytes > MAX_TOOL_OUTPUT_BYTES as u64
    {
        return Err("validation tool binding is invalid".to_owned());
    }
    validate_native_value(&output.program)?;
    require_sha256(&output.stdout_sha256, "validation tool stdout")?;
    require_sha256(&output.stderr_sha256, "validation tool stderr")
}

fn plan_satisfies(completed: &ValidationPlan, required: &ValidationPlan) -> bool {
    completed.schema_version == required.schema_version
        && completed.engine_sha256 == required.engine_sha256
        && required
            .steps
            .iter()
            .all(|step| completed.steps.binary_search(step).is_ok())
}

fn subject_digest(subject: &ValidationSubject) -> Result<String, String> {
    validate_subject(subject)?;
    digest_json(
        b"autocad-mcp-validation-subject-v1",
        subject,
        "validation subject",
    )
}

fn context_digest(context: &ValidationContext) -> Result<String, String> {
    validate_context(context)?;
    digest_json(
        b"autocad-mcp-validation-context-v1",
        context,
        "validation context",
    )
}

fn request_digest(request: &CapturedValidation) -> Result<String, String> {
    validate_captured_validation(request)?;
    digest_json(
        b"autocad-mcp-validation-request-v1",
        request,
        "validation request",
    )
}

fn digest_json<T: Serialize>(domain: &[u8], value: &T, label: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| format!("serialize {label}: {error}"))?;
    let mut hasher = Sha256::new();
    hash_framed(&mut hasher, b"domain", domain);
    hash_framed(&mut hasher, b"value", &bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn receipt_engine_sha256() -> String {
    let mut hasher = Sha256::new();
    hash_framed(
        &mut hasher,
        b"domain",
        b"autocad-mcp-validation-receipt-engine-v1",
    );
    hash_framed(&mut hasher, b"receipt-engine", RECEIPT_ENGINE_SOURCE);
    hash_framed(&mut hasher, b"orchestrator", ORCHESTRATOR_SOURCE);
    format!("{:x}", hasher.finalize())
}

fn cache_root(
    repository: &Path,
    cache_override: Option<&Path>,
    create: bool,
) -> Result<PathBuf, String> {
    let base = storage_base(repository, cache_override)?;
    if cache_override.is_some() {
        if create {
            ensure_private_directory(&base)?;
        } else {
            let metadata = fs::symlink_metadata(&base)
                .map_err(|error| format!("inspect injected validation cache: {error}"))?;
            require_real_private_directory(&base, &metadata)?;
        }
        return Ok(base);
    }

    let mut current = base;
    for component in CACHE_COMPONENTS {
        current.push(component);
        if create {
            ensure_private_directory(&current)?;
        } else {
            let metadata = fs::symlink_metadata(&current)
                .map_err(|error| format!("inspect validation cache: {error}"))?;
            require_real_private_directory(&current, &metadata)?;
        }
    }
    Ok(current)
}

fn storage_base(repository: &Path, cache_override: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(root) = cache_override {
        return canonical_real_directory(root, "injected validation cache root");
    }
    git_common_directory(repository)
}

fn git_common_directory(repository: &Path) -> Result<PathBuf, String> {
    let output = isolated_git_command(repository)
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .output()
        .map_err(|error| format!("discover Git common directory: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "discover Git common directory failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("Git common directory is not UTF-8: {error}"))?;
    let path = stdout
        .strip_suffix("\r\n")
        .or_else(|| stdout.strip_suffix('\n'))
        .unwrap_or(&stdout);
    if path.is_empty() || path.contains(['\r', '\n']) {
        return Err("Git common directory output is invalid".to_owned());
    }
    canonical_real_directory(Path::new(path), "Git common directory")
}

fn ensure_private_directory_tree(root: &Path, target: &Path) -> Result<(), String> {
    if !target.starts_with(root) {
        return Err("validation cache directory escaped its root".to_owned());
    }
    let relative = target
        .strip_prefix(root)
        .map_err(|_| "validation cache directory escaped its root".to_owned())?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err("validation cache directory contains an unsafe component".to_owned());
        };
        current.push(component);
        ensure_private_directory(&current)?;
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => require_real_private_directory(path, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "create validation cache directory {}: {error}",
                        path.display()
                    ))
                }
            }
            let metadata = fs::symlink_metadata(path).map_err(|error| {
                format!(
                    "inspect created validation cache directory {}: {error}",
                    path.display()
                )
            })?;
            require_real_private_directory(path, &metadata)
        }
        Err(error) => Err(format!(
            "inspect validation cache directory {}: {error}",
            path.display()
        )),
    }
}

fn require_real_private_directory(path: &Path, metadata: &Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "validation cache path is not a real directory: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(format!(
                "validation cache directory is not private: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_private_receipt_file(metadata: &Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
        Err("validation receipt must be mode 0600 with one link".to_owned())
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
        .map_err(|error| format!("sync validation receipt directory: {error}"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn read_regular_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} is not a regular non-symlink file: {}",
            path.display()
        ));
    }
    let mut file =
        File::open(path).map_err(|error| format!("open {label} {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read {label} {}: {error}", path.display()))?;
    Ok(bytes)
}

fn canonical_real_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect {label}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} must be a real directory"));
    }
    fs::canonicalize(path).map_err(|error| format!("canonicalize {label}: {error}"))
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

fn receipts_enabled() -> bool {
    env::var_os(DISABLE_RECEIPTS_ENVIRONMENT).is_none()
        && LEGACY_DISABLE_ENVIRONMENTS
            .iter()
            .all(|name| env::var_os(name).is_none())
}

fn require_token(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        Err(format!("{label} is invalid: {value:?}"))
    } else {
        Ok(())
    }
}

fn require_step_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 512
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'/' | b'.')
        })
    {
        Err(format!("validation step id is invalid: {value:?}"))
    } else {
        Ok(())
    }
}

fn require_command(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_COMMAND_BYTES || value.chars().any(char::is_control) {
        Err("validation command is empty, oversized, or control-bearing".to_owned())
    } else {
        Ok(())
    }
}

fn require_sha256(value: &str, label: &str) -> Result<(), String> {
    require_oid(value, 64, label)
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
            "{label} must be {length} lowercase hexadecimal digits"
        ))
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

fn unique_temporary_name(request_sha256: &str) -> String {
    format!(
        ".receipt-{}-{}-{}.tmp",
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed),
        &request_sha256[..16]
    )
}

fn encode_native_value(value: &OsStr) -> NativeValue {
    let (encoding, bytes) = native_encoding_and_bytes(value);
    NativeValue {
        encoding: encoding.to_owned(),
        content_hex: hex_encode(&bytes),
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

#[cfg(unix)]
fn native_encoding_and_bytes(value: &OsStr) -> (&'static str, Vec<u8>) {
    use std::os::unix::ffi::OsStrExt;
    ("unix_bytes", value.as_bytes().to_vec())
}

#[cfg(windows)]
fn native_encoding_and_bytes(value: &OsStr) -> (&'static str, Vec<u8>) {
    use std::os::windows::ffi::OsStrExt;
    (
        "windows_utf16le",
        value.encode_wide().flat_map(u16::to_le_bytes).collect(),
    )
}

#[cfg(not(any(unix, windows)))]
fn native_encoding_and_bytes(value: &OsStr) -> (&'static str, Vec<u8>) {
    ("utf8", value.to_string_lossy().as_bytes().to_vec())
}

fn native_bytes(value: &OsStr) -> Vec<u8> {
    native_encoding_and_bytes(value).1
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
    use std::cell::Cell;

    struct Fixture {
        repository: tempfile::TempDir,
        cache: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let repository = tempfile::tempdir().unwrap();
            fs::create_dir(repository.path().join("src")).unwrap();
            fs::write(
                repository.path().join("Cargo.toml"),
                "[package]\nname = \"receipt-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
            )
            .unwrap();
            fs::write(repository.path().join("src/lib.rs"), "pub fn value() {}\n").unwrap();
            let cache = tempfile::tempdir().unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self { repository, cache }
        }

        fn subject(&self, digit: char) -> ValidationSubject {
            ValidationSubject::content_closure("fixture", &digit.to_string().repeat(64)).unwrap()
        }

        fn plan(&self, steps: &[(&str, &str)]) -> ValidationPlan {
            ValidationPlan::new(
                steps
                    .iter()
                    .map(|(id, command)| ((*id).to_owned(), (*command).to_owned()))
                    .collect(),
            )
            .unwrap()
        }

        fn captured(&self, subject: ValidationSubject, plan: ValidationPlan) -> CapturedValidation {
            capture_validation_with_cache(
                self.repository.path(),
                Some(self.cache.path()),
                subject,
                plan,
            )
            .unwrap()
        }
    }

    #[test]
    fn subject_plan_and_context_each_bind_the_request_key() {
        let fixture = Fixture::new();
        let baseline = fixture.captured(
            fixture.subject('1'),
            fixture.plan(&[("check/a", "cargo test --locked")]),
        );
        let baseline_key = request_digest(&baseline).unwrap();

        let changed_subject = fixture.captured(
            fixture.subject('2'),
            fixture.plan(&[("check/a", "cargo test --locked")]),
        );
        assert_ne!(request_digest(&changed_subject).unwrap(), baseline_key);

        let changed_plan = fixture.captured(
            fixture.subject('1'),
            fixture.plan(&[("check/a", "cargo test --locked --all-targets")]),
        );
        assert_ne!(request_digest(&changed_plan).unwrap(), baseline_key);

        let mut changed_context = baseline.clone();
        changed_context.context.platform.architecture = "other".to_owned();
        assert_ne!(request_digest(&changed_context).unwrap(), baseline_key);
    }

    #[test]
    fn stored_receipt_is_strict_and_has_no_external_authority() {
        let fixture = Fixture::new();
        let request = fixture.captured(
            fixture.subject('1'),
            fixture.plan(&[("check/a", "cargo test --locked")]),
        );
        let mut receipt = StoredReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION,
            artifact_kind: RECEIPT_ARTIFACT_KIND.to_owned(),
            scope: RECEIPT_SCOPE.to_owned(),
            release_authority: false,
            distribution_authority: false,
            signing_authority: false,
            native_host_authority: false,
            outcome: RECEIPT_OUTCOME.to_owned(),
            request_sha256: request_digest(&request).unwrap(),
            request,
        };
        validate_stored_receipt(&receipt).unwrap();
        receipt.native_host_authority = true;
        assert!(validate_stored_receipt(&receipt).is_err());
    }

    #[test]
    fn stronger_completed_plan_satisfies_only_its_exact_subsets() {
        let fixture = Fixture::new();
        let subject = fixture.subject('1');
        let subset = fixture.plan(&[("local-gate/001", "git [\"diff\",\"--check\"]")]);
        let superset = subset
            .with_step(
                "source-candidate/release-preview",
                "xtask source-candidate-seal release preview",
            )
            .unwrap();
        assert_eq!(subset.step_count(), 1);
        assert_eq!(superset.step_count(), 2);

        let completed = fixture.captured(subject.clone(), superset.clone());
        record_receipt_with_cache(
            fixture.repository.path(),
            Some(fixture.cache.path()),
            &completed,
        )
        .unwrap();
        let requested_subset = fixture.captured(subject.clone(), subset);
        assert!(receipt_hit_with_cache(
            fixture.repository.path(),
            Some(fixture.cache.path()),
            &requested_subset
        ));

        let other = fixture.captured(
            subject,
            fixture.plan(&[("local-gate/001", "git [\"status\"]")]),
        );
        assert!(!receipt_hit_with_cache(
            fixture.repository.path(),
            Some(fixture.cache.path()),
            &other
        ));

        let smaller_completed = fixture.captured(
            fixture.subject('2'),
            fixture.plan(&[("local-gate/001", "git [\"diff\",\"--check\"]")]),
        );
        record_receipt_with_cache(
            fixture.repository.path(),
            Some(fixture.cache.path()),
            &smaller_completed,
        )
        .unwrap();
        let larger_requested = fixture.captured(fixture.subject('2'), superset);
        assert!(!receipt_hit_with_cache(
            fixture.repository.path(),
            Some(fixture.cache.path()),
            &larger_requested
        ));
    }

    #[test]
    fn successful_validation_uses_only_the_injected_durable_cache() {
        let fixture = Fixture::new();
        let calls = Cell::new(0);
        let plan = fixture.plan(&[("check/a", "cargo test --locked")]);
        let first = validate_or_run_with_cache(
            fixture.repository.path(),
            Some(fixture.cache.path()),
            true,
            &plan,
            || Ok(fixture.subject('1')),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert!(!first.reused);
        assert_eq!(calls.get(), 1);
        assert!(!fixture.repository.path().join("target").exists());

        fs::create_dir(fixture.repository.path().join("target")).unwrap();
        fs::remove_dir(fixture.repository.path().join("target")).unwrap();
        let second = validate_or_run_with_cache(
            fixture.repository.path(),
            Some(fixture.cache.path()),
            true,
            &plan,
            || Ok(fixture.subject('1')),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert!(second.reused);
        assert_eq!(calls.get(), 1);
        assert!(!fixture.repository.path().join("target").exists());
    }

    #[test]
    fn explicit_cache_disable_neither_reuses_nor_records() {
        let fixture = Fixture::new();
        let calls = Cell::new(0);
        let subject = fixture.subject('1');
        let plan = fixture.plan(&[("check/a", "cargo test --locked")]);
        for _ in 0..2 {
            let outcome = validate_or_run_with_cache(
                fixture.repository.path(),
                Some(fixture.cache.path()),
                false,
                &plan,
                || Ok(subject.clone()),
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            )
            .unwrap();
            assert!(!outcome.reused);
        }
        assert_eq!(calls.get(), 2);
        let request = fixture.captured(subject, plan);
        assert!(!receipt_hit_with_cache(
            fixture.repository.path(),
            Some(fixture.cache.path()),
            &request
        ));
    }

    #[test]
    fn failed_validation_never_records_a_reusable_result() {
        let fixture = Fixture::new();
        let plan = fixture.plan(&[("check/a", "cargo test --locked")]);
        validate_or_run_with_cache(
            fixture.repository.path(),
            Some(fixture.cache.path()),
            true,
            &plan,
            || Ok(fixture.subject('1')),
            || Err("fixture validation failed".to_owned()),
        )
        .unwrap_err();
        let request = fixture.captured(fixture.subject('1'), plan);
        assert!(!receipt_hit_with_cache(
            fixture.repository.path(),
            Some(fixture.cache.path()),
            &request
        ));
    }

    #[test]
    fn missing_and_malformed_exact_receipts_are_distinct_cache_misses() {
        let fixture = Fixture::new();
        let request = fixture.captured(
            fixture.subject('1'),
            fixture.plan(&[("check/a", "cargo test --locked")]),
        );
        let request_sha256 = request_digest(&request).unwrap();
        let path = record_receipt_with_cache(
            fixture.repository.path(),
            Some(fixture.cache.path()),
            &request,
        )
        .unwrap();
        assert_eq!(
            inspect_exact_receipt(&path, &request, &request_sha256).unwrap(),
            ExactReceiptState::Matching
        );
        let missing = path.with_file_name(format!("{}.json", "f".repeat(64)));
        assert_eq!(
            inspect_exact_receipt(&missing, &request, &request_sha256).unwrap(),
            ExactReceiptState::Missing
        );

        fs::write(&path, b"{\"release_authority\":true}\n").unwrap();
        assert_eq!(
            inspect_exact_receipt(&path, &request, &request_sha256).unwrap(),
            ExactReceiptState::Invalid
        );
        assert!(!receipt_hit_with_cache(
            fixture.repository.path(),
            Some(fixture.cache.path()),
            &request
        ));
    }

    #[test]
    fn local_ci_lock_is_exclusive_released_and_injected() {
        let fixture = Fixture::new();
        let first =
            acquire_local_ci_lock_with_cache(fixture.repository.path(), Some(fixture.cache.path()))
                .unwrap();
        assert!(acquire_local_ci_lock_with_cache(
            fixture.repository.path(),
            Some(fixture.cache.path())
        )
        .is_err());
        drop(first);
        acquire_local_ci_lock_with_cache(fixture.repository.path(), Some(fixture.cache.path()))
            .unwrap();
        assert!(!fixture.repository.path().join("target").exists());
    }
}
