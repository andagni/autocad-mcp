use distribution_approval::DistributionMode;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Instant;

use release_packager::approval::{
    verify_owner_distribution_approval, verify_preview_clean_host_receipt,
    ApprovalVerificationOptions, ApprovalVerificationReport, PreviewCleanHostVerificationOptions,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod candidate_seal;
mod pe_imports;
mod preview_e2e;
mod source_bundle;
mod validation_receipt;
mod windows_preflight;

#[derive(Debug, Eq, PartialEq)]
struct CommandSpec {
    program: &'static str,
    arguments: &'static [&'static str],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalGateCommand {
    program: String,
    arguments: Vec<String>,
    receipt_input: Option<LocalGateReceiptInput>,
}

impl LocalGateCommand {
    fn new(program: &str, arguments: &[&str]) -> Self {
        Self {
            program: program.to_owned(),
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
            receipt_input: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalGateReceiptInput {
    namespace: String,
    program: String,
    arguments: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LocalGateCargoMetadata {
    packages: Vec<LocalGateCargoPackage>,
    workspace_members: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LocalGateCargoPackage {
    id: String,
    name: String,
    version: String,
    features: BTreeMap<String, Vec<String>>,
    metadata: serde_json::Value,
    targets: Vec<LocalGateCargoTarget>,
}

#[derive(Debug, Deserialize)]
struct LocalGateCargoTarget {
    name: String,
    kind: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageLocalGate {
    #[serde(rename = "schema-version")]
    schema_version: u32,
    #[serde(default)]
    checks: Vec<PackageLocalGateCheck>,
    #[serde(default)]
    profiles: Vec<PackageLocalGateProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageLocalGateCheck {
    name: String,
    bin: String,
    arguments: Vec<String>,
    #[serde(default, rename = "input-id-arguments")]
    input_id_arguments: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageLocalGateProfile {
    name: String,
    features: Vec<String>,
    clippy: bool,
    test: bool,
    #[serde(default)]
    targets: Vec<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum LocalGateProfileTarget {
    Lib,
    Bin(String),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DiscoveredLocalGateCheck {
    package_spec: String,
    name: String,
    bin: String,
    arguments: Vec<String>,
    input_id_arguments: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DiscoveredLocalGateProfile {
    package_spec: String,
    name: String,
    features: Vec<String>,
    clippy: bool,
    test: bool,
    targets: Vec<LocalGateProfileTarget>,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct DiscoveredLocalGate {
    checks: Vec<DiscoveredLocalGateCheck>,
    profiles: Vec<DiscoveredLocalGateProfile>,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct LocalGateValidation {
    receipt_inputs: BTreeMap<String, String>,
}

#[derive(Debug, Eq, PartialEq)]
struct SourceQualityOutcome {
    candidate: candidate_seal::CandidateIdentity,
    reused: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct PushUpdate {
    local_ref: String,
    local_oid: String,
    remote_ref: String,
}

#[derive(Debug, Serialize)]
struct CurrentDistributionVerification {
    schema_version: u32,
    kind: &'static str,
    current_source_candidate_verified: bool,
    approval_distribution_set_verified: bool,
    exact_candidate_identity_joined: bool,
    native_build_attestation_semantics_verified: bool,
    clean_host_acceptance_verified: bool,
    package_mode: DistributionMode,
    decision_id: String,
    candidate: candidate_seal::CandidateIdentity,
    approval_sha256: String,
    mcpb_sha256: String,
    source_archive_sha256: String,
    source_closure_sbom_sha256: String,
    build_attestation_sha256: String,
    clean_host_receipt_sha256: Option<String>,
}

const WINDOWS_NATIVE_SEMANTIC_TESTS: &[CommandSpec] = &[
    CommandSpec {
        program: "cargo",
        arguments: &[
            "test",
            "--locked",
            "-p",
            "autocad-mcp",
            "--lib",
            "windows_native_semantic_",
            "--",
            "--test-threads=1",
        ],
    },
    CommandSpec {
        program: "cargo",
        arguments: &[
            "test",
            "--locked",
            "-p",
            "autocad-mcp",
            "--test",
            "windows_certification",
            "windows_native_semantic_",
            "--",
            "--test-threads=1",
        ],
    },
    CommandSpec {
        program: "cargo",
        arguments: &[
            "test",
            "--locked",
            "-p",
            "release-packager",
            "--lib",
            "windows_native_semantic_",
            "--",
            "--test-threads=1",
        ],
    },
];

const WINDOWS_GUARDED_RENAME_TEST: CommandSpec = CommandSpec {
    program: "cargo",
    arguments: &[
        "test",
        "--locked",
        "-p",
        "autocad-mcp",
        "--test",
        "windows_guarded_rename",
        "windows::windows_guarded_rename_feasibility_probe",
        "--",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ],
};

const WINDOWS_GUARDED_RENAME_EVIDENCE_ENV: &str =
    "AUTOCAD_MCP_WINDOWS_GUARDED_RENAME_FEASIBILITY_EVIDENCE";
const DISTRIBUTION_EVIDENCE_RECEIPT_TARGET: &str = "distribution-evidence";
const WINDOWS_NATIVE_SEMANTIC_RECEIPT_TARGET: &str = "windows-native-semantic";
const SOURCE_VALIDATION_SUBJECT_NAMESPACE: &str = "repository-source";
const SOURCE_CANDIDATE_STEP_ID: &str = "source-candidate/release-preview";
const SOURCE_CANDIDATE_STEP_COMMAND: &str =
    "xtask source-candidate-seal --mode release --mode preview --verify";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsNativeTestSuite {
    All,
    Semantic,
    GuardedRename,
}

fn repository_root_from(start: &Path) -> Result<PathBuf, String> {
    let output = git_command(start)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|error| {
            format!(
                "failed to launch git from {} to discover the repository root: {error}",
                start.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "git repository-root discovery from {} failed with {}: {}",
            start.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("git repository-root discovery returned non-UTF-8: {error}"))?;
    let root = stdout
        .strip_suffix("\r\n")
        .or_else(|| stdout.strip_suffix('\n'))
        .unwrap_or(&stdout);
    if root.is_empty() || root.contains(['\r', '\n']) {
        return Err("git repository-root discovery returned an invalid path".to_owned());
    }
    let root = PathBuf::from(root);
    if !root.is_absolute() {
        return Err(format!(
            "git repository-root discovery returned a non-absolute path: {}",
            root.display()
        ));
    }
    let root = fs::canonicalize(&root).map_err(|error| {
        format!(
            "canonicalize discovered repository root {}: {error}",
            root.display()
        )
    })?;
    let start = fs::canonicalize(start).map_err(|error| {
        format!(
            "canonicalize repository-root discovery start {}: {error}",
            start.display()
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

fn repository_root() -> PathBuf {
    let current = std::env::current_dir().expect("resolve current directory for xtask");
    repository_root_from(&current).unwrap_or_else(|error| panic!("{error}"))
}

fn discover_local_gate(root: &Path) -> Result<DiscoveredLocalGate, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("failed to launch cargo metadata for local-gate: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata for local-gate failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let metadata = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse cargo metadata for local-gate: {error}"))?;
    discover_local_gate_from_metadata(metadata)
}

fn discover_local_gate_from_metadata(
    metadata: LocalGateCargoMetadata,
) -> Result<DiscoveredLocalGate, String> {
    let workspace_members = metadata
        .workspace_members
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut package_specs = BTreeSet::new();
    let mut checks = Vec::new();
    let mut profiles = Vec::new();

    for package in metadata
        .packages
        .into_iter()
        .filter(|package| workspace_members.contains(&package.id))
    {
        let Some(local_gate_value) = package.metadata.get("local-gate") else {
            continue;
        };
        let local_gate: PackageLocalGate = serde_json::from_value(local_gate_value.clone())
            .map_err(|error| {
                format!(
                    "parse package.metadata.local-gate for {} {}: {error}",
                    package.name, package.version
                )
            })?;
        if !matches!(local_gate.schema_version, 1 | 2) {
            return Err(format!(
                "package.metadata.local-gate for {} {} has schema-version {}, expected 1 or 2",
                package.name, package.version, local_gate.schema_version
            ));
        }
        let local_gate_schema_version = local_gate.schema_version;
        if local_gate.checks.is_empty() && local_gate.profiles.is_empty() {
            return Err(format!(
                "package.metadata.local-gate for {} {} declares no checks or profiles",
                package.name, package.version
            ));
        }

        let package_spec = format!("{}@{}", package.name, package.version);
        if !package_specs.insert(package_spec.clone()) {
            return Err(format!(
                "local-gate package specification {package_spec} is not unique"
            ));
        }

        let mut check_names = BTreeSet::new();
        for check in local_gate.checks {
            require_local_gate_token(&check.name, "check name")?;
            require_local_gate_token(&check.bin, "binary name")?;
            if !check_names.insert(check.name.clone()) {
                return Err(format!(
                    "package {package_spec} repeats local-gate check {}",
                    check.name
                ));
            }
            if !package.targets.iter().any(|target| {
                target.name == check.bin && target.kind.iter().any(|kind| kind == "bin")
            }) {
                return Err(format!(
                    "package {package_spec} local-gate check {} names undeclared binary {}",
                    check.name, check.bin
                ));
            }
            if check.arguments.is_empty() {
                return Err(format!(
                    "package {package_spec} local-gate check {} has no arguments",
                    check.name
                ));
            }
            for argument in &check.arguments {
                require_local_gate_argument(argument, &package_spec, &check.name)?;
            }
            if let Some(input_id_arguments) = check.input_id_arguments.as_ref() {
                if local_gate_schema_version != 2 {
                    return Err(format!(
                        "package {package_spec} local-gate check {} requires schema-version 2 for input-id-arguments",
                        check.name
                    ));
                }
                if input_id_arguments.is_empty() {
                    return Err(format!(
                        "package {package_spec} local-gate check {} has no input-id arguments",
                        check.name
                    ));
                }
                for argument in input_id_arguments {
                    require_local_gate_argument(argument, &package_spec, &check.name)?;
                }
            }
            checks.push(DiscoveredLocalGateCheck {
                package_spec: package_spec.clone(),
                name: check.name,
                bin: check.bin,
                arguments: check.arguments,
                input_id_arguments: check.input_id_arguments,
            });
        }

        let mut profile_names = BTreeSet::new();
        for profile in local_gate.profiles {
            require_local_gate_token(&profile.name, "profile name")?;
            if !profile_names.insert(profile.name.clone()) {
                return Err(format!(
                    "package {package_spec} repeats local-gate profile {}",
                    profile.name
                ));
            }
            if !profile.clippy && !profile.test {
                return Err(format!(
                    "package {package_spec} local-gate profile {} enables neither clippy nor test",
                    profile.name
                ));
            }
            if profile.features.is_empty() {
                return Err(format!(
                    "package {package_spec} local-gate profile {} has no features",
                    profile.name
                ));
            }
            let mut feature_names = BTreeSet::new();
            for feature in &profile.features {
                require_local_gate_token(feature, "feature name")?;
                if !feature_names.insert(feature.clone()) {
                    return Err(format!(
                        "package {package_spec} local-gate profile {} repeats feature {feature}",
                        profile.name
                    ));
                }
                if !package.features.contains_key(feature) {
                    return Err(format!(
                        "package {package_spec} local-gate profile {} names undeclared feature {feature}",
                        profile.name
                    ));
                }
            }
            let mut profile_targets = BTreeSet::new();
            for target in &profile.targets {
                let target = parse_local_gate_profile_target(
                    target,
                    &package_spec,
                    &profile.name,
                    &package.targets,
                )?;
                if !profile_targets.insert(target) {
                    return Err(format!(
                        "package {package_spec} local-gate profile {} repeats a target",
                        profile.name
                    ));
                }
            }
            profiles.push(DiscoveredLocalGateProfile {
                package_spec: package_spec.clone(),
                name: profile.name,
                features: profile.features,
                clippy: profile.clippy,
                test: profile.test,
                targets: profile_targets.into_iter().collect(),
            });
        }
    }

    checks.sort();
    profiles.sort();
    Ok(DiscoveredLocalGate { checks, profiles })
}

fn require_local_gate_token(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(format!(
            "local-gate {label} {value:?} must use lowercase ASCII letters, digits, hyphen, underscore, or dot"
        ));
    }
    Ok(())
}

fn parse_local_gate_profile_target(
    value: &str,
    package_spec: &str,
    profile_name: &str,
    package_targets: &[LocalGateCargoTarget],
) -> Result<LocalGateProfileTarget, String> {
    if value == "lib" {
        if !package_targets
            .iter()
            .any(|target| target.kind.iter().any(|kind| kind == "lib"))
        {
            return Err(format!(
                "package {package_spec} local-gate profile {profile_name} selects an undeclared library target"
            ));
        }
        return Ok(LocalGateProfileTarget::Lib);
    }

    let Some(binary) = value.strip_prefix("bin:") else {
        return Err(format!(
            "package {package_spec} local-gate profile {profile_name} has unsupported target {value:?}; expected lib or bin:<declared-binary>"
        ));
    };
    require_local_gate_token(binary, "binary target name")?;
    if !package_targets
        .iter()
        .any(|target| target.name == binary && target.kind.iter().any(|kind| kind == "bin"))
    {
        return Err(format!(
            "package {package_spec} local-gate profile {profile_name} selects undeclared binary target {binary}"
        ));
    }
    Ok(LocalGateProfileTarget::Bin(binary.to_owned()))
}

fn require_local_gate_argument(
    value: &str,
    package_spec: &str,
    check_name: &str,
) -> Result<(), String> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(format!(
            "package {package_spec} local-gate check {check_name} contains an empty or control-bearing argument"
        ));
    }
    Ok(())
}

fn local_gate_commands(discovered: &DiscoveredLocalGate) -> Vec<LocalGateCommand> {
    let mut commands = vec![
        LocalGateCommand::new("git", &["diff", "--check"]),
        LocalGateCommand::new("git", &["diff", "--cached", "--check"]),
    ];

    for check in &discovered.checks {
        let mut arguments = vec![
            "run".to_owned(),
            "--locked".to_owned(),
            "-p".to_owned(),
            check.package_spec.clone(),
            "--bin".to_owned(),
            check.bin.clone(),
            "--".to_owned(),
        ];
        arguments.extend(check.arguments.iter().cloned());
        let receipt_input = check.input_id_arguments.as_ref().map(|input_arguments| {
            let mut arguments = vec![
                "run".to_owned(),
                "--quiet".to_owned(),
                "--locked".to_owned(),
                "-p".to_owned(),
                check.package_spec.clone(),
                "--bin".to_owned(),
                check.bin.clone(),
                "--".to_owned(),
            ];
            arguments.extend(input_arguments.iter().cloned());
            LocalGateReceiptInput {
                namespace: check.name.clone(),
                program: "cargo".to_owned(),
                arguments,
            }
        });
        commands.push(LocalGateCommand {
            program: "cargo".to_owned(),
            arguments,
            receipt_input,
        });
    }

    commands.push(LocalGateCommand::new(
        "cargo",
        &["fmt", "--all", "--", "--check"],
    ));
    commands.push(LocalGateCommand::new(
        "cargo",
        &[
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    ));
    for profile in discovered.profiles.iter().filter(|profile| profile.clippy) {
        commands.push(local_gate_profile_command(profile, "clippy"));
    }

    commands.push(LocalGateCommand::new(
        "cargo",
        &["test", "--locked", "--workspace", "--all-targets"],
    ));
    for profile in discovered.profiles.iter().filter(|profile| profile.test) {
        commands.push(local_gate_profile_command(profile, "test"));
    }
    commands
}

fn local_gate_profile_command(
    profile: &DiscoveredLocalGateProfile,
    operation: &str,
) -> LocalGateCommand {
    let mut arguments = vec![
        operation.to_owned(),
        "--locked".to_owned(),
        "-p".to_owned(),
        profile.package_spec.clone(),
    ];
    if profile.targets.is_empty() {
        arguments.push("--all-targets".to_owned());
    } else {
        for target in &profile.targets {
            match target {
                LocalGateProfileTarget::Lib => arguments.push("--lib".to_owned()),
                LocalGateProfileTarget::Bin(binary) => {
                    arguments.extend(["--bin".to_owned(), binary.clone()]);
                }
            }
        }
        if operation == "clippy" {
            arguments.push("--no-deps".to_owned());
        }
    }
    arguments.extend(["--features".to_owned(), profile.features.join(",")]);
    match operation {
        "clippy" => arguments.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]),
        "test" => {}
        _ => unreachable!("local-gate profile operation is closed"),
    }
    LocalGateCommand {
        program: "cargo".to_owned(),
        arguments,
        receipt_input: None,
    }
}

fn render_local_gate_command(command: &LocalGateCommand) -> String {
    let arguments = serde_json::to_string(&command.arguments)
        .expect("local-gate argv serialization cannot fail");
    format!("{} {arguments}", command.program)
}

fn render_receipt_input_command(input: &LocalGateReceiptInput) -> String {
    let arguments = serde_json::to_string(&input.arguments)
        .expect("receipt input argv serialization cannot fail");
    format!("{} {arguments}", input.program)
}

fn local_gate_validation_plan(
    commands: &[LocalGateCommand],
) -> Result<validation_receipt::ValidationPlan, String> {
    validation_receipt::ValidationPlan::new(
        commands
            .iter()
            .enumerate()
            .map(|(index, command)| {
                (
                    format!("local-gate/{:04}", index + 1),
                    render_local_gate_command(command),
                )
            })
            .collect(),
    )
}

fn source_quality_validation_plan(
    commands: &[LocalGateCommand],
) -> Result<validation_receipt::ValidationPlan, String> {
    local_gate_validation_plan(commands)?
        .with_step(SOURCE_CANDIDATE_STEP_ID, SOURCE_CANDIDATE_STEP_COMMAND)
}

fn source_validation_subject(
    identity: &candidate_seal::CandidateIdentity,
) -> Result<validation_receipt::ValidationSubject, String> {
    validation_receipt::ValidationSubject::git_commit_tree(
        SOURCE_VALIDATION_SUBJECT_NAMESPACE,
        &identity.git_object_format,
        &identity.source_commit,
        &identity.source_tree_oid,
    )
}

fn capture_package_input_id(
    root: &Path,
    input: &LocalGateReceiptInput,
) -> Result<validation_receipt::ValidationSubject, String> {
    let rendered = render_receipt_input_command(input);
    let output = Command::new(&input.program)
        .args(&input.arguments)
        .current_dir(root)
        .env("CARGO_INCREMENTAL", "1")
        .output()
        .map_err(|error| {
            format!("failed to launch package-owned input-id command {rendered}: {error}")
        })?;
    if !output.status.success() {
        return Err(format!(
            "package-owned input-id command failed with {}: {rendered}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if output.stdout.len() > 1024 || output.stderr.len() > 64 * 1024 {
        return Err("package-owned input-id output exceeds its closed size limit".to_owned());
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|error| format!("package-owned input-id output is not UTF-8: {error}"))?;
    let digest = stdout
        .strip_suffix("\r\n")
        .or_else(|| stdout.strip_suffix('\n'))
        .ok_or_else(|| "package-owned input-id must end with one newline".to_owned())?;
    if digest.contains(['\r', '\n']) {
        return Err("package-owned input-id must contain exactly one line".to_owned());
    }
    validation_receipt::ValidationSubject::content_closure(&input.namespace, digest)
}

fn has_required_distribution_evidence_check(discovered: &DiscoveredLocalGate) -> bool {
    discovered.checks.iter().any(|check| {
        check
            .package_spec
            .split_once('@')
            .is_some_and(|(name, version)| name == "distribution-evidence" && !version.is_empty())
            && check.name == "distribution-evidence"
            && check.bin == "distribution-evidence"
            && check.arguments == ["check"]
            && check
                .input_id_arguments
                .as_deref()
                .is_some_and(|arguments| arguments == ["input-id"])
    })
}

fn run_local_gate_command(root: &Path, command: &LocalGateCommand) -> Result<(), String> {
    let rendered = render_local_gate_command(command);
    let status = Command::new(&command.program)
        .args(&command.arguments)
        .current_dir(root)
        .env("CARGO_INCREMENTAL", "1")
        .status()
        .map_err(|error| format!("failed to launch {rendered}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "local gate command failed with {status}: {rendered}"
        ))
    }
}

fn run_local_gate_commands_with_receipts(
    root: &Path,
    commands: &[LocalGateCommand],
    allow_validation_receipts: bool,
) -> Result<LocalGateValidation, String> {
    let total_started = Instant::now();
    let mut validation = LocalGateValidation::default();
    for (index, command) in commands.iter().enumerate() {
        let rendered = render_local_gate_command(command);
        eprintln!("[{}/{}] {rendered}", index + 1, commands.len());
        let stage_started = Instant::now();
        let reused = if allow_validation_receipts {
            match command.receipt_input.as_ref() {
                Some(input) => {
                    let receipt_plan = validation_receipt::ValidationPlan::new(vec![(
                        format!("package-check/{}", input.namespace),
                        format!(
                            "{rendered}; input-id {}",
                            render_receipt_input_command(input)
                        ),
                    )])?;
                    let outcome = validation_receipt::validate_or_run(
                        root,
                        &receipt_plan,
                        || capture_package_input_id(root, input),
                        || run_local_gate_command(root, command),
                    )?;
                    if let Some(content_sha256) = outcome
                        .subject
                        .as_ref()
                        .and_then(validation_receipt::ValidationSubject::content_sha256)
                    {
                        validation
                            .receipt_inputs
                            .insert(input.namespace.clone(), content_sha256.to_owned());
                    }
                    outcome.reused
                }
                None => {
                    run_local_gate_command(root, command)?;
                    false
                }
            }
        } else {
            run_local_gate_command(root, command)?;
            false
        };
        let stage_elapsed = stage_started.elapsed();
        eprintln!(
            "[{}/{}] passed in {:.3}s{}",
            index + 1,
            commands.len(),
            stage_elapsed.as_secs_f64(),
            if reused { " (validation receipt)" } else { "" }
        );
    }
    eprintln!(
        "local gate commands passed in {:.3}s total",
        total_started.elapsed().as_secs_f64()
    );
    Ok(validation)
}

fn run_local_gate_commands(root: &Path, commands: &[LocalGateCommand]) -> Result<(), String> {
    run_local_gate_commands_with_receipts(root, commands, false).map(|_| ())
}

fn run_local_gate(root: &Path) -> Result<(), String> {
    let _lock = validation_receipt::acquire_local_ci_lock(root)?;
    let discovered = discover_local_gate(root)?;
    run_local_gate_commands_with_receipts(root, &local_gate_commands(&discovered), true).map(|_| ())
}

fn run_source_quality(root: &Path) -> Result<SourceQualityOutcome, String> {
    let _lock = validation_receipt::acquire_local_ci_lock(root)?;
    ensure_clean_checkout(root)?;
    let before = candidate_seal::capture_current_identity(root)?;
    let discovered = discover_local_gate(root)?;
    if !has_required_distribution_evidence_check(&discovered) {
        return Err(
            "source-quality candidate sealing requires the exact package-owned distribution-evidence check"
                .to_owned(),
        );
    }
    let commands = local_gate_commands(&discovered);
    let plan = source_quality_validation_plan(&commands)?;
    let mut sealed = None;
    let composition = validation_receipt::validate_or_run(
        root,
        &plan,
        || {
            ensure_clean_checkout(root)?;
            source_validation_subject(&candidate_seal::capture_current_identity(root)?)
        },
        || {
            let validation = run_local_gate_commands_with_receipts(root, &commands, true)?;
            let candidate = match validation
                .receipt_inputs
                .get(DISTRIBUTION_EVIDENCE_RECEIPT_TARGET)
            {
                Some(evidence_input) => {
                    candidate_seal::run_ephemeral_after_validated_distribution_evidence(
                        root,
                        evidence_input,
                    )?
                }
                None => candidate_seal::run_ephemeral(root)?,
            };
            if candidate != before {
                return Err(format!(
                    "source identity changed during source-quality validation; expected commit {} tree {}, sealed commit {} tree {}",
                    before.source_commit,
                    before.source_tree_oid,
                    candidate.source_commit,
                    candidate.source_tree_oid
                ));
            }
            sealed = Some(candidate);
            Ok(())
        },
    )?;
    if composition.reused {
        eprintln!(
            "reused exact-commit source-quality validation receipt for {}",
            before.source_commit
        );
    }
    ensure_clean_checkout(root)?;
    let after = candidate_seal::capture_current_identity(root)?;
    if after != before {
        return Err("source identity changed after source-quality validation".to_owned());
    }
    Ok(SourceQualityOutcome {
        candidate: sealed.unwrap_or(before),
        reused: composition.reused,
    })
}

fn parse_windows_native_test_suite(value: &OsStr) -> Result<WindowsNativeTestSuite, String> {
    match value.to_str() {
        Some("all") => Ok(WindowsNativeTestSuite::All),
        Some("semantic") => Ok(WindowsNativeTestSuite::Semantic),
        Some("guarded-rename") => Ok(WindowsNativeTestSuite::GuardedRename),
        Some(other) => Err(format!(
            "unsupported Windows-native test suite {other:?}; expected all, semantic, or guarded-rename"
        )),
        None => Err("Windows-native test suite is not valid UTF-8".to_owned()),
    }
}

fn windows_native_test_commands(suite: WindowsNativeTestSuite) -> Vec<&'static CommandSpec> {
    let mut commands = Vec::new();
    if matches!(
        suite,
        WindowsNativeTestSuite::All | WindowsNativeTestSuite::Semantic
    ) {
        commands.extend(WINDOWS_NATIVE_SEMANTIC_TESTS);
    }
    if matches!(
        suite,
        WindowsNativeTestSuite::All | WindowsNativeTestSuite::GuardedRename
    ) {
        commands.push(&WINDOWS_GUARDED_RENAME_TEST);
    }
    commands
}

fn removes_ambient_autocad_mcp_environment(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    name.to_ascii_uppercase().starts_with("AUTOCAD_MCP_")
        && !name.eq_ignore_ascii_case(WINDOWS_GUARDED_RENAME_EVIDENCE_ENV)
}

fn run_windows_native_tests_with<F>(
    root: &Path,
    platform: &str,
    suite: WindowsNativeTestSuite,
    mut run: F,
) -> Result<(), String>
where
    F: FnMut(&Path, &CommandSpec) -> Result<(), String>,
{
    if platform != "windows" {
        return Err(
            "windows-native-tests requires a native Windows host; it does not cross-compile or launch AutoCAD"
                .to_owned(),
        );
    }

    let commands = windows_native_test_commands(suite);
    let mut failures = Vec::new();
    for (index, command) in commands.iter().enumerate() {
        eprintln!(
            "[{}/{}] {} {}",
            index + 1,
            commands.len(),
            command.program,
            command.arguments.join(" ")
        );
        if let Err(error) = run(root, command) {
            eprintln!("[{}/{}] FAILED: {error}", index + 1, commands.len());
            failures.push(format!(
                "[{}/{}] {} {}: {error}",
                index + 1,
                commands.len(),
                command.program,
                command.arguments.join(" ")
            ));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} Windows-native test command(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        ))
    }
}

fn run_windows_native_tests(root: &Path, suite: WindowsNativeTestSuite) -> Result<(), String> {
    run_windows_native_tests_with(root, std::env::consts::OS, suite, |root, command| {
        let mut process = Command::new(command.program);
        process
            .args(command.arguments)
            .current_dir(root)
            .env("CARGO_INCREMENTAL", "0");
        for (name, _) in std::env::vars_os() {
            if removes_ambient_autocad_mcp_environment(&name) {
                process.env_remove(name);
            }
        }
        let status = process.status().map_err(|error| {
            format!(
                "failed to launch {} {}: {error}",
                command.program,
                command.arguments.join(" ")
            )
        })?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "Windows-native test command failed with {status}: {} {}",
                command.program,
                command.arguments.join(" ")
            ))
        }
    })
}

fn windows_native_semantic_input_sha256(root: &Path) -> Result<String, String> {
    validation_receipt::tracked_paths_sha256(
        root,
        &[
            "Cargo.lock",
            "Cargo.toml",
            "rust-toolchain.toml",
            "crates",
            "tests/fixtures",
            ".github/workflows/windows-native-harness.yml",
        ],
    )
}

fn run_windows_native_semantic_tests_with_receipt(root: &Path) -> Result<bool, String> {
    if std::env::consts::OS != "windows" {
        return Err(
            "Windows semantic validation receipts require a native Windows host".to_owned(),
        );
    }
    ensure_clean_checkout_for(root, "Windows validation-receipt validation")?;
    let rendered_commands = WINDOWS_NATIVE_SEMANTIC_TESTS
        .iter()
        .map(|command| format!("{} {}", command.program, command.arguments.join(" ")))
        .collect::<Vec<_>>();
    let plan = validation_receipt::ValidationPlan::new(
        rendered_commands
            .iter()
            .enumerate()
            .map(|(index, command)| {
                (
                    format!("windows-semantic/{:04}", index + 1),
                    command.clone(),
                )
            })
            .collect(),
    )?;
    let outcome = validation_receipt::validate_or_run(
        root,
        &plan,
        || {
            validation_receipt::ValidationSubject::content_closure(
                WINDOWS_NATIVE_SEMANTIC_RECEIPT_TARGET,
                &windows_native_semantic_input_sha256(root)?,
            )
        },
        || run_windows_native_tests(root, WindowsNativeTestSuite::Semantic),
    )?;
    ensure_clean_checkout_for(root, "Windows validation-receipt validation")?;
    Ok(outcome.reused)
}

fn report_windows_native_tests(
    suite: WindowsNativeTestSuite,
    allow_validation_receipt: bool,
) -> ExitCode {
    let result = if allow_validation_receipt {
        if suite != WindowsNativeTestSuite::Semantic {
            Err(
                "Windows validation receipts are supported only for the closed semantic suite"
                    .to_owned(),
            )
        } else {
            run_windows_native_semantic_tests_with_receipt(&repository_root()).map(|reused| {
                if reused {
                    eprintln!("reused exact-content Windows semantic validation receipt");
                }
            })
        }
    } else {
        run_windows_native_tests(&repository_root(), suite)
    };
    match result {
        Ok(()) => {
            eprintln!("Windows-native non-AutoCAD tests passed");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::FAILURE
        }
    }
}

fn git_output(root: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = git_command(root)
        .args(arguments)
        .output()
        .map_err(|error| format!("failed to launch git {}: {error}", arguments.join(" ")))?;
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

fn git_command(root: &Path) -> Command {
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
    command.env_clear().current_dir(root);
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

fn ensure_clean_checkout_for(root: &Path, label: &str) -> Result<(), String> {
    let status = git_output(root, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    if status.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{label} requires a clean checkout; commit or remove these paths:\n{status}"
        ))
    }
}

fn ensure_clean_checkout(root: &Path) -> Result<(), String> {
    ensure_clean_checkout_for(root, "pre-push validation")
}

fn parse_push_updates(input: &str) -> Result<Vec<PushUpdate>, String> {
    input
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 4 {
                return Err(format!(
                    "invalid pre-push record on line {}: expected four fields",
                    index + 1
                ));
            }
            Ok(PushUpdate {
                local_ref: fields[0].to_owned(),
                local_oid: fields[1].to_owned(),
                remote_ref: fields[2].to_owned(),
            })
        })
        .collect()
}

fn is_zero_oid(oid: &str) -> bool {
    !oid.is_empty() && oid.bytes().all(|byte| byte == b'0')
}

fn validate_push_updates<F>(
    updates: &[PushUpdate],
    expected_head: &str,
    mut resolve_commit: F,
) -> Result<bool, String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    let mut has_non_deletion = false;
    for update in updates {
        if is_zero_oid(&update.local_oid) {
            continue;
        }
        has_non_deletion = true;
        let commit = resolve_commit(&update.local_oid).map_err(|error| {
            format!(
                "cannot validate pushed ref {} -> {}: {error}",
                update.local_ref, update.remote_ref
            )
        })?;
        if commit != expected_head {
            return Err(format!(
                "pushed ref {} -> {} resolves to {commit}, but the clean checked-out HEAD is {expected_head}; check out the ref being pushed and retry",
                update.local_ref, update.remote_ref
            ));
        }
    }
    Ok(has_non_deletion)
}

#[derive(Debug)]
struct PreparedPrePush {
    head_before: String,
    identity_before: candidate_seal::CandidateIdentity,
}

fn prepare_pre_push(root: &Path, input: &str) -> Result<Option<PreparedPrePush>, String> {
    let updates = parse_push_updates(input)?;
    if updates.iter().all(|update| is_zero_oid(&update.local_oid)) {
        return Ok(None);
    }

    let head_before = git_output(root, &["rev-parse", "--verify", "HEAD"])?;
    ensure_clean_checkout(root)?;
    let identity_before = candidate_seal::capture_current_identity(root)?;
    if identity_before.source_commit != head_before {
        return Err("candidate identity and pushed HEAD disagree before validation".to_owned());
    }
    let has_non_deletion = validate_push_updates(&updates, &head_before, |oid| {
        let revision = format!("{oid}^{{commit}}");
        git_output(root, &["rev-parse", "--verify", &revision])
    })?;
    if !has_non_deletion {
        return Ok(None);
    }
    Ok(Some(PreparedPrePush {
        head_before,
        identity_before,
    }))
}

fn finish_pre_push(
    root: &Path,
    prepared: &PreparedPrePush,
    validated: &candidate_seal::CandidateIdentity,
) -> Result<Option<String>, String> {
    if validated != &prepared.identity_before {
        return Err(format!(
            "pre-push validated source identity does not match the exact pushed HEAD; expected commit {} tree {}, validated commit {} tree {}",
            prepared.identity_before.source_commit,
            prepared.identity_before.source_tree_oid,
            validated.source_commit,
            validated.source_tree_oid
        ));
    }
    let head_after = git_output(root, &["rev-parse", "--verify", "HEAD"])?;
    if head_after != prepared.head_before {
        return Err(format!(
            "HEAD changed during pre-push validation ({} -> {head_after}); retry the push",
            prepared.head_before
        ));
    }
    ensure_clean_checkout(root)?;
    Ok(Some(prepared.head_before.clone()))
}

#[derive(Debug, Eq, PartialEq)]
enum FullGateReceiptRecapture<T> {
    Stable(T),
    Changed,
    Unavailable(String),
}

fn classify_full_gate_receipt_recapture<T: PartialEq>(
    before: &T,
    after: Result<T, String>,
) -> FullGateReceiptRecapture<T> {
    match after {
        Ok(after) if &after == before => FullGateReceiptRecapture::Stable(after),
        Ok(_) => FullGateReceiptRecapture::Changed,
        Err(error) => FullGateReceiptRecapture::Unavailable(error),
    }
}

fn rapid_pre_push_commands() -> Vec<LocalGateCommand> {
    vec![
        LocalGateCommand::new("git", &["diff", "--check"]),
        LocalGateCommand::new("git", &["diff", "--cached", "--check"]),
        LocalGateCommand::new("cargo", &["fmt", "--all", "--", "--check"]),
    ]
}

fn run_pre_push(root: &Path, input: &str) -> Result<Option<String>, String> {
    run_rapid_pre_push_with(
        root,
        input,
        |root| run_local_gate_commands(root, &rapid_pre_push_commands()),
        candidate_seal::capture_current_identity,
    )
}

fn run_rapid_pre_push_with<G, O>(
    root: &Path,
    input: &str,
    mut gate: G,
    mut observe_source: O,
) -> Result<Option<String>, String>
where
    G: FnMut(&Path) -> Result<(), String>,
    O: FnMut(&Path) -> Result<candidate_seal::CandidateIdentity, String>,
{
    let Some(prepared) = prepare_pre_push(root, input)? else {
        return Ok(None);
    };
    gate(root)?;
    let observed = observe_source(root)?;
    finish_pre_push(root, &prepared, &observed)
}

fn run_full_pre_push(root: &Path, input: &str) -> Result<Option<String>, String> {
    let Some(prepared) = prepare_pre_push(root, input)? else {
        return Ok(None);
    };
    let discovered = discover_local_gate(root)?;
    if !has_required_distribution_evidence_check(&discovered) {
        return Err(
            "pre-push candidate sealing requires the exact package-owned distribution-evidence check"
                .to_owned(),
        );
    }
    let commands = local_gate_commands(&discovered);
    let receipt_plan = local_gate_validation_plan(&commands)?;
    let receipt_subject = source_validation_subject(&prepared.identity_before)?;
    let receipt_inputs = match validation_receipt::capture_validation(
        root,
        receipt_subject.clone(),
        receipt_plan.clone(),
    ) {
        Ok(inputs) => Some(inputs),
        Err(error) => {
            eprintln!("advisory validation receipt unavailable; running full gate: {error}");
            None
        }
    };
    if let Some(before) = receipt_inputs.as_ref() {
        if validation_receipt::receipt_hit(root, before) {
            eprintln!(
                "exact-commit validation receipt matched {}; reusing its completed local-gate subset before fresh distribution-evidence and source-candidate checks",
                prepared.head_before
            );
            let sealed = candidate_seal::run_ephemeral(root)?;
            let after = validation_receipt::capture_validation(
                root,
                receipt_subject.clone(),
                receipt_plan.clone(),
            )
            .map_err(|error| {
                format!(
                    "validation receipt inputs could not be recaptured after source-candidate validation: {error}"
                )
            })?;
            if &after != before {
                return Err(
                    "validation receipt inputs changed during source-candidate validation; retry the push"
                        .to_owned(),
                );
            }
            return finish_pre_push(root, &prepared, &sealed);
        }
    }

    run_local_gate_commands(root, &commands)?;
    let sealed = candidate_seal::run_ephemeral(root)?;
    finish_pre_push(root, &prepared, &sealed)?;

    if let Some(before) = receipt_inputs {
        match classify_full_gate_receipt_recapture(
            &before,
            validation_receipt::capture_validation(root, receipt_subject, receipt_plan),
        ) {
            FullGateReceiptRecapture::Stable(after) => {
                match validation_receipt::record_receipt(root, &after) {
                    Ok(path) => {
                        eprintln!(
                            "recorded advisory local-gate validation receipt {}",
                            path.display()
                        )
                    }
                    Err(error) => {
                        eprintln!("advisory validation receipt was not recorded: {error}")
                    }
                }
            }
            FullGateReceiptRecapture::Changed => {
                eprintln!(
                    "advisory validation receipt was not recorded because its context changed during the successful full gate"
                );
            }
            FullGateReceiptRecapture::Unavailable(error) => {
                eprintln!(
                    "advisory validation receipt was not recorded because its context could not be recaptured: {error}"
                );
            }
        }
    }
    Ok(Some(prepared.head_before))
}

fn verify_current_distribution(
    root: &Path,
    candidate_directory: &Path,
    approval_path: &Path,
    mcpb_path: &Path,
    source_closure_sbom_path: &Path,
    build_attestation_path: &Path,
    clean_host_receipt_path: Option<&Path>,
) -> Result<CurrentDistributionVerification, String> {
    let candidate = candidate_seal::verify(root, candidate_directory)?;
    let report = verify_owner_distribution_approval(&ApprovalVerificationOptions {
        approval_path: approval_path.to_path_buf(),
        mcpb_path: mcpb_path.to_path_buf(),
        source_archive_path: candidate_directory.join("source.zip"),
        source_closure_sbom_path: source_closure_sbom_path.to_path_buf(),
        build_attestation_path: build_attestation_path.to_path_buf(),
    })
    .map_err(|error| format!("verify approval-bound distribution set: {error:#}"))?;
    ensure_approval_matches_candidate(&candidate, &report)?;
    let clean_host = match (report.package_mode, clean_host_receipt_path) {
        (DistributionMode::Preview, Some(receipt_path)) => {
            let verified =
                verify_preview_clean_host_receipt(&PreviewCleanHostVerificationOptions {
                    approval_path: approval_path.to_path_buf(),
                    mcpb_path: mcpb_path.to_path_buf(),
                    receipt_path: receipt_path.to_path_buf(),
                })
                .map_err(|error| format!("verify Preview clean-host acceptance: {error:#}"))?;
            if verified.decision_id != report.decision_id
                || verified.mcpb_sha256 != report.mcpb_sha256
                || !verified.clean_host_acceptance_verified
            {
                return Err(
                    "clean-host receipt verification did not join the selected approval and MCPB"
                        .to_owned(),
                );
            }
            Some((receipt_path, verified))
        }
        (DistributionMode::Preview, None) => {
            return Err(
                "Preview current-distribution selection requires --clean-host-receipt".to_owned(),
            )
        }
        (DistributionMode::Release, Some(_)) => {
            return Err(
                "the current clean-host receipt contract is Preview-only; omit it for Release"
                    .to_owned(),
            )
        }
        (DistributionMode::Release, None) => None,
    };
    let mut named_artifacts = vec![
        StableNamedArtifact::open(
            approval_path,
            "owner distribution approval",
            &report.approval_sha256,
        )?,
        StableNamedArtifact::open(mcpb_path, "MCPB", &report.mcpb_sha256)?,
        StableNamedArtifact::open(
            &candidate_directory.join("source.zip"),
            "source archive",
            &report.source_archive_sha256,
        )?,
        StableNamedArtifact::open(
            source_closure_sbom_path,
            "source-closure SBOM",
            &report.source_closure_sbom_sha256,
        )?,
        StableNamedArtifact::open(
            build_attestation_path,
            "build attestation",
            &report.build_attestation_sha256,
        )?,
    ];
    if let Some((receipt_path, clean_host)) = &clean_host {
        named_artifacts.push(StableNamedArtifact::open(
            receipt_path,
            "clean-host acceptance receipt",
            &clean_host.receipt_sha256,
        )?);
    }
    let final_candidate = candidate_seal::recheck_recorded_current(root, candidate_directory)?;
    if final_candidate != candidate {
        return Err("source candidate changed during distribution verification".to_owned());
    }
    for artifact in &named_artifacts {
        artifact.verify_still_named()?;
    }
    candidate_seal::capture_current_identity(root).and_then(|current| {
        if current == candidate.candidate {
            Ok(())
        } else {
            Err("source changed after current distribution verification".to_owned())
        }
    })?;
    Ok(CurrentDistributionVerification {
        schema_version: 1,
        kind: "current_distribution_verification",
        current_source_candidate_verified: true,
        approval_distribution_set_verified: true,
        exact_candidate_identity_joined: true,
        native_build_attestation_semantics_verified: report
            .native_build_attestation_semantics_verified,
        clean_host_acceptance_verified: clean_host
            .as_ref()
            .is_some_and(|(_, report)| report.clean_host_acceptance_verified),
        package_mode: candidate.package_mode,
        decision_id: report.decision_id,
        candidate: candidate.candidate,
        approval_sha256: report.approval_sha256,
        mcpb_sha256: report.mcpb_sha256,
        source_archive_sha256: report.source_archive_sha256,
        source_closure_sbom_sha256: report.source_closure_sbom_sha256,
        build_attestation_sha256: report.build_attestation_sha256,
        clean_host_receipt_sha256: clean_host.map(|(_, report)| report.receipt_sha256),
    })
}

struct StableNamedArtifact {
    path: PathBuf,
    label: &'static str,
    file: File,
    metadata: Metadata,
}

impl StableNamedArtifact {
    fn open(path: &Path, label: &'static str, expected_sha256: &str) -> Result<Self, String> {
        let before = fs::symlink_metadata(path)
            .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
        if before.file_type().is_symlink() || !before.is_file() {
            return Err(format!(
                "{label} must be a regular non-symlink file: {}",
                path.display()
            ));
        }
        let mut file = File::open(path)
            .map_err(|error| format!("open {label} {}: {error}", path.display()))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("inspect open {label}: {error}"))?;
        verify_file_identity(&before, &metadata, label)?;
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
            bytes = bytes
                .checked_add(read as u64)
                .ok_or_else(|| format!("{label} size overflow"))?;
            digest.update(&buffer[..read]);
        }
        let actual_sha256 = format!("{:x}", digest.finalize());
        if bytes != metadata.len() || actual_sha256 != expected_sha256 {
            return Err(format!(
                "currently named {label} does not match the verified artifact digest"
            ));
        }
        let artifact = Self {
            path: path.to_path_buf(),
            label,
            file,
            metadata,
        };
        artifact.verify_still_named()?;
        Ok(artifact)
    }

    fn verify_still_named(&self) -> Result<(), String> {
        let named = fs::symlink_metadata(&self.path).map_err(|error| {
            format!("reinspect {} {}: {error}", self.label, self.path.display())
        })?;
        if named.file_type().is_symlink() || !named.is_file() {
            return Err(format!("{} path changed during verification", self.label));
        }
        let opened = self
            .file
            .metadata()
            .map_err(|error| format!("reinspect open {}: {error}", self.label))?;
        verify_file_identity(&self.metadata, &opened, self.label)?;
        verify_file_identity(&self.metadata, &named, self.label)
    }
}

#[cfg(unix)]
fn verify_file_identity(expected: &Metadata, actual: &Metadata, label: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    if expected.dev() == actual.dev()
        && expected.ino() == actual.ino()
        && expected.nlink() == 1
        && actual.nlink() == 1
    {
        Ok(())
    } else {
        Err(format!(
            "{label} identity changed or has multiple hard links"
        ))
    }
}

#[cfg(not(unix))]
fn verify_file_identity(expected: &Metadata, actual: &Metadata, label: &str) -> Result<(), String> {
    if expected.len() == actual.len()
        && expected.modified().ok() == actual.modified().ok()
        && expected.created().ok() == actual.created().ok()
    {
        Ok(())
    } else {
        Err(format!("{label} identity changed during verification"))
    }
}

fn ensure_approval_matches_candidate(
    candidate: &candidate_seal::SourceCandidateVerification,
    approval: &ApprovalVerificationReport,
) -> Result<(), String> {
    if approval.package_mode == candidate.package_mode
        && approval.git_object_format == candidate.candidate.git_object_format
        && approval.source_commit == candidate.candidate.source_commit
        && approval.source_tree_oid == candidate.candidate.source_tree_oid
        && approval.source_archive_sha256 == candidate.source_bundle_sha256
        && approval.source_bundle_manifest_sha256 == candidate.source_bundle_manifest_sha256
        && approval.cargo_lock_sha256 == candidate.cargo_lock_sha256
        && approval.dependency_input_closure_sha256 == candidate.dependency_input_closure_sha256
        && approval.rust_toolchain_sha256 == candidate.rust_toolchain_sha256
        && approval.build_recipe_sha256 == candidate.build_recipe_sha256
    {
        Ok(())
    } else {
        Err(
            "approval-bound distribution set belongs to a different source candidate; regenerate every release artifact and reissue owner approval"
                .to_owned(),
        )
    }
}

fn parse_distribution_mode(value: &OsStr) -> Result<DistributionMode, String> {
    match value.to_str() {
        Some("release") => Ok(DistributionMode::Release),
        Some("preview") => Ok(DistributionMode::Preview),
        Some(other) => Err(format!(
            "unsupported package mode {other:?}; expected release or preview"
        )),
        None => Err("package mode is not valid UTF-8".to_owned()),
    }
}

#[cfg(test)]
fn run_full_pre_push_with<G, S>(
    root: &Path,
    input: &str,
    mut gate: G,
    mut seal_source: S,
) -> Result<Option<String>, String>
where
    G: FnMut(&Path) -> Result<(), String>,
    S: FnMut(&Path) -> Result<candidate_seal::CandidateIdentity, String>,
{
    let Some(prepared) = prepare_pre_push(root, input)? else {
        return Ok(None);
    };

    gate(root)?;
    let sealed = seal_source(root)?;
    finish_pre_push(root, &prepared, &sealed)
}

fn main() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, output_flag, output]
            if command == "windows-source-bundle" && output_flag == "--output" =>
        {
            match source_bundle::run(&repository_root(), Path::new(output)) {
                Ok(summary) => match serde_json::to_string(&summary) {
                    Ok(summary) => {
                        println!("{summary}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("ERROR: serialize Windows source bundle summary: {error}");
                        ExitCode::FAILURE
                    }
                },
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [command, output_flag, output, mode_flag, mode]
            if command == "windows-source-bundle"
                && output_flag == "--output"
                && mode_flag == "--mode" =>
        {
            match parse_distribution_mode(mode).and_then(|mode| {
                source_bundle::run_for_mode(&repository_root(), Path::new(output), mode)
            }) {
                Ok(summary) => match serde_json::to_string(&summary) {
                    Ok(summary) => {
                        println!("{summary}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("ERROR: serialize Windows source bundle summary: {error}");
                        ExitCode::FAILURE
                    }
                },
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [command, output_flag, output]
            if command == "source-candidate-seal" && output_flag == "--output-dir" =>
        {
            match candidate_seal::run(&repository_root(), Path::new(output)) {
                Ok(summary) => match serde_json::to_string(&summary) {
                    Ok(summary) => {
                        println!("{summary}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("ERROR: serialize source candidate summary: {error}");
                        ExitCode::FAILURE
                    }
                },
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [command, output_flag, output, mode_flag, mode]
            if command == "source-candidate-seal"
                && output_flag == "--output-dir"
                && mode_flag == "--mode" =>
        {
            match parse_distribution_mode(mode).and_then(|mode| {
                candidate_seal::run_for_mode(&repository_root(), Path::new(output), mode)
            }) {
                Ok(summary) => match serde_json::to_string(&summary) {
                    Ok(summary) => {
                        println!("{summary}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("ERROR: serialize source candidate summary: {error}");
                        ExitCode::FAILURE
                    }
                },
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [command, candidate_flag, candidate]
            if command == "source-candidate-verify" && candidate_flag == "--candidate-dir" =>
        {
            match candidate_seal::verify_for_mode(
                &repository_root(),
                Path::new(candidate),
                DistributionMode::Release,
            ) {
                Ok(summary) => match serde_json::to_string(&summary) {
                    Ok(summary) => {
                        println!("{summary}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("ERROR: serialize source candidate verification: {error}");
                        ExitCode::FAILURE
                    }
                },
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [command, candidate_flag, candidate, mode_flag, mode]
            if command == "source-candidate-verify"
                && candidate_flag == "--candidate-dir"
                && mode_flag == "--mode" =>
        {
            match parse_distribution_mode(mode).and_then(|mode| {
                candidate_seal::verify_for_mode(&repository_root(), Path::new(candidate), mode)
            }) {
                Ok(summary) => match serde_json::to_string(&summary) {
                    Ok(summary) => {
                        println!("{summary}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("ERROR: serialize source candidate verification: {error}");
                        ExitCode::FAILURE
                    }
                },
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [command, candidate_flag, candidate, approval_flag, approval, mcpb_flag, mcpb, sbom_flag, sbom, attestation_flag, attestation, clean_host_flag, clean_host]
            if command == "current-distribution-verify"
                && candidate_flag == "--candidate-dir"
                && approval_flag == "--approval"
                && mcpb_flag == "--mcpb"
                && sbom_flag == "--source-closure-sbom"
                && attestation_flag == "--build-attestation"
                && clean_host_flag == "--clean-host-receipt" =>
        {
            match verify_current_distribution(
                &repository_root(),
                Path::new(candidate),
                Path::new(approval),
                Path::new(mcpb),
                Path::new(sbom),
                Path::new(attestation),
                Some(Path::new(clean_host)),
            ) {
                Ok(summary) => match serde_json::to_string(&summary) {
                    Ok(summary) => {
                        println!("{summary}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("ERROR: serialize current distribution verification: {error}");
                        ExitCode::FAILURE
                    }
                },
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [command, candidate_flag, candidate, approval_flag, approval, mcpb_flag, mcpb, sbom_flag, sbom, attestation_flag, attestation]
            if command == "current-distribution-verify"
                && candidate_flag == "--candidate-dir"
                && approval_flag == "--approval"
                && mcpb_flag == "--mcpb"
                && sbom_flag == "--source-closure-sbom"
                && attestation_flag == "--build-attestation" =>
        {
            match verify_current_distribution(
                &repository_root(),
                Path::new(candidate),
                Path::new(approval),
                Path::new(mcpb),
                Path::new(sbom),
                Path::new(attestation),
                None,
            ) {
                Ok(summary) => match serde_json::to_string(&summary) {
                    Ok(summary) => {
                        println!("{summary}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("ERROR: serialize current distribution verification: {error}");
                        ExitCode::FAILURE
                    }
                },
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [command] if command == "local-gate" => match run_local_gate(&repository_root()) {
            Ok(()) => {
                eprintln!("local development gate passed");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("ERROR: {error}");
                ExitCode::FAILURE
            }
        },
        [command] if command == "source-quality" => match run_source_quality(&repository_root()) {
            Ok(outcome) => {
                if outcome.reused {
                    eprintln!(
                        "exact-commit source-quality validation was reused for {}",
                        outcome.candidate.source_commit
                    );
                } else {
                    eprintln!(
                        "source-quality gate and exact Release/Preview candidate regeneration passed for {}",
                        outcome.candidate.source_commit
                    );
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("ERROR: {error}");
                ExitCode::FAILURE
            }
        },
        [command] if command == "windows-native-tests" => {
            report_windows_native_tests(WindowsNativeTestSuite::All, false)
        }
        [command, suite_flag, suite]
            if command == "windows-native-tests" && suite_flag == "--suite" =>
        {
            match parse_windows_native_test_suite(suite) {
                Ok(suite) => report_windows_native_tests(suite, false),
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::from(2)
                }
            }
        }
        [command, suite_flag, suite, receipt_flag]
            if command == "windows-native-tests"
                && suite_flag == "--suite"
                && receipt_flag == "--validation-receipt" =>
        {
            match parse_windows_native_test_suite(suite) {
                Ok(suite) => report_windows_native_tests(suite, true),
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::from(2)
                }
            }
        }
        [command, plan_flag, plan, work_flag, work_dir]
            if command == "preview-autocad-e2e"
                && plan_flag == "--plan"
                && work_flag == "--work-dir" =>
        {
            match preview_e2e::run(&repository_root(), Path::new(plan), Path::new(work_dir)) {
                Ok(summary) => match serde_json::to_string(&summary) {
                    Ok(serialized) => {
                        println!("{serialized}");
                        if summary.result == "evaluation_passed" {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::FAILURE
                        }
                    }
                    Err(error) => {
                        eprintln!("ERROR: serialize Preview AutoCAD E2E summary: {error}");
                        ExitCode::FAILURE
                    }
                },
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [command, _remote_name, _remote_location]
            if command == "pre-push" || command == "pre-push-full" =>
        {
            let pre_push_started = Instant::now();
            let full = command == "pre-push-full";
            let mode = if full { "full" } else { "rapid" };
            let mut input = String::new();
            if let Err(error) = std::io::stdin().read_to_string(&mut input) {
                eprintln!("ERROR: failed to read pre-push records: {error}");
                eprintln!(
                    "local {mode} pre-push command completed in {:.3}s",
                    pre_push_started.elapsed().as_secs_f64()
                );
                return ExitCode::FAILURE;
            }
            let result = if full {
                run_full_pre_push(&repository_root(), &input)
            } else {
                run_pre_push(&repository_root(), &input)
            };
            let exit_code = match result {
                Ok(Some(commit)) => {
                    eprintln!("local {mode} pre-push gate passed for {commit}");
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("local {mode} pre-push gate skipped: no commits are being pushed");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::FAILURE
                }
            };
            eprintln!(
                "local {mode} pre-push command completed in {:.3}s",
                pre_push_started.elapsed().as_secs_f64()
            );
            exit_code
        }
        [command, tier2_flag, tier2_manifest, xref_flag, xref_manifest]
            if command == "certification-manifest-preflight"
                && tier2_flag == "--tier2-manifest"
                && xref_flag == "--xref-manifest" =>
        {
            match windows_preflight::run_manifest_preflight(
                Path::new(tier2_manifest),
                Path::new(xref_manifest),
            ) {
                Ok(summary) => {
                    println!("{summary}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [command, arg_flag, arg_path, policy_flag, arg_policy, output_flag, output_dir]
            if command == "windows-certification-build-preflight"
                && arg_flag == "--arg"
                && policy_flag == "--arg-policy"
                && output_flag == "--output-dir" =>
        {
            match windows_preflight::run_windows_build_preflight(
                &repository_root(),
                Path::new(arg_path),
                Path::new(arg_policy),
                Path::new(output_dir),
            ) {
                Ok(summary) => {
                    println!("{summary}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!(
                "usage: cargo run --locked -p xtask -- windows-source-bundle --output <fresh-target-or-dist-path.zip> [--mode release|preview]\n       cargo run --locked -p xtask -- source-candidate-seal --output-dir <fresh-directory> [--mode release|preview]\n       cargo run --locked -p xtask -- source-candidate-verify --candidate-dir <sealed-directory> [--mode release|preview]\n       cargo run --locked -p xtask -- current-distribution-verify --candidate-dir <sealed-directory> --approval <owner-approval.json> --mcpb <package.mcpb> --source-closure-sbom <spdx.json> --build-attestation <attestation.json> [--clean-host-receipt <Preview-receipt.json>]\n       cargo run --locked -p xtask -- local-gate\n       cargo run --locked -p xtask -- source-quality\n       cargo run --locked -p xtask -- windows-native-tests [--suite all|semantic|guarded-rename] [--validation-receipt]\n       cargo run --locked -p xtask -- preview-autocad-e2e --plan <strict-plan.json> --work-dir <fresh-fixed-local-directory>\n       cargo run --locked -p xtask -- pre-push <remote-name> <remote-location>\n       cargo run --locked -p xtask -- pre-push-full <remote-name> <remote-location>\n       cargo run --locked -p xtask -- certification-manifest-preflight --tier2-manifest <schema-v3.json> --xref-manifest <schema-v4.json>\n       cargo run --locked -p xtask -- windows-certification-build-preflight --arg <profile.arg> --arg-policy <closed-policy.json> --output-dir <fresh-target-child>\n       Preview selection requires --clean-host-receipt; mode defaults to release when omitted"
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;

    fn test_repository() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("temporary repository");
        for arguments in [
            &[
                "init",
                "--quiet",
                "--initial-branch=main",
                "--object-format=sha1",
                ".",
            ][..],
            &["config", "user.name", "Candidate Test"][..],
            &["config", "user.email", "candidate@example.invalid"][..],
            &["config", "commit.gpgSign", "false"][..],
        ] {
            assert!(git_command(directory.path())
                .args(arguments)
                .status()
                .expect("launch git")
                .success());
        }
        fs::write(directory.path().join("source.txt"), b"source\n").expect("write source");
        assert!(git_command(directory.path())
            .args(["add", "--", "source.txt"])
            .status()
            .expect("launch git add")
            .success());
        assert!(git_command(directory.path())
            .args(["commit", "--quiet", "-m", "source"])
            .status()
            .expect("launch git commit")
            .success());
        directory
    }

    fn candidate_verification() -> candidate_seal::SourceCandidateVerification {
        candidate_seal::SourceCandidateVerification {
            current: true,
            exact_commit_and_tree: true,
            source_bundle_verified: true,
            release_authority: false,
            package_mode: DistributionMode::Release,
            candidate: candidate_seal::CandidateIdentity {
                git_object_format: "sha1".to_owned(),
                source_commit: "a".repeat(40),
                source_tree_oid: "b".repeat(40),
            },
            source_bundle_sha256: "c".repeat(64),
            source_bundle_manifest_sha256: "d".repeat(64),
            cargo_lock_sha256: "e".repeat(64),
            dependency_input_closure_sha256: "f".repeat(64),
            rust_toolchain_sha256: "1".repeat(64),
            build_recipe_sha256: "2".repeat(64),
        }
    }

    fn approval_report() -> ApprovalVerificationReport {
        ApprovalVerificationReport {
            decision_id: "decision".to_owned(),
            approval_sha256: "3".repeat(64),
            verified_artifacts: 6,
            mcpb_entries: 12,
            source_archive_entries: 34,
            distribution_evidence_validated: true,
            native_build_attestation_semantics_verified: false,
            package_mode: DistributionMode::Release,
            git_object_format: "sha1".to_owned(),
            source_commit: "a".repeat(40),
            source_tree_oid: "b".repeat(40),
            mcpb_sha256: "4".repeat(64),
            source_archive_sha256: "c".repeat(64),
            source_closure_sbom_sha256: "5".repeat(64),
            build_attestation_sha256: "6".repeat(64),
            source_bundle_manifest_sha256: "d".repeat(64),
            cargo_lock_sha256: "e".repeat(64),
            dependency_input_closure_sha256: "f".repeat(64),
            rust_toolchain_sha256: "1".repeat(64),
            build_recipe_sha256: "2".repeat(64),
        }
    }

    #[test]
    fn repository_root_is_discovered_from_the_runtime_checkout() {
        const CHILD: &str = "AUTOCAD_MCP_XTASK_ROOT_DISCOVERY_TEST_CHILD";
        const START: &str = "AUTOCAD_MCP_XTASK_ROOT_DISCOVERY_TEST_START";
        const EXPECTED: &str = "AUTOCAD_MCP_XTASK_ROOT_DISCOVERY_TEST_EXPECTED";
        const TEST_NAME: &str = "tests::repository_root_is_discovered_from_the_runtime_checkout";

        if std::env::var_os(CHILD).is_some() {
            let start = PathBuf::from(std::env::var_os(START).expect("child start path"));
            let expected =
                PathBuf::from(std::env::var_os(EXPECTED).expect("child expected repository"));
            let discovered =
                repository_root_from(&start).expect("discover root under hostile Git environment");
            assert_eq!(
                discovered,
                fs::canonicalize(expected).expect("canonical expected child repository")
            );
            return;
        }

        let repository = test_repository();
        let nested = repository.path().join("nested/runtime");
        fs::create_dir_all(&nested).expect("create nested runtime path");

        let discovered =
            repository_root_from(&nested).expect("discover temporary runtime repository");
        assert_eq!(
            fs::canonicalize(discovered).expect("canonical discovered repository"),
            fs::canonicalize(repository.path()).expect("canonical temporary repository")
        );

        let foreign = test_repository();
        let foreign_git_dir =
            fs::canonicalize(foreign.path().join(".git")).expect("canonical foreign Git directory");
        let child = Command::new(std::env::current_exe().expect("current xtask test executable"))
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD, "1")
            .env(START, &nested)
            .env(EXPECTED, repository.path())
            .env("GIT_DIR", &foreign_git_dir)
            .env("GIT_COMMON_DIR", &foreign_git_dir)
            .env("GIT_WORK_TREE", foreign.path())
            .env("GIT_INDEX_FILE", foreign_git_dir.join("index"))
            .env("GIT_OBJECT_DIRECTORY", foreign_git_dir.join("objects"))
            .output()
            .expect("launch hostile-environment root-discovery child");
        let child_stdout = String::from_utf8_lossy(&child.stdout);
        let child_stderr = String::from_utf8_lossy(&child.stderr);
        assert!(
            child.status.success()
                && child_stdout.contains("running 1 test")
                && child_stdout.contains(TEST_NAME),
            "hostile-environment root-discovery child failed with {}\nstdout:\n{}\nstderr:\n{}",
            child.status,
            child_stdout,
            child_stderr
        );
    }

    #[test]
    fn local_gate_discovers_package_owned_checks_and_profiles() {
        let metadata = serde_json::from_value(serde_json::json!({
            "workspace_members": ["path+file:///repo/crates/example#example@1.2.3"],
            "packages": [
                {
                    "id": "path+file:///repo/crates/example#example@1.2.3",
                    "name": "example",
                    "version": "1.2.3",
                    "features": {
                        "default": [],
                        "special": []
                    },
                    "targets": [
                        {
                            "name": "example",
                            "kind": ["lib"]
                        },
                        {
                            "name": "example-evidence",
                            "kind": ["bin"]
                        }
                    ],
                    "metadata": {
                        "local-gate": {
                            "schema-version": 1,
                            "checks": [
                                {
                                    "name": "evidence",
                                    "bin": "example-evidence",
                                    "arguments": ["check", "path with space"]
                                }
                            ],
                            "profiles": [
                                {
                                    "name": "special",
                                    "features": ["special"],
                                    "clippy": true,
                                    "test": true,
                                    "targets": ["bin:example-evidence", "lib"]
                                }
                            ]
                        }
                    }
                },
                {
                    "id": "registry+https://example.invalid#index@9.9.9",
                    "name": "ignored-dependency",
                    "version": "9.9.9",
                    "features": {},
                    "targets": [],
                    "metadata": {
                        "local-gate": {
                            "schema-version": 99
                        }
                    }
                }
            ]
        }))
        .expect("synthetic cargo metadata");

        let discovered =
            discover_local_gate_from_metadata(metadata).expect("discover package-owned local gate");
        assert_eq!(
            discovered,
            DiscoveredLocalGate {
                checks: vec![DiscoveredLocalGateCheck {
                    package_spec: "example@1.2.3".to_owned(),
                    name: "evidence".to_owned(),
                    bin: "example-evidence".to_owned(),
                    arguments: vec!["check".to_owned(), "path with space".to_owned()],
                    input_id_arguments: None,
                }],
                profiles: vec![DiscoveredLocalGateProfile {
                    package_spec: "example@1.2.3".to_owned(),
                    name: "special".to_owned(),
                    features: vec!["special".to_owned()],
                    clippy: true,
                    test: true,
                    targets: vec![
                        LocalGateProfileTarget::Lib,
                        LocalGateProfileTarget::Bin("example-evidence".to_owned()),
                    ],
                }],
            }
        );

        let commands = local_gate_commands(&discovered);
        assert_eq!(
            commands,
            vec![
                LocalGateCommand::new("git", &["diff", "--check"]),
                LocalGateCommand::new("git", &["diff", "--cached", "--check"]),
                LocalGateCommand::new(
                    "cargo",
                    &[
                        "run",
                        "--locked",
                        "-p",
                        "example@1.2.3",
                        "--bin",
                        "example-evidence",
                        "--",
                        "check",
                        "path with space",
                    ],
                ),
                LocalGateCommand::new("cargo", &["fmt", "--all", "--", "--check"]),
                LocalGateCommand::new(
                    "cargo",
                    &[
                        "clippy",
                        "--locked",
                        "--workspace",
                        "--all-targets",
                        "--",
                        "-D",
                        "warnings",
                    ],
                ),
                LocalGateCommand::new(
                    "cargo",
                    &[
                        "clippy",
                        "--locked",
                        "-p",
                        "example@1.2.3",
                        "--lib",
                        "--bin",
                        "example-evidence",
                        "--no-deps",
                        "--features",
                        "special",
                        "--",
                        "-D",
                        "warnings",
                    ],
                ),
                LocalGateCommand::new(
                    "cargo",
                    &["test", "--locked", "--workspace", "--all-targets"],
                ),
                LocalGateCommand::new(
                    "cargo",
                    &[
                        "test",
                        "--locked",
                        "-p",
                        "example@1.2.3",
                        "--lib",
                        "--bin",
                        "example-evidence",
                        "--features",
                        "special",
                    ],
                ),
            ]
        );
        for command in commands.iter().filter(|command| {
            command.program == "cargo"
                && command
                    .arguments
                    .first()
                    .is_some_and(|argument| argument == "test")
        }) {
            assert!(!command
                .arguments
                .iter()
                .any(|argument| argument == "--test-threads=1"));
            assert_ne!(command.arguments.last().map(String::as_str), Some("--"));
        }
        assert_eq!(
            render_local_gate_command(&commands[2]),
            "cargo [\"run\",\"--locked\",\"-p\",\"example@1.2.3\",\"--bin\",\"example-evidence\",\"--\",\"check\",\"path with space\"]"
        );
    }

    #[test]
    fn local_gate_profile_targets_default_to_all_targets() {
        let profile = DiscoveredLocalGateProfile {
            package_spec: "example@1.2.3".to_owned(),
            name: "special".to_owned(),
            features: vec!["special".to_owned()],
            clippy: true,
            test: true,
            targets: Vec::new(),
        };

        assert_eq!(
            local_gate_profile_command(&profile, "clippy"),
            LocalGateCommand::new(
                "cargo",
                &[
                    "clippy",
                    "--locked",
                    "-p",
                    "example@1.2.3",
                    "--all-targets",
                    "--features",
                    "special",
                    "--",
                    "-D",
                    "warnings",
                ],
            )
        );
        assert_eq!(
            local_gate_profile_command(&profile, "test"),
            LocalGateCommand::new(
                "cargo",
                &[
                    "test",
                    "--locked",
                    "-p",
                    "example@1.2.3",
                    "--all-targets",
                    "--features",
                    "special",
                ],
            )
        );
    }

    #[test]
    fn pre_push_evidence_handoff_requires_the_exact_package_owned_check() {
        let exact = DiscoveredLocalGate {
            checks: vec![DiscoveredLocalGateCheck {
                package_spec: "distribution-evidence@0.1.0".to_owned(),
                name: "distribution-evidence".to_owned(),
                bin: "distribution-evidence".to_owned(),
                arguments: vec!["check".to_owned()],
                input_id_arguments: Some(vec!["input-id".to_owned()]),
            }],
            profiles: Vec::new(),
        };
        assert!(has_required_distribution_evidence_check(&exact));

        for changed in [
            DiscoveredLocalGateCheck {
                arguments: vec!["write".to_owned()],
                ..exact.checks[0].clone()
            },
            DiscoveredLocalGateCheck {
                bin: "other".to_owned(),
                ..exact.checks[0].clone()
            },
            DiscoveredLocalGateCheck {
                package_spec: "other@0.1.0".to_owned(),
                ..exact.checks[0].clone()
            },
            DiscoveredLocalGateCheck {
                input_id_arguments: None,
                ..exact.checks[0].clone()
            },
        ] {
            assert!(!has_required_distribution_evidence_check(
                &DiscoveredLocalGate {
                    checks: vec![changed],
                    profiles: Vec::new(),
                }
            ));
        }
    }

    #[test]
    fn source_quality_plan_strictly_satisfies_the_pre_push_local_gate_subset() {
        let commands = vec![
            LocalGateCommand::new("git", &["diff", "--check"]),
            LocalGateCommand::new("cargo", &["test", "--locked", "--workspace"]),
        ];
        let local_gate = local_gate_validation_plan(&commands).unwrap();
        let source_quality = source_quality_validation_plan(&commands).unwrap();
        assert!(source_quality.satisfies(&local_gate));
        assert!(!local_gate.satisfies(&source_quality));

        let changed = local_gate_validation_plan(&[
            LocalGateCommand::new("git", &["diff", "--check"]),
            LocalGateCommand::new("cargo", &["test", "--locked", "--all-targets"]),
        ])
        .unwrap();
        assert!(!source_quality.satisfies(&changed));
    }

    #[test]
    fn local_gate_rejects_duplicate_profiles_without_knowing_package_names() {
        let metadata = serde_json::from_value(serde_json::json!({
            "workspace_members": ["path+file:///repo/crates/example#example@1.0.0"],
            "packages": [{
                "id": "path+file:///repo/crates/example#example@1.0.0",
                "name": "example",
                "version": "1.0.0",
                "features": {"feature": []},
                "targets": [],
                "metadata": {
                    "local-gate": {
                        "schema-version": 1,
                        "profiles": [
                            {
                                "name": "duplicate",
                                "features": ["feature"],
                                "clippy": true,
                                "test": false
                            },
                            {
                                "name": "duplicate",
                                "features": ["feature"],
                                "clippy": false,
                                "test": true
                            }
                        ]
                    }
                }
            }]
        }))
        .expect("synthetic cargo metadata");

        let error = discover_local_gate_from_metadata(metadata)
            .expect_err("duplicate package-owned profile must fail closed");
        assert!(error.contains("repeats local-gate profile duplicate"));
    }

    #[test]
    fn local_gate_rejects_undeclared_profile_targets() {
        let metadata = serde_json::from_value(serde_json::json!({
            "workspace_members": ["path+file:///repo/crates/example#example@1.0.0"],
            "packages": [{
                "id": "path+file:///repo/crates/example#example@1.0.0",
                "name": "example",
                "version": "1.0.0",
                "features": {"feature": []},
                "targets": [{
                    "name": "example",
                    "kind": ["lib"]
                }],
                "metadata": {
                    "local-gate": {
                        "schema-version": 1,
                        "profiles": [{
                            "name": "scoped",
                            "features": ["feature"],
                            "clippy": true,
                            "test": false,
                            "targets": ["bin:missing"]
                        }]
                    }
                }
            }]
        }))
        .expect("synthetic cargo metadata");

        let error = discover_local_gate_from_metadata(metadata)
            .expect_err("an undeclared profile target must fail closed");
        assert!(error.contains("selects undeclared binary target missing"));
    }

    #[test]
    fn local_gate_rejects_an_undeclared_check_binary() {
        let metadata = serde_json::from_value(serde_json::json!({
            "workspace_members": ["path+file:///repo/crates/example#example@1.0.0"],
            "packages": [{
                "id": "path+file:///repo/crates/example#example@1.0.0",
                "name": "example",
                "version": "1.0.0",
                "features": {},
                "targets": [{
                    "name": "different-binary",
                    "kind": ["bin"]
                }],
                "metadata": {
                    "local-gate": {
                        "schema-version": 1,
                        "checks": [{
                            "name": "evidence",
                            "bin": "missing-binary",
                            "arguments": ["check"]
                        }]
                    }
                }
            }]
        }))
        .expect("synthetic cargo metadata");

        let error = discover_local_gate_from_metadata(metadata)
            .expect_err("undeclared package-owned binary must fail closed");
        assert!(error.contains("names undeclared binary missing-binary"));
    }

    #[test]
    fn package_owned_input_id_requires_the_versioned_metadata_contract() {
        let metadata = serde_json::from_value(serde_json::json!({
            "workspace_members": ["path+file:///repo/crates/example#example@1.0.0"],
            "packages": [{
                "id": "path+file:///repo/crates/example#example@1.0.0",
                "name": "example",
                "version": "1.0.0",
                "features": {},
                "targets": [{
                    "name": "example",
                    "kind": ["bin"]
                }],
                "metadata": {
                    "local-gate": {
                        "schema-version": 1,
                        "checks": [{
                            "name": "example",
                            "bin": "example",
                            "arguments": ["check"],
                            "input-id-arguments": ["input-id"]
                        }]
                    }
                }
            }]
        }))
        .expect("synthetic cargo metadata");

        let error = discover_local_gate_from_metadata(metadata)
            .expect_err("schema-version 1 must not silently acquire input-id semantics");
        assert!(error.contains("requires schema-version 2 for input-id-arguments"));
    }

    #[test]
    fn windows_native_test_command_inventory_is_closed_and_autocad_independent() {
        let semantic = WINDOWS_NATIVE_SEMANTIC_TESTS
            .iter()
            .map(|command| format!("{} {}", command.program, command.arguments.join(" ")))
            .collect::<Vec<_>>();
        assert_eq!(
            semantic,
            [
                "cargo test --locked -p autocad-mcp --lib windows_native_semantic_ -- --test-threads=1",
                "cargo test --locked -p autocad-mcp --test windows_certification windows_native_semantic_ -- --test-threads=1",
                "cargo test --locked -p release-packager --lib windows_native_semantic_ -- --test-threads=1",
            ]
        );
        assert_eq!(
            format!(
                "{} {}",
                WINDOWS_GUARDED_RENAME_TEST.program,
                WINDOWS_GUARDED_RENAME_TEST.arguments.join(" ")
            ),
            "cargo test --locked -p autocad-mcp --test windows_guarded_rename windows::windows_guarded_rename_feasibility_probe -- --exact --nocapture --test-threads=1"
        );

        for command in windows_native_test_commands(WindowsNativeTestSuite::All) {
            assert_eq!(command.program, "cargo");
            assert_eq!(command.arguments.first(), Some(&"test"));
            assert!(!command.arguments.contains(&"--ignored"));
            assert!(!command.arguments.iter().any(|argument| {
                matches!(
                    *argument,
                    "windows_certification_gate"
                        | "layer_windows_certification_gate"
                        | "xref_windows_certification_gate"
                )
            }));
        }
    }

    #[test]
    fn windows_native_test_suites_are_closed_and_composable() {
        assert_eq!(
            parse_windows_native_test_suite(OsStr::new("all")),
            Ok(WindowsNativeTestSuite::All)
        );
        assert_eq!(
            parse_windows_native_test_suite(OsStr::new("semantic")),
            Ok(WindowsNativeTestSuite::Semantic)
        );
        assert_eq!(
            parse_windows_native_test_suite(OsStr::new("guarded-rename")),
            Ok(WindowsNativeTestSuite::GuardedRename)
        );
        assert!(parse_windows_native_test_suite(OsStr::new("certification")).is_err());

        let semantic = windows_native_test_commands(WindowsNativeTestSuite::Semantic);
        let guarded = windows_native_test_commands(WindowsNativeTestSuite::GuardedRename);
        let all = windows_native_test_commands(WindowsNativeTestSuite::All);
        assert_eq!(semantic.len(), WINDOWS_NATIVE_SEMANTIC_TESTS.len());
        assert_eq!(guarded, [&WINDOWS_GUARDED_RENAME_TEST]);
        assert_eq!(all.len(), semantic.len() + guarded.len());
        assert_eq!(&all[..semantic.len()], semantic);
        assert_eq!(&all[semantic.len()..], guarded);
    }

    #[test]
    fn windows_native_tests_scrub_ambient_product_configuration() {
        for name in [
            "AUTOCAD_MCP_ACCORECONSOLE_PATH",
            "autocad_mcp_title_block_profiles",
            "AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH",
            "AUTOCAD_MCP_XREF_CERT_MANIFEST",
            "AUTOCAD_MCP_TIER2_MANIFEST",
            "AUTOCAD_MCP_CERT_OUTPUT_DIR",
            "AUTOCAD_MCP_XREF_FAILPOINT",
            "AUTOCAD_MCP_FUTURE_PRODUCT_INPUT",
        ] {
            assert!(
                removes_ambient_autocad_mcp_environment(OsStr::new(name)),
                "{name} should be scrubbed"
            );
        }
        assert!(!removes_ambient_autocad_mcp_environment(OsStr::new(
            WINDOWS_GUARDED_RENAME_EVIDENCE_ENV
        )));
        assert!(!removes_ambient_autocad_mcp_environment(OsStr::new(
            "CARGO_TARGET_DIR"
        )));
    }

    #[test]
    fn windows_native_tests_reject_other_platforms_before_launch() {
        let calls = Cell::new(0);
        let error = run_windows_native_tests_with(
            Path::new("unused"),
            "macos",
            WindowsNativeTestSuite::All,
            |_, _| {
                calls.set(calls.get() + 1);
                Ok(())
            },
        )
        .expect_err("non-Windows hosts must be rejected");
        assert!(error.contains("requires a native Windows host"), "{error}");
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn windows_native_tests_report_every_failure_in_one_run() {
        let calls = Cell::new(0);
        let error = run_windows_native_tests_with(
            Path::new("unused"),
            "windows",
            WindowsNativeTestSuite::Semantic,
            |_, _| {
                calls.set(calls.get() + 1);
                if matches!(calls.get(), 1 | 3) {
                    Err(format!("simulated failure {}", calls.get()))
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("failed commands must fail the complete suite");
        assert_eq!(calls.get(), WINDOWS_NATIVE_SEMANTIC_TESTS.len());
        assert!(
            error.starts_with("2 Windows-native test command(s) failed:\n"),
            "{error}"
        );
        assert!(error.contains("simulated failure 1"), "{error}");
        assert!(error.contains("simulated failure 3"), "{error}");
    }

    #[test]
    fn successful_full_gate_treats_receipt_recapture_as_advisory() {
        assert_eq!(
            classify_full_gate_receipt_recapture(&7, Ok(7)),
            FullGateReceiptRecapture::Stable(7)
        );
        assert_eq!(
            classify_full_gate_receipt_recapture(&7, Ok(8)),
            FullGateReceiptRecapture::Changed
        );
        assert_eq!(
            classify_full_gate_receipt_recapture::<u8>(&7, Err("unavailable".to_owned())),
            FullGateReceiptRecapture::Unavailable("unavailable".to_owned())
        );
    }

    #[test]
    fn pre_push_records_are_closed_and_deletions_are_identified() {
        let updates = parse_push_updates(
            "refs/heads/main abc123 refs/heads/main def456\n(delete) 000000 refs/heads/old abc123\n",
        )
        .expect("valid records");
        assert_eq!(
            updates,
            vec![
                PushUpdate {
                    local_ref: "refs/heads/main".to_owned(),
                    local_oid: "abc123".to_owned(),
                    remote_ref: "refs/heads/main".to_owned(),
                },
                PushUpdate {
                    local_ref: "(delete)".to_owned(),
                    local_oid: "000000".to_owned(),
                    remote_ref: "refs/heads/old".to_owned(),
                },
            ]
        );
        assert!(is_zero_oid("000000"));
        assert!(!is_zero_oid(""));
        assert!(!is_zero_oid("000100"));
        assert!(parse_push_updates("too few fields").is_err());
    }

    #[test]
    fn pushed_commits_must_all_peel_to_the_snapshotted_head() {
        let updates = parse_push_updates(
            "refs/heads/main commit refs/heads/main old\nrefs/tags/v1 tag refs/tags/v1 zero\n",
        )
        .expect("valid records");
        let validated = validate_push_updates(&updates, "head", |oid| match oid {
            "commit" | "tag" => Ok("head".to_owned()),
            _ => Err("unexpected oid".to_owned()),
        })
        .expect("both refs peel to HEAD");
        assert!(validated);

        let error = validate_push_updates(&updates, "other", |_| Ok("head".to_owned()))
            .expect_err("mismatched commits must be rejected");
        assert!(error.contains("clean checked-out HEAD is other"));
    }

    #[test]
    fn full_pre_push_gates_and_source_seals_the_exact_pushed_head() {
        let repository = test_repository();
        let head = git_output(repository.path(), &["rev-parse", "--verify", "HEAD"]).unwrap();
        let tree =
            git_output(repository.path(), &["rev-parse", "--verify", "HEAD^{tree}"]).unwrap();
        let gate_calls = Cell::new(0);
        let seal_calls = Cell::new(0);
        let input = format!("refs/heads/main {head} refs/heads/main 000000\n");
        let result = run_full_pre_push_with(
            repository.path(),
            &input,
            |_| {
                gate_calls.set(gate_calls.get() + 1);
                Ok(())
            },
            |_| {
                seal_calls.set(seal_calls.get() + 1);
                Ok(candidate_seal::CandidateIdentity {
                    git_object_format: "sha1".to_owned(),
                    source_commit: head.clone(),
                    source_tree_oid: tree.clone(),
                })
            },
        )
        .expect("exact pushed HEAD should pass");

        assert_eq!(result, Some(head));
        assert_eq!(gate_calls.get(), 1);
        assert_eq!(seal_calls.get(), 1);
    }

    #[test]
    fn rapid_pre_push_admits_only_the_exact_pushed_head_without_candidate_work() {
        let repository = test_repository();
        let head = git_output(repository.path(), &["rev-parse", "--verify", "HEAD"]).unwrap();
        let tree =
            git_output(repository.path(), &["rev-parse", "--verify", "HEAD^{tree}"]).unwrap();
        let gate_calls = Cell::new(0);
        let observation_calls = Cell::new(0);
        let input = format!("refs/heads/main {head} refs/heads/main 000000\n");
        let result = run_rapid_pre_push_with(
            repository.path(),
            &input,
            |_| {
                gate_calls.set(gate_calls.get() + 1);
                Ok(())
            },
            |_| {
                observation_calls.set(observation_calls.get() + 1);
                Ok(candidate_seal::CandidateIdentity {
                    git_object_format: "sha1".to_owned(),
                    source_commit: head.clone(),
                    source_tree_oid: tree.clone(),
                })
            },
        )
        .expect("rapid admission should accept the unchanged pushed HEAD");

        assert_eq!(result, Some(head));
        assert_eq!(gate_calls.get(), 1);
        assert_eq!(observation_calls.get(), 1);
        let commands = rapid_pre_push_commands();
        assert_eq!(commands.len(), 3);
        assert!(commands.iter().all(|command| {
            let rendered = render_local_gate_command(command);
            !rendered.contains("clippy")
                && !rendered.contains("test")
                && !rendered.contains("source-candidate")
                && !rendered.contains("distribution-evidence")
        }));
    }

    #[test]
    fn pre_push_rejects_a_seal_for_any_other_commit() {
        let repository = test_repository();
        let head = git_output(repository.path(), &["rev-parse", "--verify", "HEAD"]).unwrap();
        let input = format!("refs/heads/main {head} refs/heads/main 000000\n");
        let error = run_full_pre_push_with(
            repository.path(),
            &input,
            |_| Ok(()),
            |_| {
                Ok(candidate_seal::CandidateIdentity {
                    git_object_format: "sha1".to_owned(),
                    source_commit: "0".repeat(40),
                    source_tree_oid: "0".repeat(40),
                })
            },
        )
        .expect_err("a stale source seal must reject the push");

        assert!(error.contains("does not match the exact pushed HEAD"));
    }

    #[test]
    fn pre_push_rejects_wrong_tree_or_object_format_for_the_same_commit() {
        let repository = test_repository();
        let head = git_output(repository.path(), &["rev-parse", "--verify", "HEAD"]).unwrap();
        let input = format!("refs/heads/main {head} refs/heads/main 000000\n");
        for sealed in [
            candidate_seal::CandidateIdentity {
                git_object_format: "sha1".to_owned(),
                source_commit: head.clone(),
                source_tree_oid: "0".repeat(40),
            },
            candidate_seal::CandidateIdentity {
                git_object_format: "sha256".to_owned(),
                source_commit: head.clone(),
                source_tree_oid: "0".repeat(64),
            },
        ] {
            let error = run_full_pre_push_with(
                repository.path(),
                &input,
                |_| Ok(()),
                |_| Ok(sealed.clone()),
            )
            .expect_err("wrong candidate identity must reject the push");
            assert!(error.contains("does not match the exact pushed HEAD"));
        }
    }

    #[test]
    fn deletion_only_push_does_not_manufacture_a_source_candidate() {
        let result = run_full_pre_push_with(
            Path::new("repository-is-not-consulted"),
            "(delete) 000000 refs/heads/old abc123\n",
            |_| panic!("deletion-only push must not run the gate"),
            |_| panic!("deletion-only push must not create a source seal"),
        )
        .expect("deletion-only push should skip");
        assert_eq!(result, None);
    }

    #[test]
    fn current_distribution_requires_every_approval_source_binding_to_match() {
        let candidate = candidate_verification();
        let approval = approval_report();
        ensure_approval_matches_candidate(&candidate, &approval)
            .expect("exact current distribution should join");

        let mut stale_reports = Vec::new();
        for mutate in [
            |report: &mut ApprovalVerificationReport| {
                report.git_object_format = "sha256".to_owned()
            },
            |report: &mut ApprovalVerificationReport| report.source_commit = "9".repeat(40),
            |report: &mut ApprovalVerificationReport| report.source_tree_oid = "9".repeat(40),
            |report: &mut ApprovalVerificationReport| report.source_archive_sha256 = "9".repeat(64),
            |report: &mut ApprovalVerificationReport| {
                report.source_bundle_manifest_sha256 = "9".repeat(64)
            },
            |report: &mut ApprovalVerificationReport| report.cargo_lock_sha256 = "9".repeat(64),
            |report: &mut ApprovalVerificationReport| {
                report.dependency_input_closure_sha256 = "9".repeat(64)
            },
            |report: &mut ApprovalVerificationReport| report.rust_toolchain_sha256 = "9".repeat(64),
            |report: &mut ApprovalVerificationReport| report.build_recipe_sha256 = "9".repeat(64),
        ] {
            let mut stale = approval.clone();
            mutate(&mut stale);
            stale_reports.push(stale);
        }
        for stale in stale_reports {
            let error = ensure_approval_matches_candidate(&candidate, &stale)
                .expect_err("every stale source binding must reject current selection");
            assert!(error.contains("regenerate every release artifact"));
        }
    }

    #[test]
    fn current_distribution_rejects_cross_mode_candidate_and_approval() {
        let candidate = candidate_verification();
        let mut approval = approval_report();
        approval.package_mode = DistributionMode::Preview;
        let error = ensure_approval_matches_candidate(&candidate, &approval)
            .expect_err("Preview approval must not select a Release source candidate");
        assert!(error.contains("different source candidate"));
    }
}
