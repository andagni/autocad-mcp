use distribution_approval::DistributionMode;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

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
}

impl LocalGateCommand {
    fn new(program: &str, arguments: &[&str]) -> Self {
        Self {
            program: program.to_owned(),
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
        }
    }
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageLocalGateProfile {
    name: String,
    features: Vec<String>,
    clippy: bool,
    test: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DiscoveredLocalGateCheck {
    package_spec: String,
    name: String,
    bin: String,
    arguments: Vec<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DiscoveredLocalGateProfile {
    package_spec: String,
    name: String,
    features: Vec<String>,
    clippy: bool,
    test: bool,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct DiscoveredLocalGate {
    checks: Vec<DiscoveredLocalGateCheck>,
    profiles: Vec<DiscoveredLocalGateProfile>,
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
            "activation_windows_",
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
            "--lib",
            "accoreconsole_command_normalizes_only_autocad_path_arguments",
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
            "--lib",
            "certified_profile_guard",
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
            "--lib",
            "unique_xref_profile_registry_lifecycle_refuses_adoption_and_cleans_owned_root",
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
            "--lib",
            "bounded_windows_probe_runner_",
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
            "--lib",
            "production_windows_",
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
            "certified_profile_registry_guard_owns_only_a_new_exact_subtree",
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
            "exact_runtime_file_binding_denies_windows_write_delete_and_ancestor_rename",
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
            "bounded_certification_runner_terminates_the_windows_process_tree",
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
            "bounded_certification_runner_rejects_a_successful_parent_with_a_live_descendant",
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
            "windows_run_with_timeout_",
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsNativeTestSuite {
    All,
    Semantic,
    GuardedRename,
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("xtask crate must remain under <repository>/crates/xtask")
        .to_path_buf()
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
        if local_gate.schema_version != 1 {
            return Err(format!(
                "package.metadata.local-gate for {} {} has schema-version {}, expected 1",
                package.name, package.version, local_gate.schema_version
            ));
        }
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
            checks.push(DiscoveredLocalGateCheck {
                package_spec: package_spec.clone(),
                name: check.name,
                bin: check.bin,
                arguments: check.arguments,
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
            profiles.push(DiscoveredLocalGateProfile {
                package_spec: package_spec.clone(),
                name: profile.name,
                features: profile.features,
                clippy: profile.clippy,
                test: profile.test,
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
        commands.push(LocalGateCommand {
            program: "cargo".to_owned(),
            arguments,
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
        &[
            "test",
            "--locked",
            "--workspace",
            "--all-targets",
            "--",
            "--test-threads=1",
        ],
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
        "--all-targets".to_owned(),
        "--features".to_owned(),
        profile.features.join(","),
        "--".to_owned(),
    ];
    match operation {
        "clippy" => arguments.extend(["-D".to_owned(), "warnings".to_owned()]),
        "test" => arguments.push("--test-threads=1".to_owned()),
        _ => unreachable!("local-gate profile operation is closed"),
    }
    LocalGateCommand {
        program: "cargo".to_owned(),
        arguments,
    }
}

fn render_local_gate_command(command: &LocalGateCommand) -> String {
    let arguments = serde_json::to_string(&command.arguments)
        .expect("local-gate argv serialization cannot fail");
    format!("{} {arguments}", command.program)
}

fn run_local_gate(root: &Path) -> Result<(), String> {
    let discovered = discover_local_gate(root)?;
    let commands = local_gate_commands(&discovered);
    for (index, command) in commands.iter().enumerate() {
        let rendered = render_local_gate_command(command);
        eprintln!("[{}/{}] {rendered}", index + 1, commands.len());
        let status = Command::new(&command.program)
            .args(&command.arguments)
            .current_dir(root)
            .status()
            .map_err(|error| format!("failed to launch {rendered}: {error}"))?;
        if !status.success() {
            return Err(format!(
                "local gate command failed with {status}: {rendered}"
            ));
        }
    }
    Ok(())
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
    for (index, command) in commands.iter().enumerate() {
        eprintln!(
            "[{}/{}] {} {}",
            index + 1,
            commands.len(),
            command.program,
            command.arguments.join(" ")
        );
        run(root, command)?;
    }
    Ok(())
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

fn report_windows_native_tests(suite: WindowsNativeTestSuite) -> ExitCode {
    match run_windows_native_tests(&repository_root(), suite) {
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

fn ensure_clean_checkout(root: &Path) -> Result<(), String> {
    let status = git_output(root, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    if status.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "pre-push validation requires a clean checkout; commit or remove these paths:\n{status}"
        ))
    }
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

fn run_pre_push(root: &Path, input: &str) -> Result<Option<String>, String> {
    run_pre_push_with(root, input, run_local_gate, candidate_seal::run_ephemeral)
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

fn run_pre_push_with<G, S>(
    root: &Path,
    input: &str,
    mut gate: G,
    mut seal_source: S,
) -> Result<Option<String>, String>
where
    G: FnMut(&Path) -> Result<(), String>,
    S: FnMut(&Path) -> Result<candidate_seal::CandidateIdentity, String>,
{
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

    gate(root)?;
    let sealed = seal_source(root)?;
    if sealed != identity_before {
        return Err(format!(
            "pre-push source seal identity does not match the exact pushed HEAD; expected commit {} tree {}, sealed commit {} tree {}",
            identity_before.source_commit,
            identity_before.source_tree_oid,
            sealed.source_commit,
            sealed.source_tree_oid
        ));
    }

    let head_after = git_output(root, &["rev-parse", "--verify", "HEAD"])?;
    if head_after != head_before {
        return Err(format!(
            "HEAD changed during pre-push validation ({head_before} -> {head_after}); retry the push"
        ));
    }
    ensure_clean_checkout(root)?;
    Ok(Some(head_before))
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
        [command] if command == "windows-native-tests" => {
            report_windows_native_tests(WindowsNativeTestSuite::All)
        }
        [command, suite_flag, suite]
            if command == "windows-native-tests" && suite_flag == "--suite" =>
        {
            match parse_windows_native_test_suite(suite) {
                Ok(suite) => report_windows_native_tests(suite),
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
        [command, _remote_name, _remote_location] if command == "pre-push" => {
            let mut input = String::new();
            if let Err(error) = std::io::stdin().read_to_string(&mut input) {
                eprintln!("ERROR: failed to read pre-push records: {error}");
                return ExitCode::FAILURE;
            }
            match run_pre_push(&repository_root(), &input) {
                Ok(Some(commit)) => {
                    eprintln!("local pre-push gate passed for {commit}");
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("local pre-push gate skipped: no commits are being pushed");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    ExitCode::FAILURE
                }
            }
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
                "usage: cargo run --locked -p xtask -- windows-source-bundle --output <fresh-target-or-dist-path.zip> [--mode release|preview]\n       cargo run --locked -p xtask -- source-candidate-seal --output-dir <fresh-directory> [--mode release|preview]\n       cargo run --locked -p xtask -- source-candidate-verify --candidate-dir <sealed-directory> [--mode release|preview]\n       cargo run --locked -p xtask -- current-distribution-verify --candidate-dir <sealed-directory> --approval <owner-approval.json> --mcpb <package.mcpb> --source-closure-sbom <spdx.json> --build-attestation <attestation.json> [--clean-host-receipt <Preview-receipt.json>]\n       cargo run --locked -p xtask -- local-gate\n       cargo run --locked -p xtask -- windows-native-tests [--suite all|semantic|guarded-rename]\n       cargo run --locked -p xtask -- preview-autocad-e2e --plan <strict-plan.json> --work-dir <fresh-fixed-local-directory>\n       cargo run --locked -p xtask -- pre-push <remote-name> <remote-location>\n       cargo run --locked -p xtask -- certification-manifest-preflight --tier2-manifest <schema-v3.json> --xref-manifest <schema-v4.json>\n       cargo run --locked -p xtask -- windows-certification-build-preflight --arg <profile.arg> --arg-policy <closed-policy.json> --output-dir <fresh-target-child>\n       Preview selection requires --clean-host-receipt; mode defaults to release when omitted"
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
                                    "test": true
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
                }],
                profiles: vec![DiscoveredLocalGateProfile {
                    package_spec: "example@1.2.3".to_owned(),
                    name: "special".to_owned(),
                    features: vec!["special".to_owned()],
                    clippy: true,
                    test: true,
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
                        "--all-targets",
                        "--features",
                        "special",
                        "--",
                        "-D",
                        "warnings",
                    ],
                ),
                LocalGateCommand::new(
                    "cargo",
                    &[
                        "test",
                        "--locked",
                        "--workspace",
                        "--all-targets",
                        "--",
                        "--test-threads=1",
                    ],
                ),
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
                        "--",
                        "--test-threads=1",
                    ],
                ),
            ]
        );
        assert_eq!(
            render_local_gate_command(&commands[2]),
            "cargo [\"run\",\"--locked\",\"-p\",\"example@1.2.3\",\"--bin\",\"example-evidence\",\"--\",\"check\",\"path with space\"]"
        );
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
    fn windows_native_test_command_inventory_is_closed_and_autocad_independent() {
        let semantic = WINDOWS_NATIVE_SEMANTIC_TESTS
            .iter()
            .map(|command| format!("{} {}", command.program, command.arguments.join(" ")))
            .collect::<Vec<_>>();
        assert_eq!(
            semantic,
            [
                "cargo test --locked -p autocad-mcp --lib activation_windows_ -- --test-threads=1",
                "cargo test --locked -p autocad-mcp --lib accoreconsole_command_normalizes_only_autocad_path_arguments -- --test-threads=1",
                "cargo test --locked -p autocad-mcp --lib certified_profile_guard -- --test-threads=1",
                "cargo test --locked -p autocad-mcp --lib unique_xref_profile_registry_lifecycle_refuses_adoption_and_cleans_owned_root -- --test-threads=1",
                "cargo test --locked -p autocad-mcp --lib bounded_windows_probe_runner_ -- --test-threads=1",
                "cargo test --locked -p autocad-mcp --lib production_windows_ -- --test-threads=1",
                "cargo test --locked -p autocad-mcp --test windows_certification certified_profile_registry_guard_owns_only_a_new_exact_subtree -- --test-threads=1",
                "cargo test --locked -p autocad-mcp --test windows_certification exact_runtime_file_binding_denies_windows_write_delete_and_ancestor_rename -- --test-threads=1",
                "cargo test --locked -p autocad-mcp --test windows_certification bounded_certification_runner_terminates_the_windows_process_tree -- --test-threads=1",
                "cargo test --locked -p autocad-mcp --test windows_certification bounded_certification_runner_rejects_a_successful_parent_with_a_live_descendant -- --test-threads=1",
                "cargo test --locked -p release-packager windows_run_with_timeout_ -- --test-threads=1",
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
    fn windows_native_tests_stop_at_the_first_failure() {
        let calls = Cell::new(0);
        let error = run_windows_native_tests_with(
            Path::new("unused"),
            "windows",
            WindowsNativeTestSuite::Semantic,
            |_, _| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err("simulated failure".to_owned())
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("a failed command must stop the suite");
        assert_eq!(error, "simulated failure");
        assert_eq!(calls.get(), 2);
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
    fn pre_push_gates_and_source_seals_the_exact_pushed_head() {
        let repository = test_repository();
        let head = git_output(repository.path(), &["rev-parse", "--verify", "HEAD"]).unwrap();
        let tree =
            git_output(repository.path(), &["rev-parse", "--verify", "HEAD^{tree}"]).unwrap();
        let gate_calls = Cell::new(0);
        let seal_calls = Cell::new(0);
        let input = format!("refs/heads/main {head} refs/heads/main 000000\n");
        let result = run_pre_push_with(
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
    fn pre_push_rejects_a_seal_for_any_other_commit() {
        let repository = test_repository();
        let head = git_output(repository.path(), &["rev-parse", "--verify", "HEAD"]).unwrap();
        let input = format!("refs/heads/main {head} refs/heads/main 000000\n");
        let error = run_pre_push_with(
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
            let error = run_pre_push_with(
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
        let result = run_pre_push_with(
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
