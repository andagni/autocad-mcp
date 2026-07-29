use std::ffi::OsString;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;

use autocad_mcp::ops::profiles::{self, ProfileRegistry};
use autocad_mcp::server::{cli_dispatch, AutocadServer, EngineProbeMode};
use clap::{Parser, Subcommand};

const MAX_CALL_PARAMS_FILE_BYTES: u64 = 1024 * 1024;
const XREF_CERTIFICATION_INFO_SCHEMA_VERSION: u32 = 4;

fn parse_corpus_tier(value: &str) -> Result<usize, String> {
    match value.parse::<usize>() {
        Ok(tier @ 1..=3) => Ok(tier),
        _ => Err("corpus tier must be 1, 2, or 3".to_owned()),
    }
}

#[derive(Parser)]
#[command(name = "autocad-mcp", about = "AutoCAD MCP server and CLI")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run as an MCP stdio server (default when no subcommand given)
    Serve {
        /// Enable state-changing tools in a Preview build
        #[cfg(feature = "preview")]
        #[arg(long)]
        experimental: bool,
        /// Serve-only advisory Core Console warm-up policy
        #[arg(long, value_enum, value_name = "MODE")]
        engine_probe: Option<EngineProbeMode>,
        /// Load one administrator-reviewed title-block profiles file (overrides the environment fallback)
        #[arg(long, value_name = "ABSOLUTE_JSON")]
        title_block_profiles: Option<PathBuf>,
    },
    /// Print all available tools as a JSON array
    ListTools {
        /// Include state-changing tools in a Preview build
        #[cfg(feature = "preview")]
        #[arg(long)]
        experimental: bool,
    },
    /// Invoke a tool by name with JSON parameters
    Call {
        /// Permit state-changing tools in a Preview build
        #[cfg(feature = "preview")]
        #[arg(long)]
        experimental: bool,
        /// Load one administrator-reviewed title-block profiles file (overrides the environment fallback)
        #[arg(long, value_name = "ABSOLUTE_JSON")]
        title_block_profiles: Option<PathBuf>,
        /// Tool name (e.g. list_layouts, plot_to_pdf)
        name: String,
        /// Parameters as a JSON object string (e.g. '{"drawing_path":"/path/to/file.dwg"}')
        #[arg(
            value_name = "PARAMS",
            required_unless_present = "params_file",
            conflicts_with = "params_file"
        )]
        params: Option<String>,
        /// Read parameters as strict UTF-8 JSON from a regular file
        #[arg(long, value_name = "PATH", conflicts_with = "params")]
        params_file: Option<PathBuf>,
    },
    /// Offline administrator workflows; never exposed through MCP
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    #[command(hide = true)]
    XrefCertificationInfo,
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Survey, author, and validate configurable title-block profiles
    TitleBlock {
        #[command(subcommand)]
        command: TitleBlockAdminCommand,
    },
}

#[derive(Subcommand)]
enum TitleBlockAdminCommand {
    /// Survey a drawing corpus and emit redacted JSON Lines evidence
    Survey {
        /// Absolute corpus root used to produce relative drawing identifiers
        #[arg(long, value_name = "ABSOLUTE_DIRECTORY")]
        root: PathBuf,
        /// Absolute drawing file or directory below --root; repeat as needed
        #[arg(long, value_name = "ABSOLUTE_PATH", required = true)]
        input: Vec<PathBuf>,
        /// Corpus tier label
        #[arg(long, value_parser = parse_corpus_tier)]
        corpus_tier: usize,
        /// Include observed attribute values in the private survey artifact
        #[arg(long)]
        include_values: bool,
        /// JSON Lines artifact path
        #[arg(long, value_name = "JSONL")]
        output: PathBuf,
        /// Replace an existing regular output file
        #[arg(long)]
        replace_output: bool,
    },
    /// Deterministically cluster one survey artifact by exact fingerprint
    Cluster {
        /// Survey JSON Lines artifact
        #[arg(long, value_name = "JSONL")]
        survey: PathBuf,
        /// Cluster JSON artifact path
        #[arg(long, value_name = "JSON")]
        output: PathBuf,
        /// Replace an existing regular output file
        #[arg(long)]
        replace_output: bool,
    },
    /// Validate one administrator title-block profiles file
    Validate {
        #[arg(long, value_name = "ABSOLUTE_JSON")]
        profiles: PathBuf,
    },
    /// Verify every configured profile against declared representative drawings
    Verify {
        #[arg(long, value_name = "ABSOLUTE_JSON")]
        profiles: PathBuf,
        #[arg(long, value_name = "ABSOLUTE_JSON")]
        witnesses: PathBuf,
    },
}

fn read_call_params_file(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect JSON params file {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "JSON params file must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    if metadata.len() > MAX_CALL_PARAMS_FILE_BYTES {
        return Err(format!(
            "JSON params file exceeds the {}-byte limit: {}",
            MAX_CALL_PARAMS_FILE_BYTES,
            path.display()
        ));
    }

    let bytes = fs::read(path)
        .map_err(|error| format!("read JSON params file {}: {error}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(format!(
            "JSON params file changed while it was being read: {}",
            path.display()
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| format!("JSON params file must be strict UTF-8: {error}"))
}

fn resolve_call_params(
    inline: Option<String>,
    params_file: Option<PathBuf>,
) -> Result<String, String> {
    match (inline, params_file) {
        (Some(params), None) => Ok(params),
        (None, Some(path)) => read_call_params_file(&path),
        (Some(_), Some(_)) => {
            Err("provide either inline JSON params or --params-file, not both".to_owned())
        }
        (None, None) => Err("missing JSON params or --params-file".to_owned()),
    }
}

fn server_for_command(
    experimental: bool,
    title_block_profiles: Arc<ProfileRegistry>,
) -> AutocadServer {
    #[cfg(feature = "preview")]
    {
        if experimental {
            AutocadServer::experimental_with_title_block_profiles(title_block_profiles)
        } else {
            AutocadServer::new_with_title_block_profiles(title_block_profiles)
        }
    }
    #[cfg(not(feature = "preview"))]
    {
        debug_assert!(!experimental);
        AutocadServer::new_with_title_block_profiles(title_block_profiles)
    }
}

fn resolve_title_block_profiles_path(
    cli_path: Option<PathBuf>,
    environment: Option<OsString>,
) -> Option<PathBuf> {
    cli_path.or_else(|| {
        environment
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    })
}

fn load_title_block_profiles(cli_path: Option<PathBuf>) -> Arc<ProfileRegistry> {
    let path = resolve_title_block_profiles_path(
        cli_path,
        std::env::var_os(profiles::TITLE_BLOCK_PROFILES_ENV),
    );
    profiles::load_active_profile_registry(path.as_deref()).unwrap_or_else(|error| {
        eprintln!("ERROR: {error}");
        process::exit(2);
    })
}

fn run_mcp_server(server: AutocadServer, engine_probe_mode: EngineProbeMode) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("ERROR: failed to build tokio runtime: {e}");
            process::exit(1);
        });
    rt.block_on(autocad_mcp::server::serve_stdio(server, engine_probe_mode))
        .unwrap_or_else(|e| {
            eprintln!("ERROR: {e}");
            process::exit(1);
        });
}

fn read_admin_artifact(path: &Path, maximum_bytes: u64, label: &str) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    if metadata.len() > maximum_bytes {
        return Err(format!(
            "{label} exceeds the {maximum_bytes}-byte limit: {}",
            path.display()
        ));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("read {label} {}: {error}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(format!(
            "{label} changed while it was being read: {}",
            path.display()
        ));
    }
    String::from_utf8(bytes).map_err(|error| format!("{label} must be strict UTF-8: {error}"))
}

fn write_admin_artifact(path: &Path, content: &str, replace: bool) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_file() {
            return Err(format!(
                "administrator output must be a regular non-symlink file: {}",
                path.display()
            ));
        }
        if !replace {
            return Err(format!(
                "administrator output already exists; pass --replace-output to replace it: {}",
                path.display()
            ));
        }
    }
    let mut options = OpenOptions::new();
    options.write(true);
    if replace {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("create administrator output {}: {error}", path.display()))?;
    file.write_all(content.as_bytes())
        .map_err(|error| format!("write administrator output {}: {error}", path.display()))?;
    file.write_all(b"\n")
        .map_err(|error| format!("finish administrator output {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("flush administrator output {}: {error}", path.display()))
}

fn run_title_block_admin(command: TitleBlockAdminCommand) -> Result<(), String> {
    match command {
        TitleBlockAdminCommand::Survey {
            root,
            input,
            corpus_tier,
            include_values,
            output,
            replace_output,
        } => {
            let jsonl = autocad_mcp::ops::survey::administrator_survey_paths_jsonl(
                &root,
                &input,
                corpus_tier,
                include_values,
            )
            .map_err(|error| error.to_string())?;
            write_admin_artifact(&output, &jsonl, replace_output)
        }
        TitleBlockAdminCommand::Cluster {
            survey,
            output,
            replace_output,
        } => {
            let jsonl =
                read_admin_artifact(&survey, 64 * 1024 * 1024, "title-block survey artifact")?;
            let artifact = autocad_mcp::ops::survey::cluster_survey_jsonl(&jsonl)
                .map_err(|error| error.to_string())?;
            let json = serde_json::to_string_pretty(&artifact)
                .map_err(|error| format!("serialize title-block clusters: {error}"))?;
            write_admin_artifact(&output, &json, replace_output)
        }
        TitleBlockAdminCommand::Validate { profiles } => {
            let summary = autocad_mcp::ops::profile_admin::validate_profile_pack(&profiles)
                .map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&summary)
                    .map_err(|error| format!("serialize profile validation: {error}"))?
            );
            Ok(())
        }
        TitleBlockAdminCommand::Verify {
            profiles,
            witnesses,
        } => {
            let report =
                autocad_mcp::ops::profile_admin::verify_profile_pack(&profiles, &witnesses)
                    .map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .map_err(|error| format!("serialize profile verification: {error}"))?
            );
            Ok(())
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command.unwrap_or(Command::Serve {
        #[cfg(feature = "preview")]
        experimental: false,
        engine_probe: None,
        title_block_profiles: None,
    }) {
        Command::Serve {
            #[cfg(feature = "preview")]
            experimental,
            engine_probe,
            title_block_profiles,
        } => {
            #[cfg(not(feature = "preview"))]
            let experimental = false;
            let engine_probe = engine_probe.unwrap_or(if experimental {
                EngineProbeMode::Auto
            } else {
                EngineProbeMode::Off
            });
            let title_block_profiles = load_title_block_profiles(title_block_profiles);
            run_mcp_server(
                server_for_command(experimental, title_block_profiles),
                engine_probe,
            );
        }

        Command::ListTools {
            #[cfg(feature = "preview")]
            experimental,
        } => {
            #[cfg(not(feature = "preview"))]
            let experimental = false;
            let tools = server_for_command(experimental, profiles::embedded_profile_registry())
                .list_active_tools();
            println!("{}", serde_json::to_string_pretty(&tools).unwrap());
        }

        Command::Call {
            #[cfg(feature = "preview")]
            experimental,
            title_block_profiles,
            name,
            params,
            params_file,
        } => {
            #[cfg(not(feature = "preview"))]
            let experimental = false;
            let params = match resolve_call_params(params, params_file) {
                Ok(params) => params,
                Err(error) => {
                    eprintln!("ERROR: {error}");
                    process::exit(2);
                }
            };
            let params_val: serde_json::Value = match serde_json::from_str(&params) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: invalid JSON params: {e}");
                    process::exit(2);
                }
            };
            let title_block_profiles = load_title_block_profiles(title_block_profiles);
            let server = server_for_command(experimental, title_block_profiles);
            match cli_dispatch(&server, &name, params_val) {
                Ok(output) => {
                    if output.is_error {
                        eprintln!("{}", output.text);
                        process::exit(1);
                    }
                    println!("{}", output.text);
                }
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    process::exit(1);
                }
            }
        }
        Command::Admin { command } => {
            let result = match command {
                AdminCommand::TitleBlock { command } => run_title_block_admin(command),
            };
            if let Err(error) = result {
                eprintln!("ERROR: {error}");
                process::exit(1);
            }
        }
        Command::XrefCertificationInfo => {
            let build_identity = autocad_mcp::certification::xref_certification_build_identity();
            let info = serde_json::json!({
                "schema_version": XREF_CERTIFICATION_INFO_SCHEMA_VERSION,
                "experimental_support": cfg!(feature = "preview"),
                "certified_arg_sha256": autocad_mcp::ops::xref_runtime::certified_arg_sha256_build_value(),
                "certified_arg_policy_id": (!build_identity.certified_arg_policy_id.is_empty())
                    .then_some(build_identity.certified_arg_policy_id.as_str()),
                "certified_arg_policy_sha256":
                    (!build_identity.certified_arg_policy_sha256.is_empty())
                        .then_some(build_identity.certified_arg_policy_sha256.as_str()),
                "activation_catalogue_sha256":
                    autocad_mcp::activation::activation_catalogue_sha256()
                        .expect("embedded activation catalogue must be valid"),
                "certification_failpoints_enabled": build_identity.certification_failpoints_enabled,
                "crt_linkage":
                    autocad_mcp::certification::xref_certification_crt_linkage(),
                "artifact_sha256": autocad_mcp::certification::xref_embedded_artifact_sha256(),
                "title_block_profile_registry_sha256":
                    autocad_mcp::ops::profiles::title_block_profile_registry_sha256(),
                "title_block_profiles":
                    autocad_mcp::certification::embedded_certification_profile_definitions(),
                "build_identity": build_identity,
                "xref_mutation_tools": autocad_mcp::certification::XREF_MUTATION_OPERATIONS
                    .map(|operation| operation.as_str()),
            });
            println!("{}", serde_json::to_string(&info).unwrap());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn command_surface_matches_the_compiled_build_flavor() {
        let plain =
            server_for_command(false, profiles::embedded_profile_registry()).list_active_tools();
        #[cfg(feature = "preview")]
        let opted_in =
            server_for_command(true, profiles::embedded_profile_registry()).list_active_tools();
        #[cfg(not(feature = "preview"))]
        let opted_in =
            server_for_command(false, profiles::embedded_profile_registry()).list_active_tools();
        let default = AutocadServer::default().list_active_tools();

        assert_eq!(opted_in.len(), 51);
        assert_eq!(default, plain);
        if cfg!(feature = "preview") {
            assert_eq!(plain.len(), 36);
            assert!(plain.iter().all(|tool| {
                tool.annotations
                    .as_ref()
                    .and_then(|annotations| annotations.read_only_hint)
                    == Some(true)
            }));
        } else {
            assert_eq!(plain.len(), 51);
        }
    }

    #[cfg(feature = "preview")]
    #[test]
    fn preview_cli_accepts_experimental_only_on_capability_commands() {
        assert!(Cli::try_parse_from(["autocad-mcp", "serve", "--experimental"]).is_ok());
        assert!(Cli::try_parse_from([
            "autocad-mcp",
            "serve",
            "--experimental",
            "--engine-probe",
            "off",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["autocad-mcp", "list-tools", "--experimental"]).is_ok());
        assert!(Cli::try_parse_from([
            "autocad-mcp",
            "call",
            "--experimental",
            "attach_xref",
            "{}",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["autocad-mcp", "--experimental"]).is_err());
    }

    #[cfg(not(feature = "preview"))]
    #[test]
    fn release_cli_rejects_every_experimental_option() {
        for arguments in [
            vec!["autocad-mcp", "serve", "--experimental"],
            vec!["autocad-mcp", "list-tools", "--experimental"],
            vec!["autocad-mcp", "call", "--experimental", "attach_xref", "{}"],
        ] {
            let error = match Cli::try_parse_from(arguments) {
                Ok(_) => panic!("Release CLI unexpectedly accepted --experimental"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }

    #[test]
    fn engine_probe_configuration_exists_only_on_serve_and_is_closed() {
        for mode in ["auto", "off", "on"] {
            assert!(Cli::try_parse_from(["autocad-mcp", "serve", "--engine-probe", mode]).is_ok());
        }
        assert!(
            Cli::try_parse_from(["autocad-mcp", "serve", "--engine-probe", "sometimes"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["autocad-mcp", "list-tools", "--engine-probe", "on"]).is_err()
        );
        assert!(Cli::try_parse_from([
            "autocad-mcp",
            "call",
            "--engine-probe",
            "on",
            "list_layers",
            "{}",
        ])
        .is_err());
    }

    #[test]
    fn title_block_profiles_option_exists_only_on_runtime_commands() {
        assert!(Cli::try_parse_from([
            "autocad-mcp",
            "serve",
            "--title-block-profiles",
            "/profiles.json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "autocad-mcp",
            "call",
            "--title-block-profiles",
            "/profiles.json",
            "write_title_block",
            "{}",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "autocad-mcp",
            "list-tools",
            "--title-block-profiles",
            "/profiles.json",
        ])
        .is_err());
    }

    #[test]
    fn explicit_title_block_profiles_path_precedes_environment_fallback() {
        let cli = PathBuf::from("/cli.json");
        let environment = OsString::from("/environment.json");
        assert_eq!(
            resolve_title_block_profiles_path(Some(cli.clone()), Some(environment)),
            Some(cli)
        );
        assert_eq!(
            resolve_title_block_profiles_path(None, Some(OsString::from("/environment.json"))),
            Some(PathBuf::from("/environment.json"))
        );
        assert_eq!(
            resolve_title_block_profiles_path(None, Some(OsString::new())),
            None
        );
    }

    #[test]
    fn administrator_title_block_commands_are_namespaced_outside_call() {
        assert!(Cli::try_parse_from([
            "autocad-mcp",
            "admin",
            "title-block",
            "survey",
            "--root",
            "/corpus",
            "--input",
            "/corpus/drawings",
            "--corpus-tier",
            "2",
            "--output",
            "survey.jsonl",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "autocad-mcp",
            "admin",
            "title-block",
            "validate",
            "--profiles",
            "/profiles.json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "autocad-mcp",
            "admin",
            "title-block",
            "survey",
            "--root",
            "/corpus",
            "--input",
            "/corpus/drawings",
            "--corpus-tier",
            "4",
            "--output",
            "survey.jsonl",
        ])
        .is_err());
        assert!(Cli::try_parse_from(["autocad-mcp", "call", "survey_title_blocks", "{}",]).is_ok());
    }

    #[test]
    fn call_cli_accepts_inline_or_file_params_but_not_both() {
        let inline = Cli::try_parse_from([
            "autocad-mcp",
            "call",
            "list_layouts",
            r#"{"drawing_path":"x"}"#,
        ]);
        assert!(inline.is_ok());

        let from_file = Cli::try_parse_from([
            "autocad-mcp",
            "call",
            "list_layouts",
            "--params-file",
            "params.json",
        ]);
        assert!(from_file.is_ok());

        let missing = Cli::try_parse_from(["autocad-mcp", "call", "list_layouts"]);
        assert!(missing.is_err());

        let conflicting = Cli::try_parse_from([
            "autocad-mcp",
            "call",
            "list_layouts",
            r#"{"drawing_path":"x"}"#,
            "--params-file",
            "params.json",
        ]);
        assert!(conflicting.is_err());
    }

    #[test]
    fn params_file_supports_spaces_and_non_ascii_without_native_json_quoting() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("tool params \u{03bb}.json");
        let expected = r#"{"drawing_path":"C:\\drawing space\\sample.dxf"}"#;
        fs::write(&path, expected.as_bytes()).unwrap();

        assert_eq!(
            resolve_call_params(None, Some(path)).unwrap(),
            expected.to_owned()
        );
    }

    #[test]
    fn params_file_rejects_non_utf8_non_files_and_oversize_inputs() {
        let temporary = tempfile::tempdir().unwrap();

        let invalid_utf8 = temporary.path().join("invalid.json");
        fs::write(&invalid_utf8, [0xff]).unwrap();
        assert!(read_call_params_file(&invalid_utf8)
            .unwrap_err()
            .contains("strict UTF-8"));

        assert!(read_call_params_file(temporary.path())
            .unwrap_err()
            .contains("regular non-symlink file"));

        let oversized = temporary.path().join("oversized.json");
        let mut file = fs::File::create(&oversized).unwrap();
        file.write_all(b"{").unwrap();
        file.set_len(MAX_CALL_PARAMS_FILE_BYTES + 1).unwrap();
        drop(file);
        assert!(read_call_params_file(&oversized)
            .unwrap_err()
            .contains("exceeds"));
    }

    #[cfg(unix)]
    #[test]
    fn params_file_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target.json");
        let link = temporary.path().join("link.json");
        fs::write(&target, b"{}").unwrap();
        symlink(&target, &link).unwrap();

        assert!(read_call_params_file(&link)
            .unwrap_err()
            .contains("regular non-symlink file"));
    }
}
