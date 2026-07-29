use anyhow::Result;
use clap::error::ErrorKind;
use clap::{Parser, Subcommand};
use release_packager::approval::{
    verify_owner_distribution_approval, ApprovalVerificationOptions, ApprovalVerificationReport,
};
use release_packager::manifest::{PackageMode, PackageTarget};
use release_packager::package::{create_package, PackageOptions};
use release_packager::preview_build_attestation::{
    create_preview_build_attestation, CreatePreviewBuildAttestationOptions,
};
use release_packager::preview_publication::{
    create_preview_clean_host_receipt, publish_preview_prerelease,
    seal_preview_publication_handoff, verify_preview_publication_handoff,
    CreatePreviewCleanHostReceiptOptions, PublishPreviewPrereleaseOptions,
    SealPreviewPublicationHandoffOptions, VerifyPreviewPublicationHandoffOptions,
};
use release_packager::smoke::{
    smoke_desktop_binary, smoke_lsp_binary, smoke_package, SmokeOptions, SmokeReport,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "release-packager",
    about = "Build and smoke-test AutoCAD MCP release packages"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build one platform-specific MCPB package from an already-built binary.
    Package {
        #[arg(long)]
        target: PackageTarget,
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        lsp_binary: Option<PathBuf>,
        /// Build a visibly marked Windows Preview package with experimental support.
        #[arg(long)]
        preview: bool,
        #[arg(long, default_value = "dist")]
        out_dir: PathBuf,
        #[arg(long, default_value = "plugin")]
        plugin_dir: PathBuf,
        #[arg(long, default_value = "tests/fixtures/plugin-example")]
        schema_root: PathBuf,
    },
    /// Smoke-test a generated MCPB package.
    Smoke {
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        fixture: Option<PathBuf>,
        #[arg(long)]
        require_executable: bool,
        #[arg(long)]
        require_lsp_executable: bool,
    },
    /// Exercise a native binary through the Claude Desktop stdio lifecycle.
    DesktopSmoke {
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        fixture: PathBuf,
    },
    /// Exercise a native AutoLISP LSP binary through initialize/shutdown stdio.
    LspSmoke {
        #[arg(long)]
        binary: PathBuf,
    },
    /// Verify one detached owner approval against the exact finished distribution set.
    VerifyApproval {
        #[arg(long)]
        approval: PathBuf,
        #[arg(long)]
        mcpb: PathBuf,
        #[arg(long)]
        source_zip: PathBuf,
        #[arg(long)]
        source_closure_sbom: PathBuf,
        #[arg(long)]
        build_attestation: PathBuf,
    },
    /// Create the final post-signing Preview build attestation.
    CreatePreviewBuildAttestation {
        #[arg(long)]
        source_zip: PathBuf,
        #[arg(long)]
        mcpb: PathBuf,
        #[arg(long)]
        unsigned_preflight: PathBuf,
        #[arg(long)]
        workflow: PathBuf,
        #[arg(long)]
        run_id: u64,
        #[arg(long)]
        run_attempt: u64,
        #[arg(long)]
        github_repository: String,
        #[arg(long)]
        github_server_url: String,
        #[arg(long)]
        github_ref: String,
        #[arg(long)]
        github_event_name: String,
        #[arg(long)]
        github_actor: String,
        #[arg(long)]
        github_triggering_actor: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Emit a closed privacy-safe receipt after the manual clean-host checklist passed.
    CreatePreviewCleanHostReceipt {
        #[arg(long)]
        mcpb: PathBuf,
        #[arg(long)]
        client_version: String,
        #[arg(long)]
        host_os_version: String,
        #[arg(long)]
        completed_utc: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign the exact nine-file detached Preview publication handoff.
    SealPreviewPublicationHandoff {
        #[arg(long, default_value = ".")]
        repository: PathBuf,
        #[arg(long)]
        handoff_dir: PathBuf,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        private_key_file: PathBuf,
    },
    /// Authenticate and semantically reverify a closed ten-file Preview handoff.
    VerifyPreviewPublicationHandoff {
        #[arg(long, default_value = ".")]
        repository: PathBuf,
        #[arg(long)]
        handoff_dir: PathBuf,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        public_key: String,
    },
    /// Publish a fresh immutable Preview prerelease to the fixed GitHub repository.
    PublishPreviewPrerelease {
        #[arg(long)]
        handoff_dir: PathBuf,
        #[arg(long)]
        source_repository: PathBuf,
        #[arg(long)]
        projection: PathBuf,
        #[arg(long)]
        github_cli: PathBuf,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        serial: u64,
        /// Confirm exclusive owner-enforced local-authority and destination-repository write custody.
        #[arg(long, required = true)]
        exclusive_write_window_confirmed: bool,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("ERROR: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) => {
            e.print()?;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    match cli.command {
        Command::Package {
            target,
            binary,
            lsp_binary,
            preview,
            out_dir,
            plugin_dir,
            schema_root,
        } => {
            let package = create_package(PackageOptions {
                mode: if preview {
                    PackageMode::Preview
                } else {
                    PackageMode::Release
                },
                target,
                plugin_dir,
                schema_root,
                binary_path: binary,
                lsp_binary_path: lsp_binary,
                out_dir,
            })?;
            println!("{}", package.display());
        }
        Command::Smoke {
            package,
            fixture,
            require_executable,
            require_lsp_executable,
        } => {
            let report = smoke_package(SmokeOptions {
                package_path: package,
                fixture_path: fixture,
                require_executable,
                require_lsp_executable,
            })?;
            println!("{}", smoke_success_message(&report));
        }
        Command::DesktopSmoke { binary, fixture } => {
            smoke_desktop_binary(&binary, &fixture)?;
            println!("Claude Desktop stdio smoke passed");
        }
        Command::LspSmoke { binary } => {
            smoke_lsp_binary(&binary)?;
            println!("AutoLISP LSP stdio smoke passed");
        }
        Command::VerifyApproval {
            approval,
            mcpb,
            source_zip,
            source_closure_sbom,
            build_attestation,
        } => {
            let report = verify_owner_distribution_approval(&ApprovalVerificationOptions {
                approval_path: approval,
                mcpb_path: mcpb,
                source_archive_path: source_zip,
                source_closure_sbom_path: source_closure_sbom,
                build_attestation_path: build_attestation,
            })?;
            println!("{}", approval_success_message(&report));
        }
        Command::CreatePreviewBuildAttestation {
            source_zip,
            mcpb,
            unsigned_preflight,
            workflow,
            run_id,
            run_attempt,
            github_repository,
            github_server_url,
            github_ref,
            github_event_name,
            github_actor,
            github_triggering_actor,
            output,
        } => {
            let report = create_preview_build_attestation(&CreatePreviewBuildAttestationOptions {
                source_archive_path: source_zip,
                mcpb_path: mcpb,
                unsigned_preflight_path: unsigned_preflight,
                workflow_path: workflow,
                run_id,
                run_attempt,
                github_repository,
                github_server_url,
                github_ref,
                github_event_name,
                github_actor,
                github_triggering_actor,
                output_path: output,
            })?;
            println!("{}", report.output_path.display());
        }
        Command::CreatePreviewCleanHostReceipt {
            mcpb,
            client_version,
            host_os_version,
            completed_utc,
            output,
        } => {
            create_preview_clean_host_receipt(&CreatePreviewCleanHostReceiptOptions {
                mcpb_path: mcpb,
                client_version,
                host_os_version,
                completed_utc,
                output_path: output,
            })?;
            println!("Preview clean-host receipt created");
        }
        Command::SealPreviewPublicationHandoff {
            repository,
            handoff_dir,
            key_id,
            private_key_file,
        } => {
            let verified =
                seal_preview_publication_handoff(&SealPreviewPublicationHandoffOptions {
                    repository,
                    handoff_directory: handoff_dir,
                    key_id,
                    private_key_file,
                })?;
            println!(
                "Preview publication handoff sealed for version {} decision {}",
                verified.release_version(),
                verified.decision_id()
            );
        }
        Command::VerifyPreviewPublicationHandoff {
            repository,
            handoff_dir,
            key_id,
            public_key,
        } => {
            let verified =
                verify_preview_publication_handoff(&VerifyPreviewPublicationHandoffOptions {
                    repository,
                    handoff_directory: handoff_dir,
                    key_id,
                    public_key_hex: public_key,
                })?;
            println!(
                "Preview publication handoff verified for version {} decision {} with {} public assets",
                verified.release_version(),
                verified.decision_id(),
                verified.public_asset_count()
            );
        }
        Command::PublishPreviewPrerelease {
            handoff_dir,
            source_repository,
            projection,
            github_cli,
            key_id,
            public_key,
            serial,
            exclusive_write_window_confirmed,
        } => {
            let published = publish_preview_prerelease(&PublishPreviewPrereleaseOptions {
                handoff_directory: handoff_dir,
                source_repository,
                projection_repository: projection,
                github_cli,
                key_id,
                public_key_hex: public_key,
                serial,
                exclusive_write_window_confirmed,
            })?;
            println!("immutable Preview prerelease {} published", published.tag);
        }
    }
    Ok(())
}

fn approval_success_message(report: &ApprovalVerificationReport) -> String {
    let attestation_status = if report.native_build_attestation_semantics_verified {
        "native Preview build-attestation semantics verified"
    } else {
        "native build-attestation semantics were not evaluated"
    };
    format!(
        "approval verification passed for decision {}: {} artifacts, {} MCPB entries, {} source ZIP entries, distribution evidence reconciled; {}",
        report.decision_id,
        report.verified_artifacts,
        report.mcpb_entries,
        report.source_archive_entries,
        attestation_status
    )
}

fn smoke_success_message(report: &SmokeReport) -> &'static str {
    match (report.executable_ran, report.lsp_executable_ran) {
        (true, true) => "static smoke passed; executable smoke passed; lsp smoke passed",
        (true, false) => "static smoke passed; executable smoke passed",
        (false, true) => "static smoke passed; executable smoke skipped; lsp smoke passed",
        (false, false) => "static smoke passed; executable smoke skipped",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_smoke_success_messages_are_exact() {
        assert_eq!(
            smoke_success_message(&SmokeReport {
                executable_ran: true,
                lsp_executable_ran: true
            }),
            "static smoke passed; executable smoke passed; lsp smoke passed"
        );
        assert_eq!(
            smoke_success_message(&SmokeReport {
                executable_ran: true,
                lsp_executable_ran: false
            }),
            "static smoke passed; executable smoke passed"
        );
        assert_eq!(
            smoke_success_message(&SmokeReport {
                executable_ran: false,
                lsp_executable_ran: true
            }),
            "static smoke passed; executable smoke skipped; lsp smoke passed"
        );
        assert_eq!(
            smoke_success_message(&SmokeReport {
                executable_ran: false,
                lsp_executable_ran: false
            }),
            "static smoke passed; executable smoke skipped"
        );
    }

    #[test]
    fn approval_success_message_preserves_native_semantic_boundary() {
        let mut report = ApprovalVerificationReport {
            decision_id: "decision-1".to_owned(),
            approval_sha256: "3".repeat(64),
            verified_artifacts: 6,
            mcpb_entries: 12,
            source_archive_entries: 34,
            distribution_evidence_validated: true,
            native_build_attestation_semantics_verified: false,
            package_mode: distribution_approval::DistributionMode::Release,
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
        };
        let message = approval_success_message(&report);
        assert!(message.contains("approval verification passed for decision decision-1"));
        assert!(message.contains("native build-attestation semantics were not evaluated"));

        report.package_mode = distribution_approval::DistributionMode::Preview;
        report.native_build_attestation_semantics_verified = true;
        let message = approval_success_message(&report);
        assert!(message.contains("native Preview build-attestation semantics verified"));
    }

    #[test]
    fn preview_publication_cli_requires_explicit_trust_and_selection_inputs() {
        let public_key = "a".repeat(64);
        let verify = Cli::try_parse_from([
            "release-packager",
            "verify-preview-publication-handoff",
            "--handoff-dir",
            "/detached/handoff",
            "--key-id",
            "owner-preview-1",
            "--public-key",
            &public_key,
        ])
        .unwrap();
        match verify.command {
            Command::VerifyPreviewPublicationHandoff {
                repository,
                handoff_dir,
                key_id,
                public_key: parsed_key,
            } => {
                assert_eq!(repository, PathBuf::from("."));
                assert_eq!(handoff_dir, PathBuf::from("/detached/handoff"));
                assert_eq!(key_id, "owner-preview-1");
                assert_eq!(parsed_key, public_key);
            }
            _ => panic!("wrong Preview handoff command parsed"),
        }

        assert!(Cli::try_parse_from([
            "release-packager",
            "verify-preview-publication-handoff",
            "--handoff-dir",
            "/detached/handoff",
            "--public-key",
            &public_key,
        ])
        .is_err());
    }

    #[test]
    fn preview_receipt_and_publisher_cli_shapes_are_closed() {
        let receipt = Cli::try_parse_from([
            "release-packager",
            "create-preview-clean-host-receipt",
            "--mcpb",
            "preview.mcpb",
            "--client-version",
            "0.13.78",
            "--host-os-version",
            "10.0.26100.4652",
            "--completed-utc",
            "2026-07-28T12:34:56Z",
            "--output",
            "receipt.json",
        ])
        .unwrap();
        assert!(matches!(
            receipt.command,
            Command::CreatePreviewCleanHostReceipt { .. }
        ));

        let public_key = "b".repeat(64);
        let publish = Cli::try_parse_from([
            "release-packager",
            "publish-preview-prerelease",
            "--handoff-dir",
            "/detached/handoff",
            "--source-repository",
            "/private/source",
            "--projection",
            "/detached/projection",
            "--github-cli",
            "/opt/homebrew/bin/gh",
            "--key-id",
            "owner-preview-1",
            "--public-key",
            &public_key,
            "--serial",
            "7",
            "--exclusive-write-window-confirmed",
        ])
        .unwrap();
        match publish.command {
            Command::PublishPreviewPrerelease {
                handoff_dir,
                source_repository,
                projection,
                github_cli,
                key_id,
                public_key: parsed_key,
                serial,
                exclusive_write_window_confirmed,
            } => {
                assert_eq!(handoff_dir, PathBuf::from("/detached/handoff"));
                assert_eq!(source_repository, PathBuf::from("/private/source"));
                assert_eq!(projection, PathBuf::from("/detached/projection"));
                assert_eq!(github_cli, PathBuf::from("/opt/homebrew/bin/gh"));
                assert_eq!(key_id, "owner-preview-1");
                assert_eq!(parsed_key, public_key);
                assert_eq!(serial, 7);
                assert!(exclusive_write_window_confirmed);
            }
            _ => panic!("wrong Preview publisher command parsed"),
        }

        assert!(Cli::try_parse_from([
            "release-packager",
            "publish-preview-prerelease",
            "--handoff-dir",
            "/detached/handoff",
            "--source-repository",
            "/private/source",
            "--projection",
            "/detached/projection",
            "--github-cli",
            "/opt/homebrew/bin/gh",
            "--key-id",
            "owner-preview-1",
            "--public-key",
            &public_key,
            "--serial",
            "7",
        ])
        .is_err());
    }
}
