use distribution_evidence::EvidenceSummary;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|candidate| {
            std::fs::read_to_string(candidate.join("Cargo.toml"))
                .map(|manifest| manifest.lines().any(|line| line.trim() == "[workspace]"))
                .unwrap_or(false)
        })
        .expect("distribution-evidence must be contained by a Cargo workspace")
        .to_path_buf()
}

fn report(result: Result<EvidenceSummary, String>) -> ExitCode {
    match result {
        Ok(summary) => {
            eprintln!(
                "distribution evidence passed: {} locked packages ({} third-party), Windows source closure {} packages ({} third-party), {} without retained licence files; owner approval mode: {}",
                summary.total_packages(),
                summary.third_party_packages(),
                summary.windows_source_closure_packages(),
                summary.windows_source_closure_third_party_packages(),
                summary.packages_without_retained_license_files(),
                summary.owner_approval_mode()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let repository = repository_root();
    match arguments.as_slice() {
        [command] if command == "check" => report(distribution_evidence::check(&repository)),
        [command] if command == "write" => report(distribution_evidence::write(&repository)),
        [command] if command == "release-gate" => {
            report(distribution_evidence::release_gate(&repository))
        }
        _ => {
            eprintln!(
                "usage: cargo run --locked -p distribution-evidence -- <check|write|release-gate>"
            );
            ExitCode::from(2)
        }
    }
}
