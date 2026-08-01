mod cargo_layout;

use cargo_layout::{CargoStorageLayout, SOURCE_VALIDATION_PROFILE};
use std::ffi::OsString;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u8, String> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    validate_arguments(&arguments)?;
    let current = std::env::current_dir()
        .map_err(|error| format!("resolve quality-dispatch working directory: {error}"))?;
    let repository = cargo_layout::repository_root_from(&current)?;
    let layout = CargoStorageLayout::discover(&repository)?;
    let _lock = layout.acquire_governed_lock()?;
    if arguments
        .first()
        .is_some_and(|argument| argument == "clean-core-workspace")
    {
        let status = layout
            .core_cleanup_command(
                &repository,
                arguments
                    .get(1)
                    .is_some_and(|argument| argument == "--dry-run"),
            )
            .status()
            .map_err(|error| format!("launch governed Cargo core cleanup: {error}"))?;
        return Ok(exit_code(status));
    }

    let pre_cleanup = layout
        .core_cleanup_command(&repository, false)
        .status()
        .map_err(|error| format!("launch pre-gate Cargo core cleanup: {error}"))?;
    if !pre_cleanup.success() {
        return Ok(exit_code(pre_cleanup));
    }

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command.current_dir(&repository).args([
        "run",
        "--locked",
        "--profile",
        SOURCE_VALIDATION_PROFILE,
        "-p",
        "xtask",
        "--bin",
        "xtask",
        "--",
    ]);
    layout.configure_source_validation(&mut command);
    command.args(&arguments);
    let gate_status = match command.status() {
        Ok(status) => status,
        Err(error) => {
            let cleanup = layout.core_cleanup_command(&repository, false).status();
            return Err(match cleanup {
                Ok(status) if status.success() => {
                    format!("launch governed quality coordinator: {error}")
                }
                Ok(status) => format!(
                    "launch governed quality coordinator: {error}; post-launch-failure Cargo core cleanup also failed with {status}"
                ),
                Err(cleanup_error) => format!(
                    "launch governed quality coordinator: {error}; could not launch post-launch-failure Cargo core cleanup: {cleanup_error}"
                ),
            });
        }
    };
    let post_cleanup = layout
        .core_cleanup_command(&repository, false)
        .status()
        .map_err(|error| format!("launch post-gate Cargo core cleanup: {error}"))?;
    if !gate_status.success() {
        if !post_cleanup.success() {
            eprintln!(
                "ERROR: quality gate and post-gate Cargo core cleanup both failed; preserving the quality-gate exit status"
            );
        }
        Ok(exit_code(gate_status))
    } else {
        Ok(exit_code(post_cleanup))
    }
}

fn exit_code(status: std::process::ExitStatus) -> u8 {
    status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(1)
}

fn validate_arguments(arguments: &[OsString]) -> Result<(), String> {
    let values = arguments
        .iter()
        .map(|argument| argument.to_str())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "quality-dispatch arguments must be UTF-8".to_owned())?;
    let valid = matches!(
        values.as_slice(),
        ["local-gate"]
            | ["local-gate", "--timings"]
            | ["source-quality"]
            | ["source-quality", "--timings"]
            | ["candidate-quality"]
            | ["candidate-quality", "--timings"]
            | ["clean-core-workspace"]
            | ["clean-core-workspace", "--dry-run"]
    );
    if valid {
        Ok(())
    } else {
        Err(
            "usage: cargo run --locked -p xtask --no-default-features --bin quality-dispatch -- <local-gate|source-quality|candidate-quality> [--timings]\n       cargo run --locked -p xtask --no-default-features --bin quality-dispatch -- clean-core-workspace [--dry-run]"
                .to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_surface_is_closed_to_governed_quality_operations() {
        for arguments in [
            vec!["source-quality"],
            vec!["candidate-quality", "--timings"],
            vec!["clean-core-workspace", "--dry-run"],
        ] {
            assert!(validate_arguments(
                &arguments
                    .into_iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>()
            )
            .is_ok());
        }
        assert!(validate_arguments(&[OsString::from("source-candidate-seal")]).is_err());
        assert!(validate_arguments(&[
            OsString::from("clean-core-workspace"),
            OsString::from("--force")
        ])
        .is_err());
    }
}
