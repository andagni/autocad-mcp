use distribution_evidence::EvidenceSummary;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn git_command(directory: &Path) -> Command {
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
    command.env_clear().current_dir(directory);
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
    let root = std::fs::canonicalize(&root).map_err(|error| {
        format!(
            "canonicalize discovered repository root {}: {error}",
            root.display()
        )
    })?;
    let start = std::fs::canonicalize(start).map_err(|error| {
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

fn repository_root() -> Result<PathBuf, String> {
    let current = std::env::current_dir()
        .map_err(|error| format!("resolve current directory for distribution-evidence: {error}"))?;
    repository_root_from(&current)
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

fn report_from_repository(operation: fn(&Path) -> Result<EvidenceSummary, String>) -> ExitCode {
    match repository_root() {
        Ok(repository) => report(operation(&repository)),
        Err(error) => report(Err(error)),
    }
}

fn main() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command] if command == "check" => report_from_repository(distribution_evidence::check),
        [command] if command == "write" => report_from_repository(distribution_evidence::write),
        [command] if command == "release-gate" => {
            report_from_repository(distribution_evidence::release_gate)
        }
        _ => {
            eprintln!(
                "usage: cargo run --locked -p distribution-evidence -- <check|write|release-gate>"
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestRepository(PathBuf);

    impl Drop for TestRepository {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_repository() -> TestRepository {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = (0..32)
            .find_map(|_| {
                let candidate = std::env::temp_dir().join(format!(
                    "distribution-evidence-runtime-root-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match std::fs::create_dir(&candidate) {
                    Ok(()) => Some(candidate),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => panic!("create temporary repository: {error}"),
                }
            })
            .expect("allocate unique temporary repository");
        let status = git_command(&directory)
            .args([
                "init",
                "--quiet",
                "--initial-branch=main",
                "--object-format=sha1",
                ".",
            ])
            .status()
            .expect("launch git init");
        assert!(status.success(), "initialize temporary repository");
        TestRepository(directory)
    }

    #[test]
    fn repository_root_is_discovered_from_the_runtime_checkout() {
        const CHILD: &str = "AUTOCAD_MCP_EVIDENCE_ROOT_DISCOVERY_TEST_CHILD";
        const START: &str = "AUTOCAD_MCP_EVIDENCE_ROOT_DISCOVERY_TEST_START";
        const EXPECTED: &str = "AUTOCAD_MCP_EVIDENCE_ROOT_DISCOVERY_TEST_EXPECTED";
        const TEST_NAME: &str = "tests::repository_root_is_discovered_from_the_runtime_checkout";

        if std::env::var_os(CHILD).is_some() {
            let start = PathBuf::from(std::env::var_os(START).expect("child start path"));
            let expected =
                PathBuf::from(std::env::var_os(EXPECTED).expect("child expected repository"));
            let discovered =
                repository_root_from(&start).expect("discover root under hostile Git environment");
            assert_eq!(
                discovered,
                std::fs::canonicalize(expected).expect("canonical expected child repository")
            );
            return;
        }

        let repository = test_repository();
        let nested = repository.0.join("nested/runtime");
        std::fs::create_dir_all(&nested).expect("create nested runtime path");

        let discovered =
            repository_root_from(&nested).expect("discover temporary runtime repository");
        assert_eq!(
            std::fs::canonicalize(discovered).expect("canonical discovered repository"),
            std::fs::canonicalize(&repository.0).expect("canonical temporary repository")
        );

        let foreign = test_repository();
        let foreign_git_dir =
            std::fs::canonicalize(foreign.0.join(".git")).expect("canonical foreign Git directory");
        let child =
            Command::new(std::env::current_exe().expect("current evidence test executable"))
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(CHILD, "1")
                .env(START, &nested)
                .env(EXPECTED, &repository.0)
                .env("GIT_DIR", &foreign_git_dir)
                .env("GIT_COMMON_DIR", &foreign_git_dir)
                .env("GIT_WORK_TREE", &foreign.0)
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
}
