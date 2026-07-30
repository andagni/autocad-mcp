use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::Instant;

#[derive(Debug, Eq, PartialEq)]
struct PushUpdate {
    local_ref: String,
    local_oid: String,
    remote_ref: String,
}

fn main() -> ExitCode {
    let started = Instant::now();
    let mut input = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("ERROR: failed to read pre-push records: {error}");
        return ExitCode::FAILURE;
    }

    let result = repository_root().and_then(|root| run(&root, &input));
    let exit = match result {
        Ok(Some(commit)) => {
            eprintln!("rapid pre-push dispatch gate passed for {commit}");
            ExitCode::SUCCESS
        }
        Ok(None) => {
            eprintln!("rapid pre-push dispatch gate skipped: no commits are being pushed");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::FAILURE
        }
    };
    eprintln!(
        "rapid pre-push dispatch completed in {:.3}s",
        started.elapsed().as_secs_f64()
    );
    exit
}

fn run(root: &Path, input: &str) -> Result<Option<String>, String> {
    let updates = parse_push_updates(input)?;
    if updates.iter().all(|update| is_zero_oid(&update.local_oid)) {
        return Ok(None);
    }

    let head_before = git_output(root, &["rev-parse", "--verify", "HEAD"])?;
    let tree_before = git_output(root, &["rev-parse", "--verify", "HEAD^{tree}"])?;
    ensure_clean_checkout(root)?;
    validate_push_updates(&updates, &head_before, |oid| {
        let revision = format!("{oid}^{{commit}}");
        git_output(root, &["rev-parse", "--verify", &revision])
    })?;

    run_git_check(root, &["diff", "--check"])?;
    run_git_check(root, &["diff", "--cached", "--check"])?;
    run_cargo_fmt(root)?;

    let head_after = git_output(root, &["rev-parse", "--verify", "HEAD"])?;
    let tree_after = git_output(root, &["rev-parse", "--verify", "HEAD^{tree}"])?;
    if head_after != head_before || tree_after != tree_before {
        return Err(format!(
            "HEAD changed during rapid pre-push validation; commit {head_before} tree {tree_before} became commit {head_after} tree {tree_after}"
        ));
    }
    ensure_clean_checkout(root)?;
    Ok(Some(head_before))
}

fn repository_root() -> Result<std::path::PathBuf, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|error| format!("locate repository root: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "locate repository root failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let root = String::from_utf8(output.stdout)
        .map_err(|error| format!("repository root is not UTF-8: {error}"))?;
    Ok(std::path::PathBuf::from(root.trim()))
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
) -> Result<(), String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    for update in updates {
        if is_zero_oid(&update.local_oid) {
            continue;
        }
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
    Ok(())
}

fn run_git_check(root: &Path, arguments: &[&str]) -> Result<(), String> {
    let status = git_command(root)
        .args(arguments)
        .status()
        .map_err(|error| format!("launch git {}: {error}", arguments.join(" ")))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("git {} failed with {status}", arguments.join(" ")))
    }
}

fn run_cargo_fmt(root: &Path) -> Result<(), String> {
    let status = Command::new("cargo")
        .args(["fmt", "--all", "--", "--check"])
        .current_dir(root)
        .status()
        .map_err(|error| format!("launch cargo fmt --all -- --check: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("cargo fmt --all -- --check failed with {status}"))
    }
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

fn git_output(root: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = git_command(root)
        .args(arguments)
        .output()
        .map_err(|error| format!("launch git {}: {error}", arguments.join(" ")))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestRepository(std::path::PathBuf);

    impl TestRepository {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "autocad-mcp-pre-push-dispatch-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::create_dir(path.join("src")).unwrap();
            std::fs::write(
                path.join("Cargo.toml"),
                "[package]\nname = \"dispatch-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
            )
            .unwrap();
            std::fs::write(
                path.join("src/lib.rs"),
                "pub fn value() -> u8 {\n    7\n}\n",
            )
            .unwrap();
            for arguments in [
                &["init", "--quiet", "--initial-branch=main"][..],
                &["add", "."][..],
                &[
                    "-c",
                    "user.name=fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "initial",
                ][..],
            ] {
                let status = Command::new("git")
                    .current_dir(&path)
                    .args(arguments)
                    .status()
                    .unwrap();
                assert!(status.success(), "git {arguments:?} failed");
            }
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRepository {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn push_records_are_closed_and_deletions_are_identified() {
        let updates = parse_push_updates(
            "refs/heads/main abc123 refs/heads/main def456\n(delete) 000000 refs/heads/old abc123\n",
        )
        .unwrap();
        assert_eq!(updates.len(), 2);
        assert!(is_zero_oid("000000"));
        assert!(!is_zero_oid(""));
        assert!(!is_zero_oid("000100"));
        assert!(parse_push_updates("too few fields").is_err());
    }

    #[test]
    fn every_non_deletion_must_resolve_to_the_checked_out_head() {
        let updates = parse_push_updates(
            "refs/heads/main commit refs/heads/main old\nrefs/tags/v1 tag refs/tags/v1 zero\n",
        )
        .unwrap();
        validate_push_updates(&updates, "head", |oid| match oid {
            "commit" | "tag" => Ok("head".to_owned()),
            _ => Err("unexpected object".to_owned()),
        })
        .unwrap();
        let error = validate_push_updates(&updates, "other", |_| Ok("head".to_owned()))
            .expect_err("a different checked-out HEAD must be rejected");
        assert!(error.contains("clean checked-out HEAD is other"));
    }

    #[test]
    fn dispatch_runs_end_to_end_and_rejects_dirty_source() {
        let repository = TestRepository::new();
        let head = git_output(repository.path(), &["rev-parse", "--verify", "HEAD"]).unwrap();
        let input = format!("refs/heads/main {head} refs/heads/main 000000\n");
        assert_eq!(run(repository.path(), &input).unwrap(), Some(head));

        std::fs::write(repository.path().join("untracked.txt"), b"not admitted").unwrap();
        let error = run(repository.path(), &input).expect_err("dirty source must fail closed");
        assert!(error.contains("requires a clean checkout"));
    }
}
