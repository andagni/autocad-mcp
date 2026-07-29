use std::{path::PathBuf, process::Command};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(name)
}

#[test]
fn good_command_exits_successfully_without_diagnostics() {
    let output = Command::new(env!("CARGO_BIN_EXE_autolisp-validate"))
        .arg(fixture_path("good_command.lsp"))
        .output()
        .expect("run autolisp-validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success());
    assert_eq!(stdout, "");
    assert!(stderr.contains("Checked 1 file(s): 0 error(s), 0 warning(s)."));
}

#[test]
fn bad_command_exits_with_error_and_diagnostics() {
    let output = Command::new(env!("CARGO_BIN_EXE_autolisp-validate"))
        .arg(fixture_path("bad_command.lsp"))
        .output()
        .expect("run autolisp-validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(stdout.lines().any(|line| line.contains(": ERROR:")));
    assert!(stdout.lines().any(|line| line.contains(": WARN:")));
    assert!(stderr.contains("Checked 1 file(s): 1 error(s), 5 warning(s)."));
}
