use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

fn bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_autolisp-lsp"))
}

fn read_lsp_message(
    reader: &mut BufReader<std::process::ChildStdout>,
) -> Result<serde_json::Value, String> {
    let mut content_length = None;
    loop {
        let mut line = String::new();
        let bytes = reader
            .read_line(&mut line)
            .map_err(|err| format!("failed to read LSP header: {err}"))?;
        if bytes == 0 {
            return Err("server closed stdout before sending a complete LSP message".to_string());
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("Content-Length: ") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid Content-Length {value:?}: {err}"))?,
            );
        }
    }
    let len = content_length.ok_or_else(|| "missing Content-Length".to_string())?;
    let mut body = vec![0_u8; len];
    reader
        .read_exact(&mut body)
        .map_err(|err| format!("failed to read LSP body: {err}"))?;
    serde_json::from_slice(&body).map_err(|err| format!("invalid JSON response: {err}"))
}

fn write_lsp_message(
    stdin: &mut std::process::ChildStdin,
    value: serde_json::Value,
) -> Result<(), String> {
    let body = value.to_string();
    write!(stdin, "Content-Length: {}\r\n\r\n{}", body.len(), body)
        .map_err(|err| format!("failed to write LSP message: {err}"))?;
    stdin
        .flush()
        .map_err(|err| format!("failed to flush LSP message: {err}"))
}

fn spawn_stdout_reader(
    stdout: std::process::ChildStdout,
) -> Receiver<Result<serde_json::Value, String>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let message = read_lsp_message(&mut reader);
            let done = message.is_err();
            if tx.send(message).is_err() || done {
                break;
            }
        }
    });
    rx
}

fn spawn_stderr_reader(stderr: std::process::ChildStderr) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut stderr = stderr;
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    })
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().unwrap().is_some() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn terminate_child(child: &mut Child) {
    if child.try_wait().unwrap().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn collect_stderr(stderr: &mut Option<thread::JoinHandle<String>>) -> String {
    stderr
        .take()
        .map(|handle| {
            handle
                .join()
                .unwrap_or_else(|_| "<stderr thread panicked>".to_string())
        })
        .unwrap_or_default()
}

fn fail_with_cleanup(
    child: &mut Child,
    stderr: &mut Option<thread::JoinHandle<String>>,
    message: String,
) -> ! {
    terminate_child(child);
    let stderr_text = collect_stderr(stderr);
    panic!("{message}\nstderr:\n{stderr_text}");
}

fn expect_lsp_message(
    rx: &Receiver<Result<serde_json::Value, String>>,
    child: &mut Child,
    stderr: &mut Option<thread::JoinHandle<String>>,
    context: &str,
) -> serde_json::Value {
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(value)) => value,
        Ok(Err(err)) => fail_with_cleanup(
            child,
            stderr,
            format!("failed while waiting for {context}: {err}"),
        ),
        Err(err) => fail_with_cleanup(
            child,
            stderr,
            format!("timed out waiting for {context}: {err}"),
        ),
    }
}

fn send_lsp_message(
    stdin: &mut std::process::ChildStdin,
    child: &mut Child,
    stderr: &mut Option<thread::JoinHandle<String>>,
    value: serde_json::Value,
) {
    if let Err(err) = write_lsp_message(stdin, value) {
        fail_with_cleanup(child, stderr, err);
    }
}

fn expect_json_eq(
    actual: &serde_json::Value,
    expected: serde_json::Value,
    child: &mut Child,
    stderr: &mut Option<thread::JoinHandle<String>>,
    context: &str,
) {
    if actual != &expected {
        fail_with_cleanup(
            child,
            stderr,
            format!("unexpected {context}: expected {expected}, got {actual}"),
        );
    }
}

fn expect_lsp_response(
    rx: &Receiver<Result<serde_json::Value, String>>,
    child: &mut Child,
    stderr: &mut Option<thread::JoinHandle<String>>,
    id: i64,
    context: &str,
) -> serde_json::Value {
    let message = expect_lsp_message(rx, child, stderr, context);
    expect_json_eq(
        &message["id"],
        serde_json::json!(id),
        child,
        stderr,
        context,
    );
    message
}

fn expect_lsp_notification(
    rx: &Receiver<Result<serde_json::Value, String>>,
    child: &mut Child,
    stderr: &mut Option<thread::JoinHandle<String>>,
    method: &str,
    context: &str,
) -> serde_json::Value {
    let message = expect_lsp_message(rx, child, stderr, context);
    expect_json_eq(
        &message["method"],
        serde_json::json!(method),
        child,
        stderr,
        context,
    );
    message
}

fn shutdown_server(
    mut stdin: std::process::ChildStdin,
    mut child: Child,
    rx: &Receiver<Result<serde_json::Value, String>>,
    stderr: &mut Option<thread::JoinHandle<String>>,
    shutdown_id: i64,
) {
    send_lsp_message(
        &mut stdin,
        &mut child,
        stderr,
        serde_json::json!({"jsonrpc":"2.0","id":shutdown_id,"method":"shutdown"}),
    );
    let shutdown = expect_lsp_response(rx, &mut child, stderr, shutdown_id, "shutdown response");
    expect_json_eq(
        &shutdown["result"],
        serde_json::Value::Null,
        &mut child,
        stderr,
        "shutdown result",
    );

    send_lsp_message(
        &mut stdin,
        &mut child,
        stderr,
        serde_json::json!({"jsonrpc":"2.0","method":"exit","params":{}}),
    );
    drop(stdin);
    if !wait_for_exit(&mut child, Duration::from_secs(5)) {
        fail_with_cleanup(
            &mut child,
            stderr,
            "timed out waiting for server process to exit".to_string(),
        );
    }
    let status = child.wait().unwrap();
    let stderr_text = collect_stderr(stderr);
    assert!(
        status.success(),
        "server exited with {status}\nstderr:\n{stderr_text}"
    );
}

#[test]
fn server_initializes_and_shuts_down_over_stdio() {
    let mut child = Command::new(bin())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let rx = spawn_stdout_reader(stdout);
    let mut stderr = Some(spawn_stderr_reader(stderr));

    send_lsp_message(
        &mut stdin,
        &mut child,
        &mut stderr,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": null,
                "capabilities": {}
            }
        }),
    );
    let init = expect_lsp_message(&rx, &mut child, &mut stderr, "initialize response");
    expect_json_eq(
        &init["id"],
        serde_json::json!(1),
        &mut child,
        &mut stderr,
        "initialize id",
    );
    expect_json_eq(
        &init["result"]["serverInfo"]["name"],
        serde_json::json!("autolisp-lsp"),
        &mut child,
        &mut stderr,
        "server name",
    );
    expect_json_eq(
        &init["result"]["capabilities"]["hoverProvider"],
        serde_json::json!(true),
        &mut child,
        &mut stderr,
        "hover provider capability",
    );

    send_lsp_message(
        &mut stdin,
        &mut child,
        &mut stderr,
        serde_json::json!({"jsonrpc":"2.0","method":"initialized","params":{}}),
    );

    send_lsp_message(
        &mut stdin,
        &mut child,
        &mut stderr,
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"shutdown"}),
    );
    let shutdown = expect_lsp_message(&rx, &mut child, &mut stderr, "shutdown response");
    expect_json_eq(
        &shutdown["id"],
        serde_json::json!(2),
        &mut child,
        &mut stderr,
        "shutdown id",
    );
    expect_json_eq(
        &shutdown["result"],
        serde_json::Value::Null,
        &mut child,
        &mut stderr,
        "shutdown result",
    );

    send_lsp_message(
        &mut stdin,
        &mut child,
        &mut stderr,
        serde_json::json!({"jsonrpc":"2.0","method":"exit","params":{}}),
    );
    drop(stdin);
    if !wait_for_exit(&mut child, Duration::from_secs(5)) {
        fail_with_cleanup(
            &mut child,
            &mut stderr,
            "timed out waiting for server process to exit".to_string(),
        );
    }
    let status = child.wait().unwrap();
    let stderr_text = collect_stderr(&mut stderr);
    assert!(
        status.success(),
        "server exited with {status}\nstderr:\n{stderr_text}"
    );
}

#[test]
fn server_handles_document_diagnostics_hover_and_completion_over_stdio() {
    let child = Command::new(bin())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut child = child;
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let rx = spawn_stdout_reader(stdout);
    let mut stderr = Some(spawn_stderr_reader(stderr));

    send_lsp_message(
        &mut stdin,
        &mut child,
        &mut stderr,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": null,
                "capabilities": {}
            }
        }),
    );
    let init = expect_lsp_response(&rx, &mut child, &mut stderr, 1, "initialize response");
    expect_json_eq(
        &init["result"]["capabilities"]["hoverProvider"],
        serde_json::json!(true),
        &mut child,
        &mut stderr,
        "hover provider capability",
    );
    assert!(
        init["result"]["capabilities"]["completionProvider"].is_object(),
        "expected completion provider capability, got {init}"
    );

    send_lsp_message(
        &mut stdin,
        &mut child,
        &mut stderr,
        serde_json::json!({"jsonrpc":"2.0","method":"initialized","params":{}}),
    );

    let uri = "file:///tmp/autolisp-lsp-stdio-fixture.lsp";
    let text = "(let ((value 1))\n  (setq value 2)\n  ss\n)\n";
    send_lsp_message(
        &mut stdin,
        &mut child,
        &mut stderr,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": uri,
                    "languageId": "autolisp",
                    "version": 1,
                    "text": text
                }
            }
        }),
    );
    let diagnostics = expect_lsp_notification(
        &rx,
        &mut child,
        &mut stderr,
        "textDocument/publishDiagnostics",
        "publish diagnostics notification",
    );
    expect_json_eq(
        &diagnostics["params"]["uri"],
        serde_json::json!(uri),
        &mut child,
        &mut stderr,
        "diagnostics uri",
    );
    let diagnostic_messages = diagnostics["params"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| {
            fail_with_cleanup(
                &mut child,
                &mut stderr,
                format!("expected diagnostics array, got {diagnostics}"),
            )
        });
    assert!(
        diagnostic_messages.iter().any(|diagnostic| {
            diagnostic["source"] == "autolisp-validate"
                && diagnostic["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("let") && message.contains("AutoLISP"))
        }),
        "expected AutoLISP let diagnostic, got {diagnostics}"
    );

    send_lsp_message(
        &mut stdin,
        &mut child,
        &mut stderr,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": { "uri": uri },
                "position": { "line": 1, "character": 4 }
            }
        }),
    );
    let hover = expect_lsp_response(&rx, &mut child, &mut stderr, 2, "hover response");
    let hover_text = hover["result"]["contents"]
        .as_str()
        .or_else(|| hover["result"]["contents"]["value"].as_str())
        .unwrap_or_else(|| {
            fail_with_cleanup(
                &mut child,
                &mut stderr,
                format!("expected hover string contents, got {hover}"),
            )
        });
    assert!(
        hover_text.contains("(setq symbol value") && hover_text.contains("Source:"),
        "expected useful setq hover, got {hover_text}"
    );

    send_lsp_message(
        &mut stdin,
        &mut child,
        &mut stderr,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/completion",
            "params": {
                "textDocument": { "uri": uri },
                "position": { "line": 2, "character": 4 }
            }
        }),
    );
    let completion = expect_lsp_response(&rx, &mut child, &mut stderr, 3, "completion response");
    let labels: Vec<&str> = completion["result"]
        .as_array()
        .unwrap_or_else(|| {
            fail_with_cleanup(
                &mut child,
                &mut stderr,
                format!("expected completion array, got {completion}"),
            )
        })
        .iter()
        .filter_map(|item| item["label"].as_str())
        .collect();
    assert!(
        labels.contains(&"ssget") && labels.contains(&"ssname") && labels.contains(&"sslength"),
        "expected selection-set builtin completions, got {completion}"
    );

    shutdown_server(stdin, child, &rx, &mut stderr, 4);
}
