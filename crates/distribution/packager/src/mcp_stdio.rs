//! Bounded newline-delimited MCP stdio client for repository-owned developer
//! tooling.

use crate::process_tree::ProcessTree;
use anyhow::{anyhow, Context, Result};
use autocad_mcp::certification::xref_sha256_bytes;
use serde_json::Value;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const MAX_MCP_FRAME_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MCP_SESSION_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 4 * 1024 * 1024;

/// Exact process launch configuration for one MCP stdio session.
#[derive(Clone, Debug)]
pub struct McpStdioLaunch {
    pub binary: PathBuf,
    pub arguments: Vec<String>,
    pub current_dir: PathBuf,
    pub environment: Vec<(OsString, OsString)>,
    pub clear_autocad_mcp_environment: bool,
    pub label: String,
    /// Optional caller-owned deadline spanning work outside this process.
    pub overall_deadline: Option<Instant>,
}

/// A parsed successful tool response and its normalized response digest.
#[derive(Clone, Debug)]
pub struct McpToolResponse {
    pub value: Value,
    pub response_sha256: String,
}

/// Bounded shutdown observations for one contained MCP process tree.
#[derive(Clone, Debug)]
pub struct McpShutdownObservation {
    pub status: ExitStatus,
    pub active_processes: Option<u32>,
}

/// Sequential MCP client over one contained child process.
pub struct McpStdioSession {
    child: Child,
    stdin: Option<ChildStdin>,
    response_rx: mpsc::Receiver<Result<Value>>,
    stderr_rx: mpsc::Receiver<Result<Vec<u8>>>,
    stderr: Vec<u8>,
    stderr_disconnected: bool,
    process_tree: ProcessTree,
    next_id: u64,
    label: String,
    overall_deadline: Option<Instant>,
    shutdown_complete: bool,
}

impl McpStdioSession {
    pub fn spawn(launch: McpStdioLaunch) -> Result<Self> {
        let mut command = Command::new(&launch.binary);
        command
            .args(&launch.arguments)
            .current_dir(&launch.current_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if launch.clear_autocad_mcp_environment {
            for (name, _) in std::env::vars_os() {
                if is_autocad_mcp_environment(&name) {
                    command.env_remove(name);
                }
            }
        }
        command.envs(launch.environment);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }

        let mut child = command
            .spawn()
            .with_context(|| format!("spawn {} from {}", launch.label, launch.binary.display()))?;
        let process_tree = match ProcessTree::new(&child) {
            Ok(tree) => tree,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).with_context(|| format!("contain {}", launch.label));
            }
        };
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("failed to capture stdin for {}", launch.label))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("failed to capture stdout for {}", launch.label))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("failed to capture stderr for {}", launch.label))?;

        Ok(Self {
            child,
            stdin: Some(stdin),
            response_rx: spawn_mcp_reader(stdout, &launch.label),
            stderr_rx: spawn_stderr_reader(stderr, &launch.label),
            stderr: Vec::new(),
            stderr_disconnected: false,
            process_tree,
            next_id: 1,
            label: launch.label,
            overall_deadline: launch.overall_deadline,
            shutdown_complete: false,
        })
    }

    /// Perform and validate the fixed evaluator initialization lifecycle.
    pub fn initialize(&mut self, timeout: Duration) -> Result<()> {
        let result = self.request(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "autocad-mcp-preview-evaluator",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
            timeout,
        )?;
        if result["protocolVersion"] != "2025-06-18" {
            return Err(anyhow!(
                "initialize response did not select MCP protocol 2025-06-18"
            ));
        }
        if !result["capabilities"]["tools"].is_object() {
            return Err(anyhow!(
                "initialize response did not advertise the MCP tools capability"
            ));
        }
        if result["serverInfo"]["name"] != autocad_mcp::server::SERVER_NAME
            || result["serverInfo"]["version"] != autocad_mcp::server::SERVER_VERSION
        {
            return Err(anyhow!(
                "initialize response server identity does not match the packaged autocad-mcp runtime"
            ));
        }
        self.notify("notifications/initialized", serde_json::json!({}))
    }

    pub fn list_tools(&mut self, timeout: Duration) -> Result<Value> {
        let result = self.request("tools/list", serde_json::json!({}), timeout)?;
        result
            .get("tools")
            .filter(|tools| tools.is_array())
            .cloned()
            .ok_or_else(|| anyhow!("tools/list result must contain a tools array"))
    }

    pub fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
        timeout: Duration,
    ) -> Result<McpToolResponse> {
        if !arguments.is_object() {
            return Err(anyhow!("MCP tool arguments for {name} must be an object"));
        }
        let result = self.request(
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
            timeout,
        )?;
        if result["isError"].as_bool() == Some(true) {
            return Err(anyhow!("MCP tool {name} returned a tool-level error"));
        }
        let content = result["content"]
            .as_array()
            .ok_or_else(|| anyhow!("MCP tool {name} result.content must be an array"))?;
        let texts = content
            .iter()
            .filter(|item| item["type"] == "text")
            .filter_map(|item| item["text"].as_str())
            .collect::<Vec<_>>();
        let text = match texts.as_slice() {
            [text] => *text,
            _ => {
                return Err(anyhow!(
                    "MCP tool {name} result must contain exactly one text item"
                ))
            }
        };
        let value = serde_json::from_str(text)
            .with_context(|| format!("parse MCP tool {name} text content as JSON"))?;
        let response_sha256 = xref_sha256_bytes(
            &serde_json::to_vec(&result)
                .with_context(|| format!("serialize normalized MCP tool {name} response"))?,
        );
        Ok(McpToolResponse {
            value,
            response_sha256,
        })
    }

    /// Wait until stderr contains one complete line with `marker`.
    pub fn wait_for_stderr_line(
        &mut self,
        marker: &str,
        timeout: Duration,
    ) -> Result<Option<String>> {
        let deadline = self.bounded_deadline(timeout);
        loop {
            self.drain_stderr()?;
            if let Some(line) = stderr_line_containing(&self.stderr, marker) {
                return Ok(Some(line));
            }
            if let Some(status) = self.child.try_wait()? {
                return Err(anyhow!(
                    "{} exited with {status} while waiting for its stderr observation",
                    self.label
                ));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn stderr_bytes(&mut self) -> Result<&[u8]> {
        self.drain_stderr()?;
        Ok(&self.stderr)
    }

    pub fn close_stdin_and_wait(&mut self, timeout: Duration) -> Result<McpShutdownObservation> {
        self.stdin.take();
        let deadline = self.bounded_deadline(timeout);
        loop {
            self.drain_stderr()?;
            if let Some(status) = self.child.try_wait()? {
                let drain_deadline = Instant::now() + Duration::from_millis(500);
                while !self.stderr_disconnected && Instant::now() < drain_deadline {
                    self.drain_stderr()?;
                    std::thread::sleep(Duration::from_millis(10));
                }
                if !status.success() {
                    return Err(anyhow!(
                        "{} exited unsuccessfully after stdin closed: {status}",
                        self.label
                    ));
                }
                let active_processes = self.process_tree.active_processes()?;
                if active_processes.is_some_and(|count| count != 0) {
                    self.process_tree.terminate();
                    return Err(anyhow!(
                        "{} left {active_processes:?} active Job Object processes after server exit",
                        self.label
                    ));
                }
                self.shutdown_complete = true;
                return Ok(McpShutdownObservation {
                    status,
                    active_processes,
                });
            }
            if Instant::now() >= deadline {
                self.terminate();
                return Err(anyhow!(
                    "{} did not exit within {timeout:?} after stdin closed",
                    self.label
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        self.write(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }))
    }

    fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("MCP request id exhausted"))?;
        self.write(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }))?;

        let deadline = self.bounded_deadline(timeout);
        loop {
            self.drain_stderr()?;
            if let Some(status) = self.child.try_wait()? {
                return Err(anyhow!(
                    "{} exited with {status} before {method} response",
                    self.label
                ));
            }
            match self.response_rx.try_recv() {
                Ok(Ok(response)) => return validate_response(response, id, method),
                Ok(Err(error)) => return Err(error),
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(anyhow!(
                        "{} stdout closed before {method} response",
                        self.label
                    ))
                }
            }
            if Instant::now() >= deadline {
                self.terminate();
                return Err(anyhow!("{method} timed out after {timeout:?}"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn write(&mut self, value: &Value) -> Result<()> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("{} stdin is already closed", self.label))?;
        serde_json::to_writer(&mut *stdin, value).context("serialize MCP request")?;
        stdin.write_all(b"\n").context("terminate MCP request")?;
        stdin.flush().context("flush MCP request")
    }

    fn bounded_deadline(&self, timeout: Duration) -> Instant {
        let requested = Instant::now() + timeout;
        self.overall_deadline
            .map_or(requested, |overall| requested.min(overall))
    }

    fn drain_stderr(&mut self) -> Result<()> {
        loop {
            match self.stderr_rx.try_recv() {
                Ok(Ok(chunk)) => {
                    if self.stderr.len().saturating_add(chunk.len()) > MAX_STDERR_BYTES {
                        self.terminate();
                        return Err(anyhow!(
                            "{} stderr exceeds the {MAX_STDERR_BYTES}-byte bound",
                            self.label
                        ));
                    }
                    self.stderr.extend_from_slice(&chunk);
                }
                Ok(Err(error)) => return Err(error),
                Err(mpsc::TryRecvError::Empty) => return Ok(()),
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.stderr_disconnected = true;
                    return Ok(());
                }
            }
        }
    }

    fn terminate(&mut self) {
        self.stdin.take();
        self.process_tree.terminate();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for McpStdioSession {
    fn drop(&mut self) {
        if !self.shutdown_complete {
            self.terminate();
        }
    }
}

fn is_autocad_mcp_environment(name: &OsStr) -> bool {
    name.to_string_lossy()
        .to_ascii_uppercase()
        .starts_with("AUTOCAD_MCP_")
}

fn validate_response(response: Value, id: u64, method: &str) -> Result<Value> {
    let object = response
        .as_object()
        .ok_or_else(|| anyhow!("{method} response must be a JSON object"))?;
    if object.get("jsonrpc") != Some(&Value::String("2.0".to_string())) {
        return Err(anyhow!("{method} response must declare JSON-RPC 2.0"));
    }
    if object.get("id") != Some(&Value::Number(id.into())) {
        return Err(anyhow!("{method} response id does not match request {id}"));
    }
    if object.contains_key("error") {
        return Err(anyhow!("{method} returned an MCP protocol error"));
    }
    object
        .get("result")
        .filter(|result| result.is_object())
        .cloned()
        .ok_or_else(|| anyhow!("{method} response must contain an object result"))
}

fn spawn_mcp_reader<R>(stream: R, label: &str) -> mpsc::Receiver<Result<Value>>
where
    R: Read + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let label = label.to_string();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut total = 0_u64;
        loop {
            let mut line = Vec::new();
            let read = match reader.read_until(b'\n', &mut line) {
                Ok(read) => read,
                Err(error) => {
                    let _ =
                        tx.send(Err(error).with_context(|| {
                            format!("read newline-delimited MCP stdout for {label}")
                        }));
                    return;
                }
            };
            if read == 0 {
                return;
            }
            total = total.saturating_add(read as u64);
            if line.len() as u64 > MAX_MCP_FRAME_BYTES {
                let _ = tx.send(Err(anyhow!(
                    "MCP stdout frame for {label} exceeds {MAX_MCP_FRAME_BYTES} bytes"
                )));
                return;
            }
            if total > MAX_MCP_SESSION_OUTPUT_BYTES {
                let _ = tx.send(Err(anyhow!(
                    "MCP stdout for {label} exceeds {MAX_MCP_SESSION_OUTPUT_BYTES} bytes"
                )));
                return;
            }
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            if line.is_empty() {
                continue;
            }
            let value = serde_json::from_slice(&line)
                .with_context(|| format!("parse newline-delimited MCP stdout for {label}"));
            if tx.send(value).is_err() {
                return;
            }
        }
    });
    rx
}

fn spawn_stderr_reader<R>(mut stream: R, label: &str) -> mpsc::Receiver<Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let label = label.to_string();
    std::thread::spawn(move || {
        let mut total = 0_usize;
        loop {
            let mut chunk = vec![0_u8; 8192];
            let read = match stream.read(&mut chunk) {
                Ok(read) => read,
                Err(error) => {
                    let _ = tx.send(Err(error).with_context(|| format!("read stderr for {label}")));
                    return;
                }
            };
            if read == 0 {
                return;
            }
            chunk.truncate(read);
            total = total.saturating_add(read);
            if total > MAX_STDERR_BYTES {
                let _ = tx.send(Err(anyhow!(
                    "stderr for {label} exceeds {MAX_STDERR_BYTES} bytes"
                )));
                return;
            }
            if tx.send(Ok(chunk)).is_err() {
                return;
            }
        }
    });
    rx
}

fn stderr_line_containing(stderr: &[u8], marker: &str) -> Option<String> {
    let complete_len = stderr
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|index| index + 1)?;
    String::from_utf8_lossy(&stderr[..complete_len])
        .lines()
        .find(|line| line.contains(marker))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn write_response(path: &std::path::Path, value: Value) {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        std::fs::write(path, bytes).unwrap();
    }

    #[cfg(unix)]
    fn shell_launch(
        directory: &std::path::Path,
        script: &std::path::Path,
        arguments: &[&std::path::Path],
        overall_deadline: Option<Instant>,
    ) -> McpStdioLaunch {
        let mut launch_arguments = vec![script.to_string_lossy().into_owned()];
        launch_arguments.extend(
            arguments
                .iter()
                .map(|path| path.to_string_lossy().into_owned()),
        );
        McpStdioLaunch {
            binary: PathBuf::from("/bin/sh"),
            arguments: launch_arguments,
            current_dir: directory.to_path_buf(),
            environment: vec![
                (
                    OsString::from("AUTOCAD_MCP_ALLOWED_TEST_VALUE"),
                    OsString::from("exact"),
                ),
                (OsString::from("RUST_LOG"), OsString::from("test=info")),
            ],
            clear_autocad_mcp_environment: true,
            label: "fake MCP stdio server".to_string(),
            overall_deadline,
        }
    }

    #[test]
    fn autocad_environment_filter_is_case_insensitive() {
        assert!(is_autocad_mcp_environment(OsStr::new(
            "AUTOCAD_MCP_ACCORECONSOLE_PATH"
        )));
        assert!(is_autocad_mcp_environment(OsStr::new(
            "autocad_mcp_title_block_profiles"
        )));
        assert!(!is_autocad_mcp_environment(OsStr::new("RUST_LOG")));
    }

    #[test]
    fn stderr_observation_requires_a_complete_matching_line() {
        assert_eq!(
            stderr_line_containing(b"one\nprobe state=Ready\nthree", "probe state="),
            Some("probe state=Ready".to_string())
        );
        assert_eq!(
            stderr_line_containing(b"one\nprobe state=Ready", "probe state="),
            None
        );
        assert_eq!(stderr_line_containing(b"one\npro", "probe state="), None);
    }

    #[cfg(unix)]
    #[test]
    fn fake_server_exercises_the_bounded_mcp_lifecycle() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("fake-mcp.sh");
        let transcript = directory.path().join("transcript.ndjson");
        let environment = directory.path().join("environment.txt");
        let initialize = directory.path().join("initialize.json");
        let tools = directory.path().join("tools.json");
        let call = directory.path().join("call.json");

        std::fs::write(
            &script,
            r#"set -eu
transcript=$1
environment=$2
initialize=$3
tools=$4
call=$5
: > "$transcript"
printf '%s|%s\n' "${AUTOCAD_MCP_ALLOWED_TEST_VALUE-unset}" "${RUST_LOG-unset}" > "$environment"
printf '%s\n' 'probe state=Ready elapsed_ms=7 complete' >&2
count=0
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$transcript"
  count=$((count + 1))
  case "$count" in
    1) cat "$initialize" ;;
    2) : ;;
    3) cat "$tools" ;;
    4) cat "$call" ;;
    *) exit 91 ;;
  esac
done
"#,
        )
        .unwrap();
        write_response(
            &initialize,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": autocad_mcp::server::SERVER_NAME,
                        "version": autocad_mcp::server::SERVER_VERSION
                    }
                }
            }),
        );
        write_response(
            &tools,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "tools": [{"name": "fake"}]
                }
            }),
        );
        write_response(
            &call,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 3,
                "result": {
                    "content": [{"type": "text", "text": "{\"ok\":true}"}],
                    "isError": false
                }
            }),
        );

        let mut session = McpStdioSession::spawn(shell_launch(
            directory.path(),
            &script,
            &[&transcript, &environment, &initialize, &tools, &call],
            None,
        ))
        .unwrap();
        session.initialize(Duration::from_secs(2)).unwrap();
        assert_eq!(
            session.list_tools(Duration::from_secs(2)).unwrap(),
            serde_json::json!([{"name": "fake"}])
        );
        let response = session
            .call_tool(
                "fake",
                serde_json::json!({"value": 1}),
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(response.value, serde_json::json!({"ok": true}));
        assert_eq!(response.response_sha256.len(), 64);
        assert_eq!(
            session
                .wait_for_stderr_line("probe state=Ready", Duration::from_secs(2))
                .unwrap()
                .as_deref(),
            Some("probe state=Ready elapsed_ms=7 complete")
        );
        let shutdown = session
            .close_stdin_and_wait(Duration::from_secs(2))
            .unwrap();
        assert!(shutdown.status.success());
        assert_eq!(shutdown.active_processes, None);

        let requests = std::fs::read_to_string(&transcript)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0]["method"], "initialize");
        assert_eq!(requests[1]["method"], "notifications/initialized");
        assert_eq!(requests[2]["method"], "tools/list");
        assert_eq!(requests[3]["method"], "tools/call");
        assert_eq!(requests[3]["params"]["name"], "fake");
        assert_eq!(
            std::fs::read_to_string(environment).unwrap().trim(),
            "exact|test=info"
        );
    }

    #[cfg(unix)]
    #[test]
    fn overall_deadline_terminates_an_unresponsive_process_tree() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("unresponsive-mcp.sh");
        let transcript = directory.path().join("transcript.ndjson");
        std::fs::write(
            &script,
            r#"set -eu
transcript=$1
IFS= read -r line
printf '%s\n' "$line" > "$transcript"
sleep 30
"#,
        )
        .unwrap();

        let started = Instant::now();
        let mut session = McpStdioSession::spawn(shell_launch(
            directory.path(),
            &script,
            &[&transcript],
            Some(started + Duration::from_millis(150)),
        ))
        .unwrap();
        let error = session
            .initialize(Duration::from_secs(10))
            .expect_err("overall deadline must cap the request timeout");
        assert!(error.to_string().contains("timed out"), "{error:#}");
        assert!(started.elapsed() < Duration::from_secs(3));
        let request: Value =
            serde_json::from_str(&std::fs::read_to_string(transcript).unwrap()).unwrap();
        assert_eq!(request["method"], "initialize");
    }
}
