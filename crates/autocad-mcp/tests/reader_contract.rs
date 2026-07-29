#![allow(clippy::zombie_processes)]

//! Backend-independent public reader contract.
//!
//! Successful interpretation in these tests uses only provenance-bound
//! committed drawings. Purpose-built malformed copies may prove fail-closed
//! safety and stable errors, but are not compatibility evidence. The
//! immutable-snapshot constructor is crate-private, so capture-once and
//! no-reopen semantics remain covered by reader module tests; this external
//! target binds the path behavior exposed to users.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

const DYNAMIC_BLOCK_DWG: &str =
    "tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dwg";
const DYNAMIC_BLOCK_DWG_SHA256: &str =
    "be1e24ea0cd5194d0c57935b5018123b7cc981331172a1a2ca7cecc2d9a18e4f";
const DYNAMIC_BLOCK_DXF: &str =
    "tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dxf";
const DYNAMIC_BLOCK_DXF_SHA256: &str =
    "c615664945db8ccc91b55f77e6359a15da4f7e6f30dbd8800d2d2b94029dffac";
const PROJECT_DXF: &str = "tests/corpus/open/project/generic-title-block-ascii.dxf";
const PROJECT_DXF_SHA256: &str = "36b87b71d61d8452cd257bb5028b8bb1d879cbda63c02c9951fb966ffa53a86f";
const PORTABLE_XREF_DXF: &str = "tests/fixtures/xrefs/portable-evidence-ascii.dxf";
const PORTABLE_XREF_DXF_SHA256: &str =
    "59a95656c20942822bf2d7f921a2c546713270c1ee41d19e3616798573d7635c";

// SHA-256 byte goldens include the CLI's one trailing LF. MCP text is checked
// against the same byte golden after adding that transport-external LF.
const GET_DRAWING_JSON_SHA256: &str =
    "26350b555fa77f95cf07dd5ea112e1aeb4c697fa00b9ee0c46f3335025a58f8a";
const LIST_BLOCKS_DWG_JSON_SHA256: &str =
    "cd26f00855f9d962c348134a452a583ad1b1ab305971b697c66cb80ea56b058d";
const LIST_BLOCK_DEFINITIONS_JSON_SHA256: &str =
    "ce94653726de05fc47c5497dc9e471e26e660d7e98df9e9700e73c5f5d7946f1";
const GET_BLOCK_DEFINITION_JSON_SHA256: &str =
    "c2c55f95457f69ea2f5b662c8aaeda0e18c3ca38f16652271e6cf83b745d8e45";
const LIST_BLOCK_INSERTS_JSON_SHA256: &str =
    "586c9394e8d48466bb8a5e7a2eab5bb7718b6c668911ae62f0e9900cdf47f9fe";
const GET_BLOCK_INSERT_JSON_SHA256: &str =
    "3fbe186d3fb436c2ff33c9818fffe8c07ad715770fd907c40fcc8da7560c9d0c";
const LIST_BLOCKS_PROJECT_DXF_JSON_SHA256: &str =
    "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570";
const LIST_BLOCKS_PORTABLE_DXF_JSON_SHA256: &str =
    "22f89f2cf846511f3c4b26b3f70fb955842bd47cc6e0465bb2e8d0e0e8b72250";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(relative_path: &str) -> PathBuf {
    repository_root().join(relative_path)
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_autocad-mcp"))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> String {
    sha256_bytes(&std::fs::read(path).unwrap())
}

fn full_surface_subcommand(subcommand: &str) -> Command {
    let mut command = Command::new(binary());
    command.current_dir(repository_root()).arg(subcommand);
    command
}

fn cli_call(tool: &str, params: &serde_json::Value) -> Output {
    full_surface_subcommand("call")
        .args([tool, &serde_json::to_string(params).unwrap()])
        .output()
        .unwrap()
}

fn cli_json(tool: &str, params: &serde_json::Value, expected_sha256: &str) -> serde_json::Value {
    let output = cli_call(tool, params);
    assert!(
        output.status.success(),
        "{tool} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{tool} wrote stderr on success: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout.last(),
        Some(&b'\n'),
        "{tool} must emit exactly one JSON line"
    );
    assert!(
        !output.stdout[..output.stdout.len() - 1].contains(&b'\n'),
        "{tool} emitted more than one stdout line"
    );
    assert_eq!(
        sha256_bytes(&output.stdout),
        expected_sha256,
        "{tool} public CLI JSON bytes changed"
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{tool} stdout was not JSON: {error}"))
}

fn cli_error(tool: &str, params: &serde_json::Value, expected: &str) {
    let output = cli_call(tool, params);
    assert!(
        !output.status.success(),
        "{tool} unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "{tool} must retain the public CLI tool-error exit code"
    );
    assert!(
        output.stdout.is_empty(),
        "{tool} wrote stdout on error: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!("{expected}\n"),
        "{tool} public CLI error changed"
    );
}

struct McpClient {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    next_id: u64,
}

impl McpClient {
    fn new() -> Self {
        let mut command = full_surface_subcommand("serve");
        command.args(["--engine-probe", "off"]);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let reader = BufReader::new(child.stdout.take().unwrap());
        let mut client = Self {
            child,
            stdin,
            reader,
            next_id: 1,
        };

        let response = client.request(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {
                    "name": "reader-contract-test",
                    "version": "0.1.0"
                }
            }),
        );
        assert!(
            response["result"]["capabilities"]["tools"].is_object(),
            "server must advertise tools capability: {response}"
        );
        writeln!(
            client.stdin,
            "{}",
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            })
        )
        .unwrap();
        client.stdin.flush().unwrap();
        client
    }

    fn request(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let id = self.next_id;
        self.next_id += 1;
        writeln!(
            self.stdin,
            "{}",
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params
            })
        )
        .unwrap();
        self.stdin.flush().unwrap();

        let mut line = String::new();
        assert_ne!(
            self.reader.read_line(&mut line).unwrap(),
            0,
            "MCP server closed before responding to {method}"
        );
        let response: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(response["id"], id, "unexpected MCP response: {response}");
        response
    }

    fn call_tool(
        &mut self,
        tool: &str,
        params: serde_json::Value,
        expected_sha256: &str,
    ) -> serde_json::Value {
        let response = self.request(
            "tools/call",
            serde_json::json!({"name": tool, "arguments": params}),
        );
        assert!(
            response.get("error").is_none(),
            "{tool} returned a JSON-RPC error: {response}"
        );
        assert_ne!(
            response["result"]["isError"], true,
            "{tool} returned an MCP tool error: {response}"
        );
        let text = mcp_tool_text(&response);
        assert!(!text.contains('\n'), "{tool} MCP JSON must be one line");
        let mut cli_equivalent = text.as_bytes().to_vec();
        cli_equivalent.push(b'\n');
        assert_eq!(
            sha256_bytes(&cli_equivalent),
            expected_sha256,
            "{tool} public MCP JSON bytes changed"
        );
        serde_json::from_str(text)
            .unwrap_or_else(|error| panic!("{tool} MCP text was not JSON: {error}"))
    }

    fn call_tool_error(&mut self, tool: &str, params: serde_json::Value, expected: &str) {
        let response = self.request(
            "tools/call",
            serde_json::json!({"name": tool, "arguments": params}),
        );
        assert!(
            response.get("error").is_none(),
            "{tool} returned a JSON-RPC error: {response}"
        );
        assert_eq!(
            response["result"]["isError"], true,
            "{tool} unexpectedly returned MCP success: {response}"
        );
        assert_eq!(
            mcp_tool_text(&response),
            expected,
            "{tool} public MCP error changed"
        );
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn mcp_tool_text(response: &serde_json::Value) -> &str {
    let content = response["result"]["content"]
        .as_array()
        .unwrap_or_else(|| panic!("MCP tool result content is not an array: {response}"));
    assert_eq!(
        content.len(),
        1,
        "MCP tool result must contain exactly one public text item: {response}"
    );
    assert_eq!(
        content[0]["type"], "text",
        "MCP tool result must contain one text item: {response}"
    );
    content[0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("MCP tool result text is not a string: {response}"))
}

fn assert_public_success(
    client: &mut McpClient,
    tool: &str,
    params: &serde_json::Value,
    expected_sha256: &str,
) -> serde_json::Value {
    let cli = cli_json(tool, params, expected_sha256);
    let mcp = client.call_tool(tool, params.clone(), expected_sha256);
    assert_eq!(mcp, cli, "{tool} CLI/MCP JSON values drifted");
    cli
}

fn assert_public_transport_equivalent_json(
    client: &mut McpClient,
    tool: &str,
    params: &serde_json::Value,
) -> serde_json::Value {
    let output = cli_call(tool, params);
    assert!(
        output.status.success(),
        "{tool} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{tool} wrote stderr on success: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout.last(),
        Some(&b'\n'),
        "{tool} must emit exactly one JSON line"
    );
    assert!(
        !output.stdout[..output.stdout.len() - 1].contains(&b'\n'),
        "{tool} emitted more than one stdout line"
    );

    let response = client.request(
        "tools/call",
        serde_json::json!({"name": tool, "arguments": params}),
    );
    assert!(
        response.get("error").is_none(),
        "{tool} returned a JSON-RPC error: {response}"
    );
    assert_ne!(
        response["result"]["isError"], true,
        "{tool} returned an MCP tool error: {response}"
    );
    let text = mcp_tool_text(&response);
    assert!(!text.contains('\n'), "{tool} MCP JSON must be one line");
    assert_eq!(
        format!("{text}\n").as_bytes(),
        output.stdout,
        "{tool} CLI and MCP JSON bytes drifted"
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{tool} stdout was not JSON: {error}"))
}

fn assert_public_exact_json(
    client: &mut McpClient,
    tool: &str,
    params: &serde_json::Value,
    expected: &str,
) -> serde_json::Value {
    let expected_sha256 = sha256_bytes(format!("{expected}\n").as_bytes());
    let actual = assert_public_success(client, tool, params, &expected_sha256);
    assert_eq!(
        actual,
        serde_json::from_str::<serde_json::Value>(expected).unwrap(),
        "{tool} public JSON value changed"
    );
    actual
}

fn assert_public_error(
    client: &mut McpClient,
    tool: &str,
    params: &serde_json::Value,
    expected: &str,
) {
    cli_error(tool, params, expected);
    client.call_tool_error(tool, params.clone(), expected);
}

fn expected_block_definition() -> serde_json::Value {
    serde_json::json!({
        "handle": "24F",
        "name": "block_visibility_parameter",
        "description": "This block has a visibility parameter in it",
        "has_attributes": false,
        "is_anonymous": false,
        "is_xref": false,
        "is_xref_overlay": false,
        "xref_dependent": false,
        "is_layout": false,
        "is_model_space": false,
        "is_paper_space": false,
        "layout_handle": null,
        "xref_path": null,
        "units": 4,
        "explodable": true,
        "scale_uniformly": false,
        "entity_handles": ["334", "335", "336", "337", "338"],
        "owned_entity_count": 5,
        "insert_handles": [],
        "insert_count": 0,
        "block_entity_handle": "250",
        "block_end_handle": "251"
    })
}

fn expected_block_insert() -> serde_json::Value {
    serde_json::json!({
        "handle": "252",
        "definition_handle": "343",
        "block_name": "*U7",
        "dynamic_block": {
            "state": "available",
            "definition_handle": "24F",
            "definition_name": "block_visibility_parameter",
            "visibility_parameter": {
                "state": "available",
                "handle": "33B",
                "name": "Test visibility",
                "selectable_state_count": 4,
                "current_state": {
                    "state": "unavailable",
                    "reason": "parser_not_retained"
                }
            }
        },
        "owner_handle": "1F",
        "owner_context": {
            "state": "available",
            "owner_type": "model_space",
            "owner_name": "Model"
        },
        "layer": "0",
        "insertion_point": {"x": 0.0, "y": 0.0, "z": 0.0},
        "x_scale": 0.03937007874015748,
        "y_scale": 0.03937007874015748,
        "z_scale": 0.03937007874015748,
        "rotation_radians": 0.0,
        "normal": {"x": 0.0, "y": 0.0, "z": 1.0},
        "column_count": 1,
        "row_count": 1,
        "column_spacing": 0.0,
        "row_spacing": 0.0,
        "is_array": false,
        "attributes": []
    })
}

fn assert_provenance_record(
    ledger: &serde_json::Value,
    relative_path: &str,
    expected_sha256: &str,
    expected_origin_kind: &str,
) {
    let record = ledger["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["path"] == relative_path)
        .unwrap_or_else(|| panic!("fixture provenance is missing {relative_path}"));
    assert_eq!(record["sha256"], expected_sha256);
    assert_eq!(record["artifact_class"], "drawing");
    assert_eq!(record["origin"]["kind"], expected_origin_kind);
    assert!(
        record["license_expression"]
            .as_str()
            .is_some_and(|license| !license.is_empty()),
        "{relative_path} must retain a license expression"
    );
    assert!(
        record["privacy_disposition"]
            .as_str()
            .is_some_and(|disposition| !disposition.is_empty()),
        "{relative_path} must retain a privacy disposition"
    );
}

#[test]
fn qualification_fixtures_remain_byte_exact_and_provenance_bound() {
    let ledger: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture("tests/fixture-provenance.json")).unwrap())
            .unwrap();
    assert_eq!(ledger["schema_version"], 1);

    for (relative_path, expected_sha256, origin_kind) in [
        (
            DYNAMIC_BLOCK_DWG,
            DYNAMIC_BLOCK_DWG_SHA256,
            "upstream_exact",
        ),
        (
            DYNAMIC_BLOCK_DXF,
            DYNAMIC_BLOCK_DXF_SHA256,
            "upstream_exact",
        ),
        (
            PROJECT_DXF,
            PROJECT_DXF_SHA256,
            "generated_by_checked_in_recipe",
        ),
        (
            PORTABLE_XREF_DXF,
            PORTABLE_XREF_DXF_SHA256,
            "hand_authored_from_local_contract",
        ),
    ] {
        let path = fixture(relative_path);
        assert!(path.is_file(), "missing committed fixture: {path:?}");
        assert_eq!(
            sha256_file(&path),
            expected_sha256,
            "{relative_path} bytes changed"
        );
        assert_provenance_record(&ledger, relative_path, expected_sha256, origin_kind);
    }

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture("tests/corpus/open/manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["schema_version"], 1);
    for (relative_path, expected_sha256, format) in [
        (DYNAMIC_BLOCK_DWG, DYNAMIC_BLOCK_DWG_SHA256, "DWG"),
        (DYNAMIC_BLOCK_DXF, DYNAMIC_BLOCK_DXF_SHA256, "DXF"),
        (PROJECT_DXF, PROJECT_DXF_SHA256, "DXF"),
    ] {
        assert!(
            manifest["fixtures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|record| {
                    record["path"] == relative_path
                        && record["sha256"] == expected_sha256
                        && record["format"] == format
                }),
            "Tier-1 manifest is missing exact fixture {relative_path}"
        );
    }
}

#[test]
fn drawing_route_matches_exact_cli_and_mcp_json_and_admission_contract() {
    let dwg = fixture(DYNAMIC_BLOCK_DWG).to_string_lossy().into_owned();
    let dxf = fixture(PROJECT_DXF).to_string_lossy().into_owned();
    let mut client = McpClient::new();

    let drawing = assert_public_success(
        &mut client,
        "get_drawing",
        &serde_json::json!({"drawing_path": dwg}),
        GET_DRAWING_JSON_SHA256,
    );
    assert_eq!(drawing["version"], "AC1032");
    assert_eq!(drawing["metadata"]["code_page"], "ANSI_1252");
    assert_eq!(drawing["spaces"]["model_space"]["handle"], "1F");
    assert_eq!(drawing["counts"]["entities"], 65);

    assert_public_error(
        &mut client,
        "get_drawing",
        &serde_json::json!({"drawing_path": dxf}),
        &format!(
            "code=unsupported_format expanded read tools require a DWG drawing_path; got `{dxf}`"
        ),
    );
    assert_public_error(
        &mut client,
        "get_drawing",
        &serde_json::json!({"drawing_path": DYNAMIC_BLOCK_DWG}),
        &format!(
            "code=invalid_drawing_path expanded read tools require an absolute drawing_path; got `{DYNAMIC_BLOCK_DWG}`"
        ),
    );
}

#[test]
fn five_block_routes_match_exact_cli_and_mcp_json() {
    let dwg = fixture(DYNAMIC_BLOCK_DWG).to_string_lossy().into_owned();
    let project_dxf = fixture(PROJECT_DXF).to_string_lossy().into_owned();
    let portable_dxf = fixture(PORTABLE_XREF_DXF).to_string_lossy().into_owned();
    let mut client = McpClient::new();

    let blocks = assert_public_success(
        &mut client,
        "list_blocks",
        &serde_json::json!({"drawing_path": dwg}),
        LIST_BLOCKS_DWG_JSON_SHA256,
    );
    assert_eq!(
        blocks,
        serde_json::json!([{
            "name": "block_visibility_parameter",
            "has_attributes": false,
            "description": "This block has a visibility parameter in it"
        }])
    );

    let definitions = assert_public_success(
        &mut client,
        "list_block_definitions",
        &serde_json::json!({"drawing_path": dwg}),
        LIST_BLOCK_DEFINITIONS_JSON_SHA256,
    );
    assert_eq!(
        definitions
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["handle"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "1F", "58", "5D", "24F", "2C4", "2CE", "2D8", "2E2", "305", "310", "31B", "326", "343",
            "34E", "359", "364"
        ]
    );
    let listed_definition = definitions
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["handle"] == "24F")
        .unwrap();
    assert_eq!(listed_definition, &expected_block_definition());

    let definition = assert_public_success(
        &mut client,
        "get_block_definition",
        &serde_json::json!({
            "drawing_path": dwg,
            "handle": "24F",
            "name": "block_visibility_parameter"
        }),
        GET_BLOCK_DEFINITION_JSON_SHA256,
    );
    assert_eq!(definition, expected_block_definition());
    assert_eq!(&definition, listed_definition);

    let definition_by_handle = assert_public_success(
        &mut client,
        "get_block_definition",
        &serde_json::json!({"drawing_path": dwg, "handle": "24F"}),
        GET_BLOCK_DEFINITION_JSON_SHA256,
    );
    assert_eq!(definition_by_handle, expected_block_definition());

    let definition_by_case_insensitive_name = assert_public_success(
        &mut client,
        "get_block_definition",
        &serde_json::json!({
            "drawing_path": dwg,
            "name": "BLOCK_VISIBILITY_PARAMETER"
        }),
        GET_BLOCK_DEFINITION_JSON_SHA256,
    );
    assert_eq!(
        definition_by_case_insensitive_name,
        expected_block_definition()
    );

    let inserts = assert_public_success(
        &mut client,
        "list_block_inserts",
        &serde_json::json!({"drawing_path": dwg}),
        LIST_BLOCK_INSERTS_JSON_SHA256,
    );
    assert_eq!(
        inserts
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["handle"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["252", "268", "284", "28C"]
    );
    let listed_insert = inserts
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["handle"] == "252")
        .unwrap();
    assert_eq!(listed_insert, &expected_block_insert());

    let insert = assert_public_success(
        &mut client,
        "get_block_insert",
        &serde_json::json!({"drawing_path": dwg, "handle": "252"}),
        GET_BLOCK_INSERT_JSON_SHA256,
    );
    assert_eq!(insert, expected_block_insert());
    assert_eq!(&insert, listed_insert);

    let project_blocks = assert_public_success(
        &mut client,
        "list_blocks",
        &serde_json::json!({"drawing_path": project_dxf}),
        LIST_BLOCKS_PROJECT_DXF_JSON_SHA256,
    );
    assert_eq!(project_blocks, serde_json::json!([]));

    let portable_blocks = assert_public_success(
        &mut client,
        "list_blocks",
        &serde_json::json!({"drawing_path": portable_dxf}),
        LIST_BLOCKS_PORTABLE_DXF_JSON_SHA256,
    );
    assert_eq!(
        portable_blocks,
        serde_json::json!([
            {
                "name": "DETAIL_SYMBOL",
                "has_attributes": false,
                "description": ""
            },
            {
                "name": "EMPTY_PATH",
                "has_attributes": false,
                "description": ""
            }
        ])
    );
}

#[test]
fn title_block_route_matches_exact_cli_mcp_and_structured_contracts() {
    const SPLIT_JSON: &str = concat!(
        r#"[{"block_name":"OTHER_TITLE_BLOCK","layer":"0","attributes":{"#,
        r#""DRAWING_NUMBER":"CONTROL-001","REVISION":"CONTROL"}},{"#,
        r#""block_name":"AUTOCAD_MCP_GENERIC","layer":"0","attributes":{"#,
        r#""DRAWING_NUMBER":"SYNTHETIC-001","REFERENCE":"REFERENCE-001","#,
        r#""REVISION":"P01","SHEET_COUNT":"1","SHEET_NUMBER":"1","#,
        r#""TITLE_LINE_1":"Synthetic Fixture","TITLE_LINE_2":"Example Sheet"}}]"#
    );
    const ARRAYS_JSON: &str = concat!(
        r#"[{"block_name":"OTHER_TITLE_BLOCK","layer":"0","attributes":{},"#,
        r#""attribute_arrays":{"DRAWING_NUMBER":["CONTROL-001"],"#,
        r#""REVISION":["CONTROL"]}},{"block_name":"AUTOCAD_MCP_GENERIC","#,
        r#""layer":"0","attributes":{},"attribute_arrays":{"#,
        r#""DRAWING_NUMBER":["SYNTHETIC-001"],"REFERENCE":["REFERENCE-001"],"#,
        r#""REVISION":["P01"],"SHEET_COUNT":["1"],"SHEET_NUMBER":["1"],"#,
        r#""TITLE_LINE_1":["Synthetic Fixture"],"TITLE_LINE_2":["Example Sheet"]}}]"#
    );

    let mut client = McpClient::new();
    let split_params = serde_json::json!({
        "drawing_path": PROJECT_DXF,
        "attribute_value_mode": "split"
    });
    let split =
        assert_public_exact_json(&mut client, "read_title_blocks", &split_params, SPLIT_JSON);
    let arrays_params = serde_json::json!({
        "drawing_path": PROJECT_DXF,
        "attribute_value_mode": "arrays"
    });
    assert_public_exact_json(
        &mut client,
        "read_title_blocks",
        &arrays_params,
        ARRAYS_JSON,
    );

    let response = client.request(
        "tools/call",
        serde_json::json!({
            "name": "read_title_blocks",
            "arguments": split_params
        }),
    );
    assert_eq!(
        response["result"]["structuredContent"],
        serde_json::json!({
            "status": "complete",
            "attribute_value_mode": "split",
            "title_blocks": split,
            "warnings": [],
        })
    );

    assert_public_error(
        &mut client,
        "read_title_blocks",
        &serde_json::json!({
            "drawing_path": fixture(DYNAMIC_BLOCK_DXF).to_string_lossy(),
            "attribute_value_mode": "split"
        }),
        concat!(
            "read_title_blocks failed: code=unsupported_title_block_data ",
            "reader reported an unsupported diagnostic that may affect title-block interpretation"
        ),
    );
}

#[test]
fn layout_routes_preserve_admission_and_diagnostic_contracts() {
    const PROJECT_LAYOUTS_JSON: &str = concat!(
        r#"[{"name":"Model","is_model":true,"tab_order":0,"#,
        r#""paper_width_mm":0.0,"paper_height_mm":0.0},{"name":"Layout1","#,
        r#""is_model":false,"tab_order":1,"paper_width_mm":0.0,"#,
        r#""paper_height_mm":0.0}]"#
    );

    let diagnostic_dxf = fixture(DYNAMIC_BLOCK_DXF).to_string_lossy().into_owned();
    let project_dxf = fixture(PROJECT_DXF).to_string_lossy().into_owned();
    let mut client = McpClient::new();

    assert_public_exact_json(
        &mut client,
        "list_layouts",
        &serde_json::json!({"drawing_path": PROJECT_DXF}),
        PROJECT_LAYOUTS_JSON,
    );
    assert_public_error(
        &mut client,
        "list_layouts",
        &serde_json::json!({"drawing_path": diagnostic_dxf}),
        concat!(
            "list_layouts failed: code=unsupported_layout_data ",
            "reader reported an unsupported diagnostic that may affect layout interpretation"
        ),
    );

    let dxf_error = format!(
        "code=unsupported_format expanded read tools require a DWG drawing_path; got `{project_dxf}`"
    );
    for (tool, params) in [
        (
            "get_layout",
            serde_json::json!({"drawing_path": project_dxf, "name": "Model"}),
        ),
        (
            "list_layout_viewports",
            serde_json::json!({"drawing_path": project_dxf}),
        ),
        (
            "get_layout_viewport",
            serde_json::json!({"drawing_path": project_dxf, "handle": "1"}),
        ),
        (
            "list_plot_settings",
            serde_json::json!({"drawing_path": project_dxf}),
        ),
        (
            "get_plot_setting",
            serde_json::json!({"drawing_path": project_dxf, "name": "A3"}),
        ),
    ] {
        assert_public_error(&mut client, tool, &params, &dxf_error);
    }

    let relative_path_error = format!(
        "code=invalid_drawing_path expanded read tools require an absolute drawing_path; got `{DYNAMIC_BLOCK_DWG}`"
    );
    for (tool, params) in [
        (
            "get_layout",
            serde_json::json!({"drawing_path": DYNAMIC_BLOCK_DWG, "name": "Model"}),
        ),
        (
            "list_layout_viewports",
            serde_json::json!({"drawing_path": DYNAMIC_BLOCK_DWG}),
        ),
        (
            "get_layout_viewport",
            serde_json::json!({"drawing_path": DYNAMIC_BLOCK_DWG, "handle": "1"}),
        ),
        (
            "list_plot_settings",
            serde_json::json!({"drawing_path": DYNAMIC_BLOCK_DWG}),
        ),
        (
            "get_plot_setting",
            serde_json::json!({"drawing_path": DYNAMIC_BLOCK_DWG, "name": "A3"}),
        ),
    ] {
        assert_public_error(&mut client, tool, &params, &relative_path_error);
    }
}

#[test]
fn entity_list_and_get_match_exact_cli_and_mcp_json() {
    const ENTITY_252_JSON: &str = concat!(
        r#"{"handle":"252","entity_type":"INSERT","owner_handle":"1F","#,
        r#""owner_context":{"state":"available","owner_type":"model_space","#,
        r#""owner_name":"Model"},"layer":"0","visible":true,"color":{"kind":"by_layer"},"#,
        r#""linetype":{"kind":"by_layer"},"linetype_scale":1.0,"#,
        r#""line_weight":{"kind":"by_layer"},"transparency":{"alpha":0,"fraction":0.0},"#,
        r#""bounds":{"state":"unavailable","reason":"unreliable_model_projection"},"#,
        r#""detail":{"kind":"insert","block_name":"*U7","#,
        r#""insertion_point":{"x":0.0,"y":0.0,"z":0.0},"#,
        r#""scale":{"x":0.03937007874015748,"y":0.03937007874015748,"#,
        r#""z":0.03937007874015748},"rotation_radians":0.0,"column_count":1,"#,
        r#""row_count":1,"attribute_count":0,"dynamic_block":{"state":"available","#,
        r#""definition_handle":"24F","definition_name":"block_visibility_parameter","#,
        r#""visibility_parameter":{"state":"available","handle":"33B","#,
        r#""name":"Test visibility","selectable_state_count":4,"#,
        r#""current_state":{"state":"unavailable","reason":"parser_not_retained"}}}}}"#
    );

    let dwg = fixture(DYNAMIC_BLOCK_DWG).to_string_lossy().into_owned();
    let list_params = serde_json::json!({
        "drawing_path": dwg,
        "entity_types": ["INSERT"],
        "include_invisible": true,
        "offset": 0,
        "limit": 1
    });
    let expected_list =
        format!(r#"{{"items":[{ENTITY_252_JSON}],"total":4,"offset":0,"limit":1}}"#);
    let mut client = McpClient::new();

    let listed =
        assert_public_exact_json(&mut client, "list_entities", &list_params, &expected_list);
    let selected = assert_public_exact_json(
        &mut client,
        "get_entity",
        &serde_json::json!({"drawing_path": dwg, "handle": "252"}),
        ENTITY_252_JSON,
    );

    assert_eq!(listed["items"][0], selected);
    assert_public_error(
        &mut client,
        "list_entities",
        &serde_json::json!({"drawing_path": dwg, "limit": 0}),
        "list_entities failed: code=invalid_entity_limit entity list limit must be at least 1",
    );
    assert_public_error(
        &mut client,
        "get_entity",
        &serde_json::json!({"drawing_path": dwg, "handle": "0"}),
        "get_entity failed: code=invalid_entity_handle entity handle 0 is invalid",
    );
}

#[test]
fn layer_routes_match_exact_cli_and_mcp_json_diagnostics_and_path_policy() {
    const LAYER_ZERO_JSON: &str = concat!(
        r#"{"handle":"10","name":"0","color_index":7,"line_type":"Continuous","#,
        r#""line_weight":{"kind":"default"},"frozen":false,"locked":false,"off":false,"#,
        r#""is_plottable":true,"xref_dependent":false,"xref_block_record_handle":null,"#,
        r#""xref_name":null,"xref_path":null,"xref_is_overlay":null,"material_handle":null,"#,
        r#""plotstyle_handle":null,"is_current":true}"#
    );

    let project_dxf = fixture(PROJECT_DXF).to_string_lossy().into_owned();
    let diagnostic_dxf = fixture(DYNAMIC_BLOCK_DXF).to_string_lossy().into_owned();
    let mut client = McpClient::new();

    assert_public_exact_json(
        &mut client,
        "list_layers",
        &serde_json::json!({"drawing_path": project_dxf}),
        &format!("[{LAYER_ZERO_JSON}]"),
    );
    assert_public_exact_json(
        &mut client,
        "get_layer",
        &serde_json::json!({"drawing_path": project_dxf, "name": "0"}),
        LAYER_ZERO_JSON,
    );
    assert_public_error(
        &mut client,
        "get_layer",
        &serde_json::json!({"drawing_path": project_dxf}),
        "code=layer_not_found missing layer handle or name",
    );

    for (tool, params) in [
        (
            "list_layers",
            serde_json::json!({"drawing_path": PROJECT_DXF}),
        ),
        (
            "get_layer",
            serde_json::json!({"drawing_path": PROJECT_DXF, "name": "0"}),
        ),
    ] {
        assert_public_error(
            &mut client,
            tool,
            &params,
            &format!(
                "code=drawing_unreadable {tool}: drawing_path must be absolute: {PROJECT_DXF}"
            ),
        );
    }

    let path_policy_directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        let canonical_target = path_policy_directory.path().join("canonical-target.dwg");
        std::fs::write(
            &canonical_target,
            std::fs::read(fixture(PROJECT_DXF)).unwrap(),
        )
        .unwrap();
        let admitted_link = path_policy_directory.path().join("admitted-link.dxf");
        std::os::unix::fs::symlink(&canonical_target, &admitted_link).unwrap();
        assert_public_exact_json(
            &mut client,
            "list_layers",
            &serde_json::json!({"drawing_path": admitted_link}),
            &format!("[{LAYER_ZERO_JSON}]"),
        );
    }

    let missing = path_policy_directory.path().join("missing.dxf");
    assert_public_error(
        &mut client,
        "list_layers",
        &serde_json::json!({"drawing_path": missing}),
        &format!(
            "code=drawing_not_found list_layers: drawing not found: {}",
            missing.display()
        ),
    );

    let unsupported = path_policy_directory.path().join("drawing.txt");
    std::fs::write(&unsupported, b"not a drawing").unwrap();
    assert_public_error(
        &mut client,
        "list_layers",
        &serde_json::json!({"drawing_path": unsupported}),
        "code=unsupported_format list_layers: unsupported extension `txt`; expected .dxf or .dwg",
    );

    let no_extension = path_policy_directory.path().join("drawing");
    std::fs::write(&no_extension, b"not a drawing").unwrap();
    assert_public_error(
        &mut client,
        "list_layers",
        &serde_json::json!({"drawing_path": no_extension}),
        "code=unsupported_format list_layers: file has no extension; expected .dxf or .dwg",
    );

    let diagnostic_error = concat!(
        "code=unsupported_layer_data ",
        "reader reported an unsupported diagnostic that may affect layer interpretation"
    );
    for (tool, params) in [
        (
            "list_layers",
            serde_json::json!({"drawing_path": diagnostic_dxf}),
        ),
        (
            "get_layer",
            serde_json::json!({"drawing_path": diagnostic_dxf, "name": "0"}),
        ),
    ] {
        assert_public_error(&mut client, tool, &params, diagnostic_error);
    }
}

#[test]
fn reader_open_errors_are_stable_and_decoder_safety_keeps_the_server_alive() {
    let directory = tempfile::tempdir().unwrap();
    let invalid_dwg = directory.path().join("mismatched.dwg");
    std::fs::write(&invalid_dwg, std::fs::read(fixture(PROJECT_DXF)).unwrap()).unwrap();
    let invalid_dxf = directory.path().join("mismatched.dxf");
    std::fs::write(
        &invalid_dxf,
        std::fs::read(fixture(DYNAMIC_BLOCK_DWG)).unwrap(),
    )
    .unwrap();
    let double_failure_dxf = directory.path().join("double-failure.dxf");
    std::fs::write(
        &double_failure_dxf,
        b"0\nSECTION\n2\nTABLES\n0\nTABLE\n2\nLAYER\n0\nLAYER\n62\nnot-an-integer\n",
    )
    .unwrap();

    let unsafe_dxf = directory.path().join("decoder-unsafe.dxf");
    let source = std::fs::read_to_string(fixture(PROJECT_DXF)).unwrap();
    let unsafe_source = source.replacen(" 62\r\n     7\r\n", " 62\r\n-32768\r\n", 1);
    assert_ne!(
        unsafe_source, source,
        "the provenance fixture must retain its LAYER color pair"
    );
    std::fs::write(&unsafe_dxf, unsafe_source).unwrap();

    let mut client = McpClient::new();
    assert_public_error(
        &mut client,
        "get_drawing",
        &serde_json::json!({"drawing_path": invalid_dwg}),
        "failed to open drawing: drawing could not be decoded",
    );
    assert_public_error(
        &mut client,
        "list_layers",
        &serde_json::json!({"drawing_path": invalid_dwg}),
        "code=drawing_unreadable failed to read DWG: drawing could not be decoded",
    );
    assert_public_error(
        &mut client,
        "list_layers",
        &serde_json::json!({"drawing_path": invalid_dxf}),
        "code=drawing_unreadable failed to read DXF: drawing could not be decoded",
    );
    assert_public_error(
        &mut client,
        "list_layers",
        &serde_json::json!({"drawing_path": double_failure_dxf}),
        "code=drawing_unreadable failed to read DXF: drawing could not be decoded",
    );

    let safety_error = "code=drawing_unreadable failed to read DXF: drawing could not be decoded";
    assert_public_error(
        &mut client,
        "list_layers",
        &serde_json::json!({"drawing_path": unsafe_dxf}),
        safety_error,
    );
    assert_public_error(
        &mut client,
        "get_layer",
        &serde_json::json!({"drawing_path": unsafe_dxf, "name": "0"}),
        safety_error,
    );
}

#[test]
fn text_routes_preserve_exact_json_diagnostics_and_path_policy() {
    let dwg = fixture(DYNAMIC_BLOCK_DWG).to_string_lossy().into_owned();
    let diagnostic_dxf = fixture(DYNAMIC_BLOCK_DXF).to_string_lossy().into_owned();
    let project_dxf = fixture(PROJECT_DXF).to_string_lossy().into_owned();
    let mut client = McpClient::new();

    for relative_path in [DYNAMIC_BLOCK_DWG, PROJECT_DXF] {
        assert_public_exact_json(
            &mut client,
            "dump_text",
            &serde_json::json!({"drawing_path": relative_path}),
            "[]",
        );
    }
    assert_public_exact_json(
        &mut client,
        "list_text",
        &serde_json::json!({"drawing_path": dwg}),
        "[]",
    );
    assert_public_error(
        &mut client,
        "get_text",
        &serde_json::json!({"drawing_path": dwg, "handle": "252"}),
        "get_text failed: code=text_not_found TEXT or MTEXT entity 252 was not found",
    );

    assert_public_error(
        &mut client,
        "dump_text",
        &serde_json::json!({"drawing_path": diagnostic_dxf}),
        concat!(
            "dump_text failed: code=unsupported_text_data ",
            "reader reported an unsupported diagnostic that may affect text interpretation"
        ),
    );

    let dxf_error = format!(
        "code=unsupported_format expanded read tools require a DWG drawing_path; got `{project_dxf}`"
    );
    for (tool, params) in [
        (
            "list_text",
            serde_json::json!({"drawing_path": project_dxf}),
        ),
        (
            "get_text",
            serde_json::json!({"drawing_path": project_dxf, "handle": "252"}),
        ),
    ] {
        assert_public_error(&mut client, tool, &params, &dxf_error);
    }

    let relative_path_error = format!(
        "code=invalid_drawing_path expanded read tools require an absolute drawing_path; got `{DYNAMIC_BLOCK_DWG}`"
    );
    for (tool, params) in [
        (
            "list_text",
            serde_json::json!({"drawing_path": DYNAMIC_BLOCK_DWG}),
        ),
        (
            "get_text",
            serde_json::json!({"drawing_path": DYNAMIC_BLOCK_DWG, "handle": "252"}),
        ),
    ] {
        assert_public_error(&mut client, tool, &params, &relative_path_error);
    }
}

#[test]
fn block_route_path_format_and_selector_errors_are_exact() {
    let dwg = fixture(DYNAMIC_BLOCK_DWG).to_string_lossy().into_owned();
    let diagnostic_dxf = fixture(DYNAMIC_BLOCK_DXF).to_string_lossy().into_owned();
    let project_dxf = fixture(PROJECT_DXF).to_string_lossy().into_owned();
    let mut client = McpClient::new();

    let relative_blocks = assert_public_success(
        &mut client,
        "list_blocks",
        &serde_json::json!({"drawing_path": PORTABLE_XREF_DXF}),
        LIST_BLOCKS_PORTABLE_DXF_JSON_SHA256,
    );
    assert_eq!(
        relative_blocks
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["DETAIL_SYMBOL", "EMPTY_PATH"]
    );

    let diagnostic_error = concat!(
        "list_blocks failed: code=unsupported_block_data ",
        "reader reported an unsupported diagnostic that may affect block interpretation"
    );
    assert_public_error(
        &mut client,
        "list_blocks",
        &serde_json::json!({"drawing_path": diagnostic_dxf}),
        diagnostic_error,
    );

    let rich_dxf_error = format!(
        "code=unsupported_format expanded read tools require a DWG drawing_path; got `{project_dxf}`"
    );
    for (tool, params) in [
        (
            "list_block_definitions",
            serde_json::json!({"drawing_path": project_dxf}),
        ),
        (
            "get_block_definition",
            serde_json::json!({"drawing_path": project_dxf, "handle": "24F"}),
        ),
        (
            "list_block_inserts",
            serde_json::json!({"drawing_path": project_dxf}),
        ),
        (
            "get_block_insert",
            serde_json::json!({"drawing_path": project_dxf, "handle": "252"}),
        ),
    ] {
        assert_public_error(&mut client, tool, &params, &rich_dxf_error);
    }

    let relative_dwg = DYNAMIC_BLOCK_DWG;
    let relative_path_error = format!(
        "code=invalid_drawing_path expanded read tools require an absolute drawing_path; got `{relative_dwg}`"
    );
    for (tool, params) in [
        (
            "list_block_definitions",
            serde_json::json!({"drawing_path": relative_dwg}),
        ),
        (
            "get_block_definition",
            serde_json::json!({"drawing_path": relative_dwg, "handle": "24F"}),
        ),
        (
            "list_block_inserts",
            serde_json::json!({"drawing_path": relative_dwg}),
        ),
        (
            "get_block_insert",
            serde_json::json!({"drawing_path": relative_dwg, "handle": "252"}),
        ),
    ] {
        assert_public_error(&mut client, tool, &params, &relative_path_error);
    }

    for (tool, params, expected) in [
        (
            "get_block_definition",
            serde_json::json!({"drawing_path": dwg}),
            "get_block_definition failed: code=invalid_parameters block definition selector requires handle or name",
        ),
        (
            "get_block_definition",
            serde_json::json!({"drawing_path": dwg, "handle": "0"}),
            "get_block_definition failed: code=invalid_handle block handle 0 is invalid",
        ),
        (
            "get_block_definition",
            serde_json::json!({
                "drawing_path": dwg,
                "handle": "24F",
                "name": "DOES_NOT_EXIST"
            }),
            "get_block_definition failed: code=block_definition_identity_mismatch block definition handle and name did not resolve to the same definition",
        ),
        (
            "get_block_insert",
            serde_json::json!({"drawing_path": dwg, "handle": "0"}),
            "get_block_insert failed: code=invalid_handle block handle 0 is invalid",
        ),
        (
            "get_block_insert",
            serde_json::json!({
                "drawing_path": dwg,
                "handle": "FFFFFFFFFFFFFFFF"
            }),
            "get_block_insert failed: code=block_insert_not_found ordinary block insert FFFFFFFFFFFFFFFF was not found",
        ),
    ] {
        assert_public_error(&mut client, tool, &params, expected);
    }
}

#[test]
fn symbol_routes_preserve_list_get_transport_path_and_error_contracts() {
    let dwg = fixture(DYNAMIC_BLOCK_DWG).to_string_lossy().into_owned();
    let dxf = fixture(PROJECT_DXF).to_string_lossy().into_owned();
    let mut client = McpClient::new();

    for (list_tool, get_tool, expected_fields) in [
        (
            "list_linetypes",
            "get_linetype",
            &[
                "alignment",
                "description",
                "elements",
                "handle",
                "is_continuous",
                "is_current",
                "is_standard",
                "name",
                "pattern_length",
                "xref_dependent",
            ][..],
        ),
        (
            "list_text_styles",
            "get_text_style",
            &[
                "annotative",
                "backward",
                "big_font_file",
                "fixed_height",
                "font_file",
                "handle",
                "is_current",
                "is_standard",
                "last_height",
                "name",
                "oblique_angle_radians",
                "true_type_font",
                "upside_down",
                "width_factor",
                "xref_dependent",
            ][..],
        ),
        (
            "list_dimension_styles",
            "get_dimension_style",
            &[
                "alternate_units_enabled",
                "angular_decimal_places",
                "angular_unit_format",
                "annotative",
                "arrow_block_handle",
                "arrow_size",
                "center_mark_size",
                "decimal_separator",
                "decimal_separator_code",
                "dimension_line_extension",
                "dimension_line_gap",
                "dimension_line_increment",
                "dimension_linetype_handle",
                "extension_line_extension",
                "extension_line_offset",
                "first_arrow_block_handle",
                "first_extension_linetype_handle",
                "handle",
                "is_current",
                "is_standard",
                "leader_arrow_block_handle",
                "limits_enabled",
                "linear_decimal_places",
                "linear_rounding",
                "linear_scale_factor",
                "linear_unit_format",
                "name",
                "overall_scale",
                "postfix",
                "second_arrow_block_handle",
                "second_extension_linetype_handle",
                "suppress_first_dimension_line",
                "suppress_first_extension_line",
                "suppress_second_dimension_line",
                "suppress_second_extension_line",
                "text_height",
                "text_horizontal_alignment",
                "text_style_handle",
                "text_style_name",
                "text_vertical_alignment",
                "tick_size",
                "tolerances_enabled",
            ][..],
        ),
    ] {
        let listed = assert_public_transport_equivalent_json(
            &mut client,
            list_tool,
            &serde_json::json!({"drawing_path": dwg}),
        );
        let records = listed
            .as_array()
            .unwrap_or_else(|| panic!("{list_tool} must return a bare array"));
        assert!(
            !records.is_empty(),
            "{list_tool} qualification fixture must contain a symbol"
        );
        let handles = records
            .iter()
            .map(|record| {
                u64::from_str_radix(record["handle"].as_str().unwrap(), 16)
                    .expect("symbol handle must be canonical hexadecimal")
            })
            .collect::<Vec<_>>();
        assert!(
            handles.windows(2).all(|pair| pair[0] < pair[1]),
            "{list_tool} must retain strict numeric-handle order"
        );

        let selected = &records[0];
        assert_eq!(
            selected
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            expected_fields.iter().copied().collect::<BTreeSet<_>>(),
            "{list_tool} record schema changed"
        );
        let got = assert_public_transport_equivalent_json(
            &mut client,
            get_tool,
            &serde_json::json!({
                "drawing_path": dwg,
                "handle": selected["handle"],
                "name": selected["name"],
            }),
        );
        assert_eq!(got, *selected, "{get_tool} must match its listed record");
    }

    for list_tool in ["list_named_views", "list_named_ucs"] {
        let listed = assert_public_transport_equivalent_json(
            &mut client,
            list_tool,
            &serde_json::json!({"drawing_path": dwg}),
        );
        let records = listed
            .as_array()
            .unwrap_or_else(|| panic!("{list_tool} must return a bare array"));
        let handles = records
            .iter()
            .map(|record| {
                u64::from_str_radix(record["handle"].as_str().unwrap(), 16)
                    .expect("symbol handle must be canonical hexadecimal")
            })
            .collect::<Vec<_>>();
        assert!(
            handles.windows(2).all(|pair| pair[0] < pair[1]),
            "{list_tool} must retain strict numeric-handle order"
        );
    }

    for (tool, expected) in [
        (
            "get_linetype",
            "get_linetype failed: code=linetype_missing_identity provide a linetype handle or name",
        ),
        (
            "get_text_style",
            "get_text_style failed: code=text_style_missing_identity provide a text style handle or name",
        ),
        (
            "get_dimension_style",
            "get_dimension_style failed: code=dimension_style_missing_identity provide a dimension style handle or name",
        ),
        (
            "get_named_view",
            "get_named_view failed: code=named_view_missing_identity provide a named view handle or name",
        ),
        (
            "get_named_ucs",
            "get_named_ucs failed: code=named_ucs_missing_identity provide a named UCS handle or name",
        ),
    ] {
        assert_public_error(
            &mut client,
            tool,
            &serde_json::json!({"drawing_path": dwg}),
            expected,
        );
    }

    let dxf_error = format!(
        "code=unsupported_format expanded read tools require a DWG drawing_path; got `{dxf}`"
    );
    let relative_error = format!(
        "code=invalid_drawing_path expanded read tools require an absolute drawing_path; got `{DYNAMIC_BLOCK_DWG}`"
    );
    for (tool, mut params) in [
        ("list_linetypes", serde_json::json!({})),
        ("get_linetype", serde_json::json!({"name": "Continuous"})),
        ("list_text_styles", serde_json::json!({})),
        ("get_text_style", serde_json::json!({"name": "Standard"})),
        ("list_dimension_styles", serde_json::json!({})),
        (
            "get_dimension_style",
            serde_json::json!({"name": "Standard"}),
        ),
        ("list_named_views", serde_json::json!({})),
        ("get_named_view", serde_json::json!({"name": "Detail"})),
        ("list_named_ucs", serde_json::json!({})),
        ("get_named_ucs", serde_json::json!({"name": "Site"})),
    ] {
        params["drawing_path"] = serde_json::json!(dxf);
        assert_public_error(&mut client, tool, &params, &dxf_error);
        params["drawing_path"] = serde_json::json!(DYNAMIC_BLOCK_DWG);
        assert_public_error(&mut client, tool, &params, &relative_error);
    }
}
