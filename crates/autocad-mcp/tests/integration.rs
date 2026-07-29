#![allow(clippy::write_literal, clippy::zombie_processes)]

use acadrust::entities::{AttributeEntity, EntityType, Insert, MText, Text, Viewport};
use acadrust::objects::{ObjectType, PaperMargin, PlotSettings};
use acadrust::tables::{TableEntry, Ucs, View};
use acadrust::types::Vector3;
use acadrust::{CadDocument, DwgWriter, DxfWriter};
use autocad_mcp::ops::xrefs::{
    AttachXrefRequest, BindXrefRequest, DeleteXrefInstanceRequest, DetachXrefRequest,
    GetXrefInstanceRequest, GetXrefRequest, InsertXrefInstanceRequest, ListXrefDependenciesRequest,
    ListXrefInstancesRequest, ListXrefsRequest, ReloadXrefRequest, ResolveXrefPathRequest,
    UnloadXrefRequest, UpdateXrefInstanceRequest, UpdateXrefRequest,
};
use autocad_mcp::server::AutocadServer;
use schemars::JsonSchema;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Output, Stdio};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_autocad-mcp"))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> String {
    sha256_bytes(&std::fs::read(path).unwrap())
}

fn assert_process_success(label: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn full_surface_subcommand(subcommand: &str) -> std::process::Command {
    let mut command = std::process::Command::new(bin());
    command.arg(subcommand);
    #[cfg(feature = "preview")]
    command.arg("--experimental");
    command
}

fn tier1_dwg() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dwg")
}

/// Supplies positive records for the resource families absent from the
/// committed Tier 1 DWG. This proves the real DWG reader and CLI path after a
/// binary round trip; it is not external-producer compatibility evidence.
fn temp_rich_expanded_read_dwg() -> tempfile::NamedTempFile {
    let mut document = CadDocument::new();

    document
        .add_entity(EntityType::Text(Text::with_value(
            "CLI TEXT",
            Vector3::new(10.0, 20.0, 0.0),
        )))
        .unwrap();
    document
        .add_entity(EntityType::MText(MText::with_value(
            "CLI MTEXT",
            Vector3::new(30.0, 40.0, 0.0),
        )))
        .unwrap();

    let mut viewport = Viewport::with_size(Vector3::new(5.0, 7.0, 0.0), 200.0, 100.0);
    viewport.id = 2;
    viewport.view_height = 400.0;
    document
        .add_entity_to_layout(EntityType::Viewport(viewport), "Layout1")
        .unwrap();

    let plot_settings_handle = document.allocate_handle();
    let plot_settings_dictionary = document.header.acad_plotsettings_dict_handle;
    let mut plot_settings = PlotSettings::new("CLI A3");
    plot_settings.handle = plot_settings_handle;
    plot_settings.owner = plot_settings_dictionary;
    plot_settings.printer_name = "DWG To PDF.pc3".to_string();
    plot_settings.paper_size = "ISO_A3".to_string();
    plot_settings.paper_width = 420.0;
    plot_settings.paper_height = 297.0;
    plot_settings.margins = PaperMargin::new(5.0, 5.0, 5.0, 5.0);
    plot_settings.set_custom_scale(1.0, 50.0);
    let Some(ObjectType::Dictionary(dictionary)) =
        document.objects.get_mut(&plot_settings_dictionary)
    else {
        panic!("default document must contain ACAD_PLOTSETTINGS");
    };
    dictionary.add_entry("CLI A3", plot_settings_handle);
    document.objects.insert(
        plot_settings_handle,
        ObjectType::PlotSettings(plot_settings),
    );

    let mut view = View::new("CLI_DETAIL");
    view.set_handle(document.allocate_handle());
    view.center = Vector3::new(2.0, 3.0, 0.0);
    view.target = Vector3::new(10.0, 20.0, 30.0);
    view.width = 12.0;
    view.height = 8.0;
    document.views.add(view).unwrap();

    let mut ucs = Ucs::from_origin_axes(
        "CLI_SITE",
        Vector3::new(100.0, 200.0, 0.0),
        Vector3::UNIT_Y,
        Vector3::new(-1.0, 0.0, 0.0),
    );
    ucs.set_handle(document.allocate_handle());
    document.ucss.add(ucs).unwrap();

    let file = tempfile::Builder::new().suffix(".dwg").tempfile().unwrap();
    DwgWriter::write_to_file(file.path(), &document).unwrap();
    file
}

fn temp_empty_dxf() -> tempfile::NamedTempFile {
    let doc = CadDocument::new();
    let f = tempfile::Builder::new().suffix(".dxf").tempfile().unwrap();
    DxfWriter::new(&doc).write_to_file(f.path()).unwrap();
    f
}

fn temp_empty_ac1032_dxf() -> tempfile::NamedTempFile {
    let doc = CadDocument::with_version(acadrust::types::DxfVersion::AC1032);
    let f = tempfile::Builder::new().suffix(".dxf").tempfile().unwrap();
    DxfWriter::new(&doc).write_to_file(f.path()).unwrap();
    f
}

const EXPECTED_TOOL_COUNT: usize = 51;

const EXPECTED_TOOLS: &[&str] = &[
    "list_layers",
    "get_layer",
    "create_layer",
    "update_layer",
    "rename_layer",
    "delete_layer",
    "list_xrefs",
    "get_xref",
    "attach_xref",
    "update_xref",
    "detach_xref",
    "list_xref_instances",
    "get_xref_instance",
    "insert_xref_instance",
    "update_xref_instance",
    "delete_xref_instance",
    "reload_xref",
    "unload_xref",
    "bind_xref",
    "resolve_xref_path",
    "list_xref_dependencies",
    "list_blocks",
    "get_drawing",
    "list_entities",
    "get_entity",
    "list_block_definitions",
    "get_block_definition",
    "list_block_inserts",
    "get_block_insert",
    "read_title_blocks",
    "dump_text",
    "list_text",
    "get_text",
    "write_title_block",
    "list_layouts",
    "get_layout",
    "list_layout_viewports",
    "get_layout_viewport",
    "list_plot_settings",
    "get_plot_setting",
    "list_linetypes",
    "get_linetype",
    "list_text_styles",
    "get_text_style",
    "list_dimension_styles",
    "get_dimension_style",
    "list_named_views",
    "get_named_view",
    "list_named_ucs",
    "get_named_ucs",
    "plot_to_pdf",
];

const EXPANDED_READ_TOOLS: &[&str] = &[
    "get_drawing",
    "list_entities",
    "get_entity",
    "list_block_definitions",
    "get_block_definition",
    "list_block_inserts",
    "get_block_insert",
    "list_text",
    "get_text",
    "get_layout",
    "list_layout_viewports",
    "get_layout_viewport",
    "list_plot_settings",
    "get_plot_setting",
    "list_linetypes",
    "get_linetype",
    "list_text_styles",
    "get_text_style",
    "list_dimension_styles",
    "get_dimension_style",
    "list_named_views",
    "get_named_view",
    "list_named_ucs",
    "get_named_ucs",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExpectedToolAnnotations {
    read_only: bool,
    destructive: bool,
    idempotent: bool,
    open_world: bool,
}

const fn annotations(
    read_only: bool,
    destructive: bool,
    idempotent: bool,
) -> ExpectedToolAnnotations {
    ExpectedToolAnnotations {
        read_only,
        destructive,
        idempotent,
        open_world: true,
    }
}

const EXPECTED_TOOL_ANNOTATIONS: &[(&str, ExpectedToolAnnotations)] = &[
    ("list_layers", annotations(true, false, true)),
    ("get_layer", annotations(true, false, true)),
    ("create_layer", annotations(false, false, true)),
    ("update_layer", annotations(false, true, true)),
    ("rename_layer", annotations(false, true, true)),
    ("delete_layer", annotations(false, true, true)),
    ("list_xrefs", annotations(true, false, true)),
    ("get_xref", annotations(true, false, true)),
    ("attach_xref", annotations(false, false, true)),
    ("update_xref", annotations(false, true, false)),
    ("detach_xref", annotations(false, true, true)),
    ("list_xref_instances", annotations(true, false, true)),
    ("get_xref_instance", annotations(true, false, true)),
    ("insert_xref_instance", annotations(false, false, false)),
    ("update_xref_instance", annotations(false, true, true)),
    ("delete_xref_instance", annotations(false, true, true)),
    ("reload_xref", annotations(false, true, false)),
    ("unload_xref", annotations(false, true, true)),
    ("bind_xref", annotations(false, true, true)),
    ("resolve_xref_path", annotations(true, false, true)),
    ("list_xref_dependencies", annotations(true, false, true)),
    ("list_blocks", annotations(true, false, true)),
    ("get_drawing", annotations(true, false, true)),
    ("list_entities", annotations(true, false, true)),
    ("get_entity", annotations(true, false, true)),
    ("list_block_definitions", annotations(true, false, true)),
    ("get_block_definition", annotations(true, false, true)),
    ("list_block_inserts", annotations(true, false, true)),
    ("get_block_insert", annotations(true, false, true)),
    ("read_title_blocks", annotations(true, false, true)),
    ("dump_text", annotations(true, false, true)),
    ("list_text", annotations(true, false, true)),
    ("get_text", annotations(true, false, true)),
    ("write_title_block", annotations(false, true, true)),
    ("list_layouts", annotations(true, false, true)),
    ("get_layout", annotations(true, false, true)),
    ("list_layout_viewports", annotations(true, false, true)),
    ("get_layout_viewport", annotations(true, false, true)),
    ("list_plot_settings", annotations(true, false, true)),
    ("get_plot_setting", annotations(true, false, true)),
    ("list_linetypes", annotations(true, false, true)),
    ("get_linetype", annotations(true, false, true)),
    ("list_text_styles", annotations(true, false, true)),
    ("get_text_style", annotations(true, false, true)),
    ("list_dimension_styles", annotations(true, false, true)),
    ("get_dimension_style", annotations(true, false, true)),
    ("list_named_views", annotations(true, false, true)),
    ("get_named_view", annotations(true, false, true)),
    ("list_named_ucs", annotations(true, false, true)),
    ("get_named_ucs", annotations(true, false, true)),
    ("plot_to_pdf", annotations(false, true, false)),
];

const FORBIDDEN_XREF_TOOLS: &[&str] = &[
    "list_xref_clips",
    "get_xref_clip",
    "create_xref_clip",
    "update_xref_clip",
    "delete_xref_clip",
    "open_xref",
    "rename_xref",
];

fn xref_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("autocad-mcp should live under <repo>/crates")
        .join("tests/fixtures/xrefs/portable-evidence-ascii.dxf")
}

fn xref_fixture_variant(rewrite: impl FnOnce(String) -> String) -> tempfile::NamedTempFile {
    let text = std::fs::read_to_string(xref_fixture()).unwrap();
    let file = tempfile::Builder::new().suffix(".dxf").tempfile().unwrap();
    std::fs::write(file.path(), rewrite(text)).unwrap();
    file
}

fn expected_xref_records() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "handle": "F",
            "name": "SITE_MODEL",
            "saved_path": "refs/site.dwg",
            "path_mode": "relative",
            "reference_type": "attachment",
            "load_state": "unavailable",
            "instance_count": 2,
            "definition_base_point": {
                "state": "available",
                "point": {"x": 1.0, "y": 2.0, "z": 3.0}
            }
        }),
        serde_json::json!({
            "handle": "10",
            "name": "GRID_OVERLAY",
            "saved_path": "refs/grid.dwg",
            "path_mode": "relative",
            "reference_type": "overlay",
            "load_state": "unavailable",
            "instance_count": 1,
            "definition_base_point": {
                "state": "available",
                "point": {"x": 0.0, "y": 0.0, "z": 0.0}
            }
        }),
        serde_json::json!({
            "handle": "11",
            "name": "EMPTY_PATH",
            "saved_path": "",
            "path_mode": "unsupported",
            "reference_type": "attachment",
            "load_state": "unavailable",
            "instance_count": 1,
            "definition_base_point": {
                "state": "available",
                "point": {"x": -1.0, "y": -2.0, "z": -3.0}
            }
        }),
    ]
}

fn request_schema<T: JsonSchema>() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(T)).expect("request schema should serialize")
}

fn expected_xref_schemas() -> BTreeMap<&'static str, serde_json::Value> {
    [
        ("list_xrefs", request_schema::<ListXrefsRequest>()),
        ("get_xref", request_schema::<GetXrefRequest>()),
        ("attach_xref", request_schema::<AttachXrefRequest>()),
        ("update_xref", request_schema::<UpdateXrefRequest>()),
        ("detach_xref", request_schema::<DetachXrefRequest>()),
        (
            "list_xref_instances",
            request_schema::<ListXrefInstancesRequest>(),
        ),
        (
            "get_xref_instance",
            request_schema::<GetXrefInstanceRequest>(),
        ),
        (
            "insert_xref_instance",
            request_schema::<InsertXrefInstanceRequest>(),
        ),
        (
            "update_xref_instance",
            request_schema::<UpdateXrefInstanceRequest>(),
        ),
        (
            "delete_xref_instance",
            request_schema::<DeleteXrefInstanceRequest>(),
        ),
        ("reload_xref", request_schema::<ReloadXrefRequest>()),
        ("unload_xref", request_schema::<UnloadXrefRequest>()),
        ("bind_xref", request_schema::<BindXrefRequest>()),
        (
            "resolve_xref_path",
            request_schema::<ResolveXrefPathRequest>(),
        ),
        (
            "list_xref_dependencies",
            request_schema::<ListXrefDependenciesRequest>(),
        ),
    ]
    .into_iter()
    .collect()
}

fn object_keys(value: &serde_json::Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("expected JSON object, got {value}"))
        .keys()
        .map(String::as_str)
        .collect()
}

fn expected_tool_annotations() -> BTreeMap<&'static str, ExpectedToolAnnotations> {
    EXPECTED_TOOL_ANNOTATIONS.iter().copied().collect()
}

fn assert_serialized_tool_annotations(tool: &serde_json::Value) {
    let name = tool["name"]
        .as_str()
        .unwrap_or_else(|| panic!("tool has no string name: {tool}"));
    let expected = expected_tool_annotations();
    let expected = expected
        .get(name)
        .unwrap_or_else(|| panic!("unexpected annotated tool {name}"));
    let actual = &tool["annotations"];
    assert_eq!(
        object_keys(actual),
        BTreeSet::from([
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
            "readOnlyHint",
        ]),
        "{name} must serialize all four hints with exact camelCase keys"
    );
    assert_eq!(actual["readOnlyHint"].as_bool(), Some(expected.read_only));
    assert_eq!(
        actual["destructiveHint"].as_bool(),
        Some(expected.destructive),
        "{name} destructiveHint"
    );
    assert_eq!(
        actual["idempotentHint"].as_bool(),
        Some(expected.idempotent),
        "{name} idempotentHint"
    );
    assert_eq!(
        actual["openWorldHint"].as_bool(),
        Some(expected.open_world),
        "{name} openWorldHint"
    );
}

#[test]
fn router_annotations_match_the_exact_fifty_one_tool_contract() {
    let expected = expected_tool_annotations();
    assert_eq!(expected.len(), EXPECTED_TOOL_COUNT);
    assert_eq!(
        expected.keys().copied().collect::<BTreeSet<_>>(),
        EXPECTED_TOOLS.iter().copied().collect::<BTreeSet<_>>(),
        "tool-name and annotation fixtures drifted"
    );
    assert_eq!(
        expected.values().filter(|value| value.read_only).count(),
        36,
        "read-only tool count drifted"
    );
    assert_eq!(
        expected.values().filter(|value| value.destructive).count(),
        12,
        "destructive tool count drifted"
    );
    assert_eq!(
        expected.values().filter(|value| !value.idempotent).count(),
        4,
        "non-idempotent tool count drifted"
    );
    assert!(expected.values().all(|value| value.open_world));

    let tools = AutocadServer::tool_router().list_all();
    assert_eq!(tools.len(), EXPECTED_TOOL_COUNT);
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<BTreeSet<_>>(),
        expected.keys().copied().collect::<BTreeSet<_>>()
    );

    for tool in tools {
        let name: &str = tool.name.as_ref();
        let expected = expected
            .get(name)
            .unwrap_or_else(|| panic!("unexpected router tool {name}"));
        let actual = tool
            .annotations
            .as_ref()
            .unwrap_or_else(|| panic!("{name} has no annotations"));
        assert_eq!(actual.read_only_hint, Some(expected.read_only), "{name}");
        assert_eq!(
            actual.destructive_hint,
            Some(expected.destructive),
            "{name}"
        );
        assert_eq!(actual.idempotent_hint, Some(expected.idempotent), "{name}");
        assert_eq!(actual.open_world_hint, Some(expected.open_world), "{name}");
    }
}

fn schema_explicitly_allows_null(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(values) => values.iter().any(schema_explicitly_allows_null),
        serde_json::Value::Object(object) => {
            object.get("type").is_some_and(|value| {
                value.as_str() == Some("null")
                    || value.as_array().is_some_and(|types| {
                        types.iter().any(|entry| entry.as_str() == Some("null"))
                    })
            }) || object.get("const") == Some(&serde_json::Value::Null)
                || object
                    .get("enum")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|values| values.iter().any(serde_json::Value::is_null))
                || object.values().any(schema_explicitly_allows_null)
        }
        _ => false,
    }
}

fn cli_call(tool: &str, params: &serde_json::Value) -> Output {
    let params = serde_json::to_string(params).unwrap();
    full_surface_subcommand("call")
        .args([tool, &params])
        .output()
        .unwrap()
}

fn cli_success_json(tool: &str, params: &serde_json::Value) -> serde_json::Value {
    let output = cli_call(tool, params);
    assert!(
        output.status.success(),
        "{tool} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("successful CLI output must be bare JSON")
}

fn cli_mcp_parity(
    client: &mut McpClient,
    tool: &str,
    params: &serde_json::Value,
) -> serde_json::Value {
    let cli = cli_success_json(tool, params);
    let response = client.call_tool(tool, params.clone());
    assert!(
        response.get("error").is_none(),
        "{tool} returned a JSON-RPC error through MCP: {response}"
    );
    assert_ne!(
        response["result"]["isError"], true,
        "{tool} returned a tool error through MCP: {response}"
    );
    let mcp: serde_json::Value = serde_json::from_str(mcp_tool_text(&response))
        .unwrap_or_else(|error| panic!("{tool} MCP text was not JSON: {error}"));
    assert_eq!(mcp, cli, "{tool} CLI/MCP JSON drifted");
    cli
}

fn cli_drawing_args(drawing_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "drawing_path": drawing_path.to_string_lossy().into_owned()
    })
}

fn expanded_cli_success_json(
    covered: &mut BTreeSet<&'static str>,
    tool: &'static str,
    params: &serde_json::Value,
) -> serde_json::Value {
    assert!(
        EXPANDED_READ_TOOLS.contains(&tool),
        "{tool} is not one of the 24 expanded reads"
    );
    assert!(covered.insert(tool), "{tool} was covered more than once");
    cli_success_json(tool, params)
}

#[derive(Debug, Clone, Copy)]
enum CliListShape {
    BareArray,
    EntityEnvelope,
}

fn assert_cli_list_get_round_trip(
    covered: &mut BTreeSet<&'static str>,
    drawing_path: &Path,
    list_tool: &'static str,
    get_tool: &'static str,
    list_shape: CliListShape,
    selector_fields: &[&str],
    select: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let listed = expanded_cli_success_json(covered, list_tool, &cli_drawing_args(drawing_path));
    let records = match list_shape {
        CliListShape::BareArray => listed
            .as_array()
            .unwrap_or_else(|| panic!("{list_tool} must return a bare JSON array: {listed}")),
        CliListShape::EntityEnvelope => {
            assert_eq!(
                object_keys(&listed),
                BTreeSet::from(["items", "limit", "offset", "total"]),
                "{list_tool} must return the exact bounded-envelope shape"
            );
            let records = listed["items"]
                .as_array()
                .unwrap_or_else(|| panic!("{list_tool}.items must be an array: {listed}"));
            let total = listed["total"]
                .as_u64()
                .unwrap_or_else(|| panic!("{list_tool}.total must be an unsigned integer"));
            assert!(
                total >= records.len() as u64,
                "{list_tool} returned an invalid total: {listed}"
            );
            assert_eq!(listed["offset"], 0, "{list_tool} default offset");
            assert_eq!(listed["limit"], 200, "{list_tool} default limit");
            records
        }
    };
    assert!(
        !records.is_empty(),
        "{list_tool} returned no positive records"
    );
    let expected = records
        .iter()
        .find(|record| select(record))
        .unwrap_or_else(|| {
            panic!("{list_tool} did not return the required positive record: {listed}")
        })
        .clone();

    let mut get_params = serde_json::Map::from_iter([(
        "drawing_path".to_string(),
        serde_json::Value::String(drawing_path.to_string_lossy().into_owned()),
    )]);
    for field in selector_fields {
        let value = expected
            .get(*field)
            .unwrap_or_else(|| {
                panic!("{list_tool} record lacks selector field {field}: {expected}")
            })
            .clone();
        assert!(
            value.as_str().is_some_and(|value| !value.is_empty()),
            "{list_tool} selector field {field} must be a nonempty string: {expected}"
        );
        get_params.insert((*field).to_string(), value);
    }

    let actual =
        expanded_cli_success_json(covered, get_tool, &serde_json::Value::Object(get_params));
    assert_eq!(
        actual, expected,
        "{get_tool} must return exactly the record advertised by {list_tool}"
    );
    actual
}

fn assert_cli_xref_error(tool: &str, params: &serde_json::Value, code: &str) -> String {
    let output = cli_call(tool, params);
    assert!(
        !output.status.success(),
        "{tool} unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stdout.is_empty(),
        "{tool} error must leave stdout empty: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with(&format!("code={code} ")),
        "expected code={code}, got: {stderr}"
    );
    stderr
}

struct McpClient {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    next_id: u64,
}

impl McpClient {
    fn new() -> Self {
        Self::from_command(full_surface_subcommand("serve"))
    }

    #[cfg(feature = "preview")]
    fn preview_plain() -> Self {
        let mut command = std::process::Command::new(bin());
        command.arg("serve");
        Self::from_command(command)
    }

    fn from_command(mut command: std::process::Command) -> Self {
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
                "clientInfo": {"name": "integration-test", "version": "0.1.0"}
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

    fn call_tool(&mut self, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        self.request(
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
        )
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn mcp_tool_text(response: &serde_json::Value) -> &str {
    response["result"]["content"]
        .as_array()
        .and_then(|content| content.iter().find_map(|item| item["text"].as_str()))
        .unwrap_or_else(|| panic!("MCP tool result has no text content: {response}"))
}

fn assert_mcp_xref_error(response: &serde_json::Value, code: &str) {
    assert!(
        response.get("error").is_none(),
        "expected a tool result, not a JSON-RPC error: {response}"
    );
    assert_eq!(
        response["result"]["isError"], true,
        "expected MCP tool error: {response}"
    );
    let text = mcp_tool_text(response);
    assert!(
        text.starts_with(&format!("code={code} ")),
        "expected code={code}, got: {text}"
    );
}

fn insert_with_attributes(block_name: &str, attributes: &[(&str, &str)]) -> EntityType {
    let mut insert = Insert::new(block_name, Vector3::new(0.0, 0.0, 0.0));
    for (tag, value) in attributes {
        insert
            .attributes
            .push(AttributeEntity::simple(*tag, *value));
    }
    EntityType::Insert(insert)
}

fn temp_dxf_with_later_matching_title_block() -> tempfile::NamedTempFile {
    let mut doc = CadDocument::new();
    doc.add_entity(insert_with_attributes(
        "OTHER_TITLE_BLOCK",
        &[("REVISION", "X01"), ("DRAWING_NUMBER", "WRONG")],
    ))
    .unwrap();
    doc.add_entity(insert_with_attributes(
        "AUTOCAD_MCP_GENERIC",
        &[
            ("REVISION", "P01"),
            ("DRAWING_NUMBER", "SYNTHETIC-001"),
            ("REFERENCE", "REFERENCE-001"),
            ("TITLE_LINE_1", "Synthetic Fixture"),
            ("TITLE_LINE_2", "Example Sheet"),
            ("SHEET_NUMBER", "1"),
            ("SHEET_COUNT", "1"),
        ],
    ))
    .unwrap();
    let f = tempfile::Builder::new().suffix(".dxf").tempfile().unwrap();
    DxfWriter::new(&doc).write_to_file(f.path()).unwrap();
    f
}

#[test]
fn mcp_server_lists_expected_tools() {
    let mut child = full_surface_subcommand("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // Initialize
    writeln!(
        stdin,
        "{}",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(resp["id"], 1, "expected initialize response");
    assert!(
        resp["result"]["capabilities"]["tools"].is_object(),
        "server must advertise tools capability"
    );

    // Initialized notification (no response expected)
    writeln!(
        stdin,
        "{}",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    // tools/list
    writeln!(
        stdin,
        "{}",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(resp["id"], 2, "expected tools/list response");
    let tools = resp["result"]["tools"].as_array().unwrap();
    assert_eq!(
        tools.len(),
        EXPECTED_TOOL_COUNT,
        "expected {} tools, got {}: {:?}",
        EXPECTED_TOOL_COUNT,
        tools.len(),
        tools
            .iter()
            .map(|t| t["name"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>()
    );

    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for expected in EXPECTED_TOOLS {
        assert!(
            names.contains(expected),
            "missing tool {expected}; got {names:?}"
        );
    }

    for tool in tools {
        assert_serialized_tool_annotations(tool);
    }

    let cli_output = full_surface_subcommand("list-tools").output().unwrap();
    assert!(
        cli_output.status.success(),
        "list-tools failed: {}",
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_tools: serde_json::Value =
        serde_json::from_slice(&cli_output.stdout).expect("list-tools must return JSON");
    let cli_tools = cli_tools
        .as_array()
        .expect("list-tools output must be an array");
    let cli_schemas = cli_tools
        .iter()
        .map(|tool| {
            (
                tool["name"].as_str().expect("CLI tool name").to_owned(),
                tool.get("inputSchema").expect("CLI inputSchema"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mcp_schemas = tools
        .iter()
        .map(|tool| {
            (
                tool["name"].as_str().expect("MCP tool name").to_owned(),
                tool.get("inputSchema").expect("MCP inputSchema"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for &name in EXPANDED_READ_TOOLS {
        let cli_schema = cli_schemas
            .get(name)
            .unwrap_or_else(|| panic!("CLI list-tools omitted {name}"));
        let mcp_schema = mcp_schemas
            .get(name)
            .unwrap_or_else(|| panic!("MCP tools/list omitted {name}"));
        assert_eq!(
            mcp_schema, cli_schema,
            "{name} inputSchema differs between MCP tools/list and CLI list-tools"
        );
    }

    child.kill().unwrap();
}

#[cfg(feature = "preview")]
#[test]
fn preview_plain_cli_and_mcp_surfaces_fail_closed_to_read_only_tools() {
    let list_output = std::process::Command::new(bin())
        .arg("list-tools")
        .output()
        .unwrap();
    assert!(
        list_output.status.success(),
        "{}",
        String::from_utf8_lossy(&list_output.stderr)
    );
    let cli_tools: serde_json::Value = serde_json::from_slice(&list_output.stdout).unwrap();
    let cli_tools = cli_tools.as_array().unwrap();
    assert_eq!(cli_tools.len(), 36);
    assert!(cli_tools
        .iter()
        .all(|tool| tool["annotations"]["readOnlyHint"] == true));

    let call_output = std::process::Command::new(bin())
        .args([
            "call",
            "write_title_block",
            r#"{"drawing_path":"/nonexistent/drawing.dxf","fields":{}}"#,
        ])
        .output()
        .unwrap();
    assert!(!call_output.status.success());
    assert!(
        String::from_utf8_lossy(&call_output.stderr).contains("unknown tool: write_title_block")
    );

    let mut client = McpClient::preview_plain();
    let tools_response = client.request("tools/list", serde_json::json!({}));
    let mcp_tools = tools_response["result"]["tools"].as_array().unwrap();
    assert_eq!(mcp_tools.len(), 36);
    assert!(mcp_tools
        .iter()
        .all(|tool| tool["annotations"]["readOnlyHint"] == true));

    let call_response = client.call_tool(
        "write_title_block",
        serde_json::json!({
            "drawing_path": "/nonexistent/drawing.dxf",
            "fields": {}
        }),
    );
    assert_eq!(call_response["error"]["code"], -32602);
    assert_eq!(call_response["error"]["message"], "tool not found");
}

#[test]
fn write_title_block_missing_file_returns_error_result() {
    let mut child = full_surface_subcommand("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // Initialize
    writeln!(
        stdin,
        "{}",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();

    writeln!(
        stdin,
        "{}",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    // Call write_title_block with a path that does not exist
    writeln!(
        stdin,
        "{}",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_title_block","arguments":{"drawing_path":"/nonexistent/drawing.dwg","fields":{"revision":"P02"}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();

    // Must be a valid tool result (not a protocol error)
    assert_eq!(resp["id"], 2);
    assert!(
        resp["result"].is_object(),
        "expected a tool result object, not a protocol error: {resp}"
    );
    let is_error = resp["result"]["isError"].as_bool().unwrap_or(false);
    assert!(is_error, "expected isError: true for missing file: {resp}");

    child.kill().unwrap();
    child.wait().ok();
}

#[test]
fn list_tools_outputs_expected_tools() {
    let output = full_surface_subcommand("list-tools").output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("not JSON");
    let tools = v.as_array().expect("list-tools output must be an array");
    assert_eq!(
        EXPECTED_TOOLS.len(),
        EXPECTED_TOOL_COUNT,
        "expected-tool fixture must stay aligned with the accepted count"
    );
    assert_eq!(tools.len(), EXPECTED_TOOL_COUNT, "got: {tools:?}");
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or("?"))
        .collect();
    for expected in EXPECTED_TOOLS {
        assert!(
            names.contains(expected),
            "missing tool {expected}; got {names:?}"
        );
    }

    for forbidden in FORBIDDEN_XREF_TOOLS {
        assert!(
            !names.contains(forbidden),
            "reserved or obsolete XREF tool {forbidden} must not be advertised"
        );
    }

    for tool in tools {
        assert_serialized_tool_annotations(tool);
    }

    let advertised: BTreeMap<&str, &serde_json::Value> = tools
        .iter()
        .map(|tool| (tool["name"].as_str().unwrap(), &tool["inputSchema"]))
        .collect();
    for (name, expected_schema) in expected_xref_schemas() {
        let actual = advertised
            .get(name)
            .unwrap_or_else(|| panic!("missing XREF schema for {name}"));
        assert_eq!(
            **actual, expected_schema,
            "router schema for {name} must equal schema_for!(Request)"
        );
        assert_eq!(
            actual["additionalProperties"], false,
            "{name} must reject unknown top-level parameters"
        );
        assert!(
            !schema_explicitly_allows_null(actual),
            "{name} must not advertise null for omitted-only request fields"
        );
    }

    let entity_properties = &advertised["list_entities"]["properties"];
    assert_eq!(entity_properties["entity_types"]["minItems"], 1);
    assert_eq!(entity_properties["limit"]["minimum"], 1);
    assert_eq!(entity_properties["limit"]["maximum"], 1_000);
    assert_eq!(entity_properties["limit"]["default"], 200);

    let text_schema = advertised["list_text"];
    assert_eq!(text_schema["additionalProperties"], false);
    assert_eq!(text_schema["required"], serde_json::json!(["drawing_path"]));
    assert_eq!(
        object_keys(&text_schema["properties"]),
        BTreeSet::from([
            "drawing_path",
            "layer",
            "owner_handle",
            "owner_name",
            "owner_type",
            "text_types",
        ])
    );
    assert_eq!(text_schema["properties"]["text_types"]["minItems"], 1);
    assert_eq!(
        text_schema["$defs"]["TextEntityKind"]["enum"],
        serde_json::json!(["TEXT", "MTEXT"])
    );
    assert_eq!(
        text_schema["$defs"]["DirectOwnerType"]["enum"],
        serde_json::json!(["model_space", "paper_space", "block_definition", "entity"])
    );

    let update_properties = &advertised["update_xref"]["properties"]["properties"];
    assert_eq!(update_properties["additionalProperties"], true);
    assert_eq!(
        object_keys(&update_properties["properties"]),
        BTreeSet::from(["name", "reference_type", "xref_path"])
    );
    let instance_properties = &advertised["update_xref_instance"]["properties"]["properties"];
    assert_eq!(instance_properties["additionalProperties"], true);
    assert_eq!(
        object_keys(&instance_properties["properties"]),
        BTreeSet::from([
            "array",
            "insertion_point",
            "layer_handle",
            "layer_name",
            "normal",
            "rotation_degrees",
            "scale",
            "visibility",
        ])
    );

    for tool in ["insert_xref_instance", "update_xref_instance"] {
        let array_schema = &advertised[tool]["$defs"]["XrefRectangularArray"];
        for dimension in ["rows", "columns"] {
            assert_eq!(
                array_schema["properties"][dimension]["minimum"], 1,
                "{tool} array {dimension} minimum"
            );
            assert_eq!(
                array_schema["properties"][dimension]["maximum"], 65_535,
                "{tool} array {dimension} maximum"
            );
        }
    }
}

#[test]
fn internal_and_admin_helpers_are_not_public_tools() {
    let routed = AutocadServer::tool_router()
        .list_all()
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect::<BTreeSet<_>>();

    for name in ["preflight_xref_mutation", "survey_title_blocks"] {
        assert!(
            !routed.contains(name),
            "{name} must not be MCP-discoverable"
        );

        let output = full_surface_subcommand("call")
            .args([name, "{}"])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{name} must not be CLI-callable");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(&format!("unknown tool: {name}")),
            "unexpected {name} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn xref_certification_info_reports_build_time_release_bindings() {
    let output = std::process::Command::new(bin())
        .arg("xref-certification-info")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 4);
    assert_eq!(value["experimental_support"], cfg!(feature = "preview"));
    assert_eq!(
        value["activation_catalogue_sha256"],
        autocad_mcp::activation::activation_catalogue_sha256().unwrap()
    );
    assert!(value.get("certified_arg_sha256").is_some());
    assert!(value.get("certified_arg_policy_id").is_some());
    assert!(value.get("certified_arg_policy_sha256").is_some());
    assert_eq!(value["certification_failpoints_enabled"], false);
    assert_eq!(
        value["crt_linkage"],
        autocad_mcp::certification::xref_certification_crt_linkage()
    );
    let build_identity = autocad_mcp::certification::xref_certification_build_identity();
    assert_eq!(
        value["build_identity"]["certified_arg_sha256"],
        build_identity.certified_arg_sha256
    );
    assert_eq!(
        value["build_identity"]["certified_arg_policy_id"],
        build_identity.certified_arg_policy_id
    );
    assert_eq!(
        value["build_identity"]["certified_arg_policy_sha256"],
        build_identity.certified_arg_policy_sha256
    );
    assert_eq!(
        value["title_block_profile_registry_sha256"],
        autocad_mcp::ops::profiles::title_block_profile_registry_sha256()
    );
    let reported_profiles = serde_json::from_value::<
        Vec<autocad_mcp::certification::CertificationProfileDefinition>,
    >(value["title_block_profiles"].clone())
    .unwrap();
    assert_eq!(
        reported_profiles,
        autocad_mcp::certification::embedded_certification_profile_definitions()
    );
    assert_eq!(
        object_keys(&value["artifact_sha256"]),
        BTreeSet::from([
            "bind_verifier_profiles",
            "clip_verifier_profiles",
            "mutation_capabilities",
            "preservation_verifier_profiles",
        ])
    );
    let expected_mutations = serde_json::json!([
        "attach_xref",
        "bind_xref",
        "delete_xref_instance",
        "detach_xref",
        "insert_xref_instance",
        "reload_xref",
        "unload_xref",
        "update_xref",
        "update_xref_instance"
    ]);
    assert_eq!(value["xref_mutation_tools"], expected_mutations);

    let tools_output = full_surface_subcommand("list-tools").output().unwrap();
    assert!(tools_output.status.success());
    let tools: serde_json::Value = serde_json::from_slice(&tools_output.stdout).unwrap();
    let mutation_names = tools
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .filter(|name| {
            expected_mutations
                .as_array()
                .unwrap()
                .iter()
                .any(|expected| expected.as_str() == Some(*name))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        mutation_names,
        expected_mutations
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
}

#[test]
fn call_list_layouts_on_empty_dxf() {
    let dxf = temp_empty_dxf();
    let params = serde_json::json!({"drawing_path": dxf.path().to_str().unwrap()}).to_string();
    let output = full_surface_subcommand("call")
        .args(["list_layouts", &params])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("not JSON");
    assert!(v.is_array());
    assert!(v.as_array().unwrap().iter().any(|l| l["name"] == "Model"));
}

#[test]
fn expanded_get_drawing_matches_across_cli_and_mcp_on_tier1_dwg() {
    let drawing_path = tier1_dwg();
    assert!(drawing_path.is_file(), "missing fixture: {drawing_path:?}");
    let arguments =
        serde_json::json!({"drawing_path": drawing_path.to_string_lossy().into_owned()});

    let cli = cli_success_json("get_drawing", &arguments);
    assert_eq!(cli["version"], "AC1032");
    assert!(
        cli["counts"]["entities"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "expected semantic entities in fixture: {cli}"
    );
    assert_eq!(
        object_keys(&cli["geometry"]),
        BTreeSet::from(["model_space", "paper_space"])
    );
    assert_eq!(cli["geometry"]["model_space"]["source"], "saved_header");
    assert_eq!(
        cli["geometry"]["model_space"]["insertion_base"]["state"],
        "available"
    );
    assert_eq!(
        cli["geometry"]["model_space"]["extents"]["state"],
        "available"
    );
    assert_eq!(
        cli["geometry"]["paper_space"]["extents"],
        serde_json::json!({
            "state": "unavailable",
            "reason": "empty_space_sentinel"
        })
    );
    assert_eq!(
        object_keys(&cli["current_ucs"]),
        BTreeSet::from(["model_space", "paper_space"])
    );
    for space in ["model_space", "paper_space"] {
        assert_eq!(cli["current_ucs"][space]["source"], "saved_header");
        assert_eq!(cli["current_ucs"][space]["basis"]["state"], "available");
    }

    let mut client = McpClient::new();
    let response = client.call_tool("get_drawing", arguments);
    assert!(
        response.get("error").is_none(),
        "expected a tool result, not a JSON-RPC error: {response}"
    );
    assert_ne!(
        response["result"]["isError"], true,
        "get_drawing failed through MCP: {response}"
    );
    let mcp: serde_json::Value =
        serde_json::from_str(mcp_tool_text(&response)).expect("MCP text must contain summary JSON");
    assert_eq!(mcp, cli);
}

#[test]
fn expanded_records_share_direct_owner_context_and_list_text_filters() {
    let drawing_path = tier1_dwg();
    let drawing_path = drawing_path.to_string_lossy().into_owned();

    let inserts = cli_success_json(
        "list_block_inserts",
        &serde_json::json!({"drawing_path": drawing_path}),
    );
    let insert = inserts
        .as_array()
        .and_then(|items| items.iter().find(|item| item["handle"] == "252"))
        .expect("Tier 1 fixture must contain dynamic INSERT 252");
    let expected_owner = serde_json::json!({
        "state": "available",
        "owner_type": "model_space",
        "owner_name": "Model"
    });
    assert_eq!(insert["owner_handle"], "1F");
    assert_eq!(insert["owner_context"], expected_owner);
    assert_eq!(
        insert["dynamic_block"],
        serde_json::json!({
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
        })
    );

    let entity = cli_success_json(
        "get_entity",
        &serde_json::json!({
            "drawing_path": drawing_path,
            "handle": insert["handle"]
        }),
    );
    assert_eq!(entity["owner_handle"], insert["owner_handle"]);
    assert_eq!(entity["owner_context"], expected_owner);
    assert_eq!(
        entity["bounds"],
        serde_json::json!({
            "state": "unavailable",
            "reason": "unreliable_model_projection"
        })
    );
    assert_eq!(entity["detail"]["kind"], "insert");
    assert_eq!(
        entity["detail"]["dynamic_block"], insert["dynamic_block"],
        "generic and dedicated INSERT reads must share one dynamic-block record"
    );

    let filtered_text = cli_success_json(
        "list_text",
        &serde_json::json!({
            "drawing_path": drawing_path,
            "text_types": ["TEXT", "MTEXT"],
            "layer": "0",
            "owner_handle": "1F",
            "owner_type": "model_space",
            "owner_name": "Model"
        }),
    );
    assert!(
        filtered_text.is_array(),
        "list_text must retain its array response shape"
    );
    let partial_owner = cli_call(
        "list_text",
        &serde_json::json!({
            "drawing_path": drawing_path,
            "owner_type": "model_space"
        }),
    );
    assert!(!partial_owner.status.success());
    assert!(partial_owner.stdout.is_empty());
    let stderr = String::from_utf8(partial_owner.stderr).unwrap();
    assert!(
        stderr.contains("code=invalid_text_owner "),
        "expected invalid_text_owner, got: {stderr}"
    );
    assert!(stderr.contains(
        "owner selection must use {}, {owner_handle}, {owner_type,owner_name}, or all three"
    ));
}

#[test]
fn migrated_block_routes_preserve_positive_cli_mcp_json_parity() {
    let drawing_path = tier1_dwg().to_string_lossy().into_owned();
    let base_args = serde_json::json!({"drawing_path": drawing_path.clone()});
    let mut client = McpClient::new();

    let blocks = cli_mcp_parity(&mut client, "list_blocks", &base_args);
    assert!(
        blocks.as_array().is_some_and(|records| !records.is_empty()),
        "Tier 1 fixture must expose ordinary blocks"
    );

    let definitions = cli_mcp_parity(&mut client, "list_block_definitions", &base_args);
    let definition = definitions
        .as_array()
        .and_then(|records| {
            records
                .iter()
                .find(|record| record["is_layout"] == false && record["is_xref"] == false)
        })
        .expect("Tier 1 fixture must expose an ordinary block definition");
    cli_mcp_parity(
        &mut client,
        "get_block_definition",
        &serde_json::json!({
            "drawing_path": drawing_path,
            "handle": definition["handle"],
            "name": definition["name"]
        }),
    );

    let inserts = cli_mcp_parity(&mut client, "list_block_inserts", &base_args);
    let insert = inserts
        .as_array()
        .and_then(|records| records.iter().find(|record| record["handle"] == "252"))
        .expect("Tier 1 fixture must expose dynamic INSERT 252");
    cli_mcp_parity(
        &mut client,
        "get_block_insert",
        &serde_json::json!({
            "drawing_path": drawing_path,
            "handle": insert["handle"]
        }),
    );
}

#[test]
fn all_expanded_reads_have_positive_cli_acceptance() {
    let tier1 = tier1_dwg();
    assert!(tier1.is_file(), "missing fixture: {tier1:?}");
    let rich = temp_rich_expanded_read_dwg();
    let mut covered = BTreeSet::new();

    let drawing = expanded_cli_success_json(&mut covered, "get_drawing", &cli_drawing_args(&tier1));
    assert_eq!(drawing["version"], "AC1032");
    assert!(
        drawing["counts"]["entities"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "get_drawing must report positive Tier 1 content: {drawing}"
    );

    assert_cli_list_get_round_trip(
        &mut covered,
        &tier1,
        "list_entities",
        "get_entity",
        CliListShape::EntityEnvelope,
        &["handle"],
        |_| true,
    );
    assert_cli_list_get_round_trip(
        &mut covered,
        &tier1,
        "list_block_definitions",
        "get_block_definition",
        CliListShape::BareArray,
        &["handle", "name"],
        |record| {
            record["is_layout"].as_bool() == Some(false)
                && record["is_xref"].as_bool() == Some(false)
        },
    );
    assert_cli_list_get_round_trip(
        &mut covered,
        &tier1,
        "list_block_inserts",
        "get_block_insert",
        CliListShape::BareArray,
        &["handle"],
        |record| record["dynamic_block"]["state"] == "available",
    );
    assert_cli_list_get_round_trip(
        &mut covered,
        rich.path(),
        "list_text",
        "get_text",
        CliListShape::BareArray,
        &["handle"],
        |record| record["value"] == "CLI TEXT",
    );

    let mut layout_params = cli_drawing_args(&tier1);
    layout_params
        .as_object_mut()
        .unwrap()
        .insert("name".to_string(), serde_json::json!("Model"));
    let layout = expanded_cli_success_json(&mut covered, "get_layout", &layout_params);
    assert_eq!(layout["name"], "Model");
    assert_eq!(layout["is_model"], true);
    assert!(
        layout["handle"]
            .as_str()
            .is_some_and(|handle| !handle.is_empty()),
        "get_layout must return stable identity: {layout}"
    );

    assert_cli_list_get_round_trip(
        &mut covered,
        rich.path(),
        "list_layout_viewports",
        "get_layout_viewport",
        CliListShape::BareArray,
        &["handle"],
        |record| {
            let close = |field: &serde_json::Value, expected: f64| {
                field
                    .as_f64()
                    .is_some_and(|actual| (actual - expected).abs() < 1e-9)
            };
            let object = record.as_object().expect("viewport record is an object");
            record["resource_type"] == "paper_space_entity"
                && record["layout_name"] == "Layout1"
                && record["is_last_active_for_layout"] == false
                && !object.contains_key("is_primary_for_layout")
                && object.get("is_on").is_some_and(serde_json::Value::is_null)
                && object
                    .get("custom_scale")
                    .is_some_and(serde_json::Value::is_null)
                && close(&record["center"]["x"], 5.0)
                && close(&record["center"]["y"], 7.0)
                && close(&record["center"]["z"], 0.0)
                && close(&record["width"], 200.0)
                && close(&record["height"], 100.0)
                && close(&record["view_height"], 400.0)
                && close(&record["model_to_paper_scale"], 0.25)
        },
    );
    assert_cli_list_get_round_trip(
        &mut covered,
        rich.path(),
        "list_plot_settings",
        "get_plot_setting",
        CliListShape::BareArray,
        &["handle", "name"],
        |record| record["name"] == "CLI A3",
    );

    for (list_tool, get_tool) in [
        ("list_linetypes", "get_linetype"),
        ("list_text_styles", "get_text_style"),
        ("list_dimension_styles", "get_dimension_style"),
    ] {
        assert_cli_list_get_round_trip(
            &mut covered,
            &tier1,
            list_tool,
            get_tool,
            CliListShape::BareArray,
            &["handle", "name"],
            |_| true,
        );
    }
    assert_cli_list_get_round_trip(
        &mut covered,
        rich.path(),
        "list_named_views",
        "get_named_view",
        CliListShape::BareArray,
        &["handle", "name"],
        |record| record["name"] == "CLI_DETAIL",
    );
    assert_cli_list_get_round_trip(
        &mut covered,
        rich.path(),
        "list_named_ucs",
        "get_named_ucs",
        CliListShape::BareArray,
        &["handle", "name"],
        |record| record["name"] == "CLI_SITE",
    );

    assert_eq!(covered.len(), 24);
    assert_eq!(
        covered,
        EXPANDED_READ_TOOLS.iter().copied().collect(),
        "positive CLI acceptance must cover the exact expanded-read inventory"
    );
}

#[test]
fn all_expanded_read_routes_match_cli_errors_over_mcp_stdio() {
    let dxf = temp_empty_dxf();
    let drawing_path = dxf.path().to_string_lossy().into_owned();
    let cases = [
        (
            "get_drawing",
            serde_json::json!({"drawing_path": drawing_path}),
        ),
        (
            "list_entities",
            serde_json::json!({"drawing_path": drawing_path}),
        ),
        (
            "get_entity",
            serde_json::json!({"drawing_path": drawing_path, "handle": "1"}),
        ),
        (
            "list_block_definitions",
            serde_json::json!({"drawing_path": drawing_path}),
        ),
        (
            "get_block_definition",
            serde_json::json!({"drawing_path": drawing_path, "name": "DETAIL"}),
        ),
        (
            "list_block_inserts",
            serde_json::json!({"drawing_path": drawing_path}),
        ),
        (
            "get_block_insert",
            serde_json::json!({"drawing_path": drawing_path, "handle": "1"}),
        ),
        (
            "list_text",
            serde_json::json!({"drawing_path": drawing_path}),
        ),
        (
            "get_text",
            serde_json::json!({"drawing_path": drawing_path, "handle": "1"}),
        ),
        (
            "get_layout",
            serde_json::json!({"drawing_path": drawing_path, "name": "Model"}),
        ),
        (
            "list_layout_viewports",
            serde_json::json!({"drawing_path": drawing_path}),
        ),
        (
            "get_layout_viewport",
            serde_json::json!({"drawing_path": drawing_path, "handle": "1"}),
        ),
        (
            "list_plot_settings",
            serde_json::json!({"drawing_path": drawing_path}),
        ),
        (
            "get_plot_setting",
            serde_json::json!({"drawing_path": drawing_path, "name": "A3"}),
        ),
        (
            "list_linetypes",
            serde_json::json!({"drawing_path": drawing_path}),
        ),
        (
            "get_linetype",
            serde_json::json!({"drawing_path": drawing_path, "name": "Continuous"}),
        ),
        (
            "list_text_styles",
            serde_json::json!({"drawing_path": drawing_path}),
        ),
        (
            "get_text_style",
            serde_json::json!({"drawing_path": drawing_path, "name": "Standard"}),
        ),
        (
            "list_dimension_styles",
            serde_json::json!({"drawing_path": drawing_path}),
        ),
        (
            "get_dimension_style",
            serde_json::json!({"drawing_path": drawing_path, "name": "Standard"}),
        ),
        (
            "list_named_views",
            serde_json::json!({"drawing_path": drawing_path}),
        ),
        (
            "get_named_view",
            serde_json::json!({"drawing_path": drawing_path, "name": "Detail"}),
        ),
        (
            "list_named_ucs",
            serde_json::json!({"drawing_path": drawing_path}),
        ),
        (
            "get_named_ucs",
            serde_json::json!({"drawing_path": drawing_path, "name": "Site"}),
        ),
    ];
    assert_eq!(
        cases.iter().map(|(tool, _)| *tool).collect::<BTreeSet<_>>(),
        EXPANDED_READ_TOOLS.iter().copied().collect(),
        "MCP route cases must cover the exact expanded-read inventory"
    );

    let mut client = McpClient::new();
    for (tool, arguments) in cases {
        let cli_error = assert_cli_xref_error(tool, &arguments, "unsupported_format");
        let response = client.call_tool(tool, arguments);
        assert_mcp_xref_error(&response, "unsupported_format");
        assert_eq!(
            mcp_tool_text(&response),
            cli_error.trim_end(),
            "{tool} CLI/MCP error transport drifted"
        );
    }
}

#[test]
fn expanded_get_drawing_rejects_dxf_consistently_across_cli_and_mcp() {
    let dxf = temp_empty_dxf();
    let arguments = serde_json::json!({"drawing_path": dxf.path().to_string_lossy().into_owned()});

    let cli_error = assert_cli_xref_error("get_drawing", &arguments, "unsupported_format");
    let mut client = McpClient::new();
    let response = client.call_tool("get_drawing", arguments);
    assert_mcp_xref_error(&response, "unsupported_format");
    assert_eq!(mcp_tool_text(&response), cli_error.trim_end());

    let relative_arguments = serde_json::json!({"drawing_path": "relative/drawing.dwg"});
    let cli_error =
        assert_cli_xref_error("get_drawing", &relative_arguments, "invalid_drawing_path");
    let response = client.call_tool("get_drawing", relative_arguments);
    assert_mcp_xref_error(&response, "invalid_drawing_path");
    assert_eq!(mcp_tool_text(&response), cli_error.trim_end());
}

#[test]
fn call_unknown_tool_exits_1() {
    let output = full_surface_subcommand("call")
        .args(["nonexistent_tool", "{}"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown tool"), "got: {stderr}");
}

#[test]
fn call_tool_error_exits_nonzero_and_writes_stderr() {
    let output = full_surface_subcommand("call")
        .args([
            "write_title_block",
            r#"{"drawing_path":"/nonexistent/drawing.dxf","fields":{}}"#,
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "tool errors must not be written to stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no fields specified"), "got: {stderr}");
}

#[test]
fn write_title_block_resolves_later_matching_profile() {
    let dxf = temp_dxf_with_later_matching_title_block();
    let params = serde_json::json!({
        "drawing_path": dxf.path().to_str().unwrap(),
        "fields": {
            "revision": "P02"
        }
    })
    .to_string();
    let output = full_surface_subcommand("call")
        .args(["write_title_block", &params])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout not JSON");
    assert_eq!(v["status"], "ok");
    assert_eq!(v["profile_id"], "AUTOCAD_MCP_GENERIC");
    assert_eq!(v["fields_written"], 1);
    assert_eq!(v["target_inserts"], 1);
    assert_eq!(v["attributes_written"], 1);
}

#[test]
fn administrator_title_block_lifecycle_runs_end_to_end_as_processes() {
    let temporary = tempfile::tempdir().unwrap();
    let corpus_root = temporary.path().join("private-corpus");
    let project_root = corpus_root.join("project-a");
    std::fs::create_dir_all(&project_root).unwrap();

    let drawing_path = project_root.join("A101.dxf");
    let mut document = CadDocument::new();
    document
        .add_entity(insert_with_attributes(
            "PROCESS_ADMIN_TITLE",
            &[("DRAWING_NO", "PRIVATE-001"), ("REV", "P01")],
        ))
        .unwrap();
    DxfWriter::new(&document)
        .write_to_file(&drawing_path)
        .unwrap();
    let original_drawing_sha256 = sha256_file(&drawing_path);

    let survey_path = temporary.path().join("survey.jsonl");
    let survey_output = std::process::Command::new(bin())
        .args(["admin", "title-block", "survey"])
        .arg("--root")
        .arg(&corpus_root)
        .arg("--input")
        .arg(&project_root)
        .args(["--corpus-tier", "1", "--output"])
        .arg(&survey_path)
        .output()
        .unwrap();
    assert_process_success("administrator survey process", &survey_output);
    assert!(
        survey_output.stdout.is_empty(),
        "survey artifact must be written only to its named output: {}",
        String::from_utf8_lossy(&survey_output.stdout)
    );

    let survey_bytes = std::fs::read(&survey_path).unwrap();
    let survey_text = std::str::from_utf8(&survey_bytes).unwrap();
    let survey_record: serde_json::Value = serde_json::from_str(survey_text.trim_end()).unwrap();
    assert_eq!(survey_record["survey_schema"], 1);
    assert_eq!(survey_record["file"], "project-a/A101.dxf");
    assert_eq!(
        survey_record["file_sha256"],
        original_drawing_sha256.as_str()
    );
    assert_eq!(survey_record["corpus_tier"], 1);
    assert_eq!(survey_record["format"], "DXF");
    assert_eq!(
        survey_record["title_block_candidates"][0]["normalized_block_name"],
        "PROCESS_ADMIN_TITLE"
    );
    assert_eq!(
        survey_record["title_block_candidates"][0]["normalized_attribute_tags"],
        serde_json::json!(["DRAWING_NO", "REV"])
    );
    assert!(
        !survey_text.contains(temporary.path().to_string_lossy().as_ref()),
        "survey leaked its absolute private corpus path: {survey_text}"
    );
    assert!(!survey_text.contains("PRIVATE-001"));
    assert!(!survey_text.contains("P01"));

    let cluster_path = temporary.path().join("clusters.json");
    let cluster_output = std::process::Command::new(bin())
        .args(["admin", "title-block", "cluster"])
        .arg("--survey")
        .arg(&survey_path)
        .arg("--output")
        .arg(&cluster_path)
        .output()
        .unwrap();
    assert_process_success("administrator cluster process", &cluster_output);
    assert!(
        cluster_output.stdout.is_empty(),
        "cluster artifact must be written only to its named output: {}",
        String::from_utf8_lossy(&cluster_output.stdout)
    );

    let cluster_bytes = std::fs::read(&cluster_path).unwrap();
    let cluster: serde_json::Value = serde_json::from_slice(&cluster_bytes).unwrap();
    assert_eq!(cluster["cluster_schema"], 1);
    assert_eq!(cluster["survey_sha256"], sha256_bytes(&survey_bytes));
    assert_eq!(cluster["drawing_count"], 1);
    assert_eq!(cluster["clusters"].as_array().unwrap().len(), 1);
    assert_eq!(
        cluster["clusters"][0]["normalized_block_name"],
        "PROCESS_ADMIN_TITLE"
    );
    assert_eq!(
        cluster["clusters"][0]["normalized_attribute_tags"],
        serde_json::json!(["DRAWING_NO", "REV"])
    );
    assert_eq!(
        cluster["clusters"][0]["example_files"],
        serde_json::json!(["project-a/A101.dxf"])
    );
    let candidate_id = cluster["clusters"][0]["candidate_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let profiles_path = temporary.path().join("title-block-profiles.json");
    let profile_pack = serde_json::json!({
        "profile_pack_schema": 1,
        "pack_id": "process.lifecycle.title-blocks",
        "pack_version": "1.0.0",
        "title_block_schema": 1,
        "profiles": [{
            "profile_id": "PROCESS_ADMIN_TITLE",
            "schema_version": 1,
            "description": "Process-level administrator lifecycle fixture",
            "source_evidence": [
                format!("survey:{}", cluster["survey_sha256"].as_str().unwrap()),
                format!("cluster:{candidate_id}"),
                "fixture:process-lifecycle-test"
            ],
            "fingerprint": {
                "block_name": "PROCESS_ADMIN_TITLE",
                "attribute_tags": ["DRAWING_NO", "REV"]
            },
            "fields": {
                "drawing_number": "DRAWING_NO",
                "revision": "REV"
            }
        }]
    });
    std::fs::write(
        &profiles_path,
        serde_json::to_vec_pretty(&profile_pack).unwrap(),
    )
    .unwrap();
    let profile_pack_sha256 = sha256_file(&profiles_path);

    let validate_output = std::process::Command::new(bin())
        .args(["admin", "title-block", "validate", "--profiles"])
        .arg(&profiles_path)
        .output()
        .unwrap();
    assert_process_success("administrator validate process", &validate_output);
    let validation: serde_json::Value = serde_json::from_slice(&validate_output.stdout).unwrap();
    assert_eq!(validation["profile_pack_schema"], 1);
    assert_eq!(validation["pack_id"], "process.lifecycle.title-blocks");
    assert_eq!(validation["pack_version"], "1.0.0");
    assert_eq!(validation["sha256"], profile_pack_sha256);
    assert_eq!(validation["profile_count"], 1);
    assert_eq!(
        validation["profile_ids"],
        serde_json::json!(["PROCESS_ADMIN_TITLE"])
    );

    let witnesses_path = temporary.path().join("profile-witnesses.json");
    std::fs::write(
        &witnesses_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "profile_witness_schema": 1,
            "witnesses": [{
                "drawing_id": "project-a-a101",
                "profile_id": "PROCESS_ADMIN_TITLE",
                "drawing_path": drawing_path,
                "drawing_sha256": original_drawing_sha256
            }]
        }))
        .unwrap(),
    )
    .unwrap();

    let verify_output = std::process::Command::new(bin())
        .args(["admin", "title-block", "verify", "--profiles"])
        .arg(&profiles_path)
        .arg("--witnesses")
        .arg(&witnesses_path)
        .output()
        .unwrap();
    assert_process_success("administrator verify process", &verify_output);
    let verification: serde_json::Value = serde_json::from_slice(&verify_output.stdout).unwrap();
    assert_eq!(verification["profile_verification_schema"], 1);
    assert_eq!(verification["status"], "ok");
    assert_eq!(verification["profile_pack"], validation);
    assert_eq!(verification["witnesses"].as_array().unwrap().len(), 1);
    assert_eq!(verification["witnesses"][0]["drawing_id"], "project-a-a101");
    assert_eq!(
        verification["witnesses"][0]["profile_id"],
        "PROCESS_ADMIN_TITLE"
    );
    assert_eq!(
        verification["witnesses"][0]["mapped_fields"],
        serde_json::json!(["drawing_number", "revision"])
    );
    let verification_text = std::str::from_utf8(&verify_output.stdout).unwrap();
    assert!(
        !verification_text.contains(drawing_path.to_string_lossy().as_ref()),
        "verification leaked its private witness path: {verification_text}"
    );
    assert!(!verification_text.contains("PRIVATE-001"));
    assert!(!verification_text.contains("P01"));

    let write_params = serde_json::json!({
        "drawing_path": drawing_path,
        "fields": {"revision": "P02"}
    })
    .to_string();
    let write_output = full_surface_subcommand("call")
        .arg("--title-block-profiles")
        .arg(&profiles_path)
        .args(["write_title_block", &write_params])
        .output()
        .unwrap();
    assert_process_success("configured title-block mutation process", &write_output);
    let write_result: serde_json::Value = serde_json::from_slice(&write_output.stdout).unwrap();
    assert_eq!(write_result["status"], "ok");
    assert_eq!(write_result["profile_id"], "PROCESS_ADMIN_TITLE");
    assert_eq!(write_result["profile_authority"], "administrator");
    assert_eq!(
        write_result["profile_pack_id"],
        "process.lifecycle.title-blocks"
    );
    assert_eq!(write_result["profile_pack_version"], "1.0.0");
    assert_eq!(write_result["profile_pack_sha256"], profile_pack_sha256);
    assert_eq!(write_result["fields_written"], 1);
    assert_eq!(write_result["target_inserts"], 1);
    assert_eq!(write_result["attributes_written"], 1);

    let read_params = serde_json::json!({"drawing_path": drawing_path}).to_string();
    let read_output = full_surface_subcommand("call")
        .arg("--title-block-profiles")
        .arg(&profiles_path)
        .args(["read_title_blocks", &read_params])
        .output()
        .unwrap();
    assert_process_success("persisted title-block readback process", &read_output);
    let title_blocks: serde_json::Value = serde_json::from_slice(&read_output.stdout).unwrap();
    assert_eq!(title_blocks.as_array().unwrap().len(), 1);
    assert_eq!(title_blocks[0]["block_name"], "PROCESS_ADMIN_TITLE");
    assert_eq!(title_blocks[0]["attributes"]["DRAWING_NO"], "PRIVATE-001");
    assert_eq!(title_blocks[0]["attributes"]["REV"], "P02");
}

#[test]
fn plot_to_pdf_missing_file_returns_mcp_error_result() {
    // MCP path test — via JSON-RPC protocol
    let mut child = full_surface_subcommand("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    writeln!(stdin, "{}", r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}"#).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();

    writeln!(
        stdin,
        "{}",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    writeln!(stdin, "{}", r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"plot_to_pdf","arguments":{"drawing_path":"/nonexistent/drawing.dwg","layout":"Layout1","output":"/tmp/out.pdf"}}}"#).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(resp["id"], 2);
    assert!(
        resp["result"]["isError"].as_bool().unwrap_or(false),
        "expected isError: true: {resp}"
    );

    child.kill().unwrap();
    child.wait().ok();
}

#[test]
fn call_layers_outputs_json_array() {
    let dxf = temp_empty_dxf();
    let params = serde_json::json!({"drawing_path": dxf.path().to_str().unwrap()}).to_string();
    let output = full_surface_subcommand("call")
        .args(["list_layers", &params])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout not JSON");
    assert!(v.is_array());
    let layer0 = v
        .as_array()
        .unwrap()
        .iter()
        .find(|layer| layer["name"] == "0")
        .expect("layer 0 present");
    for key in [
        "handle",
        "name",
        "color_index",
        "line_type",
        "line_weight",
        "frozen",
        "locked",
        "off",
        "is_plottable",
        "xref_dependent",
        "xref_block_record_handle",
        "xref_name",
        "xref_path",
        "xref_is_overlay",
        "material_handle",
        "plotstyle_handle",
        "is_current",
    ] {
        assert!(layer0.get(key).is_some(), "missing layer field {key}");
    }
}

#[test]
fn call_layer_crudl_round_trips_on_dxf() {
    let dxf = temp_empty_dxf();
    let path = dxf.path().to_str().unwrap();

    let create_params = serde_json::json!({
        "drawing_path": path,
        "name": "ANNO",
        "properties": {
            "color_index": 3,
            "line_type": "Continuous",
            "line_weight": {"kind": "value", "hundredths_mm": 25},
            "locked": true
        }
    })
    .to_string();
    let output = full_surface_subcommand("call")
        .args(["create_layer", &create_params])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let created: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let handle = created["layer"]["handle"].as_str().unwrap().to_string();
    assert_eq!(created["layer"]["line_type"], "Continuous");
    assert_eq!(
        created["layer"]["line_weight"],
        serde_json::json!({"kind": "value", "hundredths_mm": 25})
    );

    let get_params = serde_json::json!({"drawing_path": path, "handle": handle}).to_string();
    let output = full_surface_subcommand("call")
        .args(["get_layer", &get_params])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let got: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(got["name"], "ANNO");
    assert_eq!(got["line_type"], "Continuous");
    assert_eq!(
        got["line_weight"],
        serde_json::json!({"kind": "value", "hundredths_mm": 25})
    );

    let update_params = serde_json::json!({
        "drawing_path": path,
        "handle": handle,
        "expected_name": "ANNO",
        "properties": {"off": true, "line_weight": {"kind": "by_block"}}
    })
    .to_string();
    let output = full_surface_subcommand("call")
        .args(["update_layer", &update_params])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let updated: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(updated["layer"]["off"], true);
    assert_eq!(
        updated["layer"]["line_weight"],
        serde_json::json!({"kind": "by_block"})
    );

    let get_params = serde_json::json!({"drawing_path": path, "handle": handle}).to_string();
    let output = full_surface_subcommand("call")
        .args(["get_layer", &get_params])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let got: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(got["off"], true);
    assert_eq!(got["line_weight"], serde_json::json!({"kind": "by_block"}));

    let rename_params = serde_json::json!({
        "drawing_path": path,
        "handle": handle,
        "expected_name": "ANNO",
        "new_name": "NOTES"
    })
    .to_string();
    let output = full_surface_subcommand("call")
        .args(["rename_layer", &rename_params])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let get_params = serde_json::json!({"drawing_path": path, "handle": handle}).to_string();
    let output = full_surface_subcommand("call")
        .args(["get_layer", &get_params])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let got: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(got["name"], "NOTES");
    assert_eq!(got["off"], true);
    assert_eq!(got["line_type"], "Continuous");
    assert_eq!(got["line_weight"], serde_json::json!({"kind": "by_block"}));

    let delete_params = serde_json::json!({
        "drawing_path": path,
        "handle": handle,
        "expected_name": "NOTES"
    })
    .to_string();
    let output = full_surface_subcommand("call")
        .args(["delete_layer", &delete_params])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let deleted: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(deleted["status"], "deleted");
    assert_eq!(deleted["layer"]["name"], "NOTES");
}

#[test]
fn call_title_blocks_outputs_json_array() {
    let dxf = temp_empty_dxf();
    let params = serde_json::json!({"drawing_path": dxf.path().to_str().unwrap()}).to_string();
    let output = full_surface_subcommand("call")
        .args(["read_title_blocks", &params])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout not JSON");
    assert!(v.is_array());
}

#[test]
fn cli_xref_success_uses_bare_exact_records_and_selectors() {
    let fixture = xref_fixture();
    let drawing_path = fixture.to_str().unwrap();
    let listed = cli_success_json(
        "list_xrefs",
        &serde_json::json!({"drawing_path": drawing_path}),
    );
    let listed = listed
        .as_array()
        .expect("list_xrefs must return a bare JSON array");
    assert_eq!(listed, &expected_xref_records());

    let expected = expected_xref_records();
    for expected_record in &expected {
        let handle = expected_record["handle"].as_str().unwrap();
        let actual = listed
            .iter()
            .find(|record| record["handle"] == handle)
            .unwrap_or_else(|| panic!("missing XREF handle {handle}: {listed:?}"));
        assert_eq!(actual, expected_record);
        assert_eq!(
            object_keys(actual),
            BTreeSet::from([
                "definition_base_point",
                "handle",
                "instance_count",
                "load_state",
                "name",
                "path_mode",
                "reference_type",
                "saved_path",
            ])
        );
        assert!(actual.get("path").is_none());
    }

    for (selector, expected_handle) in [
        (serde_json::json!({"handle": "F"}), "F"),
        (serde_json::json!({"handle": "0x000f"}), "F"),
        (serde_json::json!({"name": "grid_overlay"}), "10"),
        (
            serde_json::json!({"handle": "10", "name": "GRID_OVERLAY"}),
            "10",
        ),
    ] {
        let mut params = selector.as_object().unwrap().clone();
        params.insert(
            "drawing_path".to_string(),
            serde_json::Value::String(drawing_path.to_string()),
        );
        let record = cli_success_json("get_xref", &serde_json::Value::Object(params));
        assert!(record.is_object(), "get_xref must return a bare object");
        let expected_record = expected
            .iter()
            .find(|record| record["handle"] == expected_handle)
            .unwrap();
        assert_eq!(&record, expected_record);
        assert!(record.get("path").is_none());
    }
}

#[test]
fn cli_xref_instance_reads_use_complete_records_numeric_order_and_filters() {
    let drawing_path = xref_fixture();
    let drawing_path = drawing_path.to_str().unwrap();
    let all = cli_success_json(
        "list_xref_instances",
        &serde_json::json!({"drawing_path": drawing_path}),
    );
    let all = all.as_array().expect("instance list must be a bare array");
    assert_eq!(
        all.iter()
            .map(|record| record["handle"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["20", "30", "F0", "100"]
    );
    for record in all {
        assert_eq!(
            object_keys(record),
            BTreeSet::from([
                "array",
                "attachment_handle",
                "attachment_name",
                "handle",
                "insertion_point",
                "layer_handle",
                "layer_name",
                "normal",
                "owner_handle",
                "owner_name",
                "owner_type",
                "placement_kind",
                "rotation_degrees",
                "scale",
                "unit_scaling",
                "visibility",
            ])
        );
    }

    for (filter, expected_handles) in [
        (
            serde_json::json!({"attachment_handle": "0x000f"}),
            vec!["F0", "100"],
        ),
        (
            serde_json::json!({"attachment_name": "grid_overlay"}),
            vec!["20"],
        ),
        (serde_json::json!({"owner_type": "paper_space"}), vec!["20"]),
        (
            serde_json::json!({"layer_name": "xref_layer"}),
            vec!["20", "30", "F0"],
        ),
        (serde_json::json!({"visibility": "hidden"}), vec!["30"]),
    ] {
        let mut params = filter.as_object().unwrap().clone();
        params.insert(
            "drawing_path".to_string(),
            serde_json::Value::String(drawing_path.to_string()),
        );
        let records = cli_success_json("list_xref_instances", &serde_json::Value::Object(params));
        assert_eq!(
            records
                .as_array()
                .unwrap()
                .iter()
                .map(|record| record["handle"].as_str().unwrap())
                .collect::<Vec<_>>(),
            expected_handles
        );
    }

    let selected = cli_success_json(
        "get_xref_instance",
        &serde_json::json!({
            "drawing_path": drawing_path,
            "handle": "0x0020"
        }),
    );
    assert_eq!(selected, all[0]);
}

#[test]
fn cli_xref_path_and_dependency_reads_return_closed_envelopes() {
    let drawing_path = xref_fixture();
    let drawing_path = drawing_path.to_str().unwrap();
    let resolution = cli_success_json(
        "resolve_xref_path",
        &serde_json::json!({"drawing_path": drawing_path, "handle": "F"}),
    );
    assert_eq!(
        object_keys(&resolution),
        BTreeSet::from([
            "attachment_handle",
            "drawing",
            "path_mode",
            "resolution_basis",
            "resolution_state",
            "resolved_path",
            "saved_path",
            "search_path_index",
        ])
    );
    assert_eq!(resolution["attachment_handle"], "F");
    assert_eq!(resolution["saved_path"], "refs/site.dwg");
    assert_eq!(resolution["path_mode"], "relative");
    assert_eq!(resolution["resolution_state"], "not_found");
    assert!(resolution["resolved_path"].is_null());
    assert!(resolution["resolution_basis"].is_null());
    assert!(resolution["search_path_index"].is_null());

    let traversal = cli_success_json(
        "list_xref_dependencies",
        &serde_json::json!({"drawing_path": drawing_path, "handle": "F"}),
    );
    assert_eq!(
        object_keys(&traversal),
        BTreeSet::from(["dependencies", "drawing", "truncation", "within_limits"])
    );
    assert_eq!(traversal["within_limits"], true);
    assert!(traversal["truncation"].is_null());
    let dependencies = traversal["dependencies"].as_array().unwrap();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(
        object_keys(&dependencies[0]),
        BTreeSet::from([
            "attachment",
            "attachment_chain",
            "cycle_target_chain",
            "depth",
            "immediate_host_path",
            "inspection_state",
            "propagation_state",
            "resolution_basis",
            "resolution_state",
            "resolved_path",
        ])
    );
    assert_eq!(
        dependencies[0]["attachment_chain"],
        serde_json::json!(["F"])
    );
    assert_eq!(dependencies[0]["depth"], 0);
    assert_eq!(dependencies[0]["attachment"], expected_xref_records()[0]);
    assert_eq!(dependencies[0]["propagation_state"], "root");
    assert_eq!(dependencies[0]["resolution_state"], "not_found");
    assert_eq!(dependencies[0]["inspection_state"], "not_resolved");
    assert!(dependencies[0]["resolved_path"].is_null());
    assert!(dependencies[0]["cycle_target_chain"].is_null());
}

#[test]
fn cli_xref_parameter_errors_use_tool_error_transport() {
    let fixture = xref_fixture();
    let drawing_path = fixture.to_str().unwrap();
    let cases = [
        ("list_xrefs", serde_json::json!([])),
        ("list_xrefs", serde_json::json!({})),
        ("list_xrefs", serde_json::json!({"drawing_path": 10})),
        (
            "list_xrefs",
            serde_json::json!({"drawing_path": drawing_path, "path": "bad"}),
        ),
        ("get_xref", serde_json::Value::Null),
        ("get_xref", serde_json::json!({"handle": "F"})),
        (
            "get_xref",
            serde_json::json!({"drawing_path": "relative.dxf", "handle": 10}),
        ),
        (
            "get_xref",
            serde_json::json!({"drawing_path": drawing_path, "name": false}),
        ),
        (
            "get_xref",
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "reference_type": "attachment"
            }),
        ),
        (
            "get_xref",
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "unit_assumptions": {"unexpected": true}
            }),
        ),
    ];

    for (tool, params) in cases {
        assert_cli_xref_error(tool, &params, "invalid_parameters");
    }
}

#[test]
fn cli_xref_validation_and_identity_failures_have_stable_codes() {
    let fixture = xref_fixture();
    let drawing_path = fixture.to_str().unwrap();
    let missing_dir = tempfile::tempdir().unwrap();
    let unsupported_extension = missing_dir.path().join("missing.xyz");
    let missing_drawing = missing_dir.path().join("missing.dxf");
    let unreadable = tempfile::Builder::new().suffix(".dxf").tempfile().unwrap();
    std::fs::write(unreadable.path(), "not a DXF").unwrap();

    let precedence_cases = [
        (
            serde_json::json!({"drawing_path": "relative.dxf", "handle": "not-hex"}),
            "drawing_unreadable",
        ),
        (
            serde_json::json!({
                "drawing_path": unsupported_extension,
                "handle": "not-hex"
            }),
            "unsupported_format",
        ),
        (
            serde_json::json!({"drawing_path": missing_drawing, "handle": "not-hex"}),
            "drawing_not_found",
        ),
        (
            serde_json::json!({
                "drawing_path": unreadable.path(),
                "handle": "not-hex"
            }),
            "unsupported_xref_data",
        ),
        (
            serde_json::json!({"drawing_path": drawing_path}),
            "missing_identity",
        ),
        (
            serde_json::json!({"drawing_path": drawing_path, "handle": "not-hex"}),
            "invalid_handle",
        ),
        (
            serde_json::json!({"drawing_path": drawing_path, "handle": "FFFF"}),
            "xref_not_found",
        ),
        (
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "name": "GRID_OVERLAY"
            }),
            "contradictory_identity",
        ),
    ];
    for (params, code) in precedence_cases {
        assert_cli_xref_error("get_xref", &params, code);
    }

    let ambiguous = xref_fixture_variant(|text| {
        assert!(text.contains("GRID_OVERLAY"));
        text.replace("GRID_OVERLAY", "SITE_MODEL")
    });
    assert_cli_xref_error(
        "get_xref",
        &serde_json::json!({
            "drawing_path": ambiguous.path(),
            "name": "SITE_MODEL"
        }),
        "ambiguous_identity",
    );

    let unsupported = xref_fixture_variant(|text| {
        let path_group = "  1\nrefs/grid.dwg\n";
        assert!(text.contains(path_group));
        text.replacen(path_group, "", 1)
    });
    assert_cli_xref_error(
        "list_xrefs",
        &serde_json::json!({"drawing_path": unsupported.path()}),
        "unsupported_xref_data",
    );
}

#[test]
fn mcp_xref_calls_preserve_reason_coded_tool_errors_and_match_cli() {
    let fixture = xref_fixture();
    let drawing_path = fixture.to_str().unwrap();
    let unsupported = xref_fixture_variant(|text| {
        let path_group = "  1\nrefs/grid.dwg\n";
        assert!(text.contains(path_group));
        text.replacen(path_group, "", 1)
    });
    let success_params = serde_json::json!({
        "drawing_path": drawing_path,
        "handle": "0x000f"
    });
    let cli_record = cli_success_json("get_xref", &success_params);
    let mut client = McpClient::new();

    for (tool, arguments) in [
        (
            "list_xrefs",
            serde_json::json!({"drawing_path": drawing_path, "path": "bad"}),
        ),
        (
            "get_xref",
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "reference_type": "attachment"
            }),
        ),
        (
            "get_xref",
            serde_json::json!({"drawing_path": drawing_path, "handle": 10}),
        ),
        ("list_xrefs", serde_json::json!({"drawing_path": null})),
        (
            "update_xref",
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "properties": {"name": "RENAMED"},
                "unit_assumptions": [],
                "unexpected": true
            }),
        ),
    ] {
        let cli_error = assert_cli_xref_error(tool, &arguments, "invalid_parameters");
        let response = client.call_tool(tool, arguments);
        assert_mcp_xref_error(&response, "invalid_parameters");
        assert_eq!(mcp_tool_text(&response), cli_error.trim_end());
    }

    for (tool, arguments, code) in [
        (
            "update_xref",
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "properties": {"xref_path": "refs/site.dwg"},
                "layer_reconciliation": {
                    "mode": "drawing_policy",
                    "unexpected": true
                }
            }),
            "invalid_layer_reconciliation",
        ),
        (
            "reload_xref",
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "layer_reconciliation": {"mode": "not_a_mode"}
            }),
            "invalid_layer_reconciliation",
        ),
        (
            "attach_xref",
            serde_json::json!({
                "drawing_path": drawing_path,
                "xref_path": "refs/site.dwg",
                "reference_type": "attachment",
                "unit_assumptions": {
                    "source_units": "meters",
                    "unexpected": true
                }
            }),
            "invalid_unit_assumptions",
        ),
        (
            "update_xref",
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "properties": {"xref_path": "refs/site.dwg"},
                "unit_assumptions": null
            }),
            "invalid_unit_assumptions",
        ),
        (
            "insert_xref_instance",
            serde_json::json!({
                "drawing_path": drawing_path,
                "attachment_handle": "F",
                "unit_assumptions": []
            }),
            "invalid_unit_assumptions",
        ),
        (
            "reload_xref",
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "unit_assumptions": {"host_units": null}
            }),
            "invalid_unit_assumptions",
        ),
    ] {
        let cli_error = assert_cli_xref_error(tool, &arguments, code);
        let response = client.call_tool(tool, arguments);
        assert_mcp_xref_error(&response, code);
        assert_eq!(mcp_tool_text(&response), cli_error.trim_end());
    }

    for (arguments, code) in [
        (
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "properties": {"future_property": true},
                "unit_assumptions": {"unexpected": true}
            }),
            "invalid_xref_property",
        ),
        (
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "properties": {},
                "layer_reconciliation": {"unexpected": true}
            }),
            "empty_xref_update",
        ),
        (
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "properties": {"name": "RENAMED"},
                "layer_reconciliation": {"mode": "not_a_mode"}
            }),
            "invalid_parameters",
        ),
        (
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "properties": {"name": "RENAMED"},
                "search_paths": [42]
            }),
            "invalid_parameters",
        ),
        (
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "properties": {"name": "RENAMED"},
                "unit_assumptions": []
            }),
            "invalid_parameters",
        ),
    ] {
        let cli_error = assert_cli_xref_error("update_xref", &arguments, code);
        let response = client.call_tool("update_xref", arguments);
        assert_mcp_xref_error(&response, code);
        assert_eq!(mcp_tool_text(&response), cli_error.trim_end());
    }

    for (arguments, code) in [
        (
            serde_json::json!({"drawing_path": drawing_path}),
            "missing_identity",
        ),
        (
            serde_json::json!({"drawing_path": drawing_path, "handle": "not-hex"}),
            "invalid_handle",
        ),
        (
            serde_json::json!({"drawing_path": drawing_path, "handle": "FFFF"}),
            "xref_not_found",
        ),
    ] {
        let response = client.call_tool("get_xref", arguments);
        assert_mcp_xref_error(&response, code);
    }

    let response = client.call_tool(
        "list_xrefs",
        serde_json::json!({"drawing_path": unsupported.path()}),
    );
    assert_mcp_xref_error(&response, "unsupported_xref_data");

    let response = client.call_tool("get_xref", success_params);
    assert!(
        response.get("error").is_none(),
        "expected a tool result, not a JSON-RPC error: {response}"
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    let mcp_record: serde_json::Value = serde_json::from_str(mcp_tool_text(&response)).unwrap();
    assert_eq!(mcp_record, cli_record);
}

#[test]
fn attach_xref_validation_precedence_matches_cli_and_mcp() {
    let mut client = McpClient::new();
    let directory = tempfile::tempdir().unwrap();
    let missing_host = directory.path().join("missing.dwg");
    let missing_host_args = serde_json::json!({
        "drawing_path": missing_host,
        "xref_path": "source.dwg",
        "name": "SOURCE",
        "reference_type": "attachment",
        "placement": {"owner_handle": "not-hex"}
    });
    let cli_error = assert_cli_xref_error("attach_xref", &missing_host_args, "drawing_not_found");
    let response = client.call_tool("attach_xref", missing_host_args);
    assert_mcp_xref_error(&response, "drawing_not_found");
    assert_eq!(mcp_tool_text(&response), cli_error.trim_end());

    let invalid_scale_args = serde_json::json!({
        "drawing_path": "relative-host.dwg",
        "xref_path": "source.dwg",
        "name": "SOURCE",
        "reference_type": "attachment",
        "placement": {"scale": {"x": 0.0, "y": 1.0, "z": 1.0}}
    });
    let cli_error = assert_cli_xref_error("attach_xref", &invalid_scale_args, "invalid_xref_scale");
    let response = client.call_tool("attach_xref", invalid_scale_args);
    assert_mcp_xref_error(&response, "invalid_xref_scale");
    assert_eq!(mcp_tool_text(&response), cli_error.trim_end());
}

#[cfg(not(windows))]
#[test]
fn non_windows_xref_mutations_fail_identically_before_launch() {
    let drawing = temp_empty_ac1032_dxf();
    let drawing_path = drawing.path().to_str().unwrap();
    let source = tempfile::Builder::new().suffix(".dwg").tempfile().unwrap();
    std::fs::write(source.path(), b"synthetic source placeholder").unwrap();
    let source_path = source.path().to_str().unwrap();
    let cases = vec![
        (
            "attach_xref",
            serde_json::json!({
                "drawing_path": drawing_path,
                "xref_path": source_path,
                "reference_type": "attachment"
            }),
        ),
        (
            "update_xref",
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "properties": {"name": "SITE_MODEL_RENAMED"}
            }),
        ),
        (
            "detach_xref",
            serde_json::json!({"drawing_path": drawing_path, "handle": "F"}),
        ),
        (
            "insert_xref_instance",
            serde_json::json!({
                "drawing_path": drawing_path,
                "attachment_handle": "F"
            }),
        ),
        (
            "update_xref_instance",
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F0",
                "properties": {"rotation_degrees": 15.0}
            }),
        ),
        (
            "delete_xref_instance",
            serde_json::json!({"drawing_path": drawing_path, "handle": "F0"}),
        ),
        (
            "reload_xref",
            serde_json::json!({"drawing_path": drawing_path, "handle": "F"}),
        ),
        (
            "unload_xref",
            serde_json::json!({"drawing_path": drawing_path, "handle": "F"}),
        ),
        (
            "bind_xref",
            serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "F",
                "symbol_strategy": "prefix",
                "dependency_strategy": "reject_nested"
            }),
        ),
    ];
    let mut client = McpClient::new();

    for (tool, arguments) in cases {
        let cli_error = assert_cli_xref_error(tool, &arguments, "unsupported_platform");
        let response = client.call_tool(tool, arguments);
        assert_mcp_xref_error(&response, "unsupported_platform");
        assert_eq!(mcp_tool_text(&response), cli_error.trim_end(), "{tool}");
    }
}

#[test]
fn call_blocks_outputs_json_array() {
    let dxf = temp_empty_dxf();
    let params = serde_json::json!({"drawing_path": dxf.path().to_str().unwrap()}).to_string();
    let output = full_surface_subcommand("call")
        .args(["list_blocks", &params])
        .output()
        .unwrap();
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout not JSON");
    assert!(v.is_array());
}

#[test]
fn call_text_outputs_json_array() {
    let dxf = temp_empty_dxf();
    let params = serde_json::json!({"drawing_path": dxf.path().to_str().unwrap()}).to_string();
    let output = full_surface_subcommand("call")
        .args(["dump_text", &params])
        .output()
        .unwrap();
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout not JSON");
    assert!(v.is_array());
}
