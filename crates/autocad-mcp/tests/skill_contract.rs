use autocad_mcp::{
    ops::{
        xref_preflight::XrefMutationPreflightResponse,
        xrefs::{
            AttachXrefRequest, BindXrefRequest, DeleteXrefInstanceRequest, DetachXrefRequest,
            GetXrefInstanceRequest, GetXrefRequest, InsertXrefInstanceRequest,
            ListXrefDependenciesRequest, ListXrefInstancesRequest, ListXrefsRequest,
            ReloadXrefRequest, ResolveXrefPathRequest, UnloadXrefRequest,
            UpdateXrefInstanceRequest, UpdateXrefRequest,
        },
    },
    server::AutocadServer,
};
use schemars::JsonSchema;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
struct ToolRow {
    required: BTreeSet<String>,
    optional: BTreeSet<String>,
    output: String,
    notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ToolParams {
    required: BTreeSet<String>,
    optional: BTreeSet<String>,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate should live under <repo>/crates/autocad-mcp")
        .to_path_buf()
}

fn read_repo_file(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn router_tools() -> BTreeSet<String> {
    AutocadServer::tool_router()
        .list_all()
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect()
}

fn router_contract() -> BTreeMap<String, ToolParams> {
    AutocadServer::tool_router()
        .list_all()
        .into_iter()
        .map(|tool| {
            let branches = tool
                .input_schema
                .get("oneOf")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_else(|| vec![serde_json::Value::Object((*tool.input_schema).clone())]);
            let mut properties = BTreeSet::new();
            let mut required: Option<BTreeSet<String>> = None;

            for branch in &branches {
                let branch_properties = branch
                    .get("properties")
                    .and_then(serde_json::Value::as_object)
                    .unwrap_or_else(|| panic!("router branch must declare properties: {tool:?}"))
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                properties.extend(branch_properties);

                let branch_required = branch
                    .get("required")
                    .and_then(serde_json::Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .map(|item| {
                                item.as_str()
                                    .unwrap_or_else(|| {
                                        panic!(
                                            "router required parameter must be a string: {tool:?}"
                                        )
                                    })
                                    .to_string()
                            })
                            .collect::<BTreeSet<_>>()
                    })
                    .unwrap_or_default();
                required = Some(match required {
                    Some(shared) => shared.intersection(&branch_required).cloned().collect(),
                    None => branch_required,
                });
            }

            let required = required.unwrap_or_default();
            let optional = properties.difference(&required).cloned().collect();

            (tool.name.to_string(), ToolParams { required, optional })
        })
        .collect()
}

fn tool_params(required: &[&str], optional: &[&str]) -> ToolParams {
    ToolParams {
        required: string_set(required),
        optional: string_set(optional),
    }
}

fn expected_contract() -> BTreeMap<String, ToolParams> {
    [
        ("get_drawing", tool_params(&["drawing_path"], &[])),
        (
            "list_entities",
            tool_params(
                &["drawing_path"],
                &[
                    "entity_types",
                    "layer",
                    "owner_handle",
                    "include_invisible",
                    "offset",
                    "limit",
                ],
            ),
        ),
        ("get_entity", tool_params(&["drawing_path", "handle"], &[])),
        ("list_layers", tool_params(&["drawing_path"], &[])),
        (
            "get_layer",
            tool_params(&["drawing_path"], &["handle", "name"]),
        ),
        (
            "create_layer",
            tool_params(&["drawing_path", "name"], &["properties"]),
        ),
        (
            "update_layer",
            tool_params(
                &["drawing_path", "properties"],
                &["handle", "name", "expected_handle", "expected_name"],
            ),
        ),
        (
            "rename_layer",
            tool_params(
                &["drawing_path", "new_name"],
                &["handle", "name", "expected_handle", "expected_name"],
            ),
        ),
        (
            "delete_layer",
            tool_params(
                &["drawing_path"],
                &["handle", "name", "expected_handle", "expected_name"],
            ),
        ),
        ("list_xrefs", tool_params(&["drawing_path"], &[])),
        (
            "get_xref",
            tool_params(&["drawing_path"], &["handle", "name"]),
        ),
        (
            "attach_xref",
            tool_params(
                &["drawing_path", "xref_path", "reference_type"],
                &["name", "search_paths", "placement", "unit_assumptions"],
            ),
        ),
        (
            "update_xref",
            tool_params(
                &["drawing_path", "properties"],
                &[
                    "handle",
                    "name",
                    "expected_handle",
                    "expected_name",
                    "layer_reconciliation",
                    "unit_assumptions",
                    "search_paths",
                ],
            ),
        ),
        (
            "detach_xref",
            tool_params(
                &["drawing_path"],
                &[
                    "handle",
                    "name",
                    "expected_handle",
                    "expected_name",
                    "expected_instance_count",
                    "expected_instance_handles",
                ],
            ),
        ),
        (
            "list_xref_instances",
            tool_params(
                &["drawing_path"],
                &[
                    "attachment_handle",
                    "attachment_name",
                    "owner_handle",
                    "owner_type",
                    "owner_name",
                    "layer_handle",
                    "layer_name",
                    "visibility",
                ],
            ),
        ),
        (
            "get_xref_instance",
            tool_params(&["drawing_path", "handle"], &[]),
        ),
        (
            "insert_xref_instance",
            tool_params(
                &["drawing_path"],
                &[
                    "attachment_handle",
                    "attachment_name",
                    "expected_attachment_handle",
                    "placement",
                    "unit_assumptions",
                ],
            ),
        ),
        (
            "update_xref_instance",
            tool_params(
                &["drawing_path", "handle", "properties"],
                &["expected_attachment_handle", "expected_owner_handle"],
            ),
        ),
        (
            "delete_xref_instance",
            tool_params(
                &["drawing_path", "handle"],
                &["expected_attachment_handle", "expected_owner_handle"],
            ),
        ),
        (
            "reload_xref",
            tool_params(
                &["drawing_path"],
                &[
                    "handle",
                    "name",
                    "expected_handle",
                    "expected_name",
                    "search_paths",
                    "layer_reconciliation",
                    "unit_assumptions",
                ],
            ),
        ),
        (
            "unload_xref",
            tool_params(
                &["drawing_path"],
                &["handle", "name", "expected_handle", "expected_name"],
            ),
        ),
        (
            "bind_xref",
            tool_params(
                &["drawing_path", "symbol_strategy", "dependency_strategy"],
                &[
                    "handle",
                    "name",
                    "expected_handle",
                    "expected_name",
                    "expected_instance_count",
                    "expected_instance_handles",
                    "search_paths",
                ],
            ),
        ),
        (
            "resolve_xref_path",
            tool_params(&["drawing_path"], &["handle", "name", "search_paths"]),
        ),
        (
            "list_xref_dependencies",
            tool_params(
                &["drawing_path"],
                &["handle", "name", "search_paths", "max_depth", "max_nodes"],
            ),
        ),
        ("list_blocks", tool_params(&["drawing_path"], &[])),
        (
            "list_block_definitions",
            tool_params(&["drawing_path"], &[]),
        ),
        (
            "get_block_definition",
            tool_params(&["drawing_path"], &["handle", "name"]),
        ),
        ("list_block_inserts", tool_params(&["drawing_path"], &[])),
        (
            "get_block_insert",
            tool_params(&["drawing_path", "handle"], &[]),
        ),
        (
            "read_title_blocks",
            tool_params(&["drawing_path"], &["attribute_value_mode"]),
        ),
        ("dump_text", tool_params(&["drawing_path"], &[])),
        (
            "list_text",
            tool_params(
                &["drawing_path"],
                &[
                    "text_types",
                    "layer",
                    "owner_handle",
                    "owner_type",
                    "owner_name",
                ],
            ),
        ),
        ("get_text", tool_params(&["drawing_path", "handle"], &[])),
        (
            "write_title_block",
            tool_params(&["drawing_path", "fields"], &[]),
        ),
        ("list_layouts", tool_params(&["drawing_path"], &[])),
        (
            "get_layout",
            tool_params(&["drawing_path"], &["handle", "name"]),
        ),
        (
            "list_layout_viewports",
            tool_params(&["drawing_path"], &["layout_handle", "layout_name"]),
        ),
        (
            "get_layout_viewport",
            tool_params(&["drawing_path", "handle"], &[]),
        ),
        ("list_plot_settings", tool_params(&["drawing_path"], &[])),
        (
            "get_plot_setting",
            tool_params(&["drawing_path"], &["handle", "name"]),
        ),
        ("list_linetypes", tool_params(&["drawing_path"], &[])),
        (
            "get_linetype",
            tool_params(&["drawing_path"], &["handle", "name"]),
        ),
        ("list_text_styles", tool_params(&["drawing_path"], &[])),
        (
            "get_text_style",
            tool_params(&["drawing_path"], &["handle", "name"]),
        ),
        ("list_dimension_styles", tool_params(&["drawing_path"], &[])),
        (
            "get_dimension_style",
            tool_params(&["drawing_path"], &["handle", "name"]),
        ),
        ("list_named_views", tool_params(&["drawing_path"], &[])),
        (
            "get_named_view",
            tool_params(&["drawing_path"], &["handle", "name"]),
        ),
        ("list_named_ucs", tool_params(&["drawing_path"], &[])),
        (
            "get_named_ucs",
            tool_params(&["drawing_path"], &["handle", "name"]),
        ),
        (
            "plot_to_pdf",
            tool_params(&["drawing_path", "layout", "output"], &[]),
        ),
    ]
    .into_iter()
    .map(|(name, params)| (name.to_owned(), params))
    .collect()
}

fn expected_xref_tools() -> BTreeSet<String> {
    string_set(&[
        "attach_xref",
        "bind_xref",
        "delete_xref_instance",
        "detach_xref",
        "get_xref",
        "get_xref_instance",
        "insert_xref_instance",
        "list_xref_dependencies",
        "list_xref_instances",
        "list_xrefs",
        "reload_xref",
        "resolve_xref_path",
        "unload_xref",
        "update_xref",
        "update_xref_instance",
    ])
}

fn expected_public_xref_tools() -> BTreeSet<String> {
    expected_xref_tools()
}

fn router_tool_schema(tool_name: &str) -> serde_json::Value {
    let input_schema = AutocadServer::tool_router()
        .list_all()
        .into_iter()
        .find(|tool| tool.name == tool_name)
        .unwrap_or_else(|| panic!("missing router tool `{tool_name}`"))
        .input_schema;
    serde_json::Value::Object((*input_schema).clone())
}

fn request_schema<T: JsonSchema>() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(T)).expect("request schema should serialize")
}

fn xref_request_schemas() -> BTreeMap<String, serde_json::Value> {
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
    .map(|(name, schema)| (name.to_owned(), schema))
    .collect()
}

fn string_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn schema_declares_type(schema: &serde_json::Value, expected: &str) -> bool {
    match schema.get("type") {
        Some(serde_json::Value::String(actual)) => actual == expected,
        Some(serde_json::Value::Array(actual)) => {
            actual.iter().any(|value| value.as_str() == Some(expected))
        }
        _ => false,
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

fn collect_open_schema_objects(value: &serde_json::Value, path: &str, open: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_open_schema_objects(child, &format!("{path}/{index}"), open);
            }
        }
        serde_json::Value::Object(object) => {
            let is_object_schema =
                object.get("type").and_then(serde_json::Value::as_str) == Some("object");
            if is_object_schema {
                match object.get("additionalProperties") {
                    Some(serde_json::Value::Bool(false)) => {}
                    Some(serde_json::Value::Bool(true)) => {
                        open.insert(path.to_owned());
                    }
                    other => panic!(
                        "object schema `{path}` must declare Boolean additionalProperties, got {other:?}"
                    ),
                }
            }
            for (key, child) in object {
                collect_open_schema_objects(child, &format!("{path}/{key}"), open);
            }
        }
        _ => {}
    }
}

fn assert_schema_matches_contract(
    tool_name: &str,
    schema: &serde_json::Value,
    expected: &ToolParams,
) {
    assert_eq!(
        schema.get("type"),
        Some(&serde_json::json!("object")),
        "`{tool_name}` input schema must be an object"
    );
    assert_eq!(
        schema.get("additionalProperties"),
        Some(&serde_json::json!(false)),
        "`{tool_name}` must reject unknown parameters"
    );

    let actual_required: BTreeSet<String> = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("`{tool_name}` schema must list required parameters"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("`{tool_name}` required parameter must be a string"))
                .to_string()
        })
        .collect();
    assert_eq!(
        actual_required, expected.required,
        "`{tool_name}` required parameters drifted"
    );

    let properties = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("`{tool_name}` schema must list properties"));
    let expected_properties = expected
        .required
        .union(&expected.optional)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        properties.keys().cloned().collect::<BTreeSet<_>>(),
        expected_properties,
        "`{tool_name}` property set drifted"
    );
}

fn assert_closed_object_schema(tool_name: &str, expected: &ToolParams) -> serde_json::Value {
    let schema = router_tool_schema(tool_name);
    assert_schema_matches_contract(tool_name, &schema, expected);
    schema
}

fn section<'a>(text: &'a str, heading: &str) -> &'a str {
    let mut offset = 0;

    for line in text.split_inclusive('\n') {
        if line.trim() == heading {
            let after_heading = &text[offset + line.len()..];
            let mut next_heading_offset = 0;

            for section_line in after_heading.split_inclusive('\n') {
                if section_line.starts_with("## ") {
                    return &after_heading[..next_heading_offset];
                }
                next_heading_offset += section_line.len();
            }

            return after_heading;
        }

        offset += line.len();
    }

    panic!("missing markdown section heading line `{heading}`");
}

fn clean_cell(cell: &str) -> String {
    cell.trim().trim_matches('`').trim().to_string()
}

fn parameter_set(cell: &str) -> BTreeSet<String> {
    let cleaned = clean_cell(cell);
    if cleaned.eq_ignore_ascii_case("none") {
        return BTreeSet::new();
    }
    cleaned
        .split(',')
        .map(clean_cell)
        .filter(|item| !item.is_empty())
        .collect()
}

fn parse_tool_contract(text: &str) -> BTreeMap<String, ToolRow> {
    let table = section(text, "## Tool Contract");
    let mut rows = BTreeMap::new();

    for line in table.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            continue;
        }
        if trimmed.contains("---") || trimmed.contains("Tool |") {
            continue;
        }

        let cells: Vec<String> = trimmed
            .trim_matches('|')
            // This deterministic contract parser does not support pipe characters inside cells.
            .split('|')
            .map(|cell| cell.trim().to_string())
            .collect();
        assert_eq!(
            cells.len(),
            5,
            "tool contract row must have 5 cells; pipe characters inside cells are not supported: {line}"
        );

        let tool = clean_cell(&cells[0]);
        assert!(
            rows.insert(
                tool.clone(),
                ToolRow {
                    required: parameter_set(&cells[1]),
                    optional: parameter_set(&cells[2]),
                    output: cells[3].clone(),
                    notes: cells[4].clone(),
                },
            )
            .is_none(),
            "duplicate tool contract row for {tool}"
        );
    }

    rows
}

fn cli_examples(text: &str) -> BTreeMap<String, Vec<serde_json::Map<String, serde_json::Value>>> {
    let examples = section(text, "## CLI Examples");
    let mut rows = BTreeMap::new();

    for line in examples.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix("autocad-mcp call ") else {
            continue;
        };

        let Some(tool) = rest.split_whitespace().next() else {
            panic!("CLI example must include a tool name: {line}");
        };
        let remainder = rest[tool.len()..].trim_start();
        assert!(
            !remainder.is_empty() && !line.trim_end().ends_with('\\'),
            "CLI example must be a complete single-line JSON call: {line}"
        );
        let json_arg = remainder
            .strip_prefix('\'')
            .and_then(|inner| inner.strip_suffix('\''))
            .unwrap_or_else(|| {
                panic!("CLI example JSON argument must be single-quoted for shell use: {line}")
            });
        let value = serde_json::from_str::<serde_json::Value>(json_arg)
            .unwrap_or_else(|err| panic!("CLI example JSON must parse on one line: {line}: {err}"));
        assert!(
            value.is_object(),
            "CLI example JSON argument must be an object: {line}"
        );
        let object = value
            .as_object()
            .expect("value should be an object after is_object check")
            .clone();

        let tool = tool.to_string();
        rows.entry(tool).or_insert_with(Vec::new).push(object);
    }

    rows
}

fn assert_contains_all(text: &str, required: &[&str]) {
    for needle in required {
        assert!(
            text.contains(needle),
            "missing required skill text: {needle}"
        );
    }
}

fn assert_example_keys_are_schema_valid(
    examples: &BTreeMap<String, Vec<serde_json::Map<String, serde_json::Value>>>,
    tool: &str,
    expected: &ToolParams,
) {
    let rows = examples
        .get(tool)
        .unwrap_or_else(|| panic!("missing CLI example for `{tool}`"));
    assert_eq!(
        rows.len(),
        1,
        "operations skill must include exactly one single-line autocad-mcp call example for `{tool}`"
    );
    let actual: BTreeSet<String> = rows[0].keys().cloned().collect();
    assert!(
        expected.required.is_subset(&actual),
        "CLI example parameter keys for `{tool}` must include required keys {:?}; got {:?}",
        expected.required,
        actual
    );
    let allowed: BTreeSet<String> = expected
        .required
        .union(&expected.optional)
        .cloned()
        .collect();
    assert!(
        actual.is_subset(&allowed),
        "CLI example parameter keys for `{tool}` must be schema keys {:?}; got {:?}",
        allowed,
        actual
    );
}

#[test]
fn operations_skill_tool_contract_matches_the_final_surface_exactly() {
    let text = read_repo_file("plugin/skills/autocad-mcp/SKILL.md");
    let rows = parse_tool_contract(&text);
    let table_tools: BTreeSet<String> = rows.keys().cloned().collect();

    assert_eq!(
        table_tools,
        expected_contract().keys().cloned().collect(),
        "operations skill tool table must be the exact final 51-tool surface"
    );
}

#[test]
fn router_surface_and_parameters_are_exactly_the_fifty_one_tools() {
    let expected = expected_contract();
    let expected_tools = expected.keys().cloned().collect::<BTreeSet<_>>();
    let actual_tools = router_tools();

    assert_eq!(
        actual_tools.len(),
        51,
        "the accepted router must expose 51 tools"
    );
    assert_eq!(
        actual_tools, expected_tools,
        "the accepted 51-tool router surface drifted"
    );
    assert_eq!(
        router_contract(),
        expected,
        "router required and optional parameter sets drifted"
    );
}

#[test]
fn list_text_router_schema_exposes_the_exact_closed_filter_contract() {
    let contract = expected_contract();
    let expected = contract
        .get("list_text")
        .expect("list_text contract must exist");
    let schema = assert_closed_object_schema("list_text", expected);

    assert_eq!(
        schema.pointer("/properties/text_types/minItems"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        schema.pointer("/$defs/TextEntityKind/enum"),
        Some(&serde_json::json!(["TEXT", "MTEXT"]))
    );
    assert_eq!(
        schema.pointer("/$defs/DirectOwnerType/enum"),
        Some(&serde_json::json!([
            "model_space",
            "paper_space",
            "block_definition",
            "entity"
        ]))
    );
    for field in ["layer", "owner_handle", "owner_type", "owner_name"] {
        assert!(
            schema["properties"].get(field).is_some(),
            "list_text must expose optional `{field}`"
        );
    }
}

#[test]
fn xref_request_types_match_the_final_closed_schema_contract() {
    let contract = expected_contract();
    let schemas = xref_request_schemas();

    assert_eq!(
        schemas.keys().cloned().collect::<BTreeSet<_>>(),
        expected_xref_tools(),
        "the public XREF request type set drifted"
    );

    for (tool, schema) in &schemas {
        let expected = contract
            .get(tool)
            .unwrap_or_else(|| panic!("missing expected XREF contract for `{tool}`"));
        assert_schema_matches_contract(tool, schema, expected);
        assert_eq!(
            schema.pointer("/properties/drawing_path/type"),
            Some(&serde_json::json!("string")),
            "`{tool}.drawing_path` must be a string"
        );
    }

    for tool in ["update_xref", "update_xref_instance"] {
        assert_eq!(
            schemas[tool].pointer("/properties/properties/type"),
            Some(&serde_json::json!("object")),
            "`{tool}.properties` must be an object"
        );
    }

    for (tool, property) in [
        ("attach_xref", "search_paths"),
        ("detach_xref", "expected_instance_handles"),
        ("list_xref_dependencies", "search_paths"),
    ] {
        let property_schema = schemas[tool]
            .pointer(&format!("/properties/{property}"))
            .unwrap_or_else(|| panic!("missing `{tool}.{property}` schema"));
        assert!(
            schema_declares_type(property_schema, "array"),
            "`{tool}.{property}` must be an array"
        );
    }

    let bind = &schemas["bind_xref"];
    assert_eq!(
        bind.pointer("/properties/dependency_strategy/enum"),
        Some(&serde_json::json!(["reject_nested", "bind_nested"])),
        "bind_xref.dependency_strategy must expose its valid values inline"
    );
    assert_eq!(
        bind.pointer("/properties/symbol_strategy/enum"),
        Some(&serde_json::json!(["prefix", "merge"])),
        "bind_xref.symbol_strategy must expose its valid values inline"
    );
}

#[test]
fn xref_router_schemas_match_the_final_closed_request_surface() {
    let contract = expected_contract();

    for tool in expected_xref_tools() {
        let expected = contract
            .get(&tool)
            .unwrap_or_else(|| panic!("missing expected XREF contract for `{tool}`"));
        let schema = assert_closed_object_schema(&tool, expected);

        assert_eq!(
            schema.pointer("/properties/drawing_path/type"),
            Some(&serde_json::json!("string")),
            "`{tool}.drawing_path` must be a string"
        );
    }

    for tool in ["update_xref", "update_xref_instance"] {
        assert_eq!(
            router_tool_schema(tool).pointer("/properties/properties/type"),
            Some(&serde_json::json!("object")),
            "`{tool}.properties` must be an object"
        );
    }

    for (tool, property) in [
        ("attach_xref", "search_paths"),
        ("detach_xref", "expected_instance_handles"),
        ("list_xref_dependencies", "search_paths"),
    ] {
        let schema = router_tool_schema(tool);
        let property_schema = schema
            .pointer(&format!("/properties/{property}"))
            .unwrap_or_else(|| panic!("missing `{tool}.{property}` schema"));
        assert!(
            schema_declares_type(property_schema, "array"),
            "`{tool}.{property}` must be an array"
        );
    }

    let bind = router_tool_schema("bind_xref");
    assert_eq!(
        bind.pointer("/properties/dependency_strategy/enum"),
        Some(&serde_json::json!(["reject_nested", "bind_nested"])),
        "tools/list must inline bind_xref.dependency_strategy values"
    );
    assert_eq!(
        bind.pointer("/properties/symbol_strategy/enum"),
        Some(&serde_json::json!(["prefix", "merge"])),
        "tools/list must inline bind_xref.symbol_strategy values"
    );
}

#[test]
fn retained_internal_xref_preflight_response_schema_is_closed_and_explicit() {
    let schema = request_schema::<XrefMutationPreflightResponse>();
    assert_eq!(
        schema.get("additionalProperties"),
        Some(&serde_json::json!(false))
    );
    assert_eq!(
        schema["properties"]
            .as_object()
            .expect("response properties")
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        string_set(&[
            "status",
            "operation",
            "scope",
            "portable_checks",
            "certified_runtime_checks",
        ])
    );
    assert_eq!(
        schema["required"]
            .as_array()
            .expect("response required set")
            .iter()
            .map(|value| value.as_str().expect("required key").to_owned())
            .collect::<BTreeSet<_>>(),
        string_set(&[
            "status",
            "operation",
            "scope",
            "portable_checks",
            "certified_runtime_checks",
        ])
    );
    assert_eq!(
        schema.pointer("/$defs/XrefPreflightStatus/enum"),
        Some(&serde_json::json!(["portable_checks_passed"]))
    );
    assert_eq!(
        schema.pointer("/$defs/XrefPreflightScope/enum"),
        Some(&serde_json::json!(["context_free_only"]))
    );
    assert_eq!(
        schema.pointer("/$defs/XrefPortableCheckState/enum"),
        Some(&serde_json::json!(["passed", "not_applicable"]))
    );
    assert_eq!(
        schema.pointer("/$defs/XrefCertifiedRuntime/enum"),
        Some(&serde_json::json!(["certified_windows_autocad"]))
    );
    assert_eq!(
        schema.pointer("/$defs/XrefCertifiedRuntimeCheckState/enum"),
        Some(&serde_json::json!([
            "required",
            "conditionally_required",
            "not_applicable"
        ]))
    );
    assert!(
        !schema_explicitly_allows_null(&schema),
        "the preflight response schema must not admit JSON null"
    );

    let mut open = BTreeSet::new();
    collect_open_schema_objects(&schema, "", &mut open);
    assert!(
        open.is_empty(),
        "the preflight response must be fully closed"
    );
}

#[test]
fn operations_skill_cli_examples_match_the_final_surface_exactly() {
    let text = read_repo_file("plugin/skills/autocad-mcp/SKILL.md");
    let examples = cli_examples(&text);
    let example_tools: BTreeSet<String> = examples.keys().cloned().collect();

    assert_eq!(
        example_tools,
        expected_contract().keys().cloned().collect(),
        "operations skill must include one single-line autocad-mcp call example per tool"
    );

    for (tool, rows) in examples {
        assert_eq!(
            rows.len(),
            1,
            "operations skill must include exactly one single-line autocad-mcp call example for `{tool}`"
        );
    }
}

#[test]
fn operations_skill_cli_examples_use_exact_parameter_keys() {
    let text = read_repo_file("plugin/skills/autocad-mcp/SKILL.md");
    let examples = cli_examples(&text);
    let contract = expected_contract();

    for (tool, params) in contract {
        assert_example_keys_are_schema_valid(&examples, &tool, &params);
    }
}

#[test]
fn operations_skill_documents_core_invocations() {
    let text = read_repo_file("plugin/skills/autocad-mcp/SKILL.md");

    assert_contains_all(&text, &["autocad-mcp serve", "autocad-mcp list-tools"]);
}

#[test]
fn operations_skill_documents_exact_parameters() {
    let text = read_repo_file("plugin/skills/autocad-mcp/SKILL.md");
    let rows = parse_tool_contract(&text);
    let contract = expected_contract();

    for (tool, expected) in contract {
        let actual = rows
            .get(&tool)
            .unwrap_or_else(|| panic!("missing tool row `{tool}`"));
        assert_eq!(
            actual.required, expected.required,
            "required parameters for `{tool}` drifted"
        );
        assert_eq!(
            actual.optional, expected.optional,
            "optional parameters for `{tool}` drifted"
        );
    }
}

#[test]
fn operations_skill_documents_completed_expanded_read_contracts() {
    let text = read_repo_file("plugin/skills/autocad-mcp/SKILL.md");
    let rows = parse_tool_contract(&text);
    let list_text = rows.get("list_text").expect("list_text row should exist");
    assert_eq!(
        list_text.optional,
        string_set(&[
            "text_types",
            "layer",
            "owner_handle",
            "owner_type",
            "owner_name",
        ])
    );
    assert!(list_text.output.contains("tagged direct-owner context"));

    for tool in [
        "get_entity",
        "list_block_inserts",
        "get_block_insert",
        "list_text",
        "get_text",
    ] {
        assert!(
            rows[tool].output.contains("tagged direct-owner context"),
            "{tool} must document the shared owner projection"
        );
    }
    for tool in [
        "list_entities",
        "get_entity",
        "list_block_inserts",
        "get_block_insert",
    ] {
        assert!(
            rows[tool].output.contains("dynamic linkage"),
            "{tool} must document the shared dynamic-block projection"
        );
    }

    assert_contains_all(
        &text,
        &[
            "`get_drawing.geometry` reports separately availability-tagged model-space",
            "`source: \"saved_header\"`",
            "`get_drawing.current_ucs` separately reports saved-header model-space",
            "Rich entity, ordinary block-insert, and text records keep `owner_handle`",
            "A non-null owner is either `available` with `owner_type` and\n`owner_name`, or `unavailable`",
            "Owner selection must use `{}`, `{owner_handle}`, `{owner_type, owner_name}`, or\nall three.",
            "The result remains an array, and `dump_text` remains unchanged.",
            "Entity bounds and detail use closed availability reasons",
            "ATTDEF prompt/style and ATTRIB style are\n`parser_defaulted`",
            "share a bounded `dynamic_block`\nprojection",
            "`link_not_proven` does not\nprove the block is static",
            "The active visibility choice is always\n`parser_not_retained`",
        ],
    );
}

#[test]
fn operations_skill_documents_exactly_the_fifteen_public_xref_tools() {
    let text = read_repo_file("plugin/skills/autocad-mcp/SKILL.md");
    let rows = parse_tool_contract(&text);
    let examples = cli_examples(&text);
    let xref_tools = expected_public_xref_tools();

    assert_eq!(
        xref_tools.len(),
        15,
        "the public XREF surface must contain 15 tools"
    );
    assert_eq!(
        rows.keys()
            .filter(|tool| xref_tools.contains(*tool))
            .cloned()
            .collect::<BTreeSet<_>>(),
        xref_tools,
        "the skill XREF rows drifted"
    );
    assert_eq!(
        examples
            .keys()
            .filter(|tool| expected_public_xref_tools().contains(*tool))
            .cloned()
            .collect::<BTreeSet<_>>(),
        expected_public_xref_tools(),
        "the skill XREF examples drifted"
    );

    assert!(rows
        .get("list_xrefs")
        .expect("list_xrefs row should exist")
        .output
        .contains("XrefAttachmentRecord"));
    assert!(rows
        .get("list_xref_instances")
        .expect("list_xref_instances row should exist")
        .output
        .contains("XrefInstanceRecord"));
    assert!(rows
        .get("list_xref_dependencies")
        .expect("list_xref_dependencies row should exist")
        .output
        .contains("traversal envelope"));

    let get_example = &examples
        .get("get_xref")
        .expect("get_xref example should exist")[0];
    assert_eq!(
        get_example.keys().cloned().collect::<BTreeSet<_>>(),
        string_set(&["drawing_path", "handle"]),
        "the primary get_xref example must use handle-first identity"
    );
    assert_eq!(get_example.get("handle"), Some(&serde_json::json!("2A")));

    let get_instance_example = &examples
        .get("get_xref_instance")
        .expect("get_xref_instance example should exist")[0];
    assert_eq!(
        get_instance_example
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        string_set(&["drawing_path", "handle"]),
        "the primary get_xref_instance example must use handle identity"
    );
}

#[test]
fn operations_skill_documents_xref_safety_and_recovery_contracts() {
    let text = read_repo_file("plugin/skills/autocad-mcp/SKILL.md");

    assert_contains_all(
        &text,
        &[
            "Use handles first because attachment names are mutable.",
            "A nested attachment belongs to its\nimmediate host drawing",
            "`expected_instance_count` and `expected_instance_handles`",
            "`expected_attachment_handle` and\n`expected_owner_handle`",
            "`xref_path` is accepted only by attach",
            "`search_paths` is an ordered, transient list",
            "`unit_assumptions` contains conditional `source_units` and `host_units`",
            "`layer_reconciliation` is accepted by reload",
            "source drawing and every source\ndependency as immutable",
            "All XREF mutations require Windows with AutoCAD",
            "`mutation_state_unknown` is the only uncertain-commit XREF code.",
            "Never retry\nautomatically after that code",
            "reconciliation is\ninconclusive: stop for operator recovery and do not retry.",
        ],
    );
}

#[test]
fn reserved_xref_clip_and_open_names_remain_absent() {
    let text = read_repo_file("plugin/skills/autocad-mcp/SKILL.md");
    let rows = parse_tool_contract(&text);
    let examples = cli_examples(&text);

    for reserved in [
        "list_xref_clips",
        "get_xref_clip",
        "create_xref_clip",
        "update_xref_clip",
        "delete_xref_clip",
        "open_xref",
    ] {
        assert!(!rows.contains_key(reserved));
        assert!(!examples.contains_key(reserved));
        assert!(
            !text.contains(reserved),
            "reserved XREF name `{reserved}` must remain absent from the operations skill"
        );
    }
}

#[test]
fn layer_property_schema_matches_branch_final_write_contract() {
    for tool in ["create_layer", "update_layer"] {
        let schema = router_tool_schema(tool);
        let top_properties = schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| panic!("`{tool}` schema must have object properties"));
        let property_schema = top_properties
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| panic!("`{tool}.properties` must be an object schema"));

        assert_eq!(
            property_schema.get("type"),
            Some(&serde_json::json!("object")),
            "`{tool}.properties` must be a non-null object"
        );
        assert_eq!(
            property_schema.get("additionalProperties"),
            Some(&serde_json::json!(false)),
            "`{tool}.properties` must reject unknown fields"
        );
        assert!(
            !property_schema.contains_key("default"),
            "`{tool}.properties` must not advertise null as its default"
        );
        let description = property_schema
            .get("description")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("`{tool}.properties` must document property semantics"));
        assert!(
            description.contains("unsupported/read-only layer keys")
                && description.contains("code=unsupported_layer_property")
                && description.contains("unknown keys"),
            "`{tool}.properties` must distinguish recognized unsupported/read-only keys from unknown keys"
        );

        let writable = property_schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| panic!("`{tool}.properties` must list writable fields"));
        let expected_writable: BTreeSet<String> = [
            "color_index",
            "frozen",
            "locked",
            "off",
            "is_plottable",
            "line_type",
            "line_weight",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(
            writable.keys().cloned().collect::<BTreeSet<_>>(),
            expected_writable,
            "`{tool}.properties` writable field set drifted"
        );

        let color = writable
            .get("color_index")
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| panic!("`{tool}.properties.color_index` missing"));
        assert_eq!(color.get("type"), Some(&serde_json::json!("integer")));
        assert_eq!(color.get("minimum"), Some(&serde_json::json!(1)));
        assert_eq!(color.get("maximum"), Some(&serde_json::json!(255)));

        for field in ["frozen", "locked", "off", "is_plottable"] {
            let field_schema = writable
                .get(field)
                .and_then(serde_json::Value::as_object)
                .unwrap_or_else(|| panic!("`{tool}.properties.{field}` missing"));
            assert_eq!(
                field_schema.get("type"),
                Some(&serde_json::json!("boolean")),
                "`{tool}.properties.{field}` must be a non-null boolean"
            );
        }

        let line_type = writable
            .get("line_type")
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| panic!("`{tool}.properties.line_type` missing"));
        assert_eq!(line_type.get("type"), Some(&serde_json::json!("string")));
        assert_eq!(line_type.get("minLength"), Some(&serde_json::json!(1)));

        let line_weight = writable
            .get("line_weight")
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| panic!("`{tool}.properties.line_weight` missing"));
        let line_weight_description = line_weight
            .get("description")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        assert!(
            line_weight_description.contains("raw shape is not accepted"),
            "`{tool}.properties.line_weight` must document raw as read-only"
        );
        let one_of = line_weight
            .get("oneOf")
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| panic!("`{tool}.properties.line_weight` must be structured"));
        let line_weight_kinds: BTreeSet<String> = one_of
            .iter()
            .map(|shape| {
                shape
                    .get("properties")
                    .and_then(serde_json::Value::as_object)
                    .and_then(|properties| properties.get("kind"))
                    .and_then(serde_json::Value::as_object)
                    .and_then(|kind| kind.get("const"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_else(|| {
                        panic!("`{tool}.properties.line_weight` shape missing kind const")
                    })
                    .to_string()
            })
            .collect();
        assert_eq!(
            line_weight_kinds,
            ["by_block", "by_layer", "default", "value"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            "`{tool}.properties.line_weight` writable variants drifted"
        );

        let value_shape = one_of
            .iter()
            .find(|shape| {
                shape
                    .get("properties")
                    .and_then(serde_json::Value::as_object)
                    .and_then(|properties| properties.get("kind"))
                    .and_then(serde_json::Value::as_object)
                    .and_then(|kind| kind.get("const"))
                    == Some(&serde_json::json!("value"))
            })
            .unwrap_or_else(|| panic!("`{tool}.properties.line_weight` missing value shape"));
        let allowed_weights: BTreeSet<i64> = value_shape
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .and_then(|properties| properties.get("hundredths_mm"))
            .and_then(serde_json::Value::as_object)
            .and_then(|hundredths| hundredths.get("enum"))
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| {
                panic!("`{tool}.properties.line_weight.value` must enumerate standard values")
            })
            .iter()
            .map(|value| {
                value
                    .as_i64()
                    .unwrap_or_else(|| panic!("line_weight enum must contain integers"))
            })
            .collect();
        assert_eq!(
            allowed_weights,
            [
                0, 5, 9, 13, 15, 18, 20, 25, 30, 35, 40, 50, 53, 60, 70, 80, 90, 100, 106, 120,
                140, 158, 200, 211,
            ]
            .into_iter()
            .collect(),
            "`{tool}.properties.line_weight.value` standard values drifted"
        );
    }
}

#[test]
fn operations_skill_documents_path_platform_and_workflow_facts() {
    let text = read_repo_file("plugin/skills/autocad-mcp/SKILL.md");
    let rows = parse_tool_contract(&text);
    let write_notes = &rows
        .get("write_title_block")
        .expect("write row should exist")
        .notes;
    let plot_notes = &rows
        .get("plot_to_pdf")
        .expect("plot row should exist")
        .notes;

    assert_contains_all(
        &text,
        &[
            "Every `drawing_path` is an absolute local path.",
            "`plot_to_pdf.output` is an absolute local PDF path.",
            "Run `read_title_blocks` before `write_title_block`.",
            "Run `list_layers` before layer mutations.",
            "Run `list_layouts` before `plot_to_pdf`.",
            "Layer handles are preferred because layer names are mutable.",
            "`0` and `DEFPOINTS` are protected by name after identity resolution for rename",
            "Do not freeze the current layer.",
            "Do not delete layers with content\nor unverified references.",
            "Writable layer properties are\n`color_index`, `frozen`, `locked`, `off`, `is_plottable`, `line_type`, and\n`line_weight`.",
            "Recognized unsupported/read-only layer property keys fail with\n`code=unsupported_layer_property`; unknown property keys fail with\n`code=invalid_layer_property`.",
            "Xref-dependent `update_layer` allows host overrides for `color_index`, `frozen`,\n`locked`, `off`, `is_plottable`, and `line_weight`; DXF xref-dependent\n`line_type` updates are unsupported.",
            "Xref-dependent `rename_layer` and\n`delete_layer` remain rejected.",
            "`plot_to_pdf` accepts DWG input only.",
            "DXF plotting is unsupported in the MVP.",
            "Stage 5+ v1 release packages include `plugin/.lsp.json` and a platform-specific `autolisp-lsp` binary.",
            "Use `autolisp` for AutoLISP authoring.",
            "Repeated drafter-facing workflows that require manual AutoLISP or shell work are post-v1 tool candidates when they occur more than once or block release validation.",
        ],
    );

    assert!(
        write_notes.contains("Windows-only DWG write"),
        "write_title_block notes must mention Windows-only DWG write"
    );
    assert!(
        write_notes.contains("native-DXF write"),
        "write_title_block notes must mention native-DXF write support"
    );
    assert!(
        plot_notes.contains("Windows only"),
        "plot_to_pdf notes must mention Windows-only plotting"
    );
    assert!(
        plot_notes.contains("DWG only"),
        "plot_to_pdf notes must mention DWG-only input"
    );
}

#[test]
fn operations_skill_has_no_stale_stage_or_authoring_snippets() {
    let text = read_repo_file("plugin/skills/autocad-mcp/SKILL.md");
    for forbidden in [
        "current stage",
        "Stage 4 (current)",
        "Until a capability's stage lands",
        "defun c:",
        "load_dialog",
        "action_tile",
    ] {
        assert!(
            !text.contains(forbidden),
            "operations skill must not contain stale or authoring-only text: {forbidden}"
        );
    }
}

#[test]
fn skill_boundary_is_explicit_in_both_skills() {
    let operations = read_repo_file("plugin/skills/autocad-mcp/SKILL.md");
    let autolisp = read_repo_file("plugin/skills/autolisp/SKILL.md");

    assert_contains_all(
        &operations,
        &[
            "Use `autolisp` for AutoLISP authoring.",
            "Do not use this skill to write AutoLISP routines or DCL dialogs.",
        ],
    );
    assert_contains_all(
        &autolisp,
        &[
            "Use `autocad-mcp` for shipped read, write, and plot operations.",
            "Do not replace a shipped",
            "`autocad-mcp` operation with hand-written AutoLISP during normal drawing work.",
        ],
    );
}
