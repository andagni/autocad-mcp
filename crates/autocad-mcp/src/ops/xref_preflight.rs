//! Context-free XREF request validation retained as internal implementation
//! support.
//!
//! This module is deliberately not registered as an MCP tool: mutations remain
//! responsible for performing their own complete validation and admission.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::certification::XrefMutationOperation;

use super::{
    xref_attachment_mutation::{validate_attach_xref_context_free, validate_update_xref_step_two},
    xref_instance_mutation::{
        validate_insert_xref_instance_step_two, validate_update_xref_instance_step_two,
    },
    xref_mutation::XrefTransactionError,
    xref_path::validate_mutation_host_path_shape,
    xrefs::{
        xref_failure_code, AttachXrefRequest, BindXrefRequest, DeleteXrefInstanceRequest,
        DetachXrefRequest, InsertXrefInstanceRequest, ReloadXrefRequest, UnloadXrefRequest,
        UpdateXrefInstanceRequest, UpdateXrefRequest, XrefError,
    },
};

pub const XREF_PREFLIGHT_FAILURE_CODES: [&str; 14] = [
    xref_failure_code::DRAWING_UNREADABLE,
    xref_failure_code::EMPTY_XREF_UPDATE,
    xref_failure_code::INVALID_LAYER_RECONCILIATION,
    xref_failure_code::INVALID_PARAMETERS,
    xref_failure_code::INVALID_UNIT_ASSUMPTIONS,
    xref_failure_code::INVALID_XREF_NAME,
    xref_failure_code::INVALID_XREF_NORMAL,
    xref_failure_code::INVALID_XREF_OWNER,
    xref_failure_code::INVALID_XREF_PATH,
    xref_failure_code::INVALID_XREF_PLACEMENT,
    xref_failure_code::INVALID_XREF_PROPERTY,
    xref_failure_code::INVALID_XREF_SCALE,
    xref_failure_code::UNSUPPORTED_FORMAT,
    xref_failure_code::UNSUPPORTED_XREF_PROPERTY,
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "operation",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum XrefMutationPreflightRequest {
    AttachXref(AttachXrefRequest),
    BindXref(BindXrefRequest),
    DeleteXrefInstance(DeleteXrefInstanceRequest),
    DetachXref(DetachXrefRequest),
    InsertXrefInstance(InsertXrefInstanceRequest),
    ReloadXref(ReloadXrefRequest),
    UnloadXref(UnloadXrefRequest),
    UpdateXref(UpdateXrefRequest),
    UpdateXrefInstance(UpdateXrefInstanceRequest),
}

impl XrefMutationPreflightRequest {
    pub const fn operation(&self) -> XrefMutationOperation {
        match self {
            Self::AttachXref(_) => XrefMutationOperation::AttachXref,
            Self::BindXref(_) => XrefMutationOperation::BindXref,
            Self::DeleteXrefInstance(_) => XrefMutationOperation::DeleteXrefInstance,
            Self::DetachXref(_) => XrefMutationOperation::DetachXref,
            Self::InsertXrefInstance(_) => XrefMutationOperation::InsertXrefInstance,
            Self::ReloadXref(_) => XrefMutationOperation::ReloadXref,
            Self::UnloadXref(_) => XrefMutationOperation::UnloadXref,
            Self::UpdateXref(_) => XrefMutationOperation::UpdateXref,
            Self::UpdateXrefInstance(_) => XrefMutationOperation::UpdateXrefInstance,
        }
    }

    pub fn drawing_path(&self) -> &str {
        match self {
            Self::AttachXref(request) => &request.drawing_path,
            Self::BindXref(request) => &request.drawing_path,
            Self::DeleteXrefInstance(request) => &request.drawing_path,
            Self::DetachXref(request) => &request.drawing_path,
            Self::InsertXrefInstance(request) => &request.drawing_path,
            Self::ReloadXref(request) => &request.drawing_path,
            Self::UnloadXref(request) => &request.drawing_path,
            Self::UpdateXref(request) => &request.drawing_path,
            Self::UpdateXrefInstance(request) => &request.drawing_path,
        }
    }

    fn validate_context_free(&self) -> Result<(), XrefError> {
        match self {
            Self::AttachXref(request) => {
                validate_attach_xref_context_free(request).map_err(map_context_free_error)
            }
            Self::InsertXrefInstance(request) => {
                validate_insert_xref_instance_step_two(request).map_err(map_context_free_error)
            }
            Self::ReloadXref(request) => request
                .layer_reconciliation
                .clone()
                .map(|reconciliation| reconciliation.validate())
                .transpose()
                .map(|_| ()),
            Self::UpdateXref(request) => {
                validate_update_xref_step_two(request).map_err(map_context_free_error)
            }
            Self::UpdateXrefInstance(request) => {
                validate_update_xref_instance_step_two(request).map_err(map_context_free_error)
            }
            Self::BindXref(_)
            | Self::DeleteXrefInstance(_)
            | Self::DetachXref(_)
            | Self::UnloadXref(_) => Ok(()),
        }
    }

    const fn property_classification(&self) -> XrefPortableCheckState {
        match self {
            Self::UpdateXref(_) | Self::UpdateXrefInstance(_) => XrefPortableCheckState::Passed,
            _ => XrefPortableCheckState::NotApplicable,
        }
    }

    const fn ownership_check(&self) -> XrefCertifiedRuntimeCheckState {
        match self {
            Self::AttachXref(_)
            | Self::BindXref(_)
            | Self::DeleteXrefInstance(_)
            | Self::DetachXref(_)
            | Self::InsertXrefInstance(_)
            | Self::UpdateXrefInstance(_) => XrefCertifiedRuntimeCheckState::Required,
            Self::ReloadXref(_) | Self::UnloadXref(_) | Self::UpdateXref(_) => {
                XrefCertifiedRuntimeCheckState::NotApplicable
            }
        }
    }

    fn source_graph_check(&self) -> XrefCertifiedRuntimeCheckState {
        match self {
            Self::AttachXref(_) | Self::BindXref(_) | Self::ReloadXref(_) => {
                XrefCertifiedRuntimeCheckState::Required
            }
            Self::InsertXrefInstance(_) => XrefCertifiedRuntimeCheckState::ConditionallyRequired,
            Self::UpdateXref(request) if request.properties.contains_key("xref_path") => {
                XrefCertifiedRuntimeCheckState::Required
            }
            Self::DeleteXrefInstance(_)
            | Self::DetachXref(_)
            | Self::UnloadXref(_)
            | Self::UpdateXref(_)
            | Self::UpdateXrefInstance(_) => XrefCertifiedRuntimeCheckState::NotApplicable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefPreflightStatus {
    PortableChecksPassed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefPreflightScope {
    ContextFreeOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefPortableCheckState {
    Passed,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefCertifiedRuntime {
    CertifiedWindowsAutocad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefCertifiedRuntimeCheckState {
    Required,
    ConditionallyRequired,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefPortableChecks {
    pub closed_schema: XrefPortableCheckState,
    pub property_classification: XrefPortableCheckState,
    pub context_free_values: XrefPortableCheckState,
    pub path_shape: XrefPortableCheckState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefCertifiedRuntimeChecks {
    pub runtime: XrefCertifiedRuntime,
    pub drawing: XrefCertifiedRuntimeCheckState,
    pub attachment_identity: XrefCertifiedRuntimeCheckState,
    pub ownership: XrefCertifiedRuntimeCheckState,
    pub source_graph: XrefCertifiedRuntimeCheckState,
    pub preservation: XrefCertifiedRuntimeCheckState,
    pub commit: XrefCertifiedRuntimeCheckState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefMutationPreflightResponse {
    pub status: XrefPreflightStatus,
    pub operation: XrefMutationOperation,
    pub scope: XrefPreflightScope,
    pub portable_checks: XrefPortableChecks,
    pub certified_runtime_checks: XrefCertifiedRuntimeChecks,
}

pub fn preflight_xref_mutation(
    request: XrefMutationPreflightRequest,
) -> Result<XrefMutationPreflightResponse, XrefError> {
    request.validate_context_free()?;
    validate_mutation_host_path_shape(request.drawing_path())?;

    Ok(XrefMutationPreflightResponse {
        status: XrefPreflightStatus::PortableChecksPassed,
        operation: request.operation(),
        scope: XrefPreflightScope::ContextFreeOnly,
        portable_checks: XrefPortableChecks {
            closed_schema: XrefPortableCheckState::Passed,
            property_classification: request.property_classification(),
            context_free_values: XrefPortableCheckState::Passed,
            path_shape: XrefPortableCheckState::Passed,
        },
        certified_runtime_checks: XrefCertifiedRuntimeChecks {
            runtime: XrefCertifiedRuntime::CertifiedWindowsAutocad,
            drawing: XrefCertifiedRuntimeCheckState::Required,
            attachment_identity: XrefCertifiedRuntimeCheckState::Required,
            ownership: request.ownership_check(),
            source_graph: request.source_graph_check(),
            preservation: XrefCertifiedRuntimeCheckState::Required,
            commit: XrefCertifiedRuntimeCheckState::Required,
        },
    })
}

fn map_context_free_error(error: XrefTransactionError) -> XrefError {
    let code = match error.code.as_str() {
        xref_failure_code::DRAWING_UNREADABLE => xref_failure_code::DRAWING_UNREADABLE,
        xref_failure_code::EMPTY_XREF_UPDATE => xref_failure_code::EMPTY_XREF_UPDATE,
        xref_failure_code::INVALID_LAYER_RECONCILIATION => {
            xref_failure_code::INVALID_LAYER_RECONCILIATION
        }
        xref_failure_code::INVALID_PARAMETERS => xref_failure_code::INVALID_PARAMETERS,
        xref_failure_code::INVALID_UNIT_ASSUMPTIONS => xref_failure_code::INVALID_UNIT_ASSUMPTIONS,
        xref_failure_code::INVALID_XREF_NAME => xref_failure_code::INVALID_XREF_NAME,
        xref_failure_code::INVALID_XREF_NORMAL => xref_failure_code::INVALID_XREF_NORMAL,
        xref_failure_code::INVALID_XREF_OWNER => xref_failure_code::INVALID_XREF_OWNER,
        xref_failure_code::INVALID_XREF_PATH => xref_failure_code::INVALID_XREF_PATH,
        xref_failure_code::INVALID_XREF_PLACEMENT => xref_failure_code::INVALID_XREF_PLACEMENT,
        xref_failure_code::INVALID_XREF_PROPERTY => xref_failure_code::INVALID_XREF_PROPERTY,
        xref_failure_code::INVALID_XREF_SCALE => xref_failure_code::INVALID_XREF_SCALE,
        xref_failure_code::UNSUPPORTED_FORMAT => xref_failure_code::UNSUPPORTED_FORMAT,
        xref_failure_code::UNSUPPORTED_XREF_PROPERTY => {
            xref_failure_code::UNSUPPORTED_XREF_PROPERTY
        }
        _ => xref_failure_code::INVALID_PARAMETERS,
    };
    XrefError::new(code, error.detail)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::{json, Map, Value};

    use super::*;

    const HOST_PATH: &str = "/path/that/does/not/exist/host.dwg";

    fn tagged(operation: &str, request: Value) -> XrefMutationPreflightRequest {
        serde_json::from_value(json!({
            "operation": operation,
            "request": request,
        }))
        .unwrap()
    }

    fn minimal_requests() -> Vec<(
        XrefMutationOperation,
        XrefMutationPreflightRequest,
        XrefPortableCheckState,
        XrefCertifiedRuntimeCheckState,
        XrefCertifiedRuntimeCheckState,
    )> {
        vec![
            (
                XrefMutationOperation::AttachXref,
                tagged(
                    "attach_xref",
                    json!({
                        "drawing_path": HOST_PATH,
                        "xref_path": "source.dwg",
                        "reference_type": "overlay",
                    }),
                ),
                XrefPortableCheckState::NotApplicable,
                XrefCertifiedRuntimeCheckState::Required,
                XrefCertifiedRuntimeCheckState::Required,
            ),
            (
                XrefMutationOperation::BindXref,
                tagged(
                    "bind_xref",
                    json!({
                        "drawing_path": HOST_PATH,
                        "symbol_strategy": "prefix",
                        "dependency_strategy": "reject_nested",
                    }),
                ),
                XrefPortableCheckState::NotApplicable,
                XrefCertifiedRuntimeCheckState::Required,
                XrefCertifiedRuntimeCheckState::Required,
            ),
            (
                XrefMutationOperation::DeleteXrefInstance,
                tagged(
                    "delete_xref_instance",
                    json!({
                        "drawing_path": HOST_PATH,
                        "handle": "2A",
                    }),
                ),
                XrefPortableCheckState::NotApplicable,
                XrefCertifiedRuntimeCheckState::Required,
                XrefCertifiedRuntimeCheckState::NotApplicable,
            ),
            (
                XrefMutationOperation::DetachXref,
                tagged("detach_xref", json!({ "drawing_path": HOST_PATH })),
                XrefPortableCheckState::NotApplicable,
                XrefCertifiedRuntimeCheckState::Required,
                XrefCertifiedRuntimeCheckState::NotApplicable,
            ),
            (
                XrefMutationOperation::InsertXrefInstance,
                tagged("insert_xref_instance", json!({ "drawing_path": HOST_PATH })),
                XrefPortableCheckState::NotApplicable,
                XrefCertifiedRuntimeCheckState::Required,
                XrefCertifiedRuntimeCheckState::ConditionallyRequired,
            ),
            (
                XrefMutationOperation::ReloadXref,
                tagged("reload_xref", json!({ "drawing_path": HOST_PATH })),
                XrefPortableCheckState::NotApplicable,
                XrefCertifiedRuntimeCheckState::NotApplicable,
                XrefCertifiedRuntimeCheckState::Required,
            ),
            (
                XrefMutationOperation::UnloadXref,
                tagged("unload_xref", json!({ "drawing_path": HOST_PATH })),
                XrefPortableCheckState::NotApplicable,
                XrefCertifiedRuntimeCheckState::NotApplicable,
                XrefCertifiedRuntimeCheckState::NotApplicable,
            ),
            (
                XrefMutationOperation::UpdateXref,
                tagged(
                    "update_xref",
                    json!({
                        "drawing_path": HOST_PATH,
                        "properties": { "reference_type": "attachment" },
                    }),
                ),
                XrefPortableCheckState::Passed,
                XrefCertifiedRuntimeCheckState::NotApplicable,
                XrefCertifiedRuntimeCheckState::NotApplicable,
            ),
            (
                XrefMutationOperation::UpdateXrefInstance,
                tagged(
                    "update_xref_instance",
                    json!({
                        "drawing_path": HOST_PATH,
                        "handle": "2A",
                        "properties": { "visibility": "hidden" },
                    }),
                ),
                XrefPortableCheckState::Passed,
                XrefCertifiedRuntimeCheckState::Required,
                XrefCertifiedRuntimeCheckState::NotApplicable,
            ),
        ]
    }

    #[test]
    fn all_nine_operations_project_only_portable_and_deferred_checks() {
        for (operation, request, property_classification, ownership, source_graph) in
            minimal_requests()
        {
            let response = preflight_xref_mutation(request).unwrap();
            assert_eq!(response.status, XrefPreflightStatus::PortableChecksPassed);
            assert_eq!(response.operation, operation);
            assert_eq!(response.scope, XrefPreflightScope::ContextFreeOnly);
            assert_eq!(
                response.portable_checks,
                XrefPortableChecks {
                    closed_schema: XrefPortableCheckState::Passed,
                    property_classification,
                    context_free_values: XrefPortableCheckState::Passed,
                    path_shape: XrefPortableCheckState::Passed,
                }
            );
            assert_eq!(
                response.certified_runtime_checks,
                XrefCertifiedRuntimeChecks {
                    runtime: XrefCertifiedRuntime::CertifiedWindowsAutocad,
                    drawing: XrefCertifiedRuntimeCheckState::Required,
                    attachment_identity: XrefCertifiedRuntimeCheckState::Required,
                    ownership,
                    source_graph,
                    preservation: XrefCertifiedRuntimeCheckState::Required,
                    commit: XrefCertifiedRuntimeCheckState::Required,
                }
            );
        }
    }

    #[test]
    fn nonexistent_absolute_dwg_and_dxf_paths_pass_without_io() {
        for drawing_path in [
            "/definitely/not/present/host.dwg",
            "/definitely/not/present/host.DXF",
            r"C:\definitely\not\present\host.DWG",
            r"\\server\share\definitely-not-present\host.dxf",
            "/definitely/not/present/.dwg",
        ] {
            let request = tagged("detach_xref", json!({ "drawing_path": drawing_path }));
            assert!(preflight_xref_mutation(request).is_ok(), "{drawing_path}");
        }
    }

    #[test]
    fn malformed_runtime_handles_are_deliberately_deferred() {
        let requests = [
            tagged(
                "attach_xref",
                json!({
                    "drawing_path": HOST_PATH,
                    "xref_path": "source.dwg",
                    "reference_type": "attachment",
                    "placement": {
                        "owner_handle": "not-hex",
                        "layer_handle": "also-not-hex",
                    },
                }),
            ),
            tagged(
                "detach_xref",
                json!({
                    "drawing_path": HOST_PATH,
                    "handle": "not-hex",
                    "expected_handle": "still-not-hex",
                    "expected_instance_handles": ["not-hex-either"],
                }),
            ),
            tagged(
                "update_xref_instance",
                json!({
                    "drawing_path": HOST_PATH,
                    "handle": "not-hex",
                    "expected_attachment_handle": "not-hex",
                    "expected_owner_handle": "not-hex",
                    "properties": { "visibility": "visible" },
                }),
            ),
        ];

        for request in requests {
            assert!(preflight_xref_mutation(request).is_ok());
        }
    }

    #[test]
    fn context_free_failures_precede_host_path_shape_and_keep_exact_codes() {
        let cases = [
            (
                tagged(
                    "attach_xref",
                    json!({
                        "drawing_path": "relative.txt",
                        "xref_path": "source.txt",
                        "reference_type": "attachment",
                    }),
                ),
                xref_failure_code::INVALID_XREF_PATH,
            ),
            (
                tagged(
                    "attach_xref",
                    json!({
                        "drawing_path": "relative.txt",
                        "xref_path": "source.dwg",
                        "name": "bad|name",
                        "reference_type": "attachment",
                    }),
                ),
                xref_failure_code::INVALID_XREF_NAME,
            ),
            (
                tagged(
                    "attach_xref",
                    json!({
                        "drawing_path": "relative.txt",
                        "xref_path": "source.dwg",
                        "reference_type": "attachment",
                        "placement": { "scale": { "x": 0.0, "y": 1.0, "z": 1.0 } },
                    }),
                ),
                xref_failure_code::INVALID_XREF_SCALE,
            ),
            (
                tagged(
                    "attach_xref",
                    json!({
                        "drawing_path": "relative.txt",
                        "xref_path": "source.dwg",
                        "reference_type": "attachment",
                        "placement": { "owner_type": "model_space" },
                    }),
                ),
                xref_failure_code::INVALID_XREF_OWNER,
            ),
            (
                tagged(
                    "update_xref",
                    json!({
                        "drawing_path": "relative.txt",
                        "properties": {},
                    }),
                ),
                xref_failure_code::EMPTY_XREF_UPDATE,
            ),
            (
                tagged(
                    "update_xref",
                    json!({
                        "drawing_path": "relative.txt",
                        "properties": { "future_property": true },
                    }),
                ),
                xref_failure_code::INVALID_XREF_PROPERTY,
            ),
            (
                tagged(
                    "update_xref",
                    json!({
                        "drawing_path": "relative.txt",
                        "properties": { "load_state": "loaded" },
                    }),
                ),
                xref_failure_code::UNSUPPORTED_XREF_PROPERTY,
            ),
            (
                tagged(
                    "update_xref",
                    json!({
                        "drawing_path": "relative.txt",
                        "properties": { "reference_type": "overlay" },
                        "search_paths": ["/search"],
                    }),
                ),
                xref_failure_code::INVALID_PARAMETERS,
            ),
            (
                tagged(
                    "update_xref_instance",
                    json!({
                        "drawing_path": "relative.txt",
                        "handle": "not-checked",
                        "properties": { "normal": { "x": 0.0, "y": 0.0, "z": 0.0 } },
                    }),
                ),
                xref_failure_code::INVALID_XREF_NORMAL,
            ),
            (
                tagged(
                    "reload_xref",
                    json!({
                        "drawing_path": "relative.txt",
                        "layer_reconciliation": {
                            "mode": "synchronize",
                            "properties": [],
                        },
                    }),
                ),
                xref_failure_code::INVALID_LAYER_RECONCILIATION,
            ),
        ];

        for (request, expected_code) in cases {
            let error = preflight_xref_mutation(request).unwrap_err();
            assert_eq!(error.code(), expected_code);
        }
    }

    #[test]
    fn host_path_shape_has_stable_codes_and_messages() {
        let relative =
            preflight_xref_mutation(tagged("detach_xref", json!({ "drawing_path": "host.dwg" })))
                .unwrap_err();
        assert_eq!(relative.code(), xref_failure_code::DRAWING_UNREADABLE);
        assert_eq!(
            relative.to_string(),
            "code=drawing_unreadable drawing_path must be an absolute local filesystem path"
        );

        let format = preflight_xref_mutation(tagged(
            "detach_xref",
            json!({ "drawing_path": "/drawing/host.txt" }),
        ))
        .unwrap_err();
        assert_eq!(format.code(), xref_failure_code::UNSUPPORTED_FORMAT);
        assert_eq!(
            format.to_string(),
            "code=unsupported_format drawing_path must name a .dwg or .dxf file"
        );
    }

    #[test]
    fn xref_path_property_projects_a_required_source_graph_check() {
        let request = tagged(
            "update_xref",
            json!({
                "drawing_path": HOST_PATH,
                "properties": { "xref_path": "replacement.dwg" },
            }),
        );
        let response = preflight_xref_mutation(request).unwrap();
        assert_eq!(
            response.certified_runtime_checks.source_graph,
            XrefCertifiedRuntimeCheckState::Required
        );
    }

    fn schema_definitions(schema: &Value) -> &Map<String, Value> {
        schema
            .get("$defs")
            .and_then(Value::as_object)
            .expect("schema definitions")
    }

    #[test]
    fn request_schema_is_exactly_nine_closed_tagged_variants() {
        let schema =
            serde_json::to_value(schemars::schema_for!(XrefMutationPreflightRequest)).unwrap();
        let branches = schema
            .get("oneOf")
            .and_then(Value::as_array)
            .expect("tagged request oneOf");
        assert_eq!(branches.len(), 9);

        let operations = branches
            .iter()
            .map(|branch| {
                assert_eq!(
                    branch.get("additionalProperties"),
                    Some(&Value::Bool(false))
                );
                assert_eq!(
                    branch.get("required"),
                    Some(&json!(["operation", "request"]))
                );
                branch["properties"]["operation"]["const"]
                    .as_str()
                    .expect("operation const")
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            operations,
            BTreeSet::from([
                "attach_xref",
                "bind_xref",
                "delete_xref_instance",
                "detach_xref",
                "insert_xref_instance",
                "reload_xref",
                "unload_xref",
                "update_xref",
                "update_xref_instance",
            ])
        );

        let definitions = schema_definitions(&schema);
        for name in [
            "AttachXrefRequest",
            "BindXrefRequest",
            "DeleteXrefInstanceRequest",
            "DetachXrefRequest",
            "InsertXrefInstanceRequest",
            "ReloadXrefRequest",
            "UnloadXrefRequest",
            "UpdateXrefRequest",
            "UpdateXrefInstanceRequest",
        ] {
            assert_eq!(
                definitions[name].get("additionalProperties"),
                Some(&Value::Bool(false)),
                "{name}"
            );
        }
        assert_eq!(
            definitions["UpdateXrefRequest"]["properties"]["properties"]["additionalProperties"],
            Value::Bool(true)
        );
        assert_eq!(
            definitions["UpdateXrefInstanceRequest"]["properties"]["properties"]
                ["additionalProperties"],
            Value::Bool(true)
        );
    }

    #[test]
    fn request_deserialization_rejects_extra_wrapper_fields_and_unknown_operations() {
        for value in [
            json!({
                "operation": "detach_xref",
                "request": { "drawing_path": HOST_PATH },
                "extra": true,
            }),
            json!({
                "operation": "future_xref_operation",
                "request": { "drawing_path": HOST_PATH },
            }),
        ] {
            assert!(serde_json::from_value::<XrefMutationPreflightRequest>(value).is_err());
        }
    }

    #[test]
    fn response_and_check_schemas_are_closed() {
        let schema =
            serde_json::to_value(schemars::schema_for!(XrefMutationPreflightResponse)).unwrap();
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false))
        );
        let definitions = schema_definitions(&schema);
        for name in ["XrefPortableChecks", "XrefCertifiedRuntimeChecks"] {
            assert_eq!(
                definitions[name].get("additionalProperties"),
                Some(&Value::Bool(false)),
                "{name}"
            );
        }
    }

    fn key_set(value: &Value) -> BTreeSet<&str> {
        value
            .as_object()
            .expect("JSON object")
            .keys()
            .map(String::as_str)
            .collect()
    }

    #[test]
    fn response_is_closed_and_never_claims_runtime_validity_or_success() {
        let response = preflight_xref_mutation(tagged(
            "attach_xref",
            json!({
                "drawing_path": HOST_PATH,
                "xref_path": "source.dwg",
                "reference_type": "attachment",
            }),
        ))
        .unwrap();
        let mut value = serde_json::to_value(response).unwrap();

        assert_eq!(
            key_set(&value),
            BTreeSet::from([
                "certified_runtime_checks",
                "operation",
                "portable_checks",
                "scope",
                "status",
            ])
        );
        assert_eq!(
            key_set(&value["portable_checks"]),
            BTreeSet::from([
                "closed_schema",
                "context_free_values",
                "path_shape",
                "property_classification",
            ])
        );
        assert_eq!(
            key_set(&value["certified_runtime_checks"]),
            BTreeSet::from([
                "attachment_identity",
                "commit",
                "drawing",
                "ownership",
                "preservation",
                "runtime",
                "source_graph",
            ])
        );
        assert_eq!(value["status"], "portable_checks_passed");
        assert_eq!(value["scope"], "context_free_only");
        let serialized = serde_json::to_string(&value).unwrap();
        for forbidden in [
            "\"mutation_valid\"",
            "\"request_valid\"",
            "\"will_succeed\"",
            "\"mutation_succeeded\"",
            "\"canonicalized_request\"",
        ] {
            assert!(!serialized.contains(forbidden), "{forbidden}");
        }

        value
            .as_object_mut()
            .unwrap()
            .insert("will_succeed".to_string(), Value::Bool(true));
        assert!(serde_json::from_value::<XrefMutationPreflightResponse>(value).is_err());

        let mut nested = serde_json::to_value(
            preflight_xref_mutation(tagged("detach_xref", json!({ "drawing_path": HOST_PATH })))
                .unwrap(),
        )
        .unwrap();
        nested["portable_checks"]
            .as_object_mut()
            .unwrap()
            .insert("runtime_checked".to_string(), Value::Bool(true));
        assert!(serde_json::from_value::<XrefMutationPreflightResponse>(nested).is_err());
    }

    #[test]
    fn retained_failure_codes_are_exact_sorted_and_deduplicated() {
        assert_eq!(
            XREF_PREFLIGHT_FAILURE_CODES,
            [
                "drawing_unreadable",
                "empty_xref_update",
                "invalid_layer_reconciliation",
                "invalid_parameters",
                "invalid_unit_assumptions",
                "invalid_xref_name",
                "invalid_xref_normal",
                "invalid_xref_owner",
                "invalid_xref_path",
                "invalid_xref_placement",
                "invalid_xref_property",
                "invalid_xref_scale",
                "unsupported_format",
                "unsupported_xref_property",
            ]
        );
        assert!(XREF_PREFLIGHT_FAILURE_CODES
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
    }
}
