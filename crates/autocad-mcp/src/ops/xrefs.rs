use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use schemars::{JsonSchema, Schema};
use serde::{Deserialize, Serialize};

pub use crate::autocad_reader::contract::xrefs::{
    canonical_input_handle, compare_numeric_handles, xref_name_eq, InsertionUnit, LoadState,
    PersistedInsertionUnits, ReferenceType, XrefAttachmentRecord, XrefAttachmentSelector,
    XrefError, XrefInstanceRecord, XrefInstanceSelector, XrefNormal, XrefOwnerType, XrefPathMode,
    XrefPlacementKind, XrefPoint, XrefPoint3, XrefPointAvailability, XrefRectangularArray,
    XrefScale, XrefScale3, XrefSelector, XrefUnitBasis, XrefUnitScaling, XrefUnitValue,
    XrefVector3, XrefVisibility,
};
#[cfg(test)]
pub(crate) use crate::autocad_reader::contract::xrefs::{
    XrefDomainEvidence, XrefEvidenceValue, XrefMembershipEvidence,
};

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum XrefFact<T> {
    Proven(T),
    Unsupported(String),
}

#[cfg(test)]
impl<T> XrefFact<T> {
    pub(crate) fn proven(value: T) -> Self {
        Self::Proven(value)
    }

    pub(crate) fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported(message.into())
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum XrefMembership {
    NotXref,
    Xref(ReferenceType),
    Unsupported(String),
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XrefEvidence {
    pub(crate) handle: XrefFact<String>,
    pub(crate) name: XrefFact<String>,
    pub(crate) membership: XrefMembership,
    pub(crate) path: XrefFact<String>,
    pub(crate) load_state: LoadState,
}

#[cfg(test)]
impl<T: Clone> From<&XrefFact<T>> for XrefEvidenceValue<T> {
    fn from(value: &XrefFact<T>) -> Self {
        match value {
            XrefFact::Proven(value) => Self::Proven(value.clone()),
            XrefFact::Unsupported(reason) => Self::Unsupported(reason.clone()),
        }
    }
}

#[cfg(test)]
impl From<&XrefMembership> for XrefMembershipEvidence {
    fn from(value: &XrefMembership) -> Self {
        match value {
            XrefMembership::NotXref => Self::NotXref,
            XrefMembership::Xref(reference_type) => Self::Direct(*reference_type),
            XrefMembership::Unsupported(reason) => Self::Unsupported(reason.clone()),
        }
    }
}

#[cfg(test)]
impl From<&XrefEvidence> for XrefDomainEvidence {
    fn from(value: &XrefEvidence) -> Self {
        let load_state = match value.load_state {
            LoadState::Loaded | LoadState::Unloaded => XrefEvidenceValue::Proven(value.load_state),
            LoadState::Unavailable => {
                XrefEvidenceValue::Unavailable("legacy backend cannot prove load state".to_string())
            }
        };
        Self {
            handle: (&value.handle).into(),
            name: (&value.name).into(),
            membership: (&value.membership).into(),
            saved_path: (&value.path).into(),
            load_state,
            definition_base_point: XrefEvidenceValue::Unavailable(
                "legacy evidence does not contain definition base point".to_string(),
            ),
            insertion_units: XrefEvidenceValue::Unavailable(
                "legacy evidence does not contain insertion units".to_string(),
            ),
            instances: XrefEvidenceValue::Unavailable(
                "legacy evidence does not contain persisted instances".to_string(),
            ),
        }
    }
}

const ARBITRARY_AXIS_THRESHOLD: f64 = 1.0 / 64.0;

fn disallow_null_in_request_schema(schema: &mut Schema) {
    let single_type = match schema.get_mut("type") {
        Some(serde_json::Value::Array(types)) => {
            types.retain(|value| value.as_str() != Some("null"));
            (types.len() == 1).then(|| types[0].clone())
        }
        _ => None,
    };
    if let Some(single_type) = single_type {
        schema.insert("type".to_string(), single_type);
    }

    for keyword in ["anyOf", "oneOf"] {
        if let Some(serde_json::Value::Array(alternatives)) = schema.get_mut(keyword) {
            alternatives.retain(|alternative| {
                alternative.get("type").and_then(serde_json::Value::as_str) != Some("null")
            });
        }
    }
}

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn deserialize_optional_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefPropagationState {
    Root,
    Propagated,
    ExcludedOverlay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefResolutionState {
    Resolved,
    NotFound,
    Unresolved,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefResolutionBasis {
    SavedAbsolute,
    HostRelative,
    HostDirectory,
    ExplicitSearchPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefInspectionState {
    Inspected,
    TerminalOverlay,
    NotResolved,
    Unsupported,
    Cycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefTraversalLimitReason {
    MaxDepth,
    MaxNodes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LayerReconciliationMode {
    DrawingPolicy,
    PreserveHost,
    SourceAuthoritative,
    Synchronize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveLayerReconciliationMode {
    PreserveHost,
    SourceAuthoritative,
    Synchronize,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefLayerProperty {
    Off,
    Frozen,
    Locked,
    IsPlottable,
    ColorIndex,
    LineType,
    LineWeight,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefSymbolStrategy {
    Prefix,
    Merge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefDependencyStrategy {
    RejectNested,
    BindNested,
}

fn xref_symbol_strategy_request_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "enum": ["prefix", "merge"]
    })
}

fn xref_dependency_strategy_request_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "enum": ["reject_nested", "bind_nested"]
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefSymbolType {
    Block,
    Layer,
    Linetype,
    TextStyle,
    DimensionStyle,
    TableStyle,
    MultileaderStyle,
    Material,
    PlotStyle,
    VisualStyle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefSymbolResolution {
    Prefixed,
    Imported,
    HostDefinitionUsed,
    EarlierImportUsed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefTool {
    ListXrefs,
    GetXref,
    AttachXref,
    UpdateXref,
    DetachXref,
    ListXrefInstances,
    GetXrefInstance,
    InsertXrefInstance,
    UpdateXrefInstance,
    DeleteXrefInstance,
    ReloadXref,
    UnloadXref,
    BindXref,
    ResolveXrefPath,
    ListXrefDependencies,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct XrefUnitAssumptions {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "InsertionUnit")]
    pub source_units: Option<InsertionUnit>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "InsertionUnit")]
    pub host_units: Option<InsertionUnit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct XrefLayerReconciliation {
    pub mode: LayerReconciliationMode,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<XrefLayerProperty>")]
    pub properties: Option<Vec<XrefLayerProperty>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefLayerReconciliationEvidence {
    pub requested_mode: LayerReconciliationMode,
    pub effective_mode: EffectiveLayerReconciliationMode,
    pub synchronized_properties: Vec<XrefLayerProperty>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct XrefPlacement {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub owner_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "XrefOwnerType")]
    pub owner_type: Option<XrefOwnerType>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub owner_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub layer_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub layer_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "XrefPoint3")]
    pub insertion_point: Option<XrefPoint3>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "XrefScale3")]
    pub scale: Option<XrefScale3>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "f64")]
    pub rotation_degrees: Option<f64>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "XrefVector3")]
    pub normal: Option<XrefVector3>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "XrefVisibility")]
    pub visibility: Option<XrefVisibility>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct XrefInstancePlacement {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub owner_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "XrefOwnerType")]
    pub owner_type: Option<XrefOwnerType>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub owner_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub layer_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub layer_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "XrefPoint3")]
    pub insertion_point: Option<XrefPoint3>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "XrefScale3")]
    pub scale: Option<XrefScale3>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "f64")]
    pub rotation_degrees: Option<f64>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "XrefVector3")]
    pub normal: Option<XrefVector3>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "XrefVisibility")]
    pub visibility: Option<XrefVisibility>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "XrefRectangularArray")]
    pub array: Option<XrefRectangularArray>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefDependencyRecord {
    pub attachment_chain: Vec<String>,
    pub depth: u32,
    pub immediate_host_path: String,
    pub attachment: XrefAttachmentRecord,
    pub propagation_state: XrefPropagationState,
    pub resolution_state: XrefResolutionState,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schemars(required)]
    pub resolved_path: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schemars(required)]
    pub resolution_basis: Option<XrefResolutionBasis>,
    pub inspection_state: XrefInspectionState,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schemars(required)]
    pub cycle_target_chain: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefPathResolutionRecord {
    pub drawing: String,
    pub attachment_handle: String,
    pub saved_path: String,
    pub path_mode: XrefPathMode,
    pub resolution_state: XrefResolutionState,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schemars(required)]
    pub resolved_path: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schemars(required)]
    pub resolution_basis: Option<XrefResolutionBasis>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schemars(required)]
    pub search_path_index: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefTraversalTruncation {
    pub reason: XrefTraversalLimitReason,
    pub limit: u32,
    pub attachment_chain: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefDependencyTraversalEnvelope {
    pub drawing: String,
    pub within_limits: bool,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schemars(required)]
    pub truncation: Option<XrefTraversalTruncation>,
    pub dependencies: Vec<XrefDependencyRecord>,
}

pub type XrefPathResolution = XrefPathResolutionRecord;
pub type XrefDependencyTraversal = XrefDependencyTraversalEnvelope;

macro_rules! literal_status {
    ($name:ident, $variant:ident, $serialized:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        pub enum $name {
            #[serde(rename = $serialized)]
            $variant,
        }
    };
}

literal_status!(AttachXrefStatus, Attached, "attached");
literal_status!(UpdateXrefStatus, Updated, "updated");
literal_status!(DetachXrefStatus, Detached, "detached");
literal_status!(InsertXrefInstanceStatus, Inserted, "inserted");
literal_status!(UpdateXrefInstanceStatus, Updated, "updated");
literal_status!(DeleteXrefInstanceStatus, Deleted, "deleted");
literal_status!(ReloadXrefStatus, Loaded, "loaded");
literal_status!(UnloadXrefStatus, Unloaded, "unloaded");
literal_status!(BindXrefStatus, Bound, "bound");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachXrefResponse {
    pub status: AttachXrefStatus,
    pub drawing: String,
    pub attachment: XrefAttachmentRecord,
    pub instance: XrefInstanceRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateXrefResponse {
    pub status: UpdateXrefStatus,
    pub drawing: String,
    pub attachment: XrefAttachmentRecord,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub layer_reconciliation: Option<XrefLayerReconciliationEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetachXrefResponse {
    pub status: DetachXrefStatus,
    pub drawing: String,
    pub attachment: XrefAttachmentRecord,
    pub deleted_instance_handles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsertXrefInstanceResponse {
    pub status: InsertXrefInstanceStatus,
    pub drawing: String,
    pub instance: XrefInstanceRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateXrefInstanceResponse {
    pub status: UpdateXrefInstanceStatus,
    pub drawing: String,
    pub instance: XrefInstanceRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteXrefInstanceResponse {
    pub status: DeleteXrefInstanceStatus,
    pub drawing: String,
    pub instance: XrefInstanceRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReloadXrefResponse {
    pub status: ReloadXrefStatus,
    pub drawing: String,
    pub attachment: XrefAttachmentRecord,
    pub layer_reconciliation: XrefLayerReconciliationEvidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnloadXrefResponse {
    pub status: UnloadXrefStatus,
    pub drawing: String,
    pub attachment: XrefAttachmentRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefBoundBlock {
    pub handle: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefInstanceHandleMapping {
    pub attachment_chain: Vec<String>,
    pub old_handle: String,
    pub new_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefSymbolMapping {
    pub attachment_chain: Vec<String>,
    pub symbol_type: XrefSymbolType,
    pub source_handle: String,
    pub source_name: String,
    pub final_handle: String,
    pub final_name: String,
    pub resolution: XrefSymbolResolution,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefBoundDependency {
    pub attachment_chain: Vec<String>,
    pub attachment: XrefAttachmentRecord,
    pub block: XrefBoundBlock,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindXrefResponse {
    pub status: BindXrefStatus,
    pub drawing: String,
    pub symbol_strategy: XrefSymbolStrategy,
    pub dependency_strategy: XrefDependencyStrategy,
    pub attachment: XrefAttachmentRecord,
    pub block: XrefBoundBlock,
    pub instance_handle_mappings: Vec<XrefInstanceHandleMapping>,
    pub symbol_mappings: Vec<XrefSymbolMapping>,
    pub bound_dependencies: Vec<XrefBoundDependency>,
    pub excluded_overlay_dependencies: Vec<XrefDependencyRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct ListXrefsRequest {
    pub drawing_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct GetXrefRequest {
    pub drawing_path: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct AttachXrefRequest {
    pub drawing_path: String,
    pub xref_path: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<String>,
    pub reference_type: ReferenceType,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub search_paths: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub placement: Option<XrefPlacement>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub unit_assumptions: Option<XrefUnitAssumptions>,
}

pub type XrefPropertyMap = BTreeMap<String, serde_json::Value>;

#[derive(Debug)]
pub struct UpdateXrefPropertiesSchema;

impl JsonSchema for UpdateXrefPropertiesSchema {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("UpdateXrefProperties")
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "object",
            "additionalProperties": true,
            "properties": {
                "name": { "type": "string" },
                "xref_path": { "type": "string" },
                "reference_type": {
                    "type": "string",
                    "enum": ["attachment", "overlay"]
                }
            }
        })
    }
}

#[derive(Debug)]
pub struct UpdateXrefInstancePropertiesSchema;

impl JsonSchema for UpdateXrefInstancePropertiesSchema {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("UpdateXrefInstanceProperties")
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "object",
            "additionalProperties": true,
            "properties": {
                "insertion_point": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["x", "y", "z"],
                    "properties": {
                        "x": { "type": "number" },
                        "y": { "type": "number" },
                        "z": { "type": "number" }
                    }
                },
                "scale": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["x", "y", "z"],
                    "properties": {
                        "x": { "type": "number" },
                        "y": { "type": "number" },
                        "z": { "type": "number" }
                    }
                },
                "rotation_degrees": { "type": "number" },
                "normal": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["x", "y", "z"],
                    "properties": {
                        "x": { "type": "number" },
                        "y": { "type": "number" },
                        "z": { "type": "number" }
                    }
                },
                "layer_handle": { "type": "string" },
                "layer_name": { "type": "string" },
                "visibility": {
                    "type": "string",
                    "enum": ["visible", "hidden"]
                },
                "array": generator.subschema_for::<XrefRectangularArray>()
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct UpdateXrefRequest {
    pub drawing_path: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_name: Option<String>,
    #[schemars(with = "UpdateXrefPropertiesSchema")]
    pub properties: XrefPropertyMap,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub layer_reconciliation: Option<XrefLayerReconciliation>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub unit_assumptions: Option<XrefUnitAssumptions>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub search_paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct DetachXrefRequest {
    pub drawing_path: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_instance_count: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_instance_handles: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct ListXrefInstancesRequest {
    pub drawing_path: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub attachment_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub attachment_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_type: Option<XrefOwnerType>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub layer_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub layer_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub visibility: Option<XrefVisibility>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct GetXrefInstanceRequest {
    pub drawing_path: String,
    pub handle: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct InsertXrefInstanceRequest {
    pub drawing_path: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub attachment_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub attachment_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_attachment_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub placement: Option<XrefInstancePlacement>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub unit_assumptions: Option<XrefUnitAssumptions>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct UpdateXrefInstanceRequest {
    pub drawing_path: String,
    pub handle: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_attachment_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_owner_handle: Option<String>,
    #[schemars(with = "UpdateXrefInstancePropertiesSchema")]
    pub properties: XrefPropertyMap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct DeleteXrefInstanceRequest {
    pub drawing_path: String,
    pub handle: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_attachment_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_owner_handle: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct UnloadXrefRequest {
    pub drawing_path: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct ReloadXrefRequest {
    pub drawing_path: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub search_paths: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub layer_reconciliation: Option<XrefLayerReconciliation>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub unit_assumptions: Option<XrefUnitAssumptions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct ResolveXrefPathRequest {
    pub drawing_path: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub search_paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct ListXrefDependenciesRequest {
    pub drawing_path: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub search_paths: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_depth: Option<u32>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_nodes: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schemars::transform::RecursiveTransform(disallow_null_in_request_schema))]
pub struct BindXrefRequest {
    pub drawing_path: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_handle: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_instance_count: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_instance_handles: Option<Vec<String>>,
    #[schemars(schema_with = "xref_symbol_strategy_request_schema")]
    pub symbol_strategy: XrefSymbolStrategy,
    #[schemars(schema_with = "xref_dependency_strategy_request_schema")]
    pub dependency_strategy: XrefDependencyStrategy,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub search_paths: Option<Vec<String>>,
}

// Temporary compatibility shape for the current narrow xref_io/server readers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegacyXrefRecord {
    pub handle: String,
    pub name: String,
    pub path: String,
    pub reference_type: ReferenceType,
    pub load_state: LoadState,
}

pub type XrefRecord = LegacyXrefRecord;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefAttachmentGuards {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub expected_handle: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub expected_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefDestructiveAttachmentGuards {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub expected_handle: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub expected_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub expected_instance_count: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub expected_instance_handles: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefInstanceGuards {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub expected_attachment_handle: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub expected_owner_handle: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct XrefOcsBasis {
    pub x_axis: XrefVector3,
    pub y_axis: XrefVector3,
    pub normal: XrefVector3,
}

impl XrefLayerReconciliation {
    pub fn validate(self) -> Result<Self, XrefError> {
        let properties = self.properties.as_deref().unwrap_or_default();
        let has_duplicates =
            properties.iter().copied().collect::<BTreeSet<_>>().len() != properties.len();
        let valid_shape = match self.mode {
            LayerReconciliationMode::Synchronize => !properties.is_empty(),
            _ => properties.is_empty(),
        };
        if has_duplicates || !valid_shape {
            return Err(XrefError::new(
                xref_failure_code::INVALID_LAYER_RECONCILIATION,
                "XREF layer reconciliation properties do not match the selected mode",
            ));
        }
        Ok(self)
    }
}

fn validate_owner_selector_shape(
    owner_handle: &Option<String>,
    owner_type: Option<XrefOwnerType>,
    owner_name: &Option<String>,
) -> Result<(), XrefError> {
    if matches!(
        (
            owner_handle.is_some(),
            owner_type.is_some(),
            owner_name.is_some()
        ),
        (false, false, false) | (true, false, false) | (false, true, true) | (true, true, true)
    ) {
        Ok(())
    } else {
        Err(XrefError::new(
            xref_failure_code::INVALID_XREF_OWNER,
            "owner selection must use {}, {owner_handle}, {owner_type,owner_name}, or all three",
        ))
    }
}

fn canonicalize_optional_handle(handle: &mut Option<String>) -> Result<(), XrefError> {
    if let Some(value) = handle {
        *value = canonical_input_handle(value)?;
    }
    Ok(())
}

impl XrefPlacement {
    pub fn canonicalized(mut self) -> Result<Self, XrefError> {
        validate_owner_selector_shape(&self.owner_handle, self.owner_type, &self.owner_name)?;
        canonicalize_optional_handle(&mut self.owner_handle)?;
        canonicalize_optional_handle(&mut self.layer_handle)?;
        if let Some(point) = self.insertion_point {
            self.insertion_point = Some(point.validate()?);
        }
        if let Some(scale) = self.scale {
            self.scale = Some(scale.validate()?);
        }
        if let Some(rotation) = self.rotation_degrees {
            self.rotation_degrees = Some(normalize_rotation_degrees(rotation)?);
        }
        if let Some(normal) = self.normal {
            self.normal = Some(normal.canonical_normal()?);
        }
        Ok(self)
    }
}

impl XrefInstancePlacement {
    pub fn canonicalized(mut self) -> Result<Self, XrefError> {
        let common = XrefPlacement {
            owner_handle: self.owner_handle,
            owner_type: self.owner_type,
            owner_name: self.owner_name,
            layer_handle: self.layer_handle,
            layer_name: self.layer_name,
            insertion_point: self.insertion_point,
            scale: self.scale,
            rotation_degrees: self.rotation_degrees,
            normal: self.normal,
            visibility: self.visibility,
        }
        .canonicalized()?;
        self.owner_handle = common.owner_handle;
        self.owner_type = common.owner_type;
        self.owner_name = common.owner_name;
        self.layer_handle = common.layer_handle;
        self.layer_name = common.layer_name;
        self.insertion_point = common.insertion_point;
        self.scale = common.scale;
        self.rotation_degrees = common.rotation_degrees;
        self.normal = common.normal;
        self.visibility = common.visibility;
        if let Some(array) = self.array {
            self.array = Some(array.validate()?);
        }
        Ok(self)
    }
}

impl XrefAttachmentGuards {
    pub fn canonicalized(mut self) -> Result<Self, XrefError> {
        canonicalize_optional_handle(&mut self.expected_handle)?;
        Ok(self)
    }
}

impl XrefDestructiveAttachmentGuards {
    pub fn canonicalized(mut self) -> Result<Self, XrefError> {
        canonicalize_optional_handle(&mut self.expected_handle)?;
        if let Some(handles) = &self.expected_instance_handles {
            self.expected_instance_handles = Some(canonicalize_unique_handle_set(handles)?);
        }
        Ok(self)
    }
}

impl XrefInstanceGuards {
    pub fn canonicalized(mut self) -> Result<Self, XrefError> {
        canonicalize_optional_handle(&mut self.expected_attachment_handle)?;
        canonicalize_optional_handle(&mut self.expected_owner_handle)?;
        Ok(self)
    }
}

pub fn validate_xref_name(name: &str) -> Result<(), XrefError> {
    const FORBIDDEN: &[char] = &[
        '<', '>', '/', '\\', '"', ':', ';', '?', '*', '|', ',', '=', '`',
    ];

    if name.is_empty()
        || name.trim() != name
        || name.chars().count() > 255
        || name
            .chars()
            .any(|character| character.is_ascii_control() || FORBIDDEN.contains(&character))
    {
        return Err(XrefError::new(
            xref_failure_code::INVALID_XREF_NAME,
            "XREF name violates the closed name contract",
        ));
    }
    Ok(())
}

pub fn normalize_rotation_degrees(rotation_degrees: f64) -> Result<f64, XrefError> {
    if !rotation_degrees.is_finite() {
        return Err(XrefError::new(
            xref_failure_code::INVALID_XREF_PLACEMENT,
            "XREF rotation must be finite",
        ));
    }

    let normalized = rotation_degrees.rem_euclid(360.0);
    Ok(if normalized == 0.0 { 0.0 } else { normalized })
}

pub fn xref_ocs_basis(normal: XrefVector3) -> Result<XrefOcsBasis, XrefError> {
    let normal = normal.canonical_normal()?;
    let seed =
        if normal.x.abs() < ARBITRARY_AXIS_THRESHOLD && normal.y.abs() < ARBITRARY_AXIS_THRESHOLD {
            XrefVector3 {
                x: 0.0,
                y: 1.0,
                z: 0.0,
            }
        } else {
            XrefVector3::WORLD_Z
        };
    let x_axis = seed.cross(normal).normalized().zero_tiny_components();
    let y_axis = normal.cross(x_axis).normalized().zero_tiny_components();

    Ok(XrefOcsBasis {
        x_axis,
        y_axis,
        normal,
    })
}

pub fn transform_xref_point(
    source_point: XrefPoint3,
    definition_base_point: XrefPoint3,
    insertion_point: XrefPoint3,
    effective_scale: XrefScale3,
    rotation_degrees: f64,
    normal: XrefVector3,
) -> Result<XrefPoint3, XrefError> {
    source_point.validate()?;
    definition_base_point.validate()?;
    insertion_point.validate()?;
    effective_scale.validate()?;
    let rotation = normalize_rotation_degrees(rotation_degrees)?.to_radians();
    let basis = xref_ocs_basis(normal)?;

    let local_x = (source_point.x - definition_base_point.x) * effective_scale.x;
    let local_y = (source_point.y - definition_base_point.y) * effective_scale.y;
    let local_z = (source_point.z - definition_base_point.z) * effective_scale.z;
    let (sin_rotation, cos_rotation) = rotation.sin_cos();
    let rotated_x = local_x * cos_rotation - local_y * sin_rotation;
    let rotated_y = local_x * sin_rotation + local_y * cos_rotation;

    Ok(XrefPoint3 {
        x: insertion_point.x
            + basis.x_axis.x * rotated_x
            + basis.y_axis.x * rotated_y
            + basis.normal.x * local_z,
        y: insertion_point.y
            + basis.x_axis.y * rotated_x
            + basis.y_axis.y * rotated_y
            + basis.normal.y * local_z,
        z: insertion_point.z
            + basis.x_axis.z * rotated_x
            + basis.y_axis.z * rotated_y
            + basis.normal.z * local_z,
    })
}

pub fn xref_array_cell_insertion_point(
    insertion_point: XrefPoint3,
    array: XrefRectangularArray,
    row: u32,
    column: u32,
    rotation_degrees: f64,
    normal: XrefVector3,
) -> Result<XrefPoint3, XrefError> {
    insertion_point.validate()?;
    let array = array.validate()?;
    if row >= array.rows || column >= array.columns {
        return Err(XrefError::new(
            xref_failure_code::INVALID_XREF_PLACEMENT,
            "XREF array cell index is outside the persisted array",
        ));
    }
    let rotation = normalize_rotation_degrees(rotation_degrees)?.to_radians();
    let basis = xref_ocs_basis(normal)?;
    let local_x = f64::from(column) * array.column_spacing;
    let local_y = f64::from(row) * array.row_spacing;
    let (sin_rotation, cos_rotation) = rotation.sin_cos();
    let rotated_x = local_x * cos_rotation - local_y * sin_rotation;
    let rotated_y = local_x * sin_rotation + local_y * cos_rotation;

    Ok(XrefPoint3 {
        x: insertion_point.x + basis.x_axis.x * rotated_x + basis.y_axis.x * rotated_y,
        y: insertion_point.y + basis.x_axis.y * rotated_x + basis.y_axis.y * rotated_y,
        z: insertion_point.z + basis.x_axis.z * rotated_x + basis.y_axis.z * rotated_y,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefPropertyClassification {
    Writable,
    Unsupported,
    Unknown,
}

pub const ATTACHMENT_WRITABLE_PROPERTIES: &[&str] = &["name", "xref_path", "reference_type"];

pub const ATTACHMENT_UNSUPPORTED_PROPERTIES: &[&str] = &[
    "handle",
    "saved_path",
    "path_mode",
    "load_state",
    "instance_count",
    "definition_base_point",
    "attachment_handle",
    "attachment_name",
    "owner_handle",
    "owner_type",
    "owner_name",
    "layer_handle",
    "layer_name",
    "insertion_point",
    "scale",
    "rotation_degrees",
    "normal",
    "visibility",
    "placement_kind",
    "array",
    "unit_scaling",
    "search_paths",
    "layer_reconciliation",
    "unit_assumptions",
    "symbol_strategy",
    "dependency_strategy",
];

pub const INSTANCE_WRITABLE_PROPERTIES: &[&str] = &[
    "insertion_point",
    "scale",
    "rotation_degrees",
    "normal",
    "layer_handle",
    "layer_name",
    "visibility",
    "array",
];

pub const INSTANCE_UNSUPPORTED_PROPERTIES: &[&str] = &[
    "handle",
    "attachment_handle",
    "attachment_name",
    "owner_handle",
    "owner_type",
    "owner_name",
    "placement_kind",
    "unit_scaling",
    "saved_path",
    "path_mode",
    "reference_type",
    "load_state",
    "instance_count",
    "definition_base_point",
    "color_index",
    "true_color",
    "color_book",
    "color_name",
    "line_type",
    "line_weight",
    "material_handle",
    "plotstyle_handle",
    "transparency",
    "clip",
    "clip_handle",
];

fn classify_property(
    key: &str,
    writable: &[&str],
    unsupported: &[&str],
) -> XrefPropertyClassification {
    if writable.contains(&key) {
        XrefPropertyClassification::Writable
    } else if unsupported.contains(&key) {
        XrefPropertyClassification::Unsupported
    } else {
        XrefPropertyClassification::Unknown
    }
}

pub fn classify_attachment_update_property(key: &str) -> XrefPropertyClassification {
    classify_property(
        key,
        ATTACHMENT_WRITABLE_PROPERTIES,
        ATTACHMENT_UNSUPPORTED_PROPERTIES,
    )
}

pub fn classify_instance_update_property(key: &str) -> XrefPropertyClassification {
    classify_property(
        key,
        INSTANCE_WRITABLE_PROPERTIES,
        INSTANCE_UNSUPPORTED_PROPERTIES,
    )
}

pub mod xref_failure_code {
    pub const INVALID_PARAMETERS: &str = "invalid_parameters";
    pub const DRAWING_NOT_FOUND: &str = "drawing_not_found";
    pub const DRAWING_UNREADABLE: &str = "drawing_unreadable";
    pub const UNSUPPORTED_FORMAT: &str = "unsupported_format";
    pub const UNSUPPORTED_XREF_DATA: &str = "unsupported_xref_data";
    pub const UNSUPPORTED_PLATFORM: &str = "unsupported_platform";
    pub const AUTOCAD_UNAVAILABLE: &str = "autocad_unavailable";
    pub const DRAWING_LOCKED: &str = "drawing_locked";
    pub const CONCURRENT_DRAWING_MODIFICATION: &str = "concurrent_drawing_modification";
    pub const XREF_SOURCE_CHANGED: &str = "xref_source_changed";
    pub const WRITE_FAILED: &str = "write_failed";
    pub const VERIFICATION_FAILED: &str = "verification_failed";
    pub const MUTATION_STATE_UNKNOWN: &str = "mutation_state_unknown";
    pub const MISSING_IDENTITY: &str = "missing_identity";
    pub const INVALID_HANDLE: &str = "invalid_handle";
    pub const XREF_NOT_FOUND: &str = "xref_not_found";
    pub const XREF_INSTANCE_NOT_FOUND: &str = "xref_instance_not_found";
    pub const AMBIGUOUS_IDENTITY: &str = "ambiguous_identity";
    pub const CONTRADICTORY_IDENTITY: &str = "contradictory_identity";
    pub const EXPECTED_HANDLE_MISMATCH: &str = "expected_handle_mismatch";
    pub const EXPECTED_NAME_MISMATCH: &str = "expected_name_mismatch";
    pub const EXPECTED_INSTANCE_COUNT_MISMATCH: &str = "expected_instance_count_mismatch";
    pub const EXPECTED_INSTANCE_HANDLES_MISMATCH: &str = "expected_instance_handles_mismatch";
    pub const EXPECTED_ATTACHMENT_HANDLE_MISMATCH: &str = "expected_attachment_handle_mismatch";
    pub const EXPECTED_OWNER_HANDLE_MISMATCH: &str = "expected_owner_handle_mismatch";
    pub const INVALID_XREF_NAME: &str = "invalid_xref_name";
    pub const XREF_NAME_COLLISION: &str = "xref_name_collision";
    pub const INVALID_XREF_PATH: &str = "invalid_xref_path";
    pub const INVALID_SEARCH_PATH: &str = "invalid_search_path";
    pub const XREF_SOURCE_NOT_FOUND: &str = "xref_source_not_found";
    pub const XREF_SOURCE_UNREADABLE: &str = "xref_source_unreadable";
    pub const UNSUPPORTED_XREF_SOURCE: &str = "unsupported_xref_source";
    pub const CIRCULAR_XREF: &str = "circular_xref";
    pub const AMBIGUOUS_INSERTION_UNITS: &str = "ambiguous_insertion_units";
    pub const INVALID_UNIT_ASSUMPTIONS: &str = "invalid_unit_assumptions";
    pub const UNSUPPORTED_INSERTION_UNITS: &str = "unsupported_insertion_units";
    pub const INVALID_XREF_PROPERTY: &str = "invalid_xref_property";
    pub const UNSUPPORTED_XREF_PROPERTY: &str = "unsupported_xref_property";
    pub const EMPTY_XREF_UPDATE: &str = "empty_xref_update";
    pub const INVALID_LAYER_RECONCILIATION: &str = "invalid_layer_reconciliation";
    pub const INVALID_XREF_PLACEMENT: &str = "invalid_xref_placement";
    pub const INVALID_XREF_SCALE: &str = "invalid_xref_scale";
    pub const INVALID_XREF_NORMAL: &str = "invalid_xref_normal";
    pub const INVALID_XREF_OWNER: &str = "invalid_xref_owner";
    pub const XREF_OWNER_NOT_FOUND: &str = "xref_owner_not_found";
    pub const UNSUPPORTED_XREF_OWNER: &str = "unsupported_xref_owner";
    pub const LAYER_NOT_FOUND: &str = "layer_not_found";
    pub const LAYER_NOT_HOST_OWNED: &str = "layer_not_host_owned";
    pub const XREF_INSTANCE_LOCKED: &str = "xref_instance_locked";
    pub const RECURSIVE_BLOCK_REFERENCE: &str = "recursive_block_reference";
    pub const UNSUPPORTED_XREF_CLIP_DATA: &str = "unsupported_xref_clip_data";
    pub const NESTED_XREFS_PRESENT: &str = "nested_xrefs_present";
    pub const DEPENDENCY_TRAVERSAL_INCOMPLETE: &str = "dependency_traversal_incomplete";
    pub const UNSUPPORTED_XREF_CONTENT: &str = "unsupported_xref_content";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefFailureGroup {
    Read,
    Mutation,
    AttachmentIdentity,
    InstanceIdentity,
    AttachmentGuards,
    DestructiveGuards,
    InstanceGuards,
    SourceGraph,
    SourceRead,
    Units,
    OwnerPlacement,
    Properties,
}

const FAILURE_READ: &[&str] = &[
    xref_failure_code::INVALID_PARAMETERS,
    xref_failure_code::DRAWING_NOT_FOUND,
    xref_failure_code::DRAWING_UNREADABLE,
    xref_failure_code::UNSUPPORTED_FORMAT,
    xref_failure_code::UNSUPPORTED_XREF_DATA,
];
const FAILURE_MUTATION_ADDITIONAL: &[&str] = &[
    xref_failure_code::UNSUPPORTED_PLATFORM,
    xref_failure_code::AUTOCAD_UNAVAILABLE,
    xref_failure_code::DRAWING_LOCKED,
    xref_failure_code::CONCURRENT_DRAWING_MODIFICATION,
    xref_failure_code::WRITE_FAILED,
    xref_failure_code::VERIFICATION_FAILED,
    xref_failure_code::MUTATION_STATE_UNKNOWN,
];
const FAILURE_ATTACHMENT_IDENTITY: &[&str] = &[
    xref_failure_code::MISSING_IDENTITY,
    xref_failure_code::INVALID_HANDLE,
    xref_failure_code::XREF_NOT_FOUND,
    xref_failure_code::AMBIGUOUS_IDENTITY,
    xref_failure_code::CONTRADICTORY_IDENTITY,
];
const FAILURE_INSTANCE_IDENTITY: &[&str] = &[
    xref_failure_code::INVALID_HANDLE,
    xref_failure_code::XREF_INSTANCE_NOT_FOUND,
];
const FAILURE_ATTACHMENT_GUARDS: &[&str] = &[
    xref_failure_code::EXPECTED_HANDLE_MISMATCH,
    xref_failure_code::EXPECTED_NAME_MISMATCH,
];
const FAILURE_DESTRUCTIVE_GUARDS: &[&str] = &[
    xref_failure_code::EXPECTED_INSTANCE_COUNT_MISMATCH,
    xref_failure_code::EXPECTED_INSTANCE_HANDLES_MISMATCH,
];
const FAILURE_INSTANCE_GUARDS: &[&str] = &[
    xref_failure_code::EXPECTED_ATTACHMENT_HANDLE_MISMATCH,
    xref_failure_code::EXPECTED_OWNER_HANDLE_MISMATCH,
];
const FAILURE_SOURCE_GRAPH: &[&str] = &[
    xref_failure_code::XREF_SOURCE_NOT_FOUND,
    xref_failure_code::XREF_SOURCE_UNREADABLE,
    xref_failure_code::UNSUPPORTED_XREF_SOURCE,
    xref_failure_code::CIRCULAR_XREF,
    xref_failure_code::XREF_SOURCE_CHANGED,
    xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE,
];
const FAILURE_SOURCE_READ: &[&str] = &[
    xref_failure_code::XREF_SOURCE_NOT_FOUND,
    xref_failure_code::XREF_SOURCE_UNREADABLE,
    xref_failure_code::UNSUPPORTED_XREF_SOURCE,
    xref_failure_code::XREF_SOURCE_CHANGED,
];
const FAILURE_UNITS: &[&str] = &[
    xref_failure_code::AMBIGUOUS_INSERTION_UNITS,
    xref_failure_code::INVALID_UNIT_ASSUMPTIONS,
    xref_failure_code::UNSUPPORTED_INSERTION_UNITS,
];
const FAILURE_OWNER_PLACEMENT: &[&str] = &[
    xref_failure_code::INVALID_HANDLE,
    xref_failure_code::CONTRADICTORY_IDENTITY,
    xref_failure_code::INVALID_XREF_PLACEMENT,
    xref_failure_code::INVALID_XREF_SCALE,
    xref_failure_code::INVALID_XREF_NORMAL,
    xref_failure_code::INVALID_XREF_OWNER,
    xref_failure_code::XREF_OWNER_NOT_FOUND,
    xref_failure_code::UNSUPPORTED_XREF_OWNER,
    xref_failure_code::LAYER_NOT_FOUND,
    xref_failure_code::LAYER_NOT_HOST_OWNED,
    xref_failure_code::RECURSIVE_BLOCK_REFERENCE,
];
const FAILURE_PROPERTIES: &[&str] = &[
    xref_failure_code::INVALID_XREF_PROPERTY,
    xref_failure_code::UNSUPPORTED_XREF_PROPERTY,
    xref_failure_code::EMPTY_XREF_UPDATE,
];

fn extend_failure_group(set: &mut BTreeSet<&'static str>, group: XrefFailureGroup) {
    if group == XrefFailureGroup::Mutation {
        set.extend(FAILURE_READ.iter().copied());
        set.extend(FAILURE_MUTATION_ADDITIONAL.iter().copied());
        return;
    }

    let members = match group {
        XrefFailureGroup::Read => FAILURE_READ,
        XrefFailureGroup::Mutation => unreachable!("handled above"),
        XrefFailureGroup::AttachmentIdentity => FAILURE_ATTACHMENT_IDENTITY,
        XrefFailureGroup::InstanceIdentity => FAILURE_INSTANCE_IDENTITY,
        XrefFailureGroup::AttachmentGuards => FAILURE_ATTACHMENT_GUARDS,
        XrefFailureGroup::DestructiveGuards => FAILURE_DESTRUCTIVE_GUARDS,
        XrefFailureGroup::InstanceGuards => FAILURE_INSTANCE_GUARDS,
        XrefFailureGroup::SourceGraph => FAILURE_SOURCE_GRAPH,
        XrefFailureGroup::SourceRead => FAILURE_SOURCE_READ,
        XrefFailureGroup::Units => FAILURE_UNITS,
        XrefFailureGroup::OwnerPlacement => FAILURE_OWNER_PLACEMENT,
        XrefFailureGroup::Properties => FAILURE_PROPERTIES,
    };
    set.extend(members.iter().copied());
}

pub fn xref_shared_failure_codes(group: XrefFailureGroup) -> Vec<&'static str> {
    let mut set = BTreeSet::new();
    extend_failure_group(&mut set, group);
    set.into_iter().collect()
}

pub fn xref_failure_codes(tool: XrefTool) -> Vec<&'static str> {
    use xref_failure_code as code;
    use XrefFailureGroup as Group;

    let (groups, additional): (&[Group], &[&'static str]) = match tool {
        XrefTool::ListXrefs => (&[Group::Read], &[]),
        XrefTool::GetXref => (&[Group::Read, Group::AttachmentIdentity], &[]),
        XrefTool::ListXrefInstances => (
            &[Group::Read, Group::AttachmentIdentity],
            &[
                code::INVALID_XREF_OWNER,
                code::XREF_OWNER_NOT_FOUND,
                code::LAYER_NOT_FOUND,
            ],
        ),
        XrefTool::GetXrefInstance => (&[Group::Read, Group::InstanceIdentity], &[]),
        XrefTool::ResolveXrefPath | XrefTool::ListXrefDependencies => (
            &[Group::Read, Group::AttachmentIdentity],
            &[code::INVALID_SEARCH_PATH],
        ),
        XrefTool::AttachXref => (
            &[
                Group::Mutation,
                Group::OwnerPlacement,
                Group::SourceGraph,
                Group::Units,
            ],
            &[
                code::INVALID_XREF_NAME,
                code::XREF_NAME_COLLISION,
                code::INVALID_XREF_PATH,
                code::INVALID_SEARCH_PATH,
            ],
        ),
        XrefTool::UpdateXref => (
            &[
                Group::Mutation,
                Group::AttachmentIdentity,
                Group::AttachmentGuards,
                Group::Properties,
                Group::SourceGraph,
                Group::Units,
            ],
            &[
                code::INVALID_XREF_NAME,
                code::XREF_NAME_COLLISION,
                code::INVALID_XREF_PATH,
                code::INVALID_SEARCH_PATH,
                code::INVALID_LAYER_RECONCILIATION,
                code::UNSUPPORTED_XREF_CLIP_DATA,
            ],
        ),
        XrefTool::DetachXref => (
            &[
                Group::Mutation,
                Group::AttachmentIdentity,
                Group::AttachmentGuards,
                Group::DestructiveGuards,
            ],
            &[
                code::UNSUPPORTED_XREF_OWNER,
                code::XREF_INSTANCE_LOCKED,
                code::UNSUPPORTED_XREF_CLIP_DATA,
            ],
        ),
        XrefTool::InsertXrefInstance => (
            &[
                Group::Mutation,
                Group::AttachmentIdentity,
                Group::OwnerPlacement,
                Group::SourceRead,
                Group::Units,
            ],
            &[code::EXPECTED_ATTACHMENT_HANDLE_MISMATCH],
        ),
        XrefTool::UpdateXrefInstance => (
            &[
                Group::Mutation,
                Group::InstanceIdentity,
                Group::InstanceGuards,
                Group::Properties,
            ],
            &[
                code::CONTRADICTORY_IDENTITY,
                code::INVALID_XREF_PLACEMENT,
                code::INVALID_XREF_SCALE,
                code::INVALID_XREF_NORMAL,
                code::UNSUPPORTED_XREF_OWNER,
                code::LAYER_NOT_FOUND,
                code::LAYER_NOT_HOST_OWNED,
                code::XREF_INSTANCE_LOCKED,
                code::UNSUPPORTED_XREF_CLIP_DATA,
            ],
        ),
        XrefTool::DeleteXrefInstance => (
            &[
                Group::Mutation,
                Group::InstanceIdentity,
                Group::InstanceGuards,
            ],
            &[
                code::UNSUPPORTED_XREF_OWNER,
                code::XREF_INSTANCE_LOCKED,
                code::UNSUPPORTED_XREF_CLIP_DATA,
            ],
        ),
        XrefTool::ReloadXref => (
            &[
                Group::Mutation,
                Group::AttachmentIdentity,
                Group::AttachmentGuards,
                Group::SourceGraph,
                Group::Units,
            ],
            &[
                code::INVALID_SEARCH_PATH,
                code::INVALID_LAYER_RECONCILIATION,
                code::UNSUPPORTED_XREF_CLIP_DATA,
            ],
        ),
        XrefTool::UnloadXref => (
            &[
                Group::Mutation,
                Group::AttachmentIdentity,
                Group::AttachmentGuards,
            ],
            &[code::UNSUPPORTED_XREF_CLIP_DATA],
        ),
        XrefTool::BindXref => (
            &[
                Group::Mutation,
                Group::AttachmentIdentity,
                Group::AttachmentGuards,
                Group::DestructiveGuards,
                Group::SourceGraph,
            ],
            &[
                code::INVALID_SEARCH_PATH,
                code::UNSUPPORTED_XREF_OWNER,
                code::XREF_INSTANCE_LOCKED,
                code::NESTED_XREFS_PRESENT,
                code::UNSUPPORTED_XREF_CONTENT,
                code::UNSUPPORTED_XREF_CLIP_DATA,
            ],
        ),
    };

    let mut set = BTreeSet::new();
    for group in groups {
        extend_failure_group(&mut set, *group);
    }
    set.extend(additional.iter().copied());
    set.into_iter().collect()
}

fn unsupported_xref_data(message: impl Into<String>) -> XrefError {
    XrefError::new("unsupported_xref_data", message)
}

fn compare_canonical_handle_values(left: &str, right: &str) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

pub fn canonicalize_handle_chain(chain: &[String]) -> Result<Vec<String>, XrefError> {
    if chain.is_empty() {
        return Err(XrefError::new(
            xref_failure_code::INVALID_PARAMETERS,
            "XREF attachment chain must contain at least one handle",
        ));
    }
    chain
        .iter()
        .map(|handle| canonical_input_handle(handle))
        .collect()
}

pub fn compare_handle_chains(left: &[String], right: &[String]) -> Result<Ordering, XrefError> {
    let left = canonicalize_handle_chain(left)?;
    let right = canonicalize_handle_chain(right)?;
    for (left_handle, right_handle) in left.iter().zip(&right) {
        let ordering = compare_canonical_handle_values(left_handle, right_handle);
        if ordering != Ordering::Equal {
            return Ok(ordering);
        }
    }
    Ok(left.len().cmp(&right.len()))
}

pub fn canonicalize_unique_handle_set(handles: &[String]) -> Result<Vec<String>, XrefError> {
    let mut canonical = handles
        .iter()
        .map(|handle| canonical_input_handle(handle))
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort_by(|left, right| compare_canonical_handle_values(left, right));
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(XrefError::new(
            xref_failure_code::INVALID_PARAMETERS,
            "expected_instance_handles must contain unique handles",
        ));
    }
    Ok(canonical)
}

pub fn compare_xref_names(left: &str, right: &str) -> Ordering {
    left.to_uppercase()
        .cmp(&right.to_uppercase())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

#[cfg(test)]
fn name_eq(left: &str, right: &str) -> bool {
    xref_name_eq(left, right)
}

fn validate_canonical_persisted_handle(handle: &str, field: &str) -> Result<(), XrefError> {
    let canonical = canonical_input_handle(handle).map_err(|_| {
        unsupported_xref_data(format!("{field} is not a valid persisted XREF handle"))
    })?;
    if canonical == "0" || canonical != handle {
        return Err(unsupported_xref_data(format!(
            "{field} is not a canonical non-null persisted XREF handle"
        )));
    }
    Ok(())
}

fn map_persisted_geometry_error(error: XrefError, field: &str) -> XrefError {
    unsupported_xref_data(format!("persisted XREF {field} is invalid: {error}"))
}

impl XrefDependencyRecord {
    pub fn validate(&self) -> Result<(), XrefError> {
        self.attachment.validate()?;
        let canonical_chain = canonicalize_handle_chain(&self.attachment_chain)
            .map_err(|error| map_persisted_geometry_error(error, "attachment chain"))?;
        if canonical_chain != self.attachment_chain
            || canonical_chain.iter().any(|handle| handle == "0")
        {
            return Err(unsupported_xref_data(
                "dependency attachment_chain must contain canonical non-null handles",
            ));
        }
        if usize::try_from(self.depth).ok() != Some(canonical_chain.len() - 1) {
            return Err(unsupported_xref_data(
                "dependency depth does not match attachment_chain length",
            ));
        }
        if canonical_chain.last() != Some(&self.attachment.handle) {
            return Err(unsupported_xref_data(
                "dependency attachment_chain does not end at attachment.handle",
            ));
        }
        if (self.depth == 0) != (self.propagation_state == XrefPropagationState::Root) {
            return Err(unsupported_xref_data(
                "dependency root propagation state does not match depth",
            ));
        }
        if self.propagation_state == XrefPropagationState::ExcludedOverlay && self.depth == 0 {
            return Err(unsupported_xref_data(
                "a root dependency cannot be an excluded overlay",
            ));
        }
        if self.propagation_state == XrefPropagationState::ExcludedOverlay
            && self.inspection_state != XrefInspectionState::TerminalOverlay
        {
            return Err(unsupported_xref_data(
                "an excluded overlay must use terminal_overlay inspection state",
            ));
        }

        match self.resolution_state {
            XrefResolutionState::Resolved
                if self.resolved_path.is_some() && self.resolution_basis.is_some() => {}
            XrefResolutionState::Resolved => {
                return Err(unsupported_xref_data(
                    "resolved dependency requires resolved_path and resolution_basis",
                ));
            }
            _ if self.resolved_path.is_none() && self.resolution_basis.is_none() => {}
            _ => {
                return Err(unsupported_xref_data(
                    "non-resolved dependency cannot expose resolution details",
                ));
            }
        }

        match self.inspection_state {
            XrefInspectionState::Inspected
            | XrefInspectionState::Unsupported
            | XrefInspectionState::Cycle
                if self.resolution_state != XrefResolutionState::Resolved =>
            {
                return Err(unsupported_xref_data(
                    "dependency inspection state requires a resolved source",
                ));
            }
            XrefInspectionState::TerminalOverlay
                if self.depth == 0
                    || self.propagation_state != XrefPropagationState::ExcludedOverlay =>
            {
                return Err(unsupported_xref_data(
                    "terminal_overlay requires a non-root excluded overlay",
                ));
            }
            XrefInspectionState::NotResolved
                if self.resolution_state == XrefResolutionState::Resolved =>
            {
                return Err(unsupported_xref_data(
                    "not_resolved inspection cannot have a resolved source",
                ));
            }
            _ => {}
        }

        match (&self.inspection_state, &self.cycle_target_chain) {
            (XrefInspectionState::Cycle, Some(target)) => {
                if target.len() >= canonical_chain.len()
                    || !canonical_chain.starts_with(target)
                    || target.iter().any(|handle| {
                        canonical_input_handle(handle).ok().as_ref() != Some(handle)
                            || handle == "0"
                    })
                {
                    return Err(unsupported_xref_data(
                        "cycle_target_chain must identify a canonical ancestor chain",
                    ));
                }
            }
            (XrefInspectionState::Cycle, None) => {
                return Err(unsupported_xref_data(
                    "cycle inspection requires cycle_target_chain",
                ));
            }
            (_, Some(_)) => {
                return Err(unsupported_xref_data(
                    "only cycle inspection may expose cycle_target_chain",
                ));
            }
            (_, None) => {}
        }
        Ok(())
    }
}

impl XrefPathResolutionRecord {
    pub fn validate(&self) -> Result<(), XrefError> {
        validate_canonical_persisted_handle(&self.attachment_handle, "attachment handle")?;
        match self.resolution_state {
            XrefResolutionState::Resolved => {
                let Some(basis) = self.resolution_basis else {
                    return Err(unsupported_xref_data(
                        "resolved XREF path requires resolution_basis",
                    ));
                };
                if self.resolved_path.is_none()
                    || (basis == XrefResolutionBasis::ExplicitSearchPath)
                        != self.search_path_index.is_some()
                {
                    return Err(unsupported_xref_data(
                        "resolved XREF path has inconsistent resolution details",
                    ));
                }
            }
            _ if self.resolved_path.is_some()
                || self.resolution_basis.is_some()
                || self.search_path_index.is_some() =>
            {
                return Err(unsupported_xref_data(
                    "non-resolved XREF path cannot expose resolution details",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

impl XrefDependencyTraversalEnvelope {
    pub fn validate(&self) -> Result<(), XrefError> {
        if self.within_limits != self.truncation.is_none() {
            return Err(unsupported_xref_data(
                "within_limits must be true exactly when truncation is null",
            ));
        }
        if let Some(truncation) = &self.truncation {
            let canonical = canonicalize_handle_chain(&truncation.attachment_chain)
                .map_err(|error| map_persisted_geometry_error(error, "truncation chain"))?;
            if canonical != truncation.attachment_chain
                || canonical.iter().any(|handle| handle == "0")
            {
                return Err(unsupported_xref_data(
                    "truncation attachment_chain must contain canonical non-null handles",
                ));
            }
        }
        for dependency in &self.dependencies {
            dependency.validate()?;
        }
        Ok(())
    }
}

impl XrefSymbolType {
    pub const fn sort_rank(self) -> u8 {
        match self {
            Self::Block => 0,
            Self::Layer => 1,
            Self::Linetype => 2,
            Self::TextStyle => 3,
            Self::DimensionStyle => 4,
            Self::TableStyle => 5,
            Self::MultileaderStyle => 6,
            Self::Material => 7,
            Self::PlotStyle => 8,
            Self::VisualStyle => 9,
        }
    }
}

pub fn compare_instance_handle_mappings(
    left: &XrefInstanceHandleMapping,
    right: &XrefInstanceHandleMapping,
) -> Result<Ordering, XrefError> {
    let chain_order = compare_handle_chains(&left.attachment_chain, &right.attachment_chain)?;
    if chain_order != Ordering::Equal {
        return Ok(chain_order);
    }
    compare_numeric_handles(&left.old_handle, &right.old_handle)
}

pub fn compare_symbol_mappings(
    left: &XrefSymbolMapping,
    right: &XrefSymbolMapping,
) -> Result<Ordering, XrefError> {
    let chain_order = compare_handle_chains(&left.attachment_chain, &right.attachment_chain)?;
    if chain_order != Ordering::Equal {
        return Ok(chain_order);
    }
    let symbol_order = left
        .symbol_type
        .sort_rank()
        .cmp(&right.symbol_type.sort_rank());
    if symbol_order != Ordering::Equal {
        return Ok(symbol_order);
    }
    let source_name_order = compare_xref_names(&left.source_name, &right.source_name);
    if source_name_order != Ordering::Equal {
        return Ok(source_name_order);
    }
    let source_handle_order = compare_numeric_handles(&left.source_handle, &right.source_handle)?;
    if source_handle_order != Ordering::Equal {
        return Ok(source_handle_order);
    }
    Ok(compare_xref_names(&left.final_name, &right.final_name))
}

pub fn sort_xref_attachment_records(records: &mut [XrefAttachmentRecord]) -> Result<(), XrefError> {
    for record in records.iter() {
        record.validate()?;
    }
    records.sort_by(|left, right| compare_canonical_handle_values(&left.handle, &right.handle));
    Ok(())
}

pub fn sort_xref_instance_records(records: &mut [XrefInstanceRecord]) -> Result<(), XrefError> {
    for record in records.iter() {
        if record.clone().canonicalized()? != *record {
            return Err(unsupported_xref_data(
                "XREF instance record is not in canonical response form",
            ));
        }
    }
    records.sort_by(|left, right| compare_canonical_handle_values(&left.handle, &right.handle));
    Ok(())
}

pub fn sort_xref_dependency_records(records: &mut [XrefDependencyRecord]) -> Result<(), XrefError> {
    for record in records.iter() {
        record.validate()?;
    }
    records.sort_by(|left, right| {
        compare_handle_chains(&left.attachment_chain, &right.attachment_chain)
            .expect("validated attachment chains must compare")
    });
    Ok(())
}

pub fn sort_instance_handle_mappings(
    mappings: &mut [XrefInstanceHandleMapping],
) -> Result<(), XrefError> {
    for mapping in mappings.iter() {
        let chain = canonicalize_handle_chain(&mapping.attachment_chain)?;
        if chain != mapping.attachment_chain || chain.iter().any(|handle| handle == "0") {
            return Err(unsupported_xref_data(
                "instance mapping chain must contain canonical non-null handles",
            ));
        }
        validate_canonical_persisted_handle(&mapping.old_handle, "old instance handle")?;
        validate_canonical_persisted_handle(&mapping.new_handle, "new instance handle")?;
    }
    mappings.sort_by(|left, right| {
        compare_instance_handle_mappings(left, right)
            .expect("validated instance mappings must compare")
    });
    Ok(())
}

pub fn sort_symbol_mappings(mappings: &mut [XrefSymbolMapping]) -> Result<(), XrefError> {
    for mapping in mappings.iter() {
        let chain = canonicalize_handle_chain(&mapping.attachment_chain)?;
        if chain != mapping.attachment_chain || chain.iter().any(|handle| handle == "0") {
            return Err(unsupported_xref_data(
                "symbol mapping chain must contain canonical non-null handles",
            ));
        }
        validate_canonical_persisted_handle(&mapping.source_handle, "source symbol handle")?;
        validate_canonical_persisted_handle(&mapping.final_handle, "final symbol handle")?;
    }
    mappings.sort_by(|left, right| {
        compare_symbol_mappings(left, right).expect("validated symbol mappings must compare")
    });
    Ok(())
}

#[cfg(test)]
fn fact_value<'a, T>(
    fact: &'a XrefFact<T>,
    field: &str,
    xref_name: Option<&str>,
) -> Result<&'a T, XrefError> {
    match fact {
        XrefFact::Proven(value) => Ok(value),
        XrefFact::Unsupported(reason) => Err(unsupported_xref_data(format!(
            "XREF `{}` has unsupported {field}: {reason}",
            xref_name.unwrap_or("<unknown>")
        ))),
    }
}

#[cfg(test)]
fn materialize_xref(evidence: &XrefEvidence) -> Result<XrefRecord, XrefError> {
    let name = fact_value(&evidence.name, "name", None)?.clone();
    let reference_type = match &evidence.membership {
        XrefMembership::NotXref => {
            return Err(XrefError::new(
                "xref_not_found",
                format!("block `{name}` is not an XREF attachment"),
            ));
        }
        XrefMembership::Xref(reference_type) => *reference_type,
        XrefMembership::Unsupported(reason) => {
            return Err(unsupported_xref_data(format!(
                "XREF `{name}` has unsupported reference type: {reason}"
            )));
        }
    };

    let raw_handle = fact_value(&evidence.handle, "handle", Some(&name))?;
    let handle = canonical_input_handle(raw_handle).map_err(|_| {
        unsupported_xref_data(format!("XREF `{name}` has an invalid persisted handle"))
    })?;
    if handle == "0" {
        return Err(unsupported_xref_data(format!(
            "XREF `{name}` has a null persisted handle"
        )));
    }

    let path = fact_value(&evidence.path, "path", Some(&name))?.clone();
    Ok(XrefRecord {
        handle,
        name,
        path,
        reference_type,
        load_state: evidence.load_state,
    })
}

#[cfg(test)]
fn evidence_is_xref_like(evidence: &XrefEvidence) -> bool {
    !matches!(evidence.membership, XrefMembership::NotXref)
}

#[cfg(test)]
fn resolve_by_handle(evidence: &[XrefEvidence], wanted: &str) -> Result<usize, XrefError> {
    let mut matches = Vec::new();
    for (index, candidate) in evidence.iter().enumerate() {
        let XrefFact::Proven(candidate_handle) = &candidate.handle else {
            continue;
        };
        let Ok(candidate_handle) = canonical_input_handle(candidate_handle) else {
            continue;
        };
        if candidate_handle == wanted {
            matches.push(index);
        }
    }

    if matches.is_empty() {
        return Err(XrefError::new(
            "xref_not_found",
            format!("XREF handle `{wanted}` was not found"),
        ));
    }
    if matches.len() > 1 {
        return Err(unsupported_xref_data(format!(
            "handle `{wanted}` is duplicated in the drawing"
        )));
    }

    let index = matches[0];
    match &evidence[index].membership {
        XrefMembership::NotXref => Err(XrefError::new(
            "xref_not_found",
            format!("handle `{wanted}` does not identify an XREF attachment"),
        )),
        XrefMembership::Xref(_) => Ok(index),
        XrefMembership::Unsupported(reason) => Err(unsupported_xref_data(format!(
            "handle `{wanted}` identifies unsupported XREF data: {reason}"
        ))),
    }
}

#[cfg(test)]
fn resolve_by_name(evidence: &[XrefEvidence], wanted: &str) -> Result<usize, XrefError> {
    if wanted.trim().is_empty() {
        return Err(XrefError::new(
            "xref_not_found",
            "empty XREF name was not found",
        ));
    }

    let mut matches = Vec::new();
    let mut unsupported_name_reason = None;
    for (index, candidate) in evidence.iter().enumerate() {
        if !evidence_is_xref_like(candidate) {
            continue;
        }
        match &candidate.name {
            XrefFact::Proven(name) if name_eq(name, wanted) => matches.push(index),
            XrefFact::Proven(_) => {}
            XrefFact::Unsupported(reason) => {
                unsupported_name_reason.get_or_insert(reason);
            }
        }
    }

    if matches.len() > 1 {
        return Err(XrefError::new(
            "ambiguous_identity",
            format!("XREF name `{wanted}` matches more than one attachment"),
        ));
    }
    if let Some(reason) = unsupported_name_reason {
        return Err(unsupported_xref_data(format!(
            "cannot prove XREF name uniqueness: {reason}"
        )));
    }
    if matches.is_empty() {
        return Err(XrefError::new(
            "xref_not_found",
            format!("XREF name `{wanted}` was not found"),
        ));
    }

    let index = matches[0];
    match &evidence[index].membership {
        XrefMembership::Xref(_) => Ok(index),
        XrefMembership::Unsupported(reason) => Err(unsupported_xref_data(format!(
            "XREF name `{wanted}` identifies unsupported XREF data: {reason}"
        ))),
        XrefMembership::NotXref => unreachable!("non-XREF candidates are filtered above"),
    }
}

#[cfg(test)]
fn resolve_xref_index(
    evidence: &[XrefEvidence],
    selector: &XrefSelector,
) -> Result<usize, XrefError> {
    let canonical_handle = selector
        .handle
        .as_deref()
        .map(canonical_input_handle)
        .transpose()?;
    let usable_name = selector
        .name
        .as_deref()
        .is_some_and(|name| !name.trim().is_empty());

    if canonical_handle.is_none() && !usable_name {
        return Err(XrefError::new(
            "missing_identity",
            "get_xref requires a handle or non-empty name",
        ));
    }

    let by_handle = canonical_handle
        .as_deref()
        .map(|handle| resolve_by_handle(evidence, handle))
        .transpose()?;
    let by_name = selector
        .name
        .as_deref()
        .map(|name| resolve_by_name(evidence, name))
        .transpose()?;

    match (by_handle, by_name) {
        (Some(handle_index), Some(name_index)) if handle_index == name_index => Ok(handle_index),
        (Some(_), Some(_)) => Err(XrefError::new(
            "contradictory_identity",
            "XREF handle and name resolve to different attachments",
        )),
        (Some(index), None) | (None, Some(index)) => Ok(index),
        (None, None) => Err(XrefError::new(
            "missing_identity",
            "get_xref requires a handle or non-empty name",
        )),
    }
}

#[cfg(test)]
pub(crate) fn list_xrefs(evidence: &[XrefEvidence]) -> Result<Vec<XrefRecord>, XrefError> {
    let mut records = evidence
        .iter()
        .filter(|candidate| evidence_is_xref_like(candidate))
        .map(materialize_xref)
        .collect::<Result<Vec<_>, _>>()?;
    records.sort_by(|left, right| compare_canonical_handle_values(&left.handle, &right.handle));
    Ok(records)
}

#[cfg(test)]
pub(crate) fn get_xref(
    evidence: &[XrefEvidence],
    selector: &XrefSelector,
) -> Result<XrefRecord, XrefError> {
    let index = resolve_xref_index(evidence, selector)?;
    materialize_xref(&evidence[index])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;

    fn point(x: f64, y: f64, z: f64) -> XrefPoint3 {
        XrefPoint3 { x, y, z }
    }

    fn scale(x: f64, y: f64, z: f64) -> XrefScale3 {
        XrefScale3 { x, y, z }
    }

    fn vector(x: f64, y: f64, z: f64) -> XrefVector3 {
        XrefVector3 { x, y, z }
    }

    fn complete_attachment(handle: &str) -> XrefAttachmentRecord {
        XrefAttachmentRecord {
            handle: handle.to_string(),
            name: "SITE_MODEL".to_string(),
            saved_path: "../refs/site.dwg".to_string(),
            path_mode: XrefPathMode::Relative,
            reference_type: ReferenceType::Attachment,
            load_state: LoadState::Loaded,
            instance_count: 1,
            definition_base_point: XrefPointAvailability::Available {
                point: XrefPoint3::ORIGIN,
            },
        }
    }

    fn complete_instance(handle: &str, placement_kind: XrefPlacementKind) -> XrefInstanceRecord {
        XrefInstanceRecord {
            handle: handle.to_string(),
            attachment_handle: "2A".to_string(),
            attachment_name: "SITE_MODEL".to_string(),
            owner_handle: "1F".to_string(),
            owner_type: XrefOwnerType::ModelSpace,
            owner_name: "Model".to_string(),
            layer_handle: "10".to_string(),
            layer_name: "0".to_string(),
            insertion_point: point(1.0, 2.0, 3.0),
            scale: XrefScale3::IDENTITY,
            rotation_degrees: 90.0,
            normal: XrefVector3::WORLD_Z,
            visibility: XrefVisibility::Visible,
            placement_kind,
            array: (placement_kind == XrefPlacementKind::RectangularArray).then_some(
                XrefRectangularArray {
                    rows: 2,
                    columns: 3,
                    row_spacing: 10.0,
                    column_spacing: 20.0,
                },
            ),
            unit_scaling: XrefUnitScaling::Available {
                source_units: XrefUnitValue {
                    value: InsertionUnit::Millimeters,
                    basis: XrefUnitBasis::Drawing,
                },
                host_units: XrefUnitValue {
                    value: InsertionUnit::Meters,
                    basis: XrefUnitBasis::Request,
                },
                factor: 0.001,
                effective_scale: scale(0.001, 0.001, 0.001),
            },
        }
    }

    fn root_dependency(handle: &str) -> XrefDependencyRecord {
        XrefDependencyRecord {
            attachment_chain: vec![handle.to_string()],
            depth: 0,
            immediate_host_path: "/project/host.dwg".to_string(),
            attachment: complete_attachment(handle),
            propagation_state: XrefPropagationState::Root,
            resolution_state: XrefResolutionState::Resolved,
            resolved_path: Some("/project/refs/site.dwg".to_string()),
            resolution_basis: Some(XrefResolutionBasis::HostRelative),
            inspection_state: XrefInspectionState::Inspected,
            cycle_target_chain: None,
        }
    }

    fn reconciliation_evidence() -> XrefLayerReconciliationEvidence {
        XrefLayerReconciliationEvidence {
            requested_mode: LayerReconciliationMode::DrawingPolicy,
            effective_mode: EffectiveLayerReconciliationMode::PreserveHost,
            synchronized_properties: Vec::new(),
        }
    }

    fn assert_approx(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() <= 1e-12,
            "actual={actual:?} expected={expected:?}"
        );
    }

    fn assert_point(actual: XrefPoint3, expected: XrefPoint3) {
        assert_approx(actual.x, expected.x);
        assert_approx(actual.y, expected.y);
        assert_approx(actual.z, expected.z);
    }

    fn assert_vector(actual: XrefVector3, expected: XrefVector3) {
        assert_approx(actual.x, expected.x);
        assert_approx(actual.y, expected.y);
        assert_approx(actual.z, expected.z);
    }

    fn assert_closed_schema<T: JsonSchema>() {
        let schema = serde_json::to_value(schemars::schema_for!(T)).unwrap();
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&serde_json::Value::Bool(false)),
            "schema was not closed: {schema:#}"
        );
    }

    fn assert_schema_requires<T: JsonSchema>(fields: &[&str]) {
        let schema = serde_json::to_value(schemars::schema_for!(T)).unwrap();
        let required = schema["required"]
            .as_array()
            .expect("object schema must have required fields")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<BTreeSet<_>>();
        for field in fields {
            assert!(
                required.contains(field),
                "{field} was optional in {schema:#}"
            );
        }
    }

    fn assert_closed_round_trip<T>(value: &T, expected_keys: &[&str])
    where
        T: std::fmt::Debug + PartialEq + Serialize + DeserializeOwned + JsonSchema,
    {
        assert_closed_schema::<T>();
        let serialized = serde_json::to_value(value).unwrap();
        let object = serialized.as_object().unwrap();
        let actual_keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
        let expected_keys = expected_keys.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(actual_keys, expected_keys);
        assert_eq!(
            serde_json::from_value::<T>(serialized.clone()).unwrap(),
            *value
        );

        let mut with_unknown = serialized;
        with_unknown
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<T>(with_unknown).is_err());
    }

    #[test]
    fn complete_attachment_record_is_exact_and_closed() {
        let record = complete_attachment("2A");
        assert_closed_round_trip(
            &record,
            &[
                "handle",
                "name",
                "saved_path",
                "path_mode",
                "reference_type",
                "load_state",
                "instance_count",
                "definition_base_point",
            ],
        );
        assert_eq!(
            serde_json::to_value(&record).unwrap(),
            serde_json::json!({
                "handle": "2A",
                "name": "SITE_MODEL",
                "saved_path": "../refs/site.dwg",
                "path_mode": "relative",
                "reference_type": "attachment",
                "load_state": "loaded",
                "instance_count": 1,
                "definition_base_point": {
                    "state": "available",
                    "point": { "x": 0.0, "y": 0.0, "z": 0.0 }
                }
            })
        );
        record.validate().unwrap();

        for invalid_handle in ["0", "02A", "2a", "0x2A", "G"] {
            let mut invalid = record.clone();
            invalid.handle = invalid_handle.to_string();
            assert_eq!(
                invalid.validate().unwrap_err().code(),
                "unsupported_xref_data"
            );
        }
    }

    #[test]
    fn complete_instance_record_and_tagged_units_are_exact_and_closed() {
        let record = complete_instance("40", XrefPlacementKind::RectangularArray);
        assert_closed_round_trip(
            &record,
            &[
                "handle",
                "attachment_handle",
                "attachment_name",
                "owner_handle",
                "owner_type",
                "owner_name",
                "layer_handle",
                "layer_name",
                "insertion_point",
                "scale",
                "rotation_degrees",
                "normal",
                "visibility",
                "placement_kind",
                "array",
                "unit_scaling",
            ],
        );
        let serialized = serde_json::to_value(&record).unwrap();
        assert_eq!(serialized["owner_type"], "model_space");
        assert_eq!(serialized["placement_kind"], "rectangular_array");
        assert_eq!(serialized["array"]["rows"], 2);
        assert_eq!(serialized["unit_scaling"]["state"], "available");
        assert_eq!(
            serialized["unit_scaling"]["source_units"]["value"],
            "millimeters"
        );
        assert_eq!(serialized["unit_scaling"]["host_units"]["basis"], "request");
        assert_eq!(record.clone().canonicalized().unwrap(), record);
        assert_schema_requires::<XrefInstanceRecord>(&["array"]);
        let mut missing_array = serialized.clone();
        missing_array.as_object_mut().unwrap().remove("array");
        assert!(serde_json::from_value::<XrefInstanceRecord>(missing_array).is_err());

        assert!(
            serde_json::from_value::<XrefPointAvailability>(serde_json::json!({
                "state": "unavailable",
                "point": { "x": 0.0, "y": 0.0, "z": 0.0 }
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<XrefPointAvailability>(serde_json::json!({
                "state": "available"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<XrefUnitScaling>(serde_json::json!({
                "state": "unavailable",
                "factor": 1.0
            }))
            .is_err()
        );
        assert!(serde_json::from_value::<XrefUnitValue>(serde_json::json!({
            "value": "meters",
            "basis": "drawing",
            "extra": true
        }))
        .is_err());

        assert!(
            serde_json::from_value::<XrefUnitScaling>(serde_json::json!({
                "state": "available",
                "source_units": {"value": "millimeters", "basis": "drawing"},
                "host_units": {"value": "meters", "basis": "request"},
                "factor": 0.001,
                "effective_scale": {"x": 0.001, "y": 0.001, "z": 0.001},
                "extra": true
            }))
            .is_err()
        );

        let mut mismatched = record;
        mismatched.unit_scaling = XrefUnitScaling::Available {
            source_units: XrefUnitValue {
                value: InsertionUnit::Millimeters,
                basis: XrefUnitBasis::Drawing,
            },
            host_units: XrefUnitValue {
                value: InsertionUnit::Meters,
                basis: XrefUnitBasis::Request,
            },
            factor: 0.001,
            effective_scale: scale(1.0, 1.0, 1.0),
        };
        assert_eq!(
            mismatched.canonicalized().unwrap_err().code(),
            "unsupported_xref_data"
        );

        assert!(PersistedInsertionUnits::Known {
            value: InsertionUnit::Meters
        }
        .validate()
        .is_ok());
        assert_eq!(
            PersistedInsertionUnits::Known {
                value: InsertionUnit::Unitless
            }
            .validate()
            .unwrap_err()
            .code(),
            "unsupported_xref_data"
        );
        assert!(
            serde_json::from_value::<PersistedInsertionUnits>(serde_json::json!({
                "state": "unitless",
                "value": "meters"
            }))
            .is_err()
        );
    }

    #[test]
    fn enum_spellings_match_the_contract_exactly() {
        let units = [
            InsertionUnit::Unitless,
            InsertionUnit::Inches,
            InsertionUnit::Feet,
            InsertionUnit::Miles,
            InsertionUnit::Millimeters,
            InsertionUnit::Centimeters,
            InsertionUnit::Meters,
            InsertionUnit::Kilometers,
            InsertionUnit::Microinches,
            InsertionUnit::Mils,
            InsertionUnit::Yards,
            InsertionUnit::Angstroms,
            InsertionUnit::Nanometers,
            InsertionUnit::Microns,
            InsertionUnit::Decimeters,
            InsertionUnit::Dekameters,
            InsertionUnit::Hectometers,
            InsertionUnit::Gigameters,
            InsertionUnit::AstronomicalUnits,
            InsertionUnit::LightYears,
            InsertionUnit::Parsecs,
            InsertionUnit::UsSurveyFeet,
            InsertionUnit::UsSurveyInches,
            InsertionUnit::UsSurveyYards,
            InsertionUnit::UsSurveyMiles,
        ];
        let expected = [
            "unitless",
            "inches",
            "feet",
            "miles",
            "millimeters",
            "centimeters",
            "meters",
            "kilometers",
            "microinches",
            "mils",
            "yards",
            "angstroms",
            "nanometers",
            "microns",
            "decimeters",
            "dekameters",
            "hectometers",
            "gigameters",
            "astronomical_units",
            "light_years",
            "parsecs",
            "us_survey_feet",
            "us_survey_inches",
            "us_survey_yards",
            "us_survey_miles",
        ];
        let actual = units
            .iter()
            .map(|unit| serde_json::to_value(unit).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected.map(serde_json::Value::from));

        let enum_cases = [
            (
                serde_json::to_value(XrefPathMode::FilenameOnly).unwrap(),
                "filename_only",
            ),
            (
                serde_json::to_value(XrefResolutionBasis::SavedAbsolute).unwrap(),
                "saved_absolute",
            ),
            (
                serde_json::to_value(XrefPropagationState::ExcludedOverlay).unwrap(),
                "excluded_overlay",
            ),
            (
                serde_json::to_value(XrefInspectionState::TerminalOverlay).unwrap(),
                "terminal_overlay",
            ),
            (
                serde_json::to_value(XrefOwnerType::BlockDefinition).unwrap(),
                "block_definition",
            ),
            (
                serde_json::to_value(XrefSymbolType::MultileaderStyle).unwrap(),
                "multileader_style",
            ),
            (
                serde_json::to_value(XrefSymbolResolution::EarlierImportUsed).unwrap(),
                "earlier_import_used",
            ),
        ];
        for (actual, expected) in enum_cases {
            assert_eq!(actual, expected);
        }

        fn assert_tagged_variants_are_closed<T: JsonSchema>() {
            fn visit(value: &serde_json::Value, found: &mut usize) {
                match value {
                    serde_json::Value::Object(object) => {
                        if object
                            .get("properties")
                            .and_then(serde_json::Value::as_object)
                            .is_some_and(|properties| properties.contains_key("state"))
                        {
                            *found += 1;
                            assert_eq!(
                                object.get("additionalProperties"),
                                Some(&serde_json::Value::Bool(false)),
                                "tagged variant schema is open: {value:#}"
                            );
                        }
                        for child in object.values() {
                            visit(child, found);
                        }
                    }
                    serde_json::Value::Array(values) => {
                        for child in values {
                            visit(child, found);
                        }
                    }
                    _ => {}
                }
            }

            let schema = serde_json::to_value(schemars::schema_for!(T)).unwrap();
            let mut found = 0;
            visit(&schema, &mut found);
            assert!(
                found > 0,
                "tagged union schema had no state variants: {schema:#}"
            );
        }

        assert_tagged_variants_are_closed::<XrefPointAvailability>();
        assert_tagged_variants_are_closed::<XrefUnitScaling>();
        assert_tagged_variants_are_closed::<PersistedInsertionUnits>();
    }

    #[test]
    fn dependency_path_and_traversal_records_are_closed_and_validate_invariants() {
        let dependency = root_dependency("2A");
        assert_closed_round_trip(
            &dependency,
            &[
                "attachment_chain",
                "depth",
                "immediate_host_path",
                "attachment",
                "propagation_state",
                "resolution_state",
                "resolved_path",
                "resolution_basis",
                "inspection_state",
                "cycle_target_chain",
            ],
        );
        dependency.validate().unwrap();
        assert_schema_requires::<XrefDependencyRecord>(&[
            "resolved_path",
            "resolution_basis",
            "cycle_target_chain",
        ]);
        let mut missing_cycle_target = serde_json::to_value(&dependency).unwrap();
        missing_cycle_target
            .as_object_mut()
            .unwrap()
            .remove("cycle_target_chain");
        assert!(serde_json::from_value::<XrefDependencyRecord>(missing_cycle_target).is_err());

        let path = XrefPathResolutionRecord {
            drawing: "/project/host.dwg".to_string(),
            attachment_handle: "2A".to_string(),
            saved_path: "../refs/site.dwg".to_string(),
            path_mode: XrefPathMode::Relative,
            resolution_state: XrefResolutionState::Resolved,
            resolved_path: Some("/project/refs/site.dwg".to_string()),
            resolution_basis: Some(XrefResolutionBasis::ExplicitSearchPath),
            search_path_index: Some(1),
        };
        assert_closed_round_trip(
            &path,
            &[
                "drawing",
                "attachment_handle",
                "saved_path",
                "path_mode",
                "resolution_state",
                "resolved_path",
                "resolution_basis",
                "search_path_index",
            ],
        );
        path.validate().unwrap();
        assert_schema_requires::<XrefPathResolutionRecord>(&[
            "resolved_path",
            "resolution_basis",
            "search_path_index",
        ]);
        let mut missing_search_index = serde_json::to_value(&path).unwrap();
        missing_search_index
            .as_object_mut()
            .unwrap()
            .remove("search_path_index");
        assert!(serde_json::from_value::<XrefPathResolutionRecord>(missing_search_index).is_err());

        let envelope = XrefDependencyTraversalEnvelope {
            drawing: "/project/host.dwg".to_string(),
            within_limits: false,
            truncation: Some(XrefTraversalTruncation {
                reason: XrefTraversalLimitReason::MaxNodes,
                limit: 10_000,
                attachment_chain: vec!["2A".to_string(), "51".to_string()],
            }),
            dependencies: vec![dependency.clone()],
        };
        assert_closed_round_trip(
            &envelope,
            &["drawing", "within_limits", "truncation", "dependencies"],
        );
        envelope.validate().unwrap();
        assert_schema_requires::<XrefDependencyTraversalEnvelope>(&["truncation"]);
        let mut missing_truncation = serde_json::to_value(&envelope).unwrap();
        missing_truncation
            .as_object_mut()
            .unwrap()
            .remove("truncation");
        assert!(
            serde_json::from_value::<XrefDependencyTraversalEnvelope>(missing_truncation).is_err()
        );

        let mut bad_depth = dependency.clone();
        bad_depth.depth = 1;
        assert_eq!(
            bad_depth.validate().unwrap_err().code(),
            "unsupported_xref_data"
        );
        let mut bad_final = dependency.clone();
        bad_final.attachment_chain[0] = "2B".to_string();
        assert_eq!(
            bad_final.validate().unwrap_err().code(),
            "unsupported_xref_data"
        );
        let mut bad_overlay = dependency.clone();
        bad_overlay.attachment_chain = vec!["1".to_string(), "2A".to_string()];
        bad_overlay.depth = 1;
        bad_overlay.propagation_state = XrefPropagationState::ExcludedOverlay;
        assert_eq!(
            bad_overlay.validate().unwrap_err().code(),
            "unsupported_xref_data"
        );
        let mut bad_resolution = path.clone();
        bad_resolution.search_path_index = None;
        assert_eq!(
            bad_resolution.validate().unwrap_err().code(),
            "unsupported_xref_data"
        );
        let mut bad_envelope = envelope;
        bad_envelope.within_limits = true;
        assert_eq!(
            bad_envelope.validate().unwrap_err().code(),
            "unsupported_xref_data"
        );
    }

    #[test]
    fn cycle_records_require_a_canonical_ancestor_chain() {
        let mut root_cycle = root_dependency("2A");
        root_cycle.inspection_state = XrefInspectionState::Cycle;
        root_cycle.cycle_target_chain = Some(Vec::new());
        root_cycle.validate().unwrap();

        let mut nested_cycle = root_dependency("51");
        nested_cycle.attachment_chain = vec!["2A".to_string(), "51".to_string()];
        nested_cycle.depth = 1;
        nested_cycle.propagation_state = XrefPropagationState::Propagated;
        nested_cycle.inspection_state = XrefInspectionState::Cycle;
        nested_cycle.cycle_target_chain = Some(vec!["2A".to_string()]);
        nested_cycle.validate().unwrap();

        nested_cycle.cycle_target_chain = Some(vec!["2B".to_string()]);
        assert_eq!(
            nested_cycle.validate().unwrap_err().code(),
            "unsupported_xref_data"
        );
        nested_cycle.cycle_target_chain = None;
        assert_eq!(
            nested_cycle.validate().unwrap_err().code(),
            "unsupported_xref_data"
        );
    }

    #[test]
    fn every_mutation_response_has_its_exact_closed_envelope() {
        let attachment = complete_attachment("2A");
        let instance = complete_instance("40", XrefPlacementKind::Single);

        assert_closed_round_trip(
            &AttachXrefResponse {
                status: AttachXrefStatus::Attached,
                drawing: "/project/host.dwg".to_string(),
                attachment: attachment.clone(),
                instance: instance.clone(),
            },
            &["status", "drawing", "attachment", "instance"],
        );
        assert_closed_round_trip(
            &UpdateXrefResponse {
                status: UpdateXrefStatus::Updated,
                drawing: "/project/host.dwg".to_string(),
                attachment: attachment.clone(),
                layer_reconciliation: None,
            },
            &["status", "drawing", "attachment"],
        );
        assert_closed_round_trip(
            &UpdateXrefResponse {
                status: UpdateXrefStatus::Updated,
                drawing: "/project/host.dwg".to_string(),
                attachment: attachment.clone(),
                layer_reconciliation: Some(reconciliation_evidence()),
            },
            &["status", "drawing", "attachment", "layer_reconciliation"],
        );
        assert_closed_round_trip(
            &DetachXrefResponse {
                status: DetachXrefStatus::Detached,
                drawing: "/project/host.dwg".to_string(),
                attachment: attachment.clone(),
                deleted_instance_handles: vec!["40".to_string()],
            },
            &[
                "status",
                "drawing",
                "attachment",
                "deleted_instance_handles",
            ],
        );
        assert_closed_round_trip(
            &InsertXrefInstanceResponse {
                status: InsertXrefInstanceStatus::Inserted,
                drawing: "/project/host.dwg".to_string(),
                instance: instance.clone(),
            },
            &["status", "drawing", "instance"],
        );
        assert_closed_round_trip(
            &UpdateXrefInstanceResponse {
                status: UpdateXrefInstanceStatus::Updated,
                drawing: "/project/host.dwg".to_string(),
                instance: instance.clone(),
            },
            &["status", "drawing", "instance"],
        );
        assert_closed_round_trip(
            &DeleteXrefInstanceResponse {
                status: DeleteXrefInstanceStatus::Deleted,
                drawing: "/project/host.dwg".to_string(),
                instance: instance.clone(),
            },
            &["status", "drawing", "instance"],
        );
        assert_closed_round_trip(
            &ReloadXrefResponse {
                status: ReloadXrefStatus::Loaded,
                drawing: "/project/host.dwg".to_string(),
                attachment: attachment.clone(),
                layer_reconciliation: reconciliation_evidence(),
            },
            &["status", "drawing", "attachment", "layer_reconciliation"],
        );
        assert_closed_round_trip(
            &UnloadXrefResponse {
                status: UnloadXrefStatus::Unloaded,
                drawing: "/project/host.dwg".to_string(),
                attachment: attachment.clone(),
            },
            &["status", "drawing", "attachment"],
        );
        assert_closed_round_trip(
            &BindXrefResponse {
                status: BindXrefStatus::Bound,
                drawing: "/project/host.dwg".to_string(),
                symbol_strategy: XrefSymbolStrategy::Merge,
                dependency_strategy: XrefDependencyStrategy::BindNested,
                attachment: attachment.clone(),
                block: XrefBoundBlock {
                    handle: "2A".to_string(),
                    name: "SITE_MODEL".to_string(),
                },
                instance_handle_mappings: vec![XrefInstanceHandleMapping {
                    attachment_chain: vec!["2A".to_string()],
                    old_handle: "40".to_string(),
                    new_handle: "40".to_string(),
                }],
                symbol_mappings: vec![XrefSymbolMapping {
                    attachment_chain: vec!["2A".to_string()],
                    symbol_type: XrefSymbolType::Layer,
                    source_handle: "61".to_string(),
                    source_name: "SITE_MODEL|WALL".to_string(),
                    final_handle: "12".to_string(),
                    final_name: "WALL".to_string(),
                    resolution: XrefSymbolResolution::HostDefinitionUsed,
                }],
                bound_dependencies: vec![XrefBoundDependency {
                    attachment_chain: vec!["2A".to_string(), "51".to_string()],
                    attachment: complete_attachment("51"),
                    block: XrefBoundBlock {
                        handle: "51".to_string(),
                        name: "NESTED".to_string(),
                    },
                }],
                excluded_overlay_dependencies: vec![root_dependency("2A")],
            },
            &[
                "status",
                "drawing",
                "symbol_strategy",
                "dependency_strategy",
                "attachment",
                "block",
                "instance_handle_mappings",
                "symbol_mappings",
                "bound_dependencies",
                "excluded_overlay_dependencies",
            ],
        );

        let statuses = [
            serde_json::to_value(AttachXrefStatus::Attached).unwrap(),
            serde_json::to_value(UpdateXrefStatus::Updated).unwrap(),
            serde_json::to_value(DetachXrefStatus::Detached).unwrap(),
            serde_json::to_value(InsertXrefInstanceStatus::Inserted).unwrap(),
            serde_json::to_value(UpdateXrefInstanceStatus::Updated).unwrap(),
            serde_json::to_value(DeleteXrefInstanceStatus::Deleted).unwrap(),
            serde_json::to_value(ReloadXrefStatus::Loaded).unwrap(),
            serde_json::to_value(UnloadXrefStatus::Unloaded).unwrap(),
            serde_json::to_value(BindXrefStatus::Bound).unwrap(),
        ];
        assert_eq!(
            statuses,
            [
                "attached", "updated", "detached", "inserted", "updated", "deleted", "loaded",
                "unloaded", "bound"
            ]
            .map(serde_json::Value::from)
        );
    }

    #[test]
    fn every_request_is_closed_while_update_property_maps_remain_open() {
        macro_rules! assert_request_closed {
            ($type:ty, $json:expr) => {{
                assert_closed_schema::<$type>();
                let value = $json;
                serde_json::from_value::<$type>(value.clone()).unwrap();
                let mut unknown = value;
                unknown
                    .as_object_mut()
                    .unwrap()
                    .insert("unknown".to_string(), serde_json::json!(true));
                assert!(serde_json::from_value::<$type>(unknown).is_err());
            }};
        }

        assert_request_closed!(
            ListXrefsRequest,
            serde_json::json!({"drawing_path": "/h.dwg"})
        );
        assert_request_closed!(
            GetXrefRequest,
            serde_json::json!({"drawing_path": "/h.dwg", "handle": "2A"})
        );
        assert_request_closed!(
            AttachXrefRequest,
            serde_json::json!({
                "drawing_path": "/h.dwg",
                "xref_path": "site.dwg",
                "reference_type": "attachment"
            })
        );
        assert_request_closed!(
            UpdateXrefRequest,
            serde_json::json!({
                "drawing_path": "/h.dwg",
                "handle": "2A",
                "properties": {"future_property": {"any": "shape"}}
            })
        );
        assert_request_closed!(
            DetachXrefRequest,
            serde_json::json!({"drawing_path": "/h.dwg", "name": "SITE"})
        );
        assert_request_closed!(
            ListXrefInstancesRequest,
            serde_json::json!({"drawing_path": "/h.dwg", "owner_type": "model_space"})
        );
        assert_request_closed!(
            GetXrefInstanceRequest,
            serde_json::json!({"drawing_path": "/h.dwg", "handle": "40"})
        );
        assert_request_closed!(
            InsertXrefInstanceRequest,
            serde_json::json!({"drawing_path": "/h.dwg", "attachment_handle": "2A"})
        );
        assert_request_closed!(
            UpdateXrefInstanceRequest,
            serde_json::json!({
                "drawing_path": "/h.dwg",
                "handle": "40",
                "properties": {"future_property": true}
            })
        );
        assert_request_closed!(
            DeleteXrefInstanceRequest,
            serde_json::json!({"drawing_path": "/h.dwg", "handle": "40"})
        );
        assert_request_closed!(
            ReloadXrefRequest,
            serde_json::json!({"drawing_path": "/h.dwg", "handle": "2A"})
        );
        assert_request_closed!(
            UnloadXrefRequest,
            serde_json::json!({"drawing_path": "/h.dwg", "handle": "2A"})
        );
        assert_request_closed!(
            ResolveXrefPathRequest,
            serde_json::json!({"drawing_path": "/h.dwg", "handle": "2A"})
        );
        assert_request_closed!(
            ListXrefDependenciesRequest,
            serde_json::json!({"drawing_path": "/h.dwg", "max_depth": 32, "max_nodes": 10000})
        );
        assert_request_closed!(
            BindXrefRequest,
            serde_json::json!({
                "drawing_path": "/h.dwg",
                "handle": "2A",
                "symbol_strategy": "prefix",
                "dependency_strategy": "reject_nested"
            })
        );
        assert_request_closed!(
            XrefSelector,
            serde_json::json!({"handle": "2A", "name": "SITE"})
        );
        assert_request_closed!(XrefInstanceSelector, serde_json::json!({"handle": "40"}));
        assert_request_closed!(
            XrefAttachmentGuards,
            serde_json::json!({"expected_handle": "2A", "expected_name": "SITE"})
        );
        assert_request_closed!(
            XrefDestructiveAttachmentGuards,
            serde_json::json!({
                "expected_handle": "2A",
                "expected_instance_count": 1,
                "expected_instance_handles": ["40"]
            })
        );
        assert_request_closed!(
            XrefInstanceGuards,
            serde_json::json!({
                "expected_attachment_handle": "2A",
                "expected_owner_handle": "1F"
            })
        );

        assert!(serde_json::from_value::<GetXrefRequest>(serde_json::json!({
            "drawing_path": "/h.dwg",
            "handle": 42
        }))
        .is_err());
        assert!(serde_json::from_value::<GetXrefRequest>(serde_json::json!({
            "drawing_path": "/h.dwg",
            "handle": null
        }))
        .is_err());
        assert!(
            serde_json::from_value::<DetachXrefRequest>(serde_json::json!({
                "drawing_path": "/h.dwg",
                "handle": "2A",
                "expected_instance_handles": ["40", 41]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AttachXrefRequest>(serde_json::json!({
                "drawing_path": "/h.dwg",
                "xref_path": "site.dwg",
                "reference_type": "attachment",
                "placement": null
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<XrefLayerReconciliation>(serde_json::json!({
                "mode": "drawing_policy",
                "properties": null
            }))
            .is_err()
        );
        assert!(serde_json::from_value::<XrefPlacement>(serde_json::json!({
            "layer_handle": "10",
            "array": {"rows": 1, "columns": 1, "row_spacing": 0, "column_spacing": 0}
        }))
        .is_err());
        assert!(
            serde_json::from_value::<XrefInstancePlacement>(serde_json::json!({
                "layer_handle": 16
            }))
            .is_err()
        );
    }

    #[test]
    fn complete_evidence_contract_extends_legacy_states_without_breaking_them() {
        let legacy = xref(
            "2A",
            "SITE_MODEL",
            "../refs/site.dwg",
            ReferenceType::Attachment,
        );
        let complete = XrefDomainEvidence::from(&legacy);
        assert_eq!(complete.handle, XrefEvidenceValue::Proven("2A".to_string()));
        assert_eq!(
            complete.saved_path,
            XrefEvidenceValue::Proven("../refs/site.dwg".to_string())
        );
        assert_eq!(
            complete.membership,
            XrefMembershipEvidence::Direct(ReferenceType::Attachment)
        );
        assert!(matches!(
            complete.load_state,
            XrefEvidenceValue::Unavailable(_)
        ));
        assert!(matches!(
            complete.definition_base_point,
            XrefEvidenceValue::Unavailable(_)
        ));
        assert!(matches!(
            complete.insertion_units,
            XrefEvidenceValue::Unavailable(_)
        ));
        assert!(matches!(
            complete.instances,
            XrefEvidenceValue::Unavailable(_)
        ));

        let states = [
            XrefEvidenceValue::<u8>::proven(1),
            XrefEvidenceValue::unavailable("not projected"),
            XrefEvidenceValue::unsupported("unsupported encoding"),
            XrefEvidenceValue::contradictory("owner links disagree"),
        ];
        assert!(matches!(states[0], XrefEvidenceValue::Proven(1)));
        assert!(matches!(states[1], XrefEvidenceValue::Unavailable(_)));
        assert!(matches!(states[2], XrefEvidenceValue::Unsupported(_)));
        assert!(matches!(states[3], XrefEvidenceValue::Contradictory(_)));

        let memberships = [
            XrefMembershipEvidence::External(ReferenceType::Overlay),
            XrefMembershipEvidence::Unavailable("flags absent".to_string()),
            XrefMembershipEvidence::Contradictory("owner mismatch".to_string()),
        ];
        assert!(matches!(
            memberships[0],
            XrefMembershipEvidence::External(_)
        ));
        assert!(matches!(
            memberships[1],
            XrefMembershipEvidence::Unavailable(_)
        ));
        assert!(matches!(
            memberships[2],
            XrefMembershipEvidence::Contradictory(_)
        ));
    }

    #[test]
    fn numeric_handle_and_chain_ordering_do_not_overflow_or_sort_lexically() {
        assert_eq!(compare_numeric_handles("F", "10").unwrap(), Ordering::Less);
        assert_eq!(
            compare_numeric_handles("0x0010", "10").unwrap(),
            Ordering::Equal
        );
        assert_eq!(
            compare_numeric_handles("100", "FF").unwrap(),
            Ordering::Greater
        );
        assert_eq!(
            compare_numeric_handles(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "100000000000000000000000000000000"
            )
            .unwrap(),
            Ordering::Less
        );

        let mut handles = ["100", "2", "10", "F", "A"];
        handles.sort_by(|left, right| compare_numeric_handles(left, right).unwrap());
        assert_eq!(handles, ["2", "A", "F", "10", "100"]);

        let chains = [
            vec!["10".to_string()],
            vec!["F".to_string(), "100".to_string()],
            vec!["F".to_string()],
            vec!["F".to_string(), "2".to_string()],
        ];
        let mut sorted = chains.clone();
        sorted.sort_by(|left, right| compare_handle_chains(left, right).unwrap());
        assert_eq!(
            sorted,
            [
                vec!["F".to_string()],
                vec!["F".to_string(), "2".to_string()],
                vec!["F".to_string(), "100".to_string()],
                vec!["10".to_string()],
            ]
        );
        assert_eq!(
            compare_handle_chains(
                &["0x000F".to_string(), "02".to_string()],
                &["F".to_string(), "2".to_string()]
            )
            .unwrap(),
            Ordering::Equal
        );
        assert_eq!(
            compare_handle_chains(&[], &["1".to_string()])
                .unwrap_err()
                .code(),
            "invalid_parameters"
        );
    }

    #[test]
    fn record_and_bind_sort_helpers_apply_the_public_numeric_orders() {
        let mut attachments = vec![
            complete_attachment("100"),
            complete_attachment("F"),
            complete_attachment("10"),
        ];
        sort_xref_attachment_records(&mut attachments).unwrap();
        assert_eq!(
            attachments
                .iter()
                .map(|record| record.handle.as_str())
                .collect::<Vec<_>>(),
            ["F", "10", "100"]
        );

        let mut instances = vec![
            complete_instance("100", XrefPlacementKind::Single),
            complete_instance("F", XrefPlacementKind::Single),
            complete_instance("10", XrefPlacementKind::Single),
        ];
        sort_xref_instance_records(&mut instances).unwrap();
        assert_eq!(
            instances
                .iter()
                .map(|record| record.handle.as_str())
                .collect::<Vec<_>>(),
            ["F", "10", "100"]
        );

        let mut dependencies = vec![root_dependency("10"), root_dependency("F")];
        sort_xref_dependency_records(&mut dependencies).unwrap();
        assert_eq!(dependencies[0].attachment_chain, ["F"]);
        assert_eq!(dependencies[1].attachment_chain, ["10"]);

        let mut instance_mappings = vec![
            XrefInstanceHandleMapping {
                attachment_chain: vec!["10".to_string()],
                old_handle: "1".to_string(),
                new_handle: "1".to_string(),
            },
            XrefInstanceHandleMapping {
                attachment_chain: vec!["F".to_string()],
                old_handle: "100".to_string(),
                new_handle: "100".to_string(),
            },
            XrefInstanceHandleMapping {
                attachment_chain: vec!["F".to_string()],
                old_handle: "10".to_string(),
                new_handle: "10".to_string(),
            },
        ];
        sort_instance_handle_mappings(&mut instance_mappings).unwrap();
        assert_eq!(instance_mappings[0].old_handle, "10");
        assert_eq!(instance_mappings[1].old_handle, "100");
        assert_eq!(instance_mappings[2].attachment_chain, ["10"]);

        let symbol = |symbol_type, source_name: &str, source_handle: &str| XrefSymbolMapping {
            attachment_chain: vec!["F".to_string()],
            symbol_type,
            source_handle: source_handle.to_string(),
            source_name: source_name.to_string(),
            final_handle: source_handle.to_string(),
            final_name: source_name.to_string(),
            resolution: XrefSymbolResolution::Imported,
        };
        let mut symbol_mappings = vec![
            symbol(XrefSymbolType::Layer, "beta", "2"),
            symbol(XrefSymbolType::Block, "zeta", "3"),
            symbol(XrefSymbolType::Layer, "ALPHA", "10"),
            symbol(XrefSymbolType::Layer, "alpha", "F"),
        ];
        sort_symbol_mappings(&mut symbol_mappings).unwrap();
        assert_eq!(symbol_mappings[0].symbol_type, XrefSymbolType::Block);
        assert_eq!(symbol_mappings[1].source_name, "ALPHA");
        assert_eq!(symbol_mappings[2].source_name, "alpha");
        assert_eq!(symbol_mappings[3].source_name, "beta");
    }

    #[test]
    fn expected_handle_sets_are_canonical_unique_and_numeric() {
        assert_eq!(
            canonicalize_unique_handle_set(&[
                "0x10".to_string(),
                "2".to_string(),
                "000F".to_string(),
            ])
            .unwrap(),
            ["2", "F", "10"]
        );
        assert_eq!(
            canonicalize_unique_handle_set(&["A".to_string(), "0x000a".to_string()])
                .unwrap_err()
                .code(),
            "invalid_parameters"
        );
        assert_eq!(
            canonicalize_unique_handle_set(&["G".to_string()])
                .unwrap_err()
                .code(),
            "invalid_handle"
        );
    }

    #[test]
    fn name_comparison_is_locale_independent_case_insensitive_and_deterministic() {
        assert!(xref_name_eq("Straße", "STRASSE"));
        assert!(!xref_name_eq("STRASSE", "STRASSe\u{301}"));
        assert_eq!(compare_xref_names("site", "SITE"), Ordering::Greater);
        assert_eq!(compare_xref_names("alpha", "BETA"), Ordering::Less);

        let mut names = ["site", "BETA", "SITE", "alpha"];
        names.sort_by(|left, right| compare_xref_names(left, right));
        assert_eq!(names, ["alpha", "BETA", "SITE", "site"]);
    }

    #[test]
    fn shared_name_placement_reconciliation_and_guard_validators_are_exact() {
        for valid in [
            "SITE",
            "Site Model",
            "\u{5efa}\u{7bc9}\u{30e2}\u{30c7}\u{30eb}",
        ] {
            validate_xref_name(valid).unwrap();
        }
        for invalid in ["", " SITE", "SITE ", "SITE/PLAN", "SITE|PLAN", "SITE\nPLAN"] {
            assert_eq!(
                validate_xref_name(invalid).unwrap_err().code(),
                "invalid_xref_name"
            );
        }
        assert_eq!(
            validate_xref_name(&"X".repeat(256)).unwrap_err().code(),
            "invalid_xref_name"
        );

        let placement = XrefPlacement {
            owner_handle: Some("0x001f".to_string()),
            owner_type: Some(XrefOwnerType::ModelSpace),
            owner_name: Some("Model".to_string()),
            layer_handle: Some("000a".to_string()),
            layer_name: Some("0".to_string()),
            insertion_point: Some(point(1.0, 2.0, 3.0)),
            scale: Some(scale(-1.0, 2.0, 3.0)),
            rotation_degrees: Some(-90.0),
            normal: Some(vector(0.0, 0.0, 1.0 + 0.5e-12)),
            visibility: Some(XrefVisibility::Hidden),
        }
        .canonicalized()
        .unwrap();
        assert_eq!(placement.owner_handle.as_deref(), Some("1F"));
        assert_eq!(placement.layer_handle.as_deref(), Some("A"));
        assert_eq!(placement.rotation_degrees, Some(270.0));
        assert_eq!(placement.normal, Some(XrefVector3::WORLD_Z));

        let invalid_owner = XrefPlacement {
            owner_handle: None,
            owner_type: Some(XrefOwnerType::ModelSpace),
            owner_name: None,
            layer_handle: None,
            layer_name: None,
            insertion_point: None,
            scale: None,
            rotation_degrees: None,
            normal: None,
            visibility: None,
        };
        assert_eq!(
            invalid_owner.canonicalized().unwrap_err().code(),
            "invalid_xref_owner"
        );

        XrefLayerReconciliation {
            mode: LayerReconciliationMode::Synchronize,
            properties: Some(vec![XrefLayerProperty::Off]),
        }
        .validate()
        .unwrap();
        for invalid in [
            XrefLayerReconciliation {
                mode: LayerReconciliationMode::Synchronize,
                properties: Some(Vec::new()),
            },
            XrefLayerReconciliation {
                mode: LayerReconciliationMode::PreserveHost,
                properties: Some(vec![XrefLayerProperty::Off]),
            },
            XrefLayerReconciliation {
                mode: LayerReconciliationMode::Synchronize,
                properties: Some(vec![XrefLayerProperty::Off, XrefLayerProperty::Off]),
            },
        ] {
            assert_eq!(
                invalid.validate().unwrap_err().code(),
                "invalid_layer_reconciliation"
            );
        }

        let guards = XrefDestructiveAttachmentGuards {
            expected_handle: Some("0x002a".to_string()),
            expected_name: Some("SITE".to_string()),
            expected_instance_count: Some(2),
            expected_instance_handles: Some(vec!["10".to_string(), "0x000f".to_string()]),
        }
        .canonicalized()
        .unwrap();
        assert_eq!(guards.expected_handle.as_deref(), Some("2A"));
        assert_eq!(
            guards.expected_instance_handles.unwrap(),
            ["F".to_string(), "10".to_string()]
        );
    }

    #[test]
    fn point_scale_rotation_and_normal_validation_use_exact_contract_tolerances() {
        assert_eq!(
            point(1.0, 2.0, 3.0).validate().unwrap(),
            point(1.0, 2.0, 3.0)
        );
        assert_eq!(
            point(f64::INFINITY, 0.0, 0.0)
                .validate()
                .unwrap_err()
                .code(),
            "invalid_xref_placement"
        );

        assert_eq!(
            scale(-1.0, 2.0, -3.0).validate().unwrap(),
            scale(-1.0, 2.0, -3.0)
        );
        for invalid in [
            scale(0.0, 1.0, 1.0),
            scale(1.0, f64::NAN, 1.0),
            scale(1.0, 1.0, f64::INFINITY),
        ] {
            assert_eq!(invalid.validate().unwrap_err().code(), "invalid_xref_scale");
        }

        assert_eq!(normalize_rotation_degrees(0.0).unwrap(), 0.0);
        assert_eq!(normalize_rotation_degrees(360.0).unwrap(), 0.0);
        assert_eq!(normalize_rotation_degrees(810.0).unwrap(), 90.0);
        assert_eq!(normalize_rotation_degrees(-90.0).unwrap(), 270.0);
        assert_eq!(
            normalize_rotation_degrees(f64::NAN).unwrap_err().code(),
            "invalid_xref_placement"
        );

        assert_vector(
            vector(0.0, 0.0, 1.0 + 0.5e-12).canonical_normal().unwrap(),
            XrefVector3::WORLD_Z,
        );
        let almost_z = vector(0.5e-15, 0.0, 1.0);
        assert_eq!(almost_z.canonical_normal().unwrap().x, 0.0);
        for invalid in [
            vector(0.0, 0.0, 0.0),
            vector(0.0, 0.0, 1.0 + 2.0e-12),
            vector(f64::INFINITY, 0.0, 0.0),
        ] {
            assert_eq!(
                invalid.canonical_normal().unwrap_err().code(),
                "invalid_xref_normal"
            );
        }
    }

    #[test]
    fn arbitrary_axis_basis_and_source_transform_follow_the_spec_formula() {
        let world = xref_ocs_basis(XrefVector3::WORLD_Z).unwrap();
        assert_vector(world.x_axis, vector(1.0, 0.0, 0.0));
        assert_vector(world.y_axis, vector(0.0, 1.0, 0.0));
        assert_vector(world.normal, XrefVector3::WORLD_Z);

        let horizontal = xref_ocs_basis(vector(0.0, 1.0, 0.0)).unwrap();
        assert_vector(horizontal.x_axis, vector(-1.0, 0.0, 0.0));
        assert_vector(horizontal.y_axis, vector(0.0, 0.0, 1.0));
        assert_vector(horizontal.normal, vector(0.0, 1.0, 0.0));

        let threshold_normal = vector(1.0 / 64.0, 0.0, (1.0 - (1.0 / 64.0_f64).powi(2)).sqrt());
        let threshold_basis = xref_ocs_basis(threshold_normal).unwrap();
        assert!(threshold_basis.x_axis.y > 0.999);

        let transformed = transform_xref_point(
            point(11.0, 22.0, 4.0),
            point(1.0, 2.0, 3.0),
            point(100.0, 200.0, 300.0),
            scale(2.0, 3.0, 4.0),
            90.0,
            XrefVector3::WORLD_Z,
        )
        .unwrap();
        assert_point(transformed, point(40.0, 220.0, 304.0));
    }

    #[test]
    fn minsert_arrays_preserve_one_by_one_class_and_accept_the_maximum_counts() {
        let one = XrefRectangularArray {
            rows: 1,
            columns: 1,
            row_spacing: 10.0,
            column_spacing: 20.0,
        };
        assert_eq!(one.validate().unwrap().cell_count().unwrap(), 1);
        let mut one_record = complete_instance("40", XrefPlacementKind::RectangularArray);
        one_record.array = Some(one);
        let one_record = one_record.canonicalized().unwrap();
        assert_eq!(
            one_record.placement_kind,
            XrefPlacementKind::RectangularArray
        );
        assert_eq!(one_record.array, Some(one));

        let maximum = XrefRectangularArray {
            rows: 65_535,
            columns: 65_535,
            row_spacing: -1.0,
            column_spacing: 0.0,
        };
        assert_eq!(maximum.cell_count().unwrap(), 4_294_836_225);
        for invalid in [
            XrefRectangularArray { rows: 0, ..one },
            XrefRectangularArray {
                columns: 65_536,
                ..one
            },
            XrefRectangularArray {
                row_spacing: f64::NAN,
                ..one
            },
        ] {
            assert_eq!(
                invalid.validate().unwrap_err().code(),
                "invalid_xref_placement"
            );
        }

        assert_point(
            xref_array_cell_insertion_point(
                point(100.0, 200.0, 0.0),
                XrefRectangularArray {
                    rows: 2,
                    columns: 3,
                    row_spacing: 10.0,
                    column_spacing: 20.0,
                },
                1,
                2,
                90.0,
                XrefVector3::WORLD_Z,
            )
            .unwrap(),
            point(90.0, 240.0, 0.0),
        );
        assert_eq!(
            xref_array_cell_insertion_point(
                XrefPoint3::ORIGIN,
                one,
                1,
                0,
                0.0,
                XrefVector3::WORLD_Z,
            )
            .unwrap_err()
            .code(),
            "invalid_xref_placement"
        );
    }

    #[test]
    fn property_classification_is_exhaustive_disjoint_and_exact() {
        let attachment_writable = ["name", "xref_path", "reference_type"];
        let attachment_unsupported = [
            "handle",
            "saved_path",
            "path_mode",
            "load_state",
            "instance_count",
            "definition_base_point",
            "attachment_handle",
            "attachment_name",
            "owner_handle",
            "owner_type",
            "owner_name",
            "layer_handle",
            "layer_name",
            "insertion_point",
            "scale",
            "rotation_degrees",
            "normal",
            "visibility",
            "placement_kind",
            "array",
            "unit_scaling",
            "search_paths",
            "layer_reconciliation",
            "unit_assumptions",
            "symbol_strategy",
            "dependency_strategy",
        ];
        assert_eq!(ATTACHMENT_WRITABLE_PROPERTIES, attachment_writable);
        assert_eq!(ATTACHMENT_UNSUPPORTED_PROPERTIES, attachment_unsupported);
        for key in attachment_writable {
            assert_eq!(
                classify_attachment_update_property(key),
                XrefPropertyClassification::Writable
            );
        }
        for key in attachment_unsupported {
            assert_eq!(
                classify_attachment_update_property(key),
                XrefPropertyClassification::Unsupported
            );
        }
        assert_eq!(
            classify_attachment_update_property("future_property"),
            XrefPropertyClassification::Unknown
        );

        let instance_writable = [
            "insertion_point",
            "scale",
            "rotation_degrees",
            "normal",
            "layer_handle",
            "layer_name",
            "visibility",
            "array",
        ];
        let instance_unsupported = [
            "handle",
            "attachment_handle",
            "attachment_name",
            "owner_handle",
            "owner_type",
            "owner_name",
            "placement_kind",
            "unit_scaling",
            "saved_path",
            "path_mode",
            "reference_type",
            "load_state",
            "instance_count",
            "definition_base_point",
            "color_index",
            "true_color",
            "color_book",
            "color_name",
            "line_type",
            "line_weight",
            "material_handle",
            "plotstyle_handle",
            "transparency",
            "clip",
            "clip_handle",
        ];
        assert_eq!(INSTANCE_WRITABLE_PROPERTIES, instance_writable);
        assert_eq!(INSTANCE_UNSUPPORTED_PROPERTIES, instance_unsupported);
        for key in instance_writable {
            assert_eq!(
                classify_instance_update_property(key),
                XrefPropertyClassification::Writable
            );
        }
        for key in instance_unsupported {
            assert_eq!(
                classify_instance_update_property(key),
                XrefPropertyClassification::Unsupported
            );
        }
        assert_eq!(
            classify_instance_update_property("future_property"),
            XrefPropertyClassification::Unknown
        );

        for (writable, unsupported) in [
            (
                ATTACHMENT_WRITABLE_PROPERTIES,
                ATTACHMENT_UNSUPPORTED_PROPERTIES,
            ),
            (
                INSTANCE_WRITABLE_PROPERTIES,
                INSTANCE_UNSUPPORTED_PROPERTIES,
            ),
        ] {
            assert_eq!(
                writable.iter().copied().collect::<BTreeSet<_>>().len(),
                writable.len()
            );
            assert_eq!(
                unsupported.iter().copied().collect::<BTreeSet<_>>().len(),
                unsupported.len()
            );
            assert!(writable.iter().all(|key| !unsupported.contains(key)));
        }
    }

    #[test]
    fn shared_failure_groups_expand_to_the_exact_sorted_contract() {
        fn assert_group(group: XrefFailureGroup, expected: &[&'static str]) {
            let expected = expected.iter().copied().collect::<BTreeSet<_>>();
            assert_eq!(
                xref_shared_failure_codes(group),
                expected.into_iter().collect::<Vec<_>>()
            );
        }

        assert_group(
            XrefFailureGroup::Read,
            &[
                "invalid_parameters",
                "drawing_not_found",
                "drawing_unreadable",
                "unsupported_format",
                "unsupported_xref_data",
            ],
        );
        assert_group(
            XrefFailureGroup::Mutation,
            &[
                "invalid_parameters",
                "drawing_not_found",
                "drawing_unreadable",
                "unsupported_format",
                "unsupported_xref_data",
                "unsupported_platform",
                "autocad_unavailable",
                "drawing_locked",
                "concurrent_drawing_modification",
                "write_failed",
                "verification_failed",
                "mutation_state_unknown",
            ],
        );
        assert_group(
            XrefFailureGroup::AttachmentIdentity,
            &[
                "missing_identity",
                "invalid_handle",
                "xref_not_found",
                "ambiguous_identity",
                "contradictory_identity",
            ],
        );
        assert_group(
            XrefFailureGroup::InstanceIdentity,
            &["invalid_handle", "xref_instance_not_found"],
        );
        assert_group(
            XrefFailureGroup::AttachmentGuards,
            &["expected_handle_mismatch", "expected_name_mismatch"],
        );
        assert_group(
            XrefFailureGroup::DestructiveGuards,
            &[
                "expected_instance_count_mismatch",
                "expected_instance_handles_mismatch",
            ],
        );
        assert_group(
            XrefFailureGroup::InstanceGuards,
            &[
                "expected_attachment_handle_mismatch",
                "expected_owner_handle_mismatch",
            ],
        );
        assert_group(
            XrefFailureGroup::SourceGraph,
            &[
                "xref_source_not_found",
                "xref_source_unreadable",
                "unsupported_xref_source",
                "circular_xref",
                "xref_source_changed",
                "dependency_traversal_incomplete",
            ],
        );
        assert_group(
            XrefFailureGroup::SourceRead,
            &[
                "xref_source_not_found",
                "xref_source_unreadable",
                "unsupported_xref_source",
                "xref_source_changed",
            ],
        );
        assert_group(
            XrefFailureGroup::Units,
            &[
                "ambiguous_insertion_units",
                "invalid_unit_assumptions",
                "unsupported_insertion_units",
            ],
        );
        assert_group(
            XrefFailureGroup::OwnerPlacement,
            &[
                "invalid_handle",
                "contradictory_identity",
                "invalid_xref_placement",
                "invalid_xref_scale",
                "invalid_xref_normal",
                "invalid_xref_owner",
                "xref_owner_not_found",
                "unsupported_xref_owner",
                "layer_not_found",
                "layer_not_host_owned",
                "recursive_block_reference",
            ],
        );
        assert_group(
            XrefFailureGroup::Properties,
            &[
                "invalid_xref_property",
                "unsupported_xref_property",
                "empty_xref_update",
            ],
        );
    }

    #[test]
    fn every_tool_failure_set_is_the_exact_union_from_the_spec() {
        fn assert_tool(tool: XrefTool, groups: &[XrefFailureGroup], additional: &[&'static str]) {
            let mut expected = BTreeSet::new();
            for group in groups {
                expected.extend(xref_shared_failure_codes(*group));
            }
            expected.extend(additional.iter().copied());
            assert_eq!(
                xref_failure_codes(tool),
                expected.into_iter().collect::<Vec<_>>(),
                "tool={tool:?}"
            );
        }

        use XrefFailureGroup as Group;
        assert_tool(XrefTool::ListXrefs, &[Group::Read], &[]);
        assert_tool(
            XrefTool::GetXref,
            &[Group::Read, Group::AttachmentIdentity],
            &[],
        );
        assert_tool(
            XrefTool::ListXrefInstances,
            &[Group::Read, Group::AttachmentIdentity],
            &[
                "invalid_xref_owner",
                "xref_owner_not_found",
                "layer_not_found",
            ],
        );
        assert_tool(
            XrefTool::GetXrefInstance,
            &[Group::Read, Group::InstanceIdentity],
            &[],
        );
        for tool in [XrefTool::ResolveXrefPath, XrefTool::ListXrefDependencies] {
            assert_tool(
                tool,
                &[Group::Read, Group::AttachmentIdentity],
                &["invalid_search_path"],
            );
        }
        assert_tool(
            XrefTool::AttachXref,
            &[
                Group::Mutation,
                Group::OwnerPlacement,
                Group::SourceGraph,
                Group::Units,
            ],
            &[
                "invalid_xref_name",
                "xref_name_collision",
                "invalid_xref_path",
                "invalid_search_path",
            ],
        );
        assert_tool(
            XrefTool::UpdateXref,
            &[
                Group::Mutation,
                Group::AttachmentIdentity,
                Group::AttachmentGuards,
                Group::Properties,
                Group::SourceGraph,
                Group::Units,
            ],
            &[
                "invalid_xref_name",
                "xref_name_collision",
                "invalid_xref_path",
                "invalid_search_path",
                "invalid_layer_reconciliation",
                "unsupported_xref_clip_data",
            ],
        );
        assert_tool(
            XrefTool::DetachXref,
            &[
                Group::Mutation,
                Group::AttachmentIdentity,
                Group::AttachmentGuards,
                Group::DestructiveGuards,
            ],
            &[
                "unsupported_xref_owner",
                "xref_instance_locked",
                "unsupported_xref_clip_data",
            ],
        );
        assert_tool(
            XrefTool::InsertXrefInstance,
            &[
                Group::Mutation,
                Group::AttachmentIdentity,
                Group::OwnerPlacement,
                Group::SourceRead,
                Group::Units,
            ],
            &["expected_attachment_handle_mismatch"],
        );
        assert_tool(
            XrefTool::UpdateXrefInstance,
            &[
                Group::Mutation,
                Group::InstanceIdentity,
                Group::InstanceGuards,
                Group::Properties,
            ],
            &[
                "contradictory_identity",
                "invalid_xref_placement",
                "invalid_xref_scale",
                "invalid_xref_normal",
                "unsupported_xref_owner",
                "layer_not_found",
                "layer_not_host_owned",
                "xref_instance_locked",
                "unsupported_xref_clip_data",
            ],
        );
        assert_tool(
            XrefTool::DeleteXrefInstance,
            &[
                Group::Mutation,
                Group::InstanceIdentity,
                Group::InstanceGuards,
            ],
            &[
                "unsupported_xref_owner",
                "xref_instance_locked",
                "unsupported_xref_clip_data",
            ],
        );
        assert_tool(
            XrefTool::ReloadXref,
            &[
                Group::Mutation,
                Group::AttachmentIdentity,
                Group::AttachmentGuards,
                Group::SourceGraph,
                Group::Units,
            ],
            &[
                "invalid_search_path",
                "invalid_layer_reconciliation",
                "unsupported_xref_clip_data",
            ],
        );
        assert_tool(
            XrefTool::UnloadXref,
            &[
                Group::Mutation,
                Group::AttachmentIdentity,
                Group::AttachmentGuards,
            ],
            &["unsupported_xref_clip_data"],
        );
        assert_tool(
            XrefTool::BindXref,
            &[
                Group::Mutation,
                Group::AttachmentIdentity,
                Group::AttachmentGuards,
                Group::DestructiveGuards,
                Group::SourceGraph,
            ],
            &[
                "invalid_search_path",
                "unsupported_xref_owner",
                "xref_instance_locked",
                "nested_xrefs_present",
                "unsupported_xref_content",
                "unsupported_xref_clip_data",
            ],
        );
    }

    fn xref(handle: &str, name: &str, path: &str, reference_type: ReferenceType) -> XrefEvidence {
        XrefEvidence {
            handle: XrefFact::proven(handle.to_string()),
            name: XrefFact::proven(name.to_string()),
            membership: XrefMembership::Xref(reference_type),
            path: XrefFact::proven(path.to_string()),
            load_state: LoadState::Unavailable,
        }
    }

    fn ordinary(handle: &str, name: &str) -> XrefEvidence {
        XrefEvidence {
            handle: XrefFact::proven(handle.to_string()),
            name: XrefFact::proven(name.to_string()),
            membership: XrefMembership::NotXref,
            path: XrefFact::unsupported("ordinary block path is irrelevant"),
            load_state: LoadState::Unavailable,
        }
    }

    fn selector(handle: Option<&str>, name: Option<&str>) -> XrefSelector {
        XrefSelector {
            handle: handle.map(str::to_string),
            name: name.map(str::to_string),
        }
    }

    #[test]
    fn record_schema_and_enum_values_are_exact() {
        let record = XrefRecord {
            handle: "A1".to_string(),
            name: "SITE_MODEL".to_string(),
            path: "refs/site.dwg".to_string(),
            reference_type: ReferenceType::Attachment,
            load_state: LoadState::Unavailable,
        };
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "handle": "A1",
                "name": "SITE_MODEL",
                "path": "refs/site.dwg",
                "reference_type": "attachment",
                "load_state": "unavailable"
            })
        );
        assert!(value.get("is_overlay").is_none());
        assert_eq!(
            serde_json::to_value(ReferenceType::Overlay).unwrap(),
            "overlay"
        );
        assert_eq!(serde_json::to_value(LoadState::Loaded).unwrap(), "loaded");
        assert_eq!(
            serde_json::to_value(LoadState::Unloaded).unwrap(),
            "unloaded"
        );
    }

    #[test]
    fn handle_normalization_accepts_hex_without_numeric_overflow() {
        assert_eq!(canonical_input_handle("A1").unwrap(), "A1");
        assert_eq!(canonical_input_handle("a1").unwrap(), "A1");
        assert_eq!(canonical_input_handle("0x00a1").unwrap(), "A1");
        assert_eq!(canonical_input_handle("0X10").unwrap(), "10");
        assert_eq!(canonical_input_handle("123").unwrap(), "123");
        assert_eq!(canonical_input_handle("000").unwrap(), "0");
        assert_eq!(
            canonical_input_handle("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap(),
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        );
    }

    #[test]
    fn invalid_handle_syntax_is_reason_coded() {
        for invalid in ["", " ", " 10", "10 ", "+10", "-10", "0x", "0X", "G1"] {
            let err = canonical_input_handle(invalid).unwrap_err();
            assert_eq!(err.code(), "invalid_handle", "input={invalid:?}");
        }
    }

    #[test]
    fn list_returns_only_xrefs_in_numeric_handle_order() {
        let mut ordinary_with_unknown_handle = ordinary("10", "*Model_Space");
        ordinary_with_unknown_handle.handle = XrefFact::unsupported("ordinary handle unavailable");
        let evidence = vec![
            ordinary_with_unknown_handle,
            xref(
                "A2",
                "SITE_MODEL",
                "refs/site.dwg",
                ReferenceType::Attachment,
            ),
            xref("F", "FIRST", "refs/first.dwg", ReferenceType::Attachment),
            xref(
                "10",
                "GRID_OVERLAY",
                "refs/grid.dwg",
                ReferenceType::Overlay,
            ),
        ];
        let records = list_xrefs(&evidence).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].handle, "F");
        assert_eq!(records[1].handle, "10");
        assert_eq!(records[2].handle, "A2");
    }

    #[test]
    fn get_resolves_handle_name_and_matching_pair() {
        let evidence = vec![
            xref(
                "A1",
                "Site_Model",
                "refs/site.dwg",
                ReferenceType::Attachment,
            ),
            xref(
                "A2",
                "GRID_OVERLAY",
                "refs/grid.dwg",
                ReferenceType::Overlay,
            ),
        ];
        assert_eq!(
            get_xref(&evidence, &selector(Some("0x00a1"), None))
                .unwrap()
                .name,
            "Site_Model"
        );
        assert_eq!(
            get_xref(&evidence, &selector(None, Some("site_model")))
                .unwrap()
                .handle,
            "A1"
        );
        assert_eq!(
            get_xref(&evidence, &selector(Some("A1"), Some("SITE_MODEL")))
                .unwrap()
                .path,
            "refs/site.dwg"
        );
    }

    #[test]
    fn name_matching_uses_unicode_uppercase_without_normalization() {
        let evidence = vec![xref(
            "A1",
            "Straße",
            "refs/street.dwg",
            ReferenceType::Attachment,
        )];
        assert_eq!(
            get_xref(&evidence, &selector(None, Some("STRASSE")))
                .unwrap()
                .handle,
            "A1"
        );
        assert_eq!(
            get_xref(&evidence, &selector(None, Some("STRASSe\u{301}")))
                .unwrap_err()
                .code(),
            "xref_not_found"
        );
    }

    #[test]
    fn missing_and_invalid_identity_are_distinct() {
        let evidence = vec![xref(
            "A1",
            "SITE_MODEL",
            "refs/site.dwg",
            ReferenceType::Attachment,
        )];
        assert_eq!(
            get_xref(&evidence, &selector(None, None))
                .unwrap_err()
                .code(),
            "missing_identity"
        );
        assert_eq!(
            get_xref(&evidence, &selector(None, Some("   ")))
                .unwrap_err()
                .code(),
            "missing_identity"
        );
        assert_eq!(
            get_xref(&evidence, &selector(Some("xyz"), Some("SITE_MODEL")))
                .unwrap_err()
                .code(),
            "invalid_handle"
        );
        assert_eq!(
            get_xref(&evidence, &selector(Some("A1"), Some("   ")))
                .unwrap_err()
                .code(),
            "xref_not_found"
        );
    }

    #[test]
    fn missing_and_non_xref_targets_return_not_found() {
        let evidence = vec![
            ordinary("10", "DETAIL"),
            xref(
                "A1",
                "SITE_MODEL",
                "refs/site.dwg",
                ReferenceType::Attachment,
            ),
        ];
        for target in [selector(Some("B0"), None), selector(None, Some("MISSING"))] {
            assert_eq!(
                get_xref(&evidence, &target).unwrap_err().code(),
                "xref_not_found"
            );
        }
        assert_eq!(
            get_xref(&evidence, &selector(Some("10"), None))
                .unwrap_err()
                .code(),
            "xref_not_found"
        );
    }

    #[test]
    fn ambiguous_and_contradictory_identity_are_distinct() {
        let evidence = vec![
            xref("A1", "DUP", "refs/one.dwg", ReferenceType::Attachment),
            xref("A2", "dup", "refs/two.dwg", ReferenceType::Overlay),
            xref("A3", "OTHER", "refs/other.dwg", ReferenceType::Attachment),
        ];
        assert_eq!(
            get_xref(&evidence, &selector(None, Some("DUP")))
                .unwrap_err()
                .code(),
            "ambiguous_identity"
        );
        assert_eq!(
            get_xref(&evidence, &selector(Some("A3"), Some("dup")))
                .unwrap_err()
                .code(),
            "ambiguous_identity"
        );

        let unique = vec![
            xref("A1", "ONE", "refs/one.dwg", ReferenceType::Attachment),
            xref("A2", "TWO", "refs/two.dwg", ReferenceType::Overlay),
        ];
        assert_eq!(
            get_xref(&unique, &selector(Some("A1"), Some("TWO")))
                .unwrap_err()
                .code(),
            "contradictory_identity"
        );
        assert_eq!(
            get_xref(&unique, &selector(Some("A1"), Some("MISSING")))
                .unwrap_err()
                .code(),
            "xref_not_found"
        );
    }

    #[test]
    fn list_fails_when_any_returned_xref_cannot_materialize() {
        let mut broken = xref("A2", "BROKEN", "", ReferenceType::Overlay);
        broken.path = XrefFact::unsupported("stored path was not represented");
        let evidence = vec![
            xref("A1", "GOOD", "refs/good.dwg", ReferenceType::Attachment),
            broken,
        ];
        assert_eq!(
            list_xrefs(&evidence).unwrap_err().code(),
            "unsupported_xref_data"
        );
    }

    #[test]
    fn get_materializes_only_the_selected_target() {
        let mut broken_path = xref("A2", "BROKEN_PATH", "", ReferenceType::Overlay);
        broken_path.path = XrefFact::unsupported("path unavailable");
        let mut broken_handle = xref(
            "A3",
            "BROKEN_HANDLE",
            "refs/broken.dwg",
            ReferenceType::Attachment,
        );
        broken_handle.handle = XrefFact::unsupported("handle unavailable");
        let evidence = vec![
            xref("A1", "GOOD", "refs/good.dwg", ReferenceType::Attachment),
            broken_path,
            broken_handle,
        ];

        assert_eq!(
            get_xref(&evidence, &selector(Some("A1"), None))
                .unwrap()
                .name,
            "GOOD"
        );
        assert_eq!(
            get_xref(&evidence, &selector(None, Some("good")))
                .unwrap()
                .handle,
            "A1"
        );
        assert_eq!(
            list_xrefs(&evidence).unwrap_err().code(),
            "unsupported_xref_data"
        );
    }

    #[test]
    fn name_lookup_fails_when_name_uniqueness_cannot_be_proven() {
        let mut unknown_name = xref("A2", "OTHER", "refs/other.dwg", ReferenceType::Overlay);
        unknown_name.name = XrefFact::unsupported("name unavailable");
        let evidence = vec![
            xref("A1", "GOOD", "refs/good.dwg", ReferenceType::Attachment),
            unknown_name,
        ];
        assert_eq!(
            get_xref(&evidence, &selector(None, Some("GOOD")))
                .unwrap_err()
                .code(),
            "unsupported_xref_data"
        );
        assert_eq!(
            get_xref(&evidence, &selector(Some("A1"), None))
                .unwrap()
                .handle,
            "A1"
        );
    }

    #[test]
    fn proven_name_ambiguity_wins_over_unrelated_unknown_names() {
        let mut unknown_name = xref("A3", "OTHER", "refs/other.dwg", ReferenceType::Overlay);
        unknown_name.name = XrefFact::unsupported("name unavailable");
        let evidence = vec![
            xref("A1", "DUP", "refs/one.dwg", ReferenceType::Attachment),
            unknown_name,
            xref("A2", "dup", "refs/two.dwg", ReferenceType::Overlay),
        ];

        assert_eq!(
            get_xref(&evidence, &selector(None, Some("DUP")))
                .unwrap_err()
                .code(),
            "ambiguous_identity"
        );
    }

    #[test]
    fn selected_target_required_fields_fail_loudly() {
        let mut missing_handle = xref(
            "A1",
            "MISSING_HANDLE",
            "refs/missing.dwg",
            ReferenceType::Attachment,
        );
        missing_handle.handle = XrefFact::unsupported("persisted handle missing");
        assert_eq!(
            get_xref(&[missing_handle], &selector(None, Some("MISSING_HANDLE")))
                .unwrap_err()
                .code(),
            "unsupported_xref_data"
        );

        for persisted_handle in ["0", "NOT_HEX"] {
            let invalid = xref(
                persisted_handle,
                "INVALID_HANDLE",
                "refs/invalid.dwg",
                ReferenceType::Attachment,
            );
            assert_eq!(
                get_xref(&[invalid], &selector(None, Some("INVALID_HANDLE")))
                    .unwrap_err()
                    .code(),
                "unsupported_xref_data"
            );
        }

        let mut missing_name = xref(
            "A2",
            "MISSING_NAME",
            "refs/missing-name.dwg",
            ReferenceType::Attachment,
        );
        missing_name.name = XrefFact::unsupported("persisted name missing");
        assert_eq!(
            get_xref(&[missing_name], &selector(Some("A2"), None))
                .unwrap_err()
                .code(),
            "unsupported_xref_data"
        );

        let mut missing_path = xref(
            "A3",
            "MISSING_PATH",
            "refs/missing-path.dwg",
            ReferenceType::Overlay,
        );
        missing_path.path = XrefFact::unsupported("persisted path missing");
        assert_eq!(
            get_xref(&[missing_path], &selector(Some("A3"), None))
                .unwrap_err()
                .code(),
            "unsupported_xref_data"
        );
    }

    #[test]
    fn unsupported_membership_is_target_local() {
        let unsupported = XrefEvidence {
            handle: XrefFact::proven("A2".to_string()),
            name: XrefFact::proven("BOTH_FLAGS".to_string()),
            membership: XrefMembership::Unsupported("unsupported membership fact".to_string()),
            path: XrefFact::proven("refs/both.dwg".to_string()),
            load_state: LoadState::Unavailable,
        };
        let evidence = vec![
            xref("A1", "GOOD", "refs/good.dwg", ReferenceType::Attachment),
            unsupported,
            ordinary("10", "DETAIL"),
        ];
        assert_eq!(
            get_xref(&evidence, &selector(Some("A1"), None))
                .unwrap()
                .handle,
            "A1"
        );
        assert_eq!(
            get_xref(&evidence, &selector(None, Some("GOOD")))
                .unwrap()
                .handle,
            "A1"
        );
        assert_eq!(
            list_xrefs(&evidence).unwrap_err().code(),
            "unsupported_xref_data"
        );
        assert_eq!(
            get_xref(&evidence, &selector(Some("A2"), None))
                .unwrap_err()
                .code(),
            "unsupported_xref_data"
        );
    }
}
