//! Normalized, post-validation XREF mutation plans for writer backends.
//!
//! These types cover the live route semantics but are not the public MCP
//! transport request schemas. The application adapter remains responsible for
//! transport null handling, schema compatibility, and stable failure codes.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    InsertionUnit, ReferenceType, XrefAttachmentRecord, XrefInstanceRecord, XrefOwnerType,
    XrefPoint3, XrefRectangularArray, XrefScale3, XrefVector3, XrefVisibility,
};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefAttachmentGuard {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefDestructiveAttachmentGuard {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_instance_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_instance_handles: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefInstanceAttachmentGuard {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_attachment_handle: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefInstanceGuard {
    pub handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_attachment_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_owner_handle: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefPlacement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_type: Option<XrefOwnerType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insertion_point: Option<XrefPoint3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale: Option<XrefScale3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_degrees: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normal: Option<XrefVector3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<XrefVisibility>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefInstancePlacement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_type: Option<XrefOwnerType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insertion_point: Option<XrefPoint3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale: Option<XrefScale3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_degrees: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normal: Option<XrefVector3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<XrefVisibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub array: Option<XrefRectangularArray>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefUnitAssumptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_units: Option<InsertionUnit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_units: Option<InsertionUnit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LayerReconciliationMode {
    DrawingPolicy,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LayerReconciliation {
    pub mode: LayerReconciliationMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<XrefLayerProperty>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveLayerReconciliationMode {
    PreserveHost,
    SourceAuthoritative,
    Synchronize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LayerReconciliationEvidence {
    pub requested_mode: LayerReconciliationMode,
    pub effective_mode: EffectiveLayerReconciliationMode,
    pub synchronized_properties: Vec<XrefLayerProperty>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SymbolStrategy {
    Prefix,
    Merge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DependencyStrategy {
    RejectNested,
    BindNested,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachXref {
    pub xref_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub reference_type: ReferenceType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_paths: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<XrefPlacement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_assumptions: Option<XrefUnitAssumptions>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateXrefProperties {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xref_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_type: Option<ReferenceType>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateXref {
    pub attachment: XrefAttachmentGuard,
    pub properties: UpdateXrefProperties,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_paths: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_reconciliation: Option<LayerReconciliation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_assumptions: Option<XrefUnitAssumptions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetachXref {
    pub attachment: XrefDestructiveAttachmentGuard,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsertXrefInstance {
    pub attachment: XrefInstanceAttachmentGuard,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<XrefInstancePlacement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_assumptions: Option<XrefUnitAssumptions>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateXrefInstanceProperties {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insertion_point: Option<XrefPoint3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale: Option<XrefScale3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_degrees: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normal: Option<XrefVector3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<XrefVisibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub array: Option<XrefRectangularArray>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateXrefInstance {
    pub instance: XrefInstanceGuard,
    pub properties: UpdateXrefInstanceProperties,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteXrefInstance {
    pub instance: XrefInstanceGuard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnloadXref {
    pub attachment: XrefAttachmentGuard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReloadXref {
    pub attachment: XrefAttachmentGuard,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_paths: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_reconciliation: Option<LayerReconciliation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_assumptions: Option<XrefUnitAssumptions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindXref {
    pub attachment: XrefDestructiveAttachmentGuard,
    pub symbol_strategy: SymbolStrategy,
    pub dependency_strategy: DependencyStrategy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachXrefResult {
    pub attachment: XrefAttachmentRecord,
    pub instance: XrefInstanceRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateXrefResult {
    pub attachment: XrefAttachmentRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_reconciliation: Option<LayerReconciliationEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetachXrefResult {
    pub attachment: XrefAttachmentRecord,
    pub deleted_instance_handles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsertXrefInstanceResult {
    pub instance: XrefInstanceRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateXrefInstanceResult {
    pub instance: XrefInstanceRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteXrefInstanceResult {
    pub instance: XrefInstanceRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReloadXrefResult {
    pub attachment: XrefAttachmentRecord,
    pub layer_reconciliation: LayerReconciliationEvidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnloadXrefResult {
    pub attachment: XrefAttachmentRecord,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefDependencyRecord {
    pub attachment_chain: Vec<String>,
    pub depth: u32,
    pub immediate_host_path: String,
    pub attachment: XrefAttachmentRecord,
    pub propagation_state: XrefPropagationState,
    pub resolution_state: XrefResolutionState,
    pub resolved_path: Option<String>,
    pub resolution_basis: Option<XrefResolutionBasis>,
    pub inspection_state: XrefInspectionState,
    pub cycle_target_chain: Option<Vec<String>>,
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
pub struct BindXrefResult {
    pub symbol_strategy: SymbolStrategy,
    pub dependency_strategy: DependencyStrategy,
    pub attachment: XrefAttachmentRecord,
    pub block: XrefBoundBlock,
    pub instance_handle_mappings: Vec<XrefInstanceHandleMapping>,
    pub symbol_mappings: Vec<XrefSymbolMapping>,
    pub bound_dependencies: Vec<XrefBoundDependency>,
    pub excluded_overlay_dependencies: Vec<XrefDependencyRecord>,
}
