use std::{any::Any, borrow::Cow, path::Path, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};

use crate::{
    activation::ActivationMode,
    activation_platform::ProductionMutationRuntime,
    autocad_reader::{
        self, DrawingFormat, DrawingReadSession, DrawingSnapshot, ReadErrorKind, Reader,
    },
    ops::{self, xrefs},
    probe::{ProbeController, DEFAULT_PROBE_GRACE, DEFAULT_PROBE_PROCESS_TIMEOUT},
    reader,
};

pub const SERVER_NAME: &str = "autocad-mcp";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const FOREGROUND_PROBE_WAIT: Duration = Duration::from_secs(150);

/// Process-local policy for the serve-only advisory Core Console probe.
///
/// This is CLI configuration, never an MCP tool or an agent decision.
#[derive(Debug, Clone, Copy, Eq, PartialEq, clap::ValueEnum)]
#[value(rename_all = "lower")]
pub enum EngineProbeMode {
    Auto,
    Off,
    On,
}

#[derive(Debug, Clone)]
pub struct AutocadServer {
    active_tool_router: ToolRouter<Self>,
    activation_mode: ActivationMode,
    title_block_profiles: Arc<ops::profiles::ProfileRegistry>,
    mutation_runtime: Arc<ProductionMutationRuntime>,
    probe: Arc<ProbeController>,
    schedule_probe_on_initialized: bool,
}

impl AutocadServer {
    /// Construct the default tool surface for the compiled build flavor.
    ///
    /// Release builds default to the full certified surface. Preview builds
    /// fail closed to read-only tools; callers must explicitly opt into the
    /// Preview-only experimental constructor to enable state-changing tools.
    pub fn new() -> Self {
        Self::new_with_title_block_profiles(ops::profiles::embedded_profile_registry())
    }

    pub fn new_with_title_block_profiles(
        title_block_profiles: Arc<ops::profiles::ProfileRegistry>,
    ) -> Self {
        #[cfg(feature = "preview")]
        {
            Self::read_only_with_title_block_profiles(title_block_profiles)
        }
        #[cfg(not(feature = "preview"))]
        {
            Self::all_tools(ActivationMode::Release, title_block_profiles)
        }
    }

    fn all_tools(
        mode: ActivationMode,
        title_block_profiles: Arc<ops::profiles::ProfileRegistry>,
    ) -> Self {
        let mutation_runtime = Arc::new(ProductionMutationRuntime::new(mode));
        Self {
            active_tool_router: Self::tool_router(),
            activation_mode: mode,
            title_block_profiles,
            probe: Arc::new(ProbeController::production(
                Arc::clone(&mutation_runtime),
                DEFAULT_PROBE_GRACE,
                DEFAULT_PROBE_PROCESS_TIMEOUT,
            )),
            mutation_runtime,
            schedule_probe_on_initialized: false,
        }
    }

    #[cfg(feature = "preview")]
    pub fn experimental() -> Self {
        Self::experimental_with_title_block_profiles(ops::profiles::embedded_profile_registry())
    }

    #[cfg(feature = "preview")]
    pub fn experimental_with_title_block_profiles(
        title_block_profiles: Arc<ops::profiles::ProfileRegistry>,
    ) -> Self {
        Self::all_tools(ActivationMode::Preview, title_block_profiles)
    }

    #[cfg(test)]
    fn read_only() -> Self {
        Self::read_only_with_title_block_profiles(ops::profiles::embedded_profile_registry())
    }

    #[cfg(any(feature = "preview", test))]
    fn read_only_with_title_block_profiles(
        title_block_profiles: Arc<ops::profiles::ProfileRegistry>,
    ) -> Self {
        let mut active_tool_router = Self::tool_router();
        let state_changing_tools = active_tool_router
            .list_all()
            .into_iter()
            .filter(|tool| {
                tool.annotations
                    .as_ref()
                    .and_then(|annotations| annotations.read_only_hint)
                    != Some(true)
            })
            .map(|tool| tool.name)
            .collect::<Vec<_>>();
        for name in state_changing_tools {
            active_tool_router.disable_route(name);
        }
        Self {
            active_tool_router,
            activation_mode: ActivationMode::Disabled,
            title_block_profiles,
            mutation_runtime: Arc::new(ProductionMutationRuntime::new(ActivationMode::Disabled)),
            probe: Arc::new(ProbeController::disabled()),
            schedule_probe_on_initialized: false,
        }
    }

    pub fn list_active_tools(&self) -> Vec<Tool> {
        self.active_tool_router.list_all()
    }

    #[cfg(test)]
    pub(crate) fn mutation_runtime(&self) -> Arc<ProductionMutationRuntime> {
        Arc::clone(&self.mutation_runtime)
    }

    fn prepare_foreground_engine_work(&self) {
        if !self.schedule_probe_on_initialized {
            return;
        }
        let observation = self.probe.before_foreground(FOREGROUND_PROBE_WAIT);
        if observation.cancelled_scheduled_probe {
            tracing::debug!(
                target: "autocad_mcp::probe",
                state = ?observation.snapshot.state,
                "foreground operation claimed deferred Core Console activation"
            );
        } else if observation.wait_timed_out {
            tracing::warn!(
                target: "autocad_mcp::probe",
                state = ?observation.snapshot.state,
                "foreground operation cancelled the advisory probe but reached the cleanup wait bound and will continue to authoritative activation"
            );
        } else if observation.cancelled_running_probe {
            tracing::debug!(
                target: "autocad_mcp::probe",
                state = ?observation.snapshot.state,
                "foreground operation cancelled and waited for the running advisory probe"
            );
        }
    }

    fn schedule_probe_after_initialization(&self) {
        if !self.schedule_probe_on_initialized {
            return;
        }
        let snapshot = self.probe.schedule_after_grace();
        tracing::debug!(
            target: "autocad_mcp::probe",
            state = ?snapshot.state,
            "scheduled serve-only advisory Core Console probe after MCP initialized notification"
        );
    }
}

impl Default for AutocadServer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DrawingPathParams {
    /// Absolute path to the DWG or DXF drawing file
    pub drawing_path: String,
}

fn is_dwg_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dwg"))
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TitleBlockAttributeValueMode {
    /// Keep unique tags in `attributes` and put only duplicate tags in
    /// `attribute_arrays`.
    #[default]
    Split,
    /// Put every tag in `attribute_arrays`, including singleton values.
    Arrays,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ReadTitleBlocksParams {
    /// Absolute path to the DWG or DXF drawing file.
    pub drawing_path: String,
    /// Attribute representation. `split` (default) preserves scalar values for
    /// unique tags and uses arrays only for duplicates. `arrays` returns every
    /// tag as an array.
    #[serde(default)]
    pub attribute_value_mode: TitleBlockAttributeValueMode,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadDrawingParams {
    /// Absolute path to the DWG drawing file.
    pub drawing_path: String,
}

fn default_entity_list_limit() -> usize {
    autocad_reader::contract::DEFAULT_ENTITY_LIST_LIMIT
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListEntitiesParams {
    /// Absolute path to the DWG drawing file.
    pub drawing_path: String,
    /// Optional exact, case-insensitive entity-type filter.
    #[schemars(length(min = 1))]
    pub entity_types: Option<Vec<String>>,
    /// Optional exact, case-insensitive layer-name filter.
    pub layer: Option<String>,
    /// Optional exact hexadecimal owner handle.
    pub owner_handle: Option<String>,
    /// Include entities whose persisted visibility flag is off.
    #[serde(default)]
    pub include_invisible: bool,
    /// Zero-based offset after filters and deterministic handle sorting.
    #[serde(default)]
    pub offset: usize,
    /// Page size from 1 to 1000. Defaults to 200.
    #[serde(default = "default_entity_list_limit")]
    #[schemars(range(min = 1, max = 1_000))]
    pub limit: usize,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityLookupParams {
    /// Absolute path to the DWG drawing file.
    pub drawing_path: String,
    /// Canonical hexadecimal entity handle.
    pub handle: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BlockDefinitionLookupParams {
    /// Absolute path to the DWG drawing file.
    pub drawing_path: String,
    /// Canonical hexadecimal BLOCK_RECORD handle.
    pub handle: Option<String>,
    /// Block definition name, matched case-insensitively.
    pub name: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BlockInsertLookupParams {
    /// Absolute path to the DWG drawing file.
    pub drawing_path: String,
    /// Canonical hexadecimal INSERT/MINSERT entity handle.
    pub handle: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TextLookupParams {
    /// Absolute path to the DWG drawing file.
    pub drawing_path: String,
    /// Canonical hexadecimal TEXT or MTEXT entity handle.
    pub handle: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListTextParams {
    /// Absolute path to the DWG drawing file.
    pub drawing_path: String,
    /// Optional exact TEXT/MTEXT type filter.
    #[schemars(length(min = 1))]
    pub text_types: Option<Vec<autocad_reader::contract::TextEntityKind>>,
    /// Optional exact, case-insensitive layer-name filter.
    pub layer: Option<String>,
    /// Optional exact hexadecimal direct-owner handle.
    pub owner_handle: Option<String>,
    /// Optional semantic direct-owner type. Must be paired with `owner_name`.
    pub owner_type: Option<autocad_reader::contract::DirectOwnerType>,
    /// Optional semantic direct-owner name. Must be paired with `owner_type`.
    pub owner_name: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LayoutLookupParams {
    /// Absolute path to the DWG drawing file.
    pub drawing_path: String,
    /// Canonical hexadecimal LAYOUT object handle.
    pub handle: Option<String>,
    /// Layout name, matched case-insensitively.
    pub name: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListLayoutViewportsParams {
    /// Absolute path to the DWG drawing file.
    pub drawing_path: String,
    /// Optional canonical hexadecimal layout handle filter.
    pub layout_handle: Option<String>,
    /// Optional layout-name filter, matched case-insensitively.
    pub layout_name: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LayoutViewportLookupParams {
    /// Absolute path to the DWG drawing file.
    pub drawing_path: String,
    /// Canonical hexadecimal paper-space VIEWPORT entity handle.
    pub handle: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlotSettingLookupParams {
    /// Absolute path to the DWG drawing file.
    pub drawing_path: String,
    /// Canonical hexadecimal PLOTSETTINGS object handle.
    pub handle: Option<String>,
    /// Named page-setup name, matched case-insensitively.
    pub name: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SymbolLookupParams {
    /// Absolute path to the DWG drawing file.
    pub drawing_path: String,
    /// Canonical hexadecimal table-entry or object handle.
    pub handle: Option<String>,
    /// Resource name, matched case-insensitively.
    pub name: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct LayerLookupParams {
    /// Absolute path to the DWG or DXF drawing file.
    pub drawing_path: String,
    /// Canonical hexadecimal layer handle. Preferred over name.
    pub handle: Option<String>,
    /// Layer name, matched case-insensitively.
    pub name: Option<String>,
}

#[derive(Debug)]
pub struct LayerPropertiesParams;

impl schemars::JsonSchema for LayerPropertiesParams {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("LayerPropertiesParams")
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "object",
            "description": "Writable layer properties: color_index, frozen, locked, off, is_plottable, line_type, and line_weight. Recognized unsupported/read-only layer keys fail with code=unsupported_layer_property; unknown keys fail with code=invalid_layer_property.",
            "additionalProperties": false,
            "properties": {
                "color_index": {
                    "type": "integer",
                    "description": "Indexed layer color from 1 to 255.",
                    "minimum": 1,
                    "maximum": 255
                },
                "frozen": {
                    "type": "boolean",
                    "description": "Global frozen state. update_layer cannot freeze the current layer."
                },
                "locked": {
                    "type": "boolean",
                    "description": "Layer locked state."
                },
                "off": {
                    "type": "boolean",
                    "description": "Layer off/invisible state."
                },
                "is_plottable": {
                    "type": "boolean",
                    "description": "Layer plot flag."
                },
                "line_type": {
                    "type": "string",
                    "description": "Existing linetype table record name. DXF xref-dependent line_type host overrides are unsupported until parity is proven.",
                    "minLength": 1
                },
                "line_weight": {
                    "description": "Structured writable lineweight. The read-only raw shape is not accepted for create_layer or update_layer.",
                    "oneOf": [
                        {
                            "type": "object",
                            "required": ["kind"],
                            "additionalProperties": false,
                            "properties": {
                                "kind": { "const": "by_layer" }
                            }
                        },
                        {
                            "type": "object",
                            "required": ["kind"],
                            "additionalProperties": false,
                            "properties": {
                                "kind": { "const": "by_block" }
                            }
                        },
                        {
                            "type": "object",
                            "required": ["kind"],
                            "additionalProperties": false,
                            "properties": {
                                "kind": { "const": "default" }
                            }
                        },
                        {
                            "type": "object",
                            "required": ["kind", "hundredths_mm"],
                            "additionalProperties": false,
                            "properties": {
                                "kind": { "const": "value" },
                                "hundredths_mm": {
                                    "type": "integer",
                                    "enum": [0, 5, 9, 13, 15, 18, 20, 25, 30, 35, 40, 50, 53, 60, 70, 80, 90, 100, 106, 120, 140, 158, 200, 211]
                                }
                            }
                        }
                    ]
                }
            }
        })
    }
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CreateLayerParams {
    /// Absolute path to the DWG or DXF drawing file to modify.
    pub drawing_path: String,
    /// New host-owned layer name.
    pub name: String,
    /// Writable layer properties: color_index, frozen, locked, off,
    /// is_plottable, line_type, and line_weight. Recognized
    /// unsupported/read-only layer keys fail with code=unsupported_layer_property;
    /// unknown keys fail with code=invalid_layer_property.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "LayerPropertiesParams")]
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UpdateLayerParams {
    /// Absolute path to the DWG or DXF drawing file to modify.
    pub drawing_path: String,
    /// Canonical hexadecimal layer handle. Preferred over name.
    pub handle: Option<String>,
    /// Layer name, matched case-insensitively.
    pub name: Option<String>,
    /// Optional stale-state guard for the resolved layer handle.
    pub expected_handle: Option<String>,
    /// Optional stale-state guard for the resolved layer name.
    pub expected_name: Option<String>,
    /// Writable layer properties: color_index, frozen, locked, off,
    /// is_plottable, line_type, and line_weight. Recognized
    /// unsupported/read-only layer keys fail with code=unsupported_layer_property;
    /// unknown keys fail with code=invalid_layer_property.
    #[schemars(with = "LayerPropertiesParams")]
    pub properties: serde_json::Value,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RenameLayerParams {
    /// Absolute path to the DWG or DXF drawing file to modify.
    pub drawing_path: String,
    /// Canonical hexadecimal layer handle. Preferred over name.
    pub handle: Option<String>,
    /// Layer name, matched case-insensitively.
    pub name: Option<String>,
    /// Optional stale-state guard for the resolved layer handle.
    pub expected_handle: Option<String>,
    /// Optional stale-state guard for the resolved layer name.
    pub expected_name: Option<String>,
    /// New layer name.
    pub new_name: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DeleteLayerParams {
    /// Absolute path to the DWG or DXF drawing file to modify.
    pub drawing_path: String,
    /// Canonical hexadecimal layer handle. Preferred over name.
    pub handle: Option<String>,
    /// Layer name, matched case-insensitively.
    pub name: Option<String>,
    /// Optional stale-state guard for the resolved layer handle.
    pub expected_handle: Option<String>,
    /// Optional stale-state guard for the resolved layer name.
    pub expected_name: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct WriteTitleBlockParams {
    /// Absolute path to the DWG or DXF drawing file to modify.
    pub drawing_path: String,
    /// Canonical field names mapped to their new values.
    /// Valid keys for the AUTOCAD_MCP_GENERIC profile:
    /// revision, drawing_number, alternative_reference,
    /// drawing_title_big, drawing_title_med, sheet, sheet_total.
    pub fields: std::collections::HashMap<String, String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PlotToPdfParams {
    /// Absolute path to the DWG drawing file to plot.
    pub drawing_path: String,
    /// Name of the layout tab to plot (e.g. "Layout1", "Sheet 1").
    /// Use list_layouts to discover available names.
    pub layout: String,
    /// Absolute path where the output PDF should be written.
    pub output: String,
}

fn unsupported_expanded_read_format(drawing_path: &str) -> CallToolResult {
    CallToolResult::error(vec![Content::text(
        autocad_diagnostics::DomainError::new(
            "unsupported_format",
            format!("drawing_path must be a DWG file; got `{drawing_path}`"),
        )
        .to_string(),
    )])
}

fn expanded_read_path_error(drawing_path: &str) -> Option<CallToolResult> {
    if !Path::new(drawing_path).is_absolute() {
        return Some(CallToolResult::error(vec![Content::text(
            autocad_diagnostics::DomainError::new(
                "invalid_drawing_path",
                format!("drawing_path must be an absolute path; got `{drawing_path}`"),
            )
            .to_string(),
        )]));
    }
    (!is_dwg_path(Path::new(drawing_path))).then(|| unsupported_expanded_read_format(drawing_path))
}

fn reader_open_error_detail(error: &autocad_reader::ReadError) -> &str {
    match error.kind() {
        ReadErrorKind::UnsupportedFormat
        | ReadErrorKind::NotFound
        | ReadErrorKind::Unreadable
        | ReadErrorKind::InvalidDrawing
        | ReadErrorKind::IncompleteDrawing => error.message(),
    }
}

fn fallible_session_read_op<T, E>(
    drawing_path: &str,
    operation: &str,
    op: impl FnOnce(&DrawingReadSession) -> std::result::Result<T, E>,
) -> Result<CallToolResult, McpError>
where
    T: serde::Serialize,
    E: std::fmt::Display,
{
    match Reader::open_path(Path::new(drawing_path)) {
        Ok(session) => match op(&session) {
            Ok(output) => match serde_json::to_string(&output) {
                Ok(json) => Ok(CallToolResult::success(vec![Content::text(json)])),
                Err(error) => Ok(CallToolResult::error(vec![Content::text(format!(
                    "serialization error: {error}"
                ))])),
            },
            Err(error) => Ok(CallToolResult::error(vec![Content::text(format!(
                "{operation} failed: {error}"
            ))])),
        },
        Err(error) => Ok(CallToolResult::error(vec![Content::text(format!(
            "failed to open drawing: {}",
            reader_open_error_detail(&error)
        ))])),
    }
}

fn fallible_dwg_session_read_op<T, E>(
    drawing_path: &str,
    operation: &str,
    op: impl FnOnce(&DrawingReadSession) -> std::result::Result<T, E>,
) -> Result<CallToolResult, McpError>
where
    T: serde::Serialize,
    E: std::fmt::Display,
{
    if let Some(error) = expanded_read_path_error(drawing_path) {
        return Ok(error);
    }
    fallible_session_read_op(drawing_path, operation, op)
}

fn layer_properties_object(
    input: serde_json::Value,
) -> Result<serde_json::Map<String, serde_json::Value>, ops::layers::LayerError> {
    match input {
        serde_json::Value::Object(properties) => Ok(properties),
        serde_json::Value::Null => Err(ops::layers::LayerError::new(
            "invalid_layer_property",
            "properties cannot be null",
        )),
        _ => Err(ops::layers::LayerError::new(
            "invalid_layer_property",
            "properties must be an object",
        )),
    }
}

fn canonicalize_title_block_fields(
    fields: std::collections::HashMap<String, String>,
) -> std::result::Result<std::collections::BTreeMap<String, String>, String> {
    let mut canonical = std::collections::BTreeMap::new();
    for (raw_field, value) in fields {
        let normalized = raw_field.trim().to_lowercase();
        if let Some(existing) = canonical.insert(normalized.clone(), value) {
            canonical.insert(normalized.clone(), existing);
            return Err(format!(
                "duplicate canonical field keys collapse to '{normalized}' after whitespace and \
                 case normalization"
            ));
        }
    }
    Ok(canonical)
}

fn optional_layer_properties_object(
    input: Option<serde_json::Value>,
) -> Result<serde_json::Map<String, serde_json::Value>, ops::layers::LayerError> {
    match input {
        Some(value) => layer_properties_object(value),
        None => Ok(serde_json::Map::new()),
    }
}

fn layer_selector(
    handle: Option<String>,
    name: Option<String>,
    expected_handle: Option<String>,
    expected_name: Option<String>,
) -> autocad_reader::contract::LayerSelector {
    autocad_reader::contract::LayerSelector {
        handle,
        name,
        expected_handle,
        expected_name,
    }
}

autocad_diagnostics::domain_error!(struct LayerReadOpenError, new = pub(self));

fn validated_layer_read_path(
    path: &Path,
    tool: &str,
) -> std::result::Result<(DrawingFormat, std::path::PathBuf), LayerReadOpenError> {
    if !path.is_absolute() {
        return Err(LayerReadOpenError::new(
            "drawing_unreadable",
            format!("{tool}: drawing_path must be absolute: {}", path.display()),
        ));
    }

    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let format = match extension.as_str() {
        "dxf" => DrawingFormat::Dxf,
        "dwg" => DrawingFormat::Dwg,
        "" => {
            return Err(LayerReadOpenError::new(
                "unsupported_format",
                format!("{tool}: file has no extension; expected .dxf or .dwg"),
            ));
        }
        other => {
            return Err(LayerReadOpenError::new(
                "unsupported_format",
                format!("{tool}: unsupported extension `{other}`; expected .dxf or .dwg"),
            ));
        }
    };

    if !path.exists() {
        return Err(LayerReadOpenError::new(
            "drawing_not_found",
            format!("{tool}: drawing not found: {}", path.display()),
        ));
    }

    let canonical = std::fs::canonicalize(path).map_err(|error| {
        LayerReadOpenError::new(
            "drawing_unreadable",
            format!("{tool}: failed to canonicalize drawing path: {error}"),
        )
    })?;
    Ok((format, canonical))
}

fn checked_layer_read_session(
    drawing_path: &str,
    tool: &str,
) -> std::result::Result<DrawingReadSession, LayerReadOpenError> {
    let path = Path::new(drawing_path);
    let (format, canonical) = validated_layer_read_path(path, tool)?;
    let bytes = std::fs::read(&canonical).map_err(|_| {
        LayerReadOpenError::new(
            "drawing_unreadable",
            format!(
                "failed to read {}: drawing could not be captured",
                format.name()
            ),
        )
    })?;
    Reader::open_snapshot(DrawingSnapshot::new(format, bytes)).map_err(|error| {
        LayerReadOpenError::new(
            "drawing_unreadable",
            format!(
                "failed to read {}: {}",
                format.name(),
                reader_open_error_detail(&error)
            ),
        )
    })
}

fn layer_session_read_op<T>(
    drawing_path: &str,
    tool: &str,
    op: impl FnOnce(&DrawingReadSession) -> std::result::Result<T, autocad_reader::LayerReadError>,
) -> Result<CallToolResult, McpError>
where
    T: serde::Serialize,
{
    match checked_layer_read_session(drawing_path, tool) {
        Ok(session) => layer_result(op(&session)),
        Err(error) => layer_result::<T, _>(Err(error)),
    }
}

fn layer_result<T, E>(result: std::result::Result<T, E>) -> Result<CallToolResult, McpError>
where
    T: serde::Serialize,
    E: std::fmt::Display,
{
    match result {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(json) => Ok(CallToolResult::success(vec![Content::text(json)])),
            Err(err) => Ok(CallToolResult::error(vec![Content::text(format!(
                "serialization error: {err}"
            ))])),
        },
        Err(err) => Ok(CallToolResult::error(vec![Content::text(err.to_string())])),
    }
}

fn xref_result<T: serde::Serialize>(
    result: Result<T, ops::xrefs::XrefError>,
) -> Result<CallToolResult, McpError> {
    match result {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(json) => Ok(CallToolResult::success(vec![Content::text(json)])),
            Err(err) => Ok(CallToolResult::error(vec![Content::text(format!(
                "serialization error: {err}"
            ))])),
        },
        Err(err) => Ok(CallToolResult::error(vec![Content::text(err.to_string())])),
    }
}

fn schema_is_null(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.get("type") == Some(&serde_json::Value::String("null".to_owned()))
        || object.get("const") == Some(&serde_json::Value::Null)
        || object
            .get("enum")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|values| values.len() == 1 && values[0].is_null())
}

fn remove_null_variant(schema: &mut serde_json::Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };

    let replacement_type = object.get_mut("type").and_then(|value| {
        let types = value.as_array_mut()?;
        types.retain(|entry| entry.as_str() != Some("null"));
        (types.len() == 1).then(|| types[0].clone())
    });
    if let Some(replacement_type) = replacement_type {
        object.insert("type".to_owned(), replacement_type);
    }

    if let Some(values) = object
        .get_mut("enum")
        .and_then(serde_json::Value::as_array_mut)
    {
        values.retain(|entry| !entry.is_null());
    }
    for keyword in ["anyOf", "oneOf"] {
        if let Some(variants) = object
            .get_mut(keyword)
            .and_then(serde_json::Value::as_array_mut)
        {
            variants.retain(|variant| !schema_is_null(variant));
        }
    }
}

fn strip_null_from_optional_properties(schema: &mut serde_json::Value) {
    match schema {
        serde_json::Value::Array(values) => {
            for value in values {
                strip_null_from_optional_properties(value);
            }
        }
        serde_json::Value::Object(object) => {
            let required = object
                .get("required")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect::<std::collections::BTreeSet<_>>();
            if let Some(properties) = object
                .get_mut("properties")
                .and_then(serde_json::Value::as_object_mut)
            {
                for (name, property_schema) in properties {
                    if !required.contains(name) {
                        remove_null_variant(property_schema);
                    }
                    strip_null_from_optional_properties(property_schema);
                }
            }
            for (keyword, value) in object {
                if keyword != "properties" {
                    strip_null_from_optional_properties(value);
                }
            }
        }
        _ => {}
    }
}

pub fn xref_schema_for_type<T>() -> Arc<JsonObject>
where
    T: schemars::JsonSchema + Any,
{
    let schema = rmcp::handler::server::common::schema_for_type::<T>();
    let mut schema = serde_json::Value::Object((*schema).clone());
    strip_null_from_optional_properties(&mut schema);
    Arc::new(
        schema
            .as_object()
            .expect("XREF request schema must be an object")
            .clone(),
    )
}

fn supported_xref_nested_request_objects<T: Any>() -> (bool, bool) {
    let request_type = std::any::TypeId::of::<T>();
    let accepts_layer_reconciliation = request_type
        == std::any::TypeId::of::<xrefs::UpdateXrefRequest>()
        || request_type == std::any::TypeId::of::<xrefs::ReloadXrefRequest>();
    let accepts_unit_assumptions = request_type
        == std::any::TypeId::of::<xrefs::AttachXrefRequest>()
        || request_type == std::any::TypeId::of::<xrefs::UpdateXrefRequest>()
        || request_type == std::any::TypeId::of::<xrefs::InsertXrefInstanceRequest>()
        || request_type == std::any::TypeId::of::<xrefs::ReloadXrefRequest>();
    (accepts_layer_reconciliation, accepts_unit_assumptions)
}

fn validate_xref_nested_request_objects<T: Any>(
    input: &serde_json::Value,
) -> Result<(), xrefs::XrefError> {
    let Some(object) = input.as_object() else {
        return Ok(());
    };
    let (accepts_layer_reconciliation, accepts_unit_assumptions) =
        supported_xref_nested_request_objects::<T>();

    if accepts_layer_reconciliation {
        validate_xref_layer_reconciliation(input)?;
    }
    if accepts_unit_assumptions {
        if let Some(value) = object.get("unit_assumptions") {
            if !value.is_object() {
                return Err(xrefs::XrefError::new(
                    xrefs::xref_failure_code::INVALID_UNIT_ASSUMPTIONS,
                    "unit_assumptions must be an object",
                ));
            }
            serde_json::from_value::<xrefs::XrefUnitAssumptions>(value.clone()).map_err(
                |error| {
                    xrefs::XrefError::new(
                        xrefs::xref_failure_code::INVALID_UNIT_ASSUMPTIONS,
                        format!("invalid unit_assumptions object: {error}"),
                    )
                },
            )?;
        }
    }
    Ok(())
}

fn validate_xref_layer_reconciliation(input: &serde_json::Value) -> Result<(), xrefs::XrefError> {
    let Some(value) = input
        .as_object()
        .and_then(|object| object.get("layer_reconciliation"))
    else {
        return Ok(());
    };
    if !value.is_object() {
        return Err(xrefs::XrefError::new(
            xrefs::xref_failure_code::INVALID_LAYER_RECONCILIATION,
            "layer_reconciliation must be an object",
        ));
    }
    let reconciliation = serde_json::from_value::<xrefs::XrefLayerReconciliation>(value.clone())
        .map_err(|error| {
            xrefs::XrefError::new(
                xrefs::xref_failure_code::INVALID_LAYER_RECONCILIATION,
                format!("invalid layer_reconciliation object: {error}"),
            )
        })?;
    reconciliation.validate()?;
    Ok(())
}

fn validate_xref_step_two_before_nested<T: Any>(
    sanitized_input: &serde_json::Value,
) -> Result<(), xrefs::XrefError> {
    if std::any::TypeId::of::<T>() == std::any::TypeId::of::<xrefs::UpdateXrefRequest>() {
        let request = serde_json::from_value::<xrefs::UpdateXrefRequest>(sanitized_input.clone())
            .map_err(|error| {
            xrefs::XrefError::new(
                xrefs::xref_failure_code::INVALID_PARAMETERS,
                format!("failed to deserialize parameters: {error}"),
            )
        })?;
        let mut properties_only = request.clone();
        properties_only.search_paths = None;
        properties_only.layer_reconciliation = None;
        properties_only.unit_assumptions = None;
        ops::xref_attachment_mutation::validate_update_xref_step_two(&properties_only)
            .map_err(ops::xref_runtime::transaction_error_to_xref)?;

        ops::xref_attachment_mutation::validate_update_xref_step_two(&request)
            .map_err(ops::xref_runtime::transaction_error_to_xref)?;
    }
    Ok(())
}

fn parse_xref_request<T: serde::de::DeserializeOwned + Any>(
    input: serde_json::Value,
) -> Result<T, xrefs::XrefError> {
    let deserialize_error = match serde_json::from_value(input.clone()) {
        Ok(request) => {
            validate_xref_step_two_before_nested::<T>(&input)?;
            validate_xref_nested_request_objects::<T>(&input)?;
            return Ok(request);
        }
        Err(error) => error,
    };

    // Check the top-level request shell independently so its errors retain
    // precedence over malformed nested domain objects.
    let (accepts_layer_reconciliation, accepts_unit_assumptions) =
        supported_xref_nested_request_objects::<T>();
    let mut shell = input.clone();
    if let Some(object) = shell.as_object_mut() {
        if accepts_layer_reconciliation && object.contains_key("layer_reconciliation") {
            object.insert(
                "layer_reconciliation".to_owned(),
                serde_json::json!({"mode": "drawing_policy"}),
            );
        }
        if accepts_unit_assumptions && object.contains_key("unit_assumptions") {
            object.insert("unit_assumptions".to_owned(), serde_json::json!({}));
        }
        if std::any::TypeId::of::<T>() == std::any::TypeId::of::<xrefs::UpdateXrefRequest>()
            && object.contains_key("search_paths")
        {
            object.insert("search_paths".to_owned(), serde_json::json!([]));
        }
    }
    if serde_json::from_value::<T>(shell.clone()).is_ok() {
        validate_xref_step_two_before_nested::<T>(&shell)?;
        validate_xref_nested_request_objects::<T>(&input)?;
    }

    Err(xrefs::XrefError::new(
        xrefs::xref_failure_code::INVALID_PARAMETERS,
        format!("failed to deserialize parameters: {deserialize_error}"),
    ))
}

#[tool_router(vis = "pub")]
impl AutocadServer {
    #[tool(
        description = "Read a closed DWG drawing summary, including decoded version, units, metadata, availability-qualified saved-header model/paper geometry and current UCS state, current named resources, and resource counts.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_drawing(
        &self,
        Parameters(p): Parameters<ReadDrawingParams>,
    ) -> Result<CallToolResult, McpError> {
        fallible_dwg_session_read_op(
            &p.drawing_path,
            "get_drawing",
            DrawingReadSession::get_drawing,
        )
    }

    #[tool(
        description = "List drawing entities in deterministic numeric-handle order with exact optional type, layer, owner, and visibility filters, reason-bearing bounds/detail availability, and proven dynamic-block linkage for INSERTs. Returns a bounded envelope; offset defaults to 0, limit defaults to 200, and the maximum limit is 1000.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_entities(
        &self,
        Parameters(p): Parameters<ListEntitiesParams>,
    ) -> Result<CallToolResult, McpError> {
        let options = autocad_reader::contract::EntityListOptions {
            entity_types: p.entity_types,
            layer: p.layer,
            owner_handle: p.owner_handle,
            include_invisible: p.include_invisible,
            offset: p.offset,
            limit: p.limit,
        };
        fallible_dwg_session_read_op(&p.drawing_path, "list_entities", |session| {
            session.list_entities(&options)
        })
    }

    #[tool(
        description = "Get one drawing entity by its stable hexadecimal handle. Returns common identity, direct-owner context, layer, display, availability-qualified bounds, and bounded type-specific detail, including proven dynamic-block linkage for INSERTs.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_entity(
        &self,
        Parameters(p): Parameters<EntityLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = autocad_reader::contract::EntitySelector { handle: p.handle };
        fallible_dwg_session_read_op(&p.drawing_path, "get_entity", |session| {
            session.get_entity(&selector)
        })
    }

    #[tool(
        description = "List all layers in a DWG or DXF drawing. Returns expanded LayerRecord fields: handle, name, color_index, frozen, locked, off, is_plottable, xref_dependent, is_current, line_type, line_weight, xref_block_record_handle, xref_name, xref_path, xref_is_overlay, material_handle, and plotstyle_handle.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_layers(
        &self,
        Parameters(p): Parameters<DrawingPathParams>,
    ) -> Result<CallToolResult, McpError> {
        layer_session_read_op(&p.drawing_path, "list_layers", |session| {
            session.list_layers()
        })
    }

    #[tool(
        description = "Get one layer by handle or name from a DWG or DXF drawing. Returns the expanded LayerRecord fields: handle, name, color_index, frozen, locked, off, is_plottable, xref_dependent, is_current, line_type, line_weight, xref_block_record_handle, xref_name, xref_path, xref_is_overlay, material_handle, and plotstyle_handle.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_layer(
        &self,
        Parameters(p): Parameters<LayerLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = layer_selector(p.handle, p.name, None, None);
        layer_session_read_op(&p.drawing_path, "get_layer", |session| {
            session.get_layer(&selector)
        })
    }

    #[tool(
        description = "Create a host-owned layer in a DWG or DXF drawing with writable layer properties: color_index, frozen, locked, off, is_plottable, line_type, and line_weight. Native DXF writes run on all supported hosts; DWG writes require Windows with AutoCAD accoreconsole.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn create_layer(
        &self,
        Parameters(p): Parameters<CreateLayerParams>,
    ) -> Result<CallToolResult, McpError> {
        let result = optional_layer_properties_object(p.properties).and_then(|properties| {
            if is_dwg_path(Path::new(&p.drawing_path)) {
                self.prepare_foreground_engine_work();
            }
            ops::layer_io::create_layer_file_with_activation(
                Path::new(&p.drawing_path),
                &p.name,
                &properties,
                &self.mutation_runtime,
            )
        });
        layer_result(result)
    }

    #[tool(
        description = "Update writable layer properties: color_index, frozen, locked, off, is_plottable, line_type, and line_weight. Handles are preferred; expected guards reject stale state. Xref-dependent host overrides are property-specific; DXF xref-dependent line_type updates remain unsupported.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn update_layer(
        &self,
        Parameters(p): Parameters<UpdateLayerParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = layer_selector(p.handle, p.name, p.expected_handle, p.expected_name);
        let result = layer_properties_object(p.properties).and_then(|properties| {
            if is_dwg_path(Path::new(&p.drawing_path)) {
                self.prepare_foreground_engine_work();
            }
            ops::layer_io::update_layer_file_with_activation(
                Path::new(&p.drawing_path),
                &selector,
                &properties,
                &self.mutation_runtime,
            )
        });
        layer_result(result)
    }

    #[tool(
        description = "Rename one host-owned layer by handle or name. Rejects protected and xref-dependent layers and preserves represented entity membership.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn rename_layer(
        &self,
        Parameters(p): Parameters<RenameLayerParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = layer_selector(p.handle, p.name, p.expected_handle, p.expected_name);
        if is_dwg_path(Path::new(&p.drawing_path)) {
            self.prepare_foreground_engine_work();
        }
        layer_result(ops::layer_io::rename_layer_file_with_activation(
            Path::new(&p.drawing_path),
            &selector,
            &p.new_name,
            &self.mutation_runtime,
        ))
    }

    #[tool(
        description = "Safely delete one unused host-owned layer by handle or name. Rejects layer 0, DEFPOINTS, xref-dependent layers, the current layer, and layers with content.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn delete_layer(
        &self,
        Parameters(p): Parameters<DeleteLayerParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = layer_selector(p.handle, p.name, p.expected_handle, p.expected_name);
        if is_dwg_path(Path::new(&p.drawing_path)) {
            self.prepare_foreground_engine_work();
        }
        layer_result(ops::layer_io::delete_layer_file_with_activation(
            Path::new(&p.drawing_path),
            &selector,
            &self.mutation_runtime,
        ))
    }

    #[tool(
        description = "List direct XREF attachment definitions in a DWG or DXF drawing as complete attachment records sorted by numeric handle.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::ListXrefsRequest>()
    )]
    pub fn list_xrefs(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        let result = parse_xref_request::<xrefs::ListXrefsRequest>(input)
            .and_then(|request| ops::xref_io::list_xrefs_file(Path::new(&request.drawing_path)));
        xref_result(result)
    }

    #[tool(
        description = "Get one direct XREF attachment definition by block-record handle, case-insensitive name, or a matching pair.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::GetXrefRequest>()
    )]
    pub fn get_xref(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        let result = parse_xref_request::<xrefs::GetXrefRequest>(input).and_then(|request| {
            let selector = xrefs::XrefSelector {
                handle: request.handle,
                name: request.name,
            };
            ops::xref_io::get_xref_file(Path::new(&request.drawing_path), &selector)
        });
        xref_result(result)
    }

    #[tool(
        description = "Attach a source DWG as a direct attachment or overlay and atomically create its initial instance. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = true, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::AttachXrefRequest>()
    )]
    pub fn attach_xref(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        xref_result(
            parse_xref_request::<xrefs::AttachXrefRequest>(input).and_then(|request| {
                self.prepare_foreground_engine_work();
                ops::xref_runtime::attach_xref_file_with_activation(request, &self.mutation_runtime)
            }),
        )
    }

    #[tool(
        description = "Update writable properties of one direct XREF attachment using optional stale-state guards. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::UpdateXrefRequest>()
    )]
    pub fn update_xref(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        xref_result(
            parse_xref_request::<xrefs::UpdateXrefRequest>(input).and_then(|request| {
                self.prepare_foreground_engine_work();
                ops::xref_runtime::update_xref_file_with_activation(request, &self.mutation_runtime)
            }),
        )
    }

    #[tool(
        description = "Detach one direct XREF attachment and delete all of its instances after optional exact-scope guards pass. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::DetachXrefRequest>()
    )]
    pub fn detach_xref(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        xref_result(
            parse_xref_request::<xrefs::DetachXrefRequest>(input).and_then(|request| {
                self.prepare_foreground_engine_work();
                ops::xref_runtime::detach_xref_file_with_activation(request, &self.mutation_runtime)
            }),
        )
    }

    #[tool(
        description = "List placed instances of direct XREF attachments, with optional attachment, owner, layer, and visibility filters, sorted by numeric handle.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::ListXrefInstancesRequest>()
    )]
    pub fn list_xref_instances(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        let result =
            parse_xref_request::<xrefs::ListXrefInstancesRequest>(input).and_then(|request| {
                ops::xref_io::list_xref_instances_file(Path::new(&request.drawing_path), &request)
            });
        xref_result(result)
    }

    #[tool(
        description = "Get one placed XREF instance by its entity handle from a DWG or DXF drawing.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::GetXrefInstanceRequest>()
    )]
    pub fn get_xref_instance(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        let result =
            parse_xref_request::<xrefs::GetXrefInstanceRequest>(input).and_then(|request| {
                ops::xref_io::get_xref_instance_file(
                    Path::new(&request.drawing_path),
                    &request.handle,
                )
            });
        xref_result(result)
    }

    #[tool(
        description = "Insert another instance of an existing direct XREF attachment with explicit or deterministic placement. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::InsertXrefInstanceRequest>()
    )]
    pub fn insert_xref_instance(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        xref_result(
            parse_xref_request::<xrefs::InsertXrefInstanceRequest>(input).and_then(|request| {
                self.prepare_foreground_engine_work();
                ops::xref_runtime::insert_xref_instance_file_with_activation(
                    request,
                    &self.mutation_runtime,
                )
            }),
        )
    }

    #[tool(
        description = "Update writable placement properties of one XREF instance while preserving its attachment and owner. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::UpdateXrefInstanceRequest>()
    )]
    pub fn update_xref_instance(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        xref_result(
            parse_xref_request::<xrefs::UpdateXrefInstanceRequest>(input).and_then(|request| {
                self.prepare_foreground_engine_work();
                ops::xref_runtime::update_xref_instance_file_with_activation(
                    request,
                    &self.mutation_runtime,
                )
            }),
        )
    }

    #[tool(
        description = "Delete one XREF instance by entity handle while leaving its attachment definition intact. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::DeleteXrefInstanceRequest>()
    )]
    pub fn delete_xref_instance(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        xref_result(
            parse_xref_request::<xrefs::DeleteXrefInstanceRequest>(input).and_then(|request| {
                self.prepare_foreground_engine_work();
                ops::xref_runtime::delete_xref_instance_file_with_activation(
                    request,
                    &self.mutation_runtime,
                )
            }),
        )
    }

    #[tool(
        description = "Reload one direct XREF attachment from its source and reconcile retained layer overrides. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::ReloadXrefRequest>()
    )]
    pub fn reload_xref(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        xref_result(
            parse_xref_request::<xrefs::ReloadXrefRequest>(input).and_then(|request| {
                self.prepare_foreground_engine_work();
                ops::xref_runtime::reload_xref_file_with_activation(request, &self.mutation_runtime)
            }),
        )
    }

    #[tool(
        description = "Unload one direct XREF attachment without removing its definition or instances. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::UnloadXrefRequest>()
    )]
    pub fn unload_xref(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        xref_result(
            parse_xref_request::<xrefs::UnloadXrefRequest>(input).and_then(|request| {
                self.prepare_foreground_engine_work();
                ops::xref_runtime::unload_xref_file_with_activation(request, &self.mutation_runtime)
            }),
        )
    }

    #[tool(
        description = "Bind one direct XREF into the host with explicit symbol and dependency strategies and complete mapping evidence. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::BindXrefRequest>()
    )]
    pub fn bind_xref(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        xref_result(
            parse_xref_request::<xrefs::BindXrefRequest>(input).and_then(|request| {
                self.prepare_foreground_engine_work();
                ops::xref_runtime::bind_xref_file_with_activation(request, &self.mutation_runtime)
            }),
        )
    }

    #[tool(
        description = "Resolve one direct XREF's saved path deterministically against its immediate host and optional ordered search paths.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::ResolveXrefPathRequest>()
    )]
    pub fn resolve_xref_path(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        let result =
            parse_xref_request::<xrefs::ResolveXrefPathRequest>(input).and_then(|request| {
                ops::xref_io::resolve_xref_path_file(Path::new(&request.drawing_path), &request)
            });
        xref_result(result)
    }

    #[tool(
        description = "Traverse direct and propagated XREF dependencies with deterministic pre-order output and explicit truncation metadata.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = true),
        input_schema = xref_schema_for_type::<xrefs::ListXrefDependenciesRequest>()
    )]
    pub fn list_xref_dependencies(
        &self,
        Parameters(input): Parameters<serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        let result =
            parse_xref_request::<xrefs::ListXrefDependenciesRequest>(input).and_then(|request| {
                ops::xref_io::list_xref_dependencies_file(
                    Path::new(&request.drawing_path),
                    &request,
                )
            });
        xref_result(result)
    }

    #[tool(
        description = "List all user-defined block definitions in a DWG or DXF drawing. Returns a JSON array with name, has_attributes, and description fields.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_blocks(
        &self,
        Parameters(p): Parameters<DrawingPathParams>,
    ) -> Result<CallToolResult, McpError> {
        fallible_session_read_op(
            &p.drawing_path,
            "list_blocks",
            DrawingReadSession::list_blocks,
        )
    }

    #[tool(
        description = "List every block definition in deterministic numeric-handle order, including anonymous, layout, XREF, and XREF-dependent BLOCK_RECORDs with explicit classification and retained structural context.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_block_definitions(
        &self,
        Parameters(p): Parameters<ReadDrawingParams>,
    ) -> Result<CallToolResult, McpError> {
        fallible_dwg_session_read_op(
            &p.drawing_path,
            "list_block_definitions",
            DrawingReadSession::list_block_definitions,
        )
    }

    #[tool(
        description = "Get one block definition by handle or case-insensitive name. If both identities are supplied they must resolve to the same BLOCK_RECORD.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_block_definition(
        &self,
        Parameters(p): Parameters<BlockDefinitionLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = autocad_reader::contract::BlockDefinitionSelector {
            handle: p.handle,
            name: p.name,
        };
        fallible_dwg_session_read_op(&p.drawing_path, "get_block_definition", |session| {
            session.get_block_definition(&selector)
        })
    }

    #[tool(
        description = "List ordinary host block INSERT/MINSERT entities in deterministic numeric-handle order with definition identity, proven dynamic-block linkage, direct-owner context, placement, array, and attribute data. XREF instances are excluded.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_block_inserts(
        &self,
        Parameters(p): Parameters<ReadDrawingParams>,
    ) -> Result<CallToolResult, McpError> {
        fallible_dwg_session_read_op(
            &p.drawing_path,
            "list_block_inserts",
            DrawingReadSession::list_block_inserts,
        )
    }

    #[tool(
        description = "Get one ordinary host block INSERT/MINSERT entity by handle with definition identity, proven dynamic-block linkage, direct-owner context, placement, array, and attribute data. XREF instances are excluded.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_block_insert(
        &self,
        Parameters(p): Parameters<BlockInsertLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = autocad_reader::contract::BlockInsertSelector { handle: p.handle };
        fallible_dwg_session_read_op(&p.drawing_path, "get_block_insert", |session| {
            session.get_block_insert(&selector)
        })
    }

    #[tool(
        description = "Read title-block attributes from all attributed INSERT entities in a DWG or DXF drawing. Unique tags are returned in attributes (tag → scalar); duplicate normalized tags are returned without data loss in attribute_arrays (tag → values in source order). Set attribute_value_mode=arrays to return every tag as an array. Duplicate tags produce a successful partial result with structured warnings, not a whole-drawing failure.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn read_title_blocks(
        &self,
        Parameters(p): Parameters<ReadTitleBlocksParams>,
    ) -> Result<CallToolResult, McpError> {
        let path = Path::new(&p.drawing_path);
        let session = match Reader::open_path(path) {
            Ok(session) => session,
            Err(error) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "failed to open drawing: {}",
                    reader_open_error_detail(&error)
                ))]))
            }
        };

        let mut title_blocks = match session.read_title_blocks() {
            Ok(title_blocks) => title_blocks,
            Err(error) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "read_title_blocks failed: {error}"
                ))]))
            }
        };
        let warnings = title_blocks
            .iter()
            .flat_map(|block| {
                block.duplicate_attribute_tags().into_iter().map(|tag| {
                    format!(
                        "attributed INSERT block '{}' on layer '{}' contains duplicate normalized \
                         attribute tag '{}'; values were returned as an array",
                        block.block_name, block.layer, tag
                    )
                })
            })
            .collect::<Vec<_>>();
        if p.attribute_value_mode == TitleBlockAttributeValueMode::Arrays {
            for block in &mut title_blocks {
                block.use_array_mode();
            }
        }

        let text = match serde_json::to_string(&title_blocks) {
            Ok(text) => text,
            Err(error) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "serialization error: {error}"
                ))]))
            }
        };
        let structured = serde_json::json!({
            "status": if warnings.is_empty() { "complete" } else { "partial" },
            "attribute_value_mode": match p.attribute_value_mode {
                TitleBlockAttributeValueMode::Split => "split",
                TitleBlockAttributeValueMode::Arrays => "arrays",
            },
            "title_blocks": title_blocks,
            "warnings": warnings,
        });
        let mut result = CallToolResult::success(vec![Content::text(text)]);
        result.structured_content = Some(structured);
        Ok(result)
    }

    #[tool(
        description = "Dump all TEXT and MTEXT entities from a DWG or DXF drawing. Returns a JSON array with text_type, value, layer, x, and y fields.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn dump_text(
        &self,
        Parameters(p): Parameters<DrawingPathParams>,
    ) -> Result<CallToolResult, McpError> {
        fallible_session_read_op(&p.drawing_path, "dump_text", DrawingReadSession::dump_text)
    }

    #[tool(
        description = "List TEXT and MTEXT entities in deterministic numeric-handle order with exact optional text_types, layer, owner_handle, and semantic owner_type+owner_name filters, plus stable identity, direct-owner context, 3D placement, style, visibility, and type-specific geometry.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_text(
        &self,
        Parameters(p): Parameters<ListTextParams>,
    ) -> Result<CallToolResult, McpError> {
        let options = autocad_reader::contract::TextListOptions {
            text_types: p.text_types,
            layer: p.layer,
            owner_handle: p.owner_handle,
            owner_type: p.owner_type,
            owner_name: p.owner_name,
        };
        fallible_dwg_session_read_op(&p.drawing_path, "list_text", |session| {
            session.list_text(&options)
        })
    }

    #[tool(
        description = "Get one TEXT or MTEXT entity by its stable hexadecimal handle with direct-owner context, 3D placement, style, visibility, and type-specific geometry.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_text(
        &self,
        Parameters(p): Parameters<TextLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = autocad_reader::contract::TextSelector { handle: p.handle };
        fallible_dwg_session_read_op(&p.drawing_path, "get_text", |session| {
            session.get_text(&selector)
        })
    }

    #[tool(
        description = "Write title-block attributes in place in a DWG or native ASCII DXF drawing. \
        Accepts canonical field names (e.g. 'revision', 'drawing_number') and maps \
        them to the correct DXF attribute tags for the detected profile. Duplicate \
        canonical request keys are rejected after trimming and case normalization. \
        A duplicate drawing tag blocks the write only when a requested field maps \
        to that tag; duplicate unrequested tags do not. \
        Fails loudly if the drawing contains no recognised title-block profile — \
        never guesses. Release DWG writes require accoreconsole. The Preview product \
        admits a bounded pure-Rust path only for AC1032 DWG sources whose invariant \
        sections and complete represented model pass the allowed-delta oracle. Native \
        ASCII DXF files retain the existing pure-Rust patcher on any platform.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn write_title_block(
        &self,
        Parameters(p): Parameters<WriteTitleBlockParams>,
    ) -> Result<CallToolResult, McpError> {
        use crate::ops::{dxf_patch, profiles, title_blocks, write_title_block as wtb};
        use std::collections::HashMap;

        if p.fields.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "no fields specified".to_string(),
            )]));
        }
        let fields = match canonicalize_title_block_fields(p.fields) {
            Ok(fields) => fields,
            Err(error) => return Ok(CallToolResult::error(vec![Content::text(error)])),
        };

        let path = Path::new(&p.drawing_path);
        #[cfg(feature = "preview")]
        if is_dwg_path(path) && self.activation_mode == ActivationMode::Preview {
            return match ops::preview_acadrust_title_block::write(
                path,
                &self.title_block_profiles,
                &fields,
            ) {
                Ok(report) => {
                    let mut response = serde_json::to_value(report).map_err(|error| {
                        McpError::internal_error(
                            "serialize Preview title-block receipt",
                            Some(serde_json::json!({ "detail": error.to_string() })),
                        )
                    })?;
                    let object = response
                        .as_object_mut()
                        .expect("Preview title-block receipt must serialize as an object");
                    object.insert("status".to_string(), serde_json::json!("ok"));
                    object.insert(
                        "capability_status".to_string(),
                        serde_json::json!("preview"),
                    );
                    object.insert(
                        "drawing".to_string(),
                        serde_json::Value::String(p.drawing_path),
                    );
                    Ok(CallToolResult::success(vec![Content::text(
                        response.to_string(),
                    )]))
                }
                Err(error) => Ok(CallToolResult::error(vec![Content::text(
                    serde_json::json!({
                        "status": "error",
                        "backend": "acadrust_preview",
                        "code": error.code(),
                        "message": error.message(),
                        "installation_may_have_occurred": error.installation_may_have_occurred(),
                    })
                    .to_string(),
                )])),
            };
        }
        if is_dwg_path(path) {
            self.prepare_foreground_engine_work();
        }

        let doc = match reader::open_drawing(path) {
            Ok(d) => d,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "failed to open drawing: {e}"
                ))]))
            }
        };

        let tbs = title_blocks::project_title_blocks_for_mutation(&doc);
        if tbs.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "no attributed INSERT blocks found in drawing".to_string(),
            )]));
        }

        let profile = match self.title_block_profiles.resolve_profile(&tbs) {
            Ok(pr) => pr,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "{e}. Cannot write — ask an administrator to configure a reviewed title-block profile before attempting edits."
                ))]))
            }
        };

        let mut tag_values: Vec<(String, String)> = Vec::new();
        for (canonical, value) in &fields {
            match profile.tag_for(canonical) {
                Some(tag) => tag_values.push((tag.to_string(), value.clone())),
                None => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "unknown canonical field '{canonical}' for profile '{}'; \
                         valid fields: {:?}",
                        profile.profile_id,
                        profile.canonical_fields()
                    ))]))
                }
            }
        }

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let fingerprint = profile.title_block_fingerprint();
        let result: anyhow::Result<(usize, usize)> = if ext == "dxf" {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "failed to read DXF file: {e}"
                    ))]))
                }
            };
            let replacements: HashMap<String, String> = tag_values.iter().cloned().collect();
            match dxf_patch::patch_dxf_attributes(&content, &fingerprint, &replacements) {
                Ok(patched) => std::fs::write(path, patched.content)
                    .map(|()| (patched.target_inserts, patched.attributes_written))
                    .map_err(anyhow::Error::from),
                Err(e) => Err(e),
            }
        } else {
            wtb::write_dwg_with_activation(path, profile, &tag_values, &self.mutation_runtime)
                .map(|report| (report.target_inserts, report.attributes_written))
        };

        match result {
            Ok((target_inserts, attributes_written)) => {
                let mut response = serde_json::json!({
                    "status": "ok",
                    "drawing": p.drawing_path,
                    "profile_id": profile.profile_id,
                    "profile_authority": match profile.authority() {
                        profiles::ProfileAuthority::Embedded => "embedded",
                        profiles::ProfileAuthority::Administrator(_) => "administrator",
                    },
                    "fields_written": tag_values.len(),
                    "target_inserts": target_inserts,
                    "attributes_written": attributes_written
                });
                if let Some(pack) = profile.administrator_pack() {
                    let object = response
                        .as_object_mut()
                        .expect("title-block response must be an object");
                    object.insert(
                        "profile_pack_id".to_string(),
                        serde_json::Value::String(pack.pack_id.clone()),
                    );
                    object.insert(
                        "profile_pack_version".to_string(),
                        serde_json::Value::String(pack.pack_version.clone()),
                    );
                    object.insert(
                        "profile_pack_sha256".to_string(),
                        serde_json::Value::String(pack.sha256.clone()),
                    );
                }
                Ok(CallToolResult::success(vec![Content::text(
                    response.to_string(),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "write failed: {e}"
            ))])),
        }
    }

    #[tool(
        description = "List all layouts in a DWG or DXF drawing. Returns a JSON array \
        with name, is_model, tab_order, paper_width_mm, and paper_height_mm per layout. \
        Paper dimensions are copied from stored plot settings; 0.0 means the drawing \
        reader has no usable physical paper size for that layout. \
        Call this before plot_to_pdf to discover available layout names.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_layouts(
        &self,
        Parameters(p): Parameters<DrawingPathParams>,
    ) -> Result<CallToolResult, McpError> {
        fallible_session_read_op(
            &p.drawing_path,
            "list_layouts",
            DrawingReadSession::list_layouts,
        )
    }

    #[tool(
        description = "Get one layout by handle or case-insensitive name with backing block-record identity, limits, nullable extents, insertion base, UCS, last-active paper-space viewport handle, and embedded plot settings. Empty-layout extents are returned as null. If both identities are supplied they must agree.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_layout(
        &self,
        Parameters(p): Parameters<LayoutLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = autocad_reader::contract::LayoutSelector {
            handle: p.handle,
            name: p.name,
        };
        fallible_dwg_session_read_op(&p.drawing_path, "get_layout", |session| {
            session.get_layout(&selector)
        })
    }

    #[tool(
        description = "List paper-space VIEWPORT entities in deterministic numeric-handle order, optionally filtered by layout handle or name. These are layout-owned entities, not VPORT table rows; is_last_active_for_layout identifies the layout's last-active viewport, while unavailable reader fields are null.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_layout_viewports(
        &self,
        Parameters(p): Parameters<ListLayoutViewportsParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = (p.layout_handle.is_some() || p.layout_name.is_some()).then_some(
            autocad_reader::contract::LayoutSelector {
                handle: p.layout_handle,
                name: p.layout_name,
            },
        );
        fallible_dwg_session_read_op(&p.drawing_path, "list_layout_viewports", |session| {
            session.list_layout_viewports(selector.as_ref())
        })
    }

    #[tool(
        description = "Get one paper-space VIEWPORT entity by its stable hexadecimal handle with resolved layout identity, display rectangle, view geometry, scale, clipping, render mode, and frozen layers. Unrecoverable is_on and custom_scale values are null; zero scale operands yield a null model_to_paper_scale.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_layout_viewport(
        &self,
        Parameters(p): Parameters<LayoutViewportLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = autocad_reader::contract::LayoutViewportSelector { handle: p.handle };
        fallible_dwg_session_read_op(&p.drawing_path, "get_layout_viewport", |session| {
            session.get_layout_viewport(&selector)
        })
    }

    #[tool(
        description = "List standalone named PLOTSETTINGS objects in deterministic numeric-handle order with device, media, margins, plot area, scale, rotation, style, shade, and flag data. Layout-embedded settings remain on get_layout.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_plot_settings(
        &self,
        Parameters(p): Parameters<ReadDrawingParams>,
    ) -> Result<CallToolResult, McpError> {
        fallible_dwg_session_read_op(
            &p.drawing_path,
            "list_plot_settings",
            DrawingReadSession::list_plot_settings,
        )
    }

    #[tool(
        description = "Get one standalone named PLOTSETTINGS object by handle or case-insensitive page-setup name. If both identities are supplied they must agree.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_plot_setting(
        &self,
        Parameters(p): Parameters<PlotSettingLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = autocad_reader::contract::PlotSettingSelector {
            handle: p.handle,
            name: p.name,
        };
        fallible_dwg_session_read_op(&p.drawing_path, "get_plot_setting", |session| {
            session.get_plot_setting(&selector)
        })
    }

    #[tool(
        description = "List linetype table records in deterministic numeric-handle order with stable identity, current and standard state, description, pattern length, alignment, XREF dependency, and retained signed dash, space, and dot lengths.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_linetypes(
        &self,
        Parameters(p): Parameters<ReadDrawingParams>,
    ) -> Result<CallToolResult, McpError> {
        fallible_dwg_session_read_op(
            &p.drawing_path,
            "list_linetypes",
            DrawingReadSession::list_linetypes,
        )
    }

    #[tool(
        description = "Get one linetype table record by handle or case-insensitive name. If both identities are supplied they must agree.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_linetype(
        &self,
        Parameters(p): Parameters<SymbolLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = autocad_reader::contract::SymbolSelector {
            handle: p.handle,
            name: p.name,
        };
        fallible_dwg_session_read_op(&p.drawing_path, "get_linetype", |session| {
            session.get_linetype(&selector)
        })
    }

    #[tool(
        description = "List text-style table records in deterministic numeric-handle order with stable identity, current and standard state, font files, height, width factor, oblique angle, generation flags, annotation state, and XREF dependency.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_text_styles(
        &self,
        Parameters(p): Parameters<ReadDrawingParams>,
    ) -> Result<CallToolResult, McpError> {
        fallible_dwg_session_read_op(
            &p.drawing_path,
            "list_text_styles",
            DrawingReadSession::list_text_styles,
        )
    }

    #[tool(
        description = "Get one text-style table record by handle or case-insensitive name. If both identities are supplied they must agree.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_text_style(
        &self,
        Parameters(p): Parameters<SymbolLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = autocad_reader::contract::SymbolSelector {
            handle: p.handle,
            name: p.name,
        };
        fallible_dwg_session_read_op(&p.drawing_path, "get_text_style", |session| {
            session.get_text_style(&selector)
        })
    }

    #[tool(
        description = "List dimension-style table records in deterministic numeric-handle order with stable identity, current and standard state, scale, line, text, unit, tolerance, and handle-reference data retained by the parser.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_dimension_styles(
        &self,
        Parameters(p): Parameters<ReadDrawingParams>,
    ) -> Result<CallToolResult, McpError> {
        fallible_dwg_session_read_op(
            &p.drawing_path,
            "list_dimension_styles",
            DrawingReadSession::list_dimension_styles,
        )
    }

    #[tool(
        description = "Get one dimension-style table record by handle or case-insensitive name. If both identities are supplied they must agree.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_dimension_style(
        &self,
        Parameters(p): Parameters<SymbolLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = autocad_reader::contract::SymbolSelector {
            handle: p.handle,
            name: p.name,
        };
        fallible_dwg_session_read_op(&p.drawing_path, "get_dimension_style", |session| {
            session.get_dimension_style(&selector)
        })
    }

    #[tool(
        description = "List named VIEW table records in deterministic numeric-handle order with stable identity, center, dimensions, target, direction, twist, lens, and clipping distances.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_named_views(
        &self,
        Parameters(p): Parameters<ReadDrawingParams>,
    ) -> Result<CallToolResult, McpError> {
        fallible_dwg_session_read_op(
            &p.drawing_path,
            "list_named_views",
            DrawingReadSession::list_named_views,
        )
    }

    #[tool(
        description = "Get one named VIEW table record by handle or case-insensitive name. If both identities are supplied they must agree.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_named_view(
        &self,
        Parameters(p): Parameters<SymbolLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = autocad_reader::contract::SymbolSelector {
            handle: p.handle,
            name: p.name,
        };
        fallible_dwg_session_read_op(&p.drawing_path, "get_named_view", |session| {
            session.get_named_view(&selector)
        })
    }

    #[tool(
        description = "List named UCS table records in deterministic numeric-handle order with stable identity, origin, and X/Y/Z axes.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn list_named_ucs(
        &self,
        Parameters(p): Parameters<ReadDrawingParams>,
    ) -> Result<CallToolResult, McpError> {
        fallible_dwg_session_read_op(
            &p.drawing_path,
            "list_named_ucs",
            DrawingReadSession::list_named_ucs,
        )
    }

    #[tool(
        description = "Get one named UCS table record by handle or case-insensitive name. If both identities are supplied they must agree.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    pub fn get_named_ucs(
        &self,
        Parameters(p): Parameters<SymbolLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let selector = autocad_reader::contract::SymbolSelector {
            handle: p.handle,
            name: p.name,
        };
        fallible_dwg_session_read_op(&p.drawing_path, "get_named_ucs", |session| {
            session.get_named_ucs(&selector)
        })
    }

    #[tool(
        description = "Plot a DWG layout to an absolute PDF output path via accoreconsole. \
        The layout must have a DWG To PDF.pc3 (or equivalent file-plotter) page setup \
        already configured in the drawing. Use list_layouts to discover layout names. \
        Windows only — returns an error on non-Windows platforms.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    pub fn plot_to_pdf(
        &self,
        Parameters(p): Parameters<PlotToPdfParams>,
    ) -> Result<CallToolResult, McpError> {
        let drawing = Path::new(&p.drawing_path);
        let output = std::path::PathBuf::from(&p.output);
        self.prepare_foreground_engine_work();
        match ops::plot::plot_to_pdf_with_activation(
            drawing,
            &p.layout,
            &output,
            &self.mutation_runtime,
        ) {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::json!({
                    "status": "ok",
                    "drawing": p.drawing_path,
                    "layout": p.layout,
                    "output": p.output,
                })
                .to_string(),
            )])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "plot failed: {e}"
            ))])),
        }
    }
}

#[tool_handler(router = self.active_tool_router)]
impl ServerHandler for AutocadServer {
    async fn on_initialized(&self, _context: rmcp::service::NotificationContext<rmcp::RoleServer>) {
        self.schedule_probe_after_initialization();
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(SERVER_NAME, SERVER_VERSION))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliToolOutput {
    pub text: String,
    pub is_error: bool,
}

/// Invoke an MCP tool by name with JSON params, returning the text output and
/// tool-level error status.
/// Used by the `call` CLI subcommand. Returns `Err("unknown tool: …")` if
/// `name` is not in the match — the completeness gate test detects this.
pub fn cli_dispatch(
    server: &AutocadServer,
    name: &str,
    params: serde_json::Value,
) -> anyhow::Result<CliToolOutput> {
    if !server.active_tool_router.has_route(name) {
        return Err(anyhow::anyhow!("unknown tool: {name}"));
    }
    let result = match name {
        "get_drawing" => server.get_drawing(Parameters(serde_json::from_value(params)?)),
        "list_entities" => server.list_entities(Parameters(serde_json::from_value(params)?)),
        "get_entity" => server.get_entity(Parameters(serde_json::from_value(params)?)),
        "list_layers" => server.list_layers(Parameters(serde_json::from_value(params)?)),
        "get_layer" => server.get_layer(Parameters(serde_json::from_value(params)?)),
        "create_layer" => server.create_layer(Parameters(serde_json::from_value(params)?)),
        "update_layer" => server.update_layer(Parameters(serde_json::from_value(params)?)),
        "rename_layer" => server.rename_layer(Parameters(serde_json::from_value(params)?)),
        "delete_layer" => server.delete_layer(Parameters(serde_json::from_value(params)?)),
        "list_xrefs" => server.list_xrefs(Parameters(params)),
        "get_xref" => server.get_xref(Parameters(params)),
        "attach_xref" => server.attach_xref(Parameters(params)),
        "update_xref" => server.update_xref(Parameters(params)),
        "detach_xref" => server.detach_xref(Parameters(params)),
        "list_xref_instances" => server.list_xref_instances(Parameters(params)),
        "get_xref_instance" => server.get_xref_instance(Parameters(params)),
        "insert_xref_instance" => server.insert_xref_instance(Parameters(params)),
        "update_xref_instance" => server.update_xref_instance(Parameters(params)),
        "delete_xref_instance" => server.delete_xref_instance(Parameters(params)),
        "reload_xref" => server.reload_xref(Parameters(params)),
        "unload_xref" => server.unload_xref(Parameters(params)),
        "bind_xref" => server.bind_xref(Parameters(params)),
        "resolve_xref_path" => server.resolve_xref_path(Parameters(params)),
        "list_xref_dependencies" => server.list_xref_dependencies(Parameters(params)),
        "list_blocks" => server.list_blocks(Parameters(serde_json::from_value(params)?)),
        "list_block_definitions" => {
            server.list_block_definitions(Parameters(serde_json::from_value(params)?))
        }
        "get_block_definition" => {
            server.get_block_definition(Parameters(serde_json::from_value(params)?))
        }
        "list_block_inserts" => {
            server.list_block_inserts(Parameters(serde_json::from_value(params)?))
        }
        "get_block_insert" => server.get_block_insert(Parameters(serde_json::from_value(params)?)),
        "read_title_blocks" => {
            server.read_title_blocks(Parameters(serde_json::from_value(params)?))
        }
        "dump_text" => server.dump_text(Parameters(serde_json::from_value(params)?)),
        "list_text" => server.list_text(Parameters(serde_json::from_value(params)?)),
        "get_text" => server.get_text(Parameters(serde_json::from_value(params)?)),
        "write_title_block" => {
            server.write_title_block(Parameters(serde_json::from_value(params)?))
        }
        "list_layouts" => server.list_layouts(Parameters(serde_json::from_value(params)?)),
        "get_layout" => server.get_layout(Parameters(serde_json::from_value(params)?)),
        "list_layout_viewports" => {
            server.list_layout_viewports(Parameters(serde_json::from_value(params)?))
        }
        "get_layout_viewport" => {
            server.get_layout_viewport(Parameters(serde_json::from_value(params)?))
        }
        "list_plot_settings" => {
            server.list_plot_settings(Parameters(serde_json::from_value(params)?))
        }
        "get_plot_setting" => server.get_plot_setting(Parameters(serde_json::from_value(params)?)),
        "list_linetypes" => server.list_linetypes(Parameters(serde_json::from_value(params)?)),
        "get_linetype" => server.get_linetype(Parameters(serde_json::from_value(params)?)),
        "list_text_styles" => server.list_text_styles(Parameters(serde_json::from_value(params)?)),
        "get_text_style" => server.get_text_style(Parameters(serde_json::from_value(params)?)),
        "list_dimension_styles" => {
            server.list_dimension_styles(Parameters(serde_json::from_value(params)?))
        }
        "get_dimension_style" => {
            server.get_dimension_style(Parameters(serde_json::from_value(params)?))
        }
        "list_named_views" => server.list_named_views(Parameters(serde_json::from_value(params)?)),
        "get_named_view" => server.get_named_view(Parameters(serde_json::from_value(params)?)),
        "list_named_ucs" => server.list_named_ucs(Parameters(serde_json::from_value(params)?)),
        "get_named_ucs" => server.get_named_ucs(Parameters(serde_json::from_value(params)?)),
        "plot_to_pdf" => server.plot_to_pdf(Parameters(serde_json::from_value(params)?)),
        other => return Err(anyhow::anyhow!("unknown tool: {other}")),
    }
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let is_error = result.is_error.unwrap_or(false);
    // Extract the first text content item as the CLI output string
    let text = result
        .content
        .into_iter()
        .find_map(|c| match c.raw {
            RawContent::Text(t) => Some(t.text),
            _ => None,
        })
        .unwrap_or_default();
    Ok(CliToolOutput { text, is_error })
}

fn should_schedule_probe(
    activation_mode: ActivationMode,
    engine_probe_mode: EngineProbeMode,
) -> Result<bool> {
    match (activation_mode, engine_probe_mode) {
        (ActivationMode::Disabled, EngineProbeMode::On) => Err(anyhow!(
            "--engine-probe on requires a mutation-enabled server; plain Preview serve is read-only"
        )),
        (ActivationMode::Disabled, _) => Ok(false),
        (ActivationMode::Preview, EngineProbeMode::Auto | EngineProbeMode::On) => Ok(true),
        (ActivationMode::Preview, EngineProbeMode::Off) => Ok(false),
        (ActivationMode::Release, EngineProbeMode::On) => Ok(true),
        (ActivationMode::Release, EngineProbeMode::Auto | EngineProbeMode::Off) => Ok(false),
    }
}

pub async fn serve_stdio(
    mut server: AutocadServer,
    engine_probe_mode: EngineProbeMode,
) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    server.schedule_probe_on_initialized =
        should_schedule_probe(server.activation_mode, engine_probe_mode)?;
    let probe = Arc::clone(&server.probe);
    let service = match server.serve(stdio()).await {
        Ok(service) => service,
        Err(error) => {
            probe.shutdown();
            return Err(error.into());
        }
    };
    let wait_result = service.waiting().await;
    let snapshot = probe.shutdown();
    tracing::debug!(
        target: "autocad_mcp::probe",
        state = ?snapshot.state,
        "advisory Core Console probe stopped with MCP service"
    );
    wait_result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::entities::{AttributeEntity, EntityType, Insert};
    use acadrust::types::Vector3;
    use acadrust::{CadDocument, DxfWriter};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn full_server() -> AutocadServer {
        #[cfg(feature = "preview")]
        {
            AutocadServer::experimental()
        }
        #[cfg(not(feature = "preview"))]
        {
            AutocadServer::new()
        }
    }

    fn full_server_with_profiles(profiles: Arc<ops::profiles::ProfileRegistry>) -> AutocadServer {
        #[cfg(feature = "preview")]
        {
            AutocadServer::experimental_with_title_block_profiles(profiles)
        }
        #[cfg(not(feature = "preview"))]
        {
            AutocadServer::new_with_title_block_profiles(profiles)
        }
    }

    fn empty_dxf() -> PathBuf {
        let doc = CadDocument::new();
        let path = std::env::temp_dir().join(format!(
            "server_test_empty_{}_{}.dxf",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        DxfWriter::new(&doc).write_to_file(&path).unwrap();
        path
    }

    fn duplicate_title_block_dxf() -> PathBuf {
        let mut doc = CadDocument::new();
        let mut insert = Insert::new("AUTOCAD_MCP_GENERIC", Vector3::new(0.0, 0.0, 0.0));
        insert
            .attributes
            .push(AttributeEntity::simple("revision", "P01"));
        insert
            .attributes
            .push(AttributeEntity::simple("REVISION", "P02"));
        insert
            .attributes
            .push(AttributeEntity::simple("SHEET_NUMBER", "1"));
        doc.add_entity(EntityType::Insert(insert)).unwrap();

        let path = std::env::temp_dir().join(format!(
            "server_test_duplicate_title_block_{}_{}.dxf",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        DxfWriter::new(&doc).write_to_file(&path).unwrap();
        path
    }

    fn generic_title_block_dxf() -> PathBuf {
        let mut doc = CadDocument::new();
        let mut insert = Insert::new("AUTOCAD_MCP_GENERIC", Vector3::new(0.0, 0.0, 0.0));
        for (tag, value) in [
            ("DRAWING_NUMBER", "A-001"),
            ("REFERENCE", "REF"),
            ("REVISION", "P01"),
            ("SHEET_COUNT", "10"),
            ("SHEET_NUMBER", "1"),
            ("TITLE_LINE_1", "TITLE"),
            ("TITLE_LINE_2", "SUBTITLE"),
        ] {
            insert.attributes.push(AttributeEntity::simple(tag, value));
        }
        doc.add_entity(EntityType::Insert(insert)).unwrap();

        let path = std::env::temp_dir().join(format!(
            "server_test_generic_title_block_{}_{}.dxf",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        DxfWriter::new(&doc).write_to_file(&path).unwrap();
        path
    }

    fn tool_text(result: CallToolResult) -> String {
        result
            .content
            .into_iter()
            .find_map(|content| match content.raw {
                RawContent::Text(text) => Some(text.text),
                _ => None,
            })
            .unwrap_or_default()
    }

    #[test]
    fn initialize_identity_is_the_product_not_the_transport_crate() {
        let info = full_server().get_info();
        assert_eq!(info.server_info.name, SERVER_NAME);
        assert_eq!(info.server_info.version, SERVER_VERSION);
    }

    #[test]
    fn list_text_parameters_are_closed_and_expose_owner_selectors() {
        let params = serde_json::from_value::<ListTextParams>(serde_json::json!({
            "drawing_path": "/tmp/example.dwg",
            "text_types": ["TEXT", "MTEXT"],
            "layer": "ANNO",
            "owner_handle": "1F",
            "owner_type": "entity",
            "owner_name": "INSERT"
        }))
        .unwrap();
        assert_eq!(params.text_types.unwrap().len(), 2);
        assert!(serde_json::from_value::<ListTextParams>(serde_json::json!({
            "drawing_path": "/tmp/example.dwg",
            "unexpected": true
        }))
        .is_err());

        let schema = serde_json::to_value(schemars::schema_for!(ListTextParams)).unwrap();
        assert_eq!(schema["additionalProperties"], serde_json::json!(false));
        assert_eq!(schema["required"], serde_json::json!(["drawing_path"]));
        let properties = schema["properties"].as_object().unwrap();
        let mut property_names = properties.keys().map(String::as_str).collect::<Vec<_>>();
        property_names.sort_unstable();
        assert_eq!(
            property_names,
            [
                "drawing_path",
                "layer",
                "owner_handle",
                "owner_name",
                "owner_type",
                "text_types"
            ]
        );
        assert!(schema.to_string().contains("\"entity\""));
    }

    #[test]
    fn list_layers_returns_success() {
        let p = empty_dxf();
        let result = full_server().list_layers(rmcp::handler::server::wrapper::Parameters(
            DrawingPathParams {
                drawing_path: p.to_str().unwrap().to_string(),
            },
        ));
        std::fs::remove_file(&p).ok();
        let r = result.unwrap();
        assert_eq!(r.is_error, Some(false));
        assert!(!r.content.is_empty());
    }

    #[test]
    fn dxf_layer_mutation_bypasses_autocad_activation() {
        let p = empty_dxf();
        let server = full_server();
        assert!(server.mutation_runtime().selected().is_none());
        assert_eq!(
            server.probe.snapshot().state,
            crate::probe::ProbeState::Disabled
        );
        let result = server
            .create_layer(rmcp::handler::server::wrapper::Parameters(
                CreateLayerParams {
                    drawing_path: p.to_string_lossy().into_owned(),
                    name: "ACTIVATION_BYPASS".to_string(),
                    properties: None,
                },
            ))
            .unwrap();
        assert_eq!(
            result.is_error,
            Some(false),
            "{}",
            tool_text(result.clone())
        );
        assert!(server.mutation_runtime().selected().is_none());
        assert_eq!(
            server.probe.snapshot().state,
            crate::probe::ProbeState::Disabled
        );
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn missing_file_returns_error_result() {
        let directory = tempfile::tempdir().unwrap();
        let missing_dxf = directory.path().join("drawing.dxf");
        assert!(!missing_dxf.exists());
        let result = full_server().list_layers(rmcp::handler::server::wrapper::Parameters(
            DrawingPathParams {
                drawing_path: missing_dxf.to_string_lossy().into_owned(),
            },
        ));
        let r = result.unwrap();
        assert_eq!(r.is_error, Some(true));
        let text = tool_text(r);
        assert!(text.contains("code=drawing_not_found"), "got: {text}");
    }

    #[test]
    fn create_layer_rejects_null_property_with_reason_code() {
        let p = empty_dxf();
        let result = full_server().create_layer(rmcp::handler::server::wrapper::Parameters(
            CreateLayerParams {
                drawing_path: p.to_str().unwrap().to_string(),
                name: "ANNO".to_string(),
                properties: Some(serde_json::json!({ "off": null })),
            },
        ));
        std::fs::remove_file(&p).ok();
        let r = result.unwrap();
        assert_eq!(r.is_error, Some(true));
        let text = tool_text(r);
        assert!(text.contains("code=invalid_layer_property"), "got: {text}");
    }

    #[test]
    fn title_blocks_returns_success() {
        let p = empty_dxf();
        let result = full_server().read_title_blocks(rmcp::handler::server::wrapper::Parameters(
            ReadTitleBlocksParams {
                drawing_path: p.to_str().unwrap().to_string(),
                attribute_value_mode: TitleBlockAttributeValueMode::Split,
            },
        ));
        std::fs::remove_file(&p).ok();
        assert_eq!(result.unwrap().is_error, Some(false));
    }

    #[test]
    fn title_block_read_returns_duplicate_normalized_tags_as_partial_success() {
        let path = duplicate_title_block_dxf();
        let result = full_server()
            .read_title_blocks(rmcp::handler::server::wrapper::Parameters(
                ReadTitleBlocksParams {
                    drawing_path: path.to_string_lossy().into_owned(),
                    attribute_value_mode: TitleBlockAttributeValueMode::Split,
                },
            ))
            .unwrap();
        std::fs::remove_file(path).ok();

        assert_eq!(result.is_error, Some(false));
        assert_eq!(
            result.structured_content.as_ref().unwrap()["status"],
            "partial"
        );
        let text = tool_text(result);
        let blocks: Vec<ops::title_blocks::TitleBlockInfo> = serde_json::from_str(&text).unwrap();
        assert_eq!(
            blocks[0].attribute_arrays["REVISION"],
            ["P01".to_string(), "P02".to_string()]
        );
        assert_eq!(blocks[0].attributes["SHEET_NUMBER"], "1");
    }

    #[test]
    fn title_block_array_mode_returns_singletons_and_duplicates_as_arrays() {
        let path = duplicate_title_block_dxf();
        let result = full_server()
            .read_title_blocks(rmcp::handler::server::wrapper::Parameters(
                ReadTitleBlocksParams {
                    drawing_path: path.to_string_lossy().into_owned(),
                    attribute_value_mode: TitleBlockAttributeValueMode::Arrays,
                },
            ))
            .unwrap();
        std::fs::remove_file(path).ok();

        assert_eq!(result.is_error, Some(false));
        assert_eq!(
            result.structured_content.as_ref().unwrap()["attribute_value_mode"],
            "arrays"
        );
        let text = tool_text(result);
        let blocks: Vec<ops::title_blocks::TitleBlockInfo> = serde_json::from_str(&text).unwrap();
        assert!(blocks[0].attributes.is_empty());
        assert_eq!(
            blocks[0].attribute_arrays["REVISION"],
            ["P01".to_string(), "P02".to_string()]
        );
        assert_eq!(
            blocks[0].attribute_arrays["SHEET_NUMBER"],
            ["1".to_string()]
        );
    }

    #[test]
    fn title_block_write_rejects_canonical_field_collisions_before_opening() {
        let result = full_server()
            .write_title_block(rmcp::handler::server::wrapper::Parameters(
                WriteTitleBlockParams {
                    drawing_path: "/nonexistent/drawing.dxf".to_string(),
                    fields: std::collections::HashMap::from([
                        ("revision".to_string(), "P02".to_string()),
                        (" REVISION ".to_string(), "P03".to_string()),
                    ]),
                },
            ))
            .unwrap();

        assert_eq!(result.is_error, Some(true));
        let text = tool_text(result);
        assert!(
            text.contains("duplicate canonical field keys collapse to 'revision'"),
            "unexpected error: {text}"
        );
        assert!(!text.contains("failed to open drawing"), "{text}");
    }

    #[test]
    fn dxf_title_block_mutation_bypasses_autocad_activation() {
        let path = generic_title_block_dxf();
        let server = full_server();
        assert_eq!(
            server.probe.snapshot().state,
            crate::probe::ProbeState::Disabled
        );
        let result = server
            .write_title_block(rmcp::handler::server::wrapper::Parameters(
                WriteTitleBlockParams {
                    drawing_path: path.to_string_lossy().into_owned(),
                    fields: std::collections::HashMap::from([(
                        "sheet".to_string(),
                        "2".to_string(),
                    )]),
                },
            ))
            .unwrap();
        assert_eq!(
            result.is_error,
            Some(false),
            "{}",
            tool_text(result.clone())
        );
        assert!(server.mutation_runtime().selected().is_none());
        assert_eq!(
            server.probe.snapshot().state,
            crate::probe::ProbeState::Disabled
        );
        std::fs::remove_file(path).ok();
    }

    #[cfg(all(feature = "preview", not(target_os = "windows")))]
    #[test]
    fn preview_dwg_title_block_selects_acadrust_before_path_or_autocad_access() {
        let server = full_server();
        let result = server
            .write_title_block(rmcp::handler::server::wrapper::Parameters(
                WriteTitleBlockParams {
                    drawing_path: "/nonexistent/preview-title-block.dwg".to_string(),
                    fields: std::collections::HashMap::from([(
                        "revision".to_string(),
                        "P02".to_string(),
                    )]),
                },
            ))
            .unwrap();

        assert_eq!(result.is_error, Some(true));
        let response: serde_json::Value = serde_json::from_str(&tool_text(result)).unwrap();
        assert_eq!(response["backend"], "acadrust_preview");
        assert_eq!(response["code"], "preview_writer_unsupported_platform");
        assert_eq!(response["installation_may_have_occurred"], false);
        assert!(server.mutation_runtime().selected().is_none());
        assert_eq!(
            server.probe.snapshot().state,
            crate::probe::ProbeState::Disabled
        );
    }

    #[test]
    fn administrator_profile_mutation_reports_pack_authority_and_digest() {
        let pack_json = r#"{
            "profile_pack_schema": 1,
            "pack_id": "example.title-blocks",
            "pack_version": "1.0.0",
            "title_block_schema": 1,
            "profiles": [{
                "profile_id": "EXAMPLE_A1",
                "schema_version": 1,
                "description": "Example title block",
                "source_evidence": ["review:unit-test"],
                "fingerprint": {
                    "block_name": "EXAMPLE_A1",
                    "attribute_tags": ["DRAWING_NO", "REV"]
                },
                "fields": {
                    "drawing_number": "DRAWING_NO",
                    "revision": "REV"
                }
            }]
        }"#;
        let pack = ops::profiles::parse_administrator_profile_pack(pack_json.as_bytes()).unwrap();
        let expected_digest = pack.identity().sha256.clone();
        let registry =
            Arc::new(ops::profiles::ProfileRegistry::with_administrator_pack(pack).unwrap());

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("custom.dxf");
        let mut document = CadDocument::new();
        let mut insert = Insert::new("EXAMPLE_A1", Vector3::new(0.0, 0.0, 0.0));
        insert
            .attributes
            .push(AttributeEntity::simple("DRAWING_NO", "A-001"));
        insert
            .attributes
            .push(AttributeEntity::simple("REV", "P01"));
        document.add_entity(EntityType::Insert(insert)).unwrap();
        DxfWriter::new(&document).write_to_file(&path).unwrap();

        let result = full_server_with_profiles(registry)
            .write_title_block(rmcp::handler::server::wrapper::Parameters(
                WriteTitleBlockParams {
                    drawing_path: path.to_string_lossy().into_owned(),
                    fields: std::collections::HashMap::from([(
                        "revision".to_string(),
                        "P02".to_string(),
                    )]),
                },
            ))
            .unwrap();
        assert_eq!(
            result.is_error,
            Some(false),
            "{}",
            tool_text(result.clone())
        );
        let response: serde_json::Value = serde_json::from_str(&tool_text(result)).unwrap();
        assert_eq!(response["profile_id"], "EXAMPLE_A1");
        assert_eq!(response["profile_authority"], "administrator");
        assert_eq!(response["profile_pack_id"], "example.title-blocks");
        assert_eq!(response["profile_pack_version"], "1.0.0");
        assert_eq!(response["profile_pack_sha256"], expected_digest);
    }

    #[test]
    fn xrefs_returns_success() {
        let p = empty_dxf();
        let result = full_server().list_xrefs(rmcp::handler::server::wrapper::Parameters(
            serde_json::json!({"drawing_path": p.to_str().unwrap()}),
        ));
        std::fs::remove_file(&p).ok();
        assert_eq!(result.unwrap().is_error, Some(false));
    }

    #[test]
    fn xref_domain_errors_use_tool_error_results() {
        let p = empty_dxf();
        let result = full_server()
            .get_xref(rmcp::handler::server::wrapper::Parameters(
                serde_json::json!({"drawing_path": p.to_str().unwrap()}),
            ))
            .unwrap();
        std::fs::remove_file(&p).ok();
        assert_eq!(result.is_error, Some(true));
        assert!(tool_text(result).contains("code=missing_identity"));
    }

    #[test]
    fn blocks_returns_success() {
        let p = empty_dxf();
        let result = full_server().list_blocks(rmcp::handler::server::wrapper::Parameters(
            DrawingPathParams {
                drawing_path: p.to_str().unwrap().to_string(),
            },
        ));
        std::fs::remove_file(&p).ok();
        assert_eq!(result.unwrap().is_error, Some(false));
    }

    #[test]
    fn text_returns_success() {
        let p = empty_dxf();
        let result = full_server().dump_text(rmcp::handler::server::wrapper::Parameters(
            DrawingPathParams {
                drawing_path: p.to_str().unwrap().to_string(),
            },
        ));
        std::fs::remove_file(&p).ok();
        assert_eq!(result.unwrap().is_error, Some(false));
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use acadrust::{CadDocument, DxfWriter};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn full_server() -> AutocadServer {
        #[cfg(feature = "preview")]
        {
            AutocadServer::experimental()
        }
        #[cfg(not(feature = "preview"))]
        {
            AutocadServer::new()
        }
    }

    fn empty_dxf() -> PathBuf {
        let doc = CadDocument::new();
        let path = std::env::temp_dir().join(format!(
            "server_cli_test_empty_{}_{}.dxf",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        DxfWriter::new(&doc).write_to_file(&path).unwrap();
        path
    }

    #[test]
    fn cli_dispatch_covers_all_mcp_tools() {
        let server = full_server();
        for tool in AutocadServer::tool_router().list_all() {
            let result = cli_dispatch(
                &server,
                &tool.name,
                serde_json::Value::Object(Default::default()),
            );
            if let Err(e) = result {
                assert!(
                    !e.to_string().contains("unknown tool"),
                    "cli_dispatch missing match arm for MCP tool '{}'. \
                     Add the two-line arm in cli_dispatch().",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn read_only_router_fails_closed_for_every_state_changing_tool() {
        let canonical = AutocadServer::tool_router().list_all();
        assert_eq!(canonical.len(), 51);
        assert_eq!(
            canonical
                .iter()
                .filter(|tool| {
                    tool.annotations
                        .as_ref()
                        .and_then(|annotations| annotations.read_only_hint)
                        == Some(true)
                })
                .count(),
            36
        );

        let server = AutocadServer::read_only();
        let active = server.list_active_tools();
        assert_eq!(active.len(), 36);
        assert!(active.iter().all(|tool| {
            tool.annotations
                .as_ref()
                .and_then(|annotations| annotations.read_only_hint)
                == Some(true)
        }));

        for tool in canonical {
            let read_only = tool
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.read_only_hint)
                == Some(true);
            let result = cli_dispatch(
                &server,
                &tool.name,
                serde_json::Value::Object(Default::default()),
            );
            if read_only {
                if let Err(error) = result {
                    assert!(
                        !error.to_string().contains("unknown tool"),
                        "read-only tool {} was removed from the active router",
                        tool.name
                    );
                }
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    format!("unknown tool: {}", tool.name)
                );
            }
        }
    }

    #[test]
    fn server_modes_preserve_static_tool_counts_and_lazy_activation() {
        let plain = AutocadServer::new();
        assert!(plain.mutation_runtime().selected().is_none());

        #[cfg(feature = "preview")]
        {
            assert_eq!(plain.list_active_tools().len(), 36);
            assert_eq!(
                plain
                    .mutation_runtime()
                    .acquire(crate::activation::MutationCapability::Plot)
                    .unwrap_err(),
                crate::activation::ActivationError::Disabled
            );

            let experimental = AutocadServer::experimental();
            assert_eq!(experimental.list_active_tools().len(), 51);
            assert!(experimental.mutation_runtime().selected().is_none());
        }

        #[cfg(not(feature = "preview"))]
        {
            assert_eq!(plain.list_active_tools().len(), 51);
            assert_eq!(
                plain
                    .mutation_runtime()
                    .acquire(crate::activation::MutationCapability::Plot)
                    .unwrap_err(),
                crate::activation::ActivationError::ReleaseQualificationUnavailable
            );
        }
    }

    #[test]
    fn probe_process_policy_is_mode_scoped() {
        assert!(!should_schedule_probe(ActivationMode::Disabled, EngineProbeMode::Auto).unwrap());
        assert!(!should_schedule_probe(ActivationMode::Disabled, EngineProbeMode::Off).unwrap());
        assert!(should_schedule_probe(ActivationMode::Disabled, EngineProbeMode::On).is_err());
        assert!(should_schedule_probe(ActivationMode::Preview, EngineProbeMode::Auto).unwrap());
        assert!(should_schedule_probe(ActivationMode::Preview, EngineProbeMode::On).unwrap());
        assert!(!should_schedule_probe(ActivationMode::Preview, EngineProbeMode::Off).unwrap());
        assert!(!should_schedule_probe(ActivationMode::Release, EngineProbeMode::Auto).unwrap());
        assert!(should_schedule_probe(ActivationMode::Release, EngineProbeMode::On).unwrap());
        assert!(!should_schedule_probe(ActivationMode::Release, EngineProbeMode::Off).unwrap());
    }

    #[test]
    fn probe_stays_deferred_until_the_initialized_notification_hook() {
        let mut server = full_server();
        server.schedule_probe_on_initialized = true;
        assert_eq!(
            server.probe.snapshot().state,
            crate::probe::ProbeState::Disabled
        );

        server.schedule_probe_after_initialization();
        assert_eq!(
            server.probe.snapshot().state,
            crate::probe::ProbeState::Scheduled
        );
        server.probe.shutdown();
    }

    #[test]
    fn probe_off_keeps_foreground_operations_observably_disabled() {
        let server = full_server();
        server.prepare_foreground_engine_work();
        assert_eq!(
            server.probe.snapshot().state,
            crate::probe::ProbeState::Disabled
        );
    }

    #[test]
    fn all_expanded_read_tools_reject_dxf_with_the_shared_format_code() {
        let path = empty_dxf();
        let drawing_path = path.to_string_lossy().into_owned();
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
        assert_eq!(cases.len(), 24);

        for (tool, params) in cases {
            let result = cli_dispatch(&full_server(), tool, params).unwrap();
            assert!(result.is_error, "{tool} unexpectedly accepted DXF input");
            assert!(
                result.text.starts_with("code=unsupported_format "),
                "{tool}: {}",
                result.text
            );
        }
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn expanded_read_tools_require_absolute_paths() {
        let result = cli_dispatch(
            &full_server(),
            "get_drawing",
            serde_json::json!({"drawing_path": "relative/drawing.dwg"}),
        )
        .unwrap();

        assert!(result.is_error);
        assert!(
            result.text.starts_with("code=invalid_drawing_path "),
            "{}",
            result.text
        );
    }

    #[test]
    fn cli_layer_property_errors_are_reason_coded() {
        let p = empty_dxf();
        let result = cli_dispatch(
            &full_server(),
            "create_layer",
            serde_json::json!({
                "drawing_path": p.to_str().unwrap(),
                "name": "ANNO",
                "properties": {
                    "unknown": true
                }
            }),
        )
        .unwrap();
        std::fs::remove_file(&p).ok();

        assert!(result.is_error, "got success text: {}", result.text);
        assert!(
            result.text.contains("code=invalid_layer_property"),
            "got: {}",
            result.text
        );
    }

    #[test]
    fn cli_xref_parameter_errors_are_reason_coded() {
        let result = cli_dispatch(
            &full_server(),
            "list_xrefs",
            serde_json::json!({
                "drawing_path": "/tmp/example.dxf",
                "path": "obsolete"
            }),
        )
        .unwrap();

        assert!(result.is_error, "got success text: {}", result.text);
        assert!(
            result.text.starts_with("code=invalid_parameters "),
            "got: {}",
            result.text
        );
    }
}
