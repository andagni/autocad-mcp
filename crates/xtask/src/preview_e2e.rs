//! Closed licensed-host evaluation of one Windows Preview MCPB against one
//! exact registered AutoCAD target.

use anyhow::{anyhow, Context, Result};
use autocad_mcp::{
    activation::{MutationCapability, ACTIVATION_CATALOGUE_AUTHORITY},
    activation_platform::{
        inspect_exact_registered_preview_activation, require_fixed_local_windows_volume,
        ExactPreviewActivationInspection,
    },
    certification::xref_sha256_file,
    ops::{
        layers::{LayerMutationResult, LayerRecord},
        profile_admin::validate_profile_pack,
        profiles::{
            load_active_profile_registry, ProfileAuthority, ProfilePackSummary,
            TitleBlockFingerprint,
        },
        title_blocks::TitleBlockInfo,
        xrefs::{AttachXrefResponse, ReferenceType, XrefAttachmentRecord, XrefInstanceRecord},
    },
    reader::inspect_dwg_version,
};
use release_packager::{
    mcp_stdio::{McpShutdownObservation, McpStdioLaunch, McpStdioSession},
    smoke::{
        prepare_preview_evaluation_package, validate_preview_evaluation_tool_surface,
        PreparedPreviewEvaluationPackage,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

const PLAN_SCHEMA_VERSION: u32 = 1;
const REPORT_SCHEMA_VERSION: u32 = 1;
const PLAN_KIND: &str = "preview_autocad_e2e_plan";
const REPORT_KIND: &str = "preview_autocad_e2e_report";
const AUTHORITY: &str = ACTIVATION_CATALOGUE_AUTHORITY;
const EXPECTED_DWG_FORMAT: &str = "AC1032";
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const MUTATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const PROBE_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(135);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(90);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MIN_PDF_BYTES: u64 = 256;
const MAX_PLAN_BYTES: u64 = 1024 * 1024;
const MAX_EXTERNAL_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_PDF_TAIL_BYTES: u64 = 64 * 1024;
const EXPECTED_TOOL_COUNT: usize = 51;
const ACCORECONSOLE_ENV: &str = "AUTOCAD_MCP_ACCORECONSOLE_PATH";
const TITLE_BLOCK_PROFILES_ENV: &str = "AUTOCAD_MCP_TITLE_BLOCK_PROFILES";
const PROBE_LOG_MARKER: &str = "serve-only advisory Core Console probe completed";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationPlan {
    schema_version: u32,
    artifact_kind: String,
    authority: String,
    package: FileInput,
    activation_target: ActivationTargetPlan,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    title_block_profiles: Option<TitleBlockProfilesPlan>,
    cases: EvaluationCases,
}

fn deserialize_required_nullable<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileInput {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationTargetPlan {
    catalogue_sha256: String,
    target_id: String,
    accoreconsole_path: String,
    accoreconsole_sha256: String,
    fixed_file_version: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TitleBlockProfilesPlan {
    path: String,
    sha256: String,
    pack_id: String,
    pack_version: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationCases {
    read: ReadCasePlan,
    title_block_write: TitleBlockCasePlan,
    layer_mutation: LayerCasePlan,
    plot: PlotCasePlan,
    xref_attach: XrefCasePlan,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadCasePlan {
    drawing: FileInput,
    expected_layout: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TitleBlockCasePlan {
    drawing: FileInput,
    fields: BTreeMap<String, String>,
    expected_profile: ExpectedProfilePlan,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedProfilePlan {
    profile_id: String,
    profile_authority: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LayerCasePlan {
    drawing: FileInput,
    created_name: String,
    renamed_name: String,
    create_properties: BTreeMap<String, Value>,
    update_properties: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlotCasePlan {
    drawing: FileInput,
    layout: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct XrefCasePlan {
    host: FileInput,
    source: FileInput,
    name: String,
    reference_type: String,
    placement: XrefPlacementPlan,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct XrefPlacementPlan {
    owner_type: String,
    layer_name: String,
    insertion_point: Point3Plan,
    scale: Point3Plan,
    rotation_degrees: f64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Point3Plan {
    x: f64,
    y: f64,
    z: f64,
}

#[derive(Clone, Debug)]
struct Preflight {
    invocation_started: Instant,
    plan: EvaluationPlan,
    plan_sha256: String,
    activation: ExactPreviewActivationInspection,
    profile_pack: Option<ProfilePackSummary>,
    runner: RunnerObservation,
    host: HostObservation,
}

#[derive(Clone, Debug)]
struct StagedCases {
    read: PathBuf,
    title_block: PathBuf,
    layer: PathBuf,
    plot: PathBuf,
    xref_host: PathBuf,
    xref_source: PathBuf,
    plot_pdf: PathBuf,
}

#[derive(Clone, Debug, Default)]
struct MutationState {
    title_block_target_inserts: Option<usize>,
    layer_handle: Option<String>,
    plot_written: bool,
    xref_attachment_handle: Option<String>,
    xref_instance_handle: Option<String>,
}

struct SessionHarness<'a> {
    work_dir: &'a Path,
    preflight: &'a Preflight,
    package: &'a PreparedPreviewEvaluationPackage,
    staged: &'a StagedCases,
    overall_started: Instant,
}

type CaseEvidence = (Vec<String>, Vec<String>, Vec<String>);
type CaseValueEvidence<T> = (T, Vec<String>, Vec<String>, Vec<String>);

#[derive(Clone, Debug, Serialize)]
pub struct EvaluationSummary {
    pub result: String,
    pub work_dir: String,
    pub report: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct EvaluationReport {
    schema_version: u32,
    artifact_kind: &'static str,
    authority: &'static str,
    result: String,
    subject: SubjectReport,
    runner: RunnerObservation,
    host: HostObservation,
    activation_target: ActivationReport,
    title_block_profiles: Option<ProfileReport>,
    probe: ProbeReport,
    sessions: Vec<SessionReport>,
    cases: Vec<CaseReport>,
    limitations: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct SubjectReport {
    plan_sha256: String,
    package_sha256: String,
    package_name: String,
    package_version: String,
    package_mode: &'static str,
    package_target: &'static str,
    manifest_sha256: String,
    binary_sha256: String,
    activation_catalogue_sha256: String,
    activation_binding_sha256: String,
    signature_state: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RunnerObservation {
    git_commit: String,
    runner_tree_state: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct HostObservation {
    operating_system: String,
    architecture: String,
    windows_version: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivationReport {
    target_id: String,
    release_year: u16,
    registry_family: String,
    product_language_key: String,
    ui_locale: String,
    maintained_target: bool,
    fixed_file_version: String,
    engine_sha256: String,
    engine_identity_sha256_before: String,
    engine_identity_sha256_after: String,
    profile_arg_sha256: String,
    profile_policy_id: String,
    profile_policy_sha256: String,
    operation_families: Vec<String>,
    drawing_formats: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileReport {
    pack_id: String,
    pack_version: String,
    sha256: String,
    profile_count: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeReport {
    result: String,
    elapsed_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionReport {
    session_id: &'static str,
    result: String,
    arguments: Vec<&'static str>,
    initialized: bool,
    tool_count: Option<usize>,
    exit_success: bool,
    active_processes_after_exit: Option<u32>,
    elapsed_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseReport {
    case_id: &'static str,
    result: String,
    input_sha256: Vec<String>,
    staged_inputs: Vec<&'static str>,
    output_sha256: Vec<String>,
    response_sha256: Vec<String>,
    assertions: Vec<String>,
    failure_code: Option<String>,
    elapsed_ms: u64,
}

impl CaseReport {
    fn new(
        case_id: &'static str,
        input_sha256: Vec<String>,
        staged_inputs: Vec<&'static str>,
    ) -> Self {
        Self {
            case_id,
            result: "evaluation_failed".to_string(),
            input_sha256,
            staged_inputs,
            output_sha256: Vec::new(),
            response_sha256: Vec::new(),
            assertions: Vec::new(),
            failure_code: None,
            elapsed_ms: 0,
        }
    }

    fn pass(&mut self) {
        self.result = "evaluation_passed".to_string();
        self.failure_code = None;
    }

    fn fail(&mut self, code: &str) {
        self.result = "evaluation_failed".to_string();
        self.failure_code = Some(code.to_string());
    }
}

fn parse_plan(path: &Path) -> Result<(EvaluationPlan, String)> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("inspect evaluation plan {}", path.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("evaluation plan must be a regular file"));
    }
    if metadata.len() > MAX_PLAN_BYTES {
        return Err(anyhow!(
            "evaluation plan exceeds the {MAX_PLAN_BYTES}-byte bound"
        ));
    }
    let bytes =
        fs::read(path).with_context(|| format!("read evaluation plan {}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(anyhow!("evaluation plan changed while it was read"));
    }
    let value = distribution_approval::parse_strict_json(&bytes)
        .context("strictly parse evaluation plan")?;
    let plan: EvaluationPlan =
        serde_json::from_value(value).context("validate closed evaluation plan schema")?;
    validate_plan(&plan)?;
    Ok((plan, format!("{:x}", Sha256::digest(&bytes))))
}

fn validate_plan(plan: &EvaluationPlan) -> Result<()> {
    if plan.schema_version != PLAN_SCHEMA_VERSION
        || plan.artifact_kind != PLAN_KIND
        || plan.authority != AUTHORITY
    {
        return Err(anyhow!(
            "evaluation plan identity must be schema {PLAN_SCHEMA_VERSION}, kind {PLAN_KIND}, authority {AUTHORITY}"
        ));
    }

    for (label, input) in plan_inputs(plan) {
        require_windows_drive_absolute(&input.path, label)?;
        require_lowercase_sha256(&input.sha256, &format!("{label}.sha256"))?;
    }
    require_lowercase_sha256(
        &plan.activation_target.catalogue_sha256,
        "activation_target.catalogue_sha256",
    )?;
    require_lowercase_sha256(
        &plan.activation_target.accoreconsole_sha256,
        "activation_target.accoreconsole_sha256",
    )?;
    require_windows_drive_absolute(
        &plan.activation_target.accoreconsole_path,
        "activation_target.accoreconsole_path",
    )?;
    require_identifier(
        &plan.activation_target.target_id,
        "activation_target.target_id",
        false,
    )?;
    if !plan.activation_target.target_id.starts_with("autocad-")
        || !plan.activation_target.target_id.ends_with("-preview-v1")
    {
        return Err(anyhow!(
            "activation_target.target_id must be a canonical Preview catalogue identifier"
        ));
    }
    require_bounded_text(
        &plan.activation_target.fixed_file_version,
        "activation_target.fixed_file_version",
        128,
    )?;

    if let Some(profiles) = &plan.title_block_profiles {
        require_windows_drive_absolute(&profiles.path, "title_block_profiles.path")?;
        require_lowercase_sha256(&profiles.sha256, "title_block_profiles.sha256")?;
        require_identifier(&profiles.pack_id, "title_block_profiles.pack_id", false)?;
        require_bounded_text(
            &profiles.pack_version,
            "title_block_profiles.pack_version",
            64,
        )?;
    }

    require_bounded_text(
        &plan.cases.read.expected_layout,
        "cases.read.expected_layout",
        256,
    )?;
    require_bounded_text(&plan.cases.plot.layout, "cases.plot.layout", 256)?;
    if plan.cases.title_block_write.fields.is_empty() {
        return Err(anyhow!("title_block_write.fields must not be empty"));
    }
    for (field, value) in &plan.cases.title_block_write.fields {
        require_identifier(field, "title-block canonical field", false)?;
        require_bounded_text(value, "title-block sentinel", 256)?;
        if !value.starts_with("MCP-E2E-") {
            return Err(anyhow!(
                "title-block sentinel values must begin with MCP-E2E-"
            ));
        }
    }
    require_bounded_text(
        &plan.cases.title_block_write.expected_profile.profile_id,
        "expected_profile.profile_id",
        256,
    )?;
    let expected_authority = &plan
        .cases
        .title_block_write
        .expected_profile
        .profile_authority;
    if !matches!(expected_authority.as_str(), "embedded" | "administrator") {
        return Err(anyhow!(
            "expected_profile.profile_authority must be embedded or administrator"
        ));
    }
    if (plan.title_block_profiles.is_some()) != (expected_authority == "administrator") {
        return Err(anyhow!(
            "administrator profile authority must agree with title_block_profiles presence"
        ));
    }

    validate_layer_name(
        &plan.cases.layer_mutation.created_name,
        "layer_mutation.created_name",
    )?;
    validate_layer_name(
        &plan.cases.layer_mutation.renamed_name,
        "layer_mutation.renamed_name",
    )?;
    if plan
        .cases
        .layer_mutation
        .created_name
        .eq_ignore_ascii_case(&plan.cases.layer_mutation.renamed_name)
    {
        return Err(anyhow!("created and renamed layer names must differ"));
    }
    validate_layer_properties(
        &plan.cases.layer_mutation.create_properties,
        "layer_mutation.create_properties",
    )?;
    validate_layer_properties(
        &plan.cases.layer_mutation.update_properties,
        "layer_mutation.update_properties",
    )?;

    validate_xref_name(&plan.cases.xref_attach.name)?;
    if !matches!(
        plan.cases.xref_attach.reference_type.as_str(),
        "attachment" | "overlay"
    ) {
        return Err(anyhow!(
            "xref_attach.reference_type must be attachment or overlay"
        ));
    }
    validate_placement(&plan.cases.xref_attach.placement)?;

    let mut paths = plan_inputs(plan)
        .map(|(_, input)| input.path.to_ascii_lowercase())
        .collect::<Vec<_>>();
    paths.push(
        plan.activation_target
            .accoreconsole_path
            .to_ascii_lowercase(),
    );
    if let Some(profiles) = &plan.title_block_profiles {
        paths.push(profiles.path.to_ascii_lowercase());
    }
    if paths.iter().collect::<BTreeSet<_>>().len() != paths.len() {
        return Err(anyhow!(
            "every plan package, drawing, source, engine, and profile input path must be distinct"
        ));
    }
    Ok(())
}

fn plan_inputs(plan: &EvaluationPlan) -> impl Iterator<Item = (&'static str, &FileInput)> {
    [
        ("package", &plan.package),
        ("read.drawing", &plan.cases.read.drawing),
        (
            "title_block_write.drawing",
            &plan.cases.title_block_write.drawing,
        ),
        ("layer_mutation.drawing", &plan.cases.layer_mutation.drawing),
        ("plot.drawing", &plan.cases.plot.drawing),
        ("xref_attach.host", &plan.cases.xref_attach.host),
        ("xref_attach.source", &plan.cases.xref_attach.source),
    ]
    .into_iter()
}

fn require_windows_drive_absolute(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || value.starts_with(r"\\")
        || value[2..].contains(':')
        || value.chars().any(char::is_control)
    {
        return Err(anyhow!(
            "{label} must be an absolute Windows drive-letter path"
        ));
    }
    if value
        .split('\\')
        .any(|component| matches!(component, "." | "..") || component.is_empty())
    {
        return Err(anyhow!(
            "{label} must not contain empty, dot, or parent components"
        ));
    }
    Ok(())
}

fn require_lowercase_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(anyhow!(
            "{label} must be exactly 64 lowercase hexadecimal digits"
        ));
    }
    Ok(())
}

fn require_bounded_text(value: &str, label: &str, max: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(anyhow!(
            "{label} must be nonempty, trimmed, control-free, and at most {max} bytes"
        ));
    }
    Ok(())
}

fn require_identifier(value: &str, label: &str, uppercase: bool) -> Result<()> {
    require_bounded_text(value, label, 256)?;
    let valid = value.bytes().all(|byte| {
        if uppercase {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        } else {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        }
    });
    if !valid {
        return Err(anyhow!("{label} is not a canonical identifier"));
    }
    Ok(())
}

fn validate_layer_name(value: &str, label: &str) -> Result<()> {
    require_identifier(value, label, true)?;
    if !value.starts_with("MCP_E2E_") {
        return Err(anyhow!("{label} must begin with MCP_E2E_"));
    }
    Ok(())
}

fn validate_xref_name(value: &str) -> Result<()> {
    require_identifier(value, "xref_attach.name", true)?;
    if !value.starts_with("MCP_E2E_") {
        return Err(anyhow!("xref_attach.name must begin with MCP_E2E_"));
    }
    Ok(())
}

fn validate_layer_properties(properties: &BTreeMap<String, Value>, label: &str) -> Result<()> {
    if properties.is_empty() {
        return Err(anyhow!("{label} must not be empty"));
    }
    for (name, value) in properties {
        match name.as_str() {
            "color_index" => {
                if !value
                    .as_u64()
                    .is_some_and(|value| (1..=255).contains(&value))
                {
                    return Err(anyhow!(
                        "{label}.color_index must be an integer from 1 to 255"
                    ));
                }
            }
            "frozen" | "locked" | "off" | "is_plottable" => {
                if !value.is_boolean() {
                    return Err(anyhow!("{label}.{name} must be boolean"));
                }
            }
            "line_type" => {
                require_bounded_text(
                    value
                        .as_str()
                        .ok_or_else(|| anyhow!("{label}.line_type must be a string"))?,
                    &format!("{label}.line_type"),
                    256,
                )?;
            }
            "line_weight" => validate_line_weight(value, label)?,
            _ => return Err(anyhow!("{label} contains unsupported property {name:?}")),
        }
    }
    Ok(())
}

fn validate_line_weight(value: &Value, label: &str) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("{label}.line_weight must be an object"))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{label}.line_weight.kind must be a string"))?;
    match kind {
        "by_layer" | "by_block" | "default"
            if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["kind"]) =>
        {
            Ok(())
        }
        "value"
            if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["hundredths_mm", "kind"])
                && object
                    .get("hundredths_mm")
                    .and_then(Value::as_i64)
                    .is_some_and(|value| {
                        [
                            0, 5, 9, 13, 15, 18, 20, 25, 30, 35, 40, 50, 53, 60, 70, 80, 90, 100,
                            106, 120, 140, 158, 200, 211,
                        ]
                        .contains(&value)
                    }) =>
        {
            Ok(())
        }
        _ => Err(anyhow!(
            "{label}.line_weight is not a supported closed value"
        )),
    }
}

fn validate_placement(placement: &XrefPlacementPlan) -> Result<()> {
    if placement.owner_type != "model_space" {
        return Err(anyhow!(
            "xref_attach.placement.owner_type is fixed to model_space in schema 1"
        ));
    }
    require_bounded_text(
        &placement.layer_name,
        "xref_attach.placement.layer_name",
        256,
    )?;
    for (label, value) in [
        ("insertion_point.x", placement.insertion_point.x),
        ("insertion_point.y", placement.insertion_point.y),
        ("insertion_point.z", placement.insertion_point.z),
        ("scale.x", placement.scale.x),
        ("scale.y", placement.scale.y),
        ("scale.z", placement.scale.z),
        ("rotation_degrees", placement.rotation_degrees),
    ] {
        if !value.is_finite() {
            return Err(anyhow!("xref_attach.placement.{label} must be finite"));
        }
    }
    if [placement.scale.x, placement.scale.y, placement.scale.z]
        .into_iter()
        .any(|value| value == 0.0)
    {
        return Err(anyhow!(
            "xref_attach.placement scale components must be nonzero"
        ));
    }
    Ok(())
}

fn preflight(root: &Path, plan_path: &Path, invocation_started: Instant) -> Result<Preflight> {
    let (plan, plan_sha256) = parse_plan(plan_path)?;
    if !cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        return Err(anyhow!(
            "preview-autocad-e2e requires a native Windows x64 host with licensed full AutoCAD"
        ));
    }

    for (label, input) in plan_inputs(&plan) {
        inspect_exact_input(Path::new(&input.path), &input.sha256, label)?;
    }
    if !plan.package.path.to_ascii_lowercase().ends_with(".mcpb") {
        return Err(anyhow!("package.path must name an .mcpb file"));
    }

    for (label, input) in drawing_inputs(&plan) {
        if !input.path.to_ascii_lowercase().ends_with(".dwg") {
            return Err(anyhow!("{label} must name a .dwg file"));
        }
        let version = inspect_dwg_version(Path::new(&input.path))
            .with_context(|| format!("inspect {label} DWG version"))?;
        if version != EXPECTED_DWG_FORMAT {
            return Err(anyhow!(
                "{label} uses {version}, but evaluation schema 1 requires {EXPECTED_DWG_FORMAT}"
            ));
        }
    }

    inspect_exact_input(
        Path::new(&plan.activation_target.accoreconsole_path),
        &plan.activation_target.accoreconsole_sha256,
        "activation_target.accoreconsole_path",
    )?;
    let activation = inspect_exact_registered_preview_activation(
        &plan.activation_target.target_id,
        Path::new(&plan.activation_target.accoreconsole_path),
    )
    .context("inspect exact registered Preview activation")?;
    validate_activation_inspection(&plan, &activation)?;

    let profile_pack = match &plan.title_block_profiles {
        Some(profiles) => {
            inspect_exact_input(
                Path::new(&profiles.path),
                &profiles.sha256,
                "title_block_profiles.path",
            )?;
            let summary = validate_profile_pack(Path::new(&profiles.path))
                .context("validate administrator title-block profiles")?;
            if summary.pack_id != profiles.pack_id
                || summary.pack_version != profiles.pack_version
                || summary.sha256 != profiles.sha256
            {
                return Err(anyhow!(
                    "administrator title-block profile identity does not match the plan"
                ));
            }
            Some(summary)
        }
        None => None,
    };
    validate_expected_profile(&plan)?;

    Ok(Preflight {
        invocation_started,
        plan,
        plan_sha256,
        activation,
        profile_pack,
        runner: observe_runner(root)?,
        host: observe_host()?,
    })
}

fn drawing_inputs(plan: &EvaluationPlan) -> impl Iterator<Item = (&'static str, &FileInput)> {
    [
        ("read.drawing", &plan.cases.read.drawing),
        (
            "title_block_write.drawing",
            &plan.cases.title_block_write.drawing,
        ),
        ("layer_mutation.drawing", &plan.cases.layer_mutation.drawing),
        ("plot.drawing", &plan.cases.plot.drawing),
        ("xref_attach.host", &plan.cases.xref_attach.host),
        ("xref_attach.source", &plan.cases.xref_attach.source),
    ]
    .into_iter()
}

fn inspect_exact_input(path: &Path, expected_sha256: &str, label: &str) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect exact input {label}"))?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!("{label} must be a regular non-symlink file"));
    }
    if metadata.len() == 0 || metadata.len() > MAX_EXTERNAL_FILE_BYTES {
        return Err(anyhow!(
            "{label} must be nonempty and no larger than {MAX_EXTERNAL_FILE_BYTES} bytes"
        ));
    }
    require_no_reparse_components(path, label)?;
    let digest = xref_sha256_file(path).with_context(|| format!("hash exact input {label}"))?;
    if digest != expected_sha256 {
        return Err(anyhow!(
            "{label} SHA-256 does not match the evaluation plan"
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn require_no_reparse_components(path: &Path, label: &str) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .with_context(|| format!("inspect {label} path component"))?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(anyhow!("{label} must not traverse a reparse point"));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn require_no_reparse_components(path: &Path, label: &str) -> Result<()> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .with_context(|| format!("inspect {label} path component"))?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow!("{label} must not traverse a symbolic link"));
        }
    }
    Ok(())
}

fn validate_activation_inspection(
    plan: &EvaluationPlan,
    observed: &ExactPreviewActivationInspection,
) -> Result<()> {
    let planned_canonical = fs::canonicalize(Path::new(&plan.activation_target.accoreconsole_path))
        .context("canonicalize planned AutoCAD engine path")?;
    if observed.activation_catalogue_sha256 != plan.activation_target.catalogue_sha256
        || observed.target_id != plan.activation_target.target_id
        || observed.file_version != plan.activation_target.fixed_file_version
        || observed.canonical_executable != planned_canonical
    {
        return Err(anyhow!(
            "exact AutoCAD activation inspection does not match the plan projection"
        ));
    }
    let required = MutationCapability::ALL.into_iter().collect::<BTreeSet<_>>();
    let actual = observed
        .operation_families
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if actual != required {
        return Err(anyhow!(
            "activation target must admit exactly all four required mutation families"
        ));
    }
    if observed
        .drawing_formats
        .binary_search_by(|value| value.as_str().cmp(EXPECTED_DWG_FORMAT))
        .is_err()
    {
        return Err(anyhow!(
            "activation target does not admit {EXPECTED_DWG_FORMAT}"
        ));
    }
    Ok(())
}

fn validate_expected_profile(plan: &EvaluationPlan) -> Result<()> {
    let profile_path = plan
        .title_block_profiles
        .as_ref()
        .map(|profile| Path::new(&profile.path));
    let registry =
        load_active_profile_registry(profile_path).context("load title-block profile registry")?;
    let expected = &plan.cases.title_block_write.expected_profile;
    let profile = registry.find_profile(&expected.profile_id).ok_or_else(|| {
        anyhow!(
            "expected title-block profile {:?} is not in the active registry",
            expected.profile_id
        )
    })?;
    let actual_authority = match profile.authority() {
        ProfileAuthority::Embedded => "embedded",
        ProfileAuthority::Administrator(_) => "administrator",
    };
    if actual_authority != expected.profile_authority {
        return Err(anyhow!(
            "expected title-block profile authority does not match the active registry"
        ));
    }
    for field in plan.cases.title_block_write.fields.keys() {
        if profile.tag_for(field).is_none() {
            return Err(anyhow!(
                "expected title-block profile does not own canonical field {field:?}"
            ));
        }
    }
    Ok(())
}

fn observe_runner(root: &Path) -> Result<RunnerObservation> {
    let git_commit = command_text(root, "git", &["rev-parse", "--verify", "HEAD"])
        .context("read evaluator Git commit")?;
    let status = command_text(
        root,
        "git",
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )
    .context("read evaluator Git tree state")?;
    Ok(RunnerObservation {
        git_commit,
        runner_tree_state: if status.is_empty() { "clean" } else { "dirty" }.to_string(),
    })
}

fn observe_host() -> Result<HostObservation> {
    let windows_version = command_text(Path::new("."), "cmd", &["/D", "/C", "ver"])
        .context("read Windows version")?;
    Ok(HostObservation {
        operating_system: std::env::consts::OS.to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        windows_version,
    })
}

fn command_text(current_dir: &Path, program: &str, arguments: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(current_dir)
        .output()
        .with_context(|| format!("launch {program}"))?;
    if !output.status.success() {
        return Err(anyhow!("{program} exited with {}", output.status));
    }
    let text = std::str::from_utf8(&output.stdout)
        .with_context(|| format!("{program} stdout is not UTF-8"))?
        .trim()
        .to_string();
    Ok(text)
}

fn validate_work_directory(work_dir: &Path) -> Result<()> {
    if !work_dir.is_absolute() {
        return Err(anyhow!("--work-dir must be an absolute path"));
    }
    require_fixed_local_windows_volume(work_dir)
        .map_err(|error| anyhow!("--work-dir is not on a fixed local Windows volume: {error}"))?;
    let parent = work_dir
        .parent()
        .ok_or_else(|| anyhow!("--work-dir must have an existing parent directory"))?;
    if !parent.is_dir() {
        return Err(anyhow!("--work-dir parent directory must already exist"));
    }
    require_no_reparse_components(parent, "--work-dir parent")?;
    Ok(())
}

fn initialize_work_directory(work_dir: &Path) -> Result<StagedCases> {
    for relative in [
        "package",
        "cases",
        "cases/read",
        "cases/title-block-write",
        "cases/layer-mutation",
        "cases/plot",
        "cases/xref-attach",
        "logs",
        "observations",
        "observations/primary",
        "observations/persisted-read",
    ] {
        fs::create_dir(work_dir.join(relative))
            .with_context(|| format!("create evaluator-owned directory {relative}"))?;
    }
    Ok(StagedCases {
        read: work_dir.join("cases/read/input.dwg"),
        title_block: work_dir.join("cases/title-block-write/input.dwg"),
        layer: work_dir.join("cases/layer-mutation/input.dwg"),
        plot: work_dir.join("cases/plot/input.dwg"),
        xref_host: work_dir.join("cases/xref-attach/host.dwg"),
        xref_source: work_dir.join("cases/xref-attach/source.dwg"),
        plot_pdf: work_dir.join("cases/plot/output.pdf"),
    })
}

fn stage_cases(plan: &EvaluationPlan, staged: &StagedCases) -> Result<()> {
    for (input, destination, label) in [
        (&plan.cases.read.drawing, &staged.read, "read"),
        (
            &plan.cases.title_block_write.drawing,
            &staged.title_block,
            "title-block-write",
        ),
        (
            &plan.cases.layer_mutation.drawing,
            &staged.layer,
            "layer-mutation",
        ),
        (&plan.cases.plot.drawing, &staged.plot, "plot"),
        (&plan.cases.xref_attach.host, &staged.xref_host, "xref-host"),
        (
            &plan.cases.xref_attach.source,
            &staged.xref_source,
            "xref-source",
        ),
    ] {
        copy_create_new(Path::new(&input.path), destination)
            .with_context(|| format!("stage {label} input"))?;
        let digest = xref_sha256_file(destination)?;
        if digest != input.sha256 {
            return Err(anyhow!("{label} staged input digest changed during copy"));
        }
    }
    Ok(())
}

fn copy_create_new(source: &Path, destination: &Path) -> Result<()> {
    let mut source = fs::File::open(source)?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    std::io::copy(&mut source, &mut destination)?;
    destination.sync_all()?;
    Ok(())
}

pub fn run(root: &Path, plan_path: &Path, work_dir: &Path) -> Result<EvaluationSummary, String> {
    let invocation_started = Instant::now();
    let preflight =
        preflight(root, plan_path, invocation_started).map_err(|error| error.to_string())?;
    if invocation_started.elapsed() >= OVERALL_TIMEOUT {
        return Err(
            "Preview AutoCAD evaluation preflight exceeded the 30-minute bound".to_string(),
        );
    }
    validate_work_directory(work_dir).map_err(|error| error.to_string())?;
    fs::create_dir(work_dir)
        .with_context(|| {
            format!(
                "create fresh Preview evaluation work directory {}",
                work_dir.display()
            )
        })
        .map_err(|error| error.to_string())?;
    eprintln!(
        "Preview AutoCAD evaluation work directory: {}",
        work_dir.display()
    );

    let fallback = preflight.clone();
    let staged = match initialize_work_directory(work_dir) {
        Ok(staged) => staged,
        Err(error) => {
            let _ = fs::create_dir(work_dir.join("logs"));
            let _ = write_create_new(
                &work_dir.join("logs/evaluator-fatal.log"),
                format!("{error:#}\n").as_bytes(),
            );
            let _ = write_fatal_report(work_dir, &fallback);
            return Err(error.to_string());
        }
    };

    match evaluate_created_workdir(root, work_dir, preflight, staged) {
        Ok(summary) => Ok(summary),
        Err(error) => {
            let _ = write_create_new(
                &work_dir.join("logs/evaluator-fatal.log"),
                format!("{error:#}\n").as_bytes(),
            );
            let _ = write_fatal_report(work_dir, &fallback);
            Err(format!(
                "{error:#}; retained diagnostic work directory: {}",
                work_dir.display()
            ))
        }
    }
}

fn write_fatal_report(work_dir: &Path, preflight: &Preflight) -> Result<()> {
    let mut cases = initial_case_reports(&preflight.plan);
    for case in &mut cases {
        case.fail("evaluation_aborted_before_sessions");
    }
    let report = EvaluationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        artifact_kind: REPORT_KIND,
        authority: AUTHORITY,
        result: "evaluation_failed".to_string(),
        subject: SubjectReport {
            plan_sha256: preflight.plan_sha256.clone(),
            package_sha256: preflight.plan.package.sha256.clone(),
            package_name: "unavailable".to_string(),
            package_version: "unavailable".to_string(),
            package_mode: "preview",
            package_target: "windows_x86_64",
            manifest_sha256: "0".repeat(64),
            binary_sha256: "0".repeat(64),
            activation_catalogue_sha256: preflight.plan.activation_target.catalogue_sha256.clone(),
            activation_binding_sha256: "0".repeat(64),
            signature_state: "not_evaluated",
        },
        runner: preflight.runner.clone(),
        host: preflight.host.clone(),
        activation_target: activation_report(preflight, "0".repeat(64)),
        title_block_profiles: preflight
            .profile_pack
            .as_ref()
            .map(|profiles| ProfileReport {
                pack_id: profiles.pack_id.clone(),
                pack_version: profiles.pack_version.clone(),
                sha256: profiles.sha256.clone(),
                profile_count: profiles.profile_count,
            }),
        probe: ProbeReport {
            result: "missing".to_string(),
            elapsed_ms: None,
        },
        sessions: Vec::new(),
        cases,
        limitations: report_limitations(),
    };
    write_report_atomic(&work_dir.join("preview-autocad-e2e-report.json"), &report)
}

fn evaluate_created_workdir(
    _root: &Path,
    work_dir: &Path,
    preflight: Preflight,
    staged: StagedCases,
) -> Result<EvaluationSummary> {
    let started = preflight.invocation_started;
    let package = prepare_preview_evaluation_package(
        Path::new(&preflight.plan.package.path),
        &preflight.plan.package.sha256,
        &work_dir.join("package"),
    )
    .context("prepare exact Preview MCPB")?;
    if package.package_sha256 != preflight.plan.package.sha256 {
        return Err(anyhow!(
            "prepared Preview MCPB digest does not match the evaluation plan"
        ));
    }
    if package.activation_catalogue_sha256 != preflight.plan.activation_target.catalogue_sha256 {
        return Err(anyhow!(
            "Preview MCPB activation catalogue digest does not match the exact planned target catalogue"
        ));
    }
    stage_cases(&preflight.plan, &staged)?;

    let mut cases = initial_case_reports(&preflight.plan);
    let mut errors = Vec::new();
    let mut mutation_state = MutationState::default();
    let harness = SessionHarness {
        work_dir,
        preflight: &preflight,
        package: &package,
        staged: &staged,
        overall_started: started,
    };
    let (probe, primary_session) =
        run_primary_session(&harness, &mut cases, &mut mutation_state, &mut errors);
    let persisted_session =
        run_persisted_session(&harness, &mut cases, &mutation_state, &mut errors);

    let final_observations =
        validate_final_bindings(&preflight, &package, &staged, &mut cases, &mut errors);
    if started.elapsed() > OVERALL_TIMEOUT {
        errors.push("overall_timeout: evaluation exceeded 30 minutes".to_string());
    }

    let activation_after_identity = final_observations
        .as_ref()
        .map(|observation| sha256_text(&observation.engine_identity_token))
        .unwrap_or_else(|| "0".repeat(64));
    let all_cases_passed = cases.iter().all(|case| case.result == "evaluation_passed");
    let sessions = vec![primary_session, persisted_session];
    let sessions_passed = sessions
        .iter()
        .all(|session| session.result == "evaluation_passed");
    let passed = all_cases_passed
        && sessions_passed
        && probe.result == "ready"
        && preflight.runner.runner_tree_state == "clean"
        && final_observations.is_some()
        && errors.is_empty();

    if !errors.is_empty() {
        write_create_new(
            &work_dir.join("logs/evaluator-errors.log"),
            format!("{}\n", errors.join("\n")).as_bytes(),
        )?;
    }

    let report = EvaluationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        artifact_kind: REPORT_KIND,
        authority: AUTHORITY,
        result: if passed {
            "evaluation_passed"
        } else {
            "evaluation_failed"
        }
        .to_string(),
        subject: subject_report(&preflight, &package),
        runner: preflight.runner.clone(),
        host: preflight.host.clone(),
        activation_target: activation_report(&preflight, activation_after_identity),
        title_block_profiles: preflight
            .profile_pack
            .as_ref()
            .map(|profiles| ProfileReport {
                pack_id: profiles.pack_id.clone(),
                pack_version: profiles.pack_version.clone(),
                sha256: profiles.sha256.clone(),
                profile_count: profiles.profile_count,
            }),
        probe,
        sessions,
        cases,
        limitations: report_limitations(),
    };
    let report_path = work_dir.join("preview-autocad-e2e-report.json");
    write_report_atomic(&report_path, &report)?;

    Ok(EvaluationSummary {
        result: report.result,
        work_dir: work_dir.display().to_string(),
        report: report_path.display().to_string(),
    })
}

fn subject_report(
    preflight: &Preflight,
    package: &PreparedPreviewEvaluationPackage,
) -> SubjectReport {
    SubjectReport {
        plan_sha256: preflight.plan_sha256.clone(),
        package_sha256: package.package_sha256.clone(),
        package_name: package.package_name.clone(),
        package_version: package.package_version.clone(),
        package_mode: "preview",
        package_target: "windows_x86_64",
        manifest_sha256: package.manifest_sha256.clone(),
        binary_sha256: package.binary_sha256.clone(),
        activation_catalogue_sha256: package.activation_catalogue_sha256.clone(),
        activation_binding_sha256: package.activation_binding_sha256.clone(),
        signature_state: "not_evaluated",
    }
}

fn activation_report(preflight: &Preflight, identity_after: String) -> ActivationReport {
    let activation = &preflight.activation;
    ActivationReport {
        target_id: activation.target_id.clone(),
        release_year: activation.release_year,
        registry_family: activation.registry_family.clone(),
        product_language_key: activation.product_language_key.clone(),
        ui_locale: activation.ui_locale.clone(),
        maintained_target: activation.maintained_target,
        fixed_file_version: activation.file_version.clone(),
        engine_sha256: preflight
            .plan
            .activation_target
            .accoreconsole_sha256
            .clone(),
        engine_identity_sha256_before: sha256_text(&activation.engine_identity_token),
        engine_identity_sha256_after: identity_after,
        profile_arg_sha256: activation.profile_arg_sha256.clone(),
        profile_policy_id: activation.profile_policy_id.clone(),
        profile_policy_sha256: activation.profile_policy_sha256.clone(),
        operation_families: activation
            .operation_families
            .iter()
            .map(|capability| match capability {
                MutationCapability::DwgLayerMutation => "dwg_layer_mutation",
                MutationCapability::DwgTitleBlockMutation => "dwg_title_block_mutation",
                MutationCapability::Plot => "plot",
                MutationCapability::XrefMutation => "xref_mutation",
            })
            .map(str::to_string)
            .collect(),
        drawing_formats: activation.drawing_formats.clone(),
    }
}

fn report_limitations() -> Vec<&'static str> {
    vec![
        "candidate Preview evaluation only",
        "not AutoCAD support certification",
        "not maintained-target qualification",
        "not package signature or publication verification",
        "not clean-host acceptance",
        "representative operations do not replace the complete XREF certification inventory",
    ]
}

fn initial_case_reports(plan: &EvaluationPlan) -> Vec<CaseReport> {
    vec![
        CaseReport::new(
            "read",
            vec![plan.cases.read.drawing.sha256.clone()],
            vec!["cases/read/input.dwg"],
        ),
        CaseReport::new(
            "title_block_write",
            vec![plan.cases.title_block_write.drawing.sha256.clone()],
            vec!["cases/title-block-write/input.dwg"],
        ),
        CaseReport::new(
            "layer_mutation",
            vec![plan.cases.layer_mutation.drawing.sha256.clone()],
            vec!["cases/layer-mutation/input.dwg"],
        ),
        CaseReport::new(
            "plot",
            vec![plan.cases.plot.drawing.sha256.clone()],
            vec!["cases/plot/input.dwg"],
        ),
        CaseReport::new(
            "xref_attach",
            vec![
                plan.cases.xref_attach.host.sha256.clone(),
                plan.cases.xref_attach.source.sha256.clone(),
            ],
            vec!["cases/xref-attach/host.dwg", "cases/xref-attach/source.dwg"],
        ),
    ]
}

fn run_primary_session(
    harness: &SessionHarness<'_>,
    cases: &mut [CaseReport],
    mutation_state: &mut MutationState,
    errors: &mut Vec<String>,
) -> (ProbeReport, SessionReport) {
    let session_started = Instant::now();
    let mut report = SessionReport {
        session_id: "primary",
        result: "evaluation_failed".to_string(),
        arguments: vec!["serve", "--experimental"],
        initialized: false,
        tool_count: None,
        exit_success: false,
        active_processes_after_exit: None,
        elapsed_ms: 0,
    };
    let mut probe = ProbeReport {
        result: "missing".to_string(),
        elapsed_ms: None,
    };
    let mut session = match launch_session(
        harness.work_dir,
        harness.preflight,
        harness.package,
        "primary",
        &["serve", "--experimental"],
    ) {
        Ok(session) => session,
        Err(error) => {
            errors.push(format!("primary_session_spawn: {error:#}"));
            fail_unattempted_cases(cases, "primary_session_unavailable");
            report.elapsed_ms = elapsed_ms(session_started);
            return (probe, report);
        }
    };

    let protocol_ready = initialize_and_validate_tools(&mut session)
        .map(|tool_count| {
            report.initialized = true;
            report.tool_count = Some(tool_count);
        })
        .map_err(|error| {
            errors.push(format!("primary_session_protocol: {error:#}"));
        })
        .is_ok();

    if protocol_ready {
        run_case(case_mut(cases, "read"), "read_case_failed", errors, || {
            evaluate_read_case(&mut session, harness.preflight, harness.staged)
        });

        probe = match session.wait_for_stderr_line(PROBE_LOG_MARKER, PROBE_OBSERVATION_TIMEOUT) {
            Ok(Some(line)) => parse_probe_observation(&line),
            Ok(None) => ProbeReport {
                result: "timed_out".to_string(),
                elapsed_ms: None,
            },
            Err(error) => {
                errors.push(format!("primary_probe_observation: {error:#}"));
                ProbeReport {
                    result: "missing".to_string(),
                    elapsed_ms: None,
                }
            }
        };
        if probe.result != "ready" {
            errors.push(format!(
                "primary_probe_not_ready: observed {}",
                probe.result
            ));
        }

        if harness.overall_started.elapsed() <= OVERALL_TIMEOUT {
            mutation_state.title_block_target_inserts = run_case_value(
                case_mut(cases, "title_block_write"),
                "title_block_write_failed",
                errors,
                || evaluate_title_block_case(&mut session, harness.preflight, harness.staged),
            );
        }
        if harness.overall_started.elapsed() <= OVERALL_TIMEOUT {
            mutation_state.layer_handle = run_case_value(
                case_mut(cases, "layer_mutation"),
                "layer_mutation_failed",
                errors,
                || evaluate_layer_case(&mut session, harness.preflight, harness.staged),
            );
        }
        if harness.overall_started.elapsed() <= OVERALL_TIMEOUT {
            let plot_succeeded = run_case(case_mut(cases, "plot"), "plot_failed", errors, || {
                evaluate_plot_case(&mut session, harness.preflight, harness.staged)
            });
            mutation_state.plot_written = plot_succeeded;
        }
        if harness.overall_started.elapsed() <= OVERALL_TIMEOUT {
            if let Some((attachment, instance)) = run_case_value(
                case_mut(cases, "xref_attach"),
                "xref_attach_failed",
                errors,
                || evaluate_xref_case(&mut session, harness.preflight, harness.staged),
            ) {
                mutation_state.xref_attachment_handle = Some(attachment);
                mutation_state.xref_instance_handle = Some(instance);
            }
        }
    } else {
        fail_unattempted_cases(cases, "primary_session_unavailable");
    }

    let shutdown = session.close_stdin_and_wait(SHUTDOWN_TIMEOUT);
    match shutdown {
        Ok(observation) => apply_shutdown(&mut report, observation),
        Err(error) => errors.push(format!("primary_session_shutdown: {error:#}")),
    }
    match session.stderr_bytes() {
        Ok(bytes) => {
            if let Err(error) =
                write_create_new(&harness.work_dir.join("logs/primary.stderr.log"), bytes)
            {
                errors.push(format!("primary_stderr_log: {error:#}"));
            }
        }
        Err(error) => errors.push(format!("primary_stderr_capture: {error:#}")),
    }
    if protocol_ready && report.exit_success {
        report.result = "evaluation_passed".to_string();
    }
    report.elapsed_ms = elapsed_ms(session_started);
    (probe, report)
}

fn run_persisted_session(
    harness: &SessionHarness<'_>,
    cases: &mut [CaseReport],
    mutation_state: &MutationState,
    errors: &mut Vec<String>,
) -> SessionReport {
    let session_started = Instant::now();
    let mut report = SessionReport {
        session_id: "persisted_read",
        result: "evaluation_failed".to_string(),
        arguments: vec!["serve", "--experimental", "--engine-probe", "off"],
        initialized: false,
        tool_count: None,
        exit_success: false,
        active_processes_after_exit: None,
        elapsed_ms: 0,
    };
    let mut session = match launch_session(
        harness.work_dir,
        harness.preflight,
        harness.package,
        "persisted-read",
        &["serve", "--experimental", "--engine-probe", "off"],
    ) {
        Ok(session) => session,
        Err(error) => {
            errors.push(format!("persisted_session_spawn: {error:#}"));
            fail_successful_mutations(cases, "persisted_session_unavailable");
            report.elapsed_ms = elapsed_ms(session_started);
            return report;
        }
    };
    let protocol_ready = initialize_and_validate_tools(&mut session)
        .map(|tool_count| {
            report.initialized = true;
            report.tool_count = Some(tool_count);
        })
        .map_err(|error| errors.push(format!("persisted_session_protocol: {error:#}")))
        .is_ok();

    if protocol_ready && harness.overall_started.elapsed() <= OVERALL_TIMEOUT {
        if let Some(target_inserts) = mutation_state.title_block_target_inserts {
            apply_persisted_verification(
                case_mut(cases, "title_block_write"),
                "title_block_persisted_read_failed",
                errors,
                || {
                    verify_title_block_persisted(
                        &mut session,
                        harness.preflight,
                        harness.staged,
                        target_inserts,
                    )
                },
            );
        }
        if let Some(handle) = mutation_state.layer_handle.as_deref() {
            apply_persisted_verification(
                case_mut(cases, "layer_mutation"),
                "layer_persisted_read_failed",
                errors,
                || verify_layer_persisted(&mut session, harness.preflight, harness.staged, handle),
            );
        }
        if mutation_state.plot_written {
            apply_persisted_verification(
                case_mut(cases, "plot"),
                "plot_persisted_read_failed",
                errors,
                || {
                    let digest = validate_pdf(&harness.staged.plot_pdf)?;
                    Ok((
                        vec![digest],
                        Vec::new(),
                        "retained PDF revalidated".to_string(),
                    ))
                },
            );
        }
        if let (Some(attachment), Some(instance)) = (
            mutation_state.xref_attachment_handle.as_deref(),
            mutation_state.xref_instance_handle.as_deref(),
        ) {
            apply_persisted_verification(
                case_mut(cases, "xref_attach"),
                "xref_persisted_read_failed",
                errors,
                || {
                    verify_xref_persisted(
                        &mut session,
                        harness.preflight,
                        harness.staged,
                        attachment,
                        instance,
                    )
                },
            );
        }
    } else if !protocol_ready {
        fail_successful_mutations(cases, "persisted_session_unavailable");
    }

    match session.close_stdin_and_wait(SHUTDOWN_TIMEOUT) {
        Ok(observation) => apply_shutdown(&mut report, observation),
        Err(error) => errors.push(format!("persisted_session_shutdown: {error:#}")),
    }
    match session.stderr_bytes() {
        Ok(bytes) => {
            if let Err(error) = write_create_new(
                &harness.work_dir.join("logs/persisted-read.stderr.log"),
                bytes,
            ) {
                errors.push(format!("persisted_stderr_log: {error:#}"));
            }
        }
        Err(error) => errors.push(format!("persisted_stderr_capture: {error:#}")),
    }
    if protocol_ready && report.exit_success {
        report.result = "evaluation_passed".to_string();
    }
    report.elapsed_ms = elapsed_ms(session_started);
    report
}

fn launch_session(
    work_dir: &Path,
    preflight: &Preflight,
    package: &PreparedPreviewEvaluationPackage,
    label: &str,
    arguments: &[&str],
) -> Result<McpStdioSession> {
    let mut environment = vec![
        (
            OsString::from(ACCORECONSOLE_ENV),
            preflight
                .activation
                .canonical_executable
                .as_os_str()
                .to_os_string(),
        ),
        (
            OsString::from("RUST_LOG"),
            OsString::from("autocad_mcp::probe=info"),
        ),
    ];
    if let Some(profiles) = &preflight.plan.title_block_profiles {
        environment.push((
            OsString::from(TITLE_BLOCK_PROFILES_ENV),
            OsString::from(&profiles.path),
        ));
    }
    McpStdioSession::spawn(McpStdioLaunch {
        binary: package.binary_path.clone(),
        arguments: arguments.iter().map(|value| (*value).to_string()).collect(),
        current_dir: work_dir.join(format!("observations/{label}")),
        environment,
        clear_autocad_mcp_environment: true,
        label: format!("Preview AutoCAD E2E {label} session"),
        overall_deadline: Some(preflight.invocation_started + OVERALL_TIMEOUT),
    })
}

fn initialize_and_validate_tools(session: &mut McpStdioSession) -> Result<usize> {
    session.initialize(READ_TIMEOUT)?;
    let tools = session.list_tools(READ_TIMEOUT)?;
    validate_preview_evaluation_tool_surface(&tools)?;
    let count = tools
        .as_array()
        .map(Vec::len)
        .ok_or_else(|| anyhow!("validated tools surface is not an array"))?;
    if count != EXPECTED_TOOL_COUNT {
        return Err(anyhow!(
            "Preview tool surface contains {count} tools, expected {EXPECTED_TOOL_COUNT}"
        ));
    }
    Ok(count)
}

fn evaluate_read_case(
    session: &mut McpStdioSession,
    preflight: &Preflight,
    staged: &StagedCases,
) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    let response = session.call_tool(
        "list_layouts",
        serde_json::json!({"drawing_path": path_text(&staged.read)}),
        READ_TIMEOUT,
    )?;
    let layouts: Vec<autocad_mcp::ops::layouts::LayoutInfo> =
        serde_json::from_value(response.value).context("parse list_layouts response")?;
    let matches = layouts
        .iter()
        .filter(|layout| layout.name == preflight.plan.cases.read.expected_layout)
        .count();
    if matches != 1 {
        return Err(anyhow!(
            "expected layout must occur exactly once; observed {matches}"
        ));
    }
    let digest = xref_sha256_file(&staged.read)?;
    if digest != preflight.plan.cases.read.drawing.sha256 {
        return Err(anyhow!("read case changed its staged drawing"));
    }
    Ok((
        vec![digest],
        vec![response.response_sha256],
        vec!["expected layout present exactly once".to_string()],
    ))
}

fn evaluate_title_block_case(
    session: &mut McpStdioSession,
    preflight: &Preflight,
    staged: &StagedCases,
) -> Result<CaseValueEvidence<usize>> {
    let before = session.call_tool(
        "read_title_blocks",
        serde_json::json!({
            "drawing_path": path_text(&staged.title_block),
            "attribute_value_mode": "arrays"
        }),
        READ_TIMEOUT,
    )?;
    let title_blocks: Vec<TitleBlockInfo> =
        serde_json::from_value(before.value).context("parse initial title blocks")?;
    let registry = active_profile_registry(preflight)?;
    let resolved = registry
        .resolve_profile(&title_blocks)
        .context("resolve initial title-block profile")?;
    let expected = &preflight.plan.cases.title_block_write.expected_profile;
    if resolved.profile_id != expected.profile_id {
        return Err(anyhow!(
            "initial title block resolved profile {}, expected {}",
            resolved.profile_id,
            expected.profile_id
        ));
    }
    if title_values_present(
        &title_blocks,
        resolved,
        &preflight.plan.cases.title_block_write.fields,
    )? {
        return Err(anyhow!(
            "title-block input already contains every planned sentinel value"
        ));
    }

    let mutation = session.call_tool(
        "write_title_block",
        serde_json::json!({
            "drawing_path": path_text(&staged.title_block),
            "fields": preflight.plan.cases.title_block_write.fields
        }),
        MUTATION_TIMEOUT,
    )?;
    let target_inserts = validate_title_mutation_response(preflight, &mutation.value)?;
    let digest = xref_sha256_file(&staged.title_block)?;
    if digest == preflight.plan.cases.title_block_write.drawing.sha256 {
        return Err(anyhow!(
            "title-block mutation did not change the staged drawing digest"
        ));
    }
    Ok((
        target_inserts,
        vec![digest],
        vec![before.response_sha256, mutation.response_sha256],
        vec![
            format!("profile_id={}", expected.profile_id),
            format!("profile_authority={}", expected.profile_authority),
            "backend=acadrust_preview".to_string(),
            "bounded writer and guarded-install receipts verified".to_string(),
            "mutation response counts are internally consistent".to_string(),
        ],
    ))
}

fn validate_title_mutation_response(preflight: &Preflight, response: &Value) -> Result<usize> {
    let object = response
        .as_object()
        .ok_or_else(|| anyhow!("write_title_block response must be an object"))?;
    let expected = &preflight.plan.cases.title_block_write.expected_profile;
    if object.get("status").and_then(Value::as_str) != Some("ok")
        || object.get("capability_status").and_then(Value::as_str) != Some("preview")
        || object.get("backend").and_then(Value::as_str) != Some("acadrust_preview")
        || object.get("source_format").and_then(Value::as_str) != Some("dwg")
        || object.get("drawing_version").and_then(Value::as_str) != Some("AC1032")
        || object.get("profile_id").and_then(Value::as_str) != Some(&expected.profile_id)
        || object.get("profile_authority").and_then(Value::as_str)
            != Some(&expected.profile_authority)
    {
        return Err(anyhow!(
            "write_title_block response profile or status does not match the plan"
        ));
    }
    let writer_receipt = object
        .get("writer_receipt")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("write_title_block writer_receipt is missing"))?;
    if writer_receipt.get("claim_boundary").and_then(Value::as_str) != Some("preview_qualified")
        || writer_receipt.get("format").and_then(Value::as_str) != Some("DWG")
        || writer_receipt.get("operations") != Some(&serde_json::json!(["write_title_block"]))
        || writer_receipt
            .get("reader_reopen_verified")
            .and_then(Value::as_bool)
            != Some(true)
        || writer_receipt
            .get("operation_postconditions_verified")
            .and_then(Value::as_bool)
            != Some(true)
        || writer_receipt
            .get("whole_document_preservation_verified")
            .and_then(Value::as_bool)
            != Some(true)
        || writer_receipt
            .get("native_host_verified")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(anyhow!(
            "write_title_block writer receipt does not satisfy the Preview qualification contract"
        ));
    }
    let writer_source_sha256 = writer_receipt
        .get("source_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("write_title_block writer source digest is missing"))?;
    let writer_candidate_sha256 = writer_receipt
        .get("candidate_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("write_title_block writer candidate digest is missing"))?;
    require_lowercase_sha256(
        writer_source_sha256,
        "write_title_block writer source digest",
    )?;
    require_lowercase_sha256(
        writer_candidate_sha256,
        "write_title_block writer candidate digest",
    )?;

    let install_receipt = object
        .get("install_receipt")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("write_title_block install_receipt is missing"))?;
    for field in [
        "exclusive_source_lock_verified",
        "source_identity_revalidated",
        "sibling_staging_verified",
        "transactional_atomic_install_verified",
        "original_file_identity_preserved",
        "directory_durability_verified",
        "installed_digest_verified",
    ] {
        if install_receipt.get(field).and_then(Value::as_bool) != Some(true) {
            return Err(anyhow!(
                "write_title_block guarded-install receipt did not verify {field}"
            ));
        }
    }
    if install_receipt.get("source_sha256").and_then(Value::as_str) != Some(writer_source_sha256)
        || install_receipt
            .get("installed_sha256")
            .and_then(Value::as_str)
            != Some(writer_candidate_sha256)
    {
        return Err(anyhow!(
            "write_title_block writer and guarded-install digests are not bound"
        ));
    }
    let fields = object
        .get("fields_written")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("write_title_block fields_written is missing"))?;
    let inserts = object
        .get("target_inserts")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| anyhow!("write_title_block target_inserts must be positive"))?;
    let attributes = object
        .get("attributes_written")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("write_title_block attributes_written is missing"))?;
    if fields != preflight.plan.cases.title_block_write.fields.len() as u64
        || attributes != fields.saturating_mul(inserts)
    {
        return Err(anyhow!(
            "write_title_block response counts are not internally consistent"
        ));
    }
    match &preflight.profile_pack {
        Some(pack)
            if object.get("profile_pack_id").and_then(Value::as_str) == Some(&pack.pack_id)
                && object.get("profile_pack_version").and_then(Value::as_str)
                    == Some(&pack.pack_version)
                && object.get("profile_pack_sha256").and_then(Value::as_str)
                    == Some(&pack.sha256) =>
        {
            Ok(())
        }
        Some(_) => Err(anyhow!(
            "write_title_block administrator pack identity does not match the plan"
        )),
        None if !object.contains_key("profile_pack_id")
            && !object.contains_key("profile_pack_version")
            && !object.contains_key("profile_pack_sha256") =>
        {
            Ok(())
        }
        None => Err(anyhow!(
            "embedded title-block response unexpectedly contains administrator pack identity"
        )),
    }?;
    usize::try_from(inserts).context("write_title_block target_inserts exceeds usize")
}

fn active_profile_registry(
    preflight: &Preflight,
) -> Result<std::sync::Arc<autocad_mcp::ops::profiles::ProfileRegistry>> {
    load_active_profile_registry(
        preflight
            .plan
            .title_block_profiles
            .as_ref()
            .map(|profile| Path::new(&profile.path)),
    )
}

fn title_values_present(
    title_blocks: &[TitleBlockInfo],
    profile: &autocad_mcp::ops::profiles::Profile,
    fields: &BTreeMap<String, String>,
) -> Result<bool> {
    let expected = fields
        .iter()
        .map(|(canonical, value)| {
            profile
                .tag_for(canonical)
                .map(|tag| (tag.to_ascii_uppercase(), value))
                .ok_or_else(|| anyhow!("profile does not map canonical field {canonical:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let fingerprint = profile.title_block_fingerprint();
    Ok(title_blocks
        .iter()
        .filter(|block| title_block_fingerprint(block) == fingerprint)
        .any(|block| title_block_has_exact_values(block, &expected)))
}

fn title_block_fingerprint(block: &TitleBlockInfo) -> TitleBlockFingerprint {
    TitleBlockFingerprint::new(
        &block.block_name,
        block
            .attributes
            .keys()
            .chain(block.attribute_arrays.keys())
            .map(String::as_str),
    )
}

fn title_block_has_exact_values(block: &TitleBlockInfo, expected: &[(String, &String)]) -> bool {
    expected.iter().all(|(tag, value)| {
        block
            .attribute_arrays
            .get(tag)
            .is_some_and(|values| values.as_slice() == [value.as_str()])
    })
}

fn evaluate_layer_case(
    session: &mut McpStdioSession,
    preflight: &Preflight,
    staged: &StagedCases,
) -> Result<CaseValueEvidence<String>> {
    let plan = &preflight.plan.cases.layer_mutation;
    let initial = session.call_tool(
        "list_layers",
        serde_json::json!({"drawing_path": path_text(&staged.layer)}),
        READ_TIMEOUT,
    )?;
    let layers: Vec<LayerRecord> =
        serde_json::from_value(initial.value).context("parse initial list_layers response")?;
    if layers.iter().any(|layer| {
        layer.name.eq_ignore_ascii_case(&plan.created_name)
            || layer.name.eq_ignore_ascii_case(&plan.renamed_name)
    }) {
        return Err(anyhow!(
            "planned created or renamed layer already exists in the input"
        ));
    }

    let created = session.call_tool(
        "create_layer",
        serde_json::json!({
            "drawing_path": path_text(&staged.layer),
            "name": plan.created_name,
            "properties": plan.create_properties
        }),
        MUTATION_TIMEOUT,
    )?;
    let created_result: LayerMutationResult =
        serde_json::from_value(created.value).context("parse create_layer response")?;
    if created_result.layer.name != plan.created_name {
        return Err(anyhow!("create_layer returned the wrong layer name"));
    }
    require_layer_properties(&created_result.layer, &plan.create_properties)?;
    let handle = created_result.layer.handle.clone();

    let updated = session.call_tool(
        "update_layer",
        serde_json::json!({
            "drawing_path": path_text(&staged.layer),
            "handle": handle,
            "expected_handle": handle,
            "expected_name": plan.created_name,
            "properties": plan.update_properties
        }),
        MUTATION_TIMEOUT,
    )?;
    let updated_result: LayerMutationResult =
        serde_json::from_value(updated.value).context("parse update_layer response")?;
    if updated_result.layer.handle != handle || updated_result.layer.name != plan.created_name {
        return Err(anyhow!(
            "update_layer did not preserve the created layer identity"
        ));
    }
    let final_properties = merged_layer_properties(plan);
    require_layer_properties(&updated_result.layer, &final_properties)?;

    let renamed = session.call_tool(
        "rename_layer",
        serde_json::json!({
            "drawing_path": path_text(&staged.layer),
            "handle": handle,
            "expected_handle": handle,
            "expected_name": plan.created_name,
            "new_name": plan.renamed_name
        }),
        MUTATION_TIMEOUT,
    )?;
    let renamed_result: LayerMutationResult =
        serde_json::from_value(renamed.value).context("parse rename_layer response")?;
    if renamed_result.layer.handle != handle || renamed_result.layer.name != plan.renamed_name {
        return Err(anyhow!(
            "rename_layer did not preserve the stable created layer handle"
        ));
    }
    require_layer_properties(&renamed_result.layer, &final_properties)?;
    let digest = xref_sha256_file(&staged.layer)?;
    if digest == plan.drawing.sha256 {
        return Err(anyhow!("layer lifecycle did not change the drawing digest"));
    }
    Ok((
        handle,
        vec![digest],
        vec![
            initial.response_sha256,
            created.response_sha256,
            updated.response_sha256,
            renamed.response_sha256,
        ],
        vec![
            "created and renamed names were absent from the input".to_string(),
            "create, update, and rename preserved one stable layer handle".to_string(),
            "renamed layer has the expected final writable properties".to_string(),
        ],
    ))
}

fn merged_layer_properties(plan: &LayerCasePlan) -> BTreeMap<String, Value> {
    let mut properties = plan.create_properties.clone();
    properties.extend(plan.update_properties.clone());
    properties
}

fn require_layer_properties(layer: &LayerRecord, expected: &BTreeMap<String, Value>) -> Result<()> {
    let value = serde_json::to_value(layer)?;
    for (property, expected) in expected {
        let actual = value
            .get(property)
            .ok_or_else(|| anyhow!("layer response omits expected property {property}"))?;
        if actual != expected {
            return Err(anyhow!(
                "layer property {property} does not match the planned value"
            ));
        }
    }
    Ok(())
}

fn evaluate_plot_case(
    session: &mut McpStdioSession,
    preflight: &Preflight,
    staged: &StagedCases,
) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    if staged.plot_pdf.exists() {
        return Err(anyhow!("runner-owned plot output already exists"));
    }
    let response = session.call_tool(
        "plot_to_pdf",
        serde_json::json!({
            "drawing_path": path_text(&staged.plot),
            "layout": preflight.plan.cases.plot.layout,
            "output": path_text(&staged.plot_pdf)
        }),
        MUTATION_TIMEOUT,
    )?;
    if response.value["status"] != "ok"
        || response.value["layout"] != preflight.plan.cases.plot.layout
        || response.value["output"] != path_text(&staged.plot_pdf)
    {
        return Err(anyhow!(
            "plot_to_pdf response does not match the fixed request"
        ));
    }
    let pdf_sha256 = validate_pdf(&staged.plot_pdf)?;
    let drawing_sha256 = xref_sha256_file(&staged.plot)?;
    Ok((
        vec![drawing_sha256, pdf_sha256],
        vec![response.response_sha256],
        vec![
            "new retained output has PDF header and bounded EOF trailer".to_string(),
            format!("pdf_minimum_bytes={MIN_PDF_BYTES}"),
        ],
    ))
}

fn validate_pdf(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path).context("inspect retained plot PDF")?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "retained plot output must be a regular non-symlink file"
        ));
    }
    require_no_reparse_components(path, "retained plot PDF")?;
    if metadata.len() < MIN_PDF_BYTES {
        return Err(anyhow!(
            "retained plot PDF is smaller than {MIN_PDF_BYTES} bytes"
        ));
    }
    if metadata.len() > MAX_EXTERNAL_FILE_BYTES {
        return Err(anyhow!(
            "retained plot PDF exceeds the {MAX_EXTERNAL_FILE_BYTES}-byte bound"
        ));
    }
    let mut file = fs::File::open(path)?;
    let mut header = [0_u8; 5];
    file.read_exact(&mut header)?;
    if &header != b"%PDF-" {
        return Err(anyhow!("retained plot output has no PDF header"));
    }
    let tail_len = metadata.len().min(MAX_PDF_TAIL_BYTES);
    file.seek(SeekFrom::End(-(tail_len as i64)))?;
    let mut tail = vec![0_u8; tail_len as usize];
    file.read_exact(&mut tail)?;
    if !tail
        .windows(b"%%EOF".len())
        .any(|window| window == b"%%EOF")
    {
        return Err(anyhow!(
            "retained plot output has no PDF EOF marker in its bounded tail"
        ));
    }
    xref_sha256_file(path).context("hash retained plot PDF")
}

fn evaluate_xref_case(
    session: &mut McpStdioSession,
    preflight: &Preflight,
    staged: &StagedCases,
) -> Result<CaseValueEvidence<(String, String)>> {
    let plan = &preflight.plan.cases.xref_attach;
    let initial_xrefs = session.call_tool(
        "list_xrefs",
        serde_json::json!({"drawing_path": path_text(&staged.xref_host)}),
        READ_TIMEOUT,
    )?;
    let attachments: Vec<XrefAttachmentRecord> =
        serde_json::from_value(initial_xrefs.value).context("parse initial list_xrefs")?;
    if attachments
        .iter()
        .any(|attachment| attachment.name.eq_ignore_ascii_case(&plan.name))
    {
        return Err(anyhow!("planned XREF name already exists in host drawing"));
    }
    let initial_instances = session.call_tool(
        "list_xref_instances",
        serde_json::json!({
            "drawing_path": path_text(&staged.xref_host),
            "attachment_name": plan.name
        }),
        READ_TIMEOUT,
    )?;
    let instances: Vec<XrefInstanceRecord> = serde_json::from_value(initial_instances.value)
        .context("parse initial list_xref_instances")?;
    if !instances.is_empty() {
        return Err(anyhow!("planned XREF name already has host instances"));
    }

    let response = session.call_tool(
        "attach_xref",
        serde_json::json!({
            "drawing_path": path_text(&staged.xref_host),
            "xref_path": path_text(&staged.xref_source),
            "name": plan.name,
            "reference_type": plan.reference_type,
            "placement": plan.placement
        }),
        MUTATION_TIMEOUT,
    )?;
    let attached: AttachXrefResponse =
        serde_json::from_value(response.value).context("parse attach_xref response")?;
    validate_attached_xref(plan, staged, &attached)?;
    let host_sha256 = xref_sha256_file(&staged.xref_host)?;
    let source_sha256 = xref_sha256_file(&staged.xref_source)?;
    if host_sha256 == plan.host.sha256 {
        return Err(anyhow!(
            "attach_xref did not change the staged host drawing"
        ));
    }
    if source_sha256 != plan.source.sha256 {
        return Err(anyhow!(
            "attach_xref changed the staged XREF source drawing"
        ));
    }
    Ok((
        (
            attached.attachment.handle.clone(),
            attached.instance.handle.clone(),
        ),
        vec![host_sha256, source_sha256],
        vec![
            initial_xrefs.response_sha256,
            initial_instances.response_sha256,
            response.response_sha256,
        ],
        vec![
            "planned attachment name and instances were absent from the input".to_string(),
            "attach response binds one attachment and its initial instance".to_string(),
            "staged XREF source digest remained unchanged".to_string(),
        ],
    ))
}

fn validate_attached_xref(
    plan: &XrefCasePlan,
    staged: &StagedCases,
    response: &AttachXrefResponse,
) -> Result<()> {
    let expected_type = expected_reference_type(&plan.reference_type)?;
    if response.attachment.name != plan.name
        || response.attachment.reference_type != expected_type
        || response.attachment.instance_count != 1
        || response.instance.attachment_handle != response.attachment.handle
        || response.instance.attachment_name != plan.name
        || response.attachment.saved_path != path_text(&staged.xref_source)
        || response.instance.layer_name != plan.placement.layer_name
        || response.instance.insertion_point.x != plan.placement.insertion_point.x
        || response.instance.insertion_point.y != plan.placement.insertion_point.y
        || response.instance.insertion_point.z != plan.placement.insertion_point.z
        || response.instance.scale.x != plan.placement.scale.x
        || response.instance.scale.y != plan.placement.scale.y
        || response.instance.scale.z != plan.placement.scale.z
        || response.instance.rotation_degrees != plan.placement.rotation_degrees
    {
        return Err(anyhow!(
            "attach_xref response does not match the planned attachment and placement"
        ));
    }
    Ok(())
}

fn expected_reference_type(value: &str) -> Result<ReferenceType> {
    match value {
        "attachment" => Ok(ReferenceType::Attachment),
        "overlay" => Ok(ReferenceType::Overlay),
        _ => Err(anyhow!("unsupported reference type")),
    }
}

fn verify_title_block_persisted(
    session: &mut McpStdioSession,
    preflight: &Preflight,
    staged: &StagedCases,
    expected_target_inserts: usize,
) -> Result<(Vec<String>, Vec<String>, String)> {
    let response = session.call_tool(
        "read_title_blocks",
        serde_json::json!({
            "drawing_path": path_text(&staged.title_block),
            "attribute_value_mode": "arrays"
        }),
        READ_TIMEOUT,
    )?;
    let title_blocks: Vec<TitleBlockInfo> =
        serde_json::from_value(response.value).context("parse persisted title blocks")?;
    let registry = active_profile_registry(preflight)?;
    let profile = registry
        .resolve_profile(&title_blocks)
        .context("resolve persisted title-block profile")?;
    let expected = &preflight.plan.cases.title_block_write.expected_profile;
    if profile.profile_id != expected.profile_id {
        return Err(anyhow!(
            "persisted title block does not resolve to the expected profile"
        ));
    }
    let expected_values = preflight
        .plan
        .cases
        .title_block_write
        .fields
        .iter()
        .map(|(canonical, value)| {
            profile
                .tag_for(canonical)
                .map(|tag| (tag.to_ascii_uppercase(), value))
                .ok_or_else(|| anyhow!("profile does not map canonical field {canonical:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let fingerprint = profile.title_block_fingerprint();
    let targets = title_blocks
        .iter()
        .filter(|block| title_block_fingerprint(block) == fingerprint)
        .collect::<Vec<_>>();
    if targets.len() != expected_target_inserts
        || !targets
            .iter()
            .all(|block| title_block_has_exact_values(block, &expected_values))
    {
        return Err(anyhow!(
            "persisted title block target count or exact planned sentinel values do not match the mutation response"
        ));
    }
    let digest = xref_sha256_file(&staged.title_block)?;
    Ok((
        vec![digest],
        vec![response.response_sha256],
        "persisted title-block sentinels reread through MCP".to_string(),
    ))
}

fn verify_layer_persisted(
    session: &mut McpStdioSession,
    preflight: &Preflight,
    staged: &StagedCases,
    expected_handle: &str,
) -> Result<(Vec<String>, Vec<String>, String)> {
    let response = session.call_tool(
        "list_layers",
        serde_json::json!({"drawing_path": path_text(&staged.layer)}),
        READ_TIMEOUT,
    )?;
    let layers: Vec<LayerRecord> =
        serde_json::from_value(response.value).context("parse persisted list_layers")?;
    let plan = &preflight.plan.cases.layer_mutation;
    let matching = layers
        .iter()
        .filter(|layer| {
            layer.name.eq_ignore_ascii_case(&plan.created_name)
                || layer.name.eq_ignore_ascii_case(&plan.renamed_name)
        })
        .collect::<Vec<_>>();
    let layer = match matching.as_slice() {
        [layer] => *layer,
        _ => {
            return Err(anyhow!(
                "persisted drawing must contain only the renamed evaluator layer"
            ))
        }
    };
    if layer.handle != expected_handle || layer.name != plan.renamed_name {
        return Err(anyhow!(
            "persisted layer does not preserve its handle and renamed identity"
        ));
    }
    require_layer_properties(layer, &merged_layer_properties(plan))?;
    let digest = xref_sha256_file(&staged.layer)?;
    Ok((
        vec![digest],
        vec![response.response_sha256],
        "persisted renamed layer reread by stable handle through MCP".to_string(),
    ))
}

fn verify_xref_persisted(
    session: &mut McpStdioSession,
    preflight: &Preflight,
    staged: &StagedCases,
    expected_attachment_handle: &str,
    expected_instance_handle: &str,
) -> Result<(Vec<String>, Vec<String>, String)> {
    let attachments_response = session.call_tool(
        "list_xrefs",
        serde_json::json!({"drawing_path": path_text(&staged.xref_host)}),
        READ_TIMEOUT,
    )?;
    let attachments: Vec<XrefAttachmentRecord> =
        serde_json::from_value(attachments_response.value).context("parse persisted list_xrefs")?;
    let expected_name = &preflight.plan.cases.xref_attach.name;
    let matching_attachments = attachments
        .iter()
        .filter(|attachment| attachment.name == *expected_name)
        .collect::<Vec<_>>();
    let attachment = match matching_attachments.as_slice() {
        [attachment] => *attachment,
        _ => {
            return Err(anyhow!(
                "persisted host must contain exactly one planned direct XREF attachment"
            ))
        }
    };
    if attachment.handle != expected_attachment_handle
        || attachment.saved_path != path_text(&staged.xref_source)
        || attachment.reference_type
            != expected_reference_type(&preflight.plan.cases.xref_attach.reference_type)?
        || attachment.instance_count != 1
    {
        return Err(anyhow!(
            "persisted XREF attachment does not match the planned identity"
        ));
    }

    let instances_response = session.call_tool(
        "list_xref_instances",
        serde_json::json!({
            "drawing_path": path_text(&staged.xref_host),
            "attachment_handle": expected_attachment_handle,
            "attachment_name": expected_name
        }),
        READ_TIMEOUT,
    )?;
    let instances: Vec<XrefInstanceRecord> = serde_json::from_value(instances_response.value)
        .context("parse persisted list_xref_instances")?;
    let instance = match instances.as_slice() {
        [instance] => instance,
        _ => {
            return Err(anyhow!(
                "persisted host must contain exactly one planned XREF instance"
            ))
        }
    };
    if instance.handle != expected_instance_handle
        || instance.attachment_handle != expected_attachment_handle
        || instance.attachment_name != *expected_name
        || instance.layer_name != preflight.plan.cases.xref_attach.placement.layer_name
        || instance.insertion_point.x
            != preflight.plan.cases.xref_attach.placement.insertion_point.x
        || instance.insertion_point.y
            != preflight.plan.cases.xref_attach.placement.insertion_point.y
        || instance.insertion_point.z
            != preflight.plan.cases.xref_attach.placement.insertion_point.z
        || instance.scale.x != preflight.plan.cases.xref_attach.placement.scale.x
        || instance.scale.y != preflight.plan.cases.xref_attach.placement.scale.y
        || instance.scale.z != preflight.plan.cases.xref_attach.placement.scale.z
        || instance.rotation_degrees != preflight.plan.cases.xref_attach.placement.rotation_degrees
    {
        return Err(anyhow!(
            "persisted XREF instance relationship or placement does not match the plan"
        ));
    }
    let source_sha256 = xref_sha256_file(&staged.xref_source)?;
    if source_sha256 != preflight.plan.cases.xref_attach.source.sha256 {
        return Err(anyhow!("persisted XREF source digest changed"));
    }
    Ok((
        vec![xref_sha256_file(&staged.xref_host)?, source_sha256],
        vec![
            attachments_response.response_sha256,
            instances_response.response_sha256,
        ],
        "persisted attachment and its one instance reread through MCP".to_string(),
    ))
}

fn run_case<F>(
    report: &mut CaseReport,
    failure_code: &str,
    errors: &mut Vec<String>,
    operation: F,
) -> bool
where
    F: FnOnce() -> Result<CaseEvidence>,
{
    let started = Instant::now();
    match operation() {
        Ok((outputs, responses, assertions)) => {
            report.output_sha256.extend(outputs);
            report.response_sha256.extend(responses);
            report.assertions.extend(assertions);
            report.pass();
            report.elapsed_ms = elapsed_ms(started);
            true
        }
        Err(error) => {
            report.fail(failure_code);
            report.elapsed_ms = elapsed_ms(started);
            errors.push(format!("{}: {error:#}", report.case_id));
            false
        }
    }
}

fn run_case_value<T, F>(
    report: &mut CaseReport,
    failure_code: &str,
    errors: &mut Vec<String>,
    operation: F,
) -> Option<T>
where
    F: FnOnce() -> Result<CaseValueEvidence<T>>,
{
    let started = Instant::now();
    match operation() {
        Ok((value, outputs, responses, assertions)) => {
            report.output_sha256.extend(outputs);
            report.response_sha256.extend(responses);
            report.assertions.extend(assertions);
            report.pass();
            report.elapsed_ms = elapsed_ms(started);
            Some(value)
        }
        Err(error) => {
            report.fail(failure_code);
            report.elapsed_ms = elapsed_ms(started);
            errors.push(format!("{}: {error:#}", report.case_id));
            None
        }
    }
}

fn apply_persisted_verification<F>(
    report: &mut CaseReport,
    failure_code: &str,
    errors: &mut Vec<String>,
    operation: F,
) where
    F: FnOnce() -> Result<(Vec<String>, Vec<String>, String)>,
{
    match operation() {
        Ok((outputs, responses, assertion)) => {
            report.output_sha256.extend(outputs);
            report.response_sha256.extend(responses);
            report.assertions.push(assertion);
        }
        Err(error) => {
            report.fail(failure_code);
            errors.push(format!(
                "{} persisted verification: {error:#}",
                report.case_id
            ));
        }
    }
}

fn case_mut<'a>(cases: &'a mut [CaseReport], case_id: &str) -> &'a mut CaseReport {
    cases
        .iter_mut()
        .find(|case| case.case_id == case_id)
        .expect("closed five-case inventory")
}

fn fail_unattempted_cases(cases: &mut [CaseReport], failure_code: &str) {
    for case in cases {
        if case.failure_code.is_none() && case.result != "evaluation_passed" {
            case.fail(failure_code);
        }
    }
}

fn fail_successful_mutations(cases: &mut [CaseReport], failure_code: &str) {
    for case in cases {
        if case.case_id != "read" && case.result == "evaluation_passed" {
            case.fail(failure_code);
        }
    }
}

fn apply_shutdown(report: &mut SessionReport, observation: McpShutdownObservation) {
    report.exit_success = observation.status.success();
    report.active_processes_after_exit = observation.active_processes;
}

fn parse_probe_observation(line: &str) -> ProbeReport {
    let result = if line.contains("state=Ready") {
        "ready"
    } else if line.contains("state=Failed") {
        "failed"
    } else {
        "missing"
    };
    let elapsed_ms = line.split_whitespace().find_map(|part| {
        part.strip_prefix("elapsed_ms=")
            .and_then(|value| value.trim_end_matches(',').parse().ok())
    });
    ProbeReport {
        result: result.to_string(),
        elapsed_ms,
    }
}

fn validate_final_bindings(
    preflight: &Preflight,
    package: &PreparedPreviewEvaluationPackage,
    staged: &StagedCases,
    cases: &mut [CaseReport],
    errors: &mut Vec<String>,
) -> Option<ExactPreviewActivationInspection> {
    let result = (|| -> Result<ExactPreviewActivationInspection> {
        if xref_sha256_file(Path::new(&preflight.plan.package.path))?
            != preflight.plan.package.sha256
        {
            return Err(anyhow!("source MCPB digest changed during evaluation"));
        }
        if xref_sha256_file(&package.binary_path)? != package.binary_sha256 {
            return Err(anyhow!(
                "extracted Preview binary digest changed during evaluation"
            ));
        }
        for (label, input) in plan_inputs(&preflight.plan) {
            inspect_exact_input(Path::new(&input.path), &input.sha256, label)?;
        }
        if let Some(profiles) = &preflight.plan.title_block_profiles {
            inspect_exact_input(
                Path::new(&profiles.path),
                &profiles.sha256,
                "title_block_profiles.path",
            )?;
        }
        if xref_sha256_file(&staged.xref_source)? != preflight.plan.cases.xref_attach.source.sha256
        {
            return Err(anyhow!("staged XREF source digest changed"));
        }
        let observed = inspect_exact_registered_preview_activation(
            &preflight.plan.activation_target.target_id,
            Path::new(&preflight.plan.activation_target.accoreconsole_path),
        )?;
        if observed != preflight.activation {
            return Err(anyhow!(
                "exact AutoCAD target identity changed across the two MCP sessions"
            ));
        }
        if xref_sha256_file(&observed.canonical_executable)?
            != preflight.plan.activation_target.accoreconsole_sha256
        {
            return Err(anyhow!("exact AutoCAD engine digest changed"));
        }
        Ok(observed)
    })();

    match result {
        Ok(observed) => {
            append_final_case_digests(staged, cases, errors);
            Some(observed)
        }
        Err(error) => {
            errors.push(format!("final_binding: {error:#}"));
            None
        }
    }
}

fn append_final_case_digests(
    staged: &StagedCases,
    cases: &mut [CaseReport],
    errors: &mut Vec<String>,
) {
    for (case_id, paths) in [
        ("read", vec![&staged.read]),
        ("title_block_write", vec![&staged.title_block]),
        ("layer_mutation", vec![&staged.layer]),
        ("plot", vec![&staged.plot, &staged.plot_pdf]),
        ("xref_attach", vec![&staged.xref_host, &staged.xref_source]),
    ] {
        let report = case_mut(cases, case_id);
        for path in paths {
            match hash_retained_output(path) {
                Ok(digest) => report.output_sha256.push(digest),
                Err(error) => {
                    report.fail("final_output_hash_failed");
                    errors.push(format!("{case_id} final output hash: {error:#}"));
                }
            }
        }
        report.output_sha256.sort();
        report.output_sha256.dedup();
        report.response_sha256.sort();
        report.response_sha256.dedup();
    }
}

fn hash_retained_output(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect retained output {}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "retained output must be a regular non-symlink file"
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_EXTERNAL_FILE_BYTES {
        return Err(anyhow!(
            "retained output must be nonempty and no larger than {MAX_EXTERNAL_FILE_BYTES} bytes"
        ));
    }
    require_no_reparse_components(path, "retained output")?;
    xref_sha256_file(path).context("hash retained output")
}

fn write_report_atomic(path: &Path, report: &EvaluationReport) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("evaluation report path must have a parent directory"))?;
    let mut pending =
        tempfile::NamedTempFile::new_in(parent).context("create pending evaluation report")?;
    serde_json::to_writer_pretty(pending.as_file_mut(), report)
        .context("serialize evaluation report")?;
    pending
        .as_file_mut()
        .sync_all()
        .context("sync pending evaluation report")?;
    pending.persist_noclobber(path).map_err(|error| {
        anyhow!(
            "atomically publish new evaluation report {}: {}",
            path.display(),
            error.error
        )
    })?;
    Ok(())
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create new {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn sha256_text(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: char) -> String {
        seed.to_string().repeat(64)
    }

    fn valid_plan_value() -> Value {
        serde_json::json!({
            "schema_version": 1,
            "artifact_kind": PLAN_KIND,
            "authority": AUTHORITY,
            "package": {
                "path": "C:\\evaluation\\candidate.mcpb",
                "sha256": digest('a')
            },
            "activation_target": {
                "catalogue_sha256": digest('b'),
                "target_id": "autocad-2026-r25-1-en-us-preview-v1",
                "accoreconsole_path": "C:\\Program Files\\Autodesk\\AutoCAD 2026\\accoreconsole.exe",
                "accoreconsole_sha256": digest('c'),
                "fixed_file_version": "25.1.0.0"
            },
            "title_block_profiles": null,
            "cases": {
                "read": {
                    "drawing": {
                        "path": "C:\\private\\read.dwg",
                        "sha256": digest('d')
                    },
                    "expected_layout": "Layout1"
                },
                "title_block_write": {
                    "drawing": {
                        "path": "C:\\private\\title.dwg",
                        "sha256": digest('e')
                    },
                    "fields": {
                        "drawing_number": "MCP-E2E-NUMBER",
                        "revision": "MCP-E2E-REV"
                    },
                    "expected_profile": {
                        "profile_id": "AUTOCAD_MCP_GENERIC",
                        "profile_authority": "embedded"
                    }
                },
                "layer_mutation": {
                    "drawing": {
                        "path": "C:\\private\\layer.dwg",
                        "sha256": digest('f')
                    },
                    "created_name": "MCP_E2E_LAYER_CREATED",
                    "renamed_name": "MCP_E2E_LAYER_RENAMED",
                    "create_properties": {"color_index": 3},
                    "update_properties": {
                        "color_index": 5,
                        "is_plottable": false
                    }
                },
                "plot": {
                    "drawing": {
                        "path": "C:\\private\\plot.dwg",
                        "sha256": digest('1')
                    },
                    "layout": "Layout1"
                },
                "xref_attach": {
                    "host": {
                        "path": "C:\\private\\xref-host.dwg",
                        "sha256": digest('2')
                    },
                    "source": {
                        "path": "C:\\private\\xref-source.dwg",
                        "sha256": digest('3')
                    },
                    "name": "MCP_E2E_XREF",
                    "reference_type": "attachment",
                    "placement": {
                        "owner_type": "model_space",
                        "layer_name": "0",
                        "insertion_point": {"x": 0.0, "y": 0.0, "z": 0.0},
                        "scale": {"x": 1.0, "y": 1.0, "z": 1.0},
                        "rotation_degrees": 0.0
                    }
                }
            }
        })
    }

    fn parse_value(value: Value) -> Result<EvaluationPlan> {
        let bytes = serde_json::to_vec(&value)?;
        let strict = distribution_approval::parse_strict_json(&bytes)?;
        let plan: EvaluationPlan = serde_json::from_value(strict)?;
        validate_plan(&plan)?;
        Ok(plan)
    }

    fn synthetic_preflight() -> Preflight {
        Preflight {
            invocation_started: Instant::now(),
            plan: parse_value(valid_plan_value()).expect("valid plan"),
            plan_sha256: digest('9'),
            activation: ExactPreviewActivationInspection {
                activation_catalogue_sha256: digest('b'),
                target_id: "autocad-2026-r25-1-en-us-preview-v1".to_string(),
                release_year: 2026,
                registry_family: "ACAD-1001:409".to_string(),
                product_language_key: "409".to_string(),
                ui_locale: "en-US".to_string(),
                maintained_target: true,
                canonical_executable: PathBuf::from(
                    "C:\\Program Files\\Autodesk\\AutoCAD 2026\\accoreconsole.exe",
                ),
                file_version: "25.1.0.0".to_string(),
                engine_identity_token: "synthetic-engine-identity".to_string(),
                profile_arg_sha256: digest('4'),
                profile_policy_id: "autocad-mcp-preview".to_string(),
                profile_policy_sha256: digest('5'),
                operation_families: MutationCapability::ALL.to_vec(),
                drawing_formats: vec![EXPECTED_DWG_FORMAT.to_string()],
            },
            profile_pack: None,
            runner: RunnerObservation {
                git_commit: digest('6'),
                runner_tree_state: "clean".to_string(),
            },
            host: HostObservation {
                operating_system: "windows".to_string(),
                architecture: "x86_64".to_string(),
                windows_version: "synthetic".to_string(),
            },
        }
    }

    #[cfg(unix)]
    fn write_json_line(path: &Path, value: &Value) {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        fs::write(path, bytes).unwrap();
    }

    #[cfg(unix)]
    fn prepare_fake_session_directory(path: &Path, tools: &Value) {
        fs::create_dir_all(path).unwrap();
        write_json_line(
            &path.join("initialize-response.json"),
            &serde_json::json!({
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
        write_json_line(
            &path.join("tools-response.json"),
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"tools": tools}
            }),
        );
    }

    #[cfg(unix)]
    fn assert_fake_session_observation(path: &Path, expected_arguments: &str) {
        assert_eq!(
            fs::read_to_string(path.join("arguments.txt"))
                .unwrap()
                .trim(),
            expected_arguments
        );
        let environment = fs::read_to_string(path.join("environment.txt")).unwrap();
        assert_eq!(
            environment.lines().collect::<Vec<_>>(),
            [
                "C:\\Program Files\\Autodesk\\AutoCAD 2026\\accoreconsole.exe",
                "autocad_mcp::probe=info",
                "unset",
            ]
        );
        let requests = fs::read_to_string(path.join("requests.ndjson"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0]["method"], "initialize");
        assert_eq!(requests[1]["method"], "notifications/initialized");
        assert_eq!(requests[2]["method"], "tools/list");
    }

    #[test]
    fn strict_plan_accepts_the_closed_five_case_shape() {
        let plan = parse_value(valid_plan_value()).expect("valid plan");
        assert_eq!(plan.cases.xref_attach.name, "MCP_E2E_XREF");
        assert!(plan.title_block_profiles.is_none());
    }

    #[test]
    fn strict_plan_requires_the_nullable_profile_field() {
        let mut value = valid_plan_value();
        value
            .as_object_mut()
            .unwrap()
            .remove("title_block_profiles");
        assert!(parse_value(value).is_err());
    }

    #[test]
    fn strict_plan_rejects_unknown_fields_and_general_tool_calls() {
        let mut value = valid_plan_value();
        value
            .as_object_mut()
            .unwrap()
            .insert("tool_calls".to_string(), serde_json::json!([]));
        let error = parse_value(value).expect_err("unknown top-level field");
        assert!(
            error.to_string().contains("unknown field") || error.to_string().contains("closed")
        );
    }

    #[test]
    fn strict_json_rejects_duplicate_plan_keys() {
        let serialized = serde_json::to_string(&valid_plan_value()).unwrap();
        let duplicate = serialized.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        let error = distribution_approval::parse_strict_json(duplicate.as_bytes())
            .expect_err("duplicate plan key");
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn strict_plan_rejects_paths_hashes_sentinels_and_layer_escape_hatches() {
        let mut invalid_path = valid_plan_value();
        invalid_path["package"]["path"] = serde_json::json!("candidate.mcpb");
        assert!(parse_value(invalid_path).is_err());

        let mut alternate_data_stream = valid_plan_value();
        alternate_data_stream["package"]["path"] =
            serde_json::json!("C:\\evaluation\\candidate.mcpb:stream");
        assert!(parse_value(alternate_data_stream).is_err());

        let mut invalid_hash = valid_plan_value();
        invalid_hash["package"]["sha256"] = serde_json::json!(digest('A'));
        assert!(parse_value(invalid_hash).is_err());

        let mut non_preview_target = valid_plan_value();
        non_preview_target["activation_target"]["target_id"] =
            serde_json::json!("autocad-2026-r25-1-en-us");
        assert!(parse_value(non_preview_target).is_err());

        let mut sensitive_value = valid_plan_value();
        sensitive_value["cases"]["title_block_write"]["fields"]["revision"] =
            serde_json::json!("real-project-revision");
        assert!(parse_value(sensitive_value).is_err());

        let mut unknown_property = valid_plan_value();
        unknown_property["cases"]["layer_mutation"]["create_properties"]["material_handle"] =
            serde_json::json!("AB");
        assert!(parse_value(unknown_property).is_err());
    }

    #[test]
    fn profile_authority_must_agree_with_optional_administrator_pack() {
        let mut value = valid_plan_value();
        value["cases"]["title_block_write"]["expected_profile"]["profile_authority"] =
            serde_json::json!("administrator");
        assert!(parse_value(value).is_err());
    }

    #[test]
    fn probe_parser_normalizes_only_terminal_completion_states() {
        assert_eq!(
            parse_probe_observation(
                "INFO state=Ready elapsed_ms=123 serve-only advisory Core Console probe completed"
            )
            .result,
            "ready"
        );
        let failed = parse_probe_observation(
            "INFO state=Failed elapsed_ms=456 serve-only advisory Core Console probe completed",
        );
        assert_eq!(failed.result, "failed");
        assert_eq!(failed.elapsed_ms, Some(456));
        assert_eq!(parse_probe_observation("state=Running").result, "missing");
    }

    #[test]
    fn pdf_validator_checks_header_size_and_bounded_eof_tail() {
        let directory = tempfile::tempdir().unwrap();
        let canonical_directory = fs::canonicalize(directory.path()).unwrap();
        let valid = canonical_directory.join("valid.pdf");
        let mut bytes = b"%PDF-1.7\n".to_vec();
        bytes.resize(MIN_PDF_BYTES as usize, b'x');
        bytes.extend_from_slice(b"\n%%EOF\n");
        fs::write(&valid, bytes).unwrap();
        assert_eq!(validate_pdf(&valid).unwrap().len(), 64);

        let invalid = canonical_directory.join("invalid.pdf");
        fs::write(&invalid, vec![b'x'; MIN_PDF_BYTES as usize]).unwrap();
        assert!(validate_pdf(&invalid).is_err());
    }

    #[test]
    fn report_case_paths_are_work_directory_relative() {
        let cases = initial_case_reports(&parse_value(valid_plan_value()).expect("valid plan"));
        let serialized = serde_json::to_string(&cases).unwrap();
        assert!(serialized.contains("cases/read/input.dwg"));
        assert!(!serialized.contains("C:\\\\private"));
        assert!(!serialized.contains("Program Files"));
    }

    #[test]
    fn evaluator_initializes_only_its_owned_work_tree() {
        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("operator-owned.txt");
        fs::write(&outside, b"untouched").unwrap();
        let work_dir = directory.path().join("evaluation");
        fs::create_dir(&work_dir).unwrap();

        let staged = initialize_work_directory(&work_dir).unwrap();
        for path in [
            staged.read,
            staged.title_block,
            staged.layer,
            staged.plot,
            staged.xref_host,
            staged.xref_source,
            staged.plot_pdf,
        ] {
            assert!(path.starts_with(&work_dir), "escaped work root: {path:?}");
        }

        let directories = walkdir::WalkDir::new(&work_dir)
            .min_depth(1)
            .into_iter()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_type().is_dir())
            .map(|entry| {
                entry
                    .path()
                    .strip_prefix(&work_dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            directories,
            [
                "cases",
                "cases/layer-mutation",
                "cases/plot",
                "cases/read",
                "cases/title-block-write",
                "cases/xref-attach",
                "logs",
                "observations",
                "observations/persisted-read",
                "observations/primary",
                "package",
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        );
        assert_eq!(fs::read(outside).unwrap(), b"untouched");
    }

    #[test]
    fn title_block_assertion_requires_exact_singleton_values() {
        let drawing_number = "MCP-E2E-NUMBER".to_string();
        let revision = "MCP-E2E-REV".to_string();
        let expected = vec![
            ("DRAWING_NUMBER".to_string(), &drawing_number),
            ("REVISION".to_string(), &revision),
        ];
        let mut block = TitleBlockInfo {
            block_name: "AUTOCAD_MCP_GENERIC".to_string(),
            layer: "0".to_string(),
            attributes: Default::default(),
            attribute_arrays: [
                ("DRAWING_NUMBER".to_string(), vec![drawing_number.clone()]),
                ("REVISION".to_string(), vec![revision.clone()]),
            ]
            .into_iter()
            .collect(),
        };
        assert!(title_block_has_exact_values(&block, &expected));

        block
            .attribute_arrays
            .get_mut("REVISION")
            .unwrap()
            .push(revision.clone());
        assert!(!title_block_has_exact_values(&block, &expected));
        block.attribute_arrays.remove("DRAWING_NUMBER");
        assert!(!title_block_has_exact_values(&block, &expected));
    }

    #[test]
    fn fatal_report_is_closed_redacted_and_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let preflight = synthetic_preflight();
        let report_path = directory.path().join("preview-autocad-e2e-report.json");

        write_fatal_report(directory.path(), &preflight).unwrap();
        let original = fs::read(&report_path).unwrap();
        let report = distribution_approval::parse_strict_json(&original).unwrap();
        assert_eq!(report["result"], "evaluation_failed");
        assert_eq!(
            report
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            [
                "activation_target",
                "artifact_kind",
                "authority",
                "cases",
                "host",
                "limitations",
                "probe",
                "result",
                "runner",
                "schema_version",
                "sessions",
                "subject",
                "title_block_profiles",
            ]
            .into_iter()
            .collect()
        );

        let serialized = String::from_utf8(original.clone()).unwrap();
        let work_dir_text = directory.path().to_string_lossy().into_owned();
        for sensitive in [
            "C:\\evaluation\\candidate.mcpb",
            "C:\\Program Files",
            "C:\\private",
            "MCP-E2E-NUMBER",
            "MCP-E2E-REV",
            work_dir_text.as_str(),
        ] {
            assert!(
                !serialized.contains(sensitive),
                "report leaked sensitive value {sensitive:?}"
            );
        }

        let error =
            write_fatal_report(directory.path(), &preflight).expect_err("report is create-new");
        assert!(
            error.to_string().contains("publish new evaluation report"),
            "{error:#}"
        );
        assert_eq!(fs::read(report_path).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn fake_server_exercises_exact_primary_and_persisted_sessions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let work_dir = directory.path().join("evaluation");
        let primary = work_dir.join("observations/primary");
        let persisted = work_dir.join("observations/persisted-read");
        let tools =
            serde_json::to_value(autocad_mcp::server::AutocadServer::tool_router().list_all())
                .unwrap();
        prepare_fake_session_directory(&primary, &tools);
        prepare_fake_session_directory(&persisted, &tools);

        let binary = directory.path().join("fake-autocad-mcp");
        fs::write(
            &binary,
            r#"#!/bin/sh
set -eu
printf '%s\n' "$*" > arguments.txt
printf '%s\n' \
  "${AUTOCAD_MCP_ACCORECONSOLE_PATH-unset}" \
  "${RUST_LOG-unset}" \
  "${AUTOCAD_MCP_TITLE_BLOCK_PROFILES-unset}" > environment.txt
printf '%s\n' 'serve-only advisory Core Console probe completed state=Ready elapsed_ms=7' >&2
count=0
while IFS= read -r line; do
  printf '%s\n' "$line" >> requests.ndjson
  count=$((count + 1))
  case "$count" in
    1) cat initialize-response.json ;;
    2) : ;;
    3) cat tools-response.json ;;
    *) exit 91 ;;
  esac
done
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&binary, permissions).unwrap();

        let preflight = synthetic_preflight();
        let package = PreparedPreviewEvaluationPackage {
            package_name: "autocad-mcp".to_string(),
            package_version: "0.0.1".to_string(),
            binary_path: binary,
            package_sha256: digest('a'),
            manifest_sha256: digest('7'),
            binary_sha256: digest('8'),
            activation_catalogue_sha256: digest('b'),
            activation_binding_sha256: digest('0'),
        };

        let mut primary_session = launch_session(
            &work_dir,
            &preflight,
            &package,
            "primary",
            &["serve", "--experimental"],
        )
        .unwrap();
        assert_eq!(
            initialize_and_validate_tools(&mut primary_session).unwrap(),
            EXPECTED_TOOL_COUNT
        );
        assert!(primary_session
            .wait_for_stderr_line(PROBE_LOG_MARKER, Duration::from_secs(2))
            .unwrap()
            .is_some());
        assert!(primary_session
            .close_stdin_and_wait(Duration::from_secs(2))
            .unwrap()
            .status
            .success());

        let mut persisted_session = launch_session(
            &work_dir,
            &preflight,
            &package,
            "persisted-read",
            &["serve", "--experimental", "--engine-probe", "off"],
        )
        .unwrap();
        assert_eq!(
            initialize_and_validate_tools(&mut persisted_session).unwrap(),
            EXPECTED_TOOL_COUNT
        );
        assert!(persisted_session
            .close_stdin_and_wait(Duration::from_secs(2))
            .unwrap()
            .status
            .success());

        assert_fake_session_observation(&primary, "serve --experimental");
        assert_fake_session_observation(&persisted, "serve --experimental --engine-probe off");
    }
}
