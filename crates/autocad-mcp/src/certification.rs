use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
    sync::OnceLock,
};

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::activation::{self, MutationCapability};
use crate::autocad_reader::{
    map_format_facts_snapshot_open_error, DrawingFormat, DrawingSnapshot, Reader,
};
use crate::ops::layers::{canonical_handle, parse_handle, validate_layer_name};
use crate::ops::profiles;
use crate::ops::xref_path::CanonicalDisplayPath;
use crate::ops::xrefs::{
    classify_attachment_update_property, classify_instance_update_property, AttachXrefRequest,
    BindXrefRequest, DeleteXrefInstanceRequest, DetachXrefRequest, InsertXrefInstanceRequest,
    ReferenceType, ReloadXrefRequest, UnloadXrefRequest, UpdateXrefInstanceRequest,
    UpdateXrefRequest, XrefDependencyTraversalEnvelope, XrefInspectionState,
    XrefPropertyClassification, XrefResolutionState,
};

pub const XREF_ARTIFACT_SCHEMA_VERSION: u32 = 1;
pub const XREF_MUTATION_CAPABILITY_SCHEMA_VERSION: u32 = 2;

pub const XREF_MUTATION_CAPABILITIES_BYTES: &[u8] =
    include_bytes!("../resources/xref-mutation-capabilities.json");
pub const XREF_PRESERVATION_VERIFIER_PROFILES_BYTES: &[u8] =
    include_bytes!("../resources/xref-preservation-verifier-profiles.json");
pub const XREF_BIND_VERIFIER_PROFILES_BYTES: &[u8] =
    include_bytes!("../resources/xref-bind-verifier-profiles.json");
pub const XREF_CLIP_VERIFIER_PROFILES_BYTES: &[u8] =
    include_bytes!("../resources/xref-clip-verifier-profiles.json");

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XrefEmbeddedArtifact {
    MutationCapabilities,
    PreservationVerifierProfiles,
    BindVerifierProfiles,
    ClipVerifierProfiles,
}

pub const XREF_EMBEDDED_ARTIFACTS: [XrefEmbeddedArtifact; 4] = [
    XrefEmbeddedArtifact::MutationCapabilities,
    XrefEmbeddedArtifact::PreservationVerifierProfiles,
    XrefEmbeddedArtifact::BindVerifierProfiles,
    XrefEmbeddedArtifact::ClipVerifierProfiles,
];

impl XrefEmbeddedArtifact {
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::MutationCapabilities => "xref-mutation-capabilities.json",
            Self::PreservationVerifierProfiles => "xref-preservation-verifier-profiles.json",
            Self::BindVerifierProfiles => "xref-bind-verifier-profiles.json",
            Self::ClipVerifierProfiles => "xref-clip-verifier-profiles.json",
        }
    }

    pub const fn exact_bytes(self) -> &'static [u8] {
        match self {
            Self::MutationCapabilities => XREF_MUTATION_CAPABILITIES_BYTES,
            Self::PreservationVerifierProfiles => XREF_PRESERVATION_VERIFIER_PROFILES_BYTES,
            Self::BindVerifierProfiles => XREF_BIND_VERIFIER_PROFILES_BYTES,
            Self::ClipVerifierProfiles => XREF_CLIP_VERIFIER_PROFILES_BYTES,
        }
    }

    /// Hashes the exact embedded UTF-8 bytes, before artifact parsing, with the
    /// caller-provided SHA-256 implementation.
    pub fn sha256_digest_with<T>(self, digest: impl FnOnce(&[u8]) -> T) -> T {
        digest(self.exact_bytes())
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefHostFormat {
    Dwg,
    Dxf,
}

impl XrefHostFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dwg => "dwg",
            Self::Dxf => "dxf",
        }
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefDxfForm {
    NotApplicable,
    Ascii,
    Binary,
}

impl XrefDxfForm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Ascii => "ascii",
            Self::Binary => "binary",
        }
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefAutocadProduct {
    Autocad,
}

impl XrefAutocadProduct {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Autocad => "autocad",
        }
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefMutationOperation {
    AttachXref,
    BindXref,
    DeleteXrefInstance,
    DetachXref,
    InsertXrefInstance,
    ReloadXref,
    UnloadXref,
    UpdateXref,
    UpdateXrefInstance,
}

pub const XREF_MUTATION_OPERATIONS: [XrefMutationOperation; 9] = [
    XrefMutationOperation::AttachXref,
    XrefMutationOperation::BindXref,
    XrefMutationOperation::DeleteXrefInstance,
    XrefMutationOperation::DetachXref,
    XrefMutationOperation::InsertXrefInstance,
    XrefMutationOperation::ReloadXref,
    XrefMutationOperation::UnloadXref,
    XrefMutationOperation::UpdateXref,
    XrefMutationOperation::UpdateXrefInstance,
];

impl XrefMutationOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AttachXref => "attach_xref",
            Self::BindXref => "bind_xref",
            Self::DeleteXrefInstance => "delete_xref_instance",
            Self::DetachXref => "detach_xref",
            Self::InsertXrefInstance => "insert_xref_instance",
            Self::ReloadXref => "reload_xref",
            Self::UnloadXref => "unload_xref",
            Self::UpdateXref => "update_xref",
            Self::UpdateXrefInstance => "update_xref_instance",
        }
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefClipPolicy {
    Reject,
    Verify,
}

impl XrefClipPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Verify => "verify",
        }
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefVerifierSymbolType {
    Block,
    DimensionStyle,
    Layer,
    Linetype,
    Material,
    MultileaderStyle,
    PlotStyle,
    TableStyle,
    TextStyle,
    VisualStyle,
}

impl XrefVerifierSymbolType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::DimensionStyle => "dimension_style",
            Self::Layer => "layer",
            Self::Linetype => "linetype",
            Self::Material => "material",
            Self::MultileaderStyle => "multileader_style",
            Self::PlotStyle => "plot_style",
            Self::TableStyle => "table_style",
            Self::TextStyle => "text_style",
            Self::VisualStyle => "visual_style",
        }
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefBindStrategy {
    Merge,
    Prefix,
}

impl XrefBindStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Prefix => "prefix",
        }
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefUnitRole {
    Host,
    Source,
}

impl XrefUnitRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Source => "source",
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefMutationCapabilityArtifact {
    pub schema_version: u32,
    pub rows: Vec<XrefMutationCapabilityRow>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefMutationCapabilityRow {
    pub row_id: String,
    pub host_format: XrefHostFormat,
    pub drawing_version: String,
    pub dxf_form: XrefDxfForm,
    pub code_page: Option<String>,
    pub operations: Vec<XrefMutationOperation>,
    pub preservation_verifier_profile_id: String,
    pub bind_verifier_profile_id: Option<String>,
    pub clip_policy: XrefClipPolicy,
    pub clip_verifier_profile_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefPreservationVerifierProfilesArtifact {
    pub schema_version: u32,
    pub profiles: Vec<XrefPreservationVerifierProfile>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefPreservationVerifierProfile {
    pub profile_id: String,
    pub absolute_tolerance: f64,
    pub relative_tolerance: f64,
    pub object_classes: Vec<XrefVerifierObjectClass>,
    pub symbol_types: Vec<XrefVerifierSymbol>,
    pub mapped_identity_fields: Vec<String>,
    pub authorized_differences: Vec<XrefOperationAuthorizedDifferences>,
    pub profile_default_unit_states: Vec<XrefProfileDefaultUnitState>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefBindVerifierProfilesArtifact {
    pub schema_version: u32,
    pub profiles: Vec<XrefBindVerifierProfile>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefBindVerifierProfile {
    pub profile_id: String,
    pub absolute_tolerance: f64,
    pub relative_tolerance: f64,
    pub object_classes: Vec<XrefVerifierObjectClass>,
    pub symbol_types: Vec<XrefVerifierSymbol>,
    pub mapped_identity_fields: Vec<String>,
    pub authorized_differences: Vec<XrefOperationAuthorizedDifferences>,
    pub profile_default_unit_states: Vec<XrefProfileDefaultUnitState>,
    pub strategy_authorized_differences: Vec<XrefStrategyAuthorizedDifferences>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefClipVerifierProfilesArtifact {
    pub schema_version: u32,
    pub profiles: Vec<XrefClipVerifierProfile>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefClipVerifierProfile {
    pub profile_id: String,
    pub absolute_tolerance: f64,
    pub relative_tolerance: f64,
    pub mapped_identity_fields: Vec<String>,
    pub profile_default_unit_states: Vec<XrefProfileDefaultUnitState>,
    pub clip_fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefVerifierObjectClass {
    pub class_name: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefVerifierSymbol {
    pub symbol_type: XrefVerifierSymbolType,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefOperationAuthorizedDifferences {
    pub operation: XrefMutationOperation,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefStrategyAuthorizedDifferences {
    pub strategy: XrefBindStrategy,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefProfileDefaultUnitState {
    pub host_format: XrefHostFormat,
    pub drawing_version: String,
    pub role: XrefUnitRole,
}

pub const XREF_CLIP_FIELDS: [&str; 14] = [
    "associated_instance_transform",
    "back_distance",
    "back_plane_enabled",
    "block_transform",
    "boundary_ocs_points",
    "enabled",
    "front_distance",
    "front_plane_enabled",
    "inverse_block_transform",
    "inverted",
    "local_origin",
    "normal",
    "owner_handle",
    "spatial_filter_handle",
];

#[derive(Debug)]
pub struct XrefArtifactRegistry {
    capabilities: XrefMutationCapabilityArtifact,
    preservation_profiles: XrefPreservationVerifierProfilesArtifact,
    bind_profiles: XrefBindVerifierProfilesArtifact,
    clip_profiles: XrefClipVerifierProfilesArtifact,
}

impl XrefArtifactRegistry {
    pub fn from_bytes(
        capabilities: &[u8],
        preservation_profiles: &[u8],
        bind_profiles: &[u8],
        clip_profiles: &[u8],
    ) -> Result<Self> {
        let capabilities = parse_xref_artifact(
            XrefEmbeddedArtifact::MutationCapabilities.file_name(),
            capabilities,
        )?;
        let preservation_profiles = parse_xref_artifact(
            XrefEmbeddedArtifact::PreservationVerifierProfiles.file_name(),
            preservation_profiles,
        )?;
        let bind_profiles = parse_xref_artifact(
            XrefEmbeddedArtifact::BindVerifierProfiles.file_name(),
            bind_profiles,
        )?;
        let clip_profiles = parse_xref_artifact(
            XrefEmbeddedArtifact::ClipVerifierProfiles.file_name(),
            clip_profiles,
        )?;

        let registry = Self {
            capabilities,
            preservation_profiles,
            bind_profiles,
            clip_profiles,
        };
        registry.validate()?;
        Ok(registry)
    }

    pub fn capabilities(&self) -> &XrefMutationCapabilityArtifact {
        &self.capabilities
    }

    pub fn preservation_profiles(&self) -> &XrefPreservationVerifierProfilesArtifact {
        &self.preservation_profiles
    }

    pub fn bind_profiles(&self) -> &XrefBindVerifierProfilesArtifact {
        &self.bind_profiles
    }

    pub fn clip_profiles(&self) -> &XrefClipVerifierProfilesArtifact {
        &self.clip_profiles
    }

    pub fn preservation_profile(
        &self,
        profile_id: &str,
    ) -> Option<&XrefPreservationVerifierProfile> {
        self.preservation_profiles
            .profiles
            .binary_search_by(|profile| profile.profile_id.as_str().cmp(profile_id))
            .ok()
            .map(|index| &self.preservation_profiles.profiles[index])
    }

    pub fn bind_profile(&self, profile_id: &str) -> Option<&XrefBindVerifierProfile> {
        self.bind_profiles
            .profiles
            .binary_search_by(|profile| profile.profile_id.as_str().cmp(profile_id))
            .ok()
            .map(|index| &self.bind_profiles.profiles[index])
    }

    pub fn clip_profile(&self, profile_id: &str) -> Option<&XrefClipVerifierProfile> {
        self.clip_profiles
            .profiles
            .binary_search_by(|profile| profile.profile_id.as_str().cmp(profile_id))
            .ok()
            .map(|index| &self.clip_profiles.profiles[index])
    }

    fn validate(&self) -> Result<()> {
        let mut errors = Vec::new();
        validate_capability_artifact(&self.capabilities, &mut errors);
        validate_preservation_artifact(&self.preservation_profiles, &mut errors);
        validate_bind_artifact(&self.bind_profiles, &mut errors);
        validate_clip_artifact(&self.clip_profiles, &mut errors);
        validate_profile_references(self, &mut errors);
        finish_xref_validation(errors)
    }
}

static EMBEDDED_XREF_ARTIFACTS: OnceLock<std::result::Result<XrefArtifactRegistry, String>> =
    OnceLock::new();

pub fn embedded_xref_artifacts() -> Result<&'static XrefArtifactRegistry> {
    match EMBEDDED_XREF_ARTIFACTS.get_or_init(|| {
        XrefArtifactRegistry::from_bytes(
            XREF_MUTATION_CAPABILITIES_BYTES,
            XREF_PRESERVATION_VERIFIER_PROFILES_BYTES,
            XREF_BIND_VERIFIER_PROFILES_BYTES,
            XREF_CLIP_VERIFIER_PROFILES_BYTES,
        )
        .map_err(|error| error.to_string())
    }) {
        Ok(registry) => Ok(registry),
        Err(error) => Err(anyhow::anyhow!(error.clone())),
    }
}

fn parse_xref_artifact<T>(file_name: &str, bytes: &[u8]) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let json = std::str::from_utf8(bytes)
        .map_err(|error| anyhow::anyhow!("{file_name} is not UTF-8: {error}"))?;
    serde_json::from_str(json)
        .map_err(|error| anyhow::anyhow!("failed to parse {file_name}: {error}"))
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CapabilityTuple<'a> {
    host_format: XrefHostFormat,
    drawing_version: &'a str,
    dxf_form: XrefDxfForm,
    code_page: Option<&'a str>,
}

fn validate_capability_artifact(
    artifact: &XrefMutationCapabilityArtifact,
    errors: &mut Vec<String>,
) {
    validate_schema_version(
        XrefEmbeddedArtifact::MutationCapabilities.file_name(),
        artifact.schema_version,
        XREF_MUTATION_CAPABILITY_SCHEMA_VERSION,
        errors,
    );
    if artifact.rows.is_empty() {
        errors.push("xref mutation capability matrix has no rows".to_string());
    }

    let row_ids: Vec<&str> = artifact
        .rows
        .iter()
        .map(|row| row.row_id.as_str())
        .collect();
    validate_sorted_unique_keys("capability rows by row_id", &row_ids, errors);

    let mut tuples = BTreeSet::new();
    let mut coverage: BTreeMap<XrefHostFormat, BTreeSet<XrefMutationOperation>> = BTreeMap::new();
    coverage.insert(XrefHostFormat::Dwg, BTreeSet::new());
    coverage.insert(XrefHostFormat::Dxf, BTreeSet::new());

    for row in &artifact.rows {
        let location = format!("capability row '{}'", row.row_id);
        validate_id(&row.row_id, &format!("{location} row_id"), errors);
        validate_drawing_version(&row.drawing_version, &location, errors);

        if !tuples.insert(CapabilityTuple {
            host_format: row.host_format,
            drawing_version: &row.drawing_version,
            dxf_form: row.dxf_form,
            code_page: row.code_page.as_deref(),
        }) {
            errors.push(format!("{location} duplicates a complete capability tuple"));
        }

        let operation_names: Vec<&str> = row
            .operations
            .iter()
            .map(|operation| operation.as_str())
            .collect();
        validate_sorted_unique_keys(&format!("{location} operations"), &operation_names, errors);
        if row.operations.is_empty() {
            errors.push(format!("{location} has no operations"));
        }
        coverage
            .entry(row.host_format)
            .or_default()
            .extend(row.operations.iter().copied());

        validate_id(
            &row.preservation_verifier_profile_id,
            &format!("{location} preservation_verifier_profile_id"),
            errors,
        );
        if let Some(profile_id) = &row.bind_verifier_profile_id {
            validate_id(
                profile_id,
                &format!("{location} bind_verifier_profile_id"),
                errors,
            );
        }
        if let Some(profile_id) = &row.clip_verifier_profile_id {
            validate_id(
                profile_id,
                &format!("{location} clip_verifier_profile_id"),
                errors,
            );
        }

        match (row.host_format, row.dxf_form, row.code_page.as_deref()) {
            (XrefHostFormat::Dwg, XrefDxfForm::NotApplicable, None) => {}
            (XrefHostFormat::Dwg, _, _) => errors.push(format!(
                "{location} must use dxf_form=not_applicable and code_page=null for DWG"
            )),
            (XrefHostFormat::Dxf, XrefDxfForm::Ascii, Some(code_page)) => {
                validate_code_page(code_page, &location, errors);
            }
            (XrefHostFormat::Dxf, XrefDxfForm::Binary, None) => {}
            (XrefHostFormat::Dxf, XrefDxfForm::NotApplicable, _) => errors.push(format!(
                "{location} must use dxf_form=ascii or binary for DXF"
            )),
            (XrefHostFormat::Dxf, XrefDxfForm::Ascii, None) => {
                errors.push(format!("{location} ASCII DXF requires code_page"));
            }
            (XrefHostFormat::Dxf, XrefDxfForm::Binary, Some(_)) => {
                errors.push(format!("{location} binary DXF requires code_page=null"));
            }
        }

        if row.operations.contains(&XrefMutationOperation::BindXref)
            && row.bind_verifier_profile_id.is_none()
        {
            errors.push(format!(
                "{location} advertises bind_xref without bind_verifier_profile_id"
            ));
        }

        match (row.clip_policy, row.clip_verifier_profile_id.as_deref()) {
            (XrefClipPolicy::Reject, None) | (XrefClipPolicy::Verify, Some(_)) => {}
            (XrefClipPolicy::Reject, Some(_)) => errors.push(format!(
                "{location} clip_policy=reject requires clip_verifier_profile_id=null"
            )),
            (XrefClipPolicy::Verify, None) => errors.push(format!(
                "{location} clip_policy=verify requires clip_verifier_profile_id"
            )),
        }
    }

    let required: BTreeSet<_> = XREF_MUTATION_OPERATIONS.into_iter().collect();
    for format in [XrefHostFormat::Dwg, XrefHostFormat::Dxf] {
        let actual = coverage.get(&format).cloned().unwrap_or_default();
        for operation in required.difference(&actual) {
            errors.push(format!(
                "{} capability coverage is missing operation '{}'",
                format.as_str(),
                operation.as_str()
            ));
        }
    }
}

fn validate_preservation_artifact(
    artifact: &XrefPreservationVerifierProfilesArtifact,
    errors: &mut Vec<String>,
) {
    validate_schema_version(
        XrefEmbeddedArtifact::PreservationVerifierProfiles.file_name(),
        artifact.schema_version,
        XREF_ARTIFACT_SCHEMA_VERSION,
        errors,
    );
    validate_profile_ids(
        "preservation verifier profiles",
        artifact
            .profiles
            .iter()
            .map(|profile| profile.profile_id.as_str()),
        errors,
    );
    for profile in &artifact.profiles {
        validate_common_profile(
            CommonProfile {
                profile_id: &profile.profile_id,
                absolute_tolerance: profile.absolute_tolerance,
                relative_tolerance: profile.relative_tolerance,
                object_classes: &profile.object_classes,
                symbol_types: &profile.symbol_types,
                mapped_identity_fields: &profile.mapped_identity_fields,
                authorized_differences: &profile.authorized_differences,
            },
            errors,
        );
        validate_default_unit_states(
            &profile.profile_id,
            &profile.profile_default_unit_states,
            errors,
        );
    }
}

fn validate_bind_artifact(artifact: &XrefBindVerifierProfilesArtifact, errors: &mut Vec<String>) {
    validate_schema_version(
        XrefEmbeddedArtifact::BindVerifierProfiles.file_name(),
        artifact.schema_version,
        XREF_ARTIFACT_SCHEMA_VERSION,
        errors,
    );
    validate_profile_ids(
        "bind verifier profiles",
        artifact
            .profiles
            .iter()
            .map(|profile| profile.profile_id.as_str()),
        errors,
    );
    for profile in &artifact.profiles {
        validate_common_profile(
            CommonProfile {
                profile_id: &profile.profile_id,
                absolute_tolerance: profile.absolute_tolerance,
                relative_tolerance: profile.relative_tolerance,
                object_classes: &profile.object_classes,
                symbol_types: &profile.symbol_types,
                mapped_identity_fields: &profile.mapped_identity_fields,
                authorized_differences: &profile.authorized_differences,
            },
            errors,
        );
        if !profile.profile_default_unit_states.is_empty() {
            errors.push(format!(
                "bind profile '{}' must not declare profile_default_unit_states",
                profile.profile_id
            ));
        }
        if !profile
            .authorized_differences
            .iter()
            .any(|difference| difference.operation == XrefMutationOperation::BindXref)
        {
            errors.push(format!(
                "bind profile '{}' has no bind_xref authorized differences",
                profile.profile_id
            ));
        }

        let strategies: Vec<&str> = profile
            .strategy_authorized_differences
            .iter()
            .map(|difference| difference.strategy.as_str())
            .collect();
        validate_sorted_unique_keys(
            &format!(
                "bind profile '{}' strategy_authorized_differences",
                profile.profile_id
            ),
            &strategies,
            errors,
        );
        let expected = [XrefBindStrategy::Merge, XrefBindStrategy::Prefix];
        if profile.strategy_authorized_differences.len() != expected.len()
            || !expected.iter().all(|strategy| {
                profile
                    .strategy_authorized_differences
                    .iter()
                    .any(|difference| difference.strategy == *strategy)
            })
        {
            errors.push(format!(
                "bind profile '{}' requires exactly one merge and one prefix strategy entry",
                profile.profile_id
            ));
        }
        for difference in &profile.strategy_authorized_differences {
            validate_field_list(
                &format!(
                    "bind profile '{}' strategy '{}' fields",
                    profile.profile_id,
                    difference.strategy.as_str()
                ),
                &difference.fields,
                errors,
            );
        }
    }
}

fn validate_clip_artifact(artifact: &XrefClipVerifierProfilesArtifact, errors: &mut Vec<String>) {
    validate_schema_version(
        XrefEmbeddedArtifact::ClipVerifierProfiles.file_name(),
        artifact.schema_version,
        XREF_ARTIFACT_SCHEMA_VERSION,
        errors,
    );
    validate_profile_ids(
        "clip verifier profiles",
        artifact
            .profiles
            .iter()
            .map(|profile| profile.profile_id.as_str()),
        errors,
    );
    for profile in &artifact.profiles {
        validate_tolerances(
            &profile.profile_id,
            profile.absolute_tolerance,
            profile.relative_tolerance,
            errors,
        );
        validate_field_list(
            &format!(
                "clip profile '{}' mapped_identity_fields",
                profile.profile_id
            ),
            &profile.mapped_identity_fields,
            errors,
        );
        if !profile.profile_default_unit_states.is_empty() {
            errors.push(format!(
                "clip profile '{}' must not declare profile_default_unit_states",
                profile.profile_id
            ));
        }
        validate_field_list(
            &format!("clip profile '{}' clip_fields", profile.profile_id),
            &profile.clip_fields,
            errors,
        );
        let expected: Vec<&str> = XREF_CLIP_FIELDS.into_iter().collect();
        let actual: Vec<&str> = profile.clip_fields.iter().map(String::as_str).collect();
        if actual != expected {
            errors.push(format!(
                "clip profile '{}' clip_fields must exactly match the v1 spatial-filter facts",
                profile.profile_id
            ));
        }
    }
}

fn validate_profile_references(registry: &XrefArtifactRegistry, errors: &mut Vec<String>) {
    for row in &registry.capabilities.rows {
        if registry
            .preservation_profile(&row.preservation_verifier_profile_id)
            .is_none()
        {
            errors.push(format!(
                "capability row '{}' references missing preservation profile '{}'",
                row.row_id, row.preservation_verifier_profile_id
            ));
        }
        if let Some(profile_id) = &row.bind_verifier_profile_id {
            if registry.bind_profile(profile_id).is_none() {
                errors.push(format!(
                    "capability row '{}' references missing bind profile '{}'",
                    row.row_id, profile_id
                ));
            }
        }
        if let Some(profile_id) = &row.clip_verifier_profile_id {
            if registry.clip_profile(profile_id).is_none() {
                errors.push(format!(
                    "capability row '{}' references missing clip profile '{}'",
                    row.row_id, profile_id
                ));
            }
        }
    }
}

struct CommonProfile<'a> {
    profile_id: &'a str,
    absolute_tolerance: f64,
    relative_tolerance: f64,
    object_classes: &'a [XrefVerifierObjectClass],
    symbol_types: &'a [XrefVerifierSymbol],
    mapped_identity_fields: &'a [String],
    authorized_differences: &'a [XrefOperationAuthorizedDifferences],
}

fn validate_common_profile(profile: CommonProfile<'_>, errors: &mut Vec<String>) {
    let CommonProfile {
        profile_id,
        absolute_tolerance,
        relative_tolerance,
        object_classes,
        symbol_types,
        mapped_identity_fields,
        authorized_differences,
    } = profile;
    validate_tolerances(profile_id, absolute_tolerance, relative_tolerance, errors);
    if object_classes.is_empty() {
        errors.push(format!("profile '{profile_id}' has no object_classes"));
    }
    let class_names: Vec<&str> = object_classes
        .iter()
        .map(|class| class.class_name.as_str())
        .collect();
    validate_sorted_unique_keys(
        &format!("profile '{profile_id}' object_classes"),
        &class_names,
        errors,
    );
    for class in object_classes {
        validate_token(
            &class.class_name,
            &format!("profile '{profile_id}' class_name"),
            errors,
        );
        validate_field_list(
            &format!(
                "profile '{profile_id}' object class '{}' fields",
                class.class_name
            ),
            &class.fields,
            errors,
        );
    }

    if symbol_types.is_empty() {
        errors.push(format!("profile '{profile_id}' has no symbol_types"));
    }
    let symbols: Vec<&str> = symbol_types
        .iter()
        .map(|symbol| symbol.symbol_type.as_str())
        .collect();
    validate_sorted_unique_keys(
        &format!("profile '{profile_id}' symbol_types"),
        &symbols,
        errors,
    );
    for symbol in symbol_types {
        validate_field_list(
            &format!(
                "profile '{profile_id}' symbol '{}' fields",
                symbol.symbol_type.as_str()
            ),
            &symbol.fields,
            errors,
        );
    }

    validate_field_list(
        &format!("profile '{profile_id}' mapped_identity_fields"),
        mapped_identity_fields,
        errors,
    );

    let operations: Vec<&str> = authorized_differences
        .iter()
        .map(|difference| difference.operation.as_str())
        .collect();
    validate_sorted_unique_keys(
        &format!("profile '{profile_id}' authorized_differences"),
        &operations,
        errors,
    );
    for difference in authorized_differences {
        validate_field_list(
            &format!(
                "profile '{profile_id}' operation '{}' fields",
                difference.operation.as_str()
            ),
            &difference.fields,
            errors,
        );
    }
}

fn validate_default_unit_states(
    profile_id: &str,
    states: &[XrefProfileDefaultUnitState],
    errors: &mut Vec<String>,
) {
    let keys: Vec<(XrefHostFormat, &str, XrefUnitRole)> = states
        .iter()
        .map(|state| {
            (
                state.host_format,
                state.drawing_version.as_str(),
                state.role,
            )
        })
        .collect();
    validate_sorted_unique_keys(
        &format!("profile '{profile_id}' profile_default_unit_states"),
        &keys,
        errors,
    );
    for state in states {
        validate_drawing_version(
            &state.drawing_version,
            &format!("profile '{profile_id}' default unit state"),
            errors,
        );
    }
}

fn validate_profile_ids<'a>(
    label: &str,
    profile_ids: impl Iterator<Item = &'a str>,
    errors: &mut Vec<String>,
) {
    let profile_ids: Vec<&str> = profile_ids.collect();
    if profile_ids.is_empty() {
        errors.push(format!("{label} artifact has no profiles"));
    }
    validate_sorted_unique_keys(label, &profile_ids, errors);
    for profile_id in profile_ids {
        validate_id(profile_id, &format!("{label} profile_id"), errors);
    }
}

fn validate_schema_version(file_name: &str, version: u32, expected: u32, errors: &mut Vec<String>) {
    if version != expected {
        errors.push(format!(
            "{file_name} schema_version {version} is unsupported; expected {expected}"
        ));
    }
}

fn validate_tolerances(
    profile_id: &str,
    absolute_tolerance: f64,
    relative_tolerance: f64,
    errors: &mut Vec<String>,
) {
    for (name, tolerance) in [
        ("absolute_tolerance", absolute_tolerance),
        ("relative_tolerance", relative_tolerance),
    ] {
        if !tolerance.is_finite() || tolerance < 0.0 {
            errors.push(format!(
                "profile '{profile_id}' {name} must be finite and non-negative"
            ));
        }
    }
}

fn validate_field_list(label: &str, fields: &[String], errors: &mut Vec<String>) {
    if fields.is_empty() {
        errors.push(format!("{label} must not be empty"));
    }
    let field_names: Vec<&str> = fields.iter().map(String::as_str).collect();
    validate_sorted_unique_keys(label, &field_names, errors);
    for field in fields {
        validate_field_name(field, label, errors);
    }
}

fn validate_sorted_unique_keys<T>(label: &str, values: &[T], errors: &mut Vec<String>)
where
    T: Ord,
{
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        errors.push(format!("{label} must be sorted and unique"));
    }
}

fn validate_id(value: &str, label: &str, errors: &mut Vec<String>) {
    validate_token(value, label, errors);
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || value.starts_with('-')
        || value.ends_with('-')
    {
        errors.push(format!(
            "{label} must contain only lowercase ASCII letters, digits, and interior hyphens"
        ));
    }
}

fn validate_certified_arg_policy_id(value: &str, label: &str, errors: &mut Vec<String>) {
    if let Err(error) = crate::certified_arg::validate_policy_id(value) {
        errors.push(format!("{label}: {error}"));
    }
}

fn validate_field_name(value: &str, label: &str, errors: &mut Vec<String>) {
    validate_token(value, label, errors);
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        || value.starts_with('_')
        || value.ends_with('_')
    {
        errors.push(format!("{label} contains non-canonical field '{value}'"));
    }
}

fn validate_token(value: &str, label: &str, errors: &mut Vec<String>) {
    if value.is_empty() || value.trim() != value {
        errors.push(format!("{label} must be a non-empty trimmed string"));
    }
    if value.contains('*')
        || value.contains('?')
        || value.eq_ignore_ascii_case("any")
        || value.eq_ignore_ascii_case("all")
    {
        errors.push(format!(
            "{label} must not contain a wildcard value '{value}'"
        ));
    }
}

fn validate_drawing_version(value: &str, location: &str, errors: &mut Vec<String>) {
    validate_token(value, &format!("{location} drawing_version"), errors);
    let is_canonical = value.len() == 6
        && value.starts_with("AC")
        && value[2..].bytes().all(|byte| byte.is_ascii_digit());
    if !is_canonical {
        errors.push(format!(
            "{location} drawing_version '{value}' must be an exact canonical ACxxxx value"
        ));
    }
}

fn validate_code_page(value: &str, location: &str, errors: &mut Vec<String>) {
    validate_token(value, &format!("{location} code_page"), errors);
    let is_canonical = !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
        && value.bytes().any(|byte| byte.is_ascii_uppercase());
    if !is_canonical {
        errors.push(format!(
            "{location} ASCII DXF code_page '{value}' must be canonical uppercase ASCII"
        ));
    }
}

fn finish_xref_validation(errors: Vec<String>) -> Result<()> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(errors.join("; ")))
    }
}

pub const XREF_CERTIFICATION_SCHEMA_VERSION: u32 = 4;
pub const XREF_WINDOWS_EVIDENCE_FILE: &str = "xref-windows-certification-evidence.json";
pub const XREF_TRANSACTION_EVIDENCE_FILE: &str = "xref-transaction-certification-evidence.json";
pub const XREF_CERTIFICATION_ATTESTATION_FILE: &str = "xref-certification-attestation.json";

fn deserialize_required_nullable_certification<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefCertificationEvidenceClass {
    ReleaseConformance,
    InstrumentedTransaction,
}

impl XrefCertificationEvidenceClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseConformance => "release_conformance",
            Self::InstrumentedTransaction => "instrumented_transaction",
        }
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefCertificationExpectedStatus {
    Passed,
    Failed,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefCertificationResultStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefCertificationScenario {
    OperationSuccess,
    ProfileIsolation,
    Clips,
    LockedResources,
    Guards,
    SourceRace,
    HostRace,
    BindStrategies,
    TransactionFailpoint,
}

pub const XREF_REQUIRED_CERTIFICATION_SCENARIOS: [XrefCertificationScenario; 9] = [
    XrefCertificationScenario::OperationSuccess,
    XrefCertificationScenario::ProfileIsolation,
    XrefCertificationScenario::Clips,
    XrefCertificationScenario::LockedResources,
    XrefCertificationScenario::Guards,
    XrefCertificationScenario::SourceRace,
    XrefCertificationScenario::HostRace,
    XrefCertificationScenario::BindStrategies,
    XrefCertificationScenario::TransactionFailpoint,
];

impl XrefCertificationScenario {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OperationSuccess => "operation_success",
            Self::ProfileIsolation => "profile_isolation",
            Self::Clips => "clips",
            Self::LockedResources => "locked_resources",
            Self::Guards => "guards",
            Self::SourceRace => "source_race",
            Self::HostRace => "host_race",
            Self::BindStrategies => "bind_strategies",
            Self::TransactionFailpoint => "transaction_failpoint",
        }
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefCertificationFailureStage {
    FixtureStaging,
    ScenarioSetup,
    Execution,
    Verification,
    HarnessCleanup,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefCertificationFailpoint {
    DuringSourceSnapshot,
    BeforeSave,
    AfterSave,
    BeforeVerification,
    AfterVerification,
    BeforeCleanup,
    AfterCleanup,
    BeforeHostRecheck,
    AfterHostRecheck,
    BeforeReplace,
    AfterReplace,
    BeforeDirectoryFlush,
    AfterDirectoryFlush,
    BeforeInstalledDigestCheck,
}

pub const XREF_MANDATORY_CERTIFICATION_FAILPOINTS: [XrefCertificationFailpoint; 14] = [
    XrefCertificationFailpoint::DuringSourceSnapshot,
    XrefCertificationFailpoint::BeforeSave,
    XrefCertificationFailpoint::AfterSave,
    XrefCertificationFailpoint::BeforeVerification,
    XrefCertificationFailpoint::AfterVerification,
    XrefCertificationFailpoint::BeforeCleanup,
    XrefCertificationFailpoint::AfterCleanup,
    XrefCertificationFailpoint::BeforeHostRecheck,
    XrefCertificationFailpoint::AfterHostRecheck,
    XrefCertificationFailpoint::BeforeReplace,
    XrefCertificationFailpoint::AfterReplace,
    XrefCertificationFailpoint::BeforeDirectoryFlush,
    XrefCertificationFailpoint::AfterDirectoryFlush,
    XrefCertificationFailpoint::BeforeInstalledDigestCheck,
];

impl XrefCertificationFailpoint {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DuringSourceSnapshot => "during_source_snapshot",
            Self::BeforeSave => "before_save",
            Self::AfterSave => "after_save",
            Self::BeforeVerification => "before_verification",
            Self::AfterVerification => "after_verification",
            Self::BeforeCleanup => "before_cleanup",
            Self::AfterCleanup => "after_cleanup",
            Self::BeforeHostRecheck => "before_host_recheck",
            Self::AfterHostRecheck => "after_host_recheck",
            Self::BeforeReplace => "before_replace",
            Self::AfterReplace => "after_replace",
            Self::BeforeDirectoryFlush => "before_directory_flush",
            Self::AfterDirectoryFlush => "after_directory_flush",
            Self::BeforeInstalledDigestCheck => "before_installed_digest_check",
        }
    }

    pub const fn expected_error_code(self) -> &'static str {
        match self {
            Self::DuringSourceSnapshot => "xref_source_changed",
            Self::BeforeVerification | Self::AfterVerification => "verification_failed",
            Self::AfterReplace
            | Self::BeforeDirectoryFlush
            | Self::AfterDirectoryFlush
            | Self::BeforeInstalledDigestCheck => "mutation_state_unknown",
            Self::BeforeSave
            | Self::AfterSave
            | Self::BeforeCleanup
            | Self::AfterCleanup
            | Self::BeforeHostRecheck
            | Self::AfterHostRecheck
            | Self::BeforeReplace => "write_failed",
        }
    }

    pub const fn may_cross_replacement(self) -> bool {
        matches!(
            self,
            Self::AfterReplace
                | Self::BeforeDirectoryFlush
                | Self::AfterDirectoryFlush
                | Self::BeforeInstalledDigestCheck
        )
    }
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefProfileArtifactSha256 {
    pub preservation_verifier_profiles: String,
    pub bind_verifier_profiles: String,
    pub clip_verifier_profiles: String,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefEmbeddedArtifactSha256 {
    pub mutation_capabilities: String,
    pub preservation_verifier_profiles: String,
    pub bind_verifier_profiles: String,
    pub clip_verifier_profiles: String,
}

impl XrefEmbeddedArtifactSha256 {
    pub fn profile_sha256(&self) -> XrefProfileArtifactSha256 {
        XrefProfileArtifactSha256 {
            preservation_verifier_profiles: self.preservation_verifier_profiles.clone(),
            bind_verifier_profiles: self.bind_verifier_profiles.clone(),
            clip_verifier_profiles: self.clip_verifier_profiles.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefCertificationManifest {
    pub schema_version: u32,
    pub release_id: String,
    pub activation_target: CertificationActivationTarget,
    pub fixture_root: String,
    pub certified_arg_path: String,
    pub certified_arg_sha256: String,
    pub certified_arg_policy_id: String,
    pub certified_arg_policy_sha256: String,
    pub release_binary_path: String,
    pub release_binary_sha256: String,
    pub instrumented_binary_path: String,
    pub instrumented_binary_sha256: String,
    pub accoreconsole_path: String,
    pub accoreconsole_sha256: String,
    pub autocad_product: String,
    pub autocad_version: String,
    pub matrix_sha256: String,
    pub profile_sha256: XrefProfileArtifactSha256,
    pub release_cases: Vec<XrefCertificationCase>,
    pub instrumented_cases: Vec<XrefCertificationCase>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefCertificationCase {
    pub case_id: String,
    pub row_id: String,
    pub scenario: XrefCertificationScenario,
    pub operation: XrefMutationOperation,
    pub drawing_path: String,
    pub source_fixture_paths: Vec<String>,
    pub params: serde_json::Map<String, serde_json::Value>,
    pub expected_status: XrefCertificationExpectedStatus,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub expected_error_code: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub failpoint: Option<XrefCertificationFailpoint>,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefCertificationFormatFacts {
    pub host_format: XrefHostFormat,
    pub drawing_version: String,
    pub dxf_form: XrefDxfForm,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub code_page: Option<String>,
}

impl XrefCertificationFormatFacts {
    pub fn from_capability(row: &XrefMutationCapabilityRow) -> Self {
        Self {
            host_format: row.host_format,
            drawing_version: row.drawing_version.clone(),
            dxf_form: row.dxf_form,
            code_page: row.code_page.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefArtifactCleanupEvidence {
    pub inventory_roots: Vec<String>,
    pub observation_polls: u64,
    pub attempted: Vec<String>,
    pub removed: Vec<String>,
    pub remaining: Vec<String>,
    pub process_ids_before: Vec<u32>,
    pub process_ids_observed: Vec<u32>,
    pub process_ids_remaining: Vec<u32>,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub engine_stop_error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefCertificationBuildIdentity {
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub cargo_lock_sha256: String,
    pub certified_arg_sha256: String,
    pub certified_arg_policy_id: String,
    pub certified_arg_policy_sha256: String,
    pub compiler: String,
    pub target: String,
    pub profile: String,
    pub optimization: String,
    pub build_id: String,
    pub shared_operation_source_sha256: String,
    pub certification_failpoints_enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefCertificationProfileReference {
    pub row_id: String,
    pub preservation_verifier_profile_id: String,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub bind_verifier_profile_id: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub clip_verifier_profile_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefCertificationCaseResult {
    pub case_id: String,
    pub row_id: String,
    pub operation: XrefMutationOperation,
    pub status: XrefCertificationResultStatus,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub error_code: Option<String>,
    pub input_format: XrefCertificationFormatFacts,
    pub output_format: XrefCertificationFormatFacts,
    pub original_digest_before: String,
    pub original_digest_after: String,
    pub artifact_cleanup: XrefArtifactCleanupEvidence,
    pub profile_isolation: Vec<CertificationProfileIsolationEvidence>,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefCertificationCaseFailure {
    pub case_id: String,
    pub row_id: String,
    pub scenario: XrefCertificationScenario,
    pub operation: XrefMutationOperation,
    pub stage: XrefCertificationFailureStage,
    pub detail: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefCertificationEvidence {
    pub schema_version: u32,
    pub evidence_class: XrefCertificationEvidenceClass,
    pub release_id: String,
    pub activation_target: CertificationActivationTarget,
    pub status: XrefCertificationResultStatus,
    pub manifest_sha256: String,
    pub binary_sha256: String,
    pub binary_path: String,
    pub binary_canonical_path: String,
    pub binary_sha256_before: String,
    pub binary_sha256_after: String,
    pub certified_arg_path: String,
    pub certified_arg_canonical_path: String,
    pub certified_arg_sha256_before: String,
    pub certified_arg_sha256_after: String,
    pub binary_reported_certified_arg_sha256: String,
    pub certified_arg_policy_id: String,
    pub certified_arg_policy_sha256: String,
    pub artifact_sha256: XrefEmbeddedArtifactSha256,
    pub build_identity: XrefCertificationBuildIdentity,
    pub accoreconsole_path: String,
    pub accoreconsole_canonical_path: String,
    pub accoreconsole_sha256_before: String,
    pub accoreconsole_sha256_after: String,
    pub observed_autocad_product: String,
    pub observed_autocad_version: String,
    pub profile_references: Vec<XrefCertificationProfileReference>,
    pub case_results: Vec<XrefCertificationCaseResult>,
    pub case_failures: Vec<XrefCertificationCaseFailure>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefCertificationAttestation {
    pub schema_version: u32,
    pub release_id: String,
    pub activation_target: CertificationActivationTarget,
    pub manifest_sha256: String,
    pub release_binary_sha256: String,
    pub instrumented_binary_sha256: String,
    pub certified_arg_sha256: String,
    pub certified_arg_policy_id: String,
    pub certified_arg_policy_sha256: String,
    pub artifact_sha256: XrefEmbeddedArtifactSha256,
    pub release_build_identity: XrefCertificationBuildIdentity,
    pub instrumented_build_identity: XrefCertificationBuildIdentity,
    pub shared_operation_source_sha256: String,
}

impl XrefCertificationManifest {
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|error| anyhow::anyhow!("invalid XREF certification manifest: {error}"))
    }
}

impl XrefCertificationEvidence {
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|error| anyhow::anyhow!("invalid XREF certification evidence: {error}"))
    }
}

impl XrefCertificationAttestation {
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|error| anyhow::anyhow!("invalid XREF certification attestation: {error}"))
    }
}

pub fn xref_sha256_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn xref_sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|error| {
        anyhow::anyhow!("failed to open {} for SHA-256: {error}", path.display())
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| anyhow::anyhow!("failed to hash {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn xref_embedded_artifact_sha256() -> XrefEmbeddedArtifactSha256 {
    XrefEmbeddedArtifactSha256 {
        mutation_capabilities: xref_sha256_bytes(XREF_MUTATION_CAPABILITIES_BYTES),
        preservation_verifier_profiles: xref_sha256_bytes(
            XREF_PRESERVATION_VERIFIER_PROFILES_BYTES,
        ),
        bind_verifier_profiles: xref_sha256_bytes(XREF_BIND_VERIFIER_PROFILES_BYTES),
        clip_verifier_profiles: xref_sha256_bytes(XREF_CLIP_VERIFIER_PROFILES_BYTES),
    }
}

pub fn xref_certification_build_identity() -> XrefCertificationBuildIdentity {
    XrefCertificationBuildIdentity {
        source_commit: env!("AUTOCAD_MCP_BUILD_SOURCE_COMMIT").to_string(),
        source_tree_sha256: env!("AUTOCAD_MCP_BUILD_SOURCE_TREE_SHA256").to_string(),
        cargo_lock_sha256: env!("AUTOCAD_MCP_BUILD_CARGO_LOCK_SHA256").to_string(),
        certified_arg_sha256: env!("AUTOCAD_MCP_BUILD_CERTIFIED_ARG_SHA256").to_string(),
        certified_arg_policy_id: env!("AUTOCAD_MCP_BUILD_CERTIFIED_ARG_POLICY_ID").to_string(),
        certified_arg_policy_sha256: env!("AUTOCAD_MCP_BUILD_CERTIFIED_ARG_POLICY_SHA256")
            .to_string(),
        compiler: env!("AUTOCAD_MCP_BUILD_COMPILER").to_string(),
        target: env!("AUTOCAD_MCP_BUILD_TARGET").to_string(),
        profile: env!("AUTOCAD_MCP_BUILD_PROFILE").to_string(),
        optimization: env!("AUTOCAD_MCP_BUILD_OPT_LEVEL").to_string(),
        build_id: env!("AUTOCAD_MCP_BUILD_ID").to_string(),
        shared_operation_source_sha256: env!("AUTOCAD_MCP_BUILD_SHARED_OPERATION_SOURCE_SHA256")
            .to_string(),
        certification_failpoints_enabled: cfg!(feature = "xref-certification-failpoints"),
    }
}

pub fn xref_certification_crt_linkage() -> &'static str {
    env!("AUTOCAD_MCP_BUILD_CRT_LINKAGE")
}

pub fn xref_certification_manifest_sha256(manifest: &XrefCertificationManifest) -> String {
    let bytes = serde_json::to_vec(manifest).expect("XREF certification manifest serializes");
    xref_sha256_bytes(&bytes)
}

pub fn xref_certification_profile_references(
    registry: &XrefArtifactRegistry,
) -> Vec<XrefCertificationProfileReference> {
    registry
        .capabilities()
        .rows
        .iter()
        .map(|row| XrefCertificationProfileReference {
            row_id: row.row_id.clone(),
            preservation_verifier_profile_id: row.preservation_verifier_profile_id.clone(),
            bind_verifier_profile_id: row.bind_verifier_profile_id.clone(),
            clip_verifier_profile_id: row.clip_verifier_profile_id.clone(),
        })
        .collect()
}

pub fn inspect_xref_certification_format(path: &Path) -> Result<XrefCertificationFormatFacts> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| anyhow::anyhow!("drawing has no UTF-8 extension: {}", path.display()))?;
    match extension.as_str() {
        "dwg" => {
            let mut file = File::open(path)
                .map_err(|error| anyhow::anyhow!("failed to open {}: {error}", path.display()))?;
            let mut version = [0_u8; 6];
            file.read_exact(&mut version).map_err(|error| {
                anyhow::anyhow!(
                    "failed to read DWG version from {}: {error}",
                    path.display()
                )
            })?;
            let drawing_version = std::str::from_utf8(&version)
                .map_err(|error| anyhow::anyhow!("DWG version is not ASCII: {error}"))?
                .to_string();
            let mut errors = Vec::new();
            validate_drawing_version(&drawing_version, "certification drawing", &mut errors);
            finish_xref_validation(errors)?;
            Ok(XrefCertificationFormatFacts {
                host_format: XrefHostFormat::Dwg,
                drawing_version,
                dxf_form: XrefDxfForm::NotApplicable,
                code_page: None,
            })
        }
        "dxf" => {
            const BINARY_DXF_SENTINEL: &[u8] = b"AutoCAD Binary DXF\r\n\x1a\0";
            let bytes = std::fs::read(path)
                .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?;
            let dxf_form = if bytes.starts_with(BINARY_DXF_SENTINEL) {
                XrefDxfForm::Binary
            } else {
                XrefDxfForm::Ascii
            };
            let facts = Reader::open_snapshot(DrawingSnapshot::new(DrawingFormat::Dxf, bytes))
                .map_err(map_format_facts_snapshot_open_error)
                .and_then(|session| session.format_facts())
                .map_err(|error| {
                    anyhow::anyhow!(
                        "failed to parse DXF format facts from {}: {error}",
                        path.display()
                    )
                })?;
            let code_page = match dxf_form {
                XrefDxfForm::Ascii => Some(facts.code_page),
                XrefDxfForm::Binary => None,
                XrefDxfForm::NotApplicable => unreachable!(),
            };
            Ok(XrefCertificationFormatFacts {
                host_format: XrefHostFormat::Dxf,
                drawing_version: facts.drawing_version,
                dxf_form,
                code_page,
            })
        }
        _ => Err(anyhow::anyhow!(
            "unsupported certification drawing extension '{}': {}",
            extension,
            path.display()
        )),
    }
}

pub fn validate_xref_certification_manifest(manifest: &XrefCertificationManifest) -> Result<()> {
    let registry = embedded_xref_artifacts()?;
    validate_xref_certification_manifest_with_registry(manifest, registry)
}

pub fn validate_xref_certification_manifest_with_registry(
    manifest: &XrefCertificationManifest,
    registry: &XrefArtifactRegistry,
) -> Result<()> {
    let mut errors = Vec::new();
    if manifest.schema_version != XREF_CERTIFICATION_SCHEMA_VERSION {
        errors.push(format!(
            "XREF certification manifest schema_version {} is unsupported; expected {}",
            manifest.schema_version, XREF_CERTIFICATION_SCHEMA_VERSION
        ));
    }
    validate_id(
        &manifest.release_id,
        "XREF certification release_id",
        &mut errors,
    );
    let fixture_root = if manifest.fixture_root.trim().is_empty()
        || manifest.fixture_root != manifest.fixture_root.trim()
    {
        errors.push("XREF certification fixture_root must be non-empty and trimmed".to_string());
        None
    } else {
        match CanonicalDisplayPath::from_filesystem_canonical_path(&manifest.fixture_root) {
            Ok(path) => Some(path),
            Err(error) => {
                errors.push(format!(
                    "XREF certification fixture_root must be an absolute canonical local path: {error}"
                ));
                None
            }
        }
    };
    validate_absolute_certification_file_path(
        &manifest.certified_arg_path,
        "XREF certification certified_arg_path",
        &mut errors,
    );
    validate_xref_digest(
        "XREF certification certified_arg_sha256",
        &manifest.certified_arg_sha256,
        &mut errors,
    );
    validate_certified_arg_policy_id(
        &manifest.certified_arg_policy_id,
        "XREF certification certified_arg_policy_id",
        &mut errors,
    );
    validate_xref_digest(
        "XREF certification certified_arg_policy_sha256",
        &manifest.certified_arg_policy_sha256,
        &mut errors,
    );
    for (label, path) in [
        ("release_binary_path", manifest.release_binary_path.as_str()),
        (
            "instrumented_binary_path",
            manifest.instrumented_binary_path.as_str(),
        ),
    ] {
        if path.trim().is_empty() || path != path.trim() {
            errors.push(format!(
                "XREF certification {label} must be non-empty and trimmed"
            ));
        }
        validate_absolute_certification_file_path(
            path,
            &format!("XREF certification {label}"),
            &mut errors,
        );
    }
    if manifest.release_binary_path == manifest.instrumented_binary_path {
        errors.push("release and instrumented binary paths must differ".to_string());
    }
    validate_xref_digest(
        "XREF certification release_binary_sha256",
        &manifest.release_binary_sha256,
        &mut errors,
    );
    validate_xref_digest(
        "XREF certification instrumented_binary_sha256",
        &manifest.instrumented_binary_sha256,
        &mut errors,
    );
    if manifest.release_binary_sha256 == manifest.instrumented_binary_sha256 {
        errors.push("release and instrumented binary SHA-256 values must differ".to_string());
    }
    validate_absolute_certification_file_path(
        &manifest.accoreconsole_path,
        "XREF certification accoreconsole_path",
        &mut errors,
    );
    validate_xref_digest(
        "XREF certification accoreconsole_sha256",
        &manifest.accoreconsole_sha256,
        &mut errors,
    );
    validate_nonempty_trimmed(
        &manifest.autocad_product,
        "XREF certification autocad_product",
        &mut errors,
    );
    validate_nonempty_trimmed(
        &manifest.autocad_version,
        "XREF certification autocad_version",
        &mut errors,
    );
    validate_certification_activation_target(
        &manifest.activation_target,
        CertificationActivationClaim {
            autocad_product: &manifest.autocad_product,
            autocad_version: &manifest.autocad_version,
            certified_arg_sha256: &manifest.certified_arg_sha256,
            certified_arg_policy_id: &manifest.certified_arg_policy_id,
            certified_arg_policy_sha256: &manifest.certified_arg_policy_sha256,
        },
        &[MutationCapability::XrefMutation],
        "XREF certification activation_target",
        &mut errors,
    );
    if !certification_path_has_autocad_engine_shape(
        &manifest.accoreconsole_path,
        &manifest.autocad_version,
    ) {
        errors.push(
            "XREF certification accoreconsole_path must identify accoreconsole.exe under an AutoCAD-labelled path component declaring the expected version"
                .to_string(),
        );
    }
    let expected_artifacts = xref_embedded_artifact_sha256();
    if manifest.matrix_sha256 != expected_artifacts.mutation_capabilities {
        errors.push("manifest matrix_sha256 does not match exact embedded bytes".to_string());
    }
    if manifest.profile_sha256 != expected_artifacts.profile_sha256() {
        errors.push(
            "manifest profile_sha256 does not match exact embedded profile bytes".to_string(),
        );
    }
    validate_xref_digest(
        "manifest matrix_sha256",
        &manifest.matrix_sha256,
        &mut errors,
    );
    validate_xref_profile_digests(&manifest.profile_sha256, &mut errors);

    validate_xref_manifest_cases(
        XrefCertificationEvidenceClass::ReleaseConformance,
        &manifest.release_cases,
        fixture_root.as_ref(),
        registry,
        &mut errors,
    );
    validate_xref_manifest_cases(
        XrefCertificationEvidenceClass::InstrumentedTransaction,
        &manifest.instrumented_cases,
        fixture_root.as_ref(),
        registry,
        &mut errors,
    );

    for row in &registry.capabilities().rows {
        let actual: BTreeSet<_> = manifest
            .release_cases
            .iter()
            .filter(|case| {
                case.row_id == row.row_id
                    && case.expected_status == XrefCertificationExpectedStatus::Passed
            })
            .map(|case| case.operation)
            .collect();
        let required: BTreeSet<_> = row.operations.iter().copied().collect();
        if actual != required {
            errors.push(format!(
                "successful release cases for row '{}' must cover exactly its nine operations",
                row.row_id
            ));
        }
    }

    let failpoints: BTreeSet<_> = manifest
        .instrumented_cases
        .iter()
        .filter_map(|case| case.failpoint)
        .collect();
    let required_failpoints: BTreeSet<_> = XREF_MANDATORY_CERTIFICATION_FAILPOINTS
        .into_iter()
        .collect();
    if failpoints != required_failpoints {
        errors.push(
            "instrumented cases must cover every mandatory transaction failpoint".to_string(),
        );
    }
    validate_xref_scenario_coverage(manifest, registry, &mut errors);

    finish_xref_validation(errors)
}

fn validate_xref_manifest_cases(
    evidence_class: XrefCertificationEvidenceClass,
    cases: &[XrefCertificationCase],
    fixture_root: Option<&CanonicalDisplayPath>,
    registry: &XrefArtifactRegistry,
    errors: &mut Vec<String>,
) {
    if cases.is_empty() {
        errors.push(format!(
            "{} manifest cases must not be empty",
            evidence_class.as_str()
        ));
        return;
    }
    let keys: Vec<_> = cases
        .iter()
        .map(|case| (case.row_id.as_str(), case.case_id.as_str()))
        .collect();
    validate_sorted_unique_keys(
        &format!("{} cases by row_id/case_id", evidence_class.as_str()),
        &keys,
        errors,
    );

    for case in cases {
        let location = format!(
            "{} case '{}:{}'",
            evidence_class.as_str(),
            case.row_id,
            case.case_id
        );
        validate_id(&case.case_id, &format!("{location} case_id"), errors);
        if case.drawing_path.trim().is_empty() || case.drawing_path != case.drawing_path.trim() {
            errors.push(format!(
                "{location} drawing_path must be non-empty and trimmed"
            ));
        }
        if let Some(fixture_root) = fixture_root {
            match CanonicalDisplayPath::from_filesystem_canonical_path(&case.drawing_path) {
                Ok(drawing) if xref_certification_path_is_below(fixture_root, &drawing) => {}
                Ok(_) => errors.push(format!(
                    "{location} drawing_path must be below fixture_root"
                )),
                Err(error) => errors.push(format!(
                    "{location} drawing_path must be an absolute canonical local path: {error}"
                )),
            }
        }
        let source_paths: Vec<_> = case
            .source_fixture_paths
            .iter()
            .map(String::as_str)
            .collect();
        validate_sorted_unique_keys(
            &format!("{location} source_fixture_paths"),
            &source_paths,
            errors,
        );
        if case.source_fixture_paths.is_empty() {
            errors.push(format!(
                "{location} source_fixture_paths must declare the complete source fixture set"
            ));
        }
        for path in &case.source_fixture_paths {
            validate_xref_relative_fixture_path(path, &location, errors);
        }
        if case
            .params
            .get("drawing_path")
            .and_then(serde_json::Value::as_str)
            != Some(case.drawing_path.as_str())
        {
            errors.push(format!(
                "{location} params drawing_path must exactly match the case drawing_path"
            ));
        }
        let Some(row) = registry
            .capabilities()
            .rows
            .iter()
            .find(|row| row.row_id == case.row_id)
        else {
            errors.push(format!("{location} references unknown capability row"));
            continue;
        };
        if !row.operations.contains(&case.operation) {
            errors.push(format!(
                "{location} operation '{}' is not admitted by its capability row",
                case.operation.as_str()
            ));
        }
        if registry
            .preservation_profile(&row.preservation_verifier_profile_id)
            .is_none()
        {
            errors.push(format!("{location} has an unresolved preservation profile"));
        }
        if case.operation == XrefMutationOperation::BindXref
            && row
                .bind_verifier_profile_id
                .as_deref()
                .and_then(|profile_id| registry.bind_profile(profile_id))
                .is_none()
        {
            errors.push(format!("{location} has an unresolved bind profile"));
        }
        if let Some(profile_id) = row.clip_verifier_profile_id.as_deref() {
            if registry.clip_profile(profile_id).is_none() {
                errors.push(format!("{location} has an unresolved clip profile"));
            }
        }

        match case.expected_status {
            XrefCertificationExpectedStatus::Passed if case.expected_error_code.is_some() => {
                errors.push(format!(
                    "{location} expected_status=passed requires expected_error_code=null"
                ));
            }
            XrefCertificationExpectedStatus::Failed if case.expected_error_code.is_none() => {
                errors.push(format!(
                    "{location} expected_status=failed requires expected_error_code"
                ));
            }
            _ => {}
        }

        match evidence_class {
            XrefCertificationEvidenceClass::ReleaseConformance => {
                if case.failpoint.is_some() {
                    errors.push(format!("{location} release case requires failpoint=null"));
                }
                if case.scenario == XrefCertificationScenario::TransactionFailpoint {
                    errors.push(format!(
                        "{location} release case cannot use scenario=transaction_failpoint"
                    ));
                }
            }
            XrefCertificationEvidenceClass::InstrumentedTransaction => {
                if case.scenario != XrefCertificationScenario::TransactionFailpoint {
                    errors.push(format!(
                        "{location} instrumented case requires scenario=transaction_failpoint"
                    ));
                }
                let Some(failpoint) = case.failpoint else {
                    errors.push(format!("{location} instrumented case requires failpoint"));
                    continue;
                };
                if case.expected_status != XrefCertificationExpectedStatus::Failed {
                    errors.push(format!(
                        "{location} instrumented failpoint case must expect failure"
                    ));
                }
                if case.expected_error_code.as_deref() != Some(failpoint.expected_error_code()) {
                    errors.push(format!(
                        "{location} failpoint '{}' requires expected_error_code='{}'",
                        failpoint.as_str(),
                        failpoint.expected_error_code()
                    ));
                }
            }
        }
        validate_xref_case_scenario(case, evidence_class, &location, errors);

        if evidence_class == XrefCertificationEvidenceClass::InstrumentedTransaction
            || case.expected_status == XrefCertificationExpectedStatus::Passed
        {
            if let Err(error) = validate_xref_certification_case_params(case) {
                errors.push(format!("{location} has invalid executable params: {error}"));
            }
        }
    }
}

fn xref_certification_path_is_below(
    root: &CanonicalDisplayPath,
    path: &CanonicalDisplayPath,
) -> bool {
    let root = root.as_str().trim_end_matches('/');
    path.as_str()
        .strip_prefix(root)
        .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1)
}

fn validate_xref_relative_fixture_path(path: &str, location: &str, errors: &mut Vec<String>) {
    let valid = !path.is_empty()
        && path == path.trim()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains(':')
        && path
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."));
    if !valid {
        errors.push(format!(
            "{location} source fixture path '{path}' must be a normalized relative path using forward slashes"
        ));
    }
}

fn validate_xref_case_scenario(
    case: &XrefCertificationCase,
    evidence_class: XrefCertificationEvidenceClass,
    location: &str,
    errors: &mut Vec<String>,
) {
    let passed = case.expected_status == XrefCertificationExpectedStatus::Passed;
    let expected_error = case.expected_error_code.as_deref();
    match case.scenario {
        XrefCertificationScenario::OperationSuccess
        | XrefCertificationScenario::ProfileIsolation => {
            if evidence_class != XrefCertificationEvidenceClass::ReleaseConformance || !passed {
                errors.push(format!(
                    "{location} scenario={} requires a successful release case",
                    case.scenario.as_str()
                ));
            }
        }
        XrefCertificationScenario::Clips => {
            let admitted_operation = matches!(
                case.operation,
                XrefMutationOperation::UpdateXref
                    | XrefMutationOperation::DetachXref
                    | XrefMutationOperation::UpdateXrefInstance
                    | XrefMutationOperation::DeleteXrefInstance
                    | XrefMutationOperation::ReloadXref
                    | XrefMutationOperation::UnloadXref
                    | XrefMutationOperation::BindXref
            );
            if evidence_class != XrefCertificationEvidenceClass::ReleaseConformance
                || !admitted_operation
                || (!passed && expected_error != Some("unsupported_xref_clip_data"))
            {
                errors.push(format!(
                    "{location} scenario=clips requires an executable clip-sensitive release outcome"
                ));
            }
        }
        XrefCertificationScenario::LockedResources => {
            if evidence_class != XrefCertificationEvidenceClass::ReleaseConformance
                || passed
                || expected_error != Some("xref_instance_locked")
            {
                errors.push(format!(
                    "{location} scenario=locked_resources requires xref_instance_locked from the release binary"
                ));
            }
        }
        XrefCertificationScenario::Guards => {
            const GUARD_ERRORS: [&str; 6] = [
                "expected_handle_mismatch",
                "expected_name_mismatch",
                "expected_instance_count_mismatch",
                "expected_instance_handles_mismatch",
                "expected_attachment_handle_mismatch",
                "expected_owner_handle_mismatch",
            ];
            let has_guard = case.params.keys().any(|key| key.starts_with("expected_"));
            if evidence_class != XrefCertificationEvidenceClass::ReleaseConformance
                || !has_guard
                || (!passed && !expected_error.is_some_and(|code| GUARD_ERRORS.contains(&code)))
            {
                errors.push(format!(
                    "{location} scenario=guards requires matching or mismatching executable guard parameters"
                ));
            }
        }
        XrefCertificationScenario::SourceRace => {
            if evidence_class != XrefCertificationEvidenceClass::ReleaseConformance
                || passed
                || expected_error != Some("xref_source_changed")
            {
                errors.push(format!(
                    "{location} scenario=source_race requires xref_source_changed from the release binary"
                ));
            }
        }
        XrefCertificationScenario::HostRace => {
            if evidence_class != XrefCertificationEvidenceClass::ReleaseConformance
                || passed
                || expected_error != Some("concurrent_drawing_modification")
            {
                errors.push(format!(
                    "{location} scenario=host_race requires concurrent_drawing_modification from the release binary"
                ));
            }
        }
        XrefCertificationScenario::BindStrategies => {
            if evidence_class != XrefCertificationEvidenceClass::ReleaseConformance
                || !passed
                || case.operation != XrefMutationOperation::BindXref
            {
                errors.push(format!(
                    "{location} scenario=bind_strategies requires a successful bind_xref release case"
                ));
            }
        }
        XrefCertificationScenario::TransactionFailpoint => {
            if evidence_class != XrefCertificationEvidenceClass::InstrumentedTransaction {
                errors.push(format!(
                    "{location} scenario=transaction_failpoint requires the instrumented binary"
                ));
            }
        }
    }
}

fn validate_xref_scenario_coverage(
    manifest: &XrefCertificationManifest,
    registry: &XrefArtifactRegistry,
    errors: &mut Vec<String>,
) {
    let all_cases = manifest
        .release_cases
        .iter()
        .chain(&manifest.instrumented_cases);
    let actual: BTreeSet<_> = all_cases.clone().map(|case| case.scenario).collect();
    let required: BTreeSet<_> = XREF_REQUIRED_CERTIFICATION_SCENARIOS.into_iter().collect();
    if actual != required {
        let missing = required
            .difference(&actual)
            .map(|scenario| scenario.as_str())
            .collect::<Vec<_>>();
        errors.push(format!(
            "strict XREF certification scenario coverage is incomplete; missing={missing:?}"
        ));
    }

    for row in &registry.capabilities().rows {
        if !manifest.release_cases.iter().any(|case| {
            case.row_id == row.row_id
                && case.scenario == XrefCertificationScenario::ProfileIsolation
                && case.expected_status == XrefCertificationExpectedStatus::Passed
        }) {
            errors.push(format!(
                "capability row '{}' requires a successful profile_isolation scenario",
                row.row_id
            ));
        }
    }

    let guard_cases: Vec<_> = manifest
        .release_cases
        .iter()
        .filter(|case| case.scenario == XrefCertificationScenario::Guards)
        .collect();
    if !guard_cases
        .iter()
        .any(|case| case.expected_status == XrefCertificationExpectedStatus::Passed)
        || !guard_cases
            .iter()
            .any(|case| case.expected_status == XrefCertificationExpectedStatus::Failed)
    {
        errors.push("scenario=guards requires both matching and mismatching outcomes".to_string());
    }

    let bind_strategies: BTreeSet<_> = manifest
        .release_cases
        .iter()
        .filter(|case| case.scenario == XrefCertificationScenario::BindStrategies)
        .filter_map(|case| {
            Some((
                case.params.get("symbol_strategy")?.as_str()?,
                case.params.get("dependency_strategy")?.as_str()?,
            ))
        })
        .collect();
    let required_bind_strategies = BTreeSet::from([
        ("merge", "bind_nested"),
        ("merge", "reject_nested"),
        ("prefix", "bind_nested"),
        ("prefix", "reject_nested"),
    ]);
    if bind_strategies != required_bind_strategies {
        errors.push(
            "scenario=bind_strategies must cover the four symbol/dependency strategy pairs"
                .to_string(),
        );
    }
}

fn validate_xref_certification_case_params(case: &XrefCertificationCase) -> Result<()> {
    let value = serde_json::Value::Object(case.params.clone());
    macro_rules! parse {
        ($request:ty) => {
            serde_json::from_value::<$request>(value)
                .map(|_| ())
                .map_err(anyhow::Error::from)
        };
    }
    match case.operation {
        XrefMutationOperation::AttachXref => parse!(AttachXrefRequest),
        XrefMutationOperation::UpdateXref => {
            let request = serde_json::from_value::<UpdateXrefRequest>(value)?;
            if request.properties.is_empty()
                || request.properties.keys().any(|key| {
                    classify_attachment_update_property(key) != XrefPropertyClassification::Writable
                })
            {
                anyhow::bail!("update_xref properties must be non-empty writable keys");
            }
            Ok(())
        }
        XrefMutationOperation::DetachXref => parse!(DetachXrefRequest),
        XrefMutationOperation::InsertXrefInstance => parse!(InsertXrefInstanceRequest),
        XrefMutationOperation::UpdateXrefInstance => {
            let request = serde_json::from_value::<UpdateXrefInstanceRequest>(value)?;
            if request.properties.is_empty()
                || request.properties.keys().any(|key| {
                    classify_instance_update_property(key) != XrefPropertyClassification::Writable
                })
            {
                anyhow::bail!("update_xref_instance properties must be non-empty writable keys");
            }
            Ok(())
        }
        XrefMutationOperation::DeleteXrefInstance => parse!(DeleteXrefInstanceRequest),
        XrefMutationOperation::ReloadXref => parse!(ReloadXrefRequest),
        XrefMutationOperation::UnloadXref => parse!(UnloadXrefRequest),
        XrefMutationOperation::BindXref => parse!(BindXrefRequest),
    }
}

pub fn validate_xref_certification_attestation(
    manifest: &XrefCertificationManifest,
    attestation: &XrefCertificationAttestation,
) -> Result<()> {
    let mut errors = Vec::new();
    if let Err(error) = validate_xref_certification_manifest(manifest) {
        errors.push(error.to_string());
    }
    if attestation.schema_version != XREF_CERTIFICATION_SCHEMA_VERSION {
        errors.push(format!(
            "XREF attestation schema_version {} is unsupported; expected {}",
            attestation.schema_version, XREF_CERTIFICATION_SCHEMA_VERSION
        ));
    }
    if attestation.release_id != manifest.release_id {
        errors.push("attestation release_id does not match manifest".to_string());
    }
    if attestation.activation_target != manifest.activation_target {
        errors.push("attestation activation_target does not match manifest".to_string());
    }
    let manifest_sha256 = xref_certification_manifest_sha256(manifest);
    if attestation.manifest_sha256 != manifest_sha256 {
        errors.push("attestation manifest_sha256 is stale".to_string());
    }
    let expected_artifacts = xref_embedded_artifact_sha256();
    if attestation.artifact_sha256 != expected_artifacts {
        errors.push("attestation embedded artifact digests are stale".to_string());
    }
    validate_xref_embedded_digests(&attestation.artifact_sha256, &mut errors);
    validate_xref_digest(
        "attestation release_binary_sha256",
        &attestation.release_binary_sha256,
        &mut errors,
    );
    validate_xref_digest(
        "attestation instrumented_binary_sha256",
        &attestation.instrumented_binary_sha256,
        &mut errors,
    );
    if attestation.release_binary_sha256 != manifest.release_binary_sha256 {
        errors.push("attestation release_binary_sha256 does not match the manifest".to_string());
    }
    if attestation.instrumented_binary_sha256 != manifest.instrumented_binary_sha256 {
        errors
            .push("attestation instrumented_binary_sha256 does not match the manifest".to_string());
    }
    validate_xref_digest(
        "attestation certified_arg_sha256",
        &attestation.certified_arg_sha256,
        &mut errors,
    );
    validate_certified_arg_policy_id(
        &attestation.certified_arg_policy_id,
        "attestation certified_arg_policy_id",
        &mut errors,
    );
    validate_xref_digest(
        "attestation certified_arg_policy_sha256",
        &attestation.certified_arg_policy_sha256,
        &mut errors,
    );
    if attestation.certified_arg_sha256 != manifest.certified_arg_sha256
        || attestation.certified_arg_policy_id != manifest.certified_arg_policy_id
        || attestation.certified_arg_policy_sha256 != manifest.certified_arg_policy_sha256
    {
        errors.push(
            "attestation certified ARG/policy identity does not match the manifest".to_string(),
        );
    }
    validate_xref_digest(
        "attestation shared_operation_source_sha256",
        &attestation.shared_operation_source_sha256,
        &mut errors,
    );
    if attestation.release_binary_sha256 == attestation.instrumented_binary_sha256 {
        errors.push("release and instrumented binary SHA-256 values must differ".to_string());
    }
    validate_xref_build_identity(
        "release build identity",
        &attestation.release_build_identity,
        false,
        &mut errors,
    );
    validate_xref_build_identity(
        "instrumented build identity",
        &attestation.instrumented_build_identity,
        true,
        &mut errors,
    );
    for (label, identity) in [
        ("release", &attestation.release_build_identity),
        ("instrumented", &attestation.instrumented_build_identity),
    ] {
        if identity.certified_arg_sha256 != manifest.certified_arg_sha256
            || identity.certified_arg_policy_id != manifest.certified_arg_policy_id
            || identity.certified_arg_policy_sha256 != manifest.certified_arg_policy_sha256
        {
            errors.push(format!(
                "{label} build identity certified ARG/policy values do not match the manifest"
            ));
        }
    }
    for (label, release, instrumented) in [
        (
            "source_commit",
            attestation.release_build_identity.source_commit.as_str(),
            attestation
                .instrumented_build_identity
                .source_commit
                .as_str(),
        ),
        (
            "cargo_lock_sha256",
            attestation
                .release_build_identity
                .cargo_lock_sha256
                .as_str(),
            attestation
                .instrumented_build_identity
                .cargo_lock_sha256
                .as_str(),
        ),
        (
            "certified_arg_sha256",
            attestation
                .release_build_identity
                .certified_arg_sha256
                .as_str(),
            attestation
                .instrumented_build_identity
                .certified_arg_sha256
                .as_str(),
        ),
        (
            "certified_arg_policy_id",
            attestation
                .release_build_identity
                .certified_arg_policy_id
                .as_str(),
            attestation
                .instrumented_build_identity
                .certified_arg_policy_id
                .as_str(),
        ),
        (
            "certified_arg_policy_sha256",
            attestation
                .release_build_identity
                .certified_arg_policy_sha256
                .as_str(),
            attestation
                .instrumented_build_identity
                .certified_arg_policy_sha256
                .as_str(),
        ),
        (
            "source_tree_sha256",
            attestation
                .release_build_identity
                .source_tree_sha256
                .as_str(),
            attestation
                .instrumented_build_identity
                .source_tree_sha256
                .as_str(),
        ),
        (
            "compiler",
            attestation.release_build_identity.compiler.as_str(),
            attestation.instrumented_build_identity.compiler.as_str(),
        ),
        (
            "target",
            attestation.release_build_identity.target.as_str(),
            attestation.instrumented_build_identity.target.as_str(),
        ),
        (
            "profile",
            attestation.release_build_identity.profile.as_str(),
            attestation.instrumented_build_identity.profile.as_str(),
        ),
        (
            "optimization",
            attestation.release_build_identity.optimization.as_str(),
            attestation
                .instrumented_build_identity
                .optimization
                .as_str(),
        ),
        (
            "shared_operation_source_sha256",
            attestation
                .release_build_identity
                .shared_operation_source_sha256
                .as_str(),
            attestation
                .instrumented_build_identity
                .shared_operation_source_sha256
                .as_str(),
        ),
    ] {
        if release != instrumented {
            errors.push(format!(
                "release and instrumented build identity {label} values differ"
            ));
        }
    }
    if attestation.release_build_identity.build_id
        == attestation.instrumented_build_identity.build_id
    {
        errors.push("release and instrumented build_id values must differ".to_string());
    }
    if attestation.shared_operation_source_sha256
        != attestation
            .release_build_identity
            .shared_operation_source_sha256
        || attestation.shared_operation_source_sha256
            != attestation
                .instrumented_build_identity
                .shared_operation_source_sha256
    {
        errors.push(
            "attestation shared_operation_source_sha256 does not match both executable reports"
                .to_string(),
        );
    }
    finish_xref_validation(errors)
}

fn validate_xref_engine_evidence(
    manifest: &XrefCertificationManifest,
    evidence: &XrefCertificationEvidence,
    errors: &mut Vec<String>,
) {
    if evidence.accoreconsole_path != manifest.accoreconsole_path {
        errors
            .push("strict XREF configured accoreconsole path does not match manifest".to_string());
    }
    validate_absolute_certification_file_path(
        &evidence.accoreconsole_canonical_path,
        "strict XREF canonical accoreconsole path",
        errors,
    );
    if !certification_windows_paths_equal(
        &evidence.accoreconsole_path,
        &evidence.accoreconsole_canonical_path,
    ) {
        errors.push(
            "strict XREF configured and canonical accoreconsole paths do not identify the same Windows path"
                .to_string(),
        );
    }
    if !certification_path_has_autocad_engine_shape(
        &evidence.accoreconsole_canonical_path,
        &manifest.autocad_version,
    ) {
        errors.push(
            "strict XREF canonical accoreconsole path does not identify accoreconsole.exe under an AutoCAD-labelled path component declaring the expected version"
                .to_string(),
        );
    }
    validate_digest_equality(
        "strict XREF accoreconsole SHA-256 before",
        &evidence.accoreconsole_sha256_before,
        &manifest.accoreconsole_sha256,
        errors,
    );
    validate_digest_equality(
        "strict XREF accoreconsole SHA-256 after",
        &evidence.accoreconsole_sha256_after,
        &manifest.accoreconsole_sha256,
        errors,
    );
    if evidence.observed_autocad_product != manifest.autocad_product
        || evidence.observed_autocad_version != manifest.autocad_version
    {
        errors.push(
            "strict XREF observed AutoCAD product/version does not match manifest".to_string(),
        );
    }
}

fn validate_xref_certified_arg_evidence(
    manifest: &XrefCertificationManifest,
    evidence: &XrefCertificationEvidence,
    errors: &mut Vec<String>,
) {
    if evidence.certified_arg_path != manifest.certified_arg_path {
        errors
            .push("strict XREF configured certified ARG path does not match manifest".to_string());
    }
    validate_absolute_certification_file_path(
        &evidence.certified_arg_canonical_path,
        "strict XREF canonical certified ARG path",
        errors,
    );
    if !certification_windows_paths_equal(
        &evidence.certified_arg_path,
        &evidence.certified_arg_canonical_path,
    ) {
        errors.push(
            "strict XREF configured and canonical certified ARG paths do not identify the same Windows path"
                .to_string(),
        );
    }
    validate_digest_equality(
        "strict XREF certified ARG SHA-256 before",
        &evidence.certified_arg_sha256_before,
        &manifest.certified_arg_sha256,
        errors,
    );
    validate_digest_equality(
        "strict XREF certified ARG SHA-256 after",
        &evidence.certified_arg_sha256_after,
        &manifest.certified_arg_sha256,
        errors,
    );
    validate_digest_equality(
        "strict XREF binary-reported certified ARG SHA-256",
        &evidence.binary_reported_certified_arg_sha256,
        &manifest.certified_arg_sha256,
        errors,
    );
    if evidence.certified_arg_policy_id != manifest.certified_arg_policy_id
        || evidence.certified_arg_policy_sha256 != manifest.certified_arg_policy_sha256
    {
        errors
            .push("strict XREF certified ARG policy identity does not match manifest".to_string());
    }
    if evidence.build_identity.certified_arg_sha256 != manifest.certified_arg_sha256
        || evidence.build_identity.certified_arg_policy_id != manifest.certified_arg_policy_id
        || evidence.build_identity.certified_arg_policy_sha256
            != manifest.certified_arg_policy_sha256
    {
        errors.push(
            "strict XREF build identity certified ARG/policy values do not match manifest"
                .to_string(),
        );
    }
}

pub fn validate_xref_certification_evidence(
    manifest: &XrefCertificationManifest,
    evidence: &XrefCertificationEvidence,
    attestation: &XrefCertificationAttestation,
) -> Result<()> {
    let registry = embedded_xref_artifacts()?;
    let mut errors = Vec::new();
    if let Err(error) = validate_xref_certification_attestation(manifest, attestation) {
        errors.push(error.to_string());
    }
    if evidence.schema_version != XREF_CERTIFICATION_SCHEMA_VERSION {
        errors.push(format!(
            "XREF evidence schema_version {} is unsupported; expected {}",
            evidence.schema_version, XREF_CERTIFICATION_SCHEMA_VERSION
        ));
    }
    if evidence.release_id != manifest.release_id {
        errors.push("evidence release_id does not match manifest".to_string());
    }
    if evidence.activation_target != manifest.activation_target {
        errors.push("evidence activation_target does not match manifest".to_string());
    }
    if evidence.status != XrefCertificationResultStatus::Passed {
        errors.push(format!(
            "{} evidence status must be passed, not {:?}",
            evidence.evidence_class.as_str(),
            evidence.status
        ));
    }
    let manifest_sha256 = xref_certification_manifest_sha256(manifest);
    if evidence.manifest_sha256 != manifest_sha256 {
        errors.push("evidence manifest_sha256 is stale".to_string());
    }
    if evidence.artifact_sha256 != attestation.artifact_sha256 {
        errors.push("evidence embedded artifact digests do not match attestation".to_string());
    }
    validate_xref_engine_evidence(manifest, evidence, &mut errors);
    validate_xref_certified_arg_evidence(manifest, evidence, &mut errors);
    let (expected_cases, expected_binary_path, expected_binary, expected_build) =
        match evidence.evidence_class {
            XrefCertificationEvidenceClass::ReleaseConformance => (
                manifest.release_cases.as_slice(),
                manifest.release_binary_path.as_str(),
                attestation.release_binary_sha256.as_str(),
                &attestation.release_build_identity,
            ),
            XrefCertificationEvidenceClass::InstrumentedTransaction => (
                manifest.instrumented_cases.as_slice(),
                manifest.instrumented_binary_path.as_str(),
                attestation.instrumented_binary_sha256.as_str(),
                &attestation.instrumented_build_identity,
            ),
        };
    if evidence.binary_sha256 != expected_binary {
        errors.push("evidence binary_sha256 does not match attestation".to_string());
    }
    if evidence.binary_path != expected_binary_path {
        errors.push("evidence configured binary path does not match manifest".to_string());
    }
    validate_absolute_certification_file_path(
        &evidence.binary_canonical_path,
        "strict XREF canonical binary path",
        &mut errors,
    );
    if !certification_windows_paths_equal(&evidence.binary_path, &evidence.binary_canonical_path) {
        errors.push(
            "strict XREF configured and canonical binary paths do not identify the same Windows path"
                .to_string(),
        );
    }
    validate_digest_equality(
        "strict XREF binary SHA-256 before",
        &evidence.binary_sha256_before,
        expected_binary,
        &mut errors,
    );
    validate_digest_equality(
        "strict XREF binary SHA-256 after",
        &evidence.binary_sha256_after,
        expected_binary,
        &mut errors,
    );
    if &evidence.build_identity != expected_build {
        errors.push("evidence build_identity does not match attestation".to_string());
    }
    let expected_profiles = xref_certification_profile_references(registry);
    if evidence.profile_references != expected_profiles {
        errors.push("evidence row/profile references do not match embedded registry".to_string());
    }

    let failure_keys: Vec<_> = evidence
        .case_failures
        .iter()
        .map(|failure| (failure.row_id.as_str(), failure.case_id.as_str()))
        .collect();
    validate_sorted_unique_keys(
        &format!(
            "{} evidence failures by row_id/case_id",
            evidence.evidence_class.as_str()
        ),
        &failure_keys,
        &mut errors,
    );
    let failures: BTreeMap<_, _> = evidence
        .case_failures
        .iter()
        .map(|failure| ((failure.row_id.as_str(), failure.case_id.as_str()), failure))
        .collect();
    if failures.len() != evidence.case_failures.len() {
        errors.push("evidence contains duplicate case failure identity".to_string());
    }
    for failure in &evidence.case_failures {
        if failure.detail.trim().is_empty() || failure.detail != failure.detail.trim() {
            errors.push(format!(
                "case failure '{}:{}' detail must be non-empty and trimmed",
                failure.row_id, failure.case_id
            ));
        }
        errors.push(format!(
            "case execution failed '{}:{}' at {}: {}",
            failure.row_id,
            failure.case_id,
            match failure.stage {
                XrefCertificationFailureStage::FixtureStaging => "fixture_staging",
                XrefCertificationFailureStage::ScenarioSetup => "scenario_setup",
                XrefCertificationFailureStage::Execution => "execution",
                XrefCertificationFailureStage::Verification => "verification",
                XrefCertificationFailureStage::HarnessCleanup => "harness_cleanup",
            },
            failure.detail
        ));
    }

    let result_keys: Vec<_> = evidence
        .case_results
        .iter()
        .map(|result| (result.row_id.as_str(), result.case_id.as_str()))
        .collect();
    validate_sorted_unique_keys(
        &format!(
            "{} evidence results by row_id/case_id",
            evidence.evidence_class.as_str()
        ),
        &result_keys,
        &mut errors,
    );
    let results: BTreeMap<_, _> = evidence
        .case_results
        .iter()
        .map(|result| ((result.row_id.as_str(), result.case_id.as_str()), result))
        .collect();
    if results.len() != evidence.case_results.len() {
        errors.push("evidence contains duplicate case identity".to_string());
    }
    if evidence.case_results.len() + evidence.case_failures.len() != expected_cases.len() {
        errors.push("evidence case count does not match manifest".to_string());
    }

    for case in expected_cases {
        let key = (case.row_id.as_str(), case.case_id.as_str());
        let Some(result) = results.get(&key).copied() else {
            if let Some(failure) = failures.get(&key).copied() {
                if failure.operation != case.operation || failure.scenario != case.scenario {
                    errors.push(format!(
                        "case failure '{}:{}' does not match the manifest operation/scenario",
                        case.row_id, case.case_id
                    ));
                }
                continue;
            }
            errors.push(format!(
                "missing evidence result '{}:{}'",
                case.row_id, case.case_id
            ));
            continue;
        };
        let location = format!("evidence result '{}:{}'", case.row_id, case.case_id);
        if result.operation != case.operation {
            errors.push(format!("{location} operation does not match manifest"));
        }
        if result.status != XrefCertificationResultStatus::Passed {
            errors.push(format!(
                "{location} is {:?}; skipped or failed evidence is forbidden",
                result.status
            ));
        }
        if result.error_code != case.expected_error_code {
            errors.push(format!(
                "{location} error_code does not match expected outcome"
            ));
        }
        match expected_xref_profile_isolation(case, evidence.evidence_class) {
            Ok(expected_profile_isolation) => validate_profile_isolation_evidence(
                &location,
                &expected_profile_isolation,
                &result.profile_isolation,
                &mut errors,
            ),
            Err(error) => errors.push(format!(
                "{location} cannot derive a closed profile-isolation inventory: {error}"
            )),
        }
        let Some(row) = registry
            .capabilities()
            .rows
            .iter()
            .find(|row| row.row_id == case.row_id)
        else {
            errors.push(format!("{location} references unknown capability row"));
            continue;
        };
        let expected_format = XrefCertificationFormatFacts::from_capability(row);
        if result.input_format != expected_format || result.output_format != expected_format {
            errors.push(format!(
                "{location} input/output format facts do not match exact capability row"
            ));
        }
        validate_xref_digest(
            &format!("{location} original_digest_before"),
            &result.original_digest_before,
            &mut errors,
        );
        validate_xref_digest(
            &format!("{location} original_digest_after"),
            &result.original_digest_after,
            &mut errors,
        );
        let must_remain_unchanged = match evidence.evidence_class {
            XrefCertificationEvidenceClass::ReleaseConformance => {
                case.expected_status == XrefCertificationExpectedStatus::Failed
            }
            XrefCertificationEvidenceClass::InstrumentedTransaction => case
                .failpoint
                .map(|failpoint| !failpoint.may_cross_replacement())
                .unwrap_or(true),
        };
        if must_remain_unchanged && result.original_digest_before != result.original_digest_after {
            errors.push(format!(
                "{location} changed the original despite a proven pre-replacement failure"
            ));
        }
        validate_xref_cleanup(
            &location,
            &result.artifact_cleanup,
            case.expected_status == XrefCertificationExpectedStatus::Passed,
            case.scenario == XrefCertificationScenario::ProfileIsolation,
            &mut errors,
        );
    }
    for result in &evidence.case_results {
        if !expected_cases
            .iter()
            .any(|case| case.row_id == result.row_id && case.case_id == result.case_id)
        {
            errors.push(format!(
                "unexpected evidence result '{}:{}'",
                result.row_id, result.case_id
            ));
        }
    }
    for failure in &evidence.case_failures {
        if !expected_cases
            .iter()
            .any(|case| case.row_id == failure.row_id && case.case_id == failure.case_id)
        {
            errors.push(format!(
                "unexpected evidence failure '{}:{}'",
                failure.row_id, failure.case_id
            ));
        }
        if results.contains_key(&(failure.row_id.as_str(), failure.case_id.as_str())) {
            errors.push(format!(
                "case '{}:{}' has both a result and a failure",
                failure.row_id, failure.case_id
            ));
        }
    }

    finish_xref_validation(errors)
}

pub fn validate_xref_certification_bundle(
    manifest: &XrefCertificationManifest,
    release_evidence: &XrefCertificationEvidence,
    instrumented_evidence: &XrefCertificationEvidence,
    attestation: &XrefCertificationAttestation,
) -> Result<()> {
    let mut errors = Vec::new();
    if release_evidence.evidence_class != XrefCertificationEvidenceClass::ReleaseConformance {
        errors.push("release evidence has the wrong evidence_class".to_string());
    }
    if instrumented_evidence.evidence_class
        != XrefCertificationEvidenceClass::InstrumentedTransaction
    {
        errors.push("instrumented evidence has the wrong evidence_class".to_string());
    }
    let release_engine = (
        &release_evidence.accoreconsole_path,
        &release_evidence.accoreconsole_canonical_path,
        &release_evidence.accoreconsole_sha256_before,
        &release_evidence.accoreconsole_sha256_after,
        &release_evidence.observed_autocad_product,
        &release_evidence.observed_autocad_version,
    );
    let instrumented_engine = (
        &instrumented_evidence.accoreconsole_path,
        &instrumented_evidence.accoreconsole_canonical_path,
        &instrumented_evidence.accoreconsole_sha256_before,
        &instrumented_evidence.accoreconsole_sha256_after,
        &instrumented_evidence.observed_autocad_product,
        &instrumented_evidence.observed_autocad_version,
    );
    if release_engine != instrumented_engine {
        errors.push(
            "release and instrumented evidence must bind the same strict XREF engine observation"
                .to_string(),
        );
    }
    let release_arg = (
        &release_evidence.certified_arg_path,
        &release_evidence.certified_arg_canonical_path,
        &release_evidence.certified_arg_sha256_before,
        &release_evidence.certified_arg_sha256_after,
        &release_evidence.binary_reported_certified_arg_sha256,
        &release_evidence.certified_arg_policy_id,
        &release_evidence.certified_arg_policy_sha256,
    );
    let instrumented_arg = (
        &instrumented_evidence.certified_arg_path,
        &instrumented_evidence.certified_arg_canonical_path,
        &instrumented_evidence.certified_arg_sha256_before,
        &instrumented_evidence.certified_arg_sha256_after,
        &instrumented_evidence.binary_reported_certified_arg_sha256,
        &instrumented_evidence.certified_arg_policy_id,
        &instrumented_evidence.certified_arg_policy_sha256,
    );
    if release_arg != instrumented_arg {
        errors.push(
            "release and instrumented evidence must bind the same certified ARG/policy observation"
                .to_string(),
        );
    }
    if let Err(error) =
        validate_xref_certification_evidence(manifest, release_evidence, attestation)
    {
        errors.push(error.to_string());
    }
    if let Err(error) =
        validate_xref_certification_evidence(manifest, instrumented_evidence, attestation)
    {
        errors.push(error.to_string());
    }
    finish_xref_validation(errors)
}

fn validate_xref_build_identity(
    label: &str,
    identity: &XrefCertificationBuildIdentity,
    failpoints_expected: bool,
    errors: &mut Vec<String>,
) {
    if !matches!(identity.source_commit.len(), 40 | 64)
        || !identity
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        errors.push(format!(
            "{label} source_commit must be an exact Git object ID"
        ));
    }
    validate_xref_digest(
        &format!("{label} source_tree_sha256"),
        &identity.source_tree_sha256,
        errors,
    );
    validate_xref_digest(
        &format!("{label} cargo_lock_sha256"),
        &identity.cargo_lock_sha256,
        errors,
    );
    validate_xref_digest(
        &format!("{label} certified_arg_sha256"),
        &identity.certified_arg_sha256,
        errors,
    );
    validate_certified_arg_policy_id(
        &identity.certified_arg_policy_id,
        &format!("{label} certified_arg_policy_id"),
        errors,
    );
    validate_xref_digest(
        &format!("{label} certified_arg_policy_sha256"),
        &identity.certified_arg_policy_sha256,
        errors,
    );
    validate_xref_digest(&format!("{label} build_id"), &identity.build_id, errors);
    validate_xref_digest(
        &format!("{label} shared_operation_source_sha256"),
        &identity.shared_operation_source_sha256,
        errors,
    );
    for (field, value) in [
        ("compiler", identity.compiler.as_str()),
        ("target", identity.target.as_str()),
        ("profile", identity.profile.as_str()),
        ("optimization", identity.optimization.as_str()),
    ] {
        if value.trim().is_empty() || value != value.trim() {
            errors.push(format!("{label} {field} must be non-empty and trimmed"));
        }
    }
    if identity.profile != "release" {
        errors.push(format!("{label} profile must be release"));
    }
    if !identity
        .target
        .split('-')
        .any(|component| component == "windows")
    {
        errors.push(format!("{label} target must be Windows"));
    }
    if identity.certification_failpoints_enabled != failpoints_expected {
        errors.push(format!(
            "{label} certification_failpoints_enabled must be {failpoints_expected}"
        ));
    }
}

fn validate_xref_cleanup(
    location: &str,
    cleanup: &XrefArtifactCleanupEvidence,
    require_transaction_activity: bool,
    require_isolated_profile: bool,
    errors: &mut Vec<String>,
) {
    validate_sorted_unique_keys(
        &format!("{location} cleanup inventory_roots"),
        &cleanup.inventory_roots,
        errors,
    );
    if cleanup.inventory_roots.is_empty()
        || cleanup
            .inventory_roots
            .iter()
            .any(|path| path.trim().is_empty())
    {
        errors.push(format!(
            "{location} cleanup must identify non-empty inventory roots"
        ));
    }
    if cleanup.observation_polls < 2 {
        errors.push(format!(
            "{location} cleanup requires at least two artifact/process observations"
        ));
    }
    for (label, paths) in [
        ("attempted", cleanup.attempted.as_slice()),
        ("removed", cleanup.removed.as_slice()),
        ("remaining", cleanup.remaining.as_slice()),
    ] {
        validate_sorted_unique_keys(&format!("{location} cleanup {label}"), paths, errors);
        if paths.iter().any(|path| path.trim().is_empty()) {
            errors.push(format!("{location} cleanup {label} contains an empty path"));
        }
    }
    let attempted: BTreeSet<_> = cleanup.attempted.iter().collect();
    if cleanup.removed.iter().any(|path| !attempted.contains(path)) {
        errors.push(format!(
            "{location} cleanup removed paths must be present in attempted"
        ));
    }
    let removed: BTreeSet<_> = cleanup.removed.iter().collect();
    let remaining: BTreeSet<_> = cleanup.remaining.iter().collect();
    if !removed.is_disjoint(&remaining) || attempted != removed.union(&remaining).copied().collect()
    {
        errors.push(format!(
            "{location} cleanup attempted paths must partition into removed and remaining"
        ));
    }
    for (label, process_ids) in [
        ("process_ids_before", cleanup.process_ids_before.as_slice()),
        (
            "process_ids_observed",
            cleanup.process_ids_observed.as_slice(),
        ),
        (
            "process_ids_remaining",
            cleanup.process_ids_remaining.as_slice(),
        ),
    ] {
        validate_sorted_unique_keys(&format!("{location} cleanup {label}"), process_ids, errors);
    }
    let observed_processes: BTreeSet<_> = cleanup.process_ids_observed.iter().collect();
    if cleanup
        .process_ids_remaining
        .iter()
        .any(|process_id| !observed_processes.contains(process_id))
    {
        errors.push(format!(
            "{location} cleanup remaining process IDs must have been observed"
        ));
    }
    if require_transaction_activity
        && (cleanup.attempted.is_empty() || cleanup.process_ids_observed.is_empty())
    {
        errors.push(format!(
            "{location} cleanup did not observe transaction artifacts and AutoCAD process activity"
        ));
    }
    if require_isolated_profile
        && !cleanup.attempted.iter().any(|path| {
            path.ends_with("xref-isolated-profile.arg")
                || path.ends_with("xref-isolated-profile.json")
        })
    {
        errors.push(format!(
            "{location} profile_isolation did not observe a materialized isolated profile"
        ));
    }
    if !cleanup.remaining.is_empty()
        || !cleanup.process_ids_remaining.is_empty()
        || cleanup.engine_stop_error.is_some()
    {
        errors.push(format!(
            "{location} does not prove complete artifact/process cleanup"
        ));
    }
}

fn validate_xref_profile_digests(digests: &XrefProfileArtifactSha256, errors: &mut Vec<String>) {
    validate_xref_digest(
        "profile_sha256.preservation_verifier_profiles",
        &digests.preservation_verifier_profiles,
        errors,
    );
    validate_xref_digest(
        "profile_sha256.bind_verifier_profiles",
        &digests.bind_verifier_profiles,
        errors,
    );
    validate_xref_digest(
        "profile_sha256.clip_verifier_profiles",
        &digests.clip_verifier_profiles,
        errors,
    );
}

fn validate_xref_embedded_digests(digests: &XrefEmbeddedArtifactSha256, errors: &mut Vec<String>) {
    validate_xref_digest(
        "artifact_sha256.mutation_capabilities",
        &digests.mutation_capabilities,
        errors,
    );
    validate_xref_profile_digests(&digests.profile_sha256(), errors);
}

fn validate_xref_digest(label: &str, digest: &str, errors: &mut Vec<String>) {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        errors.push(format!(
            "{label} must be a 64-character lowercase SHA-256 value"
        ));
    }
}

pub const CERTIFICATION_SCHEMA_VERSION: u32 = 3;
pub const CERTIFIED_AUTOCAD_PRODUCT: &str = "autocad";
pub const TIER2_PROFILE_WINDOWS_EVIDENCE_FILE: &str = "windows-certification-evidence.json";
pub const LAYER_MUTATION_WINDOWS_EVIDENCE_FILE: &str = "layer-windows-certification-evidence.json";

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationActivationTarget {
    pub catalogue_sha256: String,
    pub target_id: String,
    pub product: String,
    pub edition: String,
    pub architecture: String,
    pub release_year: u16,
    pub registry_family: String,
    pub product_language_key: String,
    pub ui_locale: String,
}

struct CertificationActivationClaim<'a> {
    autocad_product: &'a str,
    autocad_version: &'a str,
    certified_arg_sha256: &'a str,
    certified_arg_policy_id: &'a str,
    certified_arg_policy_sha256: &'a str,
}

pub fn embedded_certification_activation_target(
    target_id: &str,
) -> Result<CertificationActivationTarget> {
    let catalogue = activation::embedded_activation_catalogue()
        .map_err(|error| anyhow::anyhow!("load embedded activation catalogue: {error}"))?;
    let target = catalogue
        .target(target_id)
        .ok_or_else(|| anyhow::anyhow!("unknown activation target {target_id:?}"))?;
    Ok(CertificationActivationTarget {
        catalogue_sha256: catalogue.sha256.clone(),
        target_id: target.target_id.clone(),
        product: target.product.as_str().to_string(),
        edition: target.edition.as_str().to_string(),
        architecture: target.architecture.as_str().to_string(),
        release_year: target.release_year,
        registry_family: target.registry_family.clone(),
        product_language_key: target.product_language_key.clone(),
        ui_locale: target.ui_locale.clone(),
    })
}

fn validate_certification_activation_target(
    binding: &CertificationActivationTarget,
    claim: CertificationActivationClaim<'_>,
    required_capabilities: &[MutationCapability],
    label: &str,
    errors: &mut Vec<String>,
) {
    validate_xref_digest(
        &format!("{label} catalogue_sha256"),
        &binding.catalogue_sha256,
        errors,
    );
    for (field, value) in [
        ("target_id", binding.target_id.as_str()),
        ("product", binding.product.as_str()),
        ("edition", binding.edition.as_str()),
        ("architecture", binding.architecture.as_str()),
        ("registry_family", binding.registry_family.as_str()),
        (
            "product_language_key",
            binding.product_language_key.as_str(),
        ),
        ("ui_locale", binding.ui_locale.as_str()),
    ] {
        validate_nonempty_trimmed(value, &format!("{label} {field}"), errors);
    }

    let catalogue = match activation::embedded_activation_catalogue() {
        Ok(catalogue) => catalogue,
        Err(error) => {
            errors.push(format!(
                "{label} cannot load the embedded activation catalogue: {error}"
            ));
            return;
        }
    };
    if binding.catalogue_sha256 != catalogue.sha256 {
        errors.push(format!(
            "{label} catalogue_sha256 does not match the embedded activation catalogue"
        ));
    }
    let Some(target) = catalogue.target(&binding.target_id) else {
        errors.push(format!(
            "{label} target_id {:?} is not in the embedded activation catalogue",
            binding.target_id
        ));
        return;
    };
    let expected = CertificationActivationTarget {
        catalogue_sha256: catalogue.sha256.clone(),
        target_id: target.target_id.clone(),
        product: target.product.as_str().to_string(),
        edition: target.edition.as_str().to_string(),
        architecture: target.architecture.as_str().to_string(),
        release_year: target.release_year,
        registry_family: target.registry_family.clone(),
        product_language_key: target.product_language_key.clone(),
        ui_locale: target.ui_locale.clone(),
    };
    if binding != &expected {
        errors.push(format!(
            "{label} does not exactly match its embedded activation catalogue row"
        ));
    }
    if !target.maintained_target {
        errors.push(format!(
            "{label} target_id {:?} is a Preview-only candidate, not a maintained-support target",
            binding.target_id
        ));
    }
    for capability in required_capabilities {
        if !target.supports(*capability) {
            errors.push(format!(
                "{label} target_id {:?} does not admit required capability {capability:?}",
                binding.target_id
            ));
        }
    }
    if target
        .drawing_formats
        .binary_search_by(|format| format.as_str().cmp("AC1032"))
        .is_err()
    {
        errors.push(format!(
            "{label} target_id {:?} does not admit certified drawing format AC1032",
            binding.target_id
        ));
    }
    if claim.autocad_product != target.product.as_str()
        || claim.autocad_version != target.release_year.to_string()
    {
        errors.push(format!(
            "{label} product/version does not match activation target {:?}",
            binding.target_id
        ));
    }
    if claim.certified_arg_sha256 != target.profile.arg_sha256
        || claim.certified_arg_policy_id != target.profile.policy_id
        || claim.certified_arg_policy_sha256 != target.profile.policy_sha256
    {
        errors.push(format!(
            "{label} certified ARG/policy identity does not match activation target {:?}",
            binding.target_id
        ));
    }
}

const LAYER_WRITABLE_FIELDS: [&str; 7] = [
    "color_index",
    "frozen",
    "locked",
    "off",
    "is_plottable",
    "line_type",
    "line_weight",
];
const LAYER_REQUIRED_FAILURE_CODES: [&str; 4] = [
    "line_type_not_found",
    "invalid_line_weight",
    "cannot_freeze_current_layer",
    "unsupported_layer_property",
];

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationManifest {
    pub schema_version: u32,
    pub release_id: String,
    pub fixture_root: String,
    pub runtime: CertificationRuntimeRequirements,
    pub tier2_drawings: Vec<CertificationDrawing>,
    pub layer_mutation_cases: Vec<LayerMutationCertificationCase>,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationRuntimeRequirements {
    pub activation_target: CertificationActivationTarget,
    pub release_binary_path: String,
    pub release_binary_sha256: String,
    pub title_block_profile_registry_sha256: String,
    pub accoreconsole_path: String,
    pub accoreconsole_sha256: String,
    pub autocad_product: String,
    pub autocad_version: String,
    pub certified_arg_path: String,
    pub certified_arg_sha256: String,
    pub certified_arg_policy_id: String,
    pub certified_arg_policy_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationProfileDefinition {
    pub profile_id: String,
    pub field_mappings: Vec<CertificationProfileFieldMapping>,
    pub fingerprint: CertificationTitleBlockFingerprint,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationProfileFieldMapping {
    pub canonical_field: String,
    pub attribute_tag: String,
}

/// Returns the embedded title-block registry in the exact closed shape used by
/// certification manifests, runtime introspection, and evidence validation.
///
/// Keeping this projection here gives every certification producer one
/// deterministic canonical-to-tag conversion.
pub fn embedded_certification_profile_definitions() -> Vec<CertificationProfileDefinition> {
    profiles::title_block_profile_definitions()
        .into_iter()
        .map(|definition| {
            debug_assert_eq!(
                definition.canonical_fields,
                definition
                    .canonical_to_tag
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
            );
            CertificationProfileDefinition {
                profile_id: definition.profile_id,
                field_mappings: definition
                    .canonical_to_tag
                    .into_iter()
                    .map(
                        |(canonical_field, attribute_tag)| CertificationProfileFieldMapping {
                            canonical_field,
                            attribute_tag,
                        },
                    )
                    .collect(),
                fingerprint: CertificationTitleBlockFingerprint {
                    block_name: definition.fingerprint.block_name,
                    attribute_tags: definition.fingerprint.attribute_tags,
                },
            }
        })
        .collect()
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationDrawing {
    pub drawing_id: String,
    pub path: String,
    pub source_sha256: String,
    pub expected_profile_id: String,
    pub write_fields: Vec<CertificationWriteField>,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub plot_layout: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationWriteField {
    pub field: String,
    pub value: String,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LayerCertificationFixtureKind {
    HostOwned,
    XrefDependentHost,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationSourceFixture {
    pub path: String,
    pub source_sha256: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerMutationCertificationCase {
    pub case_id: String,
    pub drawing_id: String,
    pub path: String,
    pub source_sha256: String,
    pub fixture_kind: LayerCertificationFixtureKind,
    pub referenced_source_fixtures: Vec<CertificationSourceFixture>,
    pub operations: Vec<LayerMutationCertificationOperation>,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LayerMutationCertificationTool {
    ListLayers,
    GetLayer,
    CreateLayer,
    UpdateLayer,
    RenameLayer,
    DeleteLayer,
}

impl LayerMutationCertificationTool {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListLayers => "list_layers",
            Self::GetLayer => "get_layer",
            Self::CreateLayer => "create_layer",
            Self::UpdateLayer => "update_layer",
            Self::RenameLayer => "rename_layer",
            Self::DeleteLayer => "delete_layer",
        }
    }

    const fn is_mutation(self) -> bool {
        matches!(
            self,
            Self::CreateLayer | Self::UpdateLayer | Self::RenameLayer | Self::DeleteLayer
        )
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerMutationCertificationOperation {
    pub operation_id: String,
    pub tool: LayerMutationCertificationTool,
    #[schemars(with = "LayerCertificationParamsSchema")]
    pub params: serde_json::Value,
    pub expected: LayerCertificationExpectedOutcome,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(untagged)]
pub enum LayerCertificationParamsSchema {
    List(LayerListCertificationParams),
    Get(LayerGetCertificationParams),
    Create(LayerCreateCertificationParams),
    Update(LayerUpdateCertificationParams),
    Rename(LayerRenameCertificationParams),
    Delete(LayerDeleteCertificationParams),
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerListCertificationParams {}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerGetCertificationParams {
    pub handle: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerCreateCertificationParams {
    pub name: String,
    pub properties: LayerCertificationProperties,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerUpdateCertificationParams {
    pub handle: Option<String>,
    pub name: Option<String>,
    pub expected_handle: Option<String>,
    pub expected_name: Option<String>,
    pub properties: LayerCertificationProperties,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerRenameCertificationParams {
    pub handle: Option<String>,
    pub name: Option<String>,
    pub expected_handle: Option<String>,
    pub expected_name: Option<String>,
    pub new_name: String,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerDeleteCertificationParams {
    pub handle: Option<String>,
    pub name: Option<String>,
    pub expected_handle: Option<String>,
    pub expected_name: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerCertificationProperties {
    pub color_index: Option<u16>,
    pub frozen: Option<bool>,
    pub locked: Option<bool>,
    pub off: Option<bool>,
    pub is_plottable: Option<bool>,
    pub line_type: Option<String>,
    pub line_weight: Option<LayerCertificationLineWeight>,
    /// A closed representative of the runtime's recognized read-only property
    /// set, used to certify `unsupported_layer_property`.
    pub plot_style: Option<String>,
}

impl LayerCertificationProperties {
    fn writable_fields(&self) -> Vec<&'static str> {
        let mut fields = Vec::new();
        if self.color_index.is_some() {
            fields.push("color_index");
        }
        if self.frozen.is_some() {
            fields.push("frozen");
        }
        if self.locked.is_some() {
            fields.push("locked");
        }
        if self.off.is_some() {
            fields.push("off");
        }
        if self.is_plottable.is_some() {
            fields.push("is_plottable");
        }
        if self.line_type.is_some() {
            fields.push("line_type");
        }
        if self.line_weight.is_some() {
            fields.push("line_weight");
        }
        fields
    }

    fn is_empty(&self) -> bool {
        self.writable_fields().is_empty() && self.plot_style.is_none()
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LayerCertificationLineWeight {
    ByLayer,
    ByBlock,
    Default,
    Value { hundredths_mm: i16 },
}

impl LayerCertificationLineWeight {
    const fn coverage_key(self) -> &'static str {
        match self {
            Self::ByLayer => "by_layer",
            Self::ByBlock => "by_block",
            Self::Default => "default",
            Self::Value { .. } => "value",
        }
    }
}

/// Closed read-side lineweight representation.
///
/// Certification request parameters intentionally use
/// [`LayerCertificationLineWeight`], which excludes the read-only `raw`
/// variant. Persisted observations must nevertheless be able to represent
/// every layer that the product can read.
#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CertificationObservedLayerLineWeight {
    ByLayer,
    ByBlock,
    Default,
    Value { hundredths_mm: i16 },
    Raw { raw_value: i16 },
}

impl From<LayerCertificationLineWeight> for CertificationObservedLayerLineWeight {
    fn from(value: LayerCertificationLineWeight) -> Self {
        match value {
            LayerCertificationLineWeight::ByLayer => Self::ByLayer,
            LayerCertificationLineWeight::ByBlock => Self::ByBlock,
            LayerCertificationLineWeight::Default => Self::Default,
            LayerCertificationLineWeight::Value { hundredths_mm } => Self::Value { hundredths_mm },
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum LayerCertificationExpectedOutcome {
    Passed {
        assertion: LayerCertificationPassedAssertion,
    },
    Failed {
        error_code: String,
        unchanged_layer: LayerCertificationLayerExpectation,
    },
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LayerCertificationPassedAssertion {
    ExpandedRecords {
        record: CertificationExpandedLayerRecord,
    },
    Layer {
        layer: LayerCertificationLayerExpectation,
    },
    DeletedIdentity {
        handle: String,
        name: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum CertificationFieldExpectation<T> {
    #[default]
    Omitted,
    Null,
    Value(T),
}

impl<T> CertificationFieldExpectation<T> {
    pub fn is_omitted(&self) -> bool {
        matches!(self, Self::Omitted)
    }

    fn matches_value(&self, value: &T) -> bool
    where
        T: PartialEq,
    {
        matches!(self, Self::Value(expected) if expected == value)
    }
}

impl<T> Serialize for CertificationFieldExpectation<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Omitted | Self::Null => serializer.serialize_none(),
            Self::Value(value) => value.serialize(serializer),
        }
    }
}

impl<'de, T> Deserialize<'de> for CertificationFieldExpectation<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(|value| value.map_or(Self::Null, Self::Value))
    }
}

impl<T> JsonSchema for CertificationFieldExpectation<T>
where
    T: JsonSchema,
{
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Owned(format!("Nullable{}", T::schema_name()))
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <Option<T>>::json_schema(generator)
    }
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerCertificationLayerExpectation {
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub handle: CertificationFieldExpectation<String>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub name: CertificationFieldExpectation<String>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub color_index: CertificationFieldExpectation<u16>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub line_type: CertificationFieldExpectation<String>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub line_weight: CertificationFieldExpectation<CertificationObservedLayerLineWeight>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub frozen: CertificationFieldExpectation<bool>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub locked: CertificationFieldExpectation<bool>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub off: CertificationFieldExpectation<bool>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub is_plottable: CertificationFieldExpectation<bool>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub xref_dependent: CertificationFieldExpectation<bool>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub xref_block_record_handle: CertificationFieldExpectation<String>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub xref_name: CertificationFieldExpectation<String>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub xref_path: CertificationFieldExpectation<String>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub xref_is_overlay: CertificationFieldExpectation<bool>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub material_handle: CertificationFieldExpectation<String>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub plotstyle_handle: CertificationFieldExpectation<String>,
    #[serde(
        default,
        skip_serializing_if = "CertificationFieldExpectation::is_omitted"
    )]
    pub is_current: CertificationFieldExpectation<bool>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationExpandedLayerRecord {
    pub handle: String,
    pub name: String,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub color_index: Option<u16>,
    pub line_type: String,
    pub line_weight: CertificationObservedLayerLineWeight,
    pub frozen: bool,
    pub locked: bool,
    pub off: bool,
    pub is_plottable: bool,
    pub xref_dependent: bool,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub xref_block_record_handle: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub xref_name: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub xref_path: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub xref_is_overlay: Option<bool>,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub material_handle: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub plotstyle_handle: Option<String>,
    pub is_current: bool,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CertificationEvidenceClass {
    Tier2Profile,
    LayerMutation,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CertificationResultStatus {
    Passed,
    Failed,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CertificationObservedToolStatus {
    Passed,
    Failed,
}

#[derive(
    Debug, Clone, Copy, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CertificationProfileLaunchExpectation {
    NoEngineExpected,
    EngineImportRequired,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationProfileIsolationEvidence {
    pub invocation_id: String,
    pub tool: String,
    pub expectation: CertificationProfileLaunchExpectation,
    pub absent_before: bool,
    pub present_after: bool,
    pub cleanup_performed: bool,
    pub absent_after: bool,
}

pub fn layer_certification_profile_launch_expectation(
    operation: &LayerMutationCertificationOperation,
) -> Result<CertificationProfileLaunchExpectation> {
    if matches!(
        operation.tool,
        LayerMutationCertificationTool::ListLayers | LayerMutationCertificationTool::GetLayer
    ) {
        return Ok(CertificationProfileLaunchExpectation::NoEngineExpected);
    }
    match &operation.expected {
        LayerCertificationExpectedOutcome::Passed { .. } => {
            Ok(CertificationProfileLaunchExpectation::EngineImportRequired)
        }
        LayerCertificationExpectedOutcome::Failed { error_code, .. } => match error_code.as_str() {
            "invalid_line_weight" | "unsupported_layer_property" => {
                Ok(CertificationProfileLaunchExpectation::NoEngineExpected)
            }
            "line_type_not_found" | "cannot_freeze_current_layer" => {
                Ok(CertificationProfileLaunchExpectation::EngineImportRequired)
            }
            other => anyhow::bail!(
                "layer operation '{}' has no explicit certified-profile launch semantics for error code {other:?}",
                operation.operation_id
            ),
        },
    }
}

pub fn xref_certification_profile_launch_expectation(
    case: &XrefCertificationCase,
    evidence_class: XrefCertificationEvidenceClass,
) -> Result<CertificationProfileLaunchExpectation> {
    if case.expected_status == XrefCertificationExpectedStatus::Passed {
        return Ok(CertificationProfileLaunchExpectation::EngineImportRequired);
    }
    match evidence_class {
        XrefCertificationEvidenceClass::ReleaseConformance => match case.scenario {
            XrefCertificationScenario::Clips
            | XrefCertificationScenario::LockedResources
            | XrefCertificationScenario::Guards
            | XrefCertificationScenario::SourceRace
            | XrefCertificationScenario::HostRace => {
                Ok(CertificationProfileLaunchExpectation::NoEngineExpected)
            }
            scenario => anyhow::bail!(
                "failed release XREF scenario {scenario:?} has no explicit certified-profile launch semantics"
            ),
        },
        XrefCertificationEvidenceClass::InstrumentedTransaction => match case.failpoint {
            Some(
                XrefCertificationFailpoint::DuringSourceSnapshot
                | XrefCertificationFailpoint::BeforeSave,
            ) => Ok(CertificationProfileLaunchExpectation::NoEngineExpected),
            Some(_) => Ok(CertificationProfileLaunchExpectation::EngineImportRequired),
            None => anyhow::bail!(
                "instrumented XREF case has no failpoint for certified-profile launch semantics"
            ),
        },
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ExpectedCertificationProfileInvocation {
    invocation_id: String,
    tool: String,
    expectation: CertificationProfileLaunchExpectation,
}

fn expected_profile_invocation(
    invocation_id: impl Into<String>,
    tool: impl Into<String>,
    expectation: CertificationProfileLaunchExpectation,
) -> ExpectedCertificationProfileInvocation {
    ExpectedCertificationProfileInvocation {
        invocation_id: invocation_id.into(),
        tool: tool.into(),
        expectation,
    }
}

fn expected_tier2_profile_isolation(
    include_plot: bool,
) -> Vec<ExpectedCertificationProfileInvocation> {
    let offline = CertificationProfileLaunchExpectation::NoEngineExpected;
    let engine = CertificationProfileLaunchExpectation::EngineImportRequired;
    let mut expected = vec![
        expected_profile_invocation("pre/read_title_blocks", "read_title_blocks", offline),
        expected_profile_invocation("operation/write_title_block", "write_title_block", engine),
        expected_profile_invocation("post/read_title_blocks", "read_title_blocks", offline),
        expected_profile_invocation("post/list_layouts", "list_layouts", offline),
    ];
    if include_plot {
        expected.push(expected_profile_invocation(
            "plot/plot_to_pdf",
            "plot_to_pdf",
            engine,
        ));
    }
    expected
}

fn expected_xref_profile_isolation(
    case: &XrefCertificationCase,
    evidence_class: XrefCertificationEvidenceClass,
) -> Result<Vec<ExpectedCertificationProfileInvocation>> {
    let offline = CertificationProfileLaunchExpectation::NoEngineExpected;
    let operation_expectation =
        xref_certification_profile_launch_expectation(case, evidence_class)?;
    Ok(vec![
        expected_profile_invocation("pre/list_xrefs", "list_xrefs", offline),
        expected_profile_invocation("pre/list_xref_instances", "list_xref_instances", offline),
        expected_profile_invocation("pre/list_blocks", "list_blocks", offline),
        expected_profile_invocation("operation", case.operation.as_str(), operation_expectation),
        expected_profile_invocation("post/list_xrefs", "list_xrefs", offline),
        expected_profile_invocation("post/list_xref_instances", "list_xref_instances", offline),
        expected_profile_invocation("post/list_blocks", "list_blocks", offline),
    ])
}

fn expected_layer_profile_isolation(
    case: &LayerMutationCertificationCase,
    staged_drawing_sha256: &str,
    operations: &[LayerMutationOperationEvidence],
) -> Result<Vec<ExpectedCertificationProfileInvocation>> {
    let offline = CertificationProfileLaunchExpectation::NoEngineExpected;
    let mut expected = vec![
        expected_profile_invocation("initial/list_layers", "list_layers", offline),
        expected_profile_invocation(
            "initial/list_xref_dependencies",
            "list_xref_dependencies",
            offline,
        ),
    ];
    let mut previous_state_key = expected_layer_state_key(staged_drawing_sha256, case);
    for (index, operation) in case.operations.iter().enumerate() {
        expected.push(expected_profile_invocation(
            format!("operation/{}", operation.operation_id),
            operation.tool.as_str(),
            layer_certification_profile_launch_expectation(operation)?,
        ));
        let Some(actual_operation) = operations.get(index) else {
            continue;
        };
        let state_key = expected_layer_state_key(&actual_operation.output_drawing_sha256, case);
        if state_key != previous_state_key {
            expected.push(expected_profile_invocation(
                format!("readback/{}/list_layers", operation.operation_id),
                "list_layers",
                offline,
            ));
            expected.push(expected_profile_invocation(
                format!("readback/{}/list_xref_dependencies", operation.operation_id),
                "list_xref_dependencies",
                offline,
            ));
        }
        previous_state_key = state_key;
    }
    Ok(expected)
}

fn validate_profile_isolation_evidence(
    location: &str,
    expected: &[ExpectedCertificationProfileInvocation],
    actual: &[CertificationProfileIsolationEvidence],
    errors: &mut Vec<String>,
) {
    if actual.len() != expected.len() {
        errors.push(format!(
            "{location} profile_isolation invocation count {}, expected {}",
            actual.len(),
            expected.len()
        ));
    }
    for (index, (expected, actual)) in expected.iter().zip(actual).enumerate() {
        let row_location = format!("{location} profile_isolation[{index}]");
        if actual.invocation_id != expected.invocation_id {
            errors.push(format!(
                "{row_location} invocation_id {:?} does not match expected {:?}",
                actual.invocation_id, expected.invocation_id
            ));
        }
        if actual.tool != expected.tool {
            errors.push(format!(
                "{row_location} tool {:?} does not match expected {:?}",
                actual.tool, expected.tool
            ));
        }
        if actual.expectation != expected.expectation {
            errors.push(format!(
                "{row_location} expectation {:?} does not match the closed classification {:?}",
                actual.expectation, expected.expectation
            ));
        }
        if !actual.absent_before {
            errors.push(format!(
                "{row_location} must prove the profile key absent_before"
            ));
        }
        let expected_present_after =
            expected.expectation == CertificationProfileLaunchExpectation::EngineImportRequired;
        if actual.present_after != expected_present_after {
            errors.push(format!(
                "{row_location} present_after does not match the closed launch expectation"
            ));
        }
        if actual.cleanup_performed != actual.present_after {
            errors.push(format!(
                "{row_location} cleanup_performed must equal present_after"
            ));
        }
        if !actual.absent_after {
            errors.push(format!(
                "{row_location} must prove the profile key absent_after"
            ));
        }
    }
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationRuntimeEvidence {
    pub activation_target: CertificationActivationTarget,
    pub platform: String,
    pub release_binary_path: String,
    pub release_binary_canonical_path: String,
    pub release_binary_sha256_before: String,
    pub release_binary_sha256_after: String,
    pub accoreconsole_path: String,
    pub accoreconsole_canonical_path: String,
    pub accoreconsole_sha256_before: String,
    pub accoreconsole_sha256_after: String,
    pub certified_arg_path: String,
    pub certified_arg_canonical_path: String,
    pub certified_arg_sha256_before: String,
    pub certified_arg_sha256_after: String,
    pub certified_arg_policy_id: String,
    pub certified_arg_policy_sha256: String,
    pub observed_autocad_product: String,
    pub observed_autocad_version: String,
    pub binary_build_identity: XrefCertificationBuildIdentity,
    pub binary_reported_certified_arg_sha256: String,
    pub binary_reported_certified_arg_policy_id: String,
    pub binary_reported_certified_arg_policy_sha256: String,
    pub binary_reported_title_block_profile_registry_sha256: String,
    pub binary_reported_title_block_profiles: Vec<CertificationProfileDefinition>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tier2ProfileCertificationEvidence {
    pub schema_version: u32,
    pub evidence_class: CertificationEvidenceClass,
    pub release_id: String,
    pub status: CertificationResultStatus,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub reason: Option<String>,
    pub manifest_sha256: String,
    pub runtime: CertificationRuntimeEvidence,
    pub fixture_root_canonical_path: String,
    pub drawings: Vec<Tier2DrawingCertificationEvidence>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tier2DrawingCertificationEvidence {
    pub drawing_id: String,
    pub path: String,
    pub source_sha256: String,
    pub staged_case_root_canonical_path: String,
    pub staged_drawing_canonical_path: String,
    pub staged_drawing_sha256: String,
    pub final_drawing_sha256: String,
    pub status: CertificationResultStatus,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub reason: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub observed_profile_id: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub observed_fingerprint: Option<CertificationTitleBlockFingerprint>,
    pub pre_title_blocks: CertificationTitleBlockSnapshot,
    pub post_title_blocks: CertificationTitleBlockSnapshot,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub observed_layouts: Option<Vec<String>>,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub plot: Option<CertificationPlotEvidence>,
    pub profile_isolation: Vec<CertificationProfileIsolationEvidence>,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationTitleBlockFingerprint {
    pub block_name: String,
    pub attribute_tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationTitleBlockSnapshot {
    pub records: Vec<CertificationHashedTitleBlockRecord>,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationHashedTitleBlockRecord {
    pub normalized_block_name: String,
    pub layer_sha256: String,
    pub attributes: Vec<CertificationHashedTitleBlockAttribute>,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationHashedTitleBlockAttribute {
    pub tag: String,
    pub value_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationPlotEvidence {
    pub layout: String,
    pub output_canonical_path: String,
    pub pdf_sha256: String,
    pub pdf_size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerMutationCertificationEvidence {
    pub schema_version: u32,
    pub evidence_class: CertificationEvidenceClass,
    pub release_id: String,
    pub status: CertificationResultStatus,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub reason: Option<String>,
    pub manifest_sha256: String,
    pub runtime: CertificationRuntimeEvidence,
    pub fixture_root_canonical_path: String,
    pub cases: Vec<LayerMutationCaseEvidence>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerMutationCaseEvidence {
    pub case_id: String,
    pub drawing_id: String,
    pub path: String,
    pub source_sha256: String,
    pub staged_case_root_canonical_path: String,
    pub staged_drawing_canonical_path: String,
    pub staged_drawing_sha256: String,
    pub final_drawing_sha256: String,
    pub status: CertificationResultStatus,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub reason: Option<String>,
    pub referenced_sources: Vec<CertificationReferencedSourceEvidence>,
    pub initial_state_key_sha256: String,
    pub initial_readback_sha256: String,
    pub readback_snapshots: Vec<LayerConfinementSnapshotEvidence>,
    pub operations: Vec<LayerMutationOperationEvidence>,
    pub profile_isolation: Vec<CertificationProfileIsolationEvidence>,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationReferencedSourceEvidence {
    pub path: String,
    pub source_sha256: String,
    pub staged_canonical_path: String,
    pub before_sha256: String,
    pub after_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationResolvedSourceEvidence {
    pub manifest_path: String,
    pub canonical_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationLayerStateSource {
    pub manifest_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerConfinementSnapshotEvidence {
    pub state_key_sha256: String,
    pub host_drawing_sha256: String,
    pub layers: Vec<CertificationExpandedLayerRecord>,
    pub dependency_graph: XrefDependencyTraversalEnvelope,
    pub resolved_sources: Vec<CertificationResolvedSourceEvidence>,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationLayerToolObservation {
    pub result: CertificationLayerObservedResult,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CertificationLayerObservedResult {
    ListLayers {
        records: Vec<CertificationExpandedLayerRecord>,
    },
    Layer {
        record: CertificationExpandedLayerRecord,
    },
    DeletedIdentity {
        handle: String,
        name: String,
    },
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerMutationOperationEvidence {
    pub operation_id: String,
    pub tool: LayerMutationCertificationTool,
    #[schemars(with = "LayerCertificationParamsSchema")]
    pub params: serde_json::Value,
    pub status: CertificationResultStatus,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub reason: Option<String>,
    pub observed_tool_status: CertificationObservedToolStatus,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub observed_error_code: Option<String>,
    pub input_drawing_sha256: String,
    pub output_drawing_sha256: String,
    #[serde(deserialize_with = "deserialize_required_nullable_certification")]
    #[schemars(required)]
    pub actual_output: Option<CertificationLayerToolObservation>,
    pub persisted_state_key_sha256: String,
    pub persisted_readback_sha256: String,
}

impl CertificationManifest {
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|error| anyhow::anyhow!("invalid certification manifest: {error}"))
    }
}

/// Fixed authority boundary carried by the serialized manifest preflight
/// summary.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsCertificationManifestPreflightAuthority {
    DevelopmentPreflightOnly,
}

/// Development-only result of validating the two public Windows certification
/// manifest declarations without inspecting their referenced files or running
/// AutoCAD.
///
/// This summary proves only that the exact input bytes are valid UTF-8, parse
/// through the closed schema-v3 and schema-v4 manifest types, satisfy their
/// in-memory semantic validators, and agree on their shared runtime
/// declarations. It is not certification evidence.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCertificationManifestPreflightSummary {
    pub authority: WindowsCertificationManifestPreflightAuthority,
    pub schema_v3_release_id: String,
    pub schema_v4_release_id: String,
    pub schema_v3_manifest_sha256: String,
    pub schema_v4_manifest_sha256: String,
    pub activation_target: CertificationActivationTarget,
    pub release_binary_path: String,
    pub release_binary_sha256: String,
    pub accoreconsole_path: String,
    pub accoreconsole_sha256: String,
    pub autocad_product: String,
    pub autocad_version: String,
    pub certified_arg_path: String,
    pub certified_arg_sha256: String,
    pub certified_arg_policy_id: String,
    pub certified_arg_policy_sha256: String,
    pub title_block_profile_registry_sha256: String,
}

/// Validates the exact bytes of the schema-v3 and schema-v4 Windows
/// certification manifests as a development preflight.
///
/// The function deliberately performs no filesystem access, does not invoke
/// AutoCAD, and does not validate or produce certification evidence.
pub fn validate_windows_certification_manifest_preflight(
    schema_v3_json_bytes: &[u8],
    schema_v4_json_bytes: &[u8],
) -> Result<WindowsCertificationManifestPreflightSummary> {
    let schema_v3_json = std::str::from_utf8(schema_v3_json_bytes).map_err(|error| {
        anyhow::anyhow!("schema-v3 certification manifest is not UTF-8: {error}")
    })?;
    let schema_v4_json = std::str::from_utf8(schema_v4_json_bytes).map_err(|error| {
        anyhow::anyhow!("schema-v4 XREF certification manifest is not UTF-8: {error}")
    })?;
    let schema_v3 = CertificationManifest::from_json(schema_v3_json)?;
    let schema_v4 = XrefCertificationManifest::from_json(schema_v4_json)?;

    let mut join_errors = Vec::new();
    if schema_v3.runtime.activation_target != schema_v4.activation_target {
        join_errors
            .push("schema-v3/schema-v4 activation_target declarations do not match".to_string());
    }
    for (label, schema_v3_value, schema_v4_value) in [
        (
            "release_binary_path",
            schema_v3.runtime.release_binary_path.as_str(),
            schema_v4.release_binary_path.as_str(),
        ),
        (
            "release_binary_sha256",
            schema_v3.runtime.release_binary_sha256.as_str(),
            schema_v4.release_binary_sha256.as_str(),
        ),
        (
            "accoreconsole_path",
            schema_v3.runtime.accoreconsole_path.as_str(),
            schema_v4.accoreconsole_path.as_str(),
        ),
        (
            "accoreconsole_sha256",
            schema_v3.runtime.accoreconsole_sha256.as_str(),
            schema_v4.accoreconsole_sha256.as_str(),
        ),
        (
            "autocad_product",
            schema_v3.runtime.autocad_product.as_str(),
            schema_v4.autocad_product.as_str(),
        ),
        (
            "autocad_version",
            schema_v3.runtime.autocad_version.as_str(),
            schema_v4.autocad_version.as_str(),
        ),
        (
            "certified_arg_path",
            schema_v3.runtime.certified_arg_path.as_str(),
            schema_v4.certified_arg_path.as_str(),
        ),
        (
            "certified_arg_sha256",
            schema_v3.runtime.certified_arg_sha256.as_str(),
            schema_v4.certified_arg_sha256.as_str(),
        ),
        (
            "certified_arg_policy_id",
            schema_v3.runtime.certified_arg_policy_id.as_str(),
            schema_v4.certified_arg_policy_id.as_str(),
        ),
        (
            "certified_arg_policy_sha256",
            schema_v3.runtime.certified_arg_policy_sha256.as_str(),
            schema_v4.certified_arg_policy_sha256.as_str(),
        ),
    ] {
        if schema_v3_value != schema_v4_value {
            join_errors.push(format!(
                "schema-v3/schema-v4 {label} declarations do not match"
            ));
        }
    }
    finish_xref_validation(join_errors)?;

    let embedded_profiles = embedded_certification_profile_definitions();
    validate_release_manifest(&schema_v3, &embedded_profiles, true)
        .map_err(|error| anyhow::anyhow!("schema-v3 release manifest preflight failed: {error}"))?;
    validate_layer_mutation_manifest(&schema_v3).map_err(|error| {
        anyhow::anyhow!("schema-v3 layer mutation manifest preflight failed: {error}")
    })?;
    validate_xref_certification_manifest(&schema_v4)
        .map_err(|error| anyhow::anyhow!("schema-v4 XREF manifest preflight failed: {error}"))?;

    let embedded_title_registry_sha256 = profiles::title_block_profile_registry_sha256();
    if schema_v3.runtime.title_block_profile_registry_sha256 != embedded_title_registry_sha256 {
        return Err(anyhow::anyhow!(
            "schema-v3 title_block_profile_registry_sha256 is stale; it does not match the current embedded registry"
        ));
    }

    Ok(WindowsCertificationManifestPreflightSummary {
        authority: WindowsCertificationManifestPreflightAuthority::DevelopmentPreflightOnly,
        schema_v3_release_id: schema_v3.release_id,
        schema_v4_release_id: schema_v4.release_id,
        schema_v3_manifest_sha256: xref_sha256_bytes(schema_v3_json_bytes),
        schema_v4_manifest_sha256: xref_sha256_bytes(schema_v4_json_bytes),
        activation_target: schema_v3.runtime.activation_target,
        release_binary_path: schema_v3.runtime.release_binary_path,
        release_binary_sha256: schema_v3.runtime.release_binary_sha256,
        accoreconsole_path: schema_v3.runtime.accoreconsole_path,
        accoreconsole_sha256: schema_v3.runtime.accoreconsole_sha256,
        autocad_product: schema_v3.runtime.autocad_product,
        autocad_version: schema_v3.runtime.autocad_version,
        certified_arg_path: schema_v3.runtime.certified_arg_path,
        certified_arg_sha256: schema_v3.runtime.certified_arg_sha256,
        certified_arg_policy_id: schema_v3.runtime.certified_arg_policy_id,
        certified_arg_policy_sha256: schema_v3.runtime.certified_arg_policy_sha256,
        title_block_profile_registry_sha256: embedded_title_registry_sha256,
    })
}

impl Tier2ProfileCertificationEvidence {
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|error| {
            anyhow::anyhow!("invalid Tier 2 profile certification evidence: {error}")
        })
    }
}

impl LayerMutationCertificationEvidence {
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|error| {
            anyhow::anyhow!("invalid layer mutation certification evidence: {error}")
        })
    }
}

pub fn certification_manifest_sha256(bytes: &[u8]) -> String {
    xref_sha256_bytes(bytes)
}

#[derive(Serialize)]
struct CertificationTitleValueHashInput<'a> {
    schema_version: u32,
    release_id: &'a str,
    drawing_id: &'a str,
    tag: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct CertificationTitleLayerHashInput<'a> {
    schema_version: u32,
    release_id: &'a str,
    drawing_id: &'a str,
    layer: &'a str,
}

#[derive(Serialize)]
struct CertificationLayerStateKeyHashInput<'a> {
    host_drawing_sha256: &'a str,
    sources: &'a [CertificationLayerStateSource],
}

#[derive(Serialize)]
struct LayerConfinementSnapshotHashInput<'a> {
    state_key_sha256: &'a str,
    host_drawing_sha256: &'a str,
    layers: &'a [CertificationExpandedLayerRecord],
    dependency_graph: &'a XrefDependencyTraversalEnvelope,
    resolved_sources: &'a [CertificationResolvedSourceEvidence],
}

fn certification_typed_sha256(domain: &str, value: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(value).expect("closed certification value serializes");
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Hashes one exact title-block attribute value without placing that value in
/// certification evidence. The release, drawing, and normalized tag context
/// prevents accidental cross-case digest reuse.
pub fn certification_title_value_sha256(
    release_id: &str,
    drawing_id: &str,
    normalized_tag: &str,
    value: &str,
) -> String {
    certification_typed_sha256(
        "autocad-mcp/certification/title-value/v1",
        &CertificationTitleValueHashInput {
            schema_version: CERTIFICATION_SCHEMA_VERSION,
            release_id,
            drawing_id,
            tag: normalized_tag,
            value,
        },
    )
}

/// Hashes a title-block layer value using the same case-specific privacy
/// boundary as title attribute values.
pub fn certification_title_layer_sha256(release_id: &str, drawing_id: &str, layer: &str) -> String {
    certification_typed_sha256(
        "autocad-mcp/certification/title-layer/v1",
        &CertificationTitleLayerHashInput {
            schema_version: CERTIFICATION_SCHEMA_VERSION,
            release_id,
            drawing_id,
            layer,
        },
    )
}

/// Hashes the exact closed, canonically ordered title-block observation rows.
pub fn certification_title_snapshot_sha256(
    records: &[CertificationHashedTitleBlockRecord],
) -> String {
    certification_typed_sha256("autocad-mcp/certification/title-snapshot/v1", &records)
}

/// Hashes the exact closed canonical tool-result projection.
pub fn certification_layer_output_sha256(result: &CertificationLayerObservedResult) -> String {
    certification_typed_sha256("autocad-mcp/certification/layer-output/v1", result)
}

/// Hashes a persisted host/source content key. Sources must be sorted by their
/// manifest-relative path and unique before calling this helper.
pub fn certification_layer_state_key_sha256(
    host_drawing_sha256: &str,
    sources: &[CertificationLayerStateSource],
) -> String {
    certification_typed_sha256(
        "autocad-mcp/certification/layer-state-key/v1",
        &CertificationLayerStateKeyHashInput {
            host_drawing_sha256,
            sources,
        },
    )
}

/// Hashes a complete typed confinement/readback snapshot, excluding its own
/// `sha256` field.
pub fn certification_layer_readback_sha256(snapshot: &LayerConfinementSnapshotEvidence) -> String {
    certification_typed_sha256(
        "autocad-mcp/certification/layer-readback/v1",
        &LayerConfinementSnapshotHashInput {
            state_key_sha256: &snapshot.state_key_sha256,
            host_drawing_sha256: &snapshot.host_drawing_sha256,
            layers: &snapshot.layers,
            dependency_graph: &snapshot.dependency_graph,
            resolved_sources: &snapshot.resolved_sources,
        },
    )
}

pub fn validate_release_manifest(
    manifest: &CertificationManifest,
    supported_profiles: &[CertificationProfileDefinition],
    require_plotting: bool,
) -> Result<()> {
    let mut errors = Vec::new();
    validate_certification_manifest_common(manifest, &mut errors);

    validate_certification_profile_definitions(supported_profiles, &mut errors);

    if manifest.tier2_drawings.is_empty() {
        errors.push("manifest has no Tier 2 drawings".to_string());
    }
    let drawing_ids: Vec<_> = manifest
        .tier2_drawings
        .iter()
        .map(|drawing| drawing.drawing_id.as_str())
        .collect();
    validate_sorted_unique_keys("Tier 2 drawings by drawing_id", &drawing_ids, &mut errors);
    let supported_by_id: BTreeMap<_, _> = supported_profiles
        .iter()
        .map(|profile| (profile.profile_id.as_str(), profile))
        .collect();
    let mut witnesses = BTreeMap::<&str, usize>::new();
    let mut has_plot_layout = false;

    for drawing in &manifest.tier2_drawings {
        validate_id(
            &drawing.drawing_id,
            "Tier 2 drawing drawing_id",
            &mut errors,
        );
        validate_relative_dwg_fixture_path(
            &drawing.path,
            &format!("Tier 2 drawing '{}'", drawing.drawing_id),
            &mut errors,
        );
        validate_xref_digest(
            &format!("Tier 2 drawing '{}' source_sha256", drawing.drawing_id),
            &drawing.source_sha256,
            &mut errors,
        );
        validate_nonempty_trimmed(
            &drawing.expected_profile_id,
            &format!(
                "Tier 2 drawing '{}' expected_profile_id",
                drawing.drawing_id
            ),
            &mut errors,
        );
        let Some(profile) = supported_by_id.get(drawing.expected_profile_id.as_str()) else {
            errors.push(format!(
                "Tier 2 drawing '{}' references unknown supported profile '{}'",
                drawing.drawing_id, drawing.expected_profile_id
            ));
            continue;
        };
        *witnesses
            .entry(drawing.expected_profile_id.as_str())
            .or_default() += 1;
        if drawing.write_fields.is_empty() {
            errors.push(format!(
                "Tier 2 drawing '{}' write_fields must not be empty",
                drawing.drawing_id
            ));
        }
        let write_field_names: Vec<_> = drawing
            .write_fields
            .iter()
            .map(|write| write.field.as_str())
            .collect();
        validate_sorted_unique_keys(
            &format!("Tier 2 drawing '{}' write_fields", drawing.drawing_id),
            &write_field_names,
            &mut errors,
        );
        for write in &drawing.write_fields {
            validate_field_name(
                &write.field,
                &format!("Tier 2 drawing '{}' write field", drawing.drawing_id),
                &mut errors,
            );
            if !profile
                .field_mappings
                .iter()
                .any(|mapping| mapping.canonical_field == write.field)
            {
                errors.push(format!(
                    "Tier 2 drawing '{}' uses unknown canonical field '{}'",
                    drawing.drawing_id, write.field
                ));
            }
            if write.value.trim().is_empty() || write.value != write.value.trim() {
                errors.push(format!(
                    "Tier 2 drawing '{}' write field '{}' value must be non-empty and trimmed",
                    drawing.drawing_id, write.field
                ));
            }
        }
        let requested_tags = drawing
            .write_fields
            .iter()
            .filter_map(|write| {
                profile
                    .field_mappings
                    .iter()
                    .find(|mapping| mapping.canonical_field == write.field)
                    .map(|mapping| mapping.attribute_tag.as_str())
            })
            .collect::<BTreeSet<_>>();
        if profile
            .fingerprint
            .attribute_tags
            .iter()
            .all(|tag| requested_tags.contains(tag.as_str()))
        {
            errors.push(format!(
                "Tier 2 drawing '{}' must leave at least one fingerprint attribute unrequested",
                drawing.drawing_id
            ));
        }
        if let Some(layout) = &drawing.plot_layout {
            validate_nonempty_trimmed(
                layout,
                &format!("Tier 2 drawing '{}' plot_layout", drawing.drawing_id),
                &mut errors,
            );
            has_plot_layout = true;
        }
    }
    for profile in supported_profiles {
        match witnesses
            .get(profile.profile_id.as_str())
            .copied()
            .unwrap_or(0)
        {
            1 => {}
            0 => errors.push(format!(
                "missing Tier 2 drawing for supported profile '{}'",
                profile.profile_id
            )),
            count => errors.push(format!(
                "supported profile '{}' requires exactly one Tier 2 drawing, found {count}",
                profile.profile_id
            )),
        }
    }
    if require_plotting && !has_plot_layout {
        errors.push("plotting claim requires at least one plot_layout".to_string());
    }
    validate_distinct_manifest_fixture_paths(manifest, &mut errors);
    finish_xref_validation(errors)
}

pub fn validate_layer_mutation_manifest(manifest: &CertificationManifest) -> Result<()> {
    let mut errors = Vec::new();
    validate_certification_manifest_common(manifest, &mut errors);
    if manifest.layer_mutation_cases.is_empty() {
        errors.push("manifest has no layer mutation certification cases".to_string());
    }
    let case_ids: Vec<_> = manifest
        .layer_mutation_cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect();
    validate_sorted_unique_keys("layer mutation cases by case_id", &case_ids, &mut errors);

    let mut passed_mutations = BTreeSet::new();
    let mut writable_field_coverage = BTreeSet::new();
    let mut lineweight_coverage = BTreeSet::new();
    let mut xref_override_coverage = BTreeSet::new();
    let mut failure_codes = BTreeSet::new();
    let mut has_expanded_record = false;
    let mut passed_read_tools = BTreeSet::new();

    for case in &manifest.layer_mutation_cases {
        let location = format!("layer mutation case '{}'", case.case_id);
        validate_id(&case.case_id, &format!("{location} case_id"), &mut errors);
        validate_id(
            &case.drawing_id,
            &format!("{location} drawing_id"),
            &mut errors,
        );
        validate_relative_dwg_fixture_path(&case.path, &location, &mut errors);
        validate_xref_digest(
            &format!("{location} source_sha256"),
            &case.source_sha256,
            &mut errors,
        );
        let reference_paths: Vec<_> = case
            .referenced_source_fixtures
            .iter()
            .map(|fixture| fixture.path.as_str())
            .collect();
        validate_sorted_unique_keys(
            &format!("{location} referenced_source_fixtures"),
            &reference_paths,
            &mut errors,
        );
        match case.fixture_kind {
            LayerCertificationFixtureKind::HostOwned
                if !case.referenced_source_fixtures.is_empty() =>
            {
                errors.push(format!(
                    "{location} fixture_kind=host_owned requires no referenced source fixtures"
                ));
            }
            LayerCertificationFixtureKind::XrefDependentHost
                if case.referenced_source_fixtures.is_empty() =>
            {
                errors.push(format!(
                    "{location} fixture_kind=xref_dependent_host requires referenced source fixtures"
                ));
            }
            _ => {}
        }
        for fixture in &case.referenced_source_fixtures {
            validate_relative_dwg_fixture_path(&fixture.path, &location, &mut errors);
            validate_xref_digest(
                &format!(
                    "{location} referenced fixture '{}' source_sha256",
                    fixture.path
                ),
                &fixture.source_sha256,
                &mut errors,
            );
        }
        if case.operations.is_empty() {
            errors.push(format!("{location} has no operations"));
        }
        let operation_ids: Vec<_> = case
            .operations
            .iter()
            .map(|operation| operation.operation_id.as_str())
            .collect();
        validate_sorted_unique_keys(
            &format!("{location} operations by operation_id"),
            &operation_ids,
            &mut errors,
        );

        for operation in &case.operations {
            let operation_location = format!(
                "{location} operation '{}:{}'",
                operation.tool.as_str(),
                operation.operation_id
            );
            validate_id(
                &operation.operation_id,
                &format!("{operation_location} operation_id"),
                &mut errors,
            );
            let params =
                validate_layer_operation_params(operation, &operation_location, &mut errors);
            validate_layer_operation_expectation(
                operation,
                params.as_ref(),
                &operation_location,
                &mut errors,
            );

            match &operation.expected {
                LayerCertificationExpectedOutcome::Passed { assertion } => {
                    match (operation.tool, assertion) {
                        (
                            LayerMutationCertificationTool::ListLayers,
                            LayerCertificationPassedAssertion::ExpandedRecords { .. },
                        ) => {
                            passed_read_tools.insert(operation.tool);
                        }
                        (
                            LayerMutationCertificationTool::GetLayer,
                            LayerCertificationPassedAssertion::Layer { layer },
                        ) if layer_expectation_is_exact(layer) => {
                            passed_read_tools.insert(operation.tool);
                        }
                        (
                            LayerMutationCertificationTool::ListLayers
                            | LayerMutationCertificationTool::GetLayer,
                            _,
                        ) => errors.push(format!(
                            "{operation_location} must assert an exact 17-field read witness"
                        )),
                        _ => {}
                    }
                    if operation.tool.is_mutation() {
                        passed_mutations.insert(operation.tool);
                    }
                    if matches!(
                        assertion,
                        LayerCertificationPassedAssertion::ExpandedRecords { .. }
                    ) {
                        has_expanded_record = true;
                    }
                    if let Some(properties) = params
                        .as_ref()
                        .and_then(ParsedLayerCertificationParams::properties)
                    {
                        for field in properties.writable_fields() {
                            writable_field_coverage.insert(field);
                        }
                        if let Some(line_weight) = properties.line_weight {
                            lineweight_coverage.insert(line_weight.coverage_key());
                        }
                        if case.fixture_kind == LayerCertificationFixtureKind::XrefDependentHost
                            && operation.tool == LayerMutationCertificationTool::UpdateLayer
                            && properties.writable_fields().len() == 1
                        {
                            let assertion_proves_xref = matches!(
                                assertion,
                                LayerCertificationPassedAssertion::Layer { layer }
                                    if layer.xref_dependent.matches_value(&true)
                            );
                            if assertion_proves_xref {
                                xref_override_coverage.insert(properties.writable_fields()[0]);
                            } else {
                                errors.push(format!(
                                    "{operation_location} xref-dependent override assertion must include xref_dependent=true"
                                ));
                            }
                        }
                    }
                }
                LayerCertificationExpectedOutcome::Failed { error_code, .. } => {
                    validate_nonempty_trimmed(
                        error_code,
                        &format!("{operation_location} error_code"),
                        &mut errors,
                    );
                    failure_codes.insert(error_code.as_str());
                }
            }
        }
    }

    for tool in [
        LayerMutationCertificationTool::CreateLayer,
        LayerMutationCertificationTool::UpdateLayer,
        LayerMutationCertificationTool::RenameLayer,
        LayerMutationCertificationTool::DeleteLayer,
    ] {
        if !passed_mutations.contains(&tool) {
            errors.push(format!(
                "layer mutation certification lacks a passing {} operation",
                tool.as_str()
            ));
        }
    }
    for field in LAYER_WRITABLE_FIELDS {
        if !writable_field_coverage.contains(field) {
            errors.push(format!(
                "layer mutation certification lacks passing writable-field coverage for '{field}'"
            ));
        }
        if !xref_override_coverage.contains(field) {
            errors.push(format!(
                "layer mutation certification lacks property-by-property xref-dependent override coverage for '{field}'"
            ));
        }
    }
    for variant in ["by_layer", "by_block", "default", "value"] {
        if !lineweight_coverage.contains(variant) {
            errors.push(format!(
                "layer mutation certification lacks structured lineweight variant '{variant}'"
            ));
        }
    }
    if !has_expanded_record {
        errors.push(
            "layer mutation certification lacks an exact expanded 17-field record witness"
                .to_string(),
        );
    }
    for tool in [
        LayerMutationCertificationTool::ListLayers,
        LayerMutationCertificationTool::GetLayer,
    ] {
        if !passed_read_tools.contains(&tool) {
            errors.push(format!(
                "layer mutation certification lacks a passing exact 17-field {} witness",
                tool.as_str()
            ));
        }
    }
    for error_code in LAYER_REQUIRED_FAILURE_CODES {
        if !failure_codes.contains(error_code) {
            errors.push(format!(
                "layer mutation certification lacks exact negative outcome '{error_code}'"
            ));
        }
    }
    validate_distinct_manifest_fixture_paths(manifest, &mut errors);
    finish_xref_validation(errors)
}

pub fn validate_tier2_profile_certification_evidence(
    manifest: &CertificationManifest,
    supported_profiles: &[CertificationProfileDefinition],
    require_plotting: bool,
    manifest_sha256: &str,
    evidence: &Tier2ProfileCertificationEvidence,
) -> Result<()> {
    let mut errors = Vec::new();
    if let Err(error) = validate_release_manifest(manifest, supported_profiles, require_plotting) {
        errors.push(error.to_string());
    }
    validate_certification_evidence_header(
        manifest,
        manifest_sha256,
        CertificationEvidenceClass::Tier2Profile,
        CertificationEvidenceHeaderRef {
            schema_version: evidence.schema_version,
            evidence_class: evidence.evidence_class,
            release_id: &evidence.release_id,
            status: evidence.status,
            reason: evidence.reason.as_deref(),
            manifest_sha256: &evidence.manifest_sha256,
            runtime: &evidence.runtime,
        },
        &mut errors,
    );
    if evidence.runtime.binary_reported_title_block_profiles != supported_profiles {
        errors.push(
            "binary-reported title-block profile definitions do not match the validated release inventory"
                .to_string(),
        );
    }
    validate_certification_fixture_root_binding(
        manifest,
        &evidence.fixture_root_canonical_path,
        "Tier 2 evidence",
        &mut errors,
    );
    if evidence.drawings.len() != manifest.tier2_drawings.len() {
        errors.push("Tier 2 evidence drawing inventory does not match manifest".to_string());
    }
    for (index, expected) in manifest.tier2_drawings.iter().enumerate() {
        let Some(actual) = evidence.drawings.get(index) else {
            continue;
        };
        let location = format!("Tier 2 evidence drawing '{}'", expected.drawing_id);
        if actual.drawing_id != expected.drawing_id
            || actual.path != expected.path
            || actual.source_sha256 != expected.source_sha256
        {
            errors.push(format!(
                "{location} identity/input binding does not match manifest"
            ));
        }
        if actual.status != CertificationResultStatus::Passed || actual.reason.is_some() {
            errors.push(format!("{location} must be passed with reason=null"));
        }
        let expected_profile_isolation =
            expected_tier2_profile_isolation(expected.plot_layout.is_some());
        validate_profile_isolation_evidence(
            &location,
            &expected_profile_isolation,
            &actual.profile_isolation,
            &mut errors,
        );
        validate_absolute_certification_directory_path(
            &actual.staged_case_root_canonical_path,
            &format!("{location} staged_case_root_canonical_path"),
            &mut errors,
        );
        if certification_paths_overlap(
            &actual.staged_case_root_canonical_path,
            &evidence.fixture_root_canonical_path,
        ) {
            errors.push(format!(
                "{location} staged case root overlaps the private fixture root"
            ));
        }
        validate_absolute_certification_file_path(
            &actual.staged_drawing_canonical_path,
            &format!("{location} staged_drawing_canonical_path"),
            &mut errors,
        );
        if !certification_path_is_strictly_below(
            &actual.staged_drawing_canonical_path,
            &actual.staged_case_root_canonical_path,
        ) {
            errors.push(format!(
                "{location} staged drawing is not strictly below the staged case root"
            ));
        }
        if !certification_path_matches_staged_fixture(
            &actual.staged_drawing_canonical_path,
            &actual.staged_case_root_canonical_path,
            &expected.path,
        ) {
            errors.push(format!(
                "{location} staged drawing path does not preserve the manifest-relative fixture path"
            ));
        }
        validate_digest_equality(
            &format!("{location} staged_drawing_sha256"),
            &actual.staged_drawing_sha256,
            &expected.source_sha256,
            &mut errors,
        );
        validate_xref_digest(
            &format!("{location} final_drawing_sha256"),
            &actual.final_drawing_sha256,
            &mut errors,
        );
        if actual.final_drawing_sha256 == actual.staged_drawing_sha256 {
            errors.push(format!(
                "{location} write certification did not change the staged drawing digest"
            ));
        }

        if actual.observed_profile_id.as_deref() != Some(expected.expected_profile_id.as_str()) {
            errors.push(format!(
                "{location} observed_profile_id does not match manifest"
            ));
        }
        let expected_profile = supported_profiles
            .iter()
            .find(|profile| profile.profile_id == expected.expected_profile_id);
        let Some(fingerprint) = &actual.observed_fingerprint else {
            errors.push(format!("{location} is missing observed_fingerprint"));
            continue;
        };
        validate_nonempty_trimmed(
            &fingerprint.block_name,
            &format!("{location} fingerprint block_name"),
            &mut errors,
        );
        validate_sorted_unique_nonempty_strings(
            &format!("{location} fingerprint attribute_tags"),
            &fingerprint.attribute_tags,
            &mut errors,
        );
        if expected_profile.is_none_or(|profile| fingerprint != &profile.fingerprint) {
            errors.push(format!(
                "{location} observed_fingerprint does not match supported profile definition"
            ));
        }
        if let Some(expected_profile) = expected_profile {
            validate_title_block_snapshots(
                &manifest.release_id,
                expected,
                expected_profile,
                supported_profiles,
                actual,
                &location,
                &mut errors,
            );
        }
        let Some(layouts) = &actual.observed_layouts else {
            errors.push(format!("{location} is missing observed_layouts"));
            continue;
        };
        validate_sorted_unique_nonempty_strings(
            &format!("{location} observed_layouts"),
            layouts,
            &mut errors,
        );
        match (&expected.plot_layout, &actual.plot) {
            (None, None) => {}
            (None, Some(_)) => {
                errors.push(format!("{location} has unexpected plot evidence"));
            }
            (Some(_), None) => errors.push(format!("{location} is missing plot evidence")),
            (Some(expected_layout), Some(plot)) => {
                if plot.layout != *expected_layout || !layouts.contains(expected_layout) {
                    errors.push(format!("{location} plot layout does not match manifest"));
                }
                validate_absolute_certification_file_path(
                    &plot.output_canonical_path,
                    &format!("{location} plot output_canonical_path"),
                    &mut errors,
                );
                if !certification_path_is_strictly_below(
                    &plot.output_canonical_path,
                    &actual.staged_case_root_canonical_path,
                ) {
                    errors.push(format!(
                        "{location} plot output is not strictly below the staged case root"
                    ));
                }
                if certification_path_key(&plot.output_canonical_path)
                    == certification_path_key(&actual.staged_drawing_canonical_path)
                    || !certification_path_key(&plot.output_canonical_path)
                        .and_then(|path| path.components.last().cloned())
                        .is_some_and(|name| name.ends_with(".pdf"))
                {
                    errors.push(format!(
                        "{location} plot output must be a distinct canonical .pdf file"
                    ));
                }
                validate_xref_digest(
                    &format!("{location} plot pdf_sha256"),
                    &plot.pdf_sha256,
                    &mut errors,
                );
                if plot.pdf_size_bytes == 0 {
                    errors.push(format!("{location} plot PDF is empty"));
                }
            }
        }
    }
    finish_xref_validation(errors)
}

/// Reopens the private plot artifacts retained beside Tier-2 evidence and binds
/// their exact bytes to the serialized attestation.
///
/// This is intentionally separate from the portable structural validator:
/// certification paths are Windows paths and the private artifacts remain on
/// the certification host rather than entering a release package.
pub fn validate_tier2_profile_certification_artifacts(
    evidence: &Tier2ProfileCertificationEvidence,
) -> Result<()> {
    let mut errors = Vec::new();
    for drawing in &evidence.drawings {
        let Some(plot) = &drawing.plot else {
            continue;
        };
        let location = format!("Tier 2 drawing '{}' retained plot", drawing.drawing_id);
        let path = Path::new(&plot.output_canonical_path);
        let metadata_before = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                errors.push(format!("{location} cannot be inspected: {error}"));
                continue;
            }
        };
        if metadata_before.file_type().is_symlink() || !metadata_before.is_file() {
            errors.push(format!(
                "{location} must be a retained regular non-symlink file"
            ));
            continue;
        }
        let canonical_before = match path.canonicalize() {
            Ok(path) => path,
            Err(error) => {
                errors.push(format!("{location} cannot be canonicalized: {error}"));
                continue;
            }
        };
        if canonical_before.to_str().and_then(certification_path_key)
            != certification_path_key(&plot.output_canonical_path)
        {
            errors.push(format!(
                "{location} canonical identity does not match serialized evidence"
            ));
        }
        let bytes = match std::fs::read(&canonical_before) {
            Ok(bytes) => bytes,
            Err(error) => {
                errors.push(format!("{location} cannot be read: {error}"));
                continue;
            }
        };
        if bytes.len() as u64 != metadata_before.len() || bytes.len() as u64 != plot.pdf_size_bytes
        {
            errors.push(format!(
                "{location} byte length does not match serialized evidence"
            ));
        }
        if xref_sha256_bytes(&bytes) != plot.pdf_sha256 {
            errors.push(format!(
                "{location} SHA-256 does not match serialized evidence"
            ));
        }
        if !bytes.starts_with(b"%PDF-") {
            errors.push(format!("{location} does not have a PDF header"));
        }
        let tail_start = bytes.len().saturating_sub(1024);
        if !bytes[tail_start..]
            .windows(b"%%EOF".len())
            .any(|window| window == b"%%EOF")
        {
            errors.push(format!("{location} does not have a PDF EOF marker"));
        }
        let canonical_after = path.canonicalize().ok();
        let digest_after = xref_sha256_file(path).ok();
        if canonical_after.as_ref() != Some(&canonical_before)
            || digest_after.as_deref() != Some(plot.pdf_sha256.as_str())
        {
            errors.push(format!(
                "{location} pathname identity or bytes changed while it was verified"
            ));
        }
    }
    finish_xref_validation(errors)
}

pub fn validate_layer_mutation_evidence(
    manifest: &CertificationManifest,
    manifest_sha256: &str,
    evidence: &LayerMutationCertificationEvidence,
) -> Result<()> {
    let mut errors = Vec::new();
    if let Err(error) = validate_layer_mutation_manifest(manifest) {
        errors.push(error.to_string());
    }
    validate_certification_evidence_header(
        manifest,
        manifest_sha256,
        CertificationEvidenceClass::LayerMutation,
        CertificationEvidenceHeaderRef {
            schema_version: evidence.schema_version,
            evidence_class: evidence.evidence_class,
            release_id: &evidence.release_id,
            status: evidence.status,
            reason: evidence.reason.as_deref(),
            manifest_sha256: &evidence.manifest_sha256,
            runtime: &evidence.runtime,
        },
        &mut errors,
    );
    validate_certification_fixture_root_binding(
        manifest,
        &evidence.fixture_root_canonical_path,
        "layer evidence",
        &mut errors,
    );
    if evidence.cases.len() != manifest.layer_mutation_cases.len() {
        errors.push("layer evidence case inventory does not match manifest".to_string());
    }
    for (case_index, expected_case) in manifest.layer_mutation_cases.iter().enumerate() {
        let Some(actual_case) = evidence.cases.get(case_index) else {
            continue;
        };
        let location = format!("layer evidence case '{}'", expected_case.case_id);
        if actual_case.case_id != expected_case.case_id
            || actual_case.drawing_id != expected_case.drawing_id
            || actual_case.path != expected_case.path
            || actual_case.source_sha256 != expected_case.source_sha256
        {
            errors.push(format!(
                "{location} identity/input binding does not match manifest"
            ));
        }
        if actual_case.status != CertificationResultStatus::Passed || actual_case.reason.is_some() {
            errors.push(format!("{location} must be passed with reason=null"));
        }
        validate_absolute_certification_directory_path(
            &actual_case.staged_case_root_canonical_path,
            &format!("{location} staged_case_root_canonical_path"),
            &mut errors,
        );
        if certification_paths_overlap(
            &actual_case.staged_case_root_canonical_path,
            &evidence.fixture_root_canonical_path,
        ) {
            errors.push(format!(
                "{location} staged case root overlaps the private fixture root"
            ));
        }
        validate_absolute_certification_file_path(
            &actual_case.staged_drawing_canonical_path,
            &format!("{location} staged_drawing_canonical_path"),
            &mut errors,
        );
        if !certification_path_is_strictly_below(
            &actual_case.staged_drawing_canonical_path,
            &actual_case.staged_case_root_canonical_path,
        ) {
            errors.push(format!(
                "{location} staged drawing is not strictly below the staged case root"
            ));
        }
        if !certification_path_matches_staged_fixture(
            &actual_case.staged_drawing_canonical_path,
            &actual_case.staged_case_root_canonical_path,
            &expected_case.path,
        ) {
            errors.push(format!(
                "{location} staged drawing path does not preserve the manifest-relative fixture path"
            ));
        }
        validate_digest_equality(
            &format!("{location} staged_drawing_sha256"),
            &actual_case.staged_drawing_sha256,
            &expected_case.source_sha256,
            &mut errors,
        );
        validate_layer_reference_evidence(expected_case, actual_case, &location, &mut errors);
        let snapshots =
            validate_layer_readback_snapshots(expected_case, actual_case, &location, &mut errors);
        let mut referenced_readback_sha256 =
            BTreeSet::from([actual_case.initial_readback_sha256.as_str()]);
        let initial_expected_state_key =
            expected_layer_state_key(&actual_case.staged_drawing_sha256, expected_case);
        match expected_layer_profile_isolation(
            expected_case,
            &actual_case.staged_drawing_sha256,
            &actual_case.operations,
        ) {
            Ok(expected_profile_isolation) => validate_profile_isolation_evidence(
                &location,
                &expected_profile_isolation,
                &actual_case.profile_isolation,
                &mut errors,
            ),
            Err(error) => errors.push(format!(
                "{location} cannot derive a closed profile-isolation inventory: {error}"
            )),
        }
        validate_digest_equality(
            &format!("{location} initial_state_key_sha256"),
            &actual_case.initial_state_key_sha256,
            &initial_expected_state_key,
            &mut errors,
        );
        let initial_snapshot = snapshots
            .by_sha256
            .get(actual_case.initial_readback_sha256.as_str())
            .copied();
        match initial_snapshot {
            Some(snapshot) if snapshot.state_key_sha256 == actual_case.initial_state_key_sha256 => {
            }
            Some(_) => errors.push(format!(
                "{location} initial readback does not match initial state key"
            )),
            None => errors.push(format!(
                "{location} initial_readback_sha256 does not name a recorded snapshot"
            )),
        }
        if actual_case.operations.len() != expected_case.operations.len() {
            errors.push(format!(
                "{location} operation inventory does not match manifest"
            ));
        }
        let mut previous_digest = actual_case.staged_drawing_sha256.as_str();
        let mut previous_state_key = actual_case.initial_state_key_sha256.as_str();
        let mut previous_readback = actual_case.initial_readback_sha256.as_str();
        let mut previous_snapshot = initial_snapshot;
        for (operation_index, expected_operation) in expected_case.operations.iter().enumerate() {
            let Some(actual_operation) = actual_case.operations.get(operation_index) else {
                continue;
            };
            let operation_location =
                format!("{location} operation '{}'", expected_operation.operation_id);
            if actual_operation.operation_id != expected_operation.operation_id
                || actual_operation.tool != expected_operation.tool
                || actual_operation.params != expected_operation.params
            {
                errors.push(format!(
                    "{operation_location} identity/tool/params do not match manifest"
                ));
            }
            if actual_operation.status != CertificationResultStatus::Passed
                || actual_operation.reason.is_some()
            {
                errors.push(format!(
                    "{operation_location} must be passed with reason=null"
                ));
            }
            validate_digest_equality(
                &format!("{operation_location} input_drawing_sha256"),
                &actual_operation.input_drawing_sha256,
                previous_digest,
                &mut errors,
            );
            validate_xref_digest(
                &format!("{operation_location} output_drawing_sha256"),
                &actual_operation.output_drawing_sha256,
                &mut errors,
            );
            let expected_state_key =
                expected_layer_state_key(&actual_operation.output_drawing_sha256, expected_case);
            validate_digest_equality(
                &format!("{operation_location} persisted_state_key_sha256"),
                &actual_operation.persisted_state_key_sha256,
                &expected_state_key,
                &mut errors,
            );
            validate_xref_digest(
                &format!("{operation_location} persisted_readback_sha256"),
                &actual_operation.persisted_readback_sha256,
                &mut errors,
            );
            referenced_readback_sha256.insert(actual_operation.persisted_readback_sha256.as_str());
            let persisted_snapshot = snapshots
                .by_sha256
                .get(actual_operation.persisted_readback_sha256.as_str())
                .copied();
            match persisted_snapshot {
                Some(snapshot)
                    if snapshot.state_key_sha256
                        == actual_operation.persisted_state_key_sha256 => {}
                Some(_) => errors.push(format!(
                    "{operation_location} persisted readback does not match persisted state key"
                )),
                None => errors.push(format!(
                    "{operation_location} persisted_readback_sha256 does not name a recorded snapshot"
                )),
            }
            if actual_operation.persisted_state_key_sha256 == previous_state_key
                && actual_operation.persisted_readback_sha256 != previous_readback
            {
                errors.push(format!(
                    "{operation_location} unchanged digest key must reuse the preceding readback"
                ));
            }
            validate_layer_observed_outcome(
                expected_operation,
                actual_operation,
                previous_snapshot,
                persisted_snapshot,
                &operation_location,
                &mut errors,
            );
            previous_digest = actual_operation.output_drawing_sha256.as_str();
            previous_state_key = actual_operation.persisted_state_key_sha256.as_str();
            previous_readback = actual_operation.persisted_readback_sha256.as_str();
            previous_snapshot = persisted_snapshot;
        }
        let recorded_readback_sha256 = snapshots.by_sha256.keys().copied().collect::<BTreeSet<_>>();
        if recorded_readback_sha256 != referenced_readback_sha256 {
            errors.push(format!(
                "{location} readback snapshot inventory must equal exactly the initial and operation-referenced digests"
            ));
        }
        if actual_case.final_drawing_sha256 != previous_digest {
            errors.push(format!(
                "{location} final_drawing_sha256 does not close the operation digest chain"
            ));
        }
        validate_xref_digest(
            &format!("{location} final_drawing_sha256"),
            &actual_case.final_drawing_sha256,
            &mut errors,
        );
    }
    finish_xref_validation(errors)
}

fn validate_certification_manifest_common(
    manifest: &CertificationManifest,
    errors: &mut Vec<String>,
) {
    if manifest.schema_version != CERTIFICATION_SCHEMA_VERSION {
        errors.push(format!(
            "certification manifest schema_version {} is unsupported; expected {}",
            manifest.schema_version, CERTIFICATION_SCHEMA_VERSION
        ));
    }
    validate_id(&manifest.release_id, "certification release_id", errors);
    validate_absolute_certification_directory_path(
        &manifest.fixture_root,
        "certification fixture_root",
        errors,
    );
    let runtime = &manifest.runtime;
    for (label, path) in [
        ("release_binary_path", runtime.release_binary_path.as_str()),
        ("accoreconsole_path", runtime.accoreconsole_path.as_str()),
        ("certified_arg_path", runtime.certified_arg_path.as_str()),
    ] {
        validate_absolute_certification_file_path(
            path,
            &format!("certification runtime {label}"),
            errors,
        );
    }
    if !certification_path_has_autocad_engine_shape(
        &runtime.accoreconsole_path,
        &runtime.autocad_version,
    ) {
        errors.push(
            "certification runtime accoreconsole_path must identify accoreconsole.exe under an AutoCAD-labelled path component declaring the expected version"
                .to_string(),
        );
    }
    for (label, digest) in [
        (
            "release_binary_sha256",
            runtime.release_binary_sha256.as_str(),
        ),
        (
            "title_block_profile_registry_sha256",
            runtime.title_block_profile_registry_sha256.as_str(),
        ),
        (
            "accoreconsole_sha256",
            runtime.accoreconsole_sha256.as_str(),
        ),
        (
            "certified_arg_sha256",
            runtime.certified_arg_sha256.as_str(),
        ),
        (
            "certified_arg_policy_sha256",
            runtime.certified_arg_policy_sha256.as_str(),
        ),
    ] {
        validate_xref_digest(&format!("certification runtime {label}"), digest, errors);
    }
    validate_certified_arg_policy_id(
        &runtime.certified_arg_policy_id,
        "certification runtime certified_arg_policy_id",
        errors,
    );
    validate_nonempty_trimmed(
        &runtime.autocad_product,
        "certification runtime autocad_product",
        errors,
    );
    validate_nonempty_trimmed(
        &runtime.autocad_version,
        "certification runtime autocad_version",
        errors,
    );
    validate_certification_activation_target(
        &runtime.activation_target,
        CertificationActivationClaim {
            autocad_product: &runtime.autocad_product,
            autocad_version: &runtime.autocad_version,
            certified_arg_sha256: &runtime.certified_arg_sha256,
            certified_arg_policy_id: &runtime.certified_arg_policy_id,
            certified_arg_policy_sha256: &runtime.certified_arg_policy_sha256,
        },
        &[
            MutationCapability::DwgLayerMutation,
            MutationCapability::DwgTitleBlockMutation,
            MutationCapability::Plot,
        ],
        "certification runtime activation_target",
        errors,
    );
}

fn validate_certification_profile_definitions(
    profiles: &[CertificationProfileDefinition],
    errors: &mut Vec<String>,
) {
    if profiles.is_empty() {
        errors.push("release manifest validation has no supported profiles".to_string());
    }
    let profile_ids: Vec<_> = profiles
        .iter()
        .map(|profile| profile.profile_id.as_str())
        .collect();
    validate_sorted_unique_keys("supported profile definitions", &profile_ids, errors);
    for profile in profiles {
        let location = format!("certification profile '{}'", profile.profile_id);
        validate_nonempty_trimmed(&profile.profile_id, "certification profile_id", errors);
        if profile.field_mappings.is_empty() {
            errors.push(format!("{location} field_mappings must not be empty"));
        }
        let fields: Vec<_> = profile
            .field_mappings
            .iter()
            .map(|mapping| mapping.canonical_field.as_str())
            .collect();
        validate_sorted_unique_keys(&format!("{location} field_mappings"), &fields, errors);
        let mut mapped_tags = BTreeSet::new();
        for mapping in &profile.field_mappings {
            validate_field_name(
                &mapping.canonical_field,
                &format!("{location} canonical_field"),
                errors,
            );
            validate_normalized_title_identity(
                &mapping.attribute_tag,
                &format!("{location} attribute_tag"),
                errors,
            );
            if !mapped_tags.insert(mapping.attribute_tag.as_str()) {
                errors.push(format!(
                    "{location} maps more than one canonical field to attribute tag '{}'",
                    mapping.attribute_tag
                ));
            }
        }
        validate_normalized_title_identity(
            &profile.fingerprint.block_name,
            &format!("{location} fingerprint block_name"),
            errors,
        );
        validate_sorted_unique_nonempty_strings(
            &format!("{location} fingerprint attribute_tags"),
            &profile.fingerprint.attribute_tags,
            errors,
        );
        for tag in &profile.fingerprint.attribute_tags {
            validate_normalized_title_identity(
                tag,
                &format!("{location} fingerprint attribute_tag"),
                errors,
            );
        }
        for tag in mapped_tags {
            if !profile
                .fingerprint
                .attribute_tags
                .iter()
                .any(|fingerprint_tag| fingerprint_tag == tag)
            {
                errors.push(format!(
                    "{location} maps attribute tag '{tag}' outside its fingerprint"
                ));
            }
        }
    }
}

fn validate_normalized_title_identity(value: &str, label: &str, errors: &mut Vec<String>) {
    validate_nonempty_trimmed(value, label, errors);
    if value.to_uppercase() != value {
        errors.push(format!("{label} must be normalized uppercase"));
    }
}

fn title_record_matches_profile(
    record: &CertificationHashedTitleBlockRecord,
    profile: &CertificationProfileDefinition,
) -> bool {
    record.normalized_block_name == profile.fingerprint.block_name
        && record
            .attributes
            .iter()
            .map(|attribute| attribute.tag.as_str())
            .eq(profile
                .fingerprint
                .attribute_tags
                .iter()
                .map(String::as_str))
}

fn title_snapshot_matching_profile_ids<'a>(
    snapshot: &CertificationTitleBlockSnapshot,
    supported_profiles: &'a [CertificationProfileDefinition],
) -> BTreeSet<&'a str> {
    supported_profiles
        .iter()
        .filter(|profile| {
            snapshot
                .records
                .iter()
                .any(|record| title_record_matches_profile(record, profile))
        })
        .map(|profile| profile.profile_id.as_str())
        .collect()
}

fn validate_title_block_snapshots(
    release_id: &str,
    expected: &CertificationDrawing,
    profile: &CertificationProfileDefinition,
    supported_profiles: &[CertificationProfileDefinition],
    actual: &Tier2DrawingCertificationEvidence,
    location: &str,
    errors: &mut Vec<String>,
) {
    validate_title_block_snapshot(
        &actual.pre_title_blocks,
        &format!("{location} pre_title_blocks"),
        errors,
    );
    validate_title_block_snapshot(
        &actual.post_title_blocks,
        &format!("{location} post_title_blocks"),
        errors,
    );
    if actual.pre_title_blocks.sha256 == actual.post_title_blocks.sha256 {
        errors.push(format!(
            "{location} pre/post title-block snapshots are identical"
        ));
    }
    let expected_profile_ids = BTreeSet::from([profile.profile_id.as_str()]);
    for (label, snapshot) in [
        ("pre_title_blocks", &actual.pre_title_blocks),
        ("post_title_blocks", &actual.post_title_blocks),
    ] {
        let matching_profile_ids =
            title_snapshot_matching_profile_ids(snapshot, supported_profiles);
        if matching_profile_ids != expected_profile_ids {
            errors.push(format!(
                "{location} {label} resolves supported profiles {matching_profile_ids:?}; expected exactly {:?}",
                profile.profile_id
            ));
        }
    }

    let requested_tags = expected
        .write_fields
        .iter()
        .filter_map(|write| {
            profile
                .field_mappings
                .iter()
                .find(|mapping| mapping.canonical_field == write.field)
                .map(|mapping| {
                    (
                        mapping.attribute_tag.as_str(),
                        certification_title_value_sha256(
                            release_id,
                            &expected.drawing_id,
                            &mapping.attribute_tag,
                            &write.value,
                        ),
                    )
                })
        })
        .collect::<BTreeMap<_, _>>();
    if requested_tags.len() != expected.write_fields.len() {
        errors.push(format!(
            "{location} cannot map every requested canonical field to one unique attribute tag"
        ));
    }

    let is_target = |record: &CertificationHashedTitleBlockRecord| {
        title_record_matches_profile(record, profile)
    };
    let pre_targets = actual
        .pre_title_blocks
        .records
        .iter()
        .filter(|record| is_target(record))
        .collect::<Vec<_>>();
    let post_targets = actual
        .post_title_blocks
        .records
        .iter()
        .filter(|record| is_target(record))
        .collect::<Vec<_>>();
    if pre_targets.is_empty() || pre_targets.len() != post_targets.len() {
        errors.push(format!(
            "{location} must preserve a nonempty exact-profile target record inventory"
        ));
    }

    for record in &pre_targets {
        for (tag, expected_hash) in &requested_tags {
            match record
                .attributes
                .iter()
                .find(|attribute| attribute.tag == *tag)
            {
                Some(attribute) if attribute.value_sha256 != *expected_hash => {}
                Some(_) => errors.push(format!(
                    "{location} requested tag '{tag}' was already at its expected value before mutation"
                )),
                None => errors.push(format!(
                    "{location} pre-write target is missing requested tag '{tag}'"
                )),
            }
        }
    }
    for record in &post_targets {
        for (tag, expected_hash) in &requested_tags {
            match record
                .attributes
                .iter()
                .find(|attribute| attribute.tag == *tag)
            {
                Some(attribute) if attribute.value_sha256 == *expected_hash => {}
                _ => errors.push(format!(
                    "{location} post-write target does not contain the expected hash for tag '{tag}'"
                )),
            }
        }
    }

    let target_projection = |record: &&CertificationHashedTitleBlockRecord| {
        let mut projected = (*record).clone();
        projected
            .attributes
            .retain(|attribute| !requested_tags.contains_key(attribute.tag.as_str()));
        projected
    };
    let mut pre_unrequested = pre_targets
        .iter()
        .map(target_projection)
        .collect::<Vec<_>>();
    let mut post_unrequested = post_targets
        .iter()
        .map(target_projection)
        .collect::<Vec<_>>();
    sort_title_records(&mut pre_unrequested);
    sort_title_records(&mut post_unrequested);
    if pre_unrequested
        .iter()
        .all(|record| record.attributes.is_empty())
    {
        errors.push(format!(
            "{location} must observe at least one unrequested target attribute"
        ));
    }
    if pre_unrequested != post_unrequested {
        errors.push(format!(
            "{location} unrequested target attributes or target identities changed"
        ));
    }

    let mut pre_non_targets = actual
        .pre_title_blocks
        .records
        .iter()
        .filter(|record| !is_target(record))
        .cloned()
        .collect::<Vec<_>>();
    let mut post_non_targets = actual
        .post_title_blocks
        .records
        .iter()
        .filter(|record| !is_target(record))
        .cloned()
        .collect::<Vec<_>>();
    if pre_non_targets.is_empty() {
        errors.push(format!(
            "{location} must observe at least one non-target attributed record"
        ));
    }
    sort_title_records(&mut pre_non_targets);
    sort_title_records(&mut post_non_targets);
    if pre_non_targets != post_non_targets {
        errors.push(format!(
            "{location} non-target title-block observations changed"
        ));
    }
}

fn validate_title_block_snapshot(
    snapshot: &CertificationTitleBlockSnapshot,
    location: &str,
    errors: &mut Vec<String>,
) {
    validate_digest_equality(
        &format!("{location} sha256"),
        &snapshot.sha256,
        &certification_title_snapshot_sha256(&snapshot.records),
        errors,
    );
    if snapshot.records.windows(2).any(|pair| {
        serde_json::to_vec(&pair[0]).expect("title record serializes")
            > serde_json::to_vec(&pair[1]).expect("title record serializes")
    }) {
        errors.push(format!("{location} records must be canonically sorted"));
    }
    for (index, record) in snapshot.records.iter().enumerate() {
        let record_location = format!("{location} record[{index}]");
        validate_normalized_title_identity(
            &record.normalized_block_name,
            &format!("{record_location} normalized_block_name"),
            errors,
        );
        validate_xref_digest(
            &format!("{record_location} layer_sha256"),
            &record.layer_sha256,
            errors,
        );
        let tags: Vec<_> = record
            .attributes
            .iter()
            .map(|attribute| attribute.tag.as_str())
            .collect();
        validate_sorted_unique_keys(&format!("{record_location} attributes"), &tags, errors);
        for attribute in &record.attributes {
            validate_normalized_title_identity(
                &attribute.tag,
                &format!("{record_location} attribute tag"),
                errors,
            );
            validate_xref_digest(
                &format!("{record_location} attribute value_sha256"),
                &attribute.value_sha256,
                errors,
            );
        }
    }
}

fn sort_title_records(records: &mut [CertificationHashedTitleBlockRecord]) {
    records.sort_by_cached_key(|record| {
        serde_json::to_vec(record).expect("title-block record serializes")
    });
}

struct CertificationEvidenceHeaderRef<'a> {
    schema_version: u32,
    evidence_class: CertificationEvidenceClass,
    release_id: &'a str,
    status: CertificationResultStatus,
    reason: Option<&'a str>,
    manifest_sha256: &'a str,
    runtime: &'a CertificationRuntimeEvidence,
}

fn validate_certification_evidence_header(
    manifest: &CertificationManifest,
    expected_manifest_sha256: &str,
    expected_class: CertificationEvidenceClass,
    actual: CertificationEvidenceHeaderRef<'_>,
    errors: &mut Vec<String>,
) {
    if actual.schema_version != CERTIFICATION_SCHEMA_VERSION {
        errors.push(format!(
            "certification evidence schema_version {} is unsupported; expected {}",
            actual.schema_version, CERTIFICATION_SCHEMA_VERSION
        ));
    }
    if actual.evidence_class != expected_class {
        errors.push(format!(
            "certification evidence has wrong evidence_class: expected {expected_class:?}"
        ));
    }
    if actual.release_id != manifest.release_id {
        errors.push("certification evidence release_id does not match manifest".to_string());
    }
    if actual.status != CertificationResultStatus::Passed || actual.reason.is_some() {
        errors.push("release certification evidence must be passed with reason=null".to_string());
    }
    validate_xref_digest(
        "expected certification manifest_sha256",
        expected_manifest_sha256,
        errors,
    );
    if actual.manifest_sha256 != expected_manifest_sha256 {
        errors.push("certification evidence manifest_sha256 is stale".to_string());
    }
    validate_certification_runtime_evidence(&manifest.runtime, actual.runtime, errors);
}

fn validate_certification_runtime_evidence(
    expected: &CertificationRuntimeRequirements,
    actual: &CertificationRuntimeEvidence,
    errors: &mut Vec<String>,
) {
    if actual.activation_target != expected.activation_target {
        errors.push("certification runtime activation_target does not match manifest".to_string());
    }
    if actual.platform != "windows" {
        errors.push("certification runtime platform must be windows".to_string());
    }
    for (label, configured, required, canonical, before, after, expected_digest) in [
        (
            "release binary",
            actual.release_binary_path.as_str(),
            expected.release_binary_path.as_str(),
            actual.release_binary_canonical_path.as_str(),
            actual.release_binary_sha256_before.as_str(),
            actual.release_binary_sha256_after.as_str(),
            expected.release_binary_sha256.as_str(),
        ),
        (
            "accoreconsole",
            actual.accoreconsole_path.as_str(),
            expected.accoreconsole_path.as_str(),
            actual.accoreconsole_canonical_path.as_str(),
            actual.accoreconsole_sha256_before.as_str(),
            actual.accoreconsole_sha256_after.as_str(),
            expected.accoreconsole_sha256.as_str(),
        ),
        (
            "certified ARG",
            actual.certified_arg_path.as_str(),
            expected.certified_arg_path.as_str(),
            actual.certified_arg_canonical_path.as_str(),
            actual.certified_arg_sha256_before.as_str(),
            actual.certified_arg_sha256_after.as_str(),
            expected.certified_arg_sha256.as_str(),
        ),
    ] {
        if configured != required {
            errors.push(format!(
                "certification runtime configured {label} path does not match manifest"
            ));
        }
        validate_absolute_certification_file_path(
            canonical,
            &format!("certification runtime canonical {label} path"),
            errors,
        );
        let configured_key = certification_path_key(configured);
        let canonical_key = certification_path_key(canonical);
        if configured_key
            .as_ref()
            .zip(canonical_key.as_ref())
            .is_none_or(|(configured, canonical)| configured != canonical)
        {
            errors.push(format!(
                "certification runtime configured and canonical {label} paths do not identify the same Windows path"
            ));
        }
        validate_digest_equality(
            &format!("certification runtime {label} SHA-256 before"),
            before,
            expected_digest,
            errors,
        );
        validate_digest_equality(
            &format!("certification runtime {label} SHA-256 after"),
            after,
            expected_digest,
            errors,
        );
    }
    if !certification_path_has_autocad_engine_shape(
        &actual.accoreconsole_canonical_path,
        &expected.autocad_version,
    ) {
        errors.push(
            "certification runtime canonical accoreconsole path does not identify accoreconsole.exe under an AutoCAD-labelled path component declaring the expected version"
                .to_string(),
        );
    }
    if actual.observed_autocad_product != expected.autocad_product
        || actual.observed_autocad_version != expected.autocad_version
    {
        errors.push("observed AutoCAD product/version does not match manifest".to_string());
    }
    validate_xref_build_identity(
        "certification release build identity",
        &actual.binary_build_identity,
        false,
        errors,
    );
    if !actual.binary_build_identity.target.contains("windows") {
        errors.push("certification release build identity target must be Windows".to_string());
    }
    if actual.certified_arg_policy_id != expected.certified_arg_policy_id
        || actual.certified_arg_policy_sha256 != expected.certified_arg_policy_sha256
    {
        errors.push(
            "certification runtime certified ARG policy identity does not match manifest"
                .to_string(),
        );
    }
    if actual.binary_build_identity.certified_arg_sha256 != expected.certified_arg_sha256
        || actual.binary_build_identity.certified_arg_policy_id != expected.certified_arg_policy_id
        || actual.binary_build_identity.certified_arg_policy_sha256
            != expected.certified_arg_policy_sha256
    {
        errors.push(
            "certification release build identity certified ARG/policy values do not match manifest"
                .to_string(),
        );
    }
    validate_digest_equality(
        "binary-reported certified ARG SHA-256",
        &actual.binary_reported_certified_arg_sha256,
        &expected.certified_arg_sha256,
        errors,
    );
    if actual.binary_reported_certified_arg_policy_id != expected.certified_arg_policy_id {
        errors.push("binary-reported certified ARG policy ID does not match manifest".to_string());
    }
    validate_digest_equality(
        "binary-reported certified ARG policy SHA-256",
        &actual.binary_reported_certified_arg_policy_sha256,
        &expected.certified_arg_policy_sha256,
        errors,
    );
    validate_digest_equality(
        "binary-reported title-block profile registry SHA-256",
        &actual.binary_reported_title_block_profile_registry_sha256,
        &expected.title_block_profile_registry_sha256,
        errors,
    );
    validate_certification_profile_definitions(
        &actual.binary_reported_title_block_profiles,
        errors,
    );
}

fn validate_layer_operation_expectation(
    operation: &LayerMutationCertificationOperation,
    params: Option<&ParsedLayerCertificationParams>,
    location: &str,
    errors: &mut Vec<String>,
) {
    let properties = params.and_then(ParsedLayerCertificationParams::properties);
    match &operation.expected {
        LayerCertificationExpectedOutcome::Passed { assertion } => {
            if properties.is_some_and(|properties| properties.plot_style.is_some()) {
                errors.push(format!(
                    "{location} plot_style is admitted only for the exact unsupported_layer_property negative case"
                ));
            }
            let assertion_matches = matches!(
                (operation.tool, assertion),
                (
                    LayerMutationCertificationTool::ListLayers,
                    LayerCertificationPassedAssertion::ExpandedRecords { .. }
                ) | (
                    LayerMutationCertificationTool::GetLayer,
                    LayerCertificationPassedAssertion::Layer { .. }
                ) | (
                    LayerMutationCertificationTool::CreateLayer
                        | LayerMutationCertificationTool::UpdateLayer
                        | LayerMutationCertificationTool::RenameLayer,
                    LayerCertificationPassedAssertion::Layer { .. }
                ) | (
                    LayerMutationCertificationTool::DeleteLayer,
                    LayerCertificationPassedAssertion::DeletedIdentity { .. }
                )
            );
            if !assertion_matches {
                errors.push(format!(
                    "{location} expected assertion kind does not match tool"
                ));
            }
            if let (Some(params), LayerCertificationPassedAssertion::Layer { layer }) =
                (params, assertion)
            {
                validate_layer_assertion_reflects_params(params, layer, location, errors);
            }
            if let (
                Some(ParsedLayerCertificationParams::Delete(params)),
                LayerCertificationPassedAssertion::DeletedIdentity { handle, name },
            ) = (params, assertion)
            {
                validate_selected_identity_reflected(
                    params.handle.as_deref(),
                    params.name.as_deref(),
                    handle,
                    name,
                    location,
                    errors,
                );
            }
            if let Some(properties) = properties {
                if let Some(LayerCertificationLineWeight::Value { hundredths_mm }) =
                    properties.line_weight
                {
                    if !is_standard_layer_lineweight(hundredths_mm) {
                        errors.push(format!(
                            "{location} passed line_weight value {hundredths_mm} is not a standard writable value"
                        ));
                    }
                }
            }
            validate_layer_passed_assertion(assertion, location, errors);
        }
        LayerCertificationExpectedOutcome::Failed {
            error_code,
            unchanged_layer,
        } => {
            validate_nonempty_trimmed(error_code, &format!("{location} error_code"), errors);
            validate_layer_expectation_nonempty(unchanged_layer, location, errors);
            let matches_negative_params = match error_code.as_str() {
                "line_type_not_found" => {
                    matches!(
                        operation.tool,
                        LayerMutationCertificationTool::CreateLayer
                            | LayerMutationCertificationTool::UpdateLayer
                    ) && properties.is_some_and(|properties| properties.line_type.is_some())
                }
                "invalid_line_weight" => {
                    operation.tool == LayerMutationCertificationTool::UpdateLayer
                        && properties.is_some_and(|properties| {
                            matches!(
                                properties.line_weight,
                                Some(LayerCertificationLineWeight::Value { hundredths_mm })
                                    if !is_standard_layer_lineweight(hundredths_mm)
                            )
                        })
                }
                "cannot_freeze_current_layer" => {
                    operation.tool == LayerMutationCertificationTool::UpdateLayer
                        && properties.is_some_and(|properties| properties.frozen == Some(true))
                        && unchanged_layer.is_current.matches_value(&true)
                }
                "unsupported_layer_property" => {
                    operation.tool == LayerMutationCertificationTool::UpdateLayer
                        && properties.is_some_and(|properties| {
                            properties.plot_style.is_some()
                                && properties.writable_fields().is_empty()
                        })
                }
                _ => true,
            };
            if !matches_negative_params {
                errors.push(format!(
                    "{location} exact negative error_code is not exercised by matching typed params"
                ));
            }
            if error_code != "unsupported_layer_property"
                && properties.is_some_and(|properties| properties.plot_style.is_some())
            {
                errors.push(format!(
                    "{location} plot_style requires error_code=unsupported_layer_property"
                ));
            }
        }
    }
}

fn validate_layer_passed_assertion(
    assertion: &LayerCertificationPassedAssertion,
    location: &str,
    errors: &mut Vec<String>,
) {
    match assertion {
        LayerCertificationPassedAssertion::ExpandedRecords { record } => {
            validate_nonempty_trimmed(&record.handle, &format!("{location} record handle"), errors);
            validate_nonempty_trimmed(&record.name, &format!("{location} record name"), errors);
            validate_nonempty_trimmed(
                &record.line_type,
                &format!("{location} record line_type"),
                errors,
            );
        }
        LayerCertificationPassedAssertion::Layer { layer } => {
            validate_layer_expectation_nonempty(layer, location, errors);
        }
        LayerCertificationPassedAssertion::DeletedIdentity { handle, name } => {
            validate_nonempty_trimmed(handle, &format!("{location} deleted handle"), errors);
            validate_nonempty_trimmed(name, &format!("{location} deleted name"), errors);
        }
    }
}

fn validate_layer_expectation_nonempty(
    layer: &LayerCertificationLayerExpectation,
    location: &str,
    errors: &mut Vec<String>,
) {
    if layer == &LayerCertificationLayerExpectation::default() {
        errors.push(format!("{location} layer expectation must not be empty"));
    }
}

fn layer_expectation_is_exact(layer: &LayerCertificationLayerExpectation) -> bool {
    !layer.handle.is_omitted()
        && !layer.name.is_omitted()
        && !layer.color_index.is_omitted()
        && !layer.line_type.is_omitted()
        && !layer.line_weight.is_omitted()
        && !layer.frozen.is_omitted()
        && !layer.locked.is_omitted()
        && !layer.off.is_omitted()
        && !layer.is_plottable.is_omitted()
        && !layer.xref_dependent.is_omitted()
        && !layer.xref_block_record_handle.is_omitted()
        && !layer.xref_name.is_omitted()
        && !layer.xref_path.is_omitted()
        && !layer.xref_is_overlay.is_omitted()
        && !layer.material_handle.is_omitted()
        && !layer.plotstyle_handle.is_omitted()
        && !layer.is_current.is_omitted()
}

fn validate_layer_assertion_reflects_params(
    params: &ParsedLayerCertificationParams,
    layer: &LayerCertificationLayerExpectation,
    location: &str,
    errors: &mut Vec<String>,
) {
    match params {
        ParsedLayerCertificationParams::Get(params) => {
            validate_selected_layer_reflected(
                params.handle.as_deref(),
                params.name.as_deref(),
                layer,
                location,
                errors,
            );
        }
        ParsedLayerCertificationParams::Create(params) => {
            if !layer.name.matches_value(&params.name) {
                errors.push(format!(
                    "{location} expected layer must reflect created name"
                ));
            }
            validate_layer_properties_reflected(&params.properties, layer, location, errors);
        }
        ParsedLayerCertificationParams::Update(params) => {
            validate_selected_layer_reflected(
                params.handle.as_deref(),
                params.name.as_deref(),
                layer,
                location,
                errors,
            );
            validate_layer_properties_reflected(&params.properties, layer, location, errors);
        }
        ParsedLayerCertificationParams::Rename(params) => {
            if !layer.name.matches_value(&params.new_name) {
                errors.push(format!("{location} expected layer must reflect new_name"));
            }
            if let Some(handle) = params.handle.as_deref() {
                if !layer.handle.matches_value(&handle.to_ascii_uppercase())
                    && !matches!(
                        &layer.handle,
                        CertificationFieldExpectation::Value(actual)
                            if actual.eq_ignore_ascii_case(handle)
                    )
                {
                    errors.push(format!(
                        "{location} expected layer must reflect selected handle"
                    ));
                }
            }
        }
        _ => {}
    }
}

fn validate_selected_layer_reflected(
    selected_handle: Option<&str>,
    selected_name: Option<&str>,
    layer: &LayerCertificationLayerExpectation,
    location: &str,
    errors: &mut Vec<String>,
) {
    if let Some(handle) = selected_handle {
        if !matches!(
            &layer.handle,
            CertificationFieldExpectation::Value(actual) if actual.eq_ignore_ascii_case(handle)
        ) {
            errors.push(format!(
                "{location} expected layer must reflect selected handle"
            ));
        }
    }
    if let Some(name) = selected_name {
        if !matches!(
            &layer.name,
            CertificationFieldExpectation::Value(actual) if actual.eq_ignore_ascii_case(name)
        ) {
            errors.push(format!(
                "{location} expected layer must reflect selected name"
            ));
        }
    }
}

fn validate_selected_identity_reflected(
    selected_handle: Option<&str>,
    selected_name: Option<&str>,
    actual_handle: &str,
    actual_name: &str,
    location: &str,
    errors: &mut Vec<String>,
) {
    if selected_handle.is_some_and(|handle| !actual_handle.eq_ignore_ascii_case(handle)) {
        errors.push(format!(
            "{location} deleted identity must reflect selected handle"
        ));
    }
    if selected_name.is_some_and(|name| !actual_name.eq_ignore_ascii_case(name)) {
        errors.push(format!(
            "{location} deleted identity must reflect selected name"
        ));
    }
}

fn is_standard_layer_lineweight(value: i16) -> bool {
    [
        0, 5, 9, 13, 15, 18, 20, 25, 30, 35, 40, 50, 53, 60, 70, 80, 90, 100, 106, 120, 140, 158,
        200, 211,
    ]
    .contains(&value)
}

fn validate_layer_properties_reflected(
    properties: &LayerCertificationProperties,
    layer: &LayerCertificationLayerExpectation,
    location: &str,
    errors: &mut Vec<String>,
) {
    let reflected = [
        (
            "color_index",
            properties
                .color_index
                .is_none_or(|value| layer.color_index.matches_value(&value)),
        ),
        (
            "frozen",
            properties
                .frozen
                .is_none_or(|value| layer.frozen.matches_value(&value)),
        ),
        (
            "locked",
            properties
                .locked
                .is_none_or(|value| layer.locked.matches_value(&value)),
        ),
        (
            "off",
            properties
                .off
                .is_none_or(|value| layer.off.matches_value(&value)),
        ),
        (
            "is_plottable",
            properties
                .is_plottable
                .is_none_or(|value| layer.is_plottable.matches_value(&value)),
        ),
        (
            "line_type",
            properties
                .line_type
                .as_ref()
                .is_none_or(|value| layer.line_type.matches_value(value)),
        ),
        (
            "line_weight",
            properties.line_weight.is_none_or(|value| {
                layer
                    .line_weight
                    .matches_value(&CertificationObservedLayerLineWeight::from(value))
            }),
        ),
    ];
    for (field, is_reflected) in reflected {
        if !is_reflected {
            errors.push(format!(
                "{location} requested property '{field}' is not reflected in expected layer"
            ));
        }
    }
}

#[derive(Debug)]
enum ParsedLayerCertificationParams {
    List(LayerListCertificationParams),
    Get(LayerGetCertificationParams),
    Create(LayerCreateCertificationParams),
    Update(LayerUpdateCertificationParams),
    Rename(LayerRenameCertificationParams),
    Delete(LayerDeleteCertificationParams),
}

impl ParsedLayerCertificationParams {
    fn properties(&self) -> Option<&LayerCertificationProperties> {
        match self {
            Self::Create(params) => Some(&params.properties),
            Self::Update(params) => Some(&params.properties),
            _ => None,
        }
    }

    fn selector(&self) -> Option<(Option<&str>, Option<&str>)> {
        match self {
            Self::Get(params) => Some((params.handle.as_deref(), params.name.as_deref())),
            Self::Update(params) => Some((params.handle.as_deref(), params.name.as_deref())),
            Self::Rename(params) => Some((params.handle.as_deref(), params.name.as_deref())),
            Self::Delete(params) => Some((params.handle.as_deref(), params.name.as_deref())),
            Self::List(_) | Self::Create(_) => None,
        }
    }
}

fn validate_layer_operation_params(
    operation: &LayerMutationCertificationOperation,
    location: &str,
    errors: &mut Vec<String>,
) -> Option<ParsedLayerCertificationParams> {
    macro_rules! parse {
        ($type:ty, $variant:ident) => {
            serde_json::from_value::<$type>(operation.params.clone())
                .map(ParsedLayerCertificationParams::$variant)
        };
    }
    let parsed = match operation.tool {
        LayerMutationCertificationTool::ListLayers => parse!(LayerListCertificationParams, List),
        LayerMutationCertificationTool::GetLayer => parse!(LayerGetCertificationParams, Get),
        LayerMutationCertificationTool::CreateLayer => {
            parse!(LayerCreateCertificationParams, Create)
        }
        LayerMutationCertificationTool::UpdateLayer => {
            parse!(LayerUpdateCertificationParams, Update)
        }
        LayerMutationCertificationTool::RenameLayer => {
            parse!(LayerRenameCertificationParams, Rename)
        }
        LayerMutationCertificationTool::DeleteLayer => {
            parse!(LayerDeleteCertificationParams, Delete)
        }
    };
    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            errors.push(format!("{location} params are not closed/valid: {error}"));
            return None;
        }
    };
    match &parsed {
        ParsedLayerCertificationParams::Get(params) => {
            validate_layer_selector(
                params.handle.as_deref(),
                params.name.as_deref(),
                None,
                None,
                location,
                errors,
            );
        }
        ParsedLayerCertificationParams::Create(params) => {
            if let Err(error) = validate_layer_name(&params.name) {
                errors.push(format!(
                    "{location} name is not a valid creatable layer name: {error}"
                ));
            }
            validate_layer_properties(&params.properties, location, errors);
        }
        ParsedLayerCertificationParams::Update(params) => {
            validate_layer_selector(
                params.handle.as_deref(),
                params.name.as_deref(),
                params.expected_handle.as_deref(),
                params.expected_name.as_deref(),
                location,
                errors,
            );
            validate_layer_properties(&params.properties, location, errors);
        }
        ParsedLayerCertificationParams::Rename(params) => {
            validate_layer_selector(
                params.handle.as_deref(),
                params.name.as_deref(),
                params.expected_handle.as_deref(),
                params.expected_name.as_deref(),
                location,
                errors,
            );
            if let Err(error) = validate_layer_name(&params.new_name) {
                errors.push(format!(
                    "{location} new_name is not a valid creatable layer name: {error}"
                ));
            }
        }
        ParsedLayerCertificationParams::Delete(params) => {
            validate_layer_selector(
                params.handle.as_deref(),
                params.name.as_deref(),
                params.expected_handle.as_deref(),
                params.expected_name.as_deref(),
                location,
                errors,
            );
        }
        ParsedLayerCertificationParams::List(_) => {}
    }
    Some(parsed)
}

fn validate_layer_selector(
    handle: Option<&str>,
    name: Option<&str>,
    expected_handle: Option<&str>,
    expected_name: Option<&str>,
    location: &str,
    errors: &mut Vec<String>,
) {
    if handle.is_none() && name.is_none() {
        errors.push(format!("{location} selector requires handle or name"));
    }
    for (label, value) in [("handle", handle), ("expected_handle", expected_handle)] {
        if let Some(value) = value {
            validate_canonical_layer_handle(value, &format!("{location} {label}"), errors);
        }
    }
    for (label, value) in [("name", name), ("expected_name", expected_name)] {
        if let Some(value) = value {
            validate_nonempty_trimmed(value, &format!("{location} {label}"), errors);
        }
    }
}

fn validate_layer_properties(
    properties: &LayerCertificationProperties,
    location: &str,
    errors: &mut Vec<String>,
) {
    if properties.is_empty() {
        errors.push(format!("{location} properties must not be empty"));
    }
    if properties
        .color_index
        .is_some_and(|color| !(1..=255).contains(&color))
    {
        errors.push(format!("{location} color_index must be from 1 to 255"));
    }
    if let Some(line_type) = &properties.line_type {
        validate_nonempty_trimmed(line_type, &format!("{location} line_type"), errors);
    }
    if let Some(plot_style) = &properties.plot_style {
        validate_nonempty_trimmed(plot_style, &format!("{location} plot_style"), errors);
    }
}

fn validate_layer_reference_evidence(
    expected_case: &LayerMutationCertificationCase,
    actual_case: &LayerMutationCaseEvidence,
    location: &str,
    errors: &mut Vec<String>,
) {
    if actual_case.referenced_sources.len() != expected_case.referenced_source_fixtures.len() {
        errors.push(format!(
            "{location} referenced-source inventory does not match manifest"
        ));
    }
    for (expected, actual) in expected_case
        .referenced_source_fixtures
        .iter()
        .zip(&actual_case.referenced_sources)
    {
        if actual.path != expected.path || actual.source_sha256 != expected.source_sha256 {
            errors.push(format!(
                "{location} referenced source '{}' does not match manifest",
                expected.path
            ));
        }
        validate_absolute_certification_file_path(
            &actual.staged_canonical_path,
            &format!("{location} referenced source canonical path"),
            errors,
        );
        if !certification_path_is_strictly_below(
            &actual.staged_canonical_path,
            &actual_case.staged_case_root_canonical_path,
        ) {
            errors.push(format!(
                "{location} referenced source '{}' is not strictly below the staged case root",
                expected.path
            ));
        }
        if !certification_path_matches_staged_fixture(
            &actual.staged_canonical_path,
            &actual_case.staged_case_root_canonical_path,
            &expected.path,
        ) {
            errors.push(format!(
                "{location} referenced source '{}' path does not preserve the manifest-relative fixture path",
                expected.path
            ));
        }
        for (label, digest) in [
            ("before_sha256", actual.before_sha256.as_str()),
            ("after_sha256", actual.after_sha256.as_str()),
        ] {
            validate_digest_equality(
                &format!("{location} referenced source '{}' {label}", expected.path),
                digest,
                &expected.source_sha256,
                errors,
            );
        }
    }
}

struct ValidatedLayerSnapshots<'a> {
    by_sha256: BTreeMap<&'a str, &'a LayerConfinementSnapshotEvidence>,
}

fn expected_layer_state_sources(
    expected_case: &LayerMutationCertificationCase,
) -> Vec<CertificationLayerStateSource> {
    expected_case
        .referenced_source_fixtures
        .iter()
        .map(|fixture| CertificationLayerStateSource {
            manifest_path: fixture.path.clone(),
            sha256: fixture.source_sha256.clone(),
        })
        .collect()
}

fn expected_layer_state_key(
    host_drawing_sha256: &str,
    expected_case: &LayerMutationCertificationCase,
) -> String {
    certification_layer_state_key_sha256(
        host_drawing_sha256,
        &expected_layer_state_sources(expected_case),
    )
}

fn validate_layer_readback_snapshots<'a>(
    expected_case: &LayerMutationCertificationCase,
    actual_case: &'a LayerMutationCaseEvidence,
    location: &str,
    errors: &mut Vec<String>,
) -> ValidatedLayerSnapshots<'a> {
    if actual_case.readback_snapshots.is_empty() {
        errors.push(format!("{location} has no confinement/readback snapshots"));
    }
    let state_keys: Vec<_> = actual_case
        .readback_snapshots
        .iter()
        .map(|snapshot| snapshot.state_key_sha256.as_str())
        .collect();
    validate_sorted_unique_keys(
        &format!("{location} readback snapshots by state key"),
        &state_keys,
        errors,
    );

    let mut by_sha256 = BTreeMap::new();
    let mut observed_state_keys = BTreeSet::new();
    for (index, snapshot) in actual_case.readback_snapshots.iter().enumerate() {
        let snapshot_location = format!("{location} readback snapshot[{index}]");
        validate_xref_digest(
            &format!("{snapshot_location} host_drawing_sha256"),
            &snapshot.host_drawing_sha256,
            errors,
        );
        let state_sources = snapshot
            .resolved_sources
            .iter()
            .map(|source| CertificationLayerStateSource {
                manifest_path: source.manifest_path.clone(),
                sha256: source.sha256.clone(),
            })
            .collect::<Vec<_>>();
        validate_digest_equality(
            &format!("{snapshot_location} state_key_sha256"),
            &snapshot.state_key_sha256,
            &certification_layer_state_key_sha256(&snapshot.host_drawing_sha256, &state_sources),
            errors,
        );
        validate_digest_equality(
            &format!("{snapshot_location} sha256"),
            &snapshot.sha256,
            &certification_layer_readback_sha256(snapshot),
            errors,
        );
        if !observed_state_keys.insert(snapshot.state_key_sha256.as_str()) {
            errors.push(format!(
                "{snapshot_location} duplicates an existing digest-keyed state"
            ));
        }
        if by_sha256
            .insert(snapshot.sha256.as_str(), snapshot)
            .is_some()
        {
            errors.push(format!(
                "{snapshot_location} duplicates an existing readback digest"
            ));
        }
        validate_layer_records(
            &snapshot.layers,
            &format!("{snapshot_location} layers"),
            errors,
        );
        validate_layer_snapshot_sources(
            expected_case,
            actual_case,
            snapshot,
            &snapshot_location,
            errors,
        );
        validate_layer_dependency_confinement(
            expected_case,
            actual_case,
            snapshot,
            &snapshot_location,
            errors,
        );
    }
    ValidatedLayerSnapshots { by_sha256 }
}

fn validate_layer_snapshot_sources(
    expected_case: &LayerMutationCertificationCase,
    actual_case: &LayerMutationCaseEvidence,
    snapshot: &LayerConfinementSnapshotEvidence,
    location: &str,
    errors: &mut Vec<String>,
) {
    let paths: Vec<_> = snapshot
        .resolved_sources
        .iter()
        .map(|source| source.manifest_path.as_str())
        .collect();
    validate_sorted_unique_keys(&format!("{location} resolved_sources"), &paths, errors);
    if snapshot.resolved_sources.len() != expected_case.referenced_source_fixtures.len() {
        errors.push(format!(
            "{location} resolved-source inventory does not match the manifest"
        ));
    }
    let expected_canonical_by_path = actual_case
        .referenced_sources
        .iter()
        .map(|source| (source.path.as_str(), source.staged_canonical_path.as_str()))
        .collect::<BTreeMap<_, _>>();
    for (expected, actual) in expected_case
        .referenced_source_fixtures
        .iter()
        .zip(&snapshot.resolved_sources)
    {
        if actual.manifest_path != expected.path {
            errors.push(format!(
                "{location} resolved source path does not match manifest path '{}'",
                expected.path
            ));
        }
        validate_digest_equality(
            &format!(
                "{location} resolved source '{}' sha256",
                actual.manifest_path
            ),
            &actual.sha256,
            &expected.source_sha256,
            errors,
        );
        validate_absolute_certification_file_path(
            &actual.canonical_path,
            &format!(
                "{location} resolved source '{}' canonical_path",
                actual.manifest_path
            ),
            errors,
        );
        if !certification_path_is_strictly_below(
            &actual.canonical_path,
            &actual_case.staged_case_root_canonical_path,
        ) {
            errors.push(format!(
                "{location} resolved source '{}' is outside the staged case root",
                actual.manifest_path
            ));
        }
        if expected_canonical_by_path
            .get(actual.manifest_path.as_str())
            .is_none_or(|expected_path| {
                certification_path_key(expected_path)
                    != certification_path_key(&actual.canonical_path)
            })
        {
            errors.push(format!(
                "{location} resolved source '{}' canonical path does not match staged evidence",
                actual.manifest_path
            ));
        }
    }
}

fn validate_layer_dependency_confinement(
    expected_case: &LayerMutationCertificationCase,
    actual_case: &LayerMutationCaseEvidence,
    snapshot: &LayerConfinementSnapshotEvidence,
    location: &str,
    errors: &mut Vec<String>,
) {
    if let Err(error) = snapshot.dependency_graph.validate() {
        errors.push(format!("{location} dependency graph is invalid: {error}"));
    }
    if !snapshot.dependency_graph.within_limits || snapshot.dependency_graph.truncation.is_some() {
        errors.push(format!(
            "{location} dependency graph must be complete and within limits"
        ));
    }
    validate_absolute_certification_file_path(
        &snapshot.dependency_graph.drawing,
        &format!("{location} dependency graph drawing"),
        errors,
    );
    if certification_path_key(&snapshot.dependency_graph.drawing)
        != certification_path_key(&actual_case.staged_drawing_canonical_path)
    {
        errors.push(format!(
            "{location} dependency graph root does not match staged host"
        ));
    }

    let permitted_hosts = std::iter::once(actual_case.staged_drawing_canonical_path.as_str())
        .chain(
            snapshot
                .resolved_sources
                .iter()
                .map(|source| source.canonical_path.as_str()),
        )
        .filter_map(certification_path_key)
        .collect::<BTreeSet<_>>();
    let expected_resolved_paths = snapshot
        .resolved_sources
        .iter()
        .filter_map(|source| certification_path_key(&source.canonical_path))
        .collect::<BTreeSet<_>>();
    let mut dependencies_by_chain = BTreeMap::new();
    for dependency in &snapshot.dependency_graph.dependencies {
        if dependencies_by_chain
            .insert(dependency.attachment_chain.as_slice(), dependency)
            .is_some()
        {
            errors.push(format!(
                "{location} dependency graph contains a duplicate attachment_chain '{}'",
                dependency.attachment_chain.join("/")
            ));
        }
    }
    let mut graph_resolved_paths = BTreeSet::new();
    for dependency in &snapshot.dependency_graph.dependencies {
        validate_absolute_certification_file_path(
            &dependency.immediate_host_path,
            &format!("{location} dependency immediate_host_path"),
            errors,
        );
        let immediate_host = certification_path_key(&dependency.immediate_host_path);
        if immediate_host
            .as_ref()
            .is_none_or(|path| !permitted_hosts.contains(path))
            || !certification_path_is_strictly_below(
                &dependency.immediate_host_path,
                &actual_case.staged_case_root_canonical_path,
            )
        {
            errors.push(format!(
                "{location} dependency immediate_host_path is outside the staged fixture tree"
            ));
        }
        if dependency.depth == 0 {
            if immediate_host != certification_path_key(&snapshot.dependency_graph.drawing) {
                errors.push(format!(
                    "{location} root dependency immediate_host_path does not match the dependency graph root"
                ));
            }
        } else if let Some((_, parent_chain)) = dependency.attachment_chain.split_last() {
            match dependencies_by_chain.get(parent_chain).copied() {
                Some(parent)
                    if parent.inspection_state == XrefInspectionState::Inspected
                        && parent
                            .resolved_path
                            .as_deref()
                            .and_then(certification_path_key)
                            == immediate_host => {}
                Some(_) => errors.push(format!(
                    "{location} dependency '{}' immediate_host_path does not match its inspected parent resolved_path",
                    dependency.attachment_chain.join("/")
                )),
                None => errors.push(format!(
                    "{location} dependency '{}' has no parent-prefix row",
                    dependency.attachment_chain.join("/")
                )),
            }
        } else {
            errors.push(format!(
                "{location} non-root dependency has an empty attachment_chain"
            ));
        }
        if dependency.resolution_state != XrefResolutionState::Resolved {
            errors.push(format!("{location} dependency is not resolved"));
        }
        if !matches!(
            dependency.inspection_state,
            XrefInspectionState::Inspected | XrefInspectionState::TerminalOverlay
        ) {
            errors.push(format!("{location} dependency is not inspectable"));
        }
        let Some(resolved_path) = dependency.resolved_path.as_deref() else {
            errors.push(format!("{location} dependency has no resolved_path"));
            continue;
        };
        validate_absolute_certification_file_path(
            resolved_path,
            &format!("{location} dependency resolved_path"),
            errors,
        );
        if !certification_path_is_strictly_below(
            resolved_path,
            &actual_case.staged_case_root_canonical_path,
        ) {
            errors.push(format!(
                "{location} dependency resolved_path is outside the staged fixture tree"
            ));
        }
        if let Some(path) = certification_path_key(resolved_path) {
            graph_resolved_paths.insert(path);
        }
    }
    if graph_resolved_paths != expected_resolved_paths {
        errors.push(format!(
            "{location} resolved dependency path set does not exactly match declared staged sources"
        ));
    }

    match expected_case.fixture_kind {
        LayerCertificationFixtureKind::HostOwned => {
            if !snapshot.dependency_graph.dependencies.is_empty()
                || !snapshot.resolved_sources.is_empty()
                || snapshot.layers.iter().any(|layer| layer.xref_dependent)
            {
                errors.push(format!(
                    "{location} host-owned snapshot must have no XREF dependencies or XREF-dependent layers"
                ));
            }
        }
        LayerCertificationFixtureKind::XrefDependentHost => {
            if snapshot.dependency_graph.dependencies.is_empty()
                || snapshot.resolved_sources.is_empty()
            {
                errors.push(format!(
                    "{location} xref-dependent snapshot requires resolved dependencies"
                ));
            }
            for layer in snapshot.layers.iter().filter(|layer| layer.xref_dependent) {
                let correlated = snapshot
                    .dependency_graph
                    .dependencies
                    .iter()
                    .any(|dependency| {
                        dependency.depth == 0
                            && layer.xref_block_record_handle.as_deref()
                                == Some(dependency.attachment.handle.as_str())
                            && layer.xref_name.as_deref().is_some_and(|name| {
                                name.eq_ignore_ascii_case(&dependency.attachment.name)
                            })
                            && layer.xref_path.as_deref()
                                == Some(dependency.attachment.saved_path.as_str())
                            && layer.xref_is_overlay
                                == Some(
                                    dependency.attachment.reference_type == ReferenceType::Overlay,
                                )
                    });
                if !correlated {
                    errors.push(format!(
                        "{location} XREF-dependent layer '{}' does not correlate to a depth-zero dependency",
                        layer.name
                    ));
                }
            }
        }
    }
}

fn validate_layer_records(
    records: &[CertificationExpandedLayerRecord],
    location: &str,
    errors: &mut Vec<String>,
) {
    let mut previous_handle = None;
    let mut names = BTreeSet::new();
    for (index, record) in records.iter().enumerate() {
        let record_location = format!("{location}[{index}]");
        let handle = validate_canonical_layer_handle(
            &record.handle,
            &format!("{record_location} handle"),
            errors,
        );
        if previous_handle.is_some_and(|previous| handle.is_none_or(|handle| previous >= handle)) {
            errors.push(format!(
                "{location} records must be sorted and unique by numeric handle"
            ));
        }
        previous_handle = handle;
        validate_nonempty_trimmed(&record.name, &format!("{record_location} name"), errors);
        if !names.insert(record.name.to_ascii_uppercase()) {
            errors.push(format!(
                "{location} records contain a duplicate case-insensitive layer name"
            ));
        }
        validate_nonempty_trimmed(
            &record.line_type,
            &format!("{record_location} line_type"),
            errors,
        );
        if record
            .color_index
            .is_some_and(|color| !(1..=255).contains(&color))
        {
            errors.push(format!(
                "{record_location} color_index must be null or from 1 to 255"
            ));
        }
        match record.line_weight {
            CertificationObservedLayerLineWeight::Value { hundredths_mm }
                if !is_standard_layer_lineweight(hundredths_mm) =>
            {
                errors.push(format!(
                    "{record_location} value lineweight is not a standard writable value"
                ));
            }
            CertificationObservedLayerLineWeight::Raw { raw_value }
                if is_standard_layer_lineweight(raw_value) =>
            {
                errors.push(format!(
                    "{record_location} raw lineweight duplicates a standard typed value"
                ));
            }
            _ => {}
        }
        let xref_fields_present = [
            record.xref_block_record_handle.is_some(),
            record.xref_name.is_some(),
            record.xref_path.is_some(),
            record.xref_is_overlay.is_some(),
        ];
        let xref_fields_consistent = if record.xref_dependent {
            xref_fields_present.iter().all(|present| *present)
        } else {
            xref_fields_present.iter().all(|present| !*present)
        };
        if !xref_fields_consistent {
            errors.push(format!(
                "{record_location} XREF ownership fields are inconsistent"
            ));
        }
        for (label, handle) in [
            (
                "xref_block_record_handle",
                record.xref_block_record_handle.as_deref(),
            ),
            ("material_handle", record.material_handle.as_deref()),
            ("plotstyle_handle", record.plotstyle_handle.as_deref()),
        ] {
            if let Some(handle) = handle {
                validate_canonical_layer_handle(
                    handle,
                    &format!("{record_location} {label}"),
                    errors,
                );
            }
        }
        if let Some(name) = &record.xref_name {
            validate_nonempty_trimmed(name, &format!("{record_location} xref_name"), errors);
        }
        if let Some(path) = &record.xref_path {
            validate_nonempty_trimmed(path, &format!("{record_location} xref_path"), errors);
        }
    }
}

fn validate_canonical_layer_handle(
    value: &str,
    label: &str,
    errors: &mut Vec<String>,
) -> Option<u64> {
    let parsed = parse_handle(value).ok();
    let canonical = parsed.and_then(|handle| {
        canonical_handle(handle)
            .ok()
            .map(|canonical| (handle, canonical))
    });
    match canonical {
        Some((handle, canonical)) if canonical == value => Some(handle.value()),
        _ => {
            errors.push(format!(
                "{label} must be canonical nonzero uppercase hexadecimal within u64"
            ));
            None
        }
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct CertificationPathKey {
    root: String,
    components: Vec<String>,
}

fn certification_path_key(path: &str) -> Option<CertificationPathKey> {
    if path.is_empty()
        || path != path.trim()
        || path.chars().any(char::is_control)
        || path.contains('\0')
    {
        return None;
    }

    let normalized = path.replace('\\', "/");
    if let Some(extended) = normalized.strip_prefix("//?/") {
        if extended
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("UNC/"))
        {
            let (server, share, components) = certification_unc_parts(&extended[4..], true)?;
            return Some(CertificationPathKey {
                root: format!("//{server}/{share}"),
                components,
            });
        }
        let (drive, components) = certification_drive_parts(extended, true)?;
        return Some(CertificationPathKey {
            root: format!("{drive}:"),
            components,
        });
    }
    if let Some(unc) = normalized.strip_prefix("//") {
        let (server, share, components) = certification_unc_parts(unc, true)?;
        return Some(CertificationPathKey {
            root: format!("//{server}/{share}"),
            components,
        });
    }
    let (drive, components) = certification_drive_parts(&normalized, true)?;
    Some(CertificationPathKey {
        root: format!("{drive}:"),
        components,
    })
}

pub fn certification_windows_paths_equal(left: &str, right: &str) -> bool {
    certification_path_key(left)
        .zip(certification_path_key(right))
        .is_some_and(|(left, right)| left == right)
}

fn certification_drive_parts(path: &str, fold_case: bool) -> Option<(char, Vec<String>)> {
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'/' {
        return None;
    }
    let drive = (bytes[0] as char).to_ascii_lowercase();
    let components = certification_path_components(&path[3..], fold_case)?;
    Some((drive, components))
}

fn certification_unc_parts(path: &str, fold_case: bool) -> Option<(String, String, Vec<String>)> {
    let mut parts = path.splitn(3, '/');
    let server = parts.next()?;
    let share = parts.next()?;
    if !certification_path_component_is_safe(server, true)
        || !certification_path_component_is_safe(share, true)
    {
        return None;
    }
    let components = certification_path_components(parts.next().unwrap_or_default(), fold_case)?;
    Some((
        server.to_ascii_lowercase(),
        share.to_ascii_lowercase(),
        components,
    ))
}

fn certification_path_components(path: &str, fold_case: bool) -> Option<Vec<String>> {
    if path.is_empty() {
        return Some(Vec::new());
    }
    if path == "/" {
        return None;
    }
    let path = path.strip_suffix('/').unwrap_or(path);
    certification_path_component_slice(&path.split('/').collect::<Vec<_>>(), fold_case)
}

fn certification_path_component_slice(components: &[&str], fold_case: bool) -> Option<Vec<String>> {
    components
        .iter()
        .map(|component| {
            if !certification_path_component_is_safe(component, fold_case) {
                return None;
            }
            Some(if fold_case {
                component.to_ascii_lowercase()
            } else {
                (*component).to_string()
            })
        })
        .collect()
}

fn certification_path_component_is_safe(component: &str, windows: bool) -> bool {
    !component.is_empty()
        && !matches!(component, "." | "..")
        && !component.chars().any(char::is_control)
        && (!windows || certification_windows_path_component_is_safe(component))
}

fn certification_windows_path_component_is_safe(component: &str) -> bool {
    if component.ends_with(['.', ' '])
        || component
            .chars()
            .any(|character| matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
    {
        return false;
    }
    let basename = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !matches!(
        basename.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) && !basename
        .strip_prefix("COM")
        .or_else(|| basename.strip_prefix("LPT"))
        .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

fn certification_path_has_autocad_engine_shape(path: &str, version: &str) -> bool {
    let Some(path) = certification_path_key(path) else {
        return false;
    };
    if path.components.last().map(String::as_str) != Some("accoreconsole.exe") {
        return false;
    }
    path.components
        .iter()
        .filter(|component| component.starts_with("autocad"))
        .flat_map(|component| {
            component
                .split(|character: char| !character.is_ascii_digit())
                .filter(|part| part.len() == 4 && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .last()
        == Some(version)
}

fn certification_path_is_strictly_below(path: &str, root: &str) -> bool {
    let (Some(path), Some(root)) = (certification_path_key(path), certification_path_key(root))
    else {
        return false;
    };
    path.root == root.root
        && path.components.len() > root.components.len()
        && path.components.starts_with(&root.components)
}

fn certification_paths_overlap(left: &str, right: &str) -> bool {
    let (Some(left), Some(right)) = (certification_path_key(left), certification_path_key(right))
    else {
        return false;
    };
    left.root == right.root
        && (left.components.starts_with(&right.components)
            || right.components.starts_with(&left.components))
}

fn validate_certification_fixture_root_binding(
    manifest: &CertificationManifest,
    canonical_path: &str,
    location: &str,
    errors: &mut Vec<String>,
) {
    validate_absolute_certification_directory_path(
        canonical_path,
        &format!("{location} fixture_root_canonical_path"),
        errors,
    );
    if certification_path_key(canonical_path) != certification_path_key(&manifest.fixture_root) {
        errors.push(format!(
            "{location} fixture_root_canonical_path does not identify the manifest fixture_root"
        ));
    }
}

fn certification_path_matches_staged_fixture(
    path: &str,
    case_root: &str,
    manifest_relative_path: &str,
) -> bool {
    let (Some(path), Some(mut expected)) = (
        certification_path_key(path),
        certification_path_key(case_root),
    ) else {
        return false;
    };
    let Some(relative_components) = certification_path_components(manifest_relative_path, true)
    else {
        return false;
    };
    expected.components.push("fixture".to_string());
    expected.components.extend(relative_components);
    path == expected
}

fn validate_layer_observed_outcome(
    expected: &LayerMutationCertificationOperation,
    actual: &LayerMutationOperationEvidence,
    preceding_snapshot: Option<&LayerConfinementSnapshotEvidence>,
    persisted_snapshot: Option<&LayerConfinementSnapshotEvidence>,
    location: &str,
    errors: &mut Vec<String>,
) {
    match &expected.expected {
        LayerCertificationExpectedOutcome::Passed { assertion } => {
            if actual.observed_tool_status != CertificationObservedToolStatus::Passed
                || actual.observed_error_code.is_some()
            {
                errors.push(format!(
                    "{location} expected successful tool observation with error_code=null"
                ));
            }
            let Some(observation) = actual.actual_output.as_ref() else {
                errors.push(format!(
                    "{location} successful operation is missing typed actual_output"
                ));
                return;
            };
            validate_digest_equality(
                &format!("{location} actual_output sha256"),
                &observation.sha256,
                &certification_layer_output_sha256(&observation.result),
                errors,
            );
            validate_layer_observed_result(
                expected,
                assertion,
                &observation.result,
                persisted_snapshot,
                location,
                errors,
            );
            if expected.tool.is_mutation() {
                validate_layer_mutation_delta(
                    expected,
                    &observation.result,
                    preceding_snapshot,
                    persisted_snapshot,
                    location,
                    errors,
                );
            }
            if expected.tool.is_mutation()
                && actual.input_drawing_sha256 == actual.output_drawing_sha256
            {
                errors.push(format!(
                    "{location} successful mutation did not change the staged drawing digest"
                ));
            }
            if !expected.tool.is_mutation()
                && actual.input_drawing_sha256 != actual.output_drawing_sha256
            {
                errors.push(format!(
                    "{location} read-only operation changed drawing digest"
                ));
            }
        }
        LayerCertificationExpectedOutcome::Failed {
            error_code,
            unchanged_layer,
        } => {
            if actual.observed_tool_status != CertificationObservedToolStatus::Failed
                || actual.observed_error_code.as_deref() != Some(error_code.as_str())
            {
                errors.push(format!(
                    "{location} observed failure/error code does not match manifest"
                ));
            }
            if actual.actual_output.is_some() {
                errors.push(format!(
                    "{location} expected failure must have actual_output=null"
                ));
            }
            if actual.input_drawing_sha256 != actual.output_drawing_sha256 {
                errors.push(format!(
                    "{location} expected failure changed drawing digest"
                ));
            }
            if let Some(snapshot) = persisted_snapshot {
                let params = validate_layer_operation_params(expected, location, &mut Vec::new());
                let selected = params
                    .as_ref()
                    .and_then(ParsedLayerCertificationParams::selector)
                    .and_then(|(handle, name)| find_layer_record(&snapshot.layers, handle, name));
                match selected {
                    Some(record)
                        if layer_expectation_matches_record(unchanged_layer, record) => {}
                    Some(_) => errors.push(format!(
                        "{location} persisted failed-operation layer does not match unchanged_layer"
                    )),
                    None => errors.push(format!(
                        "{location} persisted readback does not contain the failed-operation target layer"
                    )),
                }
            }
        }
    }
}

fn validate_layer_observed_result(
    expected: &LayerMutationCertificationOperation,
    assertion: &LayerCertificationPassedAssertion,
    result: &CertificationLayerObservedResult,
    persisted_snapshot: Option<&LayerConfinementSnapshotEvidence>,
    location: &str,
    errors: &mut Vec<String>,
) {
    let shape_matches = matches!(
        (expected.tool, result),
        (
            LayerMutationCertificationTool::ListLayers,
            CertificationLayerObservedResult::ListLayers { .. }
        ) | (
            LayerMutationCertificationTool::GetLayer
                | LayerMutationCertificationTool::CreateLayer
                | LayerMutationCertificationTool::UpdateLayer
                | LayerMutationCertificationTool::RenameLayer,
            CertificationLayerObservedResult::Layer { .. }
        ) | (
            LayerMutationCertificationTool::DeleteLayer,
            CertificationLayerObservedResult::DeletedIdentity { .. }
        )
    );
    if !shape_matches {
        errors.push(format!(
            "{location} typed actual_output kind does not match tool"
        ));
        return;
    }

    match result {
        CertificationLayerObservedResult::ListLayers { records } => {
            validate_layer_records(records, &format!("{location} actual list"), errors);
            if let LayerCertificationPassedAssertion::ExpandedRecords { record } = assertion {
                if !records.contains(record) {
                    errors.push(format!(
                        "{location} list output does not contain the exact manifest record"
                    ));
                }
            }
            if persisted_snapshot.is_none_or(|snapshot| snapshot.layers != *records) {
                errors.push(format!(
                    "{location} list output does not exactly match persisted full readback"
                ));
            }
        }
        CertificationLayerObservedResult::Layer { record } => {
            validate_layer_records(
                std::slice::from_ref(record),
                &format!("{location} actual layer"),
                errors,
            );
            if let LayerCertificationPassedAssertion::Layer { layer } = assertion {
                if !layer_expectation_matches_record(layer, record) {
                    errors.push(format!(
                        "{location} layer output does not match the manifest assertion"
                    ));
                }
            }
            if persisted_snapshot
                .is_none_or(|snapshot| !snapshot.layers.iter().any(|persisted| persisted == record))
            {
                errors.push(format!(
                    "{location} layer output is absent from persisted full readback"
                ));
            }
        }
        CertificationLayerObservedResult::DeletedIdentity { handle, name } => {
            validate_nonempty_trimmed(handle, &format!("{location} deleted handle"), errors);
            validate_nonempty_trimmed(name, &format!("{location} deleted name"), errors);
            if let LayerCertificationPassedAssertion::DeletedIdentity {
                handle: expected_handle,
                name: expected_name,
            } = assertion
            {
                if !handle.eq_ignore_ascii_case(expected_handle)
                    || !name.eq_ignore_ascii_case(expected_name)
                {
                    errors.push(format!(
                        "{location} deleted identity does not match manifest assertion"
                    ));
                }
            }
            if persisted_snapshot.is_none_or(|snapshot| {
                find_layer_record(&snapshot.layers, Some(handle), Some(name)).is_some()
            }) {
                errors.push(format!(
                    "{location} deleted identity remains in persisted full readback"
                ));
            }
        }
    }
}

fn validate_layer_mutation_delta(
    expected: &LayerMutationCertificationOperation,
    result: &CertificationLayerObservedResult,
    preceding_snapshot: Option<&LayerConfinementSnapshotEvidence>,
    persisted_snapshot: Option<&LayerConfinementSnapshotEvidence>,
    location: &str,
    errors: &mut Vec<String>,
) {
    let (Some(before), Some(after)) = (preceding_snapshot, persisted_snapshot) else {
        return;
    };
    let Some(params) = validate_layer_operation_params(expected, location, &mut Vec::new()) else {
        return;
    };

    match (expected.tool, params, result) {
        (
            LayerMutationCertificationTool::CreateLayer,
            ParsedLayerCertificationParams::Create(_),
            CertificationLayerObservedResult::Layer { record },
        ) => {
            let mut remainder = after.layers.clone();
            let added = remainder
                .iter()
                .position(|candidate| candidate == record)
                .map(|index| remainder.remove(index));
            if after.layers.len() != before.layers.len() + 1
                || added.as_ref() != Some(record)
                || remainder != before.layers
            {
                errors.push(format!(
                    "{location} create delta must add exactly the returned layer and preserve every prior row"
                ));
            }
        }
        (
            LayerMutationCertificationTool::UpdateLayer,
            ParsedLayerCertificationParams::Update(params),
            CertificationLayerObservedResult::Layer { record },
        ) => {
            let before_split = split_layer_records(
                &before.layers,
                params.handle.as_deref(),
                params.name.as_deref(),
            );
            let after_split = before_split.as_ref().and_then(|(target, _)| {
                split_layer_records(
                    &after.layers,
                    Some(target.handle.as_str()),
                    Some(target.name.as_str()),
                )
            });
            let valid = before_split.as_ref().zip(after_split.as_ref()).is_some_and(
                |((before_target, before_others), (after_target, after_others))| {
                    *after_target == record
                        && before_others == after_others
                        && layer_update_delta_is_confined(
                            before_target,
                            after_target,
                            &params.properties,
                        )
                },
            );
            if !valid {
                errors.push(format!(
                    "{location} update delta changed an identity, unrelated row, XREF field, or unrequested target field, or made no requested semantic change"
                ));
            }
        }
        (
            LayerMutationCertificationTool::RenameLayer,
            ParsedLayerCertificationParams::Rename(params),
            CertificationLayerObservedResult::Layer { record },
        ) => {
            let before_split = split_layer_records(
                &before.layers,
                params.handle.as_deref(),
                params.name.as_deref(),
            );
            let after_split = before_split.as_ref().and_then(|(target, _)| {
                split_layer_records(
                    &after.layers,
                    Some(target.handle.as_str()),
                    Some(params.new_name.as_str()),
                )
            });
            let valid = before_split.as_ref().zip(after_split.as_ref()).is_some_and(
                |((before_target, before_others), (after_target, after_others))| {
                    let mut restored = (**after_target).clone();
                    restored.name.clone_from(&before_target.name);
                    *after_target == record
                        && before_others == after_others
                        && before_target.name != after_target.name
                        && after_target.name == params.new_name
                        && restored == **before_target
                },
            );
            if !valid {
                errors.push(format!(
                    "{location} rename delta must change only the selected layer name while preserving its handle, all other fields, and unrelated rows"
                ));
            }
        }
        (
            LayerMutationCertificationTool::DeleteLayer,
            ParsedLayerCertificationParams::Delete(_),
            CertificationLayerObservedResult::DeletedIdentity { handle, name },
        ) => {
            let removed = split_layer_records(&before.layers, Some(handle), Some(name));
            let valid = removed.as_ref().is_some_and(|(target, remainder)| {
                target.handle == *handle && target.name == *name && remainder == &after.layers
            });
            if !valid {
                errors.push(format!(
                    "{location} delete delta must remove exactly the declared handle/name and preserve every other row"
                ));
            }
        }
        _ => {}
    }
}

fn split_layer_records<'a>(
    records: &'a [CertificationExpandedLayerRecord],
    handle: Option<&str>,
    name: Option<&str>,
) -> Option<(
    &'a CertificationExpandedLayerRecord,
    Vec<CertificationExpandedLayerRecord>,
)> {
    let index = records.iter().position(|record| {
        handle.is_none_or(|handle| record.handle.eq_ignore_ascii_case(handle))
            && name.is_none_or(|name| record.name.eq_ignore_ascii_case(name))
    })?;
    let target = &records[index];
    let mut remainder = records.to_vec();
    remainder.remove(index);
    Some((target, remainder))
}

fn layer_update_delta_is_confined(
    before: &CertificationExpandedLayerRecord,
    after: &CertificationExpandedLayerRecord,
    requested: &LayerCertificationProperties,
) -> bool {
    let changed_requested_property = (requested.color_index.is_some()
        && before.color_index != after.color_index)
        || (requested.line_type.is_some() && before.line_type != after.line_type)
        || (requested.line_weight.is_some() && before.line_weight != after.line_weight)
        || (requested.frozen.is_some() && before.frozen != after.frozen)
        || (requested.locked.is_some() && before.locked != after.locked)
        || (requested.off.is_some() && before.off != after.off)
        || (requested.is_plottable.is_some() && before.is_plottable != after.is_plottable);

    changed_requested_property
        && before.handle == after.handle
        && before.name == after.name
        && (requested.color_index.is_some() || before.color_index == after.color_index)
        && (requested.line_type.is_some() || before.line_type == after.line_type)
        && (requested.line_weight.is_some() || before.line_weight == after.line_weight)
        && (requested.frozen.is_some() || before.frozen == after.frozen)
        && (requested.locked.is_some() || before.locked == after.locked)
        && (requested.off.is_some() || before.off == after.off)
        && (requested.is_plottable.is_some() || before.is_plottable == after.is_plottable)
        && before.xref_dependent == after.xref_dependent
        && before.xref_block_record_handle == after.xref_block_record_handle
        && before.xref_name == after.xref_name
        && before.xref_path == after.xref_path
        && before.xref_is_overlay == after.xref_is_overlay
        && before.material_handle == after.material_handle
        && before.plotstyle_handle == after.plotstyle_handle
        && before.is_current == after.is_current
}

fn find_layer_record<'a>(
    records: &'a [CertificationExpandedLayerRecord],
    handle: Option<&str>,
    name: Option<&str>,
) -> Option<&'a CertificationExpandedLayerRecord> {
    records.iter().find(|record| {
        handle.is_none_or(|handle| record.handle.eq_ignore_ascii_case(handle))
            && name.is_none_or(|name| record.name.eq_ignore_ascii_case(name))
    })
}

fn layer_expectation_matches_record(
    expected: &LayerCertificationLayerExpectation,
    actual: &CertificationExpandedLayerRecord,
) -> bool {
    expectation_matches_required(&expected.handle, &actual.handle)
        && expectation_matches_required(&expected.name, &actual.name)
        && expectation_matches_optional(&expected.color_index, &actual.color_index)
        && expectation_matches_required(&expected.line_type, &actual.line_type)
        && expectation_matches_required(&expected.line_weight, &actual.line_weight)
        && expectation_matches_required(&expected.frozen, &actual.frozen)
        && expectation_matches_required(&expected.locked, &actual.locked)
        && expectation_matches_required(&expected.off, &actual.off)
        && expectation_matches_required(&expected.is_plottable, &actual.is_plottable)
        && expectation_matches_required(&expected.xref_dependent, &actual.xref_dependent)
        && expectation_matches_optional(
            &expected.xref_block_record_handle,
            &actual.xref_block_record_handle,
        )
        && expectation_matches_optional(&expected.xref_name, &actual.xref_name)
        && expectation_matches_optional(&expected.xref_path, &actual.xref_path)
        && expectation_matches_optional(&expected.xref_is_overlay, &actual.xref_is_overlay)
        && expectation_matches_optional(&expected.material_handle, &actual.material_handle)
        && expectation_matches_optional(&expected.plotstyle_handle, &actual.plotstyle_handle)
        && expectation_matches_required(&expected.is_current, &actual.is_current)
}

fn expectation_matches_required<T: PartialEq>(
    expected: &CertificationFieldExpectation<T>,
    actual: &T,
) -> bool {
    match expected {
        CertificationFieldExpectation::Omitted => true,
        CertificationFieldExpectation::Null => false,
        CertificationFieldExpectation::Value(expected) => expected == actual,
    }
}

fn expectation_matches_optional<T: PartialEq>(
    expected: &CertificationFieldExpectation<T>,
    actual: &Option<T>,
) -> bool {
    match expected {
        CertificationFieldExpectation::Omitted => true,
        CertificationFieldExpectation::Null => actual.is_none(),
        CertificationFieldExpectation::Value(expected) => actual.as_ref() == Some(expected),
    }
}

fn validate_distinct_manifest_fixture_paths(
    manifest: &CertificationManifest,
    errors: &mut Vec<String>,
) {
    let mut paths = BTreeSet::new();
    for (owner, path) in manifest
        .tier2_drawings
        .iter()
        .map(|drawing| {
            (
                format!("Tier 2 drawing '{}'", drawing.drawing_id),
                &drawing.path,
            )
        })
        .chain(manifest.layer_mutation_cases.iter().flat_map(|case| {
            std::iter::once((format!("layer case '{}'", case.case_id), &case.path)).chain(
                case.referenced_source_fixtures.iter().map(|fixture| {
                    (
                        format!("layer case '{}' reference", case.case_id),
                        &fixture.path,
                    )
                }),
            )
        }))
    {
        if !paths.insert(path.to_ascii_lowercase()) {
            errors.push(format!(
                "certification fixture path '{}' is reused or aliases another Windows path for {owner}",
                path
            ));
        }
    }
}

fn validate_relative_dwg_fixture_path(path: &str, location: &str, errors: &mut Vec<String>) {
    let valid = !path.is_empty()
        && path == path.trim()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains(':')
        && path.split('/').all(|component| {
            component.is_ascii() && certification_path_component_is_safe(component, true)
        });
    if !valid {
        errors.push(format!(
            "{location} path '{path}' must be a safe normalized Windows-relative ASCII fixture path"
        ));
    }
    if path.rsplit_once('.').is_none_or(|(stem, extension)| {
        stem.rsplit('/').next().is_none_or(str::is_empty) || !extension.eq_ignore_ascii_case("dwg")
    }) {
        errors.push(format!(
            "{location} path '{path}' must name a relative DWG fixture with a .dwg extension"
        ));
    }
}

fn validate_absolute_certification_directory_path(
    path: &str,
    label: &str,
    errors: &mut Vec<String>,
) {
    if certification_path_key(path).is_none() {
        errors.push(format!(
            "{label} must be an absolute Windows path without empty or dot segments"
        ));
    }
}

fn validate_absolute_certification_file_path(path: &str, label: &str, errors: &mut Vec<String>) {
    let parsed = certification_path_key(path);
    if parsed
        .as_ref()
        .is_none_or(|path| path.components.is_empty())
        || path.ends_with('/')
        || path.ends_with('\\')
    {
        errors.push(format!(
            "{label} must be an absolute Windows file path without trailing, empty, or dot segments"
        ));
    }
}

fn validate_nonempty_trimmed(value: &str, label: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() || value != value.trim() {
        errors.push(format!("{label} must be non-empty and trimmed"));
    }
}

fn validate_sorted_unique_nonempty_strings(
    label: &str,
    values: &[String],
    errors: &mut Vec<String>,
) {
    if values.is_empty() {
        errors.push(format!("{label} must not be empty"));
    }
    let values_as_str: Vec<_> = values.iter().map(String::as_str).collect();
    validate_sorted_unique_keys(label, &values_as_str, errors);
    for value in values {
        validate_nonempty_trimmed(value, label, errors);
    }
}

fn validate_digest_equality(label: &str, actual: &str, expected: &str, errors: &mut Vec<String>) {
    validate_xref_digest(label, actual, errors);
    if actual != expected {
        errors.push(format!("{label} does not match the required exact bytes"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xref_artifact_values() -> [serde_json::Value; 4] {
        [
            serde_json::from_slice(XREF_MUTATION_CAPABILITIES_BYTES).unwrap(),
            serde_json::from_slice(XREF_PRESERVATION_VERIFIER_PROFILES_BYTES).unwrap(),
            serde_json::from_slice(XREF_BIND_VERIFIER_PROFILES_BYTES).unwrap(),
            serde_json::from_slice(XREF_CLIP_VERIFIER_PROFILES_BYTES).unwrap(),
        ]
    }

    fn xref_registry_from_values(values: &[serde_json::Value; 4]) -> Result<XrefArtifactRegistry> {
        let bytes: Vec<Vec<u8>> = values
            .iter()
            .map(|value| serde_json::to_vec(value).unwrap())
            .collect();
        XrefArtifactRegistry::from_bytes(&bytes[0], &bytes[1], &bytes[2], &bytes[3])
    }

    fn xref_validation_error(mutate: impl FnOnce(&mut [serde_json::Value; 4])) -> String {
        let mut values = xref_artifact_values();
        mutate(&mut values);
        xref_registry_from_values(&values).unwrap_err().to_string()
    }

    fn assert_schema_objects_are_closed(value: &serde_json::Value) {
        assert_schema_objects_are_closed_except(value, &[]);
    }

    fn assert_schema_objects_are_closed_except(
        value: &serde_json::Value,
        open_properties: &[&str],
    ) {
        match value {
            serde_json::Value::Object(object) => {
                if object.get("type").and_then(serde_json::Value::as_str) == Some("object") {
                    assert_eq!(
                        object.get("additionalProperties"),
                        Some(&serde_json::Value::Bool(false)),
                        "open object schema: {value}"
                    );
                }
                for (key, child) in object {
                    if !open_properties.contains(&key.as_str()) {
                        assert_schema_objects_are_closed_except(child, open_properties);
                    }
                }
            }
            serde_json::Value::Array(values) => {
                for child in values {
                    assert_schema_objects_are_closed_except(child, open_properties);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn embedded_xref_artifacts_are_valid_closed_v1_registries() {
        let registry = embedded_xref_artifacts().unwrap();
        assert_eq!(registry.capabilities().rows.len(), 2);
        assert_eq!(registry.preservation_profiles().profiles.len(), 1);
        assert_eq!(registry.bind_profiles().profiles.len(), 1);
        assert_eq!(registry.clip_profiles().profiles.len(), 1);

        let required: BTreeSet<_> = XREF_MUTATION_OPERATIONS.into_iter().collect();
        for format in [XrefHostFormat::Dwg, XrefHostFormat::Dxf] {
            let covered: BTreeSet<_> = registry
                .capabilities()
                .rows
                .iter()
                .filter(|row| row.host_format == format)
                .flat_map(|row| row.operations.iter().copied())
                .collect();
            assert_eq!(covered, required, "{} coverage", format.as_str());
        }
    }

    #[test]
    fn xref_artifact_json_schemas_close_every_object() {
        for schema in [
            serde_json::to_value(schemars::schema_for!(XrefMutationCapabilityArtifact)).unwrap(),
            serde_json::to_value(schemars::schema_for!(
                XrefPreservationVerifierProfilesArtifact
            ))
            .unwrap(),
            serde_json::to_value(schemars::schema_for!(XrefBindVerifierProfilesArtifact)).unwrap(),
            serde_json::to_value(schemars::schema_for!(XrefClipVerifierProfilesArtifact)).unwrap(),
        ] {
            assert_schema_objects_are_closed(&schema);
        }
    }

    #[test]
    fn xref_artifact_parsing_rejects_unknown_fields_at_root_and_nested_levels() {
        let root_error = xref_validation_error(|values| {
            values[0]["unexpected"] = serde_json::json!(true);
        });
        assert!(
            root_error.contains("unknown field `unexpected`"),
            "{root_error}"
        );

        let row_error = xref_validation_error(|values| {
            values[0]["rows"][0]["unexpected"] = serde_json::json!(true);
        });
        assert!(
            row_error.contains("unknown field `unexpected`"),
            "{row_error}"
        );

        let profile_error = xref_validation_error(|values| {
            values[1]["profiles"][0]["object_classes"][0]["unexpected"] = serde_json::json!(true);
        });
        assert!(
            profile_error.contains("unknown field `unexpected`"),
            "{profile_error}"
        );
    }

    #[test]
    fn xref_artifact_validation_rejects_every_unknown_schema_version() {
        for artifact_index in 0..4 {
            let invalid_version = if artifact_index == 0 { 1 } else { 2 };
            let error = xref_validation_error(|values| {
                values[artifact_index]["schema_version"] = serde_json::json!(invalid_version);
            });
            assert!(
                error.contains(&format!("schema_version {invalid_version} is unsupported")),
                "{error}"
            );
        }
    }

    #[test]
    fn xref_capability_validation_rejects_row_order_duplicate_ids_and_tuples() {
        let order_error = xref_validation_error(|values| {
            values[0]["rows"].as_array_mut().unwrap().reverse();
        });
        assert!(
            order_error.contains("capability rows by row_id must be sorted and unique"),
            "{order_error}"
        );

        let duplicate_id_error = xref_validation_error(|values| {
            let row = values[0]["rows"][1].clone();
            values[0]["rows"].as_array_mut().unwrap().push(row);
        });
        assert!(
            duplicate_id_error.contains("capability rows by row_id must be sorted and unique"),
            "{duplicate_id_error}"
        );

        let duplicate_tuple_error = xref_validation_error(|values| {
            let mut row = values[0]["rows"][1].clone();
            row["row_id"] = serde_json::json!("zz-duplicate-capability-v2");
            values[0]["rows"].as_array_mut().unwrap().push(row);
        });
        assert!(
            duplicate_tuple_error.contains("duplicates a complete capability tuple"),
            "{duplicate_tuple_error}"
        );
    }

    #[test]
    fn xref_capability_validation_rejects_wildcards_and_invalid_operations() {
        let wildcard_error = xref_validation_error(|values| {
            values[0]["rows"][0]["drawing_version"] = serde_json::json!("*");
        });
        assert!(
            wildcard_error.contains("wildcard value '*'"),
            "{wildcard_error}"
        );

        let operation_error = xref_validation_error(|values| {
            values[0]["rows"][0]["operations"][0] = serde_json::json!("explode_xref");
        });
        assert!(
            operation_error.contains("unknown variant `explode_xref`"),
            "{operation_error}"
        );
    }

    #[test]
    fn xref_capability_validation_rejects_unsorted_and_duplicate_operations() {
        let unsorted_error = xref_validation_error(|values| {
            values[0]["rows"][0]["operations"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1);
        });
        assert!(
            unsorted_error.contains("operations must be sorted and unique"),
            "{unsorted_error}"
        );

        let duplicate_error = xref_validation_error(|values| {
            let operation = values[0]["rows"][0]["operations"][0].clone();
            values[0]["rows"][0]["operations"]
                .as_array_mut()
                .unwrap()
                .insert(1, operation);
        });
        assert!(
            duplicate_error.contains("operations must be sorted and unique"),
            "{duplicate_error}"
        );
    }

    #[test]
    fn xref_capability_validation_enforces_dwg_and_dxf_format_code_page_rules() {
        let dwg_error = xref_validation_error(|values| {
            values[0]["rows"][0]["code_page"] = serde_json::json!("ANSI_1252");
        });
        assert!(dwg_error.contains("code_page=null for DWG"), "{dwg_error}");

        let missing_ascii_error = xref_validation_error(|values| {
            values[0]["rows"][1]["code_page"] = serde_json::Value::Null;
        });
        assert!(
            missing_ascii_error.contains("ASCII DXF requires code_page"),
            "{missing_ascii_error}"
        );

        let lowercase_error = xref_validation_error(|values| {
            values[0]["rows"][1]["code_page"] = serde_json::json!("ansi_1252");
        });
        assert!(
            lowercase_error.contains("canonical uppercase ASCII"),
            "{lowercase_error}"
        );

        let binary_error = xref_validation_error(|values| {
            values[0]["rows"][1]["dxf_form"] = serde_json::json!("binary");
        });
        assert!(
            binary_error.contains("binary DXF requires code_page=null"),
            "{binary_error}"
        );

        let not_applicable_error = xref_validation_error(|values| {
            values[0]["rows"][1]["dxf_form"] = serde_json::json!("not_applicable");
        });
        assert!(
            not_applicable_error.contains("dxf_form=ascii or binary for DXF"),
            "{not_applicable_error}"
        );
    }

    #[test]
    fn xref_capability_validation_requires_all_profile_references() {
        let preservation_error = xref_validation_error(|values| {
            values[0]["rows"][0]["preservation_verifier_profile_id"] =
                serde_json::json!("xref-missing-v1");
        });
        assert!(
            preservation_error.contains("references missing preservation profile"),
            "{preservation_error}"
        );

        let bind_error = xref_validation_error(|values| {
            values[0]["rows"][0]["bind_verifier_profile_id"] = serde_json::json!("xref-missing-v1");
        });
        assert!(
            bind_error.contains("references missing bind profile"),
            "{bind_error}"
        );

        let clip_error = xref_validation_error(|values| {
            values[0]["rows"][0]["clip_policy"] = serde_json::json!("verify");
            values[0]["rows"][0]["clip_verifier_profile_id"] = serde_json::json!("xref-missing-v1");
        });
        assert!(
            clip_error.contains("references missing clip profile"),
            "{clip_error}"
        );
    }

    #[test]
    fn xref_capability_validation_requires_bind_profile_for_bind_operation() {
        let error = xref_validation_error(|values| {
            values[0]["rows"][0]["bind_verifier_profile_id"] = serde_json::Value::Null;
        });
        assert!(
            error.contains("advertises bind_xref without bind_verifier_profile_id"),
            "{error}"
        );
    }

    #[test]
    fn xref_capability_validation_enforces_clip_policy_profile_consistency() {
        let reject_error = xref_validation_error(|values| {
            values[0]["rows"][0]["clip_verifier_profile_id"] = serde_json::json!("xref-clip-v1");
        });
        assert!(
            reject_error.contains("clip_policy=reject requires clip_verifier_profile_id=null"),
            "{reject_error}"
        );

        let verify_error = xref_validation_error(|values| {
            values[0]["rows"][0]["clip_policy"] = serde_json::json!("verify");
        });
        assert!(
            verify_error.contains("clip_policy=verify requires clip_verifier_profile_id"),
            "{verify_error}"
        );
    }

    #[test]
    fn xref_profile_validation_enforces_sorted_unique_members() {
        let profile_id_error = xref_validation_error(|values| {
            let profile = values[1]["profiles"][0].clone();
            values[1]["profiles"].as_array_mut().unwrap().push(profile);
        });
        assert!(
            profile_id_error.contains("preservation verifier profiles must be sorted and unique"),
            "{profile_id_error}"
        );

        let class_order_error = xref_validation_error(|values| {
            values[1]["profiles"][0]["object_classes"]
                .as_array_mut()
                .unwrap()
                .reverse();
        });
        assert!(
            class_order_error.contains("object_classes must be sorted and unique"),
            "{class_order_error}"
        );

        let field_duplicate_error = xref_validation_error(|values| {
            values[1]["profiles"][0]["mapped_identity_fields"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!("owner_handle"));
        });
        assert!(
            field_duplicate_error.contains("mapped_identity_fields must be sorted and unique"),
            "{field_duplicate_error}"
        );

        let default_tuple_error = xref_validation_error(|values| {
            let state = serde_json::json!({
                "host_format": "dwg",
                "drawing_version": "AC1032",
                "role": "host"
            });
            values[1]["profiles"][0]["profile_default_unit_states"] =
                serde_json::json!([state.clone(), state]);
        });
        assert!(
            default_tuple_error.contains("profile_default_unit_states must be sorted and unique"),
            "{default_tuple_error}"
        );
    }

    #[test]
    fn xref_bind_and_clip_profiles_enforce_specialized_contracts() {
        let strategy_error = xref_validation_error(|values| {
            values[2]["profiles"][0]["strategy_authorized_differences"]
                .as_array_mut()
                .unwrap()
                .pop();
        });
        assert!(
            strategy_error.contains("requires exactly one merge and one prefix strategy entry"),
            "{strategy_error}"
        );

        let bind_defaults_error = xref_validation_error(|values| {
            values[2]["profiles"][0]["profile_default_unit_states"] = serde_json::json!([{
                "host_format": "dwg",
                "drawing_version": "AC1032",
                "role": "host"
            }]);
        });
        assert!(
            bind_defaults_error.contains("must not declare profile_default_unit_states"),
            "{bind_defaults_error}"
        );

        let clip_defaults_error = xref_validation_error(|values| {
            values[3]["profiles"][0]["profile_default_unit_states"] = serde_json::json!([{
                "host_format": "dxf",
                "drawing_version": "AC1032",
                "role": "source"
            }]);
        });
        assert!(
            clip_defaults_error.contains("must not declare profile_default_unit_states"),
            "{clip_defaults_error}"
        );

        let clip_fields_error = xref_validation_error(|values| {
            values[3]["profiles"][0]["clip_fields"]
                .as_array_mut()
                .unwrap()
                .pop();
        });
        assert!(
            clip_fields_error.contains("must exactly match the v1 spatial-filter facts"),
            "{clip_fields_error}"
        );
    }

    #[test]
    fn xref_capability_validation_requires_nine_operations_for_dwg_and_dxf() {
        for row_index in 0..2 {
            let error = xref_validation_error(|values| {
                values[0]["rows"][row_index]["operations"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|operation| operation != "bind_xref");
            });
            let format = if row_index == 0 { "dwg" } else { "dxf" };
            assert!(
                error.contains(&format!(
                    "{format} capability coverage is missing operation 'bind_xref'"
                )),
                "{error}"
            );
        }
    }

    #[test]
    fn xref_embedded_artifacts_expose_exact_utf8_digest_inputs() {
        for artifact in XREF_EMBEDDED_ARTIFACTS {
            let bytes = artifact.exact_bytes();
            assert!(!bytes.is_empty());
            assert!(std::str::from_utf8(bytes).is_ok());
            assert_eq!(
                artifact.sha256_digest_with(|digest_input| digest_input.as_ptr()),
                bytes.as_ptr()
            );
            assert_eq!(artifact.sha256_digest_with(<[u8]>::len), bytes.len());
        }
    }

    #[test]
    fn xref_artifact_parser_rejects_non_utf8_before_json_parsing() {
        let error = XrefArtifactRegistry::from_bytes(
            &[0xff],
            XREF_PRESERVATION_VERIFIER_PROFILES_BYTES,
            XREF_BIND_VERIFIER_PROFILES_BYTES,
            XREF_CLIP_VERIFIER_PROFILES_BYTES,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("is not UTF-8"), "{error}");
    }

    fn committed_certification_manifest_bytes() -> &'static [u8] {
        include_bytes!("../../../tests/fixtures/windows_certification/manifest.example.json")
    }

    fn committed_xref_certification_manifest_bytes() -> &'static [u8] {
        include_bytes!("../../../tests/fixtures/windows_certification/xref-manifest.example.json")
    }

    fn committed_certification_manifest() -> CertificationManifest {
        CertificationManifest::from_json(
            std::str::from_utf8(committed_certification_manifest_bytes()).unwrap(),
        )
        .unwrap()
    }

    const MAINTAINED_CERTIFICATION_TARGET_IDS: [&str; 4] = [
        "autocad-2024-r24-3-en-us-preview-v1",
        "autocad-2025-r25-0-en-us-preview-v1",
        "autocad-2026-r25-1-en-us-preview-v1",
        "autocad-2027-r26-0-en-us-preview-v1",
    ];

    fn configure_certification_manifest_target(
        manifest: &mut CertificationManifest,
        target_id: &str,
    ) {
        let catalogue = activation::embedded_activation_catalogue().unwrap();
        let target = catalogue.target(target_id).unwrap();
        manifest.runtime.activation_target =
            embedded_certification_activation_target(target_id).unwrap();
        manifest.runtime.autocad_product = target.product.as_str().to_string();
        manifest.runtime.autocad_version = target.release_year.to_string();
        manifest.runtime.accoreconsole_path = format!(
            "C:/Program Files/Autodesk/AutoCAD {}/accoreconsole.exe",
            target.release_year
        );
        manifest.runtime.certified_arg_sha256 = target.profile.arg_sha256.clone();
        manifest.runtime.certified_arg_policy_id = target.profile.policy_id.clone();
        manifest.runtime.certified_arg_policy_sha256 = target.profile.policy_sha256.clone();
    }

    fn configure_xref_certification_manifest_target(
        manifest: &mut XrefCertificationManifest,
        target_id: &str,
    ) {
        let catalogue = activation::embedded_activation_catalogue().unwrap();
        let target = catalogue.target(target_id).unwrap();
        manifest.activation_target = embedded_certification_activation_target(target_id).unwrap();
        manifest.autocad_product = target.product.as_str().to_string();
        manifest.autocad_version = target.release_year.to_string();
        manifest.accoreconsole_path = format!(
            "C:/Program Files/Autodesk/AutoCAD {}/accoreconsole.exe",
            target.release_year
        );
        manifest.certified_arg_sha256 = target.profile.arg_sha256.clone();
        manifest.certified_arg_policy_id = target.profile.policy_id.clone();
        manifest.certified_arg_policy_sha256 = target.profile.policy_sha256.clone();
    }

    fn certification_profile_definition() -> CertificationProfileDefinition {
        CertificationProfileDefinition {
            profile_id: "AUTOCAD_MCP_GENERIC".to_string(),
            field_mappings: vec![
                ("alternative_reference", "REFERENCE"),
                ("drawing_number", "DRAWING_NUMBER"),
                ("drawing_title_big", "TITLE_LINE_1"),
                ("drawing_title_med", "TITLE_LINE_2"),
                ("revision", "REVISION"),
                ("sheet", "SHEET_NUMBER"),
                ("sheet_total", "SHEET_COUNT"),
            ]
            .into_iter()
            .map(
                |(canonical_field, attribute_tag)| CertificationProfileFieldMapping {
                    canonical_field: canonical_field.to_string(),
                    attribute_tag: attribute_tag.to_string(),
                },
            )
            .collect(),
            fingerprint: CertificationTitleBlockFingerprint {
                block_name: "AUTOCAD_MCP_GENERIC".to_string(),
                attribute_tags: vec![
                    "DRAWING_NUMBER".to_string(),
                    "REFERENCE".to_string(),
                    "REVISION".to_string(),
                    "SHEET_COUNT".to_string(),
                    "SHEET_NUMBER".to_string(),
                    "TITLE_LINE_1".to_string(),
                    "TITLE_LINE_2".to_string(),
                ],
            },
        }
    }

    fn certification_build_identity(
        runtime: &CertificationRuntimeRequirements,
    ) -> XrefCertificationBuildIdentity {
        XrefCertificationBuildIdentity {
            source_commit: "a".repeat(40),
            source_tree_sha256: "b".repeat(64),
            cargo_lock_sha256: "c".repeat(64),
            certified_arg_sha256: runtime.certified_arg_sha256.clone(),
            certified_arg_policy_id: runtime.certified_arg_policy_id.clone(),
            certified_arg_policy_sha256: runtime.certified_arg_policy_sha256.clone(),
            compiler: "rustc test".to_string(),
            target: "x86_64-pc-windows-msvc".to_string(),
            profile: "release".to_string(),
            optimization: "3".to_string(),
            build_id: "d".repeat(64),
            shared_operation_source_sha256: "e".repeat(64),
            certification_failpoints_enabled: false,
        }
    }

    fn certification_runtime_evidence(
        manifest: &CertificationManifest,
    ) -> CertificationRuntimeEvidence {
        CertificationRuntimeEvidence {
            activation_target: manifest.runtime.activation_target.clone(),
            platform: "windows".to_string(),
            release_binary_path: manifest.runtime.release_binary_path.clone(),
            release_binary_canonical_path:
                r"\\?\C:\REPLACE_WITH_CERTIFIED_BINARIES\autocad-mcp.exe".to_string(),
            release_binary_sha256_before: manifest.runtime.release_binary_sha256.clone(),
            release_binary_sha256_after: manifest.runtime.release_binary_sha256.clone(),
            accoreconsole_path: manifest.runtime.accoreconsole_path.clone(),
            accoreconsole_canonical_path: format!(
                r"\\?\C:\Program Files\Autodesk\AutoCAD {}\accoreconsole.exe",
                manifest.runtime.autocad_version
            ),
            accoreconsole_sha256_before: manifest.runtime.accoreconsole_sha256.clone(),
            accoreconsole_sha256_after: manifest.runtime.accoreconsole_sha256.clone(),
            certified_arg_path: manifest.runtime.certified_arg_path.clone(),
            certified_arg_canonical_path: r"\\?\C:\REPLACE_WITH_CERTIFIED_PROFILE\autocad-mcp.arg"
                .to_string(),
            certified_arg_sha256_before: manifest.runtime.certified_arg_sha256.clone(),
            certified_arg_sha256_after: manifest.runtime.certified_arg_sha256.clone(),
            certified_arg_policy_id: manifest.runtime.certified_arg_policy_id.clone(),
            certified_arg_policy_sha256: manifest.runtime.certified_arg_policy_sha256.clone(),
            observed_autocad_product: manifest.runtime.autocad_product.clone(),
            observed_autocad_version: manifest.runtime.autocad_version.clone(),
            binary_build_identity: certification_build_identity(&manifest.runtime),
            binary_reported_certified_arg_sha256: manifest.runtime.certified_arg_sha256.clone(),
            binary_reported_certified_arg_policy_id: manifest
                .runtime
                .certified_arg_policy_id
                .clone(),
            binary_reported_certified_arg_policy_sha256: manifest
                .runtime
                .certified_arg_policy_sha256
                .clone(),
            binary_reported_title_block_profile_registry_sha256: manifest
                .runtime
                .title_block_profile_registry_sha256
                .clone(),
            binary_reported_title_block_profiles: vec![certification_profile_definition()],
        }
    }

    fn title_snapshot(
        manifest: &CertificationManifest,
        drawing: &CertificationDrawing,
        profile: &CertificationProfileDefinition,
        after: bool,
    ) -> CertificationTitleBlockSnapshot {
        let attributes = profile
            .fingerprint
            .attribute_tags
            .iter()
            .map(|tag| {
                let value = if after {
                    profile
                        .field_mappings
                        .iter()
                        .find(|mapping| mapping.attribute_tag == *tag)
                        .and_then(|mapping| {
                            drawing
                                .write_fields
                                .iter()
                                .find(|write| write.field == mapping.canonical_field)
                        })
                        .map(|write| write.value.as_str())
                        .unwrap_or("private-before-value")
                } else {
                    "private-before-value"
                };
                CertificationHashedTitleBlockAttribute {
                    tag: tag.clone(),
                    value_sha256: certification_title_value_sha256(
                        &manifest.release_id,
                        &drawing.drawing_id,
                        tag,
                        value,
                    ),
                }
            })
            .collect();
        let mut records = vec![
            CertificationHashedTitleBlockRecord {
                normalized_block_name: profile.fingerprint.block_name.clone(),
                layer_sha256: certification_title_layer_sha256(
                    &manifest.release_id,
                    &drawing.drawing_id,
                    "TITLE",
                ),
                attributes,
            },
            CertificationHashedTitleBlockRecord {
                normalized_block_name: "OTHER_ATTRIBUTED_INSERT".to_string(),
                layer_sha256: certification_title_layer_sha256(
                    &manifest.release_id,
                    &drawing.drawing_id,
                    "OTHER",
                ),
                attributes: vec![CertificationHashedTitleBlockAttribute {
                    tag: "UNCHANGED_NOTE".to_string(),
                    value_sha256: certification_title_value_sha256(
                        &manifest.release_id,
                        &drawing.drawing_id,
                        "UNCHANGED_NOTE",
                        "private-non-target-value",
                    ),
                }],
            },
        ];
        sort_title_records(&mut records);
        CertificationTitleBlockSnapshot {
            sha256: certification_title_snapshot_sha256(&records),
            records,
        }
    }

    fn passing_profile_isolation(
        expected: &[ExpectedCertificationProfileInvocation],
    ) -> Vec<CertificationProfileIsolationEvidence> {
        expected
            .iter()
            .map(|expected| {
                let present_after = expected.expectation
                    == CertificationProfileLaunchExpectation::EngineImportRequired;
                CertificationProfileIsolationEvidence {
                    invocation_id: expected.invocation_id.clone(),
                    tool: expected.tool.clone(),
                    expectation: expected.expectation,
                    absent_before: true,
                    present_after,
                    cleanup_performed: present_after,
                    absent_after: true,
                }
            })
            .collect()
    }

    fn passed_tier2_evidence(
        manifest: &CertificationManifest,
        manifest_sha256: &str,
    ) -> Tier2ProfileCertificationEvidence {
        let profile = certification_profile_definition();
        Tier2ProfileCertificationEvidence {
            schema_version: CERTIFICATION_SCHEMA_VERSION,
            evidence_class: CertificationEvidenceClass::Tier2Profile,
            release_id: manifest.release_id.clone(),
            status: CertificationResultStatus::Passed,
            reason: None,
            manifest_sha256: manifest_sha256.to_string(),
            runtime: certification_runtime_evidence(manifest),
            fixture_root_canonical_path: format!(
                r"\\?\{}",
                manifest.fixture_root.replace('/', r"\")
            ),
            drawings: manifest
                .tier2_drawings
                .iter()
                .map(|drawing| {
                    let case_root =
                        format!(r"\\?\C:\cert\tier2-profile-cases\{}", drawing.drawing_id);
                    let fixture_path = drawing.path.replace('/', r"\");
                    Tier2DrawingCertificationEvidence {
                        drawing_id: drawing.drawing_id.clone(),
                        path: drawing.path.clone(),
                        source_sha256: drawing.source_sha256.clone(),
                        staged_case_root_canonical_path: case_root.clone(),
                        staged_drawing_canonical_path: format!(
                            r"{case_root}\fixture\{fixture_path}"
                        ),
                        staged_drawing_sha256: drawing.source_sha256.clone(),
                        final_drawing_sha256: "8".repeat(64),
                        status: CertificationResultStatus::Passed,
                        reason: None,
                        observed_profile_id: Some(drawing.expected_profile_id.clone()),
                        observed_fingerprint: Some(profile.fingerprint.clone()),
                        pre_title_blocks: title_snapshot(manifest, drawing, &profile, false),
                        post_title_blocks: title_snapshot(manifest, drawing, &profile, true),
                        observed_layouts: Some(vec!["Layout1".to_string(), "Model".to_string()]),
                        plot: drawing.plot_layout.as_ref().map(|layout| {
                            CertificationPlotEvidence {
                                layout: layout.clone(),
                                output_canonical_path: format!(
                                    r"{case_root}\plot\{}.pdf",
                                    drawing.drawing_id
                                ),
                                pdf_sha256: "f".repeat(64),
                                pdf_size_bytes: 1024,
                            }
                        }),
                        profile_isolation: passing_profile_isolation(
                            &expected_tier2_profile_isolation(drawing.plot_layout.is_some()),
                        ),
                    }
                })
                .collect(),
        }
    }

    fn layer_record(
        handle: &str,
        name: &str,
        xref_dependent: bool,
    ) -> CertificationExpandedLayerRecord {
        CertificationExpandedLayerRecord {
            handle: handle.to_string(),
            name: name.to_string(),
            color_index: Some(7),
            line_type: "Continuous".to_string(),
            line_weight: CertificationObservedLayerLineWeight::Default,
            frozen: false,
            locked: false,
            off: false,
            is_plottable: true,
            xref_dependent,
            xref_block_record_handle: xref_dependent.then(|| handle.to_string()),
            xref_name: xref_dependent.then(|| "LAYER_SOURCE".to_string()),
            xref_path: xref_dependent.then(|| "layers/refs/layer-source.dwg".to_string()),
            xref_is_overlay: xref_dependent.then_some(false),
            material_handle: None,
            plotstyle_handle: None,
            is_current: false,
        }
    }

    fn initial_layer_records(
        case: &LayerMutationCertificationCase,
    ) -> Vec<CertificationExpandedLayerRecord> {
        let mut records = match case.fixture_kind {
            LayerCertificationFixtureKind::HostOwned => {
                let LayerCertificationExpectedOutcome::Passed {
                    assertion: LayerCertificationPassedAssertion::ExpandedRecords { record: target },
                } = &case.operations[0].expected
                else {
                    panic!("host fixture list witness changed");
                };
                let mut current = layer_record("10", "CURRENT", false);
                current.is_current = true;
                vec![
                    target.clone(),
                    layer_record("2B", "CERT_DELETE", false),
                    layer_record("2C", "CERT_RENAME", false),
                    current,
                ]
            }
            LayerCertificationFixtureKind::XrefDependentHost => {
                vec![layer_record("3A", "LAYER_SOURCE|CERT_TARGET", true)]
            }
        };
        records.sort_by_key(|record| u128::from_str_radix(&record.handle, 16).unwrap());
        records
    }

    fn apply_layer_properties(
        record: &mut CertificationExpandedLayerRecord,
        properties: &LayerCertificationProperties,
    ) {
        if let Some(value) = properties.color_index {
            record.color_index = Some(value);
        }
        if let Some(value) = properties.frozen {
            record.frozen = value;
        }
        if let Some(value) = properties.locked {
            record.locked = value;
        }
        if let Some(value) = properties.off {
            record.off = value;
        }
        if let Some(value) = properties.is_plottable {
            record.is_plottable = value;
        }
        if let Some(value) = &properties.line_type {
            record.line_type = value.clone();
        }
        if let Some(value) = properties.line_weight {
            record.line_weight = value.into();
        }
    }

    fn layer_dependency_graph(
        staged_host: &str,
        resolved_sources: &[CertificationResolvedSourceEvidence],
    ) -> XrefDependencyTraversalEnvelope {
        let dependencies = resolved_sources
            .iter()
            .enumerate()
            .map(|(index, source)| {
                let handle = format!("{:X}", 0x3a_u64 + index as u64);
                serde_json::json!({
                    "attachment_chain": [handle],
                    "depth": 0,
                    "immediate_host_path": staged_host,
                    "attachment": {
                        "handle": handle,
                        "name": "LAYER_SOURCE",
                        "saved_path": source.manifest_path,
                        "path_mode": "relative",
                        "reference_type": "attachment",
                        "load_state": "loaded",
                        "instance_count": 1,
                        "definition_base_point": {"state": "unavailable"}
                    },
                    "propagation_state": "root",
                    "resolution_state": "resolved",
                    "resolved_path": source.canonical_path,
                    "resolution_basis": "host_relative",
                    "inspection_state": "inspected",
                    "cycle_target_chain": null
                })
            })
            .collect::<Vec<_>>();
        serde_json::from_value(serde_json::json!({
            "drawing": staged_host,
            "within_limits": true,
            "truncation": null,
            "dependencies": dependencies
        }))
        .unwrap()
    }

    fn layer_snapshot(
        case: &LayerMutationCertificationCase,
        staged_host: &str,
        host_digest: &str,
        records: &[CertificationExpandedLayerRecord],
        referenced_sources: &[CertificationReferencedSourceEvidence],
    ) -> LayerConfinementSnapshotEvidence {
        let resolved_sources = case
            .referenced_source_fixtures
            .iter()
            .zip(referenced_sources)
            .map(|(fixture, staged)| CertificationResolvedSourceEvidence {
                manifest_path: fixture.path.clone(),
                canonical_path: staged.staged_canonical_path.clone(),
                sha256: fixture.source_sha256.clone(),
            })
            .collect::<Vec<_>>();
        let state_key_sha256 = certification_layer_state_key_sha256(
            host_digest,
            &resolved_sources
                .iter()
                .map(|source| CertificationLayerStateSource {
                    manifest_path: source.manifest_path.clone(),
                    sha256: source.sha256.clone(),
                })
                .collect::<Vec<_>>(),
        );
        let mut snapshot = LayerConfinementSnapshotEvidence {
            state_key_sha256,
            host_drawing_sha256: host_digest.to_string(),
            layers: records.to_vec(),
            dependency_graph: layer_dependency_graph(staged_host, &resolved_sources),
            resolved_sources,
            sha256: String::new(),
        };
        snapshot.sha256 = certification_layer_readback_sha256(&snapshot);
        snapshot
    }

    fn passed_layer_evidence(
        manifest: &CertificationManifest,
        manifest_sha256: &str,
    ) -> LayerMutationCertificationEvidence {
        let cases = manifest
            .layer_mutation_cases
            .iter()
            .map(|case| {
                let case_root = format!(r"\\?\C:\cert\staged\{}", case.case_id);
                let staged_host = format!(r"{case_root}\fixture\{}", case.path.replace('/', r"\"));
                let referenced_sources = case
                    .referenced_source_fixtures
                    .iter()
                    .map(|fixture| CertificationReferencedSourceEvidence {
                        path: fixture.path.clone(),
                        source_sha256: fixture.source_sha256.clone(),
                        staged_canonical_path: format!(
                            r"{case_root}\fixture\{}",
                            fixture.path.replace('/', r"\")
                        ),
                        before_sha256: fixture.source_sha256.clone(),
                        after_sha256: fixture.source_sha256.clone(),
                    })
                    .collect::<Vec<_>>();
                let mut records = initial_layer_records(case);
                let mut previous_digest = case.source_sha256.clone();
                let initial = layer_snapshot(
                    case,
                    &staged_host,
                    &previous_digest,
                    &records,
                    &referenced_sources,
                );
                let initial_state_key_sha256 = initial.state_key_sha256.clone();
                let initial_readback_sha256 = initial.sha256.clone();
                let mut snapshots = BTreeMap::from([(initial.state_key_sha256.clone(), initial)]);
                let mut operations = Vec::new();

                for operation in &case.operations {
                    let input_digest = previous_digest.clone();
                    let mut observed_error_code = None;
                    let actual_result = match &operation.expected {
                        LayerCertificationExpectedOutcome::Failed { error_code, .. } => {
                            observed_error_code = Some(error_code.clone());
                            None
                        }
                        LayerCertificationExpectedOutcome::Passed { .. } => {
                            let result = match operation.tool {
                                LayerMutationCertificationTool::ListLayers => {
                                    CertificationLayerObservedResult::ListLayers {
                                        records: records.clone(),
                                    }
                                }
                                LayerMutationCertificationTool::GetLayer => {
                                    let params: LayerGetCertificationParams =
                                        serde_json::from_value(operation.params.clone()).unwrap();
                                    CertificationLayerObservedResult::Layer {
                                        record: find_layer_record(
                                            &records,
                                            params.handle.as_deref(),
                                            params.name.as_deref(),
                                        )
                                        .unwrap()
                                        .clone(),
                                    }
                                }
                                LayerMutationCertificationTool::CreateLayer => {
                                    let params: LayerCreateCertificationParams =
                                        serde_json::from_value(operation.params.clone()).unwrap();
                                    let mut record = layer_record("30", &params.name, false);
                                    apply_layer_properties(&mut record, &params.properties);
                                    records.push(record.clone());
                                    records.sort_by_key(|record| {
                                        u128::from_str_radix(&record.handle, 16).unwrap()
                                    });
                                    CertificationLayerObservedResult::Layer { record }
                                }
                                LayerMutationCertificationTool::UpdateLayer => {
                                    let params: LayerUpdateCertificationParams =
                                        serde_json::from_value(operation.params.clone()).unwrap();
                                    let record = records
                                        .iter_mut()
                                        .find(|record| {
                                            params.handle.as_deref().is_none_or(|handle| {
                                                record.handle.eq_ignore_ascii_case(handle)
                                            }) && params.name.as_deref().is_none_or(|name| {
                                                record.name.eq_ignore_ascii_case(name)
                                            })
                                        })
                                        .unwrap();
                                    apply_layer_properties(record, &params.properties);
                                    CertificationLayerObservedResult::Layer {
                                        record: record.clone(),
                                    }
                                }
                                LayerMutationCertificationTool::RenameLayer => {
                                    let params: LayerRenameCertificationParams =
                                        serde_json::from_value(operation.params.clone()).unwrap();
                                    let record = records
                                        .iter_mut()
                                        .find(|record| {
                                            params.handle.as_deref().is_none_or(|handle| {
                                                record.handle.eq_ignore_ascii_case(handle)
                                            }) && params.name.as_deref().is_none_or(|name| {
                                                record.name.eq_ignore_ascii_case(name)
                                            })
                                        })
                                        .unwrap();
                                    record.name = params.new_name;
                                    CertificationLayerObservedResult::Layer {
                                        record: record.clone(),
                                    }
                                }
                                LayerMutationCertificationTool::DeleteLayer => {
                                    let params: LayerDeleteCertificationParams =
                                        serde_json::from_value(operation.params.clone()).unwrap();
                                    let index = records
                                        .iter()
                                        .position(|record| {
                                            params.handle.as_deref().is_none_or(|handle| {
                                                record.handle.eq_ignore_ascii_case(handle)
                                            }) && params.name.as_deref().is_none_or(|name| {
                                                record.name.eq_ignore_ascii_case(name)
                                            })
                                        })
                                        .unwrap();
                                    let record = records.remove(index);
                                    CertificationLayerObservedResult::DeletedIdentity {
                                        handle: record.handle,
                                        name: record.name,
                                    }
                                }
                            };
                            Some(result)
                        }
                    };
                    if operation.tool.is_mutation() && actual_result.is_some() {
                        previous_digest = xref_sha256_bytes(
                            format!("drawing:{}", operation.operation_id).as_bytes(),
                        );
                    }
                    let snapshot = layer_snapshot(
                        case,
                        &staged_host,
                        &previous_digest,
                        &records,
                        &referenced_sources,
                    );
                    let persisted_state_key_sha256 = snapshot.state_key_sha256.clone();
                    let persisted_readback_sha256 = snapshots
                        .entry(snapshot.state_key_sha256.clone())
                        .or_insert(snapshot)
                        .sha256
                        .clone();
                    let actual_output =
                        actual_result.map(|result| CertificationLayerToolObservation {
                            sha256: certification_layer_output_sha256(&result),
                            result,
                        });
                    operations.push(LayerMutationOperationEvidence {
                        operation_id: operation.operation_id.clone(),
                        tool: operation.tool,
                        params: operation.params.clone(),
                        status: CertificationResultStatus::Passed,
                        reason: None,
                        observed_tool_status: if actual_output.is_some() {
                            CertificationObservedToolStatus::Passed
                        } else {
                            CertificationObservedToolStatus::Failed
                        },
                        observed_error_code,
                        input_drawing_sha256: input_digest,
                        output_drawing_sha256: previous_digest.clone(),
                        actual_output,
                        persisted_state_key_sha256,
                        persisted_readback_sha256,
                    });
                }

                let profile_isolation = passing_profile_isolation(
                    &expected_layer_profile_isolation(case, &case.source_sha256, &operations)
                        .unwrap(),
                );
                LayerMutationCaseEvidence {
                    case_id: case.case_id.clone(),
                    drawing_id: case.drawing_id.clone(),
                    path: case.path.clone(),
                    source_sha256: case.source_sha256.clone(),
                    staged_case_root_canonical_path: case_root,
                    staged_drawing_canonical_path: staged_host,
                    staged_drawing_sha256: case.source_sha256.clone(),
                    final_drawing_sha256: previous_digest,
                    status: CertificationResultStatus::Passed,
                    reason: None,
                    referenced_sources,
                    initial_state_key_sha256,
                    initial_readback_sha256,
                    readback_snapshots: snapshots.into_values().collect(),
                    operations,
                    profile_isolation,
                }
            })
            .collect();
        LayerMutationCertificationEvidence {
            schema_version: CERTIFICATION_SCHEMA_VERSION,
            evidence_class: CertificationEvidenceClass::LayerMutation,
            release_id: manifest.release_id.clone(),
            status: CertificationResultStatus::Passed,
            reason: None,
            manifest_sha256: manifest_sha256.to_string(),
            runtime: certification_runtime_evidence(manifest),
            fixture_root_canonical_path: format!(
                r"\\?\{}",
                manifest.fixture_root.replace('/', r"\")
            ),
            cases,
        }
    }

    fn rehash_layer_snapshot_references(case: &mut LayerMutationCaseEvidence, index: usize) {
        let old_sha256 = case.readback_snapshots[index].sha256.clone();
        case.readback_snapshots[index].sha256 =
            certification_layer_readback_sha256(&case.readback_snapshots[index]);
        let new_sha256 = case.readback_snapshots[index].sha256.clone();
        if case.initial_readback_sha256 == old_sha256 {
            case.initial_readback_sha256.clone_from(&new_sha256);
        }
        for operation in &mut case.operations {
            if operation.persisted_readback_sha256 == old_sha256 {
                operation.persisted_readback_sha256.clone_from(&new_sha256);
            }
        }
    }

    fn mutate_operation_snapshot(
        evidence: &mut LayerMutationCertificationEvidence,
        case_index: usize,
        operation_index: usize,
        mutate: impl FnOnce(&mut LayerConfinementSnapshotEvidence),
    ) {
        let readback_sha256 = evidence.cases[case_index].operations[operation_index]
            .persisted_readback_sha256
            .clone();
        let snapshot_index = evidence.cases[case_index]
            .readback_snapshots
            .iter()
            .position(|snapshot| snapshot.sha256 == readback_sha256)
            .unwrap();
        mutate(&mut evidence.cases[case_index].readback_snapshots[snapshot_index]);
        rehash_layer_snapshot_references(&mut evidence.cases[case_index], snapshot_index);
    }

    #[test]
    fn embedded_profile_projection_has_the_exact_certification_shape() {
        let definitions = embedded_certification_profile_definitions();
        assert_eq!(definitions, vec![certification_profile_definition()]);

        let serialized = serde_json::to_value(&definitions[0]).unwrap();
        assert!(serialized.get("field_mappings").is_some());
        assert!(serialized.get("canonical_fields").is_none());
        assert!(serialized.get("canonical_to_tag").is_none());
    }

    #[test]
    fn committed_certification_manifest_is_a_complete_valid_input() {
        let manifest = committed_certification_manifest();
        let profiles = [certification_profile_definition()];
        validate_release_manifest(&manifest, &profiles, true).unwrap();
        validate_layer_mutation_manifest(&manifest).unwrap();
        let LayerCertificationExpectedOutcome::Failed {
            unchanged_layer, ..
        } = &manifest.layer_mutation_cases[0].operations[11].expected
        else {
            panic!("unsupported-property fixture operation shape changed");
        };
        assert_eq!(
            unchanged_layer.plotstyle_handle,
            CertificationFieldExpectation::Null
        );
        assert_eq!(
            serde_json::to_value(unchanged_layer).unwrap()["plotstyle_handle"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn certification_manifests_admit_every_catalogue_maintained_target() {
        let profiles = [certification_profile_definition()];
        let legacy_base = committed_certification_manifest();
        let xref_base = valid_xref_certification_manifest();

        for target_id in MAINTAINED_CERTIFICATION_TARGET_IDS {
            let mut legacy = legacy_base.clone();
            configure_certification_manifest_target(&mut legacy, target_id);
            validate_release_manifest(&legacy, &profiles, true)
                .unwrap_or_else(|error| panic!("{target_id} legacy release: {error}"));
            validate_layer_mutation_manifest(&legacy)
                .unwrap_or_else(|error| panic!("{target_id} legacy layers: {error}"));

            let mut xref = xref_base.clone();
            configure_xref_certification_manifest_target(&mut xref, target_id);
            validate_xref_certification_manifest(&xref)
                .unwrap_or_else(|error| panic!("{target_id} strict XREF: {error}"));
        }
    }

    #[test]
    fn certification_manifests_reject_preview_only_target() {
        let target_id = "autocad-2023-r24-2-en-us-preview-v1";
        let profiles = [certification_profile_definition()];

        let mut legacy = committed_certification_manifest();
        configure_certification_manifest_target(&mut legacy, target_id);
        let error = validate_release_manifest(&legacy, &profiles, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Preview-only candidate"), "{error}");

        let mut xref = valid_xref_certification_manifest();
        configure_xref_certification_manifest_target(&mut xref, target_id);
        let error = validate_xref_certification_manifest(&xref)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Preview-only candidate"), "{error}");
    }

    #[test]
    fn certification_manifest_rejects_catalogue_tuple_and_profile_drift() {
        let profiles = [certification_profile_definition()];

        let mut stale_catalogue = committed_certification_manifest();
        stale_catalogue.runtime.activation_target.catalogue_sha256 = "0".repeat(64);
        let error = validate_release_manifest(&stale_catalogue, &profiles, true)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("does not match the embedded activation catalogue"),
            "{error}"
        );

        let mut tuple_drift = committed_certification_manifest();
        tuple_drift.runtime.activation_target.registry_family = "R25.0".to_string();
        let error = validate_release_manifest(&tuple_drift, &profiles, true)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("does not exactly match its embedded activation catalogue row"),
            "{error}"
        );

        let mut profile_drift = valid_xref_certification_manifest();
        profile_drift.certified_arg_sha256 = "0".repeat(64);
        let error = validate_xref_certification_manifest(&profile_drift)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("certified ARG/policy identity does not match activation target"),
            "{error}"
        );
    }

    #[test]
    fn certification_validators_reject_prior_schema_v2() {
        let manifest = committed_certification_manifest();
        let profiles = [certification_profile_definition()];
        let mut prior_manifest = manifest.clone();
        prior_manifest.schema_version = 2;

        let error = validate_release_manifest(&prior_manifest, &profiles, true)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("certification manifest schema_version 2 is unsupported; expected 3"),
            "{error}"
        );
        let error = validate_layer_mutation_manifest(&prior_manifest)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("certification manifest schema_version 2 is unsupported; expected 3"),
            "{error}"
        );

        let manifest_sha256 =
            certification_manifest_sha256(committed_certification_manifest_bytes());
        let mut tier2 = passed_tier2_evidence(&manifest, &manifest_sha256);
        tier2.schema_version = 2;
        let error = validate_tier2_profile_certification_evidence(
            &manifest,
            &profiles,
            true,
            &manifest_sha256,
            &tier2,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("certification evidence schema_version 2 is unsupported; expected 3"),
            "{error}"
        );

        let mut layers = passed_layer_evidence(&manifest, &manifest_sha256);
        layers.schema_version = 2;
        let error = validate_layer_mutation_evidence(&manifest, &manifest_sha256, &layers)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("certification evidence schema_version 2 is unsupported; expected 3"),
            "{error}"
        );
    }

    #[test]
    fn certification_schema_rejects_unknown_and_missing_fields() {
        let manifest = committed_certification_manifest();
        let mut root = serde_json::to_value(&manifest).unwrap();
        root["unexpected"] = serde_json::json!(true);
        let error = CertificationManifest::from_json(&root.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `unexpected`"), "{error}");

        let mut nested = serde_json::to_value(&manifest).unwrap();
        nested["runtime"]["unexpected"] = serde_json::json!(true);
        let error = CertificationManifest::from_json(&nested.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `unexpected`"), "{error}");

        let mut missing_activation_target = serde_json::to_value(&manifest).unwrap();
        missing_activation_target["runtime"]
            .as_object_mut()
            .unwrap()
            .remove("activation_target");
        let error = CertificationManifest::from_json(&missing_activation_target.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("missing field `activation_target`"),
            "{error}"
        );

        let mut missing_policy = serde_json::to_value(&manifest).unwrap();
        missing_policy["runtime"]
            .as_object_mut()
            .unwrap()
            .remove("certified_arg_policy_sha256");
        let error = CertificationManifest::from_json(&missing_policy.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("missing field `certified_arg_policy_sha256`"),
            "{error}"
        );

        let mut missing_nullable = serde_json::to_value(&manifest).unwrap();
        missing_nullable["tier2_drawings"][0]
            .as_object_mut()
            .unwrap()
            .remove("plot_layout");
        let error = CertificationManifest::from_json(&missing_nullable.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing field `plot_layout`"), "{error}");

        let mut unknown_params = manifest.clone();
        unknown_params.layer_mutation_cases[0].operations[0].params["unexpected"] =
            serde_json::json!(true);
        let error = validate_layer_mutation_manifest(&unknown_params)
            .unwrap_err()
            .to_string();
        assert!(error.contains("params are not closed/valid"), "{error}");

        let mut unknown_enum = serde_json::to_value(&manifest).unwrap();
        unknown_enum["layer_mutation_cases"][0]["operations"][0]["expected"]["unexpected"] =
            serde_json::json!(true);
        let error = CertificationManifest::from_json(&unknown_enum.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `unexpected`"), "{error}");
    }

    #[test]
    fn certification_generated_schemas_close_every_object() {
        for schema in [
            serde_json::to_value(schemars::schema_for!(CertificationManifest)).unwrap(),
            serde_json::to_value(schemars::schema_for!(Tier2ProfileCertificationEvidence)).unwrap(),
            serde_json::to_value(schemars::schema_for!(LayerMutationCertificationEvidence))
                .unwrap(),
        ] {
            assert_schema_objects_are_closed(&schema);
        }
    }

    #[test]
    fn certification_evidence_parsers_reject_unknown_and_missing_nullable_fields() {
        let manifest = committed_certification_manifest();
        let manifest_sha256 =
            certification_manifest_sha256(committed_certification_manifest_bytes());

        let tier2 = passed_tier2_evidence(&manifest, &manifest_sha256);
        let mut tier2_root = serde_json::to_value(&tier2).unwrap();
        tier2_root["unexpected"] = serde_json::json!(true);
        let error = Tier2ProfileCertificationEvidence::from_json(&tier2_root.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `unexpected`"), "{error}");

        let mut tier2_nested = serde_json::to_value(&tier2).unwrap();
        tier2_nested["runtime"]["unexpected"] = serde_json::json!(true);
        let error = Tier2ProfileCertificationEvidence::from_json(&tier2_nested.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `unexpected`"), "{error}");

        let mut tier2_missing_policy = serde_json::to_value(&tier2).unwrap();
        tier2_missing_policy["runtime"]
            .as_object_mut()
            .unwrap()
            .remove("binary_reported_certified_arg_policy_id");
        let error = Tier2ProfileCertificationEvidence::from_json(&tier2_missing_policy.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("missing field `binary_reported_certified_arg_policy_id`"),
            "{error}"
        );

        let mut tier2_missing_nullable = serde_json::to_value(&tier2).unwrap();
        tier2_missing_nullable["drawings"][0]
            .as_object_mut()
            .unwrap()
            .remove("plot");
        let error =
            Tier2ProfileCertificationEvidence::from_json(&tier2_missing_nullable.to_string())
                .unwrap_err()
                .to_string();
        assert!(error.contains("missing field `plot`"), "{error}");

        let mut profile_unknown = serde_json::to_value(&tier2).unwrap();
        profile_unknown["drawings"][0]["profile_isolation"][0]["registry_path"] =
            serde_json::json!(r"HKCU\Software\private");
        let error = Tier2ProfileCertificationEvidence::from_json(&profile_unknown.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `registry_path`"), "{error}");

        let mut profile_missing = serde_json::to_value(&tier2).unwrap();
        profile_missing["drawings"][0]["profile_isolation"][0]
            .as_object_mut()
            .unwrap()
            .remove("absent_after");
        let error = Tier2ProfileCertificationEvidence::from_json(&profile_missing.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing field `absent_after`"), "{error}");

        let layers = passed_layer_evidence(&manifest, &manifest_sha256);
        let mut layer_nested = serde_json::to_value(&layers).unwrap();
        layer_nested["cases"][0]["operations"][0]["unexpected"] = serde_json::json!(true);
        let error = LayerMutationCertificationEvidence::from_json(&layer_nested.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `unexpected`"), "{error}");

        let mut layer_missing_nullable = serde_json::to_value(&layers).unwrap();
        layer_missing_nullable["cases"][0]["operations"][0]
            .as_object_mut()
            .unwrap()
            .remove("actual_output");
        let error =
            LayerMutationCertificationEvidence::from_json(&layer_missing_nullable.to_string())
                .unwrap_err()
                .to_string();
        assert!(error.contains("missing field `actual_output`"), "{error}");
    }

    #[test]
    fn certification_manifest_sha256_hashes_exact_input_bytes() {
        let bytes = committed_certification_manifest_bytes();
        assert_eq!(
            certification_manifest_sha256(bytes),
            xref_sha256_bytes(bytes)
        );
        let mut altered = bytes.to_vec();
        altered.push(b'\n');
        assert_ne!(
            certification_manifest_sha256(bytes),
            certification_manifest_sha256(&altered)
        );
    }

    #[test]
    fn certification_path_confinement_rejects_lexical_and_namespace_bypasses() {
        for (path, root) in [
            (r"C:\cert\case\host.dwg", r"c:/CERT/case"),
            (r"\\?\C:\cert\case\host.dwg", r"c:\CERT\case"),
            (r"C:\cert\case\host.dwg", r"\\?\c:\CERT\case"),
            (
                r"\\server\share\cert\case\host.dwg",
                r"//SERVER/SHARE/cert/case",
            ),
            (
                r"\\?\UNC\server\share\cert\case\host.dwg",
                r"//SERVER/SHARE/cert/case",
            ),
            (
                r"\\server\share\cert\case\host.dwg",
                r"//?/unc/SERVER/SHARE/cert/case",
            ),
        ] {
            assert!(
                certification_path_is_strictly_below(path, root),
                "{path:?} should be strictly below {root:?}"
            );
        }

        for (path, root) in [
            (r"C:\cert\case", r"C:\cert\case"),
            (r"C:\cert\case-other\host.dwg", r"C:\cert\case"),
            (r"C:\cert\case\sub\..\..\outside.dwg", r"C:\cert\case"),
            (r"C:\cert\case\.\host.dwg", r"C:\cert\case"),
            (r"C:\cert\case\\host.dwg", r"C:\cert\case"),
            (r"C:cert\case\host.dwg", r"C:\cert\case"),
            (r"D:\cert\case\host.dwg", r"C:\cert\case"),
            (
                r"\\server\share-other\cert\case\host.dwg",
                r"\\server\share\cert\case",
            ),
            (
                r"\\server\share\cert\case2\host.dwg",
                r"\\server\share\cert\case",
            ),
            (
                r"\\?\UNC\server\share\cert\case\..\outside.dwg",
                r"\\?\UNC\server\share\cert\case",
            ),
        ] {
            assert!(
                !certification_path_is_strictly_below(path, root),
                "{path:?} must not be accepted below {root:?}"
            );
        }

        for path in [
            r"C:relative.dwg",
            r"C:\cert\.\host.dwg",
            r"C:\cert\sub\..\host.dwg",
            r"C:\cert\\host.dwg",
            r"C:\\",
            r"\\server\\share\host.dwg",
            r"\\server\share\\",
            r"\\?\C:\cert\..\host.dwg",
            r"//?/UNC/server/share/cert//host.dwg",
            "/cert/case/host.dwg",
        ] {
            assert!(
                certification_path_key(path).is_none(),
                "{path:?} must not parse as a canonical absolute path"
            );
        }

        for path in [
            r"C:\cert\case\host.dwg",
            r"\\?\C:\cert\case\host.dwg",
            r"\\server\share\cert\case\host.dwg",
            r"\\?\UNC\server\share\cert\case\host.dwg",
        ] {
            let mut errors = Vec::new();
            validate_absolute_certification_file_path(path, "file", &mut errors);
            assert!(errors.is_empty(), "{path:?}: {errors:?}");
        }
        for path in [
            "/cert/case/host.dwg",
            r"C:\cert\case\host.dwg\",
            r"\\server\share\cert\case\host.dwg\",
            r"C:\",
            r"\\server\share\",
        ] {
            let mut errors = Vec::new();
            validate_absolute_certification_file_path(path, "file", &mut errors);
            assert!(!errors.is_empty(), "{path:?} must not be a file path");
        }
    }

    #[test]
    fn certification_manifest_validation_rejects_semantic_drift() {
        let manifest = committed_certification_manifest();
        let profiles = [certification_profile_definition()];

        let mut uppercase_dwg_errors = Vec::new();
        validate_relative_dwg_fixture_path(
            "nested/CERTIFICATION.DwG",
            "uppercase fixture",
            &mut uppercase_dwg_errors,
        );
        assert!(uppercase_dwg_errors.is_empty(), "{uppercase_dwg_errors:?}");

        let mut wrong_engine = manifest.clone();
        wrong_engine.runtime.autocad_version = "2025".to_string();
        let error = validate_release_manifest(&wrong_engine, &profiles, true)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("product/version does not match activation target"),
            "{error}"
        );

        let mut wrong_arg_policy = manifest.clone();
        wrong_arg_policy.runtime.certified_arg_policy_id = "Personal Policy".to_string();
        let error = validate_release_manifest(&wrong_arg_policy, &profiles, true)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("certified_arg_policy_id")
                && error.contains("canonical lowercase ASCII"),
            "{error}"
        );

        let mut tier2_dxf_host = manifest.clone();
        tier2_dxf_host.tier2_drawings[0].path = "tier2/profile-host.dxf".to_string();
        let error = validate_release_manifest(&tier2_dxf_host, &profiles, true)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("profile-host.dxf") && error.contains(".dwg extension"),
            "{error}"
        );

        let mut layer_dxf_host = manifest.clone();
        layer_dxf_host.layer_mutation_cases[0].path = "layers/layer-host.dxf".to_string();
        let error = validate_layer_mutation_manifest(&layer_dxf_host)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("layer-host.dxf") && error.contains(".dwg extension"),
            "{error}"
        );

        let mut layer_dxf_source = manifest.clone();
        layer_dxf_source.layer_mutation_cases[1].referenced_source_fixtures[0].path =
            "layers/refs/layer-source.dxf".to_string();
        let error = validate_layer_mutation_manifest(&layer_dxf_source)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("layer-source.dxf") && error.contains(".dwg extension"),
            "{error}"
        );

        let mut duplicate_profile = manifest.clone();
        duplicate_profile
            .tier2_drawings
            .push(duplicate_profile.tier2_drawings[0].clone());
        let error = validate_release_manifest(&duplicate_profile, &profiles, true)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("requires exactly one Tier 2 drawing"),
            "{error}"
        );

        let mut all_fields_requested = manifest.clone();
        all_fields_requested.tier2_drawings[0].write_fields = profiles[0]
            .field_mappings
            .iter()
            .map(|mapping| CertificationWriteField {
                field: mapping.canonical_field.clone(),
                value: format!("CERT-{}", mapping.canonical_field),
            })
            .collect();
        let error = validate_release_manifest(&all_fields_requested, &profiles, true)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("must leave at least one fingerprint attribute unrequested"),
            "{error}"
        );

        let mut reserved_fixture_name = manifest.clone();
        reserved_fixture_name.tier2_drawings[0].path = "profiles/AUX.dwg".to_string();
        let error = validate_release_manifest(&reserved_fixture_name, &profiles, true)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("safe normalized Windows-relative ASCII fixture path"),
            "{error}"
        );

        let mut false_xref = manifest.clone();
        let assertion = &mut false_xref.layer_mutation_cases[1].operations[0].expected;
        let LayerCertificationExpectedOutcome::Passed {
            assertion: LayerCertificationPassedAssertion::Layer { layer },
        } = assertion
        else {
            panic!("fixture operation shape changed");
        };
        layer.xref_dependent = CertificationFieldExpectation::Omitted;
        let error = validate_layer_mutation_manifest(&false_xref)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("xref-dependent override assertion"),
            "{error}"
        );

        let mut missing_lineweight_variant = manifest.clone();
        missing_lineweight_variant.layer_mutation_cases[0]
            .operations
            .remove(3);
        let error = validate_layer_mutation_manifest(&missing_lineweight_variant)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("structured lineweight variant 'by_block'"),
            "{error}"
        );

        let mut missing_expanded_record = manifest.clone();
        missing_expanded_record.layer_mutation_cases[0].operations[0].expected =
            LayerCertificationExpectedOutcome::Passed {
                assertion: LayerCertificationPassedAssertion::Layer {
                    layer: LayerCertificationLayerExpectation {
                        handle: CertificationFieldExpectation::Value("2A".to_string()),
                        ..LayerCertificationLayerExpectation::default()
                    },
                },
            };
        let error = validate_layer_mutation_manifest(&missing_expanded_record)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("expanded 17-field record witness"),
            "{error}"
        );

        let mut missing_get_witness = manifest.clone();
        missing_get_witness.layer_mutation_cases[0]
            .operations
            .remove(1);
        let error = validate_layer_mutation_manifest(&missing_get_witness)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("passing exact 17-field get_layer witness"),
            "{error}"
        );

        let mut partial_get_witness = manifest.clone();
        partial_get_witness.layer_mutation_cases[0].operations[1].expected =
            LayerCertificationExpectedOutcome::Passed {
                assertion: LayerCertificationPassedAssertion::Layer {
                    layer: LayerCertificationLayerExpectation {
                        handle: CertificationFieldExpectation::Value("2A".to_string()),
                        ..LayerCertificationLayerExpectation::default()
                    },
                },
            };
        let error = validate_layer_mutation_manifest(&partial_get_witness)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("must assert an exact 17-field read witness")
                && error.contains("passing exact 17-field get_layer witness"),
            "{error}"
        );

        let mut raw_write = manifest.clone();
        raw_write.layer_mutation_cases[0].operations[3].params["properties"]["line_weight"] =
            serde_json::json!({"kind": "raw", "raw_value": -3});
        let error = validate_layer_mutation_manifest(&raw_write)
            .unwrap_err()
            .to_string();
        assert!(error.contains("params are not closed/valid"), "{error}");

        let mut false_negative = manifest;
        false_negative.layer_mutation_cases[0].operations[9].params["properties"]["line_weight"]
            ["hundredths_mm"] = serde_json::json!(35);
        let error = validate_layer_mutation_manifest(&false_negative)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("exact negative error_code is not exercised"),
            "{error}"
        );
    }

    #[test]
    fn certification_evidence_validators_accept_exact_closed_bundles() {
        let manifest = committed_certification_manifest();
        let manifest_sha256 =
            certification_manifest_sha256(committed_certification_manifest_bytes());
        let profiles = [certification_profile_definition()];
        let tier2 = passed_tier2_evidence(&manifest, &manifest_sha256);
        validate_tier2_profile_certification_evidence(
            &manifest,
            &profiles,
            true,
            &manifest_sha256,
            &tier2,
        )
        .unwrap();
        let layers = passed_layer_evidence(&manifest, &manifest_sha256);
        validate_layer_mutation_evidence(&manifest, &manifest_sha256, &layers).unwrap();
    }

    #[test]
    fn profile_isolation_evidence_rejects_inventory_classification_and_lifecycle_tampering() {
        let manifest = committed_certification_manifest();
        let manifest_sha256 =
            certification_manifest_sha256(committed_certification_manifest_bytes());
        let profiles = [certification_profile_definition()];
        let tier2 = passed_tier2_evidence(&manifest, &manifest_sha256);
        let validate_tier2 = |evidence: &Tier2ProfileCertificationEvidence| {
            validate_tier2_profile_certification_evidence(
                &manifest,
                &profiles,
                true,
                &manifest_sha256,
                evidence,
            )
            .unwrap_err()
            .to_string()
        };

        let serialized = serde_json::to_value(&tier2.drawings[0].profile_isolation[0]).unwrap();
        let fields = serialized
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            fields,
            BTreeSet::from([
                "absent_after",
                "absent_before",
                "cleanup_performed",
                "expectation",
                "invocation_id",
                "present_after",
                "tool",
            ])
        );

        let mut wrong_count = tier2.clone();
        wrong_count.drawings[0].profile_isolation.pop();
        assert!(validate_tier2(&wrong_count).contains("profile_isolation invocation count"));

        let mut wrong_order = tier2.clone();
        wrong_order.drawings[0].profile_isolation.swap(0, 1);
        assert!(validate_tier2(&wrong_order).contains("invocation_id"));

        let mut wrong_classification = tier2.clone();
        wrong_classification.drawings[0].profile_isolation[0].expectation =
            CertificationProfileLaunchExpectation::EngineImportRequired;
        assert!(validate_tier2(&wrong_classification).contains("closed classification"));

        let mut preexisting = tier2.clone();
        preexisting.drawings[0].profile_isolation[0].absent_before = false;
        assert!(validate_tier2(&preexisting).contains("absent_before"));

        let mut unexpected_engine = tier2.clone();
        unexpected_engine.drawings[0].profile_isolation[0].present_after = true;
        assert!(validate_tier2(&unexpected_engine).contains("present_after"));

        let mut missing_cleanup = tier2.clone();
        missing_cleanup.drawings[0].profile_isolation[1].cleanup_performed = false;
        assert!(validate_tier2(&missing_cleanup).contains("cleanup_performed"));

        let mut stale_after_cleanup = tier2;
        stale_after_cleanup.drawings[0].profile_isolation[1].absent_after = false;
        assert!(validate_tier2(&stale_after_cleanup).contains("absent_after"));

        let layers = passed_layer_evidence(&manifest, &manifest_sha256);
        let validate_layers = |evidence: &LayerMutationCertificationEvidence| {
            validate_layer_mutation_evidence(&manifest, &manifest_sha256, evidence)
                .unwrap_err()
                .to_string()
        };
        let readback_index = layers.cases[0]
            .profile_isolation
            .iter()
            .position(|row| row.invocation_id.starts_with("readback/"))
            .unwrap();
        let mut missing_conditional_readback = layers.clone();
        missing_conditional_readback.cases[0]
            .profile_isolation
            .remove(readback_index);
        assert!(validate_layers(&missing_conditional_readback)
            .contains("profile_isolation invocation count"));

        let mut wrong_tool = layers;
        wrong_tool.cases[0].profile_isolation[2].tool = "unexpected_tool".to_string();
        assert!(validate_layers(&wrong_tool).contains("tool"));

        let xref_manifest = valid_xref_certification_manifest();
        for scenario in [
            XrefCertificationScenario::SourceRace,
            XrefCertificationScenario::HostRace,
        ] {
            let race = xref_manifest
                .release_cases
                .iter()
                .find(|case| case.scenario == scenario)
                .unwrap();
            assert_eq!(
                xref_certification_profile_launch_expectation(
                    race,
                    XrefCertificationEvidenceClass::ReleaseConformance,
                )
                .unwrap(),
                CertificationProfileLaunchExpectation::NoEngineExpected
            );
        }
        let attestation = valid_xref_attestation(&xref_manifest);
        let mut xref = valid_xref_evidence(
            &xref_manifest,
            &attestation,
            XrefCertificationEvidenceClass::InstrumentedTransaction,
        );
        let before_save = xref_manifest
            .instrumented_cases
            .iter()
            .position(|case| case.failpoint == Some(XrefCertificationFailpoint::BeforeSave))
            .unwrap();
        xref.case_results[before_save].profile_isolation[3].expectation =
            CertificationProfileLaunchExpectation::EngineImportRequired;
        let error = validate_xref_certification_evidence(&xref_manifest, &xref, &attestation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("closed classification"), "{error}");
    }

    #[test]
    fn tier2_evidence_rejects_runtime_inventory_digest_and_plot_drift() {
        let manifest = committed_certification_manifest();
        let manifest_sha256 =
            certification_manifest_sha256(committed_certification_manifest_bytes());
        let profiles = [certification_profile_definition()];
        let valid = passed_tier2_evidence(&manifest, &manifest_sha256);
        let validate = |evidence: &Tier2ProfileCertificationEvidence| {
            validate_tier2_profile_certification_evidence(
                &manifest,
                &profiles,
                true,
                &manifest_sha256,
                evidence,
            )
            .unwrap_err()
            .to_string()
        };

        let mut wrong_class = valid.clone();
        wrong_class.evidence_class = CertificationEvidenceClass::LayerMutation;
        assert!(validate(&wrong_class).contains("wrong evidence_class"));

        let mut wrong_runtime = valid.clone();
        wrong_runtime.runtime.platform = "linux".to_string();
        assert!(validate(&wrong_runtime).contains("platform must be windows"));

        let mut wrong_activation_target = valid.clone();
        wrong_activation_target
            .runtime
            .activation_target
            .registry_family = "R25.0".to_string();
        assert!(validate(&wrong_activation_target)
            .contains("runtime activation_target does not match manifest"));

        let mut mismatched_canonical_binary = valid.clone();
        mismatched_canonical_binary
            .runtime
            .release_binary_canonical_path = r"\\?\C:\different\autocad-mcp.exe".to_string();
        assert!(validate(&mismatched_canonical_binary)
            .contains("configured and canonical release binary paths"));

        let mut wrong_engine_shape = valid.clone();
        wrong_engine_shape.runtime.accoreconsole_canonical_path =
            r"\\?\C:\Program Files\Autodesk\AutoCAD 2026\acad.exe".to_string();
        assert!(validate(&wrong_engine_shape)
            .contains("does not identify accoreconsole.exe under an AutoCAD-labelled path"));

        let mut unix_drawing_path = valid.clone();
        unix_drawing_path.drawings[0].staged_drawing_canonical_path =
            "/cert/staged/title.dwg".to_string();
        assert!(validate(&unix_drawing_path).contains("absolute Windows file path"));

        let mut wrong_fixture_root = valid.clone();
        wrong_fixture_root.fixture_root_canonical_path =
            r"\\?\C:\different-private-fixtures".to_string();
        assert!(
            validate(&wrong_fixture_root).contains("does not identify the manifest fixture_root")
        );

        let mut overlapping_case_root = valid.clone();
        overlapping_case_root.drawings[0].staged_case_root_canonical_path = format!(
            r"{}\case",
            overlapping_case_root.fixture_root_canonical_path
        );
        assert!(validate(&overlapping_case_root).contains("overlaps the private fixture root"));

        let mut renamed_staged_drawing = valid.clone();
        renamed_staged_drawing.drawings[0].staged_drawing_canonical_path = format!(
            r"{}\fixture\profiles\renamed.dwg",
            renamed_staged_drawing.drawings[0].staged_case_root_canonical_path
        );
        assert!(validate(&renamed_staged_drawing)
            .contains("does not preserve the manifest-relative fixture path"));

        let mut trailing_plot_path = valid.clone();
        trailing_plot_path.drawings[0]
            .plot
            .as_mut()
            .unwrap()
            .output_canonical_path
            .push('\\');
        assert!(validate(&trailing_plot_path).contains("absolute Windows file path"));

        let mut escaped_plot = valid.clone();
        escaped_plot.drawings[0]
            .plot
            .as_mut()
            .unwrap()
            .output_canonical_path = r"C:\outside\plot.pdf".to_string();
        assert!(validate(&escaped_plot).contains("not strictly below the staged case root"));

        let mut stale_binary = valid.clone();
        stale_binary.runtime.release_binary_sha256_after = "0".repeat(64);
        assert!(validate(&stale_binary).contains("release binary SHA-256 after"));

        let mut wrong_arg_policy = valid.clone();
        wrong_arg_policy
            .runtime
            .binary_reported_certified_arg_policy_sha256 = "0".repeat(64);
        assert!(
            validate(&wrong_arg_policy).contains("binary-reported certified ARG policy SHA-256")
        );

        let mut changed_mapping = valid.clone();
        let first_tag = changed_mapping.runtime.binary_reported_title_block_profiles[0]
            .field_mappings[0]
            .attribute_tag
            .clone();
        let second_tag = changed_mapping.runtime.binary_reported_title_block_profiles[0]
            .field_mappings[1]
            .attribute_tag
            .clone();
        changed_mapping.runtime.binary_reported_title_block_profiles[0].field_mappings[0]
            .attribute_tag = second_tag;
        changed_mapping.runtime.binary_reported_title_block_profiles[0].field_mappings[1]
            .attribute_tag = first_tag;
        assert!(validate(&changed_mapping)
            .contains("binary-reported title-block profile definitions do not match"));

        let mut missing_drawing = valid.clone();
        missing_drawing.drawings.clear();
        assert!(validate(&missing_drawing).contains("drawing inventory"));

        let mut changed_tags = valid.clone();
        changed_tags.drawings[0].post_title_blocks.records[0].attributes[0].tag =
            "UNEXPECTED".to_string();
        changed_tags.drawings[0].post_title_blocks.sha256 = certification_title_snapshot_sha256(
            &changed_tags.drawings[0].post_title_blocks.records,
        );
        assert!(validate(&changed_tags).contains("target"));

        let mut no_non_target_witness = valid.clone();
        let remove_non_target = |snapshot: &mut CertificationTitleBlockSnapshot| {
            snapshot
                .records
                .retain(|record| record.normalized_block_name != "OTHER_ATTRIBUTED_INSERT");
            snapshot.sha256 = certification_title_snapshot_sha256(&snapshot.records);
        };
        remove_non_target(&mut no_non_target_witness.drawings[0].pre_title_blocks);
        remove_non_target(&mut no_non_target_witness.drawings[0].post_title_blocks);
        assert!(validate(&no_non_target_witness)
            .contains("must observe at least one non-target attributed record"));

        let mut empty_plot = valid;
        empty_plot.drawings[0].plot.as_mut().unwrap().pdf_size_bytes = 0;
        assert!(validate(&empty_plot).contains("plot PDF is empty"));
    }

    #[test]
    fn tier2_title_snapshots_bind_private_values_and_unchanged_observations() {
        let manifest = committed_certification_manifest();
        let manifest_sha256 =
            certification_manifest_sha256(committed_certification_manifest_bytes());
        let profile = certification_profile_definition();
        let valid = passed_tier2_evidence(&manifest, &manifest_sha256);
        let validate = |profiles: &[CertificationProfileDefinition],
                        evidence: &Tier2ProfileCertificationEvidence| {
            validate_tier2_profile_certification_evidence(
                &manifest,
                profiles,
                true,
                &manifest_sha256,
                evidence,
            )
            .unwrap_err()
            .to_string()
        };

        let serialized = serde_json::to_string(&valid).unwrap();
        for private_value in [
            "private-before-value",
            "ALT-CERT-001",
            "CERT-001",
            "CERTIFICATION TITLE",
            "PERSISTED READBACK",
            "P02",
        ] {
            assert!(
                !serialized.contains(private_value),
                "raw title value leaked into evidence: {private_value}"
            );
        }
        let drawing = &manifest.tier2_drawings[0];
        let title_hash = certification_title_value_sha256(
            &manifest.release_id,
            &drawing.drawing_id,
            "REVISION",
            "P02",
        );
        assert_ne!(
            title_hash,
            certification_title_value_sha256(
                "different-release",
                &drawing.drawing_id,
                "REVISION",
                "P02",
            )
        );
        assert_ne!(
            title_hash,
            certification_title_value_sha256(
                &manifest.release_id,
                "different-drawing",
                "REVISION",
                "P02",
            )
        );
        assert_ne!(
            title_hash,
            certification_title_layer_sha256(&manifest.release_id, &drawing.drawing_id, "P02",)
        );

        let mut digest_tamper = valid.clone();
        digest_tamper.drawings[0].pre_title_blocks.sha256 = "0".repeat(64);
        assert!(validate(std::slice::from_ref(&profile), &digest_tamper)
            .contains("pre_title_blocks sha256"));

        let mut expected_value_tamper = valid.clone();
        expected_value_tamper.drawings[0].post_title_blocks.records[0]
            .attributes
            .iter_mut()
            .find(|attribute| attribute.tag == "REVISION")
            .unwrap()
            .value_sha256 = "0".repeat(64);
        expected_value_tamper.drawings[0].post_title_blocks.sha256 =
            certification_title_snapshot_sha256(
                &expected_value_tamper.drawings[0].post_title_blocks.records,
            );
        assert!(
            validate(std::slice::from_ref(&profile), &expected_value_tamper)
                .contains("does not contain the expected hash")
        );

        let mut overlapping_profile = profile.clone();
        overlapping_profile.profile_id = "AUTOCAD_MCP_GENERIC_ALIAS".to_string();
        let overlapping_profiles = vec![profile.clone(), overlapping_profile];
        let mut ambiguous_profile_match = valid.clone();
        ambiguous_profile_match
            .runtime
            .binary_reported_title_block_profiles = overlapping_profiles.clone();
        let error = validate(&overlapping_profiles, &ambiguous_profile_match);
        assert!(error.contains("resolves supported profiles"), "{error}");

        let mut with_non_target = valid.clone();
        let mut non_target = with_non_target.drawings[0].pre_title_blocks.records[0].clone();
        non_target.normalized_block_name = "OTHER_TITLE".to_string();
        non_target.layer_sha256 =
            certification_title_layer_sha256(&manifest.release_id, &drawing.drawing_id, "OTHER");
        let append_non_target = |snapshot: &mut CertificationTitleBlockSnapshot| {
            snapshot.records.push(non_target.clone());
            sort_title_records(&mut snapshot.records);
            snapshot.sha256 = certification_title_snapshot_sha256(&snapshot.records);
        };
        append_non_target(&mut with_non_target.drawings[0].pre_title_blocks);
        append_non_target(&mut with_non_target.drawings[0].post_title_blocks);
        validate_tier2_profile_certification_evidence(
            &manifest,
            std::slice::from_ref(&profile),
            true,
            &manifest_sha256,
            &with_non_target,
        )
        .unwrap();
        let post_non_target = with_non_target.drawings[0]
            .post_title_blocks
            .records
            .iter_mut()
            .find(|record| record.normalized_block_name == "OTHER_TITLE")
            .unwrap();
        post_non_target.attributes[0].value_sha256 = "9".repeat(64);
        with_non_target.drawings[0].post_title_blocks.sha256 = certification_title_snapshot_sha256(
            &with_non_target.drawings[0].post_title_blocks.records,
        );
        assert!(validate(std::slice::from_ref(&profile), &with_non_target)
            .contains("non-target title-block observations changed"));

        let mut profile_with_unrequested = profile;
        profile_with_unrequested
            .fingerprint
            .attribute_tags
            .push("ZZ_UNREQUESTED".to_string());
        let unrequested_hash = certification_title_value_sha256(
            &manifest.release_id,
            &drawing.drawing_id,
            "ZZ_UNREQUESTED",
            "private-unrequested-value",
        );
        let mut with_unrequested = valid;
        with_unrequested.drawings[0].observed_fingerprint =
            Some(profile_with_unrequested.fingerprint.clone());
        with_unrequested
            .runtime
            .binary_reported_title_block_profiles = vec![profile_with_unrequested.clone()];
        let append_unrequested = |snapshot: &mut CertificationTitleBlockSnapshot| {
            snapshot.records[0]
                .attributes
                .push(CertificationHashedTitleBlockAttribute {
                    tag: "ZZ_UNREQUESTED".to_string(),
                    value_sha256: unrequested_hash.clone(),
                });
            snapshot.sha256 = certification_title_snapshot_sha256(&snapshot.records);
        };
        append_unrequested(&mut with_unrequested.drawings[0].pre_title_blocks);
        append_unrequested(&mut with_unrequested.drawings[0].post_title_blocks);
        validate_tier2_profile_certification_evidence(
            &manifest,
            &[profile_with_unrequested.clone()],
            true,
            &manifest_sha256,
            &with_unrequested,
        )
        .unwrap();
        with_unrequested.drawings[0].post_title_blocks.records[0]
            .attributes
            .last_mut()
            .unwrap()
            .value_sha256 = "8".repeat(64);
        with_unrequested.drawings[0].post_title_blocks.sha256 = certification_title_snapshot_sha256(
            &with_unrequested.drawings[0].post_title_blocks.records,
        );
        assert!(validate(&[profile_with_unrequested], &with_unrequested)
            .contains("unrequested target attributes"));
    }

    #[test]
    fn layer_evidence_rejects_inventory_chain_reference_status_and_observation_drift() {
        let manifest = committed_certification_manifest();
        let manifest_sha256 =
            certification_manifest_sha256(committed_certification_manifest_bytes());
        let valid = passed_layer_evidence(&manifest, &manifest_sha256);
        let validate = |evidence: &LayerMutationCertificationEvidence| {
            validate_layer_mutation_evidence(&manifest, &manifest_sha256, evidence)
                .unwrap_err()
                .to_string()
        };

        let mut missing_case = valid.clone();
        missing_case.cases.pop();
        assert!(validate(&missing_case).contains("case inventory"));

        let mut wrong_fixture_root = valid.clone();
        wrong_fixture_root.fixture_root_canonical_path =
            r"\\?\C:\different-private-fixtures".to_string();
        assert!(
            validate(&wrong_fixture_root).contains("does not identify the manifest fixture_root")
        );

        let mut overlapping_case_root = valid.clone();
        overlapping_case_root.cases[0].staged_case_root_canonical_path = format!(
            r"{}\case",
            overlapping_case_root.fixture_root_canonical_path
        );
        assert!(validate(&overlapping_case_root).contains("overlaps the private fixture root"));

        let mut renamed_host = valid.clone();
        renamed_host.cases[0].staged_drawing_canonical_path = format!(
            r"{}\fixture\layers\renamed-host.dwg",
            renamed_host.cases[0].staged_case_root_canonical_path
        );
        assert!(validate(&renamed_host)
            .contains("staged drawing path does not preserve the manifest-relative fixture path"));

        let mut rearranged_source = valid.clone();
        rearranged_source.cases[1].referenced_sources[0].staged_canonical_path = format!(
            r"{}\fixture\layers\layer-source.dwg",
            rearranged_source.cases[1].staged_case_root_canonical_path
        );
        assert!(validate(&rearranged_source).contains(
            "referenced source 'layers/refs/layer-source.dwg' path does not preserve the manifest-relative fixture path"
        ));

        let mut wrong_params = valid.clone();
        wrong_params.cases[0].operations[0].params = serde_json::json!({"unexpected": true});
        assert!(validate(&wrong_params).contains("do not match manifest"));

        let mut broken_chain = valid.clone();
        broken_chain.cases[0].operations[1].input_drawing_sha256 = "0".repeat(64);
        assert!(validate(&broken_chain).contains("input_drawing_sha256"));

        let mut changed_reference = valid.clone();
        changed_reference.cases[1].referenced_sources[0].after_sha256 = "0".repeat(64);
        assert!(validate(&changed_reference).contains("referenced source"));

        let mut trailing_source_path = valid.clone();
        trailing_source_path.cases[1].referenced_sources[0]
            .staged_canonical_path
            .push('\\');
        assert!(validate(&trailing_source_path).contains("absolute Windows file path"));

        let mut false_assertion = valid.clone();
        let observation = false_assertion.cases[0].operations[0]
            .actual_output
            .as_mut()
            .unwrap();
        let CertificationLayerObservedResult::ListLayers { records } = &mut observation.result
        else {
            panic!("fixture list witness changed");
        };
        records
            .iter_mut()
            .find(|record| record.handle == "2A")
            .unwrap()
            .color_index = Some(1);
        observation.sha256 = certification_layer_output_sha256(&observation.result);
        assert!(validate(&false_assertion).contains("exact manifest record"));

        let failed_index = manifest.layer_mutation_cases[0]
            .operations
            .iter()
            .position(|operation| {
                matches!(
                    operation.expected,
                    LayerCertificationExpectedOutcome::Failed { .. }
                )
            })
            .unwrap();
        let mut wrong_error = valid.clone();
        wrong_error.cases[0].operations[failed_index].observed_error_code =
            Some("wrong_error".to_string());
        assert!(validate(&wrong_error).contains("observed failure/error code"));

        let mut missing_output = valid;
        missing_output.cases[0].operations[0].actual_output = None;
        assert!(validate(&missing_output).contains("missing typed actual_output"));
    }

    #[test]
    fn layer_evidence_recomputes_typed_outputs_readbacks_confinement_and_cache_keys() {
        let manifest = committed_certification_manifest();
        let manifest_sha256 =
            certification_manifest_sha256(committed_certification_manifest_bytes());
        let valid = passed_layer_evidence(&manifest, &manifest_sha256);
        let validate = |evidence: &LayerMutationCertificationEvidence| {
            validate_layer_mutation_evidence(&manifest, &manifest_sha256, evidence)
                .unwrap_err()
                .to_string()
        };

        let mut output_digest_tamper = valid.clone();
        output_digest_tamper.cases[0].operations[0]
            .actual_output
            .as_mut()
            .unwrap()
            .sha256 = "0".repeat(64);
        assert!(validate(&output_digest_tamper).contains("actual_output sha256"));

        let mut readback_digest_tamper = valid.clone();
        readback_digest_tamper.cases[0].readback_snapshots[0].layers[0].locked ^= true;
        assert!(validate(&readback_digest_tamper).contains("readback snapshot[0] sha256"));

        let mut unreferenced_snapshot = valid.clone();
        let mut extra = unreferenced_snapshot.cases[0].readback_snapshots[0].clone();
        extra.host_drawing_sha256 = "9".repeat(64);
        extra.state_key_sha256 = expected_layer_state_key(
            &extra.host_drawing_sha256,
            &manifest.layer_mutation_cases[0],
        );
        extra.sha256 = certification_layer_readback_sha256(&extra);
        unreferenced_snapshot.cases[0]
            .readback_snapshots
            .push(extra);
        assert!(validate(&unreferenced_snapshot)
            .contains("readback snapshot inventory must equal exactly"));

        let mut forged_readback = valid.clone();
        let initial_snapshot_index = forged_readback.cases[0]
            .readback_snapshots
            .iter()
            .position(|snapshot| {
                snapshot.sha256 == forged_readback.cases[0].initial_readback_sha256
            })
            .unwrap();
        forged_readback.cases[0].readback_snapshots[initial_snapshot_index].layers[0].color_index =
            Some(1);
        rehash_layer_snapshot_references(&mut forged_readback.cases[0], initial_snapshot_index);
        assert!(validate(&forged_readback).contains("persisted full readback"));

        let mut escaped_source = valid.clone();
        let xref_snapshot_index = 0;
        escaped_source.cases[1].readback_snapshots[xref_snapshot_index].resolved_sources[0]
            .canonical_path = format!(
            r"{}\nested\..\..\outside.dwg",
            escaped_source.cases[1].staged_case_root_canonical_path
        );
        rehash_layer_snapshot_references(&mut escaped_source.cases[1], xref_snapshot_index);
        let error = validate(&escaped_source);
        assert!(
            error.contains("outside the staged case root")
                || error.contains("outside the staged fixture tree"),
            "{error}"
        );

        let mut source_inventory_tamper = valid.clone();
        let source_inventory_root = source_inventory_tamper.cases[1]
            .staged_case_root_canonical_path
            .clone();
        source_inventory_tamper.cases[1].readback_snapshots[0]
            .resolved_sources
            .push(CertificationResolvedSourceEvidence {
                manifest_path: "zz-extra.dwg".to_string(),
                canonical_path: format!(r"{source_inventory_root}\zz-extra.dwg"),
                sha256: "a".repeat(64),
            });
        assert!(validate(&source_inventory_tamper).contains("resolved-source inventory"));

        let mut duplicate_chain = valid.clone();
        let duplicate = duplicate_chain.cases[1].readback_snapshots[0]
            .dependency_graph
            .dependencies[0]
            .clone();
        duplicate_chain.cases[1].readback_snapshots[0]
            .dependency_graph
            .dependencies
            .push(duplicate);
        rehash_layer_snapshot_references(&mut duplicate_chain.cases[1], 0);
        assert!(validate(&duplicate_chain).contains("duplicate attachment_chain"));

        let mut wrong_parent_host = valid.clone();
        let mut nested = serde_json::to_value(
            &wrong_parent_host.cases[1].readback_snapshots[0]
                .dependency_graph
                .dependencies[0],
        )
        .unwrap();
        nested["attachment_chain"] = serde_json::json!(["3A", "3B"]);
        nested["depth"] = serde_json::json!(1);
        nested["attachment"]["handle"] = serde_json::json!("3B");
        nested["attachment"]["name"] = serde_json::json!("NESTED_SOURCE");
        nested["propagation_state"] = serde_json::json!("propagated");
        nested["immediate_host_path"] =
            serde_json::json!(wrong_parent_host.cases[1].staged_drawing_canonical_path);
        wrong_parent_host.cases[1].readback_snapshots[0]
            .dependency_graph
            .dependencies
            .push(serde_json::from_value(nested).unwrap());
        rehash_layer_snapshot_references(&mut wrong_parent_host.cases[1], 0);
        assert!(validate(&wrong_parent_host)
            .contains("immediate_host_path does not match its inspected parent resolved_path"));

        let mut changed_state_key = valid.clone();
        changed_state_key.cases[0].operations[0].persisted_state_key_sha256 = "0".repeat(64);
        assert!(validate(&changed_state_key).contains("persisted_state_key_sha256"));

        let mut changed_cache_reference = valid.clone();
        let initial_state_key = changed_cache_reference.cases[0].operations[0]
            .persisted_state_key_sha256
            .clone();
        let different_readback = changed_cache_reference.cases[0]
            .readback_snapshots
            .iter()
            .find(|snapshot| snapshot.state_key_sha256 != initial_state_key)
            .unwrap()
            .sha256
            .clone();
        changed_cache_reference.cases[0].operations[0].persisted_readback_sha256 =
            different_readback;
        assert!(validate(&changed_cache_reference)
            .contains("unchanged digest key must reuse the preceding readback"));

        let mut raw_readback = valid;
        let mut digest_replacements = Vec::new();
        for snapshot in &mut raw_readback.cases[0].readback_snapshots {
            let old_sha256 = snapshot.sha256.clone();
            snapshot
                .layers
                .iter_mut()
                .find(|record| record.handle == "10")
                .unwrap()
                .line_weight = CertificationObservedLayerLineWeight::Raw { raw_value: -3 };
            snapshot.sha256 = certification_layer_readback_sha256(snapshot);
            digest_replacements.push((old_sha256, snapshot.sha256.clone()));
        }
        for (old_sha256, new_sha256) in digest_replacements {
            if raw_readback.cases[0].initial_readback_sha256 == old_sha256 {
                raw_readback.cases[0]
                    .initial_readback_sha256
                    .clone_from(&new_sha256);
            }
            for operation in &mut raw_readback.cases[0].operations {
                if operation.persisted_readback_sha256 == old_sha256 {
                    operation.persisted_readback_sha256.clone_from(&new_sha256);
                }
            }
        }
        let observation = raw_readback.cases[0].operations[0]
            .actual_output
            .as_mut()
            .unwrap();
        let CertificationLayerObservedResult::ListLayers { records } = &mut observation.result
        else {
            panic!("fixture list witness changed");
        };
        records
            .iter_mut()
            .find(|record| record.handle == "10")
            .unwrap()
            .line_weight = CertificationObservedLayerLineWeight::Raw { raw_value: -3 };
        observation.sha256 = certification_layer_output_sha256(&observation.result);
        validate_layer_mutation_evidence(&manifest, &manifest_sha256, &raw_readback).unwrap();
    }

    #[test]
    fn layer_mutation_deltas_reject_collateral_persisted_changes() {
        let manifest = committed_certification_manifest();
        let manifest_sha256 =
            certification_manifest_sha256(committed_certification_manifest_bytes());
        let valid = passed_layer_evidence(&manifest, &manifest_sha256);
        let validate = |evidence: &LayerMutationCertificationEvidence| {
            validate_layer_mutation_evidence(&manifest, &manifest_sha256, evidence)
                .unwrap_err()
                .to_string()
        };

        let mut create_collateral = valid.clone();
        mutate_operation_snapshot(&mut create_collateral, 0, 2, |snapshot| {
            snapshot
                .layers
                .iter_mut()
                .find(|record| record.handle == "10")
                .unwrap()
                .locked = true;
        });
        assert!(validate(&create_collateral).contains("create delta"));

        let mut update_unrequested = valid.clone();
        mutate_operation_snapshot(&mut update_unrequested, 0, 3, |snapshot| {
            snapshot
                .layers
                .iter_mut()
                .find(|record| record.handle == "2A")
                .unwrap()
                .color_index = Some(1);
        });
        let update_observation = update_unrequested.cases[0].operations[3]
            .actual_output
            .as_mut()
            .unwrap();
        let CertificationLayerObservedResult::Layer { record } = &mut update_observation.result
        else {
            panic!("fixture update result changed");
        };
        record.color_index = Some(1);
        update_observation.sha256 = certification_layer_output_sha256(&update_observation.result);
        assert!(validate(&update_unrequested).contains("update delta"));

        let mut rename_non_name = valid.clone();
        mutate_operation_snapshot(&mut rename_non_name, 0, 6, |snapshot| {
            snapshot
                .layers
                .iter_mut()
                .find(|record| record.handle == "2C")
                .unwrap()
                .locked = true;
        });
        let rename_observation = rename_non_name.cases[0].operations[6]
            .actual_output
            .as_mut()
            .unwrap();
        let CertificationLayerObservedResult::Layer { record } = &mut rename_observation.result
        else {
            panic!("fixture rename result changed");
        };
        record.locked = true;
        rename_observation.sha256 = certification_layer_output_sha256(&rename_observation.result);
        assert!(validate(&rename_non_name).contains("rename delta"));

        let mut delete_collateral = valid;
        mutate_operation_snapshot(&mut delete_collateral, 0, 7, |snapshot| {
            snapshot
                .layers
                .iter_mut()
                .find(|record| record.handle == "10")
                .unwrap()
                .off = true;
        });
        assert!(validate(&delete_collateral).contains("delete delta"));
    }

    #[test]
    fn layer_record_xref_ownership_is_strictly_all_or_none() {
        let mut partial_non_xref = layer_record("2A", "LOCAL", false);
        partial_non_xref.xref_name = Some("AMBIENT".to_string());
        let mut errors = Vec::new();
        validate_layer_records(&[partial_non_xref], "snapshot", &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("XREF ownership fields are inconsistent")),
            "{errors:?}"
        );

        let mut partial_xref = layer_record("2B", "DEPENDENT", true);
        partial_xref.xref_path = None;
        let mut errors = Vec::new();
        validate_layer_records(&[partial_xref], "snapshot", &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("XREF ownership fields are inconsistent")),
            "{errors:?}"
        );
    }

    #[test]
    fn layer_record_handles_and_colors_use_the_product_value_domains() {
        for handle in ["", "0", "02A", "2a", "10000000000000000"] {
            let mut record = layer_record("2A", "TARGET", false);
            record.handle = handle.to_string();
            let mut errors = Vec::new();
            validate_layer_records(&[record], "snapshot", &mut errors);
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("canonical nonzero uppercase hexadecimal")),
                "{handle:?}: {errors:?}"
            );
        }

        for color_index in [0, 256] {
            let mut record = layer_record("2A", "TARGET", false);
            record.color_index = Some(color_index);
            let mut errors = Vec::new();
            validate_layer_records(&[record], "snapshot", &mut errors);
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("color_index must be null or from 1 to 255")),
                "{color_index}: {errors:?}"
            );
        }

        let mut record = layer_record("2A", "TARGET", false);
        record.material_handle = Some("0".to_string());
        let mut errors = Vec::new();
        validate_layer_records(&[record], "snapshot", &mut errors);
        assert!(
            errors.iter().any(|error| error.contains("material_handle")
                && error.contains("canonical nonzero uppercase hexadecimal")),
            "{errors:?}"
        );
    }

    #[test]
    fn layer_update_delta_requires_a_requested_semantic_change() {
        let before = layer_record("2A", "TARGET", false);
        let requested = LayerCertificationProperties {
            line_weight: Some(LayerCertificationLineWeight::ByLayer),
            ..LayerCertificationProperties::default()
        };
        assert!(
            !layer_update_delta_is_confined(&before, &before, &requested),
            "a requested value that was already present must not certify an update"
        );

        let mut after = before.clone();
        after.line_weight = CertificationObservedLayerLineWeight::ByBlock;
        assert!(layer_update_delta_is_confined(
            &before,
            &after,
            &LayerCertificationProperties {
                line_weight: Some(LayerCertificationLineWeight::ByBlock),
                ..LayerCertificationProperties::default()
            }
        ));
    }

    fn valid_xref_case_params(
        operation: XrefMutationOperation,
        drawing_path: &str,
    ) -> serde_json::Map<String, serde_json::Value> {
        let value = match operation {
            XrefMutationOperation::AttachXref => serde_json::json!({
                "drawing_path": drawing_path,
                "xref_path": "C:/cert/fixtures/source.dwg",
                "reference_type": "attachment"
            }),
            XrefMutationOperation::UpdateXref => serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "2A",
                "properties": {"xref_path": "refs/source.dwg"}
            }),
            XrefMutationOperation::DetachXref => serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "2A"
            }),
            XrefMutationOperation::InsertXrefInstance => serde_json::json!({
                "drawing_path": drawing_path,
                "attachment_handle": "2A"
            }),
            XrefMutationOperation::UpdateXrefInstance => serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "3B",
                "properties": {"visibility": "hidden"}
            }),
            XrefMutationOperation::DeleteXrefInstance => serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "3B"
            }),
            XrefMutationOperation::ReloadXref => serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "2A"
            }),
            XrefMutationOperation::UnloadXref => serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "2A"
            }),
            XrefMutationOperation::BindXref => serde_json::json!({
                "drawing_path": drawing_path,
                "handle": "2A",
                "symbol_strategy": "prefix",
                "dependency_strategy": "reject_nested"
            }),
        };
        serde_json::from_value(value).unwrap()
    }

    fn valid_xref_certification_manifest() -> XrefCertificationManifest {
        let registry = embedded_xref_artifacts().unwrap();
        let artifact_sha256 = xref_embedded_artifact_sha256();
        let mut release_cases = Vec::new();
        for row in &registry.capabilities().rows {
            for operation in &row.operations {
                let drawing_path = format!(
                    "C:/cert/fixtures/{}.{}",
                    row.row_id,
                    row.host_format.as_str()
                );
                release_cases.push(XrefCertificationCase {
                    case_id: format!("release-{}", operation.as_str().replace('_', "-")),
                    row_id: row.row_id.clone(),
                    scenario: XrefCertificationScenario::OperationSuccess,
                    operation: *operation,
                    drawing_path: drawing_path.clone(),
                    source_fixture_paths: vec!["source.dwg".to_string()],
                    params: valid_xref_case_params(*operation, &drawing_path),
                    expected_status: XrefCertificationExpectedStatus::Passed,
                    expected_error_code: None,
                    failpoint: None,
                });
            }
            let drawing_path = format!(
                "C:/cert/fixtures/{}.{}",
                row.row_id,
                row.host_format.as_str()
            );
            release_cases.push(XrefCertificationCase {
                case_id: "scenario-profile-isolation".to_string(),
                row_id: row.row_id.clone(),
                scenario: XrefCertificationScenario::ProfileIsolation,
                operation: XrefMutationOperation::UnloadXref,
                drawing_path: drawing_path.clone(),
                source_fixture_paths: vec!["source.dwg".to_string()],
                params: valid_xref_case_params(XrefMutationOperation::UnloadXref, &drawing_path),
                expected_status: XrefCertificationExpectedStatus::Passed,
                expected_error_code: None,
                failpoint: None,
            });
        }
        let row = &registry.capabilities().rows[0];
        let drawing_path = format!(
            "C:/cert/fixtures/{}.{}",
            row.row_id,
            row.host_format.as_str()
        );
        let mut push_scenario =
            |case_id: &str,
             scenario: XrefCertificationScenario,
             operation: XrefMutationOperation,
             params: serde_json::Map<String, serde_json::Value>,
             expected_status: XrefCertificationExpectedStatus,
             expected_error_code: Option<&str>| {
                release_cases.push(XrefCertificationCase {
                    case_id: case_id.to_string(),
                    row_id: row.row_id.clone(),
                    scenario,
                    operation,
                    drawing_path: drawing_path.clone(),
                    source_fixture_paths: vec!["source.dwg".to_string()],
                    params,
                    expected_status,
                    expected_error_code: expected_error_code.map(str::to_string),
                    failpoint: None,
                });
            };
        push_scenario(
            "scenario-clips",
            XrefCertificationScenario::Clips,
            XrefMutationOperation::UpdateXref,
            valid_xref_case_params(XrefMutationOperation::UpdateXref, &drawing_path),
            XrefCertificationExpectedStatus::Failed,
            Some("unsupported_xref_clip_data"),
        );
        push_scenario(
            "scenario-locked-resources",
            XrefCertificationScenario::LockedResources,
            XrefMutationOperation::UpdateXrefInstance,
            valid_xref_case_params(XrefMutationOperation::UpdateXrefInstance, &drawing_path),
            XrefCertificationExpectedStatus::Failed,
            Some("xref_instance_locked"),
        );
        let mut matching_guard =
            valid_xref_case_params(XrefMutationOperation::UnloadXref, &drawing_path);
        matching_guard.insert("expected_handle".to_string(), serde_json::json!("2A"));
        push_scenario(
            "scenario-guards-match",
            XrefCertificationScenario::Guards,
            XrefMutationOperation::UnloadXref,
            matching_guard,
            XrefCertificationExpectedStatus::Passed,
            None,
        );
        let mut mismatching_guard =
            valid_xref_case_params(XrefMutationOperation::UnloadXref, &drawing_path);
        mismatching_guard.insert("expected_handle".to_string(), serde_json::json!("2B"));
        push_scenario(
            "scenario-guards-mismatch",
            XrefCertificationScenario::Guards,
            XrefMutationOperation::UnloadXref,
            mismatching_guard,
            XrefCertificationExpectedStatus::Failed,
            Some("expected_handle_mismatch"),
        );
        push_scenario(
            "scenario-source-race",
            XrefCertificationScenario::SourceRace,
            XrefMutationOperation::ReloadXref,
            valid_xref_case_params(XrefMutationOperation::ReloadXref, &drawing_path),
            XrefCertificationExpectedStatus::Failed,
            Some("xref_source_changed"),
        );
        push_scenario(
            "scenario-host-race",
            XrefCertificationScenario::HostRace,
            XrefMutationOperation::UpdateXref,
            valid_xref_case_params(XrefMutationOperation::UpdateXref, &drawing_path),
            XrefCertificationExpectedStatus::Failed,
            Some("concurrent_drawing_modification"),
        );
        for (symbol, dependency) in [
            ("merge", "bind_nested"),
            ("merge", "reject_nested"),
            ("prefix", "bind_nested"),
            ("prefix", "reject_nested"),
        ] {
            let mut params = valid_xref_case_params(XrefMutationOperation::BindXref, &drawing_path);
            params.insert("symbol_strategy".to_string(), serde_json::json!(symbol));
            params.insert(
                "dependency_strategy".to_string(),
                serde_json::json!(dependency),
            );
            push_scenario(
                &format!("scenario-bind-{symbol}-{}", dependency.replace('_', "-")),
                XrefCertificationScenario::BindStrategies,
                XrefMutationOperation::BindXref,
                params,
                XrefCertificationExpectedStatus::Passed,
                None,
            );
        }
        release_cases.sort_by(|left, right| {
            (&left.row_id, &left.case_id).cmp(&(&right.row_id, &right.case_id))
        });

        let mut instrumented_cases: Vec<_> = XREF_MANDATORY_CERTIFICATION_FAILPOINTS
            .into_iter()
            .enumerate()
            .map(|(index, failpoint)| XrefCertificationCase {
                case_id: format!(
                    "transaction-{index:02}-{}",
                    failpoint.as_str().replace('_', "-")
                ),
                row_id: row.row_id.clone(),
                scenario: XrefCertificationScenario::TransactionFailpoint,
                operation: XrefMutationOperation::UpdateXref,
                drawing_path: "C:/cert/fixtures/transaction-host.dwg".to_string(),
                source_fixture_paths: vec!["source.dwg".to_string()],
                params: serde_json::from_value(serde_json::json!({
                    "drawing_path": "C:/cert/fixtures/transaction-host.dwg",
                    "handle": "2A",
                    "properties": {"xref_path": "refs/source.dwg"}
                }))
                .unwrap(),
                expected_status: XrefCertificationExpectedStatus::Failed,
                expected_error_code: Some(failpoint.expected_error_code().to_string()),
                failpoint: Some(failpoint),
            })
            .collect();
        instrumented_cases.sort_by(|left, right| {
            (&left.row_id, &left.case_id).cmp(&(&right.row_id, &right.case_id))
        });

        XrefCertificationManifest {
            schema_version: XREF_CERTIFICATION_SCHEMA_VERSION,
            release_id: "xref-certification-v4".to_string(),
            activation_target: embedded_certification_activation_target(
                "autocad-2026-r25-1-en-us-preview-v1",
            )
            .unwrap(),
            fixture_root: "C:/cert/fixtures".to_string(),
            certified_arg_path: "C:/cert/autocad-mcp.arg".to_string(),
            certified_arg_sha256:
                "89bc4284f84d1ee9c75ef3ce8a39933d1f86e919b3092ba59ce734b2f3216fc6".to_string(),
            certified_arg_policy_id: "autocad-mcp-preview-autocad-2026-en-us-v1".to_string(),
            certified_arg_policy_sha256:
                "40b3ae0defffde4b96c5affc185775e5393478e9e6f23c1768e8cb0dae915617".to_string(),
            release_binary_path: "C:/cert/autocad-mcp.exe".to_string(),
            release_binary_sha256: "c".repeat(64),
            instrumented_binary_path: "C:/cert/autocad-mcp-instrumented.exe".to_string(),
            instrumented_binary_sha256: "d".repeat(64),
            accoreconsole_path: "C:/Program Files/Autodesk/AutoCAD 2026/accoreconsole.exe"
                .to_string(),
            accoreconsole_sha256: "f".repeat(64),
            autocad_product: CERTIFIED_AUTOCAD_PRODUCT.to_string(),
            autocad_version: "2026".to_string(),
            matrix_sha256: artifact_sha256.mutation_capabilities.clone(),
            profile_sha256: artifact_sha256.profile_sha256(),
            release_cases,
            instrumented_cases,
        }
    }

    fn valid_xref_build_identity(
        manifest: &XrefCertificationManifest,
        failpoints: bool,
    ) -> XrefCertificationBuildIdentity {
        XrefCertificationBuildIdentity {
            source_commit: "a".repeat(40),
            source_tree_sha256: "b".repeat(64),
            cargo_lock_sha256: "b".repeat(64),
            certified_arg_sha256: manifest.certified_arg_sha256.clone(),
            certified_arg_policy_id: manifest.certified_arg_policy_id.clone(),
            certified_arg_policy_sha256: manifest.certified_arg_policy_sha256.clone(),
            compiler: "rustc 1.96.0 (stable)".to_string(),
            target: "x86_64-pc-windows-msvc".to_string(),
            profile: "release".to_string(),
            optimization: "3".to_string(),
            build_id: if failpoints { "d" } else { "c" }.repeat(64),
            shared_operation_source_sha256: "e".repeat(64),
            certification_failpoints_enabled: failpoints,
        }
    }

    fn valid_xref_attestation(
        manifest: &XrefCertificationManifest,
    ) -> XrefCertificationAttestation {
        XrefCertificationAttestation {
            schema_version: XREF_CERTIFICATION_SCHEMA_VERSION,
            release_id: manifest.release_id.clone(),
            activation_target: manifest.activation_target.clone(),
            manifest_sha256: xref_certification_manifest_sha256(manifest),
            release_binary_sha256: manifest.release_binary_sha256.clone(),
            instrumented_binary_sha256: manifest.instrumented_binary_sha256.clone(),
            certified_arg_sha256: manifest.certified_arg_sha256.clone(),
            certified_arg_policy_id: manifest.certified_arg_policy_id.clone(),
            certified_arg_policy_sha256: manifest.certified_arg_policy_sha256.clone(),
            artifact_sha256: xref_embedded_artifact_sha256(),
            release_build_identity: valid_xref_build_identity(manifest, false),
            instrumented_build_identity: valid_xref_build_identity(manifest, true),
            shared_operation_source_sha256: "e".repeat(64),
        }
    }

    fn valid_xref_evidence(
        manifest: &XrefCertificationManifest,
        attestation: &XrefCertificationAttestation,
        evidence_class: XrefCertificationEvidenceClass,
    ) -> XrefCertificationEvidence {
        let registry = embedded_xref_artifacts().unwrap();
        let (cases, binary_path, binary_sha256, build_identity) = match evidence_class {
            XrefCertificationEvidenceClass::ReleaseConformance => (
                manifest.release_cases.as_slice(),
                manifest.release_binary_path.clone(),
                attestation.release_binary_sha256.clone(),
                attestation.release_build_identity.clone(),
            ),
            XrefCertificationEvidenceClass::InstrumentedTransaction => (
                manifest.instrumented_cases.as_slice(),
                manifest.instrumented_binary_path.clone(),
                attestation.instrumented_binary_sha256.clone(),
                attestation.instrumented_build_identity.clone(),
            ),
        };
        let case_results = cases
            .iter()
            .map(|case| {
                let row = registry
                    .capabilities()
                    .rows
                    .iter()
                    .find(|row| row.row_id == case.row_id)
                    .unwrap();
                let before = "1".repeat(64);
                let after = if case
                    .failpoint
                    .map(XrefCertificationFailpoint::may_cross_replacement)
                    .unwrap_or(case.expected_status == XrefCertificationExpectedStatus::Passed)
                {
                    "2".repeat(64)
                } else {
                    before.clone()
                };
                let observed_artifact =
                    "C:/Temp/autocad-mcp-xref-case/xref-isolated-profile.arg".to_string();
                let transaction_activity =
                    case.expected_status == XrefCertificationExpectedStatus::Passed;
                XrefCertificationCaseResult {
                    case_id: case.case_id.clone(),
                    row_id: case.row_id.clone(),
                    operation: case.operation,
                    status: XrefCertificationResultStatus::Passed,
                    error_code: case.expected_error_code.clone(),
                    input_format: XrefCertificationFormatFacts::from_capability(row),
                    output_format: XrefCertificationFormatFacts::from_capability(row),
                    original_digest_before: before,
                    original_digest_after: after,
                    artifact_cleanup: XrefArtifactCleanupEvidence {
                        inventory_roots: vec!["C:/Temp".to_string()],
                        observation_polls: 2,
                        attempted: transaction_activity
                            .then(|| observed_artifact.clone())
                            .into_iter()
                            .collect(),
                        removed: transaction_activity
                            .then_some(observed_artifact)
                            .into_iter()
                            .collect(),
                        remaining: Vec::new(),
                        process_ids_before: Vec::new(),
                        process_ids_observed: transaction_activity
                            .then_some(42)
                            .into_iter()
                            .collect(),
                        process_ids_remaining: Vec::new(),
                        engine_stop_error: None,
                    },
                    profile_isolation: passing_profile_isolation(
                        &expected_xref_profile_isolation(case, evidence_class).unwrap(),
                    ),
                }
            })
            .collect();
        XrefCertificationEvidence {
            schema_version: XREF_CERTIFICATION_SCHEMA_VERSION,
            evidence_class,
            release_id: manifest.release_id.clone(),
            activation_target: manifest.activation_target.clone(),
            status: XrefCertificationResultStatus::Passed,
            manifest_sha256: xref_certification_manifest_sha256(manifest),
            binary_sha256: binary_sha256.clone(),
            binary_path: binary_path.clone(),
            binary_canonical_path: binary_path,
            binary_sha256_before: binary_sha256.clone(),
            binary_sha256_after: binary_sha256,
            certified_arg_path: manifest.certified_arg_path.clone(),
            certified_arg_canonical_path: manifest.certified_arg_path.clone(),
            certified_arg_sha256_before: manifest.certified_arg_sha256.clone(),
            certified_arg_sha256_after: manifest.certified_arg_sha256.clone(),
            binary_reported_certified_arg_sha256: manifest.certified_arg_sha256.clone(),
            certified_arg_policy_id: manifest.certified_arg_policy_id.clone(),
            certified_arg_policy_sha256: manifest.certified_arg_policy_sha256.clone(),
            artifact_sha256: xref_embedded_artifact_sha256(),
            build_identity,
            accoreconsole_path: manifest.accoreconsole_path.clone(),
            accoreconsole_canonical_path: manifest.accoreconsole_path.clone(),
            accoreconsole_sha256_before: manifest.accoreconsole_sha256.clone(),
            accoreconsole_sha256_after: manifest.accoreconsole_sha256.clone(),
            observed_autocad_product: manifest.autocad_product.clone(),
            observed_autocad_version: manifest.autocad_version.clone(),
            profile_references: xref_certification_profile_references(registry),
            case_results,
            case_failures: Vec::new(),
        }
    }

    #[test]
    fn xref_certification_closed_v4_types_reject_unknown_and_missing_fields() {
        let manifest = valid_xref_certification_manifest();
        let mut root = serde_json::to_value(&manifest).unwrap();
        root["unexpected"] = serde_json::json!(true);
        let error = XrefCertificationManifest::from_json(&root.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `unexpected`"), "{error}");

        let mut nested = serde_json::to_value(&manifest).unwrap();
        nested["release_cases"][0]["unexpected"] = serde_json::json!(true);
        let error = XrefCertificationManifest::from_json(&nested.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `unexpected`"), "{error}");

        let mut missing_activation_target = serde_json::to_value(&manifest).unwrap();
        missing_activation_target
            .as_object_mut()
            .unwrap()
            .remove("activation_target");
        let error = XrefCertificationManifest::from_json(&missing_activation_target.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("missing field `activation_target`"),
            "{error}"
        );

        let mut missing_nullable = serde_json::to_value(&manifest).unwrap();
        missing_nullable["release_cases"][0]
            .as_object_mut()
            .unwrap()
            .remove("failpoint");
        let error = XrefCertificationManifest::from_json(&missing_nullable.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing field `failpoint`"), "{error}");

        let mut missing_engine = serde_json::to_value(&manifest).unwrap();
        missing_engine
            .as_object_mut()
            .unwrap()
            .remove("accoreconsole_path");
        let error = XrefCertificationManifest::from_json(&missing_engine.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("missing field `accoreconsole_path`"),
            "{error}"
        );

        let mut missing_binary_digest = serde_json::to_value(&manifest).unwrap();
        missing_binary_digest
            .as_object_mut()
            .unwrap()
            .remove("release_binary_sha256");
        let error = XrefCertificationManifest::from_json(&missing_binary_digest.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("missing field `release_binary_sha256`"),
            "{error}"
        );

        let mut missing_arg_policy = serde_json::to_value(&manifest).unwrap();
        missing_arg_policy
            .as_object_mut()
            .unwrap()
            .remove("certified_arg_policy_sha256");
        let error = XrefCertificationManifest::from_json(&missing_arg_policy.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("missing field `certified_arg_policy_sha256`"),
            "{error}"
        );

        let manifest_schema =
            serde_json::to_value(schemars::schema_for!(XrefCertificationManifest)).unwrap();
        assert_schema_objects_are_closed_except(&manifest_schema, &["params"]);

        for schema in [
            serde_json::to_value(schemars::schema_for!(XrefCertificationEvidence)).unwrap(),
            serde_json::to_value(schemars::schema_for!(XrefCertificationAttestation)).unwrap(),
        ] {
            assert_schema_objects_are_closed(&schema);
        }

        let attestation = valid_xref_attestation(&manifest);
        let mut evidence = serde_json::to_value(valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::ReleaseConformance,
        ))
        .unwrap();
        evidence["case_results"][0]["unexpected"] = serde_json::json!(true);
        let error = XrefCertificationEvidence::from_json(&evidence.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `unexpected`"), "{error}");

        let mut missing_profile_field = serde_json::to_value(valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::ReleaseConformance,
        ))
        .unwrap();
        missing_profile_field["case_results"][0]["profile_isolation"][0]
            .as_object_mut()
            .unwrap()
            .remove("expectation");
        let error = XrefCertificationEvidence::from_json(&missing_profile_field.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing field `expectation`"), "{error}");

        let mut missing_engine_observation = serde_json::to_value(valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::ReleaseConformance,
        ))
        .unwrap();
        missing_engine_observation
            .as_object_mut()
            .unwrap()
            .remove("accoreconsole_sha256_after");
        let error = XrefCertificationEvidence::from_json(&missing_engine_observation.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("missing field `accoreconsole_sha256_after`"),
            "{error}"
        );

        let mut missing_binary_observation = serde_json::to_value(valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::ReleaseConformance,
        ))
        .unwrap();
        missing_binary_observation
            .as_object_mut()
            .unwrap()
            .remove("binary_sha256_after");
        let error = XrefCertificationEvidence::from_json(&missing_binary_observation.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("missing field `binary_sha256_after`"),
            "{error}"
        );

        let mut missing_arg_observation = serde_json::to_value(valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::ReleaseConformance,
        ))
        .unwrap();
        missing_arg_observation
            .as_object_mut()
            .unwrap()
            .remove("certified_arg_sha256_after");
        let error = XrefCertificationEvidence::from_json(&missing_arg_observation.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("missing field `certified_arg_sha256_after`"),
            "{error}"
        );

        let mut attestation_json = serde_json::to_value(attestation).unwrap();
        attestation_json["release_build_identity"]["unexpected"] = serde_json::json!(true);
        let error = XrefCertificationAttestation::from_json(&attestation_json.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `unexpected`"), "{error}");

        let attestation = valid_xref_attestation(&manifest);
        let mut missing_policy = serde_json::to_value(attestation).unwrap();
        missing_policy
            .as_object_mut()
            .unwrap()
            .remove("certified_arg_policy_id");
        let error = XrefCertificationAttestation::from_json(&missing_policy.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("missing field `certified_arg_policy_id`"),
            "{error}"
        );
    }

    #[test]
    fn xref_certification_manifest_accepts_exact_rows_profiles_and_coverage() {
        let manifest = valid_xref_certification_manifest();
        validate_xref_certification_manifest(&manifest).unwrap();
        assert_eq!(manifest.release_cases.len(), 30);
        assert_eq!(manifest.instrumented_cases.len(), 14);
    }

    #[test]
    fn xref_certification_manifest_rejects_order_duplicates_and_missing_coverage() {
        let mut unsorted = valid_xref_certification_manifest();
        unsorted.release_cases.swap(0, 1);
        let error = validate_xref_certification_manifest(&unsorted)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must be sorted and unique"), "{error}");

        let mut duplicate = valid_xref_certification_manifest();
        duplicate
            .release_cases
            .insert(1, duplicate.release_cases[0].clone());
        let error = validate_xref_certification_manifest(&duplicate)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must be sorted and unique"), "{error}");

        let mut missing_operation = valid_xref_certification_manifest();
        missing_operation.release_cases.remove(0);
        let error = validate_xref_certification_manifest(&missing_operation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("exactly its nine operations"), "{error}");

        let mut failure_only_operation = valid_xref_certification_manifest();
        failure_only_operation.release_cases[0].expected_status =
            XrefCertificationExpectedStatus::Failed;
        failure_only_operation.release_cases[0].expected_error_code =
            Some("unsupported_xref_data".to_string());
        let error = validate_xref_certification_manifest(&failure_only_operation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("successful release cases")
                && error.contains("exactly its nine operations"),
            "{error}"
        );

        let mut missing_failpoint = valid_xref_certification_manifest();
        missing_failpoint.instrumented_cases.remove(0);
        let error = validate_xref_certification_manifest(&missing_failpoint)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("every mandatory transaction failpoint"),
            "{error}"
        );
    }

    #[test]
    fn xref_certification_manifest_rejects_stale_digests_and_bad_case_modes() {
        let mut v3 = valid_xref_certification_manifest();
        v3.schema_version = 3;
        let error = validate_xref_certification_manifest(&v3)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("schema_version 3 is unsupported; expected 4"),
            "{error}"
        );

        let mut stale = valid_xref_certification_manifest();
        stale.matrix_sha256 = "0".repeat(64);
        let error = validate_xref_certification_manifest(&stale)
            .unwrap_err()
            .to_string();
        assert!(error.contains("exact embedded bytes"), "{error}");

        let mut release_failpoint = valid_xref_certification_manifest();
        release_failpoint.release_cases[0].failpoint = Some(XrefCertificationFailpoint::BeforeSave);
        let error = validate_xref_certification_manifest(&release_failpoint)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("release case requires failpoint=null"),
            "{error}"
        );

        let mut wrong_error = valid_xref_certification_manifest();
        wrong_error.instrumented_cases[0].expected_error_code = Some("write_failed".to_string());
        let error = validate_xref_certification_manifest(&wrong_error)
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires expected_error_code"), "{error}");

        let mut invalid_update = valid_xref_certification_manifest();
        let update = invalid_update
            .release_cases
            .iter_mut()
            .find(|case| case.operation == XrefMutationOperation::UpdateXref)
            .unwrap();
        update.params.insert(
            "properties".to_string(),
            serde_json::json!({"saved_path": "refs/site.dwg"}),
        );
        let error = validate_xref_certification_manifest(&invalid_update)
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid executable params"), "{error}");
    }

    #[test]
    fn xref_certification_manifest_requires_exact_autocad_engine_identity() {
        let mut wrong_path = valid_xref_certification_manifest();
        wrong_path.accoreconsole_path =
            "C:/Program Files/Autodesk/AutoCAD 2025/accoreconsole.exe".to_string();
        let error = validate_xref_certification_manifest(&wrong_path)
            .unwrap_err()
            .to_string();
        assert!(error.contains("under an AutoCAD-labelled path"), "{error}");

        let mut malformed_digest = valid_xref_certification_manifest();
        malformed_digest.accoreconsole_sha256 = "F".repeat(64);
        let error = validate_xref_certification_manifest(&malformed_digest)
            .unwrap_err()
            .to_string();
        assert!(error.contains("64-character lowercase SHA-256"), "{error}");

        let mut wrong_product = valid_xref_certification_manifest();
        wrong_product.autocad_product = "autocad-lt".to_string();
        let error = validate_xref_certification_manifest(&wrong_product)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("product/version does not match activation target")
                && !error.contains("capability row"),
            "{error}"
        );
    }

    #[test]
    fn xref_certification_manifest_requires_exact_arg_policy_identity() {
        let mut wrong_path = valid_xref_certification_manifest();
        wrong_path.certified_arg_path = "relative/autocad-mcp.arg".to_string();
        let error = validate_xref_certification_manifest(&wrong_path)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("certified_arg_path") && error.contains("absolute"),
            "{error}"
        );

        let mut malformed_arg_digest = valid_xref_certification_manifest();
        malformed_arg_digest.certified_arg_sha256 = "A".repeat(64);
        let error = validate_xref_certification_manifest(&malformed_arg_digest)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("certified_arg_sha256")
                && error.contains("64-character lowercase SHA-256"),
            "{error}"
        );

        let mut malformed_policy_id = valid_xref_certification_manifest();
        malformed_policy_id.certified_arg_policy_id = "Personal Policy".to_string();
        let error = validate_xref_certification_manifest(&malformed_policy_id)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("certified_arg_policy_id")
                && error.contains("canonical lowercase ASCII"),
            "{error}"
        );

        let mut malformed_policy_digest = valid_xref_certification_manifest();
        malformed_policy_digest.certified_arg_policy_sha256 = "short".to_string();
        let error = validate_xref_certification_manifest(&malformed_policy_digest)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("certified_arg_policy_sha256")
                && error.contains("64-character lowercase SHA-256"),
            "{error}"
        );
    }

    #[test]
    fn xref_certification_manifest_requires_distinct_exact_binaries() {
        let mut malformed = valid_xref_certification_manifest();
        malformed.release_binary_sha256 = "C".repeat(64);
        let error = validate_xref_certification_manifest(&malformed)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("release_binary_sha256")
                && error.contains("64-character lowercase SHA-256"),
            "{error}"
        );

        let mut identical = valid_xref_certification_manifest();
        identical.instrumented_binary_sha256 = identical.release_binary_sha256.clone();
        let error = validate_xref_certification_manifest(&identical)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("release and instrumented binary SHA-256 values must differ"),
            "{error}"
        );
    }

    #[test]
    fn xref_certification_attestation_requires_identical_build_provenance() {
        let manifest = valid_xref_certification_manifest();
        let attestation = valid_xref_attestation(&manifest);
        validate_xref_certification_attestation(&manifest, &attestation).unwrap();

        let mut v3 = attestation.clone();
        v3.schema_version = 3;
        let error = validate_xref_certification_attestation(&manifest, &v3)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("attestation schema_version 3 is unsupported; expected 4"),
            "{error}"
        );

        let mut mismatch = attestation.clone();
        mismatch.instrumented_build_identity.compiler = "different-rustc".to_string();
        let error = validate_xref_certification_attestation(&manifest, &mismatch)
            .unwrap_err()
            .to_string();
        assert!(error.contains("compiler values differ"), "{error}");

        let mut stale = attestation.clone();
        stale.manifest_sha256 = "0".repeat(64);
        let error = validate_xref_certification_attestation(&manifest, &stale)
            .unwrap_err()
            .to_string();
        assert!(error.contains("manifest_sha256 is stale"), "{error}");

        let mut wrong_activation_target = attestation.clone();
        wrong_activation_target.activation_target.registry_family = "R25.0".to_string();
        let error = validate_xref_certification_attestation(&manifest, &wrong_activation_target)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("attestation activation_target does not match manifest"),
            "{error}"
        );

        let mut wrong_binary = attestation.clone();
        wrong_binary.release_binary_sha256 = "9".repeat(64);
        let error = validate_xref_certification_attestation(&manifest, &wrong_binary)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("release_binary_sha256 does not match the manifest"),
            "{error}"
        );

        let mut wrong_policy = attestation.clone();
        wrong_policy.certified_arg_policy_sha256 = "8".repeat(64);
        let error = validate_xref_certification_attestation(&manifest, &wrong_policy)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("certified ARG/policy identity does not match the manifest"),
            "{error}"
        );

        let mut wrong_build_policy = attestation.clone();
        wrong_build_policy
            .instrumented_build_identity
            .certified_arg_policy_id = "different-policy".to_string();
        let error = validate_xref_certification_attestation(&manifest, &wrong_build_policy)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("build identity certified ARG/policy values")
                && error.contains("certified_arg_policy_id values differ"),
            "{error}"
        );

        let mut wrong_target = attestation.clone();
        wrong_target.release_build_identity.target = "aarch64-apple-darwin".to_string();
        wrong_target.instrumented_build_identity.target = "aarch64-apple-darwin".to_string();
        let error = validate_xref_certification_attestation(&manifest, &wrong_target)
            .unwrap_err()
            .to_string();
        assert!(error.contains("target must be Windows"), "{error}");

        let mut feature = attestation;
        feature
            .release_build_identity
            .certification_failpoints_enabled = true;
        let error = validate_xref_certification_attestation(&manifest, &feature)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("certification_failpoints_enabled must be false"),
            "{error}"
        );
    }

    #[test]
    fn xref_certification_bundle_rejects_skipped_failed_stale_and_missing_evidence() {
        let manifest = valid_xref_certification_manifest();
        let attestation = valid_xref_attestation(&manifest);
        let release = valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::ReleaseConformance,
        );
        let instrumented = valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::InstrumentedTransaction,
        );
        validate_xref_certification_bundle(&manifest, &release, &instrumented, &attestation)
            .unwrap();

        let mut v3 = release.clone();
        v3.schema_version = 3;
        let error = validate_xref_certification_evidence(&manifest, &v3, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("evidence schema_version 3 is unsupported; expected 4"),
            "{error}"
        );

        let mut skipped = release.clone();
        skipped.case_results[0].status = XrefCertificationResultStatus::Skipped;
        let error = validate_xref_certification_evidence(&manifest, &skipped, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("skipped or failed evidence is forbidden"),
            "{error}"
        );

        let mut failed = release.clone();
        failed.status = XrefCertificationResultStatus::Failed;
        let error = validate_xref_certification_evidence(&manifest, &failed, &attestation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("evidence status must be passed"), "{error}");

        let mut stale = release.clone();
        stale.binary_sha256 = "0".repeat(64);
        let error = validate_xref_certification_evidence(&manifest, &stale, &attestation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("binary_sha256 does not match"), "{error}");

        let mut missing = release;
        missing.case_results.remove(0);
        let error = validate_xref_certification_evidence(&manifest, &missing, &attestation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("case count does not match"), "{error}");
        assert!(error.contains("missing evidence result"), "{error}");
    }

    #[test]
    fn xref_certification_evidence_binds_exact_engine_before_and_after_each_lane() {
        let manifest = valid_xref_certification_manifest();
        let attestation = valid_xref_attestation(&manifest);
        let release = valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::ReleaseConformance,
        );
        let instrumented = valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::InstrumentedTransaction,
        );

        let mut substituted = release.clone();
        substituted.accoreconsole_canonical_path =
            "C:/Program Files/Autodesk/AutoCAD 2026/alternate/accoreconsole.exe".to_string();
        let error = validate_xref_certification_evidence(&manifest, &substituted, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("configured and canonical accoreconsole paths"),
            "{error}"
        );

        let mut stale_before = release.clone();
        stale_before.accoreconsole_sha256_before = "0".repeat(64);
        let error = validate_xref_certification_evidence(&manifest, &stale_before, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("accoreconsole SHA-256 before does not match"),
            "{error}"
        );

        let mut changed_after = release.clone();
        changed_after.accoreconsole_sha256_after = "0".repeat(64);
        let error = validate_xref_certification_evidence(&manifest, &changed_after, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("accoreconsole SHA-256 after does not match"),
            "{error}"
        );

        let mut wrong_identity = release.clone();
        wrong_identity.observed_autocad_version = "2025".to_string();
        let error = validate_xref_certification_evidence(&manifest, &wrong_identity, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("observed AutoCAD product/version"),
            "{error}"
        );

        let mut wrong_activation_target = release.clone();
        wrong_activation_target.activation_target.registry_family = "R25.0".to_string();
        let error =
            validate_xref_certification_evidence(&manifest, &wrong_activation_target, &attestation)
                .unwrap_err()
                .to_string();
        assert!(
            error.contains("evidence activation_target does not match manifest"),
            "{error}"
        );

        let mut disagreeing_instrumented = instrumented;
        disagreeing_instrumented.accoreconsole_canonical_path =
            "c:/program files/autodesk/autocad 2026/ACCORECONSOLE.EXE".to_string();
        validate_xref_certification_evidence(&manifest, &disagreeing_instrumented, &attestation)
            .unwrap();
        let error = validate_xref_certification_bundle(
            &manifest,
            &release,
            &disagreeing_instrumented,
            &attestation,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("same strict XREF engine observation"),
            "{error}"
        );
    }

    #[test]
    fn xref_certification_evidence_binds_exact_arg_policy_before_and_after_each_lane() {
        let manifest = valid_xref_certification_manifest();
        let attestation = valid_xref_attestation(&manifest);
        let release = valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::ReleaseConformance,
        );
        let instrumented = valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::InstrumentedTransaction,
        );

        let mut wrong_path = release.clone();
        wrong_path.certified_arg_path = "C:/cert/substitute.arg".to_string();
        let error = validate_xref_certification_evidence(&manifest, &wrong_path, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("configured certified ARG path does not match manifest"),
            "{error}"
        );

        let mut changed_after = release.clone();
        changed_after.certified_arg_sha256_after = "0".repeat(64);
        let error = validate_xref_certification_evidence(&manifest, &changed_after, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("certified ARG SHA-256 after does not match"),
            "{error}"
        );

        let mut wrong_policy = release.clone();
        wrong_policy.certified_arg_policy_id = "different-policy".to_string();
        let error = validate_xref_certification_evidence(&manifest, &wrong_policy, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("certified ARG policy identity does not match manifest"),
            "{error}"
        );

        let mut wrong_binary_report = release.clone();
        wrong_binary_report.binary_reported_certified_arg_sha256 = "0".repeat(64);
        let error =
            validate_xref_certification_evidence(&manifest, &wrong_binary_report, &attestation)
                .unwrap_err()
                .to_string();
        assert!(
            error.contains("binary-reported certified ARG SHA-256 does not match"),
            "{error}"
        );

        let mut disagreeing_instrumented = instrumented;
        disagreeing_instrumented.certified_arg_canonical_path =
            "c:/CERT/autocad-mcp.arg".to_string();
        validate_xref_certification_evidence(&manifest, &disagreeing_instrumented, &attestation)
            .unwrap();
        let error = validate_xref_certification_bundle(
            &manifest,
            &release,
            &disagreeing_instrumented,
            &attestation,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("same certified ARG/policy observation"),
            "{error}"
        );
    }

    #[test]
    fn xref_certification_evidence_binds_exact_binary_before_and_after_each_lane() {
        let manifest = valid_xref_certification_manifest();
        let attestation = valid_xref_attestation(&manifest);
        let release = valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::ReleaseConformance,
        );

        let mut wrong_path = release.clone();
        wrong_path.binary_path = "C:/cert/substitute.exe".to_string();
        let error = validate_xref_certification_evidence(&manifest, &wrong_path, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("configured binary path does not match manifest"),
            "{error}"
        );

        let mut wrong_canonical = release.clone();
        wrong_canonical.binary_canonical_path = "C:/cert/substitute.exe".to_string();
        let error = validate_xref_certification_evidence(&manifest, &wrong_canonical, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("configured and canonical binary paths"),
            "{error}"
        );

        let mut stale_before = release.clone();
        stale_before.binary_sha256_before = "0".repeat(64);
        let error = validate_xref_certification_evidence(&manifest, &stale_before, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("binary SHA-256 before does not match"),
            "{error}"
        );

        let mut changed_after = release;
        changed_after.binary_sha256_after = "0".repeat(64);
        let error = validate_xref_certification_evidence(&manifest, &changed_after, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("binary SHA-256 after does not match"),
            "{error}"
        );
    }

    #[test]
    fn xref_certification_evidence_enforces_profiles_formats_digests_and_cleanup() {
        let manifest = valid_xref_certification_manifest();
        let attestation = valid_xref_attestation(&manifest);
        let release = valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::ReleaseConformance,
        );

        let mut profiles = release.clone();
        profiles.profile_references[0].preservation_verifier_profile_id = "stale".to_string();
        let error = validate_xref_certification_evidence(&manifest, &profiles, &attestation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("row/profile references"), "{error}");

        let mut format = release.clone();
        format.case_results[0].output_format.drawing_version = "AC1027".to_string();
        let error = validate_xref_certification_evidence(&manifest, &format, &attestation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("input/output format facts"), "{error}");

        let mut cleanup = release;
        cleanup.case_results[0].artifact_cleanup.remaining = vec!["C:/stale.tmp".to_string()];
        let error = validate_xref_certification_evidence(&manifest, &cleanup, &attestation)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("complete artifact/process cleanup"),
            "{error}"
        );

        let mut precommit = valid_xref_evidence(
            &manifest,
            &attestation,
            XrefCertificationEvidenceClass::InstrumentedTransaction,
        );
        let index = manifest
            .instrumented_cases
            .iter()
            .position(|case| case.failpoint == Some(XrefCertificationFailpoint::BeforeReplace))
            .unwrap();
        precommit.case_results[index].original_digest_after = "9".repeat(64);
        let error = validate_xref_certification_evidence(&manifest, &precommit, &attestation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("proven pre-replacement failure"), "{error}");
    }

    #[test]
    fn xref_certification_format_inspection_reads_exact_ascii_dxf_tuple() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .join("tests/fixtures/xrefs/portable-evidence-ascii.dxf");
        let facts = inspect_xref_certification_format(&fixture).unwrap();
        assert_eq!(facts.host_format, XrefHostFormat::Dxf);
        assert_eq!(facts.drawing_version, "AC1027");
        assert_eq!(facts.dxf_form, XrefDxfForm::Ascii);
        assert_eq!(facts.code_page.as_deref(), Some("ANSI_1252"));
    }

    #[test]
    fn xref_certification_format_inspection_preserves_binary_dxf_code_page_policy() {
        let fixture = tempfile::Builder::new().suffix(".dxf").tempfile().unwrap();
        let mut document = acadrust::CadDocument::with_version(acadrust::types::DxfVersion::AC1027);
        document.header.code_page = "ANSI_1252".to_string();
        acadrust::DxfWriter::new_binary(&document)
            .write_to_file(fixture.path())
            .unwrap();

        let facts = inspect_xref_certification_format(fixture.path()).unwrap();

        assert_eq!(facts.host_format, XrefHostFormat::Dxf);
        assert_eq!(facts.drawing_version, "AC1027");
        assert_eq!(facts.dxf_form, XrefDxfForm::Binary);
        assert_eq!(facts.code_page, None);
    }

    #[test]
    fn xref_certification_format_inspection_hides_backend_parse_details() {
        let fixture = tempfile::Builder::new().suffix(".dxf").tempfile().unwrap();
        std::fs::write(fixture.path(), b"backend-specific detail").unwrap();

        let error = inspect_xref_certification_format(fixture.path())
            .unwrap_err()
            .to_string();

        assert_eq!(
            error,
            format!(
                "failed to parse DXF format facts from {}: code=invalid_drawing reader could not decode the captured drawing snapshot",
                fixture.path().display()
            )
        );
        assert!(!error.contains("backend-specific detail"));
        assert!(!error.contains("acadrust"));
    }

    #[test]
    fn committed_certification_manifest_examples_are_complete_inputs_not_evidence() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap();
        let xref_json = std::fs::read_to_string(
            workspace.join("tests/fixtures/windows_certification/xref-manifest.example.json"),
        )
        .unwrap();
        let xref = XrefCertificationManifest::from_json(&xref_json).unwrap();
        validate_xref_certification_manifest(&xref).unwrap();
        assert_eq!(xref.release_cases.len(), 30);
        assert_eq!(xref.instrumented_cases.len(), 14);
        assert!(!xref_json.contains("case_results"));
        assert!(!xref_json.contains("evidence_class"));

        let legacy_json = std::fs::read_to_string(
            workspace.join("tests/fixtures/windows_certification/manifest.example.json"),
        )
        .unwrap();
        let legacy = CertificationManifest::from_json(&legacy_json).unwrap();
        validate_release_manifest(&legacy, &[certification_profile_definition()], true).unwrap();
        validate_layer_mutation_manifest(&legacy).unwrap();
    }

    #[test]
    fn windows_certification_manifest_preflight_accepts_joined_public_examples() {
        let schema_v4 = committed_xref_certification_manifest_bytes();
        let schema_v3 = committed_certification_manifest_bytes();
        let summary =
            validate_windows_certification_manifest_preflight(schema_v3, schema_v4).unwrap();

        assert_eq!(
            summary.authority,
            WindowsCertificationManifestPreflightAuthority::DevelopmentPreflightOnly
        );
        assert_eq!(
            serde_json::to_value(&summary).unwrap()["authority"],
            "development_preflight_only"
        );
        assert_eq!(
            summary.schema_v3_release_id,
            "template-placeholder-not-evidence"
        );
        assert_eq!(summary.schema_v4_release_id, "xref-example-not-evidence");
        assert_eq!(
            summary.schema_v3_manifest_sha256,
            xref_sha256_bytes(schema_v3)
        );
        assert_eq!(
            summary.schema_v4_manifest_sha256,
            xref_sha256_bytes(schema_v4)
        );
        assert_eq!(
            summary.activation_target,
            embedded_certification_activation_target("autocad-2026-r25-1-en-us-preview-v1")
                .unwrap()
        );
        assert_eq!(
            summary.title_block_profile_registry_sha256,
            profiles::title_block_profile_registry_sha256()
        );
        assert_eq!(
            summary.release_binary_path,
            "C:/REPLACE_WITH_CERTIFIED_BINARIES/autocad-mcp.exe"
        );
        assert_eq!(
            summary.accoreconsole_path,
            "C:/Program Files/Autodesk/AutoCAD 2026/accoreconsole.exe"
        );
        assert_eq!(summary.autocad_product, CERTIFIED_AUTOCAD_PRODUCT);
        assert_eq!(summary.autocad_version, "2026");
        assert_eq!(
            summary.certified_arg_path,
            "C:/REPLACE_WITH_CERTIFIED_PROFILE/autocad-mcp.arg"
        );
        assert_eq!(
            summary.certified_arg_sha256,
            "89bc4284f84d1ee9c75ef3ce8a39933d1f86e919b3092ba59ce734b2f3216fc6"
        );
        assert_eq!(
            summary.certified_arg_policy_id,
            "autocad-mcp-preview-autocad-2026-en-us-v1"
        );
        assert_eq!(
            summary.certified_arg_policy_sha256,
            "40b3ae0defffde4b96c5affc185775e5393478e9e6f23c1768e8cb0dae915617"
        );
    }

    #[test]
    fn windows_certification_manifest_preflight_rejects_every_cross_schema_mismatch() {
        for (field, mismatched_value) in [
            (
                "release_binary_path",
                serde_json::Value::String("C:/different/autocad-mcp.exe".to_string()),
            ),
            (
                "release_binary_sha256",
                serde_json::Value::String("e".repeat(64)),
            ),
            (
                "accoreconsole_path",
                serde_json::Value::String(
                    "C:/different/AutoCAD 2026/accoreconsole.exe".to_string(),
                ),
            ),
            (
                "accoreconsole_sha256",
                serde_json::Value::String("e".repeat(64)),
            ),
            (
                "autocad_product",
                serde_json::Value::String("different-product".to_string()),
            ),
            (
                "autocad_version",
                serde_json::Value::String("2025".to_string()),
            ),
            (
                "certified_arg_path",
                serde_json::Value::String("C:/different/autocad-mcp.arg".to_string()),
            ),
            (
                "certified_arg_sha256",
                serde_json::Value::String("e".repeat(64)),
            ),
            (
                "certified_arg_policy_id",
                serde_json::Value::String("different-policy".to_string()),
            ),
            (
                "certified_arg_policy_sha256",
                serde_json::Value::String("e".repeat(64)),
            ),
        ] {
            let mut schema_v4: serde_json::Value =
                serde_json::from_slice(committed_xref_certification_manifest_bytes()).unwrap();
            schema_v4[field] = mismatched_value;
            let schema_v4 = serde_json::to_vec(&schema_v4).unwrap();

            let error = validate_windows_certification_manifest_preflight(
                committed_certification_manifest_bytes(),
                &schema_v4,
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains(&format!(
                    "schema-v3/schema-v4 {field} declarations do not match"
                )),
                "field {field}: {error}"
            );
        }
    }

    #[test]
    fn windows_certification_manifest_preflight_rejects_activation_target_mismatch() {
        let mut schema_v4: serde_json::Value =
            serde_json::from_slice(committed_xref_certification_manifest_bytes()).unwrap();
        schema_v4["activation_target"]["registry_family"] =
            serde_json::Value::String("R25.0".to_string());
        let schema_v4 = serde_json::to_vec(&schema_v4).unwrap();

        let error = validate_windows_certification_manifest_preflight(
            committed_certification_manifest_bytes(),
            &schema_v4,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("schema-v3/schema-v4 activation_target declarations do not match"),
            "{error}"
        );
    }

    #[test]
    fn windows_certification_manifest_preflight_rejects_stale_title_registry_digest() {
        let mut schema_v3: serde_json::Value =
            serde_json::from_slice(committed_certification_manifest_bytes()).unwrap();
        schema_v3["runtime"]["title_block_profile_registry_sha256"] =
            serde_json::Value::String("a".repeat(64));
        let schema_v3 = serde_json::to_vec(&schema_v3).unwrap();

        let error = validate_windows_certification_manifest_preflight(
            &schema_v3,
            committed_xref_certification_manifest_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("title_block_profile_registry_sha256 is stale"),
            "{error}"
        );
    }

    #[test]
    fn windows_certification_manifest_preflight_requires_utf8_and_closed_schemas() {
        let non_utf8 = validate_windows_certification_manifest_preflight(
            &[0xff],
            committed_xref_certification_manifest_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(non_utf8.contains("schema-v3 certification manifest is not UTF-8"));

        let mut schema_v4: serde_json::Value =
            serde_json::from_slice(committed_xref_certification_manifest_bytes()).unwrap();
        schema_v4["unexpected"] = serde_json::Value::Bool(true);
        let schema_v4 = serde_json::to_vec(&schema_v4).unwrap();
        let open_schema = validate_windows_certification_manifest_preflight(
            committed_certification_manifest_bytes(),
            &schema_v4,
        )
        .unwrap_err()
        .to_string();
        assert!(
            open_schema.contains("unknown field `unexpected`"),
            "{open_schema}"
        );
    }
}
