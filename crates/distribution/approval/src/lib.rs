use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

mod build_attestation;
mod build_recipe;
mod evidence;
mod preview_clean_host;
mod preview_publication_handoff;
mod source_candidate;

pub use build_attestation::{
    parse_and_validate_windows_preview_build_attestation,
    serialize_windows_preview_build_attestation, WindowsPreviewBuildAttestation,
    WindowsPreviewBuildSourceIdentity, WindowsPreviewBuildSourceIdentityInput,
    WindowsPreviewBuildSubject, WindowsPreviewBuildSubjectId, WindowsPreviewNativeBuild,
    WindowsPreviewNativeBuildInput, WindowsPreviewUnsignedPreflight,
    WINDOWS_PREVIEW_BUILD_ATTESTATION_KIND, WINDOWS_PREVIEW_BUILD_ATTESTATION_PATH,
    WINDOWS_PREVIEW_BUILD_ATTESTATION_SCHEMA_PATH,
    WINDOWS_PREVIEW_BUILD_ATTESTATION_SCHEMA_VERSION,
};
pub use build_recipe::{
    render_windows_x86_64_build_recipe, BuildRecipeError, WINDOWS_X86_64_TARGET,
};
pub use evidence::{BoundDistributionEvidence, SupplementalEvidenceBytes};
pub use preview_clean_host::{
    parse_preview_clean_host_receipt, PreviewCleanHostArchitecture, PreviewCleanHostCheck,
    PreviewCleanHostClient, PreviewCleanHostClientProduct, PreviewCleanHostFixture,
    PreviewCleanHostFixtures, PreviewCleanHostHost, PreviewCleanHostLimitation,
    PreviewCleanHostOperatingSystem, PreviewCleanHostPackage, PreviewCleanHostReceipt,
    PreviewCleanHostReceiptKind, PreviewCleanHostResult, PREVIEW_CLEAN_HOST_DWG_FIXTURE_ID,
    PREVIEW_CLEAN_HOST_DWG_FIXTURE_SHA256, PREVIEW_CLEAN_HOST_DXF_FIXTURE_ID,
    PREVIEW_CLEAN_HOST_DXF_FIXTURE_SHA256, PREVIEW_CLEAN_HOST_KIND,
    PREVIEW_CLEAN_HOST_OBSERVED_TOOL_COUNT, PREVIEW_CLEAN_HOST_RECEIPT_PATH,
    PREVIEW_CLEAN_HOST_RESULT, PREVIEW_CLEAN_HOST_SCHEMA_PATH, PREVIEW_CLEAN_HOST_SCHEMA_VERSION,
    PREVIEW_CLEAN_HOST_TARGET,
};
pub use preview_publication_handoff::{
    PreviewPublicationArtifactRole, PreviewPublicationFileBinding, PreviewPublicationHandoff,
    PreviewPublicationSourceIdentity, PREVIEW_PUBLICATION_BUILD_ATTESTATION_PATH,
    PREVIEW_PUBLICATION_CLEAN_HOST_RECEIPT_PATH,
    PREVIEW_PUBLICATION_CURRENT_DISTRIBUTION_RECEIPT_PATH, PREVIEW_PUBLICATION_HANDOFF_KIND,
    PREVIEW_PUBLICATION_HANDOFF_SCHEMA_PATH, PREVIEW_PUBLICATION_HANDOFF_SCHEMA_VERSION,
    PREVIEW_PUBLICATION_HANDOFF_SIGNING_DOMAIN, PREVIEW_PUBLICATION_MCPB_PATH,
    PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH, PREVIEW_PUBLICATION_PROJECTION_RECEIPT_PATH,
    PREVIEW_PUBLICATION_PUBLIC_ASSET_PATHS, PREVIEW_PUBLICATION_SHA256SUMS_PATH,
    PREVIEW_PUBLICATION_SOURCE_ARCHIVE_PATH, PREVIEW_PUBLICATION_SOURCE_CLOSURE_SBOM_PATH,
};
pub use release_qualification::parse_strict_json;
pub use source_candidate::{
    SourceBundleArchivePolicy, SourceBundleExclusion, SourceBundleFile, SourceBundleManifest,
    SourceBundlePackage, SourceBundleRoot, SourceBundleTree, SourceBundleVendor,
    SOURCE_BUNDLE_ARTIFACT_KIND, SOURCE_BUNDLE_BUILD_RECIPE_PATH, SOURCE_BUNDLE_MANIFEST_PATH,
    SOURCE_BUNDLE_MANIFEST_SCHEMA_VERSION, SOURCE_BUNDLE_OFFLINE_CONFIG_PATH,
    SOURCE_BUNDLE_PROFILE, SOURCE_BUNDLE_TREE_DIGEST_METHOD,
};

pub const APPROVAL_SCHEMA_VERSION: u32 = 4;
pub const APPROVAL_KIND: &str = "owner_distribution_approval";

const INITIAL_WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";
const INITIAL_WINDOWS_MCPB: &str = "autocad-mcp-windows-x64.mcpb";
const INITIAL_WINDOWS_PREVIEW_MCPB: &str = "autocad-mcp-windows-x64-preview.mcpb";
const INITIAL_WINDOWS_SOURCE_ARCHIVE: &str = "autocad-mcp-windows-x64-build-source.zip";
const INITIAL_WINDOWS_PREVIEW_SOURCE_ARCHIVE: &str =
    "autocad-mcp-windows-x64-preview-build-source.zip";
const MCP_SERVER_CONTAINER_PATH: &str = "plugin/bin/autocad-mcp.exe";
const AUTOLISP_LSP_CONTAINER_PATH: &str = "plugin/bin/autolisp-lsp.exe";
const THIRD_PARTY_LICENSE_POLICY_PATH: &str = "plugin/.third-party/third-party-license-policy.json";
const SOURCE_LOCK_SBOM_PATH: &str = "plugin/.third-party/source-lock.spdx.json";
const THIRD_PARTY_NOTICES_PATH: &str = "plugin/THIRD_PARTY_LICENSES.txt";
const THIRD_PARTY_LICENSE_PROVENANCE_PATH: &str =
    "plugin/.third-party/third-party-license-provenance.json";
const PROJECT_LICENSE_PATH: &str = "plugin/LICENSE";
const APPROVAL_CONTRACT_SCHEMA_PATH: &str =
    "crates/distribution/approval/schemas/owner-distribution-approval.schema.json";
const SOURCE_CLOSURE_SBOM_PATH: &str = "distribution-evidence/windows-x64-source-closure.spdx.json";
const BUILD_ATTESTATION_PATH: &str = "distribution-evidence/windows-x64-build.json";
const PREVIEW_SOURCE_CLOSURE_SBOM_PATH: &str =
    "distribution-evidence/windows-x64-preview-source-closure.spdx.json";
const PREVIEW_BUILD_ATTESTATION_PATH: &str = "distribution-evidence/windows-x64-preview-build.json";
const RMCP_SUPPLEMENT_BINDING: &str = "rmcp-rust-sdk-license-3529c367";
const RMCP_SUPPLEMENT_PATH: &str = "plugin/.third-party/license-supplements/rmcp-1.7.0-LICENSE.txt";

const REQUIRED_INVALIDATION_CONDITIONS: &[InvalidationCondition] = &[
    InvalidationCondition::ApprovalContractSchemaChanged,
    InvalidationCondition::ArtifactBytesOrArtifactSetChanged,
    InvalidationCondition::BuildRecipeOrToolchainChanged,
    InvalidationCondition::CargoLockOrDependencyInputClosureChanged,
    InvalidationCondition::DistributionChannelOrTargetChanged,
    InvalidationCondition::PackageDeterminationChanged,
    InvalidationCondition::ProjectLicenseChanged,
    InvalidationCondition::SourceLockSbomChanged,
    InvalidationCondition::SourceBundleChanged,
    InvalidationCondition::SourceClosureSbomChanged,
    InvalidationCondition::ThirdPartyNoticeOrSupplementalEvidenceChanged,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationError {
    code: &'static str,
    detail: String,
}

impl ValidationError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ValidationError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    OwnerDistributionApproval,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseProfile {
    InitialWindowsPublic,
    InitialWindowsPreviewPublic,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DistributionMode {
    Release,
    Preview,
}

impl DistributionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Preview => "preview",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerDistributionApproval {
    schema_version: u32,
    kind: ApprovalKind,
    release_profile: ReleaseProfile,
    decision: Decision,
    project: Project,
    source_identity: SourceIdentity,
    evidence_bindings: EvidenceBindings,
    artifacts: Vec<Artifact>,
    distribution_scopes: Vec<DistributionScope>,
    source_exclusions: Vec<SourceExclusion>,
    package_determinations: Vec<PackageDetermination>,
    invalidation_conditions: Vec<InvalidationCondition>,
}

impl OwnerDistributionApproval {
    pub fn release_profile(&self) -> ReleaseProfile {
        self.release_profile
    }

    pub fn decision(&self) -> &Decision {
        &self.decision
    }

    pub fn project(&self) -> &Project {
        &self.project
    }

    pub fn source_identity(&self) -> &SourceIdentity {
        &self.source_identity
    }

    pub fn evidence_bindings(&self) -> &EvidenceBindings {
        &self.evidence_bindings
    }

    pub fn artifacts(&self) -> &[Artifact] {
        &self.artifacts
    }

    pub fn distribution_scopes(&self) -> &[DistributionScope] {
        &self.distribution_scopes
    }

    pub fn source_exclusions(&self) -> &[SourceExclusion] {
        &self.source_exclusions
    }

    pub fn package_determinations(&self) -> &[PackageDetermination] {
        &self.package_determinations
    }

    pub fn invalidation_conditions(&self) -> &[InvalidationCondition] {
        &self.invalidation_conditions
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != APPROVAL_SCHEMA_VERSION {
            return Err(error(
                "schema_version_invalid",
                format!("schema_version must equal {APPROVAL_SCHEMA_VERSION}"),
            ));
        }
        if self.kind != ApprovalKind::OwnerDistributionApproval {
            return Err(error(
                "approval_kind_invalid",
                "kind must equal owner_distribution_approval",
            ));
        }
        self.decision.validate()?;
        self.project.validate()?;
        self.source_identity.validate()?;
        self.evidence_bindings.validate()?;
        require_sorted_unique_by(&self.artifacts, "artifacts", |artifact| {
            artifact.artifact_id.clone()
        })?;
        require_sorted_unique_by(&self.distribution_scopes, "distribution_scopes", |scope| {
            scope.scope_id.clone()
        })?;
        require_sorted_unique_by(&self.source_exclusions, "source_exclusions", |exclusion| {
            exclusion.identity_key()
        })?;
        require_sorted_unique_by(
            &self.package_determinations,
            "package_determinations",
            |determination| determination.determination_id.clone(),
        )?;
        if self.artifacts.is_empty() {
            return Err(error("artifacts_empty", "artifacts must not be empty"));
        }
        if self.distribution_scopes.is_empty() {
            return Err(error(
                "distribution_scopes_empty",
                "distribution_scopes must not be empty",
            ));
        }
        if self.source_exclusions.is_empty() {
            return Err(error(
                "source_exclusions_empty",
                "source_exclusions must not be empty",
            ));
        }
        if self.package_determinations.is_empty() {
            return Err(error(
                "package_determinations_empty",
                "package_determinations must not be empty",
            ));
        }

        let artifacts = self
            .artifacts
            .iter()
            .map(|artifact| (artifact.artifact_id.as_str(), artifact))
            .collect::<BTreeMap<_, _>>();
        for artifact in &self.artifacts {
            artifact.validate(&artifacts)?;
        }
        for exclusion in &self.source_exclusions {
            exclusion.validate(&artifacts)?;
        }

        let scopes = self
            .distribution_scopes
            .iter()
            .map(|scope| (scope.scope_id.as_str(), scope))
            .collect::<BTreeMap<_, _>>();
        let mut referenced_artifacts = BTreeSet::new();
        for scope in &self.distribution_scopes {
            scope.validate(&artifacts)?;
            referenced_artifacts.extend(scope.artifact_ids.iter().map(String::as_str));
        }
        for artifact in &self.artifacts {
            if !referenced_artifacts.contains(artifact.artifact_id.as_str()) {
                return Err(error(
                    "artifact_unscoped",
                    format!(
                        "artifact {} is not referenced by a distribution scope",
                        artifact.artifact_id
                    ),
                ));
            }
        }

        self.evidence_bindings
            .validate_references(&scopes, &artifacts)?;
        let (expected_mode, expected_mcpb, expected_source, expected_sbom, expected_attestation) =
            match self.release_profile {
                ReleaseProfile::InitialWindowsPublic => (
                    DistributionMode::Release,
                    INITIAL_WINDOWS_MCPB,
                    INITIAL_WINDOWS_SOURCE_ARCHIVE,
                    SOURCE_CLOSURE_SBOM_PATH,
                    BUILD_ATTESTATION_PATH,
                ),
                ReleaseProfile::InitialWindowsPreviewPublic => (
                    DistributionMode::Preview,
                    INITIAL_WINDOWS_PREVIEW_MCPB,
                    INITIAL_WINDOWS_PREVIEW_SOURCE_ARCHIVE,
                    PREVIEW_SOURCE_CLOSURE_SBOM_PATH,
                    PREVIEW_BUILD_ATTESTATION_PATH,
                ),
            };
        self.validate_initial_windows_public_profile(
            expected_mode,
            expected_mcpb,
            expected_source,
            expected_sbom,
            expected_attestation,
        )?;

        let supplemental_bindings = self
            .evidence_bindings
            .supplemental_license_evidence
            .iter()
            .map(|binding| binding.binding_id.as_str())
            .collect::<BTreeSet<_>>();
        let source_closure_sbom_bindings = self
            .evidence_bindings
            .source_closure_sboms
            .iter()
            .map(|binding| (binding.binding_id.as_str(), binding))
            .collect::<BTreeMap<_, _>>();

        let mut package_scope_membership = BTreeSet::new();
        for determination in &self.package_determinations {
            determination.validate(
                &scopes,
                &artifacts,
                &supplemental_bindings,
                &source_closure_sbom_bindings,
            )?;
            for scope_id in &determination.scope_ids {
                for package in &determination.packages {
                    let key = (scope_id.as_str(), package.identity_key());
                    if !package_scope_membership.insert(key) {
                        return Err(error(
                            "package_determination_overlap",
                            format!(
                                "package {} {} is covered more than once in scope {}",
                                package.name, package.version, scope_id
                            ),
                        ));
                    }
                }
            }
        }

        if self.invalidation_conditions.as_slice() != REQUIRED_INVALIDATION_CONDITIONS {
            return Err(error(
                "invalidation_conditions_invalid",
                format!(
                    "invalidation_conditions must exactly equal the schema-v{APPROVAL_SCHEMA_VERSION} closed set"
                ),
            ));
        }
        Ok(())
    }

    fn validate_initial_windows_public_profile(
        &self,
        expected_mode: DistributionMode,
        expected_mcpb: &str,
        expected_source: &str,
        expected_sbom: &str,
        expected_attestation: &str,
    ) -> Result<(), ValidationError> {
        if self.source_identity.package_mode != expected_mode {
            return Err(error(
                "initial_windows_package_mode_invalid",
                format!(
                    "{:?} requires source_identity.package_mode={}",
                    self.release_profile,
                    expected_mode.as_str()
                ),
            ));
        }
        if !valid_profile_version(&self.project.release_version, expected_mode) {
            return Err(error(
                "initial_windows_release_version_invalid",
                match expected_mode {
                    DistributionMode::Release => {
                        "initial_windows_public requires a stable version with major at least 1"
                    }
                    DistributionMode::Preview => {
                        "initial_windows_preview_public requires a stable version 0.minor.patch"
                    }
                },
            ));
        }
        if self.project.name != "AutoCAD-MCP"
            || self.project.project_license_expression != "GPL-3.0-or-later"
        {
            return Err(error(
                "initial_windows_project_identity_invalid",
                "initial_windows_public requires project name AutoCAD-MCP and licence GPL-3.0-or-later",
            ));
        }
        if self.distribution_scopes.len() != 2 {
            return Err(error(
                "initial_windows_scope_cardinality_invalid",
                "initial_windows_public requires exactly one public binary scope and one public source scope",
            ));
        }
        let binary_scopes = self
            .distribution_scopes
            .iter()
            .filter(|scope| scope.kind == ScopeKind::PublicBinaryDistribution)
            .collect::<Vec<_>>();
        let source_scopes = self
            .distribution_scopes
            .iter()
            .filter(|scope| scope.kind == ScopeKind::PublicSourceDistribution)
            .collect::<Vec<_>>();
        if binary_scopes.len() != 1 || source_scopes.len() != 1 {
            return Err(error(
                "initial_windows_scope_kinds_invalid",
                "initial_windows_public requires exactly one public_binary_distribution and one public_source_distribution",
            ));
        }
        let binary_scope = binary_scopes[0];
        let source_scope = source_scopes[0];
        for scope in [binary_scope, source_scope] {
            if scope.target_triple.as_deref() != Some(INITIAL_WINDOWS_TARGET) {
                return Err(error(
                    "initial_windows_scope_target_invalid",
                    format!(
                        "scope {} must target {INITIAL_WINDOWS_TARGET}",
                        scope.scope_id
                    ),
                ));
            }
        }

        const REQUIRED_ROLES: &[ArtifactRole] = &[
            ArtifactRole::AutolispLspExecutable,
            ArtifactRole::BuildAttestation,
            ArtifactRole::CoveredSourceArchive,
            ArtifactRole::McpServerExecutable,
            ArtifactRole::Mcpb,
            ArtifactRole::SourceClosureSbom,
        ];
        if self.artifacts.len() != REQUIRED_ROLES.len() {
            return Err(error(
                "initial_windows_artifact_cardinality_invalid",
                "initial_windows_public requires exactly six release artifact records",
            ));
        }
        for role in REQUIRED_ROLES {
            if self
                .artifacts
                .iter()
                .filter(|artifact| artifact.role == *role)
                .count()
                != 1
            {
                return Err(error(
                    "initial_windows_artifact_role_cardinality_invalid",
                    format!("initial_windows_public requires exactly one {role:?} artifact"),
                ));
            }
        }

        let source_archive =
            require_single_artifact_role(&self.artifacts, ArtifactRole::CoveredSourceArchive)?;
        let build_attestation =
            require_single_artifact_role(&self.artifacts, ArtifactRole::BuildAttestation)?;
        let lsp =
            require_single_artifact_role(&self.artifacts, ArtifactRole::AutolispLspExecutable)?;
        let mcpb = require_single_artifact_role(&self.artifacts, ArtifactRole::Mcpb)?;
        let source_closure_sbom =
            require_single_artifact_role(&self.artifacts, ArtifactRole::SourceClosureSbom)?;
        let server =
            require_single_artifact_role(&self.artifacts, ArtifactRole::McpServerExecutable)?;

        if source_archive.logical_name != expected_source {
            return Err(error(
                "initial_windows_source_archive_name_invalid",
                format!("covered source archive logical_name must equal {expected_source}"),
            ));
        }
        if mcpb.logical_name != expected_mcpb {
            return Err(error(
                "initial_windows_mcpb_name_invalid",
                format!("MCPB logical_name must equal {expected_mcpb}"),
            ));
        }
        for (executable, exact_path) in [
            (lsp, AUTOLISP_LSP_CONTAINER_PATH),
            (server, MCP_SERVER_CONTAINER_PATH),
        ] {
            let container = executable.container.as_ref().ok_or_else(|| {
                error(
                    "initial_windows_executable_containment_invalid",
                    format!(
                        "executable {} lacks its exact MCPB containment",
                        executable.artifact_id
                    ),
                )
            })?;
            if executable.logical_name != exact_path
                || container.container_artifact_id != mcpb.artifact_id
                || container.container_path != exact_path
            {
                return Err(error(
                    "initial_windows_executable_containment_invalid",
                    format!(
                        "executable {} must be contained as {exact_path} in {}",
                        executable.artifact_id, mcpb.artifact_id
                    ),
                ));
            }
        }
        for artifact in &self.artifacts {
            let executable = matches!(
                artifact.role,
                ArtifactRole::McpServerExecutable | ArtifactRole::AutolispLspExecutable
            );
            if !executable && artifact.container.is_some() {
                return Err(error(
                    "initial_windows_detached_artifact_required",
                    format!("artifact {} must be detached", artifact.artifact_id),
                ));
            }
        }

        let mut logical_names = BTreeSet::new();
        let mut byte_identities = BTreeSet::new();
        let mut container_locations = BTreeSet::new();
        for artifact in &self.artifacts {
            if !logical_names.insert(artifact.logical_name.as_str()) {
                return Err(error(
                    "artifact_logical_name_alias",
                    format!(
                        "multiple release artifacts use logical name {}",
                        artifact.logical_name
                    ),
                ));
            }
            if !byte_identities.insert((artifact.sha256.as_str(), artifact.size_bytes)) {
                return Err(error(
                    "artifact_byte_identity_alias",
                    format!(
                        "release artifact {} aliases another artifact's byte identity",
                        artifact.artifact_id
                    ),
                ));
            }
            if let Some(container) = &artifact.container {
                if !container_locations.insert((
                    container.container_artifact_id.as_str(),
                    container.container_path.as_str(),
                )) {
                    return Err(error(
                        "artifact_container_location_alias",
                        format!(
                            "multiple artifacts use {} in container {}",
                            container.container_path, container.container_artifact_id
                        ),
                    ));
                }
            }
        }

        let binary_expected = BTreeSet::from([
            build_attestation.artifact_id.as_str(),
            lsp.artifact_id.as_str(),
            mcpb.artifact_id.as_str(),
            source_closure_sbom.artifact_id.as_str(),
            server.artifact_id.as_str(),
        ]);
        let binary_actual = binary_scope
            .artifact_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if binary_actual != binary_expected {
            return Err(error(
                "initial_windows_binary_scope_membership_invalid",
                "public binary scope must contain exactly the MCPB, its two executables, source-closure SBOM, and build attestation",
            ));
        }
        if source_scope.artifact_ids.len() != 1
            || source_scope.artifact_ids[0] != source_archive.artifact_id
        {
            return Err(error(
                "initial_windows_source_scope_membership_invalid",
                "public source scope must contain exactly the parallel Windows build-source archive",
            ));
        }
        const EXPECTED_SOURCE_EXCLUSIONS: &[(&str, &str, &str, u64, &str, &str)] = &[
            (
                "acadrust",
                "0.4.1",
                "src/docs/OpenDesign_Specification_for_.dwg_files.pdf",
                2_399_640,
                "1ed2e02722862188120da606e4b6a816fa4014c96de68da2f84a2ecda09461e7",
                "excluded non-source third-party specification PDF from target source bundle",
            ),
            (
                "flate2",
                "1.1.9",
                "tests/corrupt-gz-file.bin",
                7_128,
                "083dd284aa1621916a2d0f66ea048c8d3ba7a722b22d0d618722633f51e7d39c",
                "excluded non-source binary corruption test fixture from target source bundle",
            ),
        ];
        if self.source_exclusions.len() != EXPECTED_SOURCE_EXCLUSIONS.len() {
            return Err(error(
                "initial_windows_source_exclusions_invalid",
                "initial_windows_public requires exactly the two reviewed non-build source exclusions",
            ));
        }
        for (actual, expected) in self
            .source_exclusions
            .iter()
            .zip(EXPECTED_SOURCE_EXCLUSIONS)
        {
            let (name, version, path, size_bytes, sha256, reason) = *expected;
            if actual.source_artifact_id != source_archive.artifact_id
                || actual.package_name != name
                || actual.package_version != version
                || actual.crate_relative_path != path
                || actual.size_bytes != size_bytes
                || actual.sha256 != sha256
                || actual.reason != reason
            {
                return Err(error(
                    "initial_windows_source_exclusions_invalid",
                    "source exclusions do not exactly match the reviewed initial Windows source-bundle exclusions",
                ));
            }
        }
        for determination in &self.package_determinations {
            if let SourceDisposition::ExactSourceArtifact { artifact_id } =
                &determination.source_disposition
            {
                if artifact_id != &source_archive.artifact_id {
                    return Err(error(
                        "initial_windows_source_disposition_invalid",
                        format!(
                            "determination {} must bind the sole companion build-source archive",
                            determination.determination_id
                        ),
                    ));
                }
            }
        }

        let evidence = &self.evidence_bindings;
        for (binding, expected_path, label) in [
            (
                &evidence.third_party_license_policy,
                THIRD_PARTY_LICENSE_POLICY_PATH,
                "third_party_license_policy",
            ),
            (
                &evidence.source_lock_sbom,
                SOURCE_LOCK_SBOM_PATH,
                "source_lock_sbom",
            ),
            (
                &evidence.third_party_notices,
                THIRD_PARTY_NOTICES_PATH,
                "third_party_notices",
            ),
            (
                &evidence.third_party_license_provenance,
                THIRD_PARTY_LICENSE_PROVENANCE_PATH,
                "third_party_license_provenance",
            ),
            (
                &evidence.project_license,
                PROJECT_LICENSE_PATH,
                "project_license",
            ),
            (
                &evidence.approval_contract_schema,
                APPROVAL_CONTRACT_SCHEMA_PATH,
                "approval_contract_schema",
            ),
        ] {
            if binding.logical_path != expected_path {
                return Err(error(
                    "initial_windows_evidence_path_invalid",
                    format!("evidence_bindings.{label}.logical_path must equal {expected_path}"),
                ));
            }
        }

        if evidence.source_closure_sboms.len() != 1 {
            return Err(error(
                "initial_windows_source_closure_sbom_cardinality_invalid",
                "initial_windows_public requires exactly one source-closure SBOM binding",
            ));
        }
        let source_closure_binding = &evidence.source_closure_sboms[0];
        if source_closure_binding.scope_id != binary_scope.scope_id
            || source_closure_binding.target_triple != INITIAL_WINDOWS_TARGET
            || source_closure_binding.artifact_id != source_closure_sbom.artifact_id
            || source_closure_binding.covered_source_archive_artifact_id
                != source_archive.artifact_id
            || source_closure_binding.file.logical_path != expected_sbom
            || source_closure_sbom.logical_name != expected_sbom
        {
            return Err(error(
                "initial_windows_source_closure_sbom_binding_invalid",
                "source-closure SBOM must bind the exact Windows evidence-distribution scope, covered source archive, target, artifact, and evidence path",
            ));
        }

        if evidence.build_attestations.len() != 1 {
            return Err(error(
                "initial_windows_build_attestation_cardinality_invalid",
                "initial_windows_public requires exactly one build attestation binding",
            ));
        }
        let build_binding = &evidence.build_attestations[0];
        if build_binding.scope_id != binary_scope.scope_id
            || build_binding.target_triple != INITIAL_WINDOWS_TARGET
            || build_binding.artifact_id != build_attestation.artifact_id
            || build_binding.file.logical_path != expected_attestation
            || build_attestation.logical_name != expected_attestation
        {
            return Err(error(
                "initial_windows_build_attestation_binding_invalid",
                "build attestation must bind the exact Windows binary scope, target, artifact, and evidence path",
            ));
        }
        let build_describes = build_binding
            .describes_artifact_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if build_describes
            != BTreeSet::from([
                source_archive.artifact_id.as_str(),
                lsp.artifact_id.as_str(),
                server.artifact_id.as_str(),
            ])
        {
            return Err(error(
                "initial_windows_build_attestation_coverage_invalid",
                "build attestation must describe exactly the build-source archive and both executables",
            ));
        }

        let mut evidence_paths = BTreeSet::new();
        let mut evidence_byte_identities = BTreeSet::new();
        let mut check_evidence_alias =
            |binding: &FileBinding, label: &str| -> Result<(), ValidationError> {
                if !evidence_paths.insert(binding.logical_path.clone()) {
                    return Err(error(
                        "evidence_logical_path_alias",
                        format!("{label} aliases another evidence logical path"),
                    ));
                }
                if !evidence_byte_identities.insert((binding.sha256.clone(), binding.size_bytes)) {
                    return Err(error(
                        "evidence_byte_identity_alias",
                        format!("{label} aliases another evidence byte identity"),
                    ));
                }
                Ok(())
            };
        for (binding, label) in [
            (
                &evidence.third_party_license_policy,
                "third_party_license_policy",
            ),
            (&evidence.source_lock_sbom, "source_lock_sbom"),
            (&evidence.third_party_notices, "third_party_notices"),
            (
                &evidence.third_party_license_provenance,
                "third_party_license_provenance",
            ),
            (&evidence.project_license, "project_license"),
            (
                &evidence.approval_contract_schema,
                "approval_contract_schema",
            ),
            (&source_closure_binding.file, "source_closure_sbom"),
            (&build_binding.file, "build_attestation"),
        ] {
            check_evidence_alias(binding, label)?;
        }
        for binding in &evidence.supplemental_license_evidence {
            check_evidence_alias(&binding.file, &binding.binding_id)?;
        }
        if evidence.supplemental_license_evidence.len() != 1
            || evidence.supplemental_license_evidence[0].binding_id != RMCP_SUPPLEMENT_BINDING
            || evidence.supplemental_license_evidence[0].file.logical_path != RMCP_SUPPLEMENT_PATH
        {
            return Err(error(
                "initial_windows_supplemental_evidence_invalid",
                "initial_windows_public requires the exact RMCP transition-licence supplement binding",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStatus {
    ApprovedForDistribution,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKind {
    ProjectOwner,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    status: DecisionStatus,
    authority_kind: AuthorityKind,
    authority_identifier: String,
    decision_id: String,
    decided_utc: String,
    supersedes_decision_id: Option<String>,
}

impl Decision {
    pub fn status(&self) -> DecisionStatus {
        self.status
    }

    pub fn authority_identifier(&self) -> &str {
        &self.authority_identifier
    }

    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    pub fn decided_utc(&self) -> &str {
        &self.decided_utc
    }

    pub fn supersedes_decision_id(&self) -> Option<&str> {
        self.supersedes_decision_id.as_deref()
    }

    fn validate(&self) -> Result<(), ValidationError> {
        if self.status != DecisionStatus::ApprovedForDistribution
            || self.authority_kind != AuthorityKind::ProjectOwner
        {
            return Err(error(
                "decision_closed_value_invalid",
                format!(
                    "decision status and authority kind must use the schema-v{APPROVAL_SCHEMA_VERSION} closed values"
                ),
            ));
        }
        require_public_identifier(&self.authority_identifier, "decision.authority_identifier")?;
        require_decision_id(&self.decision_id, "decision.decision_id")?;
        if let Some(supersedes) = &self.supersedes_decision_id {
            require_decision_id(supersedes, "decision.supersedes_decision_id")?;
            if supersedes == &self.decision_id {
                return Err(error(
                    "decision_self_supersedes",
                    "a decision must not supersede itself",
                ));
            }
        }
        require_utc_timestamp(&self.decided_utc, "decision.decided_utc")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    name: String,
    release_version: String,
    project_license_expression: String,
}

impl Project {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn release_version(&self) -> &str {
        &self.release_version
    }

    pub fn project_license_expression(&self) -> &str {
        &self.project_license_expression
    }

    fn validate(&self) -> Result<(), ValidationError> {
        require_token(&self.name, "project.name", 1, 128)?;
        require_token(&self.release_version, "project.release_version", 1, 64)?;
        require_expression(
            &self.project_license_expression,
            "project.project_license_expression",
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitObjectFormat {
    Sha1,
    Sha256,
}

impl GitObjectFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildProfile {
    Release,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    git_object_format: GitObjectFormat,
    git_commit_oid: String,
    git_tree_oid: String,
    source_bundle_manifest_sha256: String,
    cargo_lock_sha256: String,
    dependency_input_closure_sha256: String,
    rust_toolchain_sha256: String,
    build_recipe_sha256: String,
    build_profile: BuildProfile,
    package_mode: DistributionMode,
    cargo_incremental: bool,
}

impl SourceIdentity {
    pub fn git_object_format(&self) -> GitObjectFormat {
        self.git_object_format
    }

    pub fn git_commit_oid(&self) -> &str {
        &self.git_commit_oid
    }

    pub fn git_tree_oid(&self) -> &str {
        &self.git_tree_oid
    }

    pub fn source_bundle_manifest_sha256(&self) -> &str {
        &self.source_bundle_manifest_sha256
    }

    pub fn cargo_lock_sha256(&self) -> &str {
        &self.cargo_lock_sha256
    }

    pub fn dependency_input_closure_sha256(&self) -> &str {
        &self.dependency_input_closure_sha256
    }

    pub fn rust_toolchain_sha256(&self) -> &str {
        &self.rust_toolchain_sha256
    }

    pub fn build_recipe_sha256(&self) -> &str {
        &self.build_recipe_sha256
    }

    pub fn build_profile(&self) -> BuildProfile {
        self.build_profile
    }

    pub fn package_mode(&self) -> DistributionMode {
        self.package_mode
    }

    pub fn cargo_incremental(&self) -> bool {
        self.cargo_incremental
    }

    fn validate(&self) -> Result<(), ValidationError> {
        let oid_length = match self.git_object_format {
            GitObjectFormat::Sha1 => 40,
            GitObjectFormat::Sha256 => 64,
        };
        require_lower_hex(
            &self.git_commit_oid,
            oid_length,
            "source_identity.git_commit_oid",
        )?;
        require_lower_hex(
            &self.git_tree_oid,
            oid_length,
            "source_identity.git_tree_oid",
        )?;
        for (value, label) in [
            (
                &self.source_bundle_manifest_sha256,
                "source_identity.source_bundle_manifest_sha256",
            ),
            (&self.cargo_lock_sha256, "source_identity.cargo_lock_sha256"),
            (
                &self.dependency_input_closure_sha256,
                "source_identity.dependency_input_closure_sha256",
            ),
            (
                &self.rust_toolchain_sha256,
                "source_identity.rust_toolchain_sha256",
            ),
            (
                &self.build_recipe_sha256,
                "source_identity.build_recipe_sha256",
            ),
        ] {
            require_sha256(value, label)?;
        }
        if self.build_profile != BuildProfile::Release {
            return Err(error(
                "build_profile_invalid",
                "source_identity.build_profile must equal release",
            ));
        }
        if self.cargo_incremental {
            return Err(error(
                "incremental_build_forbidden",
                "source_identity.cargo_incremental must be false",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileBinding {
    logical_path: String,
    sha256: String,
    size_bytes: u64,
}

impl FileBinding {
    pub fn logical_path(&self) -> &str {
        &self.logical_path
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<(), ValidationError> {
        if self.size_bytes != bytes.len() as u64 {
            return Err(error(
                "bound_file_size_mismatch",
                format!(
                    "{} has {} bytes, expected {}",
                    self.logical_path,
                    bytes.len(),
                    self.size_bytes
                ),
            ));
        }
        let actual = sha256_hex(bytes);
        if self.sha256 != actual {
            return Err(error(
                "bound_file_digest_mismatch",
                format!("{} SHA-256 does not match", self.logical_path),
            ));
        }
        Ok(())
    }

    fn validate(&self, label: &str) -> Result<(), ValidationError> {
        require_safe_logical_path(&self.logical_path, &format!("{label}.logical_path"))?;
        require_sha256(&self.sha256, &format!("{label}.sha256"))?;
        if self.size_bytes == 0 {
            return Err(error(
                "bound_file_empty",
                format!("{label}.size_bytes must be greater than zero"),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceClosureSbomBinding {
    binding_id: String,
    scope_id: String,
    target_triple: String,
    covered_source_archive_artifact_id: String,
    artifact_id: String,
    file: FileBinding,
}

impl SourceClosureSbomBinding {
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    pub fn target_triple(&self) -> &str {
        &self.target_triple
    }

    pub fn covered_source_archive_artifact_id(&self) -> &str {
        &self.covered_source_archive_artifact_id
    }

    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    pub fn file(&self) -> &FileBinding {
        &self.file
    }

    fn validate(&self) -> Result<(), ValidationError> {
        require_id(&self.binding_id, "source_closure_sboms.binding_id")?;
        require_id(&self.scope_id, "source_closure_sboms.scope_id")?;
        require_target_triple(&self.target_triple, "source_closure_sboms.target_triple")?;
        require_id(
            &self.covered_source_archive_artifact_id,
            "source_closure_sboms.covered_source_archive_artifact_id",
        )?;
        require_id(&self.artifact_id, "source_closure_sboms.artifact_id")?;
        self.file.validate("source_closure_sboms.file")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildAttestationBinding {
    binding_id: String,
    scope_id: String,
    target_triple: String,
    describes_artifact_ids: Vec<String>,
    artifact_id: String,
    file: FileBinding,
}

impl BuildAttestationBinding {
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    pub fn target_triple(&self) -> &str {
        &self.target_triple
    }

    pub fn describes_artifact_ids(&self) -> &[String] {
        &self.describes_artifact_ids
    }

    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    pub fn file(&self) -> &FileBinding {
        &self.file
    }

    fn validate(&self) -> Result<(), ValidationError> {
        require_id(&self.binding_id, "build_attestations.binding_id")?;
        require_id(&self.scope_id, "build_attestations.scope_id")?;
        require_target_triple(&self.target_triple, "build_attestations.target_triple")?;
        require_sorted_unique_strings(
            &self.describes_artifact_ids,
            "build_attestations.describes_artifact_ids",
            false,
        )?;
        require_id(&self.artifact_id, "build_attestations.artifact_id")?;
        self.file.validate("build_attestations.file")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupplementalEvidenceBinding {
    binding_id: String,
    file: FileBinding,
}

impl SupplementalEvidenceBinding {
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    pub fn file(&self) -> &FileBinding {
        &self.file
    }

    fn validate(&self) -> Result<(), ValidationError> {
        require_id(&self.binding_id, "supplemental_license_evidence.binding_id")?;
        self.file.validate("supplemental_license_evidence.file")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBindings {
    third_party_license_policy: FileBinding,
    source_lock_sbom: FileBinding,
    third_party_notices: FileBinding,
    third_party_license_provenance: FileBinding,
    project_license: FileBinding,
    approval_contract_schema: FileBinding,
    source_closure_sboms: Vec<SourceClosureSbomBinding>,
    build_attestations: Vec<BuildAttestationBinding>,
    supplemental_license_evidence: Vec<SupplementalEvidenceBinding>,
}

impl EvidenceBindings {
    pub fn third_party_license_policy(&self) -> &FileBinding {
        &self.third_party_license_policy
    }

    pub fn source_lock_sbom(&self) -> &FileBinding {
        &self.source_lock_sbom
    }

    pub fn third_party_notices(&self) -> &FileBinding {
        &self.third_party_notices
    }

    pub fn third_party_license_provenance(&self) -> &FileBinding {
        &self.third_party_license_provenance
    }

    pub fn project_license(&self) -> &FileBinding {
        &self.project_license
    }

    pub fn approval_contract_schema(&self) -> &FileBinding {
        &self.approval_contract_schema
    }

    pub fn source_closure_sboms(&self) -> &[SourceClosureSbomBinding] {
        &self.source_closure_sboms
    }

    pub fn build_attestations(&self) -> &[BuildAttestationBinding] {
        &self.build_attestations
    }

    pub fn supplemental_license_evidence(&self) -> &[SupplementalEvidenceBinding] {
        &self.supplemental_license_evidence
    }

    fn validate(&self) -> Result<(), ValidationError> {
        self.third_party_license_policy
            .validate("evidence_bindings.third_party_license_policy")?;
        self.source_lock_sbom
            .validate("evidence_bindings.source_lock_sbom")?;
        self.third_party_notices
            .validate("evidence_bindings.third_party_notices")?;
        self.third_party_license_provenance
            .validate("evidence_bindings.third_party_license_provenance")?;
        self.project_license
            .validate("evidence_bindings.project_license")?;
        self.approval_contract_schema
            .validate("evidence_bindings.approval_contract_schema")?;
        require_sorted_unique_by(
            &self.source_closure_sboms,
            "source_closure_sboms",
            |binding| binding.binding_id.clone(),
        )?;
        require_sorted_unique_by(&self.build_attestations, "build_attestations", |binding| {
            binding.binding_id.clone()
        })?;
        require_sorted_unique_by(
            &self.supplemental_license_evidence,
            "supplemental_license_evidence",
            |binding| binding.binding_id.clone(),
        )?;
        if self.source_closure_sboms.is_empty() {
            return Err(error(
                "source_closure_sboms_empty",
                "evidence_bindings.source_closure_sboms must not be empty",
            ));
        }
        if self.build_attestations.is_empty() {
            return Err(error(
                "build_attestations_empty",
                "evidence_bindings.build_attestations must not be empty",
            ));
        }
        for binding in &self.source_closure_sboms {
            binding.validate()?;
        }
        for binding in &self.build_attestations {
            binding.validate()?;
        }
        for binding in &self.supplemental_license_evidence {
            binding.validate()?;
        }
        Ok(())
    }

    fn validate_references(
        &self,
        scopes: &BTreeMap<&str, &DistributionScope>,
        artifacts: &BTreeMap<&str, &Artifact>,
    ) -> Result<(), ValidationError> {
        let mut binding_ids = BTreeSet::from([
            "approval_contract_schema",
            "third_party_license_provenance",
            "third_party_license_policy",
            "project_license",
            "source_lock_sbom",
            "third_party_notices",
        ]);
        for binding in &self.source_closure_sboms {
            if !binding_ids.insert(binding.binding_id.as_str()) {
                return Err(error(
                    "evidence_binding_id_duplicate",
                    format!("duplicate evidence binding id {}", binding.binding_id),
                ));
            }
            let scope = require_scope(scopes, &binding.scope_id, "source-closure SBOM")?;
            if scope.target_triple.as_deref() != Some(binding.target_triple.as_str()) {
                return Err(error(
                    "source_closure_sbom_target_mismatch",
                    format!(
                        "source-closure SBOM {} target does not match its evidence-distribution scope {}",
                        binding.binding_id, binding.scope_id
                    ),
                ));
            }
            let covered_source_archive = require_artifact(
                artifacts,
                &binding.covered_source_archive_artifact_id,
                "source-closure SBOM covered source archive",
            )?;
            if covered_source_archive.role != ArtifactRole::CoveredSourceArchive {
                return Err(error(
                    "source_closure_sbom_archive_role_invalid",
                    format!(
                        "source-closure SBOM {} does not bind a covered source archive",
                        binding.binding_id
                    ),
                ));
            }
            if !scopes.values().any(|candidate| {
                candidate.kind == ScopeKind::PublicSourceDistribution
                    && candidate.target_triple.as_deref() == Some(binding.target_triple.as_str())
                    && candidate
                        .artifact_ids
                        .contains(&binding.covered_source_archive_artifact_id)
            }) {
                return Err(error(
                    "source_closure_sbom_archive_scope_invalid",
                    format!(
                        "source-closure SBOM {} covered source archive is absent from its target-matched public source scope",
                        binding.binding_id
                    ),
                ));
            }
            let artifact =
                require_artifact(artifacts, &binding.artifact_id, "source-closure SBOM")?;
            require_binding_artifact_match(
                &binding.file,
                artifact,
                ArtifactRole::SourceClosureSbom,
                "source-closure SBOM",
            )?;
            if !scope.artifact_ids.contains(&binding.artifact_id) {
                return Err(error(
                    "source_closure_sbom_artifact_outside_scope",
                    format!(
                        "source-closure SBOM artifact {} is outside its evidence-distribution scope {}",
                        binding.artifact_id, binding.scope_id
                    ),
                ));
            }
        }
        for binding in &self.build_attestations {
            if !binding_ids.insert(binding.binding_id.as_str()) {
                return Err(error(
                    "evidence_binding_id_duplicate",
                    format!("duplicate evidence binding id {}", binding.binding_id),
                ));
            }
            let scope = require_scope(scopes, &binding.scope_id, "build attestation")?;
            if scope.target_triple.as_deref() != Some(binding.target_triple.as_str()) {
                return Err(error(
                    "build_attestation_target_mismatch",
                    format!(
                        "build attestation {} target does not match scope {}",
                        binding.binding_id, binding.scope_id
                    ),
                ));
            }
            for artifact_id in &binding.describes_artifact_ids {
                let described =
                    require_artifact(artifacts, artifact_id, "build attestation describes")?;
                if !scope.artifact_ids.contains(artifact_id)
                    && described.role != ArtifactRole::CoveredSourceArchive
                {
                    return Err(error(
                        "build_attestation_described_artifact_outside_scope",
                        format!(
                            "build attestation {} describes artifact outside scope {}",
                            binding.binding_id, binding.scope_id
                        ),
                    ));
                }
            }
            let artifact = require_artifact(artifacts, &binding.artifact_id, "build attestation")?;
            require_binding_artifact_match(
                &binding.file,
                artifact,
                ArtifactRole::BuildAttestation,
                "build attestation",
            )?;
            if !scope.artifact_ids.contains(&binding.artifact_id) {
                return Err(error(
                    "build_attestation_outside_scope",
                    format!(
                        "build attestation artifact {} is outside scope {}",
                        binding.artifact_id, binding.scope_id
                    ),
                ));
            }
        }
        for binding in &self.supplemental_license_evidence {
            if !binding_ids.insert(binding.binding_id.as_str()) {
                return Err(error(
                    "evidence_binding_id_duplicate",
                    format!("duplicate evidence binding id {}", binding.binding_id),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    AutolispLspExecutable,
    BuildAttestation,
    CoveredSourceArchive,
    McpServerExecutable,
    Mcpb,
    SourceClosureSbom,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerLocation {
    container_artifact_id: String,
    container_path: String,
}

impl ContainerLocation {
    pub fn container_artifact_id(&self) -> &str {
        &self.container_artifact_id
    }

    pub fn container_path(&self) -> &str {
        &self.container_path
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    artifact_id: String,
    role: ArtifactRole,
    logical_name: String,
    sha256: String,
    size_bytes: u64,
    container: Option<ContainerLocation>,
}

impl Artifact {
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    pub fn role(&self) -> ArtifactRole {
        self.role
    }

    pub fn logical_name(&self) -> &str {
        &self.logical_name
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn container(&self) -> Option<&ContainerLocation> {
        self.container.as_ref()
    }

    fn validate(&self, artifacts: &BTreeMap<&str, &Artifact>) -> Result<(), ValidationError> {
        require_id(&self.artifact_id, "artifacts.artifact_id")?;
        require_safe_logical_path(&self.logical_name, "artifacts.logical_name")?;
        require_sha256(&self.sha256, "artifacts.sha256")?;
        if self.size_bytes == 0 {
            return Err(error(
                "artifact_empty",
                format!("artifact {} has zero size", self.artifact_id),
            ));
        }
        match &self.container {
            Some(container) => {
                if matches!(
                    self.role,
                    ArtifactRole::Mcpb | ArtifactRole::CoveredSourceArchive
                ) {
                    return Err(error(
                        "artifact_container_forbidden",
                        format!("artifact role {:?} must be detached", self.role),
                    ));
                }
                require_id(
                    &container.container_artifact_id,
                    "artifacts.container.container_artifact_id",
                )?;
                require_safe_logical_path(
                    &container.container_path,
                    "artifacts.container.container_path",
                )?;
                if container.container_artifact_id == self.artifact_id {
                    return Err(error(
                        "artifact_self_container",
                        "an artifact must not contain itself",
                    ));
                }
                let outer = require_artifact(
                    artifacts,
                    &container.container_artifact_id,
                    "artifact container",
                )?;
                if outer.role != ArtifactRole::Mcpb {
                    return Err(error(
                        "artifact_container_role_invalid",
                        "container artifact must have role mcpb",
                    ));
                }
            }
            None => {
                if matches!(
                    self.role,
                    ArtifactRole::McpServerExecutable | ArtifactRole::AutolispLspExecutable
                ) {
                    return Err(error(
                        "executable_container_required",
                        format!(
                            "executable artifact {} must identify its MCPB container",
                            self.artifact_id
                        ),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceExclusion {
    source_artifact_id: String,
    package_name: String,
    package_version: String,
    crate_relative_path: String,
    sha256: String,
    size_bytes: u64,
    reason: String,
}

impl SourceExclusion {
    pub fn source_artifact_id(&self) -> &str {
        &self.source_artifact_id
    }

    pub fn package_name(&self) -> &str {
        &self.package_name
    }

    pub fn package_version(&self) -> &str {
        &self.package_version
    }

    pub fn crate_relative_path(&self) -> &str {
        &self.crate_relative_path
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    fn identity_key(&self) -> (String, String, String) {
        (
            self.package_name.clone(),
            self.package_version.clone(),
            self.crate_relative_path.clone(),
        )
    }

    fn validate(&self, artifacts: &BTreeMap<&str, &Artifact>) -> Result<(), ValidationError> {
        require_id(
            &self.source_artifact_id,
            "source_exclusions.source_artifact_id",
        )?;
        let source_artifact =
            require_artifact(artifacts, &self.source_artifact_id, "source exclusion")?;
        if source_artifact.role != ArtifactRole::CoveredSourceArchive {
            return Err(error(
                "source_exclusion_artifact_role_invalid",
                "source exclusions must bind a covered source archive",
            ));
        }
        require_package_token(&self.package_name, "source_exclusions.package_name")?;
        require_token(
            &self.package_version,
            "source_exclusions.package_version",
            1,
            128,
        )?;
        require_safe_logical_path(
            &self.crate_relative_path,
            "source_exclusions.crate_relative_path",
        )?;
        require_sha256(&self.sha256, "source_exclusions.sha256")?;
        if self.size_bytes == 0 {
            return Err(error(
                "source_exclusion_empty",
                "source_exclusions.size_bytes must be greater than zero",
            ));
        }
        require_non_control_text(&self.reason, "source_exclusions.reason", 1, 512)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    PublicBinaryDistribution,
    PublicSourceDistribution,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionScope {
    scope_id: String,
    kind: ScopeKind,
    target_triple: Option<String>,
    artifact_ids: Vec<String>,
}

impl DistributionScope {
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    pub fn kind(&self) -> ScopeKind {
        self.kind
    }

    pub fn target_triple(&self) -> Option<&str> {
        self.target_triple.as_deref()
    }

    pub fn artifact_ids(&self) -> &[String] {
        &self.artifact_ids
    }

    fn validate(&self, artifacts: &BTreeMap<&str, &Artifact>) -> Result<(), ValidationError> {
        require_id(&self.scope_id, "distribution_scopes.scope_id")?;
        require_sorted_unique_strings(
            &self.artifact_ids,
            "distribution_scopes.artifact_ids",
            false,
        )?;
        match (self.kind, self.target_triple.as_deref()) {
            (ScopeKind::PublicSourceDistribution, None) => {}
            (
                ScopeKind::PublicSourceDistribution | ScopeKind::PublicBinaryDistribution,
                Some(target),
            ) => require_target_triple(target, "distribution_scopes.target_triple")?,
            (_, None) => {
                return Err(error(
                    "binary_scope_target_required",
                    "binary and development distribution scopes require target_triple",
                ));
            }
        }
        let mut has_expected_primary = false;
        for artifact_id in &self.artifact_ids {
            let artifact = require_artifact(artifacts, artifact_id, "distribution scope")?;
            match self.kind {
                ScopeKind::PublicSourceDistribution => {
                    if artifact.role == ArtifactRole::CoveredSourceArchive {
                        has_expected_primary = true;
                    }
                }
                ScopeKind::PublicBinaryDistribution => {
                    if artifact.role == ArtifactRole::Mcpb {
                        has_expected_primary = true;
                    }
                }
            }
        }
        if !has_expected_primary {
            return Err(error(
                "scope_primary_artifact_missing",
                format!(
                    "scope {} lacks its required primary artifact",
                    self.scope_id
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIdentity {
    name: String,
    version: String,
    source: String,
    cargo_package_sha256: String,
    spdx_id: String,
}

impl PackageIdentity {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn cargo_package_sha256(&self) -> &str {
        &self.cargo_package_sha256
    }

    pub fn spdx_id(&self) -> &str {
        &self.spdx_id
    }

    fn identity_key(&self) -> (&str, &str, &str, &str, &str) {
        (
            self.name.as_str(),
            self.version.as_str(),
            self.source.as_str(),
            self.cargo_package_sha256.as_str(),
            self.spdx_id.as_str(),
        )
    }

    fn owned_identity_key(&self) -> (String, String, String, String, String) {
        (
            self.name.clone(),
            self.version.clone(),
            self.source.clone(),
            self.cargo_package_sha256.clone(),
            self.spdx_id.clone(),
        )
    }

    fn validate(&self) -> Result<(), ValidationError> {
        require_package_token(&self.name, "packages.name")?;
        require_token(&self.version, "packages.version", 1, 128)?;
        require_non_control_text(&self.source, "packages.source", 1, 1024)?;
        require_sha256(&self.cargo_package_sha256, "packages.cargo_package_sha256")?;
        if !self.spdx_id.starts_with("SPDXRef-") {
            return Err(error(
                "package_spdx_id_invalid",
                "packages.spdx_id must begin SPDXRef-",
            ));
        }
        require_token(&self.spdx_id, "packages.spdx_id", 9, 256)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeterminationTreatment {
    ExcludedByTargetGraph,
    IncludedNormalizedHistoricalDeclaration,
    IncludedPreservedReviewedExpression,
    IncludedReviewedCompositeExpression,
    IncludedSelectedAlternative,
    IncludedSingleLicense,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Obligation {
    IdentifyModifications,
    PreserveCoveredFileLicense,
    ProvideExactSourceCodeForm,
    RetainAttribution,
    RetainLicenseText,
    RetainNotice,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NoticeDisposition {
    ExcludedWithPackage,
    RetainedInBoundNotices,
    SupplementalEvidence { evidence_binding: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceDisposition {
    ExactSourceArtifact { artifact_id: String },
    ExcludedWithPackage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetExclusion {
    source_closure_sbom_binding: String,
    dependency_condition: String,
}

impl TargetExclusion {
    pub fn source_closure_sbom_binding(&self) -> &str {
        &self.source_closure_sbom_binding
    }

    pub fn dependency_condition(&self) -> &str {
        &self.dependency_condition
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageDetermination {
    determination_id: String,
    scope_ids: Vec<String>,
    packages: Vec<PackageIdentity>,
    declared_value: String,
    reviewed_expression: String,
    treatment: DeterminationTreatment,
    distribution_basis_expression: Option<String>,
    notice_disposition: NoticeDisposition,
    source_disposition: SourceDisposition,
    provenance_source_ids: Vec<String>,
    obligations: Vec<Obligation>,
    exclusion: Option<TargetExclusion>,
}

impl PackageDetermination {
    pub fn determination_id(&self) -> &str {
        &self.determination_id
    }

    pub fn packages(&self) -> &[PackageIdentity] {
        &self.packages
    }

    pub fn scope_ids(&self) -> &[String] {
        &self.scope_ids
    }

    pub fn declared_value(&self) -> &str {
        &self.declared_value
    }

    pub fn reviewed_expression(&self) -> &str {
        &self.reviewed_expression
    }

    pub fn treatment(&self) -> DeterminationTreatment {
        self.treatment
    }

    pub fn distribution_basis_expression(&self) -> Option<&str> {
        self.distribution_basis_expression.as_deref()
    }

    pub fn notice_disposition(&self) -> &NoticeDisposition {
        &self.notice_disposition
    }

    pub fn source_disposition(&self) -> &SourceDisposition {
        &self.source_disposition
    }

    pub fn provenance_source_ids(&self) -> &[String] {
        &self.provenance_source_ids
    }

    pub fn obligations(&self) -> &[Obligation] {
        &self.obligations
    }

    pub fn exclusion(&self) -> Option<&TargetExclusion> {
        self.exclusion.as_ref()
    }

    fn validate(
        &self,
        scopes: &BTreeMap<&str, &DistributionScope>,
        artifacts: &BTreeMap<&str, &Artifact>,
        supplemental_bindings: &BTreeSet<&str>,
        source_closure_sbom_bindings: &BTreeMap<&str, &SourceClosureSbomBinding>,
    ) -> Result<(), ValidationError> {
        require_id(
            &self.determination_id,
            "package_determinations.determination_id",
        )?;
        require_sorted_unique_strings(&self.scope_ids, "package_determinations.scope_ids", false)?;
        for scope_id in &self.scope_ids {
            require_scope(scopes, scope_id, "package determination")?;
        }
        require_sorted_unique_by(
            &self.packages,
            "package_determinations.packages",
            PackageIdentity::owned_identity_key,
        )?;
        if self.packages.is_empty() {
            return Err(error(
                "determination_packages_empty",
                format!("determination {} has no packages", self.determination_id),
            ));
        }
        for package in &self.packages {
            package.validate()?;
        }
        require_non_control_text(
            &self.declared_value,
            "package_determinations.declared_value",
            1,
            1024,
        )?;
        require_expression(
            &self.reviewed_expression,
            "package_determinations.reviewed_expression",
        )?;
        require_sorted_unique_strings(
            &self.provenance_source_ids,
            "package_determinations.provenance_source_ids",
            true,
        )?;
        require_sorted_unique_ord(&self.obligations, "package_determinations.obligations")?;

        let excluded = self.treatment == DeterminationTreatment::ExcludedByTargetGraph;
        if excluded {
            if self.distribution_basis_expression.is_some()
                || !matches!(
                    self.notice_disposition,
                    NoticeDisposition::ExcludedWithPackage
                )
                || !matches!(
                    self.source_disposition,
                    SourceDisposition::ExcludedWithPackage
                )
                || !self.provenance_source_ids.is_empty()
                || !self.obligations.is_empty()
            {
                return Err(error(
                    "excluded_determination_shape_invalid",
                    "excluded packages require null basis, excluded notice/source dispositions, no provenance source IDs, and no obligations",
                ));
            }
            let exclusion = self.exclusion.as_ref().ok_or_else(|| {
                error(
                    "target_exclusion_required",
                    "excluded_by_target_graph requires exclusion evidence",
                )
            })?;
            require_id(
                &exclusion.source_closure_sbom_binding,
                "package_determinations.exclusion.source_closure_sbom_binding",
            )?;
            let source_closure_binding = source_closure_sbom_bindings
                .get(exclusion.source_closure_sbom_binding.as_str())
                .copied()
                .ok_or_else(|| {
                    error(
                        "target_exclusion_source_closure_sbom_unknown",
                        format!(
                            "unknown source-closure SBOM binding {}",
                            exclusion.source_closure_sbom_binding
                        ),
                    )
                })?;
            if !self.scope_ids.contains(&source_closure_binding.scope_id)
                || self.scope_ids.iter().any(|scope_id| {
                    scopes.get(scope_id.as_str()).is_none_or(|scope| {
                        scope.target_triple.as_deref()
                            != Some(source_closure_binding.target_triple.as_str())
                    })
                })
            {
                return Err(error(
                    "target_exclusion_scope_mismatch",
                    format!(
                        "excluded determination must include source-closure SBOM evidence scope {} and may cover only scopes for target {}",
                        source_closure_binding.scope_id
                        , source_closure_binding.target_triple
                    ),
                ));
            }
            require_non_control_text(
                &exclusion.dependency_condition,
                "package_determinations.exclusion.dependency_condition",
                1,
                1024,
            )?;
        } else {
            if self.exclusion.is_some() {
                return Err(error(
                    "included_determination_exclusion_forbidden",
                    "included packages must not contain exclusion evidence",
                ));
            }
            let basis = self
                .distribution_basis_expression
                .as_deref()
                .ok_or_else(|| {
                    error(
                        "distribution_basis_required",
                        "included packages require distribution_basis_expression",
                    )
                })?;
            require_expression(
                basis,
                "package_determinations.distribution_basis_expression",
            )?;
            if matches!(
                self.notice_disposition,
                NoticeDisposition::ExcludedWithPackage
            ) || matches!(
                self.source_disposition,
                SourceDisposition::ExcludedWithPackage
            ) {
                return Err(error(
                    "included_disposition_invalid",
                    "included packages must retain notices and bind the exact companion source artifact",
                ));
            }
            for required in [
                Obligation::ProvideExactSourceCodeForm,
                Obligation::RetainAttribution,
                Obligation::RetainLicenseText,
                Obligation::RetainNotice,
            ] {
                if !self.obligations.contains(&required) {
                    return Err(error(
                        "included_obligations_incomplete",
                        format!(
                            "included determination {} lacks required obligation {required:?}",
                            self.determination_id
                        ),
                    ));
                }
            }
            if self.treatment == DeterminationTreatment::IncludedSingleLicense
                && (self.reviewed_expression != basis
                    || contains_spdx_boolean_operator(&self.reviewed_expression))
            {
                return Err(error(
                    "single_license_basis_invalid",
                    "included_single_license requires identical, non-choice reviewed and basis expressions",
                ));
            }
            if self.treatment == DeterminationTreatment::IncludedPreservedReviewedExpression
                && self.reviewed_expression != basis
            {
                return Err(error(
                    "preserved_expression_basis_mismatch",
                    "included_preserved_reviewed_expression requires basis to equal reviewed expression",
                ));
            }
            if self.treatment == DeterminationTreatment::IncludedReviewedCompositeExpression
                && (self.reviewed_expression == self.declared_value
                    || self.reviewed_expression != basis
                    || !contains_spdx_operator(&self.reviewed_expression, "AND"))
            {
                return Err(error(
                    "reviewed_composite_expression_invalid",
                    "included_reviewed_composite_expression requires a reviewed AND expression that differs from the declared value and exactly equals the distribution basis",
                ));
            }
            if self.treatment == DeterminationTreatment::IncludedSelectedAlternative
                && !basis_is_reviewed_selection(&self.reviewed_expression, basis)?
            {
                return Err(error(
                    "selected_alternative_basis_invalid",
                    "included_selected_alternative requires the basis to select one branch from every reviewed OR while preserving every AND component",
                ));
            }
            if self.treatment == DeterminationTreatment::IncludedNormalizedHistoricalDeclaration
                && (!self.declared_value.contains('/')
                    || self.reviewed_expression.contains('/')
                    || !contains_spdx_operator(&self.reviewed_expression, "OR")
                    || !basis_is_reviewed_selection(&self.reviewed_expression, basis)?)
            {
                return Err(error(
                    "historical_normalization_invalid",
                    "historical normalization requires a slash-form raw value, a non-slash reviewed OR expression, and a basis selected from that expression",
                ));
            }
            if let NoticeDisposition::SupplementalEvidence { evidence_binding } =
                &self.notice_disposition
            {
                require_id(
                    evidence_binding,
                    "package_determinations.notice_disposition.evidence_binding",
                )?;
                if !supplemental_bindings.contains(evidence_binding.as_str()) {
                    return Err(error(
                        "supplemental_evidence_unknown",
                        format!("unknown supplemental evidence binding {evidence_binding}"),
                    ));
                }
            }
            if let SourceDisposition::ExactSourceArtifact { artifact_id } = &self.source_disposition
            {
                let artifact =
                    require_artifact(artifacts, artifact_id, "exact source disposition")?;
                if artifact.role != ArtifactRole::CoveredSourceArchive {
                    return Err(error(
                        "source_artifact_role_invalid",
                        format!(
                            "source disposition artifact {artifact_id} is not a covered source archive"
                        ),
                    ));
                }
                if !scopes.values().any(|scope| {
                    scope.kind == ScopeKind::PublicSourceDistribution
                        && scope.artifact_ids.contains(artifact_id)
                }) {
                    return Err(error(
                        "source_artifact_outside_source_scope",
                        format!(
                            "source disposition artifact {artifact_id} is not the primary artifact of a public source scope"
                        ),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationCondition {
    ApprovalContractSchemaChanged,
    ArtifactBytesOrArtifactSetChanged,
    BuildRecipeOrToolchainChanged,
    CargoLockOrDependencyInputClosureChanged,
    DistributionChannelOrTargetChanged,
    PackageDeterminationChanged,
    ProjectLicenseChanged,
    SourceLockSbomChanged,
    SourceBundleChanged,
    SourceClosureSbomChanged,
    ThirdPartyNoticeOrSupplementalEvidenceChanged,
}

pub fn parse_and_validate(bytes: &[u8]) -> Result<OwnerDistributionApproval, ValidationError> {
    let strict = parse_strict_json(bytes).map_err(|parse_error| {
        let code = if parse_error.code() == release_qualification::ErrorCode::JsonTrailingData {
            "approval_json_trailing_data"
        } else {
            "approval_json_invalid"
        };
        error(code, format!("strict JSON parse failed: {parse_error}"))
    })?;
    let approval: OwnerDistributionApproval =
        serde_json::from_value(strict).map_err(|parse_error| {
            error(
                "approval_schema_invalid",
                format!("approval does not match the closed schema: {parse_error}"),
            )
        })?;
    approval.validate()?;
    Ok(approval)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn require_safe_logical_path(value: &str, label: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.contains('\0')
        || value.as_bytes().get(1) == Some(&b':')
    {
        return Err(error(
            "logical_path_unsafe",
            format!("{label} is not a safe relative logical path"),
        ));
    }
    for component in value.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.len() > 255
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(error(
                "logical_path_unsafe",
                format!("{label} contains an unsafe path component"),
            ));
        }
    }
    Ok(())
}

fn error(code: &'static str, detail: impl Into<String>) -> ValidationError {
    ValidationError::new(code, detail)
}

fn require_binding_artifact_match(
    binding: &FileBinding,
    artifact: &Artifact,
    expected_role: ArtifactRole,
    label: &str,
) -> Result<(), ValidationError> {
    if artifact.role != expected_role
        || artifact.logical_name != binding.logical_path
        || artifact.sha256 != binding.sha256
        || artifact.size_bytes != binding.size_bytes
    {
        return Err(error(
            "evidence_artifact_binding_mismatch",
            format!("{label} file binding does not exactly match its artifact"),
        ));
    }
    Ok(())
}

fn require_artifact<'a>(
    artifacts: &'a BTreeMap<&str, &Artifact>,
    artifact_id: &str,
    label: &str,
) -> Result<&'a Artifact, ValidationError> {
    artifacts.get(artifact_id).copied().ok_or_else(|| {
        error(
            "artifact_reference_unknown",
            format!("{label} references unknown artifact {artifact_id}"),
        )
    })
}

fn require_single_artifact_role(
    artifacts: &[Artifact],
    role: ArtifactRole,
) -> Result<&Artifact, ValidationError> {
    let mut matches = artifacts.iter().filter(|artifact| artifact.role == role);
    let artifact = matches.next().ok_or_else(|| {
        error(
            "initial_windows_artifact_role_cardinality_invalid",
            format!("initial_windows_public lacks its {role:?} artifact"),
        )
    })?;
    if matches.next().is_some() {
        return Err(error(
            "initial_windows_artifact_role_cardinality_invalid",
            format!("initial_windows_public contains multiple {role:?} artifacts"),
        ));
    }
    Ok(artifact)
}

fn require_scope<'a>(
    scopes: &'a BTreeMap<&str, &DistributionScope>,
    scope_id: &str,
    label: &str,
) -> Result<&'a DistributionScope, ValidationError> {
    scopes.get(scope_id).copied().ok_or_else(|| {
        error(
            "scope_reference_unknown",
            format!("{label} references unknown scope {scope_id}"),
        )
    })
}

fn require_sha256(value: &str, label: &str) -> Result<(), ValidationError> {
    require_lower_hex(value, 64, label)
}

fn require_lower_hex(value: &str, length: usize, label: &str) -> Result<(), ValidationError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(error(
            "lowercase_hex_invalid",
            format!("{label} must be exactly {length} lowercase hexadecimal digits"),
        ));
    }
    Ok(())
}

fn require_public_identifier(value: &str, label: &str) -> Result<(), ValidationError> {
    require_non_control_text(value, label, 1, 64)?;
    if value.contains('@')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'.' | b'_' | b'-'))
    {
        return Err(error(
            "public_identifier_invalid",
            format!("{label} must be a public non-email identifier"),
        ));
    }
    Ok(())
}

fn require_decision_id(value: &str, label: &str) -> Result<(), ValidationError> {
    if !(3..=64).contains(&value.len())
        || !value.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(error(
            "decision_id_invalid",
            format!("{label} must use 3-64 uppercase identifier characters"),
        ));
    }
    Ok(())
}

fn require_id(value: &str, label: &str) -> Result<(), ValidationError> {
    if !(1..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(error(
            "identifier_invalid",
            format!("{label} must use 1-128 safe identifier characters"),
        ));
    }
    Ok(())
}

fn require_target_triple(value: &str, label: &str) -> Result<(), ValidationError> {
    require_id(value, label)?;
    if !value.contains('-') {
        return Err(error(
            "target_triple_invalid",
            format!("{label} must contain a target-triple separator"),
        ));
    }
    Ok(())
}

fn require_package_token(value: &str, label: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(error(
            "package_name_invalid",
            format!("{label} contains invalid package-name characters"),
        ));
    }
    Ok(())
}

fn require_token(
    value: &str,
    label: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), ValidationError> {
    require_non_control_text(value, label, minimum, maximum)?;
    if value.trim() != value {
        return Err(error(
            "token_whitespace_invalid",
            format!("{label} must not have leading or trailing whitespace"),
        ));
    }
    Ok(())
}

fn require_non_control_text(
    value: &str,
    label: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), ValidationError> {
    if !(minimum..=maximum).contains(&value.len())
        || value.chars().any(char::is_control)
        || value.contains('\0')
    {
        return Err(error(
            "text_value_invalid",
            format!("{label} has invalid length or control characters"),
        ));
    }
    Ok(())
}

fn require_expression(value: &str, label: &str) -> Result<(), ValidationError> {
    require_token(value, label, 1, 1024)?;
    if value.contains('/') {
        return Err(error(
            "reviewed_expression_slash_invalid",
            format!("{label} must not use historical slash syntax"),
        ));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b' ' | b'.' | b'+' | b'-' | b'(' | b')' | b':' | b'_')
    }) {
        return Err(error(
            "expression_character_invalid",
            format!("{label} contains unsupported expression characters"),
        ));
    }
    Ok(())
}

fn contains_spdx_boolean_operator(value: &str) -> bool {
    value.split_ascii_whitespace().any(|token| {
        matches!(
            token.trim_matches(|character| matches!(character, '(' | ')')),
            "AND" | "OR" | "WITH"
        )
    })
}

fn contains_spdx_operator(value: &str, expected: &str) -> bool {
    value
        .split_ascii_whitespace()
        .map(|token| token.trim_matches(|character| matches!(character, '(' | ')')))
        .any(|token| token == expected)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SpdxExpression {
    Atom(String),
    With(Box<SpdxExpression>, String),
    And(Vec<SpdxExpression>),
    Or(Vec<SpdxExpression>),
}

fn basis_is_reviewed_selection(reviewed: &str, basis: &str) -> Result<bool, ValidationError> {
    let reviewed = parse_spdx_expression(reviewed)?;
    let basis = parse_spdx_expression(basis)?;
    if !spdx_expression_contains_or(&reviewed) || spdx_expression_contains_or(&basis) {
        return Ok(false);
    }
    Ok(spdx_expression_resolutions(&reviewed).contains(&normalize_spdx_expression(basis)))
}

fn parse_spdx_expression(value: &str) -> Result<SpdxExpression, ValidationError> {
    let tokens = spdx_tokens(value)?;
    let mut parser = SpdxExpressionParser {
        tokens: &tokens,
        position: 0,
    };
    let expression = parser.parse_or()?;
    if parser.position != tokens.len() {
        return Err(error(
            "spdx_expression_invalid",
            "SPDX expression contains trailing or misplaced tokens",
        ));
    }
    Ok(normalize_spdx_expression(expression))
}

fn spdx_tokens(value: &str) -> Result<Vec<String>, ValidationError> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for character in value.chars() {
        match character {
            '(' | ')' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                tokens.push(character.to_string());
            }
            character if character.is_ascii_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(character),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    if tokens.is_empty() {
        return Err(error(
            "spdx_expression_invalid",
            "SPDX expression must not be empty",
        ));
    }
    Ok(tokens)
}

struct SpdxExpressionParser<'a> {
    tokens: &'a [String],
    position: usize,
}

impl SpdxExpressionParser<'_> {
    fn parse_or(&mut self) -> Result<SpdxExpression, ValidationError> {
        let mut branches = vec![self.parse_and()?];
        while self.peek() == Some("OR") {
            self.position += 1;
            branches.push(self.parse_and()?);
        }
        Ok(if branches.len() == 1 {
            branches.pop().expect("one branch")
        } else {
            SpdxExpression::Or(branches)
        })
    }

    fn parse_and(&mut self) -> Result<SpdxExpression, ValidationError> {
        let mut components = vec![self.parse_with()?];
        while self.peek() == Some("AND") {
            self.position += 1;
            components.push(self.parse_with()?);
        }
        Ok(if components.len() == 1 {
            components.pop().expect("one component")
        } else {
            SpdxExpression::And(components)
        })
    }

    fn parse_with(&mut self) -> Result<SpdxExpression, ValidationError> {
        let primary = self.parse_primary()?;
        if self.peek() != Some("WITH") {
            return Ok(primary);
        }
        if !matches!(primary, SpdxExpression::Atom(_)) {
            return Err(error(
                "spdx_expression_invalid",
                "WITH must apply directly to one licence identifier",
            ));
        }
        self.position += 1;
        let exception = self.next_identifier("WITH requires an exception identifier")?;
        Ok(SpdxExpression::With(Box::new(primary), exception))
    }

    fn parse_primary(&mut self) -> Result<SpdxExpression, ValidationError> {
        if self.peek() == Some("(") {
            self.position += 1;
            let expression = self.parse_or()?;
            if self.peek() != Some(")") {
                return Err(error(
                    "spdx_expression_invalid",
                    "SPDX expression has unbalanced parentheses",
                ));
            }
            self.position += 1;
            return Ok(expression);
        }
        let identifier = self.next_identifier("SPDX expression requires a licence identifier")?;
        Ok(SpdxExpression::Atom(identifier))
    }

    fn next_identifier(&mut self, detail: &'static str) -> Result<String, ValidationError> {
        let token = self
            .tokens
            .get(self.position)
            .ok_or_else(|| error("spdx_expression_invalid", detail))?;
        if matches!(token.as_str(), "(" | ")" | "AND" | "OR" | "WITH") {
            return Err(error("spdx_expression_invalid", detail));
        }
        self.position += 1;
        Ok(token.clone())
    }

    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.position).map(String::as_str)
    }
}

fn normalize_spdx_expression(expression: SpdxExpression) -> SpdxExpression {
    match expression {
        SpdxExpression::And(components) => {
            let mut normalized = Vec::new();
            for component in components {
                match normalize_spdx_expression(component) {
                    SpdxExpression::And(nested) => normalized.extend(nested),
                    component => normalized.push(component),
                }
            }
            normalized.sort();
            if normalized.len() == 1 {
                normalized.pop().expect("one normalized component")
            } else {
                SpdxExpression::And(normalized)
            }
        }
        SpdxExpression::Or(branches) => {
            let mut normalized = Vec::new();
            for branch in branches {
                match normalize_spdx_expression(branch) {
                    SpdxExpression::Or(nested) => normalized.extend(nested),
                    branch => normalized.push(branch),
                }
            }
            normalized.sort();
            if normalized.len() == 1 {
                normalized.pop().expect("one normalized branch")
            } else {
                SpdxExpression::Or(normalized)
            }
        }
        SpdxExpression::With(licence, exception) => {
            SpdxExpression::With(Box::new(normalize_spdx_expression(*licence)), exception)
        }
        atom => atom,
    }
}

fn spdx_expression_contains_or(expression: &SpdxExpression) -> bool {
    match expression {
        SpdxExpression::Or(_) => true,
        SpdxExpression::And(components) => components.iter().any(spdx_expression_contains_or),
        SpdxExpression::With(licence, _) => spdx_expression_contains_or(licence),
        SpdxExpression::Atom(_) => false,
    }
}

fn spdx_expression_resolutions(expression: &SpdxExpression) -> BTreeSet<SpdxExpression> {
    match expression {
        SpdxExpression::Atom(_) | SpdxExpression::With(_, _) => {
            BTreeSet::from([expression.clone()])
        }
        SpdxExpression::Or(branches) => branches
            .iter()
            .flat_map(spdx_expression_resolutions)
            .collect(),
        SpdxExpression::And(components) => {
            let mut combinations = vec![Vec::new()];
            for component in components {
                let choices = spdx_expression_resolutions(component);
                let mut next = Vec::new();
                for combination in &combinations {
                    for choice in &choices {
                        let mut selected = combination.clone();
                        match choice {
                            SpdxExpression::And(nested) => selected.extend(nested.clone()),
                            choice => selected.push(choice.clone()),
                        }
                        next.push(selected);
                    }
                }
                combinations = next;
            }
            combinations
                .into_iter()
                .map(|components| normalize_spdx_expression(SpdxExpression::And(components)))
                .collect()
        }
    }
}

fn require_sorted_unique_strings(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), ValidationError> {
    if !allow_empty && values.is_empty() {
        return Err(error(
            "sorted_array_empty",
            format!("{label} must not be empty"),
        ));
    }
    for value in values {
        require_id(value, label)?;
    }
    require_sorted_unique_ord(values, label)
}

fn valid_profile_version(version: &str, mode: DistributionMode) -> bool {
    let components = version.split('.').collect::<Vec<_>>();
    if components.len() != 3
        || components.iter().any(|component| {
            component.is_empty()
                || !component.bytes().all(|byte| byte.is_ascii_digit())
                || (component.len() > 1 && component.starts_with('0'))
        })
    {
        return false;
    }
    let Ok(major) = components[0].parse::<u64>() else {
        return false;
    };
    match mode {
        DistributionMode::Release => major >= 1,
        DistributionMode::Preview => major == 0,
    }
}

fn require_sorted_unique_ord<T: Ord>(values: &[T], label: &str) -> Result<(), ValidationError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(error(
            "array_not_sorted_unique",
            format!("{label} must be strictly sorted and unique"),
        ));
    }
    Ok(())
}

fn require_sorted_unique_by<T, K: Ord>(
    values: &[T],
    label: &str,
    key: impl Fn(&T) -> K,
) -> Result<(), ValidationError> {
    if values.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return Err(error(
            "array_not_sorted_unique",
            format!("{label} must be strictly sorted and unique"),
        ));
    }
    Ok(())
}

fn require_utc_timestamp(value: &str, label: &str) -> Result<(), ValidationError> {
    let bytes = value.as_bytes();
    let shape = bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        });
    if !shape {
        return Err(error(
            "utc_timestamp_invalid",
            format!("{label} must use YYYY-MM-DDTHH:MM:SSZ"),
        ));
    }
    let number = |range: std::ops::Range<usize>| -> u32 {
        value[range]
            .parse()
            .expect("timestamp digit shape checked above")
    };
    let year = number(0..4);
    let month = number(5..7);
    let day = number(8..10);
    let hour = number(11..13);
    let minute = number(14..16);
    let second = number(17..19);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > max_day || hour > 23 || minute > 59 || second > 59 {
        return Err(error(
            "utc_timestamp_invalid",
            format!("{label} is not a valid UTC calendar timestamp"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hash(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn file(path: &str, character: char) -> Value {
        json!({
            "logical_path": path,
            "sha256": hash(character),
            "size_bytes": 1
        })
    }

    struct OwnedDistributionEvidence {
        policy: Vec<u8>,
        source_sbom: Vec<u8>,
        windows_source_closure_sbom: Vec<u8>,
        notices: Vec<u8>,
        provenance: Vec<u8>,
        project_license: Vec<u8>,
        schema: Vec<u8>,
        attestation: Vec<u8>,
        supplement: Vec<u8>,
    }

    fn bind_file(slot: &mut Value, bytes: &[u8]) {
        slot["sha256"] = json!(sha256_hex(bytes));
        slot["size_bytes"] = json!(bytes.len());
    }

    fn test_registry_packages() -> Vec<Value> {
        [
            ("acadrust", "0.4.1", 'a'),
            ("flate2", "1.1.9", 'b'),
            ("rmcp", "1.7.0", 'c'),
        ]
        .into_iter()
        .map(|(name, version, checksum)| {
            json!({
                "SPDXID": format!("SPDXRef-Package-{name}"),
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "checksums": [{
                    "algorithm": "SHA256",
                    "checksumValue": hash(checksum)
                }],
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "MPL-2.0",
                "licenseComments": "Cargo manifest licence metadata: MPL-2.0. The Cargo value is emitted as SPDX licenseDeclared. Test evidence.",
                "copyrightText": "NOASSERTION",
                "sourceInfo": "Resolved by Cargo.lock from registry+https://github.com/rust-lang/crates.io-index; SHA-256 checksum is the Cargo.lock package checksum."
            })
        })
        .collect()
    }

    fn test_spdx_document(name: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": name,
            "packages": test_registry_packages()
        }))
        .unwrap()
    }

    fn test_windows_source_closure_spdx_document(
        cargo_lock_sha256: &str,
        input_closure_sha256: &str,
    ) -> Vec<u8> {
        let mut packages = vec![
            json!({
                "SPDXID": "SPDXRef-Package-autocad-mcp",
                "name": "autocad-mcp",
                "versionInfo": "0.0.1",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "GPL-3.0-or-later",
                "licenseComments": "Cargo manifest licence metadata: GPL-3.0-or-later. The Cargo value is emitted as SPDX licenseDeclared. Test evidence.",
                "copyrightText": "NOASSERTION",
                "sourceInfo": "AutoCAD-MCP workspace package."
            }),
            json!({
                "SPDXID": "SPDXRef-Package-autolisp-lsp",
                "name": "autolisp-lsp",
                "versionInfo": "0.1.0",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "GPL-3.0-or-later",
                "licenseComments": "Cargo manifest licence metadata: GPL-3.0-or-later. The Cargo value is emitted as SPDX licenseDeclared. Test evidence.",
                "copyrightText": "NOASSERTION",
                "sourceInfo": "AutoCAD-MCP workspace package."
            }),
        ];
        packages.extend(test_registry_packages());
        let comment = format!(
            "Generated deterministically from Cargo.lock and two exact commands: `cargo metadata --locked --offline --format-version 1 --filter-platform {INITIAL_WINDOWS_TARGET} --no-default-features` for Release, and `cargo metadata --locked --offline --format-version 1 --filter-platform {INITIAL_WINDOWS_TARGET} --no-default-features --features autocad-mcp/preview` for Preview. Generation requires the selected normal/build package and dependency-edge closures of the autocad-mcp and autolisp-lsp product roots to be identical across both modes, excluding development-only edges; any divergence fails closed pending separately reviewed mode-specific evidence. Cargo.lock SHA-256: {cargo_lock_sha256}. This is conservative target build-source evidence, including build scripts and proc macros; it is not a linked-binary or native-object SBOM and does not assert legal approval. Exact executable hashes and native imports require a separate build attestation."
        );
        serde_json::to_vec(&json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "AutoCAD-MCP Windows x64 product build-source closure",
            "documentNamespace": format!(
                "https://andagni.invalid/spdx/autocad-mcp/windows-x64-source-build-closure-{input_closure_sha256}"
            ),
            "creationInfo": {
                "comment": comment
            },
            "documentDescribes": [
                "SPDXRef-Package-autocad-mcp",
                "SPDXRef-Package-autolisp-lsp"
            ],
            "packages": packages
        }))
        .unwrap()
    }

    fn bind_test_distribution_evidence(value: &mut Value) -> OwnedDistributionEvidence {
        let cargo_lock_sha256 = hash('d');
        let input_closure_sha256 = hash('e');
        let source_sbom = test_spdx_document("source");
        let windows_source_closure_sbom =
            test_windows_source_closure_spdx_document(&cargo_lock_sha256, &input_closure_sha256);
        let notices = b"test third-party notices\n".to_vec();
        let project_license = b"test project GPL text\n".to_vec();
        let schema = b"{\"test\":\"approval schema\"}\n".to_vec();
        let attestation = b"{\"test\":\"build attestation\"}\n".to_vec();
        let supplement = b"test RMCP combined licence\n".to_vec();
        let provenance = serde_json::to_vec(&json!({
            "sources": [{
                "id": "rmcp-rust-sdk-license-3529c367",
                "tracked_path": "plugin/.third-party/license-supplements/rmcp-1.7.0-LICENSE.txt",
                "byte_length": supplement.len(),
                "sha256": sha256_hex(&supplement)
            }],
            "package_bindings": [{
                "package": {
                    "name": "rmcp",
                    "version": "1.7.0",
                    "archive_sha256": hash('c'),
                    "declared_license": "MPL-2.0"
                },
                "source_id": "rmcp-rust-sdk-license-3529c367"
            }]
        }))
        .unwrap();
        let policy = serde_json::to_vec(&json!({
            "reviewed_cargo_lock_sha256": cargo_lock_sha256,
            "reviewed_input_closure_sha256": input_closure_sha256,
            "expected_sbom_sha256": sha256_hex(&source_sbom),
            "expected_windows_source_closure_sbom_sha256": sha256_hex(&windows_source_closure_sbom),
            "expected_notices_sha256": sha256_hex(&notices),
            "expected_license_provenance_sha256": sha256_hex(&provenance),
            "expected_total_packages": 3,
            "expected_third_party_packages": 3,
            "expected_windows_source_closure_packages": 5,
            "expected_windows_source_closure_third_party_packages": 3,
            "allowed_registry_sources": [
                "registry+https://github.com/rust-lang/crates.io-index"
            ],
            "owner_distribution_approval": {
                "mode": "detached_per_distribution_set",
                "contract_schema_version": APPROVAL_SCHEMA_VERSION,
                "contract_schema_path": "crates/distribution/approval/schemas/owner-distribution-approval.schema.json",
                "contract_schema_sha256": sha256_hex(&schema)
                ,
                "required_for": [
                    "public_binary_distribution",
                    "public_source_distribution"
                ]
            }
        }))
        .unwrap();

        value["source_identity"]["cargo_lock_sha256"] = json!(cargo_lock_sha256);
        value["source_identity"]["dependency_input_closure_sha256"] = json!(input_closure_sha256);
        bind_file(
            &mut value["evidence_bindings"]["third_party_license_policy"],
            &policy,
        );
        bind_file(
            &mut value["evidence_bindings"]["source_lock_sbom"],
            &source_sbom,
        );
        bind_file(
            &mut value["evidence_bindings"]["third_party_notices"],
            &notices,
        );
        bind_file(
            &mut value["evidence_bindings"]["third_party_license_provenance"],
            &provenance,
        );
        bind_file(
            &mut value["evidence_bindings"]["project_license"],
            &project_license,
        );
        bind_file(
            &mut value["evidence_bindings"]["approval_contract_schema"],
            &schema,
        );
        bind_file(
            &mut value["evidence_bindings"]["source_closure_sboms"][0]["file"],
            &windows_source_closure_sbom,
        );
        bind_file(
            &mut value["evidence_bindings"]["build_attestations"][0]["file"],
            &attestation,
        );
        bind_file(
            &mut value["evidence_bindings"]["supplemental_license_evidence"][0]["file"],
            &supplement,
        );
        bind_file(&mut value["artifacts"][1], &attestation);
        bind_file(&mut value["artifacts"][5], &windows_source_closure_sbom);

        value["package_determinations"][0]["packages"] = json!([
            {
                "name": "acadrust",
                "version": "0.4.1",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "cargo_package_sha256": hash('a'),
                "spdx_id": "SPDXRef-Package-acadrust"
            },
            {
                "name": "flate2",
                "version": "1.1.9",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "cargo_package_sha256": hash('b'),
                "spdx_id": "SPDXRef-Package-flate2"
            },
            {
                "name": "rmcp",
                "version": "1.7.0",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "cargo_package_sha256": hash('c'),
                "spdx_id": "SPDXRef-Package-rmcp"
            }
        ]);
        value["package_determinations"][0]["provenance_source_ids"] =
            json!(["rmcp-rust-sdk-license-3529c367"]);

        OwnedDistributionEvidence {
            policy,
            source_sbom,
            windows_source_closure_sbom,
            notices,
            provenance,
            project_license,
            schema,
            attestation,
            supplement,
        }
    }

    fn validate_test_distribution_evidence(
        value: &Value,
        evidence: &OwnedDistributionEvidence,
    ) -> Result<(), ValidationError> {
        let approval = parse_value(value)?;
        let supplements = [SupplementalEvidenceBytes {
            binding_id: "rmcp-rust-sdk-license-3529c367",
            bytes: &evidence.supplement,
        }];
        approval.validate_distribution_evidence(&BoundDistributionEvidence {
            third_party_license_policy: &evidence.policy,
            source_lock_sbom: &evidence.source_sbom,
            windows_source_closure_sbom: &evidence.windows_source_closure_sbom,
            third_party_notices: &evidence.notices,
            third_party_license_provenance: &evidence.provenance,
            project_license: &evidence.project_license,
            approval_contract_schema: &evidence.schema,
            build_attestation: &evidence.attestation,
            supplemental_license_evidence: &supplements,
        })
    }

    fn rebind_windows_source_closure_evidence(
        value: &mut Value,
        evidence: &mut OwnedDistributionEvidence,
        mutate: impl FnOnce(&mut Value),
    ) {
        let mut document: Value =
            serde_json::from_slice(&evidence.windows_source_closure_sbom).unwrap();
        mutate(&mut document);
        evidence.windows_source_closure_sbom = serde_json::to_vec(&document).unwrap();

        let mut policy: Value = serde_json::from_slice(&evidence.policy).unwrap();
        policy["expected_windows_source_closure_sbom_sha256"] =
            json!(sha256_hex(&evidence.windows_source_closure_sbom));
        evidence.policy = serde_json::to_vec(&policy).unwrap();

        bind_file(
            &mut value["evidence_bindings"]["source_closure_sboms"][0]["file"],
            &evidence.windows_source_closure_sbom,
        );
        bind_file(
            &mut value["artifacts"][5],
            &evidence.windows_source_closure_sbom,
        );
        bind_file(
            &mut value["evidence_bindings"]["third_party_license_policy"],
            &evidence.policy,
        );
    }

    fn valid_value() -> Value {
        json!({
            "schema_version": APPROVAL_SCHEMA_VERSION,
            "kind": "owner_distribution_approval",
            "release_profile": "initial_windows_public",
            "decision": {
                "status": "approved_for_distribution",
                "authority_kind": "project_owner",
                "authority_identifier": "andagni",
                "decision_id": "ODA-2026-0001",
                "decided_utc": "2026-07-26T12:00:00Z",
                "supersedes_decision_id": null
            },
            "project": {
                "name": "AutoCAD-MCP",
                "release_version": "1.0.0",
                "project_license_expression": "GPL-3.0-or-later"
            },
            "source_identity": {
                "git_object_format": "sha1",
                "git_commit_oid": "a".repeat(40),
                "git_tree_oid": "b".repeat(40),
                "source_bundle_manifest_sha256": hash('a'),
                "cargo_lock_sha256": hash('b'),
                "dependency_input_closure_sha256": hash('c'),
                "rust_toolchain_sha256": hash('d'),
                "build_recipe_sha256": hash('e'),
                "build_profile": "release",
                "package_mode": "release",
                "cargo_incremental": false
            },
            "evidence_bindings": {
                "third_party_license_policy": file("plugin/.third-party/third-party-license-policy.json", '1'),
                "source_lock_sbom": file("plugin/.third-party/source-lock.spdx.json", '2'),
                "third_party_notices": file("plugin/THIRD_PARTY_LICENSES.txt", '3'),
                "third_party_license_provenance": file("plugin/.third-party/third-party-license-provenance.json", '4'),
                "project_license": file("plugin/LICENSE", '5'),
                "approval_contract_schema": file("crates/distribution/approval/schemas/owner-distribution-approval.schema.json", '6'),
                "source_closure_sboms": [{
                    "binding_id": "windows-source-closure-sbom",
                    "scope_id": "windows-x64-binary",
                    "target_triple": "x86_64-pc-windows-msvc",
                    "covered_source_archive_artifact_id": "source-archive",
                    "artifact_id": "windows-source-closure-sbom",
                    "file": file("distribution-evidence/windows-x64-source-closure.spdx.json", '7')
                }],
                "build_attestations": [{
                    "binding_id": "windows-build",
                    "scope_id": "windows-x64-binary",
                    "target_triple": "x86_64-pc-windows-msvc",
                    "describes_artifact_ids": ["source-archive", "windows-lsp", "windows-server"],
                    "artifact_id": "windows-build",
                    "file": file("distribution-evidence/windows-x64-build.json", '8')
                }],
                "supplemental_license_evidence": [{
                    "binding_id": "rmcp-rust-sdk-license-3529c367",
                    "file": file("plugin/.third-party/license-supplements/rmcp-1.7.0-LICENSE.txt", 'f')
                }]
            },
            "artifacts": [
                {
                    "artifact_id": "source-archive",
                    "role": "covered_source_archive",
                    "logical_name": "autocad-mcp-windows-x64-build-source.zip",
                    "sha256": hash('9'),
                    "size_bytes": 1,
                    "container": null
                },
                {
                    "artifact_id": "windows-build",
                    "role": "build_attestation",
                    "logical_name": "distribution-evidence/windows-x64-build.json",
                    "sha256": hash('8'),
                    "size_bytes": 1,
                    "container": null
                },
                {
                    "artifact_id": "windows-lsp",
                    "role": "autolisp_lsp_executable",
                    "logical_name": "plugin/bin/autolisp-lsp.exe",
                    "sha256": hash('a'),
                    "size_bytes": 1,
                    "container": {
                        "container_artifact_id": "windows-mcpb",
                        "container_path": "plugin/bin/autolisp-lsp.exe"
                    }
                },
                {
                    "artifact_id": "windows-mcpb",
                    "role": "mcpb",
                    "logical_name": "autocad-mcp-windows-x64.mcpb",
                    "sha256": hash('b'),
                    "size_bytes": 1,
                    "container": null
                },
                {
                    "artifact_id": "windows-server",
                    "role": "mcp_server_executable",
                    "logical_name": "plugin/bin/autocad-mcp.exe",
                    "sha256": hash('c'),
                    "size_bytes": 1,
                    "container": {
                        "container_artifact_id": "windows-mcpb",
                        "container_path": "plugin/bin/autocad-mcp.exe"
                    }
                },
                {
                    "artifact_id": "windows-source-closure-sbom",
                    "role": "source_closure_sbom",
                    "logical_name": "distribution-evidence/windows-x64-source-closure.spdx.json",
                    "sha256": hash('7'),
                    "size_bytes": 1,
                    "container": null
                }
            ],
            "distribution_scopes": [
                {
                    "scope_id": "windows-x64-binary",
                    "kind": "public_binary_distribution",
                    "target_triple": "x86_64-pc-windows-msvc",
                    "artifact_ids": [
                        "windows-build",
                        "windows-lsp",
                        "windows-mcpb",
                        "windows-server",
                        "windows-source-closure-sbom"
                    ]
                },
                {
                    "scope_id": "windows-x64-source",
                    "kind": "public_source_distribution",
                    "target_triple": "x86_64-pc-windows-msvc",
                    "artifact_ids": ["source-archive"]
                }
            ],
            "source_exclusions": [
                {
                    "source_artifact_id": "source-archive",
                    "package_name": "acadrust",
                    "package_version": "0.4.1",
                    "crate_relative_path": "src/docs/OpenDesign_Specification_for_.dwg_files.pdf",
                    "sha256": "1ed2e02722862188120da606e4b6a816fa4014c96de68da2f84a2ecda09461e7",
                    "size_bytes": 2399640,
                    "reason": "excluded non-source third-party specification PDF from target source bundle"
                },
                {
                    "source_artifact_id": "source-archive",
                    "package_name": "flate2",
                    "package_version": "1.1.9",
                    "crate_relative_path": "tests/corrupt-gz-file.bin",
                    "sha256": "083dd284aa1621916a2d0f66ea048c8d3ba7a722b22d0d618722633f51e7d39c",
                    "size_bytes": 7128,
                    "reason": "excluded non-source binary corruption test fixture from target source bundle"
                }
            ],
            "package_determinations": [{
                "determination_id": "windows-acadrust",
                "scope_ids": ["windows-x64-binary", "windows-x64-source"],
                "packages": [{
                    "name": "acadrust",
                    "version": "0.4.1",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "cargo_package_sha256": hash('d'),
                    "spdx_id": "SPDXRef-Package-acadrust"
                }],
                "declared_value": "MPL-2.0",
                "reviewed_expression": "MPL-2.0",
                "treatment": "included_single_license",
                "distribution_basis_expression": "MPL-2.0",
                "notice_disposition": {
                    "kind": "retained_in_bound_notices"
                },
                "source_disposition": {
                    "kind": "exact_source_artifact",
                    "artifact_id": "source-archive"
                },
                "provenance_source_ids": [],
                "obligations": [
                    "identify_modifications",
                    "preserve_covered_file_license",
                    "provide_exact_source_code_form",
                    "retain_attribution",
                    "retain_license_text",
                    "retain_notice"
                ],
                "exclusion": null
            }],
            "invalidation_conditions": [
                "approval_contract_schema_changed",
                "artifact_bytes_or_artifact_set_changed",
                "build_recipe_or_toolchain_changed",
                "cargo_lock_or_dependency_input_closure_changed",
                "distribution_channel_or_target_changed",
                "package_determination_changed",
                "project_license_changed",
                "source_lock_sbom_changed",
                "source_bundle_changed",
                "source_closure_sbom_changed",
                "third_party_notice_or_supplemental_evidence_changed"
            ]
        })
    }

    fn valid_preview_value() -> Value {
        let mut value = valid_value();
        value["release_profile"] = json!("initial_windows_preview_public");
        value["project"]["release_version"] = json!("0.0.1");
        value["source_identity"]["package_mode"] = json!("preview");
        value["artifacts"][0]["logical_name"] =
            json!("autocad-mcp-windows-x64-preview-build-source.zip");
        value["artifacts"][1]["logical_name"] =
            json!("distribution-evidence/windows-x64-preview-build.json");
        value["artifacts"][3]["logical_name"] = json!("autocad-mcp-windows-x64-preview.mcpb");
        value["artifacts"][5]["logical_name"] =
            json!("distribution-evidence/windows-x64-preview-source-closure.spdx.json");
        value["evidence_bindings"]["source_closure_sboms"][0]["file"]["logical_path"] =
            json!("distribution-evidence/windows-x64-preview-source-closure.spdx.json");
        value["evidence_bindings"]["build_attestations"][0]["file"]["logical_path"] =
            json!("distribution-evidence/windows-x64-preview-build.json");
        value
    }

    fn parse_value(value: &Value) -> Result<OwnerDistributionApproval, ValidationError> {
        parse_and_validate(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn valid_detached_owner_approval_passes() {
        let approval = parse_value(&valid_value()).unwrap();
        assert_eq!(
            approval.decision().status(),
            DecisionStatus::ApprovedForDistribution
        );
        assert_eq!(
            approval.release_profile(),
            ReleaseProfile::InitialWindowsPublic
        );
        let source = approval.source_identity();
        assert_eq!(source.git_object_format(), GitObjectFormat::Sha1);
        assert_eq!(source.rust_toolchain_sha256(), hash('d'));
        assert_eq!(source.build_recipe_sha256(), hash('e'));
        assert_eq!(source.source_bundle_manifest_sha256(), hash('a'));
        assert_eq!(source.build_profile(), BuildProfile::Release);
        assert_eq!(source.package_mode(), DistributionMode::Release);
        assert!(!source.cargo_incremental());

        let evidence = approval.evidence_bindings();
        assert_eq!(evidence.project_license().logical_path(), "plugin/LICENSE");
        assert_eq!(
            evidence.third_party_license_provenance().logical_path(),
            "plugin/.third-party/third-party-license-provenance.json"
        );
        assert_eq!(
            evidence.approval_contract_schema().logical_path(),
            "crates/distribution/approval/schemas/owner-distribution-approval.schema.json"
        );
        assert_eq!(evidence.supplemental_license_evidence().len(), 1);
        assert_eq!(
            evidence.supplemental_license_evidence()[0].binding_id(),
            "rmcp-rust-sdk-license-3529c367"
        );
        let source_closure_sbom = &evidence.source_closure_sboms()[0];
        assert_eq!(
            source_closure_sbom.target_triple(),
            "x86_64-pc-windows-msvc"
        );
        assert_eq!(
            source_closure_sbom.covered_source_archive_artifact_id(),
            "source-archive"
        );
        assert_eq!(
            source_closure_sbom.artifact_id(),
            "windows-source-closure-sbom"
        );
        let attestation = &evidence.build_attestations()[0];
        assert_eq!(attestation.scope_id(), "windows-x64-binary");
        assert_eq!(attestation.target_triple(), "x86_64-pc-windows-msvc");
        assert_eq!(
            attestation.describes_artifact_ids(),
            ["source-archive", "windows-lsp", "windows-server"]
        );
        assert_eq!(attestation.artifact_id(), "windows-build");

        assert_eq!(approval.artifacts().len(), 6);
        let lsp = &approval.artifacts()[2];
        let container = lsp.container().unwrap();
        assert_eq!(container.container_artifact_id(), "windows-mcpb");
        assert_eq!(container.container_path(), "plugin/bin/autolisp-lsp.exe");
        assert_eq!(approval.source_exclusions().len(), 2);
        assert_eq!(
            approval.source_exclusions()[1].crate_relative_path(),
            "tests/corrupt-gz-file.bin"
        );

        assert_eq!(approval.package_determinations().len(), 1);
        let determination = &approval.package_determinations()[0];
        assert_eq!(
            determination.scope_ids(),
            ["windows-x64-binary", "windows-x64-source"]
        );
        assert_eq!(determination.declared_value(), "MPL-2.0");
        assert_eq!(determination.reviewed_expression(), "MPL-2.0");
        assert_eq!(
            determination.distribution_basis_expression(),
            Some("MPL-2.0")
        );
        assert!(matches!(
            determination.notice_disposition(),
            NoticeDisposition::RetainedInBoundNotices
        ));
        assert!(matches!(
            determination.source_disposition(),
            SourceDisposition::ExactSourceArtifact { artifact_id }
                if artifact_id == "source-archive"
        ));
        assert_eq!(
            determination.obligations(),
            [
                Obligation::IdentifyModifications,
                Obligation::PreserveCoveredFileLicense,
                Obligation::ProvideExactSourceCodeForm,
                Obligation::RetainAttribution,
                Obligation::RetainLicenseText,
                Obligation::RetainNotice
            ]
        );
        assert!(determination.exclusion().is_none());
        let package = &determination.packages()[0];
        assert_eq!(package.cargo_package_sha256(), hash('d'));
        assert_eq!(package.spdx_id(), "SPDXRef-Package-acadrust");
    }

    #[test]
    fn valid_preview_owner_approval_passes_and_cross_mode_shapes_fail() {
        let approval = parse_value(&valid_preview_value()).unwrap();
        assert_eq!(
            approval.release_profile(),
            ReleaseProfile::InitialWindowsPreviewPublic
        );
        assert_eq!(
            approval.source_identity().package_mode(),
            DistributionMode::Preview
        );
        assert_eq!(approval.project().release_version(), "0.0.1");

        let mut release_with_preview_mode = valid_value();
        release_with_preview_mode["source_identity"]["package_mode"] = json!("preview");
        assert_eq!(
            parse_value(&release_with_preview_mode).unwrap_err().code(),
            "initial_windows_package_mode_invalid"
        );

        let mut preview_with_release_name = valid_preview_value();
        preview_with_release_name["artifacts"][3]["logical_name"] =
            json!("autocad-mcp-windows-x64.mcpb");
        assert_eq!(
            parse_value(&preview_with_release_name).unwrap_err().code(),
            "initial_windows_mcpb_name_invalid"
        );

        let mut preview_with_release_version = valid_preview_value();
        preview_with_release_version["project"]["release_version"] = json!("1.0.0");
        assert_eq!(
            parse_value(&preview_with_release_version)
                .unwrap_err()
                .code(),
            "initial_windows_release_version_invalid"
        );
    }

    #[test]
    fn prior_approval_schema_version_is_rejected() {
        let mut value = valid_value();
        value["schema_version"] = json!(APPROVAL_SCHEMA_VERSION - 1);
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "schema_version_invalid"
        );
    }

    #[test]
    fn duplicate_keys_are_rejected_before_typed_parsing() {
        let bytes = br#"{"schema_version":2,"schema_version":2}"#;
        let error = parse_and_validate(bytes).unwrap_err();
        assert_eq!(error.code(), "approval_json_invalid");
        assert!(error.detail().contains("duplicate JSON key"));

        let bytes = serde_json::to_vec(&valid_value()).unwrap();
        let text = String::from_utf8(bytes).unwrap().replacen(
            "\"decision_id\":\"ODA-2026-0001\"",
            "\"decision_id\":\"ODA-2026-0001\",\"decision_id\":\"ODA-2026-0002\"",
            1,
        );
        assert_eq!(
            parse_and_validate(text.as_bytes()).unwrap_err().code(),
            "approval_json_invalid"
        );
    }

    #[test]
    fn unknown_fields_and_closed_values_are_rejected() {
        let mut value = valid_value();
        value["decision"]["unexpected"] = json!(true);
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "approval_schema_invalid"
        );

        let mut value = valid_value();
        value["decision"]["status"] = json!("draft");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "approval_schema_invalid"
        );
    }

    #[test]
    fn unsafe_paths_and_non_lowercase_hashes_are_rejected() {
        for unsafe_path in [
            "",
            "/absolute",
            "../escape",
            "a/../escape",
            "C:/windows",
            "a\\windows",
            "a//b",
        ] {
            assert!(
                require_safe_logical_path(unsafe_path, "test").is_err(),
                "{unsafe_path:?}"
            );
        }
        for safe_path in [
            "plugin/LICENSE",
            ".claude-plugin/plugin.json",
            "sources/acadrust-0.4.1.crate",
        ] {
            require_safe_logical_path(safe_path, "test").unwrap();
        }

        let mut value = valid_value();
        value["artifacts"][0]["sha256"] = json!("A".repeat(64));
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "lowercase_hex_invalid"
        );
    }

    #[test]
    fn arrays_must_be_sorted_unique_and_closed_invalidation_set_is_exact() {
        let mut value = valid_value();
        value["distribution_scopes"][0]["artifact_ids"] = json!(["windows-server", "windows-mcpb"]);
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "array_not_sorted_unique"
        );

        let mut value = valid_value();
        value["invalidation_conditions"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "invalidation_conditions_invalid"
        );
    }

    #[test]
    fn references_roles_and_scope_targets_fail_closed() {
        let mut value = valid_value();
        value["artifacts"][2]["container"]["container_artifact_id"] = json!("unknown");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "artifact_reference_unknown"
        );

        let mut value = valid_value();
        value["distribution_scopes"][0]["target_triple"] = Value::Null;
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "binary_scope_target_required"
        );

        let mut value = valid_value();
        value["evidence_bindings"]["source_closure_sboms"][0]["artifact_id"] =
            json!("windows-build");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "evidence_artifact_binding_mismatch"
        );
    }

    #[test]
    fn initial_profile_rejects_a_redundant_source_snapshot_and_unbound_source_target() {
        let mut value = valid_value();
        let source_snapshot = json!({
            "artifact_id": "source-snapshot",
            "role": "source_snapshot",
            "logical_name": "autocad-mcp-windows-x64-source.zip",
            "sha256": hash('e'),
            "size_bytes": 1,
            "container": null
        });
        value["artifacts"]
            .as_array_mut()
            .unwrap()
            .insert(1, source_snapshot);
        value["distribution_scopes"][1]["artifact_ids"] =
            json!(["source-archive", "source-snapshot"]);
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "approval_schema_invalid"
        );

        let mut value = valid_value();
        value["distribution_scopes"][1]["target_triple"] = Value::Null;
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "source_closure_sbom_archive_scope_invalid"
        );
    }

    #[test]
    fn included_and_excluded_determinations_have_disjoint_shapes() {
        let mut value = valid_value();
        value["package_determinations"][0]["distribution_basis_expression"] = Value::Null;
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "distribution_basis_required"
        );

        let mut value = valid_value();
        let determination = &mut value["package_determinations"][0];
        determination["treatment"] = json!("excluded_by_target_graph");
        determination["distribution_basis_expression"] = Value::Null;
        determination["notice_disposition"] = json!({"kind":"excluded_with_package"});
        determination["source_disposition"] = json!({"kind":"excluded_with_package"});
        determination["obligations"] = json!([]);
        determination["scope_ids"] = json!(["windows-x64-binary"]);
        determination["exclusion"] = json!({
            "source_closure_sbom_binding": "windows-source-closure-sbom",
            "dependency_condition": "cfg(target_os = \"uefi\")"
        });
        let approval = parse_value(&value).unwrap();
        let exclusion = approval.package_determinations()[0].exclusion().unwrap();
        assert_eq!(
            exclusion.source_closure_sbom_binding(),
            "windows-source-closure-sbom"
        );
        assert_eq!(
            exclusion.dependency_condition(),
            "cfg(target_os = \"uefi\")"
        );
    }

    #[test]
    fn historical_declaration_keeps_raw_slash_and_reviewed_expression_separate() {
        let mut value = valid_value();
        {
            let determination = &mut value["package_determinations"][0];
            determination["declared_value"] = json!("MIT/Apache-2.0");
            determination["reviewed_expression"] = json!("MIT OR Apache-2.0");
            determination["treatment"] = json!("included_normalized_historical_declaration");
            determination["distribution_basis_expression"] = json!("MIT");
        }
        parse_value(&value).unwrap();

        value["package_determinations"][0]["declared_value"] = json!("MIT OR Apache-2.0");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "historical_normalization_invalid"
        );

        let mut value = valid_value();
        value["package_determinations"][0]["declared_value"] = json!("MIT/Apache-2.0");
        value["package_determinations"][0]["reviewed_expression"] = json!("MIT OR Apache-2.0");
        value["package_determinations"][0]["treatment"] =
            json!("included_normalized_historical_declaration");
        value["package_determinations"][0]["distribution_basis_expression"] = json!("Zlib");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "historical_normalization_invalid"
        );
    }

    #[test]
    fn one_package_cannot_be_determined_twice_in_one_scope() {
        let mut value = valid_value();
        let duplicate = value["package_determinations"][0].clone();
        value["package_determinations"][0]["determination_id"] = json!("a-first");
        value["package_determinations"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "package_determination_overlap"
        );
    }

    #[test]
    fn initial_profile_is_explicit_and_has_closed_scope_topology() {
        let mut value = valid_value();
        value.as_object_mut().unwrap().remove("release_profile");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "approval_schema_invalid"
        );

        let mut value = valid_value();
        value["release_profile"] = json!("future_profile");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "approval_schema_invalid"
        );

        let mut value = valid_value();
        let mut extra_scope = value["distribution_scopes"][1].clone();
        extra_scope["scope_id"] = json!("windows-x64-source-copy");
        value["distribution_scopes"]
            .as_array_mut()
            .unwrap()
            .push(extra_scope);
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "initial_windows_scope_cardinality_invalid"
        );

        let mut value = valid_value();
        value["distribution_scopes"][1]["artifact_ids"] =
            json!(["source-archive", "windows-server"]);
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "initial_windows_source_scope_membership_invalid"
        );
    }

    #[test]
    fn initial_profile_requires_exact_mcpb_containment_and_distinct_artifacts() {
        let mut value = valid_value();
        value["artifacts"][2]["container"]["container_path"] = json!("plugin/bin/renamed-lsp.exe");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "initial_windows_executable_containment_invalid"
        );

        let mut value = valid_value();
        value["artifacts"][4]["sha256"] = value["artifacts"][2]["sha256"].clone();
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "artifact_byte_identity_alias"
        );
    }

    #[test]
    fn source_closure_sbom_binding_and_build_attestation_fail_closed() {
        let mut value = valid_value();
        value["evidence_bindings"]["source_closure_sboms"][0]
            ["covered_source_archive_artifact_id"] = json!("windows-server");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "source_closure_sbom_archive_role_invalid"
        );

        let mut value = valid_value();
        value["evidence_bindings"]["build_attestations"][0]["describes_artifact_ids"] =
            json!(["windows-lsp", "windows-server"]);
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "initial_windows_build_attestation_coverage_invalid"
        );

        let mut value = valid_value();
        value["evidence_bindings"]["build_attestations"][0]["target_triple"] =
            json!("aarch64-pc-windows-msvc");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "build_attestation_target_mismatch"
        );
    }

    #[test]
    fn provenance_and_core_evidence_paths_are_mandatory_and_non_aliasing() {
        let mut value = valid_value();
        value["evidence_bindings"]
            .as_object_mut()
            .unwrap()
            .remove("third_party_license_provenance");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "approval_schema_invalid"
        );

        let mut value = valid_value();
        value["evidence_bindings"]["third_party_license_provenance"]["logical_path"] =
            json!("plugin/renamed-provenance.json");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "initial_windows_evidence_path_invalid"
        );

        let mut value = valid_value();
        value["evidence_bindings"]["third_party_license_provenance"]["sha256"] =
            value["evidence_bindings"]["third_party_notices"]["sha256"].clone();
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "evidence_byte_identity_alias"
        );
    }

    #[test]
    fn target_exclusion_is_tied_to_the_exact_source_closure_sbom_scope() {
        let mut value = valid_value();
        let determination = &mut value["package_determinations"][0];
        determination["treatment"] = json!("excluded_by_target_graph");
        determination["distribution_basis_expression"] = Value::Null;
        determination["notice_disposition"] = json!({"kind":"excluded_with_package"});
        determination["source_disposition"] = json!({"kind":"excluded_with_package"});
        determination["obligations"] = json!([]);
        determination["scope_ids"] = json!(["windows-x64-source"]);
        determination["exclusion"] = json!({
            "source_closure_sbom_binding": "windows-source-closure-sbom",
            "dependency_condition": "cfg(target_os = \"uefi\")"
        });
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "target_exclusion_scope_mismatch"
        );
    }

    #[test]
    fn reviewed_composite_expression_represents_rmcp_source_applicability() {
        let mut value = valid_value();
        let determination = &mut value["package_determinations"][0];
        determination["declared_value"] = json!("Apache-2.0");
        determination["reviewed_expression"] = json!("Apache-2.0 AND MIT AND CC-BY-4.0");
        determination["treatment"] = json!("included_reviewed_composite_expression");
        determination["distribution_basis_expression"] = json!("Apache-2.0 AND MIT AND CC-BY-4.0");
        parse_value(&value).expect("reviewed composite applicability is representable");

        value["package_determinations"][0]["distribution_basis_expression"] = json!("Apache-2.0");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "reviewed_composite_expression_invalid"
        );
    }

    #[test]
    fn selected_alternative_must_select_a_reviewed_branch_and_preserve_conjuncts() {
        let mut value = valid_value();
        value["package_determinations"][0]["reviewed_expression"] =
            json!("(Apache-2.0 OR MIT) AND BSD-3-Clause");
        value["package_determinations"][0]["treatment"] = json!("included_selected_alternative");
        value["package_determinations"][0]["distribution_basis_expression"] =
            json!("MIT AND BSD-3-Clause");
        parse_value(&value).expect("reviewed branch with preserved conjunct must pass");

        value["package_determinations"][0]["distribution_basis_expression"] = json!("MIT");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "selected_alternative_basis_invalid"
        );

        value["package_determinations"][0]["distribution_basis_expression"] =
            json!("Zlib AND BSD-3-Clause");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "selected_alternative_basis_invalid"
        );
    }

    #[test]
    fn exact_initial_profile_identity_exclusions_and_supplement_are_closed() {
        let mut value = valid_value();
        value["project"]["name"] = json!("Different-Project");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "initial_windows_project_identity_invalid"
        );

        let mut value = valid_value();
        value["artifacts"][0]["logical_name"] = json!("renamed-source.zip");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "initial_windows_source_archive_name_invalid"
        );

        let mut value = valid_value();
        value["source_exclusions"][0]["sha256"] = json!(hash('0'));
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "initial_windows_source_exclusions_invalid"
        );

        let mut value = valid_value();
        value["evidence_bindings"]["supplemental_license_evidence"][0]["binding_id"] =
            json!("renamed-supplement");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "initial_windows_supplemental_evidence_invalid"
        );
    }

    #[test]
    fn supplemental_evidence_is_a_direct_binding_not_a_release_artifact() {
        let mut value = valid_value();
        value["package_determinations"][0]["notice_disposition"] = json!({
            "kind": "supplemental_evidence",
            "evidence_binding": "rmcp-rust-sdk-license-3529c367"
        });
        let approval = parse_value(&value).unwrap();
        assert_eq!(approval.artifacts().len(), 6);
        assert_eq!(
            approval.evidence_bindings().supplemental_license_evidence()[0]
                .file()
                .logical_path(),
            "plugin/.third-party/license-supplements/rmcp-1.7.0-LICENSE.txt"
        );
    }

    #[test]
    fn exact_file_binding_verifies_size_and_digest() {
        let bytes = b"bound bytes";
        let binding = FileBinding {
            logical_path: "evidence/file.txt".to_owned(),
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        };
        binding.verify_bytes(bytes).unwrap();
        assert_eq!(
            binding.verify_bytes(b"changed").unwrap_err().code(),
            "bound_file_size_mismatch"
        );
    }

    #[test]
    fn checked_in_schema_accepts_the_rust_fixture_and_rejects_closed_value_drift() {
        let schema: Value = serde_json::from_str(include_str!(
            "../schemas/owner-distribution-approval.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(validator.is_valid(&valid_value()));
        assert!(validator.is_valid(&valid_preview_value()));

        let mut value = valid_value();
        value["project"]["project_license_expression"] = json!("MIT");
        assert!(!validator.is_valid(&value));

        let mut value = valid_value();
        value["source_exclusions"][1]["crate_relative_path"] = json!("tests/renamed.bin");
        assert!(!validator.is_valid(&value));

        let mut release_with_preview_mode = valid_value();
        release_with_preview_mode["source_identity"]["package_mode"] = json!("preview");
        assert!(!validator.is_valid(&release_with_preview_mode));

        let mut preview_with_release_mcpb = valid_preview_value();
        preview_with_release_mcpb["artifacts"][3]["logical_name"] =
            json!("autocad-mcp-windows-x64.mcpb");
        assert!(!validator.is_valid(&preview_with_release_mcpb));
    }

    #[test]
    fn distribution_evidence_reconciles_every_scope_package_and_provenance_join() {
        let mut value = valid_value();
        let evidence = bind_test_distribution_evidence(&mut value);
        validate_test_distribution_evidence(&value, &evidence).unwrap();

        let mut missing = value.clone();
        missing["package_determinations"][0]["packages"]
            .as_array_mut()
            .unwrap()
            .remove(1);
        assert_eq!(
            validate_test_distribution_evidence(&missing, &evidence)
                .unwrap_err()
                .code(),
            "determination_scope_incomplete"
        );

        let mut wrong_provenance = value.clone();
        wrong_provenance["package_determinations"][0]["provenance_source_ids"] =
            json!(["invented-source"]);
        assert_eq!(
            validate_test_distribution_evidence(&wrong_provenance, &evidence)
                .unwrap_err()
                .code(),
            "determination_provenance_mismatch"
        );

        let mut wrong_declaration = value;
        wrong_declaration["package_determinations"][0]["declared_value"] = json!("MIT");
        assert_eq!(
            validate_test_distribution_evidence(&wrong_declaration, &evidence)
                .unwrap_err()
                .code(),
            "determination_declared_value_mismatch"
        );
    }

    #[test]
    fn source_closure_sbom_cannot_claim_linked_binary_scope() {
        let mut value = valid_value();
        let mut evidence = bind_test_distribution_evidence(&mut value);
        rebind_windows_source_closure_evidence(&mut value, &mut evidence, |document| {
            document["name"] = json!("AutoCAD-MCP Windows x64 linked-binary SBOM");
        });
        assert_eq!(
            validate_test_distribution_evidence(&value, &evidence)
                .unwrap_err()
                .code(),
            "source_closure_sbom_scope_invalid"
        );
    }

    #[test]
    fn approval_parser_never_creates_or_defaults_an_approved_decision() {
        let mut value = valid_value();
        value.as_object_mut().unwrap().remove("decision");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "approval_schema_invalid"
        );
    }
}
