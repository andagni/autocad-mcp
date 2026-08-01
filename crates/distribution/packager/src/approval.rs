use crate::archive_safety::{insert_archive_path, validate_archive_path};
use crate::manifest::{
    McpbManifest, PackageMode, PackageTarget, OWNER_DISTRIBUTION_APPROVAL_SCHEMA,
};
use crate::preview_build_attestation::{
    verify_preview_build_attestation_semantics, PreviewBuildAttestationSemanticInput,
    PREVIEW_WORKFLOW_ARCHIVE_PATH,
};
use crate::smoke::{
    validate_approval_package, validate_mcpb_central_directory_open,
    validate_unbound_preview_package, MAX_EXTRACTED_BYTES, MAX_EXTRACTED_FILE_BYTES,
};
use anyhow::{anyhow, bail, Context, Result};
use distribution_approval::{
    parse_and_validate, parse_preview_clean_host_receipt, render_windows_x86_64_build_recipe,
    Artifact, ArtifactRole, BoundDistributionEvidence, BuildProfile, DistributionMode, FileBinding,
    GitObjectFormat, OwnerDistributionApproval, SourceBundleArchivePolicy as ArchivePolicyManifest,
    SourceBundleExclusion as ExclusionManifest, SourceBundleManifest,
    SourceBundlePackage as PackageManifest, SourceBundleRoot as RootManifest,
    SourceBundleVendor as VendorManifest, SupplementalEvidenceBytes, SOURCE_BUNDLE_ARTIFACT_KIND,
    SOURCE_BUNDLE_BUILD_RECIPE_PATH, SOURCE_BUNDLE_MANIFEST_PATH,
    SOURCE_BUNDLE_MANIFEST_SCHEMA_VERSION, SOURCE_BUNDLE_OFFLINE_CONFIG_PATH,
    SOURCE_BUNDLE_PROFILE, SOURCE_BUNDLE_TREE_DIGEST_METHOD,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zip::{CompressionMethod, ZipArchive};

const SOURCE_MANIFEST_PATH: &str = SOURCE_BUNDLE_MANIFEST_PATH;
const MCPB_MANIFEST_PATH: &str = "manifest.json";
const PREVIEW_MCP_SERVER_PATH: &str = "plugin/bin/autocad-mcp.exe";
const PREVIEW_AUTOLISP_LSP_PATH: &str = "plugin/bin/autolisp-lsp.exe";
const CARGO_LOCK_PATH: &str = "workspace/Cargo.lock";
const RUST_TOOLCHAIN_PATH: &str = "workspace/rust-toolchain.toml";
const BUILD_RECIPE_PATH: &str = SOURCE_BUNDLE_BUILD_RECIPE_PATH;
const OFFLINE_CONFIG_PATH: &str = SOURCE_BUNDLE_OFFLINE_CONFIG_PATH;
const PACKAGED_APPROVAL_SCHEMA_PATH: &str = "plugin/owner-distribution-approval.schema.json";
const PACKAGED_WINDOWS_SOURCE_CLOSURE_SBOM_PATH: &str =
    "plugin/.third-party/source-closure-windows.spdx.json";
const WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";
const REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const REGISTRY_SOURCE_PREFIX: &str = "Resolved by Cargo.lock from ";
const REGISTRY_SOURCE_SUFFIX: &str = "; SHA-256 checksum is the Cargo.lock package checksum.";
const WORKSPACE_SOURCE_INFO: &str = "AutoCAD-MCP workspace package.";
const TREE_DIGEST_METHOD: &str = SOURCE_BUNDLE_TREE_DIGEST_METHOD;
const TREE_DIGEST_DOMAIN: &[u8] = b"autocad-mcp-source-tree-v1\0";
const MAX_APPROVAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PREVIEW_CLEAN_HOST_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_DETACHED_EVIDENCE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_ARCHIVE_ENTRY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARCHIVE_EXPANDED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_CAPTURED_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
const EXPECTED_OFFLINE_CONFIG: &[u8] = b"[source.crates-io]\n\
replace-with = \"vendored-sources\"\n\n\
[source.vendored-sources]\n\
directory = \"../../vendor\"\n\n\
[net]\n\
offline = true\n\n\
[build]\n\
incremental = false\n";

/// Explicit finished artifacts and evidence required by the approval verifier.
#[derive(Clone, Debug)]
pub struct ApprovalVerificationOptions {
    pub approval_path: PathBuf,
    pub mcpb_path: PathBuf,
    pub source_archive_path: PathBuf,
    pub source_closure_sbom_path: PathBuf,
    pub build_attestation_path: PathBuf,
}

/// Exact owner approval, MCPB, and clean-host receipt to reconcile.
#[derive(Clone, Debug)]
pub struct PreviewCleanHostVerificationOptions {
    pub approval_path: PathBuf,
    pub mcpb_path: PathBuf,
    pub receipt_path: PathBuf,
}

/// Successful semantic joins for one accepted Preview clean-host receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewCleanHostVerificationReport {
    pub decision_id: String,
    pub receipt_sha256: String,
    pub clean_host_acceptance_verified: bool,
    pub mcpb_sha256: String,
    pub mcpb_size_bytes: u64,
    pub mcp_server_sha256: String,
    pub autolisp_lsp_sha256: String,
}

/// Exact identities captured from one closed, statically valid Preview MCPB.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewMcpbIdentity {
    pub release_version: String,
    pub mcpb_sha256: String,
    pub mcpb_size_bytes: u64,
    pub mcp_server_sha256: String,
    pub mcp_server_size_bytes: u64,
    pub autolisp_lsp_sha256: String,
    pub autolisp_lsp_size_bytes: u64,
}

/// Successful checks performed over one approval-bound distribution set.
///
/// Preview attestation semantics are verified through exact source, workflow,
/// approval, and MCPB byte joins. Release attestations retain the historical
/// opaque/false boundary until a Release-specific semantic contract exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalVerificationReport {
    pub decision_id: String,
    pub approval_sha256: String,
    pub verified_artifacts: usize,
    pub mcpb_entries: usize,
    pub source_archive_entries: usize,
    pub distribution_evidence_validated: bool,
    pub native_build_attestation_semantics_verified: bool,
    pub package_mode: DistributionMode,
    pub git_object_format: String,
    pub source_commit: String,
    pub source_tree_oid: String,
    pub mcpb_sha256: String,
    pub source_archive_sha256: String,
    pub source_closure_sbom_sha256: String,
    pub build_attestation_sha256: String,
    pub source_bundle_manifest_sha256: String,
    pub cargo_lock_sha256: String,
    pub dependency_input_closure_sha256: String,
    pub rust_toolchain_sha256: String,
    pub build_recipe_sha256: String,
}

/// Inspect one exact Preview MCPB through the same bounded archive scanner and
/// closed static package validator used by approval verification.
pub fn inspect_preview_mcpb_identity(mcpb_path: &Path) -> Result<PreviewMcpbIdentity> {
    let captures = BTreeSet::from([
        MCPB_MANIFEST_PATH.to_owned(),
        PREVIEW_MCP_SERVER_PATH.to_owned(),
        PREVIEW_AUTOLISP_LSP_PATH.to_owned(),
    ]);
    let extraction_root =
        tempfile::tempdir().context("create Preview MCPB validation directory")?;
    let (inventory, mcpb_sha256, mcpb_size_bytes) =
        scan_unbound_preview_mcpb(mcpb_path, &captures, extraction_root.path())?;

    let manifest_bytes = captured(&inventory, MCPB_MANIFEST_PATH, "Preview MCPB manifest")?;
    let manifest_value = distribution_approval::parse_strict_json(manifest_bytes)
        .context("strictly parse captured Preview MCPB manifest")?;
    let manifest: McpbManifest = serde_json::from_value(manifest_value)
        .context("validate captured Preview MCPB manifest schema")?;
    let target = validate_unbound_preview_package(extraction_root.path())
        .context("closed Preview MCPB static validation failed")?;
    if target != PackageTarget::WindowsX64 {
        bail!("Preview clean-host MCPB must target Windows x64");
    }

    let mcp_server = inventory
        .entries
        .get(PREVIEW_MCP_SERVER_PATH)
        .ok_or_else(|| anyhow!("Preview MCPB has no MCP server executable"))?;
    let autolisp_lsp = inventory
        .entries
        .get(PREVIEW_AUTOLISP_LSP_PATH)
        .ok_or_else(|| anyhow!("Preview MCPB has no AutoLISP LSP executable"))?;
    Ok(PreviewMcpbIdentity {
        release_version: manifest.version,
        mcpb_sha256,
        mcpb_size_bytes,
        mcp_server_sha256: mcp_server.sha256.clone(),
        mcp_server_size_bytes: mcp_server.size,
        autolisp_lsp_sha256: autolisp_lsp.sha256.clone(),
        autolisp_lsp_size_bytes: autolisp_lsp.size,
    })
}

/// Verify one privacy-safe Preview clean-host receipt against its owner
/// approval and the exact MCPB bytes accepted on the clean host.
///
/// This verifier intentionally remains separate from
/// [`verify_owner_distribution_approval`]. Callers that select a complete
/// distribution must run both gates.
pub fn verify_preview_clean_host_receipt(
    options: &PreviewCleanHostVerificationOptions,
) -> Result<PreviewCleanHostVerificationReport> {
    let receipt_bytes = read_regular_file_bounded(
        &options.receipt_path,
        MAX_PREVIEW_CLEAN_HOST_RECEIPT_BYTES,
        "Preview clean-host receipt",
    )?;
    let receipt = parse_preview_clean_host_receipt(&receipt_bytes)
        .map_err(|error| anyhow!("Preview clean-host receipt is invalid: {error}"))?;

    let approval_bytes = read_regular_file_bounded(
        &options.approval_path,
        MAX_APPROVAL_BYTES,
        "owner distribution approval",
    )?;
    let approval = parse_and_validate(&approval_bytes)
        .map_err(|error| anyhow!("owner distribution approval is invalid: {error}"))?;
    if approval.source_identity().package_mode() != DistributionMode::Preview {
        bail!(
            "Preview clean-host receipt requires a Preview owner approval, found {}",
            approval.source_identity().package_mode().as_str()
        );
    }
    let artifacts = RequiredArtifacts::from_approval(&approval)?;
    let receipt_package = receipt.package();

    if receipt_package.mcpb_size_bytes() != artifacts.mcpb.size_bytes()
        || receipt_package.mcpb_sha256() != artifacts.mcpb.sha256()
    {
        bail!(
            "Preview clean-host receipt binds MCPB {} bytes SHA-256 {}, owner approval binds {} bytes SHA-256 {}",
            receipt_package.mcpb_size_bytes(),
            receipt_package.mcpb_sha256(),
            artifacts.mcpb.size_bytes(),
            artifacts.mcpb.sha256()
        );
    }
    verify_receipt_executable_approval_binding(
        "MCP server",
        receipt_package.mcp_server_sha256(),
        artifacts.mcp_server,
        artifacts.mcpb,
        PREVIEW_MCP_SERVER_PATH,
    )?;
    verify_receipt_executable_approval_binding(
        "AutoLISP LSP",
        receipt_package.autolisp_lsp_sha256(),
        artifacts.autolisp_lsp,
        artifacts.mcpb,
        PREVIEW_AUTOLISP_LSP_PATH,
    )?;

    let mcpb = inspect_preview_mcpb_identity(&options.mcpb_path)?;
    if mcpb.release_version != approval.project().release_version() {
        bail!(
            "Preview MCPB version {} differs from owner-approved version {}",
            mcpb.release_version,
            approval.project().release_version()
        );
    }
    if receipt_package.mcpb_size_bytes() != mcpb.mcpb_size_bytes
        || receipt_package.mcpb_sha256() != mcpb.mcpb_sha256
    {
        bail!(
            "Preview clean-host receipt binds MCPB {} bytes SHA-256 {}, actual MCPB has {} bytes SHA-256 {}",
            receipt_package.mcpb_size_bytes(),
            receipt_package.mcpb_sha256(),
            mcpb.mcpb_size_bytes,
            mcpb.mcpb_sha256
        );
    }
    verify_receipt_executable_archive_binding(
        "MCP server",
        receipt_package.mcp_server_sha256(),
        &mcpb.mcp_server_sha256,
        mcpb.mcp_server_size_bytes,
        artifacts.mcp_server.size_bytes(),
    )?;
    verify_receipt_executable_archive_binding(
        "AutoLISP LSP",
        receipt_package.autolisp_lsp_sha256(),
        &mcpb.autolisp_lsp_sha256,
        mcpb.autolisp_lsp_size_bytes,
        artifacts.autolisp_lsp.size_bytes(),
    )?;

    Ok(PreviewCleanHostVerificationReport {
        decision_id: approval.decision().decision_id().to_owned(),
        receipt_sha256: sha256(&receipt_bytes),
        clean_host_acceptance_verified: true,
        mcpb_sha256: receipt_package.mcpb_sha256().to_owned(),
        mcpb_size_bytes: receipt_package.mcpb_size_bytes(),
        mcp_server_sha256: receipt_package.mcp_server_sha256().to_owned(),
        autolisp_lsp_sha256: receipt_package.autolisp_lsp_sha256().to_owned(),
    })
}

fn verify_receipt_executable_approval_binding(
    label: &str,
    receipt_sha256: &str,
    approved_artifact: &Artifact,
    approved_mcpb: &Artifact,
    expected_container_path: &str,
) -> Result<()> {
    let container = approved_artifact
        .container()
        .ok_or_else(|| anyhow!("owner approval {label} artifact has no MCPB container binding"))?;
    if container.container_artifact_id() != approved_mcpb.artifact_id()
        || container.container_path() != expected_container_path
    {
        bail!(
            "owner approval {label} artifact is not bound to {} at {expected_container_path}",
            approved_mcpb.artifact_id()
        );
    }
    if receipt_sha256 != approved_artifact.sha256() {
        bail!(
            "Preview clean-host receipt {label} SHA-256 {receipt_sha256} differs from owner approval SHA-256 {}",
            approved_artifact.sha256()
        );
    }
    Ok(())
}

fn verify_receipt_executable_archive_binding(
    label: &str,
    receipt_sha256: &str,
    archive_sha256: &str,
    archive_size_bytes: u64,
    approved_size_bytes: u64,
) -> Result<()> {
    if receipt_sha256 != archive_sha256 || archive_size_bytes != approved_size_bytes {
        bail!(
            "contained {label} has {archive_size_bytes} bytes SHA-256 {archive_sha256}, but the receipt and owner approval require {approved_size_bytes} bytes SHA-256 {receipt_sha256}"
        );
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct EntryRecord {
    sha256: String,
    size: u64,
    mode: u32,
    git_blob_sha1: [u8; 20],
    git_blob_sha256: [u8; 32],
}

#[derive(Debug)]
struct ArchiveInventory {
    entries: BTreeMap<String, EntryRecord>,
    captured: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Copy, Debug)]
enum ArchiveKind {
    Mcpb,
    Source,
}

impl ArchiveKind {
    fn label(self) -> &'static str {
        match self {
            Self::Mcpb => "MCPB",
            Self::Source => "source ZIP",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PackageKey {
    name: String,
    version: String,
    source: Option<String>,
}

#[derive(Debug)]
struct LockPackage {
    checksum: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoChecksum {
    files: BTreeMap<String, String>,
    package: String,
}

#[derive(Debug, Deserialize)]
struct SourceClosurePackageDocument {
    packages: Vec<SourceClosurePackage>,
}

#[derive(Debug, Deserialize)]
struct SourceClosurePackage {
    name: String,
    #[serde(rename = "versionInfo")]
    version: String,
    #[serde(rename = "sourceInfo")]
    source_info: String,
    #[serde(default)]
    checksums: Vec<SourceClosureChecksum>,
}

#[derive(Debug, Deserialize)]
struct SourceClosureChecksum {
    algorithm: String,
    #[serde(rename = "checksumValue")]
    value: String,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ClosurePackageKey {
    name: String,
    version: String,
    source: String,
    checksum: Option<String>,
}

/// Verify the exact bytes and structural joins of one owner-approved release.
pub fn verify_owner_distribution_approval(
    options: &ApprovalVerificationOptions,
) -> Result<ApprovalVerificationReport> {
    let approval_bytes = read_regular_file_bounded(
        &options.approval_path,
        MAX_APPROVAL_BYTES,
        "owner distribution approval",
    )?;
    let approval = parse_and_validate(&approval_bytes)
        .map_err(|error| anyhow!("owner distribution approval is invalid: {error}"))?;
    let artifacts = RequiredArtifacts::from_approval(&approval)?;

    let mut mcpb_captures = BTreeSet::new();
    for binding in [
        approval.evidence_bindings().third_party_license_policy(),
        approval.evidence_bindings().source_lock_sbom(),
        approval.evidence_bindings().third_party_notices(),
        approval
            .evidence_bindings()
            .third_party_license_provenance(),
        approval.evidence_bindings().project_license(),
    ] {
        mcpb_captures.insert(binding.logical_path().to_owned());
    }
    mcpb_captures.insert(PACKAGED_APPROVAL_SCHEMA_PATH.to_owned());
    mcpb_captures.insert(PACKAGED_WINDOWS_SOURCE_CLOSURE_SBOM_PATH.to_owned());
    mcpb_captures.insert(required_container_path(artifacts.mcp_server)?);
    mcpb_captures.insert(required_container_path(artifacts.autolisp_lsp)?);

    let mcpb_root = tempfile::tempdir().context("create approval MCPB validation directory")?;
    let mcpb = scan_bound_archive(
        &options.mcpb_path,
        artifacts.mcpb,
        ArchiveKind::Mcpb,
        &mcpb_captures,
        false,
        Some(mcpb_root.path()),
    )?;
    let package_mode = match approval.source_identity().package_mode() {
        DistributionMode::Release => PackageMode::Release,
        DistributionMode::Preview => PackageMode::Preview,
    };
    validate_approval_package(
        mcpb_root.path(),
        approval.project().release_version(),
        package_mode,
    )
    .context("approval-bound MCPB static validation failed")?;
    verify_nested_artifact(artifacts.mcp_server, artifacts.mcpb, &mcpb)?;
    verify_nested_artifact(artifacts.autolisp_lsp, artifacts.mcpb, &mcpb)?;

    let mut source_captures = BTreeSet::from([
        SOURCE_MANIFEST_PATH.to_owned(),
        CARGO_LOCK_PATH.to_owned(),
        RUST_TOOLCHAIN_PATH.to_owned(),
        BUILD_RECIPE_PATH.to_owned(),
        OFFLINE_CONFIG_PATH.to_owned(),
    ]);
    if approval.source_identity().package_mode() == DistributionMode::Preview {
        source_captures.insert(PREVIEW_WORKFLOW_ARCHIVE_PATH.to_owned());
    }
    for binding in approval.evidence_bindings().supplemental_license_evidence() {
        source_captures.insert(format!("workspace/{}", binding.file().logical_path()));
    }
    let source = scan_bound_archive(
        &options.source_archive_path,
        artifacts.source_archive,
        ArchiveKind::Source,
        &source_captures,
        true,
        None,
    )?;

    let source_closure_sbom = read_and_verify_detached(
        &options.source_closure_sbom_path,
        artifacts.source_closure_sbom,
        approval.evidence_bindings().source_closure_sboms()[0].file(),
        "Windows source-closure SBOM",
    )?;
    if captured(
        &mcpb,
        PACKAGED_WINDOWS_SOURCE_CLOSURE_SBOM_PATH,
        "packaged Windows source-closure SBOM",
    )? != source_closure_sbom
    {
        bail!(
            "packaged Windows source-closure SBOM differs from the approval-bound detached artifact"
        );
    }
    let build_attestation = read_and_verify_detached(
        &options.build_attestation_path,
        artifacts.build_attestation,
        approval.evidence_bindings().build_attestations()[0].file(),
        "Windows build attestation",
    )?;

    let schema_bytes = captured(
        &mcpb,
        PACKAGED_APPROVAL_SCHEMA_PATH,
        "packaged approval schema",
    )?;
    approval
        .evidence_bindings()
        .approval_contract_schema()
        .verify_bytes(schema_bytes)
        .map_err(|error| anyhow!("packaged approval schema binding failed: {error}"))?;
    if schema_bytes != OWNER_DISTRIBUTION_APPROVAL_SCHEMA {
        bail!("packaged approval schema differs from the verifier's compiled contract schema");
    }

    let supplemental = approval
        .evidence_bindings()
        .supplemental_license_evidence()
        .iter()
        .map(|binding| {
            let archive_path = format!("workspace/{}", binding.file().logical_path());
            let bytes = captured(&source, &archive_path, "supplemental licence evidence")?;
            binding.file().verify_bytes(bytes).map_err(|error| {
                anyhow!(
                    "supplemental licence evidence {} binding failed: {error}",
                    binding.binding_id()
                )
            })?;
            Ok(SupplementalEvidenceBytes {
                binding_id: binding.binding_id(),
                bytes,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    approval
        .validate_distribution_evidence(&BoundDistributionEvidence {
            third_party_license_policy: captured_binding(
                &mcpb,
                approval.evidence_bindings().third_party_license_policy(),
            )?,
            source_lock_sbom: captured_binding(
                &mcpb,
                approval.evidence_bindings().source_lock_sbom(),
            )?,
            windows_source_closure_sbom: &source_closure_sbom,
            third_party_notices: captured_binding(
                &mcpb,
                approval.evidence_bindings().third_party_notices(),
            )?,
            third_party_license_provenance: captured_binding(
                &mcpb,
                approval
                    .evidence_bindings()
                    .third_party_license_provenance(),
            )?,
            project_license: captured_binding(
                &mcpb,
                approval.evidence_bindings().project_license(),
            )?,
            approval_contract_schema: schema_bytes,
            build_attestation: &build_attestation,
            supplemental_license_evidence: &supplemental,
        })
        .map_err(|error| anyhow!("approval-bound distribution evidence is invalid: {error}"))?;

    verify_source_archive(
        &approval,
        artifacts.source_archive,
        &source,
        &source_closure_sbom,
    )?;

    let source_identity = approval.source_identity();
    let native_build_attestation_semantics_verified = match source_identity.package_mode() {
        DistributionMode::Release => false,
        DistributionMode::Preview => {
            let mcp_server_path = required_container_path(artifacts.mcp_server)?;
            let autolisp_lsp_path = required_container_path(artifacts.autolisp_lsp)?;
            verify_preview_build_attestation_semantics(&PreviewBuildAttestationSemanticInput {
                approval_source_identity: source_identity,
                approved_source_archive: artifacts.source_archive,
                approved_mcp_server: artifacts.mcp_server,
                approved_autolisp_lsp: artifacts.autolisp_lsp,
                attestation_bytes: &build_attestation,
                source_manifest_bytes: captured(
                    &source,
                    SOURCE_MANIFEST_PATH,
                    "source bundle manifest",
                )?,
                workflow_bytes: captured(
                    &source,
                    PREVIEW_WORKFLOW_ARCHIVE_PATH,
                    "source-archive Preview workflow",
                )?,
                contained_mcp_server_bytes: captured(
                    &mcpb,
                    &mcp_server_path,
                    "MCPB-contained MCP server executable",
                )?,
                contained_autolisp_lsp_bytes: captured(
                    &mcpb,
                    &autolisp_lsp_path,
                    "MCPB-contained AutoLISP LSP executable",
                )?,
            })?;
            true
        }
    };
    let git_object_format = match source_identity.git_object_format() {
        GitObjectFormat::Sha1 => "sha1",
        GitObjectFormat::Sha256 => "sha256",
    };
    Ok(ApprovalVerificationReport {
        decision_id: approval.decision().decision_id().to_owned(),
        approval_sha256: sha256(&approval_bytes),
        verified_artifacts: approval.artifacts().len(),
        mcpb_entries: mcpb.entries.len(),
        source_archive_entries: source.entries.len(),
        distribution_evidence_validated: true,
        native_build_attestation_semantics_verified,
        package_mode: source_identity.package_mode(),
        git_object_format: git_object_format.to_owned(),
        source_commit: source_identity.git_commit_oid().to_owned(),
        source_tree_oid: source_identity.git_tree_oid().to_owned(),
        mcpb_sha256: artifacts.mcpb.sha256().to_owned(),
        source_archive_sha256: artifacts.source_archive.sha256().to_owned(),
        source_closure_sbom_sha256: artifacts.source_closure_sbom.sha256().to_owned(),
        build_attestation_sha256: artifacts.build_attestation.sha256().to_owned(),
        source_bundle_manifest_sha256: source_identity.source_bundle_manifest_sha256().to_owned(),
        cargo_lock_sha256: source_identity.cargo_lock_sha256().to_owned(),
        dependency_input_closure_sha256: source_identity
            .dependency_input_closure_sha256()
            .to_owned(),
        rust_toolchain_sha256: source_identity.rust_toolchain_sha256().to_owned(),
        build_recipe_sha256: source_identity.build_recipe_sha256().to_owned(),
    })
}

struct RequiredArtifacts<'a> {
    mcpb: &'a Artifact,
    source_archive: &'a Artifact,
    mcp_server: &'a Artifact,
    autolisp_lsp: &'a Artifact,
    source_closure_sbom: &'a Artifact,
    build_attestation: &'a Artifact,
}

impl<'a> RequiredArtifacts<'a> {
    fn from_approval(approval: &'a OwnerDistributionApproval) -> Result<Self> {
        if approval.artifacts().len() != 6 {
            bail!(
                "approval must bind exactly six artifacts, found {}",
                approval.artifacts().len()
            );
        }
        Ok(Self {
            mcpb: unique_artifact(approval, ArtifactRole::Mcpb)?,
            source_archive: unique_artifact(approval, ArtifactRole::CoveredSourceArchive)?,
            mcp_server: unique_artifact(approval, ArtifactRole::McpServerExecutable)?,
            autolisp_lsp: unique_artifact(approval, ArtifactRole::AutolispLspExecutable)?,
            source_closure_sbom: unique_artifact(approval, ArtifactRole::SourceClosureSbom)?,
            build_attestation: unique_artifact(approval, ArtifactRole::BuildAttestation)?,
        })
    }
}

fn unique_artifact(approval: &OwnerDistributionApproval, role: ArtifactRole) -> Result<&Artifact> {
    let matches = approval
        .artifacts()
        .iter()
        .filter(|artifact| artifact.role() == role)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!(
            "approval must bind exactly one {role:?} artifact, found {}",
            matches.len()
        );
    }
    Ok(matches[0])
}

fn required_container_path(artifact: &Artifact) -> Result<String> {
    artifact
        .container()
        .map(|container| container.container_path().to_owned())
        .ok_or_else(|| {
            anyhow!(
                "nested executable artifact {} has no container path",
                artifact.artifact_id()
            )
        })
}

fn verify_nested_artifact(
    artifact: &Artifact,
    expected_container: &Artifact,
    inventory: &ArchiveInventory,
) -> Result<()> {
    let container = artifact.container().ok_or_else(|| {
        anyhow!(
            "nested executable artifact {} has no container",
            artifact.artifact_id()
        )
    })?;
    if container.container_artifact_id() != expected_container.artifact_id() {
        bail!(
            "artifact {} names container {}, expected {}",
            artifact.artifact_id(),
            container.container_artifact_id(),
            expected_container.artifact_id()
        );
    }
    let entry = inventory
        .entries
        .get(container.container_path())
        .ok_or_else(|| {
            anyhow!(
                "MCPB does not contain approved executable {} at {}",
                artifact.artifact_id(),
                container.container_path()
            )
        })?;
    if entry.size != artifact.size_bytes() || entry.sha256 != artifact.sha256() {
        bail!(
            "MCPB executable {} at {} has {} bytes SHA-256 {}, expected {} bytes SHA-256 {}",
            artifact.artifact_id(),
            container.container_path(),
            entry.size,
            entry.sha256,
            artifact.size_bytes(),
            artifact.sha256()
        );
    }
    Ok(())
}

fn read_and_verify_detached(
    path: &Path,
    artifact: &Artifact,
    binding: &FileBinding,
    label: &str,
) -> Result<Vec<u8>> {
    let bytes = read_regular_file_bounded(path, MAX_DETACHED_EVIDENCE_BYTES, label)?;
    verify_artifact_bytes(artifact, &bytes, label)?;
    binding
        .verify_bytes(&bytes)
        .map_err(|error| anyhow!("{label} file binding failed: {error}"))?;
    Ok(bytes)
}

fn verify_artifact_bytes(artifact: &Artifact, bytes: &[u8], label: &str) -> Result<()> {
    let actual_sha256 = sha256(bytes);
    if bytes.len() as u64 != artifact.size_bytes() || actual_sha256 != artifact.sha256() {
        bail!(
            "{label} has {} bytes SHA-256 {}, expected {} bytes SHA-256 {}",
            bytes.len(),
            actual_sha256,
            artifact.size_bytes(),
            artifact.sha256()
        );
    }
    Ok(())
}

fn captured_binding<'a>(
    inventory: &'a ArchiveInventory,
    binding: &FileBinding,
) -> Result<&'a [u8]> {
    let bytes = captured(
        inventory,
        binding.logical_path(),
        "approval-bound MCPB evidence",
    )?;
    binding
        .verify_bytes(bytes)
        .map_err(|error| anyhow!("{} binding failed: {error}", binding.logical_path()))?;
    Ok(bytes)
}

fn captured<'a>(inventory: &'a ArchiveInventory, path: &str, label: &str) -> Result<&'a [u8]> {
    inventory
        .captured
        .get(path)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("{label} is absent at {path}"))
}

fn scan_unbound_preview_mcpb(
    path: &Path,
    captures: &BTreeSet<String>,
    extraction_root: &Path,
) -> Result<(ArchiveInventory, String, u64)> {
    let label = "Preview MCPB";
    let mut file = open_regular_file(path, label)?;
    let declared_size = file
        .metadata()
        .with_context(|| format!("inspect open {label} {}", path.display()))?
        .len();
    if declared_size == 0 || declared_size > MAX_ARCHIVE_EXPANDED_BYTES {
        bail!("{label} size {declared_size} is outside 1..={MAX_ARCHIVE_EXPANDED_BYTES} bytes");
    }
    let (mut snapshot, before) = snapshot_and_hash_open_file(&mut file, declared_size, label)?;
    if before.1 != declared_size {
        bail!(
            "{label} changed size while its immutable snapshot was created: metadata reported {declared_size} bytes, snapshot captured {} bytes",
            before.1
        );
    }
    snapshot
        .seek(SeekFrom::Start(0))
        .context("rewind Preview MCPB before central-directory validation")?;
    validate_mcpb_central_directory_open(&mut snapshot)
        .context("validate Preview MCPB central directory through its immutable snapshot")?;
    snapshot
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind {label} {}", path.display()))?;
    let inventory = scan_archive(
        &mut snapshot,
        ArchiveKind::Mcpb,
        captures,
        false,
        Some(extraction_root),
    )
    .with_context(|| format!("inspect {label} {}", path.display()))?;
    file.seek(SeekFrom::Start(0))
        .context("rewind Preview MCPB after inspection")?;
    let after = hash_open_file(&mut file, label)?;
    if after != before {
        bail!(
            "{label} changed while it was being inspected: before {} bytes SHA-256 {}, after {} bytes SHA-256 {}",
            before.1,
            before.0,
            after.1,
            after.0
        );
    }
    Ok((inventory, before.0, before.1))
}

fn scan_bound_archive(
    path: &Path,
    artifact: &Artifact,
    kind: ArchiveKind,
    captures: &BTreeSet<String>,
    capture_vendor_checksums: bool,
    extraction_root: Option<&Path>,
) -> Result<ArchiveInventory> {
    let mut file = open_regular_file(path, kind.label())?;
    let (mut snapshot, before) =
        snapshot_and_hash_open_file(&mut file, artifact.size_bytes(), kind.label())?;
    if before.1 != artifact.size_bytes() || before.0 != artifact.sha256() {
        bail!(
            "{} {} has {} bytes SHA-256 {}, expected {} bytes SHA-256 {}",
            kind.label(),
            path.display(),
            before.1,
            before.0,
            artifact.size_bytes(),
            artifact.sha256()
        );
    }
    if extraction_root.is_some() {
        if !matches!(kind, ArchiveKind::Mcpb) {
            bail!("only an MCPB may be extracted for approval static validation");
        }
        snapshot.seek(SeekFrom::Start(0)).with_context(|| {
            format!(
                "rewind {} before central-directory validation",
                kind.label()
            )
        })?;
        validate_mcpb_central_directory_open(&mut snapshot).with_context(|| {
            format!(
                "validate {} central directory through its approved immutable snapshot",
                kind.label()
            )
        })?;
    }
    snapshot
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind {} {}", kind.label(), path.display()))?;
    let inventory = scan_archive(
        &mut snapshot,
        kind,
        captures,
        capture_vendor_checksums,
        extraction_root,
    )
    .with_context(|| format!("inspect {} {}", kind.label(), path.display()))?;
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind {} after inspection", kind.label()))?;
    let after = hash_open_file(&mut file, kind.label())?;
    if after != before {
        bail!(
            "{} changed while it was being verified: before {} bytes SHA-256 {}, after {} bytes SHA-256 {}",
            kind.label(),
            before.1,
            before.0,
            after.1,
            after.0
        );
    }
    Ok(inventory)
}

fn scan_archive(
    file: &mut File,
    kind: ArchiveKind,
    captures: &BTreeSet<String>,
    capture_vendor_checksums: bool,
    extraction_root: Option<&Path>,
) -> Result<ArchiveInventory> {
    let archive_bytes = file
        .metadata()
        .with_context(|| format!("inspect open {}", kind.label()))?
        .len();
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("open {} central directory", kind.label()))?;
    if archive.is_empty() || archive.len() > MAX_ARCHIVE_ENTRIES {
        bail!(
            "{} entry count {} is outside 1..={MAX_ARCHIVE_ENTRIES}",
            kind.label(),
            archive.len()
        );
    }
    if matches!(kind, ArchiveKind::Source)
        && (archive_bytes > u64::from(u32::MAX) || archive.len() > usize::from(u16::MAX))
    {
        bail!("source ZIP violates the declared ZIP32 size or entry-count boundary");
    }
    let mut entries = BTreeMap::new();
    let mut captured_bytes = BTreeMap::new();
    let mut casefolded = BTreeMap::new();
    let mut total = 0u64;
    let mut previous: Option<String> = None;

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = std::str::from_utf8(entry.name_raw())
            .map_err(|_| anyhow!("{} entry {index} has a non-UTF-8 path", kind.label()))?
            .to_owned();
        validate_archive_path(&name)?;
        if entry.is_dir() {
            bail!("{} contains forbidden directory entry {name}", kind.label());
        }
        if entry.is_symlink() {
            bail!("{} contains forbidden symlink entry {name}", kind.label());
        }
        insert_archive_path(&mut casefolded, &name)?;
        if matches!(kind, ArchiveKind::Source) {
            if previous
                .as_deref()
                .is_some_and(|prior| prior >= name.as_str())
            {
                bail!("source ZIP entries are not in strictly ascending UTF-8 path order");
            }
            previous = Some(name.clone());
            if entry.compression() != CompressionMethod::Stored {
                bail!("source ZIP entry {name} is not stored without compression");
            }
            if entry.size() > u64::from(u32::MAX)
                || entry.compressed_size() > u64::from(u32::MAX)
                || entry.data_start() > u64::from(u32::MAX)
                || entry
                    .extra_data()
                    .is_some_and(|extra| zip_extra_contains(extra, 0x0001))
            {
                bail!("source ZIP entry {name} uses forbidden ZIP64 metadata");
            }
            let modified = entry
                .last_modified()
                .ok_or_else(|| anyhow!("source ZIP entry {name} has no DOS timestamp"))?;
            if (
                modified.year(),
                modified.month(),
                modified.day(),
                modified.hour(),
                modified.minute(),
                modified.second(),
            ) != (1980, 1, 1, 0, 0, 0)
            {
                bail!("source ZIP entry {name} has a non-deterministic timestamp");
            }
        }
        let expected_size = entry.size();
        if expected_size > MAX_ARCHIVE_ENTRY_BYTES {
            bail!(
                "{} entry {name} is {expected_size} bytes, exceeding {MAX_ARCHIVE_ENTRY_BYTES}",
                kind.label()
            );
        }
        total = total
            .checked_add(expected_size)
            .ok_or_else(|| anyhow!("{} expanded size overflow", kind.label()))?;
        if total > MAX_ARCHIVE_EXPANDED_BYTES {
            bail!(
                "{} expands beyond {MAX_ARCHIVE_EXPANDED_BYTES} bytes",
                kind.label()
            );
        }
        if extraction_root.is_some()
            && (expected_size > MAX_EXTRACTED_FILE_BYTES || total > MAX_EXTRACTED_BYTES)
        {
            bail!(
                "MCPB extraction limits reject entry {name}: file {expected_size} bytes, package total {total} bytes"
            );
        }
        let mode = match (kind, entry.unix_mode()) {
            (ArchiveKind::Source, None) => {
                bail!("source ZIP entry {name} has no Unix regular-file mode")
            }
            (_, Some(value)) => value & 0o7777,
            (ArchiveKind::Mcpb, None) => 0o644,
        };
        if matches!(kind, ArchiveKind::Source) && !matches!(mode, 0o644 | 0o755) {
            bail!("source ZIP entry {name} has unsupported mode {mode:o}");
        }
        let should_capture = captures.contains(&name)
            || (capture_vendor_checksums
                && name.starts_with("vendor/")
                && name.ends_with("/.cargo-checksum.json"));
        if should_capture && expected_size > MAX_CAPTURED_ENTRY_BYTES {
            bail!("required captured entry {name} exceeds {MAX_CAPTURED_ENTRY_BYTES} bytes");
        }
        let mut capture = should_capture.then(|| Vec::with_capacity(expected_size as usize));
        let mut extracted = if let Some(root) = extraction_root {
            let target = root.join(&name);
            let parent = target
                .parent()
                .ok_or_else(|| anyhow!("MCPB entry {name} has no extraction parent"))?;
            fs::create_dir_all(parent).with_context(|| {
                format!("create MCPB extraction directory {}", parent.display())
            })?;
            Some(
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)
                    .with_context(|| format!("create extracted MCPB file {}", target.display()))?,
            )
        } else {
            None
        };
        let mut digest = Sha256::new();
        let git_header = format!("blob {expected_size}\0");
        let mut git_sha1 = Sha1::new();
        git_sha1.update(git_header.as_bytes());
        let mut git_sha256 = Sha256::new();
        git_sha256.update(git_header.as_bytes());
        let mut actual_size = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = entry
                .read(&mut buffer)
                .with_context(|| format!("read {} entry {name}", kind.label()))?;
            if count == 0 {
                break;
            }
            actual_size = actual_size
                .checked_add(count as u64)
                .ok_or_else(|| anyhow!("entry size overflow for {name}"))?;
            if actual_size > expected_size || actual_size > MAX_ARCHIVE_ENTRY_BYTES {
                bail!(
                    "{} entry {name} exceeds its declared or allowed size",
                    kind.label()
                );
            }
            digest.update(&buffer[..count]);
            git_sha1.update(&buffer[..count]);
            git_sha256.update(&buffer[..count]);
            if let Some(bytes) = capture.as_mut() {
                bytes.extend_from_slice(&buffer[..count]);
            }
            if let Some(output) = extracted.as_mut() {
                output
                    .write_all(&buffer[..count])
                    .with_context(|| format!("write extracted MCPB entry {name}"))?;
            }
        }
        if actual_size != expected_size {
            bail!(
                "{} entry {name} yielded {actual_size} bytes, header declared {expected_size}",
                kind.label()
            );
        }
        let record = EntryRecord {
            sha256: hex_lower(&digest.finalize()),
            size: actual_size,
            mode,
            git_blob_sha1: git_sha1.finalize(),
            git_blob_sha256: git_sha256.finalize().into(),
        };
        if entries.insert(name.clone(), record).is_some() {
            bail!("{} repeats archive path {name}", kind.label());
        }
        if let (Some(root), Some(mut output)) = (extraction_root, extracted) {
            output
                .flush()
                .with_context(|| format!("flush extracted MCPB entry {name}"))?;
            drop(output);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(root.join(&name), fs::Permissions::from_mode(mode))
                    .with_context(|| format!("set extracted MCPB mode for {name}"))?;
            }
        }
        if let Some(bytes) = capture {
            captured_bytes.insert(name, bytes);
        }
    }
    for required in captures {
        if !entries.contains_key(required) {
            bail!("{} is missing required entry {required}", kind.label());
        }
    }
    Ok(ArchiveInventory {
        entries,
        captured: captured_bytes,
    })
}

fn zip_extra_contains(mut extra: &[u8], expected_id: u16) -> bool {
    while extra.len() >= 4 {
        let id = u16::from_le_bytes([extra[0], extra[1]]);
        let length = usize::from(u16::from_le_bytes([extra[2], extra[3]]));
        extra = &extra[4..];
        if length > extra.len() {
            return false;
        }
        if id == expected_id {
            return true;
        }
        extra = &extra[length..];
    }
    false
}

fn verify_source_archive(
    approval: &OwnerDistributionApproval,
    source_artifact: &Artifact,
    inventory: &ArchiveInventory,
    source_closure_sbom: &[u8],
) -> Result<()> {
    let manifest_bytes = captured(inventory, SOURCE_MANIFEST_PATH, "source bundle manifest")?;
    approval
        .source_identity()
        .source_bundle_manifest_sha256()
        .eq(&sha256(manifest_bytes))
        .then_some(())
        .ok_or_else(|| anyhow!("source bundle manifest SHA-256 does not match the approval"))?;
    let manifest_value = distribution_approval::parse_strict_json(manifest_bytes)
        .context("parse strict source-bundle manifest JSON")?;
    let manifest: SourceBundleManifest = serde_json::from_value(manifest_value)
        .context("parse closed source-bundle manifest schema v3")?;

    verify_manifest_identity(approval, &manifest, inventory)?;
    verify_manifest_roots(
        &manifest.roots,
        approval.project().release_version(),
        approval.source_identity().package_mode(),
    )?;
    verify_manifest_root_packages(&manifest.roots, &manifest.packages)?;
    verify_manifest_policy(&manifest.archive_policy)?;

    let cargo_lock = captured(inventory, CARGO_LOCK_PATH, "bundled Cargo.lock")?;
    let lock_packages = parse_cargo_lock(cargo_lock)?;
    verify_packages(&manifest, &lock_packages, inventory)?;
    verify_source_closure_package_join(&manifest, source_closure_sbom)?;
    verify_generated_files(&manifest, inventory)?;
    verify_workspace_tree(&manifest, inventory)?;
    verify_exclusions(approval, source_artifact, &manifest, inventory)?;
    verify_complete_source_membership(&manifest, inventory)?;
    Ok(())
}

fn verify_source_closure_package_join(
    manifest: &SourceBundleManifest,
    source_closure_sbom: &[u8],
) -> Result<()> {
    let source_closure_value = distribution_approval::parse_strict_json(source_closure_sbom)
        .context("parse strict source-closure SBOM JSON")?;
    let document: SourceClosurePackageDocument = serde_json::from_value(source_closure_value)
        .context("parse source-closure SBOM package inventory")?;
    let mut sbom_packages = BTreeSet::new();
    for package in document.packages {
        let (source, checksum) = if package.source_info == WORKSPACE_SOURCE_INFO {
            if !package.checksums.is_empty() {
                bail!(
                    "source-closure SBOM workspace package {} {} has a registry checksum",
                    package.name,
                    package.version
                );
            }
            ("workspace".to_owned(), None)
        } else {
            let source = package
                .source_info
                .strip_prefix(REGISTRY_SOURCE_PREFIX)
                .and_then(|value| value.strip_suffix(REGISTRY_SOURCE_SUFFIX))
                .ok_or_else(|| {
                    anyhow!(
                        "source-closure SBOM package {} {} has unsupported sourceInfo",
                        package.name,
                        package.version
                    )
                })?
                .to_owned();
            if package.checksums.len() != 1 || package.checksums[0].algorithm != "SHA256" {
                bail!(
                    "source-closure SBOM package {} {} must have one SHA256 checksum",
                    package.name,
                    package.version
                );
            }
            require_sha256(
                &package.checksums[0].value,
                "source-closure SBOM package checksum",
            )?;
            (source, Some(package.checksums[0].value.clone()))
        };
        if !sbom_packages.insert(ClosurePackageKey {
            name: package.name,
            version: package.version,
            source,
            checksum,
        }) {
            bail!("source-closure SBOM repeats a package identity");
        }
    }
    let manifest_packages = manifest
        .packages
        .iter()
        .map(|package| ClosurePackageKey {
            name: package.name.clone(),
            version: package.version.clone(),
            source: package.source.clone(),
            checksum: package.cargo_lock_checksum.clone(),
        })
        .collect::<BTreeSet<_>>();
    if manifest_packages.len() != manifest.packages.len() || manifest_packages != sbom_packages {
        bail!("source manifest package closure does not exactly match the source-closure SBOM");
    }
    Ok(())
}

fn verify_manifest_identity(
    approval: &OwnerDistributionApproval,
    manifest: &SourceBundleManifest,
    inventory: &ArchiveInventory,
) -> Result<()> {
    let identity = approval.source_identity();
    if manifest.schema_version != SOURCE_BUNDLE_MANIFEST_SCHEMA_VERSION
        || manifest.artifact_kind != SOURCE_BUNDLE_ARTIFACT_KIND
        || manifest.git_object_format != identity.git_object_format()
        || manifest.source_commit != identity.git_commit_oid()
        || manifest.source_tree_oid != identity.git_tree_oid()
        || manifest.cargo_lock_sha256 != identity.cargo_lock_sha256()
        || manifest.dependency_input_closure_sha256 != identity.dependency_input_closure_sha256()
        || manifest.rust_toolchain_sha256 != identity.rust_toolchain_sha256()
        || manifest.build_recipe_sha256 != identity.build_recipe_sha256()
        || manifest.target != WINDOWS_TARGET
        || manifest.profile != SOURCE_BUNDLE_PROFILE
        || manifest.package_mode != identity.package_mode()
        || manifest.cargo_incremental
        || identity.build_profile() != BuildProfile::Release
        || identity.cargo_incremental()
    {
        bail!("source bundle manifest does not match the approved schema-v3 source/build identity");
    }
    let cargo_lock = captured(inventory, CARGO_LOCK_PATH, "bundled Cargo.lock")?;
    let rust_toolchain = captured(
        inventory,
        RUST_TOOLCHAIN_PATH,
        "bundled rust-toolchain.toml",
    )?;
    let build_recipe = captured(inventory, BUILD_RECIPE_PATH, "bundled build recipe")?;
    if sha256(cargo_lock) != manifest.cargo_lock_sha256
        || sha256(rust_toolchain) != manifest.rust_toolchain_sha256
        || sha256(build_recipe) != manifest.build_recipe_sha256
    {
        bail!("source bundle manifest file digests do not match bundled build inputs");
    }
    let channel = rust_toolchain_channel(rust_toolchain)?;
    if channel != manifest.rust_toolchain {
        bail!(
            "manifest Rust toolchain {} differs from bundled channel {channel}",
            manifest.rust_toolchain
        );
    }
    let canonical_build_recipe = render_windows_x86_64_build_recipe(
        &channel,
        identity.git_object_format(),
        identity.git_commit_oid(),
        identity.package_mode(),
    )
    .context("derive canonical Windows build recipe from approved source/build identity")?;
    if build_recipe != canonical_build_recipe {
        bail!(
            "bundled build recipe differs byte-for-byte from the canonical Windows recipe for the approved Rust toolchain and Git source identity"
        );
    }
    verify_git_tree_oid(manifest, inventory)?;
    let offline_config = captured(
        inventory,
        OFFLINE_CONFIG_PATH,
        "generated offline Cargo configuration",
    )?;
    if offline_config != EXPECTED_OFFLINE_CONFIG {
        bail!("generated offline Cargo configuration differs from the closed policy");
    }
    Ok(())
}

fn verify_manifest_roots(
    roots: &[RootManifest],
    expected_release_version: &str,
    package_mode: DistributionMode,
) -> Result<()> {
    if roots.len() != 2 {
        bail!("source manifest must contain exactly two build roots");
    }
    let expected = [
        ("autocad-mcp", "crates/autocad-mcp/Cargo.toml", true),
        ("autolisp-lsp", "crates/autolisp-lsp/Cargo.toml", false),
    ];
    for (root, (name, manifest_path, no_default_features)) in roots.iter().zip(expected) {
        if root.name != name
            || root.version.is_empty()
            || root.manifest_path != manifest_path
            || root.dependency_kinds != ["normal", "build"]
            || root.excluded_dependency_kind != "dev"
            || root.package_count == 0
        {
            bail!(
                "source manifest build root {} violates the closed root policy",
                root.name
            );
        }
        let mut arguments = vec![
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--filter-platform",
            WINDOWS_TARGET,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        if no_default_features {
            arguments.push("--no-default-features".to_owned());
            if package_mode == DistributionMode::Preview {
                arguments.extend(["--features".to_owned(), "preview".to_owned()]);
            }
        }
        arguments.extend(["--manifest-path".to_owned(), manifest_path.to_owned()]);
        if root.cargo_metadata_arguments != arguments {
            bail!("source manifest build root {name} has unexpected Cargo metadata arguments");
        }
    }
    if roots[0].version != expected_release_version {
        bail!(
            "source manifest autocad-mcp root version {} does not match owner approval release version {expected_release_version}",
            roots[0].version
        );
    }
    Ok(())
}

fn verify_manifest_root_packages(
    roots: &[RootManifest],
    packages: &[PackageManifest],
) -> Result<()> {
    for root in roots {
        let workspace_packages = packages
            .iter()
            .filter(|package| package.name == root.name && package.source == "workspace")
            .collect::<Vec<_>>();
        if workspace_packages.len() != 1 {
            bail!(
                "source manifest build root {} must match exactly one workspace package row, found {}",
                root.name,
                workspace_packages.len()
            );
        }
        let workspace_package = workspace_packages[0];
        if workspace_package.version != root.version {
            bail!(
                "source manifest build root {} version {} does not match workspace package version {}",
                root.name,
                root.version,
                workspace_package.version
            );
        }
        if !workspace_package
            .roots
            .iter()
            .any(|membership| membership == &root.name)
        {
            bail!(
                "source manifest workspace package {} {} is not a member of its own build root",
                workspace_package.name,
                workspace_package.version
            );
        }
        let actual_package_count = packages
            .iter()
            .filter(|package| {
                package
                    .roots
                    .iter()
                    .any(|membership| membership == &root.name)
            })
            .count();
        if root.package_count != actual_package_count {
            bail!(
                "source manifest build root {} package_count {} does not match its {} package rows",
                root.name,
                root.package_count,
                actual_package_count
            );
        }
    }
    Ok(())
}

fn verify_manifest_policy(policy: &ArchivePolicyManifest) -> Result<()> {
    if policy.format != "ZIP32"
        || policy.compression != "stored"
        || policy.entry_order != "ascending UTF-8 path"
        || policy.timestamp != "1980-01-01T00:00:00Z"
        || policy.regular_file_modes != ["0644", "0755"]
        || policy.zip64
    {
        bail!("source manifest archive policy differs from the closed deterministic policy");
    }
    Ok(())
}

fn verify_packages(
    manifest: &SourceBundleManifest,
    lock_packages: &BTreeMap<PackageKey, LockPackage>,
    inventory: &ArchiveInventory,
) -> Result<()> {
    if manifest.packages.is_empty() {
        bail!("source manifest package closure is empty");
    }
    let mut previous = None;
    let mut seen_vendor_paths = BTreeSet::new();
    for package in &manifest.packages {
        let ordering = (&package.name, &package.version, &package.source);
        if previous.is_some_and(|prior| prior >= ordering) {
            bail!("source manifest packages are not strictly sorted and unique");
        }
        previous = Some(ordering);
        let roots = package
            .roots
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if roots.is_empty()
            || roots.len() != package.roots.len()
            || !roots
                .iter()
                .all(|root| matches!(*root, "autocad-mcp" | "autolisp-lsp"))
        {
            bail!(
                "source manifest package {} {} has invalid root membership",
                package.name,
                package.version
            );
        }
        let source = if package.source == "workspace" {
            None
        } else if package.source == REGISTRY_SOURCE {
            Some(REGISTRY_SOURCE.to_owned())
        } else {
            bail!(
                "source manifest package {} {} uses unsupported source {}",
                package.name,
                package.version,
                package.source
            );
        };
        let key = PackageKey {
            name: package.name.clone(),
            version: package.version.clone(),
            source,
        };
        let lock = lock_packages.get(&key).ok_or_else(|| {
            anyhow!(
                "source manifest package {} {} does not exactly match Cargo.lock",
                package.name,
                package.version
            )
        })?;
        match (
            &package.source[..],
            &package.cargo_lock_checksum,
            &package.vendor,
        ) {
            ("workspace", None, None) if lock.checksum.is_none() => {}
            (REGISTRY_SOURCE, Some(checksum), Some(vendor))
                if lock.checksum.as_deref() == Some(checksum.as_str())
                    && vendor.crate_archive_sha256 == *checksum =>
            {
                require_sha256(checksum, "registry Cargo.lock checksum")?;
                let expected_vendor_path = format!("vendor/{}-{}", package.name, package.version);
                if vendor.path != expected_vendor_path || !seen_vendor_paths.insert(&vendor.path) {
                    bail!(
                        "source manifest package {} {} has invalid or duplicate vendor path {}",
                        package.name,
                        package.version,
                        vendor.path
                    );
                }
                verify_vendor_tree(vendor, inventory)?;
            }
            _ => {
                bail!(
                    "source manifest package {} {} does not preserve its Cargo.lock/vendor identity",
                    package.name,
                    package.version
                )
            }
        }
    }
    Ok(())
}

fn verify_vendor_tree(vendor: &VendorManifest, inventory: &ArchiveInventory) -> Result<()> {
    validate_archive_path(&vendor.path)?;
    require_sha256(&vendor.crate_archive_sha256, "vendor crate archive digest")?;
    require_sha256(&vendor.tree_sha256, "vendor tree digest")?;
    let prefix = format!("{}/", vendor.path);
    let members = inventory
        .entries
        .iter()
        .filter_map(|(path, entry)| path.strip_prefix(&prefix).map(|relative| (relative, entry)))
        .collect::<Vec<_>>();
    if members.len() != vendor.file_count || members.is_empty() {
        bail!(
            "vendor tree {} contains {} files, manifest declares {}",
            vendor.path,
            members.len(),
            vendor.file_count
        );
    }
    if tree_digest(&members) != vendor.tree_sha256 {
        bail!(
            "vendor tree {} digest does not match its manifest",
            vendor.path
        );
    }
    let checksum_path = format!("{}/.cargo-checksum.json", vendor.path);
    let checksum_bytes = captured(inventory, &checksum_path, "vendor Cargo checksum manifest")?;
    let checksum: CargoChecksum =
        serde_json::from_slice(checksum_bytes).with_context(|| format!("parse {checksum_path}"))?;
    if checksum.package != vendor.crate_archive_sha256 {
        bail!("{} package checksum differs from Cargo.lock", checksum_path);
    }
    let actual_files = members
        .iter()
        .filter(|(relative, _)| *relative != ".cargo-checksum.json")
        .map(|(relative, entry)| ((*relative).to_owned(), entry.sha256.clone()))
        .collect::<BTreeMap<_, _>>();
    if checksum.files != actual_files {
        bail!("{checksum_path} does not exactly describe the vendored files");
    }
    Ok(())
}

fn verify_generated_files(
    manifest: &SourceBundleManifest,
    inventory: &ArchiveInventory,
) -> Result<()> {
    let expected = BTreeSet::from([OFFLINE_CONFIG_PATH, BUILD_RECIPE_PATH]);
    let actual = manifest
        .generated_files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    if actual != expected || actual.len() != manifest.generated_files.len() {
        bail!("source manifest generated-file set is not the exact closed set");
    }
    for file in &manifest.generated_files {
        require_sha256(&file.sha256, "generated file digest")?;
        let entry = inventory
            .entries
            .get(&file.path)
            .ok_or_else(|| anyhow!("generated source file {} is absent", file.path))?;
        if entry.size != file.bytes as u64 || entry.sha256 != file.sha256 {
            bail!(
                "generated source file {} does not match its manifest",
                file.path
            );
        }
    }
    Ok(())
}

fn verify_workspace_tree(
    manifest: &SourceBundleManifest,
    inventory: &ArchiveInventory,
) -> Result<()> {
    if manifest.workspace.path != "workspace"
        || manifest.workspace.digest_method != TREE_DIGEST_METHOD
    {
        bail!("workspace tree manifest uses an unexpected path or digest method");
    }
    require_sha256(&manifest.workspace.tree_sha256, "workspace tree digest")?;
    let members = inventory
        .entries
        .iter()
        .filter_map(|(path, entry)| {
            path.strip_prefix("workspace/")
                .and_then(|relative| (path != OFFLINE_CONFIG_PATH).then_some((relative, entry)))
        })
        .collect::<Vec<_>>();
    if members.len() != manifest.workspace.file_count {
        bail!(
            "workspace tree contains {} files, manifest declares {}",
            members.len(),
            manifest.workspace.file_count
        );
    }
    if tree_digest(&members) != manifest.workspace.tree_sha256 {
        bail!("workspace tree digest does not match its manifest");
    }
    Ok(())
}

fn verify_exclusions(
    approval: &OwnerDistributionApproval,
    source_artifact: &Artifact,
    manifest: &SourceBundleManifest,
    inventory: &ArchiveInventory,
) -> Result<()> {
    let manifest_exclusions = manifest.exclusions.iter().cloned().collect::<BTreeSet<_>>();
    if manifest_exclusions.len() != manifest.exclusions.len() {
        bail!("source manifest repeats an exclusion");
    }
    let expected = approval
        .source_exclusions()
        .iter()
        .map(|exclusion| {
            if exclusion.source_artifact_id() != source_artifact.artifact_id() {
                bail!(
                    "approval exclusion {} {} names the wrong source artifact",
                    exclusion.package_name(),
                    exclusion.package_version()
                );
            }
            Ok(ExclusionManifest {
                package: exclusion.package_name().to_owned(),
                version: exclusion.package_version().to_owned(),
                path: format!(
                    "vendor/{}-{}/{}",
                    exclusion.package_name(),
                    exclusion.package_version(),
                    exclusion.crate_relative_path()
                ),
                sha256: exclusion.sha256().to_owned(),
                bytes: usize::try_from(exclusion.size_bytes())
                    .context("approval exclusion size does not fit usize")?,
                reason: exclusion.reason().to_owned(),
            })
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if manifest_exclusions != expected {
        bail!("source manifest exclusions do not exactly match the approval");
    }
    for exclusion in &manifest.exclusions {
        validate_archive_path(&exclusion.path)?;
        require_sha256(&exclusion.sha256, "source exclusion digest")?;
        if inventory.entries.contains_key(&exclusion.path) {
            bail!(
                "excluded source path {} is present in the source ZIP",
                exclusion.path
            );
        }
    }
    Ok(())
}

fn verify_complete_source_membership(
    manifest: &SourceBundleManifest,
    inventory: &ArchiveInventory,
) -> Result<()> {
    let vendor_prefixes = manifest
        .packages
        .iter()
        .filter_map(|package| package.vendor.as_ref())
        .map(|vendor| format!("{}/", vendor.path))
        .collect::<Vec<_>>();
    for path in inventory.entries.keys() {
        let declared = path == SOURCE_MANIFEST_PATH
            || path == BUILD_RECIPE_PATH
            || path.starts_with("workspace/")
            || vendor_prefixes
                .iter()
                .any(|prefix| path.starts_with(prefix));
        if !declared {
            bail!("source ZIP contains undeclared member {path}");
        }
    }
    Ok(())
}

#[derive(Debug)]
enum GitTreeNode {
    File {
        mode: u32,
        sha1: [u8; 20],
        sha256: [u8; 32],
    },
    Directory(BTreeMap<String, GitTreeNode>),
}

fn verify_git_tree_oid(
    manifest: &SourceBundleManifest,
    inventory: &ArchiveInventory,
) -> Result<()> {
    let mut root = BTreeMap::new();
    for (path, entry) in &inventory.entries {
        let Some(relative) = path.strip_prefix("workspace/") else {
            continue;
        };
        if path == OFFLINE_CONFIG_PATH {
            continue;
        }
        insert_git_tree_file(
            &mut root,
            relative,
            entry.mode,
            entry.git_blob_sha1,
            entry.git_blob_sha256,
        )?;
    }
    if root.is_empty() {
        bail!("workspace contains no Git source files");
    }
    let oid = match manifest.git_object_format.as_str() {
        "sha1" => hex_lower(&git_tree_hash_sha1(&root)?),
        "sha256" => hex_lower(&git_tree_hash_sha256(&root)?),
        other => bail!("unsupported Git object format {other:?}"),
    };
    if oid != manifest.source_tree_oid {
        bail!(
            "reconstructed {} Git tree OID {} does not match approved source tree {}",
            manifest.git_object_format.as_str(),
            oid,
            manifest.source_tree_oid
        );
    }
    Ok(())
}

fn insert_git_tree_file(
    directory: &mut BTreeMap<String, GitTreeNode>,
    path: &str,
    mode: u32,
    sha1: [u8; 20],
    sha256: [u8; 32],
) -> Result<()> {
    let mut components = path.split('/');
    let first = components
        .next()
        .ok_or_else(|| anyhow!("empty Git tree path"))?;
    let remainder = components.collect::<Vec<_>>().join("/");
    if remainder.is_empty() {
        if directory
            .insert(first.to_owned(), GitTreeNode::File { mode, sha1, sha256 })
            .is_some()
        {
            bail!("workspace repeats Git tree path {path}");
        }
        return Ok(());
    }
    let node = directory
        .entry(first.to_owned())
        .or_insert_with(|| GitTreeNode::Directory(BTreeMap::new()));
    let GitTreeNode::Directory(child) = node else {
        bail!("workspace Git file {first} conflicts with descendant {path}");
    };
    insert_git_tree_file(child, &remainder, mode, sha1, sha256)
}

fn ordered_git_tree_entries(
    directory: &BTreeMap<String, GitTreeNode>,
) -> Vec<(&str, &GitTreeNode)> {
    let mut entries = directory
        .iter()
        .map(|(name, node)| (name.as_str(), node))
        .collect::<Vec<_>>();
    entries.sort_by(|(left_name, left), (right_name, right)| {
        git_tree_sort_key(left_name, left).cmp(&git_tree_sort_key(right_name, right))
    });
    entries
}

fn git_tree_sort_key(name: &str, node: &GitTreeNode) -> Vec<u8> {
    let mut key = name.as_bytes().to_vec();
    if matches!(node, GitTreeNode::Directory(_)) {
        key.push(b'/');
    }
    key
}

fn git_tree_hash_sha1(directory: &BTreeMap<String, GitTreeNode>) -> Result<[u8; 20]> {
    let mut body = Vec::new();
    for (name, node) in ordered_git_tree_entries(directory) {
        match node {
            GitTreeNode::File { mode, sha1, .. } => {
                let mode = match mode {
                    0o644 => b"100644".as_slice(),
                    0o755 => b"100755".as_slice(),
                    other => bail!("unsupported Git file mode {other:o} for {name}"),
                };
                body.extend_from_slice(mode);
                body.push(b' ');
                body.extend_from_slice(name.as_bytes());
                body.push(0);
                body.extend_from_slice(sha1);
            }
            GitTreeNode::Directory(child) => {
                body.extend_from_slice(b"40000 ");
                body.extend_from_slice(name.as_bytes());
                body.push(0);
                body.extend_from_slice(&git_tree_hash_sha1(child)?);
            }
        }
    }
    let mut hash = Sha1::new();
    hash.update(format!("tree {}\0", body.len()).as_bytes());
    hash.update(&body);
    Ok(hash.finalize())
}

fn git_tree_hash_sha256(directory: &BTreeMap<String, GitTreeNode>) -> Result<[u8; 32]> {
    let mut body = Vec::new();
    for (name, node) in ordered_git_tree_entries(directory) {
        match node {
            GitTreeNode::File { mode, sha256, .. } => {
                let mode = match mode {
                    0o644 => b"100644".as_slice(),
                    0o755 => b"100755".as_slice(),
                    other => bail!("unsupported Git file mode {other:o} for {name}"),
                };
                body.extend_from_slice(mode);
                body.push(b' ');
                body.extend_from_slice(name.as_bytes());
                body.push(0);
                body.extend_from_slice(sha256);
            }
            GitTreeNode::Directory(child) => {
                body.extend_from_slice(b"40000 ");
                body.extend_from_slice(name.as_bytes());
                body.push(0);
                body.extend_from_slice(&git_tree_hash_sha256(child)?);
            }
        }
    }
    let mut hash = Sha256::new();
    hash.update(format!("tree {}\0", body.len()).as_bytes());
    hash.update(&body);
    Ok(hash.finalize().into())
}

fn rust_toolchain_channel(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes).context("rust-toolchain.toml is not UTF-8")?;
    let mut channel = None;
    for (index, line) in text.lines().enumerate() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        if key.trim() != "channel" {
            continue;
        }
        let parsed: String = serde_json::from_str(value.trim()).with_context(|| {
            format!("rust-toolchain.toml line {} has invalid channel", index + 1)
        })?;
        if channel.replace(parsed).is_some() {
            bail!("rust-toolchain.toml repeats toolchain channel");
        }
    }
    let channel = channel.ok_or_else(|| anyhow!("rust-toolchain.toml has no channel"))?;
    let parts = channel.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || !parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
        })
    {
        bail!("rust-toolchain.toml channel is not an exact numeric Rust release");
    }
    Ok(channel)
}

fn parse_cargo_lock(bytes: &[u8]) -> Result<BTreeMap<PackageKey, LockPackage>> {
    let text = std::str::from_utf8(bytes).context("Cargo.lock is not UTF-8")?;
    let mut packages = BTreeMap::new();
    let mut current: Option<BTreeMap<String, String>> = None;
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line == "[[package]]" {
            if let Some(fields) = current.take() {
                insert_lock_package(&mut packages, fields)?;
            }
            current = Some(BTreeMap::new());
            continue;
        }
        if line.starts_with('[') {
            if let Some(fields) = current.take() {
                insert_lock_package(&mut packages, fields)?;
            }
            continue;
        }
        let Some(fields) = current.as_mut() else {
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !matches!(key, "name" | "version" | "source" | "checksum") {
            continue;
        }
        let value = value.trim();
        if !(value.starts_with('"') && value.ends_with('"')) {
            bail!(
                "Cargo.lock line {} has unsupported non-basic-string field {key}",
                index + 1
            );
        }
        let decoded: String = serde_json::from_str(value)
            .with_context(|| format!("Cargo.lock line {} has invalid {key}", index + 1))?;
        if fields.insert(key.to_owned(), decoded).is_some() {
            bail!("Cargo.lock package stanza repeats {key}");
        }
    }
    if let Some(fields) = current {
        insert_lock_package(&mut packages, fields)?;
    }
    if packages.is_empty() {
        bail!("Cargo.lock contains no package stanzas");
    }
    Ok(packages)
}

fn insert_lock_package(
    packages: &mut BTreeMap<PackageKey, LockPackage>,
    mut fields: BTreeMap<String, String>,
) -> Result<()> {
    let name = fields
        .remove("name")
        .ok_or_else(|| anyhow!("Cargo.lock package has no name"))?;
    let version = fields
        .remove("version")
        .ok_or_else(|| anyhow!("Cargo.lock package {name} has no version"))?;
    let source = fields.remove("source");
    let checksum = fields.remove("checksum");
    match (&source, &checksum) {
        (Some(_), Some(checksum)) => require_sha256(checksum, "Cargo.lock checksum")?,
        (Some(source), None) => {
            bail!("Cargo.lock package {name} {version} from {source} has no checksum")
        }
        (None, Some(_)) => bail!("Cargo.lock workspace package {name} {version} has a checksum"),
        (None, None) => {}
    }
    let key = PackageKey {
        name,
        version,
        source,
    };
    if packages
        .insert(key.clone(), LockPackage { checksum })
        .is_some()
    {
        bail!(
            "Cargo.lock repeats package {} {} source {:?}",
            key.name,
            key.version,
            key.source
        );
    }
    Ok(())
}

fn tree_digest(files: &[(&str, &EntryRecord)]) -> String {
    let mut ordered = files.to_vec();
    ordered.sort_by(|left, right| left.0.cmp(right.0));
    let mut digest = Sha256::new();
    digest.update(TREE_DIGEST_DOMAIN);
    for (path, entry) in ordered {
        digest.update((path.len() as u64).to_le_bytes());
        digest.update(path.as_bytes());
        digest.update(entry.mode.to_le_bytes());
        digest.update(entry.size.to_le_bytes());
        let raw = decode_sha256(&entry.sha256).expect("entry digest is internally generated");
        digest.update(raw);
    }
    hex_lower(&digest.finalize())
}

fn read_regular_file_bounded(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    let file = open_regular_file(path, label)?;
    let size = file
        .metadata()
        .with_context(|| format!("inspect open {label} {}", path.display()))?
        .len();
    if size == 0 || size > limit {
        bail!("{label} size {size} is outside 1..={limit} bytes");
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label} {}", path.display()))?;
    if bytes.len() as u64 != size || bytes.len() as u64 > limit {
        bail!("{label} changed while being read or exceeded its size limit");
    }
    Ok(bytes)
}

fn open_regular_file(path: &Path, label: &str) -> Result<File> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "{label} must be a regular non-symlink file: {}",
            path.display()
        );
    }
    File::open(path).with_context(|| format!("open {label} {}", path.display()))
}

fn hash_open_file(file: &mut File, label: &str) -> Result<(String, u64)> {
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("hash {label}"))?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| anyhow!("{label} size overflow"))?;
        digest.update(&buffer[..count]);
    }
    Ok((hex_lower(&digest.finalize()), size))
}

fn snapshot_and_hash_open_file(
    source: &mut File,
    expected_size: u64,
    label: &str,
) -> Result<(File, (String, u64))> {
    source
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind open {label} before immutable snapshot"))?;
    let mut snapshot =
        tempfile::tempfile().with_context(|| format!("create private {label} snapshot"))?;
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .with_context(|| format!("read open {label} into immutable snapshot"))?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| anyhow!("{label} size overflow while snapshotting"))?;
        if size > expected_size {
            bail!(
                "{label} exceeds its approved size {expected_size} while creating immutable snapshot"
            );
        }
        digest.update(&buffer[..count]);
        snapshot
            .write_all(&buffer[..count])
            .with_context(|| format!("write private {label} snapshot"))?;
    }
    snapshot
        .flush()
        .with_context(|| format!("flush private {label} snapshot"))?;
    snapshot
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind private {label} snapshot"))?;
    Ok((snapshot, (hex_lower(&digest.finalize()), size)))
}

fn sha256(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn require_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be a 64-character lowercase SHA-256");
    }
    Ok(())
}

fn decode_sha256(value: &str) -> Result<[u8; 32]> {
    require_sha256(value, "SHA-256")?;
    let mut result = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        result[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(result)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => bail!("invalid lowercase hexadecimal digit"),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Minimal streaming SHA-1 used only to reconstruct Git object IDs without
/// adding another release dependency. It is not used for security decisions;
/// all artifact/content integrity decisions use SHA-256.
struct Sha1 {
    state: [u32; 5],
    bytes: u64,
    buffer: [u8; 64],
    buffered: usize,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
            bytes: 0,
            buffer: [0; 64],
            buffered: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .expect("SHA-1 input length overflow");
        if self.buffered != 0 {
            let needed = 64 - self.buffered;
            let copied = needed.min(bytes.len());
            self.buffer[self.buffered..self.buffered + copied].copy_from_slice(&bytes[..copied]);
            self.buffered += copied;
            bytes = &bytes[copied..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
        while bytes.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&bytes[..64]);
            self.compress(&block);
            bytes = &bytes[64..];
        }
        self.buffer[..bytes.len()].copy_from_slice(bytes);
        self.buffered = bytes.len();
    }

    fn finalize(mut self) -> [u8; 20] {
        let bit_length = self
            .bytes
            .checked_mul(8)
            .expect("SHA-1 bit length overflow");
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
            self.buffered = 0;
        }
        self.buffer[self.buffered..56].fill(0);
        self.buffer[56..].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut output = [0u8; 20];
        for (chunk, word) in output.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut words = [0u32; 80];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(chunk.try_into().expect("four-byte SHA-1 word"));
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (index, word) in words.into_iter().enumerate() {
            let (function, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{manifest_for_mode, PackageTarget, PluginMetadata, PROJECT_LICENSE_TEXT};
    use crate::package::{
        embedded_preview_activation_files, PreviewActivationFileBinding,
        PreviewActivationPackageBinding, PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH,
        PREVIEW_ACTIVATION_BINDING_SCHEMA_VERSION, PREVIEW_ACTIVATION_DIRECTORY,
    };
    use distribution_approval::{
        serialize_windows_preview_build_attestation, WindowsPreviewBuildAttestation,
        WindowsPreviewBuildSourceIdentity, WindowsPreviewBuildSourceIdentityInput,
        WindowsPreviewBuildSubject, WindowsPreviewNativeBuild, WindowsPreviewNativeBuildInput,
        WindowsPreviewUnsignedPreflight,
    };
    use serde_json::{json, Value};
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    const TEST_WINDOWS_RELEASE_VERSION: &str = "1.0.0";
    const TEST_WINDOWS_PREVIEW_VERSION: &str = "0.0.1";
    const TEST_PREVIEW_WORKFLOW: &[u8] = b"name: Synthetic Preview workflow\n";

    struct DynamicFixture {
        _temp: tempfile::TempDir,
        options: ApprovalVerificationOptions,
        approval: Value,
        mcpb_entries: BTreeMap<String, (Vec<u8>, u32)>,
        source_entries: BTreeMap<String, (Vec<u8>, u32)>,
    }

    impl DynamicFixture {
        fn new() -> Self {
            Self::new_for_mode(DistributionMode::Release)
        }

        fn new_preview() -> Self {
            Self::new_for_mode(DistributionMode::Preview)
        }

        fn new_for_mode(package_mode: DistributionMode) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let approval_path = temp.path().join("approval.json");
            let mcpb_path = temp.path().join("candidate.mcpb");
            let source_archive_path = temp.path().join("source.zip");
            let source_closure_sbom_path = temp.path().join("source-closure.spdx.json");
            let build_attestation_path = temp.path().join("build-attestation.json");

            let commit = "d".repeat(40);
            let input_closure = "e".repeat(64);
            let toolchain = b"[toolchain]\nchannel = \"1.88.0\"\n".to_vec();
            let build_recipe = render_windows_x86_64_build_recipe(
                "1.88.0",
                GitObjectFormat::Sha1,
                &commit,
                package_mode,
            )
            .unwrap();
            let release_version = match package_mode {
                DistributionMode::Release => TEST_WINDOWS_RELEASE_VERSION,
                DistributionMode::Preview => TEST_WINDOWS_PREVIEW_VERSION,
            };
            let supplement = b"test RMCP combined licence\n".to_vec();
            let checksums = [
                ("acadrust", "0.4.1", "a".repeat(64)),
                ("flate2", "1.1.9", "b".repeat(64)),
                ("rmcp", "1.7.0", "c".repeat(64)),
            ];
            let mut cargo_lock = format!(
                "version = 4\n\n\
                 [[package]]\nname = \"autocad-mcp\"\nversion = \"{release_version}\"\n\n\
                 [[package]]\nname = \"autolisp-lsp\"\nversion = \"0.1.0\"\n\n"
            )
            .into_bytes();
            for (name, version, checksum) in &checksums {
                cargo_lock.extend_from_slice(
                    format!(
                        "[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n\
                         source = \"{REGISTRY_SOURCE}\"\nchecksum = \"{checksum}\"\n\n"
                    )
                    .as_bytes(),
                );
            }
            let cargo_lock_sha256 = sha256(&cargo_lock);

            let source_sbom = test_source_sbom(&checksums);
            let source_closure_sbom = test_source_closure_sbom(
                &checksums,
                &cargo_lock_sha256,
                &input_closure,
                release_version,
            );
            let notices = b"test third-party notices\n".to_vec();
            let project_license = PROJECT_LICENSE_TEXT.to_vec();
            let schema = OWNER_DISTRIBUTION_APPROVAL_SCHEMA.to_vec();
            let mut attestation = b"{\"test\":\"build attestation\"}\n".to_vec();
            let provenance = serde_json::to_vec(&json!({
                "sources": [{
                    "id": "rmcp-rust-sdk-license-3529c367",
                    "tracked_path": "plugin/.third-party/license-supplements/rmcp-1.7.0-LICENSE.txt",
                    "byte_length": supplement.len(),
                    "sha256": sha256(&supplement)
                }],
                "package_bindings": [{
                    "package": {
                        "name": "rmcp",
                        "version": "1.7.0",
                        "archive_sha256": "c".repeat(64),
                        "declared_license": "MPL-2.0"
                    },
                    "source_id": "rmcp-rust-sdk-license-3529c367"
                }]
            }))
            .unwrap();
            let policy = serde_json::to_vec(&json!({
                "reviewed_cargo_lock_sha256": cargo_lock_sha256,
                "reviewed_input_closure_sha256": input_closure,
                "expected_sbom_sha256": sha256(&source_sbom),
                "expected_windows_source_closure_sbom_sha256": sha256(&source_closure_sbom),
                "expected_notices_sha256": sha256(&notices),
                "expected_license_provenance_sha256": sha256(&provenance),
                "expected_total_packages": 3,
                "expected_third_party_packages": 3,
                "expected_windows_source_closure_packages": 5,
                "expected_windows_source_closure_third_party_packages": 3,
                "allowed_registry_sources": [REGISTRY_SOURCE],
                "owner_distribution_approval": {
                    "mode": "detached_per_distribution_set",
                    "contract_schema_version": distribution_approval::APPROVAL_SCHEMA_VERSION,
                    "contract_schema_path": "crates/distribution/approval/schemas/owner-distribution-approval.schema.json",
                    "contract_schema_sha256": sha256(&schema),
                    "required_for": [
                        "public_binary_distribution",
                        "public_source_distribution"
                    ]
                }
            }))
            .unwrap();

            let server = b"test Windows MCP server executable\n".to_vec();
            let lsp = b"test Windows AutoLISP LSP executable\n".to_vec();
            let plugin_metadata = PluginMetadata {
                name: "autocad-mcp".to_owned(),
                version: release_version.to_owned(),
                description: "Test AutoCAD MCP package".to_owned(),
                license: "GPL-3.0-or-later".to_owned(),
                author_name: "andagni".to_owned(),
            };
            let manifest_mode = match package_mode {
                DistributionMode::Release => PackageMode::Release,
                DistributionMode::Preview => PackageMode::Preview,
            };
            let mut mcpb_manifest_value =
                manifest_for_mode(PackageTarget::WindowsX64, manifest_mode, &plugin_metadata);
            if package_mode == DistributionMode::Release {
                mcpb_manifest_value.server.mcp_config.env.insert(
                    "AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH".to_owned(),
                    Value::String(
                        "${__dirname}/plugin/resources/xref-certification/certified-profile.arg"
                            .to_owned(),
                    ),
                );
            }
            let mcpb_manifest = serde_json::to_vec_pretty(&mcpb_manifest_value).unwrap();
            let plugin_descriptor = serde_json::to_vec(&json!({
                "name": plugin_metadata.name,
                "version": plugin_metadata.version,
                "description": plugin_metadata.description,
                "license": plugin_metadata.license,
                "author": {"name": plugin_metadata.author_name}
            }))
            .unwrap();
            let mcp_descriptor = br#"{"mcpServers":{"autocad-mcp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autocad-mcp","args":["serve"]}}}"#.to_vec();
            let lsp_descriptor = br#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp.exe","args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"stdio"}}"#.to_vec();
            let autocad_skill = b"# Test AutoCAD MCP skill\n".to_vec();
            let autolisp_skill = b"# Test AutoLISP skill\n".to_vec();
            let autolisp_index = br#"{"schema_version":1,"symbols":[{"name":"sample","kind":"builtin","signature":"(sample)","summary":"A sample symbol.","detail":null,"source":"plugin/skills/autolisp/references/guide.md","completion":true}]}"#.to_vec();
            let autolisp_guide = b"# Test AutoLISP guide\n".to_vec();
            let documentation_provenance = serde_json::to_vec_pretty(&json!({
                "schema_version": 1,
                "reference_root": "plugin/skills/autolisp",
                "copyright_holder": "andagni",
                "license": "GPL-3.0-or-later",
                "sources": [{
                    "id": "official-factual-reference",
                    "title": "Official factual reference",
                    "url": "https://example.test/reference",
                    "version": "reviewed snapshot 1",
                    "reviewed_on": "2026-07-26",
                    "rights_basis": "facts_only_no_source_expression_redistributed"
                }],
                "artifacts": [
                    {
                        "path": "SKILL.md",
                        "sha256": sha256(&autolisp_skill),
                        "kind": "markdown",
                        "disposition": "first_party_factual_synthesis",
                        "source_ids": ["official-factual-reference"]
                    },
                    {
                        "path": "references/autolisp-lsp-index.json",
                        "sha256": sha256(&autolisp_index),
                        "kind": "autolisp_lsp_index",
                        "disposition": "first_party_curated_index",
                        "source_ids": ["official-factual-reference"]
                    },
                    {
                        "path": "references/guide.md",
                        "sha256": sha256(&autolisp_guide),
                        "kind": "markdown",
                        "disposition": "first_party_factual_synthesis",
                        "source_ids": ["official-factual-reference"]
                    }
                ]
            }))
            .unwrap();
            let mut mcpb_entries = BTreeMap::from([
                ("manifest.json".to_owned(), (mcpb_manifest, 0o644)),
                (
                    "plugin/.claude-plugin/plugin.json".to_owned(),
                    (plugin_descriptor, 0o644),
                ),
                ("plugin/.mcp.json".to_owned(), (mcp_descriptor, 0o644)),
                ("plugin/.lsp.json".to_owned(), (lsp_descriptor, 0o644)),
                (
                    "plugin/CHANGELOG.md".to_owned(),
                    (b"# Test changelog\n".to_vec(), 0o644),
                ),
                (
                    "plugin/THIRD_PARTY_LICENSES.txt".to_owned(),
                    (notices.clone(), 0o644),
                ),
                (
                    "plugin/LICENSE".to_owned(),
                    (project_license.clone(), 0o644),
                ),
                (
                    "plugin/bin/autocad-mcp.exe".to_owned(),
                    (server.clone(), 0o755),
                ),
                (
                    "plugin/bin/autolisp-lsp.exe".to_owned(),
                    (lsp.clone(), 0o755),
                ),
                (
                    "plugin/.third-party/third-party-license-policy.json".to_owned(),
                    (policy.clone(), 0o644),
                ),
                (
                    "plugin/.third-party/third-party-license-provenance.json".to_owned(),
                    (provenance.clone(), 0o644),
                ),
                (
                    "plugin/.third-party/source-lock.spdx.json".to_owned(),
                    (source_sbom.clone(), 0o644),
                ),
                (
                    PACKAGED_WINDOWS_SOURCE_CLOSURE_SBOM_PATH.to_owned(),
                    (source_closure_sbom.clone(), 0o644),
                ),
                (
                    PACKAGED_APPROVAL_SCHEMA_PATH.to_owned(),
                    (schema.clone(), 0o644),
                ),
                (
                    "plugin/skills/autocad-mcp/SKILL.md".to_owned(),
                    (autocad_skill, 0o644),
                ),
                (
                    "plugin/skills/autolisp/SKILL.md".to_owned(),
                    (autolisp_skill, 0o644),
                ),
                (
                    "plugin/skills/autolisp/references/autolisp-lsp-index.json".to_owned(),
                    (autolisp_index, 0o644),
                ),
                (
                    "plugin/skills/autolisp/references/documentation-provenance.json".to_owned(),
                    (documentation_provenance, 0o644),
                ),
                (
                    "plugin/skills/autolisp/references/guide.md".to_owned(),
                    (autolisp_guide, 0o644),
                ),
            ]);
            if package_mode == DistributionMode::Preview {
                add_preview_activation_entries(&mut mcpb_entries, &server);
            }
            write_test_zip(&mcpb_path, &mcpb_entries, CompressionMethod::Deflated);

            let mut workspace_files = BTreeMap::from([
                ("Cargo.lock".to_owned(), (cargo_lock.clone(), 0o644)),
                ("rust-toolchain.toml".to_owned(), (toolchain.clone(), 0o644)),
                (
                    "plugin/.third-party/license-supplements/rmcp-1.7.0-LICENSE.txt".to_owned(),
                    (supplement.clone(), 0o644),
                ),
            ]);
            if package_mode == DistributionMode::Preview {
                workspace_files.insert(
                    crate::preview_build_attestation::PREVIEW_WORKFLOW_REPOSITORY_PATH.to_owned(),
                    (TEST_PREVIEW_WORKFLOW.to_vec(), 0o644),
                );
            }
            let source_tree_oid = test_git_tree_oid(&workspace_files);
            let workspace_tree_sha256 = test_tree_digest(&workspace_files);
            let mut source_entries = workspace_files
                .iter()
                .map(|(path, value)| (format!("workspace/{path}"), value.clone()))
                .collect::<BTreeMap<_, _>>();
            source_entries.insert(
                OFFLINE_CONFIG_PATH.to_owned(),
                (EXPECTED_OFFLINE_CONFIG.to_vec(), 0o644),
            );
            source_entries.insert(BUILD_RECIPE_PATH.to_owned(), (build_recipe.clone(), 0o644));

            let mut vendor_manifests = BTreeMap::new();
            for (name, version, checksum) in &checksums {
                let cargo_toml =
                    format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n").into_bytes();
                let checksum_value = json!({
                    "files": {"Cargo.toml": sha256(&cargo_toml)},
                    "package": checksum
                });
                let mut checksum_bytes = serde_json::to_vec(&checksum_value).unwrap();
                checksum_bytes.push(b'\n');
                let relative = BTreeMap::from([
                    ("Cargo.toml".to_owned(), (cargo_toml, 0o644)),
                    (".cargo-checksum.json".to_owned(), (checksum_bytes, 0o644)),
                ]);
                let vendor_path = format!("vendor/{name}-{version}");
                for (path, value) in &relative {
                    source_entries.insert(format!("{vendor_path}/{path}"), value.clone());
                }
                vendor_manifests.insert(
                    (*name).to_owned(),
                    json!({
                        "path": vendor_path,
                        "crate_archive_sha256": checksum,
                        "file_count": relative.len(),
                        "tree_sha256": test_tree_digest(&relative)
                    }),
                );
            }

            let manifest_value = json!({
                "schema_version": 3,
                "artifact_kind": "autocad-mcp-windows-x86_64-build-source",
                "git_object_format": "sha1",
                "source_commit": commit,
                "source_tree_oid": source_tree_oid,
                "cargo_lock_sha256": cargo_lock_sha256,
                "dependency_input_closure_sha256": input_closure,
                "rust_toolchain_sha256": sha256(&toolchain),
                "build_recipe_sha256": sha256(&build_recipe),
                "rust_toolchain": "1.88.0",
                "target": WINDOWS_TARGET,
                "profile": "release",
                "package_mode": package_mode,
                "cargo_incremental": false,
                "roots": [
                    test_root_manifest(
                        "autocad-mcp",
                        release_version,
                        "crates/autocad-mcp/Cargo.toml",
                        true,
                        package_mode
                    ),
                    test_root_manifest(
                        "autolisp-lsp",
                        "0.1.0",
                        "crates/autolisp-lsp/Cargo.toml",
                        false,
                        package_mode
                    )
                ],
                "packages": [
                    test_registry_manifest("acadrust", "0.4.1", &checksums[0].2, &vendor_manifests),
                    test_workspace_manifest(
                        "autocad-mcp",
                        release_version,
                        "autocad-mcp"
                    ),
                    test_workspace_manifest("autolisp-lsp", "0.1.0", "autolisp-lsp"),
                    test_registry_manifest("flate2", "1.1.9", &checksums[1].2, &vendor_manifests),
                    test_registry_manifest("rmcp", "1.7.0", &checksums[2].2, &vendor_manifests)
                ],
                "workspace": {
                    "path": "workspace",
                    "file_count": workspace_files.len(),
                    "tree_sha256": workspace_tree_sha256,
                    "digest_method": TREE_DIGEST_METHOD
                },
                "generated_files": [
                    {
                        "path": OFFLINE_CONFIG_PATH,
                        "sha256": sha256(EXPECTED_OFFLINE_CONFIG),
                        "bytes": EXPECTED_OFFLINE_CONFIG.len()
                    },
                    {
                        "path": BUILD_RECIPE_PATH,
                        "sha256": sha256(&build_recipe),
                        "bytes": build_recipe.len()
                    }
                ],
                "exclusions": test_exclusions(),
                "archive_policy": {
                    "format": "ZIP32",
                    "compression": "stored",
                    "entry_order": "ascending UTF-8 path",
                    "timestamp": "1980-01-01T00:00:00Z",
                    "regular_file_modes": ["0644", "0755"],
                    "zip64": false
                }
            });
            let mut manifest_bytes = serde_json::to_vec_pretty(&manifest_value).unwrap();
            manifest_bytes.push(b'\n');
            source_entries.insert(
                SOURCE_MANIFEST_PATH.to_owned(),
                (manifest_bytes.clone(), 0o644),
            );
            write_test_zip(
                &source_archive_path,
                &source_entries,
                CompressionMethod::Stored,
            );
            if package_mode == DistributionMode::Preview {
                let source_archive = fs::read(&source_archive_path).unwrap();
                let unsigned_server_sha256 = sha256(b"unsigned Preview server");
                let unsigned_lsp_sha256 = sha256(b"unsigned Preview LSP");
                let source_identity = WindowsPreviewBuildSourceIdentity::new(
                    WindowsPreviewBuildSourceIdentityInput {
                        git_object_format: GitObjectFormat::Sha1,
                        git_commit_oid: commit.clone(),
                        git_tree_oid: source_tree_oid.clone(),
                        source_bundle_manifest_sha256: sha256(&manifest_bytes),
                        cargo_lock_sha256: sha256(&cargo_lock),
                        dependency_input_closure_sha256: input_closure.clone(),
                        rust_toolchain_sha256: sha256(&toolchain),
                        build_recipe_sha256: sha256(&build_recipe),
                    },
                )
                .unwrap();
                let native_build = WindowsPreviewNativeBuild::new(WindowsPreviewNativeBuildInput {
                    workflow_sha256: sha256(TEST_PREVIEW_WORKFLOW),
                    run_id: 1234,
                    run_attempt: 2,
                    compiler: "rustc 1.97.0 (test); host: x86_64-pc-windows-msvc".to_owned(),
                    preview_build_id: "8".repeat(64),
                    certified_arg_sha256: "9".repeat(64),
                    certified_arg_policy_sha256: "a".repeat(64),
                })
                .unwrap();
                let unsigned_preflight = WindowsPreviewUnsignedPreflight::new(
                    sha256(b"synthetic unsigned preflight"),
                    unsigned_server_sha256.clone(),
                    unsigned_lsp_sha256.clone(),
                )
                .unwrap();
                let source_subject = WindowsPreviewBuildSubject::source_archive(
                    sha256(&source_archive),
                    source_archive.len() as u64,
                )
                .unwrap();
                let lsp_subject = WindowsPreviewBuildSubject::windows_lsp(
                    sha256(&lsp),
                    lsp.len() as u64,
                    unsigned_lsp_sha256,
                )
                .unwrap();
                let server_subject = WindowsPreviewBuildSubject::windows_server(
                    sha256(&server),
                    server.len() as u64,
                    unsigned_server_sha256,
                )
                .unwrap();
                attestation = serialize_windows_preview_build_attestation(
                    &WindowsPreviewBuildAttestation::new(
                        source_identity,
                        native_build,
                        unsigned_preflight,
                        [source_subject, lsp_subject, server_subject],
                    )
                    .unwrap(),
                )
                .unwrap();
            }
            fs::write(&source_closure_sbom_path, &source_closure_sbom).unwrap();
            fs::write(&build_attestation_path, &attestation).unwrap();

            let mut approval = test_approval_value(
                &policy,
                &source_sbom,
                &source_closure_sbom,
                &notices,
                &provenance,
                &project_license,
                &schema,
                &attestation,
                &supplement,
                &server,
                &lsp,
                &manifest_bytes,
                &cargo_lock,
                &toolchain,
                &build_recipe,
                &commit,
                &source_tree_oid,
                &input_closure,
                package_mode,
                release_version,
            );
            bind_artifact_file(&mut approval, "windows-mcpb", &mcpb_path);
            bind_artifact_file(&mut approval, "source-archive", &source_archive_path);
            fs::write(
                &approval_path,
                serde_json::to_vec_pretty(&approval).unwrap(),
            )
            .unwrap();

            Self {
                _temp: temp,
                options: ApprovalVerificationOptions {
                    approval_path,
                    mcpb_path,
                    source_archive_path,
                    source_closure_sbom_path,
                    build_attestation_path,
                },
                approval,
                mcpb_entries,
                source_entries,
            }
        }

        fn write_approval(&self) {
            fs::write(
                &self.options.approval_path,
                serde_json::to_vec_pretty(&self.approval).unwrap(),
            )
            .unwrap();
        }

        fn rebind_outer_artifact(&mut self, artifact_id: &str, path: &Path) {
            bind_artifact_file(&mut self.approval, artifact_id, path);
            self.write_approval();
        }

        fn rewrite_mcpb_and_rebind(&mut self) {
            write_test_zip(
                &self.options.mcpb_path,
                &self.mcpb_entries,
                CompressionMethod::Deflated,
            );
            let mcpb_path = self.options.mcpb_path.clone();
            self.rebind_outer_artifact("windows-mcpb", &mcpb_path);
        }

        fn replace_build_attestation_and_rebind(&mut self, attestation: Vec<u8>) {
            fs::write(&self.options.build_attestation_path, &attestation).unwrap();
            let file_binding =
                &mut self.approval["evidence_bindings"]["build_attestations"][0]["file"];
            file_binding["sha256"] = json!(sha256(&attestation));
            file_binding["size_bytes"] = json!(attestation.len());
            let path = self.options.build_attestation_path.clone();
            self.rebind_outer_artifact("windows-build", &path);
        }

        fn mutate_source_manifest(&mut self, mutate: impl FnOnce(&mut Value)) {
            let mut manifest: Value =
                serde_json::from_slice(&self.source_entries[SOURCE_MANIFEST_PATH].0).unwrap();
            mutate(&mut manifest);
            let mut manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
            manifest_bytes.push(b'\n');
            self.source_entries.insert(
                SOURCE_MANIFEST_PATH.to_owned(),
                (manifest_bytes.clone(), 0o644),
            );
            write_test_zip(
                &self.options.source_archive_path,
                &self.source_entries,
                CompressionMethod::Stored,
            );
            self.approval["source_identity"]["source_bundle_manifest_sha256"] =
                json!(sha256(&manifest_bytes));
            let source_path = self.options.source_archive_path.clone();
            self.rebind_outer_artifact("source-archive", &source_path);
        }

        fn replace_build_recipe_and_rebind(&mut self, build_recipe: Vec<u8>) {
            self.source_entries
                .insert(BUILD_RECIPE_PATH.to_owned(), (build_recipe.clone(), 0o644));
            let build_recipe_sha256 = sha256(&build_recipe);
            self.approval["source_identity"]["build_recipe_sha256"] =
                json!(build_recipe_sha256.clone());
            self.mutate_source_manifest(|manifest| {
                manifest["build_recipe_sha256"] = json!(build_recipe_sha256);
                let generated = manifest["generated_files"].as_array_mut().unwrap();
                let recipe = generated
                    .iter_mut()
                    .find(|entry| entry["path"] == BUILD_RECIPE_PATH)
                    .unwrap();
                recipe["sha256"] = json!(build_recipe_sha256);
                recipe["bytes"] = json!(build_recipe.len());
            });
        }
    }

    fn add_preview_activation_entries(
        entries: &mut BTreeMap<String, (Vec<u8>, u32)>,
        server: &[u8],
    ) {
        let files = embedded_preview_activation_files().unwrap();
        let mut inventory = Vec::with_capacity(files.len());
        for (relative_path, bytes) in &files {
            entries.insert(
                format!("{PREVIEW_ACTIVATION_DIRECTORY}/{relative_path}"),
                (bytes.clone(), 0o644),
            );
            inventory.push(PreviewActivationFileBinding {
                path: relative_path.clone(),
                sha256: sha256(bytes),
            });
        }
        let binding = PreviewActivationPackageBinding {
            schema_version: PREVIEW_ACTIVATION_BINDING_SCHEMA_VERSION,
            preview_binary_sha256: sha256(server),
            catalogue_sha256: sha256(
                files
                    .get("autocad-activation-catalogue.json")
                    .expect("embedded Preview activation bundle contains its catalogue"),
            ),
            files: inventory,
        };
        let mut binding_bytes = serde_json::to_vec_pretty(&binding).unwrap();
        binding_bytes.push(b'\n');
        entries.insert(
            PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH.to_owned(),
            (binding_bytes, 0o644),
        );
    }

    fn test_root_manifest(
        name: &str,
        version: &str,
        manifest_path: &str,
        no_default_features: bool,
        package_mode: DistributionMode,
    ) -> Value {
        let mut arguments = vec![
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--filter-platform",
            WINDOWS_TARGET,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        if no_default_features {
            arguments.push("--no-default-features".to_owned());
            if package_mode == DistributionMode::Preview {
                arguments.extend(["--features".to_owned(), "preview".to_owned()]);
            }
        }
        arguments.extend(["--manifest-path".to_owned(), manifest_path.to_owned()]);
        json!({
            "name": name,
            "version": version,
            "manifest_path": manifest_path,
            "cargo_metadata_arguments": arguments,
            "dependency_kinds": ["normal", "build"],
            "excluded_dependency_kind": "dev",
            "package_count": 4
        })
    }

    fn test_registry_manifest(
        name: &str,
        version: &str,
        checksum: &str,
        vendors: &BTreeMap<String, Value>,
    ) -> Value {
        json!({
            "name": name,
            "version": version,
            "source": REGISTRY_SOURCE,
            "cargo_lock_checksum": checksum,
            "roots": ["autocad-mcp", "autolisp-lsp"],
            "vendor": vendors[name]
        })
    }

    fn test_workspace_manifest(name: &str, version: &str, root: &str) -> Value {
        json!({
            "name": name,
            "version": version,
            "source": "workspace",
            "cargo_lock_checksum": null,
            "roots": [root],
            "vendor": null
        })
    }

    fn test_exclusions() -> Value {
        json!([
            {
                "package": "acadrust",
                "version": "0.4.1",
                "path": "vendor/acadrust-0.4.1/src/docs/OpenDesign_Specification_for_.dwg_files.pdf",
                "sha256": "1ed2e02722862188120da606e4b6a816fa4014c96de68da2f84a2ecda09461e7",
                "bytes": 2399640,
                "reason": "excluded non-source third-party specification PDF from target source bundle"
            },
            {
                "package": "flate2",
                "version": "1.1.9",
                "path": "vendor/flate2-1.1.9/tests/corrupt-gz-file.bin",
                "sha256": "083dd284aa1621916a2d0f66ea048c8d3ba7a722b22d0d618722633f51e7d39c",
                "bytes": 7128,
                "reason": "excluded non-source binary corruption test fixture from target source bundle"
            }
        ])
    }

    fn test_source_sbom(checksums: &[(&str, &str, String); 3]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "source",
            "packages": test_registry_spdx_packages(checksums)
        }))
        .unwrap()
    }

    fn test_source_closure_sbom(
        checksums: &[(&str, &str, String); 3],
        cargo_lock_sha256: &str,
        input_closure: &str,
        release_version: &str,
    ) -> Vec<u8> {
        let mut packages = vec![
            test_workspace_spdx_package("autocad-mcp", release_version),
            test_workspace_spdx_package("autolisp-lsp", "0.1.0"),
        ];
        packages.extend(test_registry_spdx_packages(checksums));
        let comment = format!(
            "Generated deterministically from Cargo.lock and two exact commands: `cargo metadata --locked --offline --format-version 1 --filter-platform {WINDOWS_TARGET} --no-default-features` for Release, and `cargo metadata --locked --offline --format-version 1 --filter-platform {WINDOWS_TARGET} --no-default-features --features autocad-mcp/preview` for Preview. Generation requires the selected normal/build package and dependency-edge closures of the autocad-mcp and autolisp-lsp product roots to be identical across both modes, excluding development-only edges; any divergence fails closed pending separately reviewed mode-specific evidence. Cargo.lock SHA-256: {cargo_lock_sha256}. This is conservative target build-source evidence, including build scripts and proc macros; it is not a linked-binary or native-object SBOM and does not assert legal approval. Exact executable hashes and native imports require a separate build attestation."
        );
        serde_json::to_vec(&json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "AutoCAD-MCP Windows x64 product build-source closure",
            "documentNamespace": format!(
                "https://andagni.invalid/spdx/autocad-mcp/windows-x64-source-build-closure-{input_closure}"
            ),
            "creationInfo": {"comment": comment},
            "documentDescribes": [
                "SPDXRef-Package-autocad-mcp",
                "SPDXRef-Package-autolisp-lsp"
            ],
            "packages": packages
        }))
        .unwrap()
    }

    fn test_registry_spdx_packages(checksums: &[(&str, &str, String); 3]) -> Vec<Value> {
        checksums
            .iter()
            .map(|(name, version, checksum)| {
                json!({
                    "SPDXID": format!("SPDXRef-Package-{name}"),
                    "name": name,
                    "versionInfo": version,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": false,
                    "checksums": [{"algorithm": "SHA256", "checksumValue": checksum}],
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "MPL-2.0",
                    "licenseComments": "Cargo manifest licence metadata: MPL-2.0. The Cargo value is emitted as SPDX licenseDeclared. Test evidence.",
                    "copyrightText": "NOASSERTION",
                    "sourceInfo": format!("Resolved by Cargo.lock from {REGISTRY_SOURCE}; SHA-256 checksum is the Cargo.lock package checksum.")
                })
            })
            .collect()
    }

    fn test_workspace_spdx_package(name: &str, version: &str) -> Value {
        json!({
            "SPDXID": format!("SPDXRef-Package-{name}"),
            "name": name,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "GPL-3.0-or-later",
            "licenseComments": "Cargo manifest licence metadata: GPL-3.0-or-later. The Cargo value is emitted as SPDX licenseDeclared. Test evidence.",
            "copyrightText": "NOASSERTION",
            "sourceInfo": "AutoCAD-MCP workspace package."
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn test_approval_value(
        policy: &[u8],
        source_sbom: &[u8],
        source_closure_sbom: &[u8],
        notices: &[u8],
        provenance: &[u8],
        project_license: &[u8],
        schema: &[u8],
        attestation: &[u8],
        supplement: &[u8],
        server: &[u8],
        lsp: &[u8],
        manifest: &[u8],
        cargo_lock: &[u8],
        toolchain: &[u8],
        build_recipe: &[u8],
        commit: &str,
        tree_oid: &str,
        input_closure: &str,
        package_mode: DistributionMode,
        release_version: &str,
    ) -> Value {
        let (
            release_profile,
            package_mode_name,
            source_archive_name,
            mcpb_name,
            source_closure_path,
            build_attestation_path,
        ) = match package_mode {
            DistributionMode::Release => (
                "initial_windows_public",
                "release",
                "autocad-mcp-windows-x64-build-source.zip",
                "autocad-mcp-windows-x64.mcpb",
                "distribution-evidence/windows-x64-source-closure.spdx.json",
                "distribution-evidence/windows-x64-build.json",
            ),
            DistributionMode::Preview => (
                "initial_windows_preview_public",
                "preview",
                "autocad-mcp-windows-x64-preview-build-source.zip",
                "autocad-mcp-windows-x64-preview.mcpb",
                "distribution-evidence/windows-x64-preview-source-closure.spdx.json",
                "distribution-evidence/windows-x64-preview-build.json",
            ),
        };
        json!({
            "schema_version": distribution_approval::APPROVAL_SCHEMA_VERSION,
            "kind": "owner_distribution_approval",
            "release_profile": release_profile,
            "decision": {
                "status": "approved_for_distribution",
                "authority_kind": "project_owner",
                "authority_identifier": "andagni",
                "decision_id": "ODA-TEST-0001",
                "decided_utc": "2026-07-26T12:00:00Z",
                "supersedes_decision_id": null
            },
            "project": {
                "name": "AutoCAD-MCP",
                "release_version": release_version,
                "project_license_expression": "GPL-3.0-or-later"
            },
            "source_identity": {
                "git_object_format": "sha1",
                "git_commit_oid": commit,
                "git_tree_oid": tree_oid,
                "source_bundle_manifest_sha256": sha256(manifest),
                "cargo_lock_sha256": sha256(cargo_lock),
                "dependency_input_closure_sha256": input_closure,
                "rust_toolchain_sha256": sha256(toolchain),
                "build_recipe_sha256": sha256(build_recipe),
                "build_profile": "release",
                "package_mode": package_mode_name,
                "cargo_incremental": false
            },
            "evidence_bindings": {
                "third_party_license_policy": test_file_binding("plugin/.third-party/third-party-license-policy.json", policy),
                "source_lock_sbom": test_file_binding("plugin/.third-party/source-lock.spdx.json", source_sbom),
                "third_party_notices": test_file_binding("plugin/THIRD_PARTY_LICENSES.txt", notices),
                "third_party_license_provenance": test_file_binding("plugin/.third-party/third-party-license-provenance.json", provenance),
                "project_license": test_file_binding("plugin/LICENSE", project_license),
                "approval_contract_schema": test_file_binding("crates/distribution/approval/schemas/owner-distribution-approval.schema.json", schema),
                "source_closure_sboms": [{
                    "binding_id": "windows-source-closure-sbom",
                    "scope_id": "windows-x64-binary",
                    "target_triple": WINDOWS_TARGET,
                    "covered_source_archive_artifact_id": "source-archive",
                    "artifact_id": "windows-source-closure-sbom",
                    "file": test_file_binding(source_closure_path, source_closure_sbom)
                }],
                "build_attestations": [{
                    "binding_id": "windows-build",
                    "scope_id": "windows-x64-binary",
                    "target_triple": WINDOWS_TARGET,
                    "describes_artifact_ids": ["source-archive", "windows-lsp", "windows-server"],
                    "artifact_id": "windows-build",
                    "file": test_file_binding(build_attestation_path, attestation)
                }],
                "supplemental_license_evidence": [{
                    "binding_id": "rmcp-rust-sdk-license-3529c367",
                    "file": test_file_binding("plugin/.third-party/license-supplements/rmcp-1.7.0-LICENSE.txt", supplement)
                }]
            },
            "artifacts": [
                test_artifact("source-archive", "covered_source_archive", source_archive_name, &[], None),
                test_artifact("windows-build", "build_attestation", build_attestation_path, attestation, None),
                test_artifact("windows-lsp", "autolisp_lsp_executable", "plugin/bin/autolisp-lsp.exe", lsp, Some(("windows-mcpb", "plugin/bin/autolisp-lsp.exe"))),
                test_artifact("windows-mcpb", "mcpb", mcpb_name, &[], None),
                test_artifact("windows-server", "mcp_server_executable", "plugin/bin/autocad-mcp.exe", server, Some(("windows-mcpb", "plugin/bin/autocad-mcp.exe"))),
                test_artifact("windows-source-closure-sbom", "source_closure_sbom", source_closure_path, source_closure_sbom, None)
            ],
            "distribution_scopes": [
                {
                    "scope_id": "windows-x64-binary",
                    "kind": "public_binary_distribution",
                    "target_triple": WINDOWS_TARGET,
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
                    "target_triple": WINDOWS_TARGET,
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
                "determination_id": "windows-test-mpl",
                "scope_ids": ["windows-x64-binary", "windows-x64-source"],
                "packages": [
                    test_determination_package("acadrust", "0.4.1", "a"),
                    test_determination_package("flate2", "1.1.9", "b"),
                    test_determination_package("rmcp", "1.7.0", "c")
                ],
                "declared_value": "MPL-2.0",
                "reviewed_expression": "MPL-2.0",
                "treatment": "included_single_license",
                "distribution_basis_expression": "MPL-2.0",
                "notice_disposition": {"kind": "retained_in_bound_notices"},
                "source_disposition": {"kind": "exact_source_artifact", "artifact_id": "source-archive"},
                "provenance_source_ids": ["rmcp-rust-sdk-license-3529c367"],
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

    fn test_determination_package(name: &str, version: &str, checksum: &str) -> Value {
        json!({
            "name": name,
            "version": version,
            "source": REGISTRY_SOURCE,
            "cargo_package_sha256": checksum.repeat(64),
            "spdx_id": format!("SPDXRef-Package-{name}")
        })
    }

    fn test_file_binding(path: &str, bytes: &[u8]) -> Value {
        json!({
            "logical_path": path,
            "sha256": sha256(bytes),
            "size_bytes": bytes.len()
        })
    }

    fn test_artifact(
        artifact_id: &str,
        role: &str,
        logical_name: &str,
        bytes: &[u8],
        container: Option<(&str, &str)>,
    ) -> Value {
        json!({
            "artifact_id": artifact_id,
            "role": role,
            "logical_name": logical_name,
            "sha256": sha256(bytes),
            "size_bytes": bytes.len().max(1),
            "container": container.map(|(artifact_id, path)| json!({
                "container_artifact_id": artifact_id,
                "container_path": path
            }))
        })
    }

    fn bind_artifact_file(approval: &mut Value, artifact_id: &str, path: &Path) {
        let bytes = fs::read(path).unwrap();
        let artifact = approval["artifacts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|artifact| artifact["artifact_id"] == artifact_id)
            .unwrap();
        artifact["sha256"] = json!(sha256(&bytes));
        artifact["size_bytes"] = json!(bytes.len());
    }

    fn write_test_zip(
        path: &Path,
        entries: &BTreeMap<String, (Vec<u8>, u32)>,
        compression: CompressionMethod,
    ) {
        let file = File::create(path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        for (name, (bytes, mode)) in entries {
            let options = SimpleFileOptions::default()
                .compression_method(compression)
                .unix_permissions(*mode);
            writer.start_file(name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
    }

    fn test_tree_digest(entries: &BTreeMap<String, (Vec<u8>, u32)>) -> String {
        let mut digest = Sha256::new();
        digest.update(TREE_DIGEST_DOMAIN);
        for (path, (bytes, mode)) in entries {
            digest.update((path.len() as u64).to_le_bytes());
            digest.update(path.as_bytes());
            digest.update(mode.to_le_bytes());
            digest.update((bytes.len() as u64).to_le_bytes());
            digest.update(Sha256::digest(bytes));
        }
        hex_lower(&digest.finalize())
    }

    fn test_git_tree_oid(entries: &BTreeMap<String, (Vec<u8>, u32)>) -> String {
        let mut root = BTreeMap::new();
        for (path, (bytes, mode)) in entries {
            let header = format!("blob {}\0", bytes.len());
            let mut sha1 = Sha1::new();
            sha1.update(header.as_bytes());
            sha1.update(bytes);
            let mut sha256 = Sha256::new();
            sha256.update(header.as_bytes());
            sha256.update(bytes);
            insert_git_tree_file(
                &mut root,
                path,
                *mode,
                sha1.finalize(),
                sha256.finalize().into(),
            )
            .unwrap();
        }
        hex_lower(&git_tree_hash_sha1(&root).unwrap())
    }

    fn assert_rebound_recipe_mutation_is_rejected(mutate: impl FnOnce(&str) -> String) {
        let mut fixture = DynamicFixture::new();
        let original =
            String::from_utf8(fixture.source_entries[BUILD_RECIPE_PATH].0.clone()).unwrap();
        let mutated = mutate(&original);
        assert_ne!(mutated, original, "test mutation must change recipe bytes");

        for formerly_checked_substring in [
            "$env:CARGO_INCREMENTAL = \"0\"",
            "--locked --offline --release --target x86_64-pc-windows-msvc",
            "-p autocad-mcp --bin autocad-mcp --no-default-features",
            "-p autolisp-lsp --bin autolisp-lsp",
            "1.88.0",
            "dddddddddddddddddddddddddddddddddddddddd",
        ] {
            assert!(
                mutated.contains(formerly_checked_substring),
                "mutation unexpectedly removed legacy substring {formerly_checked_substring:?}"
            );
        }

        fixture.replace_build_recipe_and_rebind(mutated.into_bytes());
        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("differs byte-for-byte from the canonical Windows recipe"),
            "error: {error}"
        );
    }

    fn assert_duplicate_mcpb_json_is_rejected(path: &str, mutate: impl FnOnce(&[u8]) -> Vec<u8>) {
        let mut fixture = DynamicFixture::new();
        let original = &fixture.mcpb_entries[path].0;
        let mutated = mutate(original);
        assert_ne!(mutated, *original, "test mutation must change {path}");
        fixture
            .mcpb_entries
            .insert(path.to_owned(), (mutated, 0o644));
        fixture.rewrite_mcpb_and_rebind();

        let error = format!(
            "{:#}",
            verify_owner_distribution_approval(&fixture.options).unwrap_err()
        );
        assert!(
            error.contains("duplicate JSON key"),
            "expected strict duplicate-key rejection for {path}; error: {error}"
        );
    }

    #[test]
    fn verifier_accepts_a_dynamic_six_artifact_distribution_set() {
        let fixture = DynamicFixture::new();
        let report = verify_owner_distribution_approval(&fixture.options).unwrap();
        assert_eq!(report.decision_id, "ODA-TEST-0001");
        assert_eq!(report.verified_artifacts, 6);
        assert!(report.distribution_evidence_validated);
        assert!(!report.native_build_attestation_semantics_verified);
        assert_eq!(report.package_mode, DistributionMode::Release);
    }

    #[test]
    fn verifier_accepts_a_complete_dynamic_preview_distribution_set() {
        let fixture = DynamicFixture::new_preview();
        let report = verify_owner_distribution_approval(&fixture.options).unwrap();
        assert_eq!(report.decision_id, "ODA-TEST-0001");
        assert_eq!(report.verified_artifacts, 6);
        assert!(report.distribution_evidence_validated);
        assert_eq!(report.package_mode, DistributionMode::Preview);
        assert!(
            report.native_build_attestation_semantics_verified,
            "Preview verification must complete every build-attestation semantic join"
        );
    }

    #[test]
    fn preview_verifier_rejects_rebound_attestation_source_identity_drift() {
        let mut fixture = DynamicFixture::new_preview();
        let mut attestation: Value =
            serde_json::from_slice(&fs::read(&fixture.options.build_attestation_path).unwrap())
                .unwrap();
        attestation["source_identity"]["git_commit_oid"] = json!("f".repeat(40));
        fixture
            .replace_build_attestation_and_rebind(serde_json::to_vec_pretty(&attestation).unwrap());

        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("source identity does not exactly join"),
            "error: {error}"
        );
    }

    #[test]
    fn preview_verifier_rejects_rebound_attestation_workflow_digest_drift() {
        let mut fixture = DynamicFixture::new_preview();
        let mut attestation: Value =
            serde_json::from_slice(&fs::read(&fixture.options.build_attestation_path).unwrap())
                .unwrap();
        attestation["native_build"]["workflow_sha256"] = json!("f".repeat(64));
        fixture
            .replace_build_attestation_and_rebind(serde_json::to_vec_pretty(&attestation).unwrap());

        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("workflow binding does not match"),
            "error: {error}"
        );
    }

    #[test]
    fn preview_verifier_rejects_rebound_attestation_signed_subject_drift() {
        let mut fixture = DynamicFixture::new_preview();
        let mut attestation: Value =
            serde_json::from_slice(&fs::read(&fixture.options.build_attestation_path).unwrap())
                .unwrap();
        attestation["subjects"][2]["sha256"] = json!("f".repeat(64));
        fixture
            .replace_build_attestation_and_rebind(serde_json::to_vec_pretty(&attestation).unwrap());

        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("windows-server subject does not match"),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_legacy_string_preview_metadata_after_outer_rebinding() {
        let mut fixture = DynamicFixture::new_preview();
        let mut manifest: Value =
            serde_json::from_slice(&fixture.mcpb_entries["manifest.json"].0).unwrap();
        manifest["_meta"] = json!({
            "io.github.andagni.autocad-mcp.package-mode": "preview"
        });
        fixture.mcpb_entries.insert(
            "manifest.json".to_owned(),
            (serde_json::to_vec_pretty(&manifest).unwrap(), 0o644),
        );
        fixture.rewrite_mcpb_and_rebind();

        let error = format!(
            "{:#}",
            verify_owner_distribution_approval(&fixture.options).unwrap_err()
        );
        assert!(
            error.contains("validate closed schema")
                && error.contains("io.github.andagni.autocad-mcp.package-mode"),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_an_mcpb_version_not_approved_for_release() {
        let mut fixture = DynamicFixture::new();
        fixture.approval["project"]["release_version"] = json!("1.0.1");
        fixture.write_approval();

        let error = format!(
            "{:#}",
            verify_owner_distribution_approval(&fixture.options).unwrap_err()
        );
        assert!(
            error.contains(
                "approval-bound MCPB version 1.0.0 does not match owner approval release version 1.0.1"
            ),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_a_source_root_version_not_approved_for_release() {
        let mut fixture = DynamicFixture::new();
        fixture.mutate_source_manifest(|manifest| {
            manifest["roots"][0]["version"] = json!("1.0.1");
        });

        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(
                "source manifest autocad-mcp root version 1.0.1 does not match owner approval release version 1.0.0"
            ),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_an_mcpb_without_its_manifest_after_outer_rebinding() {
        let mut fixture = DynamicFixture::new();
        fixture.mcpb_entries.remove("manifest.json");
        fixture.rewrite_mcpb_and_rebind();

        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("manifest.json") || error.contains("static validation"),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_an_mcpb_with_an_invalid_entry_point_after_outer_rebinding() {
        let mut fixture = DynamicFixture::new();
        let mut manifest: Value =
            serde_json::from_slice(&fixture.mcpb_entries["manifest.json"].0).unwrap();
        manifest["server"]["entry_point"] = json!("plugin/bin/not-the-approved-server.exe");
        fixture.mcpb_entries.insert(
            "manifest.json".to_owned(),
            (serde_json::to_vec_pretty(&manifest).unwrap(), 0o644),
        );
        fixture.rewrite_mcpb_and_rebind();

        let error = format!(
            "{:#}",
            verify_owner_distribution_approval(&fixture.options).unwrap_err()
        );
        assert!(
            error.contains("MCPB entry_point must be plugin/bin/autocad-mcp.exe"),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_an_mcpb_with_an_invalid_plugin_mcp_descriptor() {
        let mut fixture = DynamicFixture::new();
        fixture.mcpb_entries.insert(
            "plugin/.mcp.json".to_owned(),
            (
                br#"{"mcpServers":{"autocad-mcp":{"command":"other","args":["serve"]}}}"#.to_vec(),
                0o644,
            ),
        );
        fixture.rewrite_mcpb_and_rebind();

        let error = format!(
            "{:#}",
            verify_owner_distribution_approval(&fixture.options).unwrap_err()
        );
        assert!(
            error.contains("plugin/.mcp.json autocad-mcp command must be"),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_duplicate_top_level_manifest_keys() {
        assert_duplicate_mcpb_json_is_rejected("manifest.json", |original| {
            let original = std::str::from_utf8(original).unwrap();
            format!(r#"{{"manifest_version":"0.3",{}"#, &original[1..]).into_bytes()
        });
    }

    #[test]
    fn verifier_rejects_duplicate_top_level_plugin_descriptor_keys() {
        assert_duplicate_mcpb_json_is_rejected("plugin/.claude-plugin/plugin.json", |original| {
            let original = std::str::from_utf8(original).unwrap();
            format!(r#"{{"name":"autocad-mcp",{}"#, &original[1..]).into_bytes()
        });
    }

    #[test]
    fn verifier_rejects_duplicate_nested_mcp_descriptor_keys() {
        assert_duplicate_mcpb_json_is_rejected("plugin/.mcp.json", |_| {
            br#"{"mcpServers":{"autocad-mcp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autocad-mcp","command":"${CLAUDE_PLUGIN_ROOT}/bin/autocad-mcp","args":["serve"]}}}"#.to_vec()
        });
    }

    #[test]
    fn verifier_rejects_duplicate_nested_lsp_descriptor_keys() {
        assert_duplicate_mcpb_json_is_rejected("plugin/.lsp.json", |_| {
            br#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp.exe","args":[],"extensionToLanguage":{".lsp":"autolisp",".lsp":"autolisp"},"transport":"stdio"}}"#.to_vec()
        });
    }

    #[test]
    fn verifier_rejects_an_open_ended_plugin_identity_descriptor() {
        let mut fixture = DynamicFixture::new();
        let mut descriptor: Value =
            serde_json::from_slice(&fixture.mcpb_entries["plugin/.claude-plugin/plugin.json"].0)
                .unwrap();
        descriptor["unexpected"] = json!(true);
        fixture.mcpb_entries.insert(
            "plugin/.claude-plugin/plugin.json".to_owned(),
            (serde_json::to_vec(&descriptor).unwrap(), 0o644),
        );
        fixture.rewrite_mcpb_and_rebind();

        let error = format!(
            "{:#}",
            verify_owner_distribution_approval(&fixture.options).unwrap_err()
        );
        assert!(
            error.contains("unknown field") || error.contains("plugin metadata"),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_an_mcpb_with_an_extra_server_environment_override() {
        let mut fixture = DynamicFixture::new();
        let mut manifest: Value =
            serde_json::from_slice(&fixture.mcpb_entries["manifest.json"].0).unwrap();
        manifest["server"]["mcp_config"]["env"]["UNAPPROVED_OVERRIDE"] = json!("1");
        fixture.mcpb_entries.insert(
            "manifest.json".to_owned(),
            (serde_json::to_vec_pretty(&manifest).unwrap(), 0o644),
        );
        fixture.rewrite_mcpb_and_rebind();

        let error = format!(
            "{:#}",
            verify_owner_distribution_approval(&fixture.options).unwrap_err()
        );
        assert!(
            error.contains(
                "approval-bound MCPB server environment does not exactly match the target policy"
            ),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_an_mcpb_with_an_open_ended_lsp_descriptor() {
        let mut fixture = DynamicFixture::new();
        fixture.mcpb_entries.insert(
            "plugin/.lsp.json".to_owned(),
            (
                br#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp.exe","args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"stdio","extra":true},"other":{"command":"other","args":[],"extensionToLanguage":{".x":"other"},"transport":"stdio"}}"#.to_vec(),
                0o644,
            ),
        );
        fixture.rewrite_mcpb_and_rebind();

        let error = format!(
            "{:#}",
            verify_owner_distribution_approval(&fixture.options).unwrap_err()
        );
        assert!(
            error.contains("must contain exactly the autolisp-lsp server")
                || error.contains("fields do not match the closed descriptor"),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_an_mcpb_member_outside_the_closed_allowlist() {
        let mut fixture = DynamicFixture::new();
        fixture.mcpb_entries.insert(
            "plugin/bin/unapproved-helper.exe".to_owned(),
            (b"surplus executable\n".to_vec(), 0o755),
        );
        fixture.rewrite_mcpb_and_rebind();

        let error = format!(
            "{:#}",
            verify_owner_distribution_approval(&fixture.options).unwrap_err()
        );
        assert!(
            error.contains("outside the closed package allowlist"),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_packaged_source_closure_drift_after_outer_rebinding() {
        let mut fixture = DynamicFixture::new();
        fixture.mcpb_entries.insert(
            PACKAGED_WINDOWS_SOURCE_CLOSURE_SBOM_PATH.to_owned(),
            (b"{\"drifted\":true}\n".to_vec(), 0o644),
        );
        fixture.rewrite_mcpb_and_rebind();

        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(
                "packaged Windows source-closure SBOM differs from the approval-bound detached artifact"
            ),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_a_root_without_one_matching_workspace_package() {
        let mut fixture = DynamicFixture::new();
        fixture.mutate_source_manifest(|manifest| {
            let package = manifest["packages"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|package| {
                    package["name"] == "autocad-mcp" && package["source"] == "workspace"
                })
                .unwrap();
            package["source"] = json!(REGISTRY_SOURCE);
        });
        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(
                "build root autocad-mcp must match exactly one workspace package row, found 0"
            ),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_a_root_with_multiple_matching_workspace_packages() {
        let mut fixture = DynamicFixture::new();
        fixture.mutate_source_manifest(|manifest| {
            let packages = manifest["packages"].as_array_mut().unwrap();
            let mut duplicate = packages
                .iter()
                .find(|package| {
                    package["name"] == "autocad-mcp" && package["source"] == "workspace"
                })
                .unwrap()
                .clone();
            duplicate["version"] = json!("1.0.1");
            packages.push(duplicate);
        });
        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(
                "build root autocad-mcp must match exactly one workspace package row, found 2"
            ),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_a_root_version_that_differs_from_its_workspace_package() {
        let mut fixture = DynamicFixture::new();
        fixture.mutate_source_manifest(|manifest| {
            let package = manifest["packages"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|package| {
                    package["name"] == "autocad-mcp" && package["source"] == "workspace"
                })
                .unwrap();
            package["version"] = json!("9.9.9");
        });
        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!(
                "build root autocad-mcp version {TEST_WINDOWS_RELEASE_VERSION} does not match workspace package version 9.9.9"
            )),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_a_workspace_root_package_without_self_membership() {
        let mut fixture = DynamicFixture::new();
        fixture.mutate_source_manifest(|manifest| {
            let package = manifest["packages"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|package| {
                    package["name"] == "autocad-mcp" && package["source"] == "workspace"
                })
                .unwrap();
            package["roots"] = json!(["autolisp-lsp"]);
        });
        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!(
                "workspace package autocad-mcp {TEST_WINDOWS_RELEASE_VERSION} is not a member of its own build root"
            )),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_a_root_package_count_that_differs_from_membership_rows() {
        let mut fixture = DynamicFixture::new();
        fixture.mutate_source_manifest(|manifest| {
            manifest["roots"][0]["package_count"] = json!(5);
        });
        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(
                "build root autocad-mcp package_count 5 does not match its 4 package rows"
            ),
            "error: {error}"
        );
    }

    #[test]
    fn verifier_rejects_a_tampered_nested_executable_even_when_outer_mcpb_is_rebound() {
        let mut fixture = DynamicFixture::new();
        fixture.mcpb_entries.insert(
            "plugin/bin/autocad-mcp.exe".to_owned(),
            (b"tampered Windows executable\n".to_vec(), 0o755),
        );
        fixture.rewrite_mcpb_and_rebind();
        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(error.contains("windows-server"), "error: {error}");
    }

    #[test]
    fn verifier_rejects_a_tampered_source_member_even_when_outer_zip_is_rebound() {
        let mut fixture = DynamicFixture::new();
        fixture.source_entries.insert(
            RUST_TOOLCHAIN_PATH.to_owned(),
            (b"[toolchain]\nchannel = \"1.89.0\"\n".to_vec(), 0o644),
        );
        write_test_zip(
            &fixture.options.source_archive_path,
            &fixture.source_entries,
            CompressionMethod::Stored,
        );
        let source_path = fixture.options.source_archive_path.clone();
        fixture.rebind_outer_artifact("source-archive", &source_path);
        let error = verify_owner_distribution_approval(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("file digests") || error.contains("toolchain"),
            "error: {error}"
        );
    }

    #[test]
    fn canonical_recipe_rejects_incremental_control_present_only_as_a_comment() {
        assert_rebound_recipe_mutation_is_rejected(|recipe| {
            recipe.replace(
                "$env:CARGO_INCREMENTAL = \"0\"\n",
                "# $env:CARGO_INCREMENTAL = \"0\"\n",
            )
        });
    }

    #[test]
    fn canonical_recipe_rejects_a_later_incremental_override() {
        assert_rebound_recipe_mutation_is_rejected(|recipe| {
            format!("{recipe}\n$env:CARGO_INCREMENTAL = \"1\"\n")
        });
    }

    #[test]
    fn canonical_recipe_rejects_altered_toolchain_invocation_syntax() {
        assert_rebound_recipe_mutation_is_rejected(|recipe| {
            recipe.replace(
                "cargo +1.88.0 build --locked",
                "cargo + 1.88.0 build --locked",
            )
        });
    }

    #[test]
    fn canonical_recipe_rejects_an_extra_feature_build_command() {
        assert_rebound_recipe_mutation_is_rejected(|recipe| {
            format!("{recipe}\ncargo +1.88.0 build --features xref-mutations\n")
        });
    }

    #[test]
    fn canonical_recipe_rejects_a_recipe_without_static_msvc_crt() {
        assert_rebound_recipe_mutation_is_rejected(|recipe| {
            recipe.replace(
                "$env:CARGO_ENCODED_RUSTFLAGS = \"-C$([char]0x1f)target-feature=+crt-static\"\n",
                "",
            )
        });
    }

    #[test]
    fn archive_path_policy_rejects_windows_aliases_and_ancestor_conflicts() {
        assert!(validate_archive_path("../escape").is_err());
        assert!(validate_archive_path("workspace/CON.txt").is_err());
        assert!(validate_archive_path("workspace/a\\b").is_err());
        let mut paths = BTreeMap::new();
        insert_archive_path(&mut paths, "workspace/file").unwrap();
        assert!(insert_archive_path(&mut paths, "workspace/file/child").is_err());
        assert!(insert_archive_path(&mut paths, "WORKSPACE/FILE").is_err());
    }

    #[test]
    fn source_scanner_rejects_case_colliding_paths_from_a_dynamic_archive() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("duplicate.zip");
        let file = File::create(&path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o644);
        writer.start_file("WORKSPACE/Cargo.lock", options).unwrap();
        writer.write_all(b"first").unwrap();
        writer.start_file("workspace/Cargo.lock", options).unwrap();
        writer.write_all(b"second").unwrap();
        writer.finish().unwrap();

        let mut file = File::open(path).unwrap();
        let error = scan_archive(
            &mut file,
            ArchiveKind::Source,
            &BTreeSet::new(),
            false,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("duplicate") || error.contains("case-colliding"),
            "error: {error}"
        );
    }

    #[test]
    fn cargo_lock_parser_preserves_workspace_and_registry_identity() {
        let checksum = "a".repeat(64);
        let lock = format!(
            "version = 4\n\n\
             [[package]]\nname = \"local\"\nversion = \"0.1.0\"\n\n\
             [[package]]\nname = \"remote\"\nversion = \"1.2.3\"\n\
             source = \"{REGISTRY_SOURCE}\"\nchecksum = \"{checksum}\"\n"
        );
        let packages = parse_cargo_lock(lock.as_bytes()).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(
            packages
                .get(&PackageKey {
                    name: "remote".to_owned(),
                    version: "1.2.3".to_owned(),
                    source: Some(REGISTRY_SOURCE.to_owned()),
                })
                .unwrap()
                .checksum
                .as_deref(),
            Some(checksum.as_str())
        );
    }

    #[test]
    fn tree_digest_uses_raw_content_digest_not_hex_text() {
        let record = EntryRecord {
            sha256: sha256(b"content"),
            size: 7,
            mode: 0o644,
            git_blob_sha1: [0; 20],
            git_blob_sha256: [0; 32],
        };
        let actual = tree_digest(&[("file.txt", &record)]);
        let mut expected = Sha256::new();
        expected.update(TREE_DIGEST_DOMAIN);
        expected.update(8u64.to_le_bytes());
        expected.update(b"file.txt");
        expected.update(0o644u32.to_le_bytes());
        expected.update(7u64.to_le_bytes());
        expected.update(Sha256::digest(b"content"));
        assert_eq!(actual, hex_lower(&expected.finalize()));
    }

    #[test]
    fn internal_sha1_matches_the_empty_git_blob_oid() {
        let mut sha1 = Sha1::new();
        sha1.update(b"blob 0\0");
        assert_eq!(
            hex_lower(&sha1.finalize()),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
    }

    fn write_clean_host_receipt(fixture: &DynamicFixture) -> PreviewCleanHostVerificationOptions {
        let mcpb_bytes = fs::read(&fixture.options.mcpb_path).unwrap();
        let receipt = distribution_approval::PreviewCleanHostReceipt::new(
            distribution_approval::PreviewCleanHostReceiptInput {
                mcpb_sha256: sha256(&mcpb_bytes),
                mcpb_size_bytes: mcpb_bytes.len() as u64,
                mcp_server_sha256: sha256(&fixture.mcpb_entries[PREVIEW_MCP_SERVER_PATH].0),
                autolisp_lsp_sha256: sha256(&fixture.mcpb_entries[PREVIEW_AUTOLISP_LSP_PATH].0),
                client_version: "0.13.78".to_string(),
                host_os_version: "10.0.26100.4652".to_string(),
                title_block_source_sha256:
                    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
                title_block_installed_sha256:
                    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
                title_block_sentinel_sha256:
                    distribution_approval::PREVIEW_CLEAN_HOST_TITLE_BLOCK_SENTINEL_SHA256
                        .to_string(),
                completed_utc: "2026-07-28T12:34:56Z".to_string(),
            },
        )
        .unwrap();
        let receipt_path = fixture
            .options
            .approval_path
            .with_file_name("preview-clean-host.json");
        fs::write(&receipt_path, receipt.to_pretty_json().unwrap()).unwrap();
        PreviewCleanHostVerificationOptions {
            approval_path: fixture.options.approval_path.clone(),
            mcpb_path: fixture.options.mcpb_path.clone(),
            receipt_path,
        }
    }

    fn mutate_clean_host_receipt(
        options: &PreviewCleanHostVerificationOptions,
        mutate: impl FnOnce(&mut Value),
    ) {
        let mut receipt: Value =
            serde_json::from_slice(&fs::read(&options.receipt_path).unwrap()).unwrap();
        mutate(&mut receipt);
        let mut bytes = serde_json::to_vec_pretty(&receipt).unwrap();
        bytes.push(b'\n');
        fs::write(&options.receipt_path, bytes).unwrap();
    }

    #[test]
    fn preview_mcpb_inspector_reports_exact_outer_and_executable_identities() {
        let fixture = DynamicFixture::new_preview();
        let mcpb_bytes = fs::read(&fixture.options.mcpb_path).unwrap();
        let identity = inspect_preview_mcpb_identity(&fixture.options.mcpb_path).unwrap();

        assert_eq!(identity.release_version, TEST_WINDOWS_PREVIEW_VERSION);
        assert_eq!(identity.mcpb_sha256, sha256(&mcpb_bytes));
        assert_eq!(identity.mcpb_size_bytes, mcpb_bytes.len() as u64);
        assert_eq!(
            identity.mcp_server_sha256,
            sha256(&fixture.mcpb_entries[PREVIEW_MCP_SERVER_PATH].0)
        );
        assert_eq!(
            identity.mcp_server_size_bytes,
            fixture.mcpb_entries[PREVIEW_MCP_SERVER_PATH].0.len() as u64
        );
        assert_eq!(
            identity.autolisp_lsp_sha256,
            sha256(&fixture.mcpb_entries[PREVIEW_AUTOLISP_LSP_PATH].0)
        );
        assert_eq!(
            identity.autolisp_lsp_size_bytes,
            fixture.mcpb_entries[PREVIEW_AUTOLISP_LSP_PATH].0.len() as u64
        );
    }

    #[test]
    fn preview_mcpb_inspector_rejects_a_release_package() {
        let fixture = DynamicFixture::new();
        let error = format!(
            "{:#}",
            inspect_preview_mcpb_identity(&fixture.options.mcpb_path).unwrap_err()
        );
        assert!(
            error.contains("does not match required mode Preview"),
            "error: {error}"
        );
    }

    #[test]
    fn clean_host_verifier_joins_receipt_approval_and_exact_mcpb() {
        let fixture = DynamicFixture::new_preview();
        let options = write_clean_host_receipt(&fixture);
        let expected_receipt_sha256 = sha256(&fs::read(&options.receipt_path).unwrap());
        let report = verify_preview_clean_host_receipt(&options).unwrap();

        assert_eq!(report.decision_id, "ODA-TEST-0001");
        assert_eq!(report.receipt_sha256, expected_receipt_sha256);
        assert!(report.clean_host_acceptance_verified);
        let mcpb_bytes = fs::read(&fixture.options.mcpb_path).unwrap();
        assert_eq!(report.mcpb_sha256, sha256(&mcpb_bytes));
        assert_eq!(report.mcpb_size_bytes, mcpb_bytes.len() as u64);
        assert_eq!(
            report.mcp_server_sha256,
            sha256(&fixture.mcpb_entries[PREVIEW_MCP_SERVER_PATH].0)
        );
        assert_eq!(
            report.autolisp_lsp_sha256,
            sha256(&fixture.mcpb_entries[PREVIEW_AUTOLISP_LSP_PATH].0)
        );
    }

    #[test]
    fn clean_host_verifier_rejects_a_release_owner_approval() {
        let fixture = DynamicFixture::new();
        let options = write_clean_host_receipt(&fixture);
        let error = verify_preview_clean_host_receipt(&options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("requires a Preview owner approval, found release"),
            "error: {error}"
        );
    }

    #[test]
    fn clean_host_verifier_rejects_receipt_mcpb_digest_or_size_drift() {
        for field in ["mcpb_sha256", "mcpb_size_bytes"] {
            let fixture = DynamicFixture::new_preview();
            let options = write_clean_host_receipt(&fixture);
            mutate_clean_host_receipt(&options, |receipt| {
                receipt["package"][field] = if field == "mcpb_sha256" {
                    json!("f".repeat(64))
                } else {
                    json!(1)
                };
            });
            let error = verify_preview_clean_host_receipt(&options)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("owner approval binds"),
                "field {field}; error: {error}"
            );
        }
    }

    #[test]
    fn clean_host_verifier_rejects_each_receipt_executable_digest_drift() {
        for (field, label) in [
            ("mcp_server_sha256", "MCP server"),
            ("autolisp_lsp_sha256", "AutoLISP LSP"),
        ] {
            let fixture = DynamicFixture::new_preview();
            let options = write_clean_host_receipt(&fixture);
            mutate_clean_host_receipt(&options, |receipt| {
                receipt["package"][field] = json!("f".repeat(64));
            });
            let error = verify_preview_clean_host_receipt(&options)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(label) && error.contains("owner approval"),
                "field {field}; error: {error}"
            );
        }
    }

    #[test]
    fn clean_host_verifier_rehashes_the_actual_mcpb() {
        let mut fixture = DynamicFixture::new_preview();
        let options = write_clean_host_receipt(&fixture);
        fixture.mcpb_entries.insert(
            "plugin/CHANGELOG.md".to_owned(),
            (b"# Changed after clean-host acceptance\n".to_vec(), 0o644),
        );
        write_test_zip(
            &fixture.options.mcpb_path,
            &fixture.mcpb_entries,
            CompressionMethod::Deflated,
        );

        let error = verify_preview_clean_host_receipt(&options)
            .unwrap_err()
            .to_string();
        assert!(error.contains("actual MCPB has"), "error: {error}");
    }

    #[test]
    fn clean_host_verifier_hashes_contained_executable_bytes_after_outer_rebinding() {
        let mut fixture = DynamicFixture::new_preview();
        let options = write_clean_host_receipt(&fixture);
        let changed_server = b"changed signed MCP server bytes\n".to_vec();
        fixture.mcpb_entries.insert(
            PREVIEW_MCP_SERVER_PATH.to_owned(),
            (changed_server.clone(), 0o755),
        );
        let mut activation_binding: Value = serde_json::from_slice(
            &fixture.mcpb_entries[PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH].0,
        )
        .unwrap();
        activation_binding["preview_binary_sha256"] = json!(sha256(&changed_server));
        let mut activation_binding_bytes = serde_json::to_vec_pretty(&activation_binding).unwrap();
        activation_binding_bytes.push(b'\n');
        fixture.mcpb_entries.insert(
            PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH.to_owned(),
            (activation_binding_bytes, 0o644),
        );
        write_test_zip(
            &fixture.options.mcpb_path,
            &fixture.mcpb_entries,
            CompressionMethod::Deflated,
        );
        let mcpb_path = fixture.options.mcpb_path.clone();
        fixture.rebind_outer_artifact("windows-mcpb", &mcpb_path);
        let rebound_mcpb = fs::read(&fixture.options.mcpb_path).unwrap();
        mutate_clean_host_receipt(&options, |receipt| {
            receipt["package"]["mcpb_sha256"] = json!(sha256(&rebound_mcpb));
            receipt["package"]["mcpb_size_bytes"] = json!(rebound_mcpb.len());
        });

        let error = verify_preview_clean_host_receipt(&options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("contained MCP server"),
            "expected exact contained-executable join; error: {error}"
        );
    }

    #[test]
    fn clean_host_verifier_uses_the_strict_receipt_parser() {
        let fixture = DynamicFixture::new_preview();
        let options = write_clean_host_receipt(&fixture);
        fs::write(
            &options.receipt_path,
            br#"{"schema_version":1,"schema_version":1}"#,
        )
        .unwrap();

        let error = verify_preview_clean_host_receipt(&options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("duplicate JSON key"),
            "expected strict duplicate-key rejection; error: {error}"
        );
    }
}
