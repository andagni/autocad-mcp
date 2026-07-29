use crate::approval::{
    inspect_preview_mcpb_identity, verify_owner_distribution_approval,
    verify_preview_clean_host_receipt, ApprovalVerificationOptions,
    PreviewCleanHostVerificationOptions,
};
use anyhow::{anyhow, bail, Context, Result};
use distribution_approval::{
    parse_and_validate, parse_preview_clean_host_receipt, DistributionMode, GitObjectFormat,
    PreviewCleanHostReceipt, PreviewPublicationArtifactRole, PreviewPublicationFileBinding,
    PreviewPublicationHandoff, PreviewPublicationSourceIdentity,
    PREVIEW_PUBLICATION_BUILD_ATTESTATION_PATH, PREVIEW_PUBLICATION_CLEAN_HOST_RECEIPT_PATH,
    PREVIEW_PUBLICATION_CURRENT_DISTRIBUTION_RECEIPT_PATH, PREVIEW_PUBLICATION_HANDOFF_KIND,
    PREVIEW_PUBLICATION_MCPB_PATH, PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH,
    PREVIEW_PUBLICATION_PROJECTION_RECEIPT_PATH, PREVIEW_PUBLICATION_PUBLIC_ASSET_PATHS,
    PREVIEW_PUBLICATION_SHA256SUMS_PATH, PREVIEW_PUBLICATION_SOURCE_ARCHIVE_PATH,
    PREVIEW_PUBLICATION_SOURCE_CLOSURE_SBOM_PATH,
};
use release_qualification::{
    parse_and_verify, sign_canonical, KeyRing, KeyState, PinnedKey, SigningKey,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::{Builder as TempFileBuilder, TempDir};
use walkdir::WalkDir;

pub const PREVIEW_PUBLICATION_HANDOFF_PATH: &str = "preview-publication-handoff.json";
pub const PREVIEW_GITHUB_REPOSITORY: &str = "andagni/autocad-mcp";
const PREVIEW_GITHUB_HOST: &str = "github.com";
const PREVIEW_GITHUB_CLI_REPOSITORY: &str = "github.com/andagni/autocad-mcp";
const PREVIEW_GITHUB_PUBLISHER_LOGIN: &str = "andagni";
const PREVIEW_GITHUB_IMMUTABLE_RELEASES_ENDPOINT: &str =
    "repos/andagni/autocad-mcp/immutable-releases";
const GITHUB_API_VERSION: &str = "2026-03-10";
const GITHUB_ACCEPT: &str = "application/vnd.github+json";
const PREVIEW_RELEASE_BODY: &str = "Experimental Preview software; this is not a certified Release.\n\nThe attached deterministic Windows Preview build-source ZIP is the corresponding-source artifact for the MCPB. GitHub-generated source archives are not the build-source deliverable.\n";
const PROJECTION_AUTHOR: &str = "andagni <dev@andagni.invalid>";
const PROJECTION_TIMESTAMP: &str = "1785307643 +0100";
const PROJECTION_MESSAGE: &str = "Initial public development snapshot";
#[cfg(target_os = "macos")]
const TRUSTED_GIT_PROGRAM: &str = "/usr/bin/git";
#[cfg(not(target_os = "macos"))]
const TRUSTED_GIT_PROGRAM: &str = "git";

const MAX_HANDOFF_BYTES: u64 = 1024 * 1024;
const MAX_APPROVAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_PROJECTION_RECEIPT_BYTES: u64 = 4 * 1024;
const MAX_SHA256SUMS_BYTES: u64 = 64 * 1024;
const MAX_DETACHED_EVIDENCE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

const BOUND_FILES: [(PreviewPublicationArtifactRole, &str); 9] = [
    (
        PreviewPublicationArtifactRole::Sha256Sums,
        PREVIEW_PUBLICATION_SHA256SUMS_PATH,
    ),
    (
        PreviewPublicationArtifactRole::PreviewSourceArchive,
        PREVIEW_PUBLICATION_SOURCE_ARCHIVE_PATH,
    ),
    (
        PreviewPublicationArtifactRole::PreviewMcpb,
        PREVIEW_PUBLICATION_MCPB_PATH,
    ),
    (
        PreviewPublicationArtifactRole::CurrentDistributionVerification,
        PREVIEW_PUBLICATION_CURRENT_DISTRIBUTION_RECEIPT_PATH,
    ),
    (
        PreviewPublicationArtifactRole::PreviewBuildAttestation,
        PREVIEW_PUBLICATION_BUILD_ATTESTATION_PATH,
    ),
    (
        PreviewPublicationArtifactRole::PreviewCleanHostReceipt,
        PREVIEW_PUBLICATION_CLEAN_HOST_RECEIPT_PATH,
    ),
    (
        PreviewPublicationArtifactRole::PreviewSourceClosureSbom,
        PREVIEW_PUBLICATION_SOURCE_CLOSURE_SBOM_PATH,
    ),
    (
        PreviewPublicationArtifactRole::OwnerDistributionApproval,
        PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH,
    ),
    (
        PreviewPublicationArtifactRole::PublicationProjectionReceipt,
        PREVIEW_PUBLICATION_PROJECTION_RECEIPT_PATH,
    ),
];

#[derive(Clone, Debug)]
pub struct SealPreviewPublicationHandoffOptions {
    pub repository: PathBuf,
    pub handoff_directory: PathBuf,
    pub key_id: String,
    pub private_key_file: PathBuf,
}

#[derive(Clone, Debug)]
pub struct VerifyPreviewPublicationHandoffOptions {
    pub repository: PathBuf,
    pub handoff_directory: PathBuf,
    pub key_id: String,
    pub public_key_hex: String,
}

#[derive(Clone, Debug)]
pub struct CreatePreviewCleanHostReceiptOptions {
    pub mcpb_path: PathBuf,
    pub client_version: String,
    pub host_os_version: String,
    pub completed_utc: String,
    pub output_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreviewPublicAsset {
    asset_name: String,
    path: PathBuf,
    sha256: String,
    size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPreviewPublicationHandoff {
    key_id: String,
    release_version: String,
    decision_id: String,
    source_commit: String,
    source_authority_sha256: String,
    source_tree_oid: String,
    projection_commit: String,
    public_assets: Vec<PreviewPublicAsset>,
}

impl VerifiedPreviewPublicationHandoff {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn release_version(&self) -> &str {
        &self.release_version
    }

    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    pub fn public_asset_count(&self) -> usize {
        self.public_assets.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileSnapshot {
    sha256: String,
    size_bytes: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(target_os = "windows")]
    volume_serial_number: u64,
    #[cfg(target_os = "windows")]
    file_id: [u8; 16],
    #[cfg(target_os = "windows")]
    last_write_time: i64,
    #[cfg(target_os = "windows")]
    change_time: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SemanticSelection {
    git_object_format: GitObjectFormat,
    source_commit: String,
    source_tree_oid: String,
    projection_commit: String,
    release_version: String,
    decision_id: String,
}

#[derive(Debug)]
struct VerifiedSourceRepository {
    path: PathBuf,
    authority_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionReceipt {
    schema_version: u32,
    source_commit: String,
    source_tree: String,
    projection_commit: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentCandidateIdentity {
    git_object_format: String,
    source_commit: String,
    source_tree_oid: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentDistributionVerification {
    schema_version: u32,
    kind: String,
    current_source_candidate_verified: bool,
    approval_distribution_set_verified: bool,
    exact_candidate_identity_joined: bool,
    native_build_attestation_semantics_verified: bool,
    clean_host_acceptance_verified: bool,
    package_mode: DistributionMode,
    decision_id: String,
    candidate: CurrentCandidateIdentity,
    approval_sha256: String,
    mcpb_sha256: String,
    source_archive_sha256: String,
    source_closure_sbom_sha256: String,
    build_attestation_sha256: String,
    clean_host_receipt_sha256: Option<String>,
}

pub fn create_preview_clean_host_receipt(
    options: &CreatePreviewCleanHostReceiptOptions,
) -> Result<PreviewCleanHostReceipt> {
    let identity = inspect_preview_mcpb_identity(&options.mcpb_path)
        .context("inspect the exact closed Windows Preview MCPB")?;
    let receipt = PreviewCleanHostReceipt::new(
        identity.mcpb_sha256,
        identity.mcpb_size_bytes,
        identity.mcp_server_sha256,
        identity.autolisp_lsp_sha256,
        &options.client_version,
        &options.host_os_version,
        &options.completed_utc,
    )
    .map_err(|error| anyhow!("construct Preview clean-host receipt: {error}"))?;
    let bytes = receipt
        .to_pretty_json()
        .map_err(|error| anyhow!("serialize Preview clean-host receipt: {error}"))?;
    write_fresh_file(&options.output_path, &bytes, "Preview clean-host receipt")?;
    let reparsed_bytes = read_regular_file_bounded(
        &options.output_path,
        MAX_RECEIPT_BYTES,
        "written Preview clean-host receipt",
    )?;
    let reparsed = parse_preview_clean_host_receipt(&reparsed_bytes)
        .map_err(|error| anyhow!("reparse written Preview clean-host receipt: {error}"))?;
    if reparsed != receipt {
        bail!("written Preview clean-host receipt changed during persistence");
    }
    Ok(receipt)
}

pub fn seal_preview_publication_handoff(
    options: &SealPreviewPublicationHandoffOptions,
) -> Result<VerifiedPreviewPublicationHandoff> {
    let root = closed_handoff_root(&options.repository, &options.handoff_directory, false)?;
    require_private_handoff_tree(&root)?;
    let files = inspect_handoff_directory(&root, false)?;
    require_exact_sha256s(&root, &files)?;
    let selection = verify_semantic_selection(&root, &files)?;
    let mut git_executor = ProcessCommandExecutor;
    let source_repository = verify_source_repository(
        &mut git_executor,
        &options.repository,
        selection.git_object_format,
        &selection.source_commit,
        &selection.source_tree_oid,
    )?;
    require_unchanged_inventory(&root, false, &files)?;

    let bindings = BOUND_FILES
        .map(|(role, logical_path)| {
            let snapshot = files
                .get(logical_path)
                .expect("closed inventory contains every bound file");
            PreviewPublicationFileBinding::new(role, snapshot.sha256.clone(), snapshot.size_bytes)
                .map_err(|error| anyhow!("construct Preview publication binding: {error}"))
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let bindings: [PreviewPublicationFileBinding; 9] = bindings
        .try_into()
        .map_err(|_| anyhow!("internal Preview publication inventory cardinality error"))?;
    let source_identity = PreviewPublicationSourceIdentity::new(
        selection.git_object_format,
        &selection.projection_commit,
        &selection.source_tree_oid,
        &source_repository.authority_sha256,
    )
    .map_err(|error| anyhow!("construct projected publication identity: {error}"))?;
    let handoff = PreviewPublicationHandoff::new(
        source_identity,
        &selection.release_version,
        &selection.decision_id,
        bindings,
    )
    .map_err(|error| anyhow!("construct Preview publication handoff: {error}"))?;

    let repository_boundaries = repository_boundaries(&options.repository)?;
    let mut forbidden_key_roots = repository_boundaries;
    forbidden_key_roots.push(root.clone());
    let signing_key = read_detached_signing_key(&options.private_key_file, &forbidden_key_roots)?;
    let public_key = signing_key.verifying_key().to_bytes();
    let pinned = PinnedKey::new(
        &options.key_id,
        PREVIEW_PUBLICATION_HANDOFF_KIND,
        public_key,
        KeyState::Active,
    )
    .map_err(|error| anyhow!("owner publication key policy is invalid: {error}"))?;
    let envelope = sign_canonical(&handoff, &pinned, &signing_key)
        .map_err(|error| anyhow!("sign Preview publication handoff: {error}"))?;
    drop(signing_key);

    let key_ring = KeyRing::new(vec![pinned])
        .map_err(|error| anyhow!("owner publication key policy is invalid: {error}"))?;
    parse_and_verify::<PreviewPublicationHandoff>(&envelope, &key_ring)
        .map_err(|error| anyhow!("self-verify signed Preview publication handoff: {error}"))?;
    write_fresh_file(
        &root.join(PREVIEW_PUBLICATION_HANDOFF_PATH),
        &envelope,
        "Preview publication handoff",
    )?;
    require_private_handoff_tree(&root)?;

    let public_key_hex = encode_lower_hex(&public_key);
    verify_preview_publication_handoff(&VerifyPreviewPublicationHandoffOptions {
        repository: options.repository.clone(),
        handoff_directory: root,
        key_id: options.key_id.clone(),
        public_key_hex,
    })
}

pub fn verify_preview_publication_handoff(
    options: &VerifyPreviewPublicationHandoffOptions,
) -> Result<VerifiedPreviewPublicationHandoff> {
    let root = closed_handoff_root(&options.repository, &options.handoff_directory, true)?;
    require_private_handoff_tree(&root)?;
    let files = inspect_handoff_directory(&root, true)?;
    require_exact_sha256s(&root, &files)?;
    let public_key = decode_lower_hex_32(&options.public_key_hex)
        .context("owner public key must be exactly 64 lowercase hexadecimal characters")?;
    let pinned = PinnedKey::new(
        &options.key_id,
        PREVIEW_PUBLICATION_HANDOFF_KIND,
        public_key,
        KeyState::Active,
    )
    .map_err(|error| anyhow!("owner publication key policy is invalid: {error}"))?;
    let key_ring = KeyRing::new(vec![pinned])
        .map_err(|error| anyhow!("owner publication key policy is invalid: {error}"))?;
    let envelope = read_bound_bytes(
        &root,
        PREVIEW_PUBLICATION_HANDOFF_PATH,
        &files,
        MAX_HANDOFF_BYTES,
    )?;
    let verified = parse_and_verify::<PreviewPublicationHandoff>(&envelope, &key_ring)
        .map_err(|error| anyhow!("verify signed Preview publication handoff: {error}"))?;
    if verified.key_id() != options.key_id {
        bail!("signed Preview publication handoff does not use the explicitly selected key ID");
    }

    let statement = verified.statement();
    for binding in statement.inventory() {
        let snapshot = files.get(binding.logical_path()).ok_or_else(|| {
            anyhow!("signed handoff names a file absent from the closed directory")
        })?;
        if snapshot.sha256 != binding.sha256()
            || snapshot.size_bytes != binding.size_bytes()
            || binding.role().logical_path() != binding.logical_path()
        {
            bail!(
                "signed handoff binding for {} does not match the retained file",
                binding.logical_path()
            );
        }
    }

    let selection = verify_semantic_selection(&root, &files)?;
    if statement.source_identity().git_object_format() != selection.git_object_format
        || statement.source_identity().git_commit_oid() != selection.projection_commit
        || statement.source_identity().git_tree_oid() != selection.source_tree_oid
        || statement.release_version() != selection.release_version
        || statement.decision_id() != selection.decision_id
    {
        bail!(
            "authenticated handoff source, version, or owner decision does not match the reverified evidence set"
        );
    }
    let mut git_executor = ProcessCommandExecutor;
    let source_repository = verify_source_repository(
        &mut git_executor,
        &options.repository,
        selection.git_object_format,
        &selection.source_commit,
        &selection.source_tree_oid,
    )?;
    if statement.source_identity().source_authority_sha256() != source_repository.authority_sha256 {
        bail!("authenticated source authority does not match the selected private repository");
    }
    require_unchanged_inventory(&root, true, &files)?;
    let source_repository_after = verify_source_repository(
        &mut git_executor,
        &source_repository.path,
        selection.git_object_format,
        &selection.source_commit,
        &selection.source_tree_oid,
    )?;
    if source_repository_after.authority_sha256 != source_repository.authority_sha256 {
        bail!("source repository authority changed during handoff verification");
    }

    let public_assets = public_asset_inventory(&root, &files)?;
    Ok(VerifiedPreviewPublicationHandoff {
        key_id: options.key_id.clone(),
        release_version: selection.release_version,
        decision_id: selection.decision_id,
        source_commit: selection.source_commit,
        source_authority_sha256: source_repository.authority_sha256,
        source_tree_oid: selection.source_tree_oid,
        projection_commit: selection.projection_commit,
        public_assets,
    })
}

fn verify_semantic_selection(
    root: &Path,
    files: &BTreeMap<String, FileSnapshot>,
) -> Result<SemanticSelection> {
    let approval_path = root.join(PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH);
    let mcpb_path = root.join(PREVIEW_PUBLICATION_MCPB_PATH);
    let source_path = root.join(PREVIEW_PUBLICATION_SOURCE_ARCHIVE_PATH);
    let sbom_path = root.join(PREVIEW_PUBLICATION_SOURCE_CLOSURE_SBOM_PATH);
    let attestation_path = root.join(PREVIEW_PUBLICATION_BUILD_ATTESTATION_PATH);
    let clean_host_path = root.join(PREVIEW_PUBLICATION_CLEAN_HOST_RECEIPT_PATH);

    let approval_bytes = read_bound_bytes(
        root,
        PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH,
        files,
        MAX_APPROVAL_BYTES,
    )?;
    let approval = parse_and_validate(&approval_bytes)
        .map_err(|error| anyhow!("owner distribution approval is invalid: {error}"))?;
    if approval.source_identity().package_mode() != DistributionMode::Preview {
        bail!("Preview publication handoff requires a Preview owner approval");
    }

    let approval_report = verify_owner_distribution_approval(&ApprovalVerificationOptions {
        approval_path: approval_path.clone(),
        mcpb_path: mcpb_path.clone(),
        source_archive_path: source_path,
        source_closure_sbom_path: sbom_path,
        build_attestation_path: attestation_path,
    })
    .context("reverify the complete owner-approved Preview distribution set")?;
    if approval_report.package_mode != DistributionMode::Preview
        || !approval_report.native_build_attestation_semantics_verified
        || !approval_report.distribution_evidence_validated
    {
        bail!("owner-approved distribution set did not pass the required Preview semantic joins");
    }

    let clean_host_report =
        verify_preview_clean_host_receipt(&PreviewCleanHostVerificationOptions {
            approval_path,
            mcpb_path,
            receipt_path: clean_host_path,
        })
        .context("reverify Preview clean-host acceptance against the exact MCPB and approval")?;
    if !clean_host_report.clean_host_acceptance_verified {
        bail!("Preview clean-host acceptance did not pass its semantic joins");
    }

    let projection_bytes = read_bound_bytes(
        root,
        PREVIEW_PUBLICATION_PROJECTION_RECEIPT_PATH,
        files,
        MAX_PROJECTION_RECEIPT_BYTES,
    )?;
    let projection: ProjectionReceipt =
        parse_closed_json(&projection_bytes, "publication projection receipt")?;
    let current_bytes = read_bound_bytes(
        root,
        PREVIEW_PUBLICATION_CURRENT_DISTRIBUTION_RECEIPT_PATH,
        files,
        MAX_RECEIPT_BYTES,
    )?;
    let current: CurrentDistributionVerification =
        parse_closed_json(&current_bytes, "current-distribution verification")?;
    validate_current_distribution(&current)?;

    let git_object_format = match approval_report.git_object_format.as_str() {
        "sha1" => GitObjectFormat::Sha1,
        "sha256" => GitObjectFormat::Sha256,
        _ => bail!("approval verifier returned an unsupported Git object format"),
    };
    let object_id_length = match git_object_format {
        GitObjectFormat::Sha1 => 40,
        GitObjectFormat::Sha256 => 64,
    };
    for (value, label) in [
        (
            projection.source_commit.as_str(),
            "projection source commit",
        ),
        (projection.source_tree.as_str(), "projection source tree"),
        (
            projection.projection_commit.as_str(),
            "projection public commit",
        ),
    ] {
        require_object_id(value, object_id_length, label)?;
    }
    if projection.schema_version != 1 {
        bail!("publication projection receipt schema_version must equal 1");
    }

    if projection.projection_commit != approval_report.source_commit
        || projection.source_tree != approval_report.source_tree_oid
        || current.candidate.source_commit != approval_report.source_commit
        || current.candidate.source_tree_oid != approval_report.source_tree_oid
        || current.candidate.git_object_format != approval_report.git_object_format
    {
        bail!(
            "projection receipt, current-distribution receipt, and owner approval source identities do not join"
        );
    }
    if current.decision_id != approval_report.decision_id
        || current.decision_id != approval.decision().decision_id()
        || approval.project().release_version().is_empty()
    {
        bail!("current-distribution receipt does not match the approved version and decision");
    }

    let clean_host_digest = current
        .clean_host_receipt_sha256
        .as_deref()
        .ok_or_else(|| anyhow!("Preview current-distribution receipt has no clean-host digest"))?;
    let expected_digests = [
        (
            current.approval_sha256.as_str(),
            approval_report.approval_sha256.as_str(),
            "approval",
        ),
        (
            current.mcpb_sha256.as_str(),
            approval_report.mcpb_sha256.as_str(),
            "MCPB",
        ),
        (
            current.source_archive_sha256.as_str(),
            approval_report.source_archive_sha256.as_str(),
            "source archive",
        ),
        (
            current.source_closure_sbom_sha256.as_str(),
            approval_report.source_closure_sbom_sha256.as_str(),
            "source-closure SBOM",
        ),
        (
            current.build_attestation_sha256.as_str(),
            approval_report.build_attestation_sha256.as_str(),
            "build attestation",
        ),
        (
            clean_host_digest,
            clean_host_report.receipt_sha256.as_str(),
            "clean-host receipt",
        ),
    ];
    for (recorded, verified, label) in expected_digests {
        require_sha256(recorded, label)?;
        if recorded != verified {
            bail!("current-distribution {label} digest does not match reverified bytes");
        }
    }
    if clean_host_report.decision_id != approval_report.decision_id
        || clean_host_report.mcpb_sha256 != approval_report.mcpb_sha256
    {
        bail!("clean-host receipt does not join the selected approval and MCPB");
    }

    Ok(SemanticSelection {
        git_object_format,
        source_commit: projection.source_commit,
        source_tree_oid: approval_report.source_tree_oid,
        projection_commit: projection.projection_commit,
        release_version: approval.project().release_version().to_owned(),
        decision_id: approval_report.decision_id,
    })
}

fn validate_current_distribution(current: &CurrentDistributionVerification) -> Result<()> {
    if current.schema_version != 1
        || current.kind != "current_distribution_verification"
        || !current.current_source_candidate_verified
        || !current.approval_distribution_set_verified
        || !current.exact_candidate_identity_joined
        || !current.native_build_attestation_semantics_verified
        || !current.clean_host_acceptance_verified
        || current.package_mode != DistributionMode::Preview
    {
        bail!("current-distribution verification is not a closed, fully passing Preview result");
    }
    Ok(())
}

fn public_asset_inventory(
    root: &Path,
    files: &BTreeMap<String, FileSnapshot>,
) -> Result<Vec<PreviewPublicAsset>> {
    PREVIEW_PUBLICATION_PUBLIC_ASSET_PATHS
        .iter()
        .copied()
        .chain(std::iter::once(PREVIEW_PUBLICATION_SHA256SUMS_PATH))
        .map(|logical_path| {
            let snapshot = files
                .get(logical_path)
                .ok_or_else(|| anyhow!("closed handoff is missing one public asset"))?;
            let asset_name = public_asset_name(logical_path)?;
            Ok(PreviewPublicAsset {
                asset_name,
                path: root.join(logical_path),
                sha256: snapshot.sha256.clone(),
                size_bytes: snapshot.size_bytes,
            })
        })
        .collect()
}

fn require_exact_sha256s(root: &Path, files: &BTreeMap<String, FileSnapshot>) -> Result<()> {
    let expected = expected_public_sha256s(files)?;
    let actual = read_bound_bytes(
        root,
        PREVIEW_PUBLICATION_SHA256SUMS_PATH,
        files,
        MAX_SHA256SUMS_BYTES,
    )?;
    if actual != expected {
        bail!(
            "SHA256SUMS.txt must exactly cover the six public files in the closed manifest order"
        );
    }
    Ok(())
}

fn expected_public_sha256s(files: &BTreeMap<String, FileSnapshot>) -> Result<Vec<u8>> {
    let mut expected = Vec::new();
    for logical_path in PREVIEW_PUBLICATION_PUBLIC_ASSET_PATHS {
        let snapshot = files
            .get(logical_path)
            .ok_or_else(|| anyhow!("closed handoff is missing a SHA256SUMS subject"))?;
        writeln!(
            &mut expected,
            "{}  {}",
            snapshot.sha256,
            public_asset_name(logical_path)?
        )
        .expect("writing to a Vec cannot fail");
    }
    Ok(expected)
}

fn public_asset_name(logical_path: &str) -> Result<String> {
    Path::new(logical_path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("public asset has a non-portable file name"))
}

fn parse_closed_json<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T> {
    let value = distribution_approval::parse_strict_json(bytes)
        .with_context(|| format!("strictly parse {label}"))?;
    serde_json::from_value(value).with_context(|| format!("validate closed {label} schema"))
}

fn require_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be an exact lowercase SHA-256 digest");
    }
    Ok(())
}

fn require_object_id(value: &str, length: usize, label: &str) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is not a canonical Git object ID");
    }
    Ok(())
}

fn closed_handoff_root(repository: &Path, requested: &Path, signed: bool) -> Result<PathBuf> {
    require_real_directory(requested, "Preview handoff directory")?;
    let root = requested
        .canonicalize()
        .context("canonicalize detached Preview handoff directory")?;
    if is_inside_git_worktree(&root)? {
        bail!("Preview handoff directory must be outside every Git worktree");
    }
    require_directory_detached_from_repository(&root, repository, "Preview handoff directory")?;
    let output = root.join(PREVIEW_PUBLICATION_HANDOFF_PATH);
    if signed != fs::symlink_metadata(&output).is_ok() {
        if signed {
            bail!("closed Preview handoff is missing preview-publication-handoff.json");
        }
        bail!("Preview publication handoff output must be fresh");
    }
    Ok(root)
}

fn require_directory_detached_from_repository(
    directory: &Path,
    repository: &Path,
    label: &str,
) -> Result<()> {
    let directory = directory
        .canonicalize()
        .with_context(|| format!("canonicalize {label}"))?;
    for boundary in repository_boundaries(repository)? {
        if directory.starts_with(&boundary) || boundary.starts_with(&directory) {
            bail!("{label} must be outside every repository and worktree");
        }
    }
    Ok(())
}

fn repository_boundaries(repository: &Path) -> Result<Vec<PathBuf>> {
    let top_level = git_text(repository, &["rev-parse", "--show-toplevel"])
        .context("resolve publication source repository")?;
    let common = git_text(
        repository,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )
    .context("resolve publication repository Git directory")?;
    let worktrees = git_text(repository, &["worktree", "list", "--porcelain"])
        .context("enumerate publication repository worktrees")?;
    let mut boundaries = BTreeSet::new();
    for candidate in std::iter::once(top_level)
        .chain(std::iter::once(common))
        .chain(
            worktrees
                .lines()
                .filter_map(|line| line.strip_prefix("worktree ").map(str::to_owned)),
        )
    {
        let path = PathBuf::from(candidate);
        let canonical = path
            .canonicalize()
            .context("canonicalize publication repository boundary")?;
        boundaries.insert(canonical);
    }
    Ok(boundaries.into_iter().collect())
}

fn inspect_handoff_directory(root: &Path, signed: bool) -> Result<BTreeMap<String, FileSnapshot>> {
    let expected_files = BOUND_FILES
        .iter()
        .map(|(_, path)| (*path).to_owned())
        .chain(signed.then(|| PREVIEW_PUBLICATION_HANDOFF_PATH.to_owned()))
        .collect::<BTreeSet<_>>();
    let expected_directories = BTreeSet::from(["distribution-evidence".to_owned()]);
    let mut actual_files = BTreeSet::new();
    let mut actual_directories = BTreeSet::new();
    let mut casefolded = BTreeMap::<String, String>::new();

    for entry in WalkDir::new(root).follow_links(false).min_depth(1) {
        let entry = entry.context("walk closed Preview handoff directory")?;
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| anyhow!("Preview handoff traversal escaped its root"))?;
        let logical = relative
            .to_str()
            .ok_or_else(|| anyhow!("Preview handoff contains a non-UTF-8 path"))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        let metadata =
            fs::symlink_metadata(entry.path()).context("read Preview handoff entry metadata")?;
        if metadata.file_type().is_symlink() {
            bail!("Preview handoff contains a symlink");
        }
        let folded = logical.to_ascii_lowercase();
        if let Some(existing) = casefolded.insert(folded, logical.clone()) {
            if existing != logical {
                bail!("Preview handoff contains case-colliding paths");
            }
        }
        if metadata.is_dir() {
            require_real_directory(entry.path(), "Preview handoff subdirectory")?;
            actual_directories.insert(logical);
        } else if metadata.is_file() {
            actual_files.insert(logical);
        } else {
            bail!("Preview handoff contains a non-regular filesystem entry");
        }
    }
    if actual_files != expected_files || actual_directories != expected_directories {
        bail!("Preview handoff directory does not have the exact closed file inventory");
    }

    expected_files
        .into_iter()
        .map(|logical_path| {
            let path = root.join(&logical_path);
            let snapshot =
                inspect_regular_file(&path, file_limit(&logical_path), "Preview handoff file")?;
            Ok((logical_path, snapshot))
        })
        .collect()
}

fn file_limit(logical_path: &str) -> u64 {
    match logical_path {
        PREVIEW_PUBLICATION_MCPB_PATH | PREVIEW_PUBLICATION_SOURCE_ARCHIVE_PATH => {
            MAX_ARCHIVE_BYTES
        }
        PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH => MAX_APPROVAL_BYTES,
        PREVIEW_PUBLICATION_PROJECTION_RECEIPT_PATH => MAX_PROJECTION_RECEIPT_BYTES,
        PREVIEW_PUBLICATION_CURRENT_DISTRIBUTION_RECEIPT_PATH
        | PREVIEW_PUBLICATION_CLEAN_HOST_RECEIPT_PATH => MAX_RECEIPT_BYTES,
        PREVIEW_PUBLICATION_SHA256SUMS_PATH => MAX_SHA256SUMS_BYTES,
        PREVIEW_PUBLICATION_HANDOFF_PATH => MAX_HANDOFF_BYTES,
        _ => MAX_DETACHED_EVIDENCE_BYTES,
    }
}

fn inspect_regular_file(path: &Path, max_bytes: u64, label: &str) -> Result<FileSnapshot> {
    #[cfg(not(any(unix, target_os = "windows")))]
    bail!("{label} cannot be admitted on a platform without stable file identity checks");

    let path_metadata =
        fs::symlink_metadata(path).with_context(|| format!("read {label} metadata"))?;
    require_regular_single_link(&path_metadata, label)?;
    if path_metadata.len() == 0 || path_metadata.len() > max_bytes {
        bail!("{label} has an invalid byte length");
    }
    let mut file = open_regular_no_reparse(path, label)?;
    let opened = file
        .metadata()
        .with_context(|| format!("read opened {label} metadata"))?;
    require_regular_single_link(&opened, label)?;
    require_same_file_identity(&path_metadata, &opened, label)?;
    #[cfg(target_os = "windows")]
    let opened_state = require_windows_file_policy(&file, label)?;

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read {label}"))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(read).expect("buffer length fits u64"))
            .ok_or_else(|| anyhow!("{label} byte count overflowed"))?;
        if size > max_bytes {
            bail!("{label} exceeds its byte limit");
        }
        hasher.update(&buffer[..read]);
    }
    let after = file
        .metadata()
        .with_context(|| format!("recheck opened {label} metadata"))?;
    require_regular_single_link(&after, label)?;
    require_same_file_identity(&opened, &after, label)?;
    #[cfg(target_os = "windows")]
    {
        let after_state = require_windows_file_policy(&file, label)?;
        if after_state != opened_state {
            bail!("{label} identity or timestamps changed while it was read");
        }
    }
    if size != opened.len() || size == 0 {
        bail!("{label} changed size while it was read");
    }
    let named_after =
        fs::symlink_metadata(path).with_context(|| format!("recheck named {label} metadata"))?;
    require_regular_single_link(&named_after, label)?;
    require_same_file_identity(&after, &named_after, label)?;
    #[cfg(target_os = "windows")]
    {
        let named_file = open_regular_no_reparse(path, label)?;
        let named_state = require_windows_file_policy(&named_file, label)?;
        if named_state != opened_state {
            bail!("{label} identity or timestamps changed while it was read");
        }
    }
    Ok(FileSnapshot {
        sha256: format!("{:x}", hasher.finalize()),
        size_bytes: size,
        #[cfg(unix)]
        device: after.dev(),
        #[cfg(unix)]
        inode: after.ino(),
        #[cfg(unix)]
        modified_seconds: after.mtime(),
        #[cfg(unix)]
        modified_nanoseconds: after.mtime_nsec(),
        #[cfg(unix)]
        changed_seconds: after.ctime(),
        #[cfg(unix)]
        changed_nanoseconds: after.ctime_nsec(),
        #[cfg(target_os = "windows")]
        volume_serial_number: opened_state.identity.volume_serial_number,
        #[cfg(target_os = "windows")]
        file_id: opened_state.identity.file_id,
        #[cfg(target_os = "windows")]
        last_write_time: opened_state.last_write_time,
        #[cfg(target_os = "windows")]
        change_time: opened_state.change_time,
    })
}

fn require_regular_single_link(metadata: &Metadata, label: &str) -> Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("{label} must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            bail!("{label} must have exactly one hard link");
        }
    }
    Ok(())
}

fn open_regular_no_reparse(path: &Path, label: &str) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path).with_context(|| format!("open {label}"))
}

#[cfg(unix)]
fn require_same_file_identity(before: &Metadata, after: &Metadata, label: &str) -> Result<()> {
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.nlink() != after.nlink()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("{label} identity changed while it was read");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn require_same_file_identity(before: &Metadata, after: &Metadata, label: &str) -> Result<()> {
    if before.len() != after.len() {
        bail!("{label} identity changed while it was read");
    }
    Ok(())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn require_same_file_identity(_before: &Metadata, _after: &Metadata, label: &str) -> Result<()> {
    bail!("{label} cannot be admitted on a platform without stable file identity checks")
}

fn require_real_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("read {label} metadata"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{label} must be a real directory, not a symlink");
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };

        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .with_context(|| format!("open {label} for reparse-point inspection"))?;
        require_windows_not_reparse_point(&directory, label)?;
        windows_file_identity(&directory, label)?;
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    bail!("{label} cannot be admitted on a platform without reparse-point checks");
    Ok(())
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsFileIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsFileState {
    identity: WindowsFileIdentity,
    last_write_time: i64,
    change_time: i64,
}

#[cfg(target_os = "windows")]
fn require_windows_file_policy(file: &File, label: &str) -> Result<WindowsFileState> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    require_windows_not_reparse_point(file, label)?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) };
    if succeeded == 0 {
        bail!(
            "cannot inspect {label} hard-link count: {}",
            std::io::Error::last_os_error()
        );
    }
    if information.nNumberOfLinks != 1 {
        bail!("{label} must have exactly one hard link");
    }
    let identity = windows_file_identity(file, label)?;
    let (last_write_time, change_time) = windows_file_timestamps(file, label)?;
    Ok(WindowsFileState {
        identity,
        last_write_time,
        change_time,
    })
}

#[cfg(target_os = "windows")]
fn windows_file_identity(file: &File, label: &str) -> Result<WindowsFileIdentity> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
    };

    let mut information = FILE_ID_INFO::default();
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut information as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if succeeded == 0 {
        bail!(
            "cannot inspect {label} stable identity: {}",
            std::io::Error::last_os_error()
        );
    }
    if information.FileId.Identifier == [0; 16] {
        bail!("{label} does not expose an unambiguous volume/file identity");
    }
    Ok(WindowsFileIdentity {
        volume_serial_number: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
}

#[cfg(target_os = "windows")]
fn windows_file_timestamps(file: &File, label: &str) -> Result<(i64, i64)> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandleEx, FILE_BASIC_INFO,
    };

    let mut information = FILE_BASIC_INFO::default();
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            (&mut information as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if succeeded == 0 {
        bail!(
            "cannot inspect {label} timestamps: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok((information.LastWriteTime, information.ChangeTime))
}

#[cfg(target_os = "windows")]
fn require_windows_not_reparse_point(file: &File, label: &str) -> Result<()> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO,
    };

    let mut information = FILE_ATTRIBUTE_TAG_INFO::default();
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut information as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if succeeded == 0 {
        bail!(
            "cannot inspect {label} reparse attributes: {}",
            std::io::Error::last_os_error()
        );
    }
    if information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("{label} must not be a Windows reparse point");
    }
    Ok(())
}

fn require_unchanged_inventory(
    root: &Path,
    signed: bool,
    expected: &BTreeMap<String, FileSnapshot>,
) -> Result<()> {
    let actual = inspect_handoff_directory(root, signed)?;
    if actual.len() != expected.len()
        || actual.iter().any(|(path, snapshot)| {
            expected
                .get(path)
                .is_none_or(|expected| !same_snapshot(expected, snapshot))
        })
    {
        bail!("Preview handoff directory changed during verification");
    }
    Ok(())
}

fn same_snapshot(left: &FileSnapshot, right: &FileSnapshot) -> bool {
    if left.sha256 != right.sha256 || left.size_bytes != right.size_bytes {
        return false;
    }
    #[cfg(unix)]
    if left.device != right.device
        || left.inode != right.inode
        || left.modified_seconds != right.modified_seconds
        || left.modified_nanoseconds != right.modified_nanoseconds
        || left.changed_seconds != right.changed_seconds
        || left.changed_nanoseconds != right.changed_nanoseconds
    {
        return false;
    }
    #[cfg(target_os = "windows")]
    if left.volume_serial_number != right.volume_serial_number || left.file_id != right.file_id {
        return false;
    }
    #[cfg(target_os = "windows")]
    if left.last_write_time != right.last_write_time || left.change_time != right.change_time {
        return false;
    }
    true
}

fn read_bound_bytes(
    root: &Path,
    logical_path: &str,
    files: &BTreeMap<String, FileSnapshot>,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let expected = files
        .get(logical_path)
        .ok_or_else(|| anyhow!("closed Preview handoff is missing {logical_path}"))?;
    if expected.size_bytes > max_bytes {
        bail!("{logical_path} exceeds its parser byte limit");
    }
    let bytes = read_regular_file_bounded(&root.join(logical_path), max_bytes, logical_path)?;
    if u64::try_from(bytes.len()).ok() != Some(expected.size_bytes)
        || sha256_hex(&bytes) != expected.sha256
    {
        bail!("{logical_path} changed after the closed inventory was captured");
    }
    Ok(bytes)
}

fn read_regular_file_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let snapshot = inspect_regular_file(path, max_bytes, label)?;
    let capacity = usize::try_from(snapshot.size_bytes)
        .map_err(|_| anyhow!("{label} is too large for this platform"))?;
    let mut bytes = Vec::with_capacity(capacity);
    let file = open_regular_no_reparse(path, label)?;
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    if bytes.len() != capacity || sha256_hex(&bytes) != snapshot.sha256 {
        bail!("{label} changed while it was read");
    }
    Ok(bytes)
}

#[cfg(target_os = "macos")]
fn read_detached_signing_key(path: &Path, forbidden_roots: &[PathBuf]) -> Result<SigningKey> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| anyhow!("owner signing key is unavailable"))?;
    require_private_key_metadata(&metadata)?;
    let canonical = path
        .canonicalize()
        .map_err(|_| anyhow!("owner signing key is unavailable"))?;
    if forbidden_roots
        .iter()
        .any(|root| canonical.starts_with(root))
    {
        bail!("owner signing key must remain detached from repositories and the handoff");
    }
    let key_parent = canonical
        .parent()
        .ok_or_else(|| anyhow!("owner signing key is unavailable"))?;
    if is_inside_git_worktree(key_parent)? {
        bail!("owner signing key must remain outside every Git worktree");
    }

    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| anyhow!("owner signing key is unavailable"))?;
    let opened = file
        .metadata()
        .map_err(|_| anyhow!("owner signing key is unavailable"))?;
    require_private_key_metadata(&opened)?;
    require_same_file_identity(&metadata, &opened, "owner signing key")?;
    require_no_macos_extended_acl(&file, "owner signing key")?;
    let mut secret = [0_u8; 32];
    let read_result = (|| -> Result<()> {
        file.read_exact(&mut secret)
            .map_err(|_| anyhow!("owner signing key must contain exactly 32 raw bytes"))?;
        let mut trailing = [0_u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| anyhow!("owner signing key could not be read completely"))?
            != 0
        {
            bail!("owner signing key must contain exactly 32 raw bytes");
        }
        let after = file
            .metadata()
            .map_err(|_| anyhow!("owner signing key is unavailable"))?;
        require_private_key_metadata(&after)?;
        require_no_macos_extended_acl(&file, "owner signing key")?;
        require_same_file_identity(&opened, &after, "owner signing key")?;
        let named_after =
            fs::symlink_metadata(path).map_err(|_| anyhow!("owner signing key is unavailable"))?;
        require_private_key_metadata(&named_after)?;
        require_same_file_identity(&after, &named_after, "owner signing key")?;
        let named_file =
            File::open(path).map_err(|_| anyhow!("owner signing key is unavailable"))?;
        require_no_macos_extended_acl(&named_file, "owner signing key")?;
        require_same_file_identity(
            &after,
            &named_file
                .metadata()
                .map_err(|_| anyhow!("owner signing key is unavailable"))?,
            "owner signing key",
        )?;
        Ok(())
    })();
    if let Err(error) = read_result {
        secret.fill(0);
        return Err(error);
    }
    let signing_key = SigningKey::from_bytes(&secret);
    secret.fill(0);
    Ok(signing_key)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn read_detached_signing_key(_path: &Path, _forbidden_roots: &[PathBuf]) -> Result<SigningKey> {
    bail!(
        "sealing is unsupported on this Unix host until owner-only extended-ACL admission is implemented"
    )
}

#[cfg(target_os = "windows")]
fn read_detached_signing_key(_path: &Path, _forbidden_roots: &[PathBuf]) -> Result<SigningKey> {
    bail!(
        "sealing is unsupported on Windows until owner-only private-key ACL admission is implemented"
    )
}

#[cfg(not(any(unix, target_os = "windows")))]
fn read_detached_signing_key(_path: &Path, _forbidden_roots: &[PathBuf]) -> Result<SigningKey> {
    bail!("sealing is unsupported on platforms without owner-only private-key admission")
}

#[cfg(target_os = "macos")]
fn require_private_key_metadata(metadata: &Metadata) -> Result<()> {
    require_regular_single_link(metadata, "owner signing key")?;
    if metadata.len() != 32 {
        bail!("owner signing key must contain exactly 32 raw bytes");
    }
    if metadata.uid() != effective_uid() {
        bail!("owner signing key must be owned by the effective user");
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 || mode & 0o400 == 0 {
        bail!("owner signing key must have restrictive owner-only permissions");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_private_handoff_tree(root: &Path) -> Result<()> {
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.context("walk owner-private Preview handoff")?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(path).context("inspect owner-private Preview handoff entry")?;
        if metadata.file_type().is_symlink() {
            bail!("owner-private Preview handoff must not contain symlinks");
        }
        if metadata.uid() != effective_uid() {
            bail!("owner-private Preview handoff entries must be owned by the effective user");
        }
        let opened = File::open(path).context("open owner-private Preview handoff entry")?;
        require_no_macos_extended_acl(&opened, "owner-private Preview handoff entry")?;
        require_same_file_identity(
            &metadata,
            &opened
                .metadata()
                .context("recheck owner-private Preview handoff entry")?,
            "owner-private Preview handoff entry",
        )?;
        if metadata.is_dir() {
            if metadata.permissions().mode() & 0o777 != 0o700 {
                bail!("owner-private Preview handoff directories must have mode 0700");
            }
        } else {
            require_regular_single_link(&metadata, "owner-private Preview handoff file")?;
            if metadata.permissions().mode() & 0o777 != 0o600 {
                bail!("owner-private Preview handoff files must have mode 0600");
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn require_private_handoff_tree(_root: &Path) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_github_cli_program(requested: &Path) -> Result<PathBuf> {
    if !requested.is_absolute() {
        bail!("GitHub CLI executable path must be absolute");
    }
    let canonical = requested
        .canonicalize()
        .context("canonicalize owner-selected GitHub CLI executable")?;
    let metadata =
        fs::symlink_metadata(&canonical).context("inspect owner-selected GitHub CLI executable")?;
    require_regular_single_link(&metadata, "owner-selected GitHub CLI executable")?;
    if metadata.uid() != 0 && metadata.uid() != effective_uid() {
        bail!("GitHub CLI executable must be owned by root or the effective user");
    }
    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 || mode & 0o022 != 0 {
        bail!("GitHub CLI executable must be executable and not group/other writable");
    }
    let file = File::open(&canonical).context("open owner-selected GitHub CLI executable")?;
    require_no_macos_extended_acl(&file, "owner-selected GitHub CLI executable")?;
    require_same_file_identity(
        &metadata,
        &file
            .metadata()
            .context("recheck owner-selected GitHub CLI executable")?,
        "owner-selected GitHub CLI executable",
    )?;
    Ok(canonical)
}

#[cfg(not(target_os = "macos"))]
fn require_github_cli_program(_requested: &Path) -> Result<PathBuf> {
    bail!("Preview publication is unsupported on this host")
}

#[cfg(target_os = "macos")]
fn require_private_staging_directory(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).context("inspect Preview upload staging directory")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("Preview upload staging directory must be a real directory");
    }
    if metadata.uid() != effective_uid() || metadata.permissions().mode() & 0o777 != 0o700 {
        bail!("Preview upload staging directory must be owned by and accessible only to the effective user");
    }
    let directory = File::open(path).context("open Preview upload staging directory")?;
    require_no_macos_extended_acl(&directory, "Preview upload staging directory")?;
    require_same_file_identity(
        &metadata,
        &directory
            .metadata()
            .context("recheck Preview upload staging directory")?,
        "Preview upload staging directory",
    )?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn require_private_staging_directory(_path: &Path) -> Result<()> {
    bail!(
        "Preview publication is unsupported on this host until owner-only upload-staging ACL admission is implemented"
    )
}

#[cfg(target_os = "macos")]
fn require_private_staged_file_handle(file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .context("inspect anonymous staged Preview public asset")?;
    if !metadata.is_file() || metadata.nlink() != 0 {
        bail!("staged Preview public assets must be anonymous regular files");
    }
    if metadata.uid() != effective_uid() || metadata.permissions().mode() & 0o777 != 0o600 {
        bail!("staged Preview public assets must be owned by and accessible only to the effective user");
    }
    require_no_macos_extended_acl(file, "staged Preview public asset")?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn require_private_staged_file_handle(_file: &File) -> Result<()> {
    bail!(
        "Preview publication is unsupported on this host until owner-only staged-file ACL admission is implemented"
    )
}

#[cfg(target_os = "macos")]
fn effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(target_os = "macos")]
fn require_no_macos_extended_acl(file: &File, label: &str) -> Result<()> {
    use std::ffi::c_void;
    use std::os::fd::AsRawFd;
    use std::ptr;

    const ACL_TYPE_EXTENDED: i32 = 0x0000_0100;
    const ACL_FIRST_ENTRY: i32 = 0;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: i32, acl_type: i32) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry_id: i32, entry: *mut *mut c_void) -> i32;
        fn acl_free(object: *mut c_void) -> i32;
    }

    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            // Darwin reports ENOENT when the descriptor has no extended ACL.
            return Ok(());
        }
        bail!("cannot inspect {label} extended ACL: {}", error);
    }
    let mut entry = ptr::null_mut();
    let entry_result = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };
    let entry_error = std::io::Error::last_os_error();
    let free_result = unsafe { acl_free(acl) };
    if free_result != 0 {
        bail!(
            "cannot release {label} extended ACL inspection: {}",
            std::io::Error::last_os_error()
        );
    }
    match entry_result {
        0 => bail!("{label} must not have any extended ACL entries"),
        _ => bail!("cannot enumerate {label} extended ACL: {entry_error}"),
    }
}

fn write_fresh_file(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        bail!("{label} output must be fresh");
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    require_real_directory(parent, &format!("{label} parent"))?;
    let mut temporary = TempFileBuilder::new()
        .prefix(".preview-publication-write-")
        .tempfile_in(parent)
        .with_context(|| format!("create fresh {label} temporary file"))?;
    temporary
        .write_all(bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .with_context(|| format!("write fresh {label}"))?;
    temporary
        .persist_noclobber(path)
        .map_err(|_| anyhow!("{label} output already exists or could not be persisted"))?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("invalid lowercase hexadecimal key");
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("caller validates lowercase hexadecimal"),
    }
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn git_text(repository: &Path, arguments: &[&str]) -> Result<String> {
    let output = hardened_git_process(repository)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .context("execute local Git inspection")?;
    if !output.status.success() {
        bail!("local Git inspection failed");
    }
    let text = String::from_utf8(output.stdout).context("Git returned non-UTF-8 output")?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn is_inside_git_worktree(directory: &Path) -> Result<bool> {
    let has_git_boundary = has_git_boundary_in_ancestors(directory)?;
    let output = hardened_git_process(directory)
        .args(["rev-parse", "--is-inside-work-tree", "--is-inside-git-dir"])
        .stdin(Stdio::null())
        .output()
        .context("inspect detached-directory Git boundary")?;
    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr)
            .context("Git boundary failure returned non-UTF-8 diagnostics")?;
        if !has_git_boundary
            && stderr.trim()
                == "fatal: not a git repository (or any of the parent directories): .git"
        {
            return Ok(false);
        }
        bail!("could not prove that the detached directory is outside every Git worktree");
    }
    let value =
        String::from_utf8(output.stdout).context("Git boundary inspection returned non-UTF-8")?;
    Ok(value.lines().any(|line| line.trim() == "true"))
}

fn has_git_boundary_in_ancestors(directory: &Path) -> Result<bool> {
    for ancestor in directory.ancestors() {
        match fs::symlink_metadata(ancestor.join(".git")) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .context("inspect ancestor Git boundary while proving directory detachment");
            }
        }
    }
    Ok(false)
}

fn hardened_git_process(repository: &Path) -> Command {
    let mut command = Command::new(TRUSTED_GIT_PROGRAM);
    command.env_clear().current_dir(repository);
    command.envs(hardened_git_environment());
    command
}

fn hardened_git_environment() -> Vec<(String, String)> {
    #[cfg(windows)]
    const NULL_DEVICE: &str = "NUL";
    #[cfg(not(windows))]
    const NULL_DEVICE: &str = "/dev/null";

    let mut environment = ["PATH", "SystemRoot", "WINDIR", "TMPDIR", "TMP", "TEMP"]
        .into_iter()
        .filter_map(|name| {
            std::env::var(name)
                .ok()
                .map(|value| (name.to_owned(), value))
        })
        .collect::<Vec<_>>();
    environment.extend([
        ("LC_ALL".to_owned(), "C".to_owned()),
        ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
        ("GIT_CONFIG_SYSTEM".to_owned(), NULL_DEVICE.to_owned()),
        ("GIT_CONFIG_GLOBAL".to_owned(), NULL_DEVICE.to_owned()),
        ("GIT_CONFIG_COUNT".to_owned(), "0".to_owned()),
        ("GIT_ATTR_NOSYSTEM".to_owned(), "1".to_owned()),
        ("GIT_NO_REPLACE_OBJECTS".to_owned(), "1".to_owned()),
        ("GIT_OPTIONAL_LOCKS".to_owned(), "0".to_owned()),
        ("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()),
        ("GIT_PAGER".to_owned(), "cat".to_owned()),
    ]);
    environment
}

#[derive(Clone, Debug)]
pub struct PublishPreviewPrereleaseOptions {
    pub handoff_directory: PathBuf,
    pub source_repository: PathBuf,
    pub projection_repository: PathBuf,
    pub github_cli: PathBuf,
    pub key_id: String,
    pub public_key_hex: String,
    pub serial: u64,
    pub exclusive_write_window_confirmed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedPreviewPrerelease {
    pub tag: String,
}

struct GitHubTransport {
    config_directory: PathBuf,
    config_directory_environment: String,
    program: String,
    program_path: PathBuf,
    program_snapshot: Option<FileSnapshot>,
    token: String,
    enforce_local_filesystem: bool,
}

impl GitHubTransport {
    fn from_environment(staging_directory: &Path, requested_program: &Path) -> Result<Self> {
        let program_path = require_github_cli_program(requested_program)?;
        let program = program_path
            .to_str()
            .ok_or_else(|| anyhow!("GitHub CLI executable path is not UTF-8"))?
            .to_owned();
        let program_snapshot = inspect_regular_file(
            &program_path,
            256 * 1024 * 1024,
            "owner-selected GitHub CLI executable",
        )?;
        let config_directory = staging_directory.join(".gh-config");
        fs::create_dir(&config_directory)
            .context("create controlled GitHub CLI configuration directory")?;
        #[cfg(unix)]
        fs::set_permissions(&config_directory, fs::Permissions::from_mode(0o700))
            .context("restrict controlled GitHub CLI configuration directory")?;
        require_private_staging_directory(&config_directory)?;
        if fs::read_dir(&config_directory)
            .context("inspect controlled GitHub CLI configuration directory")?
            .next()
            .is_some()
        {
            bail!("controlled GitHub CLI configuration directory must start empty");
        }
        let config_directory_environment = config_directory
            .to_str()
            .ok_or_else(|| {
                anyhow!("controlled GitHub CLI configuration directory path is not UTF-8")
            })?
            .to_owned();
        let token = std::env::var("GH_TOKEN")
            .map_err(|_| anyhow!("Preview publication requires an explicit GH_TOKEN"))?;
        if token.is_empty()
            || token.len() > 4096
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            let mut token = token;
            unsafe {
                token.as_bytes_mut().fill(0);
            }
            bail!("Preview publication GH_TOKEN has an invalid closed form");
        }
        Ok(Self {
            config_directory,
            config_directory_environment,
            program,
            program_path,
            program_snapshot: Some(program_snapshot),
            token,
            enforce_local_filesystem: true,
        })
    }

    fn require_intact(&self) -> Result<()> {
        if !self.enforce_local_filesystem {
            return Ok(());
        }
        require_private_staging_directory(&self.config_directory)?;
        let path = require_github_cli_program(&self.program_path)?;
        let snapshot = inspect_regular_file(
            &path,
            256 * 1024 * 1024,
            "owner-selected GitHub CLI executable",
        )?;
        if path != self.program_path || Some(snapshot) != self.program_snapshot {
            bail!("owner-selected GitHub CLI executable changed during publication");
        }
        Ok(())
    }
}

impl Drop for GitHubTransport {
    fn drop(&mut self) {
        // Zero bytes remain valid UTF-8, so this preserves String invariants.
        unsafe {
            self.token.as_bytes_mut().fill(0);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandInvocation {
    program: String,
    arguments: Vec<String>,
    current_directory: Option<PathBuf>,
    clear_environment: bool,
    removed_environment: Vec<String>,
    environment: Vec<(String, String)>,
    stdin: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandResult {
    success: bool,
    status_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

trait PublicationCommandExecutor {
    fn execute(&mut self, invocation: &CommandInvocation) -> Result<CommandResult>;

    fn execute_with_github_token(
        &mut self,
        invocation: &CommandInvocation,
        _token: &str,
    ) -> Result<CommandResult> {
        self.execute(invocation)
    }

    fn execute_with_file_stdin(
        &mut self,
        invocation: &CommandInvocation,
        _input: &File,
    ) -> Result<CommandResult> {
        self.execute(invocation)
    }

    fn execute_with_github_token_and_file_stdin(
        &mut self,
        invocation: &CommandInvocation,
        token: &str,
        input: &File,
    ) -> Result<CommandResult> {
        let _ = token;
        self.execute_with_file_stdin(invocation, input)
    }
}

struct ProcessCommandExecutor;

impl ProcessCommandExecutor {
    fn execute_inner(
        &mut self,
        invocation: &CommandInvocation,
        file_stdin: Option<&File>,
        github_token: Option<&str>,
    ) -> Result<CommandResult> {
        if invocation.stdin.is_some() && file_stdin.is_some() {
            bail!("publication command cannot have two stdin sources");
        }
        let mut command = Command::new(&invocation.program);
        if invocation.clear_environment {
            command.env_clear();
        }
        command
            .args(&invocation.arguments)
            .env_remove("GIT_CONFIG_PARAMETERS")
            .env_remove("GIT_CONFIG_KEY_0")
            .env_remove("GIT_CONFIG_VALUE_0")
            .envs(invocation.environment.iter().cloned())
            .stdout(Stdio::piped());
        if let Some(token) = github_token {
            command.env("GH_TOKEN", token);
        }
        for name in &invocation.removed_environment {
            command.env_remove(name);
        }
        if let Some(directory) = &invocation.current_directory {
            command.current_dir(directory);
        }
        if let Some(file) = file_stdin {
            command.stdin(Stdio::from(
                file.try_clone()
                    .context("clone stable publication input handle")?,
            ));
        } else if invocation.stdin.is_some() {
            command.stdin(Stdio::piped());
        } else {
            command.stdin(Stdio::null());
        }
        command.stderr(Stdio::piped());
        let mut child = command.spawn().with_context(|| {
            format!(
                "start noninteractive {} command",
                publication_program_label(&invocation.program)
            )
        })?;
        if let Some(bytes) = &invocation.stdin {
            child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("publication command stdin was not piped"))?
                .write_all(bytes)
                .context("write publication command request")?;
        }
        let output = child
            .wait_with_output()
            .context("wait for publication command")?;
        Ok(CommandResult {
            success: output.status.success(),
            status_code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

impl PublicationCommandExecutor for ProcessCommandExecutor {
    fn execute(&mut self, invocation: &CommandInvocation) -> Result<CommandResult> {
        self.execute_inner(invocation, None, None)
    }

    fn execute_with_github_token(
        &mut self,
        invocation: &CommandInvocation,
        token: &str,
    ) -> Result<CommandResult> {
        self.execute_inner(invocation, None, Some(token))
    }

    fn execute_with_file_stdin(
        &mut self,
        invocation: &CommandInvocation,
        input: &File,
    ) -> Result<CommandResult> {
        self.execute_inner(invocation, Some(input), None)
    }

    fn execute_with_github_token_and_file_stdin(
        &mut self,
        invocation: &CommandInvocation,
        token: &str,
        input: &File,
    ) -> Result<CommandResult> {
        self.execute_inner(invocation, Some(input), Some(token))
    }
}

fn publication_program_label(program: &str) -> &'static str {
    match program {
        "git" => "Git",
        "gh" => "GitHub CLI",
        _ => "publication helper",
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GitHubAsset {
    name: String,
    size: u64,
    digest: Option<String>,
    state: String,
    uploader: GitHubActor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GitHubActor {
    login: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GitHubRelease {
    id: u64,
    upload_url: String,
    tag_name: String,
    target_commitish: String,
    name: String,
    body: String,
    draft: bool,
    prerelease: bool,
    immutable: bool,
    author: GitHubActor,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubRepository {
    full_name: String,
    private: bool,
    visibility: String,
    archived: bool,
    disabled: bool,
    default_branch: String,
}

#[derive(Debug, Deserialize)]
struct GitHubBranch {
    name: String,
    commit: GitHubBranchCommit,
}

#[derive(Debug, Deserialize)]
struct GitHubBranchCommit {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GitHubGitObject {
    #[serde(rename = "type")]
    object_type: String,
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GitHubReference {
    #[serde(rename = "ref")]
    reference: String,
    object: GitHubGitObject,
}

#[derive(Debug, Serialize)]
struct CreateReleaseRequest<'a> {
    tag_name: &'a str,
    target_commitish: &'a str,
    name: String,
    body: &'static str,
    draft: bool,
    prerelease: bool,
    make_latest: &'static str,
}

#[derive(Debug, Serialize)]
struct PublishReleaseRequest {
    tag_name: String,
    target_commitish: String,
    name: String,
    body: &'static str,
    draft: bool,
    prerelease: bool,
    make_latest: &'static str,
}

pub fn publish_preview_prerelease(
    options: &PublishPreviewPrereleaseOptions,
) -> Result<PublishedPreviewPrerelease> {
    if !options.exclusive_write_window_confirmed {
        bail!(
            "Preview publication requires an owner-enforced exclusive write window over the local source, projection, handoff and staged handles, and all destination repository, branch, release, tag, and immutable-release state"
        );
    }
    if options.serial == 0 {
        bail!("Preview prerelease serial must be positive");
    }
    let verification_options = VerifyPreviewPublicationHandoffOptions {
        repository: options.source_repository.clone(),
        handoff_directory: options.handoff_directory.clone(),
        key_id: options.key_id.clone(),
        public_key_hex: options.public_key_hex.clone(),
    };
    let verified = verify_preview_publication_handoff(&verification_options)?;
    let mut executor = ProcessCommandExecutor;
    publish_verified_preview(options, &verification_options, &verified, &mut executor)
}

fn publish_verified_preview(
    options: &PublishPreviewPrereleaseOptions,
    verification_options: &VerifyPreviewPublicationHandoffOptions,
    verified: &VerifiedPreviewPublicationHandoff,
    executor: &mut dyn PublicationCommandExecutor,
) -> Result<PublishedPreviewPrerelease> {
    let tag = format!("v{}-preview.{}", verified.release_version, options.serial);
    let release_name = format!(
        "AutoCAD MCP {} Preview {}",
        verified.release_version, options.serial
    );
    require_release_tag(&tag, &verified.release_version, options.serial)?;
    let projection = verify_projection_repository(
        executor,
        &options.projection_repository,
        &verified.projection_commit,
        &verified.source_tree_oid,
    )?;
    require_directory_detached_from_repository(
        &options.handoff_directory,
        &projection,
        "Preview handoff directory",
    )?;
    require_uploadable_assets(&verified.public_assets)?;
    let mut staged = stage_public_assets(&verified.public_assets)?;
    require_directory_detached_from_repository(
        staged.directory.path(),
        &options.source_repository,
        "Preview upload staging directory",
    )?;
    require_directory_detached_from_repository(
        staged.directory.path(),
        &projection,
        "Preview upload staging directory",
    )?;
    require_disjoint_directories(
        staged.directory.path(),
        &options.handoff_directory,
        "Preview upload staging directory",
        "Preview handoff directory",
    )?;
    let github = GitHubTransport::from_environment(staged.directory.path(), &options.github_cli)?;
    let context = PreviewPublishContext {
        options,
        verification_options,
        verified,
        projection: &projection,
        github: &github,
        tag: &tag,
        release_name: &release_name,
    };
    let result = publish_staged_preview(&context, &mut staged.assets, executor);
    let cleanup = staged
        .directory
        .close()
        .context("remove process-owned Preview upload staging directory");
    match (result, cleanup) {
        (Ok(published), Ok(())) => Ok(published),
        (Err(error), Ok(())) => Err(error),
        (Ok(published), Err(cleanup_error)) => Err(anyhow!(
            "immutable Preview prerelease {} was published, but process-owned upload staging cleanup failed: {cleanup_error:#}",
            published.tag
        )),
        (Err(error), Err(cleanup_error)) => Err(anyhow!(
            "{error:#}; additionally, Preview upload staging cleanup failed: {cleanup_error:#}"
        )),
    }
}

#[derive(Clone, Copy)]
struct PreviewPublishContext<'a> {
    options: &'a PublishPreviewPrereleaseOptions,
    verification_options: &'a VerifyPreviewPublicationHandoffOptions,
    verified: &'a VerifiedPreviewPublicationHandoff,
    projection: &'a Path,
    github: &'a GitHubTransport,
    tag: &'a str,
    release_name: &'a str,
}

fn publish_staged_preview(
    context: &PreviewPublishContext<'_>,
    public_assets: &mut [StagedPublicAsset],
    executor: &mut dyn PublicationCommandExecutor,
) -> Result<PublishedPreviewPrerelease> {
    let PreviewPublishContext {
        options,
        verification_options,
        verified,
        projection,
        github,
        tag,
        release_name,
    } = *context;
    require_unchanged_staged_assets(public_assets)?;
    require_fixed_public_repository(executor, github)?;
    require_neutral_github_publisher(executor, github)?;
    require_immutable_releases_enabled(executor, github)?;
    require_remote_main(executor, github, &verified.projection_commit)?;
    require_remote_absent(
        executor,
        github,
        &format!("repos/{PREVIEW_GITHUB_REPOSITORY}/git/ref/tags/{tag}"),
        "tag",
    )?;
    require_release_tag_absent(executor, github, tag)?;
    require_release_verification_capability(executor, github)?;
    require_unchanged_staged_assets(public_assets)?;

    let create_request = CreateReleaseRequest {
        tag_name: tag,
        target_commitish: &verified.projection_commit,
        name: release_name.to_owned(),
        body: PREVIEW_RELEASE_BODY,
        draft: true,
        prerelease: true,
        make_latest: "false",
    };
    let created: GitHubRelease = run_github_json(
        executor,
        github,
        &github_api(
            github,
            "POST",
            &format!("repos/{PREVIEW_GITHUB_REPOSITORY}/releases"),
            Some(serde_json::to_vec(&create_request).context("serialize draft release request")?),
        ),
        "create draft Preview prerelease",
    )?;
    require_release_state(
        &created,
        tag,
        &verified.projection_commit,
        release_name,
        true,
        false,
    )?;
    if !created.assets.is_empty() {
        bail!("fresh draft Preview prerelease unexpectedly contains assets");
    }

    require_unchanged_staged_assets(public_assets)?;
    upload_release_assets(executor, github, &created, public_assets)?;
    let uploaded = get_release(executor, github, created.id)?;
    require_release_state(
        &uploaded,
        tag,
        &verified.projection_commit,
        release_name,
        true,
        false,
    )?;
    require_exact_remote_assets(&uploaded.assets, public_assets)?;

    reverify_local_publication_selection(
        options,
        verification_options,
        verified,
        projection,
        executor,
        public_assets,
    )?;
    require_remote_main(executor, github, &verified.projection_commit)?;
    require_immutable_releases_enabled(executor, github)?;
    let final_draft = get_release(executor, github, created.id)?;
    require_release_state(
        &final_draft,
        tag,
        &verified.projection_commit,
        release_name,
        true,
        false,
    )?;
    require_exact_remote_assets(&final_draft.assets, public_assets)?;
    require_remote_absent(
        executor,
        github,
        &format!("repos/{PREVIEW_GITHUB_REPOSITORY}/git/ref/tags/{tag}"),
        "tag",
    )?;
    require_only_created_release_with_tag(executor, github, tag, created.id)?;
    require_unchanged_staged_assets(public_assets)?;
    require_fixed_public_repository(executor, github)?;
    require_neutral_github_publisher(executor, github)?;
    reverify_local_publication_selection(
        options,
        verification_options,
        verified,
        projection,
        executor,
        public_assets,
    )?;

    let publish_request = PublishReleaseRequest {
        tag_name: tag.to_owned(),
        target_commitish: verified.projection_commit.clone(),
        name: release_name.to_owned(),
        body: PREVIEW_RELEASE_BODY,
        draft: false,
        prerelease: true,
        make_latest: "false",
    };
    let publish_command = github_api(
        github,
        "PATCH",
        &format!("repos/{PREVIEW_GITHUB_REPOSITORY}/releases/{}", created.id),
        Some(serde_json::to_vec(&publish_request).context("serialize publish release request")?),
    );
    let expected_release = ExpectedReleaseState {
        release_id: created.id,
        tag,
        commit: &verified.projection_commit,
        name: release_name,
        assets: public_assets,
    };
    publish_and_reconcile(executor, github, &publish_command, &expected_release)?;

    let final_release = get_release(executor, github, created.id).map_err(|error| {
        anyhow!(
            "immutable Preview prerelease was confirmed published, but final release inspection failed: {error:#}"
        )
    })?;
    require_release_state(
        &final_release,
        tag,
        &verified.projection_commit,
        release_name,
        false,
        true,
    )
    .and_then(|_| require_exact_remote_assets(&final_release.assets, public_assets))
    .map_err(|error| {
        anyhow!(
            "immutable Preview prerelease was confirmed published, but final state validation failed: {error:#}"
        )
    })?;
    reverify_local_publication_selection(
        options,
        verification_options,
        verified,
        projection,
        executor,
        public_assets,
    )
    .map_err(|error| {
        anyhow!(
            "immutable Preview prerelease was published, but final local source validation failed: {error:#}"
        )
    })?;
    require_fixed_public_repository(executor, github)
        .and_then(|_| require_neutral_github_publisher(executor, github))
        .and_then(|_| require_immutable_releases_enabled(executor, github))
        .and_then(|_| require_remote_main(executor, github, &verified.projection_commit))
        .and_then(|_| require_only_created_release_with_tag(executor, github, tag, created.id))
        .map_err(|error| {
            anyhow!(
                "immutable Preview prerelease was published, but final repository validation failed: {error:#}"
            )
        })?;
    require_exact_remote_tag(executor, github, tag, &verified.projection_commit).map_err(|error| {
        anyhow!(
            "immutable Preview prerelease was confirmed published, but tag validation failed: {error:#}"
        )
    })?;
    run_github_success(
        executor,
        github,
        &github_release_verify_command(github, tag),
        "verify immutable GitHub release",
    )
    .map_err(|error| {
        anyhow!(
            "immutable Preview prerelease was confirmed published, but release verification failed: {error:#}"
        )
    })?;

    Ok(PublishedPreviewPrerelease {
        tag: tag.to_owned(),
    })
}

fn reverify_local_publication_selection(
    options: &PublishPreviewPrereleaseOptions,
    verification_options: &VerifyPreviewPublicationHandoffOptions,
    verified: &VerifiedPreviewPublicationHandoff,
    projection: &Path,
    executor: &mut dyn PublicationCommandExecutor,
    public_assets: &mut [StagedPublicAsset],
) -> Result<()> {
    let reverified = verify_preview_publication_handoff(verification_options)
        .context("reverify signed handoff and source repository")?;
    if &reverified != verified {
        bail!("signed Preview handoff selection changed after publication began");
    }
    verify_projection_repository(
        executor,
        projection,
        &verified.projection_commit,
        &verified.source_tree_oid,
    )?;
    require_directory_detached_from_repository(
        &options.handoff_directory,
        projection,
        "Preview handoff directory",
    )?;
    require_unchanged_staged_assets(public_assets)
}

struct ExpectedReleaseState<'a, T: PublicAssetDescriptor> {
    release_id: u64,
    tag: &'a str,
    commit: &'a str,
    name: &'a str,
    assets: &'a [T],
}

fn publish_and_reconcile<T: PublicAssetDescriptor>(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    invocation: &CommandInvocation,
    expected: &ExpectedReleaseState<'_, T>,
) -> Result<GitHubRelease> {
    let result = match execute_github_command(executor, github, invocation) {
        Ok(result) => result,
        Err(transport_error) => {
            return reconcile_publish_outcome(executor, github, expected, Some(&transport_error));
        }
    };
    if result.success {
        if let Ok(release) = parse_json_bytes::<GitHubRelease>(
            &result.stdout,
            "publish immutable Preview prerelease",
        ) {
            if release_matches(
                &release,
                expected.tag,
                expected.commit,
                expected.name,
                false,
                true,
                expected.assets,
            ) {
                return Ok(release);
            }
        }
    }

    reconcile_publish_outcome(executor, github, expected, None)
}

fn reconcile_publish_outcome<T: PublicAssetDescriptor>(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    expected: &ExpectedReleaseState<'_, T>,
    transport_error: Option<&anyhow::Error>,
) -> Result<GitHubRelease> {
    match get_release(executor, github, expected.release_id) {
        Ok(release)
            if release_matches(
                &release,
                expected.tag,
                expected.commit,
                expected.name,
                false,
                true,
                expected.assets,
            ) =>
        {
            Ok(release)
        }
        Ok(release)
            if release_matches(
                &release,
                expected.tag,
                expected.commit,
                expected.name,
                true,
                false,
                expected.assets,
            ) =>
        {
            if let Some(error) = transport_error {
                bail!(
                    "GitHub publish transport failed ({error:#}); the exact draft remains unpublished"
                );
            }
            bail!("GitHub publish was not confirmed; the exact draft remains unpublished");
        }
        _ => {
            if let Some(error) = transport_error {
                bail!(
                    "GitHub publish transport failed ({error:#}); outcome is ambiguous and an immutable Preview prerelease may already exist"
                );
            }
            bail!(
                "GitHub publish outcome is ambiguous; an immutable Preview prerelease may already exist"
            );
        }
    }
}

fn release_matches<T: PublicAssetDescriptor>(
    release: &GitHubRelease,
    tag: &str,
    commit: &str,
    name: &str,
    draft: bool,
    immutable: bool,
    assets: &[T],
) -> bool {
    require_release_state(release, tag, commit, name, draft, immutable).is_ok()
        && require_exact_remote_assets(&release.assets, assets).is_ok()
}

fn require_release_tag(tag: &str, version: &str, serial: u64) -> Result<()> {
    if serial == 0 || tag != format!("v{version}-preview.{serial}") {
        bail!("Preview prerelease tag does not match the approved version and positive serial");
    }
    Ok(())
}

fn require_uploadable_assets(assets: &[PreviewPublicAsset]) -> Result<()> {
    const GITHUB_ASSET_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
    if assets.len() != 7
        || assets
            .iter()
            .any(|asset| asset.size_bytes >= GITHUB_ASSET_LIMIT)
    {
        bail!("each of the seven Preview assets must be smaller than 2 GiB");
    }
    Ok(())
}

struct UploadStage {
    directory: TempDir,
    assets: Vec<StagedPublicAsset>,
}

struct StagedPublicAsset {
    asset_name: String,
    sha256: String,
    size_bytes: u64,
    file: File,
}

fn stage_public_assets(assets: &[PreviewPublicAsset]) -> Result<UploadStage> {
    require_uploadable_assets(assets)?;
    let directory = TempFileBuilder::new()
        .prefix(".autocad-mcp-preview-upload-")
        .tempdir()
        .context("create fresh Preview upload staging directory")?;
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .context("restrict fresh Preview upload staging directory")?;
    require_private_staging_directory(directory.path())?;

    let mut staged = Vec::with_capacity(assets.len());
    let mut names = BTreeSet::new();
    for asset in assets {
        if !names.insert(asset.asset_name.as_str())
            || Path::new(&asset.asset_name)
                .file_name()
                .and_then(|name| name.to_str())
                != Some(asset.asset_name.as_str())
        {
            bail!("Preview public asset names must be unique portable basenames");
        }
        let mut output = tempfile::tempfile_in(directory.path())
            .context("create anonymous Preview upload staging file")?;
        #[cfg(unix)]
        output
            .set_permissions(fs::Permissions::from_mode(0o600))
            .context("restrict anonymous Preview upload staging file")?;
        require_private_staged_file_handle(&output)?;
        copy_verified_public_asset(asset, &mut output)?;
        let mut staged_asset = StagedPublicAsset {
            asset_name: asset.asset_name.clone(),
            sha256: asset.sha256.clone(),
            size_bytes: asset.size_bytes,
            file: output,
        };
        require_unchanged_staged_asset(&mut staged_asset)?;
        staged.push(staged_asset);
    }
    Ok(UploadStage {
        directory,
        assets: staged,
    })
}

fn copy_verified_public_asset(asset: &PreviewPublicAsset, output: &mut File) -> Result<()> {
    let label = format!("Preview public asset {}", asset.asset_name);
    let named_before =
        fs::symlink_metadata(&asset.path).with_context(|| format!("inspect source {label}"))?;
    require_regular_single_link(&named_before, &label)?;
    let mut source = open_regular_no_reparse(&asset.path, &label)?;
    let opened = source
        .metadata()
        .with_context(|| format!("inspect opened source {label}"))?;
    require_regular_single_link(&opened, &label)?;
    require_same_file_identity(&named_before, &opened, &label)?;
    #[cfg(target_os = "windows")]
    let opened_state = require_windows_file_policy(&source, &label)?;

    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .with_context(|| format!("read source {label}"))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(read).expect("buffer length fits u64"))
            .ok_or_else(|| anyhow!("{label} byte count overflowed"))?;
        if size > asset.size_bytes {
            bail!("source {label} changed size before staging");
        }
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .with_context(|| format!("write staged {label}"))?;
    }
    output
        .sync_all()
        .with_context(|| format!("persist staged {label}"))?;

    let source_after = source
        .metadata()
        .with_context(|| format!("recheck opened source {label}"))?;
    require_regular_single_link(&source_after, &label)?;
    require_same_file_identity(&opened, &source_after, &label)?;
    #[cfg(target_os = "windows")]
    if require_windows_file_policy(&source, &label)? != opened_state {
        bail!("source {label} identity or timestamps changed while staging");
    }
    let named_after =
        fs::symlink_metadata(&asset.path).with_context(|| format!("recheck source {label}"))?;
    require_regular_single_link(&named_after, &label)?;
    require_same_file_identity(&source_after, &named_after, &label)?;

    if size != asset.size_bytes || format!("{:x}", hasher.finalize()) != asset.sha256 {
        bail!("source {label} no longer matches the verified handoff bytes");
    }
    output
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind staged {label}"))?;
    require_private_staged_file_handle(output)?;
    Ok(())
}

fn require_unchanged_staged_assets(assets: &mut [StagedPublicAsset]) -> Result<()> {
    for asset in assets {
        require_unchanged_staged_asset(asset)?;
    }
    Ok(())
}

fn require_unchanged_staged_asset(asset: &mut StagedPublicAsset) -> Result<()> {
    let label = format!("anonymous staged Preview public asset {}", asset.asset_name);
    require_private_staged_file_handle(&asset.file)?;
    let before = asset
        .file
        .metadata()
        .with_context(|| format!("inspect {label}"))?;
    asset
        .file
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind {label}"))?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = asset
            .file
            .read(&mut buffer)
            .with_context(|| format!("read {label}"))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(read).expect("buffer length fits u64"))
            .ok_or_else(|| anyhow!("{label} byte count overflowed"))?;
        if size > asset.size_bytes {
            bail!("{label} changed size before upload");
        }
        hasher.update(&buffer[..read]);
    }
    let after = asset
        .file
        .metadata()
        .with_context(|| format!("recheck {label}"))?;
    require_same_file_identity(&before, &after, &label)?;
    require_private_staged_file_handle(&asset.file)?;
    asset
        .file
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind {label} for upload"))?;
    if size != asset.size_bytes || format!("{:x}", hasher.finalize()) != asset.sha256 {
        bail!("{label} no longer matches the verified handoff bytes");
    }
    Ok(())
}

fn require_disjoint_directories(
    left: &Path,
    right: &Path,
    left_label: &str,
    right_label: &str,
) -> Result<()> {
    let left = left
        .canonicalize()
        .with_context(|| format!("canonicalize {left_label}"))?;
    let right = right
        .canonicalize()
        .with_context(|| format!("canonicalize {right_label}"))?;
    if left.starts_with(&right) || right.starts_with(&left) {
        bail!("{left_label} must be detached from {right_label}");
    }
    Ok(())
}

fn verify_source_repository(
    executor: &mut dyn PublicationCommandExecutor,
    requested: &Path,
    git_object_format: GitObjectFormat,
    expected_commit: &str,
    expected_tree: &str,
) -> Result<VerifiedSourceRepository> {
    require_real_directory(requested, "source repository")?;
    let repository = requested
        .canonicalize()
        .context("canonicalize source repository")?;
    let top_level = run_success_text(
        executor,
        &git_command(&repository, &["rev-parse", "--show-toplevel"]),
        "resolve source repository top level",
    )?;
    if Path::new(&top_level).canonicalize()? != repository {
        bail!("source repository must be its canonical top-level checkout");
    }
    let dot_git = repository.join(".git");
    require_real_directory(&dot_git, "source repository Git directory")?;
    let dot_git = dot_git
        .canonicalize()
        .context("canonicalize source repository Git directory")?;
    let common_git = run_success_text(
        executor,
        &git_command(&repository, &["rev-parse", "--git-common-dir"]),
        "resolve source repository common Git directory",
    )?;
    let common_git = {
        let reported = PathBuf::from(common_git);
        if reported.is_absolute() {
            reported
        } else {
            repository.join(reported)
        }
    }
    .canonicalize()
    .context("canonicalize source repository common Git directory")?;
    if common_git != dot_git {
        bail!("source repository must be the primary common checkout");
    }
    let symbolic_ref = run_success_text(
        executor,
        &git_command(&repository, &["symbolic-ref", "--quiet", "HEAD"]),
        "resolve source repository authoritative ref",
    )?;
    if symbolic_ref != "refs/heads/main" {
        bail!("source repository must have authoritative main checked out");
    }
    require_clean_ordinary_checkout(executor, &repository, "source repository")?;
    let head = run_success_text(
        executor,
        &git_command(&repository, &["rev-parse", "--verify", "HEAD^{commit}"]),
        "resolve source repository HEAD",
    )?;
    let tree = run_success_text(
        executor,
        &git_command(&repository, &["rev-parse", "--verify", "HEAD^{tree}"]),
        "resolve source repository tree",
    )?;
    let main = run_success_text(
        executor,
        &git_command(
            &repository,
            &["rev-parse", "--verify", "refs/heads/main^{commit}"],
        ),
        "resolve source repository authoritative main",
    )?;
    if head != expected_commit || main != expected_commit || tree != expected_tree {
        bail!("source repository HEAD or tree does not match the projection receipt");
    }
    let authority_sha256 = source_authority_sha256(
        &repository,
        &common_git,
        git_object_format,
        expected_commit,
        expected_tree,
    )?;
    require_clean_ordinary_checkout(executor, &repository, "source repository")?;
    Ok(VerifiedSourceRepository {
        path: repository,
        authority_sha256,
    })
}

fn source_authority_sha256(
    repository: &Path,
    common_git: &Path,
    git_object_format: GitObjectFormat,
    commit: &str,
    tree: &str,
) -> Result<String> {
    let repository = repository
        .to_str()
        .ok_or_else(|| anyhow!("source repository path is not UTF-8"))?;
    let common_git_text = common_git
        .to_str()
        .ok_or_else(|| anyhow!("private source Git directory path is not UTF-8"))?;
    let metadata =
        fs::symlink_metadata(common_git).context("inspect private source Git authority")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("private source Git authority must be a real directory");
    }
    let object_format = match git_object_format {
        GitObjectFormat::Sha1 => b"sha1".as_slice(),
        GitObjectFormat::Sha256 => b"sha256".as_slice(),
    };
    let mut hasher = Sha256::new();
    hasher.update(b"autocad-mcp.preview-source-authority/v1\0");
    for component in [
        repository.as_bytes(),
        common_git_text.as_bytes(),
        b"refs/heads/main".as_slice(),
        object_format,
        commit.as_bytes(),
        tree.as_bytes(),
    ] {
        hasher.update(
            u64::try_from(component.len())
                .expect("authority component length fits u64")
                .to_be_bytes(),
        );
        hasher.update(component);
    }
    #[cfg(unix)]
    {
        hasher.update(metadata.dev().to_be_bytes());
        hasher.update(metadata.ino().to_be_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn require_clean_ordinary_checkout(
    executor: &mut dyn PublicationCommandExecutor,
    repository: &Path,
    label: &str,
) -> Result<()> {
    let status = run_success_output(
        executor,
        &git_command(
            repository,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        ),
        &format!("inspect {label} worktree"),
    )?;
    if !status.is_empty() {
        bail!("{label} worktree is not completely clean");
    }
    let index = run_success_output(
        executor,
        &git_command(repository, &["ls-files", "-v", "-z"]),
        &format!("inspect {label} index flags"),
    )?;
    if index.is_empty()
        || index
            .split(|byte| *byte == 0)
            .filter(|record| !record.is_empty())
            .any(|record| !record.starts_with(b"H "))
    {
        bail!("{label} index contains nonordinary tracked-file flags");
    }
    Ok(())
}

fn verify_projection_repository(
    executor: &mut dyn PublicationCommandExecutor,
    requested: &Path,
    expected_commit: &str,
    expected_tree: &str,
) -> Result<PathBuf> {
    require_real_directory(requested, "public projection repository")?;
    let repository = requested
        .canonicalize()
        .context("canonicalize public projection repository")?;
    let status = run_success_output(
        executor,
        &git_command(
            &repository,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        ),
        "inspect public projection worktree",
    )?;
    if !status.is_empty() {
        bail!("public projection worktree is not completely clean");
    }
    let index = run_success_output(
        executor,
        &git_command(&repository, &["ls-files", "-v", "-z"]),
        "inspect public projection index flags",
    )?;
    if index.is_empty()
        || index
            .split(|byte| *byte == 0)
            .filter(|record| !record.is_empty())
            .any(|record| !record.starts_with(b"H "))
    {
        bail!("public projection index contains nonordinary tracked-file flags");
    }
    let branch = run_success_text(
        executor,
        &git_command(&repository, &["symbolic-ref", "--short", "HEAD"]),
        "inspect public projection branch",
    )?;
    if branch != "main" {
        bail!("public projection must have main checked out");
    }
    let shallow = run_success_text(
        executor,
        &git_command(&repository, &["rev-parse", "--is-shallow-repository"]),
        "inspect public projection history boundary",
    )?;
    if shallow != "false" {
        bail!("public projection must not be a shallow repository");
    }
    let commit_object = run_success_output(
        executor,
        &git_command(&repository, &["cat-file", "-p", "HEAD"]),
        "inspect public projection root commit",
    )?;
    let expected_commit_object = format!(
        "tree {expected_tree}\nauthor {PROJECTION_AUTHOR} {PROJECTION_TIMESTAMP}\ncommitter {PROJECTION_AUTHOR} {PROJECTION_TIMESTAMP}\n\n{PROJECTION_MESSAGE}\n"
    );
    if commit_object != expected_commit_object.as_bytes() {
        bail!(
            "public projection root commit metadata and message are not the deterministic publication identity"
        );
    }
    let commit_count = run_success_text(
        executor,
        &git_command(&repository, &["rev-list", "--count", "--all"]),
        "count public projection commits",
    )?;
    if commit_count != "1" {
        bail!("public projection must contain exactly one reachable commit");
    }
    let head = run_success_text(
        executor,
        &git_command(&repository, &["rev-parse", "--verify", "HEAD^{commit}"]),
        "resolve public projection HEAD",
    )?;
    let tree = run_success_text(
        executor,
        &git_command(&repository, &["rev-parse", "--verify", "HEAD^{tree}"]),
        "resolve public projection tree",
    )?;
    if head != expected_commit || tree != expected_tree {
        bail!("public projection HEAD or tree does not match the signed handoff");
    }
    Ok(repository)
}

fn require_immutable_releases_enabled(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
) -> Result<()> {
    run_github_success(
        executor,
        github,
        &github_api(
            github,
            "GET",
            PREVIEW_GITHUB_IMMUTABLE_RELEASES_ENDPOINT,
            None,
        ),
        "inspect GitHub immutable-release setting",
    )
}

fn require_fixed_public_repository(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
) -> Result<()> {
    let repository: GitHubRepository = run_github_json(
        executor,
        github,
        &github_api(
            github,
            "GET",
            &format!("repos/{PREVIEW_GITHUB_REPOSITORY}"),
            None,
        ),
        "inspect fixed GitHub repository identity",
    )?;
    if repository.full_name != PREVIEW_GITHUB_REPOSITORY
        || repository.private
        || repository.visibility != "public"
        || repository.archived
        || repository.disabled
        || repository.default_branch != "main"
    {
        bail!(
            "GitHub destination is not the exact active public repository with default branch main"
        );
    }
    Ok(())
}

fn require_neutral_github_publisher(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
) -> Result<()> {
    let actor: GitHubActor = run_github_json(
        executor,
        github,
        &github_api(github, "GET", "user", None),
        "inspect authenticated GitHub publication principal",
    )?;
    if actor.login != PREVIEW_GITHUB_PUBLISHER_LOGIN {
        bail!("authenticated GitHub principal is not the approved neutral publication identity");
    }
    Ok(())
}

fn require_remote_main(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    expected_commit: &str,
) -> Result<()> {
    let reference: GitHubReference = run_github_json(
        executor,
        github,
        &github_api(
            github,
            "GET",
            &format!("repos/{PREVIEW_GITHUB_REPOSITORY}/git/ref/heads/main"),
            None,
        ),
        "resolve fixed repository remote main",
    )?;
    if reference.reference != "refs/heads/main"
        || reference.object.object_type != "commit"
        || reference.object.sha != expected_commit
    {
        bail!("fixed repository remote main does not match the signed projection commit");
    }
    const PAGE_SIZE: usize = 100;
    let mut page = 1_u32;
    let mut branches = Vec::new();
    loop {
        let current: Vec<GitHubBranch> = run_github_json(
            executor,
            github,
            &github_api(
                github,
                "GET",
                &format!(
                    "repos/{PREVIEW_GITHUB_REPOSITORY}/branches?per_page={PAGE_SIZE}&page={page}"
                ),
                None,
            ),
            "enumerate fixed repository branch inventory",
        )?;
        let count = current.len();
        branches.extend(current);
        if count < PAGE_SIZE {
            break;
        }
        page = page
            .checked_add(1)
            .ok_or_else(|| anyhow!("GitHub branch pagination overflowed"))?;
    }
    if branches.len() != 1
        || branches[0].name != "main"
        || branches[0].commit.sha != expected_commit
    {
        bail!("fixed repository must expose exactly the signed main branch and no stale heads");
    }
    Ok(())
}

fn require_release_tag_absent(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    tag: &str,
) -> Result<()> {
    require_release_tag_cardinality(executor, github, tag, None)
}

fn require_only_created_release_with_tag(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    tag: &str,
    release_id: u64,
) -> Result<()> {
    require_release_tag_cardinality(executor, github, tag, Some(release_id))
}

fn require_release_tag_cardinality(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    tag: &str,
    allowed_release_id: Option<u64>,
) -> Result<()> {
    const PAGE_SIZE: usize = 100;
    let mut page = 1_u32;
    let mut matches = Vec::new();
    loop {
        let releases: Vec<GitHubRelease> = run_github_json(
            executor,
            github,
            &github_api(
                github,
                "GET",
                &format!(
                    "repos/{PREVIEW_GITHUB_REPOSITORY}/releases?per_page={PAGE_SIZE}&page={page}"
                ),
                None,
            ),
            "enumerate all GitHub releases including drafts",
        )?;
        matches.extend(
            releases
                .iter()
                .filter(|release| release.tag_name == tag)
                .map(|release| release.id),
        );
        if releases.len() < PAGE_SIZE {
            break;
        }
        page = page
            .checked_add(1)
            .ok_or_else(|| anyhow!("GitHub release pagination overflowed"))?;
    }
    match allowed_release_id {
        None if matches.is_empty() => Ok(()),
        Some(expected) if matches == [expected] => Ok(()),
        None => bail!("matching GitHub release or draft already exists; refusing to resume"),
        Some(_) => bail!("GitHub release listing does not contain only the freshly created draft"),
    }
}

fn require_remote_absent(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    endpoint: &str,
    label: &str,
) -> Result<()> {
    let result =
        execute_github_command(executor, github, &github_api(github, "GET", endpoint, None))?;
    if result.success {
        bail!("matching GitHub {label} already exists; refusing to resume or overwrite");
    }
    let stderr = String::from_utf8_lossy(&result.stderr);
    if !stderr.contains("HTTP 404") {
        bail!(
            "could not prove matching GitHub {label} absence (status {:?})",
            result.status_code
        );
    }
    Ok(())
}

fn get_release(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    release_id: u64,
) -> Result<GitHubRelease> {
    run_github_json(
        executor,
        github,
        &github_api(
            github,
            "GET",
            &format!("repos/{PREVIEW_GITHUB_REPOSITORY}/releases/{release_id}"),
            None,
        ),
        "inspect GitHub Preview prerelease",
    )
}

fn require_release_state(
    release: &GitHubRelease,
    expected_tag: &str,
    expected_commit: &str,
    expected_name: &str,
    expected_draft: bool,
    expected_immutable: bool,
) -> Result<()> {
    if release.upload_url != expected_release_upload_url(release.id)
        || release.tag_name != expected_tag
        || release.target_commitish != expected_commit
        || release.name != expected_name
        || release.body != PREVIEW_RELEASE_BODY
        || release.draft != expected_draft
        || !release.prerelease
        || release.immutable != expected_immutable
        || release.author.login != PREVIEW_GITHUB_PUBLISHER_LOGIN
    {
        bail!("GitHub Preview prerelease state does not match the closed publication plan");
    }
    Ok(())
}

trait PublicAssetDescriptor {
    fn asset_name(&self) -> &str;
    fn sha256(&self) -> &str;
    fn size_bytes(&self) -> u64;
}

impl PublicAssetDescriptor for PreviewPublicAsset {
    fn asset_name(&self) -> &str {
        &self.asset_name
    }

    fn sha256(&self) -> &str {
        &self.sha256
    }

    fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

impl PublicAssetDescriptor for StagedPublicAsset {
    fn asset_name(&self) -> &str {
        &self.asset_name
    }

    fn sha256(&self) -> &str {
        &self.sha256
    }

    fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

fn require_exact_remote_assets<T: PublicAssetDescriptor>(
    remote: &[GitHubAsset],
    local: &[T],
) -> Result<()> {
    if remote.len() != local.len() {
        bail!("GitHub release does not contain exactly the seven public assets");
    }
    let mut remote_by_name = BTreeMap::new();
    for asset in remote {
        if remote_by_name.insert(asset.name.as_str(), asset).is_some() {
            bail!("GitHub release reports duplicate asset names");
        }
    }
    for asset in local {
        let remote_asset = remote_by_name
            .get(asset.asset_name())
            .ok_or_else(|| anyhow!("GitHub release is missing {}", asset.asset_name()))?;
        let expected_digest = format!("sha256:{}", asset.sha256());
        if remote_asset.state != "uploaded"
            || remote_asset.size != asset.size_bytes()
            || remote_asset.digest.as_deref() != Some(expected_digest.as_str())
            || remote_asset.uploader.login != PREVIEW_GITHUB_PUBLISHER_LOGIN
        {
            bail!(
                "GitHub asset {} size, SHA-256 digest, state, or uploader does not match the closed publication plan",
                asset.asset_name()
            );
        }
    }
    Ok(())
}

fn expected_release_upload_url(release_id: u64) -> String {
    format!(
        "https://uploads.github.com/repos/{PREVIEW_GITHUB_REPOSITORY}/releases/{release_id}/assets{{?name,label}}"
    )
}

fn require_exact_remote_tag(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    tag: &str,
    expected_commit: &str,
) -> Result<()> {
    let reference: GitHubReference = run_github_json(
        executor,
        github,
        &github_api(
            github,
            "GET",
            &format!("repos/{PREVIEW_GITHUB_REPOSITORY}/git/ref/tags/{tag}"),
            None,
        ),
        "inspect immutable Preview tag target",
    )?;
    if reference.reference != format!("refs/tags/{tag}")
        || reference.object.object_type != "commit"
        || reference.object.sha != expected_commit
    {
        bail!("immutable Preview tag does not target the exact projection commit");
    }
    Ok(())
}

fn github_api(
    github: &GitHubTransport,
    method: &str,
    endpoint: &str,
    stdin: Option<Vec<u8>>,
) -> CommandInvocation {
    let mut arguments = vec![
        "api".to_owned(),
        "--hostname".to_owned(),
        PREVIEW_GITHUB_HOST.to_owned(),
        "--method".to_owned(),
        method.to_owned(),
        "-H".to_owned(),
        format!("Accept: {GITHUB_ACCEPT}"),
        "-H".to_owned(),
        format!("X-GitHub-Api-Version: {GITHUB_API_VERSION}"),
        endpoint.to_owned(),
    ];
    if stdin.is_some() {
        arguments.push("--input".to_owned());
        arguments.push("-".to_owned());
    }
    CommandInvocation {
        program: github.program.clone(),
        arguments,
        current_directory: None,
        clear_environment: true,
        removed_environment: Vec::new(),
        environment: github_environment(github),
        stdin,
    }
}

fn upload_release_assets(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    release: &GitHubRelease,
    assets: &mut [StagedPublicAsset],
) -> Result<()> {
    if assets.len() != 7 || release.upload_url != expected_release_upload_url(release.id) {
        bail!("Preview asset upload is not bound to the exact freshly created release");
    }
    let mut names = BTreeSet::new();
    for asset in assets {
        if !names.insert(asset.asset_name.clone()) {
            bail!("Preview public asset names must be unique");
        }
        require_unchanged_staged_asset(asset)?;
        let uploaded: GitHubAsset = run_github_json_with_file_stdin(
            executor,
            github,
            &github_asset_upload_command(github, release, asset)?,
            &asset.file,
            "upload one exact Preview release asset",
        )?;
        require_unchanged_staged_asset(asset)?;
        require_exact_remote_assets(std::slice::from_ref(&uploaded), std::slice::from_ref(asset))?;
    }
    Ok(())
}

fn github_asset_upload_command(
    github: &GitHubTransport,
    release: &GitHubRelease,
    asset: &StagedPublicAsset,
) -> Result<CommandInvocation> {
    if release.upload_url != expected_release_upload_url(release.id)
        || !asset
            .asset_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("Preview release upload URL or asset name is not the closed expected form");
    }
    let base_url = release
        .upload_url
        .strip_suffix("{?name,label}")
        .ok_or_else(|| anyhow!("GitHub release upload URL has an unexpected template"))?;
    Ok(CommandInvocation {
        program: github.program.clone(),
        arguments: vec![
            "api".to_owned(),
            "--hostname".to_owned(),
            PREVIEW_GITHUB_HOST.to_owned(),
            "--method".to_owned(),
            "POST".to_owned(),
            "-H".to_owned(),
            format!("Accept: {GITHUB_ACCEPT}"),
            "-H".to_owned(),
            format!("X-GitHub-Api-Version: {GITHUB_API_VERSION}"),
            "-H".to_owned(),
            "Content-Type: application/octet-stream".to_owned(),
            format!("{base_url}?name={}", asset.asset_name),
            "--input".to_owned(),
            "-".to_owned(),
        ],
        current_directory: None,
        clear_environment: true,
        removed_environment: Vec::new(),
        environment: github_environment(github),
        stdin: None,
    })
}

fn github_release_verify_command(github: &GitHubTransport, tag: &str) -> CommandInvocation {
    CommandInvocation {
        program: github.program.clone(),
        arguments: vec![
            "release".to_owned(),
            "verify".to_owned(),
            tag.to_owned(),
            "--repo".to_owned(),
            PREVIEW_GITHUB_CLI_REPOSITORY.to_owned(),
        ],
        current_directory: None,
        clear_environment: true,
        removed_environment: Vec::new(),
        environment: github_environment(github),
        stdin: None,
    }
}

fn github_release_verify_capability_command(github: &GitHubTransport) -> CommandInvocation {
    CommandInvocation {
        program: github.program.clone(),
        arguments: vec![
            "release".to_owned(),
            "verify".to_owned(),
            "__autocad_mcp_nonexistent_capability_probe__".to_owned(),
            "--help".to_owned(),
            "--repo".to_owned(),
            PREVIEW_GITHUB_CLI_REPOSITORY.to_owned(),
        ],
        current_directory: None,
        clear_environment: true,
        removed_environment: Vec::new(),
        environment: github_environment(github),
        stdin: None,
    }
}

fn require_release_verification_capability(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
) -> Result<()> {
    run_github_success(
        executor,
        github,
        &github_release_verify_capability_command(github),
        "preflight GitHub release-integrity verification capability",
    )
}

fn github_environment(github: &GitHubTransport) -> Vec<(String, String)> {
    vec![
        (
            "GH_CONFIG_DIR".to_owned(),
            github.config_directory_environment.clone(),
        ),
        ("GH_PROMPT_DISABLED".to_owned(), "1".to_owned()),
        ("GH_NO_UPDATE_NOTIFIER".to_owned(), "1".to_owned()),
        ("GH_NO_EXTENSION_UPDATE_NOTIFIER".to_owned(), "1".to_owned()),
        ("GH_TELEMETRY".to_owned(), "false".to_owned()),
        ("DO_NOT_TRACK".to_owned(), "1".to_owned()),
    ]
}

fn git_command(repository: &Path, arguments: &[&str]) -> CommandInvocation {
    let mut command_arguments = vec![
        "--no-replace-objects".to_owned(),
        "-C".to_owned(),
        repository.to_string_lossy().into_owned(),
    ];
    command_arguments.extend(arguments.iter().map(|argument| (*argument).to_owned()));
    CommandInvocation {
        program: TRUSTED_GIT_PROGRAM.to_owned(),
        arguments: command_arguments,
        current_directory: Some(repository.to_owned()),
        clear_environment: true,
        removed_environment: Vec::new(),
        environment: hardened_git_environment(),
        stdin: None,
    }
}

fn run_success_output(
    executor: &mut dyn PublicationCommandExecutor,
    invocation: &CommandInvocation,
    label: &str,
) -> Result<Vec<u8>> {
    let result = executor.execute(invocation)?;
    if !result.success {
        bail!("{label} failed with status {:?}", result.status_code);
    }
    Ok(result.stdout)
}

fn run_success_text(
    executor: &mut dyn PublicationCommandExecutor,
    invocation: &CommandInvocation,
    label: &str,
) -> Result<String> {
    let bytes = run_success_output(executor, invocation, label)?;
    let text = String::from_utf8(bytes).with_context(|| format!("{label} returned non-UTF-8"))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn run_github_success(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    invocation: &CommandInvocation,
    label: &str,
) -> Result<()> {
    run_github_success_output(executor, github, invocation, label).map(|_| ())
}

fn run_github_success_output(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    invocation: &CommandInvocation,
    label: &str,
) -> Result<Vec<u8>> {
    let result = execute_github_command(executor, github, invocation)?;
    if !result.success {
        bail!("{label} failed with status {:?}", result.status_code);
    }
    Ok(result.stdout)
}

fn execute_github_command(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    invocation: &CommandInvocation,
) -> Result<CommandResult> {
    github.require_intact()?;
    let result = executor.execute_with_github_token(invocation, &github.token);
    let recheck = github.require_intact();
    match (result, recheck) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(recheck_error)) => Err(anyhow!(
            "{error:#}; additionally, GitHub transport integrity recheck failed: {recheck_error:#}"
        )),
    }
}

fn run_github_json<T: DeserializeOwned>(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    invocation: &CommandInvocation,
    label: &str,
) -> Result<T> {
    let bytes = run_github_success_output(executor, github, invocation, label)?;
    parse_json_bytes(&bytes, label)
}

fn run_github_json_with_file_stdin<T: DeserializeOwned>(
    executor: &mut dyn PublicationCommandExecutor,
    github: &GitHubTransport,
    invocation: &CommandInvocation,
    input: &File,
    label: &str,
) -> Result<T> {
    if invocation.stdin.is_some() {
        bail!("{label} command unexpectedly has an in-memory stdin source");
    }
    github.require_intact()?;
    let result =
        executor.execute_with_github_token_and_file_stdin(invocation, &github.token, input);
    let recheck = github.require_intact();
    let result = match (result, recheck) {
        (Ok(result), Ok(())) => result,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(error),
        (Err(error), Err(recheck_error)) => {
            return Err(anyhow!(
            "{error:#}; additionally, GitHub transport integrity recheck failed: {recheck_error:#}"
        ))
        }
    };
    if !result.success {
        bail!("{label} failed with status {:?}", result.status_code);
    }
    parse_json_bytes(&result.stdout, label)
}

fn parse_json_bytes<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T> {
    let value = distribution_approval::parse_strict_json(bytes)
        .with_context(|| format!("strictly parse {label} response"))?;
    serde_json::from_value(value).with_context(|| format!("validate {label} response"))
}

#[cfg(test)]
impl GitHubTransport {
    fn for_test(config_directory: PathBuf) -> Self {
        let config_directory_environment = config_directory.to_string_lossy().into_owned();
        Self {
            config_directory,
            config_directory_environment,
            program: "/test/gh".to_owned(),
            program_path: PathBuf::from("/test/gh"),
            program_snapshot: None,
            token: "test-token".to_owned(),
            enforce_local_filesystem: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct ScriptedExecutor {
        results: VecDeque<CommandResult>,
        seen: Vec<CommandInvocation>,
    }

    impl ScriptedExecutor {
        fn with_results(results: impl IntoIterator<Item = CommandResult>) -> Self {
            Self {
                results: results.into_iter().collect(),
                seen: Vec::new(),
            }
        }
    }

    impl PublicationCommandExecutor for ScriptedExecutor {
        fn execute(&mut self, invocation: &CommandInvocation) -> Result<CommandResult> {
            self.seen.push(invocation.clone());
            self.results
                .pop_front()
                .ok_or_else(|| anyhow!("unexpected test command"))
        }
    }

    struct TransportErrorExecutor {
        first: bool,
        remaining: VecDeque<CommandResult>,
    }

    impl TransportErrorExecutor {
        fn then(results: impl IntoIterator<Item = CommandResult>) -> Self {
            Self {
                first: true,
                remaining: results.into_iter().collect(),
            }
        }
    }

    impl PublicationCommandExecutor for TransportErrorExecutor {
        fn execute(&mut self, _invocation: &CommandInvocation) -> Result<CommandResult> {
            if self.first {
                self.first = false;
                return Err(anyhow!("connection lost after request dispatch"));
            }
            self.remaining
                .pop_front()
                .ok_or_else(|| anyhow!("unexpected test command"))
        }
    }

    fn success(stdout: impl Into<Vec<u8>>) -> CommandResult {
        CommandResult {
            success: true,
            status_code: Some(0),
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    fn failure_404() -> CommandResult {
        CommandResult {
            success: false,
            status_code: Some(1),
            stdout: Vec::new(),
            stderr: b"gh: Not Found (HTTP 404)\n".to_vec(),
        }
    }

    fn assets() -> Vec<PreviewPublicAsset> {
        PREVIEW_PUBLICATION_PUBLIC_ASSET_PATHS
            .iter()
            .copied()
            .chain(std::iter::once(PREVIEW_PUBLICATION_SHA256SUMS_PATH))
            .enumerate()
            .map(|(index, logical_path)| PreviewPublicAsset {
                asset_name: Path::new(logical_path)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned(),
                path: PathBuf::from("/detached").join(logical_path),
                sha256: format!("{:064x}", index + 1),
                size_bytes: u64::try_from(index + 1).unwrap(),
            })
            .collect()
    }

    fn neutral_actor() -> GitHubActor {
        GitHubActor {
            login: PREVIEW_GITHUB_PUBLISHER_LOGIN.to_owned(),
        }
    }

    fn remote_assets(local: &[PreviewPublicAsset]) -> Vec<GitHubAsset> {
        local
            .iter()
            .map(|asset| GitHubAsset {
                name: asset.asset_name.clone(),
                size: asset.size_bytes,
                digest: Some(format!("sha256:{}", asset.sha256)),
                state: "uploaded".to_owned(),
                uploader: neutral_actor(),
            })
            .collect()
    }

    fn github_release(
        id: u64,
        tag: &str,
        commit: &str,
        name: &str,
        draft: bool,
        immutable: bool,
        assets: Vec<GitHubAsset>,
    ) -> GitHubRelease {
        GitHubRelease {
            id,
            upload_url: expected_release_upload_url(id),
            tag_name: tag.to_owned(),
            target_commitish: commit.to_owned(),
            name: name.to_owned(),
            body: PREVIEW_RELEASE_BODY.to_owned(),
            draft,
            prerelease: true,
            immutable,
            author: neutral_actor(),
            assets,
        }
    }

    fn test_snapshot(sha256: String, size_bytes: u64) -> FileSnapshot {
        FileSnapshot {
            sha256,
            size_bytes,
            #[cfg(unix)]
            device: 1,
            #[cfg(unix)]
            inode: size_bytes,
            #[cfg(unix)]
            modified_seconds: 1,
            #[cfg(unix)]
            modified_nanoseconds: 2,
            #[cfg(unix)]
            changed_seconds: 3,
            #[cfg(unix)]
            changed_nanoseconds: 4,
            #[cfg(target_os = "windows")]
            volume_serial_number: 1,
            #[cfg(target_os = "windows")]
            file_id: [u8::try_from(size_bytes).unwrap(); 16],
            #[cfg(target_os = "windows")]
            last_write_time: 1,
            #[cfg(target_os = "windows")]
            change_time: 2,
        }
    }

    fn test_github() -> GitHubTransport {
        GitHubTransport::for_test(PathBuf::from("/detached/.gh-config"))
    }

    #[test]
    fn github_commands_pin_transport_clear_environment_and_never_record_the_token() {
        let github = test_github();
        let command = github_api(
            &github,
            "POST",
            "repos/andagni/autocad-mcp/releases",
            Some(br#"{"draft":true}"#.to_vec()),
        );
        assert_eq!(command.program, "/test/gh");
        assert!(command
            .arguments
            .windows(2)
            .any(|pair| pair == ["--hostname", PREVIEW_GITHUB_HOST]));
        assert!(command.arguments.windows(2).any(|pair| pair
            == [
                "X-GitHub-Api-Version: 2026-03-10",
                "repos/andagni/autocad-mcp/releases"
            ]));
        assert!(command.clear_environment);
        assert!(command.removed_environment.is_empty());
        assert_eq!(command.environment, github_environment(&github));
        assert!(command
            .environment
            .iter()
            .any(|(name, value)| name == "GH_CONFIG_DIR" && value == "/detached/.gh-config"));
        for (name, value) in [
            ("GH_PROMPT_DISABLED", "1"),
            ("GH_NO_UPDATE_NOTIFIER", "1"),
            ("GH_NO_EXTENSION_UPDATE_NOTIFIER", "1"),
            ("GH_TELEMETRY", "false"),
            ("DO_NOT_TRACK", "1"),
        ] {
            assert!(command
                .environment
                .iter()
                .any(|(actual_name, actual_value)| actual_name == name && actual_value == value));
        }
        assert!(command
            .environment
            .iter()
            .all(|(name, value)| name != "GH_TOKEN" && value != "test-token"));
        assert_eq!(command.stdin, Some(br#"{"draft":true}"#.to_vec()));
        assert!(command
            .arguments
            .ends_with(&["--input".to_owned(), "-".to_owned()]));

        let verify = github_release_verify_command(&github, "v0.0.1-preview.1");
        assert!(verify.stdin.is_none());
        assert_eq!(verify.environment, command.environment);
        assert!(verify.clear_environment);
        assert!(verify
            .arguments
            .windows(2)
            .any(|pair| pair == ["--repo", PREVIEW_GITHUB_CLI_REPOSITORY]));
        assert_eq!(verify.removed_environment, command.removed_environment);
    }

    #[test]
    fn publisher_refuses_to_start_without_exclusive_write_confirmation() {
        let error = publish_preview_prerelease(&PublishPreviewPrereleaseOptions {
            handoff_directory: PathBuf::from("/does/not/matter"),
            source_repository: PathBuf::from("/does/not/matter"),
            projection_repository: PathBuf::from("/does/not/matter"),
            github_cli: PathBuf::from("/does/not/matter"),
            key_id: "owner-preview-1".to_owned(),
            public_key_hex: "a".repeat(64),
            serial: 1,
            exclusive_write_window_confirmed: false,
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("exclusive write window"),
            "{error:#}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn upload_plan_uses_anonymous_descriptor_snapshots_and_the_created_release_id() {
        let github = test_github();
        let source = tempfile::tempdir().unwrap();
        let originals = assets()
            .into_iter()
            .enumerate()
            .map(|(index, mut asset)| {
                let bytes = vec![u8::try_from(index + 1).unwrap(); index + 1];
                asset.path = source.path().join(&asset.asset_name);
                fs::write(&asset.path, &bytes).unwrap();
                asset.sha256 = sha256_hex(&bytes);
                asset.size_bytes = u64::try_from(bytes.len()).unwrap();
                asset
            })
            .collect::<Vec<_>>();
        let staged = stage_public_assets(&originals).unwrap();
        for original in &originals {
            fs::write(&original.path, b"private replacement bytes").unwrap();
        }
        let release = github_release(
            7,
            "v0.0.1-preview.1",
            &"a".repeat(40),
            "AutoCAD MCP 0.0.1 Preview 1",
            true,
            false,
            Vec::new(),
        );
        for (original, asset) in originals.iter().zip(&staged.assets) {
            let command = github_asset_upload_command(&github, &release, asset).unwrap();
            assert!(command
                .arguments
                .windows(2)
                .any(|pair| pair == ["--hostname", PREVIEW_GITHUB_HOST]));
            assert!(command.clear_environment);
            assert!(command.removed_environment.is_empty());
            assert_eq!(command.environment, github_environment(&github));
            assert!(command.stdin.is_none());
            assert!(command
                .arguments
                .ends_with(&["--input".to_owned(), "-".to_owned()]));
            assert!(!command
                .arguments
                .iter()
                .any(|argument| argument == original.path.to_str().unwrap()));
            assert!(command.arguments.iter().any(|argument| {
                argument
                    == &format!(
                    "https://uploads.github.com/repos/{PREVIEW_GITHUB_REPOSITORY}/releases/7/assets?name={}",
                    asset.asset_name
                )
            }));
            let metadata = asset.file.metadata().unwrap();
            assert_eq!(metadata.nlink(), 0);
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
        for forbidden in ["--clobber", "delete", "edit", "create"] {
            assert!(staged.assets.iter().all(|asset| {
                !github_asset_upload_command(&github, &release, asset)
                    .unwrap()
                    .arguments
                    .iter()
                    .any(|argument| argument == forbidden)
            }));
        }
        staged.directory.close().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_private_key_policy_requires_effective_owner_mode_and_no_acl() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owner.key");
        fs::write(&path, [7_u8; 32]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        require_private_key_metadata(&metadata).unwrap();
        let file = File::open(&path).unwrap();
        require_no_macos_extended_acl(&file, "test owner signing key").unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o604)).unwrap();
        assert!(require_private_key_metadata(&fs::symlink_metadata(&path).unwrap()).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_private_file_policy_rejects_an_actual_extended_acl_entry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owner.key");
        fs::write(&path, [7_u8; 32]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let file = File::open(&path).unwrap();

        let acl = Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone allow read")
            .arg(&path)
            .status();
        let Ok(status) = acl else {
            eprintln!("SKIP: this macOS host could not execute /bin/chmod to create a test ACL");
            return;
        };
        if !status.success() {
            eprintln!("SKIP: this macOS filesystem could not create a test extended ACL");
            return;
        }

        let error = require_no_macos_extended_acl(&file, "test owner signing key").unwrap_err();
        assert!(
            error.to_string().contains("must not have any extended ACL"),
            "{error:#}"
        );
    }

    #[test]
    fn public_checksum_inventory_uses_downloaded_asset_names() {
        let files = PREVIEW_PUBLICATION_PUBLIC_ASSET_PATHS
            .iter()
            .copied()
            .enumerate()
            .map(|(index, logical_path)| {
                (
                    logical_path.to_owned(),
                    test_snapshot(
                        format!("{:064x}", index + 1),
                        u64::try_from(index + 1).unwrap(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let checksum_bytes = expected_public_sha256s(&files).unwrap();
        let checksum_text = String::from_utf8(checksum_bytes).unwrap();
        assert_eq!(checksum_text.lines().count(), 6);
        for line in checksum_text.lines() {
            let (_, name) = line
                .split_once("  ")
                .expect("checksum line should contain a filename");
            assert!(!name.contains('/'), "{name}");
            assert!(!name.contains('\\'), "{name}");
        }
        assert!(checksum_text.contains("windows-x64-preview-source-closure.spdx.json"));
        assert!(!checksum_text.contains("distribution-evidence/"));
    }

    #[test]
    fn projection_plan_disables_replace_refs_and_rejects_index_flags() {
        let directory = tempfile::tempdir().unwrap();
        let canonical_directory = directory.path().canonicalize().unwrap();
        let mut executor = ScriptedExecutor::with_results([
            success(Vec::new()),
            success(b"S hidden.txt\0".to_vec()),
        ]);
        let error = verify_projection_repository(
            &mut executor,
            directory.path(),
            &"a".repeat(40),
            &"b".repeat(40),
        )
        .unwrap_err();
        assert!(error.to_string().contains("nonordinary"));
        assert!(executor.seen.iter().all(|command| {
            command.program == TRUSTED_GIT_PROGRAM
                && command.arguments.first().map(String::as_str) == Some("--no-replace-objects")
                && command.clear_environment
                && command.current_directory.as_deref() == Some(canonical_directory.as_path())
                && command
                    .environment
                    .iter()
                    .any(|(name, value)| name == "GIT_CONFIG_GLOBAL" && value == "/dev/null")
                && command
                    .environment
                    .iter()
                    .any(|(name, value)| name == "GIT_NO_REPLACE_OBJECTS" && value == "1")
        }));
        let names = hardened_git_environment()
            .into_iter()
            .map(|(name, _)| name)
            .collect::<BTreeSet<_>>();
        for poisoned in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_COMMON_DIR",
            "GIT_CONFIG",
            "GIT_CONFIG_PARAMETERS",
        ] {
            assert!(!names.contains(poisoned), "{poisoned}");
        }
    }

    #[test]
    fn detached_directory_check_rejects_an_ambiguous_broken_git_boundary() {
        let ordinary = tempfile::tempdir().unwrap();
        assert!(!is_inside_git_worktree(ordinary.path()).unwrap());

        let broken = tempfile::tempdir().unwrap();
        fs::create_dir(broken.path().join(".git")).unwrap();
        fs::write(
            broken.path().join(".git").join("HEAD"),
            b"ref: refs/heads/main\n",
        )
        .unwrap();
        fs::write(broken.path().join(".git").join("config"), b"[broken\n").unwrap();
        let error = is_inside_git_worktree(broken.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("could not prove that the detached directory"),
            "{error:#}"
        );
    }

    #[test]
    fn projection_plan_accepts_only_clean_single_commit_main() {
        let directory = tempfile::tempdir().unwrap();
        let commit = "a".repeat(40);
        let tree = "b".repeat(40);
        let mut executor = ScriptedExecutor::with_results([
            success(Vec::new()),
            success(b"H Cargo.toml\0H src/lib.rs\0".to_vec()),
            success(b"main\n".to_vec()),
            success(b"false\n".to_vec()),
            success(
                format!(
                    "tree {tree}\nauthor {PROJECTION_AUTHOR} {PROJECTION_TIMESTAMP}\ncommitter {PROJECTION_AUTHOR} {PROJECTION_TIMESTAMP}\n\n{PROJECTION_MESSAGE}\n"
                )
                .into_bytes(),
            ),
            success(b"1\n".to_vec()),
            success(format!("{commit}\n").into_bytes()),
            success(format!("{tree}\n").into_bytes()),
        ]);
        let canonical =
            verify_projection_repository(&mut executor, directory.path(), &commit, &tree).unwrap();
        assert_eq!(canonical, directory.path().canonicalize().unwrap());
        assert_eq!(executor.seen.len(), 8);
    }

    #[test]
    fn projection_timestamp_is_bound_to_initial_publication() {
        assert_eq!(PROJECTION_TIMESTAMP, "1785307643 +0100");
    }

    #[test]
    fn projection_plan_rejects_shallow_or_nondeterministic_root_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let commit = "a".repeat(40);
        let tree = "b".repeat(40);
        let prefix = [
            success(Vec::new()),
            success(b"H Cargo.toml\0".to_vec()),
            success(b"main\n".to_vec()),
        ];

        let mut shallow = ScriptedExecutor::with_results(
            prefix
                .clone()
                .into_iter()
                .chain([success(b"true\n".to_vec())]),
        );
        let error = verify_projection_repository(&mut shallow, directory.path(), &commit, &tree)
            .unwrap_err();
        assert!(error.to_string().contains("must not be a shallow"));

        let mut parented = ScriptedExecutor::with_results(prefix.into_iter().chain([
            success(b"false\n".to_vec()),
            success(format!("tree {tree}\nparent {}\n\nnot a root\n", "c".repeat(40)).into_bytes()),
        ]));
        let error = verify_projection_repository(&mut parented, directory.path(), &commit, &tree)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("deterministic publication identity"));
    }

    #[test]
    fn source_repository_requires_clean_ordinary_exact_head_and_tree() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join(".git")).unwrap();
        let canonical = directory.path().canonicalize().unwrap();
        let commit = "a".repeat(40);
        let tree = "b".repeat(40);
        let passing = [
            success(format!("{}\n", canonical.display()).into_bytes()),
            success(b".git\n".to_vec()),
            success(b"refs/heads/main\n".to_vec()),
            success(Vec::new()),
            success(b"H Cargo.toml\0".to_vec()),
            success(format!("{commit}\n").into_bytes()),
            success(format!("{tree}\n").into_bytes()),
            success(format!("{commit}\n").into_bytes()),
            success(Vec::new()),
            success(b"H Cargo.toml\0".to_vec()),
        ];
        let mut executor = ScriptedExecutor::with_results(passing.clone());
        let verified = verify_source_repository(
            &mut executor,
            directory.path(),
            GitObjectFormat::Sha1,
            &commit,
            &tree,
        )
        .unwrap();
        assert_eq!(verified.path, canonical);
        assert_eq!(verified.authority_sha256.len(), 64);
        assert!(executor
            .seen
            .iter()
            .all(|command| command.clear_environment));

        let mut stale = ScriptedExecutor::with_results([
            success(
                format!("{}\n", directory.path().canonicalize().unwrap().display()).into_bytes(),
            ),
            success(b".git\n".to_vec()),
            success(b"refs/heads/main\n".to_vec()),
            success(Vec::new()),
            success(b"H Cargo.toml\0".to_vec()),
            success(format!("{}\n", "c".repeat(40)).into_bytes()),
            success(format!("{tree}\n").into_bytes()),
            success(format!("{commit}\n").into_bytes()),
        ]);
        let error = verify_source_repository(
            &mut stale,
            directory.path(),
            GitObjectFormat::Sha1,
            &commit,
            &tree,
        )
        .unwrap_err();
        assert!(error.to_string().contains("projection receipt"));
    }

    #[test]
    fn immutable_setting_uses_the_dedicated_versioned_endpoint() {
        let github = test_github();
        let mut executor =
            ScriptedExecutor::with_results([success(br#"{"enabled":true}"#.to_vec())]);
        require_immutable_releases_enabled(&mut executor, &github).unwrap();
        let command = &executor.seen[0];
        assert!(command
            .arguments
            .iter()
            .any(|argument| argument == "repos/andagni/autocad-mcp/immutable-releases"));
    }

    #[test]
    fn destination_repository_main_and_publisher_identity_are_closed() {
        let github = test_github();
        let valid_repository = serde_json::json!({
            "full_name": PREVIEW_GITHUB_REPOSITORY,
            "private": false,
            "visibility": "public",
            "archived": false,
            "disabled": false,
            "default_branch": "main"
        });
        let mut executor = ScriptedExecutor::with_results([success(
            serde_json::to_vec(&valid_repository).unwrap(),
        )]);
        require_fixed_public_repository(&mut executor, &github).unwrap();

        for (field, value) in [
            ("full_name", serde_json::json!("personal/autocad-mcp")),
            ("private", serde_json::json!(true)),
            ("visibility", serde_json::json!("private")),
            ("archived", serde_json::json!(true)),
            ("disabled", serde_json::json!(true)),
            ("default_branch", serde_json::json!("develop")),
        ] {
            let mut drifted = valid_repository.clone();
            drifted[field] = value;
            let mut executor =
                ScriptedExecutor::with_results([success(serde_json::to_vec(&drifted).unwrap())]);
            assert!(
                require_fixed_public_repository(&mut executor, &github).is_err(),
                "{field}"
            );
        }

        let commit = "a".repeat(40);
        let valid_ref = serde_json::json!({
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": commit}
        });
        let valid_branches = serde_json::json!([
            {"name": "main", "commit": {"sha": commit}}
        ]);
        let mut executor = ScriptedExecutor::with_results([
            success(serde_json::to_vec(&valid_ref).unwrap()),
            success(serde_json::to_vec(&valid_branches).unwrap()),
        ]);
        require_remote_main(&mut executor, &github, &commit).unwrap();
        for drifted in [
            serde_json::json!({"ref": "refs/heads/other", "object": {"type": "commit", "sha": commit}}),
            serde_json::json!({"ref": "refs/heads/main", "object": {"type": "tag", "sha": commit}}),
            serde_json::json!({"ref": "refs/heads/main", "object": {"type": "commit", "sha": "b".repeat(40)}}),
        ] {
            let mut executor =
                ScriptedExecutor::with_results([success(serde_json::to_vec(&drifted).unwrap())]);
            assert!(require_remote_main(&mut executor, &github, &commit).is_err());
        }

        let mut neutral =
            ScriptedExecutor::with_results([success(br#"{"login":"andagni"}"#.to_vec())]);
        require_neutral_github_publisher(&mut neutral, &github).unwrap();
        let mut personal =
            ScriptedExecutor::with_results([success(br#"{"login":"personal-user"}"#.to_vec())]);
        assert!(require_neutral_github_publisher(&mut personal, &github).is_err());
    }

    #[test]
    fn remote_branch_inventory_is_complete_and_rejects_a_later_page_stale_head() {
        let github = test_github();
        let commit = "a".repeat(40);
        let valid_ref = serde_json::json!({
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": commit}
        });
        let mut first_page = (0..100)
            .map(|index| {
                serde_json::json!({
                    "name": if index == 0 {
                        "main".to_owned()
                    } else {
                        format!("stale-{index}")
                    },
                    "commit": {"sha": commit}
                })
            })
            .collect::<Vec<_>>();
        first_page.sort_by(|left, right| {
            left["name"]
                .as_str()
                .unwrap()
                .cmp(right["name"].as_str().unwrap())
        });
        let second_page = serde_json::json!([
            {"name": "stale-later-page", "commit": {"sha": commit}}
        ]);
        let mut executor = ScriptedExecutor::with_results([
            success(serde_json::to_vec(&valid_ref).unwrap()),
            success(serde_json::to_vec(&first_page).unwrap()),
            success(serde_json::to_vec(&second_page).unwrap()),
        ]);

        let error = require_remote_main(&mut executor, &github, &commit).unwrap_err();
        assert!(error.to_string().contains("no stale heads"), "{error:#}");
        assert_eq!(executor.seen.len(), 3);
        assert!(executor.seen[2]
            .arguments
            .iter()
            .any(|argument| argument.ends_with("per_page=100&page=2")));
    }

    #[test]
    fn release_tag_scan_includes_drafts_and_complete_pagination() {
        let github = test_github();
        let tag = "v0.0.1-preview.1";
        let first_page = (1..=100)
            .map(|id| {
                github_release(
                    id,
                    &format!("v0.0.1-preview.other-{id}"),
                    &"a".repeat(40),
                    "other",
                    true,
                    false,
                    Vec::new(),
                )
            })
            .collect::<Vec<_>>();
        let stale = github_release(
            101,
            tag,
            &"a".repeat(40),
            "stale draft",
            true,
            false,
            Vec::new(),
        );
        let mut executor = ScriptedExecutor::with_results([
            success(serde_json::to_vec(&first_page).unwrap()),
            success(serde_json::to_vec(&vec![stale]).unwrap()),
        ]);
        assert!(require_release_tag_absent(&mut executor, &github, tag).is_err());
        assert_eq!(executor.seen.len(), 2);
        assert!(executor.seen[1]
            .arguments
            .iter()
            .any(|argument| argument.ends_with("per_page=100&page=2")));

        let created = github_release(
            7,
            tag,
            &"a".repeat(40),
            "fresh draft",
            true,
            false,
            Vec::new(),
        );
        let mut executor =
            ScriptedExecutor::with_results([success(serde_json::to_vec(&vec![created]).unwrap())]);
        require_only_created_release_with_tag(&mut executor, &github, tag, 7).unwrap();
    }

    #[test]
    fn release_verification_capability_failure_is_nonmutating() {
        let github = test_github();
        let mut executor = ScriptedExecutor::with_results([CommandResult {
            success: false,
            status_code: Some(1),
            stdout: Vec::new(),
            stderr: b"unknown command verify".to_vec(),
        }]);
        assert!(require_release_verification_capability(&mut executor, &github).is_err());
        assert_eq!(executor.seen.len(), 1);
        let command = &executor.seen[0];
        assert!(command
            .arguments
            .iter()
            .any(|argument| argument == "--help"));
        assert!(command
            .arguments
            .windows(2)
            .any(|pair| pair == ["--repo", PREVIEW_GITHUB_CLI_REPOSITORY]));
        assert!(!command.arguments.iter().any(|argument| {
            matches!(argument.as_str(), "create" | "upload" | "delete" | "edit")
        }));
    }

    #[test]
    fn only_an_explicit_github_404_proves_remote_absence() {
        let github = test_github();
        let mut absent = ScriptedExecutor::with_results([failure_404()]);
        require_remote_absent(&mut absent, &github, "repos/example", "tag").unwrap();

        let mut ambiguous = ScriptedExecutor::with_results([CommandResult {
            success: false,
            status_code: Some(1),
            stdout: Vec::new(),
            stderr: b"authentication failed".to_vec(),
        }]);
        assert!(require_remote_absent(&mut ambiguous, &github, "repos/example", "tag").is_err());
    }

    #[test]
    fn release_state_and_asset_parser_require_exact_immutable_bytes() {
        let local = assets();
        let remote = remote_assets(&local);
        require_exact_remote_assets(&remote, &local).unwrap();

        let mut wrong = remote.clone();
        wrong[0].digest = Some(format!("sha256:{}", "f".repeat(64)));
        assert!(require_exact_remote_assets(&wrong, &local).is_err());

        let release = github_release(
            7,
            "v0.0.1-preview.1",
            &"a".repeat(40),
            "AutoCAD MCP 0.0.1 Preview 1",
            false,
            true,
            remote,
        );
        require_release_state(
            &release,
            "v0.0.1-preview.1",
            &"a".repeat(40),
            "AutoCAD MCP 0.0.1 Preview 1",
            false,
            true,
        )
        .unwrap();
        let mut drifted = release;
        drifted.body.push_str("changed");
        assert!(require_release_state(
            &drifted,
            "v0.0.1-preview.1",
            &"a".repeat(40),
            "AutoCAD MCP 0.0.1 Preview 1",
            false,
            true,
        )
        .is_err());
        let mut personal_author = drifted;
        personal_author.body = PREVIEW_RELEASE_BODY.to_owned();
        personal_author.author.login = "personal-user".to_owned();
        assert!(require_release_state(
            &personal_author,
            "v0.0.1-preview.1",
            &"a".repeat(40),
            "AutoCAD MCP 0.0.1 Preview 1",
            false,
            true,
        )
        .is_err());

        let mut personal_asset = remote_assets(&local);
        personal_asset[0].uploader.login = "personal-user".to_owned();
        assert!(require_exact_remote_assets(&personal_asset, &local).is_err());
    }

    #[test]
    fn publish_transport_errors_always_reconcile_the_irreversible_outcome() {
        let github = test_github();
        let local = assets();
        let remote = remote_assets(&local);
        let release = |draft, immutable| {
            github_release(
                7,
                "v0.0.1-preview.1",
                &"a".repeat(40),
                "AutoCAD MCP 0.0.1 Preview 1",
                draft,
                immutable,
                remote.clone(),
            )
        };
        let invocation = github_api(
            &github,
            "PATCH",
            "repos/andagni/autocad-mcp/releases/7",
            Some(br#"{"draft":false}"#.to_vec()),
        );
        let commit = "a".repeat(40);
        let expected = ExpectedReleaseState {
            release_id: 7,
            tag: "v0.0.1-preview.1",
            commit: &commit,
            name: "AutoCAD MCP 0.0.1 Preview 1",
            assets: &local,
        };

        let published = release(false, true);
        let mut executor =
            TransportErrorExecutor::then([success(serde_json::to_vec(&published).unwrap())]);
        assert_eq!(
            publish_and_reconcile(&mut executor, &github, &invocation, &expected).unwrap(),
            published
        );

        let mut executor = TransportErrorExecutor::then([success(
            serde_json::to_vec(&release(true, false)).unwrap(),
        )]);
        let error =
            publish_and_reconcile(&mut executor, &github, &invocation, &expected).unwrap_err();
        assert!(error
            .to_string()
            .contains("exact draft remains unpublished"));

        let mut executor = TransportErrorExecutor::then([failure_404()]);
        let error =
            publish_and_reconcile(&mut executor, &github, &invocation, &expected).unwrap_err();
        assert!(error.to_string().contains("outcome is ambiguous"));
        assert!(error.to_string().contains("may already exist"));
    }

    #[test]
    fn post_dispatch_remote_drift_is_an_ambiguous_incident_not_a_safe_draft_failure() {
        let github = test_github();
        let local = assets();
        let remote = remote_assets(&local);
        let baseline = github_release(
            7,
            "v0.0.1-preview.1",
            &"a".repeat(40),
            "AutoCAD MCP 0.0.1 Preview 1",
            false,
            true,
            remote,
        );
        let invocation = github_api(
            &github,
            "PATCH",
            "repos/andagni/autocad-mcp/releases/7",
            Some(br#"{"draft":false}"#.to_vec()),
        );
        let commit = "a".repeat(40);
        let expected = ExpectedReleaseState {
            release_id: 7,
            tag: "v0.0.1-preview.1",
            commit: &commit,
            name: "AutoCAD MCP 0.0.1 Preview 1",
            assets: &local,
        };
        let mut extra_asset = baseline.clone();
        extra_asset.assets.push(GitHubAsset {
            name: "injected.bin".to_owned(),
            size: 1,
            digest: Some(format!("sha256:{}", "f".repeat(64))),
            state: "uploaded".to_owned(),
            uploader: neutral_actor(),
        });
        let mut mutable = baseline.clone();
        mutable.immutable = false;
        let mut wrong_target = baseline;
        wrong_target.target_commitish = "b".repeat(40);

        for drifted in [extra_asset, mutable, wrong_target] {
            let encoded = serde_json::to_vec(&drifted).unwrap();
            let mut executor =
                ScriptedExecutor::with_results([success(encoded.clone()), success(encoded)]);
            let error =
                publish_and_reconcile(&mut executor, &github, &invocation, &expected).unwrap_err();
            assert!(
                error.to_string().contains("outcome is ambiguous"),
                "{error:#}"
            );
            assert_eq!(
                executor.seen.len(),
                2,
                "publication reconciliation must not retry the PATCH"
            );
        }
    }

    #[test]
    fn github_asset_size_limit_is_checked_before_remote_mutation() {
        let mut local = assets();
        require_uploadable_assets(&local).unwrap();
        local[0].size_bytes = 2 * 1024 * 1024 * 1024;
        assert!(require_uploadable_assets(&local).is_err());
    }

    #[test]
    fn closed_json_parser_rejects_duplicate_selection_fields() {
        let error = parse_closed_json::<ProjectionReceipt>(
            br#"{"schema_version":1,"schema_version":1}"#,
            "projection receipt",
        )
        .unwrap_err();
        assert!(error.to_string().contains("strictly parse"));
    }
}
