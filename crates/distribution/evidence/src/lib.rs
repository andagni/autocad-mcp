use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

pub const POLICY_PATH: &str = "plugin/.third-party/third-party-license-policy.json";
pub const SBOM_PATH: &str = "plugin/.third-party/source-lock.spdx.json";
pub const NOTICES_PATH: &str = "plugin/THIRD_PARTY_LICENSES.txt";
pub const WINDOWS_SOURCE_CLOSURE_SBOM_PATH: &str =
    "plugin/.third-party/source-closure-windows.spdx.json";
pub const LICENSE_PROVENANCE_PATH: &str = "plugin/.third-party/third-party-license-provenance.json";

const POLICY_SCHEMA_VERSION: u32 = 2;
const EVIDENCE_GENERATOR_SCHEMA_VERSION: u32 = 7;
const GENERATOR_SOURCE_PATH: &str = "crates/distribution/evidence/src/lib.rs";
const RUST_TOOLCHAIN_PATH: &str = "rust-toolchain.toml";
const OWNER_APPROVAL_SCHEMA_PATH: &str =
    "crates/distribution/approval/schemas/owner-distribution-approval.schema.json";
const SPDX_VERSION: &str = "SPDX-2.3";
const SPDX_DATA_LICENSE: &str = "CC0-1.0";
const SPDX_DOCUMENT_ID: &str = "SPDXRef-DOCUMENT";
const WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";
const WINDOWS_PRODUCT_ROOTS: [&str; 2] = ["autocad-mcp", "autolisp-lsp"];
const DETACHED_APPROVAL_MODE: &str = "detached_per_distribution_set";
const OWNER_APPROVAL_SCHEMA_VERSION: u32 = distribution_approval::APPROVAL_SCHEMA_VERSION;

#[derive(Clone, Copy)]
enum MetadataMode {
    Complete,
    WindowsRelease,
    WindowsPreview,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThirdPartyLicensePolicy {
    schema_version: u32,
    evidence_generator_schema_version: u32,
    evidence_document_created_utc: String,
    reviewed_cargo_lock_sha256: String,
    reviewed_input_closure_sha256: String,
    expected_sbom_sha256: String,
    expected_windows_source_closure_sbom_sha256: String,
    expected_notices_sha256: String,
    expected_license_provenance_sha256: String,
    expected_total_packages: usize,
    expected_third_party_packages: usize,
    expected_windows_source_closure_packages: usize,
    expected_windows_source_closure_third_party_packages: usize,
    allowed_registry_sources: Vec<String>,
    allowed_spdx_license_ids: Vec<String>,
    allowed_spdx_exception_ids: Vec<String>,
    non_spdx_declared_license_values: Vec<String>,
    expected_packages_without_retained_license_files: Vec<PackageIdentity>,
    owner_distribution_approval: OwnerDistributionApprovalContract,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct PackageIdentity {
    name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerDistributionApprovalContract {
    mode: String,
    contract_schema_version: u32,
    contract_schema_path: String,
    contract_schema_sha256: String,
    required_for: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LicenseProvenance {
    schema_version: u32,
    status: String,
    legal_effect: ProvenanceLegalEffect,
    sources: Vec<ProvenanceSource>,
    package_bindings: Vec<ProvenancePackageBinding>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceLegalEffect {
    approval_status: String,
    approval_reference: Option<String>,
    statement: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ProvenanceSource {
    UpstreamGitBlob {
        id: String,
        repository_url: String,
        git_commit: String,
        git_blob_sha1: String,
        repository_path: String,
        tracked_path: String,
        byte_length: u64,
        sha256: String,
        root_notice_search: RootNoticeSearch,
        content_note: String,
    },
    ChecksumVerifiedCrateArchiveMembers {
        id: String,
        repository_url: String,
        git_commit: String,
        source_package: ProvenancePackageIdentity,
        archive_members: Vec<ProvenanceArchiveMember>,
        content_note: String,
    },
}

impl ProvenanceSource {
    fn id(&self) -> &str {
        match self {
            Self::UpstreamGitBlob { id, .. }
            | Self::ChecksumVerifiedCrateArchiveMembers { id, .. } => id,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootNoticeSearch {
    git_commit: String,
    tree_enumeration: String,
    root_candidate_names: Vec<String>,
    matches: Vec<String>,
    result: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenancePackageIdentity {
    name: String,
    version: String,
    archive_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceArchiveMember {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenancePackageBinding {
    package: ProvenanceBoundPackage,
    path_in_vcs: String,
    git_commit: String,
    source_id: String,
    license_concluded: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceBoundPackage {
    name: String,
    version: String,
    archive_sha256: String,
    declared_license: String,
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<MetadataPackage>,
    workspace_members: Vec<String>,
    resolve: MetadataResolve,
}

struct WindowsModeMetadata<'a> {
    release: &'a CargoMetadata,
    preview: &'a CargoMetadata,
}

#[derive(Clone, Debug, Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
    license: Option<String>,
    license_file: Option<String>,
    manifest_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct MetadataResolve {
    nodes: Vec<MetadataNode>,
}

#[derive(Debug, Deserialize)]
struct MetadataNode {
    id: String,
    dependencies: Vec<String>,
    #[serde(default)]
    deps: Vec<MetadataDependency>,
}

#[derive(Clone, Debug, Deserialize)]
struct MetadataDependency {
    pkg: String,
    dep_kinds: Vec<MetadataDependencyKind>,
}

#[derive(Clone, Debug, Deserialize)]
struct MetadataDependencyKind {
    kind: Option<String>,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SelectedDependencyEdge {
    source_package_id: String,
    target_package_id: String,
    dependency_kinds: Vec<Option<String>>,
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

#[derive(Clone, Debug)]
struct LicenseEvidenceFile {
    relative_path: String,
    sha256: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoVcsInfo {
    git: CargoVcsGit,
    path_in_vcs: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoVcsGit {
    sha1: String,
}

struct CollectedArchiveEvidence {
    license_files: Vec<LicenseEvidenceFile>,
    cargo_vcs_info: Option<Vec<u8>>,
}

#[derive(Debug)]
struct AuditedPackage {
    metadata: MetadataPackage,
    lock_checksum: Option<String>,
    spdx_id: String,
    retained_license_files: Vec<LicenseEvidenceFile>,
    cargo_vcs_info: Option<Vec<u8>>,
}

#[derive(Debug)]
struct GeneratedEvidence {
    sbom: Vec<u8>,
    windows_source_closure_sbom: Vec<u8>,
    notices: Vec<u8>,
    total_packages: usize,
    third_party_packages: usize,
    windows_source_closure_packages: usize,
    windows_source_closure_third_party_packages: usize,
    packages_without_retained_license_files: Vec<PackageIdentity>,
}

struct ValidatedLicenseProvenance {
    supplemental_notice_sections: Vec<SupplementalNoticeSection>,
}

struct LicenseProvenanceInputs {
    document: LicenseProvenance,
    bytes: Vec<u8>,
    tracked_files: BTreeMap<String, Vec<u8>>,
}

struct SupplementalNoticeSection {
    source_id: String,
    applies_to: Vec<PackageIdentity>,
    evidence_description: String,
    files: Vec<LicenseEvidenceFile>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceSummary {
    total_packages: usize,
    third_party_packages: usize,
    windows_source_closure_packages: usize,
    windows_source_closure_third_party_packages: usize,
    packages_without_retained_license_files: usize,
    owner_approval_mode: String,
}

impl EvidenceSummary {
    pub fn total_packages(&self) -> usize {
        self.total_packages
    }

    pub fn third_party_packages(&self) -> usize {
        self.third_party_packages
    }

    pub fn windows_source_closure_packages(&self) -> usize {
        self.windows_source_closure_packages
    }

    pub fn windows_source_closure_third_party_packages(&self) -> usize {
        self.windows_source_closure_third_party_packages
    }

    pub fn packages_without_retained_license_files(&self) -> usize {
        self.packages_without_retained_license_files
    }

    pub fn owner_approval_mode(&self) -> &str {
        &self.owner_approval_mode
    }
}

/// Validate the repository's tracked distribution evidence without changing it.
pub fn check(repository: &Path) -> Result<EvidenceSummary, String> {
    run(repository, false, false)
}

/// Return the closed content identity used by advisory validation receipts.
///
/// This is deliberately cheaper than [`check`]: it validates the reviewed
/// policy and its exact tracked inputs and outputs, but it does not regenerate
/// the evidence from every checksum-verified registry archive. A caller may use
/// this identity only to look up a prior successful `check` result recorded
/// under an equally bound tool and execution context. The identity is not
/// distribution approval, release evidence, or a substitute for an initial
/// full validation.
pub fn validation_cache_input_sha256(repository: &Path) -> Result<String, String> {
    let policy_bytes =
        read_regular_file(&repository.join(POLICY_PATH), "third-party licence policy")?;
    let policy: ThirdPartyLicensePolicy = parse_strict_document(
        &policy_bytes,
        &format!(
            "third-party licence policy {}",
            repository.join(POLICY_PATH).display()
        ),
    )?;
    validate_policy_shape(&policy)?;

    let lock_bytes = read_regular_file(&repository.join("Cargo.lock"), "Cargo.lock")?;
    let lock_sha256 = sha256(&lock_bytes);
    if lock_sha256 != policy.reviewed_cargo_lock_sha256 {
        return Err(format!(
            "Cargo.lock SHA-256 is {lock_sha256}, but the third-party licence policy reviews {}",
            policy.reviewed_cargo_lock_sha256
        ));
    }

    let metadata = cargo_metadata(repository, MetadataMode::Complete)?;
    let provenance = load_license_provenance(repository, &policy)?;
    let owner_approval_schema = read_regular_file(
        &repository.join(OWNER_APPROVAL_SCHEMA_PATH),
        "owner distribution approval schema",
    )?;
    let owner_approval_schema_sha256 = sha256(&owner_approval_schema);
    if owner_approval_schema_sha256 != policy.owner_distribution_approval.contract_schema_sha256 {
        return Err(format!(
            "owner distribution approval schema SHA-256 is {owner_approval_schema_sha256}, but the third-party licence policy expects {}",
            policy.owner_distribution_approval.contract_schema_sha256
        ));
    }
    let input_closure_sha256 = calculate_input_closure(
        repository,
        &lock_bytes,
        &metadata,
        &policy,
        &provenance,
        &owner_approval_schema,
    )?;
    if input_closure_sha256 != policy.reviewed_input_closure_sha256 {
        return Err(format!(
            "distribution evidence input-closure SHA-256 is {input_closure_sha256}, but the policy reviews {}",
            policy.reviewed_input_closure_sha256
        ));
    }

    let mut hasher = Sha256::new();
    hash_framed(
        &mut hasher,
        b"receipt-domain",
        b"autocad-mcp-distribution-evidence-validation-cache-v1",
    );
    hash_framed(&mut hasher, b"policy", &policy_bytes);
    hash_framed(
        &mut hasher,
        b"reviewed-input-closure",
        input_closure_sha256.as_bytes(),
    );
    for (path, expected) in [
        (SBOM_PATH, policy.expected_sbom_sha256.as_str()),
        (
            WINDOWS_SOURCE_CLOSURE_SBOM_PATH,
            policy.expected_windows_source_closure_sbom_sha256.as_str(),
        ),
        (NOTICES_PATH, policy.expected_notices_sha256.as_str()),
    ] {
        let bytes = read_regular_file(&repository.join(path), path)?;
        let actual = sha256(&bytes);
        if actual != expected {
            return Err(format!(
                "{path} SHA-256 is {actual}, but the reviewed policy expects {expected}"
            ));
        }
        hash_framed(&mut hasher, b"tracked-artifact-path", path.as_bytes());
        hash_framed(&mut hasher, b"tracked-artifact-bytes", &bytes);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Regenerate the tracked distribution evidence atomically and validate the result.
pub fn write(repository: &Path) -> Result<EvidenceSummary, String> {
    run(repository, true, false)
}

/// Apply the distribution release gate.
///
/// Source-closure and third-party licence evidence alone cannot satisfy this
/// gate: a detached owner approval bound to the finished distribution must be
/// verified by the distribution approval verifier.
pub fn release_gate(repository: &Path) -> Result<EvidenceSummary, String> {
    run(repository, false, true)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxDocument {
    spdx_version: &'static str,
    data_license: &'static str,
    #[serde(rename = "SPDXID")]
    spdx_id: &'static str,
    name: String,
    document_namespace: String,
    creation_info: SpdxCreationInfo,
    document_describes: Vec<String>,
    packages: Vec<SpdxPackage>,
    relationships: Vec<SpdxRelationship>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxCreationInfo {
    created: String,
    creators: Vec<String>,
    comment: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    version_info: String,
    download_location: &'static str,
    files_analyzed: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    checksums: Vec<SpdxChecksum>,
    license_concluded: &'static str,
    license_declared: String,
    license_comments: String,
    copyright_text: &'static str,
    source_info: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxChecksum {
    algorithm: &'static str,
    checksum_value: String,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxRelationship {
    spdx_element_id: String,
    relationship_type: &'static str,
    related_spdx_element: String,
}

fn run(
    repository: &Path,
    write: bool,
    require_distribution_approval: bool,
) -> Result<EvidenceSummary, String> {
    let policy = read_policy(repository)?;
    validate_policy_shape(&policy)?;

    let lock_bytes = read_regular_file(&repository.join("Cargo.lock"), "Cargo.lock")?;
    let lock_sha256 = sha256(&lock_bytes);
    if lock_sha256 != policy.reviewed_cargo_lock_sha256 {
        return Err(format!(
            "Cargo.lock SHA-256 is {lock_sha256}, but the third-party licence policy reviews {}; update the policy only after reviewing the new exact lock",
            policy.reviewed_cargo_lock_sha256
        ));
    }

    let metadata = cargo_metadata(repository, MetadataMode::Complete)?;
    let windows_release_metadata = cargo_metadata(repository, MetadataMode::WindowsRelease)?;
    let windows_preview_metadata = cargo_metadata(repository, MetadataMode::WindowsPreview)?;
    let provenance = load_license_provenance(repository, &policy)?;
    let owner_approval_schema = read_regular_file(
        &repository.join(OWNER_APPROVAL_SCHEMA_PATH),
        "owner distribution approval schema",
    )?;
    let owner_approval_schema_sha256 = sha256(&owner_approval_schema);
    if owner_approval_schema_sha256 != policy.owner_distribution_approval.contract_schema_sha256 {
        return Err(format!(
            "owner distribution approval schema SHA-256 is {owner_approval_schema_sha256}, but the third-party licence policy expects {}",
            policy
                .owner_distribution_approval
                .contract_schema_sha256
        ));
    }
    let input_closure_sha256 = calculate_input_closure(
        repository,
        &lock_bytes,
        &metadata,
        &policy,
        &provenance,
        &owner_approval_schema,
    )?;
    if input_closure_sha256 != policy.reviewed_input_closure_sha256 {
        return Err(format!(
            "distribution evidence input-closure SHA-256 is {input_closure_sha256}, but the policy reviews {}; review workspace manifests or generator inputs before updating the policy",
            policy.reviewed_input_closure_sha256
        ));
    }
    let lock_packages = parse_cargo_lock(&lock_bytes)?;
    let generated = generate_evidence(
        &policy,
        &metadata,
        WindowsModeMetadata {
            release: &windows_release_metadata,
            preview: &windows_preview_metadata,
        },
        &provenance,
        lock_packages,
        &lock_sha256,
        &input_closure_sha256,
    )?;
    validate_reviewed_inventory(&policy, &generated)?;

    if write {
        write_atomic(repository.join(SBOM_PATH), &generated.sbom)?;
        write_atomic(
            repository.join(WINDOWS_SOURCE_CLOSURE_SBOM_PATH),
            &generated.windows_source_closure_sbom,
        )?;
        write_atomic(repository.join(NOTICES_PATH), &generated.notices)?;
    }

    validate_tracked_artifact(
        repository,
        SBOM_PATH,
        &generated.sbom,
        &policy.expected_sbom_sha256,
    )?;
    validate_tracked_artifact(
        repository,
        WINDOWS_SOURCE_CLOSURE_SBOM_PATH,
        &generated.windows_source_closure_sbom,
        &policy.expected_windows_source_closure_sbom_sha256,
    )?;
    validate_tracked_artifact(
        repository,
        NOTICES_PATH,
        &generated.notices,
        &policy.expected_notices_sha256,
    )?;

    if require_distribution_approval {
        return Err(
            "distribution release gate requires a detached owner-distribution approval sidecar bound to the exact finished distribution set; use the distribution approval verifier rather than a policy status string"
                .to_owned(),
        );
    }

    Ok(EvidenceSummary {
        total_packages: generated.total_packages,
        third_party_packages: generated.third_party_packages,
        windows_source_closure_packages: generated.windows_source_closure_packages,
        windows_source_closure_third_party_packages: generated
            .windows_source_closure_third_party_packages,
        packages_without_retained_license_files: generated
            .packages_without_retained_license_files
            .len(),
        owner_approval_mode: policy.owner_distribution_approval.mode,
    })
}

fn read_policy(repository: &Path) -> Result<ThirdPartyLicensePolicy, String> {
    let path = repository.join(POLICY_PATH);
    let bytes = read_regular_file(&path, "third-party licence policy")?;
    parse_strict_document(
        &bytes,
        &format!("third-party licence policy {}", path.display()),
    )
}

fn validate_policy_shape(policy: &ThirdPartyLicensePolicy) -> Result<(), String> {
    if policy.schema_version != POLICY_SCHEMA_VERSION {
        return Err(format!(
            "unsupported third-party licence policy schema {}; expected {POLICY_SCHEMA_VERSION}",
            policy.schema_version
        ));
    }
    if policy.evidence_generator_schema_version != EVIDENCE_GENERATOR_SCHEMA_VERSION {
        return Err(format!(
            "unsupported distribution evidence generator schema {}; expected {EVIDENCE_GENERATOR_SCHEMA_VERSION}",
            policy.evidence_generator_schema_version
        ));
    }
    require_sha256(
        &policy.reviewed_cargo_lock_sha256,
        "reviewed_cargo_lock_sha256",
    )?;
    require_sha256(
        &policy.reviewed_input_closure_sha256,
        "reviewed_input_closure_sha256",
    )?;
    require_sha256(&policy.expected_sbom_sha256, "expected_sbom_sha256")?;
    require_sha256(
        &policy.expected_windows_source_closure_sbom_sha256,
        "expected_windows_source_closure_sbom_sha256",
    )?;
    require_sha256(&policy.expected_notices_sha256, "expected_notices_sha256")?;
    require_sha256(
        &policy.expected_license_provenance_sha256,
        "expected_license_provenance_sha256",
    )?;
    if policy.expected_windows_source_closure_packages == 0
        || policy.expected_windows_source_closure_third_party_packages == 0
        || policy.expected_windows_source_closure_third_party_packages
            >= policy.expected_windows_source_closure_packages
    {
        return Err(
            "Windows source closure package counts must contain workspace and third-party packages"
                .to_owned(),
        );
    }
    if !is_utc_timestamp(&policy.evidence_document_created_utc) {
        return Err("evidence_document_created_utc must use YYYY-MM-DDTHH:MM:SSZ".to_owned());
    }
    if policy.allowed_registry_sources.is_empty() {
        return Err("allowed_registry_sources must not be empty".to_owned());
    }
    require_sorted_unique(&policy.allowed_registry_sources, "allowed_registry_sources")?;
    require_sorted_unique(&policy.allowed_spdx_license_ids, "allowed_spdx_license_ids")?;
    require_sorted_unique(
        &policy.allowed_spdx_exception_ids,
        "allowed_spdx_exception_ids",
    )?;
    require_sorted_unique(
        &policy.non_spdx_declared_license_values,
        "non_spdx_declared_license_values",
    )?;
    require_sorted_unique(
        &policy.expected_packages_without_retained_license_files,
        "expected_packages_without_retained_license_files",
    )?;

    let approval = &policy.owner_distribution_approval;
    if approval.mode != DETACHED_APPROVAL_MODE {
        return Err(format!(
            "third-party licence policy owner_distribution_approval.mode must be {DETACHED_APPROVAL_MODE:?}"
        ));
    }
    if approval.contract_schema_version != OWNER_APPROVAL_SCHEMA_VERSION {
        return Err(format!(
            "owner distribution approval contract schema version must be {OWNER_APPROVAL_SCHEMA_VERSION}"
        ));
    }
    if approval.contract_schema_path != OWNER_APPROVAL_SCHEMA_PATH {
        return Err(format!(
            "owner distribution approval contract path must be {OWNER_APPROVAL_SCHEMA_PATH}"
        ));
    }
    require_sha256(
        &approval.contract_schema_sha256,
        "owner_distribution_approval.contract_schema_sha256",
    )?;
    let expected_required_for = [
        "public_binary_distribution".to_owned(),
        "public_source_distribution".to_owned(),
    ];
    if approval.required_for != expected_required_for {
        return Err(
            "owner_distribution_approval.required_for must exactly cover public binary and source distribution"
                .to_owned(),
        );
    }
    Ok(())
}

fn load_license_provenance(
    repository: &Path,
    policy: &ThirdPartyLicensePolicy,
) -> Result<LicenseProvenanceInputs, String> {
    let path = repository.join(LICENSE_PROVENANCE_PATH);
    let bytes = read_regular_file(&path, "third-party licence provenance ledger")?;
    let actual_sha256 = sha256(&bytes);
    if actual_sha256 != policy.expected_license_provenance_sha256 {
        return Err(format!(
            "third-party licence provenance SHA-256 is {actual_sha256}, but the policy expects {}",
            policy.expected_license_provenance_sha256
        ));
    }
    let document: LicenseProvenance = parse_strict_document(
        &bytes,
        &format!("third-party licence provenance {}", path.display()),
    )?;
    if document.schema_version != 1
        || document.status != "technical_provenance_only"
        || document.legal_effect.approval_status != "not_approved"
        || document.legal_effect.approval_reference.is_some()
        || document.legal_effect.statement.trim().is_empty()
    {
        return Err(
            "third-party licence provenance must remain schema-v1 technical evidence with no approval claim"
                .to_owned(),
        );
    }
    if document.sources.is_empty() || document.package_bindings.is_empty() {
        return Err(
            "third-party licence provenance must contain sources and package bindings".to_owned(),
        );
    }
    let source_ids = document
        .sources
        .iter()
        .map(|source| source.id())
        .collect::<Vec<_>>();
    if !source_ids.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(
            "third-party licence provenance source IDs must be sorted and unique".to_owned(),
        );
    }
    let binding_keys = document
        .package_bindings
        .iter()
        .map(|binding| {
            (
                binding.package.name.as_str(),
                binding.package.version.as_str(),
            )
        })
        .collect::<Vec<_>>();
    if !binding_keys.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(
            "third-party licence provenance package bindings must be sorted and unique".to_owned(),
        );
    }

    let mut tracked_files = BTreeMap::new();
    for source in &document.sources {
        match source {
            ProvenanceSource::UpstreamGitBlob {
                id,
                repository_url,
                git_commit,
                git_blob_sha1: expected_git_blob_sha1,
                repository_path,
                tracked_path,
                byte_length,
                sha256: expected_sha256,
                root_notice_search,
                content_note,
            } => {
                require_nonempty(id, "upstream provenance source id")?;
                require_nonempty(repository_url, "upstream provenance repository_url")?;
                require_git_sha1(git_commit, "upstream provenance git_commit")?;
                require_git_sha1(expected_git_blob_sha1, "upstream provenance git_blob_sha1")?;
                if repository_path != "LICENSE"
                    || !tracked_path.starts_with("plugin/.third-party/license-supplements/")
                    || normalized_relative_path_text(Path::new(tracked_path))? != *tracked_path
                {
                    return Err(format!(
                        "upstream provenance source {id} has an unsafe or unsupported evidence path"
                    ));
                }
                require_sha256(expected_sha256, "upstream provenance SHA-256")?;
                require_nonempty(content_note, "upstream provenance content_note")?;
                if root_notice_search.git_commit != *git_commit
                    || root_notice_search.tree_enumeration != "complete_non_truncated"
                    || root_notice_search.root_candidate_names
                        != ["NOTICE".to_owned(), "NOTICE.*".to_owned()]
                    || !root_notice_search.matches.is_empty()
                    || root_notice_search.result
                        != "no_root_notice_found_in_complete_non_truncated_tree"
                {
                    return Err(format!(
                        "upstream provenance source {id} has an incomplete root NOTICE search record"
                    ));
                }
                let evidence = read_regular_file(
                    &repository.join(tracked_path),
                    "supplemental third-party licence evidence",
                )?;
                if u64::try_from(evidence.len()).ok() != Some(*byte_length)
                    || sha256(&evidence) != *expected_sha256
                    || git_blob_sha1(&evidence)? != *expected_git_blob_sha1
                {
                    return Err(format!(
                        "supplemental third-party licence evidence {tracked_path} does not match its bound byte length, SHA-256, and Git blob identity"
                    ));
                }
                if tracked_files
                    .insert(tracked_path.clone(), evidence)
                    .is_some()
                {
                    return Err(format!(
                        "third-party licence provenance repeats tracked evidence {tracked_path}"
                    ));
                }
            }
            ProvenanceSource::ChecksumVerifiedCrateArchiveMembers {
                id,
                repository_url,
                git_commit,
                source_package,
                archive_members,
                content_note,
            } => {
                require_nonempty(id, "crate-member provenance source id")?;
                require_nonempty(repository_url, "crate-member provenance repository_url")?;
                require_git_sha1(git_commit, "crate-member provenance git_commit")?;
                require_nonempty(&source_package.name, "provenance source package name")?;
                require_nonempty(&source_package.version, "provenance source package version")?;
                require_sha256(
                    &source_package.archive_sha256,
                    "provenance source package archive_sha256",
                )?;
                require_nonempty(content_note, "crate-member provenance content_note")?;
                if archive_members.is_empty()
                    || !archive_members
                        .windows(2)
                        .all(|pair| pair[0].path < pair[1].path)
                {
                    return Err(format!(
                        "crate-member provenance source {id} archive members must be sorted and unique"
                    ));
                }
                for member in archive_members {
                    if normalized_relative_path_text(Path::new(&member.path))? != member.path {
                        return Err(format!(
                            "crate-member provenance source {id} has an unsafe member path"
                        ));
                    }
                    require_sha256(&member.sha256, "provenance archive member SHA-256")?;
                }
            }
        }
    }

    Ok(LicenseProvenanceInputs {
        document,
        bytes,
        tracked_files,
    })
}

fn parse_strict_document<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, String> {
    let value = distribution_approval::parse_strict_json(bytes)
        .map_err(|error| format!("parse strict {label}: {error}"))?;
    serde_json::from_value(value).map_err(|error| format!("decode closed {label}: {error}"))
}

fn require_nonempty(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_git_sha1(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{label} must be 40 lowercase hexadecimal digits"))
    }
}

fn git_blob_sha1(bytes: &[u8]) -> Result<String, String> {
    let mut child = Command::new("git")
        .args(["hash-object", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("launch git hash-object for provenance bytes: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "git hash-object stdin was unavailable".to_owned())?
        .write_all(bytes)
        .map_err(|error| format!("write provenance bytes to git hash-object: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for git hash-object: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git hash-object failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|error| format!("git hash-object output is not UTF-8: {error}"))?
        .trim();
    require_git_sha1(value, "git hash-object output")?;
    Ok(value.to_owned())
}

fn cargo_metadata(repository: &Path, mode: MetadataMode) -> Result<CargoMetadata, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.current_dir(repository).args([
        "metadata",
        "--locked",
        "--offline",
        "--format-version",
        "1",
    ]);
    match mode {
        MetadataMode::Complete => {}
        MetadataMode::WindowsRelease => {
            command.args(["--filter-platform", WINDOWS_TARGET, "--no-default-features"]);
        }
        MetadataMode::WindowsPreview => {
            command.args([
                "--filter-platform",
                WINDOWS_TARGET,
                "--no-default-features",
                "--features",
                "autocad-mcp/preview",
            ]);
        }
    }
    let output = command
        .output()
        .map_err(|error| format!("launch cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata {} failed with {}: {}\nfetch the exact lock first with `cargo fetch --locked`",
            metadata_mode_arguments(mode),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse cargo metadata format version 1: {error}"))
}

fn metadata_mode_arguments(mode: MetadataMode) -> &'static str {
    match mode {
        MetadataMode::Complete => "--locked --offline --format-version 1",
        MetadataMode::WindowsRelease => {
            "--locked --offline --format-version 1 --filter-platform x86_64-pc-windows-msvc --no-default-features"
        }
        MetadataMode::WindowsPreview => {
            "--locked --offline --format-version 1 --filter-platform x86_64-pc-windows-msvc --no-default-features --features autocad-mcp/preview"
        }
    }
}

fn parse_cargo_lock(bytes: &[u8]) -> Result<BTreeMap<PackageKey, LockPackage>, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|error| format!("Cargo.lock must be UTF-8: {error}"))?;
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
            return Err(format!(
                "Cargo.lock line {} has unsupported non-basic-string {key}",
                index + 1
            ));
        }
        let decoded: String = serde_json::from_str(value).map_err(|error| {
            format!(
                "Cargo.lock line {} has an unsupported {key} string: {error}",
                index + 1
            )
        })?;
        if fields.insert(key.to_owned(), decoded).is_some() {
            return Err(format!(
                "Cargo.lock package stanza repeats field {key} on line {}",
                index + 1
            ));
        }
    }
    if let Some(fields) = current {
        insert_lock_package(&mut packages, fields)?;
    }
    if packages.is_empty() {
        return Err("Cargo.lock contains no [[package]] entries".to_owned());
    }
    Ok(packages)
}

fn insert_lock_package(
    packages: &mut BTreeMap<PackageKey, LockPackage>,
    mut fields: BTreeMap<String, String>,
) -> Result<(), String> {
    let name = fields
        .remove("name")
        .ok_or_else(|| "Cargo.lock package has no name".to_owned())?;
    let version = fields
        .remove("version")
        .ok_or_else(|| format!("Cargo.lock package {name} has no version"))?;
    let source = fields.remove("source");
    let checksum = fields.remove("checksum");
    if source.is_some() {
        let value = checksum
            .as_deref()
            .ok_or_else(|| format!("Cargo.lock package {name} {version} has no checksum"))?;
        require_sha256(value, "Cargo.lock package checksum")?;
    } else if checksum.is_some() {
        return Err(format!(
            "Cargo.lock workspace package {name} {version} unexpectedly has a checksum"
        ));
    }
    let key = PackageKey {
        name,
        version,
        source,
    };
    let package = LockPackage { checksum };
    if packages.insert(key.clone(), package).is_some() {
        return Err(format!(
            "Cargo.lock repeats package {} {}",
            key.name, key.version
        ));
    }
    Ok(())
}

fn generate_evidence(
    policy: &ThirdPartyLicensePolicy,
    metadata: &CargoMetadata,
    windows_metadata: WindowsModeMetadata<'_>,
    provenance: &LicenseProvenanceInputs,
    mut lock_packages: BTreeMap<PackageKey, LockPackage>,
    lock_sha256: &str,
    input_closure_sha256: &str,
) -> Result<GeneratedEvidence, String> {
    let allowed_sources = policy
        .allowed_registry_sources
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let non_spdx = policy
        .non_spdx_declared_license_values
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let allowed_license_ids = policy
        .allowed_spdx_license_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let allowed_exception_ids = policy
        .allowed_spdx_exception_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    let mut audited = Vec::with_capacity(metadata.packages.len());
    let mut package_ids = BTreeMap::new();
    for package in &metadata.packages {
        let key = PackageKey {
            name: package.name.clone(),
            version: package.version.clone(),
            source: package.source.clone(),
        };
        let lock = lock_packages.remove(&key).ok_or_else(|| {
            format!(
                "cargo metadata package {} {} source {:?} is absent from Cargo.lock",
                package.name, package.version, package.source
            )
        })?;
        if let Some(source) = package.source.as_deref() {
            if !allowed_sources.contains(source) {
                return Err(format!(
                    "package {} {} uses unreviewed source {source}",
                    package.name, package.version
                ));
            }
        }
        match (package.source.as_deref(), lock.checksum.as_deref()) {
            (Some(_), None) => {
                return Err(format!(
                    "registry package {} {} has no Cargo.lock checksum",
                    package.name, package.version
                ))
            }
            (None, Some(_)) => {
                return Err(format!(
                    "workspace package {} {} unexpectedly has a Cargo.lock checksum",
                    package.name, package.version
                ))
            }
            _ => {}
        }
        let declared = package.license.as_deref().ok_or_else(|| {
            format!(
                "package {} {} has no Cargo manifest licence metadata",
                package.name, package.version
            )
        })?;
        if declared.trim().is_empty() {
            return Err(format!(
                "package {} {} has empty Cargo manifest licence metadata",
                package.name, package.version
            ));
        }
        if !non_spdx.contains(declared) {
            validate_spdx_expression(declared, &allowed_license_ids, &allowed_exception_ids)
                .map_err(|error| {
                    format!(
                        "package {} {} has unreviewed licence expression {declared:?}: {error}",
                        package.name, package.version
                    )
                })?;
        }
        let spdx_id = package_spdx_id(&key);
        if package_ids
            .insert(package.id.clone(), spdx_id.clone())
            .is_some()
        {
            return Err(format!("cargo metadata repeats package id {}", package.id));
        }
        let archive_evidence = match lock.checksum.as_deref() {
            Some(checksum) => collect_license_evidence(package, checksum)?,
            None => CollectedArchiveEvidence {
                license_files: Vec::new(),
                cargo_vcs_info: None,
            },
        };
        audited.push(AuditedPackage {
            metadata: package.clone(),
            lock_checksum: lock.checksum,
            spdx_id,
            retained_license_files: archive_evidence.license_files,
            cargo_vcs_info: archive_evidence.cargo_vcs_info,
        });
    }
    if !lock_packages.is_empty() {
        let omitted = lock_packages
            .keys()
            .map(|key| format!("{} {}", key.name, key.version))
            .collect::<Vec<_>>();
        return Err(format!(
            "Cargo.lock packages are absent from the complete cargo metadata graph: {}",
            omitted.join(", ")
        ));
    }
    audited.sort_by(|left, right| {
        (
            &left.metadata.name,
            &left.metadata.version,
            &left.metadata.source,
        )
            .cmp(&(
                &right.metadata.name,
                &right.metadata.version,
                &right.metadata.source,
            ))
    });

    let packages_without_retained_license_files = audited
        .iter()
        .filter(|package| {
            package.metadata.source.is_some() && package.retained_license_files.is_empty()
        })
        .map(|package| PackageIdentity {
            name: package.metadata.name.clone(),
            version: package.metadata.version.clone(),
        })
        .collect::<Vec<_>>();

    let third_party_packages = audited
        .iter()
        .filter(|package| package.metadata.source.is_some())
        .count();
    let sbom = render_spdx(
        policy,
        metadata,
        &audited,
        &package_ids,
        lock_sha256,
        input_closure_sha256,
        &non_spdx,
    )?;
    let windows_closure = target_product_closure(windows_metadata.release, &WINDOWS_PRODUCT_ROOTS)?;
    let preview_closure = target_product_closure(windows_metadata.preview, &WINDOWS_PRODUCT_ROOTS)?;
    require_identical_windows_mode_closures(
        windows_metadata.release,
        &windows_closure,
        windows_metadata.preview,
        &preview_closure,
    )?;
    let windows_source_closure_sbom = render_windows_source_closure_spdx(
        policy,
        windows_metadata.release,
        &audited,
        &package_ids,
        &windows_closure,
        lock_sha256,
        input_closure_sha256,
        &non_spdx,
    )?;
    let windows_source_closure_packages = windows_closure.len();
    let windows_source_closure_third_party_packages = windows_closure
        .iter()
        .filter(|id| {
            audited
                .iter()
                .find(|package| package.metadata.id == **id)
                .is_some_and(|package| package.metadata.source.is_some())
        })
        .count();
    let provenance = validate_license_provenance(provenance, &audited)?;
    let notices = render_notices(
        &audited,
        lock_sha256,
        &provenance.supplemental_notice_sections,
    )?;

    Ok(GeneratedEvidence {
        sbom,
        windows_source_closure_sbom,
        notices,
        total_packages: audited.len(),
        third_party_packages,
        windows_source_closure_packages,
        windows_source_closure_third_party_packages,
        packages_without_retained_license_files,
    })
}

fn collect_license_evidence(
    package: &MetadataPackage,
    expected_archive_sha256: &str,
) -> Result<CollectedArchiveEvidence, String> {
    if package.source.is_none() {
        return Ok(CollectedArchiveEvidence {
            license_files: Vec::new(),
            cargo_vcs_info: None,
        });
    }
    let package_root = package.manifest_path.parent().ok_or_else(|| {
        format!(
            "package {} {} manifest has no parent",
            package.name, package.version
        )
    })?;
    let registry_hash_dir = package_root.parent().ok_or_else(|| {
        format!(
            "package {} {} source root has no registry-hash parent",
            package.name, package.version,
        )
    })?;
    let registry_hash = registry_hash_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            format!(
                "package {} {} registry hash is not UTF-8",
                package.name, package.version
            )
        })?;
    let source_dir = registry_hash_dir
        .parent()
        .filter(|path| path.file_name().is_some_and(|name| name == "src"))
        .ok_or_else(|| {
            format!(
                "package {} {} is not in Cargo's registry/src layout",
                package.name, package.version
            )
        })?;
    let registry_dir = source_dir.parent().ok_or_else(|| {
        format!(
            "package {} {} Cargo registry source has no parent",
            package.name, package.version
        )
    })?;
    let archive_path = registry_dir
        .join("cache")
        .join(registry_hash)
        .join(format!("{}-{}.crate", package.name, package.version));
    let archive_bytes = read_regular_file(&archive_path, "cached .crate archive")?;
    let actual_archive_sha256 = sha256(&archive_bytes);
    if actual_archive_sha256 != expected_archive_sha256 {
        return Err(format!(
            "cached .crate archive SHA-256 mismatch for {} {}: Cargo.lock records {expected_archive_sha256}, cache has {actual_archive_sha256}",
            package.name, package.version
        ));
    }

    let requested_license_file = package
        .license_file
        .as_deref()
        .map(normalize_relative_license_path)
        .transpose()?;
    let root_prefix = format!("{}-{}/", package.name, package.version);
    let mut decoder = flate2::read::GzDecoder::new(Cursor::new(&archive_bytes));
    let mut evidence = BTreeMap::new();
    let mut archived_manifest = None;
    let mut cargo_vcs_info = None;
    let mut zero_blocks = 0_u8;
    loop {
        let mut header = [0_u8; 512];
        let first = decoder
            .read(&mut header[..1])
            .map_err(|error| format!("read {}: {error}", archive_path.display()))?;
        if first == 0 {
            break;
        }
        decoder
            .read_exact(&mut header[1..])
            .map_err(|error| format!("read tar header from {}: {error}", archive_path.display()))?;
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks = zero_blocks.saturating_add(1);
            continue;
        }
        if zero_blocks > 0 {
            return Err(format!(
                "non-zero tar header follows end marker in {}",
                archive_path.display()
            ));
        }
        validate_tar_header_checksum(&header, &archive_path)?;
        let size = parse_tar_octal(&header[124..136], "tar entry size", &archive_path)?;
        let path = tar_header_path(&header, &archive_path)?;
        let typeflag = header[156];
        let is_regular = matches!(typeflag, 0 | b'0');
        let relative = path.strip_prefix(&root_prefix);
        let desired = relative.is_some_and(|relative| {
            relative == "Cargo.toml"
                || relative == ".cargo_vcs_info.json"
                || (!relative.contains('/') && is_license_evidence_name(relative))
                || requested_license_file.as_deref() == Some(relative)
        });
        if desired && !is_regular {
            return Err(format!(
                "required archive evidence is not a regular file in {}: {path}",
                archive_path.display()
            ));
        }

        let mut bytes = Vec::new();
        if desired {
            let length = usize::try_from(size)
                .map_err(|_| format!("tar entry is too large in {}", archive_path.display()))?;
            bytes.resize(length, 0);
            decoder.read_exact(&mut bytes).map_err(|error| {
                format!(
                    "read tar entry {path} from {}: {error}",
                    archive_path.display()
                )
            })?;
        } else {
            std::io::copy(&mut decoder.by_ref().take(size), &mut std::io::sink()).map_err(
                |error| {
                    format!(
                        "skip tar entry {path} from {}: {error}",
                        archive_path.display()
                    )
                },
            )?;
        }
        let padding = (512 - size % 512) % 512;
        std::io::copy(&mut decoder.by_ref().take(padding), &mut std::io::sink()).map_err(
            |error| {
                format!(
                    "skip tar padding after {path} in {}: {error}",
                    archive_path.display()
                )
            },
        )?;

        let Some(relative) = relative else {
            continue;
        };
        if relative == "Cargo.toml" {
            if archived_manifest.replace(bytes).is_some() {
                return Err(format!(
                    "duplicate Cargo.toml in cached archive {}",
                    archive_path.display()
                ));
            }
        } else if relative == ".cargo_vcs_info.json" {
            if cargo_vcs_info.replace(bytes).is_some() {
                return Err(format!(
                    "duplicate .cargo_vcs_info.json in cached archive {}",
                    archive_path.display()
                ));
            }
        } else if desired && evidence.insert(relative.to_owned(), bytes).is_some() {
            return Err(format!(
                "duplicate licence evidence {relative} in {}",
                archive_path.display()
            ));
        }
    }
    if zero_blocks < 2 {
        return Err(format!(
            "cached .crate tar lacks its two-block end marker: {}",
            archive_path.display()
        ));
    }
    let archived_manifest = archived_manifest.ok_or_else(|| {
        format!(
            "cached .crate archive lacks Cargo.toml: {}",
            archive_path.display()
        )
    })?;
    let unpacked_manifest =
        read_regular_file(&package.manifest_path, "unpacked registry Cargo.toml")?;
    if unpacked_manifest != archived_manifest {
        return Err(format!(
            "unpacked Cargo.toml differs from the checksum-verified .crate archive for {} {}",
            package.name, package.version
        ));
    }
    if let Some(required) = requested_license_file {
        if !evidence.contains_key(&required) {
            return Err(format!(
                "Cargo manifest license_file {required:?} is absent from checksum-verified archive {}",
                archive_path.display()
            ));
        }
    }

    let license_files = evidence
        .into_iter()
        .map(|(relative_path, bytes)| {
            std::str::from_utf8(&bytes).map_err(|error| {
                format!(
                    "third-party licence evidence must be UTF-8 for deterministic notice rendering: {} in {}: {error}",
                    relative_path,
                    archive_path.display()
                )
            })?;
            Ok::<_, String>(LicenseEvidenceFile {
                relative_path,
                sha256: sha256(&bytes),
                bytes,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CollectedArchiveEvidence {
        license_files,
        cargo_vcs_info,
    })
}

fn normalize_relative_license_path(value: &str) -> Result<String, String> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(format!("unsafe Cargo license_file path {value:?}"));
    }
    let normalized = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            Component::CurDir => None,
            _ => unreachable!("validated above"),
        })
        .collect::<Vec<_>>()
        .join("/");
    if normalized.is_empty() {
        return Err("Cargo license_file path must not be empty".to_owned());
    }
    Ok(normalized)
}

fn validate_tar_header_checksum(header: &[u8; 512], path: &Path) -> Result<(), String> {
    let expected = parse_tar_octal(&header[148..156], "tar header checksum", path)?;
    let actual = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum::<u64>();
    if actual != expected {
        return Err(format!(
            "tar header checksum mismatch in {}: expected {expected}, calculated {actual}",
            path.display()
        ));
    }
    Ok(())
}

fn parse_tar_octal(field: &[u8], label: &str, path: &Path) -> Result<u64, String> {
    let value = field
        .iter()
        .copied()
        .skip_while(|byte| matches!(byte, 0 | b' '))
        .take_while(|byte| !matches!(byte, 0 | b' '))
        .collect::<Vec<_>>();
    if value.is_empty() || value.iter().any(|byte| !(b'0'..=b'7').contains(byte)) {
        return Err(format!(
            "{label} is not a supported octal value in {}",
            path.display()
        ));
    }
    let text = std::str::from_utf8(&value)
        .map_err(|error| format!("{label} is not UTF-8 in {}: {error}", path.display()))?;
    u64::from_str_radix(text, 8)
        .map_err(|error| format!("parse {label} in {}: {error}", path.display()))
}

fn tar_header_path(header: &[u8; 512], archive_path: &Path) -> Result<String, String> {
    let name = tar_text_field(&header[..100], "tar name", archive_path)?;
    let prefix = tar_text_field(&header[345..500], "tar prefix", archive_path)?;
    if prefix.is_empty() {
        Ok(name)
    } else {
        Ok(format!("{prefix}/{name}"))
    }
}

fn tar_text_field(field: &[u8], label: &str, path: &Path) -> Result<String, String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    std::str::from_utf8(&field[..end])
        .map(str::to_owned)
        .map_err(|error| format!("{label} is not UTF-8 in {}: {error}", path.display()))
}

fn is_license_evidence_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["license", "licence", "copying", "notice", "unlicense"]
        .iter()
        .any(|prefix| {
            lower == *prefix
                || lower
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with(['-', '_', '.']))
        })
}

fn render_spdx(
    policy: &ThirdPartyLicensePolicy,
    metadata: &CargoMetadata,
    audited: &[AuditedPackage],
    package_ids: &BTreeMap<String, String>,
    lock_sha256: &str,
    input_closure_sha256: &str,
    non_spdx: &BTreeSet<&str>,
) -> Result<Vec<u8>, String> {
    let packages = audited
        .iter()
        .map(|package| spdx_package_for(package, non_spdx))
        .collect();

    let mut document_describes = metadata
        .workspace_members
        .iter()
        .map(|id| {
            package_ids.get(id).cloned().ok_or_else(|| {
                format!("workspace member {id} is missing from cargo metadata packages")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    document_describes.sort();

    let mut relationships = Vec::new();
    for node in &metadata.resolve.nodes {
        let from = package_ids
            .get(&node.id)
            .ok_or_else(|| format!("cargo metadata resolve node {} has no package", node.id))?;
        for dependency in &node.dependencies {
            let to = package_ids.get(dependency).ok_or_else(|| {
                format!(
                    "cargo metadata dependency {} from {} has no package",
                    dependency, node.id
                )
            })?;
            relationships.push(SpdxRelationship {
                spdx_element_id: from.clone(),
                relationship_type: "DEPENDS_ON",
                related_spdx_element: to.clone(),
            });
        }
    }
    relationships.sort();
    relationships.dedup();

    let document = SpdxDocument {
        spdx_version: SPDX_VERSION,
        data_license: SPDX_DATA_LICENSE,
        spdx_id: SPDX_DOCUMENT_ID,
        name: "AutoCAD-MCP Cargo.lock source dependency graph".to_owned(),
        document_namespace: format!(
            "https://andagni.invalid/spdx/autocad-mcp/source-closure-{input_closure_sha256}"
        ),
        creation_info: SpdxCreationInfo {
            created: policy.evidence_document_created_utc.clone(),
            creators: vec![format!(
                "Tool: AutoCAD-MCP distribution-evidence-{EVIDENCE_GENERATOR_SCHEMA_VERSION}"
            )],
            comment: format!("Generated deterministically from the complete Cargo.lock graph and `cargo metadata --locked --offline --format-version 1`, including workspace, development, build, and all-target dependencies. Cargo.lock SHA-256: {lock_sha256}. Registry-package retained licence evidence is read directly from cached .crate archives after their SHA-256 values are checked against Cargo.lock, and each unpacked registry Cargo.toml is required to equal the archived manifest consumed for package metadata. Workspace Cargo.toml bytes are bound directly by the evidence input-closure digest. This is a source-lock SBOM, not an exact inventory of packages linked into either shipped executable. Exact executable/source-build identity remains a separate release gate. This is technical inventory evidence, not a legal conclusion. filesAnalyzed is false."),
        },
        document_describes,
        packages,
        relationships,
    };
    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|error| format!("serialize SPDX 2.3 JSON: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn spdx_package_for(package: &AuditedPackage, non_spdx: &BTreeSet<&str>) -> SpdxPackage {
    let raw_declared = package
        .metadata
        .license
        .as_deref()
        .expect("validated above");
    let declared = if non_spdx.contains(raw_declared) {
        "NOASSERTION".to_owned()
    } else {
        raw_declared.to_owned()
    };
    let evidence_note = match package.lock_checksum.as_deref() {
        Some(_) => {
            let evidence = if package.retained_license_files.is_empty() {
                "no retained top-level licence/copying/notice file in the checksum-verified .crate archive"
                    .to_owned()
            } else {
                package
                    .retained_license_files
                    .iter()
                    .map(|file| format!("{} sha256:{}", file.relative_path, file.sha256))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            format!("Checksum-verified .crate archive evidence: {evidence}.")
        }
        None => "Workspace package: no .crate archive or Cargo.lock package checksum applies; licence metadata is read from the workspace Cargo.toml bound by the evidence input-closure digest.".to_owned(),
    };
    let syntax_note = if non_spdx.contains(raw_declared) {
        "The Cargo value is not emitted as SPDX licenseDeclared because it uses non-SPDX slash syntax."
    } else {
        "The Cargo value is emitted as SPDX licenseDeclared."
    };
    let checksums = package
        .lock_checksum
        .iter()
        .map(|checksum| SpdxChecksum {
            algorithm: "SHA256",
            checksum_value: checksum.clone(),
        })
        .collect();
    SpdxPackage {
        spdx_id: package.spdx_id.clone(),
        name: package.metadata.name.clone(),
        version_info: package.metadata.version.clone(),
        download_location: "NOASSERTION",
        files_analyzed: false,
        checksums,
        license_concluded: "NOASSERTION",
        license_declared: declared,
        license_comments: format!(
            "Cargo manifest licence metadata: {raw_declared}. {syntax_note} No governing licence conclusion or legal approval is asserted. {evidence_note}"
        ),
        copyright_text: "NOASSERTION",
        source_info: match package.metadata.source.as_deref() {
            Some(source) => format!(
                "Resolved by Cargo.lock from {source}; SHA-256 checksum is the Cargo.lock package checksum."
            ),
            None => "AutoCAD-MCP workspace package.".to_owned(),
        },
    }
}

fn target_product_closure(
    metadata: &CargoMetadata,
    root_names: &[&str],
) -> Result<BTreeSet<String>, String> {
    let nodes = metadata
        .resolve
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let mut roots = Vec::with_capacity(root_names.len());
    for root_name in root_names {
        let matches = metadata
            .packages
            .iter()
            .filter(|package| package.source.is_none() && package.name == *root_name)
            .map(|package| package.id.clone())
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(format!(
                "Windows source closure requires exactly one workspace root named {root_name}; found {}",
                matches.len()
            ));
        }
        roots.push(matches[0].clone());
    }

    let mut closure = BTreeSet::new();
    let mut pending = roots;
    while let Some(package_id) = pending.pop() {
        if !closure.insert(package_id.clone()) {
            continue;
        }
        let node = nodes.get(package_id.as_str()).ok_or_else(|| {
            format!("Windows source closure root/dependency {package_id} has no resolve node")
        })?;
        for dependency in &node.deps {
            if dependency.dep_kinds.is_empty() {
                return Err(format!(
                    "Windows source closure dependency {} from {} has no dependency-kind record",
                    dependency.pkg, node.id
                ));
            }
            if dependency
                .dep_kinds
                .iter()
                .any(|kind| kind.kind.as_deref() != Some("dev"))
            {
                pending.push(dependency.pkg.clone());
            }
        }
    }
    Ok(closure)
}

fn require_identical_windows_mode_closures(
    release_metadata: &CargoMetadata,
    release_closure: &BTreeSet<String>,
    preview_metadata: &CargoMetadata,
    preview_closure: &BTreeSet<String>,
) -> Result<(), String> {
    if release_closure != preview_closure {
        return Err(
            "Windows Release and Preview normal/build package closures differ; split and review mode-specific source-closure evidence before distribution"
                .to_owned(),
        );
    }
    let release_edges = selected_closure_edges(release_metadata, release_closure)?;
    let preview_edges = selected_closure_edges(preview_metadata, preview_closure)?;
    if release_edges != preview_edges {
        return Err(
            "Windows Release and Preview normal/build dependency-edge closures differ; split and review mode-specific source-closure evidence before distribution"
                .to_owned(),
        );
    }
    Ok(())
}

fn selected_closure_edges(
    metadata: &CargoMetadata,
    closure: &BTreeSet<String>,
) -> Result<BTreeSet<SelectedDependencyEdge>, String> {
    let mut edges = BTreeSet::new();
    for node in &metadata.resolve.nodes {
        if !closure.contains(&node.id) {
            continue;
        }
        for dependency in &node.deps {
            if !closure.contains(&dependency.pkg) {
                continue;
            }
            let mut selected_kinds = dependency
                .dep_kinds
                .iter()
                .filter(|kind| kind.kind.as_deref() != Some("dev"))
                .map(|kind| kind.kind.clone())
                .collect::<Vec<_>>();
            selected_kinds.sort();
            selected_kinds.dedup();
            if selected_kinds.is_empty() {
                continue;
            }
            edges.insert(SelectedDependencyEdge {
                source_package_id: node.id.clone(),
                target_package_id: dependency.pkg.clone(),
                dependency_kinds: selected_kinds,
            });
        }
    }
    Ok(edges)
}

#[allow(clippy::too_many_arguments)]
fn render_windows_source_closure_spdx(
    policy: &ThirdPartyLicensePolicy,
    metadata: &CargoMetadata,
    audited: &[AuditedPackage],
    package_ids: &BTreeMap<String, String>,
    closure: &BTreeSet<String>,
    lock_sha256: &str,
    input_closure_sha256: &str,
    non_spdx: &BTreeSet<&str>,
) -> Result<Vec<u8>, String> {
    let audited_by_id = audited
        .iter()
        .map(|package| (package.metadata.id.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let packages = closure
        .iter()
        .map(|id| {
            audited_by_id
                .get(id.as_str())
                .copied()
                .map(|package| spdx_package_for(package, non_spdx))
                .ok_or_else(|| {
                    format!("Windows source closure package {id} is absent from full audit")
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut document_describes = WINDOWS_PRODUCT_ROOTS
        .iter()
        .map(|root_name| {
            metadata
                .packages
                .iter()
                .find(|package| package.source.is_none() && package.name == *root_name)
                .and_then(|package| package_ids.get(&package.id))
                .cloned()
                .ok_or_else(|| {
                    format!("Windows source closure root {root_name} has no SPDX identity")
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    document_describes.sort();

    let mut relationships = Vec::new();
    for node in &metadata.resolve.nodes {
        if !closure.contains(&node.id) {
            continue;
        }
        let from = package_ids.get(&node.id).ok_or_else(|| {
            format!(
                "Windows source closure node {} has no SPDX identity",
                node.id
            )
        })?;
        for dependency in &node.deps {
            if !closure.contains(&dependency.pkg)
                || !dependency
                    .dep_kinds
                    .iter()
                    .any(|kind| kind.kind.as_deref() != Some("dev"))
            {
                continue;
            }
            let to = package_ids.get(&dependency.pkg).ok_or_else(|| {
                format!(
                    "Windows source closure dependency {} from {} has no SPDX identity",
                    dependency.pkg, node.id
                )
            })?;
            relationships.push(SpdxRelationship {
                spdx_element_id: from.clone(),
                relationship_type: "DEPENDS_ON",
                related_spdx_element: to.clone(),
            });
        }
    }
    relationships.sort();
    relationships.dedup();

    let document = SpdxDocument {
        spdx_version: SPDX_VERSION,
        data_license: SPDX_DATA_LICENSE,
        spdx_id: SPDX_DOCUMENT_ID,
        name: "AutoCAD-MCP Windows x64 product build-source closure".to_owned(),
        document_namespace: format!(
            "https://andagni.invalid/spdx/autocad-mcp/windows-x64-source-build-closure-{input_closure_sha256}"
        ),
        creation_info: SpdxCreationInfo {
            created: policy.evidence_document_created_utc.clone(),
            creators: vec![format!(
                "Tool: AutoCAD-MCP distribution-evidence-{EVIDENCE_GENERATOR_SCHEMA_VERSION}"
            )],
            comment: format!(
                "Generated deterministically from Cargo.lock and two exact commands: `cargo metadata --locked --offline --format-version 1 --filter-platform {WINDOWS_TARGET} --no-default-features` for Release, and `cargo metadata --locked --offline --format-version 1 --filter-platform {WINDOWS_TARGET} --no-default-features --features autocad-mcp/preview` for Preview. Generation requires the selected normal/build package and dependency-edge closures of the autocad-mcp and autolisp-lsp product roots to be identical across both modes, excluding development-only edges; any divergence fails closed pending separately reviewed mode-specific evidence. Cargo.lock SHA-256: {lock_sha256}. This is conservative target build-source evidence, including build scripts and proc macros; it is not a linked-binary or native-object SBOM and does not assert legal approval. Exact executable hashes and native imports require a separate build attestation."
            ),
        },
        document_describes,
        packages,
        relationships,
    };
    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|error| format!("serialize Windows source-closure SPDX 2.3 JSON: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_license_provenance(
    inputs: &LicenseProvenanceInputs,
    audited: &[AuditedPackage],
) -> Result<ValidatedLicenseProvenance, String> {
    let audited_by_identity = audited
        .iter()
        .map(|package| {
            (
                (
                    package.metadata.name.as_str(),
                    package.metadata.version.as_str(),
                ),
                package,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let sources = inputs
        .document
        .sources
        .iter()
        .map(|source| (source.id(), source))
        .collect::<BTreeMap<_, _>>();
    let mut applies_to = BTreeMap::<&str, Vec<PackageIdentity>>::new();
    let mut bound_packages = Vec::new();

    for binding in &inputs.document.package_bindings {
        let identity = (
            binding.package.name.as_str(),
            binding.package.version.as_str(),
        );
        let package = audited_by_identity.get(&identity).copied().ok_or_else(|| {
            format!(
                "third-party licence provenance binds absent package {} {}",
                identity.0, identity.1
            )
        })?;
        if package.lock_checksum.as_deref() != Some(&binding.package.archive_sha256)
            || package.metadata.license.as_deref()
                != Some(binding.package.declared_license.as_str())
        {
            return Err(format!(
                "third-party licence provenance identity, archive checksum, or declared licence drifted for {} {}",
                identity.0, identity.1
            ));
        }
        let vcs_bytes = package.cargo_vcs_info.as_deref().ok_or_else(|| {
            format!(
                "third-party licence provenance package {} {} has no checksum-verified .cargo_vcs_info.json",
                identity.0, identity.1
            )
        })?;
        let vcs: CargoVcsInfo = serde_json::from_slice(vcs_bytes).map_err(|error| {
            format!(
                "parse checksum-verified .cargo_vcs_info.json for {} {}: {error}",
                identity.0, identity.1
            )
        })?;
        if vcs.git.sha1 != binding.git_commit || vcs.path_in_vcs != binding.path_in_vcs {
            return Err(format!(
                "third-party licence provenance VCS identity drifted for {} {}",
                identity.0, identity.1
            ));
        }
        if binding.license_concluded != "NOASSERTION" {
            return Err(format!(
                "technical third-party licence provenance must not conclude a licence for {} {}",
                identity.0, identity.1
            ));
        }
        if !sources.contains_key(binding.source_id.as_str()) {
            return Err(format!(
                "third-party licence provenance binding for {} {} references unknown source {}",
                identity.0, identity.1, binding.source_id
            ));
        }
        applies_to
            .entry(binding.source_id.as_str())
            .or_default()
            .push(PackageIdentity {
                name: binding.package.name.clone(),
                version: binding.package.version.clone(),
            });
        bound_packages.push(PackageIdentity {
            name: binding.package.name.clone(),
            version: binding.package.version.clone(),
        });
    }
    let expected_bound_packages = [
        PackageIdentity {
            name: "rmcp".to_owned(),
            version: "1.7.0".to_owned(),
        },
        PackageIdentity {
            name: "rmcp-macros".to_owned(),
            version: "1.7.0".to_owned(),
        },
        PackageIdentity {
            name: "tower-lsp-macros".to_owned(),
            version: "0.9.0".to_owned(),
        },
    ];
    if bound_packages != expected_bound_packages {
        return Err(format!(
            "third-party licence provenance package boundary changed: expected {expected_bound_packages:?}, found {bound_packages:?}"
        ));
    }

    let mut supplemental_notice_sections = Vec::new();
    for source in &inputs.document.sources {
        let mut packages = applies_to.remove(source.id()).ok_or_else(|| {
            format!(
                "third-party licence provenance source {} is not used by a package binding",
                source.id()
            )
        })?;
        packages.sort();
        packages.dedup();
        let (evidence_description, files) = match source {
            ProvenanceSource::UpstreamGitBlob {
                repository_url,
                git_commit,
                git_blob_sha1,
                repository_path,
                tracked_path,
                sha256,
                ..
            } => {
                let bytes = inputs.tracked_files.get(tracked_path).ok_or_else(|| {
                    format!(
                        "third-party licence provenance source {} has no loaded tracked bytes",
                        source.id()
                    )
                })?;
                (
                    format!(
                        "Exact upstream Git blob from {repository_url} commit {git_commit}, path {repository_path}, Git blob {git_blob_sha1}."
                    ),
                    vec![LicenseEvidenceFile {
                        relative_path: repository_path.clone(),
                        sha256: sha256.clone(),
                        bytes: bytes.clone(),
                    }],
                )
            }
            ProvenanceSource::ChecksumVerifiedCrateArchiveMembers {
                repository_url,
                git_commit,
                source_package,
                archive_members,
                ..
            } => {
                let package = audited_by_identity
                    .get(&(
                        source_package.name.as_str(),
                        source_package.version.as_str(),
                    ))
                    .copied()
                    .ok_or_else(|| {
                        format!(
                            "third-party licence provenance source package {} {} is absent",
                            source_package.name, source_package.version
                        )
                    })?;
                if package.lock_checksum.as_deref() != Some(&source_package.archive_sha256) {
                    return Err(format!(
                        "third-party licence provenance source archive checksum drifted for {} {}",
                        source_package.name, source_package.version
                    ));
                }
                let vcs_bytes = package.cargo_vcs_info.as_deref().ok_or_else(|| {
                    format!(
                        "third-party licence provenance source package {} {} has no VCS identity",
                        source_package.name, source_package.version
                    )
                })?;
                let vcs: CargoVcsInfo = serde_json::from_slice(vcs_bytes).map_err(|error| {
                    format!(
                        "parse provenance source VCS identity for {} {}: {error}",
                        source_package.name, source_package.version
                    )
                })?;
                if vcs.git.sha1 != *git_commit {
                    return Err(format!(
                        "third-party licence provenance source and target packages do not share the recorded commit {git_commit}"
                    ));
                }
                let files = archive_members
                    .iter()
                    .map(|member| {
                        package
                            .retained_license_files
                            .iter()
                            .find(|file| {
                                file.relative_path == member.path && file.sha256 == member.sha256
                            })
                            .cloned()
                            .ok_or_else(|| {
                                format!(
                                    "third-party licence provenance source member {} with SHA-256 {} is absent from {} {}",
                                    member.path,
                                    member.sha256,
                                    source_package.name,
                                    source_package.version
                                )
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                (
                    format!(
                        "Checksum-verified {source_package_name} {source_package_version} crate archive from {repository_url}; source and bound package archives record upstream commit {git_commit}.",
                        source_package_name = source_package.name,
                        source_package_version = source_package.version,
                    ),
                    files,
                )
            }
        };
        supplemental_notice_sections.push(SupplementalNoticeSection {
            source_id: source.id().to_owned(),
            applies_to: packages,
            evidence_description,
            files,
        });
    }
    if !applies_to.is_empty() {
        return Err("third-party licence provenance has unresolved source bindings".to_owned());
    }

    Ok(ValidatedLicenseProvenance {
        supplemental_notice_sections,
    })
}

fn render_notices(
    audited: &[AuditedPackage],
    lock_sha256: &str,
    supplemental_sections: &[SupplementalNoticeSection],
) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    output.extend_from_slice(
        b"AutoCAD-MCP third-party licence evidence bundle\n\
=================================================\n\n\
Scope: every third-party registry package in the exact locked Rust workspace.\n\
Cargo.lock SHA-256: ",
    );
    output.extend_from_slice(lock_sha256.as_bytes());
    output.extend_from_slice(
        b"\n\nThis bundle reproduces the top-level LICEN[CS]E, COPYING, NOTICE, and\n\
UNLICENSE files read directly from each cached .crate archive after verifying\n\
its SHA-256 against Cargo.lock. The unpacked Cargo.toml must also equal the\n\
archived manifest used for Cargo metadata. Metadata is not a substitute for retained licence\n\
or notice bytes, and neither this bundle nor the SPDX inventory records legal\n\
approval or a conclusion about distribution obligations.\n\n",
    );

    for package in audited
        .iter()
        .filter(|package| package.metadata.source.is_some())
    {
        output.extend_from_slice(
            format!(
                "------------------------------------------------------------------------\n\
Package: {} {}\n\
Source: {}\n\
Cargo.lock package SHA-256: {}\n\
Cargo manifest licence metadata: {}\n",
                package.metadata.name,
                package.metadata.version,
                package.metadata.source.as_deref().expect("filtered above"),
                package.lock_checksum.as_deref().expect("validated above"),
                package
                    .metadata
                    .license
                    .as_deref()
                    .expect("validated above"),
            )
            .as_bytes(),
        );
        if package.retained_license_files.is_empty() {
            output.extend_from_slice(
                b"Retained licence/copying/notice files: NONE IN FETCHED CRATE ROOT\n\n",
            );
            continue;
        }
        output.extend_from_slice(
            format!(
                "Retained licence/copying/notice files: {}\n\n",
                package.retained_license_files.len()
            )
            .as_bytes(),
        );
        for file in &package.retained_license_files {
            output.extend_from_slice(
                format!(
                    "----- BEGIN {} (SHA-256 {}) -----\n",
                    file.relative_path, file.sha256
                )
                .as_bytes(),
            );
            output.extend_from_slice(&file.bytes);
            if !file.bytes.ends_with(b"\n") {
                output.push(b'\n');
            }
            output.extend_from_slice(
                format!("----- END {} -----\n\n", file.relative_path).as_bytes(),
            );
        }
    }
    output.extend_from_slice(
        b"========================================================================\n\
SUPPLEMENTAL LICENCE PROVENANCE\n\
========================================================================\n\n\
The following bytes close identified archive-root evidence gaps through the\n\
separately bound technical provenance ledger. They do not select a licence\n\
branch or constitute owner distribution approval.\n\n",
    );
    for section in supplemental_sections {
        let applies_to = section
            .applies_to
            .iter()
            .map(|package| format!("{} {}", package.name, package.version))
            .collect::<Vec<_>>()
            .join(", ");
        output.extend_from_slice(
            format!(
                "------------------------------------------------------------------------\n\
Provenance source: {}\n\
Applies to: {applies_to}\n\
Evidence: {}\n\n",
                section.source_id, section.evidence_description
            )
            .as_bytes(),
        );
        for file in &section.files {
            output.extend_from_slice(
                format!(
                    "----- BEGIN {} (SHA-256 {}) -----\n",
                    file.relative_path, file.sha256
                )
                .as_bytes(),
            );
            output.extend_from_slice(&file.bytes);
            if !file.bytes.ends_with(b"\n") {
                output.push(b'\n');
            }
            output.extend_from_slice(
                format!("----- END {} -----\n\n", file.relative_path).as_bytes(),
            );
        }
    }
    Ok(output)
}

fn validate_reviewed_inventory(
    policy: &ThirdPartyLicensePolicy,
    generated: &GeneratedEvidence,
) -> Result<(), String> {
    if generated.total_packages != policy.expected_total_packages {
        return Err(format!(
            "locked package inventory changed: expected {}, found {}",
            policy.expected_total_packages, generated.total_packages
        ));
    }
    if generated.third_party_packages != policy.expected_third_party_packages {
        return Err(format!(
            "third-party package inventory changed: expected {}, found {}",
            policy.expected_third_party_packages, generated.third_party_packages
        ));
    }
    if generated.windows_source_closure_packages != policy.expected_windows_source_closure_packages
    {
        return Err(format!(
            "Windows source-closure package inventory changed: expected {}, found {}",
            policy.expected_windows_source_closure_packages,
            generated.windows_source_closure_packages
        ));
    }
    if generated.windows_source_closure_third_party_packages
        != policy.expected_windows_source_closure_third_party_packages
    {
        return Err(format!(
            "Windows source-closure third-party inventory changed: expected {}, found {}",
            policy.expected_windows_source_closure_third_party_packages,
            generated.windows_source_closure_third_party_packages
        ));
    }
    if generated.packages_without_retained_license_files
        != policy.expected_packages_without_retained_license_files
    {
        return Err(format!(
            "packages without retained licence files changed: expected {:?}, found {:?}",
            policy.expected_packages_without_retained_license_files,
            generated.packages_without_retained_license_files
        ));
    }
    Ok(())
}

fn calculate_input_closure(
    repository: &Path,
    lock_bytes: &[u8],
    metadata: &CargoMetadata,
    policy: &ThirdPartyLicensePolicy,
    provenance: &LicenseProvenanceInputs,
    owner_approval_schema: &[u8],
) -> Result<String, String> {
    let workspace_manifest = read_regular_file(
        &repository.join("Cargo.toml"),
        "workspace root Cargo manifest",
    )?;
    let generator_source = read_regular_file(
        &repository.join(GENERATOR_SOURCE_PATH),
        "distribution evidence generator source",
    )?;
    let rust_toolchain = read_regular_file(
        &repository.join(RUST_TOOLCHAIN_PATH),
        "pinned Rust toolchain",
    )?;
    let canonical_repository = repository.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize repository {}: {error}",
            repository.display()
        )
    })?;

    let mut manifests = metadata
        .packages
        .iter()
        .filter(|package| package.source.is_none())
        .map(|package| {
            let relative =
                workspace_manifest_relative_path(&canonical_repository, &package.manifest_path)?;
            let relative_text = normalized_relative_path_text(&relative)?;
            let bytes = read_regular_file(&package.manifest_path, "workspace Cargo manifest")?;
            Ok((relative_text, bytes))
        })
        .collect::<Result<Vec<_>, String>>()?;
    manifests.sort_by(|left, right| left.0.cmp(&right.0));

    Ok(hash_input_closure(InputClosure {
        lock_bytes,
        workspace_manifest: &workspace_manifest,
        generator_source: &generator_source,
        rust_toolchain: &rust_toolchain,
        policy,
        manifests: &manifests,
        provenance: &provenance.bytes,
        supplemental_files: &provenance.tracked_files,
        owner_approval_schema,
    }))
}

fn workspace_manifest_relative_path(
    canonical_repository: &Path,
    manifest_path: &Path,
) -> Result<PathBuf, String> {
    let canonical_manifest = manifest_path.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize workspace manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    canonical_manifest
        .strip_prefix(canonical_repository)
        .map(Path::to_path_buf)
        .map_err(|_| {
            format!(
                "workspace manifest is outside the repository: {}",
                manifest_path.display()
            )
        })
}

fn normalized_relative_path_text(path: &Path) -> Result<String, String> {
    let components =
        path.components()
            .map(|component| match component {
                Component::Normal(value) => value.to_str().map(str::to_owned).ok_or_else(|| {
                    format!("workspace manifest path is not UTF-8: {}", path.display())
                }),
                _ => Err(format!(
                    "workspace manifest has a non-normal repository path: {}",
                    path.display()
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() {
        return Err("workspace manifest path must not be empty".to_owned());
    }
    Ok(components.join("/"))
}

struct InputClosure<'a> {
    lock_bytes: &'a [u8],
    workspace_manifest: &'a [u8],
    generator_source: &'a [u8],
    rust_toolchain: &'a [u8],
    policy: &'a ThirdPartyLicensePolicy,
    manifests: &'a [(String, Vec<u8>)],
    provenance: &'a [u8],
    supplemental_files: &'a BTreeMap<String, Vec<u8>>,
    owner_approval_schema: &'a [u8],
}

fn hash_input_closure(input: InputClosure<'_>) -> String {
    let mut hasher = Sha256::new();
    hash_framed(
        &mut hasher,
        b"generator-schema",
        EVIDENCE_GENERATOR_SCHEMA_VERSION.to_string().as_bytes(),
    );
    hash_framed(&mut hasher, b"Cargo.lock", input.lock_bytes);
    hash_framed(&mut hasher, b"workspace-root-manifest-path", b"Cargo.toml");
    hash_framed(
        &mut hasher,
        b"workspace-root-manifest-bytes",
        input.workspace_manifest,
    );
    hash_framed(
        &mut hasher,
        b"generator-source-path",
        GENERATOR_SOURCE_PATH.as_bytes(),
    );
    hash_framed(
        &mut hasher,
        b"generator-source-bytes",
        input.generator_source,
    );
    hash_framed(
        &mut hasher,
        b"rust-toolchain-path",
        RUST_TOOLCHAIN_PATH.as_bytes(),
    );
    hash_framed(&mut hasher, b"rust-toolchain-bytes", input.rust_toolchain);
    hash_framed(&mut hasher, b"windows-target", WINDOWS_TARGET.as_bytes());
    for root in WINDOWS_PRODUCT_ROOTS {
        hash_framed(&mut hasher, b"windows-product-root", root.as_bytes());
    }
    hash_framed(
        &mut hasher,
        b"license-provenance-path",
        LICENSE_PROVENANCE_PATH.as_bytes(),
    );
    hash_framed(&mut hasher, b"license-provenance-bytes", input.provenance);
    for (path, bytes) in input.supplemental_files {
        hash_framed(
            &mut hasher,
            b"supplemental-license-evidence-path",
            path.as_bytes(),
        );
        hash_framed(&mut hasher, b"supplemental-license-evidence-bytes", bytes);
    }
    hash_framed(
        &mut hasher,
        b"owner-approval-schema-path",
        OWNER_APPROVAL_SCHEMA_PATH.as_bytes(),
    );
    hash_framed(
        &mut hasher,
        b"owner-approval-schema-bytes",
        input.owner_approval_schema,
    );
    hash_framed(
        &mut hasher,
        b"evidence-document-created",
        input.policy.evidence_document_created_utc.as_bytes(),
    );
    for value in &input.policy.non_spdx_declared_license_values {
        hash_framed(&mut hasher, b"non-spdx-declaration", value.as_bytes());
    }
    for value in &input.policy.allowed_spdx_license_ids {
        hash_framed(&mut hasher, b"allowed-spdx-license", value.as_bytes());
    }
    for value in &input.policy.allowed_spdx_exception_ids {
        hash_framed(&mut hasher, b"allowed-spdx-exception", value.as_bytes());
    }
    for (path, bytes) in input.manifests {
        hash_framed(&mut hasher, b"workspace-manifest-path", path.as_bytes());
        hash_framed(&mut hasher, b"workspace-manifest-bytes", bytes);
    }
    format!("{:x}", hasher.finalize())
}

fn hash_framed(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn validate_tracked_artifact(
    repository: &Path,
    relative: &str,
    generated: &[u8],
    expected_sha256: &str,
) -> Result<(), String> {
    let path = repository.join(relative);
    let tracked = read_regular_file(&path, relative)?;
    if tracked != generated {
        return Err(format!(
            "{relative} does not match deterministic Cargo.lock/metadata output; review changes and run `cargo run --locked -p distribution-evidence -- write`"
        ));
    }
    let actual_sha256 = sha256(&tracked);
    if actual_sha256 != expected_sha256 {
        return Err(format!(
            "{relative} SHA-256 is {actual_sha256}, but the reviewed policy expects {expected_sha256}"
        ));
    }
    Ok(())
}

fn write_atomic(path: PathBuf, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("output path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create output directory {}: {error}", parent.display()))?;
    let temp = parent.join(format!(
        ".{}.distribution-evidence.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("output path is not UTF-8: {}", path.display()))?
    ));
    fs::write(&temp, bytes)
        .map_err(|error| format!("write temporary output {}: {error}", temp.display()))?;
    fs::rename(&temp, &path).map_err(|error| format!("replace output {}: {error}", path.display()))
}

fn read_regular_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{label} is not a regular file: {}", path.display()));
    }
    fs::read(path).map_err(|error| format!("read {label} {}: {error}", path.display()))
}

fn package_spdx_id(key: &PackageKey) -> String {
    let source = key.source.as_deref().unwrap_or("workspace");
    let digest = Sha256::digest(
        [
            key.name.as_bytes(),
            b"\0",
            key.version.as_bytes(),
            b"\0",
            source.as_bytes(),
        ]
        .concat(),
    );
    format!("SPDXRef-Package-{digest:x}")
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn require_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{label} must be 64 lowercase hexadecimal digits"))
    }
}

fn is_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}

fn require_sorted_unique<T: Ord>(values: &[T], label: &str) -> Result<(), String> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(format!("{label} must be strictly sorted and unique"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpressionToken<'a> {
    Identifier(&'a str),
    And,
    Or,
    With,
    LeftParen,
    RightParen,
}

fn validate_spdx_expression(
    expression: &str,
    allowed_license_ids: &BTreeSet<&str>,
    allowed_exception_ids: &BTreeSet<&str>,
) -> Result<(), String> {
    let tokens = tokenize_expression(expression)?;
    let mut parser = ExpressionParser {
        tokens: &tokens,
        position: 0,
        allowed_license_ids,
        allowed_exception_ids,
    };
    parser.parse_or()?;
    if parser.position != tokens.len() {
        return Err(format!(
            "unexpected token {:?}",
            tokens.get(parser.position)
        ));
    }
    Ok(())
}

fn tokenize_expression(expression: &str) -> Result<Vec<ExpressionToken<'_>>, String> {
    let mut tokens = Vec::new();
    let mut position = 0;
    while position < expression.len() {
        let remaining = &expression[position..];
        let first = remaining
            .chars()
            .next()
            .ok_or_else(|| "unexpected end of expression".to_owned())?;
        if first.is_ascii_whitespace() {
            position += first.len_utf8();
            continue;
        }
        match first {
            '(' => {
                tokens.push(ExpressionToken::LeftParen);
                position += 1;
            }
            ')' => {
                tokens.push(ExpressionToken::RightParen);
                position += 1;
            }
            _ if first.is_ascii_alphanumeric() => {
                let length = remaining
                    .char_indices()
                    .take_while(|(_, character)| {
                        character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '+')
                    })
                    .map(|(index, character)| index + character.len_utf8())
                    .last()
                    .unwrap_or(0);
                let word = &remaining[..length];
                tokens.push(match word {
                    "AND" => ExpressionToken::And,
                    "OR" => ExpressionToken::Or,
                    "WITH" => ExpressionToken::With,
                    _ => ExpressionToken::Identifier(word),
                });
                position += length;
            }
            _ => {
                return Err(format!(
                    "unsupported character {first:?} at byte {position}"
                ));
            }
        }
    }
    if tokens.is_empty() {
        return Err("empty expression".to_owned());
    }
    Ok(tokens)
}

struct ExpressionParser<'a, 'tokens> {
    tokens: &'tokens [ExpressionToken<'a>],
    position: usize,
    allowed_license_ids: &'tokens BTreeSet<&'a str>,
    allowed_exception_ids: &'tokens BTreeSet<&'a str>,
}

impl ExpressionParser<'_, '_> {
    fn parse_or(&mut self) -> Result<(), String> {
        self.parse_and()?;
        while self.consume(ExpressionToken::Or) {
            self.parse_and()?;
        }
        Ok(())
    }

    fn parse_and(&mut self) -> Result<(), String> {
        self.parse_with()?;
        while self.consume(ExpressionToken::And) {
            self.parse_with()?;
        }
        Ok(())
    }

    fn parse_with(&mut self) -> Result<(), String> {
        self.parse_primary()?;
        if self.consume(ExpressionToken::With) {
            let Some(ExpressionToken::Identifier(exception)) =
                self.tokens.get(self.position).copied()
            else {
                return Err("WITH must be followed by an exception identifier".to_owned());
            };
            if !self.allowed_exception_ids.contains(exception) {
                return Err(format!("unreviewed SPDX exception identifier {exception}"));
            }
            self.position += 1;
        }
        Ok(())
    }

    fn parse_primary(&mut self) -> Result<(), String> {
        match self.tokens.get(self.position).copied() {
            Some(ExpressionToken::Identifier(identifier)) => {
                if !self.allowed_license_ids.contains(identifier) {
                    return Err(format!("unreviewed SPDX licence identifier {identifier}"));
                }
                self.position += 1;
                Ok(())
            }
            Some(ExpressionToken::LeftParen) => {
                self.position += 1;
                self.parse_or()?;
                if !self.consume(ExpressionToken::RightParen) {
                    return Err("unclosed parenthesized expression".to_owned());
                }
                Ok(())
            }
            token => Err(format!("expected licence identifier, found {token:?}")),
        }
    }

    fn consume(&mut self, expected: ExpressionToken<'_>) -> bool {
        if self.tokens.get(self.position) == Some(&expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closure_policy() -> ThirdPartyLicensePolicy {
        ThirdPartyLicensePolicy {
            schema_version: POLICY_SCHEMA_VERSION,
            evidence_generator_schema_version: EVIDENCE_GENERATOR_SCHEMA_VERSION,
            evidence_document_created_utc: "2026-07-26T00:00:00Z".to_owned(),
            reviewed_cargo_lock_sha256: "0".repeat(64),
            reviewed_input_closure_sha256: "0".repeat(64),
            expected_sbom_sha256: "0".repeat(64),
            expected_windows_source_closure_sbom_sha256: "0".repeat(64),
            expected_notices_sha256: "0".repeat(64),
            expected_license_provenance_sha256: "0".repeat(64),
            expected_total_packages: 0,
            expected_third_party_packages: 0,
            expected_windows_source_closure_packages: 2,
            expected_windows_source_closure_third_party_packages: 1,
            allowed_registry_sources: vec![
                "registry+https://github.com/rust-lang/crates.io-index".to_owned()
            ],
            allowed_spdx_license_ids: vec!["MIT".to_owned()],
            allowed_spdx_exception_ids: vec!["LLVM-exception".to_owned()],
            non_spdx_declared_license_values: vec!["MIT/Apache-2.0".to_owned()],
            expected_packages_without_retained_license_files: Vec::new(),
            owner_distribution_approval: OwnerDistributionApprovalContract {
                mode: DETACHED_APPROVAL_MODE.to_owned(),
                contract_schema_version: OWNER_APPROVAL_SCHEMA_VERSION,
                contract_schema_path: OWNER_APPROVAL_SCHEMA_PATH.to_owned(),
                contract_schema_sha256: "0".repeat(64),
                required_for: vec![
                    "public_binary_distribution".to_owned(),
                    "public_source_distribution".to_owned(),
                ],
            },
        }
    }

    #[test]
    fn evidence_summary_has_stable_getters_and_serialization() {
        let summary = EvidenceSummary {
            total_packages: 10,
            third_party_packages: 7,
            windows_source_closure_packages: 6,
            windows_source_closure_third_party_packages: 4,
            packages_without_retained_license_files: 1,
            owner_approval_mode: DETACHED_APPROVAL_MODE.to_owned(),
        };

        assert_eq!(summary.total_packages(), 10);
        assert_eq!(summary.third_party_packages(), 7);
        assert_eq!(summary.windows_source_closure_packages(), 6);
        assert_eq!(summary.windows_source_closure_third_party_packages(), 4);
        assert_eq!(summary.packages_without_retained_license_files(), 1);
        assert_eq!(summary.owner_approval_mode(), DETACHED_APPROVAL_MODE);
        assert_eq!(
            serde_json::to_value(&summary).unwrap(),
            serde_json::json!({
                "total_packages": 10,
                "third_party_packages": 7,
                "windows_source_closure_packages": 6,
                "windows_source_closure_third_party_packages": 4,
                "packages_without_retained_license_files": 1,
                "owner_approval_mode": DETACHED_APPROVAL_MODE,
            })
        );
    }

    fn allowed_licenses() -> BTreeSet<&'static str> {
        ["Apache-2.0", "MIT", "Unicode-3.0"].into_iter().collect()
    }

    fn mode_closure_metadata(autocad_dependencies: &[&str]) -> CargoMetadata {
        let package = |id: &str, name: &str, source: Option<&str>| MetadataPackage {
            id: id.to_owned(),
            name: name.to_owned(),
            version: "0.0.1".to_owned(),
            source: source.map(str::to_owned),
            license: Some("MIT".to_owned()),
            license_file: None,
            manifest_path: PathBuf::from(format!("{name}/Cargo.toml")),
        };
        let node = |id: &str, dependencies: &[&str]| MetadataNode {
            id: id.to_owned(),
            dependencies: dependencies
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            deps: dependencies
                .iter()
                .map(|value| MetadataDependency {
                    pkg: (*value).to_owned(),
                    dep_kinds: vec![MetadataDependencyKind { kind: None }],
                })
                .collect(),
        };
        CargoMetadata {
            packages: vec![
                package("autocad", "autocad-mcp", None),
                package("lsp", "autolisp-lsp", None),
                package("shared", "shared", Some("registry+https://example.invalid")),
            ],
            workspace_members: vec!["autocad".to_owned(), "lsp".to_owned()],
            resolve: MetadataResolve {
                nodes: vec![
                    node("autocad", autocad_dependencies),
                    node("lsp", &["shared"]),
                    node("shared", &[]),
                ],
            },
        }
    }

    #[test]
    fn spdx_expression_parser_accepts_reviewed_boolean_forms() {
        let licenses = allowed_licenses();
        let exceptions = ["LLVM-exception"].into_iter().collect();
        for expression in [
            "MIT",
            "MIT OR Apache-2.0",
            "(MIT OR Apache-2.0) AND Unicode-3.0",
            "Apache-2.0 WITH LLVM-exception OR MIT",
        ] {
            validate_spdx_expression(expression, &licenses, &exceptions).unwrap();
        }
    }

    #[test]
    fn spdx_expression_parser_rejects_unknown_and_slash_forms() {
        let licenses = allowed_licenses();
        let exceptions = ["LLVM-exception"].into_iter().collect();
        assert!(validate_spdx_expression("MPL-2.0", &licenses, &exceptions).is_err());
        assert!(validate_spdx_expression("MIT/Apache-2.0", &licenses, &exceptions).is_err());
        assert!(
            validate_spdx_expression("Apache-2.0 WITH unknown", &licenses, &exceptions).is_err()
        );
        assert!(validate_spdx_expression("(MIT OR Apache-2.0", &licenses, &exceptions).is_err());
    }

    #[test]
    fn cargo_lock_parser_retains_registry_checksum_and_workspace_identity() {
        let lock = br#"
version = 4

[[package]]
name = "external"
version = "1.2.3"
source = "registry+https://example.invalid/index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
dependencies = [
 "workspace",
]

[[package]]
name = "workspace"
version = "0.1.0"
"#;
        let parsed = parse_cargo_lock(lock).unwrap();
        assert_eq!(parsed.len(), 2);
        let external = parsed
            .iter()
            .find(|(key, _)| key.name == "external")
            .map(|(_, package)| package)
            .unwrap();
        assert_eq!(
            external.checksum.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        let (workspace_key, workspace) = parsed
            .iter()
            .find(|(key, _)| key.name == "workspace")
            .unwrap();
        assert!(workspace.checksum.is_none());
        assert!(workspace_key.source.is_none());
    }

    #[test]
    fn spdx_package_comments_distinguish_workspace_from_archive_evidence() {
        let package = |source: Option<&str>, checksum: Option<&str>| AuditedPackage {
            metadata: MetadataPackage {
                id: "example 0.1.0".to_owned(),
                name: "example".to_owned(),
                version: "0.1.0".to_owned(),
                source: source.map(str::to_owned),
                license: Some("MIT".to_owned()),
                license_file: None,
                manifest_path: PathBuf::from("example/Cargo.toml"),
            },
            lock_checksum: checksum.map(str::to_owned),
            spdx_id: "SPDXRef-Package-example".to_owned(),
            retained_license_files: Vec::new(),
            cargo_vcs_info: None,
        };
        let non_spdx = BTreeSet::new();

        let workspace = spdx_package_for(&package(None, None), &non_spdx);
        assert!(workspace.checksums.is_empty());
        assert!(workspace.license_comments.contains(
            "Workspace package: no .crate archive or Cargo.lock package checksum applies"
        ));
        assert!(!workspace
            .license_comments
            .contains("Checksum-verified .crate archive evidence"));

        let checksum = "a".repeat(64);
        let registry = spdx_package_for(
            &package(
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(&checksum),
            ),
            &non_spdx,
        );
        assert_eq!(registry.checksums.len(), 1);
        assert!(registry
            .license_comments
            .contains("Checksum-verified .crate archive evidence"));
        assert!(!registry.license_comments.contains("Workspace package:"));
    }

    #[test]
    fn release_and_preview_closures_must_match_packages_and_edges() {
        let release = mode_closure_metadata(&["shared"]);
        let matching_preview = mode_closure_metadata(&["shared"]);
        let release_closure = target_product_closure(&release, &WINDOWS_PRODUCT_ROOTS).unwrap();
        let matching_closure =
            target_product_closure(&matching_preview, &WINDOWS_PRODUCT_ROOTS).unwrap();
        require_identical_windows_mode_closures(
            &release,
            &release_closure,
            &matching_preview,
            &matching_closure,
        )
        .unwrap();

        let edge_drift = mode_closure_metadata(&[]);
        let edge_drift_closure =
            target_product_closure(&edge_drift, &WINDOWS_PRODUCT_ROOTS).unwrap();
        let error = require_identical_windows_mode_closures(
            &release,
            &release_closure,
            &edge_drift,
            &edge_drift_closure,
        )
        .unwrap_err();
        assert!(error.contains("dependency-edge closures differ"), "{error}");
    }

    #[test]
    fn evidence_file_name_filter_is_closed() {
        for admitted in [
            "LICENSE",
            "LICENSE-MIT",
            "LICENCE.md",
            "COPYING.txt",
            "NOTICE",
            "UNLICENSE",
        ] {
            assert!(is_license_evidence_name(admitted), "{admitted}");
        }
        for rejected in ["README.md", "licensee", "notices", "COPYINGPRIVATE"] {
            assert!(!is_license_evidence_name(rejected), "{rejected}");
        }
    }

    #[test]
    fn policy_rejects_an_embedded_approval_mode() {
        let mut policy = closure_policy();
        policy.owner_distribution_approval.mode = "approved".to_owned();
        let error = validate_policy_shape(&policy).unwrap_err();
        assert!(
            error.contains("owner_distribution_approval.mode"),
            "{error}"
        );
    }

    #[test]
    fn input_closure_binds_generator_and_toolchain_bytes() {
        let policy = closure_policy();
        let manifests = vec![(
            "crates/example/Cargo.toml".to_owned(),
            b"[package]\nname = \"example\"\n".to_vec(),
        )];
        let supplemental = BTreeMap::from([(
            "plugin/.third-party/license-supplements/example-LICENSE.txt".to_owned(),
            b"example licence\n".to_vec(),
        )]);
        let inputs = |generator_source, rust_toolchain| InputClosure {
            lock_bytes: b"lock",
            workspace_manifest: b"[workspace]\n",
            generator_source,
            rust_toolchain,
            policy: &policy,
            manifests: &manifests,
            provenance: b"{\"provenance\":\"a\"}\n",
            supplemental_files: &supplemental,
            owner_approval_schema: b"{\"schema\":\"a\"}\n",
        };
        let baseline = hash_input_closure(inputs(
            b"generator-a\n",
            b"[toolchain]\nchannel = \"1.97.0\"\n",
        ));
        let changed_generator = hash_input_closure(inputs(
            b"generator-b\n",
            b"[toolchain]\nchannel = \"1.97.0\"\n",
        ));
        let changed_toolchain = hash_input_closure(inputs(
            b"generator-a\n",
            b"[toolchain]\nchannel = \"1.98.0\"\n",
        ));
        assert_ne!(baseline, changed_generator);
        assert_ne!(baseline, changed_toolchain);
    }

    #[test]
    fn workspace_manifest_paths_are_forward_slash_normalized() {
        let joined = PathBuf::from("crates").join("example").join("Cargo.toml");
        assert_eq!(
            normalized_relative_path_text(&joined).unwrap(),
            "crates/example/Cargo.toml"
        );
        assert!(normalized_relative_path_text(Path::new("../Cargo.toml")).is_err());
    }

    #[test]
    fn workspace_manifest_containment_uses_canonical_filesystem_paths() {
        let crate_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repository = crate_directory.join("..").join("..").join("..");
        let canonical_repository = repository.canonicalize().unwrap();
        let canonical_manifest = crate_directory.join("Cargo.toml").canonicalize().unwrap();

        assert_eq!(
            workspace_manifest_relative_path(&canonical_repository, &canonical_manifest).unwrap(),
            PathBuf::from("crates")
                .join("distribution")
                .join("evidence")
                .join("Cargo.toml")
        );
    }
}
