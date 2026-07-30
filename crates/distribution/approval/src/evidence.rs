use super::{
    error, sha256_hex, DeterminationTreatment, OwnerDistributionApproval, ValidationError,
    INITIAL_WINDOWS_TARGET,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const REGISTRY_SOURCE_PREFIX: &str = "Resolved by Cargo.lock from ";
const REGISTRY_SOURCE_SUFFIX: &str = "; SHA-256 checksum is the Cargo.lock package checksum.";
const WORKSPACE_SOURCE_INFO: &str = "AutoCAD-MCP workspace package.";
const CARGO_LICENSE_PREFIX: &str = "Cargo manifest licence metadata: ";
const CARGO_LICENSE_SUFFIX: &str = ". The Cargo value is emitted as SPDX licenseDeclared.";

/// Bytes for one supplemental licence-evidence binding.
#[derive(Clone, Copy, Debug)]
pub struct SupplementalEvidenceBytes<'a> {
    pub binding_id: &'a str,
    pub bytes: &'a [u8],
}

/// Exact distribution evidence bound by an owner distribution approval.
///
/// This validator reconciles the source-closure and third-party licence
/// evidence, project licence, approval schema, build-attestation binding, and
/// package determinations. It intentionally does not validate archive contents,
/// executable containment, or the semantic truth of the native build
/// attestation; those remain release-artifact gates.
#[derive(Clone, Copy, Debug)]
pub struct BoundDistributionEvidence<'a> {
    pub third_party_license_policy: &'a [u8],
    pub source_lock_sbom: &'a [u8],
    pub windows_source_closure_sbom: &'a [u8],
    pub third_party_notices: &'a [u8],
    pub third_party_license_provenance: &'a [u8],
    pub project_license: &'a [u8],
    pub approval_contract_schema: &'a [u8],
    pub build_attestation: &'a [u8],
    pub supplemental_license_evidence: &'a [SupplementalEvidenceBytes<'a>],
}

impl OwnerDistributionApproval {
    pub fn validate_distribution_evidence(
        &self,
        evidence: &BoundDistributionEvidence<'_>,
    ) -> Result<(), ValidationError> {
        self.validate()?;
        self.verify_bound_evidence_bytes(evidence)?;

        let policy = parse_strict_json(
            evidence.third_party_license_policy,
            "third-party licence policy",
        )?;
        let expected_total = required_usize(&policy, "expected_total_packages")?;
        let expected_third_party = required_usize(&policy, "expected_third_party_packages")?;
        let expected_source_closure_total =
            required_usize(&policy, "expected_windows_source_closure_packages")?;
        let expected_source_closure_third_party = required_usize(
            &policy,
            "expected_windows_source_closure_third_party_packages",
        )?;
        let allowed_registry_sources = required_string_set(&policy, "allowed_registry_sources")?;
        if allowed_registry_sources.is_empty() {
            return Err(evidence_error(
                "third_party_license_policy_invalid",
                "allowed_registry_sources must not be empty",
            ));
        }

        require_policy_digest(
            &policy,
            "reviewed_cargo_lock_sha256",
            self.source_identity.cargo_lock_sha256(),
        )?;
        require_policy_digest(
            &policy,
            "reviewed_input_closure_sha256",
            self.source_identity.dependency_input_closure_sha256(),
        )?;
        require_policy_digest(
            &policy,
            "expected_sbom_sha256",
            &sha256_hex(evidence.source_lock_sbom),
        )?;
        require_policy_digest(
            &policy,
            "expected_windows_source_closure_sbom_sha256",
            &sha256_hex(evidence.windows_source_closure_sbom),
        )?;
        require_policy_digest(
            &policy,
            "expected_notices_sha256",
            &sha256_hex(evidence.third_party_notices),
        )?;
        require_policy_digest(
            &policy,
            "expected_license_provenance_sha256",
            &sha256_hex(evidence.third_party_license_provenance),
        )?;
        let approval_policy = policy
            .get("owner_distribution_approval")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                evidence_error(
                    "third_party_license_policy_invalid",
                    "owner_distribution_approval must be an object",
                )
            })?;
        if approval_policy.get("mode").and_then(Value::as_str)
            != Some("detached_per_distribution_set")
            || approval_policy
                .get("contract_schema_version")
                .and_then(Value::as_u64)
                != Some(super::APPROVAL_SCHEMA_VERSION as u64)
            || approval_policy
                .get("contract_schema_path")
                .and_then(Value::as_str)
                != Some(super::APPROVAL_CONTRACT_SCHEMA_PATH)
            || approval_policy
                .get("required_for")
                .and_then(Value::as_array)
                != Some(&vec![
                    Value::String("public_binary_distribution".to_owned()),
                    Value::String("public_source_distribution".to_owned()),
                ])
        {
            return Err(evidence_error(
                "third_party_license_policy_approval_contract_invalid",
                format!(
                    "third-party licence policy does not require the exact detached schema-v{} approval for both public scopes",
                    super::APPROVAL_SCHEMA_VERSION
                ),
            ));
        }
        let schema_digest = approval_policy
            .get("contract_schema_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                evidence_error(
                    "third_party_license_policy_invalid",
                    "owner_distribution_approval.contract_schema_sha256 must be a string",
                )
            })?;
        if schema_digest != sha256_hex(evidence.approval_contract_schema) {
            return Err(evidence_error(
                "third_party_license_policy_digest_mismatch",
                "approval contract schema digest does not match the third-party licence policy",
            ));
        }

        let source = parse_spdx(
            evidence.source_lock_sbom,
            "source-lock SBOM",
            expected_total,
            expected_third_party,
            &allowed_registry_sources,
        )?;
        let source_closure = parse_windows_source_closure_spdx(
            evidence.windows_source_closure_sbom,
            "Windows source-closure SBOM",
            expected_source_closure_total,
            expected_source_closure_third_party,
            &allowed_registry_sources,
            self.source_identity.cargo_lock_sha256(),
            self.source_identity.dependency_input_closure_sha256(),
        )?;
        for key in source_closure.packages.keys() {
            let source_package = source.packages.get(key).ok_or_else(|| {
                evidence_error(
                    "source_closure_sbom_not_source_subset",
                    format!(
                        "source-closure package {} {} is absent from the source-lock SBOM",
                        key.name, key.version
                    ),
                )
            })?;
            if source_package != &source_closure.packages[key] {
                return Err(evidence_error(
                    "source_closure_sbom_package_drift",
                    format!(
                        "source-closure package {} {} differs from its source-lock identity",
                        key.name, key.version
                    ),
                ));
            }
        }

        for exclusion in &self.source_exclusions {
            let matches = source_closure
                .packages
                .keys()
                .filter(|key| {
                    key.name == exclusion.package_name()
                        && key.version == exclusion.package_version()
                })
                .count();
            if matches != 1 {
                return Err(evidence_error(
                    "source_exclusion_package_mismatch",
                    format!(
                        "source exclusion {} {} must identify exactly one Windows source-closure package",
                        exclusion.package_name(),
                        exclusion.package_version()
                    ),
                ));
            }
        }

        let provenance =
            parse_provenance(evidence.third_party_license_provenance, &source.packages)?;
        for binding in &self.evidence_bindings.supplemental_license_evidence {
            let provenance_file = provenance
                .supplemental_sources
                .get(binding.binding_id.as_str())
                .ok_or_else(|| {
                    evidence_error(
                        "supplemental_evidence_provenance_missing",
                        format!(
                            "supplemental evidence {} lacks an exact technical provenance source",
                            binding.binding_id
                        ),
                    )
                })?;
            if provenance_file.0 != binding.file.logical_path
                || provenance_file.1 != binding.file.size_bytes
                || provenance_file.2 != binding.file.sha256
            {
                return Err(evidence_error(
                    "supplemental_evidence_provenance_mismatch",
                    format!(
                        "supplemental evidence {} differs from its technical provenance source",
                        binding.binding_id
                    ),
                ));
            }
        }
        self.reconcile_determinations(&source.packages, &source_closure.packages, &provenance)?;
        Ok(())
    }

    fn verify_bound_evidence_bytes(
        &self,
        evidence: &BoundDistributionEvidence<'_>,
    ) -> Result<(), ValidationError> {
        let bindings = &self.evidence_bindings;
        for (binding, bytes) in [
            (
                &bindings.third_party_license_policy,
                evidence.third_party_license_policy,
            ),
            (&bindings.source_lock_sbom, evidence.source_lock_sbom),
            (&bindings.third_party_notices, evidence.third_party_notices),
            (
                &bindings.third_party_license_provenance,
                evidence.third_party_license_provenance,
            ),
            (&bindings.project_license, evidence.project_license),
            (
                &bindings.approval_contract_schema,
                evidence.approval_contract_schema,
            ),
        ] {
            binding.verify_bytes(bytes)?;
        }
        bindings.source_closure_sboms[0]
            .file
            .verify_bytes(evidence.windows_source_closure_sbom)?;
        bindings.build_attestations[0]
            .file
            .verify_bytes(evidence.build_attestation)?;

        let provided = evidence
            .supplemental_license_evidence
            .iter()
            .map(|item| (item.binding_id, item.bytes))
            .collect::<BTreeMap<_, _>>();
        if provided.len() != evidence.supplemental_license_evidence.len() {
            return Err(evidence_error(
                "supplemental_evidence_duplicate",
                "supplemental evidence byte bindings contain a duplicate ID",
            ));
        }
        let expected = bindings
            .supplemental_license_evidence
            .iter()
            .map(|binding| binding.binding_id.as_str())
            .collect::<BTreeSet<_>>();
        if provided.keys().copied().collect::<BTreeSet<_>>() != expected {
            return Err(evidence_error(
                "supplemental_evidence_set_mismatch",
                "provided supplemental evidence IDs do not exactly match the approval",
            ));
        }
        for binding in &bindings.supplemental_license_evidence {
            binding
                .file
                .verify_bytes(provided[&binding.binding_id.as_str()])?;
        }
        Ok(())
    }

    fn reconcile_determinations(
        &self,
        source: &BTreeMap<EvidencePackageKey, String>,
        source_closure: &BTreeMap<EvidencePackageKey, String>,
        provenance: &ProvenanceIndex,
    ) -> Result<(), ValidationError> {
        let source_keys = source.keys().cloned().collect::<BTreeSet<_>>();
        let mut by_scope = self
            .distribution_scopes
            .iter()
            .map(|scope| (scope.scope_id.as_str(), BTreeSet::new()))
            .collect::<BTreeMap<_, _>>();

        for determination in &self.package_determinations {
            let excluded = determination.treatment == DeterminationTreatment::ExcludedByTargetGraph;
            let mut determination_sources = BTreeSet::new();
            let mut keys = Vec::with_capacity(determination.packages.len());
            for package in &determination.packages {
                let key = EvidencePackageKey {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    source: package.source.clone(),
                    checksum: package.cargo_package_sha256.clone(),
                    spdx_id: package.spdx_id.clone(),
                };
                let declared_value = source.get(&key).ok_or_else(|| {
                    evidence_error(
                        "determination_package_unknown",
                        format!(
                            "determination {} package {} {} does not exactly match the source-lock SBOM",
                            determination.determination_id, package.name, package.version
                        ),
                    )
                })?;
                if declared_value != &determination.declared_value {
                    return Err(evidence_error(
                        "determination_declared_value_mismatch",
                        format!(
                            "determination {} does not preserve the raw Cargo licence value for {} {}",
                            determination.determination_id, package.name, package.version
                        ),
                    ));
                }
                let in_source_closure = source_closure.contains_key(&key);
                if excluded == in_source_closure {
                    return Err(evidence_error(
                        "determination_source_closure_membership_mismatch",
                        format!(
                            "determination {} classifies {} {} contrary to the Windows source-closure SBOM",
                            determination.determination_id, package.name, package.version
                        ),
                    ));
                }
                if let Some(source_id) = provenance.package_sources.get(&key) {
                    determination_sources.insert(source_id.as_str());
                }
                keys.push(key);
            }
            let actual_sources = determination
                .provenance_source_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if actual_sources != determination_sources {
                return Err(evidence_error(
                    "determination_provenance_mismatch",
                    format!(
                        "determination {} provenance_source_ids do not match the technical provenance ledger",
                        determination.determination_id
                    ),
                ));
            }
            for scope_id in &determination.scope_ids {
                let covered = by_scope.get_mut(scope_id.as_str()).ok_or_else(|| {
                    evidence_error(
                        "determination_scope_unknown",
                        format!(
                            "determination {} references unknown scope {}",
                            determination.determination_id, scope_id
                        ),
                    )
                })?;
                for key in &keys {
                    if !covered.insert(key.clone()) {
                        return Err(evidence_error(
                            "determination_scope_overlap",
                            format!(
                                "package {} {} is determined more than once in scope {}",
                                key.name, key.version, scope_id
                            ),
                        ));
                    }
                }
            }
        }
        for (scope_id, covered) in by_scope {
            if covered != source_keys {
                let missing = source_keys.difference(&covered).count();
                let extra = covered.difference(&source_keys).count();
                return Err(evidence_error(
                    "determination_scope_incomplete",
                    format!(
                        "scope {scope_id} does not exactly partition the source-lock third-party packages ({missing} missing, {extra} extra)"
                    ),
                ));
            }
        }

        let used_sources = provenance
            .package_sources
            .values()
            .cloned()
            .collect::<BTreeSet<_>>();
        if used_sources != provenance.source_ids {
            return Err(evidence_error(
                "provenance_source_boundary_mismatch",
                "technical provenance contains an unused source or a binding to an unknown source",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EvidencePackageKey {
    name: String,
    version: String,
    source: String,
    checksum: String,
    spdx_id: String,
}

#[derive(Debug, Deserialize)]
struct SpdxDocument {
    packages: Vec<SpdxPackage>,
}

#[derive(Debug, Deserialize)]
struct SourceClosureSpdxDocument {
    #[serde(rename = "spdxVersion")]
    spdx_version: String,
    #[serde(rename = "dataLicense")]
    data_license: String,
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(rename = "documentNamespace")]
    document_namespace: String,
    #[serde(rename = "creationInfo")]
    creation_info: SourceClosureCreationInfo,
    #[serde(rename = "documentDescribes")]
    document_describes: Vec<String>,
    packages: Vec<SourceClosurePackage>,
}

#[derive(Debug, Deserialize)]
struct SourceClosureCreationInfo {
    comment: String,
}

#[derive(Debug, Deserialize)]
struct SourceClosurePackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(rename = "sourceInfo")]
    source_info: String,
}

#[derive(Debug, Deserialize)]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(rename = "versionInfo")]
    version: String,
    #[serde(default)]
    checksums: Vec<SpdxChecksum>,
    #[serde(rename = "licenseComments")]
    license_comments: String,
    #[serde(rename = "sourceInfo")]
    source_info: String,
}

#[derive(Debug, Deserialize)]
struct SpdxChecksum {
    algorithm: String,
    #[serde(rename = "checksumValue")]
    value: String,
}

struct ParsedSpdx {
    packages: BTreeMap<EvidencePackageKey, String>,
}

fn parse_spdx(
    bytes: &[u8],
    label: &str,
    expected_total: usize,
    expected_third_party: usize,
    allowed_registry_sources: &BTreeSet<String>,
) -> Result<ParsedSpdx, ValidationError> {
    let value = parse_strict_json(bytes, label)?;
    parse_spdx_value(
        value,
        label,
        expected_total,
        expected_third_party,
        allowed_registry_sources,
    )
}

fn parse_windows_source_closure_spdx(
    bytes: &[u8],
    label: &str,
    expected_total: usize,
    expected_third_party: usize,
    allowed_registry_sources: &BTreeSet<String>,
    cargo_lock_sha256: &str,
    input_closure_sha256: &str,
) -> Result<ParsedSpdx, ValidationError> {
    let value = parse_strict_json(bytes, label)?;
    validate_windows_source_closure_semantics(
        value.clone(),
        label,
        cargo_lock_sha256,
        input_closure_sha256,
    )?;
    parse_spdx_value(
        value,
        label,
        expected_total,
        expected_third_party,
        allowed_registry_sources,
    )
}

fn validate_windows_source_closure_semantics(
    value: Value,
    label: &str,
    cargo_lock_sha256: &str,
    input_closure_sha256: &str,
) -> Result<(), ValidationError> {
    let document: SourceClosureSpdxDocument =
        serde_json::from_value(value).map_err(|parse_error| {
            evidence_error(
                "source_closure_sbom_scope_invalid",
                format!("{label} scope shape is invalid: {parse_error}"),
            )
        })?;
    if document.spdx_version != "SPDX-2.3"
        || document.data_license != "CC0-1.0"
        || document.spdx_id != "SPDXRef-DOCUMENT"
        || document.name != "AutoCAD-MCP Windows x64 product build-source closure"
    {
        return Err(evidence_error(
            "source_closure_sbom_scope_invalid",
            format!("{label} is not the required SPDX 2.3 build-source closure"),
        ));
    }
    let expected_namespace = format!(
        "https://andagni.invalid/spdx/autocad-mcp/windows-x64-source-build-closure-{input_closure_sha256}"
    );
    if document.document_namespace != expected_namespace {
        return Err(evidence_error(
            "source_closure_sbom_namespace_mismatch",
            format!("{label} namespace does not bind the reviewed dependency input closure"),
        ));
    }
    let expected_comment = format!(
        "Generated deterministically from Cargo.lock and two exact commands: `cargo metadata --locked --offline --format-version 1 --filter-platform {INITIAL_WINDOWS_TARGET} --no-default-features` for Release, and `cargo metadata --locked --offline --format-version 1 --filter-platform {INITIAL_WINDOWS_TARGET} --no-default-features --features autocad-mcp/preview` for Preview. Generation requires the selected normal/build package and dependency-edge closures of the autocad-mcp and autolisp-lsp product roots to be identical across both modes, excluding development-only edges; any divergence fails closed pending separately reviewed mode-specific evidence. Cargo.lock SHA-256: {cargo_lock_sha256}. This is conservative target build-source evidence, including build scripts and proc macros; it is not a linked-binary or native-object SBOM and does not assert legal approval. Exact executable hashes and native imports require a separate build attestation."
    );
    if document.creation_info.comment != expected_comment {
        return Err(evidence_error(
            "source_closure_sbom_scope_warning_mismatch",
            format!(
                "{label} does not preserve its exact source-closure and non-binary scope statement"
            ),
        ));
    }

    let expected_root_names = BTreeSet::from(["autocad-mcp", "autolisp-lsp"]);
    let mut root_ids = BTreeMap::new();
    for package in document.packages {
        if package.source_info == WORKSPACE_SOURCE_INFO
            && expected_root_names.contains(package.name.as_str())
            && root_ids
                .insert(package.name.clone(), package.spdx_id)
                .is_some()
        {
            return Err(evidence_error(
                "source_closure_sbom_product_root_duplicate",
                format!("{label} repeats product root {}", package.name),
            ));
        }
    }
    if root_ids.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_root_names {
        return Err(evidence_error(
            "source_closure_sbom_product_roots_invalid",
            format!("{label} must contain exactly the autocad-mcp and autolisp-lsp product roots"),
        ));
    }
    let described = document
        .document_describes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_described = root_ids
        .values()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if document.document_describes.len() != expected_described.len()
        || described != expected_described
    {
        return Err(evidence_error(
            "source_closure_sbom_document_describes_invalid",
            format!(
                "{label} documentDescribes must identify exactly the two product-root packages"
            ),
        ));
    }
    Ok(())
}

fn parse_spdx_value(
    value: Value,
    label: &str,
    expected_total: usize,
    expected_third_party: usize,
    allowed_registry_sources: &BTreeSet<String>,
) -> Result<ParsedSpdx, ValidationError> {
    let document: SpdxDocument = serde_json::from_value(value).map_err(|parse_error| {
        evidence_error(
            "dependency_sbom_invalid",
            format!("{label} shape is invalid: {parse_error}"),
        )
    })?;
    if document.packages.len() != expected_total {
        return Err(evidence_error(
            "dependency_sbom_count_mismatch",
            format!(
                "{label} has {} packages, expected {expected_total}",
                document.packages.len()
            ),
        ));
    }
    let mut packages = BTreeMap::new();
    for package in document.packages {
        if package.source_info == WORKSPACE_SOURCE_INFO {
            if !package.checksums.is_empty() {
                return Err(evidence_error(
                    "workspace_sbom_checksum_invalid",
                    format!(
                        "{label} workspace package {} {} unexpectedly has registry checksums",
                        package.name, package.version
                    ),
                ));
            }
            continue;
        }
        let source = package
            .source_info
            .strip_prefix(REGISTRY_SOURCE_PREFIX)
            .and_then(|value| value.strip_suffix(REGISTRY_SOURCE_SUFFIX))
            .ok_or_else(|| {
                evidence_error(
                    "dependency_sbom_source_invalid",
                    format!(
                        "{label} package {} {} has an unsupported sourceInfo",
                        package.name, package.version
                    ),
                )
            })?;
        if !allowed_registry_sources.contains(source) {
            return Err(evidence_error(
                "dependency_sbom_registry_unapproved",
                format!(
                    "{label} package {} {} uses unapproved registry source {source}",
                    package.name, package.version
                ),
            ));
        }
        if package.checksums.len() != 1 || package.checksums[0].algorithm != "SHA256" {
            return Err(evidence_error(
                "dependency_sbom_checksum_invalid",
                format!(
                    "{label} package {} {} must have exactly one SHA256 checksum",
                    package.name, package.version
                ),
            ));
        }
        super::require_sha256(
            &package.checksums[0].value,
            "dependency SBOM package checksum",
        )?;
        if !package.spdx_id.starts_with("SPDXRef-") {
            return Err(evidence_error(
                "dependency_sbom_spdx_id_invalid",
                format!(
                    "{label} package {} {} has an invalid SPDXID",
                    package.name, package.version
                ),
            ));
        }
        let declared_value = package
            .license_comments
            .strip_prefix(CARGO_LICENSE_PREFIX)
            .and_then(|value| value.split_once(CARGO_LICENSE_SUFFIX))
            .map(|(declared, _)| declared)
            .filter(|declared| !declared.is_empty())
            .ok_or_else(|| {
                evidence_error(
                    "dependency_sbom_declared_value_missing",
                    format!(
                        "{label} package {} {} does not preserve raw Cargo licence metadata",
                        package.name, package.version
                    ),
                )
            })?
            .to_owned();
        let key = EvidencePackageKey {
            name: package.name,
            version: package.version,
            source: source.to_owned(),
            checksum: package.checksums[0].value.clone(),
            spdx_id: package.spdx_id,
        };
        if packages.insert(key.clone(), declared_value).is_some() {
            return Err(evidence_error(
                "dependency_sbom_package_duplicate",
                format!(
                    "{label} repeats package identity {} {}",
                    key.name, key.version
                ),
            ));
        }
    }
    if packages.len() != expected_third_party {
        return Err(evidence_error(
            "dependency_sbom_third_party_count_mismatch",
            format!(
                "{label} has {} third-party packages, expected {expected_third_party}",
                packages.len()
            ),
        ));
    }
    Ok(ParsedSpdx { packages })
}

#[derive(Debug, Deserialize)]
struct ProvenanceDocument {
    sources: Vec<ProvenanceSource>,
    package_bindings: Vec<ProvenancePackageBinding>,
}

#[derive(Debug, Deserialize)]
struct ProvenanceSource {
    id: String,
    #[serde(default)]
    tracked_path: Option<String>,
    #[serde(default)]
    byte_length: Option<u64>,
    #[serde(default)]
    sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProvenancePackageBinding {
    package: ProvenancePackage,
    source_id: String,
}

#[derive(Debug, Deserialize)]
struct ProvenancePackage {
    name: String,
    version: String,
    archive_sha256: String,
    declared_license: String,
}

struct ProvenanceIndex {
    source_ids: BTreeSet<String>,
    package_sources: BTreeMap<EvidencePackageKey, String>,
    supplemental_sources: BTreeMap<String, (String, u64, String)>,
}

fn parse_provenance(
    bytes: &[u8],
    source_packages: &BTreeMap<EvidencePackageKey, String>,
) -> Result<ProvenanceIndex, ValidationError> {
    let document: ProvenanceDocument = serde_json::from_value(parse_strict_json(
        bytes,
        "third-party licence provenance ledger",
    )?)
    .map_err(|parse_error| {
        evidence_error(
            "third_party_license_provenance_invalid",
            format!("third-party licence provenance shape is invalid: {parse_error}"),
        )
    })?;
    let mut source_ids = BTreeSet::new();
    let mut supplemental_sources = BTreeMap::new();
    for source in document.sources {
        if !source_ids.insert(source.id.clone()) {
            return Err(evidence_error(
                "third_party_license_provenance_source_duplicate",
                format!(
                    "third-party licence provenance repeats source {}",
                    source.id
                ),
            ));
        }
        if let (Some(path), Some(size), Some(digest)) =
            (source.tracked_path, source.byte_length, source.sha256)
        {
            supplemental_sources.insert(source.id, (path, size, digest));
        }
    }

    let mut package_sources = BTreeMap::new();
    for binding in document.package_bindings {
        if !source_ids.contains(&binding.source_id) {
            return Err(evidence_error(
                "third_party_license_provenance_source_unknown",
                format!(
                    "third-party licence provenance binding references unknown source {}",
                    binding.source_id
                ),
            ));
        }
        let candidates = source_packages
            .iter()
            .filter(|(key, declared)| {
                key.name == binding.package.name
                    && key.version == binding.package.version
                    && key.checksum == binding.package.archive_sha256
                    && *declared == &binding.package.declared_license
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            return Err(evidence_error(
                "third_party_license_provenance_package_mismatch",
                format!(
                    "third-party licence provenance package {} {} does not exactly match the source-lock SBOM",
                    binding.package.name, binding.package.version
                ),
            ));
        }
        if package_sources
            .insert(candidates[0].clone(), binding.source_id)
            .is_some()
        {
            return Err(evidence_error(
                "third_party_license_provenance_package_duplicate",
                format!(
                    "third-party licence provenance repeats package {} {}",
                    binding.package.name, binding.package.version
                ),
            ));
        }
    }

    Ok(ProvenanceIndex {
        source_ids,
        package_sources,
        supplemental_sources,
    })
}

fn parse_strict_json(bytes: &[u8], label: &str) -> Result<Value, ValidationError> {
    release_qualification::parse_strict_json(bytes).map_err(|parse_error| {
        evidence_error(
            "distribution_evidence_json_invalid",
            format!("{label} strict JSON parse failed: {parse_error}"),
        )
    })
}

fn required_usize(document: &Value, field: &str) -> Result<usize, ValidationError> {
    let value = document.get(field).and_then(Value::as_u64).ok_or_else(|| {
        evidence_error(
            "third_party_license_policy_invalid",
            format!("{field} must be an unsigned integer"),
        )
    })?;
    usize::try_from(value).map_err(|_| {
        evidence_error(
            "third_party_license_policy_invalid",
            format!("{field} does not fit usize"),
        )
    })
}

fn required_string_set(document: &Value, field: &str) -> Result<BTreeSet<String>, ValidationError> {
    let values = document
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            evidence_error(
                "third_party_license_policy_invalid",
                format!("{field} must be an array"),
            )
        })?;
    let mut result = BTreeSet::new();
    for value in values {
        let value = value.as_str().ok_or_else(|| {
            evidence_error(
                "third_party_license_policy_invalid",
                format!("{field} entries must be strings"),
            )
        })?;
        if !result.insert(value.to_owned()) {
            return Err(evidence_error(
                "third_party_license_policy_invalid",
                format!("{field} must be unique"),
            ));
        }
    }
    Ok(result)
}

fn require_policy_digest(
    policy: &Value,
    field: &str,
    expected: &str,
) -> Result<(), ValidationError> {
    let actual = policy.get(field).and_then(Value::as_str).ok_or_else(|| {
        evidence_error(
            "third_party_license_policy_invalid",
            format!("{field} must be a string"),
        )
    })?;
    if actual != expected {
        return Err(evidence_error(
            "third_party_license_policy_digest_mismatch",
            format!("{field} does not match its bound evidence"),
        ));
    }
    Ok(())
}

fn evidence_error(code: &'static str, detail: impl Into<String>) -> ValidationError {
    error(code, detail)
}
