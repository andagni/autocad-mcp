use super::{
    error, require_decision_id, require_lower_hex, require_safe_logical_path, require_sha256,
    valid_profile_version, DistributionMode, GitObjectFormat, ValidationError,
};
use release_qualification::StatementContract;
use serde::{Deserialize, Serialize};

pub const PREVIEW_PUBLICATION_HANDOFF_SCHEMA_VERSION: u32 = 2;
pub const PREVIEW_PUBLICATION_HANDOFF_KIND: &str = "preview_publication_handoff";
pub const PREVIEW_PUBLICATION_HANDOFF_SIGNING_DOMAIN: &str =
    "autocad-mcp.release/preview-publication-handoff/v2";
pub const PREVIEW_PUBLICATION_HANDOFF_SCHEMA_PATH: &str =
    "crates/distribution/approval/schemas/preview-publication-handoff.schema.json";

pub const PREVIEW_PUBLICATION_SHA256SUMS_PATH: &str = "SHA256SUMS.txt";
pub const PREVIEW_PUBLICATION_SOURCE_ARCHIVE_PATH: &str =
    "autocad-mcp-windows-x64-preview-build-source.zip";
pub const PREVIEW_PUBLICATION_MCPB_PATH: &str = "autocad-mcp-windows-x64-preview.mcpb";
pub const PREVIEW_PUBLICATION_CURRENT_DISTRIBUTION_RECEIPT_PATH: &str =
    "current-distribution-verification.json";
pub const PREVIEW_PUBLICATION_SOURCE_CLOSURE_SBOM_PATH: &str =
    "distribution-evidence/windows-x64-preview-source-closure.spdx.json";
pub const PREVIEW_PUBLICATION_BUILD_ATTESTATION_PATH: &str =
    "distribution-evidence/windows-x64-preview-build.json";
pub const PREVIEW_PUBLICATION_CLEAN_HOST_RECEIPT_PATH: &str =
    "distribution-evidence/windows-x64-preview-clean-host.json";
pub const PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH: &str = "owner-distribution-approval.json";
pub const PREVIEW_PUBLICATION_PROJECTION_RECEIPT_PATH: &str = "publication-candidate-receipt.json";

/// The exact public files covered by `SHA256SUMS.txt`, in manifest order.
pub const PREVIEW_PUBLICATION_PUBLIC_ASSET_PATHS: [&str; 6] = [
    PREVIEW_PUBLICATION_MCPB_PATH,
    PREVIEW_PUBLICATION_SOURCE_ARCHIVE_PATH,
    PREVIEW_PUBLICATION_SOURCE_CLOSURE_SBOM_PATH,
    PREVIEW_PUBLICATION_BUILD_ATTESTATION_PATH,
    PREVIEW_PUBLICATION_CLEAN_HOST_RECEIPT_PATH,
    PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH,
];

const I_JSON_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

const REQUIRED_INVENTORY: [(PreviewPublicationArtifactRole, &str); 9] = [
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

/// The authenticated statement inside a canonical
/// `preview_publication_handoff` envelope.
///
/// Key admission, canonical-envelope parsing, and Ed25519 verification remain
/// caller-owned `release-qualification` policy. This type intentionally embeds
/// no production verification key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPublicationHandoff {
    schema_version: u32,
    package_mode: DistributionMode,
    source_identity: PreviewPublicationSourceIdentity,
    release_version: String,
    decision_id: String,
    inventory: Vec<PreviewPublicationFileBinding>,
}

impl PreviewPublicationHandoff {
    pub fn new(
        source_identity: PreviewPublicationSourceIdentity,
        release_version: impl Into<String>,
        decision_id: impl Into<String>,
        inventory: [PreviewPublicationFileBinding; 9],
    ) -> Result<Self, ValidationError> {
        let mut inventory = Vec::from(inventory);
        inventory.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
        let handoff = Self {
            schema_version: PREVIEW_PUBLICATION_HANDOFF_SCHEMA_VERSION,
            package_mode: DistributionMode::Preview,
            source_identity,
            release_version: release_version.into(),
            decision_id: decision_id.into(),
            inventory,
        };
        handoff.validate()?;
        Ok(handoff)
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub const fn package_mode(&self) -> DistributionMode {
        self.package_mode
    }

    pub fn source_identity(&self) -> &PreviewPublicationSourceIdentity {
        &self.source_identity
    }

    pub fn release_version(&self) -> &str {
        &self.release_version
    }

    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    pub fn inventory(&self) -> &[PreviewPublicationFileBinding] {
        &self.inventory
    }

    pub fn binding(
        &self,
        role: PreviewPublicationArtifactRole,
    ) -> Option<&PreviewPublicationFileBinding> {
        self.inventory.iter().find(|binding| binding.role == role)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != PREVIEW_PUBLICATION_HANDOFF_SCHEMA_VERSION {
            return Err(error(
                "preview_publication_schema_version_invalid",
                format!("schema_version must equal {PREVIEW_PUBLICATION_HANDOFF_SCHEMA_VERSION}"),
            ));
        }
        if self.package_mode != DistributionMode::Preview {
            return Err(error(
                "preview_publication_package_mode_invalid",
                "package_mode must equal preview",
            ));
        }
        self.source_identity.validate()?;
        if !valid_profile_version(&self.release_version, DistributionMode::Preview) {
            return Err(error(
                "preview_publication_release_version_invalid",
                "release_version must be a stable version 0.minor.patch",
            ));
        }
        require_decision_id(&self.decision_id, "decision_id")?;

        if self.inventory.len() != REQUIRED_INVENTORY.len() {
            return Err(error(
                "preview_publication_inventory_cardinality_invalid",
                "inventory must contain exactly the nine required Preview publication files",
            ));
        }
        for binding in &self.inventory {
            binding.validate()?;
        }
        if self
            .inventory
            .windows(2)
            .any(|pair| pair[0].logical_path >= pair[1].logical_path)
        {
            return Err(error(
                "preview_publication_inventory_not_sorted",
                "inventory must be strictly sorted and unique by logical_path",
            ));
        }
        for (binding, (required_role, required_path)) in
            self.inventory.iter().zip(REQUIRED_INVENTORY)
        {
            if binding.role != required_role || binding.logical_path != required_path {
                return Err(error(
                    "preview_publication_inventory_binding_invalid",
                    "inventory must exactly bind each required role to its fixed logical path",
                ));
            }
        }
        Ok(())
    }
}

impl StatementContract for PreviewPublicationHandoff {
    const KIND: &'static str = PREVIEW_PUBLICATION_HANDOFF_KIND;
    const SIGNING_DOMAIN: &'static str = PREVIEW_PUBLICATION_HANDOFF_SIGNING_DOMAIN;

    fn validate(&self) -> Result<(), &'static str> {
        PreviewPublicationHandoff::validate(self).map_err(|_| "preview_publication_handoff_invalid")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPublicationSourceIdentity {
    git_object_format: GitObjectFormat,
    git_commit_oid: String,
    git_tree_oid: String,
    source_authority_sha256: String,
}

impl PreviewPublicationSourceIdentity {
    pub fn new(
        git_object_format: GitObjectFormat,
        git_commit_oid: impl Into<String>,
        git_tree_oid: impl Into<String>,
        source_authority_sha256: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        let identity = Self {
            git_object_format,
            git_commit_oid: git_commit_oid.into(),
            git_tree_oid: git_tree_oid.into(),
            source_authority_sha256: source_authority_sha256.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub const fn git_object_format(&self) -> GitObjectFormat {
        self.git_object_format
    }

    pub fn git_commit_oid(&self) -> &str {
        &self.git_commit_oid
    }

    pub fn git_tree_oid(&self) -> &str {
        &self.git_tree_oid
    }

    pub fn source_authority_sha256(&self) -> &str {
        &self.source_authority_sha256
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
        require_sha256(
            &self.source_authority_sha256,
            "source_identity.source_authority_sha256",
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewPublicationArtifactRole {
    CurrentDistributionVerification,
    OwnerDistributionApproval,
    PreviewBuildAttestation,
    PreviewCleanHostReceipt,
    PreviewMcpb,
    PreviewSourceArchive,
    PreviewSourceClosureSbom,
    PublicationProjectionReceipt,
    Sha256Sums,
}

impl PreviewPublicationArtifactRole {
    pub const fn logical_path(self) -> &'static str {
        match self {
            Self::CurrentDistributionVerification => {
                PREVIEW_PUBLICATION_CURRENT_DISTRIBUTION_RECEIPT_PATH
            }
            Self::OwnerDistributionApproval => PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH,
            Self::PreviewBuildAttestation => PREVIEW_PUBLICATION_BUILD_ATTESTATION_PATH,
            Self::PreviewCleanHostReceipt => PREVIEW_PUBLICATION_CLEAN_HOST_RECEIPT_PATH,
            Self::PreviewMcpb => PREVIEW_PUBLICATION_MCPB_PATH,
            Self::PreviewSourceArchive => PREVIEW_PUBLICATION_SOURCE_ARCHIVE_PATH,
            Self::PreviewSourceClosureSbom => PREVIEW_PUBLICATION_SOURCE_CLOSURE_SBOM_PATH,
            Self::PublicationProjectionReceipt => PREVIEW_PUBLICATION_PROJECTION_RECEIPT_PATH,
            Self::Sha256Sums => PREVIEW_PUBLICATION_SHA256SUMS_PATH,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPublicationFileBinding {
    role: PreviewPublicationArtifactRole,
    logical_path: String,
    sha256: String,
    size_bytes: u64,
}

impl PreviewPublicationFileBinding {
    pub fn new(
        role: PreviewPublicationArtifactRole,
        sha256: impl Into<String>,
        size_bytes: u64,
    ) -> Result<Self, ValidationError> {
        let binding = Self {
            role,
            logical_path: role.logical_path().to_owned(),
            sha256: sha256.into(),
            size_bytes,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub const fn role(&self) -> PreviewPublicationArtifactRole {
        self.role
    }

    pub fn logical_path(&self) -> &str {
        &self.logical_path
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    fn validate(&self) -> Result<(), ValidationError> {
        require_safe_logical_path(&self.logical_path, "inventory.logical_path")?;
        require_sha256(&self.sha256, "inventory.sha256")?;
        if self.size_bytes == 0 || self.size_bytes > I_JSON_MAX_SAFE_INTEGER {
            return Err(error(
                "preview_publication_file_size_invalid",
                "inventory.size_bytes must be within the positive I-JSON safe-integer range",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use release_qualification::{
        parse_and_verify, sign_canonical, KeyRing, KeyState, PinnedKey, SigningKey,
    };
    use serde_json::{json, Value};

    fn hash(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn valid_value() -> Value {
        json!({
            "schema_version": PREVIEW_PUBLICATION_HANDOFF_SCHEMA_VERSION,
            "package_mode": "preview",
            "source_identity": {
                "git_object_format": "sha1",
                "git_commit_oid": "a".repeat(40),
                "git_tree_oid": "b".repeat(40),
                "source_authority_sha256": hash('c')
            },
            "release_version": "0.0.1",
            "decision_id": "ODA-2026-0001",
            "inventory": [
                {
                    "role": "sha256_sums",
                    "logical_path": PREVIEW_PUBLICATION_SHA256SUMS_PATH,
                    "sha256": hash('1'),
                    "size_bytes": 1
                },
                {
                    "role": "preview_source_archive",
                    "logical_path": PREVIEW_PUBLICATION_SOURCE_ARCHIVE_PATH,
                    "sha256": hash('2'),
                    "size_bytes": 2
                },
                {
                    "role": "preview_mcpb",
                    "logical_path": PREVIEW_PUBLICATION_MCPB_PATH,
                    "sha256": hash('3'),
                    "size_bytes": 3
                },
                {
                    "role": "current_distribution_verification",
                    "logical_path": PREVIEW_PUBLICATION_CURRENT_DISTRIBUTION_RECEIPT_PATH,
                    "sha256": hash('4'),
                    "size_bytes": 4
                },
                {
                    "role": "preview_build_attestation",
                    "logical_path": PREVIEW_PUBLICATION_BUILD_ATTESTATION_PATH,
                    "sha256": hash('5'),
                    "size_bytes": 5
                },
                {
                    "role": "preview_clean_host_receipt",
                    "logical_path": PREVIEW_PUBLICATION_CLEAN_HOST_RECEIPT_PATH,
                    "sha256": hash('6'),
                    "size_bytes": 6
                },
                {
                    "role": "preview_source_closure_sbom",
                    "logical_path": PREVIEW_PUBLICATION_SOURCE_CLOSURE_SBOM_PATH,
                    "sha256": hash('7'),
                    "size_bytes": 7
                },
                {
                    "role": "owner_distribution_approval",
                    "logical_path": PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH,
                    "sha256": hash('8'),
                    "size_bytes": 8
                },
                {
                    "role": "publication_projection_receipt",
                    "logical_path": PREVIEW_PUBLICATION_PROJECTION_RECEIPT_PATH,
                    "sha256": hash('9'),
                    "size_bytes": 9
                }
            ]
        })
    }

    fn valid_handoff() -> PreviewPublicationHandoff {
        serde_json::from_value(valid_value()).unwrap()
    }

    #[test]
    fn validated_constructors_fix_paths_sort_bindings_and_close_the_statement() {
        let source_identity = PreviewPublicationSourceIdentity::new(
            GitObjectFormat::Sha1,
            "a".repeat(40),
            "b".repeat(40),
            hash('c'),
        )
        .unwrap();
        let mut bindings = std::array::from_fn(|index| {
            PreviewPublicationFileBinding::new(
                REQUIRED_INVENTORY[index].0,
                format!("{:064x}", index + 1),
                u64::try_from(index + 1).unwrap(),
            )
            .unwrap()
        });
        bindings.reverse();
        let handoff =
            PreviewPublicationHandoff::new(source_identity, "0.0.1", "ODA-2026-0001", bindings)
                .unwrap();
        assert!(handoff
            .inventory()
            .windows(2)
            .all(|pair| pair[0].logical_path() < pair[1].logical_path()));
        for binding in handoff.inventory() {
            assert_eq!(binding.logical_path(), binding.role().logical_path());
        }

        assert!(PreviewPublicationSourceIdentity::new(
            GitObjectFormat::Sha1,
            "a".repeat(64),
            "b".repeat(40),
            hash('c'),
        )
        .is_err());
        assert!(PreviewPublicationSourceIdentity::new(
            GitObjectFormat::Sha1,
            "a".repeat(40),
            "b".repeat(40),
            "C".repeat(64),
        )
        .is_err());
        assert!(PreviewPublicationFileBinding::new(
            PreviewPublicationArtifactRole::PreviewMcpb,
            "A".repeat(64),
            1,
        )
        .is_err());
        assert!(PreviewPublicationFileBinding::new(
            PreviewPublicationArtifactRole::PreviewMcpb,
            hash('a'),
            0,
        )
        .is_err());
    }

    #[test]
    fn valid_statement_exposes_exact_closed_bindings() {
        let handoff = valid_handoff();
        handoff.validate().unwrap();
        assert_eq!(handoff.schema_version(), 2);
        assert_eq!(handoff.package_mode(), DistributionMode::Preview);
        assert_eq!(handoff.release_version(), "0.0.1");
        assert_eq!(handoff.decision_id(), "ODA-2026-0001");
        assert_eq!(
            handoff.source_identity().git_object_format(),
            GitObjectFormat::Sha1
        );
        assert_eq!(handoff.source_identity().git_commit_oid(), "a".repeat(40));
        assert_eq!(handoff.source_identity().git_tree_oid(), "b".repeat(40));
        assert_eq!(
            handoff.source_identity().source_authority_sha256(),
            hash('c')
        );
        assert_eq!(handoff.inventory().len(), 9);
        assert_eq!(
            PREVIEW_PUBLICATION_PUBLIC_ASSET_PATHS,
            [
                PREVIEW_PUBLICATION_MCPB_PATH,
                PREVIEW_PUBLICATION_SOURCE_ARCHIVE_PATH,
                PREVIEW_PUBLICATION_SOURCE_CLOSURE_SBOM_PATH,
                PREVIEW_PUBLICATION_BUILD_ATTESTATION_PATH,
                PREVIEW_PUBLICATION_CLEAN_HOST_RECEIPT_PATH,
                PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH,
            ]
        );
        let approval = handoff
            .binding(PreviewPublicationArtifactRole::OwnerDistributionApproval)
            .unwrap();
        assert_eq!(
            approval.logical_path(),
            PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH
        );
        assert_eq!(approval.role().logical_path(), approval.logical_path());
        assert_eq!(approval.sha256(), hash('8'));
        assert_eq!(approval.size_bytes(), 8);
    }

    #[test]
    fn statement_contract_uses_the_closed_kind_and_signing_domain() {
        assert_eq!(
            <PreviewPublicationHandoff as StatementContract>::KIND,
            "preview_publication_handoff"
        );
        assert_eq!(
            <PreviewPublicationHandoff as StatementContract>::SIGNING_DOMAIN,
            "autocad-mcp.release/preview-publication-handoff/v2"
        );
        StatementContract::validate(&valid_handoff()).unwrap();
    }

    #[test]
    fn synthetic_key_signs_and_external_trust_policy_verifies_the_envelope() {
        let signing_key = SigningKey::from_bytes(&[23; 32]);
        let pinned = PinnedKey::new(
            "preview-publication-test-key",
            PREVIEW_PUBLICATION_HANDOFF_KIND,
            signing_key.verifying_key().to_bytes(),
            KeyState::Active,
        )
        .unwrap();
        let canonical = sign_canonical(&valid_handoff(), &pinned, &signing_key).unwrap();
        let key_ring = KeyRing::new(vec![pinned]).unwrap();
        let verified =
            parse_and_verify::<PreviewPublicationHandoff>(&canonical, &key_ring).unwrap();
        assert_eq!(verified.key_id(), "preview-publication-test-key");
        assert_eq!(verified.statement(), &valid_handoff());
        assert_eq!(verified.canonical_envelope(), canonical);
    }

    #[test]
    fn semantic_validation_rejects_mode_version_identity_and_decision_drift() {
        let mutations = [
            ("/schema_version", json!(1)),
            ("/package_mode", json!("release")),
            ("/release_version", json!("1.0.0")),
            ("/decision_id", json!("not-an-owner-decision")),
            ("/source_identity/git_commit_oid", json!("a".repeat(64))),
            ("/source_identity/git_tree_oid", json!("B".repeat(40))),
            (
                "/source_identity/source_authority_sha256",
                json!("C".repeat(64)),
            ),
        ];
        for (pointer, replacement) in mutations {
            let mut value = valid_value();
            *value.pointer_mut(pointer).unwrap() = replacement;
            let handoff: PreviewPublicationHandoff = serde_json::from_value(value).unwrap();
            assert!(
                handoff.validate().is_err(),
                "mutation at {pointer} must fail"
            );
        }
    }

    #[test]
    fn semantic_validation_rejects_open_unsorted_or_malformed_inventory() {
        let mut missing = valid_value();
        missing["inventory"].as_array_mut().unwrap().pop();
        let missing: PreviewPublicationHandoff = serde_json::from_value(missing).unwrap();
        assert_eq!(
            missing.validate().unwrap_err().code(),
            "preview_publication_inventory_cardinality_invalid"
        );

        let mut reordered = valid_value();
        reordered["inventory"].as_array_mut().unwrap().swap(0, 1);
        let reordered: PreviewPublicationHandoff = serde_json::from_value(reordered).unwrap();
        assert_eq!(
            reordered.validate().unwrap_err().code(),
            "preview_publication_inventory_not_sorted"
        );

        let mut wrong_role = valid_value();
        wrong_role["inventory"][0]["role"] = json!("preview_mcpb");
        let wrong_role: PreviewPublicationHandoff = serde_json::from_value(wrong_role).unwrap();
        assert_eq!(
            wrong_role.validate().unwrap_err().code(),
            "preview_publication_inventory_binding_invalid"
        );

        let mut unsafe_path = valid_value();
        unsafe_path["inventory"][0]["logical_path"] = json!("../preview.mcpb");
        let unsafe_path: PreviewPublicationHandoff = serde_json::from_value(unsafe_path).unwrap();
        assert_eq!(
            unsafe_path.validate().unwrap_err().code(),
            "logical_path_unsafe"
        );

        let mut uppercase_hash = valid_value();
        uppercase_hash["inventory"][0]["sha256"] = json!("A".repeat(64));
        let uppercase_hash: PreviewPublicationHandoff =
            serde_json::from_value(uppercase_hash).unwrap();
        assert_eq!(
            uppercase_hash.validate().unwrap_err().code(),
            "lowercase_hex_invalid"
        );

        let mut empty_file = valid_value();
        empty_file["inventory"][0]["size_bytes"] = json!(0);
        let empty_file: PreviewPublicationHandoff = serde_json::from_value(empty_file).unwrap();
        assert_eq!(
            empty_file.validate().unwrap_err().code(),
            "preview_publication_file_size_invalid"
        );
    }

    #[test]
    fn serde_and_schema_are_closed_over_the_statement_shape() {
        let mut unknown = valid_value();
        unknown["unexpected"] = json!(true);
        assert!(serde_json::from_value::<PreviewPublicationHandoff>(unknown).is_err());

        let mut missing_source_authority = valid_value();
        missing_source_authority["source_identity"]
            .as_object_mut()
            .unwrap()
            .remove("source_authority_sha256");
        assert!(serde_json::from_value::<PreviewPublicationHandoff>(
            missing_source_authority.clone()
        )
        .is_err());

        let schema: Value = serde_json::from_str(include_str!(
            "../schemas/preview-publication-handoff.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let valid = valid_value();
        assert!(validator.is_valid(&valid));
        assert!(!validator.is_valid(&missing_source_authority));

        let mut invalid_source_authority = valid.clone();
        invalid_source_authority["source_identity"]["source_authority_sha256"] =
            json!("C".repeat(64));
        assert!(!validator.is_valid(&invalid_source_authority));

        let mut wrong_path = valid.clone();
        wrong_path["inventory"][0]["logical_path"] = json!("preview.mcpb");
        assert!(!validator.is_valid(&wrong_path));

        let mut wrong_order = valid;
        wrong_order["inventory"].as_array_mut().unwrap().swap(0, 1);
        assert!(!validator.is_valid(&wrong_order));
    }
}
