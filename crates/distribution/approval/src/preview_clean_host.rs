use super::{
    error, parse_strict_json, require_sha256, require_utc_timestamp, DistributionMode,
    ValidationError,
};
use serde::{Deserialize, Serialize};

pub const PREVIEW_CLEAN_HOST_SCHEMA_VERSION: u32 = 2;
pub const PREVIEW_CLEAN_HOST_KIND: &str = "claude_desktop_clean_host_acceptance";
pub const PREVIEW_CLEAN_HOST_RESULT: &str = "accepted";
pub const PREVIEW_CLEAN_HOST_TARGET: &str = "x86_64-pc-windows-msvc";
pub const PREVIEW_CLEAN_HOST_RECEIPT_PATH: &str =
    "distribution-evidence/windows-x64-preview-clean-host.json";
pub const PREVIEW_CLEAN_HOST_SCHEMA_PATH: &str =
    "crates/distribution/approval/schemas/preview-clean-host-receipt.schema.json";

// These path-free identifiers bind the paired public Tier 1 ACadSharp fixtures.
// Their byte identities come from the tracked repository fixture ledger.
pub const PREVIEW_CLEAN_HOST_DXF_FIXTURE_ID: &str = "tier1_acadsharp_blockvisibilityparameter_dxf";
pub const PREVIEW_CLEAN_HOST_DXF_FIXTURE_SHA256: &str =
    "c615664945db8ccc91b55f77e6359a15da4f7e6f30dbd8800d2d2b94029dffac";
pub const PREVIEW_CLEAN_HOST_DWG_FIXTURE_ID: &str = "tier1_acadsharp_blockvisibilityparameter_dwg";
pub const PREVIEW_CLEAN_HOST_DWG_FIXTURE_SHA256: &str =
    "be1e24ea0cd5194d0c57935b5018123b7cc981331172a1a2ca7cecc2d9a18e4f";
pub const PREVIEW_CLEAN_HOST_TITLE_BLOCK_FIXTURE_ID: &str =
    "disposable_profiled_ac1032_title_block_v1";
pub const PREVIEW_CLEAN_HOST_TITLE_BLOCK_PROFILE_ID: &str = "AUTOCAD_MCP_GENERIC";
pub const PREVIEW_CLEAN_HOST_TITLE_BLOCK_BACKEND: &str = "acadrust_preview";
pub const PREVIEW_CLEAN_HOST_TITLE_BLOCK_SENTINEL_JSON: &str = r#"{"alternative_reference":"CLEAN-HOST","drawing_number":"ACMCP-PREVIEW-0001","drawing_title_big":"PREVIEW CLEAN HOST","drawing_title_med":"TITLE BLOCK ACCEPTANCE","revision":"P01","sheet":"1","sheet_total":"1"}"#;
pub const PREVIEW_CLEAN_HOST_TITLE_BLOCK_SENTINEL_SHA256: &str =
    "e47219de2c6218badf4dbf6d53a38e4bbb96a71a6ee1d8d1676485be7802ffc2";

pub const PREVIEW_CLEAN_HOST_OBSERVED_TOOL_COUNT: u32 = 51;

const REQUIRED_CHECKS: &[PreviewCleanHostCheck] = &[
    PreviewCleanHostCheck::CleanProfile,
    PreviewCleanHostCheck::PreInstallAbsent,
    PreviewCleanHostCheck::Install,
    PreviewCleanHostCheck::EnabledConnected,
    PreviewCleanHostCheck::ToolDiscovery,
    PreviewCleanHostCheck::DxfRead,
    PreviewCleanHostCheck::DwgRead,
    PreviewCleanHostCheck::TitleBlockPreviewWrite,
    PreviewCleanHostCheck::TitleBlockPreviewReread,
    PreviewCleanHostCheck::ShutdownNoProcess,
    PreviewCleanHostCheck::RestartReconnect,
    PreviewCleanHostCheck::Uninstall,
    PreviewCleanHostCheck::PostUninstallAbsent,
];

const REQUIRED_LIMITATIONS: &[PreviewCleanHostLimitation] = &[
    PreviewCleanHostLimitation::PreviewEvidenceOnly,
    PreviewCleanHostLimitation::NotReleaseCertification,
    PreviewCleanHostLimitation::NotSigningEvidence,
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewCleanHostReceiptKind {
    ClaudeDesktopCleanHostAcceptance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewCleanHostResult {
    Accepted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewCleanHostClientProduct {
    ClaudeDesktop,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewCleanHostOperatingSystem {
    Windows,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewCleanHostArchitecture {
    X86_64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewCleanHostCheck {
    CleanProfile,
    PreInstallAbsent,
    Install,
    EnabledConnected,
    ToolDiscovery,
    DxfRead,
    DwgRead,
    TitleBlockPreviewWrite,
    TitleBlockPreviewReread,
    ShutdownNoProcess,
    RestartReconnect,
    Uninstall,
    PostUninstallAbsent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewCleanHostLimitation {
    PreviewEvidenceOnly,
    NotReleaseCertification,
    NotSigningEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewCleanHostPackage {
    mode: DistributionMode,
    target_triple: String,
    mcpb_sha256: String,
    mcpb_size_bytes: u64,
    mcp_server_sha256: String,
    autolisp_lsp_sha256: String,
}

impl PreviewCleanHostPackage {
    pub fn mode(&self) -> DistributionMode {
        self.mode
    }

    pub fn target_triple(&self) -> &str {
        &self.target_triple
    }

    pub fn mcpb_sha256(&self) -> &str {
        &self.mcpb_sha256
    }

    pub fn mcpb_size_bytes(&self) -> u64 {
        self.mcpb_size_bytes
    }

    pub fn mcp_server_sha256(&self) -> &str {
        &self.mcp_server_sha256
    }

    pub fn autolisp_lsp_sha256(&self) -> &str {
        &self.autolisp_lsp_sha256
    }

    fn validate(&self) -> Result<(), ValidationError> {
        if self.mode != DistributionMode::Preview {
            return Err(error(
                "preview_clean_host_package_mode_invalid",
                "package.mode must equal preview",
            ));
        }
        if self.target_triple != PREVIEW_CLEAN_HOST_TARGET {
            return Err(error(
                "preview_clean_host_target_invalid",
                format!("package.target_triple must equal {PREVIEW_CLEAN_HOST_TARGET}"),
            ));
        }
        require_sha256(&self.mcpb_sha256, "package.mcpb_sha256")?;
        if self.mcpb_size_bytes == 0 {
            return Err(error(
                "preview_clean_host_mcpb_size_invalid",
                "package.mcpb_size_bytes must be greater than zero",
            ));
        }
        require_sha256(&self.mcp_server_sha256, "package.mcp_server_sha256")?;
        require_sha256(&self.autolisp_lsp_sha256, "package.autolisp_lsp_sha256")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewCleanHostClient {
    product: PreviewCleanHostClientProduct,
    version: String,
}

impl PreviewCleanHostClient {
    pub fn product(&self) -> PreviewCleanHostClientProduct {
        self.product
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    fn validate(&self) -> Result<(), ValidationError> {
        if self.product != PreviewCleanHostClientProduct::ClaudeDesktop {
            return Err(error(
                "preview_clean_host_client_product_invalid",
                "client.product must equal claude_desktop",
            ));
        }
        require_concrete_version(&self.version, "client.version")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewCleanHostHost {
    operating_system: PreviewCleanHostOperatingSystem,
    architecture: PreviewCleanHostArchitecture,
    os_version: String,
}

impl PreviewCleanHostHost {
    pub fn operating_system(&self) -> PreviewCleanHostOperatingSystem {
        self.operating_system
    }

    pub fn architecture(&self) -> PreviewCleanHostArchitecture {
        self.architecture
    }

    pub fn os_version(&self) -> &str {
        &self.os_version
    }

    fn validate(&self) -> Result<(), ValidationError> {
        if self.operating_system != PreviewCleanHostOperatingSystem::Windows {
            return Err(error(
                "preview_clean_host_operating_system_invalid",
                "host.operating_system must equal windows",
            ));
        }
        if self.architecture != PreviewCleanHostArchitecture::X86_64 {
            return Err(error(
                "preview_clean_host_architecture_invalid",
                "host.architecture must equal x86_64",
            ));
        }
        require_concrete_version(&self.os_version, "host.os_version")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewCleanHostFixture {
    fixture_id: String,
    sha256: String,
}

impl PreviewCleanHostFixture {
    pub fn fixture_id(&self) -> &str {
        &self.fixture_id
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    fn validate(
        &self,
        expected_id: &str,
        expected_sha256: &str,
        label: &str,
    ) -> Result<(), ValidationError> {
        if self.fixture_id != expected_id || self.sha256 != expected_sha256 {
            return Err(error(
                "preview_clean_host_fixture_invalid",
                format!("{label} must bind fixture_id {expected_id} and SHA-256 {expected_sha256}"),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewCleanHostFixtures {
    dxf: PreviewCleanHostFixture,
    dwg: PreviewCleanHostFixture,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewCleanHostTitleBlockMutation {
    fixture_id: String,
    profile_id: String,
    backend: String,
    source_sha256: String,
    installed_sha256: String,
    sentinel_sha256: String,
}

impl PreviewCleanHostTitleBlockMutation {
    pub fn fixture_id(&self) -> &str {
        &self.fixture_id
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn backend(&self) -> &str {
        &self.backend
    }

    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    pub fn installed_sha256(&self) -> &str {
        &self.installed_sha256
    }

    pub fn sentinel_sha256(&self) -> &str {
        &self.sentinel_sha256
    }

    fn validate(&self) -> Result<(), ValidationError> {
        if self.fixture_id != PREVIEW_CLEAN_HOST_TITLE_BLOCK_FIXTURE_ID
            || self.profile_id != PREVIEW_CLEAN_HOST_TITLE_BLOCK_PROFILE_ID
            || self.backend != PREVIEW_CLEAN_HOST_TITLE_BLOCK_BACKEND
        {
            return Err(error(
                "preview_clean_host_title_block_identity_invalid",
                "title_block_mutation must bind the closed fixture, profile, and Preview backend",
            ));
        }
        require_sha256(&self.source_sha256, "title_block_mutation.source_sha256")?;
        require_sha256(
            &self.installed_sha256,
            "title_block_mutation.installed_sha256",
        )?;
        require_sha256(
            &self.sentinel_sha256,
            "title_block_mutation.sentinel_sha256",
        )?;
        if self.sentinel_sha256 != PREVIEW_CLEAN_HOST_TITLE_BLOCK_SENTINEL_SHA256 {
            return Err(error(
                "preview_clean_host_title_block_sentinel_invalid",
                "title_block_mutation.sentinel_sha256 must bind the closed post-write field set",
            ));
        }
        if self.source_sha256 == self.installed_sha256 {
            return Err(error(
                "preview_clean_host_title_block_digest_unchanged",
                "title-block mutation must change the disposable fixture digest",
            ));
        }
        Ok(())
    }
}

impl PreviewCleanHostFixtures {
    pub fn dxf(&self) -> &PreviewCleanHostFixture {
        &self.dxf
    }

    pub fn dwg(&self) -> &PreviewCleanHostFixture {
        &self.dwg
    }

    fn validate(&self) -> Result<(), ValidationError> {
        self.dxf.validate(
            PREVIEW_CLEAN_HOST_DXF_FIXTURE_ID,
            PREVIEW_CLEAN_HOST_DXF_FIXTURE_SHA256,
            "fixtures.dxf",
        )?;
        self.dwg.validate(
            PREVIEW_CLEAN_HOST_DWG_FIXTURE_ID,
            PREVIEW_CLEAN_HOST_DWG_FIXTURE_SHA256,
            "fixtures.dwg",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewCleanHostReceipt {
    schema_version: u32,
    kind: PreviewCleanHostReceiptKind,
    result: PreviewCleanHostResult,
    package: PreviewCleanHostPackage,
    client: PreviewCleanHostClient,
    host: PreviewCleanHostHost,
    fixtures: PreviewCleanHostFixtures,
    title_block_mutation: PreviewCleanHostTitleBlockMutation,
    observed_tool_count: u32,
    passed_checks: Vec<PreviewCleanHostCheck>,
    completed_utc: String,
    limitations: Vec<PreviewCleanHostLimitation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewCleanHostReceiptInput {
    pub mcpb_sha256: String,
    pub mcpb_size_bytes: u64,
    pub mcp_server_sha256: String,
    pub autolisp_lsp_sha256: String,
    pub client_version: String,
    pub host_os_version: String,
    pub title_block_source_sha256: String,
    pub title_block_installed_sha256: String,
    pub title_block_sentinel_sha256: String,
    pub completed_utc: String,
}

impl PreviewCleanHostReceipt {
    pub fn new(input: PreviewCleanHostReceiptInput) -> Result<Self, ValidationError> {
        let receipt = Self {
            schema_version: PREVIEW_CLEAN_HOST_SCHEMA_VERSION,
            kind: PreviewCleanHostReceiptKind::ClaudeDesktopCleanHostAcceptance,
            result: PreviewCleanHostResult::Accepted,
            package: PreviewCleanHostPackage {
                mode: DistributionMode::Preview,
                target_triple: PREVIEW_CLEAN_HOST_TARGET.to_owned(),
                mcpb_sha256: input.mcpb_sha256,
                mcpb_size_bytes: input.mcpb_size_bytes,
                mcp_server_sha256: input.mcp_server_sha256,
                autolisp_lsp_sha256: input.autolisp_lsp_sha256,
            },
            client: PreviewCleanHostClient {
                product: PreviewCleanHostClientProduct::ClaudeDesktop,
                version: input.client_version,
            },
            host: PreviewCleanHostHost {
                operating_system: PreviewCleanHostOperatingSystem::Windows,
                architecture: PreviewCleanHostArchitecture::X86_64,
                os_version: input.host_os_version,
            },
            fixtures: PreviewCleanHostFixtures {
                dxf: PreviewCleanHostFixture {
                    fixture_id: PREVIEW_CLEAN_HOST_DXF_FIXTURE_ID.to_owned(),
                    sha256: PREVIEW_CLEAN_HOST_DXF_FIXTURE_SHA256.to_owned(),
                },
                dwg: PreviewCleanHostFixture {
                    fixture_id: PREVIEW_CLEAN_HOST_DWG_FIXTURE_ID.to_owned(),
                    sha256: PREVIEW_CLEAN_HOST_DWG_FIXTURE_SHA256.to_owned(),
                },
            },
            title_block_mutation: PreviewCleanHostTitleBlockMutation {
                fixture_id: PREVIEW_CLEAN_HOST_TITLE_BLOCK_FIXTURE_ID.to_owned(),
                profile_id: PREVIEW_CLEAN_HOST_TITLE_BLOCK_PROFILE_ID.to_owned(),
                backend: PREVIEW_CLEAN_HOST_TITLE_BLOCK_BACKEND.to_owned(),
                source_sha256: input.title_block_source_sha256,
                installed_sha256: input.title_block_installed_sha256,
                sentinel_sha256: input.title_block_sentinel_sha256,
            },
            observed_tool_count: PREVIEW_CLEAN_HOST_OBSERVED_TOOL_COUNT,
            passed_checks: REQUIRED_CHECKS.to_vec(),
            completed_utc: input.completed_utc,
            limitations: REQUIRED_LIMITATIONS.to_vec(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn kind(&self) -> PreviewCleanHostReceiptKind {
        self.kind
    }

    pub fn result(&self) -> PreviewCleanHostResult {
        self.result
    }

    pub fn package(&self) -> &PreviewCleanHostPackage {
        &self.package
    }

    pub fn client(&self) -> &PreviewCleanHostClient {
        &self.client
    }

    pub fn host(&self) -> &PreviewCleanHostHost {
        &self.host
    }

    pub fn fixtures(&self) -> &PreviewCleanHostFixtures {
        &self.fixtures
    }

    pub fn title_block_mutation(&self) -> &PreviewCleanHostTitleBlockMutation {
        &self.title_block_mutation
    }

    pub fn observed_tool_count(&self) -> u32 {
        self.observed_tool_count
    }

    pub fn passed_checks(&self) -> &[PreviewCleanHostCheck] {
        &self.passed_checks
    }

    pub fn completed_utc(&self) -> &str {
        &self.completed_utc
    }

    pub fn limitations(&self) -> &[PreviewCleanHostLimitation] {
        &self.limitations
    }

    pub fn to_pretty_json(&self) -> Result<Vec<u8>, ValidationError> {
        self.validate()?;
        let mut rendered = serde_json::to_vec_pretty(self).map_err(|serialize_error| {
            error(
                "preview_clean_host_serialization_failed",
                format!("could not serialize Preview clean-host receipt: {serialize_error}"),
            )
        })?;
        rendered.push(b'\n');
        Ok(rendered)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != PREVIEW_CLEAN_HOST_SCHEMA_VERSION {
            return Err(error(
                "preview_clean_host_schema_version_invalid",
                format!("schema_version must equal {PREVIEW_CLEAN_HOST_SCHEMA_VERSION}"),
            ));
        }
        if self.kind != PreviewCleanHostReceiptKind::ClaudeDesktopCleanHostAcceptance {
            return Err(error(
                "preview_clean_host_kind_invalid",
                format!("kind must equal {PREVIEW_CLEAN_HOST_KIND}"),
            ));
        }
        if self.result != PreviewCleanHostResult::Accepted {
            return Err(error(
                "preview_clean_host_result_invalid",
                format!("result must equal {PREVIEW_CLEAN_HOST_RESULT}"),
            ));
        }
        self.package.validate()?;
        self.client.validate()?;
        self.host.validate()?;
        self.fixtures.validate()?;
        self.title_block_mutation.validate()?;
        if self.observed_tool_count != PREVIEW_CLEAN_HOST_OBSERVED_TOOL_COUNT {
            return Err(error(
                "preview_clean_host_tool_count_invalid",
                format!("observed_tool_count must equal {PREVIEW_CLEAN_HOST_OBSERVED_TOOL_COUNT}"),
            ));
        }
        if self.passed_checks.as_slice() != REQUIRED_CHECKS {
            return Err(error(
                "preview_clean_host_checks_invalid",
                "passed_checks must equal the closed ordered clean-host checklist",
            ));
        }
        require_utc_timestamp(&self.completed_utc, "completed_utc")?;
        if self.limitations.as_slice() != REQUIRED_LIMITATIONS {
            return Err(error(
                "preview_clean_host_limitations_invalid",
                "limitations must equal the closed ordered Preview-only limitation set",
            ));
        }
        Ok(())
    }
}

/// Parse and validate one complete privacy-safe Preview clean-host receipt.
///
/// Duplicate keys at any nesting level, trailing JSON values, unknown fields,
/// and any drift from the closed acceptance contract are rejected.
pub fn parse_preview_clean_host_receipt(
    bytes: &[u8],
) -> Result<PreviewCleanHostReceipt, ValidationError> {
    let strict = parse_strict_json(bytes).map_err(|parse_error| {
        let code = if parse_error.code() == release_qualification::ErrorCode::JsonTrailingData {
            "preview_clean_host_json_trailing_data"
        } else {
            "preview_clean_host_json_invalid"
        };
        error(code, format!("strict JSON parse failed: {parse_error}"))
    })?;
    let receipt: PreviewCleanHostReceipt =
        serde_json::from_value(strict).map_err(|parse_error| {
            error(
                "preview_clean_host_schema_invalid",
                format!(
                    "Preview clean-host receipt does not match the closed schema: {parse_error}"
                ),
            )
        })?;
    receipt.validate()?;
    Ok(receipt)
}

fn require_concrete_version(value: &str, label: &str) -> Result<(), ValidationError> {
    let components = value.split('.').collect::<Vec<_>>();
    if !(3..=4).contains(&components.len())
        || components.iter().any(|component| {
            component.is_empty()
                || component.len() > 10
                || !component.bytes().all(|byte| byte.is_ascii_digit())
                || (component.len() > 1 && component.starts_with('0'))
        })
    {
        return Err(error(
            "preview_clean_host_version_invalid",
            format!("{label} must be a concrete three- or four-component dotted numeric version"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    fn hash(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn valid_value() -> Value {
        json!({
            "schema_version": PREVIEW_CLEAN_HOST_SCHEMA_VERSION,
            "kind": PREVIEW_CLEAN_HOST_KIND,
            "result": PREVIEW_CLEAN_HOST_RESULT,
            "package": {
                "mode": "preview",
                "target_triple": PREVIEW_CLEAN_HOST_TARGET,
                "mcpb_sha256": hash('a'),
                "mcpb_size_bytes": 42,
                "mcp_server_sha256": hash('b'),
                "autolisp_lsp_sha256": hash('c')
            },
            "client": {
                "product": "claude_desktop",
                "version": "0.13.78"
            },
            "host": {
                "operating_system": "windows",
                "architecture": "x86_64",
                "os_version": "10.0.26100.4652"
            },
            "fixtures": {
                "dxf": {
                    "fixture_id": PREVIEW_CLEAN_HOST_DXF_FIXTURE_ID,
                    "sha256": PREVIEW_CLEAN_HOST_DXF_FIXTURE_SHA256
                },
                "dwg": {
                    "fixture_id": PREVIEW_CLEAN_HOST_DWG_FIXTURE_ID,
                    "sha256": PREVIEW_CLEAN_HOST_DWG_FIXTURE_SHA256
                }
            },
            "title_block_mutation": {
                "fixture_id": PREVIEW_CLEAN_HOST_TITLE_BLOCK_FIXTURE_ID,
                "profile_id": PREVIEW_CLEAN_HOST_TITLE_BLOCK_PROFILE_ID,
                "backend": PREVIEW_CLEAN_HOST_TITLE_BLOCK_BACKEND,
                "source_sha256": hash('d'),
                "installed_sha256": hash('e'),
                "sentinel_sha256": PREVIEW_CLEAN_HOST_TITLE_BLOCK_SENTINEL_SHA256
            },
            "observed_tool_count": PREVIEW_CLEAN_HOST_OBSERVED_TOOL_COUNT,
            "passed_checks": [
                "clean_profile",
                "pre_install_absent",
                "install",
                "enabled_connected",
                "tool_discovery",
                "dxf_read",
                "dwg_read",
                "title_block_preview_write",
                "title_block_preview_reread",
                "shutdown_no_process",
                "restart_reconnect",
                "uninstall",
                "post_uninstall_absent"
            ],
            "completed_utc": "2026-07-28T12:34:56Z",
            "limitations": [
                "preview_evidence_only",
                "not_release_certification",
                "not_signing_evidence"
            ]
        })
    }

    #[test]
    fn title_block_sentinel_digest_binds_the_exact_canonical_field_set() {
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(PREVIEW_CLEAN_HOST_TITLE_BLOCK_SENTINEL_JSON.as_bytes())
            ),
            PREVIEW_CLEAN_HOST_TITLE_BLOCK_SENTINEL_SHA256
        );
    }

    fn parse_value(value: &Value) -> Result<PreviewCleanHostReceipt, ValidationError> {
        parse_preview_clean_host_receipt(&serde_json::to_vec(value).unwrap())
    }

    fn receipt_input(mcpb_size_bytes: u64) -> PreviewCleanHostReceiptInput {
        PreviewCleanHostReceiptInput {
            mcpb_sha256: hash('a'),
            mcpb_size_bytes,
            mcp_server_sha256: hash('b'),
            autolisp_lsp_sha256: hash('c'),
            client_version: "0.13.78".to_string(),
            host_os_version: "10.0.26100.4652".to_string(),
            title_block_source_sha256: hash('d'),
            title_block_installed_sha256: hash('e'),
            title_block_sentinel_sha256: PREVIEW_CLEAN_HOST_TITLE_BLOCK_SENTINEL_SHA256.to_string(),
            completed_utc: "2026-07-28T12:34:56Z".to_string(),
        }
    }

    #[test]
    fn valid_receipt_preserves_exact_candidate_and_host_bindings() {
        let receipt = parse_value(&valid_value()).unwrap();
        assert_eq!(receipt.schema_version(), PREVIEW_CLEAN_HOST_SCHEMA_VERSION);
        assert_eq!(receipt.package().mode(), DistributionMode::Preview);
        assert_eq!(receipt.package().target_triple(), PREVIEW_CLEAN_HOST_TARGET);
        assert_eq!(receipt.package().mcpb_size_bytes(), 42);
        assert_eq!(
            receipt.fixtures().dxf().sha256(),
            PREVIEW_CLEAN_HOST_DXF_FIXTURE_SHA256
        );
        assert_eq!(
            receipt.fixtures().dwg().sha256(),
            PREVIEW_CLEAN_HOST_DWG_FIXTURE_SHA256
        );
        assert_eq!(receipt.title_block_mutation().installed_sha256(), hash('e'));
        assert_eq!(
            receipt.observed_tool_count(),
            PREVIEW_CLEAN_HOST_OBSERVED_TOOL_COUNT
        );
        assert_eq!(receipt.passed_checks(), REQUIRED_CHECKS);
    }

    #[test]
    fn constructor_and_pretty_serializer_are_closed_and_deterministic() {
        let receipt = PreviewCleanHostReceipt::new(receipt_input(42)).unwrap();
        let first = receipt.to_pretty_json().unwrap();
        let second = receipt.to_pretty_json().unwrap();
        assert_eq!(first, second);
        assert!(first.ends_with(b"\n"));
        assert_eq!(parse_preview_clean_host_receipt(&first).unwrap(), receipt);
        assert_eq!(
            serde_json::from_slice::<Value>(&first).unwrap(),
            valid_value()
        );

        assert_eq!(
            PreviewCleanHostReceipt::new(receipt_input(0))
                .unwrap_err()
                .code(),
            "preview_clean_host_mcpb_size_invalid"
        );
    }

    #[test]
    fn duplicate_trailing_and_unknown_json_are_rejected() {
        let duplicate = br#"{"schema_version":1,"schema_version":1}"#;
        let error = parse_preview_clean_host_receipt(duplicate).unwrap_err();
        assert_eq!(error.code(), "preview_clean_host_json_invalid");
        assert!(error.detail().contains("duplicate JSON key"));

        let mut trailing = serde_json::to_vec(&valid_value()).unwrap();
        trailing.extend_from_slice(b" {}");
        assert_eq!(
            parse_preview_clean_host_receipt(&trailing)
                .unwrap_err()
                .code(),
            "preview_clean_host_json_trailing_data"
        );

        let mut unknown = valid_value();
        unknown["host"]["machine_id"] = json!("forbidden");
        assert_eq!(
            parse_value(&unknown).unwrap_err().code(),
            "preview_clean_host_schema_invalid"
        );
    }

    #[test]
    fn closed_values_versions_and_order_are_enforced() {
        let mut value = valid_value();
        value["package"]["mode"] = json!("release");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "preview_clean_host_package_mode_invalid"
        );

        let mut value = valid_value();
        value["client"]["version"] = json!("latest");
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "preview_clean_host_version_invalid"
        );

        let mut value = valid_value();
        value["fixtures"]["dwg"]["sha256"] = json!(hash('d'));
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "preview_clean_host_fixture_invalid"
        );

        let mut value = valid_value();
        value["title_block_mutation"]["installed_sha256"] = json!(hash('d'));
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "preview_clean_host_title_block_digest_unchanged"
        );

        let mut value = valid_value();
        value["title_block_mutation"]["sentinel_sha256"] = json!(hash('f'));
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "preview_clean_host_title_block_sentinel_invalid"
        );

        let mut value = valid_value();
        value["passed_checks"].as_array_mut().unwrap().swap(5, 6);
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "preview_clean_host_checks_invalid"
        );

        let mut value = valid_value();
        value["limitations"].as_array_mut().unwrap().pop();
        assert_eq!(
            parse_value(&value).unwrap_err().code(),
            "preview_clean_host_limitations_invalid"
        );
    }

    #[test]
    fn checked_in_schema_matches_the_rust_contract() {
        let schema: Value = serde_json::from_str(include_str!(
            "../schemas/preview-clean-host-receipt.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(validator.is_valid(&valid_value()));

        let mut value = valid_value();
        value["fixtures"]["dxf"]["fixture_id"] = json!("other_fixture");
        assert!(!validator.is_valid(&value));

        let mut value = valid_value();
        value["passed_checks"].as_array_mut().unwrap().reverse();
        assert!(!validator.is_valid(&value));

        let mut value = valid_value();
        value["client"]["version"] = json!("latest");
        assert!(!validator.is_valid(&value));

        let mut value = valid_value();
        value["raw_log"] = json!("forbidden");
        assert!(!validator.is_valid(&value));

        for invalid_timestamp in [
            "0000-01-01T00:00:00Z",
            "2026-02-29T12:34:56Z",
            "2026-04-31T12:34:56Z",
            "2026-07-28T24:00:00Z",
        ] {
            let mut value = valid_value();
            value["completed_utc"] = json!(invalid_timestamp);
            assert!(
                !validator.is_valid(&value),
                "schema admitted invalid timestamp {invalid_timestamp}"
            );
            assert_eq!(
                parse_value(&value).unwrap_err().code(),
                "utc_timestamp_invalid"
            );
        }

        let mut valid_leap_day = valid_value();
        valid_leap_day["completed_utc"] = json!("2024-02-29T23:59:59Z");
        assert!(validator.is_valid(&valid_leap_day));
        parse_value(&valid_leap_day).expect("valid leap-day timestamp");
    }
}
