#[cfg(test)]
mod tests {
    use super::*;

    fn write_mutated_distribution_evidence(
        plugin_dir: &Path,
        policy: &mut serde_json::Value,
        sbom: &serde_json::Value,
    ) {
        std::fs::create_dir_all(plugin_dir.join(".third-party")).unwrap();
        let mut sbom_bytes = serde_json::to_vec_pretty(sbom).unwrap();
        sbom_bytes.push(b'\n');
        policy["expected_sbom_sha256"] = serde_json::Value::String(sha256(&sbom_bytes));
        policy["expected_notices_sha256"] = serde_json::Value::String(sha256(THIRD_PARTY_LICENSES));
        let mut policy_bytes = serde_json::to_vec_pretty(policy).unwrap();
        policy_bytes.push(b'\n');
        std::fs::write(
            plugin_dir.join(THIRD_PARTY_LICENSE_POLICY_FILE),
            policy_bytes,
        )
        .unwrap();
        std::fs::write(plugin_dir.join(SOURCE_LOCK_SBOM_FILE), sbom_bytes).unwrap();
        write_exact_supporting_distribution_evidence(plugin_dir);
    }

    fn write_exact_supporting_distribution_evidence(plugin_dir: &Path) {
        std::fs::create_dir_all(plugin_dir.join(".third-party")).unwrap();
        std::fs::write(
            plugin_dir.join(WINDOWS_SOURCE_CLOSURE_SBOM_FILE),
            WINDOWS_SOURCE_CLOSURE_SBOM,
        )
        .unwrap();
        std::fs::write(
            plugin_dir.join(THIRD_PARTY_LICENSE_PROVENANCE_FILE),
            THIRD_PARTY_LICENSE_PROVENANCE,
        )
        .unwrap();
        std::fs::write(
            plugin_dir.join(THIRD_PARTY_LICENSES_FILE),
            THIRD_PARTY_LICENSES,
        )
        .unwrap();
        std::fs::write(
            plugin_dir.join(OWNER_DISTRIBUTION_APPROVAL_SCHEMA_FILE),
            OWNER_DISTRIBUTION_APPROVAL_SCHEMA,
        )
        .unwrap();
    }

    fn current_distribution_evidence() -> (serde_json::Value, serde_json::Value) {
        (
            serde_json::from_slice(THIRD_PARTY_LICENSE_POLICY).unwrap(),
            serde_json::from_slice(SOURCE_LOCK_SBOM).unwrap(),
        )
    }

    fn metadata() -> PluginMetadata {
        PluginMetadata {
            name: "autocad-mcp".to_string(),
            version: "0.0.1".to_string(),
            description: "A rust-backed AutoLISP MCP".to_string(),
            license: PROJECT_LICENSE.to_string(),
            author_name: "andagni".to_string(),
        }
    }

    #[test]
    fn macos_manifest_launches_serve_explicitly() {
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        assert_eq!(manifest.manifest_version, "0.3");
        assert_eq!(manifest.name, "autocad-mcp");
        assert_eq!(manifest.license, PROJECT_LICENSE);
        assert_eq!(manifest.server.kind, "binary");
        assert_eq!(manifest.server.entry_point, "plugin/bin/autocad-mcp");
        assert_eq!(
            manifest.server.mcp_config.command,
            "${__dirname}/plugin/bin/autocad-mcp"
        );
        assert_eq!(manifest.server.mcp_config.args, vec!["serve".to_string()]);
        assert_eq!(
            manifest.server.mcp_config.env,
            title_block_profiles_environment()
        );
        assert_eq!(manifest.user_config, title_block_profiles_user_config());
        let profiles = manifest
            .user_config
            .get(TITLE_BLOCK_PROFILES_USER_CONFIG_KEY)
            .unwrap();
        assert_eq!(profiles.kind, "file");
        assert!(!profiles.required);
        assert!(profiles.default.is_empty());
        assert_eq!(manifest.compatibility.platforms, vec!["darwin".to_string()]);
        assert_eq!(
            validate_manifest(&manifest, PackageTarget::MacosArm64).unwrap(),
            PackageMode::Release
        );
    }

    #[test]
    fn windows_manifest_launches_serve_explicitly() {
        let mut plugin = metadata();
        plugin.version = "1.0.0".to_owned();
        let manifest = manifest_for(PackageTarget::WindowsX64, &plugin);
        assert_eq!(manifest.server.entry_point, "plugin/bin/autocad-mcp.exe");
        assert_eq!(
            manifest.server.mcp_config.command,
            "${__dirname}/plugin/bin/autocad-mcp"
        );
        assert_eq!(manifest.server.mcp_config.args, vec!["serve".to_string()]);
        assert_eq!(manifest.compatibility.platforms, vec!["win32".to_string()]);
        assert_eq!(
            validate_manifest(&manifest, PackageTarget::WindowsX64).unwrap(),
            PackageMode::Release
        );
    }

    #[test]
    fn windows_manifest_json_uses_extensionless_command() {
        let manifest = manifest_for(PackageTarget::WindowsX64, &metadata());
        let json = serde_json::to_value(&manifest).unwrap();

        assert_eq!(json["server"]["entry_point"], "plugin/bin/autocad-mcp.exe");
        assert_eq!(
            json["server"]["mcp_config"]["command"],
            "${__dirname}/plugin/bin/autocad-mcp"
        );
        assert_eq!(
            json["server"]["mcp_config"]["args"],
            serde_json::json!(["serve"])
        );
        assert_eq!(
            json["compatibility"]["platforms"],
            serde_json::json!(["win32"])
        );
        assert_eq!(json["license"], PROJECT_LICENSE);
        assert!(json.get("_meta").is_none());
    }

    #[test]
    fn windows_preview_manifest_is_distinct_visible_and_explicit() {
        let manifest =
            manifest_for_mode(PackageTarget::WindowsX64, PackageMode::Preview, &metadata());
        let json = serde_json::to_value(&manifest).unwrap();

        assert_eq!(manifest.name, "autocad-mcp-preview");
        assert_eq!(manifest.description, "A rust-backed AutoLISP MCP (Preview)");
        assert_eq!(
            manifest.server.mcp_config.args,
            ["serve", "--experimental"].map(str::to_owned)
        );
        assert_eq!(
            json["_meta"][PREVIEW_METADATA_NAMESPACE][PREVIEW_PACKAGE_MODE_META_KEY],
            serde_json::json!("preview")
        );
        assert!(
            json["_meta"][PREVIEW_METADATA_NAMESPACE].is_object(),
            "MCPB 0.3 requires each reverse-DNS _meta value to be an object"
        );
        assert_eq!(
            validate_manifest(&manifest, PackageTarget::WindowsX64).unwrap(),
            PackageMode::Preview
        );
    }

    #[test]
    fn legacy_string_preview_metadata_is_rejected() {
        let manifest =
            manifest_for_mode(PackageTarget::WindowsX64, PackageMode::Preview, &metadata());
        let mut json = serde_json::to_value(manifest).unwrap();
        json["_meta"] = serde_json::json!({
            "io.github.andagni.autocad-mcp.package-mode": "preview"
        });

        assert!(
            serde_json::from_value::<McpbManifest>(json).is_err(),
            "the legacy string-valued _meta shape is not valid MCPB 0.3 metadata"
        );
    }

    #[test]
    fn manifest_mode_marker_and_launch_arguments_must_agree() {
        let mut unmarked_experimental = manifest_for(PackageTarget::WindowsX64, &metadata());
        unmarked_experimental.server.mcp_config.args =
            ["serve", "--experimental"].map(str::to_owned).to_vec();
        let error =
            validate_manifest(&unmarked_experimental, PackageTarget::WindowsX64).unwrap_err();
        assert!(error.to_string().contains("Release MCPB args"), "{error:#}");

        let mut marked_plain =
            manifest_for_mode(PackageTarget::WindowsX64, PackageMode::Preview, &metadata());
        marked_plain.server.mcp_config.args = vec!["serve".to_owned()];
        let error = validate_manifest(&marked_plain, PackageTarget::WindowsX64).unwrap_err();
        assert!(error.to_string().contains("Preview MCPB args"), "{error:#}");

        let mut marked_release = manifest_for(PackageTarget::WindowsX64, &metadata());
        marked_release.metadata = Some(McpbMetadata {
            autocad_mcp: McpbAutocadMetadata {
                package_mode: PackageMode::Release,
            },
        });
        let error = validate_manifest(&marked_release, PackageTarget::WindowsX64).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Release MCPB must omit the Preview"),
            "{error:#}"
        );
    }

    #[test]
    fn title_block_profile_configuration_is_closed_and_bound_to_the_environment() {
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());

        let mut changed_config = manifest.clone();
        changed_config
            .user_config
            .get_mut(TITLE_BLOCK_PROFILES_USER_CONFIG_KEY)
            .unwrap()
            .required = true;
        let error = validate_manifest(&changed_config, PackageTarget::MacosArm64).unwrap_err();
        assert!(error.to_string().contains("user_config"), "{error:#}");

        let mut added_config = manifest.clone();
        added_config.user_config.insert(
            "unapproved".to_owned(),
            McpbUserConfig {
                kind: "string".to_owned(),
                title: "Unapproved".to_owned(),
                description: "Unapproved".to_owned(),
                required: false,
                default: String::new(),
            },
        );
        let error = validate_manifest(&added_config, PackageTarget::MacosArm64).unwrap_err();
        assert!(error.to_string().contains("user_config"), "{error:#}");

        let mut changed_environment = manifest;
        changed_environment.server.mcp_config.env.insert(
            TITLE_BLOCK_PROFILES_ENV.to_owned(),
            serde_json::Value::String("/unapproved/profiles.json".to_owned()),
        );
        let error = validate_manifest(&changed_environment, PackageTarget::MacosArm64).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(TITLE_BLOCK_PROFILES_USER_CONFIG_VARIABLE),
            "{error:#}"
        );
    }

    #[test]
    fn preview_is_not_a_macos_package_mode() {
        let manifest =
            manifest_for_mode(PackageTarget::MacosArm64, PackageMode::Preview, &metadata());
        let error = validate_manifest(&manifest, PackageTarget::MacosArm64).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Preview packages require windows-x64"),
            "{error:#}"
        );
    }

    #[test]
    fn windows_package_versions_are_mode_bound() {
        let release_v0 = manifest_for(PackageTarget::WindowsX64, &metadata());
        let error = validate_manifest(&release_v0, PackageTarget::WindowsX64).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Windows Release MCPB version must be stable and at least 1.0.0"),
            "{error:#}"
        );

        let mut release_metadata = metadata();
        release_metadata.version = "1.0.0".to_owned();
        let release_v1 = manifest_for(PackageTarget::WindowsX64, &release_metadata);
        assert_eq!(
            validate_manifest(&release_v1, PackageTarget::WindowsX64).unwrap(),
            PackageMode::Release
        );

        let mut later_preview_metadata = metadata();
        later_preview_metadata.version = "0.9.12".to_owned();
        let later_preview = manifest_for_mode(
            PackageTarget::WindowsX64,
            PackageMode::Preview,
            &later_preview_metadata,
        );
        assert_eq!(
            validate_manifest(&later_preview, PackageTarget::WindowsX64).unwrap(),
            PackageMode::Preview
        );

        let mut release_version_preview_metadata = metadata();
        release_version_preview_metadata.version = "1.0.0".to_owned();
        let release_version_preview = manifest_for_mode(
            PackageTarget::WindowsX64,
            PackageMode::Preview,
            &release_version_preview_metadata,
        );
        let error =
            validate_manifest(&release_version_preview, PackageTarget::WindowsX64).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Windows Preview MCPB version must be stable and pre-1.0"),
            "{error:#}"
        );

        let mut prerelease_preview_metadata = metadata();
        prerelease_preview_metadata.version = "0.1.0-beta.1".to_owned();
        let prerelease_preview = manifest_for_mode(
            PackageTarget::WindowsX64,
            PackageMode::Preview,
            &prerelease_preview_metadata,
        );
        assert!(
            validate_manifest(&prerelease_preview, PackageTarget::WindowsX64)
                .unwrap_err()
                .to_string()
                .contains("stable and pre-1.0")
        );

        for (mode, version) in [
            (PackageMode::Preview, "0.01.0"),
            (PackageMode::Release, "01.0.0"),
        ] {
            let mut invalid_metadata = metadata();
            invalid_metadata.version = version.to_owned();
            let invalid = manifest_for_mode(PackageTarget::WindowsX64, mode, &invalid_metadata);
            assert!(
                validate_manifest(&invalid, PackageTarget::WindowsX64).is_err(),
                "{mode:?} accepted a noncanonical version {version}"
            );
        }
    }

    #[test]
    fn manifest_rejects_non_project_license() {
        let mut manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        manifest.license = "GPL-3.0-only".to_string();

        let error = validate_manifest(&manifest, PackageTarget::MacosArm64).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("MCPB license must be GPL-3.0-or-later"),
            "got: {error:#}"
        );
    }

    #[test]
    fn linux_is_not_an_mvp_package_target() {
        let err = "linux-x64".parse::<PackageTarget>().unwrap_err();
        assert!(
            err.to_string().contains("unsupported MVP package target"),
            "got: {err}"
        );
    }

    #[test]
    fn source_distribution_evidence_is_exact_byte_bound() {
        let plugin = tempfile::tempdir().unwrap();
        std::fs::create_dir(plugin.path().join(".third-party")).unwrap();
        std::fs::write(
            plugin.path().join(THIRD_PARTY_LICENSE_POLICY_FILE),
            THIRD_PARTY_LICENSE_POLICY,
        )
        .unwrap();
        std::fs::write(plugin.path().join(SOURCE_LOCK_SBOM_FILE), SOURCE_LOCK_SBOM).unwrap();
        write_exact_supporting_distribution_evidence(plugin.path());
        validate_source_distribution_evidence(plugin.path()).unwrap();

        std::fs::write(plugin.path().join(THIRD_PARTY_LICENSES_FILE), b"tampered\n").unwrap();
        let error = validate_source_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("differs from the exact bytes compiled into the packager"),
            "{error:#}"
        );

        std::fs::write(
            plugin.path().join(THIRD_PARTY_LICENSES_FILE),
            THIRD_PARTY_LICENSES,
        )
        .unwrap();
        std::fs::write(plugin.path().join(SOURCE_LOCK_SBOM_FILE), b"{}\n").unwrap();
        let error = validate_packaged_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match third-party licence policy SHA-256"),
            "{error:#}"
        );
    }

    #[test]
    fn packaged_distribution_evidence_rejects_duplicate_and_dangling_spdx_ids() {
        let plugin = tempfile::tempdir().unwrap();
        let (mut policy, mut sbom) = current_distribution_evidence();
        let first_id = sbom["packages"][0]["SPDXID"].as_str().unwrap().to_owned();
        sbom["packages"][1]["SPDXID"] = serde_json::Value::String(first_id);
        write_mutated_distribution_evidence(plugin.path(), &mut policy, &sbom);
        let error = validate_packaged_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error.to_string().contains("duplicate package SPDXID"),
            "{error:#}"
        );

        let (mut policy, mut sbom) = current_distribution_evidence();
        sbom["documentDescribes"] = serde_json::json!(["SPDXRef-Package-does-not-exist"]);
        write_mutated_distribution_evidence(plugin.path(), &mut policy, &sbom);
        let error = validate_packaged_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must exactly equal its workspace package SPDXIDs"),
            "{error:#}"
        );
    }

    #[test]
    fn packaged_distribution_evidence_rejects_malformed_relationships() {
        let plugin = tempfile::tempdir().unwrap();

        let (mut policy, mut sbom) = current_distribution_evidence();
        sbom["relationships"][0]["relatedSpdxElement"] =
            serde_json::Value::String("SPDXRef-Package-does-not-exist".to_owned());
        write_mutated_distribution_evidence(plugin.path(), &mut policy, &sbom);
        let error = validate_packaged_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error.to_string().contains("endpoint does not resolve"),
            "{error:#}"
        );

        let (mut policy, mut sbom) = current_distribution_evidence();
        sbom["relationships"][0]["relationshipType"] =
            serde_json::Value::String("CONTAINS".to_owned());
        write_mutated_distribution_evidence(plugin.path(), &mut policy, &sbom);
        let error = validate_packaged_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("relationshipType must be DEPENDS_ON"),
            "{error:#}"
        );

        let (mut policy, mut sbom) = current_distribution_evidence();
        sbom["relationships"][0]["comment"] = serde_json::Value::String("extra".to_owned());
        write_mutated_distribution_evidence(plugin.path(), &mut policy, &sbom);
        let error = validate_packaged_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error.to_string().contains("relationship shape"),
            "{error:#}"
        );
    }

    #[test]
    fn packaged_distribution_evidence_rejects_malformed_package_checksums() {
        let plugin = tempfile::tempdir().unwrap();

        let (mut policy, mut sbom) = current_distribution_evidence();
        let workspace_index = sbom["packages"]
            .as_array()
            .unwrap()
            .iter()
            .position(|package| package["sourceInfo"] == "AutoCAD-MCP workspace package.")
            .unwrap();
        sbom["packages"][workspace_index]["checksums"] = serde_json::json!([{
            "algorithm": "SHA256",
            "checksumValue": "0000000000000000000000000000000000000000000000000000000000000000"
        }]);
        write_mutated_distribution_evidence(plugin.path(), &mut policy, &sbom);
        let error = validate_packaged_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("workspace packages must not carry checksums"),
            "{error:#}"
        );

        let (mut policy, mut sbom) = current_distribution_evidence();
        let registry_index = sbom["packages"]
            .as_array()
            .unwrap()
            .iter()
            .position(|package| {
                package["sourceInfo"]
                    .as_str()
                    .is_some_and(|source| source.contains("from registry+"))
            })
            .unwrap();
        sbom["packages"][registry_index]["checksums"] = serde_json::json!([]);
        write_mutated_distribution_evidence(plugin.path(), &mut policy, &sbom);
        let error = validate_packaged_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("registry package must have exactly one checksum"),
            "{error:#}"
        );

        let (mut policy, mut sbom) = current_distribution_evidence();
        let registry_index = sbom["packages"]
            .as_array()
            .unwrap()
            .iter()
            .position(|package| package["sourceInfo"] == CARGO_REGISTRY_SOURCE_INFO)
            .unwrap();
        sbom["packages"][registry_index]["sourceInfo"] = serde_json::Value::String(
            "Resolved by Cargo.lock from arbitrary; SHA-256 checksum is the Cargo.lock package checksum."
                .to_owned(),
        );
        sbom["packages"][registry_index]["checksums"] = serde_json::json!([]);
        write_mutated_distribution_evidence(plugin.path(), &mut policy, &sbom);
        let error = validate_packaged_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error.to_string().contains("unknown sourceInfo shape"),
            "{error:#}"
        );

        let (mut policy, mut sbom) = current_distribution_evidence();
        let registry_index = sbom["packages"]
            .as_array()
            .unwrap()
            .iter()
            .position(|package| {
                package["sourceInfo"]
                    .as_str()
                    .is_some_and(|source| source.contains("from registry+"))
            })
            .unwrap();
        sbom["packages"][registry_index]["checksums"][0]["algorithm"] =
            serde_json::Value::String("SHA1".to_owned());
        write_mutated_distribution_evidence(plugin.path(), &mut policy, &sbom);
        let error = validate_packaged_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error.to_string().contains("checksum must contain only"),
            "{error:#}"
        );

        let (mut policy, mut sbom) = current_distribution_evidence();
        let registry_index = sbom["packages"]
            .as_array()
            .unwrap()
            .iter()
            .position(|package| {
                package["sourceInfo"]
                    .as_str()
                    .is_some_and(|source| source.contains("from registry+"))
            })
            .unwrap();
        sbom["packages"][registry_index]["checksums"][0]["checksumValue"] =
            serde_json::Value::String(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            );
        write_mutated_distribution_evidence(plugin.path(), &mut policy, &sbom);
        let error = validate_packaged_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("checksumValue must be 64 lowercase hexadecimal digits"),
            "{error:#}"
        );

        let (mut policy, mut sbom) = current_distribution_evidence();
        let registry_index = sbom["packages"]
            .as_array()
            .unwrap()
            .iter()
            .position(|package| {
                package["sourceInfo"]
                    .as_str()
                    .is_some_and(|source| source.contains("from registry+"))
            })
            .unwrap();
        sbom["packages"][registry_index]["checksums"][0]["comment"] =
            serde_json::Value::String("extra".to_owned());
        write_mutated_distribution_evidence(plugin.path(), &mut policy, &sbom);
        let error = validate_packaged_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error.to_string().contains("checksum must contain only"),
            "{error:#}"
        );
    }

    #[test]
    fn schema_v2_evidence_rejects_an_embedded_approval_status() {
        let plugin = tempfile::tempdir().unwrap();
        let (mut policy, sbom) = current_distribution_evidence();
        policy["legal_review"] = serde_json::json!({
            "status": "approved",
            "approval_reference": "nonexistent-review"
        });
        write_mutated_distribution_evidence(plugin.path(), &mut policy, &sbom);
        let error = validate_packaged_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fields do not match the closed technical evidence contract"),
            "{error:#}"
        );
    }

    #[test]
    fn smoke_identity_requires_exact_compiled_evidence_not_self_consistency() {
        let plugin = tempfile::tempdir().unwrap();
        let (mut policy, mut sbom) = current_distribution_evidence();
        sbom["creationInfo"]["creators"] = serde_json::json!(["Tool: co-edited-reproduction"]);
        write_mutated_distribution_evidence(plugin.path(), &mut policy, &sbom);
        validate_packaged_distribution_evidence(plugin.path()).unwrap();
        let error = validate_source_distribution_evidence(plugin.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("differs from the exact bytes compiled into the packager"),
            "{error:#}"
        );
    }
}

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;

pub const PROJECT_LICENSE: &str = "GPL-3.0-or-later";
pub const PROJECT_LICENSE_TEXT: &[u8] = include_bytes!("../../../../LICENSE");
pub const THIRD_PARTY_LICENSE_POLICY: &[u8] =
    include_bytes!("../../../../plugin/.third-party/third-party-license-policy.json");
pub const SOURCE_LOCK_SBOM: &[u8] =
    include_bytes!("../../../../plugin/.third-party/source-lock.spdx.json");
pub const WINDOWS_SOURCE_CLOSURE_SBOM: &[u8] =
    include_bytes!("../../../../plugin/.third-party/source-closure-windows.spdx.json");
pub const THIRD_PARTY_LICENSE_PROVENANCE: &[u8] =
    include_bytes!("../../../../plugin/.third-party/third-party-license-provenance.json");
pub const THIRD_PARTY_LICENSES: &[u8] =
    include_bytes!("../../../../plugin/THIRD_PARTY_LICENSES.txt");
pub const OWNER_DISTRIBUTION_APPROVAL_SCHEMA: &[u8] =
    include_bytes!("../../approval/schemas/owner-distribution-approval.schema.json");

const THIRD_PARTY_LICENSE_POLICY_FILE: &str = ".third-party/third-party-license-policy.json";
const DISTRIBUTION_EVIDENCE_GENERATOR_SCHEMA_VERSION: u64 = 7;
const SOURCE_LOCK_SBOM_FILE: &str = ".third-party/source-lock.spdx.json";
const WINDOWS_SOURCE_CLOSURE_SBOM_FILE: &str = ".third-party/source-closure-windows.spdx.json";
const THIRD_PARTY_LICENSE_PROVENANCE_FILE: &str =
    ".third-party/third-party-license-provenance.json";
const THIRD_PARTY_LICENSES_FILE: &str = "THIRD_PARTY_LICENSES.txt";
pub const OWNER_DISTRIBUTION_APPROVAL_SCHEMA_FILE: &str = "owner-distribution-approval.schema.json";
const CARGO_REGISTRY_SOURCE_INFO: &str = "Resolved by Cargo.lock from registry+https://github.com/rust-lang/crates.io-index; SHA-256 checksum is the Cargo.lock package checksum.";
pub const PREVIEW_METADATA_NAMESPACE: &str = "io.github.andagni.autocad-mcp";
pub const PREVIEW_PACKAGE_MODE_META_KEY: &str = "package-mode";
pub const PREVIEW_READ_ONLY_TOOL_COUNT: usize = 36;
pub const TITLE_BLOCK_PROFILES_ENV: &str = autocad_mcp::ops::profiles::TITLE_BLOCK_PROFILES_ENV;
pub const TITLE_BLOCK_PROFILES_USER_CONFIG_KEY: &str = "title_block_profiles";
pub const TITLE_BLOCK_PROFILES_USER_CONFIG_VARIABLE: &str = "${user_config.title_block_profiles}";
const PREVIEW_NAME_SUFFIX: &str = "-preview";
const PREVIEW_DESCRIPTION_SUFFIX: &str = " (Preview)";

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageMode {
    Release,
    Preview,
}

impl PackageMode {
    pub fn manifest_name(self, base: &str) -> String {
        match self {
            Self::Release => base.to_owned(),
            Self::Preview => format!("{base}{PREVIEW_NAME_SUFFIX}"),
        }
    }

    pub fn manifest_description(self, base: &str) -> String {
        match self {
            Self::Release => base.to_owned(),
            Self::Preview => format!("{base}{PREVIEW_DESCRIPTION_SUFFIX}"),
        }
    }

    pub fn launch_args(self) -> Vec<String> {
        match self {
            Self::Release => vec!["serve".to_owned()],
            Self::Preview => ["serve", "--experimental"].map(str::to_owned).to_vec(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageTarget {
    WindowsX64,
    MacosArm64,
}

impl PackageTarget {
    pub fn package_name(self) -> &'static str {
        match self {
            PackageTarget::WindowsX64 => "autocad-mcp-windows-x64.mcpb",
            PackageTarget::MacosArm64 => "autocad-mcp-macos-arm64.mcpb",
        }
    }

    pub fn package_name_for(self, mode: PackageMode) -> &'static str {
        match (self, mode) {
            (PackageTarget::WindowsX64, PackageMode::Release) => "autocad-mcp-windows-x64.mcpb",
            (PackageTarget::WindowsX64, PackageMode::Preview) => {
                "autocad-mcp-windows-x64-preview.mcpb"
            }
            (PackageTarget::MacosArm64, PackageMode::Release) => "autocad-mcp-macos-arm64.mcpb",
            (PackageTarget::MacosArm64, PackageMode::Preview) => {
                "autocad-mcp-macos-arm64-preview.mcpb"
            }
        }
    }

    pub fn binary_name(self) -> &'static str {
        match self {
            PackageTarget::WindowsX64 => "autocad-mcp.exe",
            PackageTarget::MacosArm64 => "autocad-mcp",
        }
    }

    pub fn platform(self) -> &'static str {
        match self {
            PackageTarget::WindowsX64 => "win32",
            PackageTarget::MacosArm64 => "darwin",
        }
    }

    pub fn binary_entry_point(self) -> String {
        format!("plugin/bin/{}", self.binary_name())
    }

    pub fn command_entry_point(self) -> String {
        match self {
            PackageTarget::WindowsX64 => "plugin/bin/autocad-mcp".to_string(),
            PackageTarget::MacosArm64 => self.binary_entry_point(),
        }
    }
}

impl FromStr for PackageTarget {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "windows-x64" => Ok(Self::WindowsX64),
            "macos-arm64" => Ok(Self::MacosArm64),
            other => Err(anyhow!("unsupported MVP package target '{other}'")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub license: String,
    pub author_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginJson {
    name: String,
    version: String,
    description: String,
    license: String,
    author: PluginAuthorJson,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginAuthorJson {
    name: String,
}

pub fn read_plugin_metadata(plugin_dir: &Path) -> Result<PluginMetadata> {
    let path = plugin_dir.join(".claude-plugin/plugin.json");
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let value = distribution_approval::parse_strict_json(&bytes)
        .with_context(|| format!("strictly parse {}", path.display()))?;
    let plugin: PluginJson = serde_json::from_value(value)
        .with_context(|| format!("validate closed schema for {}", path.display()))?;
    let valid_name = !plugin.name.is_empty()
        && plugin.name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index != 0 && matches!(byte, b'.' | b'_' | b'-'))
        });
    if !valid_name
        || plugin.version.is_empty()
        || plugin.description.is_empty()
        || plugin.license.is_empty()
        || plugin.author.name.is_empty()
    {
        return Err(anyhow!(
            "plugin/.claude-plugin/plugin.json violates the closed nonempty identity schema"
        ));
    }
    Ok(PluginMetadata {
        name: plugin.name,
        version: plugin.version,
        description: plugin.description,
        license: plugin.license,
        author_name: plugin.author.name,
    })
}

pub fn validate_plugin_license(plugin_dir: &Path, metadata: &PluginMetadata) -> Result<()> {
    if metadata.license != PROJECT_LICENSE {
        return Err(anyhow!(
            "plugin license must be {PROJECT_LICENSE}; got {}",
            metadata.license
        ));
    }

    let license_path = plugin_dir.join("LICENSE");
    let license = std::fs::read(&license_path)
        .with_context(|| format!("read plugin license {}", license_path.display()))?;
    if license.is_empty() || license.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(anyhow!("plugin LICENSE must be nonempty"));
    }
    if license != PROJECT_LICENSE_TEXT {
        return Err(anyhow!(
            "plugin LICENSE must match the canonical repository GPLv3 text"
        ));
    }
    Ok(())
}

pub fn validate_source_distribution_evidence(plugin_dir: &Path) -> Result<()> {
    for (name, expected) in [
        (THIRD_PARTY_LICENSE_POLICY_FILE, THIRD_PARTY_LICENSE_POLICY),
        (SOURCE_LOCK_SBOM_FILE, SOURCE_LOCK_SBOM),
        (
            WINDOWS_SOURCE_CLOSURE_SBOM_FILE,
            WINDOWS_SOURCE_CLOSURE_SBOM,
        ),
        (
            THIRD_PARTY_LICENSE_PROVENANCE_FILE,
            THIRD_PARTY_LICENSE_PROVENANCE,
        ),
        (THIRD_PARTY_LICENSES_FILE, THIRD_PARTY_LICENSES),
        (
            OWNER_DISTRIBUTION_APPROVAL_SCHEMA_FILE,
            OWNER_DISTRIBUTION_APPROVAL_SCHEMA,
        ),
    ] {
        let path = plugin_dir.join(name);
        let actual = std::fs::read(&path)
            .with_context(|| format!("read distribution evidence {}", path.display()))?;
        if actual != expected {
            return Err(anyhow!(
                "source distribution evidence {name} differs from the exact bytes compiled into the packager"
            ));
        }
    }
    validate_packaged_distribution_evidence(plugin_dir)
}

pub fn validate_packaged_distribution_evidence(plugin_dir: &Path) -> Result<()> {
    let policy_path = plugin_dir.join(THIRD_PARTY_LICENSE_POLICY_FILE);
    let sbom_path = plugin_dir.join(SOURCE_LOCK_SBOM_FILE);
    let windows_sbom_path = plugin_dir.join(WINDOWS_SOURCE_CLOSURE_SBOM_FILE);
    let provenance_path = plugin_dir.join(THIRD_PARTY_LICENSE_PROVENANCE_FILE);
    let notices_path = plugin_dir.join(THIRD_PARTY_LICENSES_FILE);
    let approval_schema_path = plugin_dir.join(OWNER_DISTRIBUTION_APPROVAL_SCHEMA_FILE);
    let policy_bytes = std::fs::read(&policy_path)
        .with_context(|| format!("read third-party licence policy {}", policy_path.display()))?;
    let sbom_bytes =
        std::fs::read(&sbom_path).with_context(|| format!("read SBOM {}", sbom_path.display()))?;
    let windows_sbom_bytes = std::fs::read(&windows_sbom_path).with_context(|| {
        format!(
            "read Windows source-closure SBOM {}",
            windows_sbom_path.display()
        )
    })?;
    let provenance_bytes = std::fs::read(&provenance_path).with_context(|| {
        format!(
            "read third-party licence provenance {}",
            provenance_path.display()
        )
    })?;
    let notices_bytes = std::fs::read(&notices_path)
        .with_context(|| format!("read third-party licences {}", notices_path.display()))?;
    let approval_schema_bytes = std::fs::read(&approval_schema_path).with_context(|| {
        format!(
            "read owner-distribution approval schema {}",
            approval_schema_path.display()
        )
    })?;
    let policy: serde_json::Value = serde_json::from_slice(&policy_bytes)
        .with_context(|| format!("parse third-party licence policy {}", policy_path.display()))?;
    let sbom: serde_json::Value = serde_json::from_slice(&sbom_bytes)
        .with_context(|| format!("parse SPDX SBOM {}", sbom_path.display()))?;
    let windows_sbom: serde_json::Value = serde_json::from_slice(&windows_sbom_bytes)
        .with_context(|| {
            format!(
                "parse Windows source-closure SPDX SBOM {}",
                windows_sbom_path.display()
            )
        })?;
    let provenance: serde_json::Value =
        serde_json::from_slice(&provenance_bytes).with_context(|| {
            format!(
                "parse third-party licence provenance {}",
                provenance_path.display()
            )
        })?;
    let approval_schema: serde_json::Value = serde_json::from_slice(&approval_schema_bytes)
        .with_context(|| {
            format!(
                "parse owner-distribution approval schema {}",
                approval_schema_path.display()
            )
        })?;

    if require_json_u64(&policy, "schema_version")? != 2
        || require_json_u64(&policy, "evidence_generator_schema_version")?
            != DISTRIBUTION_EVIDENCE_GENERATOR_SCHEMA_VERSION
    {
        return Err(anyhow!(
            "third-party licence policy schema must be 2 and generator schema must be {}",
            DISTRIBUTION_EVIDENCE_GENERATOR_SCHEMA_VERSION
        ));
    }
    let lock_sha256 = require_json_sha256(&policy, "reviewed_cargo_lock_sha256")?;
    let input_closure_sha256 = require_json_sha256(&policy, "reviewed_input_closure_sha256")?;
    let expected_sbom_sha256 = require_json_sha256(&policy, "expected_sbom_sha256")?;
    let expected_windows_sbom_sha256 =
        require_json_sha256(&policy, "expected_windows_source_closure_sbom_sha256")?;
    let expected_notices_sha256 = require_json_sha256(&policy, "expected_notices_sha256")?;
    let expected_provenance_sha256 =
        require_json_sha256(&policy, "expected_license_provenance_sha256")?;
    let expected_packages = require_json_u64(&policy, "expected_total_packages")?;
    let expected_third_party = require_json_u64(&policy, "expected_third_party_packages")?;
    let expected_windows_packages =
        require_json_u64(&policy, "expected_windows_source_closure_packages")?;
    let expected_windows_third_party = require_json_u64(
        &policy,
        "expected_windows_source_closure_third_party_packages",
    )?;
    validate_owner_approval_contract(&policy, &approval_schema_bytes, &approval_schema)?;

    if sha256(&sbom_bytes) != expected_sbom_sha256 {
        return Err(anyhow!(
            "packaged source-lock SBOM does not match third-party licence policy SHA-256"
        ));
    }
    if sha256(&windows_sbom_bytes) != expected_windows_sbom_sha256 {
        return Err(anyhow!(
            "packaged Windows source-closure SBOM does not match third-party licence policy SHA-256"
        ));
    }
    if sha256(&notices_bytes) != expected_notices_sha256 {
        return Err(anyhow!(
            "packaged third-party licence bundle does not match third-party licence policy SHA-256"
        ));
    }
    if sha256(&provenance_bytes) != expected_provenance_sha256 {
        return Err(anyhow!(
            "packaged third-party licence provenance does not match third-party licence policy SHA-256"
        ));
    }
    if sbom["spdxVersion"] != "SPDX-2.3"
        || sbom["dataLicense"] != "CC0-1.0"
        || sbom["SPDXID"] != "SPDXRef-DOCUMENT"
        || sbom["name"] != "AutoCAD-MCP Cargo.lock source dependency graph"
    {
        return Err(anyhow!(
            "packaged dependency SBOM is not the required SPDX 2.3 source-lock document"
        ));
    }
    let expected_namespace =
        format!("https://andagni.invalid/spdx/autocad-mcp/source-closure-{input_closure_sha256}");
    if sbom["documentNamespace"] != expected_namespace {
        return Err(anyhow!(
            "packaged dependency SBOM namespace does not match the reviewed input closure"
        ));
    }
    let packages = sbom["packages"]
        .as_array()
        .ok_or_else(|| anyhow!("packaged dependency SBOM packages must be an array"))?;
    if packages.len() as u64 != expected_packages {
        return Err(anyhow!(
            "packaged dependency SBOM package count does not match policy"
        ));
    }
    if !sbom["creationInfo"].is_object() {
        return Err(anyhow!(
            "packaged dependency SBOM lacks creation information"
        ));
    }
    let relationships = sbom["relationships"]
        .as_array()
        .ok_or_else(|| anyhow!("packaged dependency SBOM relationships must be an array"))?;
    let document_describes = sbom["documentDescribes"]
        .as_array()
        .ok_or_else(|| anyhow!("packaged dependency SBOM documentDescribes must be an array"))?;

    let mut package_ids = BTreeSet::new();
    let mut workspace_package_ids = BTreeSet::new();
    let mut third_party_packages = 0_u64;
    for package in packages {
        let package_id = package["SPDXID"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("packaged dependency SBOM package has no SPDXID"))?;
        if !package_ids.insert(package_id.to_owned()) {
            return Err(anyhow!(
                "packaged dependency SBOM contains duplicate package SPDXID {package_id}"
            ));
        }
        if package["name"].as_str().is_none()
            || package["versionInfo"].as_str().is_none()
            || package["filesAnalyzed"] != false
            || package["licenseConcluded"] != "NOASSERTION"
            || package["licenseDeclared"].as_str().is_none()
            || package["copyrightText"] != "NOASSERTION"
        {
            return Err(anyhow!(
                "packaged dependency SBOM contains an incomplete package record"
            ));
        }
        let source_info = package["sourceInfo"]
            .as_str()
            .ok_or_else(|| anyhow!("packaged dependency SBOM package lacks sourceInfo"))?;
        let checksums: &[serde_json::Value] = match package.get("checksums") {
            Some(value) => value
                .as_array()
                .ok_or_else(|| {
                    anyhow!("packaged dependency SBOM package checksums must be an array")
                })?
                .as_slice(),
            None => &[],
        };
        if checksums.len() > 1 {
            return Err(anyhow!(
                "packaged dependency SBOM package may have at most one checksum"
            ));
        }
        for checksum in checksums {
            let object = checksum
                .as_object()
                .ok_or_else(|| anyhow!("packaged dependency SBOM checksum must be an object"))?;
            let fields = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
            if fields != BTreeSet::from(["algorithm", "checksumValue"])
                || object["algorithm"] != "SHA256"
            {
                return Err(anyhow!(
                    "packaged dependency SBOM checksum must contain only algorithm SHA256 and checksumValue"
                ));
            }
            let checksum_value = object["checksumValue"].as_str().ok_or_else(|| {
                anyhow!("packaged dependency SBOM checksumValue must be a string")
            })?;
            if checksum_value.len() != 64
                || !checksum_value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(anyhow!(
                    "packaged dependency SBOM checksumValue must be 64 lowercase hexadecimal digits"
                ));
            }
        }
        if source_info == "AutoCAD-MCP workspace package." {
            if !checksums.is_empty() {
                return Err(anyhow!(
                    "packaged dependency SBOM workspace packages must not carry checksums"
                ));
            }
            workspace_package_ids.insert(package_id.to_owned());
        } else if source_info == CARGO_REGISTRY_SOURCE_INFO {
            if checksums.len() != 1 {
                return Err(anyhow!(
                    "packaged dependency SBOM registry package must have exactly one checksum"
                ));
            }
            third_party_packages += 1;
        } else {
            return Err(anyhow!(
                "packaged dependency SBOM package has an unknown sourceInfo shape"
            ));
        }
    }
    if third_party_packages != expected_third_party {
        return Err(anyhow!(
            "packaged dependency SBOM third-party package count does not match policy"
        ));
    }
    if workspace_package_ids.is_empty() {
        return Err(anyhow!(
            "packaged dependency SBOM must contain workspace packages"
        ));
    }
    let mut described_ids = BTreeSet::new();
    for value in document_describes {
        let id = value
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("documentDescribes entries must be nonempty strings"))?;
        if !described_ids.insert(id.to_owned()) {
            return Err(anyhow!(
                "packaged dependency SBOM repeats documentDescribes SPDXID {id}"
            ));
        }
    }
    if described_ids != workspace_package_ids {
        return Err(anyhow!(
            "packaged dependency SBOM documentDescribes must exactly equal its workspace package SPDXIDs"
        ));
    }

    let mut relationship_identities = BTreeSet::new();
    for relationship in relationships {
        let object = relationship
            .as_object()
            .ok_or_else(|| anyhow!("packaged dependency SBOM relationship must be an object"))?;
        let fields = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
        let expected_fields =
            BTreeSet::from(["relatedSpdxElement", "relationshipType", "spdxElementId"]);
        if fields != expected_fields {
            return Err(anyhow!(
                "packaged dependency SBOM relationship shape must contain only spdxElementId, relationshipType, and relatedSpdxElement"
            ));
        }
        let from = object["spdxElementId"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("relationship spdxElementId must be a nonempty string"))?;
        let relationship_type = object["relationshipType"]
            .as_str()
            .ok_or_else(|| anyhow!("relationship relationshipType must be a string"))?;
        let to = object["relatedSpdxElement"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("relationship relatedSpdxElement must be a nonempty string"))?;
        if relationship_type != "DEPENDS_ON" {
            return Err(anyhow!(
                "packaged dependency SBOM relationshipType must be DEPENDS_ON"
            ));
        }
        if !package_ids.contains(from) || !package_ids.contains(to) {
            return Err(anyhow!(
                "packaged dependency SBOM relationship endpoint does not resolve to a package SPDXID"
            ));
        }
        if !relationship_identities.insert((from.to_owned(), to.to_owned())) {
            return Err(anyhow!(
                "packaged dependency SBOM repeats a DEPENDS_ON relationship"
            ));
        }
    }
    validate_windows_source_closure_sbom(
        &windows_sbom,
        expected_windows_packages,
        expected_windows_third_party,
        input_closure_sha256,
    )?;
    validate_provenance_notice_representation(&provenance, &notices_bytes)?;

    let notices = std::str::from_utf8(&notices_bytes)
        .context("packaged third-party licence bundle must be UTF-8")?;
    if !notices.starts_with("AutoCAD-MCP third-party licence evidence bundle\n")
        || !notices.contains(&format!("Cargo.lock SHA-256: {lock_sha256}\n"))
        || !notices.contains("Metadata is not a substitute for retained licence\nor notice bytes")
    {
        return Err(anyhow!(
            "packaged third-party licence bundle lacks its scope or evidence warning"
        ));
    }
    Ok(())
}

fn validate_owner_approval_contract(
    policy: &serde_json::Value,
    approval_schema_bytes: &[u8],
    approval_schema: &serde_json::Value,
) -> Result<()> {
    let policy_object = policy
        .as_object()
        .ok_or_else(|| anyhow!("third-party licence policy must be a JSON object"))?;
    let actual_policy_fields = policy_object
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_policy_fields = BTreeSet::from([
        "allowed_registry_sources",
        "allowed_spdx_exception_ids",
        "allowed_spdx_license_ids",
        "evidence_document_created_utc",
        "evidence_generator_schema_version",
        "expected_license_provenance_sha256",
        "expected_notices_sha256",
        "expected_packages_without_retained_license_files",
        "expected_sbom_sha256",
        "expected_third_party_packages",
        "expected_total_packages",
        "expected_windows_source_closure_packages",
        "expected_windows_source_closure_sbom_sha256",
        "expected_windows_source_closure_third_party_packages",
        "non_spdx_declared_license_values",
        "owner_distribution_approval",
        "reviewed_cargo_lock_sha256",
        "reviewed_input_closure_sha256",
        "schema_version",
    ]);
    if actual_policy_fields != expected_policy_fields {
        return Err(anyhow!(
            "third-party licence policy schema-v2 fields do not match the closed technical evidence contract"
        ));
    }

    let approval = policy["owner_distribution_approval"]
        .as_object()
        .ok_or_else(|| {
            anyhow!("third-party licence policy owner_distribution_approval must be an object")
        })?;
    let approval_fields = approval.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if approval_fields
        != BTreeSet::from([
            "contract_schema_path",
            "contract_schema_sha256",
            "contract_schema_version",
            "mode",
            "required_for",
        ])
    {
        return Err(anyhow!(
            "third-party licence policy owner_distribution_approval fields do not match the closed contract"
        ));
    }
    if approval["mode"] != "detached_per_distribution_set"
        || approval["contract_schema_version"]
            != u64::from(distribution_approval::APPROVAL_SCHEMA_VERSION)
        || approval["contract_schema_path"]
            != "crates/distribution/approval/schemas/owner-distribution-approval.schema.json"
        || approval["required_for"]
            != serde_json::json!(["public_binary_distribution", "public_source_distribution"])
    {
        return Err(anyhow!(
            "owner-distribution approval contract must remain detached schema-v{} evidence required for public binary and source distribution",
            distribution_approval::APPROVAL_SCHEMA_VERSION
        ));
    }
    let expected_schema_sha256 = require_json_sha256(
        &policy["owner_distribution_approval"],
        "contract_schema_sha256",
    )?;
    if sha256(approval_schema_bytes) != expected_schema_sha256 {
        return Err(anyhow!(
            "packaged owner-distribution approval schema does not match third-party licence policy SHA-256"
        ));
    }
    if approval_schema.pointer("/properties/schema_version/const")
        != Some(&serde_json::json!(
            distribution_approval::APPROVAL_SCHEMA_VERSION
        ))
        || approval_schema.pointer("/properties/kind/const")
            != Some(&serde_json::json!(distribution_approval::APPROVAL_KIND))
        || approval_schema.get("additionalProperties") != Some(&serde_json::Value::Bool(false))
    {
        return Err(anyhow!(
            "packaged owner-distribution approval schema is not the closed schema-v{} contract",
            distribution_approval::APPROVAL_SCHEMA_VERSION
        ));
    }
    jsonschema::validator_for(approval_schema)
        .context("compile packaged owner-distribution approval JSON Schema")?;
    Ok(())
}

fn validate_windows_source_closure_sbom(
    sbom: &serde_json::Value,
    expected_packages: u64,
    expected_third_party: u64,
    input_closure_sha256: &str,
) -> Result<()> {
    if sbom["spdxVersion"] != "SPDX-2.3"
        || sbom["dataLicense"] != "CC0-1.0"
        || sbom["SPDXID"] != "SPDXRef-DOCUMENT"
        || sbom["name"] != "AutoCAD-MCP Windows x64 product build-source closure"
    {
        return Err(anyhow!(
            "packaged Windows dependency SBOM is not the required SPDX 2.3 source-closure document"
        ));
    }
    let expected_namespace = format!(
        "https://andagni.invalid/spdx/autocad-mcp/windows-x64-source-build-closure-{input_closure_sha256}"
    );
    if sbom["documentNamespace"] != expected_namespace {
        return Err(anyhow!(
            "packaged Windows dependency SBOM namespace does not match the reviewed input closure"
        ));
    }
    if !sbom["creationInfo"].is_object() {
        return Err(anyhow!(
            "packaged Windows dependency SBOM lacks creation information"
        ));
    }

    let packages = sbom["packages"]
        .as_array()
        .ok_or_else(|| anyhow!("packaged Windows dependency SBOM packages must be an array"))?;
    if packages.len() as u64 != expected_packages {
        return Err(anyhow!(
            "packaged Windows dependency SBOM package count does not match policy"
        ));
    }
    let mut package_ids = BTreeSet::new();
    let mut workspace_roots = std::collections::BTreeMap::new();
    let mut third_party_packages = 0_u64;
    for package in packages {
        let package_id = package["SPDXID"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("packaged Windows dependency SBOM package has no SPDXID"))?;
        if !package_ids.insert(package_id.to_owned()) {
            return Err(anyhow!(
                "packaged Windows dependency SBOM contains duplicate package SPDXID {package_id}"
            ));
        }
        let package_name = package["name"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("packaged Windows dependency SBOM package has no name"))?;
        if package["versionInfo"].as_str().is_none()
            || package["filesAnalyzed"] != false
            || package["licenseConcluded"] != "NOASSERTION"
            || package["licenseDeclared"].as_str().is_none()
            || package["copyrightText"] != "NOASSERTION"
        {
            return Err(anyhow!(
                "packaged Windows dependency SBOM contains an incomplete package record"
            ));
        }
        let source_info = package["sourceInfo"]
            .as_str()
            .ok_or_else(|| anyhow!("packaged Windows dependency SBOM package lacks sourceInfo"))?;
        let checksums: &[serde_json::Value] = match package.get("checksums") {
            Some(value) => value
                .as_array()
                .ok_or_else(|| {
                    anyhow!("packaged Windows dependency SBOM package checksums must be an array")
                })?
                .as_slice(),
            None => &[],
        };
        validate_spdx_checksums(checksums, "packaged Windows dependency SBOM")?;
        if source_info == "AutoCAD-MCP workspace package." {
            if !checksums.is_empty() {
                return Err(anyhow!(
                    "packaged Windows dependency SBOM workspace packages must not carry checksums"
                ));
            }
            if workspace_roots
                .insert(package_name.to_owned(), package_id.to_owned())
                .is_some()
            {
                return Err(anyhow!(
                    "packaged Windows dependency SBOM repeats workspace package name {package_name}"
                ));
            }
        } else if source_info == CARGO_REGISTRY_SOURCE_INFO {
            if checksums.len() != 1 {
                return Err(anyhow!(
                    "packaged Windows dependency SBOM registry package must have exactly one checksum"
                ));
            }
            third_party_packages += 1;
        } else {
            return Err(anyhow!(
                "packaged Windows dependency SBOM package has an unknown sourceInfo shape"
            ));
        }
    }
    if third_party_packages != expected_third_party {
        return Err(anyhow!(
            "packaged Windows dependency SBOM third-party package count does not match policy"
        ));
    }

    let expected_described_ids = ["autocad-mcp", "autolisp-lsp"]
        .into_iter()
        .map(|name| {
            workspace_roots.get(name).cloned().ok_or_else(|| {
                anyhow!("packaged Windows dependency SBOM lacks product root {name}")
            })
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let described_ids = sbom["documentDescribes"]
        .as_array()
        .ok_or_else(|| {
            anyhow!("packaged Windows dependency SBOM documentDescribes must be an array")
        })?
        .iter()
        .map(|value| {
            value.as_str().filter(|value| !value.is_empty()).ok_or_else(|| {
                anyhow!(
                    "packaged Windows dependency SBOM documentDescribes entries must be nonempty strings"
                )
            })
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if described_ids.len() != 2
        || described_ids
            != expected_described_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
    {
        return Err(anyhow!(
            "packaged Windows dependency SBOM must describe exactly autocad-mcp and autolisp-lsp"
        ));
    }

    let relationships = sbom["relationships"].as_array().ok_or_else(|| {
        anyhow!("packaged Windows dependency SBOM relationships must be an array")
    })?;
    let mut relationship_identities = BTreeSet::new();
    for relationship in relationships {
        let object = relationship.as_object().ok_or_else(|| {
            anyhow!("packaged Windows dependency SBOM relationship must be an object")
        })?;
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != BTreeSet::from(["relatedSpdxElement", "relationshipType", "spdxElementId"])
        {
            return Err(anyhow!(
                "packaged Windows dependency SBOM relationship has an unknown field"
            ));
        }
        let from = object["spdxElementId"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow!("packaged Windows dependency SBOM relationship has no source")
            })?;
        let to = object["relatedSpdxElement"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow!("packaged Windows dependency SBOM relationship has no target")
            })?;
        if object["relationshipType"] != "DEPENDS_ON"
            || !package_ids.contains(from)
            || !package_ids.contains(to)
            || !relationship_identities.insert((from, to))
        {
            return Err(anyhow!(
                "packaged Windows dependency SBOM contains an invalid or duplicate dependency relationship"
            ));
        }
    }
    Ok(())
}

fn validate_spdx_checksums(checksums: &[serde_json::Value], label: &str) -> Result<()> {
    if checksums.len() > 1 {
        return Err(anyhow!("{label} package may have at most one checksum"));
    }
    for checksum in checksums {
        let object = checksum
            .as_object()
            .ok_or_else(|| anyhow!("{label} checksum must be an object"))?;
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != BTreeSet::from(["algorithm", "checksumValue"])
            || object["algorithm"] != "SHA256"
        {
            return Err(anyhow!(
                "{label} checksum must contain only algorithm SHA256 and checksumValue"
            ));
        }
        let value = object["checksumValue"]
            .as_str()
            .ok_or_else(|| anyhow!("{label} checksumValue must be a string"))?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(anyhow!(
                "{label} checksumValue must be 64 lowercase hexadecimal digits"
            ));
        }
    }
    Ok(())
}

fn validate_provenance_notice_representation(
    provenance: &serde_json::Value,
    notices: &[u8],
) -> Result<()> {
    if provenance["schema_version"] != 1
        || provenance["status"] != "technical_provenance_only"
        || provenance.pointer("/legal_effect/approval_status")
            != Some(&serde_json::json!("not_approved"))
        || provenance.pointer("/legal_effect/approval_reference") != Some(&serde_json::Value::Null)
    {
        return Err(anyhow!(
            "packaged third-party licence provenance must remain schema-v1 technical evidence with no approval claim"
        ));
    }
    let notices = std::str::from_utf8(notices)
        .context("packaged third-party licence bundle must be UTF-8")?;
    let supplemental = notices
        .split_once("SUPPLEMENTAL LICENCE PROVENANCE\n")
        .map(|(_, value)| value)
        .ok_or_else(|| {
            anyhow!("packaged third-party licence bundle lacks supplemental provenance section")
        })?;
    let sources = provenance["sources"]
        .as_array()
        .filter(|values| !values.is_empty())
        .ok_or_else(|| {
            anyhow!("third-party licence provenance sources must be a nonempty array")
        })?;
    let mut source_ids = BTreeSet::new();
    for source in sources {
        let source_id = source["id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("third-party licence provenance source has no id"))?;
        if !source_ids.insert(source_id) {
            return Err(anyhow!(
                "third-party licence provenance repeats source id {source_id}"
            ));
        }
        let source_marker = format!("Provenance source: {source_id}\n");
        if supplemental.match_indices(&source_marker).count() != 1 {
            return Err(anyhow!(
                "third-party licence bundle must represent provenance source {source_id} exactly once"
            ));
        }
        let section = supplemental
            .split_once(&source_marker)
            .map(|(_, tail)| {
                tail.split("\n------------------------------------------------------------------------\nProvenance source:")
                    .next()
                    .unwrap_or(tail)
            })
            .expect("unique marker checked above");
        let expected_files = match source["kind"].as_str() {
            Some("upstream_git_blob") => {
                let tracked_path = source["tracked_path"].as_str().ok_or_else(|| {
                    anyhow!("upstream Git-blob provenance source lacks tracked_path")
                })?;
                if !tracked_path.starts_with("plugin/.third-party/license-supplements/")
                    || source["byte_length"]
                        .as_u64()
                        .is_none_or(|value| value == 0)
                {
                    return Err(anyhow!(
                        "upstream Git-blob provenance source has an invalid source-only tracked path or byte length"
                    ));
                }
                vec![(
                    source["repository_path"].as_str().ok_or_else(|| {
                        anyhow!("upstream Git-blob provenance source lacks repository_path")
                    })?,
                    require_json_sha256(source, "sha256")?,
                )]
            }
            Some("checksum_verified_crate_archive_members") => source["archive_members"]
                .as_array()
                .filter(|members| !members.is_empty())
                .ok_or_else(|| anyhow!("crate-archive provenance source has no archive members"))?
                .iter()
                .map(|member| {
                    Ok((
                        member["path"]
                            .as_str()
                            .ok_or_else(|| anyhow!("crate-archive provenance member lacks path"))?,
                        require_json_sha256(member, "sha256")?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
            _ => {
                return Err(anyhow!(
                    "third-party licence provenance source has an unknown kind"
                ))
            }
        };
        for (path, digest) in expected_files {
            let marker = format!("----- BEGIN {path} (SHA-256 {digest}) -----\n");
            if section.match_indices(&marker).count() != 1 {
                return Err(anyhow!(
                    "third-party licence bundle does not represent {source_id} member {path} exactly once"
                ));
            }
        }
    }
    let bindings = provenance["package_bindings"]
        .as_array()
        .filter(|values| !values.is_empty())
        .ok_or_else(|| {
            anyhow!("third-party licence provenance package_bindings must be a nonempty array")
        })?;
    let bound_source_ids = bindings
        .iter()
        .map(|binding| {
            binding["source_id"]
                .as_str()
                .ok_or_else(|| anyhow!("third-party licence provenance binding lacks source_id"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if bound_source_ids != source_ids {
        return Err(anyhow!(
            "third-party licence provenance sources and package bindings do not form a closed set"
        ));
    }
    Ok(())
}

fn require_json_u64(value: &serde_json::Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| anyhow!("third-party licence policy {field} must be an unsigned integer"))
}

fn require_json_sha256<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    let digest = value[field]
        .as_str()
        .ok_or_else(|| anyhow!("third-party licence policy {field} must be a string"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(anyhow!(
            "third-party licence policy {field} must be 64 lowercase hexadecimal digits"
        ));
    }
    Ok(digest)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpbManifest {
    pub manifest_version: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub license: String,
    pub author: McpbAuthor,
    pub server: McpbServer,
    pub compatibility: McpbCompatibility,
    pub tools_generated: bool,
    pub user_config: BTreeMap<String, McpbUserConfig>,
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<McpbMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpbUserConfig {
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub description: String,
    pub required: bool,
    pub default: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpbMetadata {
    #[serde(rename = "io.github.andagni.autocad-mcp")]
    pub autocad_mcp: McpbAutocadMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpbAutocadMetadata {
    #[serde(rename = "package-mode")]
    pub package_mode: PackageMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpbAuthor {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpbServer {
    #[serde(rename = "type")]
    pub kind: String,
    pub entry_point: String,
    pub mcp_config: McpbConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpbConfig {
    pub command: String,
    pub args: Vec<String>,
    pub env: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpbCompatibility {
    pub claude_desktop: String,
    pub platforms: Vec<String>,
}

pub fn manifest_for(target: PackageTarget, plugin: &PluginMetadata) -> McpbManifest {
    manifest_for_mode(target, PackageMode::Release, plugin)
}

pub fn manifest_for_mode(
    target: PackageTarget,
    mode: PackageMode,
    plugin: &PluginMetadata,
) -> McpbManifest {
    let entry_point = target.binary_entry_point();
    let command_entry_point = target.command_entry_point();
    McpbManifest {
        manifest_version: "0.3".to_string(),
        name: mode.manifest_name(&plugin.name),
        version: plugin.version.clone(),
        description: mode.manifest_description(&plugin.description),
        license: plugin.license.clone(),
        author: McpbAuthor {
            name: plugin.author_name.clone(),
        },
        server: McpbServer {
            kind: "binary".to_string(),
            entry_point: entry_point.clone(),
            mcp_config: McpbConfig {
                command: format!("${{__dirname}}/{command_entry_point}"),
                args: mode.launch_args(),
                env: title_block_profiles_environment(),
            },
        },
        compatibility: McpbCompatibility {
            claude_desktop: ">=1.0.0".to_string(),
            platforms: vec![target.platform().to_string()],
        },
        tools_generated: true,
        user_config: title_block_profiles_user_config(),
        metadata: (mode == PackageMode::Preview).then_some(McpbMetadata {
            autocad_mcp: McpbAutocadMetadata {
                package_mode: PackageMode::Preview,
            },
        }),
    }
}

pub fn title_block_profiles_user_config() -> BTreeMap<String, McpbUserConfig> {
    BTreeMap::from([(
        TITLE_BLOCK_PROFILES_USER_CONFIG_KEY.to_string(),
        McpbUserConfig {
            kind: "file".to_string(),
            title: "Administrator title-block profiles".to_string(),
            description:
                "Optional administrator-reviewed JSON file extending exact title-block profiles."
                    .to_string(),
            required: false,
            default: String::new(),
        },
    )])
}

pub fn title_block_profiles_environment() -> serde_json::Map<String, serde_json::Value> {
    serde_json::Map::from_iter([(
        TITLE_BLOCK_PROFILES_ENV.to_string(),
        serde_json::Value::String(TITLE_BLOCK_PROFILES_USER_CONFIG_VARIABLE.to_string()),
    )])
}

pub fn validate_manifest(manifest: &McpbManifest, target: PackageTarget) -> Result<PackageMode> {
    let expected_entry = target.binary_entry_point();
    let expected_command = format!("${{__dirname}}/{}", target.command_entry_point());
    let mode = match manifest.metadata.as_ref() {
        None => PackageMode::Release,
        Some(McpbMetadata {
            autocad_mcp:
                McpbAutocadMetadata {
                    package_mode: PackageMode::Preview,
                },
        }) => PackageMode::Preview,
        Some(McpbMetadata {
            autocad_mcp:
                McpbAutocadMetadata {
                    package_mode: PackageMode::Release,
                },
        }) => {
            return Err(anyhow!(
                "Release MCPB must omit the Preview package-mode marker"
            ))
        }
    };
    if manifest.manifest_version != "0.3" {
        return Err(anyhow!("MCPB manifest_version must be 0.3"));
    }
    if !manifest.tools_generated {
        return Err(anyhow!("MCPB tools_generated must be true"));
    }
    if manifest.user_config != title_block_profiles_user_config() {
        return Err(anyhow!(
            "MCPB user_config must declare exactly the optional administrator title-block profiles file"
        ));
    }
    if manifest.license != PROJECT_LICENSE {
        return Err(anyhow!("MCPB license must be {PROJECT_LICENSE}"));
    }
    if manifest.server.kind != "binary" {
        return Err(anyhow!("MCPB server.type must be binary"));
    }
    if manifest.server.entry_point != expected_entry {
        return Err(anyhow!(
            "MCPB entry_point must be {expected_entry}; got {}",
            manifest.server.entry_point
        ));
    }
    if manifest.server.mcp_config.command != expected_command {
        return Err(anyhow!(
            "MCPB command must be {expected_command}; got {}",
            manifest.server.mcp_config.command
        ));
    }
    if manifest.server.mcp_config.args != mode.launch_args() {
        return Err(anyhow!(
            "{mode:?} MCPB args must be exactly {:?}",
            mode.launch_args()
        ));
    }
    if manifest.compatibility.platforms != vec![target.platform().to_string()] {
        return Err(anyhow!(
            "MCPB compatibility.platforms must be [{}]",
            target.platform()
        ));
    }
    if manifest.compatibility.claude_desktop != ">=1.0.0" {
        return Err(anyhow!("MCPB compatibility.claude_desktop must be >=1.0.0"));
    }
    let profile_environment = title_block_profiles_environment();
    if manifest.server.mcp_config.env.get(TITLE_BLOCK_PROFILES_ENV)
        != profile_environment.get(TITLE_BLOCK_PROFILES_ENV)
    {
        return Err(anyhow!(
            "MCPB server environment must bind {TITLE_BLOCK_PROFILES_ENV} to {TITLE_BLOCK_PROFILES_USER_CONFIG_VARIABLE}"
        ));
    }
    if target == PackageTarget::MacosArm64 && manifest.server.mcp_config.env != profile_environment
    {
        return Err(anyhow!(
            "macOS MCPB server environment contains configuration outside the title-block profiles binding"
        ));
    }
    match (target, mode) {
        (PackageTarget::WindowsX64, PackageMode::Preview)
            if stable_windows_version_major(&manifest.version) != Some(0) =>
        {
            return Err(anyhow!(
                "Windows Preview MCPB version must be stable and pre-1.0"
            ));
        }
        (PackageTarget::WindowsX64, PackageMode::Release)
            if !stable_windows_version_major(&manifest.version).is_some_and(|major| major >= 1) =>
        {
            return Err(anyhow!(
                "Windows Release MCPB version must be stable and at least 1.0.0"
            ));
        }
        _ => {}
    }
    if mode == PackageMode::Preview {
        if target != PackageTarget::WindowsX64 {
            return Err(anyhow!("Preview packages require windows-x64"));
        }
        if !manifest.name.ends_with(PREVIEW_NAME_SUFFIX)
            || !manifest.description.ends_with(PREVIEW_DESCRIPTION_SUFFIX)
        {
            return Err(anyhow!(
                "Preview MCPB name and description must be visibly marked Preview"
            ));
        }
    }
    Ok(mode)
}

fn stable_windows_version_major(version: &str) -> Option<u64> {
    let components = version.split('.').collect::<Vec<_>>();
    if components.len() != 3
        || components.iter().any(|component| {
            component.is_empty()
                || !component.bytes().all(|byte| byte.is_ascii_digit())
                || (component.len() > 1 && component.starts_with('0'))
        })
    {
        return None;
    }
    components[0].parse::<u64>().ok()
}
