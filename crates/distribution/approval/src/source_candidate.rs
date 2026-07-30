use crate::{DistributionMode, GitObjectFormat};
use serde::{Deserialize, Serialize};

pub const SOURCE_BUNDLE_MANIFEST_SCHEMA_VERSION: u32 = 3;
pub const SOURCE_BUNDLE_MANIFEST_PATH: &str = "source-bundle-manifest.json";
pub const SOURCE_BUNDLE_ARTIFACT_KIND: &str = "autocad-mcp-windows-x86_64-build-source";
pub const SOURCE_BUNDLE_BUILD_RECIPE_PATH: &str = "BUILD-WINDOWS-X86_64.txt";
pub const SOURCE_BUNDLE_OFFLINE_CONFIG_PATH: &str = "workspace/.cargo/config.toml";
pub const SOURCE_BUNDLE_PROFILE: &str = "release";
pub const SOURCE_BUNDLE_TREE_DIGEST_METHOD: &str =
    "SHA-256 over sorted path, normalized mode, byte length, and content digest";

/// Versioned declarative contract shared by the independent source-bundle
/// generator and verifiers. This module contains data shapes and immutable
/// values only; it deliberately owns no archive generation or verification
/// algorithm.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBundleManifest {
    pub schema_version: u32,
    pub artifact_kind: String,
    pub git_object_format: GitObjectFormat,
    pub source_commit: String,
    pub source_tree_oid: String,
    pub cargo_lock_sha256: String,
    pub dependency_input_closure_sha256: String,
    pub rust_toolchain_sha256: String,
    pub build_recipe_sha256: String,
    pub rust_toolchain: String,
    pub target: String,
    pub profile: String,
    pub package_mode: DistributionMode,
    pub cargo_incremental: bool,
    pub roots: Vec<SourceBundleRoot>,
    pub packages: Vec<SourceBundlePackage>,
    pub workspace: SourceBundleTree,
    pub generated_files: Vec<SourceBundleFile>,
    pub exclusions: Vec<SourceBundleExclusion>,
    pub archive_policy: SourceBundleArchivePolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBundleRoot {
    pub name: String,
    pub version: String,
    pub manifest_path: String,
    pub cargo_metadata_arguments: Vec<String>,
    pub dependency_kinds: [String; 2],
    pub excluded_dependency_kind: String,
    pub package_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBundlePackage {
    pub name: String,
    pub version: String,
    pub source: String,
    pub cargo_lock_checksum: Option<String>,
    pub roots: Vec<String>,
    pub vendor: Option<SourceBundleVendor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBundleVendor {
    pub path: String,
    pub crate_archive_sha256: String,
    pub file_count: usize,
    pub tree_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBundleTree {
    pub path: String,
    pub file_count: usize,
    pub tree_sha256: String,
    pub digest_method: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBundleFile {
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBundleExclusion {
    pub package: String,
    pub version: String,
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBundleArchivePolicy {
    pub format: String,
    pub compression: String,
    pub entry_order: String,
    pub timestamp: String,
    pub regular_file_modes: [String; 2],
    pub zip64: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_contract_is_closed_and_round_trips() {
        let manifest = SourceBundleManifest {
            schema_version: SOURCE_BUNDLE_MANIFEST_SCHEMA_VERSION,
            artifact_kind: SOURCE_BUNDLE_ARTIFACT_KIND.to_owned(),
            git_object_format: GitObjectFormat::Sha1,
            source_commit: "1".repeat(40),
            source_tree_oid: "2".repeat(40),
            cargo_lock_sha256: "3".repeat(64),
            dependency_input_closure_sha256: "4".repeat(64),
            rust_toolchain_sha256: "5".repeat(64),
            build_recipe_sha256: "6".repeat(64),
            rust_toolchain: "1.88.0".to_owned(),
            target: crate::WINDOWS_X86_64_TARGET.to_owned(),
            profile: SOURCE_BUNDLE_PROFILE.to_owned(),
            package_mode: DistributionMode::Release,
            cargo_incremental: false,
            roots: Vec::new(),
            packages: Vec::new(),
            workspace: SourceBundleTree {
                path: "workspace".to_owned(),
                file_count: 1,
                tree_sha256: "7".repeat(64),
                digest_method: SOURCE_BUNDLE_TREE_DIGEST_METHOD.to_owned(),
            },
            generated_files: Vec::new(),
            exclusions: Vec::new(),
            archive_policy: SourceBundleArchivePolicy {
                format: "ZIP32".to_owned(),
                compression: "stored".to_owned(),
                entry_order: "ascending UTF-8 path".to_owned(),
                timestamp: "1980-01-01T00:00:00Z".to_owned(),
                regular_file_modes: ["0644".to_owned(), "0755".to_owned()],
                zip64: false,
            },
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert_eq!(
            serde_json::from_slice::<SourceBundleManifest>(&bytes).unwrap(),
            manifest
        );
        let mut open = serde_json::to_value(&manifest).unwrap();
        open["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SourceBundleManifest>(open).is_err());
    }
}
