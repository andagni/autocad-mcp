//! Portable, package-owned AutoCAD activation policy.
//!
//! This module deliberately stops at the platform boundary. It validates the
//! immutable activation catalogue and profile assets, performs deterministic
//! selection over already-inspected installation candidates, and pins one
//! verified selection for a server lifetime. Windows registry discovery,
//! executable identity inspection, and Release signature verification are
//! injected authorities; none of them is inferred here.

use std::{
    collections::{BTreeSet, HashSet},
    fmt,
    path::{Component, Path, PathBuf},
    sync::{Arc, Condvar, Mutex, OnceLock},
};

use serde::{
    de::{Error as _, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::certified_arg;

pub const ACTIVATION_CATALOGUE_SCHEMA_VERSION: u32 = 1;
pub const ACTIVATION_CATALOGUE_ARTIFACT_KIND: &str = "preview_candidate_activation_catalogue";
pub const ACTIVATION_CATALOGUE_AUTHORITY: &str = "candidate_only_no_support_claim";
pub const ACTIVATION_CATALOGUE_BYTES: &[u8] =
    include_bytes!("../resources/autocad-activation-catalogue.json");
pub const ACTIVATION_BUNDLE_CATALOGUE_PATH: &str = "autocad-activation-catalogue.json";
const SOURCE_RESOURCE_PREFIX: &str = "crates/autocad-mcp/resources/";
const SOURCE_PROFILE_PREFIX: &str = "crates/autocad-mcp/resources/activation-profiles/";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ActivationMode {
    Disabled,
    Preview,
    Release,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum MutationCapability {
    DwgLayerMutation,
    DwgTitleBlockMutation,
    Plot,
    XrefMutation,
}

impl MutationCapability {
    pub const ALL: [Self; 4] = [
        Self::DwgLayerMutation,
        Self::DwgTitleBlockMutation,
        Self::Plot,
        Self::XrefMutation,
    ];
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ActivationProduct {
    Autocad,
}

impl ActivationProduct {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Autocad => "autocad",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ActivationEdition {
    Full,
}

impl ActivationEdition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
pub enum ActivationArchitecture {
    #[serde(rename = "x86_64")]
    X86_64,
}

impl ActivationArchitecture {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ActivationProfile {
    pub arg_path: String,
    pub arg_sha256: String,
    pub policy_path: String,
    pub policy_id: String,
    pub policy_sha256: String,
    pub profile_root: String,
    pub profile_name: String,
    arg_bytes: Arc<[u8]>,
    policy_bytes: Arc<[u8]>,
}

impl ActivationProfile {
    pub fn arg_bytes(&self) -> &[u8] {
        &self.arg_bytes
    }

    pub fn policy_bytes(&self) -> &[u8] {
        &self.policy_bytes
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ActivationTarget {
    pub target_id: String,
    pub product: ActivationProduct,
    pub edition: ActivationEdition,
    pub architecture: ActivationArchitecture,
    pub release_year: u16,
    pub registry_family: String,
    pub product_language_key: String,
    pub ui_locale: String,
    pub maintained_target: bool,
    pub profile: ActivationProfile,
    pub operation_families: Vec<MutationCapability>,
    pub drawing_formats: Vec<String>,
}

impl ActivationTarget {
    pub fn supports(&self, capability: MutationCapability) -> bool {
        self.operation_families.binary_search(&capability).is_ok()
    }

    fn exact_tuple(&self) -> ActivationTuple<'_> {
        ActivationTuple {
            product: self.product.as_str(),
            edition: self.edition.as_str(),
            architecture: self.architecture.as_str(),
            release_year: self.release_year,
            registry_family: &self.registry_family,
            product_language_key: &self.product_language_key,
            ui_locale: &self.ui_locale,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ActivationCatalogue {
    pub schema_version: u32,
    pub artifact_kind: String,
    pub authority: String,
    pub sha256: String,
    targets: Arc<[ActivationTarget]>,
}

impl ActivationCatalogue {
    pub fn targets(&self) -> &[ActivationTarget] {
        &self.targets
    }

    pub fn target(&self, target_id: &str) -> Option<&ActivationTarget> {
        self.targets
            .binary_search_by_key(&target_id, |target| target.target_id.as_str())
            .ok()
            .map(|index| &self.targets[index])
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InstalledCandidate {
    /// Stable canonical registry/inventory identity supplied by discovery.
    pub canonical_id: String,
    /// Canonical executable path supplied by discovery.
    pub executable: PathBuf,
    pub product: String,
    pub edition: String,
    pub architecture: String,
    pub release_year: u16,
    pub registry_family: String,
    pub product_language_key: String,
    pub ui_locale: String,
}

impl InstalledCandidate {
    fn exact_tuple(&self) -> ActivationTuple<'_> {
        ActivationTuple {
            product: &self.product,
            edition: &self.edition,
            architecture: &self.architecture,
            release_year: self.release_year,
            registry_family: &self.registry_family,
            product_language_key: &self.product_language_key,
            ui_locale: &self.ui_locale,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct ActivationTuple<'a> {
    product: &'a str,
    edition: &'a str,
    architecture: &'a str,
    release_year: u16,
    registry_family: &'a str,
    product_language_key: &'a str,
    ui_locale: &'a str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifiedEngineIdentity {
    /// Canonical path observed by the verifier.
    pub canonical_executable: PathBuf,
    /// Opaque, stable file identity. The Windows implementation will bind this
    /// to non-launching executable facts rather than path text alone.
    pub identity_token: String,
}

#[derive(Clone)]
pub struct SelectedActivation {
    pub target: ActivationTarget,
    pub candidate: InstalledCandidate,
    pub engine_identity: VerifiedEngineIdentity,
    pub(crate) launch_guard: Option<Arc<SelectedLaunchGuard>>,
}

impl fmt::Debug for SelectedActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedActivation")
            .field("target", &self.target)
            .field("candidate", &self.candidate)
            .field("engine_identity", &self.engine_identity)
            .finish_non_exhaustive()
    }
}

impl PartialEq for SelectedActivation {
    fn eq(&self, other: &Self) -> bool {
        self.target == other.target
            && self.candidate == other.candidate
            && self.engine_identity == other.engine_identity
    }
}

impl Eq for SelectedActivation {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ActivationError {
    CatalogueInvalid(String),
    AssetInvalid(String),
    Disabled,
    ReleaseQualificationUnavailable,
    ReleaseQualificationInvalid(String),
    DiscoveryFailed(String),
    NoEligibleCandidate,
    ExactOverrideUnavailable(PathBuf),
    VerificationFailed(String),
    SelectedEngineChanged(String),
    CapabilityUnsupported {
        target_id: String,
        capability: MutationCapability,
    },
    DrawingFormatUnsupported {
        target_id: String,
        drawing_format: String,
    },
}

impl ActivationError {
    fn is_permanent_without_external_change(&self) -> bool {
        matches!(
            self,
            Self::CatalogueInvalid(_)
                | Self::AssetInvalid(_)
                | Self::Disabled
                | Self::ReleaseQualificationUnavailable
                | Self::ReleaseQualificationInvalid(_)
        )
    }
}

impl fmt::Display for ActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CatalogueInvalid(detail) => {
                write!(formatter, "invalid AutoCAD activation catalogue: {detail}")
            }
            Self::AssetInvalid(detail) => {
                write!(formatter, "invalid AutoCAD activation asset: {detail}")
            }
            Self::Disabled => write!(formatter, "AutoCAD mutation activation is disabled"),
            Self::ReleaseQualificationUnavailable => write!(
                formatter,
                "Release AutoCAD activation is unavailable without verified qualification"
            ),
            Self::ReleaseQualificationInvalid(detail) => {
                write!(formatter, "invalid verified Release qualification: {detail}")
            }
            Self::DiscoveryFailed(detail) => {
                write!(formatter, "AutoCAD installation discovery failed: {detail}")
            }
            Self::NoEligibleCandidate => {
                write!(formatter, "no catalogue-eligible full AutoCAD installation was found")
            }
            Self::ExactOverrideUnavailable(path) => write!(
                formatter,
                "exact AutoCAD engine override did not match an eligible registered installation: {}",
                path.display()
            ),
            Self::VerificationFailed(detail) => {
                write!(formatter, "selected AutoCAD engine verification failed: {detail}")
            }
            Self::SelectedEngineChanged(detail) => write!(
                formatter,
                "selected AutoCAD engine changed; restart the server: {detail}"
            ),
            Self::CapabilityUnsupported {
                target_id,
                capability,
            } => write!(
                formatter,
                "selected AutoCAD activation target {target_id} does not support {capability:?}"
            ),
            Self::DrawingFormatUnsupported {
                target_id,
                drawing_format,
            } => write!(
                formatter,
                "selected AutoCAD activation target {target_id} does not admit drawing format {drawing_format}"
            ),
        }
    }
}

impl std::error::Error for ActivationError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogueDocument {
    schema_version: u32,
    artifact_kind: CatalogueArtifactKind,
    authority: CatalogueAuthority,
    targets: Vec<TargetDocument>,
}

#[derive(Debug, Deserialize)]
enum CatalogueArtifactKind {
    #[serde(rename = "preview_candidate_activation_catalogue")]
    PreviewCandidateActivationCatalogue,
}

#[derive(Debug, Deserialize)]
enum CatalogueAuthority {
    #[serde(rename = "candidate_only_no_support_claim")]
    CandidateOnlyNoSupportClaim,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetDocument {
    target_id: String,
    product: ActivationProduct,
    edition: ActivationEdition,
    architecture: ActivationArchitecture,
    release_year: u16,
    registry_family: String,
    product_language_key: String,
    ui_locale: String,
    maintained_target: bool,
    profile: ProfileDocument,
    operation_families: Vec<MutationCapability>,
    drawing_formats: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileDocument {
    arg_path: String,
    arg_sha256: String,
    policy_path: String,
    policy_id: String,
    policy_sha256: String,
}

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate JSON key {key:?}")));
            }
            let value = map.next_value::<StrictJsonValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

fn parse_strict_json(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let strict = StrictJsonValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(strict.0)
}

type EmbeddedAssetResolver = fn(&str) -> Option<&'static [u8]>;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct EmbeddedAsset {
    source_path: &'static str,
    package_path: &'static str,
    bytes: &'static [u8],
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EmbeddedActivationBundleFile {
    /// Normalized path relative to the package's activation-resource root.
    pub path: &'static str,
    /// Exact embedded source bytes. Callers must stage these bytes unchanged.
    pub bytes: &'static [u8],
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EmbeddedActivationBundle {
    pub catalogue_sha256: String,
    /// Catalogue first, followed by every referenced ARG/policy asset in
    /// deterministic path order.
    pub files: Vec<EmbeddedActivationBundleFile>,
}

fn embedded_asset_record(path: &str) -> Option<EmbeddedAsset> {
    let asset = match path {
        "crates/autocad-mcp/resources/activation-profiles/autocad-2018-r22.0-en-us-preview.arg" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2018-r22.0-en-us-preview.arg",
            package_path: "activation-profiles/autocad-2018-r22.0-en-us-preview.arg",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2018-r22.0-en-us-preview.arg"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2018-r22.0-en-us-preview.policy.json" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2018-r22.0-en-us-preview.policy.json",
            package_path: "activation-profiles/autocad-2018-r22.0-en-us-preview.policy.json",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2018-r22.0-en-us-preview.policy.json"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2019-r23.0-en-us-preview.arg" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2019-r23.0-en-us-preview.arg",
            package_path: "activation-profiles/autocad-2019-r23.0-en-us-preview.arg",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2019-r23.0-en-us-preview.arg"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2019-r23.0-en-us-preview.policy.json" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2019-r23.0-en-us-preview.policy.json",
            package_path: "activation-profiles/autocad-2019-r23.0-en-us-preview.policy.json",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2019-r23.0-en-us-preview.policy.json"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2020-r23.1-en-us-preview.arg" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2020-r23.1-en-us-preview.arg",
            package_path: "activation-profiles/autocad-2020-r23.1-en-us-preview.arg",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2020-r23.1-en-us-preview.arg"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2020-r23.1-en-us-preview.policy.json" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2020-r23.1-en-us-preview.policy.json",
            package_path: "activation-profiles/autocad-2020-r23.1-en-us-preview.policy.json",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2020-r23.1-en-us-preview.policy.json"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2021-r24.0-en-us-preview.arg" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2021-r24.0-en-us-preview.arg",
            package_path: "activation-profiles/autocad-2021-r24.0-en-us-preview.arg",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2021-r24.0-en-us-preview.arg"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2021-r24.0-en-us-preview.policy.json" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2021-r24.0-en-us-preview.policy.json",
            package_path: "activation-profiles/autocad-2021-r24.0-en-us-preview.policy.json",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2021-r24.0-en-us-preview.policy.json"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2022-r24.1-en-us-preview.arg" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2022-r24.1-en-us-preview.arg",
            package_path: "activation-profiles/autocad-2022-r24.1-en-us-preview.arg",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2022-r24.1-en-us-preview.arg"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2022-r24.1-en-us-preview.policy.json" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2022-r24.1-en-us-preview.policy.json",
            package_path: "activation-profiles/autocad-2022-r24.1-en-us-preview.policy.json",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2022-r24.1-en-us-preview.policy.json"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2023-r24.2-en-us-preview.arg" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2023-r24.2-en-us-preview.arg",
            package_path: "activation-profiles/autocad-2023-r24.2-en-us-preview.arg",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2023-r24.2-en-us-preview.arg"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2023-r24.2-en-us-preview.policy.json" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2023-r24.2-en-us-preview.policy.json",
            package_path: "activation-profiles/autocad-2023-r24.2-en-us-preview.policy.json",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2023-r24.2-en-us-preview.policy.json"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2024-r24.3-en-us-preview.arg" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2024-r24.3-en-us-preview.arg",
            package_path: "activation-profiles/autocad-2024-r24.3-en-us-preview.arg",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2024-r24.3-en-us-preview.arg"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2024-r24.3-en-us-preview.policy.json" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2024-r24.3-en-us-preview.policy.json",
            package_path: "activation-profiles/autocad-2024-r24.3-en-us-preview.policy.json",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2024-r24.3-en-us-preview.policy.json"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2025-r25.0-en-us-preview.arg" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2025-r25.0-en-us-preview.arg",
            package_path: "activation-profiles/autocad-2025-r25.0-en-us-preview.arg",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2025-r25.0-en-us-preview.arg"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2025-r25.0-en-us-preview.policy.json" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2025-r25.0-en-us-preview.policy.json",
            package_path: "activation-profiles/autocad-2025-r25.0-en-us-preview.policy.json",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2025-r25.0-en-us-preview.policy.json"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2026-r25.1-en-us-preview.arg" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2026-r25.1-en-us-preview.arg",
            package_path: "activation-profiles/autocad-2026-r25.1-en-us-preview.arg",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2026-r25.1-en-us-preview.arg"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2026-r25.1-en-us-preview.policy.json" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2026-r25.1-en-us-preview.policy.json",
            package_path: "activation-profiles/autocad-2026-r25.1-en-us-preview.policy.json",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2026-r25.1-en-us-preview.policy.json"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2027-r26.0-en-us-preview.arg" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2027-r26.0-en-us-preview.arg",
            package_path: "activation-profiles/autocad-2027-r26.0-en-us-preview.arg",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2027-r26.0-en-us-preview.arg"
            ),
        },
        "crates/autocad-mcp/resources/activation-profiles/autocad-2027-r26.0-en-us-preview.policy.json" => EmbeddedAsset {
            source_path: "crates/autocad-mcp/resources/activation-profiles/autocad-2027-r26.0-en-us-preview.policy.json",
            package_path: "activation-profiles/autocad-2027-r26.0-en-us-preview.policy.json",
            bytes: include_bytes!(
                "../resources/activation-profiles/autocad-2027-r26.0-en-us-preview.policy.json"
            ),
        },
        _ => return None,
    };
    Some(asset)
}

fn embedded_asset(path: &str) -> Option<&'static [u8]> {
    embedded_asset_record(path).map(|asset| asset.bytes)
}

static EMBEDDED_ACTIVATION_CATALOGUE: OnceLock<Result<ActivationCatalogue, ActivationError>> =
    OnceLock::new();

pub fn embedded_activation_catalogue() -> Result<&'static ActivationCatalogue, ActivationError> {
    EMBEDDED_ACTIVATION_CATALOGUE
        .get_or_init(|| parse_catalogue(ACTIVATION_CATALOGUE_BYTES, embedded_asset))
        .as_ref()
        .map_err(Clone::clone)
}

pub fn activation_catalogue_sha256() -> Result<&'static str, ActivationError> {
    embedded_activation_catalogue().map(|catalogue| catalogue.sha256.as_str())
}

pub fn embedded_activation_bundle() -> Result<EmbeddedActivationBundle, ActivationError> {
    let catalogue = embedded_activation_catalogue()?;
    let mut source_paths = BTreeSet::new();
    for target in catalogue.targets() {
        source_paths.insert(target.profile.arg_path.as_str());
        source_paths.insert(target.profile.policy_path.as_str());
    }

    let mut assets = source_paths
        .into_iter()
        .map(|source_path| {
            let asset = embedded_asset_record(source_path).ok_or_else(|| {
                ActivationError::AssetInvalid(format!(
                    "validated catalogue asset disappeared from the closed bundle: {source_path}"
                ))
            })?;
            if asset.source_path != source_path {
                return Err(ActivationError::AssetInvalid(format!(
                    "closed bundle source-path mismatch for {source_path}"
                )));
            }
            Ok(EmbeddedActivationBundleFile {
                path: asset.package_path,
                bytes: asset.bytes,
            })
        })
        .collect::<Result<Vec<_>, ActivationError>>()?;
    assets.sort_by_key(|asset| asset.path);

    let mut files = Vec::with_capacity(assets.len() + 1);
    files.push(EmbeddedActivationBundleFile {
        path: ACTIVATION_BUNDLE_CATALOGUE_PATH,
        bytes: ACTIVATION_CATALOGUE_BYTES,
    });
    files.extend(assets);
    Ok(EmbeddedActivationBundle {
        catalogue_sha256: catalogue.sha256.clone(),
        files,
    })
}

fn parse_catalogue(
    bytes: &[u8],
    resolve_asset: EmbeddedAssetResolver,
) -> Result<ActivationCatalogue, ActivationError> {
    let value = parse_strict_json(bytes)
        .map_err(|error| ActivationError::CatalogueInvalid(error.to_string()))?;
    let document: CatalogueDocument = serde_json::from_value(value)
        .map_err(|error| ActivationError::CatalogueInvalid(error.to_string()))?;
    if document.schema_version != ACTIVATION_CATALOGUE_SCHEMA_VERSION {
        return Err(ActivationError::CatalogueInvalid(format!(
            "schema_version {} is unsupported; expected {}",
            document.schema_version, ACTIVATION_CATALOGUE_SCHEMA_VERSION
        )));
    }
    let _ = (document.artifact_kind, document.authority);
    if document.targets.is_empty() {
        return Err(ActivationError::CatalogueInvalid(
            "targets must not be empty".to_string(),
        ));
    }

    let mut targets = Vec::with_capacity(document.targets.len());
    let mut previous_target_id: Option<String> = None;
    let mut tuples = HashSet::new();
    let mut covered_years = BTreeSet::new();

    for target in document.targets {
        validate_canonical_id(&target.target_id, "target_id")?;
        if previous_target_id
            .as_ref()
            .is_some_and(|previous| previous >= &target.target_id)
        {
            return Err(ActivationError::CatalogueInvalid(
                "targets must be sorted uniquely by target_id".to_string(),
            ));
        }
        previous_target_id = Some(target.target_id.clone());
        validate_registry_family(&target.registry_family)?;
        validate_product_language_key(&target.product_language_key)?;
        if target.ui_locale != "en-US" {
            return Err(ActivationError::CatalogueInvalid(format!(
                "{} ui_locale must be the exact initial locale en-US",
                target.target_id
            )));
        }
        if !(2018..=2027).contains(&target.release_year) {
            return Err(ActivationError::CatalogueInvalid(format!(
                "{} release_year {} is outside the initial 2018-2027 candidate window",
                target.target_id, target.release_year
            )));
        }
        let (expected_family, expected_product_language_key) =
            exact_initial_registry_tuple(target.release_year)
                .expect("validated initial candidate year");
        if target.registry_family != expected_family
            || target.product_language_key != expected_product_language_key
        {
            return Err(ActivationError::CatalogueInvalid(format!(
                "{} must use exact full-AutoCAD en-US registry tuple {}\\{}, observed {}\\{}",
                target.target_id,
                expected_family,
                expected_product_language_key,
                target.registry_family,
                target.product_language_key
            )));
        }
        if target.maintained_target != (2024..=2027).contains(&target.release_year) {
            return Err(ActivationError::CatalogueInvalid(format!(
                "{} maintained_target must be true exactly for initial 2024-2027 targets",
                target.target_id
            )));
        }
        validate_sorted_unique_capabilities(&target.target_id, &target.operation_families)?;
        validate_sorted_unique_drawing_formats(&target.target_id, &target.drawing_formats)?;

        let tuple = (
            target.product.as_str().to_string(),
            target.edition.as_str().to_string(),
            target.architecture.as_str().to_string(),
            target.release_year,
            target.registry_family.clone(),
            target.product_language_key.clone(),
            target.ui_locale.clone(),
        );
        if !tuples.insert(tuple) {
            return Err(ActivationError::CatalogueInvalid(format!(
                "{} duplicates an exact activation tuple",
                target.target_id
            )));
        }
        covered_years.insert(target.release_year);

        let profile = resolve_profile(&target, resolve_asset)?;
        targets.push(ActivationTarget {
            target_id: target.target_id,
            product: target.product,
            edition: target.edition,
            architecture: target.architecture,
            release_year: target.release_year,
            registry_family: target.registry_family,
            product_language_key: target.product_language_key,
            ui_locale: target.ui_locale,
            maintained_target: target.maintained_target,
            profile,
            operation_families: target.operation_families,
            drawing_formats: target.drawing_formats,
        });
    }

    let expected_years = (2018..=2027).collect::<BTreeSet<_>>();
    if covered_years != expected_years {
        return Err(ActivationError::CatalogueInvalid(format!(
            "initial Preview catalogue year coverage must equal 2018-2027; observed={covered_years:?}"
        )));
    }

    Ok(ActivationCatalogue {
        schema_version: ACTIVATION_CATALOGUE_SCHEMA_VERSION,
        artifact_kind: ACTIVATION_CATALOGUE_ARTIFACT_KIND.to_string(),
        authority: ACTIVATION_CATALOGUE_AUTHORITY.to_string(),
        sha256: sha256_hex(bytes),
        targets: targets.into(),
    })
}

fn exact_initial_registry_tuple(release_year: u16) -> Option<(&'static str, &'static str)> {
    match release_year {
        2018 => Some(("R22.0", "ACAD-1001:409")),
        2019 => Some(("R23.0", "ACAD-2001:409")),
        2020 => Some(("R23.1", "ACAD-3001:409")),
        2021 => Some(("R24.0", "ACAD-4101:409")),
        2022 => Some(("R24.1", "ACAD-5101:409")),
        2023 => Some(("R24.2", "ACAD-6101:409")),
        2024 => Some(("R24.3", "ACAD-7101:409")),
        2025 => Some(("R25.0", "ACAD-8101:409")),
        2026 => Some(("R25.1", "ACAD-9101:409")),
        2027 => Some(("R26.0", "ACAD-A101:409")),
        _ => None,
    }
}

fn resolve_profile(
    target: &TargetDocument,
    resolve_asset: EmbeddedAssetResolver,
) -> Result<ActivationProfile, ActivationError> {
    for (label, path) in [
        ("profile.arg_path", target.profile.arg_path.as_str()),
        ("profile.policy_path", target.profile.policy_path.as_str()),
    ] {
        validate_asset_path(path).map_err(|detail| {
            ActivationError::AssetInvalid(format!(
                "{} {label} {path:?}: {detail}",
                target.target_id
            ))
        })?;
    }
    validate_lowercase_sha256(
        &target.profile.arg_sha256,
        &format!("{}.profile.arg_sha256", target.target_id),
    )?;
    validate_lowercase_sha256(
        &target.profile.policy_sha256,
        &format!("{}.profile.policy_sha256", target.target_id),
    )?;
    certified_arg::validate_policy_id(&target.profile.policy_id).map_err(|error| {
        ActivationError::AssetInvalid(format!("{} profile policy_id: {error}", target.target_id))
    })?;

    let arg_bytes = resolve_asset(&target.profile.arg_path).ok_or_else(|| {
        ActivationError::AssetInvalid(format!(
            "{} references unknown ARG asset {}",
            target.target_id, target.profile.arg_path
        ))
    })?;
    let policy_bytes = resolve_asset(&target.profile.policy_path).ok_or_else(|| {
        ActivationError::AssetInvalid(format!(
            "{} references unknown policy asset {}",
            target.target_id, target.profile.policy_path
        ))
    })?;
    require_digest(
        arg_bytes,
        &target.profile.arg_sha256,
        &target.profile.arg_path,
    )?;
    require_digest(
        policy_bytes,
        &target.profile.policy_sha256,
        &target.profile.policy_path,
    )?;

    let inspection = certified_arg::validate_distribution_safe_arg(arg_bytes, policy_bytes)
        .map_err(|error| {
            ActivationError::AssetInvalid(format!(
                "{} profile does not satisfy its closed policy: {error}",
                target.target_id
            ))
        })?;
    require_preview_policy_purpose(&target.target_id, inspection.purpose)?;
    if inspection.policy_id != target.profile.policy_id
        || inspection.raw_arg_sha256 != target.profile.arg_sha256
        || inspection.policy_sha256 != target.profile.policy_sha256
    {
        return Err(ActivationError::AssetInvalid(format!(
            "{} profile inspection identity disagrees with catalogue",
            target.target_id
        )));
    }

    let expected_parent = format!(
        "HKEY_CURRENT_USER\\Software\\Autodesk\\AutoCAD\\{}\\{}\\Profiles\\",
        target.registry_family, target.product_language_key
    );
    let Some(profile_name) = inspection.profile_root.strip_prefix(&expected_parent) else {
        return Err(ActivationError::AssetInvalid(format!(
            "{} profile root {} is not beneath its exact registry-family/product-language tuple",
            target.target_id, inspection.profile_root
        )));
    };
    if profile_name.is_empty()
        || profile_name.contains('\\')
        || profile_name != inspection.profile_name
    {
        return Err(ActivationError::AssetInvalid(format!(
            "{} profile root does not name one exact dedicated profile",
            target.target_id
        )));
    }

    Ok(ActivationProfile {
        arg_path: target.profile.arg_path.clone(),
        arg_sha256: target.profile.arg_sha256.clone(),
        policy_path: target.profile.policy_path.clone(),
        policy_id: target.profile.policy_id.clone(),
        policy_sha256: target.profile.policy_sha256.clone(),
        profile_root: inspection.profile_root,
        profile_name: inspection.profile_name,
        arg_bytes: Arc::from(arg_bytes),
        policy_bytes: Arc::from(policy_bytes),
    })
}

fn require_preview_policy_purpose(
    target_id: &str,
    purpose: certified_arg::CertifiedArgPolicyPurpose,
) -> Result<(), ActivationError> {
    if purpose != certified_arg::CertifiedArgPolicyPurpose::PreviewCandidateActivation {
        return Err(ActivationError::AssetInvalid(format!(
            "{target_id} profile policy purpose must be preview_candidate_activation"
        )));
    }
    Ok(())
}

fn validate_canonical_id(value: &str, label: &str) -> Result<(), ActivationError> {
    if value.is_empty()
        || value != value.trim()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || value.starts_with('-')
        || value.ends_with('-')
    {
        return Err(ActivationError::CatalogueInvalid(format!(
            "{label} must contain only lowercase ASCII letters, digits, and interior hyphens"
        )));
    }
    Ok(())
}

fn validate_registry_family(value: &str) -> Result<(), ActivationError> {
    let bytes = value.as_bytes();
    if bytes.len() != 5
        || bytes[0] != b'R'
        || !bytes[1].is_ascii_digit()
        || !bytes[2].is_ascii_digit()
        || bytes[3] != b'.'
        || !bytes[4].is_ascii_digit()
    {
        return Err(ActivationError::CatalogueInvalid(format!(
            "registry_family {value:?} must have exact form Rnn.n"
        )));
    }
    Ok(())
}

fn validate_product_language_key(value: &str) -> Result<(), ActivationError> {
    if value.is_empty()
        || value != value.trim()
        || value.contains(['\\', '/', '\0'])
        || !value.is_ascii()
    {
        return Err(ActivationError::CatalogueInvalid(format!(
            "product_language_key {value:?} is not one exact registry component"
        )));
    }
    Ok(())
}

fn validate_sorted_unique_capabilities(
    target_id: &str,
    capabilities: &[MutationCapability],
) -> Result<(), ActivationError> {
    if capabilities.is_empty() || capabilities.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ActivationError::CatalogueInvalid(format!(
            "{target_id} operation_families must be nonempty, sorted, and unique"
        )));
    }
    Ok(())
}

fn validate_sorted_unique_drawing_formats(
    target_id: &str,
    drawing_formats: &[String],
) -> Result<(), ActivationError> {
    if drawing_formats.is_empty()
        || drawing_formats.windows(2).any(|pair| pair[0] >= pair[1])
        || drawing_formats.iter().any(|format| {
            format.len() != 6
                || !format.starts_with("AC")
                || !format[2..].bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(ActivationError::CatalogueInvalid(format!(
            "{target_id} drawing_formats must be nonempty, sorted, unique exact ACnnnn values"
        )));
    }
    Ok(())
}

fn validate_asset_path(path: &str) -> Result<(), &'static str> {
    let path = Path::new(path);
    if path.is_absolute()
        || !path.starts_with(SOURCE_PROFILE_PREFIX)
        || path.strip_prefix(SOURCE_RESOURCE_PREFIX).is_err()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(
            "must be a normalized repository-relative path below crates/autocad-mcp/resources/activation-profiles",
        );
    }
    Ok(())
}

fn validate_lowercase_sha256(value: &str, label: &str) -> Result<(), ActivationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ActivationError::AssetInvalid(format!(
            "{label} must contain exactly 64 lowercase hexadecimal digits"
        )));
    }
    Ok(())
}

fn require_digest(bytes: &[u8], expected: &str, path: &str) -> Result<(), ActivationError> {
    let actual = sha256_hex(bytes);
    if actual != expected {
        return Err(ActivationError::AssetInvalid(format!(
            "{path} SHA-256 mismatch: expected {expected}, observed {actual}"
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Opaque output of a future authenticated Release statement verifier.
///
/// There is intentionally no public constructor. The current implementation
/// supplies no signature verifier and therefore no production authority that
/// can create this value.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifiedReleaseQualification {
    catalogue_sha256: String,
    admitted_target_ids: BTreeSet<String>,
}

impl VerifiedReleaseQualification {
    #[cfg(test)]
    fn for_test(catalogue: &ActivationCatalogue, admitted_target_ids: &[&str]) -> Self {
        Self {
            catalogue_sha256: catalogue.sha256.clone(),
            admitted_target_ids: admitted_target_ids
                .iter()
                .map(|target_id| (*target_id).to_string())
                .collect(),
        }
    }
}

pub trait ReleaseQualificationAuthority: Send + Sync {
    fn verified_qualification(
        &self,
        catalogue: &ActivationCatalogue,
    ) -> Result<Option<VerifiedReleaseQualification>, ActivationError>;
}

#[derive(Debug, Default)]
pub struct NoReleaseQualification;

impl ReleaseQualificationAuthority for NoReleaseQualification {
    fn verified_qualification(
        &self,
        _catalogue: &ActivationCatalogue,
    ) -> Result<Option<VerifiedReleaseQualification>, ActivationError> {
        Ok(None)
    }
}

pub trait InstalledCandidateDiscovery: Send + Sync {
    fn discover(
        &self,
        exact_override: Option<&Path>,
    ) -> Result<Vec<InstalledCandidate>, ActivationError>;
}

pub trait SelectedEngineVerifier: Send + Sync {
    fn verify(
        &self,
        candidate: &InstalledCandidate,
        target: &ActivationTarget,
    ) -> Result<VerifiedEngineIdentity, ActivationError>;

    fn acquire_launch_lease(
        &self,
        candidate: &InstalledCandidate,
        target: &ActivationTarget,
    ) -> Result<(VerifiedEngineIdentity, Box<dyn SelectedEngineLease>), ActivationError> {
        self.verify(candidate, target)
            .map(|identity| (identity, Box::new(()) as Box<dyn SelectedEngineLease>))
    }
}

#[doc(hidden)]
pub trait SelectedEngineLease: Send + Sync {}

impl<T: Send + Sync> SelectedEngineLease for T {}

pub(crate) struct SelectedExecutableLaunchLease {
    _lease: Box<dyn SelectedEngineLease>,
}

impl fmt::Debug for SelectedExecutableLaunchLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedExecutableLaunchLease")
            .finish_non_exhaustive()
    }
}

pub(crate) struct SelectedLaunchGuard {
    verifier: Arc<dyn SelectedEngineVerifier>,
    permanent_failure: Mutex<Option<ActivationError>>,
}

impl SelectedLaunchGuard {
    fn new(verifier: Arc<dyn SelectedEngineVerifier>) -> Self {
        Self {
            verifier,
            permanent_failure: Mutex::new(None),
        }
    }

    fn acquire(
        &self,
        selected: &SelectedActivation,
    ) -> Result<SelectedExecutableLaunchLease, ActivationError> {
        let mut failure = self
            .permanent_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(error) = failure.as_ref() {
            return Err(error.clone());
        }
        let (observed, lease) = match self
            .verifier
            .acquire_launch_lease(&selected.candidate, &selected.target)
        {
            Ok(observed) => observed,
            Err(error) => {
                let error = ActivationError::SelectedEngineChanged(error.to_string());
                *failure = Some(error.clone());
                return Err(error);
            }
        };
        if observed != selected.engine_identity {
            let error = ActivationError::SelectedEngineChanged(format!(
                "expected identity {:?}, observed {:?}",
                selected.engine_identity, observed
            ));
            *failure = Some(error.clone());
            return Err(error);
        }
        Ok(SelectedExecutableLaunchLease { _lease: lease })
    }
}

impl SelectedActivation {
    /// Acquire an identity-proved lease over the selected executable at an
    /// actual process-creation boundary. Production Windows leases deny
    /// write/delete replacement and guard the executable's parent namespace
    /// until the caller drops the returned value.
    pub(crate) fn acquire_launch_lease(
        &self,
    ) -> Result<SelectedExecutableLaunchLease, ActivationError> {
        match &self.launch_guard {
            Some(guard) => guard.acquire(self),
            None => Ok(SelectedExecutableLaunchLease {
                _lease: Box::new(()),
            }),
        }
    }

    /// Revalidate the process-lifetime engine binding at an actual launch
    /// boundary. The first mismatch permanently poisons this selection.
    pub(crate) fn revalidate_for_launch(&self) -> Result<(), ActivationError> {
        self.acquire_launch_lease().map(drop)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ActivationSelection {
    pub target: ActivationTarget,
    pub candidate: InstalledCandidate,
}

pub fn select_activation_target(
    catalogue: &ActivationCatalogue,
    mode: ActivationMode,
    qualification: Option<&VerifiedReleaseQualification>,
    installed: &[InstalledCandidate],
    exact_override: Option<&Path>,
) -> Result<ActivationSelection, ActivationError> {
    if mode == ActivationMode::Disabled {
        return Err(ActivationError::Disabled);
    }

    let release_ids = if mode == ActivationMode::Release {
        let qualification =
            qualification.ok_or(ActivationError::ReleaseQualificationUnavailable)?;
        validate_release_qualification(catalogue, qualification)?;
        Some(&qualification.admitted_target_ids)
    } else {
        None
    };

    let considered = match exact_override {
        Some(exact) => {
            let exact_matches = installed
                .iter()
                .filter(|candidate| candidate.executable == exact)
                .collect::<Vec<_>>();
            if exact_matches.len() != 1 {
                return Err(ActivationError::ExactOverrideUnavailable(
                    exact.to_path_buf(),
                ));
            }
            exact_matches
        }
        None => installed.iter().collect(),
    };

    let mut matches = Vec::new();
    for candidate in considered {
        validate_candidate_id(&candidate.canonical_id)?;
        for target in catalogue.targets() {
            if candidate.exact_tuple() != target.exact_tuple() {
                continue;
            }
            if release_ids.is_some_and(|ids| !ids.contains(&target.target_id)) {
                continue;
            }
            matches.push((target, candidate));
        }
    }

    matches.sort_by(
        |(left_target, left_candidate), (right_target, right_candidate)| {
            right_target
                .release_year
                .cmp(&left_target.release_year)
                .then_with(|| left_target.target_id.cmp(&right_target.target_id))
                .then_with(|| {
                    left_candidate
                        .canonical_id
                        .cmp(&right_candidate.canonical_id)
                })
        },
    );
    let Some((target, candidate)) = matches.first() else {
        return match exact_override {
            Some(path) => Err(ActivationError::ExactOverrideUnavailable(
                path.to_path_buf(),
            )),
            None => Err(ActivationError::NoEligibleCandidate),
        };
    };
    Ok(ActivationSelection {
        target: (*target).clone(),
        candidate: (*candidate).clone(),
    })
}

fn validate_release_qualification(
    catalogue: &ActivationCatalogue,
    qualification: &VerifiedReleaseQualification,
) -> Result<(), ActivationError> {
    if qualification.catalogue_sha256 != catalogue.sha256 {
        return Err(ActivationError::ReleaseQualificationInvalid(
            "catalogue digest does not match".to_string(),
        ));
    }
    if qualification.admitted_target_ids.is_empty() {
        return Err(ActivationError::ReleaseQualificationInvalid(
            "qualified target inventory is empty".to_string(),
        ));
    }
    for target_id in &qualification.admitted_target_ids {
        let target = catalogue.target(target_id).ok_or_else(|| {
            ActivationError::ReleaseQualificationInvalid(format!(
                "unknown qualified target {target_id}"
            ))
        })?;
        if !target.maintained_target {
            return Err(ActivationError::ReleaseQualificationInvalid(format!(
                "{target_id} is not a maintained-support target"
            )));
        }
    }
    Ok(())
}

fn validate_candidate_id(value: &str) -> Result<(), ActivationError> {
    validate_canonical_id(value, "installed candidate canonical_id")
}

enum RuntimeState {
    Unselected,
    Selecting,
    Selected(Arc<SelectedActivation>),
    Revalidating(Arc<SelectedActivation>),
    Denied(ActivationError),
}

type ExactOverrideResolver =
    dyn Fn() -> Result<Option<PathBuf>, ActivationError> + Send + Sync + 'static;

pub struct MutationRuntime {
    mode: ActivationMode,
    catalogue: Arc<ActivationCatalogue>,
    discovery: Arc<dyn InstalledCandidateDiscovery>,
    verifier: Arc<dyn SelectedEngineVerifier>,
    release_authority: Arc<dyn ReleaseQualificationAuthority>,
    exact_override_resolver: Arc<ExactOverrideResolver>,
    state: Mutex<RuntimeState>,
    selection_changed: Condvar,
}

impl fmt::Debug for MutationRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MutationRuntime")
            .field("mode", &self.mode)
            .field("catalogue_sha256", &self.catalogue.sha256)
            .field("exact_override_resolver", &"<deferred>")
            .finish_non_exhaustive()
    }
}

impl MutationRuntime {
    pub fn new(
        mode: ActivationMode,
        catalogue: Arc<ActivationCatalogue>,
        discovery: Arc<dyn InstalledCandidateDiscovery>,
        verifier: Arc<dyn SelectedEngineVerifier>,
        release_authority: Arc<dyn ReleaseQualificationAuthority>,
        exact_override: Option<PathBuf>,
    ) -> Self {
        Self::new_with_exact_override_resolver(
            mode,
            catalogue,
            discovery,
            verifier,
            release_authority,
            Arc::new(move || Ok(exact_override.clone())),
        )
    }

    pub(crate) fn new_with_exact_override_resolver(
        mode: ActivationMode,
        catalogue: Arc<ActivationCatalogue>,
        discovery: Arc<dyn InstalledCandidateDiscovery>,
        verifier: Arc<dyn SelectedEngineVerifier>,
        release_authority: Arc<dyn ReleaseQualificationAuthority>,
        exact_override_resolver: Arc<ExactOverrideResolver>,
    ) -> Self {
        Self {
            mode,
            catalogue,
            discovery,
            verifier,
            release_authority,
            exact_override_resolver,
            state: Mutex::new(RuntimeState::Unselected),
            selection_changed: Condvar::new(),
        }
    }

    pub fn acquire(
        &self,
        capability: MutationCapability,
    ) -> Result<Arc<SelectedActivation>, ActivationError> {
        loop {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &*state {
                RuntimeState::Unselected => {
                    *state = RuntimeState::Selecting;
                    drop(state);
                    return self.select_and_pin(capability);
                }
                RuntimeState::Selecting | RuntimeState::Revalidating(_) => {
                    drop(
                        self.selection_changed
                            .wait(state)
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                    );
                }
                RuntimeState::Selected(selected) => {
                    let selected = Arc::clone(selected);
                    self.require_capability(&selected, capability)?;
                    *state = RuntimeState::Revalidating(Arc::clone(&selected));
                    drop(state);
                    let result = self
                        .revalidate_selected(&selected)
                        .map(|()| Arc::clone(&selected));
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    match &result {
                        Ok(_) => *state = RuntimeState::Selected(selected),
                        Err(error) => *state = RuntimeState::Denied(error.clone()),
                    }
                    self.selection_changed.notify_all();
                    return result;
                }
                RuntimeState::Denied(error) => return Err(error.clone()),
            }
        }
    }

    pub fn selected(&self) -> Option<Arc<SelectedActivation>> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*state {
            RuntimeState::Selected(selected) | RuntimeState::Revalidating(selected) => {
                Some(Arc::clone(selected))
            }
            _ => None,
        }
    }

    fn select_and_pin(
        &self,
        capability: MutationCapability,
    ) -> Result<Arc<SelectedActivation>, ActivationError> {
        let result = self.perform_selection().and_then(|selection| {
            let identity = self
                .verifier
                .verify(&selection.candidate, &selection.target)
                .map_err(normalize_initial_verification_error)?;
            if identity.canonical_executable != selection.candidate.executable {
                return Err(ActivationError::VerificationFailed(format!(
                    "verifier returned canonical path {} for selected candidate {}",
                    identity.canonical_executable.display(),
                    selection.candidate.executable.display()
                )));
            }
            Ok(Arc::new(SelectedActivation {
                target: selection.target,
                candidate: selection.candidate,
                engine_identity: identity,
                launch_guard: Some(Arc::new(SelectedLaunchGuard::new(Arc::clone(
                    &self.verifier,
                )))),
            }))
        });

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &result {
            Ok(selected) => *state = RuntimeState::Selected(Arc::clone(selected)),
            Err(error) if error.is_permanent_without_external_change() => {
                *state = RuntimeState::Denied(error.clone())
            }
            Err(_) => *state = RuntimeState::Unselected,
        }
        self.selection_changed.notify_all();
        drop(state);
        result.and_then(|selected| {
            self.require_capability(&selected, capability)?;
            Ok(selected)
        })
    }

    fn perform_selection(&self) -> Result<ActivationSelection, ActivationError> {
        if self.mode == ActivationMode::Disabled {
            return Err(ActivationError::Disabled);
        }
        let qualification = if self.mode == ActivationMode::Release {
            let qualification = self
                .release_authority
                .verified_qualification(&self.catalogue)?
                .ok_or(ActivationError::ReleaseQualificationUnavailable)?;
            validate_release_qualification(&self.catalogue, &qualification)?;
            Some(qualification)
        } else {
            None
        };
        // Resolve the operator path only after Release qualification has
        // admitted at least one catalogue row. A dormant Release package must
        // not touch an operator-supplied path or the Windows filesystem.
        let exact_override = (self.exact_override_resolver)()?;
        let installed = self.discovery.discover(exact_override.as_deref())?;
        select_activation_target(
            &self.catalogue,
            self.mode,
            qualification.as_ref(),
            &installed,
            exact_override.as_deref(),
        )
    }

    fn require_capability(
        &self,
        selected: &SelectedActivation,
        capability: MutationCapability,
    ) -> Result<(), ActivationError> {
        if selected.target.supports(capability) {
            Ok(())
        } else {
            Err(ActivationError::CapabilityUnsupported {
                target_id: selected.target.target_id.clone(),
                capability,
            })
        }
    }

    fn revalidate_selected(&self, selected: &SelectedActivation) -> Result<(), ActivationError> {
        if selected.launch_guard.is_some() {
            return selected.revalidate_for_launch();
        }
        let observed = self
            .verifier
            .verify(&selected.candidate, &selected.target)
            .map_err(|error| ActivationError::SelectedEngineChanged(error.to_string()))?;
        (observed == selected.engine_identity)
            .then_some(())
            .ok_or_else(|| {
                ActivationError::SelectedEngineChanged(format!(
                    "expected identity {:?}, observed {:?}",
                    selected.engine_identity, observed
                ))
            })
    }
}

fn normalize_initial_verification_error(error: ActivationError) -> ActivationError {
    match error {
        ActivationError::VerificationFailed(_) => error,
        other => ActivationError::VerificationFailed(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Barrier,
        },
        thread,
        time::Duration,
    };

    fn catalogue() -> Arc<ActivationCatalogue> {
        Arc::new(embedded_activation_catalogue().unwrap().clone())
    }

    fn candidate(target: &ActivationTarget, suffix: &str) -> InstalledCandidate {
        InstalledCandidate {
            canonical_id: format!("installed-{}-{suffix}", target.release_year),
            executable: PathBuf::from(format!(
                "/registered/{}/accoreconsole.exe",
                target.release_year
            )),
            product: target.product.as_str().to_string(),
            edition: target.edition.as_str().to_string(),
            architecture: target.architecture.as_str().to_string(),
            release_year: target.release_year,
            registry_family: target.registry_family.clone(),
            product_language_key: target.product_language_key.clone(),
            ui_locale: target.ui_locale.clone(),
        }
    }

    #[test]
    fn embedded_catalogue_has_exact_initial_inventory_and_profile_digests() {
        let catalogue = embedded_activation_catalogue().unwrap();
        assert_eq!(catalogue.schema_version, 1);
        assert_eq!(catalogue.artifact_kind, ACTIVATION_CATALOGUE_ARTIFACT_KIND);
        assert_eq!(catalogue.authority, ACTIVATION_CATALOGUE_AUTHORITY);
        assert_eq!(
            catalogue.sha256,
            "135b444325de9a20453da898ad1f86a2c78ed9edd98ec90c7e18318fde04a1d4"
        );
        assert_eq!(catalogue.targets().len(), 10);

        let expected = [
            (
                "autocad-2018-r22-0-en-us-preview-v1",
                2018,
                "R22.0",
                "ACAD-1001:409",
                "35c4b46896eb46d43c81fab2bd10e335a33698ae760c401d174497929878a62e",
                "b404fdc9ec4fc626ee9fea186412423aaa858e7ffa2459b6938f797d2a7c0013",
            ),
            (
                "autocad-2019-r23-0-en-us-preview-v1",
                2019,
                "R23.0",
                "ACAD-2001:409",
                "40dfcdb61a0ff785f53164b2be8562c6137c8aae0e74a7047ad94db25946c1bf",
                "45d22b0cabe336c42e92f54560a2fbf83e2fc32a557ee18ee9717c6ad747151e",
            ),
            (
                "autocad-2020-r23-1-en-us-preview-v1",
                2020,
                "R23.1",
                "ACAD-3001:409",
                "d49d0a0d4d0232f5e9e82f7f0b2b50be4f11f04a566b5bdd0759665bb38f939e",
                "36f5417964294b9fa7f26a122eb5eb04ceae2f605f7afddafa66a1ef0d7e8e88",
            ),
            (
                "autocad-2021-r24-0-en-us-preview-v1",
                2021,
                "R24.0",
                "ACAD-4101:409",
                "cb303316d8eb4a253893f7f6a6fe80ec3410861ebd8e05bd403b0490e9415d1b",
                "c5a39700797894e3caf0ffb36a6b05e74e47538c3639c6f0d7bbc690b293edf3",
            ),
            (
                "autocad-2022-r24-1-en-us-preview-v1",
                2022,
                "R24.1",
                "ACAD-5101:409",
                "20ca45497f006fceac9a916fe2a2bf4017cadffdcc2b63460c99d3987be316a4",
                "6e86113f72672a7342956221995b4e8c703c74c650b5ff97efac571b13a13bd4",
            ),
            (
                "autocad-2023-r24-2-en-us-preview-v1",
                2023,
                "R24.2",
                "ACAD-6101:409",
                "f636edd971ee1ad497e11212af17c2689f7579489df7a95ec6f02f5e6bc6a606",
                "59c2ef1660185847339a74dd203af45514540a4a77391fe981b319877738bbec",
            ),
            (
                "autocad-2024-r24-3-en-us-preview-v1",
                2024,
                "R24.3",
                "ACAD-7101:409",
                "028185637d0c4f7b7df09a922eac2bd3e1e23a964def2539a6db195ea0cbb03f",
                "e4961ee433d3a9ee750131c5e1182402df864c899a5dc5ea5f4148eb6495680c",
            ),
            (
                "autocad-2025-r25-0-en-us-preview-v1",
                2025,
                "R25.0",
                "ACAD-8101:409",
                "473be6d98b9a10b7042e10908fe7c664dd947228cfffac1beda3670bce63356a",
                "3cc970a453949c527c5418ab5b235cc170bea910276311dbc25c7d85b01b156e",
            ),
            (
                "autocad-2026-r25-1-en-us-preview-v1",
                2026,
                "R25.1",
                "ACAD-9101:409",
                "89bc4284f84d1ee9c75ef3ce8a39933d1f86e919b3092ba59ce734b2f3216fc6",
                "40b3ae0defffde4b96c5affc185775e5393478e9e6f23c1768e8cb0dae915617",
            ),
            (
                "autocad-2027-r26-0-en-us-preview-v1",
                2027,
                "R26.0",
                "ACAD-A101:409",
                "8ee60fc5ccf13f3d52d3cbbc5319ebd0150dab0b89261aa78d1692278e4ce0f8",
                "b094364e1785e52ccfbd0542fd5746ae291684a107fe7d781298b4562bae40be",
            ),
        ];
        for (target, expected) in catalogue.targets().iter().zip(expected) {
            assert_eq!(target.target_id, expected.0);
            assert_eq!(target.release_year, expected.1);
            assert_eq!(target.registry_family, expected.2);
            assert_eq!(target.product_language_key, expected.3);
            assert_eq!(target.ui_locale, "en-US");
            assert_eq!(target.profile.arg_sha256, expected.4);
            assert_eq!(target.profile.policy_sha256, expected.5);
        }
        for target in catalogue.targets() {
            let inspection = certified_arg::validate_distribution_safe_arg(
                target.profile.arg_bytes(),
                target.profile.policy_bytes(),
            )
            .unwrap();
            assert_eq!(
                inspection.purpose,
                certified_arg::CertifiedArgPolicyPurpose::PreviewCandidateActivation
            );
            assert_eq!(
                sha256_hex(target.profile.arg_bytes()),
                target.profile.arg_sha256
            );
            assert_eq!(
                sha256_hex(target.profile.policy_bytes()),
                target.profile.policy_sha256
            );
            assert_eq!(
                target.maintained_target,
                (2024..=2027).contains(&target.release_year)
            );
            assert_eq!(target.operation_families, MutationCapability::ALL);
            assert_eq!(target.drawing_formats, vec!["AC1032".to_string()]);
        }
    }

    #[test]
    fn embedded_bundle_exposes_validated_exact_bytes_with_package_relative_paths() {
        let bundle = embedded_activation_bundle().unwrap();
        assert_eq!(
            bundle.catalogue_sha256,
            activation_catalogue_sha256().unwrap()
        );
        assert_eq!(bundle.files.len(), 21);
        assert_eq!(bundle.files[0].path, ACTIVATION_BUNDLE_CATALOGUE_PATH);
        assert_eq!(bundle.files[0].bytes, ACTIVATION_CATALOGUE_BYTES);
        assert!(bundle.files[1..]
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path));
        assert!(bundle.files.iter().all(|file| {
            !Path::new(file.path).is_absolute()
                && file
                    .path
                    .split('/')
                    .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
        }));
        for target in embedded_activation_catalogue().unwrap().targets() {
            for (source_path, expected_digest) in [
                (
                    target.profile.arg_path.as_str(),
                    target.profile.arg_sha256.as_str(),
                ),
                (
                    target.profile.policy_path.as_str(),
                    target.profile.policy_sha256.as_str(),
                ),
            ] {
                let package_path = source_path.strip_prefix(SOURCE_RESOURCE_PREFIX).unwrap();
                let file = bundle
                    .files
                    .iter()
                    .find(|file| file.path == package_path)
                    .unwrap();
                assert_eq!(sha256_hex(file.bytes), expected_digest);
            }
        }
    }

    #[test]
    fn catalogue_rejects_a_noncanonical_product_language_tuple() {
        let mut document: serde_json::Value =
            serde_json::from_slice(ACTIVATION_CATALOGUE_BYTES).unwrap();
        document["targets"][8]["product_language_key"] =
            serde_json::Value::String("ACAD-9001:809".to_string());
        let bytes = serde_json::to_vec(&document).unwrap();

        let error = parse_catalogue(&bytes, embedded_asset).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exact full-AutoCAD en-US registry tuple"),
            "{error}"
        );
    }

    #[test]
    fn catalogue_rejects_duplicate_json_keys_before_typed_parsing() {
        let text = std::str::from_utf8(ACTIVATION_CATALOGUE_BYTES).unwrap();
        let duplicate = text.replacen(
            "\"schema_version\": 1,",
            "\"schema_version\": 1, \"schema_version\": 1,",
            1,
        );
        let error = parse_catalogue(duplicate.as_bytes(), embedded_asset).unwrap_err();
        assert!(error.to_string().contains("duplicate JSON key"), "{error}");
    }

    #[test]
    fn catalogue_profile_rejects_development_fixture_purpose() {
        let error = require_preview_policy_purpose(
            "autocad-2026-r25-1-en-us-preview-v1",
            certified_arg::CertifiedArgPolicyPurpose::DevelopmentFixture,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("purpose must be preview_candidate_activation"),
            "{error}"
        );
    }

    #[test]
    fn preview_selects_highest_eligible_year() {
        let catalogue = catalogue();
        let candidates = catalogue
            .targets()
            .iter()
            .map(|target| candidate(target, "full"))
            .collect::<Vec<_>>();
        let selected =
            select_activation_target(&catalogue, ActivationMode::Preview, None, &candidates, None)
                .unwrap();
        assert_eq!(selected.target.release_year, 2027);
    }

    #[test]
    fn release_denies_every_catalogue_row_without_verified_qualification() {
        let catalogue = catalogue();
        let candidates = catalogue
            .targets()
            .iter()
            .map(|target| candidate(target, "full"))
            .collect::<Vec<_>>();
        assert_eq!(
            select_activation_target(&catalogue, ActivationMode::Release, None, &candidates, None,)
                .unwrap_err(),
            ActivationError::ReleaseQualificationUnavailable
        );
    }

    #[test]
    fn exact_override_constrains_selection_and_never_falls_back() {
        let catalogue = catalogue();
        let target_2020 = catalogue
            .targets()
            .iter()
            .find(|target| target.release_year == 2020)
            .unwrap();
        let target_2027 = catalogue
            .targets()
            .iter()
            .find(|target| target.release_year == 2027)
            .unwrap();
        let candidates = vec![
            candidate(target_2020, "full"),
            candidate(target_2027, "full"),
        ];
        let override_path = candidates[0].executable.clone();
        let selected = select_activation_target(
            &catalogue,
            ActivationMode::Preview,
            None,
            &candidates,
            Some(&override_path),
        )
        .unwrap();
        assert_eq!(selected.target.release_year, 2020);

        let missing = Path::new("/registered/missing/accoreconsole.exe");
        assert_eq!(
            select_activation_target(
                &catalogue,
                ActivationMode::Preview,
                None,
                &candidates,
                Some(missing),
            )
            .unwrap_err(),
            ActivationError::ExactOverrideUnavailable(missing.to_path_buf())
        );
    }

    #[test]
    fn lt_and_wrong_locale_candidates_do_not_match_catalogue_authority() {
        let catalogue = catalogue();
        let target_2027 = catalogue
            .targets()
            .iter()
            .find(|target| target.release_year == 2027)
            .unwrap();
        let target_2026 = catalogue
            .targets()
            .iter()
            .find(|target| target.release_year == 2026)
            .unwrap();
        let mut lt = candidate(target_2027, "lt");
        lt.edition = "lt".to_string();
        let mut wrong_locale = candidate(target_2027, "fr");
        wrong_locale.ui_locale = "fr-FR".to_string();
        let full = candidate(target_2026, "full");

        let selected = select_activation_target(
            &catalogue,
            ActivationMode::Preview,
            None,
            &[lt, wrong_locale, full],
            None,
        )
        .unwrap();
        assert_eq!(selected.target.release_year, 2026);
    }

    #[derive(Debug)]
    struct FakeDiscovery {
        candidates: Vec<InstalledCandidate>,
        calls: AtomicUsize,
        delay: Duration,
    }

    impl InstalledCandidateDiscovery for FakeDiscovery {
        fn discover(
            &self,
            _exact_override: Option<&Path>,
        ) -> Result<Vec<InstalledCandidate>, ActivationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            thread::sleep(self.delay);
            Ok(self.candidates.clone())
        }
    }

    #[derive(Debug)]
    struct FakeVerifier {
        invalid: AtomicBool,
    }

    impl SelectedEngineVerifier for FakeVerifier {
        fn verify(
            &self,
            candidate: &InstalledCandidate,
            _target: &ActivationTarget,
        ) -> Result<VerifiedEngineIdentity, ActivationError> {
            if self.invalid.load(Ordering::SeqCst) {
                return Err(ActivationError::VerificationFailed(
                    "executable identity changed".to_string(),
                ));
            }
            Ok(VerifiedEngineIdentity {
                canonical_executable: candidate.executable.clone(),
                identity_token: format!("identity:{}", candidate.canonical_id),
            })
        }
    }

    #[test]
    fn release_rejects_before_resolving_an_exact_override_or_discovering_windows() {
        let catalogue = catalogue();
        let discovery = Arc::new(FakeDiscovery {
            candidates: Vec::new(),
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        });
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let counted_resolver_calls = Arc::clone(&resolver_calls);
        let runtime = MutationRuntime::new_with_exact_override_resolver(
            ActivationMode::Release,
            catalogue,
            discovery.clone(),
            Arc::new(FakeVerifier {
                invalid: AtomicBool::new(false),
            }),
            Arc::new(NoReleaseQualification),
            Arc::new(move || {
                counted_resolver_calls.fetch_add(1, Ordering::SeqCst);
                Err(ActivationError::DiscoveryFailed(
                    "override resolver must remain dormant".to_string(),
                ))
            }),
        );

        assert_eq!(
            runtime.acquire(MutationCapability::DwgLayerMutation),
            Err(ActivationError::ReleaseQualificationUnavailable)
        );
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
        assert_eq!(discovery.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn invalid_release_qualification_rejects_before_resolving_an_exact_override() {
        #[derive(Debug)]
        struct InvalidQualification;

        impl ReleaseQualificationAuthority for InvalidQualification {
            fn verified_qualification(
                &self,
                _catalogue: &ActivationCatalogue,
            ) -> Result<Option<VerifiedReleaseQualification>, ActivationError> {
                Ok(Some(VerifiedReleaseQualification {
                    catalogue_sha256: "0".repeat(64),
                    admitted_target_ids: BTreeSet::new(),
                }))
            }
        }

        let catalogue = catalogue();
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let counted_resolver_calls = Arc::clone(&resolver_calls);
        let runtime = MutationRuntime::new_with_exact_override_resolver(
            ActivationMode::Release,
            catalogue,
            Arc::new(FakeDiscovery {
                candidates: Vec::new(),
                calls: AtomicUsize::new(0),
                delay: Duration::ZERO,
            }),
            Arc::new(FakeVerifier {
                invalid: AtomicBool::new(false),
            }),
            Arc::new(InvalidQualification),
            Arc::new(move || {
                counted_resolver_calls.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            }),
        );

        assert!(matches!(
            runtime
                .acquire(MutationCapability::DwgLayerMutation)
                .unwrap_err(),
            ActivationError::ReleaseQualificationInvalid(_)
        ));
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn concurrent_acquisition_performs_one_discovery_and_pins_one_selection() {
        let catalogue = catalogue();
        let highest = catalogue.targets().last().unwrap();
        let discovery = Arc::new(FakeDiscovery {
            candidates: vec![candidate(highest, "full")],
            calls: AtomicUsize::new(0),
            delay: Duration::from_millis(30),
        });
        let verifier = Arc::new(FakeVerifier {
            invalid: AtomicBool::new(false),
        });
        let runtime = Arc::new(MutationRuntime::new(
            ActivationMode::Preview,
            catalogue,
            discovery.clone(),
            verifier,
            Arc::new(NoReleaseQualification),
            None,
        ));
        let barrier = Arc::new(Barrier::new(9));
        let handles = (0..8)
            .map(|_| {
                let runtime = Arc::clone(&runtime);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    runtime
                        .acquire(MutationCapability::DwgLayerMutation)
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let selections = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(discovery.calls.load(Ordering::SeqCst), 1);
        assert!(selections
            .iter()
            .all(|selection| Arc::ptr_eq(&selections[0], selection)));
    }

    #[test]
    fn unsupported_first_capability_still_pins_the_highest_selected_engine() {
        let source = embedded_activation_catalogue().unwrap();
        let mut targets = source.targets().to_vec();
        targets
            .last_mut()
            .unwrap()
            .operation_families
            .retain(|capability| *capability != MutationCapability::Plot);
        let catalogue = Arc::new(ActivationCatalogue {
            schema_version: source.schema_version,
            artifact_kind: source.artifact_kind.clone(),
            authority: source.authority.clone(),
            sha256: source.sha256.clone(),
            targets: targets.into(),
        });
        let selected_candidate = candidate(catalogue.targets().last().unwrap(), "selected");
        let fallback_candidate = candidate(
            catalogue
                .targets()
                .iter()
                .find(|target| target.release_year == 2026)
                .unwrap(),
            "fallback",
        );
        let discovery = Arc::new(FakeDiscovery {
            candidates: vec![fallback_candidate, selected_candidate],
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        });
        let runtime = MutationRuntime::new(
            ActivationMode::Preview,
            catalogue,
            discovery.clone(),
            Arc::new(FakeVerifier {
                invalid: AtomicBool::new(false),
            }),
            Arc::new(NoReleaseQualification),
            None,
        );

        assert!(matches!(
            runtime.acquire(MutationCapability::Plot).unwrap_err(),
            ActivationError::CapabilityUnsupported { .. }
        ));
        assert_eq!(runtime.selected().unwrap().target.release_year, 2027);
        assert_eq!(
            runtime
                .acquire(MutationCapability::DwgLayerMutation)
                .unwrap()
                .target
                .release_year,
            2027
        );
        assert_eq!(discovery.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn invalidated_pinned_candidate_fails_without_discovery_or_fallback() {
        let catalogue = catalogue();
        let target_2026 = catalogue
            .targets()
            .iter()
            .find(|target| target.release_year == 2026)
            .unwrap();
        let target_2027 = catalogue
            .targets()
            .iter()
            .find(|target| target.release_year == 2027)
            .unwrap();
        let discovery = Arc::new(FakeDiscovery {
            candidates: vec![
                candidate(target_2026, "fallback"),
                candidate(target_2027, "selected"),
            ],
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        });
        let verifier = Arc::new(FakeVerifier {
            invalid: AtomicBool::new(false),
        });
        let runtime = MutationRuntime::new(
            ActivationMode::Preview,
            catalogue,
            discovery.clone(),
            verifier.clone(),
            Arc::new(NoReleaseQualification),
            None,
        );

        let selected = runtime.acquire(MutationCapability::XrefMutation).unwrap();
        assert_eq!(selected.target.release_year, 2027);
        verifier.invalid.store(true, Ordering::SeqCst);
        let error = runtime
            .acquire(MutationCapability::XrefMutation)
            .unwrap_err();
        assert!(matches!(error, ActivationError::SelectedEngineChanged(_)));
        assert_eq!(discovery.calls.load(Ordering::SeqCst), 1);
        verifier.invalid.store(false, Ordering::SeqCst);
        let restart_required = runtime
            .acquire(MutationCapability::XrefMutation)
            .unwrap_err();
        assert!(matches!(
            restart_required,
            ActivationError::SelectedEngineChanged(_)
        ));
        assert_eq!(discovery.calls.load(Ordering::SeqCst), 1);
        assert!(runtime.selected().is_none());
    }

    #[test]
    fn launch_boundary_mismatch_permanently_poisons_the_pinned_selection() {
        let catalogue = catalogue();
        let target = catalogue
            .targets()
            .iter()
            .find(|target| target.release_year == 2027)
            .unwrap();
        let discovery = Arc::new(FakeDiscovery {
            candidates: vec![candidate(target, "selected")],
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        });
        let verifier = Arc::new(FakeVerifier {
            invalid: AtomicBool::new(false),
        });
        let runtime = MutationRuntime::new(
            ActivationMode::Preview,
            catalogue,
            discovery.clone(),
            verifier.clone(),
            Arc::new(NoReleaseQualification),
            None,
        );
        let selected = runtime.acquire(MutationCapability::Plot).unwrap();

        verifier.invalid.store(true, Ordering::SeqCst);
        assert!(matches!(
            selected.revalidate_for_launch().unwrap_err(),
            ActivationError::SelectedEngineChanged(_)
        ));
        verifier.invalid.store(false, Ordering::SeqCst);
        assert!(matches!(
            selected.revalidate_for_launch().unwrap_err(),
            ActivationError::SelectedEngineChanged(_)
        ));
        assert!(matches!(
            runtime.acquire(MutationCapability::Plot).unwrap_err(),
            ActivationError::SelectedEngineChanged(_)
        ));
        assert_eq!(discovery.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn opaque_test_qualification_can_only_admit_maintained_rows() {
        let catalogue = catalogue();
        let qualification = VerifiedReleaseQualification::for_test(
            &catalogue,
            &["autocad-2024-r24-3-en-us-preview-v1"],
        );
        let target = catalogue
            .target("autocad-2024-r24-3-en-us-preview-v1")
            .unwrap();
        let selected = select_activation_target(
            &catalogue,
            ActivationMode::Release,
            Some(&qualification),
            &[candidate(target, "qualified")],
            None,
        )
        .unwrap();
        assert_eq!(selected.target.release_year, 2024);
    }
}
