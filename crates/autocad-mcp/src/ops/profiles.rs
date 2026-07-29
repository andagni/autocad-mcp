use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Result};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::autocad_reader::contract::TitleBlockInfo;

pub const TITLE_BLOCK_PROFILE_REGISTRY_BYTES: &[u8] =
    include_bytes!("../../profile-registry/title-block-profiles.json");
pub const TITLE_BLOCK_PROFILES_ENV: &str = "AUTOCAD_MCP_TITLE_BLOCK_PROFILES";
pub const MAX_TITLE_BLOCK_PROFILES_BYTES: u64 = 1024 * 1024;
const MAX_ADMINISTRATOR_PROFILES: usize = 256;
const MAX_PROFILE_ID_BYTES: usize = 128;
const MAX_PACK_ID_BYTES: usize = 128;
const MAX_PACK_VERSION_BYTES: usize = 64;
const MAX_DESCRIPTION_BYTES: usize = 1024;
const MAX_EVIDENCE_REFERENCE_BYTES: usize = 512;
const MAX_FINGERPRINT_TAGS: usize = 256;
const MAX_DRAWING_IDENTITY_BYTES: usize = 256;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProfileAuthority {
    Embedded,
    Administrator(ProfilePackIdentity),
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePackIdentity {
    pub pack_id: String,
    pub pack_version: String,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub profile_id: String,
    pub schema_version: u32,
    pub description: String,
    pub source_evidence: Vec<String>,
    pub block_name: String,
    authority: ProfileAuthority,
    normalized_block_name: String,
    fingerprint_tags: Vec<String>,
    canonical_to_tag: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TitleBlockFingerprint {
    pub block_name: String,
    pub attribute_tags: Vec<String>,
}

pub type CandidateFingerprint = TitleBlockFingerprint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileResolutionError {
    NoMatch {
        candidates: Vec<CandidateFingerprint>,
        known_profiles: Vec<String>,
    },
    Ambiguous {
        profile_ids: Vec<String>,
    },
}

impl fmt::Display for ProfileResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileResolutionError::NoMatch {
                candidates,
                known_profiles,
            } => write!(
                f,
                "no recognised title-block profile for candidates {:?}; known profiles: {:?}",
                candidates, known_profiles
            ),
            ProfileResolutionError::Ambiguous { profile_ids } => {
                write!(f, "ambiguous title-block profile match: {:?}", profile_ids)
            }
        }
    }
}

impl std::error::Error for ProfileResolutionError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryDocument {
    title_block_schema: u32,
    profiles: Vec<RegistryProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfilePackDocument {
    profile_pack_schema: u32,
    pack_id: String,
    pack_version: String,
    title_block_schema: u32,
    profiles: Vec<RegistryProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryProfile {
    profile_id: String,
    schema_version: u32,
    description: String,
    source_evidence: Vec<String>,
    fingerprint: RegistryFingerprint,
    fields: RegistryFields,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFingerprint {
    block_name: String,
    attribute_tags: Vec<String>,
}

/// Registry field rows as they appeared in the JSON object.
///
/// A map type would silently discard repeated JSON keys before profile
/// validation could reject them. Retaining the rows also lets validation catch
/// distinct source keys which collapse to one normalized canonical field.
#[derive(Debug)]
struct RegistryFields(Vec<(String, String)>);

impl<'de> Deserialize<'de> for RegistryFields {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RegistryFieldsVisitor;

        impl<'de> Visitor<'de> for RegistryFieldsVisitor {
            type Value = RegistryFields;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a canonical-field-to-DXF-tag object")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut fields = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((canonical, tag)) = map.next_entry::<String, String>()? {
                    fields.push((canonical, tag));
                }
                Ok(RegistryFields(fields))
            }
        }

        deserializer.deserialize_map(RegistryFieldsVisitor)
    }
}

impl Profile {
    /// Return the DXF attribute tag for a canonical field name.
    /// Lookup is case-insensitive (the key is normalised to lowercase).
    pub fn tag_for(&self, canonical: &str) -> Option<&str> {
        self.canonical_to_tag
            .get(normalize_canonical_field(canonical).as_str())
            .map(String::as_str)
    }

    /// Return all canonical field names in sorted order.
    pub fn canonical_fields(&self) -> Vec<&str> {
        let mut fields: Vec<_> = self.canonical_to_tag.keys().map(String::as_str).collect();
        fields.sort();
        fields
    }

    pub fn fingerprint_tags(&self) -> Vec<&str> {
        self.fingerprint_tags.iter().map(String::as_str).collect()
    }

    pub fn title_block_fingerprint(&self) -> TitleBlockFingerprint {
        TitleBlockFingerprint {
            block_name: self.normalized_block_name.clone(),
            attribute_tags: self.fingerprint_tags.clone(),
        }
    }

    pub fn authority(&self) -> &ProfileAuthority {
        &self.authority
    }

    pub fn administrator_pack(&self) -> Option<&ProfilePackIdentity> {
        match &self.authority {
            ProfileAuthority::Embedded => None,
            ProfileAuthority::Administrator(pack) => Some(pack),
        }
    }

    fn matches_fingerprint(&self, candidate: &CandidateFingerprint) -> bool {
        self.normalized_block_name == candidate.block_name
            && self.fingerprint_tags == candidate.attribute_tags
    }
}

#[derive(Debug, Clone)]
pub struct AdministratorProfilePack {
    identity: ProfilePackIdentity,
    profiles: Vec<Profile>,
}

impl AdministratorProfilePack {
    pub fn identity(&self) -> &ProfilePackIdentity {
        &self.identity
    }

    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }

    pub fn summary(&self) -> ProfilePackSummary {
        ProfilePackSummary {
            profile_pack_schema: 1,
            pack_id: self.identity.pack_id.clone(),
            pack_version: self.identity.pack_version.clone(),
            sha256: self.identity.sha256.clone(),
            profile_count: self.profiles.len(),
            profile_ids: self
                .profiles
                .iter()
                .map(|profile| profile.profile_id.clone())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePackSummary {
    pub profile_pack_schema: u32,
    pub pack_id: String,
    pub pack_version: String,
    pub sha256: String,
    pub profile_count: usize,
    pub profile_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProfileRegistry {
    profiles: Vec<Profile>,
    administrator_pack: Option<ProfilePackIdentity>,
}

impl ProfileRegistry {
    fn embedded() -> Result<Self> {
        let json = std::str::from_utf8(TITLE_BLOCK_PROFILE_REGISTRY_BYTES)
            .map_err(|error| anyhow!("title-block profile registry must be UTF-8: {error}"))?;
        Ok(Self {
            profiles: profiles_from_json_with_authority(json, ProfileAuthority::Embedded)?,
            administrator_pack: None,
        })
    }

    pub fn with_administrator_pack(pack: AdministratorProfilePack) -> Result<Self> {
        let mut registry = embedded_profile_registry_ref().clone();
        let mut ids = registry
            .profiles
            .iter()
            .map(|profile| {
                (
                    normalize_identity(&profile.profile_id),
                    profile.profile_id.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut fingerprints = registry
            .profiles
            .iter()
            .map(|profile| {
                (
                    profile.title_block_fingerprint(),
                    profile.profile_id.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        for profile in &pack.profiles {
            let normalized_id = normalize_identity(&profile.profile_id);
            if let Some(existing) = ids.insert(normalized_id, profile.profile_id.clone()) {
                return Err(anyhow!(
                    "administrator profile '{}' collides with existing profile_id '{}'",
                    profile.profile_id,
                    existing
                ));
            }
            let fingerprint = profile.title_block_fingerprint();
            if let Some(existing) = fingerprints.insert(fingerprint, profile.profile_id.clone()) {
                return Err(anyhow!(
                    "administrator profile '{}' duplicates the exact fingerprint of existing profile '{}'",
                    profile.profile_id,
                    existing
                ));
            }
        }

        registry.administrator_pack = Some(pack.identity);
        registry.profiles.extend(pack.profiles);
        registry
            .profiles
            .sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
        Ok(registry)
    }

    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }

    pub fn administrator_pack(&self) -> Option<&ProfilePackIdentity> {
        self.administrator_pack.as_ref()
    }

    pub fn find_profile(&self, name: &str) -> Option<&Profile> {
        let normalized = normalize_identity(name);
        self.profiles.iter().find(|profile| {
            normalize_identity(&profile.profile_id) == normalized
                || profile.normalized_block_name == normalized
        })
    }

    pub fn all_profile_names(&self) -> Vec<&str> {
        self.profiles
            .iter()
            .map(|profile| profile.profile_id.as_str())
            .collect()
    }

    pub fn resolve_profile(
        &self,
        candidates: &[TitleBlockInfo],
    ) -> std::result::Result<&Profile, ProfileResolutionError> {
        resolve_profile_from_registry(&self.profiles, candidates)
    }
}

impl TitleBlockFingerprint {
    pub fn new<'a>(block_name: &str, attribute_tags: impl Iterator<Item = &'a str>) -> Self {
        TitleBlockFingerprint {
            block_name: normalize_identity(block_name),
            attribute_tags: sorted_normalized_tags(attribute_tags),
        }
    }

    pub(crate) fn from_title_block(block: &TitleBlockInfo) -> Self {
        TitleBlockFingerprint {
            block_name: normalize_identity(&block.block_name),
            attribute_tags: sorted_normalized_tags(block.attribute_tags()),
        }
    }
}

static EMBEDDED_PROFILE_REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();

fn embedded_profile_registry_ref() -> &'static ProfileRegistry {
    EMBEDDED_PROFILE_REGISTRY.get_or_init(|| {
        ProfileRegistry::embedded().expect("invalid embedded title-block profile registry")
    })
}

pub fn embedded_profile_registry() -> Arc<ProfileRegistry> {
    Arc::new(embedded_profile_registry_ref().clone())
}

#[cfg(test)]
fn profiles_from_json(json: &str) -> Result<Vec<Profile>> {
    profiles_from_json_with_authority(json, ProfileAuthority::Embedded)
}

fn profiles_from_json_with_authority(
    json: &str,
    authority: ProfileAuthority,
) -> Result<Vec<Profile>> {
    let registry: RegistryDocument = serde_json::from_str(json)?;
    profiles_from_rows(
        registry.title_block_schema,
        registry.profiles,
        authority,
        None,
    )
}

fn profiles_from_rows(
    title_block_schema: u32,
    profiles: Vec<RegistryProfile>,
    authority: ProfileAuthority,
    maximum_profiles: Option<usize>,
) -> Result<Vec<Profile>> {
    if title_block_schema != 1 {
        return Err(anyhow!(
            "unsupported title_block_schema {}; expected 1",
            title_block_schema
        ));
    }
    if profiles.is_empty() {
        return Err(anyhow!(
            "profile registry must declare at least one profile"
        ));
    }
    if maximum_profiles.is_some_and(|maximum| profiles.len() > maximum) {
        return Err(anyhow!(
            "profile registry contains {} profiles; maximum is {}",
            profiles.len(),
            maximum_profiles.expect("checked maximum")
        ));
    }

    let mut seen_ids = BTreeSet::new();
    let mut seen_fingerprints = BTreeMap::new();
    let mut parsed = profiles
        .into_iter()
        .map(|profile| {
            let normalized_id = normalize_identity(&profile.profile_id);
            if profile.profile_id.trim().is_empty() {
                return Err(anyhow!("profile_id must not be empty"));
            }
            if !seen_ids.insert(normalized_id) {
                return Err(anyhow!("duplicate profile_id '{}'", profile.profile_id));
            }
            let parsed = profile_from_registry(profile, authority.clone())?;
            let fingerprint = parsed.title_block_fingerprint();
            if let Some(existing) = seen_fingerprints.insert(fingerprint, parsed.profile_id.clone())
            {
                return Err(anyhow!(
                    "profile '{}' duplicates the exact fingerprint of profile '{}'",
                    parsed.profile_id,
                    existing
                ));
            }
            Ok(parsed)
        })
        .collect::<Result<Vec<_>>>()?;
    parsed.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
    Ok(parsed)
}

fn profile_from_registry(profile: RegistryProfile, authority: ProfileAuthority) -> Result<Profile> {
    validate_bounded_text(
        &profile.profile_id,
        MAX_PROFILE_ID_BYTES,
        "profile_id",
        Some(&profile.profile_id),
    )?;
    if profile.schema_version != 1 {
        return Err(anyhow!(
            "profile '{}' uses unsupported schema_version {}; expected 1",
            profile.profile_id,
            profile.schema_version
        ));
    }
    if profile.description.trim().is_empty() {
        return Err(anyhow!(
            "profile '{}' must declare a description",
            profile.profile_id
        ));
    }
    validate_bounded_text(
        &profile.description,
        MAX_DESCRIPTION_BYTES,
        "description",
        Some(&profile.profile_id),
    )?;
    if profile.source_evidence.is_empty() {
        return Err(anyhow!(
            "profile '{}' must declare source evidence",
            profile.profile_id
        ));
    }
    for evidence in &profile.source_evidence {
        validate_bounded_text(
            evidence,
            MAX_EVIDENCE_REFERENCE_BYTES,
            "source evidence reference",
            Some(&profile.profile_id),
        )?;
    }
    if profile.fingerprint.block_name.trim().is_empty() {
        return Err(anyhow!(
            "profile '{}' fingerprint block_name must not be empty",
            profile.profile_id
        ));
    }
    validate_bounded_text(
        &profile.fingerprint.block_name,
        MAX_DRAWING_IDENTITY_BYTES,
        "fingerprint block_name",
        Some(&profile.profile_id),
    )?;
    if profile.fingerprint.attribute_tags.len() > MAX_FINGERPRINT_TAGS {
        return Err(anyhow!(
            "profile '{}' fingerprint contains {} tags; maximum is {}",
            profile.profile_id,
            profile.fingerprint.attribute_tags.len(),
            MAX_FINGERPRINT_TAGS
        ));
    }

    let fingerprint_tags =
        checked_sorted_normalized_tags(&profile.profile_id, &profile.fingerprint.attribute_tags)?;
    let allowed_fields = canonical_schema_v1_fields();
    let fingerprint_tag_set: BTreeSet<_> = fingerprint_tags.iter().cloned().collect();
    let mut canonical_to_tag = BTreeMap::new();
    let mut tag_to_canonical = BTreeMap::new();

    if profile.fields.0.is_empty() {
        return Err(anyhow!(
            "profile '{}' must map at least one canonical field",
            profile.profile_id
        ));
    }
    for (canonical, tag) in profile.fields.0 {
        let field = normalize_canonical_field(&canonical);
        if !allowed_fields.contains(field.as_str()) {
            return Err(anyhow!(
                "profile '{}' maps unknown canonical field '{}'",
                profile.profile_id,
                canonical
            ));
        }
        if canonical_to_tag.contains_key(&field) {
            return Err(anyhow!(
                "profile '{}' contains duplicate canonical field key '{}' after normalization to '{}'",
                profile.profile_id,
                canonical,
                field
            ));
        }

        let normalized_tag = normalize_identity(&tag);
        if !fingerprint_tag_set.contains(&normalized_tag) {
            return Err(anyhow!(
                "profile '{}' maps field '{}' to tag '{}' outside the fingerprint",
                profile.profile_id,
                canonical,
                tag
            ));
        }
        if let Some(existing_field) = tag_to_canonical.get(&normalized_tag) {
            return Err(anyhow!(
                "profile '{}' maps canonical fields '{}' and '{}' to the same normalized tag '{}'",
                profile.profile_id,
                existing_field,
                field,
                normalized_tag
            ));
        }
        tag_to_canonical.insert(normalized_tag.clone(), field.clone());
        canonical_to_tag.insert(field, normalized_tag);
    }

    Ok(Profile {
        profile_id: profile.profile_id,
        schema_version: profile.schema_version,
        description: profile.description,
        source_evidence: profile.source_evidence,
        block_name: profile.fingerprint.block_name.clone(),
        authority,
        normalized_block_name: normalize_identity(&profile.fingerprint.block_name),
        fingerprint_tags,
        canonical_to_tag,
    })
}

fn validate_bounded_text(
    value: &str,
    maximum_bytes: usize,
    label: &str,
    profile_id: Option<&str>,
) -> Result<()> {
    let location = profile_id
        .map(|profile_id| format!("profile '{profile_id}' {label}"))
        .unwrap_or_else(|| label.to_string());
    if value.trim().is_empty() {
        return Err(anyhow!("{location} must not be empty"));
    }
    if value.len() > maximum_bytes {
        return Err(anyhow!("{location} exceeds the {maximum_bytes}-byte limit"));
    }
    if value.chars().any(char::is_control) {
        return Err(anyhow!("{location} contains a control character"));
    }
    Ok(())
}

pub fn parse_administrator_profile_pack(bytes: &[u8]) -> Result<AdministratorProfilePack> {
    if bytes.len() as u64 > MAX_TITLE_BLOCK_PROFILES_BYTES {
        return Err(anyhow!(
            "title-block profiles file exceeds the {}-byte limit",
            MAX_TITLE_BLOCK_PROFILES_BYTES
        ));
    }
    let sha256 = sha256(bytes);
    let json = std::str::from_utf8(bytes)
        .map_err(|error| anyhow!("title-block profiles file must be strict UTF-8: {error}"))?;
    let document: ProfilePackDocument = serde_json::from_str(json)?;
    if document.profile_pack_schema != 1 {
        return Err(anyhow!(
            "unsupported profile_pack_schema {}; expected 1",
            document.profile_pack_schema
        ));
    }
    validate_pack_id(&document.pack_id)?;
    validate_pack_version(&document.pack_version)?;

    let identity = ProfilePackIdentity {
        pack_id: document.pack_id,
        pack_version: document.pack_version,
        sha256,
    };
    let authority = ProfileAuthority::Administrator(identity.clone());
    let profiles = profiles_from_rows(
        document.title_block_schema,
        document.profiles,
        authority,
        Some(MAX_ADMINISTRATOR_PROFILES),
    )?;
    Ok(AdministratorProfilePack { identity, profiles })
}

pub fn load_administrator_profile_pack(path: &Path) -> Result<AdministratorProfilePack> {
    if !path.is_absolute() {
        return Err(anyhow!(
            "title-block profiles path must be absolute: {}",
            path.display()
        ));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        anyhow!(
            "inspect title-block profiles file {}: {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "title-block profiles path must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    if metadata.len() > MAX_TITLE_BLOCK_PROFILES_BYTES {
        return Err(anyhow!(
            "title-block profiles file exceeds the {}-byte limit: {}",
            MAX_TITLE_BLOCK_PROFILES_BYTES,
            path.display()
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| anyhow!("read title-block profiles file {}: {error}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(anyhow!(
            "title-block profiles file changed while it was being read: {}",
            path.display()
        ));
    }
    parse_administrator_profile_pack(&bytes)
}

pub fn load_active_profile_registry(path: Option<&Path>) -> Result<Arc<ProfileRegistry>> {
    match path {
        None => Ok(embedded_profile_registry()),
        Some(path) => {
            let pack = load_administrator_profile_pack(path)?;
            Ok(Arc::new(ProfileRegistry::with_administrator_pack(pack)?))
        }
    }
}

fn validate_pack_id(pack_id: &str) -> Result<()> {
    validate_bounded_text(pack_id, MAX_PACK_ID_BYTES, "pack_id", None)?;
    if pack_id.trim() != pack_id {
        return Err(anyhow!("pack_id must not contain surrounding whitespace"));
    }
    let mut chars = pack_id.chars();
    if !chars
        .next()
        .is_some_and(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        || !chars.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '-' | '_')
        })
    {
        return Err(anyhow!(
            "pack_id must use lowercase ASCII letters, digits, '.', '-' or '_' and begin with a letter or digit"
        ));
    }
    Ok(())
}

fn validate_pack_version(pack_version: &str) -> Result<()> {
    validate_bounded_text(pack_version, MAX_PACK_VERSION_BYTES, "pack_version", None)?;
    if pack_version.trim() != pack_version
        || !pack_version.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '+')
        })
    {
        return Err(anyhow!(
            "pack_version must use ASCII letters, digits, '.', '-', '_' or '+' without surrounding whitespace"
        ));
    }
    Ok(())
}

fn canonical_schema_v1_fields() -> BTreeSet<&'static str> {
    [
        "revision",
        "drawing_number",
        "alternative_reference",
        "drawing_title_big",
        "drawing_title_med",
        "sheet",
        "sheet_total",
    ]
    .into_iter()
    .collect()
}

fn normalize_canonical_field(value: &str) -> String {
    value.trim().to_lowercase()
}

fn normalize_identity(value: &str) -> String {
    value.trim().to_uppercase()
}

fn checked_sorted_normalized_tags(profile_id: &str, tags: &[String]) -> Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::new();
    for tag in tags {
        validate_bounded_text(
            tag,
            MAX_DRAWING_IDENTITY_BYTES,
            "fingerprint attribute tag",
            Some(profile_id),
        )?;
        let normalized_tag = normalize_identity(tag);
        if normalized_tag.is_empty() {
            return Err(anyhow!(
                "profile '{}' fingerprint contains an empty attribute tag",
                profile_id
            ));
        }
        if !seen.insert(normalized_tag.clone()) {
            return Err(anyhow!(
                "profile '{}' fingerprint contains duplicate attribute tag '{}'",
                profile_id,
                tag
            ));
        }
        normalized.push(normalized_tag);
    }
    normalized.sort();
    Ok(normalized)
}

fn sorted_normalized_tags<'a>(tags: impl Iterator<Item = &'a str>) -> Vec<String> {
    tags.map(normalize_identity)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Find a profile by profile id or block name (case-insensitive).
///
/// This helper supports existing non-write call sites. Write profile resolution
/// must use `resolve_profile` so block-name-only matches cannot authorize edits.
pub fn find_profile(name: &str) -> Option<&'static Profile> {
    embedded_profile_registry_ref().find_profile(name)
}

/// Names of all registered profiles. Used for error messages.
pub fn all_profile_names() -> Vec<&'static str> {
    embedded_profile_registry_ref().all_profile_names()
}

/// Lowercase SHA-256 of the exact embedded title-block profile registry bytes.
pub fn title_block_profile_registry_sha256() -> String {
    sha256(TITLE_BLOCK_PROFILE_REGISTRY_BYTES)
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TitleBlockProfileDefinition {
    pub profile_id: String,
    pub canonical_fields: Vec<String>,
    pub canonical_to_tag: BTreeMap<String, String>,
    pub fingerprint: TitleBlockFingerprint,
}

/// Closed, deterministic projection of every embedded profile definition.
///
/// Profile rows, owned canonical field names, and canonical-to-tag mappings are
/// sorted deterministically.
pub fn title_block_profile_definitions() -> Vec<TitleBlockProfileDefinition> {
    let mut definitions = embedded_profile_registry_ref()
        .profiles()
        .iter()
        .map(|profile| TitleBlockProfileDefinition {
            profile_id: profile.profile_id.clone(),
            canonical_fields: profile
                .canonical_fields()
                .into_iter()
                .map(str::to_string)
                .collect(),
            canonical_to_tag: profile.canonical_to_tag.clone(),
            fingerprint: profile.title_block_fingerprint(),
        })
        .collect::<Vec<_>>();
    definitions.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
    definitions
}

pub fn resolve_profile(
    candidates: &[TitleBlockInfo],
) -> std::result::Result<&'static Profile, ProfileResolutionError> {
    embedded_profile_registry_ref().resolve_profile(candidates)
}

fn resolve_profile_from_registry<'a>(
    profiles: &'a [Profile],
    candidates: &[TitleBlockInfo],
) -> std::result::Result<&'a Profile, ProfileResolutionError> {
    let fingerprints: Vec<_> = candidates
        .iter()
        .map(CandidateFingerprint::from_title_block)
        .collect();
    let mut matches: BTreeMap<&str, &Profile> = BTreeMap::new();

    for candidate in &fingerprints {
        for profile in profiles {
            if profile.matches_fingerprint(candidate) {
                matches.insert(profile.profile_id.as_str(), profile);
            }
        }
    }

    match matches.len() {
        0 => Err(ProfileResolutionError::NoMatch {
            candidates: fingerprints,
            known_profiles: profiles.iter().map(|p| p.profile_id.clone()).collect(),
        }),
        1 => Ok(*matches.values().next().expect("one profile match")),
        _ => Err(ProfileResolutionError::Ambiguous {
            profile_ids: matches.keys().map(|id| (*id).to_string()).collect(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn full_generic_tags() -> Vec<&'static str> {
        vec![
            "DRAWING_NUMBER",
            "REFERENCE",
            "REVISION",
            "SHEET_COUNT",
            "SHEET_NUMBER",
            "TITLE_LINE_1",
            "TITLE_LINE_2",
        ]
    }

    fn title_block(block_name: &str, tags: &[&str]) -> TitleBlockInfo {
        TitleBlockInfo {
            block_name: block_name.to_string(),
            layer: "0".to_string(),
            attributes: tags
                .iter()
                .map(|tag| ((*tag).to_string(), String::new()))
                .collect::<HashMap<_, _>>(),
            attribute_arrays: HashMap::new(),
        }
    }

    fn profile_json(profile_id: &str, block_name: &str) -> String {
        profile_json_with_fields(
            profile_id,
            block_name,
            &full_generic_tags(),
            r#"{
                "revision": "REVISION",
                "drawing_number": "DRAWING_NUMBER",
                "alternative_reference": "REFERENCE",
                "drawing_title_big": "TITLE_LINE_1",
                "drawing_title_med": "TITLE_LINE_2",
                "sheet": "SHEET_NUMBER",
                "sheet_total": "SHEET_COUNT"
            }"#,
        )
    }

    fn profile_json_with_fields(
        profile_id: &str,
        block_name: &str,
        fingerprint_tags: &[&str],
        fields_json: &str,
    ) -> String {
        let fingerprint_tags = serde_json::to_string(fingerprint_tags).unwrap();
        format!(
            r#"{{
                "profile_id": "{profile_id}",
                "schema_version": 1,
                "description": "test profile",
                "source_evidence": ["unit test"],
                "fingerprint": {{
                    "block_name": "{block_name}",
                    "attribute_tags": {fingerprint_tags}
                }},
                "fields": {fields_json}
            }}"#
        )
    }

    fn registry_json(profiles: &[String]) -> String {
        format!(
            r#"{{"title_block_schema":1,"profiles":[{}]}}"#,
            profiles.join(",")
        )
    }

    fn profile_pack_json(profiles: &[String]) -> String {
        format!(
            r#"{{
                "profile_pack_schema": 1,
                "pack_id": "example.title-blocks",
                "pack_version": "1.0.0",
                "title_block_schema": 1,
                "profiles": [{}]
            }}"#,
            profiles.join(",")
        )
    }

    #[test]
    fn registry_loads_generic_profile() {
        let p = find_profile("AUTOCAD_MCP_GENERIC").unwrap();
        assert_eq!(p.profile_id, "AUTOCAD_MCP_GENERIC");
        assert_eq!(p.block_name, "AUTOCAD_MCP_GENERIC");
        assert_eq!(p.schema_version, 1);
        assert_eq!(p.fingerprint_tags(), full_generic_tags());
    }

    #[test]
    fn find_profile_case_insensitive() {
        assert!(find_profile("autocad_mcp_generic").is_some());
        assert!(find_profile("AUTOCAD_MCP_GENERIC").is_some());
    }

    #[test]
    fn find_unknown_profile_returns_none() {
        assert!(find_profile("NORTH_ARROW").is_none());
        assert!(find_profile("").is_none());
    }

    #[test]
    fn tag_for_canonical_fields() {
        let p = find_profile("AUTOCAD_MCP_GENERIC").unwrap();
        assert_eq!(p.tag_for("revision"), Some("REVISION"));
        assert_eq!(p.tag_for("drawing_number"), Some("DRAWING_NUMBER"));
        assert_eq!(p.tag_for("alternative_reference"), Some("REFERENCE"));
        assert_eq!(p.tag_for("drawing_title_big"), Some("TITLE_LINE_1"));
        assert_eq!(p.tag_for("drawing_title_med"), Some("TITLE_LINE_2"));
        assert_eq!(p.tag_for("sheet"), Some("SHEET_NUMBER"));
        assert_eq!(p.tag_for("sheet_total"), Some("SHEET_COUNT"));
    }

    #[test]
    fn tag_for_canonical_field_case_insensitive() {
        let p = find_profile("AUTOCAD_MCP_GENERIC").unwrap();
        assert_eq!(p.tag_for("REVISION"), Some("REVISION"));
        assert_eq!(p.tag_for("Revision"), Some("REVISION"));
    }

    #[test]
    fn tag_for_unknown_field_returns_none() {
        let p = find_profile("AUTOCAD_MCP_GENERIC").unwrap();
        assert!(p.tag_for("nonexistent_field").is_none());
    }

    #[test]
    fn all_profile_names_includes_generic_profile() {
        let names = all_profile_names();
        assert!(names.contains(&"AUTOCAD_MCP_GENERIC"), "got: {names:?}");
    }

    #[test]
    fn embedded_registry_exposes_exact_bytes_and_lowercase_sha256() {
        assert!(std::str::from_utf8(TITLE_BLOCK_PROFILE_REGISTRY_BYTES).is_ok());
        assert_eq!(
            title_block_profile_registry_sha256(),
            "69b0c455b4730f25f441c321729394c9026ef2ffb05248913cec97649ee7d557"
        );
    }

    #[test]
    fn profile_definition_projection_is_closed_and_sorted() {
        let definitions = title_block_profile_definitions();
        assert_eq!(
            definitions,
            vec![TitleBlockProfileDefinition {
                profile_id: "AUTOCAD_MCP_GENERIC".to_string(),
                canonical_fields: vec![
                    "alternative_reference".to_string(),
                    "drawing_number".to_string(),
                    "drawing_title_big".to_string(),
                    "drawing_title_med".to_string(),
                    "revision".to_string(),
                    "sheet".to_string(),
                    "sheet_total".to_string(),
                ],
                canonical_to_tag: BTreeMap::from([
                    ("alternative_reference".to_string(), "REFERENCE".to_string(),),
                    ("drawing_number".to_string(), "DRAWING_NUMBER".to_string(),),
                    ("drawing_title_big".to_string(), "TITLE_LINE_1".to_string(),),
                    ("drawing_title_med".to_string(), "TITLE_LINE_2".to_string(),),
                    ("revision".to_string(), "REVISION".to_string()),
                    ("sheet".to_string(), "SHEET_NUMBER".to_string()),
                    ("sheet_total".to_string(), "SHEET_COUNT".to_string()),
                ]),
                fingerprint: TitleBlockFingerprint {
                    block_name: "AUTOCAD_MCP_GENERIC".to_string(),
                    attribute_tags: vec![
                        "DRAWING_NUMBER".to_string(),
                        "REFERENCE".to_string(),
                        "REVISION".to_string(),
                        "SHEET_COUNT".to_string(),
                        "SHEET_NUMBER".to_string(),
                        "TITLE_LINE_1".to_string(),
                        "TITLE_LINE_2".to_string(),
                    ],
                },
            }]
        );
        assert!(definitions
            .windows(2)
            .all(|rows| rows[0].profile_id < rows[1].profile_id));
        assert!(definitions.iter().all(|definition| definition
            .canonical_fields
            .windows(2)
            .all(|pair| pair[0] < pair[1])));
        assert!(definitions.iter().all(|definition| {
            definition.canonical_fields
                == definition
                    .canonical_to_tag
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
        }));
        assert!(definitions.iter().all(|definition| {
            definition
                .canonical_to_tag
                .values()
                .cloned()
                .collect::<BTreeSet<_>>()
                == definition
                    .fingerprint
                    .attribute_tags
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
        }));
    }

    #[test]
    fn profile_definition_projection_round_trips_as_closed_json() {
        let definition = title_block_profile_definitions()
            .into_iter()
            .next()
            .unwrap();
        let serialized = serde_json::to_value(&definition).unwrap();
        assert_eq!(
            serde_json::from_value::<TitleBlockProfileDefinition>(serialized.clone()).unwrap(),
            definition
        );

        let mut with_unknown = serialized.as_object().unwrap().clone();
        with_unknown.insert("unknown".to_string(), serde_json::Value::Bool(true));
        let error = serde_json::from_value::<TitleBlockProfileDefinition>(
            serde_json::Value::Object(with_unknown),
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"), "got: {error}");
    }

    #[test]
    fn registry_source_contract_rejects_unknown_fields() {
        let profile = profile_json_with_fields(
            "PROFILE_A",
            "PROFILE_A",
            &full_generic_tags(),
            r#"{
                "revision": "REVISION",
                "drawing_number": "DRAWING_NUMBER",
                "alternative_reference": "REFERENCE",
                "drawing_title_big": "TITLE_LINE_1",
                "drawing_title_med": "TITLE_LINE_2",
                "sheet": "SHEET_NUMBER",
                "sheet_total": "SHEET_COUNT"
            }"#,
        );
        let original =
            serde_json::from_str::<serde_json::Value>(&registry_json(&[profile])).unwrap();

        let mut root_unknown = original.clone();
        root_unknown
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        assert!(profiles_from_json(&root_unknown.to_string())
            .unwrap_err()
            .to_string()
            .contains("unknown field `unexpected`"));

        let mut profile_unknown = original.clone();
        profile_unknown["profiles"][0]
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        assert!(profiles_from_json(&profile_unknown.to_string())
            .unwrap_err()
            .to_string()
            .contains("unknown field `unexpected`"));

        let mut fingerprint_unknown = original;
        fingerprint_unknown["profiles"][0]["fingerprint"]
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        assert!(profiles_from_json(&fingerprint_unknown.to_string())
            .unwrap_err()
            .to_string()
            .contains("unknown field `unexpected`"));
    }

    #[test]
    fn registry_rejects_exact_duplicate_canonical_field_keys() {
        let profile = profile_json_with_fields(
            "PROFILE_A",
            "PROFILE_A",
            &full_generic_tags(),
            r#"{
                "revision": "REVISION",
                "revision": "REVISION",
                "drawing_number": "DRAWING_NUMBER",
                "alternative_reference": "REFERENCE",
                "drawing_title_big": "TITLE_LINE_1",
                "drawing_title_med": "TITLE_LINE_2",
                "sheet": "SHEET_NUMBER",
                "sheet_total": "SHEET_COUNT"
            }"#,
        );
        let error = profiles_from_json(&registry_json(&[profile])).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate canonical field key 'revision'"),
            "got: {error:#}"
        );
    }

    #[test]
    fn registry_rejects_canonical_field_keys_that_collide_after_normalization() {
        let profile = profile_json_with_fields(
            "PROFILE_A",
            "PROFILE_A",
            &full_generic_tags(),
            r#"{
                "revision": "REVISION",
                " Revision ": "REVISION",
                "drawing_number": "DRAWING_NUMBER",
                "alternative_reference": "REFERENCE",
                "drawing_title_big": "TITLE_LINE_1",
                "drawing_title_med": "TITLE_LINE_2",
                "sheet": "SHEET_NUMBER",
                "sheet_total": "SHEET_COUNT"
            }"#,
        );
        let error = profiles_from_json(&registry_json(&[profile])).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("after normalization to 'revision'"),
            "got: {error:#}"
        );
    }

    #[test]
    fn registry_rejects_two_canonical_fields_mapped_to_one_normalized_tag() {
        let profile = profile_json_with_fields(
            "PROFILE_A",
            "PROFILE_A",
            &full_generic_tags(),
            r#"{
                "revision": "REVISION",
                "drawing_number": " revision ",
                "alternative_reference": "REFERENCE",
                "drawing_title_big": "TITLE_LINE_1",
                "drawing_title_med": "TITLE_LINE_2",
                "sheet": "SHEET_NUMBER",
                "sheet_total": "SHEET_COUNT"
            }"#,
        );
        let error = profiles_from_json(&registry_json(&[profile])).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("to the same normalized tag 'REVISION'"),
            "got: {error:#}"
        );
    }

    #[test]
    fn registry_preserves_unmapped_fingerprint_tags() {
        let profile = profile_json_with_fields(
            "PROFILE_A",
            "PROFILE_A",
            &full_generic_tags(),
            r#"{
                "revision": "REVISION",
                "drawing_number": "DRAWING_NUMBER",
                "alternative_reference": "REFERENCE",
                "drawing_title_big": "TITLE_LINE_1",
                "drawing_title_med": "TITLE_LINE_2",
                "sheet": "SHEET_NUMBER"
            }"#,
        );
        let profiles = profiles_from_json(&registry_json(&[profile])).unwrap();
        assert_eq!(profiles[0].fingerprint_tags, full_generic_tags());
        assert!(
            !profiles[0]
                .canonical_to_tag
                .values()
                .any(|tag| tag == "SHEET_COUNT"),
            "an unmapped fingerprint tag must remain part of resolution without becoming writable"
        );
    }

    #[test]
    fn administrator_pack_extends_embedded_registry_with_distinct_authority() {
        let custom = profile_json_with_fields(
            "EXAMPLE_A1",
            "EXAMPLE_TITLE_A1",
            &["DRAWING_NO", "REV"],
            r#"{
                "drawing_number": "DRAWING_NO",
                "revision": "REV"
            }"#,
        );
        let json = profile_pack_json(&[custom]);
        let pack = parse_administrator_profile_pack(json.as_bytes()).unwrap();
        let summary = pack.summary();
        assert_eq!(summary.pack_id, "example.title-blocks");
        assert_eq!(summary.pack_version, "1.0.0");
        assert_eq!(summary.sha256, sha256(json.as_bytes()));
        assert_eq!(summary.profile_ids, ["EXAMPLE_A1".to_string()]);

        let registry = ProfileRegistry::with_administrator_pack(pack).unwrap();
        assert!(registry.find_profile("AUTOCAD_MCP_GENERIC").is_some());
        let profile = registry
            .resolve_profile(&[title_block("EXAMPLE_TITLE_A1", &["DRAWING_NO", "REV"])])
            .unwrap();
        assert_eq!(profile.profile_id, "EXAMPLE_A1");
        assert!(matches!(
            profile.authority(),
            ProfileAuthority::Administrator(identity)
                if identity.pack_id == "example.title-blocks"
        ));
    }

    #[test]
    fn administrator_pack_cannot_override_embedded_profile_id() {
        let custom = profile_json_with_fields(
            "autocad_mcp_generic",
            "DIFFERENT_BLOCK",
            &["REV"],
            r#"{"revision": "REV"}"#,
        );
        let pack =
            parse_administrator_profile_pack(profile_pack_json(&[custom]).as_bytes()).unwrap();
        let error = ProfileRegistry::with_administrator_pack(pack).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("collides with existing profile_id"),
            "got: {error:#}"
        );
    }

    #[test]
    fn administrator_pack_cannot_duplicate_embedded_fingerprint() {
        let custom = profile_json("EXAMPLE_DUPLICATE", "AUTOCAD_MCP_GENERIC");
        let pack =
            parse_administrator_profile_pack(profile_pack_json(&[custom]).as_bytes()).unwrap();
        let error = ProfileRegistry::with_administrator_pack(pack).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicates the exact fingerprint"),
            "got: {error:#}"
        );
    }

    #[test]
    fn administrator_pack_rejects_empty_field_mapping() {
        let custom = profile_json_with_fields("EXAMPLE_EMPTY", "EXAMPLE_EMPTY", &["REV"], r#"{}"#);
        let error =
            parse_administrator_profile_pack(profile_pack_json(&[custom]).as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("at least one canonical field"),
            "got: {error:#}"
        );
    }

    #[test]
    fn administrator_pack_rejects_self_declared_authority() {
        let custom = profile_json_with_fields(
            "EXAMPLE_A1",
            "EXAMPLE_TITLE_A1",
            &["REV"],
            r#"{"revision": "REV"}"#,
        );
        let mut value: serde_json::Value =
            serde_json::from_str(&profile_pack_json(&[custom])).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("authority".to_string(), serde_json::json!("certified"));
        let error = parse_administrator_profile_pack(value.to_string().as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("unknown field"),
            "got: {error:#}"
        );
    }

    #[test]
    fn resolve_profile_requires_exact_block_name_and_tag_set_match() {
        let block = title_block("autocad_mcp_generic", &full_generic_tags());
        let profile = resolve_profile(&[block]).unwrap();
        assert_eq!(profile.profile_id, "AUTOCAD_MCP_GENERIC");
    }

    #[test]
    fn resolve_profile_rejects_block_name_only_match() {
        let block = title_block("AUTOCAD_MCP_GENERIC", &["REVISION", "DRAWING_NUMBER"]);
        let err = resolve_profile(&[block]).unwrap_err();
        assert!(matches!(err, ProfileResolutionError::NoMatch { .. }));
    }

    #[test]
    fn resolve_profile_rejects_tag_set_only_match() {
        let block = title_block("Other_Title_Block", &full_generic_tags());
        let err = resolve_profile(&[block]).unwrap_err();
        assert!(matches!(err, ProfileResolutionError::NoMatch { .. }));
    }

    #[test]
    fn resolve_profile_reports_no_match() {
        let block = title_block("Unknown_Title_Block", &["REVISION"]);
        let err = resolve_profile(&[block]).unwrap_err();
        assert!(matches!(err, ProfileResolutionError::NoMatch { .. }));
        assert!(err
            .to_string()
            .contains("no recognised title-block profile"));
    }

    #[test]
    fn resolve_profile_reports_ambiguous_different_profile_matches() {
        let json = format!(
            r#"{{
                "title_block_schema": 1,
                "profiles": [
                    {},
                    {}
                ]
            }}"#,
            profile_json("PROFILE_A", "PROFILE_A"),
            profile_json("PROFILE_B", "PROFILE_B")
        );
        let profiles = profiles_from_json(&json).unwrap();
        let candidates = vec![
            title_block("PROFILE_A", &full_generic_tags()),
            title_block("PROFILE_B", &full_generic_tags()),
        ];
        let err = resolve_profile_from_registry(&profiles, &candidates).unwrap_err();
        assert!(matches!(
            err,
            ProfileResolutionError::Ambiguous { ref profile_ids }
                if profile_ids == &vec!["PROFILE_A".to_string(), "PROFILE_B".to_string()]
        ));
    }

    #[test]
    fn canonical_fields_returns_all_keys_sorted() {
        let p = find_profile("AUTOCAD_MCP_GENERIC").unwrap();
        let fields = p.canonical_fields();
        assert!(fields.contains(&"revision"));
        assert!(fields.contains(&"drawing_number"));
        assert!(fields.contains(&"alternative_reference"));
        assert!(fields.contains(&"drawing_title_big"));
        assert!(fields.contains(&"drawing_title_med"));
        assert!(fields.contains(&"sheet"));
        assert!(fields.contains(&"sheet_total"));
        assert_eq!(fields.len(), 7);
        assert!(
            fields.windows(2).all(|w| w[0] <= w[1]),
            "fields are not sorted: {fields:?}"
        );
    }
}
