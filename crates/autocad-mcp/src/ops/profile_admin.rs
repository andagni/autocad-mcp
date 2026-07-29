//! Offline administrator workflow for configurable title-block profiles.
//!
//! These operations are deliberately CLI-only. They are not registered as MCP
//! tools and do not participate in generic `call` dispatch.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::autocad_reader::{DrawingFormat, DrawingSnapshot, Reader};
use crate::ops::profiles::{
    self, CandidateFingerprint, ProfilePackSummary, ProfileRegistry, TitleBlockFingerprint,
};

const PROFILE_WITNESS_SCHEMA: u32 = 1;
const PROFILE_VERIFICATION_SCHEMA: u32 = 1;
const MAX_WITNESS_DOCUMENT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileWitnessDocument {
    pub profile_witness_schema: u32,
    pub witnesses: Vec<ProfileWitness>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileWitness {
    pub drawing_id: String,
    pub profile_id: String,
    pub drawing_path: String,
    pub drawing_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileVerificationReport {
    pub profile_verification_schema: u32,
    pub status: String,
    pub profile_pack: ProfilePackSummary,
    pub witnesses: Vec<VerifiedProfileWitness>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedProfileWitness {
    pub drawing_id: String,
    pub profile_id: String,
    pub drawing_sha256: String,
    pub fingerprint: TitleBlockFingerprint,
    pub target_inserts: usize,
    pub mapped_fields: Vec<String>,
    pub duplicate_unrequested_tags: Vec<String>,
}

pub fn validate_profile_pack(path: &Path) -> Result<ProfilePackSummary> {
    let pack = profiles::load_administrator_profile_pack(path)?;
    ProfileRegistry::with_administrator_pack(pack.clone())?;
    Ok(pack.summary())
}

pub fn verify_profile_pack(
    profile_pack_path: &Path,
    witness_document_path: &Path,
) -> Result<ProfileVerificationReport> {
    let pack = profiles::load_administrator_profile_pack(profile_pack_path)?;
    let registry = ProfileRegistry::with_administrator_pack(pack.clone())?;
    let witnesses: ProfileWitnessDocument = read_json_file(
        witness_document_path,
        MAX_WITNESS_DOCUMENT_BYTES,
        "profile witnesses",
    )?;
    validate_witness_document(&pack.summary(), &witnesses)?;

    let mut results = Vec::with_capacity(witnesses.witnesses.len());
    for witness in witnesses.witnesses {
        results.push(verify_witness(&registry, witness)?);
    }
    results.sort_by(|left, right| {
        left.profile_id
            .cmp(&right.profile_id)
            .then(left.drawing_id.cmp(&right.drawing_id))
    });

    Ok(ProfileVerificationReport {
        profile_verification_schema: PROFILE_VERIFICATION_SCHEMA,
        status: "ok".to_string(),
        profile_pack: pack.summary(),
        witnesses: results,
    })
}

fn validate_witness_document(
    pack: &ProfilePackSummary,
    document: &ProfileWitnessDocument,
) -> Result<()> {
    if document.profile_witness_schema != PROFILE_WITNESS_SCHEMA {
        return Err(anyhow!(
            "unsupported profile_witness_schema {}; expected {}",
            document.profile_witness_schema,
            PROFILE_WITNESS_SCHEMA
        ));
    }
    if document.witnesses.is_empty() {
        return Err(anyhow!("profile witnesses document contains no witnesses"));
    }

    let expected = pack.profile_ids.iter().cloned().collect::<BTreeSet<_>>();
    let mut seen_profiles = BTreeSet::new();
    let mut seen_drawing_ids = BTreeSet::new();
    for witness in &document.witnesses {
        if witness.drawing_id.trim().is_empty() {
            return Err(anyhow!("profile witness drawing_id must not be empty"));
        }
        if !seen_drawing_ids.insert(witness.drawing_id.clone()) {
            return Err(anyhow!(
                "duplicate profile witness drawing_id '{}'",
                witness.drawing_id
            ));
        }
        if !expected.contains(&witness.profile_id) {
            return Err(anyhow!(
                "profile witness '{}' references profile '{}' outside pack '{}'",
                witness.drawing_id,
                witness.profile_id,
                pack.pack_id
            ));
        }
        seen_profiles.insert(witness.profile_id.clone());
        if !is_lowercase_sha256(&witness.drawing_sha256) {
            return Err(anyhow!(
                "profile witness '{}' has an invalid drawing_sha256",
                witness.drawing_id
            ));
        }
    }
    if seen_profiles != expected {
        let missing = expected
            .difference(&seen_profiles)
            .cloned()
            .collect::<Vec<_>>();
        return Err(anyhow!(
            "profile witnesses document has no representative drawing for profiles {:?}",
            missing
        ));
    }
    Ok(())
}

fn verify_witness(
    registry: &ProfileRegistry,
    witness: ProfileWitness,
) -> Result<VerifiedProfileWitness> {
    let path = Path::new(&witness.drawing_path);
    validate_regular_absolute_file(path, "profile witness drawing")?;
    let bytes = std::fs::read(path).map_err(|error| {
        anyhow!(
            "open profile witness drawing '{}' ({}): {error}",
            witness.drawing_id,
            path.display()
        )
    })?;
    let before_sha256 = sha256_bytes(&bytes);
    if before_sha256 != witness.drawing_sha256 {
        return Err(anyhow!(
            "profile witness '{}' drawing SHA-256 is {}, expected {}",
            witness.drawing_id,
            before_sha256,
            witness.drawing_sha256
        ));
    }
    let format = DrawingFormat::from_path(path).map_err(|error| {
        anyhow!(
            "open profile witness drawing '{}' ({}): {error}",
            witness.drawing_id,
            path.display()
        )
    })?;
    let session = Reader::open_snapshot(DrawingSnapshot::new(format, bytes)).map_err(|error| {
        anyhow!(
            "open profile witness drawing '{}' ({}): {error}",
            witness.drawing_id,
            path.display()
        )
    })?;
    let candidates = session.read_title_blocks().map_err(|error| {
        anyhow!(
            "open profile witness drawing '{}' ({}): {error}",
            witness.drawing_id,
            path.display()
        )
    })?;
    if sha256_file(path)? != before_sha256 {
        return Err(anyhow!(
            "profile witness drawing '{}' changed while it was being verified",
            witness.drawing_id
        ));
    }

    let resolved = registry.resolve_profile(&candidates).map_err(|error| {
        anyhow!(
            "profile witness '{}' did not resolve exactly: {error}",
            witness.drawing_id
        )
    })?;
    if resolved.profile_id != witness.profile_id {
        return Err(anyhow!(
            "profile witness '{}' resolved to profile '{}', expected '{}'",
            witness.drawing_id,
            resolved.profile_id,
            witness.profile_id
        ));
    }
    let fingerprint = resolved.title_block_fingerprint();
    let targets = candidates
        .iter()
        .filter(|candidate| CandidateFingerprint::from_title_block(candidate) == fingerprint)
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return Err(anyhow!(
            "profile witness '{}' resolved without a target insert",
            witness.drawing_id
        ));
    }

    let mut duplicate_unrequested_tags = BTreeSet::new();
    for target in &targets {
        for canonical in resolved.canonical_fields() {
            let tag = resolved
                .tag_for(canonical)
                .expect("canonical fields must resolve to tags");
            if target.attribute_arrays.contains_key(tag) {
                return Err(anyhow!(
                    "profile witness '{}' maps canonical field '{}' to duplicate tag '{}'",
                    witness.drawing_id,
                    canonical,
                    tag
                ));
            }
            if !target.attributes.contains_key(tag) {
                return Err(anyhow!(
                    "profile witness '{}' maps canonical field '{}' to missing tag '{}'",
                    witness.drawing_id,
                    canonical,
                    tag
                ));
            }
        }
        duplicate_unrequested_tags.extend(
            target
                .duplicate_attribute_tags()
                .into_iter()
                .map(str::to_string),
        );
    }

    Ok(VerifiedProfileWitness {
        drawing_id: witness.drawing_id,
        profile_id: witness.profile_id,
        drawing_sha256: before_sha256,
        fingerprint,
        target_inserts: targets.len(),
        mapped_fields: resolved
            .canonical_fields()
            .into_iter()
            .map(str::to_string)
            .collect(),
        duplicate_unrequested_tags: duplicate_unrequested_tags.into_iter().collect(),
    })
}

fn read_json_file<T>(path: &Path, maximum_bytes: u64, label: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    validate_regular_absolute_file(path, label)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.len() > maximum_bytes {
        return Err(anyhow!(
            "{label} file exceeds the {maximum_bytes}-byte limit: {}",
            path.display()
        ));
    }
    let bytes =
        std::fs::read(path).map_err(|error| anyhow!("read {label} {}: {error}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(anyhow!(
            "{label} file changed while it was being read: {}",
            path.display()
        ));
    }
    let json = std::str::from_utf8(&bytes)
        .map_err(|error| anyhow!("{label} file must be strict UTF-8: {error}"))?;
    serde_json::from_str(json).map_err(anyhow::Error::from)
}

fn validate_regular_absolute_file(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        return Err(anyhow!("{label} path must be absolute: {}", path.display()));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| anyhow!("inspect {label} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "{label} path must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::entities::{AttributeEntity, EntityType, Insert};
    use acadrust::types::Vector3;
    use acadrust::{CadDocument, DxfWriter};

    #[test]
    fn witness_document_requires_every_pack_profile() {
        let pack = ProfilePackSummary {
            profile_pack_schema: 1,
            pack_id: "example.pack".to_string(),
            pack_version: "1.0.0".to_string(),
            sha256: "0".repeat(64),
            profile_count: 2,
            profile_ids: vec!["A".to_string(), "B".to_string()],
        };
        let document = ProfileWitnessDocument {
            profile_witness_schema: 1,
            witnesses: vec![ProfileWitness {
                drawing_id: "drawing-a".to_string(),
                profile_id: "A".to_string(),
                drawing_path: "/drawing-a.dxf".to_string(),
                drawing_sha256: "1".repeat(64),
            }],
        };
        let error = validate_witness_document(&pack, &document).unwrap_err();
        assert!(error.to_string().contains("[\"B\"]"), "got: {error:#}");
    }

    #[test]
    fn witness_document_rejects_unknown_profile() {
        let pack = ProfilePackSummary {
            profile_pack_schema: 1,
            pack_id: "example.pack".to_string(),
            pack_version: "1.0.0".to_string(),
            sha256: "0".repeat(64),
            profile_count: 1,
            profile_ids: vec!["A".to_string()],
        };
        let document = ProfileWitnessDocument {
            profile_witness_schema: 1,
            witnesses: vec![ProfileWitness {
                drawing_id: "drawing-c".to_string(),
                profile_id: "C".to_string(),
                drawing_path: "/drawing-c.dxf".to_string(),
                drawing_sha256: "1".repeat(64),
            }],
        };
        let error = validate_witness_document(&pack, &document).unwrap_err();
        assert!(error.to_string().contains("outside pack"), "got: {error:#}");
    }

    #[test]
    fn verification_proves_exact_profile_without_emitting_paths_or_values() {
        let directory = tempfile::tempdir().unwrap();
        let profile_path = directory.path().join("profiles.json");
        std::fs::write(
            &profile_path,
            br#"{
                "profile_pack_schema": 1,
                "pack_id": "example.title-blocks",
                "pack_version": "1.0.0",
                "title_block_schema": 1,
                "profiles": [{
                    "profile_id": "EXAMPLE_A1",
                    "schema_version": 1,
                    "description": "Example title block",
                    "source_evidence": ["review:unit-test"],
                    "fingerprint": {
                        "block_name": "EXAMPLE_A1",
                        "attribute_tags": ["DRAWING_NO", "REV"]
                    },
                    "fields": {
                        "drawing_number": "DRAWING_NO",
                        "revision": "REV"
                    }
                }]
            }"#,
        )
        .unwrap();

        let drawing_path = directory.path().join("private-witness.dxf");
        let mut document = CadDocument::new();
        let mut insert = Insert::new("EXAMPLE_A1", Vector3::new(0.0, 0.0, 0.0));
        insert
            .attributes
            .push(AttributeEntity::simple("DRAWING_NO", "PRIVATE-001"));
        insert
            .attributes
            .push(AttributeEntity::simple("REV", "PRIVATE-REV"));
        document.add_entity(EntityType::Insert(insert)).unwrap();
        DxfWriter::new(&document)
            .write_to_file(&drawing_path)
            .unwrap();

        let witness_path = directory.path().join("witnesses.json");
        std::fs::write(
            &witness_path,
            serde_json::to_vec(&serde_json::json!({
                "profile_witness_schema": 1,
                "witnesses": [{
                    "drawing_id": "drawing-a",
                    "profile_id": "EXAMPLE_A1",
                    "drawing_path": drawing_path.to_string_lossy(),
                    "drawing_sha256": sha256_file(&drawing_path).unwrap()
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let report = verify_profile_pack(&profile_path, &witness_path).unwrap();
        assert_eq!(report.status, "ok");
        assert_eq!(report.witnesses.len(), 1);
        assert_eq!(report.witnesses[0].profile_id, "EXAMPLE_A1");
        assert_eq!(
            report.witnesses[0].mapped_fields,
            ["drawing_number".to_owned(), "revision".to_owned()]
        );
        let serialized = serde_json::to_string(&report).unwrap();
        let private_path = drawing_path.to_string_lossy();
        assert!(!serialized.contains(private_path.as_ref()));
        assert!(!serialized.contains("PRIVATE-001"));
        assert!(!serialized.contains("PRIVATE-REV"));
    }
}
