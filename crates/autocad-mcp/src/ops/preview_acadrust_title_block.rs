//! Preview-qualified pure-Rust AC1032 title-block mutation.
//!
//! Candidate generation is deliberately separated from persistence. The
//! writer proves its bounded allowed delta first; the guarded installer then
//! builds from an exclusively locked source snapshot and commits the exact
//! verified bytes through the Windows transactional drawing-install boundary.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use autocad_writer::contract::{TitleBlockFingerprint, TitleBlockWrite};
use autocad_writer::{
    DrawingFormat, DrawingSnapshot, RoundtripClaimBoundary, RoundtripReceipt, Writer,
};

use super::profiles::{ProfileAuthority, ProfilePackIdentity, ProfileRegistry};
use super::xref_mutation::{
    guarded_install_candidate, GuardedCandidateInstallDisposition, GuardedCandidateInstallReceipt,
};

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreviewTitleBlockWriteReport {
    pub backend: String,
    pub source_format: String,
    pub drawing_version: String,
    pub profile_id: String,
    pub profile_authority: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_pack_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_pack_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_pack_sha256: Option<String>,
    pub fields_written: usize,
    pub target_inserts: usize,
    pub attributes_written: usize,
    pub writer_receipt: RoundtripReceipt,
    pub install_receipt: GuardedCandidateInstallReceipt,
}

#[derive(Debug, Clone)]
struct CandidatePlan {
    profile_id: String,
    profile_authority: String,
    profile_pack: Option<ProfilePackIdentity>,
    fields_written: usize,
    target_inserts: usize,
    attributes_written: usize,
    writer_receipt: RoundtripReceipt,
}

#[derive(Debug)]
pub(crate) struct PreviewTitleBlockWriteError {
    domain: autocad_diagnostics::DomainError,
    installation_may_have_occurred: bool,
}

impl PreviewTitleBlockWriteError {
    pub(crate) fn code(&self) -> &str {
        self.domain.code()
    }

    pub(crate) fn message(&self) -> &str {
        self.domain.message()
    }

    pub(crate) fn installation_may_have_occurred(&self) -> bool {
        self.installation_may_have_occurred
    }
}

impl std::fmt::Display for PreviewTitleBlockWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.domain, formatter)
    }
}

impl std::error::Error for PreviewTitleBlockWriteError {}

pub(crate) fn write(
    path: &Path,
    registry: &ProfileRegistry,
    canonical_fields: &BTreeMap<String, String>,
) -> Result<PreviewTitleBlockWriteReport, PreviewTitleBlockWriteError> {
    let result = guarded_install_candidate(path, |locked_source| {
        build_candidate_from_locked_source(locked_source, registry, canonical_fields)
    });
    let (plan, install_receipt) = result.map_err(|error| PreviewTitleBlockWriteError {
        domain: autocad_diagnostics::DomainError::new(
            error.code().to_string(),
            error.detail().to_string(),
        ),
        installation_may_have_occurred: error.disposition()
            == GuardedCandidateInstallDisposition::InstallationMayHaveOccurred,
    })?;

    if plan.writer_receipt.source_sha256 != install_receipt.source_sha256
        || plan.writer_receipt.candidate_sha256 != install_receipt.installed_sha256
    {
        return Err(PreviewTitleBlockWriteError {
            domain: autocad_diagnostics::DomainError::new(
                "preview_writer_install_outcome_unknown",
                "installed drawing digests do not join to the verified writer receipt",
            ),
            installation_may_have_occurred: true,
        });
    }
    Ok(PreviewTitleBlockWriteReport {
        backend: "acadrust_preview".to_string(),
        source_format: "dwg".to_string(),
        drawing_version: "AC1032".to_string(),
        profile_id: plan.profile_id,
        profile_authority: plan.profile_authority,
        profile_pack_id: plan.profile_pack.as_ref().map(|pack| pack.pack_id.clone()),
        profile_pack_version: plan
            .profile_pack
            .as_ref()
            .map(|pack| pack.pack_version.clone()),
        profile_pack_sha256: plan.profile_pack.as_ref().map(|pack| pack.sha256.clone()),
        fields_written: plan.fields_written,
        target_inserts: plan.target_inserts,
        attributes_written: plan.attributes_written,
        writer_receipt: plan.writer_receipt,
        install_receipt,
    })
}

fn build_candidate_from_locked_source(
    locked_source: &[u8],
    registry: &ProfileRegistry,
    canonical_fields: &BTreeMap<String, String>,
) -> Result<(Vec<u8>, CandidatePlan), String> {
    let reader = autocad_reader::Reader::open_snapshot(autocad_reader::DrawingSnapshot::new(
        autocad_reader::DrawingFormat::Dwg,
        locked_source.to_vec(),
    ))
    .map_err(|error| format!("locked source reader admission failed: {error}"))?;
    let title_blocks = reader
        .read_title_blocks()
        .map_err(|error| format!("locked source title-block projection failed: {error}"))?;
    if title_blocks.is_empty() {
        return Err("locked source contains no attributed INSERT blocks".to_string());
    }
    let profile = registry.resolve_profile(&title_blocks).map_err(|error| {
        format!("{error}. Cannot write without an exact administrator-reviewed title-block profile")
    })?;

    let mut tag_values = BTreeMap::new();
    for (canonical, value) in canonical_fields {
        let tag = profile.tag_for(canonical).ok_or_else(|| {
            format!(
                "unknown canonical field '{canonical}' for profile '{}'; valid fields: {:?}",
                profile.profile_id,
                profile.canonical_fields()
            )
        })?;
        tag_values.insert(tag.to_string(), value.clone());
    }

    let profile_fingerprint = profile.title_block_fingerprint();
    let mut writer = Writer::open_snapshot(DrawingSnapshot::new(
        DrawingFormat::Dwg,
        locked_source.to_vec(),
    ))
    .map_err(|error| format!("writer source admission failed: {error}"))?;
    let mutation = writer
        .write_title_block(TitleBlockWrite {
            fingerprint: TitleBlockFingerprint {
                block_name: profile_fingerprint.block_name,
                attribute_tags: profile_fingerprint.attribute_tags,
            },
            tag_values,
        })
        .map_err(|error| format!("title-block mutation rejected: {error}"))?;
    let candidate = writer
        .encode_candidate()
        .map_err(|error| format!("candidate preservation proof failed: {error}"))?;
    if candidate.receipt().claim_boundary != RoundtripClaimBoundary::PreviewQualified
        || !candidate.receipt().reader_reopen_verified
        || !candidate.receipt().operation_postconditions_verified
        || !candidate.receipt().whole_document_preservation_verified
        || candidate.receipt().native_host_verified
    {
        return Err(
            "writer receipt did not satisfy the bounded Preview qualification contract".to_string(),
        );
    }

    let profile_authority = match profile.authority() {
        ProfileAuthority::Embedded => "embedded".to_string(),
        ProfileAuthority::Administrator(_) => "administrator".to_string(),
    };
    let profile_pack = profile.administrator_pack().cloned();
    let profile_id = profile.profile_id.clone();
    let (bytes, writer_receipt) = candidate.into_parts();
    Ok((
        bytes,
        CandidatePlan {
            profile_id,
            profile_authority,
            profile_pack,
            fields_written: mutation.fields_written,
            target_inserts: mutation.target_inserts,
            attributes_written: mutation.attributes_written,
            writer_receipt,
        },
    ))
}

#[cfg(test)]
mod tests {
    use acadrust::entities::{AttributeEntity, EntityType, Insert};
    use acadrust::tables::BlockRecord;
    use acadrust::types::Vector3;
    use acadrust::{CadDocument, DwgWriter};

    use super::*;

    fn profiled_title_block_dwg() -> Vec<u8> {
        let mut document = CadDocument::new();
        let mut definition = BlockRecord::new("AUTOCAD_MCP_GENERIC");
        definition.handle = document.allocate_handle();
        definition.block_entity_handle = document.allocate_handle();
        definition.block_end_handle = document.allocate_handle();
        definition.flags.has_attributes = true;
        document.block_records.add(definition).unwrap();

        let mut insert = Insert::new("AUTOCAD_MCP_GENERIC", Vector3::ZERO);
        insert.common.handle = document.allocate_handle();
        for (tag, value) in [
            ("REVISION", "P01"),
            ("DRAWING_NUMBER", "A-001"),
            ("REFERENCE", "REF-1"),
            ("TITLE_LINE_1", "TITLE"),
            ("TITLE_LINE_2", "SUBTITLE"),
            ("SHEET_NUMBER", "1"),
            ("SHEET_COUNT", "1"),
        ] {
            let mut attribute = AttributeEntity::simple(tag, value);
            attribute.common.handle = document.allocate_handle();
            attribute.common.owner_handle = insert.common.handle;
            insert.attributes.push(attribute);
        }
        let insert_handle = insert.common.handle;
        document.add_entity(EntityType::Insert(insert)).unwrap();
        let definition = document
            .block_records
            .get_mut("AUTOCAD_MCP_GENERIC")
            .unwrap();
        definition.insert_handles.push(insert_handle);
        definition.insert_count_bytes.push(1);
        DwgWriter::write_to_vec(&document).unwrap()
    }

    #[test]
    fn locked_snapshot_build_resolves_profile_and_returns_preview_receipt() {
        let source = profiled_title_block_dwg();
        let fields = BTreeMap::from([
            ("drawing_number".to_string(), "A-002".to_string()),
            ("revision".to_string(), "P02".to_string()),
        ]);
        let (candidate, plan) = build_candidate_from_locked_source(
            &source,
            &super::super::profiles::embedded_profile_registry(),
            &fields,
        )
        .unwrap();
        assert_eq!(&candidate[..6], b"AC1032");
        assert_eq!(plan.profile_id, "AUTOCAD_MCP_GENERIC");
        assert_eq!(plan.fields_written, 2);
        assert_eq!(plan.target_inserts, 1);
        assert_eq!(plan.attributes_written, 2);
        assert_eq!(
            plan.writer_receipt.claim_boundary,
            RoundtripClaimBoundary::PreviewQualified
        );
        assert!(plan.writer_receipt.whole_document_preservation_verified);

        let response = serde_json::to_value(PreviewTitleBlockWriteReport {
            backend: "acadrust_preview".to_string(),
            source_format: "dwg".to_string(),
            drawing_version: "AC1032".to_string(),
            profile_id: plan.profile_id,
            profile_authority: plan.profile_authority,
            profile_pack_id: None,
            profile_pack_version: None,
            profile_pack_sha256: None,
            fields_written: plan.fields_written,
            target_inserts: plan.target_inserts,
            attributes_written: plan.attributes_written,
            writer_receipt: plan.writer_receipt,
            install_receipt: GuardedCandidateInstallReceipt {
                source_sha256: "a".repeat(64),
                installed_sha256: "b".repeat(64),
                exclusive_source_lock_verified: true,
                source_identity_revalidated: true,
                sibling_staging_verified: true,
                transactional_atomic_install_verified: true,
                original_file_identity_preserved: true,
                directory_durability_verified: true,
                installed_digest_verified: true,
            },
        })
        .unwrap();
        let response = response.as_object().unwrap();
        assert!(!response.contains_key("profile_pack_id"));
        assert!(!response.contains_key("profile_pack_version"));
        assert!(!response.contains_key("profile_pack_sha256"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn public_write_fails_before_candidate_build_off_windows() {
        let error = write(
            Path::new("missing.dwg"),
            &super::super::profiles::embedded_profile_registry(),
            &BTreeMap::from([("revision".to_string(), "P02".to_string())]),
        )
        .unwrap_err();
        assert_eq!(error.code(), "preview_writer_unsupported_platform");
        assert!(!error.installation_may_have_occurred());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_native_semantic_preview_title_block_guarded_install() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profiled-title-block.dwg");
        std::fs::write(&path, profiled_title_block_dwg()).unwrap();

        let report = write(
            &path,
            &super::super::profiles::embedded_profile_registry(),
            &BTreeMap::from([
                ("drawing_number".to_string(), "A-002".to_string()),
                ("revision".to_string(), "P02".to_string()),
            ]),
        )
        .unwrap();

        assert_ne!(
            report.install_receipt.source_sha256,
            report.install_receipt.installed_sha256
        );
        assert_eq!(
            report.writer_receipt.source_sha256,
            report.install_receipt.source_sha256
        );
        assert_eq!(
            report.writer_receipt.candidate_sha256,
            report.install_receipt.installed_sha256
        );
        assert!(report.install_receipt.exclusive_source_lock_verified);
        assert!(report.install_receipt.source_identity_revalidated);
        assert!(report.install_receipt.sibling_staging_verified);
        assert!(report.install_receipt.transactional_atomic_install_verified);
        assert!(report.install_receipt.original_file_identity_preserved);
        assert!(report.install_receipt.directory_durability_verified);
        assert!(report.install_receipt.installed_digest_verified);
        assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".autocad-mcp-preview-title-")
        }));

        let blocks = autocad_reader::Reader::open_path(&path)
            .unwrap()
            .read_title_blocks()
            .unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].attributes["DRAWING_NUMBER"], "A-002");
        assert_eq!(blocks[0].attributes["REVISION"], "P02");
        assert_eq!(blocks[0].attributes["REFERENCE"], "REF-1");
        assert_eq!(blocks[0].attributes["TITLE_LINE_1"], "TITLE");
        assert_eq!(blocks[0].attributes["TITLE_LINE_2"], "SUBTITLE");
        assert_eq!(blocks[0].attributes["SHEET_NUMBER"], "1");
        assert_eq!(blocks[0].attributes["SHEET_COUNT"], "1");
    }
}
