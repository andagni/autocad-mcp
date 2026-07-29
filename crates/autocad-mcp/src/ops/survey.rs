//! Title-block corpus surveying for the offline administrator profile workflow.
//!
//! This module is deliberately not registered in the drafter-facing MCP or
//! generic `call` surfaces.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::autocad_reader::{contract::TitleBlockInfo, DrawingFormat, DrawingSnapshot, Reader};

pub const TITLE_BLOCK_SURVEY_SCHEMA: u32 = 1;
const MAX_CLUSTER_EXAMPLES: usize = 5;

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyRecord {
    pub survey_schema: u32,
    pub file: String,
    pub file_sha256: String,
    pub corpus_tier: usize,
    pub format: String,
    pub title_block_candidates: Vec<SurveyTitleBlockCandidate>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyTitleBlockCandidate {
    pub block_name: String,
    pub layer: String,
    pub normalized_block_name: String,
    pub normalized_attribute_tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate_attribute_tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_values: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_value_arrays: Option<BTreeMap<String, Vec<String>>>,
}

pub fn survey_document(
    file: &str,
    file_sha256: &str,
    corpus_tier: usize,
    format: &str,
    title_blocks: &[TitleBlockInfo],
    include_values: bool,
) -> Result<SurveyRecord> {
    let title_block_candidates = title_blocks
        .iter()
        .map(|block| {
            let observed_values = include_values.then(|| {
                block
                    .attributes
                    .iter()
                    .map(|(tag, value)| (normalize_identity(tag), value.clone()))
                    .collect::<BTreeMap<_, _>>()
            });
            let observed_value_arrays = if include_values && !block.attribute_arrays.is_empty() {
                Some(
                    block
                        .attribute_arrays
                        .iter()
                        .map(|(tag, values)| (normalize_identity(tag), values.clone()))
                        .collect::<BTreeMap<_, _>>(),
                )
            } else {
                None
            };
            let duplicate_attribute_tags = block
                .duplicate_attribute_tags()
                .into_iter()
                .map(str::to_string)
                .collect();
            SurveyTitleBlockCandidate {
                normalized_block_name: normalize_identity(&block.block_name),
                normalized_attribute_tags: block
                    .attribute_tags()
                    .map(normalize_identity)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                block_name: block.block_name.clone(),
                layer: block.layer.clone(),
                duplicate_attribute_tags,
                observed_values,
                observed_value_arrays,
            }
        })
        .collect();

    Ok(SurveyRecord {
        survey_schema: TITLE_BLOCK_SURVEY_SCHEMA,
        file: file.to_string(),
        file_sha256: file_sha256.to_string(),
        corpus_tier,
        format: format.to_string(),
        title_block_candidates,
    })
}

pub fn survey_paths_jsonl(
    paths: &[String],
    corpus_tier: usize,
    include_values: bool,
) -> Result<String> {
    let records = survey_paths(paths, corpus_tier, include_values)?;
    records
        .into_iter()
        .map(|record| serde_json::to_string(&record).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()
        .map(|lines| lines.join("\n"))
}

pub fn survey_paths(
    paths: &[String],
    corpus_tier: usize,
    include_values: bool,
) -> Result<Vec<SurveyRecord>> {
    if paths.is_empty() {
        return Err(anyhow!("at least one survey path is required"));
    }

    let mut drawing_paths = Vec::new();
    for path in paths {
        collect_drawing_paths(Path::new(path), &mut drawing_paths)?;
    }
    drawing_paths.sort();
    drawing_paths.dedup();
    if drawing_paths.is_empty() {
        return Err(anyhow!("no DWG or DXF drawings found in survey paths"));
    }

    let mut records = Vec::new();
    for path in drawing_paths {
        let format = drawing_format(&path)
            .ok_or_else(|| anyhow!("unsupported drawing format: {}", path.display()))?;
        let (file_sha256, title_blocks) = capture_title_blocks(&path)?;
        if sha256_file(&path)? != file_sha256 {
            return Err(anyhow!(
                "drawing changed while it was being surveyed: {}",
                path.display()
            ));
        }
        records.push(survey_document(
            &path.to_string_lossy(),
            &file_sha256,
            corpus_tier,
            format,
            &title_blocks,
            include_values,
        )?);
    }
    Ok(records)
}

pub fn administrator_survey_paths_jsonl(
    root: &Path,
    paths: &[PathBuf],
    corpus_tier: usize,
    include_values: bool,
) -> Result<String> {
    let records = administrator_survey_paths(root, paths, corpus_tier, include_values)?;
    records
        .into_iter()
        .map(|record| serde_json::to_string(&record).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()
        .map(|lines| lines.join("\n"))
}

pub fn administrator_survey_paths(
    root: &Path,
    paths: &[PathBuf],
    corpus_tier: usize,
    include_values: bool,
) -> Result<Vec<SurveyRecord>> {
    if !(1..=3).contains(&corpus_tier) {
        return Err(anyhow!("corpus_tier must be 1, 2, or 3"));
    }
    if !root.is_absolute() {
        return Err(anyhow!("survey root must be absolute: {}", root.display()));
    }
    let root_metadata = std::fs::symlink_metadata(root)
        .map_err(|error| anyhow!("inspect survey root '{}': {error}", root.display()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(anyhow!(
            "survey root must be a regular non-symlink directory: {}",
            root.display()
        ));
    }
    let canonical_root = std::fs::canonicalize(root)
        .map_err(|error| anyhow!("canonicalize survey root '{}': {error}", root.display()))?;
    if paths.is_empty() {
        return Err(anyhow!("at least one survey input is required"));
    }

    let mut drawing_paths = Vec::new();
    for path in paths {
        if !path.is_absolute() {
            return Err(anyhow!("survey input must be absolute: {}", path.display()));
        }
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| anyhow!("inspect survey input '{}': {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow!(
                "survey input must not be a symlink: {}",
                path.display()
            ));
        }
        let canonical_path = std::fs::canonicalize(path)
            .map_err(|error| anyhow!("canonicalize survey input '{}': {error}", path.display()))?;
        if !canonical_path.starts_with(&canonical_root) {
            return Err(anyhow!(
                "survey input must remain below root '{}': {}",
                canonical_root.display(),
                canonical_path.display()
            ));
        }
        collect_drawing_paths(&canonical_path, &mut drawing_paths)?;
    }
    drawing_paths.sort();
    drawing_paths.dedup();
    if drawing_paths.is_empty() {
        return Err(anyhow!("no DWG or DXF drawings found in survey inputs"));
    }

    let mut records = Vec::with_capacity(drawing_paths.len());
    for path in drawing_paths {
        let relative = path.strip_prefix(&canonical_root).map_err(|_| {
            anyhow!(
                "survey drawing escaped root '{}': {}",
                canonical_root.display(),
                path.display()
            )
        })?;
        let file_id = safe_relative_file_id(relative)?;
        let format = drawing_format(&path)
            .ok_or_else(|| anyhow!("unsupported drawing format: {}", path.display()))?;
        let (file_sha256, title_blocks) = capture_title_blocks(&path)?;
        if sha256_file(&path)? != file_sha256 {
            return Err(anyhow!(
                "drawing changed while it was being surveyed: {}",
                path.display()
            ));
        }
        records.push(survey_document(
            &file_id,
            &file_sha256,
            corpus_tier,
            format,
            &title_blocks,
            include_values,
        )?);
    }
    Ok(records)
}

fn safe_relative_file_id(path: &Path) -> Result<String> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(anyhow!(
            "survey drawing identifier must be a non-empty relative path"
        ));
    }
    let mut components = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(anyhow!(
                "survey drawing identifier contains an unsafe path component: {}",
                path.display()
            ));
        };
        let component = component.to_str().ok_or_else(|| {
            anyhow!(
                "survey drawing identifier is not valid Unicode: {}",
                path.display()
            )
        })?;
        components.push(component);
    }
    Ok(components.join("/"))
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyClusterArtifact {
    pub cluster_schema: u32,
    pub survey_sha256: String,
    pub drawing_count: usize,
    pub clusters: Vec<SurveyCluster>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyCluster {
    pub candidate_id: String,
    pub normalized_block_name: String,
    pub normalized_attribute_tags: Vec<String>,
    pub drawing_count: usize,
    pub insert_count: usize,
    pub corpus_tiers: Vec<usize>,
    pub layers: Vec<String>,
    pub duplicate_attribute_tags: Vec<String>,
    pub example_files: Vec<String>,
}

#[derive(Debug)]
struct ClusterAccumulator {
    drawings: BTreeSet<String>,
    insert_count: usize,
    corpus_tiers: BTreeSet<usize>,
    layers: BTreeSet<String>,
    duplicate_attribute_tags: BTreeSet<String>,
}

pub fn cluster_survey_jsonl(jsonl: &str) -> Result<SurveyClusterArtifact> {
    let mut records = Vec::new();
    let mut seen_files = BTreeSet::new();
    for (index, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            return Err(anyhow!(
                "survey JSON Lines contains a blank record at line {}",
                index + 1
            ));
        }
        let record: SurveyRecord = serde_json::from_str(line)
            .map_err(|error| anyhow!("parse survey record at line {}: {error}", index + 1))?;
        validate_survey_record(&record, index + 1)?;
        if !seen_files.insert(record.file.clone()) {
            return Err(anyhow!(
                "survey JSON Lines contains duplicate file identifier '{}'",
                record.file
            ));
        }
        records.push(record);
    }
    if records.is_empty() {
        return Err(anyhow!("survey JSON Lines contains no records"));
    }

    let mut accumulators = BTreeMap::<(String, Vec<String>), ClusterAccumulator>::new();
    for record in &records {
        for candidate in &record.title_block_candidates {
            let key = (
                candidate.normalized_block_name.clone(),
                candidate.normalized_attribute_tags.clone(),
            );
            let accumulator = accumulators
                .entry(key)
                .or_insert_with(|| ClusterAccumulator {
                    drawings: BTreeSet::new(),
                    insert_count: 0,
                    corpus_tiers: BTreeSet::new(),
                    layers: BTreeSet::new(),
                    duplicate_attribute_tags: BTreeSet::new(),
                });
            accumulator.drawings.insert(record.file.clone());
            accumulator.insert_count += 1;
            accumulator.corpus_tiers.insert(record.corpus_tier);
            accumulator.layers.insert(candidate.layer.clone());
            accumulator
                .duplicate_attribute_tags
                .extend(candidate.duplicate_attribute_tags.iter().cloned());
        }
    }

    let clusters = accumulators
        .into_iter()
        .map(
            |((normalized_block_name, normalized_attribute_tags), accumulator)| {
                let example_files = accumulator
                    .drawings
                    .iter()
                    .take(MAX_CLUSTER_EXAMPLES)
                    .cloned()
                    .collect();
                SurveyCluster {
                    candidate_id: candidate_id(&normalized_block_name, &normalized_attribute_tags),
                    normalized_block_name,
                    normalized_attribute_tags,
                    drawing_count: accumulator.drawings.len(),
                    insert_count: accumulator.insert_count,
                    corpus_tiers: accumulator.corpus_tiers.into_iter().collect(),
                    layers: accumulator.layers.into_iter().collect(),
                    duplicate_attribute_tags: accumulator
                        .duplicate_attribute_tags
                        .into_iter()
                        .collect(),
                    example_files,
                }
            },
        )
        .collect();

    Ok(SurveyClusterArtifact {
        cluster_schema: 1,
        survey_sha256: sha256_bytes(jsonl.as_bytes()),
        drawing_count: records.len(),
        clusters,
    })
}

fn validate_survey_record(record: &SurveyRecord, line: usize) -> Result<()> {
    if record.survey_schema != TITLE_BLOCK_SURVEY_SCHEMA {
        return Err(anyhow!(
            "survey record at line {line} uses unsupported survey_schema {}; expected {}",
            record.survey_schema,
            TITLE_BLOCK_SURVEY_SCHEMA
        ));
    }
    if record.file.is_empty()
        || record.file.starts_with('/')
        || record.file.contains('\\')
        || record
            .file
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(anyhow!(
            "survey record at line {line} has an unsafe relative file identifier"
        ));
    }
    if !is_lowercase_sha256(&record.file_sha256) {
        return Err(anyhow!(
            "survey record at line {line} has an invalid file_sha256"
        ));
    }
    if !(1..=3).contains(&record.corpus_tier) {
        return Err(anyhow!(
            "survey record at line {line} has corpus_tier outside 1 through 3"
        ));
    }
    if !matches!(record.format.as_str(), "DWG" | "DXF") {
        return Err(anyhow!(
            "survey record at line {line} has unsupported format '{}'",
            record.format
        ));
    }
    for candidate in &record.title_block_candidates {
        if candidate.normalized_block_name != normalize_identity(&candidate.block_name) {
            return Err(anyhow!(
                "survey record at line {line} has a stale normalized block name"
            ));
        }
        let expected_tags = candidate
            .normalized_attribute_tags
            .iter()
            .map(|tag| normalize_identity(tag))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if expected_tags != candidate.normalized_attribute_tags {
            return Err(anyhow!(
                "survey record at line {line} has unsorted or duplicate normalized attribute tags"
            ));
        }
        let expected_duplicates = candidate
            .duplicate_attribute_tags
            .iter()
            .map(|tag| normalize_identity(tag))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if expected_duplicates != candidate.duplicate_attribute_tags
            || !expected_duplicates
                .iter()
                .all(|tag| expected_tags.contains(tag))
        {
            return Err(anyhow!(
                "survey record at line {line} has invalid duplicate attribute tags"
            ));
        }
    }
    Ok(())
}

fn candidate_id(block_name: &str, tags: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"autocad-mcp-title-block-candidate-v1\0");
    hasher.update(block_name.as_bytes());
    for tag in tags {
        hasher.update(b"\0");
        hasher.update(tag.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn collect_drawing_paths(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| anyhow!("inspect survey path '{}': {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "survey path must not be a symlink: {}",
            path.display()
        ));
    }
    if metadata.is_file() {
        if drawing_format(path).is_some() {
            out.push(path.to_path_buf());
        }
        return Ok(());
    }
    if metadata.is_dir() {
        let mut entries = std::fs::read_dir(path)?.collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            collect_drawing_paths(&entry.path(), out)?;
        }
        return Ok(());
    }

    Err(anyhow!(
        "survey path is neither file nor directory: {}",
        path.display()
    ))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).map_err(|error| anyhow!("open drawing '{}': {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| anyhow!("read drawing '{}': {error}", path.display()))?;
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

fn capture_title_blocks(path: &Path) -> Result<(String, Vec<TitleBlockInfo>)> {
    let bytes = std::fs::read(path)
        .map_err(|error| anyhow!("failed to open drawing '{}': {error}", path.display()))?;
    let file_sha256 = sha256_bytes(&bytes);
    let format = DrawingFormat::from_path(path)
        .map_err(|error| anyhow!("failed to open drawing '{}': {error}", path.display()))?;
    let session = Reader::open_snapshot(DrawingSnapshot::new(format, bytes))
        .map_err(|error| anyhow!("failed to open drawing '{}': {error}", path.display()))?;
    let title_blocks = session
        .read_title_blocks()
        .map_err(|error| anyhow!("failed to open drawing '{}': {error}", path.display()))?;
    Ok((file_sha256, title_blocks))
}

fn drawing_format(path: &Path) -> Option<&'static str> {
    match path
        .extension()
        .and_then(|ext| ext.to_str())?
        .to_lowercase()
        .as_str()
    {
        "dwg" => Some("DWG"),
        "dxf" => Some("DXF"),
        _ => None,
    }
}

fn normalize_identity(value: &str) -> String {
    value.trim().to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::entities::{AttributeEntity, EntityType, Insert};
    use acadrust::types::Vector3;
    use acadrust::{CadDocument, DxfWriter};

    fn title_blocks() -> Vec<TitleBlockInfo> {
        vec![TitleBlockInfo {
            block_name: "autocad_mcp_generic".to_string(),
            layer: "0".to_string(),
            attributes: [
                ("revision".to_string(), "P01".to_string()),
                ("DRAWING_NUMBER".to_string(), "ABC-001".to_string()),
            ]
            .into_iter()
            .collect(),
            attribute_arrays: Default::default(),
        }]
    }

    fn backend_doc_with_title_block() -> CadDocument {
        let mut doc = CadDocument::new();
        let mut insert = Insert::new("autocad_mcp_generic", Vector3::new(0.0, 0.0, 0.0));
        insert
            .attributes
            .push(AttributeEntity::simple("revision", "P01"));
        insert
            .attributes
            .push(AttributeEntity::simple("DRAWING_NUMBER", "ABC-001"));
        doc.add_entity(EntityType::Insert(insert)).unwrap();
        doc
    }

    #[test]
    fn survey_record_normalizes_block_name_and_sorted_tags() {
        let record = survey_document(
            "fixtures/title-block.dxf",
            &"0".repeat(64),
            1,
            "DXF",
            &title_blocks(),
            false,
        )
        .unwrap();
        assert_eq!(record.file, "fixtures/title-block.dxf");
        assert_eq!(record.corpus_tier, 1);
        assert_eq!(record.format, "DXF");
        assert_eq!(record.title_block_candidates.len(), 1);
        let candidate = &record.title_block_candidates[0];
        assert_eq!(candidate.normalized_block_name, "AUTOCAD_MCP_GENERIC");
        assert_eq!(
            candidate.normalized_attribute_tags,
            vec!["DRAWING_NUMBER".to_string(), "REVISION".to_string()]
        );
        assert!(candidate.observed_values.is_none());
        assert!(candidate.observed_value_arrays.is_none());
        assert!(candidate.duplicate_attribute_tags.is_empty());
    }

    #[test]
    fn survey_record_can_include_observed_values() {
        let record = survey_document(
            "fixtures/title-block.dxf",
            &"0".repeat(64),
            1,
            "DXF",
            &title_blocks(),
            true,
        )
        .unwrap();
        let values = record.title_block_candidates[0]
            .observed_values
            .as_ref()
            .unwrap();
        assert_eq!(values.get("REVISION").map(String::as_str), Some("P01"));
        assert_eq!(
            values.get("DRAWING_NUMBER").map(String::as_str),
            Some("ABC-001")
        );
    }

    #[test]
    fn survey_returns_duplicate_normalized_attribute_tags_as_arrays() {
        let title_blocks = vec![TitleBlockInfo {
            block_name: "autocad_mcp_generic".to_string(),
            layer: "0".to_string(),
            attributes: Default::default(),
            attribute_arrays: [(
                "REVISION".to_string(),
                vec!["P01".to_string(), "P02".to_string()],
            )]
            .into_iter()
            .collect(),
        }];

        let record = survey_document(
            "fixtures/duplicate-title-block.dxf",
            &"0".repeat(64),
            1,
            "DXF",
            &title_blocks,
            true,
        )
        .unwrap();
        let candidate = &record.title_block_candidates[0];
        assert_eq!(candidate.duplicate_attribute_tags, ["REVISION".to_string()]);
        assert_eq!(
            candidate
                .observed_value_arrays
                .as_ref()
                .unwrap()
                .get("REVISION"),
            Some(&vec!["P01".to_string(), "P02".to_string()])
        );
        assert!(candidate.observed_values.as_ref().unwrap().is_empty());
    }

    #[test]
    fn administrator_survey_uses_relative_identifiers_and_exact_digest() {
        let root = tempfile::tempdir().unwrap();
        let drawings = root.path().join("drawings");
        std::fs::create_dir(&drawings).unwrap();
        let drawing = drawings.join("title-block.dxf");
        DxfWriter::new(&backend_doc_with_title_block())
            .write_to_file(&drawing)
            .unwrap();

        let records = administrator_survey_paths(root.path(), &[drawings], 2, false).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].file, "drawings/title-block.dxf");
        assert_eq!(records[0].corpus_tier, 2);
        assert!(is_lowercase_sha256(&records[0].file_sha256));
        assert_eq!(records[0].file_sha256, sha256_file(&drawing).unwrap());
        assert!(records[0].title_block_candidates[0]
            .observed_values
            .is_none());
    }

    #[test]
    fn cluster_is_deterministic_and_does_not_propagate_values() {
        let first =
            survey_document("a.dxf", &"1".repeat(64), 1, "DXF", &title_blocks(), true).unwrap();
        let second =
            survey_document("b.dxf", &"2".repeat(64), 2, "DXF", &title_blocks(), false).unwrap();
        let jsonl = [first, second]
            .iter()
            .map(|record| serde_json::to_string(record).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        let artifact = cluster_survey_jsonl(&jsonl).unwrap();
        assert_eq!(artifact.drawing_count, 2);
        assert_eq!(artifact.clusters.len(), 1);
        let cluster = &artifact.clusters[0];
        assert_eq!(cluster.drawing_count, 2);
        assert_eq!(cluster.insert_count, 2);
        assert_eq!(cluster.corpus_tiers, [1, 2]);
        assert_eq!(cluster.example_files, ["a.dxf", "b.dxf"]);
        let serialized = serde_json::to_string(&artifact).unwrap();
        assert!(!serialized.contains("P01"));
        assert!(!serialized.contains("ABC-001"));
    }

    #[test]
    fn cluster_rejects_stale_normalized_fingerprint() {
        let mut record =
            survey_document("a.dxf", &"1".repeat(64), 1, "DXF", &title_blocks(), false).unwrap();
        record.title_block_candidates[0].normalized_block_name = "WRONG".to_string();
        let error = cluster_survey_jsonl(&serde_json::to_string(&record).unwrap()).unwrap_err();
        assert!(
            error.to_string().contains("stale normalized block name"),
            "got: {error:#}"
        );
    }
}
