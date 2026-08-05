use std::collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap};

use acadrust::entities::{attribute_definition::MTextFlag, EntityType, Insert};
use acadrust::objects::ObjectType;
use acadrust::types::Handle;
use acadrust::CadDocument;
use autocad_reader::contract::TitleBlockInfo;
use autocad_reader::DrawingReadSession;

use super::contract::{TitleBlockFingerprint, TitleBlockWrite, TitleBlockWriteResult};
use super::WriteError;

#[derive(Debug, Clone, PartialEq)]
struct InsertState {
    handle: Handle,
    insert: Insert,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct TitleBlockPostcondition {
    normalized_block_name: String,
    normalized_attribute_tags: Vec<String>,
    targets: Vec<InsertState>,
    reader_targets: Vec<TitleBlockInfo>,
}

fn normalize(value: &str) -> String {
    value.trim().to_uppercase()
}

fn normalized_fingerprint(
    fingerprint: &TitleBlockFingerprint,
) -> Result<(String, Vec<String>), WriteError> {
    if fingerprint.block_name.is_empty() || fingerprint.block_name.trim() != fingerprint.block_name
    {
        return Err(WriteError::invalid_request(
            "invalid_title_block_fingerprint",
            "title-block block name must not be empty or padded",
        ));
    }
    if fingerprint.attribute_tags.is_empty() {
        return Err(WriteError::invalid_request(
            "invalid_title_block_fingerprint",
            "title-block fingerprint has no attribute tags",
        ));
    }
    let mut tags = fingerprint
        .attribute_tags
        .iter()
        .map(|tag| normalize(tag))
        .collect::<Vec<_>>();
    if tags.iter().any(String::is_empty) {
        return Err(WriteError::invalid_request(
            "invalid_title_block_fingerprint",
            "title-block fingerprint contains an empty attribute tag",
        ));
    }
    tags.sort();
    if tags.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(WriteError::invalid_request(
            "invalid_title_block_fingerprint",
            "title-block fingerprint contains duplicate normalized tags",
        ));
    }
    Ok((normalize(&fingerprint.block_name), tags))
}

fn insert_tags(insert: &acadrust::entities::Insert) -> Vec<String> {
    let mut tags = insert
        .attributes
        .iter()
        .map(|attribute| normalize(&attribute.tag))
        .collect::<Vec<_>>();
    tags.sort();
    tags.dedup();
    tags
}

fn matches_fingerprint(
    insert: &acadrust::entities::Insert,
    block_name: &str,
    tags: &[String],
) -> bool {
    normalize(&insert.block_name) == block_name && insert_tags(insert) == tags
}

fn normalized_replacements(
    request: &TitleBlockWrite,
    fingerprint_tags: &[String],
) -> Result<BTreeMap<String, String>, WriteError> {
    if request.tag_values.is_empty() {
        return Err(WriteError::invalid_request(
            "empty_title_block_write",
            "title-block field map is empty",
        ));
    }
    let fingerprint_tags = fingerprint_tags.iter().cloned().collect::<BTreeSet<_>>();
    let mut replacements = BTreeMap::new();
    for (tag, value) in &request.tag_values {
        let normalized = normalize(tag);
        if normalized.is_empty() {
            return Err(WriteError::invalid_request(
                "invalid_title_block_tag",
                "requested title-block tag is empty",
            ));
        }
        if !fingerprint_tags.contains(&normalized) {
            return Err(WriteError::invalid_request(
                "unknown_title_block_tag",
                format!("requested tag `{tag}` is not part of the resolved fingerprint"),
            ));
        }
        if replacements.insert(normalized, value.clone()).is_some() {
            return Err(WriteError::invalid_request(
                "duplicate_title_block_tag",
                "requested tags collide after normalization",
            ));
        }
    }
    Ok(replacements)
}

fn field_backed(value: &str) -> bool {
    value.contains("%<") && value.contains(">%")
}

/// The only extension-dictionary content on an ATTRIB that a plain value
/// rewrite is known not to invalidate: a dictionary whose sole entry is the
/// well-known, AutoCAD-reserved `AcDbContextDataManager` key.
///
/// Researched, not assumed: `AcDbContextDataManager` roots the annotation-
/// scale context-data system (`ACDB_ANNOTATIONSCALES` -> one
/// `ACDB_*CONTEXTDATA_CLASS` object per scale override). Every documented
/// context-data class -- block-reference, text/mtext, and attribute -- only
/// stores *geometric* per-scale overrides: insertion point, rotation,
/// alignment, direction, width/height, scale factors. None stores the
/// object's own text content; that would defeat the point of "annotative"
/// (same content, different visual representation per scale). Confirmed at
/// the code level too: `AttributeEntity::set_value` (what `write()` below
/// calls) is `self.value = value.into()` and touches nothing else on the
/// struct -- not `insertion_point`, not `rotation`, not `height`. The two
/// are provably orthogonal.
///
/// Any dictionary that fails to resolve, or carries any entry beyond this
/// one recognized key, is refused exactly as before -- this narrows what
/// gets refused, it does not relax the fail-closed default for anything we
/// haven't specifically verified.
fn xdictionary_is_known_safe_for_value_rewrite(
    document: &CadDocument,
    xdictionary_handle: Option<Handle>,
) -> bool {
    let Some(handle) = xdictionary_handle else {
        return true;
    };
    match document.objects.get(&handle) {
        Some(ObjectType::Dictionary(dict)) => {
            !dict.entries.is_empty()
                && dict
                    .entries
                    .iter()
                    .all(|(key, _)| key == "AcDbContextDataManager")
        }
        _ => false,
    }
}

fn target_state(insert: &acadrust::entities::Insert) -> InsertState {
    InsertState {
        handle: insert.common.handle,
        insert: insert.clone(),
    }
}

fn reader_projection(insert: &Insert) -> TitleBlockInfo {
    let mut attributes = HashMap::with_capacity(insert.attributes.len());
    let mut attribute_arrays: HashMap<String, Vec<String>> = HashMap::new();
    for attribute in &insert.attributes {
        let normalized_tag = normalize(&attribute.tag);
        match attribute_arrays.entry(normalized_tag.clone()) {
            Entry::Occupied(mut entry) => entry.get_mut().push(attribute.value.clone()),
            Entry::Vacant(array_entry) => match attributes.entry(normalized_tag) {
                Entry::Vacant(entry) => {
                    entry.insert(attribute.value.clone());
                }
                Entry::Occupied(entry) => {
                    let first_value = entry.remove();
                    array_entry.insert(vec![first_value, attribute.value.clone()]);
                }
            },
        }
    }
    TitleBlockInfo {
        block_name: insert.block_name.clone(),
        layer: insert.common.layer.clone(),
        attributes,
        attribute_arrays,
    }
}

pub(super) fn write(
    document: &mut CadDocument,
    request: &TitleBlockWrite,
) -> Result<(TitleBlockWriteResult, TitleBlockPostcondition), WriteError> {
    let (block_name, fingerprint_tags) = normalized_fingerprint(&request.fingerprint)?;
    let replacements = normalized_replacements(request, &fingerprint_tags)?;

    let targets = document
        .entities()
        .filter_map(|entity| match entity {
            EntityType::Insert(insert)
                if matches_fingerprint(insert, &block_name, &fingerprint_tags) =>
            {
                Some(insert)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return Err(WriteError::target_not_found(
            "title_block_not_found",
            "no insert matches the resolved title-block fingerprint",
        ));
    }

    for insert in &targets {
        for tag in replacements.keys() {
            let matches = insert
                .attributes
                .iter()
                .filter(|attribute| normalize(&attribute.tag) == *tag)
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(WriteError::ambiguous_target(
                    "ambiguous_title_block_tag",
                    format!(
                        "requested tag `{tag}` must occur exactly once on every matching insert"
                    ),
                ));
            }
            let attribute = matches[0];
            if attribute.is_multiline
                || attribute.mtext_flag != MTextFlag::SingleLine
                || attribute.line_count != 1
                || !xdictionary_is_known_safe_for_value_rewrite(
                    document,
                    attribute.common.xdictionary_handle,
                )
                || field_backed(&attribute.value)
            {
                return Err(WriteError::unsupported_source(
                    "unsupported_title_block_attribute",
                    format!(
                        "requested tag `{tag}` has multiline, field, or extension metadata that cannot be safely rewritten"
                    ),
                ));
            }
        }
    }
    let target_count = targets.len();
    drop(targets);

    let mut attributes_written = 0usize;
    for entity in document.entities_mut() {
        let EntityType::Insert(insert) = entity else {
            continue;
        };
        if !matches_fingerprint(insert, &block_name, &fingerprint_tags) {
            continue;
        }
        for attribute in &mut insert.attributes {
            if let Some(value) = replacements.get(&normalize(&attribute.tag)) {
                attribute.set_value(value);
                attributes_written += 1;
            }
        }
    }
    let expected_attributes = target_count * replacements.len();
    if attributes_written != expected_attributes {
        return Err(WriteError::verification(
            "title_block_mutation_count_mismatch",
            "in-memory title-block write count differs from the validated plan",
        ));
    }

    let target_inserts = document
        .entities()
        .filter_map(|entity| match entity {
            EntityType::Insert(insert)
                if matches_fingerprint(insert, &block_name, &fingerprint_tags) =>
            {
                Some(insert)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let targets = target_inserts
        .iter()
        .map(|insert| target_state(insert))
        .collect();
    let reader_targets = target_inserts
        .iter()
        .map(|insert| reader_projection(insert))
        .collect();
    Ok((
        TitleBlockWriteResult {
            target_inserts: target_count,
            fields_written: replacements.len(),
            attributes_written,
        },
        TitleBlockPostcondition {
            normalized_block_name: block_name,
            normalized_attribute_tags: fingerprint_tags,
            targets,
            reader_targets,
        },
    ))
}

pub(super) fn verify_reader(
    reader: &DrawingReadSession,
    expected: &TitleBlockPostcondition,
) -> Result<(), WriteError> {
    let candidate_blocks = reader.read_title_blocks().map_err(|_| {
        WriteError::verification(
            "candidate_title_block_projection_failed",
            "independent title-block projection rejected the encoded candidate",
        )
    })?;
    let mut actual_targets = candidate_blocks
        .into_iter()
        .filter(|block| {
            let mut tags = block.attribute_tags().map(normalize).collect::<Vec<_>>();
            tags.sort();
            tags.dedup();
            normalize(&block.block_name) == expected.normalized_block_name
                && tags == expected.normalized_attribute_tags
        })
        .collect::<Vec<_>>();
    for target in &expected.reader_targets {
        let Some(index) = actual_targets
            .iter()
            .position(|candidate| candidate == target)
        else {
            return Err(WriteError::verification(
                "title_block_postcondition_failed",
                "independent reader projection did not contain an expected title-block target",
            ));
        };
        actual_targets.remove(index);
    }
    if !actual_targets.is_empty() {
        return Err(WriteError::verification(
            "title_block_postcondition_failed",
            "independent reader projection contained an unexpected title-block target",
        ));
    }
    Ok(())
}

pub(super) fn verify(
    document: &CadDocument,
    expected: &TitleBlockPostcondition,
) -> Result<(), WriteError> {
    let actual = expected
        .targets
        .iter()
        .map(|target| {
            document
                .get_entity(target.handle)
                .and_then(|entity| match entity {
                    EntityType::Insert(insert) => Some(target_state(insert)),
                    _ => None,
                })
                .ok_or_else(|| {
                    WriteError::verification(
                        "title_block_postcondition_failed",
                        "a matching title-block insert is missing after candidate reopen",
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if actual != expected.targets {
        return Err(WriteError::verification(
            "title_block_postcondition_failed",
            "title-block attributes differ after candidate reopen",
        ));
    }
    Ok(())
}
