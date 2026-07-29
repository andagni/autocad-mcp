//! Block read projections behind the transitional reader boundary.

use acadrust::entities::{EntityType, Insert};
use acadrust::objects::ObjectType;
use acadrust::tables::BlockRecord;
use acadrust::types::{Handle, Vector3};
use acadrust::CadDocument;
use serde::Serialize;

use super::{
    dynamic_blocks::resolve_dynamic_block_link,
    entity_identity::{validate_semantic_entity_handles, ACADRUST_INSERT_SCALE_SENTINEL},
    owners::{
        is_model_space_block, is_paper_space_block, is_xref_definition, resolve_direct_owner,
        DirectOwnerType, DirectOwnerUnavailableReason,
    },
};

use super::contract::DirectOwnerContext;
#[cfg(test)]
use super::contract::DynamicBlockLink;
pub use super::contract::{
    BlockAttributeRecord, BlockDefinitionRecord, BlockDefinitionSelector, BlockInfo,
    BlockInsertRecord, BlockInsertSelector, BlockPoint3,
};

/// The original user-block inventory.
///
/// This intentionally preserves its established filtering and output order.
pub fn list_blocks(doc: &CadDocument) -> Vec<BlockInfo> {
    doc.block_records
        .iter()
        .filter(|br| !br.name.starts_with('*'))
        .filter(|br| !is_xref_definition(br))
        .map(|br| BlockInfo {
            name: br.name.clone(),
            has_attributes: br.flags.has_attributes,
            description: br.description.clone(),
        })
        .collect()
}

impl From<Vector3> for BlockPoint3 {
    fn from(value: Vector3) -> Self {
        Self {
            x: value.x,
            y: value.y,
            z: value.z,
        }
    }
}

fn finite_number(value: f64, field: &str) -> Result<f64, BlockReadError> {
    value.is_finite().then_some(value).ok_or_else(|| {
        BlockReadError::new(
            "unsupported_block_data",
            format!("{field} is not a finite number"),
        )
    })
}

fn recoverable_insert_scale(value: f64, field: &str) -> Result<f64, BlockReadError> {
    let value = finite_number(value, field)?;
    if value == ACADRUST_INSERT_SCALE_SENTINEL {
        return Err(BlockReadError::new(
            "unsupported_block_data",
            format!("reader cannot recover the saved {field}"),
        ));
    }
    Ok(value)
}

fn finite_point(value: Vector3, field: &str) -> Result<BlockPoint3, BlockReadError> {
    Ok(BlockPoint3 {
        x: finite_number(value.x, &format!("{field}.x"))?,
        y: finite_number(value.y, &format!("{field}.y"))?,
        z: finite_number(value.z, &format!("{field}.z"))?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockReadError {
    code: String,
    message: String,
}

impl BlockReadError {
    pub(super) fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for BlockReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "code={} {}", self.code, self.message)
    }
}

impl std::error::Error for BlockReadError {}

fn canonical_handle(handle: Handle, resource: &str) -> Result<String, BlockReadError> {
    if handle.is_null() {
        return Err(BlockReadError::new(
            "invalid_handle",
            format!("{resource} has null handle 0"),
        ));
    }
    Ok(format!("{:X}", handle.value()))
}

fn canonical_optional_handle(handle: Handle) -> Option<String> {
    handle.is_valid().then(|| format!("{:X}", handle.value()))
}

fn parse_handle(input: &str) -> Result<Handle, BlockReadError> {
    if input.trim() != input {
        return Err(BlockReadError::new(
            "invalid_handle",
            format!("invalid block handle `{input}`"),
        ));
    }
    let digits = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BlockReadError::new(
            "invalid_handle",
            format!("invalid block handle `{input}`"),
        ));
    }
    let value = u64::from_str_radix(digits, 16).map_err(|_| {
        BlockReadError::new("invalid_handle", format!("invalid block handle `{input}`"))
    })?;
    if value == 0 {
        return Err(BlockReadError::new(
            "invalid_handle",
            "block handle 0 is invalid",
        ));
    }
    Ok(Handle::new(value))
}

fn name_key(name: &str) -> String {
    name.to_uppercase()
}

fn name_eq(left: &str, right: &str) -> bool {
    name_key(left) == name_key(right)
}

pub(crate) fn is_xref_dependent_definition(block: &BlockRecord) -> bool {
    block.flags.is_external || block.name.contains('|')
}

fn resolved_layout_handle(
    doc: &CadDocument,
    definition: &BlockRecord,
) -> Result<Option<Handle>, BlockReadError> {
    let mut handles = doc
        .objects
        .values()
        .filter_map(|object| match object {
            ObjectType::Layout(layout) if layout.block_record == definition.handle => {
                Some(layout.handle)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    handles.sort_by_key(Handle::value);
    handles.dedup();
    match handles.as_slice() {
        [] => Ok(None),
        [handle] => Ok(Some(*handle)),
        _ => Err(BlockReadError::new(
            "unsupported_block_data",
            format!(
                "block definition {:X} backs multiple layout objects",
                definition.handle.value()
            ),
        )),
    }
}

/// True for host-owned block definitions rather than layouts or XREF data.
///
/// Anonymous/dynamic definitions remain visible: they are real definitions
/// with stable handles even though the legacy `list_blocks` alias omits them.
/// Layout classification is joined through actual LAYOUT objects because the
/// pinned DWG reader can retain an unrelated non-null `BlockRecord.layout`
/// value on anonymous definitions.
fn is_ordinary_definition(doc: &CadDocument, block: &BlockRecord) -> Result<bool, BlockReadError> {
    Ok(!is_xref_definition(block)
        && !is_xref_dependent_definition(block)
        && resolved_layout_handle(doc, block)?.is_none()
        && !is_model_space_block(block)
        && !is_paper_space_block(block))
}

fn sorted_canonical_handles(
    handles: impl IntoIterator<Item = Handle>,
    resource: &str,
) -> Result<Vec<String>, BlockReadError> {
    let mut handles = handles.into_iter().collect::<Vec<_>>();
    handles.sort_by_key(Handle::value);
    if handles.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(BlockReadError::new(
            "unsupported_block_data",
            format!("{resource} handles are not unique"),
        ));
    }
    handles
        .into_iter()
        .map(|handle| canonical_handle(handle, resource))
        .collect()
}

fn matching_block_records<'a>(doc: &'a CadDocument, name: &str) -> Vec<&'a BlockRecord> {
    doc.block_records
        .iter()
        .filter(|block| name_eq(&block.name, name))
        .collect()
}

fn resolve_insert_definition<'a>(
    doc: &'a CadDocument,
    insert: &Insert,
) -> Result<&'a BlockRecord, BlockReadError> {
    let matching = matching_block_records(doc, &insert.block_name);
    match matching.as_slice() {
        [definition] => Ok(*definition),
        [] => Err(BlockReadError::new(
            "unsupported_block_data",
            format!(
                "INSERT references missing block definition `{}`",
                insert.block_name
            ),
        )),
        _ => Err(BlockReadError::new(
            "unsupported_block_data",
            format!(
                "INSERT block definition `{}` is ambiguous",
                insert.block_name
            ),
        )),
    }
}

fn definition_record(
    doc: &CadDocument,
    definition: &BlockRecord,
) -> Result<BlockDefinitionRecord, BlockReadError> {
    let layout_handle = resolved_layout_handle(doc, definition)?;
    let owner_context = resolve_direct_owner(doc, definition.handle)
        .map_err(|error| BlockReadError::new("unsupported_block_data", error.to_string()))?;
    let (is_model_space, is_paper_space) = match owner_context {
        Some(DirectOwnerContext::Available {
            owner_type: DirectOwnerType::ModelSpace,
            ..
        }) => (true, false),
        Some(DirectOwnerContext::Available {
            owner_type: DirectOwnerType::PaperSpace,
            ..
        })
        | Some(DirectOwnerContext::Unavailable {
            reason: DirectOwnerUnavailableReason::MissingPaperSpaceLayout,
        }) => (false, true),
        Some(DirectOwnerContext::Available {
            owner_type: DirectOwnerType::BlockDefinition,
            ..
        }) => (false, false),
        Some(DirectOwnerContext::Available {
            owner_type: DirectOwnerType::Entity,
            ..
        })
        | Some(DirectOwnerContext::Unavailable {
            reason: DirectOwnerUnavailableReason::UnresolvedOwner,
        })
        | None => {
            return Err(BlockReadError::new(
                "unsupported_block_data",
                format!(
                    "block definition {:X} has no coherent semantic classification",
                    definition.handle.value()
                ),
            ))
        }
    };
    let mut insert_handles = Vec::new();
    for entity in doc.entities() {
        let EntityType::Insert(insert) = entity else {
            continue;
        };
        if name_eq(&insert.block_name, &definition.name) {
            let resolved = resolve_insert_definition(doc, insert)?;
            if resolved.handle == definition.handle {
                insert_handles.push(insert.common.handle);
            }
        }
    }

    Ok(BlockDefinitionRecord {
        handle: canonical_handle(definition.handle, "block definition")?,
        name: definition.name.clone(),
        description: definition.description.clone(),
        has_attributes: definition.flags.has_attributes,
        is_anonymous: definition.flags.anonymous,
        is_xref: is_xref_definition(definition),
        is_xref_overlay: definition.flags.is_xref_overlay,
        xref_dependent: is_xref_dependent_definition(definition),
        is_layout: is_model_space || is_paper_space,
        is_model_space,
        is_paper_space,
        layout_handle: layout_handle
            .map(|handle| canonical_handle(handle, "layout object"))
            .transpose()?,
        xref_path: (!definition.xref_path.is_empty()).then(|| definition.xref_path.clone()),
        units: definition.units,
        explodable: definition.explodable,
        scale_uniformly: definition.scale_uniformly,
        entity_handles: sorted_canonical_handles(
            definition.entity_handles.iter().copied(),
            "block definition content entity",
        )?,
        owned_entity_count: definition.entity_handles.len(),
        insert_handles: sorted_canonical_handles(
            insert_handles.iter().copied(),
            "block insert referencing definition",
        )?,
        insert_count: insert_handles.len(),
        block_entity_handle: canonical_optional_handle(definition.block_entity_handle),
        block_end_handle: canonical_optional_handle(definition.block_end_handle),
    })
}

/// List all modeled block definitions, including layout, anonymous/dynamic,
/// direct-XREF, and XREF-dependent block records.
pub fn list_block_definitions(
    doc: &CadDocument,
) -> Result<Vec<BlockDefinitionRecord>, BlockReadError> {
    let mut definitions = doc.block_records.iter().collect::<Vec<_>>();
    definitions.sort_by_key(|definition| definition.handle.value());
    if definitions
        .windows(2)
        .any(|pair| pair[0].handle == pair[1].handle)
    {
        return Err(BlockReadError::new(
            "ambiguous_block_definition",
            "multiple block definitions share the same handle",
        ));
    }
    definitions
        .into_iter()
        .map(|definition| definition_record(doc, definition))
        .collect()
}

fn unique_definition_by_name<'a>(
    doc: &'a CadDocument,
    name: &str,
) -> Result<Option<&'a BlockRecord>, BlockReadError> {
    let matches = doc
        .block_records
        .iter()
        .filter(|definition| name_eq(&definition.name, name))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [definition] => Ok(Some(*definition)),
        _ => Err(BlockReadError::new(
            "ambiguous_block_definition",
            format!("multiple block definitions match name `{name}`"),
        )),
    }
}

fn unique_definition_by_handle(
    doc: &CadDocument,
    handle: Handle,
) -> Result<Option<&BlockRecord>, BlockReadError> {
    let matches = doc
        .block_records
        .iter()
        .filter(|definition| definition.handle == handle)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [definition] => Ok(Some(*definition)),
        _ => Err(BlockReadError::new(
            "ambiguous_block_definition",
            format!(
                "multiple block definitions match handle {:X}",
                handle.value()
            ),
        )),
    }
}

pub fn get_block_definition(
    doc: &CadDocument,
    selector: &BlockDefinitionSelector,
) -> Result<BlockDefinitionRecord, BlockReadError> {
    if selector.handle.is_none() && selector.name.is_none() {
        return Err(BlockReadError::new(
            "invalid_parameters",
            "block definition selector requires handle or name",
        ));
    }

    let requested_name = selector
        .name
        .as_deref()
        .map(|name| {
            if name.trim().is_empty() {
                Err(BlockReadError::new(
                    "invalid_block_definition_name",
                    "block definition name must not be empty",
                ))
            } else if name.trim() != name {
                Err(BlockReadError::new(
                    "invalid_block_definition_name",
                    "block definition name must not contain surrounding whitespace",
                ))
            } else {
                Ok(name)
            }
        })
        .transpose()?;
    let by_handle = selector
        .handle
        .as_deref()
        .map(parse_handle)
        .transpose()?
        .map(|handle| unique_definition_by_handle(doc, handle))
        .transpose()?
        .flatten();
    let by_name = requested_name
        .map(|name| unique_definition_by_name(doc, name))
        .transpose()?
        .flatten();

    let definition = match (
        selector.handle.is_some(),
        requested_name.is_some(),
        by_handle,
        by_name,
    ) {
        (true, true, Some(by_handle), Some(by_name)) if by_handle.handle == by_name.handle => {
            by_handle
        }
        (true, true, _, _) => {
            return Err(BlockReadError::new(
                "block_definition_identity_mismatch",
                "block definition handle and name did not resolve to the same definition",
            ))
        }
        (true, false, Some(definition), _) => definition,
        (false, true, _, Some(definition)) => definition,
        _ => {
            return Err(BlockReadError::new(
                "block_definition_not_found",
                "block definition was not found",
            ))
        }
    };

    unique_definition_by_handle(doc, definition.handle)?.ok_or_else(|| {
        BlockReadError::new(
            "block_definition_not_found",
            "selected block definition no longer exists",
        )
    })?;
    definition_record(doc, definition)
}

fn insert_record(
    doc: &CadDocument,
    insert: &Insert,
    definition: &BlockRecord,
) -> Result<BlockInsertRecord, BlockReadError> {
    let owner_context = resolve_direct_owner(doc, insert.common.owner_handle)
        .map_err(|error| BlockReadError::new("unsupported_block_data", error.to_string()))?;
    let mut attributes = insert
        .attributes
        .iter()
        .map(|attribute| BlockAttributeRecord {
            handle: canonical_optional_handle(attribute.common.handle),
            tag: attribute.tag.clone(),
            value: attribute.value.clone(),
            layer: attribute.common.layer.clone(),
        })
        .collect::<Vec<_>>();
    attributes.sort_by(|left, right| match (&left.handle, &right.handle) {
        (Some(left), Some(right)) => left.len().cmp(&right.len()).then_with(|| left.cmp(right)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => name_key(&left.tag)
            .cmp(&name_key(&right.tag))
            .then_with(|| left.value.cmp(&right.value)),
    });

    Ok(BlockInsertRecord {
        handle: canonical_handle(insert.common.handle, "block insert")?,
        definition_handle: canonical_handle(definition.handle, "block definition")?,
        block_name: insert.block_name.clone(),
        dynamic_block: resolve_dynamic_block_link(doc, insert)
            .map_err(|error| BlockReadError::new(error.code(), error.message()))?,
        owner_handle: canonical_optional_handle(insert.common.owner_handle),
        owner_context,
        layer: insert.common.layer.clone(),
        insertion_point: finite_point(insert.insert_point, "block insert insertion_point")?,
        x_scale: recoverable_insert_scale(insert.x_scale(), "block insert x_scale")?,
        y_scale: recoverable_insert_scale(insert.y_scale(), "block insert y_scale")?,
        z_scale: recoverable_insert_scale(insert.z_scale(), "block insert z_scale")?,
        rotation_radians: finite_number(insert.rotation, "block insert rotation_radians")?,
        normal: finite_point(insert.normal, "block insert normal")?,
        column_count: insert.column_count,
        row_count: insert.row_count,
        column_spacing: finite_number(insert.column_spacing, "block insert column_spacing")?,
        row_spacing: finite_number(insert.row_spacing, "block insert row_spacing")?,
        is_array: insert.is_array(),
        attributes,
    })
}

/// List ordinary INSERT/MINSERT entities.
///
/// INSERTs that reference XREF, XREF-overlay, XREF-dependent, or layout block
/// records are excluded. Attributed inserts (including title blocks) remain in
/// the result.
pub fn list_block_inserts(doc: &CadDocument) -> Result<Vec<BlockInsertRecord>, BlockReadError> {
    validate_semantic_entity_handles(doc)
        .map_err(|error| BlockReadError::new(error.code(), error.message()))?;
    let mut inserts = Vec::new();
    for entity in doc.entities() {
        let EntityType::Insert(insert) = entity else {
            continue;
        };
        let definition = resolve_insert_definition(doc, insert)?;
        if is_ordinary_definition(doc, definition)? {
            inserts.push((insert, definition));
        }
    }
    inserts.sort_by_key(|(insert, _)| insert.common.handle.value());
    if inserts
        .windows(2)
        .any(|pair| pair[0].0.common.handle == pair[1].0.common.handle)
    {
        return Err(BlockReadError::new(
            "unsupported_block_data",
            "multiple ordinary block inserts share the same handle",
        ));
    }
    inserts
        .into_iter()
        .map(|(insert, definition)| insert_record(doc, insert, definition))
        .collect()
}

pub fn get_block_insert(
    doc: &CadDocument,
    selector: &BlockInsertSelector,
) -> Result<BlockInsertRecord, BlockReadError> {
    let wanted = parse_handle(&selector.handle)?;
    validate_semantic_entity_handles(doc)
        .map_err(|error| BlockReadError::new(error.code(), error.message()))?;
    let matches = doc
        .entities()
        .filter_map(|entity| match entity {
            EntityType::Insert(insert) if insert.common.handle == wanted => Some(insert),
            _ => None,
        })
        .collect::<Vec<_>>();
    let insert = match matches.as_slice() {
        [] => {
            return Err(BlockReadError::new(
                "block_insert_not_found",
                format!("ordinary block insert {:X} was not found", wanted.value()),
            ))
        }
        [insert] => *insert,
        _ => {
            return Err(BlockReadError::new(
                "unsupported_block_data",
                format!("multiple block inserts share handle {:X}", wanted.value()),
            ))
        }
    };
    let definition = resolve_insert_definition(doc, insert)?;
    if !is_ordinary_definition(doc, definition)? {
        return Err(BlockReadError::new(
            "block_insert_not_found",
            format!("ordinary block insert {:X} was not found", wanted.value()),
        ));
    }
    insert_record(doc, insert, definition)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::entities::{AttributeEntity, Line};
    use acadrust::tables::BlockRecord;
    use acadrust::types::Vector3;
    use acadrust::{CadDocument, DwgReader};
    use std::path::{Path, PathBuf};

    fn fixture_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    fn add_definition(doc: &mut CadDocument, name: &str, handle: u64) {
        let mut definition = BlockRecord::new(name);
        definition.handle = Handle::new(handle);
        doc.block_records.add_or_replace(definition);
    }

    fn add_insert(
        doc: &mut CadDocument,
        block_name: &str,
        handle: u64,
        position: Vector3,
    ) -> Handle {
        let mut insert = Insert::new(block_name, position);
        insert.common.handle = Handle::new(handle);
        doc.add_entity(EntityType::Insert(insert)).unwrap()
    }

    #[test]
    fn new_doc_has_no_user_blocks() {
        let doc = CadDocument::new();
        // The default doc has *Model_Space and *Paper_Space — both filtered out.
        assert_eq!(list_blocks(&doc).len(), 0);
    }

    #[test]
    fn user_block_appears() {
        let mut doc = CadDocument::new();
        let mut br = BlockRecord::new("NORTH_ARROW");
        br.flags.has_attributes = false;
        doc.block_records.add_or_replace(br);

        let blocks = list_blocks(&doc);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].name, "NORTH_ARROW");
        assert!(!blocks[0].has_attributes);
    }

    #[test]
    fn xref_blocks_excluded() {
        let mut doc = CadDocument::new();
        let mut xref = BlockRecord::new("SITE_MODEL");
        xref.flags.is_xref = true;
        doc.block_records.add_or_replace(xref);

        let blocks = list_blocks(&doc);
        assert_eq!(
            blocks.len(),
            0,
            "xref should be excluded from block inventory"
        );
    }

    #[test]
    fn layout_blocks_excluded() {
        // *Model_Space and *Paper_Space already exist in new doc and must not appear.
        let doc = CadDocument::new();
        let blocks = list_blocks(&doc);
        for b in &blocks {
            assert!(
                !b.name.starts_with('*'),
                "layout block {:?} leaked into inventory",
                b.name
            );
        }
    }

    #[test]
    fn rich_definition_list_is_handle_sorted_and_includes_all_definition_contexts() {
        let mut doc = CadDocument::new();
        add_definition(&mut doc, "SECOND", 0x100);
        let mut anonymous = BlockRecord::new("*U42");
        anonymous.handle = Handle::new(0x20);
        anonymous.flags.anonymous = true;
        doc.block_records.add_or_replace(anonymous);
        add_definition(&mut doc, "FIRST", 0xF);

        let mut xref = BlockRecord::new("XREF");
        xref.handle = Handle::new(0x10);
        xref.flags.is_xref = true;
        doc.block_records.add_or_replace(xref);

        let mut dependent = BlockRecord::new("XREF|PART");
        dependent.handle = Handle::new(0x11);
        doc.block_records.add_or_replace(dependent);

        let mut externally_flagged = BlockRecord::new("EXTERNAL_FLAG");
        externally_flagged.handle = Handle::new(0x12);
        externally_flagged.flags.is_external = true;
        doc.block_records.add_or_replace(externally_flagged);

        let records = list_block_definitions(&doc).unwrap();
        let numeric_handles = records
            .iter()
            .map(|record| u64::from_str_radix(&record.handle, 16).unwrap())
            .collect::<Vec<_>>();
        assert!(numeric_handles.windows(2).all(|pair| pair[0] <= pair[1]));

        let anonymous = records.iter().find(|record| record.name == "*U42").unwrap();
        assert!(anonymous.is_anonymous);
        assert!(records
            .iter()
            .filter(|record| record.is_layout)
            .all(|record| !record.is_anonymous));
        let xref = records.iter().find(|record| record.name == "XREF").unwrap();
        assert!(xref.is_xref);
        let dependent = records
            .iter()
            .find(|record| record.name == "XREF|PART")
            .unwrap();
        assert!(dependent.xref_dependent);
        let externally_flagged = records
            .iter()
            .find(|record| record.name == "EXTERNAL_FLAG")
            .unwrap();
        assert!(externally_flagged.xref_dependent);
        assert!(records.iter().any(|record| record.is_model_space));
        assert!(records.iter().any(|record| record.is_paper_space));
    }

    #[test]
    fn unrelated_raw_layout_handle_does_not_hide_an_ordinary_definition() {
        let mut doc = CadDocument::new();
        let mut definition = BlockRecord::new("*U7");
        definition.handle = Handle::new(0x343);
        definition.layout = Handle::new(0x252);
        doc.block_records.add_or_replace(definition);
        add_insert(&mut doc, "*U7", 0x252, Vector3::ZERO);

        let definition = get_block_definition(
            &doc,
            &BlockDefinitionSelector {
                handle: Some("343".to_string()),
                name: Some("*U7".to_string()),
            },
        )
        .unwrap();
        assert!(!definition.is_layout);
        assert_eq!(definition.layout_handle, None);

        let inserts = list_block_inserts(&doc).unwrap();
        assert_eq!(inserts.len(), 1);
        assert_eq!(inserts[0].handle, "252");
    }

    #[test]
    fn layout_object_join_classifies_nonstandard_paper_block_and_excludes_its_inserts() {
        let mut doc = CadDocument::new();
        let layout_handle = doc.add_layout("Sheet Custom").unwrap();
        let block_handle = match doc.objects.get(&layout_handle).unwrap() {
            ObjectType::Layout(layout) => layout.block_record,
            _ => panic!("new layout handle did not resolve to a LAYOUT object"),
        };
        doc.block_records
            .iter_mut()
            .find(|block| block.handle == block_handle)
            .unwrap()
            .name = "SHEET_CUSTOM_BACKING".to_string();
        add_insert(&mut doc, "SHEET_CUSTOM_BACKING", 0xD10, Vector3::ZERO);

        let record = get_block_definition(
            &doc,
            &BlockDefinitionSelector {
                handle: Some(format!("{:X}", block_handle.value())),
                name: Some("sheet_custom_backing".to_string()),
            },
        )
        .unwrap();
        assert!(record.is_layout);
        assert!(record.is_paper_space);
        assert!(!record.is_model_space);
        let expected_layout_handle = format!("{:X}", layout_handle.value());
        assert_eq!(
            record.layout_handle.as_deref(),
            Some(expected_layout_handle.as_str())
        );
        assert!(list_block_inserts(&doc).unwrap().is_empty());
    }

    #[test]
    fn rich_definition_exposes_metadata_contents_and_references() {
        let mut doc = CadDocument::new();
        let mut definition = BlockRecord::new("TITLE");
        definition.handle = Handle::new(0xAB);
        definition.block_entity_handle = Handle::new(0xAC);
        definition.block_end_handle = Handle::new(0xAD);
        definition.description = "Sheet title".to_string();
        definition.flags.has_attributes = true;
        definition.units = 4;
        definition.explodable = false;
        definition.scale_uniformly = true;
        definition.entity_handles = vec![Handle::new(0x200), Handle::new(0x1F)];
        doc.block_records.add_or_replace(definition);
        add_insert(&mut doc, "title", 0x301, Vector3::ZERO);
        add_insert(&mut doc, "TITLE", 0x2F, Vector3::ZERO);

        let record = get_block_definition(
            &doc,
            &BlockDefinitionSelector {
                handle: Some("0x00ab".to_string()),
                name: Some("title".to_string()),
            },
        )
        .unwrap();
        assert_eq!(record.handle, "AB");
        assert_eq!(record.description, "Sheet title");
        assert!(record.has_attributes);
        assert_eq!(record.units, 4);
        assert!(!record.explodable);
        assert!(record.scale_uniformly);
        assert_eq!(record.entity_handles, ["1F", "200"]);
        assert_eq!(record.owned_entity_count, 2);
        assert_eq!(record.insert_handles, ["2F", "301"]);
        assert_eq!(record.insert_count, 2);
        assert_eq!(record.block_entity_handle.as_deref(), Some("AC"));
        assert_eq!(record.block_end_handle.as_deref(), Some("AD"));
    }

    #[test]
    fn definition_selector_errors_are_explicit() {
        let mut doc = CadDocument::new();
        add_definition(&mut doc, "A", 0xA);
        add_definition(&mut doc, "B", 0xB);

        let missing = get_block_definition(&doc, &BlockDefinitionSelector::default()).unwrap_err();
        assert_eq!(missing.code(), "invalid_parameters");

        let blank = get_block_definition(
            &doc,
            &BlockDefinitionSelector {
                name: Some("  ".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(blank.code(), "invalid_block_definition_name");
        let whitespace = get_block_definition(
            &doc,
            &BlockDefinitionSelector {
                name: Some(" A".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(whitespace.code(), "invalid_block_definition_name");
        assert!(whitespace.message().contains("surrounding whitespace"));

        let invalid = get_block_definition(
            &doc,
            &BlockDefinitionSelector {
                handle: Some("not-hex".to_string()),
                name: None,
            },
        )
        .unwrap_err();
        assert_eq!(invalid.code(), "invalid_handle");

        let not_found = get_block_definition(
            &doc,
            &BlockDefinitionSelector {
                handle: Some("FF".to_string()),
                name: None,
            },
        )
        .unwrap_err();
        assert_eq!(not_found.code(), "block_definition_not_found");

        let mismatch = get_block_definition(
            &doc,
            &BlockDefinitionSelector {
                handle: Some("A".to_string()),
                name: Some("B".to_string()),
            },
        )
        .unwrap_err();
        assert_eq!(mismatch.code(), "block_definition_identity_mismatch");
    }

    #[test]
    fn name_lookup_rejects_a_handle_shared_by_distinct_definitions() {
        let mut doc = CadDocument::new();
        add_definition(&mut doc, "FIRST", 0xA0);
        add_definition(&mut doc, "SECOND", 0xA0);

        let error = get_block_definition(
            &doc,
            &BlockDefinitionSelector {
                name: Some("FIRST".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "ambiguous_block_definition");
        assert_eq!(
            list_block_definitions(&doc).unwrap_err().code(),
            error.code()
        );
    }

    #[test]
    fn ordinary_insert_list_excludes_xrefs_and_keeps_attributed_title_blocks() {
        let mut doc = CadDocument::new();
        add_definition(&mut doc, "TITLE_BLOCK", 0x40);
        let mut xref = BlockRecord::new("SITE_XREF");
        xref.handle = Handle::new(0x41);
        xref.flags.is_xref = true;
        doc.block_records.add_or_replace(xref);

        let mut title = Insert::new("title_block", Vector3::new(10.0, 20.0, 30.0))
            .with_scale(2.0, 3.0, 4.0)
            .with_rotation(0.5)
            .with_array(2, 3, 7.0, 8.0);
        title.common.handle = Handle::new(0x100);
        title.common.layer = "SHEET".to_string();
        let mut attribute = AttributeEntity::simple("DRAWING_NO", "A-101");
        attribute.common.handle = Handle::new(0x101);
        attribute.common.layer = "ATTR".to_string();
        title.attributes.push(attribute);
        doc.add_entity(EntityType::Insert(title)).unwrap();
        add_insert(&mut doc, "SITE_XREF", 0x20, Vector3::ZERO);

        let records = list_block_inserts(&doc).unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.handle, "100");
        assert_eq!(record.definition_handle, "40");
        assert_eq!(record.block_name, "title_block");
        assert_eq!(
            record.dynamic_block,
            DynamicBlockLink::Unavailable {
                reason: super::super::dynamic_blocks::DynamicBlockUnavailableReason::LinkNotProven,
            }
        );
        assert_eq!(
            record.owner_context,
            Some(DirectOwnerContext::Available {
                owner_type: super::super::owners::DirectOwnerType::ModelSpace,
                owner_name: "Model".to_string(),
            })
        );
        assert_eq!(
            record.insertion_point,
            BlockPoint3 {
                x: 10.0,
                y: 20.0,
                z: 30.0
            }
        );
        assert_eq!(
            (record.x_scale, record.y_scale, record.z_scale),
            (2.0, 3.0, 4.0)
        );
        assert_eq!(record.rotation_radians, 0.5);
        assert!(record.is_array);
        assert_eq!((record.column_count, record.row_count), (2, 3));
        assert_eq!(record.attributes.len(), 1);
        assert_eq!(record.attributes[0].handle.as_deref(), Some("101"));
        assert_eq!(record.attributes[0].tag, "DRAWING_NO");
        assert_eq!(record.attributes[0].value, "A-101");
    }

    #[test]
    fn ordinary_inserts_are_sorted_by_numeric_handle_and_targeted_by_handle() {
        let mut doc = CadDocument::new();
        add_definition(&mut doc, "MARKER", 0x40);
        add_insert(&mut doc, "MARKER", 0x100, Vector3::new(2.0, 0.0, 0.0));
        add_insert(&mut doc, "MARKER", 0xF, Vector3::new(1.0, 0.0, 0.0));

        let records = list_block_inserts(&doc).unwrap();
        assert_eq!(
            records
                .iter()
                .map(|record| record.handle.as_str())
                .collect::<Vec<_>>(),
            ["F", "100"]
        );
        let record = get_block_insert(
            &doc,
            &BlockInsertSelector {
                handle: "0x000f".to_string(),
            },
        )
        .unwrap();
        assert_eq!(record.insertion_point.x, 1.0);
    }

    #[test]
    fn cross_type_handle_collisions_cannot_hide_behind_insert_filtering() {
        let mut doc = CadDocument::new();
        add_definition(&mut doc, "MARKER", 0x40);
        add_insert(&mut doc, "MARKER", 0x100, Vector3::ZERO);
        let mut line = Line::new();
        line.common.handle = Handle::new(0x100);
        doc.add_entity(EntityType::Line(line)).unwrap();

        assert_eq!(
            list_block_inserts(&doc).unwrap_err().code(),
            "duplicate_entity_handle"
        );
        assert_eq!(
            get_block_insert(
                &doc,
                &BlockInsertSelector {
                    handle: "100".to_string(),
                },
            )
            .unwrap_err()
            .code(),
            "duplicate_entity_handle"
        );
    }

    #[test]
    fn attached_attribute_handles_participate_in_global_identity_validation() {
        let mut top_level_collision = CadDocument::new();
        add_definition(&mut top_level_collision, "MARKER", 0x40);
        let mut insert = Insert::new("MARKER", Vector3::ZERO);
        insert.common.handle = Handle::new(0x100);
        let mut attribute = AttributeEntity::simple("TAG", "VALUE");
        attribute.common.handle = Handle::new(0x200);
        insert.attributes.push(attribute);
        top_level_collision
            .add_entity(EntityType::Insert(insert))
            .unwrap();
        let mut line = Line::new();
        line.common.handle = Handle::new(0x200);
        top_level_collision
            .add_entity(EntityType::Line(line))
            .unwrap();
        assert_eq!(
            list_block_inserts(&top_level_collision).unwrap_err().code(),
            "duplicate_entity_handle"
        );
        assert_eq!(
            get_block_insert(
                &top_level_collision,
                &BlockInsertSelector {
                    handle: "100".to_string(),
                },
            )
            .unwrap_err()
            .code(),
            "duplicate_entity_handle"
        );

        let mut nested_collision = CadDocument::new();
        add_definition(&mut nested_collision, "MARKER", 0x40);
        for insert_handle in [0x100, 0x101] {
            let mut insert = Insert::new("MARKER", Vector3::ZERO);
            insert.common.handle = Handle::new(insert_handle);
            let mut attribute = AttributeEntity::simple("TAG", "VALUE");
            attribute.common.handle = Handle::new(0x200);
            insert.attributes.push(attribute);
            nested_collision
                .add_entity(EntityType::Insert(insert))
                .unwrap();
        }
        assert_eq!(
            list_block_inserts(&nested_collision).unwrap_err().code(),
            "duplicate_entity_handle"
        );
    }

    #[test]
    fn path_only_xref_definitions_never_surface_as_ordinary_blocks_or_inserts() {
        let mut doc = CadDocument::new();
        let mut xref = BlockRecord::new("SITE");
        xref.handle = Handle::new(0x41);
        xref.xref_path = "refs/site.dwg".to_string();
        doc.block_records.add_or_replace(xref);
        add_insert(&mut doc, "SITE", 0x50, Vector3::ZERO);

        assert!(list_blocks(&doc).iter().all(|block| block.name != "SITE"));
        let definition = get_block_definition(
            &doc,
            &BlockDefinitionSelector {
                name: Some("SITE".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(definition.is_xref);
        assert_eq!(definition.xref_path.as_deref(), Some("refs/site.dwg"));
        assert!(list_block_inserts(&doc).unwrap().is_empty());
        assert_eq!(
            get_block_insert(
                &doc,
                &BlockInsertSelector {
                    handle: "50".to_string(),
                },
            )
            .unwrap_err()
            .code(),
            "block_insert_not_found"
        );
    }

    #[test]
    fn targeted_insert_rejects_invalid_missing_non_insert_and_xref_handles() {
        let mut doc = CadDocument::new();
        add_definition(&mut doc, "ORDINARY", 0x40);
        let mut xref = BlockRecord::new("XREF");
        xref.handle = Handle::new(0x41);
        xref.flags.is_xref = true;
        doc.block_records.add_or_replace(xref);
        add_insert(&mut doc, "XREF", 0x50, Vector3::ZERO);

        let mut line = Line::from_coords(0.0, 0.0, 0.0, 1.0, 1.0, 0.0);
        line.common.handle = Handle::new(0x51);
        doc.add_entity(EntityType::Line(line)).unwrap();

        for (input, code) in [
            ("", "invalid_handle"),
            (" 50", "invalid_handle"),
            ("GG", "invalid_handle"),
            ("52", "block_insert_not_found"),
            ("51", "block_insert_not_found"),
            ("50", "block_insert_not_found"),
        ] {
            let error = get_block_insert(
                &doc,
                &BlockInsertSelector {
                    handle: input.to_string(),
                },
            )
            .unwrap_err();
            assert_eq!(error.code(), code, "input={input}");
        }
    }

    #[test]
    fn unresolved_insert_definition_fails_closed() {
        let mut doc = CadDocument::new();
        add_insert(&mut doc, "MISSING", 0x70, Vector3::ZERO);
        let error = list_block_inserts(&doc).unwrap_err();
        assert_eq!(error.code(), "unsupported_block_data");
        assert!(error.message().contains("missing block definition"));
    }

    #[test]
    fn non_finite_block_insert_values_fail_closed() {
        let mut doc = CadDocument::new();
        add_definition(&mut doc, "MARKER", 0x40);
        let mut insert = Insert::new("MARKER", Vector3::ZERO);
        insert.common.handle = Handle::new(0x70);
        insert.rotation = f64::NAN;
        doc.add_entity(EntityType::Insert(insert)).unwrap();

        let error = list_block_inserts(&doc).unwrap_err();
        assert_eq!(error.code(), "unsupported_block_data");
        assert!(error.message().contains("rotation_radians"));
        assert!(error.message().contains("not a finite number"));
    }

    #[test]
    fn parser_clamped_insert_scales_fail_closed_across_both_read_surfaces() {
        let mut doc = CadDocument::new();
        add_definition(&mut doc, "MARKER", 0x40);
        let mut insert = Insert::new("MARKER", Vector3::ZERO).with_scale(0.0, 1.0, 1.0);
        insert.common.handle = Handle::new(0x70);
        doc.add_entity(EntityType::Insert(insert)).unwrap();

        for error in [
            list_block_inserts(&doc).unwrap_err(),
            get_block_insert(
                &doc,
                &BlockInsertSelector {
                    handle: "70".to_string(),
                },
            )
            .unwrap_err(),
        ] {
            assert_eq!(error.code(), "unsupported_block_data");
            assert_eq!(
                error.message(),
                "reader cannot recover the saved block insert x_scale"
            );
            assert!(!error.message().contains("acadrust"));
        }
    }

    #[test]
    fn tier1_dwg_supports_rich_definition_and_insert_reads() {
        let fixture_root = "tests/corpus/open/acadsharp/dynamic-blocks";
        let mut reader = DwgReader::from_file(fixture_path(&format!(
            "{fixture_root}/BLOCKVISIBILITYPARAMETER.dwg"
        )))
        .unwrap();
        let dwg = reader.read().unwrap();

        let dwg_definitions = list_block_definitions(&dwg).unwrap();
        assert!(!dwg_definitions.is_empty());
        for expected in &dwg_definitions {
            assert_eq!(
                get_block_definition(
                    &dwg,
                    &BlockDefinitionSelector {
                        handle: Some(expected.handle.clone()),
                        name: Some(expected.name.clone()),
                    },
                )
                .unwrap(),
                *expected
            );
        }

        let dwg_inserts = list_block_inserts(&dwg).unwrap();
        assert!(!dwg_inserts.is_empty());
        let dynamic_insert = dwg_inserts
            .iter()
            .find(|record| record.handle == "252")
            .expect("fixture INSERT 252");
        assert!(matches!(
            &dynamic_insert.dynamic_block,
            DynamicBlockLink::Available {
                definition_handle,
                definition_name,
                ..
            } if definition_handle == "24F"
                && definition_name == "block_visibility_parameter"
        ));
        for expected in &dwg_inserts {
            assert_eq!(
                get_block_insert(
                    &dwg,
                    &BlockInsertSelector {
                        handle: expected.handle.clone(),
                    },
                )
                .unwrap(),
                *expected
            );
        }
    }

    #[test]
    fn rich_output_contracts_reject_unknown_fields() {
        let definition_error =
            serde_json::from_str::<BlockDefinitionSelector>(r#"{"handle":"A","unexpected":true}"#)
                .unwrap_err();
        assert!(definition_error
            .to_string()
            .contains("unknown field `unexpected`"));

        let insert_error =
            serde_json::from_str::<BlockInsertSelector>(r#"{"handle":"A","unexpected":true}"#)
                .unwrap_err();
        assert!(insert_error
            .to_string()
            .contains("unknown field `unexpected`"));
    }
}
