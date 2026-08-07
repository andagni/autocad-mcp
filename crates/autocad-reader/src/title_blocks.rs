//! Reader-owned attributed-INSERT title-block projection.

use std::collections::{hash_map::Entry, HashMap};

use acadrust::{entities::EntityType, CadDocument};

use super::contract::TitleBlockInfo;

autocad_diagnostics::domain_error!(pub struct TitleBlockReadError, new = pub(crate));

fn normalize_attribute_tag(tag: &str) -> String {
    tag.trim().to_uppercase()
}

pub(super) fn read_title_blocks(doc: &CadDocument) -> Vec<TitleBlockInfo> {
    let mut blocks = Vec::new();
    for entity in doc.entities() {
        let EntityType::Insert(insert) = entity else {
            continue;
        };
        if insert.attributes.is_empty() {
            continue;
        }

        let mut attributes = HashMap::with_capacity(insert.attributes.len());
        let mut attribute_arrays: HashMap<String, Vec<String>> = HashMap::new();
        for attribute in &insert.attributes {
            let normalized_tag = normalize_attribute_tag(&attribute.tag);
            match attribute_arrays.entry(normalized_tag.clone()) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().push(attribute.value.clone());
                }
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
        blocks.push(TitleBlockInfo {
            block_name: insert.block_name.clone(),
            layer: insert.common.layer.clone(),
            attributes,
            attribute_arrays,
        });
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::entities::{AttributeEntity, Insert};
    use acadrust::types::Vector3;

    fn doc_with_title_block() -> CadDocument {
        let mut doc = CadDocument::new();
        let mut insert = Insert::new("AUTOCAD_MCP_GENERIC", Vector3::new(0.0, 0.0, 0.0));
        insert
            .attributes
            .push(AttributeEntity::simple("DRAWING_NUMBER", "ABC-001"));
        insert
            .attributes
            .push(AttributeEntity::simple("REVISION", "P01"));
        insert
            .attributes
            .push(AttributeEntity::simple("drawing.title.big", "Site Plan"));
        doc.add_entity(EntityType::Insert(insert)).unwrap();
        doc
    }

    #[test]
    fn empty_document_returns_empty() {
        assert!(read_title_blocks(&CadDocument::new()).is_empty());
    }

    #[test]
    fn attributed_insert_appears() {
        let blocks = read_title_blocks(&doc_with_title_block());
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].block_name, "AUTOCAD_MCP_GENERIC");
    }

    #[test]
    fn attribute_tags_are_normalized_and_values_are_preserved() {
        let blocks = read_title_blocks(&doc_with_title_block());
        assert_eq!(
            blocks[0]
                .attributes
                .get("DRAWING_NUMBER")
                .map(String::as_str),
            Some("ABC-001")
        );
        assert_eq!(
            blocks[0].attributes.get("REVISION").map(String::as_str),
            Some("P01")
        );
        assert_eq!(
            blocks[0]
                .attributes
                .get("DRAWING.TITLE.BIG")
                .map(String::as_str),
            Some("Site Plan")
        );
    }

    #[test]
    fn insert_without_attributes_is_excluded() {
        let mut doc = CadDocument::new();
        let insert = Insert::new("NORTH_ARROW", Vector3::new(0.0, 0.0, 0.0));
        doc.add_entity(EntityType::Insert(insert)).unwrap();
        assert!(read_title_blocks(&doc).is_empty());
    }

    #[test]
    fn duplicate_normalized_tags_return_all_values_in_source_order() {
        let mut doc = CadDocument::new();
        let mut insert = Insert::new("AUTOCAD_MCP_GENERIC", Vector3::new(0.0, 0.0, 0.0));
        insert.common.layer = "TITLE".to_string();
        insert
            .attributes
            .push(AttributeEntity::simple("revision", "P01"));
        insert
            .attributes
            .push(AttributeEntity::simple(" REVISION ", "P02"));
        insert
            .attributes
            .push(AttributeEntity::simple("Revision", "P03"));
        doc.add_entity(EntityType::Insert(insert)).unwrap();

        let blocks = read_title_blocks(&doc);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].attributes.is_empty());
        assert_eq!(
            blocks[0].attribute_arrays.get("REVISION"),
            Some(&vec![
                "P01".to_string(),
                "P02".to_string(),
                "P03".to_string()
            ])
        );
        assert_eq!(blocks[0].duplicate_attribute_tags(), ["REVISION"]);
    }

    #[test]
    fn split_projection_round_trips_through_json() {
        let blocks = read_title_blocks(&doc_with_title_block());
        let json = serde_json::to_string(&blocks).unwrap();
        assert!(!json.contains("attribute_arrays"));
        let parsed: Vec<TitleBlockInfo> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, blocks);
    }

    #[test]
    fn output_contract_rejects_unknown_fields() {
        let error = serde_json::from_str::<TitleBlockInfo>(
            r#"{
                "block_name": "AUTOCAD_MCP_GENERIC",
                "layer": "0",
                "attributes": {},
                "attribute_arrays": {},
                "unexpected": true
            }"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field `unexpected`"));
    }
}
