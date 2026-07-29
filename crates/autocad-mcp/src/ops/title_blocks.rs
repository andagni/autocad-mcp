//! Compatibility contract and mutation-preparation projection.
//!
//! Public title-block reads use `DrawingReadSession`. Mutation preparation
//! retains this explicitly named backend-typed projector until the writer
//! architecture owns that transition separately.

use std::collections::{hash_map::Entry, HashMap};

use acadrust::{entities::EntityType, CadDocument};

pub use crate::autocad_reader::contract::TitleBlockInfo;
pub use crate::autocad_reader::TitleBlockReadError;

fn normalize_attribute_tag(tag: &str) -> String {
    tag.trim().to_uppercase()
}

pub fn project_title_blocks_for_mutation(doc: &CadDocument) -> Vec<TitleBlockInfo> {
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
