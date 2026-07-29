use std::collections::HashMap;

use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TitleBlockInfo {
    pub block_name: String,
    pub layer: String,
    #[serde(serialize_with = "serialize_sorted_string_map")]
    pub attributes: HashMap<String, String>,
    /// Values for normalized tags that occur more than once on this INSERT.
    ///
    /// Duplicate tags are omitted from `attributes` rather than selecting an
    /// arbitrary scalar. Values remain in source order. The field is absent
    /// from JSON when every tag is unique, preserving the original response
    /// shape for unambiguous drawings.
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "serialize_sorted_string_map"
    )]
    pub attribute_arrays: HashMap<String, Vec<String>>,
}

impl TitleBlockInfo {
    pub fn duplicate_attribute_tags(&self) -> Vec<&str> {
        let mut tags = self
            .attribute_arrays
            .iter()
            .filter(|(_, values)| values.len() > 1)
            .map(|(tag, _)| tag.as_str())
            .collect::<Vec<_>>();
        tags.sort_unstable();
        tags
    }

    pub fn use_array_mode(&mut self) {
        for (tag, value) in std::mem::take(&mut self.attributes) {
            self.attribute_arrays.insert(tag, vec![value]);
        }
    }

    pub fn attribute_tags(&self) -> impl Iterator<Item = &str> {
        self.attributes
            .keys()
            .chain(self.attribute_arrays.keys())
            .map(String::as_str)
    }
}

fn serialize_sorted_string_map<S, V>(
    values: &HashMap<String, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    V: Serialize,
{
    let mut keys = values.keys().collect::<Vec<_>>();
    keys.sort_unstable();

    let mut map = serializer.serialize_map(Some(keys.len()))?;
    for key in keys {
        map.serialize_entry(key, &values[key])?;
    }
    map.end()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_serialize_in_lexicographic_key_order() {
        let block = TitleBlockInfo {
            block_name: "TITLE".to_string(),
            layer: "0".to_string(),
            attributes: HashMap::from([
                ("REVISION".to_string(), "P01".to_string()),
                ("DRAWING_NUMBER".to_string(), "A-001".to_string()),
            ]),
            attribute_arrays: HashMap::from([
                (
                    "SHEET_NUMBER".to_string(),
                    vec!["1".to_string(), "2".to_string()],
                ),
                (
                    "REFERENCE".to_string(),
                    vec!["REF-A".to_string(), "REF-B".to_string()],
                ),
            ]),
        };

        assert_eq!(
            serde_json::to_string(&block).unwrap(),
            concat!(
                r#"{"block_name":"TITLE","layer":"0","attributes":{"DRAWING_NUMBER":"A-001","#,
                r#""REVISION":"P01"},"attribute_arrays":{"REFERENCE":["REF-A","REF-B"],"#,
                r#""SHEET_NUMBER":["1","2"]}}"#
            )
        );
    }

    #[test]
    fn array_mode_singletons_are_not_duplicate_tags() {
        let mut block = TitleBlockInfo {
            block_name: "TITLE".to_string(),
            layer: "0".to_string(),
            attributes: HashMap::from([("REVISION".to_string(), "P01".to_string())]),
            attribute_arrays: HashMap::from([(
                "SHEET_NUMBER".to_string(),
                vec!["1".to_string(), "2".to_string()],
            )]),
        };

        block.use_array_mode();

        assert!(block.attributes.is_empty());
        assert_eq!(block.attribute_arrays["REVISION"], ["P01".to_string()]);
        assert_eq!(block.duplicate_attribute_tags(), ["SHEET_NUMBER"]);
        assert_eq!(
            block
                .attribute_tags()
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from(["REVISION", "SHEET_NUMBER"])
        );
    }
}
