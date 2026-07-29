use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TitleBlockFingerprint {
    pub block_name: String,
    pub attribute_tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TitleBlockWrite {
    pub fingerprint: TitleBlockFingerprint,
    /// Resolved raw attribute tag to exact replacement value.
    pub tag_values: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TitleBlockWriteResult {
    pub target_inserts: usize,
    pub fields_written: usize,
    pub attributes_written: usize,
}
