use serde::{Deserialize, Serialize};

use super::{DirectOwnerContext, DynamicBlockLink};

/// Compatibility record returned by the original `list_blocks` surface.
///
/// Keep this shape stable. Rich, handle-bearing block definition reads use
/// [`BlockDefinitionRecord`] instead.
#[derive(Debug, Serialize)]
pub struct BlockInfo {
    pub name: String,
    pub has_attributes: bool,
    pub description: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockPoint3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Rich block-definition record.
///
/// `base_point` remains deliberately absent until an externally produced
/// modern DWG with a nonzero block base and an independent oracle qualifies
/// the selected backend's projection.
pub struct BlockDefinitionRecord {
    /// Canonical, uppercase hexadecimal BLOCK_RECORD handle.
    pub handle: String,
    pub name: String,
    pub description: String,
    pub has_attributes: bool,
    pub is_anonymous: bool,
    pub is_xref: bool,
    pub is_xref_overlay: bool,
    pub xref_dependent: bool,
    pub is_layout: bool,
    pub is_model_space: bool,
    pub is_paper_space: bool,
    pub layout_handle: Option<String>,
    pub xref_path: Option<String>,
    /// Raw INSUNITS value retained by the reader.
    pub units: i16,
    pub explodable: bool,
    pub scale_uniformly: bool,
    /// Canonical handles of entities directly owned by this definition.
    pub entity_handles: Vec<String>,
    pub owned_entity_count: usize,
    /// Canonical handles of INSERT/MINSERT entities referencing this definition.
    pub insert_handles: Vec<String>,
    pub insert_count: usize,
    /// Structural BLOCK marker handle when retained by the source model.
    pub block_entity_handle: Option<String>,
    /// Structural ENDBLK marker handle when retained by the source model.
    pub block_end_handle: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockDefinitionSelector {
    pub handle: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockAttributeRecord {
    /// Attribute handles are optional because malformed/synthetic documents may
    /// contain an in-memory attribute without a persisted identity.
    pub handle: Option<String>,
    pub tag: String,
    pub value: String,
    pub layer: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockInsertRecord {
    /// Canonical, uppercase hexadecimal INSERT/MINSERT handle.
    pub handle: String,
    /// Canonical handle of the referenced ordinary block definition.
    pub definition_handle: String,
    pub block_name: String,
    pub dynamic_block: DynamicBlockLink,
    pub owner_handle: Option<String>,
    pub owner_context: Option<DirectOwnerContext>,
    pub layer: String,
    pub insertion_point: BlockPoint3,
    pub x_scale: f64,
    pub y_scale: f64,
    pub z_scale: f64,
    pub rotation_radians: f64,
    pub normal: BlockPoint3,
    pub column_count: u16,
    pub row_count: u16,
    pub column_spacing: f64,
    pub row_spacing: f64,
    pub is_array: bool,
    pub attributes: Vec<BlockAttributeRecord>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockInsertSelector {
    pub handle: String,
}
