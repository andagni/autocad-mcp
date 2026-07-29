use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LayerLineWeight {
    ByLayer,
    ByBlock,
    Default,
    Value { hundredths_mm: i16 },
    Raw { raw_value: i16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerRecord {
    pub handle: String,
    pub name: String,
    pub color_index: Option<u16>,
    pub line_type: String,
    pub line_weight: LayerLineWeight,
    pub frozen: bool,
    pub locked: bool,
    pub off: bool,
    pub is_plottable: bool,
    pub xref_dependent: bool,
    pub xref_block_record_handle: Option<String>,
    pub xref_name: Option<String>,
    pub xref_path: Option<String>,
    pub xref_is_overlay: Option<bool>,
    pub material_handle: Option<String>,
    pub plotstyle_handle: Option<String>,
    pub is_current: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerSelector {
    pub handle: Option<String>,
    pub name: Option<String>,
    pub expected_handle: Option<String>,
    pub expected_name: Option<String>,
}
