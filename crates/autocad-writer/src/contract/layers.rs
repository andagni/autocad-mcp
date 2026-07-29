use serde::{Deserialize, Serialize};

use super::{LayerLineWeight, LayerRecord, LayerSelector};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerProperties {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color_index: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_weight: Option<LayerLineWeight>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frozen: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub off: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_plottable: Option<bool>,
}

impl LayerProperties {
    pub fn is_empty(&self) -> bool {
        self.color_index.is_none()
            && self.line_type.is_none()
            && self.line_weight.is_none()
            && self.frozen.is_none()
            && self.locked.is_none()
            && self.off.is_none()
            && self.is_plottable.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateLayer {
    pub name: String,
    #[serde(default)]
    pub properties: LayerProperties,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateLayer {
    pub selector: LayerSelector,
    pub properties: LayerProperties,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameLayer {
    pub selector: LayerSelector,
    pub new_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteLayer {
    pub selector: LayerSelector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletedLayer {
    pub handle: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum LayerMutation {
    Created { layer: LayerRecord },
    Updated { layer: LayerRecord },
    Renamed { layer: LayerRecord },
    Deleted { layer: DeletedLayer },
}
