use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::owners::{DirectOwnerContext, DirectOwnerType};

/// Compatibility record returned by the original `dump_text` surface.
///
/// Keep this shape stable. Rich, handle-bearing reads use [`TextRecord`].
#[derive(Debug, Serialize)]
pub struct TextItem {
    pub text_type: String,
    pub value: String,
    pub layer: String,
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TextPoint3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
pub enum TextEntityKind {
    #[serde(rename = "TEXT")]
    Text,
    #[serde(rename = "MTEXT")]
    MText,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TextHorizontalAlignment {
    Left,
    Center,
    Right,
    Aligned,
    Middle,
    Fit,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TextVerticalAlignment {
    Baseline,
    Bottom,
    Middle,
    Top,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MTextAttachmentPoint {
    TopLeft,
    TopCenter,
    TopRight,
    MiddleLeft,
    MiddleCenter,
    MiddleRight,
    BottomLeft,
    BottomCenter,
    BottomRight,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MTextDrawingDirection {
    LeftToRight,
    TopToBottom,
    ByStyle,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TextRecord {
    /// Canonical, uppercase hexadecimal entity handle.
    pub handle: String,
    pub text_type: TextEntityKind,
    /// Persisted TEXT content or raw MTEXT content, including MTEXT inline
    /// formatting codes where present.
    pub value: String,
    pub layer: String,
    pub owner_handle: Option<String>,
    pub owner_context: Option<DirectOwnerContext>,
    pub insertion_point: TextPoint3,
    pub height: f64,
    pub rotation_radians: f64,
    pub style: String,
    pub normal: TextPoint3,
    pub invisible: bool,
    /// TEXT-only second alignment point.
    pub alignment_point: Option<TextPoint3>,
    /// TEXT-only width factor.
    pub width_factor: Option<f64>,
    /// TEXT-only oblique angle.
    pub oblique_angle_radians: Option<f64>,
    /// TEXT-only horizontal alignment.
    pub horizontal_alignment: Option<TextHorizontalAlignment>,
    /// TEXT-only vertical alignment.
    pub vertical_alignment: Option<TextVerticalAlignment>,
    /// MTEXT-only reference rectangle width.
    pub rectangle_width: Option<f64>,
    /// MTEXT-only reference rectangle height when persisted.
    pub rectangle_height: Option<f64>,
    /// MTEXT-only attachment point.
    pub attachment_point: Option<MTextAttachmentPoint>,
    /// MTEXT-only drawing direction.
    pub drawing_direction: Option<MTextDrawingDirection>,
    /// MTEXT-only line-spacing factor.
    pub line_spacing_factor: Option<f64>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TextListOptions {
    /// Exact text-entity type filter.
    #[schemars(length(min = 1))]
    pub text_types: Option<Vec<TextEntityKind>>,
    /// Exact layer-name filter using CAD's case-insensitive name semantics.
    pub layer: Option<String>,
    /// Exact hexadecimal direct-owner handle.
    pub owner_handle: Option<String>,
    /// Semantic direct-owner type. Must be paired with `owner_name`.
    pub owner_type: Option<DirectOwnerType>,
    /// Semantic direct-owner name. Must be paired with `owner_type`.
    pub owner_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TextSelector {
    pub handle: String,
}
