use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{DirectOwnerContext, DynamicBlockLink};

pub const DEFAULT_ENTITY_LIST_LIMIT: usize = 200;
pub const MAX_ENTITY_LIST_LIMIT: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityPoint3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityScale3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityBounds3 {
    pub min: EntityPoint3,
    pub max: EntityPoint3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityBoundsUnavailableReason {
    UnsupportedEntityType,
    UnreliableModelProjection,
    UnboundedGeometry,
    InsufficientModeledGeometry,
    NonFiniteProjection,
    InvertedProjection,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntityBoundsAvailability {
    Available {
        bounds: EntityBounds3,
    },
    Unavailable {
        reason: EntityBoundsUnavailableReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityStringUnavailableReason {
    ParserDefaulted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntityStringAvailability {
    Available {
        value: String,
    },
    Unavailable {
        reason: EntityStringUnavailableReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityBooleanUnavailableReason {
    ParserDiscarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntityBooleanAvailability {
    Available {
        value: bool,
    },
    Unavailable {
        reason: EntityBooleanUnavailableReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityNumberUnavailableReason {
    ParserDefaulted,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntityNumberAvailability {
    Available {
        value: f64,
    },
    Unavailable {
        reason: EntityNumberUnavailableReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntityColor {
    ByLayer,
    ByBlock,
    Indexed { index: u8 },
    TrueColor { red: u8, green: u8, blue: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntityLinetype {
    ByLayer,
    ByBlock,
    Named { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntityLineWeight {
    ByLayer,
    ByBlock,
    Default,
    Value {
        hundredths_mm: i16,
    },
    /// Preserves values outside acadrust's documented 0..=211 explicit range.
    Raw {
        raw_value: i16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityTransparency {
    /// The only transparency value retained by acadrust. Alpha 0 is opaque,
    /// but the model cannot distinguish explicit opaque from ByLayer.
    pub alpha: u8,
    /// Normalized transparency fraction in the inclusive range 0.0..=1.0.
    pub fraction: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolylineRepresentation {
    Lightweight2d,
    Heavyweight2d,
    Legacy3d,
    Polyline3d,
    PolyfaceMesh,
    PolygonMesh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityHelixHandedness {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityHelixConstraint {
    TurnHeight,
    Turns,
    Height,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityDetailUnsupportedReason {
    NotModeledByGenericSurface,
}

/// Bounded entity-specific information.
///
/// Variants with potentially large child collections expose counts only.
/// `Unsupported` preserves the common entity fields while explicitly stating
/// why this generic surface does not publish type-specific detail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntityDetail {
    Point {
        location: EntityPoint3,
    },
    Line {
        start: EntityPoint3,
        end: EntityPoint3,
    },
    Circle {
        center: EntityPoint3,
        radius: f64,
    },
    Arc {
        center: EntityPoint3,
        radius: f64,
        start_angle_radians: f64,
        end_angle_radians: f64,
    },
    Ellipse {
        center: EntityPoint3,
        major_axis: EntityPoint3,
        minor_axis_ratio: f64,
        start_parameter: f64,
        end_parameter: f64,
    },
    Helix {
        axis_base_point: EntityPoint3,
        start_point: EntityPoint3,
        axis_vector: EntityPoint3,
        radius: f64,
        turns: f64,
        turn_height: f64,
        handedness: EntityHelixHandedness,
        constraint: EntityHelixConstraint,
    },
    Polyline {
        representation: PolylineRepresentation,
        vertex_count: usize,
        face_count: Option<usize>,
        is_closed: bool,
        elevation: Option<f64>,
    },
    Text {
        value: String,
        insertion_point: EntityPoint3,
        height: f64,
        rotation_radians: f64,
        style: String,
    },
    Mtext {
        value: String,
        insertion_point: EntityPoint3,
        height: f64,
        rectangle_width: f64,
        rotation_radians: f64,
        style: String,
    },
    Insert {
        block_name: String,
        insertion_point: EntityPoint3,
        scale: EntityScale3,
        rotation_radians: f64,
        column_count: u16,
        row_count: u16,
        attribute_count: usize,
        dynamic_block: DynamicBlockLink,
    },
    Attribute {
        tag: String,
        value: String,
        insertion_point: EntityPoint3,
        height: f64,
        rotation_radians: f64,
        style: EntityStringAvailability,
    },
    AttributeDefinition {
        tag: String,
        prompt: EntityStringAvailability,
        default_value: String,
        insertion_point: EntityPoint3,
        height: f64,
        rotation_radians: f64,
        style: EntityStringAvailability,
    },
    Hatch {
        pattern_name: String,
        is_solid: bool,
        is_associative: bool,
        boundary_path_count: usize,
        seed_point_count: usize,
    },
    Dimension {
        subtype: String,
        measurement: f64,
        text: String,
        style: String,
        definition_point: EntityPoint3,
    },
    Leader {
        vertex_count: usize,
        arrow_enabled: bool,
        dimension_style: String,
        annotation_handle: Option<String>,
    },
    Viewport {
        id: i16,
        center: EntityPoint3,
        width: f64,
        height: f64,
        is_on: EntityBooleanAvailability,
        is_locked: bool,
        custom_scale: EntityNumberAvailability,
    },
    Unknown {
        dwg_type_code: Option<i16>,
    },
    Unsupported {
        reason: EntityDetailUnsupportedReason,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityRecord {
    /// Canonical, uppercase hexadecimal handle without a `0x` prefix.
    pub handle: String,
    /// Canonical DXF entity name. Unknown/proxy entities retain their parsed
    /// DXF name where one is available.
    pub entity_type: String,
    pub owner_handle: Option<String>,
    pub owner_context: Option<DirectOwnerContext>,
    pub layer: String,
    pub visible: bool,
    pub color: EntityColor,
    pub linetype: EntityLinetype,
    pub linetype_scale: f64,
    pub line_weight: EntityLineWeight,
    pub transparency: EntityTransparency,
    /// Bounds modeled by `Entity::bounding_box`, or an explicit reason that a
    /// reliable finite projection is unavailable.
    pub bounds: EntityBoundsAvailability,
    pub detail: EntityDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EntityListOptions {
    /// Exact entity-type filter. Matching is case-insensitive, with no prefix
    /// or substring matching.
    pub entity_types: Option<Vec<String>>,
    /// Exact layer-name filter using CAD's case-insensitive name semantics.
    pub layer: Option<String>,
    /// Exact hexadecimal owner handle, with an optional `0x` prefix.
    pub owner_handle: Option<String>,
    /// Invisible entities are excluded unless this is true.
    pub include_invisible: bool,
    pub offset: usize,
    pub limit: usize,
}

impl Default for EntityListOptions {
    fn default() -> Self {
        Self {
            entity_types: None,
            layer: None,
            owner_handle: None,
            include_invisible: false,
            offset: 0,
            limit: DEFAULT_ENTITY_LIST_LIMIT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntitySelector {
    pub handle: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityListResult {
    pub items: Vec<EntityRecord>,
    /// Number of entities after all filters and before pagination.
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
}
