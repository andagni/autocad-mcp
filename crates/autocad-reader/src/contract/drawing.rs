use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingPoint2 {
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingPoint3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingBounds2 {
    pub min: DrawingPoint2,
    pub max: DrawingPoint2,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingBounds3 {
    pub min: DrawingPoint3,
    pub max: DrawingPoint3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrawingSavedValueSource {
    SavedHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrawingPointUnavailableReason {
    NonFinite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrawingBoundsUnavailableReason {
    NonFinite,
    InvertedBounds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrawingExtentsUnavailableReason {
    NonFinite,
    InvertedBounds,
    EmptySpaceSentinel,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DrawingPoint3Availability {
    Available {
        point: DrawingPoint3,
    },
    Unavailable {
        reason: DrawingPointUnavailableReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DrawingBounds2Availability {
    Available {
        bounds: DrawingBounds2,
    },
    Unavailable {
        reason: DrawingBoundsUnavailableReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DrawingBounds3Availability {
    Available {
        bounds: DrawingBounds3,
    },
    Unavailable {
        reason: DrawingExtentsUnavailableReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrawingInsertionUnit {
    Unitless,
    Inches,
    Feet,
    Miles,
    Millimeters,
    Centimeters,
    Meters,
    Kilometers,
    Microinches,
    Mils,
    Yards,
    Angstroms,
    Nanometers,
    Microns,
    Decimeters,
    Decameters,
    Hectometers,
    Gigameters,
    AstronomicalUnits,
    LightYears,
    Parsecs,
    UsSurveyFeet,
    UsSurveyInches,
    UsSurveyYards,
    UsSurveyMiles,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrawingMeasurementSystem {
    English,
    Metric,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingUnits {
    /// Raw INSUNITS value is retained even when it is newer than this API.
    pub insertion_unit_code: i16,
    pub insertion_unit: Option<DrawingInsertionUnit>,
    /// Raw MEASUREMENT value is retained even when it is neither 0 nor 1.
    pub measurement_system_code: i16,
    pub measurement_system: DrawingMeasurementSystem,
    pub linear_format_code: i16,
    pub linear_precision: i16,
    pub angular_format_code: i16,
    pub angular_precision: i16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingMetadata {
    pub code_page: String,
    pub last_saved_by: Option<String>,
    pub project_name: Option<String>,
    pub fingerprint_guid: Option<String>,
    pub version_guid: Option<String>,
    pub hyperlink_base: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingSpaceGeometry {
    /// All values in this record are persisted header state, not geometry-
    /// derived measurements.
    pub source: DrawingSavedValueSource,
    pub insertion_base: DrawingPoint3Availability,
    pub extents: DrawingBounds3Availability,
    pub limits: DrawingBounds2Availability,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingGeometry {
    pub model_space: DrawingSpaceGeometry,
    /// Header-level paper-space geometry. Per-layout geometry belongs on the
    /// layout read surface.
    pub paper_space: DrawingSpaceGeometry,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingUcsBasis {
    pub origin: DrawingPoint3,
    pub x_axis: DrawingPoint3,
    pub y_axis: DrawingPoint3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrawingUcsUnavailableReason {
    NonFinite,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DrawingUcsAvailability {
    Available { basis: DrawingUcsBasis },
    Unavailable { reason: DrawingUcsUnavailableReason },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingSpaceCurrentUcs {
    /// The current UCS fields are persisted header state. No CRS or derived
    /// transformation is inferred from them.
    pub source: DrawingSavedValueSource,
    /// An empty persisted name denotes an unnamed UCS.
    pub name: Option<String>,
    pub basis: DrawingUcsAvailability,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingCurrentUcs {
    pub model_space: DrawingSpaceCurrentUcs,
    pub paper_space: DrawingSpaceCurrentUcs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingSpaceRecord {
    /// Canonical uppercase hexadecimal handle when the source has a valid one.
    pub handle: Option<String>,
    pub name: String,
    pub entity_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingSpaces {
    pub model_space: Option<DrawingSpaceRecord>,
    pub paper_spaces: Vec<DrawingSpaceRecord>,
    pub block_definition_entity_count: usize,
    /// Child entities owned by another entity, such as ATTRIB owned by INSERT.
    pub nested_entity_count: usize,
    /// Entities whose non-null owner is not represented by an entity or block
    /// record, plus entities with no owner.
    pub unresolved_owner_entity_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingCounts {
    pub entities: usize,
    pub visible_entities: usize,
    pub unknown_entities: usize,
    pub layers: usize,
    pub linetypes: usize,
    pub text_styles: usize,
    pub dimension_styles: usize,
    pub named_views: usize,
    pub named_ucs: usize,
    /// Ordinary and anonymous block definitions, excluding layout blocks and
    /// xref block records.
    pub block_definitions: usize,
    pub xref_attachments: usize,
    pub layouts: usize,
    pub objects: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingCurrentSettings {
    pub layer: String,
    pub linetype: String,
    pub text_style: String,
    pub dimension_style: String,
    pub table_style: String,
    pub multileader_style: String,
    pub show_model_space: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrawingSummary {
    /// DXF/DWG format code such as `AC1032`.
    pub version: String,
    pub maintenance_version: u8,
    pub units: DrawingUnits,
    pub metadata: DrawingMetadata,
    pub geometry: DrawingGeometry,
    pub current_ucs: DrawingCurrentUcs,
    pub spaces: DrawingSpaces,
    pub counts: DrawingCounts,
    pub current_settings: DrawingCurrentSettings,
}
