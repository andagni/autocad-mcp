use std::{cmp::Ordering, collections::BTreeMap};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn deserialize_optional_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceType {
    Attachment,
    Overlay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoadState {
    Loaded,
    Unloaded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefPathMode {
    Absolute,
    Relative,
    FilenameOnly,
    Url,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefOwnerType {
    ModelSpace,
    PaperSpace,
    BlockDefinition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefVisibility {
    Visible,
    Hidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefPlacementKind {
    Single,
    RectangularArray,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InsertionUnit {
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
    Dekameters,
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
pub enum XrefUnitBasis {
    Drawing,
    Request,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefPoint3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefScale3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefVector3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

pub type XrefPoint = XrefPoint3;
pub type XrefScale = XrefScale3;
pub type XrefNormal = XrefVector3;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum XrefPointAvailability {
    Available { point: XrefPoint3 },
    Unavailable,
}

impl<'de> Deserialize<'de> for XrefPointAvailability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum AvailableState {
            Available,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum UnavailableState {
            Unavailable,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Available {
            #[serde(rename = "state")]
            _state: AvailableState,
            point: XrefPoint3,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unavailable {
            #[serde(rename = "state")]
            _state: UnavailableState,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Available(Available),
            Unavailable(Unavailable),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Available(value) => Ok(Self::Available { point: value.point }),
            Repr::Unavailable(_) => Ok(Self::Unavailable),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefUnitValue {
    pub value: InsertionUnit,
    pub basis: XrefUnitBasis,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum XrefUnitScaling {
    Available {
        source_units: XrefUnitValue,
        host_units: XrefUnitValue,
        factor: f64,
        effective_scale: XrefScale3,
    },
    Unavailable,
}

impl<'de> Deserialize<'de> for XrefUnitScaling {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum AvailableState {
            Available,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum UnavailableState {
            Unavailable,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Available {
            #[serde(rename = "state")]
            _state: AvailableState,
            source_units: XrefUnitValue,
            host_units: XrefUnitValue,
            factor: f64,
            effective_scale: XrefScale3,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unavailable {
            #[serde(rename = "state")]
            _state: UnavailableState,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Available(Available),
            Unavailable(Unavailable),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Available(value) => Ok(Self::Available {
                source_units: value.source_units,
                host_units: value.host_units,
                factor: value.factor,
                effective_scale: value.effective_scale,
            }),
            Repr::Unavailable(_) => Ok(Self::Unavailable),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PersistedInsertionUnits {
    Known { value: InsertionUnit },
    Unitless,
    UnknownCode { code: i64 },
    Unobservable,
}

impl<'de> Deserialize<'de> for PersistedInsertionUnits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum KnownState {
            Known,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum UnitlessState {
            Unitless,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum UnknownCodeState {
            UnknownCode,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum UnobservableState {
            Unobservable,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Known {
            #[serde(rename = "state")]
            _state: KnownState,
            value: InsertionUnit,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unitless {
            #[serde(rename = "state")]
            _state: UnitlessState,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct UnknownCode {
            #[serde(rename = "state")]
            _state: UnknownCodeState,
            code: i64,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unobservable {
            #[serde(rename = "state")]
            _state: UnobservableState,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Known(Known),
            Unitless(Unitless),
            UnknownCode(UnknownCode),
            Unobservable(Unobservable),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Known(value) => Ok(Self::Known { value: value.value }),
            Repr::Unitless(_) => Ok(Self::Unitless),
            Repr::UnknownCode(value) => Ok(Self::UnknownCode { code: value.code }),
            Repr::Unobservable(_) => Ok(Self::Unobservable),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefRectangularArray {
    #[schemars(range(min = 1, max = 65_535))]
    pub rows: u32,
    #[schemars(range(min = 1, max = 65_535))]
    pub columns: u32,
    pub row_spacing: f64,
    pub column_spacing: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefAttachmentRecord {
    pub handle: String,
    pub name: String,
    pub saved_path: String,
    pub path_mode: XrefPathMode,
    pub reference_type: ReferenceType,
    pub load_state: LoadState,
    pub instance_count: u64,
    pub definition_base_point: XrefPointAvailability,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefInstanceRecord {
    pub handle: String,
    pub attachment_handle: String,
    pub attachment_name: String,
    pub owner_handle: String,
    pub owner_type: XrefOwnerType,
    pub owner_name: String,
    pub layer_handle: String,
    pub layer_name: String,
    pub insertion_point: XrefPoint3,
    pub scale: XrefScale3,
    pub rotation_degrees: f64,
    pub normal: XrefVector3,
    pub visibility: XrefVisibility,
    pub placement_kind: XrefPlacementKind,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schemars(required)]
    pub array: Option<XrefRectangularArray>,
    pub unit_scaling: XrefUnitScaling,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefSelector {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub handle: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub name: Option<String>,
}

impl XrefSelector {
    pub fn canonicalized(mut self) -> Result<Self, XrefError> {
        if let Some(value) = &mut self.handle {
            *value = canonical_input_handle(value)?;
        }
        Ok(self)
    }
}

pub type XrefAttachmentSelector = XrefSelector;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefInstanceSelector {
    pub handle: String,
}

/// Transport-independent filters for a same-snapshot instance query.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XrefInstanceListOptions {
    pub attachment_handle: Option<String>,
    pub attachment_name: Option<String>,
    pub owner_handle: Option<String>,
    pub owner_type: Option<XrefOwnerType>,
    pub owner_name: Option<String>,
    pub layer_handle: Option<String>,
    pub layer_name: Option<String>,
    pub visibility: Option<XrefVisibility>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum XrefEvidenceValue<T> {
    Proven(T),
    Unavailable(String),
    Unsupported(String),
    Contradictory(String),
}

#[allow(dead_code)]
impl<T> XrefEvidenceValue<T> {
    pub fn proven(value: T) -> Self {
        Self::Proven(value)
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable(reason.into())
    }

    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self::Unsupported(reason.into())
    }

    pub fn contradictory(reason: impl Into<String>) -> Self {
        Self::Contradictory(reason.into())
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XrefMembershipEvidence {
    NotXref,
    Direct(ReferenceType),
    External(ReferenceType),
    Unavailable(String),
    Unsupported(String),
    Contradictory(String),
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct XrefPersistedPlacementEvidence {
    pub placement_kind: XrefEvidenceValue<XrefPlacementKind>,
    pub array: XrefEvidenceValue<Option<XrefRectangularArray>>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct XrefPersistedInstanceEvidence {
    pub handle: XrefEvidenceValue<String>,
    pub attachment_handle: XrefEvidenceValue<String>,
    pub attachment_name: XrefEvidenceValue<String>,
    pub owner_handle: XrefEvidenceValue<String>,
    pub owner_type: XrefEvidenceValue<XrefOwnerType>,
    pub owner_name: XrefEvidenceValue<String>,
    pub layer_handle: XrefEvidenceValue<String>,
    pub layer_name: XrefEvidenceValue<String>,
    pub insertion_point: XrefEvidenceValue<XrefPoint3>,
    pub scale: XrefEvidenceValue<XrefScale3>,
    pub rotation_degrees: XrefEvidenceValue<f64>,
    pub normal: XrefEvidenceValue<XrefVector3>,
    pub visibility: XrefEvidenceValue<XrefVisibility>,
    pub placement: XrefPersistedPlacementEvidence,
    pub unit_scaling: XrefEvidenceValue<XrefUnitScaling>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct XrefDomainEvidence {
    pub handle: XrefEvidenceValue<String>,
    pub name: XrefEvidenceValue<String>,
    pub membership: XrefMembershipEvidence,
    pub saved_path: XrefEvidenceValue<String>,
    pub load_state: XrefEvidenceValue<LoadState>,
    pub definition_base_point: XrefEvidenceValue<XrefPoint3>,
    pub insertion_units: XrefEvidenceValue<PersistedInsertionUnits>,
    pub instances: XrefEvidenceValue<Vec<XrefPersistedInstanceEvidence>>,
}

pub type Fact<T> = XrefEvidenceValue<T>;

#[derive(Debug, Clone, PartialEq)]
pub struct XrefSnapshotEvidence {
    pub attachments: Vec<XrefDomainEvidence>,
    pub owners: Vec<OwnerEvidence>,
    pub layers: Vec<LayerEvidence>,
    pub host_units: Fact<PersistedInsertionUnits>,
    pub block_definitions_complete: bool,
    pub owners_complete: bool,
    pub layers_complete: bool,
    pub block_references_complete: bool,
    pub block_references: BTreeMap<String, Vec<String>>,
    pub instance_clips: BTreeMap<String, XrefPortableClipEvidence>,
    pub saved_visretain: Fact<i16>,
    pub saved_xrefoverride: Fact<i16>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OwnerEvidence {
    pub handle: Fact<String>,
    pub owner_type: Fact<XrefOwnerType>,
    pub name: Fact<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LayerEvidence {
    pub handle: Fact<String>,
    pub name: Fact<String>,
    pub xref_dependent: Fact<bool>,
    pub properties: Fact<XrefPortableLayerProperties>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrefPortableLayerProperties {
    pub off: bool,
    pub frozen: bool,
    pub locked: bool,
    pub is_plottable: bool,
    pub color_index: i16,
    pub line_type: String,
    pub line_weight: i16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefPortableClipEvidence {
    Absent,
    Unproven,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XrefError {
    code: &'static str,
    message: String,
}

impl XrefError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &str {
        self.code
    }
}

impl std::fmt::Display for XrefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "code={} {}", self.code, self.message)
    }
}

impl std::error::Error for XrefError {}

const NORMAL_LENGTH_TOLERANCE: f64 = 1e-12;
const NORMAL_COMPONENT_ZERO_TOLERANCE: f64 = 1e-15;

impl XrefPoint3 {
    pub const ORIGIN: Self = Self {
        x: 0.0,
        y: 0.0,
        z: 0.0,
    };

    pub fn validate(self) -> Result<Self, XrefError> {
        if self.x.is_finite() && self.y.is_finite() && self.z.is_finite() {
            Ok(self)
        } else {
            Err(XrefError::new(
                "invalid_xref_placement",
                "XREF point components must be finite",
            ))
        }
    }
}

impl XrefScale3 {
    pub const IDENTITY: Self = Self {
        x: 1.0,
        y: 1.0,
        z: 1.0,
    };

    pub fn validate(self) -> Result<Self, XrefError> {
        if self.x.is_finite()
            && self.y.is_finite()
            && self.z.is_finite()
            && self.x != 0.0
            && self.y != 0.0
            && self.z != 0.0
        {
            Ok(self)
        } else {
            Err(XrefError::new(
                "invalid_xref_scale",
                "XREF scale components must be finite and non-zero",
            ))
        }
    }
}

impl XrefVector3 {
    pub const WORLD_Z: Self = Self {
        x: 0.0,
        y: 0.0,
        z: 1.0,
    };

    pub fn length(self) -> f64 {
        self.x.hypot(self.y).hypot(self.z)
    }

    pub fn cross(self, rhs: Self) -> Self {
        Self {
            x: self.y * rhs.z - self.z * rhs.y,
            y: self.z * rhs.x - self.x * rhs.z,
            z: self.x * rhs.y - self.y * rhs.x,
        }
    }

    pub fn normalized(self) -> Self {
        let length = self.length();
        Self {
            x: self.x / length,
            y: self.y / length,
            z: self.z / length,
        }
    }

    pub fn zero_tiny_components(self) -> Self {
        fn zero_tiny(value: f64) -> f64 {
            if value.abs() < NORMAL_COMPONENT_ZERO_TOLERANCE {
                0.0
            } else {
                value
            }
        }

        Self {
            x: zero_tiny(self.x),
            y: zero_tiny(self.y),
            z: zero_tiny(self.z),
        }
    }

    pub fn canonical_normal(self) -> Result<Self, XrefError> {
        let length = self.length();
        if !self.x.is_finite()
            || !self.y.is_finite()
            || !self.z.is_finite()
            || !length.is_finite()
            || length == 0.0
            || (length - 1.0).abs() > NORMAL_LENGTH_TOLERANCE
        {
            return Err(XrefError::new(
                "invalid_xref_normal",
                "XREF normal must be a finite unit vector",
            ));
        }

        Ok(self.normalized().zero_tiny_components())
    }
}

impl XrefRectangularArray {
    pub fn validate(self) -> Result<Self, XrefError> {
        if !(1..=65_535).contains(&self.rows)
            || !(1..=65_535).contains(&self.columns)
            || !self.row_spacing.is_finite()
            || !self.column_spacing.is_finite()
        {
            return Err(XrefError::new(
                "invalid_xref_placement",
                "XREF array counts must be in 1..=65535 and spacings must be finite",
            ));
        }
        Ok(self)
    }

    pub fn cell_count(self) -> Result<u64, XrefError> {
        let validated = self.validate()?;
        Ok(u64::from(validated.rows) * u64::from(validated.columns))
    }
}

impl XrefPointAvailability {
    pub fn validate(self) -> Result<Self, XrefError> {
        match self {
            Self::Available { point } => point.validate().map(|point| Self::Available { point }),
            Self::Unavailable => Ok(Self::Unavailable),
        }
    }
}

impl XrefUnitScaling {
    pub fn validate(self) -> Result<Self, XrefError> {
        match self {
            Self::Available {
                source_units,
                host_units,
                factor,
                effective_scale,
            } => {
                if !factor.is_finite() || factor <= 0.0 {
                    return Err(XrefError::new(
                        "unsupported_xref_data",
                        "available XREF unit factor must be finite and positive",
                    ));
                }
                effective_scale.validate().map_err(|_| {
                    XrefError::new(
                        "unsupported_xref_data",
                        "available XREF effective scale must be finite and non-zero",
                    )
                })?;
                Ok(Self::Available {
                    source_units,
                    host_units,
                    factor,
                    effective_scale,
                })
            }
            Self::Unavailable => Ok(Self::Unavailable),
        }
    }

    pub fn validate_for_explicit_scale(
        self,
        explicit_scale: XrefScale3,
    ) -> Result<Self, XrefError> {
        let validated = self.validate()?;
        let Self::Available {
            factor,
            effective_scale,
            ..
        } = validated
        else {
            return Ok(validated);
        };

        fn product_matches(actual: f64, explicit: f64, factor: f64) -> bool {
            let expected = explicit * factor;
            expected.is_finite()
                && (actual - expected).abs() <= 1e-12 * actual.abs().max(expected.abs()).max(1.0)
        }

        if !product_matches(effective_scale.x, explicit_scale.x, factor)
            || !product_matches(effective_scale.y, explicit_scale.y, factor)
            || !product_matches(effective_scale.z, explicit_scale.z, factor)
        {
            return Err(XrefError::new(
                "unsupported_xref_data",
                "available XREF effective scale does not equal explicit scale times unit factor",
            ));
        }
        Ok(validated)
    }
}

impl PersistedInsertionUnits {
    pub fn validate(self) -> Result<Self, XrefError> {
        if matches!(
            self,
            Self::Known {
                value: InsertionUnit::Unitless
            }
        ) {
            return Err(unsupported_xref_data(
                "known insertion-unit evidence must contain a non-unitless value",
            ));
        }
        Ok(self)
    }
}

pub fn canonical_input_handle(input: &str) -> Result<String, XrefError> {
    let digits = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);

    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(XrefError::new(
            "invalid_handle",
            format!("invalid XREF handle `{input}`"),
        ));
    }

    let canonical = digits.trim_start_matches('0').to_ascii_uppercase();
    Ok(if canonical.is_empty() {
        "0".to_string()
    } else {
        canonical
    })
}

fn compare_canonical_handle_values(left: &str, right: &str) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

pub fn compare_numeric_handles(left: &str, right: &str) -> Result<Ordering, XrefError> {
    let left = canonical_input_handle(left)?;
    let right = canonical_input_handle(right)?;
    Ok(compare_canonical_handle_values(&left, &right))
}

pub fn xref_name_eq(left: &str, right: &str) -> bool {
    left.to_uppercase() == right.to_uppercase()
}

fn unsupported_xref_data(message: impl Into<String>) -> XrefError {
    XrefError::new("unsupported_xref_data", message)
}

fn validate_canonical_persisted_handle(handle: &str, field: &str) -> Result<(), XrefError> {
    let canonical = canonical_input_handle(handle).map_err(|_| {
        unsupported_xref_data(format!("{field} is not a valid persisted XREF handle"))
    })?;
    if canonical == "0" || canonical != handle {
        return Err(unsupported_xref_data(format!(
            "{field} is not a canonical non-null persisted XREF handle"
        )));
    }
    Ok(())
}

fn map_persisted_geometry_error(error: XrefError, field: &str) -> XrefError {
    unsupported_xref_data(format!("persisted XREF {field} is invalid: {error}"))
}

fn normalize_persisted_rotation(rotation_degrees: f64) -> Result<f64, XrefError> {
    if !rotation_degrees.is_finite() {
        return Err(XrefError::new(
            "invalid_xref_placement",
            "XREF rotation must be finite",
        ));
    }

    let normalized = rotation_degrees.rem_euclid(360.0);
    Ok(if normalized == 0.0 { 0.0 } else { normalized })
}

impl XrefAttachmentRecord {
    pub fn validate(&self) -> Result<(), XrefError> {
        validate_canonical_persisted_handle(&self.handle, "attachment handle")?;
        self.definition_base_point
            .validate()
            .map_err(|error| map_persisted_geometry_error(error, "definition base point"))?;
        Ok(())
    }
}

impl XrefInstanceRecord {
    pub fn canonicalized(mut self) -> Result<Self, XrefError> {
        for (handle, field) in [
            (&self.handle, "instance handle"),
            (&self.attachment_handle, "attachment handle"),
            (&self.owner_handle, "owner handle"),
            (&self.layer_handle, "layer handle"),
        ] {
            validate_canonical_persisted_handle(handle, field)?;
        }
        self.insertion_point
            .validate()
            .map_err(|error| map_persisted_geometry_error(error, "insertion point"))?;
        self.scale
            .validate()
            .map_err(|error| map_persisted_geometry_error(error, "scale"))?;
        self.rotation_degrees = normalize_persisted_rotation(self.rotation_degrees)
            .map_err(|error| map_persisted_geometry_error(error, "rotation"))?;
        self.normal = self
            .normal
            .canonical_normal()
            .map_err(|error| map_persisted_geometry_error(error, "normal"))?;
        self.unit_scaling = self
            .unit_scaling
            .validate_for_explicit_scale(self.scale)
            .map_err(|error| map_persisted_geometry_error(error, "unit scaling"))?;

        match (self.placement_kind, self.array) {
            (XrefPlacementKind::Single, None) => {}
            (XrefPlacementKind::RectangularArray, Some(array)) => {
                array
                    .validate()
                    .map_err(|error| map_persisted_geometry_error(error, "array"))?;
            }
            (XrefPlacementKind::Single, Some(_)) | (XrefPlacementKind::RectangularArray, None) => {
                return Err(unsupported_xref_data(
                    "persisted XREF placement_kind and array disagree",
                ));
            }
        }
        Ok(self)
    }
}
