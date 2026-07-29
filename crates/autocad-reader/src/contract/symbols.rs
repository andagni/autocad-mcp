use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolSelector {
    pub handle: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinetypeElementKind {
    Dash,
    Space,
    Dot,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinetypeElementRecord {
    pub kind: LinetypeElementKind,
    pub signed_length: f64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinetypeRecord {
    pub handle: String,
    pub name: String,
    pub description: String,
    pub pattern_length: f64,
    pub alignment: char,
    pub elements: Vec<LinetypeElementRecord>,
    pub is_continuous: bool,
    pub is_standard: bool,
    pub is_current: bool,
    pub xref_dependent: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TextStyleRecord {
    pub handle: String,
    pub name: String,
    pub fixed_height: f64,
    pub width_factor: f64,
    pub oblique_angle_radians: f64,
    pub last_height: f64,
    pub font_file: String,
    pub big_font_file: String,
    pub true_type_font: String,
    pub backward: bool,
    pub upside_down: bool,
    pub annotative: bool,
    pub xref_dependent: bool,
    pub is_standard: bool,
    pub is_current: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionStyleRecord {
    pub handle: String,
    pub name: String,
    pub is_standard: bool,
    pub is_current: bool,
    pub annotative: bool,
    pub overall_scale: f64,
    pub arrow_size: f64,
    pub center_mark_size: f64,
    pub tick_size: f64,
    pub arrow_block_handle: Option<String>,
    pub first_arrow_block_handle: Option<String>,
    pub second_arrow_block_handle: Option<String>,
    pub leader_arrow_block_handle: Option<String>,
    pub dimension_line_extension: f64,
    pub dimension_line_increment: f64,
    pub dimension_line_gap: f64,
    pub suppress_first_dimension_line: bool,
    pub suppress_second_dimension_line: bool,
    pub extension_line_extension: f64,
    pub extension_line_offset: f64,
    pub suppress_first_extension_line: bool,
    pub suppress_second_extension_line: bool,
    pub text_height: f64,
    pub text_style_handle: Option<String>,
    pub text_style_name: String,
    pub text_horizontal_alignment: i16,
    pub text_vertical_alignment: i16,
    pub linear_scale_factor: f64,
    pub linear_unit_format: i16,
    pub linear_decimal_places: i16,
    pub linear_rounding: f64,
    pub decimal_separator_code: i16,
    pub decimal_separator: Option<String>,
    pub angular_unit_format: i16,
    pub angular_decimal_places: i16,
    pub alternate_units_enabled: bool,
    pub tolerances_enabled: bool,
    pub limits_enabled: bool,
    pub postfix: String,
    pub dimension_linetype_handle: Option<String>,
    pub first_extension_linetype_handle: Option<String>,
    pub second_extension_linetype_handle: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolPoint3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedViewRecord {
    pub handle: String,
    pub name: String,
    pub center: SymbolPoint3,
    pub height: f64,
    pub width: f64,
    pub direction: SymbolPoint3,
    pub target: SymbolPoint3,
    pub lens_length_mm: f64,
    pub front_clip: f64,
    pub back_clip: f64,
    pub twist_angle_radians: f64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedUcsRecord {
    pub handle: String,
    pub name: String,
    pub origin: SymbolPoint3,
    pub x_axis: SymbolPoint3,
    pub y_axis: SymbolPoint3,
    pub z_axis: SymbolPoint3,
}
