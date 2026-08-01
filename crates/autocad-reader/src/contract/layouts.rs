use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutInfo {
    pub name: String,
    pub is_model: bool,
    pub tab_order: i16,
    pub paper_width_mm: f64,
    pub paper_height_mm: f64,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutSelector {
    pub handle: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutViewportSelector {
    pub handle: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Point2 {
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Point3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bounds2 {
    pub min: Point2,
    pub max: Point2,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bounds3 {
    pub min: Point3,
    pub max: Point3,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutUcsRecord {
    pub origin: Point3,
    pub x_axis: Point3,
    pub y_axis: Point3,
    pub orthographic_type: i16,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedPlotSettingsRecord {
    pub paper_width_mm: f64,
    pub paper_height_mm: f64,
    pub rotation_code: i16,
    pub rotation_degrees: Option<i16>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutRecord {
    pub handle: String,
    pub name: String,
    pub is_model: bool,
    pub tab_order: i16,
    pub block_record_handle: Option<String>,
    pub last_active_viewport_handle: Option<String>,
    pub limits: Bounds2,
    pub extents: Option<Bounds3>,
    pub insertion_base: Point3,
    pub elevation: f64,
    pub ucs: LayoutUcsRecord,
    pub plot_settings: EmbeddedPlotSettingsRecord,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutViewportResourceType {
    PaperSpaceEntity,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutViewportRenderMode {
    Wireframe2d,
    Wireframe3d,
    HiddenLine,
    FlatShaded,
    GouraudShaded,
    FlatShadedWithEdges,
    GouraudShadedWithEdges,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutViewportRecord {
    pub resource_type: LayoutViewportResourceType,
    pub handle: String,
    pub layout_handle: String,
    pub layout_name: String,
    pub owner_block_record_handle: String,
    pub is_last_active_for_layout: bool,
    pub viewport_id: i16,
    pub layer: String,
    pub center: Point3,
    pub width: f64,
    pub height: f64,
    pub is_on: Option<bool>,
    pub locked: bool,
    pub perspective: bool,
    pub front_clipping: bool,
    pub back_clipping: bool,
    pub view_center: Point3,
    pub view_target: Point3,
    pub view_direction: Point3,
    pub view_height: f64,
    pub twist_angle_radians: f64,
    pub lens_length_mm: f64,
    pub model_to_paper_scale: Option<f64>,
    pub custom_scale: Option<f64>,
    pub render_mode: LayoutViewportRenderMode,
    pub frozen_layer_handles: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlotSettingSelector {
    pub handle: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlotPaperUnits {
    Inches,
    Millimeters,
    Pixels,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlotRotation {
    None,
    Degrees90,
    Degrees180,
    Degrees270,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlotArea {
    LastScreenDisplay,
    Extents,
    Limits,
    View,
    Window,
    Layout,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlotScaleType {
    ScaleToFit,
    CustomScale,
    OneToOne,
    OneToTwo,
    OneToFour,
    OneToEight,
    OneToTen,
    OneToSixteen,
    OneToTwenty,
    OneToThirty,
    OneToForty,
    OneToFifty,
    OneToHundred,
    TwoToOne,
    FourToOne,
    EightToOne,
    TenToOne,
    HundredToOne,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlotShadeMode {
    AsDisplayed,
    Wireframe,
    Hidden,
    Rendered,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlotShadeResolution {
    Draft,
    Preview,
    Normal,
    Presentation,
    Maximum,
    Custom,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaperMargins {
    pub left: f64,
    pub bottom: f64,
    pub right: f64,
    pub top: f64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlotWindowRecord {
    pub lower_left: Point2,
    pub upper_right: Point2,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlotFlagsRecord {
    pub plot_viewport_borders: bool,
    pub show_plot_styles: bool,
    pub plot_centered: bool,
    pub plot_hidden: bool,
    pub use_standard_scale: bool,
    pub plot_plot_styles: bool,
    pub scale_lineweights: bool,
    pub print_lineweights: bool,
    pub draw_viewports_first: bool,
    pub model_type: bool,
    pub update_paper: bool,
    pub zoom_to_paper_on_update: bool,
    pub initializing: bool,
    pub previous_plot_initialized: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlotSettingRecord {
    pub handle: String,
    pub owner_handle: Option<String>,
    pub name: String,
    pub printer_name: String,
    pub paper_size: String,
    pub plot_view_name: String,
    pub style_sheet: String,
    pub paper_width: f64,
    pub paper_height: f64,
    pub margins: PaperMargins,
    pub origin: Point2,
    pub window: PlotWindowRecord,
    pub scale_numerator: f64,
    pub scale_denominator: f64,
    pub scale_factor: f64,
    pub paper_units: PlotPaperUnits,
    pub rotation: PlotRotation,
    pub plot_area: PlotArea,
    pub scale_type: PlotScaleType,
    pub shade_mode: PlotShadeMode,
    pub shade_resolution: PlotShadeResolution,
    pub shade_dpi: i16,
    pub flags: PlotFlagsRecord,
}
