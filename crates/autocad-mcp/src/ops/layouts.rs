//! Compatibility exports for the reader-owned layout family.

pub use crate::autocad_reader::contract::{
    Bounds2, Bounds3, EmbeddedPlotSettingsRecord, LayoutInfo, LayoutRecord, LayoutSelector,
    LayoutUcsRecord, LayoutViewportRecord, LayoutViewportRenderMode, LayoutViewportResourceType,
    LayoutViewportSelector, PaperMargins, PlotArea, PlotFlagsRecord, PlotPaperUnits, PlotRotation,
    PlotScaleType, PlotSettingRecord, PlotSettingSelector, PlotShadeMode, PlotShadeResolution,
    PlotWindowRecord, Point2, Point3,
};
pub use crate::autocad_reader::LayoutReadError;
