//! Backend-neutral semantic compiler for portable 2D plotting.
//!
//! This module consumes immutable in-memory snapshots and explicitly supplied
//! resources. It owns checked CAD semantics, bounded display values, PDF
//! encoding, and a path-free worker protocol without exposing the selected
//! drawing backend or resolving drawing-owned host paths.

mod adapter;
mod delivery;
mod diagnostics;
mod display_list;
mod geometry;
mod krilla;
mod resources;
mod style;
#[cfg(test)]
mod test_font;
mod worker;

pub use adapter::{
    compile_portable_scene, compile_portable_scene_with_resources, inspect_portable_source,
    BackendLimitation, PortablePlotLimits, PortablePlotReceipt, PortableResourceReceipt,
    PortableSceneCompilation, PortableSourceInventory, SelectedLayoutInventory,
    SourceInventoryCounts,
};
pub use delivery::{
    deliver_portable_pdf, PortableDeliveryFidelity, PortableOutputPolicy,
    PortablePlotDeliveryOptions, PortablePlotDeliveryReceipt,
};
pub use diagnostics::{
    DiagnosticLedger, DispositionCounts, FidelityDisposition, FidelitySummary, PlotCompleteness,
    PlotDiagnostic, SourceHandle, ToleranceUse,
};
pub use display_list::{
    ClipPath, DashPattern, DisplayList, DisplayListLimits, DisplayListUsage, DisplayNode, Fill,
    FillRule, FontId, FontResource, GlyphRun, GroupId, GroupInstance, ImageColorSpace, ImageId,
    ImageNode, ImageResource, InlineGroup, LineCap, LineJoin, PageGeometry, PathCommand, PathNode,
    PositionedGlyph, ResourceDigest, ReusableGroup, SceneColor, ScenePath, Stroke,
    PDF_1_4_MAX_PAGE_POINTS,
};
pub use geometry::{
    Affine2, Affine3, BlockInsertTransform3, OcsFrame, Point2, Point3, Vector2, Vector3,
};
pub use krilla::{encode_portable_pdf, PortablePdf};
pub use resources::{
    PlotStyleResource, PortableResourceBundle, ShxAdmissionOptions, ShxCompositeFontResource,
    ShxStrokeFontResource, XrefResource,
};
pub use style::{effective_layer, LayerContext, Property, PropertyContext};
pub use worker::{
    run_portable_worker, run_worker_stdio, PortableWorkerLimits, PortableWorkerOutput,
    PortableWorkerReceipt, PortableWorkerRequest,
};

use std::fmt;

/// Stable semantic failure returned before renderer-specific conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortablePlotError {
    code: &'static str,
    message: String,
}

impl PortablePlotError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Stable machine-readable failure code.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// Human-readable diagnostic without source drawing content.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PortablePlotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "code={} {}", self.code, self.message)
    }
}

impl std::error::Error for PortablePlotError {}

pub(crate) fn non_finite_input(name: &str) -> PortablePlotError {
    PortablePlotError::new(
        "non_finite_input",
        format!("{name} must contain only finite values"),
    )
}

pub(crate) fn non_finite_arithmetic(operation: &str) -> PortablePlotError {
    PortablePlotError::new(
        "non_finite_arithmetic",
        format!("{operation} produced a non-finite result"),
    )
}
