//! Transport-neutral read contracts.
//!
//! Record and selector families move here before the module is extracted into
//! the internal `autocad-reader` workspace package. Legacy `ops::*` paths
//! re-export migrated types while callers transition.

pub mod blocks;
pub mod drawing;
pub mod dynamic_blocks;
pub mod entities;
pub mod format_facts;
pub mod layers;
pub mod layouts;
pub mod owners;
pub mod symbols;
pub mod text;
pub mod title_blocks;
pub mod xrefs;

pub use blocks::{
    BlockAttributeRecord, BlockDefinitionRecord, BlockDefinitionSelector, BlockInfo,
    BlockInsertRecord, BlockInsertSelector, BlockPoint3,
};
pub use drawing::{
    DrawingBounds2, DrawingBounds2Availability, DrawingBounds3, DrawingBounds3Availability,
    DrawingBoundsUnavailableReason, DrawingCounts, DrawingCurrentSettings, DrawingCurrentUcs,
    DrawingExtentsUnavailableReason, DrawingGeometry, DrawingInsertionUnit,
    DrawingMeasurementSystem, DrawingMetadata, DrawingPoint2, DrawingPoint3,
    DrawingPoint3Availability, DrawingPointUnavailableReason, DrawingSavedValueSource,
    DrawingSpaceCurrentUcs, DrawingSpaceGeometry, DrawingSpaceRecord, DrawingSpaces,
    DrawingSummary, DrawingUcsAvailability, DrawingUcsBasis, DrawingUcsUnavailableReason,
    DrawingUnits,
};
pub use dynamic_blocks::{
    DynamicBlockLink, DynamicBlockUnavailableReason, DynamicCurrentState,
    DynamicCurrentStateUnavailableReason, DynamicVisibilityParameter,
    DynamicVisibilityParameterUnavailableReason,
};
pub use entities::{
    EntityBooleanAvailability, EntityBooleanUnavailableReason, EntityBounds3,
    EntityBoundsAvailability, EntityBoundsUnavailableReason, EntityColor, EntityDetail,
    EntityDetailUnsupportedReason, EntityHelixConstraint, EntityHelixHandedness, EntityLineWeight,
    EntityLinetype, EntityListOptions, EntityListResult, EntityNumberAvailability,
    EntityNumberUnavailableReason, EntityPoint3, EntityRecord, EntityScale3, EntitySelector,
    EntityStringAvailability, EntityStringUnavailableReason, EntityTransparency,
    PolylineRepresentation, DEFAULT_ENTITY_LIST_LIMIT, MAX_ENTITY_LIST_LIMIT,
};
pub use format_facts::DrawingFormatFacts;
pub use layers::{LayerLineWeight, LayerRecord, LayerSelector};
pub use layouts::{
    Bounds2, Bounds3, EmbeddedPlotSettingsRecord, LayoutInfo, LayoutRecord, LayoutSelector,
    LayoutUcsRecord, LayoutViewportRecord, LayoutViewportRenderMode, LayoutViewportResourceType,
    LayoutViewportSelector, PaperMargins, PlotArea, PlotFlagsRecord, PlotPaperUnits, PlotRotation,
    PlotScaleType, PlotSettingRecord, PlotSettingSelector, PlotShadeMode, PlotShadeResolution,
    PlotWindowRecord, Point2, Point3,
};
pub use owners::{DirectOwnerContext, DirectOwnerType, DirectOwnerUnavailableReason};
pub use symbols::{
    DimensionStyleRecord, LinetypeElementKind, LinetypeElementRecord, LinetypeRecord,
    NamedUcsRecord, NamedViewRecord, SymbolPoint3, SymbolSelector, TextStyleRecord,
};
pub use text::{
    MTextAttachmentPoint, MTextDrawingDirection, TextEntityKind, TextHorizontalAlignment, TextItem,
    TextListOptions, TextPoint3, TextRecord, TextSelector, TextVerticalAlignment,
};
pub use title_blocks::TitleBlockInfo;
