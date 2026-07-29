//! Compatibility paths for the migrated drawing-summary read family.
//!
//! Contract types are canonical beneath `autocad_reader::contract`; drawing
//! traversal and projection live entirely behind `DrawingReadSession`.

pub use crate::autocad_reader::contract::{
    DrawingBounds2, DrawingBounds2Availability, DrawingBounds3, DrawingBounds3Availability,
    DrawingBoundsUnavailableReason, DrawingCounts, DrawingCurrentSettings, DrawingCurrentUcs,
    DrawingExtentsUnavailableReason, DrawingGeometry, DrawingInsertionUnit,
    DrawingMeasurementSystem, DrawingMetadata, DrawingPoint2, DrawingPoint3,
    DrawingPoint3Availability, DrawingPointUnavailableReason, DrawingSavedValueSource,
    DrawingSpaceCurrentUcs, DrawingSpaceGeometry, DrawingSpaceRecord, DrawingSpaces,
    DrawingSummary, DrawingUcsAvailability, DrawingUcsBasis, DrawingUcsUnavailableReason,
    DrawingUnits,
};
pub use crate::autocad_reader::DrawingReadError;
