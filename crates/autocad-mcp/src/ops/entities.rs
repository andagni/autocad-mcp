//! Compatibility paths for the migrated entity read family.
//!
//! Contract types are canonical beneath `autocad_reader::contract`; entity
//! traversal and projection live entirely behind `DrawingReadSession`.

pub use crate::autocad_reader::contract::{
    EntityBooleanAvailability, EntityBooleanUnavailableReason, EntityBounds3,
    EntityBoundsAvailability, EntityBoundsUnavailableReason, EntityColor, EntityDetail,
    EntityDetailUnsupportedReason, EntityHelixConstraint, EntityHelixHandedness, EntityLineWeight,
    EntityLinetype, EntityListOptions, EntityListResult, EntityNumberAvailability,
    EntityNumberUnavailableReason, EntityPoint3, EntityRecord, EntityScale3,
    EntityStringAvailability, EntityStringUnavailableReason, EntityTransparency,
    PolylineRepresentation, DEFAULT_ENTITY_LIST_LIMIT, MAX_ENTITY_LIST_LIMIT,
};
pub use crate::autocad_reader::EntityReadError;
