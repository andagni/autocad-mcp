//! Compatibility paths for migrated dynamic-block contracts.
//!
//! Contract types are canonical beneath `autocad_reader::contract`; backend
//! traversal remains private to the reader implementation.

pub use crate::autocad_reader::contract::{
    DynamicBlockLink, DynamicBlockUnavailableReason, DynamicCurrentState,
    DynamicCurrentStateUnavailableReason, DynamicVisibilityParameter,
    DynamicVisibilityParameterUnavailableReason,
};
pub use crate::autocad_reader::DynamicBlockReadError;
