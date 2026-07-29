//! Compatibility paths for the migrated text read family.
//!
//! Contract types are canonical beneath `autocad_reader::contract`; text
//! traversal and projection live entirely behind `DrawingReadSession`.

pub use crate::autocad_reader::contract::{
    MTextAttachmentPoint, MTextDrawingDirection, TextEntityKind, TextHorizontalAlignment, TextItem,
    TextListOptions, TextPoint3, TextRecord, TextSelector, TextVerticalAlignment,
};
pub use crate::autocad_reader::TextReadError;
