//! Internal immutable-snapshot reader boundary.
//!
//! This crate owns immutable parsing, completeness policy, transport-neutral
//! contracts, and migrated read projections.

mod backend;
mod blocks;
pub mod contract;
mod drawing;
mod dynamic_blocks;
mod entities;
mod entity_identity;
mod error;
mod format_facts;
mod layers;
mod layouts;
mod owners;
#[cfg(test)]
mod qualification;
mod session;
mod snapshot;
mod symbols;
mod text;
mod title_blocks;
pub mod xref_path;
mod xrefs;

pub(crate) use blocks::is_xref_dependent_definition;
pub use blocks::BlockReadError;
pub use drawing::DrawingReadError;
pub use dynamic_blocks::DynamicBlockReadError;
pub use entities::EntityReadError;
pub use error::{ReadError, ReadErrorKind};
pub use format_facts::{
    map_snapshot_open_error as map_format_facts_snapshot_open_error, FormatFactsReadError,
};
pub use layers::LayerReadError;
pub use layouts::LayoutReadError;
pub use session::{DrawingReadSession, Reader};
pub use snapshot::{DrawingFormat, DrawingSnapshot};
pub use symbols::SymbolReadError;
pub use text::TextReadError;
pub use title_blocks::TitleBlockReadError;
pub use xrefs::{map_open_error as map_xref_open_error, XrefReadSession};
