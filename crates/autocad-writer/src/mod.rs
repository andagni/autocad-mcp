//! Internal candidate-generation boundary for drawing mutations.
//!
//! The backend document stays private. Callers receive only transport-neutral
//! mutation records and verified candidate bytes; this crate never replaces a
//! source drawing in place.

mod backend;
pub mod contract;
mod error;
mod layers;
#[cfg(test)]
mod qualification;
mod session;
mod snapshot;
mod title_blocks;
mod xrefs;

pub use error::{WriteError, WriteErrorKind};
pub use session::{
    DrawingWriteSession, RoundtripCandidate, RoundtripClaimBoundary, RoundtripReceipt, Writer,
};
pub use snapshot::{DrawingFormat, DrawingSnapshot};
