use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectOwnerType {
    ModelSpace,
    PaperSpace,
    BlockDefinition,
    Entity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectOwnerUnavailableReason {
    UnresolvedOwner,
    MissingPaperSpaceLayout,
}

/// Semantic context for a non-null persisted direct-owner handle.
///
/// A null owner is represented by `None` on the containing record. Every
/// non-null owner resolves to one of these closed states or fails closed when
/// the document contains duplicate or contradictory ownership facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectOwnerContext {
    Available {
        owner_type: DirectOwnerType,
        owner_name: String,
    },
    Unavailable {
        reason: DirectOwnerUnavailableReason,
    },
}

impl DirectOwnerContext {
    pub fn available_identity(&self) -> Option<(DirectOwnerType, &str)> {
        match self {
            Self::Available {
                owner_type,
                owner_name,
            } => Some((*owner_type, owner_name)),
            Self::Unavailable { .. } => None,
        }
    }
}
