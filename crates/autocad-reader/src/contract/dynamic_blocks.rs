use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DynamicBlockUnavailableReason {
    LinkNotProven,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DynamicVisibilityParameterUnavailableReason {
    ParameterNotProven,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DynamicCurrentStateUnavailableReason {
    ParserNotRetained,
}

/// Availability of the selected visibility state.
///
/// There is deliberately no `Available` variant yet: the current reader
/// retains the visibility parameter and selectable states, but not the value
/// selected by a particular INSERT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DynamicCurrentState {
    Unavailable {
        reason: DynamicCurrentStateUnavailableReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DynamicVisibilityParameter {
    Available {
        /// Canonical uppercase hexadecimal visibility-parameter handle.
        handle: String,
        name: String,
        /// Number of parsed selectable state records. State names and member
        /// arrays are intentionally omitted to keep generic entity output
        /// bounded.
        selectable_state_count: usize,
        current_state: DynamicCurrentState,
    },
    Unavailable {
        reason: DynamicVisibilityParameterUnavailableReason,
    },
}

/// Proven dynamic-definition linkage for one INSERT.
///
/// `Unavailable` means only that the reader cannot prove the relationship. It
/// must not be interpreted as proof that the INSERT is static.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DynamicBlockLink {
    Available {
        /// Canonical uppercase hexadecimal dynamic-definition BLOCK_RECORD
        /// handle. For an evaluated anonymous INSERT this is the originating
        /// dynamic definition, not the anonymous effective definition.
        definition_handle: String,
        definition_name: String,
        visibility_parameter: DynamicVisibilityParameter,
    },
    Unavailable {
        reason: DynamicBlockUnavailableReason,
    },
}
