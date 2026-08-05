use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MutationRoute {
    CreateLayer,
    UpdateLayer,
    RenameLayer,
    DeleteLayer,
    WriteTitleBlock,
    AttachXref,
    UpdateXref,
    DetachXref,
    InsertXrefInstance,
    UpdateXrefInstance,
    DeleteXrefInstance,
    ReloadXref,
    UnloadXref,
    BindXref,
    PlotToPdf,
}

pub const ALL_MUTATION_ROUTES: [MutationRoute; 15] = [
    MutationRoute::CreateLayer,
    MutationRoute::UpdateLayer,
    MutationRoute::RenameLayer,
    MutationRoute::DeleteLayer,
    MutationRoute::WriteTitleBlock,
    MutationRoute::AttachXref,
    MutationRoute::UpdateXref,
    MutationRoute::DetachXref,
    MutationRoute::InsertXrefInstance,
    MutationRoute::UpdateXrefInstance,
    MutationRoute::DeleteXrefInstance,
    MutationRoute::ReloadXref,
    MutationRoute::UnloadXref,
    MutationRoute::BindXref,
    MutationRoute::PlotToPdf,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MutationSupport {
    CandidateGeneration,
    BackendBlocked,
    ExternalRenderer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CandidateFormat {
    Dwg,
    AsciiDxf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MutationCapability {
    pub route: MutationRoute,
    pub mutates_drawing: bool,
    pub support: MutationSupport,
    pub blocker_code: Option<String>,
    pub candidate_formats: Vec<CandidateFormat>,
    pub source_admission_required: bool,
}

/// Routes whose DWG candidate generation is qualified under Preview: the
/// title-block writer (proven via whole-document CRC preservation, see
/// `backend::verify_dwg_title_block_preservation`) and the six real XREF
/// mutation routes (proven via the independent reader postcondition and
/// `XrefHandleBridge` checks in `session.rs` -- a different, route-scoped
/// evidentiary story rather than a whole-document byte-preservation proof).
/// Single source of truth for both this capability's advertised
/// `candidate_formats` and `session.rs`'s `encode_candidate` gate.
#[cfg(feature = "preview")]
pub(crate) fn dwg_preview_qualified_route(route: MutationRoute) -> bool {
    matches!(
        route,
        MutationRoute::WriteTitleBlock
            | MutationRoute::AttachXref
            | MutationRoute::UpdateXref
            | MutationRoute::DetachXref
            | MutationRoute::InsertXrefInstance
            | MutationRoute::UpdateXrefInstance
            | MutationRoute::DeleteXrefInstance
    )
}

impl MutationCapability {
    fn candidate(route: MutationRoute) -> Self {
        #[cfg(feature = "preview")]
        let candidate_formats = if dwg_preview_qualified_route(route) {
            vec![CandidateFormat::Dwg, CandidateFormat::AsciiDxf]
        } else {
            vec![CandidateFormat::AsciiDxf]
        };
        #[cfg(not(feature = "preview"))]
        let candidate_formats = vec![CandidateFormat::AsciiDxf];
        Self {
            route,
            mutates_drawing: true,
            support: MutationSupport::CandidateGeneration,
            blocker_code: None,
            candidate_formats,
            source_admission_required: true,
        }
    }

    fn blocked(route: MutationRoute, blocker_code: &str) -> Self {
        Self {
            route,
            mutates_drawing: true,
            support: MutationSupport::BackendBlocked,
            blocker_code: Some(blocker_code.to_string()),
            candidate_formats: Vec::new(),
            source_admission_required: false,
        }
    }
}

pub fn mutation_capabilities() -> Vec<MutationCapability> {
    ALL_MUTATION_ROUTES
        .into_iter()
        .map(|route| match route {
            MutationRoute::CreateLayer
            | MutationRoute::UpdateLayer
            | MutationRoute::RenameLayer
            | MutationRoute::DeleteLayer
            | MutationRoute::WriteTitleBlock
            | MutationRoute::AttachXref
            | MutationRoute::UpdateXref
            | MutationRoute::DetachXref
            | MutationRoute::InsertXrefInstance
            | MutationRoute::UpdateXrefInstance
            | MutationRoute::DeleteXrefInstance => MutationCapability::candidate(route),
            MutationRoute::ReloadXref | MutationRoute::UnloadXref => {
                MutationCapability::blocked(route, "xref_load_state_not_preserved")
            }
            MutationRoute::BindXref => {
                MutationCapability::blocked(route, "xref_graph_import_unavailable")
            }
            MutationRoute::PlotToPdf => MutationCapability {
                route,
                mutates_drawing: false,
                support: MutationSupport::ExternalRenderer,
                blocker_code: Some("plot_renderer_unavailable".to_string()),
                candidate_formats: Vec::new(),
                source_admission_required: false,
            },
        })
        .collect()
}
