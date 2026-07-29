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

impl MutationCapability {
    fn candidate(route: MutationRoute) -> Self {
        Self {
            route,
            mutates_drawing: true,
            support: MutationSupport::CandidateGeneration,
            blocker_code: None,
            candidate_formats: vec![CandidateFormat::AsciiDxf],
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
            | MutationRoute::WriteTitleBlock => MutationCapability::candidate(route),
            MutationRoute::AttachXref | MutationRoute::UpdateXref => {
                MutationCapability::blocked(route, "xref_graph_invariants_unavailable")
            }
            MutationRoute::DetachXref
            | MutationRoute::InsertXrefInstance
            | MutationRoute::UpdateXrefInstance
            | MutationRoute::DeleteXrefInstance => {
                MutationCapability::blocked(route, "xref_reverse_links_unavailable")
            }
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

pub(crate) fn capability(route: MutationRoute) -> MutationCapability {
    mutation_capabilities()
        .into_iter()
        .find(|capability| capability.route == route)
        .expect("every mutation route has a capability")
}

pub(crate) fn blocker_code(route: MutationRoute) -> Option<&'static str> {
    match route {
        MutationRoute::CreateLayer
        | MutationRoute::UpdateLayer
        | MutationRoute::RenameLayer
        | MutationRoute::DeleteLayer
        | MutationRoute::WriteTitleBlock => None,
        MutationRoute::AttachXref | MutationRoute::UpdateXref => {
            Some("xref_graph_invariants_unavailable")
        }
        MutationRoute::DetachXref
        | MutationRoute::InsertXrefInstance
        | MutationRoute::UpdateXrefInstance
        | MutationRoute::DeleteXrefInstance => Some("xref_reverse_links_unavailable"),
        MutationRoute::ReloadXref | MutationRoute::UnloadXref => {
            Some("xref_load_state_not_preserved")
        }
        MutationRoute::BindXref => Some("xref_graph_import_unavailable"),
        MutationRoute::PlotToPdf => Some("plot_renderer_unavailable"),
    }
}
