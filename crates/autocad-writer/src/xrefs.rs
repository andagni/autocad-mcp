use super::contract::{
    blocker_code, capability, AttachXref, AttachXrefResult, BindXref, BindXrefResult,
    DeleteXrefInstance, DeleteXrefInstanceResult, DetachXref, DetachXrefResult, InsertXrefInstance,
    InsertXrefInstanceResult, MutationRoute, MutationSupport, ReloadXref, ReloadXrefResult,
    UnloadXref, UnloadXrefResult, UpdateXref, UpdateXrefInstance, UpdateXrefInstanceResult,
    UpdateXrefResult,
};
use super::WriteError;

fn blocked<T>(route: MutationRoute) -> Result<T, WriteError> {
    let capability = capability(route);
    debug_assert_eq!(capability.support, MutationSupport::BackendBlocked);
    let code = blocker_code(route).expect("blocked XREF route has a blocker code");
    Err(WriteError::backend_capability(
        code,
        "the selected writer backend cannot preserve the invariants required by this XREF mutation",
    )
    .with_internal_detail(match route {
        MutationRoute::ReloadXref | MutationRoute::UnloadXref => {
            "acadrust 0.4.1 drops XREF load state and writes every R2000+ XREF as unloaded"
        }
        MutationRoute::BindXref => {
            "acadrust 0.4.1 has no complete graph-import and handle-remapping primitive"
        }
        MutationRoute::AttachXref | MutationRoute::UpdateXref => {
            "acadrust 0.4.1 cannot preserve the XREF graph invariants required by this mutation"
        }
        MutationRoute::DetachXref
        | MutationRoute::InsertXrefInstance
        | MutationRoute::UpdateXrefInstance
        | MutationRoute::DeleteXrefInstance => {
            "acadrust 0.4.1 does not maintain all XREF reverse references during entity mutation"
        }
        _ => "selected mutation route is not available through the drawing writer",
    }))
}

pub(super) fn attach(_request: &AttachXref) -> Result<AttachXrefResult, WriteError> {
    blocked(MutationRoute::AttachXref)
}

pub(super) fn update(_request: &UpdateXref) -> Result<UpdateXrefResult, WriteError> {
    blocked(MutationRoute::UpdateXref)
}

pub(super) fn detach(_request: &DetachXref) -> Result<DetachXrefResult, WriteError> {
    blocked(MutationRoute::DetachXref)
}

pub(super) fn insert_instance(
    _request: &InsertXrefInstance,
) -> Result<InsertXrefInstanceResult, WriteError> {
    blocked(MutationRoute::InsertXrefInstance)
}

pub(super) fn update_instance(
    _request: &UpdateXrefInstance,
) -> Result<UpdateXrefInstanceResult, WriteError> {
    blocked(MutationRoute::UpdateXrefInstance)
}

pub(super) fn delete_instance(
    _request: &DeleteXrefInstance,
) -> Result<DeleteXrefInstanceResult, WriteError> {
    blocked(MutationRoute::DeleteXrefInstance)
}

pub(super) fn reload(_request: &ReloadXref) -> Result<ReloadXrefResult, WriteError> {
    blocked(MutationRoute::ReloadXref)
}

pub(super) fn unload(_request: &UnloadXref) -> Result<UnloadXrefResult, WriteError> {
    blocked(MutationRoute::UnloadXref)
}

pub(super) fn bind(_request: &BindXref) -> Result<BindXrefResult, WriteError> {
    blocked(MutationRoute::BindXref)
}
