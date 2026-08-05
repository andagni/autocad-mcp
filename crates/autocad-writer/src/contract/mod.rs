mod capability;
mod layers;
mod title_blocks;
mod xrefs;

#[cfg(feature = "preview")]
pub(crate) use capability::dwg_preview_qualified_route;
pub use capability::{
    mutation_capabilities, CandidateFormat, MutationCapability, MutationRoute, MutationSupport,
    ALL_MUTATION_ROUTES,
};
pub use layers::{
    CreateLayer, DeleteLayer, DeletedLayer, LayerMutation, LayerProperties, RenameLayer,
    UpdateLayer,
};
pub use title_blocks::{TitleBlockFingerprint, TitleBlockWrite, TitleBlockWriteResult};
pub use xrefs::{
    AttachXref, AttachXrefResult, BindXref, BindXrefResult, DeleteXrefInstance,
    DeleteXrefInstanceResult, DependencyStrategy, DetachXref, DetachXrefResult,
    EffectiveLayerReconciliationMode, InsertXrefInstance, InsertXrefInstanceResult,
    LayerReconciliation, LayerReconciliationEvidence, LayerReconciliationMode, ReloadXref,
    ReloadXrefResult, SymbolStrategy, UnloadXref, UnloadXrefResult, UpdateXref, UpdateXrefInstance,
    UpdateXrefInstanceProperties, UpdateXrefInstanceResult, UpdateXrefProperties, UpdateXrefResult,
    XrefAttachmentGuard, XrefBoundBlock, XrefBoundDependency, XrefDependencyRecord,
    XrefDestructiveAttachmentGuard, XrefInspectionState, XrefInstanceAttachmentGuard,
    XrefInstanceGuard, XrefInstanceHandleMapping, XrefInstancePlacement, XrefLayerProperty,
    XrefPlacement, XrefPropagationState, XrefResolutionBasis, XrefResolutionState,
    XrefSymbolMapping, XrefSymbolResolution, XrefSymbolType, XrefUnitAssumptions,
};

pub use autocad_reader::contract::xrefs::{
    InsertionUnit, LoadState, ReferenceType, XrefAttachmentRecord, XrefInstanceRecord,
    XrefOwnerType, XrefPathMode, XrefPlacementKind, XrefPoint3, XrefPointAvailability,
    XrefRectangularArray, XrefScale3, XrefUnitScaling, XrefVector3, XrefVisibility,
};
pub use autocad_reader::contract::{LayerLineWeight, LayerRecord, LayerSelector};
