use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use crate::certification::{XrefMutationOperation, XrefUnitRole};

use super::{
    xref_graph::{
        require_complete_dependency_graph_for_mutation, traverse_xref_dependencies_for_mutation,
        XrefDependencyProvider, XrefGraphSource, XrefSourceInspection,
    },
    xref_mutation::{
        observe_xref_source_identity, XrefIsolatedProfileSpec, XrefLockedMutationContext,
        XrefMutationEngineBoundary, XrefMutationOperationCallback, XrefOperationContext,
        XrefSourceIdentityObservationError, XrefSourceIdentityProvenance, XrefSourceInput,
        XrefSourceSnapshot, XrefTransactionError, XrefTransactionErrorCode, XrefTransactionRequest,
        XrefVerificationContext,
    },
    xref_path::{
        validate_mutation_source_path, validate_search_paths, CandidateProbeResult,
        CanonicalDisplayPath, FilesystemIdentity, MutationSourcePath, ResolutionCandidate,
        ResolutionCandidateProbe, SearchPathInspection, SearchPathInspector,
    },
    xrefs::{
        canonical_input_handle, classify_attachment_update_property, compare_numeric_handles,
        validate_xref_name, xref_failure_code, xref_name_eq, AttachXrefRequest, AttachXrefResponse,
        AttachXrefStatus, DetachXrefRequest, DetachXrefResponse, DetachXrefStatus,
        EffectiveLayerReconciliationMode, InsertionUnit, LayerReconciliationMode, LoadState,
        ReferenceType, ReloadXrefRequest, ReloadXrefResponse, ReloadXrefStatus, UnloadXrefRequest,
        UnloadXrefResponse, UnloadXrefStatus, UpdateXrefRequest, UpdateXrefResponse,
        UpdateXrefStatus, XrefAttachmentGuards, XrefAttachmentRecord,
        XrefDependencyTraversalEnvelope, XrefError, XrefInspectionState, XrefInstanceRecord,
        XrefLayerProperty, XrefLayerReconciliation, XrefLayerReconciliationEvidence, XrefOwnerType,
        XrefPlacement, XrefPlacementKind, XrefPoint3, XrefPointAvailability,
        XrefPropertyClassification, XrefScale3, XrefSelector, XrefUnitAssumptions, XrefVector3,
        XrefVisibility,
    },
};

const SENTINEL_SCHEMA: &str = "autocad-mcp-xref-sentinel-v1";
const LISP_SCRIPT_SUFFIX: &str = ".lsp";
const SENTINEL_SUFFIX: &str = ".sentinel";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XrefBlockDefinitionEvidence {
    pub handle: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XrefOwnerMutationEvidence {
    pub handle: String,
    pub owner_type: XrefOwnerType,
    pub name: String,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XrefLayerMutationEvidence {
    pub handle: String,
    pub name: String,
    pub host_owned: bool,
    pub locked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XrefDependentSymbolEvidence {
    pub handle: String,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XrefClipMutationEvidence {
    Absent,
    Present,
    Unproven,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XrefAttachmentPreflightEvidence {
    pub attachment_handle: String,
    pub dependent_symbols_complete: bool,
    pub dependent_symbols: Vec<XrefDependentSymbolEvidence>,
    pub nested_projections_complete: bool,
    pub nested_attachment_chains: Vec<Vec<String>>,
    pub clips_complete: bool,
    pub instance_clips: BTreeMap<String, XrefClipMutationEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XrefSevenLayerProperties {
    pub off: bool,
    pub frozen: bool,
    pub locked: bool,
    pub is_plottable: bool,
    pub color_index: i16,
    pub line_type: String,
    pub line_weight: i16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XrefReconciliationLayerEvidence {
    pub handle: String,
    pub name: String,
    pub properties: XrefSevenLayerProperties,
    pub overridden_properties: BTreeSet<XrefLayerProperty>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct XrefAttachmentMutationSnapshot {
    pub drawing: String,
    pub graph_source: XrefGraphSource,
    pub attachments: Vec<XrefAttachmentRecord>,
    pub instances: Vec<XrefInstanceRecord>,
    pub block_definitions_complete: bool,
    pub block_definitions: Vec<XrefBlockDefinitionEvidence>,
    pub owners_complete: bool,
    pub owners: Vec<XrefOwnerMutationEvidence>,
    pub layers_complete: bool,
    pub layers: Vec<XrefLayerMutationEvidence>,
    pub attachment_preflight: Vec<XrefAttachmentPreflightEvidence>,
    pub reconciliation_layers_complete: bool,
    pub reconciliation_layers: Vec<XrefReconciliationLayerEvidence>,
    pub saved_visretain: i16,
    pub saved_xrefoverride: i16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XrefUnitRoleRequirement {
    Proven,
    AssumptionRequired,
    ProfileDefaultAssumptionRequired,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct XrefUnitRequirements {
    pub source: XrefUnitRoleRequirement,
    pub host: XrefUnitRoleRequirement,
}

impl Default for XrefUnitRequirements {
    fn default() -> Self {
        Self {
            source: XrefUnitRoleRequirement::Proven,
            host: XrefUnitRoleRequirement::Proven,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct XrefPreservationVerification<'a> {
    pub operation: XrefMutationOperation,
    pub profile_id: &'a str,
    pub before: &'a XrefAttachmentMutationSnapshot,
    pub after: &'a XrefAttachmentMutationSnapshot,
    pub selected_attachment_handle: Option<&'a str>,
    pub source_graph: Option<&'a XrefDependencyTraversalEnvelope>,
    pub source_snapshots: &'a [XrefSourceSnapshot],
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct XrefReconciliationVerification<'a> {
    pub attachment_handle: &'a str,
    pub request: &'a XrefLayerReconciliation,
    pub evidence: &'a XrefLayerReconciliationEvidence,
    pub before: &'a XrefAttachmentMutationSnapshot,
    pub after: &'a XrefAttachmentMutationSnapshot,
}

pub(crate) trait XrefAttachmentMutationServices: XrefDependencyProvider {
    fn reread_attachment_mutation_snapshot(
        &mut self,
        path: &Path,
    ) -> Result<XrefAttachmentMutationSnapshot, XrefError>;

    fn inspect_unit_requirements(
        &mut self,
        operation: XrefMutationOperation,
        graph: &XrefDependencyTraversalEnvelope,
    ) -> Result<XrefUnitRequirements, XrefError>;

    fn supports_profile_unit(&mut self, _role: XrefUnitRole, _unit: InsertionUnit) -> bool {
        true
    }

    fn verify_attachment_preservation(
        &mut self,
        verification: &XrefPreservationVerification<'_>,
    ) -> Result<(), XrefError>;

    fn verify_layer_reconciliation(
        &mut self,
        verification: &XrefReconciliationVerification<'_>,
    ) -> Result<(), XrefError>;
}

#[derive(Debug, Clone, PartialEq)]
struct ResolvedPlacement {
    owner: XrefOwnerMutationEvidence,
    layer: XrefLayerMutationEvidence,
    insertion_point: XrefPoint3,
    scale: XrefScale3,
    rotation_degrees: f64,
    normal: XrefVector3,
    visibility: XrefVisibility,
}

#[derive(Debug, Clone, PartialEq)]
struct LockedOperationState {
    snapshot: XrefAttachmentMutationSnapshot,
    selected: Option<XrefAttachmentRecord>,
    selected_instances: Vec<XrefInstanceRecord>,
    placement: Option<ResolvedPlacement>,
    source_graph: Option<XrefDependencyTraversalEnvelope>,
    root_source_id: Option<String>,
    reconciliation_request: Option<XrefLayerReconciliation>,
    reconciliation_evidence: Option<XrefLayerReconciliationEvidence>,
    preservation_profile_id: String,
    case_rename_temporary_name: Option<String>,
}

struct MutationCore<'a, Services: ?Sized> {
    services: &'a mut Services,
    host_path: PathBuf,
    drawing: String,
    operation: XrefMutationOperation,
    sources: Vec<XrefSourceInput>,
    unit_assumptions: Option<XrefUnitAssumptions>,
    reconciliation: Option<XrefLayerReconciliation>,
    locked: Option<LockedOperationState>,
    sentinel_path: Option<PathBuf>,
}

impl<'a, Services: ?Sized> MutationCore<'a, Services> {
    fn transaction_request(&self, mut profile: XrefIsolatedProfileSpec) -> XrefTransactionRequest {
        profile.unit_defaults = unit_profile_values(self.unit_assumptions.as_ref());
        profile.reconciliation = reconciliation_profile_values(self.reconciliation.as_ref());
        XrefTransactionRequest {
            host_path: self.host_path.clone(),
            operation: self.operation,
            sources: self.sources.clone(),
            profile,
        }
    }

    fn locked(&self) -> Result<&LockedOperationState, XrefTransactionError> {
        self.locked.as_ref().ok_or_else(|| {
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                "attachment mutation execute/verify called before locked validation",
            )
        })
    }

    fn verify_source_snapshots(
        &self,
        context: &XrefOperationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        verify_source_snapshots(
            &self.sources,
            context.source_snapshots,
            context.staging_directory,
        )
    }

    fn write_and_schedule_script(
        &mut self,
        engine: &mut dyn XrefMutationEngineBoundary,
        context: &XrefOperationContext<'_>,
        program: String,
    ) -> Result<Vec<PathBuf>, XrefTransactionError> {
        let operation = self.operation.as_str();
        let script_path = context
            .staging_directory
            .join(format!("{operation}{LISP_SCRIPT_SUFFIX}"));
        let sentinel_path = context
            .staging_directory
            .join(format!("{operation}{SENTINEL_SUFFIX}"));
        if program.contains(&self.host_path.to_string_lossy().to_string())
            && self
                .sources
                .iter()
                .any(|source| source.path == self.host_path)
        {
            return Err(write_failed(
                "operation script aliases the host as an XREF source",
            ));
        }
        let mut script = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&script_path)
            .map_err(|error| write_failed(format!("create {operation} AutoLISP: {error}")))?;
        script
            .write_all(program.as_bytes())
            .and_then(|()| script.sync_all())
            .map_err(|error| write_failed(format!("persist {operation} AutoLISP: {error}")))?;
        engine.execute_operation(&script_path).map_err(|error| {
            write_failed(format!(
                "schedule {operation} AutoLISP with engine: {error}"
            ))
        })?;
        self.sentinel_path = Some(sentinel_path.clone());
        Ok(vec![script_path, sentinel_path])
    }

    fn verify_sentinel(&self) -> Result<(), XrefTransactionError> {
        let path = self.sentinel_path.as_ref().ok_or_else(|| {
            verification_failed("operation did not record its sentinel artifact path")
        })?;
        verify_sentinel_file(path, self.operation.as_str())
    }
}

pub(crate) struct AttachXrefMutation<'a, Services: ?Sized> {
    request: AttachXrefRequest,
    source_path: MutationSourcePath,
    attachment_name: String,
    placement: XrefPlacement,
    core: MutationCore<'a, Services>,
}

pub(crate) struct UpdateXrefMutation<'a, Services: ?Sized> {
    request: UpdateXrefRequest,
    selector: XrefSelector,
    guards: XrefAttachmentGuards,
    properties: ParsedAttachmentUpdate,
    core: MutationCore<'a, Services>,
}

pub(crate) struct UnloadXrefMutation<'a, Services: ?Sized> {
    selector: XrefSelector,
    guards: XrefAttachmentGuards,
    core: MutationCore<'a, Services>,
}

pub(crate) struct ReloadXrefMutation<'a, Services: ?Sized> {
    request: ReloadXrefRequest,
    selector: XrefSelector,
    guards: XrefAttachmentGuards,
    core: MutationCore<'a, Services>,
}

pub(crate) struct DetachXrefMutation<'a, Services: ?Sized> {
    selector: XrefSelector,
    expected_instance_count: Option<u64>,
    expected_instance_handles: Option<Vec<String>>,
    guards: XrefAttachmentGuards,
    core: MutationCore<'a, Services>,
}

#[derive(Debug, Clone, PartialEq)]
struct ParsedAttachmentUpdate {
    name: Option<String>,
    xref_path: Option<MutationSourcePath>,
    reference_type: Option<ReferenceType>,
}

impl ParsedAttachmentUpdate {
    fn from_request(request: &UpdateXrefRequest) -> Result<Self, XrefTransactionError> {
        if request.properties.is_empty() {
            return Err(domain_error(
                xref_failure_code::EMPTY_XREF_UPDATE,
                "update_xref properties must contain at least one property",
            ));
        }

        for key in request.properties.keys() {
            match classify_attachment_update_property(key) {
                XrefPropertyClassification::Writable => {}
                XrefPropertyClassification::Unsupported => {
                    return Err(domain_error(
                        xref_failure_code::UNSUPPORTED_XREF_PROPERTY,
                        format!("update_xref property `{key}` is read-only or unsupported"),
                    ));
                }
                XrefPropertyClassification::Unknown => {
                    return Err(domain_error(
                        xref_failure_code::INVALID_XREF_PROPERTY,
                        format!("update_xref property `{key}` is unknown"),
                    ));
                }
            }
        }

        let name = request
            .properties
            .get("name")
            .map(|value| {
                serde_json::from_value::<String>(value.clone()).map_err(|_| {
                    domain_error(
                        xref_failure_code::INVALID_XREF_PROPERTY,
                        "update_xref properties.name must be a string",
                    )
                })
            })
            .transpose()?;
        if let Some(name) = &name {
            validate_xref_name(name).map_err(map_domain_error)?;
        }

        let xref_path = request
            .properties
            .get("xref_path")
            .map(|value| {
                let value = serde_json::from_value::<String>(value.clone()).map_err(|_| {
                    domain_error(
                        xref_failure_code::INVALID_XREF_PROPERTY,
                        "update_xref properties.xref_path must be a string",
                    )
                })?;
                validate_mutation_source_path(&value).map_err(|error| {
                    domain_error(xref_failure_code::INVALID_XREF_PATH, error.to_string())
                })
            })
            .transpose()?;

        let reference_type = request
            .properties
            .get("reference_type")
            .map(|value| {
                serde_json::from_value::<ReferenceType>(value.clone()).map_err(|_| {
                    domain_error(
                        xref_failure_code::INVALID_XREF_PROPERTY,
                        "update_xref properties.reference_type must be attachment or overlay",
                    )
                })
            })
            .transpose()?;

        let path_change = xref_path.is_some();
        if !path_change
            && (request.search_paths.is_some()
                || request.layer_reconciliation.is_some()
                || request.unit_assumptions.is_some())
        {
            return Err(domain_error(
                xref_failure_code::INVALID_PARAMETERS,
                "search_paths, layer_reconciliation, and unit_assumptions require xref_path",
            ));
        }
        if let Some(reconciliation) = &request.layer_reconciliation {
            reconciliation
                .clone()
                .validate()
                .map_err(map_domain_error)?;
        }

        Ok(Self {
            name,
            xref_path,
            reference_type,
        })
    }
}

pub(crate) fn validate_update_xref_step_two(
    request: &UpdateXrefRequest,
) -> Result<(), XrefTransactionError> {
    ParsedAttachmentUpdate::from_request(request).map(|_| ())
}

pub(crate) fn validate_attach_xref_context_free(
    request: &AttachXrefRequest,
) -> Result<(), XrefTransactionError> {
    let source_path = validate_mutation_source_path(&request.xref_path)
        .map_err(|error| domain_error(xref_failure_code::INVALID_XREF_PATH, error.to_string()))?;
    let attachment_name = match &request.name {
        Some(name) => name.clone(),
        None => derived_xref_name(&source_path)?,
    };
    validate_xref_name(&attachment_name).map_err(map_domain_error)?;

    let mut placement = request.placement.clone().unwrap_or_else(default_placement);
    if placement.owner_handle.is_some() {
        placement.owner_handle = Some("1".to_string());
    }
    if placement.layer_handle.is_some() {
        placement.layer_handle = Some("1".to_string());
    }
    placement.canonicalized().map_err(map_domain_error)?;
    Ok(())
}

impl<'a, Services> AttachXrefMutation<'a, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    pub(crate) fn new(
        request: AttachXrefRequest,
        sources: Vec<XrefSourceInput>,
        services: &'a mut Services,
    ) -> Result<Self, XrefTransactionError> {
        let (host_path, drawing) = validate_host_path(&request.drawing_path)?;
        let source_path = validate_mutation_source_path(&request.xref_path).map_err(|error| {
            domain_error(xref_failure_code::INVALID_XREF_PATH, error.to_string())
        })?;
        let attachment_name = match &request.name {
            Some(name) => name.clone(),
            None => derived_xref_name(&source_path)?,
        };
        validate_xref_name(&attachment_name).map_err(map_domain_error)?;
        let placement = request
            .placement
            .clone()
            .unwrap_or_else(default_placement)
            .canonicalized()
            .map_err(map_domain_error)?;

        Ok(Self {
            source_path,
            attachment_name,
            placement,
            core: MutationCore {
                services,
                host_path,
                drawing,
                operation: XrefMutationOperation::AttachXref,
                sources,
                unit_assumptions: request.unit_assumptions.clone(),
                reconciliation: None,
                locked: None,
                sentinel_path: None,
            },
            request,
        })
    }

    pub(crate) fn transaction_request(
        &self,
        profile: XrefIsolatedProfileSpec,
    ) -> XrefTransactionRequest {
        self.core.transaction_request(profile)
    }
}

impl<'a, Services> UpdateXrefMutation<'a, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    pub(crate) fn new(
        request: UpdateXrefRequest,
        sources: Vec<XrefSourceInput>,
        services: &'a mut Services,
    ) -> Result<Self, XrefTransactionError> {
        let properties = ParsedAttachmentUpdate::from_request(&request)?;
        let (host_path, drawing) = validate_host_path(&request.drawing_path)?;
        let selector = XrefSelector {
            handle: request.handle.clone(),
            name: request.name.clone(),
        }
        .canonicalized()
        .map_err(map_domain_error)?;
        validate_selector_shape(&selector)?;
        let guards = XrefAttachmentGuards {
            expected_handle: request.expected_handle.clone(),
            expected_name: request.expected_name.clone(),
        }
        .canonicalized()
        .map_err(map_domain_error)?;
        if properties.xref_path.is_none() && !sources.is_empty() {
            return Err(domain_error(
                xref_failure_code::INVALID_PARAMETERS,
                "host-only update_xref must not declare source snapshots",
            ));
        }
        let reconciliation = properties.xref_path.as_ref().map(|_| {
            request
                .layer_reconciliation
                .clone()
                .unwrap_or_else(default_reconciliation)
        });

        Ok(Self {
            selector,
            guards,
            properties,
            core: MutationCore {
                services,
                host_path,
                drawing,
                operation: XrefMutationOperation::UpdateXref,
                sources,
                unit_assumptions: request.unit_assumptions.clone(),
                reconciliation,
                locked: None,
                sentinel_path: None,
            },
            request,
        })
    }

    pub(crate) fn transaction_request(
        &self,
        profile: XrefIsolatedProfileSpec,
    ) -> XrefTransactionRequest {
        self.core.transaction_request(profile)
    }
}

impl<'a, Services> UnloadXrefMutation<'a, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    pub(crate) fn new(
        request: UnloadXrefRequest,
        services: &'a mut Services,
    ) -> Result<Self, XrefTransactionError> {
        let (host_path, drawing) = validate_host_path(&request.drawing_path)?;
        let selector = XrefSelector {
            handle: request.handle,
            name: request.name,
        }
        .canonicalized()
        .map_err(map_domain_error)?;
        validate_selector_shape(&selector)?;
        let guards = XrefAttachmentGuards {
            expected_handle: request.expected_handle,
            expected_name: request.expected_name,
        }
        .canonicalized()
        .map_err(map_domain_error)?;
        Ok(Self {
            selector,
            guards,
            core: MutationCore {
                services,
                host_path,
                drawing,
                operation: XrefMutationOperation::UnloadXref,
                sources: Vec::new(),
                unit_assumptions: None,
                reconciliation: None,
                locked: None,
                sentinel_path: None,
            },
        })
    }

    pub(crate) fn transaction_request(
        &self,
        profile: XrefIsolatedProfileSpec,
    ) -> XrefTransactionRequest {
        self.core.transaction_request(profile)
    }
}

impl<'a, Services> ReloadXrefMutation<'a, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    pub(crate) fn new(
        request: ReloadXrefRequest,
        sources: Vec<XrefSourceInput>,
        services: &'a mut Services,
    ) -> Result<Self, XrefTransactionError> {
        let (host_path, drawing) = validate_host_path(&request.drawing_path)?;
        let selector = XrefSelector {
            handle: request.handle.clone(),
            name: request.name.clone(),
        }
        .canonicalized()
        .map_err(map_domain_error)?;
        validate_selector_shape(&selector)?;
        let guards = XrefAttachmentGuards {
            expected_handle: request.expected_handle.clone(),
            expected_name: request.expected_name.clone(),
        }
        .canonicalized()
        .map_err(map_domain_error)?;
        let reconciliation = request
            .layer_reconciliation
            .clone()
            .unwrap_or_else(default_reconciliation)
            .validate()
            .map_err(map_domain_error)?;
        Ok(Self {
            selector,
            guards,
            core: MutationCore {
                services,
                host_path,
                drawing,
                operation: XrefMutationOperation::ReloadXref,
                sources,
                unit_assumptions: request.unit_assumptions.clone(),
                reconciliation: Some(reconciliation),
                locked: None,
                sentinel_path: None,
            },
            request,
        })
    }

    pub(crate) fn transaction_request(
        &self,
        profile: XrefIsolatedProfileSpec,
    ) -> XrefTransactionRequest {
        self.core.transaction_request(profile)
    }
}

impl<'a, Services> DetachXrefMutation<'a, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    pub(crate) fn new(
        request: DetachXrefRequest,
        services: &'a mut Services,
    ) -> Result<Self, XrefTransactionError> {
        let (host_path, drawing) = validate_host_path(&request.drawing_path)?;
        let selector = XrefSelector {
            handle: request.handle,
            name: request.name,
        }
        .canonicalized()
        .map_err(map_domain_error)?;
        validate_selector_shape(&selector)?;
        let guards = XrefAttachmentGuards {
            expected_handle: request.expected_handle,
            expected_name: request.expected_name,
        }
        .canonicalized()
        .map_err(map_domain_error)?;
        let expected_instance_handles = request
            .expected_instance_handles
            .map(|handles| canonicalize_exact_handle_set(&handles))
            .transpose()?;
        Ok(Self {
            selector,
            expected_instance_count: request.expected_instance_count,
            expected_instance_handles,
            guards,
            core: MutationCore {
                services,
                host_path,
                drawing,
                operation: XrefMutationOperation::DetachXref,
                sources: Vec::new(),
                unit_assumptions: None,
                reconciliation: None,
                locked: None,
                sentinel_path: None,
            },
        })
    }

    pub(crate) fn transaction_request(
        &self,
        profile: XrefIsolatedProfileSpec,
    ) -> XrefTransactionRequest {
        self.core.transaction_request(profile)
    }
}

pub(crate) fn prepare_attach_xref<'a, Services>(
    request: AttachXrefRequest,
    sources: Vec<XrefSourceInput>,
    services: &'a mut Services,
) -> Result<AttachXrefMutation<'a, Services>, XrefTransactionError>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    AttachXrefMutation::new(request, sources, services)
}

pub(crate) fn prepare_update_xref<'a, Services>(
    request: UpdateXrefRequest,
    sources: Vec<XrefSourceInput>,
    services: &'a mut Services,
) -> Result<UpdateXrefMutation<'a, Services>, XrefTransactionError>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    UpdateXrefMutation::new(request, sources, services)
}

pub(crate) fn prepare_unload_xref<'a, Services>(
    request: UnloadXrefRequest,
    services: &'a mut Services,
) -> Result<UnloadXrefMutation<'a, Services>, XrefTransactionError>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    UnloadXrefMutation::new(request, services)
}

pub(crate) fn prepare_reload_xref<'a, Services>(
    request: ReloadXrefRequest,
    sources: Vec<XrefSourceInput>,
    services: &'a mut Services,
) -> Result<ReloadXrefMutation<'a, Services>, XrefTransactionError>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    ReloadXrefMutation::new(request, sources, services)
}

pub(crate) fn prepare_detach_xref<'a, Services>(
    request: DetachXrefRequest,
    services: &'a mut Services,
) -> Result<DetachXrefMutation<'a, Services>, XrefTransactionError>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    DetachXrefMutation::new(request, services)
}

fn domain_error(code: &str, detail: impl Into<String>) -> XrefTransactionError {
    XrefTransactionError::new(
        XrefTransactionErrorCode::Domain(code.to_owned()),
        detail.into(),
    )
}

fn map_domain_error(error: XrefError) -> XrefTransactionError {
    // Use the raw message, not `to_string()`/`Display` — the latter prefixes
    // `code=<code> `, which would double up with the `code` we're already
    // carrying separately below (see the P1 #6 finding in
    // preview-agent-findings-2026-08-05.md: `update_xref` emitting
    // `unsupported_xref_data` twice for one failure).
    domain_error(error.code(), error.message())
}

fn write_failed(detail: impl Into<String>) -> XrefTransactionError {
    XrefTransactionError::new(XrefTransactionErrorCode::WriteFailed, detail)
}

fn verification_failed(detail: impl Into<String>) -> XrefTransactionError {
    XrefTransactionError::new(XrefTransactionErrorCode::VerificationFailed, detail)
}

fn validate_host_path(drawing_path: &str) -> Result<(PathBuf, String), XrefTransactionError> {
    let canonical =
        CanonicalDisplayPath::from_filesystem_canonical_path(drawing_path).map_err(|error| {
            domain_error(
                xref_failure_code::DRAWING_UNREADABLE,
                format!("drawing_path must be an absolute local path: {error}"),
            )
        })?;
    let file_name = canonical
        .as_str()
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default();
    let extension = file_name
        .rsplit_once('.')
        .map(|(_, extension)| extension)
        .unwrap_or_default();
    if !matches!(extension.to_ascii_lowercase().as_str(), "dwg" | "dxf") {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_FORMAT,
            "drawing_path must name a .dwg or .dxf host",
        ));
    }
    Ok((PathBuf::from(drawing_path), canonical.as_str().to_owned()))
}

fn validate_selector_shape(selector: &XrefSelector) -> Result<(), XrefTransactionError> {
    let usable_name = selector
        .name
        .as_deref()
        .is_some_and(|name| !name.trim().is_empty());
    if selector.handle.is_none() && !usable_name {
        return Err(domain_error(
            xref_failure_code::MISSING_IDENTITY,
            "attachment mutation requires handle or non-empty name",
        ));
    }
    Ok(())
}

fn derived_xref_name(path: &MutationSourcePath) -> Result<String, XrefTransactionError> {
    let basename = path.parsed().basename().ok_or_else(|| {
        domain_error(
            xref_failure_code::INVALID_XREF_NAME,
            "cannot derive an XREF name without a source filename",
        )
    })?;
    let stem = basename
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or("");
    validate_xref_name(stem).map_err(map_domain_error)?;
    Ok(stem.to_owned())
}

fn default_placement() -> XrefPlacement {
    XrefPlacement {
        owner_handle: None,
        owner_type: None,
        owner_name: None,
        layer_handle: None,
        layer_name: None,
        insertion_point: Some(XrefPoint3 {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        }),
        scale: Some(XrefScale3 {
            x: 1.0,
            y: 1.0,
            z: 1.0,
        }),
        rotation_degrees: Some(0.0),
        normal: Some(XrefVector3 {
            x: 0.0,
            y: 0.0,
            z: 1.0,
        }),
        visibility: Some(XrefVisibility::Visible),
    }
}

fn default_reconciliation() -> XrefLayerReconciliation {
    XrefLayerReconciliation {
        mode: LayerReconciliationMode::DrawingPolicy,
        properties: None,
    }
}

fn canonicalize_exact_handle_set(handles: &[String]) -> Result<Vec<String>, XrefTransactionError> {
    let mut canonical = Vec::with_capacity(handles.len());
    let mut seen = BTreeSet::new();
    for handle in handles {
        let handle = canonical_input_handle(handle).map_err(map_domain_error)?;
        if !seen.insert(handle.clone()) {
            return Err(domain_error(
                xref_failure_code::INVALID_PARAMETERS,
                "expected_instance_handles must contain unique handles",
            ));
        }
        canonical.push(handle);
    }
    sort_handles(&mut canonical)?;
    Ok(canonical)
}

fn sort_handles(handles: &mut [String]) -> Result<(), XrefTransactionError> {
    let mut error = None;
    handles.sort_by(|left, right| match compare_numeric_handles(left, right) {
        Ok(ordering) => ordering,
        Err(value) => {
            error = Some(value);
            std::cmp::Ordering::Equal
        }
    });
    error.map_or(Ok(()), |error| Err(map_domain_error(error)))
}

fn normalize_snapshot(
    mut snapshot: XrefAttachmentMutationSnapshot,
) -> Result<XrefAttachmentMutationSnapshot, XrefTransactionError> {
    let canonical_drawing = CanonicalDisplayPath::from_filesystem_canonical_path(&snapshot.drawing)
        .map_err(|error| {
            domain_error(
                xref_failure_code::UNSUPPORTED_XREF_DATA,
                format!("portable mutation reread returned invalid drawing path: {error}"),
            )
        })?;
    if canonical_drawing != *snapshot.graph_source.drawing_path() {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            "portable mutation reread drawing and graph root disagree",
        ));
    }

    for attachment in &snapshot.attachments {
        attachment.validate().map_err(map_domain_error)?;
    }
    snapshot.attachments.sort_by(|left, right| {
        compare_numeric_handles(&left.handle, &right.handle)
            .expect("validated persisted attachment handles are comparable")
    });
    if snapshot
        .attachments
        .windows(2)
        .any(|pair| pair[0].handle == pair[1].handle)
        || snapshot.graph_source.attachments() != snapshot.attachments
    {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            "portable attachment set is duplicated or disagrees with graph evidence",
        ));
    }

    snapshot.instances = snapshot
        .instances
        .into_iter()
        .map(|instance| instance.canonicalized().map_err(map_domain_error))
        .collect::<Result<Vec<_>, _>>()?;
    snapshot.instances.sort_by(|left, right| {
        compare_numeric_handles(&left.handle, &right.handle)
            .expect("validated persisted instance handles are comparable")
    });
    if snapshot
        .instances
        .windows(2)
        .any(|pair| pair[0].handle == pair[1].handle)
    {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            "portable mutation reread returned duplicate instance handles",
        ));
    }
    for attachment in &snapshot.attachments {
        let count = snapshot
            .instances
            .iter()
            .filter(|instance| instance.attachment_handle == attachment.handle)
            .count() as u64;
        if count != attachment.instance_count {
            return Err(domain_error(
                xref_failure_code::UNSUPPORTED_XREF_DATA,
                format!(
                    "attachment {} reports instance_count={} but portable reread found {count}",
                    attachment.handle, attachment.instance_count
                ),
            ));
        }
    }
    if snapshot.instances.iter().any(|instance| {
        !snapshot
            .attachments
            .iter()
            .any(|attachment| attachment.handle == instance.attachment_handle)
    }) {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            "portable mutation reread returned an instance outside a direct attachment",
        ));
    }

    validate_catalog_handles(
        snapshot
            .block_definitions
            .iter()
            .map(|value| value.handle.as_str()),
        "block definition",
    )?;
    validate_catalog_handles(
        snapshot.owners.iter().map(|value| value.handle.as_str()),
        "owner",
    )?;
    validate_catalog_handles(
        snapshot.layers.iter().map(|value| value.handle.as_str()),
        "layer",
    )?;
    validate_catalog_handles(
        snapshot
            .reconciliation_layers
            .iter()
            .map(|value| value.handle.as_str()),
        "reconciliation layer",
    )?;
    validate_preflight_catalog(&snapshot)?;
    if !matches!(snapshot.saved_visretain, 0 | 1) || !matches!(snapshot.saved_xrefoverride, 0 | 1) {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            "saved VISRETAIN and XREFOVERRIDE must be proven as 0 or 1",
        ));
    }
    Ok(snapshot)
}

fn validate_catalog_handles<'a>(
    handles: impl Iterator<Item = &'a str>,
    catalog: &str,
) -> Result<(), XrefTransactionError> {
    let mut seen = BTreeSet::new();
    for handle in handles {
        let canonical = canonical_input_handle(handle).map_err(|_| {
            domain_error(
                xref_failure_code::UNSUPPORTED_XREF_DATA,
                format!("portable {catalog} catalog contains an invalid handle"),
            )
        })?;
        if canonical != handle || !seen.insert(canonical) {
            return Err(domain_error(
                xref_failure_code::UNSUPPORTED_XREF_DATA,
                format!("portable {catalog} catalog contains non-canonical or duplicate handles"),
            ));
        }
    }
    Ok(())
}

fn validate_preflight_catalog(
    snapshot: &XrefAttachmentMutationSnapshot,
) -> Result<(), XrefTransactionError> {
    let mut handles = BTreeSet::new();
    for preflight in &snapshot.attachment_preflight {
        let canonical = canonical_input_handle(&preflight.attachment_handle)
            .map_err(|_| unsupported_data("preflight attachment handle is invalid"))?;
        if canonical != preflight.attachment_handle || !handles.insert(canonical) {
            return Err(unsupported_data(
                "preflight attachment handles are non-canonical or duplicated",
            ));
        }
        validate_catalog_handles(
            preflight
                .dependent_symbols
                .iter()
                .map(|symbol| symbol.handle.as_str()),
            "dependent symbol",
        )?;
        for chain in &preflight.nested_attachment_chains {
            if chain.is_empty()
                || chain
                    .iter()
                    .any(|handle| canonical_input_handle(handle).as_deref() != Ok(handle.as_str()))
                || chain.first() != Some(&preflight.attachment_handle)
            {
                return Err(unsupported_data(
                    "nested projection chains must be canonical and rooted at the attachment",
                ));
            }
        }
        for handle in preflight.instance_clips.keys() {
            if canonical_input_handle(handle).as_deref() != Ok(handle.as_str()) {
                return Err(unsupported_data(
                    "clip evidence contains a non-canonical instance handle",
                ));
            }
        }
    }
    Ok(())
}

fn unsupported_data(detail: impl Into<String>) -> XrefTransactionError {
    domain_error(xref_failure_code::UNSUPPORTED_XREF_DATA, detail)
}

fn resolve_attachment(
    snapshot: &XrefAttachmentMutationSnapshot,
    selector: &XrefSelector,
) -> Result<XrefAttachmentRecord, XrefTransactionError> {
    let by_handle = selector
        .handle
        .as_deref()
        .map(|wanted| {
            snapshot
                .attachments
                .iter()
                .find(|attachment| attachment.handle == wanted)
                .cloned()
                .ok_or_else(|| {
                    domain_error(
                        xref_failure_code::XREF_NOT_FOUND,
                        format!("direct attachment handle `{wanted}` was not found"),
                    )
                })
        })
        .transpose()?;
    let by_name = selector
        .name
        .as_deref()
        .map(|wanted| {
            if wanted.trim().is_empty() {
                return Err(domain_error(
                    xref_failure_code::XREF_NOT_FOUND,
                    "empty attachment name selector was not found",
                ));
            }
            let matches = snapshot
                .attachments
                .iter()
                .filter(|attachment| xref_name_eq(&attachment.name, wanted))
                .cloned()
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [attachment] => Ok(attachment.clone()),
                [] => Err(domain_error(
                    xref_failure_code::XREF_NOT_FOUND,
                    format!("direct attachment name `{wanted}` was not found"),
                )),
                _ => Err(domain_error(
                    xref_failure_code::AMBIGUOUS_IDENTITY,
                    format!("direct attachment name `{wanted}` is ambiguous"),
                )),
            }
        })
        .transpose()?;

    match (by_handle, by_name) {
        (Some(left), Some(right)) if left.handle == right.handle => Ok(left),
        (Some(_), Some(_)) => Err(domain_error(
            xref_failure_code::CONTRADICTORY_IDENTITY,
            "attachment handle and name resolve to different direct attachments",
        )),
        (Some(attachment), None) | (None, Some(attachment)) => Ok(attachment),
        (None, None) => Err(domain_error(
            xref_failure_code::MISSING_IDENTITY,
            "attachment mutation requires handle or non-empty name",
        )),
    }
}

fn apply_attachment_guards(
    attachment: &XrefAttachmentRecord,
    guards: &XrefAttachmentGuards,
) -> Result<(), XrefTransactionError> {
    if guards
        .expected_handle
        .as_deref()
        .is_some_and(|expected| expected != attachment.handle)
    {
        return Err(domain_error(
            xref_failure_code::EXPECTED_HANDLE_MISMATCH,
            format!("actual attachment handle is {}", attachment.handle),
        ));
    }
    if guards
        .expected_name
        .as_deref()
        .is_some_and(|expected| !xref_name_eq(expected, &attachment.name))
    {
        return Err(domain_error(
            xref_failure_code::EXPECTED_NAME_MISMATCH,
            format!("actual attachment name is `{}`", attachment.name),
        ));
    }
    Ok(())
}

fn instances_for(
    snapshot: &XrefAttachmentMutationSnapshot,
    attachment_handle: &str,
) -> Vec<XrefInstanceRecord> {
    snapshot
        .instances
        .iter()
        .filter(|instance| instance.attachment_handle == attachment_handle)
        .cloned()
        .collect()
}

fn attachment_preflight<'a>(
    snapshot: &'a XrefAttachmentMutationSnapshot,
    attachment_handle: &str,
) -> Result<&'a XrefAttachmentPreflightEvidence, XrefTransactionError> {
    let matches = snapshot
        .attachment_preflight
        .iter()
        .filter(|value| value.attachment_handle == attachment_handle)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [value] => Ok(*value),
        [] => Err(unsupported_data(format!(
            "attachment {attachment_handle} has no lifecycle preflight evidence"
        ))),
        _ => Err(unsupported_data(format!(
            "attachment {attachment_handle} has duplicate lifecycle preflight evidence"
        ))),
    }
}

fn check_clip_policy(
    snapshot: &XrefAttachmentMutationSnapshot,
    attachment: &XrefAttachmentRecord,
    instances: &[XrefInstanceRecord],
    rejects_clips: bool,
) -> Result<(), XrefTransactionError> {
    let preflight = attachment_preflight(snapshot, &attachment.handle)?;
    if !preflight.clips_complete {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_XREF_CLIP_DATA,
            "clip lifecycle evidence is incomplete",
        ));
    }
    let actual_handles = instances
        .iter()
        .map(|instance| instance.handle.as_str())
        .collect::<BTreeSet<_>>();
    let evidence_handles = preflight
        .instance_clips
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_handles != evidence_handles
        || preflight
            .instance_clips
            .values()
            .any(|value| *value == XrefClipMutationEvidence::Unproven)
    {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_XREF_CLIP_DATA,
            "clip evidence does not exactly cover every selected instance",
        ));
    }
    if rejects_clips
        && preflight
            .instance_clips
            .values()
            .any(|value| *value == XrefClipMutationEvidence::Present)
    {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_XREF_CLIP_DATA,
            "active capability row rejects clipped XREF targets",
        ));
    }
    Ok(())
}

fn validate_name_collision(
    snapshot: &XrefAttachmentMutationSnapshot,
    candidate: &str,
    excluded_handle: Option<&str>,
) -> Result<(), XrefTransactionError> {
    if !snapshot.block_definitions_complete {
        return Err(unsupported_data(
            "complete block-definition names are required for XREF collision proof",
        ));
    }
    if let Some(collision) = snapshot.block_definitions.iter().find(|definition| {
        Some(definition.handle.as_str()) != excluded_handle
            && xref_name_eq(&definition.name, candidate)
    }) {
        return Err(domain_error(
            xref_failure_code::XREF_NAME_COLLISION,
            format!(
                "requested XREF name collides with block {} `{}`",
                collision.handle, collision.name
            ),
        ));
    }
    Ok(())
}

fn resolve_placement(
    snapshot: &XrefAttachmentMutationSnapshot,
    placement: &XrefPlacement,
) -> Result<ResolvedPlacement, XrefTransactionError> {
    if !snapshot.owners_complete {
        return Err(unsupported_data(
            "complete owner catalog is required for attach placement",
        ));
    }
    if !snapshot.layers_complete {
        return Err(unsupported_data(
            "complete layer catalog is required for attach placement",
        ));
    }
    let owner = resolve_owner(snapshot, placement)?;
    if !owner.writable {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_XREF_OWNER,
            format!("owner {} `{}` is not writable", owner.handle, owner.name),
        ));
    }
    let layer = resolve_layer(snapshot, placement)?;
    if !layer.host_owned {
        return Err(domain_error(
            xref_failure_code::LAYER_NOT_HOST_OWNED,
            format!("layer {} `{}` is XREF-dependent", layer.handle, layer.name),
        ));
    }
    Ok(ResolvedPlacement {
        owner,
        layer,
        insertion_point: placement.insertion_point.unwrap_or(XrefPoint3 {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        }),
        scale: placement.scale.unwrap_or(XrefScale3 {
            x: 1.0,
            y: 1.0,
            z: 1.0,
        }),
        rotation_degrees: placement.rotation_degrees.unwrap_or(0.0),
        normal: placement.normal.unwrap_or(XrefVector3 {
            x: 0.0,
            y: 0.0,
            z: 1.0,
        }),
        visibility: placement.visibility.unwrap_or(XrefVisibility::Visible),
    })
}

fn resolve_owner(
    snapshot: &XrefAttachmentMutationSnapshot,
    placement: &XrefPlacement,
) -> Result<XrefOwnerMutationEvidence, XrefTransactionError> {
    let by_handle = placement
        .owner_handle
        .as_deref()
        .map(|wanted| {
            unique_catalog_match(
                snapshot
                    .owners
                    .iter()
                    .filter(|owner| owner.handle == wanted),
                xref_failure_code::XREF_OWNER_NOT_FOUND,
                "owner handle",
            )
        })
        .transpose()?;
    let by_semantic = match (placement.owner_type, placement.owner_name.as_deref()) {
        (Some(owner_type), Some(name)) => Some(unique_catalog_match(
            snapshot
                .owners
                .iter()
                .filter(|owner| owner.owner_type == owner_type && xref_name_eq(&owner.name, name)),
            xref_failure_code::XREF_OWNER_NOT_FOUND,
            "semantic owner",
        )?),
        (None, None) if placement.owner_handle.is_none() => Some(unique_catalog_match(
            snapshot
                .owners
                .iter()
                .filter(|owner| owner.owner_type == XrefOwnerType::ModelSpace),
            xref_failure_code::XREF_OWNER_NOT_FOUND,
            "model-space owner",
        )?),
        _ => None,
    };
    if let (Some(left), Some(right)) = (&by_handle, &by_semantic) {
        if left.handle != right.handle {
            return Err(domain_error(
                xref_failure_code::CONTRADICTORY_IDENTITY,
                "owner handle and semantic owner disagree",
            ));
        }
    }
    by_handle.or(by_semantic).ok_or_else(|| {
        domain_error(
            xref_failure_code::INVALID_XREF_OWNER,
            "owner selector does not have a valid shape",
        )
    })
}

fn resolve_layer(
    snapshot: &XrefAttachmentMutationSnapshot,
    placement: &XrefPlacement,
) -> Result<XrefLayerMutationEvidence, XrefTransactionError> {
    let by_handle = placement
        .layer_handle
        .as_deref()
        .map(|wanted| {
            unique_catalog_match(
                snapshot
                    .layers
                    .iter()
                    .filter(|layer| layer.handle == wanted),
                xref_failure_code::LAYER_NOT_FOUND,
                "layer handle",
            )
        })
        .transpose()?;
    let by_name = placement
        .layer_name
        .as_deref()
        .or_else(|| placement.layer_handle.is_none().then_some("0"))
        .map(|wanted| {
            unique_catalog_match(
                snapshot
                    .layers
                    .iter()
                    .filter(|layer| xref_name_eq(&layer.name, wanted)),
                xref_failure_code::LAYER_NOT_FOUND,
                "layer name",
            )
        })
        .transpose()?;
    if let (Some(left), Some(right)) = (&by_handle, &by_name) {
        if left.handle != right.handle {
            return Err(domain_error(
                xref_failure_code::CONTRADICTORY_IDENTITY,
                "layer handle and name disagree",
            ));
        }
    }
    by_handle.or(by_name).ok_or_else(|| {
        domain_error(
            xref_failure_code::LAYER_NOT_FOUND,
            "layer selector did not resolve",
        )
    })
}

fn unique_catalog_match<'a, T: Clone + 'a>(
    values: impl Iterator<Item = &'a T>,
    not_found_code: &str,
    description: &str,
) -> Result<T, XrefTransactionError> {
    let values = values.cloned().collect::<Vec<_>>();
    match values.as_slice() {
        [value] => Ok(value.clone()),
        [] => Err(domain_error(
            not_found_code,
            format!("{description} was not found"),
        )),
        _ => Err(unsupported_data(format!(
            "{description} resolves more than once"
        ))),
    }
}

fn virtual_graph_source(
    snapshot: &XrefAttachmentMutationSnapshot,
    attachment: XrefAttachmentRecord,
) -> Result<XrefGraphSource, XrefTransactionError> {
    XrefGraphSource::try_new(
        snapshot.graph_source.drawing_path().clone(),
        snapshot.graph_source.filesystem_identity().clone(),
        vec![attachment],
    )
    .map_err(map_domain_error)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraversedSourceIdentity {
    resolved_path: String,
    filesystem_identity: FilesystemIdentity,
    content_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct LockedSourceGraph {
    traversal: XrefDependencyTraversalEnvelope,
    identities: Vec<TraversedSourceIdentity>,
}

struct IdentityRecordingProvider<'a, Services: ?Sized> {
    services: &'a mut Services,
    identities: Vec<TraversedSourceIdentity>,
}

impl<Services> ResolutionCandidateProbe for IdentityRecordingProvider<'_, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    fn probe_candidate(&mut self, candidate: &ResolutionCandidate) -> CandidateProbeResult {
        self.services.probe_candidate(candidate)
    }
}

impl<Services> SearchPathInspector for IdentityRecordingProvider<'_, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    fn inspect_search_path(&mut self, absolute_path: &str) -> SearchPathInspection {
        self.services.inspect_search_path(absolute_path)
    }
}

impl<Services> XrefDependencyProvider for IdentityRecordingProvider<'_, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    fn inspect_resolved_source(
        &mut self,
        resolved_path: &CanonicalDisplayPath,
        filesystem_identity: &FilesystemIdentity,
    ) -> Result<XrefSourceInspection, XrefError> {
        let inspection = self
            .services
            .inspect_resolved_source(resolved_path, filesystem_identity)?;
        if let XrefSourceInspection::Inspected { content_sha256, .. } = &inspection {
            let content_sha256 = content_sha256.clone().ok_or_else(|| {
                XrefError::new(
                    xref_failure_code::UNSUPPORTED_XREF_SOURCE,
                    "locked dependency inspection did not retain the exact source-byte digest",
                )
            })?;
            self.identities.push(TraversedSourceIdentity {
                resolved_path: resolved_path.as_str().to_owned(),
                filesystem_identity: filesystem_identity.clone(),
                content_sha256: Some(content_sha256),
            });
        }
        Ok(inspection)
    }
}

fn inspect_source_graph<Services>(
    services: &mut Services,
    source: &XrefGraphSource,
    root_handle: &str,
    search_paths: &[String],
) -> Result<LockedSourceGraph, XrefTransactionError>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    let validated_paths = validate_search_paths(search_paths, source.platform(), services)
        .map_err(|error| domain_error(xref_failure_code::INVALID_SEARCH_PATH, error.to_string()))?;
    let selector = XrefSelector {
        handle: Some(root_handle.to_owned()),
        name: None,
    };
    let mut provider = IdentityRecordingProvider {
        services,
        identities: Vec::new(),
    };
    let graph = traverse_xref_dependencies_for_mutation(
        source,
        Some(&selector),
        &validated_paths,
        &mut provider,
    )
    .map_err(map_domain_error)?;
    require_complete_dependency_graph_for_mutation(&graph).map_err(map_domain_error)?;
    validate_effective_graph_root(&graph, root_handle)?;
    let locked = LockedSourceGraph {
        traversal: graph,
        identities: provider.identities,
    };
    source_inputs_from_locked_graph(&locked)?;
    Ok(locked)
}

fn validate_effective_graph_root(
    graph: &XrefDependencyTraversalEnvelope,
    root_handle: &str,
) -> Result<(), XrefTransactionError> {
    let roots = graph
        .dependencies
        .iter()
        .filter(|dependency| dependency.depth == 0)
        .collect::<Vec<_>>();
    if roots.len() != 1
        || roots[0].attachment.handle != root_handle
        || roots[0].inspection_state != XrefInspectionState::Inspected
    {
        return Err(unsupported_data(
            "source mutation graph must contain exactly one fully inspected selected root",
        ));
    }
    Ok(())
}

pub(crate) fn source_inputs_from_effective_graph(
    graph: &XrefDependencyTraversalEnvelope,
) -> Result<Vec<XrefSourceInput>, XrefTransactionError> {
    require_complete_dependency_graph_for_mutation(graph).map_err(map_domain_error)?;
    let identities = graph
        .dependencies
        .iter()
        .filter(|dependency| dependency.inspection_state == XrefInspectionState::Inspected)
        .map(|dependency| {
            let resolved_path = dependency.resolved_path.as_deref().ok_or_else(|| {
                unsupported_data("inspected dependency does not expose its resolved source path")
            })?;
            let filesystem_identity = observe_xref_source_identity(Path::new(resolved_path))
                .map_err(|error| match error {
                    XrefSourceIdentityObservationError::Changed(error) => {
                        XrefTransactionError::new(
                            XrefTransactionErrorCode::XrefSourceChanged,
                            format!(
                                "dependency '{}' identity changed after graph traversal: {error}",
                                source_id_for_chain(&dependency.attachment_chain)
                            ),
                        )
                    }
                    XrefSourceIdentityObservationError::Unreadable(error) => domain_error(
                        xref_failure_code::XREF_SOURCE_UNREADABLE,
                        format!(
                            "dependency '{}' identity is unreadable after graph traversal: {error}",
                            source_id_for_chain(&dependency.attachment_chain)
                        ),
                    ),
                })?;
            Ok(TraversedSourceIdentity {
                resolved_path: resolved_path.to_owned(),
                filesystem_identity,
                content_sha256: None,
            })
        })
        .collect::<Result<Vec<_>, XrefTransactionError>>()?;
    source_inputs_from_graph_and_identities(
        graph,
        &identities,
        XrefSourceIdentityProvenance::PathObservation,
    )
}

fn source_inputs_from_locked_graph(
    graph: &LockedSourceGraph,
) -> Result<Vec<XrefSourceInput>, XrefTransactionError> {
    source_inputs_from_graph_and_identities(
        &graph.traversal,
        &graph.identities,
        XrefSourceIdentityProvenance::LockedGraphTraversal,
    )
}

fn source_inputs_from_graph_and_identities(
    graph: &XrefDependencyTraversalEnvelope,
    identities: &[TraversedSourceIdentity],
    identity_provenance: XrefSourceIdentityProvenance,
) -> Result<Vec<XrefSourceInput>, XrefTransactionError> {
    require_complete_dependency_graph_for_mutation(graph).map_err(map_domain_error)?;
    let mut sources = Vec::new();
    let mut identities = identities.iter();
    for dependency in &graph.dependencies {
        if dependency.inspection_state != XrefInspectionState::Inspected {
            continue;
        }
        let resolved_path = dependency.resolved_path.as_ref().ok_or_else(|| {
            unsupported_data("inspected dependency does not expose its resolved source path")
        })?;
        let source_id = source_id_for_chain(&dependency.attachment_chain);
        let immediate_host_source_id = (dependency.attachment_chain.len() > 1).then(|| {
            source_id_for_chain(
                &dependency.attachment_chain[..dependency.attachment_chain.len() - 1],
            )
        });
        let identity = identities.next().ok_or_else(|| {
            unsupported_data("graph traversal omitted an inspected dependency identity")
        })?;
        if identity.resolved_path != *resolved_path {
            return Err(unsupported_data(
                "graph traversal identity order disagrees with dependency order",
            ));
        }
        sources.push(XrefSourceInput {
            source_id,
            path: PathBuf::from(resolved_path),
            saved_path: dependency.attachment.saved_path.clone(),
            immediate_host_source_id,
            filesystem_identity: identity.filesystem_identity.clone(),
            identity_provenance: identity_provenance.clone(),
            inspected_digest_sha256: identity.content_sha256.clone(),
        });
    }
    if identities.next().is_some() {
        return Err(unsupported_data(
            "graph traversal exposed an identity without an inspected dependency",
        ));
    }
    let ids = sources
        .iter()
        .map(|source| source.source_id.as_str())
        .collect::<BTreeSet<_>>();
    if ids.len() != sources.len()
        || sources.iter().any(|source| {
            source
                .immediate_host_source_id
                .as_deref()
                .is_some_and(|parent| !ids.contains(parent))
        })
    {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_XREF_SOURCE,
            "effective graph cannot be represented as unique transaction source snapshots",
        ));
    }
    Ok(sources)
}

fn source_id_for_chain(chain: &[String]) -> String {
    chain.join("/")
}

fn require_declared_sources(
    declared: &[XrefSourceInput],
    graph: &LockedSourceGraph,
) -> Result<(String, Vec<XrefSourceInput>), XrefTransactionError> {
    let required = source_inputs_from_locked_graph(graph)?;
    let same_topology = declared.len() == required.len()
        && declared.iter().zip(&required).all(|(declared, required)| {
            declared.source_id == required.source_id
                && declared.path == required.path
                && declared.saved_path == required.saved_path
                && declared.immediate_host_source_id == required.immediate_host_source_id
        });
    if !same_topology {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_XREF_SOURCE,
            "declared transaction sources do not exactly match the locked effective graph",
        ));
    }
    if declared
        .iter()
        .zip(&required)
        .any(|(declared, required)| declared.filesystem_identity != required.filesystem_identity)
    {
        return Err(XrefTransactionError::new(
            XrefTransactionErrorCode::XrefSourceChanged,
            "dependency filesystem identity changed between graph traversal and locked validation",
        ));
    }
    let root_source_id = required
        .first()
        .map(|source| source.source_id.clone())
        .ok_or_else(|| {
            domain_error(
                xref_failure_code::XREF_SOURCE_NOT_FOUND,
                "required source graph has no inspectable root source",
            )
        })?;
    Ok((root_source_id, required))
}

fn validate_unit_assumptions<Services>(
    services: &mut Services,
    context: &XrefLockedMutationContext<'_>,
    operation: XrefMutationOperation,
    graph: &XrefDependencyTraversalEnvelope,
    assumptions: Option<&XrefUnitAssumptions>,
) -> Result<(), XrefTransactionError>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    let requirements = services
        .inspect_unit_requirements(operation, graph)
        .map_err(map_domain_error)?;
    validate_unit_role(
        services,
        context,
        XrefUnitRole::Source,
        requirements.source,
        assumptions.and_then(|value| value.source_units),
    )?;
    validate_unit_role(
        services,
        context,
        XrefUnitRole::Host,
        requirements.host,
        assumptions.and_then(|value| value.host_units),
    )
}

fn validate_unit_role<Services>(
    services: &mut Services,
    context: &XrefLockedMutationContext<'_>,
    role: XrefUnitRole,
    requirement: XrefUnitRoleRequirement,
    assumption: Option<InsertionUnit>,
) -> Result<(), XrefTransactionError>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    let profile_default_admitted = context
        .admission
        .preservation_profile
        .profile_default_unit_states
        .iter()
        .any(|state| {
            state.host_format == context.format.host_format
                && state.drawing_version == context.format.drawing_version
                && state.role == role
        });
    let supported = assumption.is_none_or(|unit| services.supports_profile_unit(role, unit));
    validate_unit_role_contract(
        role,
        requirement,
        assumption,
        profile_default_admitted,
        supported,
    )
}

fn validate_unit_role_contract(
    role: XrefUnitRole,
    requirement: XrefUnitRoleRequirement,
    assumption: Option<InsertionUnit>,
    profile_default_admitted: bool,
    profile_unit_supported: bool,
) -> Result<(), XrefTransactionError> {
    if requirement == XrefUnitRoleRequirement::Unsupported {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_INSERTION_UNITS,
            format!("{} insertion units cannot be proven", role.as_str()),
        ));
    }
    if requirement == XrefUnitRoleRequirement::Proven && assumption.is_some() {
        return Err(domain_error(
            xref_failure_code::INVALID_UNIT_ASSUMPTIONS,
            format!(
                "{} unit assumption is forbidden for proven units",
                role.as_str()
            ),
        ));
    }
    if matches!(
        requirement,
        XrefUnitRoleRequirement::AssumptionRequired
            | XrefUnitRoleRequirement::ProfileDefaultAssumptionRequired
    ) && assumption.is_none()
    {
        return Err(domain_error(
            xref_failure_code::AMBIGUOUS_INSERTION_UNITS,
            format!("{} unit assumption is required", role.as_str()),
        ));
    }
    if requirement == XrefUnitRoleRequirement::ProfileDefaultAssumptionRequired
        && !profile_default_admitted
    {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_INSERTION_UNITS,
            format!(
                "active preservation profile does not certify {} profile defaults",
                role.as_str()
            ),
        ));
    }
    if !profile_unit_supported {
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_INSERTION_UNITS,
            format!(
                "active engine cannot apply the requested {} unit",
                role.as_str()
            ),
        ));
    }
    Ok(())
}

fn reconciliation_evidence(
    request: &XrefLayerReconciliation,
    saved_visretain: i16,
) -> XrefLayerReconciliationEvidence {
    let effective_mode = match request.mode {
        LayerReconciliationMode::DrawingPolicy if saved_visretain == 0 => {
            EffectiveLayerReconciliationMode::SourceAuthoritative
        }
        LayerReconciliationMode::DrawingPolicy => EffectiveLayerReconciliationMode::PreserveHost,
        LayerReconciliationMode::PreserveHost => EffectiveLayerReconciliationMode::PreserveHost,
        LayerReconciliationMode::SourceAuthoritative => {
            EffectiveLayerReconciliationMode::SourceAuthoritative
        }
        LayerReconciliationMode::Synchronize => EffectiveLayerReconciliationMode::Synchronize,
    };
    let mut synchronized_properties = if request.mode == LayerReconciliationMode::Synchronize {
        request.properties.clone().unwrap_or_default()
    } else {
        Vec::new()
    };
    synchronized_properties.sort_by_key(|property| layer_property_order(*property));
    XrefLayerReconciliationEvidence {
        requested_mode: request.mode,
        effective_mode,
        synchronized_properties,
    }
}

fn layer_property_order(property: XrefLayerProperty) -> u8 {
    match property {
        XrefLayerProperty::Off => 0,
        XrefLayerProperty::Frozen => 1,
        XrefLayerProperty::Locked => 2,
        XrefLayerProperty::IsPlottable => 3,
        XrefLayerProperty::ColorIndex => 4,
        XrefLayerProperty::LineType => 5,
        XrefLayerProperty::LineWeight => 6,
    }
}

fn visretainmode_mask(properties: &[XrefLayerProperty]) -> i32 {
    properties.iter().fold(0, |mask, property| {
        mask | match property {
            XrefLayerProperty::Off => 1,
            XrefLayerProperty::Frozen => 2,
            XrefLayerProperty::Locked => 4,
            XrefLayerProperty::IsPlottable => 8,
            XrefLayerProperty::ColorIndex => 16,
            XrefLayerProperty::LineType => 32,
            XrefLayerProperty::LineWeight => 64,
        }
    })
}

fn validate_detach_preflight(
    snapshot: &XrefAttachmentMutationSnapshot,
    attachment: &XrefAttachmentRecord,
    instances: &[XrefInstanceRecord],
    rejects_clips: bool,
) -> Result<(), XrefTransactionError> {
    if !snapshot.owners_complete || !snapshot.layers_complete {
        return Err(unsupported_data(
            "detach requires complete owner and layer catalogs",
        ));
    }
    let mut unsupported_owners = Vec::new();
    let mut locked_instances = Vec::new();
    for instance in instances {
        let owner = snapshot
            .owners
            .iter()
            .find(|owner| owner.handle == instance.owner_handle)
            .ok_or_else(|| unsupported_data("detach instance owner is not represented"))?;
        if !owner.writable {
            unsupported_owners.push(instance.handle.clone());
        }
        let layer = snapshot
            .layers
            .iter()
            .find(|layer| layer.handle == instance.layer_handle)
            .ok_or_else(|| unsupported_data("detach instance layer is not represented"))?;
        if layer.locked {
            locked_instances.push(instance.handle.clone());
        }
    }
    if !unsupported_owners.is_empty() {
        sort_handles(&mut unsupported_owners)?;
        return Err(domain_error(
            xref_failure_code::UNSUPPORTED_XREF_OWNER,
            format!("instances have non-writable owners: {unsupported_owners:?}"),
        ));
    }
    if !locked_instances.is_empty() {
        sort_handles(&mut locked_instances)?;
        return Err(domain_error(
            xref_failure_code::XREF_INSTANCE_LOCKED,
            format!("locked-layer instances block detach: {locked_instances:?}"),
        ));
    }
    let preflight = attachment_preflight(snapshot, &attachment.handle)?;
    if !preflight.dependent_symbols_complete || !preflight.nested_projections_complete {
        return Err(unsupported_data(
            "detach cannot prove complete dependent-symbol or nested-projection cleanup",
        ));
    }
    check_clip_policy(snapshot, attachment, instances, rejects_clips)
}

fn apply_destructive_guards(
    attachment: &XrefAttachmentRecord,
    instances: &[XrefInstanceRecord],
    expected_count: Option<u64>,
    expected_handles: Option<&[String]>,
) -> Result<(), XrefTransactionError> {
    if expected_count.is_some_and(|expected| expected != attachment.instance_count) {
        return Err(domain_error(
            xref_failure_code::EXPECTED_INSTANCE_COUNT_MISMATCH,
            format!("actual instance_count is {}", attachment.instance_count),
        ));
    }
    if let Some(expected) = expected_handles {
        let mut actual = instances
            .iter()
            .map(|instance| instance.handle.clone())
            .collect::<Vec<_>>();
        sort_handles(&mut actual)?;
        if actual != expected {
            return Err(domain_error(
                xref_failure_code::EXPECTED_INSTANCE_HANDLES_MISMATCH,
                format!("actual instance handles are {actual:?}"),
            ));
        }
    }
    Ok(())
}

fn case_rename_temporary_name(
    snapshot: &XrefAttachmentMutationSnapshot,
    attachment: &XrefAttachmentRecord,
    requested: Option<&str>,
) -> Option<String> {
    let requested = requested?;
    if requested == attachment.name || !xref_name_eq(requested, &attachment.name) {
        return None;
    }
    let base = format!("__AUTOCAD_MCP_XREF_{}__", attachment.handle);
    (0_u32..)
        .map(|suffix| {
            if suffix == 0 {
                base.clone()
            } else {
                format!("{base}{suffix}")
            }
        })
        .find(|candidate| {
            !snapshot
                .block_definitions
                .iter()
                .any(|definition| xref_name_eq(&definition.name, candidate))
        })
}

fn verify_source_snapshots(
    declared: &[XrefSourceInput],
    snapshots: &[XrefSourceSnapshot],
    staging_directory: &Path,
) -> Result<(), XrefTransactionError> {
    if declared.len() != snapshots.len() {
        return Err(write_failed(
            "captured source snapshot count differs from the locked source graph",
        ));
    }
    let mut snapshot_paths = BTreeSet::new();
    for (declared, snapshot) in declared.iter().zip(snapshots) {
        if declared.source_id != snapshot.source_id
            || declared.path != snapshot.original_path
            || declared.saved_path != snapshot.saved_path
            || declared.immediate_host_source_id != snapshot.immediate_host_source_id
            || declared.filesystem_identity != snapshot.filesystem_identity
            || declared.inspected_digest_sha256.as_deref() != Some(snapshot.digest_sha256.as_str())
            || snapshot.snapshot_path == snapshot.original_path
            || !snapshot.snapshot_path.starts_with(staging_directory)
            || !snapshot_paths.insert(snapshot.snapshot_path.clone())
        {
            return Err(write_failed(
                "captured source snapshots do not exactly represent isolated locked graph inputs",
            ));
        }
    }
    Ok(())
}

fn root_snapshot_path<'a>(
    state: &LockedOperationState,
    snapshots: &'a [XrefSourceSnapshot],
) -> Result<&'a Path, XrefTransactionError> {
    let source_id = state.root_source_id.as_deref().ok_or_else(|| {
        write_failed("source-dependent attachment operation has no locked root source ID")
    })?;
    snapshots
        .iter()
        .find(|snapshot| snapshot.source_id == source_id)
        .map(|snapshot| snapshot.snapshot_path.as_path())
        .ok_or_else(|| write_failed("root source snapshot was not captured"))
}

fn unit_profile_values(assumptions: Option<&XrefUnitAssumptions>) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    if let Some(unit) = assumptions.and_then(|value| value.host_units) {
        values.insert(
            "host_units".to_owned(),
            insertion_unit_name(unit).to_owned(),
        );
    }
    if let Some(unit) = assumptions.and_then(|value| value.source_units) {
        values.insert(
            "source_units".to_owned(),
            insertion_unit_name(unit).to_owned(),
        );
    }
    values
}

fn reconciliation_profile_values(
    reconciliation: Option<&XrefLayerReconciliation>,
) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    if let Some(reconciliation) = reconciliation {
        values.insert(
            "mode".to_owned(),
            reconciliation_mode_name(reconciliation.mode).to_owned(),
        );
        let mut properties = reconciliation.properties.clone().unwrap_or_default();
        properties.sort_by_key(|property| layer_property_order(*property));
        values.insert(
            "properties".to_owned(),
            properties
                .into_iter()
                .map(layer_property_name)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    values
}

fn insertion_unit_name(unit: InsertionUnit) -> &'static str {
    match unit {
        InsertionUnit::Unitless => "unitless",
        InsertionUnit::Inches => "inches",
        InsertionUnit::Feet => "feet",
        InsertionUnit::Miles => "miles",
        InsertionUnit::Millimeters => "millimeters",
        InsertionUnit::Centimeters => "centimeters",
        InsertionUnit::Meters => "meters",
        InsertionUnit::Kilometers => "kilometers",
        InsertionUnit::Microinches => "microinches",
        InsertionUnit::Mils => "mils",
        InsertionUnit::Yards => "yards",
        InsertionUnit::Angstroms => "angstroms",
        InsertionUnit::Nanometers => "nanometers",
        InsertionUnit::Microns => "microns",
        InsertionUnit::Decimeters => "decimeters",
        InsertionUnit::Dekameters => "dekameters",
        InsertionUnit::Hectometers => "hectometers",
        InsertionUnit::Gigameters => "gigameters",
        InsertionUnit::AstronomicalUnits => "astronomical_units",
        InsertionUnit::LightYears => "light_years",
        InsertionUnit::Parsecs => "parsecs",
        InsertionUnit::UsSurveyFeet => "us_survey_feet",
        InsertionUnit::UsSurveyInches => "us_survey_inches",
        InsertionUnit::UsSurveyYards => "us_survey_yards",
        InsertionUnit::UsSurveyMiles => "us_survey_miles",
    }
}

fn insertion_unit_code(unit: InsertionUnit) -> i32 {
    match unit {
        InsertionUnit::Unitless => 0,
        InsertionUnit::Inches => 1,
        InsertionUnit::Feet => 2,
        InsertionUnit::Miles => 3,
        InsertionUnit::Millimeters => 4,
        InsertionUnit::Centimeters => 5,
        InsertionUnit::Meters => 6,
        InsertionUnit::Kilometers => 7,
        InsertionUnit::Microinches => 8,
        InsertionUnit::Mils => 9,
        InsertionUnit::Yards => 10,
        InsertionUnit::Angstroms => 11,
        InsertionUnit::Nanometers => 12,
        InsertionUnit::Microns => 13,
        InsertionUnit::Decimeters => 14,
        InsertionUnit::Dekameters => 15,
        InsertionUnit::Hectometers => 16,
        InsertionUnit::Gigameters => 17,
        InsertionUnit::AstronomicalUnits => 18,
        InsertionUnit::LightYears => 19,
        InsertionUnit::Parsecs => 20,
        InsertionUnit::UsSurveyFeet => 21,
        InsertionUnit::UsSurveyInches => 22,
        InsertionUnit::UsSurveyYards => 23,
        InsertionUnit::UsSurveyMiles => 24,
    }
}

fn reconciliation_mode_name(mode: LayerReconciliationMode) -> &'static str {
    match mode {
        LayerReconciliationMode::DrawingPolicy => "drawing_policy",
        LayerReconciliationMode::PreserveHost => "preserve_host",
        LayerReconciliationMode::SourceAuthoritative => "source_authoritative",
        LayerReconciliationMode::Synchronize => "synchronize",
    }
}

fn layer_property_name(property: XrefLayerProperty) -> &'static str {
    match property {
        XrefLayerProperty::Off => "off",
        XrefLayerProperty::Frozen => "frozen",
        XrefLayerProperty::Locked => "locked",
        XrefLayerProperty::IsPlottable => "is_plottable",
        XrefLayerProperty::ColorIndex => "color_index",
        XrefLayerProperty::LineType => "line_type",
        XrefLayerProperty::LineWeight => "line_weight",
    }
}

impl<Services> AttachXrefMutation<'_, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    fn validate_locked_operation(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        let snapshot = normalize_snapshot(
            self.core
                .services
                .reread_attachment_mutation_snapshot(context.host_path)
                .map_err(map_domain_error)?,
        )?;
        require_locked_drawing(&snapshot, &self.core.drawing)?;
        validate_name_collision(&snapshot, &self.attachment_name, None)?;
        let placement = resolve_placement(&snapshot, &self.placement)?;

        let virtual_attachment = XrefAttachmentRecord {
            handle: "1".to_owned(),
            name: self.attachment_name.clone(),
            saved_path: self.source_path.saved_path().to_owned(),
            path_mode: self.source_path.mode(),
            reference_type: self.request.reference_type,
            load_state: LoadState::Unavailable,
            instance_count: 0,
            definition_base_point: XrefPointAvailability::Unavailable,
        };
        let graph_source = virtual_graph_source(&snapshot, virtual_attachment)?;
        let graph = inspect_source_graph(
            self.core.services,
            &graph_source,
            "1",
            self.request.search_paths.as_deref().unwrap_or_default(),
        )?;
        let (root_source_id, locked_sources) =
            require_declared_sources(&self.core.sources, &graph)?;
        self.core.sources = locked_sources;
        validate_unit_assumptions(
            self.core.services,
            context,
            XrefMutationOperation::AttachXref,
            &graph.traversal,
            self.request.unit_assumptions.as_ref(),
        )?;
        self.core.locked = Some(LockedOperationState {
            snapshot,
            selected: None,
            selected_instances: Vec::new(),
            placement: Some(placement),
            source_graph: Some(graph.traversal),
            root_source_id: Some(root_source_id),
            reconciliation_request: None,
            reconciliation_evidence: None,
            preservation_profile_id: context.admission.preservation_profile.profile_id.clone(),
            case_rename_temporary_name: None,
        });
        Ok(())
    }
}

impl<Services> UpdateXrefMutation<'_, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    fn validate_locked_operation(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        let snapshot = normalize_snapshot(
            self.core
                .services
                .reread_attachment_mutation_snapshot(context.host_path)
                .map_err(map_domain_error)?,
        )?;
        require_locked_drawing(&snapshot, &self.core.drawing)?;
        let selected = resolve_attachment(&snapshot, &self.selector)?;
        apply_attachment_guards(&selected, &self.guards)?;
        let selected_instances = instances_for(&snapshot, &selected.handle);

        if let Some(name) = &self.properties.name {
            validate_name_collision(&snapshot, name, Some(&selected.handle))?;
            let preflight = attachment_preflight(&snapshot, &selected.handle)?;
            if !preflight.dependent_symbols_complete {
                return Err(unsupported_data(
                    "attachment rename requires complete dependent-symbol evidence",
                ));
            }
        }
        check_clip_policy(
            &snapshot,
            &selected,
            &selected_instances,
            context.admission.rejects_clipped_targets(),
        )?;

        let mut source_graph = None;
        let mut root_source_id = None;
        let mut reconciliation_request = None;
        let mut reconciliation_result = None;
        if let Some(path) = &self.properties.xref_path {
            let mut replacement = selected.clone();
            replacement.saved_path = path.saved_path().to_owned();
            replacement.path_mode = path.mode();
            if let Some(name) = &self.properties.name {
                replacement.name = name.clone();
            }
            if let Some(reference_type) = self.properties.reference_type {
                replacement.reference_type = reference_type;
            }
            let graph_source = virtual_graph_source(&snapshot, replacement)?;
            let graph = inspect_source_graph(
                self.core.services,
                &graph_source,
                &selected.handle,
                self.request.search_paths.as_deref().unwrap_or_default(),
            )?;
            let (locked_root_source_id, locked_sources) =
                require_declared_sources(&self.core.sources, &graph)?;
            self.core.sources = locked_sources;
            root_source_id = Some(locked_root_source_id);
            validate_unit_assumptions(
                self.core.services,
                context,
                XrefMutationOperation::UpdateXref,
                &graph.traversal,
                self.request.unit_assumptions.as_ref(),
            )?;
            if !snapshot.reconciliation_layers_complete {
                return Err(unsupported_data(
                    "path-changing update requires complete seven-property layer evidence",
                ));
            }
            let reconciliation = self
                .core
                .reconciliation
                .clone()
                .expect("path-changing update installs default reconciliation");
            reconciliation_result = Some(reconciliation_evidence(
                &reconciliation,
                snapshot.saved_visretain,
            ));
            reconciliation_request = Some(reconciliation);
            source_graph = Some(graph.traversal);
        }
        let temporary_name =
            case_rename_temporary_name(&snapshot, &selected, self.properties.name.as_deref());
        self.core.locked = Some(LockedOperationState {
            snapshot,
            selected: Some(selected),
            selected_instances,
            placement: None,
            source_graph,
            root_source_id,
            reconciliation_request,
            reconciliation_evidence: reconciliation_result,
            preservation_profile_id: context.admission.preservation_profile.profile_id.clone(),
            case_rename_temporary_name: temporary_name,
        });
        Ok(())
    }
}

impl<Services> UnloadXrefMutation<'_, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    fn validate_locked_operation(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        let snapshot = normalize_snapshot(
            self.core
                .services
                .reread_attachment_mutation_snapshot(context.host_path)
                .map_err(map_domain_error)?,
        )?;
        require_locked_drawing(&snapshot, &self.core.drawing)?;
        let selected = resolve_attachment(&snapshot, &self.selector)?;
        apply_attachment_guards(&selected, &self.guards)?;
        let selected_instances = instances_for(&snapshot, &selected.handle);
        check_clip_policy(
            &snapshot,
            &selected,
            &selected_instances,
            context.admission.rejects_clipped_targets(),
        )?;
        self.core.locked = Some(LockedOperationState {
            snapshot,
            selected: Some(selected),
            selected_instances,
            placement: None,
            source_graph: None,
            root_source_id: None,
            reconciliation_request: None,
            reconciliation_evidence: None,
            preservation_profile_id: context.admission.preservation_profile.profile_id.clone(),
            case_rename_temporary_name: None,
        });
        Ok(())
    }
}

impl<Services> ReloadXrefMutation<'_, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    fn validate_locked_operation(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        let snapshot = normalize_snapshot(
            self.core
                .services
                .reread_attachment_mutation_snapshot(context.host_path)
                .map_err(map_domain_error)?,
        )?;
        require_locked_drawing(&snapshot, &self.core.drawing)?;
        let selected = resolve_attachment(&snapshot, &self.selector)?;
        apply_attachment_guards(&selected, &self.guards)?;
        let selected_instances = instances_for(&snapshot, &selected.handle);
        check_clip_policy(
            &snapshot,
            &selected,
            &selected_instances,
            context.admission.rejects_clipped_targets(),
        )?;
        let graph = inspect_source_graph(
            self.core.services,
            &snapshot.graph_source,
            &selected.handle,
            self.request.search_paths.as_deref().unwrap_or_default(),
        )?;
        let (root_source_id, locked_sources) =
            require_declared_sources(&self.core.sources, &graph)?;
        self.core.sources = locked_sources;
        validate_unit_assumptions(
            self.core.services,
            context,
            XrefMutationOperation::ReloadXref,
            &graph.traversal,
            self.request.unit_assumptions.as_ref(),
        )?;
        if !snapshot.reconciliation_layers_complete {
            return Err(unsupported_data(
                "reload requires complete seven-property layer evidence",
            ));
        }
        let reconciliation = self
            .core
            .reconciliation
            .clone()
            .expect("reload always installs default reconciliation");
        let reconciliation_result =
            reconciliation_evidence(&reconciliation, snapshot.saved_visretain);
        self.core.locked = Some(LockedOperationState {
            snapshot,
            selected: Some(selected),
            selected_instances,
            placement: None,
            source_graph: Some(graph.traversal),
            root_source_id: Some(root_source_id),
            reconciliation_request: Some(reconciliation),
            reconciliation_evidence: Some(reconciliation_result),
            preservation_profile_id: context.admission.preservation_profile.profile_id.clone(),
            case_rename_temporary_name: None,
        });
        Ok(())
    }
}

impl<Services> DetachXrefMutation<'_, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    fn validate_locked_operation(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        let snapshot = normalize_snapshot(
            self.core
                .services
                .reread_attachment_mutation_snapshot(context.host_path)
                .map_err(map_domain_error)?,
        )?;
        require_locked_drawing(&snapshot, &self.core.drawing)?;
        let selected = resolve_attachment(&snapshot, &self.selector)?;
        apply_attachment_guards(&selected, &self.guards)?;
        let selected_instances = instances_for(&snapshot, &selected.handle);
        apply_destructive_guards(
            &selected,
            &selected_instances,
            self.expected_instance_count,
            self.expected_instance_handles.as_deref(),
        )?;
        validate_detach_preflight(
            &snapshot,
            &selected,
            &selected_instances,
            context.admission.rejects_clipped_targets(),
        )?;
        self.core.locked = Some(LockedOperationState {
            snapshot,
            selected: Some(selected),
            selected_instances,
            placement: None,
            source_graph: None,
            root_source_id: None,
            reconciliation_request: None,
            reconciliation_evidence: None,
            preservation_profile_id: context.admission.preservation_profile.profile_id.clone(),
            case_rename_temporary_name: None,
        });
        Ok(())
    }
}

fn require_locked_drawing(
    snapshot: &XrefAttachmentMutationSnapshot,
    expected: &str,
) -> Result<(), XrefTransactionError> {
    if snapshot.drawing != expected {
        return Err(unsupported_data(format!(
            "portable locked reread returned `{}` instead of `{expected}`",
            snapshot.drawing
        )));
    }
    Ok(())
}

impl<Services> XrefMutationOperationCallback for AttachXrefMutation<'_, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    type Response = AttachXrefResponse;

    fn validate_locked(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        self.validate_locked_operation(context)
    }

    fn locked_source_inputs(&self) -> Option<&[XrefSourceInput]> {
        Some(&self.core.sources)
    }

    fn execute(
        &mut self,
        engine: &mut dyn XrefMutationEngineBoundary,
        context: &XrefOperationContext<'_>,
    ) -> Result<Vec<PathBuf>, XrefTransactionError> {
        self.core.verify_source_snapshots(context)?;
        let state = self.core.locked()?.clone();
        let root = root_snapshot_path(&state, context.source_snapshots)?;
        let placement = state
            .placement
            .as_ref()
            .expect("attach locked validation resolves placement");
        let sentinel = context.staging_directory.join(format!(
            "{}{}",
            self.core.operation.as_str(),
            SENTINEL_SUFFIX
        ));
        let program = render_attach_program(
            &sentinel,
            root,
            &self.attachment_name,
            self.source_path.saved_path(),
            self.request.reference_type,
            placement,
            self.request.unit_assumptions.as_ref(),
        )?;
        self.core
            .write_and_schedule_script(engine, context, program)
    }

    fn verify(
        &mut self,
        context: &XrefVerificationContext<'_>,
    ) -> Result<Self::Response, XrefTransactionError> {
        self.core.verify_sentinel()?;
        verify_captured_sources_for_output(&self.core.sources, context.source_snapshots)?;
        let state = self.core.locked()?.clone();
        let after = normalize_snapshot(
            self.core
                .services
                .reread_attachment_mutation_snapshot(context.temporary_host)
                .map_err(map_domain_error)?,
        )?;
        let (attachment, instance) = verify_attach_output(
            &state,
            &after,
            &self.attachment_name,
            self.source_path.saved_path(),
            self.request.reference_type,
        )?;
        verify_common_preservation(
            self.core.services,
            self.core.operation,
            &state,
            &after,
            Some(&attachment.handle),
            context.source_snapshots,
        )?;
        Ok(AttachXrefResponse {
            status: AttachXrefStatus::Attached,
            drawing: self.core.drawing.clone(),
            attachment,
            instance,
        })
    }
}

impl<Services> XrefMutationOperationCallback for UpdateXrefMutation<'_, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    type Response = UpdateXrefResponse;

    fn validate_locked(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        self.validate_locked_operation(context)
    }

    fn locked_source_inputs(&self) -> Option<&[XrefSourceInput]> {
        Some(&self.core.sources)
    }

    fn execute(
        &mut self,
        engine: &mut dyn XrefMutationEngineBoundary,
        context: &XrefOperationContext<'_>,
    ) -> Result<Vec<PathBuf>, XrefTransactionError> {
        self.core.verify_source_snapshots(context)?;
        let state = self.core.locked()?.clone();
        let root = if self.properties.xref_path.is_some() {
            Some(root_snapshot_path(&state, context.source_snapshots)?)
        } else {
            None
        };
        let sentinel = context.staging_directory.join(format!(
            "{}{}",
            self.core.operation.as_str(),
            SENTINEL_SUFFIX
        ));
        let program = render_update_program(
            &sentinel,
            state
                .selected
                .as_ref()
                .expect("update locked validation resolves attachment"),
            &self.properties,
            root,
            state.case_rename_temporary_name.as_deref(),
            state.reconciliation_request.as_ref(),
            state.snapshot.saved_visretain,
            state.snapshot.saved_xrefoverride,
            self.request.unit_assumptions.as_ref(),
        )?;
        self.core
            .write_and_schedule_script(engine, context, program)
    }

    fn verify(
        &mut self,
        context: &XrefVerificationContext<'_>,
    ) -> Result<Self::Response, XrefTransactionError> {
        self.core.verify_sentinel()?;
        verify_captured_sources_for_output(&self.core.sources, context.source_snapshots)?;
        let state = self.core.locked()?.clone();
        let after = normalize_snapshot(
            self.core
                .services
                .reread_attachment_mutation_snapshot(context.temporary_host)
                .map_err(map_domain_error)?,
        )?;
        let attachment = verify_update_output(&state, &after, &self.properties)?;
        verify_common_preservation(
            self.core.services,
            self.core.operation,
            &state,
            &after,
            Some(&attachment.handle),
            context.source_snapshots,
        )?;
        verify_reconciliation_if_present(self.core.services, &state, &after)?;
        Ok(UpdateXrefResponse {
            status: UpdateXrefStatus::Updated,
            drawing: self.core.drawing.clone(),
            attachment,
            layer_reconciliation: state.reconciliation_evidence,
        })
    }
}

impl<Services> XrefMutationOperationCallback for UnloadXrefMutation<'_, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    type Response = UnloadXrefResponse;

    fn validate_locked(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        self.validate_locked_operation(context)
    }

    fn execute(
        &mut self,
        engine: &mut dyn XrefMutationEngineBoundary,
        context: &XrefOperationContext<'_>,
    ) -> Result<Vec<PathBuf>, XrefTransactionError> {
        self.core.verify_source_snapshots(context)?;
        let state = self.core.locked()?.clone();
        let sentinel = context.staging_directory.join(format!(
            "{}{}",
            self.core.operation.as_str(),
            SENTINEL_SUFFIX
        ));
        let program = render_unload_program(
            &sentinel,
            state
                .selected
                .as_ref()
                .expect("unload locked validation resolves attachment"),
        )?;
        self.core
            .write_and_schedule_script(engine, context, program)
    }

    fn verify(
        &mut self,
        context: &XrefVerificationContext<'_>,
    ) -> Result<Self::Response, XrefTransactionError> {
        self.core.verify_sentinel()?;
        verify_captured_sources_for_output(&self.core.sources, context.source_snapshots)?;
        let state = self.core.locked()?.clone();
        let after = normalize_snapshot(
            self.core
                .services
                .reread_attachment_mutation_snapshot(context.temporary_host)
                .map_err(map_domain_error)?,
        )?;
        let attachment = verify_unload_output(&state, &after)?;
        verify_common_preservation(
            self.core.services,
            self.core.operation,
            &state,
            &after,
            Some(&attachment.handle),
            context.source_snapshots,
        )?;
        Ok(UnloadXrefResponse {
            status: UnloadXrefStatus::Unloaded,
            drawing: self.core.drawing.clone(),
            attachment,
        })
    }
}

impl<Services> XrefMutationOperationCallback for ReloadXrefMutation<'_, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    type Response = ReloadXrefResponse;

    fn validate_locked(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        self.validate_locked_operation(context)
    }

    fn locked_source_inputs(&self) -> Option<&[XrefSourceInput]> {
        Some(&self.core.sources)
    }

    fn execute(
        &mut self,
        engine: &mut dyn XrefMutationEngineBoundary,
        context: &XrefOperationContext<'_>,
    ) -> Result<Vec<PathBuf>, XrefTransactionError> {
        self.core.verify_source_snapshots(context)?;
        let state = self.core.locked()?.clone();
        let root = root_snapshot_path(&state, context.source_snapshots)?;
        let sentinel = context.staging_directory.join(format!(
            "{}{}",
            self.core.operation.as_str(),
            SENTINEL_SUFFIX
        ));
        let program = render_reload_program(
            &sentinel,
            state
                .selected
                .as_ref()
                .expect("reload locked validation resolves attachment"),
            root,
            state
                .reconciliation_request
                .as_ref()
                .expect("reload locked validation resolves reconciliation"),
            state.snapshot.saved_visretain,
            state.snapshot.saved_xrefoverride,
            self.request.unit_assumptions.as_ref(),
        )?;
        self.core
            .write_and_schedule_script(engine, context, program)
    }

    fn verify(
        &mut self,
        context: &XrefVerificationContext<'_>,
    ) -> Result<Self::Response, XrefTransactionError> {
        self.core.verify_sentinel()?;
        verify_captured_sources_for_output(&self.core.sources, context.source_snapshots)?;
        let state = self.core.locked()?.clone();
        let after = normalize_snapshot(
            self.core
                .services
                .reread_attachment_mutation_snapshot(context.temporary_host)
                .map_err(map_domain_error)?,
        )?;
        let attachment = verify_reload_output(&state, &after)?;
        verify_common_preservation(
            self.core.services,
            self.core.operation,
            &state,
            &after,
            Some(&attachment.handle),
            context.source_snapshots,
        )?;
        verify_reconciliation_if_present(self.core.services, &state, &after)?;
        Ok(ReloadXrefResponse {
            status: ReloadXrefStatus::Loaded,
            drawing: self.core.drawing.clone(),
            attachment,
            layer_reconciliation: state
                .reconciliation_evidence
                .expect("reload always returns reconciliation evidence"),
        })
    }
}

impl<Services> XrefMutationOperationCallback for DetachXrefMutation<'_, Services>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    type Response = DetachXrefResponse;

    fn validate_locked(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        self.validate_locked_operation(context)
    }

    fn execute(
        &mut self,
        engine: &mut dyn XrefMutationEngineBoundary,
        context: &XrefOperationContext<'_>,
    ) -> Result<Vec<PathBuf>, XrefTransactionError> {
        self.core.verify_source_snapshots(context)?;
        let state = self.core.locked()?.clone();
        let sentinel = context.staging_directory.join(format!(
            "{}{}",
            self.core.operation.as_str(),
            SENTINEL_SUFFIX
        ));
        let program = render_detach_program(
            &sentinel,
            state
                .selected
                .as_ref()
                .expect("detach locked validation resolves attachment"),
        )?;
        self.core
            .write_and_schedule_script(engine, context, program)
    }

    fn verify(
        &mut self,
        context: &XrefVerificationContext<'_>,
    ) -> Result<Self::Response, XrefTransactionError> {
        self.core.verify_sentinel()?;
        verify_captured_sources_for_output(&self.core.sources, context.source_snapshots)?;
        let state = self.core.locked()?.clone();
        let after = normalize_snapshot(
            self.core
                .services
                .reread_attachment_mutation_snapshot(context.temporary_host)
                .map_err(map_domain_error)?,
        )?;
        let deleted_instance_handles = verify_detach_output(&state, &after)?;
        let selected = state
            .selected
            .clone()
            .expect("detach locked validation resolves attachment");
        verify_common_preservation(
            self.core.services,
            self.core.operation,
            &state,
            &after,
            Some(&selected.handle),
            context.source_snapshots,
        )?;
        Ok(DetachXrefResponse {
            status: DetachXrefStatus::Detached,
            drawing: self.core.drawing.clone(),
            attachment: selected,
            deleted_instance_handles,
        })
    }
}

fn lisp_string(value: &str) -> Result<String, XrefTransactionError> {
    if value.chars().any(char::is_control) {
        return Err(write_failed(
            "AutoLISP operation values must not contain control characters",
        ));
    }
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            _ => escaped.push(character),
        }
    }
    escaped.push('"');
    Ok(escaped)
}

fn lisp_path(path: &Path) -> Result<String, XrefTransactionError> {
    let value = path
        .to_str()
        .ok_or_else(|| write_failed("staged AutoLISP path is not UTF-8"))?
        .replace('\\', "/");
    lisp_string(&value)
}

fn lisp_number(value: f64) -> String {
    if value == 0.0 {
        return "0.0".to_owned();
    }
    let mut rendered = format!("{value:.17}");
    while rendered.contains('.') && rendered.ends_with('0') {
        rendered.pop();
    }
    if rendered.ends_with('.') {
        rendered.push('0');
    }
    rendered
}

fn lisp_point(point: XrefPoint3) -> String {
    format!(
        "(vlax-3d-point {} {} {})",
        lisp_number(point.x),
        lisp_number(point.y),
        lisp_number(point.z)
    )
}

fn unit_setup(assumptions: Option<&XrefUnitAssumptions>) -> String {
    let mut setup = String::new();
    if let Some(unit) = assumptions.and_then(|value| value.source_units) {
        setup.push_str(&format!(
            "  (setvar \"INSUNITSDEFSOURCE\" {})\n",
            insertion_unit_code(unit)
        ));
    }
    if let Some(unit) = assumptions.and_then(|value| value.host_units) {
        setup.push_str(&format!(
            "  (setvar \"INSUNITSDEFTARGET\" {})\n",
            insertion_unit_code(unit)
        ));
    }
    setup
}

fn reconciliation_setup(
    reconciliation: &XrefLayerReconciliation,
    saved_visretain: i16,
    saved_xrefoverride: i16,
) -> String {
    let evidence = reconciliation_evidence(reconciliation, saved_visretain);
    let temporary_visretain = match evidence.effective_mode {
        EffectiveLayerReconciliationMode::SourceAuthoritative => 0,
        EffectiveLayerReconciliationMode::PreserveHost
        | EffectiveLayerReconciliationMode::Synchronize => 1,
    };
    let mask = if reconciliation.mode == LayerReconciliationMode::Synchronize {
        visretainmode_mask(reconciliation.properties.as_deref().unwrap_or_default())
    } else {
        0
    };
    format!(
        "  (setvar \"VISRETAIN\" {temporary_visretain})\n  (setvar \"XREFOVERRIDE\" {saved_xrefoverride})\n  (setvar \"VISRETAINMODE\" {mask})\n"
    )
}

fn reconciliation_cleanup(saved_visretain: i16, saved_xrefoverride: i16) -> String {
    format!(
        "  (setvar \"VISRETAIN\" {saved_visretain})\n  (setvar \"XREFOVERRIDE\" {saved_xrefoverride})\n"
    )
}

fn common_lisp_helpers() -> &'static str {
    r#"(vl-load-com)
(defun amcp-block (doc handle name / block)
  (setq block (vla-Item (vla-get-Blocks doc) name))
  (if (/= (strcase (vla-get-Handle block)) handle)
    (error "AUTOCAD_MCP_XREF_HANDLE_MISMATCH"))
  block)
(defun amcp-set-saved-path (name path / entity data pair)
  (setq entity (tblobjname "BLOCK" name))
  (if (null entity) (error "AUTOCAD_MCP_XREF_BLOCK_MISSING"))
  (setq data (entget entity) pair (assoc 1 data))
  (if pair
    (setq data (subst (cons 1 path) pair data))
    (setq data (append data (list (cons 1 path)))))
  (if (null (entmod data)) (error "AUTOCAD_MCP_XREF_PATH_WRITE_FAILED")))
(defun amcp-set-reference-type (name flag / entity data pair flags)
  (setq entity (tblobjname "BLOCK" name))
  (if (null entity) (error "AUTOCAD_MCP_XREF_BLOCK_MISSING"))
  (setq data (entget entity) pair (assoc 70 data))
  (if (null pair) (error "AUTOCAD_MCP_XREF_FLAGS_MISSING"))
  (setq flags (logior (logand (cdr pair) (lognot 12)) flag))
  (if (null (entmod (subst (cons 70 flags) pair data)))
    (error "AUTOCAD_MCP_XREF_TYPE_WRITE_FAILED")))
"#
}

fn render_program(
    operation: &str,
    sentinel_path: &Path,
    setup: &str,
    body: &str,
    cleanup: &str,
) -> Result<String, XrefTransactionError> {
    let sentinel = lisp_path(sentinel_path)?;
    let operation_string = lisp_string(operation)?;
    Ok(format!(
        "{}\
(defun amcp-sentinel-begin (/ stream)\n\
  (setq stream (open {sentinel} \"w\"))\n\
  (if (null stream) (error \"AUTOCAD_MCP_XREF_SENTINEL_OPEN_FAILED\"))\n\
  (write-line \"schema={SENTINEL_SCHEMA}\" stream)\n\
  (write-line \"operation={operation}\" stream)\n\
  (write-line \"state=begin\" stream)\n\
  (close stream)\n\
  (princ (strcat \"\\nAUTOCAD_MCP_XREF_SENTINEL|1|\" {operation_string} \"|BEGIN\")))\n\
(defun amcp-sentinel-finish (state / stream)\n\
  (setq stream (open {sentinel} \"a\"))\n\
  (if (null stream) (error \"AUTOCAD_MCP_XREF_SENTINEL_OPEN_FAILED\"))\n\
  (write-line (strcat \"state=\" state) stream)\n\
  (close stream)\n\
  (princ (strcat \"\\nAUTOCAD_MCP_XREF_SENTINEL|1|\" {operation_string} \"|\" (strcase state))))\n\
(defun amcp-perform (/ doc block reference owner)\n\
{setup}{body}  nil)\n\
(defun amcp-cleanup ()\n\
{cleanup}  nil)\n\
(defun autocad-mcp-xref-operation (/ result cleanup-result)\n\
  (amcp-sentinel-begin)\n\
  (setq result (vl-catch-all-apply 'amcp-perform '()))\n\
  (setq cleanup-result (vl-catch-all-apply 'amcp-cleanup '()))\n\
  (if (or (vl-catch-all-error-p result) (vl-catch-all-error-p cleanup-result))\n\
    (amcp-sentinel-finish \"error\")\n\
    (amcp-sentinel-finish \"ok\"))\n\
  (princ))\n\
(princ)\n",
        common_lisp_helpers()
    ))
}

fn render_attach_program(
    sentinel: &Path,
    root_snapshot: &Path,
    name: &str,
    saved_path: &str,
    reference_type: ReferenceType,
    placement: &ResolvedPlacement,
    assumptions: Option<&XrefUnitAssumptions>,
) -> Result<String, XrefTransactionError> {
    let source = lisp_path(root_snapshot)?;
    let name = lisp_string(name)?;
    let saved_path = lisp_string(saved_path)?;
    let owner = lisp_string(&placement.owner.handle)?;
    let layer = lisp_string(&placement.layer.name)?;
    let overlay = match reference_type {
        ReferenceType::Attachment => ":vlax-false",
        ReferenceType::Overlay => ":vlax-true",
    };
    let visible = match placement.visibility {
        XrefVisibility::Visible => ":vlax-true",
        XrefVisibility::Hidden => ":vlax-false",
    };
    let rotation_radians = placement.rotation_degrees.to_radians();
    let body = format!(
        "  (setq doc (vla-get-ActiveDocument (vlax-get-acad-object)))\n\
  (setq owner (vlax-ename->vla-object (handent {owner})))\n\
  (if (null owner) (error \"AUTOCAD_MCP_XREF_OWNER_MISSING\"))\n\
  (setq reference (vla-AttachExternalReference owner {source} {name} {} {} {} {} {} {overlay}))\n\
  (vla-put-Layer reference {layer})\n\
  (vla-put-Normal reference {})\n\
  (vla-put-Visible reference {visible})\n\
  (amcp-set-saved-path {name} {saved_path})\n",
        lisp_point(placement.insertion_point),
        lisp_number(placement.scale.x),
        lisp_number(placement.scale.y),
        lisp_number(placement.scale.z),
        lisp_number(rotation_radians),
        lisp_point(XrefPoint3 {
            x: placement.normal.x,
            y: placement.normal.y,
            z: placement.normal.z,
        }),
    );
    render_program(
        XrefMutationOperation::AttachXref.as_str(),
        sentinel,
        &unit_setup(assumptions),
        &body,
        "",
    )
}

#[allow(clippy::too_many_arguments)]
fn render_update_program(
    sentinel: &Path,
    selected: &XrefAttachmentRecord,
    properties: &ParsedAttachmentUpdate,
    root_snapshot: Option<&Path>,
    case_temporary_name: Option<&str>,
    reconciliation: Option<&XrefLayerReconciliation>,
    saved_visretain: i16,
    saved_xrefoverride: i16,
    assumptions: Option<&XrefUnitAssumptions>,
) -> Result<String, XrefTransactionError> {
    let handle = lisp_string(&selected.handle)?;
    let old_name = lisp_string(&selected.name)?;
    let mut body = format!(
        "  (setq doc (vla-get-ActiveDocument (vlax-get-acad-object)))\n  (setq block (amcp-block doc {handle} {old_name}))\n"
    );
    if let Some(path) = &properties.xref_path {
        if selected.load_state == LoadState::Unloaded {
            body.push_str(&format!(
                "  (amcp-set-saved-path {old_name} {})\n",
                lisp_string(path.saved_path())?
            ));
        } else {
            let root = root_snapshot.ok_or_else(|| {
                write_failed("path-changing update has no isolated root snapshot")
            })?;
            body.push_str(&format!(
                "  (vla-put-Path block {})\n  (vla-Reload block)\n  (amcp-set-saved-path {old_name} {})\n",
                lisp_path(root)?,
                lisp_string(path.saved_path())?
            ));
        }
    }
    if let Some(reference_type) = properties.reference_type {
        let flag = match reference_type {
            ReferenceType::Attachment => 4,
            ReferenceType::Overlay => 8,
        };
        body.push_str(&format!("  (amcp-set-reference-type {old_name} {flag})\n"));
    }
    if let Some(name) = &properties.name {
        if let Some(temporary) = case_temporary_name {
            body.push_str(&format!(
                "  (vla-put-Name block {})\n",
                lisp_string(temporary)?
            ));
        }
        body.push_str(&format!("  (vla-put-Name block {})\n", lisp_string(name)?));
    }
    let mut setup = unit_setup(assumptions);
    let cleanup = if let Some(reconciliation) = reconciliation {
        setup.push_str(&reconciliation_setup(
            reconciliation,
            saved_visretain,
            saved_xrefoverride,
        ));
        reconciliation_cleanup(saved_visretain, saved_xrefoverride)
    } else {
        String::new()
    };
    render_program(
        XrefMutationOperation::UpdateXref.as_str(),
        sentinel,
        &setup,
        &body,
        &cleanup,
    )
}

fn render_unload_program(
    sentinel: &Path,
    selected: &XrefAttachmentRecord,
) -> Result<String, XrefTransactionError> {
    let handle = lisp_string(&selected.handle)?;
    let name = lisp_string(&selected.name)?;
    let action = if selected.load_state == LoadState::Unloaded {
        "  nil\n".to_owned()
    } else {
        "  (vla-Unload block)\n".to_owned()
    };
    let body = format!(
        "  (setq doc (vla-get-ActiveDocument (vlax-get-acad-object)))\n  (setq block (amcp-block doc {handle} {name}))\n{action}"
    );
    render_program(
        XrefMutationOperation::UnloadXref.as_str(),
        sentinel,
        "",
        &body,
        "",
    )
}

#[allow(clippy::too_many_arguments)]
fn render_reload_program(
    sentinel: &Path,
    selected: &XrefAttachmentRecord,
    root_snapshot: &Path,
    reconciliation: &XrefLayerReconciliation,
    saved_visretain: i16,
    saved_xrefoverride: i16,
    assumptions: Option<&XrefUnitAssumptions>,
) -> Result<String, XrefTransactionError> {
    let handle = lisp_string(&selected.handle)?;
    let name = lisp_string(&selected.name)?;
    let body = format!(
        "  (setq doc (vla-get-ActiveDocument (vlax-get-acad-object)))\n\
  (setq block (amcp-block doc {handle} {name}))\n\
  (vla-put-Path block {})\n\
  (vla-Reload block)\n\
  (amcp-set-saved-path {name} {})\n",
        lisp_path(root_snapshot)?,
        lisp_string(&selected.saved_path)?
    );
    let mut setup = unit_setup(assumptions);
    setup.push_str(&reconciliation_setup(
        reconciliation,
        saved_visretain,
        saved_xrefoverride,
    ));
    render_program(
        XrefMutationOperation::ReloadXref.as_str(),
        sentinel,
        &setup,
        &body,
        &reconciliation_cleanup(saved_visretain, saved_xrefoverride),
    )
}

fn render_detach_program(
    sentinel: &Path,
    selected: &XrefAttachmentRecord,
) -> Result<String, XrefTransactionError> {
    let handle = lisp_string(&selected.handle)?;
    let name = lisp_string(&selected.name)?;
    let body = format!(
        "  (setq doc (vla-get-ActiveDocument (vlax-get-acad-object)))\n  (setq block (amcp-block doc {handle} {name}))\n  (vla-Detach block)\n"
    );
    render_program(
        XrefMutationOperation::DetachXref.as_str(),
        sentinel,
        "",
        &body,
        "",
    )
}

fn verify_sentinel_file(path: &Path, operation: &str) -> Result<(), XrefTransactionError> {
    let value = fs::read_to_string(path).map_err(|error| {
        verification_failed(format!(
            "read {operation} machine sentinel {}: {error}",
            path.display()
        ))
    })?;
    let expected =
        format!("schema={SENTINEL_SCHEMA}\noperation={operation}\nstate=begin\nstate=ok\n");
    if value != expected {
        return Err(verification_failed(format!(
            "{operation} machine sentinel is missing, malformed, or reports an error"
        )));
    }
    Ok(())
}

fn verify_captured_sources_for_output(
    declared: &[XrefSourceInput],
    snapshots: &[XrefSourceSnapshot],
) -> Result<(), XrefTransactionError> {
    if declared.len() != snapshots.len()
        || declared.iter().zip(snapshots).any(|(declared, snapshot)| {
            declared.source_id != snapshot.source_id
                || declared.path != snapshot.original_path
                || declared.saved_path != snapshot.saved_path
                || declared.immediate_host_source_id != snapshot.immediate_host_source_id
                || declared.filesystem_identity != snapshot.filesystem_identity
                || declared.inspected_digest_sha256.as_deref()
                    != Some(snapshot.digest_sha256.as_str())
                || snapshot.snapshot_path == snapshot.original_path
        })
    {
        return Err(verification_failed(
            "verification source snapshots differ from locked source graph",
        ));
    }
    Ok(())
}

fn verify_common_preservation<Services>(
    services: &mut Services,
    operation: XrefMutationOperation,
    state: &LockedOperationState,
    after: &XrefAttachmentMutationSnapshot,
    selected_attachment_handle: Option<&str>,
    source_snapshots: &[XrefSourceSnapshot],
) -> Result<(), XrefTransactionError>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    if state.snapshot.saved_visretain != after.saved_visretain
        || state.snapshot.saved_xrefoverride != after.saved_xrefoverride
    {
        return Err(verification_failed(
            "mutation changed saved VISRETAIN or XREFOVERRIDE",
        ));
    }
    services
        .verify_attachment_preservation(&XrefPreservationVerification {
            operation,
            profile_id: &state.preservation_profile_id,
            before: &state.snapshot,
            after,
            selected_attachment_handle,
            source_graph: state.source_graph.as_ref(),
            source_snapshots,
        })
        .map_err(|error| verification_failed(error.to_string()))
}

fn verify_reconciliation_if_present<Services>(
    services: &mut Services,
    state: &LockedOperationState,
    after: &XrefAttachmentMutationSnapshot,
) -> Result<(), XrefTransactionError>
where
    Services: XrefAttachmentMutationServices + ?Sized,
{
    let (Some(request), Some(evidence), Some(selected)) = (
        state.reconciliation_request.as_ref(),
        state.reconciliation_evidence.as_ref(),
        state.selected.as_ref(),
    ) else {
        return Ok(());
    };
    if !after.reconciliation_layers_complete {
        return Err(verification_failed(
            "post-mutation seven-property layer evidence is incomplete",
        ));
    }
    services
        .verify_layer_reconciliation(&XrefReconciliationVerification {
            attachment_handle: &selected.handle,
            request,
            evidence,
            before: &state.snapshot,
            after,
        })
        .map_err(|error| verification_failed(error.to_string()))
}

fn verify_unchanged_non_target(
    before: &XrefAttachmentMutationSnapshot,
    after: &XrefAttachmentMutationSnapshot,
    target_handle: Option<&str>,
) -> Result<(), XrefTransactionError> {
    for attachment in &before.attachments {
        if Some(attachment.handle.as_str()) == target_handle {
            continue;
        }
        if !after
            .attachments
            .iter()
            .any(|candidate| candidate == attachment)
        {
            return Err(verification_failed(format!(
                "unrelated attachment {} changed or disappeared",
                attachment.handle
            )));
        }
    }
    for instance in &before.instances {
        if target_handle == Some(instance.attachment_handle.as_str()) {
            continue;
        }
        if !after
            .instances
            .iter()
            .any(|candidate| candidate == instance)
        {
            return Err(verification_failed(format!(
                "unrelated XREF instance {} changed or disappeared",
                instance.handle
            )));
        }
    }
    Ok(())
}

fn verify_attach_output(
    state: &LockedOperationState,
    after: &XrefAttachmentMutationSnapshot,
    name: &str,
    saved_path: &str,
    reference_type: ReferenceType,
) -> Result<(XrefAttachmentRecord, XrefInstanceRecord), XrefTransactionError> {
    verify_unchanged_non_target(&state.snapshot, after, None)?;
    let old_attachment_handles = state
        .snapshot
        .attachments
        .iter()
        .map(|attachment| attachment.handle.as_str())
        .collect::<BTreeSet<_>>();
    let created_attachments = after
        .attachments
        .iter()
        .filter(|attachment| !old_attachment_handles.contains(attachment.handle.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let [attachment] = created_attachments.as_slice() else {
        return Err(verification_failed(
            "attach_xref must create exactly one direct attachment",
        ));
    };
    let expected_mode = validate_mutation_source_path(saved_path)
        .map_err(|error| verification_failed(error.to_string()))?
        .mode();
    if attachment.name != name
        || attachment.saved_path != saved_path
        || attachment.path_mode != expected_mode
        || attachment.reference_type != reference_type
        || attachment.load_state != LoadState::Loaded
        || attachment.instance_count != 1
    {
        return Err(verification_failed(
            "persisted attached definition does not match requested name/path/type/load/count",
        ));
    }

    let old_instance_handles = state
        .snapshot
        .instances
        .iter()
        .map(|instance| instance.handle.as_str())
        .collect::<BTreeSet<_>>();
    let created_instances = after
        .instances
        .iter()
        .filter(|instance| !old_instance_handles.contains(instance.handle.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let [instance] = created_instances.as_slice() else {
        return Err(verification_failed(
            "attach_xref must create exactly one initial instance",
        ));
    };
    let placement = state
        .placement
        .as_ref()
        .expect("attach validation resolves placement");
    if instance.attachment_handle != attachment.handle
        || instance.attachment_name != name
        || instance.owner_handle != placement.owner.handle
        || instance.owner_type != placement.owner.owner_type
        || instance.owner_name != placement.owner.name
        || instance.layer_handle != placement.layer.handle
        || instance.layer_name != placement.layer.name
        || instance.insertion_point != placement.insertion_point
        || instance.scale != placement.scale
        || instance.rotation_degrees != placement.rotation_degrees
        || instance.normal != placement.normal
        || instance.visibility != placement.visibility
        || instance.placement_kind != XrefPlacementKind::Single
        || instance.array.is_some()
    {
        return Err(verification_failed(
            "initial attached instance does not match explicit deterministic placement",
        ));
    }
    Ok((attachment.clone(), instance.clone()))
}

fn verify_update_output(
    state: &LockedOperationState,
    after: &XrefAttachmentMutationSnapshot,
    properties: &ParsedAttachmentUpdate,
) -> Result<XrefAttachmentRecord, XrefTransactionError> {
    let before = state
        .selected
        .as_ref()
        .expect("update validation resolves attachment");
    if after.attachments.len() != state.snapshot.attachments.len()
        || after.instances.len() != state.snapshot.instances.len()
    {
        return Err(verification_failed(
            "update_xref created or deleted attachment resources",
        ));
    }
    verify_unchanged_non_target(&state.snapshot, after, Some(&before.handle))?;
    let attachment = after
        .attachments
        .iter()
        .find(|attachment| attachment.handle == before.handle)
        .cloned()
        .ok_or_else(|| verification_failed("updated attachment handle did not persist"))?;
    let expected_name = properties.name.as_deref().unwrap_or(&before.name);
    let expected_path = properties
        .xref_path
        .as_ref()
        .map(MutationSourcePath::saved_path)
        .unwrap_or(&before.saved_path);
    let expected_path_mode = properties
        .xref_path
        .as_ref()
        .map(MutationSourcePath::mode)
        .unwrap_or(before.path_mode);
    let expected_reference_type = properties.reference_type.unwrap_or(before.reference_type);
    let expected_load_state = if properties.xref_path.is_some() {
        if before.load_state == LoadState::Unloaded {
            LoadState::Unloaded
        } else {
            LoadState::Loaded
        }
    } else {
        before.load_state
    };
    if attachment.name != expected_name
        || attachment.saved_path != expected_path
        || attachment.path_mode != expected_path_mode
        || attachment.reference_type != expected_reference_type
        || attachment.load_state != expected_load_state
        || attachment.instance_count != before.instance_count
        || (properties.xref_path.is_none()
            && attachment.definition_base_point != before.definition_base_point)
    {
        return Err(verification_failed(
            "updated attachment did not persist the exact atomic property set",
        ));
    }
    verify_instance_identity_and_placement(
        &state.selected_instances,
        &instances_for(after, &before.handle),
        expected_name,
        properties.xref_path.is_some(),
    )?;
    if properties.name.is_some() && properties.xref_path.is_none() {
        verify_dependent_symbol_rename(state, after, expected_name)?;
    }
    Ok(attachment)
}

fn verify_unload_output(
    state: &LockedOperationState,
    after: &XrefAttachmentMutationSnapshot,
) -> Result<XrefAttachmentRecord, XrefTransactionError> {
    let before = state
        .selected
        .as_ref()
        .expect("unload validation resolves attachment");
    if after.attachments.len() != state.snapshot.attachments.len()
        || after.instances.len() != state.snapshot.instances.len()
    {
        return Err(verification_failed(
            "unload_xref created or deleted attachment resources",
        ));
    }
    verify_unchanged_non_target(&state.snapshot, after, Some(&before.handle))?;
    let attachment = after
        .attachments
        .iter()
        .find(|attachment| attachment.handle == before.handle)
        .cloned()
        .ok_or_else(|| verification_failed("unloaded attachment handle did not persist"))?;
    let mut expected = before.clone();
    expected.load_state = LoadState::Unloaded;
    if attachment != expected {
        return Err(verification_failed(
            "unload changed attachment facts other than load_state",
        ));
    }
    let instances = instances_for(after, &before.handle);
    if instances != state.selected_instances {
        return Err(verification_failed(
            "unload changed attachment instances or placement",
        ));
    }
    Ok(attachment)
}

fn verify_reload_output(
    state: &LockedOperationState,
    after: &XrefAttachmentMutationSnapshot,
) -> Result<XrefAttachmentRecord, XrefTransactionError> {
    let before = state
        .selected
        .as_ref()
        .expect("reload validation resolves attachment");
    if after.attachments.len() != state.snapshot.attachments.len()
        || after.instances.len() != state.snapshot.instances.len()
    {
        return Err(verification_failed(
            "reload_xref created or deleted attachment resources",
        ));
    }
    verify_unchanged_non_target(&state.snapshot, after, Some(&before.handle))?;
    let attachment = after
        .attachments
        .iter()
        .find(|attachment| attachment.handle == before.handle)
        .cloned()
        .ok_or_else(|| verification_failed("reloaded attachment handle did not persist"))?;
    if attachment.name != before.name
        || attachment.saved_path != before.saved_path
        || attachment.path_mode != before.path_mode
        || attachment.reference_type != before.reference_type
        || attachment.load_state != LoadState::Loaded
        || attachment.instance_count != before.instance_count
    {
        return Err(verification_failed(
            "reload changed attachment identity/path/type/count or did not persist loaded state",
        ));
    }
    verify_instance_identity_and_placement(
        &state.selected_instances,
        &instances_for(after, &before.handle),
        &before.name,
        true,
    )?;
    Ok(attachment)
}

fn verify_instance_identity_and_placement(
    before: &[XrefInstanceRecord],
    after: &[XrefInstanceRecord],
    expected_attachment_name: &str,
    allow_unit_scaling_change: bool,
) -> Result<(), XrefTransactionError> {
    if before.len() != after.len() {
        return Err(verification_failed(
            "attachment instance count changed unexpectedly",
        ));
    }
    for before in before {
        let after = after
            .iter()
            .find(|candidate| candidate.handle == before.handle)
            .ok_or_else(|| verification_failed("attachment instance handle did not persist"))?;
        if after.attachment_handle != before.attachment_handle
            || after.attachment_name != expected_attachment_name
            || after.owner_handle != before.owner_handle
            || after.owner_type != before.owner_type
            || after.owner_name != before.owner_name
            || after.layer_handle != before.layer_handle
            || after.layer_name != before.layer_name
            || after.insertion_point != before.insertion_point
            || after.scale != before.scale
            || after.rotation_degrees != before.rotation_degrees
            || after.normal != before.normal
            || after.visibility != before.visibility
            || after.placement_kind != before.placement_kind
            || after.array != before.array
            || (!allow_unit_scaling_change && after.unit_scaling != before.unit_scaling)
        {
            return Err(verification_failed(format!(
                "instance {} identity or placement changed",
                before.handle
            )));
        }
    }
    Ok(())
}

fn verify_dependent_symbol_rename(
    state: &LockedOperationState,
    after: &XrefAttachmentMutationSnapshot,
    new_name: &str,
) -> Result<(), XrefTransactionError> {
    let selected = state
        .selected
        .as_ref()
        .expect("rename validation resolves attachment");
    let before = attachment_preflight(&state.snapshot, &selected.handle)?;
    let after = attachment_preflight(after, &selected.handle)?;
    if !after.dependent_symbols_complete
        || before.dependent_symbols.len() != after.dependent_symbols.len()
    {
        return Err(verification_failed(
            "dependent symbol set is incomplete after attachment rename",
        ));
    }
    let old_prefix = format!("{}|", selected.name);
    let new_prefix = format!("{new_name}|");
    for symbol in &before.dependent_symbols {
        let persisted = after
            .dependent_symbols
            .iter()
            .find(|candidate| candidate.handle == symbol.handle)
            .ok_or_else(|| verification_failed("dependent symbol handle did not persist"))?;
        let expected_name = symbol
            .name
            .strip_prefix(&old_prefix)
            .map(|suffix| format!("{new_prefix}{suffix}"))
            .unwrap_or_else(|| symbol.name.clone());
        if persisted.name != expected_name
            || persisted.name.starts_with(&old_prefix)
            || (xref_name_eq(&selected.name, new_name) && persisted.name.starts_with(&old_prefix))
        {
            return Err(verification_failed(
                "dependent XREF namespace was not atomically renamed",
            ));
        }
    }
    Ok(())
}

fn verify_detach_output(
    state: &LockedOperationState,
    after: &XrefAttachmentMutationSnapshot,
) -> Result<Vec<String>, XrefTransactionError> {
    let selected = state
        .selected
        .as_ref()
        .expect("detach validation resolves attachment");
    if after.attachments.len().checked_add(1) != Some(state.snapshot.attachments.len())
        || after
            .instances
            .len()
            .checked_add(state.selected_instances.len())
            != Some(state.snapshot.instances.len())
    {
        return Err(verification_failed(
            "detach_xref deleted or created resources outside the selected attachment scope",
        ));
    }
    verify_unchanged_non_target(&state.snapshot, after, Some(&selected.handle))?;
    if after
        .attachments
        .iter()
        .any(|attachment| attachment.handle == selected.handle)
        || after
            .instances
            .iter()
            .any(|instance| instance.attachment_handle == selected.handle)
        || after
            .attachment_preflight
            .iter()
            .any(|preflight| preflight.attachment_handle == selected.handle)
    {
        return Err(verification_failed(
            "detached attachment, instances, or lifecycle projections remain persisted",
        ));
    }
    let before_preflight = attachment_preflight(&state.snapshot, &selected.handle)?;
    let deleted_symbol_handles = before_preflight
        .dependent_symbols
        .iter()
        .map(|symbol| symbol.handle.as_str())
        .collect::<BTreeSet<_>>();
    if after.attachment_preflight.iter().any(|preflight| {
        preflight
            .dependent_symbols
            .iter()
            .any(|symbol| deleted_symbol_handles.contains(symbol.handle.as_str()))
            || preflight
                .nested_attachment_chains
                .iter()
                .any(|chain| chain.first() == Some(&selected.handle))
    }) {
        return Err(verification_failed(
            "detach left dependent symbols or nested projections owned by the target",
        ));
    }
    let mut handles = state
        .selected_instances
        .iter()
        .map(|instance| instance.handle.clone())
        .collect::<Vec<_>>();
    sort_handles(&mut handles)?;
    if handles.len() as u64 != selected.instance_count {
        return Err(verification_failed(
            "pre-detach instance_count differs from deleted handle evidence",
        ));
    }
    Ok(handles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification::XrefMutationOperation;
    use crate::ops::{
        xref_graph::{XrefSourceInspection, XrefTraversalLimits},
        xref_path::{
            parse_saved_path, CandidateProbeResult, CanonicalExistingPath, FilesystemIdentity,
            ResolutionCandidate, ResolutionCandidateProbe, SearchPathInspection,
            SearchPathInspector,
        },
        xrefs::{
            XrefDependencyRecord, XrefPropagationState, XrefResolutionBasis, XrefResolutionState,
            XrefUnitScaling,
        },
    };
    use serde_json::json;
    use std::collections::VecDeque;

    fn attachment(
        handle: &str,
        name: &str,
        saved_path: &str,
        reference_type: ReferenceType,
        load_state: LoadState,
        instance_count: u64,
    ) -> XrefAttachmentRecord {
        XrefAttachmentRecord {
            handle: handle.to_owned(),
            name: name.to_owned(),
            saved_path: saved_path.to_owned(),
            path_mode: parse_saved_path(saved_path).mode(),
            reference_type,
            load_state,
            instance_count,
            definition_base_point: XrefPointAvailability::Unavailable,
        }
    }

    fn instance(
        handle: &str,
        attachment_handle: &str,
        attachment_name: &str,
    ) -> XrefInstanceRecord {
        XrefInstanceRecord {
            handle: handle.to_owned(),
            attachment_handle: attachment_handle.to_owned(),
            attachment_name: attachment_name.to_owned(),
            owner_handle: "10".to_owned(),
            owner_type: XrefOwnerType::ModelSpace,
            owner_name: "*Model_Space".to_owned(),
            layer_handle: "11".to_owned(),
            layer_name: "0".to_owned(),
            insertion_point: XrefPoint3 {
                x: 1.0,
                y: 2.0,
                z: 3.0,
            },
            scale: XrefScale3 {
                x: 1.0,
                y: 1.0,
                z: 1.0,
            },
            rotation_degrees: 0.0,
            normal: XrefVector3 {
                x: 0.0,
                y: 0.0,
                z: 1.0,
            },
            visibility: XrefVisibility::Visible,
            placement_kind: XrefPlacementKind::Single,
            array: None,
            unit_scaling: XrefUnitScaling::Unavailable,
        }
    }

    fn identity(value: &str) -> FilesystemIdentity {
        FilesystemIdentity::opaque(value.as_bytes().to_vec()).unwrap()
    }

    fn snapshot_at(
        drawing: &str,
        attachments: Vec<XrefAttachmentRecord>,
        instances: Vec<XrefInstanceRecord>,
    ) -> XrefAttachmentMutationSnapshot {
        let graph_source = XrefGraphSource::from_filesystem_canonical_path(
            drawing,
            identity(drawing),
            attachments.clone(),
        )
        .unwrap();
        let preflight = attachments
            .iter()
            .map(|attachment| {
                let instance_clips = instances
                    .iter()
                    .filter(|instance| instance.attachment_handle == attachment.handle)
                    .map(|instance| (instance.handle.clone(), XrefClipMutationEvidence::Absent))
                    .collect();
                XrefAttachmentPreflightEvidence {
                    attachment_handle: attachment.handle.clone(),
                    dependent_symbols_complete: true,
                    dependent_symbols: vec![XrefDependentSymbolEvidence {
                        handle: format!("3{}", attachment.handle),
                        name: format!("{}|WALL", attachment.name),
                    }],
                    nested_projections_complete: true,
                    nested_attachment_chains: Vec::new(),
                    clips_complete: true,
                    instance_clips,
                }
            })
            .collect();
        XrefAttachmentMutationSnapshot {
            drawing: drawing.to_owned(),
            graph_source,
            attachments: attachments.clone(),
            instances,
            block_definitions_complete: true,
            block_definitions: attachments
                .iter()
                .map(|attachment| XrefBlockDefinitionEvidence {
                    handle: attachment.handle.clone(),
                    name: attachment.name.clone(),
                })
                .chain([
                    XrefBlockDefinitionEvidence {
                        handle: "10".to_owned(),
                        name: "*Model_Space".to_owned(),
                    },
                    XrefBlockDefinitionEvidence {
                        handle: "12".to_owned(),
                        name: "*Paper_Space".to_owned(),
                    },
                    XrefBlockDefinitionEvidence {
                        handle: "13".to_owned(),
                        name: "*U1".to_owned(),
                    },
                    XrefBlockDefinitionEvidence {
                        handle: "14".to_owned(),
                        name: "DYNAMIC_DETAIL".to_owned(),
                    },
                ])
                .collect(),
            owners_complete: true,
            owners: vec![
                XrefOwnerMutationEvidence {
                    handle: "10".to_owned(),
                    owner_type: XrefOwnerType::ModelSpace,
                    name: "*Model_Space".to_owned(),
                    writable: true,
                },
                XrefOwnerMutationEvidence {
                    handle: "12".to_owned(),
                    owner_type: XrefOwnerType::PaperSpace,
                    name: "Sheet A".to_owned(),
                    writable: true,
                },
            ],
            layers_complete: true,
            layers: vec![
                XrefLayerMutationEvidence {
                    handle: "11".to_owned(),
                    name: "0".to_owned(),
                    host_owned: true,
                    locked: false,
                },
                XrefLayerMutationEvidence {
                    handle: "15".to_owned(),
                    name: "LOCKED".to_owned(),
                    host_owned: true,
                    locked: true,
                },
            ],
            attachment_preflight: preflight,
            reconciliation_layers_complete: true,
            reconciliation_layers: vec![XrefReconciliationLayerEvidence {
                handle: "40".to_owned(),
                name: "SITE|WALL".to_owned(),
                properties: XrefSevenLayerProperties {
                    off: false,
                    frozen: false,
                    locked: false,
                    is_plottable: true,
                    color_index: 7,
                    line_type: "Continuous".to_owned(),
                    line_weight: -3,
                },
                overridden_properties: BTreeSet::new(),
            }],
            saved_visretain: 1,
            saved_xrefoverride: 0,
        }
    }

    fn base_snapshot() -> XrefAttachmentMutationSnapshot {
        snapshot_at(
            "/project/host.dwg",
            vec![attachment(
                "A",
                "SITE",
                "refs/site.dwg",
                ReferenceType::Attachment,
                LoadState::Loaded,
                1,
            )],
            vec![instance("20", "A", "SITE")],
        )
    }

    fn locked_state(
        snapshot: XrefAttachmentMutationSnapshot,
        selected_handle: Option<&str>,
    ) -> LockedOperationState {
        let selected = selected_handle.and_then(|handle| {
            snapshot
                .attachments
                .iter()
                .find(|attachment| attachment.handle == handle)
                .cloned()
        });
        let selected_instances = selected_handle
            .map(|handle| instances_for(&snapshot, handle))
            .unwrap_or_default();
        LockedOperationState {
            snapshot,
            selected,
            selected_instances,
            placement: None,
            source_graph: None,
            root_source_id: None,
            reconciliation_request: None,
            reconciliation_evidence: None,
            preservation_profile_id: "profile".to_owned(),
            case_rename_temporary_name: None,
        }
    }

    fn error_code(error: XrefTransactionError) -> String {
        error.code.as_str().to_owned()
    }

    fn update_request(properties: BTreeMap<String, serde_json::Value>) -> UpdateXrefRequest {
        UpdateXrefRequest {
            drawing_path: "/project/host.dwg".to_owned(),
            handle: Some("A".to_owned()),
            name: None,
            expected_handle: None,
            expected_name: None,
            properties,
            layer_reconciliation: None,
            unit_assumptions: None,
            search_paths: None,
        }
    }

    #[test]
    fn derives_and_validates_unsanitized_source_stems() {
        let source = validate_mutation_source_path("refs/Site Plan.dwg").unwrap();
        assert_eq!(derived_xref_name(&source).unwrap(), "Site Plan");

        let invalid = validate_mutation_source_path("refs/bad:name.dwg").unwrap();
        assert_eq!(
            error_code(derived_xref_name(&invalid).unwrap_err()),
            xref_failure_code::INVALID_XREF_NAME
        );
    }

    #[test]
    fn collision_checks_every_block_kind_and_excludes_only_update_target() {
        let snapshot = base_snapshot();
        for name in ["*Model_Space", "*u1", "dynamic_detail", "site"] {
            assert_eq!(
                error_code(validate_name_collision(&snapshot, name, None).unwrap_err()),
                xref_failure_code::XREF_NAME_COLLISION
            );
        }
        validate_name_collision(&snapshot, "site", Some("A")).unwrap();
        assert_eq!(
            error_code(
                validate_name_collision(&snapshot, "dynamic_detail", Some("A")).unwrap_err()
            ),
            xref_failure_code::XREF_NAME_COLLISION
        );
    }

    #[test]
    fn ambiguous_name_is_not_disambiguated_by_a_valid_handle() {
        let mut snapshot = base_snapshot();
        let duplicate = attachment(
            "B",
            "site",
            "other.dwg",
            ReferenceType::Overlay,
            LoadState::Loaded,
            0,
        );
        snapshot.attachments.push(duplicate);
        let selector = XrefSelector {
            handle: Some("A".to_owned()),
            name: Some("SITE".to_owned()),
        };
        assert_eq!(
            error_code(resolve_attachment(&snapshot, &selector).unwrap_err()),
            xref_failure_code::AMBIGUOUS_IDENTITY
        );
    }

    #[test]
    fn selectors_resolve_before_expected_guards() {
        let snapshot = base_snapshot();
        let selected = resolve_attachment(
            &snapshot,
            &XrefSelector {
                handle: Some("A".to_owned()),
                name: Some("site".to_owned()),
            },
        )
        .unwrap();
        assert_eq!(
            error_code(
                apply_attachment_guards(
                    &selected,
                    &XrefAttachmentGuards {
                        expected_handle: Some("B".to_owned()),
                        expected_name: Some("wrong".to_owned()),
                    },
                )
                .unwrap_err()
            ),
            xref_failure_code::EXPECTED_HANDLE_MISMATCH
        );
    }

    #[test]
    fn destructive_guards_compare_count_then_exact_numeric_handle_set() {
        let attachment = attachment(
            "A",
            "SITE",
            "site.dwg",
            ReferenceType::Attachment,
            LoadState::Loaded,
            2,
        );
        let instances = vec![instance("10", "A", "SITE"), instance("F", "A", "SITE")];
        assert_eq!(
            error_code(
                apply_destructive_guards(&attachment, &instances, Some(1), Some(&[])).unwrap_err()
            ),
            xref_failure_code::EXPECTED_INSTANCE_COUNT_MISMATCH
        );
        assert_eq!(
            error_code(
                apply_destructive_guards(
                    &attachment,
                    &instances,
                    Some(2),
                    Some(&["F".to_owned(), "11".to_owned()]),
                )
                .unwrap_err()
            ),
            xref_failure_code::EXPECTED_INSTANCE_HANDLES_MISMATCH
        );
        apply_destructive_guards(
            &attachment,
            &instances,
            Some(2),
            Some(&["F".to_owned(), "10".to_owned()]),
        )
        .unwrap();
    }

    #[test]
    fn duplicate_expected_instance_handles_fail_as_invalid_parameters() {
        let error = canonicalize_exact_handle_set(&["0xA".to_owned(), "a".to_owned()]).unwrap_err();
        assert_eq!(error_code(error), xref_failure_code::INVALID_PARAMETERS);
    }

    #[test]
    fn map_domain_error_does_not_duplicate_the_code_into_the_detail() {
        // Regression test for preview-agent-findings-2026-08-05.md P1 #6:
        // `update_xref` emitted `unsupported_xref_data` twice for one
        // failure. Root cause was `map_domain_error` building the wrapped
        // error's detail from `error.to_string()` (which is `Display`,
        // prefixing `code=<code> `), while also carrying that same code
        // separately — so the final message read
        // "code=unsupported_xref_data code=unsupported_xref_data ...".
        let inner = XrefError::new(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            "cannot prove saved XREFOVERRIDE: reader cannot decode raw EED",
        );
        let mapped = map_domain_error(inner);
        assert_eq!(
            error_code(mapped.clone()),
            xref_failure_code::UNSUPPORTED_XREF_DATA
        );
        assert_eq!(
            mapped.detail,
            "cannot prove saved XREFOVERRIDE: reader cannot decode raw EED"
        );
        assert_eq!(mapped.detail.matches("unsupported_xref_data").count(), 0);
    }

    #[test]
    fn update_classifies_every_property_before_value_parsing() {
        let request = update_request(BTreeMap::from([
            ("handle".to_owned(), json!(1)),
            ("name".to_owned(), json!(7)),
        ]));
        assert_eq!(
            error_code(ParsedAttachmentUpdate::from_request(&request).unwrap_err()),
            xref_failure_code::UNSUPPORTED_XREF_PROPERTY
        );

        let request = update_request(BTreeMap::from([("zzz".to_owned(), json!(1))]));
        assert_eq!(
            error_code(ParsedAttachmentUpdate::from_request(&request).unwrap_err()),
            xref_failure_code::INVALID_XREF_PROPERTY
        );
    }

    #[test]
    fn update_rejects_empty_wrong_types_and_path_local_options() {
        assert_eq!(
            error_code(
                ParsedAttachmentUpdate::from_request(&update_request(BTreeMap::new())).unwrap_err()
            ),
            xref_failure_code::EMPTY_XREF_UPDATE
        );
        let request = update_request(BTreeMap::from([("name".to_owned(), json!(7))]));
        assert_eq!(
            error_code(ParsedAttachmentUpdate::from_request(&request).unwrap_err()),
            xref_failure_code::INVALID_XREF_PROPERTY
        );
        let mut request = update_request(BTreeMap::from([("name".to_owned(), json!("NEW"))]));
        request.search_paths = Some(vec!["/search".to_owned()]);
        assert_eq!(
            error_code(ParsedAttachmentUpdate::from_request(&request).unwrap_err()),
            xref_failure_code::INVALID_PARAMETERS
        );
    }

    #[test]
    fn mutation_paths_keep_saved_grammar_and_reject_non_dwg_forms() {
        for accepted in [
            "site.dwg",
            "./site.DWG",
            "refs\\site.dwg",
            "C:/refs/site.dwg",
        ] {
            validate_mutation_source_path(accepted).unwrap();
        }
        for rejected in [
            "https://example/site.dwg",
            "$ROOT/site.dwg",
            "site.dxf",
            "C:site.dwg",
        ] {
            assert_eq!(
                validate_mutation_source_path(rejected).unwrap_err().code(),
                xref_failure_code::INVALID_XREF_PATH
            );
        }
    }

    #[test]
    fn placement_defaults_are_explicit_and_locked_host_layers_are_allowed() {
        let mut snapshot = base_snapshot();
        let default = resolve_placement(&snapshot, &default_placement()).unwrap();
        assert_eq!(default.owner.owner_type, XrefOwnerType::ModelSpace);
        assert_eq!(default.layer.name, "0");
        assert_eq!(default.insertion_point.x, 0.0);

        let placement = XrefPlacement {
            layer_name: Some("LOCKED".to_owned()),
            ..default_placement()
        }
        .canonicalized()
        .unwrap();
        let resolved = resolve_placement(&snapshot, &placement).unwrap();
        assert!(resolved.layer.locked);

        snapshot.layers[1].host_owned = false;
        assert_eq!(
            error_code(resolve_placement(&snapshot, &placement).unwrap_err()),
            xref_failure_code::LAYER_NOT_HOST_OWNED
        );
    }

    #[test]
    fn detach_preflight_reports_owner_before_locked_layer() {
        let mut snapshot = base_snapshot();
        snapshot.owners[0].writable = false;
        snapshot.layers[0].locked = true;
        let selected = snapshot.attachments[0].clone();
        let instances = snapshot.instances.clone();
        assert_eq!(
            error_code(
                validate_detach_preflight(&snapshot, &selected, &instances, true).unwrap_err()
            ),
            xref_failure_code::UNSUPPORTED_XREF_OWNER
        );
        snapshot.owners[0].writable = true;
        assert_eq!(
            error_code(
                validate_detach_preflight(&snapshot, &selected, &instances, true).unwrap_err()
            ),
            xref_failure_code::XREF_INSTANCE_LOCKED
        );
    }

    #[test]
    fn detach_requires_complete_dependent_nested_and_clip_evidence() {
        let mut snapshot = base_snapshot();
        let selected = snapshot.attachments[0].clone();
        let instances = snapshot.instances.clone();
        snapshot.attachment_preflight[0].dependent_symbols_complete = false;
        assert_eq!(
            error_code(
                validate_detach_preflight(&snapshot, &selected, &instances, true).unwrap_err()
            ),
            xref_failure_code::UNSUPPORTED_XREF_DATA
        );
        snapshot.attachment_preflight[0].dependent_symbols_complete = true;
        snapshot.attachment_preflight[0]
            .instance_clips
            .insert("20".to_owned(), XrefClipMutationEvidence::Present);
        assert_eq!(
            error_code(
                validate_detach_preflight(&snapshot, &selected, &instances, true).unwrap_err()
            ),
            xref_failure_code::UNSUPPORTED_XREF_CLIP_DATA
        );
    }

    #[test]
    fn drawing_policy_and_synchronize_evidence_are_deterministic() {
        let drawing_policy = default_reconciliation();
        assert_eq!(
            reconciliation_evidence(&drawing_policy, 0).effective_mode,
            EffectiveLayerReconciliationMode::SourceAuthoritative
        );
        assert_eq!(
            reconciliation_evidence(&drawing_policy, 1).effective_mode,
            EffectiveLayerReconciliationMode::PreserveHost
        );
        let synchronize = XrefLayerReconciliation {
            mode: LayerReconciliationMode::Synchronize,
            properties: Some(vec![
                XrefLayerProperty::LineWeight,
                XrefLayerProperty::Off,
                XrefLayerProperty::ColorIndex,
            ]),
        };
        let evidence = reconciliation_evidence(&synchronize, 1);
        assert_eq!(
            evidence.synchronized_properties,
            vec![
                XrefLayerProperty::Off,
                XrefLayerProperty::ColorIndex,
                XrefLayerProperty::LineWeight,
            ]
        );
        assert_eq!(visretainmode_mask(&evidence.synchronized_properties), 81);
        assert_eq!(
            visretainmode_mask(&[
                XrefLayerProperty::Off,
                XrefLayerProperty::Frozen,
                XrefLayerProperty::Locked,
                XrefLayerProperty::IsPlottable,
                XrefLayerProperty::ColorIndex,
                XrefLayerProperty::LineType,
                XrefLayerProperty::LineWeight,
            ]),
            127
        );
    }

    #[test]
    fn profile_values_are_closed_to_requested_units_and_seven_layer_properties() {
        let assumptions = XrefUnitAssumptions {
            source_units: Some(InsertionUnit::Millimeters),
            host_units: Some(InsertionUnit::Meters),
        };
        assert_eq!(
            unit_profile_values(Some(&assumptions)),
            BTreeMap::from([
                ("host_units".to_owned(), "meters".to_owned()),
                ("source_units".to_owned(), "millimeters".to_owned()),
            ])
        );
        let reconciliation = XrefLayerReconciliation {
            mode: LayerReconciliationMode::Synchronize,
            properties: Some(vec![XrefLayerProperty::LineType, XrefLayerProperty::Off]),
        };
        assert_eq!(
            reconciliation_profile_values(Some(&reconciliation))["properties"],
            "off,line_type"
        );
    }

    #[test]
    fn unit_assumption_contract_rejects_missing_extra_uncertified_and_unsupported_values() {
        assert_eq!(
            error_code(
                validate_unit_role_contract(
                    XrefUnitRole::Source,
                    XrefUnitRoleRequirement::Proven,
                    Some(InsertionUnit::Millimeters),
                    true,
                    true,
                )
                .unwrap_err()
            ),
            xref_failure_code::INVALID_UNIT_ASSUMPTIONS
        );
        assert_eq!(
            error_code(
                validate_unit_role_contract(
                    XrefUnitRole::Host,
                    XrefUnitRoleRequirement::AssumptionRequired,
                    None,
                    true,
                    true,
                )
                .unwrap_err()
            ),
            xref_failure_code::AMBIGUOUS_INSERTION_UNITS
        );
        assert_eq!(
            error_code(
                validate_unit_role_contract(
                    XrefUnitRole::Source,
                    XrefUnitRoleRequirement::ProfileDefaultAssumptionRequired,
                    Some(InsertionUnit::Meters),
                    false,
                    true,
                )
                .unwrap_err()
            ),
            xref_failure_code::UNSUPPORTED_INSERTION_UNITS
        );
        assert_eq!(
            error_code(
                validate_unit_role_contract(
                    XrefUnitRole::Source,
                    XrefUnitRoleRequirement::AssumptionRequired,
                    Some(InsertionUnit::UsSurveyFeet),
                    true,
                    false,
                )
                .unwrap_err()
            ),
            xref_failure_code::UNSUPPORTED_INSERTION_UNITS
        );
        assert_eq!(
            error_code(
                validate_unit_role_contract(
                    XrefUnitRole::Source,
                    XrefUnitRoleRequirement::Unsupported,
                    None,
                    true,
                    true,
                )
                .unwrap_err()
            ),
            xref_failure_code::UNSUPPORTED_INSERTION_UNITS
        );
        validate_unit_role_contract(
            XrefUnitRole::Host,
            XrefUnitRoleRequirement::AssumptionRequired,
            Some(InsertionUnit::Unitless),
            true,
            true,
        )
        .unwrap();
    }

    #[derive(Default)]
    struct GraphProvider {
        probes: BTreeMap<String, CandidateProbeResult>,
        children: BTreeMap<String, Vec<XrefAttachmentRecord>>,
    }

    impl ResolutionCandidateProbe for GraphProvider {
        fn probe_candidate(&mut self, candidate: &ResolutionCandidate) -> CandidateProbeResult {
            self.probes
                .get(candidate.path())
                .cloned()
                .unwrap_or(CandidateProbeResult::Missing)
        }
    }

    impl SearchPathInspector for GraphProvider {
        fn inspect_search_path(&mut self, _absolute_path: &str) -> SearchPathInspection {
            SearchPathInspection::Missing
        }
    }

    impl XrefDependencyProvider for GraphProvider {
        fn inspect_resolved_source(
            &mut self,
            resolved_path: &CanonicalDisplayPath,
            _filesystem_identity: &FilesystemIdentity,
        ) -> Result<XrefSourceInspection, XrefError> {
            Ok(XrefSourceInspection::Inspected {
                attachments: self
                    .children
                    .get(resolved_path.as_str())
                    .cloned()
                    .unwrap_or_default(),
                content_sha256: Some("11".repeat(32)),
            })
        }
    }

    fn resolved(path: &str, identity_value: &str) -> CandidateProbeResult {
        CandidateProbeResult::Resolved(
            CanonicalExistingPath::from_filesystem_canonical_path(path, identity(identity_value))
                .unwrap(),
        )
    }

    fn locked_graph(
        traversal: XrefDependencyTraversalEnvelope,
        identities: &[(&str, &str)],
    ) -> LockedSourceGraph {
        LockedSourceGraph {
            traversal,
            identities: identities
                .iter()
                .map(|(path, identity_value)| TraversedSourceIdentity {
                    resolved_path: (*path).to_owned(),
                    filesystem_identity: identity(identity_value),
                    content_sha256: Some("11".repeat(32)),
                })
                .collect(),
        }
    }

    #[test]
    fn direct_overlay_root_is_inspected_and_only_nested_overlay_branch_is_terminal() {
        let root = attachment(
            "A",
            "ROOT",
            "root.dwg",
            ReferenceType::Overlay,
            LoadState::Loaded,
            0,
        );
        let nested_overlay = attachment(
            "B",
            "NESTED",
            "nested.dwg",
            ReferenceType::Overlay,
            LoadState::Loaded,
            0,
        );
        let source = XrefGraphSource::from_filesystem_canonical_path(
            "/project/host.dwg",
            identity("host"),
            vec![root],
        )
        .unwrap();
        let mut provider = GraphProvider::default();
        provider.probes.insert(
            "/project/root.dwg".to_owned(),
            resolved("/project/root.dwg", "root"),
        );
        provider
            .children
            .insert("/project/root.dwg".to_owned(), vec![nested_overlay]);
        let graph = super::super::xref_graph::traverse_xref_dependencies(
            &source,
            Some(&XrefSelector {
                handle: Some("A".to_owned()),
                name: None,
            }),
            &super::super::xref_path::ValidatedSearchPaths::empty(source.platform()),
            XrefTraversalLimits::for_mutation(),
            &mut provider,
        )
        .unwrap();
        require_complete_dependency_graph_for_mutation(&graph).unwrap();
        assert_eq!(graph.dependencies.len(), 2);
        assert_eq!(
            graph.dependencies[0].inspection_state,
            XrefInspectionState::Inspected
        );
        assert_eq!(
            graph.dependencies[1].inspection_state,
            XrefInspectionState::TerminalOverlay
        );
        let graph = locked_graph(graph, &[("/project/root.dwg", "root")]);
        let sources = source_inputs_from_locked_graph(&graph).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].source_id, "A");
        assert_eq!(sources[0].filesystem_identity, identity("root"));
        assert_eq!(sources[0].inspected_digest_sha256, Some("11".repeat(32)));
        assert_eq!(
            sources[0].identity_provenance,
            XrefSourceIdentityProvenance::LockedGraphTraversal
        );
    }

    #[test]
    fn effective_graph_source_inputs_preserve_occurrence_parentage() {
        let root_attachment = attachment(
            "A",
            "ROOT",
            "root.dwg",
            ReferenceType::Attachment,
            LoadState::Loaded,
            0,
        );
        let child_attachment = attachment(
            "B",
            "CHILD",
            "child.dwg",
            ReferenceType::Attachment,
            LoadState::Loaded,
            0,
        );
        let graph = XrefDependencyTraversalEnvelope {
            drawing: "/project/host.dwg".to_owned(),
            within_limits: true,
            truncation: None,
            dependencies: vec![
                XrefDependencyRecord {
                    attachment_chain: vec!["A".to_owned()],
                    depth: 0,
                    immediate_host_path: "/project/host.dwg".to_owned(),
                    attachment: root_attachment,
                    propagation_state: XrefPropagationState::Root,
                    resolution_state: XrefResolutionState::Resolved,
                    resolved_path: Some("/project/root.dwg".to_owned()),
                    resolution_basis: Some(XrefResolutionBasis::HostDirectory),
                    inspection_state: XrefInspectionState::Inspected,
                    cycle_target_chain: None,
                },
                XrefDependencyRecord {
                    attachment_chain: vec!["A".to_owned(), "B".to_owned()],
                    depth: 1,
                    immediate_host_path: "/project/root.dwg".to_owned(),
                    attachment: child_attachment,
                    propagation_state: XrefPropagationState::Propagated,
                    resolution_state: XrefResolutionState::Resolved,
                    resolved_path: Some("/project/child.dwg".to_owned()),
                    resolution_basis: Some(XrefResolutionBasis::HostDirectory),
                    inspection_state: XrefInspectionState::Inspected,
                    cycle_target_chain: None,
                },
            ],
        };
        let graph = locked_graph(
            graph,
            &[
                ("/project/root.dwg", "root"),
                ("/project/child.dwg", "child"),
            ],
        );
        let sources = source_inputs_from_locked_graph(&graph).unwrap();
        assert_eq!(sources[0].source_id, "A");
        assert_eq!(sources[0].immediate_host_source_id, None);
        assert_eq!(sources[1].source_id, "A/B");
        assert_eq!(sources[1].immediate_host_source_id.as_deref(), Some("A"));
    }

    #[test]
    fn declared_sources_must_exactly_equal_locked_graph() {
        let graph = XrefDependencyTraversalEnvelope {
            drawing: "/project/host.dwg".to_owned(),
            within_limits: true,
            truncation: None,
            dependencies: vec![XrefDependencyRecord {
                attachment_chain: vec!["A".to_owned()],
                depth: 0,
                immediate_host_path: "/project/host.dwg".to_owned(),
                attachment: attachment(
                    "A",
                    "ROOT",
                    "root.dwg",
                    ReferenceType::Attachment,
                    LoadState::Loaded,
                    0,
                ),
                propagation_state: XrefPropagationState::Root,
                resolution_state: XrefResolutionState::Resolved,
                resolved_path: Some("/project/root.dwg".to_owned()),
                resolution_basis: Some(XrefResolutionBasis::HostDirectory),
                inspection_state: XrefInspectionState::Inspected,
                cycle_target_chain: None,
            }],
        };
        let graph = locked_graph(graph, &[("/project/root.dwg", "root")]);
        let required = source_inputs_from_locked_graph(&graph).unwrap();
        let mut declared = required.clone();
        declared[0].identity_provenance = XrefSourceIdentityProvenance::PathObservation;
        let (root_source_id, locked_sources) = require_declared_sources(&declared, &graph).unwrap();
        assert_eq!(root_source_id, "A");
        assert_eq!(
            locked_sources[0].identity_provenance,
            XrefSourceIdentityProvenance::LockedGraphTraversal
        );
        assert_eq!(
            error_code(require_declared_sources(&[], &graph).unwrap_err()),
            xref_failure_code::UNSUPPORTED_XREF_SOURCE
        );

        let mut changed = required;
        changed[0].filesystem_identity = identity("replacement");
        assert_eq!(
            require_declared_sources(&changed, &graph).unwrap_err().code,
            XrefTransactionErrorCode::XrefSourceChanged
        );
    }

    #[test]
    fn source_snapshot_validation_forbids_original_or_out_of_staging_inputs() {
        let declared = vec![XrefSourceInput {
            source_id: "A".to_owned(),
            path: PathBuf::from("/project/source.dwg"),
            saved_path: "source.dwg".to_owned(),
            immediate_host_source_id: None,
            filesystem_identity: identity("id"),
            identity_provenance: XrefSourceIdentityProvenance::LockedGraphTraversal,
            inspected_digest_sha256: Some("11".repeat(32)),
        }];
        let mut snapshots = vec![XrefSourceSnapshot {
            source_id: "A".to_owned(),
            original_path: PathBuf::from("/project/source.dwg"),
            saved_path: "source.dwg".to_owned(),
            immediate_host_source_id: None,
            snapshot_path: PathBuf::from("/stage/A.dwg"),
            original_identity: "id".to_owned(),
            filesystem_identity: identity("id"),
            snapshot_identity: super::super::xref_mutation::XrefFileIdentity::fake("snapshot"),
            digest_sha256: "11".repeat(32),
        }];
        verify_source_snapshots(&declared, &snapshots, Path::new("/stage")).unwrap();
        snapshots[0].snapshot_path = snapshots[0].original_path.clone();
        assert_eq!(
            verify_source_snapshots(&declared, &snapshots, Path::new("/stage"))
                .unwrap_err()
                .code
                .as_str(),
            xref_failure_code::WRITE_FAILED
        );
    }

    fn resolved_placement() -> ResolvedPlacement {
        ResolvedPlacement {
            owner: XrefOwnerMutationEvidence {
                handle: "10".to_owned(),
                owner_type: XrefOwnerType::ModelSpace,
                name: "*Model_Space".to_owned(),
                writable: true,
            },
            layer: XrefLayerMutationEvidence {
                handle: "11".to_owned(),
                name: "0".to_owned(),
                host_owned: true,
                locked: false,
            },
            insertion_point: XrefPoint3 {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            },
            scale: XrefScale3 {
                x: 1.0,
                y: 2.0,
                z: 3.0,
            },
            rotation_degrees: 90.0,
            normal: XrefVector3 {
                x: 0.0,
                y: 0.0,
                z: 1.0,
            },
            visibility: XrefVisibility::Visible,
        }
    }

    #[test]
    fn attach_script_is_deterministic_explicit_and_source_local() {
        let first = render_attach_program(
            Path::new("/stage/attach.sentinel"),
            Path::new("/stage/sources/A.dwg"),
            "SITE",
            "../refs/site.dwg",
            ReferenceType::Overlay,
            &resolved_placement(),
            None,
        )
        .unwrap();
        let second = render_attach_program(
            Path::new("/stage/attach.sentinel"),
            Path::new("/stage/sources/A.dwg"),
            "SITE",
            "../refs/site.dwg",
            ReferenceType::Overlay,
            &resolved_placement(),
            None,
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.matches("vla-AttachExternalReference").count(), 1);
        assert!(first.contains("/stage/sources/A.dwg"));
        assert!(first.contains("(amcp-set-saved-path \"SITE\" \"../refs/site.dwg\")"));
        assert!(first.contains(":vlax-true"));
        for ambient in ["CLAYER", "CTAB", "UCSNAME", "findfile", "getenv"] {
            assert!(!first.contains(ambient), "script consulted {ambient}");
        }
    }

    #[test]
    fn update_script_applies_path_type_and_case_rename_in_one_program() {
        let selected = attachment(
            "A",
            "site",
            "old.dwg",
            ReferenceType::Attachment,
            LoadState::Loaded,
            1,
        );
        let properties = ParsedAttachmentUpdate {
            name: Some("SITE".to_owned()),
            xref_path: Some(validate_mutation_source_path("new.dwg").unwrap()),
            reference_type: Some(ReferenceType::Overlay),
        };
        let script = render_update_program(
            Path::new("/stage/update.sentinel"),
            &selected,
            &properties,
            Some(Path::new("/stage/sources/new.dwg")),
            Some("__AUTOCAD_MCP_XREF_A__"),
            Some(&default_reconciliation()),
            1,
            0,
            None,
        )
        .unwrap();
        assert!(script.contains("vla-put-Path block \"/stage/sources/new.dwg\""));
        assert!(script.contains("amcp-set-reference-type \"site\" 8"));
        assert!(script.contains("vla-put-Name block \"__AUTOCAD_MCP_XREF_A__\""));
        assert!(script.contains("vla-put-Name block \"SITE\""));
        assert!(script.contains("setvar \"VISRETAIN\" 1"));
    }

    #[test]
    fn unloaded_path_update_does_not_open_even_the_snapshot() {
        let selected = attachment(
            "A",
            "SITE",
            "old.dwg",
            ReferenceType::Attachment,
            LoadState::Unloaded,
            1,
        );
        let properties = ParsedAttachmentUpdate {
            name: None,
            xref_path: Some(validate_mutation_source_path("new.dwg").unwrap()),
            reference_type: None,
        };
        let script = render_update_program(
            Path::new("/stage/update.sentinel"),
            &selected,
            &properties,
            Some(Path::new("/stage/sources/new.dwg")),
            None,
            Some(&default_reconciliation()),
            1,
            0,
            None,
        )
        .unwrap();
        assert!(!script.contains("vla-Reload"));
        assert!(!script.contains("/stage/sources/new.dwg"));
        assert!(script.contains("amcp-set-saved-path \"SITE\" \"new.dwg\""));
    }

    #[test]
    fn unload_script_is_idempotent_without_source_access() {
        let selected = attachment(
            "A",
            "SITE",
            "missing.dwg",
            ReferenceType::Attachment,
            LoadState::Unloaded,
            1,
        );
        let script = render_unload_program(Path::new("/stage/unload.sentinel"), &selected).unwrap();
        assert!(!script.contains("vla-Unload block"));
        assert!(!script.contains("missing.dwg"));
        assert!(script.contains("operation=unload_xref"));
    }

    #[test]
    fn reload_script_uses_snapshot_and_restores_saved_policy_and_path() {
        let selected = base_snapshot().attachments[0].clone();
        let reconciliation = XrefLayerReconciliation {
            mode: LayerReconciliationMode::Synchronize,
            properties: Some(vec![XrefLayerProperty::Off, XrefLayerProperty::LineWeight]),
        };
        let script = render_reload_program(
            Path::new("/stage/reload.sentinel"),
            &selected,
            Path::new("/stage/sources/A.dwg"),
            &reconciliation,
            1,
            0,
            None,
        )
        .unwrap();
        assert!(script.contains("vla-put-Path block \"/stage/sources/A.dwg\""));
        assert!(script.contains("amcp-set-saved-path \"SITE\" \"refs/site.dwg\""));
        assert!(script.contains("setvar \"VISRETAINMODE\" 65"));
        assert!(script.matches("setvar \"VISRETAIN\" 1").count() >= 2);
        assert!(script.contains("setvar \"XREFOVERRIDE\" 0"));
    }

    #[test]
    fn detach_script_targets_the_proven_definition_without_source_access() {
        let selected = base_snapshot().attachments[0].clone();
        let script = render_detach_program(Path::new("/stage/detach.sentinel"), &selected).unwrap();
        assert!(script.contains("amcp-block doc \"A\" \"SITE\""));
        assert!(script.contains("vla-Detach block"));
        assert!(!script.contains("refs/site.dwg"));
        assert!(script.contains("operation=detach_xref"));
    }

    #[test]
    fn sentinel_parser_accepts_only_exact_success_protocol() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operation.sentinel");
        fs::write(
            &path,
            format!("schema={SENTINEL_SCHEMA}\noperation=reload_xref\nstate=begin\nstate=ok\n"),
        )
        .unwrap();
        verify_sentinel_file(&path, "reload_xref").unwrap();
        fs::write(
            &path,
            format!("schema={SENTINEL_SCHEMA}\noperation=reload_xref\nstate=begin\nstate=error\n"),
        )
        .unwrap();
        assert_eq!(
            verify_sentinel_file(&path, "reload_xref")
                .unwrap_err()
                .code
                .as_str(),
            xref_failure_code::VERIFICATION_FAILED
        );
    }

    #[test]
    fn attach_verifier_requires_exactly_one_attachment_and_initial_instance() {
        let before = snapshot_at("/project/host.dwg", Vec::new(), Vec::new());
        let mut state = locked_state(before, None);
        state.placement = Some(resolved_placement());
        let created_attachment = attachment(
            "A",
            "SITE",
            "site.dwg",
            ReferenceType::Attachment,
            LoadState::Loaded,
            1,
        );
        let mut created_instance = instance("20", "A", "SITE");
        let placement = state.placement.as_ref().unwrap();
        created_instance.insertion_point = placement.insertion_point;
        created_instance.scale = placement.scale;
        created_instance.rotation_degrees = placement.rotation_degrees;
        created_instance.normal = placement.normal;
        let after = snapshot_at(
            "/tmp/output.dwg",
            vec![created_attachment],
            vec![created_instance],
        );
        let response = verify_attach_output(
            &state,
            &after,
            "SITE",
            "site.dwg",
            ReferenceType::Attachment,
        )
        .unwrap();
        assert_eq!(response.0.handle, "A");
        assert_eq!(response.1.handle, "20");

        let mut extra = after.clone();
        extra.attachments.push(attachment(
            "B",
            "EXTRA",
            "extra.dwg",
            ReferenceType::Attachment,
            LoadState::Loaded,
            0,
        ));
        assert!(verify_attach_output(
            &state,
            &extra,
            "SITE",
            "site.dwg",
            ReferenceType::Attachment
        )
        .is_err());
    }

    #[test]
    fn update_verifier_preserves_handles_placement_and_unloaded_state() {
        let before = base_snapshot();
        let state = locked_state(before.clone(), Some("A"));
        let properties = ParsedAttachmentUpdate {
            name: Some("CAMPUS".to_owned()),
            xref_path: Some(validate_mutation_source_path("refs/new.dwg").unwrap()),
            reference_type: Some(ReferenceType::Overlay),
        };
        let mut after_attachment = before.attachments[0].clone();
        after_attachment.name = "CAMPUS".to_owned();
        after_attachment.saved_path = "refs/new.dwg".to_owned();
        after_attachment.reference_type = ReferenceType::Overlay;
        let mut after_instance = before.instances[0].clone();
        after_instance.attachment_name = "CAMPUS".to_owned();
        let after = snapshot_at(
            "/tmp/output.dwg",
            vec![after_attachment],
            vec![after_instance],
        );
        assert_eq!(
            verify_update_output(&state, &after, &properties)
                .unwrap()
                .handle,
            "A"
        );

        let mut unloaded_before = base_snapshot();
        unloaded_before.attachments[0].load_state = LoadState::Unloaded;
        unloaded_before.graph_source = XrefGraphSource::from_filesystem_canonical_path(
            "/project/host.dwg",
            identity("unloaded"),
            unloaded_before.attachments.clone(),
        )
        .unwrap();
        let unloaded_state = locked_state(unloaded_before.clone(), Some("A"));
        let mut unloaded_after_attachment = unloaded_before.attachments[0].clone();
        unloaded_after_attachment.saved_path = "refs/new.dwg".to_owned();
        let mut unloaded_after = snapshot_at(
            "/tmp/output.dwg",
            vec![unloaded_after_attachment],
            unloaded_before.instances.clone(),
        );
        unloaded_after.instances[0].attachment_name = "SITE".to_owned();
        let path_only = ParsedAttachmentUpdate {
            name: None,
            xref_path: Some(validate_mutation_source_path("refs/new.dwg").unwrap()),
            reference_type: None,
        };
        assert_eq!(
            verify_update_output(&unloaded_state, &unloaded_after, &path_only)
                .unwrap()
                .load_state,
            LoadState::Unloaded
        );
    }

    #[test]
    fn unload_and_reload_verifiers_limit_authorized_changes() {
        let before = base_snapshot();
        let state = locked_state(before.clone(), Some("A"));
        let mut unloaded = snapshot_at(
            "/tmp/unload.dwg",
            before.attachments.clone(),
            before.instances.clone(),
        );
        unloaded.attachments[0].load_state = LoadState::Unloaded;
        unloaded.graph_source = XrefGraphSource::from_filesystem_canonical_path(
            "/tmp/unload.dwg",
            identity("unload"),
            unloaded.attachments.clone(),
        )
        .unwrap();
        assert_eq!(verify_unload_output(&state, &unloaded).unwrap().handle, "A");

        let mut reloaded = unloaded.clone();
        reloaded.attachments[0].load_state = LoadState::Loaded;
        reloaded.graph_source = XrefGraphSource::from_filesystem_canonical_path(
            "/tmp/unload.dwg",
            identity("reload"),
            reloaded.attachments.clone(),
        )
        .unwrap();
        assert_eq!(verify_reload_output(&state, &reloaded).unwrap().handle, "A");
        reloaded.instances[0].insertion_point.x = 99.0;
        assert!(verify_reload_output(&state, &reloaded).is_err());
    }

    #[test]
    fn detach_verifier_returns_numeric_sorted_handles_and_rejects_stale_target() {
        let before_attachment = attachment(
            "A",
            "SITE",
            "site.dwg",
            ReferenceType::Attachment,
            LoadState::Loaded,
            2,
        );
        let before = snapshot_at(
            "/project/host.dwg",
            vec![before_attachment],
            vec![instance("10", "A", "SITE"), instance("F", "A", "SITE")],
        );
        let state = locked_state(before, Some("A"));
        let after = snapshot_at("/tmp/output.dwg", Vec::new(), Vec::new());
        assert_eq!(
            verify_detach_output(&state, &after).unwrap(),
            vec!["F".to_owned(), "10".to_owned()]
        );
        let stale = snapshot_at(
            "/tmp/output.dwg",
            vec![state.selected.clone().unwrap()],
            state.selected_instances.clone(),
        );
        assert!(verify_detach_output(&state, &stale).is_err());
    }

    #[derive(Default)]
    struct VerificationServices {
        snapshots: VecDeque<XrefAttachmentMutationSnapshot>,
        preservation_calls: usize,
        reconciliation_calls: usize,
        fail_preservation: bool,
    }

    impl ResolutionCandidateProbe for VerificationServices {
        fn probe_candidate(&mut self, _candidate: &ResolutionCandidate) -> CandidateProbeResult {
            CandidateProbeResult::Missing
        }
    }

    impl SearchPathInspector for VerificationServices {
        fn inspect_search_path(&mut self, _absolute_path: &str) -> SearchPathInspection {
            SearchPathInspection::Missing
        }
    }

    impl XrefDependencyProvider for VerificationServices {
        fn inspect_resolved_source(
            &mut self,
            _resolved_path: &CanonicalDisplayPath,
            _filesystem_identity: &FilesystemIdentity,
        ) -> Result<XrefSourceInspection, XrefError> {
            Ok(XrefSourceInspection::Unsupported)
        }
    }

    impl XrefAttachmentMutationServices for VerificationServices {
        fn reread_attachment_mutation_snapshot(
            &mut self,
            _path: &Path,
        ) -> Result<XrefAttachmentMutationSnapshot, XrefError> {
            self.snapshots.pop_front().ok_or_else(|| {
                XrefError::new(xref_failure_code::UNSUPPORTED_XREF_DATA, "no snapshot")
            })
        }

        fn inspect_unit_requirements(
            &mut self,
            _operation: XrefMutationOperation,
            _graph: &XrefDependencyTraversalEnvelope,
        ) -> Result<XrefUnitRequirements, XrefError> {
            Ok(XrefUnitRequirements::default())
        }

        fn verify_attachment_preservation(
            &mut self,
            _verification: &XrefPreservationVerification<'_>,
        ) -> Result<(), XrefError> {
            self.preservation_calls += 1;
            if self.fail_preservation {
                Err(XrefError::new(
                    xref_failure_code::UNSUPPORTED_XREF_DATA,
                    "injected preservation failure",
                ))
            } else {
                Ok(())
            }
        }

        fn verify_layer_reconciliation(
            &mut self,
            _verification: &XrefReconciliationVerification<'_>,
        ) -> Result<(), XrefError> {
            self.reconciliation_calls += 1;
            Ok(())
        }
    }

    #[test]
    fn injected_preservation_and_reconciliation_verifiers_are_mandatory() {
        let before = base_snapshot();
        let after = before.clone();
        let mut state = locked_state(before, Some("A"));
        state.reconciliation_request = Some(default_reconciliation());
        state.reconciliation_evidence = Some(reconciliation_evidence(
            state.reconciliation_request.as_ref().unwrap(),
            1,
        ));
        let mut services = VerificationServices::default();
        verify_common_preservation(
            &mut services,
            XrefMutationOperation::ReloadXref,
            &state,
            &after,
            Some("A"),
            &[],
        )
        .unwrap();
        verify_reconciliation_if_present(&mut services, &state, &after).unwrap();
        assert_eq!(services.preservation_calls, 1);
        assert_eq!(services.reconciliation_calls, 1);

        services.fail_preservation = true;
        let error = verify_common_preservation(
            &mut services,
            XrefMutationOperation::ReloadXref,
            &state,
            &after,
            Some("A"),
            &[],
        )
        .unwrap_err();
        assert_eq!(error.code.as_str(), xref_failure_code::VERIFICATION_FAILED);
    }

    #[test]
    fn normalized_snapshot_rejects_count_and_graph_disagreement() {
        let mut snapshot = base_snapshot();
        snapshot.attachments[0].instance_count = 2;
        snapshot.graph_source = XrefGraphSource::from_filesystem_canonical_path(
            "/project/host.dwg",
            identity("bad-count"),
            snapshot.attachments.clone(),
        )
        .unwrap();
        assert_eq!(
            error_code(normalize_snapshot(snapshot).unwrap_err()),
            xref_failure_code::UNSUPPORTED_XREF_DATA
        );
    }
}
