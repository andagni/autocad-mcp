use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(test)]
use sha2::{Digest, Sha256};

#[cfg(test)]
use crate::certification::XrefAutocadProduct;
use crate::{
    activation::{ActivationError, MutationCapability, SelectedActivation},
    activation_platform::ProductionMutationRuntime,
    autocad_reader::{
        contract::xrefs::{
            Fact, XrefEvidenceValue, XrefInstanceListOptions, XrefMembershipEvidence,
            XrefPortableClipEvidence,
        },
        map_xref_open_error, DrawingFormat, DrawingSnapshot, Reader, XrefReadSession,
    },
    certification::{
        embedded_xref_artifacts, inspect_xref_certification_format, XrefMutationOperation,
        XrefUnitRole,
    },
};

use crate::ops::{
    xref_attachment_mutation::{
        prepare_attach_xref, prepare_detach_xref, prepare_reload_xref, prepare_unload_xref,
        prepare_update_xref, source_inputs_from_effective_graph, validate_attach_xref_context_free,
        validate_update_xref_step_two, XrefAttachmentMutationServices,
        XrefAttachmentMutationSnapshot, XrefAttachmentPreflightEvidence,
        XrefBlockDefinitionEvidence, XrefClipMutationEvidence, XrefLayerMutationEvidence,
        XrefOwnerMutationEvidence, XrefPreservationVerification, XrefReconciliationLayerEvidence,
        XrefReconciliationVerification, XrefSevenLayerProperties, XrefUnitRequirements,
        XrefUnitRoleRequirement,
    },
    xref_bind::{
        BindError, BindExecutionEvidence, BindPersistedEvidenceReader, BindPlan,
        BindPreflightInput, BindStructuralProjection, BindXrefOperation,
    },
    xref_graph::{
        traverse_xref_dependencies_for_mutation, XrefDependencyProvider, XrefGraphSource,
        XrefSourceInspection,
    },
    xref_instance_mutation::{
        validate_insert_xref_instance_step_two, validate_update_xref_instance_step_two,
        xref_instance_unit_profile_defaults, DeleteXrefInstanceOperation,
        InsertXrefInstanceOperation, PortableXrefInstanceMutationReader,
        UpdateXrefInstanceOperation, XrefInstanceClipFacts, XrefInstanceLayerFacts,
        XrefInstanceMutationEnvironment, XrefInstanceMutationFactSource, XrefInstanceOwnerFacts,
        XrefInstanceUnitFacts, XrefLayerOwnership, XrefOwnerWriteState,
    },
    xref_io::{self, FilesystemXrefProvider},
    xref_mutation::{
        execute_xref_mutation_transaction, select_xref_mutation_capability,
        transaction_error_from_capability, unsupported_xref_platform_detail,
        validate_format_only_admission, AccoreconsoleXrefMutationEngine, ProductionXrefFileSystem,
        XrefCapabilityQuery, XrefHostFormatFacts, XrefHostFormatInspector, XrefIsolatedProfileSpec,
        XrefMutationOperationCallback, XrefTransactionError, XrefTransactionErrorCode,
        XrefTransactionRequest,
    },
    xref_path::{
        validate_mutation_source_path, validate_search_paths, CandidateProbeResult,
        CanonicalDisplayPath, FilesystemIdentity, ResolutionCandidate, ResolutionCandidateProbe,
        SearchPathInspection, SearchPathInspector,
    },
    xrefs::{
        self, xref_failure_code, AttachXrefRequest, AttachXrefResponse, BindXrefRequest,
        BindXrefResponse, DeleteXrefInstanceRequest, DeleteXrefInstanceResponse, DetachXrefRequest,
        DetachXrefResponse, InsertXrefInstanceRequest, InsertXrefInstanceResponse,
        PersistedInsertionUnits, ReloadXrefRequest, ReloadXrefResponse, UnloadXrefRequest,
        UnloadXrefResponse, UpdateXrefInstanceRequest, UpdateXrefInstanceResponse,
        UpdateXrefRequest, UpdateXrefResponse, XrefAttachmentRecord,
        XrefDependencyTraversalEnvelope, XrefDestructiveAttachmentGuards, XrefError,
        XrefPointAvailability, XrefSelector, XrefTool,
    },
};

pub const XREF_CERTIFIED_ARG_PATH_ENV: &str = "AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH";
pub const XREF_CERTIFIED_ARG_SHA256_BUILD_ENV: &str = "AUTOCAD_MCP_XREF_CERTIFIED_ARG_SHA256";
const XREF_CERTIFIED_ARG_SHA256: Option<&str> =
    option_env!("AUTOCAD_MCP_XREF_CERTIFIED_ARG_SHA256");

pub fn certified_arg_sha256_build_value() -> Option<&'static str> {
    XREF_CERTIFIED_ARG_SHA256
}

#[derive(Debug, Default)]
struct ProductionXrefHostFormatInspector;

impl XrefHostFormatInspector for ProductionXrefHostFormatInspector {
    fn inspect(&mut self, path: &Path) -> Result<XrefHostFormatFacts, XrefTransactionError> {
        if !path.is_absolute() {
            return Err(domain_transaction_error(
                xref_failure_code::DRAWING_UNREADABLE,
                "drawing_path must be an absolute local path",
            ));
        }
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| {
                XrefTransactionError::new(
                    XrefTransactionErrorCode::UnsupportedFormat,
                    "drawing has no UTF-8 extension; expected .dwg or .dxf",
                )
            })?;
        if !matches!(extension.as_str(), "dwg" | "dxf") {
            return Err(XrefTransactionError::new(
                XrefTransactionErrorCode::UnsupportedFormat,
                format!("unsupported drawing extension '.{extension}'"),
            ));
        }
        match fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                return Err(domain_transaction_error(
                    xref_failure_code::DRAWING_UNREADABLE,
                    "drawing_path does not name a regular file",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(domain_transaction_error(
                    xref_failure_code::DRAWING_NOT_FOUND,
                    format!("drawing was not found: {}", path.display()),
                ))
            }
            Err(error) => {
                return Err(domain_transaction_error(
                    xref_failure_code::DRAWING_UNREADABLE,
                    format!("cannot inspect drawing {}: {error}", path.display()),
                ))
            }
        }
        let facts = inspect_xref_certification_format(path).map_err(|error| {
            XrefTransactionError::new(
                XrefTransactionErrorCode::UnsupportedFormat,
                format!("cannot prove persisted host format facts: {error}"),
            )
        })?;
        Ok(XrefHostFormatFacts {
            host_format: facts.host_format,
            drawing_version: facts.drawing_version,
            dxf_form: facts.dxf_form,
            code_page: facts.code_page,
        })
    }
}

fn domain_transaction_error(code: &str, detail: impl Into<String>) -> XrefTransactionError {
    XrefTransactionError::new(XrefTransactionErrorCode::Domain(code.to_owned()), detail)
}

fn static_failure_code(code: &str) -> Option<&'static str> {
    const TOOLS: [XrefTool; 15] = [
        XrefTool::ListXrefs,
        XrefTool::GetXref,
        XrefTool::AttachXref,
        XrefTool::UpdateXref,
        XrefTool::DetachXref,
        XrefTool::ListXrefInstances,
        XrefTool::GetXrefInstance,
        XrefTool::InsertXrefInstance,
        XrefTool::UpdateXrefInstance,
        XrefTool::DeleteXrefInstance,
        XrefTool::ReloadXref,
        XrefTool::UnloadXref,
        XrefTool::BindXref,
        XrefTool::ResolveXrefPath,
        XrefTool::ListXrefDependencies,
    ];
    TOOLS
        .into_iter()
        .flat_map(xrefs::xref_failure_codes)
        .find(|candidate| *candidate == code)
}

pub(crate) fn transaction_error_to_xref(error: XrefTransactionError) -> XrefError {
    let detail = error.detail;
    let code = match error.code {
        XrefTransactionErrorCode::UnsupportedFormat => xref_failure_code::UNSUPPORTED_FORMAT,
        XrefTransactionErrorCode::UnsupportedPlatform => xref_failure_code::UNSUPPORTED_PLATFORM,
        XrefTransactionErrorCode::AutocadUnavailable => xref_failure_code::AUTOCAD_UNAVAILABLE,
        XrefTransactionErrorCode::DrawingLocked => xref_failure_code::DRAWING_LOCKED,
        XrefTransactionErrorCode::ConcurrentDrawingModification => {
            xref_failure_code::CONCURRENT_DRAWING_MODIFICATION
        }
        XrefTransactionErrorCode::XrefSourceChanged => xref_failure_code::XREF_SOURCE_CHANGED,
        XrefTransactionErrorCode::WriteFailed => xref_failure_code::WRITE_FAILED,
        XrefTransactionErrorCode::VerificationFailed => xref_failure_code::VERIFICATION_FAILED,
        XrefTransactionErrorCode::MutationStateUnknown => xref_failure_code::MUTATION_STATE_UNKNOWN,
        XrefTransactionErrorCode::Domain(code) => match static_failure_code(&code) {
            Some(code) => code,
            None => {
                return XrefError::new(
                    xref_failure_code::UNSUPPORTED_XREF_DATA,
                    format!("unregistered XREF runtime failure code '{code}': {detail}"),
                )
            }
        },
    };
    XrefError::new(code, detail)
}

#[cfg(test)]
trait RuntimeEngineDiscovery {
    fn is_windows(&self) -> bool;
    fn detect_identity(&mut self) -> Result<crate::engine::AutocadEngineIdentity, String>;
}

#[cfg(test)]
#[derive(Debug, Default)]
struct ProductionRuntimeEngineDiscovery;

#[cfg(test)]
impl RuntimeEngineDiscovery for ProductionRuntimeEngineDiscovery {
    fn is_windows(&self) -> bool {
        cfg!(target_os = "windows")
    }

    fn detect_identity(&mut self) -> Result<crate::engine::AutocadEngineIdentity, String> {
        crate::engine::detect_accoreconsole_identity().map_err(|error| error.to_string())
    }
}

fn inspect_host_before_identity(path: &Path) -> Result<XrefHostFormatFacts, XrefError> {
    let mut inspector = ProductionXrefHostFormatInspector;
    inspector.inspect(path).map_err(transaction_error_to_xref)
}

#[cfg(test)]
fn admit_host_after_identity(
    format: &XrefHostFormatFacts,
    operation: XrefMutationOperation,
    discovery: &mut dyn RuntimeEngineDiscovery,
) -> Result<(), XrefError> {
    let registry = embedded_xref_artifacts().map_err(|error| {
        XrefError::new(
            xref_failure_code::WRITE_FAILED,
            format!("invalid embedded XREF capability artifacts: {error}"),
        )
    })?;
    validate_format_only_admission(registry, format, operation)
        .map_err(transaction_error_to_xref)?;
    if !discovery.is_windows() {
        return Err(XrefError::new(
            xref_failure_code::UNSUPPORTED_PLATFORM,
            unsupported_xref_platform_detail(format, operation, std::env::consts::OS, None),
        ));
    }
    let identity = discovery.detect_identity().map_err(|error| {
        XrefError::new(
            xref_failure_code::AUTOCAD_UNAVAILABLE,
            format!("non-launching AutoCAD discovery failed: {error}"),
        )
    })?;
    if identity.product != XrefAutocadProduct::Autocad.as_str() {
        return Err(XrefError::new(
            xref_failure_code::UNSUPPORTED_PLATFORM,
            unsupported_xref_platform_detail(
                format,
                operation,
                std::env::consts::OS,
                Some(&format!(
                    "detected uncertified AutoCAD product '{}'",
                    identity.product
                )),
            ),
        ));
    }
    select_xref_mutation_capability(
        registry,
        XrefCapabilityQuery {
            host_format: format.host_format,
            drawing_version: &format.drawing_version,
            dxf_form: format.dxf_form,
            code_page: format.code_page.as_deref(),
            operation,
        },
    )
    .map_err(transaction_error_from_capability)
    .map_err(transaction_error_to_xref)?;
    Ok(())
}

#[cfg(test)]
fn preflight_after_context_free<F>(
    path: &Path,
    operation: XrefMutationOperation,
    validate_identity: F,
) -> Result<(), XrefError>
where
    F: FnOnce() -> Result<(), XrefError>,
{
    let format = inspect_host_before_identity(path)?;
    validate_identity()?;
    admit_host_after_identity(&format, operation, &mut ProductionRuntimeEngineDiscovery)
}

fn activation_error_to_xref(
    error: ActivationError,
    format: &XrefHostFormatFacts,
    operation: XrefMutationOperation,
) -> XrefError {
    let code = match &error {
        ActivationError::Disabled
        | ActivationError::ReleaseQualificationUnavailable
        | ActivationError::ReleaseQualificationInvalid(_)
        | ActivationError::CapabilityUnsupported { .. } => xref_failure_code::UNSUPPORTED_PLATFORM,
        ActivationError::DrawingFormatUnsupported { .. } => xref_failure_code::UNSUPPORTED_FORMAT,
        ActivationError::CatalogueInvalid(_) | ActivationError::AssetInvalid(_) => {
            xref_failure_code::WRITE_FAILED
        }
        ActivationError::DiscoveryFailed(_) if !cfg!(target_os = "windows") => {
            xref_failure_code::UNSUPPORTED_PLATFORM
        }
        ActivationError::DiscoveryFailed(_)
        | ActivationError::NoEligibleCandidate
        | ActivationError::ExactOverrideUnavailable(_)
        | ActivationError::VerificationFailed(_)
        | ActivationError::SelectedEngineChanged(_) => xref_failure_code::AUTOCAD_UNAVAILABLE,
    };
    XrefError::new(
        code,
        unsupported_xref_platform_detail(
            format,
            operation,
            std::env::consts::OS,
            Some(&format!("AutoCAD activation failed: {error}")),
        ),
    )
}

fn preflight_with_activation<F>(
    path: &Path,
    operation: XrefMutationOperation,
    validate_identity: F,
    runtime: &ProductionMutationRuntime,
) -> Result<Arc<SelectedActivation>, XrefError>
where
    F: FnOnce() -> Result<(), XrefError>,
{
    let format = inspect_host_before_identity(path)?;
    validate_identity()?;
    let registry = embedded_xref_artifacts().map_err(|error| {
        XrefError::new(
            xref_failure_code::WRITE_FAILED,
            format!("invalid embedded XREF capability artifacts: {error}"),
        )
    })?;
    validate_format_only_admission(registry, &format, operation)
        .map_err(transaction_error_to_xref)?;
    let selected = runtime
        .acquire_for_format(MutationCapability::XrefMutation, &format.drawing_version)
        .map_err(|error| activation_error_to_xref(error, &format, operation))?;
    select_xref_mutation_capability(
        registry,
        XrefCapabilityQuery {
            host_format: format.host_format,
            drawing_version: &format.drawing_version,
            dxf_form: format.dxf_form,
            code_page: format.code_page.as_deref(),
            operation,
        },
    )
    .map_err(transaction_error_from_capability)
    .map_err(transaction_error_to_xref)?;
    Ok(selected)
}

#[cfg(test)]
fn preflight_with_discovery(
    path: &Path,
    operation: XrefMutationOperation,
    discovery: &mut dyn RuntimeEngineDiscovery,
) -> Result<(), XrefError> {
    let format = inspect_host_before_identity(path)?;
    admit_host_after_identity(&format, operation, discovery)
}

#[cfg(test)]
fn decode_sha256(value: &str) -> Result<[u8; 32], XrefError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(XrefError::new(
            xref_failure_code::AUTOCAD_UNAVAILABLE,
            format!(
                "{XREF_CERTIFIED_ARG_SHA256_BUILD_ENV} must contain exactly 64 hexadecimal digits"
            ),
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).expect("hexadecimal input is ASCII");
        digest[index] = u8::from_str_radix(text, 16).map_err(|_| {
            XrefError::new(
                xref_failure_code::AUTOCAD_UNAVAILABLE,
                format!("{XREF_CERTIFIED_ARG_SHA256_BUILD_ENV} is not hexadecimal"),
            )
        })?;
    }
    Ok(digest)
}

#[cfg(test)]
fn certified_profile_spec() -> Result<XrefIsolatedProfileSpec, XrefError> {
    let path = std::env::var_os(XREF_CERTIFIED_ARG_PATH_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            XrefError::new(
                xref_failure_code::AUTOCAD_UNAVAILABLE,
                format!(
                    "{XREF_CERTIFIED_ARG_PATH_ENV} must name the certified exported ARG profile"
                ),
            )
        })?;
    if !path.is_absolute()
        || !path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("arg"))
    {
        return Err(XrefError::new(
            xref_failure_code::AUTOCAD_UNAVAILABLE,
            format!("{XREF_CERTIFIED_ARG_PATH_ENV} must be an absolute .arg file"),
        ));
    }
    let expected = XREF_CERTIFIED_ARG_SHA256
        .ok_or_else(|| {
            XrefError::new(
                xref_failure_code::AUTOCAD_UNAVAILABLE,
                format!(
                    "this binary was built without {XREF_CERTIFIED_ARG_SHA256_BUILD_ENV}; no ARG profile is certified"
                ),
            )
        })
        .and_then(|value| decode_sha256(value.trim()))?;
    let bytes = fs::read(&path).map_err(|error| {
        XrefError::new(
            xref_failure_code::AUTOCAD_UNAVAILABLE,
            format!(
                "cannot read certified ARG profile {}: {error}",
                path.display()
            ),
        )
    })?;
    if bytes.is_empty() {
        return Err(XrefError::new(
            xref_failure_code::AUTOCAD_UNAVAILABLE,
            "certified ARG profile is empty",
        ));
    }
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual != expected {
        return Err(XrefError::new(
            xref_failure_code::AUTOCAD_UNAVAILABLE,
            format!(
                "certified ARG profile digest does not match build-time {XREF_CERTIFIED_ARG_SHA256_BUILD_ENV}"
            ),
        ));
    }
    Ok(XrefIsolatedProfileSpec {
        certified_autocad_arg: bytes,
        ..XrefIsolatedProfileSpec::default()
    })
}

fn selected_profile_spec(selected: &SelectedActivation) -> XrefIsolatedProfileSpec {
    XrefIsolatedProfileSpec {
        certified_autocad_arg: selected.target.profile.arg_bytes().to_vec(),
        ..XrefIsolatedProfileSpec::default()
    }
}

#[derive(Clone, Copy)]
enum XrefRuntimeActivation<'a> {
    #[cfg(test)]
    Legacy,
    Managed(&'a ProductionMutationRuntime),
}

impl XrefRuntimeActivation<'_> {
    fn preflight_and_profile<F>(
        self,
        path: &Path,
        operation: XrefMutationOperation,
        validate_identity: F,
    ) -> Result<(Option<Arc<SelectedActivation>>, XrefIsolatedProfileSpec), XrefError>
    where
        F: FnOnce() -> Result<(), XrefError>,
    {
        match self {
            #[cfg(test)]
            Self::Legacy => {
                preflight_after_context_free(path, operation, validate_identity)?;
                Ok((None, certified_profile_spec()?))
            }
            Self::Managed(runtime) => {
                let selected =
                    preflight_with_activation(path, operation, validate_identity, runtime)?;
                let profile = selected_profile_spec(&selected);
                Ok((Some(selected), profile))
            }
        }
    }
}

fn validate_attach_request(request: &AttachXrefRequest) -> Result<(), XrefError> {
    let mut services = ProductionAttachmentServices::default();
    prepare_attach_xref(request.clone(), Vec::new(), &mut services)
        .map(|_| ())
        .map_err(transaction_error_to_xref)
}

fn validate_update_request(request: &UpdateXrefRequest) -> Result<(), XrefError> {
    let mut services = ProductionAttachmentServices::default();
    prepare_update_xref(request.clone(), Vec::new(), &mut services)
        .map(|_| ())
        .map_err(transaction_error_to_xref)
}

fn validate_detach_request(request: &DetachXrefRequest) -> Result<(), XrefError> {
    let mut services = ProductionAttachmentServices::default();
    prepare_detach_xref(request.clone(), &mut services)
        .map(|_| ())
        .map_err(transaction_error_to_xref)
}

fn validate_unload_request(request: &UnloadXrefRequest) -> Result<(), XrefError> {
    let mut services = ProductionAttachmentServices::default();
    prepare_unload_xref(request.clone(), &mut services)
        .map(|_| ())
        .map_err(transaction_error_to_xref)
}

fn validate_reload_request(request: &ReloadXrefRequest) -> Result<(), XrefError> {
    let mut services = ProductionAttachmentServices::default();
    prepare_reload_xref(request.clone(), Vec::new(), &mut services)
        .map(|_| ())
        .map_err(transaction_error_to_xref)
}

fn validate_insert_instance_request(request: &InsertXrefInstanceRequest) -> Result<(), XrefError> {
    let reader = PortableXrefInstanceMutationReader::new(ProductionInstanceFactSource);
    InsertXrefInstanceOperation::new(request.clone(), reader)
        .map(|_| ())
        .map_err(transaction_error_to_xref)
}

fn validate_update_instance_request(request: &UpdateXrefInstanceRequest) -> Result<(), XrefError> {
    let reader = PortableXrefInstanceMutationReader::new(ProductionInstanceFactSource);
    UpdateXrefInstanceOperation::new(request.clone(), reader)
        .map(|_| ())
        .map_err(transaction_error_to_xref)
}

fn validate_delete_instance_request(request: &DeleteXrefInstanceRequest) -> Result<(), XrefError> {
    let reader = PortableXrefInstanceMutationReader::new(ProductionInstanceFactSource);
    DeleteXrefInstanceOperation::new(request.clone(), reader)
        .map(|_| ())
        .map_err(transaction_error_to_xref)
}

fn validate_bind_request(request: &BindXrefRequest) -> Result<(), XrefError> {
    let drawing = CanonicalDisplayPath::from_filesystem_canonical_path(&request.drawing_path)
        .map_err(|error| {
            XrefError::new(
                xref_failure_code::DRAWING_UNREADABLE,
                format!("drawing_path must be an absolute local path: {error}"),
            )
        })?;
    let extension = drawing
        .as_str()
        .trim_end_matches('/')
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase());
    if !matches!(extension.as_deref(), Some("dwg" | "dxf")) {
        return Err(XrefError::new(
            xref_failure_code::UNSUPPORTED_FORMAT,
            "drawing_path must name a .dwg or .dxf host",
        ));
    }
    let selector = XrefSelector {
        handle: request.handle.clone(),
        name: request.name.clone(),
    }
    .canonicalized()?;
    if selector.handle.is_none()
        && selector
            .name
            .as_deref()
            .is_none_or(|name| name.trim().is_empty())
    {
        return Err(XrefError::new(
            xref_failure_code::MISSING_IDENTITY,
            "bind_xref requires an attachment handle or non-empty name",
        ));
    }
    XrefDestructiveAttachmentGuards {
        expected_handle: request.expected_handle.clone(),
        expected_name: request.expected_name.clone(),
        expected_instance_count: request.expected_instance_count,
        expected_instance_handles: request.expected_instance_handles.clone(),
    }
    .canonicalized()?;
    Ok(())
}

fn execute_production<Operation>(
    request: &XrefTransactionRequest,
    operation: &mut Operation,
    selected: Option<Arc<SelectedActivation>>,
) -> Result<Operation::Response, XrefError>
where
    Operation: XrefMutationOperationCallback,
{
    let mut file_system = ProductionXrefFileSystem::default();
    let mut engine = match selected {
        Some(selected) => AccoreconsoleXrefMutationEngine::with_selected_activation(selected),
        None => AccoreconsoleXrefMutationEngine::new(),
    };
    let mut inspector = ProductionXrefHostFormatInspector;
    execute_xref_mutation_transaction(
        request,
        &mut file_system,
        &mut engine,
        &mut inspector,
        operation,
    )
    .map(|outcome| outcome.response)
    .map_err(transaction_error_to_xref)
}

fn read_portable_session(path: &Path) -> Result<XrefReadSession, XrefError> {
    let bytes = fs::read(path).map_err(|error| {
        XrefError::new(
            xref_failure_code::DRAWING_UNREADABLE,
            format!(
                "cannot capture portable mutation snapshot {}: {error}",
                path.display()
            ),
        )
    })?;
    let format = match path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("dwg") => DrawingFormat::Dwg,
        Some("dxf") => DrawingFormat::Dxf,
        _ => {
            return Err(XrefError::new(
                xref_failure_code::UNSUPPORTED_FORMAT,
                "portable mutation snapshot requires .dwg or .dxf",
            ))
        }
    };
    Reader::open_snapshot(DrawingSnapshot::new(format, bytes))
        .map_err(map_xref_open_error)?
        .xref_session()
}

fn fact<T: Clone>(value: &Fact<T>, field: &str) -> Result<T, XrefError> {
    match value {
        XrefEvidenceValue::Proven(value) => Ok(value.clone()),
        XrefEvidenceValue::Unavailable(reason)
        | XrefEvidenceValue::Unsupported(reason)
        | XrefEvidenceValue::Contradictory(reason) => Err(XrefError::new(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            format!("cannot prove {field}: {reason}"),
        )),
    }
}

struct ProductionAttachmentServices {
    provider: FilesystemXrefProvider,
    locked_host_units: Option<PersistedInsertionUnits>,
}

impl Default for ProductionAttachmentServices {
    fn default() -> Self {
        Self {
            provider: FilesystemXrefProvider::new(),
            locked_host_units: None,
        }
    }
}

impl SearchPathInspector for ProductionAttachmentServices {
    fn inspect_search_path(&mut self, absolute_path: &str) -> SearchPathInspection {
        self.provider.inspect_search_path(absolute_path)
    }
}

impl ResolutionCandidateProbe for ProductionAttachmentServices {
    fn probe_candidate(&mut self, candidate: &ResolutionCandidate) -> CandidateProbeResult {
        self.provider.probe_candidate(candidate)
    }
}

impl XrefDependencyProvider for ProductionAttachmentServices {
    fn inspect_resolved_source(
        &mut self,
        resolved_path: &CanonicalDisplayPath,
        filesystem_identity: &FilesystemIdentity,
    ) -> Result<XrefSourceInspection, XrefError> {
        self.provider
            .inspect_resolved_source(resolved_path, filesystem_identity)
    }
}

fn owner_write_state(
    owner: &XrefOwnerMutationEvidence,
    attachment_handles: &BTreeSet<&str>,
) -> XrefOwnerWriteState {
    if attachment_handles.contains(owner.handle.as_str()) {
        XrefOwnerWriteState::XrefDefinition
    } else if owner.owner_type != xrefs::XrefOwnerType::BlockDefinition {
        XrefOwnerWriteState::Writable
    } else if owner.name.starts_with('*') {
        XrefOwnerWriteState::Anonymous
    } else {
        // The selected backend does not expose enough dynamic/managed block
        // provenance to certify arbitrary block-definition owners writable.
        XrefOwnerWriteState::Unsupported
    }
}

fn attachment_snapshot_from_host(
    host: &xref_io::LoadedXrefHost,
) -> Result<XrefAttachmentMutationSnapshot, XrefError> {
    let portable = host.evidence();
    let attachments = host.attachments()?;
    let instances = host.instances(&XrefInstanceListOptions::default())?;
    let attachment_handles = attachments
        .iter()
        .map(|attachment| attachment.handle.as_str())
        .collect::<BTreeSet<_>>();
    let mut owners = Vec::new();
    for owner in &portable.owners {
        let handle = fact(&owner.handle, "owner handle")?;
        let owner_type = fact(&owner.owner_type, "owner type")?;
        let name = fact(&owner.name, "owner name")?;
        let writable = owner_write_state(
            &XrefOwnerMutationEvidence {
                handle: handle.clone(),
                owner_type,
                name: name.clone(),
                writable: false,
            },
            &attachment_handles,
        ) == XrefOwnerWriteState::Writable;
        owners.push(XrefOwnerMutationEvidence {
            handle,
            owner_type,
            name,
            writable,
        });
    }
    let mut layers = Vec::new();
    let mut reconciliation_layers = Vec::new();
    for layer in &portable.layers {
        let handle = fact(&layer.handle, "layer handle")?;
        let name = fact(&layer.name, "layer name")?;
        let xref_dependent = fact(&layer.xref_dependent, "layer ownership")?;
        let properties = fact(&layer.properties, "seven-property layer state")?;
        layers.push(XrefLayerMutationEvidence {
            handle: handle.clone(),
            name: name.clone(),
            host_owned: !xref_dependent,
            locked: properties.locked,
        });
        if xref_dependent {
            reconciliation_layers.push(XrefReconciliationLayerEvidence {
                handle,
                name,
                properties: XrefSevenLayerProperties {
                    off: properties.off,
                    frozen: properties.frozen,
                    locked: properties.locked,
                    is_plottable: properties.is_plottable,
                    color_index: properties.color_index,
                    line_type: properties.line_type,
                    line_weight: properties.line_weight,
                },
                overridden_properties: BTreeSet::new(),
            });
        }
    }
    let mut attachment_preflight = Vec::new();
    for attachment in &attachments {
        let selected = instances
            .iter()
            .filter(|instance| instance.attachment_handle == attachment.handle)
            .collect::<Vec<_>>();
        let mut clips_complete = true;
        let mut instance_clips = BTreeMap::new();
        for instance in selected {
            let clip = match portable.instance_clips.get(&instance.handle) {
                Some(XrefPortableClipEvidence::Absent) => XrefClipMutationEvidence::Absent,
                Some(XrefPortableClipEvidence::Unproven) | None => {
                    clips_complete = false;
                    XrefClipMutationEvidence::Unproven
                }
            };
            instance_clips.insert(instance.handle.clone(), clip);
        }
        attachment_preflight.push(XrefAttachmentPreflightEvidence {
            attachment_handle: attachment.handle.clone(),
            dependent_symbols_complete: false,
            dependent_symbols: Vec::new(),
            nested_projections_complete: false,
            nested_attachment_chains: Vec::new(),
            clips_complete,
            instance_clips,
        });
    }
    let block_definitions = owners
        .iter()
        .map(|owner| XrefBlockDefinitionEvidence {
            handle: owner.handle.clone(),
            name: owner.name.clone(),
        })
        .collect();
    let saved_visretain = fact(&portable.saved_visretain, "saved VISRETAIN")?;
    let saved_xrefoverride = fact(&portable.saved_xrefoverride, "saved XREFOVERRIDE")?;
    Ok(XrefAttachmentMutationSnapshot {
        drawing: host.display_path().as_str().to_owned(),
        graph_source: host.graph_source()?,
        attachments,
        instances,
        block_definitions_complete: portable.block_definitions_complete,
        block_definitions,
        owners_complete: portable.owners_complete,
        owners,
        layers_complete: portable.layers_complete,
        layers,
        attachment_preflight,
        reconciliation_layers_complete: portable.layers_complete,
        reconciliation_layers,
        saved_visretain,
        saved_xrefoverride,
    })
}

impl XrefAttachmentMutationServices for ProductionAttachmentServices {
    fn reread_attachment_mutation_snapshot(
        &mut self,
        path: &Path,
    ) -> Result<XrefAttachmentMutationSnapshot, XrefError> {
        let host = xref_io::load_xref_host(path, "xref_mutation")?;
        self.locked_host_units = Some(fact(
            &host.evidence().host_units,
            "locked host insertion units",
        )?);
        attachment_snapshot_from_host(&host)
    }

    fn inspect_unit_requirements(
        &mut self,
        _operation: XrefMutationOperation,
        graph: &XrefDependencyTraversalEnvelope,
    ) -> Result<XrefUnitRequirements, XrefError> {
        let Some(root) = graph
            .dependencies
            .iter()
            .find(|dependency| dependency.depth == 0)
        else {
            return Err(XrefError::new(
                xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE,
                "effective source graph has no root",
            ));
        };
        let Some(path) = root.resolved_path.as_deref() else {
            return Err(XrefError::new(
                xref_failure_code::XREF_SOURCE_NOT_FOUND,
                "effective source root has no resolved path",
            ));
        };
        let source = read_portable_session(Path::new(path))?;
        let source = unit_requirement(&source.evidence().host_units);
        let host = self
            .locked_host_units
            .as_ref()
            .map(|units| unit_requirement(&XrefEvidenceValue::Proven(*units)))
            .unwrap_or(XrefUnitRoleRequirement::Unsupported);
        Ok(XrefUnitRequirements { source, host })
    }

    fn supports_profile_unit(&mut self, _role: XrefUnitRole, _unit: xrefs::InsertionUnit) -> bool {
        false
    }

    fn verify_attachment_preservation(
        &mut self,
        verification: &XrefPreservationVerification<'_>,
    ) -> Result<(), XrefError> {
        if verification.profile_id != "xref-preservation-v1" {
            return Err(XrefError::new(
                xref_failure_code::UNSUPPORTED_XREF_DATA,
                "active preservation profile is unknown to the portable runtime",
            ));
        }
        Err(XrefError::new(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            "the selected parser backend cannot project every object and symbol field required by xref-preservation-v1",
        ))
    }

    fn verify_layer_reconciliation(
        &mut self,
        _verification: &XrefReconciliationVerification<'_>,
    ) -> Result<(), XrefError> {
        Err(XrefError::new(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            "portable layer reads do not prove AutoCAD override provenance required for reconciliation",
        ))
    }
}

fn unit_requirement(units: &Fact<PersistedInsertionUnits>) -> XrefUnitRoleRequirement {
    match units {
        XrefEvidenceValue::Proven(PersistedInsertionUnits::Known { .. }) => {
            XrefUnitRoleRequirement::Proven
        }
        XrefEvidenceValue::Proven(PersistedInsertionUnits::Unitless) => {
            XrefUnitRoleRequirement::AssumptionRequired
        }
        XrefEvidenceValue::Proven(PersistedInsertionUnits::UnknownCode { .. })
        | XrefEvidenceValue::Proven(PersistedInsertionUnits::Unobservable)
        | XrefEvidenceValue::Unavailable(_)
        | XrefEvidenceValue::Unsupported(_)
        | XrefEvidenceValue::Contradictory(_) => XrefUnitRoleRequirement::Unsupported,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ProductionInstanceFactSource;

impl XrefInstanceMutationFactSource for ProductionInstanceFactSource {
    fn read_environment(
        &mut self,
        host: &xref_io::LoadedXrefHost,
    ) -> Result<XrefInstanceMutationEnvironment, XrefTransactionError> {
        instance_environment(host)
            .map_err(|error| domain_transaction_error(error.code(), error.to_string()))
    }

    fn read_preservation_snapshot(
        &mut self,
        host: &xref_io::LoadedXrefHost,
    ) -> Result<XrefAttachmentMutationSnapshot, XrefTransactionError> {
        attachment_snapshot_from_host(host)
            .map_err(|error| domain_transaction_error(error.code(), error.to_string()))
    }

    fn verify_preservation(
        &mut self,
        verification: &XrefPreservationVerification<'_>,
    ) -> Result<(), XrefTransactionError> {
        ProductionAttachmentServices::default()
            .verify_attachment_preservation(verification)
            .map_err(|error| domain_transaction_error(error.code(), error.to_string()))
    }
}

fn instance_environment(
    host: &xref_io::LoadedXrefHost,
) -> Result<XrefInstanceMutationEnvironment, XrefError> {
    let portable = host.evidence();
    let attachments = host.attachments()?;
    let attachment_handles = attachments
        .iter()
        .map(|attachment| attachment.handle.as_str())
        .collect::<BTreeSet<_>>();
    let mut owners = Vec::new();
    for owner in &portable.owners {
        let handle = fact(&owner.handle, "owner handle")?;
        let owner_type = fact(&owner.owner_type, "owner type")?;
        let name = fact(&owner.name, "owner name")?;
        let mutation_owner = XrefOwnerMutationEvidence {
            handle: handle.clone(),
            owner_type,
            name: name.clone(),
            writable: false,
        };
        owners.push(XrefInstanceOwnerFacts {
            handle,
            owner_type,
            name,
            write_state: owner_write_state(&mutation_owner, &attachment_handles),
        });
    }
    let mut layers = Vec::new();
    for layer in &portable.layers {
        let properties = fact(&layer.properties, "layer state")?;
        layers.push(XrefInstanceLayerFacts {
            handle: fact(&layer.handle, "layer handle")?,
            name: fact(&layer.name, "layer name")?,
            ownership: if fact(&layer.xref_dependent, "layer ownership")? {
                XrefLayerOwnership::XrefDependent
            } else {
                XrefLayerOwnership::HostOwned
            },
            locked: properties.locked,
        });
    }
    let clips = portable
        .instance_clips
        .iter()
        .map(|(handle, clip)| {
            (
                handle.clone(),
                match clip {
                    XrefPortableClipEvidence::Absent => XrefInstanceClipFacts::Absent,
                    XrefPortableClipEvidence::Unproven => XrefInstanceClipFacts::Unobservable,
                },
            )
        })
        .collect();
    let mut attachment_units = BTreeMap::new();
    for evidence in &portable.attachments {
        if let (
            XrefEvidenceValue::Proven(handle),
            XrefEvidenceValue::Proven(units),
            XrefMembershipEvidence::Direct(_),
        ) = (
            &evidence.handle,
            &evidence.insertion_units,
            &evidence.membership,
        ) {
            attachment_units.insert(handle.clone(), *units);
        }
    }
    let host_units = fact(&portable.host_units, "host insertion units")?;
    Ok(XrefInstanceMutationEnvironment {
        owners,
        layers,
        block_references: portable.block_references.clone(),
        block_reference_graph_complete: portable.block_references_complete,
        clips,
        units: XrefInstanceUnitFacts {
            host_units,
            attachment_units,
            host_unobservable_uses_profile_default: false,
            source_unobservable_uses_profile_default: BTreeSet::new(),
            supported_profile_default_units: Vec::new(),
        },
    })
}

#[derive(Debug, Clone, Copy, Default)]
struct ProductionBindPersistedEvidenceReader;

impl BindPersistedEvidenceReader for ProductionBindPersistedEvidenceReader {
    fn read_persisted_bind_evidence(
        &mut self,
        temporary_host: &Path,
        plan: &BindPlan,
        _execution: &BindExecutionEvidence,
    ) -> Result<BindExecutionEvidence, BindError> {
        read_portable_session(temporary_host).map_err(|error| {
            BindError::verification(format!(
                "cannot inspect persisted post-save temporary host for bind verification: {error}"
            ))
        })?;
        Err(BindError::verification(format!(
            "the selected parser backend cannot project every persisted object and symbol field required by bind verifier '{}' from the post-save temporary host",
            plan.verifier.profile_id
        )))
    }
}

fn graph_with_virtual_root(
    drawing_path: &str,
    attachment: XrefAttachmentRecord,
    search_paths: &[String],
) -> Result<XrefDependencyTraversalEnvelope, XrefError> {
    let host = xref_io::load_xref_host(Path::new(drawing_path), "xref_mutation")?;
    graph_with_virtual_root_for_host(&host, attachment, search_paths)
}

fn graph_with_virtual_root_for_host(
    host: &xref_io::LoadedXrefHost,
    attachment: XrefAttachmentRecord,
    search_paths: &[String],
) -> Result<XrefDependencyTraversalEnvelope, XrefError> {
    let source = XrefGraphSource::try_new(
        host.display_path().clone(),
        host.filesystem_identity().clone(),
        vec![attachment.clone()],
    )?;
    let mut provider = FilesystemXrefProvider::with_host(host);
    let search_paths = validate_search_paths(search_paths, source.platform(), &mut provider)
        .map_err(|error| {
            XrefError::new(xref_failure_code::INVALID_SEARCH_PATH, error.to_string())
        })?;
    traverse_xref_dependencies_for_mutation(
        &source,
        Some(&XrefSelector {
            handle: Some(attachment.handle),
            name: None,
        }),
        &search_paths,
        &mut provider,
    )
}

struct ExistingGraphPreflight {
    graph: XrefDependencyTraversalEnvelope,
    sources: Vec<crate::ops::xref_mutation::XrefSourceInput>,
    host_digest_sha256: String,
}

fn graph_for_existing(
    drawing_path: &str,
    handle: Option<String>,
    name: Option<String>,
    search_paths: &[String],
) -> Result<ExistingGraphPreflight, XrefError> {
    let host = xref_io::load_xref_host(Path::new(drawing_path), "xref_mutation")?;
    let source = host.graph_source()?;
    let mut provider = FilesystemXrefProvider::with_host(&host);
    let search_paths = validate_search_paths(search_paths, source.platform(), &mut provider)
        .map_err(|error| {
            XrefError::new(xref_failure_code::INVALID_SEARCH_PATH, error.to_string())
        })?;
    let graph = traverse_xref_dependencies_for_mutation(
        &source,
        Some(&XrefSelector { handle, name }),
        &search_paths,
        &mut provider,
    )?;
    let mut sources = source_inputs(&graph)?;
    for source in &mut sources {
        source.inspected_digest_sha256 = provider
            .inspected_content_sha256(&source.path.to_string_lossy())
            .map(str::to_string);
    }
    Ok(ExistingGraphPreflight {
        graph,
        sources,
        host_digest_sha256: host.content_sha256().to_string(),
    })
}

fn source_inputs(
    graph: &XrefDependencyTraversalEnvelope,
) -> Result<Vec<crate::ops::xref_mutation::XrefSourceInput>, XrefError> {
    source_inputs_from_effective_graph(graph).map_err(transaction_error_to_xref)
}

#[cfg(test)]
pub fn attach_xref_file(request: AttachXrefRequest) -> Result<AttachXrefResponse, XrefError> {
    attach_xref_file_impl(request, XrefRuntimeActivation::Legacy)
}

pub fn attach_xref_file_with_activation(
    request: AttachXrefRequest,
    runtime: &ProductionMutationRuntime,
) -> Result<AttachXrefResponse, XrefError> {
    attach_xref_file_impl(request, XrefRuntimeActivation::Managed(runtime))
}

fn attach_xref_file_impl(
    request: AttachXrefRequest,
    activation: XrefRuntimeActivation<'_>,
) -> Result<AttachXrefResponse, XrefError> {
    validate_attach_xref_context_free(&request).map_err(transaction_error_to_xref)?;
    let host_path = PathBuf::from(&request.drawing_path);
    let (selected, mut profile) =
        activation.preflight_and_profile(&host_path, XrefMutationOperation::AttachXref, || {
            validate_attach_request(&request)
        })?;
    let source_path = validate_mutation_source_path(&request.xref_path)
        .map_err(|error| XrefError::new(xref_failure_code::INVALID_XREF_PATH, error.to_string()))?;
    let graph = graph_with_virtual_root(
        &request.drawing_path,
        XrefAttachmentRecord {
            handle: "1".to_string(),
            name: request.name.clone().unwrap_or_else(|| "XREF".to_string()),
            saved_path: source_path.saved_path().to_string(),
            path_mode: source_path.mode(),
            reference_type: request.reference_type,
            load_state: xrefs::LoadState::Unavailable,
            instance_count: 0,
            definition_base_point: XrefPointAvailability::Unavailable,
        },
        request.search_paths.as_deref().unwrap_or_default(),
    )?;
    let sources = source_inputs(&graph)?;
    let mut services = ProductionAttachmentServices::default();
    let mut operation =
        prepare_attach_xref(request, sources, &mut services).map_err(transaction_error_to_xref)?;
    let transaction = operation.transaction_request(std::mem::take(&mut profile));
    execute_production(&transaction, &mut operation, selected)
}

#[cfg(test)]
pub fn update_xref_file(request: UpdateXrefRequest) -> Result<UpdateXrefResponse, XrefError> {
    update_xref_file_impl(request, XrefRuntimeActivation::Legacy)
}

pub fn update_xref_file_with_activation(
    request: UpdateXrefRequest,
    runtime: &ProductionMutationRuntime,
) -> Result<UpdateXrefResponse, XrefError> {
    update_xref_file_impl(request, XrefRuntimeActivation::Managed(runtime))
}

fn update_xref_file_impl(
    request: UpdateXrefRequest,
    activation: XrefRuntimeActivation<'_>,
) -> Result<UpdateXrefResponse, XrefError> {
    validate_update_xref_step_two(&request).map_err(transaction_error_to_xref)?;
    let host_path = PathBuf::from(&request.drawing_path);
    let (selected, profile) =
        activation.preflight_and_profile(&host_path, XrefMutationOperation::UpdateXref, || {
            validate_update_request(&request)
        })?;
    let sources = if let Some(path) = request.properties.get("xref_path") {
        let path = serde_json::from_value::<String>(path.clone()).map_err(|_| {
            XrefError::new(
                xref_failure_code::INVALID_XREF_PROPERTY,
                "properties.xref_path must be a string",
            )
        })?;
        let path = validate_mutation_source_path(&path).map_err(|error| {
            XrefError::new(xref_failure_code::INVALID_XREF_PATH, error.to_string())
        })?;
        let host = xref_io::load_xref_host(&host_path, "xref_mutation")?;
        let mut selected = host.get_attachment(&XrefSelector {
            handle: request.handle.clone(),
            name: request.name.clone(),
        })?;
        selected.saved_path = path.saved_path().to_string();
        selected.path_mode = path.mode();
        if let Some(name) = request.properties.get("name") {
            selected.name = serde_json::from_value(name.clone()).map_err(|_| {
                XrefError::new(
                    xref_failure_code::INVALID_XREF_PROPERTY,
                    "properties.name must be a string",
                )
            })?;
        }
        if let Some(reference_type) = request.properties.get("reference_type") {
            selected.reference_type =
                serde_json::from_value(reference_type.clone()).map_err(|_| {
                    XrefError::new(
                        xref_failure_code::INVALID_XREF_PROPERTY,
                        "properties.reference_type must be attachment or overlay",
                    )
                })?;
        }
        let graph = graph_with_virtual_root_for_host(
            &host,
            selected,
            request.search_paths.as_deref().unwrap_or_default(),
        )?;
        source_inputs(&graph)?
    } else {
        Vec::new()
    };
    let mut services = ProductionAttachmentServices::default();
    let mut operation =
        prepare_update_xref(request, sources, &mut services).map_err(transaction_error_to_xref)?;
    let transaction = operation.transaction_request(profile);
    execute_production(&transaction, &mut operation, selected)
}

#[cfg(test)]
pub fn detach_xref_file(request: DetachXrefRequest) -> Result<DetachXrefResponse, XrefError> {
    detach_xref_file_impl(request, XrefRuntimeActivation::Legacy)
}

pub fn detach_xref_file_with_activation(
    request: DetachXrefRequest,
    runtime: &ProductionMutationRuntime,
) -> Result<DetachXrefResponse, XrefError> {
    detach_xref_file_impl(request, XrefRuntimeActivation::Managed(runtime))
}

fn detach_xref_file_impl(
    request: DetachXrefRequest,
    activation: XrefRuntimeActivation<'_>,
) -> Result<DetachXrefResponse, XrefError> {
    let host_path = PathBuf::from(&request.drawing_path);
    let (selected, profile) =
        activation.preflight_and_profile(&host_path, XrefMutationOperation::DetachXref, || {
            validate_detach_request(&request)
        })?;
    let mut services = ProductionAttachmentServices::default();
    let mut operation =
        prepare_detach_xref(request, &mut services).map_err(transaction_error_to_xref)?;
    let transaction = operation.transaction_request(profile);
    execute_production(&transaction, &mut operation, selected)
}

#[cfg(test)]
pub fn insert_xref_instance_file(
    request: InsertXrefInstanceRequest,
) -> Result<InsertXrefInstanceResponse, XrefError> {
    insert_xref_instance_file_impl(request, XrefRuntimeActivation::Legacy)
}

pub fn insert_xref_instance_file_with_activation(
    request: InsertXrefInstanceRequest,
    runtime: &ProductionMutationRuntime,
) -> Result<InsertXrefInstanceResponse, XrefError> {
    insert_xref_instance_file_impl(request, XrefRuntimeActivation::Managed(runtime))
}

fn insert_xref_instance_file_impl(
    request: InsertXrefInstanceRequest,
    activation: XrefRuntimeActivation<'_>,
) -> Result<InsertXrefInstanceResponse, XrefError> {
    validate_insert_xref_instance_step_two(&request).map_err(transaction_error_to_xref)?;
    let host_path = PathBuf::from(&request.drawing_path);
    let (selected, mut profile) = activation.preflight_and_profile(
        &host_path,
        XrefMutationOperation::InsertXrefInstance,
        || validate_insert_instance_request(&request),
    )?;
    profile.unit_defaults = xref_instance_unit_profile_defaults(request.unit_assumptions.as_ref());
    let reader = PortableXrefInstanceMutationReader::new(ProductionInstanceFactSource);
    let mut operation =
        InsertXrefInstanceOperation::new(request, reader).map_err(transaction_error_to_xref)?;
    let transaction = XrefTransactionRequest {
        host_path,
        operation: XrefMutationOperation::InsertXrefInstance,
        sources: Vec::new(),
        profile,
    };
    execute_production(&transaction, &mut operation, selected)
}

#[cfg(test)]
pub fn update_xref_instance_file(
    request: UpdateXrefInstanceRequest,
) -> Result<UpdateXrefInstanceResponse, XrefError> {
    update_xref_instance_file_impl(request, XrefRuntimeActivation::Legacy)
}

pub fn update_xref_instance_file_with_activation(
    request: UpdateXrefInstanceRequest,
    runtime: &ProductionMutationRuntime,
) -> Result<UpdateXrefInstanceResponse, XrefError> {
    update_xref_instance_file_impl(request, XrefRuntimeActivation::Managed(runtime))
}

fn update_xref_instance_file_impl(
    request: UpdateXrefInstanceRequest,
    activation: XrefRuntimeActivation<'_>,
) -> Result<UpdateXrefInstanceResponse, XrefError> {
    validate_update_xref_instance_step_two(&request).map_err(transaction_error_to_xref)?;
    let host_path = PathBuf::from(&request.drawing_path);
    let (selected, profile) = activation.preflight_and_profile(
        &host_path,
        XrefMutationOperation::UpdateXrefInstance,
        || validate_update_instance_request(&request),
    )?;
    let reader = PortableXrefInstanceMutationReader::new(ProductionInstanceFactSource);
    let mut operation =
        UpdateXrefInstanceOperation::new(request, reader).map_err(transaction_error_to_xref)?;
    let transaction = XrefTransactionRequest {
        host_path,
        operation: XrefMutationOperation::UpdateXrefInstance,
        sources: Vec::new(),
        profile,
    };
    execute_production(&transaction, &mut operation, selected)
}

#[cfg(test)]
pub fn delete_xref_instance_file(
    request: DeleteXrefInstanceRequest,
) -> Result<DeleteXrefInstanceResponse, XrefError> {
    delete_xref_instance_file_impl(request, XrefRuntimeActivation::Legacy)
}

pub fn delete_xref_instance_file_with_activation(
    request: DeleteXrefInstanceRequest,
    runtime: &ProductionMutationRuntime,
) -> Result<DeleteXrefInstanceResponse, XrefError> {
    delete_xref_instance_file_impl(request, XrefRuntimeActivation::Managed(runtime))
}

fn delete_xref_instance_file_impl(
    request: DeleteXrefInstanceRequest,
    activation: XrefRuntimeActivation<'_>,
) -> Result<DeleteXrefInstanceResponse, XrefError> {
    let host_path = PathBuf::from(&request.drawing_path);
    let (selected, profile) = activation.preflight_and_profile(
        &host_path,
        XrefMutationOperation::DeleteXrefInstance,
        || validate_delete_instance_request(&request),
    )?;
    let reader = PortableXrefInstanceMutationReader::new(ProductionInstanceFactSource);
    let mut operation =
        DeleteXrefInstanceOperation::new(request, reader).map_err(transaction_error_to_xref)?;
    let transaction = XrefTransactionRequest {
        host_path,
        operation: XrefMutationOperation::DeleteXrefInstance,
        sources: Vec::new(),
        profile,
    };
    execute_production(&transaction, &mut operation, selected)
}

#[cfg(test)]
pub fn unload_xref_file(request: UnloadXrefRequest) -> Result<UnloadXrefResponse, XrefError> {
    unload_xref_file_impl(request, XrefRuntimeActivation::Legacy)
}

pub fn unload_xref_file_with_activation(
    request: UnloadXrefRequest,
    runtime: &ProductionMutationRuntime,
) -> Result<UnloadXrefResponse, XrefError> {
    unload_xref_file_impl(request, XrefRuntimeActivation::Managed(runtime))
}

fn unload_xref_file_impl(
    request: UnloadXrefRequest,
    activation: XrefRuntimeActivation<'_>,
) -> Result<UnloadXrefResponse, XrefError> {
    let host_path = PathBuf::from(&request.drawing_path);
    let (selected, profile) =
        activation.preflight_and_profile(&host_path, XrefMutationOperation::UnloadXref, || {
            validate_unload_request(&request)
        })?;
    let mut services = ProductionAttachmentServices::default();
    let mut operation =
        prepare_unload_xref(request, &mut services).map_err(transaction_error_to_xref)?;
    let transaction = operation.transaction_request(profile);
    execute_production(&transaction, &mut operation, selected)
}

#[cfg(test)]
pub fn reload_xref_file(request: ReloadXrefRequest) -> Result<ReloadXrefResponse, XrefError> {
    reload_xref_file_impl(request, XrefRuntimeActivation::Legacy)
}

pub fn reload_xref_file_with_activation(
    request: ReloadXrefRequest,
    runtime: &ProductionMutationRuntime,
) -> Result<ReloadXrefResponse, XrefError> {
    reload_xref_file_impl(request, XrefRuntimeActivation::Managed(runtime))
}

fn reload_xref_file_impl(
    request: ReloadXrefRequest,
    activation: XrefRuntimeActivation<'_>,
) -> Result<ReloadXrefResponse, XrefError> {
    if let Some(reconciliation) = &request.layer_reconciliation {
        reconciliation.clone().validate()?;
    }
    let host_path = PathBuf::from(&request.drawing_path);
    let (selected, profile) =
        activation.preflight_and_profile(&host_path, XrefMutationOperation::ReloadXref, || {
            validate_reload_request(&request)
        })?;
    let preflight = graph_for_existing(
        &request.drawing_path,
        request.handle.clone(),
        request.name.clone(),
        request.search_paths.as_deref().unwrap_or_default(),
    )?;
    let sources = preflight.sources;
    let mut services = ProductionAttachmentServices::default();
    let mut operation =
        prepare_reload_xref(request, sources, &mut services).map_err(transaction_error_to_xref)?;
    let transaction = operation.transaction_request(profile);
    execute_production(&transaction, &mut operation, selected)
}

#[cfg(test)]
pub fn bind_xref_file(request: BindXrefRequest) -> Result<BindXrefResponse, XrefError> {
    bind_xref_file_impl(request, XrefRuntimeActivation::Legacy)
}

pub fn bind_xref_file_with_activation(
    request: BindXrefRequest,
    runtime: &ProductionMutationRuntime,
) -> Result<BindXrefResponse, XrefError> {
    bind_xref_file_impl(request, XrefRuntimeActivation::Managed(runtime))
}

fn bind_xref_file_impl(
    request: BindXrefRequest,
    activation: XrefRuntimeActivation<'_>,
) -> Result<BindXrefResponse, XrefError> {
    let host_path = PathBuf::from(&request.drawing_path);
    let (selected, profile) =
        activation.preflight_and_profile(&host_path, XrefMutationOperation::BindXref, || {
            validate_bind_request(&request)
        })?;
    let preflight = graph_for_existing(
        &request.drawing_path,
        request.handle.clone(),
        request.name.clone(),
        request.search_paths.as_deref().unwrap_or_default(),
    )?;
    let graph = preflight.graph;
    let sources = preflight.sources;
    let input = BindPreflightInput {
        request,
        dependency_graph: graph,
        host_digest_sha256: Some(preflight.host_digest_sha256),
        source_inputs: sources.clone(),
        host_symbols: Vec::new(),
        dependent_symbols: Vec::new(),
        instances: Vec::new(),
        pre_projection: BindStructuralProjection {
            complete: false,
            objects: Vec::new(),
            symbols: Vec::new(),
            clips: Vec::new(),
        },
    };
    let drawing_path = PathBuf::from(&input.request.drawing_path);
    let mut operation = BindXrefOperation::new(input, ProductionBindPersistedEvidenceReader);
    let transaction = XrefTransactionRequest {
        host_path: drawing_path,
        operation: XrefMutationOperation::BindXref,
        sources,
        profile,
    };
    execute_production(&transaction, &mut operation, selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admitted_fixture() -> (tempfile::TempDir, PathBuf) {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .join("tests/fixtures/xrefs/portable-evidence-ascii.dxf");
        let bytes = fs::read(&fixture).unwrap();
        let bytes = String::from_utf8(bytes)
            .unwrap()
            .replacen("AC1027", "AC1032", 1);
        let directory = tempfile::tempdir().unwrap();
        let admitted = directory.path().join("admitted.dxf");
        fs::write(&admitted, bytes).unwrap();
        (directory, admitted)
    }

    struct FakeDiscovery {
        windows: bool,
        identity: Option<Result<crate::engine::AutocadEngineIdentity, String>>,
    }

    impl RuntimeEngineDiscovery for FakeDiscovery {
        fn is_windows(&self) -> bool {
            self.windows
        }

        fn detect_identity(&mut self) -> Result<crate::engine::AutocadEngineIdentity, String> {
            self.identity.take().expect("identity requested once")
        }
    }

    #[test]
    fn transaction_error_mapping_preserves_registered_domain_codes() {
        let error = transaction_error_to_xref(domain_transaction_error(
            xref_failure_code::XREF_NOT_FOUND,
            "missing",
        ));
        assert_eq!(error.code(), xref_failure_code::XREF_NOT_FOUND);
    }

    #[test]
    fn transaction_error_mapping_closes_unknown_domain_codes() {
        let error = transaction_error_to_xref(domain_transaction_error("future_code", "detail"));
        assert_eq!(error.code(), xref_failure_code::UNSUPPORTED_XREF_DATA);
        assert!(error.to_string().contains("future_code"));
    }

    #[test]
    fn certified_arg_digest_parser_is_exact() {
        assert_eq!(decode_sha256(&"00".repeat(32)).unwrap(), [0; 32]);
        assert_eq!(
            decode_sha256("xyz").unwrap_err().code(),
            xref_failure_code::AUTOCAD_UNAVAILABLE
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn unsupported_format_precedes_the_non_windows_platform_gate() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .join("tests/fixtures/xrefs/portable-evidence-ascii.dxf");
        let error = unload_xref_file(UnloadXrefRequest {
            drawing_path: fixture.to_string_lossy().into_owned(),
            handle: Some("F".to_string()),
            name: None,
            expected_handle: None,
            expected_name: None,
        })
        .expect_err("AC1027 is outside the embedded mutation matrix");
        assert_eq!(error.code(), xref_failure_code::UNSUPPORTED_FORMAT);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn attach_unsupported_format_reports_recovery_without_internal_matrix_terms() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .join("tests/fixtures/xrefs/portable-evidence-ascii.dxf");
        let error = attach_xref_file(AttachXrefRequest {
            drawing_path: fixture.to_string_lossy().into_owned(),
            xref_path: "source.dwg".to_string(),
            name: Some("SOURCE".to_string()),
            reference_type: xrefs::ReferenceType::Attachment,
            search_paths: None,
            placement: None,
            unit_assumptions: None,
        })
        .expect_err("AC1027 is outside the embedded mutation matrix");

        assert_eq!(error.code(), xref_failure_code::UNSUPPORTED_FORMAT);
        let detail = error.to_string();
        assert!(detail.contains("attach_xref is not admitted for detected host format"));
        assert!(detail.contains("DXF AC1027 ASCII (code page ANSI_1252)"));
        assert!(detail.contains("DXF AC1032 ASCII (code page ANSI_1252)"));
        assert!(detail.contains("recovery="));
        assert!(!detail.contains("capability row"));
        assert!(!detail.contains("format-only"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn admitted_format_reaches_platform_without_loading_the_arg_profile() {
        let (_directory, admitted) = admitted_fixture();
        let before = fs::read(&admitted).unwrap();

        let error = unload_xref_file(UnloadXrefRequest {
            drawing_path: admitted.to_string_lossy().into_owned(),
            handle: Some("F".to_string()),
            name: None,
            expected_handle: None,
            expected_name: None,
        })
        .expect_err("admitted hosts cannot mutate off Windows");
        assert_eq!(error.code(), xref_failure_code::UNSUPPORTED_PLATFORM);
        let detail = error.to_string();
        assert!(detail.contains("unload_xref"));
        assert!(detail.contains("DXF AC1032 ASCII (code page ANSI_1252)"));
        assert!(detail.contains("current_platform="));
        assert!(detail.contains("required_engine="));
        assert!(detail.contains("recovery="));
        assert_eq!(fs::read(&admitted).unwrap(), before);
    }

    #[test]
    fn non_launching_discovery_precedes_profile_and_source_work() {
        let (_directory, admitted) = admitted_fixture();
        let mut discovery = FakeDiscovery {
            windows: true,
            identity: Some(Err("accoreconsole missing".to_string())),
        };
        let error =
            preflight_with_discovery(&admitted, XrefMutationOperation::ReloadXref, &mut discovery)
                .expect_err("discovery failure must stop preflight");
        assert_eq!(error.code(), xref_failure_code::AUTOCAD_UNAVAILABLE);
        assert!(error.to_string().contains("accoreconsole missing"));
    }

    #[test]
    fn managed_release_xref_path_fails_closed_without_qualification() {
        let (_directory, admitted) = admitted_fixture();
        let runtime = ProductionMutationRuntime::new(crate::activation::ActivationMode::Release);
        let error = unload_xref_file_with_activation(
            UnloadXrefRequest {
                drawing_path: admitted.to_string_lossy().into_owned(),
                handle: Some("F".to_string()),
                name: None,
                expected_handle: None,
                expected_name: None,
            },
            &runtime,
        )
        .expect_err("Release XREF mutation must require external qualification");

        assert_eq!(error.code(), xref_failure_code::UNSUPPORTED_PLATFORM);
        assert!(
            error
                .to_string()
                .contains("Release AutoCAD activation is unavailable"),
            "{error}"
        );
        assert!(runtime.selected().is_none());
    }

    #[test]
    fn uncertified_product_reports_the_shared_platform_recovery_contract() {
        let (_directory, admitted) = admitted_fixture();
        let mut discovery = FakeDiscovery {
            windows: true,
            identity: Some(Ok(crate::engine::AutocadEngineIdentity {
                executable: PathBuf::from("accoreconsole.exe"),
                product: "AutoCAD LT".to_string(),
                version: "2026".to_string(),
            })),
        };

        let error =
            preflight_with_discovery(&admitted, XrefMutationOperation::ReloadXref, &mut discovery)
                .expect_err("uncertified products must fail before mutation");
        assert_eq!(error.code(), xref_failure_code::UNSUPPORTED_PLATFORM);
        let detail = error.to_string();
        assert!(detail.contains("reload_xref"));
        assert!(detail.contains("DXF AC1032 ASCII (code page ANSI_1252)"));
        assert!(detail.contains("current_platform="));
        assert!(detail.contains("required_engine="));
        assert!(detail.contains("AutoCAD LT"));
        assert!(detail.contains("recovery="));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn malformed_handle_precedes_the_platform_gate() {
        let (_directory, admitted) = admitted_fixture();
        let before = fs::read(&admitted).unwrap();
        let error = unload_xref_file(UnloadXrefRequest {
            drawing_path: admitted.to_string_lossy().into_owned(),
            handle: Some("not-hex".to_string()),
            name: None,
            expected_handle: None,
            expected_name: None,
        })
        .expect_err("malformed handles must fail locally");
        assert_eq!(error.code(), xref_failure_code::INVALID_HANDLE);
        assert_eq!(fs::read(&admitted).unwrap(), before);
    }

    #[test]
    fn missing_host_precedes_selector_handle_syntax() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.dwg");
        let error = update_xref_file(UpdateXrefRequest {
            drawing_path: missing.to_string_lossy().into_owned(),
            handle: Some("not-hex".to_string()),
            name: None,
            expected_handle: None,
            expected_name: None,
            properties: BTreeMap::from([("name".to_string(), serde_json::json!("RENAMED"))]),
            layer_reconciliation: None,
            unit_assumptions: None,
            search_paths: None,
        })
        .expect_err("missing host must win before selector syntax");
        assert_eq!(error.code(), xref_failure_code::DRAWING_NOT_FOUND);
    }

    #[test]
    fn attach_missing_host_precedes_placement_handle_syntax() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.dwg");
        let error = attach_xref_file(AttachXrefRequest {
            drawing_path: missing.to_string_lossy().into_owned(),
            xref_path: "source.dwg".to_string(),
            name: Some("SOURCE".to_string()),
            reference_type: xrefs::ReferenceType::Attachment,
            search_paths: None,
            placement: Some(xrefs::XrefPlacement {
                owner_handle: Some("not-hex".to_string()),
                owner_type: None,
                owner_name: None,
                layer_handle: None,
                layer_name: None,
                insertion_point: None,
                scale: None,
                rotation_degrees: None,
                normal: None,
                visibility: None,
            }),
            unit_assumptions: None,
        })
        .expect_err("missing host must win before placement handle syntax");
        assert_eq!(error.code(), xref_failure_code::DRAWING_NOT_FOUND);
    }

    #[test]
    fn attach_context_free_scale_precedes_drawing_path_syntax() {
        let error = attach_xref_file(AttachXrefRequest {
            drawing_path: "relative-host.dwg".to_string(),
            xref_path: "source.dwg".to_string(),
            name: Some("SOURCE".to_string()),
            reference_type: xrefs::ReferenceType::Attachment,
            search_paths: None,
            placement: Some(xrefs::XrefPlacement {
                owner_handle: None,
                owner_type: None,
                owner_name: None,
                layer_handle: None,
                layer_name: None,
                insertion_point: None,
                scale: Some(xrefs::XrefScale3 {
                    x: 0.0,
                    y: 1.0,
                    z: 1.0,
                }),
                rotation_degrees: None,
                normal: None,
                visibility: None,
            }),
            unit_assumptions: None,
        })
        .expect_err("context-free scale validation must precede drawing_path syntax");
        assert_eq!(error.code(), xref_failure_code::INVALID_XREF_SCALE);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn invalid_property_precedes_the_platform_gate() {
        let (_directory, admitted) = admitted_fixture();
        let before = fs::read(&admitted).unwrap();
        let error = update_xref_file(UpdateXrefRequest {
            drawing_path: admitted.to_string_lossy().into_owned(),
            handle: Some("F".to_string()),
            name: None,
            expected_handle: None,
            expected_name: None,
            properties: BTreeMap::from([("future_property".to_string(), serde_json::json!(1))]),
            layer_reconciliation: None,
            unit_assumptions: None,
            search_paths: None,
        })
        .expect_err("unknown properties must fail locally");
        assert_eq!(error.code(), xref_failure_code::INVALID_XREF_PROPERTY);
        assert_eq!(fs::read(&admitted).unwrap(), before);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn invalid_instance_placement_precedes_the_platform_gate() {
        let (_directory, admitted) = admitted_fixture();
        let before = fs::read(&admitted).unwrap();
        let error = insert_xref_instance_file(InsertXrefInstanceRequest {
            drawing_path: admitted.to_string_lossy().into_owned(),
            attachment_handle: Some("F".to_string()),
            attachment_name: None,
            expected_attachment_handle: None,
            placement: Some(xrefs::XrefInstancePlacement {
                owner_handle: None,
                owner_type: None,
                owner_name: None,
                layer_handle: None,
                layer_name: None,
                insertion_point: None,
                scale: Some(xrefs::XrefScale3 {
                    x: 0.0,
                    y: 1.0,
                    z: 1.0,
                }),
                rotation_degrees: None,
                normal: None,
                visibility: None,
                array: None,
            }),
            unit_assumptions: None,
        })
        .expect_err("context-free placement values must fail before platform discovery");
        assert_eq!(error.code(), xref_failure_code::INVALID_XREF_SCALE);
        assert_eq!(fs::read(&admitted).unwrap(), before);
    }

    #[test]
    fn production_instance_preservation_remains_fail_closed_for_acadrust() {
        let (_directory, admitted) = admitted_fixture();
        let host = xref_io::load_xref_host(&admitted, "xref_mutation").unwrap();
        let snapshot = XrefAttachmentMutationSnapshot {
            drawing: admitted.to_string_lossy().into_owned(),
            graph_source: host.graph_source().unwrap(),
            attachments: host.attachments().unwrap(),
            instances: host.instances(&XrefInstanceListOptions::default()).unwrap(),
            block_definitions_complete: false,
            block_definitions: Vec::new(),
            owners_complete: false,
            owners: Vec::new(),
            layers_complete: false,
            layers: Vec::new(),
            attachment_preflight: Vec::new(),
            reconciliation_layers_complete: false,
            reconciliation_layers: Vec::new(),
            saved_visretain: 0,
            saved_xrefoverride: 0,
        };
        let mut facts = ProductionInstanceFactSource;
        let sources = Vec::new();
        let error = facts
            .verify_preservation(&XrefPreservationVerification {
                operation: XrefMutationOperation::InsertXrefInstance,
                profile_id: "xref-preservation-v1",
                before: &snapshot,
                after: &snapshot,
                selected_attachment_handle: Some("F"),
                source_graph: None,
                source_snapshots: &sources,
            })
            .unwrap_err();
        assert_eq!(
            error.code.as_str(),
            xref_failure_code::UNSUPPORTED_XREF_DATA
        );
        assert!(error.detail.contains(
            "the selected parser backend cannot project every object and symbol field required by xref-preservation-v1"
        ));
    }
}
