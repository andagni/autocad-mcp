use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    activation::SelectedActivation,
    certification::{
        embedded_xref_artifacts, XrefArtifactRegistry, XrefAutocadProduct, XrefBindVerifierProfile,
        XrefClipPolicy, XrefClipVerifierProfile, XrefDxfForm, XrefEmbeddedArtifact, XrefHostFormat,
        XrefMutationCapabilityRow, XrefMutationOperation, XrefPreservationVerifierProfile,
        XREF_EMBEDDED_ARTIFACTS,
    },
};

use super::xref_path::FilesystemIdentity;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct XrefCapabilityQuery<'a> {
    pub host_format: XrefHostFormat,
    pub drawing_version: &'a str,
    pub dxf_form: XrefDxfForm,
    pub code_page: Option<&'a str>,
    pub operation: XrefMutationOperation,
}

#[derive(Debug)]
pub struct XrefMutationAdmission<'a> {
    pub capability: &'a XrefMutationCapabilityRow,
    pub preservation_profile: &'a XrefPreservationVerifierProfile,
    pub bind_profile: Option<&'a XrefBindVerifierProfile>,
    pub clip_profile: Option<&'a XrefClipVerifierProfile>,
}

impl XrefMutationAdmission<'_> {
    pub fn rejects_clipped_targets(&self) -> bool {
        self.capability.clip_policy == XrefClipPolicy::Reject
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum XrefCapabilityAdmissionError {
    InvalidEmbeddedArtifacts(String),
    UnsupportedFormat {
        host_format: XrefHostFormat,
        drawing_version: String,
        dxf_form: XrefDxfForm,
        code_page: Option<String>,
    },
    OperationNotCertified {
        row_id: String,
        operation: XrefMutationOperation,
    },
    RegistryInvariant {
        row_id: String,
        profile_kind: &'static str,
        profile_id: String,
    },
}

impl fmt::Display for XrefCapabilityAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEmbeddedArtifacts(error) => {
                write!(formatter, "invalid embedded XREF artifacts: {error}")
            }
            Self::UnsupportedFormat {
                host_format,
                drawing_version,
                dxf_form,
                code_page,
            } => write!(
                formatter,
                "unsupported XREF mutation format tuple: host_format={}, drawing_version={}, dxf_form={}, code_page={}",
                host_format.as_str(),
                drawing_version,
                dxf_form.as_str(),
                code_page.as_deref().unwrap_or("null")
            ),
            Self::OperationNotCertified { row_id, operation } => write!(
                formatter,
                "capability row '{row_id}' does not certify operation '{}'",
                operation.as_str()
            ),
            Self::RegistryInvariant {
                row_id,
                profile_kind,
                profile_id,
            } => write!(
                formatter,
                "capability row '{row_id}' references missing {profile_kind} profile '{profile_id}'"
            ),
        }
    }
}

impl Error for XrefCapabilityAdmissionError {}

pub fn embedded_xref_mutation_admission(
    query: XrefCapabilityQuery<'_>,
) -> Result<XrefMutationAdmission<'static>, XrefCapabilityAdmissionError> {
    let registry = embedded_xref_artifacts().map_err(|error| {
        XrefCapabilityAdmissionError::InvalidEmbeddedArtifacts(error.to_string())
    })?;
    select_xref_mutation_capability(registry, query)
}

pub fn select_xref_mutation_capability<'a>(
    registry: &'a XrefArtifactRegistry,
    query: XrefCapabilityQuery<'_>,
) -> Result<XrefMutationAdmission<'a>, XrefCapabilityAdmissionError> {
    let Some(row) = registry.capabilities().rows.iter().find(|row| {
        row.host_format == query.host_format
            && row.drawing_version == query.drawing_version
            && row.dxf_form == query.dxf_form
            && row.code_page.as_deref() == query.code_page
    }) else {
        return Err(XrefCapabilityAdmissionError::UnsupportedFormat {
            host_format: query.host_format,
            drawing_version: query.drawing_version.to_string(),
            dxf_form: query.dxf_form,
            code_page: query.code_page.map(str::to_string),
        });
    };

    if !row.operations.contains(&query.operation) {
        return Err(XrefCapabilityAdmissionError::OperationNotCertified {
            row_id: row.row_id.clone(),
            operation: query.operation,
        });
    }

    let preservation_profile = registry
        .preservation_profile(&row.preservation_verifier_profile_id)
        .ok_or_else(|| XrefCapabilityAdmissionError::RegistryInvariant {
            row_id: row.row_id.clone(),
            profile_kind: "preservation",
            profile_id: row.preservation_verifier_profile_id.clone(),
        })?;
    let bind_profile = row
        .bind_verifier_profile_id
        .as_deref()
        .map(|profile_id| {
            registry.bind_profile(profile_id).ok_or_else(|| {
                XrefCapabilityAdmissionError::RegistryInvariant {
                    row_id: row.row_id.clone(),
                    profile_kind: "bind",
                    profile_id: profile_id.to_string(),
                }
            })
        })
        .transpose()?;
    let clip_profile = row
        .clip_verifier_profile_id
        .as_deref()
        .map(|profile_id| {
            registry.clip_profile(profile_id).ok_or_else(|| {
                XrefCapabilityAdmissionError::RegistryInvariant {
                    row_id: row.row_id.clone(),
                    profile_kind: "clip",
                    profile_id: profile_id.to_string(),
                }
            })
        })
        .transpose()?;

    Ok(XrefMutationAdmission {
        capability: row,
        preservation_profile,
        bind_profile,
        clip_profile,
    })
}

#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XrefEmbeddedArtifactDigest {
    pub file_name: String,
    pub sha256: String,
}

pub fn xref_embedded_artifact_sha256(artifact: XrefEmbeddedArtifact) -> [u8; 32] {
    artifact.sha256_digest_with(|bytes| Sha256::digest(bytes).into())
}

pub fn xref_embedded_artifact_sha256_hex(artifact: XrefEmbeddedArtifact) -> String {
    xref_embedded_artifact_sha256(artifact)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn xref_embedded_artifact_digests() -> Vec<XrefEmbeddedArtifactDigest> {
    let mut digests: Vec<_> = XREF_EMBEDDED_ARTIFACTS
        .into_iter()
        .map(|artifact| XrefEmbeddedArtifactDigest {
            file_name: artifact.file_name().to_string(),
            sha256: xref_embedded_artifact_sha256_hex(artifact),
        })
        .collect();
    digests.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    digests
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct XrefDigest([u8; 32]);

impl XrefDigest {
    fn from_reader(reader: &mut (impl Read + Seek)) -> io::Result<Self> {
        reader.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(Self(hasher.finalize().into()))
    }

    pub(crate) fn hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct XrefFileIdentity(String);

impl XrefFileIdentity {
    #[cfg(test)]
    pub(crate) fn fake(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefFileObservation {
    pub identity: XrefFileIdentity,
    pub path_identity: XrefFileIdentity,
    pub digest: XrefDigest,
}

impl XrefFileObservation {
    fn is_stable(&self) -> bool {
        self.identity == self.path_identity
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefHostFormatFacts {
    pub host_format: XrefHostFormat,
    pub drawing_version: String,
    pub dxf_form: XrefDxfForm,
    pub code_page: Option<String>,
}

impl XrefHostFormatFacts {
    fn capability_query<'a>(
        &'a self,
        engine: &'a crate::engine::AutocadEngineIdentity,
        operation: XrefMutationOperation,
    ) -> Result<XrefCapabilityQuery<'a>, XrefTransactionError> {
        if engine.product != XrefAutocadProduct::Autocad.as_str() {
            return Err(XrefTransactionError::new(
                XrefTransactionErrorCode::UnsupportedPlatform,
                unsupported_xref_platform_detail(
                    self,
                    operation,
                    std::env::consts::OS,
                    Some(&format!(
                        "detected uncertified AutoCAD product '{}'",
                        engine.product
                    )),
                ),
            ));
        }
        Ok(XrefCapabilityQuery {
            host_format: self.host_format,
            drawing_version: &self.drawing_version,
            dxf_form: self.dxf_form,
            code_page: self.code_page.as_deref(),
            operation,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum XrefTransactionErrorCode {
    UnsupportedFormat,
    UnsupportedPlatform,
    AutocadUnavailable,
    DrawingLocked,
    ConcurrentDrawingModification,
    XrefSourceChanged,
    WriteFailed,
    VerificationFailed,
    MutationStateUnknown,
    Domain(String),
}

impl XrefTransactionErrorCode {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::UnsupportedFormat => "unsupported_format",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::AutocadUnavailable => "autocad_unavailable",
            Self::DrawingLocked => "drawing_locked",
            Self::ConcurrentDrawingModification => "concurrent_drawing_modification",
            Self::XrefSourceChanged => "xref_source_changed",
            Self::WriteFailed => "write_failed",
            Self::VerificationFailed => "verification_failed",
            Self::MutationStateUnknown => "mutation_state_unknown",
            Self::Domain(code) => code,
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub(crate) struct XrefCleanupInventory {
    pub attempted: Vec<PathBuf>,
    pub removed: Vec<PathBuf>,
    pub remaining: Vec<PathBuf>,
    pub engine_stop_error: Option<String>,
}

impl XrefCleanupInventory {
    fn merge(&mut self, other: Self) {
        self.attempted.extend(other.attempted);
        self.removed.extend(other.removed);
        self.remaining.extend(other.remaining);
        if self.engine_stop_error.is_none() {
            self.engine_stop_error = other.engine_stop_error;
        }
        sort_deduplicate_paths(&mut self.attempted);
        sort_deduplicate_paths(&mut self.removed);
        sort_deduplicate_paths(&mut self.remaining);
    }

    fn is_clean(&self) -> bool {
        self.remaining.is_empty() && self.engine_stop_error.is_none()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefTransactionError {
    pub code: XrefTransactionErrorCode,
    pub detail: String,
    pub cleanup: Box<XrefCleanupInventory>,
}

impl XrefTransactionError {
    pub(crate) fn new(code: XrefTransactionErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            cleanup: Box::default(),
        }
    }

    fn with_cleanup(mut self, cleanup: XrefCleanupInventory) -> Self {
        if !cleanup.remaining.is_empty() {
            let paths = cleanup
                .remaining
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            self.detail
                .push_str(&format!("; cleanup_remaining=[{paths}]"));
        }
        if let Some(stop_error) = &cleanup.engine_stop_error {
            self.detail
                .push_str(&format!("; engine_stop_error={stop_error}"));
        }
        self.cleanup = Box::new(cleanup);
        self
    }
}

impl fmt::Display for XrefTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "code={} {}", self.code.as_str(), self.detail)
    }
}

impl Error for XrefTransactionError {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum XrefSourceIdentityProvenance {
    PathObservation,
    LockedGraphTraversal,
    DigestBoundGraphTraversal,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefSourceInput {
    pub source_id: String,
    pub path: PathBuf,
    pub saved_path: String,
    pub immediate_host_source_id: Option<String>,
    pub filesystem_identity: FilesystemIdentity,
    pub identity_provenance: XrefSourceIdentityProvenance,
    pub inspected_digest_sha256: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefSourceCaptureEvidence {
    pub path_identity_before: FilesystemIdentity,
    pub handle_identity_before: FilesystemIdentity,
    pub digest_before: XrefDigest,
    pub snapshot_digest: XrefDigest,
    pub snapshot_identity: XrefFileIdentity,
    pub handle_identity_after: FilesystemIdentity,
    pub path_identity_after: FilesystemIdentity,
    pub digest_after: XrefDigest,
}

impl XrefSourceCaptureEvidence {
    fn is_stable_for(&self, expected_identity: &FilesystemIdentity) -> bool {
        &self.path_identity_before == expected_identity
            && self.path_identity_before == self.handle_identity_before
            && self.handle_identity_before == self.handle_identity_after
            && self.handle_identity_after == self.path_identity_after
            && self.digest_before == self.snapshot_digest
            && self.snapshot_digest == self.digest_after
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct XrefSourceSnapshot {
    pub source_id: String,
    pub original_path: PathBuf,
    pub saved_path: String,
    pub immediate_host_source_id: Option<String>,
    pub snapshot_path: PathBuf,
    pub original_identity: String,
    #[serde(skip_serializing)]
    pub filesystem_identity: FilesystemIdentity,
    #[serde(skip_serializing)]
    pub snapshot_identity: XrefFileIdentity,
    pub digest_sha256: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub(crate) struct XrefIsolatedProfileSpec {
    pub certified_autocad_arg: Vec<u8>,
    pub unit_defaults: BTreeMap<String, String>,
    pub reconciliation: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct XrefIsolatedProfileDocument {
    schema_version: u32,
    #[serde(skip_serializing)]
    certified_autocad_arg: Vec<u8>,
    search_directories: Vec<PathBuf>,
    source_snapshots: Vec<XrefSourceSnapshot>,
    unit_defaults: BTreeMap<String, String>,
    reconciliation: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefMaterializedProfile {
    pub launch_path: PathBuf,
    pub artifacts: Vec<PathBuf>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefTransactionRequest {
    pub host_path: PathBuf,
    pub operation: XrefMutationOperation,
    pub sources: Vec<XrefSourceInput>,
    pub profile: XrefIsolatedProfileSpec,
}

#[derive(Debug)]
pub(crate) struct XrefLockedMutationContext<'a> {
    pub host_path: &'a Path,
    #[allow(dead_code)]
    pub host: &'a XrefFileObservation,
    pub format: &'a XrefHostFormatFacts,
    pub admission: &'a XrefMutationAdmission<'a>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefEngineLaunchContext<'a> {
    pub temporary_host: &'a Path,
    pub staging_directory: &'a Path,
    pub profile_path: &'a Path,
    pub certified_autocad_arg: &'a [u8],
    pub search_directories: &'a [PathBuf],
    pub source_snapshots: &'a [XrefSourceSnapshot],
    pub source_exclusion_proven: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefOperationContext<'a> {
    pub temporary_host: &'a Path,
    pub staging_directory: &'a Path,
    pub profile_path: &'a Path,
    pub source_snapshots: &'a [XrefSourceSnapshot],
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefVerificationContext<'a> {
    pub temporary_host: &'a Path,
    pub output: &'a XrefFileObservation,
    pub source_snapshots: &'a [XrefSourceSnapshot],
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefTransactionOutcome<Response> {
    pub response: Response,
    pub row_id: String,
    pub original_digest_sha256: String,
    pub installed_digest_sha256: String,
    pub source_snapshots: Vec<XrefSourceSnapshot>,
    pub cleanup: XrefCleanupInventory,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct XrefBoundaryError(String);

impl XrefBoundaryError {
    fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }
}

impl fmt::Display for XrefBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for XrefBoundaryError {}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum XrefPreparedInstallDisposition {
    DefinitelyNotInstalled,
    InstallationMayHaveOccurred,
}

#[derive(Debug)]
pub(crate) struct XrefPreparedInstallError<PreparedOutputGuard> {
    disposition: XrefPreparedInstallDisposition,
    error: XrefBoundaryError,
    prepared_output_guard: PreparedOutputGuard,
}

impl<PreparedOutputGuard> XrefPreparedInstallError<PreparedOutputGuard> {
    fn definitely_not_installed(
        error: XrefBoundaryError,
        prepared_output_guard: PreparedOutputGuard,
    ) -> Self {
        Self {
            disposition: XrefPreparedInstallDisposition::DefinitelyNotInstalled,
            error,
            prepared_output_guard,
        }
    }

    fn installation_may_have_occurred(
        error: XrefBoundaryError,
        prepared_output_guard: PreparedOutputGuard,
    ) -> Self {
        Self {
            disposition: XrefPreparedInstallDisposition::InstallationMayHaveOccurred,
            error,
            prepared_output_guard,
        }
    }
}

#[derive(Debug)]
pub(crate) enum XrefSourceCaptureError {
    SourceRace(XrefBoundaryError),
    SourceUnreadable(XrefBoundaryError),
    Staging(XrefBoundaryError),
}

#[derive(Debug)]
pub(crate) enum XrefSourceIdentityObservationError {
    Changed(XrefBoundaryError),
    Unreadable(XrefBoundaryError),
}

impl fmt::Display for XrefSourceIdentityObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Changed(error) | Self::Unreadable(error) => error.fmt(formatter),
        }
    }
}

impl Error for XrefSourceIdentityObservationError {}

impl fmt::Display for XrefSourceCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceRace(error) | Self::SourceUnreadable(error) | Self::Staging(error) => {
                error.fmt(formatter)
            }
        }
    }
}

impl Error for XrefSourceCaptureError {}

#[cfg(any(test, feature = "xref-certification-failpoints"))]
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum XrefCertificationFailpoint {
    DuringSourceSnapshot,
    BeforeSave,
    AfterSave,
    BeforeVerification,
    AfterVerification,
    BeforeCleanup,
    AfterCleanup,
    BeforeHostRecheck,
    AfterHostRecheck,
    BeforeReplace,
    AfterReplace,
    BeforeDirectoryFlush,
    AfterDirectoryFlush,
    BeforeInstalledDigestCheck,
}

const XREF_RACE_COORDINATION_ENV: &str = "AUTOCAD_MCP_XREF_RACE_COORDINATION";
#[cfg(target_os = "windows")]
const XREF_RACE_COORDINATION_TIMEOUT_MS: u32 = 30_000;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum XrefRaceCoordinationPoint {
    HostAfterInitialObservation,
    SourceAfterInitialDigest,
}

impl XrefRaceCoordinationPoint {
    #[cfg(target_os = "windows")]
    fn name(self) -> &'static str {
        match self {
            Self::HostAfterInitialObservation => "host_after_initial_observation",
            Self::SourceAfterInitialDigest => "source_after_initial_digest",
        }
    }
}

fn parse_xref_race_coordination(
    value: &str,
) -> Result<(XrefRaceCoordinationPoint, &str), XrefBoundaryError> {
    let (point, token) = value.split_once(':').ok_or_else(|| {
        XrefBoundaryError::new(format!(
            "{XREF_RACE_COORDINATION_ENV} must be '<point>:<token>'"
        ))
    })?;
    let point = match point {
        "host_after_initial_observation" => XrefRaceCoordinationPoint::HostAfterInitialObservation,
        "source_after_initial_digest" => XrefRaceCoordinationPoint::SourceAfterInitialDigest,
        _ => {
            return Err(XrefBoundaryError::new(format!(
                "{XREF_RACE_COORDINATION_ENV} contains an unknown point"
            )));
        }
    };
    if token.is_empty()
        || token.len() > 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(XrefBoundaryError::new(format!(
            "{XREF_RACE_COORDINATION_ENV} token must be 1-64 ASCII alphanumeric or '-' bytes"
        )));
    }
    Ok((point, token))
}

fn coordinate_xref_race_driver(
    requested_point: XrefRaceCoordinationPoint,
) -> Result<(), XrefBoundaryError> {
    let Some(value) = std::env::var_os(XREF_RACE_COORDINATION_ENV) else {
        return Ok(());
    };
    let value = value.to_str().ok_or_else(|| {
        XrefBoundaryError::new(format!(
            "{XREF_RACE_COORDINATION_ENV} must be valid Unicode"
        ))
    })?;
    let (configured_point, token) = parse_xref_race_coordination(value)?;
    if configured_point != requested_point {
        return Ok(());
    }

    static USED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if USED.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return Ok(());
    }
    coordinate_xref_race_driver_platform(configured_point, token)
}

#[cfg(target_os = "windows")]
fn coordinate_xref_race_driver_platform(
    point: XrefRaceCoordinationPoint,
    token: &str,
) -> Result<(), XrefBoundaryError> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        Storage::FileSystem::SYNCHRONIZE,
        System::Threading::{OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE},
    };

    fn event_name(token: &str, point: XrefRaceCoordinationPoint, suffix: &str) -> Vec<u16> {
        format!(
            "Local\\AutoCADMcpXrefRace-{token}-{}-{suffix}",
            point.name()
        )
        .encode_utf16()
        .chain(Some(0))
        .collect()
    }

    let ready_name = event_name(token, point, "ready");
    let continue_name = event_name(token, point, "continue");
    let ready = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, ready_name.as_ptr()) };
    if ready.is_null() {
        return Err(XrefBoundaryError::new(format!(
            "open XREF race ready event: {}",
            io::Error::last_os_error()
        )));
    }
    let ready = unsafe { OwnedHandle::from_raw_handle(ready) };
    let continue_event = unsafe { OpenEventW(SYNCHRONIZE, 0, continue_name.as_ptr()) };
    if continue_event.is_null() {
        return Err(XrefBoundaryError::new(format!(
            "open XREF race continue event: {}",
            io::Error::last_os_error()
        )));
    }
    let continue_event = unsafe { OwnedHandle::from_raw_handle(continue_event) };
    use std::os::windows::io::AsRawHandle;
    if unsafe { SetEvent(ready.as_raw_handle()) } == 0 {
        return Err(XrefBoundaryError::new(format!(
            "signal XREF race ready event: {}",
            io::Error::last_os_error()
        )));
    }
    match unsafe {
        WaitForSingleObject(
            continue_event.as_raw_handle(),
            XREF_RACE_COORDINATION_TIMEOUT_MS,
        )
    } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(XrefBoundaryError::new(
            "timed out waiting for deterministic XREF race driver",
        )),
        WAIT_FAILED => Err(XrefBoundaryError::new(format!(
            "wait for XREF race driver: {}",
            io::Error::last_os_error()
        ))),
        status => Err(XrefBoundaryError::new(format!(
            "unexpected XREF race wait status {status}"
        ))),
    }
}

#[cfg(not(target_os = "windows"))]
fn coordinate_xref_race_driver_platform(
    _point: XrefRaceCoordinationPoint,
    _token: &str,
) -> Result<(), XrefBoundaryError> {
    Err(XrefBoundaryError::new(
        "deterministic XREF race coordination requires Windows named events",
    ))
}

pub(crate) trait XrefMutationEngineBoundary {
    fn is_windows(&mut self) -> bool;
    fn detect_identity(
        &mut self,
    ) -> Result<crate::engine::AutocadEngineIdentity, XrefBoundaryError>;
    fn prove_exclusive_source_snapshot_resolution(
        &mut self,
        _context: &XrefEngineLaunchContext<'_>,
    ) -> Result<(), XrefBoundaryError> {
        Err(XrefBoundaryError::new(
            "engine boundary cannot prove saved-path resolution is exclusive to transaction snapshots",
        ))
    }
    fn launch(&mut self, context: &XrefEngineLaunchContext<'_>) -> Result<(), XrefBoundaryError>;
    fn execute_operation(&mut self, script: &Path) -> Result<(), XrefBoundaryError>;
    fn save(&mut self, format: &XrefHostFormatFacts) -> Result<(), XrefBoundaryError>;
    fn auxiliary_artifacts(&self) -> Vec<PathBuf>;
    fn stop(&mut self) -> Result<(), XrefBoundaryError>;

    #[cfg(any(test, feature = "xref-certification-failpoints"))]
    fn certification_failpoint(
        &mut self,
        failpoint: XrefCertificationFailpoint,
    ) -> Result<(), XrefBoundaryError>;
}

pub(crate) trait XrefMutationFileSystem {
    type OriginalHostGuard;
    type PreparedOutputGuard;
    type InstalledHostGuard;

    fn observe_path(&mut self, path: &Path) -> Result<XrefFileObservation, XrefBoundaryError>;
    fn acquire_original_host_guard(
        &mut self,
        path: &Path,
    ) -> Result<Self::OriginalHostGuard, XrefBoundaryError>;
    fn observe_original_host(
        &mut self,
        guard: &Self::OriginalHostGuard,
    ) -> Result<XrefFileObservation, XrefBoundaryError>;
    fn validate_host_replacement_guard(
        &mut self,
        guard: &Self::OriginalHostGuard,
    ) -> Result<(), XrefBoundaryError>;
    fn copy_locked_host_to_sibling(
        &mut self,
        guard: &Self::OriginalHostGuard,
        format: XrefHostFormat,
    ) -> Result<PathBuf, XrefBoundaryError>;
    fn create_staging_directory(&mut self) -> Result<PathBuf, XrefBoundaryError>;
    fn capture_source(
        &mut self,
        source: &Path,
        destination: &Path,
        expected_identity: &FilesystemIdentity,
    ) -> Result<XrefSourceCaptureEvidence, XrefSourceCaptureError>;
    fn observe_source_snapshot(
        &mut self,
        path: &Path,
    ) -> Result<XrefFileObservation, XrefBoundaryError>;
    fn prove_exclusive_source_snapshot_resolution(
        &mut self,
        _snapshots: &[XrefSourceSnapshot],
    ) -> Result<(), XrefBoundaryError> {
        Err(XrefBoundaryError::new(
            "filesystem boundary cannot exclude reads through original XREF source paths",
        ))
    }
    fn materialize_profile(
        &mut self,
        staging_directory: &Path,
        profile: &XrefIsolatedProfileDocument,
    ) -> Result<XrefMaterializedProfile, XrefBoundaryError>;
    fn flush_file(&mut self, path: &Path) -> Result<(), XrefBoundaryError>;
    fn cleanup(&mut self, paths: &[PathBuf]) -> XrefCleanupInventory;
    fn prepare_output_guard(
        &mut self,
        source: &Path,
        destination: &Path,
        original: &Self::OriginalHostGuard,
    ) -> Result<Self::PreparedOutputGuard, XrefBoundaryError>;
    fn observe_prepared_output(
        &mut self,
        prepared: &Self::PreparedOutputGuard,
    ) -> Result<XrefFileObservation, XrefBoundaryError>;
    fn install_prepared_output(
        &mut self,
        prepared: Self::PreparedOutputGuard,
        original: &Self::OriginalHostGuard,
    ) -> Result<Self::InstalledHostGuard, XrefPreparedInstallError<Self::PreparedOutputGuard>>;
    fn observe_installed_host(
        &mut self,
        installed: &Self::InstalledHostGuard,
    ) -> Result<XrefFileObservation, XrefBoundaryError>;
    fn installed_identity_matches_contract(
        &self,
        original: &XrefFileObservation,
        prepared: &XrefFileObservation,
        installed: &XrefFileObservation,
    ) -> bool {
        let _ = original;
        installed.identity == prepared.identity
    }
    fn flush_directory(&mut self, directory: &Path) -> Result<(), XrefBoundaryError>;
}

pub(crate) trait XrefMutationOperationCallback {
    type Response;

    fn validate_locked(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError>;
    fn locked_source_inputs(&self) -> Option<&[XrefSourceInput]> {
        None
    }
    fn execute(
        &mut self,
        engine: &mut dyn XrefMutationEngineBoundary,
        context: &XrefOperationContext<'_>,
    ) -> Result<Vec<PathBuf>, XrefTransactionError>;
    fn verify(
        &mut self,
        context: &XrefVerificationContext<'_>,
    ) -> Result<Self::Response, XrefTransactionError>;
}

pub(crate) trait XrefHostFormatInspector {
    fn inspect(&mut self, path: &Path) -> Result<XrefHostFormatFacts, XrefTransactionError>;
}

#[derive(Debug, Clone)]
struct AccoreconsoleSessionPlan {
    temporary_host: PathBuf,
    staging_directory: PathBuf,
    profile_path: PathBuf,
    certified_autocad_arg: Vec<u8>,
    search_directories: Vec<PathBuf>,
    operation_lisp: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub(crate) struct AccoreconsoleXrefMutationEngine {
    identity: Option<crate::engine::AutocadEngineIdentity>,
    selected_activation: Option<Arc<SelectedActivation>>,
    session: Option<AccoreconsoleSessionPlan>,
    #[cfg(feature = "xref-certification-failpoints")]
    selected_failpoint: Option<XrefCertificationFailpoint>,
}

impl AccoreconsoleXrefMutationEngine {
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(feature = "xref-certification-failpoints")]
            selected_failpoint: std::env::var("AUTOCAD_MCP_XREF_FAILPOINT")
                .ok()
                .and_then(|value| parse_certification_failpoint(&value)),
            ..Self::default()
        }
    }

    pub(crate) fn with_selected_activation(selected: Arc<SelectedActivation>) -> Self {
        Self {
            selected_activation: Some(selected),
            #[cfg(feature = "xref-certification-failpoints")]
            selected_failpoint: std::env::var("AUTOCAD_MCP_XREF_FAILPOINT")
                .ok()
                .and_then(|value| parse_certification_failpoint(&value)),
            ..Self::default()
        }
    }
}

impl XrefMutationEngineBoundary for AccoreconsoleXrefMutationEngine {
    fn is_windows(&mut self) -> bool {
        cfg!(target_os = "windows")
    }

    fn detect_identity(
        &mut self,
    ) -> Result<crate::engine::AutocadEngineIdentity, XrefBoundaryError> {
        let identity = match &self.selected_activation {
            Some(selected) => crate::engine::AutocadEngineIdentity {
                executable: selected.engine_identity.canonical_executable.clone(),
                product: selected.target.product.as_str().to_string(),
                version: selected.target.release_year.to_string(),
            },
            None => crate::engine::detect_accoreconsole_identity()
                .map_err(|error| XrefBoundaryError::new(error.to_string()))?,
        };
        self.identity = Some(identity.clone());
        Ok(identity)
    }

    fn prove_exclusive_source_snapshot_resolution(
        &mut self,
        context: &XrefEngineLaunchContext<'_>,
    ) -> Result<(), XrefBoundaryError> {
        if !context.source_exclusion_proven {
            return Err(XrefBoundaryError::new(
                "original XREF source paths were not exclusively denied to accoreconsole",
            ));
        }
        if context.source_snapshots.iter().any(|snapshot| {
            snapshot.original_path == snapshot.snapshot_path
                || !snapshot
                    .snapshot_path
                    .starts_with(context.staging_directory)
                || !context.search_directories.iter().any(|directory| {
                    snapshot
                        .snapshot_path
                        .parent()
                        .is_some_and(|parent| parent == directory)
                })
        }) {
            return Err(XrefBoundaryError::new(
                "snapshot mapping is incomplete or escaped isolated staging",
            ));
        }
        Ok(())
    }

    fn launch(&mut self, context: &XrefEngineLaunchContext<'_>) -> Result<(), XrefBoundaryError> {
        if self.identity.is_none() {
            return Err(XrefBoundaryError::new(
                "engine identity must be detected before launch",
            ));
        }
        if self.session.is_some() {
            return Err(XrefBoundaryError::new(
                "an accoreconsole XREF session is already active",
            ));
        }
        if context
            .temporary_host
            .starts_with(context.staging_directory)
        {
            return Err(XrefBoundaryError::new(
                "sibling temporary host must remain outside isolated staging",
            ));
        }
        if context.certified_autocad_arg.is_empty() {
            return Err(XrefBoundaryError::new(
                "isolated XREF launch requires certified ARG bytes",
            ));
        }
        if self.selected_activation.as_ref().is_some_and(|selected| {
            context.certified_autocad_arg != selected.target.profile.arg_bytes()
        }) {
            return Err(XrefBoundaryError::new(
                "isolated XREF launch profile bytes do not match the selected activation",
            ));
        }
        if !context.profile_path.starts_with(context.staging_directory)
            || context
                .search_directories
                .iter()
                .any(|directory| !directory.starts_with(context.staging_directory))
            || context.source_snapshots.iter().any(|snapshot| {
                !snapshot
                    .snapshot_path
                    .starts_with(context.staging_directory)
            })
        {
            return Err(XrefBoundaryError::new(
                "profile and source snapshots must remain inside isolated staging",
            ));
        }
        self.session = Some(AccoreconsoleSessionPlan {
            temporary_host: context.temporary_host.to_path_buf(),
            staging_directory: context.staging_directory.to_path_buf(),
            profile_path: context.profile_path.to_path_buf(),
            certified_autocad_arg: context.certified_autocad_arg.to_vec(),
            search_directories: context.search_directories.to_vec(),
            operation_lisp: None,
        });
        Ok(())
    }

    fn execute_operation(&mut self, script: &Path) -> Result<(), XrefBoundaryError> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| XrefBoundaryError::new("engine session is not active"))?;
        if script.extension().and_then(|extension| extension.to_str()) != Some("lsp") {
            return Err(XrefBoundaryError::new(
                "XREF operation callback must provide an AutoLISP .lsp file",
            ));
        }
        if !script.starts_with(&session.staging_directory) {
            return Err(XrefBoundaryError::new(
                "XREF operation script must be inside isolated staging",
            ));
        }
        session.operation_lisp = Some(script.to_path_buf());
        Ok(())
    }

    fn save(&mut self, _format: &XrefHostFormatFacts) -> Result<(), XrefBoundaryError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| XrefBoundaryError::new("engine session is not active"))?;
        let operation_lisp = session
            .operation_lisp
            .as_ref()
            .ok_or_else(|| XrefBoundaryError::new("XREF operation was not supplied"))?;
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| XrefBoundaryError::new("engine identity is unavailable"))?;
        if session.profile_path.exists() {
            return Err(XrefBoundaryError::new(
                "isolated XREF profile destination was populated before guarded materialization",
            ));
        }

        let driver_path = session.staging_directory.join("xref-transaction.scr");
        let operation_path = operation_lisp.to_string_lossy().replace('\\', "/");
        let driver = format!(
            "(setvar \"SECURELOAD\" 0)\n\
             (setvar \"FILEDIA\" 0)(setvar \"CMDDIA\" 0)(setvar \"ISAVEBAK\" 0)\n\
             (load \"{operation_path}\")\n\
             (autocad-mcp-xref-operation)\n\
             _.QSAVE\n\
             QUIT\n\
             N\n"
        );
        fs::write(&driver_path, driver)
            .map_err(|error| XrefBoundaryError::new(format!("write driver script: {error}")))?;
        let selected = self.selected_activation.as_deref();
        let guarded_profile = match selected {
            Some(selected) => crate::engine::stage_unique_profile_bytes_for_launch(
                &session.certified_autocad_arg,
                &selected.target.profile.arg_sha256,
                &session.staging_directory,
                &session.profile_path,
            ),
            None => crate::engine::stage_unique_xref_profile_bytes_for_launch(
                &session.certified_autocad_arg,
                &session.staging_directory,
                &session.profile_path,
            ),
        }
        .map_err(|error| XrefBoundaryError::new(format!("guard isolated XREF profile: {error}")))?;
        let run = match selected {
            Some(selected) => {
                crate::engine::run_accoreconsole_with_guarded_profile_and_selected_activation(
                    selected,
                    &session.temporary_host,
                    &driver_path,
                    &session.staging_directory,
                    guarded_profile,
                    &session.search_directories,
                )
            }
            None => crate::engine::run_accoreconsole_with_guarded_profile_and_support_paths(
                &identity.executable,
                &session.temporary_host,
                &driver_path,
                &session.staging_directory,
                guarded_profile,
                &session.search_directories,
            ),
        };
        run.map_err(|error| XrefBoundaryError::new(error.to_string()))?;
        Ok(())
    }

    fn auxiliary_artifacts(&self) -> Vec<PathBuf> {
        let Some(session) = &self.session else {
            return Vec::new();
        };
        let mut artifacts = vec![
            session.staging_directory.join("xref-transaction.scr"),
            session.temporary_host.with_extension("bak"),
            session.temporary_host.with_extension("dwl"),
            session.temporary_host.with_extension("dwl2"),
        ];
        if let Some(operation_lisp) = &session.operation_lisp {
            artifacts.push(operation_lisp.clone());
        }
        artifacts
    }

    fn stop(&mut self) -> Result<(), XrefBoundaryError> {
        self.session = None;
        Ok(())
    }

    #[cfg(any(test, feature = "xref-certification-failpoints"))]
    fn certification_failpoint(
        &mut self,
        failpoint: XrefCertificationFailpoint,
    ) -> Result<(), XrefBoundaryError> {
        #[cfg(feature = "xref-certification-failpoints")]
        if self.selected_failpoint == Some(failpoint) {
            return Err(XrefBoundaryError::new(format!(
                "certification failpoint {failpoint:?}"
            )));
        }
        let _ = failpoint;
        Ok(())
    }
}

#[cfg(feature = "xref-certification-failpoints")]
fn parse_certification_failpoint(value: &str) -> Option<XrefCertificationFailpoint> {
    match value {
        "during_source_snapshot" => Some(XrefCertificationFailpoint::DuringSourceSnapshot),
        "before_save" => Some(XrefCertificationFailpoint::BeforeSave),
        "after_save" => Some(XrefCertificationFailpoint::AfterSave),
        "before_verification" => Some(XrefCertificationFailpoint::BeforeVerification),
        "after_verification" => Some(XrefCertificationFailpoint::AfterVerification),
        "before_cleanup" => Some(XrefCertificationFailpoint::BeforeCleanup),
        "after_cleanup" => Some(XrefCertificationFailpoint::AfterCleanup),
        "before_host_recheck" => Some(XrefCertificationFailpoint::BeforeHostRecheck),
        "after_host_recheck" => Some(XrefCertificationFailpoint::AfterHostRecheck),
        "before_replace" => Some(XrefCertificationFailpoint::BeforeReplace),
        "after_replace" => Some(XrefCertificationFailpoint::AfterReplace),
        "before_directory_flush" => Some(XrefCertificationFailpoint::BeforeDirectoryFlush),
        "after_directory_flush" => Some(XrefCertificationFailpoint::AfterDirectoryFlush),
        "before_installed_digest_check" => {
            Some(XrefCertificationFailpoint::BeforeInstalledDigestCheck)
        }
        _ => None,
    }
}

#[derive(Debug, Default)]
pub(crate) struct ProductionXrefFileSystem {
    source_snapshot_guards: BTreeMap<PathBuf, File>,
    #[cfg(target_os = "windows")]
    source_resolution_guards: Vec<ProductionSourceResolutionGuard>,
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct ProductionSourceResolutionGuard {
    original_paths: BTreeSet<PathBuf>,
    snapshot_paths: BTreeSet<PathBuf>,
    file: File,
    filesystem_identity: FilesystemIdentity,
    digest: XrefDigest,
}

#[derive(Debug)]
pub(crate) struct ProductionOriginalHostGuard {
    path: PathBuf,
    file: std::cell::RefCell<Option<File>>,
    #[cfg(target_os = "windows")]
    transaction: WindowsFileTransaction,
    #[cfg(target_os = "windows")]
    commit_continuity: WindowsCommitContinuityGuard,
}

impl ProductionOriginalHostGuard {
    fn file(&self) -> Result<std::cell::Ref<'_, File>, XrefBoundaryError> {
        std::cell::Ref::filter_map(self.file.borrow(), Option::as_ref)
            .map_err(|_| XrefBoundaryError::new("original-host guard file is no longer open"))
    }

    #[cfg(target_os = "windows")]
    fn close_transaction_file(&self) {
        self.file.borrow_mut().take();
    }

    #[cfg(target_os = "windows")]
    fn close_commit_continuity_file(&self) {
        self.commit_continuity.file.borrow_mut().take();
    }
}

impl Drop for ProductionOriginalHostGuard {
    fn drop(&mut self) {
        unlock_host_file(self);
    }
}

#[derive(Debug)]
struct ProductionGuardedOutputFile {
    file: std::cell::RefCell<Option<File>>,
}

impl ProductionGuardedOutputFile {
    fn file(&self) -> Result<std::cell::Ref<'_, File>, XrefBoundaryError> {
        std::cell::Ref::filter_map(self.file.borrow(), Option::as_ref)
            .map_err(|_| XrefBoundaryError::new("guarded output file is no longer open"))
    }

    #[cfg(target_os = "windows")]
    fn close_transaction_file(&self) {
        self.file.borrow_mut().take();
    }
}

impl Drop for ProductionGuardedOutputFile {
    fn drop(&mut self) {
        if let Some(file) = self.file.get_mut().as_ref() {
            unlock_output_file(file);
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProductionPreparedOutputGuard {
    source: PathBuf,
    destination: PathBuf,
    guarded: ProductionGuardedOutputFile,
}

#[derive(Debug)]
pub(crate) struct ProductionInstalledHostGuard {
    path: PathBuf,
    guarded: ProductionGuardedOutputFile,
}

impl XrefMutationFileSystem for ProductionXrefFileSystem {
    type OriginalHostGuard = ProductionOriginalHostGuard;
    type PreparedOutputGuard = ProductionPreparedOutputGuard;
    type InstalledHostGuard = ProductionInstalledHostGuard;

    fn observe_path(&mut self, path: &Path) -> Result<XrefFileObservation, XrefBoundaryError> {
        let mut file = File::open(path).map_err(boundary_io("open file for observation"))?;
        let identity =
            file_identity(&file).map_err(boundary_io("read file identity before hash"))?;
        let digest = XrefDigest::from_reader(&mut file).map_err(boundary_io("hash file"))?;
        let repeated_digest =
            XrefDigest::from_reader(&mut file).map_err(boundary_io("rehash file"))?;
        let handle_identity_after =
            file_identity(&file).map_err(boundary_io("read file identity after hash"))?;
        let path_identity =
            file_identity(&File::open(path).map_err(boundary_io("reopen observed file path"))?)
                .map_err(boundary_io("read observed path identity after hash"))?;
        if identity != handle_identity_after || digest != repeated_digest {
            return Err(XrefBoundaryError::new(
                "file identity or digest changed during stable observation",
            ));
        }
        Ok(XrefFileObservation {
            identity,
            path_identity,
            digest,
        })
    }

    fn acquire_original_host_guard(
        &mut self,
        path: &Path,
    ) -> Result<Self::OriginalHostGuard, XrefBoundaryError> {
        lock_host_file(path)
    }

    fn observe_original_host(
        &mut self,
        lock: &Self::OriginalHostGuard,
    ) -> Result<XrefFileObservation, XrefBoundaryError> {
        let file = lock.file()?;
        let identity = file_identity(&file).map_err(boundary_io("read locked identity"))?;
        let path_identity_before = file_identity(
            &File::open(&lock.path).map_err(boundary_io("reopen locked host path before hash"))?,
        )
        .map_err(boundary_io("read locked path identity before hash"))?;
        // Read through the exact locked handle. On Windows, LockFileEx can
        // reject access through a second handle even when it was duplicated
        // by this process.
        let mut reader = &*file;
        let digest =
            XrefDigest::from_reader(&mut reader).map_err(boundary_io("hash locked host"))?;
        let repeated_digest =
            XrefDigest::from_reader(&mut reader).map_err(boundary_io("rehash locked host"))?;
        let handle_identity_after =
            file_identity(&file).map_err(boundary_io("reread locked identity"))?;
        let path_identity = file_identity(
            &File::open(&lock.path).map_err(boundary_io("reopen locked host path after hash"))?,
        )
        .map_err(boundary_io("read locked path identity after hash"))?;
        if identity != handle_identity_after
            || path_identity_before != path_identity
            || digest != repeated_digest
        {
            return Err(XrefBoundaryError::new(
                "locked host identity or digest changed during stable observation",
            ));
        }
        Ok(XrefFileObservation {
            identity,
            path_identity,
            digest,
        })
    }

    fn validate_host_replacement_guard(
        &mut self,
        lock: &Self::OriginalHostGuard,
    ) -> Result<(), XrefBoundaryError> {
        validate_production_host_replacement_guard(lock)
    }

    fn copy_locked_host_to_sibling(
        &mut self,
        lock: &Self::OriginalHostGuard,
        format: XrefHostFormat,
    ) -> Result<PathBuf, XrefBoundaryError> {
        let parent = lock
            .path
            .parent()
            .ok_or_else(|| XrefBoundaryError::new("host path has no parent directory"))?;
        let suffix = match format {
            XrefHostFormat::Dwg => ".dwg",
            XrefHostFormat::Dxf => ".dxf",
        };
        let mut output = tempfile::Builder::new()
            .prefix(".autocad-mcp-xref-")
            .suffix(suffix)
            .tempfile_in(parent)
            .map_err(boundary_io("create sibling output"))?;
        let source = lock.file()?;
        let mut source = &*source;
        source
            .seek(SeekFrom::Start(0))
            .map_err(boundary_io("seek locked host"))?;
        output
            .as_file_mut()
            .set_len(0)
            .map_err(boundary_io("truncate sibling output"))?;
        io::copy(&mut source, output.as_file_mut())
            .map_err(boundary_io("copy locked host to sibling output"))?;
        output
            .as_file_mut()
            .sync_all()
            .map_err(boundary_io("flush sibling host copy"))?;
        let (_, path) = output
            .keep()
            .map_err(|error| XrefBoundaryError::new(format!("retain sibling output: {error}")))?;
        Ok(path)
    }

    fn create_staging_directory(&mut self) -> Result<PathBuf, XrefBoundaryError> {
        tempfile::Builder::new()
            .prefix("autocad-mcp-xref-")
            .tempdir()
            .map(tempfile::TempDir::keep)
            .map_err(boundary_io("create isolated XREF staging"))
    }

    fn capture_source(
        &mut self,
        source: &Path,
        destination: &Path,
        expected_identity: &FilesystemIdentity,
    ) -> Result<XrefSourceCaptureEvidence, XrefSourceCaptureError> {
        let source_unreadable = |context, error| {
            XrefSourceCaptureError::SourceUnreadable(XrefBoundaryError::new(format!(
                "{context}: {error}"
            )))
        };
        let source_path_access = |context, error: io::Error| {
            if error.kind() == io::ErrorKind::NotFound {
                XrefSourceCaptureError::SourceRace(XrefBoundaryError::new(format!(
                    "{context}: source disappeared after locked dependency traversal: {error}"
                )))
            } else {
                source_unreadable(context, error)
            }
        };
        let staging = |context, error| {
            XrefSourceCaptureError::Staging(XrefBoundaryError::new(format!("{context}: {error}")))
        };
        let mut source_file =
            File::open(source).map_err(|error| source_path_access("open XREF source", error))?;
        let handle_identity_before = source_file_identity(&source_file, source)
            .map_err(|error| source_unreadable("read source handle identity", error))?;
        let path_file_before = File::open(source)
            .map_err(|error| source_path_access("reopen XREF source path", error))?;
        let path_identity_before = source_file_identity(&path_file_before, source)
            .map_err(|error| source_unreadable("read source path identity", error))?;
        if &handle_identity_before != expected_identity
            || &path_identity_before != expected_identity
        {
            return Err(XrefSourceCaptureError::SourceRace(XrefBoundaryError::new(
                "XREF source identity differs from locked graph traversal",
            )));
        }
        let digest_before = XrefDigest::from_reader(&mut source_file)
            .map_err(|error| source_unreadable("hash XREF source before capture", error))?;
        coordinate_xref_race_driver(XrefRaceCoordinationPoint::SourceAfterInitialDigest)
            .map_err(XrefSourceCaptureError::SourceUnreadable)?;

        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| staging("create source snapshot directory", error))?;
        }
        source_file
            .seek(SeekFrom::Start(0))
            .map_err(|error| source_unreadable("seek XREF source for capture", error))?;
        let mut snapshot = create_source_snapshot_file(destination)
            .map_err(|error| staging("create immutable source snapshot", error))?;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = source_file
                .read(&mut buffer)
                .map_err(|error| source_unreadable("read XREF source during capture", error))?;
            if read == 0 {
                break;
            }
            snapshot
                .write_all(&buffer[..read])
                .map_err(|error| staging("write immutable source snapshot", error))?;
        }
        snapshot
            .sync_all()
            .map_err(|error| staging("flush immutable source snapshot", error))?;
        let snapshot_digest = XrefDigest::from_reader(&mut snapshot)
            .map_err(|error| staging("hash immutable source snapshot", error))?;
        let digest_after = XrefDigest::from_reader(&mut source_file)
            .map_err(|error| source_unreadable("hash XREF source after capture", error))?;
        let handle_identity_after = source_file_identity(&source_file, source)
            .map_err(|error| source_unreadable("reread source handle identity", error))?;
        let path_file_after = File::open(source)
            .map_err(|error| source_path_access("reopen captured source path", error))?;
        let path_identity_after = source_file_identity(&path_file_after, source)
            .map_err(|error| source_unreadable("reread source path identity", error))?;

        let mut permissions = snapshot
            .metadata()
            .map_err(|error| staging("read source snapshot permissions", error))?
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(destination, permissions)
            .map_err(|error| staging("make source snapshot read-only", error))?;

        let snapshot_identity = file_identity(&snapshot)
            .map_err(|error| staging("read immutable source snapshot identity", error))?;
        self.source_snapshot_guards
            .insert(destination.to_path_buf(), snapshot);

        let evidence = XrefSourceCaptureEvidence {
            path_identity_before,
            handle_identity_before,
            digest_before,
            snapshot_digest,
            snapshot_identity,
            handle_identity_after,
            path_identity_after,
            digest_after,
        };

        #[cfg(target_os = "windows")]
        if evidence.is_stable_for(expected_identity) {
            drop(path_file_before);
            drop(path_file_after);
            drop(source_file);
            install_source_resolution_guard(
                &mut self.source_resolution_guards,
                source,
                destination,
                expected_identity,
                evidence.snapshot_digest,
            )
            .map_err(|error| {
                XrefSourceCaptureError::SourceUnreadable(XrefBoundaryError::new(format!(
                    "exclude original XREF source from engine resolution: {error}"
                )))
            })?;
        }

        Ok(evidence)
    }

    fn observe_source_snapshot(
        &mut self,
        path: &Path,
    ) -> Result<XrefFileObservation, XrefBoundaryError> {
        let guard = self.source_snapshot_guards.get(path).ok_or_else(|| {
            XrefBoundaryError::new(format!(
                "immutable source snapshot guard is missing for {}",
                path.display()
            ))
        })?;
        observe_guarded_file(path, guard)
    }

    fn prove_exclusive_source_snapshot_resolution(
        &mut self,
        snapshots: &[XrefSourceSnapshot],
    ) -> Result<(), XrefBoundaryError> {
        #[cfg(not(target_os = "windows"))]
        {
            let _ = snapshots;
            Err(XrefBoundaryError::new(
                "exclusive source-path read denial requires Windows file sharing",
            ))
        }
        #[cfg(target_os = "windows")]
        {
            for snapshot in snapshots {
                let guard = self
                    .source_resolution_guards
                    .iter()
                    .find(|guard| guard.filesystem_identity == snapshot.filesystem_identity)
                    .ok_or_else(|| {
                        XrefBoundaryError::new(format!(
                            "original source exclusion guard is missing for '{}'",
                            snapshot.source_id
                        ))
                    })?;
                if !guard.original_paths.contains(&snapshot.original_path)
                    || !guard.snapshot_paths.contains(&snapshot.snapshot_path)
                    || guard.digest.hex() != snapshot.digest_sha256
                {
                    return Err(XrefBoundaryError::new(format!(
                        "original source exclusion proof disagrees with snapshot '{}'",
                        snapshot.source_id
                    )));
                }
                let identity = source_file_identity(&guard.file, &snapshot.original_path)
                    .map_err(boundary_io("reread source exclusion guard identity"))?;
                let mut file = &guard.file;
                let digest = XrefDigest::from_reader(&mut file)
                    .map_err(boundary_io("rehash source exclusion guard"))?;
                if identity != snapshot.filesystem_identity || digest != guard.digest {
                    return Err(XrefBoundaryError::new(format!(
                        "original source exclusion guard changed for '{}'",
                        snapshot.source_id
                    )));
                }
            }
            Ok(())
        }
    }

    fn materialize_profile(
        &mut self,
        staging_directory: &Path,
        profile: &XrefIsolatedProfileDocument,
    ) -> Result<XrefMaterializedProfile, XrefBoundaryError> {
        if profile.certified_autocad_arg.is_empty() {
            return Err(XrefBoundaryError::new(
                "isolated launch requires a certified exported AutoCAD ARG profile",
            ));
        }

        let manifest_path = staging_directory.join("xref-isolated-profile.json");
        let manifest_bytes = serde_json::to_vec_pretty(profile)
            .map_err(|error| XrefBoundaryError::new(format!("serialize profile: {error}")))?;
        let mut manifest = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&manifest_path)
            .map_err(boundary_io("create isolated profile manifest"))?;
        manifest
            .write_all(&manifest_bytes)
            .map_err(boundary_io("write isolated profile manifest"))?;
        manifest
            .sync_all()
            .map_err(boundary_io("flush isolated profile manifest"))?;

        // Reserve the cleanup/evidence path, but defer its single write to the
        // engine's create-new guarded materialization immediately before the
        // child launch. Writing a disposable ARG here and copying it again in
        // the engine would introduce an unguarded intermediate identity.
        let arg_path = staging_directory.join("xref-isolated-profile.arg");
        if arg_path.exists() {
            return Err(XrefBoundaryError::new(
                "isolated AutoCAD ARG destination already exists",
            ));
        }
        Ok(XrefMaterializedProfile {
            launch_path: arg_path.clone(),
            artifacts: vec![manifest_path, arg_path],
        })
    }

    fn flush_file(&mut self, path: &Path) -> Result<(), XrefBoundaryError> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .and_then(|file| file.sync_all())
            .map_err(boundary_io("flush transaction output"))
    }

    fn cleanup(&mut self, paths: &[PathBuf]) -> XrefCleanupInventory {
        self.source_snapshot_guards.retain(|guarded_path, _| {
            !paths
                .iter()
                .any(|path| guarded_path == path || guarded_path.starts_with(path))
        });
        #[cfg(target_os = "windows")]
        self.source_resolution_guards.retain(|guard| {
            !guard.snapshot_paths.iter().any(|snapshot_path| {
                paths
                    .iter()
                    .any(|path| snapshot_path == path || snapshot_path.starts_with(path))
            })
        });
        cleanup_paths(paths)
    }

    fn prepare_output_guard(
        &mut self,
        source: &Path,
        destination: &Path,
        original: &Self::OriginalHostGuard,
    ) -> Result<Self::PreparedOutputGuard, XrefBoundaryError> {
        validate_production_host_replacement_guard(original)?;
        if destination != original.path {
            return Err(XrefBoundaryError::new(
                "prepared output destination differs from the guarded original host",
            ));
        }
        if source == destination || source.parent() != destination.parent() {
            return Err(XrefBoundaryError::new(
                "prepared output must be a distinct sibling of the guarded original host",
            ));
        }
        #[cfg(target_os = "windows")]
        let guarded = lock_output_file(source, &original.transaction)?;
        #[cfg(not(target_os = "windows"))]
        let guarded = lock_output_file(source)?;
        Ok(ProductionPreparedOutputGuard {
            source: source.to_path_buf(),
            destination: destination.to_path_buf(),
            guarded,
        })
    }

    fn observe_prepared_output(
        &mut self,
        prepared: &Self::PreparedOutputGuard,
    ) -> Result<XrefFileObservation, XrefBoundaryError> {
        let file = prepared.guarded.file()?;
        observe_guarded_file(&prepared.source, &file)
    }

    fn install_prepared_output(
        &mut self,
        prepared: Self::PreparedOutputGuard,
        original: &Self::OriginalHostGuard,
    ) -> Result<Self::InstalledHostGuard, XrefPreparedInstallError<Self::PreparedOutputGuard>> {
        if let Err(error) = validate_production_host_replacement_guard(original) {
            return Err(XrefPreparedInstallError::definitely_not_installed(
                error, prepared,
            ));
        }
        if prepared.destination != original.path {
            return Err(XrefPreparedInstallError::definitely_not_installed(
                XrefBoundaryError::new(
                    "prepared output no longer targets the guarded original host",
                ),
                prepared,
            ));
        }
        #[cfg(target_os = "windows")]
        let install = install_prepared_output_transactionally(&prepared, original);
        #[cfg(not(target_os = "windows"))]
        let install = atomic_replace_file(&prepared.source, &prepared.destination);
        #[cfg(target_os = "windows")]
        let guarded = match install {
            Ok(guarded) => guarded,
            Err(error) => {
                return Err(XrefPreparedInstallError::installation_may_have_occurred(
                    error, prepared,
                ));
            }
        };
        #[cfg(not(target_os = "windows"))]
        let guarded = {
            if let Err(error) = install {
                return Err(XrefPreparedInstallError::installation_may_have_occurred(
                    error, prepared,
                ));
            }
            prepared.guarded
        };
        Ok(ProductionInstalledHostGuard {
            path: prepared.destination,
            guarded,
        })
    }

    fn observe_installed_host(
        &mut self,
        installed: &Self::InstalledHostGuard,
    ) -> Result<XrefFileObservation, XrefBoundaryError> {
        let file = installed.guarded.file()?;
        observe_guarded_file(&installed.path, &file)
    }

    fn installed_identity_matches_contract(
        &self,
        original: &XrefFileObservation,
        prepared: &XrefFileObservation,
        installed: &XrefFileObservation,
    ) -> bool {
        #[cfg(target_os = "windows")]
        {
            let _ = prepared;
            installed.identity == original.identity
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = original;
            installed.identity == prepared.identity
        }
    }

    fn flush_directory(&mut self, directory: &Path) -> Result<(), XrefBoundaryError> {
        flush_directory_metadata(directory)
    }
}

/// Product-owned evidence for installing an already verified drawing
/// candidate through the same Windows transaction primitive used by guarded
/// XREF mutation. Candidate construction runs while the exact source handle is
/// exclusively locked; this adapter has no AutoCAD or XREF semantics.
#[cfg(feature = "preview")]
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardedCandidateInstallReceipt {
    pub source_sha256: String,
    pub installed_sha256: String,
    pub exclusive_source_lock_verified: bool,
    pub source_identity_revalidated: bool,
    pub sibling_staging_verified: bool,
    pub transactional_atomic_install_verified: bool,
    pub original_file_identity_preserved: bool,
    pub directory_durability_verified: bool,
    pub installed_digest_verified: bool,
}

#[cfg(feature = "preview")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum GuardedCandidateInstallDisposition {
    DefinitelyNotInstalled,
    InstallationMayHaveOccurred,
}

#[cfg(feature = "preview")]
#[derive(Debug)]
pub(crate) struct GuardedCandidateInstallError {
    code: &'static str,
    detail: String,
    disposition: GuardedCandidateInstallDisposition,
}

#[cfg(feature = "preview")]
impl GuardedCandidateInstallError {
    fn new(
        code: &'static str,
        detail: impl Into<String>,
        disposition: GuardedCandidateInstallDisposition,
    ) -> Self {
        Self {
            code,
            detail: detail.into(),
            disposition,
        }
    }

    pub(crate) fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) fn disposition(&self) -> GuardedCandidateInstallDisposition {
        self.disposition
    }

    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }
}

#[cfg(feature = "preview")]
impl fmt::Display for GuardedCandidateInstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "code={} {}", self.code, self.detail)
    }
}

#[cfg(feature = "preview")]
impl Error for GuardedCandidateInstallError {}

/// Build and install one candidate from the bytes read through an exclusively
/// locked original-host handle.
///
/// The production implementation is deliberately Windows-only. It keeps the
/// original file identity, stages a distinct same-directory sibling, copies
/// the candidate into the original file through TxF, flushes the containing
/// directory, and verifies the installed digest while a deny-write/delete
/// guard remains held.
#[cfg(feature = "preview")]
pub(crate) fn guarded_install_candidate<Response>(
    path: &Path,
    build: impl FnOnce(&[u8]) -> Result<(Vec<u8>, Response), String>,
) -> Result<(Response, GuardedCandidateInstallReceipt), GuardedCandidateInstallError> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (path, build);
        Err(GuardedCandidateInstallError::new(
            "preview_writer_unsupported_platform",
            "guarded Preview DWG installation requires native Windows/NTFS transaction support",
            GuardedCandidateInstallDisposition::DefinitelyNotInstalled,
        ))
    }

    #[cfg(target_os = "windows")]
    {
        let canonical = validate_guarded_candidate_path(path)?;
        let parent = canonical.parent().ok_or_else(|| {
            GuardedCandidateInstallError::new(
                "preview_writer_invalid_path",
                "drawing path has no containing directory",
                GuardedCandidateInstallDisposition::DefinitelyNotInstalled,
            )
        })?;
        let mut file_system = ProductionXrefFileSystem::default();
        let initial = file_system.observe_path(&canonical).map_err(|error| {
            guarded_candidate_error(
                "preview_writer_source_observation_failed",
                format!("observe source before lock: {error}"),
            )
        })?;
        if !initial.is_stable() {
            return Err(guarded_candidate_error(
                "preview_writer_source_identity_unstable",
                "source path and opened handle do not identify the same file",
            ));
        }

        let original = file_system
            .acquire_original_host_guard(&canonical)
            .map_err(|error| {
                guarded_candidate_error(
                    "preview_writer_drawing_locked",
                    format!("acquire exclusive source lock: {error}"),
                )
            })?;
        file_system
            .validate_host_replacement_guard(&original)
            .map_err(|error| {
                guarded_candidate_error(
                    "preview_writer_lock_not_exclusive",
                    format!("validate exclusive replacement guard: {error}"),
                )
            })?;
        let locked = file_system
            .observe_original_host(&original)
            .map_err(|error| {
                guarded_candidate_error(
                    "preview_writer_locked_source_unreadable",
                    format!("observe locked source: {error}"),
                )
            })?;
        if !locked.is_stable() || !same_observation(&initial, &locked) {
            return Err(guarded_candidate_error(
                "preview_writer_concurrent_source_change",
                "source identity or digest changed while the exclusive lock was acquired",
            ));
        }
        let source_bytes = read_locked_original_bytes(&original).map_err(|error| {
            guarded_candidate_error(
                "preview_writer_locked_source_unreadable",
                format!("read locked source bytes: {error}"),
            )
        })?;
        let source_sha256 = format!("{:x}", Sha256::digest(&source_bytes));
        if source_sha256 != locked.digest.hex() {
            return Err(guarded_candidate_error(
                "preview_writer_locked_source_digest_mismatch",
                "locked source bytes differ from the stable locked observation",
            ));
        }

        let (candidate_bytes, response) = build(&source_bytes).map_err(|error| {
            guarded_candidate_error(
                "preview_writer_candidate_rejected",
                format!("candidate generation failed: {error}"),
            )
        })?;
        if candidate_bytes.is_empty() {
            return Err(guarded_candidate_error(
                "preview_writer_candidate_empty",
                "candidate generation returned no drawing bytes",
            ));
        }
        let candidate_sha256 = format!("{:x}", Sha256::digest(&candidate_bytes));

        let source_before_stage =
            file_system
                .observe_original_host(&original)
                .map_err(|error| {
                    guarded_candidate_error(
                        "preview_writer_source_recheck_failed",
                        format!("recheck locked source before staging: {error}"),
                    )
                })?;
        if !same_observation(&locked, &source_before_stage) {
            return Err(guarded_candidate_error(
                "preview_writer_concurrent_source_change",
                "locked source identity or digest changed during candidate generation",
            ));
        }

        let mut sibling = tempfile::Builder::new()
            .prefix(".autocad-mcp-preview-title-")
            .suffix(".dwg")
            .tempfile_in(parent)
            .map_err(|error| {
                guarded_candidate_error(
                    "preview_writer_staging_failed",
                    format!("create sibling candidate: {error}"),
                )
            })?;
        sibling
            .as_file_mut()
            .write_all(&candidate_bytes)
            .map_err(|error| {
                guarded_candidate_error(
                    "preview_writer_staging_failed",
                    format!("write sibling candidate: {error}"),
                )
            })?;
        sibling.as_file_mut().sync_all().map_err(|error| {
            guarded_candidate_error(
                "preview_writer_staging_failed",
                format!("flush sibling candidate: {error}"),
            )
        })?;
        let (_, sibling_path) = sibling.keep().map_err(|error| {
            guarded_candidate_error(
                "preview_writer_staging_failed",
                format!("retain sibling candidate: {error}"),
            )
        })?;

        let prepared = match file_system.prepare_output_guard(&sibling_path, &canonical, &original)
        {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = fs::remove_file(&sibling_path);
                return Err(guarded_candidate_error(
                    "preview_writer_staging_guard_failed",
                    format!("guard sibling candidate: {error}"),
                ));
            }
        };
        let prepared_observation = match file_system.observe_prepared_output(&prepared) {
            Ok(observation) => observation,
            Err(error) => {
                drop(prepared);
                let _ = fs::remove_file(&sibling_path);
                return Err(guarded_candidate_error(
                    "preview_writer_staging_verification_failed",
                    format!("observe guarded sibling candidate: {error}"),
                ));
            }
        };
        if !prepared_observation.is_stable()
            || prepared_observation.digest.hex() != candidate_sha256
        {
            drop(prepared);
            let _ = fs::remove_file(&sibling_path);
            return Err(guarded_candidate_error(
                "preview_writer_staging_verification_failed",
                "guarded sibling identity or digest differs from the verified candidate",
            ));
        }

        let source_before_install = match file_system.observe_original_host(&original) {
            Ok(observation) => observation,
            Err(error) => {
                drop(prepared);
                let _ = fs::remove_file(&sibling_path);
                return Err(guarded_candidate_error(
                    "preview_writer_source_recheck_failed",
                    format!("recheck locked source before install: {error}"),
                ));
            }
        };
        if !same_observation(&locked, &source_before_install) {
            drop(prepared);
            let _ = fs::remove_file(&sibling_path);
            return Err(guarded_candidate_error(
                "preview_writer_concurrent_source_change",
                "locked source identity or digest changed before candidate installation",
            ));
        }

        let installed_guard = match file_system.install_prepared_output(prepared, &original) {
            Ok(installed) => installed,
            Err(error) => {
                let disposition = match error.disposition {
                    XrefPreparedInstallDisposition::DefinitelyNotInstalled => {
                        let _ = fs::remove_file(&sibling_path);
                        GuardedCandidateInstallDisposition::DefinitelyNotInstalled
                    }
                    XrefPreparedInstallDisposition::InstallationMayHaveOccurred => {
                        GuardedCandidateInstallDisposition::InstallationMayHaveOccurred
                    }
                };
                drop(error.prepared_output_guard);
                return Err(GuardedCandidateInstallError::new(
                    "preview_writer_install_outcome_unknown",
                    format!(
                        "transactional candidate installation failed: {}",
                        error.error
                    ),
                    disposition,
                ));
            }
        };

        file_system.flush_directory(parent).map_err(|error| {
            GuardedCandidateInstallError::new(
                "preview_writer_install_outcome_unknown",
                format!("candidate committed but directory durability failed: {error}"),
                GuardedCandidateInstallDisposition::InstallationMayHaveOccurred,
            )
        })?;
        let installed = file_system
            .observe_installed_host(&installed_guard)
            .map_err(|error| {
                GuardedCandidateInstallError::new(
                    "preview_writer_install_outcome_unknown",
                    format!("candidate committed but installed observation failed: {error}"),
                    GuardedCandidateInstallDisposition::InstallationMayHaveOccurred,
                )
            })?;
        if !installed.is_stable()
            || !file_system.installed_identity_matches_contract(
                &locked,
                &prepared_observation,
                &installed,
            )
            || installed.digest.hex() != candidate_sha256
        {
            return Err(GuardedCandidateInstallError::new(
                "preview_writer_install_outcome_unknown",
                "installed identity transition or digest does not match the guarded transaction",
                GuardedCandidateInstallDisposition::InstallationMayHaveOccurred,
            ));
        }

        Ok((
            response,
            GuardedCandidateInstallReceipt {
                source_sha256,
                installed_sha256: candidate_sha256,
                exclusive_source_lock_verified: true,
                source_identity_revalidated: true,
                sibling_staging_verified: true,
                transactional_atomic_install_verified: true,
                original_file_identity_preserved: true,
                directory_durability_verified: true,
                installed_digest_verified: true,
            },
        ))
    }
}

#[cfg(all(feature = "preview", target_os = "windows"))]
fn validate_guarded_candidate_path(path: &Path) -> Result<PathBuf, GuardedCandidateInstallError> {
    use std::os::windows::fs::MetadataExt;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| {
                guarded_candidate_error(
                    "preview_writer_invalid_path",
                    format!("resolve current directory: {error}"),
                )
            })?
            .join(path)
    };
    for component in absolute.ancestors() {
        if component.parent().is_none() {
            break;
        }
        let metadata = fs::symlink_metadata(component).map_err(|error| {
            guarded_candidate_error(
                "preview_writer_invalid_path",
                format!("inspect drawing namespace component: {error}"),
            )
        })?;
        if metadata.file_type().is_symlink() || metadata.file_attributes() & 0x0000_0400 != 0 {
            return Err(guarded_candidate_error(
                "preview_writer_invalid_path",
                "drawing path must not traverse a reparse-point namespace",
            ));
        }
    }
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| {
        guarded_candidate_error(
            "preview_writer_invalid_path",
            format!("inspect drawing path: {error}"),
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & 0x0000_0400 != 0
    {
        return Err(guarded_candidate_error(
            "preview_writer_invalid_path",
            "drawing must be a regular non-reparse file",
        ));
    }
    if !absolute
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dwg"))
    {
        return Err(guarded_candidate_error(
            "preview_writer_invalid_path",
            "guarded Preview candidate installation accepts only .dwg paths",
        ));
    }
    fs::canonicalize(&absolute).map_err(|error| {
        guarded_candidate_error(
            "preview_writer_invalid_path",
            format!("canonicalize drawing path: {error}"),
        )
    })
}

#[cfg(all(feature = "preview", target_os = "windows"))]
fn read_locked_original_bytes(lock: &ProductionOriginalHostGuard) -> io::Result<Vec<u8>> {
    let file = lock
        .file()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut reader = &*file;
    reader.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    reader.seek(SeekFrom::Start(0))?;
    Ok(bytes)
}

#[cfg(all(feature = "preview", target_os = "windows"))]
fn guarded_candidate_error(
    code: &'static str,
    detail: impl Into<String>,
) -> GuardedCandidateInstallError {
    GuardedCandidateInstallError::new(
        code,
        detail,
        GuardedCandidateInstallDisposition::DefinitelyNotInstalled,
    )
}

fn boundary_io(context: &'static str) -> impl FnOnce(io::Error) -> XrefBoundaryError {
    move |error| XrefBoundaryError::new(format!("{context}: {error}"))
}

#[cfg(target_os = "windows")]
fn create_source_snapshot_file(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .share_mode(windows_primitives::FILE_SHARE_READ)
        .open(path)
}

#[cfg(not(target_os = "windows"))]
fn create_source_snapshot_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
}

#[cfg(target_os = "windows")]
fn install_source_resolution_guard(
    guards: &mut Vec<ProductionSourceResolutionGuard>,
    source: &Path,
    snapshot: &Path,
    expected_identity: &FilesystemIdentity,
    expected_digest: XrefDigest,
) -> Result<(), XrefBoundaryError> {
    use std::os::windows::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(source)
        .map_err(boundary_io(
            "open original XREF source with deny-read guard",
        ))?;
    let identity = source_file_identity(&file, source)
        .map_err(boundary_io("read deny-read source identity"))?;
    let digest = XrefDigest::from_reader(&mut file)
        .map_err(boundary_io("hash deny-read original source"))?;
    if &identity != expected_identity || digest != expected_digest {
        return Err(XrefBoundaryError::new(
            "original XREF source changed before deny-read guard acquisition",
        ));
    }
    guards.push(ProductionSourceResolutionGuard {
        original_paths: BTreeSet::from([source.to_path_buf()]),
        snapshot_paths: BTreeSet::from([snapshot.to_path_buf()]),
        file,
        filesystem_identity: identity,
        digest,
    });
    Ok(())
}

fn observe_guarded_file(
    path: &Path,
    guard: &File,
) -> Result<XrefFileObservation, XrefBoundaryError> {
    let identity = file_identity(guard).map_err(boundary_io("read guarded file identity"))?;
    // Preserve the byte-range lock's exact handle identity while reading.
    let mut file = guard;
    let digest = XrefDigest::from_reader(&mut file).map_err(boundary_io("hash guarded file"))?;
    let repeated_digest =
        XrefDigest::from_reader(&mut file).map_err(boundary_io("rehash guarded file"))?;
    let handle_identity_after =
        file_identity(guard).map_err(boundary_io("reread guarded file identity"))?;
    let path_identity = guarded_path_identity(path)
        .map_err(boundary_io("read guarded path identity through namespace"))?;
    if identity != handle_identity_after || digest != repeated_digest {
        return Err(XrefBoundaryError::new(
            "guarded file identity or digest changed during observation",
        ));
    }
    Ok(XrefFileObservation {
        identity,
        path_identity,
        digest,
    })
}

#[cfg(target_os = "windows")]
fn guarded_path_identity(path: &Path) -> io::Result<XrefFileIdentity> {
    use std::os::windows::fs::OpenOptionsExt;

    // Request no data access: the retained prepared-output handle deliberately
    // grants no sharing, so a second read handle would violate the guard's
    // contract. A zero-access handle can still bind the current namespace
    // entry independently and expose its stable file identity.
    let path_handle = OpenOptions::new()
        .access_mode(0)
        .share_mode(
            windows_primitives::FILE_SHARE_READ
                | windows_primitives::FILE_SHARE_WRITE
                | windows_primitives::FILE_SHARE_DELETE,
        )
        .open(path)?;
    file_identity(&path_handle)
}

#[cfg(not(target_os = "windows"))]
fn guarded_path_identity(path: &Path) -> io::Result<XrefFileIdentity> {
    file_identity(&File::open(path)?)
}

fn sort_deduplicate_paths(paths: &mut Vec<PathBuf>) {
    paths.sort_by(|left, right| left.as_os_str().cmp(right.as_os_str()));
    paths.dedup();
}

#[cfg_attr(target_os = "windows", allow(clippy::permissions_set_readonly_false))]
fn cleanup_paths(paths: &[PathBuf]) -> XrefCleanupInventory {
    let mut ordered = paths.to_vec();
    sort_deduplicate_paths(&mut ordered);
    ordered.sort_by(|left, right| {
        right
            .components()
            .count()
            .cmp(&left.components().count())
            .then_with(|| left.as_os_str().cmp(right.as_os_str()))
    });

    let mut inventory = XrefCleanupInventory::default();
    for path in ordered {
        inventory.attempted.push(path.clone());
        let result = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(&path),
            Ok(_) => {
                #[cfg(target_os = "windows")]
                if let Ok(metadata) = fs::metadata(&path) {
                    // Windows models this as a single read-only attribute;
                    // clearing it does not broaden POSIX write permissions.
                    let mut permissions = metadata.permissions();
                    permissions.set_readonly(false);
                    let _ = fs::set_permissions(&path, permissions);
                }
                fs::remove_file(&path)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
        match result {
            Ok(()) => inventory.removed.push(path),
            Err(_) => inventory.remaining.push(path),
        }
    }
    sort_deduplicate_paths(&mut inventory.attempted);
    sort_deduplicate_paths(&mut inventory.removed);
    sort_deduplicate_paths(&mut inventory.remaining);
    inventory
}

pub(crate) fn observe_xref_source_identity(
    path: &Path,
) -> Result<FilesystemIdentity, XrefSourceIdentityObservationError> {
    let unreadable = |context: &str, error: io::Error| {
        XrefSourceIdentityObservationError::Unreadable(XrefBoundaryError::new(format!(
            "{context}: {error}"
        )))
    };
    let file =
        File::open(path).map_err(|error| unreadable("open XREF source identity path", error))?;
    let handle_identity = source_file_identity(&file, path)
        .map_err(|error| unreadable("read XREF source handle identity", error))?;
    let path_file =
        File::open(path).map_err(|error| unreadable("reopen XREF source identity path", error))?;
    let path_identity = source_file_identity(&path_file, path)
        .map_err(|error| unreadable("read XREF source path identity", error))?;
    if handle_identity != path_identity {
        return Err(XrefSourceIdentityObservationError::Changed(
            XrefBoundaryError::new("XREF source path identity changed during observation"),
        ));
    }
    Ok(handle_identity)
}

#[cfg(unix)]
fn source_file_identity(file: &File, _path: &Path) -> io::Result<FilesystemIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    Ok(FilesystemIdentity::posix(metadata.dev(), metadata.ino()))
}

#[cfg(target_os = "windows")]
fn source_file_identity(file: &File, _path: &Path) -> io::Result<FilesystemIdentity> {
    use std::os::windows::io::AsRawHandle;

    let mut information = windows_primitives::ByHandleFileInformation::default();
    let result = unsafe {
        windows_primitives::get_file_information_by_handle(
            file.as_raw_handle().cast(),
            &mut information,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    let file_index =
        (u64::from(information.file_index_high) << 32) | u64::from(information.file_index_low);
    Ok(FilesystemIdentity::windows(
        u64::from(information.volume_serial_number),
        u128::from(file_index),
    ))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn source_file_identity(_file: &File, path: &Path) -> io::Result<FilesystemIdentity> {
    let canonical = fs::canonicalize(path)?;
    FilesystemIdentity::opaque(format!("canonical:{}", canonical.display()).into_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(unix)]
fn file_identity(file: &File) -> io::Result<XrefFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    Ok(XrefFileIdentity(format!(
        "unix:{}:{}",
        metadata.dev(),
        metadata.ino()
    )))
}

#[cfg(target_os = "windows")]
fn file_identity(file: &File) -> io::Result<XrefFileIdentity> {
    use std::os::windows::io::AsRawHandle;

    let mut information = windows_primitives::ByHandleFileInformation::default();
    let result = unsafe {
        windows_primitives::get_file_information_by_handle(
            file.as_raw_handle().cast(),
            &mut information,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    let index =
        (u64::from(information.file_index_high) << 32) | u64::from(information.file_index_low);
    Ok(XrefFileIdentity(format!(
        "windows:{}:{index}",
        information.volume_serial_number
    )))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn file_identity(file: &File) -> io::Result<XrefFileIdentity> {
    let metadata = file.metadata()?;
    let modified = metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    Ok(XrefFileIdentity(format!(
        "portable:{}:{modified}",
        metadata.len()
    )))
}

#[cfg(unix)]
fn lock_host_file(path: &Path) -> Result<ProductionOriginalHostGuard, XrefBoundaryError> {
    use std::os::fd::AsRawFd;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(boundary_io("open host for exclusive lock"))?;
    let result = unsafe { unix_flock(file.as_raw_fd(), UNIX_LOCK_EX | UNIX_LOCK_NB) };
    if result != 0 {
        return Err(XrefBoundaryError::new(format!(
            "exclusive host lock: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(ProductionOriginalHostGuard {
        path: path.to_path_buf(),
        file: std::cell::RefCell::new(Some(file)),
    })
}

#[cfg(unix)]
fn unlock_host_file(lock: &mut ProductionOriginalHostGuard) {
    use std::os::fd::AsRawFd;

    if let Some(file) = lock.file.get_mut().as_ref() {
        let _ = unsafe { unix_flock(file.as_raw_fd(), UNIX_LOCK_UN) };
    }
}

#[cfg(unix)]
const UNIX_LOCK_EX: i32 = 2;
#[cfg(unix)]
const UNIX_LOCK_NB: i32 = 4;
#[cfg(unix)]
const UNIX_LOCK_UN: i32 = 8;

#[cfg(unix)]
#[link(name = "c")]
unsafe extern "C" {
    fn flock(file_descriptor: i32, operation: i32) -> i32;
}

#[cfg(unix)]
unsafe fn unix_flock(file_descriptor: i32, operation: i32) -> i32 {
    unsafe { flock(file_descriptor, operation) }
}

#[cfg(unix)]
fn lock_output_file(path: &Path) -> Result<ProductionGuardedOutputFile, XrefBoundaryError> {
    use std::os::fd::AsRawFd;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(boundary_io("open prepared transaction output"))?;
    let result = unsafe { unix_flock(file.as_raw_fd(), UNIX_LOCK_EX | UNIX_LOCK_NB) };
    if result != 0 {
        return Err(XrefBoundaryError::new(format!(
            "exclusive prepared-output guard: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(ProductionGuardedOutputFile {
        file: std::cell::RefCell::new(Some(file)),
    })
}

#[cfg(target_os = "windows")]
fn lock_output_file(
    path: &Path,
    transaction: &WindowsFileTransaction,
) -> Result<ProductionGuardedOutputFile, XrefBoundaryError> {
    let file = transaction.open_writer(
        path,
        true,
        WINDOWS_PREPARED_LOCK_SHARE_MODE,
        "open prepared output in host transaction",
    )?;
    Ok(ProductionGuardedOutputFile {
        file: std::cell::RefCell::new(Some(file)),
    })
}

#[cfg(not(any(unix, target_os = "windows")))]
fn lock_output_file(_path: &Path) -> Result<ProductionGuardedOutputFile, XrefBoundaryError> {
    Err(XrefBoundaryError::new(
        "prepared-output guarding is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn unlock_output_file(file: &File) {
    use std::os::fd::AsRawFd;

    let _ = unsafe { unix_flock(file.as_raw_fd(), UNIX_LOCK_UN) };
}

#[cfg(not(unix))]
fn unlock_output_file(_file: &File) {}

#[cfg(any(test, target_os = "windows"))]
const WINDOWS_HOST_LOCK_SHARE_MODE: u32 = 0x0000_0001;
#[cfg(any(test, target_os = "windows"))]
const WINDOWS_PREPARED_LOCK_SHARE_MODE: u32 = 0;
#[cfg(target_os = "windows")]
const WINDOWS_COMMIT_CONTINUITY_SHARE_MODE: u32 = 0x0000_0001 | 0x0000_0002;

#[cfg(any(test, target_os = "windows"))]
fn windows_host_lock_blocks_competing_write(share_mode: u32) -> bool {
    share_mode & 0x0000_0002 == 0
}

#[cfg(any(test, target_os = "windows"))]
fn windows_host_lock_blocks_competing_delete(share_mode: u32) -> bool {
    share_mode & 0x0000_0004 == 0
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum WindowsFileTransactionState {
    Active,
    Committed,
    RolledBack,
    OutcomeUnknown,
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct WindowsFileTransaction {
    handle: std::os::windows::io::OwnedHandle,
    state: std::cell::Cell<WindowsFileTransactionState>,
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct WindowsCommitContinuityGuard {
    // Keep the reader handle before the transaction so it is closed first.
    file: std::cell::RefCell<Option<File>>,
    transaction: WindowsFileTransaction,
}

#[cfg(target_os = "windows")]
impl WindowsCommitContinuityGuard {
    fn ensure_active(&self) -> Result<(), XrefBoundaryError> {
        self.transaction.ensure_active()?;
        if self.file.borrow().is_some() {
            Ok(())
        } else {
            Err(XrefBoundaryError::new(
                "Windows commit-continuity reader is no longer open",
            ))
        }
    }
}

#[cfg(target_os = "windows")]
impl WindowsFileTransaction {
    fn new() -> Result<Self, XrefBoundaryError> {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::{
            Foundation::INVALID_HANDLE_VALUE, Storage::FileSystem::CreateTransaction,
        };

        let description: Vec<u16> = "AutoCAD MCP XREF host transaction"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let handle = unsafe {
            CreateTransaction(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                0,
                0,
                0,
                description.as_ptr(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(XrefBoundaryError::new(format!(
                "create Windows file transaction: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(Self {
            handle: unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle) },
            state: std::cell::Cell::new(WindowsFileTransactionState::Active),
        })
    }

    fn raw_handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        use std::os::windows::io::AsRawHandle;

        self.handle.as_raw_handle()
    }

    fn ensure_active(&self) -> Result<(), XrefBoundaryError> {
        if self.state.get() == WindowsFileTransactionState::Active {
            Ok(())
        } else {
            Err(XrefBoundaryError::new(
                "Windows file transaction is not active",
            ))
        }
    }

    fn open_writer(
        &self,
        path: &Path,
        delete_access: bool,
        share_mode: u32,
        context: &str,
    ) -> Result<File, XrefBoundaryError> {
        use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
        use windows_sys::Win32::{
            Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
            Storage::FileSystem::{
                CreateFileTransactedW, DELETE, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
            },
        };

        self.ensure_active()?;
        let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let desired_access = GENERIC_READ | GENERIC_WRITE | if delete_access { DELETE } else { 0 };
        let handle = unsafe {
            CreateFileTransactedW(
                path.as_ptr(),
                desired_access,
                share_mode,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
                self.raw_handle(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(XrefBoundaryError::new(format!(
                "{context}: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn open_reader(
        &self,
        path: &Path,
        share_mode: u32,
        context: &str,
    ) -> Result<File, XrefBoundaryError> {
        use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
        use windows_sys::Win32::{
            Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
            Storage::FileSystem::{CreateFileTransactedW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING},
        };

        self.ensure_active()?;
        let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileTransactedW(
                path.as_ptr(),
                GENERIC_READ,
                share_mode,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
                self.raw_handle(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(XrefBoundaryError::new(format!(
                "{context}: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn commit(&self) -> Result<(), XrefBoundaryError> {
        use windows_sys::Win32::Storage::FileSystem::CommitTransaction;

        self.ensure_active()?;
        self.state.set(WindowsFileTransactionState::OutcomeUnknown);
        if unsafe { CommitTransaction(self.raw_handle()) } == 0 {
            return Err(XrefBoundaryError::new(format!(
                "commit Windows file transaction: {}",
                io::Error::last_os_error()
            )));
        }
        self.state.set(WindowsFileTransactionState::Committed);
        Ok(())
    }

    fn rollback(&self) -> Result<(), XrefBoundaryError> {
        use windows_sys::Win32::Storage::FileSystem::RollbackTransaction;

        if self.state.get() == WindowsFileTransactionState::RolledBack {
            return Ok(());
        }
        if self.state.get() == WindowsFileTransactionState::Committed {
            return Err(XrefBoundaryError::new(
                "cannot roll back a committed Windows file transaction",
            ));
        }
        self.state.set(WindowsFileTransactionState::OutcomeUnknown);
        if unsafe { RollbackTransaction(self.raw_handle()) } == 0 {
            return Err(XrefBoundaryError::new(format!(
                "roll back Windows file transaction: {}",
                io::Error::last_os_error()
            )));
        }
        self.state.set(WindowsFileTransactionState::RolledBack);
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsFileTransaction {
    fn drop(&mut self) {
        if matches!(
            self.state.get(),
            WindowsFileTransactionState::Active | WindowsFileTransactionState::OutcomeUnknown
        ) {
            let _ = self.rollback();
        }
    }
}

#[cfg(target_os = "windows")]
fn validate_production_host_replacement_guard(
    lock: &ProductionOriginalHostGuard,
) -> Result<(), XrefBoundaryError> {
    if !windows_host_lock_blocks_competing_write(WINDOWS_HOST_LOCK_SHARE_MODE) {
        return Err(XrefBoundaryError::new(
            "Windows host lock permits a competing write handle",
        ));
    }
    if !windows_host_lock_blocks_competing_delete(WINDOWS_HOST_LOCK_SHARE_MODE) {
        return Err(XrefBoundaryError::new(
            "Windows host lock permits a competing delete or path replacement",
        ));
    }
    lock.transaction.ensure_active()?;
    lock.commit_continuity.ensure_active()
}

#[cfg(not(target_os = "windows"))]
fn validate_production_host_replacement_guard(
    _lock: &ProductionOriginalHostGuard,
) -> Result<(), XrefBoundaryError> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn lock_host_file(path: &Path) -> Result<ProductionOriginalHostGuard, XrefBoundaryError> {
    let transaction = WindowsFileTransaction::new()?;
    let file = transaction.open_writer(
        path,
        false,
        WINDOWS_HOST_LOCK_SHARE_MODE,
        "open original host in file transaction",
    )?;
    // A reader in a separate transaction can coexist with the writer while
    // excluding non-transacted writers. Its missing delete share also excludes
    // ordinary deletion and path replacement. Retaining it across the writer's
    // commit gives the ordinary installed guard a race-free handoff.
    let continuity_transaction = WindowsFileTransaction::new()?;
    let continuity_file = continuity_transaction.open_reader(
        path,
        WINDOWS_COMMIT_CONTINUITY_SHARE_MODE,
        "open original host commit-continuity reader",
    )?;
    Ok(ProductionOriginalHostGuard {
        path: path.to_path_buf(),
        file: std::cell::RefCell::new(Some(file)),
        transaction,
        commit_continuity: WindowsCommitContinuityGuard {
            file: std::cell::RefCell::new(Some(continuity_file)),
            transaction: continuity_transaction,
        },
    })
}

#[cfg(target_os = "windows")]
fn unlock_host_file(_lock: &mut ProductionOriginalHostGuard) {}

#[cfg(target_os = "windows")]
fn install_prepared_output_transactionally(
    prepared: &ProductionPreparedOutputGuard,
    original: &ProductionOriginalHostGuard,
) -> Result<ProductionGuardedOutputFile, XrefBoundaryError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };

    original.transaction.ensure_active()?;
    let copied = (|| {
        let mut prepared_file = prepared.guarded.file.borrow_mut();
        let prepared_file = prepared_file.as_mut().ok_or_else(|| {
            XrefBoundaryError::new("prepared-output transaction handle is no longer open")
        })?;
        let prepared_digest = XrefDigest::from_reader(prepared_file).map_err(boundary_io(
            "hash prepared output during transactional install",
        ))?;
        prepared_file.seek(SeekFrom::Start(0)).map_err(boundary_io(
            "rewind prepared output for transactional install",
        ))?;

        let mut original_file = original.file.borrow_mut();
        let original_file = original_file.as_mut().ok_or_else(|| {
            XrefBoundaryError::new("original-host transaction handle is no longer open")
        })?;
        original_file
            .set_len(0)
            .map_err(boundary_io("truncate host in transactional view"))?;
        original_file
            .seek(SeekFrom::Start(0))
            .map_err(boundary_io("rewind host in transactional view"))?;
        io::copy(prepared_file, original_file).map_err(boundary_io(
            "copy verified output into transactional host view",
        ))?;
        original_file
            .sync_all()
            .map_err(boundary_io("flush transactional host view"))?;
        let installed_digest = XrefDigest::from_reader(original_file)
            .map_err(boundary_io("hash transactional host view before commit"))?;
        if installed_digest != prepared_digest {
            return Err(XrefBoundaryError::new(
                "transactional host view digest differs from guarded prepared output",
            ));
        }
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                prepared_file.as_raw_handle(),
                FileDispositionInfo,
                std::ptr::from_ref(&disposition).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            return Err(XrefBoundaryError::new(format!(
                "mark prepared output for transactional deletion: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    })();
    if let Err(error) = copied {
        prepared.guarded.close_transaction_file();
        original.close_transaction_file();
        return Err(rollback_precommit_install(&original.transaction, error));
    }

    // The retained prepared handle marked its own disposition inside the
    // transaction. Closing it consumes the prepared guard and allows commit to
    // publish the host bytes and sibling deletion atomically.
    prepared.guarded.close_transaction_file();
    original.close_transaction_file();
    original.transaction.commit()?;
    // The separate transacted reader remains live across commit. TxF excludes
    // non-transacted writers through that reader, and its missing delete share
    // excludes ordinary deletion and path replacement. Acquire the immutable
    // ordinary guard before releasing that continuity reader.
    let installed_guard = lock_installed_file_after_commit(&prepared.destination)?;
    original.close_commit_continuity_file();
    Ok(installed_guard)
}

#[cfg(target_os = "windows")]
fn rollback_precommit_install(
    transaction: &WindowsFileTransaction,
    error: XrefBoundaryError,
) -> XrefBoundaryError {
    match transaction.rollback() {
        Ok(()) => XrefBoundaryError::new(format!(
            "transactional install was rolled back before commit: {error}"
        )),
        Err(rollback_error) => XrefBoundaryError::new(format!(
            "transactional install failed before commit: {error}; {rollback_error}"
        )),
    }
}

#[cfg(target_os = "windows")]
fn lock_installed_file_after_commit(
    path: &Path,
) -> Result<ProductionGuardedOutputFile, XrefBoundaryError> {
    use std::os::windows::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .read(true)
        .share_mode(windows_primitives::FILE_SHARE_READ)
        .open(path)
        .map_err(boundary_io("open committed host with installed guard"))?;
    Ok(ProductionGuardedOutputFile {
        file: std::cell::RefCell::new(Some(file)),
    })
}

#[cfg(not(any(unix, target_os = "windows")))]
fn lock_host_file(_path: &Path) -> Result<ProductionOriginalHostGuard, XrefBoundaryError> {
    Err(XrefBoundaryError::new(
        "exclusive host locking is unsupported on this platform",
    ))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn unlock_host_file(_lock: &mut ProductionOriginalHostGuard) {}

#[cfg(unix)]
fn atomic_replace_file(source: &Path, destination: &Path) -> Result<(), XrefBoundaryError> {
    fs::rename(source, destination).map_err(boundary_io("atomic replace"))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn atomic_replace_file(_source: &Path, _destination: &Path) -> Result<(), XrefBoundaryError> {
    Err(XrefBoundaryError::new(
        "atomic replacement is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn flush_directory_metadata(directory: &Path) -> Result<(), XrefBoundaryError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(boundary_io("flush containing directory"))
}

#[cfg(target_os = "windows")]
fn flush_directory_metadata(directory: &Path) -> Result<(), XrefBoundaryError> {
    use std::os::windows::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(
            windows_primitives::FILE_SHARE_READ
                | windows_primitives::FILE_SHARE_WRITE
                | windows_primitives::FILE_SHARE_DELETE,
        )
        .custom_flags(windows_primitives::FILE_FLAG_BACKUP_SEMANTICS)
        .open(directory)
        .and_then(|file| file.sync_all())
        .map_err(boundary_io("flush containing directory"))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn flush_directory_metadata(_directory: &Path) -> Result<(), XrefBoundaryError> {
    Err(XrefBoundaryError::new(
        "directory durability is unsupported on this platform",
    ))
}

#[cfg(target_os = "windows")]
mod windows_primitives {
    use std::ffi::c_void;

    pub type Handle = *mut c_void;

    pub const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    pub const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    pub const FILE_SHARE_READ: u32 = 0x0000_0001;
    pub const FILE_SHARE_WRITE: u32 = 0x0000_0002;

    #[repr(C)]
    #[derive(Default)]
    pub struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time_low: u32,
        creation_time_high: u32,
        last_access_time_low: u32,
        last_access_time_high: u32,
        last_write_time_low: u32,
        last_write_time_high: u32,
        pub volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        pub file_index_high: u32,
        pub file_index_low: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "GetFileInformationByHandle"]
        pub fn get_file_information_by_handle(
            file: Handle,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }
}

#[derive(Debug, Default)]
struct XrefTransactionArtifacts {
    sibling_output: Option<PathBuf>,
    auxiliary: BTreeSet<PathBuf>,
}

impl XrefTransactionArtifacts {
    fn all_paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<_> = self.auxiliary.iter().cloned().collect();
        if let Some(output) = &self.sibling_output {
            paths.push(output.clone());
        }
        sort_deduplicate_paths(&mut paths);
        paths
    }

    fn auxiliary_paths(&self) -> Vec<PathBuf> {
        self.auxiliary.iter().cloned().collect()
    }
}

macro_rules! certification_checkpoint {
    ($engine:expr, $point:ident) => {{
        #[cfg(any(test, feature = "xref-certification-failpoints"))]
        {
            $engine.certification_failpoint(XrefCertificationFailpoint::$point)
        }
        #[cfg(not(any(test, feature = "xref-certification-failpoints")))]
        {
            Ok::<(), XrefBoundaryError>(())
        }
    }};
}

pub(crate) fn execute_xref_mutation_transaction<FileSystem, Engine, Inspector, Operation>(
    request: &XrefTransactionRequest,
    file_system: &mut FileSystem,
    engine: &mut Engine,
    inspector: &mut Inspector,
    operation: &mut Operation,
) -> Result<XrefTransactionOutcome<Operation::Response>, XrefTransactionError>
where
    FileSystem: XrefMutationFileSystem,
    Engine: XrefMutationEngineBoundary,
    Inspector: XrefHostFormatInspector,
    Operation: XrefMutationOperationCallback,
{
    let registry = embedded_xref_artifacts().map_err(|error| {
        XrefTransactionError::new(
            XrefTransactionErrorCode::UnsupportedFormat,
            format!("invalid embedded XREF capability artifacts: {error}"),
        )
    })?;

    let initial_format = inspector.inspect(&request.host_path)?;
    validate_format_only_admission(registry, &initial_format, request.operation)?;

    if !engine.is_windows() {
        return Err(XrefTransactionError::new(
            XrefTransactionErrorCode::UnsupportedPlatform,
            unsupported_xref_platform_detail(
                &initial_format,
                request.operation,
                std::env::consts::OS,
                None,
            ),
        ));
    }

    let engine_identity = engine.detect_identity().map_err(|error| {
        XrefTransactionError::new(
            XrefTransactionErrorCode::AutocadUnavailable,
            format!("non-launching AutoCAD discovery failed: {error}"),
        )
    })?;

    let initial_host = file_system
        .observe_path(&request.host_path)
        .map_err(|error| {
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("observe host before lock: {error}"),
            )
        })?;
    coordinate_xref_race_driver(XrefRaceCoordinationPoint::HostAfterInitialObservation).map_err(
        |error| {
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("coordinate deterministic host race: {error}"),
            )
        },
    )?;
    let host_lock = file_system
        .acquire_original_host_guard(&request.host_path)
        .map_err(|error| {
            XrefTransactionError::new(
                XrefTransactionErrorCode::DrawingLocked,
                format!("exclusive host lock failed: {error}"),
            )
        })?;
    let mut artifacts = XrefTransactionArtifacts::default();

    let locked_host = match file_system.observe_original_host(&host_lock) {
        Ok(observation) => observation,
        Err(error) => {
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &initial_host,
                &artifacts,
                false,
                false,
                XrefCleanupInventory::default(),
                XrefTransactionError::new(
                    XrefTransactionErrorCode::ConcurrentDrawingModification,
                    format!("reopen locked host snapshot: {error}"),
                ),
            ));
        }
    };
    if !same_observation(&initial_host, &locked_host) {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::ConcurrentDrawingModification,
                "host identity or digest changed before locked snapshot revalidation",
            ),
        ));
    }
    if let Err(error) = file_system.validate_host_replacement_guard(&host_lock) {
        let reason = format!("host replacement cannot retain the required exclusion: {error}");
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::UnsupportedPlatform,
                unsupported_xref_platform_detail(
                    &initial_format,
                    request.operation,
                    std::env::consts::OS,
                    Some(&reason),
                ),
            ),
        ));
    }

    let locked_format = match inspector.inspect(&request.host_path) {
        Ok(format) => format,
        Err(error) => {
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &locked_host,
                &artifacts,
                false,
                false,
                XrefCleanupInventory::default(),
                error,
            ));
        }
    };
    if locked_format != initial_format {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::UnsupportedFormat,
                "locked host format facts differ from pre-lock admission",
            ),
        ));
    }
    if let Err(error) = validate_format_only_admission(registry, &locked_format, request.operation)
    {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory::default(),
            error,
        ));
    }

    let query = match locked_format.capability_query(&engine_identity, request.operation) {
        Ok(query) => query,
        Err(error) => {
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &locked_host,
                &artifacts,
                false,
                false,
                XrefCleanupInventory::default(),
                error,
            ));
        }
    };
    let admission = match select_xref_mutation_capability(registry, query) {
        Ok(admission) => admission,
        Err(error) => {
            let error = transaction_error_from_capability(error);
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &locked_host,
                &artifacts,
                false,
                false,
                XrefCleanupInventory::default(),
                error,
            ));
        }
    };

    if let Err(error) = operation.validate_locked(&XrefLockedMutationContext {
        host_path: &request.host_path,
        host: &locked_host,
        format: &locked_format,
        admission: &admission,
    }) {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory::default(),
            error,
        ));
    }
    let sources = operation
        .locked_source_inputs()
        .unwrap_or(&request.sources)
        .to_vec();
    if let Err(error) = validate_source_graph(&sources) {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory::default(),
            error,
        ));
    }

    let sibling_output =
        match file_system.copy_locked_host_to_sibling(&host_lock, locked_format.host_format) {
            Ok(path) => path,
            Err(error) => {
                return Err(finish_pre_replace_failure(
                    file_system,
                    engine,
                    &host_lock,
                    &locked_host,
                    &artifacts,
                    false,
                    false,
                    XrefCleanupInventory::default(),
                    XrefTransactionError::new(
                        XrefTransactionErrorCode::WriteFailed,
                        format!("create sibling transaction output: {error}"),
                    ),
                ));
            }
        };
    artifacts.sibling_output = Some(sibling_output.clone());

    let staging_directory = match file_system.create_staging_directory() {
        Ok(path) => path,
        Err(error) => {
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &locked_host,
                &artifacts,
                false,
                false,
                XrefCleanupInventory::default(),
                XrefTransactionError::new(
                    XrefTransactionErrorCode::WriteFailed,
                    format!("create isolated staging: {error}"),
                ),
            ));
        }
    };
    artifacts.auxiliary.insert(staging_directory.clone());

    let mut snapshots = Vec::with_capacity(sources.len());
    for (index, source) in sources.iter().enumerate() {
        if let Err(error) = certification_checkpoint!(engine, DuringSourceSnapshot) {
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &locked_host,
                &artifacts,
                false,
                true,
                XrefCleanupInventory::default(),
                XrefTransactionError::new(
                    XrefTransactionErrorCode::XrefSourceChanged,
                    format!("source snapshot failpoint: {error}"),
                ),
            ));
        }
        let extension = source
            .path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("dwg");
        let destination = staging_directory.join("sources").join(format!(
            "{index:04}-{}.{}",
            safe_source_id(&source.source_id),
            extension.to_ascii_lowercase()
        ));
        artifacts.auxiliary.insert(destination.clone());
        let evidence = match file_system.capture_source(
            &source.path,
            &destination,
            &source.filesystem_identity,
        ) {
            Ok(evidence) => evidence,
            Err(XrefSourceCaptureError::SourceRace(error)) => {
                return Err(finish_pre_replace_failure(
                    file_system,
                    engine,
                    &host_lock,
                    &locked_host,
                    &artifacts,
                    false,
                    true,
                    XrefCleanupInventory::default(),
                    XrefTransactionError::new(
                        XrefTransactionErrorCode::XrefSourceChanged,
                        format!("capture source '{}': {error}", source.source_id),
                    ),
                ));
            }
            Err(XrefSourceCaptureError::SourceUnreadable(error)) => {
                return Err(finish_pre_replace_failure(
                    file_system,
                    engine,
                    &host_lock,
                    &locked_host,
                    &artifacts,
                    false,
                    false,
                    XrefCleanupInventory::default(),
                    XrefTransactionError::new(
                        XrefTransactionErrorCode::Domain("xref_source_unreadable".to_string()),
                        format!("read source '{}': {error}", source.source_id),
                    ),
                ));
            }
            Err(XrefSourceCaptureError::Staging(error)) => {
                return Err(finish_pre_replace_failure(
                    file_system,
                    engine,
                    &host_lock,
                    &locked_host,
                    &artifacts,
                    false,
                    false,
                    XrefCleanupInventory::default(),
                    XrefTransactionError::new(
                        XrefTransactionErrorCode::WriteFailed,
                        format!("stage source snapshot '{}': {error}", source.source_id),
                    ),
                ));
            }
        };
        if !evidence.is_stable_for(&source.filesystem_identity) {
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &locked_host,
                &artifacts,
                false,
                true,
                XrefCleanupInventory::default(),
                XrefTransactionError::new(
                    XrefTransactionErrorCode::XrefSourceChanged,
                    format!(
                        "source '{}' identity/digest changed or snapshot digest disagreed",
                        source.source_id
                    ),
                ),
            ));
        }
        let captured_digest_sha256 = evidence.digest_before.hex();
        if source.inspected_digest_sha256.as_deref() != Some(captured_digest_sha256.as_str()) {
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &locked_host,
                &artifacts,
                false,
                true,
                XrefCleanupInventory::default(),
                XrefTransactionError::new(
                    XrefTransactionErrorCode::XrefSourceChanged,
                    format!(
                        "source '{}' bytes differ from the exact dependency bytes inspected during preflight",
                        source.source_id
                    ),
                ),
            ));
        }
        snapshots.push(XrefSourceSnapshot {
            source_id: source.source_id.clone(),
            original_path: source.path.clone(),
            saved_path: source.saved_path.clone(),
            immediate_host_source_id: source.immediate_host_source_id.clone(),
            snapshot_path: destination,
            original_identity: format!("{:?}", evidence.handle_identity_before),
            filesystem_identity: evidence.handle_identity_before,
            snapshot_identity: evidence.snapshot_identity,
            digest_sha256: evidence.snapshot_digest.hex(),
        });
    }

    let mut search_directories: Vec<PathBuf> = snapshots
        .iter()
        .filter_map(|snapshot| snapshot.snapshot_path.parent().map(Path::to_path_buf))
        .collect();
    sort_deduplicate_paths(&mut search_directories);
    let profile_document = XrefIsolatedProfileDocument {
        schema_version: 1,
        certified_autocad_arg: request.profile.certified_autocad_arg.clone(),
        search_directories,
        source_snapshots: snapshots.clone(),
        unit_defaults: request.profile.unit_defaults.clone(),
        reconciliation: request.profile.reconciliation.clone(),
    };
    let materialized_profile =
        match file_system.materialize_profile(&staging_directory, &profile_document) {
            Ok(profile) => profile,
            Err(error) => {
                return Err(finish_pre_replace_failure(
                    file_system,
                    engine,
                    &host_lock,
                    &locked_host,
                    &artifacts,
                    false,
                    false,
                    XrefCleanupInventory::default(),
                    XrefTransactionError::new(
                        XrefTransactionErrorCode::WriteFailed,
                        format!("materialize isolated profile: {error}"),
                    ),
                ));
            }
        };
    if !materialized_profile
        .launch_path
        .starts_with(&staging_directory)
        || materialized_profile
            .artifacts
            .iter()
            .any(|path| !path.starts_with(&staging_directory))
        || !materialized_profile
            .artifacts
            .contains(&materialized_profile.launch_path)
    {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                "materialized profile artifacts escaped staging or omitted the launch profile",
            ),
        ));
    }
    artifacts
        .auxiliary
        .extend(materialized_profile.artifacts.iter().cloned());
    let profile_path = materialized_profile.launch_path;

    let mut launch_context = XrefEngineLaunchContext {
        temporary_host: &sibling_output,
        staging_directory: &staging_directory,
        profile_path: &profile_path,
        certified_autocad_arg: &profile_document.certified_autocad_arg,
        search_directories: &profile_document.search_directories,
        source_snapshots: &snapshots,
        source_exclusion_proven: false,
    };
    if let Err(error) = verify_source_snapshot_integrity(file_system, &snapshots) {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("immutable source snapshot integrity failed before launch: {error}"),
            ),
        ));
    }
    if let Err(error) = file_system.prove_exclusive_source_snapshot_resolution(&snapshots) {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::Domain("unsupported_xref_source".to_string()),
                format!("original source-path exclusion is not proven: {error}"),
            ),
        ));
    }
    launch_context.source_exclusion_proven = true;
    if let Err(error) = engine.prove_exclusive_source_snapshot_resolution(&launch_context) {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::Domain("unsupported_xref_source".to_string()),
                format!("immutable source resolution is not proven: {error}"),
            ),
        ));
    }
    if let Err(error) = engine.launch(&launch_context) {
        artifacts.auxiliary.extend(engine.auxiliary_artifacts());
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            true,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::AutocadUnavailable,
                format!("launch isolated AutoCAD session: {error}"),
            ),
        ));
    }
    let engine_started = true;

    let operation_artifacts = match operation.execute(
        engine,
        &XrefOperationContext {
            temporary_host: &sibling_output,
            staging_directory: &staging_directory,
            profile_path: &profile_path,
            source_snapshots: &snapshots,
        },
    ) {
        Ok(paths) => paths,
        Err(error) => {
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &locked_host,
                &artifacts,
                engine_started,
                false,
                XrefCleanupInventory::default(),
                error,
            ));
        }
    };
    for path in operation_artifacts {
        if !path.starts_with(&staging_directory) {
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &locked_host,
                &artifacts,
                engine_started,
                false,
                XrefCleanupInventory::default(),
                XrefTransactionError::new(
                    XrefTransactionErrorCode::WriteFailed,
                    format!(
                        "operation artifact escaped isolated staging: {}",
                        path.display()
                    ),
                ),
            ));
        }
        artifacts.auxiliary.insert(path);
    }

    if let Err(error) = certification_checkpoint!(engine, BeforeSave) {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            engine_started,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("before save: {error}"),
            ),
        ));
    }
    let save_result = engine.save(&locked_format);
    artifacts.auxiliary.extend(engine.auxiliary_artifacts());
    if let Err(error) = save_result {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            engine_started,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("explicit AutoCAD save failed: {error}"),
            ),
        ));
    }
    if let Err(error) = certification_checkpoint!(engine, AfterSave) {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            engine_started,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("after save: {error}"),
            ),
        ));
    }
    if let Err(error) = file_system.flush_file(&sibling_output) {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            engine_started,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("flush saved temporary host: {error}"),
            ),
        ));
    }

    if let Err(error) = certification_checkpoint!(engine, BeforeVerification) {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            engine_started,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::VerificationFailed,
                format!("before verification: {error}"),
            ),
        ));
    }
    let output_observation = match file_system.observe_path(&sibling_output) {
        Ok(observation) if observation.is_stable() => observation,
        Ok(_) => {
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &locked_host,
                &artifacts,
                engine_started,
                false,
                XrefCleanupInventory::default(),
                XrefTransactionError::new(
                    XrefTransactionErrorCode::VerificationFailed,
                    "temporary output identity changed during reopen",
                ),
            ));
        }
        Err(error) => {
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &locked_host,
                &artifacts,
                engine_started,
                false,
                XrefCleanupInventory::default(),
                XrefTransactionError::new(
                    XrefTransactionErrorCode::VerificationFailed,
                    format!("reopen saved temporary output: {error}"),
                ),
            ));
        }
    };
    let output_format = match inspector.inspect(&sibling_output) {
        Ok(format) => format,
        Err(error) => {
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &locked_host,
                &artifacts,
                engine_started,
                false,
                XrefCleanupInventory::default(),
                XrefTransactionError::new(
                    XrefTransactionErrorCode::VerificationFailed,
                    format!("reopen output format verification: {error}"),
                ),
            ));
        }
    };
    if output_format != locked_format {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            engine_started,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::VerificationFailed,
                "temporary output changed host format/version/form/code page",
            ),
        ));
    }
    let response = match operation.verify(&XrefVerificationContext {
        temporary_host: &sibling_output,
        output: &output_observation,
        source_snapshots: &snapshots,
    }) {
        Ok(response) => response,
        Err(error) => {
            let error = normalize_verification_error(error);
            return Err(finish_pre_replace_failure(
                file_system,
                engine,
                &host_lock,
                &locked_host,
                &artifacts,
                engine_started,
                false,
                XrefCleanupInventory::default(),
                error,
            ));
        }
    };
    if let Err(error) = certification_checkpoint!(engine, AfterVerification) {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            engine_started,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::VerificationFailed,
                format!("after verification: {error}"),
            ),
        ));
    }

    let stop_error = engine.stop().err().map(|error| error.to_string());
    if let Some(stop_error) = stop_error {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory {
                engine_stop_error: Some(stop_error.clone()),
                ..XrefCleanupInventory::default()
            },
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("stop AutoCAD before commit: {stop_error}"),
            ),
        ));
    }

    if let Err(error) = verify_source_snapshot_integrity(file_system, &snapshots) {
        return Err(finish_pre_replace_failure(
            file_system,
            engine,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::VerificationFailed,
                format!("immutable source snapshot integrity failed after engine stop: {error}"),
            ),
        ));
    }

    let prepared_output_guard =
        match file_system.prepare_output_guard(&sibling_output, &request.host_path, &host_lock) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(finish_pre_replace_failure(
                    file_system,
                    engine,
                    &host_lock,
                    &locked_host,
                    &artifacts,
                    false,
                    false,
                    XrefCleanupInventory::default(),
                    XrefTransactionError::new(
                        XrefTransactionErrorCode::VerificationFailed,
                        format!("acquire verified transaction-output guard: {error}"),
                    ),
                ));
            }
        };
    let prepared_observation = match file_system.observe_prepared_output(&prepared_output_guard) {
        Ok(observation) => observation,
        Err(error) => {
            return Err(finish_prepared_output_failure(
                file_system,
                engine,
                prepared_output_guard,
                &host_lock,
                &locked_host,
                &artifacts,
                false,
                false,
                XrefCleanupInventory::default(),
                XrefTransactionError::new(
                    XrefTransactionErrorCode::VerificationFailed,
                    format!("observe guarded transaction output before commit: {error}"),
                ),
            ));
        }
    };
    if !same_observation(&output_observation, &prepared_observation) {
        return Err(finish_prepared_output_failure(
            file_system,
            engine,
            prepared_output_guard,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::VerificationFailed,
                "transaction output changed between persisted verification and commit preparation",
            ),
        ));
    }

    if let Err(error) = certification_checkpoint!(engine, BeforeCleanup) {
        return Err(finish_prepared_output_failure(
            file_system,
            engine,
            prepared_output_guard,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            XrefCleanupInventory::default(),
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("before cleanup: {error}"),
            ),
        ));
    }
    let cleanup = file_system.cleanup(&artifacts.auxiliary_paths());
    if !cleanup.is_clean() {
        return Err(finish_prepared_output_failure(
            file_system,
            engine,
            prepared_output_guard,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            cleanup,
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                "auxiliary cleanup could not be proven before replacement",
            ),
        ));
    }
    if let Err(error) = certification_checkpoint!(engine, AfterCleanup) {
        return Err(finish_prepared_output_failure(
            file_system,
            engine,
            prepared_output_guard,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            cleanup,
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("after cleanup: {error}"),
            ),
        ));
    }

    if let Err(error) = certification_checkpoint!(engine, BeforeHostRecheck) {
        return Err(finish_prepared_output_failure(
            file_system,
            engine,
            prepared_output_guard,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            cleanup,
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("before host recheck: {error}"),
            ),
        ));
    }
    let host_before_replace = match file_system.observe_original_host(&host_lock) {
        Ok(observation) => observation,
        Err(error) => {
            return Err(finish_prepared_output_failure(
                file_system,
                engine,
                prepared_output_guard,
                &host_lock,
                &locked_host,
                &artifacts,
                false,
                false,
                cleanup,
                XrefTransactionError::new(
                    XrefTransactionErrorCode::ConcurrentDrawingModification,
                    format!("recheck original host before replacement: {error}"),
                ),
            ));
        }
    };
    if !same_observation(&locked_host, &host_before_replace) {
        return Err(finish_prepared_output_failure(
            file_system,
            engine,
            prepared_output_guard,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            cleanup,
            XrefTransactionError::new(
                XrefTransactionErrorCode::ConcurrentDrawingModification,
                "original host identity or digest changed before replacement",
            ),
        ));
    }
    if let Err(error) = certification_checkpoint!(engine, AfterHostRecheck) {
        return Err(finish_prepared_output_failure(
            file_system,
            engine,
            prepared_output_guard,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            cleanup,
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("after host recheck: {error}"),
            ),
        ));
    }
    if let Err(error) = certification_checkpoint!(engine, BeforeReplace) {
        return Err(finish_prepared_output_failure(
            file_system,
            engine,
            prepared_output_guard,
            &host_lock,
            &locked_host,
            &artifacts,
            false,
            false,
            cleanup,
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("before atomic replacement: {error}"),
            ),
        ));
    }

    let installed_guard =
        match file_system.install_prepared_output(prepared_output_guard, &host_lock) {
            Ok(installed) => installed,
            Err(error) => {
                return Err(finish_replace_failure(
                    file_system,
                    error,
                    &host_lock,
                    &request.host_path,
                    &locked_host,
                    &artifacts,
                    cleanup,
                ));
            }
        };
    artifacts.sibling_output = None;

    if let Err(error) = certification_checkpoint!(engine, AfterReplace) {
        return Err(uncertain_commit_error(
            cleanup,
            format!("after atomic replacement: {error}"),
        ));
    }
    if let Err(error) = certification_checkpoint!(engine, BeforeDirectoryFlush) {
        return Err(uncertain_commit_error(
            cleanup,
            format!("before directory flush: {error}"),
        ));
    }
    let parent = request.host_path.parent().ok_or_else(|| {
        uncertain_commit_error(cleanup.clone(), "installed host has no parent directory")
    })?;
    if let Err(error) = file_system.flush_directory(parent) {
        return Err(uncertain_commit_error(
            cleanup,
            format!("directory durability failed after replacement: {error}"),
        ));
    }
    if let Err(error) = certification_checkpoint!(engine, AfterDirectoryFlush) {
        return Err(uncertain_commit_error(
            cleanup,
            format!("after directory flush: {error}"),
        ));
    }
    if let Err(error) = certification_checkpoint!(engine, BeforeInstalledDigestCheck) {
        return Err(uncertain_commit_error(
            cleanup,
            format!("before installed digest check: {error}"),
        ));
    }
    let installed = file_system
        .observe_installed_host(&installed_guard)
        .map_err(|error| {
            uncertain_commit_error(
                cleanup.clone(),
                format!("observe installed host after replacement: {error}"),
            )
        })?;
    if !installed.is_stable()
        || !file_system.installed_identity_matches_contract(
            &locked_host,
            &output_observation,
            &installed,
        )
        || installed.digest != output_observation.digest
    {
        return Err(uncertain_commit_error(
            cleanup,
            "installed file identity transition or digest does not match the guarded install contract",
        ));
    }

    Ok(XrefTransactionOutcome {
        response,
        row_id: admission.capability.row_id.clone(),
        original_digest_sha256: locked_host.digest.hex(),
        installed_digest_sha256: installed.digest.hex(),
        source_snapshots: snapshots,
        cleanup,
    })
}

fn describe_xref_host_format(
    host_format: XrefHostFormat,
    drawing_version: &str,
    dxf_form: XrefDxfForm,
    code_page: Option<&str>,
) -> String {
    match (host_format, dxf_form) {
        (XrefHostFormat::Dwg, _) => format!("DWG {drawing_version}"),
        (XrefHostFormat::Dxf, XrefDxfForm::Ascii) => format!(
            "DXF {drawing_version} ASCII (code page {})",
            code_page.unwrap_or("unknown")
        ),
        (XrefHostFormat::Dxf, XrefDxfForm::Binary) => {
            format!("DXF {drawing_version} binary")
        }
        (XrefHostFormat::Dxf, XrefDxfForm::NotApplicable) => {
            format!("DXF {drawing_version} (form unavailable)")
        }
    }
}

pub(crate) fn unsupported_xref_platform_detail(
    format: &XrefHostFormatFacts,
    operation: XrefMutationOperation,
    current_platform: &str,
    reason: Option<&str>,
) -> String {
    let reason = reason
        .map(|reason| format!("; reason=\"{reason}\""))
        .unwrap_or_default();
    format!(
        "{} is unavailable for detected host format {}; current_platform={current_platform}; required_engine=\"package-mode-admitted full AutoCAD accoreconsole runtime on Windows\"{reason}; recovery=\"run {} on Windows with an AutoCAD activation admitted by this package mode; Preview activation is candidate-only\"",
        operation.as_str(),
        describe_xref_host_format(
            format.host_format,
            &format.drawing_version,
            format.dxf_form,
            format.code_page.as_deref(),
        ),
        operation.as_str(),
    )
}

pub(crate) fn validate_format_only_admission(
    registry: &XrefArtifactRegistry,
    format: &XrefHostFormatFacts,
    operation: XrefMutationOperation,
) -> Result<(), XrefTransactionError> {
    let admitted = registry.capabilities().rows.iter().any(|row| {
        row.host_format == format.host_format
            && row.drawing_version == format.drawing_version
            && row.dxf_form == format.dxf_form
            && row.code_page == format.code_page
            && row.operations.contains(&operation)
    });
    if admitted {
        Ok(())
    } else {
        let admitted_formats = registry
            .capabilities()
            .rows
            .iter()
            .filter(|row| row.operations.contains(&operation))
            .map(|row| {
                describe_xref_host_format(
                    row.host_format,
                    &row.drawing_version,
                    row.dxf_form,
                    row.code_page.as_deref(),
                )
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        let detected_format = describe_xref_host_format(
            format.host_format,
            &format.drawing_version,
            format.dxf_form,
            format.code_page.as_deref(),
        );
        Err(XrefTransactionError::new(
            XrefTransactionErrorCode::UnsupportedFormat,
            format!(
                "{} is not admitted for detected host format {}; admitted formats for this operation: [{}]; recovery=\"save or convert a working copy to one of the admitted formats, then run {} on Windows with an activation target that admits that operation and format\"",
                operation.as_str(),
                detected_format,
                admitted_formats,
                operation.as_str(),
            ),
        ))
    }
}

pub(crate) fn transaction_error_from_capability(
    error: XrefCapabilityAdmissionError,
) -> XrefTransactionError {
    let code = match error {
        XrefCapabilityAdmissionError::UnsupportedFormat { .. } => {
            XrefTransactionErrorCode::UnsupportedFormat
        }
        XrefCapabilityAdmissionError::OperationNotCertified { .. } => {
            XrefTransactionErrorCode::UnsupportedPlatform
        }
        XrefCapabilityAdmissionError::InvalidEmbeddedArtifacts(_)
        | XrefCapabilityAdmissionError::RegistryInvariant { .. } => {
            XrefTransactionErrorCode::WriteFailed
        }
    };
    XrefTransactionError::new(code, error.to_string())
}

fn normalize_verification_error(mut error: XrefTransactionError) -> XrefTransactionError {
    error.code = XrefTransactionErrorCode::VerificationFailed;
    error
}

fn validate_source_graph(sources: &[XrefSourceInput]) -> Result<(), XrefTransactionError> {
    if sources.iter().any(|source| {
        !matches!(
            source.identity_provenance,
            XrefSourceIdentityProvenance::LockedGraphTraversal
                | XrefSourceIdentityProvenance::DigestBoundGraphTraversal
        )
    }) {
        return Err(XrefTransactionError::new(
            XrefTransactionErrorCode::Domain("unsupported_xref_source".to_string()),
            "source filesystem identity was not retained by locked dependency traversal",
        ));
    }
    let ids: BTreeSet<&str> = sources
        .iter()
        .map(|source| source.source_id.as_str())
        .collect();
    if ids.len() != sources.len()
        || sources.iter().any(|source| {
            source.source_id.is_empty()
                || source.saved_path.is_empty()
                || source
                    .inspected_digest_sha256
                    .as_deref()
                    .is_none_or(|digest| {
                        digest.len() != 64
                            || !digest
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
        })
    {
        return Err(XrefTransactionError::new(
            XrefTransactionErrorCode::Domain("unsupported_xref_source".to_string()),
            "source snapshot IDs must be unique and source IDs, saved paths, and exact inspected-byte digests must be valid",
        ));
    }
    for source in sources {
        if source
            .immediate_host_source_id
            .as_deref()
            .is_some_and(|parent| parent == source.source_id || !ids.contains(parent))
        {
            return Err(XrefTransactionError::new(
                XrefTransactionErrorCode::Domain("unsupported_xref_source".to_string()),
                format!(
                    "source '{}' has an invalid immediate-host source reference",
                    source.source_id
                ),
            ));
        }
    }
    Ok(())
}

fn verify_source_snapshot_integrity<FileSystem>(
    file_system: &mut FileSystem,
    snapshots: &[XrefSourceSnapshot],
) -> Result<(), XrefBoundaryError>
where
    FileSystem: XrefMutationFileSystem,
{
    for snapshot in snapshots {
        let observation = file_system.observe_source_snapshot(&snapshot.snapshot_path)?;
        if !observation.is_stable()
            || observation.identity != snapshot.snapshot_identity
            || observation.digest.hex() != snapshot.digest_sha256
        {
            return Err(XrefBoundaryError::new(format!(
                "source snapshot '{}' identity or digest changed",
                snapshot.source_id
            )));
        }
    }
    Ok(())
}

fn safe_source_id(source_id: &str) -> String {
    let value: String = source_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect();
    if value.is_empty() {
        "source".to_string()
    } else {
        value
    }
}

fn same_observation(expected: &XrefFileObservation, actual: &XrefFileObservation) -> bool {
    expected.is_stable() && actual.is_stable() && expected == actual
}

#[allow(clippy::too_many_arguments)]
fn finish_pre_replace_failure<FileSystem, Engine>(
    file_system: &mut FileSystem,
    engine: &mut Engine,
    host_lock: &FileSystem::OriginalHostGuard,
    locked_host: &XrefFileObservation,
    artifacts: &XrefTransactionArtifacts,
    engine_started: bool,
    source_race: bool,
    mut cleanup: XrefCleanupInventory,
    mut underlying: XrefTransactionError,
) -> XrefTransactionError
where
    FileSystem: XrefMutationFileSystem,
    Engine: XrefMutationEngineBoundary,
{
    let mut failure_paths = artifacts.all_paths();
    failure_paths.extend(engine.auxiliary_artifacts());
    sort_deduplicate_paths(&mut failure_paths);

    if engine_started {
        if let Err(error) = engine.stop() {
            cleanup.engine_stop_error = Some(error.to_string());
        }
    }

    let host_changed_before_cleanup = file_system
        .observe_original_host(host_lock)
        .map(|observation| !same_observation(locked_host, &observation))
        .unwrap_or(true);
    cleanup.merge(file_system.cleanup(&failure_paths));
    let host_changed_after_cleanup = file_system
        .observe_original_host(host_lock)
        .map(|observation| !same_observation(locked_host, &observation))
        .unwrap_or(true);

    if host_changed_before_cleanup || host_changed_after_cleanup {
        underlying = XrefTransactionError::new(
            XrefTransactionErrorCode::ConcurrentDrawingModification,
            format!(
                "host changed during transaction failure epilogue; underlying={}",
                underlying.code.as_str()
            ),
        );
    } else if source_race {
        underlying = XrefTransactionError::new(
            XrefTransactionErrorCode::XrefSourceChanged,
            underlying.detail,
        );
    } else if !cleanup.is_clean()
        && matches!(
            underlying.code,
            XrefTransactionErrorCode::WriteFailed | XrefTransactionErrorCode::AutocadUnavailable
        )
    {
        underlying.code = XrefTransactionErrorCode::WriteFailed;
    }
    underlying.with_cleanup(cleanup)
}

#[allow(clippy::too_many_arguments)]
fn finish_prepared_output_failure<FileSystem, Engine>(
    file_system: &mut FileSystem,
    engine: &mut Engine,
    prepared_output_guard: FileSystem::PreparedOutputGuard,
    host_lock: &FileSystem::OriginalHostGuard,
    locked_host: &XrefFileObservation,
    artifacts: &XrefTransactionArtifacts,
    engine_started: bool,
    source_race: bool,
    cleanup: XrefCleanupInventory,
    underlying: XrefTransactionError,
) -> XrefTransactionError
where
    FileSystem: XrefMutationFileSystem,
    Engine: XrefMutationEngineBoundary,
{
    // A future Windows guard may deny deletion or rename while it is live.
    // Release it before the ordinary failure epilogue inventories artifacts.
    drop(prepared_output_guard);
    finish_pre_replace_failure(
        file_system,
        engine,
        host_lock,
        locked_host,
        artifacts,
        engine_started,
        source_race,
        cleanup,
        underlying,
    )
}

fn finish_replace_failure<FileSystem>(
    file_system: &mut FileSystem,
    install_failure: XrefPreparedInstallError<FileSystem::PreparedOutputGuard>,
    original_host_guard: &FileSystem::OriginalHostGuard,
    host_path: &Path,
    locked_host: &XrefFileObservation,
    artifacts: &XrefTransactionArtifacts,
    mut cleanup: XrefCleanupInventory,
) -> XrefTransactionError
where
    FileSystem: XrefMutationFileSystem,
{
    let XrefPreparedInstallError {
        disposition,
        error,
        prepared_output_guard,
    } = install_failure;
    let guarded_original_proven_unchanged = file_system
        .observe_original_host(original_host_guard)
        .map(|observation| same_observation(locked_host, &observation))
        .unwrap_or(false);
    let original_path_proven_unchanged = file_system
        .observe_path(host_path)
        .map(|observation| same_observation(locked_host, &observation))
        .unwrap_or(false);
    drop(prepared_output_guard);
    cleanup.merge(file_system.cleanup(&artifacts.all_paths()));
    let code = if disposition == XrefPreparedInstallDisposition::DefinitelyNotInstalled
        && guarded_original_proven_unchanged
        && original_path_proven_unchanged
    {
        XrefTransactionErrorCode::WriteFailed
    } else {
        XrefTransactionErrorCode::MutationStateUnknown
    };
    XrefTransactionError::new(code, format!("atomic replacement failed: {error}"))
        .with_cleanup(cleanup)
}

fn uncertain_commit_error(
    cleanup: XrefCleanupInventory,
    detail: impl Into<String>,
) -> XrefTransactionError {
    XrefTransactionError::new(XrefTransactionErrorCode::MutationStateUnknown, detail)
        .with_cleanup(cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification::{XrefEmbeddedArtifact, XREF_MUTATION_OPERATIONS};
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

    type EventLog = Rc<RefCell<Vec<String>>>;

    fn fake_digest(byte: u8) -> XrefDigest {
        XrefDigest([byte; 32])
    }

    fn fake_observation(identity: &str, digest: u8) -> XrefFileObservation {
        let identity = XrefFileIdentity::fake(identity);
        XrefFileObservation {
            identity: identity.clone(),
            path_identity: identity,
            digest: fake_digest(digest),
        }
    }

    fn fake_source_identity(identity: &str) -> FilesystemIdentity {
        FilesystemIdentity::opaque(identity.as_bytes().to_vec()).unwrap()
    }

    fn valid_format() -> XrefHostFormatFacts {
        XrefHostFormatFacts {
            host_format: XrefHostFormat::Dwg,
            drawing_version: "AC1032".to_string(),
            dxf_form: XrefDxfForm::NotApplicable,
            code_page: None,
        }
    }

    fn stable_source_evidence(identity: &str, digest: u8) -> XrefSourceCaptureEvidence {
        let identity = fake_source_identity(identity);
        XrefSourceCaptureEvidence {
            path_identity_before: identity.clone(),
            handle_identity_before: identity.clone(),
            digest_before: fake_digest(digest),
            snapshot_digest: fake_digest(digest),
            snapshot_identity: XrefFileIdentity::fake(format!("snapshot-{identity:?}")),
            handle_identity_after: identity.clone(),
            path_identity_after: identity,
            digest_after: fake_digest(digest),
        }
    }

    #[derive(Debug)]
    struct FakeOriginalHostGuard {
        events: EventLog,
    }

    impl Drop for FakeOriginalHostGuard {
        fn drop(&mut self) {
            self.events
                .borrow_mut()
                .push("guard:original-release".to_string());
        }
    }

    #[derive(Debug)]
    struct FakePreparedOutputGuard {
        events: Option<EventLog>,
    }

    impl FakePreparedOutputGuard {
        fn transition(mut self) -> EventLog {
            let events = self
                .events
                .take()
                .expect("prepared output guard already transitioned");
            events
                .borrow_mut()
                .push("guard:prepared-transition".to_string());
            events
        }
    }

    impl Drop for FakePreparedOutputGuard {
        fn drop(&mut self) {
            if let Some(events) = &self.events {
                events
                    .borrow_mut()
                    .push("guard:prepared-release".to_string());
            }
        }
    }

    #[derive(Debug)]
    struct FakeInstalledHostGuard {
        events: EventLog,
    }

    impl Drop for FakeInstalledHostGuard {
        fn drop(&mut self) {
            self.events
                .borrow_mut()
                .push("guard:installed-release".to_string());
        }
    }

    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    enum FakeReplaceFailure {
        BeforeInstall,
        AfterInstall,
        AmbiguousOriginalRestored,
    }

    #[derive(Debug)]
    struct FakeFileSystem {
        events: EventLog,
        host_path: PathBuf,
        output_path: PathBuf,
        staging_path: PathBuf,
        initial_host: XrefFileObservation,
        locked_host: XrefFileObservation,
        output: XrefFileObservation,
        installed: XrefFileObservation,
        locked_observations: VecDeque<XrefFileObservation>,
        source_evidence: VecDeque<XrefSourceCaptureEvidence>,
        source_snapshot_observations: BTreeMap<PathBuf, XrefFileObservation>,
        source_snapshot_observation_count: usize,
        change_snapshot_after_first_observation: bool,
        source_capture_error: Option<XrefSourceCaptureError>,
        materialized_profile: Option<XrefIsolatedProfileDocument>,
        sibling_outputs_created: usize,
        capture_calls: usize,
        replaced: bool,
        lock_fail: bool,
        replacement_guarded: bool,
        cleanup_fail: bool,
        flush_file_fail: bool,
        prepare_failure: bool,
        prepared_mismatch: bool,
        replace_failure: Option<FakeReplaceFailure>,
        directory_flush_fail: bool,
        installed_mismatch: bool,
    }

    impl FakeFileSystem {
        fn new(events: EventLog) -> Self {
            let initial_host = fake_observation("host", 1);
            let locked_host = initial_host.clone();
            let output = fake_observation("output", 2);
            Self {
                events,
                host_path: PathBuf::from("/drawings/host.dwg"),
                output_path: PathBuf::from("/drawings/.autocad-mcp-xref-output.dwg"),
                staging_path: PathBuf::from("/isolated/xref-transaction"),
                initial_host,
                locked_host,
                output: output.clone(),
                installed: output,
                locked_observations: VecDeque::new(),
                source_evidence: VecDeque::from([stable_source_evidence("source-a", 9)]),
                source_snapshot_observations: BTreeMap::new(),
                source_snapshot_observation_count: 0,
                change_snapshot_after_first_observation: false,
                source_capture_error: None,
                materialized_profile: None,
                sibling_outputs_created: 0,
                capture_calls: 0,
                replaced: false,
                lock_fail: false,
                replacement_guarded: true,
                cleanup_fail: false,
                flush_file_fail: false,
                prepare_failure: false,
                prepared_mismatch: false,
                replace_failure: None,
                directory_flush_fail: false,
                installed_mismatch: false,
            }
        }

        fn event(&self, value: impl Into<String>) {
            self.events.borrow_mut().push(value.into());
        }
    }

    impl XrefMutationFileSystem for FakeFileSystem {
        type OriginalHostGuard = FakeOriginalHostGuard;
        type PreparedOutputGuard = FakePreparedOutputGuard;
        type InstalledHostGuard = FakeInstalledHostGuard;

        fn observe_path(&mut self, path: &Path) -> Result<XrefFileObservation, XrefBoundaryError> {
            if path == self.host_path {
                self.event(if self.replaced {
                    "fs:observe-installed"
                } else {
                    "fs:observe-host"
                });
                if self.replaced {
                    if self.installed_mismatch {
                        return Ok(fake_observation("unexpected-installed", 7));
                    }
                    Ok(self.installed.clone())
                } else {
                    Ok(self.initial_host.clone())
                }
            } else if path == self.output_path {
                self.event("fs:reopen-output");
                Ok(self.output.clone())
            } else {
                Err(XrefBoundaryError::new(format!(
                    "unexpected observed path {}",
                    path.display()
                )))
            }
        }

        fn acquire_original_host_guard(
            &mut self,
            _path: &Path,
        ) -> Result<Self::OriginalHostGuard, XrefBoundaryError> {
            self.event("guard:original-acquire");
            if self.lock_fail {
                return Err(XrefBoundaryError::new("injected lock contention"));
            }
            Ok(FakeOriginalHostGuard {
                events: self.events.clone(),
            })
        }

        fn observe_original_host(
            &mut self,
            _lock: &Self::OriginalHostGuard,
        ) -> Result<XrefFileObservation, XrefBoundaryError> {
            self.event("guard:observe-original");
            Ok(self
                .locked_observations
                .pop_front()
                .unwrap_or_else(|| self.locked_host.clone()))
        }

        fn validate_host_replacement_guard(
            &mut self,
            _lock: &Self::OriginalHostGuard,
        ) -> Result<(), XrefBoundaryError> {
            self.event("fs:validate-replacement-guard");
            if self.replacement_guarded {
                Ok(())
            } else {
                Err(XrefBoundaryError::new("injected replacement exclusion gap"))
            }
        }

        fn copy_locked_host_to_sibling(
            &mut self,
            _lock: &Self::OriginalHostGuard,
            _format: XrefHostFormat,
        ) -> Result<PathBuf, XrefBoundaryError> {
            self.event("fs:create-sibling-output");
            self.sibling_outputs_created += 1;
            Ok(self.output_path.clone())
        }

        fn create_staging_directory(&mut self) -> Result<PathBuf, XrefBoundaryError> {
            self.event("fs:create-staging");
            Ok(self.staging_path.clone())
        }

        fn capture_source(
            &mut self,
            source: &Path,
            destination: &Path,
            _expected_identity: &FilesystemIdentity,
        ) -> Result<XrefSourceCaptureEvidence, XrefSourceCaptureError> {
            self.event(format!("fs:capture-source:{}", source.display()));
            self.capture_calls += 1;
            if let Some(error) = self.source_capture_error.take() {
                return Err(error);
            }
            let evidence = self.source_evidence.pop_front().ok_or_else(|| {
                XrefSourceCaptureError::SourceRace(XrefBoundaryError::new(
                    "missing fake source evidence",
                ))
            })?;
            self.source_snapshot_observations.insert(
                destination.to_path_buf(),
                XrefFileObservation {
                    identity: evidence.snapshot_identity.clone(),
                    path_identity: evidence.snapshot_identity.clone(),
                    digest: evidence.snapshot_digest,
                },
            );
            Ok(evidence)
        }

        fn observe_source_snapshot(
            &mut self,
            path: &Path,
        ) -> Result<XrefFileObservation, XrefBoundaryError> {
            self.event(format!("fs:observe-source-snapshot:{}", path.display()));
            self.source_snapshot_observation_count += 1;
            let mut observation = self
                .source_snapshot_observations
                .get(path)
                .cloned()
                .ok_or_else(|| XrefBoundaryError::new("missing fake source snapshot"))?;
            if self.change_snapshot_after_first_observation
                && self.source_snapshot_observation_count > 1
            {
                observation.digest = fake_digest(0xff);
            }
            Ok(observation)
        }

        fn prove_exclusive_source_snapshot_resolution(
            &mut self,
            _snapshots: &[XrefSourceSnapshot],
        ) -> Result<(), XrefBoundaryError> {
            self.event("fs:prove-source-exclusion");
            Ok(())
        }

        fn materialize_profile(
            &mut self,
            _staging_directory: &Path,
            profile: &XrefIsolatedProfileDocument,
        ) -> Result<XrefMaterializedProfile, XrefBoundaryError> {
            self.event("fs:materialize-profile");
            self.materialized_profile = Some(profile.clone());
            let manifest_path = self.staging_path.join("xref-isolated-profile.json");
            let launch_path = self.staging_path.join("xref-isolated-profile.arg");
            Ok(XrefMaterializedProfile {
                launch_path: launch_path.clone(),
                artifacts: vec![manifest_path, launch_path],
            })
        }

        fn flush_file(&mut self, _path: &Path) -> Result<(), XrefBoundaryError> {
            self.event("fs:flush-output");
            if self.flush_file_fail {
                Err(XrefBoundaryError::new("injected output flush failure"))
            } else {
                Ok(())
            }
        }

        fn cleanup(&mut self, paths: &[PathBuf]) -> XrefCleanupInventory {
            self.event("fs:cleanup");
            let mut paths = paths.to_vec();
            sort_deduplicate_paths(&mut paths);
            if self.cleanup_fail && !paths.is_empty() {
                XrefCleanupInventory {
                    attempted: paths.clone(),
                    removed: Vec::new(),
                    remaining: paths,
                    engine_stop_error: None,
                }
            } else {
                XrefCleanupInventory {
                    attempted: paths.clone(),
                    removed: paths,
                    remaining: Vec::new(),
                    engine_stop_error: None,
                }
            }
        }

        fn prepare_output_guard(
            &mut self,
            _source: &Path,
            _destination: &Path,
            _original: &Self::OriginalHostGuard,
        ) -> Result<Self::PreparedOutputGuard, XrefBoundaryError> {
            self.event("guard:prepare-output");
            if self.prepare_failure {
                Err(XrefBoundaryError::new(
                    "injected prepared output guard failure",
                ))
            } else {
                Ok(FakePreparedOutputGuard {
                    events: Some(self.events.clone()),
                })
            }
        }

        fn observe_prepared_output(
            &mut self,
            _prepared: &Self::PreparedOutputGuard,
        ) -> Result<XrefFileObservation, XrefBoundaryError> {
            self.event("guard:observe-prepared");
            if self.prepared_mismatch {
                Ok(fake_observation("changed-prepared-output", 7))
            } else {
                Ok(self.output.clone())
            }
        }

        fn install_prepared_output(
            &mut self,
            prepared: Self::PreparedOutputGuard,
            _original: &Self::OriginalHostGuard,
        ) -> Result<Self::InstalledHostGuard, XrefPreparedInstallError<Self::PreparedOutputGuard>>
        {
            self.event("guard:install-output");
            match self.replace_failure {
                Some(FakeReplaceFailure::BeforeInstall) => {
                    Err(XrefPreparedInstallError::definitely_not_installed(
                        XrefBoundaryError::new("replace failed before install"),
                        prepared,
                    ))
                }
                Some(FakeReplaceFailure::AfterInstall) => {
                    self.replaced = true;
                    Err(XrefPreparedInstallError::installation_may_have_occurred(
                        XrefBoundaryError::new("replace outcome lost"),
                        prepared,
                    ))
                }
                Some(FakeReplaceFailure::AmbiguousOriginalRestored) => {
                    Err(XrefPreparedInstallError::installation_may_have_occurred(
                        XrefBoundaryError::new("replace outcome lost after original restoration"),
                        prepared,
                    ))
                }
                None => {
                    self.replaced = true;
                    let events = prepared.transition();
                    Ok(FakeInstalledHostGuard { events })
                }
            }
        }

        fn observe_installed_host(
            &mut self,
            _installed: &Self::InstalledHostGuard,
        ) -> Result<XrefFileObservation, XrefBoundaryError> {
            self.event("guard:observe-installed");
            if self.installed_mismatch {
                Ok(fake_observation("unexpected-installed", 7))
            } else {
                Ok(self.installed.clone())
            }
        }

        fn flush_directory(&mut self, _directory: &Path) -> Result<(), XrefBoundaryError> {
            self.event("fs:flush-directory");
            if self.directory_flush_fail {
                Err(XrefBoundaryError::new("injected directory flush failure"))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    enum FakeEngineFailure {
        Detect,
        Launch,
        Execute,
        Save,
        Stop,
    }

    #[derive(Debug)]
    struct FakeEngine {
        events: EventLog,
        windows: bool,
        identity: crate::engine::AutocadEngineIdentity,
        failure: Option<FakeEngineFailure>,
        failpoint: Option<XrefCertificationFailpoint>,
        failpoint_fired: bool,
        discovery_calls: usize,
        snapshot_resolution_proven: bool,
        started: bool,
        launched_host: Option<PathBuf>,
        launched_certified_autocad_arg: Vec<u8>,
        launched_search_directories: Vec<PathBuf>,
        auxiliary_artifacts: Vec<PathBuf>,
    }

    impl FakeEngine {
        fn new(events: EventLog) -> Self {
            Self {
                events,
                windows: true,
                identity: crate::engine::AutocadEngineIdentity {
                    executable: PathBuf::from("C:/AutoCAD 2026/accoreconsole.exe"),
                    product: "autocad".to_string(),
                    version: "2026".to_string(),
                },
                failure: None,
                failpoint: None,
                failpoint_fired: false,
                discovery_calls: 0,
                snapshot_resolution_proven: true,
                started: false,
                launched_host: None,
                launched_certified_autocad_arg: Vec::new(),
                launched_search_directories: Vec::new(),
                auxiliary_artifacts: Vec::new(),
            }
        }

        fn event(&self, value: impl Into<String>) {
            self.events.borrow_mut().push(value.into());
        }
    }

    impl XrefMutationEngineBoundary for FakeEngine {
        fn is_windows(&mut self) -> bool {
            self.event("engine:platform");
            self.windows
        }

        fn detect_identity(
            &mut self,
        ) -> Result<crate::engine::AutocadEngineIdentity, XrefBoundaryError> {
            self.event("engine:detect");
            self.discovery_calls += 1;
            if self.failure == Some(FakeEngineFailure::Detect) {
                Err(XrefBoundaryError::new("injected discovery failure"))
            } else {
                Ok(self.identity.clone())
            }
        }

        fn prove_exclusive_source_snapshot_resolution(
            &mut self,
            context: &XrefEngineLaunchContext<'_>,
        ) -> Result<(), XrefBoundaryError> {
            self.event("engine:prove-source-resolution");
            if self.snapshot_resolution_proven && context.source_exclusion_proven {
                Ok(())
            } else {
                Err(XrefBoundaryError::new("injected ambient source resolution"))
            }
        }

        fn launch(
            &mut self,
            context: &XrefEngineLaunchContext<'_>,
        ) -> Result<(), XrefBoundaryError> {
            self.event("engine:launch");
            self.started = true;
            self.launched_host = Some(context.temporary_host.to_path_buf());
            self.launched_certified_autocad_arg = context.certified_autocad_arg.to_vec();
            self.launched_search_directories = context.search_directories.to_vec();
            if self.failure == Some(FakeEngineFailure::Launch) {
                Err(XrefBoundaryError::new("injected launch failure"))
            } else {
                Ok(())
            }
        }

        fn execute_operation(&mut self, _script: &Path) -> Result<(), XrefBoundaryError> {
            self.event("engine:execute");
            if self.failure == Some(FakeEngineFailure::Execute) {
                Err(XrefBoundaryError::new("injected operation failure"))
            } else {
                Ok(())
            }
        }

        fn save(&mut self, _format: &XrefHostFormatFacts) -> Result<(), XrefBoundaryError> {
            self.event("engine:save");
            if self.failure == Some(FakeEngineFailure::Save) {
                Err(XrefBoundaryError::new("injected save failure"))
            } else {
                Ok(())
            }
        }

        fn auxiliary_artifacts(&self) -> Vec<PathBuf> {
            self.auxiliary_artifacts.clone()
        }

        fn stop(&mut self) -> Result<(), XrefBoundaryError> {
            self.event("engine:stop");
            self.started = false;
            if self.failure == Some(FakeEngineFailure::Stop) {
                Err(XrefBoundaryError::new("injected stop failure"))
            } else {
                Ok(())
            }
        }

        fn certification_failpoint(
            &mut self,
            failpoint: XrefCertificationFailpoint,
        ) -> Result<(), XrefBoundaryError> {
            self.event(format!("failpoint:{failpoint:?}"));
            if self.failpoint == Some(failpoint) && !self.failpoint_fired {
                self.failpoint_fired = true;
                Err(XrefBoundaryError::new(format!("injected {failpoint:?}")))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Debug)]
    struct FakeInspector {
        events: EventLog,
        host_formats: VecDeque<XrefHostFormatFacts>,
        output_format: XrefHostFormatFacts,
    }

    impl FakeInspector {
        fn new(events: EventLog) -> Self {
            Self {
                events,
                host_formats: VecDeque::from([valid_format(), valid_format()]),
                output_format: valid_format(),
            }
        }
    }

    impl XrefHostFormatInspector for FakeInspector {
        fn inspect(&mut self, path: &Path) -> Result<XrefHostFormatFacts, XrefTransactionError> {
            if path == Path::new("/drawings/host.dwg") {
                self.events.borrow_mut().push("inspect:host".to_string());
                self.host_formats.pop_front().ok_or_else(|| {
                    XrefTransactionError::new(
                        XrefTransactionErrorCode::UnsupportedFormat,
                        "missing host format observation",
                    )
                })
            } else {
                self.events.borrow_mut().push("inspect:output".to_string());
                Ok(self.output_format.clone())
            }
        }
    }

    #[derive(Debug)]
    struct FakeOperation {
        events: EventLog,
        validation_error: Option<XrefTransactionError>,
        execution_error: Option<XrefTransactionError>,
        verification_error: Option<XrefTransactionError>,
        locked_sources: Option<Vec<XrefSourceInput>>,
        response: String,
    }

    impl FakeOperation {
        fn new(events: EventLog) -> Self {
            Self {
                events,
                validation_error: None,
                execution_error: None,
                verification_error: None,
                locked_sources: None,
                response: "prebuilt-response".to_string(),
            }
        }
    }

    impl XrefMutationOperationCallback for FakeOperation {
        type Response = String;

        fn validate_locked(
            &mut self,
            context: &XrefLockedMutationContext<'_>,
        ) -> Result<(), XrefTransactionError> {
            self.events
                .borrow_mut()
                .push("operation:validate".to_string());
            assert_eq!(context.host_path, Path::new("/drawings/host.dwg"));
            assert!(context.host.is_stable());
            assert_eq!(context.format, &valid_format());
            assert!(context
                .admission
                .capability
                .operations
                .contains(&XrefMutationOperation::UpdateXref));
            match &self.validation_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }

        fn locked_source_inputs(&self) -> Option<&[XrefSourceInput]> {
            self.locked_sources.as_deref()
        }

        fn execute(
            &mut self,
            engine: &mut dyn XrefMutationEngineBoundary,
            context: &XrefOperationContext<'_>,
        ) -> Result<Vec<PathBuf>, XrefTransactionError> {
            self.events
                .borrow_mut()
                .push("operation:callback".to_string());
            if let Some(error) = &self.execution_error {
                return Err(error.clone());
            }
            let script = context.staging_directory.join("operation.lsp");
            engine.execute_operation(&script).map_err(|error| {
                XrefTransactionError::new(
                    XrefTransactionErrorCode::WriteFailed,
                    format!("execute fake operation: {error}"),
                )
            })?;
            Ok(vec![script])
        }

        fn verify(
            &mut self,
            _context: &XrefVerificationContext<'_>,
        ) -> Result<Self::Response, XrefTransactionError> {
            self.events
                .borrow_mut()
                .push("operation:verify".to_string());
            match &self.verification_error {
                Some(error) => Err(error.clone()),
                None => Ok(self.response.clone()),
            }
        }
    }

    #[derive(Debug)]
    struct TransactionFixture {
        events: EventLog,
        request: XrefTransactionRequest,
        file_system: FakeFileSystem,
        engine: FakeEngine,
        inspector: FakeInspector,
        operation: FakeOperation,
    }

    impl TransactionFixture {
        fn new() -> Self {
            let events = Rc::new(RefCell::new(Vec::new()));
            let file_system = FakeFileSystem::new(events.clone());
            Self {
                request: XrefTransactionRequest {
                    host_path: file_system.host_path.clone(),
                    operation: XrefMutationOperation::UpdateXref,
                    sources: vec![XrefSourceInput {
                        source_id: "root-source".to_string(),
                        path: PathBuf::from("/sources/root.dwg"),
                        saved_path: "root.dwg".to_string(),
                        immediate_host_source_id: None,
                        filesystem_identity: fake_source_identity("source-a"),
                        identity_provenance: XrefSourceIdentityProvenance::LockedGraphTraversal,
                        inspected_digest_sha256: Some(fake_digest(9).hex()),
                    }],
                    profile: XrefIsolatedProfileSpec {
                        certified_autocad_arg: b"certified-arg-profile".to_vec(),
                        ..XrefIsolatedProfileSpec::default()
                    },
                },
                file_system,
                engine: FakeEngine::new(events.clone()),
                inspector: FakeInspector::new(events.clone()),
                operation: FakeOperation::new(events.clone()),
                events,
            }
        }

        fn run(&mut self) -> Result<XrefTransactionOutcome<String>, XrefTransactionError> {
            execute_xref_mutation_transaction(
                &self.request,
                &mut self.file_system,
                &mut self.engine,
                &mut self.inspector,
                &mut self.operation,
            )
        }

        fn events(&self) -> Vec<String> {
            self.events.borrow().clone()
        }
    }

    fn event_position(events: &[String], event: &str) -> usize {
        events
            .iter()
            .position(|candidate| candidate == event)
            .unwrap_or_else(|| panic!("missing event '{event}' in {events:?}"))
    }

    fn last_event_position(events: &[String], event: &str) -> usize {
        events
            .iter()
            .rposition(|candidate| candidate == event)
            .unwrap_or_else(|| panic!("missing event '{event}' in {events:?}"))
    }

    #[test]
    fn transaction_success_transitions_original_to_prepared_to_installed_guards() {
        let mut fixture = TransactionFixture::new();
        let outcome = fixture.run().unwrap();
        assert_eq!(outcome.response, "prebuilt-response");
        assert_eq!(outcome.row_id, "dwg-ac1032-xref-v2");
        assert_eq!(outcome.source_snapshots.len(), 1);
        assert!(outcome.cleanup.is_clean());
        assert!(outcome.cleanup.attempted.contains(
            &fixture
                .file_system
                .staging_path
                .join("xref-isolated-profile.json")
        ));
        assert!(outcome.cleanup.attempted.contains(
            &fixture
                .file_system
                .staging_path
                .join("xref-isolated-profile.arg")
        ));
        assert_eq!(fixture.file_system.sibling_outputs_created, 1);
        assert_eq!(
            fixture.engine.launched_host.as_deref(),
            Some(fixture.file_system.output_path.as_path())
        );
        assert_ne!(
            fixture.engine.launched_host.as_deref(),
            Some(fixture.file_system.host_path.as_path())
        );
        assert_eq!(
            fixture.engine.launched_certified_autocad_arg,
            b"certified-arg-profile"
        );
        assert_eq!(fixture.engine.launched_search_directories.len(), 1);
        assert!(fixture.engine.launched_search_directories[0]
            .starts_with(&fixture.file_system.staging_path));

        let events = fixture.events();
        for pair in [
            ("inspect:host", "engine:platform"),
            ("engine:platform", "engine:detect"),
            ("engine:detect", "guard:original-acquire"),
            ("guard:original-acquire", "guard:observe-original"),
            ("guard:observe-original", "fs:validate-replacement-guard"),
            ("fs:validate-replacement-guard", "operation:validate"),
            ("operation:validate", "fs:create-sibling-output"),
            (
                "fs:create-sibling-output",
                "fs:capture-source:/sources/root.dwg",
            ),
            (
                "fs:capture-source:/sources/root.dwg",
                "fs:materialize-profile",
            ),
            ("fs:materialize-profile", "fs:prove-source-exclusion"),
            (
                "fs:prove-source-exclusion",
                "engine:prove-source-resolution",
            ),
            ("engine:prove-source-resolution", "engine:launch"),
            ("engine:launch", "operation:callback"),
            ("operation:callback", "engine:execute"),
            ("engine:execute", "engine:save"),
            ("engine:save", "fs:flush-output"),
            ("fs:flush-output", "fs:reopen-output"),
            ("fs:reopen-output", "operation:verify"),
            ("operation:verify", "engine:stop"),
            ("engine:stop", "guard:prepare-output"),
            ("guard:prepare-output", "guard:observe-prepared"),
            ("guard:observe-prepared", "fs:cleanup"),
            ("fs:cleanup", "guard:install-output"),
            ("guard:install-output", "guard:prepared-transition"),
            ("guard:prepared-transition", "fs:flush-directory"),
            ("fs:flush-directory", "guard:observe-installed"),
            ("guard:observe-installed", "guard:installed-release"),
            ("guard:installed-release", "guard:original-release"),
        ] {
            assert!(
                event_position(&events, pair.0) < event_position(&events, pair.1),
                "out-of-order {:?} in {events:?}",
                pair
            );
        }
    }

    #[test]
    fn total_precedence_is_format_then_platform_then_engine_without_launch() {
        let mut invalid_format = TransactionFixture::new();
        invalid_format.inspector.host_formats[0].drawing_version = "AC1027".to_string();
        invalid_format.engine.windows = false;
        invalid_format.engine.failure = Some(FakeEngineFailure::Detect);
        let error = invalid_format.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::UnsupportedFormat);
        assert_eq!(invalid_format.engine.discovery_calls, 0);
        assert!(!invalid_format
            .events()
            .contains(&"engine:platform".to_string()));

        let mut unsupported_platform = TransactionFixture::new();
        unsupported_platform.engine.windows = false;
        unsupported_platform.engine.failure = Some(FakeEngineFailure::Detect);
        let error = unsupported_platform.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::UnsupportedPlatform);
        assert!(error.detail.contains("update_xref"));
        assert!(error.detail.contains("DWG AC1032"));
        assert!(error.detail.contains("current_platform="));
        assert!(error.detail.contains("required_engine="));
        assert!(error.detail.contains("recovery="));
        assert_eq!(unsupported_platform.engine.discovery_calls, 0);
        assert!(!unsupported_platform
            .events()
            .contains(&"engine:detect".to_string()));

        let mut missing_engine = TransactionFixture::new();
        missing_engine.engine.failure = Some(FakeEngineFailure::Detect);
        let error = missing_engine.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::AutocadUnavailable);
        assert_eq!(missing_engine.engine.discovery_calls, 1);
        assert!(!missing_engine
            .events()
            .contains(&"guard:original-acquire".to_string()));
        assert!(!missing_engine
            .events()
            .contains(&"engine:launch".to_string()));

        let mut locked = TransactionFixture::new();
        locked.file_system.lock_fail = true;
        let error = locked.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::DrawingLocked);
        assert!(locked.events().contains(&"engine:detect".to_string()));
        assert!(!locked.events().contains(&"fs:observe-locked".to_string()));
    }

    #[test]
    fn unsupported_format_admission_explains_admitted_formats_and_recovery() {
        let registry = embedded_xref_artifacts().unwrap();
        let error = validate_format_only_admission(
            registry,
            &XrefHostFormatFacts {
                host_format: XrefHostFormat::Dxf,
                drawing_version: "AC1027".to_string(),
                dxf_form: XrefDxfForm::Ascii,
                code_page: Some("ANSI_1252".to_string()),
            },
            XrefMutationOperation::AttachXref,
        )
        .expect_err("AC1027 is outside the admitted XREF mutation formats");

        assert_eq!(error.code, XrefTransactionErrorCode::UnsupportedFormat);
        assert!(error
            .detail
            .contains("attach_xref is not admitted for detected host format"));
        assert!(error
            .detail
            .contains("DXF AC1027 ASCII (code page ANSI_1252)"));
        assert!(error
            .detail
            .contains("DXF AC1032 ASCII (code page ANSI_1252)"));
        assert!(error.detail.contains("recovery="));
        assert!(!error.detail.contains("capability row"));
        assert!(!error.detail.contains("format-only"));
    }

    #[test]
    fn capability_row_is_engine_version_neutral_under_lock() {
        let mut fixture = TransactionFixture::new();
        fixture.engine.identity.version = "2025".to_string();
        let outcome = fixture.run().unwrap();
        assert_eq!(outcome.row_id, "dwg-ac1032-xref-v2");
        let events = fixture.events();
        assert!(events.contains(&"guard:original-acquire".to_string()));
        assert!(events.contains(&"guard:original-release".to_string()));
        assert!(events.contains(&"operation:validate".to_string()));
    }

    #[test]
    fn locked_snapshot_revalidation_precedes_guards_and_temporary_output() {
        let mut changed = TransactionFixture::new();
        changed
            .file_system
            .locked_observations
            .push_back(fake_observation("replacement-host", 1));
        let error = changed.run().unwrap_err();
        assert_eq!(
            error.code,
            XrefTransactionErrorCode::ConcurrentDrawingModification
        );
        assert!(changed.events().contains(&"engine:detect".to_string()));
        assert!(!changed.events().contains(&"engine:launch".to_string()));
        assert!(!changed
            .events()
            .contains(&"fs:materialize-profile".to_string()));
        assert!(!changed.events().contains(&"operation:validate".to_string()));
        assert_eq!(changed.file_system.sibling_outputs_created, 0);

        let mut guard_failure = TransactionFixture::new();
        guard_failure.operation.validation_error = Some(XrefTransactionError::new(
            XrefTransactionErrorCode::Domain("expected_name_mismatch".to_string()),
            "guard mismatch",
        ));
        let error = guard_failure.run().unwrap_err();
        assert_eq!(
            error.code,
            XrefTransactionErrorCode::Domain("expected_name_mismatch".to_string())
        );
        assert!(!guard_failure
            .events()
            .contains(&"fs:create-sibling-output".to_string()));
        assert_eq!(guard_failure.file_system.capture_calls, 0);
    }

    #[test]
    fn source_snapshots_preserve_graph_relative_mapping_in_isolated_profile() {
        let mut fixture = TransactionFixture::new();
        fixture.request.sources.push(XrefSourceInput {
            source_id: "nested-source".to_string(),
            path: PathBuf::from("/sources/nested.dwg"),
            saved_path: "nested.dwg".to_string(),
            immediate_host_source_id: Some("root-source".to_string()),
            filesystem_identity: fake_source_identity("source-b"),
            identity_provenance: XrefSourceIdentityProvenance::LockedGraphTraversal,
            inspected_digest_sha256: Some(fake_digest(10).hex()),
        });
        fixture
            .file_system
            .source_evidence
            .push_back(stable_source_evidence("source-b", 10));

        let outcome = fixture.run().unwrap();
        assert_eq!(outcome.source_snapshots.len(), 2);
        assert_eq!(
            outcome.source_snapshots[1]
                .immediate_host_source_id
                .as_deref(),
            Some("root-source")
        );
        assert!(outcome.source_snapshots.iter().all(|snapshot| snapshot
            .snapshot_path
            .starts_with(&fixture.file_system.staging_path)));
        let profile = fixture.file_system.materialized_profile.as_ref().unwrap();
        assert_eq!(profile.source_snapshots, outcome.source_snapshots);
        assert_eq!(profile.search_directories.len(), 1);
        assert!(profile.search_directories[0].starts_with(&fixture.file_system.staging_path));
    }

    #[test]
    fn source_change_and_change_back_cannot_pass_snapshot_digest_proof() {
        let mut fixture = TransactionFixture::new();
        let mut evidence = stable_source_evidence("source-a", 9);
        evidence.snapshot_digest = fake_digest(8);
        fixture.file_system.source_evidence = VecDeque::from([evidence]);
        let error = fixture.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::XrefSourceChanged);
        assert!(!fixture.events().contains(&"engine:launch".to_string()));
        assert!(!error.cleanup.attempted.is_empty());
    }

    #[test]
    fn in_place_source_edit_after_graph_inspection_fails_digest_binding() {
        let mut fixture = TransactionFixture::new();
        fixture.file_system.source_evidence =
            VecDeque::from([stable_source_evidence("source-a", 8)]);
        let error = fixture.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::XrefSourceChanged);
        assert!(!fixture.events().contains(&"engine:launch".to_string()));
    }

    #[test]
    fn guarded_snapshot_digest_change_after_engine_use_blocks_commit() {
        let mut fixture = TransactionFixture::new();
        fixture.file_system.change_snapshot_after_first_observation = true;
        let error = fixture.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::VerificationFailed);
        assert!(fixture.events().contains(&"engine:stop".to_string()));
        assert!(!fixture.file_system.replaced);
    }

    #[test]
    fn source_identity_change_is_detected_but_later_edits_are_linearized_after_capture() {
        let mut changed = TransactionFixture::new();
        let mut evidence = stable_source_evidence("source-a", 9);
        evidence.path_identity_after = fake_source_identity("source-replaced");
        changed.file_system.source_evidence = VecDeque::from([evidence]);
        let error = changed.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::XrefSourceChanged);

        let mut later_edit = TransactionFixture::new();
        let outcome = later_edit.run().unwrap();
        assert_eq!(
            outcome.source_snapshots[0].digest_sha256,
            fake_digest(9).hex()
        );
        assert_eq!(later_edit.file_system.capture_calls, 1);
        assert_eq!(
            later_edit
                .events()
                .iter()
                .filter(|event| event.starts_with("fs:capture-source:"))
                .count(),
            1,
            "sources must not be reread after the immutable snapshot linearization point"
        );
    }

    #[test]
    fn staging_create_write_and_flush_failures_are_write_failed_not_source_changed() {
        for detail in [
            "injected snapshot create failure",
            "injected snapshot write failure",
            "injected snapshot flush failure",
        ] {
            let mut fixture = TransactionFixture::new();
            fixture.file_system.source_capture_error = Some(XrefSourceCaptureError::Staging(
                XrefBoundaryError::new(detail),
            ));
            let error = fixture.run().unwrap_err();
            assert_eq!(error.code, XrefTransactionErrorCode::WriteFailed);
            assert!(error.detail.contains(detail));
            assert!(!fixture.events().contains(&"engine:launch".to_string()));
        }
    }

    #[test]
    fn source_io_failure_is_unreadable_not_a_proven_source_race() {
        let mut fixture = TransactionFixture::new();
        fixture.file_system.source_capture_error = Some(XrefSourceCaptureError::SourceUnreadable(
            XrefBoundaryError::new("injected source read failure"),
        ));
        let error = fixture.run().unwrap_err();
        assert_eq!(
            error.code,
            XrefTransactionErrorCode::Domain("xref_source_unreadable".to_string())
        );
        assert!(error.detail.contains("injected source read failure"));
        assert!(!fixture.events().contains(&"engine:launch".to_string()));
    }

    #[test]
    fn unproven_snapshot_resolution_fails_before_engine_launch() {
        let mut fixture = TransactionFixture::new();
        fixture.engine.snapshot_resolution_proven = false;
        let error = fixture.run().unwrap_err();
        assert_eq!(
            error.code,
            XrefTransactionErrorCode::Domain("unsupported_xref_source".to_string())
        );
        assert!(fixture
            .events()
            .contains(&"engine:prove-source-resolution".to_string()));
        assert!(!fixture.events().contains(&"engine:launch".to_string()));
    }

    #[test]
    fn unguarded_replacement_boundary_fails_before_mutation_or_launch() {
        let mut fixture = TransactionFixture::new();
        fixture.file_system.replacement_guarded = false;
        let error = fixture.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::UnsupportedPlatform);
        assert!(error.detail.contains("update_xref"));
        assert!(error.detail.contains("DWG AC1032"));
        assert!(error.detail.contains("current_platform="));
        assert!(error.detail.contains("required_engine="));
        assert!(error.detail.contains("host replacement"));
        assert!(error.detail.contains("recovery="));
        assert!(!fixture.events().contains(&"operation:validate".to_string()));
        assert!(!fixture.events().contains(&"engine:launch".to_string()));
        assert!(!fixture.file_system.replaced);
    }

    #[test]
    fn path_observed_identity_fails_closed_without_locked_graph_upgrade() {
        let mut fixture = TransactionFixture::new();
        fixture.request.sources[0].identity_provenance =
            XrefSourceIdentityProvenance::PathObservation;
        let error = fixture.run().unwrap_err();
        assert_eq!(
            error.code,
            XrefTransactionErrorCode::Domain("unsupported_xref_source".to_string())
        );
        assert_eq!(fixture.file_system.sibling_outputs_created, 0);
        assert_eq!(fixture.file_system.capture_calls, 0);
        assert!(!fixture.events().contains(&"engine:launch".to_string()));
    }

    #[test]
    fn locked_callback_source_identity_upgrade_is_used_by_transaction() {
        let mut fixture = TransactionFixture::new();
        let locked_sources = fixture.request.sources.clone();
        fixture.request.sources[0].identity_provenance =
            XrefSourceIdentityProvenance::PathObservation;
        fixture.operation.locked_sources = Some(locked_sources);

        let outcome = fixture.run().unwrap();
        assert_eq!(outcome.source_snapshots.len(), 1);
        assert_eq!(fixture.file_system.capture_calls, 1);
        assert!(fixture.events().contains(&"engine:launch".to_string()));
    }

    #[test]
    fn digest_bound_prelock_graph_is_admitted_against_locked_host_version() {
        let mut fixture = TransactionFixture::new();
        fixture.request.sources[0].identity_provenance =
            XrefSourceIdentityProvenance::DigestBoundGraphTraversal;
        let outcome = fixture.run().unwrap();
        assert_eq!(outcome.source_snapshots.len(), 1);
        assert!(fixture.events().contains(&"engine:launch".to_string()));
    }

    #[test]
    fn windows_transaction_share_policy_blocks_competing_writes_and_replacement() {
        assert!(windows_host_lock_blocks_competing_write(
            WINDOWS_HOST_LOCK_SHARE_MODE
        ));
        assert!(windows_host_lock_blocks_competing_delete(
            WINDOWS_HOST_LOCK_SHARE_MODE
        ));
        assert!(windows_host_lock_blocks_competing_write(
            WINDOWS_PREPARED_LOCK_SHARE_MODE
        ));
        assert!(windows_host_lock_blocks_competing_delete(
            WINDOWS_PREPARED_LOCK_SHARE_MODE
        ));
    }

    #[test]
    fn production_engine_fails_closed_for_source_snapshots_before_session_launch() {
        let staging = PathBuf::from("C:/isolated/xref-transaction");
        let profile = staging.join("xref-isolated-profile.arg");
        let snapshot_path = staging.join("sources/root.dwg");
        let search_directories = vec![snapshot_path.parent().unwrap().to_path_buf()];
        let snapshots = vec![XrefSourceSnapshot {
            source_id: "root".to_owned(),
            original_path: PathBuf::from("C:/drawings/root.dwg"),
            saved_path: "root.dwg".to_owned(),
            immediate_host_source_id: None,
            snapshot_path,
            original_identity: "source".to_owned(),
            filesystem_identity: fake_source_identity("source"),
            snapshot_identity: XrefFileIdentity::fake("snapshot"),
            digest_sha256: fake_digest(9).hex(),
        }];
        let context = XrefEngineLaunchContext {
            temporary_host: Path::new("C:/drawings/.xref-output.dwg"),
            staging_directory: &staging,
            profile_path: &profile,
            certified_autocad_arg: b"certified-arg-profile",
            search_directories: &search_directories,
            source_snapshots: &snapshots,
            source_exclusion_proven: false,
        };
        let mut engine = AccoreconsoleXrefMutationEngine::new();

        let error = engine
            .prove_exclusive_source_snapshot_resolution(&context)
            .unwrap_err();
        assert!(error.to_string().contains("were not exclusively denied"));
        assert!(engine.session.is_none());
    }

    #[test]
    fn production_engine_uses_the_selected_activation_without_rediscovery() {
        let target = crate::activation::embedded_activation_catalogue()
            .unwrap()
            .target("autocad-2026-r25-1-en-us-preview-v1")
            .unwrap()
            .clone();
        let executable = PathBuf::from("C:/Program Files/Autodesk/AutoCAD 2026/accoreconsole.exe");
        let selected = Arc::new(SelectedActivation {
            candidate: crate::activation::InstalledCandidate {
                canonical_id: "registered-autocad-2026".to_string(),
                executable: executable.clone(),
                product: target.product.as_str().to_string(),
                edition: target.edition.as_str().to_string(),
                architecture: target.architecture.as_str().to_string(),
                release_year: target.release_year,
                registry_family: target.registry_family.clone(),
                product_language_key: target.product_language_key.clone(),
                ui_locale: target.ui_locale.clone(),
            },
            engine_identity: crate::activation::VerifiedEngineIdentity {
                canonical_executable: executable.clone(),
                identity_token: "selected-file-identity".to_string(),
            },
            launch_guard: None,
            target,
        });
        let profile_bytes = selected.target.profile.arg_bytes().to_vec();
        let staging = PathBuf::from("C:/isolated/xref-transaction");
        let profile = staging.join("xref-isolated-profile.arg");
        let search_directories = Vec::new();
        let snapshots = Vec::new();
        let context = XrefEngineLaunchContext {
            temporary_host: Path::new("C:/drawings/.xref-output.dwg"),
            staging_directory: &staging,
            profile_path: &profile,
            certified_autocad_arg: &profile_bytes,
            search_directories: &search_directories,
            source_snapshots: &snapshots,
            source_exclusion_proven: true,
        };
        let mut engine =
            AccoreconsoleXrefMutationEngine::with_selected_activation(Arc::clone(&selected));

        let identity = engine.detect_identity().unwrap();
        assert_eq!(identity.executable, executable);
        assert_eq!(identity.product, "autocad");
        assert_eq!(identity.version, "2026");
        engine.launch(&context).unwrap();
        assert_eq!(
            engine
                .selected_activation
                .as_ref()
                .unwrap()
                .target
                .profile
                .arg_sha256,
            selected.target.profile.arg_sha256
        );
        assert_eq!(
            engine
                .selected_activation
                .as_ref()
                .unwrap()
                .target
                .ui_locale,
            "en-US"
        );
        assert_eq!(
            engine.session.as_ref().unwrap().certified_autocad_arg,
            profile_bytes
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_native_semantic_transactional_install_is_atomic_and_guarded() {
        use std::os::windows::fs::OpenOptionsExt;

        let directory = tempfile::tempdir().unwrap();
        let host = directory.path().join("host.dwg");
        let output = directory.path().join("output.dwg");
        fs::write(&host, b"original-host").unwrap();
        fs::write(&output, b"replacement-host").unwrap();

        let mut file_system = ProductionXrefFileSystem::default();
        let lock = file_system.acquire_original_host_guard(&host).unwrap();
        let original_observation = file_system.observe_original_host(&lock).unwrap();
        file_system.validate_host_replacement_guard(&lock).unwrap();
        let prepared = file_system
            .prepare_output_guard(&output, &host, &lock)
            .unwrap();
        let prepared_observation = file_system.observe_prepared_output(&prepared).unwrap();

        let competing_write = OpenOptions::new()
            .write(true)
            .share_mode(
                windows_primitives::FILE_SHARE_READ
                    | windows_primitives::FILE_SHARE_WRITE
                    | windows_primitives::FILE_SHARE_DELETE,
            )
            .open(&host);
        assert!(competing_write.is_err());
        assert!(fs::remove_file(&host).is_err());
        let competing_prepared_write = OpenOptions::new()
            .write(true)
            .share_mode(
                windows_primitives::FILE_SHARE_READ
                    | windows_primitives::FILE_SHARE_WRITE
                    | windows_primitives::FILE_SHARE_DELETE,
            )
            .open(&output);
        assert!(competing_prepared_write.is_err());
        assert!(
            fs::remove_file(&output).is_err(),
            "the retained no-share prepared handle must exclude an outside delete"
        );
        assert_eq!(fs::read(&host).unwrap(), b"original-host");

        let installed = file_system
            .install_prepared_output(prepared, &lock)
            .unwrap();
        let installed_observation = file_system.observe_installed_host(&installed).unwrap();
        assert_eq!(
            installed_observation.identity,
            original_observation.identity
        );
        assert_eq!(installed_observation.digest, prepared_observation.digest);
        let competing_installed_write = OpenOptions::new()
            .write(true)
            .share_mode(
                windows_primitives::FILE_SHARE_READ
                    | windows_primitives::FILE_SHARE_WRITE
                    | windows_primitives::FILE_SHARE_DELETE,
            )
            .open(&host);
        assert!(
            competing_installed_write.is_err(),
            "the installed guard must exclude an outside write"
        );
        assert!(fs::remove_file(&host).is_err());
        assert_eq!(fs::read(&host).unwrap(), b"replacement-host");
        assert!(!output.exists());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_native_semantic_source_snapshot_excludes_every_original_path_read() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.dwg");
        let staging = directory.path().join("staging");
        let snapshot_path = staging.join("sources/source.dwg");
        fs::write(&source, b"immutable-source").unwrap();
        let source_identity = observe_xref_source_identity(&source).unwrap();

        let mut file_system = ProductionXrefFileSystem::default();
        let evidence = file_system
            .capture_source(&source, &snapshot_path, &source_identity)
            .unwrap();
        let snapshot = XrefSourceSnapshot {
            source_id: "source".to_owned(),
            original_path: source.clone(),
            saved_path: "source.dwg".to_owned(),
            immediate_host_source_id: None,
            snapshot_path: snapshot_path.clone(),
            original_identity: format!("{source_identity:?}"),
            filesystem_identity: source_identity,
            snapshot_identity: evidence.snapshot_identity,
            digest_sha256: evidence.snapshot_digest.hex(),
        };

        file_system
            .prove_exclusive_source_snapshot_resolution(std::slice::from_ref(&snapshot))
            .unwrap();
        assert!(
            File::open(&source).is_err(),
            "the retained source guard must deny accoreconsole's original-path read"
        );
        assert_eq!(fs::read(&snapshot_path).unwrap(), b"immutable-source");

        let cleanup = file_system.cleanup(&[staging]);
        assert!(cleanup.is_clean());
        assert_eq!(fs::read(&source).unwrap(), b"immutable-source");
    }

    #[test]
    fn failure_epilogue_prioritizes_host_then_source_then_underlying_failure() {
        let changed_host = fake_observation("host", 3);
        let mut host_race = TransactionFixture::new();
        host_race.engine.failure = Some(FakeEngineFailure::Save);
        host_race.file_system.locked_observations = VecDeque::from([
            host_race.file_system.locked_host.clone(),
            changed_host.clone(),
            changed_host.clone(),
        ]);
        let error = host_race.run().unwrap_err();
        assert_eq!(
            error.code,
            XrefTransactionErrorCode::ConcurrentDrawingModification
        );

        let mut source_race = TransactionFixture::new();
        let mut evidence = stable_source_evidence("source-a", 9);
        evidence.snapshot_digest = fake_digest(4);
        source_race.file_system.source_evidence = VecDeque::from([evidence]);
        let error = source_race.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::XrefSourceChanged);

        let mut verification_with_cleanup_failure = TransactionFixture::new();
        verification_with_cleanup_failure
            .operation
            .verification_error = Some(XrefTransactionError::new(
            XrefTransactionErrorCode::Domain("unexpected".to_string()),
            "persisted invariant failed",
        ));
        verification_with_cleanup_failure.file_system.cleanup_fail = true;
        let error = verification_with_cleanup_failure.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::VerificationFailed);
        assert!(!error.cleanup.remaining.is_empty());
    }

    #[test]
    fn every_certification_failpoint_has_the_exact_commit_boundary_code() {
        let cases = [
            (
                XrefCertificationFailpoint::DuringSourceSnapshot,
                XrefTransactionErrorCode::XrefSourceChanged,
            ),
            (
                XrefCertificationFailpoint::BeforeSave,
                XrefTransactionErrorCode::WriteFailed,
            ),
            (
                XrefCertificationFailpoint::AfterSave,
                XrefTransactionErrorCode::WriteFailed,
            ),
            (
                XrefCertificationFailpoint::BeforeVerification,
                XrefTransactionErrorCode::VerificationFailed,
            ),
            (
                XrefCertificationFailpoint::AfterVerification,
                XrefTransactionErrorCode::VerificationFailed,
            ),
            (
                XrefCertificationFailpoint::BeforeCleanup,
                XrefTransactionErrorCode::WriteFailed,
            ),
            (
                XrefCertificationFailpoint::AfterCleanup,
                XrefTransactionErrorCode::WriteFailed,
            ),
            (
                XrefCertificationFailpoint::BeforeHostRecheck,
                XrefTransactionErrorCode::WriteFailed,
            ),
            (
                XrefCertificationFailpoint::AfterHostRecheck,
                XrefTransactionErrorCode::WriteFailed,
            ),
            (
                XrefCertificationFailpoint::BeforeReplace,
                XrefTransactionErrorCode::WriteFailed,
            ),
            (
                XrefCertificationFailpoint::AfterReplace,
                XrefTransactionErrorCode::MutationStateUnknown,
            ),
            (
                XrefCertificationFailpoint::BeforeDirectoryFlush,
                XrefTransactionErrorCode::MutationStateUnknown,
            ),
            (
                XrefCertificationFailpoint::AfterDirectoryFlush,
                XrefTransactionErrorCode::MutationStateUnknown,
            ),
            (
                XrefCertificationFailpoint::BeforeInstalledDigestCheck,
                XrefTransactionErrorCode::MutationStateUnknown,
            ),
        ];

        for (failpoint, expected) in cases {
            let mut fixture = TransactionFixture::new();
            fixture.engine.failpoint = Some(failpoint);
            let error = fixture.run().unwrap_err();
            assert_eq!(error.code, expected, "failpoint {failpoint:?}: {error}");
            assert!(fixture
                .events()
                .contains(&"guard:original-release".to_string()));
            if expected == XrefTransactionErrorCode::MutationStateUnknown {
                assert!(fixture.file_system.replaced);
            } else {
                assert!(!fixture.file_system.replaced);
            }
        }
    }

    #[test]
    fn write_verification_cleanup_and_stop_failures_are_proven_precommit() {
        let mut launch = TransactionFixture::new();
        launch.engine.failure = Some(FakeEngineFailure::Launch);
        assert_eq!(
            launch.run().unwrap_err().code,
            XrefTransactionErrorCode::AutocadUnavailable
        );

        let mut save = TransactionFixture::new();
        save.engine.failure = Some(FakeEngineFailure::Save);
        assert_eq!(
            save.run().unwrap_err().code,
            XrefTransactionErrorCode::WriteFailed
        );

        let mut execute = TransactionFixture::new();
        execute.engine.failure = Some(FakeEngineFailure::Execute);
        let engine_artifact = execute
            .file_system
            .staging_path
            .join("engine-known-operation.lsp");
        execute.engine.auxiliary_artifacts = vec![engine_artifact.clone()];
        let error = execute.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::WriteFailed);
        assert!(error.cleanup.attempted.contains(&engine_artifact));

        let mut flush = TransactionFixture::new();
        flush.file_system.flush_file_fail = true;
        assert_eq!(
            flush.run().unwrap_err().code,
            XrefTransactionErrorCode::WriteFailed
        );

        let mut verification = TransactionFixture::new();
        verification.operation.verification_error = Some(XrefTransactionError::new(
            XrefTransactionErrorCode::Domain("bad_projection".to_string()),
            "bad persisted projection",
        ));
        assert_eq!(
            verification.run().unwrap_err().code,
            XrefTransactionErrorCode::VerificationFailed
        );

        let mut cleanup = TransactionFixture::new();
        cleanup.file_system.cleanup_fail = true;
        let error = cleanup.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::WriteFailed);
        assert!(!error.cleanup.remaining.is_empty());

        let mut stop = TransactionFixture::new();
        stop.engine.failure = Some(FakeEngineFailure::Stop);
        let error = stop.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::WriteFailed);
        assert!(error.cleanup.engine_stop_error.is_some());
    }

    #[test]
    fn atomic_replace_failure_is_write_failed_only_when_original_is_proven_unchanged() {
        let mut unchanged = TransactionFixture::new();
        unchanged.file_system.replace_failure = Some(FakeReplaceFailure::BeforeInstall);
        let error = unchanged.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::WriteFailed);
        assert!(!unchanged.file_system.replaced);
        let events = unchanged.events();
        assert!(
            event_position(&events, "guard:install-output")
                < last_event_position(&events, "guard:observe-original")
        );
        assert!(
            last_event_position(&events, "guard:observe-original")
                < last_event_position(&events, "fs:observe-host")
        );
        assert!(
            last_event_position(&events, "fs:observe-host")
                < event_position(&events, "guard:prepared-release")
        );
        assert!(
            event_position(&events, "guard:prepared-release")
                < last_event_position(&events, "fs:cleanup")
        );
        assert!(!events.contains(&"guard:prepared-transition".to_string()));
        assert!(!events.contains(&"guard:installed-release".to_string()));

        let mut uncertain = TransactionFixture::new();
        uncertain.file_system.replace_failure = Some(FakeReplaceFailure::AfterInstall);
        let error = uncertain.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::MutationStateUnknown);
        assert!(uncertain.file_system.replaced);
        let events = uncertain.events();
        assert!(
            event_position(&events, "guard:install-output")
                < event_position(&events, "fs:observe-installed")
        );
        assert!(
            event_position(&events, "fs:observe-installed")
                < event_position(&events, "guard:prepared-release")
        );
        assert!(!events.contains(&"guard:prepared-transition".to_string()));
        assert!(!events.contains(&"guard:installed-release".to_string()));

        let mut restored = TransactionFixture::new();
        restored.file_system.replace_failure = Some(FakeReplaceFailure::AmbiguousOriginalRestored);
        let error = restored.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::MutationStateUnknown);
        assert!(!restored.file_system.replaced);
        let events = restored.events();
        assert!(
            last_event_position(&events, "guard:observe-original")
                < last_event_position(&events, "fs:observe-host")
        );
        assert!(
            last_event_position(&events, "fs:observe-host")
                < event_position(&events, "guard:prepared-release")
        );
    }

    #[test]
    fn prepared_output_guard_failure_is_verification_failed_before_cleanup() {
        let mut fixture = TransactionFixture::new();
        fixture.file_system.prepare_failure = true;

        let error = fixture.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::VerificationFailed);
        assert!(!fixture.file_system.replaced);
        let events = fixture.events();
        assert!(events.contains(&"guard:prepare-output".to_string()));
        assert!(!events.contains(&"guard:observe-prepared".to_string()));
        assert!(!events.contains(&"guard:install-output".to_string()));
        assert!(
            last_event_position(&events, "fs:cleanup")
                < event_position(&events, "guard:original-release")
        );
    }

    #[test]
    fn changed_prepared_output_releases_its_guard_before_failure_cleanup() {
        let mut fixture = TransactionFixture::new();
        fixture.file_system.prepared_mismatch = true;

        let error = fixture.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::VerificationFailed);
        assert!(!fixture.file_system.replaced);
        let events = fixture.events();
        assert!(
            event_position(&events, "guard:observe-prepared")
                < event_position(&events, "guard:prepared-release")
        );
        assert!(
            event_position(&events, "guard:prepared-release")
                < last_event_position(&events, "fs:cleanup")
        );
        assert!(
            last_event_position(&events, "fs:cleanup")
                < event_position(&events, "guard:original-release")
        );
        assert!(!events.contains(&"guard:install-output".to_string()));
    }

    #[test]
    fn preinstall_failpoint_drops_prepared_guard_before_epilogue_but_retains_original() {
        let mut fixture = TransactionFixture::new();
        fixture.engine.failpoint = Some(XrefCertificationFailpoint::BeforeReplace);

        let error = fixture.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::WriteFailed);
        assert!(!fixture.file_system.replaced);
        let events = fixture.events();
        assert!(
            event_position(&events, "failpoint:BeforeReplace")
                < event_position(&events, "guard:prepared-release")
        );
        assert!(
            event_position(&events, "guard:prepared-release")
                < last_event_position(&events, "fs:cleanup")
        );
        assert!(
            last_event_position(&events, "guard:observe-original")
                < event_position(&events, "guard:original-release")
        );
        assert!(!events.contains(&"guard:installed-release".to_string()));
    }

    #[test]
    fn post_replace_durability_or_installed_digest_failure_is_mutation_state_unknown() {
        let mut directory_flush = TransactionFixture::new();
        directory_flush.file_system.directory_flush_fail = true;
        let error = directory_flush.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::MutationStateUnknown);
        let events = directory_flush.events();
        assert!(
            event_position(&events, "guard:prepared-transition")
                < event_position(&events, "fs:flush-directory")
        );
        assert!(
            event_position(&events, "fs:flush-directory")
                < event_position(&events, "guard:installed-release")
        );
        assert!(
            event_position(&events, "guard:installed-release")
                < event_position(&events, "guard:original-release")
        );

        let mut installed_mismatch = TransactionFixture::new();
        installed_mismatch.file_system.installed_mismatch = true;
        let error = installed_mismatch.run().unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::MutationStateUnknown);
        let events = installed_mismatch.events();
        assert!(
            event_position(&events, "guard:observe-installed")
                < event_position(&events, "guard:installed-release")
        );
        assert!(
            event_position(&events, "guard:installed-release")
                < event_position(&events, "guard:original-release")
        );
    }

    #[test]
    fn response_is_prebuilt_before_replace_and_no_fallible_stage_follows_installed_proof() {
        let mut fixture = TransactionFixture::new();
        fixture.operation.response = "verified-before-commit".to_string();
        let outcome = fixture.run().unwrap();
        assert_eq!(outcome.response, "verified-before-commit");
        let events = fixture.events();
        assert!(
            event_position(&events, "operation:verify")
                < event_position(&events, "guard:install-output")
        );
        assert!(
            event_position(&events, "guard:observe-installed")
                < event_position(&events, "guard:installed-release")
        );
        assert!(
            event_position(&events, "guard:installed-release")
                < event_position(&events, "guard:original-release")
        );
        assert_eq!(
            events.last().map(String::as_str),
            Some("guard:original-release")
        );
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn production_engine_fails_platform_before_non_launching_discovery() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut file_system = FakeFileSystem::new(events.clone());
        let request = XrefTransactionRequest {
            host_path: file_system.host_path.clone(),
            operation: XrefMutationOperation::UpdateXref,
            sources: Vec::new(),
            profile: XrefIsolatedProfileSpec::default(),
        };
        let mut engine = AccoreconsoleXrefMutationEngine::new();
        let mut inspector = FakeInspector::new(events.clone());
        let mut operation = FakeOperation::new(events);
        let error = execute_xref_mutation_transaction(
            &request,
            &mut file_system,
            &mut engine,
            &mut inspector,
            &mut operation,
        )
        .unwrap_err();
        assert_eq!(error.code, XrefTransactionErrorCode::UnsupportedPlatform);
        assert_eq!(file_system.sibling_outputs_created, 0);
    }

    #[test]
    #[cfg(unix)]
    fn production_filesystem_preserves_guarded_replace_state_machine_contract() {
        let directory = tempfile::tempdir().unwrap();
        let host = directory.path().join("host.dwg");
        let source = directory.path().join("source.dwg");
        fs::write(&host, b"original-host").unwrap();
        fs::write(&source, b"immutable-source").unwrap();

        let mut file_system = ProductionXrefFileSystem::default();
        let initial = file_system.observe_path(&host).unwrap();
        let lock = file_system.acquire_original_host_guard(&host).unwrap();
        assert_eq!(file_system.observe_original_host(&lock).unwrap(), initial);

        let output = file_system
            .copy_locked_host_to_sibling(&lock, XrefHostFormat::Dwg)
            .unwrap();
        assert_eq!(output.parent(), host.parent());
        assert_eq!(fs::read(&output).unwrap(), b"original-host");

        let staging = file_system.create_staging_directory().unwrap();
        let snapshot = staging.join("sources/source.dwg");
        let source_identity = observe_xref_source_identity(&source).unwrap();
        let evidence = file_system
            .capture_source(&source, &snapshot, &source_identity)
            .unwrap();
        assert!(evidence.is_stable_for(&source_identity));
        assert_eq!(fs::read(&snapshot).unwrap(), b"immutable-source");
        let guarded_snapshot = file_system.observe_source_snapshot(&snapshot).unwrap();
        assert_eq!(guarded_snapshot.identity, evidence.snapshot_identity);
        assert_eq!(guarded_snapshot.digest, evidence.snapshot_digest);

        let mut profile = XrefIsolatedProfileDocument {
            schema_version: 1,
            certified_autocad_arg: Vec::new(),
            search_directories: vec![snapshot.parent().unwrap().to_path_buf()],
            source_snapshots: Vec::new(),
            unit_defaults: BTreeMap::new(),
            reconciliation: BTreeMap::new(),
        };
        let missing_profile = file_system
            .materialize_profile(&staging, &profile)
            .unwrap_err();
        assert!(missing_profile
            .to_string()
            .contains("certified exported AutoCAD ARG"));
        profile.certified_autocad_arg = b"certified-arg-profile".to_vec();
        let materialized_profile = file_system.materialize_profile(&staging, &profile).unwrap();
        let profile_path = materialized_profile.launch_path;
        assert_eq!(
            profile_path.extension().and_then(|value| value.to_str()),
            Some("arg")
        );
        assert!(
            !profile_path.exists(),
            "the ARG must be written exactly once by the guarded engine boundary"
        );
        assert_eq!(materialized_profile.artifacts.len(), 2);
        assert!(materialized_profile
            .artifacts
            .contains(&staging.join("xref-isolated-profile.json")));
        assert!(materialized_profile.artifacts.contains(&profile_path));

        fs::write(&output, b"verified-output").unwrap();
        file_system.flush_file(&output).unwrap();
        let verified = file_system.observe_path(&output).unwrap();
        let prepared = file_system
            .prepare_output_guard(&output, &host, &lock)
            .unwrap();
        assert_eq!(
            file_system.observe_prepared_output(&prepared).unwrap(),
            verified
        );
        let prepared_contention = lock_host_file(&output).unwrap_err();
        assert!(prepared_contention
            .to_string()
            .contains("exclusive host lock"));
        let installed_guard = file_system
            .install_prepared_output(prepared, &lock)
            .unwrap();
        let installed_contention = lock_host_file(&host).unwrap_err();
        assert!(installed_contention
            .to_string()
            .contains("exclusive host lock"));
        file_system.flush_directory(directory.path()).unwrap();
        let installed = file_system
            .observe_installed_host(&installed_guard)
            .unwrap();
        assert_eq!(installed.identity, verified.identity);
        assert_eq!(installed.digest, verified.digest);
        assert_eq!(fs::read(&host).unwrap(), b"verified-output");

        drop(installed_guard);
        let replacement_lock = lock_host_file(&host).unwrap();
        drop(replacement_lock);
        drop(lock);
        let cleanup = file_system.cleanup(&[staging]);
        assert!(cleanup.is_clean());
    }

    #[test]
    #[cfg(unix)]
    fn production_source_identity_swap_is_rejected_before_snapshot_creation() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.dwg");
        let replacement = directory.path().join("replacement.dwg");
        let snapshot = directory.path().join("staging/source.dwg");
        fs::write(&source, b"reviewed-source").unwrap();
        let expected_identity = observe_xref_source_identity(&source).unwrap();
        fs::write(&replacement, b"replacement-source").unwrap();
        fs::rename(&replacement, &source).unwrap();

        let mut file_system = ProductionXrefFileSystem::default();
        let error = file_system
            .capture_source(&source, &snapshot, &expected_identity)
            .unwrap_err();
        assert!(matches!(error, XrefSourceCaptureError::SourceRace(_)));
        assert!(!snapshot.exists());
        assert!(!snapshot.parent().unwrap().exists());
    }

    #[test]
    fn disappeared_locked_source_is_classified_as_a_source_race() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.dwg");
        let snapshot = directory.path().join("staging/source.dwg");
        fs::write(&source, b"reviewed-source").unwrap();
        let expected_identity = observe_xref_source_identity(&source).unwrap();
        fs::remove_file(&source).unwrap();

        let mut file_system = ProductionXrefFileSystem::default();
        let error = file_system
            .capture_source(&source, &snapshot, &expected_identity)
            .unwrap_err();
        assert!(matches!(error, XrefSourceCaptureError::SourceRace(_)));
        assert!(!snapshot.exists());
    }

    fn dwg_query(operation: XrefMutationOperation) -> XrefCapabilityQuery<'static> {
        XrefCapabilityQuery {
            host_format: XrefHostFormat::Dwg,
            drawing_version: "AC1032",
            dxf_form: XrefDxfForm::NotApplicable,
            code_page: None,
            operation,
        }
    }

    #[test]
    fn embedded_rows_admit_every_dwg_operation_with_profiles() {
        for operation in XREF_MUTATION_OPERATIONS {
            let admission = embedded_xref_mutation_admission(dwg_query(operation)).unwrap();
            assert_eq!(admission.capability.host_format, XrefHostFormat::Dwg);
            assert_eq!(
                admission.preservation_profile.profile_id,
                "xref-preservation-v1"
            );
            assert_eq!(
                admission
                    .bind_profile
                    .map(|profile| profile.profile_id.as_str()),
                Some("xref-bind-v1")
            );
            assert!(admission.rejects_clipped_targets());
            assert!(admission.clip_profile.is_none());
        }
    }

    #[test]
    fn embedded_rows_admit_every_ascii_dxf_operation_with_exact_code_page() {
        for operation in XREF_MUTATION_OPERATIONS {
            let admission = embedded_xref_mutation_admission(XrefCapabilityQuery {
                host_format: XrefHostFormat::Dxf,
                drawing_version: "AC1032",
                dxf_form: XrefDxfForm::Ascii,
                code_page: Some("ANSI_1252"),
                operation,
            })
            .unwrap();
            assert_eq!(admission.capability.host_format, XrefHostFormat::Dxf);
        }
    }

    #[test]
    fn capability_selection_is_bound_only_to_format_and_operation() {
        let format_error = embedded_xref_mutation_admission(XrefCapabilityQuery {
            drawing_version: "AC1027",
            ..dwg_query(XrefMutationOperation::AttachXref)
        })
        .unwrap_err();
        assert!(matches!(
            format_error,
            XrefCapabilityAdmissionError::UnsupportedFormat { .. }
        ));
    }

    #[test]
    fn ascii_dxf_code_page_is_part_of_the_exact_tuple() {
        let error = embedded_xref_mutation_admission(XrefCapabilityQuery {
            host_format: XrefHostFormat::Dxf,
            drawing_version: "AC1032",
            dxf_form: XrefDxfForm::Ascii,
            code_page: Some("ANSI_1251"),
            operation: XrefMutationOperation::AttachXref,
        })
        .unwrap_err();
        assert!(matches!(
            error,
            XrefCapabilityAdmissionError::UnsupportedFormat { .. }
        ));
    }

    #[test]
    fn digest_inventory_is_sorted_and_uses_lowercase_sha256() {
        let digests = xref_embedded_artifact_digests();
        assert_eq!(digests.len(), 4);
        assert!(digests
            .windows(2)
            .all(|pair| pair[0].file_name < pair[1].file_name));
        assert!(digests.iter().all(|digest| {
            digest.sha256.len() == 64
                && digest
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }));
    }

    #[test]
    fn sha256_hashes_exact_embedded_bytes() {
        let expected = [
            (
                XrefEmbeddedArtifact::MutationCapabilities,
                "c50c8963636913026434afce0263cb9766d1e6acab92522525a5f05590965000",
            ),
            (
                XrefEmbeddedArtifact::PreservationVerifierProfiles,
                "4f869dce25dd74b11466c3dcecb8258fe7575ae1bdec2207be5425ceec71c333",
            ),
            (
                XrefEmbeddedArtifact::BindVerifierProfiles,
                "4c6b4842a47a2ca7d6ce71522b1434011463b6b3c4acf3bb643c3fa8adc1c7cc",
            ),
            (
                XrefEmbeddedArtifact::ClipVerifierProfiles,
                "5c912e43c93d8a774835f9d938862224d031565c6c83469ff5995b59ac3cb1e8",
            ),
        ];

        for (artifact, expected_sha256) in expected {
            assert_eq!(xref_embedded_artifact_sha256_hex(artifact), expected_sha256);
        }
    }

    #[cfg(all(feature = "preview", not(target_os = "windows")))]
    #[test]
    fn guarded_preview_installer_rejects_before_candidate_build_off_windows() {
        let build_called = std::cell::Cell::new(false);

        let error = guarded_install_candidate(Path::new("missing.dwg"), |_| {
            build_called.set(true);
            Ok::<_, String>((vec![0_u8], ()))
        })
        .unwrap_err();

        assert!(!build_called.get());
        assert_eq!(error.code(), "preview_writer_unsupported_platform");
        assert_eq!(
            error.disposition(),
            GuardedCandidateInstallDisposition::DefinitelyNotInstalled
        );
    }
}
