use std::collections::HashMap;
use std::fs::{self, File, Metadata};
use std::io::{ErrorKind, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::autocad_reader::contract::xrefs::{XrefInstanceListOptions, XrefSnapshotEvidence};
use crate::autocad_reader::{
    map_xref_open_error, DrawingFormat, DrawingSnapshot, Reader, XrefReadSession,
};
use crate::ops::xref_graph::{
    self, XrefDependencyProvider, XrefGraphSource, XrefSourceInspection, XrefTraversalLimits,
};
use crate::ops::xref_path::{
    self, AbsolutePathKind, CandidateProbeResult, CanonicalDisplayPath, CanonicalExistingPath,
    FilesystemIdentity, PathPlatform, ResolutionCandidate, ResolutionCandidateProbe,
    SearchPathInspection, SearchPathInspector,
};
use crate::ops::xrefs::{
    self, xref_failure_code, ListXrefDependenciesRequest, ListXrefInstancesRequest,
    ResolveXrefPathRequest, XrefAttachmentRecord, XrefDependencyTraversalEnvelope, XrefError,
    XrefInstanceRecord, XrefPathResolutionRecord, XrefSelector,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XrefFileFormat {
    Dxf,
    Dwg,
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn validate_xref_path(path: &Path, tool: &str) -> Result<XrefFileFormat, XrefError> {
    if !path.is_absolute() {
        return Err(XrefError::new(
            "drawing_unreadable",
            format!("{tool}: drawing_path must be absolute: {}", path.display()),
        ));
    }

    let format = match extension(path).as_str() {
        "dxf" => XrefFileFormat::Dxf,
        "dwg" => XrefFileFormat::Dwg,
        "" => {
            return Err(XrefError::new(
                "unsupported_format",
                format!("{tool}: file has no extension; expected .dxf or .dwg"),
            ));
        }
        other => {
            return Err(XrefError::new(
                "unsupported_format",
                format!("{tool}: unsupported extension `{other}`; expected .dxf or .dwg"),
            ));
        }
    };

    if !path.exists() {
        return Err(XrefError::new(
            "drawing_not_found",
            format!("{tool}: drawing not found: {}", path.display()),
        ));
    }
    Ok(format)
}

fn capture_snapshot(path: &Path, tool: &str) -> Result<Vec<u8>, XrefError> {
    fs::read(path).map_err(|error| {
        XrefError::new(
            "drawing_unreadable",
            format!("{tool}: failed to capture {}: {error}", path.display()),
        )
    })
}

fn reader_format(format: XrefFileFormat) -> DrawingFormat {
    match format {
        XrefFileFormat::Dxf => DrawingFormat::Dxf,
        XrefFileFormat::Dwg => DrawingFormat::Dwg,
    }
}

fn decode_snapshot(format: XrefFileFormat, bytes: Vec<u8>) -> Result<XrefReadSession, XrefError> {
    Reader::open_snapshot(DrawingSnapshot::new(reader_format(format), bytes))
        .map_err(map_xref_open_error)?
        .xref_session()
}

fn load_session(path: &Path, tool: &str) -> Result<XrefReadSession, XrefError> {
    let format = validate_xref_path(path, tool)?;
    let bytes = capture_snapshot(path, tool)?;
    decode_snapshot(format, bytes)
}

#[cfg(any(target_os = "windows", test))]
fn normalize_windows_verbatim_display_path(path: &str) -> Option<String> {
    let slash_path = path.replace('\\', "/");
    let remainder = slash_path.strip_prefix("//?/")?;
    if remainder
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("UNC/"))
    {
        Some(format!("//{}", &remainder[4..]))
    } else if remainder.as_bytes().get(1) == Some(&b':') {
        Some(remainder.to_owned())
    } else {
        None
    }
}

fn canonical_display_path(path: &Path) -> Result<CanonicalDisplayPath, ()> {
    let path = path.to_str().ok_or(())?;
    #[cfg(windows)]
    let path = normalize_windows_verbatim_display_path(path).unwrap_or_else(|| path.to_owned());
    #[cfg(not(windows))]
    let path = path.to_owned();
    CanonicalDisplayPath::from_filesystem_canonical_path(&path).map_err(|_| ())
}

fn filesystem_identity(
    file: &File,
    metadata: &Metadata,
    display_path: &CanonicalDisplayPath,
) -> Result<FilesystemIdentity, ()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let _ = file;
        let _ = display_path;
        Ok(FilesystemIdentity::posix(metadata.dev(), metadata.ino()))
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawHandle;

        let _ = metadata;
        let _ = display_path;
        let mut information = windows_identity::ByHandleFileInformation::default();
        let result = unsafe {
            windows_identity::get_file_information_by_handle(
                file.as_raw_handle().cast(),
                &mut information,
            )
        };
        if result == 0 {
            return Err(());
        }
        let file_index =
            (u64::from(information.file_index_high) << 32) | u64::from(information.file_index_low);
        Ok(FilesystemIdentity::windows(
            u64::from(information.volume_serial_number),
            u128::from(file_index),
        ))
    }

    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = file;
        let _ = metadata;
        let key = format!("canonical:{}", display_path.as_str());
        FilesystemIdentity::opaque(key.into_bytes()).map_err(|_| ())
    }
}

#[cfg(target_os = "windows")]
mod windows_identity {
    use std::ffi::c_void;

    type Handle = *mut c_void;

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

fn same_revision(
    before: &Metadata,
    after: &Metadata,
    before_identity: &FilesystemIdentity,
    after_identity: &FilesystemIdentity,
) -> bool {
    before_identity == after_identity
        && before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
}

#[derive(Debug, Clone)]
pub(crate) struct LoadedXrefHost {
    display_path: CanonicalDisplayPath,
    filesystem_identity: FilesystemIdentity,
    content_sha256: String,
    session: XrefReadSession,
}

impl LoadedXrefHost {
    pub(crate) fn display_path(&self) -> &CanonicalDisplayPath {
        &self.display_path
    }

    pub(crate) fn filesystem_identity(&self) -> &FilesystemIdentity {
        &self.filesystem_identity
    }

    pub(crate) fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    pub(crate) fn attachments(&self) -> Result<Vec<XrefAttachmentRecord>, XrefError> {
        self.session.list_attachments()
    }

    pub(crate) fn get_attachment(
        &self,
        selector: &XrefSelector,
    ) -> Result<XrefAttachmentRecord, XrefError> {
        self.session.get_attachment(selector)
    }

    pub(crate) fn instances(
        &self,
        options: &XrefInstanceListOptions,
    ) -> Result<Vec<XrefInstanceRecord>, XrefError> {
        self.session.list_instances(options)
    }

    pub(crate) fn get_instance(&self, handle: &str) -> Result<XrefInstanceRecord, XrefError> {
        self.session.get_instance(handle)
    }

    pub(crate) fn evidence(&self) -> &XrefSnapshotEvidence {
        self.session.evidence()
    }

    pub(crate) fn graph_source(&self) -> Result<XrefGraphSource, XrefError> {
        XrefGraphSource::try_new(
            self.display_path.clone(),
            self.filesystem_identity.clone(),
            self.attachments()?,
        )
    }
}

pub(crate) fn load_xref_host(path: &Path, tool: &str) -> Result<LoadedXrefHost, XrefError> {
    let format = validate_xref_path(path, tool)?;
    let canonical_path = fs::canonicalize(path).map_err(|error| {
        XrefError::new(
            xref_failure_code::DRAWING_UNREADABLE,
            format!("{tool}: failed to canonicalize {}: {error}", path.display()),
        )
    })?;
    let display_path = canonical_display_path(&canonical_path).map_err(|()| {
        XrefError::new(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            format!(
                "{tool}: canonical drawing path is not representable in the public path contract"
            ),
        )
    })?;
    let mut file = File::open(&canonical_path).map_err(|error| {
        XrefError::new(
            xref_failure_code::DRAWING_UNREADABLE,
            format!(
                "{tool}: failed to open {}: {error}",
                canonical_path.display()
            ),
        )
    })?;
    let before = file.metadata().map_err(|error| {
        XrefError::new(
            xref_failure_code::DRAWING_UNREADABLE,
            format!(
                "{tool}: failed to inspect {}: {error}",
                canonical_path.display()
            ),
        )
    })?;
    if !before.is_file() {
        return Err(XrefError::new(
            xref_failure_code::DRAWING_UNREADABLE,
            format!("{tool}: drawing is not a regular file: {}", path.display()),
        ));
    }
    let before_identity = filesystem_identity(&file, &before, &display_path).map_err(|()| {
        XrefError::new(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            format!("{tool}: drawing filesystem identity cannot be proven"),
        )
    })?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        XrefError::new(
            xref_failure_code::DRAWING_UNREADABLE,
            format!(
                "{tool}: failed to capture {}: {error}",
                canonical_path.display()
            ),
        )
    })?;
    let after = file.metadata().map_err(|error| {
        XrefError::new(
            xref_failure_code::DRAWING_UNREADABLE,
            format!(
                "{tool}: failed to re-inspect {}: {error}",
                canonical_path.display()
            ),
        )
    })?;
    let after_identity = filesystem_identity(&file, &after, &display_path).map_err(|()| {
        XrefError::new(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            format!("{tool}: drawing filesystem identity cannot be proven"),
        )
    })?;
    if !same_revision(&before, &after, &before_identity, &after_identity) {
        return Err(XrefError::new(
            xref_failure_code::DRAWING_UNREADABLE,
            format!("{tool}: drawing changed while its snapshot was captured"),
        ));
    }

    let content_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let session = decode_snapshot(format, bytes)?;
    Ok(LoadedXrefHost {
        display_path,
        filesystem_identity: before_identity,
        content_sha256,
        session,
    })
}

fn path_platform(path: &CanonicalDisplayPath) -> PathPlatform {
    match path.kind() {
        AbsolutePathKind::WindowsDrive | AbsolutePathKind::WindowsUnc => PathPlatform::Windows,
        AbsolutePathKind::Posix => PathPlatform::Posix,
    }
}

fn map_search_path_error(error: impl std::fmt::Display) -> XrefError {
    XrefError::new(xref_failure_code::INVALID_SEARCH_PATH, error.to_string())
}

fn validate_selector_syntax(
    handle: Option<&str>,
    name: Option<&str>,
    required: bool,
) -> Result<(), XrefError> {
    if let Some(handle) = handle {
        xrefs::canonical_input_handle(handle)?;
    }
    if handle.is_none() && name.is_some_and(|name| name.trim().is_empty()) {
        return Err(XrefError::new(
            xref_failure_code::MISSING_IDENTITY,
            "XREF selection requires a handle or non-empty name",
        ));
    }
    if required && handle.is_none() && name.is_none() {
        return Err(XrefError::new(
            xref_failure_code::MISSING_IDENTITY,
            "XREF selection requires a handle or non-empty name",
        ));
    }
    Ok(())
}

#[derive(Default)]
pub(crate) struct FilesystemXrefProvider {
    sessions: HashMap<FilesystemIdentity, XrefReadSession>,
    content_sha256: HashMap<FilesystemIdentity, String>,
    content_sha256_by_path: HashMap<String, String>,
}

impl FilesystemXrefProvider {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_host(host: &LoadedXrefHost) -> Self {
        let mut provider = Self::new();
        provider.content_sha256.insert(
            host.filesystem_identity.clone(),
            host.content_sha256.clone(),
        );
        provider.content_sha256_by_path.insert(
            host.display_path.as_str().to_string(),
            host.content_sha256.clone(),
        );
        provider.cache_session(host.filesystem_identity.clone(), host.session.clone());
        provider
    }

    pub(crate) fn inspected_content_sha256(&self, resolved_path: &str) -> Option<&str> {
        self.content_sha256_by_path
            .get(resolved_path)
            .map(String::as_str)
    }

    pub(crate) fn cache_session(
        &mut self,
        filesystem_identity: FilesystemIdentity,
        session: XrefReadSession,
    ) {
        self.sessions.insert(filesystem_identity, session);
    }

    fn resolved_candidate(&mut self, candidate: &ResolutionCandidate) -> CandidateProbeResult {
        if extension(Path::new(candidate.path())) != "dwg" {
            return CandidateProbeResult::Unsupported;
        }

        let canonical_path = match fs::canonicalize(candidate.path()) {
            Ok(path) => path,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return CandidateProbeResult::Missing;
            }
            Err(_) => return CandidateProbeResult::Unresolved,
        };
        let display_path = match canonical_display_path(&canonical_path) {
            Ok(path) => path,
            Err(()) => return CandidateProbeResult::Unsupported,
        };
        let mut file = match File::open(&canonical_path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return CandidateProbeResult::Missing;
            }
            Err(_) => return CandidateProbeResult::Unresolved,
        };
        let before = match file.metadata() {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) | Err(_) => return CandidateProbeResult::Unresolved,
        };
        let before_identity = match filesystem_identity(&file, &before, &display_path) {
            Ok(identity) => identity,
            Err(()) => return CandidateProbeResult::Unsupported,
        };

        if !self.sessions.contains_key(&before_identity) {
            let mut bytes = Vec::new();
            if file.read_to_end(&mut bytes).is_err() {
                return CandidateProbeResult::Unresolved;
            }
            let after = match file.metadata() {
                Ok(metadata) => metadata,
                Err(_) => return CandidateProbeResult::Unresolved,
            };
            let after_identity = match filesystem_identity(&file, &after, &display_path) {
                Ok(identity) => identity,
                Err(()) => return CandidateProbeResult::Unsupported,
            };
            if !same_revision(&before, &after, &before_identity, &after_identity) {
                return CandidateProbeResult::Unresolved;
            }
            let content_sha256 = format!("{:x}", Sha256::digest(&bytes));
            let session = match decode_snapshot(XrefFileFormat::Dwg, bytes) {
                Ok(session) => session,
                Err(_) => return CandidateProbeResult::Unresolved,
            };
            self.content_sha256
                .insert(before_identity.clone(), content_sha256);
            self.cache_session(before_identity.clone(), session);
        }

        if let Some(digest) = self.content_sha256.get(&before_identity) {
            self.content_sha256_by_path
                .insert(display_path.as_str().to_string(), digest.clone());
        }

        CandidateProbeResult::Resolved(CanonicalExistingPath::new(display_path, before_identity))
    }
}

impl SearchPathInspector for FilesystemXrefProvider {
    fn inspect_search_path(&mut self, absolute_path: &str) -> SearchPathInspection {
        let canonical_path = match fs::canonicalize(absolute_path) {
            Ok(path) => path,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return SearchPathInspection::Missing;
            }
            Err(error) if error.kind() == ErrorKind::PermissionDenied => {
                return SearchPathInspection::Unreadable;
            }
            Err(_) => return SearchPathInspection::Unreadable,
        };
        let metadata = match fs::metadata(&canonical_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return SearchPathInspection::Missing;
            }
            Err(_) => return SearchPathInspection::Unreadable,
        };
        if !metadata.is_dir() {
            return SearchPathInspection::NotDirectory;
        }
        if fs::read_dir(&canonical_path).is_err() {
            return SearchPathInspection::Unreadable;
        }
        match canonical_display_path(&canonical_path) {
            Ok(path) => SearchPathInspection::ReadableDirectory(path),
            Err(()) => SearchPathInspection::Unrepresentable,
        }
    }
}

impl ResolutionCandidateProbe for FilesystemXrefProvider {
    fn probe_candidate(&mut self, candidate: &ResolutionCandidate) -> CandidateProbeResult {
        self.resolved_candidate(candidate)
    }
}

impl XrefDependencyProvider for FilesystemXrefProvider {
    fn inspect_resolved_source(
        &mut self,
        _resolved_path: &CanonicalDisplayPath,
        filesystem_identity: &FilesystemIdentity,
    ) -> Result<XrefSourceInspection, XrefError> {
        let Some(session) = self.sessions.get(filesystem_identity) else {
            return Ok(XrefSourceInspection::Unsupported);
        };
        match session.list_attachments() {
            Ok(attachments) => Ok(XrefSourceInspection::Inspected {
                attachments,
                content_sha256: self.content_sha256.get(filesystem_identity).cloned(),
            }),
            Err(error) if error.code() == xref_failure_code::UNSUPPORTED_XREF_DATA => {
                Ok(XrefSourceInspection::Unsupported)
            }
            Err(error) => Err(error),
        }
    }
}

pub fn list_xrefs_file(path: &Path) -> Result<Vec<XrefAttachmentRecord>, XrefError> {
    load_session(path, "list_xrefs")?.list_attachments()
}

pub fn get_xref_file(
    path: &Path,
    selector: &XrefSelector,
) -> Result<XrefAttachmentRecord, XrefError> {
    load_session(path, "get_xref")?.get_attachment(selector)
}

pub(crate) fn instance_list_options(request: &ListXrefInstancesRequest) -> XrefInstanceListOptions {
    XrefInstanceListOptions {
        attachment_handle: request.attachment_handle.clone(),
        attachment_name: request.attachment_name.clone(),
        owner_handle: request.owner_handle.clone(),
        owner_type: request.owner_type,
        owner_name: request.owner_name.clone(),
        layer_handle: request.layer_handle.clone(),
        layer_name: request.layer_name.clone(),
        visibility: request.visibility,
    }
}

pub fn list_xref_instances_file(
    path: &Path,
    request: &ListXrefInstancesRequest,
) -> Result<Vec<XrefInstanceRecord>, XrefError> {
    load_session(path, "list_xref_instances")?.list_instances(&instance_list_options(request))
}

pub fn get_xref_instance_file(path: &Path, handle: &str) -> Result<XrefInstanceRecord, XrefError> {
    load_session(path, "get_xref_instance")?.get_instance(handle)
}

pub fn resolve_xref_path_file(
    path: &Path,
    request: &ResolveXrefPathRequest,
) -> Result<XrefPathResolutionRecord, XrefError> {
    let host = load_xref_host(path, "resolve_xref_path")?;
    validate_selector_syntax(request.handle.as_deref(), request.name.as_deref(), true)?;

    let mut provider = FilesystemXrefProvider::with_host(&host);
    let platform = path_platform(host.display_path());
    let search_paths = xref_path::validate_search_paths(
        request.search_paths.as_deref().unwrap_or_default(),
        platform,
        &mut provider,
    )
    .map_err(map_search_path_error)?;

    let selector = XrefSelector {
        handle: request.handle.clone(),
        name: request.name.clone(),
    };
    let attachment = host.get_attachment(&selector)?;
    let plan = xref_path::build_resolution_plan(
        &attachment.saved_path,
        host.display_path(),
        platform,
        &search_paths,
    )
    .map_err(|error| {
        XrefError::new(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            format!("cannot build XREF resolution plan: {error}"),
        )
    })?;
    let resolution = xref_path::resolve_candidate_plan(&plan, &mut provider).map_err(|error| {
        XrefError::new(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            format!("filesystem resolver returned invalid evidence: {error}"),
        )
    })?;
    let search_path_index = resolution
        .search_path_index()
        .map(u32::try_from)
        .transpose()
        .map_err(|_| {
            XrefError::new(
                xref_failure_code::UNSUPPORTED_XREF_DATA,
                "resolved search-path index exceeds the public integer range",
            )
        })?;

    Ok(XrefPathResolutionRecord {
        drawing: host.display_path().as_str().to_owned(),
        attachment_handle: attachment.handle,
        saved_path: attachment.saved_path,
        path_mode: plan.path_mode(),
        resolution_state: resolution.resolution_state(),
        resolved_path: resolution
            .resolved_path()
            .map(|path| path.as_str().to_owned()),
        resolution_basis: resolution.resolution_basis(),
        search_path_index,
    })
}

pub fn list_xref_dependencies_file(
    path: &Path,
    request: &ListXrefDependenciesRequest,
) -> Result<XrefDependencyTraversalEnvelope, XrefError> {
    let limits = XrefTraversalLimits::for_list(request.max_depth, request.max_nodes)?;
    let host = load_xref_host(path, "list_xref_dependencies")?;
    validate_selector_syntax(request.handle.as_deref(), request.name.as_deref(), false)?;

    let mut provider = FilesystemXrefProvider::with_host(&host);
    let platform = path_platform(host.display_path());
    let search_paths = xref_path::validate_search_paths(
        request.search_paths.as_deref().unwrap_or_default(),
        platform,
        &mut provider,
    )
    .map_err(map_search_path_error)?;
    let source = host.graph_source()?;
    let selector = (request.handle.is_some() || request.name.is_some()).then(|| XrefSelector {
        handle: request.handle.clone(),
        name: request.name.clone(),
    });

    xref_graph::traverse_xref_dependencies(
        &source,
        selector.as_ref(),
        &search_paths,
        limits,
        &mut provider,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::xrefs::{
        XrefInspectionState, XrefOwnerType, XrefPlacementKind, XrefResolutionBasis,
        XrefResolutionState, XrefTraversalLimitReason,
    };
    use acadrust::tables::BlockRecord;
    use acadrust::types::Handle;
    use acadrust::{CadDocument, DwgWriter};
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("autocad-mcp should live under <repo>/crates")
            .join("tests/fixtures/xrefs")
            .join(name)
    }

    fn write_dwg(path: &Path, attachments: &[(u64, &str, &str)]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut document = CadDocument::new();
        for (index, (handle, name, saved_path)) in attachments.iter().enumerate() {
            let mut attachment = BlockRecord::new(*name);
            attachment.handle = Handle::new(*handle);
            attachment.block_entity_handle = Handle::new(0x1_0000 + (index as u64 * 2));
            attachment.block_end_handle = Handle::new(0x1_0001 + (index as u64 * 2));
            attachment.flags.is_xref = true;
            attachment.xref_path = (*saved_path).to_owned();
            document.block_records.add(attachment).unwrap();
        }
        DwgWriter::write_to_file(path, &document).unwrap();
    }

    fn canonical(path: &Path) -> String {
        let canonical = fs::canonicalize(path).unwrap();
        canonical_display_path(&canonical)
            .unwrap()
            .as_str()
            .to_owned()
    }

    fn resolve_request(path: &Path, handle: &str) -> ResolveXrefPathRequest {
        ResolveXrefPathRequest {
            drawing_path: path.display().to_string(),
            handle: Some(handle.to_owned()),
            name: None,
            search_paths: None,
        }
    }

    fn dependency_request(path: &Path) -> ListXrefDependenciesRequest {
        ListXrefDependenciesRequest {
            drawing_path: path.display().to_string(),
            handle: None,
            name: None,
            search_paths: None,
            max_depth: None,
            max_nodes: None,
        }
    }

    #[test]
    fn path_validation_precedes_existence() {
        let err = list_xrefs_file(Path::new("relative.xyz")).unwrap_err();
        assert_eq!(err.code(), "drawing_unreadable");

        let missing = std::env::temp_dir().join("missing-xref-fixture.xyz");
        let err = list_xrefs_file(&missing).unwrap_err();
        assert_eq!(err.code(), "unsupported_format");

        let missing = std::env::temp_dir().join("missing-xref-fixture.dxf");
        let err = list_xrefs_file(&missing).unwrap_err();
        assert_eq!(err.code(), "drawing_not_found");
    }

    #[test]
    fn public_xref_reads_map_fatal_reader_errors_without_backend_details() {
        let directory = tempfile::tempdir().unwrap();
        let invalid = directory.path().join("invalid.dwg");
        fs::write(&invalid, b"not a DWG").unwrap();

        let error = list_xrefs_file(&invalid).unwrap_err();
        assert_eq!(error.code(), "unsupported_xref_data");
        assert_eq!(
            error.to_string(),
            "code=unsupported_xref_data drawing could not be decoded for XREF projection"
        );
        assert!(!error.to_string().contains("acadrust"));
        assert!(!error.to_string().contains("Invalid file format"));
    }

    #[test]
    fn windows_verbatim_paths_normalize_for_public_display() {
        let drive =
            normalize_windows_verbatim_display_path(r"\\?\c:\Project\Refs\Site.dwg").unwrap();
        assert_eq!(drive, "c:/Project/Refs/Site.dwg");
        assert_eq!(
            CanonicalDisplayPath::from_filesystem_canonical_path(&drive)
                .unwrap()
                .as_str(),
            "C:/Project/Refs/Site.dwg"
        );
        assert_eq!(
            normalize_windows_verbatim_display_path(r"\\?\UNC\Server\Share\Site.dwg"),
            Some("//Server/Share/Site.dwg".to_owned())
        );
        assert_eq!(
            normalize_windows_verbatim_display_path("/tmp/site.dwg"),
            None
        );
    }

    #[test]
    fn portable_attachment_file_entry_points_return_full_records() {
        let path = fixture("portable-evidence-ascii.dxf");
        let records = list_xrefs_file(&path).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].handle, "F");
        assert_eq!(records[0].instance_count, 2);

        let selected = get_xref_file(
            &path,
            &XrefSelector {
                handle: Some("0x0010".to_string()),
                name: Some("GRID_OVERLAY".to_string()),
            },
        )
        .unwrap();
        assert_eq!(selected.handle, "10");
    }

    #[test]
    fn portable_instance_file_entry_points_preserve_owners_and_arrays() {
        let path = fixture("portable-evidence-ascii.dxf");
        let request = ListXrefInstancesRequest {
            drawing_path: path.display().to_string(),
            attachment_handle: Some("F".to_string()),
            attachment_name: None,
            owner_handle: None,
            owner_type: None,
            owner_name: None,
            layer_handle: None,
            layer_name: None,
            visibility: None,
        };
        let records = list_xref_instances_file(&path, &request).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].handle, "F0");
        assert_eq!(records[0].owner_type, XrefOwnerType::BlockDefinition);
        assert_eq!(
            records[0].placement_kind,
            XrefPlacementKind::RectangularArray
        );

        let selected = get_xref_instance_file(&path, "0x20").unwrap();
        assert_eq!(selected.owner_type, XrefOwnerType::PaperSpace);
        assert_eq!(selected.owner_name, "Sheet A");
    }

    #[test]
    fn captured_snapshot_supports_non_utf8_ascii_without_path_rereads() {
        let path = fixture("non-utf8-ansi-1252.dxf");
        let record = get_xref_file(
            &path,
            &XrefSelector {
                handle: None,
                name: Some("caf\u{e9}_site".to_string()),
            },
        )
        .unwrap();
        assert_eq!(record.saved_path, "r\u{e9}fs/site.dwg");
    }

    #[test]
    fn resolves_host_relative_source_from_the_canonical_host_directory() {
        let directory = tempfile::tempdir().unwrap();
        let host = directory.path().join("host.dwg");
        let source = directory.path().join("refs/source.dwg");
        write_dwg(&source, &[]);
        write_dwg(&host, &[(0xA1, "SOURCE", "refs/source.dwg")]);

        let record = resolve_xref_path_file(&host, &resolve_request(&host, "0x00a1")).unwrap();

        assert_eq!(record.drawing, canonical(&host));
        assert_eq!(record.attachment_handle, "A1");
        assert_eq!(record.saved_path, "refs/source.dwg");
        assert_eq!(record.resolution_state, XrefResolutionState::Resolved);
        assert_eq!(
            record.resolved_path.as_deref(),
            Some(canonical(&source).as_str())
        );
        assert_eq!(
            record.resolution_basis,
            Some(XrefResolutionBasis::HostRelative)
        );
        assert_eq!(record.search_path_index, None);
    }

    #[test]
    fn absent_source_is_successful_not_found_resolution_data() {
        let directory = tempfile::tempdir().unwrap();
        let host = directory.path().join("host.dwg");
        write_dwg(&host, &[(0xA1, "MISSING", "missing.dwg")]);

        let record = resolve_xref_path_file(&host, &resolve_request(&host, "A1")).unwrap();

        assert_eq!(record.resolution_state, XrefResolutionState::NotFound);
        assert_eq!(record.resolved_path, None);
        assert_eq!(record.resolution_basis, None);
        assert_eq!(record.search_path_index, None);
    }

    #[test]
    fn invalid_search_paths_fail_in_caller_order() {
        let directory = tempfile::tempdir().unwrap();
        let host = directory.path().join("host.dwg");
        write_dwg(&host, &[(0xA1, "MISSING", "missing.dwg")]);
        let mut request = resolve_request(&host, "A1");

        request.search_paths = Some(vec!["relative".to_owned()]);
        assert_eq!(
            resolve_xref_path_file(&host, &request).unwrap_err().code(),
            xref_failure_code::INVALID_SEARCH_PATH
        );

        request.search_paths = Some(vec![directory.path().join("absent").display().to_string()]);
        assert_eq!(
            resolve_xref_path_file(&host, &request).unwrap_err().code(),
            xref_failure_code::INVALID_SEARCH_PATH
        );

        request.search_paths = Some(vec![host.display().to_string()]);
        assert_eq!(
            resolve_xref_path_file(&host, &request).unwrap_err().code(),
            xref_failure_code::INVALID_SEARCH_PATH
        );
    }

    #[test]
    fn existing_invalid_dwg_is_successful_unresolved_data() {
        let directory = tempfile::tempdir().unwrap();
        let host = directory.path().join("host.dwg");
        let invalid = directory.path().join("invalid.dwg");
        write_dwg(&host, &[(0xA1, "INVALID", "invalid.dwg")]);
        fs::write(&invalid, b"not a DWG").unwrap();

        let record = resolve_xref_path_file(&host, &resolve_request(&host, "A1")).unwrap();

        assert_eq!(record.resolution_state, XrefResolutionState::Unresolved);
        assert_eq!(record.resolved_path, None);
    }

    #[test]
    fn dependency_roots_are_depth_first_and_numeric_handle_sorted() {
        let directory = tempfile::tempdir().unwrap();
        let host = directory.path().join("host.dwg");
        let first = directory.path().join("first.dwg");
        let second = directory.path().join("second.dwg");
        write_dwg(&first, &[]);
        write_dwg(&second, &[]);
        write_dwg(
            &host,
            &[
                (0x100, "SECOND", "second.dwg"),
                (0xA1, "FIRST", "first.dwg"),
            ],
        );

        let result = list_xref_dependencies_file(&host, &dependency_request(&host)).unwrap();
        let chains = result
            .dependencies
            .iter()
            .map(|record| record.attachment_chain.clone())
            .collect::<Vec<_>>();

        assert_eq!(chains, vec![vec!["A1".to_owned()], vec!["100".to_owned()]]);
        assert!(result.within_limits);
        assert!(result.truncation.is_none());
        assert!(result
            .dependencies
            .iter()
            .all(|record| record.inspection_state == XrefInspectionState::Inspected));
    }

    #[test]
    fn dependency_cycles_and_limit_prefixes_use_filesystem_identity() {
        let directory = tempfile::tempdir().unwrap();
        let host = directory.path().join("host.dwg");
        let child = directory.path().join("refs/child.dwg");
        write_dwg(&child, &[(0xB1, "HOST", "../host.dwg")]);
        write_dwg(&host, &[(0xA1, "CHILD", "refs/child.dwg")]);

        let complete = list_xref_dependencies_file(&host, &dependency_request(&host)).unwrap();
        assert_eq!(complete.dependencies.len(), 2);
        assert_eq!(
            complete.dependencies[1].attachment_chain,
            vec!["A1".to_owned(), "B1".to_owned()]
        );
        assert_eq!(
            complete.dependencies[1].inspection_state,
            XrefInspectionState::Cycle
        );
        assert_eq!(complete.dependencies[1].cycle_target_chain, Some(vec![]));

        let mut depth_limited = dependency_request(&host);
        depth_limited.max_depth = Some(0);
        let depth_limited = list_xref_dependencies_file(&host, &depth_limited).unwrap();
        assert_eq!(depth_limited.dependencies.len(), 1);
        assert!(!depth_limited.within_limits);
        let truncation = depth_limited.truncation.unwrap();
        assert_eq!(truncation.reason, XrefTraversalLimitReason::MaxDepth);
        assert_eq!(
            truncation.attachment_chain,
            vec!["A1".to_owned(), "B1".to_owned()]
        );

        let mut node_limited = dependency_request(&host);
        node_limited.max_nodes = Some(1);
        let node_limited = list_xref_dependencies_file(&host, &node_limited).unwrap();
        assert_eq!(node_limited.dependencies.len(), 1);
        assert_eq!(
            node_limited.truncation.unwrap().reason,
            XrefTraversalLimitReason::MaxNodes
        );

        let mut simultaneously_limited = dependency_request(&host);
        simultaneously_limited.max_depth = Some(0);
        simultaneously_limited.max_nodes = Some(1);
        let simultaneously_limited =
            list_xref_dependencies_file(&host, &simultaneously_limited).unwrap();
        assert_eq!(
            simultaneously_limited.truncation.unwrap().reason,
            XrefTraversalLimitReason::MaxDepth
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolved_display_path_follows_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let host = directory.path().join("host.dwg");
        let actual = directory.path().join("sources/actual.dwg");
        let alias = directory.path().join("refs/alias.dwg");
        write_dwg(&actual, &[]);
        fs::create_dir_all(alias.parent().unwrap()).unwrap();
        symlink(&actual, &alias).unwrap();
        write_dwg(&host, &[(0xA1, "ALIASED", "refs/alias.dwg")]);

        let record = resolve_xref_path_file(&host, &resolve_request(&host, "A1")).unwrap();

        assert_eq!(
            record.resolved_path.as_deref(),
            Some(canonical(&actual).as_str())
        );
    }
}
