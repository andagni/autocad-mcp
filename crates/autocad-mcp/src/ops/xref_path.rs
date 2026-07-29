use serde::{Serialize, Serializer};
use std::fmt;

use super::xrefs::{xref_failure_code, XrefError};

pub use super::xrefs::{
    XrefPathMode, XrefResolutionBasis as ResolutionBasis, XrefResolutionState as ResolutionState,
};
pub use crate::autocad_reader::xref_path::{
    parse_saved_path, AbsolutePathKind, ParsedXrefPath, UnsupportedPathReason, XrefPathSyntax,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum AbsoluteRoot {
    WindowsDrive(char),
    WindowsUnc { server: String, share: String },
    Posix,
}

impl AbsoluteRoot {
    fn kind(&self) -> AbsolutePathKind {
        match self {
            Self::WindowsDrive(_) => AbsolutePathKind::WindowsDrive,
            Self::WindowsUnc { .. } => AbsolutePathKind::WindowsUnc,
            Self::Posix => AbsolutePathKind::Posix,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AbsoluteParts {
    root: AbsoluteRoot,
    components: Vec<String>,
}

enum AbsoluteParse {
    Absolute(AbsoluteParts),
    Unsupported(UnsupportedPathReason),
    NotAbsolute,
}

fn is_separator(byte: u8) -> bool {
    matches!(byte, b'/' | b'\\')
}

fn has_two_leading_separators(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && is_separator(bytes[0]) && is_separator(bytes[1])
}

fn split_components(value: &str) -> Vec<String> {
    value
        .split(['/', '\\'])
        .filter(|component| !component.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_unc_remainder(value: &str) -> Result<AbsoluteParts, UnsupportedPathReason> {
    let mut components = split_components(value).into_iter();
    let Some(server) = components.next() else {
        return Err(UnsupportedPathReason::MalformedUnc);
    };
    let Some(share) = components.next() else {
        return Err(UnsupportedPathReason::MalformedUnc);
    };
    if matches!(server.as_str(), "." | "..") || matches!(share.as_str(), "." | "..") {
        return Err(UnsupportedPathReason::MalformedUnc);
    }

    Ok(AbsoluteParts {
        root: AbsoluteRoot::WindowsUnc { server, share },
        components: components.collect(),
    })
}

fn parse_drive_path(value: &str) -> Result<AbsoluteParts, UnsupportedPathReason> {
    let bytes = value.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return Err(UnsupportedPathReason::WindowsDevicePath);
    }
    if !is_separator(bytes[2]) {
        return Err(UnsupportedPathReason::DriveRelative);
    }

    Ok(AbsoluteParts {
        root: AbsoluteRoot::WindowsDrive((bytes[0] as char).to_ascii_uppercase()),
        components: split_components(&value[3..]),
    })
}

fn parse_absolute_path(value: &str) -> AbsoluteParse {
    let bytes = value.as_bytes();

    if bytes.len() >= 4
        && has_two_leading_separators(bytes)
        && matches!(bytes[2], b'?' | b'.')
        && is_separator(bytes[3])
    {
        if bytes[2] == b'.' {
            return AbsoluteParse::Unsupported(UnsupportedPathReason::WindowsDevicePath);
        }

        let remainder = &value[4..];
        let remainder_bytes = remainder.as_bytes();
        if remainder_bytes.len() >= 4
            && remainder_bytes[..3].eq_ignore_ascii_case(b"UNC")
            && is_separator(remainder_bytes[3])
        {
            return match parse_unc_remainder(&remainder[4..]) {
                Ok(parts) => AbsoluteParse::Absolute(parts),
                Err(reason) => AbsoluteParse::Unsupported(reason),
            };
        }

        return match parse_drive_path(remainder) {
            Ok(parts) => AbsoluteParse::Absolute(parts),
            Err(_) => AbsoluteParse::Unsupported(UnsupportedPathReason::WindowsDevicePath),
        };
    }

    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return match parse_drive_path(value) {
            Ok(parts) => AbsoluteParse::Absolute(parts),
            Err(reason) => AbsoluteParse::Unsupported(reason),
        };
    }

    if has_two_leading_separators(bytes) {
        return match parse_unc_remainder(&value[2..]) {
            Ok(parts) => AbsoluteParse::Absolute(parts),
            Err(reason) => AbsoluteParse::Unsupported(reason),
        };
    }

    if bytes.first() == Some(&b'/') {
        return AbsoluteParse::Absolute(AbsoluteParts {
            root: AbsoluteRoot::Posix,
            components: split_components(&value[1..]),
        });
    }

    if bytes.first() == Some(&b'\\') {
        return AbsoluteParse::Unsupported(UnsupportedPathReason::WindowsRootRelative);
    }

    AbsoluteParse::NotAbsolute
}

fn contains_control_character(value: &str) -> bool {
    value
        .chars()
        .any(|character| character.is_control() || character == '\u{7f}')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationPathErrorReason {
    Url,
    Unsupported(UnsupportedPathReason),
    TrailingSeparator,
    MissingDwgFilename,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationPathError {
    path: String,
    reason: MutationPathErrorReason,
}

impl MutationPathError {
    pub fn code(&self) -> &'static str {
        "invalid_xref_path"
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn reason(&self) -> MutationPathErrorReason {
        self.reason
    }
}

impl fmt::Display for MutationPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "code={} invalid mutation XREF path `{}`: {:?}",
            self.code(),
            self.path,
            self.reason
        )
    }
}

impl std::error::Error for MutationPathError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationSourcePath(ParsedXrefPath);

impl MutationSourcePath {
    pub fn parsed(&self) -> &ParsedXrefPath {
        &self.0
    }

    pub fn saved_path(&self) -> &str {
        self.0.saved_path()
    }

    pub fn mode(&self) -> XrefPathMode {
        self.0.mode()
    }
}

fn has_dwg_extension(basename: &str) -> bool {
    basename
        .rsplit_once('.')
        .is_some_and(|(stem, extension)| !stem.is_empty() && extension.eq_ignore_ascii_case("dwg"))
}

pub fn validate_mutation_source_path(
    xref_path: &str,
) -> Result<MutationSourcePath, MutationPathError> {
    let parsed = parse_saved_path(xref_path);
    let reason = match parsed.syntax() {
        XrefPathSyntax::Url => Some(MutationPathErrorReason::Url),
        XrefPathSyntax::Unsupported(reason) => Some(MutationPathErrorReason::Unsupported(reason)),
        XrefPathSyntax::WindowsDriveAbsolute
        | XrefPathSyntax::WindowsUncAbsolute
        | XrefPathSyntax::PosixAbsolute
        | XrefPathSyntax::Relative
        | XrefPathSyntax::FilenameOnly => {
            if parsed.has_trailing_separator() {
                Some(MutationPathErrorReason::TrailingSeparator)
            } else if !parsed.basename().is_some_and(has_dwg_extension) {
                Some(MutationPathErrorReason::MissingDwgFilename)
            } else {
                None
            }
        }
    };

    match reason {
        Some(reason) => Err(MutationPathError {
            path: xref_path.to_owned(),
            reason,
        }),
        None => Ok(MutationSourcePath(parsed)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathPlatform {
    Windows,
    Posix,
}

impl PathPlatform {
    pub fn supports(self, kind: AbsolutePathKind) -> bool {
        match self {
            Self::Windows => matches!(
                kind,
                AbsolutePathKind::WindowsDrive | AbsolutePathKind::WindowsUnc
            ),
            Self::Posix => kind == AbsolutePathKind::Posix,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalPathErrorReason {
    NotAbsoluteLocalPath,
    UnsupportedSyntax(UnsupportedPathReason),
    ControlCharacter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPathError {
    path: String,
    reason: CanonicalPathErrorReason,
}

impl CanonicalPathError {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn reason(&self) -> CanonicalPathErrorReason {
        self.reason
    }
}

impl fmt::Display for CanonicalPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cannot format canonical path `{}`: {:?}",
            self.path, self.reason
        )
    }
}

impl std::error::Error for CanonicalPathError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalDisplayPath {
    value: String,
    kind: AbsolutePathKind,
}

impl CanonicalDisplayPath {
    pub fn from_filesystem_canonical_path(path: &str) -> Result<Self, CanonicalPathError> {
        if contains_control_character(path) {
            return Err(CanonicalPathError {
                path: path.to_owned(),
                reason: CanonicalPathErrorReason::ControlCharacter,
            });
        }

        let mut parts = match parse_absolute_path(path) {
            AbsoluteParse::Absolute(parts) => parts,
            AbsoluteParse::Unsupported(reason) => {
                return Err(CanonicalPathError {
                    path: path.to_owned(),
                    reason: CanonicalPathErrorReason::UnsupportedSyntax(reason),
                });
            }
            AbsoluteParse::NotAbsolute => {
                return Err(CanonicalPathError {
                    path: path.to_owned(),
                    reason: CanonicalPathErrorReason::NotAbsoluteLocalPath,
                });
            }
        };

        let mut normalized = Vec::with_capacity(parts.components.len());
        for component in parts.components.drain(..) {
            match component.as_str() {
                "." => {}
                ".." => {
                    normalized.pop();
                }
                _ => normalized.push(component),
            }
        }
        parts.components = normalized;

        let kind = parts.root.kind();
        Ok(Self {
            value: render_absolute_parts(&parts),
            kind,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn kind(&self) -> AbsolutePathKind {
        self.kind
    }

    fn parent_directory(&self) -> Option<Self> {
        let AbsoluteParse::Absolute(mut parts) = parse_absolute_path(&self.value) else {
            return None;
        };
        parts.components.pop()?;
        Some(Self {
            value: render_absolute_parts(&parts),
            kind: self.kind,
        })
    }

    fn join(&self, child: &str) -> String {
        let child = child.replace('\\', "/");
        if self.value.ends_with('/') {
            format!("{}{}", self.value, child)
        } else {
            format!("{}/{}", self.value, child)
        }
    }
}

pub(crate) fn validate_mutation_host_path_shape(
    drawing_path: &str,
) -> Result<CanonicalDisplayPath, XrefError> {
    let canonical =
        CanonicalDisplayPath::from_filesystem_canonical_path(drawing_path).map_err(|_| {
            XrefError::new(
                xref_failure_code::DRAWING_UNREADABLE,
                "drawing_path must be an absolute local filesystem path",
            )
        })?;
    let basename = canonical.as_str().rsplit('/').next().unwrap_or_default();
    let supported_extension = basename.rsplit_once('.').is_some_and(|(_, extension)| {
        extension.eq_ignore_ascii_case("dwg") || extension.eq_ignore_ascii_case("dxf")
    });
    if !supported_extension {
        return Err(XrefError::new(
            xref_failure_code::UNSUPPORTED_FORMAT,
            "drawing_path must name a .dwg or .dxf file",
        ));
    }
    Ok(canonical)
}

impl fmt::Display for CanonicalDisplayPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.value)
    }
}

impl Serialize for CanonicalDisplayPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.value)
    }
}

fn render_absolute_parts(parts: &AbsoluteParts) -> String {
    match &parts.root {
        AbsoluteRoot::Posix => {
            if parts.components.is_empty() {
                "/".to_owned()
            } else {
                format!("/{}", parts.components.join("/"))
            }
        }
        AbsoluteRoot::WindowsDrive(drive) => {
            if parts.components.is_empty() {
                format!("{drive}:/")
            } else {
                format!("{drive}:/{}", parts.components.join("/"))
            }
        }
        AbsoluteRoot::WindowsUnc { server, share } => {
            if parts.components.is_empty() {
                format!("//{server}/{share}/")
            } else {
                format!("//{server}/{share}/{}", parts.components.join("/"))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FilesystemIdentityKey {
    Posix { device: u64, inode: u64 },
    Windows { volume_serial: u64, file_id: u128 },
    Opaque(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FilesystemIdentity(FilesystemIdentityKey);

impl FilesystemIdentity {
    pub fn posix(device: u64, inode: u64) -> Self {
        Self(FilesystemIdentityKey::Posix { device, inode })
    }

    pub fn windows(volume_serial: u64, file_id: u128) -> Self {
        Self(FilesystemIdentityKey::Windows {
            volume_serial,
            file_id,
        })
    }

    pub fn opaque(bytes: impl Into<Vec<u8>>) -> Result<Self, FilesystemIdentityError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(FilesystemIdentityError);
        }
        Ok(Self(FilesystemIdentityKey::Opaque(bytes)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemIdentityError;

impl fmt::Display for FilesystemIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("filesystem identity must not be empty")
    }
}

impl std::error::Error for FilesystemIdentityError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalExistingPath {
    display_path: CanonicalDisplayPath,
    filesystem_identity: FilesystemIdentity,
}

impl CanonicalExistingPath {
    pub fn new(
        display_path: CanonicalDisplayPath,
        filesystem_identity: FilesystemIdentity,
    ) -> Self {
        Self {
            display_path,
            filesystem_identity,
        }
    }

    pub fn from_filesystem_canonical_path(
        path: &str,
        filesystem_identity: FilesystemIdentity,
    ) -> Result<Self, CanonicalPathError> {
        Ok(Self::new(
            CanonicalDisplayPath::from_filesystem_canonical_path(path)?,
            filesystem_identity,
        ))
    }

    pub fn display_path(&self) -> &CanonicalDisplayPath {
        &self.display_path
    }

    pub fn filesystem_identity(&self) -> &FilesystemIdentity {
        &self.filesystem_identity
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchPathInspection {
    ReadableDirectory(CanonicalDisplayPath),
    Missing,
    NotDirectory,
    Unreadable,
    Unrepresentable,
}

pub trait SearchPathInspector {
    fn inspect_search_path(&mut self, absolute_path: &str) -> SearchPathInspection;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchPathErrorReason {
    NotAbsoluteLocalPath,
    UnsupportedSyntax(UnsupportedPathReason),
    IncompatiblePlatform,
    Missing,
    NotDirectory,
    Unreadable,
    Unrepresentable,
    IncompatibleCanonicalPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchPathValidationError {
    index: usize,
    path: String,
    reason: SearchPathErrorReason,
}

impl SearchPathValidationError {
    pub fn code(&self) -> &'static str {
        "invalid_search_path"
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn reason(&self) -> SearchPathErrorReason {
        self.reason
    }
}

impl fmt::Display for SearchPathValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "code={} invalid search_paths[{}] `{}`: {:?}",
            self.code(),
            self.index,
            self.path,
            self.reason
        )
    }
}

impl std::error::Error for SearchPathValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSearchPath {
    index: usize,
    supplied_path: String,
    canonical_directory: CanonicalDisplayPath,
}

impl ValidatedSearchPath {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn supplied_path(&self) -> &str {
        &self.supplied_path
    }

    pub fn canonical_directory(&self) -> &CanonicalDisplayPath {
        &self.canonical_directory
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSearchPaths {
    platform: PathPlatform,
    entries: Vec<ValidatedSearchPath>,
}

impl ValidatedSearchPaths {
    pub fn empty(platform: PathPlatform) -> Self {
        Self {
            platform,
            entries: Vec::new(),
        }
    }

    pub fn platform(&self) -> PathPlatform {
        self.platform
    }

    pub fn entries(&self) -> &[ValidatedSearchPath] {
        &self.entries
    }
}

fn search_path_error(
    index: usize,
    path: &str,
    reason: SearchPathErrorReason,
) -> SearchPathValidationError {
    SearchPathValidationError {
        index,
        path: path.to_owned(),
        reason,
    }
}

pub fn validate_search_paths<S, I>(
    search_paths: &[S],
    platform: PathPlatform,
    inspector: &mut I,
) -> Result<ValidatedSearchPaths, SearchPathValidationError>
where
    S: AsRef<str>,
    I: SearchPathInspector + ?Sized,
{
    let mut entries = Vec::with_capacity(search_paths.len());
    for (index, supplied) in search_paths.iter().enumerate() {
        let supplied = supplied.as_ref();
        let parsed = parse_saved_path(supplied);
        let kind = match parsed.syntax() {
            XrefPathSyntax::WindowsDriveAbsolute => AbsolutePathKind::WindowsDrive,
            XrefPathSyntax::WindowsUncAbsolute => AbsolutePathKind::WindowsUnc,
            XrefPathSyntax::PosixAbsolute => AbsolutePathKind::Posix,
            XrefPathSyntax::Unsupported(reason) => {
                return Err(search_path_error(
                    index,
                    supplied,
                    SearchPathErrorReason::UnsupportedSyntax(reason),
                ));
            }
            XrefPathSyntax::Relative | XrefPathSyntax::FilenameOnly | XrefPathSyntax::Url => {
                return Err(search_path_error(
                    index,
                    supplied,
                    SearchPathErrorReason::NotAbsoluteLocalPath,
                ));
            }
        };

        if !platform.supports(kind) {
            return Err(search_path_error(
                index,
                supplied,
                SearchPathErrorReason::IncompatiblePlatform,
            ));
        }

        let canonical_directory = match inspector.inspect_search_path(supplied) {
            SearchPathInspection::ReadableDirectory(path) => path,
            SearchPathInspection::Missing => {
                return Err(search_path_error(
                    index,
                    supplied,
                    SearchPathErrorReason::Missing,
                ));
            }
            SearchPathInspection::NotDirectory => {
                return Err(search_path_error(
                    index,
                    supplied,
                    SearchPathErrorReason::NotDirectory,
                ));
            }
            SearchPathInspection::Unreadable => {
                return Err(search_path_error(
                    index,
                    supplied,
                    SearchPathErrorReason::Unreadable,
                ));
            }
            SearchPathInspection::Unrepresentable => {
                return Err(search_path_error(
                    index,
                    supplied,
                    SearchPathErrorReason::Unrepresentable,
                ));
            }
        };

        if !platform.supports(canonical_directory.kind()) {
            return Err(search_path_error(
                index,
                supplied,
                SearchPathErrorReason::IncompatibleCanonicalPath,
            ));
        }

        entries.push(ValidatedSearchPath {
            index,
            supplied_path: supplied.to_owned(),
            canonical_directory,
        });
    }

    Ok(ValidatedSearchPaths { platform, entries })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionCandidate {
    path: String,
    path_kind: AbsolutePathKind,
    basis: ResolutionBasis,
    search_path_index: Option<usize>,
}

impl ResolutionCandidate {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn path_kind(&self) -> AbsolutePathKind {
        self.path_kind
    }

    pub fn basis(&self) -> ResolutionBasis {
        self.basis
    }

    pub fn search_path_index(&self) -> Option<usize> {
        self.search_path_index
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionPlan {
    path_mode: XrefPathMode,
    platform: PathPlatform,
    candidates: Vec<ResolutionCandidate>,
    all_missing_state: ResolutionState,
}

impl ResolutionPlan {
    pub fn path_mode(&self) -> XrefPathMode {
        self.path_mode
    }

    pub fn platform(&self) -> PathPlatform {
        self.platform
    }

    pub fn candidates(&self) -> &[ResolutionCandidate] {
        &self.candidates
    }

    pub fn all_missing_state(&self) -> ResolutionState {
        self.all_missing_state
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionPlanError {
    IncompatibleImmediateHost,
    ImmediateHostHasNoFilename,
    SearchPathPlatformMismatch,
}

impl fmt::Display for ResolutionPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cannot build XREF resolution plan: {self:?}")
    }
}

impl std::error::Error for ResolutionPlanError {}

fn candidate(
    path: String,
    path_kind: AbsolutePathKind,
    basis: ResolutionBasis,
    search_path_index: Option<usize>,
) -> ResolutionCandidate {
    ResolutionCandidate {
        path,
        path_kind,
        basis,
        search_path_index,
    }
}

pub fn build_resolution_plan(
    saved_path: &str,
    immediate_host_path: &CanonicalDisplayPath,
    platform: PathPlatform,
    search_paths: &ValidatedSearchPaths,
) -> Result<ResolutionPlan, ResolutionPlanError> {
    if !platform.supports(immediate_host_path.kind()) {
        return Err(ResolutionPlanError::IncompatibleImmediateHost);
    }
    if search_paths.platform != platform {
        return Err(ResolutionPlanError::SearchPathPlatformMismatch);
    }
    let host_directory = immediate_host_path
        .parent_directory()
        .ok_or(ResolutionPlanError::ImmediateHostHasNoFilename)?;

    let parsed = parse_saved_path(saved_path);
    let mut candidates = Vec::new();
    let mut all_missing_state = ResolutionState::NotFound;
    let mut use_search_paths = true;

    match parsed.syntax() {
        XrefPathSyntax::WindowsDriveAbsolute => {
            if platform.supports(AbsolutePathKind::WindowsDrive) {
                candidates.push(candidate(
                    saved_path.to_owned(),
                    AbsolutePathKind::WindowsDrive,
                    ResolutionBasis::SavedAbsolute,
                    None,
                ));
            } else {
                all_missing_state = ResolutionState::Unsupported;
            }
        }
        XrefPathSyntax::WindowsUncAbsolute => {
            if platform.supports(AbsolutePathKind::WindowsUnc) {
                candidates.push(candidate(
                    saved_path.to_owned(),
                    AbsolutePathKind::WindowsUnc,
                    ResolutionBasis::SavedAbsolute,
                    None,
                ));
            } else {
                all_missing_state = ResolutionState::Unsupported;
            }
        }
        XrefPathSyntax::PosixAbsolute => {
            if platform.supports(AbsolutePathKind::Posix) {
                candidates.push(candidate(
                    saved_path.to_owned(),
                    AbsolutePathKind::Posix,
                    ResolutionBasis::SavedAbsolute,
                    None,
                ));
            } else {
                all_missing_state = ResolutionState::Unsupported;
            }
        }
        XrefPathSyntax::Relative => candidates.push(candidate(
            host_directory.join(saved_path),
            host_directory.kind(),
            ResolutionBasis::HostRelative,
            None,
        )),
        XrefPathSyntax::FilenameOnly => candidates.push(candidate(
            host_directory.join(saved_path),
            host_directory.kind(),
            ResolutionBasis::HostDirectory,
            None,
        )),
        XrefPathSyntax::Url | XrefPathSyntax::Unsupported(_) => {
            all_missing_state = ResolutionState::Unsupported;
            use_search_paths = false;
        }
    }

    if use_search_paths {
        if let Some(basename) = parsed.basename() {
            for search_path in &search_paths.entries {
                candidates.push(candidate(
                    search_path.canonical_directory.join(basename),
                    search_path.canonical_directory.kind(),
                    ResolutionBasis::ExplicitSearchPath,
                    Some(search_path.index),
                ));
            }
        }
    }

    Ok(ResolutionPlan {
        path_mode: parsed.mode(),
        platform,
        candidates,
        all_missing_state,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateProbeResult {
    Missing,
    Unresolved,
    Unsupported,
    Resolved(CanonicalExistingPath),
}

pub trait ResolutionCandidateProbe {
    fn probe_candidate(&mut self, candidate: &ResolutionCandidate) -> CandidateProbeResult;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionInvariantError {
    ResolvedPathMissing,
    ResolvedIdentityMissing,
    ResolvedBasisMissing,
    NonResolvedPathPresent,
    NonResolvedIdentityPresent,
    NonResolvedBasisPresent,
    NonResolvedSearchIndexPresent,
    ExplicitSearchIndexMissing,
    UnexpectedSearchIndex,
    ResolvedPathIncompatible,
}

impl fmt::Display for ResolutionInvariantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid XREF path resolution: {self:?}")
    }
}

impl std::error::Error for ResolutionInvariantError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XrefPathResolution {
    resolution_state: ResolutionState,
    resolved_path: Option<CanonicalDisplayPath>,
    resolution_basis: Option<ResolutionBasis>,
    search_path_index: Option<usize>,
    #[serde(skip)]
    filesystem_identity: Option<FilesystemIdentity>,
}

impl XrefPathResolution {
    pub fn try_from_parts(
        resolution_state: ResolutionState,
        resolved_path: Option<CanonicalDisplayPath>,
        filesystem_identity: Option<FilesystemIdentity>,
        resolution_basis: Option<ResolutionBasis>,
        search_path_index: Option<usize>,
    ) -> Result<Self, ResolutionInvariantError> {
        validate_resolution_parts(
            resolution_state,
            resolved_path.as_ref(),
            filesystem_identity.as_ref(),
            resolution_basis,
            search_path_index,
        )?;
        Ok(Self {
            resolution_state,
            resolved_path,
            resolution_basis,
            search_path_index,
            filesystem_identity,
        })
    }

    pub fn resolution_state(&self) -> ResolutionState {
        self.resolution_state
    }

    pub fn resolved_path(&self) -> Option<&CanonicalDisplayPath> {
        self.resolved_path.as_ref()
    }

    pub fn filesystem_identity(&self) -> Option<&FilesystemIdentity> {
        self.filesystem_identity.as_ref()
    }

    pub fn resolution_basis(&self) -> Option<ResolutionBasis> {
        self.resolution_basis
    }

    pub fn search_path_index(&self) -> Option<usize> {
        self.search_path_index
    }

    pub fn validate(&self) -> Result<(), ResolutionInvariantError> {
        validate_resolution_parts(
            self.resolution_state,
            self.resolved_path.as_ref(),
            self.filesystem_identity.as_ref(),
            self.resolution_basis,
            self.search_path_index,
        )
    }
}

fn validate_resolution_parts(
    state: ResolutionState,
    path: Option<&CanonicalDisplayPath>,
    identity: Option<&FilesystemIdentity>,
    basis: Option<ResolutionBasis>,
    search_path_index: Option<usize>,
) -> Result<(), ResolutionInvariantError> {
    if state == ResolutionState::Resolved {
        if path.is_none() {
            return Err(ResolutionInvariantError::ResolvedPathMissing);
        }
        if identity.is_none() {
            return Err(ResolutionInvariantError::ResolvedIdentityMissing);
        }
        let Some(basis) = basis else {
            return Err(ResolutionInvariantError::ResolvedBasisMissing);
        };
        match (basis, search_path_index) {
            (ResolutionBasis::ExplicitSearchPath, None) => {
                return Err(ResolutionInvariantError::ExplicitSearchIndexMissing);
            }
            (ResolutionBasis::ExplicitSearchPath, Some(_)) => {}
            (_, Some(_)) => return Err(ResolutionInvariantError::UnexpectedSearchIndex),
            (_, None) => {}
        }
    } else {
        if path.is_some() {
            return Err(ResolutionInvariantError::NonResolvedPathPresent);
        }
        if identity.is_some() {
            return Err(ResolutionInvariantError::NonResolvedIdentityPresent);
        }
        if basis.is_some() {
            return Err(ResolutionInvariantError::NonResolvedBasisPresent);
        }
        if search_path_index.is_some() {
            return Err(ResolutionInvariantError::NonResolvedSearchIndexPresent);
        }
    }
    Ok(())
}

fn terminal_resolution(state: ResolutionState) -> XrefPathResolution {
    debug_assert_ne!(state, ResolutionState::Resolved);
    XrefPathResolution::try_from_parts(state, None, None, None, None)
        .expect("terminal resolution is invariant-valid")
}

pub fn resolve_candidate_plan<P>(
    plan: &ResolutionPlan,
    probe: &mut P,
) -> Result<XrefPathResolution, ResolutionInvariantError>
where
    P: ResolutionCandidateProbe + ?Sized,
{
    for candidate in &plan.candidates {
        match probe.probe_candidate(candidate) {
            CandidateProbeResult::Missing => {}
            CandidateProbeResult::Unresolved => {
                return Ok(terminal_resolution(ResolutionState::Unresolved));
            }
            CandidateProbeResult::Unsupported => {
                return Ok(terminal_resolution(ResolutionState::Unsupported));
            }
            CandidateProbeResult::Resolved(existing) => {
                if !plan.platform.supports(existing.display_path.kind()) {
                    return Err(ResolutionInvariantError::ResolvedPathIncompatible);
                }
                return XrefPathResolution::try_from_parts(
                    ResolutionState::Resolved,
                    Some(existing.display_path),
                    Some(existing.filesystem_identity),
                    Some(candidate.basis),
                    candidate.search_path_index,
                );
            }
        }
    }

    Ok(terminal_resolution(plan.all_missing_state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn canonical(path: &str) -> CanonicalDisplayPath {
        CanonicalDisplayPath::from_filesystem_canonical_path(path).unwrap()
    }

    fn existing(path: &str, identity: u8) -> CanonicalExistingPath {
        CanonicalExistingPath::new(
            canonical(path),
            FilesystemIdentity::opaque(vec![identity]).unwrap(),
        )
    }

    #[derive(Default)]
    struct QueueSearchInspector {
        results: VecDeque<SearchPathInspection>,
        seen: Vec<String>,
    }

    impl SearchPathInspector for QueueSearchInspector {
        fn inspect_search_path(&mut self, absolute_path: &str) -> SearchPathInspection {
            self.seen.push(absolute_path.to_owned());
            self.results.pop_front().expect("missing inspection result")
        }
    }

    fn validated_search_paths(
        platform: PathPlatform,
        supplied: &[&str],
        canonical_paths: &[&str],
    ) -> ValidatedSearchPaths {
        let mut inspector = QueueSearchInspector {
            results: canonical_paths
                .iter()
                .map(|path| SearchPathInspection::ReadableDirectory(canonical(path)))
                .collect(),
            seen: Vec::new(),
        };
        validate_search_paths(supplied, platform, &mut inspector).unwrap()
    }

    #[derive(Default)]
    struct QueueCandidateProbe {
        results: VecDeque<CandidateProbeResult>,
        seen: Vec<String>,
    }

    impl ResolutionCandidateProbe for QueueCandidateProbe {
        fn probe_candidate(&mut self, candidate: &ResolutionCandidate) -> CandidateProbeResult {
            self.seen.push(candidate.path().to_owned());
            self.results.pop_front().expect("missing candidate result")
        }
    }

    #[test]
    fn classifies_windows_drive_paths_independently_of_host_os() {
        for path in [
            r"C:\refs\site.dwg",
            "c:/refs/site.dwg",
            r"\\?\C:\refs\site.dwg",
            "//?/c:/refs/site.dwg",
        ] {
            let parsed = parse_saved_path(path);
            assert_eq!(parsed.syntax(), XrefPathSyntax::WindowsDriveAbsolute);
            assert_eq!(parsed.mode(), XrefPathMode::Absolute);
            assert_eq!(parsed.basename(), Some("site.dwg"));
            assert_eq!(parsed.saved_path(), path);
        }
    }

    #[test]
    fn drive_recognition_precedes_url_recognition() {
        assert_eq!(
            parse_saved_path("C://refs/site.dwg").syntax(),
            XrefPathSyntax::WindowsDriveAbsolute
        );
    }

    #[test]
    fn classifies_unc_paths_with_both_separator_styles() {
        for path in [
            r"\\server\share\refs\site.dwg",
            "//server/share/refs/site.dwg",
            r"\\?\UNC\server\share\site.dwg",
            "//?/unc/server/share/site.dwg",
        ] {
            let parsed = parse_saved_path(path);
            assert_eq!(parsed.syntax(), XrefPathSyntax::WindowsUncAbsolute);
            assert_eq!(parsed.basename(), Some("site.dwg"));
        }
    }

    #[test]
    fn rejects_malformed_unc_and_device_paths() {
        assert_eq!(
            parse_saved_path(r"\\server").syntax(),
            XrefPathSyntax::Unsupported(UnsupportedPathReason::MalformedUnc)
        );
        assert_eq!(
            parse_saved_path(r"\\.\C:\site.dwg").syntax(),
            XrefPathSyntax::Unsupported(UnsupportedPathReason::WindowsDevicePath)
        );
        assert_eq!(
            parse_saved_path(r"\\?\GLOBALROOT\site.dwg").syntax(),
            XrefPathSyntax::Unsupported(UnsupportedPathReason::WindowsDevicePath)
        );
    }

    #[test]
    fn classifies_posix_absolute_paths_with_mixed_separators() {
        let parsed = parse_saved_path(r"/project\refs/site.dwg");
        assert_eq!(parsed.syntax(), XrefPathSyntax::PosixAbsolute);
        assert_eq!(parsed.basename(), Some("site.dwg"));
    }

    #[test]
    fn classifies_relative_forms_without_collapsing_saved_text() {
        for path in [
            "refs/site.dwg",
            r"refs\site.dwg",
            "./site.dwg",
            "../refs/site.dwg",
            ".",
            "..",
        ] {
            assert_eq!(parse_saved_path(path).mode(), XrefPathMode::Relative);
        }
        assert_eq!(parse_saved_path("./site.dwg").saved_path(), "./site.dwg");
        assert_eq!(
            parse_saved_path("../refs/site.dwg").basename(),
            Some("site.dwg")
        );
    }

    #[test]
    fn classifies_one_component_as_filename_only() {
        let parsed = parse_saved_path("site.DWG");
        assert_eq!(parsed.syntax(), XrefPathSyntax::FilenameOnly);
        assert_eq!(parsed.basename(), Some("site.DWG"));
    }

    #[test]
    fn classifies_only_allowlisted_urls_with_authority() {
        for path in [
            "http://example.test/site.dwg",
            "HTTPS://example.test/site.dwg",
            "FtP://user@example.test/site.dwg",
        ] {
            assert_eq!(parse_saved_path(path).syntax(), XrefPathSyntax::Url);
        }
        for path in ["http:///site.dwg", "https://", "ftp:site.dwg"] {
            assert_eq!(
                parse_saved_path(path).syntax(),
                XrefPathSyntax::Unsupported(UnsupportedPathReason::MalformedUrl)
            );
        }
    }

    #[test]
    fn classifies_unknown_schemes_as_unsupported() {
        for path in [
            "file:///project/site.dwg",
            "s3://bucket/site.dwg",
            "mailto:site.dwg",
        ] {
            assert_eq!(
                parse_saved_path(path).syntax(),
                XrefPathSyntax::Unsupported(UnsupportedPathReason::UnsupportedScheme)
            );
        }
    }

    #[test]
    fn classifies_ambient_and_ambiguous_forms_as_unsupported() {
        let cases = [
            ("", UnsupportedPathReason::Empty),
            (r"C:site.dwg", UnsupportedPathReason::DriveRelative),
            (
                r"\refs\site.dwg",
                UnsupportedPathReason::WindowsRootRelative,
            ),
            ("~/site.dwg", UnsupportedPathReason::HomeExpansion),
            (
                "$HOME/site.dwg",
                UnsupportedPathReason::EnvironmentExpansion,
            ),
            (
                r"%USERPROFILE%\site.dwg",
                UnsupportedPathReason::EnvironmentExpansion,
            ),
            (
                r"!XREF_ROOT!\site.dwg",
                UnsupportedPathReason::EnvironmentExpansion,
            ),
            (
                "/project/${NAME}/site.dwg",
                UnsupportedPathReason::EnvironmentExpansion,
            ),
            ("site\n.dwg", UnsupportedPathReason::ControlCharacter),
        ];
        for (path, reason) in cases {
            assert_eq!(
                parse_saved_path(path).syntax(),
                XrefPathSyntax::Unsupported(reason),
                "{path:?}"
            );
        }
    }

    #[test]
    fn mutation_validation_accepts_only_supported_dwg_paths() {
        for path in [
            r"C:\refs\site.dwg",
            r"\\server\share\site.DWG",
            "/project/site.DwG",
            "refs/site.dwg",
            "./site.dwg",
            "../site.dwg",
            "site.dwg",
        ] {
            let validated = validate_mutation_source_path(path).unwrap();
            assert_eq!(validated.saved_path(), path);
            assert!(matches!(
                validated.mode(),
                XrefPathMode::Absolute | XrefPathMode::Relative | XrefPathMode::FilenameOnly
            ));
        }
    }

    #[test]
    fn mutation_validation_rejects_urls_unsupported_forms_and_non_dwg_paths() {
        let cases = [
            (
                "https://example.test/site.dwg",
                MutationPathErrorReason::Url,
            ),
            (
                r"C:site.dwg",
                MutationPathErrorReason::Unsupported(UnsupportedPathReason::DriveRelative),
            ),
            ("site.dxf", MutationPathErrorReason::MissingDwgFilename),
            (".dwg", MutationPathErrorReason::MissingDwgFilename),
            ("refs/site.dwg/", MutationPathErrorReason::TrailingSeparator),
        ];
        for (path, reason) in cases {
            let error = validate_mutation_source_path(path).unwrap_err();
            assert_eq!(error.code(), "invalid_xref_path");
            assert_eq!(error.path(), path);
            assert_eq!(error.reason(), reason);
        }
    }

    #[test]
    fn canonical_display_normalizes_windows_paths_without_case_folding_components() {
        let cases = [
            (r"c:\Project\.\Refs\..\SITE.dwg", "C:/Project/SITE.dwg"),
            (
                r"\\?\c:\Project\\Refs\site.dwg\",
                "C:/Project/Refs/site.dwg",
            ),
            (
                r"\\?\UNC\Server\Share\Refs\..\Site.dwg",
                "//Server/Share/Site.dwg",
            ),
            (
                r"\\Server\Share\\Refs\.\Site.dwg\",
                "//Server/Share/Refs/Site.dwg",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(canonical(input).as_str(), expected, "{input}");
        }
    }

    #[test]
    fn canonical_display_normalizes_posix_paths() {
        assert_eq!(
            canonical("/project//jobs/./refs/../site.dwg/").as_str(),
            "/project/jobs/site.dwg"
        );
        assert_eq!(canonical("/../../site.dwg").as_str(), "/site.dwg");
    }

    #[test]
    fn canonical_display_preserves_root_trailing_separators_only() {
        assert_eq!(canonical("/").as_str(), "/");
        assert_eq!(canonical(r"c:\").as_str(), "C:/");
        assert_eq!(canonical(r"\\server\share\").as_str(), "//server/share/");
        assert_eq!(canonical(r"c:\project\").as_str(), "C:/project");
    }

    #[test]
    fn canonical_display_rejects_non_absolute_and_unsupported_paths() {
        assert_eq!(
            CanonicalDisplayPath::from_filesystem_canonical_path("site.dwg")
                .unwrap_err()
                .reason(),
            CanonicalPathErrorReason::NotAbsoluteLocalPath
        );
        assert_eq!(
            CanonicalDisplayPath::from_filesystem_canonical_path(r"\site.dwg")
                .unwrap_err()
                .reason(),
            CanonicalPathErrorReason::UnsupportedSyntax(UnsupportedPathReason::WindowsRootRelative)
        );
    }

    #[test]
    fn canonical_display_and_filesystem_identity_are_distinct() {
        let first_identity = FilesystemIdentity::posix(10, 20);
        let same_identity = FilesystemIdentity::posix(10, 20);
        let different_identity = FilesystemIdentity::posix(10, 21);
        let first = CanonicalExistingPath::new(canonical("/real/site.dwg"), first_identity);
        let alias = CanonicalExistingPath::new(canonical("/alias/site.dwg"), same_identity);
        let other = CanonicalExistingPath::new(canonical("/real/site.dwg"), different_identity);

        assert_ne!(first.display_path(), alias.display_path());
        assert_eq!(first.filesystem_identity(), alias.filesystem_identity());
        assert_eq!(first.display_path(), other.display_path());
        assert_ne!(first.filesystem_identity(), other.filesystem_identity());
        assert!(FilesystemIdentity::opaque(Vec::<u8>::new()).is_err());
    }

    #[test]
    fn search_path_validation_preserves_caller_order_and_canonical_evidence() {
        let supplied = ["/search/first", "/search/alias"];
        let mut inspector = QueueSearchInspector {
            results: VecDeque::from([
                SearchPathInspection::ReadableDirectory(canonical("/search/first")),
                SearchPathInspection::ReadableDirectory(canonical("/real/second")),
            ]),
            seen: Vec::new(),
        };
        let validated =
            validate_search_paths(&supplied, PathPlatform::Posix, &mut inspector).unwrap();

        assert_eq!(inspector.seen, supplied);
        assert_eq!(validated.entries()[0].index(), 0);
        assert_eq!(validated.entries()[0].supplied_path(), "/search/first");
        assert_eq!(
            validated.entries()[1].canonical_directory().as_str(),
            "/real/second"
        );
    }

    #[test]
    fn search_path_validation_rejects_syntax_before_inspection() {
        let mut inspector = QueueSearchInspector::default();
        let error =
            validate_search_paths(&["relative/search"], PathPlatform::Posix, &mut inspector)
                .unwrap_err();
        assert_eq!(error.code(), "invalid_search_path");
        assert_eq!(error.index(), 0);
        assert_eq!(error.reason(), SearchPathErrorReason::NotAbsoluteLocalPath);
        assert!(inspector.seen.is_empty());
    }

    #[test]
    fn search_path_validation_rejects_platform_incompatible_paths() {
        let mut inspector = QueueSearchInspector::default();
        let error = validate_search_paths(&[r"C:\search"], PathPlatform::Posix, &mut inspector)
            .unwrap_err();
        assert_eq!(error.reason(), SearchPathErrorReason::IncompatiblePlatform);
        assert!(inspector.seen.is_empty());
    }

    #[test]
    fn search_path_validation_maps_every_filesystem_failure() {
        let cases = [
            (
                SearchPathInspection::Missing,
                SearchPathErrorReason::Missing,
            ),
            (
                SearchPathInspection::NotDirectory,
                SearchPathErrorReason::NotDirectory,
            ),
            (
                SearchPathInspection::Unreadable,
                SearchPathErrorReason::Unreadable,
            ),
            (
                SearchPathInspection::Unrepresentable,
                SearchPathErrorReason::Unrepresentable,
            ),
        ];
        for (inspection, expected) in cases {
            let mut inspector = QueueSearchInspector {
                results: VecDeque::from([inspection]),
                seen: Vec::new(),
            };
            let error = validate_search_paths(&["/search"], PathPlatform::Posix, &mut inspector)
                .unwrap_err();
            assert_eq!(error.reason(), expected);
        }
    }

    #[test]
    fn search_path_validation_rejects_incompatible_canonical_evidence() {
        let mut inspector = QueueSearchInspector {
            results: VecDeque::from([SearchPathInspection::ReadableDirectory(canonical(
                r"C:\search",
            ))]),
            seen: Vec::new(),
        };
        let error =
            validate_search_paths(&["/search"], PathPlatform::Posix, &mut inspector).unwrap_err();
        assert_eq!(
            error.reason(),
            SearchPathErrorReason::IncompatibleCanonicalPath
        );
    }

    #[test]
    fn relative_candidate_order_is_host_then_explicit_search_paths() {
        let host = canonical("/project/jobs/host.dwg");
        let searches = validated_search_paths(
            PathPlatform::Posix,
            &["/search/one", "/search/two"],
            &["/search/one", "/search/two"],
        );
        let plan = build_resolution_plan("../refs/site.dwg", &host, PathPlatform::Posix, &searches)
            .unwrap();

        assert_eq!(plan.path_mode(), XrefPathMode::Relative);
        assert_eq!(
            plan.candidates()
                .iter()
                .map(ResolutionCandidate::path)
                .collect::<Vec<_>>(),
            [
                "/project/jobs/../refs/site.dwg",
                "/search/one/site.dwg",
                "/search/two/site.dwg"
            ]
        );
        assert_eq!(plan.candidates()[0].basis(), ResolutionBasis::HostRelative);
        assert_eq!(
            plan.candidates()[1].basis(),
            ResolutionBasis::ExplicitSearchPath
        );
        assert_eq!(plan.candidates()[1].search_path_index(), Some(0));
        assert_eq!(plan.candidates()[2].search_path_index(), Some(1));
        assert_eq!(plan.all_missing_state(), ResolutionState::NotFound);
    }

    #[test]
    fn relative_backslashes_are_path_separators_on_posix() {
        let plan = build_resolution_plan(
            r"..\refs\site.dwg",
            &canonical("/project/jobs/host.dwg"),
            PathPlatform::Posix,
            &ValidatedSearchPaths::empty(PathPlatform::Posix),
        )
        .unwrap();
        assert_eq!(
            plan.candidates()[0].path(),
            "/project/jobs/../refs/site.dwg"
        );
    }

    #[test]
    fn filename_only_uses_host_directory_basis() {
        let plan = build_resolution_plan(
            "site.dwg",
            &canonical("/project/host.dwg"),
            PathPlatform::Posix,
            &ValidatedSearchPaths::empty(PathPlatform::Posix),
        )
        .unwrap();
        assert_eq!(plan.candidates()[0].path(), "/project/site.dwg");
        assert_eq!(plan.candidates()[0].basis(), ResolutionBasis::HostDirectory);
    }

    #[test]
    fn compatible_absolute_path_is_probed_before_search_fallback() {
        let searches =
            validated_search_paths(PathPlatform::Windows, &[r"D:\search"], &[r"D:\search"]);
        let plan = build_resolution_plan(
            r"C:\refs\site.dwg",
            &canonical(r"C:\project\host.dwg"),
            PathPlatform::Windows,
            &searches,
        )
        .unwrap();
        assert_eq!(
            plan.candidates()
                .iter()
                .map(ResolutionCandidate::path)
                .collect::<Vec<_>>(),
            [r"C:\refs\site.dwg", "D:/search/site.dwg"]
        );
        assert_eq!(plan.candidates()[0].basis(), ResolutionBasis::SavedAbsolute);
        assert_eq!(plan.all_missing_state(), ResolutionState::NotFound);
    }

    #[test]
    fn incompatible_absolute_path_uses_only_search_fallback_and_stays_unsupported_if_missing() {
        let searches = validated_search_paths(
            PathPlatform::Posix,
            &["/search/one", "/search/two"],
            &["/search/one", "/search/two"],
        );
        let plan = build_resolution_plan(
            r"C:\refs\site.dwg",
            &canonical("/project/host.dwg"),
            PathPlatform::Posix,
            &searches,
        )
        .unwrap();
        assert_eq!(
            plan.candidates()
                .iter()
                .map(ResolutionCandidate::path)
                .collect::<Vec<_>>(),
            ["/search/one/site.dwg", "/search/two/site.dwg"]
        );
        assert_eq!(plan.all_missing_state(), ResolutionState::Unsupported);
    }

    #[test]
    fn incompatible_absolute_path_without_search_paths_has_no_candidates() {
        let plan = build_resolution_plan(
            r"C:\refs\site.dwg",
            &canonical("/project/host.dwg"),
            PathPlatform::Posix,
            &ValidatedSearchPaths::empty(PathPlatform::Posix),
        )
        .unwrap();
        assert!(plan.candidates().is_empty());
        assert_eq!(plan.all_missing_state(), ResolutionState::Unsupported);
    }

    #[test]
    fn url_and_unsupported_paths_never_generate_candidates() {
        let searches = validated_search_paths(PathPlatform::Posix, &["/search"], &["/search"]);
        for saved_path in ["https://example.test/site.dwg", r"C:site.dwg"] {
            let plan = build_resolution_plan(
                saved_path,
                &canonical("/project/host.dwg"),
                PathPlatform::Posix,
                &searches,
            )
            .unwrap();
            assert!(plan.candidates().is_empty());
            assert_eq!(plan.all_missing_state(), ResolutionState::Unsupported);
        }
    }

    #[test]
    fn explicit_search_duplicates_are_not_deduplicated() {
        let searches = validated_search_paths(
            PathPlatform::Posix,
            &["/search", "/search"],
            &["/search", "/search"],
        );
        let plan = build_resolution_plan(
            "site.dwg",
            &canonical("/project/host.dwg"),
            PathPlatform::Posix,
            &searches,
        )
        .unwrap();
        assert_eq!(plan.candidates().len(), 3);
        assert_eq!(plan.candidates()[1].path(), plan.candidates()[2].path());
        assert_eq!(plan.candidates()[1].search_path_index(), Some(0));
        assert_eq!(plan.candidates()[2].search_path_index(), Some(1));
    }

    #[test]
    fn nested_relative_paths_use_the_immediate_host() {
        let plan = build_resolution_plan(
            "../child/site.dwg",
            &canonical("/sources/parent/parent.dwg"),
            PathPlatform::Posix,
            &ValidatedSearchPaths::empty(PathPlatform::Posix),
        )
        .unwrap();
        assert_eq!(
            plan.candidates()[0].path(),
            "/sources/parent/../child/site.dwg"
        );
    }

    #[test]
    fn plan_rejects_incompatible_host_and_search_platforms() {
        let error = build_resolution_plan(
            "site.dwg",
            &canonical(r"C:\project\host.dwg"),
            PathPlatform::Posix,
            &ValidatedSearchPaths::empty(PathPlatform::Posix),
        )
        .unwrap_err();
        assert_eq!(error, ResolutionPlanError::IncompatibleImmediateHost);

        let error = build_resolution_plan(
            "site.dwg",
            &canonical("/project/host.dwg"),
            PathPlatform::Posix,
            &ValidatedSearchPaths::empty(PathPlatform::Windows),
        )
        .unwrap_err();
        assert_eq!(error, ResolutionPlanError::SearchPathPlatformMismatch);
    }

    #[test]
    fn resolution_uses_first_resolved_candidate_and_preserves_identity() {
        let searches = validated_search_paths(PathPlatform::Posix, &["/search"], &["/search"]);
        let plan = build_resolution_plan(
            "site.dwg",
            &canonical("/project/host.dwg"),
            PathPlatform::Posix,
            &searches,
        )
        .unwrap();
        let expected_identity = FilesystemIdentity::posix(1, 99);
        let mut probe = QueueCandidateProbe {
            results: VecDeque::from([CandidateProbeResult::Resolved(CanonicalExistingPath::new(
                canonical("/real/project/site.dwg"),
                expected_identity.clone(),
            ))]),
            seen: Vec::new(),
        };

        let resolution = resolve_candidate_plan(&plan, &mut probe).unwrap();
        assert_eq!(probe.seen, ["/project/site.dwg"]);
        assert_eq!(resolution.resolution_state(), ResolutionState::Resolved);
        assert_eq!(
            resolution.resolved_path().unwrap().as_str(),
            "/real/project/site.dwg"
        );
        assert_eq!(resolution.filesystem_identity(), Some(&expected_identity));
        assert_eq!(
            resolution.resolution_basis(),
            Some(ResolutionBasis::HostDirectory)
        );
        assert_eq!(resolution.search_path_index(), None);
        resolution.validate().unwrap();
    }

    #[test]
    fn resolution_reports_explicit_search_basis_and_index() {
        let searches = validated_search_paths(
            PathPlatform::Posix,
            &["/search/first", "/search/second"],
            &["/search/first", "/search/second"],
        );
        let plan = build_resolution_plan(
            "site.dwg",
            &canonical("/project/host.dwg"),
            PathPlatform::Posix,
            &searches,
        )
        .unwrap();
        let mut probe = QueueCandidateProbe {
            results: VecDeque::from([
                CandidateProbeResult::Missing,
                CandidateProbeResult::Missing,
                CandidateProbeResult::Resolved(existing("/search/second/site.dwg", 3)),
            ]),
            seen: Vec::new(),
        };

        let resolution = resolve_candidate_plan(&plan, &mut probe).unwrap();
        assert_eq!(
            resolution.resolution_basis(),
            Some(ResolutionBasis::ExplicitSearchPath)
        );
        assert_eq!(resolution.search_path_index(), Some(1));
    }

    #[test]
    fn existing_unresolved_candidate_stops_fallback() {
        let searches = validated_search_paths(PathPlatform::Posix, &["/search"], &["/search"]);
        let plan = build_resolution_plan(
            "site.dwg",
            &canonical("/project/host.dwg"),
            PathPlatform::Posix,
            &searches,
        )
        .unwrap();
        let mut probe = QueueCandidateProbe {
            results: VecDeque::from([CandidateProbeResult::Unresolved]),
            seen: Vec::new(),
        };

        let resolution = resolve_candidate_plan(&plan, &mut probe).unwrap();
        assert_eq!(resolution.resolution_state(), ResolutionState::Unresolved);
        assert_eq!(probe.seen, ["/project/site.dwg"]);
        assert_eq!(resolution.resolved_path(), None);
        assert_eq!(resolution.resolution_basis(), None);
    }

    #[test]
    fn unsupported_candidate_stops_fallback() {
        let searches = validated_search_paths(PathPlatform::Posix, &["/search"], &["/search"]);
        let plan = build_resolution_plan(
            "site.dwg",
            &canonical("/project/host.dwg"),
            PathPlatform::Posix,
            &searches,
        )
        .unwrap();
        let mut probe = QueueCandidateProbe {
            results: VecDeque::from([CandidateProbeResult::Unsupported]),
            seen: Vec::new(),
        };
        let resolution = resolve_candidate_plan(&plan, &mut probe).unwrap();
        assert_eq!(resolution.resolution_state(), ResolutionState::Unsupported);
        assert_eq!(probe.seen.len(), 1);
    }

    #[test]
    fn all_missing_supported_candidates_are_not_found() {
        let plan = build_resolution_plan(
            "site.dwg",
            &canonical("/project/host.dwg"),
            PathPlatform::Posix,
            &ValidatedSearchPaths::empty(PathPlatform::Posix),
        )
        .unwrap();
        let mut probe = QueueCandidateProbe {
            results: VecDeque::from([CandidateProbeResult::Missing]),
            seen: Vec::new(),
        };
        let resolution = resolve_candidate_plan(&plan, &mut probe).unwrap();
        assert_eq!(resolution.resolution_state(), ResolutionState::NotFound);
    }

    #[test]
    fn all_missing_incompatible_absolute_candidates_are_unsupported() {
        let searches = validated_search_paths(PathPlatform::Posix, &["/search"], &["/search"]);
        let plan = build_resolution_plan(
            r"C:\refs\site.dwg",
            &canonical("/project/host.dwg"),
            PathPlatform::Posix,
            &searches,
        )
        .unwrap();
        let mut probe = QueueCandidateProbe {
            results: VecDeque::from([CandidateProbeResult::Missing]),
            seen: Vec::new(),
        };
        let resolution = resolve_candidate_plan(&plan, &mut probe).unwrap();
        assert_eq!(resolution.resolution_state(), ResolutionState::Unsupported);
    }

    #[test]
    fn resolution_invariants_require_all_resolved_fields() {
        let path = canonical("/project/site.dwg");
        let identity = FilesystemIdentity::opaque(b"site".to_vec()).unwrap();

        assert_eq!(
            XrefPathResolution::try_from_parts(
                ResolutionState::Resolved,
                None,
                Some(identity.clone()),
                Some(ResolutionBasis::SavedAbsolute),
                None,
            )
            .unwrap_err(),
            ResolutionInvariantError::ResolvedPathMissing
        );
        assert_eq!(
            XrefPathResolution::try_from_parts(
                ResolutionState::Resolved,
                Some(path.clone()),
                None,
                Some(ResolutionBasis::SavedAbsolute),
                None,
            )
            .unwrap_err(),
            ResolutionInvariantError::ResolvedIdentityMissing
        );
        assert_eq!(
            XrefPathResolution::try_from_parts(
                ResolutionState::Resolved,
                Some(path),
                Some(identity),
                None,
                None,
            )
            .unwrap_err(),
            ResolutionInvariantError::ResolvedBasisMissing
        );
    }

    #[test]
    fn resolution_invariants_enforce_search_index_iff_explicit_basis() {
        let path = canonical("/search/site.dwg");
        let identity = FilesystemIdentity::opaque(b"site".to_vec()).unwrap();
        assert_eq!(
            XrefPathResolution::try_from_parts(
                ResolutionState::Resolved,
                Some(path.clone()),
                Some(identity.clone()),
                Some(ResolutionBasis::ExplicitSearchPath),
                None,
            )
            .unwrap_err(),
            ResolutionInvariantError::ExplicitSearchIndexMissing
        );
        assert_eq!(
            XrefPathResolution::try_from_parts(
                ResolutionState::Resolved,
                Some(path),
                Some(identity),
                Some(ResolutionBasis::HostDirectory),
                Some(0),
            )
            .unwrap_err(),
            ResolutionInvariantError::UnexpectedSearchIndex
        );
    }

    #[test]
    fn resolution_invariants_forbid_metadata_on_non_resolved_states() {
        let path = canonical("/project/site.dwg");
        let identity = FilesystemIdentity::opaque(b"site".to_vec()).unwrap();
        assert_eq!(
            XrefPathResolution::try_from_parts(
                ResolutionState::NotFound,
                Some(path),
                None,
                None,
                None,
            )
            .unwrap_err(),
            ResolutionInvariantError::NonResolvedPathPresent
        );
        assert_eq!(
            XrefPathResolution::try_from_parts(
                ResolutionState::Unresolved,
                None,
                Some(identity),
                None,
                None,
            )
            .unwrap_err(),
            ResolutionInvariantError::NonResolvedIdentityPresent
        );
        assert_eq!(
            XrefPathResolution::try_from_parts(
                ResolutionState::Unsupported,
                None,
                None,
                Some(ResolutionBasis::HostRelative),
                None,
            )
            .unwrap_err(),
            ResolutionInvariantError::NonResolvedBasisPresent
        );
    }

    #[test]
    fn resolution_serialization_excludes_filesystem_identity() {
        let resolution = XrefPathResolution::try_from_parts(
            ResolutionState::Resolved,
            Some(canonical("/project/site.dwg")),
            Some(FilesystemIdentity::opaque(b"secret-identity".to_vec()).unwrap()),
            Some(ResolutionBasis::SavedAbsolute),
            None,
        )
        .unwrap();
        let json = serde_json::to_value(resolution).unwrap();
        assert_eq!(json["resolution_state"], "resolved");
        assert_eq!(json["resolved_path"], "/project/site.dwg");
        assert_eq!(json["resolution_basis"], "saved_absolute");
        assert_eq!(json["search_path_index"], serde_json::Value::Null);
        assert!(json.get("filesystem_identity").is_none());
        assert!(!json.to_string().contains("secret-identity"));
    }

    #[test]
    fn resolved_probe_path_must_match_the_explicit_platform() {
        let plan = build_resolution_plan(
            "site.dwg",
            &canonical("/project/host.dwg"),
            PathPlatform::Posix,
            &ValidatedSearchPaths::empty(PathPlatform::Posix),
        )
        .unwrap();
        let mut probe = QueueCandidateProbe {
            results: VecDeque::from([CandidateProbeResult::Resolved(existing(
                r"C:\project\site.dwg",
                1,
            ))]),
            seen: Vec::new(),
        };
        assert_eq!(
            resolve_candidate_plan(&plan, &mut probe).unwrap_err(),
            ResolutionInvariantError::ResolvedPathIncompatible
        );
    }
}
