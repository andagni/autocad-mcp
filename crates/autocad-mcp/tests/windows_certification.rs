use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::process::Child;

use autocad_mcp::certification::{
    certification_layer_output_sha256, certification_layer_readback_sha256,
    certification_layer_state_key_sha256, certification_manifest_sha256,
    certification_title_layer_sha256, certification_title_snapshot_sha256,
    certification_title_value_sha256, embedded_certification_profile_definitions,
    embedded_xref_artifacts, inspect_xref_certification_format,
    layer_certification_profile_launch_expectation, validate_layer_mutation_evidence,
    validate_layer_mutation_manifest, validate_release_manifest,
    validate_tier2_profile_certification_artifacts, validate_tier2_profile_certification_evidence,
    validate_xref_certification_attestation, validate_xref_certification_bundle,
    validate_xref_certification_manifest, xref_certification_manifest_sha256,
    xref_certification_profile_launch_expectation, xref_certification_profile_references,
    xref_embedded_artifact_sha256, xref_sha256_bytes, xref_sha256_file,
    CertificationActivationTarget, CertificationEvidenceClass, CertificationExpandedLayerRecord,
    CertificationHashedTitleBlockAttribute, CertificationHashedTitleBlockRecord,
    CertificationLayerObservedResult, CertificationLayerStateSource,
    CertificationLayerToolObservation, CertificationManifest, CertificationObservedToolStatus,
    CertificationPlotEvidence, CertificationProfileDefinition,
    CertificationProfileIsolationEvidence, CertificationProfileLaunchExpectation,
    CertificationReferencedSourceEvidence, CertificationResolvedSourceEvidence,
    CertificationResultStatus, CertificationRuntimeEvidence, CertificationRuntimeRequirements,
    CertificationTitleBlockFingerprint, CertificationTitleBlockSnapshot,
    LayerCertificationExpectedOutcome, LayerCertificationFixtureKind,
    LayerCertificationPassedAssertion, LayerConfinementSnapshotEvidence, LayerMutationCaseEvidence,
    LayerMutationCertificationEvidence, LayerMutationCertificationOperation,
    LayerMutationCertificationTool, LayerMutationOperationEvidence,
    Tier2DrawingCertificationEvidence, Tier2ProfileCertificationEvidence,
    XrefArtifactCleanupEvidence, XrefCertificationAttestation, XrefCertificationBuildIdentity,
    XrefCertificationCase, XrefCertificationCaseFailure, XrefCertificationCaseResult,
    XrefCertificationEvidence, XrefCertificationEvidenceClass, XrefCertificationExpectedStatus,
    XrefCertificationFailpoint, XrefCertificationFailureStage, XrefCertificationManifest,
    XrefCertificationResultStatus, XrefCertificationScenario, XrefMutationOperation,
    CERTIFICATION_SCHEMA_VERSION, LAYER_MUTATION_WINDOWS_EVIDENCE_FILE,
    TIER2_PROFILE_WINDOWS_EVIDENCE_FILE, XREF_CERTIFICATION_ATTESTATION_FILE,
    XREF_CERTIFICATION_SCHEMA_VERSION, XREF_TRANSACTION_EVIDENCE_FILE, XREF_WINDOWS_EVIDENCE_FILE,
};
use autocad_mcp::engine;
use autocad_mcp::ops::layers::LayerRecord;
use autocad_mcp::ops::profiles;
use autocad_mcp::ops::xref_path::CanonicalDisplayPath;
use autocad_mcp::ops::xrefs::{
    canonical_input_handle, xref_name_eq, ReferenceType, XrefDependencyTraversalEnvelope,
    XrefInspectionState, XrefResolutionState,
};

const XREF_CERTIFICATION_INFO_SCHEMA_VERSION: u64 = 4;

#[derive(Debug, Clone, Eq, PartialEq)]
struct StrictCertificationInputs {
    manifest_path: PathBuf,
    output_dir: PathBuf,
}

fn strict_windows_inputs(
    platform: &str,
    manifest_path: Option<PathBuf>,
    output_dir: Option<PathBuf>,
) -> Result<StrictCertificationInputs, String> {
    if platform != "windows" {
        return Err(format!(
            "strict Windows certification requires Windows; current platform is {platform}"
        ));
    }
    let manifest_path = manifest_path
        .ok_or_else(|| "strict Windows certification requires a manifest".to_string())?;
    let output_dir = output_dir.ok_or_else(|| {
        "strict Windows certification requires an evidence output directory".to_string()
    })?;
    Ok(StrictCertificationInputs {
        manifest_path,
        output_dir,
    })
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct StagedCertificationFile {
    source_path: PathBuf,
    staged_path: PathBuf,
    sha256: String,
}

fn create_fresh_certification_case_root(path: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir(path).map_err(|error| {
        format!(
            "certification case root must be new at {}: {error}",
            path.display()
        )
    })?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect fresh case root {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "fresh certification case root is not a real directory: {}",
            path.display()
        ));
    }
    path.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize case root {}: {error}",
            path.display()
        )
    })?;
    Ok(path.to_path_buf())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CertificationFileIdentity {
    #[cfg(windows)]
    Windows {
        volume_serial_number: u64,
        file_id: [u8; 16],
    },
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(not(any(windows, unix)))]
    Unsupported,
}

#[derive(Debug)]
struct ExactCertificationFile {
    configured_path: String,
    canonical_path: PathBuf,
    sha256_before: String,
    guard: File,
    identity: CertificationFileIdentity,
    #[cfg(windows)]
    directory_guards: Vec<ExactCertificationDirectoryGuard>,
}

#[cfg(windows)]
#[derive(Debug)]
struct ExactCertificationDirectoryGuard {
    canonical_path: PathBuf,
    guard: File,
    identity: CertificationFileIdentity,
}

fn certification_file_identity(
    file: &File,
    label: &str,
) -> Result<CertificationFileIdentity, String> {
    #[cfg(windows)]
    {
        use std::mem::size_of;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
        };

        let mut info = FILE_ID_INFO::default();
        let succeeded = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut info as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        };
        if succeeded == 0 {
            return Err(format!(
                "cannot query {label} identity: {}",
                std::io::Error::last_os_error()
            ));
        }
        if info.FileId.Identifier == [0; 16] {
            return Err(format!(
                "{label} does not expose an unambiguous volume/file identity"
            ));
        }
        Ok(CertificationFileIdentity::Windows {
            volume_serial_number: info.VolumeSerialNumber,
            file_id: info.FileId.Identifier,
        })
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = file
            .metadata()
            .map_err(|error| format!("failed to query {label} identity: {error}"))?;
        Ok(CertificationFileIdentity::Unix {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (file, label);
        Ok(CertificationFileIdentity::Unsupported)
    }
}

#[cfg(windows)]
fn certification_handle_is_reparse_point(file: &File, label: &str) -> Result<bool, String> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO,
    };

    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if succeeded == 0 {
        return Err(format!(
            "cannot query {label} reparse attributes: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

fn open_exact_certification_file(path: &Path, label: &str) -> Result<File, String> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::GENERIC_READ;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };

        let mut options = std::fs::OpenOptions::new();
        options
            .access_mode(GENERIC_READ)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        options
            .open(path)
            .map_err(|error| format!("failed to open guarded {label} {}: {error}", path.display()))
    }
    #[cfg(not(windows))]
    {
        File::open(path)
            .map_err(|error| format!("failed to open guarded {label} {}: {error}", path.display()))
    }
}

#[cfg(windows)]
fn open_exact_certification_directory(
    path: &Path,
    label: &str,
) -> Result<ExactCertificationDirectoryGuard, String> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = std::fs::OpenOptions::new();
    options
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let guard = options.open(path).map_err(|error| {
        format!(
            "failed to open guarded {label} directory {}: {error}",
            path.display()
        )
    })?;
    let metadata = guard.metadata().map_err(|error| {
        format!(
            "failed to inspect guarded {label} directory {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "guarded {label} directory is not a direct directory: {}",
            path.display()
        ));
    }
    if certification_handle_is_reparse_point(&guard, &format!("{label} directory"))? {
        return Err(format!(
            "guarded {label} directory must not be a reparse point: {}",
            path.display()
        ));
    }
    let identity = certification_file_identity(&guard, &format!("{label} directory"))?;
    Ok(ExactCertificationDirectoryGuard {
        canonical_path: path.to_path_buf(),
        guard,
        identity,
    })
}

#[cfg(windows)]
fn guard_exact_certification_directory_chain(
    canonical_file: &Path,
    label: &str,
) -> Result<Vec<ExactCertificationDirectoryGuard>, String> {
    let parent = canonical_file
        .parent()
        .ok_or_else(|| format!("{label} canonical path has no parent"))?;
    parent
        .ancestors()
        .map(|directory| open_exact_certification_directory(directory, label))
        .collect()
}

#[cfg(windows)]
fn verify_exact_certification_directory_chain(
    directories: &[ExactCertificationDirectoryGuard],
    label: &str,
) -> Result<(), String> {
    for directory in directories.iter().rev() {
        if certification_file_identity(&directory.guard, &format!("{label} retained directory"))?
            != directory.identity
        {
            return Err(format!(
                "{label} guarded directory identity changed: {}",
                directory.canonical_path.display()
            ));
        }
        let current = open_exact_certification_directory(&directory.canonical_path, label)?;
        if current.identity != directory.identity {
            return Err(format!(
                "{label} canonical directory resolved to a different identity during certification: {}",
                directory.canonical_path.display()
            ));
        }
    }
    Ok(())
}

fn sha256_certification_file_handle(file: &File, label: &str) -> Result<String, String> {
    let mut reader = file
        .try_clone()
        .map_err(|error| format!("failed to clone guarded {label} handle: {error}"))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("failed to rewind guarded {label}: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("failed to hash guarded {label}: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct CertifiedArgProfileRoot {
    hkcu_subkey: String,
}

fn decode_certified_arg(bytes: &[u8]) -> Result<String, String> {
    fn decode_utf16(bytes: &[u8], little_endian: bool) -> Result<String, String> {
        if !bytes.len().is_multiple_of(2) {
            return Err("certified ARG has an odd-length UTF-16 payload".to_string());
        }
        let code_units = bytes
            .chunks_exact(2)
            .map(|pair| {
                if little_endian {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                }
            })
            .collect::<Vec<_>>();
        String::from_utf16(&code_units)
            .map_err(|error| format!("certified ARG is not valid UTF-16: {error}"))
    }

    let decoded = if let Some(payload) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        std::str::from_utf8(payload)
            .map(str::to_string)
            .map_err(|error| format!("certified ARG is not valid BOM-marked UTF-8: {error}"))?
    } else if let Some(payload) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        decode_utf16(payload, true)?
    } else if let Some(payload) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        decode_utf16(payload, false)?
    } else {
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|error| {
                format!("certified ARG is neither UTF-8 nor BOM-marked UTF-16: {error}")
            })?
    };
    if decoded.contains('\0') {
        return Err("certified ARG contains a NUL character".to_string());
    }
    Ok(decoded)
}

fn certified_arg_profile_root(bytes: &[u8]) -> Result<CertifiedArgProfileRoot, String> {
    const HKCU: &str = "HKEY_CURRENT_USER";
    const AUTOCAD_PREFIX: [&str; 3] = ["Software", "Autodesk", "AutoCAD"];

    let text = decode_certified_arg(bytes)?;
    let mut common_root: Option<Vec<String>> = None;
    let mut header_count = 0_usize;
    for (line_index, line) in text.lines().enumerate() {
        let line = line.trim();
        if !line.starts_with('[') {
            continue;
        }
        if !line.ends_with(']') || line.len() < 3 {
            return Err(format!(
                "certified ARG registry header on line {} is malformed",
                line_index + 1
            ));
        }
        let header = &line[1..line.len() - 1];
        if header.starts_with('-')
            || header.trim() != header
            || header.contains('[')
            || header.contains(']')
            || header.chars().any(char::is_control)
        {
            return Err(format!(
                "certified ARG registry header on line {} is not an import header",
                line_index + 1
            ));
        }
        let components = header.split('\\').collect::<Vec<_>>();
        if components.iter().any(|component| component.is_empty())
            || !components
                .first()
                .is_some_and(|component| component.eq_ignore_ascii_case(HKCU))
            || components.len() < AUTOCAD_PREFIX.len() + 3
            || !components[1..=AUTOCAD_PREFIX.len()]
                .iter()
                .zip(AUTOCAD_PREFIX)
                .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
        {
            return Err(format!(
                "certified ARG registry header on line {} is not beneath HKCU\\Software\\Autodesk\\AutoCAD",
                line_index + 1
            ));
        }
        let profiles_index = components
            .iter()
            .enumerate()
            .skip(AUTOCAD_PREFIX.len() + 1)
            .find_map(|(index, component)| {
                component.eq_ignore_ascii_case("Profiles").then_some(index)
            })
            .ok_or_else(|| {
                format!(
                    "certified ARG registry header on line {} has no Profiles component",
                    line_index + 1
                )
            })?;
        let profile_index = profiles_index + 1;
        if components
            .get(profile_index)
            .is_none_or(|name| name.is_empty())
        {
            return Err(format!(
                "certified ARG registry header on line {} does not name a profile",
                line_index + 1
            ));
        }
        let root = components[..=profile_index]
            .iter()
            .map(|component| (*component).to_string())
            .collect::<Vec<_>>();
        if let Some(expected) = &common_root {
            if root.len() != expected.len()
                || !root
                    .iter()
                    .zip(expected)
                    .all(|(left, right)| left.eq_ignore_ascii_case(right))
            {
                return Err(format!(
                    "certified ARG registry header on line {} belongs to a different profile root",
                    line_index + 1
                ));
            }
        } else {
            common_root = Some(root.clone());
        }
        if components.len() < root.len()
            || !components
                .iter()
                .zip(&root)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        {
            return Err(format!(
                "certified ARG registry header on line {} escapes its profile root",
                line_index + 1
            ));
        }
        header_count += 1;
    }
    let root = common_root
        .filter(|_| header_count != 0)
        .ok_or_else(|| "certified ARG contains no registry profile headers".to_string())?;
    Ok(CertifiedArgProfileRoot {
        hkcu_subkey: root[1..].join("\\"),
    })
}

fn certified_arg_profile_root_from_file(
    path: &Path,
    expected_sha256: Option<&str>,
) -> Result<CertifiedArgProfileRoot, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("failed to read certified ARG {}: {error}", path.display()))?;
    if let Some(expected) = expected_sha256 {
        let actual = xref_sha256_bytes(&bytes);
        if actual != expected {
            return Err(format!(
                "certified ARG changed before its profile root was bound: {}",
                path.display()
            ));
        }
    }
    certified_arg_profile_root(&bytes)
}

#[cfg(windows)]
fn certified_profile_registry_key_exists(root: &CertifiedArgProfileRoot) -> Result<bool, String> {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_READ,
    };

    let path = registry_wide_path(&root.hkcu_subkey)?;
    let mut key: HKEY = std::ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_READ, &mut key) };
    match status {
        ERROR_SUCCESS => {
            let close_status = unsafe { RegCloseKey(key) };
            if close_status != ERROR_SUCCESS {
                return Err(format!(
                    "failed to close certified AutoCAD profile registry key (Win32 {close_status})"
                ));
            }
            Ok(true)
        }
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(false),
        status => Err(format!(
            "failed to query certified AutoCAD profile registry key (Win32 {status})"
        )),
    }
}

#[cfg(not(windows))]
fn certified_profile_registry_key_exists(_root: &CertifiedArgProfileRoot) -> Result<bool, String> {
    Err("certified AutoCAD profile registry isolation requires Windows".to_string())
}

#[cfg(windows)]
fn delete_certified_profile_registry_tree(root: &CertifiedArgProfileRoot) -> Result<(), String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{RegDeleteTreeW, HKEY_CURRENT_USER};

    let path = registry_wide_path(&root.hkcu_subkey)?;
    let status = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, path.as_ptr()) };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "failed to delete the per-launch-owned certified AutoCAD profile registry subtree (Win32 {status})"
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn delete_certified_profile_registry_tree(_root: &CertifiedArgProfileRoot) -> Result<(), String> {
    Err("certified AutoCAD profile registry isolation requires Windows".to_string())
}

#[cfg(windows)]
fn registry_wide_path(path: &str) -> Result<Vec<u16>, String> {
    if path.is_empty() || path.contains('\0') {
        return Err("registry subkey path must be non-empty and contain no NUL".to_string());
    }
    Ok(path.encode_utf16().chain(std::iter::once(0)).collect())
}

#[derive(Debug)]
struct CertifiedArgProfileIsolation {
    root: CertifiedArgProfileRoot,
    cleanup_complete: bool,
}

fn validate_certified_profile_postcondition(
    expectation: CertificationProfileLaunchExpectation,
    profile_key_exists: bool,
) -> Result<(), String> {
    match (expectation, profile_key_exists) {
        (CertificationProfileLaunchExpectation::NoEngineExpected, false)
        | (CertificationProfileLaunchExpectation::EngineImportRequired, true) => Ok(()),
        (CertificationProfileLaunchExpectation::NoEngineExpected, true) => Err(
            "a command declared offline unexpectedly created the certified AutoCAD profile key"
                .to_string(),
        ),
        (CertificationProfileLaunchExpectation::EngineImportRequired, false) => Err(
            "an engine-backed command did not create the certified AutoCAD profile key".to_string(),
        ),
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct CertifiedProfileIsolationOutcome {
    present_after: bool,
    cleanup_performed: bool,
    absent_after: bool,
}

impl CertifiedArgProfileIsolation {
    fn acquire(
        path: &Path,
        expected_sha256: Option<&str>,
    ) -> Result<CertifiedArgProfileIsolation, String> {
        let root = certified_arg_profile_root_from_file(path, expected_sha256)?;
        Self::acquire_root(root)
    }

    fn acquire_root(root: CertifiedArgProfileRoot) -> Result<Self, String> {
        if certified_profile_registry_key_exists(&root)? {
            return Err(format!(
                "certified AutoCAD profile registry key already exists; a fresh first import cannot be proved: HKCU\\{}",
                root.hkcu_subkey
            ));
        }
        Ok(Self {
            root,
            cleanup_complete: false,
        })
    }

    fn finish(
        &mut self,
        expectation: CertificationProfileLaunchExpectation,
    ) -> Result<CertifiedProfileIsolationOutcome, String> {
        if self.cleanup_complete {
            return Err("certified AutoCAD profile isolation was already finalized".to_string());
        }
        let present_after = certified_profile_registry_key_exists(&self.root)?;
        let postcondition = validate_certified_profile_postcondition(expectation, present_after);
        let cleanup_performed = present_after;
        let cleanup = if cleanup_performed {
            delete_certified_profile_registry_tree(&self.root)
        } else {
            Ok(())
        };
        let absent_after = !certified_profile_registry_key_exists(&self.root)?;
        let cleanup = cleanup.and_then(|()| {
            if absent_after {
                Ok(())
            } else {
                Err(format!(
                    "certified AutoCAD profile registry key remained after exact-subtree cleanup: HKCU\\{}",
                    self.root.hkcu_subkey
                ))
            }
        });
        if cleanup.is_ok() && absent_after {
            self.cleanup_complete = true;
        }
        match (postcondition, cleanup) {
            (Ok(()), Ok(())) => Ok(CertifiedProfileIsolationOutcome {
                present_after,
                cleanup_performed,
                absent_after,
            }),
            (Err(postcondition), Ok(())) => Err(postcondition),
            (Ok(()), Err(cleanup)) => Err(cleanup),
            (Err(postcondition), Err(cleanup)) => Err(format!("{postcondition}; {cleanup}")),
        }
    }
}

impl Drop for CertifiedArgProfileIsolation {
    fn drop(&mut self) {
        if self.cleanup_complete {
            return;
        }
        let cleanup = (|| {
            if certified_profile_registry_key_exists(&self.root)? {
                delete_certified_profile_registry_tree(&self.root)?;
                if certified_profile_registry_key_exists(&self.root)? {
                    return Err("registry key remained present after unwind cleanup".to_string());
                }
            }
            Ok::<(), String>(())
        })();
        if let Err(error) = cleanup {
            eprintln!(
                "failed to clean the per-launch-owned certified AutoCAD profile registry subtree during unwind: {error}"
            );
        }
        self.cleanup_complete = true;
    }
}

fn run_with_fresh_certified_profile<T>(
    certified_arg: &Path,
    certified_arg_sha256: &str,
    invocation_id: &str,
    tool: &str,
    expectation: CertificationProfileLaunchExpectation,
    run: impl FnOnce() -> Result<T, String>,
) -> Result<(T, CertificationProfileIsolationEvidence), String> {
    let mut isolation =
        CertifiedArgProfileIsolation::acquire(certified_arg, Some(certified_arg_sha256)).map_err(
            |error| format!("certified ARG per-launch isolation precondition failed: {error}"),
        )?;
    let run_result = run();
    let cleanup_result = isolation.finish(expectation);
    match (run_result, cleanup_result) {
        (Ok(value), Ok(outcome)) => Ok((
            value,
            CertificationProfileIsolationEvidence {
                invocation_id: invocation_id.to_string(),
                tool: tool.to_string(),
                expectation,
                absent_before: true,
                present_after: outcome.present_after,
                cleanup_performed: outcome.cleanup_performed,
                absent_after: outcome.absent_after,
            },
        )),
        (Err(run_error), Ok(_)) => Err(run_error),
        (Ok(_), Err(cleanup_error)) => Err(format!(
            "certified ARG per-launch isolation postcondition failed: {cleanup_error}"
        )),
        (Err(run_error), Err(cleanup_error)) => Err(format!(
            "{run_error}; certified ARG per-launch isolation postcondition failed: {cleanup_error}"
        )),
    }
}

fn unique_xref_profile_root(
    certified_root: &CertifiedArgProfileRoot,
    token: &str,
) -> Result<CertifiedArgProfileRoot, String> {
    let (parent, _) = certified_root
        .hkcu_subkey
        .rsplit_once('\\')
        .ok_or_else(|| "certified AutoCAD profile root has no Profiles parent".to_string())?;
    let profile_name = autocad_mcp::certified_arg::xref_isolated_profile_name(token)
        .map_err(|error| error.to_string())?;
    Ok(CertifiedArgProfileRoot {
        hkcu_subkey: format!("{parent}\\{profile_name}"),
    })
}

fn next_xref_profile_token(invocation_id: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
    let material = format!(
        "{}:{}:{invocation_id}",
        std::process::id(),
        NEXT_TOKEN.fetch_add(1, Ordering::Relaxed)
    );
    xref_sha256_bytes(material.as_bytes())[..32].to_string()
}

#[cfg(windows)]
fn observe_unique_xref_profile_lifecycle(
    token: &str,
    root: CertifiedArgProfileRoot,
) -> Result<thread::JoinHandle<Result<bool, String>>, String> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{CreateEventW, SetEvent, WaitForSingleObject},
    };

    const PROFILE_OBSERVATION_WAIT_MS: u32 = 30_000;

    fn event_name(token: &str, suffix: &str) -> Vec<u16> {
        format!("Local\\AutoCADMcpXrefProfile-{token}-{suffix}")
            .encode_utf16()
            .chain(Some(0))
            .collect()
    }

    fn create_event(name: &[u16], label: &str) -> Result<OwnedHandle, String> {
        let raw = unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) };
        if raw.is_null() {
            return Err(format!(
                "create deterministic XREF profile {label} event: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }

    let ready = create_event(&event_name(token, "ready"), "ready")?;
    let continue_event = create_event(&event_name(token, "continue"), "continue")?;
    let observer = thread::spawn(move || -> Result<bool, String> {
        match unsafe { WaitForSingleObject(ready.as_raw_handle(), PROFILE_OBSERVATION_WAIT_MS) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                return Err("timed out waiting for production XREF profile lifecycle".to_string())
            }
            WAIT_FAILED => {
                return Err(format!(
                    "wait for production XREF profile lifecycle: {}",
                    std::io::Error::last_os_error()
                ))
            }
            status => {
                return Err(format!(
                    "unexpected production XREF profile wait status {status}"
                ))
            }
        }
        let observation = certified_profile_registry_key_exists(&root);
        let signal = if unsafe { SetEvent(continue_event.as_raw_handle()) } == 0 {
            Err(format!(
                "release production XREF profile cleanup: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(())
        };
        match (observation, signal) {
            (Ok(present), Ok(())) => Ok(present),
            (Err(error), Ok(())) | (_, Err(error)) => Err(error),
        }
    });
    Ok(observer)
}

#[cfg(not(windows))]
fn observe_unique_xref_profile_lifecycle(
    _token: &str,
    _root: CertifiedArgProfileRoot,
) -> Result<thread::JoinHandle<Result<bool, String>>, String> {
    Err("production XREF profile lifecycle observation requires Windows".to_string())
}

#[allow(clippy::too_many_arguments)]
fn run_with_unique_xref_profile<T>(
    certified_arg: &Path,
    certified_arg_sha256: &str,
    invocation_id: &str,
    tool: &str,
    expectation: CertificationProfileLaunchExpectation,
    mut command: Command,
    run: impl FnOnce(Command) -> Result<T, String>,
) -> Result<(T, CertificationProfileIsolationEvidence), String> {
    let certified_root =
        certified_arg_profile_root_from_file(certified_arg, Some(certified_arg_sha256))?;
    if certified_profile_registry_key_exists(&certified_root)? {
        return Err(format!(
            "source certified AutoCAD profile registry key already exists; XREF must never adopt it: HKCU\\{}",
            certified_root.hkcu_subkey
        ));
    }
    let token = next_xref_profile_token(invocation_id);
    let unique_root = unique_xref_profile_root(&certified_root, &token)?;
    if certified_profile_registry_key_exists(&unique_root)? {
        return Err(format!(
            "per-launch unique XREF profile registry key already exists: HKCU\\{}",
            unique_root.hkcu_subkey
        ));
    }
    command.env(
        autocad_mcp::certified_arg::XREF_ISOLATED_PROFILE_TOKEN_ENV,
        &token,
    );

    let observation = if expectation == CertificationProfileLaunchExpectation::EngineImportRequired
    {
        command.env(
            autocad_mcp::certified_arg::XREF_PROFILE_LIFECYCLE_COORDINATION_ENV,
            &token,
        );
        Some(observe_unique_xref_profile_lifecycle(
            &token,
            unique_root.clone(),
        )?)
    } else {
        None
    };
    let run_result = run(command);
    let present_after = match observation {
        Some(observer) => observer
            .join()
            .map_err(|_| "production XREF profile observer panicked".to_string())??,
        None => false,
    };
    let absent_after = !certified_profile_registry_key_exists(&unique_root)?;
    let source_absent_after = !certified_profile_registry_key_exists(&certified_root)?;

    let lifecycle_result = match (
        expectation,
        present_after,
        absent_after,
        source_absent_after,
    ) {
        (CertificationProfileLaunchExpectation::EngineImportRequired, true, true, true)
        | (CertificationProfileLaunchExpectation::NoEngineExpected, false, true, true) => Ok(()),
        (_, _, false, _) => {
            let cleanup = delete_certified_profile_registry_tree(&unique_root).and_then(|()| {
                if certified_profile_registry_key_exists(&unique_root)? {
                    Err("unique XREF profile remained after harness recovery cleanup".to_string())
                } else {
                    Ok(())
                }
            });
            Err(match cleanup {
                Ok(()) => "production left the unique XREF profile registry subtree behind; the harness recovered it".to_string(),
                Err(error) => format!(
                    "production left the unique XREF profile registry subtree behind; harness recovery failed: {error}"
                ),
            })
        }
        (_, _, _, false) => Err(
            "production imported or modified the fixed source certified profile root".to_string(),
        ),
        (CertificationProfileLaunchExpectation::EngineImportRequired, false, _, _) => Err(
            "production did not expose the imported unique XREF profile before cleanup".to_string(),
        ),
        (CertificationProfileLaunchExpectation::NoEngineExpected, true, _, _) => Err(
            "an offline XREF command unexpectedly imported a unique AutoCAD profile".to_string(),
        ),
    };

    match (run_result, lifecycle_result) {
        (Ok(value), Ok(())) => Ok((
            value,
            CertificationProfileIsolationEvidence {
                invocation_id: invocation_id.to_string(),
                tool: tool.to_string(),
                expectation,
                absent_before: true,
                present_after,
                cleanup_performed: present_after && absent_after,
                absent_after,
            },
        )),
        (Err(run_error), Ok(())) => Err(run_error),
        (Ok(_), Err(lifecycle_error)) => Err(format!(
            "production XREF profile lifecycle failed: {lifecycle_error}"
        )),
        (Err(run_error), Err(lifecycle_error)) => Err(format!(
            "{run_error}; production XREF profile lifecycle failed: {lifecycle_error}"
        )),
    }
}

fn bind_exact_certification_file(
    configured_path: &str,
    expected_sha256: &str,
    label: &str,
) -> Result<ExactCertificationFile, String> {
    let configured = Path::new(configured_path);
    let metadata = std::fs::symlink_metadata(configured)
        .map_err(|error| format!("failed to inspect {label} {configured_path}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} must be a regular non-symlink file: {configured_path}"
        ));
    }
    let canonical_path = configured
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize {label} {configured_path}: {error}"))?;
    #[cfg(windows)]
    {
        let canonical_display = certification_path_string(&canonical_path)?;
        if !autocad_mcp::certification::certification_windows_paths_equal(
            configured_path,
            &canonical_display,
        ) {
            return Err(format!(
                "{label} configured path must already identify its canonical Windows path"
            ));
        }
    }
    let guard = open_exact_certification_file(configured, label)?;
    let guarded_metadata = guard
        .metadata()
        .map_err(|error| format!("failed to inspect guarded {label}: {error}"))?;
    if !guarded_metadata.is_file() || guarded_metadata.file_type().is_symlink() {
        return Err(format!(
            "guarded {label} must be a direct regular file: {configured_path}"
        ));
    }
    #[cfg(windows)]
    if certification_handle_is_reparse_point(&guard, label)? {
        return Err(format!(
            "guarded {label} must not be a reparse point: {configured_path}"
        ));
    }
    let identity = certification_file_identity(&guard, label)?;
    let canonical_guard = open_exact_certification_file(&canonical_path, label)?;
    let canonical_identity = certification_file_identity(&canonical_guard, label)?;
    if canonical_identity != identity {
        return Err(format!(
            "{label} configured and canonical paths identify different files"
        ));
    }
    let sha256_before = sha256_certification_file_handle(&guard, label)?;
    let canonical_sha256 = sha256_certification_file_handle(&canonical_guard, label)?;
    if canonical_sha256 != sha256_before {
        return Err(format!(
            "{label} configured and canonical handles expose different bytes"
        ));
    }
    drop(canonical_guard);
    if sha256_before != expected_sha256 {
        return Err(format!(
            "{label} SHA-256 {sha256_before} does not match manifest {expected_sha256}"
        ));
    }

    #[cfg(windows)]
    let directory_guards = guard_exact_certification_directory_chain(&canonical_path, label)?;
    #[cfg(windows)]
    verify_exact_certification_directory_chain(&directory_guards, label)?;

    let rebound_canonical = configured
        .canonicalize()
        .map_err(|error| format!("failed to recanonicalize guarded {label}: {error}"))?;
    if rebound_canonical != canonical_path {
        return Err(format!(
            "{label} configured path changed while its guards were installed"
        ));
    }
    let rebound = open_exact_certification_file(configured, label)?;
    if certification_file_identity(&rebound, label)? != identity
        || sha256_certification_file_handle(&rebound, label)? != sha256_before
    {
        return Err(format!(
            "{label} configured path changed while its guards were installed"
        ));
    }

    Ok(ExactCertificationFile {
        configured_path: configured_path.to_string(),
        canonical_path,
        sha256_before,
        guard,
        identity,
        #[cfg(windows)]
        directory_guards,
    })
}

fn verify_exact_certification_file_unchanged(
    binding: &ExactCertificationFile,
    label: &str,
) -> Result<String, String> {
    let guarded_identity = certification_file_identity(&binding.guard, label)?;
    if guarded_identity != binding.identity {
        return Err(format!("{label} guarded file identity changed"));
    }
    let guarded_sha256 = sha256_certification_file_handle(&binding.guard, label)?;
    if guarded_sha256 != binding.sha256_before {
        return Err(format!(
            "{label} guarded bytes changed during certification"
        ));
    }
    let configured = Path::new(&binding.configured_path);
    let metadata = std::fs::symlink_metadata(configured)
        .map_err(|error| format!("failed to reinspect {label}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} ceased to be a regular non-symlink file during certification"
        ));
    }
    let canonical = configured
        .canonicalize()
        .map_err(|error| format!("failed to recanonicalize {label}: {error}"))?;
    if canonical != binding.canonical_path {
        return Err(format!(
            "{label} configured path resolved to a different file during certification"
        ));
    }
    let current_guard = open_exact_certification_file(configured, label)?;
    #[cfg(windows)]
    if certification_handle_is_reparse_point(&current_guard, label)? {
        return Err(format!(
            "{label} became a reparse point during certification"
        ));
    }
    if certification_file_identity(&current_guard, label)? != binding.identity {
        return Err(format!(
            "{label} configured path resolved to a different file identity during certification"
        ));
    }
    let current = sha256_certification_file_handle(&current_guard, label)?;
    if current != binding.sha256_before {
        return Err(format!(
            "{label} changed during certification: {}",
            binding.canonical_path.display()
        ));
    }

    #[cfg(windows)]
    verify_exact_certification_directory_chain(&binding.directory_guards, label)?;
    Ok(current)
}

fn safe_fixture_relative_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() || value != value.trim() || value.contains('\\') {
        return Err(format!(
            "certification fixture path must be a non-empty normalized forward-slash path: {value:?}"
        ));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "certification fixture path must stay beneath fixture_root: {value:?}"
        ));
    }
    let normalized = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    if normalized != value {
        return Err(format!(
            "certification fixture path must be normalized: {value:?}"
        ));
    }
    Ok(path.to_path_buf())
}

fn stage_certification_file(
    fixture_root: &Path,
    relative_path: &str,
    expected_sha256: &str,
    staging_root: &Path,
) -> Result<StagedCertificationFile, String> {
    let relative = safe_fixture_relative_path(relative_path)?;
    let canonical_root = fixture_root.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize certification fixture root {}: {error}",
            fixture_root.display()
        )
    })?;
    let source_candidate = canonical_root.join(&relative);
    let source_metadata = std::fs::symlink_metadata(&source_candidate).map_err(|error| {
        format!(
            "failed to inspect certification fixture {}: {error}",
            source_candidate.display()
        )
    })?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
        return Err(format!(
            "certification fixture must be a regular non-symlink file: {}",
            source_candidate.display()
        ));
    }
    let source_path = source_candidate.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize certification fixture {}: {error}",
            source_candidate.display()
        )
    })?;
    if !source_path.starts_with(&canonical_root) {
        return Err(format!(
            "certification fixture escaped fixture_root: {}",
            source_path.display()
        ));
    }

    let source_before = xref_sha256_file(&source_path).map_err(|error| error.to_string())?;
    if source_before != expected_sha256 {
        return Err(format!(
            "certification fixture {} SHA-256 {source_before} does not match manifest {expected_sha256}",
            source_path.display()
        ));
    }

    let canonical_staging_root = staging_root.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize certification staging root {}: {error}",
            staging_root.display()
        )
    })?;
    let staging_metadata = std::fs::symlink_metadata(staging_root).map_err(|error| {
        format!(
            "failed to inspect certification staging root {}: {error}",
            staging_root.display()
        )
    })?;
    if staging_metadata.file_type().is_symlink() || !staging_metadata.is_dir() {
        return Err(format!(
            "certification staging root must be a real directory: {}",
            staging_root.display()
        ));
    }
    let parent_relative = relative.parent().unwrap_or_else(|| Path::new(""));
    let parent = create_certification_staging_parents(staging_root, parent_relative)?;
    let canonical_parent = parent.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize certification staging directory {}: {error}",
            parent.display()
        )
    })?;
    if !canonical_parent.starts_with(&canonical_staging_root) {
        return Err(format!(
            "certification staging directory escaped its fresh root: {}",
            parent.display()
        ));
    }
    let file_name = relative.file_name().ok_or_else(|| {
        format!(
            "certification fixture path has no file name: {}",
            relative.display()
        )
    })?;
    let staged_path = parent.join(file_name);
    let mut source_file = std::fs::File::open(&source_path)
        .map_err(|error| format!("failed to open {}: {error}", source_path.display()))?;
    let mut staged_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged_path)
        .map_err(|error| {
            format!(
                "refusing to overwrite staged certification fixture {}: {error}",
                staged_path.display()
            )
        })?;
    std::io::copy(&mut source_file, &mut staged_file).map_err(|error| {
        format!(
            "failed to stage certification fixture {} as {}: {error}",
            source_path.display(),
            staged_path.display()
        )
    })?;
    staged_file
        .sync_all()
        .map_err(|error| format!("failed to sync {}: {error}", staged_path.display()))?;

    let source_after = xref_sha256_file(&source_path).map_err(|error| error.to_string())?;
    let staged_sha256 = xref_sha256_file(&staged_path).map_err(|error| error.to_string())?;
    if source_after != source_before {
        return Err(format!(
            "certification fixture changed while it was staged: {}",
            source_path.display()
        ));
    }
    if staged_sha256 != source_before {
        return Err(format!(
            "staged certification fixture digest mismatch for {}",
            staged_path.display()
        ));
    }

    Ok(StagedCertificationFile {
        source_path,
        staged_path,
        sha256: staged_sha256,
    })
}

fn create_certification_staging_parents(
    staging_root: &Path,
    relative: &Path,
) -> Result<PathBuf, String> {
    let mut current = staging_root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(format!(
                "invalid certification staging directory component: {}",
                relative.display()
            ));
        };
        current.push(component);
        match std::fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = std::fs::symlink_metadata(&current).map_err(|inspect_error| {
                    format!(
                        "failed to inspect existing staging directory {}: {inspect_error}",
                        current.display()
                    )
                })?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "staging path component is not a real directory: {}",
                        current.display()
                    ));
                }
            }
            Err(error) => {
                return Err(format!(
                    "failed to create staging directory {}: {error}",
                    current.display()
                ));
            }
        }
    }
    Ok(current)
}

#[derive(Debug)]
struct TitleBlockObservation {
    title_blocks: Vec<autocad_mcp::ops::title_blocks::TitleBlockInfo>,
    profile_id: String,
    fingerprint: autocad_mcp::ops::profiles::TitleBlockFingerprint,
    snapshot_sha256: String,
}

fn observe_title_blocks(stdout: &str) -> Result<TitleBlockObservation, String> {
    let value = parse_certification_json("read_title_blocks", stdout)?;
    let records = value
        .as_array()
        .ok_or_else(|| "read_title_blocks output was not an array".to_string())?;
    for record in records {
        verify_exact_object_fields(
            record,
            &["block_name", "layer", "attributes"],
            "read_title_blocks record",
        )?;
    }
    let title_blocks =
        serde_json::from_value::<Vec<autocad_mcp::ops::title_blocks::TitleBlockInfo>>(value)
            .map_err(|error| {
                certification_json_error_diagnostic(
                    "read_title_blocks typed output",
                    stdout,
                    &error,
                )
            })?;
    let profile = profiles::resolve_profile(&title_blocks)
        .map_err(|error| format!("read_title_blocks did not resolve one exact profile: {error}"))?;
    let fingerprint = profile.title_block_fingerprint();
    let snapshot_sha256 = title_block_snapshot_sha256(&title_blocks)?;
    Ok(TitleBlockObservation {
        title_blocks,
        profile_id: profile.profile_id.clone(),
        fingerprint,
        snapshot_sha256,
    })
}

fn title_block_snapshot_sha256(
    title_blocks: &[autocad_mcp::ops::title_blocks::TitleBlockInfo],
) -> Result<String, String> {
    let canonical = canonical_title_block_multiset(title_blocks)?;
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| format!("failed to serialize title-block observation: {error}"))?;
    Ok(xref_sha256_bytes(&bytes))
}

fn certification_title_block_snapshot(
    release_id: &str,
    drawing_id: &str,
    title_blocks: &[autocad_mcp::ops::title_blocks::TitleBlockInfo],
) -> Result<CertificationTitleBlockSnapshot, String> {
    let mut records = title_blocks
        .iter()
        .map(|block| {
            let mut attributes = block
                .attributes
                .iter()
                .map(|(tag, value)| {
                    let tag = tag.trim().to_ascii_uppercase();
                    CertificationHashedTitleBlockAttribute {
                        value_sha256: certification_title_value_sha256(
                            release_id, drawing_id, &tag, value,
                        ),
                        tag,
                    }
                })
                .collect::<Vec<_>>();
            attributes.sort_by(|left, right| left.tag.cmp(&right.tag));
            CertificationHashedTitleBlockRecord {
                normalized_block_name: block.block_name.trim().to_ascii_uppercase(),
                layer_sha256: certification_title_layer_sha256(
                    release_id,
                    drawing_id,
                    &block.layer,
                ),
                attributes,
            }
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        serde_json::to_vec(left)
            .expect("closed title-block record serializes")
            .cmp(&serde_json::to_vec(right).expect("closed title-block record serializes"))
    });
    let sha256 = certification_title_snapshot_sha256(&records);
    Ok(CertificationTitleBlockSnapshot { records, sha256 })
}

fn canonical_title_block_multiset(
    title_blocks: &[autocad_mcp::ops::title_blocks::TitleBlockInfo],
) -> Result<Vec<serde_json::Value>, String> {
    let mut canonical = title_blocks
        .iter()
        .map(|block| {
            let attributes = block
                .attributes
                .iter()
                .map(|(tag, value)| (tag.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>();
            let value = serde_json::json!({
                "block_name": block.block_name,
                "layer": block.layer,
                "attributes": attributes,
            });
            let sort_key = serde_json::to_vec(&value).map_err(|error| {
                format!("failed to serialize canonical title-block record: {error}")
            })?;
            Ok((sort_key, value))
        })
        .collect::<Result<Vec<_>, String>>()?;
    canonical.sort_by(|(left, _), (right, _)| left.cmp(right));
    Ok(canonical.into_iter().map(|(_, value)| value).collect())
}

fn title_block_fingerprint(
    block: &autocad_mcp::ops::title_blocks::TitleBlockInfo,
) -> autocad_mcp::ops::profiles::TitleBlockFingerprint {
    autocad_mcp::ops::profiles::TitleBlockFingerprint::new(
        &block.block_name,
        block.attributes.keys().map(String::as_str),
    )
}

fn requested_title_block_tags(
    title_blocks: &[autocad_mcp::ops::title_blocks::TitleBlockInfo],
    write_fields: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    let profile = profiles::resolve_profile(title_blocks)
        .map_err(|error| format!("failed to resolve pre-write profile: {error}"))?;
    let requested_tags = write_fields
        .iter()
        .map(|(field, value)| {
            profile
                .tag_for(field)
                .map(|tag| (tag.to_string(), value.clone()))
                .ok_or_else(|| {
                    format!(
                        "manifest requested unknown field {field:?} for profile {}",
                        profile.profile_id
                    )
                })
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if requested_tags.len() != write_fields.len() {
        return Err(format!(
            "manifest canonical fields collapse onto duplicate profile tags for profile {}",
            profile.profile_id
        ));
    }
    Ok(requested_tags)
}

fn verify_title_block_readback(
    before: &TitleBlockObservation,
    after: &TitleBlockObservation,
    expected_profile_id: &str,
    write_fields: &BTreeMap<String, String>,
) -> Result<(Vec<String>, Vec<String>), String> {
    if before.profile_id != expected_profile_id || after.profile_id != expected_profile_id {
        return Err(format!(
            "title-block profile changed or did not match manifest: before={}, after={}, expected={expected_profile_id}",
            before.profile_id, after.profile_id
        ));
    }
    if before.fingerprint != after.fingerprint {
        return Err("title-block fingerprint changed after write".to_string());
    }
    if before.title_blocks.len() != after.title_blocks.len() {
        return Err(format!(
            "title-block inventory changed after write: before={}, after={}",
            before.title_blocks.len(),
            after.title_blocks.len()
        ));
    }

    let requested_tags = requested_title_block_tags(&before.title_blocks, write_fields)?;

    let mut matching_inserts = 0_usize;
    let mut unchanged_tags = BTreeSet::new();
    let mut expected_after = before.title_blocks.clone();
    for (index, before_block) in expected_after.iter_mut().enumerate() {
        if title_block_fingerprint(before_block) != before.fingerprint {
            continue;
        }

        matching_inserts += 1;
        for tag in before_block.attributes.keys() {
            if !requested_tags.contains_key(tag) {
                unchanged_tags.insert(tag.clone());
            }
        }
        for (tag, expected_value) in &requested_tags {
            let before_value = before_block.attributes.get_mut(tag).ok_or_else(|| {
                format!(
                    "pre-write title block did not contain requested profile tag {tag:?} at index {index}"
                )
            })?;
            if before_value == expected_value {
                return Err(format!(
                    "certification write for tag {tag:?} was a no-op at index {index}; the Tier 2 fixture must start with a different value"
                ));
            }
            *before_value = expected_value.clone();
        }
    }
    if matching_inserts == 0 {
        return Err("no title-block insert matched the resolved profile fingerprint".to_string());
    }
    if canonical_title_block_multiset(&expected_after)?
        != canonical_title_block_multiset(&after.title_blocks)?
    {
        return Err(
            "post-write title-block multiset did not preserve identities, duplicate counts, and unrequested fields while applying the requested mutations"
                .to_string(),
        );
    }

    Ok((
        write_fields.keys().cloned().collect(),
        unchanged_tags.into_iter().collect(),
    ))
}

fn observe_layout_names(stdout: &str) -> Result<Vec<String>, String> {
    let value = parse_certification_json("list_layouts", stdout)?;
    let records = value
        .as_array()
        .ok_or_else(|| "list_layouts output was not an array".to_string())?;
    for record in records {
        verify_exact_object_fields(
            record,
            &[
                "name",
                "is_model",
                "tab_order",
                "paper_width_mm",
                "paper_height_mm",
            ],
            "list_layouts record",
        )?;
    }
    let layouts = serde_json::from_value::<Vec<autocad_mcp::ops::layouts::LayoutInfo>>(value)
        .map_err(|error| {
            certification_json_error_diagnostic("list_layouts typed output", stdout, &error)
        })?;
    let mut names = BTreeSet::new();
    for (index, layout) in layouts.into_iter().enumerate() {
        if layout.name.trim().is_empty() || !names.insert(layout.name.clone()) {
            return Err(format!(
                "list_layouts returned an empty or duplicate layout name at record {index}"
            ));
        }
    }
    Ok(names.into_iter().collect())
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PdfObservation {
    sha256: String,
    size: u64,
}

fn verify_pdf_path_matches_opened_bytes(
    path: &Path,
    canonical_before: &Path,
    opened_sha256: &str,
) -> Result<(), String> {
    let path_metadata_after = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to reinspect plotted PDF {}: {error}",
            path.display()
        )
    })?;
    let canonical_after = path
        .canonicalize()
        .map_err(|error| format!("failed to recanonicalize plotted PDF: {error}"))?;
    if path_metadata_after.file_type().is_symlink()
        || !path_metadata_after.is_file()
        || canonical_after != canonical_before
    {
        return Err(format!(
            "plot output path changed while it was read: {}",
            path.display()
        ));
    }
    let final_path_sha256 = xref_sha256_file(path)
        .map_err(|error| format!("failed to rehash plotted PDF {}: {error}", path.display()))?;
    if final_path_sha256 != opened_sha256 {
        return Err(format!(
            "plot output pathname bytes changed while it was read: {}",
            path.display()
        ));
    }
    Ok(())
}

fn observe_pdf(path: &Path) -> Result<PdfObservation, String> {
    let path_metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect plotted PDF {}: {error}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(format!(
            "plot output must be a non-empty regular non-symlink PDF: {}",
            path.display()
        ));
    }
    let canonical_before = path
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize plotted PDF: {error}"))?;
    let mut file = std::fs::File::open(&canonical_before)
        .map_err(|error| format!("failed to open plotted PDF {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect opened PDF {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "plot output must be a non-empty regular PDF: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read plotted PDF {}: {error}", path.display()))?;
    if metadata.len() != bytes.len() as u64 {
        return Err(format!(
            "plot output changed while it was read: {}",
            path.display()
        ));
    }
    let opened_sha256 = xref_sha256_bytes(&bytes);
    verify_pdf_path_matches_opened_bytes(path, &canonical_before, &opened_sha256)?;
    if !bytes.starts_with(b"%PDF-") {
        return Err(format!(
            "plot output does not have a PDF header: {}",
            path.display()
        ));
    }
    let tail_start = bytes.len().saturating_sub(1024);
    if !bytes[tail_start..]
        .windows(b"%%EOF".len())
        .any(|window| window == b"%%EOF")
    {
        return Err(format!(
            "plot output does not have a PDF EOF marker: {}",
            path.display()
        ));
    }
    Ok(PdfObservation {
        sha256: opened_sha256,
        size: metadata.len(),
    })
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct CertificationCommandRuntime {
    release_binary: PathBuf,
    accoreconsole: PathBuf,
    certified_arg: PathBuf,
    certified_arg_sha256: String,
}

const CERTIFICATION_TOOL_TIMEOUT: Duration = Duration::from_secs(300);
const CERTIFICATION_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(windows)]
const CERTIFICATION_PROCESS_INSPECTION_TIMEOUT: Duration = Duration::from_secs(10);
const CERTIFICATION_POLL_INTERVAL: Duration = Duration::from_millis(10);

fn certification_tool_command(
    runtime: &CertificationCommandRuntime,
    tool: &str,
    params: &serde_json::Value,
) -> Command {
    let mut command = Command::new(&runtime.release_binary);
    command
        .args(["call", tool, &params.to_string()])
        .env_remove("AUTOCAD_MCP_XREF_FAILPOINT")
        .env(
            "AUTOCAD_MCP_ACCORECONSOLE_PATH",
            runtime.accoreconsole.as_os_str(),
        )
        .env(
            "AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH",
            runtime.certified_arg.as_os_str(),
        );
    command
}

fn run_certification_tool(
    runtime: &CertificationCommandRuntime,
    profile_isolation: &mut Vec<CertificationProfileIsolationEvidence>,
    invocation_id: &str,
    expectation: CertificationProfileLaunchExpectation,
    tool: &str,
    params: &serde_json::Value,
) -> Result<Output, String> {
    let (output, observation) = run_with_fresh_certified_profile(
        &runtime.certified_arg,
        &runtime.certified_arg_sha256,
        invocation_id,
        tool,
        expectation,
        || {
            run_command_bounded(
                certification_tool_command(runtime, tool, params),
                CERTIFICATION_TOOL_TIMEOUT,
            )
            .map_err(|error| {
                format!(
                    "failed to run {tool} through {}: {error}",
                    runtime.release_binary.display()
                )
            })
        },
    )?;
    profile_isolation.push(observation);
    Ok(output)
}

fn certification_capture_file(label: &str) -> Result<(std::fs::File, Stdio), String> {
    let capture = tempfile::tempfile()
        .map_err(|error| format!("failed to create {label} capture: {error}"))?;
    let child_capture = capture
        .try_clone()
        .map_err(|error| format!("failed to clone {label} capture: {error}"))?;
    Ok((capture, Stdio::from(child_capture)))
}

fn read_certification_capture(capture: &mut std::fs::File, label: &str) -> Result<Vec<u8>, String> {
    capture
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("failed to seek {label} capture: {error}"))?;
    let mut bytes = Vec::new();
    capture
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {label} capture: {error}"))?;
    Ok(bytes)
}

fn certification_capture_diagnostic(stdout: &[u8], stderr: &[u8]) -> String {
    format!(
        "{}; {}",
        certification_bytes_diagnostic("stdout", stdout),
        certification_bytes_diagnostic("stderr", stderr)
    )
}

fn certification_captured_output(
    status: ExitStatus,
    stdout_capture: &mut std::fs::File,
    stderr_capture: &mut std::fs::File,
) -> Result<Output, String> {
    Ok(Output {
        status,
        stdout: read_certification_capture(stdout_capture, "stdout")?,
        stderr: read_certification_capture(stderr_capture, "stderr")?,
    })
}

#[cfg(not(windows))]
fn run_command_bounded(mut command: Command, timeout: Duration) -> Result<Output, String> {
    let (mut stdout_capture, stdout_stdio) = certification_capture_file("stdout")?;
    let (mut stderr_capture, stderr_stdio) = certification_capture_file("stderr")?;
    command
        .stdin(Stdio::null())
        .stdout(stdout_stdio)
        .stderr(stderr_stdio);
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to spawn certification child: {error}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("failed to wait for certification child: {error}"))?
        {
            return certification_captured_output(status, &mut stdout_capture, &mut stderr_capture);
        }
        if Instant::now() >= deadline {
            let kill_result = child.kill();
            let cleanup_deadline = Instant::now() + CERTIFICATION_CLEANUP_TIMEOUT;
            let mut reaped = false;
            while Instant::now() < cleanup_deadline {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        reaped = true;
                        break;
                    }
                    Ok(None) => thread::sleep(CERTIFICATION_POLL_INTERVAL),
                    Err(_) => break,
                }
            }
            let stdout =
                read_certification_capture(&mut stdout_capture, "stdout").unwrap_or_default();
            let stderr =
                read_certification_capture(&mut stderr_capture, "stderr").unwrap_or_default();
            return Err(format!(
                "certification command timed out after {}s; kill={kill_result:?}; reaped={reaped}; {}",
                timeout.as_secs(),
                certification_capture_diagnostic(&stdout, &stderr)
            ));
        }
        thread::sleep(CERTIFICATION_POLL_INTERVAL);
    }
}

#[cfg(windows)]
struct OwnedCertificationHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl OwnedCertificationHandle {
    fn from_nullable(
        raw: windows_sys::Win32::Foundation::HANDLE,
        label: &str,
    ) -> Result<Self, String> {
        if raw.is_null() {
            Err(format!("{label}: {}", std::io::Error::last_os_error()))
        } else {
            Ok(Self(raw))
        }
    }

    fn from_snapshot(raw: windows_sys::Win32::Foundation::HANDLE) -> Result<Self, String> {
        if raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            Err(format!(
                "CreateToolhelp32Snapshot: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(Self(raw))
        }
    }

    fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for OwnedCertificationHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
struct KillOnCloseCertificationJob(OwnedCertificationHandle);

#[cfg(windows)]
impl KillOnCloseCertificationJob {
    fn new() -> Result<Self, String> {
        use std::ffi::c_void;
        use std::mem::size_of_val;
        use std::ptr::null;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let handle = OwnedCertificationHandle::from_nullable(
            unsafe { CreateJobObjectW(null(), null()) },
            "CreateJobObjectW",
        )?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                handle.raw(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                size_of_val(&limits) as u32,
            )
        };
        if configured == 0 {
            return Err(format!(
                "SetInformationJobObject: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self(handle))
    }

    fn assign(&self, process: windows_sys::Win32::Foundation::HANDLE) -> Result<(), String> {
        let assigned = unsafe {
            windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(self.0.raw(), process)
        };
        if assigned == 0 {
            Err(format!(
                "AssignProcessToJobObject: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    }

    fn terminate(&self) -> Result<(), String> {
        let terminated = unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0.raw(), 124)
        };
        if terminated == 0 {
            Err(format!(
                "TerminateJobObject: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    }

    fn active_processes(&self) -> Result<u32, String> {
        use std::ffi::c_void;
        use std::mem::size_of_val;
        use std::ptr::null_mut;
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };

        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let queried = unsafe {
            QueryInformationJobObject(
                self.0.raw(),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast::<c_void>(),
                size_of_val(&accounting) as u32,
                null_mut(),
            )
        };
        if queried == 0 {
            Err(format!(
                "QueryInformationJobObject: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(accounting.ActiveProcesses)
        }
    }
}

#[cfg(windows)]
fn resume_suspended_certification_process(process_id: u32) -> Result<(), String> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_NO_MORE_FILES};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    let snapshot = OwnedCertificationHandle::from_snapshot(unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    })?;
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    if unsafe { Thread32First(snapshot.raw(), &mut entry) } == 0 {
        return Err(format!(
            "Thread32First: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut thread_id = None;
    loop {
        if entry.th32OwnerProcessID == process_id && thread_id.replace(entry.th32ThreadID).is_some()
        {
            return Err(format!(
                "suspended certification child {process_id} unexpectedly had multiple threads"
            ));
        }
        if unsafe { Thread32Next(snapshot.raw(), &mut entry) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_NO_MORE_FILES {
                return Err(format!(
                    "Thread32Next: {}",
                    std::io::Error::from_raw_os_error(error as i32)
                ));
            }
            break;
        }
    }
    let thread_id = thread_id
        .ok_or_else(|| format!("no primary thread found for suspended child {process_id}"))?;
    let thread = OwnedCertificationHandle::from_nullable(
        unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id) },
        "OpenThread",
    )?;
    let previous = unsafe { ResumeThread(thread.raw()) };
    if previous == u32::MAX {
        return Err(format!("ResumeThread: {}", std::io::Error::last_os_error()));
    }
    if previous != 1 {
        return Err(format!(
            "primary thread suspend count was {previous}, expected 1"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_wait_millis(duration: Duration) -> u32 {
    duration.as_millis().min(u128::from(u32::MAX - 1)).max(1) as u32
}

#[cfg(windows)]
fn wait_for_empty_certification_job(
    job: &KillOnCloseCertificationJob,
    deadline: Instant,
) -> Result<(), String> {
    loop {
        if job.active_processes()? == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(
                "certification Job Object did not become empty before its deadline".to_string(),
            );
        }
        thread::sleep(CERTIFICATION_POLL_INTERVAL);
    }
}

#[cfg(windows)]
fn wait_for_windows_child_bounded(
    child: &mut Child,
    timeout: Duration,
) -> Result<Option<ExitStatus>, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    let process = child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    match unsafe { WaitForSingleObject(process, windows_wait_millis(timeout)) } {
        WAIT_OBJECT_0 => child
            .try_wait()
            .map_err(|error| format!("failed to reap certification child: {error}"))
            .and_then(|status| {
                status
                    .map(Some)
                    .ok_or_else(|| "signaled certification child had no exit status".to_string())
            }),
        WAIT_TIMEOUT => Ok(None),
        WAIT_FAILED => Err(format!(
            "WaitForSingleObject: {}",
            std::io::Error::last_os_error()
        )),
        other => Err(format!("unexpected process wait result {other}")),
    }
}

#[cfg(windows)]
fn cleanup_windows_certification_process(
    mut job: Option<KillOnCloseCertificationJob>,
    child: &mut Child,
    assigned: bool,
) -> String {
    let terminate_result = if assigned {
        job.as_ref()
            .ok_or_else(|| "assigned process lost its Job Object".to_string())
            .and_then(KillOnCloseCertificationJob::terminate)
    } else {
        child
            .kill()
            .map_err(|error| format!("failed to kill suspended certification child: {error}"))
    };
    let cleanup_deadline = Instant::now() + CERTIFICATION_CLEANUP_TIMEOUT;
    let empty_result = if assigned && terminate_result.is_ok() {
        job.as_ref()
            .ok_or_else(|| "assigned process lost its Job Object".to_string())
            .and_then(|job| wait_for_empty_certification_job(job, cleanup_deadline))
    } else if assigned {
        Err("skipped Job Object empty wait because termination failed".to_string())
    } else {
        Ok(())
    };
    if terminate_result.is_err() || empty_result.is_err() {
        drop(job.take());
    }
    let child_result = wait_for_windows_child_bounded(
        child,
        cleanup_deadline.saturating_duration_since(Instant::now()),
    );
    format!("terminate={terminate_result:?}; empty={empty_result:?}; child={child_result:?}")
}

#[cfg(windows)]
fn run_command_bounded(mut command: Command, timeout: Duration) -> Result<Output, String> {
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{WaitForSingleObject, CREATE_SUSPENDED};

    let (mut stdout_capture, stdout_stdio) = certification_capture_file("stdout")?;
    let (mut stderr_capture, stderr_stdio) = certification_capture_file("stderr")?;
    command
        .stdin(Stdio::null())
        .stdout(stdout_stdio)
        .stderr(stderr_stdio)
        .creation_flags(CREATE_SUSPENDED);

    let mut job = Some(KillOnCloseCertificationJob::new()?);
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to spawn suspended certification child: {error}"))?;
    let process = child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut assigned = false;
    let prepare_result = job
        .as_ref()
        .ok_or_else(|| "certification Job Object was absent".to_string())
        .and_then(|job| {
            job.assign(process)?;
            assigned = true;
            resume_suspended_certification_process(child.id())
        });
    if let Err(error) = prepare_result {
        let cleanup = cleanup_windows_certification_process(job.take(), &mut child, assigned);
        return Err(format!(
            "failed to contain and resume certification child: {error}; {cleanup}"
        ));
    }

    let deadline = Instant::now() + timeout;
    match unsafe { WaitForSingleObject(process, windows_wait_millis(timeout)) } {
        WAIT_OBJECT_0 => {
            let status = match child.try_wait() {
                Ok(Some(status)) => status,
                Ok(None) => {
                    let cleanup =
                        cleanup_windows_certification_process(job.take(), &mut child, assigned);
                    return Err(format!(
                        "signaled certification child had no exit status; {cleanup}"
                    ));
                }
                Err(error) => {
                    let cleanup =
                        cleanup_windows_certification_process(job.take(), &mut child, assigned);
                    return Err(format!(
                        "failed to reap certification child: {error}; {cleanup}"
                    ));
                }
            };
            let job_empty = job
                .as_ref()
                .ok_or_else(|| "certification Job Object was absent".to_string())
                .and_then(|job| wait_for_empty_certification_job(job, deadline));
            if let Err(error) = job_empty {
                let active = job
                    .as_ref()
                    .and_then(|job| job.active_processes().ok())
                    .unwrap_or(u32::MAX);
                let cleanup =
                    cleanup_windows_certification_process(job.take(), &mut child, assigned);
                let stdout =
                    read_certification_capture(&mut stdout_capture, "stdout").unwrap_or_default();
                let stderr =
                    read_certification_capture(&mut stderr_capture, "stderr").unwrap_or_default();
                return Err(format!(
                    "certification CLI exited while {active} job process(es) remained: {error}; {cleanup}; {}",
                    certification_capture_diagnostic(&stdout, &stderr)
                ));
            }
            certification_captured_output(status, &mut stdout_capture, &mut stderr_capture)
        }
        WAIT_TIMEOUT => {
            let cleanup = cleanup_windows_certification_process(job.take(), &mut child, assigned);
            let stdout =
                read_certification_capture(&mut stdout_capture, "stdout").unwrap_or_default();
            let stderr =
                read_certification_capture(&mut stderr_capture, "stderr").unwrap_or_default();
            Err(format!(
                "certification command timed out after {}s; {cleanup}; {}",
                timeout.as_secs(),
                certification_capture_diagnostic(&stdout, &stderr)
            ))
        }
        WAIT_FAILED => {
            let wait_error = std::io::Error::last_os_error();
            let cleanup = cleanup_windows_certification_process(job.take(), &mut child, assigned);
            Err(format!(
                "WaitForSingleObject failed: {wait_error}; {cleanup}"
            ))
        }
        other => {
            let cleanup = cleanup_windows_certification_process(job.take(), &mut child, assigned);
            Err(format!("unexpected process wait result {other}; {cleanup}"))
        }
    }
}

fn require_certification_tool_success(
    runtime: &CertificationCommandRuntime,
    profile_isolation: &mut Vec<CertificationProfileIsolationEvidence>,
    invocation_id: &str,
    expectation: CertificationProfileLaunchExpectation,
    tool: &str,
    params: &serde_json::Value,
) -> Result<String, String> {
    let output = run_certification_tool(
        runtime,
        profile_isolation,
        invocation_id,
        expectation,
        tool,
        params,
    )?;
    if !output.status.success() {
        return Err(format!(
            "{tool} failed; {}",
            certification_output_diagnostic(&output)
        ));
    }
    if !output.stderr.is_empty() {
        return Err(format!(
            "{tool} successful execution wrote unexpected stderr; {}",
            certification_output_diagnostic(&output)
        ));
    }
    let stdout = std::str::from_utf8(&output.stdout).map_err(|_| {
        format!(
            "{tool} stdout encoding was not UTF-8; {}",
            certification_output_diagnostic(&output)
        )
    })?;
    Ok(stdout.to_string())
}

fn certification_tool_error_code(output: &Output) -> Result<Option<String>, String> {
    let stdout = std::str::from_utf8(&output.stdout).map_err(|_| {
        format!(
            "failed-tool stdout encoding was not UTF-8; {}",
            certification_output_diagnostic(output)
        )
    })?;
    let stderr = std::str::from_utf8(&output.stderr).map_err(|_| {
        format!(
            "failed-tool stderr encoding was not UTF-8; {}",
            certification_output_diagnostic(output)
        )
    })?;
    Ok(certification_error_code_text(stdout, stderr))
}

fn certification_error_code_text(_stdout: &str, stderr: &str) -> Option<String> {
    let code_tokens = stderr
        .split_whitespace()
        .filter(|word| word.starts_with("code="))
        .collect::<Vec<_>>();
    if code_tokens.len() != 1 {
        return None;
    }
    let code = code_tokens[0]
        .strip_prefix("code=")?
        .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '_');
    (!code.is_empty()).then(|| code.to_string())
}

fn parse_certification_json(tool: &str, stdout: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(stdout.trim())
        .map_err(|error| certification_json_error_diagnostic(tool, stdout, &error))
}

fn certification_bytes_diagnostic(label: &str, bytes: &[u8]) -> String {
    format!(
        "{label}_bytes={}; {label}_sha256={}",
        bytes.len(),
        xref_sha256_bytes(bytes)
    )
}

fn certification_output_diagnostic(output: &Output) -> String {
    format!(
        "status_code={:?}; {}; {}",
        output.status.code(),
        certification_bytes_diagnostic("stdout", &output.stdout),
        certification_bytes_diagnostic("stderr", &output.stderr)
    )
}

fn certification_json_error_diagnostic(
    label: &str,
    bytes: &str,
    error: &serde_json::Error,
) -> String {
    certification_json_bytes_error_diagnostic(label, bytes.as_bytes(), error)
}

fn certification_json_bytes_error_diagnostic(
    label: &str,
    bytes: &[u8],
    error: &serde_json::Error,
) -> String {
    format!(
        "{label} output was not closed JSON: category={:?}; line={}; column={}; {}",
        error.classify(),
        error.line(),
        error.column(),
        certification_bytes_diagnostic("output", bytes)
    )
}

fn redacted_certification_failure(class: &str, detail: &str) -> String {
    format!(
        "class={class}; {}",
        certification_bytes_diagnostic("detail", detail.as_bytes())
    )
}

fn canonical_certification_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(canonical_certification_json).collect())
        }
        serde_json::Value::Object(values) => {
            let sorted = values
                .iter()
                .map(|(key, value)| (key.clone(), canonical_certification_json(value)))
                .collect::<BTreeMap<_, _>>();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar.clone(),
    }
}

fn verify_expanded_layer_records(output: &serde_json::Value) -> Result<(), String> {
    const FIELDS: [&str; 17] = [
        "handle",
        "name",
        "color_index",
        "line_type",
        "line_weight",
        "frozen",
        "locked",
        "off",
        "is_plottable",
        "xref_dependent",
        "xref_block_record_handle",
        "xref_name",
        "xref_path",
        "xref_is_overlay",
        "material_handle",
        "plotstyle_handle",
        "is_current",
    ];
    let records = output
        .as_array()
        .ok_or_else(|| "list_layers certification output must be an array".to_string())?;
    if records.is_empty() {
        return Err("list_layers certification output must not be empty".to_string());
    }
    let required = FIELDS.into_iter().collect::<BTreeSet<_>>();
    for (index, record) in records.iter().enumerate() {
        let record = record
            .as_object()
            .ok_or_else(|| format!("list_layers certification record {index} must be an object"))?;
        let actual = record.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if actual != required {
            return Err(format!(
                "list_layers certification record {index} has a non-closed field inventory; expected {required:?}"
            ));
        }
    }
    Ok(())
}

fn write_certification_json(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("evidence path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing certification evidence: {}",
            path.display()
        ));
    }
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("failed to stage evidence in {}: {error}", parent.display()))?;
    serde_json::to_writer_pretty(staged.as_file_mut(), value)
        .map_err(|error| format!("failed to serialize evidence {}: {error}", path.display()))?;
    staged
        .as_file_mut()
        .write_all(b"\n")
        .map_err(|error| format!("failed to finish evidence {}: {error}", path.display()))?;
    staged
        .as_file_mut()
        .sync_all()
        .map_err(|error| format!("failed to sync evidence {}: {error}", path.display()))?;
    staged
        .persist_noclobber(path)
        .map_err(|error| format!("failed to publish evidence {}: {error}", path.display()))?;
    Ok(())
}

#[derive(Debug)]
struct BoundCertificationRuntime {
    activation_target: CertificationActivationTarget,
    command: CertificationCommandRuntime,
    release_binary: ExactCertificationFile,
    accoreconsole: ExactCertificationFile,
    certified_arg: ExactCertificationFile,
    engine_identity: engine::AutocadEngineIdentity,
    binary_build_identity: XrefCertificationBuildIdentity,
    binary_reported_certified_arg_sha256: String,
    binary_reported_certified_arg_policy_id: String,
    binary_reported_certified_arg_policy_sha256: String,
    binary_reported_title_block_profile_registry_sha256: String,
    binary_reported_title_block_profiles: Vec<CertificationProfileDefinition>,
}

impl BoundCertificationRuntime {
    fn bind(requirements: &CertificationRuntimeRequirements) -> Result<Self, String> {
        let release_binary = bind_exact_certification_file(
            &requirements.release_binary_path,
            &requirements.release_binary_sha256,
            "release binary",
        )?;
        let accoreconsole = bind_exact_certification_file(
            &requirements.accoreconsole_path,
            &requirements.accoreconsole_sha256,
            "accoreconsole",
        )?;
        let certified_arg = bind_exact_certification_file(
            &requirements.certified_arg_path,
            &requirements.certified_arg_sha256,
            "certified ARG",
        )?;

        let engine_identity = engine::identify_accoreconsole(accoreconsole.canonical_path.clone())
            .map_err(|error| format!("failed to identify exact accoreconsole: {error}"))?;
        if engine_identity.product != requirements.autocad_product
            || engine_identity.version != requirements.autocad_version
        {
            return Err(format!(
                "observed AutoCAD identity {}/{} does not match manifest {}/{}",
                engine_identity.product,
                engine_identity.version,
                requirements.autocad_product,
                requirements.autocad_version
            ));
        }

        let local_profile_sha256 = profiles::title_block_profile_registry_sha256();
        let local_profile_definitions = embedded_certification_profile_definitions();
        if local_profile_sha256 != requirements.title_block_profile_registry_sha256 {
            return Err(format!(
                "manifest title profile registry SHA-256 {} does not match the harness registry {}",
                requirements.title_block_profile_registry_sha256, local_profile_sha256
            ));
        }

        let binary_info = xref_binary_certification_info(&release_binary.canonical_path)?;
        validate_release_flavor_certification_info(&binary_info, "release binary", false)?;
        let binary_build_identity = xref_binary_build_identity(&binary_info, "release");
        if binary_build_identity.profile != "release"
            || binary_build_identity.certification_failpoints_enabled
            || !binary_build_identity.target.contains("windows")
        {
            return Err(format!(
                "certification executable is not an exact non-failpoint Windows release build: {:?}",
                binary_build_identity
            ));
        }
        let binary_reported_certified_arg_sha256 =
            required_binary_info_digest(&binary_info, "certified_arg_sha256")?;
        if binary_reported_certified_arg_sha256 != requirements.certified_arg_sha256 {
            return Err(
                "release binary was not built for the manifest-certified ARG digest".to_string(),
            );
        }
        let binary_reported_certified_arg_policy_id =
            required_binary_info_string(&binary_info, "certified_arg_policy_id")?;
        let binary_reported_certified_arg_policy_sha256 =
            required_binary_info_digest(&binary_info, "certified_arg_policy_sha256")?;
        if binary_reported_certified_arg_policy_id != requirements.certified_arg_policy_id
            || binary_reported_certified_arg_policy_sha256
                != requirements.certified_arg_policy_sha256
            || binary_build_identity.certified_arg_sha256 != requirements.certified_arg_sha256
            || binary_build_identity.certified_arg_policy_id != requirements.certified_arg_policy_id
            || binary_build_identity.certified_arg_policy_sha256
                != requirements.certified_arg_policy_sha256
        {
            return Err(
                "release binary was not built for the manifest-certified ARG policy identity"
                    .to_string(),
            );
        }
        let binary_reported_title_block_profile_registry_sha256 =
            required_binary_info_digest(&binary_info, "title_block_profile_registry_sha256")?;
        if binary_reported_title_block_profile_registry_sha256
            != requirements.title_block_profile_registry_sha256
        {
            return Err(
                "release binary does not embed the manifest-certified title profile registry"
                    .to_string(),
            );
        }
        let binary_reported_title_block_profiles = serde_json::from_value::<
            Vec<CertificationProfileDefinition>,
        >(
            binary_info
                .get("title_block_profiles")
                .cloned()
                .ok_or_else(|| "release binary did not report title_block_profiles".to_string())?,
        )
        .map_err(|error| {
            format!("release binary reported invalid title_block_profiles: {error}")
        })?;
        if binary_reported_title_block_profiles != local_profile_definitions {
            return Err(
                "release binary title-block profile definitions do not match the harness registry"
                    .to_string(),
            );
        }

        let command = CertificationCommandRuntime {
            release_binary: release_binary.canonical_path.clone(),
            accoreconsole: accoreconsole.canonical_path.clone(),
            certified_arg: certified_arg.canonical_path.clone(),
            certified_arg_sha256: certified_arg.sha256_before.clone(),
        };
        certified_arg_profile_root_from_file(
            &certified_arg.canonical_path,
            Some(&certified_arg.sha256_before),
        )
        .map_err(|error| format!("certified ARG profile binding failed: {error}"))?;
        Ok(Self {
            activation_target: requirements.activation_target.clone(),
            command,
            release_binary,
            accoreconsole,
            certified_arg,
            engine_identity,
            binary_build_identity,
            binary_reported_certified_arg_sha256,
            binary_reported_certified_arg_policy_id,
            binary_reported_certified_arg_policy_sha256,
            binary_reported_title_block_profile_registry_sha256,
            binary_reported_title_block_profiles,
        })
    }

    fn finish(self) -> Result<CertificationRuntimeEvidence, String> {
        let release_binary_sha256_after =
            verify_exact_certification_file_unchanged(&self.release_binary, "release binary")?;
        let accoreconsole_sha256_after =
            verify_exact_certification_file_unchanged(&self.accoreconsole, "accoreconsole")?;
        let certified_arg_sha256_after =
            verify_exact_certification_file_unchanged(&self.certified_arg, "certified ARG")?;
        Ok(CertificationRuntimeEvidence {
            activation_target: self.activation_target,
            platform: std::env::consts::OS.to_string(),
            release_binary_path: self.release_binary.configured_path,
            release_binary_canonical_path: certification_path_string(
                &self.release_binary.canonical_path,
            )?,
            release_binary_sha256_before: self.release_binary.sha256_before,
            release_binary_sha256_after,
            accoreconsole_path: self.accoreconsole.configured_path,
            accoreconsole_canonical_path: certification_path_string(
                &self.accoreconsole.canonical_path,
            )?,
            accoreconsole_sha256_before: self.accoreconsole.sha256_before,
            accoreconsole_sha256_after,
            certified_arg_path: self.certified_arg.configured_path,
            certified_arg_canonical_path: certification_path_string(
                &self.certified_arg.canonical_path,
            )?,
            certified_arg_sha256_before: self.certified_arg.sha256_before,
            certified_arg_sha256_after,
            certified_arg_policy_id: self.binary_reported_certified_arg_policy_id.clone(),
            certified_arg_policy_sha256: self.binary_reported_certified_arg_policy_sha256.clone(),
            observed_autocad_product: self.engine_identity.product,
            observed_autocad_version: self.engine_identity.version,
            binary_build_identity: self.binary_build_identity,
            binary_reported_certified_arg_sha256: self.binary_reported_certified_arg_sha256,
            binary_reported_certified_arg_policy_id: self.binary_reported_certified_arg_policy_id,
            binary_reported_certified_arg_policy_sha256: self
                .binary_reported_certified_arg_policy_sha256,
            binary_reported_title_block_profile_registry_sha256: self
                .binary_reported_title_block_profile_registry_sha256,
            binary_reported_title_block_profiles: self.binary_reported_title_block_profiles,
        })
    }
}

fn required_binary_info_digest(
    binary_info: &serde_json::Value,
    field: &str,
) -> Result<String, String> {
    let value = required_binary_info_string(binary_info, field)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!(
            "release binary reported malformed lowercase SHA-256 in {field}"
        ));
    }
    Ok(value)
}

fn required_binary_info_string(
    binary_info: &serde_json::Value,
    field: &str,
) -> Result<String, String> {
    binary_info
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("release binary did not report string {field}"))
}

fn certification_path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("certification path is not UTF-8: {}", path.display()))
}

fn read_certification_manifest(path: &Path) -> Result<(CertificationManifest, String), String> {
    let bytes = std::fs::read(path).map_err(|error| {
        format!(
            "failed to read certification manifest {}: {error}",
            path.display()
        )
    })?;
    let json = std::str::from_utf8(&bytes)
        .map_err(|error| format!("certification manifest is not UTF-8: {error}"))?;
    let manifest = CertificationManifest::from_json(json)
        .map_err(|error| format!("invalid certification manifest: {error}"))?;
    Ok((manifest, certification_manifest_sha256(&bytes)))
}

#[derive(Debug)]
struct Tier2DrawingSuccess {
    profile_id: String,
    fingerprint: CertificationTitleBlockFingerprint,
    pre_title_blocks: CertificationTitleBlockSnapshot,
    post_title_blocks: CertificationTitleBlockSnapshot,
    observed_layouts: Vec<String>,
    plot: Option<CertificationPlotEvidence>,
}

fn run_tier2_drawing_certification(
    release_id: &str,
    fixture_root: &Path,
    drawing: &autocad_mcp::certification::CertificationDrawing,
    lane_root: &Path,
    runtime: &CertificationCommandRuntime,
) -> Result<Tier2DrawingCertificationEvidence, String> {
    let case_root = create_fresh_certification_case_root(&lane_root.join(&drawing.drawing_id))?;
    let case_root_canonical = case_root
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize Tier 2 case root: {error}"))?;
    let staged_root = create_fresh_certification_case_root(&case_root.join("fixture"))?;
    let staged = stage_certification_file(
        fixture_root,
        &drawing.path,
        &drawing.source_sha256,
        &staged_root,
    )?;
    if staged
        .staged_path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
        != Some("dwg")
    {
        return Err(format!(
            "Tier 2 certification requires a DWG fixture: {}",
            staged.staged_path.display()
        ));
    }
    let staged_drawing_canonical_path = staged.staged_path.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize staged Tier 2 drawing {}: {error}",
            staged.staged_path.display()
        )
    })?;
    let drawing_path = certification_path_string(&staged.staged_path)?;
    let write_fields =
        drawing
            .write_fields
            .iter()
            .try_fold(BTreeMap::new(), |mut fields, write| {
                if fields
                    .insert(write.field.clone(), write.value.clone())
                    .is_some()
                {
                    return Err(format!(
                        "Tier 2 drawing '{}' repeats canonical write field {:?}",
                        drawing.drawing_id, write.field
                    ));
                }
                Ok(fields)
            })?;
    let mut profile_isolation = Vec::new();

    let result = (|| -> Result<Tier2DrawingSuccess, String> {
        let read_params = serde_json::json!({"drawing_path": &drawing_path});
        let before_stdout = require_certification_tool_success(
            runtime,
            &mut profile_isolation,
            "pre/read_title_blocks",
            CertificationProfileLaunchExpectation::NoEngineExpected,
            "read_title_blocks",
            &read_params,
        )?;
        let before = observe_title_blocks(&before_stdout)?;
        if before.profile_id != drawing.expected_profile_id {
            return Err(format!(
                "pre-write observed profile {} does not match manifest {}",
                before.profile_id, drawing.expected_profile_id
            ));
        }
        requested_title_block_tags(&before.title_blocks, &write_fields)?;

        let write_params = serde_json::json!({
            "drawing_path": &drawing_path,
            "fields": &write_fields,
        });
        let write_stdout = require_certification_tool_success(
            runtime,
            &mut profile_isolation,
            "operation/write_title_block",
            CertificationProfileLaunchExpectation::EngineImportRequired,
            "write_title_block",
            &write_params,
        )?;
        verify_write_output(
            &write_stdout,
            &drawing_path,
            &drawing.expected_profile_id,
            drawing.write_fields.len(),
        )?;

        let after_stdout = require_certification_tool_success(
            runtime,
            &mut profile_isolation,
            "post/read_title_blocks",
            CertificationProfileLaunchExpectation::NoEngineExpected,
            "read_title_blocks",
            &read_params,
        )?;
        let after = observe_title_blocks(&after_stdout)?;
        verify_title_block_readback(&before, &after, &drawing.expected_profile_id, &write_fields)?;
        let pre_title_blocks = certification_title_block_snapshot(
            release_id,
            &drawing.drawing_id,
            &before.title_blocks,
        )?;
        let post_title_blocks = certification_title_block_snapshot(
            release_id,
            &drawing.drawing_id,
            &after.title_blocks,
        )?;

        let layouts_stdout = require_certification_tool_success(
            runtime,
            &mut profile_isolation,
            "post/list_layouts",
            CertificationProfileLaunchExpectation::NoEngineExpected,
            "list_layouts",
            &read_params,
        )?;
        let observed_layouts = observe_layout_names(&layouts_stdout)?;
        let plot = if let Some(layout) = &drawing.plot_layout {
            if !observed_layouts.contains(layout) {
                return Err(format!(
                    "manifest plot layout {layout:?} was not observed in the staged drawing"
                ));
            }
            let plot_dir = create_fresh_certification_case_root(&case_root.join("plot"))?;
            let output_path = plot_dir.join(format!("{}.pdf", drawing.drawing_id));
            let output_text = certification_path_string(&output_path)?;
            let plot_params = serde_json::json!({
                "drawing_path": &drawing_path,
                "layout": layout,
                "output": &output_text,
            });
            let stdout = require_certification_tool_success(
                runtime,
                &mut profile_isolation,
                "plot/plot_to_pdf",
                CertificationProfileLaunchExpectation::EngineImportRequired,
                "plot_to_pdf",
                &plot_params,
            )?;
            verify_plot_output(&stdout, &drawing_path, layout, &output_text)?;
            let observation = observe_pdf(&output_path)?;
            Some(CertificationPlotEvidence {
                layout: layout.clone(),
                output_canonical_path: certification_path_string(
                    &output_path
                        .canonicalize()
                        .map_err(|error| format!("failed to canonicalize plotted PDF: {error}"))?,
                )?,
                pdf_sha256: observation.sha256,
                pdf_size_bytes: observation.size,
            })
        } else {
            None
        };

        Ok(Tier2DrawingSuccess {
            profile_id: after.profile_id.clone(),
            fingerprint: CertificationTitleBlockFingerprint {
                block_name: after.fingerprint.block_name.clone(),
                attribute_tags: after.fingerprint.attribute_tags.clone(),
            },
            pre_title_blocks,
            post_title_blocks,
            observed_layouts,
            plot,
        })
    })();

    let final_drawing_sha256 =
        xref_sha256_file(&staged_drawing_canonical_path).map_err(|error| error.to_string())?;
    let source_sha256_after =
        xref_sha256_file(&staged.source_path).map_err(|error| error.to_string())?;
    let result = result.and_then(|success| {
        if source_sha256_after != drawing.source_sha256 {
            return Err("private Tier 2 source drawing changed during certification".to_string());
        }
        if final_drawing_sha256 == staged.sha256 {
            return Err(
                "title-block certification did not change the staged drawing bytes".to_string(),
            );
        }
        Ok(success)
    });

    let (status, reason, success) = match result {
        Ok(success) => (CertificationResultStatus::Passed, None, Some(success)),
        Err(reason) => (
            CertificationResultStatus::Failed,
            Some(redacted_certification_failure(
                "tier2_drawing_failure",
                &reason,
            )),
            None,
        ),
    };
    Ok(Tier2DrawingCertificationEvidence {
        drawing_id: drawing.drawing_id.clone(),
        path: drawing.path.clone(),
        source_sha256: drawing.source_sha256.clone(),
        staged_case_root_canonical_path: certification_path_string(&case_root_canonical)?,
        staged_drawing_canonical_path: certification_path_string(&staged_drawing_canonical_path)?,
        staged_drawing_sha256: staged.sha256,
        final_drawing_sha256,
        status,
        reason,
        observed_profile_id: success.as_ref().map(|success| success.profile_id.clone()),
        observed_fingerprint: success.as_ref().map(|success| success.fingerprint.clone()),
        pre_title_blocks: success
            .as_ref()
            .map(|success| success.pre_title_blocks.clone())
            .unwrap_or_else(|| CertificationTitleBlockSnapshot {
                records: Vec::new(),
                sha256: certification_title_snapshot_sha256(&[]),
            }),
        post_title_blocks: success
            .as_ref()
            .map(|success| success.post_title_blocks.clone())
            .unwrap_or_else(|| CertificationTitleBlockSnapshot {
                records: Vec::new(),
                sha256: certification_title_snapshot_sha256(&[]),
            }),
        observed_layouts: success
            .as_ref()
            .map(|success| success.observed_layouts.clone()),
        plot: success.and_then(|success| success.plot),
        profile_isolation,
    })
}

fn prepare_certification_output_dir(
    output_dir: &Path,
    fixture_root: &Path,
) -> Result<PathBuf, String> {
    if !output_dir.is_absolute() {
        return Err(format!(
            "certification output directory must be absolute: {}",
            output_dir.display()
        ));
    }
    let metadata = std::fs::symlink_metadata(output_dir).map_err(|error| {
        format!(
            "certification output directory must already exist at {}: {error}",
            output_dir.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "certification output must be a real directory, not a symlink or file: {}",
            output_dir.display()
        ));
    }
    let output = output_dir.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize certification output {}: {error}",
            output_dir.display()
        )
    })?;
    let fixtures = fixture_root.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize certification fixture root {}: {error}",
            fixture_root.display()
        )
    })?;
    if output.starts_with(&fixtures) || fixtures.starts_with(&output) {
        return Err(format!(
            "certification output and private fixture roots must not overlap: output={}, fixtures={}",
            output.display(),
            fixtures.display()
        ));
    }
    Ok(output_dir.to_path_buf())
}

#[test]
#[ignore]
fn xref_windows_certification_gate() {
    let manifest_path = env_path("AUTOCAD_MCP_XREF_CERT_MANIFEST")
        .expect("strict XREF certification requires AUTOCAD_MCP_XREF_CERT_MANIFEST");
    let output_dir = env_path("AUTOCAD_MCP_CERT_OUTPUT_DIR")
        .expect("strict XREF certification requires AUTOCAD_MCP_CERT_OUTPUT_DIR");
    let certified_arg_path = env_path("AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH")
        .expect("strict XREF certification requires AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH");
    if std::env::consts::OS != "windows" {
        panic!("strict XREF certification requires Windows");
    }

    let manifest_json = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", manifest_path.display()));
    let manifest = XrefCertificationManifest::from_json(&manifest_json)
        .unwrap_or_else(|error| panic!("invalid XREF certification manifest: {error}"));
    validate_xref_certification_manifest(&manifest)
        .unwrap_or_else(|error| panic!("invalid XREF certification manifest: {error}"));
    let configured_arg_path = certification_path_string(&certified_arg_path)
        .unwrap_or_else(|error| panic!("strict XREF certified ARG path is invalid: {error}"));
    if !autocad_mcp::certification::certification_windows_paths_equal(
        &configured_arg_path,
        &manifest.certified_arg_path,
    ) {
        panic!("strict XREF certified ARG environment path does not match the manifest");
    }
    let certified_arg_binding = bind_exact_certification_file(
        &manifest.certified_arg_path,
        &manifest.certified_arg_sha256,
        "strict XREF certified ARG",
    )
    .unwrap_or_else(|error| panic!("strict XREF certified ARG binding failed: {error}"));
    let certified_arg_canonical_path = certified_arg_binding.canonical_path.clone();
    let certified_arg_sha256 = certified_arg_binding.sha256_before.clone();

    let registry = embedded_xref_artifacts().expect("embedded XREF artifacts must be valid");

    let release_binary_binding = bind_exact_certification_file(
        &manifest.release_binary_path,
        &manifest.release_binary_sha256,
        "strict XREF release binary",
    )
    .unwrap_or_else(|error| panic!("strict XREF release binary binding failed: {error}"));
    let instrumented_binary_binding = bind_exact_certification_file(
        &manifest.instrumented_binary_path,
        &manifest.instrumented_binary_sha256,
        "strict XREF instrumented binary",
    )
    .unwrap_or_else(|error| panic!("strict XREF instrumented binary binding failed: {error}"));
    let release_binary = release_binary_binding.canonical_path.clone();
    let instrumented_binary = instrumented_binary_binding.canonical_path.clone();
    let release_binary_info = xref_binary_certification_info(&release_binary)
        .unwrap_or_else(|error| panic!("release binary introspection failed: {error}"));
    let instrumented_binary_info = xref_binary_certification_info(&instrumented_binary)
        .unwrap_or_else(|error| panic!("instrumented binary introspection failed: {error}"));
    validate_release_flavor_certification_info(&release_binary_info, "release binary", false)
        .unwrap_or_else(|error| panic!("release binary admission failed: {error}"));
    validate_release_flavor_certification_info(
        &instrumented_binary_info,
        "instrumented binary",
        true,
    )
    .unwrap_or_else(|error| panic!("instrumented binary admission failed: {error}"));
    let release_build_identity = xref_binary_build_identity(&release_binary_info, "release");
    let instrumented_build_identity =
        xref_binary_build_identity(&instrumented_binary_info, "instrumented");
    let expected_artifacts = serde_json::to_value(xref_embedded_artifact_sha256()).unwrap();
    assert_eq!(release_binary_info["artifact_sha256"], expected_artifacts);
    assert_eq!(
        instrumented_binary_info["artifact_sha256"],
        expected_artifacts
    );
    assert_eq!(
        release_binary_info["certified_arg_sha256"].as_str(),
        Some(certified_arg_sha256.as_str()),
        "release binary must report the certified ARG digest embedded in that executable"
    );
    assert_eq!(
        instrumented_binary_info["certified_arg_sha256"].as_str(),
        Some(certified_arg_sha256.as_str()),
        "instrumented binary must report the same certified ARG digest"
    );
    for (label, info, identity) in [
        ("release", &release_binary_info, &release_build_identity),
        (
            "instrumented",
            &instrumented_binary_info,
            &instrumented_build_identity,
        ),
    ] {
        assert_eq!(
            info["certified_arg_policy_id"].as_str(),
            Some(manifest.certified_arg_policy_id.as_str()),
            "{label} binary must report the certified ARG policy ID"
        );
        assert_eq!(
            info["certified_arg_policy_sha256"].as_str(),
            Some(manifest.certified_arg_policy_sha256.as_str()),
            "{label} binary must report the certified ARG policy digest"
        );
        assert_eq!(
            identity.certified_arg_sha256, manifest.certified_arg_sha256,
            "{label} build identity must bind the certified ARG digest"
        );
        assert_eq!(
            identity.certified_arg_policy_id, manifest.certified_arg_policy_id,
            "{label} build identity must bind the certified ARG policy ID"
        );
        assert_eq!(
            identity.certified_arg_policy_sha256, manifest.certified_arg_policy_sha256,
            "{label} build identity must bind the certified ARG policy digest"
        );
    }
    let release_binary_sha256 = release_binary_binding.sha256_before.clone();
    let instrumented_binary_sha256 = instrumented_binary_binding.sha256_before.clone();
    assert_ne!(
        release_binary_sha256, instrumented_binary_sha256,
        "release and failpoint-enabled binaries must differ"
    );

    std::fs::create_dir_all(&output_dir)
        .unwrap_or_else(|error| panic!("failed to create {}: {error}", output_dir.display()));
    let shared_operation_source_sha256 = release_build_identity
        .shared_operation_source_sha256
        .clone();
    let attestation = XrefCertificationAttestation {
        schema_version: XREF_CERTIFICATION_SCHEMA_VERSION,
        release_id: manifest.release_id.clone(),
        activation_target: manifest.activation_target.clone(),
        manifest_sha256: xref_certification_manifest_sha256(&manifest),
        release_binary_sha256: release_binary_sha256.clone(),
        instrumented_binary_sha256: instrumented_binary_sha256.clone(),
        certified_arg_sha256: manifest.certified_arg_sha256.clone(),
        certified_arg_policy_id: manifest.certified_arg_policy_id.clone(),
        certified_arg_policy_sha256: manifest.certified_arg_policy_sha256.clone(),
        artifact_sha256: xref_embedded_artifact_sha256(),
        release_build_identity: release_build_identity.clone(),
        instrumented_build_identity: instrumented_build_identity.clone(),
        shared_operation_source_sha256,
    };
    validate_xref_certification_attestation(&manifest, &attestation)
        .unwrap_or_else(|error| panic!("invalid XREF binary attestation: {error}"));

    certified_arg_profile_root_from_file(
        &certified_arg_canonical_path,
        Some(&certified_arg_sha256),
    )
    .unwrap_or_else(|error| panic!("strict XREF certified ARG binding failed: {error}"));
    let (release_engine_binding, release_engine_identity) =
        bind_xref_certification_engine(&manifest)
            .unwrap_or_else(|error| panic!("strict XREF release engine binding failed: {error}"));
    let release_runtime = XrefCertificationCommandRuntime {
        binary: release_binary.clone(),
        accoreconsole: release_engine_binding.canonical_path.clone(),
        certified_arg: certified_arg_canonical_path.clone(),
        certified_arg_sha256: certified_arg_sha256.clone(),
    };
    let release_run = run_xref_certification_cases(
        &manifest.fixture_root,
        &manifest.release_cases,
        XrefCertificationEvidenceClass::ReleaseConformance,
        &release_runtime,
        &output_dir,
    );
    let release_engine =
        finish_xref_certification_engine(release_engine_binding, release_engine_identity)
            .unwrap_or_else(|error| panic!("strict XREF release engine changed: {error}"));
    let release_binary_observation =
        finish_xref_certification_binary(release_binary_binding, "strict XREF release binary")
            .unwrap_or_else(|error| panic!("strict XREF release binary changed: {error}"));

    let (instrumented_engine_binding, instrumented_engine_identity) =
        bind_xref_certification_engine(&manifest).unwrap_or_else(|error| {
            panic!("strict XREF instrumented engine binding failed: {error}")
        });
    let instrumented_runtime = XrefCertificationCommandRuntime {
        binary: instrumented_binary.clone(),
        accoreconsole: instrumented_engine_binding.canonical_path.clone(),
        certified_arg: certified_arg_canonical_path.clone(),
        certified_arg_sha256: certified_arg_sha256.clone(),
    };
    let instrumented_run = run_xref_certification_cases(
        &manifest.fixture_root,
        &manifest.instrumented_cases,
        XrefCertificationEvidenceClass::InstrumentedTransaction,
        &instrumented_runtime,
        &output_dir,
    );
    let instrumented_engine =
        finish_xref_certification_engine(instrumented_engine_binding, instrumented_engine_identity)
            .unwrap_or_else(|error| panic!("strict XREF instrumented engine changed: {error}"));
    let instrumented_binary_observation = finish_xref_certification_binary(
        instrumented_binary_binding,
        "strict XREF instrumented binary",
    )
    .unwrap_or_else(|error| panic!("strict XREF instrumented binary changed: {error}"));
    let certified_arg_sha256_after = verify_exact_certification_file_unchanged(
        &certified_arg_binding,
        "strict XREF certified ARG",
    )
    .unwrap_or_else(|error| panic!("strict XREF certified ARG changed: {error}"));
    let certified_arg_configured_path = certified_arg_binding.configured_path.clone();
    let certified_arg_canonical_path =
        certification_path_string(&certified_arg_binding.canonical_path)
            .unwrap_or_else(|error| panic!("strict XREF certified ARG path is invalid: {error}"));
    let certified_arg_sha256_before = certified_arg_binding.sha256_before.clone();
    let profile_references = xref_certification_profile_references(registry);
    let release_evidence = XrefCertificationEvidence {
        schema_version: XREF_CERTIFICATION_SCHEMA_VERSION,
        evidence_class: XrefCertificationEvidenceClass::ReleaseConformance,
        release_id: manifest.release_id.clone(),
        activation_target: manifest.activation_target.clone(),
        status: aggregate_xref_case_status(&release_run),
        manifest_sha256: xref_certification_manifest_sha256(&manifest),
        binary_sha256: release_binary_sha256,
        binary_path: release_binary_observation.binary_path,
        binary_canonical_path: release_binary_observation.binary_canonical_path,
        binary_sha256_before: release_binary_observation.binary_sha256_before,
        binary_sha256_after: release_binary_observation.binary_sha256_after,
        certified_arg_path: certified_arg_configured_path.clone(),
        certified_arg_canonical_path: certified_arg_canonical_path.clone(),
        certified_arg_sha256_before: certified_arg_sha256_before.clone(),
        certified_arg_sha256_after: certified_arg_sha256_after.clone(),
        binary_reported_certified_arg_sha256: manifest.certified_arg_sha256.clone(),
        certified_arg_policy_id: manifest.certified_arg_policy_id.clone(),
        certified_arg_policy_sha256: manifest.certified_arg_policy_sha256.clone(),
        artifact_sha256: xref_embedded_artifact_sha256(),
        build_identity: release_build_identity,
        accoreconsole_path: release_engine.accoreconsole_path,
        accoreconsole_canonical_path: release_engine.accoreconsole_canonical_path,
        accoreconsole_sha256_before: release_engine.accoreconsole_sha256_before,
        accoreconsole_sha256_after: release_engine.accoreconsole_sha256_after,
        observed_autocad_product: release_engine.observed_autocad_product,
        observed_autocad_version: release_engine.observed_autocad_version,
        profile_references: profile_references.clone(),
        case_results: release_run.results,
        case_failures: release_run.failures,
    };
    let instrumented_evidence = XrefCertificationEvidence {
        schema_version: XREF_CERTIFICATION_SCHEMA_VERSION,
        evidence_class: XrefCertificationEvidenceClass::InstrumentedTransaction,
        release_id: manifest.release_id.clone(),
        activation_target: manifest.activation_target.clone(),
        status: aggregate_xref_case_status(&instrumented_run),
        manifest_sha256: xref_certification_manifest_sha256(&manifest),
        binary_sha256: instrumented_binary_sha256,
        binary_path: instrumented_binary_observation.binary_path,
        binary_canonical_path: instrumented_binary_observation.binary_canonical_path,
        binary_sha256_before: instrumented_binary_observation.binary_sha256_before,
        binary_sha256_after: instrumented_binary_observation.binary_sha256_after,
        certified_arg_path: certified_arg_configured_path,
        certified_arg_canonical_path,
        certified_arg_sha256_before,
        certified_arg_sha256_after,
        binary_reported_certified_arg_sha256: manifest.certified_arg_sha256.clone(),
        certified_arg_policy_id: manifest.certified_arg_policy_id.clone(),
        certified_arg_policy_sha256: manifest.certified_arg_policy_sha256.clone(),
        artifact_sha256: xref_embedded_artifact_sha256(),
        build_identity: instrumented_build_identity,
        accoreconsole_path: instrumented_engine.accoreconsole_path,
        accoreconsole_canonical_path: instrumented_engine.accoreconsole_canonical_path,
        accoreconsole_sha256_before: instrumented_engine.accoreconsole_sha256_before,
        accoreconsole_sha256_after: instrumented_engine.accoreconsole_sha256_after,
        observed_autocad_product: instrumented_engine.observed_autocad_product,
        observed_autocad_version: instrumented_engine.observed_autocad_version,
        profile_references,
        case_results: instrumented_run.results,
        case_failures: instrumented_run.failures,
    };

    validate_xref_certification_bundle(
        &manifest,
        &release_evidence,
        &instrumented_evidence,
        &attestation,
    )
    .unwrap_or_else(|error| panic!("strict XREF certification did not pass: {error}"));
    write_xref_json(
        &output_dir.join(XREF_WINDOWS_EVIDENCE_FILE),
        &release_evidence,
    );
    write_xref_json(
        &output_dir.join(XREF_TRANSACTION_EVIDENCE_FILE),
        &instrumented_evidence,
    );
    write_xref_json(
        &output_dir.join(XREF_CERTIFICATION_ATTESTATION_FILE),
        &attestation,
    );
}

#[test]
#[ignore]
fn windows_certification_gate() {
    let inputs = strict_windows_inputs(
        std::env::consts::OS,
        env_path("AUTOCAD_MCP_TIER2_MANIFEST"),
        env_path("AUTOCAD_MCP_CERT_OUTPUT_DIR"),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let (manifest, manifest_sha256) = read_certification_manifest(&inputs.manifest_path)
        .unwrap_or_else(|error| panic!("{error}"));
    let supported_profiles = embedded_certification_profile_definitions();
    validate_release_manifest(&manifest, &supported_profiles, true)
        .unwrap_or_else(|error| panic!("invalid release certification manifest: {error}"));
    let fixture_root = PathBuf::from(&manifest.fixture_root);
    let output_dir = prepare_certification_output_dir(&inputs.output_dir, &fixture_root)
        .unwrap_or_else(|error| panic!("{error}"));
    let fixture_root_canonical_path = certification_path_string(
        &fixture_root
            .canonicalize()
            .unwrap_or_else(|error| panic!("failed to canonicalize fixture root: {error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let lane_root = create_fresh_certification_case_root(&output_dir.join("tier2-profile-cases"))
        .unwrap_or_else(|error| panic!("{error}"));
    let runtime = BoundCertificationRuntime::bind(&manifest.runtime)
        .unwrap_or_else(|error| panic!("invalid certification runtime: {error}"));

    let drawings = manifest
        .tier2_drawings
        .iter()
        .map(|drawing| {
            run_tier2_drawing_certification(
                &manifest.release_id,
                &fixture_root,
                drawing,
                &lane_root,
                &runtime.command,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "failed to run Tier 2 drawing '{}': {error}",
                    drawing.drawing_id
                )
            })
        })
        .collect::<Vec<_>>();
    let passed = drawings
        .iter()
        .all(|drawing| drawing.status == CertificationResultStatus::Passed);
    let runtime_evidence = runtime
        .finish()
        .unwrap_or_else(|error| panic!("runtime stability check failed: {error}"));
    let evidence = Tier2ProfileCertificationEvidence {
        schema_version: CERTIFICATION_SCHEMA_VERSION,
        evidence_class: CertificationEvidenceClass::Tier2Profile,
        release_id: manifest.release_id.clone(),
        status: if passed {
            CertificationResultStatus::Passed
        } else {
            CertificationResultStatus::Failed
        },
        reason: (!passed).then(|| "one or more Tier 2 drawing cases failed".to_string()),
        manifest_sha256: manifest_sha256.clone(),
        runtime: runtime_evidence,
        fixture_root_canonical_path,
        drawings,
    };
    let evidence_path = output_dir.join(TIER2_PROFILE_WINDOWS_EVIDENCE_FILE);
    validate_tier2_profile_certification_evidence(
        &manifest,
        &supported_profiles,
        true,
        &manifest_sha256,
        &evidence,
    )
    .unwrap_or_else(|error| panic!("Tier 2 profile certification did not pass: {error}"));
    validate_tier2_profile_certification_artifacts(&evidence)
        .unwrap_or_else(|error| panic!("Tier 2 retained plot artifacts did not pass: {error}"));
    write_certification_json(&evidence_path, &evidence).unwrap_or_else(|error| panic!("{error}"));
    eprintln!("wrote {}", evidence_path.display());
}

#[test]
#[ignore]
fn layer_windows_certification_gate() {
    let inputs = strict_windows_inputs(
        std::env::consts::OS,
        env_path("AUTOCAD_MCP_TIER2_MANIFEST"),
        env_path("AUTOCAD_MCP_CERT_OUTPUT_DIR"),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let (manifest, manifest_sha256) = read_certification_manifest(&inputs.manifest_path)
        .unwrap_or_else(|error| panic!("{error}"));
    validate_layer_mutation_manifest(&manifest)
        .unwrap_or_else(|error| panic!("invalid layer mutation certification manifest: {error}"));
    let fixture_root = PathBuf::from(&manifest.fixture_root);
    let output_dir = prepare_certification_output_dir(&inputs.output_dir, &fixture_root)
        .unwrap_or_else(|error| panic!("{error}"));
    let fixture_root_canonical_path = certification_path_string(
        &fixture_root
            .canonicalize()
            .unwrap_or_else(|error| panic!("failed to canonicalize fixture root: {error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let lane_root = create_fresh_certification_case_root(&output_dir.join("layer-mutation-cases"))
        .unwrap_or_else(|error| panic!("{error}"));
    let runtime = BoundCertificationRuntime::bind(&manifest.runtime)
        .unwrap_or_else(|error| panic!("invalid certification runtime: {error}"));

    let cases = manifest
        .layer_mutation_cases
        .iter()
        .map(|case| {
            run_layer_mutation_case(&fixture_root, case, &lane_root, &runtime.command)
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to run layer mutation case '{}': {error}",
                        case.case_id
                    )
                })
        })
        .collect::<Vec<_>>();
    let runtime_evidence = runtime
        .finish()
        .unwrap_or_else(|error| panic!("runtime stability check failed: {error}"));
    let evidence = LayerMutationCertificationEvidence {
        schema_version: CERTIFICATION_SCHEMA_VERSION,
        evidence_class: CertificationEvidenceClass::LayerMutation,
        release_id: manifest.release_id.clone(),
        status: CertificationResultStatus::Passed,
        reason: None,
        manifest_sha256: manifest_sha256.clone(),
        runtime: runtime_evidence,
        fixture_root_canonical_path,
        cases,
    };
    let evidence_path = output_dir.join(LAYER_MUTATION_WINDOWS_EVIDENCE_FILE);
    validate_layer_mutation_evidence(&manifest, &manifest_sha256, &evidence)
        .unwrap_or_else(|error| panic!("layer mutation certification did not pass: {error}"));
    write_certification_json(&evidence_path, &evidence).unwrap_or_else(|error| panic!("{error}"));
    eprintln!("wrote {}", evidence_path.display());
}

#[derive(Debug)]
struct StagedLayerReference {
    manifest_path: String,
    source_sha256: String,
    staged: StagedCertificationFile,
    staged_canonical_path: PathBuf,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct LayerConfinementKey {
    staged_host_sha256: String,
    sources: Vec<CertificationLayerStateSource>,
    state_key_sha256: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum LayerConfinementCacheAction {
    Reuse,
    Refresh,
}

fn layer_confinement_cache_action(
    cached: Option<&LayerConfinementKey>,
    current: &LayerConfinementKey,
) -> LayerConfinementCacheAction {
    if cached == Some(current) {
        LayerConfinementCacheAction::Reuse
    } else {
        LayerConfinementCacheAction::Refresh
    }
}

#[derive(Debug)]
struct VerifiedLayerConfinement {
    key: LayerConfinementKey,
    evidence: LayerConfinementSnapshotEvidence,
}

fn inspect_regular_layer_case_file(
    path: &Path,
    expected_canonical_path: Option<&Path>,
    case_root: &Path,
    label: &str,
) -> Result<PathBuf, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} must remain a regular non-symlink file: {}",
            path.display()
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize {label} {}: {error}", path.display()))?;
    if canonical == case_root || !canonical.starts_with(case_root) {
        return Err(format!(
            "{label} escaped the fresh layer case root: {}",
            canonical.display()
        ));
    }
    if expected_canonical_path.is_some_and(|expected| canonical != expected) {
        return Err(format!(
            "{label} resolved to a different file during certification: {}",
            path.display()
        ));
    }
    Ok(canonical)
}

fn current_layer_confinement_key(
    staged_host: &StagedCertificationFile,
    staged_host_canonical_path: &Path,
    references: &[StagedLayerReference],
    case_root: &Path,
) -> Result<LayerConfinementKey, String> {
    inspect_regular_layer_case_file(
        &staged_host.staged_path,
        Some(staged_host_canonical_path),
        case_root,
        "staged layer host",
    )?;
    let staged_host_sha256 =
        xref_sha256_file(&staged_host.staged_path).map_err(|error| error.to_string())?;
    let mut sources = references
        .iter()
        .map(|reference| {
            inspect_regular_layer_case_file(
                &reference.staged.staged_path,
                Some(&reference.staged_canonical_path),
                case_root,
                &format!("staged referenced source '{}'", reference.manifest_path),
            )?;
            Ok::<CertificationLayerStateSource, String>(CertificationLayerStateSource {
                manifest_path: reference.manifest_path.clone(),
                sha256: xref_sha256_file(&reference.staged.staged_path)
                    .map_err(|error| error.to_string())?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    sources.sort_by(|left, right| left.manifest_path.cmp(&right.manifest_path));
    if sources
        .windows(2)
        .any(|pair| pair[0].manifest_path == pair[1].manifest_path)
    {
        return Err(
            "layer confinement sources contain duplicate manifest-relative paths".to_string(),
        );
    }
    let state_key_sha256 = certification_layer_state_key_sha256(&staged_host_sha256, &sources);
    Ok(LayerConfinementKey {
        staged_host_sha256,
        sources,
        state_key_sha256,
    })
}

fn verify_layer_fixture_sources_unchanged(
    staged_host: &StagedCertificationFile,
    references: &[StagedLayerReference],
) -> Result<(), String> {
    fn verify_private_source(
        path: &Path,
        expected_sha256: &str,
        label: &str,
    ) -> Result<(), String> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "{label} ceased to be a regular non-symlink file: {}",
                path.display()
            ));
        }
        let canonical = path
            .canonicalize()
            .map_err(|error| format!("failed to canonicalize {label}: {error}"))?;
        if canonical != path {
            return Err(format!(
                "{label} resolved to a different private source file"
            ));
        }
        let actual = xref_sha256_file(path).map_err(|error| error.to_string())?;
        if actual != expected_sha256 {
            return Err(format!("{label} changed during certification"));
        }
        Ok(())
    }

    verify_private_source(
        &staged_host.source_path,
        &staged_host.sha256,
        "private layer host source",
    )?;
    for reference in references {
        verify_private_source(
            &reference.staged.source_path,
            &reference.source_sha256,
            &format!("private referenced source '{}'", reference.manifest_path),
        )?;
        let staged_sha256 =
            xref_sha256_file(&reference.staged.staged_path).map_err(|error| error.to_string())?;
        if staged_sha256 != reference.source_sha256 {
            return Err(format!(
                "staged referenced source '{}' changed during certification",
                reference.manifest_path
            ));
        }
    }
    Ok(())
}

fn canonical_reported_layer_case_file(
    value: &str,
    case_root: &Path,
    label: &str,
) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(format!("{label} is not an absolute path: {value:?}"));
    }
    inspect_regular_layer_case_file(path, None, case_root, label)
}

fn verify_layer_dependency_confinement(
    fixture_kind: LayerCertificationFixtureKind,
    staged_host_canonical_path: &Path,
    case_root: &Path,
    references: &[StagedLayerReference],
    layers: &[LayerRecord],
    dependencies: &XrefDependencyTraversalEnvelope,
) -> Result<Vec<CertificationResolvedSourceEvidence>, String> {
    dependencies
        .validate()
        .map_err(|error| format!("dependency envelope failed closed validation: {error}"))?;
    let reported_host = canonical_reported_layer_case_file(
        &dependencies.drawing,
        case_root,
        "dependency envelope drawing",
    )?;
    if reported_host != staged_host_canonical_path {
        return Err(format!(
            "dependency envelope root {} does not match staged host {}",
            reported_host.display(),
            staged_host_canonical_path.display()
        ));
    }
    if !dependencies.within_limits || dependencies.truncation.is_some() {
        return Err(
            "layer dependency readback must be complete with within_limits=true and truncation=null"
                .to_string(),
        );
    }

    let declared_sources = references
        .iter()
        .map(|reference| reference.staged_canonical_path.clone())
        .collect::<BTreeSet<_>>();
    let mut allowed_immediate_hosts = declared_sources.clone();
    allowed_immediate_hosts.insert(staged_host_canonical_path.to_path_buf());
    let mut dependencies_by_chain = BTreeMap::new();
    for dependency in &dependencies.dependencies {
        if dependencies_by_chain
            .insert(dependency.attachment_chain.clone(), dependency)
            .is_some()
        {
            return Err(
                "dependency graph contains duplicate attachment_chain identities".to_string(),
            );
        }
    }
    let mut resolved_sources = BTreeSet::new();
    for (index, dependency) in dependencies.dependencies.iter().enumerate() {
        if dependency.resolution_state != XrefResolutionState::Resolved
            || dependency.resolution_basis.is_none()
            || !matches!(
                dependency.inspection_state,
                XrefInspectionState::Inspected | XrefInspectionState::TerminalOverlay
            )
            || dependency.cycle_target_chain.is_some()
        {
            return Err(format!(
                "dependency {index} was not fully resolved and inspectable: {dependency:?}"
            ));
        }
        if dependency.attachment_chain.len() != dependency.depth as usize + 1 {
            return Err(format!(
                "dependency {index} attachment_chain length did not match depth"
            ));
        }
        let immediate_host = canonical_reported_layer_case_file(
            &dependency.immediate_host_path,
            case_root,
            &format!("dependency {index} immediate_host_path"),
        )?;
        if !allowed_immediate_hosts.contains(&immediate_host) {
            return Err(format!(
                "dependency {index} immediate host was not the staged host or a declared source: {}",
                immediate_host.display()
            ));
        }
        if dependency.depth == 0 && immediate_host != staged_host_canonical_path {
            return Err(format!(
                "depth-zero dependency {index} did not originate in the staged host"
            ));
        }
        if dependency.depth > 0 {
            let parent_chain =
                dependency.attachment_chain[..dependency.attachment_chain.len() - 1].to_vec();
            let parent = dependencies_by_chain.get(&parent_chain).ok_or_else(|| {
                format!("nested dependency {index} has no exact parent attachment-chain row")
            })?;
            if parent.inspection_state != XrefInspectionState::Inspected {
                return Err(format!(
                    "nested dependency {index} descends from a parent that was not inspected"
                ));
            }
            let parent_resolved_path = parent.resolved_path.as_deref().ok_or_else(|| {
                format!("nested dependency {index} parent did not resolve to a source")
            })?;
            let parent_resolved = canonical_reported_layer_case_file(
                parent_resolved_path,
                case_root,
                &format!("nested dependency {index} parent resolved_path"),
            )?;
            if immediate_host != parent_resolved {
                return Err(format!(
                    "nested dependency {index} immediate host did not equal its parent resolved source"
                ));
            }
        }
        let resolved_path = dependency
            .resolved_path
            .as_deref()
            .ok_or_else(|| format!("resolved dependency {index} did not report resolved_path"))?;
        resolved_sources.insert(canonical_reported_layer_case_file(
            resolved_path,
            case_root,
            &format!("dependency {index} resolved_path"),
        )?);
    }
    if resolved_sources != declared_sources {
        return Err(format!(
            "resolved dependency source set {resolved_sources:?} did not exactly match declared staged sources {declared_sources:?}"
        ));
    }

    let xref_layers = layers
        .iter()
        .filter(|layer| layer.xref_dependent)
        .collect::<Vec<_>>();
    match fixture_kind {
        LayerCertificationFixtureKind::HostOwned => {
            if !dependencies.dependencies.is_empty() || !xref_layers.is_empty() {
                return Err(
                    "host-owned layer case must have an empty dependency graph and no xref-dependent layers"
                        .to_string(),
                );
            }
        }
        LayerCertificationFixtureKind::XrefDependentHost => {
            if dependencies.dependencies.is_empty() || xref_layers.is_empty() {
                return Err(
                    "xref-dependent layer case must expose dependencies and xref-dependent layers"
                        .to_string(),
                );
            }
            for layer in xref_layers {
                let handle = layer.xref_block_record_handle.as_deref().ok_or_else(|| {
                    format!(
                        "xref-dependent layer {:?} omitted xref_block_record_handle",
                        layer.name
                    )
                })?;
                let name = layer.xref_name.as_deref().ok_or_else(|| {
                    format!("xref-dependent layer {:?} omitted xref_name", layer.name)
                })?;
                let saved_path = layer.xref_path.as_deref().ok_or_else(|| {
                    format!("xref-dependent layer {:?} omitted xref_path", layer.name)
                })?;
                let matches = dependencies
                    .dependencies
                    .iter()
                    .filter(|dependency| {
                        dependency.depth == 0
                            && dependency.attachment.handle.eq_ignore_ascii_case(handle)
                            && xref_name_eq(&dependency.attachment.name, name)
                            && dependency.attachment.saved_path == saved_path
                            && layer.xref_is_overlay
                                == Some(
                                    dependency.attachment.reference_type == ReferenceType::Overlay,
                                )
                    })
                    .count();
                if matches != 1 {
                    return Err(format!(
                        "xref-dependent layer {:?} correlated to {matches} depth-zero dependencies; expected exactly one",
                        layer.name
                    ));
                }
            }
        }
    }
    references
        .iter()
        .map(|reference| {
            Ok(CertificationResolvedSourceEvidence {
                manifest_path: reference.manifest_path.clone(),
                canonical_path: certification_path_string(&reference.staged_canonical_path)?,
                sha256: reference.source_sha256.clone(),
            })
        })
        .collect()
}

// The complete confinement boundary stays explicit at this one call site so a
// staged host, case root, or declared source set cannot be silently omitted.
#[allow(clippy::too_many_arguments)]
fn read_verified_layer_confinement(
    runtime: &CertificationCommandRuntime,
    profile_isolation: &mut Vec<CertificationProfileIsolationEvidence>,
    invocation_prefix: &str,
    drawing_path: &str,
    fixture_kind: LayerCertificationFixtureKind,
    staged_host: &StagedCertificationFile,
    staged_host_canonical_path: &Path,
    case_root: &Path,
    references: &[StagedLayerReference],
    key: LayerConfinementKey,
) -> Result<VerifiedLayerConfinement, String> {
    let layers_stdout = require_certification_tool_success(
        runtime,
        profile_isolation,
        &format!("{invocation_prefix}/list_layers"),
        CertificationProfileLaunchExpectation::NoEngineExpected,
        "list_layers",
        &serde_json::json!({"drawing_path": drawing_path}),
    )?;
    let layers_json = parse_certification_json("list_layers", &layers_stdout)?;
    verify_expanded_layer_records(&layers_json)?;
    let layers =
        serde_json::from_value::<Vec<LayerRecord>>(layers_json.clone()).map_err(|error| {
            format!("list_layers output was not an expanded layer inventory: {error}")
        })?;
    let observed_layers =
        serde_json::from_value::<Vec<CertificationExpandedLayerRecord>>(layers_json).map_err(
            |error| format!("list_layers output was not closed certification evidence: {error}"),
        )?;

    let dependencies_stdout = require_certification_tool_success(
        runtime,
        profile_isolation,
        &format!("{invocation_prefix}/list_xref_dependencies"),
        CertificationProfileLaunchExpectation::NoEngineExpected,
        "list_xref_dependencies",
        &serde_json::json!({
            "drawing_path": drawing_path,
            "search_paths": [],
        }),
    )?;
    let dependencies_json =
        parse_certification_json("list_xref_dependencies", &dependencies_stdout)?;
    let dependencies =
        serde_json::from_value::<XrefDependencyTraversalEnvelope>(dependencies_json.clone())
            .map_err(|error| {
                format!(
                    "list_xref_dependencies output was not a closed traversal envelope: {error}"
                )
            })?;
    let resolved_sources = verify_layer_dependency_confinement(
        fixture_kind,
        staged_host_canonical_path,
        case_root,
        references,
        &layers,
        &dependencies,
    )?;
    let key_after = current_layer_confinement_key(
        staged_host,
        staged_host_canonical_path,
        references,
        case_root,
    )?;
    if key_after != key {
        return Err(
            "layer host or declared reference bytes changed during confinement readback"
                .to_string(),
        );
    }
    verify_layer_fixture_sources_unchanged(staged_host, references)?;
    let mut evidence = LayerConfinementSnapshotEvidence {
        state_key_sha256: key.state_key_sha256.clone(),
        host_drawing_sha256: key.staged_host_sha256.clone(),
        layers: observed_layers,
        dependency_graph: dependencies,
        resolved_sources,
        sha256: String::new(),
    };
    evidence.sha256 = certification_layer_readback_sha256(&evidence);
    Ok(VerifiedLayerConfinement { key, evidence })
}

#[allow(clippy::too_many_arguments)]
fn establish_layer_confinement<'a>(
    cache: &'a mut Option<VerifiedLayerConfinement>,
    evidence_snapshots: &mut Vec<LayerConfinementSnapshotEvidence>,
    profile_isolation: &mut Vec<CertificationProfileIsolationEvidence>,
    invocation_prefix: &str,
    current_key: LayerConfinementKey,
    runtime: &CertificationCommandRuntime,
    drawing_path: &str,
    fixture_kind: LayerCertificationFixtureKind,
    staged_host: &StagedCertificationFile,
    staged_host_canonical_path: &Path,
    case_root: &Path,
    references: &[StagedLayerReference],
) -> Result<&'a VerifiedLayerConfinement, String> {
    if layer_confinement_cache_action(cache.as_ref().map(|snapshot| &snapshot.key), &current_key)
        == LayerConfinementCacheAction::Refresh
    {
        let refreshed = read_verified_layer_confinement(
            runtime,
            profile_isolation,
            invocation_prefix,
            drawing_path,
            fixture_kind,
            staged_host,
            staged_host_canonical_path,
            case_root,
            references,
            current_key,
        )?;
        if let Some(recorded) = evidence_snapshots
            .iter()
            .find(|snapshot| snapshot.state_key_sha256 == refreshed.evidence.state_key_sha256)
        {
            if recorded != &refreshed.evidence {
                return Err(
                    "the same layer confinement state key produced different closed readback evidence"
                        .to_string(),
                );
            }
        } else {
            evidence_snapshots.push(refreshed.evidence.clone());
        }
        *cache = Some(refreshed);
    }
    verify_layer_fixture_sources_unchanged(staged_host, references)?;
    cache
        .as_ref()
        .ok_or_else(|| "layer confinement cache was unexpectedly empty".to_string())
}

fn layer_operation_params(
    operation: &LayerMutationCertificationOperation,
    drawing_path: &str,
) -> Result<serde_json::Value, String> {
    let mut params = operation.params.as_object().cloned().ok_or_else(|| {
        format!(
            "operation '{}' params must be an object",
            operation.operation_id
        )
    })?;
    if params
        .insert(
            "drawing_path".to_string(),
            serde_json::Value::String(drawing_path.to_string()),
        )
        .is_some()
    {
        return Err(format!(
            "operation '{}' params unexpectedly contain drawing_path",
            operation.operation_id
        ));
    }
    Ok(serde_json::Value::Object(params))
}

fn verify_exact_object_fields(
    value: &serde_json::Value,
    expected: &[&str],
    label: &str,
) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "{label} has a non-closed field inventory; expected {expected:?}"
        ));
    }
    Ok(())
}

fn verify_exact_layer_record(
    value: &serde_json::Value,
    label: &str,
) -> Result<CertificationExpandedLayerRecord, String> {
    verify_expanded_layer_records(&serde_json::json!([value]))?;
    serde_json::from_value(value.clone())
        .map_err(|error| format!("{label} was not an expanded layer record: {error}"))
}

fn verify_layer_expectation(
    actual: &serde_json::Value,
    expected: &autocad_mcp::certification::LayerCertificationLayerExpectation,
    label: &str,
) -> Result<(), String> {
    let expected = serde_json::to_value(expected)
        .map_err(|error| format!("failed to serialize {label} expectation: {error}"))?;
    let expected = expected
        .as_object()
        .ok_or_else(|| format!("{label} expectation was not an object"))?;
    let actual = actual
        .as_object()
        .ok_or_else(|| format!("{label} actual layer was not an object"))?;
    for (field, expected_value) in expected {
        let actual_value = actual
            .get(field)
            .ok_or_else(|| format!("{label} actual layer omitted expected field {field:?}"))?;
        if actual_value != expected_value {
            return Err(format!(
                "{label} field {field:?} was {actual_value}, expected {expected_value}"
            ));
        }
    }
    Ok(())
}

fn layer_expectation_identity(
    expected: &autocad_mcp::certification::LayerCertificationLayerExpectation,
    fallback_params: &serde_json::Value,
) -> Result<(Option<String>, Option<String>), String> {
    let expected = serde_json::to_value(expected)
        .map_err(|error| format!("failed to serialize layer expectation: {error}"))?;
    let handle = expected
        .get("handle")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            fallback_params
                .get("handle")
                .and_then(serde_json::Value::as_str)
        })
        .map(str::to_string);
    let name = expected
        .get("name")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            fallback_params
                .get("name")
                .and_then(serde_json::Value::as_str)
        })
        .map(str::to_string);
    if handle.is_none() && name.is_none() {
        return Err("layer expectation/readback requires a handle or name identity".to_string());
    }
    Ok((handle, name))
}

fn find_snapshot_layer<'a>(
    snapshot: &'a VerifiedLayerConfinement,
    handle: Option<&str>,
    name: Option<&str>,
    label: &str,
) -> Result<&'a CertificationExpandedLayerRecord, String> {
    let matches = snapshot
        .evidence
        .layers
        .iter()
        .filter(|layer| {
            handle.is_none_or(|expected| layer.handle.eq_ignore_ascii_case(expected))
                && name.is_none_or(|expected| layer.name.eq_ignore_ascii_case(expected))
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!(
            "{label} identity handle={handle:?} name={name:?} matched {} persisted layers",
            matches.len()
        ));
    }
    Ok(matches[0])
}

fn verify_mutation_response_envelope<'a>(
    output: &'a serde_json::Value,
    expected_status: &str,
    staged_host_canonical_path: &Path,
) -> Result<&'a serde_json::Value, String> {
    verify_exact_object_fields(
        output,
        &["status", "drawing", "layer"],
        "layer mutation output",
    )?;
    if output.get("status").and_then(serde_json::Value::as_str) != Some(expected_status) {
        return Err(format!(
            "layer mutation status did not equal {expected_status:?}: {output}"
        ));
    }
    let drawing = output
        .get("drawing")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "layer mutation output omitted string drawing".to_string())?;
    let canonical = Path::new(drawing)
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize mutation drawing {drawing:?}: {error}"))?;
    if canonical != staged_host_canonical_path {
        return Err("layer mutation output did not identify the staged host".to_string());
    }
    output
        .get("layer")
        .ok_or_else(|| "layer mutation output omitted layer".to_string())
}

fn canonical_json_multiset(value: &serde_json::Value, label: &str) -> Result<Vec<Vec<u8>>, String> {
    let values = value
        .as_array()
        .ok_or_else(|| format!("{label} must be an array"))?;
    let mut canonical = values
        .iter()
        .map(|value| {
            serde_json::to_vec(&canonical_certification_json(value))
                .map_err(|error| format!("failed to serialize {label} record: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort();
    Ok(canonical)
}

fn verify_successful_layer_operation(
    operation: &LayerMutationCertificationOperation,
    actual_output: &serde_json::Value,
    snapshot: &VerifiedLayerConfinement,
    staged_host_canonical_path: &Path,
) -> Result<CertificationLayerObservedResult, String> {
    let LayerCertificationExpectedOutcome::Passed { assertion } = &operation.expected else {
        return Err("internal certification error: expected a passed outcome".to_string());
    };
    match assertion {
        LayerCertificationPassedAssertion::ExpandedRecords { record } => {
            verify_expanded_layer_records(actual_output)?;
            let records = serde_json::from_value::<Vec<CertificationExpandedLayerRecord>>(
                actual_output.clone(),
            )
            .map_err(|error| {
                format!("list_layers output was not closed certification evidence: {error}")
            })?;
            let persisted_json =
                serde_json::to_value(&snapshot.evidence.layers).map_err(|error| {
                    format!("failed to serialize persisted list_layers readback: {error}")
                })?;
            if canonical_json_multiset(actual_output, "list_layers output")?
                != canonical_json_multiset(&persisted_json, "persisted list_layers readback")?
            {
                return Err(
                    "list_layers output did not equal the independent persisted layer snapshot"
                        .to_string(),
                );
            }
            let expected = serde_json::to_value(record).map_err(|error| {
                format!("failed to serialize expanded-record assertion: {error}")
            })?;
            let matches = actual_output
                .as_array()
                .expect("expanded records were checked")
                .iter()
                .filter(|actual| **actual == expected)
                .count();
            if matches != 1 {
                return Err(format!(
                    "expanded-record assertion matched {matches} list_layers records; expected one"
                ));
            }
            Ok(CertificationLayerObservedResult::ListLayers { records })
        }
        LayerCertificationPassedAssertion::Layer { layer } => {
            let (actual_layer, actual_record) = match operation.tool {
                LayerMutationCertificationTool::GetLayer => {
                    let record = verify_exact_layer_record(actual_output, "get_layer output")?;
                    (actual_output, record)
                }
                LayerMutationCertificationTool::CreateLayer
                | LayerMutationCertificationTool::UpdateLayer
                | LayerMutationCertificationTool::RenameLayer => {
                    let actual_layer = verify_mutation_response_envelope(
                        actual_output,
                        "ok",
                        staged_host_canonical_path,
                    )?;
                    let record = verify_exact_layer_record(actual_layer, "layer mutation output")?;
                    (actual_layer, record)
                }
                _ => {
                    return Err(format!(
                        "Layer assertion is incompatible with tool {:?}",
                        operation.tool
                    ))
                }
            };
            verify_layer_expectation(actual_layer, layer, "tool output")?;
            let (handle, name) = layer_expectation_identity(layer, &operation.params)?;
            let persisted_layer = find_snapshot_layer(
                snapshot,
                handle.as_deref(),
                name.as_deref(),
                "persisted layer readback",
            )?;
            let persisted_layer_json = serde_json::to_value(persisted_layer).map_err(|error| {
                format!("failed to serialize persisted layer readback: {error}")
            })?;
            verify_layer_expectation(&persisted_layer_json, layer, "persisted layer readback")?;
            if actual_record != *persisted_layer {
                return Err(
                    "tool-returned layer did not exactly equal the independent persisted layer readback"
                        .to_string(),
                );
            }
            Ok(CertificationLayerObservedResult::Layer {
                record: actual_record,
            })
        }
        LayerCertificationPassedAssertion::DeletedIdentity { handle, name } => {
            let deleted = verify_mutation_response_envelope(
                actual_output,
                "deleted",
                staged_host_canonical_path,
            )?;
            verify_exact_object_fields(deleted, &["handle", "name"], "deleted layer identity")?;
            if deleted.get("handle").and_then(serde_json::Value::as_str) != Some(handle)
                || deleted.get("name").and_then(serde_json::Value::as_str) != Some(name)
            {
                return Err(
                    "delete_layer output did not exactly match the declared deleted identity"
                        .to_string(),
                );
            }
            let remaining = snapshot.evidence.layers.iter().any(|layer| {
                layer.handle.eq_ignore_ascii_case(handle) || layer.name.eq_ignore_ascii_case(name)
            });
            if remaining {
                return Err(
                    "deleted layer handle or name remained in the persisted layer snapshot"
                        .to_string(),
                );
            }
            Ok(CertificationLayerObservedResult::DeletedIdentity {
                handle: handle.clone(),
                name: name.clone(),
            })
        }
    }
}

fn verify_failed_layer_operation_readback(
    operation: &LayerMutationCertificationOperation,
    snapshot: &VerifiedLayerConfinement,
) -> Result<(), String> {
    let LayerCertificationExpectedOutcome::Failed {
        unchanged_layer, ..
    } = &operation.expected
    else {
        return Err("internal certification error: expected a failed outcome".to_string());
    };
    let (handle, name) = layer_expectation_identity(unchanged_layer, &operation.params)?;
    let persisted_layer = find_snapshot_layer(
        snapshot,
        handle.as_deref(),
        name.as_deref(),
        "unchanged layer readback",
    )?;
    let persisted_layer = serde_json::to_value(persisted_layer)
        .map_err(|error| format!("failed to serialize unchanged layer readback: {error}"))?;
    verify_layer_expectation(
        &persisted_layer,
        unchanged_layer,
        "unchanged layer readback",
    )
}

#[allow(clippy::too_many_arguments)]
fn run_layer_mutation_operation(
    operation: &LayerMutationCertificationOperation,
    runtime: &CertificationCommandRuntime,
    drawing_path: &str,
    fixture_kind: LayerCertificationFixtureKind,
    staged_host: &StagedCertificationFile,
    staged_host_canonical_path: &Path,
    case_root: &Path,
    references: &[StagedLayerReference],
    cache: &mut Option<VerifiedLayerConfinement>,
    evidence_snapshots: &mut Vec<LayerConfinementSnapshotEvidence>,
    profile_isolation: &mut Vec<CertificationProfileIsolationEvidence>,
) -> Result<LayerMutationOperationEvidence, String> {
    let input_key = current_layer_confinement_key(
        staged_host,
        staged_host_canonical_path,
        references,
        case_root,
    )?;
    if cache
        .as_ref()
        .is_none_or(|snapshot| snapshot.key != input_key)
    {
        return Err(
            "operation input did not match the last verified confinement snapshot".to_string(),
        );
    }
    let params = layer_operation_params(operation, drawing_path)?;
    let profile_expectation = layer_certification_profile_launch_expectation(operation)
        .map_err(|error| error.to_string())?;
    let output = run_certification_tool(
        runtime,
        profile_isolation,
        &format!("operation/{}", operation.operation_id),
        profile_expectation,
        operation.tool.as_str(),
        &params,
    )?;

    let (observed_tool_status, observed_error_code, actual_output) = match &operation.expected {
        LayerCertificationExpectedOutcome::Passed { .. } => {
            if !output.status.success() {
                return Err(format!(
                    "{} unexpectedly failed; {}",
                    operation.tool.as_str(),
                    certification_output_diagnostic(&output)
                ));
            }
            if !output.stderr.is_empty() {
                return Err(format!(
                    "{} successful execution wrote unexpected stderr; {}",
                    operation.tool.as_str(),
                    certification_output_diagnostic(&output)
                ));
            }
            let stdout = std::str::from_utf8(&output.stdout)
                .map_err(|_| {
                    format!(
                        "{} stdout encoding was not UTF-8; {}",
                        operation.tool.as_str(),
                        certification_output_diagnostic(&output)
                    )
                })?
                .to_string();
            (
                CertificationObservedToolStatus::Passed,
                None,
                Some(parse_certification_json(operation.tool.as_str(), &stdout)?),
            )
        }
        LayerCertificationExpectedOutcome::Failed { error_code, .. } => {
            if output.status.success() {
                return Err(format!(
                    "{} unexpectedly succeeded; expected exact error code {error_code}; {}",
                    operation.tool.as_str(),
                    certification_output_diagnostic(&output)
                ));
            }
            if !output.stdout.is_empty() {
                return Err(format!(
                    "{} expected failure wrote unexpected stdout; {}",
                    operation.tool.as_str(),
                    certification_output_diagnostic(&output)
                ));
            }
            let observed = certification_tool_error_code(&output)?.ok_or_else(|| {
                format!(
                    "{} failure did not contain exactly one stderr code= token; {}",
                    operation.tool.as_str(),
                    certification_output_diagnostic(&output)
                )
            })?;
            if observed != *error_code {
                return Err(format!(
                    "{} returned error code {observed:?}, expected {error_code:?}",
                    operation.tool.as_str()
                ));
            }
            (
                CertificationObservedToolStatus::Failed,
                Some(observed),
                None,
            )
        }
    };

    let output_key = current_layer_confinement_key(
        staged_host,
        staged_host_canonical_path,
        references,
        case_root,
    )?;
    let snapshot = establish_layer_confinement(
        cache,
        evidence_snapshots,
        profile_isolation,
        &format!("readback/{}", operation.operation_id),
        output_key.clone(),
        runtime,
        drawing_path,
        fixture_kind,
        staged_host,
        staged_host_canonical_path,
        case_root,
        references,
    )?;
    let observed_result = match (&operation.expected, &actual_output) {
        (LayerCertificationExpectedOutcome::Passed { .. }, Some(actual_output)) => {
            let result = verify_successful_layer_operation(
                operation,
                actual_output,
                snapshot,
                staged_host_canonical_path,
            )?;
            if operation.tool != LayerMutationCertificationTool::ListLayers
                && operation.tool != LayerMutationCertificationTool::GetLayer
                && output_key.staged_host_sha256 == input_key.staged_host_sha256
            {
                return Err(format!(
                    "successful {} did not change the staged host digest",
                    operation.tool.as_str()
                ));
            }
            if matches!(
                operation.tool,
                LayerMutationCertificationTool::ListLayers
                    | LayerMutationCertificationTool::GetLayer
            ) && output_key.staged_host_sha256 != input_key.staged_host_sha256
            {
                return Err(format!(
                    "read-only {} changed the staged host digest",
                    operation.tool.as_str()
                ));
            }
            Some(result)
        }
        (LayerCertificationExpectedOutcome::Failed { .. }, None) => {
            if output_key.staged_host_sha256 != input_key.staged_host_sha256 {
                return Err(format!(
                    "expected {} failure changed the staged host digest",
                    operation.tool.as_str()
                ));
            }
            verify_failed_layer_operation_readback(operation, snapshot)?;
            None
        }
        _ => {
            return Err("internal certification outcome/output mismatch".to_string());
        }
    };
    let actual_output = observed_result.map(|result| CertificationLayerToolObservation {
        sha256: certification_layer_output_sha256(&result),
        result,
    });
    Ok(LayerMutationOperationEvidence {
        operation_id: operation.operation_id.clone(),
        tool: operation.tool,
        params: operation.params.clone(),
        status: CertificationResultStatus::Passed,
        reason: None,
        observed_tool_status,
        observed_error_code,
        input_drawing_sha256: input_key.staged_host_sha256,
        output_drawing_sha256: output_key.staged_host_sha256,
        actual_output,
        persisted_state_key_sha256: snapshot.evidence.state_key_sha256.clone(),
        persisted_readback_sha256: snapshot.evidence.sha256.clone(),
    })
}

fn run_layer_mutation_case(
    fixture_root: &Path,
    case: &autocad_mcp::certification::LayerMutationCertificationCase,
    lane_root: &Path,
    runtime: &CertificationCommandRuntime,
) -> Result<LayerMutationCaseEvidence, String> {
    let case_root = create_fresh_certification_case_root(&lane_root.join(&case.case_id))?;
    let case_root_canonical = case_root
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize layer case root: {error}"))?;
    let staged_root = create_fresh_certification_case_root(&case_root.join("fixture"))?;
    let staged_host =
        stage_certification_file(fixture_root, &case.path, &case.source_sha256, &staged_root)?;
    let staged_host_canonical_path = staged_host
        .staged_path
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize staged layer host: {error}"))?;
    let references = case
        .referenced_source_fixtures
        .iter()
        .map(|fixture| {
            let staged = stage_certification_file(
                fixture_root,
                &fixture.path,
                &fixture.source_sha256,
                &staged_root,
            )?;
            let staged_canonical_path = staged.staged_path.canonicalize().map_err(|error| {
                format!(
                    "failed to canonicalize staged reference '{}': {error}",
                    fixture.path
                )
            })?;
            Ok(StagedLayerReference {
                manifest_path: fixture.path.clone(),
                source_sha256: fixture.source_sha256.clone(),
                staged,
                staged_canonical_path,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let drawing_path = certification_path_string(&staged_host.staged_path)?;
    let initial_key = current_layer_confinement_key(
        &staged_host,
        &staged_host_canonical_path,
        &references,
        &case_root_canonical,
    )?;
    if initial_key.staged_host_sha256 != case.source_sha256 {
        return Err("staged layer host digest did not match manifest".to_string());
    }
    verify_layer_fixture_sources_unchanged(&staged_host, &references)?;
    let mut cache = None;
    let mut readback_snapshots = Vec::new();
    let mut profile_isolation = Vec::new();
    let initial_snapshot = establish_layer_confinement(
        &mut cache,
        &mut readback_snapshots,
        &mut profile_isolation,
        "initial",
        initial_key,
        runtime,
        &drawing_path,
        case.fixture_kind,
        &staged_host,
        &staged_host_canonical_path,
        &case_root_canonical,
        &references,
    )?;
    let initial_state_key_sha256 = initial_snapshot.evidence.state_key_sha256.clone();
    let initial_readback_sha256 = initial_snapshot.evidence.sha256.clone();

    let mut operations = Vec::with_capacity(case.operations.len());
    for operation in &case.operations {
        operations.push(
            run_layer_mutation_operation(
                operation,
                runtime,
                &drawing_path,
                case.fixture_kind,
                &staged_host,
                &staged_host_canonical_path,
                &case_root_canonical,
                &references,
                &mut cache,
                &mut readback_snapshots,
                &mut profile_isolation,
            )
            .map_err(|error| format!("operation '{}': {error}", operation.operation_id))?,
        );
    }
    verify_layer_fixture_sources_unchanged(&staged_host, &references)?;
    let final_drawing_sha256 = cache
        .as_ref()
        .ok_or_else(|| "layer case finished without a verified snapshot".to_string())?
        .key
        .staged_host_sha256
        .clone();
    let referenced_sources = references
        .iter()
        .map(|reference| {
            Ok(CertificationReferencedSourceEvidence {
                path: reference.manifest_path.clone(),
                source_sha256: reference.source_sha256.clone(),
                staged_canonical_path: certification_path_string(&reference.staged_canonical_path)?,
                before_sha256: reference.source_sha256.clone(),
                after_sha256: reference.source_sha256.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    readback_snapshots.sort_by(|left, right| left.state_key_sha256.cmp(&right.state_key_sha256));
    Ok(LayerMutationCaseEvidence {
        case_id: case.case_id.clone(),
        drawing_id: case.drawing_id.clone(),
        path: case.path.clone(),
        source_sha256: case.source_sha256.clone(),
        staged_case_root_canonical_path: certification_path_string(&case_root_canonical)?,
        staged_drawing_canonical_path: certification_path_string(&staged_host_canonical_path)?,
        staged_drawing_sha256: staged_host.sha256,
        final_drawing_sha256,
        status: CertificationResultStatus::Passed,
        reason: None,
        referenced_sources,
        initial_state_key_sha256,
        initial_readback_sha256,
        readback_snapshots,
        operations,
        profile_isolation,
    })
}

#[derive(Debug, Clone, PartialEq)]
struct XrefPersistedState {
    attachments: Vec<serde_json::Value>,
    instances: Vec<serde_json::Value>,
    blocks: Vec<serde_json::Value>,
}

#[derive(Debug)]
struct XrefCertificationRun {
    results: Vec<XrefCertificationCaseResult>,
    failures: Vec<XrefCertificationCaseFailure>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct XrefCertificationCommandRuntime {
    binary: PathBuf,
    accoreconsole: PathBuf,
    certified_arg: PathBuf,
    certified_arg_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct XrefCertificationEngineObservation {
    accoreconsole_path: String,
    accoreconsole_canonical_path: String,
    accoreconsole_sha256_before: String,
    accoreconsole_sha256_after: String,
    observed_autocad_product: String,
    observed_autocad_version: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct XrefCertificationBinaryObservation {
    binary_path: String,
    binary_canonical_path: String,
    binary_sha256_before: String,
    binary_sha256_after: String,
}

fn finish_xref_certification_binary(
    binding: ExactCertificationFile,
    label: &str,
) -> Result<XrefCertificationBinaryObservation, String> {
    let binary_sha256_after = verify_exact_certification_file_unchanged(&binding, label)?;
    Ok(XrefCertificationBinaryObservation {
        binary_path: binding.configured_path,
        binary_canonical_path: certification_path_string(&binding.canonical_path)?,
        binary_sha256_before: binding.sha256_before,
        binary_sha256_after,
    })
}

fn bind_xref_certification_engine(
    manifest: &XrefCertificationManifest,
) -> Result<(ExactCertificationFile, engine::AutocadEngineIdentity), String> {
    let binding = bind_exact_certification_file(
        &manifest.accoreconsole_path,
        &manifest.accoreconsole_sha256,
        "strict XREF accoreconsole",
    )?;
    let identity = engine::identify_accoreconsole(binding.canonical_path.clone())
        .map_err(|error| format!("failed to identify exact strict XREF accoreconsole: {error}"))?;
    if identity.product != manifest.autocad_product || identity.version != manifest.autocad_version
    {
        return Err(format!(
            "strict XREF observed AutoCAD identity {}/{} does not match manifest {}/{}",
            identity.product, identity.version, manifest.autocad_product, manifest.autocad_version
        ));
    }
    Ok((binding, identity))
}

fn finish_xref_certification_engine(
    binding: ExactCertificationFile,
    identity: engine::AutocadEngineIdentity,
) -> Result<XrefCertificationEngineObservation, String> {
    let accoreconsole_sha256_after =
        verify_exact_certification_file_unchanged(&binding, "strict XREF accoreconsole")?;
    Ok(XrefCertificationEngineObservation {
        accoreconsole_path: binding.configured_path,
        accoreconsole_canonical_path: certification_path_string(&binding.canonical_path)?,
        accoreconsole_sha256_before: binding.sha256_before,
        accoreconsole_sha256_after,
        observed_autocad_product: identity.product,
        observed_autocad_version: identity.version,
    })
}

fn xref_certification_tool_command(
    runtime: &XrefCertificationCommandRuntime,
    tool: &str,
    params: &serde_json::Value,
) -> Command {
    let mut command = Command::new(&runtime.binary);
    command
        .args(["call", tool, &params.to_string()])
        .env(
            "AUTOCAD_MCP_ACCORECONSOLE_PATH",
            runtime.accoreconsole.as_os_str(),
        )
        .env(
            "AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH",
            runtime.certified_arg.as_os_str(),
        )
        .env_remove("AUTOCAD_MCP_XREF_FAILPOINT");
    command
}

#[derive(Debug)]
struct XrefCaseRunError {
    stage: XrefCertificationFailureStage,
    detail: String,
}

impl XrefCaseRunError {
    fn new(stage: XrefCertificationFailureStage, detail: impl Into<String>) -> Self {
        Self {
            stage,
            detail: detail.into(),
        }
    }
}

#[derive(Debug)]
struct XrefStagedCase {
    case_dir: PathBuf,
    drawing: PathBuf,
    params: serde_json::Map<String, serde_json::Value>,
    source_fixtures: Vec<PathBuf>,
}

fn run_xref_certification_cases(
    fixture_root: &str,
    cases: &[XrefCertificationCase],
    evidence_class: XrefCertificationEvidenceClass,
    runtime: &XrefCertificationCommandRuntime,
    output_dir: &Path,
) -> XrefCertificationRun {
    let mut run = XrefCertificationRun {
        results: Vec::new(),
        failures: Vec::new(),
    };
    for case in cases {
        match run_xref_certification_case(fixture_root, case, evidence_class, runtime, output_dir) {
            Ok(result) => run.results.push(result),
            Err(error) => run.failures.push(XrefCertificationCaseFailure {
                case_id: case.case_id.clone(),
                row_id: case.row_id.clone(),
                scenario: case.scenario,
                operation: case.operation,
                stage: error.stage,
                detail: redacted_certification_failure("xref_case_failure", &error.detail),
            }),
        }
    }
    run
}

fn run_xref_certification_case(
    fixture_root: &str,
    case: &XrefCertificationCase,
    evidence_class: XrefCertificationEvidenceClass,
    runtime: &XrefCertificationCommandRuntime,
    output_dir: &Path,
) -> Result<XrefCertificationCaseResult, XrefCaseRunError> {
    let staged = stage_xref_certification_case(fixture_root, case, evidence_class, output_dir)?;
    let result = run_staged_xref_certification_case(case, evidence_class, runtime, &staged)
        .map_err(|detail| {
            XrefCaseRunError::new(XrefCertificationFailureStage::Verification, detail)
        });
    let cleanup = std::fs::remove_dir_all(&staged.case_dir).map_err(|error| {
        XrefCaseRunError::new(
            XrefCertificationFailureStage::HarnessCleanup,
            format!(
                "remove fresh case directory {}: {error}",
                staged.case_dir.display()
            ),
        )
    });
    match (result, cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) | (_, Err(error)) => Err(error),
    }
}

fn run_staged_xref_certification_case(
    case: &XrefCertificationCase,
    evidence_class: XrefCertificationEvidenceClass,
    runtime: &XrefCertificationCommandRuntime,
    staged: &XrefStagedCase,
) -> Result<XrefCertificationCaseResult, String> {
    let registry = embedded_xref_artifacts().map_err(|error| error.to_string())?;
    let row = registry
        .capabilities()
        .rows
        .iter()
        .find(|row| row.row_id == case.row_id)
        .ok_or_else(|| format!("unknown capability row '{}'", case.row_id))?;
    let working_drawing = &staged.drawing;

    let input_format = inspect_xref_certification_format(working_drawing)
        .map_err(|error| format!("inspect input format: {error}"))?;
    let expected_format =
        autocad_mcp::certification::XrefCertificationFormatFacts::from_capability(row);
    if input_format != expected_format {
        return Err(format!(
            "input format {:?} does not match row {:?}",
            input_format, expected_format
        ));
    }
    let original_digest_before =
        xref_sha256_file(working_drawing).map_err(|error| error.to_string())?;
    let mut profile_isolation = Vec::new();
    let before =
        read_xref_persisted_state(runtime, working_drawing, "pre", &mut profile_isolation)?;
    let source_digests_before = xref_source_digests(
        &staged.params,
        working_drawing,
        &before,
        &staged.source_fixtures,
    )?;
    let canonical_staged_host = canonical_staged_host_identity(working_drawing)?;
    let profile_expectation = xref_certification_profile_launch_expectation(case, evidence_class)
        .map_err(|error| error.to_string())?;

    let observed = run_xref_cli_observed(
        runtime,
        &mut profile_isolation,
        "operation",
        profile_expectation,
        case.operation.as_str(),
        &serde_json::Value::Object(staged.params.clone()),
        match evidence_class {
            XrefCertificationEvidenceClass::ReleaseConformance => None,
            XrefCertificationEvidenceClass::InstrumentedTransaction => case.failpoint,
        },
        working_drawing,
        case.scenario,
        staged.source_fixtures.first().map(PathBuf::as_path),
    )?;
    let output = observed.output;
    let (response, error_code) = match case.expected_status {
        XrefCertificationExpectedStatus::Passed => {
            if !output.status.success() {
                return Err(format!(
                    "operation unexpectedly failed; {}",
                    certification_output_diagnostic(&output)
                ));
            }
            if !output.stderr.is_empty() {
                return Err(format!(
                    "successful operation wrote unexpected stderr; {}",
                    certification_output_diagnostic(&output)
                ));
            }
            let response = serde_json::from_slice(&output.stdout).map_err(|error| {
                certification_json_bytes_error_diagnostic(
                    "successful XREF operation",
                    &output.stdout,
                    &error,
                )
            })?;
            (Some(response), None)
        }
        XrefCertificationExpectedStatus::Failed => {
            if output.status.success() {
                return Err(format!(
                    "operation unexpectedly succeeded; {}",
                    certification_output_diagnostic(&output)
                ));
            }
            if !output.stdout.is_empty() {
                return Err(format!(
                    "failed operation wrote unexpected stdout; {}",
                    certification_output_diagnostic(&output)
                ));
            }
            let actual_code = xref_error_code(&output.stderr).ok_or_else(|| {
                format!(
                    "failed operation did not emit exactly one code=<value>; {}",
                    certification_output_diagnostic(&output)
                )
            })?;
            if Some(actual_code.as_str()) != case.expected_error_code.as_deref() {
                return Err(format!(
                    "operation error code '{actual_code}' does not match {:?}",
                    case.expected_error_code
                ));
            }
            (None, Some(actual_code))
        }
    };

    let output_format = inspect_xref_certification_format(working_drawing)
        .map_err(|error| format!("inspect output format: {error}"))?;
    if output_format != input_format {
        return Err("operation changed host format/version/form/code page".to_string());
    }
    let original_digest_after =
        xref_sha256_file(working_drawing).map_err(|error| error.to_string())?;
    let after =
        read_xref_persisted_state(runtime, working_drawing, "post", &mut profile_isolation)?;
    let source_digests_after = xref_source_digests(
        &staged.params,
        working_drawing,
        &before,
        &staged.source_fixtures,
    )?;
    if source_digests_after != source_digests_before {
        return Err("one or more XREF source digests changed during certification".to_string());
    }

    if let Some(response) = response.as_ref() {
        verify_xref_response_matches_request(
            case.operation,
            &staged.params,
            response,
            &before,
            &canonical_staged_host,
        )?;
        verify_xref_persisted_response(case.operation, response, &before, &after)?;
        verify_xref_unrelated_resources(case.operation, &staged.params, response, &before, &after)?;
    } else if case
        .failpoint
        .map(|failpoint| !failpoint.may_cross_replacement())
        .unwrap_or(true)
        && before != after
    {
        return Err("pre-replacement failure changed persisted XREF state".to_string());
    }

    Ok(XrefCertificationCaseResult {
        case_id: case.case_id.clone(),
        row_id: case.row_id.clone(),
        operation: case.operation,
        status: XrefCertificationResultStatus::Passed,
        error_code,
        input_format,
        output_format,
        original_digest_before,
        original_digest_after,
        artifact_cleanup: observed.cleanup,
        profile_isolation,
    })
}

fn stage_xref_certification_case(
    fixture_root: &str,
    case: &XrefCertificationCase,
    evidence_class: XrefCertificationEvidenceClass,
    output_dir: &Path,
) -> Result<XrefStagedCase, XrefCaseRunError> {
    let failure =
        |detail| XrefCaseRunError::new(XrefCertificationFailureStage::FixtureStaging, detail);
    let declared_fixture_root = PathBuf::from(fixture_root);
    let fixture_root = std::fs::canonicalize(&declared_fixture_root).map_err(|error| {
        failure(format!(
            "canonicalize fixture_root '{fixture_root}': {error}"
        ))
    })?;
    if !fixture_root.is_dir() {
        return Err(failure(format!(
            "fixture_root is not a directory: {}",
            fixture_root.display()
        )));
    }
    let drawing = std::fs::canonicalize(&case.drawing_path).map_err(|error| {
        failure(format!(
            "drawing fixture is absent or unreadable {}: {error}",
            case.drawing_path
        ))
    })?;
    let drawing_relative = drawing.strip_prefix(&fixture_root).map_err(|_| {
        failure(format!(
            "drawing fixture {} is outside fixture_root {}",
            drawing.display(),
            fixture_root.display()
        ))
    })?;
    if !drawing.is_file() {
        return Err(failure(format!(
            "drawing fixture is not a regular file: {}",
            drawing.display()
        )));
    }

    let mut missing_sources = Vec::new();
    for relative in &case.source_fixture_paths {
        let path = fixture_root.join(relative);
        if !path.is_file() {
            missing_sources.push(relative.clone());
        }
    }
    if !missing_sources.is_empty() {
        return Err(failure(format!(
            "declared source fixtures are absent: {}",
            missing_sources.join(", ")
        )));
    }

    let case_dir = output_dir
        .join(evidence_class.as_str())
        .join(&case.row_id)
        .join(&case.case_id);
    if let Ok(canonical_output) = std::fs::canonicalize(output_dir) {
        if canonical_output.starts_with(&fixture_root)
            || fixture_root.starts_with(&canonical_output)
        {
            return Err(failure(format!(
                "fixture_root {} and certification output {} must not overlap",
                fixture_root.display(),
                canonical_output.display()
            )));
        }
    }
    if case_dir.exists() {
        std::fs::remove_dir_all(&case_dir).map_err(|error| {
            failure(format!(
                "remove stale case directory {}: {error}",
                case_dir.display()
            ))
        })?;
    }
    std::fs::create_dir_all(&case_dir).map_err(|error| {
        failure(format!(
            "create fresh case directory {}: {error}",
            case_dir.display()
        ))
    })?;
    let staged_root = case_dir.join("fixture");
    if let Err(error) = copy_xref_fixture_tree(&fixture_root, &staged_root) {
        let cleanup = std::fs::remove_dir_all(&case_dir);
        let detail = match cleanup {
            Ok(()) => error,
            Err(cleanup_error) => format!(
                "{error}; remove incomplete case directory {}: {cleanup_error}",
                case_dir.display()
            ),
        };
        return Err(failure(detail));
    }

    let drawing = staged_root.join(drawing_relative);
    let source_fixtures = case
        .source_fixture_paths
        .iter()
        .map(|relative| staged_root.join(relative))
        .collect();
    let mut value = serde_json::Value::Object(case.params.clone());
    rewrite_staged_fixture_paths(
        &mut value,
        &declared_fixture_root,
        &fixture_root,
        &staged_root,
    );
    let mut params = value
        .as_object()
        .expect("case params remain an object")
        .clone();
    params.insert(
        "drawing_path".to_string(),
        serde_json::Value::String(drawing.to_string_lossy().into_owned()),
    );
    Ok(XrefStagedCase {
        case_dir,
        drawing,
        params,
        source_fixtures,
    })
}

fn copy_xref_fixture_tree(source: &Path, destination: &Path) -> Result<(), String> {
    std::fs::create_dir_all(destination).map_err(|error| {
        format!(
            "create staged fixture directory {}: {error}",
            destination.display()
        )
    })?;
    let mut entries = std::fs::read_dir(source)
        .map_err(|error| format!("read fixture directory {}: {error}", source.display()))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    for path in entries {
        let file_name = path
            .file_name()
            .ok_or_else(|| format!("fixture entry has no file name: {}", path.display()))?;
        let target = destination.join(file_name);
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect fixture entry {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "fixture tree contains unsupported symbolic link or junction: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            copy_xref_fixture_tree(&path, &target)?;
        } else if metadata.is_file() {
            std::fs::copy(&path, &target).map_err(|error| {
                format!(
                    "copy fixture {} to {}: {error}",
                    path.display(),
                    target.display()
                )
            })?;
        } else {
            return Err(format!(
                "fixture tree contains unsupported entry: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn rewrite_staged_fixture_paths(
    value: &mut serde_json::Value,
    declared_fixture_root: &Path,
    canonical_fixture_root: &Path,
    staged_root: &Path,
) {
    match value {
        serde_json::Value::String(string) => {
            let path = Path::new(string);
            if path.is_absolute() {
                if let Ok(relative) = path
                    .strip_prefix(declared_fixture_root)
                    .or_else(|_| path.strip_prefix(canonical_fixture_root))
                {
                    *string = staged_root.join(relative).to_string_lossy().into_owned();
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                rewrite_staged_fixture_paths(
                    value,
                    declared_fixture_root,
                    canonical_fixture_root,
                    staged_root,
                );
            }
        }
        serde_json::Value::Object(object) => {
            for value in object.values_mut() {
                rewrite_staged_fixture_paths(
                    value,
                    declared_fixture_root,
                    canonical_fixture_root,
                    staged_root,
                );
            }
        }
        _ => {}
    }
}

fn read_xref_persisted_state(
    runtime: &XrefCertificationCommandRuntime,
    drawing: &Path,
    invocation_prefix: &str,
    profile_isolation: &mut Vec<CertificationProfileIsolationEvidence>,
) -> Result<XrefPersistedState, String> {
    let params = serde_json::json!({"drawing_path": drawing.to_string_lossy()});
    Ok(XrefPersistedState {
        attachments: xref_records(run_xref_cli_json(
            runtime,
            profile_isolation,
            &format!("{invocation_prefix}/list_xrefs"),
            "list_xrefs",
            &params,
        )?),
        instances: xref_records(run_xref_cli_json(
            runtime,
            profile_isolation,
            &format!("{invocation_prefix}/list_xref_instances"),
            "list_xref_instances",
            &params,
        )?),
        blocks: xref_records(run_xref_cli_json(
            runtime,
            profile_isolation,
            &format!("{invocation_prefix}/list_blocks"),
            "list_blocks",
            &params,
        )?),
    })
}

fn verify_xref_persisted_response(
    operation: XrefMutationOperation,
    response: &serde_json::Value,
    before: &XrefPersistedState,
    after: &XrefPersistedState,
) -> Result<(), String> {
    let expected_status = match operation {
        XrefMutationOperation::AttachXref => "attached",
        XrefMutationOperation::BindXref => "bound",
        XrefMutationOperation::DeleteXrefInstance => "deleted",
        XrefMutationOperation::DetachXref => "detached",
        XrefMutationOperation::InsertXrefInstance => "inserted",
        XrefMutationOperation::ReloadXref => "loaded",
        XrefMutationOperation::UnloadXref => "unloaded",
        XrefMutationOperation::UpdateXref | XrefMutationOperation::UpdateXrefInstance => "updated",
    };
    if response.get("status").and_then(serde_json::Value::as_str) != Some(expected_status) {
        return Err(format!(
            "operation response has unexpected status; expected '{expected_status}': {response}"
        ));
    }

    match operation {
        XrefMutationOperation::AttachXref => {
            require_response_record(&after.attachments, response.get("attachment"), "attachment")?;
            require_response_record(&after.instances, response.get("instance"), "instance")?;
        }
        XrefMutationOperation::UpdateXref
        | XrefMutationOperation::ReloadXref
        | XrefMutationOperation::UnloadXref => {
            require_response_record(&after.attachments, response.get("attachment"), "attachment")?;
        }
        XrefMutationOperation::DetachXref | XrefMutationOperation::BindXref => {
            require_response_record(
                &before.attachments,
                response.get("attachment"),
                "removed attachment before mutation",
            )?;
            require_response_record_absent(
                &after.attachments,
                response.get("attachment"),
                "attachment",
            )?;
            if operation == XrefMutationOperation::BindXref {
                require_response_record(&after.blocks, response.get("block"), "bound block")?;
            }
        }
        XrefMutationOperation::InsertXrefInstance | XrefMutationOperation::UpdateXrefInstance => {
            require_response_record(&after.instances, response.get("instance"), "instance")?;
        }
        XrefMutationOperation::DeleteXrefInstance => {
            require_response_record(
                &before.instances,
                response.get("instance"),
                "deleted instance before mutation",
            )?;
            require_response_record_absent(&after.instances, response.get("instance"), "instance")?;
        }
    }
    Ok(())
}

fn verify_xref_response_matches_request(
    operation: XrefMutationOperation,
    params: &serde_json::Map<String, serde_json::Value>,
    response: &serde_json::Value,
    before: &XrefPersistedState,
    canonical_staged_host: &str,
) -> Result<(), String> {
    let response_drawing = response
        .get("drawing")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "operation response is missing string drawing identity".to_string())?;
    if response_drawing != canonical_staged_host {
        return Err(format!(
            "response drawing '{response_drawing}' does not match canonical staged host '{canonical_staged_host}'"
        ));
    }
    verify_xref_response_target(operation, params, response, before)?;
    match operation {
        XrefMutationOperation::AttachXref => {
            require_equal_field(
                response.get("attachment"),
                "saved_path",
                params.get("xref_path"),
                "attach_xref",
            )?;
            require_equal_field(
                response.get("attachment"),
                "reference_type",
                params.get("reference_type"),
                "attach_xref",
            )?;
            if params.contains_key("name") {
                require_equal_field(
                    response.get("attachment"),
                    "name",
                    params.get("name"),
                    "attach_xref",
                )?;
            }
            verify_placement_projection(
                params.get("placement"),
                response.get("instance"),
                "attach_xref placement",
            )?;
        }
        XrefMutationOperation::UpdateXref => {
            if let Some(properties) = params
                .get("properties")
                .and_then(serde_json::Value::as_object)
            {
                for (request_key, response_key) in [
                    ("name", "name"),
                    ("xref_path", "saved_path"),
                    ("reference_type", "reference_type"),
                ] {
                    if properties.contains_key(request_key) {
                        require_equal_field(
                            response.get("attachment"),
                            response_key,
                            properties.get(request_key),
                            "update_xref",
                        )?;
                    }
                }
            }
            if let Some(reconciliation) = params
                .get("layer_reconciliation")
                .and_then(serde_json::Value::as_object)
            {
                require_equal_field(
                    response.get("layer_reconciliation"),
                    "requested_mode",
                    reconciliation.get("mode"),
                    "update_xref layer reconciliation",
                )?;
            }
        }
        XrefMutationOperation::ReloadXref => {
            require_literal_field(
                response.get("attachment"),
                "load_state",
                "loaded",
                "reload_xref",
            )?;
            if let Some(reconciliation) = params
                .get("layer_reconciliation")
                .and_then(serde_json::Value::as_object)
            {
                require_equal_field(
                    response.get("layer_reconciliation"),
                    "requested_mode",
                    reconciliation.get("mode"),
                    "reload_xref layer reconciliation",
                )?;
            }
        }
        XrefMutationOperation::UnloadXref => require_literal_field(
            response.get("attachment"),
            "load_state",
            "unloaded",
            "unload_xref",
        )?,
        XrefMutationOperation::InsertXrefInstance => verify_placement_projection(
            params.get("placement"),
            response.get("instance"),
            "insert_xref_instance placement",
        )?,
        XrefMutationOperation::UpdateXrefInstance => verify_placement_projection(
            params.get("properties"),
            response.get("instance"),
            "update_xref_instance properties",
        )?,
        XrefMutationOperation::BindXref => {
            require_equal_field(
                Some(response),
                "symbol_strategy",
                params.get("symbol_strategy"),
                "bind_xref",
            )?;
            require_equal_field(
                Some(response),
                "dependency_strategy",
                params.get("dependency_strategy"),
                "bind_xref",
            )?;
        }
        XrefMutationOperation::DetachXref | XrefMutationOperation::DeleteXrefInstance => {}
    }
    Ok(())
}

fn verify_xref_response_target(
    operation: XrefMutationOperation,
    params: &serde_json::Map<String, serde_json::Value>,
    response: &serde_json::Value,
    before: &XrefPersistedState,
) -> Result<(), String> {
    let (response_record, response_handle_key, records, request_handle_key, request_name_key) =
        match operation {
            XrefMutationOperation::UpdateXref
            | XrefMutationOperation::DetachXref
            | XrefMutationOperation::ReloadXref
            | XrefMutationOperation::UnloadXref
            | XrefMutationOperation::BindXref => (
                response.get("attachment"),
                "handle",
                before.attachments.as_slice(),
                "handle",
                Some("name"),
            ),
            XrefMutationOperation::InsertXrefInstance => (
                response.get("instance"),
                "attachment_handle",
                before.attachments.as_slice(),
                "attachment_handle",
                Some("attachment_name"),
            ),
            XrefMutationOperation::UpdateXrefInstance
            | XrefMutationOperation::DeleteXrefInstance => (
                response.get("instance"),
                "handle",
                before.instances.as_slice(),
                "handle",
                None,
            ),
            XrefMutationOperation::AttachXref => return Ok(()),
        };
    let response_record = response_record
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "operation response is missing its target record".to_string())?;
    let requested_handle = params
        .get(request_handle_key)
        .and_then(serde_json::Value::as_str)
        .map(canonical_input_handle)
        .transpose()
        .map_err(|error| format!("invalid certification target handle: {error}"))?;
    let requested_name = request_name_key
        .and_then(|key| params.get(key))
        .and_then(serde_json::Value::as_str);
    let by_handle = requested_handle.as_deref().map(|handle| {
        records
            .iter()
            .find(|record| record.get("handle").and_then(serde_json::Value::as_str) == Some(handle))
            .ok_or_else(|| format!("pre-mutation target handle '{handle}' was not found"))
    });
    let by_name = requested_name.map(|name| {
        let mut matches = records.iter().filter(|record| {
            record
                .get("name")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|actual| xref_name_eq(actual, name))
        });
        let selected = matches
            .next()
            .ok_or_else(|| format!("pre-mutation target name '{name}' was not found"))?;
        if matches.next().is_some() {
            return Err(format!(
                "pre-mutation target name '{name}' is ambiguous in certification fixture"
            ));
        }
        Ok(selected)
    });
    let by_handle = by_handle.transpose()?;
    let by_name = by_name.transpose()?;
    let selected = match (by_handle, by_name) {
        (Some(by_handle), Some(by_name)) => {
            if by_handle.get("handle") != by_name.get("handle") {
                return Err(
                    "pre-mutation handle and name selectors resolve to different targets"
                        .to_string(),
                );
            }
            by_handle
        }
        (Some(selected), None) | (None, Some(selected)) => selected,
        (None, None) => {
            return Err(
                "certification mutation has no resolvable pre-mutation selector".to_string(),
            )
        }
    };
    let selected_handle = selected
        .get("handle")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "pre-mutation target has no stable string handle".to_string())?;
    let actual = response_record
        .get(response_handle_key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("response target has no string {response_handle_key}"))?;
    if actual != selected_handle {
        return Err(format!(
            "response target handle '{actual}' does not match pre-mutation target handle '{selected_handle}'"
        ));
    }
    Ok(())
}

fn canonical_staged_host_identity(path: &Path) -> Result<String, String> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("canonicalize staged host {}: {error}", path.display()))?;
    let display = canonical
        .to_str()
        .ok_or_else(|| "canonical staged host path is not UTF-8".to_string())?;
    #[cfg(windows)]
    let display = {
        let slash_path = display.replace('\\', "/");
        if let Some(remainder) = slash_path.strip_prefix("//?/") {
            if remainder
                .get(..4)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("UNC/"))
            {
                format!("//{}", &remainder[4..])
            } else {
                remainder.to_string()
            }
        } else {
            slash_path
        }
    };
    #[cfg(not(windows))]
    let display = display.to_string();
    CanonicalDisplayPath::from_filesystem_canonical_path(&display)
        .map(|path| path.as_str().to_string())
        .map_err(|error| format!("canonical staged host has unsupported path syntax: {error}"))
}

fn verify_placement_projection(
    requested: Option<&serde_json::Value>,
    response_record: Option<&serde_json::Value>,
    context: &str,
) -> Result<(), String> {
    let Some(requested) = requested.and_then(serde_json::Value::as_object) else {
        return Ok(());
    };
    for key in [
        "owner_handle",
        "owner_type",
        "owner_name",
        "layer_handle",
        "layer_name",
        "insertion_point",
        "scale",
        "rotation_degrees",
        "normal",
        "visibility",
        "array",
    ] {
        if requested.contains_key(key) {
            require_equal_field(response_record, key, requested.get(key), context)?;
        }
    }
    Ok(())
}

fn require_equal_field(
    response: Option<&serde_json::Value>,
    response_key: &str,
    expected: Option<&serde_json::Value>,
    context: &str,
) -> Result<(), String> {
    let expected =
        expected.ok_or_else(|| format!("{context} request is missing its expected value"))?;
    let actual = response
        .and_then(|value| value.get(response_key))
        .ok_or_else(|| format!("{context} response is missing '{response_key}'"))?;
    if !json_equivalent(actual, expected) {
        return Err(format!(
            "{context} response field '{response_key}' does not match request: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

fn require_literal_field(
    response: Option<&serde_json::Value>,
    response_key: &str,
    expected: &str,
    context: &str,
) -> Result<(), String> {
    let actual = response
        .and_then(|value| value.get(response_key))
        .and_then(serde_json::Value::as_str);
    if actual != Some(expected) {
        return Err(format!(
            "{context} response field '{response_key}' must be '{expected}', got {actual:?}"
        ));
    }
    Ok(())
}

fn json_equivalent(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    match (left, right) {
        (serde_json::Value::Number(left), serde_json::Value::Number(right)) => left
            .as_f64()
            .zip(right.as_f64())
            .is_some_and(|(left, right)| (left - right).abs() <= 1e-12),
        (serde_json::Value::Array(left), serde_json::Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| json_equivalent(left, right))
        }
        (serde_json::Value::Object(left), serde_json::Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right
                        .get(key)
                        .is_some_and(|right| json_equivalent(value, right))
                })
        }
        _ => left == right,
    }
}

fn verify_xref_unrelated_resources(
    operation: XrefMutationOperation,
    params: &serde_json::Map<String, serde_json::Value>,
    response: &serde_json::Value,
    before: &XrefPersistedState,
    after: &XrefPersistedState,
) -> Result<(), String> {
    let mut attachment_handles = BTreeSet::new();
    let mut instance_handles = BTreeSet::new();
    match operation {
        XrefMutationOperation::UpdateXref
        | XrefMutationOperation::DetachXref
        | XrefMutationOperation::ReloadXref
        | XrefMutationOperation::UnloadXref
        | XrefMutationOperation::BindXref => {
            collect_handle(params.get("handle"), &mut attachment_handles);
        }
        XrefMutationOperation::UpdateXrefInstance | XrefMutationOperation::DeleteXrefInstance => {
            collect_handle(params.get("handle"), &mut instance_handles);
        }
        XrefMutationOperation::AttachXref | XrefMutationOperation::InsertXrefInstance => {}
    }
    collect_record_handle(response.get("attachment"), &mut attachment_handles);
    collect_record_handle(response.get("instance"), &mut instance_handles);
    if let Some(handles) = response
        .get("deleted_instance_handles")
        .and_then(serde_json::Value::as_array)
    {
        for handle in handles {
            collect_handle(Some(handle), &mut instance_handles);
        }
    }
    if let Some(mappings) = response
        .get("instance_handle_mappings")
        .and_then(serde_json::Value::as_array)
    {
        for mapping in mappings {
            collect_handle(mapping.get("old_handle"), &mut instance_handles);
            collect_handle(mapping.get("new_handle"), &mut instance_handles);
        }
    }

    compare_unrelated_records(
        "attachments",
        &before.attachments,
        &after.attachments,
        &attachment_handles,
    )?;
    compare_unrelated_records(
        "instances",
        &before.instances,
        &after.instances,
        &instance_handles,
    )?;
    Ok(())
}

fn compare_unrelated_records(
    label: &str,
    before: &[serde_json::Value],
    after: &[serde_json::Value],
    affected: &BTreeSet<String>,
) -> Result<(), String> {
    let before = records_by_handle(before, affected)?;
    let after = records_by_handle(after, affected)?;
    if before != after {
        return Err(format!(
            "unrelated {label} differ outside the active preservation profile exception"
        ));
    }
    Ok(())
}

fn records_by_handle(
    records: &[serde_json::Value],
    excluded: &BTreeSet<String>,
) -> Result<BTreeMap<String, serde_json::Value>, String> {
    let mut result = BTreeMap::new();
    for record in records {
        let handle = record
            .get("handle")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("persisted XREF record has no string handle: {record}"))?;
        if !excluded.contains(handle) {
            result.insert(handle.to_string(), record.clone());
        }
    }
    Ok(result)
}

fn require_response_record(
    records: &[serde_json::Value],
    response_record: Option<&serde_json::Value>,
    label: &str,
) -> Result<(), String> {
    let response_record = response_record.ok_or_else(|| format!("response has no {label}"))?;
    let handle = response_record
        .get("handle")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("response {label} has no string handle"))?;
    let persisted = records
        .iter()
        .find(|record| record.get("handle").and_then(serde_json::Value::as_str) == Some(handle))
        .ok_or_else(|| format!("verified {label} handle '{handle}' is not persisted"))?;
    let response_object = response_record
        .as_object()
        .ok_or_else(|| format!("response {label} must be an object"))?;
    if !response_object.iter().all(|(key, expected)| {
        persisted
            .get(key)
            .is_some_and(|actual| json_equivalent(actual, expected))
    }) {
        return Err(format!(
            "persisted {label} handle '{handle}' does not contain the exact response projection"
        ));
    }
    Ok(())
}

fn require_response_record_absent(
    records: &[serde_json::Value],
    response_record: Option<&serde_json::Value>,
    label: &str,
) -> Result<(), String> {
    let response_record = response_record.ok_or_else(|| format!("response has no {label}"))?;
    let handle = response_record
        .get("handle")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("response {label} has no string handle"))?;
    if records
        .iter()
        .any(|record| record.get("handle").and_then(serde_json::Value::as_str) == Some(handle))
    {
        return Err(format!(
            "removed {label} handle '{handle}' is still persisted"
        ));
    }
    Ok(())
}

fn collect_record_handle(value: Option<&serde_json::Value>, handles: &mut BTreeSet<String>) {
    collect_handle(value.and_then(|value| value.get("handle")), handles);
}

fn collect_handle(value: Option<&serde_json::Value>, handles: &mut BTreeSet<String>) {
    if let Some(handle) = value.and_then(serde_json::Value::as_str) {
        handles.insert(handle.to_string());
    }
}

fn xref_records(value: serde_json::Value) -> Vec<serde_json::Value> {
    match value {
        serde_json::Value::Array(records) => records,
        serde_json::Value::Object(mut object) => ["records", "xrefs", "instances", "blocks"]
            .into_iter()
            .find_map(|key| {
                object
                    .remove(key)
                    .and_then(|value| value.as_array().cloned())
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn xref_source_digests(
    params: &serde_json::Map<String, serde_json::Value>,
    drawing: &Path,
    state: &XrefPersistedState,
    declared_sources: &[PathBuf],
) -> Result<BTreeMap<String, String>, String> {
    let mut candidates: BTreeSet<_> = declared_sources.iter().cloned().collect();
    collect_xref_source_paths(
        &serde_json::Value::Object(params.clone()),
        drawing,
        &mut candidates,
    );
    collect_xref_source_paths(
        &serde_json::Value::Array(state.attachments.clone()),
        drawing,
        &mut candidates,
    );
    candidates
        .into_iter()
        .map(|path| {
            if !path.is_file() {
                return Err(format!(
                    "declared or discovered XREF source fixture is absent: {}",
                    path.display()
                ));
            }
            let digest = xref_sha256_file(&path).map_err(|error| error.to_string())?;
            Ok((path.to_string_lossy().into_owned(), digest))
        })
        .collect()
}

fn collect_xref_source_paths(
    value: &serde_json::Value,
    drawing: &Path,
    paths: &mut BTreeSet<PathBuf>,
) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if matches!(
                    key.as_str(),
                    "xref_path" | "resolved_path" | "saved_path" | "path"
                ) {
                    if let Some(path) = value.as_str() {
                        let path = PathBuf::from(path);
                        let path = if path.is_absolute() {
                            path
                        } else {
                            drawing
                                .parent()
                                .unwrap_or_else(|| Path::new("."))
                                .join(path)
                        };
                        paths.insert(path);
                    }
                }
                collect_xref_source_paths(value, drawing, paths);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_xref_source_paths(value, drawing, paths);
            }
        }
        _ => {}
    }
}

fn xref_artifact_inventory(drawing: &Path) -> Result<BTreeSet<String>, String> {
    let mut artifacts = BTreeSet::new();
    let temp_directory = std::env::temp_dir();
    for directory in [drawing.parent(), Some(temp_directory.as_path())]
        .into_iter()
        .flatten()
    {
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "scan artifact directory {}: {error}",
                    directory.display()
                ))
            }
        };
        for entry in entries {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.to_string()),
            };
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            let extension = path
                .extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or_default();
            if name.starts_with("autocad-mcp-xref-")
                || name.starts_with(".autocad-mcp-xref-")
                || matches!(
                    extension.to_ascii_lowercase().as_str(),
                    "bak" | "dwl" | "dwl2"
                )
            {
                collect_xref_artifact_paths(&path, &mut artifacts)?;
            }
        }
    }
    Ok(artifacts)
}

fn collect_xref_artifact_paths(
    path: &Path,
    artifacts: &mut BTreeSet<String>,
) -> Result<(), String> {
    artifacts.insert(path.to_string_lossy().into_owned());
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("inspect artifact {}: {error}", path.display())),
    };
    if metadata.is_dir() {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("scan artifact {}: {error}", path.display())),
        };
        for entry in entries {
            match entry {
                Ok(entry) => collect_xref_artifact_paths(&entry.path(), artifacts)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct XrefObservedOutput {
    output: Output,
    cleanup: XrefArtifactCleanupEvidence,
}

#[derive(Debug)]
struct XrefLiveObservation {
    artifacts: BTreeSet<String>,
    processes: BTreeSet<u32>,
    polls: u64,
    error: Option<String>,
}

fn xref_race_coordination_point(scenario: XrefCertificationScenario) -> Option<&'static str> {
    match scenario {
        XrefCertificationScenario::HostRace => Some("host_after_initial_observation"),
        XrefCertificationScenario::SourceRace => Some("source_after_initial_digest"),
        _ => None,
    }
}

fn run_command_bounded_with_xref_race(
    command: Command,
    timeout: Duration,
    scenario: XrefCertificationScenario,
    drawing: &Path,
    race_source: Option<&Path>,
) -> Result<Output, String> {
    let Some(point) = xref_race_coordination_point(scenario) else {
        return run_command_bounded(command, timeout);
    };
    let target = match scenario {
        XrefCertificationScenario::HostRace => drawing,
        XrefCertificationScenario::SourceRace => race_source
            .ok_or_else(|| "source_race requires one declared staged source fixture".to_string())?,
        _ => unreachable!("race point exists only for race scenarios"),
    };
    run_command_bounded_with_xref_race_platform(command, timeout, point, target)
}

#[cfg(windows)]
fn run_command_bounded_with_xref_race_platform(
    mut command: Command,
    timeout: Duration,
    point: &'static str,
    target: &Path,
) -> Result<Output, String> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::atomic::{AtomicU64, Ordering};
    use windows_sys::Win32::{
        Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{CreateEventW, SetEvent, WaitForSingleObject},
    };

    static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
    const RACE_WAIT_MS: u32 = 30_000;
    const RACE_ENV: &str = "AUTOCAD_MCP_XREF_RACE_COORDINATION";

    fn event_name(token: &str, point: &str, suffix: &str) -> Vec<u16> {
        format!("Local\\AutoCADMcpXrefRace-{token}-{point}-{suffix}")
            .encode_utf16()
            .chain(Some(0))
            .collect()
    }

    fn create_event(name: &[u16], label: &str) -> Result<OwnedHandle, String> {
        let handle = unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(format!(
                "create deterministic XREF {label} event: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }

    fn write_synced(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|error| format!("{label} {}: {error}", path.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("{label} {}: {error}", path.display()))?;
        file.sync_all()
            .map_err(|error| format!("flush {label} {}: {error}", path.display()))
    }

    let token = format!(
        "{}-{}",
        std::process::id(),
        NEXT_TOKEN.fetch_add(1, Ordering::Relaxed)
    );
    let ready = create_event(&event_name(&token, point, "ready"), "ready")?;
    let continue_event = create_event(&event_name(&token, point, "continue"), "continue")?;
    command.env(RACE_ENV, format!("{point}:{token}"));

    let target = target.to_path_buf();
    let driver = thread::spawn(move || -> Result<(PathBuf, Vec<u8>), String> {
        match unsafe { WaitForSingleObject(ready.as_raw_handle(), RACE_WAIT_MS) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                return Err("timed out waiting for release binary's XREF race point".to_string());
            }
            WAIT_FAILED => {
                return Err(format!(
                    "wait for XREF race point: {}",
                    std::io::Error::last_os_error()
                ));
            }
            status => return Err(format!("unexpected XREF race wait status {status}")),
        }

        let original = std::fs::read(&target)
            .map_err(|error| format!("read race target {}: {error}", target.display()));
        let mutation = original.and_then(|original| {
            let mut changed = original.clone();
            if let Some(last) = changed.last_mut() {
                *last ^= 0x01;
            } else {
                changed.push(0x01);
            }
            write_synced(&target, &changed, "mutate deterministic XREF race target")?;
            Ok((target, original))
        });
        let signal = if unsafe { SetEvent(continue_event.as_raw_handle()) } == 0 {
            Err(format!(
                "signal deterministic XREF race continuation: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(())
        };
        match (mutation, signal) {
            (Ok(mutation), Ok(())) => Ok(mutation),
            (Err(error), Ok(())) | (_, Err(error)) => Err(error),
        }
    });

    let command_result = run_command_bounded(command, timeout);
    let mutation = driver
        .join()
        .map_err(|_| "deterministic XREF race driver panicked".to_string())?;
    let restore = mutation.and_then(|(target, original)| {
        write_synced(&target, &original, "restore deterministic XREF race target")
    });
    match (command_result, restore) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) | (_, Err(error)) => Err(error),
    }
}

#[cfg(not(windows))]
fn run_command_bounded_with_xref_race_platform(
    _command: Command,
    _timeout: Duration,
    _point: &'static str,
    _target: &Path,
) -> Result<Output, String> {
    Err("deterministic XREF race drivers require Windows named events".to_string())
}

#[allow(clippy::too_many_arguments)]
fn run_xref_cli_observed(
    runtime: &XrefCertificationCommandRuntime,
    profile_isolation: &mut Vec<CertificationProfileIsolationEvidence>,
    invocation_id: &str,
    profile_expectation: CertificationProfileLaunchExpectation,
    tool: &str,
    params: &serde_json::Value,
    failpoint: Option<XrefCertificationFailpoint>,
    drawing: &Path,
    scenario: XrefCertificationScenario,
    race_source: Option<&Path>,
) -> Result<XrefObservedOutput, String> {
    let mut inventory_roots = vec![
        drawing
            .parent()
            .ok_or_else(|| "staged drawing has no parent directory".to_string())?
            .to_path_buf(),
        std::env::temp_dir(),
    ];
    inventory_roots.sort();
    inventory_roots.dedup();
    let before_artifacts = xref_artifact_inventory(drawing)?;
    let mut process_error = None;
    let process_ids_before = match accoreconsole_process_ids() {
        Ok(processes) => processes,
        Err(error) => {
            process_error = Some(error);
            BTreeSet::new()
        }
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    let live = Arc::new(Mutex::new(XrefLiveObservation {
        artifacts: before_artifacts.clone(),
        processes: process_ids_before.clone(),
        polls: 1,
        error: process_error,
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let monitor_live = Arc::clone(&live);
    let monitor_stop = Arc::clone(&stop);
    let monitor_drawing = drawing.to_path_buf();
    let monitor = thread::spawn(move || {
        while !monitor_stop.load(Ordering::Acquire) {
            thread::sleep(CERTIFICATION_POLL_INTERVAL);
            if monitor_stop.load(Ordering::Acquire) {
                break;
            }
            let artifacts = xref_artifact_inventory(&monitor_drawing);
            let processes = accoreconsole_process_ids();
            let mut state = monitor_live
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.polls += 1;
            match artifacts {
                Ok(paths) => state.artifacts.extend(paths),
                Err(error) => {
                    state.error.get_or_insert(error);
                }
            }
            match processes {
                Ok(processes) => state.processes.extend(processes),
                Err(error) => {
                    state.error.get_or_insert(error);
                }
            }
        }
    });
    let mut command = xref_certification_tool_command(runtime, tool, params);
    if let Some(failpoint) = failpoint {
        command.env("AUTOCAD_MCP_XREF_FAILPOINT", failpoint.as_str());
    }
    let output = run_with_unique_xref_profile(
        &runtime.certified_arg,
        &runtime.certified_arg_sha256,
        invocation_id,
        tool,
        profile_expectation,
        command,
        |command| {
            run_command_bounded_with_xref_race(
                command,
                CERTIFICATION_TOOL_TIMEOUT,
                scenario,
                drawing,
                race_source,
            )
            .map_err(|error| format!("bounded {tool} execution failed: {error}"))
        },
    );
    stop.store(true, Ordering::Release);
    monitor
        .join()
        .map_err(|_| "XREF live-observation thread panicked".to_string())?;
    let (output, profile_observation) = output?;
    profile_isolation.push(profile_observation);
    thread::sleep(Duration::from_millis(20));
    let mut live = live
        .lock()
        .map_err(|_| "XREF live-observation state was poisoned".to_string())?;
    live.polls += 1;
    let after_artifacts = match xref_artifact_inventory(drawing) {
        Ok(paths) => paths,
        Err(error) => {
            live.error.get_or_insert(error);
            BTreeSet::new()
        }
    };
    live.artifacts.extend(after_artifacts.iter().cloned());
    let process_ids_after = match accoreconsole_process_ids() {
        Ok(processes) => processes,
        Err(error) => {
            live.error.get_or_insert(error);
            BTreeSet::new()
        }
    };
    live.processes.extend(process_ids_after.iter().copied());

    let attempted: BTreeSet<_> = live
        .artifacts
        .difference(&before_artifacts)
        .cloned()
        .collect();
    let removed: Vec<_> = attempted.difference(&after_artifacts).cloned().collect();
    let remaining: Vec<_> = attempted.intersection(&after_artifacts).cloned().collect();
    let process_ids_observed: Vec<_> = live
        .processes
        .difference(&process_ids_before)
        .copied()
        .collect();
    let process_ids_remaining: Vec<_> = process_ids_after
        .difference(&process_ids_before)
        .copied()
        .collect();
    best_effort_remove_observed_artifacts(&remaining);

    Ok(XrefObservedOutput {
        output,
        cleanup: XrefArtifactCleanupEvidence {
            inventory_roots: inventory_roots
                .into_iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
            observation_polls: live.polls,
            attempted: attempted.into_iter().collect(),
            removed,
            remaining,
            process_ids_before: process_ids_before.into_iter().collect(),
            process_ids_observed,
            process_ids_remaining,
            engine_stop_error: live
                .error
                .as_deref()
                .map(|error| redacted_certification_failure("cleanup_observation_failure", error)),
        },
    })
}

#[cfg(windows)]
fn accoreconsole_process_ids() -> Result<BTreeSet<u32>, String> {
    let mut command = Command::new("tasklist");
    command.args(["/FI", "IMAGENAME eq accoreconsole.exe", "/FO", "CSV", "/NH"]);
    let output = run_command_bounded(command, CERTIFICATION_PROCESS_INSPECTION_TIMEOUT)
        .map_err(|error| format!("inspect bounded accoreconsole process state: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "inspect accoreconsole process state failed; {}",
            certification_output_diagnostic(&output)
        ));
    }
    if !output.stderr.is_empty() {
        return Err(format!(
            "inspect accoreconsole process state wrote unexpected stderr; {}",
            certification_output_diagnostic(&output)
        ));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| {
            format!(
                "tasklist process-state encoding was not UTF-8; {}",
                certification_output_diagnostic(&output)
            )
        })?
        .to_string();
    let mut processes = BTreeSet::new();
    for line in stdout.lines().map(str::trim) {
        if !line.starts_with('"') {
            continue;
        }
        let fields = line.trim_matches('"').split("\",\"").collect::<Vec<_>>();
        if fields
            .first()
            .is_some_and(|image| image.eq_ignore_ascii_case("accoreconsole.exe"))
        {
            let process_id = fields
                .get(1)
                .ok_or_else(|| "tasklist row has no PID".to_string())?
                .replace(',', "")
                .parse::<u32>()
                .map_err(|_| "tasklist row has an invalid PID".to_string())?;
            processes.insert(process_id);
        }
    }
    Ok(processes)
}

#[cfg(not(windows))]
fn accoreconsole_process_ids() -> Result<BTreeSet<u32>, String> {
    Ok(BTreeSet::new())
}

fn best_effort_remove_observed_artifacts(paths: &[String]) {
    let mut paths = paths.iter().map(PathBuf::from).collect::<Vec<_>>();
    paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in paths {
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => {
                let _ = std::fs::remove_dir_all(path);
            }
            Ok(_) => {
                let _ = std::fs::remove_file(path);
            }
            Err(_) => {}
        }
    }
}

fn run_xref_cli_json(
    runtime: &XrefCertificationCommandRuntime,
    profile_isolation: &mut Vec<CertificationProfileIsolationEvidence>,
    invocation_id: &str,
    tool: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let output = run_xref_cli(
        runtime,
        profile_isolation,
        invocation_id,
        CertificationProfileLaunchExpectation::NoEngineExpected,
        tool,
        params,
        None,
    )?;
    if !output.status.success() {
        return Err(format!(
            "{tool} failed; {}",
            certification_output_diagnostic(&output)
        ));
    }
    if !output.stderr.is_empty() {
        return Err(format!(
            "{tool} successful execution wrote unexpected stderr; {}",
            certification_output_diagnostic(&output)
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| certification_json_bytes_error_diagnostic(tool, &output.stdout, &error))
}

fn run_xref_cli(
    runtime: &XrefCertificationCommandRuntime,
    profile_isolation: &mut Vec<CertificationProfileIsolationEvidence>,
    invocation_id: &str,
    profile_expectation: CertificationProfileLaunchExpectation,
    tool: &str,
    params: &serde_json::Value,
    failpoint: Option<XrefCertificationFailpoint>,
) -> Result<Output, String> {
    let mut command = xref_certification_tool_command(runtime, tool, params);
    if let Some(failpoint) = failpoint {
        command.env("AUTOCAD_MCP_XREF_FAILPOINT", failpoint.as_str());
    }
    let (output, observation) = run_with_fresh_certified_profile(
        &runtime.certified_arg,
        &runtime.certified_arg_sha256,
        invocation_id,
        tool,
        profile_expectation,
        || {
            run_command_bounded(command, CERTIFICATION_TOOL_TIMEOUT)
                .map_err(|error| format!("failed to run bounded {tool}: {error}"))
        },
    )?;
    profile_isolation.push(observation);
    Ok(output)
}

fn xref_error_code(stderr: &[u8]) -> Option<String> {
    std::str::from_utf8(stderr)
        .ok()
        .and_then(|stderr| certification_error_code_text("", stderr))
}

fn aggregate_xref_case_status(run: &XrefCertificationRun) -> XrefCertificationResultStatus {
    if run.failures.is_empty()
        && !run.results.is_empty()
        && run
            .results
            .iter()
            .all(|result| result.status == XrefCertificationResultStatus::Passed)
    {
        XrefCertificationResultStatus::Passed
    } else {
        XrefCertificationResultStatus::Failed
    }
}

fn xref_binary_certification_info(binary: &Path) -> Result<serde_json::Value, String> {
    let mut command = Command::new(binary);
    command.arg("xref-certification-info");
    let output = run_command_bounded(command, CERTIFICATION_TOOL_TIMEOUT)
        .map_err(|error| format!("failed to inspect bounded XREF certification build: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "XREF certification introspection failed; {}",
            certification_output_diagnostic(&output)
        ));
    }
    if !output.stderr.is_empty() {
        return Err(format!(
            "XREF certification introspection wrote unexpected stderr; {}",
            certification_output_diagnostic(&output)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        certification_json_bytes_error_diagnostic(
            "XREF certification introspection",
            &output.stdout,
            &error,
        )
    })
}

fn validate_release_flavor_certification_info(
    info: &serde_json::Value,
    label: &str,
    expected_failpoints: bool,
) -> Result<(), String> {
    let object = info
        .as_object()
        .ok_or_else(|| format!("{label} introspection must be an object"))?;
    let schema_version = object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            format!(
                "{label} introspection must report integer schema_version={XREF_CERTIFICATION_INFO_SCHEMA_VERSION}"
            )
        })?;
    if schema_version != XREF_CERTIFICATION_INFO_SCHEMA_VERSION {
        return Err(format!(
            "{label} introspection schema_version must be {XREF_CERTIFICATION_INFO_SCHEMA_VERSION}, got {schema_version}"
        ));
    }

    let experimental_support = object
        .get("experimental_support")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            format!("{label} introspection must report boolean experimental_support=false")
        })?;
    if experimental_support {
        return Err(format!(
            "{label} introspection reports experimental_support=true; Preview builds are not admissible for Windows certification"
        ));
    }

    let activation_catalogue_sha256 = object
        .get("activation_catalogue_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{label} introspection must report activation_catalogue_sha256"))?;
    let expected_activation_catalogue = autocad_mcp::activation::activation_catalogue_sha256()
        .map_err(|error| format!("validate embedded activation catalogue: {error}"))?;
    if activation_catalogue_sha256 != expected_activation_catalogue {
        return Err(format!(
            "{label} introspection activation catalogue digest is stale"
        ));
    }

    let reported_failpoints = object
        .get("certification_failpoints_enabled")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            format!("{label} introspection must report boolean certification_failpoints_enabled")
        })?;
    let identity_failpoints = object
        .get("build_identity")
        .and_then(serde_json::Value::as_object)
        .and_then(|identity| identity.get("certification_failpoints_enabled"))
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            format!(
                "{label} introspection build_identity must report boolean certification_failpoints_enabled"
            )
        })?;
    if reported_failpoints != expected_failpoints
        || identity_failpoints != expected_failpoints
        || reported_failpoints != identity_failpoints
    {
        return Err(format!(
            "{label} introspection has the wrong failpoint flavor; expected certification_failpoints_enabled={expected_failpoints} at the root and in build_identity"
        ));
    }

    verify_exact_object_fields(
        info,
        &[
            "schema_version",
            "experimental_support",
            "certified_arg_sha256",
            "certified_arg_policy_id",
            "certified_arg_policy_sha256",
            "activation_catalogue_sha256",
            "certification_failpoints_enabled",
            "crt_linkage",
            "artifact_sha256",
            "title_block_profile_registry_sha256",
            "title_block_profiles",
            "build_identity",
            "xref_mutation_tools",
        ],
        &format!("{label} introspection"),
    )
}

fn xref_binary_build_identity(
    info: &serde_json::Value,
    label: &str,
) -> XrefCertificationBuildIdentity {
    let identity = info
        .get("build_identity")
        .unwrap_or_else(|| panic!("{label} executable did not report build_identity"))
        .clone();
    serde_json::from_value(identity)
        .unwrap_or_else(|error| panic!("{label} executable build_identity is invalid: {error}"))
}

fn write_xref_json(path: &Path, value: &impl serde::Serialize) {
    write_certification_json(path, value)
        .unwrap_or_else(|error| panic!("failed to publish XREF certification evidence: {error}"));
    eprintln!("wrote {}", path.display());
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

fn verify_write_output(
    stdout: &str,
    expected_drawing: &str,
    expected_profile_id: &str,
    fields_written: usize,
) -> Result<(), String> {
    let value = parse_certification_json("write_title_block", stdout)?;
    verify_exact_object_fields(
        &value,
        &[
            "status",
            "drawing",
            "profile_id",
            "fields_written",
            "target_inserts",
            "attributes_written",
        ],
        "write_title_block response",
    )?;
    if value.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
        return Err("write_title_block response status was not ok".to_string());
    }
    if value.get("drawing").and_then(serde_json::Value::as_str) != Some(expected_drawing) {
        return Err(
            "write_title_block response did not identify the ordinary staged drawing path"
                .to_string(),
        );
    }
    if value.get("profile_id").and_then(serde_json::Value::as_str) != Some(expected_profile_id) {
        return Err("write_title_block resolved an unexpected profile_id".to_string());
    }
    if value["fields_written"].as_u64() != Some(fields_written as u64) {
        return Err("write_title_block fields_written did not match the request".to_string());
    }
    let target_inserts = value["target_inserts"]
        .as_u64()
        .ok_or_else(|| "write_title_block target_inserts was not numeric".to_string())?;
    if target_inserts == 0 {
        return Err("write_title_block target_inserts was zero".to_string());
    }
    let attributes_written = value["attributes_written"]
        .as_u64()
        .ok_or_else(|| "write_title_block attributes_written was not numeric".to_string())?;
    let expected_attributes = target_inserts * fields_written as u64;
    if attributes_written != expected_attributes {
        return Err(
            "write_title_block attributes_written did not close target_inserts * fields_written"
                .to_string(),
        );
    }
    Ok(())
}

fn verify_plot_output(
    stdout: &str,
    expected_drawing: &str,
    expected_layout: &str,
    expected_output: &str,
) -> Result<(), String> {
    let value = parse_certification_json("plot_to_pdf", stdout)?;
    verify_exact_object_fields(
        &value,
        &["status", "drawing", "layout", "output"],
        "plot_to_pdf response",
    )?;
    if value.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
        return Err("plot_to_pdf response status was not ok".to_string());
    }
    if value.get("drawing").and_then(serde_json::Value::as_str) != Some(expected_drawing) {
        return Err(
            "plot_to_pdf response did not identify the ordinary staged drawing path".to_string(),
        );
    }
    if value.get("layout").and_then(serde_json::Value::as_str) != Some(expected_layout)
        || value.get("output").and_then(serde_json::Value::as_str) != Some(expected_output)
    {
        return Err("plot_to_pdf response did not bind the requested layout/output".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod xref_harness_tests {
    use super::*;

    fn release_flavor_info(
        certification_failpoints_enabled: bool,
        experimental_support: bool,
    ) -> serde_json::Value {
        serde_json::json!({
            "schema_version": XREF_CERTIFICATION_INFO_SCHEMA_VERSION,
            "experimental_support": experimental_support,
            "certified_arg_sha256": null,
            "certified_arg_policy_id": null,
            "certified_arg_policy_sha256": null,
            "activation_catalogue_sha256":
                autocad_mcp::activation::activation_catalogue_sha256().unwrap(),
            "certification_failpoints_enabled": certification_failpoints_enabled,
            "crt_linkage": "static",
            "artifact_sha256": {},
            "title_block_profile_registry_sha256": "a".repeat(64),
            "title_block_profiles": [],
            "build_identity": {
                "certification_failpoints_enabled": certification_failpoints_enabled,
            },
            "xref_mutation_tools": [],
        })
    }

    #[test]
    fn release_flavor_admission_accepts_release_and_instrumented_binaries() {
        validate_release_flavor_certification_info(
            &release_flavor_info(false, false),
            "release binary",
            false,
        )
        .unwrap();
        validate_release_flavor_certification_info(
            &release_flavor_info(true, false),
            "instrumented binary",
            true,
        )
        .unwrap();
    }

    #[test]
    fn release_flavor_admission_rejects_preview_binaries() {
        for expected_failpoints in [false, true] {
            let error = validate_release_flavor_certification_info(
                &release_flavor_info(expected_failpoints, true),
                "certification binary",
                expected_failpoints,
            )
            .unwrap_err();
            assert!(
                error.contains("Preview builds are not admissible"),
                "{error}"
            );
        }
    }

    #[test]
    fn release_flavor_admission_is_fail_closed_for_schema_and_flavor() {
        let mut stale_schema = release_flavor_info(false, false);
        stale_schema["schema_version"] = serde_json::json!(2);
        let error =
            validate_release_flavor_certification_info(&stale_schema, "release binary", false)
                .unwrap_err();
        assert!(error.contains("schema_version must be 4"), "{error}");

        let mut missing_flavor = release_flavor_info(false, false);
        missing_flavor
            .as_object_mut()
            .unwrap()
            .remove("experimental_support");
        let error =
            validate_release_flavor_certification_info(&missing_flavor, "release binary", false)
                .unwrap_err();
        assert!(error.contains("experimental_support=false"), "{error}");

        let mut mismatched_identity = release_flavor_info(false, false);
        mismatched_identity["build_identity"]["certification_failpoints_enabled"] =
            serde_json::json!(true);
        let error = validate_release_flavor_certification_info(
            &mismatched_identity,
            "release binary",
            false,
        )
        .unwrap_err();
        assert!(error.contains("wrong failpoint flavor"), "{error}");

        let mut open_schema = release_flavor_info(false, false);
        open_schema["unexpected"] = serde_json::Value::Null;
        let error =
            validate_release_flavor_certification_info(&open_schema, "release binary", false)
                .unwrap_err();
        assert!(error.contains("non-closed field inventory"), "{error}");
    }

    fn persisted_state() -> XrefPersistedState {
        XrefPersistedState {
            attachments: vec![serde_json::json!({
                "handle": "A",
                "name": "SITE",
                "saved_path": "refs/old.dwg"
            })],
            instances: vec![serde_json::json!({"handle": "10"})],
            blocks: Vec::new(),
        }
    }

    #[test]
    fn strict_xref_children_are_pinned_to_exact_binary_engine_and_arg() {
        let runtime = XrefCertificationCommandRuntime {
            binary: PathBuf::from("C:/cert/autocad-mcp.exe"),
            accoreconsole: PathBuf::from(
                "C:/Program Files/Autodesk/AutoCAD 2026/accoreconsole.exe",
            ),
            certified_arg: PathBuf::from("C:/cert/autocad-mcp.arg"),
            certified_arg_sha256: "a".repeat(64),
        };
        let command =
            xref_certification_tool_command(&runtime, "update_xref", &serde_json::json!({}));
        assert_eq!(command.get_program(), runtime.binary.as_os_str());
        let environment = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            environment["AUTOCAD_MCP_ACCORECONSOLE_PATH"].as_deref(),
            Some(runtime.accoreconsole.to_string_lossy().as_ref())
        );
        assert_eq!(
            environment["AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH"].as_deref(),
            Some(runtime.certified_arg.to_string_lossy().as_ref())
        );
        assert_eq!(environment["AUTOCAD_MCP_XREF_FAILPOINT"], None);
    }

    #[test]
    fn update_response_must_match_requested_persisted_values() {
        let params = serde_json::json!({
            "name": "SITE",
            "properties": {
                "name": "RENAMED",
                "xref_path": "refs/new.dwg",
                "reference_type": "overlay"
            }
        });
        let response = serde_json::json!({
            "drawing": "/host.dwg",
            "attachment": {
                "handle": "A",
                "name": "RENAMED",
                "saved_path": "refs/old.dwg",
                "reference_type": "overlay"
            }
        });
        let error = verify_xref_response_matches_request(
            XrefMutationOperation::UpdateXref,
            params.as_object().unwrap(),
            &response,
            &persisted_state(),
            "/host.dwg",
        )
        .unwrap_err();
        assert!(error.contains("saved_path"), "got: {error}");
    }

    #[test]
    fn persisted_record_must_contain_exact_response_projection() {
        let persisted = vec![serde_json::json!({
            "handle": "A",
            "name": "ACTUAL",
            "saved_path": "refs/site.dwg"
        })];
        let response = serde_json::json!({
            "handle": "A",
            "name": "STALE",
            "saved_path": "refs/site.dwg"
        });
        let error = require_response_record(&persisted, Some(&response), "attachment").unwrap_err();
        assert!(error.contains("exact response projection"), "got: {error}");
    }

    #[test]
    fn response_target_must_match_requested_identity() {
        let params = serde_json::json!({"handle": "A", "name": "SITE"});
        let response = serde_json::json!({
            "drawing": "/host.dwg",
            "attachment": {"handle": "B", "name": "OTHER"}
        });
        let error = verify_xref_response_matches_request(
            XrefMutationOperation::DetachXref,
            params.as_object().unwrap(),
            &response,
            &persisted_state(),
            "/host.dwg",
        )
        .unwrap_err();
        assert!(error.contains("pre-mutation target handle"), "got: {error}");

        let params = serde_json::json!({"handle": "10"});
        let response = serde_json::json!({
            "drawing": "/host.dwg",
            "instance": {"handle": "11"}
        });
        let error = verify_xref_response_matches_request(
            XrefMutationOperation::DeleteXrefInstance,
            params.as_object().unwrap(),
            &response,
            &persisted_state(),
            "/host.dwg",
        )
        .unwrap_err();
        assert!(error.contains("pre-mutation target handle"), "got: {error}");
    }

    #[test]
    fn renamed_target_is_resolved_by_pre_mutation_handle() {
        let params = serde_json::json!({
            "name": "SITE",
            "properties": {"name": "RENAMED"}
        });
        let response = serde_json::json!({
            "drawing": "/staged/host.dwg",
            "attachment": {
                "handle": "A",
                "name": "RENAMED"
            }
        });
        verify_xref_response_matches_request(
            XrefMutationOperation::UpdateXref,
            params.as_object().unwrap(),
            &response,
            &persisted_state(),
            "/staged/host.dwg",
        )
        .unwrap();
    }

    #[test]
    fn fixture_staging_preserves_the_complete_relative_tree() {
        let directory = tempfile::tempdir().unwrap();
        let fixture_root = directory.path().join("fixtures");
        let output = directory.path().join("evidence");
        std::fs::create_dir_all(fixture_root.join("sources/nested")).unwrap();
        std::fs::create_dir_all(&output).unwrap();
        let host = fixture_root.join("hosts/host.dwg");
        std::fs::create_dir_all(host.parent().unwrap()).unwrap();
        std::fs::write(&host, b"host").unwrap();
        std::fs::write(fixture_root.join("sources/site.dwg"), b"source").unwrap();
        std::fs::write(
            fixture_root.join("sources/nested/dependency.dwg"),
            b"dependency",
        )
        .unwrap();
        let case = XrefCertificationCase {
            case_id: "stage-tree".to_string(),
            row_id: "row".to_string(),
            scenario: XrefCertificationScenario::OperationSuccess,
            operation: XrefMutationOperation::AttachXref,
            drawing_path: host.to_string_lossy().into_owned(),
            source_fixture_paths: vec![
                "sources/nested/dependency.dwg".to_string(),
                "sources/site.dwg".to_string(),
            ],
            params: serde_json::json!({
                "drawing_path": host,
                "xref_path": fixture_root.join("sources/site.dwg"),
                "reference_type": "attachment"
            })
            .as_object()
            .unwrap()
            .clone(),
            expected_status: XrefCertificationExpectedStatus::Passed,
            expected_error_code: None,
            failpoint: None,
        };
        let staged = stage_xref_certification_case(
            fixture_root.to_str().unwrap(),
            &case,
            XrefCertificationEvidenceClass::ReleaseConformance,
            &output,
        )
        .unwrap();
        assert!(staged
            .case_dir
            .join("fixture/sources/nested/dependency.dwg")
            .is_file());
        assert!(staged
            .params
            .get("xref_path")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|path| path.contains("stage-tree/fixture/sources/site.dwg")));
        std::fs::remove_dir_all(staged.case_dir).unwrap();
    }

    #[test]
    fn missing_declared_source_is_an_explicit_staging_failure() {
        let directory = tempfile::tempdir().unwrap();
        let fixture_root = directory.path().join("fixtures");
        let output = directory.path().join("evidence");
        std::fs::create_dir_all(&fixture_root).unwrap();
        std::fs::create_dir_all(&output).unwrap();
        let host = fixture_root.join("host.dwg");
        std::fs::write(&host, b"host").unwrap();
        let case = XrefCertificationCase {
            case_id: "missing-source".to_string(),
            row_id: "row".to_string(),
            scenario: XrefCertificationScenario::OperationSuccess,
            operation: XrefMutationOperation::UnloadXref,
            drawing_path: host.to_string_lossy().into_owned(),
            source_fixture_paths: vec!["sources/missing.dwg".to_string()],
            params: serde_json::json!({"drawing_path": host, "handle": "2A"})
                .as_object()
                .unwrap()
                .clone(),
            expected_status: XrefCertificationExpectedStatus::Passed,
            expected_error_code: None,
            failpoint: None,
        };
        let error = stage_xref_certification_case(
            fixture_root.to_str().unwrap(),
            &case,
            XrefCertificationEvidenceClass::ReleaseConformance,
            &output,
        )
        .unwrap_err();
        assert_eq!(error.stage, XrefCertificationFailureStage::FixtureStaging);
        assert!(error.detail.contains("sources/missing.dwg"));
    }
}

#[cfg(test)]
mod certification_harness_tests {
    use super::*;

    #[cfg(windows)]
    fn windows_process_is_running(process_id: u32) -> Result<bool, String> {
        use windows_sys::Win32::Foundation::{
            ERROR_INVALID_PARAMETER, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
        };

        let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, process_id) };
        if raw.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                return Ok(false);
            }
            return Err(format!("OpenProcess({process_id}): {error}"));
        }
        let process = OwnedCertificationHandle::from_nullable(raw, "OpenProcess")?;
        match unsafe { WaitForSingleObject(process.raw(), 0) } {
            WAIT_OBJECT_0 => Ok(false),
            WAIT_TIMEOUT => Ok(true),
            WAIT_FAILED => Err(format!(
                "WaitForSingleObject({process_id}): {}",
                std::io::Error::last_os_error()
            )),
            other => Err(format!(
                "unexpected zero-duration wait result {other} for process {process_id}"
            )),
        }
    }

    #[cfg(windows)]
    fn wait_for_windows_process_exit(process_id: u32, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if !windows_process_is_running(process_id)? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "process {process_id} remained alive after {}s",
                    timeout.as_secs_f64()
                ));
            }
            thread::sleep(CERTIFICATION_POLL_INTERVAL);
        }
    }

    #[test]
    fn explicit_legacy_certification_inputs_fail_closed() {
        let manifest = PathBuf::from("C:/cert/manifest.json");
        let output = PathBuf::from("C:/cert/evidence");

        assert!(
            strict_windows_inputs("macos", Some(manifest.clone()), Some(output.clone()))
                .unwrap_err()
                .contains("requires Windows")
        );
        assert!(strict_windows_inputs("windows", None, Some(output.clone()))
            .unwrap_err()
            .contains("requires a manifest"));
        assert!(
            strict_windows_inputs("windows", Some(manifest.clone()), None)
                .unwrap_err()
                .contains("requires an evidence output directory")
        );
        assert_eq!(
            strict_windows_inputs("windows", Some(manifest.clone()), Some(output.clone())).unwrap(),
            StrictCertificationInputs {
                manifest_path: manifest,
                output_dir: output,
            }
        );
    }

    fn certified_arg_fixture(profile_name: &str) -> String {
        format!(
            "Windows Registry Editor Version 5.00\r\n\
             \r\n\
             [HKEY_CURRENT_USER\\Software\\Autodesk\\AutoCAD\\R25.1\\ACAD-9101:409\\Profiles\\{profile_name}]\r\n\
             \"Description\"=\"certification\"\r\n\
             \r\n\
             [HKEY_CURRENT_USER\\Software\\Autodesk\\AutoCAD\\R25.1\\ACAD-9101:409\\Profiles\\{profile_name}\\General]\r\n\
             \"Example\"=\"value\"\r\n"
        )
    }

    fn utf16_fixture(text: &str, little_endian: bool) -> Vec<u8> {
        let mut bytes = if little_endian {
            vec![0xFF, 0xFE]
        } else {
            vec![0xFE, 0xFF]
        };
        for code_unit in text.encode_utf16() {
            bytes.extend(if little_endian {
                code_unit.to_le_bytes()
            } else {
                code_unit.to_be_bytes()
            });
        }
        bytes
    }

    #[test]
    fn certified_arg_profile_parser_accepts_utf8_and_bom_marked_utf16() {
        let text = certified_arg_fixture("AutoCAD-MCP Certified");
        let expected = CertifiedArgProfileRoot {
            hkcu_subkey:
                "Software\\Autodesk\\AutoCAD\\R25.1\\ACAD-9101:409\\Profiles\\AutoCAD-MCP Certified"
                    .to_string(),
        };
        let mut utf8_bom = vec![0xEF, 0xBB, 0xBF];
        utf8_bom.extend(text.as_bytes());

        assert_eq!(
            certified_arg_profile_root(text.as_bytes()).unwrap(),
            expected
        );
        assert_eq!(certified_arg_profile_root(&utf8_bom).unwrap(), expected);
        assert_eq!(
            certified_arg_profile_root(&utf16_fixture(&text, true)).unwrap(),
            expected
        );
        assert_eq!(
            certified_arg_profile_root(&utf16_fixture(&text, false)).unwrap(),
            expected
        );
    }

    #[test]
    fn certified_arg_profile_parser_rejects_mixed_or_non_hkcu_profile_roots() {
        let mut mixed = certified_arg_fixture("Certified A");
        mixed.push_str(
            "\r\n[HKEY_CURRENT_USER\\Software\\Autodesk\\AutoCAD\\R25.1\\ACAD-9101:409\\Profiles\\Certified B]\r\n",
        );
        let error = certified_arg_profile_root(mixed.as_bytes()).unwrap_err();
        assert!(error.contains("different profile root"), "got: {error}");

        let wrong_hive =
            certified_arg_fixture("Certified").replace("HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE");
        let error = certified_arg_profile_root(wrong_hive.as_bytes()).unwrap_err();
        assert!(
            error.contains("not beneath HKCU"),
            "unexpected wrong-hive error: {error}"
        );

        let outside = format!(
            "{}\r\n[HKEY_CURRENT_USER\\Software\\Autodesk\\AutoCAD\\R25.1\\Unrelated]\r\n",
            certified_arg_fixture("Certified")
        );
        let error = certified_arg_profile_root(outside.as_bytes()).unwrap_err();
        assert!(error.contains("no Profiles component"), "got: {error}");
    }

    #[test]
    fn certified_arg_profile_parser_rejects_malformed_encodings_and_headers() {
        let odd_utf16 = [0xFF, 0xFE, b'['];
        assert!(certified_arg_profile_root(&odd_utf16)
            .unwrap_err()
            .contains("odd-length"));

        let malformed = b"[HKEY_CURRENT_USER\\Software\\Autodesk\\AutoCAD\\R25.1\\ACAD-9101:409\\Profiles\\Certified";
        assert!(certified_arg_profile_root(malformed)
            .unwrap_err()
            .contains("malformed"));

        let deletion = b"[-HKEY_CURRENT_USER\\Software\\Autodesk\\AutoCAD\\R25.1\\ACAD-9101:409\\Profiles\\Certified]";
        assert!(certified_arg_profile_root(deletion)
            .unwrap_err()
            .contains("not an import header"));
    }

    #[test]
    fn certified_profile_postconditions_distinguish_offline_and_engine_calls() {
        validate_certified_profile_postcondition(
            CertificationProfileLaunchExpectation::NoEngineExpected,
            false,
        )
        .unwrap();
        let unexpected_engine = validate_certified_profile_postcondition(
            CertificationProfileLaunchExpectation::NoEngineExpected,
            true,
        )
        .unwrap_err();
        assert!(
            unexpected_engine.contains("declared offline unexpectedly created"),
            "got: {unexpected_engine}"
        );

        validate_certified_profile_postcondition(
            CertificationProfileLaunchExpectation::EngineImportRequired,
            true,
        )
        .unwrap();
        let missing_import = validate_certified_profile_postcondition(
            CertificationProfileLaunchExpectation::EngineImportRequired,
            false,
        )
        .unwrap_err();
        assert!(
            missing_import.contains("did not create"),
            "got: {missing_import}"
        );
    }

    #[cfg(windows)]
    fn create_registry_test_key(path: &str) -> Result<(), String> {
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegCreateKeyExW, HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS,
            REG_CREATED_NEW_KEY, REG_OPTION_NON_VOLATILE,
        };

        let path = registry_wide_path(path)?;
        let mut key: HKEY = std::ptr::null_mut();
        let mut disposition = 0;
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                std::ptr::null(),
                &mut key,
                &mut disposition,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("RegCreateKeyExW failed with Win32 {status}"));
        }
        let close_status = unsafe { RegCloseKey(key) };
        if close_status != ERROR_SUCCESS {
            return Err(format!("RegCloseKey failed with Win32 {close_status}"));
        }
        if disposition != REG_CREATED_NEW_KEY {
            return Err("unique registry test key unexpectedly already existed".to_string());
        }
        Ok(())
    }

    #[cfg(windows)]
    struct RegistryTestTreeCleanup(CertifiedArgProfileRoot);

    #[cfg(windows)]
    impl Drop for RegistryTestTreeCleanup {
        fn drop(&mut self) {
            match certified_profile_registry_key_exists(&self.0) {
                Ok(true) => {
                    if let Err(error) = delete_certified_profile_registry_tree(&self.0) {
                        eprintln!("failed to clean registry lifecycle test tree: {error}");
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    eprintln!("failed to query registry lifecycle test tree: {error}");
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn certified_profile_registry_guard_owns_only_a_new_exact_subtree() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static NEXT_TEST_KEY: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_TEST_KEY.fetch_add(1, Ordering::Relaxed)
        );
        let base = CertifiedArgProfileRoot {
            hkcu_subkey: format!(
                "Software\\AutoCAD-MCP\\Tests\\CertifiedArgProfileIsolation\\{unique}"
            ),
        };
        assert!(!certified_profile_registry_key_exists(&base).unwrap());
        let _cleanup = RegistryTestTreeCleanup(base.clone());
        let profiles = format!("{}\\Profiles", base.hkcu_subkey);
        let sibling = CertifiedArgProfileRoot {
            hkcu_subkey: format!("{profiles}\\sibling"),
        };
        create_registry_test_key(&sibling.hkcu_subkey).unwrap();

        let owned = CertifiedArgProfileRoot {
            hkcu_subkey: format!("{profiles}\\owned"),
        };
        let mut isolation = CertifiedArgProfileIsolation::acquire_root(owned.clone()).unwrap();
        create_registry_test_key(&format!("{}\\Nested", owned.hkcu_subkey)).unwrap();
        isolation
            .finish(CertificationProfileLaunchExpectation::EngineImportRequired)
            .unwrap();
        assert!(!certified_profile_registry_key_exists(&owned).unwrap());
        assert!(certified_profile_registry_key_exists(&sibling).unwrap());

        let mut second_isolation =
            CertifiedArgProfileIsolation::acquire_root(owned.clone()).unwrap();
        create_registry_test_key(&owned.hkcu_subkey).unwrap();
        second_isolation
            .finish(CertificationProfileLaunchExpectation::EngineImportRequired)
            .unwrap();
        assert!(!certified_profile_registry_key_exists(&owned).unwrap());
        assert!(certified_profile_registry_key_exists(&sibling).unwrap());

        let offline = CertifiedArgProfileRoot {
            hkcu_subkey: format!("{profiles}\\offline"),
        };
        let mut offline_isolation =
            CertifiedArgProfileIsolation::acquire_root(offline.clone()).unwrap();
        offline_isolation
            .finish(CertificationProfileLaunchExpectation::NoEngineExpected)
            .unwrap();
        assert!(!certified_profile_registry_key_exists(&offline).unwrap());

        let unexpected_engine = CertifiedArgProfileRoot {
            hkcu_subkey: format!("{profiles}\\unexpected-engine"),
        };
        let mut unexpected_isolation =
            CertifiedArgProfileIsolation::acquire_root(unexpected_engine.clone()).unwrap();
        create_registry_test_key(&unexpected_engine.hkcu_subkey).unwrap();
        let error = unexpected_isolation
            .finish(CertificationProfileLaunchExpectation::NoEngineExpected)
            .unwrap_err();
        assert!(error.contains("unexpectedly created"), "got: {error}");
        assert!(!certified_profile_registry_key_exists(&unexpected_engine).unwrap());
        assert!(certified_profile_registry_key_exists(&sibling).unwrap());

        let unwind_owned = CertifiedArgProfileRoot {
            hkcu_subkey: format!("{profiles}\\unwind-owned"),
        };
        let unwind_result = std::panic::catch_unwind({
            let unwind_owned = unwind_owned.clone();
            move || {
                let _isolation =
                    CertifiedArgProfileIsolation::acquire_root(unwind_owned.clone()).unwrap();
                create_registry_test_key(&format!("{}\\Nested", unwind_owned.hkcu_subkey)).unwrap();
                panic!("exercise certified profile registry unwind cleanup");
            }
        });
        assert!(unwind_result.is_err());
        assert!(!certified_profile_registry_key_exists(&unwind_owned).unwrap());
        assert!(certified_profile_registry_key_exists(&sibling).unwrap());

        let preexisting = CertifiedArgProfileRoot {
            hkcu_subkey: format!("{profiles}\\preexisting"),
        };
        create_registry_test_key(&preexisting.hkcu_subkey).unwrap();
        let error = CertifiedArgProfileIsolation::acquire_root(preexisting.clone()).unwrap_err();
        assert!(error.contains("already exists"), "got: {error}");
        assert!(certified_profile_registry_key_exists(&preexisting).unwrap());
    }

    #[test]
    fn fixture_staging_is_relative_digest_bound_and_non_symlinked() {
        let directory = tempfile::tempdir().unwrap();
        let fixture_root = directory.path().join("private-fixtures");
        let staging_root = directory.path().join("evidence/run");
        let source = fixture_root.join("hosts/nested/title.dwg");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::create_dir_all(staging_root.parent().unwrap()).unwrap();
        std::fs::write(&source, b"AC1032-private-fixture").unwrap();
        let digest = xref_sha256_file(&source).unwrap();
        let staging_root = create_fresh_certification_case_root(&staging_root).unwrap();

        let staged = stage_certification_file(
            &fixture_root,
            "hosts/nested/title.dwg",
            &digest,
            staging_root.as_path(),
        )
        .unwrap();
        assert_eq!(
            staged.staged_path,
            staging_root.join("hosts/nested/title.dwg")
        );
        assert_eq!(staged.sha256, digest);
        assert_eq!(
            std::fs::read(staged.staged_path).unwrap(),
            b"AC1032-private-fixture"
        );
        let error = stage_certification_file(
            &fixture_root,
            "hosts/nested/title.dwg",
            &digest,
            staging_root.as_path(),
        )
        .unwrap_err();
        assert!(
            error.contains("refusing to overwrite staged certification fixture"),
            "got: {error}"
        );

        let error = stage_certification_file(
            &fixture_root,
            "../outside.dwg",
            &digest,
            staging_root.as_path(),
        )
        .unwrap_err();
        assert!(error.contains("stay beneath fixture_root"), "got: {error}");

        let error = stage_certification_file(
            &fixture_root,
            "hosts/nested/title.dwg",
            &"0".repeat(64),
            staging_root.as_path(),
        )
        .unwrap_err();
        assert!(error.contains("does not match manifest"), "got: {error}");
    }

    #[test]
    #[cfg(not(windows))]
    fn exact_runtime_file_binding_detects_substitution() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("autocad-mcp.exe");
        std::fs::write(&binary, b"release-binary-one").unwrap();
        let digest = xref_sha256_file(&binary).unwrap();
        let binding =
            bind_exact_certification_file(binary.to_str().unwrap(), &digest, "release binary")
                .unwrap();
        assert_eq!(
            verify_exact_certification_file_unchanged(&binding, "release binary").unwrap(),
            digest
        );

        std::fs::write(&binary, b"release-binary-two").unwrap();
        let error =
            verify_exact_certification_file_unchanged(&binding, "release binary").unwrap_err();
        assert!(
            error.contains("changed during certification"),
            "got: {error}"
        );
    }

    #[test]
    #[cfg(windows)]
    fn exact_runtime_file_binding_denies_windows_write_delete_and_ancestor_rename() {
        let current_exe = std::env::current_exe().unwrap();
        let current_exe_digest = xref_sha256_file(&current_exe).unwrap();
        let executable_binding = bind_exact_certification_file(
            current_exe.to_str().unwrap(),
            &current_exe_digest,
            "certification test executable",
        )
        .unwrap();
        let output = Command::new(&executable_binding.canonical_path)
            .arg("--list")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Windows must permit CreateProcess while the exact executable guard is retained: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            verify_exact_certification_file_unchanged(
                &executable_binding,
                "certification test executable"
            )
            .unwrap(),
            current_exe_digest
        );
        drop(executable_binding);

        let directory = tempfile::tempdir().unwrap();
        let ancestor = directory.path().join("runtime");
        let parent = ancestor.join("bin");
        let renamed_parent = ancestor.join("renamed-bin");
        let renamed_ancestor = directory.path().join("renamed-runtime");
        std::fs::create_dir(&parent).unwrap();
        let binary = parent.join("autocad-mcp.exe");
        std::fs::write(&binary, b"release-binary-one").unwrap();
        let digest = xref_sha256_file(&binary).unwrap();
        let binding =
            bind_exact_certification_file(binary.to_str().unwrap(), &digest, "release binary")
                .unwrap();

        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&binary)
                .is_err(),
            "the retained exact-file guard must deny write opens"
        );
        assert!(
            std::fs::remove_file(&binary).is_err(),
            "the retained exact-file guard must deny deletion"
        );
        assert!(
            std::fs::rename(&parent, &renamed_parent).is_err(),
            "the retained immediate-directory guard must deny namespace relocation"
        );
        assert!(
            std::fs::rename(&ancestor, &renamed_ancestor).is_err(),
            "the retained ancestor chain must deny subtree relocation"
        );
        assert_eq!(
            verify_exact_certification_file_unchanged(&binding, "release binary").unwrap(),
            digest
        );

        drop(binding);
        std::fs::rename(&ancestor, &renamed_ancestor).unwrap();
        std::fs::write(
            renamed_ancestor.join("bin").join("autocad-mcp.exe"),
            b"replacement",
        )
        .unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn exact_runtime_file_binding_rejects_same_byte_symlink_substitution() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let configured = directory.path().join("autocad-mcp.exe");
        let substitute = directory.path().join("same-bytes.exe");
        std::fs::write(&configured, b"identical-release-bytes").unwrap();
        std::fs::write(&substitute, b"identical-release-bytes").unwrap();
        let digest = xref_sha256_file(&configured).unwrap();
        let binding =
            bind_exact_certification_file(configured.to_str().unwrap(), &digest, "release binary")
                .unwrap();

        std::fs::remove_file(&configured).unwrap();
        symlink(&substitute, &configured).unwrap();
        let error =
            verify_exact_certification_file_unchanged(&binding, "release binary").unwrap_err();
        assert!(error.contains("non-symlink"), "got: {error}");
    }

    fn title_block(revision: &str, sheet: &str) -> autocad_mcp::ops::title_blocks::TitleBlockInfo {
        autocad_mcp::ops::title_blocks::TitleBlockInfo {
            block_name: "AUTOCAD_MCP_GENERIC".to_string(),
            layer: "TITLE".to_string(),
            attributes: [
                ("REVISION", revision),
                ("DRAWING_NUMBER", "A-001"),
                ("REFERENCE", "REF"),
                ("TITLE_LINE_1", "SYNTHETIC"),
                ("TITLE_LINE_2", "FIXTURE"),
                ("SHEET_NUMBER", sheet),
                ("SHEET_COUNT", "10"),
            ]
            .into_iter()
            .map(|(tag, value)| (tag.to_string(), value.to_string()))
            .collect(),
            attribute_arrays: std::collections::HashMap::new(),
        }
    }

    fn title_observation(
        block: autocad_mcp::ops::title_blocks::TitleBlockInfo,
    ) -> TitleBlockObservation {
        title_observation_many(vec![block])
    }

    fn title_observation_many(
        blocks: Vec<autocad_mcp::ops::title_blocks::TitleBlockInfo>,
    ) -> TitleBlockObservation {
        let stdout = serde_json::to_string(&blocks).unwrap();
        observe_title_blocks(&stdout).unwrap()
    }

    #[test]
    fn title_block_readback_proves_requested_and_unchanged_values() {
        let before = title_observation(title_block("P01", "1"));
        let after = title_observation(title_block("P02", "1"));
        let fields = BTreeMap::from([("revision".to_string(), "P02".to_string())]);
        let (verified, unchanged) =
            verify_title_block_readback(&before, &after, "AUTOCAD_MCP_GENERIC", &fields).unwrap();
        assert_eq!(verified, vec!["revision"]);
        assert!(unchanged.contains(&"SHEET_NUMBER".to_string()));

        let altered = title_observation(title_block("P02", "2"));
        let error = verify_title_block_readback(&before, &altered, "AUTOCAD_MCP_GENERIC", &fields)
            .unwrap_err();
        assert!(error.contains("unrequested fields"), "got: {error}");

        let no_op = title_observation(title_block("P02", "1"));
        let error = verify_title_block_readback(&no_op, &no_op, "AUTOCAD_MCP_GENERIC", &fields)
            .unwrap_err();
        assert!(error.contains("was a no-op"), "got: {error}");
    }

    #[test]
    fn title_block_readback_is_order_independent_and_preserves_duplicate_counts() {
        let before = title_observation_many(vec![title_block("P01", "1"), title_block("P03", "2")]);
        let reordered_before =
            title_observation_many(vec![title_block("P03", "2"), title_block("P01", "1")]);
        assert_eq!(before.snapshot_sha256, reordered_before.snapshot_sha256);

        let after = title_observation_many(vec![title_block("P02", "2"), title_block("P02", "1")]);
        let fields = BTreeMap::from([("revision".to_string(), "P02".to_string())]);
        verify_title_block_readback(&before, &after, "AUTOCAD_MCP_GENERIC", &fields).unwrap();

        let missing_duplicate = title_observation_many(vec![title_block("P02", "1")]);
        let error = verify_title_block_readback(
            &before,
            &missing_duplicate,
            "AUTOCAD_MCP_GENERIC",
            &fields,
        )
        .unwrap_err();
        assert!(error.contains("inventory changed"), "got: {error}");

        let wrong_duplicate_multiset =
            title_observation_many(vec![title_block("P02", "1"), title_block("P02", "1")]);
        let error = verify_title_block_readback(
            &before,
            &wrong_duplicate_multiset,
            "AUTOCAD_MCP_GENERIC",
            &fields,
        )
        .unwrap_err();
        assert!(error.contains("duplicate counts"), "got: {error}");
    }

    #[test]
    fn title_block_readback_rejects_canonical_fields_that_collapse_to_one_tag() {
        let before = title_observation(title_block("P01", "1"));
        let after = title_observation(title_block("P02", "1"));
        let fields = BTreeMap::from([
            ("REVISION".to_string(), "P02".to_string()),
            ("revision".to_string(), "P02".to_string()),
        ]);
        let error = verify_title_block_readback(&before, &after, "AUTOCAD_MCP_GENERIC", &fields)
            .unwrap_err();
        assert!(error.contains("duplicate profile tags"), "got: {error}");
    }

    #[test]
    fn plotted_pdf_requires_header_eof_and_records_exact_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let pdf = directory.path().join("drawing.pdf");
        std::fs::write(&pdf, b"%PDF-1.7\nfixture\n%%EOF\n").unwrap();
        let observation = observe_pdf(&pdf).unwrap();
        assert_eq!(observation.size, 23);
        assert_eq!(observation.sha256, xref_sha256_file(&pdf).unwrap());

        std::fs::write(&pdf, b"not a PDF").unwrap();
        let error = observe_pdf(&pdf).unwrap_err();
        assert!(error.contains("PDF header"), "got: {error}");
    }

    #[test]
    fn plotted_pdf_rejects_pathname_bytes_that_do_not_match_opened_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let pdf = directory.path().join("drawing.pdf");
        let opened_bytes = b"%PDF-1.7\nopened\n%%EOF\n";
        std::fs::write(&pdf, opened_bytes).unwrap();
        let canonical = pdf.canonicalize().unwrap();
        let opened_sha256 = xref_sha256_bytes(opened_bytes);

        std::fs::write(&pdf, b"%PDF-1.7\nreplacement\n%%EOF\n").unwrap();
        let error =
            verify_pdf_path_matches_opened_bytes(&pdf, &canonical, &opened_sha256).unwrap_err();
        assert!(error.contains("pathname bytes changed"), "got: {error}");
    }

    #[test]
    #[cfg(unix)]
    fn plotted_pdf_rejects_atomic_pathname_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let pdf = directory.path().join("drawing.pdf");
        let replacement = directory.path().join("replacement.pdf");
        let opened_bytes = b"%PDF-1.7\nopened\n%%EOF\n";
        std::fs::write(&pdf, opened_bytes).unwrap();
        std::fs::write(&replacement, b"%PDF-1.7\nreplacement\n%%EOF\n").unwrap();
        let canonical = pdf.canonicalize().unwrap();
        let opened_sha256 = xref_sha256_bytes(opened_bytes);

        std::fs::rename(&replacement, &pdf).unwrap();
        let error =
            verify_pdf_path_matches_opened_bytes(&pdf, &canonical, &opened_sha256).unwrap_err();
        assert!(error.contains("pathname bytes changed"), "got: {error}");
    }

    #[test]
    fn certification_children_are_pinned_to_exact_binary_engine_and_arg() {
        let runtime = CertificationCommandRuntime {
            release_binary: PathBuf::from("C:/cert/autocad-mcp.exe"),
            accoreconsole: PathBuf::from(
                "C:/Program Files/Autodesk/AutoCAD 2026/accoreconsole.exe",
            ),
            certified_arg: PathBuf::from("C:/cert/autocad-mcp.arg"),
            certified_arg_sha256: "a".repeat(64),
        };
        let command = certification_tool_command(&runtime, "list_layouts", &serde_json::json!({}));
        assert_eq!(command.get_program(), runtime.release_binary.as_os_str());
        let environment = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            environment["AUTOCAD_MCP_ACCORECONSOLE_PATH"].as_deref(),
            Some(runtime.accoreconsole.to_string_lossy().as_ref())
        );
        assert_eq!(
            environment["AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH"].as_deref(),
            Some(runtime.certified_arg.to_string_lossy().as_ref())
        );
        assert_eq!(environment["AUTOCAD_MCP_XREF_FAILPOINT"], None);
    }

    #[test]
    fn layer_failure_codes_are_observed_from_the_child_error_channel() {
        assert_eq!(
            certification_error_code_text(
                "",
                "update_layer failed: code=line_type_not_found missing linetype"
            )
            .as_deref(),
            Some("line_type_not_found")
        );
        assert_eq!(
            certification_error_code_text("", "unstructured failure"),
            None
        );
        assert_eq!(
            certification_error_code_text("code=fake_stdout_code", "unstructured failure"),
            None
        );
        assert_eq!(
            certification_error_code_text(
                "",
                "first failure code=line_type_not_found second code=invalid_line_weight"
            ),
            None
        );
        assert_eq!(
            certification_error_code_text("", "code= code=line_type_not_found"),
            None
        );
    }

    #[test]
    fn certification_diagnostics_do_not_publish_child_payloads() {
        let secret = "never-publish-this-private-value";
        let malformed = format!(r#"{{"private":"{secret}","#);
        let error = parse_certification_json("redaction_probe", &malformed).unwrap_err();
        assert!(!error.contains(secret), "got: {error}");
        assert!(error.contains("output_bytes="), "got: {error}");
        assert!(error.contains("output_sha256="), "got: {error}");

        let redacted =
            redacted_certification_failure("test_failure", &format!("private detail {secret}"));
        assert!(!redacted.contains(secret), "got: {redacted}");
        assert!(redacted.contains("detail_sha256="), "got: {redacted}");
    }

    #[test]
    fn title_and_layout_reads_reject_open_records_without_leaking_values() {
        let secret = "never-publish-this-private-value";
        let title = serde_json::json!([{
            "block_name": "TITLE",
            "layer": "SHEET",
            "attributes": {"DRAWING_NUMBER": secret},
            "private_payload": secret,
        }])
        .to_string();
        let title_error = observe_title_blocks(&title).unwrap_err();
        assert!(!title_error.contains(secret), "got: {title_error}");
        assert!(
            !title_error.contains("private_payload"),
            "got: {title_error}"
        );

        let layouts = serde_json::json!([
            {
                "name": secret,
                "is_model": false,
                "tab_order": 1,
                "paper_width_mm": 1.0,
                "paper_height_mm": 1.0,
            },
            {
                "name": secret,
                "is_model": false,
                "tab_order": 2,
                "paper_width_mm": 1.0,
                "paper_height_mm": 1.0,
            }
        ])
        .to_string();
        let layout_error = observe_layout_names(&layouts).unwrap_err();
        assert!(!layout_error.contains(secret), "got: {layout_error}");
    }

    #[test]
    fn write_and_plot_responses_are_exact_closed_envelopes() {
        let drawing = "C:/cert/cases/host.dwg";
        let write = serde_json::json!({
            "status": "ok",
            "drawing": drawing,
            "profile_id": "profile",
            "fields_written": 2,
            "target_inserts": 1,
            "attributes_written": 2,
        });
        verify_write_output(&write.to_string(), drawing, "profile", 2).unwrap();
        let mut open_write = write;
        open_write
            .as_object_mut()
            .unwrap()
            .insert("private_payload".to_string(), serde_json::json!("secret"));
        let error =
            verify_write_output(&open_write.to_string(), drawing, "profile", 2).unwrap_err();
        assert!(!error.contains("private_payload"), "got: {error}");
        assert!(!error.contains("secret"), "got: {error}");

        let plot = serde_json::json!({
            "status": "ok",
            "drawing": drawing,
            "layout": "Layout1",
            "output": "C:/cert/cases/plot.pdf",
        });
        verify_plot_output(
            &plot.to_string(),
            drawing,
            "Layout1",
            "C:/cert/cases/plot.pdf",
        )
        .unwrap();
        let mut open_plot = plot;
        open_plot
            .as_object_mut()
            .unwrap()
            .insert("private_payload".to_string(), serde_json::json!("secret"));
        let error = verify_plot_output(
            &open_plot.to_string(),
            drawing,
            "Layout1",
            "C:/cert/cases/plot.pdf",
        )
        .unwrap_err();
        assert!(!error.contains("private_payload"), "got: {error}");
        assert!(!error.contains("secret"), "got: {error}");
    }

    #[test]
    fn layer_confinement_cache_reuses_only_an_exact_digest_key() {
        let key = |host: char, sources: &[(&str, char)]| {
            let mut sources = sources
                .iter()
                .map(|(manifest_path, digest)| CertificationLayerStateSource {
                    manifest_path: (*manifest_path).to_string(),
                    sha256: digest.to_string().repeat(64),
                })
                .collect::<Vec<_>>();
            sources.sort_by(|left, right| left.manifest_path.cmp(&right.manifest_path));
            let staged_host_sha256 = host.to_string().repeat(64);
            let state_key_sha256 =
                certification_layer_state_key_sha256(&staged_host_sha256, &sources);
            LayerConfinementKey {
                staged_host_sha256,
                sources,
                state_key_sha256,
            }
        };
        let baseline = key('a', &[("refs/a.dwg", 'b'), ("refs/b.dwg", 'c')]);
        assert_eq!(
            layer_confinement_cache_action(Some(&baseline), &baseline),
            LayerConfinementCacheAction::Reuse
        );

        let changed_host = key('d', &[("refs/a.dwg", 'b'), ("refs/b.dwg", 'c')]);
        assert_eq!(
            layer_confinement_cache_action(Some(&baseline), &changed_host),
            LayerConfinementCacheAction::Refresh
        );

        let changed_reference = key('a', &[("refs/a.dwg", 'b'), ("refs/b.dwg", 'e')]);
        assert_eq!(
            layer_confinement_cache_action(Some(&baseline), &changed_reference),
            LayerConfinementCacheAction::Refresh
        );
        let changed_reference_path = key('a', &[("refs/a.dwg", 'b'), ("refs/c.dwg", 'c')]);
        assert_eq!(
            layer_confinement_cache_action(Some(&baseline), &changed_reference_path),
            LayerConfinementCacheAction::Refresh
        );
        assert_eq!(
            layer_confinement_cache_action(None, &baseline),
            LayerConfinementCacheAction::Refresh
        );
    }

    #[test]
    fn bounded_certification_runner_enforces_a_portable_deadline() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--ignored",
            "--exact",
            "certification_harness_tests::bounded_certification_runner_sleep_child",
        ]);
        let error = run_command_bounded(command, Duration::from_millis(50)).unwrap_err();
        assert!(error.contains("timed out"), "got: {error}");
    }

    #[test]
    #[ignore]
    fn bounded_certification_runner_sleep_child() {
        thread::sleep(Duration::from_secs(5));
    }

    #[cfg(windows)]
    #[test]
    fn bounded_certification_runner_terminates_the_windows_process_tree() {
        let directory = tempfile::tempdir().unwrap();
        let script_path = directory.path().join("spawn-descendant.ps1");
        let pid_path = directory.path().join("process-ids.txt");
        std::fs::write(
            &script_path,
            r#"param([string]$PidPath)
$descendant = Start-Process -FilePath $env:ComSpec -ArgumentList @('/d', '/c', 'ping -n 120 127.0.0.1 >NUL') -PassThru
Set-Content -LiteralPath $PidPath -Value @($PID, $descendant.Id) -Encoding ascii
Start-Sleep -Seconds 120
"#,
        )
        .unwrap();

        let mut command = Command::new("powershell.exe");
        command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&script_path)
            .arg("-PidPath")
            .arg(&pid_path);
        let error = run_command_bounded(command, Duration::from_secs(5)).unwrap_err();
        assert!(error.contains("timed out"), "got: {error}");

        let process_ids = std::fs::read_to_string(&pid_path)
            .unwrap_or_else(|read_error| {
                panic!(
                    "PowerShell did not record its process tree at {}: {read_error}; runner error: {error}",
                    pid_path.display()
                )
            })
            .lines()
            .map(|line| line.trim().parse::<u32>().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            process_ids.len(),
            2,
            "expected parent and descendant process IDs"
        );
        assert_ne!(
            process_ids[0], process_ids[1],
            "parent and descendant IDs must differ"
        );
        for process_id in process_ids {
            wait_for_windows_process_exit(process_id, Duration::from_secs(5)).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn bounded_certification_runner_rejects_a_successful_parent_with_a_live_descendant() {
        let directory = tempfile::tempdir().unwrap();
        let script_path = directory.path().join("leave-descendant.ps1");
        let pid_path = directory.path().join("process-ids.txt");
        std::fs::write(
            &script_path,
            r#"param([string]$PidPath)
$descendant = Start-Process -FilePath $env:ComSpec -ArgumentList @('/d', '/c', 'ping -n 120 127.0.0.1 >NUL') -PassThru
Set-Content -LiteralPath $PidPath -Value @($PID, $descendant.Id) -Encoding ascii
exit 0
"#,
        )
        .unwrap();

        let mut command = Command::new("powershell.exe");
        command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&script_path)
            .arg("-PidPath")
            .arg(&pid_path);
        let error = run_command_bounded(command, Duration::from_secs(5)).unwrap_err();
        assert!(
            error.contains("CLI exited while"),
            "runner did not reject the surviving descendant: {error}"
        );

        let process_ids = std::fs::read_to_string(&pid_path)
            .unwrap_or_else(|read_error| {
                panic!(
                    "PowerShell did not record its process tree at {}: {read_error}; runner error: {error}",
                    pid_path.display()
                )
            })
            .lines()
            .map(|line| line.trim().parse::<u32>().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            process_ids.len(),
            2,
            "expected parent and descendant process IDs"
        );
        for process_id in process_ids {
            wait_for_windows_process_exit(process_id, Duration::from_secs(5)).unwrap();
        }
    }

    #[test]
    fn expanded_layer_record_witness_requires_the_exact_seventeen_fields() {
        let record = serde_json::json!({
            "handle": "2A",
            "name": "ANNO",
            "color_index": 7,
            "line_type": "Continuous",
            "line_weight": {"kind": "default"},
            "frozen": false,
            "locked": false,
            "off": false,
            "is_plottable": true,
            "xref_dependent": false,
            "xref_block_record_handle": null,
            "xref_name": null,
            "xref_path": null,
            "xref_is_overlay": null,
            "material_handle": null,
            "plotstyle_handle": null,
            "is_current": false
        });
        verify_expanded_layer_records(&serde_json::json!([record.clone()])).unwrap();

        let mut incomplete = record;
        incomplete
            .as_object_mut()
            .unwrap()
            .remove("plotstyle_handle");
        let error = verify_expanded_layer_records(&serde_json::json!([incomplete])).unwrap_err();
        assert!(error.contains("expected"), "got: {error}");
    }

    #[test]
    fn evidence_publication_is_complete_and_never_overwrites() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.json");
        let value = serde_json::json!({"status": "passed"});
        write_certification_json(&path, &value).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(parsed, value);

        let error =
            write_certification_json(&path, &serde_json::json!({"status": "failed"})).unwrap_err();
        assert!(error.contains("refusing to overwrite"), "got: {error}");
        let persisted: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(persisted, value);
    }

    #[test]
    fn certification_output_must_not_overlap_private_fixtures() {
        let directory = tempfile::tempdir().unwrap();
        let fixtures = directory.path().join("fixtures");
        let output = directory.path().join("evidence");
        std::fs::create_dir_all(&fixtures).unwrap();
        std::fs::create_dir_all(&output).unwrap();
        let prepared = prepare_certification_output_dir(&output, &fixtures).unwrap();
        assert_eq!(prepared, output);

        let nested = fixtures.join("generated");
        std::fs::create_dir_all(&nested).unwrap();
        let error = prepare_certification_output_dir(&nested, &fixtures).unwrap_err();
        assert!(error.contains("must not overlap"), "got: {error}");
    }
}
