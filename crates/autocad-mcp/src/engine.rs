use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

use crate::{
    activation::SelectedActivation,
    ops::xref_runtime::{
        certified_arg_sha256_build_value, XREF_CERTIFIED_ARG_PATH_ENV,
        XREF_CERTIFIED_ARG_SHA256_BUILD_ENV,
    },
};

pub const ACCORECONSOLE_PATH_ENV: &str = "AUTOCAD_MCP_ACCORECONSOLE_PATH";
const STAGED_CERTIFIED_PROFILE_FILE_NAME: &str = "certified-profile.arg";
#[cfg(target_os = "windows")]
const WINDOWS_FILE_SHARE_READ: u32 = 0x0000_0001;
#[cfg(target_os = "windows")]
const WINDOWS_FILE_SHARE_WRITE: u32 = 0x0000_0002;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AutocadEngineIdentity {
    pub executable: PathBuf,
    pub product: String,
    pub version: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct AccoreconsoleExecutableObservation {
    pub canonical_executable: PathBuf,
    pub architecture: &'static str,
    pub file_version: Option<String>,
    pub identity_token: String,
}

/// Owned Windows lease that keeps the exact executable bytes and immediate
/// parent namespace stable while `CreateProcess` resolves the selected path.
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(crate) struct AccoreconsoleExecutableLaunchLease {
    observation: AccoreconsoleExecutableObservation,
    _file_guard: File,
    _parent_guard: File,
}

#[cfg(target_os = "windows")]
impl AccoreconsoleExecutableLaunchLease {
    pub(crate) fn observation(&self) -> &AccoreconsoleExecutableObservation {
        &self.observation
    }
}

#[derive(Debug)]
pub(crate) struct StagedCertifiedProfile {
    path: PathBuf,
    xref_registry_binding: Option<crate::certified_arg::CertifiedArgProfileBinding>,
    xref_profile_token: Option<String>,
    // On Windows this handle has GENERIC_READ and FILE_SHARE_READ. Its granted
    // read access makes the share mask effective: compatible readers remain
    // possible while write/delete access is denied until the child exits. The
    // handle is reached through an identity-bound ReOpenFile transition and is
    // proved again after the final sharing mode is installed. Non-Windows
    // builds retain the create-new handle for the same lifetime structure; no
    // cross-process locking property is claimed there.
    _guard: File,
    // Windows also retains the staging-directory handle without
    // FILE_SHARE_DELETE, preventing the immediate parent from being renamed or
    // deleted while AutoCAD resolves the ordinary DOS/UNC `/p` path.
    #[cfg(target_os = "windows")]
    _parent_guard: File,
}

impl StagedCertifiedProfile {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// Create a temporary staging directory for accoreconsole operations.
///
/// The returned `TempDir` cleans itself up on drop. Callers that need the
/// directory to outlive the call must call `.into_path()` and manage cleanup
/// themselves.
pub fn create_staging_dir() -> Result<tempfile::TempDir> {
    Ok(tempfile::Builder::new().prefix("autocad-mcp-").tempdir()?)
}

/// Locate the accoreconsole executable.
///
/// Search order:
///   1. Exact `AUTOCAD_MCP_ACCORECONSOLE_PATH` override
///   2. `PATH` environment variable
///   3. Standard Autodesk install locations under `%ProgramFiles%` (Windows only)
///
/// Returns `Err` on non-Windows platforms — accoreconsole is a Windows binary.
pub fn find_accoreconsole() -> Result<PathBuf> {
    let explicit =
        resolve_accoreconsole_override(std::env::var_os(ACCORECONSOLE_PATH_ENV).as_deref())?;

    #[cfg(target_os = "windows")]
    {
        if let Some(path) = explicit {
            return Ok(path);
        }
        // 2. PATH lookup
        if let Ok(path) = which_accoreconsole_in_path() {
            return Ok(path);
        }
        // 3. Autodesk install dirs under %ProgramFiles%
        search_autodesk_install_dirs()
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = explicit;
        Err(anyhow!(
            "accoreconsole is a Windows-only binary; cannot locate it on this platform"
        ))
    }
}

/// Resolves an exact accoreconsole override without reading process state.
///
/// `None` preserves ordinary discovery. A present but defective value is an
/// error and must never fall through to `PATH` or install-directory discovery.
pub fn resolve_accoreconsole_override(value: Option<&OsStr>) -> Result<Option<PathBuf>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(anyhow!(
            "{ACCORECONSOLE_PATH_ENV} must be an absolute path: {}",
            path.display()
        ));
    }
    canonical_accoreconsole_path(path, ACCORECONSOLE_PATH_ENV).map(Some)
}

/// Resolves the optional certified AutoCAD profile used by legacy engine calls
/// without reading process state.
///
/// A present but defective value is an error. The returned path is canonical
/// and names a regular `.arg` file.
pub fn resolve_certified_profile_override(value: Option<&OsStr>) -> Result<Option<PathBuf>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(anyhow!(
            "{XREF_CERTIFIED_ARG_PATH_ENV} must be an absolute path: {}",
            path.display()
        ));
    }
    if !has_arg_extension(path) {
        return Err(anyhow!(
            "{XREF_CERTIFIED_ARG_PATH_ENV} must name an exported .arg file: {}",
            path.display()
        ));
    }
    let canonical = canonical_regular_file(path, XREF_CERTIFIED_ARG_PATH_ENV)?;
    if !has_arg_extension(&canonical) {
        return Err(anyhow!(
            "{XREF_CERTIFIED_ARG_PATH_ENV} canonical target must name an exported .arg file: {}",
            canonical.display()
        ));
    }
    Ok(Some(canonical))
}

/// Identifies the selected AutoCAD engine from its canonical path without
/// launching AutoCAD.
///
/// The version is derived from an AutoCAD-labelled component of the canonical
/// executable path. This is a path-shape assertion, not independent proof of
/// an Autodesk installation, PE version resource, or code signature.
pub fn detect_accoreconsole_identity() -> Result<AutocadEngineIdentity> {
    identify_accoreconsole(find_accoreconsole()?)
}

pub fn identify_accoreconsole(executable: PathBuf) -> Result<AutocadEngineIdentity> {
    let executable = canonical_accoreconsole_path(&executable, "AutoCAD engine path")?;
    let version = autocad_version_from_path(&executable).ok_or_else(|| {
        anyhow!(
            "cannot identify AutoCAD version without launching engine: {}",
            executable.display()
        )
    })?;
    Ok(AutocadEngineIdentity {
        executable,
        product: "autocad".to_string(),
        version,
    })
}

fn canonical_accoreconsole_path(path: &Path, label: &str) -> Result<PathBuf> {
    if !has_accoreconsole_file_name(path) {
        return Err(anyhow!(
            "{label} does not name accoreconsole(.exe): {}",
            path.display()
        ));
    }
    let canonical = canonical_regular_file(path, label)?;
    if !has_accoreconsole_file_name(&canonical) {
        return Err(anyhow!(
            "{label} canonical target does not name accoreconsole(.exe): {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn canonical_regular_file(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| anyhow!("{label} is not accessible at {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!(
            "{label} must name a regular file: {}",
            path.display()
        ));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| anyhow!("canonicalize {label} {}: {error}", path.display()))?;
    let canonical_metadata = std::fs::metadata(&canonical).map_err(|error| {
        anyhow!(
            "{label} canonical target is not accessible at {}: {error}",
            canonical.display()
        )
    })?;
    if !canonical_metadata.is_file() {
        return Err(anyhow!(
            "{label} canonical target must be a regular file: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

/// Observe one exact Core Console executable without launching it.
///
/// The token is an operational replacement detector, not a signature or
/// support qualification. On Windows it binds the volume/file identity plus
/// cheap metadata and the PE machine type; Release qualification remains
/// responsible for publisher and digest authority.
pub(crate) fn observe_accoreconsole_executable(
    path: &Path,
) -> Result<AccoreconsoleExecutableObservation> {
    #[cfg(target_os = "windows")]
    {
        return acquire_accoreconsole_executable_launch_lease(path).map(|lease| lease.observation);
    }

    #[cfg(not(target_os = "windows"))]
    {
        observe_accoreconsole_executable_portable(path)
    }
}

#[cfg(not(target_os = "windows"))]
fn observe_accoreconsole_executable_portable(
    path: &Path,
) -> Result<AccoreconsoleExecutableObservation> {
    if std::fs::symlink_metadata(path)
        .map_err(|error| anyhow!("inspect AutoCAD engine path {}: {error}", path.display()))?
        .file_type()
        .is_symlink()
    {
        return Err(anyhow!(
            "AutoCAD engine path must not be a symbolic link: {}",
            path.display()
        ));
    }
    let canonical = canonical_accoreconsole_path(path, "AutoCAD engine path")?;
    let mut file = File::open(&canonical).map_err(|error| {
        anyhow!(
            "open AutoCAD engine executable {}: {error}",
            canonical.display()
        )
    })?;
    let machine = read_pe_machine(&mut file)?;
    if machine != 0x8664 {
        return Err(anyhow!(
            "AutoCAD engine executable is not Windows x86-64 PE (machine=0x{machine:04x}): {}",
            canonical.display()
        ));
    }
    let metadata = file.metadata().map_err(|error| {
        anyhow!(
            "inspect AutoCAD engine executable {}: {error}",
            canonical.display()
        )
    })?;
    let modified = metadata
        .modified()
        .map_err(|error| anyhow!("inspect AutoCAD engine modification time: {error}"))?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| anyhow!("AutoCAD engine modification time predates Unix epoch: {error}"))?
        .as_nanos();
    let identity_token = format!(
        "portable-file-observation:{};len={};modified_ns={modified};machine=8664",
        canonical.display(),
        metadata.len()
    );

    Ok(AccoreconsoleExecutableObservation {
        canonical_executable: canonical,
        architecture: "x86_64",
        file_version: None,
        identity_token,
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn acquire_accoreconsole_executable_launch_lease(
    path: &Path,
) -> Result<AccoreconsoleExecutableLaunchLease> {
    let (canonical, mut file_guard, parent_guard) = windows_guard_accoreconsole_executable(path)?;
    let machine = read_pe_machine(&mut file_guard)?;
    if machine != 0x8664 {
        return Err(anyhow!(
            "AutoCAD engine executable is not Windows x86-64 PE (machine=0x{machine:04x}): {}",
            canonical.display()
        ));
    }
    let metadata = file_guard.metadata().map_err(|error| {
        anyhow!(
            "inspect AutoCAD engine executable {}: {error}",
            canonical.display()
        )
    })?;
    let modified = metadata
        .modified()
        .map_err(|error| anyhow!("inspect AutoCAD engine modification time: {error}"))?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| anyhow!("AutoCAD engine modification time predates Unix epoch: {error}"))?
        .as_nanos();
    let identity = windows_file_identity(&file_guard, "AutoCAD engine executable")?;

    // GetFileVersionInfoW is path-based. The share-read-only file handle and
    // no-delete parent guard remain alive across this call, so these bytes and
    // the path cannot be replaced between PE, identity, and version reads.
    let file_version = windows_fixed_file_version(&canonical)?;
    let identity_token = format!(
        "windows-file-id:{:016x}:{};len={};modified_ns={modified};machine=8664;file_version={file_version}",
        identity.volume_serial_number,
        identity
            .file_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        metadata.len()
    );
    Ok(AccoreconsoleExecutableLaunchLease {
        observation: AccoreconsoleExecutableObservation {
            canonical_executable: canonical,
            architecture: "x86_64",
            file_version: Some(file_version),
            identity_token,
        },
        _file_guard: file_guard,
        _parent_guard: parent_guard,
    })
}

#[cfg(target_os = "windows")]
fn windows_fixed_file_version(path: &Path) -> Result<String> {
    use std::os::windows::ffi::OsStrExt;
    use std::{ffi::c_void, mem::size_of, ptr::null_mut};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
    };

    let path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut ignored = 0_u32;
    let byte_len = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), &mut ignored) };
    if byte_len == 0 {
        return Err(anyhow!(
            "AutoCAD engine has no readable fixed file-version resource: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut bytes = vec![0_u8; byte_len as usize];
    if unsafe {
        GetFileVersionInfoW(
            path.as_ptr(),
            0,
            byte_len,
            bytes.as_mut_ptr().cast::<c_void>(),
        )
    } == 0
    {
        return Err(anyhow!(
            "read AutoCAD engine file-version resource: {}",
            std::io::Error::last_os_error()
        ));
    }
    let root = ['\\' as u16, 0];
    let mut fixed_ptr = null_mut::<c_void>();
    let mut fixed_len = 0_u32;
    if unsafe {
        VerQueryValueW(
            bytes.as_ptr().cast::<c_void>(),
            root.as_ptr(),
            &mut fixed_ptr,
            &mut fixed_len,
        )
    } == 0
        || fixed_ptr.is_null()
        || fixed_len < size_of::<VS_FIXEDFILEINFO>() as u32
    {
        return Err(anyhow!(
            "AutoCAD engine has no complete fixed file-version resource"
        ));
    }
    let fixed = unsafe { &*fixed_ptr.cast::<VS_FIXEDFILEINFO>() };
    if fixed.dwSignature != 0xFEEF_04BD {
        return Err(anyhow!(
            "AutoCAD engine fixed file-version resource has invalid signature 0x{:08x}",
            fixed.dwSignature
        ));
    }
    Ok(format!(
        "{}.{}.{}.{}",
        fixed.dwFileVersionMS >> 16,
        fixed.dwFileVersionMS & 0xffff,
        fixed.dwFileVersionLS >> 16,
        fixed.dwFileVersionLS & 0xffff
    ))
}

fn read_pe_machine(file: &mut File) -> Result<u16> {
    let mut dos_header = [0_u8; 64];
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_exact(&mut dos_header))
        .map_err(|error| anyhow!("read AutoCAD engine DOS header: {error}"))?;
    if &dos_header[..2] != b"MZ" {
        return Err(anyhow!("AutoCAD engine executable has no DOS MZ header"));
    }
    let pe_offset = u32::from_le_bytes(
        dos_header[0x3c..0x40]
            .try_into()
            .expect("fixed DOS header slice"),
    ) as u64;
    if !(64..=16 * 1024 * 1024).contains(&pe_offset) {
        return Err(anyhow!(
            "AutoCAD engine executable has an invalid PE header offset {pe_offset}"
        ));
    }
    file.seek(SeekFrom::Start(pe_offset))
        .map_err(|error| anyhow!("seek AutoCAD engine PE header: {error}"))?;
    let mut signature_and_machine = [0_u8; 6];
    file.read_exact(&mut signature_and_machine)
        .map_err(|error| anyhow!("read AutoCAD engine PE header: {error}"))?;
    if &signature_and_machine[..4] != b"PE\0\0" {
        return Err(anyhow!("AutoCAD engine executable has no PE signature"));
    }
    Ok(u16::from_le_bytes([
        signature_and_machine[4],
        signature_and_machine[5],
    ]))
}

fn has_accoreconsole_file_name(path: &Path) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| {
            name.eq_ignore_ascii_case("accoreconsole.exe")
                || name.eq_ignore_ascii_case("accoreconsole")
        })
}

fn has_arg_extension(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("arg"))
}

fn certified_profile_source_bytes(
    source: &Path,
    expected_digest: Option<&str>,
) -> Result<(Vec<u8>, String)> {
    let source_bytes = std::fs::read(source).map_err(|error| {
        anyhow!(
            "cannot read certified ARG profile {}: {error}",
            source.display()
        )
    })?;
    let expected_digest = validate_certified_profile_bytes(&source_bytes, expected_digest)?;
    Ok((source_bytes, expected_digest))
}

fn validate_certified_profile_bytes(
    source_bytes: &[u8],
    expected_digest: Option<&str>,
) -> Result<String> {
    let expected_digest = expected_digest.ok_or_else(|| {
        anyhow!(
            "this binary was built without {XREF_CERTIFIED_ARG_SHA256_BUILD_ENV}; \
             no ARG profile is certified"
        )
    })?;
    let expected_digest = expected_digest.trim();
    if expected_digest.len() != 64 || !expected_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(anyhow!(
            "{XREF_CERTIFIED_ARG_SHA256_BUILD_ENV} must contain exactly 64 hexadecimal digits"
        ));
    }

    if source_bytes.is_empty() {
        return Err(anyhow!("certified ARG profile is empty"));
    }
    let source_digest = format!("{:x}", Sha256::digest(source_bytes));
    if !source_digest.eq_ignore_ascii_case(expected_digest) {
        return Err(anyhow!(
            "certified ARG profile digest does not match build-time \
             {XREF_CERTIFIED_ARG_SHA256_BUILD_ENV}"
        ));
    }

    Ok(expected_digest.to_ascii_lowercase())
}

fn validate_profile_destination<'a>(staging: &Path, destination: &'a Path) -> Result<&'a OsStr> {
    if destination.parent() != Some(staging) {
        return Err(anyhow!(
            "isolated certified ARG destination must be a direct child of staging: {}",
            destination.display()
        ));
    }
    let file_name = destination.file_name().ok_or_else(|| {
        anyhow!(
            "isolated certified ARG destination has no file name: {}",
            destination.display()
        )
    })?;
    if Path::new(file_name).components().count() != 1 || !has_arg_extension(destination) {
        return Err(anyhow!(
            "isolated certified ARG destination must be a single .arg file name: {}",
            destination.display()
        ));
    }
    Ok(file_name)
}

fn validate_operation_staging(staging: &Path) -> Result<()> {
    if !staging.is_absolute() {
        return Err(anyhow!(
            "operation staging directory must be an absolute path: {}",
            staging.display()
        ));
    }
    let staging_metadata = std::fs::metadata(staging).map_err(|error| {
        anyhow!(
            "operation staging directory is not accessible at {}: {error}",
            staging.display()
        )
    })?;
    if !staging_metadata.is_dir() {
        return Err(anyhow!(
            "operation staging path must name a directory: {}",
            staging.display()
        ));
    }
    Ok(())
}

fn stage_certified_profile_for_launch(
    source: &Path,
    staging: &Path,
    expected_digest: Option<&str>,
) -> Result<StagedCertifiedProfile> {
    validate_operation_staging(staging)?;
    let (source_bytes, expected_digest) = certified_profile_source_bytes(source, expected_digest)?;
    let destination = staging.join(STAGED_CERTIFIED_PROFILE_FILE_NAME);
    stage_certified_profile_bytes_with_digest(
        &source_bytes,
        staging,
        &destination,
        &expected_digest,
    )
}

fn stage_certified_profile_bytes_with_digest(
    source_bytes: &[u8],
    staging: &Path,
    destination: &Path,
    expected_digest: &str,
) -> Result<StagedCertifiedProfile> {
    let _destination_file_name = validate_profile_destination(staging, destination)?;
    #[cfg(target_os = "windows")]
    {
        stage_certified_profile_for_launch_windows(
            staging,
            _destination_file_name,
            source_bytes,
            expected_digest,
            |_| Ok(()),
        )
    }

    #[cfg(not(target_os = "windows"))]
    {
        stage_certified_profile_for_launch_portable(destination, source_bytes, expected_digest)
    }
}

pub(crate) fn stage_unique_xref_profile_bytes_for_launch(
    source_bytes: &[u8],
    staging: &Path,
    destination: &Path,
) -> Result<StagedCertifiedProfile> {
    let expected_digest = certified_arg_sha256_build_value().ok_or_else(|| {
        anyhow!(
            "this binary was built without {XREF_CERTIFIED_ARG_SHA256_BUILD_ENV}; \
             no ARG profile is certified"
        )
    })?;
    stage_unique_profile_bytes_for_launch(source_bytes, expected_digest, staging, destination)
}

/// Materialize one exact package-owned ARG as a per-launch profile.
///
/// Unlike the compatibility wrapper above, the expected digest belongs to the
/// selected activation row rather than the legacy singular build-time ARG
/// binding. The unique profile is still derived beneath the validated
/// release/product-language registry tuple and retains the same guarded
/// lifecycle through child exit and registry cleanup.
pub(crate) fn stage_unique_profile_bytes_for_launch(
    source_bytes: &[u8],
    expected_digest: &str,
    staging: &Path,
    destination: &Path,
) -> Result<StagedCertifiedProfile> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_PROFILE_TOKEN: AtomicU64 = AtomicU64::new(1);

    validate_operation_staging(staging)?;
    validate_certified_profile_bytes(source_bytes, Some(expected_digest))?;
    let token = match std::env::var_os(crate::certified_arg::XREF_ISOLATED_PROFILE_TOKEN_ENV) {
        Some(value) => {
            let value = value.to_str().ok_or_else(|| {
                anyhow!(
                    "{} must be valid Unicode",
                    crate::certified_arg::XREF_ISOLATED_PROFILE_TOKEN_ENV
                )
            })?;
            crate::certified_arg::validate_xref_isolated_profile_token(value)?;
            value.to_string()
        }
        None => {
            let mut hasher = Sha256::new();
            hasher.update(std::process::id().to_le_bytes());
            hasher.update(
                NEXT_PROFILE_TOKEN
                    .fetch_add(1, Ordering::Relaxed)
                    .to_le_bytes(),
            );
            hasher.update(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|error| anyhow!("system clock precedes Unix epoch: {error}"))?
                    .as_nanos()
                    .to_le_bytes(),
            );
            hasher.update(staging.to_string_lossy().as_bytes());
            format!("{:x}", hasher.finalize())[..32].to_string()
        }
    };
    let derived = crate::certified_arg::derive_xref_certified_arg(source_bytes, &token)?;
    let derived_digest = format!("{:x}", Sha256::digest(&derived.bytes));
    let mut staged = stage_certified_profile_bytes_with_digest(
        &derived.bytes,
        staging,
        destination,
        &derived_digest,
    )?;
    staged.xref_registry_binding = Some(derived.binding);
    staged.xref_profile_token = Some(token);
    Ok(staged)
}

#[cfg(not(target_os = "windows"))]
fn stage_certified_profile_for_launch_portable(
    staged_profile: &Path,
    source_bytes: &[u8],
    expected_digest: &str,
) -> Result<StagedCertifiedProfile> {
    let mut staged_options = std::fs::OpenOptions::new();
    staged_options.read(true).write(true).create_new(true);
    let mut staged_file = staged_options.open(staged_profile).map_err(|error| {
        anyhow!(
            "create isolated certified ARG profile {} without replacement: {error}",
            staged_profile.display()
        )
    })?;
    staged_file.write_all(source_bytes).map_err(|error| {
        anyhow!(
            "write isolated certified ARG profile {}: {error}",
            staged_profile.display()
        )
    })?;
    staged_file.sync_all().map_err(|error| {
        anyhow!(
            "sync isolated certified ARG profile {}: {error}",
            staged_profile.display()
        )
    })?;
    staged_file.seek(SeekFrom::Start(0)).map_err(|error| {
        anyhow!(
            "rewind isolated certified ARG profile {}: {error}",
            staged_profile.display()
        )
    })?;

    let mut staged_bytes = Vec::with_capacity(source_bytes.len());
    staged_file
        .read_to_end(&mut staged_bytes)
        .map_err(|error| {
            anyhow!(
                "re-read isolated certified ARG profile {} through retained handle: {error}",
                staged_profile.display()
            )
        })?;
    let staged_digest = format!("{:x}", Sha256::digest(&staged_bytes));
    if staged_bytes != source_bytes || !staged_digest.eq_ignore_ascii_case(expected_digest) {
        return Err(anyhow!(
            "isolated certified ARG profile changed before AutoCAD launch: {}",
            staged_profile.display()
        ));
    }

    // Keep the ordinary path spelling supplied by the operation. In
    // particular, do not canonicalize this to a Windows `\\?\` path before
    // passing it to AutoCAD's `/p` switch.
    Ok(StagedCertifiedProfile {
        path: staged_profile.to_path_buf(),
        xref_registry_binding: None,
        xref_profile_token: None,
        _guard: staged_file,
    })
}

/// Converts the DOS-volume spelling returned by `GetFinalPathNameByHandleW`
/// into the ordinary path syntax accepted by AutoCAD's `/p` switch.
///
/// Device paths, volume-GUID paths, relative paths, and paths containing dot
/// components are rejected rather than passed to AutoCAD with ambiguous
/// resolution semantics.
#[cfg(any(target_os = "windows", test))]
fn ordinary_windows_path_from_final_text(final_path: &str) -> Result<String> {
    if final_path.contains('\0') || final_path.contains('/') {
        return Err(anyhow!(
            "Windows final path contains an unsupported separator or NUL"
        ));
    }

    let ordinary = if let Some(unc_tail) = final_path.strip_prefix(r"\\?\UNC\") {
        let mut components = unc_tail.split('\\');
        let server = components.next().unwrap_or_default();
        let share = components.next().unwrap_or_default();
        if server.is_empty() || share.is_empty() {
            return Err(anyhow!(
                "Windows final UNC path does not contain a server and share"
            ));
        }
        format!(r"\\{unc_tail}")
    } else if let Some(dos_tail) = final_path.strip_prefix(r"\\?\") {
        let bytes = dos_tail.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || bytes[2] != b'\\'
        {
            return Err(anyhow!("Windows final path is not a drive-letter DOS path"));
        }
        dos_tail.to_string()
    } else {
        return Err(anyhow!(
            "Windows final path is not in the expected DOS-volume namespace"
        ));
    };

    if ordinary
        .split('\\')
        .any(|component| component == "." || component == "..")
    {
        return Err(anyhow!("Windows final path contains a dot component"));
    }
    Ok(ordinary)
}

/// Returns the ordinary DOS/UNC spelling AutoCAD accepts for a path-bearing
/// command-line argument.
///
/// Internal filesystem checks may retain canonical Windows `\\?\` paths for
/// identity and namespace safety. Only the final `/p`, `/s`, `/i`, and `/b`
/// argument spellings cross this compatibility boundary. Already-ordinary
/// paths are preserved exactly.
#[cfg(any(target_os = "windows", test))]
fn autocad_cli_path_text(path: &str) -> Result<std::borrow::Cow<'_, str>> {
    if path.starts_with(r"\\?\") {
        ordinary_windows_path_from_final_text(path).map(std::borrow::Cow::Owned)
    } else {
        Ok(std::borrow::Cow::Borrowed(path))
    }
}

#[cfg(target_os = "windows")]
fn autocad_cli_path(path: &Path, label: &str) -> Result<std::ffi::OsString> {
    use std::os::windows::ffi::OsStrExt;

    const VERBATIM_PREFIX: [u16; 4] = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];

    let encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if !encoded.starts_with(&VERBATIM_PREFIX) {
        return Ok(path.as_os_str().to_os_string());
    }
    let text = String::from_utf16(&encoded)
        .map_err(|_| anyhow!("{label} verbatim Windows path is not valid Unicode"))?;
    let ordinary = autocad_cli_path_text(&text)
        .map_err(|error| anyhow!("{label} cannot be passed to AutoCAD: {error}"))?;
    Ok(std::ffi::OsString::from(ordinary.as_ref()))
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsFileIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[cfg(target_os = "windows")]
fn windows_file_identity(file: &File, label: &str) -> Result<WindowsFileIdentity> {
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
        return Err(anyhow!(
            "cannot query {label} identity: {}",
            std::io::Error::last_os_error()
        ));
    }
    if info.FileId.Identifier == [0; 16] {
        return Err(anyhow!(
            "{label} does not expose an unambiguous volume/file identity"
        ));
    }
    Ok(WindowsFileIdentity {
        volume_serial_number: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}

#[cfg(target_os = "windows")]
fn windows_handle_is_reparse_point(file: &File, label: &str) -> Result<bool> {
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
        return Err(anyhow!(
            "cannot query {label} reparse attributes: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

#[cfg(target_os = "windows")]
fn windows_final_path(file: &File, label: &str) -> Result<PathBuf> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };

    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    let required =
        unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), std::ptr::null_mut(), 0, flags) };
    if required == 0 {
        return Err(anyhow!(
            "cannot query {label} final path length: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut buffer = vec![0u16; required as usize];
    let written = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            flags,
        )
    };
    if written == 0 || written as usize >= buffer.len() {
        return Err(anyhow!(
            "cannot query a stable {label} final path: {}",
            std::io::Error::last_os_error()
        ));
    }
    buffer.truncate(written as usize);
    let final_text = String::from_utf16(&buffer)
        .map_err(|_| anyhow!("{label} final path is not valid Unicode"))?;
    ordinary_windows_path_from_final_text(&final_text).map(PathBuf::from)
}

#[cfg(target_os = "windows")]
fn windows_reopen_file(file: &File, desired_access: u32, share_mode: u32) -> Result<File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::ReOpenFile;

    let handle = unsafe { ReOpenFile(file.as_raw_handle(), desired_access, share_mode, 0) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(anyhow!(
            "ReOpenFile failed while installing certified ARG guard: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(target_os = "windows")]
fn windows_directory_namespace_guard(path: &Path, label: &str) -> Result<(File, PathBuf)> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = std::fs::OpenOptions::new();
    options
        // Attribute-only or zero-access handles do not participate in the
        // read/write/delete sharing check. Retain real read access so omitting
        // FILE_SHARE_DELETE actually guards this directory's namespace.
        .access_mode(GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let guard = options.open(path).map_err(|error| {
        anyhow!(
            "open {label} with namespace guard {}: {error}",
            path.display()
        )
    })?;
    let metadata = guard
        .metadata()
        .map_err(|error| anyhow!("query guarded {label} {}: {error}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "guarded {label} is not a direct directory: {}",
            path.display()
        ));
    }
    if windows_handle_is_reparse_point(&guard, label)? {
        return Err(anyhow!(
            "{label} must not be a reparse point: {}",
            path.display()
        ));
    }
    windows_file_identity(&guard, label)?;
    let final_path = windows_final_path(&guard, label)?;
    Ok((guard, final_path))
}

#[cfg(target_os = "windows")]
fn windows_staging_directory_guard(staging: &Path) -> Result<(File, PathBuf)> {
    windows_directory_namespace_guard(staging, "operation staging directory")
}

#[cfg(target_os = "windows")]
fn windows_guard_accoreconsole_executable(path: &Path) -> Result<(PathBuf, File, File)> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    if std::fs::symlink_metadata(path)
        .map_err(|error| anyhow!("inspect AutoCAD engine path {}: {error}", path.display()))?
        .file_type()
        .is_symlink()
    {
        return Err(anyhow!(
            "AutoCAD engine path must not be a symbolic link: {}",
            path.display()
        ));
    }
    let canonical = canonical_accoreconsole_path(path, "AutoCAD engine path")?;
    let mut options = std::fs::OpenOptions::new();
    options
        .access_mode(GENERIC_READ)
        .share_mode(WINDOWS_FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file_guard = options.open(&canonical).map_err(|error| {
        anyhow!(
            "open AutoCAD engine executable with replacement guard {}: {error}",
            canonical.display()
        )
    })?;
    let metadata = file_guard.metadata().map_err(|error| {
        anyhow!(
            "inspect guarded AutoCAD engine executable {}: {error}",
            canonical.display()
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "guarded AutoCAD engine path is not a direct regular file: {}",
            canonical.display()
        ));
    }
    if windows_handle_is_reparse_point(&file_guard, "AutoCAD engine executable")? {
        return Err(anyhow!(
            "AutoCAD engine executable must not be a reparse point: {}",
            canonical.display()
        ));
    }
    let file_identity = windows_file_identity(&file_guard, "AutoCAD engine executable")?;
    let final_path = windows_final_path(&file_guard, "AutoCAD engine executable")?;
    if !has_accoreconsole_file_name(&final_path) {
        return Err(anyhow!(
            "guarded AutoCAD engine final path does not name accoreconsole.exe: {}",
            final_path.display()
        ));
    }
    let parent = final_path.parent().ok_or_else(|| {
        anyhow!(
            "guarded AutoCAD engine final path has no parent: {}",
            final_path.display()
        )
    })?;
    let (parent_guard, guarded_parent) =
        windows_directory_namespace_guard(parent, "AutoCAD engine parent directory")?;
    if guarded_parent != parent {
        return Err(anyhow!(
            "AutoCAD engine parent changed while its namespace guard was acquired: expected {}, observed {}",
            parent.display(),
            guarded_parent.display()
        ));
    }

    // Re-open the ordinary path after both guards are installed. This proves
    // that the spelling passed to CreateProcess still resolves to the exact
    // guarded volume/FileId rather than only to equivalent-looking path text.
    let mut verifier_options = std::fs::OpenOptions::new();
    verifier_options
        .access_mode(GENERIC_READ)
        .share_mode(WINDOWS_FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let verifier = verifier_options.open(&canonical).map_err(|error| {
        anyhow!(
            "re-open guarded AutoCAD engine path {}: {error}",
            canonical.display()
        )
    })?;
    if windows_handle_is_reparse_point(&verifier, "AutoCAD engine path verifier")? {
        return Err(anyhow!(
            "AutoCAD engine path became a reparse point while guarded"
        ));
    }
    if windows_file_identity(&verifier, "AutoCAD engine path verifier")? != file_identity {
        return Err(anyhow!(
            "AutoCAD engine path resolved to a different volume/FileId while guarded"
        ));
    }
    if windows_final_path(&verifier, "AutoCAD engine path verifier")? != final_path {
        return Err(anyhow!("AutoCAD engine final path changed while guarded"));
    }
    drop(verifier);

    Ok((canonical, file_guard, parent_guard))
}

#[cfg(target_os = "windows")]
fn stage_certified_profile_for_launch_windows<F>(
    staging: &Path,
    destination_file_name: &OsStr,
    source_bytes: &[u8],
    expected_digest: &str,
    transition_hook: F,
) -> Result<StagedCertifiedProfile>
where
    F: FnOnce(&Path) -> Result<()>,
{
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::GENERIC_READ;

    let (parent_guard, ordinary_parent) = windows_staging_directory_guard(staging)?;
    let parent_identity = windows_file_identity(&parent_guard, "operation staging directory")?;
    let staged_profile = ordinary_parent.join(destination_file_name);

    let mut staged_options = std::fs::OpenOptions::new();
    staged_options
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(WINDOWS_FILE_SHARE_READ);
    let mut initial_file = staged_options.open(&staged_profile).map_err(|error| {
        anyhow!(
            "create isolated certified ARG profile {} without replacement: {error}",
            staged_profile.display()
        )
    })?;
    initial_file.write_all(source_bytes).map_err(|error| {
        anyhow!(
            "write isolated certified ARG profile {}: {error}",
            staged_profile.display()
        )
    })?;
    initial_file.sync_all().map_err(|error| {
        anyhow!(
            "sync isolated certified ARG profile {}: {error}",
            staged_profile.display()
        )
    })?;

    if windows_handle_is_reparse_point(&initial_file, "isolated certified ARG profile")? {
        return Err(anyhow!(
            "isolated certified ARG profile unexpectedly became a reparse point"
        ));
    }
    let initial_identity = windows_file_identity(&initial_file, "isolated certified ARG profile")?;
    let initial_profile_path = windows_final_path(&initial_file, "isolated certified ARG profile")?;
    if initial_profile_path.file_name() != Some(destination_file_name)
        || initial_profile_path.parent() != Some(ordinary_parent.as_path())
    {
        return Err(anyhow!(
            "isolated certified ARG initial path escaped its guarded staging directory"
        ));
    }

    // ReOpenFile cannot directly replace a read/write handle with a
    // share-read-only zero-access handle: the new share mode would conflict
    // with the old handle's write access. Install an identity-bound
    // zero-access bridge that shares read/write but not delete, close the
    // writer, then install the final read/share-read guard. A zero-access
    // handle does not make its share mask effective for data access, so the
    // final guard must retain real read access in order to deny writers. There
    // is always a handle to the original file, but a data or namespace change
    // can race during the bridge interval. The exact identity, path, and byte
    // proof below runs after the final guard is active and fails closed on any
    // such change.
    let bridge = windows_reopen_file(
        &initial_file,
        0,
        WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_WRITE,
    )?;
    let bridge_verifier = windows_reopen_file(
        &bridge,
        GENERIC_READ,
        WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_WRITE,
    )?;
    if windows_file_identity(&bridge_verifier, "certified ARG transition bridge")?
        != initial_identity
    {
        return Err(anyhow!(
            "certified ARG transition bridge changed file identity"
        ));
    }
    drop(bridge_verifier);
    drop(initial_file);

    transition_hook(&staged_profile)?;

    let final_guard = windows_reopen_file(&bridge, GENERIC_READ, WINDOWS_FILE_SHARE_READ)?;
    drop(bridge);

    let final_handle_verifier =
        windows_reopen_file(&final_guard, GENERIC_READ, WINDOWS_FILE_SHARE_READ)?;
    if windows_file_identity(
        &final_handle_verifier,
        "certified ARG final-handle verifier",
    )? != initial_identity
    {
        return Err(anyhow!("certified ARG verifier changed file identity"));
    }
    drop(final_handle_verifier);

    // Prove the exact ordinary DOS/UNC spelling that will be passed to
    // AutoCAD, rather than relying only on a path derived from a held handle.
    // A compatible read/share-read open must resolve back to the same
    // volume/FileId and exact certified bytes.
    let mut path_verifier_options = std::fs::OpenOptions::new();
    path_verifier_options
        .read(true)
        .share_mode(WINDOWS_FILE_SHARE_READ);
    let mut verifier = path_verifier_options
        .open(&initial_profile_path)
        .map_err(|error| {
            anyhow!(
                "open ordinary certified ARG path {} with compatible read proof: {error}",
                initial_profile_path.display()
            )
        })?;
    if windows_file_identity(&verifier, "ordinary-path certified ARG verifier")? != initial_identity
    {
        return Err(anyhow!(
            "ordinary certified ARG path resolved to a different file identity"
        ));
    }
    if windows_handle_is_reparse_point(&verifier, "ordinary-path certified ARG profile")? {
        return Err(anyhow!(
            "isolated certified ARG profile became a reparse point during guard transition"
        ));
    }

    let final_profile_path = windows_final_path(&verifier, "isolated certified ARG profile")?;
    if final_profile_path != initial_profile_path {
        return Err(anyhow!(
            "isolated certified ARG path changed during guard transition"
        ));
    }
    let final_parent_path = windows_final_path(&parent_guard, "operation staging directory")?;
    if final_parent_path != ordinary_parent
        || windows_file_identity(&parent_guard, "operation staging directory")? != parent_identity
    {
        return Err(anyhow!(
            "operation staging directory namespace changed during ARG guard transition"
        ));
    }

    verifier.seek(SeekFrom::Start(0)).map_err(|error| {
        anyhow!(
            "rewind isolated certified ARG profile {} through final verifier: {error}",
            final_profile_path.display()
        )
    })?;
    let mut staged_bytes = Vec::with_capacity(source_bytes.len());
    verifier.read_to_end(&mut staged_bytes).map_err(|error| {
        anyhow!(
            "re-read isolated certified ARG profile {} through final verifier: {error}",
            final_profile_path.display()
        )
    })?;
    let staged_digest = format!("{:x}", Sha256::digest(&staged_bytes));
    if staged_bytes != source_bytes || staged_digest != expected_digest {
        return Err(anyhow!(
            "ordinary certified ARG path bytes changed during guard transition: {}",
            final_profile_path.display()
        ));
    }
    drop(verifier);

    Ok(StagedCertifiedProfile {
        path: final_profile_path,
        xref_registry_binding: None,
        xref_profile_token: None,
        _guard: final_guard,
        _parent_guard: parent_guard,
    })
}

fn autocad_version_from_path(path: &Path) -> Option<String> {
    path.to_string_lossy()
        .split(['/', '\\'])
        .filter(|component| component.to_ascii_lowercase().starts_with("autocad"))
        .flat_map(|component| {
            component
                .split(|character: char| !character.is_ascii_digit())
                .filter(|part| part.len() == 4 && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .last()
        .map(str::to_string)
}

#[cfg(target_os = "windows")]
fn which_accoreconsole_in_path() -> Result<PathBuf> {
    std::env::var("PATH")
        .unwrap_or_default()
        .split(';')
        .map(|dir| PathBuf::from(dir).join("accoreconsole.exe"))
        .find(|p| p.is_file())
        .ok_or_else(|| anyhow!("accoreconsole.exe not found in PATH"))
}

#[cfg(target_os = "windows")]
fn search_autodesk_install_dirs() -> Result<PathBuf> {
    // Autodesk installs to %ProgramFiles%\Autodesk\AutoCAD <year>\
    let program_files =
        std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
    let autodesk = PathBuf::from(program_files).join("Autodesk");
    if !autodesk.is_dir() {
        return Err(anyhow!(
            "Autodesk install directory not found: {}",
            autodesk.display()
        ));
    }
    // Walk immediate children; pick the newest AutoCAD directory
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(&autodesk)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("AutoCAD"))
                    .unwrap_or(false)
        })
        .map(|dir| dir.join("accoreconsole.exe"))
        .filter(|p| p.is_file())
        .collect();
    candidates.sort();
    candidates
        .into_iter()
        .next_back()
        .ok_or_else(|| anyhow!("accoreconsole.exe not found under {}", autodesk.display()))
}

/// Run accoreconsole against a drawing with a command script.
///
/// - `exe`: path to `accoreconsole.exe`
/// - `drawing`: absolute path to the source drawing (`.dwg` or `.dxf`)
/// - `script`: absolute path to the `.scr` command script to execute
/// - `staging`: absolute path to the operation staging directory
///
/// Returns the combined stdout+stderr output of the accoreconsole process.
/// Returns `Err` if the process could not be spawned or exited non-zero.
pub fn run_accoreconsole(
    exe: &Path,
    drawing: &Path,
    script: &Path,
    staging: &Path,
) -> Result<String> {
    let profile = resolve_certified_profile_override(
        std::env::var_os(XREF_CERTIFIED_ARG_PATH_ENV).as_deref(),
    )?;
    run_accoreconsole_with_profile(exe, drawing, script, staging, profile.as_deref())
}

/// Runs accoreconsole with an optional exported AutoCAD profile selected before
/// the input drawing is opened. The profile path must name a certified `.arg`
/// file; AutoCAD's `/p` switch imports/selects that profile for this session.
pub fn run_accoreconsole_with_profile(
    exe: &Path,
    drawing: &Path,
    script: &Path,
    staging: &Path,
    profile: Option<&Path>,
) -> Result<String> {
    run_accoreconsole_with_profile_and_support_paths(exe, drawing, script, staging, profile, &[])
}

/// Runs accoreconsole with a profile and transaction-only support paths selected
/// before the input drawing is opened.
pub fn run_accoreconsole_with_profile_and_support_paths(
    exe: &Path,
    drawing: &Path,
    script: &Path,
    staging: &Path,
    profile: Option<&Path>,
    support_paths: &[PathBuf],
) -> Result<String> {
    let staged_profile = profile
        .map(|profile| {
            if !has_arg_extension(profile) {
                return Err(anyhow!(
                    "isolated AutoCAD profile must be an exported .arg file: {}",
                    profile.display()
                ));
            }
            stage_certified_profile_for_launch(profile, staging, certified_arg_sha256_build_value())
        })
        .transpose()?;
    let result = run_accoreconsole_process_with_profile_and_support_paths(
        exe,
        drawing,
        script,
        staging,
        staged_profile.as_ref().map(StagedCertifiedProfile::path),
        support_paths,
        "en-US",
    );
    // Keep the no-write/no-delete profile guard alive until accoreconsole has
    // exited. All public path-based profile launches pass through this
    // materialization boundary.
    drop(staged_profile);
    result
}

pub(crate) fn run_accoreconsole_with_guarded_profile_and_support_paths(
    exe: &Path,
    drawing: &Path,
    script: &Path,
    staging: &Path,
    profile: StagedCertifiedProfile,
    support_paths: &[PathBuf],
) -> Result<String> {
    run_accoreconsole_with_guarded_profile_and_support_paths_and_locale(
        exe,
        drawing,
        script,
        staging,
        profile,
        support_paths,
        "en-US",
    )
}

enum GuardedLaunchAuthority<'a> {
    Explicit {
        executable: &'a Path,
        locale: &'a str,
    },
    Selected(&'a SelectedActivation),
}

impl GuardedLaunchAuthority<'_> {
    fn executable(&self) -> &Path {
        match self {
            Self::Explicit { executable, .. } => executable,
            Self::Selected(selected) => &selected.engine_identity.canonical_executable,
        }
    }

    fn locale(&self) -> &str {
        match self {
            Self::Explicit { locale, .. } => locale,
            Self::Selected(selected) => &selected.target.ui_locale,
        }
    }

    fn acquire_launch_lease(
        &self,
    ) -> Result<Option<crate::activation::SelectedExecutableLaunchLease>> {
        match self {
            Self::Explicit { .. } => Ok(None),
            Self::Selected(selected) => selected
                .acquire_launch_lease()
                .map(Some)
                .map_err(anyhow::Error::new),
        }
    }
}

/// Managed launch path for a process-lifetime activation selection.
///
/// The selected engine is revalidated after guarded profile materialization
/// and immediately before process creation. A mismatch permanently poisons the
/// selection and no executable is launched.
#[cfg(target_os = "windows")]
pub(crate) fn run_accoreconsole_with_selected_activation(
    selected: &SelectedActivation,
    drawing: &Path,
    script: &Path,
    staging: &Path,
    support_paths: &[PathBuf],
) -> Result<String> {
    let destination = staging.join(STAGED_CERTIFIED_PROFILE_FILE_NAME);
    let profile = stage_unique_profile_bytes_for_launch(
        selected.target.profile.arg_bytes(),
        &selected.target.profile.arg_sha256,
        staging,
        &destination,
    )?;
    run_accoreconsole_with_guarded_profile_and_selected_activation(
        selected,
        drawing,
        script,
        staging,
        profile,
        support_paths,
    )
}

pub(crate) fn run_accoreconsole_with_guarded_profile_and_selected_activation(
    selected: &SelectedActivation,
    drawing: &Path,
    script: &Path,
    staging: &Path,
    profile: StagedCertifiedProfile,
    support_paths: &[PathBuf],
) -> Result<String> {
    run_accoreconsole_with_guarded_profile_and_support_paths_and_locale_impl(
        GuardedLaunchAuthority::Selected(selected),
        drawing,
        script,
        staging,
        profile,
        support_paths,
    )
}

pub(crate) fn run_accoreconsole_with_guarded_profile_and_support_paths_and_locale(
    exe: &Path,
    drawing: &Path,
    script: &Path,
    staging: &Path,
    profile: StagedCertifiedProfile,
    support_paths: &[PathBuf],
    locale: &str,
) -> Result<String> {
    run_accoreconsole_with_guarded_profile_and_support_paths_and_locale_impl(
        GuardedLaunchAuthority::Explicit {
            executable: exe,
            locale,
        },
        drawing,
        script,
        staging,
        profile,
        support_paths,
    )
}

fn run_accoreconsole_with_guarded_profile_and_support_paths_and_locale_impl(
    authority: GuardedLaunchAuthority<'_>,
    drawing: &Path,
    script: &Path,
    staging: &Path,
    profile: StagedCertifiedProfile,
    support_paths: &[PathBuf],
) -> Result<String> {
    let executable = authority.executable();
    let locale = authority.locale();
    #[cfg(target_os = "windows")]
    {
        let binding = profile.xref_registry_binding.as_ref().ok_or_else(|| {
            anyhow!("guarded XREF launch requires a uniquely derived certified ARG")
        })?;
        let token = profile
            .xref_profile_token
            .as_deref()
            .ok_or_else(|| anyhow!("guarded XREF launch is missing its unique profile token"))?;
        let mut lifecycle = WindowsXrefProfileLifecycle::acquire(binding, token)?;
        let run_result = authority.acquire_launch_lease().and_then(|launch_lease| {
            // Keep the selected executable and its parent namespace guarded
            // through process creation and the synchronous child lifetime.
            let _launch_lease = launch_lease;
            run_accoreconsole_process_with_profile_and_support_paths(
                executable,
                drawing,
                script,
                staging,
                Some(profile.path()),
                support_paths,
                locale,
            )
        });
        let lifecycle_result = lifecycle.finish();
        // Taking ownership makes it impossible for an internal caller to drop
        // the unforgeable file guard or profile-lifecycle token before the
        // synchronous child process exits and exact registry cleanup completes.
        drop(profile);
        match (run_result, lifecycle_result) {
            (Ok(output), Ok(true)) => Ok(output),
            (Ok(_), Ok(false)) => Err(anyhow!(
                "accoreconsole reported success without importing the unique XREF profile"
            )),
            (Err(error), Ok(_)) => Err(error),
            (Ok(_), Err(lifecycle_error)) => Err(lifecycle_error),
            (Err(run_error), Err(lifecycle_error)) => {
                Err(anyhow!("{run_error}; {lifecycle_error}"))
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let result = authority.acquire_launch_lease().and_then(|launch_lease| {
            let _launch_lease = launch_lease;
            run_accoreconsole_process_with_profile_and_support_paths(
                executable,
                drawing,
                script,
                staging,
                Some(profile.path()),
                support_paths,
                locale,
            )
        });
        drop(profile);
        result
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct WindowsXrefProfileMutex {
    handle: std::os::windows::io::OwnedHandle,
    owned: bool,
}

#[cfg(target_os = "windows")]
impl WindowsXrefProfileMutex {
    fn acquire(token: &str) -> Result<Self> {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::{
            Foundation::{WAIT_ABANDONED_0, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::{CreateMutexW, WaitForSingleObject},
        };

        const MUTEX_WAIT_MS: u32 = 120_000;
        let name = format!("Local\\AutoCADMcpXrefProfile-{token}")
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let raw = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if raw.is_null() {
            return Err(anyhow!(
                "create unique XREF profile mutex: {}",
                std::io::Error::last_os_error()
            ));
        }
        let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
        match unsafe { WaitForSingleObject(raw, MUTEX_WAIT_MS) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED_0 => Ok(Self {
                handle,
                owned: true,
            }),
            WAIT_TIMEOUT => Err(anyhow!(
                "timed out waiting for the unique XREF profile lifecycle mutex"
            )),
            WAIT_FAILED => Err(anyhow!(
                "wait for unique XREF profile mutex: {}",
                std::io::Error::last_os_error()
            )),
            status => Err(anyhow!(
                "unexpected unique XREF profile mutex wait status {status}"
            )),
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsXrefProfileMutex {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::ReleaseMutex;

        if self.owned {
            let released = unsafe { ReleaseMutex(self.handle.as_raw_handle()) };
            debug_assert_ne!(released, 0, "release unique XREF profile mutex");
            self.owned = false;
        }
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct WindowsXrefProfileLifecycle {
    binding: crate::certified_arg::CertifiedArgProfileBinding,
    token: String,
    cleanup_complete: bool,
    _mutex: WindowsXrefProfileMutex,
}

#[cfg(target_os = "windows")]
impl WindowsXrefProfileLifecycle {
    fn acquire(
        binding: &crate::certified_arg::CertifiedArgProfileBinding,
        token: &str,
    ) -> Result<Self> {
        crate::certified_arg::validate_xref_isolated_profile_token(token)?;
        let mutex = WindowsXrefProfileMutex::acquire(token)?;
        if windows_profile_registry_key_exists(&binding.hkcu_subkey)? {
            return Err(anyhow!(
                "unique XREF profile registry root already exists; refusing to adopt or delete it: HKCU\\{}",
                binding.hkcu_subkey
            ));
        }
        Ok(Self {
            binding: binding.clone(),
            token: token.to_string(),
            cleanup_complete: false,
            _mutex: mutex,
        })
    }

    fn finish(&mut self) -> Result<bool> {
        if self.cleanup_complete {
            return Err(anyhow!(
                "unique XREF profile registry lifecycle was already finalized"
            ));
        }
        let present_after_engine = windows_profile_registry_key_exists(&self.binding.hkcu_subkey)?;
        let coordination = if present_after_engine {
            coordinate_xref_profile_observation(&self.token)
        } else {
            Ok(())
        };
        let cleanup = if present_after_engine {
            windows_delete_profile_registry_tree(&self.binding.hkcu_subkey)
        } else {
            Ok(())
        };
        let absent_after = !windows_profile_registry_key_exists(&self.binding.hkcu_subkey)?;
        let cleanup = cleanup.and_then(|()| {
            if absent_after {
                Ok(())
            } else {
                Err(anyhow!(
                    "unique XREF profile registry root remained after exact-subtree cleanup: HKCU\\{}",
                    self.binding.hkcu_subkey
                ))
            }
        });
        if cleanup.is_ok() && absent_after {
            self.cleanup_complete = true;
        }
        match (coordination, cleanup) {
            (Ok(()), Ok(())) => Ok(present_after_engine),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(coordination_error), Err(cleanup_error)) => {
                Err(anyhow!("{coordination_error}; {cleanup_error}"))
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsXrefProfileLifecycle {
    fn drop(&mut self) {
        if self.cleanup_complete {
            return;
        }
        let cleanup = (|| {
            if windows_profile_registry_key_exists(&self.binding.hkcu_subkey)? {
                windows_delete_profile_registry_tree(&self.binding.hkcu_subkey)?;
                if windows_profile_registry_key_exists(&self.binding.hkcu_subkey)? {
                    return Err(anyhow!(
                        "unique XREF profile root remained after unwind cleanup"
                    ));
                }
            }
            Ok(())
        })();
        if let Err(error) = cleanup {
            eprintln!(
                "failed to clean the per-launch unique XREF profile registry subtree during unwind: {error}"
            );
        }
        self.cleanup_complete = true;
    }
}

#[cfg(target_os = "windows")]
fn windows_profile_registry_key_exists(hkcu_subkey: &str) -> Result<bool> {
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS},
        System::Registry::{RegCloseKey, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_READ},
    };

    let path = windows_registry_path(hkcu_subkey)?;
    let mut key: HKEY = std::ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_READ, &mut key) };
    match status {
        ERROR_SUCCESS => {
            let close_status = unsafe { RegCloseKey(key) };
            if close_status != ERROR_SUCCESS {
                return Err(anyhow!(
                    "close unique XREF profile registry key failed with Win32 {close_status}"
                ));
            }
            Ok(true)
        }
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(false),
        status => Err(anyhow!(
            "query unique XREF profile registry key failed with Win32 {status}"
        )),
    }
}

#[cfg(target_os = "windows")]
fn windows_delete_profile_registry_tree(hkcu_subkey: &str) -> Result<()> {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{RegDeleteTreeW, HKEY_CURRENT_USER},
    };

    let path = windows_registry_path(hkcu_subkey)?;
    let status = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, path.as_ptr()) };
    if status != ERROR_SUCCESS {
        return Err(anyhow!(
            "delete per-launch unique XREF profile registry subtree failed with Win32 {status}"
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_registry_path(path: &str) -> Result<Vec<u16>> {
    if path.is_empty() || path.contains('\0') {
        return Err(anyhow!(
            "registry subkey path must be non-empty and contain no NUL"
        ));
    }
    Ok(path.encode_utf16().chain(Some(0)).collect())
}

#[cfg(target_os = "windows")]
fn coordinate_xref_profile_observation(token: &str) -> Result<()> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        Storage::FileSystem::SYNCHRONIZE,
        System::Threading::{OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE},
    };

    const OBSERVATION_WAIT_MS: u32 = 30_000;
    let Some(configured) =
        std::env::var_os(crate::certified_arg::XREF_PROFILE_LIFECYCLE_COORDINATION_ENV)
    else {
        return Ok(());
    };
    let configured = configured.to_str().ok_or_else(|| {
        anyhow!(
            "{} must be valid Unicode",
            crate::certified_arg::XREF_PROFILE_LIFECYCLE_COORDINATION_ENV
        )
    })?;
    if configured != token {
        return Err(anyhow!(
            "{} must equal the active unique profile token",
            crate::certified_arg::XREF_PROFILE_LIFECYCLE_COORDINATION_ENV
        ));
    }
    let event_name = |suffix: &str| {
        format!("Local\\AutoCADMcpXrefProfile-{token}-{suffix}")
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>()
    };
    let open = |access, suffix: &str| -> Result<OwnedHandle> {
        let raw = unsafe { OpenEventW(access, 0, event_name(suffix).as_ptr()) };
        if raw.is_null() {
            return Err(anyhow!(
                "open XREF profile {suffix} event: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    };
    let ready = open(EVENT_MODIFY_STATE, "ready")?;
    let continue_event = open(SYNCHRONIZE, "continue")?;
    if unsafe { SetEvent(ready.as_raw_handle()) } == 0 {
        return Err(anyhow!(
            "signal XREF profile observation: {}",
            std::io::Error::last_os_error()
        ));
    }
    match unsafe { WaitForSingleObject(continue_event.as_raw_handle(), OBSERVATION_WAIT_MS) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(anyhow!(
            "timed out waiting for deterministic XREF profile observation"
        )),
        WAIT_FAILED => Err(anyhow!(
            "wait for XREF profile observation: {}",
            std::io::Error::last_os_error()
        )),
        status => Err(anyhow!(
            "unexpected XREF profile observation wait status {status}"
        )),
    }
}

/// Cooperative cancellation for one bounded Core Console process tree.
///
/// Cancellation is intentionally independent from the probe controller so the
/// process-containment boundary cannot depend on MCP or server lifecycle code.
#[derive(Clone, Debug, Default)]
pub(crate) struct BoundedProcessCancellation {
    state: std::sync::Arc<BoundedProcessCancellationState>,
}

#[derive(Debug, Default)]
struct BoundedProcessCancellationState {
    cancelled: std::sync::atomic::AtomicBool,
    process_boundary: std::sync::Mutex<()>,
}

impl BoundedProcessCancellation {
    pub(crate) fn cancel(&self) {
        // Serialize cancellation with spawn and ResumeThread. Whichever side
        // owns this gate first is the linearization point: a later process
        // boundary observes cancellation and fails closed, while cancellation
        // after a completed boundary terminates the already Job-owned tree.
        self.state
            .cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        let _boundary = self
            .state
            .process_boundary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.state
            .cancelled
            .load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(target_os = "windows")]
    fn run_process_boundary<T>(
        &self,
        cancelled_message: &'static str,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let _boundary = self
            .state
            .process_boundary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.is_cancelled() {
            Err(anyhow!(cancelled_message))
        } else {
            action()
        }
    }
}

#[cfg(target_os = "windows")]
const BOUNDED_CAPTURE_BYTES_PER_STREAM: usize = 256 * 1024;
#[cfg(target_os = "windows")]
const BOUNDED_CAPTURE_HEAD_BYTES: usize = BOUNDED_CAPTURE_BYTES_PER_STREAM / 2;
#[cfg(target_os = "windows")]
const BOUNDED_CAPTURE_TAIL_BYTES: usize =
    BOUNDED_CAPTURE_BYTES_PER_STREAM - BOUNDED_CAPTURE_HEAD_BYTES;

#[derive(Debug)]
struct BoundedProcessCapture {
    retained: Vec<u8>,
    total_bytes: u64,
    truncated: bool,
}

impl BoundedProcessCapture {
    fn contains(&self, needle: &[u8]) -> bool {
        !needle.is_empty()
            && self
                .retained
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn diagnostic(&self, label: &str) -> String {
        const DIAGNOSTIC_BYTES: usize = 4096;
        let retained = &self.retained[..self.retained.len().min(DIAGNOSTIC_BYTES)];
        format!(
            "{label}_total_bytes={}; {label}_truncated={}; {label}_retained={:?}",
            self.total_bytes,
            self.truncated,
            String::from_utf8_lossy(retained)
        )
    }
}

#[derive(Debug)]
pub(crate) struct BoundedAccoreconsoleOutput {
    status: std::process::ExitStatus,
    stdout: BoundedProcessCapture,
    stderr: BoundedProcessCapture,
}

impl BoundedAccoreconsoleOutput {
    pub(crate) fn success(&self) -> bool {
        self.status.success()
    }

    pub(crate) fn contains(&self, sentinel: &[u8]) -> bool {
        self.stdout.contains(sentinel) || self.stderr.contains(sentinel)
    }

    pub(crate) fn diagnostic(&self) -> String {
        format!(
            "status={}; {}; {}",
            self.status,
            self.stdout.diagnostic("stdout"),
            self.stderr.diagnostic("stderr")
        )
    }
}

/// Run the launch-only server probe through the same exact executable,
/// package-owned profile bytes, profile digest, locale, and unique profile
/// lifecycle used by foreground activation.
///
/// This API does not cache or interpret success. The probe controller remains
/// advisory, while this boundary provides only bounded process containment.
pub(crate) fn run_accoreconsole_probe_bounded(
    selected: &SelectedActivation,
    drawing: &Path,
    script: &Path,
    staging: &Path,
    timeout: std::time::Duration,
    cancellation: &BoundedProcessCancellation,
) -> Result<BoundedAccoreconsoleOutput> {
    #[cfg(target_os = "windows")]
    {
        if cancellation.is_cancelled() {
            return Err(anyhow!(
                "Core Console probe was cancelled before profile staging"
            ));
        }
        let destination = staging.join(STAGED_CERTIFIED_PROFILE_FILE_NAME);
        let profile = stage_unique_profile_bytes_for_launch(
            selected.target.profile.arg_bytes(),
            &selected.target.profile.arg_sha256,
            staging,
            &destination,
        )?;
        let binding = profile.xref_registry_binding.as_ref().ok_or_else(|| {
            anyhow!("guarded Core Console probe requires a uniquely derived certified ARG")
        })?;
        let token = profile
            .xref_profile_token
            .as_deref()
            .ok_or_else(|| anyhow!("guarded Core Console probe is missing its profile token"))?;
        let mut lifecycle = WindowsXrefProfileLifecycle::acquire(binding, token)?;
        let command = accoreconsole_command(
            &selected.engine_identity.canonical_executable,
            drawing,
            script,
            staging,
            Some(profile.path()),
            &[],
            &selected.target.ui_locale,
        )?;
        let run_result = selected
            .acquire_launch_lease()
            .map_err(anyhow::Error::new)
            .and_then(|launch_lease| {
                let _launch_lease = launch_lease;
                run_windows_command_bounded(command, timeout, cancellation)
            });
        let lifecycle_result = lifecycle.finish();
        drop(profile);
        match (run_result, lifecycle_result) {
            (Ok(output), Ok(true)) => Ok(output),
            (Ok(_), Ok(false)) => Err(anyhow!(
                "Core Console probe exited without importing its unique profile"
            )),
            (Err(error), Ok(_)) => Err(error),
            (Ok(_), Err(lifecycle_error)) => Err(lifecycle_error),
            (Err(run_error), Err(lifecycle_error)) => {
                Err(anyhow!("{run_error}; {lifecycle_error}"))
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (selected, drawing, script, staging, timeout, cancellation);
        Err(anyhow!(
            "bounded Core Console probe launch requires Windows x64"
        ))
    }
}

fn run_accoreconsole_process_with_profile_and_support_paths(
    exe: &Path,
    drawing: &Path,
    script: &Path,
    staging: &Path,
    profile: Option<&Path>,
    support_paths: &[PathBuf],
    locale: &str,
) -> Result<String> {
    #[cfg(target_os = "windows")]
    {
        let mut command = accoreconsole_command(
            exe,
            drawing,
            script,
            staging,
            profile,
            support_paths,
            locale,
        )?;
        let output = command.output()?;
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !output.status.success() {
            return Err(anyhow!(
                "accoreconsole exited with {}: {}",
                output.status,
                combined.trim()
            ));
        }
        Ok(combined)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (
            exe,
            drawing,
            script,
            staging,
            profile,
            support_paths,
            locale,
        );
        Err(anyhow!(
            "accoreconsole is a Windows-only binary; cannot run on this platform"
        ))
    }
}

#[cfg(target_os = "windows")]
type BoundedCaptureJoin =
    std::thread::JoinHandle<std::result::Result<BoundedProcessCapture, String>>;

#[cfg(target_os = "windows")]
fn spawn_bounded_capture<R>(mut reader: R, label: &'static str) -> BoundedCaptureJoin
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        use std::collections::VecDeque;

        let mut head = Vec::with_capacity(BOUNDED_CAPTURE_HEAD_BYTES);
        let mut tail = VecDeque::with_capacity(BOUNDED_CAPTURE_TAIL_BYTES);
        let mut total_bytes = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|error| format!("read bounded {label} capture: {error}"))?;
            if count == 0 {
                break;
            }
            total_bytes = total_bytes.saturating_add(count as u64);
            let head_count = (BOUNDED_CAPTURE_HEAD_BYTES - head.len()).min(count);
            head.extend_from_slice(&buffer[..head_count]);
            for byte in &buffer[head_count..count] {
                if tail.len() == BOUNDED_CAPTURE_TAIL_BYTES {
                    tail.pop_front();
                }
                tail.push_back(*byte);
            }
        }

        let truncated = total_bytes > BOUNDED_CAPTURE_BYTES_PER_STREAM as u64;
        let marker = b"\n...[bounded output omitted]...\n";
        if truncated {
            for _ in 0..marker.len().min(tail.len()) {
                tail.pop_front();
            }
        }
        let mut retained =
            Vec::with_capacity(head.len() + tail.len() + if truncated { marker.len() } else { 0 });
        retained.extend_from_slice(&head);
        if truncated {
            retained.extend_from_slice(marker);
        }
        retained.extend(tail);
        Ok(BoundedProcessCapture {
            retained,
            total_bytes,
            truncated,
        })
    })
}

#[cfg(target_os = "windows")]
fn join_bounded_capture(thread: BoundedCaptureJoin, label: &str) -> Result<BoundedProcessCapture> {
    thread
        .join()
        .map_err(|_| anyhow!("bounded {label} capture thread panicked"))?
        .map_err(anyhow::Error::msg)
}

#[cfg(target_os = "windows")]
struct ProbeOwnedHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(target_os = "windows")]
impl ProbeOwnedHandle {
    fn from_nullable(raw: windows_sys::Win32::Foundation::HANDLE, label: &str) -> Result<Self> {
        if raw.is_null() {
            Err(anyhow!("{label}: {}", std::io::Error::last_os_error()))
        } else {
            Ok(Self(raw))
        }
    }

    fn from_snapshot(raw: windows_sys::Win32::Foundation::HANDLE) -> Result<Self> {
        if raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            Err(anyhow!(
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

#[cfg(target_os = "windows")]
impl Drop for ProbeOwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(target_os = "windows")]
struct KillOnCloseProbeJob(ProbeOwnedHandle);

#[cfg(target_os = "windows")]
impl KillOnCloseProbeJob {
    fn new() -> Result<Self> {
        use std::ffi::c_void;
        use std::mem::size_of_val;
        use std::ptr::null;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let handle = ProbeOwnedHandle::from_nullable(
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
            return Err(anyhow!(
                "SetInformationJobObject: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self(handle))
    }

    fn assign(&self, process: windows_sys::Win32::Foundation::HANDLE) -> Result<()> {
        let assigned = unsafe {
            windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(self.0.raw(), process)
        };
        if assigned == 0 {
            Err(anyhow!(
                "AssignProcessToJobObject: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    }

    fn terminate(&self) -> Result<()> {
        let terminated = unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0.raw(), 124)
        };
        if terminated == 0 {
            Err(anyhow!(
                "TerminateJobObject: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    }

    fn active_processes(&self) -> Result<u32> {
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
            Err(anyhow!(
                "QueryInformationJobObject: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(accounting.ActiveProcesses)
        }
    }
}

#[cfg(target_os = "windows")]
fn resume_suspended_probe_process(process_id: u32) -> Result<()> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_NO_MORE_FILES};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    let snapshot =
        ProbeOwnedHandle::from_snapshot(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) })?;
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    if unsafe { Thread32First(snapshot.raw(), &mut entry) } == 0 {
        return Err(anyhow!(
            "Thread32First: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut thread_id = None;
    loop {
        if entry.th32OwnerProcessID == process_id && thread_id.replace(entry.th32ThreadID).is_some()
        {
            return Err(anyhow!(
                "suspended Core Console probe {process_id} unexpectedly had multiple threads"
            ));
        }
        if unsafe { Thread32Next(snapshot.raw(), &mut entry) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_NO_MORE_FILES {
                return Err(anyhow!(
                    "Thread32Next: {}",
                    std::io::Error::from_raw_os_error(error as i32)
                ));
            }
            break;
        }
    }
    let thread_id =
        thread_id.ok_or_else(|| anyhow!("no primary thread found for probe child {process_id}"))?;
    let thread = ProbeOwnedHandle::from_nullable(
        unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id) },
        "OpenThread",
    )?;
    let previous = unsafe { ResumeThread(thread.raw()) };
    if previous == u32::MAX {
        return Err(anyhow!("ResumeThread: {}", std::io::Error::last_os_error()));
    }
    if previous != 1 {
        return Err(anyhow!(
            "probe primary thread suspend count was {previous}, expected 1"
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_probe_wait_millis(duration: std::time::Duration) -> u32 {
    duration.as_millis().min(u128::from(u32::MAX - 1)).max(1) as u32
}

#[cfg(target_os = "windows")]
fn wait_for_empty_probe_job(
    job: &KillOnCloseProbeJob,
    deadline: std::time::Instant,
    cancellation: Option<&BoundedProcessCancellation>,
) -> Result<()> {
    const POLL: std::time::Duration = std::time::Duration::from_millis(20);
    loop {
        if job.active_processes()? == 0 {
            return Ok(());
        }
        if cancellation.is_some_and(BoundedProcessCancellation::is_cancelled) {
            return Err(anyhow!(
                "Core Console probe was cancelled while its process tree was draining"
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "Core Console probe Job Object did not become empty before its deadline"
            ));
        }
        std::thread::sleep(POLL);
    }
}

#[cfg(target_os = "windows")]
fn wait_for_probe_child_cleanup(
    child: &mut std::process::Child,
    deadline: std::time::Instant,
) -> Result<()> {
    const POLL: std::time::Duration = std::time::Duration::from_millis(20);
    loop {
        if child
            .try_wait()
            .map_err(|error| anyhow!("wait for Core Console probe cleanup: {error}"))?
            .is_some()
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "Core Console probe child was not reaped before its cleanup deadline"
            ));
        }
        std::thread::sleep(POLL);
    }
}

#[cfg(target_os = "windows")]
fn cleanup_windows_probe_process(
    job: &KillOnCloseProbeJob,
    child: &mut std::process::Child,
    assigned: bool,
) -> String {
    const CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    let deadline = std::time::Instant::now() + CLEANUP_TIMEOUT;
    if assigned {
        let terminate = match job.active_processes() {
            Ok(0) => Ok(()),
            Ok(_) => job.terminate(),
            Err(error) => Err(error),
        };
        let empty = wait_for_empty_probe_job(job, deadline, None);
        let child = wait_for_probe_child_cleanup(child, deadline);
        format!("terminate={terminate:?}; job_empty={empty:?}; child_reaped={child:?}")
    } else {
        let kill = child
            .kill()
            .map_err(|error| anyhow!("kill unassigned suspended probe child: {error}"));
        let child = wait_for_probe_child_cleanup(child, deadline);
        format!("kill={kill:?}; child_reaped={child:?}; process_never_resumed=true")
    }
}

#[cfg(target_os = "windows")]
fn wait_for_windows_probe_process(
    child: &mut std::process::Child,
    timeout: std::time::Duration,
    cancellation: &BoundedProcessCancellation,
) -> Result<std::process::ExitStatus> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    const POLL: std::time::Duration = std::time::Duration::from_millis(25);
    let deadline = std::time::Instant::now() + timeout;
    let process = child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    loop {
        if cancellation.is_cancelled() {
            return Err(anyhow!("Core Console probe was cancelled"));
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(anyhow!(
                "Core Console probe timed out after {}ms",
                timeout.as_millis()
            ));
        }
        match unsafe {
            WaitForSingleObject(process, windows_probe_wait_millis(remaining.min(POLL)))
        } {
            WAIT_OBJECT_0 => {
                return child
                    .try_wait()
                    .map_err(|error| anyhow!("reap Core Console probe child: {error}"))?
                    .ok_or_else(|| {
                        anyhow!("signaled Core Console probe child had no exit status")
                    });
            }
            WAIT_TIMEOUT => {}
            WAIT_FAILED => {
                return Err(anyhow!(
                    "WaitForSingleObject: {}",
                    std::io::Error::last_os_error()
                ));
            }
            other => return Err(anyhow!("unexpected Core Console probe wait result {other}")),
        }
    }
}

#[cfg(target_os = "windows")]
fn run_windows_command_bounded(
    command: std::process::Command,
    timeout: std::time::Duration,
    cancellation: &BoundedProcessCancellation,
) -> Result<BoundedAccoreconsoleOutput> {
    run_windows_command_bounded_with_before_resume(command, timeout, cancellation, || {})
}

#[cfg(target_os = "windows")]
fn run_windows_command_bounded_with_before_resume(
    mut command: std::process::Command,
    timeout: std::time::Duration,
    cancellation: &BoundedProcessCancellation,
    before_resume: impl FnOnce(),
) -> Result<BoundedAccoreconsoleOutput> {
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::Stdio;
    use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

    if timeout.is_zero() {
        return Err(anyhow!("Core Console probe timeout must be non-zero"));
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_SUSPENDED);

    let job = KillOnCloseProbeJob::new()?;
    let mut child = cancellation.run_process_boundary(
        "Core Console probe was cancelled before spawn",
        || {
            command
                .spawn()
                .map_err(|error| anyhow!("spawn suspended Core Console probe: {error}"))
        },
    )?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let cleanup = cleanup_windows_probe_process(&job, &mut child, false);
            return Err(anyhow!(
                "suspended Core Console probe had no stdout pipe; {cleanup}"
            ));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            drop(stdout);
            let cleanup = cleanup_windows_probe_process(&job, &mut child, false);
            return Err(anyhow!(
                "suspended Core Console probe had no stderr pipe; {cleanup}"
            ));
        }
    };
    let process = child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    if let Err(error) = job.assign(process) {
        drop(stdout);
        drop(stderr);
        let cleanup = cleanup_windows_probe_process(&job, &mut child, false);
        drop(job);
        return Err(anyhow!(
            "assign suspended Core Console probe to its Job Object: {error}; {cleanup}"
        ));
    }

    // Start the pipe drains only after the suspended child is owned by the
    // kill-on-close Job Object. An assignment failure therefore cannot leave
    // detached capture threads waiting on an unowned process.
    let stdout_capture = spawn_bounded_capture(stdout, "stdout");
    let stderr_capture = spawn_bounded_capture(stderr, "stderr");
    before_resume();
    let preparation = cancellation.run_process_boundary(
        "Core Console probe was cancelled before its process was resumed",
        || resume_suspended_probe_process(child.id()),
    );

    let process_result = preparation.and_then(|()| {
        let deadline = std::time::Instant::now() + timeout;
        let status = wait_for_windows_probe_process(&mut child, timeout, cancellation)?;
        wait_for_empty_probe_job(&job, deadline, Some(cancellation))?;
        Ok(status)
    });
    let cleanup = process_result
        .as_ref()
        .err()
        .map(|_| cleanup_windows_probe_process(&job, &mut child, true));

    // Close the kill-on-close owner before joining capture threads. Even when
    // explicit cleanup reported an OS error, this is the final authoritative
    // process-tree termination boundary and prevents a retained descendant
    // pipe from turning the bounded runner into an unbounded join.
    drop(job);
    let post_close_child = process_result.as_ref().err().map(|_| {
        wait_for_probe_child_cleanup(
            &mut child,
            std::time::Instant::now() + std::time::Duration::from_secs(30),
        )
    });
    if post_close_child
        .as_ref()
        .is_some_and(std::result::Result::is_err)
    {
        // Dropping a JoinHandle detaches the bounded-capture thread. This path
        // is reached only after both explicit termination and Job close have
        // failed to make the primary process observable as reaped; returning
        // remains bounded rather than waiting forever on inherited pipes.
        drop(stdout_capture);
        drop(stderr_capture);
        return Err(anyhow!(
            "Core Console probe cleanup remained incomplete after Job close; \
             cleanup={cleanup:?}; child={post_close_child:?}; capture_abandoned=true"
        ));
    }
    let stdout = join_bounded_capture(stdout_capture, "stdout");
    let stderr = join_bounded_capture(stderr_capture, "stderr");

    match (process_result, stdout, stderr) {
        (Ok(status), Ok(stdout), Ok(stderr)) => Ok(BoundedAccoreconsoleOutput {
            status,
            stdout,
            stderr,
        }),
        (Err(error), Ok(stdout), Ok(stderr)) => Err(anyhow!(
            "{error}; {}; post_job_close={post_close_child:?}; {}; {}",
            cleanup.unwrap_or_else(|| "cleanup=not-required".to_string()),
            stdout.diagnostic("stdout"),
            stderr.diagnostic("stderr")
        )),
        (result, stdout, stderr) => Err(anyhow!(
            "bounded Core Console capture failed after process result {result:?}; \
             cleanup={cleanup:?}; stdout={stdout:?}; stderr={stderr:?}"
        )),
    }
}

#[cfg(target_os = "windows")]
fn accoreconsole_command(
    exe: &Path,
    drawing: &Path,
    script: &Path,
    staging: &Path,
    profile: Option<&Path>,
    support_paths: &[PathBuf],
    locale: &str,
) -> Result<std::process::Command> {
    use std::ffi::OsString;
    use std::process::Command;

    let mut command = Command::new(exe);
    if locale.is_empty()
        || locale.len() > 35
        || !locale
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(anyhow!(
            "AutoCAD launch locale must be a non-empty ASCII language tag"
        ));
    }
    if let Some(profile) = profile {
        command
            .arg("/p")
            .arg(autocad_cli_path(profile, "AutoCAD /p profile")?);
    }
    if support_paths.len() > 15 {
        return Err(anyhow!(
            "AutoCAD /s accepts at most 15 isolated support paths"
        ));
    }
    if !support_paths.is_empty() {
        let mut argument = OsString::new();
        for (index, path) in support_paths.iter().enumerate() {
            if !path.is_absolute() || path.to_string_lossy().contains(';') {
                return Err(anyhow!(
                    "isolated AutoCAD support path must be absolute and contain no semicolon: {}",
                    path.display()
                ));
            }
            if index != 0 {
                argument.push(";");
            }
            argument.push(autocad_cli_path(path, "AutoCAD /s support path")?);
        }
        command.arg("/s").arg(argument);
    }
    command
        .arg("/i")
        .arg(autocad_cli_path(drawing, "AutoCAD /i drawing")?)
        .arg("/l")
        .arg(locale)
        .arg("/b")
        .arg(autocad_cli_path(script, "AutoCAD /b script")?)
        .current_dir(staging);
    Ok(command)
}

/// Future hook for explicit AutoCAD trust registration.
///
/// MVP engine-backed operations do not require TRUSTEDPATHS registration.
/// Generated command scripts are per-operation artifacts and start with
/// `(setvar "SECURELOAD" 0)`, then suppress dialogs before loading only the
/// generated AutoLISP file from the current staging directory. This function is
/// retained as an erroring stub in case future hardening needs explicit trust
/// registration, a stable install-scoped script directory, or signing.
pub fn register_trusted_path(path: &Path) -> Result<()> {
    let _ = path;
    Err(anyhow!(
        "register_trusted_path is not implemented; \
         use (setvar \"SECURELOAD\" 0) in generated scripts instead"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_file(path: &Path) {
        std::fs::create_dir_all(path.parent().expect("test file must have a parent")).unwrap();
        std::fs::write(path, b"test executable bytes").unwrap();
    }

    fn create_test_pe(path: &Path, machine: u16) {
        std::fs::create_dir_all(path.parent().expect("test file must have a parent")).unwrap();
        let mut bytes = vec![0_u8; 0x100];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(0x80_u32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        std::fs::write(path, bytes).unwrap();
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn create_staging_dir_creates_real_dir() {
        let dir = create_staging_dir().unwrap();
        assert!(dir.path().exists());
        assert!(dir.path().is_dir());
        // TempDir auto-cleans on drop
    }

    #[test]
    fn identifies_canonical_regular_engine_without_launching() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("Autodesk")
            .join("AutoCAD 2026")
            .join("accoreconsole.exe");
        create_file(&path);

        let identity = identify_accoreconsole(path.clone()).unwrap();
        assert_eq!(identity.executable, std::fs::canonicalize(path).unwrap());
        assert_eq!(identity.product, "autocad");
        assert_eq!(identity.version, "2026");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn observes_exact_x64_pe_engine_without_launching() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("Autodesk")
            .join("AutoCAD 2027")
            .join("accoreconsole.exe");
        create_test_pe(&path, 0x8664);

        let observed = observe_accoreconsole_executable(&path).unwrap();
        assert_eq!(
            observed.canonical_executable,
            std::fs::canonicalize(path).unwrap()
        );
        assert_eq!(observed.architecture, "x86_64");
        assert_eq!(observed.file_version, None);
        assert!(observed.identity_token.contains("machine=8664"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn activation_windows_observation_requires_a_fixed_file_version_resource() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("Autodesk")
            .join("AutoCAD 2027")
            .join("accoreconsole.exe");
        create_test_pe(&path, 0x8664);

        let error = observe_accoreconsole_executable(&path).unwrap_err();
        assert!(
            error.to_string().contains("fixed file-version resource"),
            "{error}"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn activation_windows_executable_launch_lease_guards_file_and_parent_through_spawn() {
        let directory = tempfile::tempdir().unwrap();
        let ancestor = directory.path().join("Autodesk");
        let parent = ancestor.join("AutoCAD 2027");
        std::fs::create_dir_all(&parent).unwrap();
        let executable = parent.join("accoreconsole.exe");
        let command_interpreter =
            PathBuf::from(std::env::var_os("ComSpec").expect("Windows ComSpec must be set"));
        std::fs::copy(&command_interpreter, &executable).unwrap();

        let (canonical, file_guard, parent_guard) =
            windows_guard_accoreconsole_executable(&executable).unwrap();
        let original_identity =
            windows_file_identity(&file_guard, "guarded test executable").unwrap();
        let original_version = windows_fixed_file_version(&canonical).unwrap();

        let compatible_reader = File::open(&canonical).unwrap();
        assert_eq!(
            windows_file_identity(&compatible_reader, "compatible test reader").unwrap(),
            original_identity
        );
        drop(compatible_reader);

        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&canonical)
                .is_err(),
            "share-read-only executable guard unexpectedly admitted a writer"
        );
        assert!(
            std::fs::remove_file(&canonical).is_err(),
            "share-read-only executable guard unexpectedly admitted deletion"
        );
        assert!(
            std::fs::rename(&canonical, parent.join("replacement.exe")).is_err(),
            "share-read-only executable guard unexpectedly admitted executable rename"
        );
        assert!(
            std::fs::rename(&parent, ancestor.join("AutoCAD moved")).is_err(),
            "parent namespace guard unexpectedly admitted immediate-parent rename"
        );
        assert!(
            std::fs::rename(&ancestor, directory.path().join("Autodesk moved")).is_err(),
            "open guarded descendant unexpectedly admitted higher-ancestor rename"
        );
        assert_eq!(
            windows_fixed_file_version(&canonical).unwrap(),
            original_version
        );

        let output = std::process::Command::new(&canonical)
            .args(["/D", "/C", "echo guarded-original"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("guarded-original"),
            "{output:?}"
        );

        drop(parent_guard);
        drop(file_guard);
        let moved_executable = parent.join("moved.exe");
        std::fs::rename(&canonical, &moved_executable).unwrap();
        std::fs::rename(&moved_executable, &canonical).unwrap();
        let moved_parent = ancestor.join("AutoCAD moved");
        std::fs::rename(&parent, &moved_parent).unwrap();
        std::fs::rename(&moved_parent, &parent).unwrap();
        std::fs::rename(&ancestor, directory.path().join("Autodesk moved")).unwrap();
    }

    #[test]
    fn engine_observation_rejects_non_x64_or_non_pe_files() {
        let directory = tempfile::tempdir().unwrap();
        let x86 = directory.path().join("AutoCAD 2026/accoreconsole.exe");
        create_test_pe(&x86, 0x014c);
        assert!(observe_accoreconsole_executable(&x86)
            .unwrap_err()
            .to_string()
            .contains("not Windows x86-64 PE"));

        let not_pe = directory.path().join("AutoCAD 2025/accoreconsole.exe");
        create_file(&not_pe);
        assert!(observe_accoreconsole_executable(&not_pe)
            .unwrap_err()
            .to_string()
            .contains("DOS header"));
    }

    #[test]
    fn engine_identity_rejects_unknown_binary_and_unversioned_path() {
        let directory = tempfile::tempdir().unwrap();
        let wrong_path = directory
            .path()
            .join("Autodesk")
            .join("AutoCAD 2026")
            .join("acad.exe");
        create_file(&wrong_path);
        let wrong_binary = identify_accoreconsole(wrong_path).unwrap_err();
        assert!(wrong_binary
            .to_string()
            .contains("does not name accoreconsole"));

        let unversioned_path = directory.path().join("Tools").join("accoreconsole.exe");
        create_file(&unversioned_path);
        let missing_version = identify_accoreconsole(unversioned_path).unwrap_err();
        assert!(missing_version
            .to_string()
            .contains("without launching engine"));
    }

    #[test]
    fn engine_identity_requires_an_existing_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory
            .path()
            .join("AutoCAD 2026")
            .join("accoreconsole.exe");
        let missing_error = identify_accoreconsole(missing).unwrap_err().to_string();
        assert!(missing_error.contains("not accessible"), "{missing_error}");

        let not_file = directory
            .path()
            .join("AutoCAD 2026")
            .join("accoreconsole.exe");
        std::fs::create_dir_all(&not_file).unwrap();
        let directory_error = identify_accoreconsole(not_file).unwrap_err().to_string();
        assert!(
            directory_error.contains("regular file"),
            "{directory_error}"
        );
    }

    #[test]
    fn exact_engine_override_is_optional_and_canonical() {
        assert_eq!(resolve_accoreconsole_override(None).unwrap(), None);

        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("AutoCAD 2026")
            .join("accoreconsole.exe");
        create_file(&path);
        assert_eq!(
            resolve_accoreconsole_override(Some(path.as_os_str())).unwrap(),
            Some(std::fs::canonicalize(path).unwrap())
        );
    }

    #[test]
    fn exact_engine_override_fails_closed_on_every_defect() {
        let relative =
            resolve_accoreconsole_override(Some(OsStr::new("accoreconsole.exe"))).unwrap_err();
        assert!(relative.to_string().contains("absolute path"));

        let directory = tempfile::tempdir().unwrap();
        let missing = directory
            .path()
            .join("AutoCAD 2026")
            .join("accoreconsole.exe");
        assert!(resolve_accoreconsole_override(Some(missing.as_os_str()))
            .unwrap_err()
            .to_string()
            .contains("not accessible"));

        let wrong_name = directory.path().join("AutoCAD 2026").join("acad.exe");
        create_file(&wrong_name);
        assert!(resolve_accoreconsole_override(Some(wrong_name.as_os_str()))
            .unwrap_err()
            .to_string()
            .contains("does not name accoreconsole"));

        let not_file = directory
            .path()
            .join("AutoCAD 2026")
            .join("accoreconsole.exe");
        std::fs::create_dir_all(&not_file).unwrap();
        assert!(resolve_accoreconsole_override(Some(not_file.as_os_str()))
            .unwrap_err()
            .to_string()
            .contains("regular file"));
    }

    #[test]
    fn certified_profile_override_is_optional_and_canonical() {
        assert_eq!(resolve_certified_profile_override(None).unwrap(), None);

        let directory = tempfile::tempdir().unwrap();
        let profile = directory.path().join("certified-profile.ARG");
        create_file(&profile);
        assert_eq!(
            resolve_certified_profile_override(Some(profile.as_os_str())).unwrap(),
            Some(std::fs::canonicalize(profile).unwrap())
        );
    }

    #[test]
    fn certified_profile_override_fails_closed_on_every_defect() {
        let relative =
            resolve_certified_profile_override(Some(OsStr::new("certified.arg"))).unwrap_err();
        assert!(relative.to_string().contains("absolute path"));

        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("certified.arg");
        assert!(
            resolve_certified_profile_override(Some(missing.as_os_str()))
                .unwrap_err()
                .to_string()
                .contains("not accessible")
        );

        let wrong_extension = directory.path().join("certified.txt");
        create_file(&wrong_extension);
        assert!(
            resolve_certified_profile_override(Some(wrong_extension.as_os_str()))
                .unwrap_err()
                .to_string()
                .contains("exported .arg file")
        );

        let not_file = directory.path().join("certified.arg");
        std::fs::create_dir(&not_file).unwrap();
        assert!(
            resolve_certified_profile_override(Some(not_file.as_os_str()))
                .unwrap_err()
                .to_string()
                .contains("regular file")
        );
    }

    #[test]
    fn certified_profile_is_digest_bound_and_staged_without_canonicalizing_the_result() {
        let source_directory = tempfile::tempdir().unwrap();
        let source = source_directory.path().join("source.arg");
        let source_bytes = b"exact certified ARG bytes\r\n";
        std::fs::write(&source, source_bytes).unwrap();
        let source = resolve_certified_profile_override(Some(source.as_os_str()))
            .unwrap()
            .unwrap();
        let staging = tempfile::tempdir().unwrap();

        let staged = stage_certified_profile_for_launch(
            &source,
            staging.path(),
            Some(&sha256_hex(source_bytes)),
        )
        .unwrap();

        let staged_path = staging.path().join(STAGED_CERTIFIED_PROFILE_FILE_NAME);
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            staged.path(),
            staged_path,
            "the guard must preserve the ordinary non-canonicalized /p path"
        );
        #[cfg(target_os = "windows")]
        {
            // GetFinalPathNameByHandleW may expand an 8.3 component such as
            // RUNNER~1 to its long spelling. Both remain the same ordinary
            // DOS path; identity, rather than lexical spelling, is the
            // portable Windows assertion.
            let returned = File::open(staged.path()).unwrap();
            let requested = File::open(&staged_path).unwrap();
            assert_eq!(
                windows_file_identity(&returned, "returned staged ARG").unwrap(),
                windows_file_identity(&requested, "requested staged ARG").unwrap()
            );
            assert!(
                !staged.path().to_string_lossy().starts_with(r"\\?\"),
                "the /p path must remain in the ordinary DOS namespace"
            );
        }
        assert_eq!(std::fs::read(staged.path()).unwrap(), source_bytes);
        assert!(
            staged.path().is_file(),
            "the staged path must remain live while its guard is held"
        );
        drop(staged);
        assert_eq!(std::fs::read(staged_path).unwrap(), source_bytes);
    }

    #[test]
    fn certified_profile_bytes_are_written_once_to_the_requested_direct_arg_destination() {
        let staging = tempfile::tempdir().unwrap();
        let source_bytes = b"exact XREF certified ARG bytes\r\n";
        let destination = staging.path().join("xref-isolated-profile.arg");

        let staged = stage_certified_profile_bytes_with_digest(
            source_bytes,
            staging.path(),
            &destination,
            &sha256_hex(source_bytes),
        )
        .unwrap();

        assert_eq!(
            staged.path().file_name(),
            destination.file_name(),
            "the guarded token must name the requested XREF artifact"
        );
        assert_eq!(std::fs::read(staged.path()).unwrap(), source_bytes);
        assert!(
            !staging
                .path()
                .join(STAGED_CERTIFIED_PROFILE_FILE_NAME)
                .exists(),
            "the shared XREF integration must not create a second ARG copy"
        );

        let nested = staging.path().join("nested").join("profile.arg");
        let nested_error = stage_certified_profile_bytes_with_digest(
            source_bytes,
            staging.path(),
            &nested,
            &sha256_hex(source_bytes),
        )
        .unwrap_err()
        .to_string();
        assert!(nested_error.contains("direct child"), "{nested_error}");
    }

    #[test]
    fn windows_final_paths_are_reduced_only_to_unambiguous_ordinary_paths() {
        assert_eq!(
            ordinary_windows_path_from_final_text(
                r"\\?\C:\Users\username\AppData\Local\Temp\certified-profile.arg"
            )
            .unwrap(),
            r"C:\Users\username\AppData\Local\Temp\certified-profile.arg"
        );
        assert_eq!(
            ordinary_windows_path_from_final_text(
                r"\\?\UNC\build-host\evidence\certified-profile.arg"
            )
            .unwrap(),
            r"\\build-host\evidence\certified-profile.arg"
        );

        for ambiguous in [
            r"C:\relative-to-parser\certified-profile.arg",
            r"\\?\Volume{00000000-0000-0000-0000-000000000000}\certified-profile.arg",
            r"\\.\C:\certified-profile.arg",
            r"\\?\UNC\server",
            r"\\?\C:\safe\..\replacement.arg",
            r"\\?\C:/mixed/separators.arg",
        ] {
            assert!(
                ordinary_windows_path_from_final_text(ambiguous).is_err(),
                "ambiguous final path must fail closed: {ambiguous}"
            );
        }
    }

    #[test]
    fn autocad_cli_path_boundary_preserves_ordinary_paths_and_reduces_verbatim_paths() {
        for ordinary in [
            r"C:\Users\username\drawing.dwg",
            r"\\build-host\evidence\transaction.scr",
        ] {
            let converted = autocad_cli_path_text(ordinary).unwrap();
            assert!(
                matches!(converted, std::borrow::Cow::Borrowed(_)),
                "ordinary CLI paths must remain borrowed and unchanged"
            );
            assert_eq!(converted, ordinary);
        }

        assert_eq!(
            autocad_cli_path_text(r"\\?\C:\Users\username\drawing.dwg").unwrap(),
            r"C:\Users\username\drawing.dwg"
        );
        assert_eq!(
            autocad_cli_path_text(r"\\?\UNC\build-host\evidence\transaction.scr").unwrap(),
            r"\\build-host\evidence\transaction.scr"
        );
        assert!(autocad_cli_path_text(
            r"\\?\Volume{00000000-0000-0000-0000-000000000000}\drawing.dwg"
        )
        .is_err());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn accoreconsole_command_normalizes_only_autocad_path_arguments() {
        let executable = Path::new(r"\\?\C:\Program Files\Autodesk\AutoCAD 2026\accoreconsole.exe");
        let drawing = Path::new(r"\\?\C:\drawings\host.dwg");
        let script = Path::new(r"\\?\C:\staging\transaction.scr");
        let staging = Path::new(r"\\?\C:\staging");
        let profile = Path::new(r"\\?\C:\staging\profile.arg");
        let support_paths = vec![
            PathBuf::from(r"\\?\C:\staging\sources"),
            PathBuf::from(r"\\?\UNC\build-host\evidence\sources"),
        ];

        let command = accoreconsole_command(
            executable,
            drawing,
            script,
            staging,
            Some(profile),
            &support_paths,
            "en-US",
        )
        .unwrap();

        assert_eq!(
            command.get_program(),
            executable.as_os_str(),
            "the canonical executable identity must remain unchanged"
        );
        assert_eq!(
            command.get_current_dir(),
            Some(staging),
            "the guarded staging-directory identity must remain unchanged"
        );
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            arguments,
            [
                "/p",
                r"C:\staging\profile.arg",
                "/s",
                r"C:\staging\sources;\\build-host\evidence\sources",
                "/i",
                r"C:\drawings\host.dwg",
                "/l",
                "en-US",
                "/b",
                r"C:\staging\transaction.scr",
            ]
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn certified_profile_guard_allows_compatible_reader_and_denies_mutation_or_replacement() {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, FILE_SHARE_DELETE, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING,
        };

        const DELETE_ACCESS: u32 = 0x0001_0000;

        let source_directory = tempfile::tempdir().unwrap();
        let source = source_directory.path().join("source.arg");
        let source_bytes = b"certified ARG bytes";
        std::fs::write(&source, source_bytes).unwrap();
        let source = resolve_certified_profile_override(Some(source.as_os_str()))
            .unwrap()
            .unwrap();
        let staging = tempfile::tempdir().unwrap();
        let staged = stage_certified_profile_for_launch(
            &source,
            staging.path(),
            Some(&sha256_hex(source_bytes)),
        )
        .unwrap();
        let all_shares = WINDOWS_FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

        // A read/share-read handle models a compatible AutoCAD profile reader
        // while the retained guard continues to exclude write and delete.
        let mut read_handle = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(WINDOWS_FILE_SHARE_READ)
            .open(staged.path())
            .expect("the final guard must permit a compatible reader");
        let ordinary_identity =
            windows_file_identity(&read_handle, "test ordinary-path verifier").unwrap();
        assert_ne!(ordinary_identity.file_id, [0; 16]);
        assert_eq!(
            windows_final_path(&read_handle, "test ordinary-path verifier").unwrap(),
            staged.path()
        );
        let mut read_bytes = Vec::new();
        read_handle.read_to_end(&mut read_bytes).unwrap();
        assert_eq!(read_bytes, source_bytes);
        drop(read_handle);

        let write_error = std::fs::OpenOptions::new()
            .write(true)
            .share_mode(all_shares)
            .open(staged.path())
            .expect_err("the retained guard must deny a competing write");
        assert!(
            !write_error.to_string().is_empty(),
            "the write denial must report an OS error"
        );

        let delete_error = std::fs::OpenOptions::new()
            .access_mode(DELETE_ACCESS)
            .share_mode(all_shares)
            .open(staged.path())
            .expect_err("the retained guard must deny a competing delete-access open");
        assert!(
            !delete_error.to_string().is_empty(),
            "the delete denial must report an OS error"
        );
        assert!(
            std::fs::remove_file(staged.path()).is_err(),
            "the retained guard must deny ordinary path deletion"
        );

        let replacement = staging.path().join("replacement.arg");
        std::fs::write(&replacement, b"replacement bytes").unwrap();
        let replacement_wide = replacement
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let staged_wide = staged
            .path()
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let replaced = unsafe {
            MoveFileExW(
                replacement_wide.as_ptr(),
                staged_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING,
            )
        };
        assert_eq!(
            replaced, 0,
            "the final guard must deny path-based replacement"
        );
        assert_eq!(std::fs::read(staged.path()).unwrap(), source_bytes);
        assert_eq!(std::fs::read(&replacement).unwrap(), b"replacement bytes");

        let staging_path = staging.path().to_path_buf();
        let renamed_staging = staging_path.with_extension("renamed");
        assert!(
            std::fs::rename(&staging_path, &renamed_staging).is_err(),
            "the retained parent guard must deny staging-directory rename"
        );

        let staged_path = staged.path().to_path_buf();
        drop(staged);
        let delete_handle = std::fs::OpenOptions::new()
            .access_mode(DELETE_ACCESS)
            .share_mode(all_shares)
            .open(&staged_path)
            .expect("delete access must become available after the guard drops");
        drop(delete_handle);
        std::fs::remove_file(staged_path).unwrap();

        std::fs::rename(&staging_path, &renamed_staging)
            .expect("parent rename must become available after both guards drop");
        std::fs::rename(&renamed_staging, &staging_path).unwrap();
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn certified_profile_guard_detects_transition_window_tampering() {
        let source_directory = tempfile::tempdir().unwrap();
        let source = source_directory.path().join("source.arg");
        let source_bytes = b"certified ARG bytes";
        std::fs::write(&source, source_bytes).unwrap();
        let staging = tempfile::tempdir().unwrap();
        let expected_digest = sha256_hex(source_bytes);

        let error = stage_certified_profile_for_launch_windows(
            staging.path(),
            OsStr::new(STAGED_CERTIFIED_PROFILE_FILE_NAME),
            source_bytes,
            &expected_digest,
            |staged_path| {
                // The bridge deliberately permits write opens while the
                // original writer is retired. The final verifier must catch a
                // writer that opens, mutates, and closes in this exact window.
                std::fs::write(staged_path, b"transition-window tamper")?;
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("changed during guard transition"), "{error}");
    }

    #[test]
    fn certified_profile_staging_requires_a_build_digest_and_exact_source_bytes() {
        let source_directory = tempfile::tempdir().unwrap();
        let source = source_directory.path().join("source.arg");
        let original_bytes = b"original certified ARG bytes";
        std::fs::write(&source, original_bytes).unwrap();
        let source = resolve_certified_profile_override(Some(source.as_os_str()))
            .unwrap()
            .unwrap();

        let staging_without_digest = tempfile::tempdir().unwrap();
        let missing_digest =
            stage_certified_profile_for_launch(&source, staging_without_digest.path(), None)
                .unwrap_err()
                .to_string();
        assert!(
            missing_digest.contains("built without")
                && missing_digest.contains(XREF_CERTIFIED_ARG_SHA256_BUILD_ENV),
            "{missing_digest}"
        );

        let staging_with_wrong_digest = tempfile::tempdir().unwrap();
        let wrong_digest = stage_certified_profile_for_launch(
            &source,
            staging_with_wrong_digest.path(),
            Some(&"0".repeat(64)),
        )
        .unwrap_err()
        .to_string();
        assert!(
            wrong_digest.contains("digest does not match"),
            "{wrong_digest}"
        );
        assert!(!staging_with_wrong_digest
            .path()
            .join(STAGED_CERTIFIED_PROFILE_FILE_NAME)
            .exists());

        // Model replacement after identity resolution but before capture.
        std::fs::write(&source, b"substituted ARG bytes").unwrap();
        let staging_after_substitution = tempfile::tempdir().unwrap();
        let substituted = stage_certified_profile_for_launch(
            &source,
            staging_after_substitution.path(),
            Some(&sha256_hex(original_bytes)),
        )
        .unwrap_err()
        .to_string();
        assert!(
            substituted.contains("digest does not match"),
            "{substituted}"
        );
    }

    #[test]
    fn certified_profile_staging_never_clobbers_an_existing_path() {
        let source_directory = tempfile::tempdir().unwrap();
        let source = source_directory.path().join("source.arg");
        let source_bytes = b"certified ARG bytes";
        std::fs::write(&source, source_bytes).unwrap();
        let source = resolve_certified_profile_override(Some(source.as_os_str()))
            .unwrap()
            .unwrap();
        let staging = tempfile::tempdir().unwrap();
        let destination = staging.path().join(STAGED_CERTIFIED_PROFILE_FILE_NAME);
        let sentinel = b"pre-existing staging content";
        std::fs::write(&destination, sentinel).unwrap();

        let error = stage_certified_profile_for_launch(
            &source,
            staging.path(),
            Some(&sha256_hex(source_bytes)),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("without replacement"), "{error}");
        assert_eq!(std::fs::read(destination).unwrap(), sentinel);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn unique_xref_profile_registry_lifecycle_refuses_adoption_and_cleans_owned_root() {
        use windows_sys::Win32::{
            Foundation::ERROR_SUCCESS,
            System::Registry::{RegCloseKey, RegCreateKeyW, HKEY, HKEY_CURRENT_USER},
        };

        fn create_key(path: &str) {
            let path = windows_registry_path(path).unwrap();
            let mut key: HKEY = std::ptr::null_mut();
            let status = unsafe { RegCreateKeyW(HKEY_CURRENT_USER, path.as_ptr(), &mut key) };
            assert_eq!(status, ERROR_SUCCESS);
            assert_eq!(unsafe { RegCloseKey(key) }, ERROR_SUCCESS);
        }

        let token = sha256_hex(
            format!("{}:{:?}", std::process::id(), std::time::SystemTime::now()).as_bytes(),
        )[..32]
            .to_string();
        let profile_name = crate::certified_arg::xref_isolated_profile_name(&token).unwrap();
        let parent = "Software\\Autodesk\\AutoCAD\\R25.1\\ACAD-TEST:409\\Profiles";
        let binding = crate::certified_arg::CertifiedArgProfileBinding {
            profile_root: format!("HKEY_CURRENT_USER\\{parent}\\{profile_name}"),
            hkcu_subkey: format!("{parent}\\{profile_name}"),
            hkcu_parent_subkey: parent.to_string(),
            profile_name,
        };

        create_key(&binding.hkcu_subkey);
        let refusal = WindowsXrefProfileLifecycle::acquire(&binding, &token).unwrap_err();
        assert!(refusal.to_string().contains("refusing to adopt"));
        assert!(windows_profile_registry_key_exists(&binding.hkcu_subkey).unwrap());
        windows_delete_profile_registry_tree(&binding.hkcu_subkey).unwrap();

        let mut lifecycle = WindowsXrefProfileLifecycle::acquire(&binding, &token).unwrap();
        create_key(&binding.hkcu_subkey);
        assert!(lifecycle.finish().unwrap());
        assert!(!windows_profile_registry_key_exists(&binding.hkcu_subkey).unwrap());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn bounded_windows_probe_runner_drains_all_bytes_while_retaining_a_strict_cap() {
        let mut bytes = vec![b'a'; BOUNDED_CAPTURE_BYTES_PER_STREAM + 8192];
        *bytes.last_mut().unwrap() = b'z';
        let capture = spawn_bounded_capture(std::io::Cursor::new(bytes.clone()), "test");
        let capture = join_bounded_capture(capture, "test").unwrap();

        assert_eq!(capture.total_bytes, bytes.len() as u64);
        assert!(capture.truncated);
        assert!(capture.retained.len() <= BOUNDED_CAPTURE_BYTES_PER_STREAM);
        assert_eq!(capture.retained.first(), Some(&b'a'));
        assert_eq!(capture.retained.last(), Some(&b'z'));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn bounded_windows_probe_runner_observes_pre_spawn_cancellation() {
        let cancellation = BoundedProcessCancellation::default();
        cancellation.cancel();
        let error = run_windows_command_bounded(
            std::process::Command::new("this-command-must-not-be-spawned.exe"),
            std::time::Duration::from_secs(1),
            &cancellation,
        )
        .unwrap_err();
        assert!(error.to_string().contains("cancelled before spawn"));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn bounded_windows_probe_runner_linearizes_cancellation_before_resume() {
        let directory = tempfile::tempdir().unwrap();
        let side_effect = directory.path().join("resumed.txt");
        let cancellation = BoundedProcessCancellation::default();
        let cancellation_signal = cancellation.clone();
        let mut command = std::process::Command::new("cmd.exe");
        let script = format!("echo resumed>\"{}\"", side_effect.display());
        command.args(["/D", "/C", &script]);

        let error = run_windows_command_bounded_with_before_resume(
            command,
            std::time::Duration::from_secs(5),
            &cancellation,
            move || cancellation_signal.cancel(),
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("cancelled before its process was resumed"),
            "{error}"
        );
        assert!(error.contains("job_empty=Ok(())"), "{error}");
        assert!(error.contains("child_reaped=Ok(())"), "{error}");
        assert!(
            !side_effect.exists(),
            "cancelled suspended helper unexpectedly executed"
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn bounded_windows_probe_runner_terminates_inherited_pipe_tree_on_timeout() {
        let cancellation = BoundedProcessCancellation::default();
        let mut command = std::process::Command::new("cmd.exe");
        command.args(["/D", "/C", "ping.exe -n 30 127.0.0.1 >NUL"]);
        let started = std::time::Instant::now();
        let error = run_windows_command_bounded(
            command,
            std::time::Duration::from_millis(100),
            &cancellation,
        )
        .unwrap_err();

        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "bounded runner retained an inherited pipe/process tree for {:?}",
            started.elapsed()
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn bounded_windows_probe_runner_cancels_and_joins_running_tree() {
        let cancellation = BoundedProcessCancellation::default();
        let cancellation_signal = cancellation.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            cancellation_signal.cancel();
        });
        let mut command = std::process::Command::new("cmd.exe");
        command.args(["/D", "/C", "ping.exe -n 30 127.0.0.1 >NUL"]);
        let started = std::time::Instant::now();
        let error =
            run_windows_command_bounded(command, std::time::Duration::from_secs(30), &cancellation)
                .unwrap_err();
        canceller.join().unwrap();

        assert!(error.to_string().contains("cancelled"), "{error}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "cancelled runner retained an inherited pipe/process tree for {:?}",
            started.elapsed()
        );
    }

    #[test]
    #[cfg(unix)]
    fn certified_profile_staging_rejects_a_prepositioned_symlink() {
        use std::os::unix::fs::symlink;

        let source_directory = tempfile::tempdir().unwrap();
        let source = source_directory.path().join("source.arg");
        let source_bytes = b"certified ARG bytes";
        std::fs::write(&source, source_bytes).unwrap();
        let source = resolve_certified_profile_override(Some(source.as_os_str()))
            .unwrap()
            .unwrap();
        let staging = tempfile::tempdir().unwrap();
        let victim = staging.path().join("victim.txt");
        let sentinel = b"victim content";
        std::fs::write(&victim, sentinel).unwrap();
        symlink(
            &victim,
            staging.path().join(STAGED_CERTIFIED_PROFILE_FILE_NAME),
        )
        .unwrap();

        let error = stage_certified_profile_for_launch(
            &source,
            staging.path(),
            Some(&sha256_hex(source_bytes)),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("without replacement"), "{error}");
        assert_eq!(std::fs::read(victim).unwrap(), sentinel);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn find_accoreconsole_errors_on_non_windows() {
        let result = find_accoreconsole();
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Windows"),
            "error should mention Windows: {msg}"
        );
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn identity_detection_fails_without_attempting_a_launch_on_non_windows() {
        let result = detect_accoreconsole_identity();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Windows"));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn run_accoreconsole_errors_on_non_windows() {
        use std::path::Path;
        let result = run_accoreconsole(
            Path::new("/fake/accore.exe"),
            Path::new("/fake/drawing.dwg"),
            Path::new("/fake/script.scr"),
            Path::new("/fake/staging"),
        );
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn register_trusted_path_errors_on_non_windows() {
        use std::path::Path;
        let result = register_trusted_path(Path::new("/fake/path"));
        assert!(result.is_err());
    }
}
