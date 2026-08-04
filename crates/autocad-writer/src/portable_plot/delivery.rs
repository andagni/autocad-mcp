use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::{
    run_portable_worker, PlotCompleteness, PortablePlotError, PortablePlotLimits,
    PortableResourceBundle, PortableWorkerLimits, PortableWorkerRequest, ResourceDigest,
};
use crate::{DrawingFormat, DrawingSnapshot};

/// Whether a delivery may publish an explicitly partial development plot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortableDeliveryFidelity {
    /// Persist only a semantically complete plot.
    CompleteOnly,
    /// Persist an explicitly receipted partial plot for development evidence.
    AllowPartialDevelopment,
}

/// Atomic destination policy selected explicitly by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortableOutputPolicy {
    /// Fail if the destination exists at commit time.
    CreateNew,
    /// Atomically replace an existing regular PDF, or create it if absent.
    ReplaceExisting,
}

/// Caller-selected delivery policy. There is deliberately no default: partial
/// fidelity and replacement are separate, explicit authorities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortablePlotDeliveryOptions {
    pub fidelity: PortableDeliveryFidelity,
    pub output: PortableOutputPolicy,
}

impl PortablePlotDeliveryOptions {
    pub const fn new(fidelity: PortableDeliveryFidelity, output: PortableOutputPolicy) -> Self {
        Self { fidelity, output }
    }
}

/// Evidence returned only after the verified temporary PDF has been committed
/// atomically in the destination directory.
#[derive(Debug, Clone)]
pub struct PortablePlotDeliveryReceipt {
    source_sha256: ResourceDigest,
    source_bytes: usize,
    pdf_sha256: ResourceDigest,
    pdf_bytes: usize,
    completeness: PlotCompleteness,
    output_replaced: bool,
    source_identity_revalidated: bool,
    atomic_output_committed: bool,
    source_lock: &'static str,
    worker_receipt_json: String,
}

impl PortablePlotDeliveryReceipt {
    pub fn source_sha256(&self) -> ResourceDigest {
        self.source_sha256
    }

    pub fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    pub fn pdf_sha256(&self) -> ResourceDigest {
        self.pdf_sha256
    }

    pub fn pdf_bytes(&self) -> usize {
        self.pdf_bytes
    }

    pub fn completeness(&self) -> PlotCompleteness {
        self.completeness
    }

    pub fn output_replaced(&self) -> bool {
        self.output_replaced
    }

    pub fn source_identity_revalidated(&self) -> bool {
        self.source_identity_revalidated
    }

    pub fn atomic_output_committed(&self) -> bool {
        self.atomic_output_committed
    }

    pub fn source_lock(&self) -> &'static str {
        self.source_lock
    }

    pub fn worker_receipt_json(&self) -> &str {
        &self.worker_receipt_json
    }
}

/// Capture one stable source snapshot, render it in the bounded worker, then
/// commit the verified PDF without ever exposing a partially written output.
/// This is an internal delivery primitive, not an MCP or Preview registration.
pub fn deliver_portable_pdf(
    worker_executable: &Path,
    source_path: &Path,
    layout_name: &str,
    resources: PortableResourceBundle,
    output_pdf: &Path,
    worker_limits: PortableWorkerLimits,
    options: PortablePlotDeliveryOptions,
) -> Result<PortablePlotDeliveryReceipt, PortablePlotError> {
    if !worker_executable.is_absolute() || !source_path.is_absolute() || !output_pdf.is_absolute() {
        return Err(delivery_error(
            "portable_delivery_path_invalid",
            "worker, source, and output paths must be absolute",
        ));
    }
    if output_pdf
        .extension()
        .and_then(|extension| extension.to_str())
        .is_none_or(|extension| !extension.eq_ignore_ascii_case("pdf"))
    {
        return Err(delivery_error(
            "portable_delivery_path_invalid",
            "portable plot output must have a PDF extension",
        ));
    }
    let capture = LockedDrawingCapture::open(source_path, worker_limits.maximum_request_bytes)?;
    let output = canonical_output_path(output_pdf)?;
    if output == capture.canonical_path {
        return Err(delivery_error(
            "portable_delivery_path_invalid",
            "portable plot output must be distinct from the source drawing",
        ));
    }
    let request =
        PortableWorkerRequest::with_resources(capture.snapshot.clone(), layout_name, resources)?;
    let worker_output = run_portable_worker(worker_executable, &request, worker_limits)?;
    let completeness = worker_output.receipt().completeness();
    if completeness == PlotCompleteness::Rejected
        || (completeness == PlotCompleteness::Partial
            && options.fidelity == PortableDeliveryFidelity::CompleteOnly)
    {
        return Err(delivery_error(
            "portable_delivery_fidelity_rejected",
            "worker fidelity does not satisfy the caller-selected delivery policy",
        ));
    }
    if worker_output.receipt().pdf_sha256() != ResourceDigest::of(worker_output.pdf_bytes()) {
        return Err(delivery_error(
            "portable_delivery_receipt_invalid",
            "worker PDF bytes do not match the mandatory output receipt",
        ));
    }

    let staged = stage_pdf(&output, worker_output.pdf_bytes())?;
    capture.verify_unchanged()?;
    let output_replaced = commit_staged_pdf(staged, &output, options.output)?;
    sync_parent_best_effort(&output);

    Ok(PortablePlotDeliveryReceipt {
        source_sha256: capture.digest,
        source_bytes: capture.snapshot.bytes().len(),
        pdf_sha256: worker_output.receipt().pdf_sha256(),
        pdf_bytes: worker_output.pdf_bytes().len(),
        completeness,
        output_replaced,
        source_identity_revalidated: true,
        atomic_output_committed: true,
        source_lock: capture.lock_kind,
        worker_receipt_json: worker_output.receipt().json().to_string(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileObservation {
    identity: FileIdentity,
    length: u64,
    modified: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileIdentity {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(target_os = "windows")]
    Windows {
        volume_serial_number: u64,
        file_id: [u8; 16],
    },
}

struct LockedDrawingCapture {
    canonical_path: PathBuf,
    file: File,
    observation: FileObservation,
    snapshot: DrawingSnapshot,
    digest: ResourceDigest,
    maximum_bytes: usize,
    lock_kind: &'static str,
}

impl LockedDrawingCapture {
    fn open(path: &Path, maximum_request_bytes: usize) -> Result<Self, PortablePlotError> {
        if std::fs::symlink_metadata(path)
            .map_err(|_| source_capture_error())?
            .file_type()
            .is_symlink()
        {
            return Err(source_capture_error());
        }
        let canonical_path = std::fs::canonicalize(path).map_err(|_| source_capture_error())?;
        let format = DrawingFormat::from_path(&canonical_path).map_err(|_| {
            delivery_error(
                "portable_delivery_source_invalid",
                "portable delivery source must be a DWG or DXF drawing",
            )
        })?;
        let file = open_source_guard(&canonical_path)?;
        let observation = observe_file(&file)?;
        if !file
            .metadata()
            .map_err(|_| source_capture_error())?
            .is_file()
        {
            return Err(source_capture_error());
        }
        let maximum_bytes =
            maximum_request_bytes.min(PortablePlotLimits::default().max_source_bytes);
        let bytes = read_file_bounded(&file, maximum_bytes)?;
        let after = observe_file(&file)?;
        if observation != after || byte_length(&bytes)? != observation.length {
            return Err(source_changed_error());
        }
        let digest = ResourceDigest::of(&bytes);
        Ok(Self {
            canonical_path,
            file,
            observation,
            snapshot: DrawingSnapshot::new(format, bytes),
            digest,
            maximum_bytes,
            lock_kind: source_lock_kind(),
        })
    }

    fn verify_unchanged(&self) -> Result<(), PortablePlotError> {
        let held = observe_file(&self.file)?;
        let path_file = open_source_guard(&self.canonical_path)?;
        let path = observe_file(&path_file)?;
        if held != self.observation || path != self.observation {
            return Err(source_changed_error());
        }
        let bytes = read_file_bounded(&self.file, self.maximum_bytes)?;
        if byte_length(&bytes)? != self.observation.length
            || ResourceDigest::of(&bytes) != self.digest
        {
            return Err(source_changed_error());
        }
        Ok(())
    }
}

fn read_file_bounded(file: &File, maximum_bytes: usize) -> Result<Vec<u8>, PortablePlotError> {
    let mut reader = file.try_clone().map_err(|_| source_capture_error())?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| source_capture_error())?;
    let take = u64::try_from(maximum_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    reader
        .take(take)
        .read_to_end(&mut bytes)
        .map_err(|_| source_capture_error())?;
    if bytes.len() > maximum_bytes {
        return Err(delivery_error(
            "portable_delivery_source_budget_exceeded",
            "source drawing exceeds the worker request byte budget",
        ));
    }
    Ok(bytes)
}

fn byte_length(bytes: &[u8]) -> Result<u64, PortablePlotError> {
    u64::try_from(bytes.len()).map_err(|_| source_capture_error())
}

#[cfg(unix)]
fn open_source_guard(path: &Path) -> Result<File, PortablePlotError> {
    use std::os::fd::AsRawFd;

    let file = File::open(path).map_err(|_| source_capture_error())?;
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
    if locked != 0 {
        return Err(source_capture_error());
    }
    Ok(file)
}

#[cfg(target_os = "windows")]
fn open_source_guard(path: &Path) -> Result<File, PortablePlotError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|_| source_capture_error())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn open_source_guard(_path: &Path) -> Result<File, PortablePlotError> {
    Err(source_capture_error())
}

#[cfg(unix)]
fn observe_file(file: &File) -> Result<FileObservation, PortablePlotError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata().map_err(|_| source_capture_error())?;
    Ok(FileObservation {
        identity: FileIdentity::Unix {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        length: metadata.len(),
        modified: metadata.modified().map_err(|_| source_capture_error())?,
    })
}

#[cfg(target_os = "windows")]
fn observe_file(file: &File) -> Result<FileObservation, PortablePlotError> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
    };

    let metadata = file.metadata().map_err(|_| source_capture_error())?;
    let mut identity = FILE_ID_INFO::default();
    let observed = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut identity as *mut FILE_ID_INFO).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>())
                .expect("Windows file identity information size fits u32"),
        )
    };
    if observed == 0 || identity.FileId.Identifier == [0; 16] {
        return Err(source_capture_error());
    }
    Ok(FileObservation {
        identity: FileIdentity::Windows {
            volume_serial_number: identity.VolumeSerialNumber,
            file_id: identity.FileId.Identifier,
        },
        length: metadata.len(),
        modified: metadata.modified().map_err(|_| source_capture_error())?,
    })
}

#[cfg(not(any(unix, target_os = "windows")))]
fn observe_file(_file: &File) -> Result<FileObservation, PortablePlotError> {
    Err(source_capture_error())
}

#[cfg(target_os = "windows")]
const fn source_lock_kind() -> &'static str {
    "windows_share_read_only"
}

#[cfg(unix)]
const fn source_lock_kind() -> &'static str {
    "unix_advisory_shared"
}

#[cfg(not(any(unix, target_os = "windows")))]
const fn source_lock_kind() -> &'static str {
    "unsupported"
}

fn canonical_output_path(path: &Path) -> Result<PathBuf, PortablePlotError> {
    let parent = path.parent().ok_or_else(output_path_error)?;
    let name = path.file_name().ok_or_else(output_path_error)?;
    let parent = std::fs::canonicalize(parent).map_err(|_| output_path_error())?;
    if !parent.is_dir() {
        return Err(output_path_error());
    }
    Ok(parent.join(name))
}

fn stage_pdf(destination: &Path, pdf: &[u8]) -> Result<tempfile::NamedTempFile, PortablePlotError> {
    let parent = destination.parent().ok_or_else(output_path_error)?;
    let mut staged = tempfile::Builder::new()
        .prefix(".autocad-mcp-portable-plot-")
        .suffix(".pdf")
        .tempfile_in(parent)
        .map_err(|_| output_commit_error())?;
    staged
        .write_all(pdf)
        .and_then(|_| staged.flush())
        .and_then(|_| staged.as_file().sync_all())
        .map_err(|_| output_commit_error())?;
    staged
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(|_| output_commit_error())?;
    let mut persisted = Vec::with_capacity(pdf.len());
    staged
        .as_file_mut()
        .read_to_end(&mut persisted)
        .map_err(|_| output_commit_error())?;
    if persisted != pdf || ResourceDigest::of(&persisted) != ResourceDigest::of(pdf) {
        return Err(output_commit_error());
    }
    Ok(staged)
}

fn commit_staged_pdf(
    staged: tempfile::NamedTempFile,
    destination: &Path,
    policy: PortableOutputPolicy,
) -> Result<bool, PortablePlotError> {
    let existed = match std::fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(output_path_error());
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(output_path_error()),
    };
    if existed && policy == PortableOutputPolicy::CreateNew {
        return Err(delivery_error(
            "portable_delivery_output_exists",
            "portable plot destination already exists",
        ));
    }
    if !existed {
        return staged
            .persist_noclobber(destination)
            .map(|_| false)
            .map_err(|_| output_commit_error());
    }
    persist_replacement(staged, destination)?;
    Ok(true)
}

#[cfg(not(target_os = "windows"))]
fn persist_replacement(
    staged: tempfile::NamedTempFile,
    destination: &Path,
) -> Result<(), PortablePlotError> {
    staged
        .persist(destination)
        .map(|_| ())
        .map_err(|_| output_commit_error())
}

#[cfg(target_os = "windows")]
fn persist_replacement(
    staged: tempfile::NamedTempFile,
    destination: &Path,
) -> Result<(), PortablePlotError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    let staged = staged.into_temp_path();
    let replacement = staged
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let replaced = unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            replacement.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if replaced == 0 {
        Err(output_commit_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent_best_effort(path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = File::open(parent).and_then(|directory| directory.sync_all());
    }
}

#[cfg(not(unix))]
fn sync_parent_best_effort(_path: &Path) {}

fn delivery_error(code: &'static str, message: &'static str) -> PortablePlotError {
    PortablePlotError::new(code, message)
}

fn source_capture_error() -> PortablePlotError {
    delivery_error(
        "portable_delivery_source_capture_failed",
        "source drawing could not be captured under the platform file guard",
    )
}

fn source_changed_error() -> PortablePlotError {
    delivery_error(
        "portable_delivery_source_changed",
        "source drawing identity or bytes changed during portable plotting",
    )
}

fn output_path_error() -> PortablePlotError {
    delivery_error(
        "portable_delivery_output_invalid",
        "portable plot destination must be a regular PDF in an existing directory",
    )
}

fn output_commit_error() -> PortablePlotError {
    delivery_error(
        "portable_delivery_output_commit_failed",
        "verified PDF bytes could not be committed atomically",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_options_keep_fidelity_and_replacement_authority_separate() {
        let options = PortablePlotDeliveryOptions::new(
            PortableDeliveryFidelity::CompleteOnly,
            PortableOutputPolicy::CreateNew,
        );
        assert_eq!(options.fidelity, PortableDeliveryFidelity::CompleteOnly);
        assert_eq!(options.output, PortableOutputPolicy::CreateNew);
    }
}
