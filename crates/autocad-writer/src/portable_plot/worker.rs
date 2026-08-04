use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::resources::PortableResourceTransport;
use super::{
    compile_portable_scene_with_resources, encode_portable_pdf, BackendLimitation,
    DisplayListLimits, FidelityDisposition, FontResource, ImageColorSpace, ImageResource,
    PlotCompleteness, PlotStyleResource, PortablePlotError, PortablePlotLimits,
    PortablePlotReceipt, PortableResourceBundle, ResourceDigest, ShxAdmissionOptions,
    ShxCompositeFontResource, ShxStrokeFontResource, XrefResource,
};
use crate::{DrawingFormat, DrawingSnapshot};

const REQUEST_MAGIC: &[u8; 4] = b"P2D1";
const RESPONSE_MAGIC: &[u8; 4] = b"P2DO";
const PROTOCOL_VERSION: u8 = 2;
const RESOURCE_MANIFEST_SCHEMA_VERSION: u32 = 1;
const RECEIPT_SCHEMA_VERSION: u32 = 2;
const MAXIMUM_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

/// One immutable, path-free worker request.
#[derive(Debug, Clone)]
pub struct PortableWorkerRequest {
    snapshot: DrawingSnapshot,
    layout_name: String,
    resources: PortableResourceBundle,
}

impl PortableWorkerRequest {
    pub fn new(
        snapshot: DrawingSnapshot,
        layout_name: impl Into<String>,
    ) -> Result<Self, PortablePlotError> {
        Self::with_resources(snapshot, layout_name, PortableResourceBundle::new())
    }

    pub fn with_resources(
        snapshot: DrawingSnapshot,
        layout_name: impl Into<String>,
        resources: PortableResourceBundle,
    ) -> Result<Self, PortablePlotError> {
        let layout_name = layout_name.into();
        if layout_name.is_empty()
            || layout_name.len() > 1_024
            || layout_name.contains(['\r', '\n', '\0'])
        {
            return Err(PortablePlotError::new(
                "portable_worker_request_invalid",
                "worker layout identity must be bounded and contain no control separators",
            ));
        }
        Ok(Self {
            snapshot,
            layout_name,
            resources,
        })
    }
}

/// Parent-enforced process isolation limits.
#[derive(Debug, Clone, Copy)]
pub struct PortableWorkerLimits {
    pub maximum_request_bytes: usize,
    pub maximum_response_bytes: usize,
    pub maximum_memory_bytes: u64,
    pub wall_time: Duration,
}

impl Default for PortableWorkerLimits {
    fn default() -> Self {
        Self {
            maximum_request_bytes: 320 * 1024 * 1024,
            maximum_response_bytes: 64 * 1024 * 1024,
            maximum_memory_bytes: 1024 * 1024 * 1024,
            wall_time: Duration::from_secs(60),
        }
    }
}

impl PortableWorkerLimits {
    fn validate(self) -> Result<Self, PortablePlotError> {
        if self.maximum_request_bytes == 0
            || self.maximum_response_bytes == 0
            || self.maximum_memory_bytes == 0
            || self.wall_time.is_zero()
        {
            return Err(PortablePlotError::new(
                "portable_worker_limits_invalid",
                "worker byte, memory, and wall-clock limits must be positive",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerWaitDecision {
    Continue,
    Timeout,
}

fn worker_wait_decision(elapsed: Duration, wall_time: Duration) -> WorkerWaitDecision {
    if elapsed >= wall_time {
        WorkerWaitDecision::Timeout
    } else {
        WorkerWaitDecision::Continue
    }
}

/// A portable plot candidate returned together with its mandatory receipt.
#[derive(Debug, Clone)]
pub struct PortableWorkerOutput {
    pdf_bytes: Vec<u8>,
    receipt: PortableWorkerReceipt,
}

impl PortableWorkerOutput {
    pub fn pdf_bytes(&self) -> &[u8] {
        &self.pdf_bytes
    }

    pub fn into_pdf_bytes(self) -> Vec<u8> {
        self.pdf_bytes
    }

    pub fn receipt(&self) -> &PortableWorkerReceipt {
        &self.receipt
    }
}

/// Stable, self-contained development receipt carried across the worker boundary.
#[derive(Debug, Clone)]
pub struct PortableWorkerReceipt {
    json: String,
    completeness: PlotCompleteness,
    encoder: String,
    pdf_sha256: ResourceDigest,
}

impl PortableWorkerReceipt {
    pub fn json(&self) -> &str {
        &self.json
    }

    pub fn completeness(&self) -> PlotCompleteness {
        self.completeness
    }

    pub fn encoder(&self) -> &str {
        &self.encoder
    }

    pub fn pdf_sha256(&self) -> ResourceDigest {
        self.pdf_sha256
    }
}

/// Spawn the dedicated worker, enforcing wall-clock and address-space limits.
///
/// The executable path identifies the repository-built
/// `portable-plot-worker`; drawing and resource paths never cross the
/// boundary.
#[cfg(any(unix, target_os = "windows"))]
pub fn run_portable_worker(
    executable: &Path,
    request: &PortableWorkerRequest,
    limits: PortableWorkerLimits,
) -> Result<PortableWorkerOutput, PortablePlotError> {
    let limits = limits.validate()?;
    let encoded = encode_request(request)?;
    if encoded.len() > limits.maximum_request_bytes {
        return Err(PortablePlotError::new(
            "portable_worker_request_budget_exceeded",
            "encoded worker request exceeds the configured byte limit",
        ));
    }
    let mut process = spawn_limited_worker(executable, limits)?;
    let mut stdin = process.child.stdin.take().ok_or_else(|| {
        PortablePlotError::new(
            "portable_worker_spawn_failed",
            "worker stdin was not available",
        )
    })?;
    let writer = std::thread::spawn(move || stdin.write_all(&encoded));
    let mut stdout = process.child.stdout.take().ok_or_else(|| {
        PortablePlotError::new(
            "portable_worker_spawn_failed",
            "worker stdout was not available",
        )
    })?;
    let response_limit = limits.maximum_response_bytes;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .by_ref()
            .take(response_limit.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = process.child.try_wait().map_err(|_| {
            PortablePlotError::new(
                "portable_worker_wait_failed",
                "worker status could not be observed",
            )
        })? {
            break status;
        }
        if !process.memory_within_limit(limits.maximum_memory_bytes)? {
            process.terminate();
            return Err(PortablePlotError::new(
                "portable_worker_memory_limit_exceeded",
                "worker exceeded the configured physical-memory limit",
            ));
        }
        match worker_wait_decision(started.elapsed(), limits.wall_time) {
            WorkerWaitDecision::Continue => {}
            WorkerWaitDecision::Timeout => {
                process.terminate();
                return Err(PortablePlotError::new(
                    "portable_worker_timeout",
                    "worker exceeded the configured wall-clock limit",
                ));
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    writer
        .join()
        .map_err(|_| worker_io_error())?
        .map_err(|_| worker_io_error())?;
    let response = reader
        .join()
        .map_err(|_| worker_io_error())?
        .map_err(|_| worker_io_error())?;
    if response.len() > limits.maximum_response_bytes {
        return Err(PortablePlotError::new(
            "portable_worker_response_budget_exceeded",
            "worker response exceeds the configured byte limit",
        ));
    }
    if !status.success() {
        return Err(PortablePlotError::new(
            "portable_worker_failed",
            "worker terminated without a successful protocol response",
        ));
    }
    decode_response(&response, request)
}

#[cfg(not(any(unix, target_os = "windows")))]
pub fn run_portable_worker(
    _executable: &Path,
    _request: &PortableWorkerRequest,
    _limits: PortableWorkerLimits,
) -> Result<PortableWorkerOutput, PortablePlotError> {
    Err(PortablePlotError::new(
        "portable_worker_platform_unsupported",
        "portable worker containment is available only on Unix and Windows hosts",
    ))
}

#[cfg(any(unix, target_os = "windows"))]
struct LimitedWorkerProcess {
    child: std::process::Child,
    #[cfg(target_os = "windows")]
    job: WindowsWorkerJob,
}

#[cfg(any(unix, target_os = "windows"))]
impl LimitedWorkerProcess {
    fn memory_within_limit(&self, maximum_memory_bytes: u64) -> Result<bool, PortablePlotError> {
        #[cfg(target_os = "macos")]
        {
            darwin_process_memory_within_limit(self.child.id(), maximum_memory_bytes)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = maximum_memory_bytes;
            Ok(true)
        }
    }

    fn terminate(&mut self) {
        #[cfg(target_os = "windows")]
        self.job.terminate();
        #[cfg(unix)]
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(any(unix, target_os = "windows"))]
impl Drop for LimitedWorkerProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            self.terminate();
        }
    }
}

#[cfg(unix)]
fn spawn_limited_worker(
    executable: &Path,
    limits: PortableWorkerLimits,
) -> Result<LimitedWorkerProcess, PortablePlotError> {
    #[cfg(not(target_os = "macos"))]
    use std::os::unix::process::CommandExt;

    #[cfg(target_os = "macos")]
    let _ = limits;

    let mut command = Command::new(executable);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(not(target_os = "macos"))]
    {
        let memory = libc::rlimit {
            rlim_cur: limits.maximum_memory_bytes as libc::rlim_t,
            rlim_max: limits.maximum_memory_bytes as libc::rlim_t,
        };
        // SAFETY: pre_exec performs the single async-signal-safe setrlimit
        // call, captures only a Copy value, and returns an OS error without
        // allocation. Darwin instead uses parent-observed physical footprint
        // because its RLIMIT_AS/RLIMIT_DATA setters reject useful worker
        // ceilings before exec.
        unsafe {
            command.pre_exec(move || {
                if libc::setrlimit(libc::RLIMIT_AS, &memory) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let child = command.spawn().map_err(|_| worker_spawn_error())?;
    Ok(LimitedWorkerProcess { child })
}

#[cfg(target_os = "macos")]
fn darwin_process_memory_within_limit(
    process_id: u32,
    maximum_memory_bytes: u64,
) -> Result<bool, PortablePlotError> {
    use std::mem::MaybeUninit;

    let mut usage = MaybeUninit::<libc::rusage_info_v2>::zeroed();
    let observed = unsafe {
        libc::proc_pid_rusage(
            libc::c_int::try_from(process_id).map_err(|_| worker_spawn_error())?,
            libc::RUSAGE_INFO_V2,
            usage.as_mut_ptr().cast(),
        )
    };
    if observed != 0 {
        return Err(PortablePlotError::new(
            "portable_worker_wait_failed",
            "worker physical-memory usage could not be observed",
        ));
    }
    let usage = unsafe { usage.assume_init() };
    Ok(usage.ri_phys_footprint.max(usage.ri_resident_size) <= maximum_memory_bytes)
}

#[cfg(target_os = "windows")]
fn spawn_limited_worker(
    executable: &Path,
    limits: PortableWorkerLimits,
) -> Result<LimitedWorkerProcess, PortablePlotError> {
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

    let job = WindowsWorkerJob::new(limits.maximum_memory_bytes)?;
    let mut command = Command::new(executable);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_SUSPENDED);
    let mut child = command.spawn().map_err(|_| worker_spawn_error())?;
    let process = child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    if job.assign(process).is_err() || resume_suspended_worker(child.id()).is_err() {
        job.terminate();
        let _ = child.wait();
        return Err(worker_spawn_error());
    }
    Ok(LimitedWorkerProcess { child, job })
}

#[cfg(target_os = "windows")]
struct WindowsWorkerJob(windows_sys::Win32::Foundation::HANDLE);

#[cfg(target_os = "windows")]
impl WindowsWorkerJob {
    fn new(maximum_memory_bytes: u64) -> Result<Self, PortablePlotError> {
        use std::ffi::c_void;
        use std::mem::size_of;
        use std::ptr::null;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        };

        let handle = unsafe { CreateJobObjectW(null(), null()) };
        if handle.is_null() {
            return Err(worker_spawn_error());
        }
        let job = Self(handle);
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        information.ProcessMemoryLimit =
            usize::try_from(maximum_memory_bytes).map_err(|_| worker_spawn_error())?;
        let configured = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&information as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .expect("Windows Job Object information size fits u32"),
            )
        };
        if configured == 0 {
            return Err(worker_spawn_error());
        }
        Ok(job)
    }

    fn assign(
        &self,
        process: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), PortablePlotError> {
        let assigned = unsafe {
            windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(self.0, process)
        };
        if assigned == 0 {
            Err(worker_spawn_error())
        } else {
            Ok(())
        }
    }

    fn terminate(&self) {
        unsafe {
            let _ = windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0, 124);
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsWorkerJob {
    fn drop(&mut self) {
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(target_os = "windows")]
fn resume_suspended_worker(process_id: u32) -> Result<(), PortablePlotError> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_NO_MORE_FILES};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(worker_spawn_error());
    }
    let mut entry = THREADENTRY32 {
        dwSize: u32::try_from(size_of::<THREADENTRY32>())
            .expect("Windows thread entry size fits u32"),
        ..THREADENTRY32::default()
    };
    let mut thread_id = None;
    let first = unsafe { Thread32First(snapshot, &mut entry) };
    if first != 0 {
        loop {
            if entry.th32OwnerProcessID == process_id
                && thread_id.replace(entry.th32ThreadID).is_some()
            {
                thread_id = None;
                break;
            }
            if unsafe { Thread32Next(snapshot, &mut entry) } == 0 {
                let error = unsafe { GetLastError() };
                if error != ERROR_NO_MORE_FILES {
                    thread_id = None;
                }
                break;
            }
        }
    }
    unsafe {
        let _ = CloseHandle(snapshot);
    }
    let thread_id = thread_id.ok_or_else(worker_spawn_error)?;
    let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id) };
    if thread.is_null() {
        return Err(worker_spawn_error());
    }
    let previous = unsafe { ResumeThread(thread) };
    unsafe {
        let _ = CloseHandle(thread);
    }
    if previous != 1 {
        return Err(worker_spawn_error());
    }
    Ok(())
}

fn worker_spawn_error() -> PortablePlotError {
    PortablePlotError::new(
        "portable_worker_spawn_failed",
        "the dedicated portable plot worker could not be started inside its process limits",
    )
}

/// Entry point used only by the dedicated worker binary.
#[doc(hidden)]
pub fn run_worker_stdio() -> Result<(), PortablePlotError> {
    let mut input = Vec::new();
    let input_limit = u64::try_from(PortableWorkerLimits::default().maximum_request_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    std::io::stdin()
        .take(input_limit)
        .read_to_end(&mut input)
        .map_err(|_| worker_io_error())?;
    let result = decode_request(&input).and_then(|request| {
        let compilation = compile_portable_scene_with_resources(
            &request.snapshot,
            &request.layout_name,
            &request.resources,
            PortablePlotLimits::default(),
        )?;
        let scene = compilation.display_list().ok_or_else(|| {
            PortablePlotError::new(
                "portable_worker_scene_rejected",
                "semantic fidelity rejected the source before PDF encoding",
            )
        })?;
        let pdf = encode_portable_pdf(scene, DisplayListLimits::default())?;
        let receipt = encode_receipt(compilation.receipt(), pdf.encoder(), pdf.bytes())?;
        Ok((receipt, pdf.into_bytes()))
    });
    let response = match result {
        Ok((receipt, bytes)) => encode_success_response(&receipt, &bytes)?,
        Err(error) => encode_response(1, error.code().as_bytes())?,
    };
    std::io::stdout()
        .write_all(&response)
        .map_err(|_| worker_io_error())
}

fn encode_request(request: &PortableWorkerRequest) -> Result<Vec<u8>, PortablePlotError> {
    let source = request.snapshot.bytes();
    let layout = request.layout_name.as_bytes();
    let layout_len = u32::try_from(layout.len()).map_err(|_| request_error())?;
    let source_len = u64::try_from(source.len()).map_err(|_| request_error())?;
    let (manifest, resource_blob) = encode_resource_manifest(&request.resources)?;
    if manifest.len() > MAXIMUM_MANIFEST_BYTES {
        return Err(PortablePlotError::new(
            "portable_worker_resource_budget_exceeded",
            "worker resource manifest exceeds the fixed byte budget",
        ));
    }
    let manifest_len = u32::try_from(manifest.len()).map_err(|_| request_error())?;
    let resource_len = u64::try_from(resource_blob.len()).map_err(|_| request_error())?;
    let mut output = Vec::with_capacity(
        4_usize
            .saturating_add(1)
            .saturating_add(1)
            .saturating_add(4)
            .saturating_add(8)
            .saturating_add(4)
            .saturating_add(8)
            .saturating_add(32)
            .saturating_add(32)
            .saturating_add(layout.len())
            .saturating_add(source.len())
            .saturating_add(manifest.len())
            .saturating_add(resource_blob.len()),
    );
    output.extend_from_slice(REQUEST_MAGIC);
    output.push(PROTOCOL_VERSION);
    output.push(match request.snapshot.format() {
        DrawingFormat::Dwg => 1,
        DrawingFormat::Dxf => 2,
    });
    output.extend_from_slice(&layout_len.to_be_bytes());
    output.extend_from_slice(&source_len.to_be_bytes());
    output.extend_from_slice(&manifest_len.to_be_bytes());
    output.extend_from_slice(&resource_len.to_be_bytes());
    output.extend_from_slice(&Sha256::digest(&source));
    output.extend_from_slice(&Sha256::digest(&resource_blob));
    output.extend_from_slice(layout);
    output.extend_from_slice(&source);
    output.extend_from_slice(&manifest);
    output.extend_from_slice(&resource_blob);
    Ok(output)
}

fn decode_request(bytes: &[u8]) -> Result<PortableWorkerRequest, PortablePlotError> {
    const HEADER: usize = 4 + 1 + 1 + 4 + 8 + 4 + 8 + 32 + 32;
    if bytes.len() < HEADER || &bytes[..4] != REQUEST_MAGIC || bytes[4] != PROTOCOL_VERSION {
        return Err(request_error());
    }
    let format = match bytes[5] {
        1 => DrawingFormat::Dwg,
        2 => DrawingFormat::Dxf,
        _ => return Err(request_error()),
    };
    let layout_len = usize::try_from(u32::from_be_bytes(
        bytes[6..10].try_into().map_err(|_| request_error())?,
    ))
    .map_err(|_| request_error())?;
    let source_len = usize::try_from(u64::from_be_bytes(
        bytes[10..18].try_into().map_err(|_| request_error())?,
    ))
    .map_err(|_| request_error())?;
    let manifest_len = usize::try_from(u32::from_be_bytes(
        bytes[18..22].try_into().map_err(|_| request_error())?,
    ))
    .map_err(|_| request_error())?;
    let resource_len = usize::try_from(u64::from_be_bytes(
        bytes[22..30].try_into().map_err(|_| request_error())?,
    ))
    .map_err(|_| request_error())?;
    if manifest_len > MAXIMUM_MANIFEST_BYTES {
        return Err(PortablePlotError::new(
            "portable_worker_resource_budget_exceeded",
            "worker resource manifest exceeds the fixed byte budget",
        ));
    }
    let plot_limits = PortablePlotLimits::default();
    if source_len > plot_limits.max_source_bytes || resource_len > plot_limits.max_dependency_bytes
    {
        return Err(PortablePlotError::new(
            "portable_worker_resource_budget_exceeded",
            "worker source or dependency bytes exceed the portable plot budget",
        ));
    }
    let expected = HEADER
        .checked_add(layout_len)
        .and_then(|length| length.checked_add(source_len))
        .and_then(|length| length.checked_add(manifest_len))
        .and_then(|length| length.checked_add(resource_len))
        .ok_or_else(request_error)?;
    if bytes.len() != expected {
        return Err(request_error());
    }
    let layout_end = HEADER + layout_len;
    let layout = std::str::from_utf8(&bytes[HEADER..layout_end]).map_err(|_| request_error())?;
    let source_end = layout_end + source_len;
    let manifest_end = source_end + manifest_len;
    let source = &bytes[layout_end..source_end];
    let manifest = &bytes[source_end..manifest_end];
    let resource_blob = &bytes[manifest_end..];
    if Sha256::digest(source).as_slice() != &bytes[30..62]
        || Sha256::digest(resource_blob).as_slice() != &bytes[62..94]
    {
        return Err(PortablePlotError::new(
            "portable_worker_digest_mismatch",
            "worker request source or resource bytes do not match their SHA-256 binding",
        ));
    }
    let resources = decode_resource_manifest(manifest, resource_blob, plot_limits)?;
    PortableWorkerRequest::with_resources(
        DrawingSnapshot::new(format, Arc::<[u8]>::from(source)),
        layout,
        resources,
    )
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceManifest {
    schema_version: u32,
    resources: Vec<ResourceManifestEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ResourceManifestEntry {
    Font {
        binding_identity: String,
        fallback: bool,
        logical_identity: String,
        face_index: u32,
        sha256: String,
        offset: u64,
        length: u64,
    },
    StrokeFont {
        binding_identity: String,
        logical_identity: String,
        source_format: String,
        semantic_sha256: String,
        legacy_code_points: Vec<LegacyCodePoint>,
        sha256: String,
        offset: u64,
        length: u64,
    },
    CompositeStrokeFont {
        primary_binding_identity: String,
        big_binding_identity: String,
        logical_identity: String,
        semantic_sha256: String,
        sha256: String,
        offset: u64,
        length: u64,
    },
    Image {
        binding_identity: String,
        logical_identity: String,
        width: u32,
        height: u32,
        color_space: WireImageColorSpace,
        sha256: String,
        offset: u64,
        length: u64,
    },
    PlotStyle {
        binding_identity: String,
        logical_identity: String,
        source_format: String,
        semantic_sha256: String,
        sha256: String,
        offset: u64,
        length: u64,
    },
    Xref {
        binding_identity: String,
        logical_identity: String,
        format: WireDrawingFormat,
        sha256: String,
        offset: u64,
        length: u64,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireImageColorSpace {
    Gray8,
    Rgb8,
    Rgba8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireDrawingFormat {
    Dwg,
    Dxf,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCodePoint {
    shape_code: u16,
    unicode_scalar: u32,
}

fn encode_resource_manifest(
    resources: &PortableResourceBundle,
) -> Result<(Vec<u8>, Vec<u8>), PortablePlotError> {
    let transports = resources.transport_entries();
    if transports.len() > PortablePlotLimits::default().max_dependency_members {
        return Err(resource_budget_error());
    }
    let mut blob = Vec::with_capacity(resources.total_bytes()?);
    let mut manifest = Vec::with_capacity(transports.len());
    for transport in transports {
        manifest.push(encode_resource_entry(transport, &mut blob)?);
    }
    if blob.len() > PortablePlotLimits::default().max_dependency_bytes {
        return Err(resource_budget_error());
    }
    let manifest = serde_json::to_vec(&ResourceManifest {
        schema_version: RESOURCE_MANIFEST_SCHEMA_VERSION,
        resources: manifest,
    })
    .map_err(|_| request_error())?;
    Ok((manifest, blob))
}

fn encode_resource_entry(
    transport: PortableResourceTransport,
    blob: &mut Vec<u8>,
) -> Result<ResourceManifestEntry, PortablePlotError> {
    let (offset, length, digest) = match &transport {
        PortableResourceTransport::Font { bytes, digest, .. }
        | PortableResourceTransport::StrokeFont { bytes, digest, .. }
        | PortableResourceTransport::CompositeStrokeFont { bytes, digest, .. }
        | PortableResourceTransport::Image { bytes, digest, .. }
        | PortableResourceTransport::PlotStyle { bytes, digest, .. }
        | PortableResourceTransport::Xref { bytes, digest, .. } => {
            if ResourceDigest::of(bytes) != *digest {
                return Err(resource_transport_error());
            }
            let offset = u64::try_from(blob.len()).map_err(|_| resource_budget_error())?;
            let length = u64::try_from(bytes.len()).map_err(|_| resource_budget_error())?;
            blob.extend_from_slice(bytes);
            (offset, length, digest.to_hex())
        }
    };
    Ok(match transport {
        PortableResourceTransport::Font {
            binding_identity,
            fallback,
            logical_identity,
            face_index,
            ..
        } => ResourceManifestEntry::Font {
            binding_identity,
            fallback,
            logical_identity,
            face_index,
            sha256: digest,
            offset,
            length,
        },
        PortableResourceTransport::StrokeFont {
            binding_identity,
            logical_identity,
            source_format,
            semantic_digest,
            legacy_code_points,
            ..
        } => ResourceManifestEntry::StrokeFont {
            binding_identity,
            logical_identity,
            source_format,
            semantic_sha256: semantic_digest.to_hex(),
            legacy_code_points: legacy_code_points
                .into_iter()
                .map(|(shape_code, character)| LegacyCodePoint {
                    shape_code,
                    unicode_scalar: u32::from(character),
                })
                .collect(),
            sha256: digest,
            offset,
            length,
        },
        PortableResourceTransport::CompositeStrokeFont {
            primary_binding_identity,
            big_binding_identity,
            logical_identity,
            semantic_digest,
            ..
        } => ResourceManifestEntry::CompositeStrokeFont {
            primary_binding_identity,
            big_binding_identity,
            logical_identity,
            semantic_sha256: semantic_digest.to_hex(),
            sha256: digest,
            offset,
            length,
        },
        PortableResourceTransport::Image {
            binding_identity,
            logical_identity,
            width,
            height,
            color_space,
            ..
        } => ResourceManifestEntry::Image {
            binding_identity,
            logical_identity,
            width,
            height,
            color_space: match color_space {
                ImageColorSpace::Gray8 => WireImageColorSpace::Gray8,
                ImageColorSpace::Rgb8 => WireImageColorSpace::Rgb8,
                ImageColorSpace::Rgba8 => WireImageColorSpace::Rgba8,
            },
            sha256: digest,
            offset,
            length,
        },
        PortableResourceTransport::PlotStyle {
            binding_identity,
            logical_identity,
            source_format,
            semantic_digest,
            ..
        } => ResourceManifestEntry::PlotStyle {
            binding_identity,
            logical_identity,
            source_format,
            semantic_sha256: semantic_digest.to_hex(),
            sha256: digest,
            offset,
            length,
        },
        PortableResourceTransport::Xref {
            binding_identity,
            logical_identity,
            format,
            ..
        } => ResourceManifestEntry::Xref {
            binding_identity,
            logical_identity,
            format: match format {
                DrawingFormat::Dwg => WireDrawingFormat::Dwg,
                DrawingFormat::Dxf => WireDrawingFormat::Dxf,
            },
            sha256: digest,
            offset,
            length,
        },
    })
}

fn decode_resource_manifest(
    manifest: &[u8],
    blob: &[u8],
    limits: PortablePlotLimits,
) -> Result<PortableResourceBundle, PortablePlotError> {
    let manifest: ResourceManifest =
        serde_json::from_slice(manifest).map_err(|_| resource_transport_error())?;
    if manifest.schema_version != RESOURCE_MANIFEST_SCHEMA_VERSION
        || manifest.resources.len() > limits.max_dependency_members
        || blob.len() > limits.max_dependency_bytes
    {
        return Err(resource_budget_error());
    }
    let mut bundle = PortableResourceBundle::new();
    let mut cursor = 0_usize;
    for entry in manifest.resources {
        decode_resource_entry(entry, blob, &mut cursor, &mut bundle)?;
    }
    if cursor != blob.len() || bundle.total_bytes()? != blob.len() {
        return Err(resource_transport_error());
    }
    Ok(bundle)
}

fn decode_resource_entry(
    entry: ResourceManifestEntry,
    blob: &[u8],
    cursor: &mut usize,
    bundle: &mut PortableResourceBundle,
) -> Result<(), PortablePlotError> {
    match entry {
        ResourceManifestEntry::Font {
            binding_identity,
            fallback,
            logical_identity,
            face_index,
            sha256,
            offset,
            length,
        } => {
            let (bytes, digest) = decode_resource_bytes(blob, cursor, offset, length, &sha256)?;
            let resource = FontResource::new(logical_identity, bytes, face_index, digest)?;
            if fallback {
                if !binding_identity.is_empty() {
                    return Err(resource_transport_error());
                }
                bundle.bind_fallback_font(resource)
            } else {
                bundle.bind_font(binding_identity, resource)
            }
        }
        ResourceManifestEntry::StrokeFont {
            binding_identity,
            logical_identity,
            source_format,
            semantic_sha256,
            legacy_code_points,
            sha256,
            offset,
            length,
        } => {
            let (bytes, digest) = decode_resource_bytes(blob, cursor, offset, length, &sha256)?;
            let mut options = ShxAdmissionOptions::new();
            for mapping in legacy_code_points {
                let character =
                    char::from_u32(mapping.unicode_scalar).ok_or_else(resource_transport_error)?;
                options = options.with_legacy_code_point(mapping.shape_code, character)?;
            }
            let resource = if source_format == "portable_shx_v1" {
                if !options.legacy_code_points().is_empty() {
                    return Err(resource_transport_error());
                }
                ShxStrokeFontResource::new(logical_identity, bytes, digest)?
            } else {
                ShxStrokeFontResource::from_shx(logical_identity, bytes, digest, &options)?
            };
            if resource.source_format() != source_format
                || resource.semantic_digest() != ResourceDigest::from_hex(&semantic_sha256)?
            {
                return Err(resource_transport_error());
            }
            bundle.bind_shx_stroke_font(binding_identity, resource)
        }
        ResourceManifestEntry::CompositeStrokeFont {
            primary_binding_identity,
            big_binding_identity,
            logical_identity,
            semantic_sha256,
            sha256,
            offset,
            length,
        } => {
            let (bytes, digest) = decode_resource_bytes(blob, cursor, offset, length, &sha256)?;
            let resource = ShxCompositeFontResource::new(logical_identity, bytes, digest)?;
            if resource.semantic_digest() != ResourceDigest::from_hex(&semantic_sha256)? {
                return Err(resource_transport_error());
            }
            bundle.bind_shx_composite_font(primary_binding_identity, big_binding_identity, resource)
        }
        ResourceManifestEntry::Image {
            binding_identity,
            logical_identity,
            width,
            height,
            color_space,
            sha256,
            offset,
            length,
        } => {
            let (bytes, digest) = decode_resource_bytes(blob, cursor, offset, length, &sha256)?;
            let resource = ImageResource::new(
                logical_identity,
                width,
                height,
                match color_space {
                    WireImageColorSpace::Gray8 => ImageColorSpace::Gray8,
                    WireImageColorSpace::Rgb8 => ImageColorSpace::Rgb8,
                    WireImageColorSpace::Rgba8 => ImageColorSpace::Rgba8,
                },
                bytes,
                digest,
            )?;
            bundle.bind_image(binding_identity, resource)
        }
        ResourceManifestEntry::PlotStyle {
            binding_identity,
            logical_identity,
            source_format,
            semantic_sha256,
            sha256,
            offset,
            length,
        } => {
            let (bytes, digest) = decode_resource_bytes(blob, cursor, offset, length, &sha256)?;
            let resource = match source_format.as_str() {
                "portable_ctb_v1" => PlotStyleResource::new(logical_identity, bytes, digest)?,
                "autodesk_ctb_v1" => PlotStyleResource::from_ctb(logical_identity, bytes, digest)?,
                _ => return Err(resource_transport_error()),
            };
            if resource.source_format() != source_format
                || resource.semantic_digest() != ResourceDigest::from_hex(&semantic_sha256)?
            {
                return Err(resource_transport_error());
            }
            bundle.bind_plot_style(binding_identity, resource)
        }
        ResourceManifestEntry::Xref {
            binding_identity,
            logical_identity,
            format,
            sha256,
            offset,
            length,
        } => {
            let (bytes, digest) = decode_resource_bytes(blob, cursor, offset, length, &sha256)?;
            let snapshot = DrawingSnapshot::new(
                match format {
                    WireDrawingFormat::Dwg => DrawingFormat::Dwg,
                    WireDrawingFormat::Dxf => DrawingFormat::Dxf,
                },
                bytes,
            );
            let resource = XrefResource::new(logical_identity, snapshot, digest)?;
            bundle.bind_xref(binding_identity, resource)
        }
    }
}

fn decode_resource_bytes(
    blob: &[u8],
    cursor: &mut usize,
    offset: u64,
    length: u64,
    sha256: &str,
) -> Result<(Arc<[u8]>, ResourceDigest), PortablePlotError> {
    let offset = usize::try_from(offset).map_err(|_| resource_transport_error())?;
    let length = usize::try_from(length).map_err(|_| resource_transport_error())?;
    if offset != *cursor {
        return Err(resource_transport_error());
    }
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= blob.len())
        .ok_or_else(resource_transport_error)?;
    let bytes = Arc::<[u8]>::from(&blob[offset..end]);
    let digest = ResourceDigest::from_hex(sha256)?;
    if ResourceDigest::of(&bytes) != digest {
        return Err(PortablePlotError::new(
            "portable_worker_digest_mismatch",
            "worker resource bytes do not match their manifest SHA-256 binding",
        ));
    }
    *cursor = end;
    Ok((bytes, digest))
}

fn encode_response(status: u8, body: &[u8]) -> Result<Vec<u8>, PortablePlotError> {
    let length = u64::try_from(body.len()).map_err(|_| worker_io_error())?;
    let mut output = Vec::with_capacity(4 + 1 + 8 + body.len());
    output.extend_from_slice(RESPONSE_MAGIC);
    output.push(status);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(body);
    Ok(output)
}

fn encode_success_response(receipt: &[u8], pdf: &[u8]) -> Result<Vec<u8>, PortablePlotError> {
    let receipt_length = u32::try_from(receipt.len()).map_err(|_| worker_io_error())?;
    let mut body = Vec::with_capacity(4 + receipt.len() + pdf.len());
    body.extend_from_slice(&receipt_length.to_be_bytes());
    body.extend_from_slice(receipt);
    body.extend_from_slice(pdf);
    encode_response(0, &body)
}

fn decode_response(
    bytes: &[u8],
    request: &PortableWorkerRequest,
) -> Result<PortableWorkerOutput, PortablePlotError> {
    const HEADER: usize = 4 + 1 + 8;
    if bytes.len() < HEADER || &bytes[..4] != RESPONSE_MAGIC {
        return Err(worker_io_error());
    }
    let length = usize::try_from(u64::from_be_bytes(
        bytes[5..13].try_into().map_err(|_| worker_io_error())?,
    ))
    .map_err(|_| worker_io_error())?;
    if bytes.len() != HEADER.checked_add(length).ok_or_else(worker_io_error)? {
        return Err(worker_io_error());
    }
    if bytes[4] != 0 {
        return Err(PortablePlotError::new(
            "portable_worker_semantic_failure",
            "worker rejected the request; the response carries only a stable private error code",
        ));
    }
    let body = &bytes[HEADER..];
    if body.len() < 4 {
        return Err(worker_io_error());
    }
    let receipt_length = usize::try_from(u32::from_be_bytes(
        body[..4].try_into().map_err(|_| worker_io_error())?,
    ))
    .map_err(|_| worker_io_error())?;
    let receipt_end = 4_usize
        .checked_add(receipt_length)
        .ok_or_else(worker_io_error)?;
    if receipt_end > body.len() {
        return Err(worker_io_error());
    }
    let json = std::str::from_utf8(&body[4..receipt_end])
        .map_err(|_| worker_io_error())?
        .to_owned();
    let envelope: ReceiptEnvelope = serde_json::from_str(&json).map_err(|_| worker_io_error())?;
    let completeness = parse_completeness(&envelope.completeness)?;
    let pdf_bytes = body[receipt_end..].to_vec();
    let pdf_sha256 = ResourceDigest::of(&pdf_bytes);
    if envelope.schema_version != RECEIPT_SCHEMA_VERSION
        || envelope.profile != "portable_2d_v1"
        || envelope.semantic_renderer != "autocad_writer_semantic_compiler_v1"
        || envelope.encoder != "krilla-0.8.2-pdf-1.4"
        || envelope.source.sha256 != ResourceDigest::of(request.snapshot.bytes().as_ref()).to_hex()
        || envelope.source.selected_layout.name != request.layout_name
        || completeness == PlotCompleteness::Rejected
        || envelope.partial_output != (completeness == PlotCompleteness::Partial)
        || envelope.output.pdf_bytes != pdf_bytes.len()
        || ResourceDigest::from_hex(&envelope.output.pdf_sha256)? != pdf_sha256
        || !receipt_resources_are_bound(&envelope.resources, request)?
    {
        return Err(worker_io_error());
    }
    if !pdf_bytes.starts_with(b"%PDF-1.4") || !pdf_bytes.ends_with(b"%%EOF") {
        return Err(worker_io_error());
    }
    Ok(PortableWorkerOutput {
        pdf_bytes,
        receipt: PortableWorkerReceipt {
            json,
            completeness,
            encoder: envelope.encoder,
            pdf_sha256,
        },
    })
}

#[derive(Deserialize)]
struct ReceiptEnvelope {
    schema_version: u32,
    profile: String,
    semantic_renderer: String,
    completeness: String,
    partial_output: bool,
    encoder: String,
    source: ReceiptSourceEnvelope,
    resources: Vec<ReceiptResourceEnvelope>,
    output: ReceiptOutputEnvelope,
}

#[derive(Deserialize)]
struct ReceiptSourceEnvelope {
    sha256: String,
    selected_layout: ReceiptLayoutEnvelope,
}

#[derive(Deserialize)]
struct ReceiptLayoutEnvelope {
    name: String,
}

#[derive(Deserialize)]
struct ReceiptResourceEnvelope {
    kind: String,
    logical_identity: String,
    sha256: String,
    source_format: Option<String>,
    semantic_sha256: Option<String>,
}

#[derive(Deserialize)]
struct ReceiptOutputEnvelope {
    pdf_bytes: usize,
    pdf_sha256: String,
}

fn encode_receipt(
    receipt: &PortablePlotReceipt,
    encoder: &str,
    pdf: &[u8],
) -> Result<Vec<u8>, PortablePlotError> {
    let fidelity = receipt.fidelity();
    let source = receipt.source();
    let selected_layout = source.selected_layout();
    let limits = receipt.limits();
    let display_limits = limits.display_list;
    let totals = fidelity.totals();
    let source_counts = fidelity
        .source_counts()
        .iter()
        .map(|(source_type, counts)| (source_type.clone(), disposition_counts(*counts)))
        .collect::<serde_json::Map<_, _>>();
    let representatives = fidelity
        .representative_diagnostics()
        .iter()
        .map(|diagnostic| {
            json!({
                "code": diagnostic.code(),
                "source_type": diagnostic.source_type(),
                "source_handle": diagnostic.source_handle().map(|handle| handle.as_str()),
                "disposition": disposition_name(diagnostic.disposition()),
                "message": diagnostic.message(),
            })
        })
        .collect::<Vec<_>>();
    let tolerances = fidelity
        .tolerances()
        .iter()
        .map(|tolerance| {
            json!({
                "name": tolerance.name(),
                "maximum_error_points": tolerance.maximum_error_points(),
            })
        })
        .collect::<Vec<_>>();
    let limitations = source
        .limitations()
        .iter()
        .map(|limitation| match limitation {
            BackendLimitation::TransparencyInheritanceUnavailable => {
                "transparency_inheritance_unavailable"
            }
            BackendLimitation::NonzeroBlockBasePointUnqualified => {
                "nonzero_block_base_point_unqualified"
            }
            BackendLimitation::ExternalDependenciesRequireBundle => {
                "external_dependencies_require_bundle"
            }
            BackendLimitation::StaleBlockInsertIndexIgnored => "stale_block_insert_index_ignored",
        })
        .collect::<Vec<_>>();
    let resources = receipt
        .resources()
        .iter()
        .map(|resource| {
            json!({
                "kind": resource.kind(),
                "logical_identity": resource.logical_identity(),
                "sha256": resource.digest().to_hex(),
                "source_format": resource.source_format(),
                "semantic_sha256": resource.semantic_digest().map(ResourceDigest::to_hex),
            })
        })
        .collect::<Vec<_>>();
    let usage = receipt.usage().map(|usage| {
        json!({
            "nodes": usage.nodes,
            "expanded_nodes": usage.expanded_nodes,
            "path_commands": usage.path_commands,
            "expanded_path_commands": usage.expanded_path_commands,
            "glyphs": usage.glyphs,
            "expanded_glyphs": usage.expanded_glyphs,
            "text_bytes": usage.text_bytes,
            "font_bytes": usage.font_bytes,
            "groups": usage.groups,
            "images": usage.images,
            "expanded_images": usage.expanded_images,
            "image_bytes": usage.image_bytes,
            "image_pixels": usage.image_pixels,
            "maximum_group_depth": usage.maximum_group_depth,
            "maximum_graphics_state_depth": usage.maximum_graphics_state_depth,
        })
    });
    let counts = source.counts();
    let completeness = completeness_name(fidelity.completeness());
    let value = json!({
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "profile": receipt.profile(),
        "semantic_renderer": receipt.renderer(),
        "encoder": encoder,
        "completeness": completeness,
        "partial_output": fidelity.completeness() == PlotCompleteness::Partial,
        "source": {
            "sha256": source.source_digest().to_hex(),
            "bytes": source.source_bytes(),
            "format": source.format().name(),
            "version": source.source_version(),
            "selected_layout": {
                "handle": selected_layout.handle().as_str(),
                "name": selected_layout.name(),
                "is_model": selected_layout.is_model(),
                "paper_width_mm": selected_layout.paper_width_mm(),
                "paper_height_mm": selected_layout.paper_height_mm(),
                "viewport_handles": selected_layout.viewport_handles()
                    .iter().map(|handle| handle.as_str()).collect::<Vec<_>>(),
                "requests_plot_styles": selected_layout.requests_plot_styles(),
            },
            "counts": {
                "entities": counts.entities,
                "layers": counts.layers,
                "block_definitions": counts.block_definitions,
                "block_inserts": counts.block_inserts,
                "layouts": counts.layouts,
                "viewports": counts.viewports,
                "linetypes": counts.linetypes,
                "text_styles": counts.text_styles,
                "dimension_styles": counts.dimension_styles,
                "plot_settings": counts.plot_settings,
                "external_dependencies": counts.external_dependencies,
            },
            "entity_counts": source.entity_counts(),
            "backend_limitations": limitations,
        },
        "limits": {
            "max_source_bytes": limits.max_source_bytes,
            "max_source_entities": limits.max_source_entities,
            "max_insert_depth": limits.max_insert_depth,
            "max_insert_instances": limits.max_insert_instances,
            "max_curve_segments": limits.max_curve_segments,
            "max_dependency_members": limits.max_dependency_members,
            "max_dependency_bytes": limits.max_dependency_bytes,
            "curve_tolerance_points": limits.curve_tolerance_points,
            "representative_diagnostics": limits.representative_diagnostics,
            "display_list": {
                "max_output_bytes": display_limits.max_output_bytes,
                "max_nodes": display_limits.max_nodes,
                "max_expanded_nodes": display_limits.max_expanded_nodes,
                "max_path_commands": display_limits.max_path_commands,
                "max_expanded_path_commands": display_limits.max_expanded_path_commands,
                "max_glyphs": display_limits.max_glyphs,
                "max_expanded_glyphs": display_limits.max_expanded_glyphs,
                "max_text_bytes": display_limits.max_text_bytes,
                "max_font_bytes": display_limits.max_font_bytes,
                "max_groups": display_limits.max_groups,
                "max_group_depth": display_limits.max_group_depth,
                "max_graphics_state_depth": display_limits.max_graphics_state_depth,
                "max_images": display_limits.max_images,
                "max_image_bytes": display_limits.max_image_bytes,
                "max_image_pixels": display_limits.max_image_pixels,
            },
        },
        "fidelity": {
            "totals": disposition_counts(totals),
            "diagnostic_counts": fidelity.diagnostic_counts(),
            "source_counts": Value::Object(source_counts),
            "representative_diagnostics": representatives,
            "tolerances": tolerances,
        },
        "display_list_usage": usage,
        "rendered_viewports": receipt.rendered_viewports(),
        "resources": resources,
        "output": {
            "pdf_bytes": pdf.len(),
            "pdf_sha256": ResourceDigest::of(pdf).to_hex(),
        },
    });
    serde_json::to_vec(&value).map_err(|_| worker_io_error())
}

fn disposition_counts(counts: super::DispositionCounts) -> Value {
    json!({
        "exact": counts.exact,
        "tolerance_bounded": counts.tolerance_bounded,
        "substituted": counts.substituted,
        "omitted": counts.omitted,
        "unsupported": counts.unsupported,
        "invalid": counts.invalid,
    })
}

fn disposition_name(disposition: FidelityDisposition) -> &'static str {
    match disposition {
        FidelityDisposition::Exact => "exact",
        FidelityDisposition::ToleranceBounded => "tolerance_bounded",
        FidelityDisposition::Substituted => "substituted",
        FidelityDisposition::Omitted => "omitted",
        FidelityDisposition::Unsupported => "unsupported",
        FidelityDisposition::Invalid => "invalid",
    }
}

fn completeness_name(completeness: PlotCompleteness) -> &'static str {
    match completeness {
        PlotCompleteness::Complete => "complete",
        PlotCompleteness::Partial => "partial",
        PlotCompleteness::Rejected => "rejected",
    }
}

fn parse_completeness(value: &str) -> Result<PlotCompleteness, PortablePlotError> {
    match value {
        "complete" => Ok(PlotCompleteness::Complete),
        "partial" => Ok(PlotCompleteness::Partial),
        "rejected" => Ok(PlotCompleteness::Rejected),
        _ => Err(worker_io_error()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ResourceSignature {
    kind: String,
    logical_identity: String,
    sha256: String,
    source_format: Option<String>,
    semantic_sha256: Option<String>,
}

fn receipt_resources_are_bound(
    resources: &[ReceiptResourceEnvelope],
    request: &PortableWorkerRequest,
) -> Result<bool, PortablePlotError> {
    let admitted = request
        .resources
        .transport_entries()
        .into_iter()
        .map(resource_signature)
        .collect::<BTreeSet<_>>();
    let mut receipted = BTreeSet::new();
    for resource in resources {
        ResourceDigest::from_hex(&resource.sha256)?;
        if let Some(digest) = &resource.semantic_sha256 {
            ResourceDigest::from_hex(digest)?;
        }
        let signature = ResourceSignature {
            kind: resource.kind.clone(),
            logical_identity: resource.logical_identity.clone(),
            sha256: resource.sha256.to_ascii_lowercase(),
            source_format: resource.source_format.clone(),
            semantic_sha256: resource
                .semantic_sha256
                .as_ref()
                .map(|digest| digest.to_ascii_lowercase()),
        };
        if !admitted.contains(&signature) || !receipted.insert(signature) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn resource_signature(resource: PortableResourceTransport) -> ResourceSignature {
    match resource {
        PortableResourceTransport::Font {
            logical_identity,
            digest,
            ..
        } => ResourceSignature {
            kind: "font".to_string(),
            logical_identity,
            sha256: digest.to_hex(),
            source_format: None,
            semantic_sha256: None,
        },
        PortableResourceTransport::StrokeFont {
            logical_identity,
            source_format,
            semantic_digest,
            digest,
            ..
        } => ResourceSignature {
            kind: "stroke_font".to_string(),
            logical_identity,
            sha256: digest.to_hex(),
            source_format: Some(source_format),
            semantic_sha256: Some(semantic_digest.to_hex()),
        },
        PortableResourceTransport::CompositeStrokeFont {
            logical_identity,
            semantic_digest,
            digest,
            ..
        } => ResourceSignature {
            kind: "stroke_font_composite".to_string(),
            logical_identity,
            sha256: digest.to_hex(),
            source_format: Some("portable_shx_composite_v1".to_string()),
            semantic_sha256: Some(semantic_digest.to_hex()),
        },
        PortableResourceTransport::Image {
            logical_identity,
            digest,
            ..
        } => ResourceSignature {
            kind: "image".to_string(),
            logical_identity,
            sha256: digest.to_hex(),
            source_format: None,
            semantic_sha256: None,
        },
        PortableResourceTransport::PlotStyle {
            logical_identity,
            source_format,
            semantic_digest,
            digest,
            ..
        } => ResourceSignature {
            kind: "plot_style".to_string(),
            logical_identity,
            sha256: digest.to_hex(),
            source_format: Some(source_format),
            semantic_sha256: Some(semantic_digest.to_hex()),
        },
        PortableResourceTransport::Xref {
            logical_identity,
            format,
            digest,
            ..
        } => ResourceSignature {
            kind: "xref".to_string(),
            logical_identity,
            sha256: digest.to_hex(),
            source_format: Some(format.name().to_ascii_lowercase()),
            semantic_sha256: None,
        },
    }
}

fn request_error() -> PortablePlotError {
    PortablePlotError::new(
        "portable_worker_request_invalid",
        "worker request framing is invalid or contradictory",
    )
}

fn resource_transport_error() -> PortablePlotError {
    PortablePlotError::new(
        "portable_worker_resource_invalid",
        "worker resource manifest is invalid or contradicts admitted resource semantics",
    )
}

fn resource_budget_error() -> PortablePlotError {
    PortablePlotError::new(
        "portable_worker_resource_budget_exceeded",
        "worker resource manifest exceeds the portable dependency budget",
    )
}

fn worker_io_error() -> PortablePlotError {
    PortablePlotError::new(
        "portable_worker_protocol_failed",
        "portable worker protocol I/O failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized_plot_style_bytes() -> Arc<[u8]> {
        let mut styles = serde_json::Map::new();
        for index in 1..=255 {
            styles.insert(
                index.to_string(),
                json!({
                    "color": null,
                    "grayscale": false,
                    "screening_percent": 100,
                    "lineweight_mm": null,
                    "line_cap": "use_object",
                    "line_join": "use_object",
                    "linetype": "use_object",
                    "fill_style": "use_object",
                    "dither": false,
                }),
            );
        }
        Arc::from(
            serde_json::to_vec(&json!({
                "schema": "portable_ctb_v1",
                "styles": styles,
            }))
            .unwrap(),
        )
    }

    fn resource_bundle() -> PortableResourceBundle {
        let font_bytes: Arc<[u8]> = Arc::from(&b"font"[..]);
        let fallback_bytes: Arc<[u8]> = Arc::from(&b"fallback"[..]);
        let stroke_bytes: Arc<[u8]> = Arc::from(
            serde_json::to_vec(&json!({
                "schema": "portable_shx_v1",
                "cap_height": 10.0,
                "descent": 2.0,
                "glyphs": {
                    "0041": {
                        "advance": 8.0,
                        "maximum_error": 0.0,
                        "commands": [
                            { "op": "move_to", "x": 0.0, "y": 0.0 },
                            { "op": "line_to", "x": 4.0, "y": 10.0 }
                        ]
                    }
                }
            }))
            .unwrap(),
        );
        let composite_bytes: Arc<[u8]> = Arc::from(
            serde_json::to_vec(&json!({
                "schema": "portable_shx_composite_v1",
                "glyphs": {
                    "4E00": { "font": "big", "glyph": "4E8C" }
                }
            }))
            .unwrap(),
        );
        let image_bytes: Arc<[u8]> = Arc::from(&b"\x01\x02\x03"[..]);
        let plot_style_bytes = normalized_plot_style_bytes();
        let xref_bytes: Arc<[u8]> = Arc::from(&b"xref"[..]);
        let mut bundle = PortableResourceBundle::new();
        bundle
            .bind_font(
                r"C:\Fonts\Exact.ttf",
                FontResource::new(
                    "fonts/exact",
                    font_bytes.clone(),
                    0,
                    ResourceDigest::of(&font_bytes),
                )
                .unwrap(),
            )
            .unwrap();
        bundle
            .bind_fallback_font(
                FontResource::new(
                    "fonts/fallback",
                    fallback_bytes.clone(),
                    1,
                    ResourceDigest::of(&fallback_bytes),
                )
                .unwrap(),
            )
            .unwrap();
        bundle
            .bind_shx_stroke_font(
                "simplex.shx",
                ShxStrokeFontResource::new(
                    "fonts/simplex.json",
                    stroke_bytes.clone(),
                    ResourceDigest::of(&stroke_bytes),
                )
                .unwrap(),
            )
            .unwrap();
        bundle
            .bind_shx_composite_font(
                "simplex.shx",
                "bigfont.shx",
                ShxCompositeFontResource::new(
                    "fonts/composite.json",
                    composite_bytes.clone(),
                    ResourceDigest::of(&composite_bytes),
                )
                .unwrap(),
            )
            .unwrap();
        bundle
            .bind_image(
                "image.raw",
                ImageResource::new(
                    "images/one",
                    1,
                    1,
                    ImageColorSpace::Rgb8,
                    image_bytes.clone(),
                    ResourceDigest::of(&image_bytes),
                )
                .unwrap(),
            )
            .unwrap();
        bundle
            .bind_plot_style(
                "mono.ctb",
                PlotStyleResource::new(
                    "styles/mono",
                    plot_style_bytes.clone(),
                    ResourceDigest::of(&plot_style_bytes),
                )
                .unwrap(),
            )
            .unwrap();
        bundle
            .bind_xref(
                "xref.dwg",
                XrefResource::new(
                    "xrefs/one",
                    DrawingSnapshot::new(DrawingFormat::Dwg, xref_bytes.clone()),
                    ResourceDigest::of(&xref_bytes),
                )
                .unwrap(),
            )
            .unwrap();
        bundle
    }

    #[test]
    fn worker_limits_and_deadline_are_fail_closed() {
        let defaults = PortableWorkerLimits::default();
        for limits in [
            PortableWorkerLimits {
                maximum_request_bytes: 0,
                ..defaults
            },
            PortableWorkerLimits {
                maximum_response_bytes: 0,
                ..defaults
            },
            PortableWorkerLimits {
                maximum_memory_bytes: 0,
                ..defaults
            },
            PortableWorkerLimits {
                wall_time: Duration::ZERO,
                ..defaults
            },
        ] {
            assert_eq!(
                limits.validate().unwrap_err().code(),
                "portable_worker_limits_invalid"
            );
        }
        defaults.validate().unwrap();
        assert_eq!(
            worker_wait_decision(Duration::from_millis(999), Duration::from_secs(1)),
            WorkerWaitDecision::Continue
        );
        assert_eq!(
            worker_wait_decision(Duration::from_secs(1), Duration::from_secs(1)),
            WorkerWaitDecision::Timeout
        );
        assert_eq!(
            worker_wait_decision(Duration::from_millis(1001), Duration::from_secs(1)),
            WorkerWaitDecision::Timeout
        );
    }

    fn test_request() -> PortableWorkerRequest {
        let source: Arc<[u8]> = Arc::from(&b"dwg"[..]);
        PortableWorkerRequest::new(DrawingSnapshot::new(DrawingFormat::Dwg, source), "Layout1")
            .unwrap()
    }

    fn test_receipt(encoder: &str, completeness: &str, partial_output: bool) -> Vec<u8> {
        let pdf = b"%PDF-1.4\n%%EOF";
        serde_json::to_vec(&json!({
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "profile": "portable_2d_v1",
            "semantic_renderer": "autocad_writer_semantic_compiler_v1",
            "completeness": completeness,
            "partial_output": partial_output,
            "encoder": encoder,
            "source": {
                "sha256": ResourceDigest::of(b"dwg").to_hex(),
                "selected_layout": {
                    "name": "Layout1",
                },
            },
            "resources": [],
            "output": {
                "pdf_bytes": pdf.len(),
                "pdf_sha256": ResourceDigest::of(pdf).to_hex(),
            },
        }))
        .unwrap()
    }

    #[test]
    fn request_round_trip_is_digest_bound_and_path_free() {
        let source: Arc<[u8]> = Arc::from(&b"dwg"[..]);
        let snapshot = DrawingSnapshot::new(DrawingFormat::Dwg, source);
        let request = PortableWorkerRequest::new(snapshot, "Layout1").unwrap();
        let encoded = encode_request(&request).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        assert_eq!(decoded.layout_name, "Layout1");
        assert_eq!(&*decoded.snapshot.bytes(), b"dwg");
        let mut corrupt = encoded;
        corrupt[94 + "Layout1".len()] ^= 1;
        assert_eq!(
            decode_request(&corrupt).unwrap_err().code(),
            "portable_worker_digest_mismatch"
        );
    }

    #[test]
    fn admitted_resource_bundle_round_trips_without_paths_or_semantic_drift() {
        let resources = resource_bundle();
        let expected = resources
            .transport_entries()
            .into_iter()
            .map(resource_signature)
            .collect::<BTreeSet<_>>();
        let request = PortableWorkerRequest::with_resources(
            DrawingSnapshot::new(DrawingFormat::Dwg, Arc::<[u8]>::from(&b"dwg"[..])),
            "Layout1",
            resources,
        )
        .unwrap();
        let encoded = encode_request(&request).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains(r"C:\Fonts"));
        let decoded = decode_request(&encoded).unwrap();
        let actual = decoded
            .resources
            .transport_entries()
            .into_iter()
            .map(resource_signature)
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
        assert_eq!(decoded.resources.font_count(), 2);
        assert_eq!(decoded.resources.shx_stroke_font_count(), 1);
        assert_eq!(decoded.resources.shx_composite_font_count(), 1);
        assert_eq!(decoded.resources.image_count(), 1);
        assert_eq!(decoded.resources.plot_style_count(), 1);
        assert_eq!(decoded.resources.xref_count(), 1);

        let mut corrupt = encoded;
        *corrupt.last_mut().unwrap() ^= 1;
        assert_eq!(
            decode_request(&corrupt).unwrap_err().code(),
            "portable_worker_digest_mismatch"
        );
    }

    #[test]
    fn response_budget_and_status_are_explicit() {
        let request = test_request();
        let receipt = test_receipt("krilla-0.8.2-pdf-1.4", "partial", true);
        let encoded = encode_success_response(&receipt, b"%PDF-1.4\n%%EOF").unwrap();
        let decoded = decode_response(&encoded, &request).unwrap();
        assert_eq!(decoded.pdf_bytes(), b"%PDF-1.4\n%%EOF");
        assert_eq!(decoded.receipt().completeness(), PlotCompleteness::Partial);
        assert_eq!(decoded.receipt().encoder(), "krilla-0.8.2-pdf-1.4");
        let failure = encode_response(1, b"stable_code").unwrap();
        assert_eq!(
            decode_response(&failure, &request).unwrap_err().code(),
            "portable_worker_semantic_failure"
        );
    }

    #[test]
    fn success_without_a_valid_receipt_fails_closed() {
        let request = test_request();
        let encoded = encode_response(0, b"%PDF-1.4\n%%EOF").unwrap();
        assert_eq!(
            decode_response(&encoded, &request).unwrap_err().code(),
            "portable_worker_protocol_failed"
        );
        let wrong_encoder = test_receipt("other", "partial", true);
        let encoded = encode_success_response(&wrong_encoder, b"%PDF-1.4\n%%EOF").unwrap();
        assert_eq!(
            decode_response(&encoded, &request).unwrap_err().code(),
            "portable_worker_protocol_failed"
        );
        let mut wrong_source: Value =
            serde_json::from_slice(&test_receipt("krilla-0.8.2-pdf-1.4", "partial", true)).unwrap();
        wrong_source["source"]["sha256"] = Value::String("0".repeat(64));
        let encoded = encode_success_response(
            &serde_json::to_vec(&wrong_source).unwrap(),
            b"%PDF-1.4\n%%EOF",
        )
        .unwrap();
        assert_eq!(
            decode_response(&encoded, &request).unwrap_err().code(),
            "portable_worker_protocol_failed"
        );
        let valid = test_receipt("krilla-0.8.2-pdf-1.4", "partial", true);
        let encoded = encode_success_response(&valid, b"%PDF-1.4\nchanged\n%%EOF").unwrap();
        assert_eq!(
            decode_response(&encoded, &request).unwrap_err().code(),
            "portable_worker_protocol_failed"
        );
        let mut unbound_resource: Value = serde_json::from_slice(&valid).unwrap();
        unbound_resource["resources"] = json!([{
            "kind": "font",
            "logical_identity": "fonts/unbound",
            "sha256": ResourceDigest::of(b"unbound").to_hex(),
            "source_format": null,
            "semantic_sha256": null,
        }]);
        let encoded = encode_success_response(
            &serde_json::to_vec(&unbound_resource).unwrap(),
            b"%PDF-1.4\n%%EOF",
        )
        .unwrap();
        assert_eq!(
            decode_response(&encoded, &request).unwrap_err().code(),
            "portable_worker_protocol_failed"
        );
    }
}
