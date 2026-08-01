use std::io::{Read, Write};
use std::path::Path;
#[cfg(all(unix, not(target_os = "macos")))]
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
#[cfg(all(unix, not(target_os = "macos")))]
use std::time::Instant;

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    compile_portable_scene, encode_portable_pdf, BackendLimitation, DisplayListLimits,
    FidelityDisposition, PlotCompleteness, PortablePlotError, PortablePlotLimits,
    PortablePlotReceipt, ResourceDigest,
};
use crate::{DrawingFormat, DrawingSnapshot};

const REQUEST_MAGIC: &[u8; 4] = b"P2D1";
const RESPONSE_MAGIC: &[u8; 4] = b"P2DO";
const PROTOCOL_VERSION: u8 = 1;
const RECEIPT_SCHEMA_VERSION: u32 = 1;

/// One immutable, path-free worker request.
#[derive(Debug, Clone)]
pub struct PortableWorkerRequest {
    snapshot: DrawingSnapshot,
    layout_name: String,
}

impl PortableWorkerRequest {
    pub fn new(
        snapshot: DrawingSnapshot,
        layout_name: impl Into<String>,
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
    #[cfg(any(test, all(unix, not(target_os = "macos"))))]
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

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerWaitDecision {
    Continue,
    Timeout,
}

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
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
}

/// Spawn the dedicated worker, enforcing wall-clock and address-space limits.
///
/// The executable path identifies the repository-built
/// `portable-plot-worker`; drawing and resource paths never cross the
/// boundary.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn run_portable_worker(
    executable: &Path,
    request: &PortableWorkerRequest,
    limits: PortableWorkerLimits,
) -> Result<PortableWorkerOutput, PortablePlotError> {
    use std::os::unix::process::CommandExt;

    let limits = limits.validate()?;
    let encoded = encode_request(request)?;
    if encoded.len() > limits.maximum_request_bytes {
        return Err(PortablePlotError::new(
            "portable_worker_request_budget_exceeded",
            "encoded worker request exceeds the configured byte limit",
        ));
    }
    let memory = libc::rlimit {
        rlim_cur: limits.maximum_memory_bytes as libc::rlim_t,
        rlim_max: limits.maximum_memory_bytes as libc::rlim_t,
    };
    let mut command = Command::new(executable);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: pre_exec performs the single async-signal-safe setrlimit call,
    // captures only a Copy value, and returns an OS error without allocation.
    unsafe {
        command.pre_exec(move || {
            if libc::setrlimit(libc::RLIMIT_AS, &memory) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|_| {
        PortablePlotError::new(
            "portable_worker_spawn_failed",
            "the dedicated portable plot worker could not be started",
        )
    })?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        PortablePlotError::new(
            "portable_worker_spawn_failed",
            "worker stdin was not available",
        )
    })?;
    let writer = std::thread::spawn(move || stdin.write_all(&encoded));
    let mut stdout = child.stdout.take().ok_or_else(|| {
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
        if let Some(status) = child.try_wait().map_err(|_| {
            PortablePlotError::new(
                "portable_worker_wait_failed",
                "worker status could not be observed",
            )
        })? {
            break status;
        }
        match worker_wait_decision(started.elapsed(), limits.wall_time) {
            WorkerWaitDecision::Continue => {}
            WorkerWaitDecision::Timeout => {
                let _ = child.kill();
                let _ = child.wait();
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

#[cfg(any(not(unix), target_os = "macos"))]
pub fn run_portable_worker(
    _executable: &Path,
    _request: &PortableWorkerRequest,
    _limits: PortableWorkerLimits,
) -> Result<PortableWorkerOutput, PortablePlotError> {
    Err(PortablePlotError::new(
        "portable_worker_platform_unsupported",
        "hard address-space enforcement is currently qualified only on non-Darwin Unix development hosts",
    ))
}

/// Entry point used only by the dedicated worker binary.
#[doc(hidden)]
pub fn run_worker_stdio() -> Result<(), PortablePlotError> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(PortableWorkerLimits::default().maximum_request_bytes as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| worker_io_error())?;
    let result = decode_request(&input).and_then(|request| {
        let compilation = compile_portable_scene(
            &request.snapshot,
            &request.layout_name,
            PortablePlotLimits::default(),
        )?;
        let scene = compilation.display_list().ok_or_else(|| {
            PortablePlotError::new(
                "portable_worker_scene_rejected",
                "semantic fidelity rejected the source before PDF encoding",
            )
        })?;
        let pdf = encode_portable_pdf(scene, DisplayListLimits::default())?;
        let receipt = encode_receipt(compilation.receipt(), pdf.encoder())?;
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

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
fn encode_request(request: &PortableWorkerRequest) -> Result<Vec<u8>, PortablePlotError> {
    let bytes = request.snapshot.bytes();
    let layout = request.layout_name.as_bytes();
    let layout_len = u32::try_from(layout.len()).map_err(|_| request_error())?;
    let source_len = u64::try_from(bytes.len()).map_err(|_| request_error())?;
    let mut output = Vec::with_capacity(
        4_usize
            .saturating_add(1)
            .saturating_add(1)
            .saturating_add(4)
            .saturating_add(8)
            .saturating_add(32)
            .saturating_add(layout.len())
            .saturating_add(bytes.len()),
    );
    output.extend_from_slice(REQUEST_MAGIC);
    output.push(PROTOCOL_VERSION);
    output.push(match request.snapshot.format() {
        DrawingFormat::Dwg => 1,
        DrawingFormat::Dxf => 2,
    });
    output.extend_from_slice(&layout_len.to_be_bytes());
    output.extend_from_slice(&source_len.to_be_bytes());
    output.extend_from_slice(&Sha256::digest(&bytes));
    output.extend_from_slice(layout);
    output.extend_from_slice(&bytes);
    Ok(output)
}

fn decode_request(bytes: &[u8]) -> Result<PortableWorkerRequest, PortablePlotError> {
    const HEADER: usize = 4 + 1 + 1 + 4 + 8 + 32;
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
    let expected = HEADER
        .checked_add(layout_len)
        .and_then(|length| length.checked_add(source_len))
        .ok_or_else(request_error)?;
    if bytes.len() != expected {
        return Err(request_error());
    }
    let layout_end = HEADER + layout_len;
    let layout = std::str::from_utf8(&bytes[HEADER..layout_end]).map_err(|_| request_error())?;
    let source = &bytes[layout_end..];
    if Sha256::digest(source).as_slice() != &bytes[18..50] {
        return Err(PortablePlotError::new(
            "portable_worker_digest_mismatch",
            "worker request source bytes do not match their SHA-256 binding",
        ));
    }
    PortableWorkerRequest::new(
        DrawingSnapshot::new(format, Arc::<[u8]>::from(source)),
        layout,
    )
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

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
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
    if envelope.schema_version != RECEIPT_SCHEMA_VERSION
        || envelope.profile != "portable_2d_v1"
        || envelope.semantic_renderer != "autocad_writer_semantic_compiler_v1"
        || envelope.encoder != "krilla-0.8.2-pdf-1.4"
        || envelope.source.sha256 != ResourceDigest::of(request.snapshot.bytes().as_ref()).to_hex()
        || envelope.source.selected_layout.name != request.layout_name
        || completeness == PlotCompleteness::Rejected
        || envelope.partial_output != (completeness == PlotCompleteness::Partial)
    {
        return Err(worker_io_error());
    }
    let pdf_bytes = body[receipt_end..].to_vec();
    if !pdf_bytes.starts_with(b"%PDF-1.4") || !pdf_bytes.ends_with(b"%%EOF") {
        return Err(worker_io_error());
    }
    Ok(PortableWorkerOutput {
        pdf_bytes,
        receipt: PortableWorkerReceipt {
            json,
            completeness,
            encoder: envelope.encoder,
        },
    })
}

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
#[derive(Deserialize)]
struct ReceiptEnvelope {
    schema_version: u32,
    profile: String,
    semantic_renderer: String,
    completeness: String,
    partial_output: bool,
    encoder: String,
    source: ReceiptSourceEnvelope,
}

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
#[derive(Deserialize)]
struct ReceiptSourceEnvelope {
    sha256: String,
    selected_layout: ReceiptLayoutEnvelope,
}

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
#[derive(Deserialize)]
struct ReceiptLayoutEnvelope {
    name: String,
}

fn encode_receipt(
    receipt: &PortablePlotReceipt,
    encoder: &str,
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

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
fn parse_completeness(value: &str) -> Result<PlotCompleteness, PortablePlotError> {
    match value {
        "complete" => Ok(PlotCompleteness::Complete),
        "partial" => Ok(PlotCompleteness::Partial),
        "rejected" => Ok(PlotCompleteness::Rejected),
        _ => Err(worker_io_error()),
    }
}

fn request_error() -> PortablePlotError {
    PortablePlotError::new(
        "portable_worker_request_invalid",
        "worker request framing is invalid or contradictory",
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
        serde_json::to_vec(&json!({
            "schema_version": 1,
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
    }
}
