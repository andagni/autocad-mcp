use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};

use acadrust::{CadDocument, DxfReader, DxfWriter};
use sha2::{Digest, Sha256};

use crate::{
    activation::{ActivationError, MutationCapability, SelectedActivation},
    activation_platform::ProductionMutationRuntime,
    ops::layers::{
        self, DeleteLayerResult, LayerError, LayerMutationProjectionContext,
        LayerMutationProjectionMetadata, LayerMutationResult, LayerSelector,
    },
};

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

#[cfg(not(target_os = "windows"))]
fn unsupported_platform(tool: &str, path: &Path) -> LayerError {
    LayerError::new(
        "unsupported_platform",
        format!(
            "{tool} DWG mutation is unsupported on {}; format=DWG required_platform=Windows required_engine=accoreconsole recovery=\"run on Windows with AutoCAD/accoreconsole or convert to supported DXF\" drawing={}",
            std::env::consts::OS,
            path.display()
        ),
    )
}

fn validate_layer_path(path: &Path, tool: &str) -> Result<(String, PathBuf), LayerError> {
    if !path.is_absolute() {
        return Err(LayerError::new(
            "drawing_unreadable",
            format!("{tool}: drawing_path must be absolute: {}", path.display()),
        ));
    }

    let ext = extension(path);
    match ext.as_str() {
        "dxf" | "dwg" => {}
        "" => {
            return Err(LayerError::new(
                "unsupported_format",
                format!("{tool}: file has no extension; expected .dxf or .dwg"),
            ))
        }
        other => {
            return Err(LayerError::new(
                "unsupported_format",
                format!("{tool}: unsupported extension `{other}`; expected .dxf or .dwg"),
            ))
        }
    }

    if !path.exists() {
        return Err(LayerError::new(
            "drawing_not_found",
            format!("{tool}: drawing not found: {}", path.display()),
        ));
    }

    let absolute = std::fs::canonicalize(path).map_err(|err| {
        LayerError::new(
            "drawing_unreadable",
            format!("{tool}: failed to canonicalize drawing path: {err}"),
        )
    })?;
    Ok((ext, absolute))
}

fn activation_layer_error(tool: &str, path: &Path, error: ActivationError) -> LayerError {
    let code = match &error {
        ActivationError::Disabled
        | ActivationError::ReleaseQualificationUnavailable
        | ActivationError::ReleaseQualificationInvalid(_)
        | ActivationError::CapabilityUnsupported { .. } => "unsupported_platform",
        ActivationError::DrawingFormatUnsupported { .. } => "unsupported_format",
        ActivationError::CatalogueInvalid(_) | ActivationError::AssetInvalid(_) => "write_failed",
        ActivationError::DiscoveryFailed(_) if !cfg!(target_os = "windows") => {
            "unsupported_platform"
        }
        ActivationError::DiscoveryFailed(_)
        | ActivationError::NoEligibleCandidate
        | ActivationError::ExactOverrideUnavailable(_)
        | ActivationError::VerificationFailed(_)
        | ActivationError::SelectedEngineChanged(_) => "autocad_unavailable",
    };
    LayerError::new(
        code,
        format!(
            "{tool}: AutoCAD activation failed before DWG mutation: {error}; drawing={}",
            path.display()
        ),
    )
}

fn acquire_dwg_layer_activation(
    runtime: Option<&ProductionMutationRuntime>,
    tool: &str,
    path: &Path,
) -> Result<Option<std::sync::Arc<SelectedActivation>>, LayerError> {
    let drawing_format = runtime
        .is_some()
        .then(|| crate::reader::inspect_dwg_version(path))
        .transpose()
        .map_err(|error| {
            LayerError::new(
                "drawing_unreadable",
                format!(
                    "{tool}: failed to inspect persisted DWG version before activation: {error}"
                ),
            )
        })?;
    runtime
        .map(|runtime| {
            runtime
                .acquire_for_format(
                    MutationCapability::DwgLayerMutation,
                    drawing_format
                        .as_deref()
                        .expect("managed DWG activation has a format"),
                )
                .map_err(|error| activation_layer_error(tool, path, error))
        })
        .transpose()
}

struct DxfMutationLock {
    _file: File,
}

#[derive(Debug, Clone)]
struct DxfSourceIdentity {
    byte_len: u64,
    sha256: String,
    permissions: std::fs::Permissions,
}

fn dxf_mutation_lock_path(path: &Path) -> Result<PathBuf, LayerError> {
    let lock_root = std::env::temp_dir().join("autocad-mcp-layer-locks-v1");
    std::fs::create_dir_all(&lock_root).map_err(|err| {
        LayerError::new(
            "write_failed",
            format!("failed to create DXF mutation lock directory: {err}"),
        )
    })?;
    let digest = Sha256::digest(path.as_os_str().as_encoded_bytes());
    Ok(lock_root.join(format!("{digest:x}.lock")))
}

fn acquire_dxf_mutation_lock(path: &Path) -> Result<DxfMutationLock, LayerError> {
    let lock_path = dxf_mutation_lock_path(path)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| {
            LayerError::new(
                "write_failed",
                format!(
                    "failed to open per-drawing DXF mutation lock {}: {err}",
                    lock_path.display()
                ),
            )
        })?;
    file.lock().map_err(|err| {
        LayerError::new(
            "write_failed",
            format!(
                "failed to acquire per-drawing DXF mutation lock {}: {err}",
                lock_path.display()
            ),
        )
    })?;
    Ok(DxfMutationLock { _file: file })
}

#[cfg(unix)]
fn source_has_multiple_hard_links(_path: &Path, metadata: &Metadata) -> Result<bool, LayerError> {
    use std::os::unix::fs::MetadataExt;

    Ok(metadata.nlink() > 1)
}

#[cfg(target_os = "windows")]
fn source_has_multiple_hard_links(path: &Path, _metadata: &Metadata) -> Result<bool, LayerError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let file = File::open(path).map_err(|err| {
        LayerError::new(
            "drawing_unreadable",
            format!("failed to open source DXF for hard-link inspection: {err}"),
        )
    })?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let result =
        unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) };
    if result == 0 {
        return Err(LayerError::new(
            "drawing_unreadable",
            format!(
                "failed to inspect source DXF hard-link count: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }
    Ok(information.nNumberOfLinks > 1)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn source_has_multiple_hard_links(_path: &Path, _metadata: &Metadata) -> Result<bool, LayerError> {
    Ok(false)
}

fn capture_dxf_source_identity(path: &Path) -> Result<DxfSourceIdentity, LayerError> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        LayerError::new(
            "drawing_unreadable",
            format!("failed to inspect source DXF metadata: {err}"),
        )
    })?;
    if !metadata.is_file() {
        return Err(LayerError::new(
            "drawing_unreadable",
            "source DXF is not a regular file",
        ));
    }
    if source_has_multiple_hard_links(path, &metadata)? {
        return Err(LayerError::new(
            "unsupported_layer_data",
            "source DXF has multiple hard links; atomic replacement would leave aliases stale",
        ));
    }
    let bytes = std::fs::read(path).map_err(|err| {
        LayerError::new(
            "drawing_unreadable",
            format!("failed to capture source DXF bytes: {err}"),
        )
    })?;
    if metadata.len() != bytes.len() as u64 {
        return Err(LayerError::new(
            "drawing_unreadable",
            "source DXF changed while its mutation identity was captured",
        ));
    }
    Ok(DxfSourceIdentity {
        byte_len: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        permissions: metadata.permissions(),
    })
}

fn verify_dxf_source_identity(path: &Path, expected: &DxfSourceIdentity) -> Result<(), LayerError> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        LayerError::new(
            "write_failed",
            format!("failed to re-inspect source DXF before replacement: {err}"),
        )
    })?;
    if !metadata.is_file() || source_has_multiple_hard_links(path, &metadata)? {
        return Err(LayerError::new(
            "write_failed",
            "source DXF identity changed before replacement; no replacement was performed",
        ));
    }
    let bytes = std::fs::read(path).map_err(|err| {
        LayerError::new(
            "write_failed",
            format!("failed to re-read source DXF before replacement: {err}"),
        )
    })?;
    let actual_sha256 = format!("{:x}", Sha256::digest(&bytes));
    if bytes.len() as u64 != expected.byte_len || actual_sha256 != expected.sha256 {
        return Err(LayerError::new(
            "write_failed",
            "source DXF bytes changed during layer mutation; no replacement was performed",
        ));
    }
    Ok(())
}

fn open_dxf(path: &Path) -> Result<CadDocument, LayerError> {
    // Parse and validate raw ASCII layer data before handing it to acadrust.
    // This prevents malformed numeric fields (notably i16::MIN color values)
    // from reaching dependency code paths that cannot represent them safely.
    let raw_table = read_optional_raw_layer_table(path)?;
    let mut doc = DxfReader::from_file(path)
        .map_err(|err| LayerError::new("drawing_unreadable", format!("failed to open DXF: {err}")))?
        .read()
        .map_err(|err| {
            LayerError::new("drawing_unreadable", format!("failed to read DXF: {err}"))
        })?;
    apply_dxf_direct_layer_overrides(raw_table.as_ref(), &mut doc)?;
    Ok(doc)
}

fn synchronize_dxf_allocator(path: &Path, document: &mut CadDocument) -> Result<(), LayerError> {
    let text = std::fs::read_to_string(path).map_err(|err| {
        LayerError::new(
            "drawing_unreadable",
            format!("failed to read DXF for handle-allocation safety: {err}"),
        )
    })?;
    let pairs = parse_raw_dxf_pairs(&text).map_err(|message| {
        LayerError::new(
            "drawing_unreadable",
            format!("failed to parse DXF for handle-allocation safety: {message}"),
        )
    })?;
    let identities = raw_identity_handles(&pairs)
        .map_err(|message| unsupported_layer_data(Some("<drawing>"), message))?;
    let references = raw_reference_handles_outside_range(&pairs, &(0..0));
    let mut max_persisted = 0u64;
    for handle in identities.iter().chain(references.iter()) {
        max_persisted = max_persisted.max(raw_hex_value(handle, "source DXF handle")?);
    }
    let minimum_next = max_persisted.checked_add(1).ok_or_else(|| {
        unsupported_layer_data(
            Some("<drawing>"),
            "persisted handle space is exhausted at FFFFFFFFFFFFFFFF",
        )
    })?;
    let handseed = header_variable_value_index(&pairs, "$HANDSEED", 5)
        .map_err(|message| unsupported_layer_data(Some("<HEADER>"), message))?
        .map(|index| raw_hex_value(&pairs[index].value, "source DXF $HANDSEED"))
        .transpose()?
        .unwrap_or(0);
    let minimum_next = minimum_next.max(handseed);
    if document.next_handle() >= minimum_next {
        return Ok(());
    }
    if minimum_next == u64::MAX {
        return Err(unsupported_layer_data(
            Some("<drawing>"),
            "cannot safely advance the document allocator beyond FFFFFFFFFFFFFFFF",
        ));
    }

    // The selected backend's DXF post-read allocator scan omits most table-entry
    // handles. Insert and immediately remove one sentinel entity to advance
    // its private counter in O(1), then scrub the block-record membership that
    // remove_entity does not currently remove.
    let sentinel_handle = acadrust::types::Handle::new(minimum_next);
    let mut sentinel = acadrust::entities::Point::new();
    sentinel.common.handle = sentinel_handle;
    document
        .add_entity(acadrust::entities::EntityType::Point(sentinel))
        .map_err(|err| {
            LayerError::new(
                "write_failed",
                format!("failed to advance the DXF handle allocator safely: {err}"),
            )
        })?;
    document.remove_entity(sentinel_handle).ok_or_else(|| {
        LayerError::new(
            "write_failed",
            "failed to remove the DXF handle-allocation sentinel",
        )
    })?;
    for block_record in document.block_records.iter_mut() {
        block_record
            .entity_handles
            .retain(|handle| *handle != sentinel_handle);
    }
    if document.next_handle() <= minimum_next {
        return Err(LayerError::new(
            "write_failed",
            "DXF handle allocator did not advance beyond persisted identities",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawDxfPair {
    code: String,
    value: String,
}

impl RawDxfPair {
    fn is(&self, code: i32, value: &str) -> bool {
        self.code_number() == Some(code) && self.value.trim().eq_ignore_ascii_case(value)
    }

    fn code_number(&self) -> Option<i32> {
        self.code.trim().parse().ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawLayerEntry {
    pairs: Vec<RawDxfPair>,
}

impl RawLayerEntry {
    fn direct_pair_indices(&self) -> Vec<usize> {
        let mut depth = 0usize;
        let mut result = Vec::new();
        for (index, pair) in self.pairs.iter().enumerate() {
            let is_open = pair.code_number() == Some(102) && pair.value.trim().starts_with('{');
            let is_close = pair.code_number() == Some(102) && pair.value.trim() == "}";
            if depth == 0 && !is_open && !is_close {
                result.push(index);
            }
            if is_open {
                depth = depth.saturating_add(1);
            } else if is_close {
                depth = depth.saturating_sub(1);
            }
        }
        result
    }

    fn direct_pair(&self, code: i32) -> Option<&RawDxfPair> {
        self.direct_pair_indices()
            .into_iter()
            .map(|index| &self.pairs[index])
            .find(|pair| pair.code_number() == Some(code))
    }

    fn value(&self, code: i32) -> Option<&str> {
        self.direct_pair(code).map(|pair| pair.value.as_str())
    }

    fn name(&self) -> Option<&str> {
        self.value(2)
    }

    fn canonical_handle(&self) -> Option<String> {
        self.value(5).and_then(canonical_raw_handle)
    }

    fn has_non_indexed_color(&self) -> bool {
        self.direct_pair(420).is_some() || self.direct_pair(430).is_some()
    }

    fn has_unproven_delete_dependencies(&self) -> bool {
        self.pairs.iter().any(|pair| {
            pair.code_number() == Some(360)
                || (pair.code_number() == Some(102) && pair.value.trim().starts_with('{'))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawLayerTable {
    start: usize,
    end: usize,
    header: Vec<RawDxfPair>,
    entries: Vec<RawLayerEntry>,
    trailer: RawDxfPair,
}

#[derive(Debug, Clone, Default)]
struct DxfLayerWritePolicy {
    indexed_color_handles: BTreeSet<String>,
}

struct RawLayerMerge {
    table_pairs: Vec<RawDxfPair>,
    expected_header: Vec<RawDxfPair>,
    expected_entries: Vec<RawLayerEntry>,
    renames: Vec<(String, String)>,
    created_handles: Vec<String>,
}

fn canonical_raw_handle(value: &str) -> Option<String> {
    let value = value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or(value.trim());
    let handle = u64::from_str_radix(value, 16).ok()?;
    (handle != 0).then(|| format!("{handle:X}"))
}

fn parse_raw_dxf_pairs(text: &str) -> Result<Vec<RawDxfPair>, String> {
    let lines = text
        .split_terminator('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect::<Vec<_>>();
    if lines.len() % 2 != 0 {
        return Err("DXF text contains an unmatched group-code line".to_string());
    }

    lines
        .chunks_exact(2)
        .map(|lines| {
            let code = lines[0].trim();
            code.parse::<i32>()
                .map_err(|_| format!("invalid DXF group code `{code}`"))?;
            Ok(RawDxfPair {
                // Keep the original group-code formatting. Layer mutations are
                // bounded raw patches, so unrelated records should not be
                // normalized merely because acadrust cannot round-trip them.
                code: lines[0].to_string(),
                value: lines[1].to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
fn render_raw_dxf_pairs(pairs: &[RawDxfPair]) -> String {
    render_raw_dxf_pairs_with_line_ending(pairs, "\n")
}

fn render_raw_dxf_pairs_with_line_ending(pairs: &[RawDxfPair], line_ending: &str) -> String {
    let mut text = String::new();
    for pair in pairs {
        text.push_str(&pair.code);
        text.push_str(line_ending);
        text.push_str(&pair.value);
        text.push_str(line_ending);
    }
    text
}

fn raw_section_range(
    pairs: &[RawDxfPair],
    section_name: &str,
) -> Result<Option<std::ops::Range<usize>>, String> {
    let mut found = None;
    let mut index = 0usize;
    while index < pairs.len() {
        if !pairs[index].is(0, "SECTION") {
            index += 1;
            continue;
        }
        let Some(name) = pairs.get(index + 1) else {
            return Err("DXF SECTION is missing its name pair".to_string());
        };
        if name.code_number() != Some(2) {
            return Err("DXF SECTION is missing group code 2".to_string());
        }
        let end = (index + 2..pairs.len())
            .find(|candidate| pairs[*candidate].is(0, "ENDSEC"))
            .ok_or_else(|| format!("unterminated DXF {} section", name.value.trim()))?
            + 1;
        if name.value.trim().eq_ignore_ascii_case(section_name) {
            if found.is_some() {
                return Err(format!("DXF contains more than one {section_name} section"));
            }
            found = Some(index..end);
        }
        index = end;
    }
    Ok(found)
}

fn raw_reference_handles_outside_range(
    pairs: &[RawDxfPair],
    excluded: &std::ops::Range<usize>,
) -> BTreeSet<String> {
    pairs
        .iter()
        .enumerate()
        .filter(|(index, _)| !excluded.contains(index))
        .filter_map(|(_, pair)| {
            let code = pair.code_number()?;
            ((320..=369).contains(&code)
                || (390..=399).contains(&code)
                || matches!(code, 480 | 481 | 1005))
            .then(|| canonical_raw_handle(&pair.value))
            .flatten()
        })
        .collect()
}

fn raw_identity_handles(pairs: &[RawDxfPair]) -> Result<BTreeSet<String>, String> {
    let header = raw_section_range(pairs, "HEADER")?;
    let mut identities = BTreeSet::new();
    for (index, pair) in pairs.iter().enumerate() {
        if header
            .as_ref()
            .is_some_and(|header| header.contains(&index))
            || !matches!(pair.code_number(), Some(5 | 105))
        {
            continue;
        }
        let Some(handle) = canonical_raw_handle(&pair.value) else {
            return Err(format!(
                "invalid object identity handle `{}`",
                pair.value.trim()
            ));
        };
        if !identities.insert(handle.clone()) {
            return Err(format!("duplicate object identity handle {handle}"));
        }
    }
    Ok(identities)
}

fn raw_layer_reference_names_outside_range(
    pairs: &[RawDxfPair],
    excluded: &std::ops::Range<usize>,
) -> BTreeSet<String> {
    let mut depth = 0usize;
    let mut names = BTreeSet::new();
    for (index, pair) in pairs.iter().enumerate() {
        if excluded.contains(&index) {
            continue;
        }
        let is_open = pair.code_number() == Some(102) && pair.value.trim().starts_with('{');
        let is_close = pair.code_number() == Some(102) && pair.value.trim() == "}";
        if depth == 0 && matches!(pair.code_number(), Some(8 | 1003)) {
            names.insert(pair.value.to_uppercase());
        }
        if is_open {
            depth = depth.saturating_add(1);
        } else if is_close {
            depth = depth.saturating_sub(1);
        }
    }
    names
}

fn raw_opaque_layer_reference_names_outside_range(
    pairs: &[RawDxfPair],
    excluded: &std::ops::Range<usize>,
) -> BTreeSet<String> {
    let mut depth = 0usize;
    let mut names = BTreeSet::new();
    for (index, pair) in pairs.iter().enumerate() {
        if excluded.contains(&index) {
            continue;
        }
        let is_open = pair.code_number() == Some(102) && pair.value.trim().starts_with('{');
        let is_close = pair.code_number() == Some(102) && pair.value.trim() == "}";
        if is_open {
            depth = depth.saturating_add(1);
        } else if is_close {
            depth = depth.saturating_sub(1);
        } else if depth > 0 && matches!(pair.code_number(), Some(8 | 1003)) {
            names.insert(pair.value.to_uppercase());
        }
    }
    names
}

fn validate_application_groups(pairs: &[RawDxfPair]) -> Result<(), String> {
    let mut depth = 0usize;
    for pair in pairs {
        if pair.code_number() != Some(102) {
            continue;
        }
        if pair.value.trim().starts_with('{') {
            depth = depth
                .checked_add(1)
                .ok_or_else(|| "application-group nesting overflow".to_string())?;
        } else if pair.value.trim() == "}" {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| "unmatched application-group terminator".to_string())?;
        }
    }
    if depth == 0 {
        Ok(())
    } else {
        Err("unterminated application group".to_string())
    }
}

fn validate_direct_layer_singletons(table: &RawLayerTable) -> Result<(), LayerError> {
    const SINGLETON_CODES: [i32; 9] = [2, 5, 6, 62, 70, 290, 370, 420, 430];

    let header = RawLayerEntry {
        pairs: table.header.clone(),
    };
    for code in [2, 70] {
        let count = header
            .direct_pair_indices()
            .into_iter()
            .filter(|index| header.pairs[*index].code_number() == Some(code))
            .count();
        if count != 1 {
            return Err(unsupported_layer_data(
                Some("<LAYER table header>"),
                format!("expected exactly one direct group code {code}, found {count}"),
            ));
        }
    }
    if !header
        .value(2)
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("LAYER"))
    {
        return Err(unsupported_layer_data(
            Some("<LAYER table header>"),
            "direct group code 2 does not identify the LAYER table",
        ));
    }
    let declared_count = pair_integer(&header, 70, 0)?;
    let actual_count = i32::try_from(table.entries.len()).map_err(|_| {
        unsupported_layer_data(
            Some("<LAYER table header>"),
            "layer count exceeds the supported integer domain",
        )
    })?;
    if declared_count != actual_count {
        return Err(unsupported_layer_data(
            Some("<LAYER table header>"),
            format!(
                "declared group code 70 count {declared_count} does not match {actual_count} LAYER records"
            ),
        ));
    }
    let header_handles = header
        .direct_pair_indices()
        .into_iter()
        .filter(|index| header.pairs[*index].code_number() == Some(5))
        .count();
    if header_handles > 1 {
        return Err(unsupported_layer_data(
            Some("<LAYER table header>"),
            format!("ambiguous repeated direct group code 5 ({header_handles} occurrences)"),
        ));
    }

    for entry in &table.entries {
        for code in [2, 5] {
            let count = entry
                .direct_pair_indices()
                .into_iter()
                .filter(|index| entry.pairs[*index].code_number() == Some(code))
                .count();
            if count != 1 {
                return Err(unsupported_layer_data(
                    entry.name(),
                    format!("expected exactly one direct group code {code}, found {count}"),
                ));
            }
        }

        let mut seen = BTreeSet::new();
        for index in entry.direct_pair_indices() {
            let Some(code) = entry.pairs[index].code_number() else {
                continue;
            };
            if SINGLETON_CODES.contains(&code) && !seen.insert(code) {
                return Err(unsupported_layer_data(
                    entry.name(),
                    format!("ambiguous repeated direct group code {code}"),
                ));
            }
        }

        if entry.value(70).is_some() {
            let flags = pair_integer(entry, 70, 0)?;
            if !(0..=i16::MAX as i32).contains(&flags) {
                return Err(unsupported_layer_data(
                    entry.name(),
                    format!("group code 70 value {flags} is outside the layer-flag domain"),
                ));
            }
        }
        if entry.value(62).is_some() {
            let color = pair_integer(entry, 62, 7)?;
            if !(-255..=255).contains(&color) {
                return Err(unsupported_layer_data(
                    entry.name(),
                    format!(
                        "group code 62 value {color} is outside the round-trip-safe -255..=255 domain"
                    ),
                ));
            }
        }
        if entry.value(370).is_some() {
            let line_weight = pair_integer(entry, 370, -3)?;
            if i16::try_from(line_weight).is_err() {
                return Err(unsupported_layer_data(
                    entry.name(),
                    format!("group code 370 value {line_weight} is outside the i16 domain"),
                ));
            }
        }
        if entry.value(290).is_some() {
            let plot = pair_integer(entry, 290, 1)?;
            if !matches!(plot, 0 | 1) {
                return Err(unsupported_layer_data(
                    entry.name(),
                    format!("group code 290 value {plot} is not the required boolean 0 or 1"),
                ));
            }
        }
    }
    Ok(())
}

fn try_parse_raw_layer_table(pairs: &[RawDxfPair]) -> Result<Option<RawLayerTable>, String> {
    let mut found = None;
    let mut index = 0usize;
    while index < pairs.len() {
        if !pairs[index].is(0, "TABLE") {
            index += 1;
            continue;
        }

        let start = index;
        let endtab = (start + 1..pairs.len())
            .find(|candidate| pairs[*candidate].is(0, "ENDTAB"))
            .ok_or_else(|| "unterminated DXF TABLE section".to_string())?;
        let first_record = (start + 1..endtab)
            .find(|candidate| pairs[*candidate].code_number() == Some(0))
            .unwrap_or(endtab);
        let is_layer_table = pairs[start + 1..first_record]
            .iter()
            .any(|pair| pair.is(2, "LAYER"));

        if !is_layer_table {
            index = endtab + 1;
            continue;
        }
        if found.is_some() {
            return Err("DXF contains more than one LAYER table".to_string());
        }

        let mut entries = Vec::new();
        let mut cursor = first_record;
        while cursor < endtab {
            if !pairs[cursor].is(0, "LAYER") {
                return Err(format!(
                    "unexpected record `{}` inside LAYER table",
                    pairs[cursor].value
                ));
            }
            let entry_end = (cursor + 1..=endtab)
                .find(|candidate| pairs[*candidate].code_number() == Some(0))
                .unwrap_or(endtab);
            let entry_pairs = pairs[cursor..entry_end].to_vec();
            validate_application_groups(&entry_pairs)?;
            entries.push(RawLayerEntry { pairs: entry_pairs });
            cursor = entry_end;
        }

        let header = pairs[start..first_record].to_vec();
        validate_application_groups(&header)?;
        found = Some(RawLayerTable {
            start,
            end: endtab + 1,
            header,
            entries,
            trailer: pairs[endtab].clone(),
        });
        index = endtab + 1;
    }

    Ok(found)
}

fn parse_raw_layer_table(pairs: &[RawDxfPair]) -> Result<RawLayerTable, String> {
    try_parse_raw_layer_table(pairs)?
        .ok_or_else(|| "DXF does not contain a LAYER table".to_string())
}

fn read_dxf_text_for_layer_metadata(path: &Path) -> Result<String, LayerError> {
    std::fs::read_to_string(path).map_err(|err| {
        LayerError::new(
            "drawing_unreadable",
            format!("failed to read DXF text for layer metadata: {err}"),
        )
    })
}

fn parse_optional_raw_layer_table(text: &str) -> Result<Option<RawLayerTable>, LayerError> {
    let pairs = parse_raw_dxf_pairs(text).map_err(|message| {
        LayerError::new(
            "drawing_unreadable",
            format!("failed to parse DXF text for layer metadata: {message}"),
        )
    })?;
    let table = try_parse_raw_layer_table(&pairs).map_err(|message| {
        LayerError::new(
            "drawing_unreadable",
            format!("failed to parse DXF LAYER table: {message}"),
        )
    })?;
    if let Some(table) = &table {
        validate_direct_layer_singletons(table)?;
    }
    Ok(table)
}

fn read_optional_raw_layer_table(path: &Path) -> Result<Option<RawLayerTable>, LayerError> {
    let text = read_dxf_text_for_layer_metadata(path)?;
    parse_optional_raw_layer_table(&text)
}

#[cfg(test)]
fn read_raw_layer_table(path: &Path) -> Result<RawLayerTable, LayerError> {
    read_optional_raw_layer_table(path)?.ok_or_else(|| {
        LayerError::new(
            "drawing_unreadable",
            "failed to parse DXF LAYER table: DXF does not contain a LAYER table",
        )
    })
}

fn apply_dxf_direct_layer_overrides(
    table: Option<&RawLayerTable>,
    doc: &mut CadDocument,
) -> Result<(), LayerError> {
    let Some(table) = table else {
        return Ok(());
    };
    for entry in &table.entries {
        let handle = entry
            .canonical_handle()
            .and_then(|value| u64::from_str_radix(&value, 16).ok())
            .map(acadrust::types::Handle::new)
            .ok_or_else(|| {
                unsupported_layer_data(
                    entry.name(),
                    "missing or invalid handle prevents direct-field recovery",
                )
            })?;
        let layer = doc
            .layers
            .iter_mut()
            .find(|layer| layer.handle == handle)
            .ok_or_else(|| {
                unsupported_layer_data(
                    entry.name(),
                    format!(
                        "decoded layer handle {:X} does not match the raw LAYER table",
                        handle.value()
                    ),
                )
            })?;

        let flags = pair_integer(entry, 70, 0)?;
        let color = i16::try_from(pair_integer(entry, 62, 7)?).map_err(|_| {
            unsupported_layer_data(
                entry.name(),
                "group code 62 is outside the i16 value domain",
            )
        })?;
        let line_weight = i16::try_from(pair_integer(entry, 370, -3)?).map_err(|_| {
            unsupported_layer_data(
                entry.name(),
                "group code 370 is outside the i16 value domain",
            )
        })?;
        let raw_name = entry.name().unwrap_or("0");
        if layer.name != raw_name {
            return Err(unsupported_layer_data(
                entry.name(),
                "application-group data changed decoded layer identity",
            ));
        }

        layer.flags.frozen = flags & 1 != 0;
        layer.flags.locked = flags & 4 != 0;
        layer.flags.off = color < 0;
        layer.flags.xref_dependent = flags & 16 != 0;
        layer.color = acadrust::types::Color::from_index(color);
        layer.line_type = entry.value(6).unwrap_or("Continuous").to_string();
        layer.line_weight = acadrust::types::LineWeight::from_value(line_weight);
        layer.is_plottable = pair_integer(entry, 290, 1)? != 0;
    }
    Ok(())
}

fn layer_metadata_from_raw_table(table: Option<&RawLayerTable>) -> LayerMutationProjectionMetadata {
    let mut metadata = LayerMutationProjectionMetadata::default();
    for entry in table.into_iter().flat_map(|table| &table.entries) {
        if !entry.has_non_indexed_color() {
            continue;
        }
        let handle = entry
            .canonical_handle()
            .and_then(|value| u64::from_str_radix(&value, 16).ok())
            .map(acadrust::types::Handle::new);
        if let Some(name) = entry.name() {
            metadata.mark_non_indexed_color(handle, name);
        }
    }
    metadata
}

fn read_dxf_layer_metadata(path: &Path) -> Result<LayerMutationProjectionMetadata, LayerError> {
    let table = read_optional_raw_layer_table(path)?;
    Ok(layer_metadata_from_raw_table(table.as_ref()))
}

fn pair_integer(entry: &RawLayerEntry, code: i32, default: i32) -> Result<i32, LayerError> {
    entry
        .value(code)
        .map(|value| {
            value.trim().parse::<i32>().map_err(|_| {
                unsupported_layer_data(
                    entry.name(),
                    format!("invalid value `{}` for group code {code}", value.trim()),
                )
            })
        })
        .unwrap_or(Ok(default))
}

fn required_pair(entry: &RawLayerEntry, code: i32) -> Result<&RawDxfPair, LayerError> {
    entry.direct_pair(code).ok_or_else(|| {
        LayerError::new(
            "write_failed",
            format!(
                "generated DXF LAYER `{}` omitted required group code {code}",
                entry.name().unwrap_or("<unknown>")
            ),
        )
    })
}

fn replace_or_append_pair(entry: &mut RawLayerEntry, replacement: &RawDxfPair) {
    if let Some(index) = entry
        .direct_pair_indices()
        .into_iter()
        .find(|index| entry.pairs[*index].code_number() == replacement.code_number())
    {
        entry.pairs[index].value.clone_from(&replacement.value);
    } else {
        const STANDARD_CODES: [i32; 6] = [2, 70, 62, 6, 290, 370];
        let insert_at = entry
            .direct_pair_indices()
            .into_iter()
            .filter(|index| {
                entry.pairs[*index]
                    .code_number()
                    .is_some_and(|code| STANDARD_CODES.contains(&code))
            })
            .max()
            .map(|index| index + 1)
            .unwrap_or(entry.pairs.len());
        entry.pairs.insert(insert_at, replacement.clone());
    }
}

fn format_integer_like(original: Option<&str>, value: i32) -> String {
    let Some(original) = original else {
        return value.to_string();
    };
    let leading_len = original.len() - original.trim_start().len();
    let trailing_len = original.len() - original.trim_end().len();
    format!(
        "{}{}{}",
        &original[..leading_len],
        value,
        &original[original.len() - trailing_len..]
    )
}

fn merge_existing_layer_entry(
    original: &RawLayerEntry,
    generated: &RawLayerEntry,
    policy: &DxfLayerWritePolicy,
) -> Result<RawLayerEntry, LayerError> {
    let original_handle = original.canonical_handle().ok_or_else(|| {
        unsupported_layer_data(
            original.name(),
            "missing or invalid handle prevents preservation-safe matching",
        )
    })?;
    let generated_handle = generated.canonical_handle().ok_or_else(|| {
        LayerError::new(
            "write_failed",
            "generated DXF LAYER has a missing or invalid handle",
        )
    })?;
    if original_handle != generated_handle {
        return Err(LayerError::new(
            "write_failed",
            format!("generated DXF changed LAYER handle {original_handle} to {generated_handle}"),
        ));
    }

    let mut merged = original.clone();

    let generated_name = required_pair(generated, 2)?;
    let original_name = required_pair(original, 2)?;
    if original_name.value != generated_name.value {
        replace_or_append_pair(&mut merged, generated_name);
    }

    let original_flags = pair_integer(original, 70, 0)?;
    let generated_flags = pair_integer(generated, 70, 0)?;
    const REPRESENTED_FLAG_BITS: i32 = 1 | 4 | 16;
    let merged_flags =
        (original_flags & !REPRESENTED_FLAG_BITS) | (generated_flags & REPRESENTED_FLAG_BITS);
    if merged_flags != original_flags {
        let mut pair = required_pair(generated, 70)?.clone();
        pair.value = format_integer_like(original.value(70), merged_flags);
        replace_or_append_pair(&mut merged, &pair);
    }

    for (code, default) in [(62, 7), (370, -3), (290, 1)] {
        let original_value = pair_integer(original, code, default)?;
        let generated_value = pair_integer(generated, code, default)?;
        if original_value != generated_value {
            replace_or_append_pair(&mut merged, required_pair(generated, code)?);
        }
    }

    let original_line_type = original.value(6).unwrap_or("Continuous");
    let generated_line_type = generated.value(6).unwrap_or("Continuous");
    if original_line_type != generated_line_type {
        replace_or_append_pair(&mut merged, required_pair(generated, 6)?);
    }

    if policy.indexed_color_handles.contains(&original_handle) {
        let direct_extended_color_indices = merged
            .direct_pair_indices()
            .into_iter()
            .filter(|index| matches!(merged.pairs[*index].code_number(), Some(420 | 430)))
            .collect::<BTreeSet<_>>();
        merged.pairs = merged
            .pairs
            .into_iter()
            .enumerate()
            .filter_map(|(index, pair)| {
                (!direct_extended_color_indices.contains(&index)).then_some(pair)
            })
            .collect();
    }

    Ok(merged)
}

fn reparent_created_layer_entry(
    generated: &RawLayerEntry,
    original_table_handle: &str,
) -> Result<RawLayerEntry, LayerError> {
    let owner_indices = generated
        .direct_pair_indices()
        .into_iter()
        .filter(|index| generated.pairs[*index].code_number() == Some(330))
        .collect::<Vec<_>>();
    let [owner_index] = owner_indices.as_slice() else {
        return Err(LayerError::new(
            "write_failed",
            format!(
                "generated DXF LAYER `{}` has {} direct group code 330 owners; expected exactly one",
                generated.name().unwrap_or("<unknown>"),
                owner_indices.len()
            ),
        ));
    };
    canonical_raw_handle(&generated.pairs[*owner_index].value).ok_or_else(|| {
        LayerError::new(
            "write_failed",
            format!(
                "generated DXF LAYER `{}` has an invalid owner handle",
                generated.name().unwrap_or("<unknown>")
            ),
        )
    })?;

    let mut reparented = generated.clone();
    let table_handle = raw_hex_value(original_table_handle, "source LAYER table handle")?;
    reparented.pairs[*owner_index].value =
        format_hex_like(&reparented.pairs[*owner_index].value, table_handle);
    Ok(reparented)
}

fn merge_raw_layer_table(
    original: &RawLayerTable,
    generated: &RawLayerTable,
    policy: &DxfLayerWritePolicy,
    source_identity_handles: &BTreeSet<String>,
    external_reference_handles: &BTreeSet<String>,
    external_layer_names: &BTreeSet<String>,
    external_opaque_layer_names: &BTreeSet<String>,
) -> Result<RawLayerMerge, LayerError> {
    // Revalidate at write time so a source changed between read and save cannot
    // turn a singleton field into an ambiguous last-writer-wins mutation.
    validate_direct_layer_singletons(original)?;
    let original_header = RawLayerEntry {
        pairs: original.header.clone(),
    };
    let original_table_handle = original_header.canonical_handle();

    let mut original_by_handle = BTreeMap::new();
    for entry in &original.entries {
        let handle = entry.canonical_handle().ok_or_else(|| {
            unsupported_layer_data(
                entry.name(),
                "missing or invalid handle prevents preservation-safe matching",
            )
        })?;
        if original_by_handle.insert(handle.clone(), entry).is_some() {
            return Err(unsupported_layer_data(
                entry.name(),
                format!("duplicate LAYER handle {handle}"),
            ));
        }
    }

    let mut generated_by_handle = BTreeMap::new();
    for entry in &generated.entries {
        let handle = entry.canonical_handle().ok_or_else(|| {
            LayerError::new(
                "write_failed",
                "generated DXF LAYER has a missing or invalid handle",
            )
        })?;
        if generated_by_handle.insert(handle.clone(), entry).is_some() {
            return Err(LayerError::new(
                "write_failed",
                format!("generated DXF contains duplicate LAYER handle {handle}"),
            ));
        }
    }

    // Preserve every pre-existing record's relative order. acadrust sorts the
    // generated table, but reordering untouched source records is not part of
    // any layer mutation contract.
    let mut entries = Vec::with_capacity(generated.entries.len());
    let mut renames = Vec::new();
    let mut created_handles = Vec::new();
    for original_entry in &original.entries {
        let handle = original_entry
            .canonical_handle()
            .expect("source handles were validated above");
        if let Some(generated_entry) = generated_by_handle.get(&handle) {
            let original_name = required_pair(original_entry, 2)?.value.clone();
            let generated_name = required_pair(generated_entry, 2)?.value.clone();
            if original_name != generated_name {
                let old_name = original_name.to_uppercase();
                let opaque_table_reference =
                    raw_opaque_layer_reference_names_outside_range(&original.header, &(0..0))
                        .contains(&old_name)
                        || original.entries.iter().any(|candidate| {
                            raw_opaque_layer_reference_names_outside_range(
                                &candidate.pairs,
                                &(0..0),
                            )
                            .contains(&old_name)
                        });
                if external_opaque_layer_names.contains(&old_name) || opaque_table_reference {
                    return Err(unsupported_layer_data(
                        Some(&original_name),
                        "cannot safely rename a layer referenced inside opaque group-102 application data",
                    ));
                }
                renames.push((original_name, generated_name));
            }
            entries.push(merge_existing_layer_entry(
                original_entry,
                generated_entry,
                policy,
            )?);
        } else {
            if original_entry.has_unproven_delete_dependencies() {
                return Err(unsupported_layer_data(
                    original_entry.name(),
                    "cannot safely delete a layer with application groups or hard-owner references",
                ));
            }
            if external_reference_handles.contains(&handle) {
                return Err(unsupported_layer_data(
                    original_entry.name(),
                    format!(
                        "cannot safely delete layer handle {handle} because the source DXF references it"
                    ),
                ));
            }
            if original_entry
                .name()
                .is_some_and(|name| external_layer_names.contains(&name.to_uppercase()))
            {
                return Err(unsupported_layer_data(
                    original_entry.name(),
                    "cannot safely delete a layer referenced outside the LAYER table",
                ));
            }
            if original_entry.name().is_some_and(|deleted_name| {
                external_opaque_layer_names.contains(&deleted_name.to_uppercase())
            }) {
                return Err(unsupported_layer_data(
                    original_entry.name(),
                    "cannot safely delete a layer referenced inside opaque group-102 application data",
                ));
            }
            let referenced_by_other_layer_name =
                original_entry.name().is_some_and(|deleted_name| {
                    let deleted_name = deleted_name.to_uppercase();
                    raw_layer_reference_names_outside_range(&original.header, &(0..0))
                        .contains(&deleted_name)
                        || original.entries.iter().any(|candidate| {
                            candidate.canonical_handle().as_deref() != Some(handle.as_str())
                                && raw_layer_reference_names_outside_range(
                                    &candidate.pairs,
                                    &(0..0),
                                )
                                .contains(&deleted_name)
                        })
                });
            if referenced_by_other_layer_name {
                return Err(unsupported_layer_data(
                    original_entry.name(),
                    "cannot safely delete a layer referenced by another LAYER record",
                ));
            }
            let opaque_reference_in_retained_table =
                original_entry.name().is_some_and(|deleted_name| {
                    let deleted_name = deleted_name.to_uppercase();
                    raw_opaque_layer_reference_names_outside_range(&original.header, &(0..0))
                        .contains(&deleted_name)
                        || original.entries.iter().any(|candidate| {
                            candidate.canonical_handle().as_deref() != Some(handle.as_str())
                                && raw_opaque_layer_reference_names_outside_range(
                                    &candidate.pairs,
                                    &(0..0),
                                )
                                .contains(&deleted_name)
                        })
                });
            if opaque_reference_in_retained_table {
                return Err(unsupported_layer_data(
                    original_entry.name(),
                    "cannot safely delete a layer referenced inside retained opaque group-102 application data",
                ));
            }
        }
    }

    // New records have no source-relative position, so append them in the
    // deterministic order emitted by the generated document.
    for generated_entry in &generated.entries {
        let handle = generated_entry
            .canonical_handle()
            .expect("generated handles were validated above");
        if original_by_handle.contains_key(&handle) {
            continue;
        }
        if source_identity_handles.contains(&handle) || external_reference_handles.contains(&handle)
        {
            return Err(LayerError::new(
                "write_failed",
                format!(
                    "generated DXF LAYER handle {handle} collides with a persisted source identity or reference"
                ),
            ));
        }
        let table_handle = original_table_handle.as_deref().ok_or_else(|| {
            unsupported_layer_data(
                Some("<LAYER table header>"),
                "cannot create a layer because the source LAYER table handle is absent",
            )
        })?;
        created_handles.push(handle);
        entries.push(reparent_created_layer_entry(generated_entry, table_handle)?);
    }

    // Group 1003 is an XDATA layer-name reference. Update direct XDATA and
    // ordinary group-code-8 references in preserved LAYER records, while
    // keeping group-102 application data opaque.
    for entry in &mut entries {
        apply_raw_layer_renames(&mut entry.pairs, &(0..0), &renames);
    }

    let generated_header = RawLayerEntry {
        pairs: generated.header.clone(),
    };
    let mut header = original_header.clone();
    let original_count = pair_integer(&original_header, 70, original.entries.len() as i32)?;
    let generated_count = pair_integer(&generated_header, 70, generated.entries.len() as i32)?;
    if original_count != generated_count {
        let mut count_pair = generated_header
            .direct_pair(70)
            .cloned()
            .unwrap_or(RawDxfPair {
                code: "70".to_string(),
                value: generated_count.to_string(),
            });
        count_pair.value = format_integer_like(original_header.value(70), generated_count);
        replace_or_append_pair(&mut header, &count_pair);
    }
    apply_raw_layer_renames(&mut header.pairs, &(0..0), &renames);

    let expected_header = header.pairs.clone();
    let mut table_pairs = header.pairs;
    for entry in &entries {
        table_pairs.extend(entry.pairs.iter().cloned());
    }
    table_pairs.push(original.trailer.clone());
    Ok(RawLayerMerge {
        table_pairs,
        expected_header,
        expected_entries: entries,
        renames,
        created_handles,
    })
}

fn header_variable_value_index(
    pairs: &[RawDxfPair],
    variable: &str,
    value_code: i32,
) -> Result<Option<usize>, String> {
    let Some(header) = raw_section_range(pairs, "HEADER")? else {
        return Ok(None);
    };
    let mut matches = Vec::new();
    let mut index = header.start;
    while index < header.end {
        if pairs[index].code_number() == Some(9)
            && pairs[index].value.trim().eq_ignore_ascii_case(variable)
        {
            let value_end = (index + 1..header.end)
                .find(|candidate| pairs[*candidate].code_number() == Some(9))
                .unwrap_or(header.end);
            let values = (index + 1..value_end)
                .filter(|candidate| pairs[*candidate].code_number() == Some(value_code))
                .collect::<Vec<_>>();
            match values.as_slice() {
                [value] => matches.push(*value),
                [] => {
                    return Err(format!(
                        "DXF header variable {variable} has no group code {value_code}"
                    ))
                }
                _ => {
                    return Err(format!(
                        "DXF header variable {variable} has repeated group code {value_code}"
                    ))
                }
            }
            index = value_end;
        } else {
            index += 1;
        }
    }
    match matches.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(*value)),
        _ => Err(format!("DXF header repeats variable {variable}")),
    }
}

fn raw_hex_value(value: &str, label: &str) -> Result<u64, LayerError> {
    let value = value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or(value.trim());
    u64::from_str_radix(value, 16).map_err(|_| {
        LayerError::new(
            "write_failed",
            format!("{label} `{value}` is not a hexadecimal handle"),
        )
    })
}

fn format_hex_like(original: &str, value: u64) -> String {
    let leading_len = original.len() - original.trim_start().len();
    let trailing_len = original.len() - original.trim_end().len();
    format!(
        "{}{value:X}{}",
        &original[..leading_len],
        &original[original.len() - trailing_len..]
    )
}

fn advance_handseed_for_created_layers(
    merged_pairs: &mut [RawDxfPair],
    generated_pairs: &[RawDxfPair],
    created_handles: &[String],
) -> Result<(), LayerError> {
    let Some(max_created) = created_handles
        .iter()
        .map(|handle| raw_hex_value(handle, "generated LAYER handle"))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
    else {
        return Ok(());
    };
    let original_index = header_variable_value_index(merged_pairs, "$HANDSEED", 5)
        .map_err(|message| unsupported_layer_data(Some("<HEADER>"), message))?
        .ok_or_else(|| {
            unsupported_layer_data(
                Some("<HEADER>"),
                "cannot create a layer because $HANDSEED is absent",
            )
        })?;
    let original_seed = raw_hex_value(&merged_pairs[original_index].value, "source DXF $HANDSEED")?;
    if original_seed > max_created {
        return Ok(());
    }

    let generated_index = header_variable_value_index(generated_pairs, "$HANDSEED", 5)
        .map_err(|message| LayerError::new("write_failed", message))?
        .ok_or_else(|| LayerError::new("write_failed", "generated DXF omitted $HANDSEED"))?;
    let generated_seed = raw_hex_value(
        &generated_pairs[generated_index].value,
        "generated DXF $HANDSEED",
    )?;
    if generated_seed <= max_created {
        return Err(LayerError::new(
            "write_failed",
            format!(
                "generated DXF $HANDSEED {generated_seed:X} does not advance past new LAYER handle {max_created:X}"
            ),
        ));
    }
    merged_pairs[original_index].value =
        format_hex_like(&merged_pairs[original_index].value, generated_seed);
    Ok(())
}

fn apply_raw_layer_renames(
    pairs: &mut [RawDxfPair],
    excluded: &std::ops::Range<usize>,
    renames: &[(String, String)],
) {
    let renames = renames
        .iter()
        .map(|(old, new)| (old.to_uppercase(), new))
        .collect::<Vec<_>>();
    let mut depth = 0usize;
    for (index, pair) in pairs.iter_mut().enumerate() {
        if excluded.contains(&index) {
            continue;
        }
        let is_open = pair.code_number() == Some(102) && pair.value.trim().starts_with('{');
        let is_close = pair.code_number() == Some(102) && pair.value.trim() == "}";
        if depth == 0 && matches!(pair.code_number(), Some(8 | 1003)) {
            let key = pair.value.to_uppercase();
            if let Some((_, new_name)) = renames.iter().find(|(old, _)| *old == key) {
                pair.value.clone_from(new_name);
            }
        }
        if is_open {
            depth = depth.saturating_add(1);
        } else if is_close {
            depth = depth.saturating_sub(1);
        }
    }
}

fn restore_raw_dxf_layer_data(
    original_path: &Path,
    generated_path: &Path,
    policy: &DxfLayerWritePolicy,
) -> Result<(), LayerError> {
    let original_text = std::fs::read_to_string(original_path).map_err(|err| {
        LayerError::new(
            "drawing_unreadable",
            format!("failed to read source DXF for layer preservation: {err}"),
        )
    })?;
    let generated_text = std::fs::read_to_string(generated_path).map_err(|err| {
        LayerError::new(
            "write_failed",
            format!("failed to read generated DXF for layer preservation: {err}"),
        )
    })?;
    let original_pairs = parse_raw_dxf_pairs(&original_text).map_err(|message| {
        LayerError::new(
            "drawing_unreadable",
            format!("failed to parse source DXF for layer preservation: {message}"),
        )
    })?;
    let generated_pairs = parse_raw_dxf_pairs(&generated_text).map_err(|message| {
        LayerError::new(
            "write_failed",
            format!("failed to parse generated DXF for layer preservation: {message}"),
        )
    })?;
    let original_table = try_parse_raw_layer_table(&original_pairs).map_err(|message| {
        LayerError::new(
            "drawing_unreadable",
            format!("failed to parse source LAYER table: {message}"),
        )
    })?;
    let generated_table = parse_raw_layer_table(&generated_pairs).map_err(|message| {
        LayerError::new(
            "write_failed",
            format!("failed to parse generated LAYER table: {message}"),
        )
    })?;
    let original_table = original_table.ok_or_else(|| {
        unsupported_layer_data(
            Some("<LAYER table>"),
            "the raw LAYER table is absent, so a bounded mutation cannot be proven",
        )
    })?;
    validate_application_groups(&original_pairs)
        .map_err(|message| unsupported_layer_data(Some("<drawing>"), message))?;
    let source_identity_handles = raw_identity_handles(&original_pairs)
        .map_err(|message| unsupported_layer_data(Some("<drawing>"), message))?;
    let external_reference_handles = raw_reference_handles_outside_range(&original_pairs, &(0..0));
    let external_layer_names = raw_layer_reference_names_outside_range(
        &original_pairs,
        &(original_table.start..original_table.end),
    );
    let external_opaque_layer_names = raw_opaque_layer_reference_names_outside_range(
        &original_pairs,
        &(original_table.start..original_table.end),
    );
    let merged = merge_raw_layer_table(
        &original_table,
        &generated_table,
        policy,
        &source_identity_handles,
        &external_reference_handles,
        &external_layer_names,
        &external_opaque_layer_names,
    )?;
    let expected_header = merged.expected_header;
    let expected_entries = merged.expected_entries;

    // Start with the source pairs, not DxfWriter's whole-document output.
    // The selected backend rewrites unrelated HEADER/BLOCK_RECORD/BLOCK/INSERT
    // metadata, including the flags that prove XREF membership. The only
    // authorized non-table delta is a layer rename's direct group-code-8
    // references (including $CLAYER); application groups remain opaque.
    let original_table_range = original_table.start..original_table.end;
    let mut merged_pairs = original_pairs.clone();
    apply_raw_layer_renames(&mut merged_pairs, &original_table_range, &merged.renames);
    merged_pairs.splice(original_table_range, merged.table_pairs);
    advance_handseed_for_created_layers(
        &mut merged_pairs,
        &generated_pairs,
        &merged.created_handles,
    )?;

    let line_ending = if original_text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut rendered = render_raw_dxf_pairs_with_line_ending(&merged_pairs, line_ending);
    if !original_text.ends_with('\n') {
        rendered.truncate(rendered.len().saturating_sub(line_ending.len()));
    }
    std::fs::write(generated_path, rendered).map_err(|err| {
        LayerError::new(
            "write_failed",
            format!("failed to write bounded raw DXF layer patch: {err}"),
        )
    })?;

    let verified_text = std::fs::read_to_string(generated_path).map_err(|err| {
        LayerError::new(
            "write_failed",
            format!("failed to verify preserved DXF layer data: {err}"),
        )
    })?;
    let verified_pairs = parse_raw_dxf_pairs(&verified_text).map_err(|message| {
        LayerError::new(
            "write_failed",
            format!("failed to verify preserved DXF layer data: {message}"),
        )
    })?;
    if verified_pairs != merged_pairs {
        return Err(LayerError::new(
            "write_failed",
            "post-write verification found data outside the bounded raw layer patch",
        ));
    }
    let verified_table = parse_raw_layer_table(&verified_pairs).map_err(|message| {
        LayerError::new(
            "write_failed",
            format!("failed to verify preserved DXF LAYER table: {message}"),
        )
    })?;
    if verified_table.header != expected_header {
        return Err(LayerError::new(
            "write_failed",
            "post-write verification found changed LAYER table header data",
        ));
    }
    if verified_table.entries != expected_entries {
        return Err(LayerError::new(
            "write_failed",
            "post-write verification found changed LAYER record data",
        ));
    }

    DxfReader::from_file(generated_path)
        .map_err(|err| {
            LayerError::new(
                "write_failed",
                format!("failed to reopen preserved DXF: {err}"),
            )
        })?
        .read()
        .map_err(|err| {
            LayerError::new(
                "write_failed",
                format!("failed to parse preserved DXF: {err}"),
            )
        })?;
    Ok(())
}

fn write_dxf_atomically(
    path: &Path,
    doc: &CadDocument,
    policy: &DxfLayerWritePolicy,
    source_identity: &DxfSourceIdentity,
) -> Result<(), LayerError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temp = tempfile::Builder::new()
        .prefix(".autocad-mcp-layer-")
        .suffix(".dxf")
        .tempfile_in(parent)
        .map_err(|err| {
            LayerError::new("write_failed", format!("failed to create temp DXF: {err}"))
        })?;

    DxfWriter::new(doc)
        .write_to_file(temp.path())
        .map_err(|err| {
            LayerError::new("write_failed", format!("failed to write temp DXF: {err}"))
        })?;

    restore_raw_dxf_layer_data(path, temp.path(), policy)?;
    std::fs::set_permissions(temp.path(), source_identity.permissions.clone()).map_err(|err| {
        LayerError::new(
            "write_failed",
            format!("failed to preserve source DXF permissions: {err}"),
        )
    })?;

    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(temp.path())
        .and_then(|file| file.sync_all())
        .map_err(|err| {
            LayerError::new("write_failed", format!("failed to sync temp DXF: {err}"))
        })?;

    // Keep this check immediately adjacent to the atomic replacement. The
    // stable sidecar lock serializes cooperating processes; this byte identity
    // additionally rejects edits from non-cooperating writers.
    verify_dxf_source_identity(path, source_identity)?;
    persist_dxf_temp(temp, path)?;

    std::fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .ok();
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn persist_dxf_temp(temp: tempfile::NamedTempFile, path: &Path) -> Result<(), LayerError> {
    temp.persist(path).map(|_| ()).map_err(|err| {
        LayerError::new(
            "write_failed",
            format!("failed to replace source DXF: {}", err.error),
        )
    })
}

#[cfg(target_os = "windows")]
fn persist_dxf_temp(temp: tempfile::NamedTempFile, path: &Path) -> Result<(), LayerError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    let temp = temp.into_temp_path();
    let replacement = temp
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            replacement.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if result == 0 {
        return Err(LayerError::new(
            "write_failed",
            format!(
                "failed to replace source DXF while preserving Windows metadata: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

fn unsupported_layer_data(layer_name: Option<&str>, message: impl Into<String>) -> LayerError {
    let layer = layer_name.unwrap_or("<unknown>");
    LayerError::new(
        "unsupported_layer_data",
        format!(
            "DXF layer `{layer}` cannot be mutated safely with the selected parser backend's native DXF path: {}",
            message.into()
        ),
    )
}

fn mutate_dxf<T>(
    path: &Path,
    operation: impl FnOnce(&mut CadDocument, &LayerMutationProjectionMetadata) -> Result<T, LayerError>,
    write_policy: impl FnOnce(&T) -> DxfLayerWritePolicy,
) -> Result<T, LayerError> {
    mutate_dxf_with_hook(path, || {}, operation, write_policy)
}

fn mutate_dxf_with_hook<T>(
    canonical_path: &Path,
    after_identity_capture: impl FnOnce(),
    operation: impl FnOnce(&mut CadDocument, &LayerMutationProjectionMetadata) -> Result<T, LayerError>,
    write_policy: impl FnOnce(&T) -> DxfLayerWritePolicy,
) -> Result<T, LayerError> {
    debug_assert!(canonical_path.is_absolute());
    let _mutation_lock = acquire_dxf_mutation_lock(canonical_path)?;
    let source_identity = capture_dxf_source_identity(canonical_path)?;
    after_identity_capture();

    let mut doc = open_dxf(canonical_path)?;
    synchronize_dxf_allocator(canonical_path, &mut doc)?;
    let metadata = read_dxf_layer_metadata(canonical_path)?;
    let result = operation(&mut doc, &metadata)?;
    let policy = write_policy(&result);
    write_dxf_atomically(canonical_path, &doc, &policy, &source_identity)?;
    Ok(result)
}

#[cfg(test)]
pub fn create_layer_file(
    path: &Path,
    name: &str,
    properties: &serde_json::Map<String, serde_json::Value>,
) -> Result<LayerMutationResult, LayerError> {
    create_layer_file_impl(path, name, properties, None)
}

pub fn create_layer_file_with_activation(
    path: &Path,
    name: &str,
    properties: &serde_json::Map<String, serde_json::Value>,
    runtime: &ProductionMutationRuntime,
) -> Result<LayerMutationResult, LayerError> {
    create_layer_file_impl(path, name, properties, Some(runtime))
}

fn create_layer_file_impl(
    path: &Path,
    name: &str,
    properties: &serde_json::Map<String, serde_json::Value>,
    runtime: Option<&ProductionMutationRuntime>,
) -> Result<LayerMutationResult, LayerError> {
    let (ext, drawing) = validate_layer_path(path, "create_layer")?;
    let drawing_display = drawing.to_string_lossy().into_owned();
    match ext.as_str() {
        "dxf" => {
            let layer = mutate_dxf(
                &drawing,
                |doc, _metadata| {
                    layers::create_layer_with_mutation_projection(
                        doc,
                        name,
                        properties,
                        LayerMutationProjectionContext::DXF,
                    )
                },
                |_| DxfLayerWritePolicy::default(),
            )?;
            Ok(LayerMutationResult {
                status: "ok".to_string(),
                drawing: drawing_display,
                layer,
            })
        }
        "dwg" => {
            let selected = acquire_dwg_layer_activation(runtime, "create_layer", &drawing)?;
            create_layer_dwg(&drawing, name, properties, selected.as_deref())
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
pub fn update_layer_file(
    path: &Path,
    selector: &LayerSelector,
    properties: &serde_json::Map<String, serde_json::Value>,
) -> Result<LayerMutationResult, LayerError> {
    update_layer_file_impl(path, selector, properties, None)
}

pub fn update_layer_file_with_activation(
    path: &Path,
    selector: &LayerSelector,
    properties: &serde_json::Map<String, serde_json::Value>,
    runtime: &ProductionMutationRuntime,
) -> Result<LayerMutationResult, LayerError> {
    update_layer_file_impl(path, selector, properties, Some(runtime))
}

fn update_layer_file_impl(
    path: &Path,
    selector: &LayerSelector,
    properties: &serde_json::Map<String, serde_json::Value>,
    runtime: Option<&ProductionMutationRuntime>,
) -> Result<LayerMutationResult, LayerError> {
    let (ext, drawing) = validate_layer_path(path, "update_layer")?;
    let drawing_display = drawing.to_string_lossy().into_owned();
    match ext.as_str() {
        "dxf" => {
            let writes_indexed_color = properties.contains_key("color_index");
            let layer = mutate_dxf(
                &drawing,
                |doc, metadata| {
                    let updated = layers::update_layer_with_mutation_projection(
                        doc,
                        selector,
                        properties,
                        LayerMutationProjectionContext::DXF,
                    )?;
                    if writes_indexed_color {
                        Ok(updated)
                    } else {
                        layers::project_layer_for_mutation_with_metadata(
                            doc,
                            &LayerSelector {
                                handle: Some(updated.handle),
                                ..Default::default()
                            },
                            LayerMutationProjectionContext::DXF,
                            metadata,
                        )
                    }
                },
                |layer| {
                    let mut policy = DxfLayerWritePolicy::default();
                    if writes_indexed_color {
                        policy
                            .indexed_color_handles
                            .insert(layer.handle.to_ascii_uppercase());
                    }
                    policy
                },
            )?;
            Ok(LayerMutationResult {
                status: "ok".to_string(),
                drawing: drawing_display,
                layer,
            })
        }
        "dwg" => {
            let selected = acquire_dwg_layer_activation(runtime, "update_layer", &drawing)?;
            update_layer_dwg(&drawing, selector, properties, selected.as_deref())
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
pub fn rename_layer_file(
    path: &Path,
    selector: &LayerSelector,
    new_name: &str,
) -> Result<LayerMutationResult, LayerError> {
    rename_layer_file_impl(path, selector, new_name, None)
}

pub fn rename_layer_file_with_activation(
    path: &Path,
    selector: &LayerSelector,
    new_name: &str,
    runtime: &ProductionMutationRuntime,
) -> Result<LayerMutationResult, LayerError> {
    rename_layer_file_impl(path, selector, new_name, Some(runtime))
}

fn rename_layer_file_impl(
    path: &Path,
    selector: &LayerSelector,
    new_name: &str,
    runtime: Option<&ProductionMutationRuntime>,
) -> Result<LayerMutationResult, LayerError> {
    let (ext, drawing) = validate_layer_path(path, "rename_layer")?;
    let drawing_display = drawing.to_string_lossy().into_owned();
    match ext.as_str() {
        "dxf" => {
            let layer = mutate_dxf(
                &drawing,
                |doc, metadata| {
                    let renamed = layers::rename_layer_with_mutation_projection(
                        doc,
                        selector,
                        new_name,
                        LayerMutationProjectionContext::DXF,
                    )?;
                    layers::project_layer_for_mutation_with_metadata(
                        doc,
                        &LayerSelector {
                            handle: Some(renamed.handle),
                            ..Default::default()
                        },
                        LayerMutationProjectionContext::DXF,
                        metadata,
                    )
                },
                |_| DxfLayerWritePolicy::default(),
            )?;
            Ok(LayerMutationResult {
                status: "ok".to_string(),
                drawing: drawing_display,
                layer,
            })
        }
        "dwg" => {
            let selected = acquire_dwg_layer_activation(runtime, "rename_layer", &drawing)?;
            rename_layer_dwg(&drawing, selector, new_name, selected.as_deref())
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
pub fn delete_layer_file(
    path: &Path,
    selector: &LayerSelector,
) -> Result<DeleteLayerResult, LayerError> {
    delete_layer_file_impl(path, selector, None)
}

pub fn delete_layer_file_with_activation(
    path: &Path,
    selector: &LayerSelector,
    runtime: &ProductionMutationRuntime,
) -> Result<DeleteLayerResult, LayerError> {
    delete_layer_file_impl(path, selector, Some(runtime))
}

fn delete_layer_file_impl(
    path: &Path,
    selector: &LayerSelector,
    runtime: Option<&ProductionMutationRuntime>,
) -> Result<DeleteLayerResult, LayerError> {
    let (ext, drawing) = validate_layer_path(path, "delete_layer")?;
    let drawing_display = drawing.to_string_lossy().into_owned();
    match ext.as_str() {
        "dxf" => {
            let layer = mutate_dxf(
                &drawing,
                |doc, _metadata| layers::delete_layer(doc, selector),
                |_| DxfLayerWritePolicy::default(),
            )?;
            Ok(DeleteLayerResult {
                status: "deleted".to_string(),
                drawing: drawing_display,
                layer,
            })
        }
        "dwg" => {
            let selected = acquire_dwg_layer_activation(runtime, "delete_layer", &drawing)?;
            delete_layer_dwg(&drawing, selector, selected.as_deref())
        }
        _ => unreachable!(),
    }
}

#[cfg(not(target_os = "windows"))]
fn create_layer_dwg(
    path: &Path,
    _name: &str,
    _properties: &serde_json::Map<String, serde_json::Value>,
    _selected: Option<&SelectedActivation>,
) -> Result<LayerMutationResult, LayerError> {
    Err(unsupported_platform("create_layer", path))
}

#[cfg(not(target_os = "windows"))]
fn update_layer_dwg(
    path: &Path,
    _selector: &LayerSelector,
    _properties: &serde_json::Map<String, serde_json::Value>,
    _selected: Option<&SelectedActivation>,
) -> Result<LayerMutationResult, LayerError> {
    Err(unsupported_platform("update_layer", path))
}

#[cfg(not(target_os = "windows"))]
fn rename_layer_dwg(
    path: &Path,
    _selector: &LayerSelector,
    _new_name: &str,
    _selected: Option<&SelectedActivation>,
) -> Result<LayerMutationResult, LayerError> {
    Err(unsupported_platform("rename_layer", path))
}

#[cfg(not(target_os = "windows"))]
fn delete_layer_dwg(
    path: &Path,
    _selector: &LayerSelector,
    _selected: Option<&SelectedActivation>,
) -> Result<DeleteLayerResult, LayerError> {
    Err(unsupported_platform("delete_layer", path))
}

#[cfg(target_os = "windows")]
fn create_layer_dwg(
    path: &Path,
    name: &str,
    properties: &serde_json::Map<String, serde_json::Value>,
    selected: Option<&SelectedActivation>,
) -> Result<LayerMutationResult, LayerError> {
    let lsp = generate_create_layer_lsp(name, properties)?;
    run_layer_dwg_script("create_layer", path, lsp, selected)
}

#[cfg(target_os = "windows")]
fn update_layer_dwg(
    path: &Path,
    selector: &LayerSelector,
    properties: &serde_json::Map<String, serde_json::Value>,
    selected: Option<&SelectedActivation>,
) -> Result<LayerMutationResult, LayerError> {
    let lsp = generate_update_layer_lsp(selector, properties)?;
    run_layer_dwg_script("update_layer", path, lsp, selected)
}

#[cfg(target_os = "windows")]
fn rename_layer_dwg(
    path: &Path,
    selector: &LayerSelector,
    new_name: &str,
    selected: Option<&SelectedActivation>,
) -> Result<LayerMutationResult, LayerError> {
    let lsp = generate_rename_layer_lsp(selector, new_name)?;
    run_layer_dwg_script("rename_layer", path, lsp, selected)
}

#[cfg(target_os = "windows")]
fn delete_layer_dwg(
    path: &Path,
    selector: &LayerSelector,
    selected: Option<&SelectedActivation>,
) -> Result<DeleteLayerResult, LayerError> {
    let lsp = generate_delete_layer_lsp(selector)?;
    run_layer_dwg_script("delete_layer", path, lsp, selected)
}

#[cfg(target_os = "windows")]
fn run_layer_dwg_script<T: serde::de::DeserializeOwned>(
    tool: &str,
    path: &Path,
    lsp: String,
    selected: Option<&SelectedActivation>,
) -> Result<T, LayerError> {
    use crate::engine;

    let staging = engine::create_staging_dir()
        .map_err(|err| LayerError::new("write_failed", format!("{tool}: {err}")))?;
    let staging_path = staging.path();
    let lsp_path = staging_path.join(format!("{tool}.lsp"));
    let scr_path = staging_path.join(format!("{tool}.scr"));

    std::fs::write(&lsp_path, lsp)
        .map_err(|err| LayerError::new("write_failed", format!("failed to write LSP: {err}")))?;
    let lsp_path_str = lsp_path
        .to_str()
        .ok_or_else(|| LayerError::new("write_failed", "staging path is not valid UTF-8"))?;
    std::fs::write(&scr_path, generate_layer_scr(lsp_path_str))
        .map_err(|err| LayerError::new("write_failed", format!("failed to write script: {err}")))?;

    let output = match selected {
        Some(selected) => engine::run_accoreconsole_with_selected_activation(
            selected,
            path,
            &scr_path,
            staging_path,
            &[],
        ),
        None => {
            let exe = engine::find_accoreconsole()
                .map_err(|err| LayerError::new("write_failed", format!("{tool}: {err}")))?;
            engine::run_accoreconsole(&exe, path, &scr_path, staging_path)
        }
    }
    .map_err(|err| {
        LayerError::new(
            "mutation_state_unknown",
            format!("{tool}: drawing_may_be_modified=true accoreconsole failed: {err}"),
        )
    })?;
    parse_layer_result_output(tool, &output)
}

#[cfg(any(test, target_os = "windows"))]
fn lisp_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(any(test, target_os = "windows"))]
fn lisp_optional_string(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", lisp_string(value)))
        .unwrap_or_else(|| "nil".to_string())
}

#[cfg(any(test, target_os = "windows"))]
fn validate_selector_handles(selector: &LayerSelector) -> Result<(), LayerError> {
    if let Some(handle) = &selector.handle {
        layers::parse_handle(handle)?;
    }
    if let Some(expected_handle) = &selector.expected_handle {
        layers::parse_handle(expected_handle)?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn generate_layer_scr(lsp_path: &str) -> String {
    let lsp_forward = lsp_path.replace('\\', "/");
    format!(
        "(setvar \"SECURELOAD\" 0)\n\
         (setvar \"FILEDIA\" 0)(setvar \"CMDDIA\" 0)\n\
         (load \"{lsp_forward}\")\n\
         QUIT\n\
         Y\n"
    )
}

#[cfg(any(test, target_os = "windows"))]
fn layer_script_prelude(selector: Option<&LayerSelector>) -> String {
    let handle = selector.and_then(|selector| selector.handle.as_deref());
    let name = selector.and_then(|selector| selector.name.as_deref());
    let expected_handle = selector.and_then(|selector| selector.expected_handle.as_deref());
    let expected_name = selector.and_then(|selector| selector.expected_name.as_deref());
    format!(
        r#";; Generated by autocad-mcp - do not edit
(setq _mcpl:handle {handle})
(setq _mcpl:name {name})
(setq _mcpl:expected-handle {expected_handle})
(setq _mcpl:expected-name {expected_name})
(defun _mcpl:bool (v) (if v "true" "false"))
(defun _mcpl:ci= (a b) (= (strcase a) (strcase b)))
(defun _mcpl:bit (flags bit) (not (= 0 (logand flags bit))))
(defun _mcpl:err (code msg) (princ (strcat "\nRESULT:ERROR:" code ":" msg "\n")) nil)
(defun _mcpl:drawing () (strcat (getvar "DWGPREFIX") (getvar "DWGNAME")))
(defun _mcpl:replace-all (s old new / p old-len)
  (setq old-len (strlen old))
  (while (setq p (vl-string-search old s))
    (setq s (strcat (substr s 1 p) new (substr s (+ p old-len 1)))))
  s)
(defun _mcpl:json-escape (s / )
  (if (not s) (setq s ""))
  (setq s (_mcpl:replace-all s "\\" "\\\\"))
  (setq s (_mcpl:replace-all s "\"" "\\\""))
  s)
(defun _mcpl:json-string (s) (strcat "\"" (_mcpl:json-escape s) "\""))
(defun _mcpl:json-opt-string (s) (if s (_mcpl:json-string s) "null"))
(defun _mcpl:canon-handle (h / u) (if h (progn (setq u (strcase h)) (if (= "0X" (substr u 1 2)) (substr u 3) u)) nil))
(setq _mcpl:handle (_mcpl:canon-handle _mcpl:handle))
(setq _mcpl:expected-handle (_mcpl:canon-handle _mcpl:expected-handle))
(defun _mcpl:line-weight-json (v / standards)
  (setq standards (list 0 5 9 13 15 18 20 25 30 35 40 50 53 60 70 80 90 100 106 120 140 158 200 211))
  (cond
    ((= v -1) "{{\"kind\":\"by_layer\"}}")
    ((= v -2) "{{\"kind\":\"by_block\"}}")
    ((= v -3) "{{\"kind\":\"default\"}}")
    ((member v standards) (strcat "{{\"kind\":\"value\",\"hundredths_mm\":" (itoa v) "}}"))
    (T (strcat "{{\"kind\":\"raw\",\"raw_value\":" (itoa v) "}}"))))
(defun _mcpl:app-open-p (pair)
  (and (= (car pair) 102) (> (strlen (cdr pair)) 0) (= (substr (cdr pair) 1 1) "{{")))
(defun _mcpl:app-close-p (pair) (and (= (car pair) 102) (= (cdr pair) "}}")))
(defun _mcpl:direct-assoc (code d / depth pair found)
  (setq depth 0)
  (while (and d (not found))
    (setq pair (car d))
    (cond
      ((_mcpl:app-open-p pair) (setq depth (1+ depth)))
      ((_mcpl:app-close-p pair) (setq depth (max 0 (1- depth))))
      ((and (= depth 0) (= (car pair) code)) (setq found pair)))
    (setq d (cdr d)))
  found)
(defun _mcpl:set-pair (d code value / depth pair out replaced)
  (setq depth 0 out nil replaced nil)
  (while d
    (setq pair (car d))
    (cond
      ((_mcpl:app-open-p pair) (setq out (cons pair out) depth (1+ depth)))
      ((_mcpl:app-close-p pair) (setq depth (max 0 (1- depth)) out (cons pair out)))
      ((and (= depth 0) (= (car pair) code) (not replaced))
        (setq out (cons (cons code value) out) replaced T))
      (T (setq out (cons pair out))))
    (setq d (cdr d)))
  (setq out (reverse out))
  (if replaced out (append out (list (cons code value)))))
(defun _mcpl:remove-direct-code (d code / depth pair out)
  (setq depth 0 out nil)
  (while d
    (setq pair (car d))
    (cond
      ((_mcpl:app-open-p pair) (setq out (cons pair out) depth (1+ depth)))
      ((_mcpl:app-close-p pair) (setq depth (max 0 (1- depth)) out (cons pair out)))
      ((and (= depth 0) (= (car pair) code)) nil)
      (T (setq out (cons pair out))))
    (setq d (cdr d)))
  (reverse out))
(defun _mcpl:handle-value (v / d)
  (cond
    ((not v) nil)
    ((= (type v) 'ENAME) (progn (setq d (entget v)) (if d (cdr (_mcpl:direct-assoc 5 d)) nil)))
    ((= (type v) 'STR) (_mcpl:canon-handle v))
    (T nil)))
(defun _mcpl:xref-name (n / p) (if (setq p (vl-string-search "|" n)) (if (> p 0) (substr n 1 p) nil) nil))
(defun _mcpl:record-json (e / d h n color abscolor non-indexed-color flags plot frozen locked off xref current line-type line-weight xref-name xref-block xref-data xref-handle xref-path xref-flags xref-overlay material-handle plotstyle-handle)
  (setq d (entget e) h (cdr (_mcpl:direct-assoc 5 d)) n (cdr (_mcpl:direct-assoc 2 d)) color (cdr (_mcpl:direct-assoc 62 d)) flags (cdr (_mcpl:direct-assoc 70 d)) plot (cdr (_mcpl:direct-assoc 290 d)) line-type (cdr (_mcpl:direct-assoc 6 d)) line-weight (cdr (_mcpl:direct-assoc 370 d)))
  (setq non-indexed-color (or (_mcpl:direct-assoc 420 d) (_mcpl:direct-assoc 430 d)))
  (if (not color) (setq color 7))
  (if (not flags) (setq flags 0))
  (if (not plot) (setq plot 1))
  (if (not line-type) (setq line-type "Continuous"))
  (if (not line-weight) (setq line-weight -3))
  (setq off (< color 0) abscolor (abs color) frozen (_mcpl:bit flags 1) locked (_mcpl:bit flags 4) xref (or (_mcpl:bit flags 16) (wcmatch n "*|*")) current (_mcpl:ci= n (getvar "CLAYER")))
  (setq xref-name (_mcpl:xref-name n))
  (setq xref-block (if xref-name (tblobjname "BLOCK" xref-name) nil))
  (setq xref-data (if xref-block (entget xref-block) nil))
  (setq xref-handle (if xref-data (cdr (_mcpl:direct-assoc 5 xref-data)) nil))
  (setq xref-path (if xref-data (cdr (_mcpl:direct-assoc 1 xref-data)) nil))
  (setq xref-flags (if xref-data (cdr (_mcpl:direct-assoc 70 xref-data)) nil))
  (setq xref-overlay (if xref-flags (_mcpl:bit xref-flags 8) nil))
  (setq material-handle (_mcpl:handle-value (cdr (_mcpl:direct-assoc 347 d))))
  (setq plotstyle-handle (_mcpl:handle-value (cdr (_mcpl:direct-assoc 390 d))))
  (strcat "{{\"handle\":" (_mcpl:json-string h) ",\"name\":" (_mcpl:json-string n) ",\"color_index\":" (if (and (not non-indexed-color) (>= abscolor 1) (<= abscolor 255)) (itoa abscolor) "null") ",\"line_type\":" (_mcpl:json-string line-type) ",\"line_weight\":" (_mcpl:line-weight-json line-weight) ",\"frozen\":" (_mcpl:bool frozen) ",\"locked\":" (_mcpl:bool locked) ",\"off\":" (_mcpl:bool off) ",\"is_plottable\":" (_mcpl:bool (= plot 1)) ",\"xref_dependent\":" (_mcpl:bool xref) ",\"xref_block_record_handle\":" (_mcpl:json-opt-string xref-handle) ",\"xref_name\":" (_mcpl:json-opt-string xref-name) ",\"xref_path\":" (_mcpl:json-opt-string xref-path) ",\"xref_is_overlay\":" (if xref-overlay (_mcpl:bool xref-overlay) "null") ",\"material_handle\":" (_mcpl:json-opt-string material-handle) ",\"plotstyle_handle\":" (_mcpl:json-opt-string plotstyle-handle) ",\"is_current\":" (_mcpl:bool current) "}}"))
(defun _mcpl:ok-layer (drawing e) (princ (strcat "\nRESULT:OK:{{\"status\":\"ok\",\"drawing\":" (_mcpl:json-string drawing) ",\"layer\":" (_mcpl:record-json e) "}}\n")))
(defun _mcpl:save-ok ( / )
  (command "_.QSAVE")
  (if (= 0 (getvar "DBMOD")) T (_mcpl:err "mutation_state_unknown" "drawing_may_be_modified=true save not confirmed")))
(defun _mcpl:save-and-ok-layer (e) (if (_mcpl:save-ok) (_mcpl:ok-layer (_mcpl:drawing) e)))
(defun _mcpl:resolve ( / byh byn dh dn)
  (if _mcpl:handle (setq byh (handent _mcpl:handle)))
  (if (and byh (/= "LAYER" (cdr (_mcpl:direct-assoc 0 (entget byh))))) (setq byh nil))
  (if _mcpl:name (setq byn (tblobjname "LAYER" _mcpl:name)))
  (if (and _mcpl:handle _mcpl:name (or (not byh) (not byn))) (progn (_mcpl:err "layer_identity_mismatch" "layer handle and name did not both resolve to the same layer") nil)
  (if (and _mcpl:handle (not byh)) (_mcpl:err "layer_not_found" "layer handle not found")
  (if (and _mcpl:name (not byn)) (_mcpl:err "layer_not_found" "layer name not found")
  (if (and byh byn (/= (cdr (_mcpl:direct-assoc 5 (entget byh))) (cdr (_mcpl:direct-assoc 5 (entget byn))))) (progn (_mcpl:err "layer_identity_mismatch" "layer handle and name resolved to different layers") nil)
    (progn
      (setq byh (if byh byh byn))
      (if (not byh) (_mcpl:err "layer_not_found" "layer not found")
        (progn
          (setq dh (cdr (_mcpl:direct-assoc 5 (entget byh))) dn (cdr (_mcpl:direct-assoc 2 (entget byh))))
          (if (and _mcpl:expected-handle (/= (strcase _mcpl:expected-handle) (strcase dh))) (_mcpl:err "expected_handle_mismatch" "expected handle mismatch")
            (if (and _mcpl:expected-name (not (_mcpl:ci= _mcpl:expected-name dn))) (_mcpl:err "expected_name_mismatch" "expected name mismatch") byh)))))))))
(defun _mcpl:protected-p (name) (or (_mcpl:ci= name "0") (_mcpl:ci= name "DEFPOINTS")))
(defun _mcpl:xref-p (e / d flags name) (setq d (entget e) flags (cdr (_mcpl:direct-assoc 70 d)) name (cdr (_mcpl:direct-assoc 2 d))) (or (and flags (_mcpl:bit flags 16)) (wcmatch name "*|*")))
(defun _mcpl:has-any-char-p (s chars / hit)
  (setq hit nil)
  (while chars (if (vl-string-search (car chars) s) (setq hit T)) (setq chars (cdr chars)))
  hit)
(defun _mcpl:invalid-name-p (s / trimmed)
  (setq trimmed (if s (vl-string-trim " \t\r\n" s) ""))
  (or (not s) (= s "") (/= s trimmed) (> (strlen s) 255) (_mcpl:ci= s "0") (_mcpl:ci= s "DEFPOINTS") (_mcpl:has-any-char-p s (list "<" ">" "/" "\\" "\"" ":" ";" "?" "*" "|" "=" "`"))))
"#,
        handle = lisp_optional_string(handle),
        name = lisp_optional_string(name),
        expected_handle = lisp_optional_string(expected_handle),
        expected_name = lisp_optional_string(expected_name),
    )
}

#[cfg(any(test, target_os = "windows"))]
fn parse_bool_property(value: &serde_json::Value, name: &str) -> Result<bool, LayerError> {
    value.as_bool().ok_or_else(|| {
        LayerError::new(
            "invalid_layer_property",
            format!("{name} must be a boolean"),
        )
    })
}

#[cfg(any(test, target_os = "windows"))]
fn parse_color_property(value: &serde_json::Value) -> Result<u64, LayerError> {
    let raw = value.as_u64().ok_or_else(|| {
        LayerError::new(
            "invalid_layer_property",
            "color_index must be an integer from 1 to 255",
        )
    })?;
    if !(1..=255).contains(&raw) {
        return Err(LayerError::new(
            "invalid_layer_property",
            "color_index must be from 1 to 255",
        ));
    }
    Ok(raw)
}

#[cfg(any(test, target_os = "windows"))]
fn parse_line_type_property(value: &serde_json::Value) -> Result<&str, LayerError> {
    let Some(line_type) = value.as_str() else {
        return Err(LayerError::new(
            "invalid_layer_property",
            "line_type must be a string",
        ));
    };
    if line_type.is_empty() || line_type.trim() != line_type {
        return Err(LayerError::new(
            "invalid_layer_property",
            "line_type must not be empty or padded",
        ));
    }
    Ok(line_type)
}

#[cfg(any(test, target_os = "windows"))]
fn push_property_lisp(
    lisp: &mut String,
    key: &str,
    value: &serde_json::Value,
) -> Result<(), LayerError> {
    match key {
        "color_index" => lisp.push_str(&format!(
            "(setq _mcpl:color {})\n",
            parse_color_property(value)?
        )),
        "line_type" => lisp.push_str(&format!(
            "(setq _mcpl:line-type \"{}\")\n",
            lisp_string(parse_line_type_property(value)?)
        )),
        "line_weight" => lisp.push_str(&format!(
            "(setq _mcpl:line-weight {})\n",
            layers::parse_line_weight_property(value)?.value()
        )),
        "frozen" => lisp.push_str(&format!(
            "(setq _mcpl:frozen {})\n",
            if parse_bool_property(value, key)? {
                "T"
            } else {
                "nil"
            }
        )),
        "locked" => lisp.push_str(&format!(
            "(setq _mcpl:locked {})\n",
            if parse_bool_property(value, key)? {
                "T"
            } else {
                "nil"
            }
        )),
        "off" => lisp.push_str(&format!(
            "(setq _mcpl:off {})\n",
            if parse_bool_property(value, key)? {
                "T"
            } else {
                "nil"
            }
        )),
        "is_plottable" => lisp.push_str(&format!(
            "(setq _mcpl:plot {})\n",
            if parse_bool_property(value, key)? {
                "1"
            } else {
                "0"
            }
        )),
        other if layers::is_unsupported_layer_property(other) => {
            return Err(layers::unsupported_layer_property(other));
        }
        other => {
            return Err(LayerError::new(
                "invalid_layer_property",
                format!("unknown layer property `{other}`"),
            ))
        }
    }
    Ok(())
}

#[cfg(any(test, target_os = "windows"))]
fn layer_property_lisp(
    properties: &serde_json::Map<String, serde_json::Value>,
) -> Result<String, LayerError> {
    if properties.is_empty() {
        return Err(LayerError::new(
            "empty_layer_update",
            "layer update properties are empty",
        ));
    }
    let mut lisp = String::new();
    for (key, value) in properties {
        push_property_lisp(&mut lisp, key, value)?;
    }
    Ok(lisp)
}

#[cfg(any(test, target_os = "windows"))]
fn generate_create_layer_lsp(
    name: &str,
    properties: &serde_json::Map<String, serde_json::Value>,
) -> Result<String, LayerError> {
    layers::validate_layer_name(name)?;
    let mut s = layer_script_prelude(None);
    s.push_str(&format!(
        "(setq _mcpl:new-name \"{}\" _mcpl:color 7 _mcpl:line-type \"Continuous\" _mcpl:line-weight -3 _mcpl:frozen nil _mcpl:locked nil _mcpl:off nil _mcpl:plot 1)\n",
        lisp_string(name)
    ));
    for (key, value) in properties {
        push_property_lisp(&mut s, key, value)?;
    }
    s.push_str(
        r#"
(if (tblobjname "LAYER" _mcpl:new-name)
  (_mcpl:err "layer_name_collision" "layer already exists")
  (if (not (tblobjname "LTYPE" _mcpl:line-type))
    (_mcpl:err "line_type_not_found" "line_type was not found in the drawing linetype table")
    (progn
      (setq _mcpl:flags (+ (if _mcpl:frozen 1 0) (if _mcpl:locked 4 0)))
      (setq _mcpl:aci (if _mcpl:off (- 0 _mcpl:color) _mcpl:color))
      (entmake (list '(0 . "LAYER") '(100 . "AcDbSymbolTableRecord") '(100 . "AcDbLayerTableRecord") (cons 2 _mcpl:new-name) (cons 70 _mcpl:flags) (cons 62 _mcpl:aci) (cons 6 _mcpl:line-type) (cons 370 _mcpl:line-weight) (cons 290 _mcpl:plot)))
      (setq _mcpl:e (tblobjname "LAYER" _mcpl:new-name))
      (if _mcpl:e (_mcpl:save-and-ok-layer _mcpl:e) (_mcpl:err "write_failed" "AutoCAD did not create the layer")))))
(princ)
"#,
    );
    Ok(s)
}

#[cfg(any(test, target_os = "windows"))]
fn generate_update_layer_lsp(
    selector: &LayerSelector,
    properties: &serde_json::Map<String, serde_json::Value>,
) -> Result<String, LayerError> {
    validate_selector_handles(selector)?;
    let mut s = layer_script_prelude(Some(selector));
    s.push_str("(setq _mcpl:color nil _mcpl:line-type nil _mcpl:line-weight nil _mcpl:frozen 'unset _mcpl:locked 'unset _mcpl:off 'unset _mcpl:plot nil)\n");
    s.push_str(&layer_property_lisp(properties)?);
    s.push_str(
        r#"
(setq _mcpl:e (_mcpl:resolve))
(if _mcpl:e
  (progn
    (setq _mcpl:d (entget _mcpl:e) _mcpl:name (cdr (_mcpl:direct-assoc 2 _mcpl:d)) _mcpl:flags (cdr (_mcpl:direct-assoc 70 _mcpl:d)) _mcpl:aci (cdr (_mcpl:direct-assoc 62 _mcpl:d)))
    (if (not _mcpl:flags) (setq _mcpl:flags 0))
    (if (not _mcpl:aci) (setq _mcpl:aci 7))
    (if (and _mcpl:line-type (not (tblobjname "LTYPE" _mcpl:line-type)))
      (_mcpl:err "line_type_not_found" "line_type was not found in the drawing linetype table")
      (if (and (_mcpl:ci= _mcpl:name (getvar "CLAYER")) (eq _mcpl:frozen T))
        (_mcpl:err "cannot_freeze_current_layer" "cannot freeze the current layer")
        (progn
          (if (not (eq _mcpl:frozen 'unset)) (setq _mcpl:flags (if _mcpl:frozen (logior _mcpl:flags 1) (logand _mcpl:flags -2))))
          (if (not (eq _mcpl:locked 'unset)) (setq _mcpl:flags (if _mcpl:locked (logior _mcpl:flags 4) (logand _mcpl:flags -5))))
          (if _mcpl:color
            (progn
              (setq _mcpl:aci (if (< _mcpl:aci 0) (- 0 _mcpl:color) _mcpl:color))
              (setq _mcpl:d (_mcpl:remove-direct-code (_mcpl:remove-direct-code _mcpl:d 420) 430))))
          (if (not (eq _mcpl:off 'unset)) (setq _mcpl:aci (if _mcpl:off (- 0 (abs _mcpl:aci)) (abs _mcpl:aci))))
          (setq _mcpl:d (_mcpl:set-pair _mcpl:d 70 _mcpl:flags))
          (setq _mcpl:d (_mcpl:set-pair _mcpl:d 62 _mcpl:aci))
          (if _mcpl:line-type (setq _mcpl:d (_mcpl:set-pair _mcpl:d 6 _mcpl:line-type)))
          (if _mcpl:line-weight (setq _mcpl:d (_mcpl:set-pair _mcpl:d 370 _mcpl:line-weight)))
          (if _mcpl:plot (setq _mcpl:d (_mcpl:set-pair _mcpl:d 290 _mcpl:plot)))
          (entmod _mcpl:d) (entupd _mcpl:e) (_mcpl:save-and-ok-layer _mcpl:e)))))))
(princ)
"#,
    );
    Ok(s)
}

#[cfg(any(test, target_os = "windows"))]
fn generate_rename_layer_lsp(
    selector: &LayerSelector,
    new_name: &str,
) -> Result<String, LayerError> {
    validate_selector_handles(selector)?;
    let mut s = layer_script_prelude(Some(selector));
    s.push_str(&format!(
        "(setq _mcpl:new-name \"{}\")\n",
        lisp_string(new_name)
    ));
    s.push_str(
        r#"
(setq _mcpl:e (_mcpl:resolve))
(if _mcpl:e
  (progn
    (setq _mcpl:d (entget _mcpl:e) _mcpl:old-name (cdr (_mcpl:direct-assoc 2 _mcpl:d)) _mcpl:old-handle (cdr (_mcpl:direct-assoc 5 _mcpl:d)) _mcpl:target (tblobjname "LAYER" _mcpl:new-name))
    (cond
      ((_mcpl:protected-p _mcpl:old-name) (_mcpl:err "protected_layer" "cannot rename protected layer"))
      ((_mcpl:xref-p _mcpl:e) (_mcpl:err "xref_dependent_layer" "cannot rename xref-dependent layer"))
      ((_mcpl:invalid-name-p _mcpl:new-name) (_mcpl:err "invalid_layer_name" "invalid new layer name"))
      ((and _mcpl:target (/= _mcpl:old-handle (cdr (_mcpl:direct-assoc 5 (entget _mcpl:target))))) (_mcpl:err "layer_name_collision" "target layer already exists"))
      (T
        (setq _mcpl:ss (ssget "X" (list (cons 8 _mcpl:old-name))))
        (entmod (_mcpl:set-pair _mcpl:d 2 _mcpl:new-name))
        (if _mcpl:ss
          (progn
            (setq _mcpl:i 0)
            (while (< _mcpl:i (sslength _mcpl:ss))
              (setq _mcpl:obj (ssname _mcpl:ss _mcpl:i) _mcpl:od (entget _mcpl:obj))
              (entmod (_mcpl:set-pair _mcpl:od 8 _mcpl:new-name))
              (setq _mcpl:i (1+ _mcpl:i)))))
        (if (_mcpl:ci= _mcpl:old-name (getvar "CLAYER")) (setvar "CLAYER" _mcpl:new-name))
        (_mcpl:save-and-ok-layer (tblobjname "LAYER" _mcpl:new-name)))))))
(princ)
"#,
    );
    Ok(s)
}

#[cfg(any(test, target_os = "windows"))]
fn generate_delete_layer_lsp(selector: &LayerSelector) -> Result<String, LayerError> {
    validate_selector_handles(selector)?;
    let mut s = layer_script_prelude(Some(selector));
    s.push_str(
        r#"
(setq _mcpl:e (_mcpl:resolve))
(if _mcpl:e
  (progn
    (setq _mcpl:d (entget _mcpl:e) _mcpl:name (cdr (_mcpl:direct-assoc 2 _mcpl:d)) _mcpl:handle (cdr (_mcpl:direct-assoc 5 _mcpl:d)))
    (cond
      ((_mcpl:protected-p _mcpl:name) (_mcpl:err "protected_layer" "cannot delete protected layer"))
      ((_mcpl:xref-p _mcpl:e) (_mcpl:err "xref_dependent_layer" "cannot delete xref-dependent layer"))
      ((_mcpl:ci= _mcpl:name (getvar "CLAYER")) (_mcpl:err "cannot_delete_current_layer" "cannot delete current layer"))
      ((ssget "X" (list (cons 8 _mcpl:name))) (_mcpl:err "layer_has_content" "layer has content"))
      (T
        (entdel _mcpl:e)
        (if (tblobjname "LAYER" _mcpl:name)
          (_mcpl:err "layer_has_unverified_references" "layer deletion was not confirmed after entdel")
          (if (_mcpl:save-ok)
            (if (tblobjname "LAYER" _mcpl:name)
              (_mcpl:err "mutation_state_unknown" "drawing_may_be_modified=true layer delete was not durable after save")
              (princ (strcat "\nRESULT:OK:{\"status\":\"deleted\",\"drawing\":" (_mcpl:json-string (_mcpl:drawing)) ",\"layer\":{\"handle\":" (_mcpl:json-string _mcpl:handle) ",\"name\":" (_mcpl:json-string _mcpl:name) "}}\n")))))))))
(princ)
"#,
    );
    Ok(s)
}

#[cfg(any(test, target_os = "windows"))]
fn parse_layer_result_output<T: serde::de::DeserializeOwned>(
    tool: &str,
    output: &str,
) -> Result<T, LayerError> {
    for line in output.lines() {
        let line = line.trim();
        if let Some(json) = line.strip_prefix("RESULT:OK:") {
            return serde_json::from_str(json).map_err(|err| {
                LayerError::new(
                    "mutation_state_unknown",
                    format!("{tool}: drawing_may_be_modified=true invalid success JSON: {err}"),
                )
            });
        }
        if let Some(rest) = line.strip_prefix("RESULT:ERROR:") {
            let (code, message) = rest.split_once(':').unwrap_or((rest, ""));
            return Err(LayerError::new(code, message.to_string()));
        }
        if let Some(message) = line.strip_prefix("RESULT:WARN:") {
            return Err(LayerError::new(
                "mutation_state_unknown",
                format!("{tool}: drawing_may_be_modified=true {message}"),
            ));
        }
    }

    Err(LayerError::new(
        "mutation_state_unknown",
        format!("{tool}: drawing_may_be_modified=true no RESULT sentinel found"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::tables::{LineType, TableEntry};

    fn reader_list_layers_file(
        path: &Path,
    ) -> Result<Vec<layers::LayerRecord>, crate::autocad_reader::LayerReadError> {
        crate::autocad_reader::Reader::open_path(path)
            .expect("test drawing must open through the reader boundary")
            .list_layers()
    }

    fn reader_get_layer_file(
        path: &Path,
        selector: &LayerSelector,
    ) -> Result<layers::LayerRecord, crate::autocad_reader::LayerReadError> {
        crate::autocad_reader::Reader::open_path(path)
            .expect("test drawing must open through the reader boundary")
            .get_layer(selector)
    }

    fn temp_dxf() -> tempfile::NamedTempFile {
        let mut doc = CadDocument::new();
        let mut dashed = LineType::new("Dashed");
        dashed.set_handle(doc.allocate_handle());
        doc.line_types.add(dashed).unwrap();
        let file = tempfile::Builder::new().suffix(".dxf").tempfile().unwrap();
        DxfWriter::new(&doc).write_to_file(file.path()).unwrap();
        file
    }

    fn append_raw_layer_pairs(path: &Path, layer_name: &str, appended: &[(&str, &str)]) {
        rewrite_raw_layer_entry(path, layer_name, |entry| {
            entry
                .pairs
                .extend(appended.iter().map(|(code, value)| RawDxfPair {
                    code: (*code).to_string(),
                    value: (*value).to_string(),
                }));
        });
    }

    fn append_raw_layer_pair(path: &Path, layer_name: &str, code: &str, value: &str) {
        append_raw_layer_pairs(path, layer_name, &[(code, value)]);
    }

    fn raw_layer_table(path: &Path) -> RawLayerTable {
        read_raw_layer_table(path).unwrap()
    }

    fn raw_layer_entry(path: &Path, layer_name: &str) -> RawLayerEntry {
        raw_layer_table(path)
            .entries
            .into_iter()
            .find(|entry| entry.name() == Some(layer_name))
            .expect("target raw layer entry")
    }

    fn raw_layer_names(path: &Path) -> Vec<String> {
        raw_layer_table(path)
            .entries
            .iter()
            .map(|entry| entry.name().expect("layer name").to_string())
            .collect()
    }

    fn rewrite_raw_layer_order(path: &Path, names: &[&str]) {
        let text = std::fs::read_to_string(path).unwrap();
        let mut pairs = parse_raw_dxf_pairs(&text).unwrap();
        let table = parse_raw_layer_table(&pairs).unwrap();
        assert_eq!(names.len(), table.entries.len());
        let mut reordered = table.header.clone();
        for name in names {
            let entry = table
                .entries
                .iter()
                .find(|entry| entry.name() == Some(*name))
                .expect("ordered layer exists");
            reordered.extend(entry.pairs.iter().cloned());
        }
        reordered.push(table.trailer.clone());
        pairs.splice(table.start..table.end, reordered);
        std::fs::write(path, render_raw_dxf_pairs(&pairs)).unwrap();
    }

    fn rewrite_raw_layer_entry(
        path: &Path,
        layer_name: &str,
        rewrite: impl FnOnce(&mut RawLayerEntry),
    ) {
        let text = std::fs::read_to_string(path).unwrap();
        let mut pairs = parse_raw_dxf_pairs(&text).unwrap();
        let table = parse_raw_layer_table(&pairs).unwrap();
        let entry_index = table
            .entries
            .iter()
            .position(|entry| entry.name() == Some(layer_name))
            .expect("target raw layer entry");
        let entry_start = table.start
            + table.header.len()
            + table.entries[..entry_index]
                .iter()
                .map(|entry| entry.pairs.len())
                .sum::<usize>();
        let entry_end = entry_start + table.entries[entry_index].pairs.len();
        let mut entry = table.entries[entry_index].clone();
        rewrite(&mut entry);
        pairs.splice(entry_start..entry_end, entry.pairs);
        std::fs::write(path, render_raw_dxf_pairs(&pairs)).unwrap();
    }

    fn rewrite_raw_layer_header(path: &Path, rewrite: impl FnOnce(&mut RawLayerEntry)) {
        let text = std::fs::read_to_string(path).unwrap();
        let mut pairs = parse_raw_dxf_pairs(&text).unwrap();
        let table = parse_raw_layer_table(&pairs).unwrap();
        let mut header = RawLayerEntry {
            pairs: table.header.clone(),
        };
        rewrite(&mut header);
        pairs.splice(table.start..table.start + table.header.len(), header.pairs);
        std::fs::write(path, render_raw_dxf_pairs(&pairs)).unwrap();
    }

    fn append_raw_object(path: &Path, object: &[RawDxfPair]) {
        let text = std::fs::read_to_string(path).unwrap();
        let mut pairs = parse_raw_dxf_pairs(&text).unwrap();
        let objects = raw_section_range(&pairs, "OBJECTS")
            .unwrap()
            .expect("OBJECTS section");
        pairs.splice(objects.end - 1..objects.end - 1, object.iter().cloned());
        std::fs::write(path, render_raw_dxf_pairs(&pairs)).unwrap();
    }

    fn application_group_pairs(pairs: &[RawDxfPair]) -> Vec<RawDxfPair> {
        let mut result = Vec::new();
        let mut in_group = false;
        for pair in pairs {
            if pair.code_number() == Some(102) && pair.value.trim().starts_with('{') {
                in_group = true;
            }
            if in_group {
                result.push(pair.clone());
            }
            if pair.code_number() == Some(102) && pair.value.trim() == "}" {
                in_group = false;
            }
        }
        result
    }

    fn fixture_copy(relative: &str) -> tempfile::NamedTempFile {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative);
        let file = tempfile::Builder::new().suffix(".dxf").tempfile().unwrap();
        std::fs::copy(fixture, file.path()).unwrap();
        file
    }

    #[test]
    fn create_update_rename_delete_persist_to_dxf() {
        let file = temp_dxf();
        let props = serde_json::json!({
            "color_index": 3,
            "line_type": "Dashed",
            "line_weight": {"kind": "value", "hundredths_mm": 25},
            "locked": true
        })
        .as_object()
        .unwrap()
        .clone();
        let created = create_layer_file(file.path(), "ANNO", &props).unwrap();
        assert_eq!(created.status, "ok");
        assert_eq!(created.layer.name, "ANNO");
        assert!(Path::new(&created.drawing).is_absolute());

        let read_back = reader_get_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle.clone()),
                expected_name: Some("ANNO".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(read_back.color_index, Some(3));
        assert_eq!(read_back.line_type, "Dashed");
        assert_eq!(
            read_back.line_weight,
            layers::LayerLineWeight::Value { hundredths_mm: 25 }
        );
        assert!(read_back.locked);

        let update = serde_json::json!({
            "line_type": "Continuous",
            "line_weight": {"kind": "by_block"},
            "off": true
        })
        .as_object()
        .unwrap()
        .clone();
        let updated = update_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle.clone()),
                expected_name: Some("ANNO".to_string()),
                ..Default::default()
            },
            &update,
        )
        .unwrap();
        assert!(updated.layer.off);

        let read_back = reader_get_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle.clone()),
                expected_name: Some("ANNO".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(read_back.color_index, Some(3));
        assert_eq!(read_back.line_type, "Continuous");
        assert_eq!(read_back.line_weight, layers::LayerLineWeight::ByBlock);
        assert!(read_back.off);

        let renamed = rename_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle.clone()),
                expected_name: Some("ANNO".to_string()),
                ..Default::default()
            },
            "NOTES",
        )
        .unwrap();
        assert_eq!(renamed.layer.name, "NOTES");

        let read_back = DxfReader::from_file(file.path()).unwrap().read().unwrap();
        assert!(read_back.layers.get("NOTES").is_some());

        let deleted = delete_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle),
                expected_name: Some("NOTES".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(deleted.status, "deleted");

        let read_back = DxfReader::from_file(file.path()).unwrap().read().unwrap();
        assert!(read_back.layers.get("NOTES").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_mutation_updates_canonical_target_and_preserves_mode() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.dxf");
        let alias = directory.path().join("alias.dxf");
        let source = temp_dxf();
        std::fs::copy(source.path(), &target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&target, &alias).unwrap();
        let before = std::fs::read(&target).unwrap();

        let result = update_layer_file(
            &alias,
            &LayerSelector {
                name: Some("0".to_string()),
                ..Default::default()
            },
            serde_json::json!({"locked": true}).as_object().unwrap(),
        )
        .unwrap();

        assert!(std::fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_ne!(std::fs::read(&target).unwrap(), before);
        assert!(
            reader_get_layer_file(
                &target,
                &LayerSelector {
                    name: Some("0".to_string()),
                    ..Default::default()
                }
            )
            .unwrap()
            .locked
        );
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o640
        );
        assert_eq!(
            PathBuf::from(result.drawing),
            std::fs::canonicalize(&target).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn hard_link_mutation_fails_closed_without_splitting_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.dxf");
        let alias = directory.path().join("alias.dxf");
        let source = temp_dxf();
        std::fs::copy(source.path(), &target).unwrap();
        std::fs::hard_link(&target, &alias).unwrap();
        let before = std::fs::read(&target).unwrap();

        let error = update_layer_file(
            &alias,
            &LayerSelector {
                name: Some("0".to_string()),
                ..Default::default()
            },
            serde_json::json!({"locked": true}).as_object().unwrap(),
        )
        .unwrap_err();

        assert_eq!(error.code(), "unsupported_layer_data");
        assert!(error.to_string().contains("multiple hard links"));
        assert_eq!(std::fs::read(&target).unwrap(), before);
        assert_eq!(std::fs::read(&alias).unwrap(), before);
    }

    #[test]
    fn noncooperating_source_edit_is_rejected_before_replacement() {
        let file = temp_dxf();
        let path = std::fs::canonicalize(file.path()).unwrap();
        let external_path = path.clone();
        let error = mutate_dxf_with_hook(
            &path,
            move || append_raw_layer_pair(&external_path, "0", "999", "external edit"),
            |doc, _metadata| {
                layers::update_layer_with_mutation_projection(
                    doc,
                    &LayerSelector {
                        name: Some("0".to_string()),
                        ..Default::default()
                    },
                    serde_json::json!({"locked": true}).as_object().unwrap(),
                    LayerMutationProjectionContext::DXF,
                )
            },
            |_| DxfLayerWritePolicy::default(),
        )
        .unwrap_err();

        assert_eq!(error.code(), "write_failed");
        assert!(error
            .to_string()
            .contains("source DXF bytes changed during layer mutation"));
        assert!(std::fs::read_to_string(file.path())
            .unwrap()
            .contains("external edit"));
    }

    #[test]
    fn concurrent_mutations_are_serialized_and_both_persist() {
        use std::sync::mpsc;
        use std::time::Duration;

        let file = temp_dxf();
        let path = std::fs::canonicalize(file.path()).unwrap();
        let (first_entered_tx, first_entered_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first_path = path.clone();
        let first = std::thread::spawn(move || {
            mutate_dxf_with_hook(
                &first_path,
                move || {
                    first_entered_tx.send(()).unwrap();
                    release_first_rx.recv().unwrap();
                },
                |doc, _metadata| {
                    layers::update_layer_with_mutation_projection(
                        doc,
                        &LayerSelector {
                            name: Some("0".to_string()),
                            ..Default::default()
                        },
                        serde_json::json!({"locked": true}).as_object().unwrap(),
                        LayerMutationProjectionContext::DXF,
                    )
                },
                |_| DxfLayerWritePolicy::default(),
            )
        });
        first_entered_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();

        let (second_started_tx, second_started_rx) = mpsc::channel();
        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let second_path = path.clone();
        let second = std::thread::spawn(move || {
            second_started_tx.send(()).unwrap();
            mutate_dxf_with_hook(
                &second_path,
                move || second_entered_tx.send(()).unwrap(),
                |doc, _metadata| {
                    layers::update_layer_with_mutation_projection(
                        doc,
                        &LayerSelector {
                            name: Some("0".to_string()),
                            ..Default::default()
                        },
                        serde_json::json!({"off": true}).as_object().unwrap(),
                        LayerMutationProjectionContext::DXF,
                    )
                },
                |_| DxfLayerWritePolicy::default(),
            )
        });
        second_started_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert!(second_entered_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err());

        release_first_tx.send(()).unwrap();
        first.join().unwrap().unwrap();
        second_entered_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        second.join().unwrap().unwrap();

        let layer = reader_get_layer_file(
            &path,
            &LayerSelector {
                name: Some("0".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(layer.locked);
        assert!(layer.off);
    }

    #[test]
    fn raw_layer_order_is_preserved_and_new_records_append() {
        let file = temp_dxf();
        create_layer_file(file.path(), "XREF_LAYER", &serde_json::Map::new()).unwrap();
        rewrite_raw_layer_order(file.path(), &["XREF_LAYER", "0"]);
        assert_eq!(raw_layer_names(file.path()), ["XREF_LAYER", "0"]);

        update_layer_file(
            file.path(),
            &LayerSelector {
                name: Some("0".to_string()),
                ..Default::default()
            },
            serde_json::json!({"locked": true}).as_object().unwrap(),
        )
        .unwrap();
        assert_eq!(raw_layer_names(file.path()), ["XREF_LAYER", "0"]);

        create_layer_file(file.path(), "NOTES", &serde_json::Map::new()).unwrap();
        assert_eq!(raw_layer_names(file.path()), ["XREF_LAYER", "0", "NOTES"]);
    }

    #[test]
    fn consecutive_raw_layer_creates_keep_handles_unique_and_owned_by_source_table() {
        let file = temp_dxf();
        let first = create_layer_file(file.path(), "ANNO", &serde_json::Map::new()).unwrap();
        let second = create_layer_file(file.path(), "NOTES", &serde_json::Map::new()).unwrap();
        assert_ne!(first.layer.handle, second.layer.handle);

        let table = raw_layer_table(file.path());
        let table_handle = RawLayerEntry {
            pairs: table.header.clone(),
        }
        .canonical_handle()
        .expect("source LAYER table handle");
        for name in ["ANNO", "NOTES"] {
            let entry = raw_layer_entry(file.path(), name);
            assert_eq!(
                entry.value(330).and_then(canonical_raw_handle).as_deref(),
                Some(table_handle.as_str())
            );
        }

        let text = std::fs::read_to_string(file.path()).unwrap();
        let pairs = parse_raw_dxf_pairs(&text).unwrap();
        raw_identity_handles(&pairs).expect("persisted object identities remain unique");
        let handseed = header_variable_value_index(&pairs, "$HANDSEED", 5)
            .unwrap()
            .expect("$HANDSEED");
        let handseed = raw_hex_value(&pairs[handseed].value, "$HANDSEED").unwrap();
        let highest_created = [&first.layer.handle, &second.layer.handle]
            .into_iter()
            .map(|handle| raw_hex_value(handle, "created handle").unwrap())
            .max()
            .unwrap();
        assert!(handseed > highest_created);
    }

    #[test]
    fn raw_layer_rename_updates_entity_and_current_layer_references() {
        let file = tempfile::Builder::new().suffix(".dxf").tempfile().unwrap();
        let mut document = CadDocument::new();
        let created = layers::create_layer(&mut document, "ANNO", &serde_json::Map::new()).unwrap();
        let mut line = acadrust::entities::Line::from_points(
            acadrust::types::Vector3::new(0.0, 0.0, 0.0),
            acadrust::types::Vector3::new(1.0, 1.0, 0.0),
        );
        line.common.layer = "ANNO".to_string();
        document
            .add_entity(acadrust::entities::EntityType::Line(line))
            .unwrap();
        document.header.current_layer_name = "ANNO".to_string();
        document.header.current_layer_handle =
            acadrust::types::Handle::new(u64::from_str_radix(&created.handle, 16).unwrap());
        DxfWriter::new(&document)
            .write_to_file(file.path())
            .unwrap();

        rename_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.handle),
                expected_name: Some("ANNO".to_string()),
                ..Default::default()
            },
            "NOTES",
        )
        .unwrap();

        let read_back = DxfReader::from_file(file.path()).unwrap().read().unwrap();
        assert_eq!(read_back.header.current_layer_name, "NOTES");
        assert!(read_back
            .entities()
            .any(|entity| entity.common().layer == "NOTES"));
    }

    #[test]
    fn raw_layer_rename_updates_direct_xdata_references_in_table_header_and_records() {
        let file = temp_dxf();
        let created = create_layer_file(file.path(), "ANNO", &serde_json::Map::new()).unwrap();
        rewrite_raw_layer_header(file.path(), |header| {
            header.pairs.extend([
                RawDxfPair {
                    code: "1001".to_string(),
                    value: "MCP_TEST".to_string(),
                },
                RawDxfPair {
                    code: "1003".to_string(),
                    value: "ANNO".to_string(),
                },
            ]);
        });
        append_raw_layer_pairs(file.path(), "0", &[("1001", "MCP_TEST"), ("1003", "ANNO")]);

        rename_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle),
                expected_name: Some("ANNO".to_string()),
                ..Default::default()
            },
            "NOTES",
        )
        .unwrap();

        let table = raw_layer_table(file.path());
        let header_names = raw_layer_reference_names_outside_range(&table.header, &(0..0));
        let layer_names = raw_layer_reference_names_outside_range(
            &raw_layer_entry(file.path(), "0").pairs,
            &(0..0),
        );
        assert!(header_names.contains("NOTES"));
        assert!(!header_names.contains("ANNO"));
        assert!(layer_names.contains("NOTES"));
        assert!(!layer_names.contains("ANNO"));
    }

    #[test]
    fn raw_layer_rename_fails_closed_on_opaque_application_reference() {
        let file = temp_dxf();
        let created = create_layer_file(file.path(), "ANNO", &serde_json::Map::new()).unwrap();
        append_raw_layer_pairs(
            file.path(),
            "0",
            &[("102", "{MCP_TEST"), ("8", "ANNO"), ("102", "}")],
        );
        let before = std::fs::read(file.path()).unwrap();

        let error = rename_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle),
                ..Default::default()
            },
            "NOTES",
        )
        .unwrap_err();

        assert_eq!(error.code(), "unsupported_layer_data");
        assert!(error.to_string().contains("opaque group-102"));
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
    }

    #[test]
    fn portable_xref_evidence_survives_unrelated_raw_layer_cycle() {
        use crate::ops::xref_io::{list_xref_instances_file, list_xrefs_file};
        use crate::ops::xrefs::ListXrefInstancesRequest;

        let file = fixture_copy("tests/fixtures/xrefs/portable-evidence-ascii.dxf");
        let source_fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("tests/fixtures/xrefs/portable-evidence-ascii.dxf");
        let source_bytes = std::fs::read(&source_fixture).unwrap();
        let source_text = std::str::from_utf8(&source_bytes).unwrap();
        let source_pairs = parse_raw_dxf_pairs(source_text).unwrap();
        let preserved_sections = ["BLOCKS", "ENTITIES", "OBJECTS"].map(|section| {
            let range = raw_section_range(&source_pairs, section)
                .unwrap()
                .expect("portable fixture section");
            (section, source_pairs[range].to_vec())
        });
        let before_xrefs = list_xrefs_file(file.path()).unwrap();
        let request = ListXrefInstancesRequest {
            drawing_path: file.path().display().to_string(),
            attachment_handle: None,
            attachment_name: None,
            owner_handle: None,
            owner_type: None,
            owner_name: None,
            layer_handle: None,
            layer_name: None,
            visibility: None,
        };
        let before_instances = list_xref_instances_file(file.path(), &request).unwrap();
        assert_eq!(before_xrefs.len(), 3);
        assert_eq!(before_instances.len(), 4);

        let assert_xref_evidence_unchanged = || {
            assert_eq!(list_xrefs_file(file.path()).unwrap(), before_xrefs);
            assert_eq!(
                list_xref_instances_file(file.path(), &request).unwrap(),
                before_instances
            );
            let text = std::fs::read_to_string(file.path()).unwrap();
            let pairs = parse_raw_dxf_pairs(&text).unwrap();
            for (section, expected) in &preserved_sections {
                let range = raw_section_range(&pairs, section)
                    .unwrap()
                    .expect("preserved portable fixture section");
                assert_eq!(&pairs[range], expected);
            }
        };

        let created = create_layer_file(file.path(), "ANNO", &serde_json::Map::new()).unwrap();
        let table = raw_layer_table(file.path());
        let table_handle = RawLayerEntry {
            pairs: table.header.clone(),
        }
        .canonical_handle()
        .unwrap();
        assert_eq!(
            raw_layer_entry(file.path(), "ANNO")
                .value(330)
                .and_then(canonical_raw_handle)
                .as_deref(),
            Some(table_handle.as_str())
        );
        assert_xref_evidence_unchanged();

        update_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle.clone()),
                ..Default::default()
            },
            serde_json::json!({"locked": true, "off": true})
                .as_object()
                .unwrap(),
        )
        .unwrap();
        assert_xref_evidence_unchanged();

        rename_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle.clone()),
                expected_name: Some("ANNO".to_string()),
                ..Default::default()
            },
            "NOTES",
        )
        .unwrap();
        assert_xref_evidence_unchanged();

        delete_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle),
                expected_name: Some("NOTES".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_xref_evidence_unchanged();
        assert_eq!(std::fs::read(source_fixture).unwrap(), source_bytes);
    }

    #[test]
    fn dxf_off_overlay_reads_negative_group_62() {
        let file = temp_dxf();
        let mut doc = DxfReader::from_file(file.path()).unwrap().read().unwrap();
        let mut layer = acadrust::tables::Layer::new("ANNO");
        layer.set_handle(doc.allocate_handle());
        layer.color = acadrust::types::Color::from_index(3);
        layer.flags.off = true;
        doc.layers.add(layer).unwrap();
        DxfWriter::new(&doc).write_to_file(file.path()).unwrap();

        let layer = reader_get_layer_file(
            file.path(),
            &LayerSelector {
                name: Some("ANNO".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(layer.color_index, Some(3));
        assert!(layer.off);
    }

    #[test]
    fn dxf_mutation_preserves_non_indexed_color_until_explicitly_replaced() {
        let file = temp_dxf();
        append_raw_layer_pairs(
            file.path(),
            "0",
            &[
                ("430", "Example color book$Example color"),
                ("420", "16711680"),
            ],
        );

        let before = reader_get_layer_file(
            file.path(),
            &LayerSelector {
                name: Some("0".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(before.color_index, None);

        let updated = update_layer_file(
            file.path(),
            &LayerSelector {
                name: Some("0".to_string()),
                ..Default::default()
            },
            serde_json::json!({"off": true}).as_object().unwrap(),
        )
        .unwrap();
        assert_eq!(updated.layer.color_index, None);
        assert!(updated.layer.off);
        let preserved = raw_layer_entry(file.path(), "0");
        assert_eq!(preserved.value(420).map(str::trim), Some("16711680"));
        assert_eq!(
            preserved.value(430),
            Some("Example color book$Example color")
        );
        assert!(pair_integer(&preserved, 62, 7).unwrap() < 0);

        let updated = update_layer_file(
            file.path(),
            &LayerSelector {
                name: Some("0".to_string()),
                ..Default::default()
            },
            serde_json::json!({"color_index": 5}).as_object().unwrap(),
        )
        .unwrap();
        assert_eq!(updated.layer.color_index, Some(5));
        let replaced = raw_layer_entry(file.path(), "0");
        assert!(replaced.value(420).is_none());
        assert!(replaced.value(430).is_none());
        assert_eq!(pair_integer(&replaced, 62, 7).unwrap(), -5);
    }

    #[test]
    fn dxf_color_book_without_true_color_is_not_reported_as_aci() {
        let file = temp_dxf();
        append_raw_layer_pair(file.path(), "0", "430", "Example color book$Example color");

        let listed = reader_list_layers_file(file.path()).unwrap();
        assert_eq!(listed[0].color_index, None);
        let fetched = reader_get_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(listed[0].handle.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(fetched.color_index, None);
    }

    #[test]
    fn dxf_repeated_direct_singleton_field_fails_closed_without_replacement() {
        let file = temp_dxf();
        append_raw_layer_pair(file.path(), "0", "62", "5");
        let before = std::fs::read(file.path()).unwrap();

        let err = update_layer_file(
            file.path(),
            &LayerSelector {
                name: Some("0".to_string()),
                ..Default::default()
            },
            serde_json::json!({"locked": true}).as_object().unwrap(),
        )
        .unwrap_err();

        assert_eq!(err.code(), "unsupported_layer_data");
        assert!(err
            .to_string()
            .contains("ambiguous repeated direct group code 62"));
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
    }

    #[test]
    fn dxf_invalid_plot_boolean_fails_closed_without_normalization() {
        let file = temp_dxf();
        rewrite_raw_layer_entry(file.path(), "0", |entry| {
            let plot = entry
                .direct_pair_indices()
                .into_iter()
                .find(|index| entry.pairs[*index].code_number() == Some(290))
                .expect("generated layer plot flag");
            entry.pairs[plot].value = "2".to_string();
        });
        let before = std::fs::read(file.path()).unwrap();

        let err = update_layer_file(
            file.path(),
            &LayerSelector {
                name: Some("0".to_string()),
                ..Default::default()
            },
            serde_json::json!({"locked": true}).as_object().unwrap(),
        )
        .unwrap_err();

        assert_eq!(err.code(), "unsupported_layer_data");
        assert!(err
            .to_string()
            .contains("group code 290 value 2 is not the required boolean"));
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
    }

    #[test]
    fn dxf_out_of_domain_color_fails_closed_before_dependency_decode() {
        let file = temp_dxf();
        rewrite_raw_layer_entry(file.path(), "0", |entry| {
            let color = entry
                .direct_pair_indices()
                .into_iter()
                .find(|index| entry.pairs[*index].code_number() == Some(62))
                .expect("generated layer color");
            entry.pairs[color].value = "300".to_string();
        });
        let before = std::fs::read(file.path()).unwrap();

        let err = update_layer_file(
            file.path(),
            &LayerSelector {
                name: Some("0".to_string()),
                ..Default::default()
            },
            serde_json::json!({"locked": true}).as_object().unwrap(),
        )
        .unwrap_err();

        assert_eq!(err.code(), "unsupported_layer_data");
        assert!(err
            .to_string()
            .contains("group code 62 value 300 is outside the round-trip-safe -255..=255 domain"));
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
    }

    #[test]
    fn dxf_stale_layer_table_count_fails_closed_without_normalization() {
        let file = temp_dxf();
        rewrite_raw_layer_header(file.path(), |header| {
            let count = header
                .direct_pair_indices()
                .into_iter()
                .find(|index| header.pairs[*index].code_number() == Some(70))
                .expect("generated LAYER table count");
            header.pairs[count].value = "99".to_string();
        });
        let before = std::fs::read(file.path()).unwrap();

        let err = create_layer_file(file.path(), "ANNO", &serde_json::Map::new()).unwrap_err();
        assert_eq!(err.code(), "unsupported_layer_data");
        assert!(err
            .to_string()
            .contains("declared group code 70 count 99 does not match"));
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
    }

    #[test]
    fn dxf_layer_without_direct_name_fails_closed_in_read_path() {
        let file = temp_dxf();
        rewrite_raw_layer_entry(file.path(), "0", |entry| {
            let name = entry
                .direct_pair_indices()
                .into_iter()
                .find(|index| entry.pairs[*index].code_number() == Some(2))
                .expect("generated layer name");
            entry.pairs.remove(name);
        });

        let err = reader_list_layers_file(file.path()).unwrap_err();
        assert_eq!(err.code(), "unsupported_layer_data");
        assert_eq!(
            err.to_string(),
            "code=unsupported_layer_data DXF layer `<unknown>` cannot be interpreted faithfully: \
             expected exactly one direct group code 2, found 0"
        );
    }

    #[test]
    fn dxf_without_raw_layer_table_fails_closed_without_replacing_source() {
        let file = temp_dxf();
        let text = std::fs::read_to_string(file.path()).unwrap();
        let mut pairs = parse_raw_dxf_pairs(&text).unwrap();
        let table = parse_raw_layer_table(&pairs).unwrap();
        pairs.splice(table.start..table.end, []);
        std::fs::write(file.path(), render_raw_dxf_pairs(&pairs)).unwrap();
        let before = std::fs::read(file.path()).unwrap();

        let err = create_layer_file(file.path(), "ANNO", &serde_json::Map::new()).unwrap_err();
        assert_eq!(err.code(), "unsupported_layer_data");
        assert!(err.to_string().contains("raw LAYER table is absent"));
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
    }

    #[test]
    fn dxf_unrepresented_pairs_and_flag_bits_survive_supported_update_in_order() {
        let file = temp_dxf();
        let created = create_layer_file(file.path(), "ANNO", &serde_json::Map::new()).unwrap();
        let opaque = vec![
            RawDxfPair {
                code: "91".to_string(),
                value: "123456".to_string(),
            },
            RawDxfPair {
                code: "102".to_string(),
                value: "{VENDOR_LAYER_DATA".to_string(),
            },
            RawDxfPair {
                code: "70".to_string(),
                value: "123".to_string(),
            },
            RawDxfPair {
                code: "420".to_string(),
                value: "1122867".to_string(),
            },
            RawDxfPair {
                code: "102".to_string(),
                value: "}".to_string(),
            },
            RawDxfPair {
                code: "1001".to_string(),
                value: "VENDOR_APP".to_string(),
            },
            RawDxfPair {
                code: "1000".to_string(),
                value: "  padded layer note  ".to_string(),
            },
            RawDxfPair {
                code: "1070".to_string(),
                value: "42".to_string(),
            },
        ];
        rewrite_raw_layer_entry(file.path(), "ANNO", |entry| {
            let flags = entry
                .direct_pair_indices()
                .into_iter()
                .find(|index| entry.pairs[*index].code_number() == Some(70))
                .unwrap();
            entry.pairs[flags].value = "2".to_string();
            entry.pairs.extend(opaque.iter().cloned());
        });

        let before = reader_get_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(before.color_index, Some(7));

        update_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle),
                ..Default::default()
            },
            serde_json::json!({"locked": true}).as_object().unwrap(),
        )
        .unwrap();

        let preserved = raw_layer_entry(file.path(), "ANNO");
        assert_eq!(pair_integer(&preserved, 70, 0).unwrap(), 2 | 4);
        let opaque_start = preserved
            .pairs
            .iter()
            .position(|pair| pair.code_number() == Some(91))
            .unwrap();
        assert_eq!(&preserved.pairs[opaque_start..], opaque.as_slice());
        assert_eq!(
            reader_get_layer_file(
                file.path(),
                &LayerSelector {
                    name: Some("ANNO".to_string()),
                    ..Default::default()
                }
            )
            .unwrap()
            .color_index,
            Some(7)
        );
    }

    #[test]
    fn tracked_xdictionary_fixture_supports_full_unrelated_layer_cycle_losslessly() {
        let file =
            fixture_copy("tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dxf");
        let original_table = raw_layer_table(file.path());
        let original_header_groups = application_group_pairs(&original_table.header);
        let original_layer_zero = raw_layer_entry(file.path(), "0");
        let original_text = std::fs::read_to_string(file.path()).unwrap();
        let original_pairs = parse_raw_dxf_pairs(&original_text).unwrap();
        let original_objects = raw_section_range(&original_pairs, "OBJECTS")
            .unwrap()
            .map(|range| original_pairs[range].to_vec())
            .expect("tracked fixture OBJECTS section");
        assert!(!original_header_groups.is_empty());
        assert!(!application_group_pairs(&original_layer_zero.pairs).is_empty());
        assert!(original_layer_zero
            .pairs
            .iter()
            .any(|pair| pair.code_number() == Some(360) && pair.value.trim() == "E6"));

        let created = create_layer_file(file.path(), "ANNO", &serde_json::Map::new()).unwrap();
        assert_eq!(
            application_group_pairs(&raw_layer_table(file.path()).header),
            original_header_groups
        );
        assert_eq!(raw_layer_entry(file.path(), "0"), original_layer_zero);

        update_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle.clone()),
                ..Default::default()
            },
            serde_json::json!({"locked": true, "off": true})
                .as_object()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw_layer_entry(file.path(), "0"), original_layer_zero);

        rename_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle.clone()),
                ..Default::default()
            },
            "NOTES",
        )
        .unwrap();
        assert_eq!(raw_layer_entry(file.path(), "0"), original_layer_zero);

        delete_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle),
                ..Default::default()
            },
        )
        .unwrap();

        let final_table = raw_layer_table(file.path());
        assert_eq!(final_table.header, original_table.header);
        assert_eq!(raw_layer_entry(file.path(), "0"), original_layer_zero);
        let final_text = std::fs::read_to_string(file.path()).unwrap();
        let final_pairs = parse_raw_dxf_pairs(&final_text).unwrap();
        let final_objects = raw_section_range(&final_pairs, "OBJECTS")
            .unwrap()
            .map(|range| final_pairs[range].to_vec())
            .expect("preserved OBJECTS section");
        assert_eq!(final_objects, original_objects);
        let dictionary_is_still_owned_by_layer_zero = final_pairs
            .iter()
            .enumerate()
            .filter(|(_, pair)| pair.is(0, "DICTIONARY"))
            .any(|(start, _)| {
                let end = (start + 1..final_pairs.len())
                    .find(|index| final_pairs[*index].code_number() == Some(0))
                    .unwrap_or(final_pairs.len());
                let dictionary = RawLayerEntry {
                    pairs: final_pairs[start..end].to_vec(),
                };
                dictionary.value(5).map(str::trim) == Some("E6")
                    && dictionary.value(330).map(str::trim) == Some("10")
            });
        assert!(dictionary_is_still_owned_by_layer_zero);
    }

    #[test]
    fn delete_with_unproven_layer_application_group_fails_without_replacing_source() {
        let file = temp_dxf();
        let created = create_layer_file(file.path(), "ANNO", &serde_json::Map::new()).unwrap();
        append_raw_layer_pairs(
            file.path(),
            "ANNO",
            &[("102", "{ACAD_XDICTIONARY"), ("360", "ABC"), ("102", "}")],
        );
        let before = std::fs::read(file.path()).unwrap();

        let err = delete_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "unsupported_layer_data");
        assert!(err.to_string().contains("cannot safely delete"));
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
    }

    #[test]
    fn delete_with_reference_from_another_layer_application_group_fails_closed() {
        let file = temp_dxf();
        let created = create_layer_file(file.path(), "ANNO", &serde_json::Map::new()).unwrap();
        append_raw_layer_pairs(
            file.path(),
            "0",
            &[
                ("102", "{ACAD_REACTORS"),
                ("330", &created.layer.handle),
                ("102", "}"),
            ],
        );
        let before = std::fs::read(file.path()).unwrap();

        let error = delete_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle),
                ..Default::default()
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "unsupported_layer_data");
        assert!(error.to_string().contains("source DXF references it"));
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
    }

    #[test]
    fn delete_with_direct_xdata_layer_reference_fails_closed() {
        let file = temp_dxf();
        let created = create_layer_file(file.path(), "ANNO", &serde_json::Map::new()).unwrap();
        append_raw_layer_pairs(file.path(), "0", &[("1001", "MCP_TEST"), ("1003", "ANNO")]);
        let before = std::fs::read(file.path()).unwrap();

        let error = delete_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle),
                ..Default::default()
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "unsupported_layer_data");
        assert!(error
            .to_string()
            .contains("referenced by another LAYER record"));
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
    }

    #[test]
    fn delete_with_external_opaque_layer_reference_fails_closed() {
        let file = temp_dxf();
        let created = create_layer_file(file.path(), "ANNO", &serde_json::Map::new()).unwrap();
        append_raw_object(
            file.path(),
            &[
                RawDxfPair {
                    code: "0".to_string(),
                    value: "XRECORD".to_string(),
                },
                RawDxfPair {
                    code: "5".to_string(),
                    value: "FFFE".to_string(),
                },
                RawDxfPair {
                    code: "100".to_string(),
                    value: "AcDbXrecord".to_string(),
                },
                RawDxfPair {
                    code: "280".to_string(),
                    value: "1".to_string(),
                },
                RawDxfPair {
                    code: "102".to_string(),
                    value: "{MCP_TEST".to_string(),
                },
                RawDxfPair {
                    code: "1003".to_string(),
                    value: "ANNO".to_string(),
                },
                RawDxfPair {
                    code: "102".to_string(),
                    value: "}".to_string(),
                },
            ],
        );
        let before = std::fs::read(file.path()).unwrap();

        let error = delete_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle),
                ..Default::default()
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "unsupported_layer_data");
        assert!(error.to_string().contains("opaque group-102"));
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
    }

    #[test]
    fn delete_with_objects_reference_to_plain_layer_fails_without_replacing_source() {
        let file = temp_dxf();
        let created = create_layer_file(file.path(), "ANNO", &serde_json::Map::new()).unwrap();
        append_raw_object(
            file.path(),
            &[
                RawDxfPair {
                    code: "0".to_string(),
                    value: "XRECORD".to_string(),
                },
                RawDxfPair {
                    code: "5".to_string(),
                    value: "FFFF".to_string(),
                },
                RawDxfPair {
                    code: "330".to_string(),
                    value: created.layer.handle.clone(),
                },
                RawDxfPair {
                    code: "100".to_string(),
                    value: "AcDbXrecord".to_string(),
                },
                RawDxfPair {
                    code: "280".to_string(),
                    value: "1".to_string(),
                },
            ],
        );
        let before = std::fs::read(file.path()).unwrap();

        let err = delete_layer_file(
            file.path(),
            &LayerSelector {
                handle: Some(created.layer.handle),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "unsupported_layer_data");
        assert!(err.to_string().contains("source DXF references it"));
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn dwg_mutation_reports_unsupported_platform_on_non_windows() {
        let temp = tempfile::Builder::new().suffix(".dwg").tempfile().unwrap();
        let path = temp.path();
        let err = create_layer_file(path, "ANNO", &serde_json::Map::new()).unwrap_err();
        assert_eq!(err.code(), "unsupported_platform");
        let text = err.to_string();
        assert!(text.contains("code=unsupported_platform"));
        assert!(text.contains("create_layer"));
        assert!(text.contains("DWG"));
        assert!(text.contains("Windows"));
        assert!(text.contains("accoreconsole"));
    }

    #[test]
    fn layer_dwg_script_contains_safety_contracts() {
        let selector = LayerSelector {
            handle: Some("10".to_string()),
            expected_name: Some("ANNO".to_string()),
            ..Default::default()
        };
        let lsp = generate_rename_layer_lsp(&selector, "NOTES").unwrap();
        assert!(lsp.contains("RESULT:ERROR:"), "{lsp}");
        assert!(lsp.contains("\"protected_layer\""), "{lsp}");
        assert!(lsp.contains("\"xref_dependent_layer\""), "{lsp}");
        assert!(lsp.contains("\"expected_name_mismatch\""), "{lsp}");
        assert!(lsp.contains("_.QSAVE"), "{lsp}");
    }

    #[test]
    fn layer_dwg_scripts_escape_json_strings_and_verify_delete() {
        let selector = LayerSelector {
            handle: Some("10".to_string()),
            expected_name: Some("ANNO".to_string()),
            ..Default::default()
        };
        let rename = generate_rename_layer_lsp(&selector, "NOTES").unwrap();
        assert!(rename.contains("_mcpl:json-string drawing"), "{rename}");
        assert!(rename.contains("_mcpl:json-string n"), "{rename}");

        let delete = generate_delete_layer_lsp(&selector).unwrap();
        assert!(
            delete.contains("layer deletion was not confirmed after entdel"),
            "{delete}"
        );
        assert!(
            delete.contains("layer delete was not durable after save"),
            "{delete}"
        );
        assert!(
            delete.contains("_mcpl:json-string (_mcpl:drawing)"),
            "{delete}"
        );
    }

    #[test]
    fn layer_dwg_generators_support_line_type_and_line_weight() {
        let selector = LayerSelector {
            handle: Some("10".to_string()),
            expected_name: Some("ANNO".to_string()),
            ..Default::default()
        };
        let properties = serde_json::json!({
            "line_type": "Dashed",
            "line_weight": {"kind": "value", "hundredths_mm": 25}
        })
        .as_object()
        .unwrap()
        .clone();

        let create = generate_create_layer_lsp("ANNO", &properties).unwrap();
        assert!(create.contains("_mcpl:line-type \"Dashed\""), "{create}");
        assert!(create.contains("_mcpl:line-weight 25"), "{create}");
        assert!(create.contains("(cons 6 _mcpl:line-type)"), "{create}");
        assert!(create.contains("(cons 370 _mcpl:line-weight)"), "{create}");

        let update = generate_update_layer_lsp(&selector, &properties).unwrap();
        assert!(update.contains("_mcpl:line-type \"Dashed\""), "{update}");
        assert!(update.contains("_mcpl:line-weight 25"), "{update}");
        assert!(
            update.contains("_mcpl:set-pair _mcpl:d 6 _mcpl:line-type"),
            "{update}"
        );
    }

    #[test]
    fn layer_dwg_update_replaces_non_indexed_color_and_projection_respects_it() {
        let selector = LayerSelector {
            handle: Some("10".to_string()),
            expected_name: Some("ANNO".to_string()),
            ..Default::default()
        };
        let properties = serde_json::json!({"color_index": 5})
            .as_object()
            .unwrap()
            .clone();

        let update = generate_update_layer_lsp(&selector, &properties).unwrap();
        assert!(
            update.contains("(or (_mcpl:direct-assoc 420 d) (_mcpl:direct-assoc 430 d))"),
            "{update}"
        );
        assert!(update.contains("(and (not non-indexed-color)"), "{update}");
        assert!(
            update
                .contains("(_mcpl:remove-direct-code (_mcpl:remove-direct-code _mcpl:d 420) 430)"),
            "{update}"
        );
        assert!(update.contains("(_mcpl:app-open-p pair)"), "{update}");
        assert!(update.contains("(setq depth (1+ depth))"), "{update}");
        assert!(!update.contains("(or (assoc 420 d)"), "{update}");
    }

    #[test]
    fn layer_dwg_generators_reject_invalid_selector_handles() {
        let selector = LayerSelector {
            handle: Some("0".to_string()),
            ..Default::default()
        };
        let err = generate_rename_layer_lsp(&selector, "NOTES").unwrap_err();
        assert_eq!(err.code(), "invalid_layer_handle");

        let selector = LayerSelector {
            name: Some("ANNO".to_string()),
            expected_handle: Some("not-a-handle".to_string()),
            ..Default::default()
        };
        let err = generate_delete_layer_lsp(&selector).unwrap_err();
        assert_eq!(err.code(), "invalid_layer_handle");
    }

    #[test]
    fn layer_dwg_generators_reject_invalid_layer_properties() {
        let selector = LayerSelector {
            name: Some("ANNO".to_string()),
            ..Default::default()
        };
        let err = generate_update_layer_lsp(
            &selector,
            serde_json::json!({"line_weight": {"kind": "raw", "raw_value": 42}})
                .as_object()
                .unwrap(),
        )
        .unwrap_err();
        assert_eq!(err.code(), "invalid_line_weight");

        let err = generate_update_layer_lsp(
            &selector,
            serde_json::json!({"true_color": 16711680})
                .as_object()
                .unwrap(),
        )
        .unwrap_err();
        assert_eq!(err.code(), "unsupported_layer_property");
    }

    #[test]
    fn parse_layer_result_output_requires_result_sentinel() {
        let output = r#"loading
RESULT:OK:{"status":"ok","drawing":"C:/tmp/a.dwg","layer":{"handle":"10","name":"ANNO","color_index":7,"line_type":"Continuous","line_weight":{"kind":"default"},"frozen":false,"locked":false,"off":false,"is_plottable":true,"xref_dependent":false,"xref_block_record_handle":null,"xref_name":null,"xref_path":null,"xref_is_overlay":null,"material_handle":null,"plotstyle_handle":null,"is_current":false}}
"#;
        let parsed: LayerMutationResult =
            parse_layer_result_output("create_layer", output).unwrap();
        assert_eq!(parsed.layer.name, "ANNO");

        let err = parse_layer_result_output::<LayerMutationResult>("create_layer", "no sentinel")
            .unwrap_err();
        assert_eq!(err.code(), "mutation_state_unknown");
        assert!(err.to_string().contains("drawing_may_be_modified=true"));
    }
}
