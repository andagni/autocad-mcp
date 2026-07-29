use anyhow::{anyhow, bail, Context, Result};
use distribution_approval::{
    parse_and_validate_windows_preview_build_attestation, parse_strict_json,
    serialize_windows_preview_build_attestation, sha256_hex, Artifact, DistributionMode,
    GitObjectFormat, SourceIdentity, WindowsPreviewBuildAttestation,
    WindowsPreviewBuildSourceIdentity, WindowsPreviewBuildSourceIdentityInput,
    WindowsPreviewBuildSubject, WindowsPreviewBuildSubjectId, WindowsPreviewNativeBuild,
    WindowsPreviewNativeBuildInput, WindowsPreviewUnsignedPreflight, WINDOWS_X86_64_TARGET,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

pub(crate) const SOURCE_MANIFEST_ARCHIVE_PATH: &str = "source-bundle-manifest.json";
pub(crate) const PREVIEW_WORKFLOW_REPOSITORY_PATH: &str =
    ".github/workflows/windows-preview-review-candidate.yml";
pub(crate) const PREVIEW_WORKFLOW_ARCHIVE_PATH: &str =
    "workspace/.github/workflows/windows-preview-review-candidate.yml";

const MCP_SERVER_ARCHIVE_PATH: &str = "plugin/bin/autocad-mcp.exe";
const AUTOLISP_LSP_ARCHIVE_PATH: &str = "plugin/bin/autolisp-lsp.exe";
const SOURCE_MANIFEST_SCHEMA_VERSION: u32 = 3;
const SOURCE_MANIFEST_ARTIFACT_KIND: &str = "autocad-mcp-windows-x86_64-build-source";
const PREFLIGHT_EVIDENCE_CLASS: &str = "development_windows_build_preflight";
const PREFLIGHT_AUTHORITY: &str = "development_only_not_certification_evidence";
const CERTIFIED_ARG_POLICY_ID: &str = "autocad-mcp-public-development-v1";
const CRT_LINKAGE: &str = "static";
const PE_IMPORT_POLICY_ID: &str = "pe-no-vc-runtime-imports-v1";
const RELEASE_PROFILE: &str = "release";
const MAX_JSON_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_WORKFLOW_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_CAPTURED_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_WINDOWS_RELATIVE_PATH_BYTES: usize = 240;
const MAX_WINDOWS_COMPONENT_BYTES: usize = 200;
const AUTHORIZED_GITHUB_REPOSITORY: &str = "andagni/autocad-mcp";
const AUTHORIZED_GITHUB_SERVER_URL: &str = "https://github.com";
const AUTHORIZED_GITHUB_REF: &str = "refs/heads/main";
const AUTHORIZED_GITHUB_EVENT_NAME: &str = "workflow_dispatch";
const AUTHORIZED_GITHUB_ACTOR: &str = "andagni";
const AUTHORIZED_GITHUB_TRIGGERING_ACTOR: &str = "andagni";
const UNAUTHORIZED_GITHUB_CONTEXT_ERROR: &str =
    "Preview build attestation GitHub context is not authorized";

#[derive(Clone, Debug)]
pub struct CreatePreviewBuildAttestationOptions {
    pub source_archive_path: PathBuf,
    pub mcpb_path: PathBuf,
    pub unsigned_preflight_path: PathBuf,
    pub workflow_path: PathBuf,
    pub run_id: u64,
    pub run_attempt: u64,
    pub github_repository: String,
    pub github_server_url: String,
    pub github_ref: String,
    pub github_event_name: String,
    pub github_actor: String,
    pub github_triggering_actor: String,
    pub output_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewBuildAttestationCreationReport {
    pub output_path: PathBuf,
    pub output_sha256: String,
    pub source_archive_sha256: String,
    pub mcp_server_sha256: String,
    pub autolisp_lsp_sha256: String,
}

pub(crate) struct PreviewBuildAttestationSemanticInput<'a> {
    pub approval_source_identity: &'a SourceIdentity,
    pub approved_source_archive: &'a Artifact,
    pub approved_mcp_server: &'a Artifact,
    pub approved_autolisp_lsp: &'a Artifact,
    pub attestation_bytes: &'a [u8],
    pub source_manifest_bytes: &'a [u8],
    pub workflow_bytes: &'a [u8],
    pub contained_mcp_server_bytes: &'a [u8],
    pub contained_autolisp_lsp_bytes: &'a [u8],
}

#[derive(Debug, Deserialize)]
struct SelectedSourceManifest {
    schema_version: u32,
    artifact_kind: String,
    git_object_format: GitObjectFormat,
    source_commit: String,
    source_tree_oid: String,
    cargo_lock_sha256: String,
    dependency_input_closure_sha256: String,
    rust_toolchain_sha256: String,
    build_recipe_sha256: String,
    target: String,
    profile: String,
    package_mode: DistributionMode,
    cargo_incremental: bool,
}

#[derive(Debug, Deserialize)]
struct SelectedUnsignedPreflight {
    evidence_class: String,
    authority: String,
    source_commit: String,
    cargo_lock_sha256: String,
    target: String,
    compiler: String,
    profile: String,
    cargo_incremental: bool,
    certified_arg_sha256: String,
    certified_arg_policy_id: String,
    certified_arg_policy_sha256: String,
    lsp_binary_sha256: String,
    crt_linkage: String,
    pe_import_policy_id: String,
    preview_binary_sha256: String,
    preview_build_id: String,
}

#[derive(Debug)]
struct ArchiveSelection {
    sha256: String,
    size_bytes: u64,
    captured: BTreeMap<String, Vec<u8>>,
}

/// Create the final, post-signing Preview build attestation from exact review
/// inputs. The output path is create-new and the written bytes are reparsed
/// through the closed distribution contract before success is returned.
pub fn create_preview_build_attestation(
    options: &CreatePreviewBuildAttestationOptions,
) -> Result<PreviewBuildAttestationCreationReport> {
    require_authorized_github_context(options)?;
    require_fresh_output(&options.output_path)?;

    let source = inspect_archive(
        &options.source_archive_path,
        "Preview build-source ZIP",
        &BTreeSet::from([
            SOURCE_MANIFEST_ARCHIVE_PATH.to_owned(),
            PREVIEW_WORKFLOW_ARCHIVE_PATH.to_owned(),
        ]),
    )?;
    let source_manifest_bytes = selected_archive_bytes(
        &source,
        SOURCE_MANIFEST_ARCHIVE_PATH,
        "source-bundle manifest",
    )?;
    let source_manifest = parse_source_manifest(source_manifest_bytes)?;

    let workflow_bytes = read_regular_file_bounded(
        &options.workflow_path,
        MAX_WORKFLOW_BYTES,
        "Preview workflow",
    )?;
    let archived_workflow = selected_archive_bytes(
        &source,
        PREVIEW_WORKFLOW_ARCHIVE_PATH,
        "archived Preview workflow",
    )?;
    if workflow_bytes != archived_workflow {
        bail!(
            "Preview workflow {} differs byte-for-byte from {} in the exact build-source ZIP",
            options.workflow_path.display(),
            PREVIEW_WORKFLOW_ARCHIVE_PATH
        );
    }

    let unsigned_preflight_bytes = read_regular_file_bounded(
        &options.unsigned_preflight_path,
        MAX_JSON_INPUT_BYTES,
        "unsigned Windows build preflight",
    )?;
    let unsigned_preflight = parse_unsigned_preflight(&unsigned_preflight_bytes)?;
    validate_preflight_source_join(&unsigned_preflight, &source_manifest)?;

    let mcpb = inspect_archive(
        &options.mcpb_path,
        "Preview MCPB",
        &BTreeSet::from([
            MCP_SERVER_ARCHIVE_PATH.to_owned(),
            AUTOLISP_LSP_ARCHIVE_PATH.to_owned(),
        ]),
    )?;
    let signed_server = selected_archive_bytes(
        &mcpb,
        MCP_SERVER_ARCHIVE_PATH,
        "signed MCP server executable",
    )?;
    let signed_lsp = selected_archive_bytes(
        &mcpb,
        AUTOLISP_LSP_ARCHIVE_PATH,
        "signed AutoLISP LSP executable",
    )?;

    let source_identity =
        WindowsPreviewBuildSourceIdentity::new(WindowsPreviewBuildSourceIdentityInput {
            git_object_format: source_manifest.git_object_format,
            git_commit_oid: source_manifest.source_commit,
            git_tree_oid: source_manifest.source_tree_oid,
            source_bundle_manifest_sha256: sha256_hex(source_manifest_bytes),
            cargo_lock_sha256: source_manifest.cargo_lock_sha256,
            dependency_input_closure_sha256: source_manifest.dependency_input_closure_sha256,
            rust_toolchain_sha256: source_manifest.rust_toolchain_sha256,
            build_recipe_sha256: source_manifest.build_recipe_sha256,
        })
        .map_err(|error| anyhow!("Preview source identity is invalid: {error}"))?;
    let native_build = WindowsPreviewNativeBuild::new(WindowsPreviewNativeBuildInput {
        workflow_sha256: sha256_hex(&workflow_bytes),
        run_id: options.run_id,
        run_attempt: options.run_attempt,
        compiler: unsigned_preflight.compiler,
        preview_build_id: unsigned_preflight.preview_build_id,
        certified_arg_sha256: unsigned_preflight.certified_arg_sha256,
        certified_arg_policy_sha256: unsigned_preflight.certified_arg_policy_sha256,
    })
    .map_err(|error| anyhow!("Preview native-build identity is invalid: {error}"))?;
    let unsigned = WindowsPreviewUnsignedPreflight::new(
        sha256_hex(&unsigned_preflight_bytes),
        unsigned_preflight.preview_binary_sha256,
        unsigned_preflight.lsp_binary_sha256,
    )
    .map_err(|error| anyhow!("Preview unsigned-preflight binding is invalid: {error}"))?;
    let source_subject =
        WindowsPreviewBuildSubject::source_archive(source.sha256.clone(), source.size_bytes)
            .map_err(|error| anyhow!("Preview source-archive subject is invalid: {error}"))?;
    let lsp_subject = WindowsPreviewBuildSubject::windows_lsp(
        sha256_hex(signed_lsp),
        signed_lsp.len() as u64,
        unsigned.lsp_binary_sha256().to_owned(),
    )
    .map_err(|error| anyhow!("Preview AutoLISP LSP subject is invalid: {error}"))?;
    let server_subject = WindowsPreviewBuildSubject::windows_server(
        sha256_hex(signed_server),
        signed_server.len() as u64,
        unsigned.preview_binary_sha256().to_owned(),
    )
    .map_err(|error| anyhow!("Preview MCP server subject is invalid: {error}"))?;
    let attestation = WindowsPreviewBuildAttestation::new(
        source_identity,
        native_build,
        unsigned,
        [source_subject, lsp_subject, server_subject],
    )
    .map_err(|error| anyhow!("Preview build attestation is invalid: {error}"))?;
    let output_bytes = serialize_windows_preview_build_attestation(&attestation)
        .map_err(|error| anyhow!("serialize Preview build attestation: {error}"))?;
    parse_and_validate_windows_preview_build_attestation(&output_bytes)
        .map_err(|error| anyhow!("generated Preview build attestation is invalid: {error}"))?;

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&options.output_path)
        .with_context(|| {
            format!(
                "create fresh Preview build attestation {}",
                options.output_path.display()
            )
        })?;
    output.write_all(&output_bytes).with_context(|| {
        format!(
            "write Preview build attestation {}",
            options.output_path.display()
        )
    })?;
    output.sync_all().with_context(|| {
        format!(
            "synchronize Preview build attestation {}",
            options.output_path.display()
        )
    })?;
    drop(output);

    let reparsed_bytes = read_regular_file_bounded(
        &options.output_path,
        MAX_JSON_INPUT_BYTES,
        "written Preview build attestation",
    )?;
    if reparsed_bytes != output_bytes {
        bail!("written Preview build attestation bytes differ from the generated contract");
    }
    parse_and_validate_windows_preview_build_attestation(&reparsed_bytes)
        .map_err(|error| anyhow!("reparse written Preview build attestation: {error}"))?;

    Ok(PreviewBuildAttestationCreationReport {
        output_path: options.output_path.clone(),
        output_sha256: sha256_hex(&reparsed_bytes),
        source_archive_sha256: source.sha256,
        mcp_server_sha256: sha256_hex(signed_server),
        autolisp_lsp_sha256: sha256_hex(signed_lsp),
    })
}

fn require_authorized_github_context(options: &CreatePreviewBuildAttestationOptions) -> Result<()> {
    if options.github_repository != AUTHORIZED_GITHUB_REPOSITORY
        || options.github_server_url != AUTHORIZED_GITHUB_SERVER_URL
        || options.github_ref != AUTHORIZED_GITHUB_REF
        || options.github_event_name != AUTHORIZED_GITHUB_EVENT_NAME
        || options.github_actor != AUTHORIZED_GITHUB_ACTOR
        || options.github_triggering_actor != AUTHORIZED_GITHUB_TRIGGERING_ACTOR
    {
        bail!(UNAUTHORIZED_GITHUB_CONTEXT_ERROR);
    }
    Ok(())
}

/// Verify every Preview-only semantic join that can be established from the
/// approval-bound distribution bytes. This proves the declared relationships;
/// it does not independently establish Authenticode trust or workflow origin.
pub(crate) fn verify_preview_build_attestation_semantics(
    input: &PreviewBuildAttestationSemanticInput<'_>,
) -> Result<()> {
    if input.approval_source_identity.package_mode() != DistributionMode::Preview {
        bail!("Preview build-attestation semantics require a Preview owner approval");
    }
    let attestation = parse_and_validate_windows_preview_build_attestation(input.attestation_bytes)
        .map_err(|error| anyhow!("Preview build attestation is invalid: {error}"))?;
    let manifest = parse_source_manifest(input.source_manifest_bytes)?;
    verify_source_identity(
        attestation.source_identity(),
        input.approval_source_identity,
        &manifest,
        input.source_manifest_bytes,
    )?;

    let workflow_sha256 = sha256_hex(input.workflow_bytes);
    if attestation.native_build().workflow_path() != PREVIEW_WORKFLOW_REPOSITORY_PATH
        || attestation.native_build().workflow_sha256() != workflow_sha256
    {
        bail!(
            "Preview build attestation workflow binding does not match exact source-archive workflow bytes"
        );
    }

    verify_source_subject(
        subject(&attestation, WindowsPreviewBuildSubjectId::SourceArchive)?,
        input.approved_source_archive,
    )?;
    verify_executable_subject(
        "windows-server",
        subject(&attestation, WindowsPreviewBuildSubjectId::WindowsServer)?,
        input.approved_mcp_server,
        input.contained_mcp_server_bytes,
        attestation.unsigned_preflight().preview_binary_sha256(),
    )?;
    verify_executable_subject(
        "windows-lsp",
        subject(&attestation, WindowsPreviewBuildSubjectId::WindowsLsp)?,
        input.approved_autolisp_lsp,
        input.contained_autolisp_lsp_bytes,
        attestation.unsigned_preflight().lsp_binary_sha256(),
    )?;
    Ok(())
}

fn verify_source_identity(
    attested: &WindowsPreviewBuildSourceIdentity,
    approved: &SourceIdentity,
    manifest: &SelectedSourceManifest,
    manifest_bytes: &[u8],
) -> Result<()> {
    let expected_manifest_sha256 = sha256_hex(manifest_bytes);
    let joined = attested.git_object_format() == approved.git_object_format()
        && attested.git_object_format() == manifest.git_object_format
        && attested.git_commit_oid() == approved.git_commit_oid()
        && attested.git_commit_oid() == manifest.source_commit
        && attested.git_tree_oid() == approved.git_tree_oid()
        && attested.git_tree_oid() == manifest.source_tree_oid
        && attested.source_bundle_manifest_sha256() == approved.source_bundle_manifest_sha256()
        && attested.source_bundle_manifest_sha256() == expected_manifest_sha256
        && attested.cargo_lock_sha256() == approved.cargo_lock_sha256()
        && attested.cargo_lock_sha256() == manifest.cargo_lock_sha256
        && attested.dependency_input_closure_sha256() == approved.dependency_input_closure_sha256()
        && attested.dependency_input_closure_sha256() == manifest.dependency_input_closure_sha256
        && attested.rust_toolchain_sha256() == approved.rust_toolchain_sha256()
        && attested.rust_toolchain_sha256() == manifest.rust_toolchain_sha256
        && attested.build_recipe_sha256() == approved.build_recipe_sha256()
        && attested.build_recipe_sha256() == manifest.build_recipe_sha256;
    if !joined {
        bail!(
            "Preview build attestation source identity does not exactly join the owner approval and source-bundle manifest"
        );
    }
    Ok(())
}

fn verify_source_subject(subject: &WindowsPreviewBuildSubject, approved: &Artifact) -> Result<()> {
    if subject.sha256() != approved.sha256()
        || subject.size_bytes() != approved.size_bytes()
        || subject.unsigned_sha256().is_some()
    {
        bail!(
            "Preview build attestation source-archive subject does not match the approval-bound source ZIP"
        );
    }
    Ok(())
}

fn verify_executable_subject(
    label: &str,
    subject: &WindowsPreviewBuildSubject,
    approved: &Artifact,
    contained_bytes: &[u8],
    expected_unsigned_sha256: &str,
) -> Result<()> {
    let contained_sha256 = sha256_hex(contained_bytes);
    if subject.sha256() != approved.sha256()
        || subject.size_bytes() != approved.size_bytes()
        || subject.sha256() != contained_sha256
        || subject.size_bytes() != contained_bytes.len() as u64
    {
        bail!(
            "Preview build attestation {label} subject does not match both the owner approval and exact MCPB-contained executable bytes"
        );
    }
    if subject.unsigned_sha256() != Some(expected_unsigned_sha256) {
        bail!(
            "Preview build attestation {label} unsigned digest does not match the selected unsigned preflight identity"
        );
    }
    if subject.sha256() == expected_unsigned_sha256 {
        bail!(
            "Preview build attestation {label} final signed digest equals its unsigned preflight digest"
        );
    }
    Ok(())
}

fn subject(
    attestation: &WindowsPreviewBuildAttestation,
    subject_id: WindowsPreviewBuildSubjectId,
) -> Result<&WindowsPreviewBuildSubject> {
    attestation
        .subjects()
        .iter()
        .find(|subject| subject.subject_id() == subject_id)
        .ok_or_else(|| {
            anyhow!(
                "Preview build attestation has no {} subject",
                subject_id.as_str()
            )
        })
}

fn parse_source_manifest(bytes: &[u8]) -> Result<SelectedSourceManifest> {
    let value = parse_strict_json(bytes)
        .map_err(|error| anyhow!("source-bundle manifest is not strict JSON: {error}"))?;
    let manifest: SelectedSourceManifest = serde_json::from_value(value)
        .map_err(|error| anyhow!("source-bundle manifest selected fields are invalid: {error}"))?;
    if manifest.schema_version != SOURCE_MANIFEST_SCHEMA_VERSION
        || manifest.artifact_kind != SOURCE_MANIFEST_ARTIFACT_KIND
        || manifest.target != WINDOWS_X86_64_TARGET
        || manifest.profile != RELEASE_PROFILE
        || manifest.package_mode != DistributionMode::Preview
        || manifest.cargo_incremental
    {
        bail!(
            "source-bundle manifest is not the closed non-incremental Windows x64 Preview release recipe"
        );
    }
    Ok(manifest)
}

fn parse_unsigned_preflight(bytes: &[u8]) -> Result<SelectedUnsignedPreflight> {
    let value = parse_strict_json(bytes)
        .map_err(|error| anyhow!("unsigned Windows build preflight is not strict JSON: {error}"))?;
    let preflight: SelectedUnsignedPreflight = serde_json::from_value(value).map_err(|error| {
        anyhow!("unsigned Windows build preflight selected fields are invalid: {error}")
    })?;
    if preflight.evidence_class != PREFLIGHT_EVIDENCE_CLASS
        || preflight.authority != PREFLIGHT_AUTHORITY
        || preflight.target != WINDOWS_X86_64_TARGET
        || preflight.profile != RELEASE_PROFILE
        || preflight.cargo_incremental
        || preflight.certified_arg_policy_id != CERTIFIED_ARG_POLICY_ID
        || preflight.crt_linkage != CRT_LINKAGE
        || preflight.pe_import_policy_id != PE_IMPORT_POLICY_ID
    {
        bail!(
            "unsigned Windows build preflight is not the closed non-incremental Windows x64 Preview identity"
        );
    }
    Ok(preflight)
}

fn validate_preflight_source_join(
    preflight: &SelectedUnsignedPreflight,
    manifest: &SelectedSourceManifest,
) -> Result<()> {
    if preflight.source_commit != manifest.source_commit
        || preflight.cargo_lock_sha256 != manifest.cargo_lock_sha256
    {
        bail!(
            "unsigned Windows build preflight source identity does not match the exact build-source manifest"
        );
    }
    Ok(())
}

fn inspect_archive(
    path: &Path,
    label: &str,
    capture_paths: &BTreeSet<String>,
) -> Result<ArchiveSelection> {
    let (mut file, metadata) = open_regular_file(path, label)?;
    let (sha256, size_bytes) = hash_open_file(&mut file, label)?;
    if size_bytes != metadata.len() {
        bail!("{label} size changed while hashing");
    }
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind {label} {}", path.display()))?;
    let mut archive =
        ZipArchive::new(file).with_context(|| format!("open {label} {}", path.display()))?;
    if archive.is_empty() || archive.len() > MAX_ARCHIVE_ENTRIES {
        bail!(
            "{label} entry count {} is outside the closed limit",
            archive.len()
        );
    }
    let mut casefolded = BTreeMap::new();
    let mut captured = BTreeMap::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("read {label} central entry {index}"))?;
        let name = std::str::from_utf8(entry.name_raw())
            .map_err(|_| anyhow!("{label} entry {index} has a non-UTF-8 path"))?
            .to_owned();
        validate_archive_path(&name)?;
        if entry.is_dir() {
            bail!("{label} contains forbidden directory entry {name}");
        }
        if entry.is_symlink() {
            bail!("{label} contains forbidden symlink entry {name}");
        }
        insert_archive_path(&mut casefolded, &name)?;
        if !capture_paths.contains(&name) {
            continue;
        }
        if !entry.is_file() {
            bail!("{label} required entry {name} is not a regular file");
        }
        if entry.size() == 0 || entry.size() > MAX_CAPTURED_ENTRY_BYTES {
            bail!("{label} required entry {name} size is outside the closed limit");
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(entry.size())
                .map_err(|_| anyhow!("{label} required entry {name} is too large"))?,
        );
        entry
            .read_to_end(&mut bytes)
            .with_context(|| format!("read {label} required entry {name}"))?;
        if bytes.len() as u64 != entry.size() {
            bail!("{label} required entry {name} expanded size is inconsistent");
        }
        captured.insert(name, bytes);
    }
    for required in capture_paths {
        if !captured.contains_key(required) {
            bail!("{label} does not contain required entry {required}");
        }
    }
    let mut file = archive.into_inner();
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind {label} after archive inspection"))?;
    let after = hash_open_file(&mut file, label)?;
    if after != (sha256.clone(), size_bytes) {
        bail!("{label} changed while its archive entries were being inspected");
    }
    Ok(ArchiveSelection {
        sha256,
        size_bytes,
        captured,
    })
}

fn validate_archive_path(path: &str) -> Result<()> {
    if path.is_empty()
        || !path.is_ascii()
        || path.len() > MAX_WINDOWS_RELATIVE_PATH_BYTES
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.ends_with('/')
        || path.contains('\\')
    {
        bail!("unsafe archive path {path:?}");
    }
    for component in path.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.len() > MAX_WINDOWS_COMPONENT_BYTES
            || component.ends_with(' ')
            || component.ends_with('.')
            || component.bytes().any(|byte| {
                byte < b' '
                    || byte == 0x7f
                    || matches!(byte, b'<' | b'>' | b':' | b'"' | b'\\' | b'|' | b'?' | b'*')
            })
        {
            bail!("unsafe archive path component {component:?} in {path:?}");
        }
        let stem = component
            .split('.')
            .next()
            .unwrap_or(component)
            .to_ascii_lowercase();
        let reserved = matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
            || stem.strip_prefix("com").is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
            || stem.strip_prefix("lpt").is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
        if reserved {
            bail!("reserved Windows device component {component:?} in archive path {path:?}");
        }
    }
    Ok(())
}

fn insert_archive_path(casefolded: &mut BTreeMap<String, String>, path: &str) -> Result<()> {
    let folded = path.to_ascii_lowercase();
    if let Some(existing) = casefolded.get(&folded) {
        bail!("duplicate or case-colliding archive paths {existing:?} and {path:?}");
    }
    for (index, byte) in folded.bytes().enumerate() {
        if byte == b'/' {
            let ancestor = &folded[..index];
            if let Some(existing) = casefolded.get(ancestor) {
                bail!("archive file {existing:?} conflicts with descendant {path:?}");
            }
        }
    }
    let descendant_prefix = format!("{folded}/");
    if let Some((candidate, existing)) = casefolded.range(descendant_prefix.clone()..).next() {
        if candidate.starts_with(&descendant_prefix) {
            bail!("archive file {path:?} conflicts with descendant {existing:?}");
        }
    }
    casefolded.insert(folded, path.to_owned());
    Ok(())
}

fn selected_archive_bytes<'a>(
    archive: &'a ArchiveSelection,
    path: &str,
    label: &str,
) -> Result<&'a [u8]> {
    archive
        .captured
        .get(path)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("{label} was not captured at required path {path}"))
}

fn require_fresh_output(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "Preview build attestation output already exists: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "inspect Preview build attestation output {}",
                path.display()
            )
        }),
    }
}

fn read_regular_file_bounded(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    let (mut file, metadata) = open_regular_file(path, label)?;
    if metadata.len() == 0 || metadata.len() > limit {
        bail!(
            "{label} {} has {} bytes, outside the closed 1..={limit} limit",
            path.display(),
            metadata.len()
        );
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| anyhow!("{label} is too large"))?,
    );
    file.read_to_end(&mut bytes)
        .with_context(|| format!("read {label} {}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        bail!("{label} size changed while reading");
    }
    Ok(bytes)
}

fn open_regular_file(path: &Path, label: &str) -> Result<(File, fs::Metadata)> {
    let named = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if !named.file_type().is_file() {
        bail!(
            "{label} must be a regular non-symlink file: {}",
            path.display()
        );
    }
    let file = File::open(path).with_context(|| format!("open {label} {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect opened {label} {}", path.display()))?;
    if !opened.is_file() || opened.len() != named.len() {
        bail!("{label} identity changed while opening");
    }
    Ok((file, opened))
}

fn hash_open_file(file: &mut File, label: &str) -> Result<(String, u64)> {
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("hash {label}"))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("{label} size overflow"))?;
        digest.update(&buffer[..read]);
    }
    Ok((format!("{:x}", digest.finalize()), size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use zip::write::SimpleFileOptions;
    use zip::CompressionMethod;

    const WORKFLOW: &[u8] = b"name: Exact Preview workflow\n";
    const SIGNED_SERVER: &[u8] = b"signed Preview MCP server\n";
    const SIGNED_LSP: &[u8] = b"signed AutoLISP LSP\n";

    struct CreationFixture {
        _temp: tempfile::TempDir,
        options: CreatePreviewBuildAttestationOptions,
    }

    impl CreationFixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let source_archive_path = temp.path().join("source.zip");
            let mcpb_path = temp.path().join("candidate.mcpb");
            let unsigned_preflight_path = temp.path().join("unsigned-preflight.json");
            let workflow_path = temp.path().join("windows-preview-review-candidate.yml");
            let output_path = temp.path().join("attestation.json");

            let manifest = json!({
                "schema_version": SOURCE_MANIFEST_SCHEMA_VERSION,
                "artifact_kind": SOURCE_MANIFEST_ARTIFACT_KIND,
                "git_object_format": "sha1",
                "source_commit": "1".repeat(40),
                "source_tree_oid": "2".repeat(40),
                "cargo_lock_sha256": "3".repeat(64),
                "dependency_input_closure_sha256": "4".repeat(64),
                "rust_toolchain_sha256": "5".repeat(64),
                "build_recipe_sha256": "6".repeat(64),
                "rust_toolchain": "1.97.0",
                "target": WINDOWS_X86_64_TARGET,
                "profile": RELEASE_PROFILE,
                "package_mode": "preview",
                "cargo_incremental": false,
                "roots": [],
                "packages": [],
                "workspace": {},
                "generated_files": [],
                "exclusions": [],
                "archive_policy": {}
            });
            let mut manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
            manifest_bytes.push(b'\n');
            write_zip(
                &source_archive_path,
                &[
                    (SOURCE_MANIFEST_ARCHIVE_PATH, manifest_bytes.as_slice()),
                    (PREVIEW_WORKFLOW_ARCHIVE_PATH, WORKFLOW),
                ],
            );
            write_zip(
                &mcpb_path,
                &[
                    (MCP_SERVER_ARCHIVE_PATH, SIGNED_SERVER),
                    (AUTOLISP_LSP_ARCHIVE_PATH, SIGNED_LSP),
                ],
            );
            fs::write(&workflow_path, WORKFLOW).unwrap();
            fs::write(
                &unsigned_preflight_path,
                preflight_bytes(&"1".repeat(40), &"3".repeat(64)),
            )
            .unwrap();

            Self {
                _temp: temp,
                options: CreatePreviewBuildAttestationOptions {
                    source_archive_path,
                    mcpb_path,
                    unsigned_preflight_path,
                    workflow_path,
                    run_id: 1234,
                    run_attempt: 2,
                    github_repository: AUTHORIZED_GITHUB_REPOSITORY.to_owned(),
                    github_server_url: AUTHORIZED_GITHUB_SERVER_URL.to_owned(),
                    github_ref: AUTHORIZED_GITHUB_REF.to_owned(),
                    github_event_name: AUTHORIZED_GITHUB_EVENT_NAME.to_owned(),
                    github_actor: AUTHORIZED_GITHUB_ACTOR.to_owned(),
                    github_triggering_actor: AUTHORIZED_GITHUB_TRIGGERING_ACTOR.to_owned(),
                    output_path,
                },
            }
        }
    }

    fn preflight_bytes(source_commit: &str, cargo_lock_sha256: &str) -> Vec<u8> {
        let value = json!({
            "evidence_class": PREFLIGHT_EVIDENCE_CLASS,
            "authority": PREFLIGHT_AUTHORITY,
            "source_commit": source_commit,
            "source_tree_sha256": "7".repeat(64),
            "cargo_lock_sha256": cargo_lock_sha256,
            "target": WINDOWS_X86_64_TARGET,
            "compiler": "rustc 1.97.0 (test); host: x86_64-pc-windows-msvc",
            "profile": RELEASE_PROFILE,
            "cargo_incremental": false,
            "release_build_command": "cargo release",
            "instrumented_build_command": "cargo instrumented",
            "preview_build_command": "cargo preview",
            "certified_arg_sha256": "8".repeat(64),
            "certified_arg_policy_id": CERTIFIED_ARG_POLICY_ID,
            "certified_arg_policy_sha256": "9".repeat(64),
            "release_binary_path": "target/release/autocad-mcp.exe",
            "release_binary_sha256": "a".repeat(64),
            "release_build_id": "b".repeat(64),
            "lsp_binary_path": "target/release/autolisp-lsp.exe",
            "lsp_binary_sha256": "c".repeat(64),
            "crt_linkage": CRT_LINKAGE,
            "pe_import_policy_id": PE_IMPORT_POLICY_ID,
            "pe_load_time_imports": [],
            "pe_delay_load_imports": [],
            "lsp_pe_load_time_imports": [],
            "lsp_pe_delay_load_imports": [],
            "instrumented_binary_path": "target/instrumented/autocad-mcp.exe",
            "instrumented_binary_sha256": "d".repeat(64),
            "instrumented_build_id": "e".repeat(64),
            "preview_binary_path": "target/preview/autocad-mcp.exe",
            "preview_binary_sha256": "f".repeat(64),
            "preview_build_id": "0".repeat(64)
        });
        let mut bytes = serde_json::to_vec_pretty(&value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o644);
        for (name, bytes) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
    }

    #[test]
    fn creator_binds_exact_source_workflow_preflight_and_signed_executables() {
        let fixture = CreationFixture::new();
        let report = create_preview_build_attestation(&fixture.options).unwrap();
        let bytes = fs::read(&fixture.options.output_path).unwrap();
        let parsed = parse_and_validate_windows_preview_build_attestation(&bytes).unwrap();

        assert_eq!(report.output_path, fixture.options.output_path);
        assert_eq!(report.output_sha256, sha256_hex(&bytes));
        assert_eq!(
            parsed.native_build().workflow_sha256(),
            sha256_hex(WORKFLOW)
        );
        assert_eq!(parsed.native_build().run_id(), 1234);
        assert_eq!(parsed.native_build().run_attempt(), 2);
        assert_eq!(
            parsed.unsigned_preflight().sha256(),
            sha256_hex(&fs::read(&fixture.options.unsigned_preflight_path).unwrap())
        );
        assert_eq!(
            parsed
                .subjects()
                .iter()
                .find(|subject| {
                    subject.subject_id() == WindowsPreviewBuildSubjectId::WindowsServer
                })
                .unwrap()
                .sha256(),
            sha256_hex(SIGNED_SERVER)
        );
        assert_eq!(
            parsed
                .subjects()
                .iter()
                .find(|subject| subject.subject_id() == WindowsPreviewBuildSubjectId::WindowsLsp)
                .unwrap()
                .sha256(),
            sha256_hex(SIGNED_LSP)
        );
    }

    #[test]
    fn creator_refuses_an_existing_output_before_reading_inputs() {
        let fixture = CreationFixture::new();
        fs::write(&fixture.options.output_path, b"owner bytes\n").unwrap();
        fs::write(
            &fixture.options.unsigned_preflight_path,
            b"not JSON and must not be reached",
        )
        .unwrap();

        let error = create_preview_build_attestation(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already exists"), "error: {error}");
        assert_eq!(
            fs::read(&fixture.options.output_path).unwrap(),
            b"owner bytes\n"
        );
    }

    #[test]
    fn creator_rejects_each_github_context_drift_before_creating_output() {
        for field in [
            "repository",
            "server_url",
            "ref",
            "event_name",
            "actor",
            "triggering_actor",
        ] {
            let mut fixture = CreationFixture::new();
            match field {
                "repository" => fixture.options.github_repository = "drifted".to_owned(),
                "server_url" => fixture.options.github_server_url = "drifted".to_owned(),
                "ref" => fixture.options.github_ref = "drifted".to_owned(),
                "event_name" => fixture.options.github_event_name = "drifted".to_owned(),
                "actor" => fixture.options.github_actor = "drifted".to_owned(),
                "triggering_actor" => {
                    fixture.options.github_triggering_actor = "drifted".to_owned()
                }
                _ => unreachable!(),
            }

            let error = create_preview_build_attestation(&fixture.options)
                .unwrap_err()
                .to_string();
            assert_eq!(error, UNAUTHORIZED_GITHUB_CONTEXT_ERROR, "field {field}");
            assert!(
                !fixture.options.output_path.exists(),
                "field {field} created an output"
            );
        }
    }

    #[test]
    fn creator_rejects_workflow_or_preflight_source_drift() {
        let workflow_drift = CreationFixture::new();
        fs::write(&workflow_drift.options.workflow_path, b"name: drifted\n").unwrap();
        let error = create_preview_build_attestation(&workflow_drift.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("differs byte-for-byte"),
            "workflow error: {error}"
        );

        let preflight_drift = CreationFixture::new();
        fs::write(
            &preflight_drift.options.unsigned_preflight_path,
            preflight_bytes(&"f".repeat(40), &"3".repeat(64)),
        )
        .unwrap();
        let error = create_preview_build_attestation(&preflight_drift.options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("does not match the exact build-source manifest"),
            "preflight error: {error}"
        );
    }

    #[test]
    fn creator_rejects_duplicate_preflight_keys_with_strict_json() {
        let fixture = CreationFixture::new();
        let bytes = fs::read(&fixture.options.unsigned_preflight_path).unwrap();
        let duplicate = String::from_utf8(bytes).unwrap().replacen(
            "\"source_commit\":",
            "\"source_commit\":\"1\",\"source_commit\":",
            1,
        );
        fs::write(&fixture.options.unsigned_preflight_path, duplicate).unwrap();

        let error = create_preview_build_attestation(&fixture.options)
            .unwrap_err()
            .to_string();
        assert!(error.contains("duplicate JSON key"), "error: {error}");
    }

    #[test]
    fn creator_requires_signing_to_change_both_executable_digests() {
        for field in ["preview_binary_sha256", "lsp_binary_sha256"] {
            let fixture = CreationFixture::new();
            let mut preflight: serde_json::Value = serde_json::from_slice(
                &fs::read(&fixture.options.unsigned_preflight_path).unwrap(),
            )
            .unwrap();
            preflight[field] = json!(if field == "preview_binary_sha256" {
                sha256_hex(SIGNED_SERVER)
            } else {
                sha256_hex(SIGNED_LSP)
            });
            fs::write(
                &fixture.options.unsigned_preflight_path,
                serde_json::to_vec_pretty(&preflight).unwrap(),
            )
            .unwrap();

            let error = create_preview_build_attestation(&fixture.options)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("final sha256 must differ"),
                "field {field}; error: {error}"
            );
        }
    }
}
