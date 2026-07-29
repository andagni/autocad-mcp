use crate::manifest::{
    manifest_for_mode, read_plugin_metadata, validate_manifest, validate_plugin_license,
    validate_source_distribution_evidence, McpbManifest, PackageMode, PackageTarget,
    OWNER_DISTRIBUTION_APPROVAL_SCHEMA, OWNER_DISTRIBUTION_APPROVAL_SCHEMA_FILE,
    PREVIEW_READ_ONLY_TOOL_COUNT,
};
use anyhow::{anyhow, Context, Result};
use autocad_mcp::certification::{
    xref_sha256_bytes, xref_sha256_file, CertificationProfileDefinition,
    XrefCertificationBuildIdentity, XrefEmbeddedArtifactSha256, XrefMutationOperation,
    XREF_MUTATION_OPERATIONS,
};
use plugin_validate::{
    validate_documentation_provenance_for_package_source, validate_packaged_plugin,
    DOCUMENTATION_PROVENANCE_PLUGIN_PATH,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;
use zip::write::SimpleFileOptions as FileOptions;

pub(crate) const PREVIEW_ACTIVATION_DIRECTORY: &str = "plugin/resources/autocad-preview-activation";
pub(crate) const PREVIEW_ACTIVATION_CATALOGUE_PACKAGE_PATH: &str =
    "plugin/resources/autocad-preview-activation/autocad-activation-catalogue.json";
pub(crate) const PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH: &str =
    "plugin/resources/autocad-preview-activation/package-binding.json";
pub(crate) const XREF_PACKAGE_BINDING_SCHEMA_VERSION: u32 = 1;
pub(crate) const PREVIEW_ACTIVATION_BINDING_SCHEMA_VERSION: u32 = 2;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct XrefPackageBinding {
    pub(crate) schema_version: u32,
    pub(crate) release_binary_sha256: String,
    pub(crate) certified_arg_sha256: String,
    pub(crate) manifest_sha256: String,
    pub(crate) release_evidence_sha256: String,
    pub(crate) transaction_evidence_sha256: String,
    pub(crate) attestation_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreviewActivationPackageBinding {
    pub(crate) schema_version: u32,
    pub(crate) preview_binary_sha256: String,
    pub(crate) catalogue_sha256: String,
    pub(crate) files: Vec<PreviewActivationFileBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreviewActivationFileBinding {
    pub(crate) path: String,
    pub(crate) sha256: String,
}

#[derive(Debug)]
struct StagedXrefBinary {
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct XrefCertificationInfoV4 {
    schema_version: u32,
    experimental_support: bool,
    activation_catalogue_sha256: String,
    #[serde(
        rename = "certified_arg_sha256",
        deserialize_with = "deserialize_required_nullable"
    )]
    _certified_arg_sha256: Option<String>,
    #[serde(
        rename = "certified_arg_policy_id",
        deserialize_with = "deserialize_required_nullable"
    )]
    _certified_arg_policy_id: Option<String>,
    #[serde(
        rename = "certified_arg_policy_sha256",
        deserialize_with = "deserialize_required_nullable"
    )]
    _certified_arg_policy_sha256: Option<String>,
    certification_failpoints_enabled: bool,
    #[serde(rename = "crt_linkage")]
    _crt_linkage: String,
    #[serde(rename = "artifact_sha256")]
    _artifact_sha256: XrefEmbeddedArtifactSha256,
    #[serde(rename = "title_block_profile_registry_sha256")]
    _title_block_profile_registry_sha256: String,
    #[serde(rename = "title_block_profiles")]
    _title_block_profiles: Vec<CertificationProfileDefinition>,
    build_identity: XrefCertificationBuildIdentity,
    xref_mutation_tools: Vec<XrefMutationOperation>,
}

fn deserialize_required_nullable<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

pub struct PackageOptions {
    pub mode: PackageMode,
    pub target: PackageTarget,
    pub plugin_dir: PathBuf,
    pub schema_root: PathBuf,
    pub binary_path: PathBuf,
    pub lsp_binary_path: Option<PathBuf>,
    pub out_dir: PathBuf,
}

pub fn create_package(options: PackageOptions) -> Result<PathBuf> {
    validate_package_mode_inputs(&options)?;
    if !options.binary_path.is_file() {
        return Err(anyhow!(
            "release binary does not exist: {}",
            options.binary_path.display()
        ));
    }
    for required_source in [
        "skills/autolisp/SKILL.md",
        DOCUMENTATION_PROVENANCE_PLUGIN_PATH,
    ] {
        if !options.plugin_dir.join(required_source).is_file() {
            return Err(anyhow!(
                "missing required plugin source file: {required_source}"
            ));
        }
    }
    let provenance_errors =
        validate_documentation_provenance_for_package_source(&options.plugin_dir);
    if !provenance_errors.is_empty() {
        return Err(anyhow!(
            "source plugin documentation provenance validation failed: {}",
            provenance_errors.join("; ")
        ));
    }

    std::fs::create_dir_all(&options.out_dir)?;
    let staging = tempfile::tempdir()?;
    let staged_plugin = staging.path().join("plugin");
    copy_clean_plugin_tree(&options.plugin_dir, &staged_plugin)?;
    std::fs::write(
        staged_plugin.join(OWNER_DISTRIBUTION_APPROVAL_SCHEMA_FILE),
        OWNER_DISTRIBUTION_APPROVAL_SCHEMA,
    )
    .context("stage exact owner-distribution approval schema")?;
    let staged_binary = stage_binary(options.target, &options.binary_path, &staged_plugin)?;
    if let Some(lsp_binary_path) = &options.lsp_binary_path {
        stage_lsp_binary(options.target, lsp_binary_path, &staged_plugin)?;
        stage_lsp_config(options.target, &staged_plugin)?;
    } else {
        remove_lsp_config(&staged_plugin)?;
    }

    let report = validate_packaged_plugin(&staged_plugin, &options.schema_root);
    if report.errors > 0 {
        return Err(anyhow!(
            "staged plugin validation failed with {} error(s)",
            report.errors
        ));
    }

    #[cfg(not(test))]
    let binary_inspection = Some(inspect_staged_binary(&staged_binary, options.mode)?);
    #[cfg(test)]
    let binary_inspection = test_staged_binary_info(&staged_binary, &staged_plugin, options.mode)?;

    if options.mode == PackageMode::Preview {
        let binary = binary_inspection.as_ref().ok_or_else(|| {
            anyhow!("Preview packaging requires successful staged-binary introspection")
        })?;
        stage_preview_activation_bundle(staging.path(), binary)?;
    }

    let metadata = read_plugin_metadata(&staged_plugin)?;
    validate_plugin_license(&staged_plugin, &metadata)?;
    validate_source_distribution_evidence(&staged_plugin)?;
    let manifest = manifest_for_mode(options.target, options.mode, &metadata);
    let validated_mode = validate_manifest(&manifest, options.target)?;
    if validated_mode != options.mode {
        return Err(anyhow!(
            "generated MCPB manifest package mode does not match requested mode"
        ));
    }
    write_manifest(&manifest, staging.path())?;

    let package_path = options
        .out_dir
        .join(options.target.package_name_for(options.mode));
    write_mcpb_archive(staging.path(), &package_path)?;
    Ok(package_path)
}

fn validate_package_mode_inputs(options: &PackageOptions) -> Result<()> {
    match options.mode {
        PackageMode::Release => {
            if options.target == PackageTarget::WindowsX64 {
                return Err(anyhow!(
                    "Windows Release packaging is unavailable until the package-safe statement, signature verification, and closed package-safe binding are implemented"
                ));
            }
        }
        PackageMode::Preview => {
            if options.target != PackageTarget::WindowsX64 {
                return Err(anyhow!("Preview packaging requires target windows-x64"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn skill_advertises_xref_mutations(plugin_dir: &Path) -> Result<bool> {
    let skill_path = plugin_dir.join("skills/autocad-mcp/SKILL.md");
    let skill = std::fs::read_to_string(&skill_path)
        .with_context(|| format!("read public tool contract {}", skill_path.display()))?;
    Ok(XREF_MUTATION_OPERATIONS
        .iter()
        .any(|operation| skill.contains(operation.as_str())))
}

fn inspect_staged_binary(binary_path: &Path, mode: PackageMode) -> Result<StagedXrefBinary> {
    let info = read_binary_xref_certification_info(binary_path)?;
    validate_binary_package_mode(&info, mode)?;
    let reported = &info.xref_mutation_tools;
    if reported.is_empty() {
        return Err(anyhow!(
            "release binary xref_mutation_tools inventory must not be empty"
        ));
    }
    match mode {
        PackageMode::Release => {
            let listed = read_binary_tool_names(binary_path, false)?;
            validate_xref_mutation_inventory(reported, &listed)?;
            require_experimental_list_tools_rejected(binary_path)?;
        }
        PackageMode::Preview => {
            let plain_tools = read_binary_tools(binary_path, false)?;
            validate_preview_plain_tool_inventory(&plain_tools)?;
            let listed = tool_names(&plain_tools)?;
            let expected_mutations = XREF_MUTATION_OPERATIONS.map(XrefMutationOperation::as_str);
            if listed
                .iter()
                .map(String::as_str)
                .any(|name| expected_mutations.contains(&name))
            {
                return Err(anyhow!(
                    "Preview binary plain list-tools must not expose XREF mutations"
                ));
            }

            let listed = read_binary_tool_names(binary_path, true)?;
            validate_xref_mutation_inventory(reported, &listed)?;
        }
    }
    let sha256 =
        xref_sha256_file(binary_path).context("hash staged package binary after introspection")?;
    Ok(StagedXrefBinary { sha256 })
}

fn validate_binary_package_mode(info: &XrefCertificationInfoV4, mode: PackageMode) -> Result<()> {
    if info.schema_version != 4 {
        return Err(anyhow!(
            "release binary certification introspection schema_version must be 4"
        ));
    }
    let embedded_bundle = autocad_mcp::activation::embedded_activation_bundle()
        .map_err(|error| anyhow!("validate embedded activation bundle for packaging: {error}"))?;
    if info.activation_catalogue_sha256 != embedded_bundle.catalogue_sha256 {
        return Err(anyhow!(
            "{mode:?} packaging requires the staged binary activation_catalogue_sha256 to match the exact embedded Preview activation catalogue"
        ));
    }
    let experimental_support = info.experimental_support;
    let expected = mode == PackageMode::Preview;
    if experimental_support != expected {
        return Err(anyhow!(
            "{mode:?} packaging requires experimental_support={expected}; staged binary reported {experimental_support}"
        ));
    }
    if info.certification_failpoints_enabled || info.build_identity.certification_failpoints_enabled
    {
        return Err(anyhow!(
            "{mode:?} packaging rejects certification-failpoint binaries"
        ));
    }
    Ok(())
}

#[cfg(test)]
fn test_staged_binary_info(
    binary_path: &Path,
    staged_plugin: &Path,
    mode: PackageMode,
) -> Result<Option<StagedXrefBinary>> {
    // Legacy unit fixtures model a non-XREF package with inert binary bytes.
    // Once a fixture supplies readable introspection, all mode/schema checks
    // remain mandatory even when its synthetic skill omits XREF tools.
    if !skill_advertises_xref_mutations(staged_plugin)?
        && read_binary_xref_certification_info(binary_path).is_err()
    {
        return Ok(None);
    }
    inspect_staged_binary(binary_path, mode).map(Some)
}

fn validate_xref_mutation_inventory(
    reported: &[XrefMutationOperation],
    listed_tools: &[String],
) -> Result<()> {
    if reported != XREF_MUTATION_OPERATIONS.as_slice() {
        let expected = XREF_MUTATION_OPERATIONS.map(XrefMutationOperation::as_str);
        let actual = reported
            .iter()
            .map(|operation| operation.as_str())
            .collect::<Vec<_>>();
        return Err(anyhow!(
            "release binary xref_mutation_tools must match the canonical registry order; expected {expected:?}, got {actual:?}"
        ));
    }

    let expected = XREF_MUTATION_OPERATIONS.map(XrefMutationOperation::as_str);
    let listed_mutations = listed_tools
        .iter()
        .map(String::as_str)
        .filter(|name| expected.contains(name))
        .collect::<Vec<_>>();
    if listed_mutations.as_slice() != expected.as_slice() {
        return Err(anyhow!(
            "release binary list-tools XREF mutation inventory/order does not match hidden certification inventory; expected {expected:?}, got {listed_mutations:?}"
        ));
    }
    Ok(())
}

fn validate_preview_plain_tool_inventory(tools: &[Value]) -> Result<()> {
    if tools.len() != PREVIEW_READ_ONLY_TOOL_COUNT {
        return Err(anyhow!(
            "Preview binary plain list-tools inventory must contain exactly {PREVIEW_READ_ONLY_TOOL_COUNT} read-only tools; got {}",
            tools.len()
        ));
    }
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("staged Preview list-tools entry lacks a string name"))?;
        if tool
            .pointer("/annotations/readOnlyHint")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(anyhow!(
                "Preview binary plain list-tools entry {name} must declare readOnlyHint=true"
            ));
        }
    }
    Ok(())
}

pub(crate) fn embedded_preview_activation_files() -> Result<BTreeMap<String, Vec<u8>>> {
    let bundle = autocad_mcp::activation::embedded_activation_bundle()
        .map_err(|error| anyhow!("validate embedded Preview activation bundle: {error}"))?;
    let mut files = BTreeMap::new();
    for file in bundle.files {
        let path = Path::new(file.path);
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(anyhow!(
                "embedded Preview activation asset path must be normalized: {}",
                path.display()
            ));
        }
        if files
            .insert(file.path.to_owned(), file.bytes.to_vec())
            .is_some()
        {
            return Err(anyhow!(
                "embedded Preview activation bundle contains duplicate path {}",
                file.path
            ));
        }
    }
    if files.len() != 21 {
        return Err(anyhow!(
            "embedded Preview activation bundle is not closed: expected 21 catalogue/profile files, got {}",
            files.len()
        ));
    }
    let catalogue_bytes = files
        .get("autocad-activation-catalogue.json")
        .ok_or_else(|| anyhow!("embedded Preview activation bundle lacks its catalogue"))?;
    if xref_sha256_bytes(catalogue_bytes) != bundle.catalogue_sha256 {
        return Err(anyhow!(
            "embedded Preview activation catalogue digest does not match its validated bundle"
        ));
    }
    Ok(files)
}

fn stage_preview_activation_bundle(staging_root: &Path, binary: &StagedXrefBinary) -> Result<()> {
    let files = embedded_preview_activation_files()?;
    let directory = staging_root.join(PREVIEW_ACTIVATION_DIRECTORY);
    if directory.exists() {
        return Err(anyhow!(
            "staged Preview resource directory already exists: {}",
            directory.display()
        ));
    }
    std::fs::create_dir_all(&directory)?;

    let mut inventory = Vec::with_capacity(files.len());
    for (relative_path, bytes) in &files {
        let staged_path = directory.join(relative_path);
        let parent = staged_path
            .parent()
            .ok_or_else(|| anyhow!("Preview activation asset path has no parent"))?;
        std::fs::create_dir_all(parent)?;
        std::fs::write(&staged_path, bytes).with_context(|| {
            format!(
                "write staged Preview activation asset {}",
                staged_path.display()
            )
        })?;
        inventory.push(PreviewActivationFileBinding {
            path: relative_path.clone(),
            sha256: xref_sha256_file(&staged_path)?,
        });
    }

    let catalogue_sha256 = files
        .get("autocad-activation-catalogue.json")
        .map(|bytes| xref_sha256_bytes(bytes))
        .ok_or_else(|| anyhow!("embedded Preview activation bundle lacks its catalogue"))?;
    let binding = PreviewActivationPackageBinding {
        schema_version: PREVIEW_ACTIVATION_BINDING_SCHEMA_VERSION,
        preview_binary_sha256: binary.sha256.clone(),
        catalogue_sha256,
        files: inventory,
    };
    let binding_path = staging_root.join(PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH);
    std::fs::write(
        &binding_path,
        format!("{}\n", serde_json::to_string_pretty(&binding)?),
    )
    .with_context(|| {
        format!(
            "write staged Preview activation package binding {}",
            binding_path.display()
        )
    })?;
    Ok(())
}

fn parse_binary_xref_certification_info(bytes: &[u8]) -> Result<XrefCertificationInfoV4> {
    serde_json::from_slice(bytes)
        .context("parse release binary XREF certification introspection as closed schema v4")
}

fn read_binary_xref_certification_info(binary_path: &Path) -> Result<XrefCertificationInfoV4> {
    let output = Command::new(binary_path)
        .arg("xref-certification-info")
        .output()
        .with_context(|| {
            format!(
                "run release binary XREF certification introspection {}",
                binary_path.display()
            )
        })?;
    if !output.status.success() {
        return Err(anyhow!(
            "release binary XREF certification introspection failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    parse_binary_xref_certification_info(&output.stdout).with_context(|| {
        format!(
            "staged binary XREF certification introspection stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn read_binary_tools(binary_path: &Path, experimental: bool) -> Result<Vec<Value>> {
    let mut command = Command::new(binary_path);
    command.arg("list-tools");
    if experimental {
        command.arg("--experimental");
    }
    let label = if experimental {
        "list-tools --experimental"
    } else {
        "list-tools"
    };
    let output = command.output().with_context(|| {
        format!(
            "run staged release binary {label} {}",
            binary_path.display()
        )
    })?;
    if !output.status.success() {
        return Err(anyhow!(
            "staged release binary {label} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let value: Value = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse staged release binary {label} output: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })?;
    let tools = value
        .as_array()
        .ok_or_else(|| anyhow!("staged release binary {label} output must be an array"))?;
    Ok(tools.clone())
}

fn tool_names(tools: &[Value]) -> Result<Vec<String>> {
    let mut names = Vec::with_capacity(tools.len());
    let mut seen = BTreeSet::new();
    for tool in tools {
        let name = tool.get("name").and_then(Value::as_str).ok_or_else(|| {
            anyhow!("staged release binary list-tools entries require string name fields")
        })?;
        if !seen.insert(name) {
            return Err(anyhow!(
                "staged release binary list-tools contains duplicate tool {name}"
            ));
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

fn read_binary_tool_names(binary_path: &Path, experimental: bool) -> Result<Vec<String>> {
    tool_names(&read_binary_tools(binary_path, experimental)?)
}

fn require_experimental_list_tools_rejected(binary_path: &Path) -> Result<()> {
    let output = Command::new(binary_path)
        .args(["list-tools", "--experimental"])
        .output()
        .with_context(|| {
            format!(
                "probe staged Release binary experimental option {}",
                binary_path.display()
            )
        })?;
    if output.status.success() {
        return Err(anyhow!(
            "Release binary unexpectedly accepts list-tools --experimental"
        ));
    }
    Ok(())
}

fn copy_clean_plugin_tree(source: &Path, dest: &Path) -> Result<()> {
    for entry in WalkDir::new(source).into_iter().filter_entry(|entry| {
        entry
            .path()
            .strip_prefix(source)
            .map(|rel| {
                rel.as_os_str().is_empty()
                    || is_package_plugin_source_path(rel, entry.file_type().is_dir())
            })
            .unwrap_or(true)
    }) {
        let entry = entry.with_context(|| format!("walk {}", source.display()))?;
        let path = entry.path();
        let rel = path.strip_prefix(source)?;
        if rel.as_os_str().is_empty()
            || !is_package_plugin_source_path(rel, entry.file_type().is_dir())
        {
            continue;
        }
        let target = dest.join(rel);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            std::fs::create_dir_all(target.parent().unwrap())?;
            std::fs::copy(path, &target)
                .with_context(|| format!("copy {} to {}", path.display(), target.display()))?;
        }
    }
    Ok(())
}

pub(crate) fn is_package_plugin_source_path(rel: &Path, is_directory: bool) -> bool {
    let Some(components) = rel
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };

    if components.iter().any(|name| {
        name.eq_ignore_ascii_case(".gitignore") || name.eq_ignore_ascii_case(".DS_Store")
    }) {
        return false;
    }

    if is_directory {
        return matches!(
            components.as_slice(),
            [".claude-plugin"]
                | [".third-party"]
                | ["skills"]
                | ["skills", "autocad-mcp"]
                | ["skills", "autolisp"]
                | ["skills", "autolisp", "references"]
        ) || components.starts_with(&["skills", "autolisp", "references"]);
    }

    match components.as_slice() {
        [".lsp.json" | ".mcp.json" | "CHANGELOG.md" | "LICENSE" | "THIRD_PARTY_LICENSES.txt"]
        | [".claude-plugin", "plugin.json"]
        | [".third-party", "third-party-license-policy.json"]
        | [".third-party", "third-party-license-provenance.json"]
        | [".third-party", "source-lock.spdx.json"]
        | [".third-party", "source-closure-windows.spdx.json"]
        | ["skills", "autocad-mcp", "SKILL.md"]
        | ["skills", "autolisp", "SKILL.md"]
        | ["skills", "autolisp", "references", "documentation-provenance.json"]
        | ["skills", "autolisp", "references", "autolisp-lsp-index.json"] => true,
        ["skills", "autolisp", "references", reference @ ..] => reference
            .last()
            .is_some_and(|file_name| file_name.ends_with(".md")),
        _ => false,
    }
}

/// Return whether one regular file is admissible in a finished MCPB.
///
/// Package-source files use the same closed nested allowlist as staging. The
/// remaining paths are generated by the packager for the selected target.
pub(crate) fn is_package_archive_file_path(rel: &Path, target: PackageTarget) -> bool {
    let Some(components) = rel
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };

    if components.as_slice() == ["manifest.json"] {
        return true;
    }
    let ["plugin", plugin_components @ ..] = components.as_slice() else {
        return false;
    };
    let plugin_relative = PathBuf::from(plugin_components.join("/"));
    if is_package_plugin_source_path(&plugin_relative, false)
        || plugin_components == ["owner-distribution-approval.schema.json"]
    {
        return true;
    }

    match target {
        PackageTarget::MacosArm64 => matches!(
            plugin_components,
            ["bin", "autocad-mcp"] | ["bin", "autolisp-lsp"]
        ),
        PackageTarget::WindowsX64 => {
            if let ["resources", "autocad-preview-activation", relative @ ..] = plugin_components {
                let relative = relative.join("/");
                return relative == "package-binding.json"
                    || autocad_mcp::activation::embedded_activation_bundle()
                        .is_ok_and(|bundle| bundle.files.iter().any(|file| file.path == relative));
            }
            matches!(
                plugin_components,
                ["bin", "autocad-mcp.exe"]
                    | ["bin", "autolisp-lsp.exe"]
                    | ["resources", "xref-certification", "certified-profile.arg"]
                    | ["resources", "xref-certification", "manifest.json"]
                    | ["resources", "xref-certification", "release-evidence.json"]
                    | [
                        "resources",
                        "xref-certification",
                        "transaction-evidence.json"
                    ]
                    | ["resources", "xref-certification", "attestation.json"]
                    | ["resources", "xref-certification", "package-binding.json"]
            )
        }
    }
}

pub(crate) fn reject_release_gitignore(path: &Path) -> Result<()> {
    if path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(".gitignore"))
    }) {
        return Err(anyhow!(
            "release artifact must not contain a .gitignore path: {}",
            path.display()
        ));
    }
    Ok(())
}

fn stage_binary(
    target: PackageTarget,
    binary_path: &Path,
    staged_plugin: &Path,
) -> Result<PathBuf> {
    let bin_dir = staged_plugin.join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    let staged_binary = bin_dir.join(target.binary_name());
    std::fs::copy(binary_path, &staged_binary).with_context(|| {
        format!(
            "copy binary {} to {}",
            binary_path.display(),
            staged_binary.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&staged_binary)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&staged_binary, perms)?;
    }
    Ok(staged_binary)
}

fn stage_lsp_binary(target: PackageTarget, binary_path: &Path, staged_plugin: &Path) -> Result<()> {
    if !binary_path.is_file() {
        return Err(anyhow!(
            "LSP release binary does not exist: {}",
            binary_path.display()
        ));
    }
    let bin_dir = staged_plugin.join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    let staged_name = match target {
        PackageTarget::WindowsX64 => "autolisp-lsp.exe",
        PackageTarget::MacosArm64 => "autolisp-lsp",
    };
    let staged_binary = bin_dir.join(staged_name);
    std::fs::copy(binary_path, &staged_binary).with_context(|| {
        format!(
            "copy LSP binary {} to {}",
            binary_path.display(),
            staged_binary.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&staged_binary)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&staged_binary, perms)?;
    }
    Ok(())
}

fn remove_lsp_config(staged_plugin: &Path) -> Result<()> {
    let lsp_path = staged_plugin.join(".lsp.json");
    if lsp_path.is_file() {
        std::fs::remove_file(&lsp_path)
            .with_context(|| format!("remove {}", lsp_path.display()))?;
    }
    Ok(())
}

fn stage_lsp_config(target: PackageTarget, staged_plugin: &Path) -> Result<()> {
    let lsp_path = staged_plugin.join(".lsp.json");
    if !lsp_path.is_file() {
        return Err(anyhow!(
            "plugin/.lsp.json is required when an LSP binary is supplied"
        ));
    }

    let text = std::fs::read_to_string(&lsp_path)
        .with_context(|| format!("read {}", lsp_path.display()))?;
    let mut value: Value =
        serde_json::from_str(&text).with_context(|| format!("parse {}", lsp_path.display()))?;
    let server = value
        .get_mut("autolisp-lsp")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("plugin/.lsp.json missing autolisp-lsp object"))?;
    server.insert(
        "command".to_string(),
        Value::String(lsp_command(target).to_string()),
    );

    let text = serde_json::to_string_pretty(&value)?;
    std::fs::write(&lsp_path, format!("{text}\n"))
        .with_context(|| format!("write {}", lsp_path.display()))?;
    Ok(())
}

fn lsp_command(target: PackageTarget) -> &'static str {
    match target {
        PackageTarget::WindowsX64 => "${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp.exe",
        PackageTarget::MacosArm64 => "${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp",
    }
}

fn write_manifest(manifest: &McpbManifest, staging_root: &Path) -> Result<()> {
    let text = serde_json::to_string_pretty(manifest)?;
    std::fs::write(staging_root.join("manifest.json"), format!("{text}\n"))?;
    Ok(())
}

fn write_mcpb_archive(staging_root: &Path, package_path: &Path) -> Result<()> {
    let package_dir = package_path
        .parent()
        .ok_or_else(|| anyhow!("package path has no parent: {}", package_path.display()))?;
    let temp_file = tempfile::NamedTempFile::new_in(package_dir)
        .with_context(|| format!("create temporary package in {}", package_dir.display()))?;
    let temp_path = temp_file.path().to_path_buf();
    let file = temp_file
        .reopen()
        .with_context(|| format!("open temporary package {}", temp_path.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);
    let executable_options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);

    let mut files = Vec::new();
    for entry in WalkDir::new(staging_root) {
        let entry = entry.with_context(|| format!("walk {}", staging_root.display()))?;
        if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    files.sort();

    for path in files {
        let relative_path = path.strip_prefix(staging_root)?;
        reject_release_gitignore(relative_path)?;
        let rel = relative_path.to_string_lossy().replace('\\', "/");
        let mut source =
            File::open(&path).with_context(|| format!("open archive source {}", path.display()))?;
        let mut bytes = Vec::new();
        source
            .read_to_end(&mut bytes)
            .with_context(|| format!("read archive source {}", path.display()))?;
        let opts = if rel.starts_with("plugin/bin/") {
            executable_options
        } else {
            options
        };
        zip.start_file(&rel, opts)
            .with_context(|| format!("start archive file {rel}"))?;
        zip.write_all(&bytes)
            .with_context(|| format!("write archive file {rel}"))?;
    }

    zip.finish()
        .with_context(|| format!("finish archive {}", temp_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o644))
            .with_context(|| format!("set package permissions on {}", temp_path.display()))?;
    }
    temp_file
        .persist(package_path)
        .map_err(|err| err.error)
        .with_context(|| {
            format!(
                "rename {} to {}",
                temp_path.display(),
                package_path.display()
            )
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        PROJECT_LICENSE_TEXT, SOURCE_LOCK_SBOM, THIRD_PARTY_LICENSES, THIRD_PARTY_LICENSE_POLICY,
        THIRD_PARTY_LICENSE_PROVENANCE, WINDOWS_SOURCE_CLOSURE_SBOM,
    };
    use crate::smoke::{smoke_package, SmokeOptions};
    use std::io::Read;
    use tempfile::TempDir;
    use zip::ZipArchive;

    fn write_file(path: &std::path::Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn valid_certification_info(experimental_support: bool) -> Value {
        let build_identity = autocad_mcp::certification::xref_certification_build_identity();
        let certified_arg_sha256 =
            autocad_mcp::ops::xref_runtime::certified_arg_sha256_build_value().map(str::to_owned);
        let certified_arg_policy_id = (!build_identity.certified_arg_policy_id.is_empty())
            .then_some(build_identity.certified_arg_policy_id.clone());
        let certified_arg_policy_sha256 = (!build_identity.certified_arg_policy_sha256.is_empty())
            .then_some(build_identity.certified_arg_policy_sha256.clone());
        let activation_catalogue_sha256 =
            autocad_mcp::activation::activation_catalogue_sha256().unwrap();
        serde_json::json!({
            "schema_version": 4,
            "experimental_support": experimental_support,
            "activation_catalogue_sha256": activation_catalogue_sha256,
            "certified_arg_sha256": certified_arg_sha256,
            "certified_arg_policy_id": certified_arg_policy_id,
            "certified_arg_policy_sha256": certified_arg_policy_sha256,
            "certification_failpoints_enabled":
                build_identity.certification_failpoints_enabled,
            "crt_linkage": autocad_mcp::certification::xref_certification_crt_linkage(),
            "artifact_sha256":
                autocad_mcp::certification::xref_embedded_artifact_sha256(),
            "title_block_profile_registry_sha256":
                autocad_mcp::ops::profiles::title_block_profile_registry_sha256(),
            "title_block_profiles":
                autocad_mcp::certification::embedded_certification_profile_definitions(),
            "build_identity": build_identity,
            "xref_mutation_tools":
                XREF_MUTATION_OPERATIONS.map(XrefMutationOperation::as_str),
        })
    }

    #[cfg(unix)]
    fn write_mode_introspection_binary(path: &Path, experimental_support: bool) {
        use std::os::unix::fs::PermissionsExt;

        let canonical = XREF_MUTATION_OPERATIONS.map(XrefMutationOperation::as_str);
        let info = valid_certification_info(experimental_support);
        let tools = canonical
            .iter()
            .map(|name| serde_json::json!({"name": name}))
            .collect::<Vec<_>>();
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\n  xref-certification-info) printf '%s\\n' '{}' ;;\n  list-tools) [ \"$2\" = \"--experimental\" ] && exit 2; printf '%s\\n' '{}' ;;\n  *) exit 2 ;;\nesac\n",
            serde_json::to_string(&info).unwrap(),
            serde_json::to_string(&tools).unwrap(),
        );
        write_file(path, &script);
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn advertise_xref_mutations(plugin: &Path) {
        write_file(
            &plugin.join("skills/autocad-mcp/SKILL.md"),
            "---\nname: autocad-mcp\ndescription: Test skill\n---\n# Test\n\nUse attach_xref.\n",
        );
    }

    fn write_fake_documentation_provenance(plugin: &Path) {
        let autolisp_skill = plugin.join("skills/autolisp");
        let references = autolisp_skill.join("references");
        let ledger = serde_json::json!({
            "schema_version": 1,
            "reference_root": "plugin/skills/autolisp",
            "copyright_holder": "andagni",
            "license": "GPL-3.0-or-later",
            "sources": [{
                "id": "official-factual-reference",
                "title": "Official factual reference",
                "url": "https://example.test/reference",
                "version": "reviewed snapshot 1",
                "reviewed_on": "2026-07-26",
                "rights_basis": "facts_only_no_source_expression_redistributed"
            }],
            "artifacts": [
                {
                    "path": "SKILL.md",
                    "sha256": xref_sha256_file(&autolisp_skill.join("SKILL.md")).unwrap(),
                    "kind": "markdown",
                    "disposition": "first_party_factual_synthesis",
                    "source_ids": ["official-factual-reference"]
                },
                {
                    "path": "references/autolisp-lsp-index.json",
                    "sha256": xref_sha256_file(&references.join("autolisp-lsp-index.json")).unwrap(),
                    "kind": "autolisp_lsp_index",
                    "disposition": "first_party_curated_index",
                    "source_ids": ["official-factual-reference"]
                },
                {
                    "path": "references/dcl/guide.md",
                    "sha256": xref_sha256_file(&references.join("dcl/guide.md")).unwrap(),
                    "kind": "markdown",
                    "disposition": "first_party_factual_synthesis",
                    "source_ids": ["official-factual-reference"]
                },
                {
                    "path": "references/guide.md",
                    "sha256": xref_sha256_file(&references.join("guide.md")).unwrap(),
                    "kind": "markdown",
                    "disposition": "first_party_factual_synthesis",
                    "source_ids": ["official-factual-reference"]
                }
            ]
        });
        write_file(
            &references.join("documentation-provenance.json"),
            &format!("{}\n", serde_json::to_string_pretty(&ledger).unwrap()),
        );
    }

    fn fake_plugin() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        let plugin = dir.path().join("plugin");
        write_file(
            &plugin.join(".claude-plugin/plugin.json"),
            r#"{"name":"autocad-mcp","description":"A rust-backed AutoLISP MCP","version":"0.0.1","license":"GPL-3.0-or-later","author":{"name":"andagni"}}"#,
        );
        write_file(
            &plugin.join(".mcp.json"),
            r#"{"mcpServers":{"autocad-mcp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autocad-mcp","args":["serve"]}}}"#,
        );
        write_file(
            &plugin.join("skills/autocad-mcp/SKILL.md"),
            "---\nname: autocad-mcp\ndescription: Test skill\n---\n# Test\n",
        );
        write_file(
            &plugin.join("LICENSE"),
            std::str::from_utf8(PROJECT_LICENSE_TEXT).unwrap(),
        );
        std::fs::create_dir_all(plugin.join(".third-party")).unwrap();
        std::fs::write(
            plugin.join(".third-party/third-party-license-policy.json"),
            THIRD_PARTY_LICENSE_POLICY,
        )
        .unwrap();
        std::fs::write(
            plugin.join(".third-party/source-lock.spdx.json"),
            SOURCE_LOCK_SBOM,
        )
        .unwrap();
        std::fs::write(
            plugin.join(".third-party/source-closure-windows.spdx.json"),
            WINDOWS_SOURCE_CLOSURE_SBOM,
        )
        .unwrap();
        std::fs::write(
            plugin.join(".third-party/third-party-license-provenance.json"),
            THIRD_PARTY_LICENSE_PROVENANCE,
        )
        .unwrap();
        std::fs::write(
            plugin.join("THIRD_PARTY_LICENSES.txt"),
            THIRD_PARTY_LICENSES,
        )
        .unwrap();
        write_file(&plugin.join("CHANGELOG.md"), "# Changelog\n");
        write_file(&plugin.join(".gitignore"), "*\n");
        write_file(&plugin.join("skills/autocad-mcp/.gitignore"), "*\n");
        write_file(&plugin.join(".DS_Store"), "local\n");
        write_file(&plugin.join("bin/old-dev-binary"), "old\n");
        write_file(&plugin.join("private-material/leak.txt"), "no\n");
        write_file(&plugin.join("scratch/leak.txt"), "no\n");
        write_file(&plugin.join(".claude-plugin/private.json"), "no\n");
        write_file(&plugin.join("skills/private/SKILL.md"), "no\n");
        write_file(&plugin.join("skills/autocad-mcp/private.md"), "no\n");
        write_file(
            &plugin.join("skills/autolisp/SKILL.md"),
            "---\nname: autolisp\ndescription: Test skill\n---\n# Test\n",
        );
        write_file(
            &plugin.join("skills/autolisp/references/guide.md"),
            "# Guide\n",
        );
        write_file(
            &plugin.join("skills/autolisp/references/dcl/guide.md"),
            "# DCL Guide\n",
        );
        write_file(
            &plugin.join("skills/autolisp/references/autolisp-lsp-index.json"),
            &format!(
                "{}\n",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": 1,
                    "symbols": [{
                        "name": "sample",
                        "kind": "builtin",
                        "signature": "(sample)",
                        "summary": "A sample symbol.",
                        "detail": null,
                        "source": "plugin/skills/autolisp/references/guide.md",
                        "completion": true
                    }]
                }))
                .unwrap()
            ),
        );
        write_file(
            &plugin.join("skills/autolisp/references/private.json"),
            "no\n",
        );
        write_fake_documentation_provenance(&plugin);
        dir
    }

    fn zip_names(path: &std::path::Path) -> Vec<String> {
        let file = std::fs::File::open(path).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        let mut names = Vec::new();
        for i in 0..archive.len() {
            names.push(archive.by_index(i).unwrap().name().to_string());
        }
        names.sort();
        names
    }

    #[test]
    fn plugin_source_copy_uses_explicit_nested_allowlist() {
        for (path, is_directory) in [
            (".claude-plugin", true),
            (".claude-plugin/plugin.json", false),
            (".lsp.json", false),
            (".mcp.json", false),
            ("CHANGELOG.md", false),
            ("LICENSE", false),
            ("THIRD_PARTY_LICENSES.txt", false),
            (".third-party", true),
            (".third-party/third-party-license-policy.json", false),
            (".third-party/third-party-license-provenance.json", false),
            (".third-party/source-lock.spdx.json", false),
            (".third-party/source-closure-windows.spdx.json", false),
            ("skills", true),
            ("skills/autocad-mcp", true),
            ("skills/autocad-mcp/SKILL.md", false),
            ("skills/autolisp", true),
            ("skills/autolisp/SKILL.md", false),
            ("skills/autolisp/references", true),
            ("skills/autolisp/references/README.md", false),
            ("skills/autolisp/references/dcl", true),
            (
                "skills/autolisp/references/dcl/reference-dcl-summary.md",
                false,
            ),
            (
                "skills/autolisp/references/documentation-provenance.json",
                false,
            ),
            ("skills/autolisp/references/autolisp-lsp-index.json", false),
        ] {
            assert!(
                is_package_plugin_source_path(Path::new(path), is_directory),
                "expected package source path: {path}"
            );
        }

        for (path, is_directory) in [
            ("bin", true),
            ("bin/autocad-mcp", false),
            ("LICENSE/private.txt", false),
            ("THIRD_PARTY_LICENSES.txt/private.txt", false),
            (
                ".third-party/third-party-license-policy.json/private.txt",
                false,
            ),
            (
                ".third-party/third-party-license-provenance.json/private.txt",
                false,
            ),
            (".third-party/source-lock.spdx.json/private.txt", false),
            (
                ".third-party/source-closure-windows.spdx.json/private.txt",
                false,
            ),
            (".third-party/license-supplements", true),
            (
                ".third-party/license-supplements/rmcp-1.7.0-LICENSE.txt",
                false,
            ),
            (".third-party/private.json", false),
            (".third-party/private", true),
            (".third-party/private/secret.txt", false),
            ("dependency-license-policy.json", false),
            ("dependency-license-provenance.json", false),
            ("dependency-source-lock.spdx.json", false),
            ("dependency-windows-source-closure.spdx.json", false),
            ("dependency-license-supplements", true),
            (
                "dependency-license-supplements/rmcp-1.7.0-LICENSE.txt",
                false,
            ),
            ("owner-distribution-approval.json", false),
            ("owner-distribution-approval.schema.json", false),
            (".lsp.json/private.txt", false),
            (".mcp.json/private.txt", false),
            ("CHANGELOG.md/private.txt", false),
            ("private-material/secret.txt", false),
            ("scratch/notes.txt", false),
            (".claude-plugin/private.json", false),
            (".claude-plugin/nested", true),
            (".claude-plugin/nested/plugin.json", false),
            ("skills/private", true),
            ("skills/private/SKILL.md", false),
            ("skills/autocad-mcp/private.md", false),
            ("skills/autocad-mcp/references", true),
            ("skills/autolisp/private.md", false),
            ("skills/autolisp/references/private.json", false),
            (
                "skills/autolisp/references/dcl/documentation-provenance.json",
                false,
            ),
            (
                "skills/autolisp/references/DOCUMENTATION-PROVENANCE.JSON",
                false,
            ),
            ("skills/autolisp/references/dcl/private.json", false),
            (
                "skills/autolisp/references/dcl/autolisp-lsp-index.json",
                false,
            ),
            ("skills/autolisp/references/notes.MD", false),
            ("skills/.DS_Store", false),
            ("skills/autocad-mcp/.gitignore", false),
        ] {
            assert!(
                !is_package_plugin_source_path(Path::new(path), is_directory),
                "unexpected package source path: {path}"
            );
        }
    }

    #[test]
    fn package_rejects_empty_plugin_license() {
        let fixture = fake_plugin();
        write_file(&fixture.path().join("plugin/LICENSE"), "");
        let binary = fixture.path().join("autocad-mcp");
        write_file(&binary, "fake binary\n");

        let error = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: None,
            out_dir: fixture.path().join("dist"),
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("plugin LICENSE must be nonempty"),
            "got: {error:#}"
        );
    }

    #[test]
    fn package_rejects_noncanonical_plugin_license() {
        let fixture = fake_plugin();
        write_file(&fixture.path().join("plugin/LICENSE"), "license\n");
        let binary = fixture.path().join("autocad-mcp");
        write_file(&binary, "fake binary\n");

        let error = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: None,
            out_dir: fixture.path().join("dist"),
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("must match the canonical repository GPLv3 text"),
            "got: {error:#}"
        );
    }

    #[test]
    fn package_rejects_autolisp_documentation_without_provenance_ledger() {
        let fixture = fake_plugin();
        std::fs::remove_file(
            fixture
                .path()
                .join("plugin/skills/autolisp/references/documentation-provenance.json"),
        )
        .unwrap();
        let binary = fixture.path().join("autocad-mcp");
        write_file(&binary, "fake binary\n");

        let error = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: None,
            out_dir: fixture.path().join("dist"),
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("missing required plugin source file: skills/autolisp/references/documentation-provenance.json"),
            "got: {error:#}"
        );
    }

    #[test]
    fn package_rejects_missing_autolisp_skill_directory() {
        let fixture = fake_plugin();
        std::fs::remove_dir_all(fixture.path().join("plugin/skills/autolisp")).unwrap();
        let binary = fixture.path().join("autocad-mcp");
        write_file(&binary, "fake binary\n");

        let error = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: None,
            out_dir: fixture.path().join("dist"),
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("missing required plugin source file: skills/autolisp/SKILL.md"),
            "got: {error:#}"
        );
    }

    #[test]
    fn package_rejects_reference_bytes_drifted_from_provenance_ledger() {
        let fixture = fake_plugin();
        write_file(
            &fixture
                .path()
                .join("plugin/skills/autolisp/references/guide.md"),
            "# Tampered guide\n",
        );
        let binary = fixture.path().join("autocad-mcp");
        write_file(&binary, "fake binary\n");

        let error = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: None,
            out_dir: fixture.path().join("dist"),
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("artifact \"references/guide.md\" byte digest mismatch"),
            "got: {error:#}"
        );
    }

    #[test]
    fn archive_rejects_gitignore_at_any_depth() {
        let fixture = tempfile::tempdir().unwrap();
        let staging = fixture.path().join("staging");
        write_file(&staging.join("manifest.json"), "{}\n");
        write_file(&staging.join("plugin/skills/autocad-mcp/.GITIGNORE"), "*\n");

        let error = write_mcpb_archive(&staging, &fixture.path().join("out.mcpb")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must not contain a .gitignore path"),
            "got: {error:#}"
        );
    }

    fn read_zip_file(path: &std::path::Path, name: &str) -> String {
        String::from_utf8(read_zip_bytes(path, name)).unwrap()
    }

    fn read_zip_bytes(path: &std::path::Path, name: &str) -> Vec<u8> {
        let file = std::fs::File::open(path).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        let mut file = archive.by_name(name).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn xref_inventory_uses_canonical_registry_order_and_rejects_order_drift() {
        let canonical = XREF_MUTATION_OPERATIONS.to_vec();
        let listed = canonical
            .iter()
            .map(|operation| operation.as_str().to_owned())
            .collect::<Vec<_>>();
        validate_xref_mutation_inventory(&canonical, &listed).unwrap();

        let mut reported_drift = canonical.clone();
        reported_drift.swap(0, 1);
        let error = validate_xref_mutation_inventory(&reported_drift, &listed).unwrap_err();
        assert!(
            error.to_string().contains("canonical registry order"),
            "got: {error:#}"
        );

        let mut listed_drift = listed;
        listed_drift.swap(0, 1);
        let error = validate_xref_mutation_inventory(&canonical, &listed_drift).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("list-tools XREF mutation inventory/order"),
            "got: {error:#}"
        );
    }

    #[test]
    fn certification_info_schema_v4_accepts_valid_release_and_preview_roots() {
        for experimental_support in [false, true] {
            let value = valid_certification_info(experimental_support);
            let parsed =
                parse_binary_xref_certification_info(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(parsed.schema_version, 4);
            assert_eq!(parsed.experimental_support, experimental_support);
            assert_eq!(
                parsed.xref_mutation_tools,
                XREF_MUTATION_OPERATIONS.as_slice()
            );
        }
    }

    #[test]
    fn certification_info_schema_v4_rejects_unknown_root_field() {
        let mut value = valid_certification_info(false);
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), Value::Bool(true));

        let error =
            parse_binary_xref_certification_info(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("unknown field `unexpected`"), "{error}");
    }

    #[test]
    fn certification_info_schema_v4_rejects_missing_required_nullable_field() {
        let mut value = valid_certification_info(false);
        value
            .as_object_mut()
            .unwrap()
            .remove("certified_arg_policy_id");

        let error =
            parse_binary_xref_certification_info(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        let error = format!("{error:#}");
        assert!(
            error.contains("missing field `certified_arg_policy_id`"),
            "{error}"
        );
    }

    #[test]
    fn certification_info_schema_v4_requires_and_binds_activation_catalogue_digest() {
        let mut missing = valid_certification_info(false);
        missing
            .as_object_mut()
            .unwrap()
            .remove("activation_catalogue_sha256");
        let error = parse_binary_xref_certification_info(&serde_json::to_vec(&missing).unwrap())
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("missing field `activation_catalogue_sha256`"),
            "got: {error:#}"
        );

        for (mode, experimental_support) in
            [(PackageMode::Release, false), (PackageMode::Preview, true)]
        {
            let mut mismatched = valid_certification_info(experimental_support);
            mismatched["activation_catalogue_sha256"] = Value::String("0".repeat(64));
            let parsed =
                parse_binary_xref_certification_info(&serde_json::to_vec(&mismatched).unwrap())
                    .unwrap();
            let error = validate_binary_package_mode(&parsed, mode).unwrap_err();
            assert!(
                error.to_string().contains("activation_catalogue_sha256"),
                "got: {error:#}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn staged_binary_introspection_accepts_canonical_order_and_rejects_drift() {
        use std::os::unix::fs::PermissionsExt;

        fn write_introspection_binary(path: &Path, inventory: &[&str], listed_tools: &[&str]) {
            let mut info = valid_certification_info(false);
            info["xref_mutation_tools"] = serde_json::json!(inventory);
            let tools = listed_tools
                .iter()
                .map(|name| serde_json::json!({"name": name}))
                .collect::<Vec<_>>();
            let script = format!(
                "#!/bin/sh\ncase \"$1\" in\n  xref-certification-info) printf '%s\\n' '{}' ;;\n  list-tools) [ \"$2\" = \"--experimental\" ] && exit 2; printf '%s\\n' '{}' ;;\n  *) exit 1 ;;\nesac\n",
                serde_json::to_string(&info).unwrap(),
                serde_json::to_string(&tools).unwrap(),
            );
            write_file(path, &script);
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).unwrap();
        }

        let fixture = tempfile::tempdir().unwrap();
        let binary = fixture.path().join("staging/plugin/bin/autocad-mcp.exe");
        let canonical = XREF_MUTATION_OPERATIONS.map(XrefMutationOperation::as_str);
        write_introspection_binary(&binary, &canonical, &canonical);
        inspect_staged_binary(&binary, PackageMode::Release).unwrap();

        let mut drifted = canonical;
        drifted.swap(0, 1);
        write_introspection_binary(&binary, &drifted, &canonical);
        let error = inspect_staged_binary(&binary, PackageMode::Release).unwrap_err();
        assert!(
            error.to_string().contains("canonical registry order"),
            "got: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn macos_release_package_accepts_release_flavor_binary() {
        let fixture = fake_plugin();
        let plugin = fixture.path().join("plugin");
        advertise_xref_mutations(&plugin);
        let binary = fixture.path().join("autocad-mcp-release");
        write_mode_introspection_binary(&binary, false);

        let package = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: plugin,
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: None,
            out_dir: fixture.path().join("dist"),
        })
        .unwrap();

        assert_eq!(
            package.file_name().and_then(|name| name.to_str()),
            Some("autocad-mcp-macos-arm64.mcpb")
        );
        let manifest: Value =
            serde_json::from_slice(&read_zip_bytes(&package, "manifest.json")).unwrap();
        assert_eq!(
            manifest["server"]["mcp_config"]["args"],
            serde_json::json!(["serve"])
        );
        assert!(manifest.get("_meta").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn macos_release_package_rejects_preview_flavor_binary() {
        let fixture = fake_plugin();
        let plugin = fixture.path().join("plugin");
        advertise_xref_mutations(&plugin);
        let binary = fixture.path().join("autocad-mcp-preview");
        write_mode_introspection_binary(&binary, true);
        let out_dir = fixture.path().join("dist");

        let error = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: plugin,
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: None,
            out_dir: out_dir.clone(),
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Release packaging requires experimental_support=false"),
            "{error:#}"
        );
        assert!(
            !out_dir.join("autocad-mcp-macos-arm64.mcpb").exists(),
            "Preview flavor must not produce an unmarked macOS Release package"
        );
    }

    #[cfg(unix)]
    #[test]
    fn windows_preview_package_is_visibly_distinct_public_bound_and_static_smokes() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = fake_plugin();
        write_file(
            &fixture.path().join("plugin/skills/autocad-mcp/SKILL.md"),
            "---\nname: autocad-mcp\ndescription: Test skill\n---\n# Test\n\nUse attach_xref.\n",
        );
        write_file(
            &fixture.path().join("plugin/.lsp.json"),
            r#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp","args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"stdio"}}"#,
        );
        let activation_files = embedded_preview_activation_files().unwrap();
        let canonical = XREF_MUTATION_OPERATIONS.map(XrefMutationOperation::as_str);
        let info = valid_certification_info(true);
        let plain_tools = (0..PREVIEW_READ_ONLY_TOOL_COUNT)
            .map(|index| {
                serde_json::json!({
                    "name": format!("read_only_{index}"),
                    "annotations": {"readOnlyHint": true}
                })
            })
            .collect::<Vec<_>>();
        let experimental_tools = canonical
            .iter()
            .map(|name| serde_json::json!({"name": name}))
            .collect::<Vec<_>>();
        let binary = fixture.path().join("autocad-mcp-preview");
        let lsp_binary = fixture.path().join("autolisp-lsp.exe");
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\n  xref-certification-info) printf '%s\\n' '{}' ;;\n  list-tools) if [ \"$2\" = \"--experimental\" ]; then printf '%s\\n' '{}'; else printf '%s\\n' '{}'; fi ;;\n  *) exit 2 ;;\nesac\n",
            serde_json::to_string(&info).unwrap(),
            serde_json::to_string(&experimental_tools).unwrap(),
            serde_json::to_string(&plain_tools).unwrap(),
        );
        write_file(&binary, &script);
        let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&binary, permissions).unwrap();
        write_file(&lsp_binary, "fake Preview LSP binary\n");

        let package = create_package(PackageOptions {
            mode: PackageMode::Preview,
            target: PackageTarget::WindowsX64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: Some(lsp_binary),
            out_dir: fixture.path().join("dist"),
        })
        .unwrap();

        assert_eq!(
            package.file_name().and_then(|name| name.to_str()),
            Some("autocad-mcp-windows-x64-preview.mcpb")
        );
        let names = zip_names(&package);
        for required in [
            "plugin/bin/autolisp-lsp.exe",
            PREVIEW_ACTIVATION_CATALOGUE_PACKAGE_PATH,
            PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH,
        ] {
            assert!(names.iter().any(|name| name == required), "{names:?}");
        }
        for relative_path in activation_files.keys() {
            let package_path = format!("{PREVIEW_ACTIVATION_DIRECTORY}/{relative_path}");
            assert!(names.iter().any(|name| name == &package_path), "{names:?}");
        }
        assert!(
            !names
                .iter()
                .any(|name| name.starts_with("plugin/resources/xref-certification/")),
            "{names:?}"
        );

        let manifest: Value =
            serde_json::from_slice(&read_zip_bytes(&package, "manifest.json")).unwrap();
        assert_eq!(manifest["name"], "autocad-mcp-preview");
        assert_eq!(
            manifest["description"],
            "A rust-backed AutoLISP MCP (Preview)"
        );
        assert_eq!(
            manifest["server"]["mcp_config"]["args"],
            serde_json::json!(["serve", "--experimental"])
        );
        assert_eq!(
            manifest["_meta"][crate::manifest::PREVIEW_METADATA_NAMESPACE]
                [crate::manifest::PREVIEW_PACKAGE_MODE_META_KEY],
            "preview"
        );
        assert!(
            manifest["_meta"][crate::manifest::PREVIEW_METADATA_NAMESPACE].is_object(),
            "the packaged MCPB must use an object-valued reverse-DNS metadata namespace"
        );
        assert_eq!(
            manifest["server"]["mcp_config"]["env"],
            Value::Object(crate::manifest::title_block_profiles_environment())
        );
        let lsp_config: Value =
            serde_json::from_slice(&read_zip_bytes(&package, "plugin/.lsp.json")).unwrap();
        assert_eq!(
            lsp_config["autolisp-lsp"]["command"],
            "${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp.exe"
        );

        let binding: PreviewActivationPackageBinding = serde_json::from_slice(&read_zip_bytes(
            &package,
            PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH,
        ))
        .unwrap();
        assert_eq!(
            binding.schema_version,
            PREVIEW_ACTIVATION_BINDING_SCHEMA_VERSION
        );
        assert_eq!(
            binding.preview_binary_sha256,
            autocad_mcp::certification::xref_sha256_bytes(&read_zip_bytes(
                &package,
                "plugin/bin/autocad-mcp.exe"
            ))
        );
        assert_eq!(
            binding.catalogue_sha256,
            autocad_mcp::certification::xref_sha256_bytes(
                activation_files
                    .get("autocad-activation-catalogue.json")
                    .unwrap()
            )
        );
        assert_eq!(
            binding.files,
            activation_files
                .iter()
                .map(|(path, bytes)| PreviewActivationFileBinding {
                    path: path.clone(),
                    sha256: autocad_mcp::certification::xref_sha256_bytes(bytes),
                })
                .collect::<Vec<_>>()
        );

        let report = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap();
        assert!(!report.executable_ran);
        assert!(!report.lsp_executable_ran);
    }

    #[test]
    fn package_mode_inputs_enforce_preview_target_and_release_closure() {
        let fixture = fake_plugin();
        let mut options = PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::WindowsX64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: fixture.path().join("binary"),
            lsp_binary_path: None,
            out_dir: fixture.path().join("dist"),
        };
        let error = validate_package_mode_inputs(&options).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Windows Release packaging is unavailable"),
            "{error:#}"
        );

        options.mode = PackageMode::Preview;
        validate_package_mode_inputs(&options).unwrap();

        options.target = PackageTarget::MacosArm64;
        let error = validate_package_mode_inputs(&options).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Preview packaging requires target windows-x64"),
            "{error:#}"
        );
    }

    #[test]
    fn macos_package_contains_manifest_plugin_contents_and_binary() {
        let fixture = fake_plugin();
        let binary = fixture.path().join("autocad-mcp");
        std::fs::write(&binary, "fake binary\n").unwrap();
        let out_dir = fixture.path().join("dist");

        let package = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: None,
            out_dir,
        })
        .unwrap();

        assert_eq!(package.file_name().unwrap(), "autocad-mcp-macos-arm64.mcpb");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&package).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
        let names = zip_names(&package);
        assert_eq!(
            names,
            [
                "manifest.json",
                "plugin/.claude-plugin/plugin.json",
                "plugin/.mcp.json",
                "plugin/.third-party/source-closure-windows.spdx.json",
                "plugin/.third-party/source-lock.spdx.json",
                "plugin/.third-party/third-party-license-policy.json",
                "plugin/.third-party/third-party-license-provenance.json",
                "plugin/CHANGELOG.md",
                "plugin/LICENSE",
                "plugin/THIRD_PARTY_LICENSES.txt",
                "plugin/bin/autocad-mcp",
                "plugin/owner-distribution-approval.schema.json",
                "plugin/skills/autocad-mcp/SKILL.md",
                "plugin/skills/autolisp/SKILL.md",
                "plugin/skills/autolisp/references/autolisp-lsp-index.json",
                "plugin/skills/autolisp/references/dcl/guide.md",
                "plugin/skills/autolisp/references/documentation-provenance.json",
                "plugin/skills/autolisp/references/guide.md",
            ]
            .map(str::to_owned)
        );

        let manifest = read_zip_file(&package, "manifest.json");
        let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(manifest["license"], "GPL-3.0-or-later");
        assert_eq!(
            read_zip_file(&package, "plugin/LICENSE").as_bytes(),
            PROJECT_LICENSE_TEXT
        );
        assert_eq!(
            read_zip_file(
                &package,
                "plugin/.third-party/third-party-license-policy.json"
            )
            .as_bytes(),
            THIRD_PARTY_LICENSE_POLICY
        );
        assert_eq!(
            read_zip_file(&package, "plugin/.third-party/source-lock.spdx.json").as_bytes(),
            SOURCE_LOCK_SBOM
        );
        assert_eq!(
            read_zip_file(
                &package,
                "plugin/.third-party/source-closure-windows.spdx.json"
            )
            .as_bytes(),
            WINDOWS_SOURCE_CLOSURE_SBOM
        );
        assert_eq!(
            read_zip_file(
                &package,
                "plugin/.third-party/third-party-license-provenance.json"
            )
            .as_bytes(),
            THIRD_PARTY_LICENSE_PROVENANCE
        );
        assert_eq!(
            read_zip_file(&package, "plugin/owner-distribution-approval.schema.json").as_bytes(),
            OWNER_DISTRIBUTION_APPROVAL_SCHEMA
        );
        assert_eq!(
            read_zip_file(&package, "plugin/THIRD_PARTY_LICENSES.txt").as_bytes(),
            THIRD_PARTY_LICENSES
        );
        assert_eq!(manifest["server"]["type"], "binary");
        assert_eq!(
            manifest["server"]["mcp_config"]["args"],
            serde_json::json!(["serve"])
        );
        assert_eq!(
            manifest["compatibility"]["platforms"],
            serde_json::json!(["darwin"])
        );
    }

    #[cfg(unix)]
    #[test]
    fn macos_package_without_lsp_binary_omits_lsp_config_and_static_smokes() {
        let fixture = tempfile::tempdir().unwrap();
        let binary = fixture.path().join("autocad-mcp");
        write_mode_introspection_binary(&binary, false);

        let package = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: repo_root().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: None,
            out_dir: fixture.path().join("dist"),
        })
        .unwrap();

        let names = zip_names(&package);
        assert!(
            !names.contains(&"plugin/.lsp.json".to_string()),
            "{names:?}"
        );
        let report = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap();
        assert!(!report.executable_ran);
        assert!(!report.lsp_executable_ran);
    }

    #[test]
    fn macos_package_stages_lsp_binary_when_supplied() {
        let fixture = fake_plugin();
        write_file(
            &fixture.path().join("plugin/.lsp.json"),
            r#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp","args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"stdio"}}"#,
        );
        let binary = fixture.path().join("autocad-mcp");
        let lsp_binary = fixture.path().join("autolisp-lsp");
        std::fs::write(&binary, "fake binary\n").unwrap();
        std::fs::write(&lsp_binary, "fake lsp\n").unwrap();

        let package = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: Some(lsp_binary),
            out_dir: fixture.path().join("dist"),
        })
        .unwrap();

        let names = zip_names(&package);
        assert!(names.contains(&"plugin/.lsp.json".to_string()), "{names:?}");
        assert!(
            names.contains(&"plugin/bin/autolisp-lsp".to_string()),
            "{names:?}"
        );
        let lsp_json = read_zip_file(&package, "plugin/.lsp.json");
        let lsp_json: serde_json::Value = serde_json::from_str(&lsp_json).unwrap();
        assert_eq!(
            lsp_json["autolisp-lsp"]["command"],
            "${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp"
        );
    }

    #[test]
    fn package_rejects_lsp_binary_without_lsp_config() {
        let fixture = fake_plugin();
        let binary = fixture.path().join("autocad-mcp");
        let lsp_binary = fixture.path().join("autolisp-lsp");
        std::fs::write(&binary, "fake binary\n").unwrap();
        std::fs::write(&lsp_binary, "fake lsp\n").unwrap();

        let err = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: Some(lsp_binary),
            out_dir: fixture.path().join("dist"),
        })
        .unwrap_err();

        assert!(err.to_string().contains("plugin/.lsp.json"), "got: {err:#}");
    }

    #[test]
    fn package_rejects_missing_lsp_binary_when_supplied() {
        let fixture = fake_plugin();
        let binary = fixture.path().join("autocad-mcp");
        std::fs::write(&binary, "fake binary\n").unwrap();

        let err = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: Some(fixture.path().join("missing-autolisp-lsp")),
            out_dir: fixture.path().join("dist"),
        })
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("LSP release binary does not exist"),
            "got: {err:#}"
        );
    }

    #[test]
    fn windows_release_package_creation_fails_closed_before_staging() {
        let fixture = fake_plugin();
        let binary = fixture.path().join("autocad-mcp.exe");
        std::fs::write(&binary, "fake binary\n").unwrap();
        let out_dir = fixture.path().join("dist");
        let error = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::WindowsX64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: None,
            out_dir: out_dir.clone(),
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Windows Release packaging is unavailable"),
            "{error:#}"
        );
        assert!(
            !out_dir.exists(),
            "fail-closed Windows Release validation must precede staging"
        );
    }

    fn repo_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .find(|candidate| {
                std::fs::read_to_string(candidate.join("Cargo.toml"))
                    .map(|manifest| manifest.lines().any(|line| line.trim() == "[workspace]"))
                    .unwrap_or(false)
            })
            .expect("release-packager must be contained by a Cargo workspace")
            .to_path_buf()
    }

    #[cfg(unix)]
    #[test]
    fn package_fails_when_plugin_tree_cannot_be_fully_walked() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = fake_plugin();
        let binary = fixture.path().join("autocad-mcp");
        std::fs::write(&binary, "fake binary\n").unwrap();
        let restricted = fixture
            .path()
            .join("plugin/skills/autolisp/references/restricted");
        write_file(&restricted.join("local.txt"), "local\n");

        let original_permissions = std::fs::metadata(&restricted).unwrap().permissions();
        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: None,
            out_dir: fixture.path().join("dist"),
        });
        std::fs::set_permissions(&restricted, original_permissions).unwrap();

        let err = result.unwrap_err();
        assert!(err.to_string().contains("walk"), "got: {err:#}");
    }

    #[cfg(unix)]
    #[test]
    fn archive_fails_when_staging_tree_cannot_be_fully_walked() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let staging_root = dir.path().join("staging");
        write_file(&staging_root.join("manifest.json"), "{}\n");
        write_file(
            &staging_root.join("plugin/bin/autocad-mcp"),
            "fake binary\n",
        );
        let restricted = staging_root.join("plugin/skills/autocad-mcp/references/restricted");
        write_file(&restricted.join("local.txt"), "local\n");

        let original_permissions = std::fs::metadata(&restricted).unwrap().permissions();
        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = write_mcpb_archive(&staging_root, &dir.path().join("out.mcpb"));
        std::fs::set_permissions(&restricted, original_permissions).unwrap();

        let err = result.unwrap_err();
        assert!(err.to_string().contains("walk"), "got: {err:#}");
    }

    #[cfg(unix)]
    #[test]
    fn package_does_not_traverse_unlisted_plugin_roots() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = fake_plugin();
        let binary = fixture.path().join("autocad-mcp");
        std::fs::write(&binary, "fake binary\n").unwrap();
        let restricted = fixture.path().join("plugin/private-material/restricted");
        write_file(&restricted.join("local.txt"), "local\n");

        let original_permissions = std::fs::metadata(&restricted).unwrap().permissions();
        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o000)).unwrap();
        let package = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: None,
            out_dir: fixture.path().join("dist"),
        });
        std::fs::set_permissions(&restricted, original_permissions).unwrap();

        let package = package.unwrap();
        let names = zip_names(&package);
        assert!(
            !names
                .iter()
                .any(|name| name.starts_with("plugin/private-material/")),
            "{names:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn package_does_not_traverse_unlisted_nested_plugin_paths() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = fake_plugin();
        let binary = fixture.path().join("autocad-mcp");
        std::fs::write(&binary, "fake binary\n").unwrap();
        let restricted = fixture
            .path()
            .join("plugin/skills/autocad-mcp/references/restricted");
        write_file(&restricted.join("local.md"), "local\n");

        let original_permissions = std::fs::metadata(&restricted).unwrap().permissions();
        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o000)).unwrap();
        let package = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: fixture.path().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: None,
            out_dir: fixture.path().join("dist"),
        });
        std::fs::set_permissions(&restricted, original_permissions).unwrap();

        let package = package.unwrap();
        let names = zip_names(&package);
        assert!(
            !names
                .iter()
                .any(|name| name.starts_with("plugin/skills/autocad-mcp/references/")),
            "{names:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn archive_failure_does_not_replace_existing_package() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let staging_root = dir.path().join("staging");
        let package_path = dir.path().join("out.mcpb");
        write_file(&staging_root.join("manifest.json"), "{}\n");
        write_file(
            &staging_root.join("plugin/bin/autocad-mcp"),
            "fake binary\n",
        );
        std::fs::write(&package_path, "existing package\n").unwrap();
        let restricted = staging_root.join("plugin/skills/autocad-mcp/references/restricted");
        write_file(&restricted.join("local.txt"), "local\n");

        let original_permissions = std::fs::metadata(&restricted).unwrap().permissions();
        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = write_mcpb_archive(&staging_root, &package_path);
        std::fs::set_permissions(&restricted, original_permissions).unwrap();

        let err = result.unwrap_err();
        assert!(err.to_string().contains("walk"), "got: {err:#}");
        assert_eq!(
            std::fs::read_to_string(&package_path).unwrap(),
            "existing package\n"
        );
    }
}
