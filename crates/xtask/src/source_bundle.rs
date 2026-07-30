use distribution_approval::{
    render_windows_x86_64_build_recipe, DistributionMode, GitObjectFormat,
    SourceBundleArchivePolicy as ArchivePolicyManifest, SourceBundleExclusion as ExclusionManifest,
    SourceBundleFile as FileManifest, SourceBundleManifest, SourceBundlePackage as PackageManifest,
    SourceBundleRoot as RootManifest, SourceBundleTree as TreeManifest,
    SourceBundleVendor as VendorManifest, SOURCE_BUNDLE_ARTIFACT_KIND,
    SOURCE_BUNDLE_BUILD_RECIPE_PATH as BUILD_INSTRUCTIONS_PATH,
    SOURCE_BUNDLE_MANIFEST_PATH as MANIFEST_PATH, SOURCE_BUNDLE_MANIFEST_SCHEMA_VERSION,
    SOURCE_BUNDLE_OFFLINE_CONFIG_PATH as OFFLINE_CONFIG_PATH, SOURCE_BUNDLE_PROFILE,
    SOURCE_BUNDLE_TREE_DIGEST_METHOD, WINDOWS_X86_64_TARGET as WINDOWS_TARGET,
};
use flate2::read::MultiGzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

const REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const THIRD_PARTY_LICENSE_POLICY_PATH: &str = "plugin/.third-party/third-party-license-policy.json";
const RUST_TOOLCHAIN_PATH: &str = "rust-toolchain.toml";
const MAX_CRATE_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_UNPACKED_CRATE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_WINDOWS_RELATIVE_PATH_BYTES: usize = 240;
const MAX_WINDOWS_COMPONENT_BYTES: usize = 200;
const ALLOWED_REPOSITORY_CARGO_CONFIG: &[u8] = b"[build]\nincremental = false\n";
const ALLOWED_COMMON_CHECKOUT_CARGO_CONFIG: &[u8] =
    b"[build]\ntarget-dir = \".cargo-target\"\nincremental = false\n";
const ZIP_UTF8_FLAG: u16 = 0x0800;
const ZIP_DOS_TIME: u16 = 0;
const ZIP_DOS_DATE: u16 = 0x0021;

const ROOTS: [RootSpec; 2] = [
    RootSpec {
        name: "autocad-mcp",
        manifest_path: "crates/autocad-mcp/Cargo.toml",
        no_default_features: true,
    },
    RootSpec {
        name: "autolisp-lsp",
        manifest_path: "crates/autolisp-lsp/Cargo.toml",
        no_default_features: false,
    },
];

const ALLOWED_WORKSPACE_PACKAGES: [(&str, &str); 5] = [
    ("autocad-mcp", "crates/autocad-mcp/Cargo.toml"),
    ("autocad-reader", "crates/autocad-reader/Cargo.toml"),
    ("autocad-writer", "crates/autocad-writer/Cargo.toml"),
    ("autolisp-lsp", "crates/autolisp-lsp/Cargo.toml"),
    ("autolisp-validate", "crates/autolisp-validate/Cargo.toml"),
];

const DENY_RULES: [DenyRule; 2] = [
    DenyRule {
        package: "acadrust",
        version: "0.4.1",
        relative_path: "src/docs/OpenDesign_Specification_for_.dwg_files.pdf",
        expected_bytes: 2_399_640,
        expected_sha256: "1ed2e02722862188120da606e4b6a816fa4014c96de68da2f84a2ecda09461e7",
        reason: "excluded non-source third-party specification PDF from target source bundle",
    },
    DenyRule {
        package: "flate2",
        version: "1.1.9",
        relative_path: "tests/corrupt-gz-file.bin",
        expected_bytes: 7_128,
        expected_sha256: "083dd284aa1621916a2d0f66ea048c8d3ba7a722b22d0d618722633f51e7d39c",
        reason: "excluded non-source binary corruption test fixture from target source bundle",
    },
];

#[derive(Debug, Serialize)]
pub struct SourceBundleSummary {
    pub output: PathBuf,
    pub git_object_format: String,
    pub source_commit: String,
    pub source_tree_oid: String,
    pub source_bundle_manifest_sha256: String,
    pub cargo_lock_sha256: String,
    pub dependency_input_closure_sha256: String,
    pub rust_toolchain_sha256: String,
    pub build_recipe_sha256: String,
    pub package_mode: DistributionMode,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub archive_entries: usize,
    pub closure_packages: usize,
    pub vendored_packages: usize,
    pub excluded_files: usize,
}

#[derive(Clone, Copy, Debug)]
struct RootSpec {
    name: &'static str,
    manifest_path: &'static str,
    no_default_features: bool,
}

#[derive(Clone, Copy)]
struct DenyRule {
    package: &'static str,
    version: &'static str,
    relative_path: &'static str,
    expected_bytes: usize,
    expected_sha256: &'static str,
    reason: &'static str,
}

#[derive(Clone, Debug)]
struct GitTreeEntry {
    path: String,
    object_id: String,
    mode: u32,
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<MetadataPackage>,
    resolve: MetadataResolve,
}

#[derive(Clone, Debug, Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
    manifest_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct MetadataResolve {
    root: Option<String>,
    nodes: Vec<MetadataNode>,
}

#[derive(Debug, Deserialize)]
struct MetadataNode {
    id: String,
    dependencies: Vec<String>,
    deps: Vec<MetadataDependency>,
}

#[derive(Clone, Debug, Deserialize)]
struct MetadataDependency {
    pkg: String,
    dep_kinds: Vec<MetadataDependencyKind>,
}

#[derive(Clone, Debug, Deserialize)]
struct MetadataDependencyKind {
    kind: Option<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PackageKey {
    name: String,
    version: String,
    source: Option<String>,
}

#[derive(Clone, Debug)]
struct LockPackage {
    checksum: Option<String>,
}

#[derive(Debug)]
struct RootClosure {
    spec: RootSpec,
    metadata_stdout: Vec<u8>,
    metadata: CargoMetadata,
    package_ids: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct IncludedPackage {
    metadata: MetadataPackage,
    scopes: BTreeSet<String>,
}

#[derive(Debug)]
struct TarEntry {
    relative_path: String,
    bytes: Vec<u8>,
    mode: u32,
}

#[derive(Clone, Debug)]
struct SourceFile {
    relative_path: String,
    bytes: Arc<[u8]>,
    mode: u32,
}

#[derive(Clone, Debug)]
struct PayloadEntry {
    bytes: Arc<[u8]>,
    mode: u32,
}

#[derive(Default)]
struct ArchiveEntries {
    entries: BTreeMap<String, PayloadEntry>,
    casefolded_paths: BTreeMap<String, String>,
}

#[derive(Debug)]
struct PreparedMode {
    closures: Vec<RootClosure>,
    included: BTreeMap<PackageKey, IncludedPackage>,
}

#[derive(Clone, Debug)]
struct PreparedVendorPackage {
    manifest: VendorManifest,
    files: Vec<SourceFile>,
    exclusions: Vec<ExclusionManifest>,
    encountered_deny_rules: BTreeSet<usize>,
    archived_manifest: Arc<[u8]>,
}

#[derive(Debug)]
pub(crate) struct PreparedSourceBundles {
    repository: PathBuf,
    git_object_format: String,
    source_commit: String,
    source_tree_oid: String,
    lock_sha256: String,
    lock_packages: BTreeMap<PackageKey, LockPackage>,
    dependency_input_closure_sha256: String,
    rust_toolchain_sha256: String,
    toolchain: String,
    workspace_files: Vec<SourceFile>,
    modes: BTreeMap<DistributionMode, PreparedMode>,
    vendors: BTreeMap<PackageKey, PreparedVendorPackage>,
}

#[derive(Serialize)]
struct CargoChecksum<'a> {
    files: &'a BTreeMap<String, String>,
    package: &'a str,
}

pub fn run(repository: &Path, out_file: &Path) -> Result<SourceBundleSummary, String> {
    run_for_mode(repository, out_file, DistributionMode::Release)
}

pub fn run_for_mode(
    repository: &Path,
    out_file: &Path,
    package_mode: DistributionMode,
) -> Result<SourceBundleSummary, String> {
    let prepared = prepare_for_modes(repository, &[package_mode])?;
    write_prepared_for_mode(&prepared, out_file, package_mode, true)
}

pub(crate) fn prepare_for_modes(
    repository: &Path,
    package_modes: &[DistributionMode],
) -> Result<PreparedSourceBundles, String> {
    if package_modes.is_empty() {
        return Err("source-bundle preparation requires at least one package mode".to_owned());
    }
    let requested_modes = package_modes.iter().copied().collect::<BTreeSet<_>>();
    if requested_modes.len() != package_modes.len() {
        return Err("source-bundle preparation repeats a package mode".to_owned());
    }

    let repository = canonical_repository(repository)?;
    ensure_clean_checkout(&repository)?;
    let source_commit = head_commit(&repository)?;
    let (git_object_format, source_tree_oid) = source_tree_identity(&repository, &source_commit)?;
    let tree = read_head_tree(&repository, &source_commit)?;
    let head_blobs = read_head_blobs(&repository, &tree)?;
    let lock_bytes = head_blobs
        .get("Cargo.lock")
        .ok_or_else(|| "clean HEAD has no Cargo.lock".to_owned())?;
    let lock_sha256 = sha256(lock_bytes);
    let lock_packages = parse_cargo_lock(lock_bytes)?;
    let dependency_input_closure_sha256 = reviewed_dependency_input_closure(
        head_blobs
            .get(THIRD_PARTY_LICENSE_POLICY_PATH)
            .ok_or_else(|| format!("clean HEAD has no {THIRD_PARTY_LICENSE_POLICY_PATH}"))?,
        &lock_sha256,
    )?;
    let rust_toolchain_bytes = head_blobs
        .get(RUST_TOOLCHAIN_PATH)
        .ok_or_else(|| format!("clean HEAD has no {RUST_TOOLCHAIN_PATH}"))?;
    let rust_toolchain_sha256 = sha256(rust_toolchain_bytes);
    let toolchain = rust_toolchain_channel(rust_toolchain_bytes)?;
    ensure_controlled_cargo_configuration(&repository)?;
    verify_exact_toolchain(&toolchain)?;

    let mut modes = BTreeMap::new();
    let mut union = BTreeMap::<PackageKey, IncludedPackage>::new();
    for package_mode in requested_modes {
        let mut closures = Vec::with_capacity(ROOTS.len());
        for spec in ROOTS {
            let (metadata_stdout, metadata) =
                cargo_metadata(&repository, &toolchain, spec, package_mode)?;
            validate_metadata_manifests(&repository, &head_blobs, &metadata)?;
            let package_ids = derive_closure(&metadata, spec)?;
            closures.push(RootClosure {
                spec,
                metadata_stdout,
                metadata,
                package_ids,
            });
        }
        let included = combine_closures(&closures)?;
        merge_mode_packages_into_union(&mut union, &included)?;
        modes.insert(package_mode, PreparedMode { closures, included });
    }

    let workspace_files = workspace_source_files(&tree, &head_blobs)?;
    let mut vendors = BTreeMap::new();
    for (key, package) in &union {
        if package_key(&package.metadata) != *key {
            return Err("source-bundle union package key is internally inconsistent".to_owned());
        }
        let lock = lock_packages.get(key).ok_or_else(|| {
            format!(
                "target closure package {} {} source {:?} is absent from Cargo.lock",
                key.name, key.version, key.source
            )
        })?;
        validate_package_source(&repository, &head_blobs, &package.metadata, lock)?;
        match package.metadata.source.as_deref() {
            Some(REGISTRY_SOURCE) => {
                let prepared = prepare_vendor_package(&package.metadata, lock)?;
                if vendors.insert(key.clone(), prepared).is_some() {
                    return Err(format!(
                        "source-bundle preparation repeats registry package {} {}",
                        package.metadata.name, package.metadata.version
                    ));
                }
            }
            None => {}
            Some(source) => {
                return Err(format!(
                    "target closure package {} {} uses unsupported source {source}",
                    package.metadata.name, package.metadata.version
                ))
            }
        };
    }
    verify_repository_identity(
        &repository,
        &git_object_format,
        &source_commit,
        &source_tree_oid,
        &toolchain,
    )?;

    Ok(PreparedSourceBundles {
        repository,
        git_object_format,
        source_commit,
        source_tree_oid,
        lock_sha256,
        lock_packages,
        dependency_input_closure_sha256,
        rust_toolchain_sha256,
        toolchain,
        workspace_files,
        modes,
        vendors,
    })
}

pub(crate) fn write_prepared_for_mode(
    prepared: &PreparedSourceBundles,
    out_file: &Path,
    package_mode: DistributionMode,
    durable_output: bool,
) -> Result<SourceBundleSummary, String> {
    let mode = prepared.modes.get(&package_mode).ok_or_else(|| {
        format!(
            "source-bundle preparation did not include {} mode",
            package_mode.as_str()
        )
    })?;
    verify_repository_identity(
        &prepared.repository,
        &prepared.git_object_format,
        &prepared.source_commit,
        &prepared.source_tree_oid,
        &prepared.toolchain,
    )?;

    let mut archive = ArchiveEntries::default();
    let workspace = TreeManifest {
        path: "workspace".to_owned(),
        file_count: prepared.workspace_files.len(),
        tree_sha256: tree_digest(&prepared.workspace_files),
        digest_method: SOURCE_BUNDLE_TREE_DIGEST_METHOD.to_owned(),
    };
    for file in &prepared.workspace_files {
        archive.insert(
            format!("workspace/{}", file.relative_path),
            Arc::clone(&file.bytes),
            file.mode,
        )?;
    }

    let mut package_manifests = Vec::with_capacity(mode.included.len());
    let mut exclusions = Vec::new();
    let mut encountered_deny_rules = BTreeSet::new();
    for (key, package) in &mode.included {
        let lock = prepared.lock_packages.get(key).ok_or_else(|| {
            format!(
                "prepared target closure package {} {} source {:?} is absent from Cargo.lock",
                key.name, key.version, key.source
            )
        })?;
        let vendor = match package.metadata.source.as_deref() {
            Some(REGISTRY_SOURCE) => {
                let prepared_vendor = prepared.vendors.get(key).ok_or_else(|| {
                    format!(
                        "prepared registry package {} {} is absent",
                        package.metadata.name, package.metadata.version
                    )
                })?;
                validate_prepared_vendor_manifest(&package.metadata, prepared_vendor)?;
                apply_prepared_vendor(
                    prepared_vendor,
                    &mut archive,
                    &mut exclusions,
                    &mut encountered_deny_rules,
                )?;
                Some(prepared_vendor.manifest.clone())
            }
            None => None,
            Some(source) => {
                return Err(format!(
                    "prepared package {} {} uses unsupported source {source}",
                    package.metadata.name, package.metadata.version
                ))
            }
        };
        package_manifests.push(PackageManifest {
            name: package.metadata.name.clone(),
            version: package.metadata.version.clone(),
            source: package
                .metadata
                .source
                .clone()
                .unwrap_or_else(|| "workspace".to_owned()),
            cargo_lock_checksum: lock.checksum.clone(),
            roots: package.scopes.iter().cloned().collect(),
            vendor,
        });
    }
    package_manifests.sort_by(|left, right| {
        (&left.name, &left.version, &left.source).cmp(&(&right.name, &right.version, &right.source))
    });
    validate_denylist_coverage(&mode.included, &encountered_deny_rules)?;
    exclusions.sort();

    let offline_config = offline_cargo_config();
    let recipe_object_format = match prepared.git_object_format.as_str() {
        "sha1" => GitObjectFormat::Sha1,
        "sha256" => GitObjectFormat::Sha256,
        other => {
            return Err(format!(
                "cannot render Windows build recipe for unsupported Git object format {other:?}"
            ))
        }
    };
    let build_instructions = render_windows_x86_64_build_recipe(
        &prepared.toolchain,
        recipe_object_format,
        &prepared.source_commit,
        package_mode,
    )
    .map_err(|error| format!("render canonical Windows build recipe: {error}"))?;
    let build_recipe_sha256 = sha256(&build_instructions);
    let generated_files = vec![
        file_manifest(OFFLINE_CONFIG_PATH, &offline_config),
        file_manifest(BUILD_INSTRUCTIONS_PATH, &build_instructions),
    ];
    archive.insert(OFFLINE_CONFIG_PATH.to_owned(), offline_config, 0o644)?;
    archive.insert(
        BUILD_INSTRUCTIONS_PATH.to_owned(),
        build_instructions,
        0o644,
    )?;

    let root_manifests = root_manifests(&mode.closures, package_mode)?;
    let manifest = SourceBundleManifest {
        schema_version: SOURCE_BUNDLE_MANIFEST_SCHEMA_VERSION,
        artifact_kind: SOURCE_BUNDLE_ARTIFACT_KIND.to_owned(),
        git_object_format: recipe_object_format,
        source_commit: prepared.source_commit.clone(),
        source_tree_oid: prepared.source_tree_oid.clone(),
        cargo_lock_sha256: prepared.lock_sha256.clone(),
        dependency_input_closure_sha256: prepared.dependency_input_closure_sha256.clone(),
        rust_toolchain_sha256: prepared.rust_toolchain_sha256.clone(),
        build_recipe_sha256: build_recipe_sha256.clone(),
        rust_toolchain: prepared.toolchain.clone(),
        target: WINDOWS_TARGET.to_owned(),
        profile: SOURCE_BUNDLE_PROFILE.to_owned(),
        package_mode,
        cargo_incremental: false,
        roots: root_manifests,
        packages: package_manifests,
        workspace,
        generated_files,
        exclusions,
        archive_policy: ArchivePolicyManifest {
            format: "ZIP32".to_owned(),
            compression: "stored".to_owned(),
            entry_order: "ascending UTF-8 path".to_owned(),
            timestamp: "1980-01-01T00:00:00Z".to_owned(),
            regular_file_modes: ["0644".to_owned(), "0755".to_owned()],
            zip64: false,
        },
    };
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serialize source bundle manifest: {error}"))?;
    manifest_bytes.push(b'\n');
    let source_bundle_manifest_sha256 = sha256(&manifest_bytes);
    archive.insert(MANIFEST_PATH.to_owned(), manifest_bytes, 0o644)?;

    verify_repository_snapshot(
        &prepared.repository,
        &prepared.git_object_format,
        &prepared.source_commit,
        &prepared.source_tree_oid,
        &prepared.toolchain,
        &mode.closures,
        package_mode,
    )?;
    validate_output_location(&prepared.repository, out_file)?;
    let (archive_sha256, archive_bytes) =
        write_archive(out_file, &archive.entries, durable_output)?;
    if let Err(error) = verify_repository_snapshot(
        &prepared.repository,
        &prepared.git_object_format,
        &prepared.source_commit,
        &prepared.source_tree_oid,
        &prepared.toolchain,
        &mode.closures,
        package_mode,
    ) {
        return Err(remove_invalid_archive(out_file, error));
    }
    let vendored_packages = manifest
        .packages
        .iter()
        .filter(|package| package.vendor.is_some())
        .count();
    Ok(SourceBundleSummary {
        output: out_file.to_path_buf(),
        git_object_format: prepared.git_object_format.clone(),
        source_commit: prepared.source_commit.clone(),
        source_tree_oid: prepared.source_tree_oid.clone(),
        source_bundle_manifest_sha256,
        cargo_lock_sha256: prepared.lock_sha256.clone(),
        dependency_input_closure_sha256: prepared.dependency_input_closure_sha256.clone(),
        rust_toolchain_sha256: prepared.rust_toolchain_sha256.clone(),
        build_recipe_sha256,
        package_mode,
        archive_sha256,
        archive_bytes,
        archive_entries: archive.entries.len(),
        closure_packages: manifest.packages.len(),
        vendored_packages,
        excluded_files: manifest.exclusions.len(),
    })
}

fn merge_mode_packages_into_union(
    union: &mut BTreeMap<PackageKey, IncludedPackage>,
    included: &BTreeMap<PackageKey, IncludedPackage>,
) -> Result<(), String> {
    for (key, package) in included {
        match union.get_mut(key) {
            Some(existing) => {
                if existing.metadata.name != package.metadata.name
                    || existing.metadata.version != package.metadata.version
                    || existing.metadata.source != package.metadata.source
                    || existing.metadata.manifest_path != package.metadata.manifest_path
                {
                    return Err(format!(
                        "Release and Preview metadata disagree about package {} {}",
                        package.metadata.name, package.metadata.version
                    ));
                }
                existing.scopes.extend(package.scopes.iter().cloned());
            }
            None => {
                union.insert(key.clone(), package.clone());
            }
        }
    }
    Ok(())
}

fn canonical_repository(repository: &Path) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(repository)
        .map_err(|error| format!("inspect repository {}: {error}", repository.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "repository {} must be a real directory, not a symlink",
            repository.display()
        ));
    }
    let canonical = fs::canonicalize(repository)
        .map_err(|error| format!("canonicalize repository {}: {error}", repository.display()))?;
    let top_level = git_text(&canonical, &["rev-parse", "--show-toplevel"])?;
    let git_root = fs::canonicalize(top_level.trim())
        .map_err(|error| format!("canonicalize Git top level {}: {error}", top_level.trim()))?;
    if git_root != canonical {
        return Err(format!(
            "{} is not the Git worktree root {}",
            canonical.display(),
            git_root.display()
        ));
    }
    Ok(canonical)
}

fn git_command(repository: &Path) -> Command {
    #[cfg(windows)]
    const NULL_DEVICE: &str = "NUL";
    #[cfg(not(windows))]
    const NULL_DEVICE: &str = "/dev/null";

    let inherited_environment = [
        ("PATH", std::env::var_os("PATH")),
        ("SystemRoot", std::env::var_os("SystemRoot")),
        ("WINDIR", std::env::var_os("WINDIR")),
        ("TMPDIR", std::env::var_os("TMPDIR")),
        ("TMP", std::env::var_os("TMP")),
        ("TEMP", std::env::var_os("TEMP")),
    ];
    let mut command = Command::new("git");
    command.env_clear().current_dir(repository);
    for (name, value) in inherited_environment {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
    command
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", NULL_DEVICE)
        .env("GIT_CONFIG_GLOBAL", NULL_DEVICE)
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

fn git_bytes(repository: &Path, arguments: &[&str]) -> Result<Vec<u8>, String> {
    let output = git_command(repository)
        .args(arguments)
        .output()
        .map_err(|error| format!("launch git {}: {error}", arguments.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed with {}: {}",
            arguments.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

fn git_text(repository: &Path, arguments: &[&str]) -> Result<String, String> {
    let bytes = git_bytes(repository, arguments)?;
    String::from_utf8(bytes).map_err(|error| {
        format!(
            "git {} returned non-UTF-8 output: {error}",
            arguments.join(" ")
        )
    })
}

fn ensure_clean_checkout(repository: &Path) -> Result<(), String> {
    ensure_plain_index(repository)?;
    let status = git_bytes(
        repository,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    if status.is_empty() {
        ensure_plain_index(repository)?;
        return Ok(());
    }
    let paths = status
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .map(|record| String::from_utf8_lossy(record).into_owned())
        .collect::<Vec<_>>();
    Err(format!(
        "source bundling requires a clean checkout, including no untracked files:\n{}",
        paths.join("\n")
    ))
}

fn ensure_plain_index(repository: &Path) -> Result<(), String> {
    let records = git_bytes(repository, &["ls-files", "-v", "-z", "--"])?;
    for record in records
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if record.len() < 3 || record[0] != b'H' || record[1] != b' ' {
            return Err(
                "source bundling rejects assume-unchanged, skip-worktree, or nonordinary index state"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn head_commit(repository: &Path) -> Result<String, String> {
    let commit = git_text(repository, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let commit = commit.trim().to_owned();
    if !matches!(commit.len(), 40 | 64)
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("Git returned invalid HEAD object ID {commit:?}"));
    }
    Ok(commit)
}

fn source_tree_identity(
    repository: &Path,
    source_commit: &str,
) -> Result<(String, String), String> {
    let object_format = git_text(repository, &["rev-parse", "--show-object-format"])?
        .trim()
        .to_owned();
    let oid_length = match object_format.as_str() {
        "sha1" => 40,
        "sha256" => 64,
        other => return Err(format!("Git returned unsupported object format {other:?}")),
    };
    require_git_oid(source_commit, oid_length, "source commit")?;

    let tree_expression = format!("{source_commit}^{{tree}}");
    let tree_oid = git_text(
        repository,
        &["rev-parse", "--verify", tree_expression.as_str()],
    )?
    .trim()
    .to_owned();
    require_git_oid(&tree_oid, oid_length, "source tree")?;
    Ok((object_format, tree_oid))
}

fn require_git_oid(value: &str, expected_length: usize, context: &str) -> Result<(), String> {
    if value.len() == expected_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "{context} must be a {expected_length}-character lowercase Git object ID, got {value:?}"
        ))
    }
}

fn read_head_tree(repository: &Path, source_commit: &str) -> Result<Vec<GitTreeEntry>, String> {
    let output = git_bytes(
        repository,
        &["ls-tree", "-r", "-z", "--full-tree", source_commit],
    )?;
    let mut entries = Vec::new();
    let mut paths = BTreeSet::new();
    let mut casefolded = BTreeMap::new();
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| "git ls-tree record has no path delimiter".to_owned())?;
        let header = std::str::from_utf8(&record[..tab])
            .map_err(|error| format!("git ls-tree header is not UTF-8: {error}"))?;
        let path = std::str::from_utf8(&record[tab + 1..])
            .map_err(|error| format!("Git tree contains a non-UTF-8 path: {error}"))?
            .to_owned();
        validate_relative_path(&path, false)?;
        let mut fields = header.split_whitespace();
        let mode_text = fields
            .next()
            .ok_or_else(|| format!("git ls-tree record for {path} has no mode"))?;
        let object_type = fields
            .next()
            .ok_or_else(|| format!("git ls-tree record for {path} has no object type"))?;
        let object_id = fields
            .next()
            .ok_or_else(|| format!("git ls-tree record for {path} has no object ID"))?;
        if fields.next().is_some() {
            return Err(format!(
                "git ls-tree record for {path} has unexpected header fields"
            ));
        }
        if object_type != "blob" {
            return Err(format!(
                "Git tree path {path} has unsupported object type {object_type}"
            ));
        }
        let mode = match mode_text {
            "100644" => 0o644,
            "100755" => 0o755,
            other => {
                return Err(format!(
                    "Git tree path {path} has unsupported mode {other}; symlinks and special entries are forbidden"
                ))
            }
        };
        if !paths.insert(path.clone()) {
            return Err(format!("Git tree repeats path {path}"));
        }
        insert_casefolded_path(&mut casefolded, &path)?;
        entries.push(GitTreeEntry {
            path,
            object_id: object_id.to_owned(),
            mode,
        });
    }
    if entries.is_empty() {
        return Err("clean HEAD tree is empty".to_owned());
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn read_head_blobs(
    repository: &Path,
    tree: &[GitTreeEntry],
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut child = git_command(repository)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("launch git cat-file --batch: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "git cat-file --batch has no stdin".to_owned())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "git cat-file --batch has no stdout".to_owned())?;
    let mut stdout = BufReader::new(stdout);
    let mut result = (|| {
        let mut blobs = BTreeMap::new();
        for entry in tree {
            // Keep only one request in flight. Writing the complete request
            // inventory first can deadlock when Git fills stdout with an early
            // blob while this process is still blocked on its stdin pipe.
            stdin
                .write_all(entry.object_id.as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
                .and_then(|()| stdin.flush())
                .map_err(|error| format!("write git cat-file --batch request: {error}"))?;
            let mut header = Vec::new();
            let read = stdout
                .read_until(b'\n', &mut header)
                .map_err(|error| format!("read git cat-file header for {}: {error}", entry.path))?;
            if read == 0 || header.last() != Some(&b'\n') {
                return Err(format!(
                    "git cat-file --batch ended before the header for {}",
                    entry.path
                ));
            }
            header.pop();
            let header = std::str::from_utf8(&header).map_err(|error| {
                format!(
                    "git cat-file header for {} is not UTF-8: {error}",
                    entry.path
                )
            })?;
            let fields = header.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() != 3
                || fields[0] != entry.object_id
                || fields[1] != "blob"
                || matches!(fields[2].as_bytes().first(), Some(b'+' | b'-'))
                || !fields[2].bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(format!(
                    "git cat-file returned unexpected header for {}: {header:?}",
                    entry.path
                ));
            }
            let size = fields[2].parse::<usize>().map_err(|error| {
                format!(
                    "git cat-file blob size for {} is invalid: {error}",
                    entry.path
                )
            })?;
            let mut bytes = vec![0u8; size];
            stdout
                .read_exact(&mut bytes)
                .map_err(|error| format!("read clean HEAD blob for {}: {error}", entry.path))?;
            let mut terminator = [0u8; 1];
            stdout.read_exact(&mut terminator).map_err(|error| {
                format!("read git cat-file terminator for {}: {error}", entry.path)
            })?;
            if terminator[0] != b'\n' {
                return Err(format!(
                    "git cat-file blob for {} has an invalid terminator",
                    entry.path
                ));
            }
            if blobs.insert(entry.path.clone(), bytes).is_some() {
                return Err(format!("clean HEAD repeats blob path {}", entry.path));
            }
        }
        Ok(blobs)
    })();
    drop(stdin);

    let mut trailing = Vec::new();
    match stdout.read_to_end(&mut trailing) {
        Ok(_) if result.is_ok() && !trailing.is_empty() => {
            result = Err("git cat-file --batch returned unrequested trailing output".to_owned())
        }
        Ok(_) => {}
        Err(error) if result.is_ok() => {
            result = Err(format!("read trailing git cat-file output: {error}"))
        }
        Err(_) => {}
    }
    drop(stdout);

    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_end(&mut stderr);
    }
    let status = child
        .wait()
        .map_err(|error| format!("wait for git cat-file --batch: {error}"))?;
    match (result, status.success()) {
        (Ok(blobs), true) => Ok(blobs),
        (Ok(_), false) => Err(format!(
            "git cat-file --batch failed with {status}: {}",
            String::from_utf8_lossy(&stderr).trim()
        )),
        (Err(error), true) => Err(error),
        (Err(error), false) => Err(format!(
            "{error}; git cat-file --batch failed with {status}: {}",
            String::from_utf8_lossy(&stderr).trim()
        )),
    }
}

fn ensure_controlled_cargo_configuration(repository: &Path) -> Result<(), String> {
    let repository_config = repository.join(".cargo").join("config.toml");
    let common_checkout_config = common_checkout_cargo_configuration(repository)?;
    let mut cargo_directories = repository
        .ancestors()
        .map(|ancestor| ancestor.join(".cargo"))
        .collect::<BTreeSet<_>>();
    let configured_home = std::env::var_os("CARGO_HOME").map(PathBuf::from);
    let default_home = if cfg!(windows) {
        std::env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join(".cargo"))
    } else {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo"))
    };
    if let Some(cargo_home) = configured_home.or(default_home) {
        cargo_directories.insert(if cargo_home.is_absolute() {
            cargo_home
        } else {
            repository.join(cargo_home)
        });
    }

    for directory in cargo_directories {
        match fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(format!(
                    "source bundling rejects non-directory or symlinked Cargo configuration root {}",
                    directory.display()
                ))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "inspect Cargo configuration root {}: {error}",
                    directory.display()
                ))
            }
        }
        for name in ["config", "config.toml"] {
            let path = directory.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) => validate_cargo_configuration_file(
                    &path,
                    &repository_config,
                    common_checkout_config.as_deref(),
                    &metadata,
                )?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "inspect Cargo configuration {}: {error}",
                        path.display()
                    ))
                }
            }
        }
    }
    Ok(())
}

fn common_checkout_cargo_configuration(repository: &Path) -> Result<Option<PathBuf>, String> {
    let reported = git_text(repository, &["rev-parse", "--git-common-dir"])?
        .trim()
        .to_owned();
    let reported = PathBuf::from(reported);
    let common_git_dir = if reported.is_absolute() {
        reported
    } else {
        repository.join(reported)
    };
    let metadata = fs::symlink_metadata(&common_git_dir).map_err(|error| {
        format!(
            "inspect Git common directory {}: {error}",
            common_git_dir.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Ok(None);
    }
    let common_git_dir = fs::canonicalize(&common_git_dir).map_err(|error| {
        format!(
            "canonicalize Git common directory {}: {error}",
            common_git_dir.display()
        )
    })?;
    if common_git_dir.file_name().and_then(|name| name.to_str()) != Some(".git") {
        return Ok(None);
    }
    let Some(common_checkout) = common_git_dir.parent() else {
        return Ok(None);
    };
    let reported_top_level = git_text(common_checkout, &["rev-parse", "--show-toplevel"])?;
    let canonical_top_level = fs::canonicalize(reported_top_level.trim()).map_err(|error| {
        format!(
            "canonicalize Git common-checkout top level {}: {error}",
            reported_top_level.trim()
        )
    })?;
    if canonical_top_level != common_checkout {
        return Ok(None);
    }
    Ok(Some(common_checkout.join(".cargo").join("config.toml")))
}

fn validate_cargo_configuration_file(
    path: &Path,
    repository_config: &Path,
    common_checkout_config: Option<&Path>,
    metadata: &fs::Metadata,
) -> Result<(), String> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "Cargo configuration must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("read Cargo configuration {}: {error}", path.display()))?;
    if bytes == ALLOWED_REPOSITORY_CARGO_CONFIG
        || (common_checkout_config.is_some_and(|allowed| path == allowed)
            && bytes == ALLOWED_COMMON_CHECKOUT_CARGO_CONFIG)
    {
        return Ok(());
    }
    if common_checkout_config.is_some_and(|allowed| path == allowed) {
        return Err(format!(
            "common-checkout Cargo configuration {} is not the exact shared-target, non-incremental policy",
            path.display()
        ));
    }
    if path == repository_config {
        return Err(format!(
            "repository Cargo configuration {} is not the exact inert incremental-compilation policy",
            path.display()
        ));
    }
    Err(format!(
        "source bundling rejects ambient Cargo configuration {} unless it is the exact inert incremental-compilation policy",
        path.display()
    ))
}

fn remove_ambient_cargo_overrides(command: &mut Command) {
    for (name, _) in std::env::vars_os() {
        let should_remove = name.to_str().is_some_and(is_ambient_cargo_or_rust_override);
        if should_remove {
            command.env_remove(&name);
        }
    }
}

fn is_ambient_cargo_or_rust_override(name: &str) -> bool {
    (name.starts_with("CARGO_") && name != "CARGO_HOME")
        || matches!(
            name,
            "RUSTC"
                | "RUSTC_BOOTSTRAP"
                | "RUSTC_WRAPPER"
                | "RUSTC_WORKSPACE_WRAPPER"
                | "RUSTDOC"
                | "RUSTDOCFLAGS"
                | "RUSTFLAGS"
                | "RUSTUP_TOOLCHAIN"
        )
}

fn rustup_tool_command(toolchain: &str, tool: &str) -> Command {
    let mut command = Command::new("rustup");
    command.arg("run").arg(toolchain).arg(tool);
    remove_ambient_cargo_overrides(&mut command);
    command
}

fn verify_exact_toolchain(toolchain: &str) -> Result<(), String> {
    for tool in ["rustc", "cargo"] {
        let output = rustup_tool_command(toolchain, tool)
            .arg("--version")
            .output()
            .map_err(|error| format!("launch rustup run {toolchain} {tool} --version: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "rustup run {toolchain} {tool} --version failed with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let version = std::str::from_utf8(&output.stdout)
            .map_err(|error| format!("{tool} --version output is not UTF-8: {error}"))?
            .trim();
        if !exact_tool_version_matches(version, tool, toolchain) {
            return Err(format!(
                "rustup toolchain {toolchain} returned unexpected {tool} version {version:?}"
            ));
        }
    }
    Ok(())
}

fn exact_tool_version_matches(output: &str, tool: &str, toolchain: &str) -> bool {
    let expected = format!("{tool} {toolchain}");
    output == expected
        || output
            .strip_prefix(&expected)
            .is_some_and(|suffix| suffix.starts_with(' '))
}

fn cargo_metadata(
    repository: &Path,
    toolchain: &str,
    spec: RootSpec,
    package_mode: DistributionMode,
) -> Result<(Vec<u8>, CargoMetadata), String> {
    let arguments = metadata_arguments(spec, package_mode);
    let output = rustup_tool_command(toolchain, "cargo")
        .current_dir(repository)
        .args(&arguments)
        .output()
        .map_err(|error| {
            format!(
                "launch rustup run {toolchain} cargo metadata for {} with {}: {error}",
                spec.name,
                arguments.join(" ")
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "cargo {} failed with {}: {}",
            arguments.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let metadata = serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "parse cargo metadata format version 1 for {}: {error}",
            spec.name
        )
    })?;
    Ok((output.stdout, metadata))
}

fn metadata_arguments(spec: RootSpec, package_mode: DistributionMode) -> Vec<String> {
    let mut arguments = vec![
        "metadata".to_owned(),
        "--locked".to_owned(),
        "--offline".to_owned(),
        "--format-version".to_owned(),
        "1".to_owned(),
        "--filter-platform".to_owned(),
        WINDOWS_TARGET.to_owned(),
    ];
    if spec.no_default_features {
        arguments.push("--no-default-features".to_owned());
        if package_mode == DistributionMode::Preview {
            arguments.extend(["--features".to_owned(), "preview".to_owned()]);
        }
    }
    arguments.push("--manifest-path".to_owned());
    arguments.push(spec.manifest_path.to_owned());
    arguments
}

fn validate_metadata_manifests(
    repository: &Path,
    head_blobs: &BTreeMap<String, Vec<u8>>,
    metadata: &CargoMetadata,
) -> Result<(), String> {
    let mut package_ids = BTreeSet::new();
    for package in &metadata.packages {
        if !package_ids.insert(package.id.clone()) {
            return Err(format!("cargo metadata repeats package ID {}", package.id));
        }
        if package.source.is_some() {
            continue;
        }
        let manifest = fs::canonicalize(&package.manifest_path).map_err(|error| {
            format!(
                "canonicalize workspace manifest {}: {error}",
                package.manifest_path.display()
            )
        })?;
        let relative = manifest.strip_prefix(repository).map_err(|_| {
            format!(
                "workspace package {} manifest {} is outside the repository",
                package.name,
                manifest.display()
            )
        })?;
        let relative = path_to_slashes(relative)?;
        let expected = head_blobs.get(&relative).ok_or_else(|| {
            format!(
                "workspace package {} manifest {relative} is absent from clean HEAD",
                package.name
            )
        })?;
        let actual = read_regular_file(&manifest, "workspace Cargo manifest")?;
        if &actual != expected {
            return Err(format!(
                "workspace package {} manifest {relative} differs from clean HEAD",
                package.name
            ));
        }
    }
    Ok(())
}

fn derive_closure(metadata: &CargoMetadata, spec: RootSpec) -> Result<BTreeSet<String>, String> {
    let root_id = metadata.resolve.root.as_deref().ok_or_else(|| {
        format!(
            "cargo metadata for {} has no single resolve.root",
            spec.name
        )
    })?;
    let packages = metadata
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let root_package = packages.get(root_id).ok_or_else(|| {
        format!(
            "cargo metadata resolve.root {root_id} for {} is absent from packages",
            spec.name
        )
    })?;
    if root_package.name != spec.name {
        return Err(format!(
            "cargo metadata resolve.root for {} is package {}",
            spec.name, root_package.name
        ));
    }
    let expected_manifest = Path::new(spec.manifest_path);
    if !root_package.manifest_path.ends_with(expected_manifest) {
        return Err(format!(
            "cargo metadata root {} uses unexpected manifest {}",
            spec.name,
            root_package.manifest_path.display()
        ));
    }

    let mut nodes = BTreeMap::new();
    for node in &metadata.resolve.nodes {
        if nodes.insert(node.id.as_str(), node).is_some() {
            return Err(format!("cargo metadata repeats resolve node {}", node.id));
        }
        let dependency_ids = node.dependencies.iter().collect::<BTreeSet<_>>();
        let detailed_ids = node
            .deps
            .iter()
            .map(|dependency| &dependency.pkg)
            .collect::<BTreeSet<_>>();
        if dependency_ids != detailed_ids {
            return Err(format!(
                "cargo metadata node {} has inconsistent dependencies and deps lists",
                node.id
            ));
        }
    }

    let mut closure = BTreeSet::new();
    let mut queue = VecDeque::from([root_id.to_owned()]);
    while let Some(package_id) = queue.pop_front() {
        if !closure.insert(package_id.clone()) {
            continue;
        }
        if !packages.contains_key(package_id.as_str()) {
            return Err(format!(
                "cargo metadata closure references absent package {package_id}"
            ));
        }
        let node = nodes.get(package_id.as_str()).ok_or_else(|| {
            format!("cargo metadata closure package {package_id} has no resolve node")
        })?;
        for dependency in &node.deps {
            if include_dependency(dependency)? {
                queue.push_back(dependency.pkg.clone());
            }
        }
    }
    Ok(closure)
}

fn include_dependency(dependency: &MetadataDependency) -> Result<bool, String> {
    if dependency.dep_kinds.is_empty() {
        return Err(format!(
            "cargo metadata dependency {} has no dependency kinds",
            dependency.pkg
        ));
    }
    let mut include = false;
    for kind in &dependency.dep_kinds {
        match kind.kind.as_deref() {
            None | Some("normal") | Some("build") => include = true,
            Some("dev") => {}
            Some(other) => {
                return Err(format!(
                    "cargo metadata dependency {} has unknown dependency kind {other}",
                    dependency.pkg
                ))
            }
        }
    }
    Ok(include)
}

fn combine_closures(
    closures: &[RootClosure],
) -> Result<BTreeMap<PackageKey, IncludedPackage>, String> {
    let mut included: BTreeMap<PackageKey, IncludedPackage> = BTreeMap::new();
    for closure in closures {
        let packages = closure
            .metadata
            .packages
            .iter()
            .map(|package| (package.id.as_str(), package))
            .collect::<BTreeMap<_, _>>();
        for package_id in &closure.package_ids {
            let package = packages.get(package_id.as_str()).ok_or_else(|| {
                format!(
                    "{} closure package {package_id} is absent from cargo metadata",
                    closure.spec.name
                )
            })?;
            let key = package_key(package);
            match included.get_mut(&key) {
                Some(existing) => {
                    if existing.metadata.name != package.name
                        || existing.metadata.version != package.version
                        || existing.metadata.source != package.source
                    {
                        return Err(format!(
                            "cargo metadata disagrees about package {} {}",
                            package.name, package.version
                        ));
                    }
                    existing.scopes.insert(closure.spec.name.to_owned());
                }
                None => {
                    included.insert(
                        key,
                        IncludedPackage {
                            metadata: (*package).clone(),
                            scopes: BTreeSet::from([closure.spec.name.to_owned()]),
                        },
                    );
                }
            }
        }
    }
    if included.is_empty() {
        return Err("target closure contains no packages".to_owned());
    }
    Ok(included)
}

fn root_manifests(
    closures: &[RootClosure],
    package_mode: DistributionMode,
) -> Result<Vec<RootManifest>, String> {
    let mut roots = Vec::with_capacity(closures.len());
    for closure in closures {
        let root_id = closure
            .metadata
            .resolve
            .root
            .as_deref()
            .ok_or_else(|| format!("{} metadata has no root", closure.spec.name))?;
        let package = closure
            .metadata
            .packages
            .iter()
            .find(|package| package.id == root_id)
            .ok_or_else(|| format!("{} metadata root package is absent", closure.spec.name))?;
        roots.push(RootManifest {
            name: package.name.clone(),
            version: package.version.clone(),
            manifest_path: closure.spec.manifest_path.to_owned(),
            cargo_metadata_arguments: metadata_arguments(closure.spec, package_mode),
            dependency_kinds: ["normal".to_owned(), "build".to_owned()],
            excluded_dependency_kind: "dev".to_owned(),
            package_count: closure.package_ids.len(),
        });
    }
    roots.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(roots)
}

fn verify_repository_snapshot(
    repository: &Path,
    git_object_format: &str,
    source_commit: &str,
    source_tree_oid: &str,
    toolchain: &str,
    closures: &[RootClosure],
    package_mode: DistributionMode,
) -> Result<(), String> {
    verify_repository_identity(
        repository,
        git_object_format,
        source_commit,
        source_tree_oid,
        toolchain,
    )?;
    for closure in closures {
        let (stdout, _) = cargo_metadata(repository, toolchain, closure.spec, package_mode)?;
        if stdout != closure.metadata_stdout {
            return Err(format!(
                "cargo metadata for {} changed while the source bundle was being prepared",
                closure.spec.name
            ));
        }
    }
    verify_repository_identity(
        repository,
        git_object_format,
        source_commit,
        source_tree_oid,
        toolchain,
    )
}

fn verify_repository_identity(
    repository: &Path,
    git_object_format: &str,
    source_commit: &str,
    source_tree_oid: &str,
    toolchain: &str,
) -> Result<(), String> {
    if head_commit(repository)? != source_commit {
        return Err("HEAD changed while the source bundle was being prepared".to_owned());
    }
    if source_tree_identity(repository, source_commit)?
        != (git_object_format.to_owned(), source_tree_oid.to_owned())
    {
        return Err(
            "Git object format or source tree changed while the source bundle was being prepared"
                .to_owned(),
        );
    }
    ensure_clean_checkout(repository)?;
    ensure_controlled_cargo_configuration(repository)?;
    verify_exact_toolchain(toolchain)?;
    if head_commit(repository)? != source_commit {
        return Err("HEAD changed during final source-bundle verification".to_owned());
    }
    if source_tree_identity(repository, source_commit)?
        != (git_object_format.to_owned(), source_tree_oid.to_owned())
    {
        return Err(
            "Git object format or source tree changed during final source-bundle verification"
                .to_owned(),
        );
    }
    ensure_clean_checkout(repository)
}

fn parse_cargo_lock(bytes: &[u8]) -> Result<BTreeMap<PackageKey, LockPackage>, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|error| format!("Cargo.lock is not UTF-8: {error}"))?;
    let mut packages = BTreeMap::new();
    let mut current: Option<BTreeMap<String, String>> = None;

    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line == "[[package]]" {
            if let Some(fields) = current.take() {
                insert_lock_package(&mut packages, fields)?;
            }
            current = Some(BTreeMap::new());
            continue;
        }
        if line.starts_with('[') {
            if let Some(fields) = current.take() {
                insert_lock_package(&mut packages, fields)?;
            }
            continue;
        }
        let Some(fields) = current.as_mut() else {
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !matches!(key, "name" | "version" | "source" | "checksum") {
            continue;
        }
        let value = value.trim();
        if !(value.starts_with('"') && value.ends_with('"')) {
            return Err(format!(
                "Cargo.lock line {} has unsupported non-basic-string field {key}",
                index + 1
            ));
        }
        let decoded: String = serde_json::from_str(value).map_err(|error| {
            format!(
                "Cargo.lock line {} has invalid {key} string: {error}",
                index + 1
            )
        })?;
        if fields.insert(key.to_owned(), decoded).is_some() {
            return Err(format!(
                "Cargo.lock package stanza repeats {key} on line {}",
                index + 1
            ));
        }
    }
    if let Some(fields) = current {
        insert_lock_package(&mut packages, fields)?;
    }
    if packages.is_empty() {
        return Err("Cargo.lock contains no [[package]] entries".to_owned());
    }
    Ok(packages)
}

fn insert_lock_package(
    packages: &mut BTreeMap<PackageKey, LockPackage>,
    mut fields: BTreeMap<String, String>,
) -> Result<(), String> {
    let name = fields
        .remove("name")
        .ok_or_else(|| "Cargo.lock package has no name".to_owned())?;
    let version = fields
        .remove("version")
        .ok_or_else(|| format!("Cargo.lock package {name} has no version"))?;
    let source = fields.remove("source");
    let checksum = fields.remove("checksum");
    match (&source, &checksum) {
        (Some(_), Some(checksum)) => require_sha256(checksum, "Cargo.lock package checksum")?,
        (Some(source), None) => {
            return Err(format!(
                "Cargo.lock package {name} {version} from {source} has no checksum"
            ))
        }
        (None, Some(_)) => {
            return Err(format!(
                "Cargo.lock workspace package {name} {version} unexpectedly has a checksum"
            ))
        }
        (None, None) => {}
    }
    let key = PackageKey {
        name,
        version,
        source,
    };
    if packages
        .insert(key.clone(), LockPackage { checksum })
        .is_some()
    {
        return Err(format!(
            "Cargo.lock repeats package {} {} source {:?}",
            key.name, key.version, key.source
        ));
    }
    Ok(())
}

fn package_key(package: &MetadataPackage) -> PackageKey {
    PackageKey {
        name: package.name.clone(),
        version: package.version.clone(),
        source: package.source.clone(),
    }
}

fn validate_package_source(
    repository: &Path,
    head_blobs: &BTreeMap<String, Vec<u8>>,
    package: &MetadataPackage,
    lock: &LockPackage,
) -> Result<(), String> {
    match package.source.as_deref() {
        Some(REGISTRY_SOURCE) => {
            let checksum = lock.checksum.as_deref().ok_or_else(|| {
                format!(
                    "registry package {} {} has no Cargo.lock checksum",
                    package.name, package.version
                )
            })?;
            require_sha256(checksum, "registry package Cargo.lock checksum")
        }
        None => {
            if lock.checksum.is_some() {
                return Err(format!(
                    "workspace package {} {} unexpectedly has a Cargo.lock checksum",
                    package.name, package.version
                ));
            }
            let expected_manifest = ALLOWED_WORKSPACE_PACKAGES
                .iter()
                .find_map(|(name, path)| (*name == package.name).then_some(*path))
                .ok_or_else(|| {
                    format!(
                        "target closure contains unapproved workspace package {} {}",
                        package.name, package.version
                    )
                })?;
            let canonical = fs::canonicalize(&package.manifest_path).map_err(|error| {
                format!(
                    "canonicalize manifest for workspace package {}: {error}",
                    package.name
                )
            })?;
            let expected_path =
                fs::canonicalize(repository.join(expected_manifest)).map_err(|error| {
                    format!(
                        "canonicalize expected manifest {expected_manifest} for {}: {error}",
                        package.name
                    )
                })?;
            if canonical != expected_path {
                return Err(format!(
                    "workspace package {} uses unexpected manifest {}; expected {expected_manifest}",
                    package.name,
                    package.manifest_path.display()
                ));
            }
            let expected_bytes = head_blobs.get(expected_manifest).ok_or_else(|| {
                format!("clean HEAD has no approved workspace manifest {expected_manifest}")
            })?;
            let actual = read_regular_file(&canonical, "workspace package manifest")?;
            if &actual != expected_bytes {
                return Err(format!(
                    "workspace package {} manifest differs from clean HEAD",
                    package.name
                ));
            }
            Ok(())
        }
        Some(source) => Err(format!(
            "target closure package {} {} uses unsupported source {source}",
            package.name, package.version
        )),
    }
}

fn workspace_source_files(
    tree: &[GitTreeEntry],
    head_blobs: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<SourceFile>, String> {
    let mut files = Vec::with_capacity(tree.len());
    for entry in tree {
        validate_workspace_source_path(&entry.path)?;
        let bytes = head_blobs.get(&entry.path).ok_or_else(|| {
            format!(
                "clean HEAD blob inventory is missing tree path {}",
                entry.path
            )
        })?;
        files.push(SourceFile {
            relative_path: entry.path.clone(),
            bytes: Arc::from(bytes.clone()),
            mode: entry.mode,
        });
    }
    Ok(files)
}

fn validate_workspace_source_path(path: &str) -> Result<(), String> {
    validate_relative_path(path, false)?;
    let components = path.split('/').collect::<Vec<_>>();
    if components.contains(&".git") {
        return Err(format!(
            "clean HEAD unexpectedly contains Git administration path {path}"
        ));
    }
    if components
        .windows(2)
        .any(|parts| parts == [".cargo", "registry"])
    {
        return Err(format!(
            "clean HEAD unexpectedly contains Cargo registry cache path {path}"
        ));
    }
    if matches!(components.first().copied(), Some("target" | "dist")) {
        return Err(format!(
            "clean HEAD unexpectedly contains generated output path {path}"
        ));
    }
    if path.ends_with(".crate") {
        return Err(format!(
            "clean HEAD unexpectedly contains downloaded crate archive {path}"
        ));
    }
    if path == ".cargo/config" || path == ".cargo/config.toml" {
        return Err(format!(
            "clean HEAD path {path} collides with the generated offline Cargo configuration"
        ));
    }
    Ok(())
}

fn reviewed_dependency_input_closure(
    policy_bytes: &[u8],
    cargo_lock_sha256: &str,
) -> Result<String, String> {
    let policy: serde_json::Value = serde_json::from_slice(policy_bytes)
        .map_err(|error| format!("parse clean HEAD {THIRD_PARTY_LICENSE_POLICY_PATH}: {error}"))?;
    let object = policy.as_object().ok_or_else(|| {
        format!("clean HEAD {THIRD_PARTY_LICENSE_POLICY_PATH} must contain a JSON object")
    })?;
    let reviewed_lock = object
        .get("reviewed_cargo_lock_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            format!("clean HEAD {THIRD_PARTY_LICENSE_POLICY_PATH} has no string reviewed_cargo_lock_sha256")
        })?;
    require_sha256(
        reviewed_lock,
        "third-party licence policy reviewed_cargo_lock_sha256",
    )?;
    if reviewed_lock != cargo_lock_sha256 {
        return Err(format!(
            "clean HEAD {THIRD_PARTY_LICENSE_POLICY_PATH} reviews Cargo.lock SHA-256 {reviewed_lock}, but the bundled Cargo.lock SHA-256 is {cargo_lock_sha256}"
        ));
    }
    let input_closure = object
        .get("reviewed_input_closure_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            format!(
                "clean HEAD {THIRD_PARTY_LICENSE_POLICY_PATH} has no string reviewed_input_closure_sha256"
            )
        })?
        .to_owned();
    require_sha256(
        &input_closure,
        "third-party licence policy reviewed_input_closure_sha256",
    )?;
    Ok(input_closure)
}

fn rust_toolchain_channel(bytes: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| format!("rust-toolchain.toml is not UTF-8: {error}"))?;
    let mut channel = None;
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "channel" {
            continue;
        }
        let parsed: String = serde_json::from_str(value.trim()).map_err(|error| {
            format!(
                "rust-toolchain.toml line {} has invalid channel: {error}",
                index + 1
            )
        })?;
        validate_exact_toolchain_channel(&parsed)?;
        if channel.replace(parsed).is_some() {
            return Err("rust-toolchain.toml repeats toolchain channel".to_owned());
        }
    }
    channel.ok_or_else(|| "rust-toolchain.toml has no toolchain channel".to_owned())
}

fn validate_exact_toolchain_channel(channel: &str) -> Result<(), String> {
    let components = channel.split('.').collect::<Vec<_>>();
    if components.len() == 3
        && components.iter().all(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && (component.len() == 1 || !component.starts_with('0'))
        })
    {
        Ok(())
    } else {
        Err(format!(
            "rust-toolchain.toml channel must pin an exact numeric Rust release, got {channel:?}"
        ))
    }
}

fn offline_cargo_config() -> Vec<u8> {
    b"[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"../../vendor\"\n\n[net]\noffline = true\n\n[build]\nincremental = false\n"
        .to_vec()
}

fn file_manifest(path: &str, bytes: &[u8]) -> FileManifest {
    FileManifest {
        path: path.to_owned(),
        sha256: sha256(bytes),
        bytes: bytes.len(),
    }
}

fn prepare_vendor_package(
    package: &MetadataPackage,
    lock: &LockPackage,
) -> Result<PreparedVendorPackage, String> {
    let expected_checksum = lock.checksum.as_deref().ok_or_else(|| {
        format!(
            "registry package {} {} has no Cargo.lock checksum",
            package.name, package.version
        )
    })?;
    let crate_path = crate_archive_path(package)?;
    let crate_metadata = fs::symlink_metadata(&crate_path).map_err(|error| {
        format!(
            "inspect cached archive for {} {} at {}: {error}",
            package.name,
            package.version,
            crate_path.display()
        )
    })?;
    if crate_metadata.file_type().is_symlink() || !crate_metadata.is_file() {
        return Err(format!(
            "cached archive for {} {} must be a regular non-symlink file: {}",
            package.name,
            package.version,
            crate_path.display()
        ));
    }
    if crate_metadata.len() > MAX_CRATE_ARCHIVE_BYTES {
        return Err(format!(
            "cached archive for {} {} is {} bytes, exceeding the {} byte safety limit",
            package.name,
            package.version,
            crate_metadata.len(),
            MAX_CRATE_ARCHIVE_BYTES
        ));
    }
    let crate_bytes = fs::read(&crate_path).map_err(|error| {
        format!(
            "read cached archive for {} {} at {}: {error}",
            package.name,
            package.version,
            crate_path.display()
        )
    })?;
    let crate_sha256 = sha256(&crate_bytes);
    if crate_sha256 != expected_checksum {
        return Err(format!(
            "cached archive SHA-256 for {} {} is {crate_sha256}, but Cargo.lock requires {expected_checksum}",
            package.name, package.version
        ));
    }

    let tar_entries = parse_crate_archive(package, &crate_bytes)?;
    let manifest_bytes = tar_entries
        .iter()
        .find(|entry| entry.relative_path == "Cargo.toml")
        .map(|entry| entry.bytes.as_slice())
        .ok_or_else(|| {
            format!(
                "cached archive for {} {} has no Cargo.toml",
                package.name, package.version
            )
        })?;
    let archived_manifest = Arc::<[u8]>::from(manifest_bytes);
    let cached_manifest = read_regular_file(
        &package.manifest_path,
        &format!("unpacked manifest for {} {}", package.name, package.version),
    )?;
    if manifest_bytes != cached_manifest {
        return Err(format!(
            "unpacked registry manifest for {} {} differs from the checksum-verified .crate archive",
            package.name, package.version
        ));
    }

    let vendor_dir = format!("vendor/{}-{}", package.name, package.version);
    let mut files = Vec::new();
    let mut checksum_files = BTreeMap::new();
    let mut exclusions = Vec::new();
    let mut encountered_deny_rules = BTreeSet::new();
    for entry in tar_entries {
        if entry.relative_path == ".cargo-checksum.json" {
            return Err(format!(
                "registry archive for {} {} unexpectedly contains .cargo-checksum.json",
                package.name, package.version
            ));
        }
        if let Some((rule_index, rule)) =
            matching_deny_rule(&package.name, &package.version, &entry.relative_path)
        {
            if !encountered_deny_rules.insert(rule_index) {
                return Err(format!(
                    "denylisted archive member {} {} {} appeared more than once",
                    package.name, package.version, entry.relative_path
                ));
            }
            let excluded_sha256 = sha256(&entry.bytes);
            if entry.bytes.len() != rule.expected_bytes || excluded_sha256 != rule.expected_sha256 {
                return Err(format!(
                    "denylisted archive member {} {} {} changed: expected {} bytes SHA-256 {}, found {} bytes SHA-256 {}",
                    package.name,
                    package.version,
                    entry.relative_path,
                    rule.expected_bytes,
                    rule.expected_sha256,
                    entry.bytes.len(),
                    excluded_sha256
                ));
            }
            exclusions.push(ExclusionManifest {
                package: package.name.clone(),
                version: package.version.clone(),
                path: format!("{vendor_dir}/{}", entry.relative_path),
                sha256: excluded_sha256,
                bytes: entry.bytes.len(),
                reason: rule.reason.to_owned(),
            });
            continue;
        }
        let file_sha256 = sha256(&entry.bytes);
        if checksum_files
            .insert(entry.relative_path.clone(), file_sha256)
            .is_some()
        {
            return Err(format!(
                "registry archive for {} {} repeats path {}",
                package.name, package.version, entry.relative_path
            ));
        }
        files.push(SourceFile {
            relative_path: entry.relative_path,
            bytes: Arc::from(entry.bytes),
            mode: entry.mode,
        });
    }
    if files.is_empty() {
        return Err(format!(
            "registry archive for {} {} contains no permitted files",
            package.name, package.version
        ));
    }
    let mut checksum_bytes = serde_json::to_vec(&CargoChecksum {
        files: &checksum_files,
        package: expected_checksum,
    })
    .map_err(|error| {
        format!(
            "serialize .cargo-checksum.json for {} {}: {error}",
            package.name, package.version
        )
    })?;
    checksum_bytes.push(b'\n');
    files.push(SourceFile {
        relative_path: ".cargo-checksum.json".to_owned(),
        bytes: Arc::from(checksum_bytes),
        mode: 0o644,
    });
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let tree_sha256 = tree_digest(&files);
    let file_count = files.len();
    Ok(PreparedVendorPackage {
        manifest: VendorManifest {
            path: vendor_dir,
            crate_archive_sha256: crate_sha256,
            file_count,
            tree_sha256,
        },
        files,
        exclusions,
        encountered_deny_rules,
        archived_manifest,
    })
}

fn validate_prepared_vendor_manifest(
    package: &MetadataPackage,
    prepared: &PreparedVendorPackage,
) -> Result<(), String> {
    let cached_manifest = read_regular_file(
        &package.manifest_path,
        &format!("unpacked manifest for {} {}", package.name, package.version),
    )?;
    if cached_manifest.as_slice() != prepared.archived_manifest.as_ref() {
        return Err(format!(
            "unpacked registry manifest for {} {} changed after checksum-verified preparation",
            package.name, package.version
        ));
    }
    Ok(())
}

fn apply_prepared_vendor(
    prepared: &PreparedVendorPackage,
    archive: &mut ArchiveEntries,
    exclusions: &mut Vec<ExclusionManifest>,
    encountered_deny_rules: &mut BTreeSet<usize>,
) -> Result<(), String> {
    for rule in &prepared.encountered_deny_rules {
        if !encountered_deny_rules.insert(*rule) {
            return Err(format!(
                "prepared source-bundle deny rule {rule} was encountered by more than one package"
            ));
        }
    }
    exclusions.extend(prepared.exclusions.iter().cloned());
    for file in &prepared.files {
        archive.insert(
            format!("{}/{}", prepared.manifest.path, file.relative_path),
            Arc::clone(&file.bytes),
            file.mode,
        )?;
    }
    Ok(())
}

fn crate_archive_path(package: &MetadataPackage) -> Result<PathBuf, String> {
    let manifest = &package.manifest_path;
    let source_dir = manifest.parent().ok_or_else(|| {
        format!(
            "registry package {} {} has invalid manifest path {}",
            package.name,
            package.version,
            manifest.display()
        )
    })?;
    let expected_dir = format!("{}-{}", package.name, package.version);
    if source_dir.file_name().and_then(|name| name.to_str()) != Some(expected_dir.as_str()) {
        return Err(format!(
            "registry package {} {} manifest is not under expected source directory {expected_dir}: {}",
            package.name,
            package.version,
            manifest.display()
        ));
    }
    let source_hash_dir = source_dir.parent().ok_or_else(|| {
        format!(
            "registry package {} {} manifest has no registry source parent",
            package.name, package.version
        )
    })?;
    let source_hash = source_hash_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            format!(
                "registry source directory for {} {} is not UTF-8",
                package.name, package.version
            )
        })?;
    validate_cache_component(source_hash, "Cargo registry source hash")?;
    let source_root = source_hash_dir.parent().ok_or_else(|| {
        format!(
            "registry package {} {} manifest has no registry src directory",
            package.name, package.version
        )
    })?;
    if source_root.file_name().and_then(|name| name.to_str()) != Some("src") {
        return Err(format!(
            "registry package {} {} manifest is not under a Cargo registry src directory: {}",
            package.name,
            package.version,
            manifest.display()
        ));
    }
    let registry_root = source_root.parent().ok_or_else(|| {
        format!(
            "registry package {} {} manifest has no Cargo registry root",
            package.name, package.version
        )
    })?;
    Ok(registry_root
        .join("cache")
        .join(source_hash)
        .join(format!("{}-{}.crate", package.name, package.version)))
}

fn validate_cache_component(value: &str, context: &str) -> Result<(), String> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
        })
    {
        return Err(format!("{context} contains unsafe component {value:?}"));
    }
    Ok(())
}

fn parse_crate_archive(
    package: &MetadataPackage,
    crate_bytes: &[u8],
) -> Result<Vec<TarEntry>, String> {
    let mut decoder = MultiGzDecoder::new(crate_bytes);
    let mut tar_bytes = Vec::new();
    let mut limited = (&mut decoder).take(MAX_UNPACKED_CRATE_BYTES + 1);
    limited.read_to_end(&mut tar_bytes).map_err(|error| {
        format!(
            "decompress checksum-verified archive for {} {}: {error}",
            package.name, package.version
        )
    })?;
    if tar_bytes.len() as u64 > MAX_UNPACKED_CRATE_BYTES {
        return Err(format!(
            "unpacked archive for {} {} exceeds the {} byte safety limit",
            package.name, package.version, MAX_UNPACKED_CRATE_BYTES
        ));
    }
    parse_ustar(&tar_bytes, &format!("{}-{}", package.name, package.version)).map_err(|error| {
        format!(
            "parse checksum-verified archive for {} {}: {error}",
            package.name, package.version
        )
    })
}

fn parse_ustar(bytes: &[u8], expected_root: &str) -> Result<Vec<TarEntry>, String> {
    validate_cache_component(expected_root, "expected tar root")?;
    let mut offset = 0usize;
    let mut entries = Vec::new();
    let mut paths = BTreeSet::new();
    let mut casefolded = BTreeMap::new();
    let mut zero_blocks = 0usize;
    let mut pending_long_name = None;

    while offset < bytes.len() {
        if bytes.len() - offset < 512 {
            return Err(format!(
                "truncated tar header at byte {offset}; {} bytes remain",
                bytes.len() - offset
            ));
        }
        let header = &bytes[offset..offset + 512];
        offset += 512;
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks += 1;
            if zero_blocks >= 2 {
                if pending_long_name.is_some() {
                    return Err("tar ends before a GNU long-name record is consumed".to_owned());
                }
                if bytes[offset..].iter().any(|byte| *byte != 0) {
                    return Err("tar contains non-zero data after end markers".to_owned());
                }
                return Ok(entries);
            }
            continue;
        }
        if zero_blocks != 0 {
            return Err("tar contains an entry after a zero end-marker block".to_owned());
        }
        validate_tar_header_checksum(header)?;
        if &header[257..263] != b"ustar\0" && &header[257..263] != b"ustar " {
            return Err("tar entry is not encoded as ustar".to_owned());
        }
        let name = parse_tar_text(&header[0..100], "name")?;
        let prefix = parse_tar_text(&header[345..500], "prefix")?;
        let full_path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let size = usize::try_from(parse_tar_octal(&header[124..136], "size")?)
            .map_err(|_| format!("tar path {full_path:?} size does not fit memory"))?;
        let padded_size = size
            .checked_add(511)
            .ok_or_else(|| format!("tar path {full_path:?} size overflows"))?
            / 512
            * 512;
        let end = offset
            .checked_add(padded_size)
            .ok_or_else(|| format!("tar path {full_path:?} data offset overflows"))?;
        if end > bytes.len() || offset + size > bytes.len() {
            return Err(format!(
                "tar path {full_path:?} data is truncated at byte {offset}"
            ));
        }
        if bytes[offset + size..end].iter().any(|byte| *byte != 0) {
            return Err(format!(
                "tar path {full_path:?} has non-zero alignment padding"
            ));
        }
        let mode = parse_tar_octal(&header[100..108], "mode")?;
        let normalized_mode = if mode & 0o111 != 0 { 0o755 } else { 0o644 };
        let type_flag = header[156];
        if type_flag == b'L' {
            if pending_long_name.is_some() {
                return Err("tar contains consecutive GNU long-name records".to_owned());
            }
            if full_path != "././@LongLink" {
                return Err(format!(
                    "GNU long-name record uses unexpected marker path {full_path:?}"
                ));
            }
            let link_name = parse_tar_text(&header[157..257], "link name")?;
            if !link_name.is_empty() {
                return Err("GNU long-name record unexpectedly has a link target".to_owned());
            }
            pending_long_name = Some(parse_gnu_long_name(&bytes[offset..offset + size])?);
            offset = end;
            continue;
        }
        let is_regular = matches!(type_flag, 0 | b'0');
        let is_directory = type_flag == b'5';
        if !is_regular && !is_directory {
            return Err(format!(
                "tar path {full_path:?} has unsupported type flag 0x{type_flag:02x}"
            ));
        }
        let link_name = parse_tar_text(&header[157..257], "link name")?;
        if !link_name.is_empty() {
            return Err(format!(
                "tar path {full_path:?} unexpectedly has link target {link_name:?}"
            ));
        }
        let full_path = pending_long_name.take().unwrap_or(full_path);
        validate_relative_path(&full_path, is_directory)?;
        let root_prefix = format!("{expected_root}/");
        let relative = if is_directory && full_path.trim_end_matches('/') == expected_root {
            ""
        } else {
            full_path
                .strip_prefix(&root_prefix)
                .ok_or_else(|| {
                    format!("tar path {full_path:?} is outside expected root {expected_root:?}")
                })?
                .trim_end_matches('/')
        };

        if is_directory {
            if size != 0 {
                return Err(format!(
                    "tar directory path {full_path:?} has non-zero size {size}"
                ));
            }
            offset = end;
            continue;
        }
        if relative.is_empty() {
            return Err(format!(
                "tar regular file path {full_path:?} has no relative name"
            ));
        }
        validate_relative_path(relative, false)?;
        if !paths.insert(relative.to_owned()) {
            return Err(format!("tar repeats regular file path {relative}"));
        }
        insert_casefolded_path(&mut casefolded, relative)?;
        entries.push(TarEntry {
            relative_path: relative.to_owned(),
            bytes: bytes[offset..offset + size].to_vec(),
            mode: normalized_mode,
        });
        offset = end;
    }
    Err("tar has no two-block end marker".to_owned())
}

fn parse_gnu_long_name(bytes: &[u8]) -> Result<String, String> {
    let Some((&0, name_bytes)) = bytes.split_last() else {
        return Err("GNU long-name record must end with exactly one NUL".to_owned());
    };
    if name_bytes.is_empty() || name_bytes.contains(&0) {
        return Err("GNU long-name record contains an empty or embedded-NUL path".to_owned());
    }
    let name = std::str::from_utf8(name_bytes)
        .map_err(|error| format!("GNU long-name record is not UTF-8: {error}"))?
        .to_owned();
    validate_relative_path(&name, name.ends_with('/'))?;
    Ok(name)
}

fn validate_tar_header_checksum(header: &[u8]) -> Result<(), String> {
    let stored = parse_tar_octal(&header[148..156], "header checksum")?;
    let calculated = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum::<u64>();
    if stored != calculated {
        return Err(format!(
            "tar header checksum is {stored:o}, expected {calculated:o}"
        ));
    }
    Ok(())
}

fn parse_tar_text(field: &[u8], name: &str) -> Result<String, String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(format!("tar {name} contains bytes after NUL terminator"));
    }
    std::str::from_utf8(&field[..end])
        .map(str::to_owned)
        .map_err(|error| format!("tar {name} is not UTF-8: {error}"))
}

fn parse_tar_octal(field: &[u8], name: &str) -> Result<u64, String> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(format!("tar {name} uses unsupported base-256 encoding"));
    }
    let mut value = 0u64;
    let mut saw_digit = false;
    let mut ended = false;
    for byte in field {
        match *byte {
            b' ' | 0 if !saw_digit => {}
            b'0'..=b'7' if !ended => {
                saw_digit = true;
                value = value
                    .checked_mul(8)
                    .and_then(|current| current.checked_add(u64::from(byte - b'0')))
                    .ok_or_else(|| format!("tar {name} octal value overflows"))?;
            }
            b' ' | 0 => ended = true,
            other => {
                return Err(format!(
                    "tar {name} contains invalid octal byte 0x{other:02x}"
                ))
            }
        }
    }
    Ok(value)
}

fn matching_deny_rule(
    package: &str,
    version: &str,
    relative_path: &str,
) -> Option<(usize, &'static DenyRule)> {
    DENY_RULES.iter().enumerate().find(|(_, rule)| {
        rule.package == package && rule.version == version && rule.relative_path == relative_path
    })
}

fn validate_denylist_coverage(
    included: &BTreeMap<PackageKey, IncludedPackage>,
    encountered: &BTreeSet<usize>,
) -> Result<(), String> {
    for (index, rule) in DENY_RULES.iter().enumerate() {
        let package_is_included = included.keys().any(|key| {
            key.name == rule.package
                && key.version == rule.version
                && key.source.as_deref() == Some(REGISTRY_SOURCE)
        });
        if !package_is_included {
            return Err(format!(
                "required denylist package {} {} is absent from the target closure",
                rule.package, rule.version
            ));
        }
        if !encountered.contains(&index) {
            return Err(format!(
                "required denylist path {} {} {} is absent from its checksum-verified archive",
                rule.package, rule.version, rule.relative_path
            ));
        }
    }
    if encountered.len() != DENY_RULES.len() {
        return Err("source-bundle denylist coverage is internally inconsistent".to_owned());
    }
    Ok(())
}

impl ArchiveEntries {
    fn insert(
        &mut self,
        path: String,
        bytes: impl Into<Arc<[u8]>>,
        mode: u32,
    ) -> Result<(), String> {
        validate_relative_path(&path, false)?;
        if !matches!(mode, 0o644 | 0o755) {
            return Err(format!(
                "archive path {path} has unsupported normalized mode {mode:o}"
            ));
        }
        if self.entries.contains_key(&path) {
            return Err(format!("archive repeats output path {path}"));
        }
        insert_casefolded_path(&mut self.casefolded_paths, &path)?;
        self.entries.insert(
            path,
            PayloadEntry {
                bytes: bytes.into(),
                mode,
            },
        );
        Ok(())
    }
}

fn validate_relative_path(path: &str, allow_trailing_slash: bool) -> Result<(), String> {
    if path.is_empty() {
        return Err("archive path must not be empty".to_owned());
    }
    if !path.is_ascii() {
        return Err(format!(
            "archive path {path:?} is not ASCII-safe for deterministic Windows extraction"
        ));
    }
    if path.len() > MAX_WINDOWS_RELATIVE_PATH_BYTES {
        return Err(format!(
            "archive path {path:?} is {} bytes, exceeding the conservative Windows limit of {MAX_WINDOWS_RELATIVE_PATH_BYTES}",
            path.len()
        ));
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(format!("archive path {path:?} must be relative"));
    }
    if path.contains('\\') {
        return Err(format!(
            "archive path {path:?} contains a Windows path separator"
        ));
    }
    if path.ends_with('/') && !allow_trailing_slash {
        return Err(format!(
            "regular-file archive path {path:?} must not end with a slash"
        ));
    }
    let trimmed = if allow_trailing_slash {
        path.trim_end_matches('/')
    } else {
        path
    };
    if trimmed.is_empty() {
        return Err(format!("archive path {path:?} has no components"));
    }
    for component in trimmed.split('/') {
        if component.is_empty() || matches!(component, "." | "..") {
            return Err(format!(
                "archive path {path:?} contains unsafe component {component:?}"
            ));
        }
        if component.len() > MAX_WINDOWS_COMPONENT_BYTES {
            return Err(format!(
                "archive path {path:?} contains a {} byte component, exceeding the conservative Windows limit of {MAX_WINDOWS_COMPONENT_BYTES}",
                component.len()
            ));
        }
        if component.bytes().any(|byte| {
            byte < b' '
                || byte == 0x7f
                || matches!(byte, b'<' | b'>' | b':' | b'"' | b'\\' | b'|' | b'?' | b'*')
        }) {
            return Err(format!(
                "archive path {path:?} contains a Windows-unsafe character"
            ));
        }
        if component.ends_with(' ') || component.ends_with('.') {
            return Err(format!(
                "archive path {path:?} contains a component with a Windows-unsafe suffix"
            ));
        }
        let device_stem = component
            .split('.')
            .next()
            .unwrap_or(component)
            .to_ascii_lowercase();
        let reserved = matches!(device_stem.as_str(), "con" | "prn" | "aux" | "nul")
            || device_stem.strip_prefix("com").is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
            || device_stem.strip_prefix("lpt").is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
        if reserved {
            return Err(format!(
                "archive path {path:?} contains reserved Windows device component {component:?}"
            ));
        }
    }
    Ok(())
}

fn insert_casefolded_path(
    casefolded: &mut BTreeMap<String, String>,
    path: &str,
) -> Result<(), String> {
    let folded = path.to_ascii_lowercase();
    if let Some(existing) = casefolded.get(&folded) {
        if existing != path {
            return Err(format!(
                "archive paths {existing:?} and {path:?} collide case-insensitively"
            ));
        }
        return Err(format!("archive repeats case-normalized path {path:?}"));
    }
    for (index, byte) in folded.bytes().enumerate() {
        if byte != b'/' {
            continue;
        }
        let ancestor = &folded[..index];
        if let Some(existing) = casefolded.get(ancestor) {
            return Err(format!(
                "archive file path {existing:?} conflicts with descendant path {path:?}"
            ));
        }
    }
    let descendant_prefix = format!("{folded}/");
    if let Some((existing_folded, existing)) = casefolded.range(descendant_prefix.clone()..).next()
    {
        if existing_folded.starts_with(descendant_prefix.as_str()) {
            return Err(format!(
                "archive file path {path:?} conflicts with descendant path {existing:?}"
            ));
        }
    }
    casefolded.insert(folded, path.to_owned());
    Ok(())
}

fn path_to_slashes(path: &Path) -> Result<String, String> {
    let mut components = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(format!(
                "path {} is not a clean relative path",
                path.display()
            ));
        };
        let component = component
            .to_str()
            .ok_or_else(|| format!("path {} is not UTF-8", path.display()))?;
        components.push(component);
    }
    let result = components.join("/");
    validate_relative_path(&result, false)?;
    Ok(result)
}

fn tree_digest(files: &[SourceFile]) -> String {
    let mut ordered = files.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let mut digest = Sha256::new();
    digest.update(b"autocad-mcp-source-tree-v1\0");
    for file in ordered {
        digest.update((file.relative_path.len() as u64).to_le_bytes());
        digest.update(file.relative_path.as_bytes());
        digest.update(file.mode.to_le_bytes());
        digest.update((file.bytes.len() as u64).to_le_bytes());
        digest.update(Sha256::digest(&file.bytes));
    }
    hex_lower(&digest.finalize())
}

fn sha256(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn require_sha256(value: &str, context: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "{context} must be a 64-character lowercase SHA-256, got {value:?}"
        ))
    }
}

fn read_regular_file(path: &Path, context: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect {context}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{context} must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    fs::read(path).map_err(|error| format!("read {context} {}: {error}", path.display()))
}

fn validate_output_location(repository: &Path, out_file: &Path) -> Result<(), String> {
    if out_file.file_name().is_none() {
        return Err("source bundle output must name a file".to_owned());
    }
    let parent = out_file.parent().unwrap_or_else(|| Path::new("."));
    let parent_metadata = fs::symlink_metadata(parent).map_err(|error| {
        format!(
            "inspect source bundle output directory {}: {error}",
            parent.display()
        )
    })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(format!(
            "source bundle output directory {} must be a real directory",
            parent.display()
        ));
    }
    match fs::symlink_metadata(out_file) {
        Ok(_) => {
            return Err(format!(
                "source bundle output already exists and will not be overwritten: {}",
                out_file.display()
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "inspect source bundle output {}: {error}",
                out_file.display()
            ))
        }
    }

    let canonical_parent = fs::canonicalize(parent).map_err(|error| {
        format!(
            "canonicalize source bundle output directory {}: {error}",
            parent.display()
        )
    })?;
    if let Ok(relative_parent) = canonical_parent.strip_prefix(repository) {
        let relative = relative_parent.join(
            out_file
                .file_name()
                .ok_or_else(|| "source bundle output has no filename".to_owned())?,
        );
        let relative = path_to_slashes(&relative)?;
        let status = git_command(repository)
            .args(["check-ignore", "--quiet", "--no-index", "--", &relative])
            .status()
            .map_err(|error| format!("launch git check-ignore for {relative}: {error}"))?;
        match status.code() {
            Some(0) => {}
            Some(1) => {
                return Err(format!(
                    "source bundle output inside the repository must be ignored: {relative}"
                ))
            }
            _ => {
                return Err(format!(
                    "git check-ignore failed with {status} for output {relative}"
                ))
            }
        }
    }
    Ok(())
}

struct HashingWriter<W> {
    inner: W,
    digest: Sha256,
    bytes: u64,
}

impl<W> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            bytes: 0,
        }
    }

    fn finish(self) -> (W, String, u64) {
        (self.inner, hex_lower(&self.digest.finalize()), self.bytes)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.digest.update(&buffer[..written]);
        self.bytes = self
            .bytes
            .checked_add(written as u64)
            .ok_or_else(|| std::io::Error::other("source bundle size overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn write_archive(
    out_file: &Path,
    entries: &BTreeMap<String, PayloadEntry>,
    durable_output: bool,
) -> Result<(String, u64), String> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out_file)
        .map_err(|error| {
            format!(
                "create source bundle output {} without overwrite: {error}",
                out_file.display()
            )
        })?;
    let result = (|| {
        let mut writer = HashingWriter::new(file);
        write_zip(&mut writer, entries)?;
        writer
            .flush()
            .map_err(|error| format!("flush source bundle {}: {error}", out_file.display()))?;
        let (file, archive_sha256, archive_bytes) = writer.finish();
        if durable_output {
            file.sync_all()
                .map_err(|error| format!("sync source bundle {}: {error}", out_file.display()))?;
        }
        drop(file);
        if durable_output {
            let (actual_sha256, actual_bytes) = hash_file(out_file)?;
            if actual_sha256 != archive_sha256 || actual_bytes != archive_bytes {
                return Err(format!(
                    "source bundle read-back mismatch: wrote {archive_bytes} bytes SHA-256 {archive_sha256}, read {actual_bytes} bytes SHA-256 {actual_sha256}"
                ));
            }
        }
        Ok((archive_sha256, archive_bytes))
    })();
    if result.is_err() {
        let _ = fs::remove_file(out_file);
    }
    result
}

fn remove_invalid_archive(out_file: &Path, verification_error: String) -> String {
    match fs::remove_file(out_file) {
        Ok(()) => verification_error,
        Err(error) => format!(
            "{verification_error}; additionally failed to remove invalid source bundle {}: {error}",
            out_file.display()
        ),
    }
}

fn hash_file(path: &Path) -> Result<(String, u64), String> {
    let mut file = File::open(path).map_err(|error| {
        format!(
            "open source bundle {} for read-back: {error}",
            path.display()
        )
    })?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read back source bundle {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| "source bundle read-back size overflow".to_owned())?;
    }
    Ok((hex_lower(&digest.finalize()), total))
}

#[derive(Debug)]
struct CentralDirectoryEntry {
    path: String,
    crc32: u32,
    size: u32,
    mode: u32,
    local_header_offset: u32,
}

fn write_zip<W: Write>(
    writer: &mut W,
    entries: &BTreeMap<String, PayloadEntry>,
) -> Result<(), String> {
    if entries.is_empty() {
        return Err("source bundle ZIP must contain at least one entry".to_owned());
    }
    let entry_count = u16::try_from(entries.len())
        .map_err(|_| "source bundle ZIP needs ZIP64 because it has too many entries".to_owned())?;
    let mut position = 0u64;
    let mut central_entries = Vec::with_capacity(entries.len());

    for (path, entry) in entries {
        validate_relative_path(path, false)?;
        let path_bytes = path.as_bytes();
        let path_length = u16::try_from(path_bytes.len())
            .map_err(|_| format!("source bundle ZIP path is too long for ZIP32: {path}"))?;
        let size = u32::try_from(entry.bytes.len())
            .map_err(|_| format!("source bundle ZIP entry is too large for ZIP32: {path}"))?;
        let local_header_offset = u32::try_from(position)
            .map_err(|_| format!("source bundle ZIP needs ZIP64 before local entry {path}"))?;
        let crc32 = crc32(&entry.bytes);

        write_u32(writer, &mut position, 0x0403_4b50)?;
        write_u16(writer, &mut position, 20)?;
        write_u16(writer, &mut position, ZIP_UTF8_FLAG)?;
        write_u16(writer, &mut position, 0)?;
        write_u16(writer, &mut position, ZIP_DOS_TIME)?;
        write_u16(writer, &mut position, ZIP_DOS_DATE)?;
        write_u32(writer, &mut position, crc32)?;
        write_u32(writer, &mut position, size)?;
        write_u32(writer, &mut position, size)?;
        write_u16(writer, &mut position, path_length)?;
        write_u16(writer, &mut position, 0)?;
        write_counted(writer, &mut position, path_bytes)?;
        write_counted(writer, &mut position, &entry.bytes)?;

        central_entries.push(CentralDirectoryEntry {
            path: path.clone(),
            crc32,
            size,
            mode: entry.mode,
            local_header_offset,
        });
    }

    let central_offset = u32::try_from(position)
        .map_err(|_| "source bundle ZIP central directory needs ZIP64".to_owned())?;
    for entry in &central_entries {
        let path_bytes = entry.path.as_bytes();
        let path_length = u16::try_from(path_bytes.len())
            .map_err(|_| format!("source bundle ZIP path is too long: {}", entry.path))?;
        write_u32(writer, &mut position, 0x0201_4b50)?;
        write_u16(writer, &mut position, 0x0314)?;
        write_u16(writer, &mut position, 20)?;
        write_u16(writer, &mut position, ZIP_UTF8_FLAG)?;
        write_u16(writer, &mut position, 0)?;
        write_u16(writer, &mut position, ZIP_DOS_TIME)?;
        write_u16(writer, &mut position, ZIP_DOS_DATE)?;
        write_u32(writer, &mut position, entry.crc32)?;
        write_u32(writer, &mut position, entry.size)?;
        write_u32(writer, &mut position, entry.size)?;
        write_u16(writer, &mut position, path_length)?;
        write_u16(writer, &mut position, 0)?;
        write_u16(writer, &mut position, 0)?;
        write_u16(writer, &mut position, 0)?;
        write_u16(writer, &mut position, 0)?;
        let unix_mode = (0o100000 | entry.mode) << 16;
        write_u32(writer, &mut position, unix_mode)?;
        write_u32(writer, &mut position, entry.local_header_offset)?;
        write_counted(writer, &mut position, path_bytes)?;
    }
    let central_size_u64 = position
        .checked_sub(u64::from(central_offset))
        .ok_or_else(|| "source bundle ZIP central directory offset underflow".to_owned())?;
    let central_size = u32::try_from(central_size_u64)
        .map_err(|_| "source bundle ZIP central directory needs ZIP64".to_owned())?;

    write_u32(writer, &mut position, 0x0605_4b50)?;
    write_u16(writer, &mut position, 0)?;
    write_u16(writer, &mut position, 0)?;
    write_u16(writer, &mut position, entry_count)?;
    write_u16(writer, &mut position, entry_count)?;
    write_u32(writer, &mut position, central_size)?;
    write_u32(writer, &mut position, central_offset)?;
    write_u16(writer, &mut position, 0)?;
    Ok(())
}

fn write_counted<W: Write>(writer: &mut W, position: &mut u64, bytes: &[u8]) -> Result<(), String> {
    writer
        .write_all(bytes)
        .map_err(|error| format!("write deterministic ZIP: {error}"))?;
    *position = position
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| "deterministic ZIP position overflow".to_owned())?;
    Ok(())
}

fn write_u16<W: Write>(writer: &mut W, position: &mut u64, value: u16) -> Result<(), String> {
    write_counted(writer, position, &value.to_le_bytes())
}

fn write_u32<W: Write>(writer: &mut W, position: &mut u64, value: u32) -> Result<(), String> {
    write_counted(writer, position, &value.to_le_bytes())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        let index = ((crc ^ u32::from(*byte)) & 0xff) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    !crc
}

const CRC32_TABLE: [u32; 256] = crc32_table();

const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0usize;
    while index < table.len() {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            let mask = 0u32.wrapping_sub(value & 1);
            value = (value >> 1) ^ (0xedb8_8320 & mask);
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(id: &str) -> MetadataPackage {
        MetadataPackage {
            id: id.to_owned(),
            name: id.to_owned(),
            version: "1.0.0".to_owned(),
            source: Some(REGISTRY_SOURCE.to_owned()),
            manifest_path: PathBuf::from(format!("/registry/{id}-1.0.0/Cargo.toml")),
        }
    }

    fn included_registry_package(
        name: &str,
        version: &str,
        manifest_path: &str,
        scopes: &[&str],
    ) -> (PackageKey, IncludedPackage) {
        let metadata = MetadataPackage {
            id: format!("{name}-{version}"),
            name: name.to_owned(),
            version: version.to_owned(),
            source: Some(REGISTRY_SOURCE.to_owned()),
            manifest_path: PathBuf::from(manifest_path),
        };
        (
            package_key(&metadata),
            IncludedPackage {
                metadata,
                scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            },
        )
    }

    fn dependency(id: &str, kinds: &[Option<&str>]) -> MetadataDependency {
        MetadataDependency {
            pkg: id.to_owned(),
            dep_kinds: kinds
                .iter()
                .map(|kind| MetadataDependencyKind {
                    kind: kind.map(str::to_owned),
                })
                .collect(),
        }
    }

    fn node(id: &str, dependencies: Vec<MetadataDependency>) -> MetadataNode {
        MetadataNode {
            id: id.to_owned(),
            dependencies: dependencies
                .iter()
                .map(|dependency| dependency.pkg.clone())
                .collect(),
            deps: dependencies,
        }
    }

    #[test]
    fn shared_preparation_preserves_mode_membership_and_unifies_common_package() {
        let (common_key, release_common) = included_registry_package(
            "common",
            "1.0.0",
            "/registry/common-1.0.0/Cargo.toml",
            &["autolisp-lsp"],
        );
        let (_, preview_common) = included_registry_package(
            "common",
            "1.0.0",
            "/registry/common-1.0.0/Cargo.toml",
            &["autocad-mcp"],
        );
        let (release_only_key, release_only) = included_registry_package(
            "release-only",
            "1.0.0",
            "/registry/release-only-1.0.0/Cargo.toml",
            &["autolisp-lsp"],
        );
        let (preview_only_key, preview_only) = included_registry_package(
            "preview-only",
            "1.0.0",
            "/registry/preview-only-1.0.0/Cargo.toml",
            &["autocad-mcp"],
        );

        let release = BTreeMap::from([
            (common_key.clone(), release_common),
            (release_only_key.clone(), release_only),
        ]);
        let preview = BTreeMap::from([
            (common_key.clone(), preview_common),
            (preview_only_key.clone(), preview_only),
        ]);
        let mut union = BTreeMap::new();

        merge_mode_packages_into_union(&mut union, &release)
            .expect("merge Release package inventory");
        merge_mode_packages_into_union(&mut union, &preview)
            .expect("merge Preview package inventory");

        assert_eq!(union.len(), 3);
        assert_eq!(
            union[&common_key].scopes,
            BTreeSet::from(["autocad-mcp".to_owned(), "autolisp-lsp".to_owned()])
        );
        assert_eq!(
            release[&common_key].scopes,
            BTreeSet::from(["autolisp-lsp".to_owned()])
        );
        assert_eq!(
            preview[&common_key].scopes,
            BTreeSet::from(["autocad-mcp".to_owned()])
        );
        assert!(release.contains_key(&release_only_key));
        assert!(!preview.contains_key(&release_only_key));
        assert!(preview.contains_key(&preview_only_key));
        assert!(!release.contains_key(&preview_only_key));
    }

    #[test]
    fn shared_preparation_rejects_cross_mode_manifest_disagreement() {
        let (key, release_package) = included_registry_package(
            "common",
            "1.0.0",
            "/release-cache/common-1.0.0/Cargo.toml",
            &["autolisp-lsp"],
        );
        let (_, preview_package) = included_registry_package(
            "common",
            "1.0.0",
            "/preview-cache/common-1.0.0/Cargo.toml",
            &["autocad-mcp"],
        );
        let release = BTreeMap::from([(key.clone(), release_package)]);
        let preview = BTreeMap::from([(key.clone(), preview_package)]);
        let mut union = BTreeMap::new();

        merge_mode_packages_into_union(&mut union, &release)
            .expect("merge Release package inventory");
        let error = merge_mode_packages_into_union(&mut union, &preview)
            .expect_err("reject cross-mode metadata disagreement");

        assert!(error.contains("Release and Preview metadata disagree"));
        assert_eq!(
            union[&key].metadata.manifest_path,
            PathBuf::from("/release-cache/common-1.0.0/Cargo.toml")
        );
        assert_eq!(
            union[&key].scopes,
            BTreeSet::from(["autolisp-lsp".to_owned()])
        );
    }

    #[test]
    fn shared_preparation_reuses_vendor_payload_without_copying() {
        let payload: Arc<[u8]> = Arc::from(&b"pub fn shared() {}\n"[..]);
        let exclusion = ExclusionManifest {
            package: "common".to_owned(),
            version: "1.0.0".to_owned(),
            path: "excluded.bin".to_owned(),
            sha256: "00".repeat(32),
            bytes: 1,
            reason: "test exclusion".to_owned(),
        };
        let prepared = PreparedVendorPackage {
            manifest: VendorManifest {
                path: "vendor/common-1.0.0".to_owned(),
                crate_archive_sha256: "11".repeat(32),
                file_count: 1,
                tree_sha256: "22".repeat(32),
            },
            files: vec![SourceFile {
                relative_path: "src/lib.rs".to_owned(),
                bytes: Arc::clone(&payload),
                mode: 0o644,
            }],
            exclusions: vec![exclusion.clone()],
            encountered_deny_rules: BTreeSet::from([0]),
            archived_manifest: Arc::from(&b"[package]\nname = \"common\"\n"[..]),
        };
        let mut release_archive = ArchiveEntries::default();
        let mut release_exclusions = Vec::new();
        let mut release_rules = BTreeSet::new();
        let mut preview_archive = ArchiveEntries::default();
        let mut preview_exclusions = Vec::new();
        let mut preview_rules = BTreeSet::new();

        apply_prepared_vendor(
            &prepared,
            &mut release_archive,
            &mut release_exclusions,
            &mut release_rules,
        )
        .expect("apply prepared vendor to Release");
        apply_prepared_vendor(
            &prepared,
            &mut preview_archive,
            &mut preview_exclusions,
            &mut preview_rules,
        )
        .expect("apply prepared vendor to Preview");

        let path = "vendor/common-1.0.0/src/lib.rs";
        let release_entry = &release_archive.entries[path];
        let preview_entry = &preview_archive.entries[path];
        assert!(Arc::ptr_eq(&payload, &release_entry.bytes));
        assert!(Arc::ptr_eq(&payload, &preview_entry.bytes));
        assert!(Arc::ptr_eq(&release_entry.bytes, &preview_entry.bytes));
        assert_eq!(release_entry.mode, 0o644);
        assert_eq!(preview_entry.mode, 0o644);
        assert_eq!(release_exclusions, vec![exclusion.clone()]);
        assert_eq!(preview_exclusions, vec![exclusion]);
        assert_eq!(release_rules, BTreeSet::from([0]));
        assert_eq!(preview_rules, BTreeSet::from([0]));
    }

    #[test]
    fn shared_preparation_evaluates_denylist_coverage_per_mode() {
        let (acadrust_key, acadrust) = included_registry_package(
            DENY_RULES[0].package,
            DENY_RULES[0].version,
            "/registry/acadrust-0.4.1/Cargo.toml",
            &["autocad-mcp"],
        );
        let (flate2_key, flate2) = included_registry_package(
            DENY_RULES[1].package,
            DENY_RULES[1].version,
            "/registry/flate2-1.1.9/Cargo.toml",
            &["autocad-mcp"],
        );
        let release = BTreeMap::from([
            (acadrust_key.clone(), acadrust.clone()),
            (flate2_key, flate2),
        ]);
        let preview = release.clone();
        let all_rules = (0..DENY_RULES.len()).collect::<BTreeSet<_>>();
        let preview_rules = BTreeSet::from([0]);

        validate_denylist_coverage(&release, &all_rules)
            .expect("Release has complete denylist evidence");
        let error = validate_denylist_coverage(&preview, &preview_rules)
            .expect_err("Preview must use its own denylist evidence");
        assert!(error.contains(DENY_RULES[1].relative_path));
        validate_denylist_coverage(&release, &all_rules)
            .expect("Preview failure must not consume Release evidence");

        let preview_without_flate2 = BTreeMap::from([(acadrust_key, acadrust)]);
        let error = validate_denylist_coverage(&preview_without_flate2, &all_rules)
            .expect_err("Preview inventory must contain every required package");
        assert!(error.contains("required denylist package flate2 1.1.9 is absent"));
    }

    #[test]
    fn clean_head_blobs_are_read_through_one_batch_protocol() {
        let repository = tempfile::tempdir().expect("temporary repository");
        git_bytes(repository.path(), &["init", "--quiet"]).expect("initialize repository");
        fs::write(repository.path().join("alpha.txt"), b"same bytes\n").expect("write first blob");
        fs::write(repository.path().join("beta.txt"), b"same bytes\n")
            .expect("write repeated blob");
        fs::write(repository.path().join("binary.bin"), [0, 1, 2, 0xff])
            .expect("write binary blob");
        git_bytes(repository.path(), &["add", "--", "."]).expect("stage fixture");
        git_bytes(
            repository.path(),
            &[
                "-c",
                "user.name=andagni",
                "-c",
                "user.email=dev@andagni.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        )
        .expect("commit fixture");

        let repository =
            fs::canonicalize(repository.path()).expect("canonical temporary repository");
        let head = head_commit(&repository).expect("read fixture HEAD");
        let tree = read_head_tree(&repository, &head).expect("read fixture tree");
        let blobs = read_head_blobs(&repository, &tree).expect("batch-read fixture blobs");

        assert_eq!(blobs.len(), 3);
        assert_eq!(blobs["alpha.txt"], b"same bytes\n");
        assert_eq!(blobs["beta.txt"], b"same bytes\n");
        assert_eq!(blobs["binary.bin"], [0, 1, 2, 0xff]);
    }

    #[test]
    fn closure_includes_normal_and_build_but_excludes_development_edges() {
        let root = MetadataPackage {
            id: "root".to_owned(),
            name: "autocad-mcp".to_owned(),
            version: "0.0.1".to_owned(),
            source: None,
            manifest_path: PathBuf::from("/repo/crates/autocad-mcp/Cargo.toml"),
        };
        let metadata = CargoMetadata {
            packages: vec![
                root,
                package("normal"),
                package("build"),
                package("development"),
                package("transitive"),
            ],
            resolve: MetadataResolve {
                root: Some("root".to_owned()),
                nodes: vec![
                    node(
                        "root",
                        vec![
                            dependency("normal", &[None]),
                            dependency("build", &[Some("build")]),
                            dependency("development", &[Some("dev")]),
                        ],
                    ),
                    node(
                        "normal",
                        vec![dependency("transitive", &[None, Some("dev")])],
                    ),
                    node("build", vec![]),
                    node("development", vec![]),
                    node("transitive", vec![]),
                ],
            },
        };
        let closure = derive_closure(&metadata, ROOTS[0]).expect("derive closure");
        assert_eq!(
            closure,
            BTreeSet::from([
                "build".to_owned(),
                "normal".to_owned(),
                "root".to_owned(),
                "transitive".to_owned(),
            ])
        );
    }

    #[test]
    fn closure_rejects_unknown_dependency_kind() {
        let error = include_dependency(&dependency("package", &[Some("future-kind")]))
            .expect_err("unknown kind must fail closed");
        assert!(error.contains("unknown dependency kind future-kind"));
    }

    #[test]
    fn cargo_lock_parser_keys_packages_by_exact_source() {
        let lock = br#"
version = 4

[[package]]
name = "workspace"
version = "0.1.0"

[[package]]
name = "registry"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
dependencies = [
 "workspace",
]
"#;
        let packages = parse_cargo_lock(lock).expect("parse lock");
        assert_eq!(packages.len(), 2);
        assert_eq!(
            packages
                .get(&PackageKey {
                    name: "registry".to_owned(),
                    version: "1.2.3".to_owned(),
                    source: Some(REGISTRY_SOURCE.to_owned()),
                })
                .and_then(|package| package.checksum.as_deref()),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn third_party_license_policy_identity_must_match_the_bundled_lock() {
        let lock_sha256 = "a".repeat(64);
        let input_closure_sha256 = "b".repeat(64);
        let policy = serde_json::to_vec(&serde_json::json!({
            "reviewed_cargo_lock_sha256": lock_sha256,
            "reviewed_input_closure_sha256": input_closure_sha256,
        }))
        .unwrap();
        assert_eq!(
            reviewed_dependency_input_closure(&policy, &"a".repeat(64)).unwrap(),
            "b".repeat(64)
        );
        assert!(reviewed_dependency_input_closure(&policy, &"c".repeat(64)).is_err());
    }

    #[test]
    fn workspace_source_files_include_tracked_release_tool_inputs_verbatim() {
        let tree = vec![
            GitTreeEntry {
                path: "crates/distribution/packager/tools/mcpb-validator/package.json".to_owned(),
                object_id: "package-object".to_owned(),
                mode: 0o644,
            },
            GitTreeEntry {
                path: "crates/distribution/packager/tools/mcpb-validator/package-lock.json"
                    .to_owned(),
                object_id: "lock-object".to_owned(),
                mode: 0o644,
            },
        ];
        let blobs = BTreeMap::from([
            (
                "crates/distribution/packager/tools/mcpb-validator/package.json".to_owned(),
                b"{\"private\":true}\n".to_vec(),
            ),
            (
                "crates/distribution/packager/tools/mcpb-validator/package-lock.json".to_owned(),
                b"{\"lockfileVersion\":3}\n".to_vec(),
            ),
        ]);

        let files = workspace_source_files(&tree, &blobs).expect("collect workspace source files");
        assert_eq!(files.len(), 2);
        for (index, entry) in tree.iter().enumerate() {
            assert_eq!(files[index].relative_path, entry.path);
            assert_eq!(files[index].bytes.as_ref(), blobs[&entry.path].as_slice());
            assert_eq!(files[index].mode, entry.mode);
        }
    }

    #[test]
    fn workspace_source_files_include_hidden_machine_evidence_verbatim() {
        let tree = vec![
            GitTreeEntry {
                path: "plugin/.third-party/third-party-license-policy.json".to_owned(),
                object_id: "policy-object".to_owned(),
                mode: 0o644,
            },
            GitTreeEntry {
                path: "plugin/.third-party/license-supplements/rmcp-1.7.0-LICENSE.txt".to_owned(),
                object_id: "supplement-object".to_owned(),
                mode: 0o644,
            },
        ];
        let blobs = BTreeMap::from([
            (
                "plugin/.third-party/third-party-license-policy.json".to_owned(),
                b"{\"schema_version\":2}\n".to_vec(),
            ),
            (
                "plugin/.third-party/license-supplements/rmcp-1.7.0-LICENSE.txt".to_owned(),
                b"supplement\n".to_vec(),
            ),
        ]);

        let files = workspace_source_files(&tree, &blobs).expect("collect hidden evidence files");
        assert_eq!(files.len(), tree.len());
        for (index, entry) in tree.iter().enumerate() {
            assert_eq!(files[index].relative_path, entry.path);
            assert_eq!(files[index].bytes.as_ref(), blobs[&entry.path].as_slice());
        }
    }

    #[test]
    fn paths_reject_traversal_windows_devices_and_case_collisions() {
        assert!(validate_relative_path("../escape", false).is_err());
        assert!(validate_relative_path("safe/../../escape", false).is_err());
        assert!(validate_relative_path("safe\\escape", false).is_err());
        assert!(validate_relative_path("vendor/con/file", false).is_err());
        assert!(validate_relative_path("vendor/name:stream", false).is_err());
        assert!(validate_relative_path("vendor/non-ascii-\u{e9}.rs", false).is_err());
        for forbidden in ['<', '>', '"', '|', '?', '*'] {
            assert!(
                validate_relative_path(&format!("vendor/bad{forbidden}name.rs"), false).is_err()
            );
        }
        assert!(
            validate_relative_path(&"a".repeat(MAX_WINDOWS_COMPONENT_BYTES + 1), false).is_err()
        );
        let overlong_path = format!("{}/{}", "a".repeat(120), "b".repeat(120));
        assert!(validate_relative_path(&overlong_path, false).is_err());

        let mut archive = ArchiveEntries::default();
        archive
            .insert("vendor/Case.rs".to_owned(), vec![], 0o644)
            .expect("first path");
        assert!(archive
            .insert("vendor/case.rs".to_owned(), vec![], 0o644)
            .is_err());

        let mut ancestor_first = ArchiveEntries::default();
        ancestor_first
            .insert("vendor/file".to_owned(), vec![], 0o644)
            .expect("ancestor file");
        assert!(ancestor_first
            .insert("vendor/file/child".to_owned(), vec![], 0o644)
            .is_err());

        let mut descendant_first = ArchiveEntries::default();
        descendant_first
            .insert("vendor/File/child".to_owned(), vec![], 0o644)
            .expect("descendant file");
        assert!(descendant_first
            .insert("vendor/file".to_owned(), vec![], 0o644)
            .is_err());
    }

    #[test]
    fn metadata_environment_is_bound_to_cargo_home_and_the_pinned_toolchain() {
        assert!(is_ambient_cargo_or_rust_override("CARGO_TARGET_DIR"));
        assert!(is_ambient_cargo_or_rust_override(
            "CARGO_REGISTRIES_CRATES_IO_INDEX"
        ));
        assert!(is_ambient_cargo_or_rust_override("RUSTFLAGS"));
        assert!(is_ambient_cargo_or_rust_override("RUSTUP_TOOLCHAIN"));
        assert!(!is_ambient_cargo_or_rust_override("CARGO_HOME"));
        assert!(!is_ambient_cargo_or_rust_override("RUSTUP_HOME"));

        assert!(exact_tool_version_matches(
            "cargo 1.97.0 (abcdef 2026-01-01)",
            "cargo",
            "1.97.0"
        ));
        assert!(!exact_tool_version_matches(
            "cargo 1.96.0 (abcdef 2025-01-01)",
            "cargo",
            "1.97.0"
        ));
        assert!(validate_exact_toolchain_channel("1.97.0").is_ok());
        assert!(validate_exact_toolchain_channel("stable").is_err());
        assert!(validate_exact_toolchain_channel("1.097.0").is_err());

        assert!(require_git_oid(&"a".repeat(40), 40, "test SHA-1").is_ok());
        assert!(require_git_oid(&"b".repeat(64), 64, "test SHA-256").is_ok());
        assert!(require_git_oid(&"a".repeat(39), 40, "short OID").is_err());
        assert!(require_git_oid(&"A".repeat(40), 40, "uppercase OID").is_err());
    }

    #[test]
    fn exact_inert_cargo_configuration_is_safe_at_a_linked_worktree_ancestor() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let ancestor_config = directory.path().join("config.toml");
        fs::write(&ancestor_config, ALLOWED_REPOSITORY_CARGO_CONFIG)
            .expect("write exact inert configuration");
        let metadata = fs::symlink_metadata(&ancestor_config).expect("inspect configuration");
        let linked_worktree_config = directory
            .path()
            .join("worktree")
            .join(".cargo")
            .join("config.toml");
        let common_checkout_config = directory
            .path()
            .join("common")
            .join(".cargo")
            .join("config.toml");

        validate_cargo_configuration_file(
            &ancestor_config,
            &linked_worktree_config,
            Some(&common_checkout_config),
            &metadata,
        )
        .expect("exact inert ancestor configuration must be admitted");

        fs::write(&ancestor_config, b"[build]\nincremental = true\n")
            .expect("replace with unsafe configuration");
        let metadata = fs::symlink_metadata(&ancestor_config).expect("inspect replacement");
        let error = validate_cargo_configuration_file(
            &ancestor_config,
            &linked_worktree_config,
            Some(&common_checkout_config),
            &metadata,
        )
        .expect_err("ambient override must remain rejected");
        assert!(error.contains("rejects ambient Cargo configuration"));
    }

    #[test]
    fn exact_common_checkout_shared_target_configuration_is_narrowly_admitted() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let common_cargo_directory = directory.path().join(".cargo");
        fs::create_dir(&common_cargo_directory).expect("create common Cargo directory");
        let common_checkout_config = common_cargo_directory.join("config.toml");
        fs::write(
            &common_checkout_config,
            ALLOWED_COMMON_CHECKOUT_CARGO_CONFIG,
        )
        .expect("write exact common-checkout configuration");
        let metadata =
            fs::symlink_metadata(&common_checkout_config).expect("inspect configuration");
        let repository_config = directory
            .path()
            .join("worktree")
            .join(".cargo")
            .join("config.toml");

        validate_cargo_configuration_file(
            &common_checkout_config,
            &repository_config,
            Some(&common_checkout_config),
            &metadata,
        )
        .expect("exact common-checkout shared-target configuration must be admitted");

        fs::create_dir_all(
            repository_config
                .parent()
                .expect("repository configuration parent"),
        )
        .expect("create linked-worktree Cargo directory");
        fs::write(&repository_config, ALLOWED_COMMON_CHECKOUT_CARGO_CONFIG)
            .expect("write linked-worktree shared-target configuration");
        let metadata =
            fs::symlink_metadata(&repository_config).expect("inspect linked configuration");
        let error = validate_cargo_configuration_file(
            &repository_config,
            &repository_config,
            Some(&common_checkout_config),
            &metadata,
        )
        .expect_err("shared-target policy must not be admitted at the linked worktree root");
        assert!(error.contains("not the exact inert incremental-compilation policy"));

        let ambient_config = directory.path().join("ambient-config.toml");
        fs::write(&ambient_config, ALLOWED_COMMON_CHECKOUT_CARGO_CONFIG)
            .expect("write ambient shared-target configuration");
        let metadata =
            fs::symlink_metadata(&ambient_config).expect("inspect ambient configuration");
        let error = validate_cargo_configuration_file(
            &ambient_config,
            &repository_config,
            Some(&common_checkout_config),
            &metadata,
        )
        .expect_err("shared-target policy must not be admitted at an arbitrary ancestor");
        assert!(error.contains("rejects ambient Cargo configuration"));

        let legacy_common_config = common_cargo_directory.join("config");
        fs::write(&legacy_common_config, ALLOWED_COMMON_CHECKOUT_CARGO_CONFIG)
            .expect("write legacy-named common configuration");
        let metadata =
            fs::symlink_metadata(&legacy_common_config).expect("inspect legacy configuration");
        let error = validate_cargo_configuration_file(
            &legacy_common_config,
            &repository_config,
            Some(&common_checkout_config),
            &metadata,
        )
        .expect_err("shared-target policy must require the exact config.toml path");
        assert!(error.contains("rejects ambient Cargo configuration"));

        fs::write(
            &common_checkout_config,
            b"[build]\ntarget-dir = \"other-target\"\nincremental = false\n",
        )
        .expect("replace common-checkout configuration");
        let metadata = fs::symlink_metadata(&common_checkout_config).expect("inspect replacement");
        let error = validate_cargo_configuration_file(
            &common_checkout_config,
            &repository_config,
            Some(&common_checkout_config),
            &metadata,
        )
        .expect_err("different common-checkout target policy must remain rejected");
        assert!(error.contains("not the exact shared-target, non-incremental policy"));
    }

    #[test]
    fn real_linked_worktree_admits_only_the_common_checkout_shared_target() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let primary = directory.path().join("primary");
        fs::create_dir(&primary).expect("create primary checkout");
        git_bytes(&primary, &["init"]).expect("initialize primary Git checkout");
        fs::write(primary.join(".gitignore"), b".cargo/\n.worktrees/\n")
            .expect("write primary ignore policy");
        fs::write(primary.join("README.md"), b"linked-worktree fixture\n")
            .expect("write tracked fixture");
        git_bytes(&primary, &["add", ".gitignore", "README.md"]).expect("stage primary fixture");
        git_bytes(
            &primary,
            &[
                "-c",
                "user.name=andagni",
                "-c",
                "user.email=dev@andagni.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        )
        .expect("commit primary fixture");

        let linked = primary.join(".worktrees").join("linked");
        let linked_text = linked.to_str().expect("temporary path must be UTF-8");
        git_bytes(
            &primary,
            &["worktree", "add", "--detach", linked_text, "HEAD"],
        )
        .expect("create linked Git worktree");

        let common_cargo_directory = primary.join(".cargo");
        fs::create_dir(&common_cargo_directory).expect("create common Cargo directory");
        let common_checkout_config = common_cargo_directory.join("config.toml");
        fs::write(
            &common_checkout_config,
            ALLOWED_COMMON_CHECKOUT_CARGO_CONFIG,
        )
        .expect("write common-checkout shared-target configuration");

        let canonical_primary = fs::canonicalize(&primary).expect("canonicalize primary checkout");
        let canonical_linked = fs::canonicalize(&linked).expect("canonicalize linked worktree");
        assert_eq!(
            common_checkout_cargo_configuration(&canonical_linked)
                .expect("discover common-checkout Cargo configuration"),
            Some(canonical_primary.join(".cargo").join("config.toml"))
        );
        ensure_controlled_cargo_configuration(&canonical_linked)
            .expect("admit the exact common-checkout shared-target policy");

        let linked_cargo_directory = canonical_linked.join(".cargo");
        fs::create_dir(&linked_cargo_directory).expect("create linked Cargo directory");
        fs::write(
            linked_cargo_directory.join("config.toml"),
            ALLOWED_COMMON_CHECKOUT_CARGO_CONFIG,
        )
        .expect("write forbidden linked-worktree shared-target configuration");
        let error = ensure_controlled_cargo_configuration(&canonical_linked)
            .expect_err("reject shared-target policy outside the common checkout");
        assert!(error.contains("not the exact inert incremental-compilation policy"));
    }

    #[test]
    fn denylist_matches_only_exact_package_version_and_path() {
        assert_eq!(
            matching_deny_rule(
                "acadrust",
                "0.4.1",
                "src/docs/OpenDesign_Specification_for_.dwg_files.pdf"
            )
            .map(|(index, rule)| (index, rule.expected_bytes, rule.expected_sha256)),
            Some((
                0,
                2_399_640,
                "1ed2e02722862188120da606e4b6a816fa4014c96de68da2f84a2ecda09461e7"
            ))
        );
        assert!(matching_deny_rule(
            "acadrust",
            "0.4.0",
            "src/docs/OpenDesign_Specification_for_.dwg_files.pdf"
        )
        .is_none());
        assert!(matching_deny_rule("acadrust", "0.4.1", "src/docs/other.pdf").is_none());
    }

    fn write_tar_octal(field: &mut [u8], value: u64) {
        field.fill(b'0');
        let digits = format!("{value:o}");
        let start = field.len() - 1 - digits.len();
        field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
        field[field.len() - 1] = 0;
    }

    fn tar_with_entry(path: &str, type_flag: u8, contents: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        assert!(path.len() <= 100);
        header[..path.len()].copy_from_slice(path.as_bytes());
        write_tar_octal(&mut header[100..108], 0o644);
        write_tar_octal(&mut header[108..116], 0);
        write_tar_octal(&mut header[116..124], 0);
        write_tar_octal(&mut header[124..136], contents.len() as u64);
        write_tar_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = type_flag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        let checksum_text = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum_text.as_bytes());

        let mut tar = header.to_vec();
        tar.extend_from_slice(contents);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
        tar.resize(tar.len() + 1024, 0);
        tar
    }

    #[test]
    fn ustar_parser_accepts_regular_file_and_rejects_unsafe_or_special_entries() {
        let tar = tar_with_entry("crate-1.0.0/src/lib.rs", b'0', b"pub fn ok() {}\n");
        let entries = parse_ustar(&tar, "crate-1.0.0").expect("parse safe ustar");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].relative_path, "src/lib.rs");
        assert_eq!(entries[0].bytes, b"pub fn ok() {}\n");

        let traversal = tar_with_entry("crate-1.0.0/../escape", b'0', b"bad");
        assert!(parse_ustar(&traversal, "crate-1.0.0").is_err());
        let symlink = tar_with_entry("crate-1.0.0/link", b'2', b"");
        assert!(parse_ustar(&symlink, "crate-1.0.0").is_err());
    }

    #[test]
    fn ustar_parser_safely_consumes_gnu_long_name_records() {
        let long_path =
            "crate-1.0.0/tests/snapshots/a-very-long-name-that-cannot-fit-in-the-header.rs";
        let mut long_name_bytes = long_path.as_bytes().to_vec();
        long_name_bytes.push(0);
        let mut tar = tar_with_entry("././@LongLink", b'L', &long_name_bytes);
        tar.truncate(tar.len() - 1024);
        tar.extend_from_slice(&tar_with_entry("crate-1.0.0/truncated", b'0', b"contents"));
        let entries = parse_ustar(&tar, "crate-1.0.0").expect("parse GNU long name");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].relative_path,
            "tests/snapshots/a-very-long-name-that-cannot-fit-in-the-header.rs"
        );

        let mut unsafe_name = tar_with_entry("././@LongLink", b'L', b"crate-1.0.0/../escape\0");
        unsafe_name.truncate(unsafe_name.len() - 1024);
        unsafe_name.extend_from_slice(&tar_with_entry("crate-1.0.0/truncated", b'0', b"contents"));
        assert!(parse_ustar(&unsafe_name, "crate-1.0.0").is_err());
    }

    #[test]
    fn deterministic_zip_is_sorted_stored_and_uses_fixed_metadata() {
        let entries = BTreeMap::from([
            (
                "b.txt".to_owned(),
                PayloadEntry {
                    bytes: Arc::from(b"second".as_slice()),
                    mode: 0o755,
                },
            ),
            (
                "a.txt".to_owned(),
                PayloadEntry {
                    bytes: Arc::from(b"first".as_slice()),
                    mode: 0o644,
                },
            ),
        ]);
        let mut first = Vec::new();
        write_zip(&mut first, &entries).expect("write first ZIP");
        let mut second = Vec::new();
        write_zip(&mut second, &entries).expect("write second ZIP");
        assert_eq!(first, second);
        assert_eq!(
            u32::from_le_bytes(first[0..4].try_into().unwrap()),
            0x0403_4b50
        );
        assert_eq!(
            u16::from_le_bytes(first[6..8].try_into().unwrap()),
            ZIP_UTF8_FLAG
        );
        assert_eq!(u16::from_le_bytes(first[8..10].try_into().unwrap()), 0);
        assert_eq!(
            u16::from_le_bytes(first[10..12].try_into().unwrap()),
            ZIP_DOS_TIME
        );
        assert_eq!(
            u16::from_le_bytes(first[12..14].try_into().unwrap()),
            ZIP_DOS_DATE
        );
        let path_length = usize::from(u16::from_le_bytes(first[26..28].try_into().unwrap()));
        assert_eq!(&first[30..30 + path_length], b"a.txt");
        assert_eq!(
            u32::from_le_bytes(
                first[first.len() - 22..first.len() - 18]
                    .try_into()
                    .unwrap()
            ),
            0x0605_4b50
        );
    }

    #[test]
    fn failed_post_write_snapshot_verification_removes_only_the_new_archive() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archive = directory.path().join("source.zip");
        let unrelated = directory.path().join("unrelated.zip");
        fs::write(&archive, b"new source archive").expect("write source archive");
        fs::write(&unrelated, b"unrelated archive").expect("write unrelated archive");

        let error = remove_invalid_archive(&archive, "HEAD changed".to_owned());

        assert_eq!(error, "HEAD changed");
        assert!(!archive.exists());
        assert_eq!(
            fs::read(&unrelated).expect("read unrelated archive"),
            b"unrelated archive"
        );
    }

    #[test]
    fn crc32_matches_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn cargo_checksum_json_is_stable_and_excludes_absent_files() {
        let files = BTreeMap::from([
            ("Cargo.toml".to_owned(), "aa".repeat(32)),
            ("src/lib.rs".to_owned(), "bb".repeat(32)),
        ]);
        let bytes = serde_json::to_vec(&CargoChecksum {
            files: &files,
            package: &"cc".repeat(32),
        })
        .expect("serialize Cargo checksum");
        let text = String::from_utf8(bytes).expect("UTF-8 JSON");
        assert_eq!(
            text,
            format!(
                "{{\"files\":{{\"Cargo.toml\":\"{}\",\"src/lib.rs\":\"{}\"}},\"package\":\"{}\"}}",
                "aa".repeat(32),
                "bb".repeat(32),
                "cc".repeat(32)
            )
        );
        assert!(!text.contains("corrupt-gz-file.bin"));
    }

    #[test]
    fn offline_recipe_disables_incremental_and_uses_static_msvc_crt() {
        let config = String::from_utf8(offline_cargo_config()).unwrap();
        assert!(config.contains("incremental = false"));
        assert!(config.contains("offline = true"));

        let source_commit = "a".repeat(40);
        let instructions = String::from_utf8(
            render_windows_x86_64_build_recipe(
                "1.97.0",
                GitObjectFormat::Sha1,
                &source_commit,
                DistributionMode::Release,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!instructions.contains("rustup toolchain install"));
        assert!(instructions.contains("Rust toolchain 1.97.0 already installed"));
        assert!(instructions.contains(
            "required Windows-only acceptance gate: extract this archive on a clean Windows"
        ));
        assert!(instructions.contains("extract at a short ASCII path such as C:\\acmcp-source"));
        assert!(instructions.contains("ambient Cargo configuration is forbidden"));
        assert!(instructions.contains(
            "$env:AUTOCAD_MCP_SOURCE_COMMIT = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
        ));
        assert!(instructions.contains("$env:CARGO_HOME = $isolatedCargoHome"));
        assert!(instructions.contains("$env:CARGO_INCREMENTAL = \"0\""));
        assert!(instructions.contains(
            "$env:CARGO_ENCODED_RUSTFLAGS = \"-C$([char]0x1f)target-feature=+crt-static\""
        ));
        let exact_build = "cargo +1.97.0 build --locked --offline --release --target x86_64-pc-windows-msvc -p autocad-mcp --bin autocad-mcp --no-default-features -p autolisp-lsp --bin autolisp-lsp";
        assert!(instructions.contains(exact_build));
        assert_eq!(instructions.matches("cargo +1.97.0 build ").count(), 1);
    }

    #[test]
    fn workspace_package_inventory_is_exact() {
        assert_eq!(ROOTS.len(), 2);
        assert_eq!(
            ALLOWED_WORKSPACE_PACKAGES,
            [
                ("autocad-mcp", "crates/autocad-mcp/Cargo.toml"),
                ("autocad-reader", "crates/autocad-reader/Cargo.toml"),
                ("autocad-writer", "crates/autocad-writer/Cargo.toml"),
                ("autolisp-lsp", "crates/autolisp-lsp/Cargo.toml"),
                ("autolisp-validate", "crates/autolisp-validate/Cargo.toml"),
            ]
        );
        assert!(
            ROOTS.iter().all(|root| root.name != "autocad-reader"),
            "autocad-reader is dependency closure, not a third product root"
        );
        assert!(
            ROOTS.iter().all(|root| root.name != "autocad-writer"),
            "autocad-writer is dependency closure, not a third product root"
        );
    }

    #[test]
    fn preview_metadata_and_recipe_bind_the_preview_feature() {
        assert_eq!(
            metadata_arguments(ROOTS[0], DistributionMode::Preview),
            [
                "metadata",
                "--locked",
                "--offline",
                "--format-version",
                "1",
                "--filter-platform",
                WINDOWS_TARGET,
                "--no-default-features",
                "--features",
                "preview",
                "--manifest-path",
                "crates/autocad-mcp/Cargo.toml",
            ]
        );
        assert!(!metadata_arguments(ROOTS[1], DistributionMode::Preview)
            .iter()
            .any(|argument| argument == "--features"));
    }
}
