use crate::source_bundle::{self, SourceBundleSummary};
use distribution_approval::DistributionMode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const SEAL_SCHEMA_VERSION: u32 = 3;
const SEAL_ARTIFACT_KIND: &str = "autocad-mcp-source-candidate";
const SEAL_SCOPE: &str = "source_only_development";
const DISTRIBUTION_EVIDENCE_STATUS: &str = "reviewed_bytes_revalidated";
const SCRATCH_ROOT: &str = "target";
const SOURCE_BUNDLE_FILENAME: &str = "source.zip";
const SEAL_FILENAME: &str = "candidate-seal.json";
const SOURCE_BUNDLE_MANIFEST_PATH: &str = "source-bundle-manifest.json";
const SOURCE_BUNDLE_MANIFEST_SCHEMA_VERSION: u32 = 3;
const SOURCE_BUNDLE_ARTIFACT_KIND: &str = "autocad-mcp-windows-x86_64-build-source";
const ZIP_UTF8_FLAG: u16 = 0x0800;
const MAX_SEAL_BYTES: u64 = 64 * 1024;
const MAX_MANIFEST_BYTES: u32 = 8 * 1024 * 1024;
const MAX_ZIP_PATH_BYTES: usize = 4096;
const INVALIDATED_RELEASE_EVIDENCE: [&str; 8] = [
    "release_package",
    "preview_package",
    "windows_native_build_attestation",
    "autocad_host_certification",
    "code_signature",
    "clean_host_application_acceptance",
    "owner_distribution_approval",
    "publication_projection_receipt",
];

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateIdentity {
    pub git_object_format: String,
    pub source_commit: String,
    pub source_tree_oid: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceBundleBinding {
    relative_path: String,
    sha256: String,
    bytes: u64,
    manifest_sha256: String,
    cargo_lock_sha256: String,
    dependency_input_closure_sha256: String,
    rust_toolchain_sha256: String,
    build_recipe_sha256: String,
    archive_entries: usize,
    closure_packages: usize,
    vendored_packages: usize,
    excluded_files: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceCandidateSeal {
    schema_version: u32,
    artifact_kind: String,
    scope: String,
    release_authority: bool,
    distribution_evidence_status: String,
    package_mode: DistributionMode,
    candidate: CandidateIdentity,
    source_bundle: SourceBundleBinding,
    invalidated_release_evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SourceBundleManifestIdentity {
    schema_version: u32,
    artifact_kind: String,
    git_object_format: String,
    source_commit: String,
    source_tree_oid: String,
    cargo_lock_sha256: String,
    dependency_input_closure_sha256: String,
    rust_toolchain_sha256: String,
    build_recipe_sha256: String,
    package_mode: DistributionMode,
}

#[derive(Debug)]
struct InspectedBundle {
    sha256: String,
    bytes: u64,
    archive_entries: usize,
    manifest_sha256: String,
    manifest: SourceBundleManifestIdentity,
}

#[derive(Debug, Serialize)]
pub struct SourceCandidateSummary {
    pub output_directory: PathBuf,
    pub candidate: CandidateIdentity,
    pub source_bundle_sha256: String,
    pub source_bundle_bytes: u64,
    pub source_bundle_manifest_sha256: String,
    pub package_mode: DistributionMode,
    pub release_authority: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceCandidateVerification {
    pub current: bool,
    pub exact_commit_and_tree: bool,
    pub source_bundle_verified: bool,
    pub release_authority: bool,
    pub package_mode: DistributionMode,
    pub candidate: CandidateIdentity,
    pub source_bundle_sha256: String,
    pub source_bundle_manifest_sha256: String,
    pub cargo_lock_sha256: String,
    pub dependency_input_closure_sha256: String,
    pub rust_toolchain_sha256: String,
    pub build_recipe_sha256: String,
}

pub fn run(repository: &Path, output_directory: &Path) -> Result<SourceCandidateSummary, String> {
    run_for_mode(repository, output_directory, DistributionMode::Release)
}

pub fn run_for_mode(
    repository: &Path,
    output_directory: &Path,
    package_mode: DistributionMode,
) -> Result<SourceCandidateSummary, String> {
    run_internal(repository, output_directory, true, package_mode)
}

fn run_internal(
    repository: &Path,
    output_directory: &Path,
    retain_output: bool,
    package_mode: DistributionMode,
) -> Result<SourceCandidateSummary, String> {
    populate_locked_sources(repository)?;
    let before = capture_current_identity(repository)?;
    distribution_evidence::check(repository)
        .map_err(|error| format!("revalidate reviewed distribution evidence: {error}"))?;
    require_current_identity(repository, &before, "distribution evidence validation")?;
    let prepared = source_bundle::prepare_for_modes(repository, &[package_mode])?;
    run_with_generator_retention(
        repository,
        output_directory,
        before,
        retain_output,
        package_mode,
        |bundle_path| {
            source_bundle::write_prepared_for_mode(
                &prepared,
                bundle_path,
                package_mode,
                retain_output,
            )
        },
    )
}

pub fn verify(
    repository: &Path,
    candidate_directory: &Path,
) -> Result<SourceCandidateVerification, String> {
    let (verification, seal) = verify_recorded_candidate(repository, candidate_directory)?;
    populate_locked_sources(repository)?;
    distribution_evidence::check(repository)
        .map_err(|error| format!("revalidate reviewed distribution evidence: {error}"))?;
    require_current_identity(
        repository,
        &verification.candidate,
        "candidate distribution-evidence revalidation",
    )?;

    let regenerated_directory = visible_scratch_directory(repository)?;
    let owned = OwnedCandidateDirectory::create(&regenerated_directory)?;
    let regeneration = (|| {
        let regenerated_path = owned.path().join(SOURCE_BUNDLE_FILENAME);
        let regenerated =
            source_bundle::run_for_mode(repository, &regenerated_path, seal.package_mode)?;
        let regenerated_identity = CandidateIdentity {
            git_object_format: regenerated.git_object_format.clone(),
            source_commit: regenerated.source_commit.clone(),
            source_tree_oid: regenerated.source_tree_oid.clone(),
        };
        if regenerated_identity != verification.candidate
            || source_bundle_binding(regenerated) != seal.source_bundle
        {
            return Err(
                "fresh deterministic source bundle does not match the retained candidate"
                    .to_owned(),
            );
        }
        Ok(())
    })();
    let cleanup = owned.cleanup();
    match (regeneration, cleanup) {
        (Ok(()), Ok(())) => {}
        (Err(error), Ok(())) => return Err(error),
        (Ok(()), Err(cleanup)) => return Err(cleanup),
        (Err(error), Err(cleanup)) => return Err(format!("{error}; additionally {cleanup}")),
    }
    require_current_identity(
        repository,
        &verification.candidate,
        "candidate regeneration verification",
    )?;
    let (final_verification, final_seal) =
        verify_recorded_candidate(repository, candidate_directory)?;
    if final_verification != verification || final_seal != seal {
        return Err("retained candidate changed during independent regeneration".to_owned());
    }
    Ok(final_verification)
}

pub fn verify_for_mode(
    repository: &Path,
    candidate_directory: &Path,
    package_mode: DistributionMode,
) -> Result<SourceCandidateVerification, String> {
    let recorded = recheck_recorded_current(repository, candidate_directory)?;
    if recorded.package_mode != package_mode {
        return Err(format!(
            "source candidate mode {} does not match requested mode {}",
            recorded.package_mode.as_str(),
            package_mode.as_str()
        ));
    }
    verify(repository, candidate_directory)
}

pub(crate) fn recheck_recorded_current(
    repository: &Path,
    candidate_directory: &Path,
) -> Result<SourceCandidateVerification, String> {
    verify_recorded_candidate(repository, candidate_directory).map(|(verification, _)| verification)
}

fn verify_recorded_candidate(
    repository: &Path,
    candidate_directory: &Path,
) -> Result<(SourceCandidateVerification, SourceCandidateSeal), String> {
    let directory = canonical_real_directory(candidate_directory, "candidate directory")?;
    validate_candidate_directory_inventory(&directory)?;
    let seal = read_seal(&directory.join(SEAL_FILENAME))?;
    validate_seal_shape(&seal)?;

    let current_before = capture_current_identity(repository)?;
    if current_before != seal.candidate {
        return Err(format!(
            "candidate was sealed for commit {} tree {}, but the current clean source is commit {} tree {}; regenerate the candidate",
            seal.candidate.source_commit,
            seal.candidate.source_tree_oid,
            current_before.source_commit,
            current_before.source_tree_oid
        ));
    }

    let bundle_path = directory.join(SOURCE_BUNDLE_FILENAME);
    let inspected = inspect_source_bundle(&bundle_path)?;
    verify_bundle_binding(&seal, &inspected)?;
    require_current_identity(repository, &current_before, "candidate verification")?;

    let verification = SourceCandidateVerification {
        current: true,
        exact_commit_and_tree: true,
        source_bundle_verified: true,
        release_authority: false,
        package_mode: seal.package_mode,
        candidate: current_before,
        source_bundle_sha256: seal.source_bundle.sha256.clone(),
        source_bundle_manifest_sha256: seal.source_bundle.manifest_sha256.clone(),
        cargo_lock_sha256: seal.source_bundle.cargo_lock_sha256.clone(),
        dependency_input_closure_sha256: seal.source_bundle.dependency_input_closure_sha256.clone(),
        rust_toolchain_sha256: seal.source_bundle.rust_toolchain_sha256.clone(),
        build_recipe_sha256: seal.source_bundle.build_recipe_sha256.clone(),
    };
    Ok((verification, seal))
}

fn validate_candidate_directory_inventory(directory: &Path) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("enumerate candidate directory: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("read candidate directory entry: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "candidate directory entry name is not UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    if entries == [SEAL_FILENAME, SOURCE_BUNDLE_FILENAME] {
        Ok(())
    } else {
        Err(
            "candidate directory must contain exactly candidate-seal.json and source.zip"
                .to_owned(),
        )
    }
}

pub(crate) fn run_ephemeral(repository: &Path) -> Result<CandidateIdentity, String> {
    run_ephemeral_internal(repository, None)
}

pub(crate) fn run_ephemeral_after_validated_distribution_evidence(
    repository: &Path,
    expected_validation_input_sha256: &str,
) -> Result<CandidateIdentity, String> {
    run_ephemeral_internal(repository, Some(expected_validation_input_sha256))
}

fn run_ephemeral_internal(
    repository: &Path,
    validated_distribution_evidence: Option<&str>,
) -> Result<CandidateIdentity, String> {
    let total = Instant::now();
    let phase = Instant::now();
    populate_locked_sources(repository)?;
    eprintln!(
        "candidate seal phase locked-source acquisition passed in {:.3}s",
        phase.elapsed().as_secs_f64()
    );
    let phase = Instant::now();
    let before = capture_current_identity(repository)?;
    eprintln!(
        "candidate seal phase source identity passed in {:.3}s",
        phase.elapsed().as_secs_f64()
    );
    let phase = Instant::now();
    if let Some(expected) = validated_distribution_evidence {
        let actual = distribution_evidence::validation_cache_input_sha256(repository)
            .map_err(|error| format!("recapture validated distribution evidence: {error}"))?;
        if actual != expected {
            return Err(format!(
                "validated distribution-evidence input changed before candidate preparation: expected {expected}, found {actual}"
            ));
        }
        eprintln!("candidate seal reused the exact local distribution-evidence validation");
    } else {
        distribution_evidence::check(repository)
            .map_err(|error| format!("revalidate reviewed distribution evidence: {error}"))?;
    }
    require_current_identity(repository, &before, "distribution evidence validation")?;
    eprintln!(
        "candidate seal phase distribution evidence passed in {:.3}s",
        phase.elapsed().as_secs_f64()
    );
    let phase = Instant::now();
    let prepared = source_bundle::prepare_for_modes(
        repository,
        &[DistributionMode::Release, DistributionMode::Preview],
    )?;
    require_current_identity(repository, &before, "shared source-bundle preparation")?;
    eprintln!(
        "candidate seal phase shared source preparation passed in {:.3}s",
        phase.elapsed().as_secs_f64()
    );

    run_ephemeral_with(|package_mode| {
        let phase = Instant::now();
        let candidate_directory = visible_scratch_directory(repository)?;
        let summary = run_with_generator_retention(
            repository,
            &candidate_directory,
            before.clone(),
            false,
            package_mode,
            |bundle_path| {
                source_bundle::write_prepared_for_mode(&prepared, bundle_path, package_mode, false)
            },
        )?;
        eprintln!(
            "candidate seal phase {} emission passed in {:.3}s",
            package_mode.as_str(),
            phase.elapsed().as_secs_f64()
        );
        Ok(summary.candidate)
    })
    .inspect(|_| {
        eprintln!(
            "candidate seal passed in {:.3}s",
            total.elapsed().as_secs_f64()
        );
    })
}

fn run_ephemeral_with<F>(mut generate: F) -> Result<CandidateIdentity, String>
where
    F: FnMut(DistributionMode) -> Result<CandidateIdentity, String>,
{
    let release = generate(DistributionMode::Release)?;
    let preview = generate(DistributionMode::Preview)?;
    if release != preview {
        return Err(
            "automatic Release and Preview source candidates resolved different source identities"
                .to_owned(),
        );
    }
    Ok(release)
}

fn visible_scratch_directory(repository: &Path) -> Result<PathBuf, String> {
    let repository = canonical_repository(repository)?;
    let scratch_root = repository.join(SCRATCH_ROOT);
    match fs::symlink_metadata(&scratch_root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "candidate scratch root must be a real worktree-local directory: {}",
                    scratch_root.display()
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&scratch_root) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "create visible candidate scratch root {}: {error}",
                        scratch_root.display()
                    ))
                }
            }
        }
        Err(error) => {
            return Err(format!(
                "inspect candidate scratch root {}: {error}",
                scratch_root.display()
            ))
        }
    }
    let canonical = canonical_real_directory(&scratch_root, "candidate scratch root")?;
    if canonical != scratch_root {
        return Err("candidate scratch root resolved outside the worktree target".to_owned());
    }
    Ok(canonical.join(unique_temporary_name()?))
}

#[cfg(test)]
fn run_with_generator<F>(
    repository: &Path,
    output_directory: &Path,
    expected: CandidateIdentity,
    package_mode: DistributionMode,
    generator: F,
) -> Result<SourceCandidateSummary, String>
where
    F: FnOnce(&Path) -> Result<SourceBundleSummary, String>,
{
    run_with_generator_retention(
        repository,
        output_directory,
        expected,
        true,
        package_mode,
        generator,
    )
}

fn run_with_generator_retention<F>(
    repository: &Path,
    output_directory: &Path,
    expected: CandidateIdentity,
    retain_output: bool,
    package_mode: DistributionMode,
    generator: F,
) -> Result<SourceCandidateSummary, String>
where
    F: FnOnce(&Path) -> Result<SourceBundleSummary, String>,
{
    require_current_identity(repository, &expected, "candidate generation start")?;
    let owned = OwnedCandidateDirectory::create(output_directory)?;
    let result = (|| {
        let bundle_path = owned.path().join(SOURCE_BUNDLE_FILENAME);
        let bundle_summary = generator(&bundle_path)?;
        if bundle_summary.output != bundle_path {
            return Err(format!(
                "source bundle generator reported unexpected output {}; expected {}",
                bundle_summary.output.display(),
                bundle_path.display()
            ));
        }
        let generated_identity = CandidateIdentity {
            git_object_format: bundle_summary.git_object_format.clone(),
            source_commit: bundle_summary.source_commit.clone(),
            source_tree_oid: bundle_summary.source_tree_oid.clone(),
        };
        validate_candidate_identity(&generated_identity)?;
        if generated_identity != expected {
            return Err(
                "source bundle identity does not match the snapshotted candidate identity"
                    .to_owned(),
            );
        }
        if bundle_summary.package_mode != package_mode {
            return Err(
                "source bundle mode does not match the requested candidate mode".to_owned(),
            );
        }
        require_current_identity(repository, &expected, "source bundle generation")?;

        let seal = SourceCandidateSeal {
            schema_version: SEAL_SCHEMA_VERSION,
            artifact_kind: SEAL_ARTIFACT_KIND.to_owned(),
            scope: SEAL_SCOPE.to_owned(),
            release_authority: false,
            distribution_evidence_status: DISTRIBUTION_EVIDENCE_STATUS.to_owned(),
            package_mode,
            candidate: expected.clone(),
            source_bundle: source_bundle_binding(bundle_summary),
            invalidated_release_evidence: invalidated_release_evidence(),
        };
        validate_seal_shape(&seal)?;
        write_seal(&owned.path().join(SEAL_FILENAME), &seal)?;
        require_current_identity(repository, &expected, "candidate seal write")?;
        let (verification, _) = verify_recorded_candidate(repository, owned.path())?;
        if verification.candidate != expected {
            return Err(
                "persisted candidate verification returned a different identity".to_owned(),
            );
        }

        Ok(SourceCandidateSummary {
            output_directory: owned.path().to_path_buf(),
            candidate: expected,
            source_bundle_sha256: seal.source_bundle.sha256,
            source_bundle_bytes: seal.source_bundle.bytes,
            source_bundle_manifest_sha256: seal.source_bundle.manifest_sha256,
            package_mode,
            release_authority: false,
        })
    })();
    match result {
        Ok(summary) => {
            if retain_output {
                owned.persist();
            } else {
                owned.cleanup()?;
            }
            Ok(summary)
        }
        Err(error) => match owned.cleanup() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!("{error}; additionally {cleanup}")),
        },
    }
}

fn source_bundle_binding(summary: SourceBundleSummary) -> SourceBundleBinding {
    SourceBundleBinding {
        relative_path: SOURCE_BUNDLE_FILENAME.to_owned(),
        sha256: summary.archive_sha256,
        bytes: summary.archive_bytes,
        manifest_sha256: summary.source_bundle_manifest_sha256,
        cargo_lock_sha256: summary.cargo_lock_sha256,
        dependency_input_closure_sha256: summary.dependency_input_closure_sha256,
        rust_toolchain_sha256: summary.rust_toolchain_sha256,
        build_recipe_sha256: summary.build_recipe_sha256,
        archive_entries: summary.archive_entries,
        closure_packages: summary.closure_packages,
        vendored_packages: summary.vendored_packages,
        excluded_files: summary.excluded_files,
    }
}

fn invalidated_release_evidence() -> Vec<String> {
    INVALIDATED_RELEASE_EVIDENCE
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

fn validate_seal_shape(seal: &SourceCandidateSeal) -> Result<(), String> {
    if seal.schema_version != SEAL_SCHEMA_VERSION
        || seal.artifact_kind != SEAL_ARTIFACT_KIND
        || seal.scope != SEAL_SCOPE
        || seal.release_authority
        || seal.distribution_evidence_status != DISTRIBUTION_EVIDENCE_STATUS
    {
        return Err("candidate seal has an unsupported authority or schema".to_owned());
    }
    if seal.invalidated_release_evidence != invalidated_release_evidence() {
        return Err(
            "candidate seal must invalidate every package, native, signature, and owner evidence class"
                .to_owned(),
        );
    }
    validate_candidate_identity(&seal.candidate)?;
    if seal.source_bundle.relative_path != SOURCE_BUNDLE_FILENAME {
        return Err("candidate seal source bundle path is not the closed filename".to_owned());
    }
    for (label, value) in [
        ("source bundle", seal.source_bundle.sha256.as_str()),
        (
            "source bundle manifest",
            seal.source_bundle.manifest_sha256.as_str(),
        ),
        ("Cargo.lock", seal.source_bundle.cargo_lock_sha256.as_str()),
        (
            "dependency input closure",
            seal.source_bundle.dependency_input_closure_sha256.as_str(),
        ),
        (
            "Rust toolchain",
            seal.source_bundle.rust_toolchain_sha256.as_str(),
        ),
        (
            "Windows build recipe",
            seal.source_bundle.build_recipe_sha256.as_str(),
        ),
    ] {
        require_sha256(value, label)?;
    }
    if seal.source_bundle.bytes == 0
        || seal.source_bundle.archive_entries == 0
        || seal.source_bundle.closure_packages == 0
    {
        return Err("candidate seal contains an empty source bundle identity".to_owned());
    }
    Ok(())
}

fn verify_bundle_binding(
    seal: &SourceCandidateSeal,
    inspected: &InspectedBundle,
) -> Result<(), String> {
    let binding = &seal.source_bundle;
    if inspected.sha256 != binding.sha256
        || inspected.bytes != binding.bytes
        || inspected.archive_entries != binding.archive_entries
        || inspected.manifest_sha256 != binding.manifest_sha256
    {
        return Err("source bundle bytes do not match the candidate seal".to_owned());
    }
    let manifest = &inspected.manifest;
    if manifest.schema_version != SOURCE_BUNDLE_MANIFEST_SCHEMA_VERSION
        || manifest.artifact_kind != SOURCE_BUNDLE_ARTIFACT_KIND
        || manifest.git_object_format != seal.candidate.git_object_format
        || manifest.source_commit != seal.candidate.source_commit
        || manifest.source_tree_oid != seal.candidate.source_tree_oid
        || manifest.cargo_lock_sha256 != binding.cargo_lock_sha256
        || manifest.dependency_input_closure_sha256 != binding.dependency_input_closure_sha256
        || manifest.rust_toolchain_sha256 != binding.rust_toolchain_sha256
        || manifest.build_recipe_sha256 != binding.build_recipe_sha256
        || manifest.package_mode != seal.package_mode
    {
        return Err("source bundle manifest identity does not match the candidate seal".to_owned());
    }
    Ok(())
}

fn write_seal(path: &Path, seal: &SourceCandidateSeal) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(seal)
        .map_err(|error| format!("serialize candidate seal: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_SEAL_BYTES {
        return Err("candidate seal exceeds its closed size limit".to_owned());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        format!(
            "create candidate seal {} without overwrite: {error}",
            path.display()
        )
    })?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("write and sync candidate seal {}: {error}", path.display()))
}

fn read_seal(path: &Path) -> Result<SourceCandidateSeal, String> {
    let (mut file, metadata) = open_stable_regular_file(path, "candidate seal")?;
    if metadata.len() > MAX_SEAL_BYTES {
        return Err("candidate seal exceeds its closed size limit".to_owned());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_SEAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read candidate seal {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_SEAL_BYTES {
        return Err("candidate seal exceeds its closed size limit".to_owned());
    }
    verify_opened_file_still_named(path, &metadata, "candidate seal")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse strict candidate seal {}: {error}", path.display()))
}

fn inspect_source_bundle(path: &Path) -> Result<InspectedBundle, String> {
    let (mut file, metadata) = open_stable_regular_file(path, "source bundle")?;
    let (sha256, bytes) = hash_open_file(&mut file, "source bundle")?;
    if bytes != metadata.len() {
        return Err("source bundle size changed while it was being read".to_owned());
    }
    if bytes < 22 {
        return Err("source bundle is too short to be a deterministic ZIP32 archive".to_owned());
    }

    let (archive_entries, manifest_bytes) = file
        .seek(SeekFrom::End(-22))
        .and_then(|_| {
            let mut end = [0u8; 22];
            file.read_exact(&mut end)?;
            Ok(end)
        })
        .map_err(|error| format!("read source bundle ZIP end record: {error}"))
        .and_then(|end| inspect_zip_end(path, &mut file, bytes, end))?;
    let manifest_sha256 = sha256_bytes(&manifest_bytes);
    let manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("parse source bundle manifest: {error}"))?;
    let inspected = InspectedBundle {
        sha256,
        bytes,
        archive_entries,
        manifest_sha256,
        manifest,
    };
    verify_opened_file_still_named(path, &metadata, "source bundle")?;
    Ok(inspected)
}

fn inspect_zip_end(
    path: &Path,
    file: &mut File,
    archive_bytes: u64,
    end: [u8; 22],
) -> Result<(usize, Vec<u8>), String> {
    if le_u32(&end[0..4]) != 0x0605_4b50
        || le_u16(&end[4..6]) != 0
        || le_u16(&end[6..8]) != 0
        || le_u16(&end[8..10]) != le_u16(&end[10..12])
        || le_u16(&end[20..22]) != 0
    {
        return Err("source bundle has an unsupported ZIP32 end record".to_owned());
    }
    let entry_count = usize::from(le_u16(&end[10..12]));
    let central_size = u64::from(le_u32(&end[12..16]));
    let central_offset = u64::from(le_u32(&end[16..20]));
    if entry_count == 0
        || central_offset
            .checked_add(central_size)
            .and_then(|value| value.checked_add(22))
            != Some(archive_bytes)
    {
        return Err("source bundle ZIP32 central directory bounds are invalid".to_owned());
    }
    file.seek(SeekFrom::Start(central_offset))
        .map_err(|error| format!("seek source bundle central directory: {error}"))?;

    let mut manifest = None;
    for _ in 0..entry_count {
        let mut header = [0u8; 46];
        file.read_exact(&mut header)
            .map_err(|error| format!("read source bundle central entry: {error}"))?;
        if le_u32(&header[0..4]) != 0x0201_4b50
            || le_u16(&header[8..10]) != ZIP_UTF8_FLAG
            || le_u16(&header[10..12]) != 0
            || le_u32(&header[20..24]) != le_u32(&header[24..28])
            || le_u16(&header[30..32]) != 0
            || le_u16(&header[32..34]) != 0
        {
            return Err("source bundle central entry violates deterministic ZIP policy".to_owned());
        }
        let name_length = usize::from(le_u16(&header[28..30]));
        if name_length == 0 || name_length > MAX_ZIP_PATH_BYTES {
            return Err("source bundle central entry path length is invalid".to_owned());
        }
        let mut name = vec![0u8; name_length];
        file.read_exact(&mut name)
            .map_err(|error| format!("read source bundle entry name: {error}"))?;
        let name = std::str::from_utf8(&name)
            .map_err(|_| "source bundle entry path is not UTF-8".to_owned())?;
        if name == SOURCE_BUNDLE_MANIFEST_PATH {
            if manifest.is_some() {
                return Err("source bundle contains duplicate manifests".to_owned());
            }
            let central_resume = file
                .stream_position()
                .map_err(|error| format!("record source bundle central position: {error}"))?;
            let local_offset = u64::from(le_u32(&header[42..46]));
            let expected_crc = le_u32(&header[16..20]);
            let expected_size = le_u32(&header[24..28]);
            manifest = Some(read_local_manifest(
                file,
                local_offset,
                expected_crc,
                expected_size,
            )?);
            file.seek(SeekFrom::Start(central_resume))
                .map_err(|error| format!("resume source bundle central directory: {error}"))?;
        }
    }
    let final_position = file
        .stream_position()
        .map_err(|error| format!("inspect source bundle central position: {error}"))?;
    if final_position != central_offset + central_size {
        return Err(format!(
            "source bundle central directory has unexpected trailing data in {}",
            path.display()
        ));
    }
    manifest
        .map(|bytes| (entry_count, bytes))
        .ok_or_else(|| "source bundle has no source-bundle-manifest.json".to_owned())
}

fn read_local_manifest(
    file: &mut File,
    local_offset: u64,
    expected_crc: u32,
    expected_size: u32,
) -> Result<Vec<u8>, String> {
    if expected_size == 0 || expected_size > MAX_MANIFEST_BYTES {
        return Err("source bundle manifest size is outside the closed limit".to_owned());
    }
    file.seek(SeekFrom::Start(local_offset))
        .map_err(|error| format!("seek source bundle manifest: {error}"))?;
    let mut header = [0u8; 30];
    file.read_exact(&mut header)
        .map_err(|error| format!("read source bundle manifest header: {error}"))?;
    if le_u32(&header[0..4]) != 0x0403_4b50
        || le_u16(&header[6..8]) != ZIP_UTF8_FLAG
        || le_u16(&header[8..10]) != 0
        || le_u32(&header[14..18]) != expected_crc
        || le_u32(&header[18..22]) != expected_size
        || le_u32(&header[22..26]) != expected_size
        || le_u16(&header[28..30]) != 0
    {
        return Err("source bundle manifest local header is inconsistent".to_owned());
    }
    let name_length = usize::from(le_u16(&header[26..28]));
    let mut name = vec![0u8; name_length];
    file.read_exact(&mut name)
        .map_err(|error| format!("read source bundle manifest local name: {error}"))?;
    if name != SOURCE_BUNDLE_MANIFEST_PATH.as_bytes() {
        return Err("source bundle manifest local path is inconsistent".to_owned());
    }
    let mut bytes = vec![0u8; expected_size as usize];
    file.read_exact(&mut bytes)
        .map_err(|error| format!("read source bundle manifest bytes: {error}"))?;
    if crc32(&bytes) != expected_crc {
        return Err("source bundle manifest CRC-32 is invalid".to_owned());
    }
    Ok(bytes)
}

#[cfg(test)]
fn hash_file(path: &Path) -> Result<(String, u64), String> {
    let (mut file, metadata) = open_stable_regular_file(path, "file to hash")?;
    let label = path.display().to_string();
    let result = hash_open_file(&mut file, &label)?;
    if result.1 != metadata.len() {
        return Err(format!(
            "{} changed size while being hashed",
            path.display()
        ));
    }
    verify_opened_file_still_named(path, &metadata, "file to hash")?;
    Ok(result)
}

fn hash_open_file(file: &mut File, label: &str) -> Result<(String, u64), String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek {label} before hashing: {error}"))?;
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("hash {label}: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| "source bundle byte count overflow".to_owned())?;
    }
    Ok((format!("{:x}", digest.finalize()), bytes))
}

fn open_stable_regular_file(path: &Path, label: &str) -> Result<(File, Metadata), String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(format!(
            "{label} must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    let file =
        File::open(path).map_err(|error| format!("open {label} {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("inspect opened {label} {}: {error}", path.display()))?;
    if !opened.is_file() {
        return Err(format!("{label} opened as a non-regular file"));
    }
    verify_metadata_identity(&before, &opened, label)?;
    verify_opened_file_still_named(path, &opened, label)?;
    Ok((file, opened))
}

fn verify_opened_file_still_named(
    path: &Path,
    opened: &Metadata,
    label: &str,
) -> Result<(), String> {
    let link = fs::symlink_metadata(path)
        .map_err(|error| format!("reinspect {label} {}: {error}", path.display()))?;
    if link.file_type().is_symlink() || !link.is_file() {
        return Err(format!("{label} path changed while open"));
    }
    let named = fs::metadata(path)
        .map_err(|error| format!("inspect named {label} {}: {error}", path.display()))?;
    verify_metadata_identity(opened, &named, label)
}

#[cfg(unix)]
fn verify_metadata_identity(
    expected: &Metadata,
    actual: &Metadata,
    label: &str,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    if expected.dev() != actual.dev()
        || expected.ino() != actual.ino()
        || expected.nlink() != 1
        || actual.nlink() != 1
    {
        Err(format!(
            "{label} identity changed or has multiple hard links"
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn verify_metadata_identity(
    expected: &Metadata,
    actual: &Metadata,
    label: &str,
) -> Result<(), String> {
    if expected.len() != actual.len()
        || expected.modified().ok() != actual.modified().ok()
        || expected.created().ok() != actual.created().ok()
    {
        Err(format!("{label} identity changed while open"))
    } else {
        Ok(())
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn le_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes.try_into().expect("two-byte ZIP field"))
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("four-byte ZIP field"))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

pub(crate) fn capture_current_identity(repository: &Path) -> Result<CandidateIdentity, String> {
    let repository = canonical_repository(repository)?;
    ensure_plain_index(&repository)?;
    ensure_clean_checkout(&repository)?;
    let identity = read_candidate_identity(&repository)?;
    ensure_plain_index(&repository)?;
    ensure_clean_checkout(&repository)?;
    let closing_identity = read_candidate_identity(&repository)?;
    if closing_identity != identity {
        return Err("source identity changed while it was being captured".to_owned());
    }
    Ok(identity)
}

fn read_candidate_identity(repository: &Path) -> Result<CandidateIdentity, String> {
    let git_object_format = git_text(repository, &["rev-parse", "--show-object-format"])?
        .trim()
        .to_owned();
    let source_commit = git_text(repository, &["rev-parse", "--verify", "HEAD^{commit}"])?
        .trim()
        .to_owned();
    let tree_expression = format!("{source_commit}^{{tree}}");
    let source_tree_oid = git_text(
        repository,
        &["rev-parse", "--verify", tree_expression.as_str()],
    )?
    .trim()
    .to_owned();
    let identity = CandidateIdentity {
        git_object_format,
        source_commit,
        source_tree_oid,
    };
    validate_candidate_identity(&identity)?;
    Ok(identity)
}

fn ensure_clean_checkout(repository: &Path) -> Result<(), String> {
    let status = git_bytes(
        repository,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    if status.is_empty() {
        Ok(())
    } else {
        Err(
            "current-candidate operations require a clean checkout, including no untracked files"
                .to_owned(),
        )
    }
}

fn ensure_plain_index(repository: &Path) -> Result<(), String> {
    let records = git_bytes(repository, &["ls-files", "-v", "-z", "--"])?;
    for record in records
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if record.len() < 3 || record[0] != b'H' || record[1] != b' ' {
            return Err(
                "current-candidate operations reject assume-unchanged, skip-worktree, or nonordinary index state"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn populate_locked_sources(repository: &Path) -> Result<(), String> {
    let status = Command::new("cargo")
        .args(["fetch", "--locked"])
        .current_dir(repository)
        .status()
        .map_err(|error| format!("launch cargo fetch --locked: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "cargo fetch --locked failed with {status}; source sealing requires the exact locked Windows dependency archives"
        ))
    }
}

fn require_current_identity(
    repository: &Path,
    expected: &CandidateIdentity,
    operation: &str,
) -> Result<(), String> {
    let actual = capture_current_identity(repository)
        .map_err(|error| format!("source became unusable during {operation}: {error}"))?;
    if &actual == expected {
        Ok(())
    } else {
        Err(format!(
            "source commit or tree changed during {operation}; expected commit {} tree {}, found commit {} tree {}",
            expected.source_commit,
            expected.source_tree_oid,
            actual.source_commit,
            actual.source_tree_oid
        ))
    }
}

fn validate_candidate_identity(identity: &CandidateIdentity) -> Result<(), String> {
    let oid_length = match identity.git_object_format.as_str() {
        "sha1" => 40,
        "sha256" => 64,
        other => return Err(format!("unsupported Git object format {other:?}")),
    };
    require_oid(&identity.source_commit, oid_length, "source commit")?;
    require_oid(&identity.source_tree_oid, oid_length, "source tree")
}

fn require_oid(value: &str, length: usize, label: &str) -> Result<(), String> {
    if value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{label} is not a lowercase {length}-digit Git OID"))
    }
}

fn require_sha256(value: &str, label: &str) -> Result<(), String> {
    require_oid(value, 64, &format!("{label} SHA-256"))
}

fn canonical_repository(repository: &Path) -> Result<PathBuf, String> {
    let repository = canonical_real_directory(repository, "source repository")?;
    let top_level = git_text(&repository, &["rev-parse", "--show-toplevel"])?;
    let top_level = fs::canonicalize(top_level.trim())
        .map_err(|error| format!("canonicalize Git top level: {error}"))?;
    if top_level != repository {
        return Err(format!(
            "{} is not the Git worktree root {}",
            repository.display(),
            top_level.display()
        ));
    }
    Ok(repository)
}

fn canonical_real_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect {label}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} must be a real directory"));
    }
    fs::canonicalize(path).map_err(|error| format!("canonicalize {label}: {error}"))
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
    String::from_utf8(git_bytes(repository, arguments)?)
        .map_err(|error| format!("git {} returned non-UTF-8: {error}", arguments.join(" ")))
}

struct OwnedCandidateDirectory {
    path: PathBuf,
    identity: Metadata,
    active: bool,
}

impl OwnedCandidateDirectory {
    fn create(requested: &Path) -> Result<Self, String> {
        let name = requested
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "candidate output must name a fresh directory".to_owned())?;
        let parent = requested
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = canonical_real_directory(parent, "candidate output parent")?;
        let path = parent.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(format!(
                    "candidate output already exists and will not be replaced: {}",
                    path.display()
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "inspect candidate output {}: {error}",
                    path.display()
                ))
            }
        }
        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).map_err(|error| {
            format!("create fresh candidate output {}: {error}", path.display())
        })?;
        let canonical = fs::canonicalize(&path)
            .map_err(|error| format!("canonicalize candidate output: {error}"))?;
        if canonical != path {
            let _ = fs::remove_dir(&path);
            return Err("candidate output resolved to an unexpected path".to_owned());
        }
        let identity = fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect created candidate output: {error}"))?;
        Ok(Self {
            path,
            identity,
            active: true,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn persist(mut self) -> PathBuf {
        self.active = false;
        self.path.clone()
    }

    fn cleanup(mut self) -> Result<(), String> {
        match remove_owned_candidate_directory(&self.path, &self.identity) {
            Ok(()) => {
                self.active = false;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for OwnedCandidateDirectory {
    fn drop(&mut self) {
        if self.active {
            let _ = remove_owned_candidate_directory(&self.path, &self.identity);
        }
    }
}

fn remove_owned_candidate_directory(path: &Path, expected: &Metadata) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect owned candidate directory for cleanup: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("refusing to recursively clean a non-directory candidate path".to_owned());
    }
    verify_directory_identity(expected, &metadata)?;
    fs::remove_dir_all(path).map_err(|error| {
        format!(
            "remove owned candidate directory {}: {error}",
            path.display()
        )
    })
}

#[cfg(unix)]
fn verify_directory_identity(expected: &Metadata, actual: &Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    if expected.dev() == actual.dev() && expected.ino() == actual.ino() {
        Ok(())
    } else {
        Err("refusing to clean a replaced candidate directory".to_owned())
    }
}

#[cfg(not(unix))]
fn verify_directory_identity(expected: &Metadata, actual: &Metadata) -> Result<(), String> {
    if expected.created().ok() == actual.created().ok()
        && expected.modified().ok() == actual.modified().ok()
    {
        Ok(())
    } else {
        Err("refusing to clean a replaced candidate directory".to_owned())
    }
}

fn unique_temporary_name() -> Result<String, String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(format!(
        "autocad-mcp-source-candidate-{}-{}-{sequence}",
        std::process::id(),
        elapsed.as_nanos()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::process::Stdio;

    struct RepositoryFixture {
        temporary: tempfile::TempDir,
        repository: PathBuf,
    }

    impl RepositoryFixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let repository = temporary.path().join("source");
            fs::create_dir(&repository).expect("create repository");
            run_git(
                &repository,
                [
                    "init",
                    "--quiet",
                    "--initial-branch=main",
                    "--object-format=sha1",
                    ".",
                ],
            );
            run_git(&repository, ["config", "user.name", "Candidate Test"]);
            run_git(
                &repository,
                ["config", "user.email", "candidate@example.invalid"],
            );
            run_git(&repository, ["config", "commit.gpgSign", "false"]);
            fs::write(repository.join("source.txt"), b"one\n").expect("write source");
            fs::write(repository.join(".gitignore"), b"/target/\n").expect("write ignore");
            run_git(&repository, ["add", "--", "source.txt", ".gitignore"]);
            run_git(&repository, ["commit", "--quiet", "-m", "source A"]);
            Self {
                temporary,
                repository,
            }
        }

        fn candidate_path(&self, name: &str) -> PathBuf {
            self.temporary.path().join(name)
        }

        fn identity(&self) -> CandidateIdentity {
            capture_current_identity(&self.repository).expect("capture identity")
        }

        fn seal(&self, name: &str) -> PathBuf {
            self.seal_mode(name, DistributionMode::Release)
        }

        fn seal_mode(&self, name: &str, package_mode: DistributionMode) -> PathBuf {
            let output = self.candidate_path(name);
            let identity = self.identity();
            run_with_generator(
                &self.repository,
                &output,
                identity.clone(),
                package_mode,
                |path| write_test_source_bundle(path, &identity, package_mode),
            )
            .expect("seal candidate");
            output
        }
    }

    fn run_git<I, S>(repository: &Path, arguments: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let status = git_command(repository)
            .args(arguments)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("launch git");
        assert!(status.success(), "git command should succeed");
    }

    fn write_test_source_bundle(
        path: &Path,
        identity: &CandidateIdentity,
        package_mode: DistributionMode,
    ) -> Result<SourceBundleSummary, String> {
        let cargo_lock_sha256 = "11".repeat(32);
        let dependency_input_closure_sha256 = "22".repeat(32);
        let rust_toolchain_sha256 = "33".repeat(32);
        let build_recipe_sha256 = "44".repeat(32);
        let manifest = serde_json::json!({
            "schema_version": SOURCE_BUNDLE_MANIFEST_SCHEMA_VERSION,
            "artifact_kind": SOURCE_BUNDLE_ARTIFACT_KIND,
            "git_object_format": identity.git_object_format,
            "source_commit": identity.source_commit,
            "source_tree_oid": identity.source_tree_oid,
            "cargo_lock_sha256": cargo_lock_sha256,
            "dependency_input_closure_sha256": dependency_input_closure_sha256,
            "rust_toolchain_sha256": rust_toolchain_sha256,
            "build_recipe_sha256": build_recipe_sha256,
            "package_mode": package_mode
        });
        let mut manifest_bytes =
            serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?;
        manifest_bytes.push(b'\n');
        write_single_entry_zip(path, SOURCE_BUNDLE_MANIFEST_PATH, &manifest_bytes)?;
        let (archive_sha256, archive_bytes) = hash_file(path)?;
        Ok(SourceBundleSummary {
            output: path.to_path_buf(),
            git_object_format: identity.git_object_format.clone(),
            source_commit: identity.source_commit.clone(),
            source_tree_oid: identity.source_tree_oid.clone(),
            source_bundle_manifest_sha256: sha256_bytes(&manifest_bytes),
            cargo_lock_sha256,
            dependency_input_closure_sha256,
            rust_toolchain_sha256,
            build_recipe_sha256,
            package_mode,
            archive_sha256,
            archive_bytes,
            archive_entries: 1,
            closure_packages: 1,
            vendored_packages: 0,
            excluded_files: 0,
        })
    }

    fn write_single_entry_zip(path: &Path, name: &str, payload: &[u8]) -> Result<(), String> {
        let name = name.as_bytes();
        let name_length = u16::try_from(name.len()).map_err(|error| error.to_string())?;
        let size = u32::try_from(payload.len()).map_err(|error| error.to_string())?;
        let crc = crc32(payload);
        let mut bytes = Vec::new();
        push_u32(&mut bytes, 0x0403_4b50);
        push_u16(&mut bytes, 20);
        push_u16(&mut bytes, ZIP_UTF8_FLAG);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0x0021);
        push_u32(&mut bytes, crc);
        push_u32(&mut bytes, size);
        push_u32(&mut bytes, size);
        push_u16(&mut bytes, name_length);
        push_u16(&mut bytes, 0);
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(payload);
        let central_offset = u32::try_from(bytes.len()).map_err(|error| error.to_string())?;
        push_u32(&mut bytes, 0x0201_4b50);
        push_u16(&mut bytes, 0x0314);
        push_u16(&mut bytes, 20);
        push_u16(&mut bytes, ZIP_UTF8_FLAG);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0x0021);
        push_u32(&mut bytes, crc);
        push_u32(&mut bytes, size);
        push_u32(&mut bytes, size);
        push_u16(&mut bytes, name_length);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u32(&mut bytes, (0o100644_u32) << 16);
        push_u32(&mut bytes, 0);
        bytes.extend_from_slice(name);
        let central_size =
            u32::try_from(bytes.len()).map_err(|error| error.to_string())? - central_offset;
        push_u32(&mut bytes, 0x0605_4b50);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 1);
        push_u16(&mut bytes, 1);
        push_u32(&mut bytes, central_size);
        push_u32(&mut bytes, central_offset);
        push_u16(&mut bytes, 0);
        fs::write(path, bytes).map_err(|error| error.to_string())
    }

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn same_tree_successor_invalidates_candidate() {
        let fixture = RepositoryFixture::new();
        let candidate = fixture.seal("candidate");
        run_git(
            &fixture.repository,
            ["commit", "--quiet", "--allow-empty", "-m", "source B"],
        );

        let error = verify(&fixture.repository, &candidate)
            .expect_err("same-tree successor must invalidate the old candidate");
        assert!(error.contains("regenerate the candidate"));
    }

    #[test]
    fn changed_tree_successor_invalidates_candidate() {
        let fixture = RepositoryFixture::new();
        let candidate = fixture.seal("candidate");
        fs::write(fixture.repository.join("source.txt"), b"two\n").expect("change source");
        run_git(&fixture.repository, ["add", "--", "source.txt"]);
        run_git(&fixture.repository, ["commit", "--quiet", "-m", "source B"]);

        let error = verify(&fixture.repository, &candidate)
            .expect_err("changed-tree successor must invalidate the old candidate");
        assert!(error.contains("regenerate the candidate"));
    }

    #[test]
    fn dirty_source_never_has_a_current_candidate() {
        let fixture = RepositoryFixture::new();
        let candidate = fixture.seal("candidate");

        fs::write(fixture.repository.join("untracked.txt"), b"untracked\n")
            .expect("write untracked file");
        assert!(verify(&fixture.repository, &candidate).is_err());
        fs::remove_file(fixture.repository.join("untracked.txt")).expect("remove untracked file");

        fs::write(fixture.repository.join("source.txt"), b"unstaged\n").expect("write unstaged");
        assert!(verify(&fixture.repository, &candidate).is_err());
        run_git(&fixture.repository, ["restore", "--", "source.txt"]);

        fs::write(fixture.repository.join("source.txt"), b"staged\n").expect("write staged");
        run_git(&fixture.repository, ["add", "--", "source.txt"]);
        assert!(verify(&fixture.repository, &candidate).is_err());
    }

    #[test]
    fn hidden_index_flags_are_rejected() {
        let fixture = RepositoryFixture::new();

        run_git(
            &fixture.repository,
            ["update-index", "--assume-unchanged", "--", "source.txt"],
        );
        let error = capture_current_identity(&fixture.repository)
            .expect_err("assume-unchanged must not hide source state");
        assert!(error.contains("nonordinary index state"));
        run_git(
            &fixture.repository,
            ["update-index", "--no-assume-unchanged", "--", "source.txt"],
        );

        run_git(
            &fixture.repository,
            ["update-index", "--skip-worktree", "--", "source.txt"],
        );
        let error = capture_current_identity(&fixture.repository)
            .expect_err("skip-worktree must not hide source state");
        assert!(error.contains("nonordinary index state"));
    }

    #[test]
    fn replacement_refs_do_not_change_the_candidate_identity() {
        let fixture = RepositoryFixture::new();
        let original = fixture.identity();
        fs::write(fixture.repository.join("source.txt"), b"replacement\n")
            .expect("write replacement source");
        run_git(&fixture.repository, ["add", "--", "source.txt"]);
        run_git(
            &fixture.repository,
            ["commit", "--quiet", "-m", "replacement source"],
        );
        let replacement = git_text(&fixture.repository, &["rev-parse", "HEAD"])
            .unwrap()
            .trim()
            .to_owned();
        run_git(
            &fixture.repository,
            ["switch", "--quiet", "--detach", &original.source_commit],
        );
        run_git(
            &fixture.repository,
            ["replace", &original.source_commit, &replacement],
        );

        assert_eq!(
            capture_current_identity(&fixture.repository).unwrap(),
            original
        );
    }

    #[test]
    fn source_move_during_generation_publishes_no_seal() {
        let fixture = RepositoryFixture::new();
        let candidate = fixture.candidate_path("candidate");
        let identity = fixture.identity();
        let error = run_with_generator(
            &fixture.repository,
            &candidate,
            identity.clone(),
            DistributionMode::Release,
            |path| {
                let summary = write_test_source_bundle(path, &identity, DistributionMode::Release)?;
                run_git(
                    &fixture.repository,
                    ["commit", "--quiet", "--allow-empty", "-m", "source B"],
                );
                Ok(summary)
            },
        )
        .expect_err("source movement must fail generation");

        assert!(error.contains("source commit or tree changed"));
        assert!(!candidate.exists());
    }

    #[test]
    fn bundle_mutation_is_rejected_and_seal_has_no_release_authority() {
        let fixture = RepositoryFixture::new();
        let candidate = fixture.seal("candidate");
        let seal = read_seal(&candidate.join(SEAL_FILENAME)).expect("read seal");
        assert!(!seal.release_authority);
        assert_eq!(seal.package_mode, DistributionMode::Release);
        assert_eq!(
            seal.invalidated_release_evidence,
            [
                "release_package",
                "preview_package",
                "windows_native_build_attestation",
                "autocad_host_certification",
                "code_signature",
                "clean_host_application_acceptance",
                "owner_distribution_approval",
                "publication_projection_receipt",
            ]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&candidate).unwrap().permissions().mode() & 0o077,
                0
            );
            assert_eq!(
                fs::metadata(candidate.join(SEAL_FILENAME))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }

        let mut bundle = OpenOptions::new()
            .append(true)
            .open(candidate.join(SOURCE_BUNDLE_FILENAME))
            .expect("open bundle");
        bundle.write_all(b"changed").expect("mutate bundle");
        bundle.sync_all().expect("sync bundle");
        let error =
            verify(&fixture.repository, &candidate).expect_err("mutated bundle must not verify");
        assert!(!error.is_empty());
    }

    #[test]
    fn manifest_only_forgery_is_not_a_verified_reproduction() {
        let fixture = RepositoryFixture::new();
        let candidate = fixture.seal("candidate");
        let error = verify(&fixture.repository, &candidate)
            .expect_err("standalone verification must independently regenerate the bundle");
        assert!(error.contains("cargo fetch --locked failed"));
    }

    #[test]
    fn missing_or_extra_candidate_files_are_rejected() {
        let fixture = RepositoryFixture::new();
        let candidate = fixture.seal("candidate");
        fs::write(candidate.join("newest-seal.json"), b"not selectable\n").unwrap();
        let error = verify_recorded_candidate(&fixture.repository, &candidate)
            .expect_err("an extra candidate file must not be selected");
        assert!(error.contains("must contain exactly"));
        fs::remove_file(candidate.join("newest-seal.json")).unwrap();
        fs::remove_file(candidate.join(SEAL_FILENAME)).unwrap();
        let error = verify_recorded_candidate(&fixture.repository, &candidate)
            .expect_err("a missing seal must fail");
        assert!(error.contains("must contain exactly"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_seal_is_rejected() {
        use std::os::unix::fs::symlink;

        let fixture = RepositoryFixture::new();
        let candidate = fixture.seal("candidate");
        let detached = fixture.temporary.path().join("detached-seal.json");
        fs::rename(candidate.join(SEAL_FILENAME), &detached).unwrap();
        symlink(&detached, candidate.join(SEAL_FILENAME)).unwrap();

        let error = verify_recorded_candidate(&fixture.repository, &candidate)
            .expect_err("a symlinked seal must fail");
        assert!(error.contains("regular non-symlink"));
    }

    #[test]
    fn existing_output_is_never_selected_or_replaced() {
        let fixture = RepositoryFixture::new();
        let candidate = fixture.candidate_path("candidate");
        fs::create_dir(&candidate).expect("create pre-existing output");
        let identity = fixture.identity();
        let error = run_with_generator(
            &fixture.repository,
            &candidate,
            identity,
            DistributionMode::Release,
            |_| panic!("generator must not run for an existing output"),
        )
        .expect_err("existing output must be rejected");
        assert!(error.contains("already exists"));
        assert!(!candidate.join(SEAL_FILENAME).exists());
    }

    #[test]
    fn cleanup_refuses_a_replaced_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let requested = temporary.path().join("owned");
        let owned = OwnedCandidateDirectory::create(&requested).unwrap();
        let moved = temporary.path().join("moved-owned");
        fs::rename(&requested, &moved).unwrap();
        fs::create_dir(&requested).unwrap();

        let error = owned
            .cleanup()
            .expect_err("cleanup must not delete a replacement");
        assert!(error.contains("replaced candidate directory"));
        assert!(requested.is_dir());
        assert!(moved.is_dir());
    }

    #[test]
    fn automatic_scratch_is_visible_below_the_worktree_target() {
        let fixture = RepositoryFixture::new();
        let scratch = visible_scratch_directory(&fixture.repository).unwrap();
        let target = fs::canonicalize(fixture.repository.join("target")).unwrap();

        assert_eq!(scratch.parent(), Some(target.as_path()));
        assert!(scratch
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("autocad-mcp-source-candidate-"));
        assert!(!scratch.exists());
    }

    #[test]
    fn automatic_sealing_requires_release_and_preview_for_one_identity() {
        let identity = CandidateIdentity {
            git_object_format: "sha1".to_owned(),
            source_commit: "a".repeat(40),
            source_tree_oid: "b".repeat(40),
        };
        let mut modes = Vec::new();
        let actual = run_ephemeral_with(|mode| {
            modes.push(mode);
            Ok(identity.clone())
        })
        .unwrap();

        assert_eq!(
            modes,
            [DistributionMode::Release, DistributionMode::Preview]
        );
        assert_eq!(actual, identity);
    }

    #[test]
    fn preview_mode_is_bound_and_cross_mode_verification_rejects() {
        let fixture = RepositoryFixture::new();
        let candidate = fixture.seal_mode("preview-candidate", DistributionMode::Preview);
        let (_, seal) = verify_recorded_candidate(&fixture.repository, &candidate).unwrap();
        assert_eq!(seal.package_mode, DistributionMode::Preview);

        let error = verify_for_mode(&fixture.repository, &candidate, DistributionMode::Release)
            .expect_err("a Preview candidate must not satisfy Release selection");
        assert!(error.contains("does not match requested mode"));
    }

    #[test]
    fn prior_candidate_seal_schema_is_rejected() {
        let fixture = RepositoryFixture::new();
        let candidate = fixture.seal("candidate");
        let seal_path = candidate.join(SEAL_FILENAME);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&seal_path).unwrap()).unwrap();
        value["schema_version"] = serde_json::json!(SEAL_SCHEMA_VERSION - 1);
        fs::write(&seal_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

        let error = verify_recorded_candidate(&fixture.repository, &candidate)
            .expect_err("the prior closed seal schema must be rejected");
        assert!(error.contains("unsupported authority or schema"));
    }
}
