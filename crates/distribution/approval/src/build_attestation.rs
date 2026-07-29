use crate::{
    error, parse_strict_json, require_lower_hex, require_sha256, BuildProfile, DistributionMode,
    GitObjectFormat, ValidationError, WINDOWS_X86_64_TARGET,
};
use serde::{Deserialize, Deserializer, Serialize};

pub const WINDOWS_PREVIEW_BUILD_ATTESTATION_SCHEMA_VERSION: u32 = 1;
pub const WINDOWS_PREVIEW_BUILD_ATTESTATION_KIND: &str = "windows_preview_build_attestation";
pub const WINDOWS_PREVIEW_BUILD_ATTESTATION_PATH: &str =
    "distribution-evidence/windows-x64-preview-build.json";
pub const WINDOWS_PREVIEW_BUILD_ATTESTATION_SCHEMA_PATH: &str =
    "crates/distribution/approval/schemas/windows-preview-build-attestation.schema.json";

const NATIVE_BUILD_AUTHORITY: &str = "github_actions_windows_preview_review";
const NATIVE_BUILD_REPOSITORY: &str = "andagni/autocad-mcp";
const NATIVE_BUILD_WORKFLOW_PATH: &str = ".github/workflows/windows-preview-review-candidate.yml";
const NATIVE_BUILD_RUNNER_OS: &str = "Windows";
const NATIVE_BUILD_RUNNER_ARCH: &str = "X64";
const REQUIRED_RUSTC_PREFIX: &str = "rustc 1.97.0 ";
const REQUIRED_RUSTC_HOST: &str = "host: x86_64-pc-windows-msvc";
const CERTIFIED_ARG_POLICY_ID: &str = "autocad-mcp-public-development-v1";
const CRT_LINKAGE: &str = "static";
const PE_IMPORT_POLICY_ID: &str = "pe-no-vc-runtime-imports-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WindowsPreviewBuildAttestationKind {
    WindowsPreviewBuildAttestation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPreviewBuildAttestation {
    schema_version: u32,
    kind: WindowsPreviewBuildAttestationKind,
    package_mode: DistributionMode,
    target_triple: String,
    build_profile: BuildProfile,
    cargo_incremental: bool,
    source_identity: WindowsPreviewBuildSourceIdentity,
    native_build: WindowsPreviewNativeBuild,
    unsigned_preflight: WindowsPreviewUnsignedPreflight,
    subjects: Vec<WindowsPreviewBuildSubject>,
}

impl WindowsPreviewBuildAttestation {
    pub fn new(
        source_identity: WindowsPreviewBuildSourceIdentity,
        native_build: WindowsPreviewNativeBuild,
        unsigned_preflight: WindowsPreviewUnsignedPreflight,
        subjects: [WindowsPreviewBuildSubject; 3],
    ) -> Result<Self, ValidationError> {
        let mut subjects = Vec::from(subjects);
        subjects.sort_by_key(|subject| subject.subject_id);
        let attestation = Self {
            schema_version: WINDOWS_PREVIEW_BUILD_ATTESTATION_SCHEMA_VERSION,
            kind: WindowsPreviewBuildAttestationKind::WindowsPreviewBuildAttestation,
            package_mode: DistributionMode::Preview,
            target_triple: WINDOWS_X86_64_TARGET.to_owned(),
            build_profile: BuildProfile::Release,
            cargo_incremental: false,
            source_identity,
            native_build,
            unsigned_preflight,
            subjects,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn kind(&self) -> &'static str {
        WINDOWS_PREVIEW_BUILD_ATTESTATION_KIND
    }

    pub fn package_mode(&self) -> DistributionMode {
        self.package_mode
    }

    pub fn target_triple(&self) -> &str {
        &self.target_triple
    }

    pub fn build_profile(&self) -> BuildProfile {
        self.build_profile
    }

    pub fn cargo_incremental(&self) -> bool {
        self.cargo_incremental
    }

    pub fn source_identity(&self) -> &WindowsPreviewBuildSourceIdentity {
        &self.source_identity
    }

    pub fn native_build(&self) -> &WindowsPreviewNativeBuild {
        &self.native_build
    }

    pub fn unsigned_preflight(&self) -> &WindowsPreviewUnsignedPreflight {
        &self.unsigned_preflight
    }

    pub fn subjects(&self) -> &[WindowsPreviewBuildSubject] {
        &self.subjects
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != WINDOWS_PREVIEW_BUILD_ATTESTATION_SCHEMA_VERSION {
            return Err(error(
                "build_attestation_schema_version_invalid",
                format!(
                    "schema_version must equal {WINDOWS_PREVIEW_BUILD_ATTESTATION_SCHEMA_VERSION}"
                ),
            ));
        }
        if self.kind != WindowsPreviewBuildAttestationKind::WindowsPreviewBuildAttestation {
            return Err(error(
                "build_attestation_kind_invalid",
                format!("kind must equal {WINDOWS_PREVIEW_BUILD_ATTESTATION_KIND}"),
            ));
        }
        if self.package_mode != DistributionMode::Preview {
            return Err(error(
                "build_attestation_package_mode_invalid",
                "package_mode must equal preview",
            ));
        }
        if self.target_triple != WINDOWS_X86_64_TARGET {
            return Err(error(
                "build_attestation_target_invalid",
                format!("target_triple must equal {WINDOWS_X86_64_TARGET}"),
            ));
        }
        if self.build_profile != BuildProfile::Release {
            return Err(error(
                "build_attestation_profile_invalid",
                "build_profile must equal release",
            ));
        }
        if self.cargo_incremental {
            return Err(error(
                "build_attestation_incremental_forbidden",
                "cargo_incremental must be false",
            ));
        }

        self.source_identity.validate()?;
        self.native_build.validate()?;
        self.unsigned_preflight.validate()?;
        self.validate_subjects()
    }

    pub fn to_pretty_json(&self) -> Result<Vec<u8>, ValidationError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|serialization_error| {
            error(
                "build_attestation_serialization_failed",
                format!("could not serialize build attestation: {serialization_error}"),
            )
        })?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn validate_subjects(&self) -> Result<(), ValidationError> {
        let expected = [
            WindowsPreviewBuildSubjectId::SourceArchive,
            WindowsPreviewBuildSubjectId::WindowsLsp,
            WindowsPreviewBuildSubjectId::WindowsServer,
        ];
        let actual = self
            .subjects
            .iter()
            .map(|subject| subject.subject_id)
            .collect::<Vec<_>>();
        if actual != expected {
            return Err(error(
                "build_attestation_subjects_invalid",
                "subjects must contain exactly source-archive, windows-lsp, and windows-server in that order",
            ));
        }

        for subject in &self.subjects {
            subject.validate()?;
            match subject.subject_id {
                WindowsPreviewBuildSubjectId::SourceArchive => {
                    if subject.unsigned_sha256.is_some() {
                        return Err(error(
                            "build_attestation_source_unsigned_digest_forbidden",
                            "source-archive must not declare unsigned_sha256",
                        ));
                    }
                }
                WindowsPreviewBuildSubjectId::WindowsLsp => {
                    if subject.unsigned_sha256.as_deref()
                        != Some(self.unsigned_preflight.lsp_binary_sha256.as_str())
                    {
                        return Err(error(
                            "build_attestation_unsigned_lsp_mismatch",
                            "windows-lsp unsigned_sha256 must match unsigned_preflight.lsp_binary_sha256",
                        ));
                    }
                    if subject.sha256 == self.unsigned_preflight.lsp_binary_sha256 {
                        return Err(error(
                            "build_attestation_signed_unsigned_digest_equal",
                            "windows-lsp final sha256 must differ from its unsigned preflight digest",
                        ));
                    }
                }
                WindowsPreviewBuildSubjectId::WindowsServer => {
                    if subject.unsigned_sha256.as_deref()
                        != Some(self.unsigned_preflight.preview_binary_sha256.as_str())
                    {
                        return Err(error(
                            "build_attestation_unsigned_server_mismatch",
                            "windows-server unsigned_sha256 must match unsigned_preflight.preview_binary_sha256",
                        ));
                    }
                    if subject.sha256 == self.unsigned_preflight.preview_binary_sha256 {
                        return Err(error(
                            "build_attestation_signed_unsigned_digest_equal",
                            "windows-server final sha256 must differ from its unsigned preflight digest",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn parse_and_validate_windows_preview_build_attestation(
    bytes: &[u8],
) -> Result<WindowsPreviewBuildAttestation, ValidationError> {
    let value = parse_strict_json(bytes).map_err(|parse_error| {
        error(
            "build_attestation_json_invalid",
            format!("strict JSON parse failed: {parse_error}"),
        )
    })?;
    let attestation: WindowsPreviewBuildAttestation =
        serde_json::from_value(value).map_err(|parse_error| {
            error(
                "build_attestation_schema_invalid",
                format!("build attestation does not match the closed schema: {parse_error}"),
            )
        })?;
    attestation.validate()?;
    Ok(attestation)
}

pub fn serialize_windows_preview_build_attestation(
    attestation: &WindowsPreviewBuildAttestation,
) -> Result<Vec<u8>, ValidationError> {
    attestation.to_pretty_json()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPreviewBuildSourceIdentityInput {
    pub git_object_format: GitObjectFormat,
    pub git_commit_oid: String,
    pub git_tree_oid: String,
    pub source_bundle_manifest_sha256: String,
    pub cargo_lock_sha256: String,
    pub dependency_input_closure_sha256: String,
    pub rust_toolchain_sha256: String,
    pub build_recipe_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPreviewBuildSourceIdentity {
    git_object_format: GitObjectFormat,
    git_commit_oid: String,
    git_tree_oid: String,
    source_bundle_manifest_sha256: String,
    cargo_lock_sha256: String,
    dependency_input_closure_sha256: String,
    rust_toolchain_sha256: String,
    build_recipe_sha256: String,
}

impl WindowsPreviewBuildSourceIdentity {
    pub fn new(input: WindowsPreviewBuildSourceIdentityInput) -> Result<Self, ValidationError> {
        let identity = Self {
            git_object_format: input.git_object_format,
            git_commit_oid: input.git_commit_oid,
            git_tree_oid: input.git_tree_oid,
            source_bundle_manifest_sha256: input.source_bundle_manifest_sha256,
            cargo_lock_sha256: input.cargo_lock_sha256,
            dependency_input_closure_sha256: input.dependency_input_closure_sha256,
            rust_toolchain_sha256: input.rust_toolchain_sha256,
            build_recipe_sha256: input.build_recipe_sha256,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn git_object_format(&self) -> GitObjectFormat {
        self.git_object_format
    }

    pub fn git_commit_oid(&self) -> &str {
        &self.git_commit_oid
    }

    pub fn git_tree_oid(&self) -> &str {
        &self.git_tree_oid
    }

    pub fn source_bundle_manifest_sha256(&self) -> &str {
        &self.source_bundle_manifest_sha256
    }

    pub fn cargo_lock_sha256(&self) -> &str {
        &self.cargo_lock_sha256
    }

    pub fn dependency_input_closure_sha256(&self) -> &str {
        &self.dependency_input_closure_sha256
    }

    pub fn rust_toolchain_sha256(&self) -> &str {
        &self.rust_toolchain_sha256
    }

    pub fn build_recipe_sha256(&self) -> &str {
        &self.build_recipe_sha256
    }

    fn validate(&self) -> Result<(), ValidationError> {
        let oid_length = match self.git_object_format {
            GitObjectFormat::Sha1 => 40,
            GitObjectFormat::Sha256 => 64,
        };
        require_lower_hex(
            &self.git_commit_oid,
            oid_length,
            "source_identity.git_commit_oid",
        )?;
        require_lower_hex(
            &self.git_tree_oid,
            oid_length,
            "source_identity.git_tree_oid",
        )?;
        for (digest, label) in [
            (
                &self.source_bundle_manifest_sha256,
                "source_identity.source_bundle_manifest_sha256",
            ),
            (&self.cargo_lock_sha256, "source_identity.cargo_lock_sha256"),
            (
                &self.dependency_input_closure_sha256,
                "source_identity.dependency_input_closure_sha256",
            ),
            (
                &self.rust_toolchain_sha256,
                "source_identity.rust_toolchain_sha256",
            ),
            (
                &self.build_recipe_sha256,
                "source_identity.build_recipe_sha256",
            ),
        ] {
            require_sha256(digest, label)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPreviewNativeBuildInput {
    pub workflow_sha256: String,
    pub run_id: u64,
    pub run_attempt: u64,
    pub compiler: String,
    pub preview_build_id: String,
    pub certified_arg_sha256: String,
    pub certified_arg_policy_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPreviewNativeBuild {
    authority: String,
    repository: String,
    workflow_path: String,
    workflow_sha256: String,
    run_id: u64,
    run_attempt: u64,
    runner_os: String,
    runner_arch: String,
    compiler: String,
    preview_build_id: String,
    certified_arg_sha256: String,
    certified_arg_policy_id: String,
    certified_arg_policy_sha256: String,
    crt_linkage: String,
    pe_import_policy_id: String,
}

impl WindowsPreviewNativeBuild {
    pub fn new(input: WindowsPreviewNativeBuildInput) -> Result<Self, ValidationError> {
        let native_build = Self {
            authority: NATIVE_BUILD_AUTHORITY.to_owned(),
            repository: NATIVE_BUILD_REPOSITORY.to_owned(),
            workflow_path: NATIVE_BUILD_WORKFLOW_PATH.to_owned(),
            workflow_sha256: input.workflow_sha256,
            run_id: input.run_id,
            run_attempt: input.run_attempt,
            runner_os: NATIVE_BUILD_RUNNER_OS.to_owned(),
            runner_arch: NATIVE_BUILD_RUNNER_ARCH.to_owned(),
            compiler: input.compiler,
            preview_build_id: input.preview_build_id,
            certified_arg_sha256: input.certified_arg_sha256,
            certified_arg_policy_id: CERTIFIED_ARG_POLICY_ID.to_owned(),
            certified_arg_policy_sha256: input.certified_arg_policy_sha256,
            crt_linkage: CRT_LINKAGE.to_owned(),
            pe_import_policy_id: PE_IMPORT_POLICY_ID.to_owned(),
        };
        native_build.validate()?;
        Ok(native_build)
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    pub fn workflow_sha256(&self) -> &str {
        &self.workflow_sha256
    }

    pub fn run_id(&self) -> u64 {
        self.run_id
    }

    pub fn run_attempt(&self) -> u64 {
        self.run_attempt
    }

    pub fn runner_os(&self) -> &str {
        &self.runner_os
    }

    pub fn runner_arch(&self) -> &str {
        &self.runner_arch
    }

    pub fn compiler(&self) -> &str {
        &self.compiler
    }

    pub fn preview_build_id(&self) -> &str {
        &self.preview_build_id
    }

    pub fn certified_arg_sha256(&self) -> &str {
        &self.certified_arg_sha256
    }

    pub fn certified_arg_policy_id(&self) -> &str {
        &self.certified_arg_policy_id
    }

    pub fn certified_arg_policy_sha256(&self) -> &str {
        &self.certified_arg_policy_sha256
    }

    pub fn crt_linkage(&self) -> &str {
        &self.crt_linkage
    }

    pub fn pe_import_policy_id(&self) -> &str {
        &self.pe_import_policy_id
    }

    fn validate(&self) -> Result<(), ValidationError> {
        for (actual, expected, label) in [
            (
                self.authority.as_str(),
                NATIVE_BUILD_AUTHORITY,
                "native_build.authority",
            ),
            (
                self.repository.as_str(),
                NATIVE_BUILD_REPOSITORY,
                "native_build.repository",
            ),
            (
                self.workflow_path.as_str(),
                NATIVE_BUILD_WORKFLOW_PATH,
                "native_build.workflow_path",
            ),
            (
                self.runner_os.as_str(),
                NATIVE_BUILD_RUNNER_OS,
                "native_build.runner_os",
            ),
            (
                self.runner_arch.as_str(),
                NATIVE_BUILD_RUNNER_ARCH,
                "native_build.runner_arch",
            ),
            (
                self.certified_arg_policy_id.as_str(),
                CERTIFIED_ARG_POLICY_ID,
                "native_build.certified_arg_policy_id",
            ),
            (
                self.crt_linkage.as_str(),
                CRT_LINKAGE,
                "native_build.crt_linkage",
            ),
            (
                self.pe_import_policy_id.as_str(),
                PE_IMPORT_POLICY_ID,
                "native_build.pe_import_policy_id",
            ),
        ] {
            if actual != expected {
                return Err(error(
                    "build_attestation_native_identity_invalid",
                    format!("{label} must equal {expected}"),
                ));
            }
        }
        if self.run_id == 0 || self.run_attempt == 0 {
            return Err(error(
                "build_attestation_native_run_invalid",
                "native_build.run_id and run_attempt must be positive",
            ));
        }
        if self.compiler.is_empty()
            || self.compiler.len() > 512
            || !self
                .compiler
                .bytes()
                .all(|byte| matches!(byte, b' '..=b'~'))
        {
            return Err(error(
                "build_attestation_compiler_invalid",
                "native_build.compiler must contain 1 to 512 printable ASCII bytes",
            ));
        }
        if !self.compiler.starts_with(REQUIRED_RUSTC_PREFIX)
            || !self.compiler.contains(REQUIRED_RUSTC_HOST)
        {
            return Err(error(
                "build_attestation_compiler_invalid",
                format!(
                    "native_build.compiler must identify native Rust 1.97.0 for {WINDOWS_X86_64_TARGET}"
                ),
            ));
        }
        for (digest, label) in [
            (&self.workflow_sha256, "native_build.workflow_sha256"),
            (&self.preview_build_id, "native_build.preview_build_id"),
            (
                &self.certified_arg_sha256,
                "native_build.certified_arg_sha256",
            ),
            (
                &self.certified_arg_policy_sha256,
                "native_build.certified_arg_policy_sha256",
            ),
        ] {
            require_sha256(digest, label)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPreviewUnsignedPreflight {
    sha256: String,
    preview_binary_sha256: String,
    lsp_binary_sha256: String,
}

impl WindowsPreviewUnsignedPreflight {
    pub fn new(
        sha256: String,
        preview_binary_sha256: String,
        lsp_binary_sha256: String,
    ) -> Result<Self, ValidationError> {
        let preflight = Self {
            sha256,
            preview_binary_sha256,
            lsp_binary_sha256,
        };
        preflight.validate()?;
        Ok(preflight)
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn preview_binary_sha256(&self) -> &str {
        &self.preview_binary_sha256
    }

    pub fn lsp_binary_sha256(&self) -> &str {
        &self.lsp_binary_sha256
    }

    fn validate(&self) -> Result<(), ValidationError> {
        for (digest, label) in [
            (&self.sha256, "unsigned_preflight.sha256"),
            (
                &self.preview_binary_sha256,
                "unsigned_preflight.preview_binary_sha256",
            ),
            (
                &self.lsp_binary_sha256,
                "unsigned_preflight.lsp_binary_sha256",
            ),
        ] {
            require_sha256(digest, label)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum WindowsPreviewBuildSubjectId {
    #[serde(rename = "source-archive")]
    SourceArchive,
    #[serde(rename = "windows-lsp")]
    WindowsLsp,
    #[serde(rename = "windows-server")]
    WindowsServer,
}

impl WindowsPreviewBuildSubjectId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceArchive => "source-archive",
            Self::WindowsLsp => "windows-lsp",
            Self::WindowsServer => "windows-server",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPreviewBuildSubject {
    subject_id: WindowsPreviewBuildSubjectId,
    sha256: String,
    size_bytes: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null_string"
    )]
    unsigned_sha256: Option<String>,
}

impl WindowsPreviewBuildSubject {
    pub fn source_archive(sha256: String, size_bytes: u64) -> Result<Self, ValidationError> {
        let subject = Self {
            subject_id: WindowsPreviewBuildSubjectId::SourceArchive,
            sha256,
            size_bytes,
            unsigned_sha256: None,
        };
        subject.validate()?;
        Ok(subject)
    }

    pub fn windows_lsp(
        sha256: String,
        size_bytes: u64,
        unsigned_sha256: String,
    ) -> Result<Self, ValidationError> {
        Self::executable(
            WindowsPreviewBuildSubjectId::WindowsLsp,
            sha256,
            size_bytes,
            unsigned_sha256,
        )
    }

    pub fn windows_server(
        sha256: String,
        size_bytes: u64,
        unsigned_sha256: String,
    ) -> Result<Self, ValidationError> {
        Self::executable(
            WindowsPreviewBuildSubjectId::WindowsServer,
            sha256,
            size_bytes,
            unsigned_sha256,
        )
    }

    pub fn subject_id(&self) -> WindowsPreviewBuildSubjectId {
        self.subject_id
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn unsigned_sha256(&self) -> Option<&str> {
        self.unsigned_sha256.as_deref()
    }

    fn executable(
        subject_id: WindowsPreviewBuildSubjectId,
        sha256: String,
        size_bytes: u64,
        unsigned_sha256: String,
    ) -> Result<Self, ValidationError> {
        let subject = Self {
            subject_id,
            sha256,
            size_bytes,
            unsigned_sha256: Some(unsigned_sha256),
        };
        subject.validate()?;
        Ok(subject)
    }

    fn validate(&self) -> Result<(), ValidationError> {
        require_sha256(&self.sha256, "subjects[].sha256")?;
        if self.size_bytes == 0 {
            return Err(error(
                "build_attestation_subject_empty",
                format!(
                    "subject {} size_bytes must be greater than zero",
                    self.subject_id.as_str()
                ),
            ));
        }
        if let Some(unsigned_sha256) = &self.unsigned_sha256 {
            require_sha256(unsigned_sha256, "subjects[].unsigned_sha256")?;
        }
        Ok(())
    }
}

fn deserialize_optional_non_null_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn hash(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn valid_value() -> Value {
        json!({
            "schema_version": 1,
            "kind": "windows_preview_build_attestation",
            "package_mode": "preview",
            "target_triple": "x86_64-pc-windows-msvc",
            "build_profile": "release",
            "cargo_incremental": false,
            "source_identity": {
                "git_object_format": "sha1",
                "git_commit_oid": "1".repeat(40),
                "git_tree_oid": "2".repeat(40),
                "source_bundle_manifest_sha256": hash('3'),
                "cargo_lock_sha256": hash('4'),
                "dependency_input_closure_sha256": hash('5'),
                "rust_toolchain_sha256": hash('6'),
                "build_recipe_sha256": hash('7')
            },
            "native_build": {
                "authority": "github_actions_windows_preview_review",
                "repository": "andagni/autocad-mcp",
                "workflow_path": ".github/workflows/windows-preview-review-candidate.yml",
                "workflow_sha256": hash('8'),
                "run_id": 1234,
                "run_attempt": 2,
                "runner_os": "Windows",
                "runner_arch": "X64",
                "compiler": "rustc 1.97.0 (test); host: x86_64-pc-windows-msvc",
                "preview_build_id": hash('9'),
                "certified_arg_sha256": hash('a'),
                "certified_arg_policy_id": "autocad-mcp-public-development-v1",
                "certified_arg_policy_sha256": hash('b'),
                "crt_linkage": "static",
                "pe_import_policy_id": "pe-no-vc-runtime-imports-v1"
            },
            "unsigned_preflight": {
                "sha256": hash('c'),
                "preview_binary_sha256": hash('d'),
                "lsp_binary_sha256": hash('e')
            },
            "subjects": [
                {
                    "subject_id": "source-archive",
                    "sha256": hash('f'),
                    "size_bytes": 100
                },
                {
                    "subject_id": "windows-lsp",
                    "sha256": hash('0'),
                    "size_bytes": 200,
                    "unsigned_sha256": hash('e')
                },
                {
                    "subject_id": "windows-server",
                    "sha256": hash('1'),
                    "size_bytes": 300,
                    "unsigned_sha256": hash('d')
                }
            ]
        })
    }

    fn parse_value(value: &Value) -> Result<WindowsPreviewBuildAttestation, ValidationError> {
        parse_and_validate_windows_preview_build_attestation(
            &serde_json::to_vec(value).expect("serialize test value"),
        )
    }

    fn valid_constructed_attestation() -> WindowsPreviewBuildAttestation {
        let source =
            WindowsPreviewBuildSourceIdentity::new(WindowsPreviewBuildSourceIdentityInput {
                git_object_format: GitObjectFormat::Sha1,
                git_commit_oid: "1".repeat(40),
                git_tree_oid: "2".repeat(40),
                source_bundle_manifest_sha256: hash('3'),
                cargo_lock_sha256: hash('4'),
                dependency_input_closure_sha256: hash('5'),
                rust_toolchain_sha256: hash('6'),
                build_recipe_sha256: hash('7'),
            })
            .expect("valid source identity");
        let native = WindowsPreviewNativeBuild::new(WindowsPreviewNativeBuildInput {
            workflow_sha256: hash('8'),
            run_id: 1234,
            run_attempt: 2,
            compiler: "rustc 1.97.0 (test); host: x86_64-pc-windows-msvc".to_owned(),
            preview_build_id: hash('9'),
            certified_arg_sha256: hash('a'),
            certified_arg_policy_sha256: hash('b'),
        })
        .expect("valid native build");
        let preflight = WindowsPreviewUnsignedPreflight::new(hash('c'), hash('d'), hash('e'))
            .expect("valid unsigned preflight");
        let source_subject = WindowsPreviewBuildSubject::source_archive(hash('f'), 100)
            .expect("valid source subject");
        let lsp_subject = WindowsPreviewBuildSubject::windows_lsp(hash('0'), 200, hash('e'))
            .expect("valid LSP subject");
        let server_subject = WindowsPreviewBuildSubject::windows_server(hash('1'), 300, hash('d'))
            .expect("valid server subject");
        WindowsPreviewBuildAttestation::new(
            source,
            native,
            preflight,
            [server_subject, source_subject, lsp_subject],
        )
        .expect("valid constructed attestation")
    }

    #[test]
    fn valid_attestation_exposes_every_join_and_round_trips_deterministically() {
        let parsed = parse_value(&valid_value()).expect("valid fixture");
        assert_eq!(parsed.schema_version(), 1);
        assert_eq!(parsed.kind(), WINDOWS_PREVIEW_BUILD_ATTESTATION_KIND);
        assert_eq!(parsed.package_mode(), DistributionMode::Preview);
        assert_eq!(parsed.target_triple(), WINDOWS_X86_64_TARGET);
        assert_eq!(parsed.build_profile(), BuildProfile::Release);
        assert!(!parsed.cargo_incremental());
        assert_eq!(
            parsed.source_identity().git_object_format(),
            GitObjectFormat::Sha1
        );
        assert_eq!(parsed.source_identity().git_commit_oid(), "1".repeat(40));
        assert_eq!(parsed.source_identity().git_tree_oid(), "2".repeat(40));
        assert_eq!(
            parsed.source_identity().source_bundle_manifest_sha256(),
            hash('3')
        );
        assert_eq!(parsed.source_identity().cargo_lock_sha256(), hash('4'));
        assert_eq!(
            parsed.source_identity().dependency_input_closure_sha256(),
            hash('5')
        );
        assert_eq!(parsed.source_identity().rust_toolchain_sha256(), hash('6'));
        assert_eq!(parsed.source_identity().build_recipe_sha256(), hash('7'));

        let native = parsed.native_build();
        assert_eq!(native.authority(), NATIVE_BUILD_AUTHORITY);
        assert_eq!(native.repository(), NATIVE_BUILD_REPOSITORY);
        assert_eq!(native.workflow_path(), NATIVE_BUILD_WORKFLOW_PATH);
        assert_eq!(native.workflow_sha256(), hash('8'));
        assert_eq!(native.run_id(), 1234);
        assert_eq!(native.run_attempt(), 2);
        assert_eq!(native.runner_os(), NATIVE_BUILD_RUNNER_OS);
        assert_eq!(native.runner_arch(), NATIVE_BUILD_RUNNER_ARCH);
        assert_eq!(
            native.compiler(),
            "rustc 1.97.0 (test); host: x86_64-pc-windows-msvc"
        );
        assert_eq!(native.preview_build_id(), hash('9'));
        assert_eq!(native.certified_arg_sha256(), hash('a'));
        assert_eq!(native.certified_arg_policy_id(), CERTIFIED_ARG_POLICY_ID);
        assert_eq!(native.certified_arg_policy_sha256(), hash('b'));
        assert_eq!(native.crt_linkage(), CRT_LINKAGE);
        assert_eq!(native.pe_import_policy_id(), PE_IMPORT_POLICY_ID);

        assert_eq!(parsed.unsigned_preflight().sha256(), hash('c'));
        assert_eq!(
            parsed.unsigned_preflight().preview_binary_sha256(),
            hash('d')
        );
        assert_eq!(parsed.unsigned_preflight().lsp_binary_sha256(), hash('e'));
        assert_eq!(
            parsed
                .subjects()
                .iter()
                .map(|subject| subject.subject_id().as_str())
                .collect::<Vec<_>>(),
            ["source-archive", "windows-lsp", "windows-server"]
        );
        assert_eq!(parsed.subjects()[0].sha256(), hash('f'));
        assert_eq!(parsed.subjects()[0].size_bytes(), 100);
        assert_eq!(parsed.subjects()[0].unsigned_sha256(), None);
        assert_eq!(
            parsed.subjects()[1].unsigned_sha256(),
            Some(hash('e').as_str())
        );

        let constructed = valid_constructed_attestation();
        let bytes = serialize_windows_preview_build_attestation(&constructed)
            .expect("serialize attestation");
        assert!(bytes.ends_with(b"\n"));
        assert!(!String::from_utf8_lossy(&bytes).contains("\"unsigned_sha256\": null"));
        let reparsed =
            parse_and_validate_windows_preview_build_attestation(&bytes).expect("round trip");
        assert_eq!(constructed, reparsed);
        assert_eq!(
            bytes,
            serialize_windows_preview_build_attestation(&reparsed).expect("stable serialization")
        );
    }

    #[test]
    fn duplicate_keys_unknown_fields_and_explicit_null_are_rejected() {
        let duplicate = br#"{"schema_version":1,"schema_version":1}"#;
        let duplicate_error =
            parse_and_validate_windows_preview_build_attestation(duplicate).unwrap_err();
        assert_eq!(duplicate_error.code(), "build_attestation_json_invalid");
        assert!(duplicate_error.detail().contains("duplicate JSON key"));

        let bytes = serde_json::to_vec(&valid_value()).expect("serialize fixture");
        let nested_duplicate = String::from_utf8(bytes).expect("UTF-8 fixture").replacen(
            "\"run_id\":1234",
            "\"run_id\":1234,\"run_id\":5678",
            1,
        );
        assert_eq!(
            parse_and_validate_windows_preview_build_attestation(nested_duplicate.as_bytes())
                .unwrap_err()
                .code(),
            "build_attestation_json_invalid"
        );

        let mut unknown = valid_value();
        unknown["native_build"]["runner_name"] = json!("private-runner");
        assert_eq!(
            parse_value(&unknown).unwrap_err().code(),
            "build_attestation_schema_invalid"
        );

        let mut explicit_null = valid_value();
        explicit_null["subjects"][0]["unsigned_sha256"] = Value::Null;
        assert_eq!(
            parse_value(&explicit_null).unwrap_err().code(),
            "build_attestation_schema_invalid"
        );
    }

    #[test]
    fn fixed_preview_recipe_and_native_identity_are_semantically_closed() {
        for (pointer, replacement, expected_code) in [
            (
                "/schema_version",
                json!(2),
                "build_attestation_schema_version_invalid",
            ),
            (
                "/package_mode",
                json!("release"),
                "build_attestation_package_mode_invalid",
            ),
            (
                "/target_triple",
                json!("aarch64-pc-windows-msvc"),
                "build_attestation_target_invalid",
            ),
            (
                "/cargo_incremental",
                json!(true),
                "build_attestation_incremental_forbidden",
            ),
            (
                "/native_build/repository",
                json!("other/repository"),
                "build_attestation_native_identity_invalid",
            ),
            (
                "/native_build/runner_os",
                json!("Linux"),
                "build_attestation_native_identity_invalid",
            ),
            (
                "/native_build/certified_arg_policy_id",
                json!("other-policy"),
                "build_attestation_native_identity_invalid",
            ),
            (
                "/native_build/run_id",
                json!(0),
                "build_attestation_native_run_invalid",
            ),
            (
                "/native_build/compiler",
                json!("rustc 1.97.0; host: aarch64-pc-windows-msvc"),
                "build_attestation_compiler_invalid",
            ),
        ] {
            let mut value = valid_value();
            *value.pointer_mut(pointer).expect("fixture pointer") = replacement;
            assert_eq!(
                parse_value(&value).unwrap_err().code(),
                expected_code,
                "{pointer}"
            );
        }
    }

    #[test]
    fn git_oid_length_is_selected_by_object_format() {
        parse_value(&valid_value()).expect("SHA-1 identity");

        let mut sha256 = valid_value();
        sha256["source_identity"]["git_object_format"] = json!("sha256");
        sha256["source_identity"]["git_commit_oid"] = json!("1".repeat(64));
        sha256["source_identity"]["git_tree_oid"] = json!("2".repeat(64));
        let parsed = parse_value(&sha256).expect("SHA-256 identity");
        assert_eq!(
            parsed.source_identity().git_object_format(),
            GitObjectFormat::Sha256
        );

        let mut sha1_with_long_oid = valid_value();
        sha1_with_long_oid["source_identity"]["git_commit_oid"] = json!("1".repeat(64));
        assert_eq!(
            parse_value(&sha1_with_long_oid).unwrap_err().code(),
            "lowercase_hex_invalid"
        );

        let mut sha256_with_short_oid = sha256;
        sha256_with_short_oid["source_identity"]["git_tree_oid"] = json!("2".repeat(40));
        assert_eq!(
            parse_value(&sha256_with_short_oid).unwrap_err().code(),
            "lowercase_hex_invalid"
        );
    }

    #[test]
    fn subject_set_order_and_unsigned_preflight_joins_are_exact() {
        let mut unsorted = valid_value();
        unsorted["subjects"]
            .as_array_mut()
            .expect("subjects")
            .swap(0, 1);
        assert_eq!(
            parse_value(&unsorted).unwrap_err().code(),
            "build_attestation_subjects_invalid"
        );

        let mut missing = valid_value();
        missing["subjects"].as_array_mut().expect("subjects").pop();
        assert_eq!(
            parse_value(&missing).unwrap_err().code(),
            "build_attestation_subjects_invalid"
        );

        let mut duplicate = valid_value();
        duplicate["subjects"][2]["subject_id"] = json!("windows-lsp");
        duplicate["subjects"][2]["unsigned_sha256"] = json!(hash('e'));
        assert_eq!(
            parse_value(&duplicate).unwrap_err().code(),
            "build_attestation_subjects_invalid"
        );

        let mut source_unsigned = valid_value();
        source_unsigned["subjects"][0]["unsigned_sha256"] = json!(hash('f'));
        assert_eq!(
            parse_value(&source_unsigned).unwrap_err().code(),
            "build_attestation_source_unsigned_digest_forbidden"
        );

        let mut missing_lsp_unsigned = valid_value();
        missing_lsp_unsigned["subjects"][1]
            .as_object_mut()
            .expect("LSP subject")
            .remove("unsigned_sha256");
        assert_eq!(
            parse_value(&missing_lsp_unsigned).unwrap_err().code(),
            "build_attestation_unsigned_lsp_mismatch"
        );

        let mut wrong_server_unsigned = valid_value();
        wrong_server_unsigned["subjects"][2]["unsigned_sha256"] = json!(hash('e'));
        assert_eq!(
            parse_value(&wrong_server_unsigned).unwrap_err().code(),
            "build_attestation_unsigned_server_mismatch"
        );
    }

    #[test]
    fn signed_executable_digests_must_differ_from_unsigned_preflight() {
        parse_value(&valid_value()).expect("signing may change executable bytes");

        for (subject_index, preflight_field) in
            [(1, "lsp_binary_sha256"), (2, "preview_binary_sha256")]
        {
            let mut equal = valid_value();
            equal["subjects"][subject_index]["sha256"] =
                equal["unsigned_preflight"][preflight_field].clone();
            assert_eq!(
                parse_value(&equal).unwrap_err().code(),
                "build_attestation_signed_unsigned_digest_equal",
                "subject {subject_index}"
            );
        }
    }

    #[test]
    fn checked_in_schema_matches_the_rust_contract() {
        let schema: Value = serde_json::from_str(include_str!(
            "../schemas/windows-preview-build-attestation.schema.json"
        ))
        .expect("parse checked-in schema");
        let validator = jsonschema::validator_for(&schema).expect("compile schema");
        assert!(validator.is_valid(&valid_value()));

        let mut unknown = valid_value();
        unknown["source_identity"]["unexpected"] = json!(true);
        assert!(!validator.is_valid(&unknown));

        let mut unsorted = valid_value();
        unsorted["subjects"]
            .as_array_mut()
            .expect("subjects")
            .swap(0, 1);
        assert!(!validator.is_valid(&unsorted));

        let mut wrong_sha1 = valid_value();
        wrong_sha1["source_identity"]["git_commit_oid"] = json!("1".repeat(64));
        assert!(!validator.is_valid(&wrong_sha1));

        let mut sha256 = valid_value();
        sha256["source_identity"]["git_object_format"] = json!("sha256");
        sha256["source_identity"]["git_commit_oid"] = json!("1".repeat(64));
        sha256["source_identity"]["git_tree_oid"] = json!("2".repeat(64));
        assert!(validator.is_valid(&sha256));

        let mut explicit_null = valid_value();
        explicit_null["subjects"][0]["unsigned_sha256"] = Value::Null;
        assert!(!validator.is_valid(&explicit_null));

        let mut controlled_compiler = valid_value();
        controlled_compiler["native_build"]["compiler"] =
            json!("rustc 1.97.0\t(test); host: x86_64-pc-windows-msvc");
        assert!(!validator.is_valid(&controlled_compiler));

        let mut non_ascii_compiler = valid_value();
        non_ascii_compiler["native_build"]["compiler"] =
            json!("rustc 1.97.0 (tést); host: x86_64-pc-windows-msvc");
        assert!(!validator.is_valid(&non_ascii_compiler));
        assert_eq!(
            parse_value(&non_ascii_compiler).unwrap_err().code(),
            "build_attestation_compiler_invalid"
        );
    }
}
