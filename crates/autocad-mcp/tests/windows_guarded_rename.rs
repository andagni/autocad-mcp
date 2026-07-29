use std::collections::BTreeSet;
use std::ffi::c_void;
use std::mem::{offset_of, size_of, MaybeUninit};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: u32 = 1;
const EVIDENCE_CLASS: &str = "windows_native_guarded_rename_feasibility";
const FILE_RENAME_REPLACE_IF_EXISTS: u32 = 0x0000_0001;
const FILE_RENAME_POSIX_SEMANTICS: u32 = 0x0000_0002;
const FILE_RENAME_INFO_EX_CLASS: i32 = 22;
const FILE_PERSISTENT_ACLS: u32 = 0x0000_0008;
const FILE_SUPPORTS_POSIX_UNLINK_RENAME: u32 = 0x0000_0400;
const FILE_NAMED_STREAMS: u32 = 0x0004_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
#[cfg(target_os = "windows")]
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_SHARING_VIOLATION: u32 = 32;
const NOT_REACHED_OBSERVATION: &str =
    "not reached because an earlier feasibility-probe step failed";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedApiOutcome {
    Success,
    SharingViolation,
    AccessDenied,
}

impl ExpectedApiOutcome {
    const fn matrix_label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::SharingViolation => "sharing_violation",
            Self::AccessDenied => "access_denied",
        }
    }

    const fn expected_result(self) -> (bool, Option<u32>) {
        match self {
            Self::Success => (true, None),
            Self::SharingViolation => (false, Some(ERROR_SHARING_VIOLATION)),
            Self::AccessDenied => (false, Some(ERROR_ACCESS_DENIED)),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum IdentityRole {
    Source,
    Destination,
}

impl IdentityRole {
    const fn matrix_label(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Destination => "destination",
        }
    }
}

#[derive(Clone, Copy)]
struct CaseDefinition {
    case_id: &'static str,
    api: &'static str,
    expected: &'static str,
    expected_api_outcome: ExpectedApiOutcome,
}

const CASE_DEFINITIONS: &[CaseDefinition] = &[
    CaseDefinition {
        case_id: "environment_boundary",
        api: "RtlGetVersion/GetVolumeInformationByHandleW/GetDriveTypeW",
        expected: "x86_64 Windows build >= 16299 on a fixed NTFS volume with POSIX rename support",
        expected_api_outcome: ExpectedApiOutcome::Success,
    },
    CaseDefinition {
        case_id: "unguarded_namespace_controls",
        api: "DeleteFileW/MoveFileExW/ReplaceFileW/SetFileInformationByHandle(FileRenameInfoEx)",
        expected: "equivalent unguarded delete and replacement calls succeed and install the expected objects",
        expected_api_outcome: ExpectedApiOutcome::Success,
    },
    CaseDefinition {
        case_id: "original_guard_identity",
        api: "CreateFileW/LockFileEx/GetFileInformationByHandleEx",
        expected: "retained no-delete original handle identifies and hashes the original object",
        expected_api_outcome: ExpectedApiOutcome::Success,
    },
    CaseDefinition {
        case_id: "original_competing_write_excluded",
        api: "CreateFileW",
        expected: "a competing write open fails while the original guard remains live",
        expected_api_outcome: ExpectedApiOutcome::SharingViolation,
    },
    CaseDefinition {
        case_id: "original_delete_excluded",
        api: "DeleteFileW",
        expected: "ordinary deletion fails and the guarded path identity remains unchanged",
        expected_api_outcome: ExpectedApiOutcome::SharingViolation,
    },
    CaseDefinition {
        case_id: "ordinary_rename_excluded",
        api: "MoveFileExW",
        expected: "ordinary replace-existing rename fails and the guarded path identity remains unchanged",
        expected_api_outcome: ExpectedApiOutcome::AccessDenied,
    },
    CaseDefinition {
        case_id: "replace_file_excluded",
        api: "ReplaceFileW",
        expected: "ReplaceFileW fails and the guarded path identity remains unchanged",
        expected_api_outcome: ExpectedApiOutcome::SharingViolation,
    },
    CaseDefinition {
        case_id: "prepared_guard_identity",
        api: "CreateFileW/LockFileEx/GetFileInformationByHandleEx",
        expected: "retained prepared handle is a distinct same-volume object with the verified digest",
        expected_api_outcome: ExpectedApiOutcome::Success,
    },
    CaseDefinition {
        case_id: "prepared_competing_write_excluded",
        api: "CreateFileW",
        expected: "a competing write open fails while the prepared guard remains live",
        expected_api_outcome: ExpectedApiOutcome::SharingViolation,
    },
    CaseDefinition {
        case_id: "prepared_delete_excluded",
        api: "DeleteFileW",
        expected: "ordinary deletion fails and the prepared path identity remains unchanged",
        expected_api_outcome: ExpectedApiOutcome::SharingViolation,
    },
    CaseDefinition {
        case_id: "prepared_ordinary_rename_excluded",
        api: "MoveFileExW",
        expected: "ordinary replace-existing rename fails and the prepared path identity remains unchanged",
        expected_api_outcome: ExpectedApiOutcome::AccessDenied,
    },
    CaseDefinition {
        case_id: "prepared_replace_file_excluded",
        api: "ReplaceFileW",
        expected: "ReplaceFileW fails and the prepared path identity remains unchanged",
        expected_api_outcome: ExpectedApiOutcome::SharingViolation,
    },
    CaseDefinition {
        case_id: "non_posix_handle_rename_excluded",
        api: "SetFileInformationByHandle(FileRenameInfoEx)",
        expected: "replace-without-POSIX fails against the no-delete guarded destination",
        expected_api_outcome: ExpectedApiOutcome::AccessDenied,
    },
    CaseDefinition {
        case_id: "posix_without_delete_share_excluded",
        api: "SetFileInformationByHandle(FileRenameInfoEx)",
        expected: "REPLACE_IF_EXISTS|POSIX_SEMANTICS fails while the no-delete original guard remains live",
        expected_api_outcome: ExpectedApiOutcome::SharingViolation,
    },
    CaseDefinition {
        case_id: "delete_shared_original_guard_identity",
        api: "CreateFileW/LockFileEx/GetFileInformationByHandleEx",
        expected: "the same original object is reacquired only after an explicit no-delete guard release/reacquire gap",
        expected_api_outcome: ExpectedApiOutcome::Success,
    },
    CaseDefinition {
        case_id: "delete_shared_competing_write_excluded",
        api: "CreateFileW",
        expected: "delete sharing still excludes a competing write open",
        expected_api_outcome: ExpectedApiOutcome::SharingViolation,
    },
    CaseDefinition {
        case_id: "non_posix_with_delete_share_excluded",
        api: "SetFileInformationByHandle(FileRenameInfoEx)",
        expected: "replace-without-POSIX still fails against an open delete-shared destination",
        expected_api_outcome: ExpectedApiOutcome::AccessDenied,
    },
    CaseDefinition {
        case_id: "delete_shared_guard_allows_delete",
        api: "DeleteFileW",
        expected: "ordinary deletion is admitted when the retained target handle shares delete access",
        expected_api_outcome: ExpectedApiOutcome::Success,
    },
    CaseDefinition {
        case_id: "posix_with_delete_share_install",
        api: "SetFileInformationByHandle(FileRenameInfoEx)",
        expected: "REPLACE_IF_EXISTS|POSIX_SEMANTICS installs the prepared object only after delete sharing is admitted",
        expected_api_outcome: ExpectedApiOutcome::Success,
    },
    CaseDefinition {
        case_id: "retained_original_observation",
        api: "GetFileInformationByHandleEx/ReadFile",
        expected: "the retained original handle still identifies and hashes the displaced original",
        expected_api_outcome: ExpectedApiOutcome::Success,
    },
    CaseDefinition {
        case_id: "installed_path_observation",
        api: "GetFileInformationByHandleEx/ReadFile",
        expected: "the destination path and installed handle identify the prepared object and its digest",
        expected_api_outcome: ExpectedApiOutcome::Success,
    },
    CaseDefinition {
        case_id: "write_through_flush",
        api: "FlushFileBuffers",
        expected: "the write-through installed handle flushes successfully after rename",
        expected_api_outcome: ExpectedApiOutcome::Success,
    },
    CaseDefinition {
        case_id: "installed_competing_write_excluded",
        api: "CreateFileW",
        expected: "a competing write open fails while the installed guard remains live",
        expected_api_outcome: ExpectedApiOutcome::SharingViolation,
    },
    CaseDefinition {
        case_id: "post_release_write_control",
        api: "CreateFileW/WriteFile",
        expected: "the same write control succeeds after the installed guard is released",
        expected_api_outcome: ExpectedApiOutcome::Success,
    },
    CaseDefinition {
        case_id: "same_content_delete_shared_replacement",
        api: "SetFileInformationByHandle(FileRenameInfoEx)",
        expected: "a distinct same-content object can POSIX-replace a delete-shared path and is detected by identity",
        expected_api_outcome: ExpectedApiOutcome::Success,
    },
];

const LIMITATIONS: &[&str] = &[
    "acl_owner_group_dacl_and_named_stream_policy",
    "empirical_power_loss_survival",
    "failure_injection_and_mutation_state_classification",
    "memory_mapped_non_cooperating_writer",
    "minimum_windows_and_non_ntfs_negative_hosts",
    "production_boundary_integration",
    "share_mode_transition_is_not_continuously_guarded",
    "two_process_barrier_interleavings",
];

const NO_IDENTITY_TRANSITIONS: &[IdentityRole] = &[];
const DESTINATION_IDENTITY_TRANSITION: &[IdentityRole] = &[IdentityRole::Destination];
const SOURCE_DESTINATION_IDENTITY_TRANSITIONS: &[IdentityRole] =
    &[IdentityRole::Source, IdentityRole::Destination];

fn expected_identity_roles(case_id: &str) -> &'static [IdentityRole] {
    match case_id {
        "original_delete_excluded" | "prepared_delete_excluded" => DESTINATION_IDENTITY_TRANSITION,
        "ordinary_rename_excluded"
        | "replace_file_excluded"
        | "prepared_ordinary_rename_excluded"
        | "prepared_replace_file_excluded"
        | "non_posix_handle_rename_excluded"
        | "posix_without_delete_share_excluded"
        | "non_posix_with_delete_share_excluded" => SOURCE_DESTINATION_IDENTITY_TRANSITIONS,
        _ => NO_IDENTITY_TRANSITIONS,
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FileRenameInfo {
    flags: u32,
    root_directory: *mut c_void,
    file_name_length: u32,
    file_name: [u16; 1],
}

struct RenameBuffer {
    storage: Vec<MaybeUninit<FileRenameInfo>>,
    byte_len: u32,
    name_units: usize,
}

impl RenameBuffer {
    fn new(destination: &[u16], flags: u32) -> Result<Self, String> {
        if destination.is_empty() {
            return Err("rename destination must not be empty".to_string());
        }
        if destination.contains(&0) {
            return Err("rename destination must not contain NUL".to_string());
        }

        let name_bytes = destination
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| "rename destination length overflow".to_string())?;
        let file_name_length = u32::try_from(name_bytes)
            .map_err(|_| "rename destination exceeds the Win32 byte bound".to_string())?;
        let byte_len = size_of::<FileRenameInfo>()
            .checked_add(name_bytes)
            .and_then(|length| length.checked_add(size_of::<u16>()))
            .ok_or_else(|| "rename buffer length overflow".to_string())?;
        let byte_len = u32::try_from(byte_len)
            .map_err(|_| "rename buffer exceeds the Win32 byte bound".to_string())?;
        let slots = (byte_len as usize).div_ceil(size_of::<MaybeUninit<FileRenameInfo>>());
        let mut storage = Vec::with_capacity(slots);
        storage.resize_with(slots, MaybeUninit::zeroed);
        let information = storage.as_mut_ptr().cast::<FileRenameInfo>();

        // SAFETY: `storage` is aligned for `FileRenameInfo`, has at least
        // `byte_len` initialized zero bytes, and the flexible name begins at
        // the actual field offset rather than the padded structure size.
        unsafe {
            std::ptr::addr_of_mut!((*information).flags).write(flags);
            std::ptr::addr_of_mut!((*information).root_directory).write(std::ptr::null_mut());
            std::ptr::addr_of_mut!((*information).file_name_length).write(file_name_length);
            let name = std::ptr::addr_of_mut!((*information).file_name).cast::<u16>();
            std::ptr::copy_nonoverlapping(destination.as_ptr(), name, destination.len());
            name.add(destination.len()).write(0);
        }

        Ok(Self {
            storage,
            byte_len,
            name_units: destination.len(),
        })
    }

    fn flags(&self) -> u32 {
        // SAFETY: construction initialized the fixed header.
        unsafe { self.storage.as_ptr().cast::<FileRenameInfo>().read().flags }
    }

    fn file_name_length(&self) -> u32 {
        // SAFETY: construction initialized the fixed header.
        unsafe {
            self.storage
                .as_ptr()
                .cast::<FileRenameInfo>()
                .read()
                .file_name_length
        }
    }

    fn destination(&self) -> &[u16] {
        // SAFETY: construction wrote `name_units` UTF-16 units beginning at
        // the flexible-array offset and retains the aligned backing storage.
        unsafe {
            let information = self.storage.as_ptr().cast::<FileRenameInfo>();
            let name = std::ptr::addr_of!((*information).file_name).cast::<u16>();
            std::slice::from_raw_parts(name, self.name_units)
        }
    }

    #[cfg(target_os = "windows")]
    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.storage.as_mut_ptr().cast()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CaseStatus {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceEvidence {
    commit: String,
    tree: String,
    dirty: bool,
    harness_sha256: String,
    cargo_lock_sha256: String,
    test_binary_sha256: String,
    rustc_verbose: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RunnerEvidence {
    runner_name: Option<String>,
    image_os: Option<String>,
    image_version: Option<String>,
    github_sha: Option<String>,
    github_run_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MachineEvidence {
    operating_system: String,
    architecture: String,
    os_build: Option<u32>,
    runner: RunnerEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VolumeEvidence {
    file_system: String,
    drive_type: u32,
    formatted_volume_serial: String,
    file_id_volume_serial: String,
    file_system_flags: u32,
    persistent_acls: bool,
    named_streams: bool,
    posix_unlink_rename: bool,
    same_volume: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PrimitiveEvidence {
    api: String,
    information_class: i32,
    flags: u32,
    write_through: bool,
    no_delete_original_share_mode: u32,
    delete_shared_original_share_mode: u32,
    prepared_share_mode: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FileProjectionEvidence {
    volume_serial_number: String,
    file_id: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FileIdentityEvidence {
    volume_serial_number: String,
    file_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityTransitionEvidence {
    role: IdentityRole,
    before: FileIdentityEvidence,
    after: FileIdentityEvidence,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionEvidence {
    original_before: Option<FileProjectionEvidence>,
    prepared_before: Option<FileProjectionEvidence>,
    no_delete_original_after_rejected: Option<FileProjectionEvidence>,
    no_delete_prepared_after_rejected: Option<FileProjectionEvidence>,
    delete_shared_original_before: Option<FileProjectionEvidence>,
    retained_original_after: Option<FileProjectionEvidence>,
    installed_handle_after: Option<FileProjectionEvidence>,
    installed_path_after: Option<FileProjectionEvidence>,
    delete_shared_delete_before: Option<FileProjectionEvidence>,
    delete_shared_delete_retained_after: Option<FileProjectionEvidence>,
    same_content_original_before: Option<FileProjectionEvidence>,
    same_content_attacker_before: Option<FileProjectionEvidence>,
    same_content_retained_after: Option<FileProjectionEvidence>,
    same_content_path_after: Option<FileProjectionEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseEvidence {
    case_id: String,
    status: CaseStatus,
    api: String,
    expected: String,
    expected_api_outcome: ExpectedApiOutcome,
    identity_transitions: Vec<IdentityTransitionEvidence>,
    observed: String,
    api_returned_success: Option<bool>,
    win32_error: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FeasibilityEvidence {
    schema_version: u32,
    evidence_class: String,
    matrix_sha256: String,
    source: SourceEvidence,
    machine: MachineEvidence,
    volume: Option<VolumeEvidence>,
    primitive: PrimitiveEvidence,
    projections: ProjectionEvidence,
    cases: Vec<CaseEvidence>,
    limitations: Vec<String>,
    validation_errors: Vec<String>,
    first_failure_case: Option<String>,
    candidate_accepted: bool,
    production_enabled: bool,
    autocad_required: bool,
    status: CaseStatus,
}

fn matrix_sha256() -> String {
    let mut hasher = Sha256::new();
    for definition in CASE_DEFINITIONS {
        hasher.update(definition.case_id.as_bytes());
        hasher.update([0]);
        hasher.update(definition.api.as_bytes());
        hasher.update([0]);
        hasher.update(definition.expected.as_bytes());
        hasher.update([0]);
        hasher.update(definition.expected_api_outcome.matrix_label().as_bytes());
        for role in expected_identity_roles(definition.case_id) {
            hasher.update([0]);
            hasher.update(role.matrix_label().as_bytes());
        }
        hasher.update([0xff]);
    }
    for limitation in LIMITATIONS {
        hasher.update(limitation.as_bytes());
        hasher.update([0xfe]);
    }
    format!("{:x}", hasher.finalize())
}

fn empty_cases() -> Vec<CaseEvidence> {
    CASE_DEFINITIONS
        .iter()
        .map(|definition| CaseEvidence {
            case_id: definition.case_id.to_string(),
            status: CaseStatus::Failed,
            api: definition.api.to_string(),
            expected: definition.expected.to_string(),
            expected_api_outcome: definition.expected_api_outcome,
            identity_transitions: Vec::new(),
            observed: NOT_REACHED_OBSERVATION.to_string(),
            api_returned_success: None,
            win32_error: None,
        })
        .collect()
}

fn evidence_content_errors(evidence: &FeasibilityEvidence) -> Vec<String> {
    let mut errors = Vec::new();
    if evidence.schema_version != SCHEMA_VERSION {
        errors.push("unsupported schema_version".to_string());
    }
    if evidence.evidence_class != EVIDENCE_CLASS {
        errors.push("unexpected evidence_class".to_string());
    }
    if evidence.matrix_sha256 != matrix_sha256() {
        errors.push("matrix_sha256 does not bind the closed case inventory".to_string());
    }
    if evidence.candidate_accepted {
        errors.push("feasibility evidence must not accept the incompatible candidate".to_string());
    }
    if evidence.production_enabled {
        errors.push("feasibility evidence must not report production enabled".to_string());
    }
    if evidence.autocad_required {
        errors.push("native filesystem feasibility evidence must not require AutoCAD".to_string());
    }
    if evidence.primitive.api != "SetFileInformationByHandle"
        || evidence.primitive.information_class != FILE_RENAME_INFO_EX_CLASS
        || evidence.primitive.flags != FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS
        || !evidence.primitive.write_through
        || evidence.primitive.no_delete_original_share_mode != FILE_SHARE_READ
        || evidence.primitive.delete_shared_original_share_mode
            != FILE_SHARE_READ | FILE_SHARE_DELETE
        || evidence.primitive.prepared_share_mode != FILE_SHARE_READ
    {
        errors.push("primitive identity, flags, or share-mode matrix changed".to_string());
    }

    let expected_case_ids = CASE_DEFINITIONS
        .iter()
        .map(|definition| definition.case_id)
        .collect::<Vec<_>>();
    let actual_case_ids = evidence
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<Vec<_>>();
    if actual_case_ids != expected_case_ids {
        errors.push("case inventory is missing, duplicated, or out of order".to_string());
    }
    let unique_case_ids = actual_case_ids.iter().copied().collect::<BTreeSet<_>>();
    if unique_case_ids.len() != actual_case_ids.len() {
        errors.push("case inventory contains duplicates".to_string());
    }
    if evidence.cases.len() == CASE_DEFINITIONS.len() {
        for (case, definition) in evidence.cases.iter().zip(CASE_DEFINITIONS) {
            if case.api != definition.api
                || case.expected != definition.expected
                || case.expected_api_outcome != definition.expected_api_outcome
            {
                errors.push(format!(
                    "case {} API or expected result contract changed",
                    definition.case_id
                ));
            }
            let expected_roles = expected_identity_roles(definition.case_id);
            let actual_roles = case
                .identity_transitions
                .iter()
                .map(|transition| transition.role)
                .collect::<Vec<_>>();
            let unique_roles = actual_roles.iter().copied().collect::<BTreeSet<_>>();
            if unique_roles.len() != actual_roles.len()
                || actual_roles
                    .iter()
                    .any(|role| !expected_roles.contains(role))
            {
                errors.push(format!(
                    "case {} contains duplicate or unexpected identity transitions",
                    definition.case_id
                ));
            }
            if case.status == CaseStatus::Passed && actual_roles.as_slice() != expected_roles {
                errors.push(format!(
                    "passed case {} lacks its closed identity-transition inventory",
                    definition.case_id
                ));
            }
            for transition in &case.identity_transitions {
                for (position, identity) in
                    [("before", &transition.before), ("after", &transition.after)]
                {
                    if identity.volume_serial_number.len() != 16
                        || !identity
                            .volume_serial_number
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit())
                        || identity.file_id.len() != 32
                        || !identity
                            .file_id
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit())
                    {
                        errors.push(format!(
                            "case {} {} identity transition is not closed",
                            definition.case_id, position
                        ));
                    }
                    if evidence.volume.as_ref().is_some_and(|volume| {
                        identity.volume_serial_number != volume.file_id_volume_serial
                    }) {
                        errors.push(format!(
                            "case {} {} identity volume does not match the admitted volume",
                            definition.case_id, position
                        ));
                    }
                }
                if case.status == CaseStatus::Passed && transition.before != transition.after {
                    errors.push(format!(
                        "passed rejected case {} changed its {:?} identity",
                        definition.case_id, transition.role
                    ));
                }
            }
            if case.status == CaseStatus::Passed
                && case.identity_transitions.len() == 2
                && case.identity_transitions[0].before == case.identity_transitions[1].before
            {
                errors.push(format!(
                    "passed case {} does not identify distinct source and destination objects",
                    definition.case_id
                ));
            }
            if case.status == CaseStatus::Passed
                && (case.observed.trim().is_empty() || case.observed == NOT_REACHED_OBSERVATION)
            {
                errors.push(format!(
                    "passed case {} retains an empty or not-reached observation",
                    definition.case_id
                ));
            }
            if case.status == CaseStatus::Passed {
                let (expected_success, expected_error) =
                    definition.expected_api_outcome.expected_result();
                if case.api_returned_success != Some(expected_success)
                    || case.win32_error != expected_error
                {
                    errors.push(format!(
                        "passed case {} does not match its bound API outcome",
                        definition.case_id
                    ));
                }
            } else if matches!(
                (case.api_returned_success, case.win32_error),
                (Some(true), Some(_)) | (Some(false), None)
            ) {
                errors.push(format!(
                    "case {} API success field is inconsistent with status and Win32 error",
                    definition.case_id
                ));
            }
        }
    }

    let expected_limitations = LIMITATIONS
        .iter()
        .map(|limitation| (*limitation).to_string())
        .collect::<Vec<_>>();
    if evidence.limitations != expected_limitations {
        errors.push("feasibility-evidence limitation boundary changed".to_string());
    }

    for (name, digest) in [
        ("harness_sha256", &evidence.source.harness_sha256),
        ("cargo_lock_sha256", &evidence.source.cargo_lock_sha256),
        ("test_binary_sha256", &evidence.source.test_binary_sha256),
    ] {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            errors.push(format!("{name} must be one SHA-256 digest"));
        }
    }
    for (name, object) in [
        ("commit", &evidence.source.commit),
        ("tree", &evidence.source.tree),
    ] {
        if object.len() != 40 || !object.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            errors.push(format!("{name} must be one full Git object ID"));
        }
    }
    if evidence.source.rustc_verbose.trim().is_empty() {
        errors.push("rustc_verbose must be present".to_string());
    }
    if evidence
        .machine
        .runner
        .github_sha
        .as_ref()
        .is_some_and(|github_sha| github_sha != &evidence.source.commit)
    {
        errors.push("GITHUB_SHA does not match the checked-out commit".to_string());
    }
    if let Some(volume) = &evidence.volume {
        if volume.formatted_volume_serial.len() != 8
            || !volume
                .formatted_volume_serial
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || volume.file_id_volume_serial.len() != 16
            || !volume
                .file_id_volume_serial
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            errors.push("volume serials are not fixed-width hexadecimal values".to_string());
        }
        if volume.persistent_acls != (volume.file_system_flags & FILE_PERSISTENT_ACLS != 0)
            || volume.named_streams != (volume.file_system_flags & FILE_NAMED_STREAMS != 0)
            || volume.posix_unlink_rename
                != (volume.file_system_flags & FILE_SUPPORTS_POSIX_UNLINK_RENAME != 0)
        {
            errors.push("volume capability booleans do not match file_system_flags".to_string());
        }
    }

    for (name, projection) in [
        ("original_before", &evidence.projections.original_before),
        ("prepared_before", &evidence.projections.prepared_before),
        (
            "no_delete_original_after_rejected",
            &evidence.projections.no_delete_original_after_rejected,
        ),
        (
            "no_delete_prepared_after_rejected",
            &evidence.projections.no_delete_prepared_after_rejected,
        ),
        (
            "delete_shared_original_before",
            &evidence.projections.delete_shared_original_before,
        ),
        (
            "retained_original_after",
            &evidence.projections.retained_original_after,
        ),
        (
            "installed_handle_after",
            &evidence.projections.installed_handle_after,
        ),
        (
            "installed_path_after",
            &evidence.projections.installed_path_after,
        ),
        (
            "delete_shared_delete_before",
            &evidence.projections.delete_shared_delete_before,
        ),
        (
            "delete_shared_delete_retained_after",
            &evidence.projections.delete_shared_delete_retained_after,
        ),
        (
            "same_content_original_before",
            &evidence.projections.same_content_original_before,
        ),
        (
            "same_content_attacker_before",
            &evidence.projections.same_content_attacker_before,
        ),
        (
            "same_content_retained_after",
            &evidence.projections.same_content_retained_after,
        ),
        (
            "same_content_path_after",
            &evidence.projections.same_content_path_after,
        ),
    ] {
        if let Some(projection) = projection {
            if projection.volume_serial_number.len() != 16
                || !projection
                    .volume_serial_number
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || projection.file_id.len() != 32
                || !projection
                    .file_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || projection.sha256.len() != 64
                || !projection
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                errors.push(format!("{name} is not a closed file projection"));
            }
            if evidence.volume.as_ref().is_some_and(|volume| {
                projection.volume_serial_number != volume.file_id_volume_serial
            }) {
                errors.push(format!(
                    "{name} volume serial does not match the admitted volume"
                ));
            }
        }
    }

    let all_cases_passed = evidence
        .cases
        .iter()
        .all(|case| case.status == CaseStatus::Passed);
    if all_cases_passed {
        if evidence.source.dirty {
            errors.push("passing evidence must be bound to a clean checkout".to_string());
        }
        if evidence.machine.operating_system != "windows"
            || evidence.machine.architecture != "x86_64"
            || evidence.machine.os_build.is_none_or(|build| build < 16_299)
        {
            errors
                .push("passing evidence is outside the admitted Windows host boundary".to_string());
        }
        match &evidence.volume {
            Some(volume)
                if volume.file_system.eq_ignore_ascii_case("NTFS")
                    && volume.drive_type == 3
                    && volume.persistent_acls
                    && volume.named_streams
                    && volume.posix_unlink_rename
                    && volume.same_volume => {}
            _ => errors.push(
                "passing evidence requires fixed same-volume NTFS capability facts".to_string(),
            ),
        }
        match &evidence.projections {
            ProjectionEvidence {
                original_before: Some(original_before),
                prepared_before: Some(prepared_before),
                no_delete_original_after_rejected: Some(no_delete_original_after_rejected),
                no_delete_prepared_after_rejected: Some(no_delete_prepared_after_rejected),
                delete_shared_original_before: Some(delete_shared_original_before),
                retained_original_after: Some(retained_original_after),
                installed_handle_after: Some(installed_handle_after),
                installed_path_after: Some(installed_path_after),
                delete_shared_delete_before: Some(delete_shared_delete_before),
                delete_shared_delete_retained_after: Some(delete_shared_delete_retained_after),
                same_content_original_before: Some(same_content_original_before),
                same_content_attacker_before: Some(same_content_attacker_before),
                same_content_retained_after: Some(same_content_retained_after),
                same_content_path_after: Some(same_content_path_after),
            } if original_before == no_delete_original_after_rejected
                && prepared_before == no_delete_prepared_after_rejected
                && original_before == delete_shared_original_before
                && original_before == retained_original_after
                && prepared_before == installed_handle_after
                && prepared_before == installed_path_after
                && delete_shared_delete_before == delete_shared_delete_retained_after
                && same_content_original_before == same_content_retained_after
                && same_content_attacker_before == same_content_path_after
                && same_content_original_before.sha256 == same_content_attacker_before.sha256
                && original_before.volume_serial_number == prepared_before.volume_serial_number
                && original_before.file_id != prepared_before.file_id
                && same_content_original_before.volume_serial_number
                    == same_content_attacker_before.volume_serial_number
                && same_content_original_before.file_id != same_content_attacker_before.file_id => {
            }
            _ => errors.push(
                "passing evidence lacks consistent structured before/after projections".to_string(),
            ),
        }
    }

    errors
}

fn finalize_evidence(evidence: &mut FeasibilityEvidence) {
    evidence.validation_errors = evidence_content_errors(evidence);
    evidence.first_failure_case = evidence
        .cases
        .iter()
        .find(|case| case.status == CaseStatus::Failed)
        .map(|case| case.case_id.clone());
    evidence.status =
        if evidence.first_failure_case.is_none() && evidence.validation_errors.is_empty() {
            CaseStatus::Passed
        } else {
            CaseStatus::Failed
        };
}

fn validate_evidence(evidence: &FeasibilityEvidence) -> Result<(), String> {
    let expected_validation_errors = evidence_content_errors(evidence);
    let mut errors = Vec::new();
    if evidence.validation_errors != expected_validation_errors {
        errors.push("validation_errors do not match the evidence envelope".to_string());
    }
    let expected_first_failure = evidence
        .cases
        .iter()
        .find(|case| case.status == CaseStatus::Failed)
        .map(|case| case.case_id.clone());
    if evidence.first_failure_case != expected_first_failure {
        errors.push("first_failure_case does not match ordered case results".to_string());
    }
    let expected_status =
        if expected_first_failure.is_none() && expected_validation_errors.is_empty() {
            CaseStatus::Passed
        } else {
            CaseStatus::Failed
        };
    if evidence.status != expected_status {
        errors.push("overall status does not match cases and envelope validation".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[test]
fn rename_buffer_uses_the_flexible_array_offset() {
    let destination = "C:\\probe\\prepared.dwg".encode_utf16().collect::<Vec<_>>();
    let flags = FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS;
    let buffer = RenameBuffer::new(&destination, flags).unwrap();

    assert_eq!(buffer.flags(), flags);
    assert_eq!(
        buffer.file_name_length(),
        u32::try_from(destination.len() * size_of::<u16>()).unwrap()
    );
    assert_eq!(buffer.destination(), destination);
    assert!(
        offset_of!(FileRenameInfo, file_name) < size_of::<FileRenameInfo>(),
        "the flexible array starts before x64 tail padding"
    );
    assert!(
        buffer.byte_len as usize
            >= offset_of!(FileRenameInfo, file_name)
                + destination.len() * size_of::<u16>()
                + size_of::<u16>()
    );
}

#[test]
fn evidence_schema_is_closed_and_failure_aware() {
    let mut evidence = FeasibilityEvidence {
        schema_version: SCHEMA_VERSION,
        evidence_class: EVIDENCE_CLASS.to_string(),
        matrix_sha256: matrix_sha256(),
        source: SourceEvidence {
            commit: "1".repeat(40),
            tree: "2".repeat(40),
            dirty: false,
            harness_sha256: "3".repeat(64),
            cargo_lock_sha256: "4".repeat(64),
            test_binary_sha256: "5".repeat(64),
            rustc_verbose: "rustc test".to_string(),
        },
        machine: MachineEvidence {
            operating_system: "windows".to_string(),
            architecture: "x86_64".to_string(),
            os_build: Some(26_100),
            runner: RunnerEvidence {
                runner_name: None,
                image_os: None,
                image_version: None,
                github_sha: None,
                github_run_id: None,
            },
        },
        volume: Some(VolumeEvidence {
            file_system: "NTFS".to_string(),
            drive_type: 3,
            formatted_volume_serial: "12345678".to_string(),
            file_id_volume_serial: "1234567890abcdef".to_string(),
            file_system_flags: FILE_PERSISTENT_ACLS
                | FILE_NAMED_STREAMS
                | FILE_SUPPORTS_POSIX_UNLINK_RENAME,
            persistent_acls: true,
            named_streams: true,
            posix_unlink_rename: true,
            same_volume: true,
        }),
        primitive: PrimitiveEvidence {
            api: "SetFileInformationByHandle".to_string(),
            information_class: FILE_RENAME_INFO_EX_CLASS,
            flags: FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
            write_through: true,
            no_delete_original_share_mode: FILE_SHARE_READ,
            delete_shared_original_share_mode: FILE_SHARE_READ | FILE_SHARE_DELETE,
            prepared_share_mode: FILE_SHARE_READ,
        },
        projections: ProjectionEvidence::default(),
        cases: empty_cases(),
        limitations: LIMITATIONS
            .iter()
            .map(|limitation| (*limitation).to_string())
            .collect(),
        validation_errors: Vec::new(),
        first_failure_case: Some(CASE_DEFINITIONS[0].case_id.to_string()),
        candidate_accepted: false,
        production_enabled: false,
        autocad_required: false,
        status: CaseStatus::Failed,
    };
    finalize_evidence(&mut evidence);
    validate_evidence(&evidence).unwrap();

    for case in &mut evidence.cases {
        case.status = CaseStatus::Passed;
        case.observed = "passed".to_string();
        let (success, error) = case.expected_api_outcome.expected_result();
        case.api_returned_success = Some(success);
        case.win32_error = error;
        case.identity_transitions = expected_identity_roles(&case.case_id)
            .iter()
            .map(|role| {
                let identity = FileIdentityEvidence {
                    volume_serial_number: "1234567890abcdef".to_string(),
                    file_id: match role {
                        IdentityRole::Source => "e".repeat(32),
                        IdentityRole::Destination => "f".repeat(32),
                    },
                };
                IdentityTransitionEvidence {
                    role: *role,
                    before: identity.clone(),
                    after: identity,
                }
            })
            .collect();
    }
    let projection = |file_id: char, sha256: char| FileProjectionEvidence {
        volume_serial_number: "1234567890abcdef".to_string(),
        file_id: file_id.to_string().repeat(32),
        sha256: sha256.to_string().repeat(64),
    };
    let original = projection('1', 'a');
    let prepared = projection('2', 'b');
    let delete_shared_delete = projection('3', 'c');
    let same_content_original = projection('4', 'd');
    let same_content_attacker = projection('5', 'd');
    evidence.projections = ProjectionEvidence {
        original_before: Some(original.clone()),
        prepared_before: Some(prepared.clone()),
        no_delete_original_after_rejected: Some(original.clone()),
        no_delete_prepared_after_rejected: Some(prepared.clone()),
        delete_shared_original_before: Some(original.clone()),
        retained_original_after: Some(original),
        installed_handle_after: Some(prepared.clone()),
        installed_path_after: Some(prepared),
        delete_shared_delete_before: Some(delete_shared_delete.clone()),
        delete_shared_delete_retained_after: Some(delete_shared_delete),
        same_content_original_before: Some(same_content_original.clone()),
        same_content_attacker_before: Some(same_content_attacker.clone()),
        same_content_retained_after: Some(same_content_original),
        same_content_path_after: Some(same_content_attacker),
    };
    finalize_evidence(&mut evidence);
    validate_evidence(&evidence).unwrap();
    assert_eq!(evidence.status, CaseStatus::Passed);
    let passing = evidence.clone();

    let mut inconsistent_volume = passing.clone();
    inconsistent_volume
        .volume
        .as_mut()
        .expect("passing fixture has volume facts")
        .file_system_flags = 0;
    finalize_evidence(&mut inconsistent_volume);
    assert_eq!(inconsistent_volume.status, CaseStatus::Failed);
    assert!(inconsistent_volume
        .validation_errors
        .iter()
        .any(|error| error.contains("capability booleans")));

    let mut not_reached_pass = passing.clone();
    not_reached_pass.cases[0].observed = NOT_REACHED_OBSERVATION.to_string();
    finalize_evidence(&mut not_reached_pass);
    assert_eq!(not_reached_pass.status, CaseStatus::Failed);
    assert!(not_reached_pass
        .validation_errors
        .iter()
        .any(|error| error.contains("not-reached observation")));

    let mut changed_case_contract = passing.clone();
    changed_case_contract.cases[0].api.push_str("/unexpected");
    finalize_evidence(&mut changed_case_contract);
    assert_eq!(changed_case_contract.status, CaseStatus::Failed);
    assert!(changed_case_contract
        .validation_errors
        .iter()
        .any(|error| error.contains("API or expected result contract changed")));

    let mut wrong_api_outcome = passing.clone();
    let sharing_case = wrong_api_outcome
        .cases
        .iter_mut()
        .find(|case| case.expected_api_outcome == ExpectedApiOutcome::SharingViolation)
        .expect("passing fixture includes a sharing-violation case");
    sharing_case.api_returned_success = Some(true);
    sharing_case.win32_error = None;
    finalize_evidence(&mut wrong_api_outcome);
    assert_eq!(wrong_api_outcome.status, CaseStatus::Failed);
    assert!(wrong_api_outcome
        .validation_errors
        .iter()
        .any(|error| error.contains("bound API outcome")));

    let mut accepted_candidate = passing.clone();
    accepted_candidate.candidate_accepted = true;
    finalize_evidence(&mut accepted_candidate);
    assert_eq!(accepted_candidate.status, CaseStatus::Failed);
    assert!(accepted_candidate
        .validation_errors
        .iter()
        .any(|error| error.contains("incompatible candidate")));

    let mut changed_share_matrix = passing.clone();
    changed_share_matrix
        .primitive
        .delete_shared_original_share_mode = FILE_SHARE_READ;
    finalize_evidence(&mut changed_share_matrix);
    assert_eq!(changed_share_matrix.status, CaseStatus::Failed);
    assert!(changed_share_matrix
        .validation_errors
        .iter()
        .any(|error| error.contains("share-mode matrix")));

    let mut missing_identity_transition = passing.clone();
    missing_identity_transition
        .cases
        .iter_mut()
        .find(|case| !case.identity_transitions.is_empty())
        .expect("passing fixture includes identity transitions")
        .identity_transitions
        .pop();
    finalize_evidence(&mut missing_identity_transition);
    assert_eq!(missing_identity_transition.status, CaseStatus::Failed);
    assert!(missing_identity_transition
        .validation_errors
        .iter()
        .any(|error| error.contains("closed identity-transition inventory")));

    let mut changed_identity_transition = passing.clone();
    changed_identity_transition
        .cases
        .iter_mut()
        .flat_map(|case| &mut case.identity_transitions)
        .next()
        .expect("passing fixture includes identity transitions")
        .after
        .file_id = "a".repeat(32);
    finalize_evidence(&mut changed_identity_transition);
    assert_eq!(changed_identity_transition.status, CaseStatus::Failed);
    assert!(changed_identity_transition
        .validation_errors
        .iter()
        .any(|error| error.contains("changed its")));

    let mut inconsistent_projection = passing.clone();
    inconsistent_projection
        .projections
        .installed_path_after
        .as_mut()
        .expect("passing fixture has installed path projection")
        .file_id = "f".repeat(32);
    finalize_evidence(&mut inconsistent_projection);
    assert_eq!(inconsistent_projection.status, CaseStatus::Failed);
    assert!(inconsistent_projection
        .validation_errors
        .iter()
        .any(|error| error.contains("structured before/after projections")));

    let mut inconsistent_projection_volume = passing.clone();
    inconsistent_projection_volume
        .projections
        .original_before
        .as_mut()
        .expect("passing fixture has original projection")
        .volume_serial_number = "f".repeat(16);
    finalize_evidence(&mut inconsistent_projection_volume);
    assert_eq!(inconsistent_projection_volume.status, CaseStatus::Failed);
    assert!(inconsistent_projection_volume
        .validation_errors
        .iter()
        .any(|error| error.contains("admitted volume")));

    evidence = passing;
    evidence.source.dirty = true;
    finalize_evidence(&mut evidence);
    validate_evidence(&evidence).unwrap();
    assert_eq!(evidence.status, CaseStatus::Failed);
    assert_eq!(
        evidence.validation_errors,
        ["passing evidence must be bound to a clean checkout"]
    );
    evidence.status = CaseStatus::Passed;
    assert!(validate_evidence(&evidence).is_err());
    finalize_evidence(&mut evidence);

    let mut serialized = serde_json::to_value(&evidence).unwrap();
    serialized["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<FeasibilityEvidence>(serialized).is_err());
}

#[cfg(target_os = "windows")]
mod windows {
    use std::ffi::{c_void, OsStr};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::mem::{offset_of, size_of, MaybeUninit};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use sha2::{Digest, Sha256};

    use super::{
        empty_cases, finalize_evidence, matrix_sha256, validate_evidence, CaseEvidence, CaseStatus,
        FeasibilityEvidence, FileIdentityEvidence, FileProjectionEvidence, IdentityRole,
        IdentityTransitionEvidence, MachineEvidence, PrimitiveEvidence, ProjectionEvidence,
        RenameBuffer, RunnerEvidence, SourceEvidence, VolumeEvidence, CASE_DEFINITIONS,
        ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, EVIDENCE_CLASS, FILE_NAMED_STREAMS,
        FILE_PERSISTENT_ACLS, FILE_RENAME_INFO_EX_CLASS, FILE_RENAME_POSIX_SEMANTICS,
        FILE_RENAME_REPLACE_IF_EXISTS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_SUPPORTS_POSIX_UNLINK_RENAME, LIMITATIONS, NOT_REACHED_OBSERVATION, SCHEMA_VERSION,
    };

    type Bool = i32;
    type Dword = u32;
    type Handle = *mut c_void;

    const DELETE: Dword = 0x0001_0000;
    const SYNCHRONIZE: Dword = 0x0010_0000;
    const GENERIC_READ: Dword = 0x8000_0000;
    const GENERIC_WRITE: Dword = 0x4000_0000;
    const FILE_FLAG_WRITE_THROUGH: Dword = 0x8000_0000;
    const LOCKFILE_FAIL_IMMEDIATELY: Dword = 0x0000_0001;
    const LOCKFILE_EXCLUSIVE_LOCK: Dword = 0x0000_0002;
    const FILE_ID_INFO_CLASS: i32 = 18;
    const MOVEFILE_REPLACE_EXISTING: Dword = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: Dword = 0x0000_0008;
    const DRIVE_FIXED: Dword = 3;

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileId128 {
        identifier: [u8; 16],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileIdInfo {
        volume_serial_number: u64,
        file_id: FileId128,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileIdentity {
        volume_serial_number: u64,
        file_id: [u8; 16],
    }

    impl FileIdentity {
        fn display(self) -> String {
            format!(
                "{:016x}:{}",
                self.volume_serial_number,
                hex_bytes(&self.file_id)
            )
        }

        fn projection(self, sha256: String) -> FileProjectionEvidence {
            FileProjectionEvidence {
                volume_serial_number: format!("{:016x}", self.volume_serial_number),
                file_id: hex_bytes(&self.file_id),
                sha256,
            }
        }

        fn evidence(self) -> FileIdentityEvidence {
            FileIdentityEvidence {
                volume_serial_number: format!("{:016x}", self.volume_serial_number),
                file_id: hex_bytes(&self.file_id),
            }
        }
    }

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: Dword,
        offset_high: Dword,
        event: Handle,
    }

    impl Overlapped {
        fn zeroed() -> Self {
            Self {
                internal: 0,
                internal_high: 0,
                offset: 0,
                offset_high: 0,
                event: std::ptr::null_mut(),
            }
        }
    }

    #[repr(C)]
    struct OsVersionInfo {
        size: Dword,
        major: Dword,
        minor: Dword,
        build: Dword,
        platform_id: Dword,
        service_pack: [u16; 128],
    }

    impl OsVersionInfo {
        fn zeroed() -> Self {
            Self {
                size: u32::try_from(size_of::<Self>()).expect("OS version structure fits DWORD"),
                major: 0,
                minor: 0,
                build: 0,
                platform_id: 0,
                service_pack: [0; 128],
            }
        }
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn DeleteFileW(file_name: *const u16) -> Bool;
        fn FlushFileBuffers(file: Handle) -> Bool;
        fn GetDriveTypeW(root_path_name: *const u16) -> Dword;
        fn GetFileInformationByHandleEx(
            file: Handle,
            information_class: i32,
            information: *mut c_void,
            buffer_size: Dword,
        ) -> Bool;
        fn GetVolumeInformationByHandleW(
            file: Handle,
            volume_name: *mut u16,
            volume_name_size: Dword,
            volume_serial_number: *mut Dword,
            maximum_component_length: *mut Dword,
            file_system_flags: *mut Dword,
            file_system_name: *mut u16,
            file_system_name_size: Dword,
        ) -> Bool;
        fn GetVolumePathNameW(
            file_name: *const u16,
            volume_path_name: *mut u16,
            buffer_length: Dword,
        ) -> Bool;
        fn LockFileEx(
            file: Handle,
            flags: Dword,
            reserved: Dword,
            bytes_low: Dword,
            bytes_high: Dword,
            overlapped: *mut Overlapped,
        ) -> Bool;
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: Dword,
        ) -> Bool;
        fn ReplaceFileW(
            replaced_file_name: *const u16,
            replacement_file_name: *const u16,
            backup_file_name: *const u16,
            replace_flags: Dword,
            exclude: *const c_void,
            reserved: *const c_void,
        ) -> Bool;
        fn SetFileInformationByHandle(
            file: Handle,
            information_class: i32,
            information: *const c_void,
            buffer_size: Dword,
        ) -> Bool;
        fn UnlockFileEx(
            file: Handle,
            reserved: Dword,
            bytes_low: Dword,
            bytes_high: Dword,
            overlapped: *mut Overlapped,
        ) -> Bool;
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(version: *mut OsVersionInfo) -> i32;
    }

    struct LockedFile {
        file: File,
        overlapped: Overlapped,
    }

    impl LockedFile {
        fn acquire_no_delete_original(path: &Path) -> io::Result<Self> {
            let file = open_access(path, GENERIC_READ, FILE_SHARE_READ, 0)?;
            Self::lock(file)
        }

        fn acquire_delete_shared_original(path: &Path) -> io::Result<Self> {
            let file = open_access(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, 0)?;
            Self::lock(file)
        }

        fn acquire_prepared(path: &Path) -> io::Result<Self> {
            let file = open_access(
                path,
                GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
                FILE_SHARE_READ,
                FILE_FLAG_WRITE_THROUGH,
            )?;
            Self::lock(file)
        }

        fn lock(file: File) -> io::Result<Self> {
            let mut overlapped = Overlapped::zeroed();
            // SAFETY: the handle and overlapped storage are live for the
            // synchronous call; the requested range covers the complete file.
            let result = unsafe {
                LockFileEx(
                    raw_handle(&file),
                    LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                )
            };
            if result == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { file, overlapped })
        }
    }

    impl Drop for LockedFile {
        fn drop(&mut self) {
            // SAFETY: this guard owns the live handle and the same range and
            // offset structure used for its successful lock.
            let _ = unsafe {
                UnlockFileEx(
                    raw_handle(&self.file),
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut self.overlapped,
                )
            };
        }
    }

    #[derive(Debug)]
    struct NativeFailure {
        api: &'static str,
        detail: String,
        api_returned_success: Option<bool>,
        win32_error: Option<u32>,
    }

    impl NativeFailure {
        fn io(api: &'static str, error: io::Error) -> Self {
            Self {
                api,
                detail: error.to_string(),
                api_returned_success: error.raw_os_error().map(|_| false),
                win32_error: error.raw_os_error().map(|code| code as u32),
            }
        }

        fn invariant(api: &'static str, detail: impl Into<String>) -> Self {
            Self {
                api,
                detail: detail.into(),
                api_returned_success: None,
                win32_error: None,
            }
        }

        fn after_api(
            api: &'static str,
            detail: impl Into<String>,
            api_returned_success: bool,
            win32_error: Option<u32>,
        ) -> Self {
            debug_assert_eq!(api_returned_success, win32_error.is_none());
            Self {
                api,
                detail: detail.into(),
                api_returned_success: Some(api_returned_success),
                win32_error,
            }
        }
    }

    struct Recorder {
        evidence: FeasibilityEvidence,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                evidence: FeasibilityEvidence {
                    schema_version: SCHEMA_VERSION,
                    evidence_class: EVIDENCE_CLASS.to_string(),
                    matrix_sha256: matrix_sha256(),
                    source: source_evidence(),
                    machine: MachineEvidence {
                        operating_system: std::env::consts::OS.to_string(),
                        architecture: std::env::consts::ARCH.to_string(),
                        os_build: None,
                        runner: RunnerEvidence {
                            runner_name: std::env::var("RUNNER_NAME").ok(),
                            image_os: std::env::var("ImageOS").ok(),
                            image_version: std::env::var("ImageVersion").ok(),
                            github_sha: std::env::var("GITHUB_SHA").ok(),
                            github_run_id: std::env::var("GITHUB_RUN_ID").ok(),
                        },
                    },
                    volume: None,
                    primitive: PrimitiveEvidence {
                        api: "SetFileInformationByHandle".to_string(),
                        information_class: FILE_RENAME_INFO_EX_CLASS,
                        flags: FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
                        write_through: true,
                        no_delete_original_share_mode: FILE_SHARE_READ,
                        delete_shared_original_share_mode: FILE_SHARE_READ | FILE_SHARE_DELETE,
                        prepared_share_mode: FILE_SHARE_READ,
                    },
                    projections: ProjectionEvidence::default(),
                    cases: empty_cases(),
                    limitations: LIMITATIONS
                        .iter()
                        .map(|limitation| (*limitation).to_string())
                        .collect(),
                    validation_errors: Vec::new(),
                    first_failure_case: Some(CASE_DEFINITIONS[0].case_id.to_string()),
                    candidate_accepted: false,
                    production_enabled: false,
                    autocad_required: false,
                    status: CaseStatus::Failed,
                },
            }
        }

        fn record_identity_transitions(
            &mut self,
            case_id: &str,
            transitions: &[(IdentityRole, FileIdentity, FileIdentity)],
        ) {
            let case = self.case_mut(case_id);
            assert_eq!(
                case.observed, NOT_REACHED_OBSERVATION,
                "feasibility-probe case {case_id} recorded identities after transition"
            );
            assert!(
                case.identity_transitions.is_empty(),
                "feasibility-probe case {case_id} recorded identities more than once"
            );
            case.identity_transitions = transitions
                .iter()
                .map(|(role, before, after)| IdentityTransitionEvidence {
                    role: *role,
                    before: before.evidence(),
                    after: after.evidence(),
                })
                .collect();
        }

        fn observe_after_failed_api<T>(
            &mut self,
            case_id: &str,
            api: &'static str,
            win32_error: u32,
            observation: &'static str,
            result: io::Result<T>,
        ) -> Option<T> {
            match result {
                Ok(value) => Some(value),
                Err(error) => {
                    self.fail(
                        case_id,
                        NativeFailure::after_api(
                            api,
                            format!("{observation}: {error}"),
                            false,
                            Some(win32_error),
                        ),
                    );
                    None
                }
            }
        }

        fn pass(&mut self, case_id: &str, observed: impl Into<String>, win32_error: Option<u32>) {
            let case = self.case_mut(case_id);
            assert_eq!(
                case.observed, NOT_REACHED_OBSERVATION,
                "feasibility-probe case {case_id} transitioned more than once"
            );
            case.status = CaseStatus::Passed;
            case.observed = observed.into();
            case.api_returned_success = Some(win32_error.is_none());
            case.win32_error = win32_error;
        }

        fn fail(&mut self, case_id: &str, failure: NativeFailure) {
            let case = self.case_mut(case_id);
            assert_eq!(
                case.observed, NOT_REACHED_OBSERVATION,
                "feasibility-probe case {case_id} transitioned more than once"
            );
            case.status = CaseStatus::Failed;
            case.observed = format!("{}: {}", failure.api, failure.detail);
            case.api_returned_success = failure.api_returned_success;
            case.win32_error = failure.win32_error;
        }

        fn case_mut(&mut self, case_id: &str) -> &mut CaseEvidence {
            self.evidence
                .cases
                .iter_mut()
                .find(|case| case.case_id == case_id)
                .unwrap_or_else(|| panic!("unknown feasibility-probe case {case_id}"))
        }

        fn finish(mut self) -> FeasibilityEvidence {
            finalize_evidence(&mut self.evidence);
            self.evidence
        }
    }

    #[test]
    fn windows_guarded_rename_feasibility_probe() {
        let mut recorder = Recorder::new();
        run_probe(&mut recorder);
        let evidence = recorder.finish();
        let validation = validate_evidence(&evidence);
        let output = evidence_path();
        write_evidence(&output, &evidence).unwrap_or_else(|error| {
            panic!(
                "failed to write feasibility evidence {}: {error}",
                output.display()
            )
        });

        assert!(
            validation.is_ok() && evidence.status == CaseStatus::Passed,
            "Windows guarded-rename feasibility probe failed; evidence={}; integrity={}; \
validation_errors={:?}; first_failure_case={:?}",
            output.display(),
            validation
                .err()
                .unwrap_or_else(|| "self-consistent evidence envelope".to_string()),
            evidence.validation_errors,
            evidence.first_failure_case,
        );
    }

    fn run_probe(recorder: &mut Recorder) {
        if let Err(failure) = verify_raw_layout() {
            recorder.fail("environment_boundary", failure);
            return;
        }
        let temporary = match tempfile::Builder::new()
            .prefix("autocad-mcp-windows-rename-")
            .tempdir()
        {
            Ok(temporary) => temporary,
            Err(error) => {
                recorder.fail(
                    "environment_boundary",
                    NativeFailure::io("create probe directory", error),
                );
                return;
            }
        };
        let host = temporary.path().join("host.dwg");
        let prepared = temporary.path().join("prepared.dwg");
        let original_move_source = temporary.path().join("original-move-source.dwg");
        let original_replace_source = temporary.path().join("original-replace-source.dwg");
        let prepared_move_source = temporary.path().join("prepared-move-source.dwg");
        let prepared_replace_source = temporary.path().join("prepared-replace-source.dwg");
        let non_posix_source = temporary.path().join("non-posix-source.dwg");
        let delete_shared_non_posix_source =
            temporary.path().join("delete-shared-non-posix-source.dwg");
        if let Err(error) = write_synced(&host, b"original-host")
            .and_then(|_| write_synced(&prepared, b"prepared-output"))
            .and_then(|_| write_synced(&original_move_source, b"original-move-source"))
            .and_then(|_| write_synced(&original_replace_source, b"original-replace-source"))
            .and_then(|_| write_synced(&prepared_move_source, b"prepared-move-source"))
            .and_then(|_| write_synced(&prepared_replace_source, b"prepared-replace-source"))
            .and_then(|_| write_synced(&non_posix_source, b"non-posix-source"))
            .and_then(|_| {
                write_synced(
                    &delete_shared_non_posix_source,
                    b"delete-shared-non-posix-source",
                )
            })
        {
            recorder.fail(
                "environment_boundary",
                NativeFailure::io("create probe files", error),
            );
            return;
        }

        let environment_file = match open_observer(&host) {
            Ok(file) => file,
            Err(error) => {
                recorder.fail(
                    "environment_boundary",
                    NativeFailure::io("open environment probe handle", error),
                );
                return;
            }
        };
        let os_build = match os_build() {
            Ok(build) => build,
            Err(failure) => {
                recorder.fail("environment_boundary", failure);
                return;
            }
        };
        recorder.evidence.machine.os_build = Some(os_build);
        let volume = match volume_facts(&environment_file, &host) {
            Ok(volume) => volume,
            Err(failure) => {
                recorder.fail("environment_boundary", failure);
                return;
            }
        };
        let environment_identity = match file_identity(&environment_file) {
            Ok(identity) => identity,
            Err(error) => {
                recorder.fail(
                    "environment_boundary",
                    NativeFailure::io("GetFileInformationByHandleEx", error),
                );
                return;
            }
        };
        recorder.evidence.volume = Some(VolumeEvidence {
            file_system: volume.file_system.clone(),
            drive_type: volume.drive_type,
            formatted_volume_serial: format!("{:08x}", volume.formatted_volume_serial),
            file_id_volume_serial: format!("{:016x}", environment_identity.volume_serial_number),
            file_system_flags: volume.file_system_flags,
            persistent_acls: volume.file_system_flags & FILE_PERSISTENT_ACLS != 0,
            named_streams: volume.file_system_flags & FILE_NAMED_STREAMS != 0,
            posix_unlink_rename: volume.file_system_flags & FILE_SUPPORTS_POSIX_UNLINK_RENAME != 0,
            same_volume: false,
        });
        if std::env::consts::ARCH != "x86_64"
            || os_build < 16_299
            || !volume.file_system.eq_ignore_ascii_case("NTFS")
            || volume.drive_type != DRIVE_FIXED
            || volume.file_system_flags & FILE_PERSISTENT_ACLS == 0
            || volume.file_system_flags & FILE_NAMED_STREAMS == 0
            || volume.file_system_flags & FILE_SUPPORTS_POSIX_UNLINK_RENAME == 0
        {
            recorder.fail(
                "environment_boundary",
                NativeFailure::invariant(
                    "host admission",
                    format!(
                        "arch={}, build={os_build}, filesystem={}, drive_type={}, flags=0x{:08x}",
                        std::env::consts::ARCH,
                        volume.file_system,
                        volume.drive_type,
                        volume.file_system_flags
                    ),
                ),
            );
            return;
        }
        recorder.pass(
            "environment_boundary",
            format!(
                "build={os_build}; filesystem={}; drive_type={}; flags=0x{:08x}",
                volume.file_system, volume.drive_type, volume.file_system_flags
            ),
            None,
        );
        drop(environment_file);
        match unguarded_namespace_controls(temporary.path()) {
            Ok(observed) => {
                recorder.pass("unguarded_namespace_controls", observed, None);
            }
            Err(failure) => {
                recorder.fail("unguarded_namespace_controls", failure);
                return;
            }
        }

        let mut original = match LockedFile::acquire_no_delete_original(&host) {
            Ok(guard) => guard,
            Err(error) => {
                recorder.fail(
                    "original_guard_identity",
                    NativeFailure::io("acquire original guard", error),
                );
                return;
            }
        };
        let original_identity = match file_identity(&original.file) {
            Ok(identity) => identity,
            Err(error) => {
                recorder.fail(
                    "original_guard_identity",
                    NativeFailure::io("observe original identity", error),
                );
                return;
            }
        };
        let original_digest = match hash_handle(&mut original.file) {
            Ok(digest) => digest,
            Err(error) => {
                recorder.fail(
                    "original_guard_identity",
                    NativeFailure::io("hash original handle", error),
                );
                return;
            }
        };
        recorder.evidence.projections.original_before =
            Some(original_identity.projection(original_digest.clone()));
        recorder.pass(
            "original_guard_identity",
            format!(
                "identity={}; digest={original_digest}",
                original_identity.display()
            ),
            None,
        );

        match expect_open_failure(&host, GENERIC_WRITE) {
            Ok(error) => recorder.pass(
                "original_competing_write_excluded",
                "competing write open was excluded",
                Some(error),
            ),
            Err(failure) => {
                recorder.fail("original_competing_write_excluded", failure);
                return;
            }
        }
        match expect_path_api_failure("DeleteFileW", &[ERROR_SHARING_VIOLATION], || {
            let path = wide_path(&host)?;
            // SAFETY: `path` is a live NUL-terminated UTF-16 string.
            win32_call("DeleteFileW", unsafe { DeleteFileW(path.as_ptr()) })
        }) {
            Ok(error) => {
                let Some(original_after) = recorder.observe_after_failed_api(
                    "original_delete_excluded",
                    "DeleteFileW",
                    error,
                    "observe guarded path after expected failure",
                    path_identity(&host),
                ) else {
                    return;
                };
                recorder.record_identity_transitions(
                    "original_delete_excluded",
                    &[(IdentityRole::Destination, original_identity, original_after)],
                );
                if original_after != original_identity {
                    recorder.fail(
                        "original_delete_excluded",
                        NativeFailure::after_api(
                            "DeleteFileW",
                            "guarded path identity changed after expected failure",
                            false,
                            Some(error),
                        ),
                    );
                    return;
                }
                recorder.pass(
                    "original_delete_excluded",
                    format!(
                        "delete failed and path remained {}",
                        original_after.display()
                    ),
                    Some(error),
                )
            }
            Err(failure) => {
                recorder.fail("original_delete_excluded", failure);
                return;
            }
        }
        let original_move_identity = match path_identity(&original_move_source) {
            Ok(identity) => identity,
            Err(error) => {
                recorder.fail(
                    "ordinary_rename_excluded",
                    NativeFailure::io("observe ordinary move source", error),
                );
                return;
            }
        };
        // `MoveFileExW` reports the guarded replace-existing namespace denial
        // as `ERROR_ACCESS_DENIED`. The safety fact is the rejected call plus
        // unchanged source/destination identities; this feasibility row does
        // not admit a mutation path.
        match expect_path_api_failure("MoveFileExW", &[ERROR_ACCESS_DENIED], || {
            let source = wide_path(&original_move_source)?;
            let destination = wide_path(&host)?;
            // SAFETY: both path buffers are live NUL-terminated UTF-16 strings.
            win32_call("MoveFileExW", unsafe {
                MoveFileExW(
                    source.as_ptr(),
                    destination.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING,
                )
            })
        }) {
            Ok(error) => {
                let Some(original_after) = recorder.observe_after_failed_api(
                    "ordinary_rename_excluded",
                    "MoveFileExW",
                    error,
                    "observe guarded destination after expected failure",
                    path_identity(&host),
                ) else {
                    return;
                };
                let Some(source_after) = recorder.observe_after_failed_api(
                    "ordinary_rename_excluded",
                    "MoveFileExW",
                    error,
                    "observe move source after expected failure",
                    path_identity(&original_move_source),
                ) else {
                    return;
                };
                recorder.record_identity_transitions(
                    "ordinary_rename_excluded",
                    &[
                        (IdentityRole::Source, original_move_identity, source_after),
                        (IdentityRole::Destination, original_identity, original_after),
                    ],
                );
                if original_after != original_identity || source_after != original_move_identity {
                    recorder.fail(
                        "ordinary_rename_excluded",
                        NativeFailure::after_api(
                            "MoveFileExW",
                            "source or guarded destination identity changed after expected failure",
                            false,
                            Some(error),
                        ),
                    );
                    return;
                }
                recorder.pass(
                    "ordinary_rename_excluded",
                    "ordinary replace-existing rename returned ERROR_ACCESS_DENIED; source and destination identities remained unchanged",
                    Some(error),
                )
            }
            Err(failure) => {
                recorder.fail("ordinary_rename_excluded", failure);
                return;
            }
        }
        let original_replace_identity = match path_identity(&original_replace_source) {
            Ok(identity) => identity,
            Err(error) => {
                recorder.fail(
                    "replace_file_excluded",
                    NativeFailure::io("observe ReplaceFileW source", error),
                );
                return;
            }
        };
        match expect_path_api_failure("ReplaceFileW", &[ERROR_SHARING_VIOLATION], || {
            let destination = wide_path(&host)?;
            let replacement = wide_path(&original_replace_source)?;
            // SAFETY: both path buffers remain live; null optional arguments
            // request no backup and no exclusion list.
            win32_call("ReplaceFileW", unsafe {
                ReplaceFileW(
                    destination.as_ptr(),
                    replacement.as_ptr(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    std::ptr::null(),
                )
            })
        }) {
            Ok(error) => {
                let Some(original_after) = recorder.observe_after_failed_api(
                    "replace_file_excluded",
                    "ReplaceFileW",
                    error,
                    "observe guarded destination after expected failure",
                    path_identity(&host),
                ) else {
                    return;
                };
                let Some(source_after) = recorder.observe_after_failed_api(
                    "replace_file_excluded",
                    "ReplaceFileW",
                    error,
                    "observe replacement source after expected failure",
                    path_identity(&original_replace_source),
                ) else {
                    return;
                };
                recorder.record_identity_transitions(
                    "replace_file_excluded",
                    &[
                        (
                            IdentityRole::Source,
                            original_replace_identity,
                            source_after,
                        ),
                        (IdentityRole::Destination, original_identity, original_after),
                    ],
                );
                if original_after != original_identity || source_after != original_replace_identity
                {
                    recorder.fail(
                        "replace_file_excluded",
                        NativeFailure::after_api(
                            "ReplaceFileW",
                            "replacement source or guarded destination identity changed after expected failure",
                            false,
                            Some(error),
                        ),
                    );
                    return;
                }
                recorder.pass(
                    "replace_file_excluded",
                    "ReplaceFileW returned ERROR_SHARING_VIOLATION; replacement source and guarded destination identities remained unchanged",
                    Some(error),
                )
            }
            Err(failure) => {
                recorder.fail("replace_file_excluded", failure);
                return;
            }
        }

        let mut prepared_guard = match LockedFile::acquire_prepared(&prepared) {
            Ok(guard) => guard,
            Err(error) => {
                recorder.fail(
                    "prepared_guard_identity",
                    NativeFailure::io("acquire prepared guard", error),
                );
                return;
            }
        };
        let prepared_identity = match file_identity(&prepared_guard.file) {
            Ok(identity) => identity,
            Err(error) => {
                recorder.fail(
                    "prepared_guard_identity",
                    NativeFailure::io("observe prepared identity", error),
                );
                return;
            }
        };
        let prepared_digest = match hash_handle(&mut prepared_guard.file) {
            Ok(digest) => digest,
            Err(error) => {
                recorder.fail(
                    "prepared_guard_identity",
                    NativeFailure::io("hash prepared handle", error),
                );
                return;
            }
        };
        recorder.evidence.projections.prepared_before =
            Some(prepared_identity.projection(prepared_digest.clone()));
        if prepared_identity == original_identity
            || prepared_identity.volume_serial_number != original_identity.volume_serial_number
        {
            recorder.fail(
                "prepared_guard_identity",
                NativeFailure::invariant(
                    "prepared guard",
                    "prepared and original identities are not distinct same-volume objects",
                ),
            );
            return;
        }
        if let Some(volume) = recorder.evidence.volume.as_mut() {
            volume.same_volume = true;
        }
        recorder.pass(
            "prepared_guard_identity",
            format!(
                "identity={}; digest={prepared_digest}",
                prepared_identity.display()
            ),
            None,
        );

        match expect_open_failure(&prepared, GENERIC_WRITE) {
            Ok(error) => recorder.pass(
                "prepared_competing_write_excluded",
                "competing write open was excluded",
                Some(error),
            ),
            Err(failure) => {
                recorder.fail("prepared_competing_write_excluded", failure);
                return;
            }
        }
        match expect_path_api_failure("DeleteFileW", &[ERROR_SHARING_VIOLATION], || {
            let path = wide_path(&prepared)?;
            // SAFETY: `path` is a live NUL-terminated UTF-16 string.
            win32_call("DeleteFileW", unsafe { DeleteFileW(path.as_ptr()) })
        }) {
            Ok(error) => {
                let Some(prepared_after) = recorder.observe_after_failed_api(
                    "prepared_delete_excluded",
                    "DeleteFileW",
                    error,
                    "observe prepared path after expected failure",
                    path_identity(&prepared),
                ) else {
                    return;
                };
                recorder.record_identity_transitions(
                    "prepared_delete_excluded",
                    &[(IdentityRole::Destination, prepared_identity, prepared_after)],
                );
                if prepared_after != prepared_identity {
                    recorder.fail(
                        "prepared_delete_excluded",
                        NativeFailure::after_api(
                            "DeleteFileW",
                            "prepared path identity changed after expected failure",
                            false,
                            Some(error),
                        ),
                    );
                    return;
                }
                recorder.pass(
                    "prepared_delete_excluded",
                    "delete failed and prepared path identity remained unchanged",
                    Some(error),
                )
            }
            Err(failure) => {
                recorder.fail("prepared_delete_excluded", failure);
                return;
            }
        }
        let prepared_move_identity = match path_identity(&prepared_move_source) {
            Ok(identity) => identity,
            Err(error) => {
                recorder.fail(
                    "prepared_ordinary_rename_excluded",
                    NativeFailure::io("observe prepared move source", error),
                );
                return;
            }
        };
        match expect_path_api_failure("MoveFileExW", &[ERROR_ACCESS_DENIED], || {
            let source = wide_path(&prepared_move_source)?;
            let destination = wide_path(&prepared)?;
            // SAFETY: both path buffers are live NUL-terminated UTF-16 strings.
            win32_call("MoveFileExW", unsafe {
                MoveFileExW(
                    source.as_ptr(),
                    destination.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING,
                )
            })
        }) {
            Ok(error) => {
                let Some(prepared_after) = recorder.observe_after_failed_api(
                    "prepared_ordinary_rename_excluded",
                    "MoveFileExW",
                    error,
                    "observe prepared destination after expected failure",
                    path_identity(&prepared),
                ) else {
                    return;
                };
                let Some(source_after) = recorder.observe_after_failed_api(
                    "prepared_ordinary_rename_excluded",
                    "MoveFileExW",
                    error,
                    "observe move source after expected failure",
                    path_identity(&prepared_move_source),
                ) else {
                    return;
                };
                recorder.record_identity_transitions(
                    "prepared_ordinary_rename_excluded",
                    &[
                        (IdentityRole::Source, prepared_move_identity, source_after),
                        (IdentityRole::Destination, prepared_identity, prepared_after),
                    ],
                );
                if prepared_after != prepared_identity || source_after != prepared_move_identity {
                    recorder.fail(
                        "prepared_ordinary_rename_excluded",
                        NativeFailure::after_api(
                            "MoveFileExW",
                            "source or prepared destination identity changed after expected failure",
                            false,
                            Some(error),
                        ),
                    );
                    return;
                }
                recorder.pass(
                    "prepared_ordinary_rename_excluded",
                    "ordinary replace-existing rename returned ERROR_ACCESS_DENIED; source and prepared destination identities remained unchanged",
                    Some(error),
                )
            }
            Err(failure) => {
                recorder.fail("prepared_ordinary_rename_excluded", failure);
                return;
            }
        }
        let prepared_replace_identity = match path_identity(&prepared_replace_source) {
            Ok(identity) => identity,
            Err(error) => {
                recorder.fail(
                    "prepared_replace_file_excluded",
                    NativeFailure::io("observe prepared ReplaceFileW source", error),
                );
                return;
            }
        };
        match expect_path_api_failure("ReplaceFileW", &[ERROR_SHARING_VIOLATION], || {
            let destination = wide_path(&prepared)?;
            let replacement = wide_path(&prepared_replace_source)?;
            // SAFETY: both path buffers remain live; null optional arguments
            // request no backup and no exclusion list.
            win32_call("ReplaceFileW", unsafe {
                ReplaceFileW(
                    destination.as_ptr(),
                    replacement.as_ptr(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    std::ptr::null(),
                )
            })
        }) {
            Ok(error) => {
                let Some(prepared_after) = recorder.observe_after_failed_api(
                    "prepared_replace_file_excluded",
                    "ReplaceFileW",
                    error,
                    "observe prepared destination after expected failure",
                    path_identity(&prepared),
                ) else {
                    return;
                };
                let Some(source_after) = recorder.observe_after_failed_api(
                    "prepared_replace_file_excluded",
                    "ReplaceFileW",
                    error,
                    "observe replacement source after expected failure",
                    path_identity(&prepared_replace_source),
                ) else {
                    return;
                };
                recorder.record_identity_transitions(
                    "prepared_replace_file_excluded",
                    &[
                        (
                            IdentityRole::Source,
                            prepared_replace_identity,
                            source_after,
                        ),
                        (IdentityRole::Destination, prepared_identity, prepared_after),
                    ],
                );
                if prepared_after != prepared_identity || source_after != prepared_replace_identity
                {
                    recorder.fail(
                        "prepared_replace_file_excluded",
                        NativeFailure::after_api(
                            "ReplaceFileW",
                            "replacement source or prepared destination identity changed after expected failure",
                            false,
                            Some(error),
                        ),
                    );
                    return;
                }
                recorder.pass(
                    "prepared_replace_file_excluded",
                    "ReplaceFileW returned ERROR_SHARING_VIOLATION; replacement source and prepared destination identities remained unchanged",
                    Some(error),
                )
            }
            Err(failure) => {
                recorder.fail("prepared_replace_file_excluded", failure);
                return;
            }
        }

        let mut ordinary_handle = match open_access(
            &non_posix_source,
            GENERIC_READ | DELETE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        ) {
            Ok(file) => file,
            Err(error) => {
                recorder.fail(
                    "non_posix_handle_rename_excluded",
                    NativeFailure::io("open ordinary rename source", error),
                );
                return;
            }
        };
        let non_posix_identity = match file_identity(&ordinary_handle) {
            Ok(identity) => identity,
            Err(error) => {
                recorder.fail(
                    "non_posix_handle_rename_excluded",
                    NativeFailure::io("observe non-POSIX rename source", error),
                );
                return;
            }
        };
        match set_handle_name(&mut ordinary_handle, &host, FILE_RENAME_REPLACE_IF_EXISTS) {
            Err(failure) if failure.win32_error == Some(ERROR_ACCESS_DENIED) => {
                let error = failure
                    .win32_error
                    .expect("matched SetFileInformationByHandle error is present");
                let Some(original_after) = recorder.observe_after_failed_api(
                    "non_posix_handle_rename_excluded",
                    "SetFileInformationByHandle",
                    error,
                    "observe no-delete destination after expected failure",
                    path_identity(&host),
                ) else {
                    return;
                };
                let Some(source_after) = recorder.observe_after_failed_api(
                    "non_posix_handle_rename_excluded",
                    "SetFileInformationByHandle",
                    error,
                    "observe non-POSIX source after expected failure",
                    path_identity(&non_posix_source),
                ) else {
                    return;
                };
                recorder.record_identity_transitions(
                    "non_posix_handle_rename_excluded",
                    &[
                        (IdentityRole::Source, non_posix_identity, source_after),
                        (IdentityRole::Destination, original_identity, original_after),
                    ],
                );
                if original_after != original_identity || source_after != non_posix_identity {
                    recorder.fail(
                        "non_posix_handle_rename_excluded",
                        NativeFailure::after_api(
                            "SetFileInformationByHandle",
                            "source or no-delete destination identity changed after expected failure",
                            false,
                            Some(error),
                        ),
                    );
                    return;
                }
                recorder.pass(
                    "non_posix_handle_rename_excluded",
                    "non-POSIX handle rename returned ERROR_ACCESS_DENIED; source and no-delete destination identities remained unchanged",
                    Some(error),
                );
            }
            Err(failure) => {
                recorder.fail("non_posix_handle_rename_excluded", failure);
                return;
            }
            Ok(()) => {
                recorder.fail(
                    "non_posix_handle_rename_excluded",
                    NativeFailure::after_api(
                        "SetFileInformationByHandle",
                        "non-POSIX replacement unexpectedly succeeded",
                        true,
                        None,
                    ),
                );
                return;
            }
        }
        drop(ordinary_handle);

        if let Err(error) = flush_handle(&prepared_guard.file) {
            recorder.fail(
                "posix_without_delete_share_excluded",
                NativeFailure::io("pre-characterization FlushFileBuffers", error),
            );
            return;
        }
        match set_handle_name(
            &mut prepared_guard.file,
            &host,
            FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
        ) {
            // POSIX replacement reaches the destination's immutable share-mode
            // check. A live target that omitted `FILE_SHARE_DELETE` rejects it
            // with `ERROR_SHARING_VIOLATION`; admission still requires stable
            // source/destination identities and digests below.
            Err(failure) if failure.win32_error == Some(ERROR_SHARING_VIOLATION) => {
                let error = failure
                    .win32_error
                    .expect("matched SetFileInformationByHandle error is present");
                let Some(original_handle_after) = recorder.observe_after_failed_api(
                    "posix_without_delete_share_excluded",
                    "SetFileInformationByHandle",
                    error,
                    "observe original handle after expected failure",
                    file_identity(&original.file),
                ) else {
                    return;
                };
                let Some(original_digest_after) = recorder.observe_after_failed_api(
                    "posix_without_delete_share_excluded",
                    "SetFileInformationByHandle",
                    error,
                    "hash original handle after expected failure",
                    hash_handle(&mut original.file),
                ) else {
                    return;
                };
                let Some(original_path_after) = recorder.observe_after_failed_api(
                    "posix_without_delete_share_excluded",
                    "SetFileInformationByHandle",
                    error,
                    "observe original path after expected failure",
                    path_identity(&host),
                ) else {
                    return;
                };
                let Some(prepared_handle_after) = recorder.observe_after_failed_api(
                    "posix_without_delete_share_excluded",
                    "SetFileInformationByHandle",
                    error,
                    "observe prepared handle after expected failure",
                    file_identity(&prepared_guard.file),
                ) else {
                    return;
                };
                let Some(prepared_digest_after) = recorder.observe_after_failed_api(
                    "posix_without_delete_share_excluded",
                    "SetFileInformationByHandle",
                    error,
                    "hash prepared handle after expected failure",
                    hash_handle(&mut prepared_guard.file),
                ) else {
                    return;
                };
                let Some(prepared_path_after) = recorder.observe_after_failed_api(
                    "posix_without_delete_share_excluded",
                    "SetFileInformationByHandle",
                    error,
                    "observe prepared path after expected failure",
                    path_identity(&prepared),
                ) else {
                    return;
                };
                recorder
                    .evidence
                    .projections
                    .no_delete_original_after_rejected =
                    Some(original_handle_after.projection(original_digest_after.clone()));
                recorder
                    .evidence
                    .projections
                    .no_delete_prepared_after_rejected =
                    Some(prepared_handle_after.projection(prepared_digest_after.clone()));
                recorder.record_identity_transitions(
                    "posix_without_delete_share_excluded",
                    &[
                        (IdentityRole::Source, prepared_identity, prepared_path_after),
                        (
                            IdentityRole::Destination,
                            original_identity,
                            original_path_after,
                        ),
                    ],
                );
                if original_handle_after != original_identity
                    || original_path_after != original_identity
                    || original_handle_after != original_path_after
                    || original_digest_after != original_digest
                    || prepared_handle_after != prepared_identity
                    || prepared_path_after != prepared_identity
                    || prepared_handle_after != prepared_path_after
                    || prepared_digest_after != prepared_digest
                {
                    recorder.fail(
                        "posix_without_delete_share_excluded",
                        NativeFailure::after_api(
                            "SetFileInformationByHandle",
                            "original or prepared handle/path identity or digest changed after expected failure",
                            false,
                            Some(error),
                        ),
                    );
                    return;
                }
                recorder.pass(
                    "posix_without_delete_share_excluded",
                    "POSIX replacement returned ERROR_SHARING_VIOLATION; original and prepared handle/path identities and digests remained unchanged",
                    Some(error),
                );
            }
            Err(failure) => {
                recorder.fail("posix_without_delete_share_excluded", failure);
                return;
            }
            Ok(()) => {
                recorder.fail(
                    "posix_without_delete_share_excluded",
                    NativeFailure::after_api(
                        "SetFileInformationByHandle",
                        "POSIX replacement unexpectedly succeeded against a no-delete guard",
                        true,
                        None,
                    ),
                );
                return;
            }
        }

        drop(original);
        let mut original = match LockedFile::acquire_delete_shared_original(&host) {
            Ok(guard) => guard,
            Err(error) => {
                recorder.fail(
                    "delete_shared_original_guard_identity",
                    NativeFailure::io("reacquire delete-shared original guard", error),
                );
                return;
            }
        };
        match (
            file_identity(&original.file),
            hash_handle(&mut original.file),
        ) {
            (Ok(identity), Ok(digest))
                if identity == original_identity && digest == original_digest =>
            {
                recorder.evidence.projections.delete_shared_original_before =
                    Some(identity.projection(digest.clone()));
                recorder.pass(
                    "delete_shared_original_guard_identity",
                    format!(
                        "reacquired identity={}; digest={digest}; the no-delete guard was explicitly released first",
                        identity.display()
                    ),
                    None,
                );
            }
            (identity, digest) => {
                recorder.fail(
                    "delete_shared_original_guard_identity",
                    NativeFailure::invariant(
                        "delete-shared original guard",
                        format!("identity={identity:?}; digest={digest:?}"),
                    ),
                );
                return;
            }
        }

        match expect_open_failure(&host, GENERIC_WRITE) {
            Ok(error) => recorder.pass(
                "delete_shared_competing_write_excluded",
                "delete-shared original guard still excluded a competing write open",
                Some(error),
            ),
            Err(failure) => {
                recorder.fail("delete_shared_competing_write_excluded", failure);
                return;
            }
        }

        let mut delete_shared_ordinary_handle = match open_access(
            &delete_shared_non_posix_source,
            GENERIC_READ | DELETE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        ) {
            Ok(file) => file,
            Err(error) => {
                recorder.fail(
                    "non_posix_with_delete_share_excluded",
                    NativeFailure::io("open delete-shared ordinary rename source", error),
                );
                return;
            }
        };
        let delete_shared_non_posix_identity = match file_identity(&delete_shared_ordinary_handle) {
            Ok(identity) => identity,
            Err(error) => {
                recorder.fail(
                    "non_posix_with_delete_share_excluded",
                    NativeFailure::io("observe delete-shared non-POSIX source", error),
                );
                return;
            }
        };
        match set_handle_name(
            &mut delete_shared_ordinary_handle,
            &host,
            FILE_RENAME_REPLACE_IF_EXISTS,
        ) {
            Err(failure) if failure.win32_error == Some(ERROR_ACCESS_DENIED) => {
                let error = failure
                    .win32_error
                    .expect("matched SetFileInformationByHandle error is present");
                let Some(original_after) = recorder.observe_after_failed_api(
                    "non_posix_with_delete_share_excluded",
                    "SetFileInformationByHandle",
                    error,
                    "observe delete-shared destination after expected failure",
                    path_identity(&host),
                ) else {
                    return;
                };
                let Some(source_after) = recorder.observe_after_failed_api(
                    "non_posix_with_delete_share_excluded",
                    "SetFileInformationByHandle",
                    error,
                    "observe delete-shared non-POSIX source after expected failure",
                    path_identity(&delete_shared_non_posix_source),
                ) else {
                    return;
                };
                recorder.record_identity_transitions(
                    "non_posix_with_delete_share_excluded",
                    &[
                        (
                            IdentityRole::Source,
                            delete_shared_non_posix_identity,
                            source_after,
                        ),
                        (IdentityRole::Destination, original_identity, original_after),
                    ],
                );
                if original_after != original_identity
                    || source_after != delete_shared_non_posix_identity
                {
                    recorder.fail(
                        "non_posix_with_delete_share_excluded",
                        NativeFailure::after_api(
                            "SetFileInformationByHandle",
                            "source or delete-shared destination identity changed after expected failure",
                            false,
                            Some(error),
                        ),
                    );
                    return;
                }
                recorder.pass(
                    "non_posix_with_delete_share_excluded",
                    "non-POSIX handle rename returned ERROR_ACCESS_DENIED; source and delete-shared destination identities remained unchanged",
                    Some(error),
                );
            }
            Err(failure) => {
                recorder.fail("non_posix_with_delete_share_excluded", failure);
                return;
            }
            Ok(()) => {
                recorder.fail(
                    "non_posix_with_delete_share_excluded",
                    NativeFailure::after_api(
                        "SetFileInformationByHandle",
                        "non-POSIX replacement unexpectedly succeeded against an open target",
                        true,
                        None,
                    ),
                );
                return;
            }
        }
        drop(delete_shared_ordinary_handle);

        match delete_shared_delete_control(temporary.path()) {
            Ok(projections) => {
                recorder.evidence.projections.delete_shared_delete_before =
                    Some(projections.before);
                recorder
                    .evidence
                    .projections
                    .delete_shared_delete_retained_after = Some(projections.retained_after);
                recorder.pass(
                    "delete_shared_guard_allows_delete",
                    "DeleteFileW succeeded, the retained handle remained stable, and the path disappeared after guard release",
                    None,
                );
            }
            Err(failure) => {
                recorder.fail("delete_shared_guard_allows_delete", failure);
                return;
            }
        }

        if let Err(error) = flush_handle(&prepared_guard.file) {
            recorder.fail(
                "posix_with_delete_share_install",
                NativeFailure::io("pre-install FlushFileBuffers", error),
            );
            return;
        }
        if let Err(failure) = set_handle_name(
            &mut prepared_guard.file,
            &host,
            FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
        ) {
            recorder.fail("posix_with_delete_share_install", failure);
            return;
        }
        recorder.pass(
            "posix_with_delete_share_install",
            "POSIX rename succeeded only with the delete-shared original and prepared guards live; this does not close the preceding guard gap",
            None,
        );

        match (
            file_identity(&original.file),
            hash_handle(&mut original.file),
        ) {
            (Ok(identity), Ok(digest))
                if identity == original_identity && digest == original_digest =>
            {
                recorder.evidence.projections.retained_original_after =
                    Some(identity.projection(digest.clone()));
                recorder.pass(
                    "retained_original_observation",
                    format!("retained identity={}; digest={digest}", identity.display()),
                    None,
                );
            }
            (identity, digest) => {
                recorder.fail(
                    "retained_original_observation",
                    NativeFailure::invariant(
                        "retained original observation",
                        format!("identity={identity:?}; digest={digest:?}"),
                    ),
                );
                return;
            }
        }
        let installed_identity = file_identity(&prepared_guard.file);
        let installed_digest = hash_handle(&mut prepared_guard.file);
        let current_path_observation = observe_path(&host);
        let prepared_path_absent = std::fs::symlink_metadata(&prepared)
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound);
        match (
            installed_identity,
            installed_digest,
            current_path_observation,
        ) {
            (Ok(handle_identity), Ok(digest), Ok((path_identity, path_digest)))
                if handle_identity == prepared_identity
                    && path_identity == prepared_identity
                    && digest == prepared_digest
                    && path_digest == prepared_digest
                    && prepared_path_absent =>
            {
                recorder.evidence.projections.installed_handle_after =
                    Some(handle_identity.projection(digest.clone()));
                recorder.evidence.projections.installed_path_after =
                    Some(path_identity.projection(path_digest));
                recorder.pass(
                    "installed_path_observation",
                    format!(
                        "installed identity={}; digest={digest}; prepared path absent",
                        handle_identity.display()
                    ),
                    None,
                );
            }
            (handle_identity, digest, path_observation) => {
                recorder.fail(
                    "installed_path_observation",
                    NativeFailure::invariant(
                        "installed observation",
                        format!(
                            "handle={handle_identity:?}; digest={digest:?}; path={path_observation:?}; prepared_path_absent={prepared_path_absent}"
                        ),
                    ),
                );
                return;
            }
        }
        match flush_handle(&prepared_guard.file) {
            Ok(()) => recorder.pass(
                "write_through_flush",
                "FlushFileBuffers succeeded on the write-through installed handle",
                None,
            ),
            Err(error) => {
                recorder.fail(
                    "write_through_flush",
                    NativeFailure::io("FlushFileBuffers", error),
                );
                return;
            }
        }
        match expect_open_failure(&host, GENERIC_WRITE) {
            Ok(error) => recorder.pass(
                "installed_competing_write_excluded",
                "competing write open was excluded by the installed guard",
                Some(error),
            ),
            Err(failure) => {
                recorder.fail("installed_competing_write_excluded", failure);
                return;
            }
        }

        drop(prepared_guard);
        drop(original);
        match open_access(
            &host,
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        ) {
            Ok(mut file) => match file.write_all(b"!") {
                Ok(()) => recorder.pass(
                    "post_release_write_control",
                    "competing write control succeeded after guard release",
                    None,
                ),
                Err(error) => {
                    recorder.fail(
                        "post_release_write_control",
                        NativeFailure::io("post-release WriteFile", error),
                    );
                    return;
                }
            },
            Err(error) => {
                recorder.fail(
                    "post_release_write_control",
                    NativeFailure::io("post-release CreateFileW", error),
                );
                return;
            }
        }

        match same_content_delete_shared_replacement(temporary.path()) {
            Ok(projections) => {
                let observed = format!(
                    "same digest {}; delete-shared identity {} was retained while attacker identity {} became current",
                    projections.original_before.sha256,
                    projections.original_before.file_id,
                    projections.attacker_before.file_id,
                );
                recorder.evidence.projections.same_content_original_before =
                    Some(projections.original_before);
                recorder.evidence.projections.same_content_attacker_before =
                    Some(projections.attacker_before);
                recorder.evidence.projections.same_content_retained_after =
                    Some(projections.retained_after);
                recorder.evidence.projections.same_content_path_after =
                    Some(projections.path_after);
                recorder.pass("same_content_delete_shared_replacement", observed, None);
            }
            Err(failure) => recorder.fail("same_content_delete_shared_replacement", failure),
        }
    }

    fn verify_raw_layout() -> Result<(), NativeFailure> {
        if size_of::<Handle>() != 8
            || offset_of!(super::FileRenameInfo, root_directory) != 8
            || offset_of!(super::FileRenameInfo, file_name_length) != 16
            || offset_of!(super::FileRenameInfo, file_name) != 20
            || size_of::<super::FileRenameInfo>() != 24
            || offset_of!(Overlapped, offset) != 16
            || offset_of!(Overlapped, event) != 24
            || size_of::<Overlapped>() != 32
            || offset_of!(FileIdInfo, file_id) != 8
            || size_of::<FileId128>() != 16
            || size_of::<FileIdInfo>() != 24
        {
            return Err(NativeFailure::invariant(
                "raw Win32 ABI",
                "probe supports only the SDK-audited x86_64 layouts",
            ));
        }
        Ok(())
    }

    fn unguarded_namespace_controls(directory: &Path) -> Result<String, NativeFailure> {
        let delete_path = directory.join("control-delete.dwg");
        write_synced(&delete_path, b"delete-control")
            .map_err(|error| NativeFailure::io("create DeleteFileW control", error))?;
        let delete_wide = wide_path(&delete_path)?;
        // SAFETY: `delete_wide` is a live NUL-terminated UTF-16 string.
        win32_call("DeleteFileW control", unsafe {
            DeleteFileW(delete_wide.as_ptr())
        })?;
        if !path_is_absent(&delete_path) {
            return Err(NativeFailure::invariant(
                "DeleteFileW control",
                "successful delete left the control path present",
            ));
        }

        let move_source = directory.join("control-move-source.dwg");
        let move_destination = directory.join("control-move-destination.dwg");
        write_synced(&move_source, b"move-control-source")
            .and_then(|_| write_synced(&move_destination, b"move-control-destination"))
            .map_err(|error| NativeFailure::io("create MoveFileExW controls", error))?;
        let move_source_identity = path_identity(&move_source)
            .map_err(|error| NativeFailure::io("observe MoveFileExW source", error))?;
        let move_source_wide = wide_path(&move_source)?;
        let move_destination_wide = wide_path(&move_destination)?;
        // SAFETY: both path buffers are live NUL-terminated UTF-16 strings.
        win32_call("MoveFileExW control", unsafe {
            MoveFileExW(
                move_source_wide.as_ptr(),
                move_destination_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING,
            )
        })?;
        if !path_is_absent(&move_source)
            || path_identity(&move_destination).ok() != Some(move_source_identity)
        {
            return Err(NativeFailure::after_api(
                "MoveFileExW control",
                "successful replace-existing move did not install the source identity",
                true,
                None,
            ));
        }

        let replace_source = directory.join("control-replace-source.dwg");
        let replace_destination = directory.join("control-replace-destination.dwg");
        write_synced(&replace_source, b"replace-control-source")
            .and_then(|_| write_synced(&replace_destination, b"replace-control-destination"))
            .map_err(|error| NativeFailure::io("create ReplaceFileW controls", error))?;
        let (replace_source_identity, replace_source_digest) = observe_path(&replace_source)
            .map_err(|error| NativeFailure::io("observe ReplaceFileW source", error))?;
        let replace_destination_wide = wide_path(&replace_destination)?;
        let replace_source_wide = wide_path(&replace_source)?;
        // SAFETY: both paths remain live; null optional arguments request no
        // backup and no exclusion list.
        win32_call("ReplaceFileW control", unsafe {
            ReplaceFileW(
                replace_destination_wide.as_ptr(),
                replace_source_wide.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null(),
            )
        })?;
        let replace_after = observe_path(&replace_destination)
            .map_err(|error| NativeFailure::io("observe ReplaceFileW destination", error))?;
        if !path_is_absent(&replace_source)
            || replace_after != (replace_source_identity, replace_source_digest)
        {
            return Err(NativeFailure::after_api(
                "ReplaceFileW control",
                "successful replacement did not install the replacement identity and digest",
                true,
                None,
            ));
        }

        let handle_source = directory.join("control-handle-source.dwg");
        let handle_destination = directory.join("control-handle-destination.dwg");
        write_synced(&handle_source, b"handle-control-source")
            .and_then(|_| write_synced(&handle_destination, b"handle-control-destination"))
            .map_err(|error| NativeFailure::io("create handle-rename controls", error))?;
        let mut handle = open_access(
            &handle_source,
            GENERIC_READ | DELETE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
        .map_err(|error| NativeFailure::io("open handle-rename control", error))?;
        let handle_source_identity = file_identity(&handle)
            .map_err(|error| NativeFailure::io("observe handle-rename source", error))?;
        set_handle_name(
            &mut handle,
            &handle_destination,
            FILE_RENAME_REPLACE_IF_EXISTS,
        )?;
        if !path_is_absent(&handle_source)
            || path_identity(&handle_destination).ok() != Some(handle_source_identity)
        {
            return Err(NativeFailure::after_api(
                "SetFileInformationByHandle control",
                "successful non-POSIX rename did not install the source identity",
                true,
                None,
            ));
        }

        Ok(format!(
            "all unguarded calls succeeded; move identity={}; replace identity={}; handle identity={}",
            move_source_identity.display(),
            replace_source_identity.display(),
            handle_source_identity.display(),
        ))
    }

    struct DeleteSharedDeleteProjections {
        before: FileProjectionEvidence,
        retained_after: FileProjectionEvidence,
    }

    fn delete_shared_delete_control(
        directory: &Path,
    ) -> Result<DeleteSharedDeleteProjections, NativeFailure> {
        let path = directory.join("delete-shared-delete-control.dwg");
        write_synced(&path, b"delete-shared-delete-control")
            .map_err(|error| NativeFailure::io("create delete-shared delete control", error))?;
        let mut guarded = LockedFile::acquire_delete_shared_original(&path)
            .map_err(|error| NativeFailure::io("acquire delete-shared delete control", error))?;
        let identity = file_identity(&guarded.file)
            .map_err(|error| NativeFailure::io("observe delete-shared delete control", error))?;
        let digest = hash_handle(&mut guarded.file)
            .map_err(|error| NativeFailure::io("hash delete-shared delete control", error))?;
        let path_wide = wide_path(&path)?;
        // SAFETY: `path_wide` is a live NUL-terminated UTF-16 string.
        win32_call("DeleteFileW delete-shared control", unsafe {
            DeleteFileW(path_wide.as_ptr())
        })?;
        let retained_identity = file_identity(&guarded.file)
            .map_err(|error| NativeFailure::io("reobserve deleted retained handle", error))?;
        let retained_digest = hash_handle(&mut guarded.file)
            .map_err(|error| NativeFailure::io("rehash deleted retained handle", error))?;
        if retained_identity != identity || retained_digest != digest {
            return Err(NativeFailure::after_api(
                "DeleteFileW delete-shared control",
                "retained handle identity or digest changed after successful deletion",
                true,
                None,
            ));
        }
        drop(guarded);
        if !path_is_absent(&path) {
            return Err(NativeFailure::after_api(
                "DeleteFileW delete-shared control",
                "successfully deleted path remained after the retained handle closed",
                true,
                None,
            ));
        }
        Ok(DeleteSharedDeleteProjections {
            before: identity.projection(digest),
            retained_after: retained_identity.projection(retained_digest),
        })
    }

    struct SameContentProjections {
        original_before: FileProjectionEvidence,
        attacker_before: FileProjectionEvidence,
        retained_after: FileProjectionEvidence,
        path_after: FileProjectionEvidence,
    }

    fn same_content_delete_shared_replacement(
        directory: &Path,
    ) -> Result<SameContentProjections, NativeFailure> {
        let guarded_path = directory.join("boundary-guarded.dwg");
        let attacker_path = directory.join("boundary-attacker.dwg");
        let content = b"same-content-distinct-identity";
        write_synced(&guarded_path, content)
            .and_then(|_| write_synced(&attacker_path, content))
            .map_err(|error| NativeFailure::io("create boundary files", error))?;
        let mut guarded = LockedFile::acquire_delete_shared_original(&guarded_path)
            .map_err(|error| NativeFailure::io("acquire delete-shared boundary guard", error))?;
        let guarded_identity = file_identity(&guarded.file)
            .map_err(|error| NativeFailure::io("observe boundary original", error))?;
        let guarded_digest = hash_handle(&mut guarded.file)
            .map_err(|error| NativeFailure::io("hash boundary original", error))?;
        let mut attacker = LockedFile::acquire_prepared(&attacker_path)
            .map_err(|error| NativeFailure::io("acquire boundary attacker", error))?;
        let attacker_identity = file_identity(&attacker.file)
            .map_err(|error| NativeFailure::io("observe boundary attacker", error))?;
        let attacker_digest = hash_handle(&mut attacker.file)
            .map_err(|error| NativeFailure::io("hash boundary attacker", error))?;
        if attacker_identity == guarded_identity || attacker_digest != guarded_digest {
            return Err(NativeFailure::invariant(
                "boundary fixture",
                "fixture must have the same digest and a distinct file identity",
            ));
        }
        set_handle_name(
            &mut attacker.file,
            &guarded_path,
            FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
        )?;
        let (current_identity, current_digest) = observe_path(&guarded_path)
            .map_err(|error| NativeFailure::io("observe boundary path", error))?;
        let retained_identity = file_identity(&guarded.file)
            .map_err(|error| NativeFailure::io("reobserve boundary original", error))?;
        let retained_digest = hash_handle(&mut guarded.file)
            .map_err(|error| NativeFailure::io("rehash boundary original", error))?;
        if current_identity != attacker_identity
            || retained_identity != guarded_identity
            || retained_digest != guarded_digest
            || current_digest != attacker_digest
        {
            return Err(NativeFailure::after_api(
                "boundary observation",
                "POSIX replacement did not retain the expected old/new identities",
                true,
                None,
            ));
        }
        Ok(SameContentProjections {
            original_before: guarded_identity.projection(guarded_digest),
            attacker_before: attacker_identity.projection(attacker_digest),
            retained_after: retained_identity.projection(retained_digest),
            path_after: current_identity.projection(current_digest),
        })
    }

    fn open_access(path: &Path, access: Dword, share: Dword, flags: Dword) -> io::Result<File> {
        OpenOptions::new()
            .access_mode(access)
            .share_mode(share)
            .custom_flags(flags)
            .open(path)
    }

    fn open_observer(path: &Path) -> io::Result<File> {
        open_access(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    }

    fn expect_open_failure(path: &Path, access: Dword) -> Result<u32, NativeFailure> {
        match open_access(
            path,
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        ) {
            Ok(_) => Err(NativeFailure::after_api(
                "CreateFileW",
                "competing open unexpectedly succeeded",
                true,
                None,
            )),
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => {
                Ok(ERROR_SHARING_VIOLATION)
            }
            Err(error) => Err(NativeFailure::io(
                "CreateFileW returned an unadmitted error",
                error,
            )),
        }
    }

    fn win32_call(api: &'static str, result: Bool) -> Result<(), NativeFailure> {
        if result == 0 {
            // This must be adjacent to the raw call. Even dropping a path
            // buffer before reading the thread-local error can overwrite it.
            Err(NativeFailure::io(api, io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    fn expect_path_api_failure(
        api: &'static str,
        admitted_errors: &[Dword],
        operation: impl FnOnce() -> Result<(), NativeFailure>,
    ) -> Result<u32, NativeFailure> {
        match operation() {
            Ok(()) => Err(NativeFailure::after_api(
                api,
                "ordinary namespace operation unexpectedly succeeded",
                true,
                None,
            )),
            Err(failure)
                if failure
                    .win32_error
                    .is_some_and(|error| admitted_errors.contains(&error)) =>
            {
                Ok(failure.win32_error.expect("admitted error is present"))
            }
            Err(failure) => Err(NativeFailure {
                api,
                detail: format!(
                    "operation returned an unadmitted error; expected={admitted_errors:?}; {}",
                    failure.detail
                ),
                api_returned_success: failure.api_returned_success,
                win32_error: failure.win32_error,
            }),
        }
    }

    fn set_handle_name(
        file: &mut File,
        destination: &Path,
        flags: Dword,
    ) -> Result<(), NativeFailure> {
        let wide = destination.as_os_str().encode_wide().collect::<Vec<_>>();
        let mut information = RenameBuffer::new(&wide, flags)
            .map_err(|error| NativeFailure::invariant("rename buffer", error))?;
        // SAFETY: the handle has DELETE access, the aligned buffer contains a
        // valid FileRenameInfoEx record, and both remain live for the call.
        let result = unsafe {
            SetFileInformationByHandle(
                raw_handle(file),
                FILE_RENAME_INFO_EX_CLASS,
                information.as_mut_ptr(),
                information.byte_len,
            )
        };
        if result == 0 {
            Err(NativeFailure::io(
                "SetFileInformationByHandle",
                io::Error::last_os_error(),
            ))
        } else {
            Ok(())
        }
    }

    fn file_identity(file: &File) -> io::Result<FileIdentity> {
        let mut information = MaybeUninit::<FileIdInfo>::uninit();
        // SAFETY: the output points to correctly sized writable storage and
        // the handle remains live for the complete call.
        let result = unsafe {
            GetFileInformationByHandleEx(
                raw_handle(file),
                FILE_ID_INFO_CLASS,
                information.as_mut_ptr().cast(),
                u32::try_from(size_of::<FileIdInfo>()).expect("FILE_ID_INFO fits DWORD"),
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful call initialized the complete structure.
        let information = unsafe { information.assume_init() };
        Ok(FileIdentity {
            volume_serial_number: information.volume_serial_number,
            file_id: information.file_id.identifier,
        })
    }

    fn path_identity(path: &Path) -> io::Result<FileIdentity> {
        let file = open_observer(path)?;
        file_identity(&file)
    }

    fn observe_path(path: &Path) -> io::Result<(FileIdentity, String)> {
        let mut file = open_observer(path)?;
        let identity = file_identity(&file)?;
        let digest = hash_handle(&mut file)?;
        Ok((identity, digest))
    }

    fn path_is_absent(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
    }

    fn hash_handle(file: &mut File) -> io::Result<String> {
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn flush_handle(file: &File) -> io::Result<()> {
        // SAFETY: `file` retains its live handle for the synchronous call.
        if unsafe { FlushFileBuffers(raw_handle(file)) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    struct NativeVolumeFacts {
        file_system: String,
        drive_type: Dword,
        formatted_volume_serial: Dword,
        file_system_flags: Dword,
    }

    fn volume_facts(file: &File, path: &Path) -> Result<NativeVolumeFacts, NativeFailure> {
        let mut formatted_volume_serial = 0;
        let mut maximum_component_length = 0;
        let mut file_system_flags = 0;
        let mut file_system_name = [0_u16; 64];
        // SAFETY: output pointers reference live writable storage and the
        // handle remains valid for the call.
        let result = unsafe {
            GetVolumeInformationByHandleW(
                raw_handle(file),
                std::ptr::null_mut(),
                0,
                &mut formatted_volume_serial,
                &mut maximum_component_length,
                &mut file_system_flags,
                file_system_name.as_mut_ptr(),
                u32::try_from(file_system_name.len()).expect("filesystem buffer fits DWORD"),
            )
        };
        if result == 0 {
            return Err(NativeFailure::io(
                "GetVolumeInformationByHandleW",
                io::Error::last_os_error(),
            ));
        }
        let name_length = file_system_name
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(file_system_name.len());
        let file_system =
            String::from_utf16(&file_system_name[..name_length]).map_err(|error| {
                NativeFailure::invariant(
                    "GetVolumeInformationByHandleW",
                    format!("filesystem name is not UTF-16: {error}"),
                )
            })?;
        let path = wide_path(path)?;
        let mut volume_path = [0_u16; 1024];
        // SAFETY: the path is NUL-terminated and the output buffer is writable.
        if unsafe {
            GetVolumePathNameW(
                path.as_ptr(),
                volume_path.as_mut_ptr(),
                u32::try_from(volume_path.len()).expect("volume path buffer fits DWORD"),
            )
        } == 0
        {
            return Err(NativeFailure::io(
                "GetVolumePathNameW",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: `GetVolumePathNameW` returned a NUL-terminated root path.
        let drive_type = unsafe { GetDriveTypeW(volume_path.as_ptr()) };
        Ok(NativeVolumeFacts {
            file_system,
            drive_type,
            formatted_volume_serial,
            file_system_flags,
        })
    }

    fn os_build() -> Result<u32, NativeFailure> {
        let mut version = OsVersionInfo::zeroed();
        // SAFETY: `version` is correctly sized writable storage.
        let status = unsafe { RtlGetVersion(&mut version) };
        if status != 0 {
            return Err(NativeFailure::invariant(
                "RtlGetVersion",
                format!("NTSTATUS=0x{:08x}", status as u32),
            ));
        }
        Ok(version.build)
    }

    fn wide_path(path: &Path) -> Result<Vec<u16>, NativeFailure> {
        wide_os(path.as_os_str())
    }

    fn wide_os(value: &OsStr) -> Result<Vec<u16>, NativeFailure> {
        let mut wide = value.encode_wide().collect::<Vec<_>>();
        if wide.is_empty() || wide.contains(&0) {
            return Err(NativeFailure::invariant(
                "UTF-16 path conversion",
                "path is empty or contains NUL",
            ));
        }
        wide.push(0);
        Ok(wide)
    }

    fn raw_handle(file: &File) -> Handle {
        file.as_raw_handle().cast()
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }

    fn source_evidence() -> SourceEvidence {
        let repository = repository_root();
        SourceEvidence {
            commit: git_output(&repository, &["rev-parse", "--verify", "HEAD"])
                .unwrap_or_else(|error| format!("unavailable:{error}")),
            tree: git_output(&repository, &["rev-parse", "--verify", "HEAD^{tree}"])
                .unwrap_or_else(|error| format!("unavailable:{error}")),
            dirty: git_output(
                &repository,
                &["status", "--porcelain=v1", "--untracked-files=all"],
            )
            .map_or(true, |status| !status.is_empty()),
            harness_sha256: sha256_path(
                &repository.join("crates/autocad-mcp/tests/windows_guarded_rename.rs"),
            )
            .unwrap_or_else(|error| format!("unavailable:{error}")),
            cargo_lock_sha256: sha256_path(&repository.join("Cargo.lock"))
                .unwrap_or_else(|error| format!("unavailable:{error}")),
            test_binary_sha256: std::env::current_exe()
                .map_err(|error| error.to_string())
                .and_then(|path| sha256_path(&path).map_err(|error| error.to_string()))
                .unwrap_or_else(|error| format!("unavailable:{error}")),
            rustc_verbose: command_output("rustc", &["--version", "--verbose"])
                .unwrap_or_else(|error| format!("unavailable:{error}")),
        }
    }

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate must remain below the repository root")
            .to_path_buf()
    }

    fn git_output(repository: &Path, arguments: &[&str]) -> Result<String, String> {
        let inherited_environment = [
            ("PATH", std::env::var_os("PATH")),
            ("SystemRoot", std::env::var_os("SystemRoot")),
            ("WINDIR", std::env::var_os("WINDIR")),
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
        let output = command
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", "NUL")
            .env("GIT_CONFIG_GLOBAL", "NUL")
            .env("GIT_CONFIG_COUNT", "0")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(arguments)
            .output()
            .map_err(|error| error.to_string())?;
        if output.status.success() {
            String::from_utf8(output.stdout)
                .map(|stdout| stdout.trim().to_string())
                .map_err(|error| error.to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }

    fn command_output(program: &str, arguments: &[&str]) -> Result<String, String> {
        let output = Command::new(program)
            .args(arguments)
            .output()
            .map_err(|error| error.to_string())?;
        if output.status.success() {
            String::from_utf8(output.stdout)
                .map(|stdout| stdout.trim().to_string())
                .map_err(|error| error.to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }

    fn sha256_path(path: &Path) -> io::Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn evidence_path() -> PathBuf {
        std::env::var_os("AUTOCAD_MCP_WINDOWS_GUARDED_RENAME_FEASIBILITY_EVIDENCE")
            .map(PathBuf::from)
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    repository_root().join(path)
                }
            })
            .unwrap_or_else(|| {
                repository_root()
                    .join("target/xref-windows-guarded-rename-feasibility-evidence.json")
            })
    }

    fn write_evidence(path: &Path, evidence: &FeasibilityEvidence) -> io::Result<()> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "evidence path has no parent")
        })?;
        std::fs::create_dir_all(parent)?;
        let bytes = serde_json::to_vec_pretty(evidence)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let temporary = path.with_extension("json.next");
        let mut file = File::create(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        let temporary_wide = wide_path(&temporary)
            .map_err(|failure| io::Error::new(io::ErrorKind::InvalidInput, failure.detail))?;
        let destination_wide = wide_path(path)
            .map_err(|failure| io::Error::new(io::ErrorKind::InvalidInput, failure.detail))?;
        // SAFETY: both buffers are live NUL-terminated UTF-16 paths. The
        // replace-existing flag makes repeated local runs publish fresh JSON.
        if unsafe {
            MoveFileExW(
                temporary_wide.as_ptr(),
                destination_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
