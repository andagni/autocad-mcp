//! Production platform boundary for package-owned AutoCAD activation.
//!
//! The portable policy lives in `activation`. This module delays all process
//! state and filesystem work until the first engine-backed operation, then
//! discovers only exact catalogue rows from the 64-bit HKLM AutoCAD registry
//! view and verifies the selected PE without launching it.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

#[cfg(any(target_os = "windows", test))]
use std::collections::BTreeMap;

use crate::{
    activation::{
        embedded_activation_catalogue, ActivationError, ActivationMode, ActivationTarget,
        InstalledCandidate, InstalledCandidateDiscovery, MutationCapability, MutationRuntime,
        NoReleaseQualification, SelectedActivation, SelectedEngineLease, SelectedEngineVerifier,
        VerifiedEngineIdentity,
    },
    engine,
};

/// Lazily constructs the production activation runtime.
///
/// Server construction, MCP initialization, tool discovery, and read-only
/// calls therefore perform no registry or AutoCAD filesystem access.
#[derive(Debug)]
pub struct ProductionMutationRuntime {
    mode: ActivationMode,
    runtime: OnceLock<Result<Arc<MutationRuntime>, ActivationError>>,
}

/// Read-only facts established for one exact registered AutoCAD executable
/// before a licensed-host Preview evaluation launches the MCP server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactPreviewActivationInspection {
    pub activation_catalogue_sha256: String,
    pub target_id: String,
    pub release_year: u16,
    pub registry_family: String,
    pub product_language_key: String,
    pub ui_locale: String,
    pub maintained_target: bool,
    pub canonical_executable: PathBuf,
    pub file_version: String,
    pub engine_identity_token: String,
    pub profile_arg_sha256: String,
    pub profile_policy_id: String,
    pub profile_policy_sha256: String,
    pub operation_families: Vec<MutationCapability>,
    pub drawing_formats: Vec<String>,
}

/// Inspect an operator-selected Core Console against one exact Preview
/// catalogue row without launching it or changing process-global state.
pub fn inspect_exact_registered_preview_activation(
    target_id: &str,
    exact_override: &Path,
) -> Result<ExactPreviewActivationInspection, ActivationError> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (target_id, exact_override);
        Err(ActivationError::DiscoveryFailed(
            "exact Preview activation inspection requires a native Windows x64 host".to_string(),
        ))
    }

    #[cfg(target_os = "windows")]
    {
        use crate::activation::select_activation_target;

        let catalogue = embedded_activation_catalogue()?;
        if catalogue.target(target_id).is_none() {
            return Err(ActivationError::DiscoveryFailed(format!(
                "requested Preview activation target {target_id:?} is not in the embedded catalogue"
            )));
        }
        let canonical =
            resolve_exact_override(ActivationMode::Preview, Some(exact_override.as_os_str()))?
                .expect("a present Preview exact override must remain present");
        let installed = discover_exact_registered_autocad(catalogue, &canonical)?;
        let selection = select_activation_target(
            catalogue,
            ActivationMode::Preview,
            None,
            &installed,
            Some(&canonical),
        )?;
        if selection.target.target_id != target_id {
            return Err(ActivationError::DiscoveryFailed(format!(
                "exact AutoCAD engine maps to Preview target {}, not requested target {target_id}",
                selection.target.target_id
            )));
        }
        let observed = engine::observe_accoreconsole_executable(&selection.candidate.executable)
            .map_err(|error| ActivationError::VerificationFailed(error.to_string()))?;
        let identity =
            verified_engine_identity(&selection.candidate, &selection.target, &observed)?;
        let file_version = observed.file_version.ok_or_else(|| {
            ActivationError::VerificationFailed(
                "selected Windows AutoCAD engine has no fixed file version".to_string(),
            )
        })?;

        Ok(ExactPreviewActivationInspection {
            activation_catalogue_sha256: catalogue.sha256.clone(),
            target_id: selection.target.target_id,
            release_year: selection.target.release_year,
            registry_family: selection.target.registry_family,
            product_language_key: selection.target.product_language_key,
            ui_locale: selection.target.ui_locale,
            maintained_target: selection.target.maintained_target,
            canonical_executable: identity.canonical_executable,
            file_version,
            engine_identity_token: identity.identity_token,
            profile_arg_sha256: selection.target.profile.arg_sha256,
            profile_policy_id: selection.target.profile.policy_id,
            profile_policy_sha256: selection.target.profile.policy_sha256,
            operation_families: selection.target.operation_families,
            drawing_formats: selection.target.drawing_formats,
        })
    }
}

impl ProductionMutationRuntime {
    pub fn new(mode: ActivationMode) -> Self {
        Self {
            mode,
            runtime: OnceLock::new(),
        }
    }

    pub fn acquire(
        &self,
        capability: MutationCapability,
    ) -> Result<Arc<SelectedActivation>, ActivationError> {
        if self.mode == ActivationMode::Disabled {
            return Err(ActivationError::Disabled);
        }
        self.runtime()?.acquire(capability)
    }

    pub fn acquire_for_format(
        &self,
        capability: MutationCapability,
        drawing_format: &str,
    ) -> Result<Arc<SelectedActivation>, ActivationError> {
        let selected = self.acquire(capability)?;
        if selected
            .target
            .drawing_formats
            .binary_search_by(|candidate| candidate.as_str().cmp(drawing_format))
            .is_err()
        {
            return Err(ActivationError::DrawingFormatUnsupported {
                target_id: selected.target.target_id.clone(),
                drawing_format: drawing_format.to_string(),
            });
        }
        Ok(selected)
    }

    pub fn selected(&self) -> Option<Arc<SelectedActivation>> {
        self.runtime
            .get()
            .and_then(|runtime| runtime.as_ref().ok())
            .and_then(|runtime| runtime.selected())
    }

    fn runtime(&self) -> Result<&Arc<MutationRuntime>, ActivationError> {
        self.runtime
            .get_or_init(|| {
                let catalogue = Arc::new(embedded_activation_catalogue()?.clone());
                let raw_exact_override = std::env::var_os(engine::ACCORECONSOLE_PATH_ENV);
                let mode = self.mode;
                Ok(Arc::new(MutationRuntime::new_with_exact_override_resolver(
                    self.mode,
                    catalogue,
                    Arc::new(RegisteredAutocadDiscovery),
                    Arc::new(ProductionSelectedEngineVerifier),
                    Arc::new(NoReleaseQualification),
                    Arc::new(move || resolve_exact_override(mode, raw_exact_override.as_deref())),
                )))
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

fn resolve_exact_override(
    mode: ActivationMode,
    value: Option<&std::ffi::OsStr>,
) -> Result<Option<PathBuf>, ActivationError> {
    if mode == ActivationMode::Disabled {
        return Ok(None);
    }
    if let Some(raw) = value {
        require_fixed_local_windows_path(Path::new(raw)).map_err(|error| {
            ActivationError::DiscoveryFailed(format!(
                "exact AutoCAD engine override is not on a fixed local Windows volume: {error}"
            ))
        })?;
    }
    let resolved = engine::resolve_accoreconsole_override(value)
        .map_err(|error| ActivationError::DiscoveryFailed(error.to_string()))?;
    if let Some(canonical) = resolved.as_deref() {
        require_fixed_local_windows_path(canonical).map_err(|error| {
            ActivationError::DiscoveryFailed(format!(
                "canonical exact AutoCAD engine override is not on a fixed local Windows volume: {error}"
            ))
        })?;
    }
    Ok(resolved)
}

#[derive(Debug, Default)]
struct RegisteredAutocadDiscovery;

impl InstalledCandidateDiscovery for RegisteredAutocadDiscovery {
    fn discover(
        &self,
        exact_override: Option<&Path>,
    ) -> Result<Vec<InstalledCandidate>, ActivationError> {
        discover_registered_autocad(exact_override)
    }
}

#[derive(Debug, Default)]
struct ProductionSelectedEngineVerifier;

impl SelectedEngineVerifier for ProductionSelectedEngineVerifier {
    fn verify(
        &self,
        candidate: &InstalledCandidate,
        target: &ActivationTarget,
    ) -> Result<VerifiedEngineIdentity, ActivationError> {
        let observed = engine::observe_accoreconsole_executable(&candidate.executable)
            .map_err(|error| ActivationError::VerificationFailed(error.to_string()))?;
        verified_engine_identity(candidate, target, &observed)
    }

    fn acquire_launch_lease(
        &self,
        candidate: &InstalledCandidate,
        target: &ActivationTarget,
    ) -> Result<(VerifiedEngineIdentity, Box<dyn SelectedEngineLease>), ActivationError> {
        #[cfg(target_os = "windows")]
        {
            let lease =
                engine::acquire_accoreconsole_executable_launch_lease(&candidate.executable)
                    .map_err(|error| ActivationError::VerificationFailed(error.to_string()))?;
            let identity = verified_engine_identity(candidate, target, lease.observation())?;
            Ok((identity, Box::new(lease)))
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.verify(candidate, target)
                .map(|identity| (identity, Box::new(()) as Box<dyn SelectedEngineLease>))
        }
    }
}

fn verified_engine_identity(
    candidate: &InstalledCandidate,
    target: &ActivationTarget,
    observed: &engine::AccoreconsoleExecutableObservation,
) -> Result<VerifiedEngineIdentity, ActivationError> {
    if observed.canonical_executable != candidate.executable {
        return Err(ActivationError::VerificationFailed(format!(
            "registered executable canonicalized from {} to {}",
            candidate.executable.display(),
            observed.canonical_executable.display()
        )));
    }
    if observed.architecture != target.architecture.as_str() {
        return Err(ActivationError::VerificationFailed(format!(
            "registered executable architecture {} does not match activation target {}",
            observed.architecture,
            target.architecture.as_str()
        )));
    }
    require_fixed_local_windows_path(&observed.canonical_executable)
        .map_err(ActivationError::VerificationFailed)?;
    require_observed_release_family(observed, target)
        .map_err(ActivationError::VerificationFailed)?;
    require_path_year_consistency(&observed.canonical_executable, target)
        .map_err(ActivationError::VerificationFailed)?;
    Ok(VerifiedEngineIdentity {
        canonical_executable: observed.canonical_executable.clone(),
        identity_token: observed.identity_token.clone(),
    })
}

#[cfg(not(target_os = "windows"))]
fn discover_registered_autocad(
    _exact_override: Option<&Path>,
) -> Result<Vec<InstalledCandidate>, ActivationError> {
    Err(ActivationError::DiscoveryFailed(
        "exact full-AutoCAD registry discovery requires Windows x64".to_string(),
    ))
}

#[cfg(target_os = "windows")]
fn discover_registered_autocad(
    exact_override: Option<&Path>,
) -> Result<Vec<InstalledCandidate>, ActivationError> {
    let catalogue = embedded_activation_catalogue()?;
    if let Some(exact_override) = exact_override {
        return discover_exact_registered_autocad(catalogue, exact_override);
    }
    let mut candidates = Vec::new();
    let mut rejected = Vec::new();

    for target in catalogue.targets() {
        let location = match registered_install_location(target) {
            Ok(Some(location)) => location,
            Ok(None) => continue,
            Err(error) => {
                rejected.push(format!("{}: {error}", target.target_id));
                continue;
            }
        };
        match candidate_from_install_location(target, &location) {
            Ok(candidate) => candidates.push(candidate),
            Err(error) => rejected.push(format!("{}: {error}", target.target_id)),
        }
    }

    reject_ambiguous_candidate_executables(&candidates)?;

    if candidates.is_empty() && !rejected.is_empty() {
        return Err(ActivationError::DiscoveryFailed(format!(
            "registered AutoCAD candidates were rejected: {}",
            rejected.join("; ")
        )));
    }
    for detail in rejected {
        tracing::warn!(target: "autocad_mcp::activation", "{detail}");
    }
    Ok(candidates)
}

#[cfg(target_os = "windows")]
fn discover_exact_registered_autocad(
    catalogue: &crate::activation::ActivationCatalogue,
    exact_override: &Path,
) -> Result<Vec<InstalledCandidate>, ActivationError> {
    let observed = engine::observe_accoreconsole_executable(exact_override)
        .map_err(|error| ActivationError::DiscoveryFailed(error.to_string()))?;
    if observed.canonical_executable != exact_override {
        return Err(ActivationError::DiscoveryFailed(format!(
            "exact AutoCAD engine override canonicalized from {} to {} during discovery",
            exact_override.display(),
            observed.canonical_executable.display()
        )));
    }
    require_fixed_local_windows_path(&observed.canonical_executable)
        .map_err(ActivationError::DiscoveryFailed)?;

    let matching_targets = catalogue
        .targets()
        .iter()
        .filter(|target| {
            observed.architecture == target.architecture.as_str()
                && require_observed_release_family(&observed, target).is_ok()
        })
        .collect::<Vec<_>>();
    if matching_targets.len() != 1 {
        return Err(ActivationError::DiscoveryFailed(format!(
            "exact AutoCAD engine override {} maps to {} catalogue release families",
            exact_override.display(),
            matching_targets.len()
        )));
    }
    let target = matching_targets[0];
    require_path_year_consistency(&observed.canonical_executable, target)
        .map_err(ActivationError::DiscoveryFailed)?;

    let location = registered_install_location(target)?.ok_or_else(|| {
        ActivationError::DiscoveryFailed(format!(
            "exact AutoCAD engine override has no registered catalogue installation at {}\\{}",
            target.registry_family, target.product_language_key
        ))
    })?;
    if !location.is_absolute() {
        return Err(ActivationError::DiscoveryFailed(format!(
            "registered installation Location is not absolute: {}",
            location.display()
        )));
    }
    require_fixed_local_windows_path(&location).map_err(ActivationError::DiscoveryFailed)?;
    let registered_executable = engine::resolve_accoreconsole_override(Some(
        location.join("accoreconsole.exe").as_os_str(),
    ))
    .map_err(|error| ActivationError::DiscoveryFailed(error.to_string()))?
    .expect("present exact registered executable");
    require_fixed_local_windows_path(&registered_executable)
        .map_err(ActivationError::DiscoveryFailed)?;
    if registered_executable != observed.canonical_executable {
        return Err(ActivationError::DiscoveryFailed(format!(
            "exact AutoCAD engine override {} does not equal registered catalogue executable {}",
            observed.canonical_executable.display(),
            registered_executable.display()
        )));
    }

    Ok(vec![candidate_from_observation(target, observed)])
}

#[cfg(any(target_os = "windows", test))]
fn reject_ambiguous_candidate_executables(
    candidates: &[InstalledCandidate],
) -> Result<(), ActivationError> {
    let mut owners = BTreeMap::<&Path, &str>::new();
    for candidate in candidates {
        if let Some(previous) = owners.insert(&candidate.executable, &candidate.canonical_id) {
            return Err(ActivationError::DiscoveryFailed(format!(
                "canonical engine {} is claimed by ambiguous registered candidates {previous} and {}",
                candidate.executable.display(),
                candidate.canonical_id
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn candidate_from_install_location(
    target: &ActivationTarget,
    location: &Path,
) -> Result<InstalledCandidate, ActivationError> {
    if !location.is_absolute() {
        return Err(ActivationError::DiscoveryFailed(format!(
            "registered installation Location is not absolute: {}",
            location.display()
        )));
    }
    require_fixed_local_windows_path(location).map_err(ActivationError::DiscoveryFailed)?;
    let executable = location.join("accoreconsole.exe");
    let observed = engine::observe_accoreconsole_executable(&executable)
        .map_err(|error| ActivationError::DiscoveryFailed(error.to_string()))?;
    require_fixed_local_windows_path(&observed.canonical_executable)
        .map_err(ActivationError::DiscoveryFailed)?;
    if observed.architecture != target.architecture.as_str() {
        return Err(ActivationError::DiscoveryFailed(format!(
            "registered engine architecture {} does not match {}",
            observed.architecture,
            target.architecture.as_str()
        )));
    }
    require_observed_release_family(&observed, target).map_err(ActivationError::DiscoveryFailed)?;
    require_path_year_consistency(&observed.canonical_executable, target)
        .map_err(ActivationError::DiscoveryFailed)?;
    Ok(candidate_from_observation(target, observed))
}

#[cfg(target_os = "windows")]
fn candidate_from_observation(
    target: &ActivationTarget,
    observed: engine::AccoreconsoleExecutableObservation,
) -> InstalledCandidate {
    InstalledCandidate {
        canonical_id: format!("registered-{}", target.target_id),
        executable: observed.canonical_executable,
        product: target.product.as_str().to_string(),
        edition: target.edition.as_str().to_string(),
        architecture: target.architecture.as_str().to_string(),
        release_year: target.release_year,
        registry_family: target.registry_family.clone(),
        product_language_key: target.product_language_key.clone(),
        ui_locale: target.ui_locale.clone(),
    }
}

#[cfg(target_os = "windows")]
fn require_fixed_local_windows_path(path: &Path) -> Result<(), String> {
    use std::path::{Component, Prefix};
    use windows_sys::Win32::{
        Storage::FileSystem::GetDriveTypeW, System::WindowsProgramming::DRIVE_FIXED,
    };

    let drive = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
            other => {
                return Err(format!(
                    "AutoCAD engine path must use a local drive-letter volume, observed prefix {other:?}: {}",
                    path.display()
                ))
            }
        },
        _ => {
            return Err(format!(
                "AutoCAD engine path has no Windows drive-letter prefix: {}",
                path.display()
            ))
        }
    };
    let root = [u16::from(drive), u16::from(b':'), u16::from(b'\\'), 0];
    let drive_type = unsafe { GetDriveTypeW(root.as_ptr()) };
    if drive_type != DRIVE_FIXED {
        return Err(format!(
            "AutoCAD engine drive {}: is not a fixed local volume (GetDriveTypeW={drive_type})",
            char::from(drive)
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn require_fixed_local_windows_path(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Require a drive-letter path on a fixed local Windows volume.
///
/// This is exposed for repository-owned Windows harnesses that need the same
/// volume admission rule as production activation. Non-Windows hosts return a
/// platform error instead of treating the portable test seam as admission.
pub fn require_fixed_local_windows_volume(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        require_fixed_local_windows_path(path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        Err("fixed-local Windows volume validation requires a native Windows host".to_string())
    }
}

fn require_observed_release_family(
    observed: &engine::AccoreconsoleExecutableObservation,
    target: &ActivationTarget,
) -> Result<(), String> {
    let expected = target
        .registry_family
        .strip_prefix('R')
        .expect("validated registry family");
    match observed.file_version.as_deref() {
        Some(version)
            if version == expected
                || version
                    .strip_prefix(expected)
                    .is_some_and(|suffix| suffix.starts_with('.')) =>
        {
            Ok(())
        }
        Some(version) => Err(format!(
            "engine file version {version} does not match registry family {}",
            target.registry_family
        )),
        None if cfg!(target_os = "windows") => Err(format!(
            "engine has no fixed file version for registry family {}",
            target.registry_family
        )),
        None => Ok(()),
    }
}

fn require_path_year_consistency(path: &Path, target: &ActivationTarget) -> Result<(), String> {
    let observed = autocad_years_from_path(path);
    if observed.iter().any(|year| *year != target.release_year) {
        return Err(format!(
            "registered engine path identifies AutoCAD year set {observed:?}, not only activation target {}",
            target.release_year
        ));
    }
    Ok(())
}

fn autocad_years_from_path(path: &Path) -> BTreeSet<u16> {
    path.to_string_lossy()
        .split(['/', '\\'])
        .filter(|component| component.to_ascii_lowercase().starts_with("autocad"))
        .flat_map(|component| {
            component
                .split(|character: char| !character.is_ascii_digit())
                .filter(|part| part.len() == 4 && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .filter_map(|year| year.parse::<u16>().ok())
        .collect()
}

#[cfg(target_os = "windows")]
struct WindowsRegistryKey(windows_sys::Win32::System::Registry::HKEY);

#[cfg(target_os = "windows")]
impl Drop for WindowsRegistryKey {
    fn drop(&mut self) {
        unsafe {
            let _ = windows_sys::Win32::System::Registry::RegCloseKey(self.0);
        }
    }
}

#[cfg(target_os = "windows")]
fn windows_registry_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(target_os = "windows")]
fn query_registry_string_two_pass(
    key: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
) -> Result<String, ActivationError> {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{RegQueryValueExW, REG_SZ},
    };

    let name = windows_registry_wide(name);
    let mut value_type = 0_u32;
    let mut byte_len = 0_u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null(),
            &mut value_type,
            std::ptr::null_mut(),
            &mut byte_len,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(ActivationError::DiscoveryFailed(format!(
            "query registry value length failed with Win32 {status}"
        )));
    }
    if value_type != REG_SZ || byte_len < 2 || byte_len % 2 != 0 {
        return Err(ActivationError::DiscoveryFailed(format!(
            "registry value must be a nonempty REG_SZ, observed type={value_type} bytes={byte_len}"
        )));
    }

    let mut buffer = vec![0_u16; byte_len as usize / 2];
    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null(),
            &mut value_type,
            buffer.as_mut_ptr().cast(),
            &mut byte_len,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(ActivationError::DiscoveryFailed(format!(
            "read registry value failed with Win32 {status}"
        )));
    }
    if value_type != REG_SZ
        || byte_len < 2
        || byte_len % 2 != 0
        || byte_len as usize > buffer.len() * std::mem::size_of::<u16>()
    {
        return Err(ActivationError::DiscoveryFailed(format!(
            "registry value changed during two-pass read, observed type={value_type} bytes={byte_len}"
        )));
    }
    buffer.truncate(byte_len as usize / std::mem::size_of::<u16>());
    if buffer.last() != Some(&0) {
        return Err(ActivationError::DiscoveryFailed(
            "registry string is not NUL terminated".to_string(),
        ));
    }
    buffer.pop();
    if buffer.contains(&0) {
        return Err(ActivationError::DiscoveryFailed(
            "registry string contains an embedded NUL".to_string(),
        ));
    }
    String::from_utf16(&buffer).map_err(|error| {
        ActivationError::DiscoveryFailed(format!("registry string is not valid UTF-16: {error}"))
    })
}

#[cfg(target_os = "windows")]
fn registered_install_location_from_root(
    root: windows_sys::Win32::System::Registry::HKEY,
    root_label: &str,
    autocad_root: &str,
    additional_access: u32,
    target: &ActivationTarget,
) -> Result<Option<PathBuf>, ActivationError> {
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS},
        System::Registry::{RegOpenKeyExW, HKEY, KEY_READ},
    };

    let subkey = format!(
        r"{autocad_root}\{}\{}",
        target.registry_family, target.product_language_key
    );
    let subkey_wide = windows_registry_wide(&subkey);
    let mut raw_key: HKEY = std::ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            root,
            subkey_wide.as_ptr(),
            0,
            KEY_READ | additional_access,
            &mut raw_key,
        )
    };
    if matches!(status, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(ActivationError::DiscoveryFailed(format!(
            "open {root_label} registry key {subkey} failed with Win32 {status}"
        )));
    }
    let key = WindowsRegistryKey(raw_key);
    let language = query_registry_string_two_pass(key.0, "Language")?;
    if language != "English" {
        return Err(ActivationError::DiscoveryFailed(format!(
            "registered Language {language:?} does not match exact en-US activation row"
        )));
    }
    let location = query_registry_string_two_pass(key.0, "Location")?;
    Ok(Some(PathBuf::from(location)))
}

#[cfg(target_os = "windows")]
fn registered_install_location(
    target: &ActivationTarget,
) -> Result<Option<PathBuf>, ActivationError> {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY};

    registered_install_location_from_root(
        HKEY_LOCAL_MACHINE,
        "HKLM 64-bit",
        r"SOFTWARE\Autodesk\AutoCAD",
        KEY_WOW64_64KEY,
        target,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    struct TemporaryActivationRegistryTree {
        subkey: String,
    }

    #[cfg(target_os = "windows")]
    impl Drop for TemporaryActivationRegistryTree {
        fn drop(&mut self) {
            use windows_sys::Win32::{
                Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS},
                System::Registry::{RegDeleteTreeW, HKEY_CURRENT_USER},
            };

            const TEST_ROOT_PREFIX: &str = r"Software\AutoCADMcpActivationTest-";
            let suffix = self.subkey.strip_prefix(TEST_ROOT_PREFIX);
            if !matches!(suffix, Some(suffix) if !suffix.is_empty() && !suffix.contains('\\')) {
                eprintln!(
                    "refusing to delete an invalid activation registry test root: {}",
                    self.subkey
                );
                return;
            }
            let status = unsafe {
                RegDeleteTreeW(
                    HKEY_CURRENT_USER,
                    windows_registry_wide(&self.subkey).as_ptr(),
                )
            };
            if !matches!(
                status,
                ERROR_SUCCESS | ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND
            ) {
                eprintln!(
                    "failed to clean activation registry test root {} with Win32 {status}",
                    self.subkey
                );
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn activation_test_registry_tree_exists(subkey: &str) -> bool {
        use windows_sys::Win32::{
            Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS},
            System::Registry::{RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_READ},
        };

        let mut raw_key: HKEY = std::ptr::null_mut();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                windows_registry_wide(subkey).as_ptr(),
                0,
                KEY_READ,
                &mut raw_key,
            )
        };
        match status {
            ERROR_SUCCESS => {
                drop(WindowsRegistryKey(raw_key));
                true
            }
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => false,
            status => panic!("inspect activation registry test root failed with Win32 {status}"),
        }
    }

    #[cfg(target_os = "windows")]
    fn set_activation_test_registry_string(
        key: windows_sys::Win32::System::Registry::HKEY,
        name: &str,
        value: &str,
    ) {
        use windows_sys::Win32::{
            Foundation::ERROR_SUCCESS,
            System::Registry::{RegSetValueExW, REG_SZ},
        };

        let bytes = windows_registry_wide(value);
        let byte_len = u32::try_from(bytes.len() * std::mem::size_of::<u16>())
            .expect("activation registry test value length");
        let status = unsafe {
            RegSetValueExW(
                key,
                windows_registry_wide(name).as_ptr(),
                0,
                REG_SZ,
                bytes.as_ptr().cast(),
                byte_len,
            )
        };
        assert_eq!(
            status, ERROR_SUCCESS,
            "write activation registry test value {name}"
        );
    }

    #[test]
    fn path_year_is_only_advisory_when_autocad_components_are_consistent() {
        assert_eq!(
            autocad_years_from_path(Path::new(
                r"C:\Program Files\Autodesk\AutoCAD 2026\accoreconsole.exe"
            )),
            BTreeSet::from([2026])
        );
        assert_eq!(
            autocad_years_from_path(Path::new(r"D:\CAD\accoreconsole.exe")),
            BTreeSet::new()
        );
        assert_eq!(
            autocad_years_from_path(Path::new(r"D:\2027\accoreconsole.exe")),
            BTreeSet::new()
        );
        assert_eq!(
            autocad_years_from_path(Path::new(
                r"C:\AutoCAD 2025\Autodesk\AutoCAD 2026\accoreconsole.exe"
            )),
            BTreeSet::from([2025, 2026])
        );
        let target = embedded_activation_catalogue()
            .unwrap()
            .target("autocad-2026-r25-1-en-us-preview-v1")
            .unwrap();
        assert!(require_path_year_consistency(
            Path::new(r"C:\AutoCAD 2025\Autodesk\AutoCAD 2026\accoreconsole.exe"),
            target,
        )
        .is_err());
    }

    #[test]
    fn production_runtime_construction_is_lazy() {
        let runtime = ProductionMutationRuntime::new(ActivationMode::Disabled);
        assert!(runtime.runtime.get().is_none());
        assert_eq!(
            runtime.acquire(MutationCapability::DwgLayerMutation),
            Err(ActivationError::Disabled)
        );
        assert!(runtime.runtime.get().is_none());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn exact_preview_evaluation_inspection_is_windows_only() {
        let error = inspect_exact_registered_preview_activation(
            "autocad-2026-r25-1-en-us-preview-v1",
            Path::new(r"C:\Program Files\Autodesk\AutoCAD 2026\accoreconsole.exe"),
        )
        .expect_err("portable hosts must not manufacture native activation evidence");
        assert!(
            error
                .to_string()
                .contains("requires a native Windows x64 host"),
            "{error}"
        );
    }

    #[test]
    fn release_mode_resolves_the_exact_operator_override_constraint() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("accoreconsole.exe");
        std::fs::write(&executable, b"test executable").unwrap();
        let expected = std::fs::canonicalize(&executable).unwrap();

        assert_eq!(
            resolve_exact_override(ActivationMode::Release, Some(executable.as_os_str())).unwrap(),
            Some(expected.clone())
        );
        assert_eq!(
            resolve_exact_override(ActivationMode::Preview, Some(executable.as_os_str())).unwrap(),
            Some(expected)
        );
        assert_eq!(
            resolve_exact_override(ActivationMode::Disabled, Some(executable.as_os_str())).unwrap(),
            None
        );
    }

    #[test]
    fn duplicate_canonical_engine_paths_are_rejected_as_ambiguous() {
        let candidate = |canonical_id: &str| InstalledCandidate {
            canonical_id: canonical_id.to_string(),
            executable: PathBuf::from(r"C:\Program Files\Autodesk\AutoCAD 2026\accoreconsole.exe"),
            product: "autocad".to_string(),
            edition: "full".to_string(),
            architecture: "x86_64".to_string(),
            release_year: 2026,
            registry_family: "R25.1".to_string(),
            product_language_key: "ACAD-9101:409".to_string(),
            ui_locale: "en-US".to_string(),
        };
        let error = reject_ambiguous_candidate_executables(&[
            candidate("registered-first"),
            candidate("registered-second"),
        ])
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("ambiguous registered candidates"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn activation_windows_fixed_local_volume_admission_rejects_unc() {
        let directory = tempfile::tempdir().unwrap();
        require_fixed_local_windows_path(directory.path()).unwrap();

        let error =
            require_fixed_local_windows_path(Path::new(r"\\server\share\accoreconsole.exe"))
                .unwrap_err();
        assert!(error.contains("local drive-letter volume"), "{error}");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn activation_windows_exact_override_rejects_unc_before_canonicalization() {
        let error = resolve_exact_override(
            ActivationMode::Preview,
            Some(std::ffi::OsStr::new(
                r"\\server\share\AutoCAD 2026\accoreconsole.exe",
            )),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exact AutoCAD engine override is not on a fixed local Windows volume"),
            "{error}"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn activation_windows_registry_root_seam_reads_exact_language_and_location_and_cleans_up() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use windows_sys::Win32::{
            Foundation::ERROR_SUCCESS,
            System::Registry::{RegCreateKeyW, HKEY, HKEY_CURRENT_USER},
        };

        static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(1);
        let nonce = NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("activation registry test clock")
            .as_nanos();
        let test_root = format!(
            r"Software\AutoCADMcpActivationTest-{}-{nonce}-{timestamp}",
            std::process::id()
        );
        assert!(!activation_test_registry_tree_exists(&test_root));
        let cleanup = TemporaryActivationRegistryTree {
            subkey: test_root.clone(),
        };

        let target = embedded_activation_catalogue()
            .unwrap()
            .target("autocad-2026-r25-1-en-us-preview-v1")
            .unwrap();
        let autocad_root = format!(r"{test_root}\AutoCAD");
        let product_subkey = format!(
            r"{autocad_root}\{}\{}",
            target.registry_family, target.product_language_key
        );
        let mut raw_key: HKEY = std::ptr::null_mut();
        let status = unsafe {
            RegCreateKeyW(
                HKEY_CURRENT_USER,
                windows_registry_wide(&product_subkey).as_ptr(),
                &mut raw_key,
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "create activation registry test key");
        let key = WindowsRegistryKey(raw_key);

        let deep_path = (0..64)
            .map(|index| format!("segment-{index:02}\\"))
            .collect::<String>();
        let location = format!("C:\\Program Files\\Autodesk\\{deep_path}AutoCAD 2026 \u{03a9}");
        set_activation_test_registry_string(key.0, "Language", "english");
        set_activation_test_registry_string(key.0, "Location", &location);
        let language_error = registered_install_location_from_root(
            HKEY_CURRENT_USER,
            "HKCU activation test",
            &autocad_root,
            0,
            target,
        )
        .unwrap_err();
        assert!(
            language_error
                .to_string()
                .contains("does not match exact en-US activation row"),
            "{language_error}"
        );

        set_activation_test_registry_string(key.0, "Language", "English");
        assert_eq!(
            query_registry_string_two_pass(key.0, "Language").unwrap(),
            "English"
        );
        assert_eq!(
            query_registry_string_two_pass(key.0, "Location").unwrap(),
            location
        );
        assert_eq!(
            registered_install_location_from_root(
                HKEY_CURRENT_USER,
                "HKCU activation test",
                &autocad_root,
                0,
                target,
            )
            .unwrap(),
            Some(PathBuf::from(&location))
        );

        drop(key);
        drop(cleanup);
        assert!(
            !activation_test_registry_tree_exists(&test_root),
            "temporary HKCU activation registry tree was not cleaned"
        );
    }

    #[test]
    fn executable_file_version_must_match_the_exact_registry_family() {
        let target = embedded_activation_catalogue()
            .unwrap()
            .target("autocad-2026-r25-1-en-us-preview-v1")
            .unwrap();
        let observed = |file_version: &str| engine::AccoreconsoleExecutableObservation {
            canonical_executable: PathBuf::from("accoreconsole.exe"),
            architecture: "x86_64",
            file_version: Some(file_version.to_string()),
            identity_token: "test".to_string(),
        };
        require_observed_release_family(&observed("25.1.72.0"), target).unwrap();
        assert!(require_observed_release_family(&observed("25.0.72.0"), target).is_err());
        assert!(require_observed_release_family(&observed("25.10.1.0"), target).is_err());
    }
}
