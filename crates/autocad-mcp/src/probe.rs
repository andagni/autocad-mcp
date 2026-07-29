//! Serve-only advisory Core Console warm-up probe.
//!
//! The controller is deliberately independent from MCP routing. A server may
//! own it, schedule it after initialization, consult it before a foreground
//! engine call, and shut it down. Probe success is never an activation,
//! qualification, or mutation-admission authority.

use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
    thread::JoinHandle,
    time::Duration,
};

use crate::{
    activation::MutationCapability, activation_platform::ProductionMutationRuntime, engine,
};

pub(crate) const PROBE_SENTINEL: &[u8] = b"AUTOCAD_MCP_COMMON_PROBE_READY_V1";
pub(crate) const DEFAULT_PROBE_GRACE: Duration = Duration::from_millis(750);
pub(crate) const DEFAULT_PROBE_PROCESS_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_PROBE_SHUTDOWN_JOIN_TIMEOUT: Duration = Duration::from_secs(75);

const SCRATCH_DXF_FILE_NAME: &str = "common-probe-input.dxf";
const PROBE_SCRIPT_FILE_NAME: &str = "common-probe.scr";
const SCRATCH_DXF_BYTES: &[u8] = b"0\r\n\
SECTION\r\n\
2\r\n\
HEADER\r\n\
9\r\n\
$ACADVER\r\n\
1\r\n\
AC1032\r\n\
0\r\n\
ENDSEC\r\n\
0\r\n\
SECTION\r\n\
2\r\n\
ENTITIES\r\n\
0\r\n\
ENDSEC\r\n\
0\r\n\
EOF\r\n";
const PROBE_SCRIPT_BYTES: &[u8] =
    b"(princ \"\\nAUTOCAD_MCP_COMMON_PROBE_READY_V1\\n\")\r\n_.QUIT\r\n";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProbeState {
    Disabled,
    Scheduled,
    Running,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ProbeSnapshot {
    pub state: ProbeState,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ForegroundProbeObservation {
    /// State observed after cancellation/waiting.
    pub snapshot: ProbeSnapshot,
    /// True when this foreground operation won the race before probe launch.
    pub cancelled_scheduled_probe: bool,
    /// True when this foreground operation cancelled an already-running probe
    /// before waiting for its bounded cleanup.
    pub cancelled_running_probe: bool,
    /// True when the caller's bounded wait ended while the probe was running.
    ///
    /// This is still an advisory observation, not an error or denial.
    pub wait_timed_out: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ProbeCancellation {
    process: engine::BoundedProcessCancellation,
}

impl ProbeCancellation {
    fn cancel(&self) {
        self.process.cancel();
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.process.is_cancelled()
    }
}

pub(crate) trait ProbeLauncher: Send + Sync + 'static {
    fn launch(&self, cancellation: &ProbeCancellation) -> Result<(), String>;
}

#[derive(Debug)]
struct ProbeRecord {
    state: ProbeState,
    detail: Option<String>,
    shutdown_requested: bool,
}

struct ProbeInner {
    record: Mutex<ProbeRecord>,
    changed: Condvar,
    cancellation: ProbeCancellation,
    launcher: Option<Arc<dyn ProbeLauncher>>,
    grace: Duration,
}

impl std::fmt::Debug for ProbeInner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProbeInner")
            .field("snapshot", &self.snapshot())
            .field("grace", &self.grace)
            .finish_non_exhaustive()
    }
}

impl ProbeInner {
    fn snapshot(&self) -> ProbeSnapshot {
        let record = self
            .record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ProbeSnapshot {
            state: record.state,
            detail: record.detail.clone(),
        }
    }

    fn fail_if_active(&self, detail: impl Into<String>) {
        let mut record = self
            .record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(record.state, ProbeState::Scheduled | ProbeState::Running) {
            record.state = ProbeState::Failed;
            record.detail = Some(detail.into());
            self.changed.notify_all();
        }
    }
}

/// One server-owned, single-flight background probe.
///
/// An enabled controller is deferred until the serve lifecycle schedules its
/// one worker. The worker then remains dormant for `grace`, allowing an early
/// foreground operation to cancel the schedule and own activation instead.
#[derive(Debug)]
pub(crate) struct ProbeController {
    inner: Arc<ProbeInner>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl ProbeController {
    #[cfg(any(feature = "preview", test))]
    pub(crate) fn disabled() -> Self {
        Self {
            inner: Arc::new(ProbeInner {
                record: Mutex::new(ProbeRecord {
                    state: ProbeState::Disabled,
                    detail: None,
                    shutdown_requested: false,
                }),
                changed: Condvar::new(),
                cancellation: ProbeCancellation::default(),
                launcher: None,
                grace: Duration::ZERO,
            }),
            worker: Mutex::new(None),
        }
    }

    pub(crate) fn deferred(launcher: Arc<dyn ProbeLauncher>, grace: Duration) -> Self {
        Self {
            inner: Arc::new(ProbeInner {
                record: Mutex::new(ProbeRecord {
                    state: ProbeState::Disabled,
                    detail: None,
                    shutdown_requested: false,
                }),
                changed: Condvar::new(),
                cancellation: ProbeCancellation::default(),
                launcher: Some(launcher),
                grace,
            }),
            worker: Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn scheduled(launcher: Arc<dyn ProbeLauncher>, grace: Duration) -> Self {
        let controller = Self::deferred(launcher, grace);
        controller.schedule_after_grace();
        controller
    }

    /// Transition an enabled, deferred controller to `scheduled`.
    ///
    /// The server's `notifications/initialized` hook calls this only after the
    /// client completes MCP initialization. Repeated calls are idempotent; a
    /// disabled or already-shut-down controller stays disabled.
    pub(crate) fn schedule_after_grace(&self) -> ProbeSnapshot {
        let mut worker_slot = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut record = self
            .inner
            .record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if record.state != ProbeState::Disabled
            || record.shutdown_requested
            || self.inner.launcher.is_none()
        {
            return ProbeSnapshot {
                state: record.state,
                detail: record.detail.clone(),
            };
        }
        record.state = ProbeState::Scheduled;
        record.detail = None;
        drop(record);

        let inner = Arc::clone(&self.inner);
        match std::thread::Builder::new()
            .name("autocad-mcp-core-console-probe".to_string())
            .spawn(move || run_scheduled_probe(inner))
        {
            Ok(worker) => {
                *worker_slot = Some(worker);
            }
            Err(error) => self
                .inner
                .fail_if_active(format!("failed to spawn advisory probe worker: {error}")),
        }
        drop(worker_slot);
        self.snapshot()
    }

    /// Build the production controller without starting a thread.
    ///
    /// The serve lifecycle must call `schedule_after_grace` after successful
    /// MCP initialization.
    pub(crate) fn production(
        runtime: Arc<ProductionMutationRuntime>,
        grace: Duration,
        process_timeout: Duration,
    ) -> Self {
        Self::deferred(
            Arc::new(ProductionProbeLauncher {
                runtime,
                process_timeout,
            }),
            grace,
        )
    }

    pub(crate) fn snapshot(&self) -> ProbeSnapshot {
        self.inner.snapshot()
    }

    /// Give a foreground operation priority over a not-yet-started probe.
    ///
    /// If the probe is already running, wait only for the caller-provided
    /// bound. Every result means "proceed": failed/running observations never
    /// become a new mutation denial.
    pub(crate) fn before_foreground(&self, max_wait: Duration) -> ForegroundProbeObservation {
        let mut record = self
            .inner
            .record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut cancelled_scheduled_probe = false;
        let mut cancelled_running_probe = false;
        let mut wait_timed_out = false;

        if record.state == ProbeState::Disabled
            && self.inner.launcher.is_some()
            && !record.shutdown_requested
        {
            // `serve` attaches the deferred controller before the MCP
            // initialization handshake, then schedules it from the client's
            // `notifications/initialized` hook. A foreground request can race
            // that hook; claiming the still-deferred controller here ensures
            // the user operation always wins.
            self.inner.cancellation.cancel();
            record.state = ProbeState::Failed;
            record.detail =
                Some("advisory probe cancelled while deferred by foreground operation".to_string());
            cancelled_scheduled_probe = true;
            self.inner.changed.notify_all();
        } else if record.state == ProbeState::Scheduled {
            self.inner.cancellation.cancel();
            record.state = ProbeState::Failed;
            record.detail =
                Some("advisory probe cancelled before launch by foreground operation".to_string());
            cancelled_scheduled_probe = true;
            self.inner.changed.notify_all();
        } else if record.state == ProbeState::Running {
            self.inner.cancellation.cancel();
            cancelled_running_probe = true;
            let (updated, wait) = self
                .inner
                .changed
                .wait_timeout_while(record, max_wait, |record| {
                    record.state == ProbeState::Running
                })
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            record = updated;
            wait_timed_out = wait.timed_out() && record.state == ProbeState::Running;
            if wait_timed_out {
                record.state = ProbeState::Failed;
                record.detail = Some(format!(
                    "advisory probe cancellation cleanup exceeded the foreground coordination bound of {}ms",
                    max_wait.as_millis()
                ));
                self.inner.changed.notify_all();
            }
        }

        ForegroundProbeObservation {
            snapshot: ProbeSnapshot {
                state: record.state,
                detail: record.detail.clone(),
            },
            cancelled_scheduled_probe,
            cancelled_running_probe,
            wait_timed_out,
        }
    }

    /// Cancel any scheduled/running work and join the owned worker within the
    /// cleanup budget. A worker stuck in a local OS observation is detached
    /// only after cancellation has made every later process boundary fail
    /// closed before resume.
    pub(crate) fn shutdown(&self) -> ProbeSnapshot {
        self.shutdown_with_join_timeout(DEFAULT_PROBE_SHUTDOWN_JOIN_TIMEOUT)
    }

    fn shutdown_with_join_timeout(&self, max_wait: Duration) -> ProbeSnapshot {
        self.inner.cancellation.cancel();
        {
            let mut record = self
                .inner
                .record
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            record.shutdown_requested = true;
            if record.state == ProbeState::Scheduled {
                record.state = ProbeState::Failed;
                record.detail =
                    Some("advisory probe cancelled before launch during shutdown".to_string());
            }
            self.inner.changed.notify_all();
        }

        let worker = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(worker) = worker {
            let deadline = std::time::Instant::now() + max_wait;
            while !worker.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if worker.is_finished() {
                if worker.join().is_err() {
                    self.inner
                        .fail_if_active("advisory probe worker panicked during shutdown");
                }
            } else {
                self.inner.fail_if_active(format!(
                    "advisory probe worker exceeded bounded shutdown join of {}ms and was detached after cancellation",
                    max_wait.as_millis()
                ));
                drop(worker);
            }
        }
        self.snapshot()
    }
}

impl Drop for ProbeController {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn run_scheduled_probe(inner: Arc<ProbeInner>) {
    let mut record = inner
        .record
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (updated, _) = inner
        .changed
        .wait_timeout_while(record, inner.grace, |record| {
            record.state == ProbeState::Scheduled && !inner.cancellation.is_cancelled()
        })
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    record = updated;
    if record.state != ProbeState::Scheduled || inner.cancellation.is_cancelled() {
        return;
    }
    record.state = ProbeState::Running;
    record.detail = None;
    inner.changed.notify_all();
    drop(record);

    let started = std::time::Instant::now();
    let result = inner
        .launcher
        .as_ref()
        .expect("scheduled controller has a launcher")
        .launch(&inner.cancellation);
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    let mut record = inner
        .record
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if record.state == ProbeState::Running {
        match result {
            Ok(()) => {
                record.state = ProbeState::Ready;
                record.detail = None;
            }
            Err(error) => {
                record.state = ProbeState::Failed;
                record.detail = Some(error);
            }
        }
        inner.changed.notify_all();
    }
    let final_state = record.state;
    let final_detail = record.detail.clone();
    drop(record);
    tracing::info!(
        target: "autocad_mcp::probe",
        state = ?final_state,
        elapsed_ms,
        detail = ?final_detail,
        "serve-only advisory Core Console probe completed"
    );
}

#[derive(Debug)]
struct ProductionProbeLauncher {
    runtime: Arc<ProductionMutationRuntime>,
    process_timeout: Duration,
}

impl ProbeLauncher for ProductionProbeLauncher {
    fn launch(&self, cancellation: &ProbeCancellation) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("advisory probe cancelled before activation".to_string());
        }
        let selected = self
            .runtime
            .acquire_for_format(MutationCapability::DwgLayerMutation, "AC1032")
            .map_err(|error| {
                format!("common activation unavailable for advisory probe: {error}")
            })?;
        if cancellation.is_cancelled() {
            return Err("advisory probe cancelled before staging".to_string());
        }

        let staging = engine::create_staging_dir()
            .map_err(|error| format!("create private probe staging: {error}"))?;
        let drawing =
            create_private_probe_file(staging.path(), SCRATCH_DXF_FILE_NAME, SCRATCH_DXF_BYTES)?;
        let script =
            create_private_probe_file(staging.path(), PROBE_SCRIPT_FILE_NAME, PROBE_SCRIPT_BYTES)?;

        let launch = engine::run_accoreconsole_probe_bounded(
            &selected,
            &drawing,
            &script,
            staging.path(),
            self.process_timeout,
            &cancellation.process,
        )
        .map_err(|error| format!("bounded Core Console advisory probe failed: {error}"));
        let unchanged = verify_private_probe_file_unchanged(&drawing, SCRATCH_DXF_BYTES);

        match (launch, unchanged) {
            (Ok(output), Ok(())) if !output.success() => Err(format!(
                "Core Console advisory probe exited unsuccessfully: {}",
                output.diagnostic()
            )),
            (Ok(output), Ok(())) if !output.contains(PROBE_SENTINEL) => Err(format!(
                "Core Console advisory probe exited without its sentinel: {}",
                output.diagnostic()
            )),
            (Ok(_), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(output), Err(unchanged_error)) => Err(format!(
                "{unchanged_error}; Core Console result: {}",
                output.diagnostic()
            )),
            (Err(error), Err(unchanged_error)) => Err(format!("{error}; {unchanged_error}")),
        }
    }
}

fn create_private_probe_file(
    staging: &Path,
    file_name: &str,
    bytes: &[u8],
) -> Result<PathBuf, String> {
    let path = staging.join(file_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("create private probe file {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write private probe file {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync private probe file {}: {error}", path.display()))?;
    Ok(path)
}

fn verify_private_probe_file_unchanged(path: &Path, expected: &[u8]) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect private probe drawing {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "private probe drawing was replaced by a non-regular file: {}",
            path.display()
        ));
    }
    let observed = std::fs::read(path)
        .map_err(|error| format!("read private probe drawing {}: {error}", path.display()))?;
    if observed != expected {
        return Err(format!(
            "private probe drawing bytes changed during Core Console launch: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        time::Instant,
    };

    struct FunctionLauncher<F>(F);

    impl<F> ProbeLauncher for FunctionLauncher<F>
    where
        F: Fn(&ProbeCancellation) -> Result<(), String> + Send + Sync + 'static,
    {
        fn launch(&self, cancellation: &ProbeCancellation) -> Result<(), String> {
            (self.0)(cancellation)
        }
    }

    fn launcher<F>(function: F) -> Arc<dyn ProbeLauncher>
    where
        F: Fn(&ProbeCancellation) -> Result<(), String> + Send + Sync + 'static,
    {
        Arc::new(FunctionLauncher(function))
    }

    fn wait_for_state(controller: &ProbeController, expected: ProbeState) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if controller.snapshot().state == expected {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!(
            "probe did not reach {expected:?}; observed {:?}",
            controller.snapshot()
        );
    }

    #[test]
    fn disabled_controller_never_launches() {
        let controller = ProbeController::disabled();
        assert_eq!(controller.snapshot().state, ProbeState::Disabled);
        assert_eq!(
            controller.schedule_after_grace().state,
            ProbeState::Disabled
        );
        let observation = controller.before_foreground(Duration::from_millis(1));
        assert_eq!(observation.snapshot.state, ProbeState::Disabled);
        assert!(!observation.cancelled_scheduled_probe);
        assert!(!observation.cancelled_running_probe);
        assert!(!observation.wait_timed_out);
    }

    #[test]
    fn enabled_controller_does_not_schedule_before_explicit_serve_hook() {
        let launches = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::clone(&launches);
        let controller = ProbeController::deferred(
            launcher(move |_| {
                launch_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            Duration::from_millis(10),
        );

        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(controller.snapshot().state, ProbeState::Disabled);
        assert_eq!(launches.load(Ordering::SeqCst), 0);
        assert_eq!(
            controller.schedule_after_grace().state,
            ProbeState::Scheduled
        );
        wait_for_state(&controller, ProbeState::Ready);
        assert_eq!(launches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn scheduled_probe_waits_for_grace_then_runs_once() {
        let launches = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::clone(&launches);
        let controller = ProbeController::scheduled(
            launcher(move |_| {
                launch_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            Duration::from_millis(75),
        );

        assert_eq!(controller.snapshot().state, ProbeState::Scheduled);
        assert_eq!(launches.load(Ordering::SeqCst), 0);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(launches.load(Ordering::SeqCst), 0);
        wait_for_state(&controller, ProbeState::Ready);
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        assert_eq!(controller.shutdown().state, ProbeState::Ready);
    }

    #[test]
    fn foreground_cancels_probe_before_launch() {
        let launches = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::clone(&launches);
        let controller = ProbeController::scheduled(
            launcher(move |_| {
                launch_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            Duration::from_secs(1),
        );

        let observation = controller.before_foreground(Duration::ZERO);
        assert!(observation.cancelled_scheduled_probe);
        assert!(!observation.cancelled_running_probe);
        assert!(!observation.wait_timed_out);
        assert_eq!(observation.snapshot.state, ProbeState::Failed);
        controller.shutdown();
        assert_eq!(launches.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn foreground_cancels_deferred_probe_before_serve_can_schedule_it() {
        let launches = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::clone(&launches);
        let controller = ProbeController::deferred(
            launcher(move |_| {
                launch_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            Duration::ZERO,
        );

        let observation = controller.before_foreground(Duration::ZERO);
        assert!(observation.cancelled_scheduled_probe);
        assert!(!observation.cancelled_running_probe);
        assert_eq!(observation.snapshot.state, ProbeState::Failed);
        assert_eq!(controller.schedule_after_grace().state, ProbeState::Failed);
        assert_eq!(launches.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn foreground_waits_for_running_probe_without_creating_a_denial() {
        let controller = ProbeController::scheduled(
            launcher(|_| {
                std::thread::sleep(Duration::from_millis(50));
                Ok(())
            }),
            Duration::ZERO,
        );
        wait_for_state(&controller, ProbeState::Running);

        let observation = controller.before_foreground(Duration::from_secs(1));
        assert_eq!(observation.snapshot.state, ProbeState::Ready);
        assert!(!observation.cancelled_scheduled_probe);
        assert!(observation.cancelled_running_probe);
        assert!(!observation.wait_timed_out);
    }

    #[test]
    fn bounded_foreground_wait_fails_probe_without_repeating_coordination() {
        let release = Arc::new(AtomicBool::new(false));
        let release_launcher = Arc::clone(&release);
        let controller = ProbeController::scheduled(
            launcher(move |_| {
                while !release_launcher.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err("synthetic delayed cancellation".to_string())
            }),
            Duration::ZERO,
        );
        wait_for_state(&controller, ProbeState::Running);

        let observation = controller.before_foreground(Duration::from_millis(20));
        assert_eq!(observation.snapshot.state, ProbeState::Failed);
        assert!(observation.cancelled_running_probe);
        assert!(observation.wait_timed_out);
        let repeated = controller.before_foreground(Duration::ZERO);
        assert_eq!(repeated.snapshot.state, ProbeState::Failed);
        assert!(!repeated.cancelled_running_probe);
        assert!(!repeated.wait_timed_out);
        release.store(true, Ordering::SeqCst);
        assert_eq!(controller.shutdown().state, ProbeState::Failed);
    }

    #[test]
    fn launcher_failure_is_advisory_to_foreground() {
        let controller = ProbeController::scheduled(
            launcher(|_| Err("synthetic launch failure".to_string())),
            Duration::ZERO,
        );
        wait_for_state(&controller, ProbeState::Failed);

        let observation = controller.before_foreground(Duration::from_secs(1));
        assert_eq!(observation.snapshot.state, ProbeState::Failed);
        assert_eq!(
            observation.snapshot.detail.as_deref(),
            Some("synthetic launch failure")
        );
        assert!(!observation.cancelled_running_probe);
        assert!(!observation.wait_timed_out);
    }

    #[test]
    fn shutdown_cancels_and_joins_scheduled_probe() {
        let launches = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::clone(&launches);
        let controller = ProbeController::scheduled(
            launcher(move |_| {
                launch_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            Duration::from_secs(1),
        );

        let snapshot = controller.shutdown();
        assert_eq!(snapshot.state, ProbeState::Failed);
        assert_eq!(launches.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn shutdown_detaches_a_cancelled_worker_only_after_its_join_bound() {
        let release = Arc::new(AtomicBool::new(false));
        let release_launcher = Arc::clone(&release);
        let controller = ProbeController::scheduled(
            launcher(move |_| {
                while !release_launcher.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err("synthetic blocked observation released".to_string())
            }),
            Duration::ZERO,
        );
        wait_for_state(&controller, ProbeState::Running);

        let started = Instant::now();
        let snapshot = controller.shutdown_with_join_timeout(Duration::from_millis(20));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(snapshot.state, ProbeState::Failed);
        assert!(snapshot
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("bounded shutdown join")));
        release.store(true, Ordering::SeqCst);
    }

    #[test]
    fn private_scratch_verifier_rejects_changed_or_replaced_file() {
        let staging = tempfile::tempdir().unwrap();
        let path =
            create_private_probe_file(staging.path(), SCRATCH_DXF_FILE_NAME, SCRATCH_DXF_BYTES)
                .unwrap();
        verify_private_probe_file_unchanged(&path, SCRATCH_DXF_BYTES).unwrap();

        std::fs::write(&path, b"changed").unwrap();
        assert!(verify_private_probe_file_unchanged(&path, SCRATCH_DXF_BYTES).is_err());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn production_process_boundary_fails_explicitly_off_windows() {
        let staging = tempfile::tempdir().unwrap();
        let cancellation = engine::BoundedProcessCancellation::default();
        let target = crate::activation::embedded_activation_catalogue()
            .unwrap()
            .targets()[0]
            .clone();
        let executable = PathBuf::from("/not/accoreconsole.exe");
        let selected = crate::activation::SelectedActivation {
            candidate: crate::activation::InstalledCandidate {
                canonical_id: "off-windows-probe-test".to_string(),
                executable: executable.clone(),
                product: target.product.as_str().to_string(),
                edition: target.edition.as_str().to_string(),
                architecture: target.architecture.as_str().to_string(),
                release_year: target.release_year,
                registry_family: target.registry_family.clone(),
                product_language_key: target.product_language_key.clone(),
                ui_locale: target.ui_locale.clone(),
            },
            engine_identity: crate::activation::VerifiedEngineIdentity {
                canonical_executable: executable,
                identity_token: "off-windows-test".to_string(),
            },
            launch_guard: None,
            target,
        };
        let error = engine::run_accoreconsole_probe_bounded(
            &selected,
            Path::new("/not/input.dxf"),
            Path::new("/not/probe.scr"),
            staging.path(),
            Duration::from_secs(1),
            &cancellation,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("bounded Core Console probe launch requires Windows x64"));
    }
}
