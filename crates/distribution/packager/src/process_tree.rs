//! Cross-platform subprocess-tree containment for developer tooling.
//!
//! Unix callers must place the child in a process group before spawning. On
//! Windows, construction assigns the child to a kill-on-close Job Object.

use anyhow::Result;
use std::process::Child;

/// Owns the containment boundary for one spawned subprocess tree.
pub struct ProcessTree {
    #[cfg(unix)]
    child_id: u32,
    #[cfg(windows)]
    job: windows_job::JobHandle,
}

impl ProcessTree {
    /// Bind a newly spawned child to its platform containment boundary.
    pub fn new(child: &Child) -> Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                child_id: child.id(),
            })
        }
        #[cfg(windows)]
        {
            Ok(Self {
                job: windows_job::JobHandle::assign(child)?,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child;
            Ok(Self {})
        }
    }

    /// Terminate every process still owned by the containment boundary.
    pub fn terminate(&mut self) {
        #[cfg(unix)]
        terminate_process_group(self.child_id);
        #[cfg(windows)]
        self.job.terminate();
    }

    /// Return the Job Object's active-process count when the platform exposes
    /// one. `None` means that the host cannot prove this property directly.
    pub fn active_processes(&self) -> Result<Option<u32>> {
        #[cfg(windows)]
        {
            self.job.active_processes().map(Some)
        }
        #[cfg(not(windows))]
        {
            Ok(None)
        }
    }
}

#[cfg(unix)]
fn terminate_process_group(child_id: u32) {
    const SIGKILL: i32 = 9;
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        let _ = kill(-(child_id as i32), SIGKILL);
    }
}

#[cfg(windows)]
mod windows_job {
    use anyhow::{Context, Result};
    use std::ffi::c_void;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use std::ptr::{null, null_mut};

    type Bool = i32;
    type Dword = u32;
    type Handle = *mut c_void;
    type LargeInteger = i64;
    type UlongLong = u64;
    type UlongPtr = usize;

    const JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS: i32 = 1;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Dword = 0x0000_2000;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct JobObjectBasicAccountingInformation {
        TotalUserTime: LargeInteger,
        TotalKernelTime: LargeInteger,
        ThisPeriodTotalUserTime: LargeInteger,
        ThisPeriodTotalKernelTime: LargeInteger,
        TotalPageFaultCount: Dword,
        TotalProcesses: Dword,
        ActiveProcesses: Dword,
        TotalTerminatedProcesses: Dword,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct IoCounters {
        ReadOperationCount: UlongLong,
        WriteOperationCount: UlongLong,
        OtherOperationCount: UlongLong,
        ReadTransferCount: UlongLong,
        WriteTransferCount: UlongLong,
        OtherTransferCount: UlongLong,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct JobObjectBasicLimitInformation {
        PerProcessUserTimeLimit: LargeInteger,
        PerJobUserTimeLimit: LargeInteger,
        LimitFlags: Dword,
        MinimumWorkingSetSize: UlongPtr,
        MaximumWorkingSetSize: UlongPtr,
        ActiveProcessLimit: Dword,
        Affinity: UlongPtr,
        PriorityClass: Dword,
        SchedulingClass: Dword,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct JobObjectExtendedLimitInformation {
        BasicLimitInformation: JobObjectBasicLimitInformation,
        IoInfo: IoCounters,
        ProcessMemoryLimit: UlongPtr,
        JobMemoryLimit: UlongPtr,
        PeakProcessMemoryUsed: UlongPtr,
        PeakJobMemoryUsed: UlongPtr,
    }

    unsafe extern "system" {
        fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(
            job: Handle,
            info_class: i32,
            info: *mut c_void,
            info_len: Dword,
        ) -> Bool;
        fn QueryInformationJobObject(
            job: Handle,
            info_class: i32,
            info: *mut c_void,
            info_len: Dword,
            return_len: *mut Dword,
        ) -> Bool;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> Bool;
        fn TerminateJobObject(job: Handle, exit_code: u32) -> Bool;
        fn CloseHandle(handle: Handle) -> Bool;
    }

    pub struct JobHandle {
        handle: Handle,
    }

    impl JobHandle {
        pub fn assign(child: &Child) -> Result<Self> {
            unsafe {
                let job = CreateJobObjectW(null_mut(), null());
                if job.is_null() {
                    return Err(io::Error::last_os_error()).context("create Windows Job Object");
                }

                let mut info: JobObjectExtendedLimitInformation = zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if SetInformationJobObject(
                    job,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                    &mut info as *mut _ as *mut c_void,
                    size_of::<JobObjectExtendedLimitInformation>() as Dword,
                ) == 0
                {
                    let error = io::Error::last_os_error();
                    let _ = CloseHandle(job);
                    return Err(error).context("configure Windows Job Object");
                }

                if AssignProcessToJobObject(job, child.as_raw_handle() as Handle) == 0 {
                    let error = io::Error::last_os_error();
                    let _ = CloseHandle(job);
                    return Err(error).context("assign process to Windows Job Object");
                }

                Ok(Self { handle: job })
            }
        }

        pub fn active_processes(&self) -> Result<u32> {
            if self.handle.is_null() {
                return Ok(0);
            }
            unsafe {
                let mut info: JobObjectBasicAccountingInformation = zeroed();
                if QueryInformationJobObject(
                    self.handle,
                    JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS,
                    &mut info as *mut _ as *mut c_void,
                    size_of::<JobObjectBasicAccountingInformation>() as Dword,
                    null_mut(),
                ) == 0
                {
                    return Err(io::Error::last_os_error())
                        .context("query Windows Job Object accounting");
                }
                Ok(info.ActiveProcesses)
            }
        }

        pub fn terminate(&mut self) {
            if self.handle.is_null() {
                return;
            }
            unsafe {
                let handle = std::mem::replace(&mut self.handle, null_mut());
                let _ = TerminateJobObject(handle, 1);
                let _ = CloseHandle(handle);
            }
        }
    }

    impl Drop for JobHandle {
        fn drop(&mut self) {
            if self.handle.is_null() {
                return;
            }
            unsafe {
                let handle = std::mem::replace(&mut self.handle, null_mut());
                let _ = CloseHandle(handle);
            }
        }
    }
}
