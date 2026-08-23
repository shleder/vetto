//! Small, independent Job Object wrapper.
//!
//! The sandbox launcher has an equivalent internal path.  This public module
//! is useful to platform tests and future backends that need the same
//! kill-on-close invariant without duplicating the ABI definitions.

use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;

use anyhow::{bail, Result};

pub type RawHandle = *mut c_void;
type Handle = RawHandle;
type Dword = u32;

const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: Dword = 9;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Dword = 0x0000_2000;
const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoCounters {
    read_operation_count: u64,
    write_operation_count: u64,
    other_operation_count: u64,
    read_transfer_count: u64,
    write_transfer_count: u64,
    other_transfer_count: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BasicLimitInformation {
    per_process_user_time_limit: i64,
    per_job_user_time_limit: i64,
    limit_flags: Dword,
    minimum_working_set_size: usize,
    maximum_working_set_size: usize,
    active_process_limit: Dword,
    affinity: usize,
    priority_class: Dword,
    scheduling_class: Dword,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ExtendedLimitInformation {
    basic_limit_information: BasicLimitInformation,
    io_info: IoCounters,
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> Handle;
    fn SetInformationJobObject(
        job: Handle,
        information_class: Dword,
        information: *const c_void,
        information_length: Dword,
    ) -> i32;
    fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
    fn GetLastError() -> Dword;
}

/// A dynamic Job Object whose close terminates all assigned processes.
pub struct JobObject {
    handle: OwnedHandle,
}

impl std::fmt::Debug for JobObject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JobObject")
            .field("handle", &self.handle.as_raw_handle())
            .finish()
    }
}

impl JobObject {
    pub fn new_kill_on_close() -> Result<Self> {
        let raw = unsafe { CreateJobObjectW(null_mut(), std::ptr::null()) };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            bail!("CreateJobObjectW failed with {}", unsafe { GetLastError() });
        }
        let mut limits = ExtendedLimitInformation::default();
        limits.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = unsafe {
            SetInformationJobObject(
                raw,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                (&limits as *const ExtendedLimitInformation).cast(),
                size_of::<ExtendedLimitInformation>() as Dword,
            )
        };
        if ok == 0 {
            drop(unsafe { OwnedHandle::from_raw_handle(raw.cast()) });
            bail!(
                "SetInformationJobObject(KILL_ON_CLOSE) failed with {}",
                unsafe { GetLastError() }
            );
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        Ok(Self { handle })
    }

    /// Assign a process handle with `PROCESS_SET_QUOTA | PROCESS_TERMINATE`.
    ///
    /// # Safety
    ///
    /// `process` must be a live process handle with the documented access
    /// rights and must remain valid for the duration of the call.
    pub unsafe fn assign_process(&self, process: RawHandle) -> Result<()> {
        if process.is_null() || process == INVALID_HANDLE_VALUE {
            bail!("cannot assign an invalid process handle to a Job Object");
        }
        let ok = unsafe { AssignProcessToJobObject(self.handle.as_raw_handle().cast(), process) };
        if ok == 0 {
            bail!("AssignProcessToJobObject failed with {}", unsafe {
                GetLastError()
            });
        }
        Ok(())
    }

    pub fn raw_handle(&self) -> RawHandle {
        self.handle.as_raw_handle().cast()
    }
}

/// Kept as a named contract so callers do not accidentally downgrade this
/// wrapper to a kill-on-request-only implementation.
pub const fn kill_contract() -> &'static str {
    "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE"
}
