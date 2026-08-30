//! Windows process sandbox backend.
//!
//! This module deliberately keeps all Windows-only code behind `target_os =
//! "windows"`.  The first containment choice is the Windows 11
//! `processmodel.dll!Experimental_CreateProcessInSandbox` API.  That API is
//! experimental and is therefore resolved at runtime instead of being linked
//! at build time.  Its compiled FlatBuffer specification requests
//! AppContainer isolation, low integrity, least privilege, the policy's file
//! roots, and a default-deny network policy.
//!
//! A Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` is always attached to
//! a successfully-created child.  If the experimental API is absent or cannot
//! be used, this backend fails closed.  It never silently launches an ordinary
//! process, changes host firewall rules, changes host DACLs, or installs a
//! driver. When the token-taking experimental export is present, the child is
//! launched with a restricted, low-integrity primary token as well. The direct
//! processmodel variant remains an explicit AppContainer/least-privilege path;
//! a restricted token alone is never treated as filesystem/network enforcement.

#![allow(clashing_extern_declarations)]

use std::collections::BTreeMap;
use std::ffi::{c_char, c_void};
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{anyhow, bail, Context, Result};

use crate::config::NetMode;
use crate::policy::{Policy, ResourceLimits};
use crate::sandbox::handle::{KillStrategy, SandboxHandle, SpawnOptions};
use crate::sandbox::Spawned;

// Optional platform backends live in separate files.  The process launcher
// below remains the stable facade used by the sandbox worker; these modules
// expose explicit capability-gated interfaces for callers that opt into
// host-level observation or policy.  None of them silently elevates or
// changes persistent host configuration.
pub mod appcontainer;
pub mod etw;
pub mod eventlog;
pub mod firewall;
pub mod integrity;
pub mod job_object;
pub mod minifilter;
pub mod restricted_token;
pub mod windows_sandbox;

type Handle = *mut c_void;
type Hmodule = *mut c_void;
type Dword = u32;
type Bool = i32;
type Lpvoid = *mut c_void;

const TRUE: Bool = 1;
const FALSE: Bool = 0;
const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;

const CREATE_SUSPENDED: Dword = 0x0000_0004;
const CREATE_NEW_PROCESS_GROUP: Dword = 0x0000_0200;
const CREATE_UNICODE_ENVIRONMENT: Dword = 0x0000_0400;

const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: Dword = 9;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Dword = 0x0000_2000;
const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: Dword = 0x0000_0008;
// Defined for completeness of the extended-limit flag family.  The backend
// currently expresses the address-space ceiling through the job-wide memory
// limit only, so the per-process variant stays unused.
#[allow(dead_code)]
const JOB_OBJECT_LIMIT_PROCESS_MEMORY: Dword = 0x0000_0100;
const JOB_OBJECT_LIMIT_JOB_MEMORY: Dword = 0x0000_0200;

const TOKEN_ASSIGN_PRIMARY: Dword = 0x0001;
const TOKEN_DUPLICATE: Dword = 0x0002;
const TOKEN_QUERY: Dword = 0x0008;
const TOKEN_ADJUST_DEFAULT: Dword = 0x0080;
const DISABLE_MAX_PRIVILEGE: Dword = 0x0000_0001;
const SECURITY_IMPERSONATION: Dword = 2;
const TOKEN_PRIMARY: Dword = 1;
const TOKEN_INTEGRITY_LEVEL: Dword = 25;
const SECURITY_MANDATORY_LABEL_ATTRIBUTE: Dword = 0x0000_0020;
const SECURITY_MANDATORY_LOW_RID: Dword = 0x1000;

const LOAD_LIBRARY_SEARCH_SYSTEM32: Dword = 0x0000_0800;

static NEXT_SANDBOX_ID: AtomicU64 = AtomicU64::new(1);

#[repr(C)]
struct SecurityAttributes {
    length: Dword,
    security_descriptor: Lpvoid,
    inherit_handle: Bool,
}

#[repr(C)]
struct StartupInfoW {
    cb: Dword,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: Dword,
    y: Dword,
    x_size: Dword,
    y_size: Dword,
    x_count_chars: Dword,
    y_count_chars: Dword,
    fill_attribute: Dword,
    flags: Dword,
    show_window: u16,
    reserved2: u16,
    reserved2_ptr: *mut u8,
    std_input: Handle,
    std_output: Handle,
    std_error: Handle,
}

#[repr(C)]
struct ProcessInformation {
    process: Handle,
    thread: Handle,
    process_id: Dword,
    thread_id: Dword,
}

#[repr(C)]
struct IoCounters {
    read_operation_count: u64,
    write_operation_count: u64,
    other_operation_count: u64,
    read_transfer_count: u64,
    write_transfer_count: u64,
    other_transfer_count: u64,
}

#[repr(C)]
struct JobObjectBasicLimitInformation {
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
struct JobObjectExtendedLimitInformation {
    basic_limit_information: JobObjectBasicLimitInformation,
    io_info: IoCounters,
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

#[repr(C)]
struct TokenMandatoryLabel {
    label: SidAndAttributes,
}

#[repr(C)]
struct SidAndAttributes {
    sid: Lpvoid,
    attributes: Dword,
}

type ExperimentalCreateProcessInSandbox = unsafe extern "system" fn(
    application_name: *const u16,
    command_line: *mut u16,
    process_attributes: *mut SecurityAttributes,
    thread_attributes: *mut SecurityAttributes,
    inherit_handles: Bool,
    creation_flags: Dword,
    environment: Lpvoid,
    current_directory: *const u16,
    startup_info: *mut StartupInfoW,
    identity: *const u16,
    sandbox_specification: *const c_void,
    sandbox_specification_size: Dword,
    process_information: *mut ProcessInformation,
) -> Bool;

type ExperimentalCreateProcessAsUserInSandbox = unsafe extern "system" fn(
    token: Handle,
    application_name: *const u16,
    command_line: *mut u16,
    process_attributes: *mut SecurityAttributes,
    thread_attributes: *mut SecurityAttributes,
    inherit_handles: Bool,
    creation_flags: Dword,
    environment: Lpvoid,
    current_directory: *const u16,
    startup_info: *mut StartupInfoW,
    identity: *const u16,
    sandbox_specification: *const c_void,
    sandbox_specification_size: Dword,
    process_information: *mut ProcessInformation,
) -> Bool;

#[allow(non_snake_case)]
#[link(name = "kernel32")]
extern "system" {
    fn CloseHandle(handle: Handle) -> Bool;
    fn CreateJobObjectW(attributes: *mut SecurityAttributes, name: *const u16) -> Handle;
    fn SetInformationJobObject(
        job: Handle,
        information_class: Dword,
        information: Lpvoid,
        information_length: Dword,
    ) -> Bool;
    fn AssignProcessToJobObject(job: Handle, process: Handle) -> Bool;
    fn ResumeThread(thread: Handle) -> Dword;
    fn TerminateProcess(process: Handle, exit_code: u32) -> Bool;
    fn GetCurrentProcess() -> Handle;
    fn GetLastError() -> Dword;
    fn LoadLibraryExW(name: *const u16, file: Handle, flags: Dword) -> Hmodule;
    fn GetProcAddress(module: Hmodule, name: *const c_char) -> *mut c_void;
}

#[allow(non_snake_case)]
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, desired_access: Dword, token: *mut Handle) -> Bool;
    fn CreateRestrictedToken(
        existing_token: Handle,
        flags: Dword,
        disable_sid_count: Dword,
        sids_to_disable: Lpvoid,
        delete_privilege_count: Dword,
        privileges_to_delete: Lpvoid,
        restrict_sid_count: Dword,
        sids_to_restrict: Lpvoid,
        restricted_token: *mut Handle,
    ) -> Bool;
    fn DuplicateTokenEx(
        existing_token: Handle,
        desired_access: Dword,
        token_attributes: *mut SecurityAttributes,
        impersonation_level: Dword,
        token_type: Dword,
        new_token: *mut Handle,
    ) -> Bool;
    fn SetTokenInformation(
        token: Handle,
        token_information_class: Dword,
        token_information: Lpvoid,
        token_information_length: Dword,
    ) -> Bool;
    fn GetLengthSid(sid: Lpvoid) -> Dword;
}

#[allow(non_snake_case)]
#[link(name = "advapi32")]
extern "system" {
    fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut Lpvoid) -> Bool;
}

#[allow(non_snake_case)]
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(memory: Lpvoid) -> Lpvoid;
}

/// Runtime capabilities exposed to `doctor` and integrations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsCapabilities {
    pub job_object_kill_on_close: bool,
    pub restricted_token: bool,
    pub low_integrity_token: bool,
    pub appcontainer_api: bool,
    pub lpac_api: bool,
    pub experimental_create_process_in_sandbox: bool,
    pub experimental_create_process_as_user_in_sandbox: bool,
    pub filesystem_policy: bool,
    pub network_policy: bool,
    /// Host firewall/WFP mutation is deliberately not performed by vetto.
    pub privileged_network_backend_enabled: bool,
    pub privileged_network_backend_requires_admin: bool,
    pub notes: Vec<String>,
}

impl WindowsCapabilities {
    pub fn enforcement_ready(&self) -> bool {
        self.job_object_kill_on_close
            && self.restricted_token
            && self.low_integrity_token
            && self.appcontainer_api
            && self.experimental_create_process_in_sandbox
            && self.filesystem_policy
            && self.network_policy
    }

    pub fn summary(&self) -> String {
        format!(
            "windows job-kill={}, restricted-token={}, low-integrity={}, appcontainer-api={}, lpac-api={}, experimental-process-sandbox={}, experimental-as-user={}, fs-policy={}, network-policy={}, privileged-network-backend={}, admin-required={}",
            yn(self.job_object_kill_on_close),
            yn(self.restricted_token),
            yn(self.low_integrity_token),
            yn(self.appcontainer_api),
            yn(self.lpac_api),
            yn(self.experimental_create_process_in_sandbox),
            yn(self.experimental_create_process_as_user_in_sandbox),
            yn(self.filesystem_policy),
            yn(self.network_policy),
            // Keep the process backend's privileged gate visible in doctor
            // output. The separate WFP module is opt-in and is not invoked by
            // this launcher path.
            yn(self.privileged_network_backend_enabled),
            yn(self.privileged_network_backend_requires_admin),
        )
    }
}

/// Explicit status for optional host-impacting network backends. The process
/// launcher never creates firewall/WFP rules or requests elevation; callers
/// must opt into the separate capability-gated WFP lease API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedNetworkBackendStatus {
    pub enabled: bool,
    pub requires_admin: bool,
    pub reason: &'static str,
}

/// Capability-only snapshot for optional host backends.  This is exported so
/// doctor/reporting code can present the admin/feature boundaries without
/// changing the main CLI or silently enabling any backend.
#[derive(Debug, Clone)]
pub struct OptionalBackendReport {
    pub firewall: firewall::FirewallCapabilities,
    pub etw: etw::EtwCapabilities,
    pub windows_sandbox: windows_sandbox::WindowsSandboxCapabilities,
    pub eventlog: eventlog::EventLogCapabilities,
}

pub fn optional_backend_report() -> OptionalBackendReport {
    OptionalBackendReport {
        firewall: firewall::capabilities(),
        etw: etw::capability_probe(),
        windows_sandbox: windows_sandbox::capabilities(),
        eventlog: eventlog::capabilities("vetto"),
    }
}

pub fn privileged_network_backend_status() -> PrivilegedNetworkBackendStatus {
    PrivilegedNetworkBackendStatus {
        enabled: false,
        requires_admin: true,
        reason: "the process sandbox never mutates host firewall state; the optional WFP lease is explicit, admin-gated, image-scoped, dynamic, and read-back verified",
    }
}

/// Probe without changing host policy.  The restricted-token probe creates and
/// closes an in-memory token only; it does not alter the current process.
pub fn probe() -> WindowsCapabilities {
    let job = probe_job_object();
    let (restricted, low) = probe_restricted_token();
    let appcontainer = probe_appcontainer_api();
    let lpac_api = appcontainer::probe_lpac();
    let experimental = experimental_create_process_in_sandbox().is_some();
    let experimental_as_user = experimental_create_process_as_user_in_sandbox().is_some();
    let mut notes = vec![
        "read/write and read-only filesystem grants plus network default-deny are delegated to the Windows AppContainer process sandbox; denied paths and host firewall/WFP/DACL/driver guarantees are not claimed"
            .to_string(),
    ];
    if !experimental {
        notes.push(
            "Windows 11 processmodel.dll sandbox export is unavailable; refusing an ordinary process fallback"
                .to_string(),
        );
    }
    if !experimental_as_user {
        notes.push(
            "Experimental_CreateProcessAsUserInSandbox is unavailable; using the AppContainer API without the optional restricted-token launch path"
                .to_string(),
        );
    }
    if !appcontainer {
        notes.push(
            "AppContainer profile/capability APIs are unavailable; no AppContainer fallback is claimed"
                .to_string(),
        );
    }
    if !job {
        notes.push("Job Object kill-on-close could not be created".to_string());
    }
    if !restricted || !low {
        notes.push(
            "restricted/low-integrity token probe failed; no weaker token fallback is allowed"
                .to_string(),
        );
    }
    WindowsCapabilities {
        job_object_kill_on_close: job,
        restricted_token: restricted,
        low_integrity_token: low,
        appcontainer_api: appcontainer,
        lpac_api,
        experimental_create_process_in_sandbox: experimental,
        experimental_create_process_as_user_in_sandbox: experimental_as_user,
        filesystem_policy: experimental,
        network_policy: experimental,
        privileged_network_backend_enabled: false,
        privileged_network_backend_requires_admin: true,
        notes,
    }
}

pub fn describe() -> String {
    let p = probe();
    let mut text = p.summary();
    for note in p.notes {
        text.push_str("; note: ");
        text.push_str(&note);
    }
    text
}

/// Windows backend state.  It is intentionally small; all handles are
/// transferred into the returned `SandboxHandle` after the child is resumed.
pub struct WindowsSandbox {
    pub capabilities: WindowsCapabilities,
    pub net: NetMode,
}

impl WindowsSandbox {
    pub fn new(net: NetMode) -> Result<Self> {
        let capabilities = probe();
        if !capabilities.job_object_kill_on_close {
            bail!("Windows Job Object kill-on-close is unavailable; refusing to run")
        }
        if !capabilities.restricted_token || !capabilities.low_integrity_token {
            bail!("restricted low-integrity token setup is unavailable; refusing to run")
        }
        if !capabilities.appcontainer_api {
            bail!("AppContainer capability APIs are unavailable; refusing to run")
        }
        if !capabilities.experimental_create_process_in_sandbox {
            bail!(
                "Experimental_CreateProcessInSandbox is unavailable; refusing an unsandboxed Windows fallback"
            )
        }
        if !capabilities.filesystem_policy || !capabilities.network_policy {
            bail!("Windows process sandbox policy capabilities are incomplete; refusing to run")
        }
        if !matches!(&net, &NetMode::Off) {
            bail!(
                "Windows experimental process sandbox needs a compiled IP/port policy; vetto's domain network modes have no DNS-to-IP compiler on this backend, refusing a weaker network policy"
            )
        }
        Ok(Self { capabilities, net })
    }

    pub fn spawn(self, policy: &Policy, opts: SpawnOptions) -> Result<Spawned> {
        if opts.agent_cmd.is_empty() {
            bail!("empty agent command")
        }
        if !self.capabilities.enforcement_ready() {
            bail!("Windows sandbox capabilities are not enforcement-ready; refusing to run")
        }
        if !matches!(opts.stdio, crate::sandbox::handle::StdioMode::Inherit) {
            bail!(
                "Windows backend currently supports inherited stdio only; refusing to detach output handles"
            )
        }
        if opts.agent_cmd.iter().any(|arg| arg.contains('\0')) {
            bail!("Windows agent command contains an embedded NUL")
        }

        let mut command_line = command_line(&opts.agent_cmd)?;
        let application_name = wide_null(&opts.agent_cmd[0]);
        let current_directory = wide_path(&opts.cwd)?;
        // The identity becomes the AppContainer profile name. Keep it short,
        // package-name-safe, and unique even when several children are started
        // in the same process during one clock tick.
        let identity = format!(
            "vetto_{}_{}_{}",
            std::process::id(),
            identity_nonce(),
            NEXT_SANDBOX_ID.fetch_add(1, Ordering::Relaxed)
        );
        let identity = wide_null(&identity);
        let mut environment = environment_block(policy, &opts)?;
        let specification = build_sandbox_spec(policy, &self.net)?;
        let mut startup = startup_info();
        let mut process_info = ProcessInformation {
            process: null_mut(),
            thread: null_mut(),
            process_id: 0,
            thread_id: 0,
        };
        let create = experimental_create_process_in_sandbox()
            .context("Experimental_CreateProcessInSandbox export disappeared")?;
        let create_as_user = if self
            .capabilities
            .experimental_create_process_as_user_in_sandbox
        {
            Some(
                experimental_create_process_as_user_in_sandbox()
                    .context("Experimental_CreateProcessAsUserInSandbox export disappeared")?,
            )
        } else {
            None
        };
        // Prefer the as-user variant when the OS exposes it so the restricted,
        // low-integrity primary token is an actual launch input. The direct
        // variant remains an explicit AppContainer/least-privilege path when
        // that optional export is absent; it is never an ordinary process
        // fallback.
        let restricted_token = if create_as_user.is_some() {
            Some(restricted_primary_token()?)
        } else {
            None
        };
        let using_as_user = create_as_user.is_some();

        // SAFETY: all pointers refer to mutable, NUL-terminated buffers kept
        // alive for the duration of this call; reserved attributes are null as
        // required by the experimental API.  The child is created suspended so
        // it cannot execute before the Job Object is attached.
        let ok = if let Some(create_as_user) = create_as_user {
            let token = restricted_token
                .as_ref()
                .expect("as-user process creation requires a restricted token");
            // SAFETY: token is a live primary token with the documented
            // TOKEN_QUERY/TOKEN_DUPLICATE/TOKEN_ASSIGN_PRIMARY rights.
            unsafe {
                create_as_user(
                    token.as_raw_handle().cast(),
                    application_name.as_ptr(),
                    command_line.as_mut_ptr(),
                    null_mut(),
                    null_mut(),
                    FALSE,
                    CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
                    environment.as_mut_ptr().cast(),
                    current_directory.as_ptr(),
                    &mut startup,
                    identity.as_ptr(),
                    specification.as_ptr().cast(),
                    specification.len() as Dword,
                    &mut process_info,
                )
            }
        } else {
            unsafe {
                create(
                    application_name.as_ptr(),
                    command_line.as_mut_ptr(),
                    null_mut(),
                    null_mut(),
                    FALSE,
                    CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
                    environment.as_mut_ptr().cast(),
                    current_directory.as_ptr(),
                    &mut startup,
                    identity.as_ptr(),
                    specification.as_ptr().cast(),
                    specification.len() as Dword,
                    &mut process_info,
                )
            }
        };
        if ok != TRUE {
            let error = last_error();
            // Defensive cleanup: a failed experimental implementation must
            // not leave any partially returned native handles behind.
            close_handle(process_info.thread);
            close_handle(process_info.process);
            if using_as_user {
                bail!(
                    "Experimental_CreateProcessAsUserInSandbox failed: {}",
                    error
                )
            } else {
                bail!("Experimental_CreateProcessInSandbox failed: {}", error)
            }
        }
        if !valid_handle(process_info.process) || !valid_handle(process_info.thread) {
            // A successful BOOL without both documented output handles is an
            // invalid runtime contract; never continue with partially-owned
            // process state.
            close_handle(process_info.thread);
            close_handle(process_info.process);
            bail!("Windows sandbox API returned invalid process handles")
        }

        let process = process_info.process;
        let thread = process_info.thread;
        let job = match create_kill_on_close_job(&policy.limits) {
            Ok(job) => job,
            Err(error) => {
                // SAFETY: process/thread are valid handles returned by the
                // successful creation call; terminate before closing them.
                unsafe {
                    TerminateProcess(process, 1);
                    CloseHandle(thread);
                    CloseHandle(process);
                }
                return Err(error);
            }
        };
        // SAFETY: process and job are valid handles; the process is suspended.
        if unsafe { AssignProcessToJobObject(job.as_raw_handle().cast(), process) } != TRUE {
            let error = anyhow!("AssignProcessToJobObject failed: {}", last_error());
            // SAFETY: the process has not resumed and is still owned by us.
            unsafe {
                TerminateProcess(process, 1);
                CloseHandle(thread);
                CloseHandle(process);
            }
            return Err(error);
        }
        // SAFETY: thread is a valid suspended thread handle from the process
        // creation result.
        if unsafe { ResumeThread(thread) } == u32::MAX {
            let error = anyhow!("ResumeThread failed: {}", last_error());
            unsafe {
                TerminateProcess(process, 1);
                CloseHandle(thread);
                CloseHandle(process);
            }
            return Err(error);
        }
        // SAFETY: the Job Object now owns the lifetime relationship. Retain
        // the process handle for reliable waits/exit codes; only the thread
        // handle is closed here.
        let process = unsafe { OwnedHandle::from_raw_handle(process.cast()) };
        unsafe {
            CloseHandle(thread);
        }

        Ok(Spawned {
            handle: SandboxHandle {
                root_pid: process_info.process_id,
                strategy: Some(KillStrategy::JobObject { job, process }),
            },
        })
    }
}

fn yn(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn last_error() -> std::io::Error {
    // SAFETY: GetLastError has no preconditions and is thread-local.
    std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
}

fn valid_handle(handle: Handle) -> bool {
    !handle.is_null() && handle != INVALID_HANDLE_VALUE
}

fn close_handle(handle: Handle) {
    if valid_handle(handle) {
        // SAFETY: caller only passes a live Win32 handle; duplicate closes are
        // prevented by ownership transfer at each call site.
        unsafe { CloseHandle(handle) };
    }
}

fn create_kill_on_close_job(limits: &ResourceLimits) -> Result<OwnedHandle> {
    // SAFETY: null attributes/name request an unnamed Job Object.
    let job = unsafe { CreateJobObjectW(null_mut(), null()) };
    if !valid_handle(job) {
        bail!("CreateJobObjectW failed: {}", last_error())
    }
    // Optional ceilings from the policy.  A Job memory limit caps the total
    // commit charge of every process in the job, which is the closest Job
    // Object approximation of RLIMIT_AS (`address_space_bytes`).  A zero or
    // absent limit leaves the flag unset and reproduces the previous behavior
    // exactly; values that cannot be represented on this platform fail closed.
    let mut limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let job_memory_limit = match limits.address_space_bytes {
        Some(bytes) if bytes > 0 => {
            limit_flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            match usize::try_from(bytes) {
                Ok(bytes) => bytes,
                Err(_) => bail!("address_space_bytes does not fit the platform usize: {bytes}"),
            }
        }
        _ => 0,
    };
    let active_process_limit = match limits.processes {
        Some(processes) if processes > 0 => {
            limit_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            match u32::try_from(processes) {
                Ok(processes) => processes,
                Err(_) => bail!("processes does not fit a 32-bit Job Object limit: {processes}"),
            }
        }
        _ => 0,
    };
    let mut extended = JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation {
            per_process_user_time_limit: 0,
            per_job_user_time_limit: 0,
            limit_flags,
            minimum_working_set_size: 0,
            maximum_working_set_size: 0,
            active_process_limit,
            affinity: 0,
            priority_class: 0,
            scheduling_class: 0,
        },
        io_info: IoCounters {
            read_operation_count: 0,
            write_operation_count: 0,
            other_operation_count: 0,
            read_transfer_count: 0,
            write_transfer_count: 0,
            other_transfer_count: 0,
        },
        process_memory_limit: 0,
        job_memory_limit,
        peak_process_memory_used: 0,
        peak_job_memory_used: 0,
    };
    // SAFETY: `extended` has the documented Job Object layout and remains live
    // for the duration of this call.
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            (&mut extended as *mut JobObjectExtendedLimitInformation).cast(),
            size_of::<JobObjectExtendedLimitInformation>() as Dword,
        )
    };
    if ok != TRUE {
        let error = anyhow!("SetInformationJobObject failed: {}", last_error());
        close_handle(job);
        return Err(error);
    }
    // Optional IO rate limits from the policy (Feature 60).
    if let Some(io_rate) = &limits.io_rate {
        if io_rate.max_iops.is_some() || io_rate.max_bandwidth.is_some() {
            let mut io_info = job_object::JobObjectIoRateControlInformation {
                max_iops: io_rate.max_iops.map(|v| v as i64).unwrap_or(0),
                max_bandwidth: io_rate.max_bandwidth.map(|v| v as i64).unwrap_or(0),
                reservation_iops: 0,
                volume_name: null(),
                base_io_size: 0,
                control_flags: 0,
            };
            // Best-effort: on older Windows versions where IO rate control is unsupported,
            // SetInformationJobObject returns FALSE. We do not fail the entire job creation.
            unsafe {
                SetInformationJobObject(
                    job,
                    job_object::JOB_OBJECT_IO_RATE_CONTROL_INFORMATION,
                    (&mut io_info as *mut job_object::JobObjectIoRateControlInformation).cast(),
                    size_of::<job_object::JobObjectIoRateControlInformation>() as Dword,
                );
            }
        }
    }
    // SAFETY: successful CreateJobObjectW returned an owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(job.cast()) })
}

fn probe_job_object() -> bool {
    // Probes carry no policy: default limits leave the optional job limit
    // flags unset, so the probe exercises exactly the always-on
    // kill-on-close path.
    create_kill_on_close_job(&ResourceLimits::default()).is_ok()
}

fn probe_restricted_token() -> (bool, bool) {
    let mut current = null_mut();
    // SAFETY: current process pseudo-handle is valid; output points to local
    // storage.  The requested rights are exactly those needed below.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
            &mut current,
        )
    };
    if opened != TRUE {
        return (false, false);
    }
    let mut restricted = null_mut();
    // SAFETY: all optional SID/privilege arrays are empty and represented by
    // null pointers; output is local storage.
    let restricted_ok = unsafe {
        CreateRestrictedToken(
            current,
            DISABLE_MAX_PRIVILEGE,
            0,
            null_mut(),
            0,
            null_mut(),
            0,
            null_mut(),
            &mut restricted,
        )
    } == TRUE;
    close_handle(current);
    if !restricted_ok || !valid_handle(restricted) {
        return (false, false);
    }
    let low = set_low_integrity(restricted);
    close_handle(restricted);
    (true, low)
}

#[allow(dead_code)]
fn restricted_primary_token() -> Result<OwnedHandle> {
    let mut current = null_mut();
    // SAFETY: see `probe_restricted_token`; output points to local storage.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
            &mut current,
        )
    } != TRUE
    {
        bail!("OpenProcessToken failed: {}", last_error())
    }
    let mut restricted = null_mut();
    // SAFETY: empty restriction arrays are intentional; the resulting token
    // has all privileges disabled before its integrity level is lowered.
    let ok = unsafe {
        CreateRestrictedToken(
            current,
            DISABLE_MAX_PRIVILEGE,
            0,
            null_mut(),
            0,
            null_mut(),
            0,
            null_mut(),
            &mut restricted,
        )
    };
    close_handle(current);
    if ok != TRUE || !valid_handle(restricted) {
        bail!("CreateRestrictedToken failed: {}", last_error())
    }
    let mut primary = null_mut();
    // SAFETY: restricted is a valid token; DuplicateTokenEx returns a primary
    // token suitable for CreateProcessWithTokenW.
    let ok = unsafe {
        DuplicateTokenEx(
            restricted,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
            null_mut(),
            SECURITY_IMPERSONATION,
            TOKEN_PRIMARY,
            &mut primary,
        )
    };
    close_handle(restricted);
    if ok != TRUE || !valid_handle(primary) {
        bail!("DuplicateTokenEx failed: {}", last_error())
    }
    if !set_low_integrity(primary) {
        let error = anyhow!(
            "SetTokenInformation(low integrity) failed: {}",
            last_error()
        );
        close_handle(primary);
        return Err(error);
    }
    // SAFETY: successful DuplicateTokenEx returned an owned token handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(primary.cast()) })
}

fn set_low_integrity(token: Handle) -> bool {
    let mut sid = null_mut();
    let sid_text = wide_null(&format!("S-1-16-{SECURITY_MANDATORY_LOW_RID}"));
    // SAFETY: valid NUL-terminated SID text and output storage.
    if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } != TRUE {
        return false;
    }
    // SAFETY: `sid` was validated by ConvertStringSidToSidW above.
    let sid_length = unsafe { GetLengthSid(sid) };
    if sid_length == 0 {
        // SAFETY: sid was returned by ConvertStringSidToSidW.
        unsafe { LocalFree(sid) };
        return false;
    }
    let Some(label_length) = size_of::<TokenMandatoryLabel>().checked_add(sid_length as usize)
    else {
        // SAFETY: sid was returned by ConvertStringSidToSidW.
        unsafe { LocalFree(sid) };
        return false;
    };
    // SetTokenInformation expects the TOKEN_MANDATORY_LABEL structure followed
    // by the SID bytes in the same buffer. A bare stack structure plus a larger
    // length is not sufficient: the kernel may read the advertised SID payload
    // past the structure. Use a word-aligned allocation so the structure is
    // correctly aligned on both 32- and 64-bit Windows, then copy the SID into
    // the trailing payload and point the structure at that copy.
    let words = label_length.saturating_add(size_of::<usize>() - 1) / size_of::<usize>();
    let mut buffer = vec![0usize; words];
    let label_ptr = buffer.as_mut_ptr().cast::<TokenMandatoryLabel>();
    let sid_copy = unsafe {
        label_ptr
            .cast::<u8>()
            .add(size_of::<TokenMandatoryLabel>())
            .cast::<c_void>()
    };
    // SAFETY: `sid` points to at least `sid_length` initialized bytes returned
    // by ConvertStringSidToSidW; `sid_copy` points into the larger aligned
    // buffer and the regions do not overlap.
    let ok = unsafe {
        std::ptr::copy_nonoverlapping(sid.cast::<u8>(), sid_copy.cast::<u8>(), sid_length as usize);
        (*label_ptr).label = SidAndAttributes {
            sid: sid_copy,
            attributes: SECURITY_MANDATORY_LABEL_ATTRIBUTE,
        };
        SetTokenInformation(
            token,
            TOKEN_INTEGRITY_LEVEL,
            label_ptr.cast(),
            label_length as Dword,
        )
    };
    // SAFETY: ConvertStringSidToSidW allocates with LocalAlloc; LocalFree is the
    // matching release operation.
    unsafe { LocalFree(sid) };
    ok == TRUE
}

fn probe_appcontainer_api() -> bool {
    // Keep the ABI and LocalAlloc cleanup in the dedicated probe module. It
    // resolves Userenv.dll dynamically, calls the documented derivation
    // routine, and never creates a profile or changes token state.
    let capabilities = appcontainer::probe();
    capabilities.derive_capability_sids && capabilities.create_appcontainer_profile
}

fn experimental_create_process_in_sandbox() -> Option<ExperimentalCreateProcessInSandbox> {
    // The API is Windows 11-only and intentionally not linked.  Loading from
    // System32 avoids DLL search-path hijacking.
    // SAFETY: static module name and documented LOAD_LIBRARY_SEARCH_SYSTEM32.
    let module = unsafe {
        LoadLibraryExW(
            wide_null("processmodel.dll").as_ptr(),
            null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if !valid_handle(module) {
        return None;
    }
    // SAFETY: export name is static and the pointer is transmuted only after
    // checking that the export exists.  The signature mirrors the Microsoft
    // API documentation exactly; the module remains loaded for the process.
    let address = unsafe {
        GetProcAddress(
            module,
            b"Experimental_CreateProcessInSandbox\0".as_ptr().cast(),
        )
    };
    if address.is_null() {
        None
    } else {
        // SAFETY: the address is the documented function export and its ABI is
        // represented by `ExperimentalCreateProcessInSandbox` above.
        Some(unsafe {
            std::mem::transmute::<*mut c_void, ExperimentalCreateProcessInSandbox>(address)
        })
    }
}

fn experimental_create_process_as_user_in_sandbox(
) -> Option<ExperimentalCreateProcessAsUserInSandbox> {
    // Resolve the token-taking sibling through the same System32-only path.
    // It is optional because some Windows 11 builds expose only the caller-
    // identity variant; the latter still has AppContainer/least-privilege
    // enforcement and is selected explicitly by the caller.
    // SAFETY: static module name and documented LOAD_LIBRARY_SEARCH_SYSTEM32.
    let module = unsafe {
        LoadLibraryExW(
            wide_null("processmodel.dll").as_ptr(),
            null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if !valid_handle(module) {
        return None;
    }
    // SAFETY: export name is static and the pointer is transmuted only after
    // checking that the export exists.
    let address = unsafe {
        GetProcAddress(
            module,
            b"Experimental_CreateProcessAsUserInSandbox\0"
                .as_ptr()
                .cast(),
        )
    };
    if address.is_null() {
        None
    } else {
        // SAFETY: the address is the documented token-taking export and its
        // ABI is represented by `ExperimentalCreateProcessAsUserInSandbox`.
        Some(unsafe {
            std::mem::transmute::<*mut c_void, ExperimentalCreateProcessAsUserInSandbox>(address)
        })
    }
}

fn startup_info() -> StartupInfoW {
    StartupInfoW {
        cb: size_of::<StartupInfoW>() as Dword,
        reserved: null_mut(),
        desktop: null_mut(),
        title: null_mut(),
        x: 0,
        y: 0,
        x_size: 0,
        y_size: 0,
        x_count_chars: 0,
        y_count_chars: 0,
        fill_attribute: 0,
        flags: 0,
        show_window: 0,
        reserved2: 0,
        reserved2_ptr: null_mut(),
        std_input: null_mut(),
        std_output: null_mut(),
        std_error: null_mut(),
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    let value = path
        .to_str()
        .ok_or_else(|| anyhow!("path is not valid Unicode: {}", path.display()))?;
    if value.contains('\0') {
        bail!("path contains an embedded NUL: {}", path.display())
    }
    Ok(wide_null(value))
}

fn quote_windows_arg(value: &str) -> String {
    if !value.is_empty() && !value.chars().any(|c| c.is_whitespace() || c == '"') {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    let mut slashes = 0usize;
    for ch in value.chars() {
        if ch == '\\' {
            slashes += 1;
        } else if ch == '"' {
            out.push_str(&"\\".repeat(slashes * 2 + 1));
            out.push('"');
            slashes = 0;
        } else {
            out.push_str(&"\\".repeat(slashes));
            slashes = 0;
            out.push(ch);
        }
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

fn command_line(args: &[String]) -> Result<Vec<u16>> {
    if args.is_empty() {
        bail!("empty command line")
    }
    let joined = args
        .iter()
        .map(|arg| {
            if arg.contains('\0') {
                Err(anyhow!("command argument contains an embedded NUL"))
            } else {
                Ok(quote_windows_arg(arg))
            }
        })
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    // CreateProcess-compatible command lines are limited to 32,767 UTF-16
    // code units including the terminator. Reject oversized input before the
    // experimental API can truncate or reinterpret it.
    if joined.encode_utf16().count() + 1 > 32_767 {
        bail!("Windows command line exceeds the 32,767 UTF-16 code-unit limit")
    }
    Ok(wide_null(&joined))
}

fn environment_block(policy: &Policy, opts: &SpawnOptions) -> Result<Vec<u16>> {
    // Windows treats environment names case-insensitively. Keep a normalized
    // key in the map so `Path` and `PATH` cannot produce an ambiguous child
    // environment; explicit extras replace the inherited value regardless of
    // spelling.
    let mut env = BTreeMap::<String, (String, String)>::new();
    for (key, value) in std::env::vars_os() {
        if policy.environment.allows(&key) {
            // Windows natively stores UTF-16, but an ill-formed surrogate
            // cannot be represented by this API's safe Rust String path. Drop
            // such entries rather than panic or construct a malformed block.
            let (Some(key), Some(value)) = (key.to_str(), value.to_str()) else {
                continue;
            };
            env.insert(key.to_lowercase(), (key.to_string(), value.to_string()));
        }
    }
    for (key, value) in &opts.env_extra {
        env.insert(key.to_lowercase(), (key.clone(), value.clone()));
    }
    // Windows requires the supplied block to be sorted by variable name using
    // case-insensitive Unicode order. BTreeMap's bytewise ordering is not that
    // contract, so sort the final entries explicitly and use the original name
    // only as a deterministic tie-breaker.
    let mut entries = env.into_values().collect::<Vec<_>>();
    entries.sort_by(|(left, _), (right, _)| {
        left.to_lowercase()
            .cmp(&right.to_lowercase())
            .then_with(|| left.cmp(right))
    });
    let mut block = Vec::new();
    for (key, value) in entries {
        // Environment names containing '=' or NUL are invalid. Dropping the
        // ambiguous entry is safer than passing a malformed native block.
        if key.is_empty() || key.contains('=') || key.contains('\0') {
            continue;
        }
        if value.contains('\0') {
            bail!("environment variable {key:?} contains an embedded NUL")
        }
        block.extend(key.encode_utf16());
        block.push('=' as u16);
        block.extend(value.encode_utf16());
        block.push(0);
    }
    if block.is_empty() {
        // A Unicode environment block is terminated by two WCHAR NULs,
        // including the empty-environment case.
        block.extend([0, 0]);
    } else {
        block.push(0);
    }
    if block.len() > (32 * 1024 * 1024) / size_of::<u16>() {
        bail!("environment block exceeds the 32 MiB Windows sandbox limit")
    }
    Ok(block)
}

fn build_sandbox_spec(policy: &Policy, net: &NetMode) -> Result<Vec<u8>> {
    if !matches!(net, &NetMode::Off) {
        bail!("domain network modes require a DNS/IP policy compiler; refusing a weaker network policy")
    }
    // The published SandboxSpec.fbs contract exposes read/write and read-only
    // grants, but no verified denied-path field.  The compiled spec is
    // default-deny outside the grant roots, so a deny path that lies outside
    // every granted root is already unreachable for the sandboxed child and
    // needs no extra field; do not put an invented FlatBuffer slot on the wire
    // and claim that it is enforced.  A deny path that sits inside a granted
    // root cannot be subtracted from the spec, so that genuinely dangerous
    // configuration must fail closed with an actionable reason.
    let granted_roots: Vec<&Path> = policy
        .allow_write
        .iter()
        .chain(policy.allow_read.iter())
        .map(|root| root.as_path())
        .collect();
    for denied in &policy.deny_resolved {
        if let Some(root) = granted_roots
            .iter()
            .copied()
            .find(|root| path_inside_root(&denied.path, root))
        {
            bail!(
                "secret path {} sits inside granted root {}; Windows SandboxSpec cannot subtract a subpath — narrow the grant or drop the secret from display_only_deny",
                denied.path.display(),
                root.display()
            );
        }
    }

    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(4096);
    let version = builder.create_string("0.1.0");

    let mut read_write = Vec::new();
    for path in &policy.allow_write {
        if !path.is_absolute() {
            bail!(
                "Windows process sandbox write path must be absolute: {}",
                path.display()
            )
        }
        let value = path
            .to_str()
            .ok_or_else(|| anyhow!("write path is not valid Unicode: {}", path.display()))?;
        if value.contains('\0') {
            bail!("write path contains an embedded NUL: {}", path.display())
        }
        read_write.push(builder.create_string(value));
    }
    let read_write = builder.create_vector(&read_write);

    let mut read_only = Vec::new();
    for path in &policy.allow_read {
        if !path.is_absolute() {
            bail!(
                "Windows process sandbox read path must be absolute: {}",
                path.display()
            )
        }
        let value = path
            .to_str()
            .ok_or_else(|| anyhow!("read path is not valid Unicode: {}", path.display()))?;
        if value.contains('\0') {
            bail!("read path contains an embedded NUL: {}", path.display())
        }
        read_only.push(builder.create_string(value));
    }
    let read_only = builder.create_vector(&read_only);

    // With AppContainer enabled and no network capability/proxy, the
    // documented processmodel contract is default-deny. Keep an empty
    // NetworkPolicy table so the OS parser sees the field without inventing
    // an unverified `egress` subtable.
    let network_start = builder.start_table();
    let network = builder.end_table(network_start);

    let spec_start = builder.start_table();
    // FlatBuffers builder slots are vtable byte offsets (4 + 2 * schema
    // field-index), not the field indexes themselves.  These constants match
    // the published SandboxSpec.fbs fields: version=0, app_container=1,
    // least_privilege=5, fs_read_write=7, fs_read_only=8,
    // network_policy=9.
    builder.push_slot_always::<flatbuffers::WIPOffset<_>>(4, version); // version
    builder.push_slot_always::<bool>(6, true); // app_container
    builder.push_slot_always::<bool>(14, true); // least_privilege
                                                // AppContainer processes receive low integrity by definition.  The
                                                // experimental API rejects an explicit non-default integrity enum when
                                                // app_container=true, so leave the `integrity` field at system_default.
    builder.push_slot_always::<flatbuffers::WIPOffset<_>>(18, read_write);
    builder.push_slot_always::<flatbuffers::WIPOffset<_>>(20, read_only);
    builder.push_slot_always::<flatbuffers::WIPOffset<_>>(22, network);
    let spec = builder.end_table(spec_start);
    builder.finish(spec, Some("SBOX"));
    Ok(builder.finished_data().to_vec())
}

/// Component-wise lexical check for `candidate == root || candidate` being
/// below `root`.  Components — not raw strings — are compared so mixed `/` and
/// `\` separators and repeated separators cannot defeat the check, and
/// comparison folds Unicode case because Windows filesystems resolve paths
/// case-insensitively (a spurious match only causes a redundant fail-closed
/// bail, while a missed match would leave a readable secret inside a grant).
/// This is a lexical analysis of the spec inputs only: symlink aliases whose
/// target leaves the granted tree and 8.3 short names are not modeled here.
/// `deny_resolved` entries are loader-resolved existing paths and grants are
/// validated absolute below, which keeps the common forms aligned.
fn path_inside_root(candidate: &Path, root: &Path) -> bool {
    let mut roots = root.components();
    let mut candidates = candidate.components();
    loop {
        match (candidates.next(), roots.next()) {
            // Every root component matched: candidate equals the root or lies
            // underneath it.
            (_, None) => return true,
            // Candidate exhausted while root components remain: candidate is a
            // strict prefix of the root, not inside it.
            (None, Some(_)) => return false,
            (Some(cand), Some(root_component)) => {
                if !windows_component_match(cand, root_component) {
                    return false;
                }
            }
        }
    }
}

/// Case-insensitive equality of two path components.  Structural matching
/// keeps unit components (`RootDir`, `CurDir`, `ParentDir`) independent of
/// their `as_os_str` rendering; prefixes and normal names fold case because
/// Windows filesystems match paths case-insensitively.
fn windows_component_match(
    left: std::path::Component<'_>,
    right: std::path::Component<'_>,
) -> bool {
    fn fold(value: &std::ffi::OsStr) -> String {
        value.to_string_lossy().to_lowercase()
    }
    match (left, right) {
        (std::path::Component::RootDir, std::path::Component::RootDir) => true,
        (std::path::Component::CurDir, std::path::Component::CurDir) => true,
        (std::path::Component::ParentDir, std::path::Component::ParentDir) => true,
        (std::path::Component::Prefix(left), std::path::Component::Prefix(right)) => {
            fold(left.as_os_str()) == fold(right.as_os_str())
        }
        (std::path::Component::Normal(left), std::path::Component::Normal(right)) => {
            fold(left) == fold(right)
        }
        _ => false,
    }
}

fn identity_nonce() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        path_inside_root, privileged_network_backend_status, quote_windows_arg, wide_null,
    };

    #[test]
    fn path_inside_root_matches_children_and_the_root_itself() {
        let root = Path::new(r"C:\Users\dev\project");
        assert!(path_inside_root(Path::new(r"C:\Users\dev\project"), root));
        assert!(path_inside_root(
            Path::new(r"C:\Users\dev\project\.env"),
            root
        ));
        assert!(path_inside_root(
            Path::new(r"C:\Users\dev\project\sub\.env"),
            root
        ));
        // A sibling sharing a string prefix is not inside the root.
        assert!(!path_inside_root(
            Path::new(r"C:\Users\dev\project2\.env"),
            root
        ));
        // A parent of the root is not inside it.
        assert!(!path_inside_root(Path::new(r"C:\Users\dev"), root));
        assert!(!path_inside_root(
            Path::new(r"D:\Users\dev\project\.env"),
            root
        ));
    }

    #[test]
    fn path_inside_root_folds_case_and_mixed_separators() {
        // Windows resolves paths case-insensitively and accepts both
        // separators; the overlap refusal must not miss such matches.
        let root = Path::new(r"C:\Users\dev\project");
        assert!(path_inside_root(
            Path::new(r"c:/users/DEV/PROJECT/.env"),
            root
        ));
        assert!(path_inside_root(
            Path::new(r"C:/users/dev/project/.ssh"),
            root
        ));
    }

    #[test]
    fn windows_argv_quoting_handles_spaces_and_trailing_slashes() {
        assert_eq!(quote_windows_arg("simple"), "simple");
        assert_eq!(quote_windows_arg("two words"), "\"two words\"");
        assert_eq!(
            quote_windows_arg(r#"C:\\path with space\\"#),
            r#""C:\\path with space\\\\""#
        );
    }

    #[test]
    fn wide_strings_are_nul_terminated() {
        assert_eq!(wide_null("vetto").last(), Some(&0));
    }

    #[test]
    fn privileged_network_mutation_is_explicitly_disabled() {
        let status = privileged_network_backend_status();
        assert!(!status.enabled);
        assert!(status.requires_admin);
        assert!(status.reason.contains("optional WFP lease"));
    }
}
