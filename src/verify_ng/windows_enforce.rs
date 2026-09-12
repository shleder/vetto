//! Windows host-side enforcement evidence (Stage 3C, Windows agent).
//!
//! This module is the Windows counterpart of [`super::linux_enforce`]: pure
//! capability mapping plus host-observed verification of a production child,
//! read from Win32 handles the parent retains. It never trusts child output.
//!
//! Honesty contract (fail-closed, no fake security):
//! - [`ProbeFacts`] snapshots what the OS offers. [`states_for_facts`] is a
//!   pure function from facts to per-capability states: at most `Configured`
//!   (plus `HostEvidence = Enforced`, which needs no child setup), never
//!   `Enforced`/`Verified` — nothing is installed until a
//!   backend-controlled spawn.
//! - Only [`BackendKind::Windows`](super::sandbox_backend::BackendKind::Windows)
//!   promotion rules apply: `note_spawned` records the pid WITHOUT promoting
//!   (there is no `pre_exec` plan on Windows; the install happens inside the
//!   mechanics spawn). Promotion to `Enforced` happens in
//!   `note_host_verified` and only for capabilities with positive
//!   host-observed evidence; unobserved stays `Configured`, never `Enforced`.
//! - `ResourceLimits` additionally maxes out at `Enforced`: the capability
//!   layer cannot see the frozen policy values (only the canonical bytes),
//!   so value-equality with the policy is attested at the mechanics layer
//!   (fail-closed bail on unrepresentable values), not here.
//! - `SyscallRestriction` and `ExecutionRootIsolation` have no mechanism and
//!   stay `Unsupported`: no syscall filter exists on this backend, and grant
//!   coverage of the cwd is not visible at the capability layer.
//! - Tree `Verified` comes only from the finish-time sweep
//!   ([`pids_still_alive`] after kill-on-close termination), never from PID
//!   existence alone: a PID outliving its parent proves nothing about
//!   containment.

use std::collections::BTreeMap;
#[cfg(target_os = "windows")]
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use super::sandbox_backend::HostVerification;
use super::sandbox_backend::{EnforcementState, PreparationFailureKind, SecurityCapability};

/// Host-probed facts that drive the Windows capability mapping.
///
/// `net_off` is policy-derived (frozen `net_mode == "off"`); every other
/// field is OS-observed. [`ProbeFacts::none`] (all false) is the honest
/// answer off Windows and on machines without the sandbox stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeFacts {
    pub job_kill_on_close: bool,
    pub restricted_token: bool,
    pub low_integrity_token: bool,
    pub appcontainer_api: bool,
    pub experimental_process_sandbox: bool,
    pub experimental_as_user: bool,
    pub net_off: bool,
}

impl ProbeFacts {
    /// No mechanism available. Off Windows this is the only honest answer;
    /// the backend keeps its legacy all-`Unsupported` behavior there.
    pub fn none() -> Self {
        ProbeFacts {
            job_kill_on_close: false,
            restricted_token: false,
            low_integrity_token: false,
            appcontainer_api: false,
            experimental_process_sandbox: false,
            experimental_as_user: false,
            net_off: false,
        }
    }

    /// Probe the real OS. Windows-only: mirrors the fail-closed gate in
    /// `WindowsSandbox::new` (job + restricted/low token + AppContainer API
    /// + experimental export), so capability and mechanics agree on what a
    /// spawn requires.
    #[cfg(target_os = "windows")]
    pub fn current(net_off: bool) -> Self {
        let caps = crate::sandbox::windows::probe();
        ProbeFacts {
            job_kill_on_close: caps.job_object_kill_on_close,
            restricted_token: caps.restricted_token,
            low_integrity_token: caps.low_integrity_token,
            appcontainer_api: caps.appcontainer_api,
            experimental_process_sandbox: caps.experimental_create_process_in_sandbox,
            experimental_as_user: caps.experimental_create_process_as_user_in_sandbox,
            net_off,
        }
    }

    fn critical_ready(&self) -> bool {
        self.job_kill_on_close
            && self.restricted_token
            && self.low_integrity_token
            && self.appcontainer_api
            && self.experimental_process_sandbox
    }
}

/// Pure capability mapping: facts in, per-capability states plus the
/// preparation flag out. No I/O, no platform branches: identical facts yield
/// identical states on every OS, so this is unit-testable anywhere.
///
/// - Not critical-ready: every capability `Failed` (`PlatformUnavailable`)
///   and `preparation_ok == false` — the production boundary then refuses to
///   spawn, matching the mechanics fail-closed gate.
/// - Ready: containment is at most `Configured`; `HostEvidence` is
///   `Enforced` (retained-handle wait/kill observation needs no child
///   setup, same as Linux/Direct). Network is `Configured` only for
///   net-off (the compiled spec carries an empty default-deny network
///   policy); any other net mode stays `Unsupported` (the mechanics layer
///   additionally refuses to spawn there).
#[allow(clippy::type_complexity)]
pub fn states_for_facts(
    facts: &ProbeFacts,
) -> (
    BTreeMap<SecurityCapability, EnforcementState>,
    BTreeMap<SecurityCapability, PreparationFailureKind>,
    bool,
) {
    if !facts.critical_ready() {
        let states: BTreeMap<SecurityCapability, EnforcementState> = SecurityCapability::all()
            .into_iter()
            .map(|c| (c, EnforcementState::Failed))
            .collect();
        let failures: BTreeMap<SecurityCapability, PreparationFailureKind> =
            SecurityCapability::all()
                .into_iter()
                .map(|c| (c, PreparationFailureKind::PlatformUnavailable))
                .collect();
        return (states, failures, false);
    }
    let mut states = BTreeMap::new();
    states.insert(
        SecurityCapability::FilesystemIsolation,
        EnforcementState::Configured,
    );
    states.insert(
        SecurityCapability::ExecutionRootIsolation,
        EnforcementState::Unsupported,
    );
    states.insert(
        SecurityCapability::NetworkIsolation,
        if facts.net_off {
            EnforcementState::Configured
        } else {
            EnforcementState::Unsupported
        },
    );
    states.insert(
        SecurityCapability::ProcessIsolation,
        EnforcementState::Configured,
    );
    states.insert(
        SecurityCapability::ProcessTreeContainment,
        EnforcementState::Configured,
    );
    states.insert(
        SecurityCapability::ResourceLimits,
        EnforcementState::Configured,
    );
    states.insert(
        SecurityCapability::SyscallRestriction,
        EnforcementState::Unsupported,
    );
    states.insert(SecurityCapability::HostEvidence, EnforcementState::Enforced);
    (states, BTreeMap::new(), true)
}

// ---------------------------------------------------------------------------
// Windows-only host observation (retained parent handles, never child I/O)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
type RawHandle = *mut std::ffi::c_void;
#[cfg(target_os = "windows")]
type Dword = u32;
#[cfg(target_os = "windows")]
type Bool = i32;

#[cfg(target_os = "windows")]
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: Dword = 9;
#[cfg(target_os = "windows")]
const JOB_OBJECT_BASIC_PROCESS_ID_LIST: Dword = 3;
#[cfg(target_os = "windows")]
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Dword = 0x0000_2000;
#[cfg(target_os = "windows")]
const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: Dword = 0x0000_0008;
#[cfg(target_os = "windows")]
const JOB_OBJECT_LIMIT_JOB_MEMORY: Dword = 0x0000_0200;
#[cfg(target_os = "windows")]
const PROCESS_QUERY_LIMITED_INFORMATION: Dword = 0x1000;
#[cfg(target_os = "windows")]
const STILL_ACTIVE: Dword = 259;
#[cfg(target_os = "windows")]
const ERROR_INVALID_PARAMETER: Dword = 87;
#[cfg(target_os = "windows")]
const ERROR_MORE_DATA: Dword = 234;
#[cfg(target_os = "windows")]
const TOKEN_QUERY: Dword = 0x0008;
#[cfg(target_os = "windows")]
const TOKEN_INTEGRITY_LEVEL: Dword = 25;
#[cfg(target_os = "windows")]
const SECURITY_MANDATORY_LOW_RID: u32 = 0x1000;
/// Offset of `limit_flags` inside `JOBOBJECT_BASIC_LIMIT_INFORMATION`
/// (two 8-byte `LARGE_INTEGER` time limits precede the `DWORD` flags).
#[cfg(target_os = "windows")]
const LIMIT_FLAGS_OFFSET: usize = 16;

/// Mandatory-label view for reading (SID pointer first, both widths).
#[cfg(target_os = "windows")]
#[repr(C)]
struct TokenMandatoryLabelRead {
    sid: *mut std::ffi::c_void,
    attributes: Dword,
}

#[cfg(target_os = "windows")]
#[allow(non_snake_case)]
#[link(name = "kernel32")]
extern "system" {
    fn IsProcessInJob(process: RawHandle, job: RawHandle, result: *mut Bool) -> Bool;
    fn QueryInformationJobObject(
        job: RawHandle,
        information_class: Dword,
        information: *mut std::ffi::c_void,
        information_length: Dword,
        return_length: *mut Dword,
    ) -> Bool;
    fn OpenProcess(desired_access: Dword, inherit_handle: Bool, process_id: Dword) -> RawHandle;
    fn GetExitCodeProcess(process: RawHandle, exit_code: *mut Dword) -> Bool;
    fn CloseHandle(handle: RawHandle) -> Bool;
    fn GetLastError() -> Dword;
}

#[cfg(target_os = "windows")]
#[allow(non_snake_case)]
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: RawHandle, desired_access: Dword, token: *mut RawHandle) -> Bool;
    fn GetTokenInformation(
        token: RawHandle,
        information_class: Dword,
        information: *mut std::ffi::c_void,
        information_length: Dword,
        return_length: *mut Dword,
    ) -> Bool;
    fn GetSidSubAuthorityCount(sid: *mut std::ffi::c_void) -> *mut u8;
    fn GetSidSubAuthority(sid: *mut std::ffi::c_void, index: Dword) -> *mut u32;
}

/// Host-observed verification of a live production child.
///
/// Every flag the host could not observe stays false (short-lived children
/// may exit first: their caps honestly stay `Configured`). Reads the
/// retained process/job handles only — never child stdio, exit codes, or
/// files the child could influence.
///
/// # Safety
///
/// Both handles must be live Win32 handles owned by the caller.
#[cfg(target_os = "windows")]
pub unsafe fn verify_production_child(process: RawHandle, job: RawHandle) -> HostVerification {
    let mut out = HostVerification::none();
    if process.is_null() || job.is_null() {
        return out;
    }
    // SAFETY: caller guarantees live handles; output points to locals.
    let mut in_job: Bool = 0;
    if unsafe { IsProcessInJob(process, job, &mut in_job) } != 0 && in_job != 0 {
        out.win_in_job = true;
    }
    let flags = unsafe { job_limit_flags(job) };
    if flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0 {
        out.win_kill_on_close = true;
    }
    if flags & (JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS) != 0 {
        out.win_job_ceiling = true;
    }
    if unsafe { child_runs_low_integrity(process) } {
        out.win_low_integrity = true;
    }
    out
}

/// Read `limit_flags` from the job's extended-limit information.
/// Returns 0 when the query fails (flags stay unobserved, never assumed).
///
/// # Safety
///
/// `job` must be a live Job Object handle owned by the caller.
#[cfg(target_os = "windows")]
unsafe fn job_limit_flags(job: RawHandle) -> Dword {
    let mut buffer = [0u8; 256];
    // SAFETY: buffer is a live 256-byte local; length matches.
    let ok = unsafe {
        QueryInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            buffer.as_mut_ptr().cast(),
            buffer.len() as Dword,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return 0;
    }
    Dword::from_ne_bytes([
        buffer[LIMIT_FLAGS_OFFSET],
        buffer[LIMIT_FLAGS_OFFSET + 1],
        buffer[LIMIT_FLAGS_OFFSET + 2],
        buffer[LIMIT_FLAGS_OFFSET + 3],
    ])
}

/// True only when the child's token integrity RID is low or below, read
/// from the retained process handle. Any failure (no query rights, dead
/// child) yields false: unobserved, never assumed.
///
/// # Safety
///
/// `process` must be a live process handle owned by the caller.
#[cfg(target_os = "windows")]
unsafe fn child_runs_low_integrity(process: RawHandle) -> bool {
    let mut token: RawHandle = std::ptr::null_mut();
    // SAFETY: process is a live handle per the caller contract.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
        return false;
    }
    let holds_low = integrity_rid(token).is_some_and(|rid| rid <= SECURITY_MANDATORY_LOW_RID);
    // SAFETY: token came from the successful OpenProcessToken above.
    unsafe { CloseHandle(token) };
    holds_low
}

/// Read the integrity RID (last SID sub-authority) of a token, or `None`
/// when unreadable.
///
/// # Safety
///
/// `token` must be a live token handle with `TOKEN_QUERY` access.
#[cfg(target_os = "windows")]
unsafe fn integrity_rid(token: RawHandle) -> Option<u32> {
    let mut needed: Dword = 0;
    // SAFETY: null buffer with zero length is the documented size query.
    unsafe {
        GetTokenInformation(
            token,
            TOKEN_INTEGRITY_LEVEL,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed == 0 || needed > 1024 {
        return None;
    }
    let mut buffer = vec![0u8; needed as usize];
    let mut returned: Dword = 0;
    // SAFETY: buffer is live for `needed` bytes per the size query.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TOKEN_INTEGRITY_LEVEL,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut returned,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: successful query filled a TOKEN_MANDATORY_LABEL whose SID
    // pointer is valid for this read.
    unsafe {
        let label = buffer.as_ptr().cast::<TokenMandatoryLabelRead>();
        let sid = (*label).sid;
        if sid.is_null() {
            return None;
        }
        let count_ptr = GetSidSubAuthorityCount(sid);
        if count_ptr.is_null() || *count_ptr == 0 {
            return None;
        }
        let last = (*count_ptr as Dword).saturating_sub(1);
        let rid_ptr = GetSidSubAuthority(sid, last);
        if rid_ptr.is_null() {
            return None;
        }
        Some(*rid_ptr)
    }
}

/// PIDs currently assigned to the job (host-observed tree membership).
/// Empty on any query failure: absence of evidence, never evidence of
/// absence (the caller fails the tree claim closed on doubt).
///
/// # Safety
///
/// `job` must be a live Job Object handle owned by the caller.
#[cfg(target_os = "windows")]
pub unsafe fn job_assigned_pids(job: RawHandle) -> Vec<Dword> {
    // Header (2 DWORDs) plus room for 64 PIDs; grows on MORE_DATA.
    let mut capacity: usize = 64;
    for _ in 0..4 {
        let mut buffer = vec![0u32; 2 + capacity];
        let bytes = (buffer.len() * 4) as Dword;
        // SAFETY: buffer is live; length matches.
        let ok = unsafe {
            QueryInformationJobObject(
                job,
                JOB_OBJECT_BASIC_PROCESS_ID_LIST,
                buffer.as_mut_ptr().cast(),
                bytes,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            let count = buffer[1] as usize;
            if count > capacity {
                capacity = count + 16;
                continue;
            }
            return buffer.into_iter().skip(2).take(count).collect();
        }
        // SAFETY: no preconditions.
        if unsafe { GetLastError() } != ERROR_MORE_DATA {
            return Vec::new();
        }
        capacity *= 4;
    }
    Vec::new()
}

/// Subset of `pids` that still looks alive after polling until `budget`.
/// A PID counts as dead only when the OS reports no such process
/// (`ERROR_INVALID_PARAMETER`) or a non-`STILL_ACTIVE` exit code; opening
/// failures for any other reason count as alive (fail-closed: doubt keeps
/// the tree claim from verifying).
#[cfg(target_os = "windows")]
pub fn pids_still_alive(pids: &[Dword], budget: Duration) -> Vec<Dword> {
    let deadline = Instant::now() + budget;
    let mut alive: Vec<Dword> = pids.to_vec();
    while !alive.is_empty() && Instant::now() < deadline {
        alive.retain(|&pid| pid_may_be_alive(pid));
        if !alive.is_empty() {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    alive
}

/// True unless the OS positively reports the PID gone.
#[cfg(target_os = "windows")]
fn pid_may_be_alive(pid: Dword) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: scalar OpenProcess on an arbitrary PID; the handle (if any)
    // is closed before returning.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        // SAFETY: no preconditions.
        return unsafe { GetLastError() } != ERROR_INVALID_PARAMETER;
    }
    let mut code: Dword = STILL_ACTIVE;
    // SAFETY: handle came from the successful OpenProcess above.
    let ok = unsafe { GetExitCodeProcess(handle, &mut code) };
    unsafe { CloseHandle(handle) };
    ok == 0 || code == STILL_ACTIVE
}

#[cfg(test)]
mod windows_enforce_tests {
    use super::*;

    fn full_facts(net_off: bool) -> ProbeFacts {
        ProbeFacts {
            job_kill_on_close: true,
            restricted_token: true,
            low_integrity_token: true,
            appcontainer_api: true,
            experimental_process_sandbox: true,
            experimental_as_user: true,
            net_off,
        }
    }

    /// TEST-WIN-MAP-001: a machine without the sandbox stack fails closed.
    #[test]
    fn test_win_map_001_no_stack_fails_closed() {
        let (states, failures, ok) = states_for_facts(&ProbeFacts::none());
        assert!(!ok, "no probe evidence must not prepare");
        for cap in SecurityCapability::all() {
            assert_eq!(states[&cap], EnforcementState::Failed);
            assert_eq!(failures[&cap], PreparationFailureKind::PlatformUnavailable);
        }
    }

    /// TEST-WIN-MAP-002: a missing experimental export fails closed even
    /// when Job Objects and tokens work (no ordinary-process fallback).
    #[test]
    fn test_win_map_002_missing_export_fails_closed() {
        let mut facts = full_facts(true);
        facts.experimental_process_sandbox = false;
        let (_, _, ok) = states_for_facts(&facts);
        assert!(!ok, "without the sandbox export there is no honest spawn");
        facts = full_facts(true);
        facts.appcontainer_api = false;
        let (_, _, ok) = states_for_facts(&facts);
        assert!(!ok);
        facts = full_facts(true);
        facts.job_kill_on_close = false;
        let (_, _, ok) = states_for_facts(&facts);
        assert!(!ok, "without kill-on-close there is no tree containment");
    }

    /// TEST-WIN-MAP-003: the ready mapping claims exactly the provable
    /// subset — never syscall filtering, never execution-root scoping.
    #[test]
    fn test_win_map_003_ready_subset_is_minimal() {
        let (states, failures, ok) = states_for_facts(&full_facts(true));
        assert!(ok);
        assert!(failures.is_empty());
        assert_eq!(
            states[&SecurityCapability::FilesystemIsolation],
            EnforcementState::Configured
        );
        assert_eq!(
            states[&SecurityCapability::NetworkIsolation],
            EnforcementState::Configured
        );
        assert_eq!(
            states[&SecurityCapability::ProcessIsolation],
            EnforcementState::Configured
        );
        assert_eq!(
            states[&SecurityCapability::ProcessTreeContainment],
            EnforcementState::Configured
        );
        assert_eq!(
            states[&SecurityCapability::ResourceLimits],
            EnforcementState::Configured
        );
        assert_eq!(
            states[&SecurityCapability::HostEvidence],
            EnforcementState::Enforced
        );
        assert_eq!(
            states[&SecurityCapability::SyscallRestriction],
            EnforcementState::Unsupported,
            "no syscall filter exists on this backend"
        );
        assert_eq!(
            states[&SecurityCapability::ExecutionRootIsolation],
            EnforcementState::Unsupported,
            "grant coverage of the cwd is invisible at this layer"
        );
    }

    /// TEST-WIN-MAP-004: non-off network modes are honestly unsupported
    /// (the mechanics layer additionally refuses to spawn there).
    #[test]
    fn test_win_map_004_non_off_network_unsupported() {
        let (states, _, ok) = states_for_facts(&full_facts(false));
        assert!(ok, "prepare still binds identity; only network degrades");
        assert_eq!(
            states[&SecurityCapability::NetworkIsolation],
            EnforcementState::Unsupported
        );
        assert_eq!(
            states[&SecurityCapability::FilesystemIsolation],
            EnforcementState::Configured
        );
    }

    /// TEST-WIN-MAP-005: the pure mapping is platform-independent —
    /// identical facts always yield identical states.
    #[test]
    fn test_win_map_005_mapping_is_deterministic() {
        let first = states_for_facts(&full_facts(true));
        let second = states_for_facts(&full_facts(true));
        assert_eq!(first.0, second.0);
        assert_eq!(first.2, second.2);
    }
}
