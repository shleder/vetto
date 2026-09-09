//! Real Linux enforcement for the verify-ng harness (Stage 3B).
//!
//! The [`SandboxBackend`](super::sandbox_backend::SandboxBackend) boundary
//! only *reports* enforcement; this module *installs* it. The runner applies
//! [`apply_child_plan`] in the forked child before `exec` (via
//! `Command::pre_exec`), so there is exactly one authoritative spawn path:
//! a backend cannot claim `Enforced` for a child that bypassed setup.
//!
//! Mechanisms (all unprivileged, all already used by the production
//! FS-ONLY/seccomp tiers):
//!
//! - Filesystem + execution-root isolation: Landlock allowlist
//!   (`exec_root` read/write, system roots read-only, host control dir
//!   read/write, everything else denied by default).
//! - Network isolation (`--net=off`): seccomp-BPF `UnixOnly` socket policy
//!   (non-`AF_UNIX` `socket`/`socketpair` fail with `EAFNOSUPPORT`).
//! - Syscall restriction: the same seccomp filter's hardening denylist
//!   (`mount`, `ptrace`, `io_uring_*`, `userfaultfd`, `bpf`, ... deny with
//!   `EPERM`). Verified host-side via `/proc/<pid>/status` (`Seccomp: 2`).
//! - Privilege boundary: `PR_SET_NO_NEW_PRIVS` (+ Landlock, which sets it
//!   too). Verified host-side via `NoNewPrivs: 1`.
//! - Process isolation: new process group in the child (`setpgid`), so the
//!   killer can signal the whole tree with `kill(-pgid)`.
//! - Process-tree containment: group kill plus a nonce-targeted sub-reaper
//!   sweep ([`sweep_tree_by_nonce`]). Only processes whose inherited
//!   environment carries this run's session nonce are touched, so parallel
//!   test runs can never cross-kill each other.
//! - Resource limits: `setrlimit` ceilings (`RLIMIT_AS`, `RLIMIT_NPROC`,
//!   `RLIMIT_CPU`, `RLIMIT_FSIZE`) lowered before `exec`; inherited
//!   ceilings can only be lowered, never raised, by the child. Verified
//!   host-side via `/proc/<pid>/limits`.
//!
//! Honesty rules: every probe degrades to `Unsupported`/unverified instead
//! of a fake claim. Filesystem/network isolation have no per-process kernel
//! indicator, so they stay at `Enforced` (installed without error, effect
//! proven behaviorally by the adversarial tests); only host-observed state
//! promotes to `Verified`.

/// System roots the confined child may read (interpreter, loader, configs,
/// devices). Everything else — host home, `/tmp` siblings (including the
/// dedicated denied canary dirs), `/root`, `/opt`, `/srv`, `/mnt` — is
/// denied by Landlock default-deny.
///
/// NOTE: `/tmp` and `/dev/null` stay DENIED. The dynamic loader, shell and
/// Python must therefore run without them: shell payloads redirect into
/// `$VETTO_VNG_ROOT` files, and no payload may rely on `/dev/null`,
/// `/dev/zero` or `/tmp` scratch space.
#[cfg(target_os = "linux")]
pub const SYSTEM_ROOTS: &[&str] = &[
    "/bin", "/sbin", "/lib", "/lib64", "/usr", "/etc", "/dev", "/proc",
];

/// Default ceilings applied to every Linux-backend run (lowered via
/// `setrlimit` before `exec`; the child cannot raise them afterwards).
/// Generous for shell payloads, tight enough to catch abuse:
/// - address space 256 MiB (MEM test allocates past it),
/// - max user processes 128 (PID test forks past it),
/// - CPU time 5 s (CPU test busy-loops past it; normal payloads use ~0),
/// - max file size 64 MiB.
pub const DEFAULT_RLIMIT_AS_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_RLIMIT_NPROC: u64 = 128;
pub const DEFAULT_RLIMIT_CPU_SECS: u64 = 5;
pub const DEFAULT_RLIMIT_FSIZE_BYTES: u64 = 64 * 1024 * 1024;

/// Budget for one nonce-targeted tree sweep.
pub const SWEEP_BUDGET_MS: u64 = 2_000;

/// Apply the enforcement plan in the forked child before `exec`.
///
/// All-or-nothing: any enabled step that fails aborts the spawn (the
/// `pre_exec` error fails `Command::spawn` in the parent), so a child can
/// never run partially confined while the backend claims enforcement.
/// Linux-only; the non-Linux stub always errors (a plan must never exist
/// there — `prepare` reports `Unsupported` instead).
pub fn apply_child_plan(
    plan: &super::sandbox_backend::ChildEnforcementPlan,
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        apply_child_plan_linux(plan)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = plan;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "linux enforcement plan requires Linux",
        ))
    }
}

/// Host-side verification of a live confined child, read from `/proc`
/// without trusting any child output. Best-effort with a bounded wait:
/// short-lived children may exit before every field is observed, in which
/// case the corresponding flags stay false (caps remain `Enforced`, never
/// promoted to `Verified`).
pub fn verify_child_host(pid: u32) -> super::sandbox_backend::HostVerification {
    #[cfg(target_os = "linux")]
    {
        verify_child_host_linux(pid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        super::sandbox_backend::HostVerification::none()
    }
}

/// Outcome of one nonce-targeted tree sweep, with diagnostics for the
/// run detail string (never a verdict input by itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepOutcome {
    /// True when no process carrying this run's session nonce survives.
    pub clean: bool,
    /// Total SIGKILLs delivered across all passes.
    pub killed: usize,
    /// Nonce-matching pids still present at the deadline (empty when clean).
    pub residual: Vec<i32>,
    /// Whether our sub-reaper flag was observed (blind without it).
    pub subreaper: bool,
}

/// Sweep this run's residual processes after the root was reaped.
///
/// Returns `None` off Linux. Only nonce-matching processes are signalled,
/// so parallel runs are never disturbed. `clean == false` covers both
/// surviving residuals and a blind sweep (no sub-reaper — orphans would
/// reparent to init instead of us): both fail the tree claim closed.
pub fn sweep_tree_by_nonce(nonce: &str, root_pid: u32) -> Option<SweepOutcome> {
    #[cfg(target_os = "linux")]
    {
        Some(sweep_tree_by_nonce_linux(nonce, root_pid))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (nonce, root_pid);
        None
    }
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

/// Install every enabled mechanism. Errors abort the spawn (fail-closed).
#[cfg(target_os = "linux")]
fn apply_child_plan_linux(
    plan: &super::sandbox_backend::ChildEnforcementPlan,
) -> std::io::Result<()> {
    // New process group first: the host kills the tree via kill(-pgid).
    if plan.new_pgroup {
        // SAFETY: setpgid(0,0) in the freshly forked child.
        if unsafe { libc::setpgid(0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Resource ceilings (lowering only; the child cannot raise them back).
    set_rlimit_if_some(libc::RLIMIT_AS, plan.rlimit_as)?;
    set_rlimit_if_some(libc::RLIMIT_NPROC, plan.rlimit_nproc)?;
    set_rlimit_if_some(libc::RLIMIT_CPU, plan.rlimit_cpu)?;
    set_rlimit_if_some(libc::RLIMIT_FSIZE, plan.rlimit_fsize)?;

    // Filesystem isolation via Landlock (also sets NO_NEW_PRIVS itself).
    if plan.landlock {
        let mut write_roots = vec![plan.exec_root.clone()];
        write_roots.extend(plan.extra_rw.iter().cloned());
        let read_roots: Vec<std::path::PathBuf> = plan
            .system_ro
            .iter()
            .map(std::path::PathBuf::from)
            .collect();
        crate::sandbox::linux::landlock::apply_policy(&write_roots, &read_roots, false)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
    } else {
        // SAFETY: scalar-only prctl; required before any seccomp filter.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Seccomp: network socket policy plus the hardening denylist.
    // `AgentMin` additionally denies `chroot(2)` (absent from the Default
    // denylist); the syscall-escape tests require it, so install AgentMin.
    if plan.harden_syscalls {
        let socket_policy = if plan.net_deny {
            crate::sandbox::linux::seccomp_netblock::SocketPolicy::UnixOnly
        } else {
            crate::sandbox::linux::seccomp_netblock::SocketPolicy::UnixAndIp
        };
        crate::sandbox::linux::seccomp_netblock::install_for_profile(
            socket_policy,
            crate::policy::SeccompProfile::AgentMin,
        )
        .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
    }
    Ok(())
}

/// Lower one rlimit (soft and hard together) when configured.
#[cfg(target_os = "linux")]
fn set_rlimit_if_some(
    resource: libc::__rlimit_resource_t,
    value: Option<u64>,
) -> std::io::Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY: fixed resource constant + valid local rlimit struct.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Read `/proc/<pid>/status` + `/proc/<pid>/limits` + own pgid/sub-reaper
/// state with a bounded wait while the child is alive.
#[cfg(target_os = "linux")]
fn verify_child_host_linux(pid: u32) -> super::sandbox_backend::HostVerification {
    use super::sandbox_backend::HostVerification;
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut out = HostVerification::none();
    loop {
        let status = read_proc_file(pid, "status");
        if let Some(body) = status.as_deref() {
            if proc_field_is(body, "Seccomp:", "2") {
                out.seccomp_filter = true;
            }
            if proc_field_is(body, "NoNewPrivs:", "1") {
                out.no_new_privs = true;
            }
        }
        // SAFETY: scalar getpgid on the (possibly reaped) child pid.
        let pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
        if pgid == pid as libc::pid_t {
            out.pgroup_separate = true;
        }
        if let Some(limits) = read_proc_file(pid, "limits").as_deref() {
            if limits_field_is(limits, "Max address space", DEFAULT_RLIMIT_AS_BYTES) {
                out.rlimit_as_ok = true;
            }
            if limits_field_is(limits, "Max processes", DEFAULT_RLIMIT_NPROC) {
                out.rlimit_nproc_ok = true;
            }
            if limits_field_is(limits, "Max cpu time", DEFAULT_RLIMIT_CPU_SECS) {
                out.rlimit_cpu_ok = true;
            }
            if limits_field_is(limits, "Max file size", DEFAULT_RLIMIT_FSIZE_BYTES) {
                out.rlimit_fsize_ok = true;
            }
        }
        // SAFETY: scalar prctl query on our own process.
        out.subreaper_ok = unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, 0, 0, 0, 0) } == 1;
        if out.all_observed() || Instant::now() >= deadline || !pid_alive(pid) {
            return out;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Nonce-targeted orphan sweep (see [`sweep_tree_by_nonce`]).
#[cfg(target_os = "linux")]
fn sweep_tree_by_nonce_linux(nonce: &str, root_pid: u32) -> SweepOutcome {
    use std::time::{Duration, Instant};
    // SAFETY: scalar prctl query on our own process.
    let subreaper = unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, 0, 0, 0, 0) } == 1;
    let mut outcome = SweepOutcome {
        clean: false,
        killed: 0,
        residual: Vec::new(),
        subreaper,
    };
    // Without our sub-reaper flag, escapers reparent to init and this scan
    // is blind — report not-clean (fail-closed) instead of a false clean.
    if !subreaper {
        return outcome;
    }
    // SAFETY: scalar getpid.
    let me = unsafe { libc::getpid() } as u32;
    let needle = nonce.as_bytes();
    let deadline = Instant::now() + Duration::from_millis(SWEEP_BUDGET_MS);
    loop {
        let mut matched = Vec::new();
        let mut blind = false;
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let Ok(name) = entry.file_name().into_string() else {
                    continue;
                };
                let Ok(pid) = name.parse::<i32>() else {
                    continue;
                };
                if pid <= 0 || pid as u32 == root_pid || pid as u32 == me {
                    continue;
                }
                let status_path = format!("/proc/{pid}/status");
                let Ok(status) = std::fs::read_to_string(&status_path) else {
                    continue;
                };
                if crate::sandbox::linux::proctrack::ppid_from_status(&status) != Some(me) {
                    continue;
                }
                // Environ is unreadable for zombies (reaped below if
                // ours) or mid-exit races (ENOENT/ESRCH — the process is
                // going away): never blocking clean. Only a hard read
                // error on a live, un-reaped child (EACCES/hidepid) is
                // blindness (fail-closed).
                let env = match std::fs::read(format!("/proc/{pid}/environ")) {
                    Ok(env) => env,
                    Err(e)
                        if e.raw_os_error() == Some(libc::ENOENT)
                            || e.raw_os_error() == Some(libc::ESRCH) =>
                    {
                        continue;
                    }
                    Err(_) => {
                        if pid_is_zombie(&status) {
                            let mut st = 0i32;
                            // SAFETY: non-blocking waitpid on our own child.
                            unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
                            continue;
                        }
                        blind = true;
                        continue;
                    }
                };
                if contains_slice(&env, needle) {
                    matched.push(pid);
                }
            }
        }
        if blind {
            outcome.residual = last_nonce_pids(nonce, root_pid, me);
            return outcome;
        }
        if matched.is_empty() {
            if root_gone_or_zombie(root_pid, me) {
                outcome.clean = true;
                return outcome;
            }
        } else {
            for pid in matched {
                // SAFETY: SIGKILL to a direct child carrying our run nonce.
                if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
                    outcome.killed += 1;
                }
                let mut status = 0i32;
                // SAFETY: non-blocking waitpid on our own child.
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            }
        }
        if Instant::now() >= deadline {
            outcome.residual = last_nonce_pids(nonce, root_pid, me);
            return outcome;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Final best-effort listing of surviving nonce-matching pids for the
/// diagnostic string (no signalling here).
#[cfg(target_os = "linux")]
fn last_nonce_pids(nonce: &str, root_pid: u32, me: u32) -> Vec<i32> {
    let mut out = Vec::new();
    let needle = nonce.as_bytes();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let Ok(pid) = name.parse::<i32>() else {
                continue;
            };
            if pid <= 0 || pid as u32 == root_pid || pid as u32 == me {
                continue;
            }
            let Ok(env) = std::fs::read(format!("/proc/{pid}/environ")) else {
                continue;
            };
            if contains_slice(&env, needle) {
                out.push(pid);
            }
        }
    }
    out.sort_unstable();
    out.truncate(8);
    out
}

/// True when a `/proc/<pid>/status` body describes a zombie.
#[cfg(target_os = "linux")]
fn pid_is_zombie(status: &str) -> bool {
    for line in status.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("State:") {
            return rest.trim_start().starts_with('Z');
        }
    }
    false
}

/// True when the root can no longer produce new orphans: gone, reaped,
/// reparented away from us, or a zombie (the kernel already reparented its
/// children at termination).
#[cfg(target_os = "linux")]
fn root_gone_or_zombie(root_pid: u32, me: u32) -> bool {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{root_pid}/status")) else {
        return true;
    };
    if crate::sandbox::linux::proctrack::ppid_from_status(&status) != Some(me) {
        return true;
    }
    pid_is_zombie(&status)
}

/// True while `kill(pid, 0)` succeeds (process exists and we may signal it).
#[cfg(target_os = "linux")]
fn pid_alive(pid: u32) -> bool {
    // SAFETY: signal 0 performs no delivery; ESRCH means gone.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(target_os = "linux")]
fn read_proc_file(pid: u32, file: &str) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/{file}")).ok()
}

// ---------------------------------------------------------------------------
// Pure parsers (host-side string matching; unit-tested on every platform)
// ---------------------------------------------------------------------------

/// True when a `/proc/<pid>/status` field has exactly the expected value
/// (`"Seccomp:\t2"` style; any whitespace shape accepted).
pub fn proc_field_is(status_body: &str, field: &str, expected: &str) -> bool {
    for line in status_body.lines() {
        if let Some(rest) = line.trim_start().strip_prefix(field) {
            return rest.trim() == expected;
        }
    }
    false
}

/// True when a `/proc/<pid>/limits` row for `row` carries `expected` in
/// both the soft and hard columns. Rows look like
/// `Max cpu time   5   5   seconds` (units trailing) or `unlimited`.
pub fn limits_field_is(limits_body: &str, row: &str, expected: u64) -> bool {
    for line in limits_body.lines() {
        if let Some(idx) = line.find(row) {
            let after = line[idx + row.len()..].trim_start();
            let mut cols = after.split_whitespace();
            let soft = cols.next().unwrap_or("");
            let hard = cols.next().unwrap_or("");
            let want = expected.to_string();
            return soft == want && hard == want;
        }
    }
    false
}

/// Byte-substring search (haystack may be NUL-separated, e.g. `environ`).
pub fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod linux_enforce_tests {
    use super::*;

    #[test]
    fn proc_field_matches_status_shapes() {
        let body = "Name:\tsh\nState:\tS (sleeping)\nSeccomp:\t2\nNoNewPrivs:\t1\n";
        assert!(proc_field_is(body, "Seccomp:", "2"));
        assert!(proc_field_is(body, "NoNewPrivs:", "1"));
        assert!(!proc_field_is(body, "Seccomp:", "0"));
        assert!(!proc_field_is(body, "Missing:", "2"));
        assert!(!proc_field_is("", "Seccomp:", "2"));
    }

    #[test]
    fn limits_field_matches_both_columns() {
        let body = "Limit                     Soft Limit           Hard Limit           Units\n\
            Max cpu time              5                    5                    seconds\n\
            Max file size             67108864             67108864             bytes\n\
            Max processes             128                  128                  processes\n\
            Max address space         268435456            268435456            bytes\n\
            Max open files            1024                 1024                 files\n";
        assert!(limits_field_is(body, "Max cpu time", 5));
        assert!(limits_field_is(body, "Max file size", 67_108_864));
        assert!(limits_field_is(body, "Max processes", 128));
        assert!(limits_field_is(body, "Max address space", 268_435_456));
        assert!(!limits_field_is(body, "Max cpu time", 6));
        assert!(!limits_field_is(body, "Max open files", 512));
        assert!(!limits_field_is(body, "No such row", 0));
    }

    #[test]
    fn limits_field_rejects_unlimited_and_split() {
        let body = "Max cpu time              unlimited            unlimited            seconds\n\
            Max processes             128                  64                   processes\n";
        assert!(!limits_field_is(body, "Max cpu time", 5));
        assert!(!limits_field_is(body, "Max processes", 128));
    }

    #[test]
    fn contains_slice_finds_nonce_in_environ() {
        let env = b"PATH=/bin\x00VETTO_VNG_NONCE=abc123\x00HOME=/x\x00";
        assert!(contains_slice(env, b"abc123"));
        assert!(contains_slice(env, b"VETTO_VNG_NONCE"));
        assert!(!contains_slice(env, b"other"));
        assert!(!contains_slice(env, b""));
        assert!(!contains_slice(b"short", b"much-longer-needle"));
    }
}
