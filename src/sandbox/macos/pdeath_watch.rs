//! Parent-death watchdog for the macOS backend.
//!
//! Linux has `PR_SET_PDEATHSIG`; macOS has nothing equivalent, so vetto's
//! PARENT forks a tiny unsandboxed helper right after the agent child exists.
//! The helper watches vetto's pid with a kqueue `EVFILT_PROC`/`NOTE_EXIT`
//! registration and SIGKILLs the agent if vetto dies. Without it, a SIGKILLed
//! vetto leaves a running (sandboxed, but unmanaged) agent behind.
//!
//! The helper MUST be forked from the parent, not from the agent child: a
//! second fork inside the child poisons libSystem's fork-safety state, and
//! the CoreFoundation/ObjC calls inside `sandbox_init_with_parameters` then
//! abort the agent with a silent SIGABRT before it ever execs. The parent
//! never execs and has no threads at that point, so its fork is safe.
//!
//! The helper immediately detaches from stdio (and closes every inherited
//! descriptor) and from the agent's process group, and self-exits when the
//! agent exits. A 1-second kevent timeout doubles as a poll:
//! `kill(vetto_pid, 0)` catches exits that were missed before the
//! registration landed.
//!
//! Best-effort by design: if the fork or kqueue setup fails, the session
//! continues without the watchdog (the Linux-level guarantees do not apply
//! here anyway); failures are reported on vetto's stderr.

/// Fork the watchdog helper. Called in the agent process after fork, before
/// `apply_seatbelt`, so the helper itself is never sandboxed.
///
/// `vetto_pid` is the process to watch (normally `getppid()` from the caller),
/// `agent_pid` is the process to kill (normally `getpid()` pre-exec).
pub fn spawn(vetto_pid: libc::pid_t, agent_pid: libc::pid_t) {
    // Diagnostic kill-switch: isolates the watchdog when bisecting a failure.
    if std::env::var_os("VETTO_NO_PDEATH_WATCH").is_some() {
        return;
    }
    if vetto_pid <= 0 || agent_pid <= 0 || vetto_pid == agent_pid {
        return;
    }
    // SAFETY: fork before any thread exists in this child; the helper side
    // only touches libc (kqueue/kevent/kill/close/_exit).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!(
            "vetto: warning: parent-death watchdog fork failed: {}",
            std::io::Error::last_os_error()
        );
        return;
    }
    if pid == 0 {
        // SAFETY: helper never returns.
        unsafe { run_watch(vetto_pid, agent_pid) }
    }
    // The agent process does not wait on the helper; it self-exits.
}

/// Helper body. Never returns.
///
/// SAFETY (caller): only async-signal-safe libc calls after the fork; no
/// allocator use, no Rust runtime services beyond the static eprintln paths
/// that were already exercised before the fork.
unsafe fn run_watch(vetto_pid: libc::pid_t, agent_pid: libc::pid_t) -> ! {
    detach_from_session_stdio();

    let kq = libc::kqueue();
    if kq < 0 {
        poll_loop(vetto_pid, agent_pid);
    }

    // Register NOTE_EXIT for both processes. EV_RECEIPT makes the first
    // kevent() call return one event per change without consuming real
    // notifications.
    let changes = [
        libc::kevent {
            ident: vetto_pid as usize,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_RECEIPT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        },
        libc::kevent {
            ident: agent_pid as usize,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_RECEIPT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        },
    ];
    let mut receipts = [libc::kevent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }; 2];
    let n = libc::kevent(
        kq,
        changes.as_ptr(),
        2,
        receipts.as_mut_ptr(),
        2,
        std::ptr::null(),
    );
    // A registration error (e.g. permission) is not recoverable here; fall
    // back to the plain poll loop, which needs no kqueue.
    if n < 0 {
        libc::close(kq);
        poll_loop(vetto_pid, agent_pid);
    }

    loop {
        let mut events = [receipts[0]; 8];
        let timeout = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        let n = libc::kevent(
            kq,
            std::ptr::null(),
            0,
            events.as_mut_ptr(),
            8,
            &timeout,
        );
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            libc::close(kq);
            poll_loop(vetto_pid, agent_pid);
        }
        for event in &events[..n.max(0) as usize] {
            if event.ident == vetto_pid as usize && event.filter == libc::EVFILT_PROC {
                // vetto died: the agent must not outlive it.
                libc::kill(agent_pid, libc::SIGKILL);
                libc::close(kq);
                libc::_exit(0);
            }
            if event.ident == agent_pid as usize && event.filter == libc::EVFILT_PROC {
                // Agent exited on its own: nothing left to guard.
                libc::close(kq);
                libc::_exit(0);
            }
        }
        // Timed out: the registration can miss an exit that happened before
        // it landed, so re-check liveness once per second.
        if libc::kill(vetto_pid, 0) == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            libc::kill(agent_pid, libc::SIGKILL);
            libc::close(kq);
            libc::_exit(0);
        }
        if libc::kill(agent_pid, 0) == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            libc::close(kq);
            libc::_exit(0);
        }
    }
}

/// Fallback watchdog without kqueue: poll liveness twice per second.
unsafe fn poll_loop(vetto_pid: libc::pid_t, agent_pid: libc::pid_t) -> ! {
    loop {
        libc::usleep(500_000);
        if libc::kill(vetto_pid, 0) == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            libc::kill(agent_pid, libc::SIGKILL);
            libc::_exit(0);
        }
        if libc::kill(agent_pid, 0) == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            libc::_exit(0);
        }
    }
}

/// Helper must hold neither stdio (would break parent EOF semantics) nor the
/// agent's process group (would die with the group it guards).
unsafe fn detach_from_session_stdio() {
    let _ = libc::setsid();
    let devnull = b"/dev/null\0";
    let fd = libc::open(devnull.as_ptr().cast(), libc::O_RDWR);
    if fd >= 0 {
        for target in 0..=2 {
            if target != fd {
                libc::dup2(fd, target);
            }
        }
        if fd > 2 {
            libc::close(fd);
        }
    }
    // Forked from vetto's parent context: drop EVERY inherited descriptor
    // (sandbox setup pipes, pty ends, stdio pipes) so the helper can never
    // hold an end open past the agent's exit and break EOF/drain semantics.
    // SAFETY: sysconf is scalar-only; EBADF on closed slots is ignored.
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) } as i32;
    let max = max.clamp(16, 65_536);
    for candidate in 3..max {
        unsafe { libc::close(candidate) };
    }
}
