# Threat model

## Assets
- Developer secrets: `~/.ssh`, `~/.aws`, `~/.gnupg`, credential files,
  project `.env`, `*.pem/*.key/*.p12/*.kdbx`.
- Source and machine integrity: anything outside `$PROJECT` (system config,
  other projects, shell profiles).
- Data confidentiality: network exfiltration of the above.
- Availability: the developer's machine staying free of runaway processes.

## Adversary
A **locally-invoked AI coding agent** and everything it executes: prompt-
injected instructions, malicious dependencies pulled during the session,
compromised tools, or plain buggy automation. Capability assumption: full
arbitrary code execution as the invoking user, including shell escapes,
background daemons, and attempts to read/replace its own supervisor inputs.

Non-goals: a hostile kernel, root compromise, other users on the machine,
physical access, or a malicious vetto binary itself.

## Enforcement layers (Linux)

| Layer | Defends | Bypass resistance |
|---|---|---|
| Landlock allowlist | reads/writes/exec outside policy; symlink/TOCTOU tricks | kernel VFS decision on resolved inode; unprivileged; irreversible per session |
| Mount overlays | `cat .env`, `ls ~/.ssh` inside otherwise-allowed trees | hidden behind mode-000 tmpfs / `/dev/null` binds in a private mount ns |
| NET namespace | any sockets incl. DNS (off mode) | no interfaces ⇒ no route; loopback-only in allowlist mode |
| PID namespace | orphan/zombie persistence after vetto dies | kernel kills the ns when its init dies |
| seccomp netblock (FS-ONLY) | socket(AF_INET/6) without userns | coarse but kernel-level |
| IPC namespace | shared-memory side channels | isolation |

Known residual risks are enumerated in SECURITY.md (FS-ONLY `setsid`
orphans; late-created secret-shaped files in the writable project root;
allowlist limited to proxy-shaped protocols).

## Deliberate non-defenses
- No attempt to constrain the *operator* (they can read everything anyway).
- No anti-debugging of the agent (the agent may inspect itself freely; it
  still cannot escape the kernel rules).
- No coverage for the moment *before* vetto starts or after it exits.

## Why observation never feeds enforcement
Every visibility channel (poller, seccomp tap, audit reader) is explicitly
downgraded: events are advisory, racy, and best-effort. Enforcement state is
computed once at spawn from the policy and applied in the kernel. This
separation is what makes racy observation *acceptable* — a tampered or
missed event changes nothing about what the sandbox allows.

## Process and kernel-interface attacks

The untrusted command may run arbitrary native code, not just the documented
agent executable. It can therefore attempt cross-process reads, namespace
changes, asynchronous I/O paths and privileged kernel control operations by
issuing raw syscalls directly.

| Interface | Threat | Default decision | Compatibility cost |
|---|---|---|---|
| `ptrace`, `process_vm_readv/writev`, `pidfd_getfd` | inspect or copy another process's memory/descriptors | reject with `EPERM` | debuggers cannot attach inside a vetto session |
| mount API, `pivot_root`, `umount2` | remove secret overlays or replace the filesystem view | reject with `EPERM` | nested container/mount tools cannot run |
| `io_uring_*` | historical gaps between asynchronous operations and security hooks | reject with `EPERM` | programs must use ordinary synchronous/epoll I/O |
| `userfaultfd` | kernel-exploit primitive and cross-thread memory manipulation | reject with `EPERM` | user-space paging runtimes cannot run |
| `bpf`, `perf_event_open` | kernel attack surface and observation of processes outside the intended task | reject with `EPERM` | eBPF loaders and hardware profilers cannot run |
| module/kexec/reboot/swap syscalls | kernel replacement, code loading, or host disruption on an unexpectedly permissive kernel/user namespace | reject with `EPERM` | kernel administration is intentionally impossible |

Blocking `bpf` and `perf_event_open` is deliberate rather than a claim that
every invocation is malicious. Typical compilers, package managers and test
runners do not require them. Workloads whose purpose is kernel tracing or
profiling are outside the sandbox's supported workload set; vetto does not
silently weaken the boundary for those tools.

The filter is installed after vetto finishes its own namespace/mount setup and
immediately before `execve`, then inherited irreversibly by descendants. Tests
exercise the native syscall ABI rather than command wrappers. Architecture
numbers come from `libc::SYS_*`, so x86-64 constants are never reused on ARM64.
