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

## What Vetto Does NOT Protect

Vetto enforces strict OS-level containment for untrusted agent subprocesses. However, security guarantees are bounded by the underlying kernel and host architecture. Vetto explicitly does NOT defend against the following four threat classes:

### 1. Prompt Injection Within Authorized Agent Tools & Allowed Network APIs
Vetto operates strictly at the OS kernel boundary (LSM, namespaces, and TCP transport brokers). It is **not** an application-level prompt firewall or an LLM guardrail:
- Vetto does **not** inspect, filter, or semantically validate payload contents exchanged over TLS with allowlisted endpoints (e.g., Anthropic, OpenAI, or GitHub APIs).
- If an agent is coerced via prompt injection into transmitting project source code to an allowed external API or executing authorized tool commands (e.g., committing code to a permitted Git branch), Vetto treats these operations as legitimate within the defined policy.
- Defenses against semantic manipulation, prompt poisoning, and model-level hallucinations must be implemented at the orchestration or application layer.

### 2. Legitimate Writes to Explicitly Allowed Project Paths
To allow coding agents to perform their core duties, the designated project directory (`$PROJECT`) and `/tmp` are explicitly granted read-write access in the Landlock/Seatbelt policy:
- Vetto prevents modifications to files outside `$PROJECT` and shields masked paths (such as `$PROJECT/.env*`).
- Vetto does **not** monitor or prevent destructive, buggy, or malicious file edits, code deletions, or subtle backdoor insertions within the allowed project directory.
- Developers must rely on version control (Git branches, staged commits, pre-merge reviews) and workspace backups to verify and safeguard project code integrity.

### 3. Microarchitectural and Timing Side-Channels
Vetto utilizes operating system isolation primitives (namespaces, Landlock LSM, and seccomp-bpf), not hardware virtualization boundaries:
- Untrusted agent processes share physical CPU cores, cache hierarchies (L1/L2/L3), TLBs, and branch predictors with host processes.
- Vetto does **not** defend against hardware speculative execution attacks (e.g., Spectre, Meltdown, MDS) or cache-timing side-channels (e.g., Flush+Reload, Prime+Probe), particularly under SMT/Hyper-Threading.
- Workloads requiring complete side-channel immunity must be isolated via hardware hypervisors (microVMs), dedicated CPU affinity pinning, or disabled SMT.

### 4. Compromised Host Kernel or Root-Level Operator Compromise
Vetto executes entirely as an unprivileged user-space process and relies fundamentally on the integrity and correctness of the host operating system kernel:
- Vetto does **not** defend against host kernel vulnerabilities (e.g., kernel privilege escalation CVEs, unpatched LSM bugs, or memory corruption flaws).
- Vetto does **not** protect against a compromised root/administrator account or another host process executing under the same user ID outside the sandbox.
- Vetto does not implement hardware-rooted cryptographic attestation or secure enclave execution. If the host environment is compromised, all sandbox guarantees fail.
- Operator non-defense: No attempt is made to constrain the operator (they can inspect or terminate everything). No anti-debugging is imposed on the agent. No coverage exists for the moment before Vetto starts or after it exits.

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
