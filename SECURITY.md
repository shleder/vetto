# Security policy and limitations

vetto treats the locally invoked coding agent and every descendant process as
untrusted. It protects developer secrets, files outside the selected project,
network boundaries and process lifetime from malicious model output, prompt
injection, compromised dependencies and buggy automation. It does not defend
against a hostile kernel, root/administrator, physical access, another user
who can modify the operator's files, or a malicious vetto binary.

See [docs/threat-model.md](docs/threat-model.md) for the attack-by-attack
analysis.

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| `0.2.x` | ✅ Yes | Current active release branch |
| `< 0.2.0` | ❌ No | Early preview builds; please upgrade to `0.2.x` |

## Reporting a vulnerability and response SLA

- **Reporting Channel**: Use GitHub's private vulnerability-reporting flow (Security → Report a vulnerability) or consult [.well-known/security.txt](.well-known/security.txt).
- **Response SLA**:
  - **48 hours**: Initial acknowledgment of report receipt.
  - **7 days**: Triage, reproduction, and initial severity / CVSS assessment.
  - **30 days**: Coordinated disclosure window with patch release and CVE assignment.
- Detailed procedures and severity guidelines are documented in [docs/security/cve-process.md](docs/security/cve-process.md).

Include the vetto revision, OS/kernel, detected tier, policy, shortest safe
reproducer and whether the result is an enforcement bypass or only a missing
observation event. Never attach real credentials; replace them with test data.

## Enforcement and observation are different

Filesystem/network/process controls are the security boundary. Event feeds,
the TUI and reports are evidence gathered around that boundary and can miss
events. A missing “blocked” row never means the operation was allowed.

- Linux Landlock denials reach the kernel audit stream only on sufficiently
  new kernels (currently kernel 6.12 or newer), and an unprivileged process
  usually cannot read that stream without audit privileges. vetto probes it
  and normally reports it unavailable while enforcement remains active.
- `--observe-seccomp` is optional. Its default mode responds with
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE`; paths copied from another process are
  racy and are used only for display. `SECCOMP_IOCTL_NOTIF_ID_VALID` narrows
  the notification race but does not turn the path into an enforcement input.
- Any seccomp `ADDFD` substitution mode is separately opt-in and changes
  syscall behaviour. It is not described as observation-only and is never
  enabled by `--observe-seccomp` alone.
- Linux allowed-file visibility polls `/proc` adaptively. Short opens and
  short-lived processes can be missed.
- macOS FSEvents reports coarse directory changes after they occur. It does
  **not** report file reads, Seatbelt denials, or a complete per-process audit
  trail. FSEvents must never be presented as file-read visibility.

## Linux tiers

FULL requires Landlock and unprivileged user namespaces. It combines user,
mount, PID, network and IPC namespaces, Landlock, secret overlays and seccomp.
The PID-namespace init reaps and terminates descendants when vetto exits.

FS-ONLY is the fail-closed fallback when Landlock works but user namespaces do
not. It retains Landlock and inherited seccomp, but no mount/PID/network
namespace exists. Project enumeration errors and the safety budget return an
error; there is no broad read fallback. Lifecycle cleanup uses
`PR_SET_PDEATHSIG` plus a process group. A grandchild that deliberately calls
`setsid()` can escape cleanup in this tier, although it still inherits
Landlock and seccomp restrictions.

If neither tier can establish its advertised controls, the command does not
run.

## Filesystem and secret overlays

Landlock is an allowlist evaluated on the resolved inode. It cannot subtract
`$PROJECT/.env` from an allowed project root. FULL therefore bind-mounts
`/dev/null` over secret files and an empty private tmpfs over secret
directories before Landlock is restricted. FS-ONLY constructs narrower
concrete read rules and fails closed if it cannot do so.

The agent retains no usable way to dismantle this view: seccomp rejects
`umount2`, the mount API and `pivot_root`, and descendants inherit the filter.
Report/JSONL destinations are opened outside the sandbox with exclusive,
no-follow semantics and regular-file checks. The secret sanitizer applied to
reports is **best-effort** and can have both false positives and false
negatives; it is not a confidentiality guarantee.

`~/.gitconfig` is intentionally readable for commit identity. A user who
stores credentials in URL rewrites inside that file exposes those credentials
to the agent and should move them to a credential helper.

## Process and kernel hardening

Both Linux tiers reject cross-process access through `ptrace`,
`process_vm_readv`, `process_vm_writev` and `pidfd_getfd`. The filter also
rejects `io_uring_setup/enter/register`, `userfaultfd`, mount manipulation,
kernel module/kexec operations, `bpf`, `perf_event_open`, reboot and swap
control. This intentionally makes debuggers, eBPF loaders, kernel tools and
hardware profilers incompatible inside the sandbox; see the rationale in the
threat model.

FULL mounts an isolated, size-limited `/dev/shm`. Processes within one sandbox
can still communicate with each other through that shared memory because they
are members of the same trust boundary. Resource limits reduce accidental or
malicious exhaustion but are not a defense against every host-level denial of
service.

## Network policy and DNS rebinding

Network `off` is the default. Allowlist/strict connections use a host-side
broker; the child has no direct Internet route. The broker validates the DNS
name, resolves it outside the sandbox, rejects the entire answer set if it
contains loopback/private/link-local/shared/metadata/multicast/reserved IPv4 or
IPv6 (including mapped/NAT64 forms), then connects directly to one validated
`SocketAddr`. The name is not resolved a second time for that connection.

This is CONNECT-level mediation, not content inspection. vetto never performs
TLS interception, SNI filtering, CA installation or credential injection.
Non-proxy protocols fail closed unless an explicit relay exists. `--git-ssh`
uses the same broker and still requires an allowlisted host/port.

## Environment variables

The child environment is allowlist-only. Built-in profiles preserve basic
terminal, locale, editor and toolchain-location variables. `GH_TOKEN`,
`OPENAI_API_KEY`, `ANTHROPIC_API_KEY` and `AWS_*` are not passed by default.
An exact name added to `[environment].pass_through` is an explicit choice to
expose that value to the agent. Unknown policy fields are errors so a misspelt
environment restriction cannot silently disappear.

## Platform Security Tiers

### Tier 1: Linux (Production-Grade)
Linux is Vetto's reference production platform, offering hardware-enforced unprivileged isolation via:
- **Landlock LSM (ABI v1–v6)**: Inode-level access restriction evaluated in the kernel VFS before `execve`.
- **Private Namespaces**: Mount namespace (`CLONE_NEWNS`) with empty `tmpfs` mode-000 and `/dev/null` overlays masking `~/.ssh`, `~/.aws`, and `.env*`; PID namespace (`CLONE_NEWPID`) ensuring 100% process tree teardown; Network namespace (`CLONE_NEWNET`) with loopback-only egress and local TCP/TLS broker.
- **Seccomp-BPF**: System call filtering preventing ptrace, process_vm_readv, mount, bpf, userfaultfd, and dangerous syscalls.
- **Tiers within Linux**: `FULL` tier leverages user namespaces (`CLONE_NEWUSER`) for private mount and network namespaces; `FS-ONLY` tier provides Landlock filesystem confinement and seccomp network blocking on systems where unprivileged user namespaces are disabled.
- **Windows WSL2**: Fully supported as Tier 1, utilizing the native Linux kernel inside WSL2.

### Tier 2: macOS (Experimental)
The macOS backend uses Apple's private Seatbelt API (`libsandbox.1.dylib!sandbox_init_with_parameters`):
- **Write and Exec Isolation**: File writes are strictly locked to `$PROJECT` and `/tmp`. Network egress is locked via `--net=off` (`(deny network*)`).
- **dyld Crash Limitation & Broad Reads**: On modern macOS (13/14/15), the dynamic linker (`dyld`) aborts (`SIGABRT`) when SBPL read rules are fragmented across multiple discrete path clauses. Vetto applies broad read permissions `(allow file-read* (subpath "/"))` alongside tail denials on known secrets. Because Darwin lacks unprivileged mount overlays and VFS inode masking, unprivileged read denial cannot guarantee absolute secrecy against all native binaries. This platform defect is tracked via `vetto doctor` under `sbpl-read-fragment`.
- **Process Supervision**: Enforced via a `kqueue` EVFILT_PROC watchdog (`pdeath_watch`), providing best-effort process tree termination.
- **Recommendation**: For hardware-enforced kernel read-denial of host credentials on macOS, run Vetto inside **OrbStack**, a lightweight Linux VM, or Docker devcontainers.

### Tier 3: Windows (Experimental / Preview)
Windows native isolation uses Win32 security tokens and Job Objects:
- **Process Guardrails**: Job Objects enforce `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` to terminate all descendant processes on exit. AppContainer and LPAC (`S-1-15-2-2`) tokens isolate IPC and local tokens.
- **No Unprivileged LSM / Mounts**: The Windows kernel does not expose unprivileged mount namespaces or LSM hooks. Fine-grained network filtering via WFP requires administrator rights, which Vetto strictly refuses to require.
- **Production Recommendation**: For production-grade Tier 1 isolation on Windows hosts, execute Vetto within **WSL2** (`wsl -- vetto ...`).
- **Windows Sandbox**: Available as an opt-in hardware-virtualized tier (`--backend win-sandbox`), generating `.wsb` specifications with dedicated virtual storage.

---

## What Vetto Does NOT Protect

Vetto enforces strict OS-level containment for untrusted agent subprocesses. However, security boundaries are defined and limited by the underlying kernel and host architecture. Vetto explicitly does NOT defend against the following four threat classes:

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

### Additional Residual Risks
- Kernel 0-days or VFS race conditions can bypass software kernel sandboxes.
- Files created in the writable project root after session startup that match secret naming patterns may not be masked until the next session.
- Visibility feeds, logging, and audit channels are racy and advisory by design; missing audit events never imply permission.
- User-selected pass-through environment variables, widened read roots, and permissive network destinations deliberately expand the attack surface.
