# Platform backend boundaries

The platform modules expose capability probes and explicit opt-in contracts.
They do not silently elevate, install drivers, create persistent firewall
rules, or claim visibility/enforcement that the operating system API cannot
provide.

> **Uniform runtime (canonical)**: the default on every OS requires Tier-1 —
> direct Linux kernel enforcement, or Tier-1 inside a VM (`--backend mac-vm`
> on macOS, `--backend wsl2` on Windows). Legacy process backends (Seatbelt,
> AppContainer) are deprecated and explicit-only (`--backend process`).
> Missing VM/distro fails closed. See `docs/uniform-runtime.md`.

---

## 0. Canonical enforcement matrix (uniform dispatch)

`--backend` names: `auto, process, mac-vm, wsl2, win-sandbox`.
`vetto doctor` prints these rows plus the platform default and its reason.

| OS | Default (`auto`) | Enforcement row | Legacy process | win-sandbox |
| :--- | :--- | :--- | :--- | :--- |
| Linux | Tier-1 direct | `linux-tier-1` | explicit `--backend process` only (deprecated) | n/a (Windows-only, fails closed elsewhere) |
| macOS | Tier-1 via `mac-vm` (default) | `mac-vm (tier-1 in VM)` | Seatbelt, deprecated, explicit `--backend process` only | n/a |
| Windows | Tier-1 via `wsl2` (default) | `wsl2 (tier-1 in VM)` | AppContainer, deprecated, explicit `--backend process` only | opt-in (`--backend win-sandbox`, Hyper-V required) |

Fail-closed contract: default requires Tier-1 (direct or VM). A missing VM
runtime or distro never falls back to a weaker backend — vetto exits with
`103` (`VETTO_ERR_FAIL_CLOSED`) and `vetto doctor` explains the action.

---

## Scope Closure: Issue #26 (Platform Parity & Scope Honesty)

Vetto formally repudiates ungrounded claims of cross-platform security equivalence.
Operating system kernels provide fundamentally unequal primitives to unprivileged userspace.
Accordingly, Vetto enforces an immutable 3-tier boundary architecture:
- **Tier 1 (Production-Grade)**: Linux Kernel LSM (Landlock + Seccomp + Namespaces). Available on Linux (Native) and Linux (WSL2).
- **Tier 2 (deprecated legacy, explicit `--backend process` only)**: macOS Darwin Seatbelt (SBPL write/exec containment + dyld read constraints). Default on macOS is Tier-1 via `mac-vm`.
- **Tier 3 (deprecated legacy, explicit `--backend process` only)**: Windows Process Sandboxing (AppContainer + Job Objects + LPAC). Default on Windows is Tier-1 via `wsl2`.

---

## 1. Operating System Parity Guarantee Matrix (Canonical 5 Dimensions)

| Platform / Tier | Filesystem Write | Filesystem Read | Network Namespace | Process Reaping | Secret Overlays per OS | Assurance Status |
| :--- | :--- | :--- | :---: | :--- | :---: | :--- |
| **Linux (Native)**<br/>*Tier 1 (Production)* | **100% Kernel Deny** (Landlock ABI v1–v6 + R/O Mounts) | **100% Scoped Read** (Landlock VFS Inode checks, `~/.ssh` / `.env` blocked) | **Yes** (`CLONE_NEWNET`, loopback-only + local TCP/TLS broker) | **100% PID Namespace** (`CLONE_NEWPID` init teardown + `PR_SET_PDEATHSIG`) | **Yes** (tmpfs mode-000 and `/dev/null` bind-mounts over secrets) | **Production-grade**: Complete hardware & kernel isolation boundary |
| **Linux (WSL2)**<br/>*Tier 1 (Production)* | **100% Kernel Deny** (Landlock via WSL2 Linux Kernel) | **100% Scoped Read** (Landlock VFS Inode checks) | **Yes** (`CLONE_NEWNET` inside WSL2 VM) | **100% PID Namespace** teardown | **Yes** (tmpfs mount overlays inside WSL2) | **Production-grade**: Recommended path for Windows workstations |
| **macOS via mac-vm**<br/>*Tier 1 (uniform default)* | **100% Kernel Deny** (Linux Landlock inside the VM) | **100% Scoped Read** (Landlock VFS Inode checks inside the VM) | **Yes** (`CLONE_NEWNET` inside the VM) | **100% PID Namespace** teardown | **Yes** (tmpfs mount overlays inside the VM) | **Production-grade**: same guarantees as Linux, via uniform runtime (see `docs/uniform-runtime.md`) |
| **Windows via wsl2**<br/>*Tier 1 (uniform default)* | **100% Kernel Deny** (Linux Landlock inside WSL2) | **100% Scoped Read** (Landlock VFS Inode checks inside WSL2) | **Yes** (`CLONE_NEWNET` inside WSL2) | **100% PID Namespace** teardown | **Yes** (tmpfs mount overlays inside WSL2) | **Production-grade**: same guarantees as Linux, via uniform runtime (see `docs/uniform-runtime.md`) |
| **macOS (Darwin)**<br/>*legacy process, deprecated — explicit `--backend process` only* | **100% Locked** (Seatbelt SBPL `(allow file-write*)` to workspace & `/tmp`) | **Broad Reads** (System `/` read due to dyld bug; tail `deny` on known secrets) | **No** (Unsupported by Darwin; `--net=off` via SBPL `(deny network*)`) | **Partial** (Watchdog `kqueue` `pdeath_watch` sends `SIGKILL` to group) | **No** (VFS overlays unavailable unprivileged; SBPL static deny only) | **Deprecated legacy**: write confinement and `--net=off` network lockdown only; default is Tier-1 via `mac-vm` |
| **Windows Native**<br/>*legacy process, deprecated — explicit `--backend process` only* | **Workspace Only** (AppContainer DACL + LPAC `S-1-15-2-2` write grants) | **ACL Fallback** (AppContainer default-deny; partial token restriction) | **No** (Network namespaces unavailable; `--net=off` via AppContainer caps) | **100% Job Object** (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` terminates process tree) | **No** (No unprivileged mount namespaces; fails closed on collision) | **Deprecated legacy**: process guardrails only; default is Tier-1 via `wsl2` |
| **Windows Sandbox**<br/>*opt-in VM (`--backend win-sandbox`)* | **VM Isolated** (Dedicated virtual disk, mapped read-write folders only) | **VM Isolated** (Host secrets never mapped into `.wsb` specification) | **Virtual Switch** (Hyper-V vSwitch disabled under `--net=off`) | **VM Teardown** (Hyper-V VM instance termination) | **Full Isolation** (Physically separated filesystem in disposable VM) | **Disposable VM**: Hardware-virtualized container (requires Hyper-V) |

---

## 2. Linux Backend (Tier 1 Production-Grade)

The Linux backend represents Vetto's reference production architecture, leveraging unprivileged Linux kernel security modules and isolation primitives:

### Landlock LSM (ABI v1–v6)
- Evaluates path rules on underlying filesystem inodes within the kernel VFS before `execve`.
- Irreversible per session via `PR_SET_NO_NEW_PRIVS`.
- Restricts `LANDLOCK_ACCESS_FS_READ_FILE`, `READ_DIR`, `WRITE_FILE`, `REMOVE_FILE`, `REMOVE_DIR`, `MAKE_REG`, `MAKE_DIR`.

### Mount Namespaces & Tmpfs Secret Masking
- Private mount namespace (`CLONE_NEWNS`) created in unprivileged user namespaces (`CLONE_NEWUSER`).
- Mode-000 empty `tmpfs` mounted over sensitive directories (`~/.ssh`, `~/.aws`, `~/.gnupg`).
- Read-only bind-mounts of `/dev/null` placed over known secret files (`.env*`).

### Network Isolation & TCP/TLS Broker
- Dedicated network namespace (`CLONE_NEWNET`) with only a loopback interface.
- Outbound traffic strictly routed through an in-process TCP/TLS relay broker with DNS rebinding protection and private IP blocking.

### Process Tree Supervision
- Child executed inside a dedicated PID namespace (`CLONE_NEWPID`) as PID 1 (init).
- When the Vetto supervisor process terminates, the kernel destroys the PID namespace, ensuring 100% orphan and zombie cleanup.
- Fallback subreaper (`PR_SET_CHILD_SUBREAPER`) and `PR_SET_PDEATHSIG` prevent detached `setsid` escapes.

---

## 3. macOS Backend (legacy Seatbelt — deprecated, explicit `--backend process` only)

> Default on macOS is Tier-1 via `mac-vm` (uniform runtime, see
> `docs/uniform-runtime.md`). This section documents the legacy process
> backend kept for explicit opt-in only.

### Seatbelt (SBPL) & Regression Tracking
- Vetto dynamically loads Apple's private Seatbelt API (`libsandbox.1.dylib!sandbox_init_with_parameters`), avoiding brittle reliance on the deprecated `/usr/bin/sandbox-exec` CLI wrapper.
- **Root Cause of dyld SIGABRT Crashes**: On modern macOS releases (macOS 13 Ventura, macOS 14 Sonoma, macOS 15 Sequoia), Apple's dynamic linker (`dyld`) maps system dynamic libraries directly from shared caches (`/System/Library/dyld/dyld_shared_cache_*`). When SBPL policies employ fragmented file-read allowlists (multiple discrete `(allow file-read* (subpath "..."))` clauses), dyld's internal validation routines and memory mappings abort with `SIGABRT` upon first library resolution.
- **Compensating Policy Architecture**: To guarantee process stability while preventing data destruction, Vetto applies broad read access `(allow file-read* (subpath "/"))` alongside tail denials `(deny file-read* (subpath (param "DENY_PATH_...")))`. Write access is strictly constrained to the workspace root and `/tmp`.
- **Read-Isolation Limitations**: Because Darwin kernels do not expose unprivileged mount namespaces or VFS inode masking, unprivileged read denial on macOS cannot guarantee absolute secrecy against all native binaries. Vetto transparently exposes this platform behavior in `vetto doctor` under the `sbpl-read-fragment` probe.
- **Network Boundaries**: Darwin kernels lack unprivileged network namespaces (`CLONE_NEWNET`). Egress restriction is limited to `--net=off` via SBPL `(deny network*)` (with a local UNIX domain socket exemption for libSystem/XPC IPC). Per-domain allowlisting is unsupported and fails closed.
- **Process Supervision**: In the absence of PID namespaces, process reaping is enforced by a dedicated `kqueue` EVFILT_PROC watchdog (`pdeath_watch`) that broadcasts `SIGKILL` to the process tree when the supervisor terminates.
- **Production Recommendation**: For threat models requiring 100% hardware-enforced kernel read-denial of host credentials (`~/.ssh`, `~/.aws`, `.env`), run Vetto inside **OrbStack**, a lightweight Linux VM, or Docker devcontainers.

### macOS Unified Logging (`os_log`)
- When `--oslog` or `oslog = true` in policy is enabled, `sandbox::logger::oslog::OsLogSink` streams sandbox events (policy denials, warnings, session lifecycle) to the macOS unified log via `/usr/bin/logger -t vetto`.
- Logging is non-blocking and best-effort: logging failures never interrupt the sandbox session.

### Packaging and Apple Notarization
- `packaging/macos/build_pkg.sh` packages `vetto` into a native `.pkg` installer.
- Supports Hardened Runtime codesigning (`codesign --options runtime`), component package building (`pkgbuild`), Apple notary service submission (`xcrun notarytool submit --wait`), ticket stapling (`xcrun stapler staple`), and Gatekeeper verification (`spctl --assess`).

---

## 4. Windows Backend (legacy AppContainer — deprecated, explicit `--backend process` only)

> Default on Windows is Tier-1 via `wsl2` (uniform runtime, see
> `docs/uniform-runtime.md`). This section documents the legacy process
> backend kept for explicit opt-in only.

The Windows native backend is designated **legacy (deprecated, explicit `--backend process` only)**. It provides process-level guardrails using native Win32 security mechanisms:

### AppContainer & LPAC (Less Privileged AppContainer)
- The default Windows process sandbox runs under an AppContainer token combined with low integrity (`S-1-16-4096`).
- When `--lpac` or `lpac = true` is configured, Vetto validates the Less Privileged AppContainer SID (`S-1-15-2-2`, `ALL RESTRICTED APPLICATION PACKAGES`), stripping implicit package capabilities and isolating local IPC/RPC endpoints.
- `sandbox::windows::probe()` inspects `lpac_api` and reports status in `vetto doctor`.

### Job Object Lifecycle & IO Rate Control
- Windows Job Objects enforce `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` to ensure 100% of descendant processes are terminated when Vetto exits.
- When `io_rate` limits are specified (`--limits max_iops=...,max_bandwidth=...`), Vetto sets `JOB_OBJECT_IO_RATE_CONTROL_INFORMATION` (information class 37) on the Job Object, capping IOPS and bandwidth across the sandbox.

### Windows Sandbox VM Opt-in (`--backend win-sandbox`)
- `sandbox::windows::windows_sandbox` generates `.wsb` disposable VM specifications with mapped read-only and read-write folders (`mapped_read_only`, `mapped_read_write`).
- Activated explicitly via `--backend win-sandbox`. Fails closed if Hyper-V virtualization or the Windows Sandbox feature is not enabled.

### WSL2 uniform default for Windows
- The native Windows kernel does not provide unprivileged mount namespaces or LSM hooks equivalent to Linux Landlock. Fine-grained network filtering via Windows Filtering Platform (WFP) requires administrator privileges, which Vetto strictly refuses to demand.
- **Uniform default**: Windows runs Tier-1 via `wsl2` (`--backend wsl2`, default under `--backend auto`): VM provision → sync workspace → exec Linux vetto → sync back → teardown. A missing WSL2 distro fails closed (exit `103`); the legacy AppContainer backend never applies implicitly. See `docs/uniform-runtime.md`.

### Authenticode Digital Signing
- `packaging/windows/sign.ps1` signs `vetto.exe` using `signtool.exe` or `osslsigncode` with SHA-256 and RFC 3161 timestamps (`http://timestamp.digicert.com`).
- Configured in CI release workflows via `SIGNING_CERT_PFX` and `SIGNING_CERT_PASSWORD`.
