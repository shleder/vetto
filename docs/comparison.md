# Sandbox Comparison: vetto vs. Built-in Agent Sandboxes vs. Containers

A fair, factual comparison of isolation mechanisms, threat models, failure modes, and platform trade-offs.

---

## 1. Feature & Boundary Matrix

| Dimension | `vetto` | Built-in Agent Sandboxes (Claude Code / Codex / Gemini) | Docker / OCI Containers | gVisor / MicroVMs (Firecracker) |
|---|---|---|---|---|
| **Threat Model** | Compromised agent, untrusted repo scripts, prompt injection attempting host escape or data exfiltration. | Agent accidental mistakes and unauthorized tool calls within IDE / CLI lifecycle. | Untrusted multi-tenant workload isolation with root separation. | Hostile untrusted code execution in multi-tenant cloud environments. |
| **Startup Overhead** | **~0.8ms – 3ms** (sub-millisecond process-level kernel sandbox, daemon-less). | **0ms** (application-level checks) or process wrapper. | **150ms – 1s** (container daemon + bridge network setup). | **50ms – 500ms** (user-space kernel / VMM boot). |
| **Daemon / Dependencies** | **None** (zero background daemons, single native binary). | **None** (integrated into CLI/IDE). | Requires Docker daemon / dockerd / rootless daemon. | Requires containerd / runsc / KVM access. |
| **Filesystem Write Isolation** | **Enforced**: Landlock ABI 1–5 on Linux, Seatbelt on macOS, AppContainer on Windows. Fails closed. | Varies: interactive user confirmations or tool-level path allowlists. | OverlayFS / volume mounts. | Virtualized guest filesystem or 9p / virtio-fs. |
| **Filesystem Read Isolation** | **Enforced on Linux** (Landlock scoped reads); **Known limitation on macOS** (broad reads required to avoid dyld SIGABRT); **Default-deny on Windows** (AppContainer). | Not isolated (agent processes inherit full user read access). | Scoped to container image + explicit bind mounts. | Scoped to guest VM image + explicit shares. |
| **Intra-Project Secret Masking** | **Enforced**: Tmpfs mount overlays (Linux Full) or carved sub-rules (Linux FsOnly) over `.env`, `~/.ssh`, credentials. | None (agent reads environment variables and disk secrets unless excluded by prompt). | Requires manual `.dockerignore` / secret mount hygiene. | Handled via external secret management systems. |
| **Network Default-Deny (`--net=off`)** | **Enforced**: `CLONE_NEWNET` (Linux Full), seccomp family blocker (Linux FsOnly), Seatbelt `(deny network*)` (macOS), AppContainer network isolate (Windows). | Often open by default; relies on API gateway or tool filters. | Network bridge or `--net=none`. | Network tap or gVisor netstack sandbox. |
| **Domain-Filtered Egress** | **Enforced**: In-kernel netns + user-space loopback TLS/TCP relay with pinned DNS resolution. Host never leaks direct routes. | Tool-level URL allowlists (bypassed by subshells or child processes). | Requires external proxy container or complex iptables. | Integrated user-space TCP/IP stack (netstack). |
| **Child Process Inheritance** | **Strict**: Inherited by all child processes via kernel boundary (Landlock / seccomp / Job Objects). Setsid escapers tracked. | Process wrappers often do not enforce child or nested shell isolation. | All container processes share the container cgroups/namespaces. | All VM processes run within the guest kernel boundary. |
| **System Diagnostics** | Built-in `vetto doctor`, `vetto policy explain`, `vetto verify`, audit logging, and JSONL post-session reports. | CLI debug logs only. | `docker inspect`, `docker logs`. | System audit / hypervisor telemetry. |

---

## 2. Platform Realities and Known Limitations

Enforcement relies on host operating system kernel primitives. `vetto` never silently downgrades to an unsandboxed state:

### Linux
- **Tier FULL** (`Landlock` + unprivileged user namespaces): Full filesystem read/write scoping, intra-project secret mount overlays, interface-less network namespaces, and local domain proxy relay.
- **Tier FS-ONLY** (`Landlock` without userns): Scoped filesystem read/write, sub-rule path carving (file names visible, file content denied), and seccomp network family filtering. Network domain relay is unavailable and fails closed.
- **Tier SECCOMP** (seccomp-only fallback): System call filtering when Landlock is unavailable.

### macOS
- **Enforcement**: Native C API Seatbelt (`sandbox_init_with_parameters`).
- **Filesystem Writes**: Strictly isolated via SBPL write filters.
- **Network**: `--net=off` strictly enforced via `(deny network*)`. Domain relay is currently unavailable.
- **Read Isolation Caveat**: Due to a known Apple Seatbelt regression where path-fragmented SBPL read rules trigger dynamic linker (`dyld`) aborts (SIGABRT), broad read permissions are maintained on macOS to guarantee process stability.

### Windows (Experimental)
- Default process sandbox uses **AppContainer + LPAC** (Less Privileged AppContainer) tokens and Job Objects for process lifecycle termination and IO rate control.
- Disposable full VM isolation is available via `--backend win-sandbox` (requires Hyper-V and Windows Sandbox feature enabled).

---

## 3. When to Choose What

### Choose `vetto` when:
1. You run AI coding agents (Claude Code, Codex, Gemini CLI, Aider, OpenCode) directly on your developer workstation and need sub-millisecond startup without running inside heavy containers.
2. You want automatic detection and protection of credentials (`.env`, `~/.aws`, `~/.ssh`) without modifying the agent's code.
3. You need deterministic, fail-closed CI execution with detailed audit trails and SARIF/HTML security reports.

### Choose Built-in Agent Sandboxes when:
1. You only need basic UI-level permission prompts for file edits.
2. You do not run untrusted third-party build scripts, npm/pip hooks, or multi-process workflows.

### Choose Docker / gVisor / MicroVMs when:
1. You need 100% OS environment isolation (custom Linux kernel, separate root filesystem, multi-tenant cloud hosting).
2. The agent requires kernel modules, raw network device creation, or root privileges.
