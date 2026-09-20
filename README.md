<div align="center">

# vetto

**The OS-native, fail-closed sandbox & policy runtime for AI coding agents.**

[![CI](https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/shleder/vetto/actions) [![Version](https://img.shields.io/badge/version-0.3.5-blue?style=flat-square)](https://github.com/shleder/vetto/releases/tag/v0.3.5) [![npm](https://img.shields.io/npm/v/%40shledery%2Fvetto?logo=npm&style=flat-square)](https://www.npmjs.com/package/@shledery/vetto) [![License](https://img.shields.io/badge/license-Apache--2.0%20%2F%20MIT-green?style=flat-square)](#license) [![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-informational?style=flat-square)](#platform-guarantees) [![Security](https://img.shields.io/badge/security-fail--closed%20%28exit%20125%29-success?style=flat-square)](#what-vetto-intercepts)

<br/>

![Vetto Demo](assets/demo.svg)

</div>

---

<a id="quickstart"></a>
## ⚡ Quickstart (10 seconds)

### 1. Install

One-line installation commands:

```bash
# Standalone curl (Linux / macOS / WSL2)
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh

# Homebrew (macOS / Linux)
brew install shleder/tap/vetto

# npm global
npm install -g @shledery/vetto

# Cargo (from crates.io)
cargo install vetto
```

<details>
<summary><b>Alternative Install Options (System-wide, Cargo locked, Docker)</b></summary>

```bash
# System-wide installation
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh -s -- --system

# Cargo locked build from crates.io
cargo install vetto --locked

# Docker / Devcontainer (unprivileged user namespaces)
docker run --rm -it --security-opt seccomp=unconfined ghcr.io/shleder/vetto:0.3.5 vetto doctor
```

*Every release binary is attested with **SLSA Level 3 Provenance** and signed with **Minisign** (Key ID `75ECEC9B5080C590`). Pre-built archives and CycloneDX 1.5 SBOMs are published on [GitHub Releases](https://github.com/shleder/vetto/releases/tag/v0.3.5). See [Installation Guide](docs/INSTALL.md) for custom paths and platform options.*

</details>

### 2. Run

1-command agent activation:

```bash
# Enable transparent sandbox shim for your agent:
vetto enable claude     # or codex, cursor, aider, opencode

# Run your agent as usual — vetto enforces boundaries underneath:
claude
```

Direct execution without shims:

```bash
# Execute command under default strict sandbox:
vetto run -- python script.py

# Direct shortcut syntax:
vetto -- npm test
```

---

<a id="what-vetto-intercepts"></a>
## 🛡️ What vetto intercepts

When autonomous AI agents run with full execution privileges (e.g. `--dangerously-skip-permissions` or unattended loops), a single hallucination, compromised dependency hook, or prompt injection can wipe host files or leak sensitive developer keys (`~/.ssh`, `~/.aws`, `.env`). **vetto** neutralizes these risks at the OS kernel boundary **before** untrusted processes execute:

```text
$ claude
> Reading ~/.ssh/id_rsa...
[vetto] BLOCKED: Inode-level secret mask (INV-08). EACCES.
> Opening raw socket to 198.51.100.1...
[vetto] BLOCKED: Network namespace isolated (INV-04). EAFNOSUPPORT.
> Spawning detached daemon via setsid...
[vetto] TERMINATED: Process tree extinction breach (INV-20). Exit 125.
```

### 5 Core Security Guarantees

1. **Zero Secret Leaks**: Credential stores (`~/.ssh`, `~/.aws`, `~/.gnupg`) and intra-project secrets (`.env*`, `*.pem`, `*.key`) are physically stripped from environment variables (35+ patterns) and masked at the filesystem layer via `mode-000` tmpfs overlays and `/dev/null` binds.
2. **Strict Workspace Isolation**: Filesystem writes are locked strictly to the target workspace root and `/tmp`. Destructive host modifications are blocked fail-closed.
3. **Governed Network Relay**: Network access is blocked by default (`--net off`) via network namespaces (`CLONE_NEWNET`) or routed exclusively through a loopback relay broker enforcing domain allowlists and anti-DNS rebinding defenses.
4. **Guaranteed Process Extinction (<500ms)**: Fail-closed process supervision sweeps all descendant fork trees (`cgroup.kill` / PID namespaces / Job Objects / kqueue), terminating runaway zombie daemons and orphaned background processes.
5. **Zero Daemon Latency (~4ms cold start)**: Sub-4ms cold start latency, 0 MB idle RAM footprint, and zero background daemons (`no root`, `no dockerd`). Boundaries are injected directly between `fork()` and `execve()`.

---

<a id="platform-guarantees"></a>
## 💻 Platform Guarantees (3-Tier Honesty)

vetto formally separates operating system platforms into 3 distinct tiers to reflect actual kernel guarantees (Issue #26):

| Platform / Tier | Status | Filesystem Write | Filesystem Read | Network Egress | Process Lifecycle | Secret Masking | Recommended Deployment |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- | :--- |
| **Linux (Native & WSL2)**<br/>*Tier 1* | **Production** | **100% Kernel Deny** (Landlock ABI v1–v6 + R/O VFS) | **100% Scoped Read** (Landlock inode rules, secrets blocked) | **Network Namespaces** (`CLONE_NEWNET` + loopback relay broker) | **100% PID Namespace** (`CLONE_NEWPID` init + `PR_SET_PDEATHSIG` + tree sweep) | **tmpfs mode-000** overlays & `/dev/null` binds | **Production Agents** (unattended autonomy) |
| **macOS (Darwin)**<br/>*Tier 2* | **Experimental** | **Seatbelt SBPL** (write locked to workspace & `/tmp`) | **Broad Reads + Tail Deny** (known dyld shared cache restriction, #62) | **`--net off` lockdown** (SBPL network* deny + UNIX socket exemption) | **kqueue Watchdog** (`EVFILT_PROC` + process-group SIGKILL sweep) | **SBPL tail deny** (unprivileged VFS overlay unsupported) | **Interactive dev** (run inside OrbStack/WSL2 for read secrecy) |
| **Windows Native**<br/>*Tier 3* | **Experimental** | **AppContainer DACL** (LPAC write grants to workspace) | **Default-Deny + Overlap Analysis** (AppContainer capability sandbox, #63) | **`--net off` only** (WFP domain filtering requires admin opt-in) | **Job Objects** (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) | **Fails closed** on deny-path overlap | **Preview / Testing** (run in **WSL2** for production Tier 1 isolation) |

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                vetto Supervisor Engine                                 │
│          (Fail-Closed Lifecycle · Env Sanitizer · Secret Masker · Audit Log)           │
└──────────────────┬────────────────────────────┬────────────────────────────┬───────────┘
                   │                            │                            │
                   ▼                            ▼                            ▼
┌─────────────────────────────────────┐ ┌──────────────────────────────┐ ┌──────────────────────────────┐
│       Linux Backend (Tier 1)        │ │    macOS Backend (Tier 2)    │ │   Windows Backend (Tier 3)   │
│ ─────────────────────────────────── │ │ ──────────────────────────── │ │ ──────────────────────────── │
│ • Landlock LSM (ABI v1–v6) Inodes   │ │ • Apple Seatbelt C API (SBPL)│ │ • AppContainer & LPAC Tokens │
│ • Rootless Namespaces (bwrap/clone) │ │ • Shape D AST Engine         │ │ • Job Object Kill-On-Close   │
│ • Seccomp-BPF Syscall Filter        │ │ • dyld Tracking (Issue #62)  │ │ • Deny-Path Overlap Analysis │
│ • PID Namespace / Deathsig init     │ │ • kqueue Watchdog & pgroup   │ │ • Opt-in WFP Admin Gate (#63)│
│ • cgroups v2 & rlimits Ceilings     │ │ • Best-effort rlimits        │ │ • WSL2 Production Pathway    │
└─────────────────────────────────────┘ └──────────────────────────────┘ └──────────────────────────────┘
```

### Linux Backend (Tier 1 — Production)
- **Rootless Namespaces & Bubblewrap (`bwrap`)**: Isolates Mount (`CLONE_NEWNS`), Network (`CLONE_NEWNET`), PID (`CLONE_NEWPID`), and IPC (`CLONE_NEWIPC`) namespaces entirely in unprivileged user space.
- **Landlock LSM**: Kernel-level VFS inode access control (ABI v1–v6) restricting filesystem reads and writes.
- **Seccomp-BPF**: Enforces fine-grained system call interception before `execve` (`UnixOnly` and `AgentMin`), terminating debugger attachment (`ptrace`), eBPF injections (`bpf`), userfaultfd exploits, and raw socket allocations.
- **cgroups v2 & rlimits**: Immutable resource ceilings on CPU time (`RLIMIT_CPU`), virtual memory address space (`RLIMIT_AS`), process limits (`RLIMIT_NPROC`), and file size (`RLIMIT_FSIZE`).

### macOS Backend (Tier 2 — Experimental)
- **Native Seatbelt**: Dynamic Scheme SBPL (Sandbox Profile Language) compilation loaded via Apple's private C API (`libsandbox.1.dylib`), bypassing brittle CLI wrappers.
- **Filesystem Confinement**: Strict write isolation locked to the workspace root and `/tmp`. Known secret paths (`~/.ssh`, `~/.aws`, `.env`) are masked via tail denials (`deny_resolved`). Broad reads remain permitted due to Apple's `dyld` shared cache constraints (Issue #62).
- **Process Lifecycle Supervision**: Watchdog supervisor thread monitoring parent death via `kqueue` and executing clean process-group (`pgroup`) SIGKILL sweeps on termination.

### Windows Backend (Tier 3 — Experimental)
- **AppContainer & LPAC**: Process sandboxing via Less Privileged AppContainer tokens (`S-1-15-2-2`) stripping implicit capabilities and enforcing default-deny filesystem boundaries.
- **Deny-Path Overlap Analysis**: Granular verification of display-only deny paths against granted roots; fails closed on unsubtractable subpath collisions (Issue #63).
- **Job Objects**: Enforces `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` ensuring 100% process tree extinction upon session exit.
- **WSL2 Production Pathway**: For production-grade Landlock LSM and namespace isolation on Windows, executing through WSL2 (`wsl -- vetto ...`) is recommended.

---

<a id="supported-agents"></a>
## 🤖 Supported AI Agents (Roster)

vetto includes 20 native agent presets with automatic credential isolation, configuration path allowlisting, and zero-config network profiles (see [Agent Compatibility Registry](docs/agents.md)):

| Agent | Preset | Guide | Agent | Preset | Guide |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Claude Code** | `claude` | [Guide](docs/integrations/claude-code.md) | **OpenCode** | `opencode` | [Guide](docs/integrations/opencode.md) |
| **OpenAI Codex** | `codex` | [Tutorial](docs/tutorials/codex.md) | **Google Gemini** | `gemini` | Built-in preset |
| **Cursor Agent** | `cursor` | [Guide](docs/integrations/cursor.md) | **Antigravity** | `antigravity` | Built-in preset |
| **Aider** | `aider` | [Guide](docs/integrations/aider.md) | **Cline** | `cline` | [Guide](docs/integrations/cline.md) |
| **Codeium Windsurf** | `windsurf` | Built-in preset | **GitHub Copilot CLI** | `copilot` | Built-in preset |
| **Continue CLI** | `continue` | Built-in preset | **Block Goose** | `goose` | Built-in preset |
| **OpenHands** | `openhands` | Built-in preset | **SWE-agent** | `swe-agent` | Built-in preset |
| **Plandex** | `plandex` | Built-in preset | **Mentat** | `mentat` | Built-in preset |
| **GPT Engineer** | `gpt-engineer` | Built-in preset | **Cognition Devin** | `devin` | Built-in preset |
| **Crust AI** | `crust` | Built-in preset | **Amp AI** | `amp` | Built-in preset |

### Model Context Protocol (MCP) Support

Isolate third-party MCP servers connected to Claude Desktop or Codex Desktop (see [MCP Integration Guide](docs/integrations/mcp.md) and [Tutorial](docs/tutorials/mcp.md)):

```bash
vetto mcp wrap --allow ./data --allow-read /usr/share --net off -- <mcp-server-binary> [args...]
```

---

<a id="policy-ux"></a>
## 🔒 Policy Management & Security Audit (Policy UX)

vetto compiles declarative security policies into deterministic, BLAKE3-sealed cryptographic contracts before execution:

```bash
# Explain resolved policy and sealed BLAKE3 contract:
vetto policy explain --limits pids=50,mem=1G

# Preflight configuration linter:
vetto policy lint --strict

# Check configuration and verify policies without spawning:
vetto check

# Run throwaway leak-detection battery on current policy:
vetto verify

# Inspect blocked filesystem attempts, syscalls, and network egress from past runs:
vetto audit --latest

# Print post-session security recap:
vetto audit --latest --recap

# Dynamic runtime grants (no manual TOML editing):
vetto allow ./target                    # Grant read+write to a folder
vetto allow --read-only /usr/share/doc  # Grant read-only access
vetto allow --net api.github.com        # Allow egress to domain
vetto deny ~/.aws/credentials           # Mask sensitive file
```

---

<a id="architecture-invariants"></a>
## 📚 Architecture Invariants & Specifications

Deep architectural specifications, threat models, and verification suites:

- 🏛️ **[Architecture Blueprint](docs/architecture/NEXT_GEN_SPECIFICATION.md)** — Tri-plane compiler, execution FSM, kernel invariants, and process extinction theorems.
- 🛡️ **[Threat Model & Boundary Guarantees](docs/threat-model.md)** — Inode-level masking, network brokers, and attack vector mitigations.
- 🧪 **[Verify-NG Test Harness](docs/architecture/verify-ng.md)** — 6-tier hermetic trap suites and kernel boundary regression testing.
- 🔏 **[SLSA Level 3 Provenance & Attestation](docs/security/slsa-provenance.md)** — Cryptographic supply-chain attestations, Minisign signatures, and CycloneDX SBOMs.
- ⚠️ **[Exit Codes Specification](docs/exit-codes.md)** — Fail-closed exit contract (`125`), child process exit propagation, and signal handling.
- ⚙️ **[Profile Inheritance & Presets](docs/profiles.md)** — Hierarchical security profile syntax and preset configuration.
- 🌐 **[Platform Backends & Parity Matrix](docs/platform-backends.md)** — Technical deep dive into Linux, macOS, and Windows isolation mechanisms.

### Built-in Security Profiles

| Profile | Target Use Case | Filesystem Bounds | Network Egress | Resource Ceilings |
| :--- | :--- | :--- | :--- | :--- |
| **`strict`** *(default)* | Untrusted scripts, unattended autonomous agent runs | `$PROJECT` and `/dev/null` only; `/tmp` writes denied; secrets masked | Denied (`--net off`) | Strict: 1h CPU, 8GB RAM, 256 procs, 1024 FDs |
| **`dev`** | Active interactive development with compilers and tools | `$PROJECT`, `/tmp`, and standard build tool caches (`~/.cargo`, `~/.npm`) | Denied or provider allowlist | Balanced developer ceilings |
| **`network-isolated`** | Hermetic builds, compliance auditing, zero-leak validation | `$PROJECT` and `/tmp`; read-only system tools | Completely disabled (`CLONE_NEWNET` / SBPL deny) | Default limits |
| **`ci`** | GitHub Actions, GitLab CI, headless evaluation pipelines | Workspace root; automated report output directory | Allowlisted or off | Headless, `--tui none`, JSON summary on stdout |

---

<a id="comparison"></a>
## ⚖️ Comparison: vetto vs. Alternatives

| Dimension | `vetto` | Built-in LLM Sandbox | Docker Containers | MicroVMs (Firecracker) |
| :--- | :--- | :--- | :--- | :--- |
| **Startup Overhead** | **~4ms** (instant) | 0ms (app-level prompt) | 3.5s – 8s (daemon boot) | 100ms – 500ms |
| **Daemon Required** | **None** (zero daemons) | None | `dockerd` service required | KVM / containerd |
| **RAM Footprint** | **0 MB** idle | 0 MB | 1.5 GB+ (engine/VM) | 500 MB+ |
| **Privilege Level** | **Unprivileged** (no root) | User-level | Root-equivalent (`docker` group) | Root / KVM group |
| **Filesystem Sync** | **Instant native I/O** | Native | Slow bind mounts / UID issues | 9p / virtio-fs sync |
| **Secret Masking** | **Automatic VFS overlays** | None (reads `.env`, `~/.ssh`) | Manual `.dockerignore` | Guest VM disk image |
| **Network Egress** | **Per-domain loopback broker** | Unfiltered or app-level | Bridge network or none | Virtualized netstack |
| **Fail-Closed Contract** | **100% Fail-Closed** | Varies / Fail-Open | Container fallback | VM error |
 
See [In-Depth Sandbox Comparison](docs/comparison.md) for full benchmark metrics, microVM trade-offs, and platform breakdown.

---

<a id="contributing"></a>
## Contributing

We welcome contributions from security researchers, systems engineers, and AI developers!

1. Fork the repository and create your branch from `main`.
2. Follow strict code hygiene: adhere to formatting, clippy lints, and existing error-handling idioms.
3. Ensure every capability claim is backed by real kernel tests:
   - **No mock tests for kernel boundaries**: all boundary checks must assert real kernel enforcement.
   - **No silent downgrades**: any failure to establish isolation must fail closed with exit code `125`.
4. Open a Pull Request with a clear description of changes and test evidence.

For security vulnerabilities, please refer to [SECURITY.md](SECURITY.md) and report responsibly via GitHub Security Advisories.

---

<a id="license"></a>
## License

vetto is distributed under the dual **Apache-2.0 / MIT** license.

See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for full terms.
