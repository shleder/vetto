<div align="center">

# vetto

**Lightweight, zero-leak security sandbox and isolation boundary for AI agents and developer workflows.**

[![CI](https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/shleder/vetto/actions)
[![Version](https://img.shields.io/badge/version-0.2.25-blue?style=flat-square)](https://github.com/shleder/vetto/releases/tag/v0.2.25)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%2F%20MIT-green?style=flat-square)](#license)
[![Platform support](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-informational?style=flat-square)](#core-architecture--backends)
[![Security Model](https://img.shields.io/badge/security-fail--closed-success?style=flat-square)](#zero-leak-design)
[![npm version](https://img.shields.io/npm/v/%40shledery%2Fvetto?logo=npm&label=npm&style=flat-square)](https://www.npmjs.com/package/@shledery/vetto)

<br/>

![Vetto Demo](assets/demo.svg)

</div>

---

## What is vetto?

**vetto** provides unprivileged, kernel-enforced isolation for autonomous AI coding agents and developer automation tools. It protects host systems from rogue LLM commands, supply-chain attacks, unauthorized network egress, and secret exfiltration during autonomous agent execution across **Claude Code**, **Windsurf**, **OpenDevin**, **Cursor**, **OpenCode**, **Aider**, and custom CLI agents.

When autonomous agents run with full execution privileges (e.g. `--dangerously-skip-permissions` or unattended loops), a single hallucination, compromised dependency hook, or prompt injection can wipe host files or leak sensitive developer keys (`~/.ssh`, `~/.aws`, `.env`). **vetto** neutralizes these risks at the OS kernel boundary **before** untrusted processes execute:

- **Zero Secret Leakage**: Credential stores (`~/.ssh`, `~/.aws`, `~/.gnupg`) and intra-project secrets (`.env*`, `*.pem`, `*.key`) are physically stripped from environment variables and masked at the filesystem layer.
- **Strict Write Containment**: Filesystem writes are locked strictly to the target workspace root and `/tmp`. Destructive host modifications are blocked fail-closed.
- **Governed Network Egress**: Network access is blocked by default (`--net off`) or routed exclusively through a loopback relay broker enforcing domain allowlists and anti-DNS rebinding defenses.
- **Deterministic Process Teardown**: Fail-closed process supervision sweeps all descendant fork trees, preventing runaway zombie daemons and orphaned background processes.
- **Ultra-Low Latency**: Near-zero startup overhead (~4ms), 0 MB idle RAM, and zero background daemons.

---

## Core Architecture & Backends

vetto enforces isolation using native operating system kernel primitives without requiring root privileges or container daemons:

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

### Platform Capability & Assurance Matrix (3-Tier Honesty)

vetto formally separates operating system platforms into 3 distinct tiers to reflect actual kernel guarantees:

| Platform / Tier | Status | Filesystem Write | Filesystem Read | Network Egress | Process Lifecycle | Secret Masking | Recommended Deployment |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- | :--- |
| **Linux (Native & WSL2)**<br/>*Tier 1* | **Production** | **100% Kernel Deny** (Landlock ABI v1–v6 + R/O VFS) | **100% Scoped Read** (Landlock inode rules, secrets blocked) | **Network Namespaces** (`CLONE_NEWNET` + loopback relay broker) | **100% PID Namespace** (`CLONE_NEWPID` init + `PR_SET_PDEATHSIG` + tree sweep) | **tmpfs mode-000** overlays & `/dev/null` binds | **Production Agents** (unattended autonomy) |
| **macOS (Darwin)**<br/>*Tier 2* | **Experimental** | **Seatbelt SBPL** (write locked to workspace & `/tmp`) | **Broad Reads + Tail Deny** (known dyld shared cache restriction, #62) | **`--net off` lockdown** (SBPL network* deny + UNIX socket exemption) | **kqueue Watchdog** (`EVFILT_PROC` + process-group SIGKILL sweep) | **SBPL tail deny** (unprivileged VFS overlay unsupported) | **Interactive dev** (run inside OrbStack/WSL2 for read secrecy) |
| **Windows Native**<br/>*Tier 3* | **Experimental** | **AppContainer DACL** (LPAC write grants to workspace) | **Default-Deny + Overlap Analysis** (AppContainer capability sandbox, #63) | **`--net off` only** (WFP domain filtering requires admin opt-in) | **Job Objects** (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) | **Fails closed** on deny-path overlap | **Preview / Testing** (run in **WSL2** for production Tier 1 isolation) |

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
- **Deny-Path Overlap Analysis**: Replaces blanket refusals with granular verification of display-only deny paths against granted roots; fails closed on unsubtractable subpath collisions (Issue #63).
- **Job Objects**: Enforces `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` ensuring 100% process tree extinction upon session exit.
- **WSL2 Production Pathway**: For production-grade Landlock LSM and namespace isolation on Windows, executing through WSL2 (`wsl -- vetto ...`) is recommended.

### Zero-Leak Design
- **Sanitized Environment Variables**: Strips all sensitive credentials (`HARD_DENY_PREFIXES`: 35 secret patterns including `AWS_*`, `GITHUB_*`, `OPENAI_*`, `ANTHROPIC_*`, SSH keys, and auth tokens) and normalizes `$PATH` to prevent directory traversal and binary hijacking.
- **Secret Masking Overlays**: High-risk paths (`~/.ssh`, `~/.aws`, `.env*`, `*.pem`, `*.key`) are masked with mode-000 tmpfs overlays or `/dev/null` binds.
- **Gated Network Egress**: Network namespaces maintain loopback-only visibility under `--net off`. When domain egress is granted, traffic routes through an in-process TCP broker with DNS pinning.
- **Fail-Closed Guarantees**: If any requested boundary or kernel security primitive is unavailable, vetto exits immediately with code `125` (`EXIT_FAIL_CLOSED`) rather than running unconfined.

---

## Installation

### Quick Install Script (Linux, macOS, WSL2)
Install the official pre-compiled standalone binary to `~/.local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

System-wide installation:
```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh -s -- --system
```

### Cargo (crates.io)
Compile and install directly from crates.io:

```bash
cargo install vetto --locked
```

### NPM Global Package
Install as a global Node.js binary wrapper with bundled native executables:

```bash
npm install --global @shledery/vetto
```

### Homebrew (macOS & Linux)
```bash
brew tap shleder/vetto
brew install vetto
```

### Docker / Containerized Workflows
To run vetto inside CI containers or Docker devcontainers, ensure unprivileged user namespaces are enabled:

```bash
docker run --rm -it --security-opt seccomp=unconfined ghcr.io/shleder/vetto:0.2.25 vetto doctor
```

*Every release binary is attested with **SLSA Level 3 Provenance** and signed with **Minisign** (Key ID `75ECEC9B5080C590`). Pre-built archives and CycloneDX 1.5 SBOMs are published on [GitHub Releases](https://github.com/shleder/vetto/releases).*

---

## Quickstart & Common Commands

### 1. Diagnose Environment & Permissions
Verify platform capabilities, kernel LSM status, and isolation readiness:

```bash
vetto doctor
```
Add `--fix` to display OS-specific remediation commands for missing primitives:
```bash
vetto doctor --fix
```

### 2. Run Commands Under the Sandbox
Execute any arbitrary command or agent under the default strict sandbox:

```bash
# Execute command under default strict sandbox
vetto run -- python script.py

# Direct shortcut syntax
vetto -- npm test
```

### 3. Wrap Commands with Developer Profiles
Use developer profiles for full toolchain compatibility:

```bash
# Run with the 'dev' profile (permits compiler & package caches)
vetto wrap --profile dev -- cargo test

# Shortcut using direct execution flag
vetto --profile dev -- go test ./...
```

### 4. Inspect, Lint & Explain Policies (`vetto policy`)
Deeply inspect active policy boundaries, cryptographic digests, and lint for configuration hazards:

```bash
# Check configuration and verify policies without spawning
vetto check

# Lint policy rules for security hazards (broad grants, overlapping secrets)
vetto policy lint
# Or run with strict enforcement
vetto policy lint --strict

# Explain resolved policy boundaries, BLAKE3 contract digest, and resource limits
vetto policy explain
# Output machine-readable JSON format
vetto policy explain --json

# Run throwaway leak-detection battery on current policy
vetto verify

# Inspect blocked filesystem attempts, syscalls, and network egress from past runs
vetto audit --latest

# Print post-session security recap
vetto audit --latest --recap
```

### 5. Transparent Agent Shims (`vetto enable`)
Activate zero-overhead transparent shims for your AI coding assistant:

```bash
# Enable transparent sandbox wrapping for your agent
vetto enable claude        # Claude Code
vetto enable codex         # OpenAI Codex CLI
vetto enable cursor        # Cursor Agent
vetto enable windsurf      # Codeium Windsurf
vetto enable opencode      # OpenCode CLI
vetto enable aider         # Aider

# Now run your agent normally — it runs sandboxed under the hood!
claude --dangerously-skip-permissions
codex exec --full-auto

# Inspect or disable shims
vetto enable --status
vetto disable claude
```

### 6. Dynamic Policy Grants (No Manual TOML Editing)
When an agent requires additional access during execution, grant permissions instantly:

```bash
vetto allow ./target                    # Grant read+write to a folder
vetto allow --read-only /usr/share/doc  # Grant read-only access
vetto allow --net api.github.com        # Allow egress to domain
vetto deny ~/.aws/credentials           # Mask sensitive file
```

---

## Security & Profile Model

Policies in vetto are hierarchical, additive, and strictly typed. Unknown configuration keys fail closed.

### Built-in Security Profiles

| Profile | Target Use Case | Filesystem Bounds | Network Egress | Resource Ceilings |
| :--- | :--- | :--- | :--- | :--- |
| **`strict`** *(default)* | Untrusted scripts, unattended autonomous agent runs | `$PROJECT` and `/dev/null` only; `/tmp` writes denied; secrets masked | Denied (`--net off`) | Strict: 1h CPU, 8GB RAM, 256 procs, 1024 FDs |
| **`dev`** | Active interactive development with compilers and tools | `$PROJECT`, `/tmp`, and standard build tool caches (`~/.cargo`, `~/.npm`) | Denied or provider allowlist | Balanced developer ceilings |
| **`network-isolated`** | Hermetic builds, compliance auditing, zero-leak validation | `$PROJECT` and `/tmp`; read-only system tools | Completely disabled (`CLONE_NEWNET` / SBPL deny) | Default limits |
| **`ci`** | GitHub Actions, GitLab CI, headless evaluation pipelines | Workspace root; automated report output directory | Allowlisted or off | Headless, `--tui none`, JSON summary on stdout |

For complete threat surface documentation and policy syntax:
- [Threat Model & Boundary Guarantees](docs/threat-model.md)
- [Profile Inheritance & Agent Presets](docs/profiles.md)
- [Platform Backends & Parity Matrix](docs/platform-backends.md)
- [Exit Codes Specification](docs/exit-codes.md)

---

## AI Agent Ecosystem Roster

vetto includes 20 native agent presets with automatic credential isolation, configuration path allowlisting, and zero-config network profiles:

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
Isolate third-party MCP servers connected to Claude Desktop or Codex Desktop:

```bash
vetto mcp wrap --allow ./data --allow-read /usr/share --net off -- <mcp-server-binary> [args...]
```

---

## Comparison: vetto vs. Alternatives

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

---

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

## License

vetto is distributed under the dual **Apache-2.0 / MIT** license.

See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for full terms.
