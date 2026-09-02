<div align="center">

# VETTO — Daemon-less, 0ms sandbox for AI coding agents

<p align="center">
  <b>Run Claude Code, Codex, and Cursor unattended with zero credential-leak anxiety.</b><br/>
  <i>Enforced directly by Linux Landlock &amp; Seccomp. No Docker, no root, no daemon.</i>
</p>

[![Release](https://img.shields.io/github/v/release/shleder/vetto?include_prereleases&label=release&color=blue&style=flat-square)](https://github.com/shleder/vetto/releases)
[![npm version](https://img.shields.io/npm/v/%40shledery%2Fvetto?logo=npm&label=npm&style=flat-square)](https://www.npmjs.com/package/@shledery/vetto)
[![CI](https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/shleder/vetto/actions/workflows/ci.yml)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)](#platform-support)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Fail-Closed](https://img.shields.io/badge/fallback-none%20%2F%20fail--closed-success?style=flat-square)](#honest-status)

<br/>

![Vetto Demo](assets/demo.svg)

</div>

---

## Stop Fearing `--dangerously-skip-permissions`

AI coding agents write impressive code, but running them unprompted on your local workstation is terrifying:
a single hallucination, rogue bash loop, or prompt injection can exfiltrate your `~/.ssh` keys, wipe your home directory (`rm -rf ~`), or leak `.env` secrets.

**VETTO** wraps Claude Code, Codex, Antigravity, Cursor, and Aider in an OS-level kernel sandbox **before the agent process starts**:
- **Zero Credential Theft**: `~/.ssh`, `~/.aws`, `~/.gnupg`, and `.env*` are physically unreadable by the agent.
- **Zero Destructive Writes**: Agent file modifications are strictly confined to your project root and `/tmp`.
- **Zero Performance Penalty**: **0.002s** startup latency, 0 MB idle RAM, unprivileged execution without Docker.

---

## Installation

Choose your preferred installation method:

```bash
# Standalone POSIX script (Linux, macOS, WSL2 — zero dependencies)
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | bash
```

```bash
# Via npm (global binary for Node.js environments)
npm install --global @shledery/vetto
```

```bash
# Via Cargo (crates.io — compiled from source)
cargo install vetto --locked
```

```bash
# Via Homebrew (macOS & Linux)
brew install shleder/tap/vetto
```

```bash
# Run one-off without installing (npx)
npx @shledery/vetto doctor
```

*Prebuilt standalone archives with SHA256 checksums and CycloneDX SBOMs for all architectures (`x86_64`, `aarch64`, Windows `.zip`, Linux/macOS `.tar.gz`) are published on [GitHub Releases](https://github.com/shleder/vetto/releases).*

---

## Quick Start

Protect your workstation and run any AI coding agent unattended in seconds:

### 1. Enable Your Agent
```bash
# Wrap any agent of choice (creates transparent zero-overhead shims):
vetto enable codex         # OpenAI Codex CLI
vetto enable claude        # Claude Code
vetto enable antigravity   # Antigravity CLI
vetto enable cursor        # Cursor Agent
vetto enable aider         # Aider
```
*Creates transparent, zero-latency shims in `~/.vetto/shims/` and configures shell PATH priority.*

### 2. Run Completely Unattended
Launch your agent with full autonomy:
```bash
# OpenAI Codex
codex exec --full-auto

# Claude Code
claude --dangerously-skip-permissions

# Antigravity CLI
antigravity run --autonomous

# Aider
aider --yes

# Or run any custom binary / agent directly inside vetto:
vetto -- <agent> [args...]
```
*Files outside the workspace are blocked, host credentials (`~/.ssh`, `~/.aws`, `.env`) are masked, and network egress is locked down to provider APIs.*

To check wrapped status or unwrap at any time:
```bash
vetto enable --status      # Check all active shims
vetto disable <agent>      # Unwrap agent (e.g. vetto disable codex)
```

---

## Why Not Docker?

Containers were designed for packaging backend microservices—not for interactive developer coding loops. Vetto enforces OS-level kernel confinement directly around your host processes:

| Dimension | VETTO | Docker Containers | Why It Matters |
| :--- | :--- | :--- | :--- |
| **Startup Overhead** | **0.002s** (effectively 0ms) | **3.5s – 8.0s** | Subagents and test loops execute with zero perceptible latency |
| **Daemon** | **None** (zero background processes) | `dockerd` background service | No background daemon to crash, stall, or consume idle resources |
| **RAM Overhead** | **0 MB** | **1.5 GB+** (VM / daemon engine) | Leaves all workstation RAM free for compilation and local models |
| **Permissions** | **Unprivileged** (no root / no sudo) | Root / `docker` group (root-equivalent) | Completely eliminates root-escalation attack surface on your host |
| **Host File Sync** | **Native Filesystem** (instant) | Volume mounts (slow I/O, UID sync bugs) | Edits, hot-reloading, and git diffs reflect immediately |
| **Kernel Barrier** | **Linux Landlock + Seccomp-BPF** | Namespaces + cgroups | In-process confinement applied before `execve`, strictly fail-closed |
| **Network Egress** | **Per-Domain Allowlist** (`api.anthropic.com`) | All-or-nothing bridge | Prevents unauthorized data exfiltration without breaking inference |

---

## Platform Reality (Zero Snake Oil)

Security tooling frequently makes deceptive cross-platform claims. Vetto is architecturally transparent about what each operating system kernel can and cannot enforce:

| Operating System | Enforcement Primitives | Read Isolation (`~/.ssh`, `.env`) | Write Isolation (Host/System) | Network Allowlist | Security Tier |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Linux (Native)** | **Landlock ABI (v1–v6)** + **Seccomp-BPF** + **NetNS** | **100% Kernel Deny** | **100% Locked to Project** | **Per-Domain Broker** | **Tier 1 (Complete Boundary)** |
| **Windows WSL2** | **Linux Landlock via WSL2 Kernel** | **100% Kernel Deny** | **100% Locked to Project** | **Per-Domain Broker** | **Tier 1 (Recommended for Windows)** |
| **macOS (Darwin)** | **Apple Seatbelt (`libsandbox`)** + **Kqueue** | **Broad Reads (SBPL bug)** | **100% System Protected** | **`--net=off` Lockdown** | **Tier 2 (Write Safety & Ceilings)** |
| **Windows Native** | **Job Objects** + **Restricted Tokens** | **ACL Fallback** | **Workspace Only** | **Host Firewall Rules** | **Tier 3 (Process Guardrails)** |

> **The Honest macOS Disclosure**:
> Apple has deprecated SBPL (`sandbox-exec`) and deliberately restricts unprivileged file-read denial in modern Darwin kernels. Any tool claiming unprivileged read-masking on macOS without SIP bypass is misleading you.
> **Recommendation**: If you require hardware-enforced, 100% kernel read-denial for SSH and AWS credentials on a Mac, run your agent with Vetto inside **OrbStack**, a lightweight Linux VM, or Docker devcontainer. On host macOS, Vetto guarantees write safety, network lockdown, and watchdog termination.

---

## Ecosystem Integration Guides

Vetto natively integrates with modern AI coding workflows:

| Agent / Tool | Guide & Details | Setup Command |
| :--- | :--- | :--- |
| **Claude Code** | [Claude Code Guide](docs/integrations/claude-code.md) · Unprompted mode, `PreToolUse` hook, Anthropic API allowlist | `vetto enable claude` |
| **Cursor** | [Cursor Guide](docs/integrations/cursor.md) · Agent & Composer sandboxing, terminal execution, storage masking | `vetto enable cursor` |
| **Cline** | [Cline Guide](docs/integrations/cline.md) · VS Code extension terminal task isolation, zero-config shims | `vetto hook install` |
| **Aider** | [Aider Guide](docs/integrations/aider.md) · Zero-config network allowlists, git protection, automated tests | `vetto enable aider` |
| **OpenCode & Codex** | [OpenCode Guide](docs/integrations/opencode.md) · CLI runners, subagent supervision, and model sandboxing | `vetto enable codex` |
| **Claude Desktop & Codex Desktop** | [Desktop Integration Guide](docs/integrations/desktop.md) · Native MCP server (`vetto mcp`), terminal shims, sandboxed subtools | `vetto mcp` · `vetto enable` |

---

## Boundary Verification & Audit

Trust nothing—verify the sandbox boundary and audit past operations:

```bash
# Probe running kernel capabilities (Landlock ABI, seccomp, userns)
vetto doctor

# Run active leak battery (tests secret paths and loopback isolation)
vetto verify

# Inspect effective policy and test path blocks
vetto policy explain
vetto policy explain --why ~/.ssh/id_rsa

# Inspect intercepted security violations and blocked paths from past sessions
vetto audit
vetto audit --latest
```

### Dynamic Policy Grants (No Manual TOML Editing)
When an agent is blocked from accessing a legitimate project path, Vetto prints an immediate grant command:

```bash
vetto allow ./vendor                    # Grant read+write to a folder
vetto allow --read-only /usr/share/doc  # Grant read-only access
vetto allow --net registry.npmjs.org    # Allow egress to a package registry
vetto deny ~/.aws/credentials           # Explicitly mask a secret file
```

---

## Advanced CLI Execution

Beyond transparent `vetto enable` shims, you can run one-off commands or custom agents directly:

```bash
# Auto-detect agent in current workspace and run inside sandbox
vetto

# Explicit command supervision
vetto -- claude -p "fix failing tests"
vetto -- aider --model sonnet
vetto -- codex exec "refactor auth module"

# Security presets: balanced (default) | paranoid | yolo
vetto --preset paranoid -- npm test

# Network modes: off (default) | allowlist:<domains> | strict:<host:port>
vetto --net allowlist:api.anthropic.com,github.com -- cargo check
vetto --net strict:github.com:22 --git-ssh -- git fetch origin

# Output detailed HTML / SARIF audit reports
vetto --report html,sarif --jsonl session.jsonl -- cargo test
```

---

## What Vetto Deliberately Excludes

- **No background daemon** — zero idle CPU, zero RAM consumption, no service to stall or crash.
- **No root / sudo** — runs completely unprivileged; cannot escalate host permissions.
- **No TLS interception** — zero MITM, no custom root certificate authority; moves opaque bytes only.
- **No telemetry or tracking** — completely private by default; zero network calls home.
- **No Docker dependency** — instant 0.002s startup directly on your native OS kernel.

---

<details>
<summary><b>Deep Architecture & Kernel Enforcement (Click to expand)</b></summary>

### 1. The Fail-Closed Discipline
Vetto puts the agent process inside an OS-level sandbox **before the agent process starts**. The foundational guarantee of Vetto is fail-closed execution:
> **If the requested boundary cannot be established on the current host, `vetto` exits immediately instead of starting the agent.** There is no fallback to an unconfined process anywhere in the codebase.

### 2. Linux Landlock LSM & Seccomp-BPF
- **Landlock ABI Negotiation**: Automatically negotiates Landlock ABI versions 1 through 6 with the running kernel. Landlock restricts filesystem operations (`open`, `read`, `write`, `unlink`, `rename`) directly in kernel space.
- **Seccomp-BPF**: Enforces fine-grained syscall restrictions before `execve`. Disallowed syscalls receive `EPERM` or `ENOSYS`.
- **Secret Masking (`display_only_deny`)**: Because Landlock is a pure allowlist and cannot subtract subpaths from an allowed directory tree, Vetto masks secret files (such as `~/.ssh`, `~/.aws`, `~/.gnupg`, `.env`, tokens) by mounting an empty tmpfs or `/dev/null` over them on the Linux `full` tier, or by carving them out of generated read allowlists.
- **Path Resolution**: Symlinks and globs are expanded to concrete filesystem paths before rules reach the kernel. Patterns never reach the kernel.

### 3. In-Process Network Relay Broker
- **Network Namespaces**: When network filtering is enabled (`--net=allowlist:...`), Vetto isolates the child process in a dedicated Linux network namespace with only a loopback device.
- **Broker Relay**: Outbound TCP connections route through an in-process local CONNECT/SOCKS broker.
- **DNS Validation & Anti-Rebinding**: The host broker performs DNS resolution itself and pins addresses per rule. Any DNS response resolving to private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`) is rejected.
- **Zero TLS MITM**: The broker moves opaque bytes. There is no TLS interception, no custom certificate authority, and no MITM proxy.

### 4. Recursion Barriers & Transparent Shims
- When `vetto enable <agent>` creates shims in `~/.vetto/shims`, recursion barriers (`VETTO_WRAPPED`, `VETTO_SANDBOXED`, `VETTO_SHIM_ACTIVE`) guarantee that subagent tool invocations (such as an agent invoking `git`, `python`, or nested compiler toolchains) resolve directly to real host binaries without recursive supervisor overhead or infinite loops.
- `vetto enable` refuses to overwrite non-Vetto binaries without `--force`.

### 5. Policy Layer Hierarchy
Policies merge in a deterministic, strict hierarchy where every TOML struct rejects unknown fields:
```text
Host Global (~/etc/vetto/config.toml)
  └── User Global (~/.vetto/config.toml)
        └── Built-in Profile (default, strict, paranoid)
              └── Agent Preset (claude, cursor, aider, cline, codex)
                    └── Project Policy (./vetto.toml + policy.d/)
                          └── Local Override (./vetto.local.toml)
                                └── CLI Overrides (--allow, --net, --limits)
```

</details>

---

<details>
<summary><b>Session Rescue & Diagnostics (Click to expand)</b></summary>

Recover interrupted, frozen, or corrupted agent sessions without losing progress:

```bash
# Scan recent sessions
vetto rescue --json scan --limit 25

# Diagnose Claude Code or Cursor sessions
vetto rescue --adapter claude diagnose <session-id>
vetto rescue --adapter cursor snapshot <session-id> --output ./recovered.jsonl

# Rollback a failed repair
vetto rescue rollback --receipt <receipt-path>
```

Adapters supported: `claude`, `cursor`, `codex`. Snapshots are verified with SHA-256 and created strictly outside the original state root.
</details>

---

## Documentation

- [Architecture & Startup Order](ARCHITECTURE.md)
- [Docker vs. Vetto Comparison](docs/comparison.md)
- [Claude Code Integration](docs/integrations/claude-code.md)
- [Cursor Integration](docs/integrations/cursor.md)
- [Cline Integration](docs/integrations/cline.md)
- [Aider Integration](docs/integrations/aider.md)
- [Claude & Codex Desktop Integration](docs/integrations/desktop.md)
- [Threat Model](docs/threat-model.md)
- [Network Internals](docs/network.md)
- [Platform Backends](docs/platform-backends.md)
- [Exit Codes Reference](docs/exit-codes.md)
- [Security Policy](SECURITY.md) · [Changelog](CHANGELOG.md)

---

## License

Apache-2.0 — see [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
