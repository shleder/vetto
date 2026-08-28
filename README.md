# vetto

<p align="center">
  <strong>Your AI agent runs with your tokens, your files, and your network.</strong><br>
  <code>vetto</code> enforces an operator-controlled OS security boundary around it — before the process exists.<br>
  <em>If the kernel boundary cannot be established, nothing launches.</em>
</p>

<p align="center">
  <a href="https://github.com/shleder/vetto/actions/workflows/ci.yml"><img src="https://github.com/shleder/vetto/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status"></a>
  <a href="https://www.npmjs.com/package/@shledery/vetto"><img src="https://img.shields.io/npm/v/%40shledery%2Fvetto?logo=npm&color=2ea44f&label=npm" alt="npm version"></a>
  <a href="#platforms"><img src="https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-blue" alt="platforms"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0"></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/telemetry-zero-success" alt="Zero telemetry"></a>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> •
  <a href="#why-vetto">Why Vetto</a> •
  <a href="#subagent-isolation">Subagent Guard</a> •
  <a href="#controls">Controls</a> •
  <a href="#platforms">Platform Matrix</a> •
  <a href="#rescue">Session Rescue</a> •
  <a href="#anti-features">Guarantees</a> •
  <a href="SECURITY.md">Security</a>
</p>

---

<a id="why-vetto"></a>

## Why Vetto

Every local AI coding agent you launch (**Codex**, **Claude Code**, **Cursor**, **Aider**, **Copilot**) inherits your complete ambient privilege: private SSH keys, cloud credentials, tokens in environment variables, read/write access to your entire filesystem, and an open outbound network route.

Agent-native sandboxes provide helpful defense-in-depth, but their policies, platform support, and permission boundaries differ. **Vetto provides a unified, deterministic, kernel-enforced perimeter around the agent.**

```text
┌───────────────────────────────────────────────────────────────────────┐
│ OPERATOR PERIMETER (VETTO)                                            │
│                                                                       │
│  • Landlock / Seatbelt (read-only project + secret masking)           │
│  • Isolated PID & Network Namespaces (default-deny net)               │
│  • Seccomp System Call Filter (blocks ptrace, io_uring, socket abuse) │
│                                                                       │
│     ┌───────────────────────────────────────────────────────────┐     │
│     │ AGENT RUNTIME (Codex / Claude Code / Cursor / Aider)      │     │
│     │                                                           │     │
│     │   Subagent Worker ──x [BLOCKED: Parent IPC & Control]     │     │
│     │   Tool Output     ──x [BLOCKED: Unconstrained Dumps]      │     │
│     │                                                           │     │
│     └───────────────────────────────────────────────────────────┘     │
└───────────────────────────────────────────────────────────────────────┘
```

| Security Vector | Without Vetto | With Vetto |
| :--- | :--- | :--- |
| **Credential Access** | Agent reads `~/.ssh`, `~/.aws`, `.env`, `.git-credentials` | **Masked & Denied**: Files mapped to `/dev/null`, directories empty |
| **Network Exfiltration** | Unrestricted outbound HTTP/SOCKS/raw TCP connections | **Default-Off**: Pinned domain allowlist relay (Linux FULL) |
| **Subagent Privilege Leaks** | Child tasks inherit control sockets and mutate other threads | **Isolated**: IPC sockets (`*.sock`, `*.ipc`) and state DBs blocked |
| **Tool Output Poisoning** | Heavy base64 images and memory dumps crash CLI/TUI | **Sanitized**: Memory dumps and oversized payloads classified |
| **Failure Mode** | Silent fallback to unconfined execution | **Fail-Closed**: If kernel sandbox cannot apply, process never launches |

> [!IMPORTANT]
> **No boundary, no process.** If the requested security policy cannot be established on the current host, Vetto aborts before spawning the agent. It never falls back to an unconfined process.

---

### Real Capability Probing (`vetto doctor`)

Vetto inspects actual host kernel capabilities at runtime instead of assuming environment support:

```console
$ vetto doctor
vetto v0.2.3 doctor
landlock:                available (ABI 4/5)
unprivileged userns:     yes
full namespace stack:    yes
seccomp filters:         yes
seccomp user-notify:     yes
audit feed readable:     no
chosen tier:             full
```

```text
  01. RESOLVE POLICY       02. PROBE HOST          03. INSTALL BOUNDARY      04. EXECUTE AGENT
┌─────────────────────┐  ┌────────────────────┐  ┌───────────────────────┐  ┌─────────────────────┐
│ Base + Org + Local  │─▶│ Kernel Landlock    │─▶│ Apply VFS & Net Gates │─▶│ Spawn Agent Subtree │
│ Rules & Deny Config │  │ ABI v1–5 & Seccomp │  │ [Fail-Closed Halt]    │  │ (Inherited Sandbox) │
└─────────────────────┘  └────────────────────┘  └───────────────────────┘  └─────────────────────┘
```

---

<a id="subagent-isolation"></a>

## Subagent Capability Isolation & Socket Guard

Autonomous agents often spawn child subagents to perform background research, tool execution, or code review. In complex multi-agent graphs, subagents can inadvertently access parent IPC sockets, control plane APIs, or mutate unrelated user sessions.

Vetto isolates the entire process subtree:

```toml
# Built-in agent presets automatically mask parent control surfaces:
[display_only_deny]
paths = [
    "$AGENT/auth.json",
    "$AGENT/app_server.sock",
    "$AGENT/*.sock",
    "$AGENT/*.ipc",
    "$AGENT/state_*.sqlite",
]
```

- **IPC Boundary Enforcement**: Subagents cannot connect to parent app servers or Unix domain sockets (`codex_app.sock`, `claude_code.sock`, `vscode-ipc-*.sock`).
- **Debugger & DevTools Port Protection**: Network attempts targeting browser debugging ports (`9222`, `9229`, `5678`) are intercepted.
- **Interception Tool Shield**: Spawning raw network manipulation tools (`socat`, `ncat`, `chisel`, `tcpdump`) triggers immediate high-severity security alerts.

---

<a id="quickstart"></a>

```console
$ vetto --profile strict -- codex exec "inspect credentials & deploy"

[vetto] OS sandbox applied: Landlock ABI v5, Seccomp-BPF, UserNS (0.8ms)
[agent] Reading credentials: cat ~/.ssh/id_rsa ~/.aws/credentials
[vetto] [BLOCKED] VFS Mask: ~/.ssh/id_rsa mapped to /dev/null (0 bytes returned)
[agent] Probing AWS metadata: curl -s http://169.254.169.254/latest/meta-data/
[vetto] [BLOCKED] Net Deny: 169.254.169.254:80 [EPERM: Network unreachable]
[agent] Dumping tokens: OPENAI_API_KEY=sk-proj-9A8f7B2... ghp_9381kLz...
[vetto] [PTY REDACT] Entropy filter scrubbed 2 secret tokens -> [REDACTED]
─────────────────────────────────────────────────────────────────────────────
✓ Operator boundary held: 0 leaks, 0 disk bloat, 0 unconfined processes.
```

## Quickstart

Install globally with npm (includes prebuilt native binaries for Linux, macOS, Windows):

```bash
npm install --global @shledery/vetto
vetto doctor
```

Or run instantly without installation:

```bash
npx @shledery/vetto doctor
```

### 2. Wrap Your Agent

```bash
# OpenAI Codex
vetto --agent codex --profile default -- codex exec "refactor database query"

# Claude Code
vetto --agent claude --profile strict -- claude -p "fix failing test"

# Cursor / Aider / OpenCode / Custom script
vetto -- aider
vetto -- opencode
vetto -- python my_agent.py
```

### 3. TUI & Display Modes

- **Statusline (Default)**: Preserves the agent's interactive PTY while dedicating a 1-row status bar for real-time sandbox telemetry.
- **Full Dashboard (`--tui=full`)**: Dedicated fullscreen terminal dashboard with real-time file access graph, blocked attempts, and network metrics.
- **Headless / CI (`--tui=none` / `--ci`)**: Formatted for CI/CD pipelines, outputting structured logs and SARIF reports.

---

<a id="controls"></a>

## What the Boundary Controls

| Surface | Linux (FULL) | macOS (Seatbelt) | Windows (AppContainer) |
| :--- | :--- | :--- | :--- |
| **Filesystem Read** | Additive allowlist via Landlock ABI 1-4 | Seatbelt profile allowlist | Capability-gated directory permissions |
| **Secret Masking** | File-bind `/dev/null` + tmpfs overlays | Blocked via Seatbelt rules | Path exclusion validation |
| **Process Hardening** | Seccomp: blocks `ptrace`, `bpf`, `io_uring` | Sandbox containment | Low-integrity token + Job Object |
| **Network Perimeter** | Default-off / Verified domain allowlist relay | Default-off spawn path | Network-off token restriction |
| **Environment Clean** | Rebuilt from minimal allowlist | Rebuilt from minimal allowlist | Rebuilt from minimal allowlist |
| **Audit Logging** | SQLite audit log + SARIF export | SQLite audit log + SARIF export | SQLite audit log + SARIF export |

### Network Relay Modes (Linux FULL)

```bash
# Complete network isolation (Default)
vetto --net=off -- agent_command

# Proxy-aware domain allowlist
vetto --net=allowlist:api.github.com,registry.npmjs.org -- agent_command

# Strict host and port binding
vetto --net=strict:registry.npmjs.org:443 -- agent_command

# Pinned Git over SSH relay
vetto --net=strict:github.com:22 --git-ssh -- git fetch origin
```

---

<a id="platforms"></a>

## Platform Matrix

| Platform | Tier | Backend Primitives | Status |
| :--- | :--- | :--- | :--- |
| **Linux x86_64 / ARM64** | **FULL** | Landlock + User/Mount/PID/Net/IPC namespaces + Seccomp-BPF | **Tier 1 (Complete)** |
| **Linux (Restricted)** | **FS-ONLY** | Landlock + Seccomp (for hosts lacking unprivileged namespaces) | **Tier 1 (Filesystem-only)** |
| **macOS Apple Silicon / Intel** | **Seatbelt** | Dynamic Seatbelt profile (`sandbox-exec`) + FSEvents observer | **Tier 1 (Native)** |
| **Windows 11 x64** | **AppContainer** | Windows 11 Process Sandbox API + Low Integrity + Job Object | **Tier 2 (Experimental)** |

---

<a id="rescue"></a>

## Session Rescue (Recovery Engine)

Vetto embeds a provider-neutral, **read-only and transactional recovery engine** for corrupted, interrupted, or damaged agent sessions across **Claude Code**, **OpenAI Codex**, and **Cursor**:

```bash
# 1. Multi-Agent Discovery: scan and diagnose local session health
vetto rescue --adapter claude --root ~/.claude --json scan
vetto rescue --adapter codex --root ~/.codex diagnose
vetto rescue --adapter cursor --root ~/.config/Cursor scan

# 2. Transactional WAL Checkpointing: safely clear stale locks ('already has an active writer')
vetto rescue --adapter codex checkpoint ~/.codex/sessions/.../rollout.jsonl

# 3. Non-destructive Sanitized Snapshots
vetto rescue --adapter claude snapshot session.jsonl --output ./recovered_session.jsonl
```

- **Guarantees**: Never exposes credentials, follows symlinks, or mutates original state files without transactional receipts.

---

<a id="hooks"></a>

## Transparent Shell & Git Auto-Wrapping (`vetto hook`)

Instead of manually prefixing every command, install transparent shell and Git hooks to automatically sandbox subagents:

```bash
# Install transparent shim dispatcher into ~/.local/bin/vetto-shims
vetto hook install

# Inspect active hooks and recursive sandbox barriers
vetto hook status

# Uninstall and restore pristine PATH
vetto hook uninstall
```

---

<a id="anti-features"></a>

## Honest Limits & Deliberate Anti-Features

### Deliberate Anti-Features
- **No Background Daemon**: No long-running services, background daemons, or root helper processes.
- **Zero Telemetry**: No cloud connections, analytics pings, or data collection.
- **No TLS Interception**: No custom root CAs, MITM proxies, or certificate tampering.
- **No Docker/VM Requirement**: Native kernel primitives execute with near-zero runtime latency.

### Known Boundaries
- Observation feeds (e.g. FSEvents, `/proc` poller) provide visibility, not enforcement authority. The kernel sandbox is the sole security authority.
- Linux FS-ONLY tier provides filesystem and seccomp containment, but lacks complete PID/Network namespace isolation.

---

## Documentation

- [Architecture & Startup Lifecycle](ARCHITECTURE.md)
- [Threat Model & Security Policy](SECURITY.md)
- [Platform Backends & Capability Details](docs/platform-backends.md)
- [CI/CD & GitHub Actions Integration](docs/ci-cd.md)
- [Network Topologies & Broker Details](docs/network.md)

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
