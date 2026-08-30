# Compatibility Matrix: Agents, Platforms, and Tiers

This matrix documents the verified isolation levels, platform primitives, and feature support across AI coding agents supervised by `vetto`.

---

## 1. Host Platform & Isolation Tiers

| Platform | Recommended Tier | Kernel Primitives | Secret Isolation | Network Controls | Process Tree Cleanup |
|---|---|---|---|---|---|
| **Linux x86_64** (Kernel >= 5.13) | **Tier FULL** | Landlock (ABI 1–5), unprivileged userns, PID/net namespaces, seccomp-BPF | Empty tmpfs & `/dev/null` bind-mount overlays | Broker relay with domain/port strict allowlist | PID namespace init reaps all descendants |
| **Linux aarch64** (Kernel >= 5.13) | **Tier FULL** | Landlock (ABI 1–5), unprivileged userns, PID/net namespaces, seccomp-BPF | Empty tmpfs & `/dev/null` bind-mount overlays | Broker relay with domain/port strict allowlist | PID namespace init reaps all descendants |
| **Linux (Legacy/Restricted)** | **Tier FS-ONLY** | Landlock (ABI 1–5), seccomp-BPF (userns disabled) | Read allowlist carve-out (fail-closed) | Disabled by default (fail-closed for relay) | `PR_SET_PDEATHSIG` + Process Group |
| **macOS Apple Silicon** (macOS 14+) | **macOS Backend** | `sandbox-exec` / Seatbelt (write-isolation), FSEvents | Seatbelt path deny rules for credentials | In-process proxy broker + Loopback restriction | Child process tree termination |
| **macOS Intel** (macOS 14+) | **macOS Backend** | `sandbox-exec` / Seatbelt (write-isolation), FSEvents | Seatbelt path deny rules for credentials | In-process proxy broker + Loopback restriction | Child process tree termination |
| **Windows 11 x86_64** | **Windows Backend** | AppContainer, Low-Integrity Token, Job Object kill-on-close | Token ACL isolation & deny SID rules | Host broker relay with Windows Firewall integration | Job Object `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` |

---

## 2. AI Coding Agents Compatibility

| Agent Name | Preset Flag | Tested Execution Method | Secret Masking | Network Broker | PTY Statusline | Verify Battery |
|---|---|---|---|---|---|---|
| **Claude Code** | `--agent claude` | `claude -p "..."` / `npx @anthropic-ai/claude-code` | ✅ Verified | ✅ `--net=allowlist:api.anthropic.com` | ✅ Full TUI & Statusline | ✅ 100% Pass |
| **OpenAI Codex** | `--agent codex` | `codex exec "..."` | ✅ Verified | ✅ `--net=allowlist:api.openai.com` | ✅ Full TUI & Statusline | ✅ 100% Pass |
| **Cursor Agent** | `--agent cursor` | `cursor-agent "..."` | ✅ Verified | ✅ Allowlisted API targets | ✅ Statusline | ✅ 100% Pass |
| **Cline** | `--agent cline` | `cline --prompt "..."` | ✅ Verified | ✅ Allowlisted API targets | ✅ Statusline | ✅ 100% Pass |
| **Aider** | `--agent aider` | `aider --message "..."` | ✅ Verified | ✅ Allowlisted API targets | ✅ Full PTY | ✅ 100% Pass |
| **GitHub Copilot** | `--agent copilot` | `copilot "..."` | ✅ Verified | ✅ Allowlisted GitHub endpoints | ✅ Statusline | ✅ 100% Pass |
| **OpenCode** | `--agent opencode` | `opencode "..."` | ✅ Verified | ✅ Allowlisted model endpoints | ✅ Statusline | ✅ 100% Pass |
| **Custom Agent / Shell** | (Default) | `vetto -- <command> [args...]` | ✅ Strict-Wins | ✅ Mode-dependent | ✅ Configurable | ✅ 100% Pass |

---

## 3. Sandboxing Feature Support by Tier

| Capability | Linux Tier FULL | Linux Tier FS-ONLY | macOS Seatbelt | Windows AppContainer |
|---|:---:|:---:|:---:|:---:|
| **Filesystem Write Protection** | ✅ Hard Inode Enforced | ✅ Hard Inode Enforced | ✅ Sandbox-exec Policy | ✅ Access Control Token |
| **Secret File Overlays (`.env`)** | ✅ Masked with tmpfs | ⚠️ Read-carveout | ✅ Path-deny rules | ✅ Capability ACL |
| **Network Isolation (`--net=off`)** | ✅ Isolated Netns | ✅ Seccomp socket block | ✅ Deny network rule | ✅ AppContainer network cap |
| **Domain Allowlist Broker** | ✅ Unix Bridge Relay | ❌ (Requires Tier FULL) | ✅ Local Proxy Relay | ✅ Local Broker |
| **Cross-Process `ptrace` Block** | ✅ Seccomp-BPF | ✅ Seccomp-BPF | ✅ Hardened Runtime | ✅ Restricted Token |
| **Post-Session Audit Reports** | ✅ HTML/MD/JSON/SARIF | ✅ HTML/MD/JSON/SARIF | ✅ HTML/MD/JSON/SARIF | ✅ HTML/MD/JSON/SARIF |
| **Mathematical Preflight (`verify`)**| ✅ Throwaway Sandbox | ✅ Throwaway Sandbox | ✅ Throwaway Sandbox | ⚠️ Capability Probe |
| **Session Rescue & Rollback** | ✅ Full Support | ✅ Full Support | ✅ Full Support | ✅ Full Support |

---

*This document is automatically verified and updated by CI.*
