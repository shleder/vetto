# Sandboxing Cursor with Vetto

[Cursor](https://cursor.com) is an AI-first IDE equipped with autonomous Agent and Composer capabilities that write code and execute terminal commands across your project.

By wrapping Cursor with **Vetto**, you can run Cursor Agent in fully autonomous mode ("YOLO" mode) without credential-leak anxiety. Vetto's OS-level kernel boundaries enforce strict filesystem isolation, secret masking, and network allowlists at zero runtime cost.

---

## 1. Quick Start (Zero-Config)

### Step 1: Enable Cursor Wrapping
```bash
vetto enable cursor
```

This performs the following zero-friction steps:
1. Resolves the real `cursor` binary location on your machine.
2. Installs a high-priority shim at `~/.vetto/shims/cursor`.
3. Injects PATH hooks into your shell profile (`~/.bashrc`, `~/.zshrc`).
4. Pre-configures the Cursor preset (`profiles/agents/cursor.toml`) with network allowlists for Cursor's backend APIs (`api.cursor.com`, `api2.cursor.sh`).

### Step 2: Verify Status
```bash
vetto enable --status
```
Output:
```text
cursor     [wrapped]    -> /usr/bin/cursor (preset: default+agent)
```

### Step 3: Launch Cursor
```bash
cursor .
```
Cursor launches normally, but any terminal session, Composer execution, or background subagent command runs under unprivileged Linux Landlock and Seccomp-BPF barriers.

---

## 2. Integrated Terminal & Agent Mode Protection

Cursor's Agent Mode can autonomously run commands to compile code, run tests, install packages, and debug errors.

To guarantee that all terminal tasks spawned directly by Cursor's internal UI inherit Vetto protection, configure Cursor's `settings.json`:

```json
{
  "terminal.integrated.env.linux": {
    "PATH": "${env:HOME}/.vetto/shims:${env:PATH}",
    "VETTO_SANDBOX": "1"
  }
}
```

### Why This Matters:
- **Zero Prompt Interruptions**: You can safely allow Cursor Agent to run terminal commands without manually inspecting every line.
- **Fail-Closed Security**: If Cursor attempts to read `~/.ssh/id_rsa`, `~/.aws/credentials`, or `/etc/shadow`, the Linux kernel immediately aborts the read with `EACCES`.
- **Recursion Barriers**: Child processes spawned inside Cursor terminals (e.g. `python`, `cargo`, `node`, `make`) inherit the exact same sandbox without nested supervisor latency or recursion traps.

---

## 3. Storage & Secret Masking

Cursor stores user preferences, session histories, and sensitive auth tokens under its application configuration directories. Vetto's built-in `profiles/agents/cursor.toml` preset automatically protects this state:

```toml
[metadata]
name = "cursor"
description = "Safe read-only compatibility roots for Cursor Agent."

[filesystem]
# Allow reading legitimate caches and extension logs
allow_read = ["$AGENT/cache", "$AGENT/logs"]

[display_only_deny]
# Strictly mask Cursor internal tokens, global storage, and UNIX sockets
paths = [
    "$AGENT/User/globalStorage",
    "$AGENT/*.sock",
    "$AGENT/*.ipc",
]
```

Even if an agent command runs an expansive search (such as `grep -r token ~`), Vetto masks Cursor's `globalStorage` credentials using a kernel bind-mount over `/dev/null` or empty tmpfs.

---

## 4. Network Control & Allowlisting

Cursor requires access to its backend AI infrastructure. By default, Vetto configures network namespaces to permit only authorized Cursor endpoints:

- `api.cursor.com`
- `api2.cursor.sh`

### Adding Custom LLM Providers / Registries
If you configure Cursor to use your own API keys (e.g., Anthropic or OpenAI) or if your build requires package downloads, declare them in your project's `vetto.toml`:

```toml
[network]
mode = "allowlist"
allow = [
    "api.cursor.com",
    "api2.cursor.sh",
    "api.anthropic.com",
    "api.openai.com",
    "registry.npmjs.org",
    "crates.io",
]
```

Or allow temporary access on demand:
```bash
vetto allow --net api.openai.com
```

---

## 5. Cursor Session Diagnostics & Rescue

During heavy multi-turn agent refactorings, session state can occasionally corrupt or desynchronize. Vetto provides a built-in recovery adapter specifically for Cursor:

```bash
# Scan recent Cursor sessions
vetto rescue --adapter cursor scan

# Snapshot and back up an active session safely before a risky refactor
vetto rescue --adapter cursor snapshot <session-id> --output ./cursor-backup.jsonl

# Diagnose corrupted state
vetto rescue --adapter cursor diagnose <session-id>
```

All rescue commands operate safely outside the sandbox boundary and never mutate active IDE state without explicit user confirmation.

---

## 6. Verifying the Sandbox

Verify your configuration before starting work:

```bash
# Probe the kernel security features
vetto doctor

# Check what Cursor can access in the current workspace
vetto policy explain --agent cursor

# Test that home secrets are unreachable
vetto policy explain --why ~/.aws/credentials
```
Output:
```text
[DENIED] Path matches secret deny pattern ~/.aws/** -> Landlock kernel barrier active
```
