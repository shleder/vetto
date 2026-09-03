# Sandboxing Claude Code with Vetto

Run [Claude Code](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/overview) (`@anthropic-ai/claude-code`) unattended with total confidence. Vetto wraps Claude Code inside a kernel-enforced, unprivileged sandbox using Linux Landlock and Seccomp-BPF—preventing rogue filesystem modifications, unauthorized secret exfiltration, and arbitrary network egress without requiring Docker or root privileges.

---

## 1. Quick Start (Zero-Config)

### Step 1: Enable Claude Code in Vetto
Run:
```bash
vetto enable claude
```
This automatically:
1. Locates your host `claude` / `claude-code` binary.
2. Creates a transparent, high-priority shim at `~/.vetto/shims/claude`.
3. Ensures your shell rc files (`~/.bashrc`, `~/.zshrc`) include `~/.vetto/shims` in your `$PATH`.
4. Applies the built-in `claude` security preset with pre-configured network and filesystem boundaries.

### Step 2: Verify Wrapping Status
```bash
vetto enable --status
# Or list all detected agents
vetto enable
```
Output:
```text
claude     [wrapped]    -> /usr/local/bin/claude (preset: default+agent)
```

### Step 3: Run Claude Code Normally
```bash
claude
```
Under the hood, Vetto configures the kernel security boundaries **before** Claude Code spawns.

---

## 2. Unattended / Unprompted Execution

Developers love Claude Code's unattended flag (`--dangerously-skip-permissions` or `-p "<prompt>"`), but running an autonomous LLM with unconfined shell execution is a major security risk: a hallucinated command or prompt injection can wipe directories, leak `~/.ssh/id_rsa`, or exfiltrate environment secrets.

With Vetto, `--dangerously-skip-permissions` becomes safe:

```bash
claude --dangerously-skip-permissions
```

### What Happens Under the Hood:
- **Fail-Closed Filesystem Boundary**: Write access is locked exclusively to your current project directory (`$PWD`) and `/tmp`. Reads to sensitive user directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`) are completely blocked at the kernel level via Landlock.
- **Recursion Barrier**: When Claude Code invokes toolchain commands (`cargo check`, `npm test`, `git status`, `python`), Vetto's recursion barrier (`VETTO_SANDBOXED=1`, `VETTO_SHIM_ACTIVE=1`) ensures child processes inherit the exact same sandbox without nested supervisor overhead or infinite shim loops.
- **Microsecond Latency**: Unlike Docker containers that take 3+ seconds to spin up, Vetto imposes less than **0.002s** (2ms) of spawn overhead.

---

## 3. Configuration & Filesystem Protections

Claude Code stores persistent state, telemetry, and configuration in `~/.claude` and `~/.claude.json`. Vetto's built-in `profiles/agents/claude.toml` automatically handles this:

```toml
[metadata]
name = "claude"
description = "Safe compatibility roots for Claude Code."

[filesystem]
# Allows write access to agent workspace cache
allow_write = ["$AGENT"]

# Allows reading configuration without exposing global user configs
allow_read = ["$HOME/.claude.json", "$AGENT"]

[environment]
# Environment variables safely passed into the sandbox
pass_through = [
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
    "CLAUDE_*",
]

[display_only_deny]
# Sensitive credentials masked inside the sandbox
paths = [
    "$AGENT/.credentials.json",
    "$AGENT/*.sock",
    "$AGENT/*.ipc",
]
```

### Masking vs. Denying
- **Safe State Access**: Claude Code can read its workspace configurations and write caches without permission errors.
- **Secret Masking**: Any attempt by Claude Code or a child sub-process to open `$HOME/.claude/.credentials.json` or UNIX sockets is met with an immediate `EACCES` kernel denial or routed to `/dev/null`.

---

## 4. Network Allowlisting

By default, an AI agent should only talk to its approved inference APIs. Vetto enforces this using kernel network namespaces and an in-process DNS/CONNECT relay broker.

### Out-of-the-Box Allowlist
When wrapped with `vetto enable claude`, outbound network connections are restricted strictly to:
- `api.anthropic.com`

Any egress to unknown hosts, arbitrary IPs, or local LAN services (`192.168.x.x`, `10.x.x.x`, `169.254.169.254` AWS metadata) is immediately dropped.

### Customizing Allowed Endpoints
If your Claude Code workflow requires pulling packages or interacting with external documentation, specify additional domains in your project's `vetto.toml`:

```toml
[network]
mode = "allowlist"
allow = [
    "api.anthropic.com",
    "registry.npmjs.org",
    "crates.io",
    "github.com",
]
```

Or grant access on the fly from the terminal:
```bash
vetto allow --net registry.npmjs.org
```

---

## 5. Hook Configuration (`PreToolUse`)

If you prefer Claude Code's native hook system instead of global PATH shims, you can configure Claude Code's `~/.claude/settings.json` or project `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": {
      "command": "vetto shim"
    }
  },
  "vetto": {
    "enabled": true,
    "version": "0.2.12",
    "managed": true
  }
}
```

This intercepts every bash tool invocation generated by Claude Code and dispatches it through `vetto`, ensuring child commands execute within the kernel sandbox.

---

## 6. Testing & Verifying the Boundary

Test that your Claude Code sandbox is impenetrable:

```bash
# 1. Probing the sandbox directly without launching the agent
vetto verify

# 2. Inspecting effective permissions for Claude in your current directory
vetto policy explain --agent claude

# 3. Verifying secret masking
vetto policy explain --why ~/.ssh/id_rsa
# Output: [DENIED] Matched rule 'deny.ssh' (~/.ssh/id_rsa) -> blocked by Landlock
```

If Claude Code is blocked from accessing a legitimate project path (such as an external assets directory), Vetto prints a direct grant hint:
```bash
vetto allow ./external-assets
```
Your rule is instantly saved into `./vetto.toml` for subsequent runs.
