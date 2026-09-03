# OpenCode Integration Guide

OpenCode is an open-source terminal coding assistant. Vetto provides zero-config kernel sandboxing and network egress allowlisting for OpenCode sessions without requiring Docker or root privileges.

---

## 1. Quick Start: Transparent Shim

The fastest and most reliable way to sandbox OpenCode is via Vetto priority shims:

```bash
vetto enable opencode
```

Once enabled, simply run OpenCode normally in any project:

```bash
opencode
# Or unattended:
opencode run --yes
```

Vetto intercepts the execution, defaults network egress to provider inference APIs (`api.openai.com`, `api.anthropic.com`, `openrouter.ai`), masks system credentials (`~/.ssh`, `~/.aws`, `.env`), and isolates disk access.

---

## 2. Configuration Runner Integration

You can also integrate Vetto directly into OpenCode's configuration runner:

```bash
vetto plugin install opencode
```

This merges the sandbox runner into `~/.config/opencode/config.json`:

```json
{
  "sandbox": {
    "command": "vetto",
    "args": [
      "--ci",
      "--"
    ]
  },
  "vetto": {
    "enabled": true,
    "version": "0.2.13"
  }
}
```

---

## 3. Direct Execution

To run OpenCode inside a specific preset or custom boundary:

```bash
# Balanced preset (recommended: workspace write, secrets masked, inference network)
vetto -- opencode

# Paranoid preset (read-only workspace, zero network)
vetto --preset paranoid -- opencode
```
