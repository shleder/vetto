# Claude Code Integration Guide

Claude Code (`@anthropic-ai/claude-code`) can be transparently sandboxed with Vetto using automated hook shims or one-liner plugin configuration.

---

## 1. Automated Installation

Run the one-liner installer:
```bash
vetto plugin install claude-code
```

This performs a non-destructive merge on `~/.claude/settings.json`, preserving all your custom configurations and backing up the original file to `~/.claude/settings.json.bak.<timestamp>`.

---

## 2. Configuration Structure

The generated `~/.claude/settings.json` contains:

```json
{
  "hooks": {
    "PreToolUse": {
      "command": "vetto shim"
    }
  },
  "vetto": {
    "enabled": true,
    "version": "0.2.5",
    "managed": true
  }
}
```

---

## 3. How It Works

When Claude Code attempts to execute a shell tool or bash command:
1. The `PreToolUse` hook intercepts the execution request.
2. Vetto's native zero-latency shim inspects the policy for the current workspace.
3. The command is launched inside an unprivileged Landlock/Seatbelt kernel sandbox.
4. If the agent attempts unauthorized filesystem access or forbidden network egress, the action is blocked immediately.
