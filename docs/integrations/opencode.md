# OpenCode Integration Guide

OpenCode is an open-source terminal coding assistant. Vetto integrates directly with OpenCode to sandbox all generated code executions and shell commands.

---

## 1. Automated Installation

Run:
```bash
vetto plugin install opencode
```

This creates or merges `~/.config/opencode/config.json` with an atomic backup at `~/.config/opencode/config.json.bak.<timestamp>`.

---

## 2. Configuration Format

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
    "version": "0.2.5"
  }
}
```

---

## 3. Manual Verification

To run OpenCode directly under Vetto:
```bash
vetto --profile strict -- opencode
```
All subagents and background commands spawned by OpenCode inherit the security sandbox restrictions.
