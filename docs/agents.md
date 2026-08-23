# Agent compatibility registry

This registry describes the outer vetto integration contract. Built-in agent
sandbox behavior changes independently, so an agent preset may add required
read paths or environment names but must never weaken vetto's enforcement.
`Last tested` is intentionally explicit; `not in CI` means compatibility is
unproven rather than assumed.

| Agent | Typical command | Built-in isolation | Recommended mode | Preset | Network notes | Last tested |
|---|---|---|---|---|---|---|
| OpenAI Codex CLI | `codex`, `codex exec` | Yes; platform/config dependent | statusline for interactive, full/none for `exec` | `codex` | Provider and Git endpoints must be explicitly allowed | not in CI |
| Claude Code | `claude`, `claude -p` | Optional/tool-specific | statusline for interactive, full/none for `-p` | `claude` | Provider and package endpoints depend on the task | not in CI |
| Aider | `aider` | No uniform OS boundary assumed | statusline | `aider` | Model provider plus optional Git endpoints | not in CI |
| Cursor Agent | `cursor-agent` | Implementation/version dependent | full | `cursor` | Treat endpoints as untrusted configuration | not in CI |
| Cline | user-configured CLI/extension command | unknown | full | `cline` | Do not infer endpoints from the preset | not in CI |
| OpenCode | `opencode` | permission model is not treated as an OS boundary | statusline | `opencode` | Provider-specific | not in CI |
| GitHub Copilot CLI | `copilot` | implementation/version dependent | statusline | `copilot` | GitHub endpoints only when needed | not in CI |
| Custom process | any executable | unknown | statusline or none | `custom` | Default remains `off` | process contract covered |

## Compatibility rules

1. The command must be executable from the policy's read scope.
2. Interactive programs use a PTY; headless programs should use `--tui=full`
   or `--tui=none`.
3. Credential variables are stripped unless a project policy explicitly opts
   into each name.
4. An agent's own sandbox is defense in depth. vetto does not detect it and
   then remove outer restrictions.
5. `doctor --check-agent` reports observed version/output only. It must not say
   “no conflicts” unless that exact version is covered by an automated test.
