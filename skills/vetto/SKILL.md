---
name: vetto-sandbox
description: Enforce zero-daemon Landlock/Seatbelt security boundaries, network isolation, and subagent capability controls when executing untrusted commands or running subagents. Use when running terminal commands, testing untrusted scripts, isolating AI subagent workflows, or performing read-only session recovery for Codex and Claude Code.
---

# Vetto Sandbox & Security Skill

Use `vetto` to execute commands inside an isolated, operator-controlled OS sandbox before untrusted code or AI agents run.

## When to use

1. **Running untrusted scripts, test suites, or package installations**:
   ```bash
   vetto --profile default -- <command>
   ```
2. **Strict network-off execution (complete isolation)**:
   ```bash
   vetto --net=off -- <command>
   ```
3. **Whitelisted outbound domain access only**:
   ```bash
   vetto --net=allowlist:api.github.com,registry.npmjs.org -- <command>
   ```
4. **Wrapping autonomous AI coding agents**:
   ```bash
   # Codex
   vetto --agent codex --profile default -- codex exec "<prompt>"

   # Claude Code
   vetto --agent claude --profile strict -- claude -p "<prompt>"
   ```
5. **Session Rescue & Corrupted History Diagnosis**:
   ```bash
   # Scan sessions
   vetto rescue --json scan

   # Diagnose session health read-only
   vetto rescue diagnose <path_to_session.jsonl>

   # Create clean sanitized snapshot
   vetto rescue snapshot <path_to_session.jsonl> --output <destination.jsonl>
   ```

## Security Guarantees

- **Filesystem**: Landlock/Seatbelt enforce project-only read/write. `$HOME/.ssh`, cloud keys, and `.env` are masked with `/dev/null`.
- **Subagent Guard**: Control plane sockets (`app_server.sock`, `*.sock`, `*.ipc`) and debugger ports (`9222`, `9229`, `5678`) are blocked from child processes.
- **Fail-Closed**: If the kernel sandbox cannot be applied, execution is halted immediately.
