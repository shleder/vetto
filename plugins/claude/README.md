# Vetto for Claude Code

Seamless host-native security sandbox and project transcript recovery for Claude Code.

## Features

- **Kernel VFS Isolation**: Prevents Claude Code from reading ambient credentials (`~/.ssh`, `~/.aws`, `.env`).
- **Transcript & Session Rescue**: Repai damaged `~/.claude/projects/**/*.jsonl` state trees without losing chat context.
- **PTY Stream Redactor**: Intercepts high-entropy tokens and API keys in real-time.

## Setup

### Option 1: Wrap Claude Code Invocations
```bash
vetto --agent claude --profile strict -- claude
```

### Option 2: Automatic Shell Hook
```bash
# Install once across your shell and Git hooks
vetto hook install
```

### Option 3: Claude Code Custom Commands
Symlink or copy `config/slash-commands.json` to your Claude Code configuration:
```bash
mkdir -p ~/.claude/commands
cp plugins/claude/config/slash-commands.json ~/.claude/commands/vetto.json
```
