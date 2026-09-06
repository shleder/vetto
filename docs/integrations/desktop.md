# Sandboxing Claude Desktop & Codex Desktop with Vetto

Vetto provides two complementary mechanisms to sandbox desktop AI coding applications (Claude Desktop, Codex Desktop, Cursor, and IDE-based agents):

1. **Model Context Protocol (MCP) Server**: Exposes a sandboxed execution engine (`run_sandboxed`) directly to the desktop application over stdio JSON-RPC.
2. **Transparent Binary Shims**: Intercepts terminal tasks, agent subprocesses, and CLI runners spawned from integrated desktop environments.

---

## 1. Claude Desktop (via MCP Server)

[Claude Desktop](https://claude.ai/download) executes tools locally using Anthropic's open Model Context Protocol (MCP). By configuring Vetto as an MCP server, any code or shell commands executed by Claude Desktop are automatically confined by Linux Landlock or macOS Seatbelt.

### Step 1: Locate Configuration File
Open your Claude Desktop configuration file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Step 2: Register Vetto MCP Server
Add the `vetto` entry under `mcpServers`:

```json
{
  "mcpServers": {
    "vetto": {
      "command": "vetto",
      "args": ["mcp"]
    }
  }
}
```

*If `vetto` is not in your global system PATH, specify the absolute path (e.g. `/home/user/.local/bin/vetto` or `C:\\Users\\user\\.cargo\\bin\\vetto.exe`).*

### Step 3: Sandboxing Existing MCP Servers
If you already use third-party MCP servers (such as `@modelcontextprotocol/server-filesystem` or `fetch`), you can isolate them directly by prepending `vetto --`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "vetto",
      "args": ["--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects/my-app"]
    }
  }
}
```
*Now, even if a prompt injection instructs the filesystem MCP server to read `~/.ssh/id_rsa`, the OS kernel rejects the read with `Permission Denied`.*

---

## 2. Claude Code & Codex Desktop (Terminal / Subprocess Interception)

When using desktop agent environments that run terminal tasks (such as Claude Code running in Cursor/VSCode, or Codex desktop tooling), Vetto's **shims** provide zero-config interception.

### Step 1: Enable Transparent Shims
Run once on your machine:
```bash
vetto enable claude
vetto enable codex
```

This writes transparent shims to `~/.vetto/shims/claude` and `~/.vetto/shims/codex`.

### Step 2: How Desktop Subprocesses are Sandboxed
1. **PATH Priority**: Vetto automatically adds `~/.vetto/shims` to the beginning of your shell `$PATH`.
2. **Subprocess Spawning**: Whenever Claude Desktop, Cursor, or Codex spawns a terminal shell or subagent process (`claude ...` or `codex ...`), the call resolves to the Vetto shim.
3. **Pre-Exec Confinement**: The shim configures the kernel Landlock/Seccomp boundaries **before** the agent binary starts.
4. **Credential Masking**: The desktop agent can freely edit project code, but cannot touch `~/.ssh`, `~/.aws`, `.env`, or modify system files.

---

## 3. Verification

To verify that your desktop agent is properly sandboxed:

1. In Claude Desktop or your desktop agent chat, ask:
   > *"Run a bash command to check the first line of ~/.ssh/id_rsa"*
2. Observe the result:
   - **Unsandboxed**: Returns the private key header (High risk!).
   - **With Vetto**: Returns `Permission denied: ~/.ssh/id_rsa` or `Landlock LSM kernel barrier blocked read`.
