# Model Context Protocol (MCP) Server for Vetto

Vetto natively implements an MCP (Model Context Protocol) JSON-RPC 2.0 server over standard I/O (stdio). This allows any MCP-compatible LLM host (such as Claude Desktop, Cursor, Zed, or custom agent frameworks) to invoke isolated sandboxed commands.

---

## 1. Running the MCP Server

```bash
vetto mcp
```

---

## 2. Exposed MCP Tools

### `run_sandboxed`
Executes an arbitrary shell command or binary within the Vetto security sandbox.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "command": {
      "type": "string",
      "description": "Shell command line to execute inside the sandbox"
    },
    "policy": {
      "type": "string",
      "description": "Optional policy profile name or path to policy TOML"
    },
    "timeout": {
      "type": "string",
      "description": "Optional timeout duration (e.g. '30s', '2m')"
    }
  },
  "required": ["command"]
}
```

**Output Structure**:
```json
{
  "stdout": "...",
  "stderr": "...",
  "exit_code": 0,
  "blocked_count": 0
}
```

---

## 3. Claude Desktop Configuration Example

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

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

---

## 4. Wrapping External MCP Servers (`vetto mcp wrap`)

Vetto can wrap and sandbox any third-party MCP server binary (e.g. filesystem servers, database runners, web scrapers) to constrain its filesystem and network access:

```bash
vetto mcp wrap --allow /path/to/workspace --allow-read /usr/share --net off -- <server-binary> [args...]
```

### Windows Path Hardening
On Windows hosts, `vetto mcp wrap` automatically resolves and grants read access to:
- Canonical `%SystemRoot%` (`C:\Windows`) and `%SystemRoot%\System32` (with binary existence verification against `cmd.exe` / `kernel32.dll` to prevent ENV-POISON attacks).
- `%ProgramFiles%` (and `%ProgramFiles(x86)%`).
- Temporary directories (`%TEMP%`, `%TMP%`).

### Platform Network Requirement
- **Linux**: Network relay supports `--net off`, `--net allowlist:<domains>`, and strict port filtering.
- **Non-Linux (macOS & Windows)**: Network relay requires Linux network namespaces (`CLONE_NEWNET`). On macOS and Windows, `vetto mcp wrap` requires `--net off` (the default). Attempting other network modes on non-Linux platforms fails closed with `PlatformUnsupported`.
