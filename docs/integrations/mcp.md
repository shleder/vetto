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
