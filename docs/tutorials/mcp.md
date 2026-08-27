# MCP (Model Context Protocol) Integration

You can integrate Vetto directly into Model Context Protocol (MCP) clients (such as Claude Desktop, Cursor, and Codex) to ensure all tool invocations and subagent tasks run inside a kernel-enforced sandbox.

## 1. Claude Desktop / Claude Code MCP Config

Add Vetto to your `claude_desktop_config.json` or MCP server registry:

```json
{
  "mcpServers": {
    "vetto-sandbox": {
      "command": "vetto",
      "args": [
        "--agent", "claude",
        "--profile", "strict",
        "--net", "off",
        "--"
      ]
    }
  }
}
```

## 2. Cursor IDE MCP Setup

In Cursor settings under **Features -> MCP Servers**, add a new server:
- **Name**: `vetto`
- **Type**: `command`
- **Command**: `npx -y @shledery/vetto --profile strict --`

## 3. Subagent Safety Guarantees via MCP

When subagents execute tools through Vetto MCP:
1. **IPC sockets blocked**: Parent sockets (`*.sock`, `*.ipc`) are invisible.
2. **Environment filtered**: API keys and tokens are stripped unless explicitly allowed.
3. **Fail-Closed**: If the OS sandbox fails to apply, the tool call aborts immediately.
