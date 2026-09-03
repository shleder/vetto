//! MCP (Model Context Protocol) stdio JSON-RPC server implementation for vetto.
//!
//! Exposes vetto sandboxing as an MCP tool (`run_sandboxed`) for AI agents and LLM clients.

pub mod wrap;
pub use wrap::run_wrap;

use std::io::{BufRead, BufReader, Write};
use std::process::Command;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Deserialize, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Executes the MCP server loop reading JSON-RPC 2.0 messages from stdin and replying to stdout.
pub fn run_stdio_server() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(resp) = handle_message_str(line) {
            let out_str = serde_json::to_string(&resp)?;
            writer.write_all(out_str.as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }

    Ok(())
}

/// Processes a single incoming JSON-RPC raw string and returns an optional JSON-RPC response.
pub fn handle_message_str(raw: &str) -> Option<Value> {
    let req: JsonRpcRequest = match serde_json::from_str(raw) {
        Ok(r) => r,
        Err(e) => {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": {
                    "code": -32700,
                    "message": format!("Parse error: {e}")
                }
            }));
        }
    };

    handle_request(&req)
}

/// Handles a parsed JSON-RPC request.
pub fn handle_request(req: &JsonRpcRequest) -> Option<Value> {
    // If request has no ID, it's a notification: don't respond unless it's an RPC error
    let is_notification = req.id.is_none();
    let id = req.id.clone().unwrap_or(Value::Null);

    let result = match req.method.as_str() {
        "initialize" => handle_initialize(),
        "notifications/initialized" | "initialized" => {
            return None;
        }
        "ping" => Ok(json!({})),
        "tools/list" => handle_tools_list(),
        "tools/call" => handle_tools_call(req.params.as_ref()),
        other => {
            if is_notification {
                return None;
            }
            return Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("Method not found: {other}")
                }
            }));
        }
    };

    if is_notification {
        return None;
    }

    match result {
        Ok(res) => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": res
        })),
        Err(err) => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32000,
                "message": err.to_string()
            }
        })),
    }
}

fn handle_initialize() -> Result<Value> {
    Ok(json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "vetto",
            "version": "0.2.5"
        }
    }))
}

fn handle_tools_list() -> Result<Value> {
    Ok(json!({
        "tools": [
            {
                "name": "run_sandboxed",
                "description": "Execute a command inside the vetto daemon-less security sandbox with strict filesystem and network isolation",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Shell command line or program to execute inside the sandbox"
                        },
                        "policy": {
                            "type": "string",
                            "description": "Optional policy profile (e.g. 'strict', 'default') or path to custom policy TOML"
                        },
                        "timeout": {
                            "type": "string",
                            "description": "Optional maximum execution duration (e.g. '30s', '2m')"
                        }
                    },
                    "required": ["command"]
                }
            }
        ]
    }))
}

fn handle_tools_call(params: Option<&Value>) -> Result<Value> {
    let params = params.ok_or_else(|| anyhow::anyhow!("missing params for tools/call"))?;
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing tool name in tools/call"))?;

    if name != "run_sandboxed" {
        bail!("unknown tool '{name}'");
    }

    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let command_str = args
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing 'command' argument for run_sandboxed"))?;

    let policy_opt = args.get("policy").and_then(|v| v.as_str());
    let timeout_opt = args.get("timeout").and_then(|v| v.as_str());

    let exec_res = execute_sandboxed_command(command_str, policy_opt, timeout_opt)?;

    let is_error = exec_res.exit_code != 0;
    let output_json = serde_json::to_string_pretty(&exec_res)?;

    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": output_json
            }
        ],
        "isError": is_error
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxedOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub blocked_count: u64,
}

fn execute_sandboxed_command(
    command_str: &str,
    policy: Option<&str>,
    timeout: Option<&str>,
) -> Result<SandboxedOutput> {
    let current_exe = std::env::current_exe().unwrap_or_else(|_| "vetto".into());

    let mut cmd = Command::new(current_exe);
    cmd.arg("--ci");
    cmd.arg("--tui=none");

    if let Some(p) = policy {
        if p.ends_with(".toml") || p.contains('/') || p.contains('\\') {
            cmd.arg("--policy").arg(p);
        } else {
            cmd.arg("--profile").arg(p);
        }
    }

    if let Some(t) = timeout {
        cmd.arg("--timeout").arg(t);
    }

    cmd.arg("--");
    #[cfg(unix)]
    {
        cmd.arg("sh").arg("-c").arg(command_str);
    }
    #[cfg(windows)]
    {
        cmd.arg("cmd.exe").arg("/C").arg(command_str);
    }

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    // Blocked count: best effort extraction from stderr or exit code
    let blocked_count = if stderr.contains("BLOCKED") || stderr.contains("denied") {
        1
    } else {
        0
    };

    Ok(SandboxedOutput {
        stdout,
        stderr,
        exit_code,
        blocked_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize_response() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let resp = handle_message_str(&req.to_string()).expect("response expected");
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["serverInfo"]["name"], "vetto");
        assert_eq!(resp["result"]["serverInfo"]["version"], "0.2.5");
    }

    #[test]
    fn test_tools_list_response() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": "list-1",
            "method": "tools/list"
        });
        let resp = handle_message_str(&req.to_string()).expect("response expected");
        assert_eq!(resp["id"], "list-1");
        let tools = resp["result"]["tools"].as_array().expect("tools array");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "run_sandboxed");
    }

    #[test]
    fn test_unknown_method_error() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "non_existent_method"
        });
        let resp = handle_message_str(&req.to_string()).expect("response expected");
        assert_eq!(resp["id"], 42);
        assert!(resp["error"].is_object());
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn test_invalid_json_parse_error() {
        let resp = handle_message_str("{ invalid_json }").expect("response expected");
        assert_eq!(resp["error"]["code"], -32700);
    }

    #[test]
    fn test_tools_call_validation() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "unknown_tool",
                "arguments": {}
            }
        });
        let resp = handle_message_str(&req.to_string()).expect("response expected");
        assert!(resp["error"].is_object());
    }
}
