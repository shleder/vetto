//! MCP (Model Context Protocol) stdio JSON-RPC server implementation for vetto.
//!
//! Exposes vetto sandboxing as an MCP tool (`run_sandboxed`) for AI agents and LLM clients.

pub mod wrap;
pub use wrap::run_wrap;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

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
            "version": env!("CARGO_PKG_VERSION")
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
                            "description": "Program to execute inside the sandbox (or command line string)"
                        },
                        "args": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Optional list of command line arguments passed directly without a shell"
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

pub fn handle_tools_call(params: Option<&Value>) -> Result<Value> {
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

    let extra_args = args.get("args").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<Vec<String>>()
    });
    let policy_opt = args.get("policy").and_then(|v| v.as_str());
    let timeout_opt = args.get("timeout").and_then(|v| v.as_str());

    let exec_res =
        execute_sandboxed_command(command_str, extra_args.as_deref(), policy_opt, timeout_opt)?;

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

/// Parses a command line string into separate arguments without invoking a shell.
pub fn parse_command_tokens(command_str: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = command_str.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            '\\' if !in_single => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(current);
                    current = String::new();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(unix)]
#[allow(dead_code)]
fn pipe2() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: valid out-array for the libc pipe call.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    for fd in fds {
        // SAFETY: fd came from the successful pipe call.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            bail!("fcntl(F_GETFD): {error}");
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            bail!("fcntl(F_SETFD): {error}");
        }
    }
    use std::os::fd::FromRawFd;
    // SAFETY: fresh descriptors from successful pipe and CLOEXEC setup.
    Ok((
        unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) },
        unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) },
    ))
}

pub fn execute_sandboxed_command(
    command_str: &str,
    extra_args: Option<&[String]>,
    policy: Option<&str>,
    timeout: Option<&str>,
) -> Result<SandboxedOutput> {
    let mut argv = if let Some(extra) = extra_args {
        let mut list = vec![command_str.to_string()];
        list.extend(extra.iter().cloned());
        list
    } else {
        parse_command_tokens(command_str)
    };

    if argv.is_empty() {
        bail!("no command specified to run_sandboxed");
    }

    let resolved_bin = wrap::resolve_in_path(&argv[0])?;
    argv[0] = resolved_bin.to_string_lossy().to_string();

    let net_mode = crate::config::NetMode::Off;
    let backend = crate::sandbox::Backend::detect(net_mode.clone(), false)?;
    let backend_tier = backend.tier();
    let tier_for_policy = backend_tier.unwrap_or(crate::policy::Tier::Full);
    let project = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| project.clone());

    let (profile, policy_path) = match policy {
        Some(p) if p.ends_with(".toml") || p.contains('/') || p.contains('\\') => {
            ("default", Some(Path::new(p)))
        }
        Some(p) => (p, None),
        None => ("default", None),
    };

    let mut pol =
        crate::policy::loader::load(profile, policy_path, &project, &home, tier_for_policy)?;

    if let Some(parent) = resolved_bin.parent() {
        let parent_buf = parent.to_path_buf();
        if !pol.in_read_scope(&resolved_bin) && !pol.allow_read.contains(&parent_buf) {
            pol.allow_read.push(parent_buf);
        }
    }

    let parsed_timeout = timeout
        .map(crate::config::parse_session_timeout)
        .transpose()?
        .unwrap_or(std::time::Duration::from_secs(30));

    let mut spawn_log = crate::sandbox::production::ProdSpawnLog::new();
    let prod_res = crate::sandbox::production::execute_simple(
        &pol,
        argv,
        project,
        std::collections::HashMap::new(),
        net_mode,
        backend_tier,
        parsed_timeout,
        &mut spawn_log,
    )?;

    let stdout = String::from_utf8_lossy(&prod_res.stdout).to_string();
    let mut stderr = String::from_utf8_lossy(&prod_res.stderr).to_string();
    let exit_code = prod_res.exit_code.unwrap_or(-1);
    if let Some(ref diag) = prod_res.diagnostic {
        if exit_code != 0 && !diag.is_empty() {
            if !stderr.is_empty() && !stderr.ends_with('\n') {
                stderr.push('\n');
            }
            stderr.push_str("Diagnostic: ");
            stderr.push_str(diag);
        }
    }
    let blocked_count = if stderr.contains("BLOCKED")
        || stderr.contains("denied")
        || exit_code == 124
        || exit_code == 125
    {
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
        assert_eq!(resp["result"]["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
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

    #[test]
    fn test_parse_command_tokens() {
        assert_eq!(
            parse_command_tokens("echo hello world"),
            vec!["echo", "hello", "world"]
        );
        assert_eq!(
            parse_command_tokens("echo 'hello world'"),
            vec!["echo", "hello world"]
        );
        assert_eq!(
            parse_command_tokens("echo \"double quoted\""),
            vec!["echo", "double quoted"]
        );
        assert_eq!(
            parse_command_tokens("  spaced   arguments   "),
            vec!["spaced", "arguments"]
        );
    }
}
