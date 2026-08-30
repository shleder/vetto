//! Remote sandboxing client and server orchestration over SSH / loopback REST API.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::daemon;

pub fn run_serve(port: u16) -> Result<()> {
    println!("=== Vetto Serve (Remote Multiplexer) ===");
    println!();
    println!("To expose this sandbox to a local or remote agent over SSH:");
    println!("  1. Forward loopback HTTP API:");
    println!("     ssh -R {port}:127.0.0.1:{port} user@remote-agent-box");
    println!("  2. Forward Unix socket (Linux/macOS):");
    println!(
        "     ssh -R /tmp/vetto-remote.sock:$HOME/.vetto/daemon/vetto.sock user@remote-agent-box"
    );
    println!();
    println!("Then execute commands remotely via:");
    println!("  vetto --remote http://127.0.0.1:{port} -- <agent command>");
    println!();

    daemon::start_daemon(None, port, true)
}

pub fn run_remote_client(
    endpoint: &str,
    command: Vec<String>,
    policy: Option<String>,
    net: Option<String>,
) -> Result<()> {
    if command.is_empty() {
        bail!("no command specified for remote execution");
    }

    // Resolve daemon token from ~/.vetto/daemon/token or VETTO_REMOTE_TOKEN env
    let token = if let Ok(t) = std::env::var("VETTO_REMOTE_TOKEN") {
        t
    } else {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .context("home dir required to read remote token")?;
        let token_path = home.join(".vetto").join("daemon").join("token");
        if token_path.is_file() {
            std::fs::read_to_string(&token_path)?.trim().to_string()
        } else {
            bail!("missing remote authentication token; set VETTO_REMOTE_TOKEN or ensure ~/.vetto/daemon/token exists");
        }
    };

    println!("Submitting command to remote vetto at {}...", endpoint);

    let host_port = endpoint
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_start_matches("ssh://");
    let mut stream = TcpStream::connect(host_port)
        .with_context(|| format!("failed to connect to remote vetto endpoint {}", endpoint))?;

    let payload = json!({
        "command": command,
        "policy": policy.unwrap_or_else(|| "default".to_string()),
        "net": net.unwrap_or_else(|| "off".to_string()),
    });
    let payload_bytes = serde_json::to_vec(&payload)?;

    let http_req = format!(
        "POST /sessions HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        host_port,
        token,
        payload_bytes.len()
    );

    stream.write_all(http_req.as_bytes())?;
    stream.write_all(&payload_bytes)?;
    stream.flush()?;

    let mut resp = String::new();
    stream.read_to_string(&mut resp)?;

    if !resp.contains("201 Created") && !resp.contains("200 OK") {
        bail!("remote session start failed: {}", resp);
    }

    println!("Remote sandboxed session started successfully.");
    Ok(())
}
