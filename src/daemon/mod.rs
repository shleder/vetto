//! Vetto Multiplexer Daemon and Session Orchestrator.
//!
//! Exposes:
//! - Unix Domain Socket with mandatory SO_PEERCRED authentication
//! - Loopback HTTP REST API with Bearer token authentication
//! - Persistent and in-memory session registry

pub mod auth;
pub mod http;
pub mod registry;
pub mod socket;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};
use clap::Subcommand;
#[cfg(unix)]
use serde_json::json;

use registry::SessionRegistry;

pub const DEFAULT_HTTP_PORT: u16 = 54321;

#[derive(Subcommand, Debug, Clone)]
pub enum DaemonCommand {
    /// Start the vetto multiplexer daemon (Unix socket + REST API)
    Start {
        /// Custom Unix socket path (default: ~/.vetto/daemon/vetto.sock)
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Loopback HTTP port for REST API (default: 54321)
        #[arg(long, default_value_t = DEFAULT_HTTP_PORT)]
        port: u16,
        /// Run in foreground instead of detaching
        #[arg(short, long)]
        foreground: bool,
    },
    /// Query status of the running daemon and active sessions
    Status,
    /// Stop the running vetto daemon
    Stop,
}

pub fn run_cli(cmd: &DaemonCommand) -> Result<()> {
    match cmd {
        DaemonCommand::Start {
            socket,
            port,
            foreground,
        } => start_daemon(socket.as_deref(), *port, *foreground),
        DaemonCommand::Status => query_daemon_status(),
        DaemonCommand::Stop => stop_daemon(),
    }
}

pub fn start_daemon(custom_socket: Option<&Path>, port: u16, foreground: bool) -> Result<()> {
    let state_dir = auth::default_daemon_dir()?;
    auth::ensure_daemon_dir(&state_dir)?;

    let token = auth::ensure_daemon_token(&state_dir)?;
    let socket_path = custom_socket
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir.join(socket::SOCKET_FILENAME));

    let pid_path = state_dir.join("daemon.pid");
    let my_pid = std::process::id();
    fs::write(&pid_path, my_pid.to_string())
        .with_context(|| format!("failed to write PID file {}", pid_path.display()))?;

    let registry = Arc::new(SessionRegistry::new(state_dir.clone()));

    println!("Starting Vetto Daemon (PID: {})...", my_pid);
    println!("  State Directory: {}", state_dir.display());
    println!("  Unix Socket:     {}", socket_path.display());
    println!("  HTTP REST API:   http://127.0.0.1:{}", port);
    println!(
        "  Token File:      {}",
        state_dir.join(auth::TOKEN_FILENAME).display()
    );

    // 1. Bind HTTP REST API
    let http_addr: SocketAddr = format!("127.0.0.1:{}", port)
        .parse()
        .context("invalid HTTP listen address")?;
    let http_server = http::HttpServer::bind(http_addr, token, Arc::clone(&registry))?;
    thread::spawn(move || {
        let _ = http_server.run_loop();
    });

    // 2. Bind Unix domain socket (Unix only)
    #[cfg(unix)]
    {
        let socket_server = socket::SocketServer::bind(socket_path, Arc::clone(&registry))?;
        if foreground {
            socket_server.run_loop()?;
        } else {
            thread::spawn(move || {
                let _ = socket_server.run_loop();
            });
            // Keep main thread alive if running as daemon process
            loop {
                thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = foreground;
        println!("Unix domain socket listener is disabled on Windows. REST API is active.");
        loop {
            thread::sleep(std::time::Duration::from_secs(3600));
        }
    }

    #[cfg(unix)]
    Ok(())
}

pub fn query_daemon_status() -> Result<()> {
    let state_dir = auth::default_daemon_dir()?;
    let pid_path = state_dir.join("daemon.pid");

    if !pid_path.exists() {
        println!(
            "Vetto daemon is NOT running (no daemon.pid at {})",
            pid_path.display()
        );
        return Ok(());
    }

    let pid_str = fs::read_to_string(&pid_path)?;
    println!("Vetto daemon PID: {}", pid_str.trim());

    #[cfg(unix)]
    {
        let socket_path = state_dir.join(socket::SOCKET_FILENAME);
        if socket_path.exists() {
            match socket::send_socket_request(&socket_path, &json!({"action": "list_sessions"})) {
                Ok(resp) => {
                    println!("Daemon Socket: ONLINE ({})", socket_path.display());
                    if let Some(sessions) = resp.get("data").and_then(|d| d.as_array()) {
                        println!("Active Sandboxed Sessions: {}", sessions.len());
                        for s in sessions {
                            println!(
                                "  - ID: {} | PID: {} | Status: {} | Policy: {}",
                                s.get("id").and_then(|v| v.as_str()).unwrap_or("?"),
                                s.get("pid").and_then(|v| v.as_u64()).unwrap_or(0),
                                s.get("status").and_then(|v| v.as_str()).unwrap_or("?"),
                                s.get("policy").and_then(|v| v.as_str()).unwrap_or("?"),
                            );
                        }
                    }
                }
                Err(e) => {
                    println!(
                        "Daemon Socket: UNREACHABLE ({}) - error: {e}",
                        socket_path.display()
                    );
                }
            }
        }
    }

    Ok(())
}

pub fn stop_daemon() -> Result<()> {
    let state_dir = auth::default_daemon_dir()?;
    let pid_path = state_dir.join("daemon.pid");

    if !pid_path.exists() {
        println!("No running daemon found.");
        return Ok(());
    }

    let pid_str = fs::read_to_string(&pid_path)?;
    if let Ok(pid) = pid_str.trim().parse::<i32>() {
        #[cfg(unix)]
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        println!("Sent SIGTERM to daemon process {}", pid);
    }

    let _ = fs::remove_file(&pid_path);
    #[cfg(unix)]
    {
        let socket_path = state_dir.join(socket::SOCKET_FILENAME);
        let _ = fs::remove_file(&socket_path);
    }

    println!("Vetto daemon stopped.");
    Ok(())
}
