//! Unix Domain Socket multiplexer listener with mandatory SO_PEERCRED / getpeereid auth.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::auth;
use super::registry::{SessionRegistry, StartSessionRequest};

pub const SOCKET_FILENAME: &str = "vetto.sock";

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SocketRequest {
    Ping,
    StartSession(StartSessionRequest),
    ListSessions,
    GetSession { id: String },
    StopSession { id: String },
}

#[derive(Debug, Serialize)]
pub struct SocketResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(unix)]
pub struct SocketServer {
    socket_path: PathBuf,
    listener: std::os::unix::net::UnixListener,
    registry: Arc<SessionRegistry>,
}

#[cfg(unix)]
impl SocketServer {
    pub fn bind(socket_path: PathBuf, registry: Arc<SessionRegistry>) -> Result<Self> {
        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }

        let listener = std::os::unix::net::UnixListener::bind(&socket_path).with_context(|| {
            format!(
                "failed to bind Unix domain socket at {}",
                socket_path.display()
            )
        })?;

        // Restrict socket file permissions to 0600
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(&socket_path, perms);

        Ok(Self {
            socket_path,
            listener,
            registry,
        })
    }

    pub fn run_loop(self) -> Result<()> {
        for stream in self.listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };

            // MANDATORY SECURITY: Authenticate peer credentials (SO_PEERCRED)
            if let Err(e) = auth::verify_peer_cred(&stream) {
                eprintln!("vetto daemon: rejected unauthorized socket connection: {e}");
                let resp = json!({
                    "status": "error",
                    "error": format!("unauthorized peer credentials: {e}")
                });
                let _ = writeln!(
                    stream,
                    "{}",
                    serde_json::to_string(&resp).unwrap_or_default()
                );
                let _ = stream.flush();
                continue;
            }

            let registry_clone = Arc::clone(&self.registry);
            thread::spawn(move || {
                let _ = handle_socket_client(stream, &registry_clone);
            });
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for SocketServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
fn handle_socket_client(
    mut stream: std::os::unix::net::UnixStream,
    registry: &SessionRegistry,
) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    let req: SocketRequest = match serde_json::from_str(trimmed) {
        Ok(r) => r,
        Err(e) => {
            let resp = json!({
                "status": "error",
                "error": format!("invalid request format: {e}")
            });
            writeln!(stream, "{}", serde_json::to_string(&resp)?)?;
            return Ok(());
        }
    };

    let resp_val = match req {
        SocketRequest::Ping => json!({"status": "ok", "pong": true}),
        SocketRequest::StartSession(start_req) => match registry.start_session(start_req) {
            Ok(entry) => json!({"status": "ok", "data": entry}),
            Err(e) => json!({"status": "error", "error": e.to_string()}),
        },
        SocketRequest::ListSessions => {
            let list = registry.list_sessions();
            json!({"status": "ok", "data": list})
        }
        SocketRequest::GetSession { id } => match registry.get_session(&id) {
            Some(entry) => json!({"status": "ok", "data": entry}),
            None => json!({"status": "error", "error": "session not found"}),
        },
        SocketRequest::StopSession { id } => match registry.stop_session(&id) {
            Ok(true) => json!({"status": "ok", "stopped": true}),
            _ => json!({"status": "error", "error": "session not found"}),
        },
    };

    writeln!(stream, "{}", serde_json::to_string(&resp_val)?)?;
    stream.flush()?;
    Ok(())
}

/// Sends a request over Unix domain socket and reads response.
#[cfg(unix)]
pub fn send_socket_request(
    socket_path: &Path,
    req: &serde_json::Value,
) -> Result<serde_json::Value> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect to socket at {}", socket_path.display()))?;

    writeln!(stream, "{}", serde_json::to_string(req)?)?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let val: serde_json::Value = serde_json::from_str(line.trim())
        .with_context(|| "failed to parse daemon socket response")?;
    Ok(val)
}

#[cfg(not(unix))]
pub fn send_socket_request(
    _socket_path: &Path,
    _req: &serde_json::Value,
) -> Result<serde_json::Value> {
    bail!("Unix domain sockets are supported on Unix only")
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_lifecycle_and_peercred() {
        let dir = std::env::temp_dir().join(format!("vetto-sock-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let sock_path = dir.join("test.sock");
        let registry = Arc::new(SessionRegistry::new(dir.clone()));

        let server = SocketServer::bind(sock_path.clone(), Arc::clone(&registry)).unwrap();
        thread::spawn(move || {
            let _ = server.run_loop();
        });

        // Test ping request from same process (same UID)
        let ping_req = json!({"action": "ping"});
        let resp = send_socket_request(&sock_path, &ping_req).expect("socket response");
        assert_eq!(resp["status"], "ok");
        assert_eq!(resp["pong"], true);

        // Test list sessions
        let list_req = json!({"action": "list_sessions"});
        let resp = send_socket_request(&sock_path, &list_req).expect("list response");
        assert_eq!(resp["status"], "ok");
        assert_eq!(resp["data"], json!([]));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
