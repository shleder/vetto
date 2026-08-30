//! Lightweight REST HTTP API server bound strictly to loopback (`127.0.0.1`).
//!
//! Provides:
//! - POST /sessions -> start sandboxed session
//! - GET /sessions -> list active/recent sessions
//! - GET /sessions/{id} -> inspect single session
//! - DELETE /sessions/{id} -> kill session

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};
use serde_json::json;

use super::registry::{SessionRegistry, StartSessionRequest};

pub struct HttpServer {
    listener: TcpListener,
    token: String,
    registry: Arc<SessionRegistry>,
}

impl HttpServer {
    pub fn bind(addr: SocketAddr, token: String, registry: Arc<SessionRegistry>) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .with_context(|| format!("failed to bind REST HTTP server to {}", addr))?;
        Ok(Self {
            listener,
            token,
            registry,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().context("local_addr")
    }

    pub fn run_loop(self) -> Result<()> {
        let token = Arc::new(self.token);
        for stream in self.listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let token_clone = Arc::clone(&token);
            let registry_clone = Arc::clone(&self.registry);
            thread::spawn(move || {
                let _ = handle_http_connection(stream, &token_clone, &registry_clone);
            });
        }
        Ok(())
    }
}

pub fn handle_http_connection(
    mut stream: TcpStream,
    expected_token: &str,
    registry: &SessionRegistry,
) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        write_http_response(
            &mut stream,
            400,
            "Bad Request",
            &json!({"error": "invalid request line"}),
        )?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    // Read headers
    let mut headers = Vec::new();
    let mut content_length: usize = 0;
    let mut auth_header: Option<String> = None;

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        let trimmed = line.trim();
        if trimmed.to_ascii_lowercase().starts_with("authorization:") {
            auth_header = Some(trimmed[14..].trim().to_string());
        } else if trimmed.to_ascii_lowercase().starts_with("content-length:") {
            if let Ok(len) = trimmed[15..].trim().parse::<usize>() {
                content_length = len;
            }
        }
        headers.push(line);
    }

    // Authenticate Bearer token
    let authenticated = match auth_header {
        Some(ref h) => {
            let token_part = h.strip_prefix("Bearer ").unwrap_or(h).trim();
            token_part == expected_token
        }
        None => false,
    };

    if !authenticated {
        write_http_response(
            &mut stream,
            401,
            "Unauthorized",
            &json!({"error": "unauthorized: valid Bearer token required"}),
        )?;
        return Ok(());
    }

    // Read body if present
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    // Route dispatch
    if method == "GET" && path == "/sessions" {
        let list = registry.list_sessions();
        write_http_response(&mut stream, 200, "OK", &json!(list))?;
    } else if method == "POST" && path == "/sessions" {
        let req: StartSessionRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                write_http_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    &json!({"error": format!("invalid JSON body: {e}")}),
                )?;
                return Ok(());
            }
        };

        match registry.start_session(req) {
            Ok(entry) => write_http_response(&mut stream, 201, "Created", &json!(entry))?,
            Err(e) => write_http_response(
                &mut stream,
                500,
                "Internal Server Error",
                &json!({"error": e.to_string()}),
            )?,
        }
    } else if method == "GET" && path.starts_with("/sessions/") {
        let id = path.trim_start_matches("/sessions/");
        match registry.get_session(id) {
            Some(entry) => write_http_response(&mut stream, 200, "OK", &json!(entry))?,
            None => write_http_response(
                &mut stream,
                404,
                "Not Found",
                &json!({"error": "session not found"}),
            )?,
        }
    } else if method == "DELETE" && path.starts_with("/sessions/") {
        let id = path.trim_start_matches("/sessions/");
        match registry.stop_session(id) {
            Ok(true) => write_http_response(&mut stream, 200, "OK", &json!({"status": "stopped"}))?,
            _ => write_http_response(
                &mut stream,
                404,
                "Not Found",
                &json!({"error": "session not found"}),
            )?,
        }
    } else {
        write_http_response(
            &mut stream,
            404,
            "Not Found",
            &json!({"error": "endpoint not found"}),
        )?;
    }

    Ok(())
}

fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    body: &serde_json::Value,
) -> Result<()> {
    let body_bytes = serde_json::to_vec_pretty(body)?;
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status_code,
        status_text,
        body_bytes.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(&body_bytes)?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_rest_api_auth_and_endpoints() {
        let dir = std::env::temp_dir().join(format!("vetto-http-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let registry = Arc::new(SessionRegistry::new(dir.clone()));
        let token = "test-secret-token-12345".to_string();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = HttpServer::bind(addr, token.clone(), Arc::clone(&registry)).unwrap();
        let bound_addr = server.local_addr().unwrap();

        thread::spawn(move || {
            let _ = server.run_loop();
        });

        // 1. Unauthorized request
        let mut client = TcpStream::connect(bound_addr).unwrap();
        client
            .write_all(b"GET /sessions HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("401 Unauthorized"));

        // 2. Authorized GET /sessions
        let mut client = TcpStream::connect(bound_addr).unwrap();
        let req = format!(
            "GET /sessions HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\n\r\n",
            token
        );
        client.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("[]"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
