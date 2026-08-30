//! Credential Broker (Feature 26).
//!
//! Provides out-of-process secret injection via a host-side Unix domain socket broker.
//! Secrets listed in `secrets.proxy` are completely stripped from the sandboxed agent's
//! environment and injected into upstream requests by the host broker only for allowlisted domains.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::events::{Event, EventBus};

/// Configuration for the credential broker.
#[derive(Debug, Clone, Default)]
pub struct CredBrokerConfig {
    pub proxy_secrets: Vec<String>,
    pub allowlist_domains: Vec<String>,
}

/// Request received over the broker unix socket.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum BrokerRequest {
    /// Request an injected authorization header for an allowlisted domain.
    GetHeader { domain: String, secret: String },
    /// Status ping.
    Ping,
}

/// Response returned to the sandboxed caller.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BrokerResponse {
    Ok {
        header_name: String,
        header_value: String,
    },
    Pong,
    Error {
        message: String,
    },
}

/// Strip broker-managed secrets from the environment.
pub fn filter_proxy_secrets(
    env: &mut std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
    proxy_secrets: &[String],
) {
    if proxy_secrets.is_empty() {
        return;
    }
    env.retain(|k, _| {
        let key_str = k.to_string_lossy();
        !proxy_secrets.iter().any(|p| p == key_str.as_ref())
    });
}

/// Helper to check if a domain is allowed by the broker allowlist.
pub fn is_domain_allowed(domain: &str, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return false;
    }
    let domain_clean = domain.trim().to_ascii_lowercase();
    allowlist.iter().any(|allowed| {
        let allowed_clean = allowed.trim().to_ascii_lowercase();
        allowed_clean == "*"
            || allowed_clean == domain_clean
            || domain_clean.ends_with(&format!(".{allowed_clean}"))
    })
}

/// Resolve appropriate authorization header name and value for a domain.
pub fn resolve_auth_header(
    domain: &str,
    secret_name: &str,
    secret_value: &str,
) -> (String, String) {
    let lower_domain = domain.to_ascii_lowercase();
    if lower_domain.contains("anthropic.com") {
        ("x-api-key".to_string(), secret_value.to_string())
    } else if lower_domain.contains("openai.com") || lower_domain.contains("github.com") {
        (
            "Authorization".to_string(),
            format!("Bearer {secret_value}"),
        )
    } else if secret_name.to_ascii_uppercase().contains("API_KEY") {
        ("x-api-key".to_string(), secret_value.to_string())
    } else {
        (
            "Authorization".to_string(),
            format!("Bearer {secret_value}"),
        )
    }
}

/// Spawns the credential broker thread listening on the specified Unix socket.
#[cfg(unix)]
pub fn spawn_credential_broker(
    socket_path: PathBuf,
    config: CredBrokerConfig,
    secrets: HashMap<String, String>,
    bus: EventBus,
) -> Result<std::thread::JoinHandle<()>> {
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind credential broker socket at {}", socket_path.display()))?;

    let handle = std::thread::Builder::new()
        .name("vetto-cred-broker".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let config = config.clone();
                        let secrets = secrets.clone();
                        let bus = bus.clone();
                        std::thread::spawn(move || {
                            let _ = handle_client(stream, &config, &secrets, &bus);
                        });
                    }
                    Err(_) => break,
                }
            }
            let _ = std::fs::remove_file(&socket_path);
        })?;

    Ok(handle)
}

#[cfg(unix)]
fn handle_client(
    mut stream: UnixStream,
    config: &CredBrokerConfig,
    secrets: &HashMap<String, String>,
    bus: &EventBus,
) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    if line.trim().is_empty() {
        return Ok(());
    }

    let trimmed = line.trim();
    if trimmed.starts_with('{') {
        // JSON Protocol
        let request: Result<BrokerRequest, _> = serde_json::from_str(trimmed);
        let response = match request {
            Ok(BrokerRequest::Ping) => BrokerResponse::Pong,
            Ok(BrokerRequest::GetHeader { domain, secret }) => {
                if !is_domain_allowed(&domain, &config.allowlist_domains) {
                    bus.publish(Event::Notice {
                        ts: crate::events::types::now(),
                        message: format!(
                            "credential broker rejected domain '{domain}' (not in allowlist)"
                        ),
                    });
                    BrokerResponse::Error {
                        message: format!("domain '{domain}' not in proxy allowlist"),
                    }
                } else if let Some(val) = secrets.get(&secret) {
                    let (h_name, h_val) = resolve_auth_header(&domain, &secret, val);
                    bus.publish(Event::Notice {
                        ts: crate::events::types::now(),
                        message: format!(
                            "credential broker injected '{secret}' for domain '{domain}'"
                        ),
                    });
                    BrokerResponse::Ok {
                        header_name: h_name,
                        header_value: h_val,
                    }
                } else {
                    BrokerResponse::Error {
                        message: format!("secret '{secret}' not available in host environment"),
                    }
                }
            }
            Err(e) => BrokerResponse::Error {
                message: format!("invalid broker request JSON: {e}"),
            },
        };

        let res_json = serde_json::to_string(&response)?;
        stream.write_all(res_json.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_proxy_secrets_from_env() {
        let mut env = std::collections::BTreeMap::new();
        env.insert("PATH".into(), "/bin".into());
        env.insert("ANTHROPIC_API_KEY".into(), "sk-ant-secret".into());
        env.insert("OPENAI_API_KEY".into(), "sk-openai-secret".into());

        filter_proxy_secrets(&mut env, &["ANTHROPIC_API_KEY".into()]);

        assert!(env.contains_key(OsStr::new("PATH")));
        assert!(!env.contains_key(OsStr::new("ANTHROPIC_API_KEY")));
        assert!(env.contains_key(OsStr::new("OPENAI_API_KEY")));
    }

    #[test]
    fn validates_domain_allowlist() {
        let allowlist = vec!["api.anthropic.com".to_string(), "openai.com".to_string()];

        assert!(is_domain_allowed("api.anthropic.com", &allowlist));
        assert!(is_domain_allowed("api.openai.com", &allowlist));
        assert!(!is_domain_allowed("evil.com", &allowlist));
    }

    #[test]
    fn resolves_custom_headers_per_domain() {
        let (name, val) =
            resolve_auth_header("api.anthropic.com", "ANTHROPIC_API_KEY", "secret123");
        assert_eq!(name, "x-api-key");
        assert_eq!(val, "secret123");

        let (name, val) = resolve_auth_header("api.openai.com", "OPENAI_API_KEY", "secret123");
        assert_eq!(name, "Authorization");
        assert_eq!(val, "Bearer secret123");
    }
}
