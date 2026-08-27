//! Local loopback debug port isolation (`DebugPortGuard`).
//!
//! AI coding agents often attempt to inspect or control host processes via
//! local loopback debugging interfaces. By default, Vetto strictly isolates
//! sensitive loopback debug ports:
//!
//! * Chrome DevTools: `9222`, `9223`
//! * Node.js Inspector: `9229`, `9230`
//! * Python debugpy: `5678`
//!
//! Unauthorized connections are blocked with `403 Forbidden` / `ECONNREFUSED`
//! unless accompanied by a cryptographically-generated per-session token
//! (`X-Vetto-Debug-Token`) or explicitly whitelisted via `DebugPortConfig`.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CHROME_DEVTOOLS_PORTS: &[u16] = &[9222, 9223];
pub const NODE_INSPECT_PORTS: &[u16] = &[9229, 9230];
pub const PYTHON_DEBUGPY_PORTS: &[u16] = &[5678];

pub const DEBUG_AUTH_HEADER: &str = "X-Vetto-Debug-Token";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugPortConfig {
    #[serde(default = "default_true")]
    pub isolate_devtools: bool,
    #[serde(default = "default_true")]
    pub isolate_node_inspect: bool,
    #[serde(default = "default_true")]
    pub isolate_debugpy: bool,
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
}

fn default_true() -> bool {
    true
}

impl Default for DebugPortConfig {
    fn default() -> Self {
        Self {
            isolate_devtools: true,
            isolate_node_inspect: true,
            isolate_debugpy: true,
            allowed_ports: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugPortVerdict {
    Allowed,
    Blocked { port: u16, service: &'static str },
}

#[derive(Debug, Clone)]
pub struct DebugPortGuard {
    config: DebugPortConfig,
    session_token: String,
    whitelisted: HashSet<u16>,
}

impl DebugPortGuard {
    /// Create a new `DebugPortGuard` with the provided configuration and a
    /// generated session authentication token.
    pub fn new(config: DebugPortConfig) -> Self {
        let session_token = Self::generate_token();
        let whitelisted: HashSet<u16> = config.allowed_ports.iter().copied().collect();
        Self {
            config,
            session_token,
            whitelisted,
        }
    }

    /// Create with an explicit token (for tests or multi-agent coordinators).
    pub fn with_token(config: DebugPortConfig, token: impl Into<String>) -> Self {
        let whitelisted: HashSet<u16> = config.allowed_ports.iter().copied().collect();
        Self {
            config,
            session_token: token.into(),
            whitelisted,
        }
    }

    /// Cryptographically derive a per-session debug token.
    pub fn generate_token() -> String {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let mut hasher = Sha256::new();
        hasher.update(b"vetto-debug-token-v1-");
        hasher.update(pid.to_le_bytes());
        hasher.update(nonce.to_le_bytes());
        let digest = hasher.finalize();
        format!("vdt_{}", hex::encode(&digest[..16]))
    }

    pub fn session_token(&self) -> &str {
        &self.session_token
    }

    pub fn is_debug_port(&self, port: u16) -> bool {
        if self.config.isolate_devtools && CHROME_DEVTOOLS_PORTS.contains(&port) {
            return true;
        }
        if self.config.isolate_node_inspect && NODE_INSPECT_PORTS.contains(&port) {
            return true;
        }
        if self.config.isolate_debugpy && PYTHON_DEBUGPY_PORTS.contains(&port) {
            return true;
        }
        false
    }

    pub fn identify_service(&self, port: u16) -> Option<&'static str> {
        if CHROME_DEVTOOLS_PORTS.contains(&port) {
            Some("Chrome DevTools")
        } else if NODE_INSPECT_PORTS.contains(&port) {
            Some("Node.js Inspector")
        } else if PYTHON_DEBUGPY_PORTS.contains(&port) {
            Some("Python debugpy")
        } else {
            None
        }
    }

    /// Check if loopback access to `port` is permitted.
    ///
    /// If `port` is an isolated debug port, access is granted ONLY if:
    /// 1. It is explicitly in `allowed_ports`, OR
    /// 2. `token_candidate` matches `self.session_token`.
    pub fn check_access(&self, port: u16, token_candidate: Option<&str>) -> DebugPortVerdict {
        if self.whitelisted.contains(&port) {
            return DebugPortVerdict::Allowed;
        }

        if let Some(token) = token_candidate {
            if token.trim() == self.session_token {
                return DebugPortVerdict::Allowed;
            }
        }

        if self.config.isolate_devtools && CHROME_DEVTOOLS_PORTS.contains(&port) {
            return DebugPortVerdict::Blocked {
                port,
                service: "Chrome DevTools",
            };
        }

        if self.config.isolate_node_inspect && NODE_INSPECT_PORTS.contains(&port) {
            return DebugPortVerdict::Blocked {
                port,
                service: "Node.js Inspector",
            };
        }

        if self.config.isolate_debugpy && PYTHON_DEBUGPY_PORTS.contains(&port) {
            return DebugPortVerdict::Blocked {
                port,
                service: "Python debugpy",
            };
        }

        DebugPortVerdict::Allowed
    }
}

// Minimal hex encoding helper to avoid external hex crate dependency
mod hex {
    pub fn encode(data: &[u8]) -> String {
        let mut s = String::with_capacity(data.len() * 2);
        for &b in data {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
        }
        s
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn default_blocks_sensitive_ports_without_token() {
        let guard = DebugPortGuard::new(DebugPortConfig::default());
        assert_eq!(
            guard.check_access(9222, None),
            DebugPortVerdict::Blocked {
                port: 9222,
                service: "Chrome DevTools",
            }
        );
        assert_eq!(
            guard.check_access(9229, None),
            DebugPortVerdict::Blocked {
                port: 9229,
                service: "Node.js Inspector",
            }
        );
        assert_eq!(
            guard.check_access(5678, None),
            DebugPortVerdict::Blocked {
                port: 5678,
                service: "Python debugpy",
            }
        );
        assert_eq!(guard.check_access(8080, None), DebugPortVerdict::Allowed);
        assert_eq!(guard.check_access(3000, None), DebugPortVerdict::Allowed);
    }

    #[test]
    fn valid_session_token_allows_access() {
        let guard = DebugPortGuard::new(DebugPortConfig::default());
        let token = guard.session_token().to_string();
        assert_eq!(
            guard.check_access(9222, Some(&token)),
            DebugPortVerdict::Allowed
        );
        assert_eq!(
            guard.check_access(9229, Some(&token)),
            DebugPortVerdict::Allowed
        );
        assert_eq!(
            guard.check_access(5678, Some(&token)),
            DebugPortVerdict::Allowed
        );

        // Invalid token
        assert_eq!(
            guard.check_access(9222, Some("invalid_token")),
            DebugPortVerdict::Blocked {
                port: 9222,
                service: "Chrome DevTools",
            }
        );
    }

    #[test]
    fn allowed_ports_config_bypasses_block() {
        let config = DebugPortConfig {
            isolate_devtools: true,
            isolate_node_inspect: true,
            isolate_debugpy: true,
            allowed_ports: vec![9229],
        };
        let guard = DebugPortGuard::new(config);
        assert_eq!(guard.check_access(9229, None), DebugPortVerdict::Allowed);
        assert_eq!(
            guard.check_access(9222, None),
            DebugPortVerdict::Blocked {
                port: 9222,
                service: "Chrome DevTools",
            }
        );
    }

    #[test]
    fn selective_feature_flags() {
        let config = DebugPortConfig {
            isolate_devtools: false,
            isolate_node_inspect: true,
            isolate_debugpy: false,
            allowed_ports: vec![],
        };
        let guard = DebugPortGuard::new(config);
        assert_eq!(guard.check_access(9222, None), DebugPortVerdict::Allowed);
        assert_eq!(
            guard.check_access(9229, None),
            DebugPortVerdict::Blocked {
                port: 9229,
                service: "Node.js Inspector",
            }
        );
        assert_eq!(guard.check_access(5678, None), DebugPortVerdict::Allowed);
    }
}
