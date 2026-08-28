//! Dev Server Port Armor, WebSocket Frame Inspector, and Webhook HMAC Gateway.
//!
//! Covers:
//! - **R2.2**: Dev server port armor (`DevServerPortArmor`, `DevPortArmorConfig`, `ProtectedPortRule`, `DevServerSecurityVerdict`)
//! - **R2.7**: WebSocket frame inspector and scrubbing (`WsFrameInspector`, `WsFrameKind`, `WsInspectionPolicy`, `WsFrameMutation`, `WsFrameAction`)
//! - **R2.12**: Webhook gateway with constant-time HMAC validation & payload scrubbing (`WebhookArmorEngine`, `WebhookProviderKind`, `WebhookSecurityPolicy`, `WebhookVerificationResult`)

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

// ============================================================================
// Constant-Time Comparison Utility (Zero-Dependency Cryptographic Equality)
// ============================================================================

/// Constant-time byte slice comparison resistant to timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Constant-time hex string comparison.
pub fn constant_time_eq_hex(a_hex: &str, b_hex: &str) -> bool {
    let a = a_hex.trim().to_ascii_lowercase();
    let b = b_hex.trim().to_ascii_lowercase();
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

// ============================================================================
// RFC 2104 Generic HMAC-SHA256 & HMAC-SHA512 Implementation
// ============================================================================

/// Compute HMAC-SHA256 of `data` using `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let key_hash = hasher.finalize();
        key_block[..32].copy_from_slice(&key_hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner_hash);
    let outer_hash = outer_hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&outer_hash);
    result
}

/// Compute HMAC-SHA512 of `data` using `key`.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    const BLOCK_SIZE: usize = 128;
    let mut key_block = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let mut hasher = Sha512::new();
        hasher.update(key);
        let key_hash = hasher.finalize();
        key_block[..64].copy_from_slice(&key_hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_hasher = Sha512::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha512::new();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner_hash);
    let outer_hash = outer_hasher.finalize();

    let mut result = [0u8; 64];
    result.copy_from_slice(&outer_hash);
    result
}

// ============================================================================
// R2.2: Dev Server Port Armor
// ============================================================================

/// Token-bucket rate limiter per port.
#[derive(Debug)]
struct TokenBucketRateLimiter {
    capacity: u32,
    tokens: f64,
    refill_rate_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucketRateLimiter {
    fn new(rate_per_sec: u32) -> Self {
        Self {
            capacity: rate_per_sec.max(1),
            tokens: rate_per_sec as f64,
            refill_rate_per_sec: rate_per_sec as f64,
            last_refill: Instant::now(),
        }
    }

    fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.refill_rate_per_sec).min(self.capacity as f64);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Security rule for a protected development server port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedPortRule {
    pub port: u16,
    pub description: String,
    pub blocked_route_patterns: Vec<String>,
    pub require_session_auth_header: bool,
    pub max_connections_per_sec: u32,
    pub allowed_origins: Vec<String>,
    pub allowed_hosts: Vec<String>,
}

/// Configuration for Dev Server Port Armor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevPortArmorConfig {
    pub enabled: bool,
    pub default_blocked_routes: Vec<String>,
    pub port_rules: Vec<ProtectedPortRule>,
    pub auth_header_name: String,
}

impl Default for DevPortArmorConfig {
    fn default() -> Self {
        let default_blocked = vec![
            "/__vite_ping".to_string(),
            "/_next/webpack-hmr".to_string(),
            "/console".to_string(),
            "/__debugger__".to_string(),
            "/admin*".to_string(),
            "/eval".to_string(),
            "/phpmyadmin*".to_string(),
            "/debug*".to_string(),
            "/actuator*".to_string(),
        ];

        let default_ports = vec![
            ProtectedPortRule {
                port: 3000, // Next.js / React / Express
                description: "Node / Next.js dev server".to_string(),
                blocked_route_patterns: default_blocked.clone(),
                require_session_auth_header: false,
                max_connections_per_sec: 100,
                allowed_origins: vec!["http://localhost:3000".to_string(), "http://127.0.0.1:3000".to_string()],
                allowed_hosts: vec!["localhost:3000".to_string(), "127.0.0.1:3000".to_string(), "localhost".to_string(), "127.0.0.1".to_string()],
            },
            ProtectedPortRule {
                port: 5173, // Vite
                description: "Vite HMR frontend dev server".to_string(),
                blocked_route_patterns: default_blocked.clone(),
                require_session_auth_header: false,
                max_connections_per_sec: 100,
                allowed_origins: vec!["http://localhost:5173".to_string(), "http://127.0.0.1:5173".to_string()],
                allowed_hosts: vec!["localhost:5173".to_string(), "127.0.0.1:5173".to_string(), "localhost".to_string(), "127.0.0.1".to_string()],
            },
            ProtectedPortRule {
                port: 8000, // FastAPI / Django
                description: "Python FastAPI / Django dev server".to_string(),
                blocked_route_patterns: default_blocked.clone(),
                require_session_auth_header: false,
                max_connections_per_sec: 50,
                allowed_origins: vec!["http://localhost:8000".to_string(), "http://127.0.0.1:8000".to_string()],
                allowed_hosts: vec!["localhost:8000".to_string(), "127.0.0.1:8000".to_string(), "localhost".to_string(), "127.0.0.1".to_string()],
            },
            ProtectedPortRule {
                port: 8080, // Webpack / Tomcat / General dev
                description: "General dev server port 8080".to_string(),
                blocked_route_patterns: default_blocked.clone(),
                require_session_auth_header: false,
                max_connections_per_sec: 50,
                allowed_origins: vec!["http://localhost:8080".to_string(), "http://127.0.0.1:8080".to_string()],
                allowed_hosts: vec!["localhost:8080".to_string(), "127.0.0.1:8080".to_string(), "localhost".to_string(), "127.0.0.1".to_string()],
            },
        ];

        Self {
            enabled: true,
            default_blocked_routes: default_blocked,
            port_rules: default_ports,
            auth_header_name: "X-Vetto-Dev-Auth".to_string(),
        }
    }
}

/// Security inspection verdict for dev server traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DevServerSecurityVerdict {
    /// Traffic is legitimate and permitted.
    AllowTraffic,
    /// Unauthorized route access attempt on dev server.
    BlockUnauthorizedDevRoute { port: u16, route: String },
    /// Missing or invalid session authentication token.
    RejectMissingAuthHeader { port: u16, header_name: String },
    /// Rate limit exceeded for local port.
    RateLimitThrottled { port: u16, limit_qps: u32 },
    /// Host header injection or spoofing detected.
    HostHeaderViolation { port: u16, host: String },
    /// Cross-Origin Request Forgery (CSRF) origin mismatch.
    CsrfOriginBlocked { port: u16, origin: String },
}

/// Dev Server Port Armor engine.
pub struct DevServerPortArmor {
    config: DevPortArmorConfig,
    active_session_token: String,
    port_rules: HashMap<u16, ProtectedPortRule>,
    rate_limiters: Mutex<HashMap<u16, TokenBucketRateLimiter>>,
}

impl DevServerPortArmor {
    /// Create new Dev Server Port Armor engine with session token.
    pub fn new(config: DevPortArmorConfig, active_session_token: String) -> Self {
        let mut port_rules = HashMap::new();
        let mut rate_limiters = HashMap::new();

        for rule in &config.port_rules {
            port_rules.insert(rule.port, rule.clone());
            rate_limiters.insert(rule.port, TokenBucketRateLimiter::new(rule.max_connections_per_sec));
        }

        Self {
            config,
            active_session_token,
            port_rules,
            rate_limiters: Mutex::new(rate_limiters),
        }
    }

    /// Inspect an HTTP request directed at a local dev server port.
    pub fn inspect_dev_request(
        &self,
        dest_port: u16,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> DevServerSecurityVerdict {
        if !self.config.enabled {
            return DevServerSecurityVerdict::AllowTraffic;
        }

        let rule = match self.port_rules.get(&dest_port) {
            Some(r) => r,
            None => return DevServerSecurityVerdict::AllowTraffic,
        };

        // 1. Rate limiting check
        if let Ok(mut limiters) = self.rate_limiters.lock() {
            if let Some(limiter) = limiters.get_mut(&dest_port) {
                if !limiter.try_acquire() {
                    return DevServerSecurityVerdict::RateLimitThrottled {
                        port: dest_port,
                        limit_qps: rule.max_connections_per_sec,
                    };
                }
            }
        }

        // 2. Host header injection check
        if let Some(host_val) = headers.get("host") {
            let host_clean = host_val.trim();
            if !rule.allowed_hosts.is_empty()
                && !rule.allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(host_clean))
            {
                return DevServerSecurityVerdict::HostHeaderViolation {
                    port: dest_port,
                    host: host_clean.to_string(),
                };
            }
        }

        // 3. CSRF Origin header check
        if let Some(origin_val) = headers.get("origin") {
            let origin_clean = origin_val.trim();
            if !rule.allowed_origins.is_empty()
                && !rule.allowed_origins.iter().any(|o| o.eq_ignore_ascii_case(origin_clean))
            {
                return DevServerSecurityVerdict::CsrfOriginBlocked {
                    port: dest_port,
                    origin: origin_clean.to_string(),
                };
            }
        }

        // 4. Session auth header validation if required
        if rule.require_session_auth_header {
            let header_key = self.config.auth_header_name.to_lowercase();
            let auth_token = headers.get(&header_key);
            match auth_token {
                Some(tok) if constant_time_eq(tok.as_bytes(), self.active_session_token.as_bytes()) => {}
                _ => {
                    return DevServerSecurityVerdict::RejectMissingAuthHeader {
                        port: dest_port,
                        header_name: self.config.auth_header_name.clone(),
                    };
                }
            }
        }

        // 5. Blocked route patterns check
        let clean_path = path.split('?').next().unwrap_or(path);
        for pattern in &rule.blocked_route_patterns {
            if route_pattern_matches(pattern, clean_path) {
                return DevServerSecurityVerdict::BlockUnauthorizedDevRoute {
                    port: dest_port,
                    route: clean_path.to_string(),
                };
            }
        }

        DevServerSecurityVerdict::AllowTraffic
    }
}

fn route_pattern_matches(pattern: &str, path: &str) -> bool {
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        path.starts_with(prefix)
    } else {
        path == pattern
    }
}

// ============================================================================
// R2.7: WebSocket Frame Inspector & Scrubbing
// ============================================================================

/// WebSocket Opcode per RFC 6455.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WsFrameKind {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl WsFrameKind {
    pub fn from_opcode(opcode: u8) -> Option<Self> {
        match opcode {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }

    pub fn to_opcode(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }
}

/// Policy for inspecting and sanitizing WebSocket streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsInspectionPolicy {
    pub max_frame_size_bytes: usize,
    pub allow_binary_frames: bool,
    pub redact_secrets_in_text_frames: bool,
    pub blocked_json_methods: Vec<String>,
    pub secret_patterns: Vec<String>,
    pub max_continuation_frames: usize,
}

impl Default for WsInspectionPolicy {
    fn default() -> Self {
        Self {
            max_frame_size_bytes: 1024 * 1024, // 1 MB
            allow_binary_frames: false,        // By default block arbitrary binary exfiltration channels
            redact_secrets_in_text_frames: true,
            blocked_json_methods: vec!["eval".to_string(), "exec".to_string(), "spawn_pty".to_string()],
            secret_patterns: vec![
                "ghp_".to_string(),
                "glpat-".to_string(),
                "sk-".to_string(),
                "AKIA".to_string(),
                "bearer ".to_string(),
            ],
            max_continuation_frames: 100,
        }
    }
}

/// Action to perform on an inspected WebSocket frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsFrameAction {
    ForwardUnmodified,
    MutatePayload(WsFrameMutation),
    DropFrame { reason: String },
    TerminateConnection { close_code: u16, reason: String },
}

/// Payload mutation after secret scrubbing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsFrameMutation {
    None,
    RedactedText(String),
    MaskedBinary(Vec<u8>),
}

/// Errors raised during WebSocket frame decoding and validation.
#[derive(Debug, Error)]
pub enum WsInspectionError {
    #[error("Frame length ({0} bytes) exceeds configured limit of {1} bytes")]
    FrameTooLarge(usize, usize),
    #[error("Malformed WebSocket frame: {0}")]
    MalformedFrame(String),
    #[error("Invalid UTF-8 in WebSocket text frame: {0}")]
    InvalidUtf8(String),
}

/// Header metadata parsed from an RFC 6455 WebSocket frame.
#[derive(Debug, Clone)]
pub struct WsFrameHeader {
    pub fin: bool,
    pub rsv: u8,
    pub kind: WsFrameKind,
    pub masked: bool,
    pub payload_len: usize,
    pub masking_key: Option<[u8; 4]>,
    pub header_size: usize,
}

/// WebSocket Stream and Frame Security Inspector.
pub struct WsFrameInspector {
    policy: WsInspectionPolicy,
}

impl WsFrameInspector {
    /// Create new WebSocket frame inspector.
    pub fn new(policy: WsInspectionPolicy) -> Self {
        Self { policy }
    }

    /// Parse frame header from raw wire bytes.
    pub fn parse_header(&self, raw: &[u8]) -> Result<WsFrameHeader, WsInspectionError> {
        if raw.len() < 2 {
            return Err(WsInspectionError::MalformedFrame("Buffer too short for WS header".to_string()));
        }

        let byte0 = raw[0];
        let byte1 = raw[1];

        let fin = (byte0 & 0x80) != 0;
        let rsv = (byte0 & 0x70) >> 4;
        let opcode = byte0 & 0x0F;

        let kind = WsFrameKind::from_opcode(opcode)
            .ok_or_else(|| WsInspectionError::MalformedFrame(format!("Unknown opcode: 0x{:x}", opcode)))?;

        let masked = (byte1 & 0x80) != 0;
        let mut len_code = (byte1 & 0x7F) as usize;
        let mut offset = 2;

        let payload_len = if len_code == 126 {
            if raw.len() < offset + 2 {
                return Err(WsInspectionError::MalformedFrame("Incomplete 16-bit extended length".to_string()));
            }
            let len = u16::from_be_bytes([raw[offset], raw[offset + 1]]) as usize;
            offset += 2;
            len
        } else if len_code == 127 {
            if raw.len() < offset + 8 {
                return Err(WsInspectionError::MalformedFrame("Incomplete 64-bit extended length".to_string()));
            }
            let len = u64::from_be_bytes([
                raw[offset],
                raw[offset + 1],
                raw[offset + 2],
                raw[offset + 3],
                raw[offset + 4],
                raw[offset + 5],
                raw[offset + 6],
                raw[offset + 7],
            ]) as usize;
            offset += 8;
            len
        } else {
            len_code
        };

        let masking_key = if masked {
            if raw.len() < offset + 4 {
                return Err(WsInspectionError::MalformedFrame("Incomplete masking key".to_string()));
            }
            let key = [raw[offset], raw[offset + 1], raw[offset + 2], raw[offset + 3]];
            offset += 4;
            Some(key)
        } else {
            None
        };

        Ok(WsFrameHeader {
            fin,
            rsv,
            kind,
            masked,
            payload_len,
            masking_key,
            header_size: offset,
        })
    }

    /// Inspect frame payload and execute policy decisions (scrubbing, blocking, unmasking).
    pub fn inspect_payload(&self, kind: WsFrameKind, payload: &[u8]) -> Result<WsFrameAction, WsInspectionError> {
        if payload.len() > self.policy.max_frame_size_bytes {
            return Ok(WsFrameAction::TerminateConnection {
                close_code: 1009, // Message Too Big
                reason: format!("Frame payload size {} exceeds limit {}", payload.len(), self.policy.max_frame_size_bytes),
            });
        }

        match kind {
            WsFrameKind::Binary => {
                if !self.policy.allow_binary_frames {
                    return Ok(WsFrameAction::TerminateConnection {
                        close_code: 1003, // Unsupported Data
                        reason: "Binary WebSocket frames are forbidden by policy".to_string(),
                    });
                }
                Ok(WsFrameAction::ForwardUnmodified)
            }
            WsFrameKind::Text => {
                let text = match std::str::from_utf8(payload) {
                    Ok(s) => s,
                    Err(e) => return Err(WsInspectionError::InvalidUtf8(e.to_string())),
                };

                // Check blocked JSON methods
                if let Ok(json_val) = serde_json::from_str::<Value>(text) {
                    if let Some(method) = json_val.get("method").and_then(|m| m.as_str()) {
                        if self.policy.blocked_json_methods.iter().any(|b| b.eq_ignore_ascii_case(method)) {
                            return Ok(WsFrameAction::DropFrame {
                                reason: format!("Blocked dangerous WebSocket JSON-RPC method: '{}'", method),
                            });
                        }
                    }
                }

                // Redact secrets in text frame
                if self.policy.redact_secrets_in_text_frames {
                    let mut modified = text.to_string();
                    let mut changed = false;

                    for pattern in &self.policy.secret_patterns {
                        if modified.contains(pattern) {
                            modified = scrub_secret_pattern(&modified, pattern);
                            changed = true;
                        }
                    }

                    if changed {
                        return Ok(WsFrameAction::MutatePayload(WsFrameMutation::RedactedText(modified)));
                    }
                }

                Ok(WsFrameAction::ForwardUnmodified)
            }
            WsFrameKind::Close | WsFrameKind::Ping | WsFrameKind::Pong | WsFrameKind::Continuation => {
                Ok(WsFrameAction::ForwardUnmodified)
            }
        }
    }
}

fn scrub_secret_pattern(text: &str, pattern: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut remainder = text;

    while let Some(pos) = remainder.find(pattern) {
        out.push_str(&remainder[..pos]);
        out.push_str(pattern);
        out.push_str("[REDACTED_BY_VETTO]");

        let after_pat = &remainder[pos + pattern.len()..];
        let token_len = after_pat
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == '}')
            .unwrap_or(after_pat.len());

        remainder = &after_pat[token_len..];
    }
    out.push_str(remainder);
    out
}

// ============================================================================
// R2.12: Webhook Gateway with Constant-Time HMAC Validation & Payload Scrubbing
// ============================================================================

/// Recognized Webhook Provider Signature Algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WebhookProviderKind {
    GitHubSha256,
    StripeV1,
    SlackV0,
    ShopifyHmacSha256,
    GenericHmacSha256,
    GenericHmacSha512,
}

/// Webhook security and validation policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSecurityPolicy {
    pub provider: WebhookProviderKind,
    pub secret_key: Vec<u8>,
    pub max_payload_size_bytes: usize,
    pub tolerance_timestamp_seconds: u64,
    pub sanitize_outbound: bool,
    pub sensitive_field_names: Vec<String>,
}

impl Default for WebhookSecurityPolicy {
    fn default() -> Self {
        Self {
            provider: WebhookProviderKind::GitHubSha256,
            secret_key: Vec::new(),
            max_payload_size_bytes: 5 * 1024 * 1024, // 5 MB
            tolerance_timestamp_seconds: 300,        // 5 minute replay tolerance window
            sanitize_outbound: true,
            sensitive_field_names: vec![
                "password".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "api_key".to_string(),
                "private_key".to_string(),
                "ssh_key".to_string(),
                "authorization".to_string(),
                "access_token".to_string(),
            ],
        }
    }
}

/// Result of webhook signature verification and payload sanitation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebhookVerificationResult {
    /// Valid signature and optional sanitized JSON payload.
    Valid {
        provider: WebhookProviderKind,
        sanitized_payload: Option<Value>,
        timestamp: Option<i64>,
    },
    /// Cryptographic signature mismatch.
    InvalidSignature {
        expected_preview: String,
        computed_preview: String,
        reason: String,
    },
    /// Webhook timestamp expired (replay attack defense).
    TimestampExpired {
        age_seconds: i64,
        max_allowed: u64,
    },
    /// Malformed signature header format or payload.
    MalformedPayload(String),
}

/// Errors raised during webhook processing.
#[derive(Debug, Error)]
pub enum WebhookSanitizeError {
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Secret redaction error: {0}")]
    RedactionError(String),
}

/// Webhook Armor Gateway Engine.
pub struct WebhookArmorEngine {
    policies: RwLock<HashMap<WebhookProviderKind, WebhookSecurityPolicy>>,
}

impl WebhookArmorEngine {
    /// Create new engine with given security policies.
    pub fn new(policies: Vec<WebhookSecurityPolicy>) -> Self {
        let mut map = HashMap::new();
        for p in policies {
            map.insert(p.provider, p);
        }
        Self {
            policies: RwLock::new(map),
        }
    }

    /// Register or update a security policy for a webhook provider.
    pub fn register_policy(&self, policy: WebhookSecurityPolicy) {
        if let Ok(mut map) = self.policies.write() {
            map.insert(policy.provider, policy);
        }
    }

    /// Verify an incoming webhook payload signature and sanitize content.
    pub fn verify_and_sanitize_incoming(
        &self,
        provider: WebhookProviderKind,
        raw_body: &[u8],
        signature_header: &str,
    ) -> WebhookVerificationResult {
        let policies = match self.policies.read() {
            Ok(p) => p,
            Err(_) => {
                return WebhookVerificationResult::MalformedPayload("Internal policy lock poisoned".to_string())
            }
        };

        let policy = match policies.get(&provider) {
            Some(p) => p,
            None => {
                return WebhookVerificationResult::MalformedPayload(format!("No policy configured for provider {:?}", provider))
            }
        };

        if raw_body.len() > policy.max_payload_size_bytes {
            return WebhookVerificationResult::MalformedPayload(format!(
                "Payload size {} exceeds maximum {}",
                raw_body.len(),
                policy.max_payload_size_bytes
            ));
        }

        let mut webhook_timestamp: Option<i64> = None;

        // Perform signature verification per provider
        let signature_valid = match provider {
            WebhookProviderKind::GitHubSha256 => {
                // Header format: sha256=HEX_DIGEST
                let expected_hex = if let Some(stripped) = signature_header.strip_prefix("sha256=") {
                    stripped.trim()
                } else {
                    signature_header.trim()
                };

                let computed_mac = hmac_sha256(&policy.secret_key, raw_body);
                let computed_hex = hex_encode(&computed_mac);
                constant_time_eq_hex(expected_hex, &computed_hex)
            }
            WebhookProviderKind::StripeV1 => {
                // Header format: t=TIMESTAMP,v1=HEX_DIGEST
                let mut t_val = None;
                let mut v1_val = None;

                for part in signature_header.split(',') {
                    let mut kv = part.splitn(2, '=');
                    match (kv.next().map(str::trim), kv.next().map(str::trim)) {
                        (Some("t"), Some(val)) => t_val = Some(val),
                        (Some("v1"), Some(val)) => v1_val = Some(val),
                        _ => {}
                    }
                }

                match (t_val, v1_val) {
                    (Some(t_str), Some(v1_hex)) => {
                        if let Ok(ts) = t_str.parse::<i64>() {
                            webhook_timestamp = Some(ts);
                            let now = Utc::now().timestamp();
                            let age = (now - ts).abs();
                            if age as u64 > policy.tolerance_timestamp_seconds {
                                return WebhookVerificationResult::TimestampExpired {
                                    age_seconds: age,
                                    max_allowed: policy.tolerance_timestamp_seconds,
                                };
                            }

                            // Signed payload = t.payload
                            let mut signed_payload = Vec::with_capacity(t_str.len() + 1 + raw_body.len());
                            signed_payload.extend_from_slice(t_str.as_bytes());
                            signed_payload.push(b'.');
                            signed_payload.extend_from_slice(raw_body);

                            let computed_mac = hmac_sha256(&policy.secret_key, &signed_payload);
                            let computed_hex = hex_encode(&computed_mac);
                            constant_time_eq_hex(v1_hex, &computed_hex)
                        } else {
                            false
                        }
                    }
                    _ => false,
                }
            }
            WebhookProviderKind::SlackV0 => {
                // Header format: v0=HEX_DIGEST, with X-Slack-Request-Timestamp
                let expected_hex = signature_header.strip_prefix("v0=").unwrap_or(signature_header).trim();
                let computed_mac = hmac_sha256(&policy.secret_key, raw_body);
                let computed_hex = hex_encode(&computed_mac);
                constant_time_eq_hex(expected_hex, &computed_hex)
            }
            WebhookProviderKind::ShopifyHmacSha256 | WebhookProviderKind::GenericHmacSha256 => {
                let computed_mac = hmac_sha256(&policy.secret_key, raw_body);
                let computed_hex = hex_encode(&computed_mac);
                constant_time_eq_hex(signature_header.trim(), &computed_hex)
            }
            WebhookProviderKind::GenericHmacSha512 => {
                let computed_mac = hmac_sha512(&policy.secret_key, raw_body);
                let computed_hex = hex_encode(&computed_mac);
                constant_time_eq_hex(signature_header.trim(), &computed_hex)
            }
        };

        if !signature_valid {
            return WebhookVerificationResult::InvalidSignature {
                expected_preview: signature_header.chars().take(16).collect(),
                computed_preview: "[REDACTED_CRYPTO_HASH]".to_string(),
                reason: "HMAC cryptographic signature mismatch".to_string(),
            };
        }

        // Parse and optionally sanitize JSON payload
        let sanitized_payload = if let Ok(mut json_val) = serde_json::from_slice::<Value>(raw_body) {
            self.sanitize_payload_tree(&mut json_val, &policy.sensitive_field_names);
            Some(json_val)
        } else {
            None
        };

        WebhookVerificationResult::Valid {
            provider,
            sanitized_payload,
            timestamp: webhook_timestamp,
        }
    }

    /// Recursively sanitize sensitive keys in a JSON Value tree.
    pub fn sanitize_payload_tree(&self, value: &mut Value, sensitive_keys: &[String]) {
        match value {
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    let k_lower = k.to_lowercase();
                    if sensitive_keys.iter().any(|s| k_lower.contains(s)) {
                        *v = Value::String("[REDACTED_BY_VETTO_WEBHOOK_ARMOR]".to_string());
                    } else {
                        self.sanitize_payload_tree(v, sensitive_keys);
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.sanitize_payload_tree(item, sensitive_keys);
                }
            }
            _ => {}
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = b"super_secret_token_123";
        let b = b"super_secret_token_123";
        let c = b"super_secret_token_456";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, b"short"));
    }

    #[test]
    fn test_hmac_sha256_rfc_vectors() {
        // RFC 4231 Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?"
        // HMAC-SHA256 = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac_sha256(key, data);
        assert_eq!(
            hex_encode(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn test_dev_server_port_armor() {
        let config = DevPortArmorConfig::default();
        let armor = DevServerPortArmor::new(config, "vetto-session-secret-999".to_string());

        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "localhost:3000".to_string());
        headers.insert("origin".to_string(), "http://localhost:3000".to_string());

        // Legitimate frontend request -> Allow
        let v1 = armor.inspect_dev_request(3000, "/api/todos", &headers);
        assert_eq!(v1, DevServerSecurityVerdict::AllowTraffic);

        // Blocked internal dev route (/__vite_ping or /console) -> BlockUnauthorizedDevRoute
        let v2 = armor.inspect_dev_request(3000, "/console", &headers);
        assert!(matches!(v2, DevServerSecurityVerdict::BlockUnauthorizedDevRoute { .. }));

        // Host header spoofing attack -> HostHeaderViolation
        let mut bad_host_headers = headers.clone();
        bad_host_headers.insert("host".to_string(), "evil-site.com".to_string());
        let v3 = armor.inspect_dev_request(3000, "/index.html", &bad_host_headers);
        assert!(matches!(v3, DevServerSecurityVerdict::HostHeaderViolation { .. }));
    }

    #[test]
    fn test_ws_frame_inspector_text_and_redaction() {
        let policy = WsInspectionPolicy::default();
        let inspector = WsFrameInspector::new(policy);

        // Text frame with API secret -> Redacted
        let payload = br#"{"action": "sync", "token": "ghp_1234567890abcdef"}"#;
        let action = inspector.inspect_payload(WsFrameKind::Text, payload).unwrap();

        match action {
            WsFrameAction::MutatePayload(WsFrameMutation::RedactedText(redacted)) => {
                assert!(redacted.contains("ghp_[REDACTED_BY_VETTO]"));
                assert!(!redacted.contains("ghp_1234567890abcdef"));
            }
            other => panic!("Expected MutatePayload with RedactedText, got {:?}", other),
        }

        // Binary frame blocked by default policy
        let bin_action = inspector.inspect_payload(WsFrameKind::Binary, &[0x00, 0xFF]).unwrap();
        assert!(matches!(bin_action, WsFrameAction::TerminateConnection { .. }));
    }

    #[test]
    fn test_webhook_armor_github_hmac() {
        let secret = b"my_webhook_secret_key_123".to_vec();
        let policy = WebhookSecurityPolicy {
            provider: WebhookProviderKind::GitHubSha256,
            secret_key: secret.clone(),
            ..Default::default()
        };

        let engine = WebhookArmorEngine::new(vec![policy]);

        let payload = br#"{"action": "opened", "issue": {"title": "Bug", "user_token": "secret_123"}}"#;
        let mac = hmac_sha256(&secret, payload);
        let header = format!("sha256={}", hex_encode(&mac));

        // Valid signature -> Valid and sanitized
        let res = engine.verify_and_sanitize_incoming(WebhookProviderKind::GitHubSha256, payload, &header);
        match res {
            WebhookVerificationResult::Valid { sanitized_payload, .. } => {
                let json = sanitized_payload.unwrap();
                assert_eq!(
                    json["issue"]["user_token"].as_str().unwrap(),
                    "[REDACTED_BY_VETTO_WEBHOOK_ARMOR]"
                );
            }
            other => panic!("Expected Valid result, got {:?}", other),
        }

        // Invalid signature -> InvalidSignature
        let bad_res = engine.verify_and_sanitize_incoming(
            WebhookProviderKind::GitHubSha256,
            payload,
            "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(matches!(bad_res, WebhookVerificationResult::InvalidSignature { .. }));
    }
}
