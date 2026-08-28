//! Deep L7 Access Control Lists, DNS Rebinding Defense, AF_UNIX Firewall, and HTTP Smuggling Guard.
//!
//! Covers:
//! - **R2.1**: L7 HTTP/HTTPS method and endpoint REST filtering (`L7HttpFilterEngine`, `L7AclRule`, `L7AclAction`, `HttpMethod`, `L7PathPattern`)
//! - **R2.5**: DNS rebinding & private network defense (`DnsRebindingArmor`, `IpClassification`, `DnsResolutionRecord`, `PrivateNetworkPolicy`)
//! - **R2.8**: AF_UNIX local socket firewall & FD passing inspector (`UnixSocketFirewall`, `UnixSocketAcl`, `FdPassingRule`, `AncillaryDataReport`)
//! - **R2.9**: HTTP request smuggling & framing anomaly detector (`RequestSmugglingDetector`, `HttpFramingAnomaly`, `SmugglingRiskLevel`)

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// R2.1: L7 HTTP/HTTPS Method & Endpoint Filtering
// ============================================================================

/// Canonical and custom HTTP methods for L7 inspection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Connect,
    Trace,
    Any,
    Custom(String),
}

impl HttpMethod {
    /// Parse method from standard ASCII string (case-insensitive for standard verbs).
    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "PATCH" => Self::Patch,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "CONNECT" => Self::Connect,
            "TRACE" => Self::Trace,
            "*" | "ANY" => Self::Any,
            other => Self::Custom(other.to_string()),
        }
    }

    /// Convert method to string representation.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Connect => "CONNECT",
            Self::Trace => "TRACE",
            Self::Any => "*",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Check whether this method matches another method (considering `Any` wildcard).
    pub fn matches(&self, other: &HttpMethod) -> bool {
        match (self, other) {
            (Self::Any, _) | (_, Self::Any) => true,
            (Self::Get, Self::Get) => true,
            (Self::Post, Self::Post) => true,
            (Self::Put, Self::Put) => true,
            (Self::Delete, Self::Delete) => true,
            (Self::Patch, Self::Patch) => true,
            (Self::Head, Self::Head) => true,
            (Self::Options, Self::Options) => true,
            (Self::Connect, Self::Connect) => true,
            (Self::Trace, Self::Trace) => true,
            (Self::Custom(a), Self::Custom(b)) => a.eq_ignore_ascii_case(b),
            _ => false,
        }
    }
}

/// Pattern matching strategy for URI paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum L7PathPattern {
    /// Exact match on the entire path (e.g. `/api/v1/user`).
    Exact(String),
    /// Prefix match (e.g. `/repos/`).
    Prefix(String),
    /// Glob matching pattern with `*` and `?` (e.g. `/repos/*/*/keys`).
    Glob(String),
    /// Parameterized template matching (e.g. `/repos/:owner/:repo/pulls`).
    Parameterized(String),
    /// Match any path.
    CatchAll,
}

impl L7PathPattern {
    /// Evaluate whether a concrete request path matches this pattern.
    pub fn matches_path(&self, request_path: &str) -> bool {
        let clean_path = request_path.split('?').next().unwrap_or(request_path);
        let normalized = if clean_path.is_empty() { "/" } else { clean_path };

        match self {
            Self::CatchAll => true,
            Self::Exact(expected) => {
                let exp_norm = if expected.is_empty() { "/" } else { expected.as_str() };
                normalized == exp_norm
            }
            Self::Prefix(prefix) => normalized.starts_with(prefix),
            Self::Glob(glob_pat) => glob_match(glob_pat, normalized),
            Self::Parameterized(template) => parameterized_match(template, normalized),
        }
    }
}

/// Simple glob matcher without external regex dependency.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p_bytes = pattern.as_bytes();
    let t_bytes = text.as_bytes();
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_p = None;
    let mut match_t = 0;

    while t_idx < t_bytes.len() {
        if p_idx < p_bytes.len() && (p_bytes[p_idx] == b'?' || p_bytes[p_idx] == t_bytes[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
            star_p = Some(p_idx);
            p_idx += 1;
            match_t = t_idx;
        } else if let Some(sp) = star_p {
            p_idx = sp + 1;
            match_t += 1;
            t_idx = match_t;
        } else {
            return false;
        }
    }

    while p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
        p_idx += 1;
    }

    p_idx == p_bytes.len()
}

/// Match parameterized routes like `/repos/:owner/:repo/issues` against `/repos/shleder/vetto/issues`.
fn parameterized_match(template: &str, path: &str) -> bool {
    let t_parts: Vec<&str> = template.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    let p_parts: Vec<&str> = path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();

    if t_parts.len() != p_parts.len() {
        return false;
    }

    for (t, p) in t_parts.iter().zip(p_parts.iter()) {
        if t.starts_with(':') {
            // Parameter wildcard matches any non-empty segment
            if p.is_empty() {
                return false;
            }
        } else if *t != *p {
            return false;
        }
    }

    true
}

/// Action to execute when an L7 rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum L7AclAction {
    /// Allow the request immediately.
    Allow,
    /// Block the request and return synthetic HTTP 403 Forbidden with message.
    BlockWith403 { message: String },
    /// Drop the TCP connection immediately without response.
    DropConnection,
    /// Require interactive human operator approval.
    RequireApproval { prompt: String },
    /// Allow the request but emit an audit warning event.
    LogAndAllow,
    /// Redirect to another endpoint.
    Redirect { target_url: String },
}

/// Rule definition for L7 REST endpoint filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7AclRule {
    pub id: String,
    pub description: String,
    pub method: HttpMethod,
    pub host_pattern: String,
    pub path_pattern: L7PathPattern,
    pub action: L7AclAction,
    pub priority: i32,
    pub enabled: bool,
}

/// Verdict emitted by the L7 filter engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7InspectionVerdict {
    pub action: L7AclAction,
    pub matched_rule_id: Option<String>,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

/// Compile error for invalid L7 rules.
#[derive(Debug, Error)]
pub enum L7CompileError {
    #[error("Empty rule ID or invalid host pattern: {0}")]
    InvalidRule(String),
    #[error("Duplicate rule ID: {0}")]
    DuplicateRuleId(String),
}

/// High-performance L7 HTTP/HTTPS Policy Filter Engine.
pub struct L7HttpFilterEngine {
    rules: RwLock<Vec<L7AclRule>>,
    default_action: L7AclAction,
}

impl L7HttpFilterEngine {
    /// Create a new engine with a default fallback action (typically BlockWith403 or DropConnection).
    pub fn new(default_action: L7AclAction) -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            default_action,
        }
    }

    /// Create engine pre-loaded and sorted by priority (highest priority first).
    pub fn from_rules(mut rules: Vec<L7AclRule>, default_action: L7AclAction) -> Result<Self, L7CompileError> {
        let mut seen_ids = HashSet::new();
        for r in &rules {
            if r.id.trim().is_empty() {
                return Err(L7CompileError::InvalidRule("Rule ID cannot be empty".to_string()));
            }
            if !seen_ids.insert(r.id.clone()) {
                return Err(L7CompileError::DuplicateRuleId(r.id.clone()));
            }
        }
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        Ok(Self {
            rules: RwLock::new(rules),
            default_action,
        })
    }

    /// Add a new rule dynamically.
    pub fn add_rule(&self, rule: L7AclRule) -> Result<(), L7CompileError> {
        if rule.id.trim().is_empty() {
            return Err(L7CompileError::InvalidRule("Rule ID cannot be empty".to_string()));
        }
        let mut rules = self.rules.write().map_err(|_| L7CompileError::InvalidRule("Lock poisoned".to_string()))?;
        if rules.iter().any(|r| r.id == rule.id) {
            return Err(L7CompileError::DuplicateRuleId(rule.id));
        }
        rules.push(rule);
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        Ok(())
    }

    /// Evaluate an incoming HTTP request against the compiled rule set.
    pub fn evaluate_request(&self, method: &HttpMethod, host: &str, path_and_query: &str) -> L7InspectionVerdict {
        let rules_guard = match self.rules.read() {
            Ok(g) => g,
            Err(_) => {
                return L7InspectionVerdict {
                    action: L7AclAction::DropConnection,
                    matched_rule_id: None,
                    reason: "Internal engine lock failure".to_string(),
                    timestamp: Utc::now(),
                }
            }
        };

        let clean_host = host.split(':').next().unwrap_or(host).to_lowercase();
        let path = path_and_query.split('?').next().unwrap_or(path_and_query);

        for rule in rules_guard.iter() {
            if !rule.enabled {
                continue;
            }

            // Check host match (supports exact or glob host like *.github.com)
            let host_matches = if rule.host_pattern == "*" || rule.host_pattern.is_empty() {
                true
            } else if rule.host_pattern.starts_with("*.") {
                let suffix = &rule.host_pattern[1..]; // e.g. ".github.com"
                clean_host.ends_with(suffix) || clean_host == &rule.host_pattern[2..]
            } else {
                clean_host.eq_ignore_ascii_case(&rule.host_pattern)
            };

            if !host_matches {
                continue;
            }

            // Check HTTP method match
            if !rule.method.matches(method) {
                continue;
            }

            // Check URI path match
            if !rule.path_pattern.matches_path(path) {
                continue;
            }

            // Matched highest-priority rule
            return L7InspectionVerdict {
                action: rule.action.clone(),
                matched_rule_id: Some(rule.id.clone()),
                reason: format!("Matched rule '{}' ({})", rule.id, rule.description),
                timestamp: Utc::now(),
            };
        }

        // Fallback default action
        L7InspectionVerdict {
            action: self.default_action.clone(),
            matched_rule_id: None,
            reason: "No explicit rule matched; applying default L7 fallback action".to_string(),
            timestamp: Utc::now(),
        }
    }
}

// ============================================================================
// R2.5: DNS Rebinding & Private Network Defense
// ============================================================================

/// Detailed classification of an IP address to defend against rebinding and SSRF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpClassification {
    Public,
    PrivateRfc1918,
    Loopback,
    LinkLocalRfc3927,
    CarrierGradeNatRfc6598,
    Documentation,
    Multicast,
    Broadcast,
    Unspecified,
    BogonOther,
}

impl IpClassification {
    /// Classify an IPv4 or IPv6 address according to RFC standards.
    pub fn classify(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                if v4.is_loopback() {
                    Self::Loopback
                } else if v4.is_unspecified() {
                    Self::Unspecified
                } else if v4.is_broadcast() {
                    Self::Broadcast
                } else if v4.is_multicast() {
                    Self::Multicast
                } else if v4.is_link_local() || (octets[0] == 169 && octets[1] == 254) {
                    // RFC 3927: 169.254.0.0/16 (includes AWS/cloud metadata 169.254.169.254)
                    Self::LinkLocalRfc3927
                } else if v4.is_private() {
                    // RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
                    Self::PrivateRfc1918
                } else if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) {
                    // RFC 6598: Carrier Grade NAT 100.64.0.0/10 (often used by Tailscale/CGNAT)
                    Self::CarrierGradeNatRfc6598
                } else if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                    || (octets[0] == 198 && (octets[1] == 51 && octets[2] == 100))
                    || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                {
                    // RFC 5737 Documentation ranges (TEST-NET-1/2/3)
                    Self::Documentation
                } else if octets[0] == 0 || (octets[0] >= 240 && octets[0] <= 255) {
                    // 0.0.0.0/8 and Class E 240.0.0.0/4
                    Self::BogonOther
                } else {
                    Self::Public
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    Self::Loopback
                } else if v6.is_unspecified() {
                    Self::Unspecified
                } else if v6.is_multicast() {
                    Self::Multicast
                } else {
                    let segs = v6.segments();
                    // Unique Local Addresses (fc00::/7)
                    if (segs[0] & 0xfe00) == 0xfc00 {
                        Self::PrivateRfc1918
                    }
                    // Link-Local Unicast (fe80::/10)
                    else if (segs[0] & 0xffc0) == 0xfe80 {
                        Self::LinkLocalRfc3927
                    }
                    // Documentation (2001:db8::/32)
                    else if segs[0] == 0x2001 && segs[1] == 0x0db8 {
                        Self::Documentation
                    } else {
                        Self::Public
                    }
                }
            }
        }
    }

    /// Check if the classification is safe for public internet egress.
    pub fn is_routable_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    /// Check if the classification represents a dangerous local or bogon destination.
    pub fn is_forbidden_bogon_or_private(&self) -> bool {
        !self.is_routable_public()
    }
}

/// Policy for accessing private/loopback networks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivateNetworkPolicy {
    /// Completely block all private, loopback, link-local, and bogon addresses.
    BlockAllPrivate,
    /// Allow connections only to explicit whitelist of IP addresses.
    AllowSpecific(Vec<IpAddr>),
    /// Allow loopback (127.0.0.1 / ::1) but block all RFC 1918 and link-local ranges.
    AllowLoopbackOnly,
    /// Allow all addresses (unrestricted dev mode).
    AllowAll,
}

/// Cached DNS record with pin timestamp and TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolutionRecord {
    pub hostname: String,
    pub resolved_ips: Vec<IpAddr>,
    pub resolved_at: DateTime<Utc>,
    pub ttl_seconds: u64,
    pub is_pinned: bool,
}

/// Errors raised during DNS validation and rebinding detection.
#[derive(Debug, Error)]
pub enum DnsSecurityError {
    #[error("DNS resolution failed for hostname '{0}': {1}")]
    LookupFailed(String, String),
    #[error("DNS Rebinding attack detected: hostname '{hostname}' re-resolved from public IP to forbidden IP '{new_ip}'")]
    RebindingAttemptDetected { hostname: String, new_ip: IpAddr },
    #[error("Target IP '{ip}' is blocked by private network policy ({classification:?})")]
    PrivateNetworkAccessBlocked { ip: IpAddr, classification: IpClassification },
    #[error("Hostname '{0}' resolved to no valid IP addresses")]
    NoAddressesFound(String),
}

/// Armor against DNS Rebinding and SSRF attacks with domain pinning and bogon filtering.
pub struct DnsRebindingArmor {
    policy: PrivateNetworkPolicy,
    cache: RwLock<HashMap<String, DnsResolutionRecord>>,
}

impl DnsRebindingArmor {
    /// Create new DNS Rebinding armor with specified policy.
    pub fn new(policy: PrivateNetworkPolicy) -> Self {
        Self {
            policy,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Verify an IP address against the active private network policy.
    pub fn check_ip_allowed(&self, ip: &IpAddr) -> Result<(), DnsSecurityError> {
        let class = IpClassification::classify(ip);

        match &self.policy {
            PrivateNetworkPolicy::AllowAll => Ok(()),
            PrivateNetworkPolicy::BlockAllPrivate => {
                if class.is_forbidden_bogon_or_private() {
                    Err(DnsSecurityError::PrivateNetworkAccessBlocked {
                        ip: *ip,
                        classification: class,
                    })
                } else {
                    Ok(())
                }
            }
            PrivateNetworkPolicy::AllowLoopbackOnly => {
                if matches!(class, IpClassification::Public | IpClassification::Loopback) {
                    Ok(())
                } else {
                    Err(DnsSecurityError::PrivateNetworkAccessBlocked {
                        ip: *ip,
                        classification: class,
                    })
                }
            }
            PrivateNetworkPolicy::AllowSpecific(allowed) => {
                if allowed.contains(ip) || class.is_routable_public() {
                    Ok(())
                } else {
                    Err(DnsSecurityError::PrivateNetworkAccessBlocked {
                        ip: *ip,
                        classification: class,
                    })
                }
            }
        }
    }

    /// Record a resolution result, check for rebinding anomalies against cached records, and pin IP.
    pub fn record_and_verify_resolution(
        &self,
        hostname: &str,
        fresh_ips: &[IpAddr],
        ttl_seconds: u64,
    ) -> Result<IpAddr, DnsSecurityError> {
        if fresh_ips.is_empty() {
            return Err(DnsSecurityError::NoAddressesFound(hostname.to_string()));
        }

        let primary_ip = fresh_ips[0];
        self.check_ip_allowed(&primary_ip)?;

        let mut cache = self
            .cache
            .write()
            .map_err(|_| DnsSecurityError::LookupFailed(hostname.to_string(), "Lock poisoned".to_string()))?;

        if let Some(existing) = cache.get(hostname) {
            let was_public = existing.resolved_ips.iter().any(|ip| IpClassification::classify(ip).is_routable_public());
            let is_now_private = IpClassification::classify(&primary_ip).is_forbidden_bogon_or_private();

            // Rebinding alert: A hostname previously known as public suddenly resolves to private/loopback!
            if was_public && is_now_private {
                return Err(DnsSecurityError::RebindingAttemptDetected {
                    hostname: hostname.to_string(),
                    new_ip: primary_ip,
                });
            }
        }

        cache.insert(
            hostname.to_lowercase(),
            DnsResolutionRecord {
                hostname: hostname.to_lowercase(),
                resolved_ips: fresh_ips.to_vec(),
                resolved_at: Utc::now(),
                ttl_seconds: ttl_seconds.max(10), // minimum 10s pinning to mitigate fast-flux rebinding
                is_pinned: true,
            },
        );

        Ok(primary_ip)
    }

    /// Get pinned IP from cache if still valid.
    pub fn get_pinned_ip(&self, hostname: &str) -> Option<IpAddr> {
        let cache = self.cache.read().ok()?;
        let record = cache.get(&hostname.to_lowercase())?;
        let elapsed = Utc::now().signed_duration_since(record.resolved_at).num_seconds();
        if elapsed >= 0 && (elapsed as u64) < record.ttl_seconds {
            record.resolved_ips.first().copied()
        } else {
            None
        }
    }
}

// ============================================================================
// R2.8: AF_UNIX Local Socket Firewall & FD Passing Inspector
// ============================================================================

/// Type of file descriptor passed in UNIX ancillary data (`SCM_RIGHTS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FdType {
    RegularFile,
    Pipe,
    Socket,
    DevNull,
    MemFd,
    TerminalPty,
    PrivilegedControl,
    Unknown,
}

/// Rule for inspecting or blocking file descriptor passing (`SCM_RIGHTS`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FdPassingRule {
    /// Disallow any FD passing via UNIX domain sockets.
    DenyAll,
    /// Allow only safe, unprivileged FDs (pipes, /dev/null, stdio).
    AllowSafeOnly,
    /// Allow all FD passing.
    AllowAll,
}

/// Access control list entry for a specific UNIX domain socket path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnixSocketAcl {
    pub socket_path: PathBuf,
    pub allow_connect: bool,
    pub allow_bind: bool,
    pub fd_passing_rule: FdPassingRule,
    pub max_concurrent_connections: usize,
    pub redirect_target: Option<PathBuf>,
}

/// Verdict for an AF_UNIX socket operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketVerdict {
    Permit,
    Deny { reason: String },
    RedirectToVirtualProxy { proxy_path: PathBuf },
    RequireAudit { note: String },
}

/// Summary report of ancillary messages and passed file descriptors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AncillaryDataReport {
    pub caller_pid: u32,
    pub target_socket: PathBuf,
    pub passed_fds_count: usize,
    pub detected_fd_types: Vec<FdType>,
    pub verdict: SocketVerdict,
    pub timestamp: DateTime<Utc>,
}

/// Error types for AF_UNIX firewall operations.
#[derive(Debug, Error)]
pub enum AfUnixError {
    #[error("Unauthorized AF_UNIX access to '{0:?}': access denied by security policy")]
    SocketAccessDenied(PathBuf),
    #[error("SCM_RIGHTS descriptor passing blocked: policy forbids sending {count} FDs of types {types:?}")]
    DescriptorPassingBlocked { count: usize, types: Vec<FdType> },
    #[error("Socket path '{0:?}' exceeds maximum allowed path length")]
    PathTooLong(PathBuf),
}

/// Firewall and security filter for local UNIX domain sockets.
pub struct UnixSocketFirewall {
    acls: RwLock<HashMap<PathBuf, UnixSocketAcl>>,
    default_deny: bool,
}

impl UnixSocketFirewall {
    /// Create new AF_UNIX firewall.
    pub fn new(default_deny: bool) -> Self {
        let mut fw = Self {
            acls: RwLock::new(HashMap::new()),
            default_deny,
        };
        // Add hardened default protection for sensitive known system sockets
        fw.add_hardened_system_defaults();
        fw
    }

    fn add_hardened_system_defaults(&mut self) {
        let docker_sock = PathBuf::from("/var/run/docker.sock");
        let docker_user_sock = PathBuf::from("/run/user/1000/docker.sock");
        let podman_sock = PathBuf::from("/run/podman/podman.sock");

        if let Ok(mut acls) = self.acls.write() {
            acls.insert(
                docker_sock.clone(),
                UnixSocketAcl {
                    socket_path: docker_sock,
                    allow_connect: false, // Block direct docker socket access by default
                    allow_bind: false,
                    fd_passing_rule: FdPassingRule::DenyAll,
                    max_concurrent_connections: 0,
                    redirect_target: None,
                },
            );
            acls.insert(
                docker_user_sock.clone(),
                UnixSocketAcl {
                    socket_path: docker_user_sock,
                    allow_connect: false,
                    allow_bind: false,
                    fd_passing_rule: FdPassingRule::DenyAll,
                    max_concurrent_connections: 0,
                    redirect_target: None,
                },
            );
            acls.insert(
                podman_sock.clone(),
                UnixSocketAcl {
                    socket_path: podman_sock,
                    allow_connect: false,
                    allow_bind: false,
                    fd_passing_rule: FdPassingRule::DenyAll,
                    max_concurrent_connections: 0,
                    redirect_target: None,
                },
            );
        }
    }

    /// Register or update an ACL rule for a UNIX socket path.
    pub fn register_socket_acl(&self, acl: UnixSocketAcl) {
        if let Ok(mut acls) = self.acls.write() {
            acls.insert(acl.socket_path.clone(), acl);
        }
    }

    /// Evaluate an agent's attempt to connect to a UNIX domain socket.
    pub fn evaluate_connect(&self, socket_path: &Path, _caller_pid: u32) -> SocketVerdict {
        let acls = match self.acls.read() {
            Ok(g) => g,
            Err(_) => {
                return SocketVerdict::Deny {
                    reason: "Firewall lock poisoned".to_string(),
                }
            }
        };

        if let Some(acl) = acls.get(socket_path) {
            if !acl.allow_connect {
                return SocketVerdict::Deny {
                    reason: format!("Explicitly blocked by UNIX socket ACL: {:?}", socket_path),
                };
            }
            if let Some(proxy) = &acl.redirect_target {
                return SocketVerdict::RedirectToVirtualProxy {
                    proxy_path: proxy.clone(),
                };
            }
            SocketVerdict::Permit
        } else if self.default_deny {
            SocketVerdict::Deny {
                reason: format!("Default deny policy: socket '{:?}' is not allowlisted", socket_path),
            }
        } else {
            SocketVerdict::Permit
        }
    }

    /// Inspect SCM_RIGHTS file descriptor passing message.
    pub fn inspect_scm_rights(
        &self,
        socket_path: &Path,
        caller_pid: u32,
        passed_fd_types: &[FdType],
    ) -> Result<AncillaryDataReport, AfUnixError> {
        let acls = match self.acls.read() {
            Ok(g) => g,
            Err(_) => {
                return Err(AfUnixError::SocketAccessDenied(socket_path.to_path_buf()));
            }
        };

        let fd_rule = if let Some(acl) = acls.get(socket_path) {
            &acl.fd_passing_rule
        } else if self.default_deny {
            &FdPassingRule::DenyAll
        } else {
            &FdPassingRule::AllowSafeOnly
        };

        let mut violation = false;
        match fd_rule {
            FdPassingRule::DenyAll => {
                if !passed_fd_types.is_empty() {
                    violation = true;
                }
            }
            FdPassingRule::AllowSafeOnly => {
                for fdt in passed_fd_types {
                    match fdt {
                        FdType::Pipe | FdType::DevNull | FdType::TerminalPty | FdType::RegularFile => {}
                        _ => {
                            violation = true;
                            break;
                        }
                    }
                }
            }
            FdPassingRule::AllowAll => {}
        }

        let verdict = if violation {
            SocketVerdict::Deny {
                reason: format!("FD passing violation: policy forbids types {:?}", passed_fd_types),
            }
        } else {
            SocketVerdict::Permit
        };

        let report = AncillaryDataReport {
            caller_pid,
            target_socket: socket_path.to_path_buf(),
            passed_fds_count: passed_fd_types.len(),
            detected_fd_types: passed_fd_types.to_vec(),
            verdict: verdict.clone(),
            timestamp: Utc::now(),
        };

        if violation {
            Err(AfUnixError::DescriptorPassingBlocked {
                count: passed_fd_types.len(),
                types: passed_fd_types.to_vec(),
            })
        } else {
            Ok(report)
        }
    }
}

// ============================================================================
// R2.9: HTTP Request Smuggling & Framing Anomaly Detector
// ============================================================================

/// Anomalies in HTTP/1.1 message framing that indicate HTTP Request Smuggling attacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpFramingAnomaly {
    /// Both Content-Length and Transfer-Encoding present (CL.TE / TE.CL conflict).
    DualFramingConflict {
        content_length: u64,
        transfer_encoding: String,
    },
    /// Obfuscated or malformed Transfer-Encoding header value (e.g. `Transfer-Encoding: [tab]chunked`).
    ObfuscatedTransferEncoding(String),
    /// Multiple contradictory Content-Length headers present.
    MultipleContentLengthHeaders(Vec<u64>),
    /// Non-hexadecimal characters or malformed line endings in chunk size specifier.
    MalformedChunkHexSize(String),
    /// Premature EOF or abrupt stream closure inside a chunk.
    PrematureChunkEof,
    /// Illegal newline sequence (bare LF without CR, or CR without LF in HTTP headers).
    IllegalHeaderNewlineSequence,
    /// Whitespace before colon in header name (RFC 7230 / 9112 violation often used in smuggling).
    WhitespaceBeforeHeaderColon(String),
    /// Transfer-Encoding value other than chunked (e.g. gzip, identity) in request without chunked.
    UnsupportedTransferCoding(String),
}

/// Security risk level associated with framing anomalies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SmugglingRiskLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    CriticalDrop = 4,
}

/// Comprehensive result of framing validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FramingValidationResult {
    pub is_valid: bool,
    pub risk_level: SmugglingRiskLevel,
    pub anomalies: Vec<HttpFramingAnomaly>,
    pub canonical_content_length: Option<u64>,
    pub is_chunked: bool,
}

/// Strict RFC 9112 Section 6 HTTP Request Smuggling & Framing Detector.
#[derive(Default)]
pub struct RequestSmugglingDetector;

impl RequestSmugglingDetector {
    /// Create new detector instance.
    pub fn new() -> Self {
        Self
    }

    /// Validate raw HTTP header list representation for smuggling indicators.
    /// `headers` is a list of `(header_name, header_value)` tuples.
    pub fn validate_headers(&self, raw_header_lines: &[String]) -> FramingValidationResult {
        let mut anomalies = Vec::new();
        let mut content_lengths: Vec<u64> = Vec::new();
        let mut transfer_encodings: Vec<String> = Vec::new();
        let mut is_chunked = false;

        for line in raw_header_lines {
            // Check for illegal CR/LF combinations
            if line.contains('\r') && !line.ends_with("\r\n") && !line.ends_with('\r') {
                anomalies.push(HttpFramingAnomaly::IllegalHeaderNewlineSequence);
            }

            // Check whitespace before colon
            if let Some(colon_pos) = line.find(':') {
                let name_part = &line[..colon_pos];
                if name_part.ends_with(' ') || name_part.ends_with('\t') {
                    anomalies.push(HttpFramingAnomaly::WhitespaceBeforeHeaderColon(name_part.to_string()));
                }

                let header_name = name_part.trim().to_lowercase();
                let header_val = line[colon_pos + 1..].trim();

                if header_name == "content-length" {
                    // Check if value contains comma-separated or non-numeric tokens
                    if header_val.contains(',') {
                        for sub in header_val.split(',') {
                            if let Ok(num) = sub.trim().parse::<u64>() {
                                content_lengths.push(num);
                            } else {
                                anomalies.push(HttpFramingAnomaly::MultipleContentLengthHeaders(vec![]));
                            }
                        }
                    } else if let Ok(num) = header_val.parse::<u64>() {
                        content_lengths.push(num);
                    } else {
                        anomalies.push(HttpFramingAnomaly::MultipleContentLengthHeaders(vec![]));
                    }
                } else if header_name == "transfer-encoding" {
                    transfer_encodings.push(header_val.to_string());
                    let val_lower = header_val.to_lowercase();
                    if val_lower.contains("chunked") {
                        is_chunked = true;
                    }

                    // Obfuscation checks: extra spaces, null bytes, unsupported codings
                    if header_val.starts_with(' ') || header_val.starts_with('\t') || header_val.contains('\0') {
                        anomalies.push(HttpFramingAnomaly::ObfuscatedTransferEncoding(header_val.to_string()));
                    }
                    if !val_lower.ends_with("chunked") && !val_lower.is_empty() {
                        anomalies.push(HttpFramingAnomaly::UnsupportedTransferCoding(header_val.to_string()));
                    }
                }
            }
        }

        // Multiple distinct Content-Length values -> High Risk Smuggling
        if content_lengths.len() > 1 {
            let first = content_lengths[0];
            let has_divergent = content_lengths.iter().any(|&cl| cl != first);
            if has_divergent {
                anomalies.push(HttpFramingAnomaly::MultipleContentLengthHeaders(content_lengths.clone()));
            }
        }

        // Dual framing conflict (CL + TE) -> Critical Risk
        if !content_lengths.is_empty() && !transfer_encodings.is_empty() {
            anomalies.push(HttpFramingAnomaly::DualFramingConflict {
                content_length: content_lengths[0],
                transfer_encoding: transfer_encodings.join(", "),
            });
        }

        let risk_level = if anomalies.iter().any(|a| {
            matches!(
                a,
                HttpFramingAnomaly::DualFramingConflict { .. }
                    | HttpFramingAnomaly::MultipleContentLengthHeaders(_)
                    | HttpFramingAnomaly::ObfuscatedTransferEncoding(_)
            )
        }) {
            SmugglingRiskLevel::CriticalDrop
        } else if !anomalies.is_empty() {
            SmugglingRiskLevel::High
        } else {
            SmugglingRiskLevel::None
        };

        let is_valid = anomalies.is_empty();
        let canonical_cl = if is_chunked { None } else { content_lengths.first().copied() };

        FramingValidationResult {
            is_valid,
            risk_level,
            anomalies,
            canonical_content_length: canonical_cl,
            is_chunked,
        }
    }

    /// Validate a chunk header line (e.g. `1a;ext=val\r\n`) and extract chunk size in bytes.
    pub fn parse_chunk_size(&self, chunk_line: &str) -> Result<usize, HttpFramingAnomaly> {
        let clean = chunk_line.trim_end_matches("\r\n").trim_end_matches('\n');
        // Chunk extensions begin with semicolon
        let hex_part = clean.split(';').next().unwrap_or(clean).trim();

        if hex_part.is_empty() {
            return Err(HttpFramingAnomaly::MalformedChunkHexSize(clean.to_string()));
        }

        match usize::from_str_radix(hex_part, 16) {
            Ok(size) => Ok(size),
            Err(_) => Err(HttpFramingAnomaly::MalformedChunkHexSize(clean.to_string())),
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_matching() {
        assert!(HttpMethod::Get.matches(&HttpMethod::Get));
        assert!(HttpMethod::Any.matches(&HttpMethod::Post));
        assert!(HttpMethod::Delete.matches(&HttpMethod::Any));
        assert!(!HttpMethod::Get.matches(&HttpMethod::Post));
        assert!(HttpMethod::Custom("PURGE".into()).matches(&HttpMethod::Custom("purge".into())));
    }

    #[test]
    fn test_l7_path_patterns() {
        let exact = L7PathPattern::Exact("/api/v1/user".to_string());
        assert!(exact.matches_path("/api/v1/user"));
        assert!(exact.matches_path("/api/v1/user?query=1"));
        assert!(!exact.matches_path("/api/v1/user/settings"));

        let prefix = L7PathPattern::Prefix("/repos/".to_string());
        assert!(prefix.matches_path("/repos/shleder/vetto"));
        assert!(!prefix.matches_path("/users/shleder"));

        let glob = L7PathPattern::Glob("/repos/*/*/keys".to_string());
        assert!(glob.matches_path("/repos/shleder/vetto/keys"));
        assert!(!glob.matches_path("/repos/shleder/vetto/issues"));

        let param = L7PathPattern::Parameterized("/orgs/:org/members".to_string());
        assert!(param.matches_path("/orgs/acme-corp/members"));
        assert!(!param.matches_path("/orgs/acme-corp/teams/devs"));
    }

    #[test]
    fn test_l7_filter_engine_priority() {
        let allow_rule = L7AclRule {
            id: "allow-get-repos".to_string(),
            description: "Allow reading repository content".to_string(),
            method: HttpMethod::Get,
            host_pattern: "api.github.com".to_string(),
            path_pattern: L7PathPattern::Prefix("/repos/".to_string()),
            action: L7AclAction::Allow,
            priority: 10,
            enabled: true,
        };

        let block_delete_rule = L7AclRule {
            id: "block-destructive-delete".to_string(),
            description: "Block DELETE requests".to_string(),
            method: HttpMethod::Delete,
            host_pattern: "api.github.com".to_string(),
            path_pattern: L7PathPattern::CatchAll,
            action: L7AclAction::BlockWith403 {
                message: "DELETE operations on GitHub API are forbidden".to_string(),
            },
            priority: 100,
            enabled: true,
        };

        let engine = L7HttpFilterEngine::from_rules(
            vec![allow_rule, block_delete_rule],
            L7AclAction::BlockWith403 {
                message: "Default forbidden".to_string(),
            },
        )
        .unwrap();

        // GET /repos/shleder/vetto -> Allow
        let v1 = engine.evaluate_request(&HttpMethod::Get, "api.github.com", "/repos/shleder/vetto");
        assert_eq!(v1.action, L7AclAction::Allow);
        assert_eq!(v1.matched_rule_id.as_deref(), Some("allow-get-repos"));

        // DELETE /repos/shleder/vetto -> BlockWith403
        let v2 = engine.evaluate_request(&HttpMethod::Delete, "api.github.com", "/repos/shleder/vetto");
        assert!(matches!(v2.action, L7AclAction::BlockWith403 { .. }));
        assert_eq!(v2.matched_rule_id.as_deref(), Some("block-destructive-delete"));

        // POST /repos/shleder/vetto/hooks -> Default fallback
        let v3 = engine.evaluate_request(&HttpMethod::Post, "api.github.com", "/repos/shleder/vetto/hooks");
        assert!(matches!(v3.action, L7AclAction::BlockWith403 { .. }));
        assert_eq!(v3.matched_rule_id, None);
    }

    #[test]
    fn test_ip_classification_and_dns_rebinding() {
        let pub_ip: IpAddr = "93.184.216.34".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let rfc1918: IpAddr = "192.168.1.1".parse().unwrap();
        let metadata: IpAddr = "169.254.169.254".parse().unwrap();

        assert_eq!(IpClassification::classify(&pub_ip), IpClassification::Public);
        assert_eq!(IpClassification::classify(&loopback), IpClassification::Loopback);
        assert_eq!(IpClassification::classify(&rfc1918), IpClassification::PrivateRfc1918);
        assert_eq!(IpClassification::classify(&metadata), IpClassification::LinkLocalRfc3927);

        let armor = DnsRebindingArmor::new(PrivateNetworkPolicy::BlockAllPrivate);

        // Public IP -> allowed and cached
        let res = armor.record_and_verify_resolution("example.com", &[pub_ip], 60);
        assert!(res.is_ok());

        // Private metadata direct resolution -> blocked
        let res_meta = armor.record_and_verify_resolution("attacker.com", &[metadata], 60);
        assert!(res_meta.is_err());

        // Rebinding: re-resolving example.com to 127.0.0.1 -> rebinding attempt detected!
        let rebind_res = armor.record_and_verify_resolution("example.com", &[loopback], 60);
        assert!(matches!(rebind_res, Err(DnsSecurityError::RebindingAttemptDetected { .. })));
    }

    #[test]
    fn test_afunix_firewall_and_scm_rights() {
        let firewall = UnixSocketFirewall::new(true);

        // System docker sock is blocked by default
        let docker_path = Path::new("/var/run/docker.sock");
        let v = firewall.evaluate_connect(docker_path, 1234);
        assert!(matches!(v, SocketVerdict::Deny { .. }));

        // Allow custom socket with safe FD passing
        let my_socket = PathBuf::from("/tmp/my-agent-ipc.sock");
        firewall.register_socket_acl(UnixSocketAcl {
            socket_path: my_socket.clone(),
            allow_connect: true,
            allow_bind: true,
            fd_passing_rule: FdPassingRule::AllowSafeOnly,
            max_concurrent_connections: 5,
            redirect_target: None,
        });

        assert_eq!(firewall.evaluate_connect(&my_socket, 1234), SocketVerdict::Permit);

        // Safe FDs: Pipe + DevNull -> Ok
        let safe_res = firewall.inspect_scm_rights(&my_socket, 1234, &[FdType::Pipe, FdType::DevNull]);
        assert!(safe_res.is_ok());

        // Privileged control FD -> Blocked
        let priv_res = firewall.inspect_scm_rights(&my_socket, 1234, &[FdType::PrivilegedControl]);
        assert!(priv_res.is_err());
    }

    #[test]
    fn test_http_request_smuggling_detection() {
        let detector = RequestSmugglingDetector::new();

        // Clean headers
        let valid_headers = vec![
            "Host: example.com\r\n".to_string(),
            "Content-Length: 42\r\n".to_string(),
            "User-Agent: test\r\n".to_string(),
        ];
        let res_clean = detector.validate_headers(&valid_headers);
        assert!(res_clean.is_valid);
        assert_eq!(res_clean.risk_level, SmugglingRiskLevel::None);
        assert_eq!(res_clean.canonical_content_length, Some(42));

        // Smuggling attack: Dual framing conflict (CL + TE)
        let conflict_headers = vec![
            "Host: example.com\r\n".to_string(),
            "Content-Length: 10\r\n".to_string(),
            "Transfer-Encoding: chunked\r\n".to_string(),
        ];
        let res_conflict = detector.validate_headers(&conflict_headers);
        assert!(!res_conflict.is_valid);
        assert_eq!(res_conflict.risk_level, SmugglingRiskLevel::CriticalDrop);

        // Smuggling attack: Whitespace before colon
        let bad_whitespace = vec![
            "Transfer-Encoding : chunked\r\n".to_string(),
        ];
        let res_ws = detector.validate_headers(&bad_whitespace);
        assert!(!res_ws.is_valid);

        // Chunk hex size parsing
        assert_eq!(detector.parse_chunk_size("1a\r\n").unwrap(), 26);
        assert_eq!(detector.parse_chunk_size("0\r\n").unwrap(), 0);
        assert_eq!(detector.parse_chunk_size("ff;extension=val\r\n").unwrap(), 255);
        assert!(detector.parse_chunk_size("invalid_hex\r\n").is_err());
    }
}
