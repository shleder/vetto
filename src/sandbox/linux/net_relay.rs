//! `--net=allowlist:<domains>` implementation — unix-fd bridge relay.
//!
//! Topology (spec v3): the agent talks HTTP CONNECT / socks5 to `relay`, a
//! small process running INSIDE the interface-less network namespace,
//! listening on 127.0.0.1. The relay forwards `{host, port}` over an
//! inherited AF_UNIX socketpair to `broker` running OUTSIDE the sandbox in
//! vetto itself. The broker resolves DNS remotely, checks the CONNECT-level
//! domain allowlist, opens the outbound TCP connection itself and hands a
//! fresh data fd back to the relay via SCM_RIGHTS. Bytes are pumped both
//! ways until EOF.
//!
//! Dual-mode support (Phase 4, Step 20):
//! Mode A (eBPF): Transparent socket redirection via cgroup_sock_addr.
//! Mode B (NetNS): User-space SOCKS5/HTTP CONNECT proxy with loopback debug isolation.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::config::NetRule;
use crate::events::{bus::EventBus, Event};
use crate::report::stats::DomainStats;
use crate::sandbox::linux::debug_guard::{DebugPortConfig, DebugPortGuard, DebugPortVerdict};

pub const RELAY_PORT_BASE: u16 = 47129;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMode {
    NetNs,
    Ebpf,
}

// ---------------------------------------------------------------------------
// Host side: the broker.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum BrokerPolicy {
    Allowlist(Vec<String>),
    Strict(Vec<NetRule>),
    Ask(Vec<String>),
}

impl From<Vec<String>> for BrokerPolicy {
    fn from(domains: Vec<String>) -> Self {
        Self::Allowlist(domains)
    }
}

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub policy: BrokerPolicy,
    pub debug_guard: Option<DebugPortGuard>,
    pub mode: RelayMode,
    pub allow_cidr: Vec<String>,
    pub quotas: std::collections::HashMap<String, u64>,
    pub policy_path: Option<PathBuf>,
    pub block_doh: bool,
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
    pub no_proxy: Option<String>,
}

impl From<BrokerPolicy> for BrokerConfig {
    fn from(policy: BrokerPolicy) -> Self {
        let http_proxy = std::env::var("HTTP_PROXY")
            .or_else(|_| std::env::var("http_proxy"))
            .or_else(|_| std::env::var("ALL_PROXY"))
            .or_else(|_| std::env::var("all_proxy"))
            .ok();
        let https_proxy = std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .or_else(|_| std::env::var("ALL_PROXY"))
            .or_else(|_| std::env::var("all_proxy"))
            .ok();
        let no_proxy = std::env::var("NO_PROXY")
            .or_else(|_| std::env::var("no_proxy"))
            .ok();

        Self {
            policy,
            debug_guard: Some(DebugPortGuard::new(DebugPortConfig::default())),
            mode: RelayMode::NetNs,
            allow_cidr: Vec::new(),
            quotas: std::collections::HashMap::new(),
            policy_path: None,
            block_doh: false,
            http_proxy,
            https_proxy,
            no_proxy,
        }
    }
}

impl From<Vec<String>> for BrokerConfig {
    fn from(domains: Vec<String>) -> Self {
        Self::from(BrokerPolicy::Allowlist(domains))
    }
}

static DOMAIN_TRANSFER_STATS: Mutex<Option<std::collections::HashMap<String, DomainStats>>> =
    Mutex::new(None);

#[cfg(test)]
pub fn reset_domain_transfer_stats() {
    let mut guard = DOMAIN_TRANSFER_STATS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

fn add_domain_transfer(host: &str, tx: u64, rx: u64) {
    let mut guard = DOMAIN_TRANSFER_STATS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    let entry = map.entry(host.trim().to_ascii_lowercase()).or_default();
    entry.requests += 1;
    entry.bytes_tx += tx;
    entry.bytes_rx += rx;
}

/// Match a hostname against a pattern (exact match, wildcard *.suffix, or parent domain match).
pub fn domain_matches_pattern(host: &str, pattern: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let pat = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if pat == "*" {
        return true;
    }
    if host == pat {
        return true;
    }
    let clean_ip = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = clean_ip.parse::<std::net::IpAddr>() {
        if let Ok(cidr) = IpCidr::parse(&pat) {
            return cidr.contains(ip);
        }
    }
    if let Some(suffix) = pat.strip_prefix("*.") {
        host.ends_with(&format!(".{suffix}")) || host == suffix
    } else {
        host.ends_with(&format!(".{pat}"))
    }
}

/// Return the total bytes transferred across all recorded domains matching `pattern`.
pub fn get_quota_bytes(pattern: &str) -> u64 {
    let guard = DOMAIN_TRANSFER_STATS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(map) = guard.as_ref() else {
        return 0;
    };
    let mut total: u64 = 0;
    for (recorded_host, stats) in map {
        if domain_matches_pattern(recorded_host, pattern) {
            total = total.saturating_add(stats.bytes_tx.saturating_add(stats.bytes_rx));
        }
    }
    total
}

/// Find all quota rules matching `host`, sorted by specificity (most specific first).
pub fn find_matching_quotas(
    host: &str,
    quotas: &std::collections::HashMap<String, u64>,
) -> Vec<(String, u64)> {
    let mut matches = Vec::new();
    for (pat, &limit) in quotas {
        if domain_matches_pattern(host, pat) {
            matches.push((pat.clone(), limit));
        }
    }
    matches.sort_by_key(|a| std::cmp::Reverse(a.0.len()));
    matches
}

fn get_domain_bytes(host: &str) -> u64 {
    let guard = DOMAIN_TRANSFER_STATS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .and_then(|map| map.get(&host.trim().to_ascii_lowercase()))
        .map(|s| s.bytes_tx + s.bytes_rx)
        .unwrap_or(0)
}

static ASK_CACHE: Mutex<Option<std::collections::HashMap<String, bool>>> = Mutex::new(None);

#[cfg(test)]
pub fn reset_ask_cache() {
    let mut guard = ASK_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

fn is_stdin_tty() -> bool {
    unsafe { libc::isatty(0) == 1 }
}

pub fn prompt_confirmation_interactive<R: std::io::BufRead, W: std::io::Write>(
    host: &str,
    port: u16,
    policy_path: Option<&Path>,
    is_tty: bool,
    mut reader: R,
    mut writer: W,
) -> bool {
    let key = host.trim().trim_end_matches('.').to_ascii_lowercase();

    if !is_tty {
        let _ = writeln!(
            writer,
            "vetto: [net=ask] interactive confirmation unavailable (stdin is not a tty); connection to '{host}:{port}' denied (fail-closed)"
        );
        return false;
    }

    let _ = write!(
        writer,
        "vetto: allow network connection to '{host}:{port}'? [y/N/p (permanent)]: "
    );
    let _ = writer.flush();

    let mut line = String::new();
    let (allowed, permanent) = if reader.read_line(&mut line).is_ok() {
        let trimmed = line.trim().to_ascii_lowercase();
        match trimmed.as_str() {
            "y" | "yes" => (true, false),
            "p" | "perm" | "permanent" => (true, true),
            _ => (false, false),
        }
    } else {
        (false, false)
    };

    if permanent {
        match crate::policy::edit::persist_net_target(&key, policy_path) {
            Ok((path, kind)) => {
                let _ = writeln!(
                    writer,
                    "vetto: {kind} '{key}' permanently allowed and saved to {}",
                    path.display()
                );
            }
            Err(e) => {
                let _ = writeln!(writer, "vetto: failed to persist '{key}': {e}");
            }
        }
    }

    allowed
}

struct TimeoutReader {
    fd: std::os::unix::io::RawFd,
    file: std::fs::File,
    timeout_ms: libc::c_int,
}

impl std::io::Read for TimeoutReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, self.timeout_ms) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if ret == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
        }
        std::io::Read::read(&mut self.file, buf)
    }
}

fn ask_confirmation(host: &str, port: u16, policy_path: Option<&Path>) -> bool {
    let mut guard = ASK_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.get_or_insert_with(std::collections::HashMap::new);
    let key = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(&allowed) = cache.get(&key) {
        return allowed;
    }

    let allowed = if let Ok(tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        use std::os::unix::io::AsRawFd;
        let fd = tty.as_raw_fd();
        let timeout_reader = TimeoutReader {
            fd,
            file: tty.try_clone().unwrap_or(tty),
            timeout_ms: 30_000,
        };
        let mut buf_reader = std::io::BufReader::new(timeout_reader);
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .unwrap_or_else(|_| std::fs::File::create("/dev/null").unwrap());
        prompt_confirmation_interactive(host, port, policy_path, true, &mut buf_reader, &mut writer)
    } else {
        prompt_confirmation_interactive(
            host,
            port,
            policy_path,
            is_stdin_tty(),
            &mut std::io::stdin().lock(),
            &mut std::io::stderr(),
        )
    };
    cache.insert(key, allowed);
    allowed
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpCidr {
    pub network: IpAddr,
    pub prefix_len: u8,
}

impl IpCidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (ip_str, prefix_opt) = match s.split_once('/') {
            Some((ip_part, prefix_part)) => {
                let prefix: u8 = prefix_part
                    .trim()
                    .parse()
                    .map_err(|e| format!("invalid prefix in CIDR '{s}': {e}"))?;
                (ip_part.trim(), Some(prefix))
            }
            None => (s, None),
        };

        let ip_clean = ip_str.trim_start_matches('[').trim_end_matches(']');
        let ip: IpAddr = ip_clean
            .parse()
            .map_err(|e| format!("invalid IP in CIDR '{s}': {e}"))?;

        let prefix_len = match (ip, prefix_opt) {
            (IpAddr::V4(_), Some(pfx)) if pfx > 32 => {
                return Err(format!("IPv4 prefix length must be 0..=32, got {pfx}"));
            }
            (IpAddr::V6(_), Some(pfx)) if pfx > 128 => {
                return Err(format!("IPv6 prefix length must be 0..=128, got {pfx}"));
            }
            (IpAddr::V4(_), Some(pfx)) => pfx,
            (IpAddr::V6(_), Some(pfx)) => pfx,
            (IpAddr::V4(_), None) => 32,
            (IpAddr::V6(_), None) => 128,
        };
        Ok(Self {
            network: ip,
            prefix_len,
        })
    }

    pub fn contains(&self, target: IpAddr) -> bool {
        match (self.network, target) {
            (IpAddr::V4(net), IpAddr::V4(tgt)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_u32 = u32::from_be_bytes(net.octets());
                let tgt_u32 = u32::from_be_bytes(tgt.octets());
                let mask = if self.prefix_len == 32 {
                    u32::MAX
                } else {
                    !((1u64 << (32 - self.prefix_len)) - 1) as u32
                };
                (net_u32 & mask) == (tgt_u32 & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(tgt)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_u128 = u128::from_be_bytes(net.octets());
                let tgt_u128 = u128::from_be_bytes(tgt.octets());
                let mask = if self.prefix_len == 128 {
                    u128::MAX
                } else {
                    !((1u128 << (128 - self.prefix_len)) - 1)
                };
                (net_u128 & mask) == (tgt_u128 & mask)
            }
            _ => false,
        }
    }
}

pub const DOH_DOT_DENY_IPS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
    "76.76.2.0",
    "76.76.10.0",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "2620:fe::fe",
    "2620:fe::9",
    "2620:119:35::35",
    "2620:119:53::53",
    "2a10:50c0::ad1:ff",
    "2a10:50c0::ad2:ff",
];

pub const DOH_DOT_DENY_DOMAINS: &[&str] = &[
    "cloudflare-dns.com",
    "one.one.one.one",
    "mozilla.cloudflare-dns.com",
    "dns.cloudflare.com",
    "dns.google",
    "dns.google.com",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.adguard-dns.com",
    "unfiltered.adguard-dns.com",
    "freedns.controld.com",
    "dns.nextdns.io",
];

pub const DOT_PORT: u16 = 853;

pub fn is_doh_or_dot(host: &str, port: u16, ip: Option<IpAddr>) -> bool {
    if port == DOT_PORT {
        return true;
    }
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if DOH_DOT_DENY_DOMAINS
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
    {
        return true;
    }
    let clean_ip = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip_addr) = clean_ip.parse::<IpAddr>() {
        if DOH_DOT_DENY_IPS
            .iter()
            .any(|&denied| denied == ip_addr.to_string())
        {
            return true;
        }
    }
    if let Some(ip) = ip {
        let ip_str = ip.to_string();
        if DOH_DOT_DENY_IPS.iter().any(|&denied| denied == ip_str) {
            return true;
        }
    }
    false
}

/// Spawn the broker thread owning `broker_fd` (its end of the control
/// socketpair whose other end lives inside the sandbox).
pub fn spawn_broker<P>(broker_fd: RawFd, config: P, bus: EventBus)
where
    P: Into<BrokerConfig>,
{
    let config = config.into();
    let thread_bus = bus.clone();
    std::thread::Builder::new()
        .name("vetto-broker".into())
        .spawn(move || {
            let bus = thread_bus;
            // SAFETY: broker_fd is an owned socketpair end created pre-fork.
            let mut ctrl = unsafe { std::os::unix::net::UnixStream::from_raw_fd(broker_fd) };
            let _ = ctrl.set_read_timeout(Some(std::time::Duration::from_secs(300)));
            // relay gone => loop (and thread) ends
            while let Some(req) = read_framed_request(&mut ctrl) {
                if !request_allowed(&req.host, req.port, req.token.as_deref(), &config, &bus) {
                    bus.publish(Event::NetRequest {
                        ts: crate::events::types::now(),
                        host: req.host.clone(),
                        port: req.port,
                        allowed: false,
                    });
                    if ctrl.write_all(b"D").is_err() {
                        break;
                    }
                    continue;
                }
                match resolve_and_connect(&req.host, req.port, &config, &bus) {
                    Ok((tcp, addr)) => {
                        bus.publish(Event::NetRequest {
                            ts: crate::events::types::now(),
                            host: req.host.clone(),
                            port: req.port,
                            allowed: true,
                        });
                        let active_quotas =
                            Arc::new(find_matching_quotas(&req.host, &config.quotas));
                        if create_and_send_data_fd(
                            &mut ctrl,
                            tcp,
                            &req.host,
                            addr,
                            Arc::clone(&active_quotas),
                            bus.clone(),
                        )
                        .is_err()
                            && ctrl.write_all(b"X").is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => {
                        // Resolution/IP policy is part of the broker decision:
                        // private, special-use, or otherwise invalid answers
                        // are reported as denied rather than as a successful
                        // allowlist match that merely failed to connect.
                        bus.publish(Event::NetRequest {
                            ts: crate::events::types::now(),
                            host: req.host.clone(),
                            port: req.port,
                            allowed: false,
                        });
                        if ctrl.write_all(b"X").is_err() {
                            break;
                        }
                    }
                }
            }

            // Session network summary (Feature 24)
            let summary = {
                let guard = DOMAIN_TRANSFER_STATS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                guard.clone().unwrap_or_default()
            };
            if !summary.is_empty() {
                let mut parts = Vec::new();
                for (domain, st) in &summary {
                    parts.push(format!(
                        "{domain} ({} bytes tx, {} bytes rx, {} reqs)",
                        st.bytes_tx, st.bytes_rx, st.requests
                    ));
                }
                bus.publish(Event::Notice {
                    ts: crate::events::types::now(),
                    message: format!("network session summary: {}", parts.join(", ")),
                });
            }
        })
        .expect("spawn vetto-broker thread");
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RelayReq {
    host: String,
    port: u16,
    #[serde(default)]
    token: Option<String>,
}

fn read_framed_request(ctrl: &mut std::os::unix::net::UnixStream) -> Option<RelayReq> {
    let mut len_buf = [0u8; 2];
    ctrl.read_exact(&mut len_buf).ok()?;
    let len = u16::from_le_bytes(len_buf) as usize;
    if len == 0 || len > 4096 {
        return None;
    }
    let mut buf = vec![0u8; len];
    ctrl.read_exact(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

pub fn strip_domain_port(s: &str) -> &str {
    let s = s.trim().trim_end_matches('.');
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end_bracket) = rest.find(']') {
            &rest[..end_bracket]
        } else {
            s
        }
    } else if let Some((host_part, port_part)) = s.rsplit_once(':') {
        if !port_part.is_empty()
            && port_part.chars().all(|c| c.is_ascii_digit())
            && !host_part.contains(':')
        {
            host_part
        } else {
            s
        }
    } else {
        s
    }
}

/// Allowlist semantics: exact match, wildcard subdomain (*.domain.com), or parent domain match
pub fn domain_allowed(host: &str, allowlist: &[String]) -> bool {
    let host = strip_domain_port(host).to_ascii_lowercase();
    allowlist.iter().any(|pat| {
        let pat = strip_domain_port(pat).to_ascii_lowercase();
        if pat == "*" {
            return true;
        }
        if let Some(suffix) = pat.strip_prefix("*.") {
            // Wildcard covers only subdomains, not the domain itself
            host.ends_with(&format!(".{suffix}"))
        } else {
            host == pat || host.ends_with(&format!(".{pat}"))
        }
    })
}

/// Strict mode checks both the normalized host and the requested port before
/// DNS resolution. A bare `*` pattern never matches: use an explicit
/// `*.domain` suffix or an exact host (P06 network proposal: `strict:*`
/// is rejected, not silently allowed).
pub fn strict_allowed(host: &str, port: u16, rules: &[NetRule]) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    rules.iter().any(|rule| {
        if rule.port != port {
            return false;
        }
        let pat = rule
            .domain
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if pat == "*" || pat.is_empty() {
            return false;
        }
        if let Some(suffix) = pat.strip_prefix("*.") {
            host.ends_with(&format!(".{suffix}"))
        } else {
            host == pat || host.ends_with(&format!(".{pat}"))
        }
    })
}

pub const DOH_ENDPOINTS: &[&str] = &[
    "cloudflare-dns.com",
    "dns.google",
    "dns.quad9.net",
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
];

pub(crate) fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]"
}

fn request_allowed(
    host: &str,
    port: u16,
    token: Option<&str>,
    config: &BrokerConfig,
    bus: &EventBus,
) -> bool {
    // Check loopback debug port guard
    if is_loopback_host(host) {
        if let Some(ref guard) = config.debug_guard {
            if guard.check_access(port, token) != DebugPortVerdict::Allowed {
                return false;
            }
        }
    }

    // Check per-domain quota (hierarchical)
    let matching_quotas = find_matching_quotas(host, &config.quotas);
    for (pat, limit) in &matching_quotas {
        let used = get_quota_bytes(pat);
        if used >= *limit {
            return false;
        }
    }

    let mut is_explicitly_allowed = is_loopback_host(host);

    // If host is an IP that matches an allowed CIDR
    let clean_ip = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = clean_ip.parse::<IpAddr>() {
        let cidrs: Vec<IpCidr> = config
            .allow_cidr
            .iter()
            .filter_map(|c| IpCidr::parse(c).ok())
            .collect();
        if cidrs.iter().any(|c| c.contains(ip)) {
            is_explicitly_allowed = true;
        }
    }

    if !is_explicitly_allowed {
        is_explicitly_allowed = match &config.policy {
            BrokerPolicy::Allowlist(domains) => domain_allowed(host, domains),
            BrokerPolicy::Strict(rules) => strict_allowed(host, port, rules),
            BrokerPolicy::Ask(allowlist) => {
                if domain_allowed(host, allowlist) {
                    true
                } else {
                    ask_confirmation(host, port, config.policy_path.as_deref())
                }
            }
        };
    }

    // Check DoH/DoT block
    if config.block_doh {
        if port == 853 {
            return false;
        }

        if !is_explicitly_allowed {
            let host_lower = host.trim().trim_end_matches('.').to_ascii_lowercase();
            let is_doh = DOH_ENDPOINTS
                .iter()
                .any(|&d| d == host_lower || host_lower.ends_with(&format!(".{d}")));
            if is_doh {
                bus.publish(Event::Notice {
                    ts: crate::events::types::now(),
                    message: format!("blocked DoH/DoT bypass attempt to {host}:{port}"),
                });
                return false;
            }
        }
    }

    is_explicitly_allowed
}

fn get_upstream_proxy(host: &str, port: u16, config: &BrokerConfig) -> Option<String> {
    if let Some(no_proxy) = config.no_proxy.as_deref() {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        for item in no_proxy.split(',') {
            let item = item
                .trim()
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !item.is_empty() && (item == "*" || h == item || h.ends_with(&format!(".{item}"))) {
                return None;
            }
        }
    }
    if port == 443 {
        config.https_proxy.clone()
    } else {
        config.http_proxy.clone()
    }
}

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
fn encode_base64(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity((bytes.len() * 4 / 3) + 4);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };

        let enc0 = b0 >> 2;
        let enc1 = ((b0 & 3) << 4) | (b1 >> 4);
        let enc2 = ((b1 & 15) << 2) | (b2 >> 6);
        let enc3 = b2 & 63;

        out.push(B64_CHARS[enc0 as usize] as char);
        out.push(B64_CHARS[enc1 as usize] as char);
        if i + 1 < bytes.len() {
            out.push(B64_CHARS[enc2 as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(B64_CHARS[enc3 as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

fn connect_via_proxy(
    proxy_url: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, ()> {
    let trimmed = proxy_url.trim();
    let trimmed = trimmed.strip_prefix("http://").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix("https://").unwrap_or(trimmed);
    let (auth, host_port) = if let Some((userinfo, hp)) = trimmed.split_once('@') {
        (Some(userinfo), hp)
    } else {
        (None, trimmed)
    };
    let (p_host, p_port_str) = host_port.split_once(':').unwrap_or((host_port, "8080"));
    let p_port: u16 = p_port_str.trim_matches('/').parse().unwrap_or(8080);
    let mut tcp = TcpStream::connect((p_host, p_port)).map_err(|_| ())?;
    let mut req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    );
    if let Some(userinfo) = auth {
        let b64 = encode_base64(userinfo);
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", b64));
    }
    req.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");
    tcp.write_all(req.as_bytes()).map_err(|_| ())?;
    let mut buf = [0u8; 1024];
    let mut resp = Vec::new();
    loop {
        let n = tcp.read(&mut buf).map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        resp.extend_from_slice(&buf[..n]);
        if resp.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let resp_str = String::from_utf8_lossy(&resp);
    if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.0 200") {
        return Err(());
    }
    Ok(tcp)
}

/// Resolve and connect entirely in the broker, pinning the selected
/// `SocketAddr` for the lifetime of the TCP connection.
fn resolve_and_connect(
    host: &str,
    port: u16,
    config: &BrokerConfig,
    bus: &EventBus,
) -> Result<(TcpStream, SocketAddr), ()> {
    use std::net::ToSocketAddrs;
    let host = host.trim().trim_end_matches('.');
    if host.is_empty()
        || host
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b == b'\r' || b == b'\n')
    {
        return Err(());
    }

    if is_doh_or_dot(host, port, None) {
        return Err(());
    }

    if let Some(proxy_url) = get_upstream_proxy(host, port, config) {
        if let Ok(stream) = connect_via_proxy(&proxy_url, host, port) {
            let dummy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
            return Ok((stream, dummy_addr));
        }
    }

    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|_| ())?
        .collect::<Vec<_>>();

    if resolved.is_empty() {
        return Err(());
    }

    let cidrs: Vec<IpCidr> = config
        .allow_cidr
        .iter()
        .filter_map(|c| IpCidr::parse(c).ok())
        .collect();

    let any_forbidden = resolved.iter().any(|addr| {
        if is_doh_or_dot(host, port, Some(addr.ip())) {
            return true;
        }
        if (is_loopback_host(host) && addr.ip().is_loopback())
            || cidrs.iter().any(|c| c.contains(addr.ip()))
        {
            false
        } else {
            forbidden_destination(addr.ip())
        }
    });

    if any_forbidden {
        return Err(());
    }

    let ips: Vec<String> = resolved.iter().map(|a| a.ip().to_string()).collect();
    bus.publish(Event::DnsResolved {
        ts: crate::events::types::now(),
        host: host.to_string(),
        ips,
    });

    for addr in resolved {
        if let Ok(s) = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10)) {
            return Ok((s, addr));
        }
    }
    Err(())
}

const NAT64_WELL_KNOWN_PREFIX: [u8; 12] = [
    0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const NAT64_NETWORK_PREFIX: [u8; 6] = [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01];

/// Extract an IPv4 address embedded according to RFC 6052 from one of the
/// NAT64 prefixes that can appear in DNS answers.  For the /48 prefix, the
/// reserved `u` octet and suffix are ignored as prescribed by the RFC; the
/// embedded IPv4 bytes are at positions 48..64 and 72..88.
fn nat64_embedded_ipv4(octets: &[u8; 16]) -> Option<Ipv4Addr> {
    if octets.starts_with(&NAT64_WELL_KNOWN_PREFIX) {
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    if octets.starts_with(&NAT64_NETWORK_PREFIX) {
        return Some(Ipv4Addr::new(octets[6], octets[7], octets[9], octets[10]));
    }
    None
}

/// Reject destinations that identify local, private, link-local, multicast,
/// or otherwise non-public address space. This check runs on every resolved
/// answer in the broker, including literal IP targets, IPv4-mapped IPv6
/// answers, and NAT64-embedded IPv4 answers, before any socket connect is
/// attempted.
pub(crate) fn forbidden_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => forbidden_ipv4(ip),
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            let is_unspecified = octets.iter().all(|&b| b == 0);
            let is_loopback = octets[..15].iter().all(|&b| b == 0) && octets[15] == 1;
            let is_link_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80;
            let is_unique_local = (octets[0] & 0xfe) == 0xfc;
            let is_site_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0xc0;
            let is_multicast = octets[0] == 0xff;
            let is_documentation = (octets[0] == 0x20
                && octets[1] == 0x01
                && octets[2] == 0x0d
                && octets[3] == 0xb8)
                // 3fff::/20 is the newer IPv6 documentation prefix.
                || (octets[0] == 0x3f && octets[1] == 0xff && (octets[2] & 0xf0) == 0);
            let is_reserved_special_use = (octets[0] == 0x20
                && octets[1] == 0x01
                && octets[2] == 0
                && (octets[3] == 0 || octets[3] == 2))
                // 2002::/16 (6to4) is deprecated and not a valid egress target.
                || (octets[0] == 0x20 && octets[1] == 0x02);

            // IPv4-mapped IPv6 addresses must receive the same IPv4 policy.
            let is_v4_mapped =
                octets[..10].iter().all(|&b| b == 0) && octets[10] == 0xff && octets[11] == 0xff;
            let mapped_forbidden = is_v4_mapped
                && forbidden_ipv4(Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                ));
            let nat64_forbidden = nat64_embedded_ipv4(&octets)
                .map(forbidden_ipv4)
                .unwrap_or(false);

            is_unspecified
                || is_loopback
                || is_link_local
                || is_unique_local
                || is_site_local
                || is_multicast
                || is_documentation
                || is_reserved_special_use
                || mapped_forbidden
                || nat64_forbidden
        }
    }
}

fn forbidden_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    let private = a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168);
    let link_local = a == 169 && b == 254;
    let loopback = a == 127;
    let shared = a == 100 && (64..=127).contains(&b);
    let benchmarking = a == 198 && (18..=19).contains(&b);
    let protocol_assignment = a == 192 && b == 0 && c == 0;
    let documentation = (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113);
    let deprecated_6to4_anycast = a == 192 && b == 88 && c == 99;
    let multicast_or_reserved = a >= 224;
    let unspecified = a == 0;
    let broadcast = a == 255 && b == 255 && c == 255 && d == 255;
    let cloud_metadata = (a == 169 && b == 254 && c == 169 && d == 254)
        // Alibaba Cloud metadata endpoint.
        || (a == 100 && b == 100 && c == 100 && d == 200);

    private
        || link_local
        || loopback
        || shared
        || benchmarking
        || protocol_assignment
        || documentation
        || deprecated_6to4_anycast
        || multicast_or_reserved
        || unspecified
        || broadcast
        || cloud_metadata
}

pub(crate) fn extract_sni(buf: &[u8]) -> Result<Option<String>, ()> {
    if buf.is_empty() {
        return Ok(None);
    }
    if buf[0] != 0x16 {
        return Err(());
    }
    if buf.len() < 5 {
        return Ok(None);
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return Ok(None);
    }
    if buf[5] != 0x01 {
        return Err(());
    }

    let handshake_len = (u32::from_be_bytes([0, buf[6], buf[7], buf[8]])) as usize;
    if record_len < 4 + handshake_len {
        return Err(());
    }

    let mut pos = 9;
    pos += 2;
    pos += 32;

    if pos >= buf.len() {
        return Err(());
    }
    let session_id_len = buf[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > buf.len() {
        return Err(());
    }
    let cipher_suites_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    if pos >= buf.len() {
        return Err(());
    }
    let comp_methods_len = buf[pos] as usize;
    pos += 1 + comp_methods_len;

    if pos + 2 > buf.len() {
        return Ok(Some("".to_string()));
    }
    let extensions_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + extensions_len;
    if ext_end > buf.len() {
        return Err(());
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            if pos + ext_len > ext_end {
                return Err(());
            }
            let mut sni_pos = pos;
            if sni_pos + 2 > pos + ext_len {
                return Err(());
            }
            let _list_len = u16::from_be_bytes([buf[sni_pos], buf[sni_pos + 1]]) as usize;
            sni_pos += 2;

            while sni_pos + 3 <= pos + ext_len {
                let name_type = buf[sni_pos];
                let name_len = u16::from_be_bytes([buf[sni_pos + 1], buf[sni_pos + 2]]) as usize;
                sni_pos += 3;
                if name_type == 0 && sni_pos + name_len <= pos + ext_len {
                    return Ok(Some(
                        String::from_utf8_lossy(&buf[sni_pos..sni_pos + name_len]).to_string(),
                    ));
                }
                sni_pos += name_len;
            }
        }
        pos += ext_len;
    }
    Ok(Some("".to_string()))
}

const CMSG_SPACE_FD: usize = 32; // CMSG_SPACE(sizeof(int)) on 64-bit

fn create_and_send_data_fd(
    ctrl: &mut std::os::unix::net::UnixStream,
    tcp: TcpStream,
    host: &str,
    target_addr: SocketAddr,
    quotas: std::sync::Arc<Vec<(String, u64)>>,
    bus: EventBus,
) -> Result<(), ()> {
    let Some((mine, theirs)) = socketpair_stream().ok() else {
        return Err(());
    };
    // Reply status first, then the fd.
    if ctrl.write_all(b"O").is_err() || send_fd(ctrl.as_raw_fd(), theirs.as_raw_fd()).is_err() {
        return Err(()); // drops close both ends => tunnel torn down
    }
    drop(theirs);

    // Two independent half-duplex pumps with byte counting and quota enforcement:
    let mine = unsafe { std::os::unix::net::UnixStream::from_raw_fd(mine.into_raw_fd()) };
    let host_owned = host.to_string();
    std::thread::Builder::new()
        .name("broker-tunnel".into())
        .spawn(move || {
            forward_data_tunnel(mine, tcp, host_owned, target_addr, quotas, bus);
        })
        .map_err(|_| ())?;
    Ok(())
}

fn forward_data_tunnel(
    mine: std::os::unix::net::UnixStream,
    tcp: TcpStream,
    host_owned: String,
    target_addr: SocketAddr,
    quotas: std::sync::Arc<Vec<(String, u64)>>,
    bus: EventBus,
) {
    let Ok(unix_write) = mine.try_clone() else {
        return;
    };
    let Ok(tcp_read) = tcp.try_clone() else {
        return;
    };

    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    let bytes_rx = Arc::new(AtomicU64::new(0));
    let bytes_tx = Arc::new(AtomicU64::new(0));
    let quota_killed = Arc::new(AtomicBool::new(false));

    let rx_clone = Arc::clone(&bytes_rx);
    let tx_clone = Arc::clone(&bytes_tx);
    let quota_kill_rx = Arc::clone(&quota_killed);
    let quota_kill_tx = Arc::clone(&quota_killed);

    let host_tx = host_owned.clone();
    let bus_rx = bus.clone();
    let quotas_rx = Arc::clone(&quotas);
    let quotas_tx = Arc::clone(&quotas);

    // thread: outbound TCP -> unix (server responses toward the relay)
    let rev = std::thread::Builder::new()
        .name("broker-fwd-rx".into())
        .spawn(move || {
            let mut t = tcp_read;
            let mut u = unix_write;
            let mut buf = [0u8; 16384];
            loop {
                if quota_kill_rx.load(Ordering::Relaxed) {
                    break;
                }
                match t.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let total_rx = rx_clone.fetch_add(n as u64, Ordering::Relaxed) + (n as u64);
                        let total_tx = tx_clone.load(Ordering::Relaxed);
                        let transfer_now = total_rx + total_tx;
                        for (pat, limit) in quotas_rx.as_ref() {
                            let total = get_quota_bytes(pat) + transfer_now;
                            if total > *limit {
                                quota_kill_rx.store(true, Ordering::Relaxed);
                                bus_rx.publish(Event::NetQuotaExceeded {
                                    ts: crate::events::types::now(),
                                    host: pat.clone(),
                                    limit_bytes: *limit,
                                    used_bytes: total,
                                });
                                break;
                            }
                        }
                        if u.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = u.shutdown(std::net::Shutdown::Write);
        })
        .ok();

    let mut unix_side = mine;
    let mut outbound = tcp;

    if target_addr.port() == 443 {
        let mut sni_buf = Vec::new();
        let mut sni_ok = false;
        loop {
            let mut chunk = [0u8; 4096];
            match unix_side.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    sni_buf.extend_from_slice(&chunk[..n]);
                    match extract_sni(&sni_buf) {
                        Ok(Some(sni)) => {
                            let req_h = host_tx.trim().trim_end_matches('.').to_ascii_lowercase();
                            let act = sni.trim().trim_end_matches('.').to_ascii_lowercase();
                            let is_ip = req_h.parse::<std::net::IpAddr>().is_ok();
                            if (act.is_empty() && is_ip)
                                || act == req_h
                                || act.ends_with(&format!(".{req_h}"))
                                || req_h.ends_with(&format!(".{act}"))
                            {
                                sni_ok = true;
                            } else {
                                bus.publish(Event::Notice {
                                    ts: crate::events::types::now(),
                                    message: format!(
                                        "SNI mismatch: expected '{req_h}', got '{act}'"
                                    ),
                                });
                            }
                            break;
                        }
                        Ok(None) => {
                            if sni_buf.len() > 8192 {
                                break;
                            }
                        }
                        Err(_) => {
                            bus.publish(Event::Notice {
                                ts: crate::events::types::now(),
                                message: format!(
                                    "Non-TLS or malformed traffic on port 443 to {}",
                                    host_tx
                                ),
                            });
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }

        if !sni_ok {
            let _ = outbound.shutdown(std::net::Shutdown::Both);
            return;
        }

        if outbound.write_all(&sni_buf).is_err() {
            return;
        }
        bytes_tx.fetch_add(sni_buf.len() as u64, Ordering::Relaxed);
    }

    let mut buf = [0u8; 16384];
    loop {
        if quota_kill_tx.load(Ordering::Relaxed) {
            break;
        }
        match unix_side.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let total_tx = bytes_tx.fetch_add(n as u64, Ordering::Relaxed) + (n as u64);
                let total_rx = bytes_rx.load(Ordering::Relaxed);
                let transfer_now = total_rx + total_tx;
                for (pat, limit) in quotas_tx.as_ref() {
                    let total = get_quota_bytes(pat) + transfer_now;
                    if total > *limit {
                        quota_kill_tx.store(true, Ordering::Relaxed);
                        bus.publish(Event::NetQuotaExceeded {
                            ts: crate::events::types::now(),
                            host: pat.clone(),
                            limit_bytes: *limit,
                            used_bytes: total,
                        });
                        break;
                    }
                }
                if outbound.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    // Client closed: propagate EOF to the outbound connection.
    let _ = outbound.shutdown(std::net::Shutdown::Write);
    if let Some(h) = rev {
        let _ = h.join();
    }

    let final_tx = bytes_tx.load(Ordering::Relaxed);
    let final_rx = bytes_rx.load(Ordering::Relaxed);
    add_domain_transfer(&host_owned, final_tx, final_rx);

    bus.publish(Event::NetEgress {
        ts: crate::events::types::now(),
        host: host_owned,
        ip: target_addr.ip().to_string(),
        port: target_addr.port(),
        bytes_tx: final_tx,
        bytes_rx: final_rx,
    });
}

fn socketpair_stream() -> Result<(OwnedFd, OwnedFd), ()> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: valid out-array; flags are scalar.
    let r = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if r != 0 {
        return Err(());
    }
    // SAFETY: fresh owned fds from a successful socketpair.
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

/// sendmsg(2) carrying one fd in SCM_RIGHTS over `sock`.
pub(crate) fn send_fd(sock: RawFd, fd_to_send: RawFd) -> Result<(), ()> {
    #[repr(C)]
    struct CmsghdrAligned {
        hdr: libc::cmsghdr,
        data: libc::c_int,
        pad: [u8; 16],
    }
    let mut cmsg = CmsghdrAligned {
        hdr: libc::cmsghdr {
            cmsg_len: std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<libc::c_int>(),
            cmsg_level: libc::SOL_SOCKET,
            cmsg_type: libc::SCM_RIGHTS,
        },
        data: fd_to_send,
        pad: [0; 16],
    };
    let payload = b"F";
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let msghdr = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: &mut cmsg as *mut _ as *mut libc::c_void,
        msg_controllen: std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<libc::c_int>(),
        msg_flags: 0,
    };
    // SAFETY: all pointers valid for the call duration.
    let r = unsafe { libc::sendmsg(sock, &msghdr, 0) };
    if r < 0 {
        Err(())
    } else {
        Ok(())
    }
}

/// recvmsg(2) counterpart: receive one fd sent by [`send_fd`].
pub(crate) fn recv_fd(sock: RawFd) -> Result<OwnedFd, ()> {
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut control = [0u8; CMSG_SPACE_FD];
    let mut msghdr = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: control.len(),
        msg_flags: 0,
    };
    // SAFETY: all pointers/buffers valid for the call duration.
    let r = unsafe { libc::recvmsg(sock, &mut msghdr, libc::MSG_CMSG_CLOEXEC) };
    if r < 0 {
        return Err(());
    }
    let hdr_len = std::mem::size_of::<libc::cmsghdr>();
    if (msghdr.msg_controllen as usize) < hdr_len {
        return Err(());
    }
    // SAFETY: control buffer holds at least one cmsghdr we just validated.
    let cmsg = unsafe { control.as_ptr().cast::<libc::cmsghdr>().read_unaligned() };
    if cmsg.cmsg_level != libc::SOL_SOCKET || cmsg.cmsg_type != libc::SCM_RIGHTS {
        return Err(());
    }
    let data_len = cmsg.cmsg_len - hdr_len;
    if data_len < std::mem::size_of::<libc::c_int>() as usize {
        return Err(());
    }
    let fd_bytes = [
        control[hdr_len],
        control[hdr_len + 1],
        control[hdr_len + 2],
        control[hdr_len + 3],
    ];
    let fd = i32::from_ne_bytes(fd_bytes);
    // SAFETY: fresh fd received from the kernel via SCM_RIGHTS.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// ---------------------------------------------------------------------------
// Sandbox side: the relay process (runs INSIDE the netns as process R).
// ---------------------------------------------------------------------------

/// Serializes tunnel setup over the shared control socket (each accepted
/// client connection holds a dup of the same underlying socket).
static SETUP_LOCK: Mutex<()> = Mutex::new(());

/// Entry point of the relay process R. Never returns.
pub fn serve_relay(ctrl_fd: RawFd, port: u16) -> ! {
    // SAFETY: scalar-only signal call; a dead client must not kill the relay.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    if bring_up_loopback().is_err() {
        // No loopback => nothing is reachable at all: fails closed by design.
        std::process::exit(97);
    }
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(_) => std::process::exit(98),
    };
    for client in listener.incoming() {
        let Ok(client) = client else { continue };
        // SAFETY: ctrl_fd stays open for the whole relay lifetime.
        let dup_fd = unsafe { libc::dup(ctrl_fd) };
        if dup_fd < 0 {
            continue;
        }
        std::thread::Builder::new()
            .name("relay-conn".into())
            .spawn(move || handle_client(client, dup_fd))
            .ok();
    }
    std::process::exit(0)
}

fn handle_client(mut client: TcpStream, ctrl_fd: RawFd) {
    let _ = client.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let _ = client.set_write_timeout(Some(std::time::Duration::from_secs(30)));

    let mut first = [0u8; 1];
    if client.read_exact(&mut first).is_err() {
        return;
    }

    let target = if first[0] == 5 {
        socks5_handshake(&mut client, first[0]).map(|(h, p)| (h, p, None))
    } else {
        http_connect_head(&mut client, first[0])
    };

    let Some((host, port, token)) = target else {
        return;
    };

    let outcome = {
        let _guard = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        send_request_frame(ctrl_fd, &host, port, token.as_deref())
            .and_then(|_| read_status_and_fd(ctrl_fd))
    };

    match outcome {
        Ok(data_fd) => {
            // Timeouts protect the handshake from a stalled client, but an
            // SSH tunnel must be able to remain idle after it is established.
            let _ = client.set_read_timeout(None);
            let _ = client.set_write_timeout(None);
            if first[0] == 5 {
                let _ = client.write_all(&[5u8, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            } else {
                let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
            }
            pump(client, data_fd);
        }
        Err(denied) => {
            if first[0] == 5 {
                let code = if denied { 2 } else { 1 }; // 2=connection not allowed, 1=general failure
                let _ = client.write_all(&[5u8, code, 0, 1, 0, 0, 0, 0, 0, 0]);
            } else if denied {
                let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            } else {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            }
        }
    }
}

type HttpTarget = Option<(String, u16, Option<String>)>;
type SocksTarget = Option<(String, u16)>;

/// Parse an HTTP CONNECT request head (first byte already consumed).
fn http_connect_head(stream: &mut TcpStream, first: u8) -> HttpTarget {
    let mut buf = Vec::with_capacity(512);
    buf.push(first);
    const MAX_HEAD: usize = 16 * 1024;
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        if buf.len() > MAX_HEAD {
            return None;
        }
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).ok()?;
        buf.push(b[0]);
    }
    let head = String::from_utf8_lossy(&buf);
    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_ascii_uppercase();
    if method != "CONNECT" {
        // Plain absolute-URI HTTP is intentionally unsupported: fail closed.
        let _ = stream.write_all(b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n");
        return None;
    }
    let authority = parts.next()?;
    let (host, port_str) = authority.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;

    let mut token = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim()
                .eq_ignore_ascii_case(crate::sandbox::linux::debug_guard::DEBUG_AUTH_HEADER)
            {
                token = Some(v.trim().to_string());
                break;
            }
        }
    }

    Some((host.to_ascii_lowercase(), port, token))
}

/// Minimal socks5h server-side handshake (no-auth only, CONNECT only).
fn socks5_handshake(stream: &mut TcpStream, first: u8) -> SocksTarget {
    let mut nmethods = [0u8; 1];
    stream.read_exact(&mut nmethods).ok()?;
    if nmethods[0] == 0 || nmethods[0] > 32 {
        return None;
    }
    let mut methods = vec![0u8; nmethods[0] as usize];
    stream.read_exact(&mut methods).ok()?;
    if !methods.contains(&0u8) {
        let _ = stream.write_all(&[5u8, 0xFF]);
        return None;
    }
    let _ = stream.write_all(&[first, 0]); // chosen: no-auth

    let mut head = [0u8; 4]; // VER CMD RSV ATYP
    stream.read_exact(&mut head).ok()?;
    if head[1] != 1 {
        return None; // only CONNECT
    }
    let host = match head[3] {
        1 => {
            let mut o = [0u8; 4];
            stream.read_exact(&mut o).ok()?;
            format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
        }
        3 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).ok()?;
            let mut d = vec![0u8; l[0] as usize];
            stream.read_exact(&mut d).ok()?;
            String::from_utf8_lossy(&d).to_string()
        }
        4 => {
            let mut o = [0u8; 16];
            stream.read_exact(&mut o).ok()?;
            let halves: Vec<String> = o
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect();
            format!("[{}]", halves.join(":"))
        }
        _ => return None,
    };
    let mut pb = [0u8; 2];
    stream.read_exact(&mut pb).ok()?;
    let port = u16::from_be_bytes(pb);
    Some((host.to_ascii_lowercase(), port))
}

fn send_request_frame(
    ctrl_fd: RawFd,
    host: &str,
    port: u16,
    token: Option<&str>,
) -> Result<(), bool> {
    let req = RelayReq {
        host: host.to_string(),
        port,
        token: token.map(|t| t.to_string()),
    };
    let body = serde_json::to_string(&req).map_err(|_| false)?;
    let bytes = body.as_bytes();
    if bytes.len() > 4096 {
        return Err(false);
    }
    let mut frame = Vec::with_capacity(bytes.len() + 2);
    frame.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    frame.extend_from_slice(bytes);
    write_all_fd(ctrl_fd, &frame).map_err(|_| false)
}

fn read_status_and_fd(ctrl_fd: RawFd) -> Result<OwnedFd, bool> {
    let mut status = [0u8; 1];
    read_exact_fd(ctrl_fd, &mut status).map_err(|_| false)?;
    match status[0] {
        b'O' => recv_fd(ctrl_fd).map_err(|_| false),
        b'D' => Err(true),
        _ => Err(false),
    }
}

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<(), ()> {
    while !buf.is_empty() {
        // SAFETY: valid fd + buffer range.
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EINTR {
                continue;
            }
            return Err(());
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

fn read_exact_fd(fd: RawFd, mut buf: &mut [u8]) -> Result<(), ()> {
    while !buf.is_empty() {
        // SAFETY: valid fd + buffer range.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EINTR {
                continue;
            }
            return Err(());
        }
        if n == 0 {
            return Err(());
        }
        buf = &mut buf[n as usize..];
    }
    Ok(())
}

/// Pump both directions until both EOF. Blocks the calling thread.
fn pump(client: TcpStream, data_fd: OwnedFd) {
    // SAFETY: owned fd from recv_fd.
    let unix_side = unsafe { std::os::unix::net::UnixStream::from_raw_fd(data_fd.into_raw_fd()) };
    // Two independent half-duplex pumps:
    //   thread: client TCP -> unix (requests toward the broker)
    //   here:   unix -> client TCP (responses from the broker)
    let Ok(unix_write) = unix_side.try_clone() else {
        return;
    };
    let Ok(client_read) = client.try_clone() else {
        return;
    };
    let rev = std::thread::spawn(move || {
        let mut c = client_read;
        let mut u = unix_write;
        let _ = std::io::copy(&mut c, &mut u);
        // Client closed its sending side: propagate EOF to the broker.
        let _ = u.shutdown(std::net::Shutdown::Write);
    });
    let mut u = unix_side;
    let mut c = client;
    let _ = std::io::copy(&mut u, &mut c);
    let _ = c.shutdown(std::net::Shutdown::Write);
    let _ = rev.join();
}

pub fn build_proxy_env(port: u16) -> Vec<(String, String)> {
    let url = format!("http://127.0.0.1:{port}");
    [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ]
    .into_iter()
    .map(|k| (k.to_string(), url.clone()))
    .chain([
        ("NO_PROXY".to_string(), String::new()),
        ("no_proxy".to_string(), String::new()),
    ])
    .collect()
}

/// Build a shell-safe `GIT_SSH_COMMAND` using the current executable as the
/// in-process ProxyCommand helper. The helper is intentionally a child of
/// OpenSSH, not a background daemon.
pub fn build_git_ssh_command(executable: &std::path::Path) -> String {
    let executable = executable.to_string_lossy();
    let helper = format!("{} ssh-proxy %h %p", shell_quote(executable.as_ref()));
    format!(
        "ssh -o BatchMode=yes -o ProxyCommand={}",
        shell_quote(&helper)
    )
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".into();
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for c in value.chars() {
        if c == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(c);
        }
    }
    quoted.push('\'');
    quoted
}

/// Run the SSH `ProxyCommand` helper in this process. It speaks only HTTP
/// CONNECT to the in-sandbox relay and then forwards opaque SSH bytes; there
/// is no TLS interception, certificate handling, or external daemon.
pub fn run_ssh_proxy(host: &str, port: u16) -> anyhow::Result<()> {
    if port == 0
        || host.is_empty()
        || host
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b == b'\r' || b == b'\n')
    {
        anyhow::bail!("invalid SSH proxy target");
    }
    let mut relay = TcpStream::connect(("127.0.0.1", RELAY_PORT_BASE))?;
    relay.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    relay.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    let authority = format!("{host}:{port}");
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\n\r\n"
    );
    relay.write_all(request.as_bytes())?;
    let mut response = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while response.len() <= 16 * 1024 && !response.windows(4).any(|w| w == b"\r\n\r\n") {
        relay.read_exact(&mut byte)?;
        response.push(byte[0]);
    }
    let status = String::from_utf8_lossy(&response);
    if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.0 200 ") {
        anyhow::bail!("SSH proxy relay denied CONNECT");
    }
    relay.set_read_timeout(None)?;
    relay.set_write_timeout(None)?;

    let mut outbound = relay.try_clone()?;
    let from_stdin = std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let _ = std::io::copy(&mut stdin, &mut outbound);
        let _ = outbound.shutdown(std::net::Shutdown::Write);
    });
    let mut stdout = std::io::stdout();
    let _ = std::io::copy(&mut relay, &mut stdout);
    let _ = stdout.flush();
    let _ = from_stdin.join();
    Ok(())
}

// ---------------------------------------------------------------------------
// Loopback bring-up inside the fresh netns (raw netlink, no iproute2).
// ---------------------------------------------------------------------------

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;
const NLMSG_ERROR: u16 = 2;
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const RT_SCOPE_HOST: u8 = 254;
const IFA_LOCAL: u16 = 2;
const IFF_UP: u32 = 0x1;

#[repr(C)]
struct NlMsgHdr {
    len: u32,
    nlmsg_type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

#[repr(C)]
struct IfAddrMsgNl {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: u32,
}

#[repr(C)]
struct RtAttr {
    len: u16,
    rta_type: u16,
}

#[repr(C)]
struct IfInfoMsgNl {
    family: u8,
    _pad: u8,
    nl_type: u16,
    index: i32,
    flags: u32,
    change: u32,
}

const fn align4(x: usize) -> usize {
    (x + 3) & !3
}

fn netlink_exchange(buf: &[u8]) -> Result<(), ()> {
    // SAFETY: scalar args; socket closed via guard below.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(());
    }
    let sent = unsafe { libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0) };
    if sent as usize != buf.len() {
        unsafe { libc::close(fd) };
        return Err(());
    }
    let mut resp = [0u8; 256];
    let mut ok = false;
    for _ in 0..4 {
        let n = unsafe { libc::recv(fd, resp.as_mut_ptr() as *mut libc::c_void, resp.len(), 0) };
        if n < (std::mem::size_of::<NlMsgHdr>() as isize) {
            break;
        }
        // SAFETY: buffer holds at least one full header (checked above).
        let hdr = unsafe { resp.as_ptr().cast::<NlMsgHdr>().read_unaligned() };
        if hdr.nlmsg_type == NLMSG_ERROR {
            // error==0 means ACK success; anything else fails.
            let err_off = std::mem::size_of::<NlMsgHdr>();
            let err = i32::from_ne_bytes([
                resp[err_off],
                resp[err_off + 1],
                resp[err_off + 2],
                resp[err_off + 3],
            ]);
            ok = err == 0;
            break;
        }
    }
    // SAFETY: plain close on our own descriptor.
    unsafe { libc::close(fd) };
    if ok {
        Ok(())
    } else {
        Err(())
    }
}

/// Bring `lo` up with 127.0.0.1/8 inside this namespace.
fn bring_up_loopback() -> Result<(), ()> {
    // --- RTM_NEWADDR: assign 127.0.0.1/8 to ifindex 1 -----------------------
    let addr_payload_len = std::mem::size_of::<IfAddrMsgNl>();
    let attr_space = align4(std::mem::size_of::<RtAttr>()) + 4;
    let total = align4(std::mem::size_of::<NlMsgHdr>()) + addr_payload_len + attr_space;

    let mut msg = vec![0u8; total];
    let hdr = NlMsgHdr {
        len: total as u32,
        nlmsg_type: RTM_NEWADDR,
        flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq: 1,
        pid: 0,
    };
    let mut off = 0;
    put(&mut msg, &mut off, &hdr);
    put(
        &mut msg,
        &mut off,
        &IfAddrMsgNl {
            family: libc::AF_INET as u8,
            prefixlen: 8,
            flags: 0,
            scope: RT_SCOPE_HOST,
            index: 1, // lo always has ifindex 1 in a fresh netns
        },
    );
    let attr = RtAttr {
        len: (std::mem::size_of::<RtAttr>() + 4) as u16,
        rta_type: IFA_LOCAL,
    };
    put(&mut msg, &mut off, &attr);
    msg[off..off + 4].copy_from_slice(&[127, 0, 0, 1]);

    netlink_exchange(&msg)?;

    // --- RTM_NEWLINK: set IFF_UP on lo --------------------------------------
    let link_total =
        align4(std::mem::size_of::<NlMsgHdr>()) + align4(std::mem::size_of::<IfInfoMsgNl>());
    let mut lmsg = vec![0u8; link_total];
    let hdr = NlMsgHdr {
        len: link_total as u32,
        nlmsg_type: RTM_NEWLINK,
        flags: NLM_F_REQUEST | NLM_F_ACK,
        seq: 2,
        pid: 0,
    };
    let mut off = 0;
    put(&mut lmsg, &mut off, &hdr);
    put(
        &mut lmsg,
        &mut off,
        &IfInfoMsgNl {
            family: 0,
            _pad: 0,
            nl_type: 0,
            index: 1,
            flags: IFF_UP,
            change: IFF_UP,
        },
    );
    netlink_exchange(&lmsg)
}

fn put<T>(buf: &mut [u8], off: &mut usize, val: &T) {
    let size = std::mem::size_of::<T>();
    // SAFETY: reading a repr(C) struct as raw bytes into a sized buffer.
    let bytes = unsafe { std::slice::from_raw_parts(val as *const T as *const u8, size) };
    buf[*off..*off + size].copy_from_slice(bytes);
    *off += align4(size);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn extracts_rfc6052_nat64_ipv4_for_both_prefix_lengths() {
        let well_known = Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0xc000, 0x0221);
        assert_eq!(
            nat64_embedded_ipv4(&well_known.octets()),
            Some(Ipv4Addr::new(192, 0, 2, 33))
        );

        let network_specific = Ipv6Addr::new(0x0064, 0xff9b, 1, 0xc000, 2, 0x2100, 0, 0);
        assert_eq!(
            nat64_embedded_ipv4(&network_specific.octets()),
            Some(Ipv4Addr::new(192, 0, 2, 33))
        );
    }

    #[test]
    fn rejects_forbidden_ipv4_destinations() {
        let forbidden = [
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 0, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 1),
            Ipv4Addr::new(203, 0, 113, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(192, 88, 99, 1),
            Ipv4Addr::new(100, 100, 100, 200),
        ];

        for ip in forbidden {
            assert!(forbidden_destination(IpAddr::V4(ip)), "allowed {ip}");
        }
        assert!(!forbidden_destination(IpAddr::V4(Ipv4Addr::new(
            93, 184, 216, 34,
        ))));
    }

    #[test]
    fn test_loopback_host_verification() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("evil.com"));
        assert!(!is_loopback_host("api.openai.com"));
        assert!(!is_loopback_host("192.168.1.1"));
    }

    #[test]
    fn rejects_forbidden_ipv6_destinations_and_mapped_ipv4() {
        let forbidden = [
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 254),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 1),
            // 64:ff9b::/96 embedding 10.1.2.3.
            Ipv6Addr::from([0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 1, 2, 3]),
            // 64:ff9b::/96 embedding the AWS/GCP metadata endpoint.
            Ipv6Addr::from([
                0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 169, 254, 169, 254,
            ]),
            // 64:ff9b:1::/48 embedding 192.168.1.1; byte 8 is the RFC 6052 u octet.
            Ipv6Addr::from([
                0x00, 0x64, 0xff, 0x9b, 0, 1, 192, 168, 0, 1, 1, 0, 0, 0, 0, 0,
            ]),
            // 64:ff9b:1::/48 embedding the metadata endpoint.
            Ipv6Addr::from([
                0x00, 0x64, 0xff, 0x9b, 0, 1, 169, 254, 0, 169, 254, 0, 0, 0, 0, 0,
            ]),
        ];

        for ip in forbidden {
            assert!(forbidden_destination(IpAddr::V6(ip)), "allowed {ip}");
        }
        assert!(!forbidden_destination(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0x20, 0, 0, 0, 0, 1,
        ))));
        assert!(!forbidden_destination(IpAddr::V6(Ipv6Addr::from([
            0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8,
        ]))));
        assert!(!forbidden_destination(IpAddr::V6(Ipv6Addr::from([
            0x00, 0x64, 0xff, 0x9b, 0, 1, 8, 8, 0, 8, 8, 0, 0, 0, 0, 0,
        ]))));
    }

    #[test]
    fn strict_policy_requires_exact_port_and_domain_boundary() {
        let rules = vec![NetRule {
            domain: "github.com".into(),
            port: 443,
        }];
        assert!(strict_allowed("github.com", 443, &rules));
        assert!(strict_allowed("api.github.com.", 443, &rules));
        assert!(!strict_allowed("github.com", 22, &rules));
        assert!(!strict_allowed("notgithub.com", 443, &rules));
    }

    #[test]
    fn git_ssh_command_quotes_executable_and_uses_proxy_helper() {
        let command = build_git_ssh_command(std::path::Path::new("/tmp/vetto agent"));
        assert!(command.contains("ProxyCommand="));
        assert!(command.contains("ssh-proxy %h %p"));
        assert!(command.contains("'\\''") || command.contains("'/tmp/vetto agent'"));
    }

    #[test]
    fn loopback_debug_guard_integration() {
        let bus = crate::events::bus::EventBus::new();
        let guard = DebugPortGuard::new(DebugPortConfig {
            isolate_devtools: true,
            ..DebugPortConfig::default()
        });
        let config = BrokerConfig {
            policy: BrokerPolicy::Allowlist(vec!["127.0.0.1".into()]),
            debug_guard: Some(guard.clone()),
            mode: RelayMode::NetNs,
            allow_cidr: Vec::new(),
            quotas: std::collections::HashMap::new(),
            policy_path: None,
            block_doh: false,
            http_proxy: None,
            https_proxy: None,
            no_proxy: None,
        };

        // Blocked without token when isolate_devtools is true
        assert!(!request_allowed("127.0.0.1", 9222, None, &config, &bus));
        assert!(!request_allowed("127.0.0.1", 9229, None, &config, &bus));
        assert!(!request_allowed("127.0.0.1", 5678, None, &config, &bus));

        // Allowed with valid token
        let token = guard.session_token();
        assert!(request_allowed(
            "127.0.0.1",
            9222,
            Some(token),
            &config,
            &bus
        ));
        assert!(request_allowed(
            "127.0.0.1",
            9229,
            Some(token),
            &config,
            &bus
        ));
        assert!(request_allowed(
            "127.0.0.1",
            5678,
            Some(token),
            &config,
            &bus
        ));

        // Allowed on other non-debug port
        assert!(request_allowed("127.0.0.1", 8080, None, &config, &bus));

        // With default DebugPortConfig: Computer Use (port 9222/9223) and localhost dev servers are allowed
        let default_guard = DebugPortGuard::new(DebugPortConfig::default());
        let default_config = BrokerConfig {
            policy: BrokerPolicy::Allowlist(Vec::new()),
            debug_guard: Some(default_guard),
            mode: RelayMode::NetNs,
            allow_cidr: Vec::new(),
            quotas: std::collections::HashMap::new(),
            policy_path: None,
            block_doh: false,
            http_proxy: None,
            https_proxy: None,
            no_proxy: None,
        };
        assert!(request_allowed(
            "127.0.0.1",
            9222,
            None,
            &default_config,
            &bus
        ));
        assert!(request_allowed(
            "127.0.0.1",
            9223,
            None,
            &default_config,
            &bus
        ));
        assert!(request_allowed(
            "localhost",
            3000,
            None,
            &default_config,
            &bus
        ));
        assert!(request_allowed(
            "127.0.0.1",
            5173,
            None,
            &default_config,
            &bus
        ));
        // Host debuggers still blocked by default
        assert!(!request_allowed(
            "127.0.0.1",
            9229,
            None,
            &default_config,
            &bus
        ));
        assert!(!request_allowed(
            "127.0.0.1",
            5678,
            None,
            &default_config,
            &bus
        ));
    }

    #[test]
    fn wildcard_domain_matching_covers_subdomains_only() {
        let allowlist = vec![
            "*.githubusercontent.com".to_string(),
            "crates.io".to_string(),
        ];
        // Subdomains of wildcard match
        assert!(domain_allowed("raw.githubusercontent.com", &allowlist));
        assert!(domain_allowed("avatars.githubusercontent.com", &allowlist));
        assert!(domain_allowed("a.b.githubusercontent.com", &allowlist));

        // Base domain of wildcard does NOT match (subdomains only!)
        assert!(!domain_allowed("githubusercontent.com", &allowlist));
        // Suffix collision does NOT match
        assert!(!domain_allowed("notgithubusercontent.com", &allowlist));

        // Regular domain matches itself and subdomains
        assert!(domain_allowed("crates.io", &allowlist));
        assert!(domain_allowed("index.crates.io", &allowlist));
        assert!(!domain_allowed("notcrates.io", &allowlist));
    }

    #[test]
    fn ip_cidr_parsing_and_containment() {
        let cidr_v4 = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(cidr_v4.contains("10.0.0.1".parse().unwrap()));
        assert!(cidr_v4.contains("10.255.255.255".parse().unwrap()));
        assert!(!cidr_v4.contains("11.0.0.1".parse().unwrap()));

        let cidr_v4_single = IpCidr::parse("192.168.1.100/32").unwrap();
        assert!(cidr_v4_single.contains("192.168.1.100".parse().unwrap()));
        assert!(!cidr_v4_single.contains("192.168.1.101".parse().unwrap()));

        let cidr_v6 = IpCidr::parse("2001:db8::/32").unwrap();
        assert!(cidr_v6.contains("2001:db8:1234::1".parse().unwrap()));
        assert!(!cidr_v6.contains("2001:db9::1".parse().unwrap()));

        let bare_v4 = IpCidr::parse("10.0.0.5").unwrap();
        assert_eq!(bare_v4.prefix_len, 32);
        assert!(bare_v4.contains("10.0.0.5".parse().unwrap()));
        assert!(!bare_v4.contains("10.0.0.6".parse().unwrap()));

        let bare_v6 = IpCidr::parse("::1").unwrap();
        assert_eq!(bare_v6.prefix_len, 128);
        assert!(bare_v6.contains("::1".parse().unwrap()));

        let bracketed_v6 = IpCidr::parse("[2001:db8::]/64").unwrap();
        assert_eq!(bracketed_v6.prefix_len, 64);
        assert!(bracketed_v6.contains("2001:db8::1".parse().unwrap()));

        let bracketed_bare = IpCidr::parse("[::1]").unwrap();
        assert_eq!(bracketed_bare.prefix_len, 128);
        assert!(bracketed_bare.contains("::1".parse().unwrap()));

        assert!(IpCidr::parse("invalid").is_err());
        assert!(IpCidr::parse("10.0.0.1/33").is_err());
    }

    #[test]
    fn doh_and_dot_blocking_intercepts_known_providers_and_ports() {
        assert!(is_doh_or_dot("1.1.1.1", 443, None));
        assert!(is_doh_or_dot("8.8.8.8", 443, None));
        assert!(is_doh_or_dot("dns.google", 443, None));
        assert!(is_doh_or_dot("cloudflare-dns.com", 443, None));
        assert!(is_doh_or_dot("dns.quad9.net", 443, None));
        // Port 853 is DoT
        assert!(is_doh_or_dot("anydomain.com", 853, None));

        // Normal domain & port not blocked
        assert!(!is_doh_or_dot(
            "example.com",
            443,
            Some("93.184.216.34".parse().unwrap())
        ));
    }

    #[test]
    fn domain_allowed_normalizes_port_suffixes() {
        let allowlist_with_ports =
            vec!["crates.io:443".to_string(), "*.github.com:443".to_string()];
        assert!(domain_allowed("crates.io", &allowlist_with_ports));
        assert!(domain_allowed("crates.io:443", &allowlist_with_ports));
        assert!(domain_allowed("api.github.com", &allowlist_with_ports));
        assert!(domain_allowed("api.github.com:443", &allowlist_with_ports));
        assert!(!domain_allowed("evil.com", &allowlist_with_ports));

        let plain_allowlist = vec!["crates.io".to_string(), "*.github.com".to_string()];
        assert!(domain_allowed("crates.io:443", &plain_allowlist));
        assert!(domain_allowed("api.github.com:443", &plain_allowlist));
    }

    #[test]
    fn interactive_ask_non_tty_fails_closed() {
        let mut output = Vec::new();
        let reader = std::io::Cursor::new(b"y\n");
        let allowed = prompt_confirmation_interactive(
            "api.example.com",
            443,
            None,
            false,
            reader,
            &mut output,
        );
        assert!(!allowed);
        let out_str = String::from_utf8_lossy(&output);
        assert!(out_str.contains("interactive confirmation unavailable (stdin is not a tty)"));
        assert!(out_str.contains("connection to 'api.example.com:443' denied (fail-closed)"));
    }

    #[test]
    fn interactive_ask_temporary_yes() {
        let mut output = Vec::new();
        let reader = std::io::Cursor::new(b"y\n");
        let allowed = prompt_confirmation_interactive(
            "api.example.com",
            443,
            None,
            true,
            reader,
            &mut output,
        );
        assert!(allowed);
        let out_str = String::from_utf8_lossy(&output);
        assert!(out_str
            .contains("allow network connection to 'api.example.com:443'? [y/N/p (permanent)]:"));
        assert!(!out_str.contains("permanently allowed"));

        let mut output2 = Vec::new();
        let reader2 = std::io::Cursor::new(b"yes\n");
        let allowed2 = prompt_confirmation_interactive(
            "api2.example.com",
            443,
            None,
            true,
            reader2,
            &mut output2,
        );
        assert!(allowed2);
    }

    #[test]
    fn interactive_ask_denial_on_no_or_invalid() {
        for input in [
            b"n\n".as_slice(),
            b"no\n".as_slice(),
            b"\n".as_slice(),
            b"invalid\n".as_slice(),
        ] {
            let mut output = Vec::new();
            let reader = std::io::Cursor::new(input);
            let allowed = prompt_confirmation_interactive(
                "blocked.example.com",
                443,
                None,
                true,
                reader,
                &mut output,
            );
            assert!(!allowed);
        }
    }

    #[test]
    fn interactive_ask_permanent_persists_domain() {
        let temp_dir = std::env::temp_dir().join(format!("vetto-ask-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let policy_file = temp_dir.join("policy.toml");

        let mut output = Vec::new();
        let reader = std::io::Cursor::new(b"p\n");
        let allowed = prompt_confirmation_interactive(
            "api.github.com",
            443,
            Some(&policy_file),
            true,
            reader,
            &mut output,
        );
        assert!(allowed);
        let out_str = String::from_utf8_lossy(&output);
        assert!(out_str.contains("domain 'api.github.com' permanently allowed and saved to"));

        assert!(policy_file.is_file());
        let content = std::fs::read_to_string(&policy_file).unwrap();
        assert!(content.contains("\"api.github.com\""));
        assert!(content.contains("mode = \"allowlist\""));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn interactive_ask_permanent_persists_ip_as_cidr() {
        let temp_dir =
            std::env::temp_dir().join(format!("vetto-ask-ip-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let policy_file = temp_dir.join("policy.toml");

        let mut output = Vec::new();
        let reader = std::io::Cursor::new(b"permanent\n");
        let allowed = prompt_confirmation_interactive(
            "192.168.1.100",
            8080,
            Some(&policy_file),
            true,
            reader,
            &mut output,
        );
        assert!(allowed);
        let out_str = String::from_utf8_lossy(&output);
        assert!(out_str.contains("CIDR '192.168.1.100' permanently allowed and saved to"));

        assert!(policy_file.is_file());
        let content = std::fs::read_to_string(&policy_file).unwrap();
        assert!(content.contains("192.168.1.100/32"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn request_allowed_ask_preallowed_domain_does_not_prompt() {
        let bus = crate::events::bus::EventBus::new();
        let config = BrokerConfig {
            policy: BrokerPolicy::Ask(vec!["preallowed.com".into()]),
            debug_guard: None,
            mode: RelayMode::NetNs,
            allow_cidr: Vec::new(),
            quotas: std::collections::HashMap::new(),
            policy_path: None,
            block_doh: false,
            http_proxy: None,
            https_proxy: None,
            no_proxy: None,
        };

        // Pre-allowed domain is permitted immediately without prompt
        assert!(request_allowed("preallowed.com", 443, None, &config, &bus));
        assert!(request_allowed(
            "sub.preallowed.com",
            443,
            None,
            &config,
            &bus
        ));

        // Non-preallowed domain goes to ask_confirmation; in non-tty test env it fails closed
        assert!(!request_allowed("unknown.com", 443, None, &config, &bus));
    }

    #[test]
    fn test_domain_matches_pattern_hierarchy() {
        assert!(domain_matches_pattern("github.com", "github.com"));
        assert!(domain_matches_pattern("api.github.com", "github.com"));
        assert!(domain_matches_pattern("codeload.github.com", "github.com"));
        assert!(domain_matches_pattern("a.b.c.github.com", "github.com"));
        assert!(!domain_matches_pattern("notgithub.com", "github.com"));

        assert!(domain_matches_pattern("api.github.com", "*.github.com"));
        assert!(domain_matches_pattern("github.com", "*.github.com"));
        assert!(!domain_matches_pattern("evil.com", "*.github.com"));

        assert!(domain_matches_pattern("anything.com", "*"));

        assert!(domain_matches_pattern("10.0.1.5", "10.0.0.0/16"));
        assert!(!domain_matches_pattern("192.168.1.1", "10.0.0.0/16"));
    }

    #[test]
    fn test_hierarchical_quota_aggregation_and_enforcement() {
        let bus = crate::events::bus::EventBus::new();
        reset_domain_transfer_stats();

        // Record traffic across different subdomains
        add_domain_transfer("api.github.com", 30 * 1024 * 1024, 10 * 1024 * 1024); // 40MB
        add_domain_transfer("codeload.github.com", 15 * 1024 * 1024, 5 * 1024 * 1024); // 20MB
        add_domain_transfer("crates.io", 5 * 1024 * 1024, 5 * 1024 * 1024); // 10MB

        // Check aggregate bytes
        assert_eq!(get_quota_bytes("api.github.com"), 40 * 1024 * 1024);
        assert_eq!(get_quota_bytes("codeload.github.com"), 20 * 1024 * 1024);
        // Parent domain aggregates all github.com subdomains
        assert_eq!(get_quota_bytes("github.com"), 60 * 1024 * 1024);
        assert_eq!(get_quota_bytes("crates.io"), 10 * 1024 * 1024);
        assert_eq!(get_quota_bytes("other.org"), 0);

        // Test request_allowed with parent domain quota
        let mut quotas = std::collections::HashMap::new();
        quotas.insert("github.com".to_string(), 100 * 1024 * 1024); // 100MB limit
        let config = BrokerConfig {
            policy: BrokerPolicy::Allowlist(vec!["github.com".into()]),
            debug_guard: None,
            mode: RelayMode::NetNs,
            allow_cidr: Vec::new(),
            quotas,
            policy_path: None,
            block_doh: false,
            http_proxy: None,
            https_proxy: None,
            no_proxy: None,
        };

        // 60MB used < 100MB limit -> allowed
        assert!(request_allowed("gist.github.com", 443, None, &config, &bus));

        // Add more traffic that exceeds the 100MB parent limit
        add_domain_transfer("gist.github.com", 25 * 1024 * 1024, 25 * 1024 * 1024); // +50MB -> total 110MB
        assert_eq!(get_quota_bytes("github.com"), 110 * 1024 * 1024);

        // Now parent domain limit is exceeded: fail-closed on any github.com subdomain
        assert!(!request_allowed("api.github.com", 443, None, &config, &bus));
        assert!(!request_allowed("raw.github.com", 443, None, &config, &bus));

        reset_domain_transfer_stats();
    }

    #[test]
    fn test_doh_dot_blocking_flags() {
        let bus = crate::events::bus::EventBus::new();
        let mut config = BrokerConfig {
            policy: BrokerPolicy::Allowlist(vec!["allowed.com".into()]),
            debug_guard: None,
            mode: RelayMode::NetNs,
            allow_cidr: Vec::new(),
            quotas: std::collections::HashMap::new(),
            policy_path: None,
            block_doh: true,
            http_proxy: None,
            https_proxy: None,
            no_proxy: None,
        };

        // Port 853 (DoT) should be blocked when block_doh is true
        assert!(!request_allowed("anydomain.com", 853, None, &config, &bus));
        assert!(!request_allowed("8.8.8.8", 853, None, &config, &bus));

        // DoH endpoints should be blocked if not explicitly allowed
        assert!(!request_allowed(
            "cloudflare-dns.com",
            443,
            None,
            &config,
            &bus
        ));
        assert!(!request_allowed("dns.google", 443, None, &config, &bus));
        assert!(!request_allowed("8.8.8.8", 443, None, &config, &bus));

        // But explicitly allowed DoH endpoint should be allowed
        let mut config_allowed = config.clone();
        config_allowed.policy = BrokerPolicy::Allowlist(vec!["cloudflare-dns.com".into()]);
        assert!(request_allowed(
            "cloudflare-dns.com",
            443,
            None,
            &config_allowed,
            &bus
        ));

        // When block_doh is false, DoH and DoT should not be specifically blocked (unless policy denies it)
        config.block_doh = false;
        config.policy = BrokerPolicy::Allowlist(vec!["*".into()]);
        assert!(request_allowed("anydomain.com", 853, None, &config, &bus));
        assert!(request_allowed(
            "cloudflare-dns.com",
            443,
            None,
            &config,
            &bus
        ));
    }

    #[test]
    fn test_encode_base64() {
        assert_eq!(super::encode_base64("user:pass"), "dXNlcjpwYXNz");
        assert_eq!(
            super::encode_base64("admin:password123"),
            "YWRtaW46cGFzc3dvcmQxMjM="
        );
        assert_eq!(
            super::encode_base64("Aladdin:open sesame"),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn test_get_upstream_proxy_routing() {
        let config = BrokerConfig {
            policy: BrokerPolicy::Allowlist(Vec::new()),
            debug_guard: None,
            mode: RelayMode::NetNs,
            allow_cidr: Vec::new(),
            quotas: std::collections::HashMap::new(),
            policy_path: None,
            block_doh: false,
            http_proxy: Some("http://proxy.corp:8080".into()),
            https_proxy: Some("http://proxy.corp:8443".into()),
            no_proxy: Some("localhost,127.0.0.1,.local,ignore.com".into()),
        };

        // Standard routing
        assert_eq!(
            super::get_upstream_proxy("example.com", 80, &config).as_deref(),
            Some("http://proxy.corp:8080")
        );
        assert_eq!(
            super::get_upstream_proxy("example.com", 443, &config).as_deref(),
            Some("http://proxy.corp:8443")
        );

        // No-proxy routing
        assert_eq!(super::get_upstream_proxy("localhost", 80, &config), None);
        assert_eq!(super::get_upstream_proxy("127.0.0.1", 443, &config), None);
        assert_eq!(super::get_upstream_proxy("api.local", 443, &config), None);
        assert_eq!(super::get_upstream_proxy("ignore.com", 80, &config), None);
        assert_eq!(
            super::get_upstream_proxy("sub.ignore.com", 80, &config),
            None
        );
    }
}
