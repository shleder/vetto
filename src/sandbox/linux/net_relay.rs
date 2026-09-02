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
use std::sync::Mutex;

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
    Ask,
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
}

impl From<BrokerPolicy> for BrokerConfig {
    fn from(policy: BrokerPolicy) -> Self {
        Self {
            policy,
            debug_guard: Some(DebugPortGuard::new(DebugPortConfig::default())),
            mode: RelayMode::NetNs,
            allow_cidr: Vec::new(),
            quotas: std::collections::HashMap::new(),
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

fn is_stdin_tty() -> bool {
    unsafe { libc::isatty(0) == 1 }
}

fn ask_confirmation(host: &str, port: u16) -> bool {
    let mut guard = ASK_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.get_or_insert_with(std::collections::HashMap::new);
    let key = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(&allowed) = cache.get(&key) {
        return allowed;
    }

    if !is_stdin_tty() {
        eprintln!(
            "vetto: [net=ask] interactive confirmation unavailable (stdin is not a tty); connection to '{host}:{port}' denied (fail-closed)"
        );
        cache.insert(key, false);
        return false;
    }

    eprint!("vetto: allow network connection to '{host}:{port}'? [y/N]: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let allowed = if std::io::stdin().read_line(&mut line).is_ok() {
        let trimmed = line.trim().to_ascii_lowercase();
        trimmed == "y" || trimmed == "yes"
    } else {
        false
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
        let (ip_str, prefix_str) = s
            .trim()
            .split_once('/')
            .ok_or_else(|| format!("CIDR '{s}' must be in IP/prefix format"))?;
        let ip: IpAddr = ip_str
            .trim()
            .parse()
            .map_err(|e| format!("invalid IP in CIDR '{s}': {e}"))?;
        let prefix_len: u8 = prefix_str
            .trim()
            .parse()
            .map_err(|e| format!("invalid prefix in CIDR '{s}': {e}"))?;
        match ip {
            IpAddr::V4(_) if prefix_len > 32 => {
                return Err(format!(
                    "IPv4 prefix length must be 0..=32, got {prefix_len}"
                ));
            }
            IpAddr::V6(_) if prefix_len > 128 => {
                return Err(format!(
                    "IPv6 prefix length must be 0..=128, got {prefix_len}"
                ));
            }
            _ => {}
        }
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
    if let Ok(ip_addr) = host.parse::<IpAddr>() {
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
                if !request_allowed(&req.host, req.port, req.token.as_deref(), &config) {
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
                match resolve_and_connect(&req.host, req.port, &config.allow_cidr, &bus) {
                    Ok((tcp, addr)) => {
                        bus.publish(Event::NetRequest {
                            ts: crate::events::types::now(),
                            host: req.host.clone(),
                            port: req.port,
                            allowed: true,
                        });
                        let quota = config.quotas.get(&req.host).copied();
                        if create_and_send_data_fd(
                            &mut ctrl,
                            tcp,
                            &req.host,
                            addr,
                            quota,
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

/// Allowlist semantics: exact match, wildcard subdomain (*.domain.com), or parent domain match
pub fn domain_allowed(host: &str, allowlist: &[String]) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    allowlist.iter().any(|pat| {
        let pat = pat.trim().trim_end_matches('.').to_ascii_lowercase();
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
/// DNS resolution.
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
        if pat == "*" {
            return true;
        }
        if let Some(suffix) = pat.strip_prefix("*.") {
            host.ends_with(&format!(".{suffix}"))
        } else {
            host == pat || host.ends_with(&format!(".{pat}"))
        }
    })
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]"
}

fn request_allowed(host: &str, port: u16, token: Option<&str>, config: &BrokerConfig) -> bool {
    // Check DoH/DoT block
    if is_doh_or_dot(host, port, None) {
        return false;
    }

    // Check loopback debug port guard
    if is_loopback_host(host) {
        if let Some(ref guard) = config.debug_guard {
            if guard.check_access(port, token) != DebugPortVerdict::Allowed {
                return false;
            }
        }
    }

    // Check per-domain quota
    if let Some(&limit) = config.quotas.get(host) {
        let used = get_domain_bytes(host);
        if used >= limit {
            return false;
        }
    }

    // If host is an IP that matches an allowed CIDR
    if let Ok(ip) = host.parse::<IpAddr>() {
        let cidrs: Vec<IpCidr> = config
            .allow_cidr
            .iter()
            .filter_map(|c| IpCidr::parse(c).ok())
            .collect();
        if cidrs.iter().any(|c| c.contains(ip)) {
            return true;
        }
    }

    match &config.policy {
        BrokerPolicy::Allowlist(domains) => domain_allowed(host, domains),
        BrokerPolicy::Strict(rules) => strict_allowed(host, port, rules),
        BrokerPolicy::Ask => ask_confirmation(host, port),
    }
}

fn get_upstream_proxy(host: &str, port: u16) -> Option<String> {
    if let Ok(no_proxy) = std::env::var("NO_PROXY").or_else(|_| std::env::var("no_proxy")) {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        for item in no_proxy.split(',') {
            let item = item.trim().trim_end_matches('.').to_ascii_lowercase();
            if !item.is_empty() && (item == "*" || h == item || h.ends_with(&format!(".{item}"))) {
                return None;
            }
        }
    }
    if port == 443 {
        std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .or_else(|_| std::env::var("ALL_PROXY"))
            .or_else(|_| std::env::var("all_proxy"))
            .ok()
    } else {
        std::env::var("HTTP_PROXY")
            .or_else(|_| std::env::var("http_proxy"))
            .or_else(|_| std::env::var("ALL_PROXY"))
            .or_else(|_| std::env::var("all_proxy"))
            .ok()
    }
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
    if let Some(_userinfo) = auth {
        // basic auth if needed
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
    let status_line = String::from_utf8_lossy(&resp);
    if status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200") {
        Ok(tcp)
    } else {
        Err(())
    }
}

/// Resolve and connect entirely in the broker, pinning the selected
/// `SocketAddr` for the lifetime of the TCP connection.
fn resolve_and_connect(
    host: &str,
    port: u16,
    allow_cidrs: &[String],
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

    if let Some(proxy_url) = get_upstream_proxy(host, port) {
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

    let cidrs: Vec<IpCidr> = allow_cidrs
        .iter()
        .filter_map(|c| IpCidr::parse(c).ok())
        .collect();

    let any_forbidden = resolved.iter().any(|addr| {
        if is_doh_or_dot(host, port, Some(addr.ip())) {
            return true;
        }
        if cidrs.iter().any(|c| c.contains(addr.ip())) {
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
fn forbidden_destination(ip: IpAddr) -> bool {
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

const CMSG_SPACE_FD: usize = 32; // CMSG_SPACE(sizeof(int)) on 64-bit

fn create_and_send_data_fd(
    ctrl: &mut std::os::unix::net::UnixStream,
    tcp: TcpStream,
    host: &str,
    target_addr: SocketAddr,
    quota: Option<u64>,
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
    let Ok(unix_write) = mine.try_clone() else {
        return Ok(());
    };
    let Ok(tcp_read) = tcp.try_clone() else {
        return Ok(());
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

    let host_owned = host.to_string();
    let host_rx = host_owned.clone();
    let host_tx = host_owned.clone();
    let bus_rx = bus.clone();

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
                        if let Some(limit) = quota {
                            let total = get_domain_bytes(&host_rx) + total_rx + total_tx;
                            if total > limit {
                                quota_kill_rx.store(true, Ordering::Relaxed);
                                bus_rx.publish(Event::NetQuotaExceeded {
                                    ts: crate::events::types::now(),
                                    host: host_rx.clone(),
                                    limit_bytes: limit,
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
                if let Some(limit) = quota {
                    let total = get_domain_bytes(&host_tx) + total_rx + total_tx;
                    if total > limit {
                        quota_kill_tx.store(true, Ordering::Relaxed);
                        bus.publish(Event::NetQuotaExceeded {
                            ts: crate::events::types::now(),
                            host: host_tx.clone(),
                            limit_bytes: limit,
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

    Ok(())
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
        let guard = DebugPortGuard::new(DebugPortConfig::default());
        let config = BrokerConfig {
            policy: BrokerPolicy::Allowlist(vec!["127.0.0.1".into()]),
            debug_guard: Some(guard.clone()),
            mode: RelayMode::NetNs,
            allow_cidr: Vec::new(),
            quotas: std::collections::HashMap::new(),
        };

        // Blocked without token
        assert!(!request_allowed("127.0.0.1", 9222, None, &config));
        assert!(!request_allowed("127.0.0.1", 9229, None, &config));
        assert!(!request_allowed("127.0.0.1", 5678, None, &config));

        // Allowed with valid token
        let token = guard.session_token();
        assert!(request_allowed("127.0.0.1", 9222, Some(token), &config));
        assert!(request_allowed("127.0.0.1", 9229, Some(token), &config));
        assert!(request_allowed("127.0.0.1", 5678, Some(token), &config));

        // Allowed on other non-debug port
        assert!(request_allowed("127.0.0.1", 8080, None, &config));
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
}
