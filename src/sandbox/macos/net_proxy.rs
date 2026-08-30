#![cfg(target_os = "macos")]

//! macOS local broker/proxy primitives for pinned outbound connections.
//!
//! DNS resolution happens in the broker process, not in the sandboxed child.
//! Every permitted connection stores the resulting `SocketAddr` and connects
//! to that address directly, preventing a second resolver lookup at connect
//! time.  Private, loopback, link-local, metadata, documentation, and NAT64
//! translation addresses are rejected for both IPv4 and IPv6.  This module is
//! a TCP pass-through helper: it never performs TLS MITM or certificate
//! substitution.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::config::NetMode;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedConnection {
    host: String,
    port: u16,
    addr: SocketAddr,
}

impl PinnedConnection {
    /// Connect to the already-pinned address.  No hostname is passed to the
    /// socket API, so DNS cannot be re-resolved after policy authorization.
    pub fn connect(&self, timeout: Option<Duration>) -> io::Result<TcpStream> {
        if self.port == 0 || self.addr.port() != self.port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pinned connection port does not match its SocketAddr",
            ));
        }
        if normalize_host(&self.host).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid pinned host",
            ));
        }
        validate_public_addr(self.addr.ip())
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
        let stream = match timeout {
            Some(timeout) => TcpStream::connect_timeout(&self.addr, timeout)?,
            None => TcpStream::connect(self.addr)?,
        };
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }
}

#[derive(Clone, Debug)]
pub struct BrokerPolicy {
    mode: NetMode,
    bind: SocketAddr,
}

impl BrokerPolicy {
    pub fn new(mode: NetMode, bind: SocketAddr) -> Result<Self> {
        if !is_loopback(bind.ip()) {
            bail!("local broker must bind to loopback, not {}", bind.ip());
        }
        if matches!(&mode, &NetMode::Off) {
            bail!("a broker policy cannot be constructed for --net=off");
        }
        Ok(Self { mode, bind })
    }

    pub fn authorize(&self, host: &str, port: u16, addr: SocketAddr) -> Result<PinnedConnection> {
        let host = normalize_host(host)?;
        if port == 0 || addr.port() != port {
            bail!("pinned endpoint port does not match the requested port");
        }
        validate_public_addr(addr.ip())?;
        match &self.mode {
            NetMode::Off => bail!("network policy is off"),
            NetMode::Allowlist(domains) => {
                if !domains.iter().any(|domain| host_matches(&host, domain)) {
                    bail!("host {host:?} is not in the broker allowlist");
                }
            }
            NetMode::Strict(rules) => {
                if !rules
                    .iter()
                    .any(|rule| rule.port == port && host_matches(&host, &rule.domain))
                {
                    bail!("host {host:?}:{port} is not in the strict broker policy");
                }
            }
            NetMode::Ask => {}
        }
        Ok(PinnedConnection { host, port, addr })
    }

    /// Resolve and authorize in the broker.  The returned addresses are the
    /// only addresses this policy permits the caller to connect to.
    pub fn resolve(&self, host: &str, port: u16) -> Result<Vec<PinnedConnection>> {
        let normalized = normalize_host(host)?;
        if port == 0 {
            bail!("port 0 is not a connectable broker target");
        }
        let mut addresses = (normalized.as_str(), port)
            .to_socket_addrs()
            .with_context(|| format!("resolve {normalized}:{port} in broker"))?
            .collect::<Vec<_>>();
        addresses.sort();
        addresses.dedup();
        if addresses.is_empty() {
            bail!("resolver returned no addresses for {normalized}:{port}");
        }
        if addresses.len() > 1024 {
            bail!("resolver returned too many addresses for {normalized}:{port}");
        }
        let mut pinned = Vec::with_capacity(addresses.len());
        for addr in addresses {
            pinned.push(self.authorize(&normalized, port, addr)?);
        }
        Ok(pinned)
    }

    pub fn mode(&self) -> &NetMode {
        &self.mode
    }

    pub const fn bind_addr(&self) -> SocketAddr {
        self.bind
    }
}

/// A loopback listener owned by the broker.  It does not proxy transparently
/// by itself; callers accept child connections and use `BrokerPolicy::resolve`
/// plus `PinnedConnection::connect` for the outbound side.
pub struct LocalBroker {
    listener: TcpListener,
    policy: BrokerPolicy,
}

impl std::fmt::Debug for LocalBroker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalBroker")
            .field("local_addr", &self.listener.local_addr().ok())
            .field("policy", &self.policy)
            .field("tls", &"passthrough; no MITM")
            .finish()
    }
}

impl LocalBroker {
    pub fn bind(policy: BrokerPolicy) -> Result<Self> {
        let listener = TcpListener::bind(policy.bind)
            .with_context(|| format!("bind local broker at {}", policy.bind))?;
        let bound = listener.local_addr()?;
        if !is_loopback(bound.ip()) {
            bail!("OS returned a non-loopback broker address {bound}");
        }
        Ok(Self { listener, policy })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.listener.accept()
    }

    pub fn policy(&self) -> &BrokerPolicy {
        &self.policy
    }

    pub const fn tls_mode() -> &'static str {
        "TLS pass-through only; no certificate interception or MITM"
    }
}

pub fn validate_public_addr(addr: IpAddr) -> Result<()> {
    if is_restricted_addr(addr) {
        bail!("refusing private, loopback, metadata, documentation, or NAT64 address {addr}");
    }
    Ok(())
}

fn normalize_host(host: &str) -> Result<String> {
    if host.is_empty() || host.contains('\0') || host.chars().any(char::is_whitespace) {
        bail!("host is empty, contains NUL, or contains whitespace");
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.contains('@') || host.contains('/') || host.contains('\\') {
        bail!("host contains unsupported URL/userinfo syntax");
    }
    if host.len() > 253 || host.parse::<IpAddr>().is_ok() || !host.is_ascii() {
        bail!("host must be an ASCII DNS name, not an IP literal");
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|character| character.is_ascii_alphanumeric() || character == b'-')
        {
            bail!("host contains an invalid DNS label");
        }
    }
    Ok(host)
}

fn host_matches(host: &str, configured: &str) -> bool {
    let Ok(configured) = normalize_host(configured) else {
        return false;
    };
    host == configured || host.ends_with(&format!(".{configured}"))
}

fn is_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(value) => value.is_loopback(),
        IpAddr::V6(value) => value.is_loopback(),
    }
}

fn is_restricted_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(value) => is_restricted_v4(value),
        IpAddr::V6(value) => is_restricted_v6(value),
    }
}

fn is_restricted_v4(value: Ipv4Addr) -> bool {
    let octets = value.octets();
    let first = octets[0];
    let second = octets[1];
    let third = octets[2];
    let fourth = octets[3];
    value.is_unspecified()
        || value.is_loopback()
        || value.is_private()
        || value.is_link_local()
        || value.is_multicast()
        || value.is_broadcast()
        || (first == 0)
        || (first == 100 && (64..=127).contains(&second)) // RFC 6598 CGNAT
        || (first == 169 && second == 254) // link-local and cloud metadata
        || (first == 192 && second == 0 && third == 0) // IETF protocol assignments
        || (first == 192 && second == 0 && third == 2) // TEST-NET-1
        || (first == 198 && second == 18) // benchmarking
        || (first == 198 && second == 19)
        || (first == 198 && second == 51 && third == 100) // TEST-NET-2
        || (first == 203 && second == 0 && third == 113) // TEST-NET-3
        || (first == 192 && second == 88 && third == 99) // 6to4 anycast
        || (first == 169 && second == 254 && third == 169 && fourth == 254)
}

fn is_restricted_v6(value: Ipv6Addr) -> bool {
    let segments = value.segments();
    let mapped_v4 = if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        Some(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        ))
    } else if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        // IPv4-compatible and IPv4-translated forms should not bypass the
        // IPv4 policy by arriving as IPv6 literals.
        Some(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        ))
    } else {
        None
    };
    value.is_unspecified()
        || value.is_loopback()
        || value.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00 // ULA/private
        || (segments[0] & 0xffc0) == 0xfe80 // link-local
        || segments[0] == 0x2001 && segments[1] == 0x0db8 // documentation
        || (segments[0] == 0x0064 && segments[1] == 0xff9b) // RFC 6052 NAT64
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1)
        || mapped_v4.is_some_and(is_restricted_v4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_metadata_and_nat64_are_rejected() {
        for address in [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V6("fd00::1".parse().unwrap()),
            IpAddr::V6("64:ff9b::c000:0201".parse().unwrap()),
        ] {
            assert!(validate_public_addr(address).is_err(), "{address}");
        }
    }

    #[test]
    fn policy_pins_the_supplied_socket_address() {
        let policy = BrokerPolicy::new(
            NetMode::Strict(vec![crate::config::NetRule {
                domain: "example.com".into(),
                port: 443,
            }]),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let pinned = policy
            .authorize("example.com", 443, "93.184.216.34:443".parse().unwrap())
            .unwrap();
        assert_eq!(pinned.addr(), "93.184.216.34:443".parse().unwrap());
        assert_eq!(
            LocalBroker::tls_mode(),
            "TLS pass-through only; no certificate interception or MITM"
        );
    }
}
