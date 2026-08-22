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
//! The child NEVER resolves DNS (`/etc/resolv.conf` is blackholed) and has
//! no route except loopback + inherited unix fds, so anything non-proxy-aware
//! fails closed. No TLS decryption, no CA injection, no SNI parsing — ever.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::Mutex;

use crate::events::{bus::EventBus, Event};
use crate::error::{VettoError, VettoResult};

pub const RELAY_PORT_BASE: u16 = 47129;

// ---------------------------------------------------------------------------
// Host side: the broker.
// ---------------------------------------------------------------------------

/// Spawn the broker thread owning `broker_fd` (its end of the control
/// socketpair whose other end lives inside the sandbox).
pub fn spawn_broker(broker_fd: RawFd, allowlist: Vec<String>, bus: EventBus) {
    std::thread::Builder::new()
        .name("vetto-broker".into())
        .spawn(move || {
            // SAFETY: broker_fd is an owned socketpair end created pre-fork.
            let mut ctrl = unsafe { std::os::unix::net::UnixStream::from_raw_fd(broker_fd) };
            let _ = ctrl.set_read_timeout(Some(std::time::Duration::from_secs(300)));
            loop {
                let Some(req) = read_framed_request(&mut ctrl) else {
                    break; // relay gone => session ended
                };
                let allowed = domain_allowed(&req.host, &allowlist);
                bus.publish(Event::NetRequest {
                    ts: crate::events::types::now(),
                    host: req.host.clone(),
                    port: req.port,
                    allowed,
                });
                if !allowed {
                    if ctrl.write_all(b"D").is_err() {
                        break;
                    }
                    continue;
                }
                let target = format!("{}:{}", req.host.trim_end_matches('.'), req.port);
                match resolve_and_connect(&target) {
                    Ok(tcp) => {
                        if create_and_send_data_fd(&mut ctrl, tcp).is_err() && ctrl.write_all(b"X").is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        if ctrl.write_all(b"X").is_err() {
                            break;
                        }
                    }
                }
            }
        })
        .expect("spawn vetto-broker thread");
}

#[derive(serde::Deserialize)]
struct RelayReq {
    host: String,
    port: u16,
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

/// Allowlist semantics: exact match, or subdomain of an entry
/// (`example.com` matches `api.example.com`, not `notexample.com`).
fn domain_allowed(host: &str, allowlist: &[String]) -> bool {
    let host = host.trim().to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    allowlist
        .iter()
        .any(|pat| pat == host || host.ends_with(&format!(".{pat}")))
}

fn resolve_and_connect(target: &str) -> Result<TcpStream, ()> {
    use std::net::ToSocketAddrs;
    let addrs = target.to_socket_addrs().map_err(|_| ())?.collect::<Vec<_>>();
    for addr in addrs {
        if let Ok(s) = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10)) {
            return Ok(s);
        }
    }
    Err(())
}

const CMSG_SPACE_FD: usize = 32; // CMSG_SPACE(sizeof(int)) on 64-bit

fn create_and_send_data_fd(
    ctrl: &mut std::os::unix::net::UnixStream,
    tcp: TcpStream,
) -> Result<(), ()> {
    let Some((mine, theirs)) = socketpair_stream().ok() else {
        return Err(());
    };
    // Reply status first, then the fd.
    if ctrl.write_all(b"O").is_err() || send_fd(ctrl.as_raw_fd(), theirs.as_raw_fd()).is_err() {
        return Err(()); // drops close both ends => tunnel torn down
    }
    drop(theirs);

    // Pump both directions between our end and the outbound TCP connection.
    let mine_rev = match mine.try_clone() {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    let tcp_rev = match tcp.try_clone() {
        Ok(t) => t,
        Err(_) => return Ok(()),
    };
    let fwd = std::thread::Builder::new()
        .name("broker-fwd".into())
        .spawn(move || {
            let mut m = mine_rev;
            let _ = std::io::copy(&mut m, &mut { tcp_rev });
            shutdown_write(m.as_raw_fd());
        })
        .ok();
    let mut mine_fwd = mine;
    let mut tcp_fwd = tcp;
    let _ = std::io::copy(&mut mine_fwd, &mut tcp_fwd);
    shutdown_write(mine_fwd.as_raw_fd());
    if let Some(h) = fwd {
        let _ = h.join();
    }
    Ok(())
}

fn shutdown_write(fd: RawFd) {
    // SAFETY: scalar-only call on an owned descriptor.
    unsafe { libc::shutdown(fd, libc::SHUT_WR) };
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
    Ok((
        unsafe { OwnedFd::from_raw_fd(fds[0]) },
        unsafe { OwnedFd::from_raw_fd(fds[1]) },
    ))
}

/// sendmsg(2) carrying one fd in SCM_RIGHTS over `sock`.
fn send_fd(sock: RawFd, fd_to_send: RawFd) -> Result<(), ()> {
    #[repr(C)]
    struct CmsghdrAligned {
        hdr: libc::cmsghdr,
        data: libc::c_int,
        pad: [u8; 16],
    }
    let mut cmsg = CmsghdrAligned {
        hdr: libc::cmsghdr {
            cmsg_len: std::mem::size_of::<libc::cmsghdr>()
                + std::mem::size_of::<libc::c_int>(),
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
        msg_controllen: std::mem::size_of::<libc::cmsghdr>()
            + std::mem::size_of::<libc::c_int>(),
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
fn recv_fd(sock: RawFd) -> Result<OwnedFd, ()> {
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
    let fd_bytes = [control[hdr_len], control[hdr_len + 1], control[hdr_len + 2], control[hdr_len + 3]];
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
        socks5_handshake(&mut client, first[0])
    } else {
        http_connect_head(&mut client, first[0])
    };

    let Some((host, port)) = target else { return };

    let outcome = {
        let _guard = SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        send_request_frame(ctrl_fd, &host, port)
            .and_then(|_| read_status_and_fd(ctrl_fd))
    };

    match outcome {
        Ok(data_fd) => {
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

type Target = Option<(String, u16)>;

/// Parse an HTTP CONNECT request head (first byte already consumed).
fn http_connect_head(stream: &mut TcpStream, first: u8) -> Target {
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
    let request_line = head.lines().next()?;
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
    Some((host.to_ascii_lowercase(), port))
}

/// Minimal socks5h server-side handshake (no-auth only, CONNECT only).
fn socks5_handshake(stream: &mut TcpStream, first: u8) -> Target {
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

fn send_request_frame(ctrl_fd: RawFd, host: &str, port: u16) -> Result<(), bool> {
    let body = serde_json::json!({ "host": host, "port": port }).to_string();
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
fn pump(a: TcpStream, data_fd: OwnedFd) {
    // SAFETY: owned fd from recv_fd.
    let unix_side = unsafe { std::os::unix::net::UnixStream::from_raw_fd(data_fd.into_raw_fd()) };
    let unix_a = unix_side.try_clone();
    let tcp_b = a.try_clone();
    let (Ok(unix_a), Ok(tcp_b)) = (unix_a, tcp_b) else {
        return;
    };
    let rev = std::thread::spawn(move || {
        let _ = std::io::copy(&mut { unix_a }, &mut { a });
    });
    let _ = std::io::copy(&mut { unix_side }, &mut { tcp_b });
    let _ = rev.join();
}

pub fn build_proxy_env(port: u16) -> Vec<(String, String)> {
    let url = format!("http://127.0.0.1:{port}");
    [
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "http_proxy", "https_proxy", "all_proxy",
    ]
    .into_iter()
    .map(|k| (k.to_string(), url.clone()))
    .chain([("NO_PROXY".to_string(), String::new()), ("no_proxy".to_string(), String::new())])
    .collect()
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
