//! Best-effort kernel audit feed reader (Linux >= 6.12 landlock denials).
//!
//! Reality check: reading the audit stream requires privileges (auditd /
//! CAP_AUDIT_READ). An unprivileged vetto will USUALLY be unable to open it.
//! Probe at runtime; when unavailable, vetto shows a persistent notice and
//! enforcement remains ACTIVE regardless.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use crate::events::{bus::EventBus, Event};

pub const NETLINK_AUDIT: libc::c_int = 9;

/// Try to open the audit netlink feed. Err carries the honest reason.
pub fn open_audit_feed() -> Result<OwnedFd, String> {
    // SAFETY: scalar args only.
    let fd = unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_AUDIT)
    };
    if fd < 0 {
        return Err(format!(
            "audit netlink socket: {} (needs CAP_AUDIT_READ / auditd; kernel >= 6.12 for landlock denials)",
            std::io::Error::last_os_error()
        ));
    }
    #[repr(C)]
    struct SockAddrNl {
        nl_family: libc::sa_family_t,
        nl_pad: u16,
        nl_pid: u32,
        nl_groups: u32,
    }
    let addr = SockAddrNl {
        nl_family: libc::AF_NETLINK as libc::sa_family_t,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 1, // subscribe to the broadcast group
    };
    // SAFETY: valid fd + properly sized sockaddr.
    let r = unsafe {
        libc::bind(
            fd,
            &addr as *const SockAddrNl as *const libc::sockaddr,
            std::mem::size_of::<SockAddrNl>() as u32,
        )
    };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: plain close on our own descriptor.
        unsafe { libc::close(fd) };
        return Err(format!("audit bind: {err}"));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Spawn a reader thread if the feed is readable. Returns the reason it
/// could NOT be started otherwise (for the persistent notice).
pub fn spawn_reader_if_available(bus: EventBus) -> Option<String> {
    let fd = match open_audit_feed() {
        Ok(fd) => fd,
        Err(reason) => return Some(reason),
    };
    std::thread::Builder::new()
        .name("vetto-audit".into())
        .spawn(move || {
            let file = std::fs::File::from(fd);
            let mut reader = std::io::BufReader::new(file);
            use std::io::BufRead;
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let lower = line.to_ascii_lowercase();
                        if lower.contains("landlock") && lower.contains("denied") {
                            bus.publish(Event::BlockedAttempt {
                                ts: crate::events::types::now(),
                                pid: parse_audit_pid(&line),
                                comm: "?".into(),
                                path: extract_denied_path(&line).unwrap_or_default(),
                                source: "kernel-audit".into(),
                            });
                        }
                    }
                    Err(_) => break,
                }
            }
        })
        .expect("spawn audit reader");
    None
}

fn parse_audit_pid(line: &str) -> u32 {
    line.split_whitespace()
        .find_map(|f| f.strip_prefix("pid="))
        .and_then(|p| p.parse().ok())
        .unwrap_or(0)
}

fn extract_denied_path(line: &str) -> Option<String> {
    let idx = line.find("path=\"")? + 6;
    let rest = &line[idx..];
    Some(rest[..rest.find('"')?].to_string())
}
