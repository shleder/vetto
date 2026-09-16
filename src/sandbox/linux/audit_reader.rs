//! Best-effort kernel audit feed reader (Linux >= 6.12 landlock denials).
//!
//! Reality check: reading the audit stream requires privileges (auditd /
//! CAP_AUDIT_READ). An unprivileged vetto will USUALLY be unable to open it.
//! Probe at runtime; when unavailable, vetto shows a persistent notice and
//! enforcement remains ACTIVE regardless.
//!
//! Enforces INV-37 (Netlink Buffer Overflow & Disruption Detection):
//! Netlink socket buffer overflow errors (`ENOBUFS`, errno 105) and sequence
//! gap packet drops immediately flag the evidence channel as disrupted
//! (`evidence_channel_intact = false`), driving `VerdictEngine` to force an
//! `INCONCLUSIVE [STRONG]` verdict with Exit Code 125.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::events::{bus::EventBus, Event};

pub const NETLINK_AUDIT: libc::c_int = 9;

/// Linux Netlink buffer overflow errno (ENOBUFS = 105).
pub const ENOBUFS_CODE: i32 = 105;

/// Netlink message types.
#[allow(dead_code)]
pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
#[allow(dead_code)]
pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_OVERRUN: u16 = 4;

/// Linux netlink message header layout.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

/// Global atomic flag tracking evidence channel integrity (INV-37).
/// Defaults to true; switched to false upon Netlink ENOBUFS or dropped packets.
pub static EVIDENCE_CHANNEL_INTACT: AtomicBool = AtomicBool::new(true);
pub static BUFFER_OVERFLOW_COUNT: AtomicU64 = AtomicU64::new(0);
pub static PACKET_DROP_COUNT: AtomicU64 = AtomicU64::new(0);

/// Check if the evidence channel is intact (no drops, no buffer overflows).
pub fn is_evidence_channel_intact() -> bool {
    EVIDENCE_CHANNEL_INTACT.load(Ordering::SeqCst)
}

/// Flags the evidence channel as disrupted (INV-37 trigger).
pub fn mark_evidence_channel_disrupted() {
    EVIDENCE_CHANNEL_INTACT.store(false, Ordering::SeqCst);
}

/// Resets the evidence channel state and counters (for tests and session start).
pub fn reset_evidence_channel() {
    EVIDENCE_CHANNEL_INTACT.store(true, Ordering::SeqCst);
    BUFFER_OVERFLOW_COUNT.store(0, Ordering::SeqCst);
    PACKET_DROP_COUNT.store(0, Ordering::SeqCst);
}

/// Returns the number of detected Netlink buffer overflows (ENOBUFS / NLMSG_OVERRUN).
pub fn buffer_overflow_count() -> u64 {
    BUFFER_OVERFLOW_COUNT.load(Ordering::SeqCst)
}

/// Returns the number of detected packet drops.
pub fn packet_drop_count() -> u64 {
    PACKET_DROP_COUNT.load(Ordering::SeqCst)
}

/// Try to open the audit netlink feed. Err carries the honest reason.
pub fn open_audit_feed() -> Result<OwnedFd, String> {
    // SAFETY: scalar args only.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_AUDIT,
        )
    };
    if fd < 0 {
        return Err(format!(
            "audit netlink socket: {} (needs CAP_AUDIT_READ / auditd; kernel >= 6.12 for landlock denials)",
            std::io::Error::last_os_error()
        ));
    }
    // Set 4MB SO_RCVBUF to absorb burst traffic and prevent spurious ENOBUFS (INV-37).
    let rcvbuf: libc::c_int = 4 * 1024 * 1024;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
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

/// Processes a buffer of Netlink datagrams, iterating over composite messages
/// aligned to 4-byte boundaries (NLMSG_ALIGN). Fulfills INV-37.
pub fn process_netlink_buffer(
    bytes: &[u8],
    last_seq: &mut Option<u32>,
    bus: Option<&EventBus>,
) {
    let mut offset = 0;
    let hdr_size = std::mem::size_of::<NlMsgHdr>();

    while offset + hdr_size <= bytes.len() {
        let msg_bytes = &bytes[offset..];
        // Read unaligned to avoid UB across raw byte slices.
        let nlm: NlMsgHdr = unsafe {
            std::ptr::read_unaligned(msg_bytes.as_ptr() as *const NlMsgHdr)
        };
        let msg_len = nlm.nlmsg_len as usize;
        if msg_len < hdr_size || offset + msg_len > bytes.len() {
            break;
        }

        // 1. Sequence gap detection: packet drop
        if nlm.nlmsg_seq > 0 {
            if let Some(prev) = *last_seq {
                if nlm.nlmsg_seq > prev + 1 {
                    let dropped = (nlm.nlmsg_seq - prev - 1) as u64;
                    PACKET_DROP_COUNT.fetch_add(dropped, Ordering::SeqCst);
                    mark_evidence_channel_disrupted();
                    if let Some(bus) = bus {
                        bus.publish(Event::Notice {
                            ts: crate::events::types::now(),
                            message: format!(
                                "Netlink audit packet drop detected: seq gap from {} to {} (INV-37)",
                                prev, nlm.nlmsg_seq
                            ),
                        });
                    }
                }
            }
            *last_seq = Some(nlm.nlmsg_seq);
        }

        // 2. NLMSG_OVERRUN: kernel buffer overrun
        if nlm.nlmsg_type == NLMSG_OVERRUN {
            BUFFER_OVERFLOW_COUNT.fetch_add(1, Ordering::SeqCst);
            mark_evidence_channel_disrupted();
            if let Some(bus) = bus {
                bus.publish(Event::Notice {
                    ts: crate::events::types::now(),
                    message: "Netlink audit buffer overrun (NLMSG_OVERRUN): evidence channel disrupted (INV-37)".to_string(),
                });
            }
        }

        // 3. NLMSG_ERROR: check error payload for ENOBUFS
        if nlm.nlmsg_type == NLMSG_ERROR
            && msg_len >= hdr_size + std::mem::size_of::<libc::c_int>()
        {
            let err_code = unsafe {
                std::ptr::read_unaligned(
                    msg_bytes[hdr_size..].as_ptr() as *const libc::c_int,
                )
            };
            if err_code == -ENOBUFS_CODE
                || err_code == ENOBUFS_CODE
                || err_code == -libc::ENOBUFS
                || err_code == libc::ENOBUFS
            {
                BUFFER_OVERFLOW_COUNT.fetch_add(1, Ordering::SeqCst);
                mark_evidence_channel_disrupted();
                if let Some(bus) = bus {
                    bus.publish(Event::Notice {
                        ts: crate::events::types::now(),
                        message: "Netlink audit message error ENOBUFS: evidence channel disrupted (INV-37)".to_string(),
                    });
                }
            }
        }

        // 4. Extract audit text payload (strictly bounded within this message)
        if msg_len > hdr_size {
            let payload = &msg_bytes[hdr_size..msg_len];
            let text = String::from_utf8_lossy(payload);
            let lower = text.to_ascii_lowercase();
            if lower.contains("landlock") && lower.contains("denied") {
                if let Some(bus) = bus {
                    bus.publish(Event::BlockedAttempt {
                        ts: crate::events::types::now(),
                        pid: parse_audit_pid(&text),
                        comm: "?".into(),
                        path: extract_denied_path(&text).unwrap_or_default(),
                        source: "kernel-audit".into(),
                    });
                }
            }
        }

        if nlm.nlmsg_type == NLMSG_DONE {
            break;
        }

        // Advance offset aligned to 4 bytes (NLMSG_ALIGN)
        let aligned_len = (msg_len + 3) & !3;
        if aligned_len == 0 {
            break;
        }
        offset += aligned_len;
    }
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
            let raw_fd = fd.as_raw_fd();
            let mut buf = [0u8; 16384];
            let mut last_seq: Option<u32> = None;

            loop {
                let n = unsafe {
                    libc::recv(
                        raw_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    )
                };
                if n > 0 {
                    process_netlink_buffer(&buf[..n as usize], &mut last_seq, Some(&bus));
                } else if n == 0 {
                    // Socket closed
                    break;
                } else {
                    let err = std::io::Error::last_os_error();
                    let code = err.raw_os_error().unwrap_or(0);
                    if code == ENOBUFS_CODE || code == libc::ENOBUFS {
                        BUFFER_OVERFLOW_COUNT.fetch_add(1, Ordering::SeqCst);
                        mark_evidence_channel_disrupted();
                        bus.publish(Event::Notice {
                            ts: crate::events::types::now(),
                            message: "Netlink socket buffer overflow (ENOBUFS, errno 105): evidence channel disrupted (INV-37)".to_string(),
                        });
                        continue;
                    } else if code == libc::EINTR {
                        continue;
                    } else if code == libc::EAGAIN || code == libc::EWOULDBLOCK {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    } else {
                        break;
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_channel_lifecycle() {
        reset_evidence_channel();
        assert!(is_evidence_channel_intact());
        assert_eq!(buffer_overflow_count(), 0);
        assert_eq!(packet_drop_count(), 0);

        mark_evidence_channel_disrupted();
        assert!(!is_evidence_channel_intact());

        reset_evidence_channel();
        assert!(is_evidence_channel_intact());
    }

    #[test]
    fn test_enobufs_constant_matches_linux_errno() {
        assert_eq!(ENOBUFS_CODE, 105);
        assert_eq!(libc::ENOBUFS, 105);
    }

    #[test]
    fn test_parse_audit_pid() {
        let line = "type=LANDLOCK_DENIED msg=audit(1726488345.123:45): pid=4242 comm=\"bash\" path=\"/etc/shadow\"";
        assert_eq!(parse_audit_pid(line), 4242);
    }

    #[test]
    fn test_extract_denied_path() {
        let line = "type=LANDLOCK_DENIED msg=audit(1726488345.123:45): pid=4242 comm=\"bash\" path=\"/etc/shadow\"";
        assert_eq!(extract_denied_path(line), Some("/etc/shadow".to_string()));
    }

    #[test]
    fn test_process_netlink_buffer_composite_and_overflow() {
        reset_evidence_channel();
        let mut last_seq = None;

        let hdr_size = std::mem::size_of::<NlMsgHdr>();
        let mut buf = Vec::new();

        let hdr1 = NlMsgHdr {
            nlmsg_len: hdr_size as u32,
            nlmsg_type: NLMSG_NOOP,
            nlmsg_flags: 0,
            nlmsg_seq: 1,
            nlmsg_pid: 100,
        };
        let hdr1_bytes: [u8; std::mem::size_of::<NlMsgHdr>()] = unsafe { std::mem::transmute(hdr1) };
        buf.extend_from_slice(&hdr1_bytes);

        let hdr2 = NlMsgHdr {
            nlmsg_len: hdr_size as u32,
            nlmsg_type: NLMSG_OVERRUN,
            nlmsg_flags: 0,
            nlmsg_seq: 2,
            nlmsg_pid: 100,
        };
        let hdr2_bytes: [u8; std::mem::size_of::<NlMsgHdr>()] = unsafe { std::mem::transmute(hdr2) };
        buf.extend_from_slice(&hdr2_bytes);

        process_netlink_buffer(&buf, &mut last_seq, None);

        assert!(!is_evidence_channel_intact(), "NLMSG_OVERRUN in composite packet must disrupt channel");
        assert_eq!(buffer_overflow_count(), 1);
        assert_eq!(last_seq, Some(2));
    }

    #[test]
    fn test_process_netlink_buffer_sequence_gap() {
        reset_evidence_channel();
        let mut last_seq = None;
        let hdr_size = std::mem::size_of::<NlMsgHdr>();

        let hdr1 = NlMsgHdr {
            nlmsg_len: hdr_size as u32,
            nlmsg_type: NLMSG_NOOP,
            nlmsg_flags: 0,
            nlmsg_seq: 1,
            nlmsg_pid: 100,
        };
        let hdr1_bytes: [u8; std::mem::size_of::<NlMsgHdr>()] = unsafe { std::mem::transmute(hdr1) };
        process_netlink_buffer(&hdr1_bytes, &mut last_seq, None);
        assert!(is_evidence_channel_intact());
        assert_eq!(packet_drop_count(), 0);

        let hdr2 = NlMsgHdr {
            nlmsg_len: hdr_size as u32,
            nlmsg_type: NLMSG_NOOP,
            nlmsg_flags: 0,
            nlmsg_seq: 5,
            nlmsg_pid: 100,
        };
        let hdr2_bytes: [u8; std::mem::size_of::<NlMsgHdr>()] = unsafe { std::mem::transmute(hdr2) };
        process_netlink_buffer(&hdr2_bytes, &mut last_seq, None);

        assert!(!is_evidence_channel_intact());
        assert_eq!(packet_drop_count(), 3);
        assert_eq!(last_seq, Some(5));
    }

    #[test]
    fn test_process_netlink_buffer_enobufs_error() {
        reset_evidence_channel();
        let mut last_seq = None;
        let hdr_size = std::mem::size_of::<NlMsgHdr>();
        let err_size = std::mem::size_of::<libc::c_int>();

        let hdr = NlMsgHdr {
            nlmsg_len: (hdr_size + err_size) as u32,
            nlmsg_type: NLMSG_ERROR,
            nlmsg_flags: 0,
            nlmsg_seq: 1,
            nlmsg_pid: 100,
        };
        let mut buf = Vec::new();
        let hdr_bytes: [u8; std::mem::size_of::<NlMsgHdr>()] = unsafe { std::mem::transmute(hdr) };
        buf.extend_from_slice(&hdr_bytes);
        let err_code: libc::c_int = -ENOBUFS_CODE;
        let err_bytes: [u8; std::mem::size_of::<libc::c_int>()] = unsafe { std::mem::transmute(err_code) };
        buf.extend_from_slice(&err_bytes);

        process_netlink_buffer(&buf, &mut last_seq, None);

        assert!(!is_evidence_channel_intact());
        assert_eq!(buffer_overflow_count(), 1);
    }
}
