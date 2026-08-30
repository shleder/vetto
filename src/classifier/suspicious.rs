//! Best-effort suspicious-pattern classification for audit visibility.
//!
//! This module never participates in enforcement. A signal can be a false
//! positive and the observation feed can miss activity; the sandbox policy
//! remains the only security boundary.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::Serialize;

use crate::events::Event;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspicionSeverity {
    Advisory,
    Warning,
    High,
}

impl SuspicionSeverity {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::Warning => "warning",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspiciousSignal {
    pub category: &'static str,
    pub severity: SuspicionSeverity,
    pub subject: String,
    pub reason: &'static str,
}

/// Classify one observed event. Results are audit hints, never policy
/// decisions, and callers must label them as best-effort.
pub fn classify_event(event: &Event) -> Option<SuspiciousSignal> {
    match event {
        Event::FileObserved { path, .. } | Event::BlockedAttempt { path, .. } => {
            classify_path(path)
        }
        Event::ExecObserved { argv, .. } => classify_exec(argv),
        Event::NetRequest { host, port, .. } => classify_network(host, *port),
        Event::SessionStarted { .. }
        | Event::SecretMasked { .. }
        | Event::Notice { .. }
        | Event::SessionTimeout { .. }
        | Event::DnsResolved { .. }
        | Event::NetEgress { .. }
        | Event::NetQuotaExceeded { .. }
        | Event::SessionEnded { .. } => None,
    }
}

fn classify_path(path: &str) -> Option<SuspiciousSignal> {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let components: Vec<&str> = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let basename = components.last().copied().unwrap_or_default();
    let sensitive_directory = components.iter().any(|component| {
        matches!(
            *component,
            ".ssh" | ".aws" | ".gnupg" | ".kube" | ".npmrc" | ".netrc" | ".git-credentials"
        )
    }) || components
        .windows(2)
        .any(|pair| matches!(pair, [".config", "gcloud"] | [".config", "github-copilot"]));
    let sensitive = basename == ".env"
        || basename.starts_with(".env.")
        || matches!(basename, ".git-credentials" | ".netrc" | ".npmrc")
        || sensitive_directory
        || ["pem", "key", "p12", "pfx", "kdbx"]
            .iter()
            .any(|ext| basename.rsplit_once('.').map(|(_, value)| value) == Some(*ext));
    if sensitive {
        return Some(SuspiciousSignal {
            category: "credential_path_access",
            severity: SuspicionSeverity::High,
            subject: path.to_string(),
            reason: "access to a credential-shaped path was observed",
        });
    }

    let proc_component = components.first().copied() == Some("proc")
        && components
            .iter()
            .skip(2)
            .any(|component| matches!(*component, "mem" | "fd" | "map_files" | "syscall"));
    let device_memory =
        components.starts_with(&["dev", "mem"]) || components.starts_with(&["dev", "kmem"]);
    if proc_component || device_memory {
        return Some(SuspiciousSignal {
            category: "process_memory_access",
            severity: SuspicionSeverity::High,
            subject: path.to_string(),
            reason: "access to process or kernel memory surfaces was observed",
        });
    }

    let is_socket =
        basename.ends_with(".sock") || basename.ends_with(".socket") || basename.ends_with(".ipc");
    let is_agent_ipc = is_socket
        && (basename.contains("codex")
            || basename.contains("claude")
            || basename.contains("cursor")
            || basename.contains("vscode")
            || basename.contains("agent"));
    let is_session_db = (basename.starts_with("state_") && basename.ends_with(".sqlite"))
        || (components.iter().any(|c| *c == ".codex" || *c == ".claude")
            && basename.ends_with(".sqlite"));
    if is_agent_ipc || is_session_db {
        return Some(SuspiciousSignal {
            category: "subagent_control_plane_tampering",
            severity: SuspicionSeverity::High,
            subject: path.to_string(),
            reason:
                "access to agent control plane IPC socket or session state database was observed",
        });
    }

    let is_dump = basename.starts_with("core.")
        || ["hprof", "heapsnapshot", "dump"]
            .iter()
            .any(|ext| basename.rsplit_once('.').map(|(_, value)| value) == Some(*ext));
    if is_dump {
        return Some(SuspiciousSignal {
            category: "heavy_payload_dump_observed",
            severity: SuspicionSeverity::Warning,
            subject: path.to_string(),
            reason: "creation or reading of large unconstrained dump files was observed",
        });
    }

    None
}

fn classify_exec(argv: &[String]) -> Option<SuspiciousSignal> {
    let program = argv.first()?;
    let name = Path::new(program)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(program)
        .to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "sudo" | "su" | "mount" | "umount" | "umount2" | "nsenter" | "unshare" | "gdb"
    ) {
        return Some(SuspiciousSignal {
            category: "process_manipulation_tool",
            severity: SuspicionSeverity::Advisory,
            subject: program.clone(),
            reason: "a process or namespace manipulation tool was executed",
        });
    }
    if matches!(
        name.as_str(),
        "socat" | "nc" | "ncat" | "netcat" | "chisel" | "ngrok" | "cloudflared" | "tcpdump"
    ) {
        return Some(SuspiciousSignal {
            category: "tunneling_or_interception_tool",
            severity: SuspicionSeverity::High,
            subject: program.clone(),
            reason: "a network tunneling, interception or raw socket tool was executed",
        });
    }
    None
}

fn classify_network(host: &str, port: u16) -> Option<SuspiciousSignal> {
    if port == 9222 || port == 9229 || port == 5678 {
        return Some(SuspiciousSignal {
            category: "subagent_debug_port_probe",
            severity: SuspicionSeverity::High,
            subject: format!("{host}:{port}"),
            reason: "a browser devtools or debugger runtime port was requested",
        });
    }

    let host_without_brackets = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    let host_without_zone = host_without_brackets
        .split_once('%')
        .map_or(host_without_brackets, |(address, _)| address);
    let metadata_name = matches!(
        host_without_brackets.to_ascii_lowercase().as_str(),
        "metadata.google.internal" | "instance-data" | "metadata.azure.internal"
    );
    let special_ip = host_without_zone
        .parse::<IpAddr>()
        .is_ok_and(is_non_public_or_metadata);
    if metadata_name || special_ip {
        return Some(SuspiciousSignal {
            category: "non_public_network_target",
            severity: SuspicionSeverity::High,
            subject: format!("{host}:{port}"),
            reason: "a private, local, link-local, or metadata endpoint was requested",
        });
    }
    None
}

fn is_non_public_or_metadata(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_non_public_v4(ip),
        IpAddr::V6(ip) => is_non_public_v6(ip),
    }
}

fn is_non_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
        || (a == 255 && b == 255 && c == 255 && d == 255)
}

fn is_non_public_v6(ip: Ipv6Addr) -> bool {
    let octets = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || (octets[0] & 0xfe) == 0xfc
        || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
        || octets[0] == 0xff
        || ip.to_ipv4_mapped().is_some_and(is_non_public_v4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{types::now, FileAccess};

    #[test]
    fn credential_and_process_memory_paths_are_signalled() {
        let credential = Event::FileObserved {
            ts: now(),
            pid: 1,
            comm: "agent".into(),
            path: "/home/user/.ssh/id_ed25519".into(),
            access: FileAccess::Read,
        };
        assert_eq!(
            classify_event(&credential).unwrap().category,
            "credential_path_access"
        );

        let memory = Event::BlockedAttempt {
            ts: now(),
            pid: 2,
            comm: "agent".into(),
            path: "/proc/123/mem".into(),
            source: "landlock".into(),
        };
        assert_eq!(
            classify_event(&memory).unwrap().category,
            "process_memory_access"
        );

        let ipc = Event::FileObserved {
            ts: now(),
            pid: 3,
            comm: "agent".into(),
            path: "/tmp/codex_app.sock".into(),
            access: FileAccess::Read,
        };
        assert_eq!(
            classify_event(&ipc).unwrap().category,
            "subagent_control_plane_tampering"
        );

        for path in [
            "/home/user/.ssh",
            "/home/user/.config/gcloud",
            r"C:\Users\user\.AWS\credentials",
            "/proc/123/fd",
            "/dev/mem/device",
            "/tmp/vscode-ipc-123.sock",
            "/home/user/.codex/state_5.sqlite",
            "/home/user/app.heapsnapshot",
        ] {
            assert!(classify_path(path).is_some(), "missed {path}");
        }
    }

    #[test]
    fn private_and_metadata_targets_are_signalled() {
        for host in [
            "169.254.169.254",
            "10.1.2.3",
            "fc00::1",
            "metadata.google.internal.",
            "[fe80::1%eth0]",
            "198.51.100.7",
        ] {
            let event = Event::NetRequest {
                ts: now(),
                host: host.into(),
                port: 80,
                allowed: false,
            };
            assert!(classify_event(&event).is_some(), "missed {host}");
        }
        let public = Event::NetRequest {
            ts: now(),
            host: "example.com".into(),
            port: 443,
            allowed: true,
        };
        assert!(classify_event(&public).is_none());

        let debug_port = Event::NetRequest {
            ts: now(),
            host: "127.0.0.1".into(),
            port: 9222,
            allowed: false,
        };
        assert_eq!(
            classify_event(&debug_port).unwrap().category,
            "subagent_debug_port_probe"
        );
    }

    #[test]
    fn shell_execution_is_not_flagged_by_name_alone() {
        let event = Event::ExecObserved {
            ts: now(),
            pid: 1,
            argv: vec!["/bin/sh".into(), "-c".into(), "build".into()],
        };
        assert!(classify_event(&event).is_none());

        let tunnel = Event::ExecObserved {
            ts: now(),
            pid: 2,
            argv: vec!["/usr/bin/socat".into()],
        };
        assert_eq!(
            classify_event(&tunnel).unwrap().category,
            "tunneling_or_interception_tool"
        );
    }
}
