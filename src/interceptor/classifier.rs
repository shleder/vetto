#![allow(dead_code)]

use crate::events::types::SyscallEvent;

/// Verdict assigned to an intercepted syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    Blocked,
    Suspicious,
}

/// Maps intercepted syscalls to verdicts based on the active policy.
pub struct Classifier;

impl Classifier {
    pub fn new() -> Self {
        Self
    }

    pub fn classify(&self, syscall: &str, _event: &SyscallEvent) -> Verdict {
        match syscall {
            "execve" | "ptrace" | "mount" | "unshare" | "bpf" => Verdict::Blocked,
            "connect" | "socket" | "openat2" => Verdict::Suspicious,
            _ => Verdict::Allowed,
        }
    }
}
