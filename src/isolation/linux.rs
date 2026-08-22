#![allow(dead_code)]

/// Planned Linux sandbox built from namespaces + seccomp.
pub struct LinuxIsolation {
    namespaces: Vec<&'static str>,
}

impl LinuxIsolation {
    pub fn new() -> Self {
        Self {
            namespaces: vec!["pid", "net", "mnt", "ipc", "uts"],
        }
    }

    pub fn plan(&self) -> &[&'static str] {
        &self.namespaces
    }
}
