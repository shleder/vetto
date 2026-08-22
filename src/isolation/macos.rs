#![allow(dead_code)]

/// Planned macOS sandbox backed by sandbox-exec profiles.
pub struct MacIsolation {
    profile: &'static str,
}

impl MacIsolation {
    pub fn new() -> Self {
        Self {
            profile: "(version 1)(allow default)",
        }
    }

    pub fn profile(&self) -> &'static str {
        self.profile
    }
}
