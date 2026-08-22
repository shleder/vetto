//! Platform isolation backends. Each supported target gets its own module.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;
