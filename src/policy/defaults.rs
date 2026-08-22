//! Built-in profiles, embedded at compile time from /profiles.

pub const DEFAULT_TOML: &str = include_str!("../../profiles/default.toml");
pub const STRICT_TOML: &str = include_str!("../../profiles/strict.toml");
pub const AUDIT_TOML: &str = include_str!("../../profiles/audit.toml");
pub const PERMISSIVE_TOML: &str = include_str!("../../profiles/permissive.toml");

pub const PROFILE_NAMES: [&str; 4] = ["default", "strict", "audit", "permissive"];

pub fn builtin(name: &str) -> Option<&'static str> {
    match name {
        "default" => Some(DEFAULT_TOML),
        "strict" => Some(STRICT_TOML),
        "audit" => Some(AUDIT_TOML),
        "permissive" => Some(PERMISSIVE_TOML),
        _ => None,
    }
}
