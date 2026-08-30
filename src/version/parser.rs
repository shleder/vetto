//! SemVer parsing and npm registry response extraction.

use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub prerelease: Option<String>,
}

impl SemVer {
    pub fn parse(s: &str) -> Option<Self> {
        let clean = s.trim().strip_prefix('v').unwrap_or(s.trim());
        let (ver_part, prerelease) = match clean.split_once('-') {
            Some((v, pre)) => (v, Some(pre.to_string())),
            None => (clean, None),
        };

        let parts: Vec<&str> = ver_part.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let major = parts[0].parse::<u64>().ok()?;
        let minor = parts[1].parse::<u64>().ok()?;
        let patch = parts[2].parse::<u64>().ok()?;

        Some(Self {
            major,
            minor,
            patch,
            prerelease,
        })
    }

    pub fn is_newer_than(&self, other: &Self) -> bool {
        match (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch)) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => match (&self.prerelease, &other.prerelease) {
                // Release is newer than pre-release for identical (major, minor, patch)
                (None, Some(_)) => true,
                (Some(_), None) => false,
                (None, None) => false,
                (Some(a), Some(b)) => a > b,
            },
        }
    }
}

/// Extracts the target version string for the requested channel from npm registry response.
///
/// Handles both direct version objects `{"version": "0.2.6"}` and full package manifests
/// with `{"dist-tags": {"latest": "0.2.6", "alpha": "0.2.7-alpha.1"}}`.
pub fn parse_registry_version(json_str: &str, channel: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(json_str).ok()?;

    // 1. Check if dist-tags is present
    if let Some(dist_tags) = val.get("dist-tags").and_then(|v| v.as_object()) {
        let tag_key = match channel {
            "alpha" => "alpha",
            _ => "latest",
        };
        if let Some(ver) = dist_tags.get(tag_key).and_then(|v| v.as_str()) {
            return Some(ver.to_string());
        }
        // Fallback to latest if requested tag not found
        if let Some(ver) = dist_tags.get("latest").and_then(|v| v.as_str()) {
            return Some(ver.to_string());
        }
    }

    // 2. Direct version field (e.g. from /latest endpoint)
    if let Some(ver) = val.get("version").and_then(|v| v.as_str()) {
        return Some(ver.to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_parsing_and_comparison() {
        let v025 = SemVer::parse("0.2.5").unwrap();
        let v026 = SemVer::parse("v0.2.6").unwrap();
        let v026_alpha = SemVer::parse("0.2.6-alpha.1").unwrap();
        let v026_alpha2 = SemVer::parse("0.2.6-alpha.2").unwrap();

        assert!(v026.is_newer_than(&v025));
        assert!(!v025.is_newer_than(&v026));
        assert!(!v025.is_newer_than(&v025));

        assert!(v026.is_newer_than(&v026_alpha));
        assert!(v026_alpha2.is_newer_than(&v026_alpha));
        assert!(v026_alpha.is_newer_than(&v025));
    }

    #[test]
    fn parse_registry_response_dist_tags() {
        let json = r#"{
            "name": "@shledery/vetto",
            "dist-tags": {
                "latest": "0.2.6",
                "alpha": "0.2.7-alpha.1"
            }
        }"#;

        assert_eq!(
            parse_registry_version(json, "stable").as_deref(),
            Some("0.2.6")
        );
        assert_eq!(
            parse_registry_version(json, "alpha").as_deref(),
            Some("0.2.7-alpha.1")
        );
    }

    #[test]
    fn parse_registry_response_direct_version() {
        let json = r#"{"version": "0.2.6"}"#;
        assert_eq!(
            parse_registry_version(json, "stable").as_deref(),
            Some("0.2.6")
        );
    }

    #[test]
    fn parse_registry_response_invalid_json() {
        assert_eq!(parse_registry_version("not json", "stable"), None);
    }
}
