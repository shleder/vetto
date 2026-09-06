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
        // SemVer 2.0: build metadata (+...) MUST be ignored in precedence
        let (ver_and_pre, _build) = match clean.split_once('+') {
            Some((vp, b)) => (vp, Some(b)),
            None => (clean, None),
        };
        let (ver_part, prerelease) = match ver_and_pre.split_once('-') {
            Some((v, pre)) => (v, Some(pre.to_string())),
            None => (ver_and_pre, None),
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
                (Some(a), Some(b)) => compare_prerelease(a, b) == Ordering::Greater,
            },
        }
    }
}

fn compare_prerelease(a: &str, b: &str) -> Ordering {
    let a_parts: Vec<&str> = a.split('.').collect();
    let b_parts: Vec<&str> = b.split('.').collect();

    for (pa, pb) in a_parts.iter().zip(b_parts.iter()) {
        if pa == pb {
            continue;
        }
        match (pa.parse::<u64>(), pb.parse::<u64>()) {
            (Ok(num_a), Ok(num_b)) => {
                let cmp = num_a.cmp(&num_b);
                if cmp != Ordering::Equal {
                    return cmp;
                }
            }
            (Ok(_), Err(_)) => return Ordering::Less,
            (Err(_), Ok(_)) => return Ordering::Greater,
            (Err(_), Err(_)) => {
                let cmp = pa.cmp(pb);
                if cmp != Ordering::Equal {
                    return cmp;
                }
            }
        }
    }
    a_parts.len().cmp(&b_parts.len())
}

/// Extracts the target version string for the requested channel from npm registry response.
///
/// Handles both direct version objects `{"version": "0.2.6"}` and full package manifests
/// with `{"dist-tags": {"latest": "0.2.6", "alpha": "0.2.7-alpha.1"}}`.
pub fn parse_registry_version(json_str: &str, channel: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(json_str).ok()?;

    // 1. Check if dist-tags is present
    if let Some(dist_tags) = val.get("dist-tags").and_then(|v| v.as_object()) {
        let tag_key = if channel == "stable" {
            "latest"
        } else {
            channel
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

    // 3. GitHub releases tag_name or name field (e.g. from /releases/latest endpoint)
    let is_prerelease = val
        .get("prerelease")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if channel != "stable" || !is_prerelease {
        if let Some(tag) = val.get("tag_name").and_then(|v| v.as_str()) {
            let clean = tag.strip_prefix('v').unwrap_or(tag);
            return Some(clean.to_string());
        }
        if let Some(name) = val.get("name").and_then(|v| v.as_str()) {
            if let Some(_semver) = SemVer::parse(name) {
                let clean = name.strip_prefix('v').unwrap_or(name);
                return Some(clean.to_string());
            }
        }
    }

    // 4. GitHub releases array (e.g. from /releases endpoint)
    if let Some(arr) = val.as_array() {
        for item in arr {
            let is_pre = item
                .get("prerelease")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if channel != "stable" || !is_pre {
                if let Some(tag) = item.get("tag_name").and_then(|v| v.as_str()) {
                    let clean = tag.strip_prefix('v').unwrap_or(tag);
                    return Some(clean.to_string());
                }
            }
        }
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
        let v026_build = SemVer::parse("0.2.6+build.42").unwrap();
        let v026_alpha = SemVer::parse("0.2.6-alpha.1").unwrap();
        let v026_alpha_build = SemVer::parse("0.2.6-alpha.1+20260902").unwrap();
        let v026_alpha2 = SemVer::parse("0.2.6-alpha.2").unwrap();
        let v026_alpha10 = SemVer::parse("0.2.6-alpha.10").unwrap();

        assert!(v026.is_newer_than(&v025));
        assert!(!v025.is_newer_than(&v026));
        assert!(!v025.is_newer_than(&v025));

        assert!(v026.is_newer_than(&v026_alpha));
        assert!(v026_alpha2.is_newer_than(&v026_alpha));
        assert!(v026_alpha10.is_newer_than(&v026_alpha2));
        assert!(v026_alpha.is_newer_than(&v025));

        // Build metadata is ignored in precedence
        assert_eq!(v026_build.major, 0);
        assert_eq!(v026_build.minor, 2);
        assert_eq!(v026_build.patch, 6);
        assert_eq!(v026_build.prerelease, None);
        assert_eq!(v026_alpha_build.prerelease, Some("alpha.1".to_string()));
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
    fn parse_github_releases_response() {
        let gh_single =
            r#"{"tag_name": "v0.2.11", "name": "v0.2.11 release", "prerelease": false}"#;
        assert_eq!(
            parse_registry_version(gh_single, "stable").as_deref(),
            Some("0.2.11")
        );

        let gh_array = r#"[
            {"tag_name": "v0.2.12-alpha.1", "prerelease": true},
            {"tag_name": "v0.2.11", "prerelease": false}
        ]"#;
        assert_eq!(
            parse_registry_version(gh_array, "stable").as_deref(),
            Some("0.2.11")
        );
        assert_eq!(
            parse_registry_version(gh_array, "alpha").as_deref(),
            Some("0.2.12-alpha.1")
        );
    }

    #[test]
    fn parse_registry_response_invalid_json() {
        assert_eq!(parse_registry_version("not json", "stable"), None);
    }
}
