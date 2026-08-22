//! Built-in default security rules.

use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Filesystem access rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsRule {
    AllowRead(PathBuf),
    AllowWrite(PathBuf),
    DenyAll(PathBuf),
}

impl Serialize for FsRule {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Raw {
            action: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            path: Option<String>,
        }
        let raw = match self {
            FsRule::AllowRead(p) => Raw {
                action: "allow_read".into(),
                path: Some(p.display().to_string()),
            },
            FsRule::AllowWrite(p) => Raw {
                action: "allow_write".into(),
                path: Some(p.display().to_string()),
            },
            FsRule::DenyAll(p) => Raw {
                action: "deny_all".into(),
                path: Some(p.display().to_string()),
            },
        };
        raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FsRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            action: String,
            path: Option<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let action = raw.action.clone();
        let missing = || serde::de::Error::custom(format!("rule '{action}' requires 'path'"));
        Ok(match action.as_str() {
            "allow_read" => FsRule::AllowRead(PathBuf::from(raw.path.ok_or_else(missing)?)),
            "allow_write" => FsRule::AllowWrite(PathBuf::from(raw.path.ok_or_else(missing)?)),
            "deny_all" => FsRule::DenyAll(PathBuf::from(raw.path.ok_or_else(missing)?)),
            other => return Err(serde::de::Error::custom(format!("unknown fs rule '{other}'"))),
        })
    }
}

/// Network access rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetRule {
    AllowOutbound(String),
    DenyAllOutbound,
    DenyAllInbound,
}

impl Serialize for NetRule {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Raw {
            action: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            target: Option<String>,
        }
        let raw = match self {
            NetRule::AllowOutbound(t) => Raw {
                action: "allow_outbound".into(),
                target: Some(t.clone()),
            },
            NetRule::DenyAllOutbound => Raw {
                action: "deny_all_outbound".into(),
                target: None,
            },
            NetRule::DenyAllInbound => Raw {
                action: "deny_all_inbound".into(),
                target: None,
            },
        };
        raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NetRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            action: String,
            target: Option<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(match raw.action.as_str() {
            "allow_outbound" => NetRule::AllowOutbound(
                raw.target
                    .ok_or_else(|| serde::de::Error::custom("rule 'allow_outbound' requires 'target'"))?,
            ),
            "deny_all_outbound" => NetRule::DenyAllOutbound,
            "deny_all_inbound" => NetRule::DenyAllInbound,
            other => return Err(serde::de::Error::custom(format!("unknown net rule '{other}'"))),
        })
    }
}

/// Serde-friendly on-disk policy representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    pub fs_rules: Vec<FsRule>,
    pub net_rules: Vec<NetRule>,
}

/// Built-in default security profile:
/// read ./, deny secret paths, allow LLM API hosts + localhost outbound only.
pub fn default_policy() -> PolicyFile {
    PolicyFile {
        fs_rules: vec![
            FsRule::AllowRead(PathBuf::from("./")),
            FsRule::DenyAll(home_join(".ssh")),
            FsRule::DenyAll(home_join(".aws")),
            FsRule::DenyAll(PathBuf::from(".env*")),
        ],
        net_rules: vec![
            NetRule::AllowOutbound("api.openai.com:443".into()),
            NetRule::AllowOutbound("api.anthropic.com:443".into()),
            NetRule::AllowOutbound("localhost:*".into()),
            NetRule::DenyAllOutbound,
            NetRule::DenyAllInbound,
        ],
    }
}

fn home_join(relative: &str) -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(relative)
}
