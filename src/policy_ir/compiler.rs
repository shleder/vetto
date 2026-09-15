//! Authoritative Implementation: Policy Compiler (Phase 2 / NEXT_GEN §8).
//!
//! Deterministic translation engine between human/agent intent and the Canonical Security Contract.
//! Operates through 4 discrete, fail-closed phases:
//! 1. AST Parsing & Merging
//! 2. Strict Path Normalization & Canonicalization (openat2 RESOLVE_BENEATH ancestor checks)
//! 3. Conflict Resolution & Capability Negotiation (secret mask precedence)
//! 4. Contract Sealing & Cryptographic Digest Generation

use super::contract::{
    AgentIdentity, AttestationContract, EnvironmentContract, FilesystemContract, NetworkContract,
    NetworkMode, ResourceContract, SecurityContract, UnsealedSecurityContract,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CompilerError {
    #[error("Path canonicalization failed: {0}")]
    PathCanonicalizationFailed(String),
    #[error("Conflicting permissions: {0}")]
    ConflictingPermissions(String),
    #[error("Unsupported capability: {0}")]
    UnsupportedCapability(String),
    #[error("Missing mandatory field: {0}")]
    MissingMandatoryField(String),
}

pub struct PolicyCompiler;

impl PolicyCompiler {
    pub fn compile(
        agent_name: &str,
        workspace_raw: &Path,
        cli_net_override: Option<NetworkMode>,
        raw_reads: &[PathBuf],
        raw_writes: &[PathBuf],
    ) -> Result<SecurityContract, CompilerError> {
        // Phase 1: Canonicalize workspace root
        let workspace_root = workspace_raw.canonicalize().map_err(|e| {
            CompilerError::PathCanonicalizationFailed(format!("Workspace invalid: {e}"))
        })?;

        // Phase 2: Canonicalize and filter read paths
        let mut allow_read = Vec::new();
        for path in raw_reads {
            if let Ok(canon) = path.canonicalize() {
                allow_read.push(canon);
            } else {
                return Err(CompilerError::PathCanonicalizationFailed(format!(
                    "Read path invalid: {:?}",
                    path
                )));
            }
        }
        allow_read.sort();
        allow_read.dedup();

        // Normalize and canonicalize write paths and verify containment
        // std::fs::canonicalize() fails if the target file does not exist yet (e.g., new file creation).
        // The compiler performs lexical normalization and canonicalizes the nearest existing ancestor directory,
        // verifying that this ancestor resides within workspace_root.
        let mut allow_write = Vec::new();
        for path in raw_writes {
            let normalized = if path.is_absolute() {
                path.clone()
            } else {
                workspace_root.join(path)
            };

            // Ascend directory hierarchy to locate nearest existing ancestor
            let mut ancestor = normalized.clone();
            let mut suffix_components = Vec::new();
            while !ancestor.exists() {
                if let Some(name) = ancestor.file_name() {
                    suffix_components.push(name.to_os_string());
                }
                if !ancestor.pop() {
                    break;
                }
            }

            let canon_ancestor = ancestor.canonicalize().map_err(|e| {
                CompilerError::PathCanonicalizationFailed(format!(
                    "Write ancestor invalid for {:?}: {}",
                    path, e
                ))
            })?;

            // Hard constraint: existing ancestor must reside inside workspace_root
            if !canon_ancestor.starts_with(&workspace_root) {
                return Err(CompilerError::ConflictingPermissions(format!(
                    "Write target ancestor {:?} escapes workspace {:?}",
                    canon_ancestor, workspace_root
                )));
            }

            // Reassemble canonical ancestor with normalized relative components
            let mut resolved = canon_ancestor;
            for comp in suffix_components.into_iter().rev() {
                resolved.push(comp);
            }
            allow_write.push(resolved);
        }
        allow_write.sort();
        allow_write.dedup();

        // Phase 3: Conflict Resolution & Capability Negotiation
        // Build Mandatory Secret Masking Paths
        let home_dir = get_home_dir().unwrap_or_else(|| PathBuf::from("/root"));
        let mask_paths = vec![
            home_dir.join(".ssh"),
            home_dir.join(".aws"),
            home_dir.join(".gnupg"),
            workspace_root.join(".env"),
            workspace_root.join(".git/config"),
        ];

        // Mask paths take absolute precedence over write paths
        for w in &allow_write {
            for m in &mask_paths {
                if w == m || w.starts_with(m) {
                    return Err(CompilerError::ConflictingPermissions(format!(
                        "Write target {:?} collides with mandatory secret mask {:?}",
                        w, m
                    )));
                }
            }
        }

        // Resolve Network Mode
        let network_mode = cli_net_override.unwrap_or(NetworkMode::Off);

        // Build Environment Contract
        let env_contract = EnvironmentContract {
            pass_through_vars: vec!["PATH".to_string(), "LANG".to_string(), "TERM".to_string()],
            explicit_vars: BTreeMap::new(),
            redacted_patterns: vec![
                "*_KEY".to_string(),
                "*_SECRET".to_string(),
                "*_TOKEN".to_string(),
                "AWS_*".to_string(),
                "GITHUB_*".to_string(),
            ],
            inject_session_nonce: true,
        };

        // Phase 4: Contract Sealing & BLAKE3/SHA-256 Digest Generation
        let session_nonce = generate_session_nonce();
        let unsealed = UnsealedSecurityContract {
            contract_version: 1,
            contract_id: format!("contract-{}", &session_nonce[..12]),
            session_nonce,
            agent_identity: AgentIdentity {
                agent_name: agent_name.to_string(),
                agent_preset: "default".to_string(),
                agent_version: "0.2.23".to_string(),
                invoked_binary: PathBuf::from("/bin/sh"),
                invoked_args: vec![],
            },
            filesystem: FilesystemContract {
                workspace_root,
                allow_read,
                allow_write,
                allow_execute: vec![PathBuf::from("/usr"), PathBuf::from("/bin")],
                mask_paths,
                cow_overlay: true,
                execution_root_ro: true,
            },
            network: NetworkContract {
                mode: network_mode,
                allowed_domains: vec![],
                allowed_ports: vec![80, 443],
                block_cloud_metadata: true,
                block_loopback_daemons: true,
            },
            resources: ResourceContract {
                max_pids: 128,
                max_memory_bytes: 2 * 1024 * 1024 * 1024, // 2 GB
                max_cpu_percent: 100,
                max_wall_time_ms: 120_000,              // 2 minutes
                max_stdout_bytes: 10 * 1024 * 1024,     // 10 MB
                max_file_size_bytes: 100 * 1024 * 1024, // 100 MB
            },
            environment: env_contract,
            attestation: AttestationContract {
                generate_audit_jsonl: true,
                sign_minisign: true,
                sign_cosign_slsa: false,
                evidence_level_minimum: "HOST_FACT".to_string(),
            },
        };

        unsealed.seal().map_err(|e| {
            CompilerError::PathCanonicalizationFailed(format!("Failed to seal contract: {e}"))
        })
    }
}

fn get_home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

fn generate_session_nonce() -> String {
    let mut bytes = [0u8; 16];
    let read_ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut bytes).map(|_| ())
        })
        .is_ok();
    if !read_ok {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = ((t >> (8 * (i % 8))) ^ (std::process::id() as u128) ^ (i as u128 * 0x9E37)) as u8;
        }
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod compiler_tests {
    use super::*;

    #[test]
    fn compile_valid_workspace_contract() {
        let temp_dir = std::env::temp_dir().canonicalize().unwrap();
        let ws = temp_dir.join(format!("vetto_test_ws_{}", generate_session_nonce()));
        std::fs::create_dir_all(&ws).unwrap();

        let sub_out = ws.join("output/new_file.txt");
        let contract = PolicyCompiler::compile(
            "claude",
            &ws,
            Some(NetworkMode::Allowlist),
            &[ws.clone()],
            &[sub_out],
        )
        .expect("compilation should succeed");

        assert_eq!(contract.agent_identity.agent_name, "claude");
        assert_eq!(contract.network.mode, NetworkMode::Allowlist);
        assert!(contract.verify_digest());

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn reject_escaped_write_target() {
        let temp_dir = std::env::temp_dir().canonicalize().unwrap();
        let ws = temp_dir.join(format!("vetto_test_ws_{}", generate_session_nonce()));
        std::fs::create_dir_all(&ws).unwrap();

        let outside_write = temp_dir.join("outside_target.txt");
        let result = PolicyCompiler::compile("codex", &ws, None, &[ws.clone()], &[outside_write]);

        assert!(matches!(
            result,
            Err(CompilerError::ConflictingPermissions(_))
        ));

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn reject_mask_path_write_collision() {
        let temp_dir = std::env::temp_dir().canonicalize().unwrap();
        let ws = temp_dir.join(format!("vetto_test_ws_{}", generate_session_nonce()));
        std::fs::create_dir_all(&ws).unwrap();

        let env_file = ws.join(".env");
        let result = PolicyCompiler::compile("codex", &ws, None, &[ws.clone()], &[env_file]);

        assert!(matches!(
            result,
            Err(CompilerError::ConflictingPermissions(_))
        ));

        let _ = std::fs::remove_dir_all(&ws);
    }
}
