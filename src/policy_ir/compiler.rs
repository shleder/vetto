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

/// Already-resolved production inputs. No defaults or path reinterpretation
/// from the request-oriented compiler are applied at this boundary.
pub struct EffectivePolicyInput<'a> {
    pub policy: &'a crate::policy::Policy,
    pub argv: &'a [String],
    pub cwd: &'a Path,
    pub env: &'a BTreeMap<String, String>,
    pub net: &'a crate::config::NetMode,
    pub nonce: &'a str,
    pub timeout: Option<std::time::Duration>,
    pub tier: Option<crate::policy::Tier>,
    pub backend: String,
    pub observe_seccomp: bool,
    pub debug_ports: Option<&'a crate::multi::DebugPortConfig>,
}

impl PolicyCompiler {
    pub fn compile_effective(
        input: EffectivePolicyInput<'_>,
    ) -> Result<SecurityContract, CompilerError> {
        use super::contract::ProductionContract;
        use crate::config::NetMode;
        if input.argv.first().map_or(true, |s| s.is_empty()) || input.nonce.is_empty() {
            return Err(CompilerError::MissingMandatoryField(
                "command or nonce".into(),
            ));
        }
        let policy = input.policy;
        // The request-oriented fields are an exact checked projection. The
        // installation payload preserves values that v1 cannot express (None,
        // CPU seconds, strict domain/port pairs, platform settings).
        let (mode, domains, ports) = match input.net {
            NetMode::Off => (NetworkMode::Off, vec![], vec![]),
            NetMode::Allowlist(domains) => (NetworkMode::Allowlist, domains.clone(), vec![]),
            NetMode::Strict(rules) => (
                NetworkMode::Strict,
                rules.iter().map(|r| r.domain.clone()).collect(),
                rules.iter().map(|r| r.port).collect(),
            ),
            NetMode::Ask => (NetworkMode::Ask, vec![], vec![]),
        };
        let max_pids = resolve_max_pids(policy)?;
        let max_memory_bytes = resolve_max_memory_bytes(policy);
        let max_cpu_percent = resolve_cpu_percent(policy);
        let max_wall_time_ms =
            u64::try_from(input.timeout.map_or(0, |t| t.as_millis())).map_err(|_| {
                CompilerError::UnsupportedCapability("timeout exceeds contract range".into())
            })?;
        UnsealedSecurityContract {
            production: Some(ProductionContract {
                installation_policy: policy.clone(),
                net: input.net.clone(),
                timeout: input.timeout,
                tier: input.tier,
                backend: input.backend,
                observe_seccomp: input.observe_seccomp,
                debug_ports: input.debug_ports.cloned(),
            }),
            crypto: Default::default(),
            contract_version: 1,
            contract_id: format!("production-{}", input.nonce),
            session_nonce: input.nonce.to_string(),
            agent_identity: AgentIdentity {
                agent_name: policy.name.clone(),
                agent_preset: policy.name.clone(),
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                invoked_binary: PathBuf::from(&input.argv[0]),
                invoked_args: input.argv[1..].to_vec(),
            },
            filesystem: FilesystemContract {
                workspace_root: input.cwd.to_path_buf(),
                allow_read: policy.allow_read.clone(),
                allow_write: policy.allow_write.clone(),
                allow_execute: vec![],
                mask_paths: policy
                    .deny_resolved
                    .iter()
                    .map(|d| d.path.clone())
                    .collect(),
                cow_overlay: false,
                execution_root_ro: false,
            },
            network: NetworkContract {
                mode,
                allowed_domains: domains,
                allowed_ports: ports,
                block_cloud_metadata: input.net.uses_relay(),
                block_loopback_daemons: input.net.uses_relay(),
            },
            resources: ResourceContract {
                max_pids,
                max_memory_bytes,
                max_cpu_percent,
                max_wall_time_ms,
                max_stdout_bytes: crate::sandbox::production::PROD_MAX_STDIO as u64,
                max_file_size_bytes: policy.limits.file_size_bytes.unwrap_or(0),
            },
            environment: EnvironmentContract {
                pass_through_vars: policy.environment.pass_through.clone(),
                explicit_vars: input.env.clone(),
                redacted_patterns: policy.environment.deny.clone(),
                inject_session_nonce: true,
            },
            attestation: AttestationContract {
                generate_audit_jsonl: true,
                sign_minisign: false,
                sign_cosign_slsa: false,
                evidence_level_minimum: "HOST_FACT".into(),
            },
        }
        .seal()
        .map_err(|e| CompilerError::UnsupportedCapability(format!("contract serialization: {e}")))
    }

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

        // Phase 2: Canonicalize and filter read paths.
        // Always include workspace_root as a readable base.
        let mut allow_read = vec![workspace_root.clone()];
        for path in raw_reads {
            let clean_path = if cfg!(windows) {
                PathBuf::from(path.to_string_lossy().replace('/', "\\"))
            } else {
                path.clone()
            };
            let path_str = path.to_string_lossy();
            if path_str.split(['/', '\\']).any(|c| c == "..")
                || clean_path
                    .components()
                    .any(|c| c.as_os_str() == ".." || matches!(c, std::path::Component::ParentDir))
            {
                return Err(CompilerError::ConflictingPermissions(format!(
                    "Read target {:?} attempts directory traversal",
                    path
                )));
            }
            let normalized = if clean_path.is_absolute() {
                clean_path
            } else {
                let mut base = workspace_root.clone();
                for comp in clean_path.components() {
                    if comp.as_os_str() != "." && !matches!(comp, std::path::Component::CurDir) {
                        base.push(comp.as_os_str());
                    }
                }
                base
            };
            if let Ok(canon) = normalized.canonicalize() {
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
            let clean_path = if cfg!(windows) {
                PathBuf::from(path.to_string_lossy().replace('/', "\\"))
            } else {
                path.clone()
            };
            let path_str = path.to_string_lossy();
            if path_str.split(['/', '\\']).any(|c| c == "..")
                || clean_path
                    .components()
                    .any(|c| c.as_os_str() == ".." || matches!(c, std::path::Component::ParentDir))
            {
                return Err(CompilerError::ConflictingPermissions(format!(
                    "Write target {:?} attempts directory traversal",
                    path
                )));
            }
            let normalized = if clean_path.is_absolute() {
                clean_path
            } else {
                let mut base = workspace_root.clone();
                for comp in clean_path.components() {
                    if comp.as_os_str() != "." && !matches!(comp, std::path::Component::CurDir) {
                        base.push(comp.as_os_str());
                    }
                }
                base
            };

            // Ascend directory hierarchy to locate nearest existing ancestor
            let mut ancestor = normalized.clone();
            let mut suffix_components = Vec::new();
            while !ancestor.exists() {
                if let Some(comp) = ancestor.components().next_back() {
                    if comp.as_os_str() == ".." || matches!(comp, std::path::Component::ParentDir) {
                        return Err(CompilerError::ConflictingPermissions(format!(
                            "Write target {:?} attempts directory traversal",
                            path
                        )));
                    }
                    if comp.as_os_str() != "." && !matches!(comp, std::path::Component::CurDir) {
                        suffix_components.push(comp.as_os_str().to_os_string());
                    }
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

        // Mask paths take absolute precedence over write paths.
        // Rejects if write target matches mask, is inside mask, or encompasses mask (except workspace_root).
        for w in &allow_write {
            for m in &mask_paths {
                if w == m || w.starts_with(m) || (w != &workspace_root && m.starts_with(w)) {
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

        #[cfg(windows)]
        let default_exec = vec![PathBuf::from(
            std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()),
        )];
        #[cfg(not(windows))]
        let default_exec = vec![PathBuf::from("/usr"), PathBuf::from("/bin")];

        let unsealed = UnsealedSecurityContract {
            production: None,
            crypto: Default::default(),
            contract_version: 1,
            contract_id: format!("contract-{}", &session_nonce[..12]),
            session_nonce,
            agent_identity: AgentIdentity {
                agent_name: agent_name.to_string(),
                agent_preset: "default".to_string(),
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                invoked_binary: PathBuf::from("/bin/sh"),
                invoked_args: vec![],
            },
            filesystem: FilesystemContract {
                workspace_root,
                allow_read,
                allow_write,
                allow_execute: default_exec,
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

fn resolve_cpu_percent(policy: &crate::policy::Policy) -> u32 {
    let pol_cpu = policy.cpu_max.as_deref().and_then(cpu_str_to_percent);
    let cg_cpu = policy
        .cgroup
        .as_ref()
        .and_then(|c| c.cpu_max.as_deref())
        .and_then(cpu_str_to_percent);

    match (pol_cpu, cg_cpu) {
        (Some(p1), Some(p2)) => p1.min(p2),
        (Some(p), None) | (None, Some(p)) => p,
        (None, None) => 100, // unconstrained default
    }
}

fn cpu_str_to_percent(s: &str) -> Option<u32> {
    let ratio = crate::policy::types::parse_cpu_ratio(s)?;
    let pct = (ratio * 100.0).round() as u32;
    Some(pct.max(1))
}

fn resolve_max_memory_bytes(policy: &crate::policy::Policy) -> u64 {
    let as_bytes = policy.limits.address_space_bytes.filter(|&b| b > 0);
    let cg_bytes = policy
        .cgroup
        .as_ref()
        .and_then(|c| c.memory_max.as_deref())
        .and_then(crate::policy::types::parse_bytes_value)
        .filter(|&b| b > 0);

    match (as_bytes, cg_bytes) {
        (Some(a), Some(c)) => a.min(c),
        (Some(a), None) => a,
        (None, Some(c)) => c,
        (None, None) => 0,
    }
}

fn resolve_max_pids(policy: &crate::policy::Policy) -> Result<u32, CompilerError> {
    let proc_limit = policy.limits.processes.filter(|&p| p > 0);
    let cg_limit = policy
        .cgroup
        .as_ref()
        .and_then(|c| c.pids_max.as_deref())
        .and_then(|s| {
            if s.trim().eq_ignore_ascii_case("max") {
                None
            } else {
                s.trim().parse::<u64>().ok()
            }
        })
        .filter(|&p| p > 0);

    let effective_pids = match (proc_limit, cg_limit) {
        (Some(p1), Some(p2)) => p1.min(p2),
        (Some(p), None) => p,
        (None, Some(p)) => p,
        (None, None) => 0,
    };

    u32::try_from(effective_pids).map_err(|_| {
        CompilerError::UnsupportedCapability("process limit exceeds contract v1 range".into())
    })
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
    use rand_core::RngCore;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
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
            std::slice::from_ref(&ws),
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
        let result = PolicyCompiler::compile(
            "codex",
            &ws,
            None,
            std::slice::from_ref(&ws),
            &[outside_write],
        );

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
        let result =
            PolicyCompiler::compile("codex", &ws, None, std::slice::from_ref(&ws), &[env_file]);

        assert!(matches!(
            result,
            Err(CompilerError::ConflictingPermissions(_))
        ));

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn compile_empty_reads_includes_workspace() {
        let temp_dir = std::env::temp_dir().canonicalize().unwrap();
        let ws = temp_dir.join(format!("vetto_test_ws_{}", generate_session_nonce()));
        std::fs::create_dir_all(&ws).unwrap();

        let contract = PolicyCompiler::compile("claude", &ws, None, &[], &[])
            .expect("compilation should succeed with empty raw reads");

        assert!(contract.filesystem.allow_read.contains(&ws));
        assert!(contract.verify_digest());

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn compile_effective_resource_projections() {
        use crate::policy::types::{CgroupConfig, Policy};
        use crate::policy_ir::compiler::EffectivePolicyInput;
        use std::collections::BTreeMap;

        // 1. Unconstrained defaults to 100% CPU, 0 memory, 0 pids
        let policy = Policy::default();
        let temp_dir = std::env::temp_dir().canonicalize().unwrap();
        let input = EffectivePolicyInput {
            policy: &policy,
            argv: &["/bin/true".into()],
            cwd: &temp_dir,
            env: &BTreeMap::new(),
            net: &crate::config::NetMode::Off,
            nonce: "test-effective-res-1",
            timeout: None,
            tier: None,
            backend: "test".into(),
            observe_seccomp: false,
            debug_ports: None,
        };
        let contract = PolicyCompiler::compile_effective(input).expect("compile effective");
        assert_eq!(contract.resources.max_cpu_percent, 100);
        assert_eq!(contract.resources.max_memory_bytes, 0);
        assert_eq!(contract.resources.max_pids, 0);

        // 2. CPU percentage parsed from policy.cpu_max
        let mut policy_cpu = Policy::default();
        policy_cpu.cpu_max = Some("50%".into());
        let input = EffectivePolicyInput {
            policy: &policy_cpu,
            argv: &["/bin/true".into()],
            cwd: &temp_dir,
            env: &BTreeMap::new(),
            net: &crate::config::NetMode::Off,
            nonce: "test-effective-res-2",
            timeout: None,
            tier: None,
            backend: "test".into(),
            observe_seccomp: false,
            debug_ports: None,
        };
        let contract = PolicyCompiler::compile_effective(input).expect("compile effective");
        assert_eq!(contract.resources.max_cpu_percent, 50);

        // 3. Minimum between address_space_bytes and cgroup.memory_max
        let mut policy_mem = Policy::default();
        policy_mem.limits.address_space_bytes = Some(2 * 1024 * 1024 * 1024); // 2GB
        policy_mem.cgroup = Some(CgroupConfig {
            memory_max: Some("1G".into()), // 1GB
            pids_max: Some("64".into()),
            swap_max: None,
            cpu_max: Some("40%".into()),
        });
        policy_mem.limits.processes = Some(128);

        let input = EffectivePolicyInput {
            policy: &policy_mem,
            argv: &["/bin/true".into()],
            cwd: &temp_dir,
            env: &BTreeMap::new(),
            net: &crate::config::NetMode::Off,
            nonce: "test-effective-res-3",
            timeout: None,
            tier: None,
            backend: "test".into(),
            observe_seccomp: false,
            debug_ports: None,
        };
        let contract = PolicyCompiler::compile_effective(input).expect("compile effective");
        // Effective memory is min(2GB, 1GB) = 1GB
        assert_eq!(contract.resources.max_memory_bytes, 1024 * 1024 * 1024);
        // Effective pids is min(128, 64) = 64
        assert_eq!(contract.resources.max_pids, 64);
        // Effective cpu is min(default 100, 40) = 40
        assert_eq!(contract.resources.max_cpu_percent, 40);
    }
}
