//! MCP server wrapper and sandboxing execution layer.
//!
//! Wraps and sandboxes external third-party Model Context Protocol (MCP) servers
//! (such as those used by Claude Desktop and Cursor) in an isolated sandbox.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::cli::McpWrapArgs;
use crate::config::NetMode;
use crate::policy::types::{DenyEntry, Policy};
use crate::sandbox::{self, StdioMode};

/// Resolves an executable binary candidate from PATH or a relative/absolute path.
pub fn resolve_in_path(cmd: &str) -> Result<PathBuf> {
    let p = Path::new(cmd);
    if p.is_absolute() || p.components().count() > 1 {
        return Ok(p.to_path_buf());
    }
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(cmd);
            if candidate.is_file() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = candidate.metadata() {
                        if meta.permissions().mode() & 0o111 != 0 {
                            return Ok(candidate);
                        }
                    }
                }
                #[cfg(not(unix))]
                return Ok(candidate);
            }
        }
    }
    bail!("command '{cmd}' not found in PATH")
}

/// Parses the network mode for MCP wrapping.
///
/// Supports "off" (default), "open", or standard allowlist/strict rules.
pub fn parse_wrap_net(net: &str) -> Result<NetMode> {
    if net == "off" {
        return Ok(NetMode::Off);
    }
    if net == "open" {
        return Ok(NetMode::Allowlist(vec!["*".to_string()]));
    }
    crate::config::parse_net_mode(net)
}

/// Synthesizes an isolated sandbox policy and network configuration for wrapping an MCP server.
pub fn build_wrap_policy(args: &McpWrapArgs) -> Result<(Policy, NetMode)> {
    let mut allow_write: Vec<PathBuf> = vec![PathBuf::from("/tmp"), PathBuf::from("/dev/null")];
    #[cfg(windows)]
    {
        if let Ok(temp) = std::env::var("TEMP") {
            allow_write.push(PathBuf::from(temp));
        }
    }
    for path in &args.allow {
        let pb = PathBuf::from(path);
        if !allow_write.contains(&pb) {
            allow_write.push(pb);
        }
    }

    let mut allow_read: Vec<PathBuf> = vec![
        PathBuf::from("/usr"),
        PathBuf::from("/lib"),
        PathBuf::from("/bin"),
    ];
    #[cfg(target_os = "linux")]
    {
        if Path::new("/lib64").exists() {
            allow_read.push(PathBuf::from("/lib64"));
        }
        if Path::new("/etc").exists() {
            allow_read.push(PathBuf::from("/etc"));
        }
    }
    for path in &args.allow {
        let pb = PathBuf::from(path);
        if !allow_read.contains(&pb) {
            allow_read.push(pb);
        }
    }
    for path in &args.allow_read {
        let pb = PathBuf::from(path);
        if !allow_read.contains(&pb) {
            allow_read.push(pb);
        }
    }

    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);

    let mut deny_resolved = Vec::new();
    let mut deny_read = Vec::new();
    let mut deny_write = Vec::new();

    if let Some(ref h) = home {
        for rel in &[".ssh", ".aws", ".gnupg"] {
            let path = h.join(rel);
            deny_read.push(path.clone());
            deny_write.push(path.clone());
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                deny_resolved.push(DenyEntry {
                    path,
                    is_dir: meta.is_dir(),
                });
            }
        }
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for pat in &[".env*", "*.pem", "*.key"] {
        let full_pat = cwd.join(pat).to_string_lossy().to_string();
        if let Ok(paths) = glob::glob(&full_pat) {
            for entry in paths.flatten() {
                deny_read.push(entry.clone());
                deny_write.push(entry.clone());
                if let Ok(meta) = std::fs::symlink_metadata(&entry) {
                    deny_resolved.push(DenyEntry {
                        path: entry,
                        is_dir: meta.is_dir(),
                    });
                }
            }
        }
    }

    let net_mode = parse_wrap_net(&args.net)?;
    let deny_network = matches!(net_mode, NetMode::Off);

    let mut policy = Policy::default();
    policy.name = "mcp-wrap".to_string();
    policy.allow_write = allow_write;
    policy.allow_read = allow_read;
    policy.deny_write = deny_write;
    policy.deny_read = deny_read;
    policy.deny_resolved = deny_resolved;
    policy.deny_network = deny_network;

    Ok((policy, net_mode))
}

/// Executes a third-party MCP server in an isolated sandbox.
pub fn run_wrap(args: &McpWrapArgs) -> Result<()> {
    if args.command.is_empty() {
        bail!(
            "no command specified to wrap. \
             Usage: vetto mcp wrap [options] -- <command> [args...]"
        );
    }

    let (mut policy, net_mode) = build_wrap_policy(args)?;

    let mut full_cmd = args.command.clone();
    let resolved_bin = resolve_in_path(&full_cmd[0])?;
    full_cmd[0] = resolved_bin.to_string_lossy().to_string();

    // Ensure parent directory of the binary is accessible so it can be executed
    if let Some(parent) = resolved_bin.parent() {
        let parent_buf = parent.to_path_buf();
        if !policy.in_read_scope(&resolved_bin) && !policy.allow_read.contains(&parent_buf) {
            policy.allow_read.push(parent_buf);
        }
    }

    let backend = sandbox::Backend::detect(net_mode.clone(), false)?;
    let project = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let opts = sandbox::SpawnOptions {
        agent_cmd: full_cmd,
        cwd: project,
        env_extra: HashMap::new(),
        stdio: StdioMode::Inherit,
    };

    let spawned = backend.spawn(&policy, opts)?;
    let mut handle = spawned.handle;

    #[cfg(target_os = "linux")]
    if let Some(fd) = spawned.broker_ctrl_fd {
        use std::os::unix::io::IntoRawFd;
        let broker_policy = match &net_mode {
            NetMode::Allowlist(d) => {
                crate::sandbox::linux::net_relay::BrokerPolicy::Allowlist(d.clone())
            }
            NetMode::Strict(rules) => {
                crate::sandbox::linux::net_relay::BrokerPolicy::Strict(rules.clone())
            }
            NetMode::Ask => crate::sandbox::linux::net_relay::BrokerPolicy::Ask,
            NetMode::Off => crate::sandbox::linux::net_relay::BrokerPolicy::Allowlist(Vec::new()),
        };
        let mut broker_config = crate::sandbox::linux::net_relay::BrokerConfig::from(broker_policy);
        broker_config.allow_cidr = policy.allow_cidr.clone();
        broker_config.quotas = policy.net_quota.clone();
        let bus = crate::events::EventBus::new();
        crate::sandbox::linux::net_relay::spawn_broker(fd.into_raw_fd(), broker_config, bus);
    }

    let exit_code = handle.wait();
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_wrap_empty_command_fails() {
        let args = McpWrapArgs {
            allow: vec![],
            allow_read: vec![],
            net: "off".to_string(),
            command: vec![],
        };
        let result = run_wrap(&args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("no command specified to wrap"));
        assert!(err_msg.contains("Usage: vetto mcp wrap [options] -- <command> [args...]"));
    }

    #[test]
    fn test_mcp_wrap_policy_generation() {
        let args = McpWrapArgs {
            allow: vec!["/workspace/project".to_string()],
            allow_read: vec!["/opt/data".to_string()],
            net: "off".to_string(),
            command: vec!["echo".to_string(), "hello".to_string()],
        };

        let (policy, net) = build_wrap_policy(&args).expect("build policy");

        assert!(policy.allow_write.contains(&PathBuf::from("/tmp")));
        assert!(policy.allow_write.contains(&PathBuf::from("/dev/null")));
        assert!(policy
            .allow_write
            .contains(&PathBuf::from("/workspace/project")));

        assert!(policy
            .allow_read
            .contains(&PathBuf::from("/workspace/project")));
        assert!(policy.allow_read.contains(&PathBuf::from("/opt/data")));
        assert!(policy.allow_read.contains(&PathBuf::from("/usr")));
        assert!(policy.allow_read.contains(&PathBuf::from("/lib")));
        assert!(policy.allow_read.contains(&PathBuf::from("/bin")));

        assert!(matches!(net, NetMode::Off));
        assert!(policy.deny_network);
    }

    #[test]
    fn test_mcp_wrap_net_modes() {
        let off = parse_wrap_net("off").expect("parse off");
        assert!(matches!(off, NetMode::Off));

        let open = parse_wrap_net("open").expect("parse open");
        assert!(matches!(
            open,
            NetMode::Allowlist(ref d) if d == &["*".to_string()]
        ));

        let allowlist = parse_wrap_net("allowlist:api.example.com").expect("parse allowlist");
        assert!(matches!(
            allowlist,
            NetMode::Allowlist(ref d) if d == &["api.example.com".to_string()]
        ));
    }

    #[test]
    fn test_mcp_wrap_resolve_in_path() {
        let resolved = resolve_in_path("sh");
        assert!(resolved.is_ok());

        let direct = resolve_in_path("/bin/sh");
        assert!(direct.is_ok());
        assert_eq!(direct.unwrap(), PathBuf::from("/bin/sh"));

        let nonexistent = resolve_in_path("non_existent_binary_xyz_12345");
        assert!(nonexistent.is_err());
    }
}
