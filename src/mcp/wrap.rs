//! MCP server wrapper and sandboxing execution layer.
//!
//! Wraps and sandboxes external third-party Model Context Protocol (MCP) servers
//! (such as those used by Claude Desktop and Cursor) in an isolated sandbox.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::cli::McpWrapArgs;
use crate::config::NetMode;
use crate::error::VettoError;
use crate::policy::types::{DenyEntry, Policy};
use crate::sandbox::{self, StdioMode};

/// Resolves an executable binary candidate from PATH or a relative/absolute path.
pub fn resolve_in_path(cmd: &str) -> Result<PathBuf> {
    let p = Path::new(cmd);
    if p.is_absolute() || p.components().count() > 1 {
        return Ok(p.to_path_buf());
    }
    if let Some(path_var) = std::env::var_os("PATH") {
        #[cfg(windows)]
        let extensions = [".exe", ".cmd", ".bat", ""];

        for dir in std::env::split_paths(&path_var) {
            #[cfg(unix)]
            {
                let candidate = dir.join(cmd);
                if candidate.is_file() {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = candidate.metadata() {
                        if meta.permissions().mode() & 0o111 != 0 {
                            return Ok(candidate);
                        }
                    }
                }
            }

            #[cfg(windows)]
            {
                let candidate = dir.join(cmd);
                if candidate.is_file() {
                    return Ok(candidate);
                }
                for ext in &extensions {
                    let with_ext = dir.join(format!("{cmd}{ext}"));
                    if with_ext.is_file() {
                        return Ok(with_ext);
                    }
                }
            }
        }
    }
    #[cfg(unix)]
    {
        for dir in ["/bin", "/usr/bin"] {
            let candidate = Path::new(dir).join(cmd);
            if candidate.is_file() {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = candidate.metadata() {
                    if meta.permissions().mode() & 0o111 != 0 {
                        return Ok(candidate);
                    }
                }
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

/// Validates network relay mode against the current execution platform.
pub fn validate_wrap_relay(net_mode: &NetMode) -> Result<()> {
    validate_wrap_relay_for_platform(net_mode, cfg!(target_os = "linux"))
}

pub(crate) fn validate_wrap_relay_for_platform(net_mode: &NetMode, is_linux: bool) -> Result<()> {
    if net_mode.uses_relay() && !is_linux {
        return Err(anyhow::Error::new(VettoError::UnsupportedPlatform(
            "network relay requires Linux network namespaces; use --net off on this platform",
        )));
    }
    Ok(())
}

/// Returns true if the path contains any relative parent directory traversal components (`..` or `...`).
#[cfg(any(windows, test))]
fn path_has_parent_dir(path: &Path) -> bool {
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return true;
    }
    let s = path.to_string_lossy();
    s.split(['/', '\\']).any(|seg| {
        let trimmed = seg.trim();
        trimmed == ".." || (trimmed.len() >= 2 && trimmed.chars().all(|c| c == '.'))
    })
}

/// Returns true if the path starts with a valid Windows drive root (e.g. `C:\` or `c:/`).
#[cfg(any(windows, test))]
fn starts_with_valid_drive(path: &Path) -> bool {
    let s = path.to_string_lossy();
    let bytes = s.as_bytes();
    if bytes.len() < 3 {
        return false;
    }
    bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/')
}

/// Checks that a Windows path is absolute, has a directory component beyond the drive root,
/// contains no parent traversal components, and has no invalid characters or UNC syntax.
#[cfg(any(windows, test))]
fn is_safe_windows_path<P: AsRef<Path>>(path: P) -> bool {
    let p = path.as_ref();
    let s = p.to_string_lossy();
    if s.chars()
        .any(|c| matches!(c, '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return false;
    }
    // UNC paths (\\server\share) are network paths, not safe local paths.
    if s.starts_with(r"\\") || s.starts_with("//") {
        return false;
    }
    #[cfg(windows)]
    let is_abs = p.is_absolute();
    #[cfg(not(windows))]
    let is_abs = starts_with_valid_drive(p);

    if !is_abs || path_has_parent_dir(p) {
        return false;
    }

    // Must not be a bare drive root like "C:\" or "C:/" without a directory component
    let trimmed = s.trim_end_matches(['/', '\\']);
    if starts_with_valid_drive(p) && trimmed.len() <= 2 {
        return false;
    }

    true
}

/// Validates that a path is absolute, starts with a valid drive root (e.g. `C:\`),
/// contains a directory component beyond the drive root, and contains no parent traversal components.
#[cfg(any(windows, test))]
fn is_valid_windows_drive_path<P: AsRef<Path>>(path: P) -> bool {
    let p = path.as_ref();
    starts_with_valid_drive(p) && is_safe_windows_path(p)
}

/// Validates a Windows SystemRoot candidate against structural and existence criteria.
#[cfg(any(windows, test))]
fn is_valid_system_root_with_check<F>(path: &Path, check_sys32: F) -> bool
where
    F: Fn(&Path) -> bool,
{
    if !is_valid_windows_drive_path(path) {
        return false;
    }
    let sys32 = path.join("System32");
    check_sys32(&sys32)
}

/// Resolves a Windows SystemRoot from candidates with validation and canonical fallback to `C:\Windows`.
#[cfg(any(windows, test))]
fn resolve_windows_system_root_with<F>(
    sys_root: Option<&str>,
    windir: Option<&str>,
    check_sys32: F,
) -> PathBuf
where
    F: Fn(&Path) -> bool,
{
    if let Some(sr) = sys_root {
        let p = PathBuf::from(sr);
        if is_valid_system_root_with_check(&p, &check_sys32) {
            return p;
        }
    }
    if let Some(wd) = windir {
        let p = PathBuf::from(wd);
        if is_valid_system_root_with_check(&p, &check_sys32) {
            return p;
        }
    }
    PathBuf::from(r"C:\Windows")
}

/// Resolves a Windows SystemRoot from an optional raw environment value,
/// falling back to canonical `C:\Windows` if validation fails.
#[cfg(any(windows, test))]
fn resolve_windows_system_root_from<F>(raw_env: Option<&str>, check_sys32: F) -> PathBuf
where
    F: Fn(&Path) -> bool,
{
    resolve_windows_system_root_with(raw_env, None, check_sys32)
}

/// Verifies whether the System32 directory contains critical system binaries.
#[cfg(windows)]
fn default_check_system32(sys32: &Path) -> bool {
    sys32.join("cmd.exe").is_file() || sys32.join("kernel32.dll").is_file()
}

/// Resolves the Windows SystemRoot directory from environment variables,
/// hardened against ENV-POISON attacks. Tries SystemRoot, then windir,
/// falling back to canonical C:\Windows.
#[cfg(windows)]
fn resolve_windows_system_root() -> PathBuf {
    let sr = std::env::var("SystemRoot").ok();
    let wd = std::env::var("windir").ok();
    resolve_windows_system_root_with(sr.as_deref(), wd.as_deref(), default_check_system32)
}

/// Synthesizes an isolated sandbox policy and network configuration for wrapping an MCP server.
pub fn build_wrap_policy(args: &McpWrapArgs) -> Result<(Policy, NetMode)> {
    #[cfg(unix)]
    let mut allow_write: Vec<PathBuf> = vec![PathBuf::from("/tmp"), PathBuf::from("/dev/null")];
    #[cfg(not(unix))]
    let mut allow_write: Vec<PathBuf> = Vec::new();
    #[cfg(windows)]
    {
        let temp = std::env::temp_dir();
        if is_safe_windows_path(&temp) && !allow_write.contains(&temp) {
            allow_write.push(temp);
        }
        for var in &["TEMP", "TMP"] {
            if let Ok(temp) = std::env::var(var) {
                let pb = PathBuf::from(temp);
                if is_safe_windows_path(&pb) && !allow_write.contains(&pb) {
                    allow_write.push(pb);
                }
            }
        }
    }
    for path in &args.allow {
        let pb = PathBuf::from(path);
        if !allow_write.contains(&pb) {
            allow_write.push(pb);
        }
    }

    #[cfg(unix)]
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
    #[cfg(not(unix))]
    let mut allow_read: Vec<PathBuf> = Vec::new();
    #[cfg(windows)]
    {
        let mut add_path = |p: PathBuf| {
            if !allow_read.contains(&p) {
                allow_read.push(p);
            }
        };

        let sysroot = resolve_windows_system_root();
        add_path(sysroot.clone());
        add_path(sysroot.join("System32"));

        let program_files = std::env::var("ProgramFiles")
            .ok()
            .map(PathBuf::from)
            .filter(|p| is_valid_windows_drive_path(p))
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
        add_path(program_files);

        let program_files_x86 = std::env::var("ProgramFiles(x86)")
            .ok()
            .map(PathBuf::from)
            .filter(|p| is_valid_windows_drive_path(p))
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files (x86)"));
        add_path(program_files_x86);

        if let Ok(val) = std::env::var("ProgramW6432") {
            let p = PathBuf::from(val);
            if is_valid_windows_drive_path(&p) {
                add_path(p);
            }
        }

        let local_app_data = std::env::var("LOCALAPPDATA")
            .ok()
            .map(PathBuf::from)
            .filter(|p| is_safe_windows_path(p));
        if let Some(p) = local_app_data {
            add_path(p);
        } else if let Some(userprofile) = std::env::var_os("USERPROFILE") {
            let fallback = PathBuf::from(userprofile).join("AppData").join("Local");
            if is_safe_windows_path(&fallback) {
                add_path(fallback);
            }
        }

        let temp = std::env::temp_dir();
        if is_safe_windows_path(&temp) {
            add_path(temp);
        }
        for var in &["TEMP", "TMP"] {
            if let Ok(temp) = std::env::var(var) {
                let pb = PathBuf::from(temp);
                if is_safe_windows_path(&pb) {
                    add_path(pb);
                }
            }
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
    validate_wrap_relay(&net_mode)?;
    let deny_network = matches!(net_mode, NetMode::Off);

    let policy = Policy {
        name: "mcp-wrap".to_string(),
        allow_write,
        allow_read,
        deny_write,
        deny_read,
        deny_resolved,
        deny_network,
        ..Policy::default()
    };

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
    validate_wrap_relay(&net_mode)?;

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

    // One authoritative boundary: frozen inputs → prepared backend → the
    // single real spawn. No MCP-specific direct spawn exists.
    let unprepared = sandbox::production::UnpreparedProductionExecution::new(
        backend,
        policy,
        full_cmd,
        project,
        HashMap::new(),
        net_mode,
        None,
        StdioMode::Inherit,
        "mcp".to_string(),
    );
    // `take_broker_ctrl_fd` is Linux-only; `wait_collect` consumes without
    // `&mut`. `allow` keeps one spelling across platforms, not two.
    #[allow(unused_mut)]
    let mut spawned = unprepared.prepare()?.spawn()?;

    #[cfg(target_os = "linux")]
    if let Some(fd) = spawned.take_broker_ctrl_fd() {
        use std::os::unix::io::IntoRawFd;
        let production = spawned
            .contract()
            .production
            .as_ref()
            .expect("production contract validated before spawn");
        let broker_policy = match &production.net {
            NetMode::Allowlist(d) => {
                crate::sandbox::linux::net_relay::BrokerPolicy::Allowlist(d.clone())
            }
            NetMode::Strict(rules) => {
                crate::sandbox::linux::net_relay::BrokerPolicy::Strict(rules.clone())
            }
            NetMode::Ask => crate::sandbox::linux::net_relay::BrokerPolicy::Ask(
                production.installation_policy.network_allow.clone(),
            ),
            NetMode::Off => crate::sandbox::linux::net_relay::BrokerPolicy::Allowlist(Vec::new()),
        };
        let mut broker_config = crate::sandbox::linux::net_relay::BrokerConfig::from(broker_policy);
        broker_config.allow_cidr = production.installation_policy.allow_cidr.clone();
        broker_config.quotas = production.installation_policy.net_quota.clone();
        broker_config.block_doh = matches!(net, crate::config::NetMode::Allowlist(_) | crate::config::NetMode::Strict(_));
        let bus = crate::events::EventBus::new();
        crate::sandbox::linux::net_relay::spawn_broker(fd.into_raw_fd(), broker_config, bus);
    }

    // Proven killer path with the frozen (absent) deadline, then the typed
    // result; never a bare blocking wait.
    let result = spawned.wait_collect();
    let exit_code = result.exit_code.unwrap_or(-1);
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

        #[cfg(unix)]
        {
            assert!(policy.allow_write.contains(&PathBuf::from("/tmp")));
            assert!(policy.allow_write.contains(&PathBuf::from("/dev/null")));
        }
        #[cfg(windows)]
        {
            assert!(policy.allow_write.contains(&std::env::temp_dir()));
        }
        assert!(policy
            .allow_write
            .contains(&PathBuf::from("/workspace/project")));

        assert!(policy
            .allow_read
            .contains(&PathBuf::from("/workspace/project")));
        assert!(policy.allow_read.contains(&PathBuf::from("/opt/data")));
        #[cfg(unix)]
        {
            assert!(policy.allow_read.contains(&PathBuf::from("/usr")));
            assert!(policy.allow_read.contains(&PathBuf::from("/lib")));
            assert!(policy.allow_read.contains(&PathBuf::from("/bin")));
        }
        #[cfg(windows)]
        {
            let sysroot = resolve_windows_system_root();
            assert!(policy.allow_read.contains(&sysroot));
            assert!(policy.allow_read.contains(&sysroot.join("System32")));
            assert!(policy.allow_read.contains(&std::env::temp_dir()));
        }

        assert!(matches!(net, NetMode::Off));
        assert!(policy.deny_network);
    }

    #[test]
    fn test_mcp_wrap_network_relay_unsupported_on_non_linux() {
        let args = McpWrapArgs {
            allow: vec![],
            allow_read: vec![],
            net: "open".to_string(),
            command: vec!["echo".to_string()],
        };
        let result = build_wrap_policy(&args);
        #[cfg(not(target_os = "linux"))]
        {
            assert!(result.is_err());
            let err = result.unwrap_err();
            let vetto_err = err.downcast_ref::<VettoError>();
            assert!(matches!(
                vetto_err,
                Some(VettoError::UnsupportedPlatform(_))
            ));
            assert!(err
                .to_string()
                .contains("network relay requires Linux network namespaces"));
        }
        #[cfg(target_os = "linux")]
        {
            assert!(result.is_ok());
            let (policy, net_mode) = result.unwrap();
            assert!(matches!(
                net_mode,
                NetMode::Allowlist(ref d) if d == &["*".to_string()]
            ));
            assert!(!policy.deny_network);
        }
    }

    #[test]
    fn test_mcp_wrap_validate_relay_for_platform() {
        let open_mode = NetMode::Allowlist(vec!["*".to_string()]);
        let off_mode = NetMode::Off;

        let non_linux_err = validate_wrap_relay_for_platform(&open_mode, false);
        assert!(non_linux_err.is_err());
        let err = non_linux_err.unwrap_err();
        let vetto_err = err.downcast_ref::<VettoError>();
        assert!(matches!(
            vetto_err,
            Some(VettoError::UnsupportedPlatform(_))
        ));

        assert!(validate_wrap_relay_for_platform(&off_mode, false).is_ok());
        assert!(validate_wrap_relay_for_platform(&open_mode, true).is_ok());
        assert!(validate_wrap_relay_for_platform(&off_mode, true).is_ok());
    }

    #[test]
    fn test_windows_path_traversal_detection() {
        assert!(!path_has_parent_dir(Path::new(r"C:\Windows\System32")));
        assert!(!path_has_parent_dir(Path::new("C:/Windows/System32")));
        assert!(!path_has_parent_dir(Path::new(
            r"C:\Program Files\App..dir"
        )));
        assert!(path_has_parent_dir(Path::new(r"C:\Windows\..\System32")));
        assert!(path_has_parent_dir(Path::new("C:/Windows/../System32")));
        assert!(path_has_parent_dir(Path::new(r"C:\Windows\.. \System32")));
        assert!(path_has_parent_dir(Path::new(r"C:\Windows\... \System32")));
        assert!(path_has_parent_dir(Path::new(r"C:\Windows\....\System32")));
        assert!(path_has_parent_dir(Path::new("..")));
        assert!(path_has_parent_dir(Path::new(r"..\AppData\Local")));
        assert!(path_has_parent_dir(Path::new(r"C:\..\secret")));
    }

    #[test]
    fn test_windows_drive_prefix_validation() {
        assert!(starts_with_valid_drive(Path::new(r"C:\Windows")));
        assert!(starts_with_valid_drive(Path::new("c:/windows")));
        assert!(starts_with_valid_drive(Path::new(r"D:\Program Files")));
        assert!(starts_with_valid_drive(Path::new(r"z:\data")));
        assert!(!starts_with_valid_drive(Path::new(r"1:\data")));
        assert!(!starts_with_valid_drive(Path::new(r"C:relative")));
        assert!(!starts_with_valid_drive(Path::new(r"\\server\share")));
        assert!(!starts_with_valid_drive(Path::new(r"/usr/bin")));
        assert!(!starts_with_valid_drive(Path::new(r"")));
    }

    #[test]
    fn test_windows_drive_path_validation() {
        assert!(is_valid_windows_drive_path(Path::new(r"C:\Program Files")));
        assert!(is_valid_windows_drive_path(Path::new(
            r"C:\Program Files (x86)"
        )));
        assert!(is_valid_windows_drive_path(Path::new("D:/Tools")));
        assert!(!is_valid_windows_drive_path(Path::new(r"C:\")));
        assert!(!is_valid_windows_drive_path(Path::new("C:/")));
        assert!(!is_valid_windows_drive_path(Path::new(
            r"C:\Program Files\..\Evil"
        )));
        assert!(!is_valid_windows_drive_path(Path::new(
            r"C:\Program Files\.. \Evil"
        )));
        assert!(!is_valid_windows_drive_path(Path::new(r"relative\path")));
        assert!(!is_valid_windows_drive_path(Path::new(
            r"\\evil_server\share"
        )));
        assert!(!is_valid_windows_drive_path(Path::new(r"C:relative")));
    }

    #[test]
    fn test_windows_safe_path_validation() {
        assert!(is_safe_windows_path(Path::new(
            r"C:\Users\user\AppData\Local"
        )));
        assert!(is_safe_windows_path(Path::new(
            r"C:\Users\user\AppData\Local\Temp"
        )));
        assert!(!is_safe_windows_path(Path::new(r"C:\")));
        assert!(!is_safe_windows_path(Path::new("C:/")));
        assert!(!is_safe_windows_path(Path::new(r"..\AppData\Local")));
        assert!(!is_safe_windows_path(Path::new(r"C:\Users\..\Sensitive")));
        assert!(!is_safe_windows_path(Path::new(r"C:\Users\.. \Sensitive")));
        assert!(!is_safe_windows_path(Path::new(r"C:\Users\... \Sensitive")));
        assert!(!is_safe_windows_path(Path::new(r"relative\temp")));
        assert!(!is_safe_windows_path(Path::new(r"\\evil_server\share")));
    }

    #[test]
    fn test_windows_system_root_resolution() {
        let fallback = PathBuf::from(r"C:\Windows");

        assert_eq!(resolve_windows_system_root_from(None, |_| true), fallback);
        assert_eq!(
            resolve_windows_system_root_from(Some(""), |_| true),
            fallback
        );
        assert_eq!(
            resolve_windows_system_root_from(Some("   "), |_| true),
            fallback
        );
        assert_eq!(
            resolve_windows_system_root_from(Some(r"C:\"), |_| true),
            fallback
        );

        assert_eq!(
            resolve_windows_system_root_from(Some("relative/path"), |_| true),
            fallback
        );
        assert_eq!(
            resolve_windows_system_root_from(Some(r"C:\Windows\..\Evil"), |_| true),
            fallback
        );
        assert_eq!(
            resolve_windows_system_root_from(Some(r"\\server\share\Windows"), |_| true),
            fallback
        );

        assert_eq!(
            resolve_windows_system_root_from(Some(r"C:\Users\victim"), |_| false),
            fallback
        );

        assert_eq!(
            resolve_windows_system_root_from(Some(r"C:\Windows"), |sys32| {
                sys32.to_string_lossy().ends_with("System32")
            }),
            PathBuf::from(r"C:\Windows")
        );
        assert_eq!(
            resolve_windows_system_root_from(Some(r"D:\CustomWin"), |sys32| {
                sys32.to_string_lossy().ends_with("System32")
            }),
            PathBuf::from(r"D:\CustomWin")
        );
    }

    #[test]
    fn test_windows_system_root_env_fallback() {
        let check_sys32 = |p: &Path| {
            let s = p.to_string_lossy();
            (s.starts_with(r"C:\Windows") || s.starts_with(r"D:\RealWin"))
                && s.ends_with("System32")
        };

        // When SystemRoot is valid, use it:
        assert_eq!(
            resolve_windows_system_root_with(Some(r"C:\Windows"), Some(r"D:\Win"), check_sys32),
            PathBuf::from(r"C:\Windows")
        );

        // When SystemRoot is poisoned, fall back to windir:
        assert_eq!(
            resolve_windows_system_root_with(
                Some(r"C:\Users\victim"),
                Some(r"D:\RealWin"),
                check_sys32
            ),
            PathBuf::from(r"D:\RealWin")
        );

        // When both are poisoned, fall back to canonical C:\Windows:
        assert_eq!(
            resolve_windows_system_root_with(Some(r"C:\Users\victim"), Some(r"C:\Evil"), |_| false),
            PathBuf::from(r"C:\Windows")
        );
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
        #[cfg(unix)]
        {
            let resolved = resolve_in_path("sh");
            assert!(resolved.is_ok());

            let direct = resolve_in_path("/bin/sh");
            assert!(direct.is_ok());
            assert_eq!(direct.unwrap(), PathBuf::from("/bin/sh"));
        }

        #[cfg(windows)]
        {
            let resolved = resolve_in_path("cmd");
            assert!(resolved.is_ok());

            let resolved_exe = resolve_in_path("cmd.exe");
            assert!(resolved_exe.is_ok());

            let comspec = std::env::var("COMSPEC")
                .unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".into());
            let direct = resolve_in_path(&comspec);
            assert!(direct.is_ok());
        }

        let nonexistent = resolve_in_path("non_existent_binary_xyz_12345");
        assert!(nonexistent.is_err());
    }
}
