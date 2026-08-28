//! Fast native shim dispatcher & recursion barrier (Step 15).
//!
//! When developer tools are invoked through transparent shims (e.g. `git`, `node`, `cargo`),
//! this module intercepts execution, prevents recursive sandbox nesting via `VETTO_SANDBOXED=1`,
//! discovers project policy, and delegates to the real host binary.

pub mod registry;

use anyhow::{bail, Context, Result};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Environment variable set to indicate execution inside an active Vetto sandbox.
pub const ENV_VETTO_SANDBOXED: &str = "VETTO_SANDBOXED";

/// Environment variable set to prevent nested shim interception.
pub const ENV_VETTO_SHIM_ACTIVE: &str = "VETTO_SHIM_ACTIVE";

/// Check if the current process is already running in a sandboxed or shim-active context.
pub fn is_sandboxed() -> bool {
    env::var(ENV_VETTO_SANDBOXED)
        .map(|v| v == "1")
        .unwrap_or(false)
        || env::var(ENV_VETTO_SHIM_ACTIVE)
            .map(|v| v == "1")
            .unwrap_or(false)
}

/// Detects if `vetto` was invoked as a shim via `argv[0]` (e.g., symlinked or renamed).
pub fn detect_argv0_shim() -> Option<String> {
    let arg0 = env::args_os().next()?;
    let path = PathBuf::from(arg0);
    let stem = path.file_stem()?.to_string_lossy().to_string();

    if stem == "vetto" || stem == "vetto-shim" || stem == "__vetto" {
        None
    } else {
        Some(stem)
    }
}

/// Finds the real host binary on `$PATH`, strictly excluding Vetto shim directories
/// to eliminate circular interception loops.
pub fn find_real_binary(name: &str) -> Result<PathBuf> {
    let name_path = Path::new(name);
    if name_path.is_absolute() && is_executable_file(name_path) && !is_shim_path(name_path) {
        return Ok(name_path.to_path_buf());
    }

    let path_var = env::var_os("PATH").context("PATH environment variable is not set")?;
    let paths = env::split_paths(&path_var);

    let current_exe = env::current_exe().ok();

    for dir in paths {
        if is_shim_directory(&dir) {
            continue;
        }

        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            // Ensure we don't resolve to our own current executable
            if let Some(ref current) = current_exe {
                if let (Ok(c1), Ok(c2)) = (candidate.canonicalize(), current.canonicalize()) {
                    if c1 == c2 {
                        continue;
                    }
                }
            }
            return Ok(candidate);
        }

        #[cfg(windows)]
        {
            let pathext = env::var_os("PATHEXT").unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
            for ext in pathext.to_string_lossy().split(';') {
                let ext = ext.trim().trim_start_matches('.');
                if ext.is_empty() {
                    continue;
                }
                let ext_candidate = candidate.with_extension(ext);
                if is_executable_file(&ext_candidate) {
                    return Ok(ext_candidate);
                }
            }
        }
    }

    bail!("could not locate real host binary for '{name}' outside Vetto shims in PATH")
}

/// Checks if a directory path belongs to a Vetto shims directory.
pub fn is_shim_directory(dir: &Path) -> bool {
    let s = dir.to_string_lossy();
    s.contains(".vetto/shims")
        || s.contains(".vetto\\shims")
        || s.ends_with("/vetto/shims")
        || s.ends_with("\\vetto\\shims")
        || s.contains(".vetto/git-hooks")
        || s.contains(".vetto\\git-hooks")
}

/// Checks if a file path is located in a Vetto shims directory.
pub fn is_shim_path(path: &Path) -> bool {
    if let Some(parent) = path.parent() {
        is_shim_directory(parent)
    } else {
        false
    }
}

/// Discovers the nearest project root starting from current directory upwards.
pub fn find_project_root() -> Option<PathBuf> {
    let mut curr = env::current_dir().ok()?;
    loop {
        if curr.join(".vetto").is_dir()
            || curr.join(".vetto.toml").is_file()
            || curr.join("vetto.toml").is_file()
            || curr.join(".git").exists()
            || curr.join("Cargo.toml").is_file()
            || curr.join("package.json").is_file()
            || curr.join("pyproject.toml").is_file()
            || curr.join("go.mod").is_file()
        {
            return Some(curr);
        }
        if !curr.pop() {
            break;
        }
    }
    None
}

/// Fast native dispatch entrypoint for shimmed binaries.
pub fn dispatch(binary_name: &str, args: &[String]) -> Result<i32> {
    let real_binary = find_real_binary(binary_name)
        .with_context(|| format!("shim: failed to resolve host binary for '{binary_name}'"))?;

    if is_sandboxed() {
        // Recursion barrier active — execute real binary directly with zero overhead
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let err = Command::new(&real_binary).args(args).exec();
            bail!(
                "failed to exec real binary {}: {err}",
                real_binary.display()
            );
        }

        #[cfg(not(unix))]
        {
            let mut child = Command::new(&real_binary).args(args).spawn()?;
            let status = child.wait()?;
            return Ok(status.code().unwrap_or(1));
        }
    }

    // Not sandboxed yet: execute under Vetto sandbox supervisor
    let vetto_exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("vetto"));

    let mut supervisor_cmd = Command::new(vetto_exe);
    supervisor_cmd.env(ENV_VETTO_SANDBOXED, "1");
    supervisor_cmd.env(ENV_VETTO_SHIM_ACTIVE, "1");

    supervisor_cmd.arg("--");
    supervisor_cmd.arg(&real_binary);
    supervisor_cmd.args(args);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = supervisor_cmd.exec();
        bail!("failed to exec vetto supervisor: {err}");
    }

    #[cfg(not(unix))]
    {
        let mut child = supervisor_cmd.spawn()?;
        let status = child.wait()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// Entrypoint for the `vetto shim` subcommand.
pub fn run_cli(binary: Option<String>, args: Vec<String>) -> Result<()> {
    let target = match binary {
        Some(b) => b,
        None => {
            if let Some(detected) = detect_argv0_shim() {
                detected
            } else {
                bail!("no target binary specified for shim execution; usage: vetto shim <binary> -- [args...]");
            }
        }
    };

    let code = dispatch(&target, &args)?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn is_executable_file(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(p) {
            Ok(m) => m.is_file() && (m.permissions().mode() & 0o111) != 0,
            Err(_) => false,
        }
    }
    #[cfg(windows)]
    {
        p.is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_shim_directory_patterns() {
        assert!(is_shim_directory(Path::new("/home/user/.vetto/shims")));
        assert!(is_shim_directory(Path::new(
            "C:\\Users\\user\\.vetto\\shims"
        )));
        assert!(is_shim_directory(Path::new("/repo/.vetto/shims")));
        assert!(!is_shim_directory(Path::new("/usr/bin")));
        assert!(!is_shim_directory(Path::new("/home/user/.cargo/bin")));
    }

    #[test]
    fn recursion_barrier_checks_environment() {
        env::remove_var(ENV_VETTO_SANDBOXED);
        env::remove_var(ENV_VETTO_SHIM_ACTIVE);
        assert!(!is_sandboxed());

        env::set_var(ENV_VETTO_SANDBOXED, "1");
        assert!(is_sandboxed());
        env::remove_var(ENV_VETTO_SANDBOXED);

        env::set_var(ENV_VETTO_SHIM_ACTIVE, "1");
        assert!(is_sandboxed());
        env::remove_var(ENV_VETTO_SHIM_ACTIVE);
    }

    #[test]
    fn finds_real_system_binary_such_as_sh() {
        #[cfg(unix)]
        {
            let sh_path = find_real_binary("sh");
            assert!(sh_path.is_ok(), "sh should be present in standard PATH");
            let p = sh_path.unwrap();
            assert!(p.exists());
            assert!(!is_shim_directory(p.parent().unwrap()));
        }
    }
}
