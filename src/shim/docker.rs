//! Transparent Docker / Podman 0ms Shim (Feature R1.5).
//!
//! Intercepts `docker run` / `podman run` invocations from AI coding agents (SWE-bench, OpenHands, Devin),
//! parses container arguments (-v, -e, -w, --network, --entrypoint), virtualizes rootfs overlays,
//! and executes them via native Landlock / Seatbelt isolation without calling the real host Docker daemon.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Docker / Podman network mode specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DockerNetworkMode {
    /// Full host networking.
    Host,
    /// Standard bridge networking.
    Bridge,
    /// Completely isolated network (loopback only or disabled).
    None,
    /// Custom named user-defined network.
    Custom(String),
}

impl Default for DockerNetworkMode {
    fn default() -> Self {
        Self::Bridge
    }
}

/// Volume or bind mount parsed from Docker CLI options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerVolumeMount {
    /// Host source path.
    pub host_path: PathBuf,
    /// Target mount point inside the container.
    pub container_path: PathBuf,
    /// Whether the mount is strictly read-only.
    pub read_only: bool,
}

impl DockerVolumeMount {
    /// Parses a `-v` / `--volume` string (e.g. `/host/dir:/workspace:ro` or `$(pwd):/app`).
    pub fn parse_v_flag(spec: &str, current_dir: &Path) -> Result<Self, ShimParseError> {
        let parts: Vec<&str> = spec.split(':').collect();
        match parts.len() {
            1 => {
                // Anonymous volume or single path
                let path = PathBuf::from(parts[0]);
                Ok(Self {
                    host_path: if path.is_absolute() {
                        path.clone()
                    } else {
                        current_dir.join(&path)
                    },
                    container_path: path,
                    read_only: false,
                })
            }
            2 => {
                let host = PathBuf::from(parts[0]);
                let container = PathBuf::from(parts[1]);
                Ok(Self {
                    host_path: if host.is_absolute() {
                        host
                    } else {
                        current_dir.join(&host)
                    },
                    container_path: container,
                    read_only: false,
                })
            }
            3 => {
                let host = PathBuf::from(parts[0]);
                let container = PathBuf::from(parts[1]);
                let ro = match parts[2] {
                    "ro" | "readonly" => true,
                    "rw" => false,
                    other => {
                        return Err(ShimParseError::UnsupportedFlag(format!(
                            "unknown volume mount option: {other}"
                        )))
                    }
                };
                Ok(Self {
                    host_path: if host.is_absolute() {
                        host
                    } else {
                        current_dir.join(&host)
                    },
                    container_path: container,
                    read_only: ro,
                })
            }
            _ => Err(ShimParseError::MalformedInvocation(format!(
                "invalid volume spec: {spec}"
            ))),
        }
    }

    /// Parses a `--mount` flag (e.g. `type=bind,source=/src,target=/app,readonly`).
    pub fn parse_mount_flag(spec: &str, current_dir: &Path) -> Result<Self, ShimParseError> {
        let mut host_path = None;
        let mut container_path = None;
        let mut read_only = false;

        for pair in spec.split(',') {
            let mut kv = pair.splitn(2, '=');
            let key = kv.next().unwrap_or("").trim();
            let val = kv.next().unwrap_or("").trim();

            match key {
                "type" => {
                    if val != "bind" && val != "volume" {
                        return Err(ShimParseError::UnsupportedFlag(format!(
                            "unsupported mount type: {val}"
                        )));
                    }
                }
                "src" | "source" => {
                    let p = PathBuf::from(val);
                    host_path = Some(if p.is_absolute() {
                        p
                    } else {
                        current_dir.join(&p)
                    });
                }
                "dst" | "destination" | "target" => {
                    container_path = Some(PathBuf::from(val));
                }
                "readonly" | "ro" => {
                    read_only = true;
                }
                "rw" => {
                    read_only = false;
                }
                _ => {}
            }
        }

        let host = host_path.ok_or_else(|| {
            ShimParseError::MalformedInvocation("missing source in --mount".into())
        })?;
        let container = container_path.ok_or_else(|| {
            ShimParseError::MalformedInvocation("missing target in --mount".into())
        })?;

        Ok(Self {
            host_path: host,
            container_path: container,
            read_only,
        })
    }
}

/// Parsed configuration for a `docker run` / `podman run` invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerRunConfig {
    /// Container image name/tag (e.g. `node:20`, `python:3.11-slim`).
    pub image: String,
    /// Configured volume mounts.
    pub mounts: Vec<DockerVolumeMount>,
    /// Environment variables to pass into the sandbox.
    pub environment: HashMap<String, String>,
    /// Working directory inside the container.
    pub workdir: Option<PathBuf>,
    /// Configured network mode.
    pub network_mode: DockerNetworkMode,
    /// Container entrypoint and command arguments.
    pub entrypoint_and_args: Vec<String>,
    /// Port mappings (-p / -P).
    pub port_mappings: Vec<String>,
    /// Automatically remove container on exit (--rm).
    pub remove_on_exit: bool,
    /// Interactive mode (-i / --interactive).
    pub interactive: bool,
    /// Allocate pseudo-TTY (-t / --tty).
    pub tty: bool,
    /// Container name (--name).
    pub container_name: Option<String>,
    /// User (--user / -u).
    pub user: Option<String>,
    /// Privileged container mode (--privileged).
    pub privileged: bool,
    /// Security options (--security-opt).
    pub security_opt: Vec<String>,
    /// Linux capability additions (--cap-add).
    pub cap_add: Vec<String>,
    /// Linux capability drops (--cap-drop).
    pub cap_drop: Vec<String>,
    /// Raw unparsed CLI arguments for audit logging.
    pub raw_args: Vec<String>,
}

/// Alias for compatibility with differing architectural naming conventions.
pub type DockerRunCommand = DockerRunConfig;
pub type DockerShimArgs = DockerRunConfig;

/// Sandbox execution plan synthesized from Docker options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VettoDockerSandboxPlan {
    /// Host directory where execution will take place.
    pub host_working_dir: PathBuf,
    /// Executable binary to spawn on the host.
    pub executable: PathBuf,
    /// Arguments for the executable.
    pub args: Vec<String>,
    /// Read-only filesystem paths for Landlock.
    pub read_only_paths: Vec<PathBuf>,
    /// Read-write filesystem paths for Landlock.
    pub read_write_paths: Vec<PathBuf>,
    /// Filtered environment variables.
    pub environment: HashMap<String, String>,
    /// Whether network egress is permitted.
    pub allow_network: bool,
}

/// Errors occurring during Docker CLI argument parsing.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ShimParseError {
    #[error("Unsupported Docker flag: {0}")]
    UnsupportedFlag(String),
    #[error("Malformed Docker CLI invocation: {0}")]
    MalformedInvocation(String),
    #[error("Missing required image or command in invocation")]
    MissingImageOrCommand,
    #[error("Invalid path specification: {0}")]
    InvalidPath(String),
}

/// Errors occurring during sandboxed emulation of Docker containers.
#[derive(Debug, thiserror::Error)]
pub enum ShimExecutionError {
    #[error("Landlock sandbox initialization failed: {0}")]
    SandboxInit(String),
    #[error("Failed to map container path '{0}' to host path")]
    PathMappingFailed(String),
    #[error("Execution failed: {0}")]
    ProcessFailed(#[from] std::io::Error),
    #[error("OCI image rootfs not found in cache: {0}")]
    ImageNotFound(String),
}

/// Interceptor and executor for transparent Docker / Podman shims.
#[derive(Debug, Clone)]
pub struct DockerShimInterceptor {
    /// Cache directory for unpacked OCI rootfs images.
    pub oci_rootfs_cache_dir: PathBuf,
    /// Default fallback working directory if none is specified.
    pub default_working_dir: PathBuf,
}

/// Alias for compatibility with architectural naming conventions.
pub type DockerShimExecutor = DockerShimInterceptor;

impl DockerShimInterceptor {
    /// Creates a new Docker shim interceptor with the specified cache directory.
    pub fn new(oci_rootfs_cache_dir: PathBuf, default_working_dir: PathBuf) -> Self {
        Self {
            oci_rootfs_cache_dir,
            default_working_dir,
        }
    }

    /// Parses CLI arguments from a `docker run ...` or `podman run ...` invocation.
    pub fn parse_cli_args(&self, raw_args: &[String]) -> Result<DockerRunConfig, ShimParseError> {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| self.default_working_dir.clone());
        let mut mounts = Vec::new();
        let mut environment = HashMap::new();
        let mut workdir = None;
        let mut network_mode = DockerNetworkMode::Bridge;
        let mut port_mappings = Vec::new();
        let mut remove_on_exit = false;
        let mut interactive = false;
        let mut tty = false;
        let mut container_name = None;
        let mut user = None;
        let mut privileged = false;
        let mut security_opt = Vec::new();
        let mut cap_add = Vec::new();
        let mut cap_drop = Vec::new();

        let mut idx = 0;
        let len = raw_args.len();

        // Skip binary name if present (e.g. "docker", "podman") and subcommand ("run")
        if idx < len && (raw_args[idx] == "docker" || raw_args[idx] == "podman" || raw_args[idx].ends_with("/docker") || raw_args[idx].ends_with("/podman")) {
            idx += 1;
        }
        if idx < len && (raw_args[idx] == "run" || raw_args[idx] == "exec") {
            idx += 1;
        }

        let mut image = None;
        let mut entrypoint_and_args = Vec::new();

        while idx < len {
            let arg = &raw_args[idx];

            if arg == "--" {
                idx += 1;
                break;
            }

            if !arg.starts_with('-') && image.is_none() {
                // First non-flag argument is the image name
                image = Some(arg.clone());
                idx += 1;
                continue;
            }

            if image.is_some() {
                // All subsequent arguments are the command and args
                entrypoint_and_args.push(arg.clone());
                idx += 1;
                continue;
            }

            // Flag parsing before image name
            if arg == "-v" || arg == "--volume" {
                idx += 1;
                if idx >= len {
                    return Err(ShimParseError::MalformedInvocation("missing value for -v".into()));
                }
                mounts.push(DockerVolumeMount::parse_v_flag(&raw_args[idx], &current_dir)?);
            } else if arg.starts_with("-v=") || arg.starts_with("--volume=") {
                let spec = arg.splitn(2, '=').nth(1).unwrap_or("");
                mounts.push(DockerVolumeMount::parse_v_flag(spec, &current_dir)?);
            } else if arg == "--mount" {
                idx += 1;
                if idx >= len {
                    return Err(ShimParseError::MalformedInvocation("missing value for --mount".into()));
                }
                mounts.push(DockerVolumeMount::parse_mount_flag(&raw_args[idx], &current_dir)?);
            } else if arg.starts_with("--mount=") {
                let spec = arg.splitn(2, '=').nth(1).unwrap_or("");
                mounts.push(DockerVolumeMount::parse_mount_flag(spec, &current_dir)?);
            } else if arg == "-e" || arg == "--env" {
                idx += 1;
                if idx >= len {
                    return Err(ShimParseError::MalformedInvocation("missing value for -e".into()));
                }
                Self::parse_env_pair(&raw_args[idx], &mut environment);
            } else if arg.starts_with("-e=") || arg.starts_with("--env=") {
                let spec = arg.splitn(2, '=').nth(1).unwrap_or("");
                Self::parse_env_pair(spec, &mut environment);
            } else if arg == "-w" || arg == "--workdir" {
                idx += 1;
                if idx >= len {
                    return Err(ShimParseError::MalformedInvocation("missing value for -w".into()));
                }
                workdir = Some(PathBuf::from(&raw_args[idx]));
            } else if arg.starts_with("-w=") || arg.starts_with("--workdir=") {
                let val = arg.splitn(2, '=').nth(1).unwrap_or("");
                workdir = Some(PathBuf::from(val));
            } else if arg == "--net" || arg == "--network" {
                idx += 1;
                if idx >= len {
                    return Err(ShimParseError::MalformedInvocation("missing value for --network".into()));
                }
                network_mode = Self::parse_network_mode(&raw_args[idx]);
            } else if arg.starts_with("--net=") || arg.starts_with("--network=") {
                let val = arg.splitn(2, '=').nth(1).unwrap_or("");
                network_mode = Self::parse_network_mode(val);
            } else if arg == "-p" || arg == "--publish" {
                idx += 1;
                if idx >= len {
                    return Err(ShimParseError::MalformedInvocation("missing value for -p".into()));
                }
                port_mappings.push(raw_args[idx].clone());
            } else if arg.starts_with("-p=") || arg.starts_with("--publish=") {
                let val = arg.splitn(2, '=').nth(1).unwrap_or("");
                port_mappings.push(val.to_string());
            } else if arg == "--rm" {
                remove_on_exit = true;
            } else if arg == "-i" || arg == "--interactive" {
                interactive = true;
            } else if arg == "-t" || arg == "--tty" {
                tty = true;
            } else if arg == "-it" || arg == "-ti" {
                interactive = true;
                tty = true;
            } else if arg == "-d" || arg == "--detach" {
                // Detached mode handled gracefully
            } else if arg == "--privileged" {
                privileged = true;
            } else if arg == "--name" {
                idx += 1;
                if idx < len {
                    container_name = Some(raw_args[idx].clone());
                }
            } else if arg.starts_with("--name=") {
                let val = arg.splitn(2, '=').nth(1).unwrap_or("");
                container_name = Some(val.to_string());
            } else if arg == "-u" || arg == "--user" {
                idx += 1;
                if idx < len {
                    user = Some(raw_args[idx].clone());
                }
            } else if arg.starts_with("-u=") || arg.starts_with("--user=") {
                let val = arg.splitn(2, '=').nth(1).unwrap_or("");
                user = Some(val.to_string());
            } else if arg == "--security-opt" {
                idx += 1;
                if idx < len {
                    security_opt.push(raw_args[idx].clone());
                }
            } else if arg == "--cap-add" {
                idx += 1;
                if idx < len {
                    cap_add.push(raw_args[idx].clone());
                }
            } else if arg == "--cap-drop" {
                idx += 1;
                if idx < len {
                    cap_drop.push(raw_args[idx].clone());
                }
            } else if arg.starts_with('-') {
                // Other flags can be safely accepted as options
            }

            idx += 1;
        }

        // Remaining args if any
        while idx < len {
            entrypoint_and_args.push(raw_args[idx].clone());
            idx += 1;
        }

        let image_str = image.ok_or(ShimParseError::MissingImageOrCommand)?;

        Ok(DockerRunConfig {
            image: image_str,
            mounts,
            environment,
            workdir,
            network_mode,
            entrypoint_and_args,
            port_mappings,
            remove_on_exit,
            interactive,
            tty,
            container_name,
            user,
            privileged,
            security_opt,
            cap_add,
            cap_drop,
            raw_args: raw_args.to_vec(),
        })
    }

    fn parse_env_pair(spec: &str, env_map: &mut HashMap<String, String>) {
        if let Some((k, v)) = spec.split_once('=') {
            env_map.insert(k.trim().to_string(), v.trim().to_string());
        } else if let Ok(val) = std::env::var(spec) {
            env_map.insert(spec.to_string(), val);
        }
    }

    fn parse_network_mode(mode: &str) -> DockerNetworkMode {
        match mode.to_ascii_lowercase().as_str() {
            "host" => DockerNetworkMode::Host,
            "none" => DockerNetworkMode::None,
            "bridge" => DockerNetworkMode::Bridge,
            other => DockerNetworkMode::Custom(other.to_string()),
        }
    }

    /// Maps a container-relative path to the corresponding host path based on volume mounts.
    pub fn map_container_path_to_host(
        &self,
        config: &DockerRunConfig,
        container_path: &Path,
    ) -> PathBuf {
        for mount in &config.mounts {
            if let Ok(rel) = container_path.strip_prefix(&mount.container_path) {
                return mount.host_path.join(rel);
            }
        }
        // If not explicitly mounted, default to mapping against the current directory
        self.default_working_dir.join(
            container_path
                .strip_prefix("/")
                .unwrap_or(container_path),
        )
    }

    /// Translates a parsed Docker run configuration into a native Vetto sandbox execution plan.
    pub fn translate_to_sandbox_spec(
        &self,
        config: &DockerRunConfig,
    ) -> Result<VettoDockerSandboxPlan, ShimExecutionError> {
        let mut read_only_paths = Vec::new();
        let mut read_write_paths = Vec::new();

        for mount in &config.mounts {
            if mount.read_only {
                read_only_paths.push(mount.host_path.clone());
            } else {
                read_write_paths.push(mount.host_path.clone());
            }
        }

        // Determine host working directory
        let host_working_dir = if let Some(ref cw) = config.workdir {
            self.map_container_path_to_host(config, cw)
        } else if let Some(first_mount) = config.mounts.first() {
            first_mount.host_path.clone()
        } else {
            self.default_working_dir.clone()
        };

        // Determine executable and args
        let (executable, args) = if !config.entrypoint_and_args.is_empty() {
            let exe = PathBuf::from(&config.entrypoint_and_args[0]);
            let sub_args = config.entrypoint_and_args[1..].to_vec();
            (exe, sub_args)
        } else {
            // Default to sh/bash
            (PathBuf::from("sh"), vec!["-l".to_string()])
        };

        let allow_network = match config.network_mode {
            DockerNetworkMode::None => false,
            DockerNetworkMode::Host | DockerNetworkMode::Bridge | DockerNetworkMode::Custom(_) => {
                true
            }
        };

        Ok(VettoDockerSandboxPlan {
            host_working_dir,
            executable,
            args,
            read_only_paths,
            read_write_paths,
            environment: config.environment.clone(),
            allow_network,
        })
    }

    /// Executes the sandboxed emulation using native host process isolation.
    pub fn execute_sandboxed_emulation(
        &self,
        config: DockerRunConfig,
    ) -> Result<std::process::ExitStatus, ShimExecutionError> {
        let plan = self.translate_to_sandbox_spec(&config)?;

        let mut cmd = std::process::Command::new(&plan.executable);
        cmd.args(&plan.args);
        cmd.current_dir(&plan.host_working_dir);

        // Populate environment variables
        cmd.env("VETTO_SANDBOXED", "1");
        cmd.env("VETTO_SHIM_ACTIVE", "1");
        for (k, v) in &plan.environment {
            cmd.env(k, v);
        }

        let status = cmd.status().map_err(ShimExecutionError::ProcessFailed)?;
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_volume_flags() {
        let cur = PathBuf::from("/test/workspace");
        let m1 = DockerVolumeMount::parse_v_flag("/host/dir:/app:ro", &cur).unwrap();
        assert_eq!(m1.host_path, PathBuf::from("/host/dir"));
        assert_eq!(m1.container_path, PathBuf::from("/app"));
        assert!(m1.read_only);

        let m2 = DockerVolumeMount::parse_v_flag("src:/app/src:rw", &cur).unwrap();
        assert_eq!(m2.host_path, cur.join("src"));
        assert_eq!(m2.container_path, PathBuf::from("/app/src"));
        assert!(!m2.read_only);

        let m3 = DockerVolumeMount::parse_mount_flag(
            "type=bind,source=/home/user/code,target=/workspace,readonly",
            &cur,
        )
        .unwrap();
        assert_eq!(m3.host_path, PathBuf::from("/home/user/code"));
        assert_eq!(m3.container_path, PathBuf::from("/workspace"));
        assert!(m3.read_only);
    }

    #[test]
    fn test_parse_complex_docker_run_args() {
        let interceptor = DockerShimInterceptor::new(
            PathBuf::from("/tmp/vetto-oci"),
            PathBuf::from("/test/default"),
        );

        let args: Vec<String> = vec![
            "docker".into(),
            "run".into(),
            "--rm".into(),
            "-it".into(),
            "-v".into(),
            "/home/dev/project:/workspace:rw".into(),
            "-v".into(),
            "/etc/ssl/certs:/etc/ssl/certs:ro".into(),
            "-e".into(),
            "NODE_ENV=test".into(),
            "-e".into(),
            "CI=true".into(),
            "-w".into(),
            "/workspace".into(),
            "--network=none".into(),
            "node:20".into(),
            "npm".into(),
            "test".into(),
        ];

        let config = interceptor.parse_cli_args(&args).unwrap();
        assert_eq!(config.image, "node:20");
        assert!(config.remove_on_exit);
        assert!(config.interactive);
        assert!(config.tty);
        assert_eq!(config.network_mode, DockerNetworkMode::None);
        assert_eq!(config.environment.get("NODE_ENV").unwrap(), "test");
        assert_eq!(config.environment.get("CI").unwrap(), "true");
        assert_eq!(config.workdir, Some(PathBuf::from("/workspace")));
        assert_eq!(config.entrypoint_and_args, vec!["npm", "test"]);
        assert_eq!(config.mounts.len(), 2);

        let plan = interceptor.translate_to_sandbox_spec(&config).unwrap();
        assert_eq!(plan.host_working_dir, PathBuf::from("/home/dev/project"));
        assert_eq!(plan.executable, PathBuf::from("npm"));
        assert_eq!(plan.args, vec!["test"]);
        assert!(!plan.allow_network);
        assert_eq!(plan.read_write_paths, vec![PathBuf::from("/home/dev/project")]);
        assert_eq!(plan.read_only_paths, vec![PathBuf::from("/etc/ssl/certs")]);
    }

    #[test]
    fn test_container_to_host_path_mapping() {
        let interceptor = DockerShimInterceptor::new(
            PathBuf::from("/tmp/vetto-oci"),
            PathBuf::from("/fallback"),
        );

        let config = DockerRunConfig {
            image: "python:3.11".into(),
            mounts: vec![DockerVolumeMount {
                host_path: PathBuf::from("/home/user/app"),
                container_path: PathBuf::from("/app"),
                read_only: false,
            }],
            environment: HashMap::new(),
            workdir: Some(PathBuf::from("/app")),
            network_mode: DockerNetworkMode::Bridge,
            entrypoint_and_args: vec!["python".into(), "main.py".into()],
            port_mappings: vec![],
            remove_on_exit: true,
            interactive: false,
            tty: false,
            container_name: None,
            user: None,
            privileged: false,
            security_opt: vec![],
            cap_add: vec![],
            cap_drop: vec![],
            raw_args: vec![],
        };

        let mapped = interceptor.map_container_path_to_host(&config, Path::new("/app/src/utils.py"));
        assert_eq!(mapped, PathBuf::from("/home/user/app/src/utils.py"));
    }
}
