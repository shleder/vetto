use thiserror::Error;

#[derive(Error, Debug)]
pub enum VettoError {
    #[error("landlock: {0}")]
    Landlock(String),
    #[error("namespace operation failed: {0}")]
    Namespace(String),
    #[error("mount operation failed: {0}")]
    Mount(String),
    #[error("seccomp: {0}")]
    Seccomp(String),
    #[error("sandbox setup failed: {0}")]
    Sandbox(String),
    #[error("pty error: {0}")]
    Pty(String),
    #[error("policy error: {0}")]
    Policy(String),
    #[error("{0} is not supported by vetto v0.1 (see SECURITY.md roadmap)")]
    UnsupportedPlatform(&'static str),
}

pub type VettoResult<T> = Result<T, VettoError>;
