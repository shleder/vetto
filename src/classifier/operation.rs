//! Coarse classification of observed operations for stats and reports.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    FsRead,
    FsWrite,
    Exec,
    Net,
    Other,
}

impl Operation {
    pub fn label(&self) -> &'static str {
        match self {
            Operation::FsRead => "fs-read",
            Operation::FsWrite => "fs-write",
            Operation::Exec => "exec",
            Operation::Net => "net",
            Operation::Other => "other",
        }
    }
}

/// Best-effort classification of a filesystem path by extension.
pub fn classify_path(path: &str) -> Operation {
    let p = Path::new(path);
    if p.is_dir() {
        return Operation::FsRead;
    }
    match p.extension().and_then(|e| e.to_str()) {
        Some("sh") | Some("bash") | Some("zsh") | Some("exe") | Some("bin") => Operation::Exec,
        _ => Operation::FsRead,
    }
}
