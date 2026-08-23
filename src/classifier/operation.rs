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
    let extension = p
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("sh") | Some("bash") | Some("zsh") | Some("exe") | Some("bin") => Operation::Exec,
        _ => Operation::FsRead,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_extensions_without_touching_the_filesystem() {
        assert_eq!(classify_path("/tmp/run.SH"), Operation::Exec);
        assert_eq!(classify_path("/tmp/tool.BIN"), Operation::Exec);
        assert_eq!(classify_path("/tmp/project/src"), Operation::FsRead);
    }
}
