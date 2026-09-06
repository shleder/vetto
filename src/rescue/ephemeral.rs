//! Ephemeral Disposable Sandbox Engine.
//!
//! Provides automatic rollback on failure/cancellation and interactive/flag-based
//! workspace application on success, protecting projects from speculative agent mutations.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;

fn find_snapshot_archive(session_id: &str) -> Option<PathBuf> {
    let direct = Path::new(session_id);
    if direct.is_file() {
        return Some(direct.to_path_buf());
    }
    if let Ok(root) = crate::rescue::snapshot::snapshots_root_dir() {
        let candidate = root.join(session_id).join("snapshot.tar");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if let Ok(snapshots) = crate::rescue::snapshot::list_snapshots() {
        for s in snapshots {
            if s.session_id == session_id && s.archive_file.is_file() {
                return Some(s.archive_file);
            }
        }
    }
    None
}

fn print_change_preview(session_id: &str, project_dir: &Path) {
    let Some(archive) = find_snapshot_archive(session_id) else {
        return;
    };
    let telemetry = crate::cli::diff::SecurityTelemetry::default();
    let Ok(review) = crate::cli::diff::compare_snapshot_against_disk(
        &archive,
        project_dir,
        None,
        &telemetry,
        session_id,
    ) else {
        return;
    };

    let mut added = 0usize;
    let mut modified = 0usize;
    let mut deleted = 0usize;
    for file in &review.files {
        match file.change_type {
            crate::cli::diff::ChangeType::Added => added += 1,
            crate::cli::diff::ChangeType::Modified => modified += 1,
            crate::cli::diff::ChangeType::Deleted => deleted += 1,
        }
    }

    if added == 0 && modified == 0 && deleted == 0 {
        eprintln!("[VETTO EPHEMERAL] No filesystem changes detected.");
    } else {
        eprintln!(
            "[VETTO EPHEMERAL] Changes: {modified} modified, {added} added, {deleted} deleted"
        );
    }
}

/// Handle post-session ephemeral actions: auto-rollback on failure/force-discard,
/// or prompt user / auto-accept on session success.
pub fn handle_ephemeral_completion(
    session_id: &str,
    project_dir: &Path,
    exit_code: i32,
    auto_accept: bool,
    force_discard: bool,
) -> Result<()> {
    if force_discard || exit_code != 0 {
        crate::rescue::snapshot::rollback_snapshot(session_id, Some(project_dir))?;
        eprintln!(
            "[VETTO EPHEMERAL] Session ended (exit {exit_code}). \
             Working tree automatically restored to clean pre-session state."
        );
        return Ok(());
    }

    // exit_code == 0
    if auto_accept {
        eprintln!("[VETTO EPHEMERAL] Session succeeded. Changes kept in workspace.");
        return Ok(());
    }

    if std::io::stdin().is_terminal() {
        print_change_preview(session_id, project_dir);
        eprint!("[VETTO EPHEMERAL] Apply changes to workspace? [Y/n]: ");
        let _ = std::io::stderr().flush();

        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        let trimmed = input.trim();
        if trimmed.eq_ignore_ascii_case("n") || trimmed.eq_ignore_ascii_case("no") {
            crate::rescue::snapshot::rollback_snapshot(session_id, Some(project_dir))?;
            eprintln!("[VETTO EPHEMERAL] Changes discarded. Working tree restored to clean state.");
        } else {
            eprintln!("[VETTO EPHEMERAL] Changes kept in workspace.");
        }
    } else {
        // Non-interactive (piped / CI): default to keeping changes on exit 0
        eprintln!("[VETTO EPHEMERAL] Changes kept in workspace.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue::snapshot::{create_snapshot, DEFAULT_MAX_SNAPSHOT_SIZE};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-ephem-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_ephemeral_discards_on_failure() {
        let project_dir = temp_test_dir("fail");
        let file_path = project_dir.join("code.rs");
        fs::write(&file_path, "fn main() { /* clean */ }\n").unwrap();

        let session_id = format!(
            "test-fail-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        create_snapshot(&project_dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE).unwrap();

        // Mutate file to simulate agent failure state
        fs::write(&file_path, "fn main() { /* broken */ }\n").unwrap();
        assert_eq!(
            fs::read_to_string(&file_path).unwrap(),
            "fn main() { /* broken */ }\n"
        );

        // Fail with exit code 1
        handle_ephemeral_completion(&session_id, &project_dir, 1, false, false).unwrap();

        // Working tree restored
        assert_eq!(
            fs::read_to_string(&file_path).unwrap(),
            "fn main() { /* clean */ }\n"
        );

        let _ = fs::remove_dir_all(&project_dir);
        if let Ok(root) = crate::rescue::snapshot::snapshots_root_dir() {
            let _ = fs::remove_dir_all(root.join(&session_id));
        }
    }

    #[test]
    fn test_ephemeral_force_discard() {
        let project_dir = temp_test_dir("force");
        let file_path = project_dir.join("code.rs");
        fs::write(&file_path, "fn main() { /* original */ }\n").unwrap();

        let session_id = format!(
            "test-force-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        create_snapshot(&project_dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE).unwrap();

        // Mutate file
        fs::write(&file_path, "fn main() { /* unwanted */ }\n").unwrap();

        // Force discard even with exit code 0
        handle_ephemeral_completion(&session_id, &project_dir, 0, false, true).unwrap();

        // Working tree restored
        assert_eq!(
            fs::read_to_string(&file_path).unwrap(),
            "fn main() { /* original */ }\n"
        );

        let _ = fs::remove_dir_all(&project_dir);
        if let Ok(root) = crate::rescue::snapshot::snapshots_root_dir() {
            let _ = fs::remove_dir_all(root.join(&session_id));
        }
    }

    #[test]
    fn test_ephemeral_auto_accept() {
        let project_dir = temp_test_dir("accept");
        let file_path = project_dir.join("code.rs");
        fs::write(&file_path, "fn main() { /* original */ }\n").unwrap();

        let session_id = format!(
            "test-accept-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        create_snapshot(&project_dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE).unwrap();

        // Mutate file
        fs::write(&file_path, "fn main() { /* good changes */ }\n").unwrap();

        // auto_accept is true with exit code 0
        handle_ephemeral_completion(&session_id, &project_dir, 0, true, false).unwrap();

        // Changes are kept
        assert_eq!(
            fs::read_to_string(&file_path).unwrap(),
            "fn main() { /* good changes */ }\n"
        );

        let _ = fs::remove_dir_all(&project_dir);
        if let Ok(root) = crate::rescue::snapshot::snapshots_root_dir() {
            let _ = fs::remove_dir_all(root.join(&session_id));
        }
    }
}
