//! Read-only Claude Code transcript adapter.
//!
//! Claude Code's on-disk state is intentionally treated as an opaque JSONL
//! transcript.  The adapter understands only the stable outer layout that is
//! useful for recovery (`projects`, `sessions`, and `archived_sessions` under
//! an explicitly supplied state root).  It does not interpret, rewrite, or
//! reconstruct provider state.  In particular, credentials and settings are
//! never discovery candidates, and snapshot/fork are copy-only operations.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::report;

use super::adapter::RescueAdapter;
use super::types::{
    AdapterStatus, Availability, RescueContext, SessionHealth, SessionRef, SessionView,
    SnapshotReceipt,
};

/// Claude state is only supported when the caller supplies the state root.
/// We deliberately do not infer a home directory here: an implicit home root
/// could cause a recovery command to traverse unrelated credentials.
pub struct ClaudeAdapter;

const KNOWN_STATE_DIRS: [&str; 3] = ["projects", "sessions", "archived_sessions"];

impl ClaudeAdapter {
    fn validate_root(context: &RescueContext) -> Result<PathBuf> {
        let metadata = fs::symlink_metadata(&context.root)
            .with_context(|| format!("inspect Claude state root {}", context.root.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "Claude state root must be a real directory, not a symlink: {}",
                context.root.display()
            );
        }
        fs::canonicalize(&context.root)
            .with_context(|| format!("canonicalize Claude state root {}", context.root.display()))
    }

    fn is_known_directory_name(name: &str) -> bool {
        KNOWN_STATE_DIRS.contains(&name)
    }

    /// Return canonical, non-symlink roots that are known to contain
    /// transcript files.  An explicitly supplied `--root` may point at the
    /// `.claude` directory or directly at one of its named state directories.
    fn canonical_session_roots(context: &RescueContext) -> Result<Vec<PathBuf>> {
        let canonical_root = Self::validate_root(context)?;
        let mut candidates = Vec::new();

        if let Some(name) = canonical_root.file_name().and_then(|name| name.to_str()) {
            if Self::is_known_directory_name(name) {
                candidates.push(canonical_root.clone());
            }
        }

        for name in KNOWN_STATE_DIRS {
            let path = canonical_root.join(name);
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                continue;
            }
            let canonical = fs::canonicalize(&path)
                .with_context(|| format!("canonicalize Claude state directory {}", path.display()))?;
            if canonical.starts_with(&canonical_root) {
                candidates.push(canonical);
            }
        }

        candidates.sort();
        candidates.dedup();
        Ok(candidates)
    }

    fn normalized_relative(context: &RescueContext, path: &Path) -> Result<String> {
        let canonical_root = Self::validate_root(context)?;
        let relative = path.strip_prefix(&canonical_root).with_context(|| {
            format!(
                "Claude transcript {} is outside state root",
                path.display()
            )
        })?;
        Ok(relative.to_string_lossy().replace('\\', "/"))
    }

    fn is_credential_path(path: &Path) -> bool {
        // These names are not transcript state.  Keep this deny-list even
        // though the normal scanner accepts only JSONL, because future
        // layout changes must not accidentally turn a credential file into a
        // recovery candidate. Only the final three path components are
        // inspected so a user's home directory named `secrets` does not
        // cause every transcript to be rejected.
        path.iter().rev().take(3).any(|component| {
            let name = component.to_string_lossy().to_ascii_lowercase();
            matches!(
                name.as_str(),
                ".credentials.json"
                    | "credentials.json"
                    | "credentials.jsonl"
                    | "auth.json"
                    | "oauth.json"
                    | "tokens.json"
                    | "token.json"
                    | "settings.json"
                    | "settings.local.json"
            ) || name.contains("credential")
                || name.contains("secret")
        })
    }

    fn sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    fn validate_session_path(context: &RescueContext, path: &Path) -> Result<PathBuf> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect Claude transcript {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("Claude transcript must be a regular non-symlink file");
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 {
            bail!("Claude transcript hardlinks are not accepted");
        }
        if metadata.len() > context.max_session_bytes {
            bail!(
                "Claude transcript exceeds the {} byte inspection budget",
                context.max_session_bytes
            );
        }
        let canonical = fs::canonicalize(path)
            .with_context(|| format!("canonicalize Claude transcript {}", path.display()))?;
        if Self::is_credential_path(&canonical) {
            bail!("credential-shaped Claude state is not readable");
        }
        let roots = Self::canonical_session_roots(context)?;
        if !roots.iter().any(|root| canonical.starts_with(root)) {
            bail!("Claude transcript is outside the configured state directories");
        }
        Ok(canonical)
    }

    fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
        let file = File::open(path)?;
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            bail!("Claude transcript grew beyond the inspection budget while reading");
        }
        Ok(bytes)
    }

    fn read_stable(context: &RescueContext, path: &Path) -> Result<Vec<u8>> {
        let canonical = Self::validate_session_path(context, path)?;
        let first = Self::read_bounded(&canonical, context.max_session_bytes)
            .with_context(|| format!("read Claude transcript {}", canonical.display()))?;
        let second = Self::read_bounded(&canonical, context.max_session_bytes)
            .with_context(|| format!("re-read Claude transcript {}", canonical.display()))?;
        if Self::sha256(&first) != Self::sha256(&second) {
            bail!("Claude transcript changed while being read; retry after the writer stops");
        }
        Ok(first)
    }

    fn scan_directory(
        context: &RescueContext,
        root: &Path,
        sessions: &mut Vec<SessionRef>,
        total_bytes: &mut u64,
        entries_seen: &mut usize,
    ) -> Result<()> {
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            let mut entries = fs::read_dir(&directory)
                .with_context(|| format!("scan Claude state directory {}", directory.display()))?
                .collect::<std::io::Result<Vec<_>>>()?;
            entries.sort_by_key(|entry| entry.path());
            for entry in entries {
                *entries_seen = entries_seen
                    .checked_add(1)
                    .context("Claude entry counter overflow")?;
                if *entries_seen > context.max_files {
                    bail!(
                        "Claude discovery exceeded the {} entry budget",
                        context.max_files
                    );
                }

                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() || Self::is_credential_path(&path) {
                    continue;
                }
                if metadata.is_dir() {
                    let canonical = match fs::canonicalize(&path) {
                        Ok(canonical) if canonical.starts_with(root) => canonical,
                        _ => continue,
                    };
                    pending.push(canonical);
                    continue;
                }
                if !metadata.is_file()
                    || path.extension().and_then(|ext| ext.to_str()) != Some("jsonl")
                {
                    continue;
                }
                #[cfg(unix)]
                if metadata.nlink() != 1 {
                    continue;
                }
                let canonical = match fs::canonicalize(&path) {
                    Ok(canonical) if canonical.starts_with(root) => canonical,
                    _ => continue,
                };
                if Self::is_credential_path(&canonical) {
                    continue;
                }
                *total_bytes = total_bytes
                    .checked_add(metadata.len())
                    .context("Claude transcript byte counter overflow")?;
                if *total_bytes > context.max_total_bytes {
                    bail!(
                        "Claude discovery exceeded the {} byte budget",
                        context.max_total_bytes
                    );
                }
                let relative_path = Self::normalized_relative(context, &canonical)?;
                let modified_unix_secs = metadata
                    .modified()
                    .ok()
                    .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
                    .map(|duration| duration.as_secs());
                sessions.push(SessionRef {
                    adapter: "claude".to_string(),
                    key: relative_path.clone(),
                    relative_path,
                    bytes: metadata.len(),
                    modified_unix_secs,
                    source_path: canonical,
                });
            }
        }
        Ok(())
    }
}

impl RescueAdapter for ClaudeAdapter {
    fn id(&self) -> &'static str {
        "claude"
    }

    fn detect(&self, context: &RescueContext) -> Result<AdapterStatus> {
        match Self::canonical_session_roots(context) {
            Ok(roots) if !roots.is_empty() => Ok(AdapterStatus {
                adapter: self.id().to_string(),
                availability: Availability::Available,
                support_level: "rescue-only".to_string(),
                reason: Some(
                    "Claude JSONL is treated as opaque; only bounded copy-based recovery is supported"
                        .to_string(),
                ),
            }),
            Ok(_) => Ok(AdapterStatus {
                adapter: self.id().to_string(),
                availability: Availability::Unavailable,
                support_level: "unsupported".to_string(),
                reason: Some(
                    "no supported Claude projects/sessions JSONL directory was found under the explicit root"
                        .to_string(),
                ),
            }),
            Err(error) => Ok(AdapterStatus {
                adapter: self.id().to_string(),
                availability: Availability::Unavailable,
                support_level: "unsupported".to_string(),
                reason: Some(error.to_string()),
            }),
        }
    }

    fn discover_sessions(&self, context: &RescueContext) -> Result<Vec<SessionRef>> {
        Self::validate_root(context)?;
        let mut sessions = Vec::new();
        let mut total_bytes = 0u64;
        let mut entries_seen = 0usize;
        for root in Self::canonical_session_roots(context)? {
            Self::scan_directory(
                context,
                &root,
                &mut sessions,
                &mut total_bytes,
                &mut entries_seen,
            )?;
        }
        sessions.sort_by(|left, right| {
            right
                .modified_unix_secs
                .cmp(&left.modified_unix_secs)
                .then_with(|| left.key.cmp(&right.key))
        });
        Ok(sessions)
    }

    fn diagnose(&self, context: &RescueContext, session: &SessionRef) -> Result<SessionView> {
        let bytes = Self::read_stable(context, &session.source_path)?;
        let terminated_with_newline = bytes.is_empty() || bytes.ends_with(b"\n");
        let mut records = 0usize;
        let mut malformed_records = 0usize;
        let mut oversized_records = 0usize;

        for raw_record in bytes.split_inclusive(|byte| *byte == b'\n') {
            let mut record = raw_record;
            if record.ends_with(b"\n") {
                record = &record[..record.len() - 1];
            }
            if record.ends_with(b"\r") {
                record = &record[..record.len() - 1];
            }
            if record.is_empty() {
                continue;
            }
            if record.len() > context.max_record_bytes {
                oversized_records += 1;
                continue;
            }
            match serde_json::from_slice::<serde_json::Value>(record) {
                Ok(value) if value.is_object() => records += 1,
                Ok(_) | Err(_) => malformed_records += 1,
            }
        }

        let mut notices = vec![
            "Claude transcript schema is intentionally opaque; no provider state was reconstructed"
                .to_string(),
            "snapshot/fork copies bytes only and never writes the Claude state root".to_string(),
        ];
        if !terminated_with_newline {
            notices.push("transcript tail is not newline-terminated".to_string());
        }
        if malformed_records > 0 {
            notices.push(format!("{malformed_records} malformed JSONL record(s)"));
        }
        if oversized_records > 0 {
            notices.push(format!(
                "{oversized_records} record(s) exceeded the {} byte budget",
                context.max_record_bytes
            ));
        }
        let health = if malformed_records > 0 || oversized_records > 0 {
            SessionHealth::Corrupt
        } else {
            // A syntactically valid JSONL file is not evidence that the
            // provider's evolving transcript schema is understood.
            SessionHealth::Unknown
        };

        Ok(SessionView {
            adapter: self.id().to_string(),
            key: session.key.clone(),
            relative_path: session.relative_path.clone(),
            bytes: bytes.len() as u64,
            sha256: Self::sha256(&bytes),
            health,
            records,
            malformed_records,
            oversized_records,
            terminated_with_newline,
            notices,
        })
    }

    fn snapshot(
        &self,
        context: &RescueContext,
        session: &SessionRef,
        destination: &Path,
    ) -> Result<SnapshotReceipt> {
        let bytes = Self::read_stable(context, &session.source_path)?;
        let source_hash = Self::sha256(&bytes);
        let destination = if destination.is_absolute() {
            destination.to_path_buf()
        } else {
            std::env::current_dir()?.join(destination)
        };
        let parent = destination
            .parent()
            .context("Claude snapshot destination must have a parent directory")?;
        let file_name = destination
            .file_name()
            .context("Claude snapshot destination must have a file name")?;
        let canonical_parent = fs::canonicalize(parent).with_context(|| {
            format!(
                "canonicalize Claude snapshot parent {}",
                parent.display()
            )
        })?;
        let canonical_root = Self::validate_root(context)?;
        if canonical_parent.starts_with(&canonical_root) {
            bail!("Claude snapshot destination may not be inside the original state root");
        }
        let destination = canonical_parent.join(file_name);
        report::write_new_bytes(&destination, &bytes)
            .with_context(|| format!("create Claude snapshot {}", destination.display()))?;
        let written = fs::read(&destination)
            .with_context(|| format!("verify Claude snapshot {}", destination.display()))?;
        let written_hash = Self::sha256(&written);
        if written_hash != source_hash {
            bail!("Claude snapshot verification hash mismatch");
        }

        Ok(SnapshotReceipt {
            adapter: self.id().to_string(),
            source_key: session.key.clone(),
            destination: destination.to_string_lossy().to_string(),
            bytes: written.len() as u64,
            sha256: written_hash,
            source_preserved: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vetto-claude-{label}-{}-{nonce}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create test directory");
        path
    }

    fn context(root: &Path) -> RescueContext {
        RescueContext::new(root.to_path_buf())
    }

    #[test]
    fn detect_is_fail_closed_without_known_layout() {
        let root = test_dir("unknown");
        let status = ClaudeAdapter.detect(&context(&root)).expect("detect");
        assert_eq!(status.availability, Availability::Unavailable);
        assert_eq!(status.support_level, "unsupported");
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn discovers_only_jsonl_and_skips_credential_shaped_paths() {
        let root = test_dir("discover");
        let projects = root.join("projects").join("demo");
        fs::create_dir_all(&projects).expect("create projects");
        fs::write(
            projects.join("session.jsonl"),
            br#"{"type":"user","sessionId":"synthetic"}
{"type":"assistant","message":{"role":"assistant"}}
"#,
        )
        .expect("write transcript");
        fs::write(projects.join("credentials.jsonl"), b"not a transcript\n")
            .expect("write credential-shaped file");
        fs::write(projects.join("notes.txt"), b"not a transcript\n")
            .expect("write non-jsonl file");

        let sessions = ClaudeAdapter
            .discover_sessions(&context(&root))
            .expect("discover sessions");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].adapter, "claude");
        assert!(sessions[0].key.ends_with("projects/demo/session.jsonl"));
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn diagnosis_is_opaque_and_does_not_claim_schema_health() {
        let root = test_dir("diagnose");
        let projects = root.join("projects").join("demo");
        fs::create_dir_all(&projects).expect("create projects");
        let path = projects.join("session.jsonl");
        fs::write(
            &path,
            br#"{"type":"unknown-provider-record"}
not-json
"#,
        )
        .expect("write transcript");
        let session = ClaudeAdapter
            .discover_sessions(&context(&root))
            .expect("discover sessions")
            .pop()
            .expect("session");
        let view = ClaudeAdapter
            .diagnose(&context(&root), &session)
            .expect("diagnose");
        assert_eq!(view.health, SessionHealth::Corrupt);
        assert_eq!(view.records, 1);
        assert_eq!(view.malformed_records, 1);
        assert!(view.notices.iter().any(|notice| notice.contains("opaque")));
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn snapshot_is_copy_only_and_preserves_source() {
        let root = test_dir("snapshot");
        let output = test_dir("snapshot-output");
        let projects = root.join("sessions");
        fs::create_dir_all(&projects).expect("create sessions");
        let path = projects.join("session.jsonl");
        let contents = b"{\"type\":\"synthetic\"}\n";
        fs::write(&path, contents).expect("write transcript");
        let session = ClaudeAdapter
            .discover_sessions(&context(&root))
            .expect("discover sessions")
            .pop()
            .expect("session");
        let destination = output.join("snapshot.jsonl");
        let receipt = ClaudeAdapter
            .snapshot(&context(&root), &session, &destination)
            .expect("snapshot");
        assert_eq!(fs::read(&path).expect("read source"), contents);
        assert_eq!(fs::read(&destination).expect("read snapshot"), contents);
        assert!(receipt.source_preserved);
        assert_eq!(receipt.bytes, contents.len() as u64);
        fs::remove_dir_all(root).expect("remove source directory");
        fs::remove_dir_all(output).expect("remove output directory");
    }

    #[test]
    fn snapshot_refuses_destination_inside_source_root() {
        let root = test_dir("inside");
        let sessions = root.join("projects");
        fs::create_dir_all(&sessions).expect("create projects");
        let path = sessions.join("session.jsonl");
        fs::write(&path, b"{}\n").expect("write transcript");
        let session = ClaudeAdapter
            .discover_sessions(&context(&root))
            .expect("discover sessions")
            .pop()
            .expect("session");
        let result = ClaudeAdapter.snapshot(
            &context(&root),
            &session,
            &root.join("copy.jsonl"),
        );
        assert!(result.is_err());
        assert!(!root.join("copy.jsonl").exists());
        fs::remove_dir_all(root).expect("remove test directory");
    }
}
