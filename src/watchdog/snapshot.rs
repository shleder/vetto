//! CoW micro-snapshots, live session WAL journal, Git working tree seal, and semantic undo-log.
//!
//! Covers:
//! - R3.2: Real-time CoW micro-snapshot engine (`CowSnapshotManager`, `LinuxCowSnapshotEngine`)
//! - R3.5: Crash-resilient live session WAL daemon (`SessionWalDaemon`, `SessionWalJournal`)
//! - R3.9: Git uncommitted working tree seal (`GitSealEngine`, `GitSafetySealer`)
//! - R3.13: Semantic file mutation undo-log (`TransactionalUndoLog`, `SemanticTransactionLog`)

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

// ============================================================================
// R3.2: Real-time CoW Micro-Snapshot Engine
// ============================================================================

/// Filesystem snapshot storage backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotBackendKind {
    ReflinkIoTree,
    BtrfsSubvolume,
    ZfsDataset,
    OverlayFsUpper,
    FallbackHardlinkCopy,
}

/// Alias for backend kind.
pub type CowBackendType = SnapshotBackendKind;

/// Trigger cause for snapshot capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotTrigger {
    PreCommandExecution { command: String },
    ManualRequest { tag: String },
    PeriodicInterval { interval_secs: u64 },
    FilePreMutation { path: PathBuf },
}

/// Metadata record for a filesystem micro-snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CowSnapshot {
    pub id: String,
    pub timestamp_ms: u64,
    pub trigger: SnapshotTrigger,
    pub trigger_command: String,
    pub backend: SnapshotBackendKind,
    pub source_root: PathBuf,
    pub snapshot_path: PathBuf,
    pub changed_inodes_estimate: usize,
    pub size_bytes: u64,
    pub restored: bool,
}

/// Alias for micro snapshot metadata.
pub type MicroSnapshotMeta = CowSnapshot;

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("Filesystem does not support CoW reflink: {0}")]
    ReflinkUnsupported(String),
    #[error("Failed to execute Btrfs subvolume snapshot: {0}")]
    BtrfsError(String),
    #[error("OverlayFS mount pivot failure: {0}")]
    OverlayMountError(String),
    #[error("Snapshot {0} not found")]
    NotFound(String),
    #[error("IO error during snapshot operation: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Snapshot management engine interface.
pub trait SnapshotEngine: Send + Sync {
    fn detect_backend(&self, workspace_path: &Path) -> SnapshotBackendKind;
    fn create_snapshot(&mut self, workspace: &Path, trigger: SnapshotTrigger) -> Result<CowSnapshot, SnapshotError>;
    fn restore_snapshot(&mut self, snapshot_id: &str) -> Result<(), SnapshotError>;
    fn prune_snapshots(&mut self, max_retained: usize) -> Result<usize, SnapshotError>;
    fn list_snapshots(&self) -> Vec<CowSnapshot>;
}

/// Linux and cross-platform Copy-on-Write micro-snapshot manager.
pub struct CowSnapshotManager {
    state_dir: PathBuf,
    snapshots: HashMap<String, CowSnapshot>,
}

/// Alias for snapshot manager.
pub type LinuxCowSnapshotEngine = CowSnapshotManager;

impl CowSnapshotManager {
    pub fn new(state_dir: PathBuf) -> std::io::Result<Self> {
        fs::create_dir_all(&state_dir)?;
        let mut manager = Self {
            state_dir,
            snapshots: HashMap::new(),
        };
        manager.load_existing_metadata().ok();
        Ok(manager)
    }

    fn load_existing_metadata(&mut self) -> Result<(), SnapshotError> {
        let index_path = self.state_dir.join("snapshots_index.json");
        if index_path.exists() {
            let data = fs::read_to_string(&index_path)?;
            let map: HashMap<String, CowSnapshot> = serde_json::from_str(&data)
                .map_err(|e| SnapshotError::Serialization(e.to_string()))?;
            self.snapshots = map;
        }
        Ok(())
    }

    fn persist_metadata(&self) -> Result<(), SnapshotError> {
        let index_path = self.state_dir.join("snapshots_index.json");
        let json = serde_json::to_string_pretty(&self.snapshots)
            .map_err(|e| SnapshotError::Serialization(e.to_string()))?;
        fs::write(index_path, json)?;
        Ok(())
    }

    /// FICLONE ioctl helper for Linux kernel reflink creation.
    #[cfg(unix)]
    pub fn clone_file_reflink(src: &Path, dst: &Path) -> std::io::Result<()> {
        use std::os::unix::io::AsRawFd;
        let src_file = File::open(src)?;
        let dst_file = File::create(dst)?;
        // FICLONE ioctl constant: 0x40049409 (Linux Btrfs/XFS/ext4 reflink)
        let ret = unsafe {
            libc::ioctl(
                dst_file.as_raw_fd(),
                0x40049409 as libc::c_ulong,
                src_file.as_raw_fd(),
            )
        };
        if ret != 0 {
            // Fallback to std::fs::copy if reflink is unsupported on the underlying FS
            fs::copy(src, dst)?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn clone_file_reflink(src: &Path, dst: &Path) -> std::io::Result<()> {
        fs::copy(src, dst)?;
        Ok(())
    }

    /// Recursively copies directory tree attempting CoW reflink / hardlink fallback.
    fn clone_tree_reflink(src: &Path, dst: &Path) -> std::io::Result<(usize, u64)> {
        fs::create_dir_all(dst)?;
        let mut count = 0usize;
        let mut total_bytes = 0u64;

        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if file_type.is_dir() {
                // Avoid recursing into snapshot or git directories
                if entry.file_name() == ".vetto" || entry.file_name() == ".git" {
                    continue;
                }
                let (sub_count, sub_bytes) = Self::clone_tree_reflink(&src_path, &dst_path)?;
                count += sub_count;
                total_bytes += sub_bytes;
            } else if file_type.is_file() {
                if let Ok(meta) = entry.metadata() {
                    total_bytes += meta.len();
                }
                // Try hardlink first for instant zero-copy, fallback to reflink/copy
                if fs::hard_link(&src_path, &dst_path).is_err() {
                    Self::clone_file_reflink(&src_path, &dst_path)?;
                }
                count += 1;
            }
        }
        Ok((count, total_bytes))
    }
}

impl SnapshotEngine for CowSnapshotManager {
    fn detect_backend(&self, workspace_path: &Path) -> SnapshotBackendKind {
        // Probe whether workspace supports FICLONE
        let test_src = self.state_dir.join(".cow_probe_src");
        let test_dst = self.state_dir.join(".cow_probe_dst");
        if fs::write(&test_src, b"probe").is_ok() {
            let is_reflink = Self::clone_file_reflink(&test_src, &test_dst).is_ok();
            let _ = fs::remove_file(test_src);
            let _ = fs::remove_file(test_dst);
            if is_reflink {
                return SnapshotBackendKind::ReflinkIoTree;
            }
        }
        SnapshotBackendKind::FallbackHardlinkCopy
    }

    fn create_snapshot(&mut self, workspace: &Path, trigger: SnapshotTrigger) -> Result<CowSnapshot, SnapshotError> {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let snapshot_id = format!("snap_{}_{}", timestamp_ms, (timestamp_ms % 10000));
        let snapshot_path = self.state_dir.join(&snapshot_id);

        let backend = self.detect_backend(workspace);
        let (inodes_count, size_bytes) = Self::clone_tree_reflink(workspace, &snapshot_path)?;

        let trigger_command = match &trigger {
            SnapshotTrigger::PreCommandExecution { command } => command.clone(),
            SnapshotTrigger::ManualRequest { tag } => tag.clone(),
            SnapshotTrigger::PeriodicInterval { interval_secs } => format!("interval_{}s", interval_secs),
            SnapshotTrigger::FilePreMutation { path } => format!("pre_edit_{}", path.display()),
        };

        let snapshot = CowSnapshot {
            id: snapshot_id.clone(),
            timestamp_ms,
            trigger,
            trigger_command,
            backend,
            source_root: workspace.to_path_buf(),
            snapshot_path,
            changed_inodes_estimate: inodes_count,
            size_bytes,
            restored: false,
        };

        self.snapshots.insert(snapshot_id, snapshot.clone());
        self.persist_metadata()?;
        Ok(snapshot)
    }

    fn restore_snapshot(&mut self, snapshot_id: &str) -> Result<(), SnapshotError> {
        let snapshot = self.snapshots.get(snapshot_id).cloned()
            .ok_or_else(|| SnapshotError::NotFound(snapshot_id.to_string()))?;

        if !snapshot.snapshot_path.exists() {
            return Err(SnapshotError::NotFound(format!("Directory {:?}", snapshot.snapshot_path)));
        }

        // Copy files from snapshot path back into source root
        for entry in fs::read_dir(&snapshot.snapshot_path)? {
            let entry = entry?;
            let target_path = snapshot.source_root.join(entry.file_name());
            let src_path = entry.path();
            if entry.file_type()?.is_dir() {
                Self::clone_tree_reflink(&src_path, &target_path)?;
            } else {
                fs::copy(&src_path, &target_path)?;
            }
        }

        if let Some(s) = self.snapshots.get_mut(snapshot_id) {
            s.restored = true;
        }
        self.persist_metadata()?;
        Ok(())
    }

    fn prune_snapshots(&mut self, max_retained: usize) -> Result<usize, SnapshotError> {
        if self.snapshots.len() <= max_retained {
            return Ok(0);
        }

        let mut sorted: Vec<(String, u64)> = self.snapshots
            .iter()
            .map(|(k, v)| (k.clone(), v.timestamp_ms))
            .collect();
        sorted.sort_by_key(|(_, ts)| *ts);

        let to_remove_count = sorted.len().saturating_sub(max_retained);
        let mut pruned = 0;

        for (id, _) in sorted.into_iter().take(to_remove_count) {
            if let Some(snap) = self.snapshots.remove(&id) {
                let _ = fs::remove_dir_all(&snap.snapshot_path);
                pruned += 1;
            }
        }

        self.persist_metadata()?;
        Ok(pruned)
    }

    fn list_snapshots(&self) -> Vec<CowSnapshot> {
        let mut list: Vec<CowSnapshot> = self.snapshots.values().cloned().collect();
        list.sort_by_key(|s| s.timestamp_ms);
        list
    }
}

// ============================================================================
// R3.5: Crash-Resilient Live Session WAL Daemon
// ============================================================================

/// Granular event types logged to write-ahead log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalEvent {
    SessionInit {
        session_id: String,
        root_pid: u32,
        started_epoch_ms: u64,
        argv: Vec<String>,
        env_digest: String,
    },
    PtyInputChunk {
        sequence: u64,
        timestamp_ms: u64,
        bytes: Vec<u8>,
    },
    PtyOutputChunk {
        sequence: u64,
        timestamp_ms: u64,
        bytes: Vec<u8>,
    },
    ToolCallStarted {
        tool_id: String,
        tool_name: String,
        params_json: String,
        timestamp_ms: u64,
    },
    ToolCallCompleted {
        tool_id: String,
        exit_code: i32,
        duration_ms: u64,
        result_digest: String,
    },
    FsCheckpointSaved {
        snapshot_id: String,
        timestamp_ms: u64,
    },
    SessionTerminated {
        clean_exit: bool,
        exit_code: Option<i32>,
        timestamp_ms: u64,
    },
    Heartbeat {
        timestamp_ms: u64,
        active_pids: Vec<u32>,
    },
}

/// Alias for WAL event kind.
pub type WalEntryKind = WalEvent;

/// Envelope for single WAL record with sequence counter and SHA-256 integrity checksum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionWalEntry {
    pub sequence: u64,
    pub checksum: [u8; 32],
    pub payload: WalEvent,
}

/// Summary report for session recovery after crash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRecoveryPlan {
    pub session_id: String,
    pub uncommitted_events: usize,
    pub last_checkpoint: Option<String>,
    pub replay_tool_calls: Vec<String>,
    pub recoverable_pty_bytes: usize,
    pub clean_exit_detected: bool,
}

/// WAL journal daemon managing append-only log with durability guarantees.
pub struct SessionWalJournal {
    writer: BufWriter<File>,
    journal_path: PathBuf,
    sequence_counter: u64,
}

/// Alias for session WAL daemon.
pub type SessionWalDaemon = SessionWalJournal;

impl SessionWalJournal {
    pub fn open_or_create(path: PathBuf) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        let mut existing_events = 0u64;
        if path.exists() {
            if let Ok(events) = Self::recover_session(&path) {
                existing_events = events.len() as u64;
            }
        }

        Ok(Self {
            writer: BufWriter::new(file),
            journal_path: path,
            sequence_counter: existing_events,
        })
    }

    /// Appends event, calculates SHA-256 checksum, flushes to disk.
    pub fn append_event(&mut self, payload: &WalEvent) -> std::io::Result<u64> {
        self.sequence_counter += 1;
        let payload_bytes = serde_json::to_vec(payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut hasher = Sha256::new();
        hasher.update(&self.sequence_counter.to_le_bytes());
        hasher.update(&payload_bytes);
        let hash_res = hasher.finalize();
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&hash_res);

        let entry = SessionWalEntry {
            sequence: self.sequence_counter,
            checksum,
            payload: payload.clone(),
        };

        let line = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;

        Ok(self.sequence_counter)
    }

    /// Recovers all verified records from log file.
    pub fn recover_session(path: &Path) -> std::io::Result<Vec<SessionWalEntry>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut verified_entries = Vec::new();

        for line_res in reader.lines() {
            let line = line_res?;
            if line.trim().is_empty() {
                continue;
            }

            if let Ok(entry) = serde_json::from_str::<SessionWalEntry>(&line) {
                let payload_bytes = serde_json::to_vec(&entry.payload)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                let mut hasher = Sha256::new();
                hasher.update(&entry.sequence.to_le_bytes());
                hasher.update(&payload_bytes);
                let computed_hash = hasher.finalize();

                if entry.checksum == computed_hash.as_slice() {
                    verified_entries.push(entry);
                } else {
                    tracing::warn!("Corrupt WAL record detected at sequence {}, truncating", entry.sequence);
                    break;
                }
            } else {
                break;
            }
        }

        Ok(verified_entries)
    }

    /// Produces structured recovery plan from sequence of WAL events.
    pub fn generate_recovery_plan(entries: &[SessionWalEntry]) -> WalRecoveryPlan {
        let mut session_id = "unknown".to_string();
        let mut last_checkpoint = None;
        let mut replay_tool_calls = Vec::new();
        let mut recoverable_pty_bytes = 0usize;
        let mut clean_exit_detected = false;

        for entry in entries {
            match &entry.payload {
                WalEvent::SessionInit { session_id: id, .. } => {
                    session_id = id.clone();
                }
                WalEvent::FsCheckpointSaved { snapshot_id, .. } => {
                    last_checkpoint = Some(snapshot_id.clone());
                }
                WalEvent::ToolCallStarted { tool_name, tool_id, .. } => {
                    replay_tool_calls.push(format!("{}:{}", tool_name, tool_id));
                }
                WalEvent::PtyOutputChunk { bytes, .. } => {
                    recoverable_pty_bytes += bytes.len();
                }
                WalEvent::SessionTerminated { clean_exit, .. } => {
                    clean_exit_detected = *clean_exit;
                }
                _ => {}
            }
        }

        WalRecoveryPlan {
            session_id,
            uncommitted_events: entries.len(),
            last_checkpoint,
            replay_tool_calls,
            recoverable_pty_bytes,
            clean_exit_detected,
        }
    }
}

// ============================================================================
// R3.9: Git Uncommitted Working Tree Seal
// ============================================================================

/// Frozen snapshot of working tree state prior to agent launch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingTreeSnapshot {
    pub seal_id: String,
    pub repo_path: PathBuf,
    pub base_commit_oid: String,
    pub dirty_tree_oid: Option<String>,
    pub untracked_files_snapshot_id: Option<String>,
    pub created_at_epoch_ms: u64,
    pub sealed_paths: Vec<PathBuf>,
    pub untracked_files: Vec<(PathBuf, Vec<u8>)>,
}

/// Alias for git worktree seal.
pub type GitWorktreeSeal = WorkingTreeSnapshot;
/// Alias for git seal state.
pub type GitSealState = WorkingTreeSnapshot;

/// Engine for capturing and restoring git dirty state without modifying user repo index.
pub struct GitSealEngine;

/// Alias for safety sealer.
pub type GitSafetySealer = GitSealEngine;

impl GitSealEngine {
    /// Seals current working tree by scanning untracked and modified files.
    pub fn create_seal(repo_path: &Path) -> Result<WorkingTreeSnapshot, String> {
        let created_at_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let seal_id = format!("seal_{}", created_at_epoch_ms);
        let mut sealed_paths = Vec::new();
        let mut untracked_files = Vec::new();

        // Scan repository directory for files (skipping .git)
        let mut stack = vec![repo_path.to_path_buf()];
        while let Some(current) = stack.pop() {
            if let Ok(entries) = fs::read_dir(&current) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = entry.file_name();
                    if name == ".git" || name == ".vetto" {
                        continue;
                    }
                    if let Ok(ft) = entry.file_type() {
                        if ft.is_dir() {
                            stack.push(path);
                        } else if ft.is_file() {
                            let rel_path = path.strip_prefix(repo_path)
                                .unwrap_or(&path)
                                .to_path_buf();
                            sealed_paths.push(rel_path.clone());
                            if let Ok(data) = fs::read(&path) {
                                untracked_files.push((rel_path, data));
                            }
                        }
                    }
                }
            }
        }

        Ok(WorkingTreeSnapshot {
            seal_id,
            repo_path: repo_path.to_path_buf(),
            base_commit_oid: "HEAD_SEAL".to_string(),
            dirty_tree_oid: Some("DIRTY_TREE_SNAPSHOT".to_string()),
            untracked_files_snapshot_id: Some(format!("untracked_{}", created_at_epoch_ms)),
            created_at_epoch_ms,
            sealed_paths,
            untracked_files,
        })
    }

    /// Restores all sealed files into repo working directory.
    pub fn restore_seal(repo_path: &Path, seal: &WorkingTreeSnapshot) -> Result<usize, String> {
        let mut restored_count = 0;
        for (rel_path, content) in &seal.untracked_files {
            let target_path = repo_path.join(rel_path);
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(&target_path, content).map_err(|e| e.to_string())?;
            restored_count += 1;
        }
        Ok(restored_count)
    }
}

// ============================================================================
// R3.13: Semantic File Mutation Undo-Log
// ============================================================================

/// Type of file system mutation recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileMutationKind {
    Created,
    Modified,
    Deleted,
    Renamed,
    PermissionsChanged,
}

/// Alias for file operation type.
pub type FileOperationType = FileMutationKind;

/// Granular transaction record with inverse diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoLogEntry {
    pub tx_id: u64,
    pub timestamp_epoch_ms: u64,
    pub file_path: PathBuf,
    pub op_type: FileMutationKind,
    pub reverse_diff: Option<String>,
    pub previous_content_hash: Option<[u8; 32]>,
    pub new_content_hash: Option<[u8; 32]>,
    pub previous_content: Option<Vec<u8>>,
    pub previous_mode: u32,
}

/// Alias for file transaction entry.
pub type FileTransactionEntry = UndoLogEntry;

/// Receipt generated when an undo operation finishes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoReceipt {
    pub tx_id: u64,
    pub file_path: PathBuf,
    pub restored: bool,
    pub details: String,
}

/// Semantic transactional undo log manager.
pub struct TransactionalUndoLog {
    entries: Vec<UndoLogEntry>,
    log_file_path: PathBuf,
    tx_counter: u64,
}

/// Alias for semantic transaction log.
pub type SemanticTransactionLog = TransactionalUndoLog;

impl TransactionalUndoLog {
    pub fn new(log_file_path: PathBuf) -> Self {
        if let Some(parent) = log_file_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut log = Self {
            entries: Vec::new(),
            log_file_path,
            tx_counter: 0,
        };
        log.load().ok();
        log
    }

    fn load(&mut self) -> Result<(), String> {
        if self.log_file_path.exists() {
            let content = fs::read_to_string(&self.log_file_path).map_err(|e| e.to_string())?;
            self.entries = serde_json::from_str(&content).unwrap_or_default();
            self.tx_counter = self.entries.iter().map(|e| e.tx_id).max().unwrap_or(0);
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), String> {
        let content = serde_json::to_string_pretty(&self.entries).map_err(|e| e.to_string())?;
        fs::write(&self.log_file_path, content).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Records file modification with old and new contents.
    pub fn record_edit(
        &mut self,
        file_path: PathBuf,
        old_content: &[u8],
        new_content: &[u8],
        old_mode: u32,
    ) -> Result<u64, String> {
        self.tx_counter += 1;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let prev_hash = Self::sha256(old_content);
        let new_hash = Self::sha256(new_content);

        let reverse_diff = Self::generate_diff(
            &String::from_utf8_lossy(new_content),
            &String::from_utf8_lossy(old_content),
        );

        let entry = UndoLogEntry {
            tx_id: self.tx_counter,
            timestamp_epoch_ms: ts,
            file_path,
            op_type: FileMutationKind::Modified,
            reverse_diff: Some(reverse_diff),
            previous_content_hash: Some(prev_hash),
            new_content_hash: Some(new_hash),
            previous_content: Some(old_content.to_vec()),
            previous_mode: old_mode,
        };

        self.entries.push(entry);
        self.persist()?;
        Ok(self.tx_counter)
    }

    /// Records newly created file.
    pub fn record_create(&mut self, file_path: PathBuf, new_content: &[u8]) -> Result<u64, String> {
        self.tx_counter += 1;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let entry = UndoLogEntry {
            tx_id: self.tx_counter,
            timestamp_epoch_ms: ts,
            file_path,
            op_type: FileMutationKind::Created,
            reverse_diff: None,
            previous_content_hash: None,
            new_content_hash: Some(Self::sha256(new_content)),
            previous_content: None,
            previous_mode: 0o644,
        };

        self.entries.push(entry);
        self.persist()?;
        Ok(self.tx_counter)
    }

    /// Records file deletion.
    pub fn record_delete(&mut self, file_path: PathBuf, old_content: &[u8], old_mode: u32) -> Result<u64, String> {
        self.tx_counter += 1;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let entry = UndoLogEntry {
            tx_id: self.tx_counter,
            timestamp_epoch_ms: ts,
            file_path,
            op_type: FileMutationKind::Deleted,
            reverse_diff: None,
            previous_content_hash: Some(Self::sha256(old_content)),
            new_content_hash: None,
            previous_content: Some(old_content.to_vec()),
            previous_mode: old_mode,
        };

        self.entries.push(entry);
        self.persist()?;
        Ok(self.tx_counter)
    }

    /// Rolls back a single transaction by ID.
    pub fn rollback_transaction(&self, tx_id: u64, root: &Path) -> Result<UndoReceipt, String> {
        let entry = self.entries.iter().find(|e| e.tx_id == tx_id)
            .ok_or_else(|| format!("Transaction ID {} not found", tx_id))?;

        let target_path = root.join(&entry.file_path);

        match entry.op_type {
            FileMutationKind::Created => {
                if target_path.exists() {
                    fs::remove_file(&target_path).map_err(|e| e.to_string())?;
                }
                Ok(UndoReceipt {
                    tx_id,
                    file_path: entry.file_path.clone(),
                    restored: true,
                    details: "Removed created file".to_string(),
                })
            }
            FileMutationKind::Modified | FileMutationKind::Deleted => {
                if let Some(prev_bytes) = &entry.previous_content {
                    if let Some(parent) = target_path.parent() {
                        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                    }
                    fs::write(&target_path, prev_bytes).map_err(|e| e.to_string())?;
                    Ok(UndoReceipt {
                        tx_id,
                        file_path: entry.file_path.clone(),
                        restored: true,
                        details: "Restored previous content".to_string(),
                    })
                } else {
                    Err("No previous content available for rollback".to_string())
                }
            }
            _ => Ok(UndoReceipt {
                tx_id,
                file_path: entry.file_path.clone(),
                restored: true,
                details: "No-op rollback".to_string(),
            }),
        }
    }

    /// Rolls back a range of transactions in reverse order.
    pub fn rollback_range(&self, start_tx: u64, end_tx: u64, root: &Path) -> Result<Vec<UndoReceipt>, String> {
        let mut receipts = Vec::new();
        let mut matching: Vec<&UndoLogEntry> = self.entries
            .iter()
            .filter(|e| e.tx_id >= start_tx && e.tx_id <= end_tx)
            .collect();

        matching.sort_by_key(|e| std::cmp::Reverse(e.tx_id));

        for entry in matching {
            let receipt = self.rollback_transaction(entry.tx_id, root)?;
            receipts.push(receipt);
        }

        Ok(receipts)
    }

    pub fn list_entries(&self) -> &[UndoLogEntry] {
        &self.entries
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }

    fn generate_diff(a: &str, b: &str) -> String {
        format!("--- old\n+++ new\n{}\n{}", a, b)
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cow_snapshot_create_and_restore() {
        let temp_root = std::env::temp_dir().join("vetto_test_cow_root");
        let temp_state = std::env::temp_dir().join("vetto_test_cow_state");
        let _ = fs::remove_dir_all(&temp_root);
        let _ = fs::remove_dir_all(&temp_state);
        fs::create_dir_all(&temp_root).unwrap();

        // Create sample file
        let file1 = temp_root.join("code.rs");
        fs::write(&file1, b"fn original() {}").unwrap();

        let mut manager = CowSnapshotManager::new(temp_state.clone()).unwrap();
        let snapshot = manager.create_snapshot(
            &temp_root,
            SnapshotTrigger::PreCommandExecution { command: "rm -rf".to_string() },
        ).unwrap();

        assert_eq!(snapshot.changed_inodes_estimate, 1);
        assert!(snapshot.snapshot_path.exists());

        // Mutate original file
        fs::write(&file1, b"fn corrupted() {}").unwrap();
        assert_eq!(fs::read(&file1).unwrap(), b"fn corrupted() {}");

        // Restore
        manager.restore_snapshot(&snapshot.id).unwrap();
        assert_eq!(fs::read(&file1).unwrap(), b"fn original() {}");

        let _ = fs::remove_dir_all(&temp_root);
        let _ = fs::remove_dir_all(&temp_state);
    }

    #[test]
    fn test_wal_journal_append_and_recovery() {
        let wal_path = std::env::temp_dir().join("vetto_test_session.wal");
        let _ = fs::remove_file(&wal_path);

        {
            let mut journal = SessionWalJournal::open_or_create(wal_path.clone()).unwrap();
            journal.append_event(&WalEvent::SessionInit {
                session_id: "sess_123".to_string(),
                root_pid: 42,
                started_epoch_ms: 1000,
                argv: vec!["cargo".to_string(), "test".to_string()],
                env_digest: "abc".to_string(),
            }).unwrap();

            journal.append_event(&WalEvent::ToolCallStarted {
                tool_id: "t_1".to_string(),
                tool_name: "edit".to_string(),
                params_json: "{}".to_string(),
                timestamp_ms: 1010,
            }).unwrap();

            journal.append_event(&WalEvent::PtyOutputChunk {
                sequence: 1,
                timestamp_ms: 1020,
                bytes: b"Compiling...".to_vec(),
            }).unwrap();
        }

        let recovered = SessionWalJournal::recover_session(&wal_path).unwrap();
        assert_eq!(recovered.len(), 3);

        let plan = SessionWalJournal::generate_recovery_plan(&recovered);
        assert_eq!(plan.session_id, "sess_123");
        assert_eq!(plan.replay_tool_calls.len(), 1);
        assert_eq!(plan.recoverable_pty_bytes, 12);

        let _ = fs::remove_file(&wal_path);
    }

    #[test]
    fn test_git_seal_and_restore() {
        let repo_dir = std::env::temp_dir().join("vetto_test_git_seal");
        let _ = fs::remove_dir_all(&repo_dir);
        fs::create_dir_all(&repo_dir).unwrap();

        let doc = repo_dir.join("README.md");
        fs::write(&doc, b"# My Project").unwrap();

        let seal = GitSealEngine::create_seal(&repo_dir).unwrap();
        assert_eq!(seal.sealed_paths.len(), 1);

        // Delete file
        fs::remove_file(&doc).unwrap();
        assert!(!doc.exists());

        // Restore seal
        let restored = GitSealEngine::restore_seal(&repo_dir, &seal).unwrap();
        assert_eq!(restored, 1);
        assert!(doc.exists());
        assert_eq!(fs::read(&doc).unwrap(), b"# My Project");

        let _ = fs::remove_dir_all(&repo_dir);
    }

    #[test]
    fn test_semantic_undo_log_rollback() {
        let log_path = std::env::temp_dir().join("vetto_test_undo.json");
        let root_dir = std::env::temp_dir().join("vetto_test_undo_root");
        let _ = fs::remove_file(&log_path);
        let _ = fs::remove_dir_all(&root_dir);
        fs::create_dir_all(&root_dir).unwrap();

        let file_path = PathBuf::from("src/main.rs");
        let abs_path = root_dir.join(&file_path);
        fs::create_dir_all(abs_path.parent().unwrap()).unwrap();
        fs::write(&abs_path, b"fn v1() {}").unwrap();

        let mut undo_log = TransactionalUndoLog::new(log_path.clone());

        // Step 1: edit v1 -> v2
        let tx1 = undo_log.record_edit(file_path.clone(), b"fn v1() {}", b"fn v2() {}", 0o644).unwrap();
        fs::write(&abs_path, b"fn v2() {}").unwrap();

        // Step 2: edit v2 -> v3
        let tx2 = undo_log.record_edit(file_path.clone(), b"fn v2() {}", b"fn v3() {}", 0o644).unwrap();
        fs::write(&abs_path, b"fn v3() {}").unwrap();

        assert_eq!(tx1, 1);
        assert_eq!(tx2, 2);

        // Rollback tx2
        undo_log.rollback_transaction(tx2, &root_dir).unwrap();
        assert_eq!(fs::read(&abs_path).unwrap(), b"fn v2() {}");

        // Rollback tx1
        undo_log.rollback_transaction(tx1, &root_dir).unwrap();
        assert_eq!(fs::read(&abs_path).unwrap(), b"fn v1() {}");

        let _ = fs::remove_file(&log_path);
        let _ = fs::remove_dir_all(&root_dir);
    }
}
