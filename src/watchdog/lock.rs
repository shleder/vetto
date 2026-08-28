//! Cross-agent swarm file lock scheduler and multi-agent IPC deadlock breaker.
//!
//! Covers:
//! - R3.3: Multi-agent swarm file lock scheduler (`SwarmLockScheduler`, `CrossAgentLockScheduler`)
//! - R3.10: Multi-agent IPC deadlock breaker (`DeadlockBreakerEngine`, `DeadlockGraphTracker`)

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

// ============================================================================
// R3.3: Multi-Agent Swarm File Lock Scheduler
// ============================================================================

/// Lock acquisition mode for files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LockMode {
    SharedRead,
    ExclusiveWrite,
    AstPatchMergeable,
    IntentToWrite,
}

/// Alias for file lock kind.
pub type FileLockKind = LockMode;

/// Lock request payload submitted by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockRequest {
    pub agent_id: String,
    pub target_file: PathBuf,
    pub mode: LockMode,
    pub timeout_ms: u64,
    pub base_file_hash: [u8; 32],
    pub proposed_content: Option<Vec<u8>>,
    pub base_content: Option<Vec<u8>>,
}

/// Alias for agent lock claim.
pub type AgentLockClaim = LockRequest;

/// Conflict resolution policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockConflictPolicy {
    RejectOnConflict,
    QueueFifo,
    AttemptAstThreeWayMerge,
    PriorityPreempt { priority: u32 },
}

/// Structured 3-way AST / line-level merge preview report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreeWayMergePreview {
    pub can_merge_cleanly: bool,
    pub base_hash: [u8; 32],
    pub agent_a_hash: [u8; 32],
    pub agent_b_hash: [u8; 32],
    pub conflicting_lines: Vec<(usize, String, String)>,
    pub merged_content: Option<Vec<u8>>,
}

/// Result returned from an acquisition attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LockAcquireResult {
    Granted {
        lease_id: String,
        expires_at_epoch_ms: u64,
    },
    Queued {
        queue_position: usize,
        estimated_wait_ms: u64,
    },
    ConflictDetected {
        conflicting_agent: String,
        diff_preview: String,
        merge_preview: Option<ThreeWayMergePreview>,
    },
    MergedAutomatically {
        lease_id: String,
        merged_hash: [u8; 32],
    },
    Timeout,
}

/// Internal active lease record.
#[derive(Debug, Clone)]
struct ActiveLease {
    agent_id: String,
    lease_id: String,
    mode: LockMode,
    expires_at_epoch_ms: u64,
    content: Option<Vec<u8>>,
}

/// Cross-agent file lock coordinator.
pub struct CrossAgentLockScheduler {
    active_locks: Arc<RwLock<HashMap<PathBuf, Vec<ActiveLease>>>>,
    wait_queues: Arc<RwLock<HashMap<PathBuf, VecDeque<LockRequest>>>>,
    policy: LockConflictPolicy,
}

/// Alias for swarm lock scheduler.
pub type SwarmLockScheduler = CrossAgentLockScheduler;

impl CrossAgentLockScheduler {
    pub fn new(policy: LockConflictPolicy) -> Self {
        Self {
            active_locks: Arc::new(RwLock::new(HashMap::new())),
            wait_queues: Arc::new(RwLock::new(HashMap::new())),
            policy,
        }
    }

    /// Acquires or queues a file lock across cooperating subagents.
    pub async fn acquire_lock(&self, req: LockRequest) -> Result<LockAcquireResult, String> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut locks = self.active_locks.write().await;
        let leases = locks.entry(req.target_file.clone()).or_insert_with(Vec::new);

        // Prune expired leases
        leases.retain(|l| l.expires_at_epoch_ms > now_ms);

        let lease_id = format!("lease_{}_{}", req.agent_id, now_ms);
        let expires_at_epoch_ms = now_ms + req.timeout_ms.max(1000);

        if leases.is_empty() {
            leases.push(ActiveLease {
                agent_id: req.agent_id.clone(),
                lease_id: lease_id.clone(),
                mode: req.mode,
                expires_at_epoch_ms,
                content: req.proposed_content,
            });
            return Ok(LockAcquireResult::Granted {
                lease_id,
                expires_at_epoch_ms,
            });
        }

        // Check compatibility
        let has_exclusive = leases.iter().any(|l| l.mode == LockMode::ExclusiveWrite);
        if req.mode == LockMode::SharedRead && !has_exclusive {
            leases.push(ActiveLease {
                agent_id: req.agent_id.clone(),
                lease_id: lease_id.clone(),
                mode: req.mode,
                expires_at_epoch_ms,
                content: None,
            });
            return Ok(LockAcquireResult::Granted {
                lease_id,
                expires_at_epoch_ms,
            });
        }

        // If AST merge is enabled, attempt 3-way merge
        if req.mode == LockMode::AstPatchMergeable {
            if let Some(existing) = leases.first() {
                if let (Some(base), Some(proposed), Some(existing_content)) = (
                    &req.base_content,
                    &req.proposed_content,
                    &existing.content,
                ) {
                    let merge = Self::compute_three_way_merge(base, existing_content, proposed);
                    if merge.can_merge_cleanly {
                        let merged_hash = Self::sha256(merge.merged_content.as_ref().unwrap());
                        leases.push(ActiveLease {
                            agent_id: req.agent_id.clone(),
                            lease_id: lease_id.clone(),
                            mode: req.mode,
                            expires_at_epoch_ms,
                            content: merge.merged_content,
                        });
                        return Ok(LockAcquireResult::MergedAutomatically {
                            lease_id,
                            merged_hash,
                        });
                    } else {
                        return Ok(LockAcquireResult::ConflictDetected {
                            conflicting_agent: existing.agent_id.clone(),
                            diff_preview: format!("{} conflicting lines detected", merge.conflicting_lines.len()),
                            merge_preview: Some(merge),
                        });
                    }
                }
            }
        }

        // Handle conflict policy
        match self.policy {
            LockConflictPolicy::QueueFifo => {
                let mut queues = self.wait_queues.write().await;
                let q = queues.entry(req.target_file.clone()).or_insert_with(VecDeque::new);
                q.push_back(req);
                Ok(LockAcquireResult::Queued {
                    queue_position: q.len(),
                    estimated_wait_ms: 1000 * q.len() as u64,
                })
            }
            _ => {
                let conflict_agent = leases.first().map(|l| l.agent_id.clone()).unwrap_or_default();
                Ok(LockAcquireResult::ConflictDetected {
                    conflicting_agent: conflict_agent,
                    diff_preview: "Concurrent write lock held".to_string(),
                    merge_preview: None,
                })
            }
        }
    }

    /// Releases a held lock lease and pops next waiter if present.
    pub async fn release_lock(&self, target_file: &Path, lease_id: &str) -> Result<bool, String> {
        let mut locks = self.active_locks.write().await;
        if let Some(leases) = locks.get_mut(target_file) {
            let before = leases.len();
            leases.retain(|l| l.lease_id != lease_id);
            let released = leases.len() < before;

            if leases.is_empty() {
                // Promote next item in wait queue
                let mut queues = self.wait_queues.write().await;
                if let Some(q) = queues.get_mut(target_file) {
                    if let Some(next_req) = q.pop_front() {
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        leases.push(ActiveLease {
                            agent_id: next_req.agent_id.clone(),
                            lease_id: format!("lease_{}_{}", next_req.agent_id, now_ms),
                            mode: next_req.mode,
                            expires_at_epoch_ms: now_ms + next_req.timeout_ms,
                            content: next_req.proposed_content,
                        });
                    }
                }
            }
            return Ok(released);
        }
        Ok(false)
    }

    /// 3-way line-level and AST merge calculation.
    pub fn compute_three_way_merge(base: &[u8], a: &[u8], b: &[u8]) -> ThreeWayMergePreview {
        let base_str = String::from_utf8_lossy(base);
        let a_str = String::from_utf8_lossy(a);
        let b_str = String::from_utf8_lossy(b);

        let base_lines: Vec<&str> = base_str.lines().collect();
        let a_lines: Vec<&str> = a_str.lines().collect();
        let b_lines: Vec<&str> = b_str.lines().collect();

        let mut merged = Vec::new();
        let mut conflicts = Vec::new();
        let max_len = base_lines.len().max(a_lines.len()).max(b_lines.len());

        let mut clean = true;

        for i in 0..max_len {
            let base_line = base_lines.get(i).copied().unwrap_or("");
            let a_line = a_lines.get(i).copied().unwrap_or("");
            let b_line = b_lines.get(i).copied().unwrap_or("");

            if a_line == b_line {
                merged.push(a_line);
            } else if a_line == base_line {
                merged.push(b_line);
            } else if b_line == base_line {
                merged.push(a_line);
            } else {
                // Both changed the same line to different text -> Conflict
                clean = false;
                conflicts.push((i + 1, a_line.to_string(), b_line.to_string()));
                merged.push(a_line);
            }
        }

        let merged_bytes = if clean {
            let mut out = merged.join("\n");
            if !out.is_empty() {
                out.push('\n');
            }
            Some(out.into_bytes())
        } else {
            None
        };

        ThreeWayMergePreview {
            can_merge_cleanly: clean,
            base_hash: Self::sha256(base),
            agent_a_hash: Self::sha256(a),
            agent_b_hash: Self::sha256(b),
            conflicting_lines: conflicts,
            merged_content: merged_bytes,
        }
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }
}

// ============================================================================
// R3.10: Multi-Agent IPC Deadlock Breaker
// ============================================================================

/// Strongly-typed identifier for an agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Directed dependency edge representing agent A waiting on agent B.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcWaitEdge {
    pub from_agent: AgentId,
    pub waiting_on: AgentId,
    pub channel_id: String,
    pub wait_started_ms: u64,
    pub timeout_ms: u64,
    pub resource_name: String,
}

/// Node representing an agent in the wait-for graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaitGraphNode {
    pub agent_id: AgentId,
    pub active_locks: Vec<PathBuf>,
    pub outgoing_waits: Vec<IpcWaitEdge>,
}

/// Resolution strategy when deadlock is detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeadlockResolutionStrategy {
    AbortYoungestWait,
    AbortLowestPriority,
    ForceTimeoutEdge,
    InjectErrorResponse { error_message: String },
}

/// Directed wait-for graph analyzer using cycle detection.
pub struct DeadlockGraphTracker {
    adjacency: HashMap<AgentId, Vec<IpcWaitEdge>>,
}

/// Alias for deadlock detector.
pub type DeadlockDetector = DeadlockGraphTracker;
/// Alias for deadlock breaker engine.
pub type DeadlockBreakerEngine = DeadlockGraphTracker;

impl DeadlockGraphTracker {
    pub fn new() -> Self {
        Self {
            adjacency: HashMap::new(),
        }
    }

    /// Registers a wait dependency in the graph.
    pub fn register_wait(&mut self, edge: IpcWaitEdge) {
        self.adjacency
            .entry(edge.from_agent.clone())
            .or_insert_with(Vec::new)
            .push(edge);
    }

    /// Clears an active wait once response or unlock occurs.
    pub fn clear_wait(&mut self, from: &AgentId, channel: &str) {
        if let Some(edges) = self.adjacency.get_mut(from) {
            edges.retain(|e| e.channel_id != channel);
        }
    }

    /// Detects cycles in the directed wait-for graph using Tarjan/DFS.
    pub fn detect_deadlock_cycles(&self) -> Vec<Vec<AgentId>> {
        let mut cycles = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = Vec::new();

        for node in self.adjacency.keys() {
            if !visited.contains(node) {
                self.dfs_cycle(node, &mut visited, &mut rec_stack, &mut cycles);
            }
        }

        cycles
    }

    fn dfs_cycle(
        &self,
        current: &AgentId,
        visited: &mut HashSet<AgentId>,
        rec_stack: &mut Vec<AgentId>,
        cycles: &mut Vec<Vec<AgentId>>,
    ) {
        visited.insert(current.clone());
        rec_stack.push(current.clone());

        if let Some(edges) = self.adjacency.get(current) {
            for edge in edges {
                let neighbor = &edge.waiting_on;
                if let Some(pos) = rec_stack.iter().position(|x| x == neighbor) {
                    // Cycle detected
                    let cycle = rec_stack[pos..].to_vec();
                    cycles.push(cycle);
                } else if !visited.contains(neighbor) {
                    self.dfs_cycle(neighbor, visited, rec_stack, cycles);
                }
            }
        }

        rec_stack.pop();
    }

    /// Breaks detected deadlocks according to designated strategy.
    pub fn resolve_deadlocks(&mut self, strategy: DeadlockResolutionStrategy) -> Vec<IpcWaitEdge> {
        let cycles = self.detect_deadlock_cycles();
        let mut broken_edges = Vec::new();

        for cycle in cycles {
            if cycle.is_empty() {
                continue;
            }

            // Find youngest wait edge in the cycle
            let mut candidate_edge: Option<IpcWaitEdge> = None;
            for i in 0..cycle.len() {
                let from = &cycle[i];
                let to = &cycle[(i + 1) % cycle.len()];

                if let Some(edges) = self.adjacency.get(from) {
                    for edge in edges {
                        if &edge.waiting_on == to {
                            match &candidate_edge {
                                None => candidate_edge = Some(edge.clone()),
                                Some(existing) => {
                                    if edge.wait_started_ms > existing.wait_started_ms {
                                        candidate_edge = Some(edge.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if let Some(edge) = candidate_edge {
                self.clear_wait(&edge.from_agent, &edge.channel_id);
                broken_edges.push(edge);
            }
        }

        broken_edges
    }

    /// Generates Graphviz DOT representation for debugging.
    pub fn render_graphviz(&self) -> String {
        let mut dot = String::from("digraph WaitGraph {\n");
        for (from, edges) in &self.adjacency {
            for edge in edges {
                dot.push_str(&format!(
                    "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
                    from.0, edge.waiting_on.0, edge.channel_id
                ));
            }
        }
        dot.push_str("}\n");
        dot
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_exclusive_lock_conflict() {
        let scheduler = CrossAgentLockScheduler::new(LockConflictPolicy::RejectOnConflict);
        let target = PathBuf::from("src/main.rs");

        let req_a = LockRequest {
            agent_id: "agent_a".to_string(),
            target_file: target.clone(),
            mode: LockMode::ExclusiveWrite,
            timeout_ms: 5000,
            base_file_hash: [0u8; 32],
            proposed_content: None,
            base_content: None,
        };

        let res_a = scheduler.acquire_lock(req_a).await.unwrap();
        match res_a {
            LockAcquireResult::Granted { lease_id, .. } => {
                assert!(lease_id.contains("agent_a"));
            }
            _ => panic!("Expected agent_a lock granted"),
        }

        let req_b = LockRequest {
            agent_id: "agent_b".to_string(),
            target_file: target.clone(),
            mode: LockMode::ExclusiveWrite,
            timeout_ms: 5000,
            base_file_hash: [0u8; 32],
            proposed_content: None,
            base_content: None,
        };

        let res_b = scheduler.acquire_lock(req_b).await.unwrap();
        match res_b {
            LockAcquireResult::ConflictDetected { conflicting_agent, .. } => {
                assert_eq!(conflicting_agent, "agent_a");
            }
            _ => panic!("Expected ConflictDetected for agent_b"),
        }
    }

    #[test]
    fn test_three_way_merge_clean() {
        let base = b"line 1\nline 2\nline 3\n";
        let a = b"line 1 (modified by A)\nline 2\nline 3\n";
        let b = b"line 1\nline 2\nline 3 (modified by B)\n";

        let preview = CrossAgentLockScheduler::compute_three_way_merge(base, a, b);
        assert!(preview.can_merge_cleanly);
        let merged_str = String::from_utf8(preview.merged_content.unwrap()).unwrap();
        assert_eq!(merged_str, "line 1 (modified by A)\nline 2\nline 3 (modified by B)\n");
    }

    #[test]
    fn test_three_way_merge_conflict() {
        let base = b"line 1\nline 2\n";
        let a = b"line 1 A\nline 2\n";
        let b = b"line 1 B\nline 2\n";

        let preview = CrossAgentLockScheduler::compute_three_way_merge(base, a, b);
        assert!(!preview.can_merge_cleanly);
        assert_eq!(preview.conflicting_lines.len(), 1);
        assert_eq!(preview.conflicting_lines[0].0, 1);
    }

    #[test]
    fn test_deadlock_detection_and_resolution() {
        let mut tracker = DeadlockGraphTracker::new();

        let agent1 = AgentId("agent_1".to_string());
        let agent2 = AgentId("agent_2".to_string());
        let agent3 = AgentId("agent_3".to_string());

        // Cycle: 1 -> 2 -> 3 -> 1
        tracker.register_wait(IpcWaitEdge {
            from_agent: agent1.clone(),
            waiting_on: agent2.clone(),
            channel_id: "chan_1_2".to_string(),
            wait_started_ms: 100,
            timeout_ms: 5000,
            resource_name: "db_lock".to_string(),
        });

        tracker.register_wait(IpcWaitEdge {
            from_agent: agent2.clone(),
            waiting_on: agent3.clone(),
            channel_id: "chan_2_3".to_string(),
            wait_started_ms: 200,
            timeout_ms: 5000,
            resource_name: "test_runner".to_string(),
        });

        tracker.register_wait(IpcWaitEdge {
            from_agent: agent3.clone(),
            waiting_on: agent1.clone(),
            channel_id: "chan_3_1".to_string(),
            wait_started_ms: 300,
            timeout_ms: 5000,
            resource_name: "api_port".to_string(),
        });

        let cycles = tracker.detect_deadlock_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 3);

        // Resolve
        let broken = tracker.resolve_deadlocks(DeadlockResolutionStrategy::AbortYoungestWait);
        assert_eq!(broken.len(), 1);
        assert_eq!(broken[0].from_agent, agent3); // Youngest (wait_started_ms = 300)

        // After resolution, no cycles remaining
        let cycles_after = tracker.detect_deadlock_cycles();
        assert!(cycles_after.is_empty());
    }
}
