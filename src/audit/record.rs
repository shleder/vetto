//! Authoritative Machine-Verifiable Audit Record Specification (Phase 4 / NEXT_GEN §17.1).
//!
//! Provides strictly typed, schema-compliant JSON representations for append-only
//! audit ledgers (`vetto-audit.jsonl`).

use serde::{Deserialize, Serialize};

/// Record types supported by the Vetto audit ledger (§17.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecordType {
    SessionInit,
    SyscallDenial,
    FsMutation,
    ResourceSample,
    TreeExtinction,
    SessionVerdict,
}

/// Platform isolation tier classification (§17.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TierClassification {
    #[serde(rename = "TIER_1_LINUX")]
    Tier1Linux,
    #[serde(rename = "TIER_2_MACOS")]
    Tier2Macos,
    #[serde(rename = "TIER_3_WINDOWS")]
    Tier3Windows,
}

/// Action taken on an intercepted system call (§17.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SyscallActionTaken {
    Blocked,
    Audited,
}

/// Filesystem mutation type (§17.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FsMutationType {
    Created,
    Modified,
    Deleted,
}

/// Payload for SESSION_INIT record (§17.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInitPayload {
    pub platform: String,
    pub kernel_release: String,
    pub agent_name: String,
    pub tier: TierClassification,
}

/// Payload for SYSCALL_DENIAL record (§17.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallDenialPayload {
    pub syscall_name: String,
    pub target_path: String,
    pub lsm_backend: String,
    pub action_taken: SyscallActionTaken,
}

/// Payload for FS_MUTATION record (§17.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsMutationPayload {
    pub relative_path: String,
    pub mutation_type: FsMutationType,
    pub sha256_digest: String,
}

/// Payload for RESOURCE_SAMPLE record (§17.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceSamplePayload {
    pub cpu_percent: f64,
    pub memory_rss_bytes: u64,
    pub pid_count: u32,
}

/// Payload for TREE_EXTINCTION record (§17.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeExtinctionPayload {
    pub tier: String,
    pub survivors: u32,
    pub signal_sent: i32,
    pub elapsed_ms: u64,
    pub clean: bool,
}

/// Payload for SESSION_VERDICT record (§17.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionVerdictPayload {
    pub verdict: String,
    pub evidence_strength: String,
    pub exit_code: i32,
    pub root_dag_digest: String,
}

/// Union of all possible record payloads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuditPayload {
    SessionInit(SessionInitPayload),
    SyscallDenial(SyscallDenialPayload),
    FsMutation(FsMutationPayload),
    ResourceSample(ResourceSamplePayload),
    TreeExtinction(TreeExtinctionPayload),
    SessionVerdict(SessionVerdictPayload),
}

/// Concrete Machine-Verifiable Audit Record for `vetto-audit.jsonl` (§17.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VettoAuditRecord {
    pub timestamp_utc: String,
    pub record_type: RecordType,
    pub session_id: String,
    pub contract_digest: String,
    pub payload: AuditPayload,
}

impl VettoAuditRecord {
    /// Creates a new `VettoAuditRecord`.
    pub fn new(
        record_type: RecordType,
        session_id: impl Into<String>,
        contract_digest: impl Into<String>,
        payload: AuditPayload,
    ) -> Self {
        Self {
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
            record_type,
            session_id: session_id.into(),
            contract_digest: contract_digest.into(),
            payload,
        }
    }

    /// Helper to construct a SESSION_INIT record.
    pub fn session_init(
        session_id: impl Into<String>,
        contract_digest: impl Into<String>,
        platform: impl Into<String>,
        kernel_release: impl Into<String>,
        agent_name: impl Into<String>,
        tier: TierClassification,
    ) -> Self {
        Self::new(
            RecordType::SessionInit,
            session_id,
            contract_digest,
            AuditPayload::SessionInit(SessionInitPayload {
                platform: platform.into(),
                kernel_release: kernel_release.into(),
                agent_name: agent_name.into(),
                tier,
            }),
        )
    }

    /// Helper to construct a SYSCALL_DENIAL record.
    pub fn syscall_denial(
        session_id: impl Into<String>,
        contract_digest: impl Into<String>,
        syscall_name: impl Into<String>,
        target_path: impl Into<String>,
        lsm_backend: impl Into<String>,
        action_taken: SyscallActionTaken,
    ) -> Self {
        Self::new(
            RecordType::SyscallDenial,
            session_id,
            contract_digest,
            AuditPayload::SyscallDenial(SyscallDenialPayload {
                syscall_name: syscall_name.into(),
                target_path: target_path.into(),
                lsm_backend: lsm_backend.into(),
                action_taken,
            }),
        )
    }

    /// Helper to construct a FS_MUTATION record.
    pub fn fs_mutation(
        session_id: impl Into<String>,
        contract_digest: impl Into<String>,
        relative_path: impl Into<String>,
        mutation_type: FsMutationType,
        sha256_digest: impl Into<String>,
    ) -> Self {
        Self::new(
            RecordType::FsMutation,
            session_id,
            contract_digest,
            AuditPayload::FsMutation(FsMutationPayload {
                relative_path: relative_path.into(),
                mutation_type,
                sha256_digest: sha256_digest.into(),
            }),
        )
    }

    /// Helper to construct a RESOURCE_SAMPLE record.
    pub fn resource_sample(
        session_id: impl Into<String>,
        contract_digest: impl Into<String>,
        cpu_percent: f64,
        memory_rss_bytes: u64,
        pid_count: u32,
    ) -> Self {
        Self::new(
            RecordType::ResourceSample,
            session_id,
            contract_digest,
            AuditPayload::ResourceSample(ResourceSamplePayload {
                cpu_percent,
                memory_rss_bytes,
                pid_count,
            }),
        )
    }

    /// Helper to construct a TREE_EXTINCTION record.
    pub fn tree_extinction(
        session_id: impl Into<String>,
        contract_digest: impl Into<String>,
        tier: impl Into<String>,
        survivors: u32,
        signal_sent: i32,
        elapsed_ms: u64,
        clean: bool,
    ) -> Self {
        Self::new(
            RecordType::TreeExtinction,
            session_id,
            contract_digest,
            AuditPayload::TreeExtinction(TreeExtinctionPayload {
                tier: tier.into(),
                survivors,
                signal_sent,
                elapsed_ms,
                clean,
            }),
        )
    }

    /// Helper to construct a SESSION_VERDICT record from a `FinalVerdict`.
    pub fn session_verdict(
        session_id: impl Into<String>,
        contract_digest: impl Into<String>,
        verdict: &crate::audit::verdict::FinalVerdict,
        root_dag_digest: impl Into<String>,
    ) -> Self {
        Self::new(
            RecordType::SessionVerdict,
            session_id,
            contract_digest,
            AuditPayload::SessionVerdict(SessionVerdictPayload {
                verdict: verdict.status.label().to_string(),
                evidence_strength: verdict.strength.label().to_string(),
                exit_code: verdict.exit_code,
                root_dag_digest: root_dag_digest.into(),
            }),
        )
    }

    /// Serializes the record to canonical JSON line.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_types_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&RecordType::SessionInit).unwrap(),
            "\"SESSION_INIT\""
        );
        assert_eq!(
            serde_json::to_string(&RecordType::SyscallDenial).unwrap(),
            "\"SYSCALL_DENIAL\""
        );
        assert_eq!(
            serde_json::to_string(&RecordType::FsMutation).unwrap(),
            "\"FS_MUTATION\""
        );
        assert_eq!(
            serde_json::to_string(&RecordType::ResourceSample).unwrap(),
            "\"RESOURCE_SAMPLE\""
        );
        assert_eq!(
            serde_json::to_string(&RecordType::TreeExtinction).unwrap(),
            "\"TREE_EXTINCTION\""
        );
        assert_eq!(
            serde_json::to_string(&RecordType::SessionVerdict).unwrap(),
            "\"SESSION_VERDICT\""
        );
    }

    #[test]
    fn test_tier_classification_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&TierClassification::Tier1Linux).unwrap(),
            "\"TIER_1_LINUX\""
        );
        assert_eq!(
            serde_json::to_string(&TierClassification::Tier2Macos).unwrap(),
            "\"TIER_2_MACOS\""
        );
        assert_eq!(
            serde_json::to_string(&TierClassification::Tier3Windows).unwrap(),
            "\"TIER_3_WINDOWS\""
        );
    }

    #[test]
    fn test_syscall_action_taken_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&SyscallActionTaken::Blocked).unwrap(),
            "\"BLOCKED\""
        );
        assert_eq!(
            serde_json::to_string(&SyscallActionTaken::Audited).unwrap(),
            "\"AUDITED\""
        );
    }

    #[test]
    fn test_fs_mutation_type_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&FsMutationType::Created).unwrap(),
            "\"CREATED\""
        );
        assert_eq!(
            serde_json::to_string(&FsMutationType::Modified).unwrap(),
            "\"MODIFIED\""
        );
        assert_eq!(
            serde_json::to_string(&FsMutationType::Deleted).unwrap(),
            "\"DELETED\""
        );
    }
}
