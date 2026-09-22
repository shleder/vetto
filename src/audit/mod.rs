//! Audit history indexing, session security inspection, daily digest, and verdict evaluation.

pub mod chain;
pub mod diff_sessions;
pub mod digest;
pub mod history;
pub mod recap;
pub mod record;
pub mod verdict;

pub use digest::run_digest;
pub use history::{
    default_history_path, inspect_latest_session, inspect_session, record_session_history,
    run_audit, run_audit_command, AuditRecord, SessionAuditDetail,
};
pub use recap::{format_session_recap, SessionRecapInput, RECAP_TOP_N};
pub use record::{
    AuditPayload, FsMutationPayload, FsMutationType, RecordType, ResourceSamplePayload,
    SessionInitPayload, SessionVerdictPayload, SyscallActionTaken, SyscallDenialPayload,
    TierClassification, TreeExtinctionPayload, VettoAuditRecord,
};
pub use verdict::{EvidenceStrength, FinalVerdict, VerdictEngine, VerdictStatus};
