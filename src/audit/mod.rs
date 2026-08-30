//! Audit history indexing and daily digest.

pub mod digest;
pub mod history;

pub use digest::run_digest;
pub use history::{default_history_path, record_session_history, run_audit, AuditRecord};
