//! Coarse classification of observed operations for stats and reports.

pub mod operation;
pub mod suspicious;

pub use operation::{classify_path, Operation};
pub use suspicious::{classify_event, SuspicionSeverity, SuspiciousSignal};
