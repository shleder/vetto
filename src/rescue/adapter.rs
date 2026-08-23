use anyhow::Result;

use super::types::{AdapterStatus, RescueContext, SessionRef, SessionView, SnapshotReceipt};

pub trait RescueAdapter: Send + Sync {
    fn id(&self) -> &'static str;

    fn detect(&self, context: &RescueContext) -> Result<AdapterStatus>;

    fn discover_sessions(&self, context: &RescueContext) -> Result<Vec<SessionRef>>;

    fn diagnose(&self, context: &RescueContext, session: &SessionRef) -> Result<SessionView>;

    fn snapshot(
        &self,
        context: &RescueContext,
        session: &SessionRef,
        destination: &std::path::Path,
    ) -> Result<SnapshotReceipt>;
}
