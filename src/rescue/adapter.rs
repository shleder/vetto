use anyhow::{bail, Result};
use std::path::Path;

use super::types::{
    AdapterStatus, RepairReceipt, RescueContext, SessionRef, SessionView, SnapshotReceipt,
};

pub trait RescueAdapter: Send + Sync {
    fn id(&self) -> &'static str;

    fn detect(&self, context: &RescueContext) -> Result<AdapterStatus>;

    fn discover_sessions(&self, context: &RescueContext) -> Result<Vec<SessionRef>>;

    fn diagnose(&self, context: &RescueContext, session: &SessionRef) -> Result<SessionView>;

    fn snapshot(
        &self,
        context: &RescueContext,
        session: &SessionRef,
        destination: &Path,
    ) -> Result<SnapshotReceipt>;

    fn repair(
        &self,
        context: &RescueContext,
        session: &SessionRef,
        backup_dir: &Path,
    ) -> Result<RepairReceipt> {
        let _ = (context, session, backup_dir);
        bail!("repair is not supported by adapter {}", self.id());
    }
}
