use anyhow::Result;
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
        // Typed Policy (exit 1): the message says "not supported", so the
        // legacy substring fallback would otherwise mis-map this generic
        // adapter limitation to 125 (fail-closed sandbox error).
        Err(anyhow::Error::new(crate::error::VettoError::Policy(
            format!("repair is not supported by adapter {}", self.id()),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue::types::{Availability, RescueContext};

    struct StubAdapter;

    impl RescueAdapter for StubAdapter {
        fn id(&self) -> &'static str {
            "stub"
        }

        fn detect(&self, _context: &RescueContext) -> Result<AdapterStatus> {
            Ok(AdapterStatus {
                adapter: "stub".into(),
                availability: Availability::Unavailable,
                support_level: "stub".into(),
                reason: None,
            })
        }

        fn discover_sessions(&self, _context: &RescueContext) -> Result<Vec<SessionRef>> {
            Ok(Vec::new())
        }

        fn diagnose(&self, _context: &RescueContext, session: &SessionRef) -> Result<SessionView> {
            let _ = session;
            anyhow::bail!("unimplemented for stub")
        }

        fn snapshot(
            &self,
            _context: &RescueContext,
            _session: &SessionRef,
            _destination: &Path,
        ) -> Result<SnapshotReceipt> {
            anyhow::bail!("unimplemented for stub")
        }
    }

    #[test]
    fn unsupported_repair_is_a_generic_error_not_fail_closed() {
        // The default repair() message contains "not supported" but must
        // exit 1 (agent error), never 125 (fail-closed).
        let context = RescueContext::new(std::path::PathBuf::from("/tmp"));
        let session = SessionRef {
            adapter: "stub".into(),
            key: "k".into(),
            relative_path: "k".into(),
            bytes: 0,
            modified_unix_secs: None,
            source_path: std::path::PathBuf::from("/tmp/k"),
        };
        let err = StubAdapter
            .repair(&context, &session, Path::new("/tmp"))
            .expect_err("stub repair unsupported");
        assert_eq!(
            crate::exit_codes::map_error_to_exit_code(&err),
            crate::exit_codes::EXIT_AGENT_ERROR
        );
    }
}
