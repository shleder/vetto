//! FSEvents-based visibility — honest v0.1 stub.
//!
//! NOT implemented, NOT claimed. Seatbelt denials are invisible to FSEvents
//! anyway (enforcement vs observation gap); even allowed-file visibility
//! would arrive with 50-200ms latency. Reports show a persistent notice
//! instead, exactly like the Linux audit-feed-unavailable path.

use crate::events::bus::EventBus;

/// Returns Some(reason) when no watcher could be started (always, in v0.1).
pub fn spawn_watcher_if_available(_bus: &EventBus) -> Option<String> {
    Some(
        "FSEvents visibility is not implemented in v0.1; macOS sessions show \
          no allowed-file feed (enforcement is ACTIVE regardless)"
            .to_string(),
    )
}
