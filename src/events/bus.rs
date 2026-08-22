//! tokio broadcast bus carrying session events to every consumer
//! (statusline, JSONL sink, report stats, overlay TUI).

use tokio::sync::broadcast;

use super::types::Event;

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(4096);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// Synchronous publish; safe to call from non-async contexts.
    /// Errors are ignored deliberately: zero live receivers is not a fault.
    pub fn publish(&self, event: Event) {
        let _ = self.tx.send(event);
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
