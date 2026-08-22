#![allow(dead_code)]

/// Terminal dashboard state for interactive supervision.
pub struct App {
    pub title: String,
    pub should_quit: bool,
}

impl App {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            should_quit: false,
        }
    }

    pub fn quit(&mut self) {
        self.should_quit = true;
    }
}
