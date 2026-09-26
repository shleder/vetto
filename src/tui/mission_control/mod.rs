//! Vetto Interactive TUI Mission Control Dashboard.
//!
//! Provides a cybernetic dashboard for fleet agent management, sandbox VFS inspection,
//! kernel diagnostics, and session rollback/undo.
//! Triggered strictly via bare `vetto` in an interactive TTY.

pub mod state;
pub mod theme;
pub mod ui;

use std::io::{self, stdout};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

pub use state::{AgentCard, DashboardState, MissionTab};
pub use theme::{Theme, ThemeMode};

const TICK_RATE: Duration = Duration::from_millis(250);

/// Runs the interactive Mission Control dashboard in the active terminal.
///
/// Sets raw mode, switches to alternate screen, hides cursor, installs a panic hook
/// ensuring terminal restoration, and enters the 250ms event polling loop.
pub fn run_dashboard(theme_override: Option<&str>) -> Result<()> {
    // 1. Setup raw mode and alternate screen
    enable_raw_mode().context("failed to enable raw mode")?;
    execute!(stdout(), EnterAlternateScreen, Hide).context("failed to enter alternate screen")?;

    // 2. Install panic hook ensuring terminal restoration on panic
    let original_hook = Arc::new(std::panic::take_hook());
    let hook_clone = Arc::clone(&original_hook);
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
        let _ = disable_raw_mode();
        hook_clone(panic_info);
    }));

    // 3. Initialize terminal backend
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;

    // 4. Initialize dashboard state
    let mut state = DashboardState::new(theme_override);

    // 5. Main event loop
    let mut last_tick = Instant::now();

    let loop_result = loop {
        if let Err(e) = terminal.draw(|f| ui::draw(f, &state)) {
            break Err(e).context("failed to draw dashboard frame");
        }

        let timeout = TICK_RATE
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_millis(0));

        match event::poll(timeout) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key)) => {
                    if key.kind == KeyEventKind::Press {
                        // Global Ctrl+C handler
                        if key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL)
                        {
                            break Ok(());
                        }

                        match key.code {
                            // Tab switching [1-4]
                            KeyCode::Char('1') => state.active_tab = MissionTab::Agents,
                            KeyCode::Char('2') => state.active_tab = MissionTab::Sandbox,
                            KeyCode::Char('3') => {
                                state.active_tab = MissionTab::Doctor;
                                if state.doctor_report.is_none() {
                                    state.doctor_report = Some(
                                        crate::doctor::preflight::execute_preflight_diagnostics(),
                                    );
                                }
                            }
                            KeyCode::Char('4') => state.active_tab = MissionTab::Sessions,

                            // Tab cycling (Tab / BackTab)
                            KeyCode::Tab => {
                                state.active_tab = state.active_tab.next();
                                if state.active_tab == MissionTab::Doctor
                                    && state.doctor_report.is_none()
                                {
                                    state.doctor_report = Some(
                                        crate::doctor::preflight::execute_preflight_diagnostics(),
                                    );
                                }
                            }
                            KeyCode::BackTab => {
                                state.active_tab = state.active_tab.prev();
                                if state.active_tab == MissionTab::Doctor
                                    && state.doctor_report.is_none()
                                {
                                    state.doctor_report = Some(
                                        crate::doctor::preflight::execute_preflight_diagnostics(),
                                    );
                                }
                            }

                            // Vertical navigation (Up/k, Down/j)
                            KeyCode::Up | KeyCode::Char('k') => state.select_prev(),
                            KeyCode::Down | KeyCode::Char('j') => state.select_next(),

                            // Space: Toggle shim for selected agent
                            KeyCode::Char(' ') => {
                                if let Err(e) = state.toggle_shim() {
                                    state.set_status(format!("Error toggling shim: {e}"));
                                }
                            }

                            // 't': Toggle color theme (Arasaka <-> Circuit)
                            KeyCode::Char('t') => {
                                state.theme.toggle();
                                state.set_status(format!("Active theme: {}", state.theme.name()));
                            }

                            // 'r': Refresh system state & agent discovery
                            KeyCode::Char('r') => {
                                state.refresh();
                            }

                            // 'u': Undo / Rollback selected session snapshot (Sessions tab)
                            KeyCode::Char('u') => {
                                if state.active_tab == MissionTab::Sessions {
                                    if let Err(e) = state.rollback_selected_snapshot() {
                                        state.set_status(format!("Rollback failed: {e}"));
                                    }
                                } else {
                                    state.set_status(
                                        "Rollback [u] is only available on Sessions tab ([4])",
                                    );
                                }
                            }

                            // Enter: Launch selected agent in sandbox
                            KeyCode::Enter => {
                                if state.active_tab == MissionTab::Agents {
                                    if let Some(agent) =
                                        state.installed_agents.get(state.selected_agent)
                                    {
                                        state.pending_launch_agent = Some(agent.name.to_string());
                                        break Ok(());
                                    } else {
                                        state.set_status("No agent selected to launch");
                                    }
                                } else {
                                    state.set_status(
                                        "Launch [Enter] is only available on Agents tab ([1])",
                                    );
                                }
                            }

                            // Quit cleanly
                            KeyCode::Char('q') | KeyCode::Esc => {
                                break Ok(());
                            }

                            _ => {}
                        }
                    }
                }
                Ok(Event::Resize(_, _)) => {
                    // Window resized; next loop iteration will redraw with new dimensions
                }
                Ok(_) => {}
                Err(e) => {
                    break Err(e).context("error reading crossterm event");
                }
            },
            Ok(false) => {
                // Timeout elapsed with no input
            }
            Err(e) => {
                break Err(e).context("error polling crossterm events");
            }
        }

        if last_tick.elapsed() >= TICK_RATE {
            last_tick = Instant::now();
        }
    };

    // 6. Clean up terminal
    let _ = execute!(stdout(), LeaveAlternateScreen, Show);
    let _ = disable_raw_mode();

    // 7. Restore original panic hook
    let hook_restore = Arc::clone(&original_hook);
    std::panic::set_hook(Box::new(move |info| {
        hook_restore(info);
    }));

    // If an error occurred in the loop, return it now
    loop_result?;

    // 8. If an agent launch was requested, launch it now in sandbox
    if let Some(agent_name) = state.pending_launch_agent {
        println!("Launching '{}' inside Vetto sandbox...", agent_name);
        let current_exe =
            std::env::current_exe().context("failed to get current executable path")?;
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new(current_exe)
                .arg("--")
                .arg(&agent_name)
                .exec();
            return Err(anyhow::anyhow!(
                "failed to exec agent '{}': {err}",
                agent_name
            ));
        }
        #[cfg(not(unix))]
        {
            let status = std::process::Command::new(current_exe)
                .arg("--")
                .arg(&agent_name)
                .status()
                .context("failed to execute agent in sandbox")?;
            if let Some(code) = status.code() {
                if code != 0 {
                    std::process::exit(code);
                }
            }
        }
    }

    Ok(())
}
