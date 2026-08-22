//! `--tui=statusline`: the agent keeps full terminal control (its own PTY at
//! `(rows-1, cols)`); vetto draws ONE status row on the last line using a
//! DECSTBM scroll region, repaint-capped at ~5 fps. `Ctrl+]` opens a
//! scrollable event overlay on the alternate screen.
//!
//! Honest limits: an agent that switches the terminal to its own alternate
//! screen will visually cover the status row for the duration; the row comes
//! back when the agent leaves the alternate screen. Bytes are never modified.

use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event as CEvent, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use tokio::sync::broadcast;

use crate::events::{Event, EventBus};
use crate::pty;
use crate::sandbox::handle::SandboxHandle;

use super::app::{self, AppState};
use super::input;

const REPAINT_INTERVAL: Duration = Duration::from_millis(200); // ~5 fps cap
const TICK: Duration = Duration::from_millis(20);
const REPLAY_CAP: usize = 1024 * 1024;

/// Run the session in statusline mode; returns the agent's exit code.
pub fn run(
    bus: &EventBus,
    pty_master: &OwnedFd,
    mut handle: SandboxHandle,
    tier: &str,
    net: &str,
    profile: &str,
) -> i32 {
    let mut rx = bus.subscribe();
    let mut app_state = AppState::new(tier, net, profile);
    let master = pty_master.as_raw_fd();

    let _ = terminal::enable_raw_mode();
    let _ = pty::set_nonblocking(master, true);
    let _ = pty::sigwinch::install();
    let fwd = input::Forwarder::spawn(master);

    let mut outer = terminal::size().unwrap_or((24, 80));
    set_scroll_region(outer.0.saturating_sub(1).max(1));

    let mut last_paint = Instant::now() - REPAINT_INTERVAL;
    let mut replay: Vec<u8> = Vec::new();

    let exit_code = loop {
        if let Some(code) = handle.try_wait() {
            break code;
        }

        // Outer resize -> resize inner pty (the kernel then signals the
        // agent's foreground group on the pty; we do not signal manually).
        if let Some((rows, cols)) = pty::resizer::sync_to_outer(master) {
            outer = (rows + 1, cols);
            set_scroll_region(rows);
        }

        // Ctrl+] -> scrollable event overlay.
        if fwd.take_overlay_request() {
            fwd.pause();
            run_overlay(&mut app_state, &mut rx, &mut handle, master, &mut replay);
            fwd.resume();
            let _ = terminal::enable_raw_mode();
            set_scroll_region(outer.0.saturating_sub(1).max(1));
            if !replay.is_empty() {
                let mut out = io::stdout();
                let _ = out.write_all(&replay);
                let _ = out.flush();
                replay.clear();
            }
            last_paint = Instant::now() - REPAINT_INTERVAL;
        }

        // Agent output pass-through: pty master -> our stdout, verbatim.
        let mut buf = [0u8; 8192];
        let n = pty::read_ready(master, &mut buf);
        if n > 0 {
            let mut out = io::stdout();
            let _ = out.write_all(&buf[..n]);
            let _ = out.flush();
        }

        app_state.drain(&mut rx);
        if last_paint.elapsed() >= REPAINT_INTERVAL {
            draw_status(outer.0, &app_state.status_text(outer.1));
            last_paint = Instant::now();
        }
        std::thread::sleep(TICK);
    };

    restore_terminal(outer.0);
    exit_code
}

/// Alternate-screen scrollable event overlay.
fn run_overlay(
    app_state: &mut AppState,
    rx: &mut broadcast::Receiver<Event>,
    handle: &mut SandboxHandle,
    master: RawFd,
    replay: &mut Vec<u8>,
) {
    let _ = execute!(io::stdout(), EnterAlternateScreen);
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let Ok(mut terminal) = ratatui::Terminal::new(backend) else {
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        return;
    };

    let mut offset_from_end: usize = 0;
    loop {
        app_state.drain(rx);

        // Keep draining the pty so the agent cannot stall while we overlay;
        // bytes are buffered and replayed verbatim after exit (capped).
        let mut buf = [0u8; 8192];
        let n = pty::read_ready(master, &mut buf);
        if n > 0 && replay.len() < REPLAY_CAP {
            replay.extend_from_slice(&buf[..n]);
        }

        let total = app_state.events.len();
        if total > 0 {
            offset_from_end = offset_from_end.min(total - 1);
        }

        if terminal
            .draw(|f| overlay_ui(f, app_state, offset_from_end))
            .is_err()
        {
            break;
        }
        if handle.try_wait().is_some() {
            break;
        }
        if event::poll(Duration::from_millis(100)).unwrap_or(false) {
            if let Ok(CEvent::Key(k)) = event::read() {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match (k.code, k.modifiers) {
                    (KeyCode::Esc, _) | (KeyCode::Char('q'), _) => break,
                    (KeyCode::Char(']'), KeyModifiers::CONTROL) => break,
                    (KeyCode::Up, _) => offset_from_end += 1,
                    (KeyCode::Down, _) => offset_from_end = offset_from_end.saturating_sub(1),
                    (KeyCode::PageUp, _) => offset_from_end += 10,
                    (KeyCode::PageDown, _) => offset_from_end = offset_from_end.saturating_sub(10),
                    _ => {}
                }
            }
        }
    }

    let _ = execute!(io::stdout(), LeaveAlternateScreen);
}

fn overlay_ui(f: &mut ratatui::Frame, app_state: &AppState, offset_from_end: usize) {
    use ratatui::layout::{Constraint, Direction, Layout};
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};

    let area = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);

    let header = Paragraph::new(vec![
        Line::from(Span::styled(
            format!(
                " vetto events — tier={} net={} profile={}",
                app_state.tier, app_state.net, app_state.profile
            ),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            " blocked={} files={} exec={} net={} notices={}  |  Esc/Ctrl+]/q close · Up/Down/PgUp/PgDn scroll",
            app_state.blocked, app_state.files, app_state.execs, app_state.net_requests,
            app_state.notices
        )),
    ])
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, chunks[0]);

    let total = app_state.events.len();
    let height = chunks[1].height.saturating_sub(2) as usize; // inside borders
    let end = total.saturating_sub(offset_from_end);
    let start = end.saturating_sub(height.max(1));

    let mut rows = Vec::new();
    for ev in app_state.events.iter().skip(start).take(end - start) {
        let blocked = matches!(ev, Event::BlockedAttempt { .. });
        let kind = if blocked { "BLOCKED" } else { ev.kind() };
        let style = if blocked {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        rows.push(Row::new(vec![kind.to_string(), app::describe(ev)]).style(style));
    }

    let table = Table::new(rows, vec![Constraint::Length(16), Constraint::Min(10)]).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" session events (best-effort observation) "),
    );
    f.render_widget(table, chunks[1]);

    let footer = Paragraph::new(format!(
        " showing {} of {} events, {} up from newest ",
        end - start,
        total,
        offset_from_end
    ));
    f.render_widget(footer, chunks[2]);
}

fn draw_status(rows_total: u16, text: &str) {
    let mut out: Vec<u8> = Vec::with_capacity(text.len() + 32);
    out.extend_from_slice(b"\x1b7"); // save cursor
    out.extend_from_slice(format!("\x1b[{rows_total};1H").as_bytes());
    out.extend_from_slice(b"\x1b[2K\x1b[7m"); // erase line + reverse video
    out.extend_from_slice(text.as_bytes());
    out.extend_from_slice(b"\x1b[0m\x1b8"); // attrs off + restore cursor
    let mut so = io::stdout();
    let _ = so.write_all(&out);
    let _ = so.flush();
}

/// DECSTBM 1..bottom: the agent's output scrolls above the reserved row.
fn set_scroll_region(bottom: u16) {
    let mut out = io::stdout();
    let _ = out.write_all(format!("\x1b[1;{bottom}r").as_bytes());
    let _ = out.flush();
}

fn restore_terminal(rows_total: u16) {
    let mut out = io::stdout();
    let _ = out.write_all(format!("\x1b[1;{rows_total}r").as_bytes());
    let _ = out.write_all(b"\x1b[0m");
    let _ = out.flush();
    let _ = terminal::disable_raw_mode();
}
