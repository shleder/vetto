//! `--tui=full`: vetto owns the alternate-screen dashboard; the agent runs
//! HEADLESS (`codex exec`, `claude -p`) with captured stdout/stderr shown in
//! a pane. For batch/CI/observability runs.

use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::event::{self, Event as CEvent, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};
use ratatui::Terminal;

use crate::events::EventBus;
use crate::sandbox::handle::SandboxHandle;

use super::app::{self, AppState};

const OUTPUT_CAP: usize = 512 * 1024;

type SharedBuf = Arc<Mutex<Vec<u8>>>;

/// Run the session in full-dashboard mode; returns the agent's exit code.
pub fn run(
    bus: &EventBus,
    stdout_r: OwnedFd,
    stderr_r: OwnedFd,
    mut handle: SandboxHandle,
    tier: &str,
    net: &str,
    profile: &str,
) -> i32 {
    let mut rx = bus.subscribe();
    let mut app_state = AppState::new(tier, net, profile);

    let out_buf: SharedBuf = Arc::new(Mutex::new(Vec::new()));
    let err_buf: SharedBuf = Arc::new(Mutex::new(Vec::new()));
    spawn_pipe_reader(stdout_r, Arc::clone(&out_buf));
    spawn_pipe_reader(stderr_r, Arc::clone(&err_buf));

    let _ = terminal::enable_raw_mode();
    let _ = execute!(io::stdout(), EnterAlternateScreen);
    let backend = CrosstermBackend::new(io::stdout());
    let Ok(mut terminal) = Terminal::new(backend) else {
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
        return handle.wait();
    };

    let mut scroll_up: usize = 0; // lines up from the tail
    let exit_code = loop {
        app_state.drain(&mut rx);

        if terminal
            .draw(|f| dashboard_ui(f, &app_state, &out_buf, &err_buf, scroll_up))
            .is_err()
        {
            break -1;
        }

        if event::poll(Duration::from_millis(100)).unwrap_or(false) {
            if let Ok(CEvent::Key(k)) = event::read() {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        handle.terminate();
                        break handle.wait();
                    }
                    KeyCode::Up => scroll_up += 1,
                    KeyCode::Down => scroll_up = scroll_up.saturating_sub(1),
                    KeyCode::PageUp => scroll_up += 20,
                    KeyCode::PageDown => scroll_up = scroll_up.saturating_sub(20),
                    _ => {}
                }
            }
        }
        if let Some(code) = handle.try_wait() {
            break code;
        }
    };

    let _ = execute!(io::stdout(), LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();
    exit_code
}

fn spawn_pipe_reader(fd: OwnedFd, buf: SharedBuf) {
    std::thread::Builder::new()
        .name("vetto-pipe-reader".into())
        .spawn(move || {
            let mut file: std::fs::File = fd.into();
            let mut chunk = [0u8; 8192];
            loop {
                match file.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut b) = buf.lock() {
                            b.extend_from_slice(&chunk[..n]);
                            if b.len() > OUTPUT_CAP {
                                let excess = b.len() - OUTPUT_CAP;
                                b.drain(..excess);
                            }
                        }
                    }
                }
            }
        })
        .expect("spawn pipe reader");
}

fn dashboard_ui(
    f: &mut ratatui::Frame,
    app_state: &AppState,
    out_buf: &SharedBuf,
    err_buf: &SharedBuf,
    scroll_up: usize,
) {
    let area = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Percentage(55),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);

    // Header: badges + counters.
    let blocked_style = if app_state.blocked > 0 {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" vetto v{}", env!("CARGO_PKG_VERSION")),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "  tier={}  net={}  profile={}",
            app_state.tier, app_state.net, app_state.profile
        )),
        Span::raw(format!(
            "  blocked={}  files={}  exec={}  net={}",
            app_state.blocked, app_state.files, app_state.execs, app_state.net_requests
        )),
        Span::styled(
            if app_state.blocked > 0 {
                "  ⚠ BLOCKED"
            } else {
                "  ✓"
            },
            blocked_style,
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, chunks[0]);

    // Agent output pane (stdout + interleaved stderr tail).
    let text = {
        let o = out_buf.lock().map(|b| b.clone()).unwrap_or_default();
        let e = err_buf.lock().map(|b| b.clone()).unwrap_or_default();
        let mut all = o;
        all.extend_from_slice(&e);
        all
    };
    let text = String::from_utf8_lossy(&text);
    let line_count = text.lines().count().max(1);
    let visible = chunks[1].height.saturating_sub(2) as usize;
    let scroll_base = line_count.saturating_sub(visible);
    let scroll = scroll_base.saturating_sub(scroll_up.min(scroll_base));
    let output = Paragraph::new(text.into_owned())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" agent output (headless capture) "),
        )
        .scroll((scroll as u16, 0));
    f.render_widget(output, chunks[1]);

    // Events table.
    let height = chunks[2].height.saturating_sub(2) as usize;
    let total = app_state.events.len();
    let start = total.saturating_sub(height.max(1));
    let mut rows = Vec::new();
    for ev in app_state.events.iter().skip(start) {
        let blocked = matches!(ev, crate::events::Event::BlockedAttempt { .. });
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
    f.render_widget(table, chunks[2]);

    let footer = Paragraph::new(" q quit (kills agent) · Up/Down/PgUp/PgDn scroll output ");
    f.render_widget(footer, chunks[3]);
}
