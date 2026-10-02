//! `--tui=statusline`: the agent keeps full terminal control (its own PTY at
//! `(rows-1, cols)`); vetto draws ONE status row on the last line using a
//! DECSTBM scroll region, repaint-capped at ~5 fps. `Ctrl+]` opens a
//! scrollable event overlay on the alternate screen.
//!
//! Honest limits: an agent that switches the terminal to its own alternate
//! screen will visually cover the status row for the duration; the row comes
//! back when the agent leaves the alternate screen. Bytes are never modified.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event as CEvent, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use tokio::sync::broadcast;

use crate::events::{Event, EventBus};
use crate::pty;
use crate::sandbox::handle::SandboxHandle;

use super::app::{self, AppState, EventFilter};
use super::input;

const REPAINT_INTERVAL: Duration = Duration::from_millis(200); // ~5 fps cap
const TICK: Duration = Duration::from_millis(20);
const REPLAY_CAP: usize = 1024 * 1024;

/// Non-blocking buffered writer for stdout in statusline mode (INV-25).
/// Prevents stdout pipe/terminal congestion from stalling PTY reads or freezing
/// the event loop. Ephemeral statusline frames are dropped if stdout is congested;
/// agent output is bounded-buffered and drained non-blocking.
pub struct NonblockingStdout {
    raw_fd: RawFd,
    orig_flags: Option<libc::c_int>,
    buffer: VecDeque<u8>,
    max_capacity: usize,
    pub overflow_count: usize,
}

impl NonblockingStdout {
    pub fn new(max_capacity: usize) -> Self {
        let raw_fd = libc::STDOUT_FILENO;
        let orig_flags = unsafe {
            let flags = libc::fcntl(raw_fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                Some(flags)
            } else {
                None
            }
        };
        Self {
            raw_fd,
            orig_flags,
            buffer: VecDeque::with_capacity(32 * 1024),
            max_capacity,
            overflow_count: 0,
        }
    }

    /// Append agent output to the buffer, strictly bounded by max_capacity.
    pub fn write_agent_output(&mut self, data: &[u8]) {
        if data.len() >= self.max_capacity {
            self.buffer.clear();
            let slice = &data[data.len() - self.max_capacity..];
            self.buffer.extend(slice);
            self.overflow_count += 1;
        } else {
            if self.buffer.len() + data.len() > self.max_capacity {
                let overflow = (self.buffer.len() + data.len()) - self.max_capacity;
                self.buffer.drain(..overflow);
                self.overflow_count += 1;
            }
            self.buffer.extend(data);
        }
        self.flush_nonblocking();
    }

    /// Attempt to draw a status line frame. If stdout is congested, the frame
    /// is discarded immediately (ephemeral UI discard).
    pub fn write_status_frame(&mut self, frame: &[u8]) {
        // If buffer already has backpressure (> 16KB), drop ephemeral status frame
        if self.buffer.len() > 16 * 1024 || !self.is_writable() {
            return;
        }
        self.buffer.extend(frame);
        self.flush_nonblocking();
    }

    /// Check if stdout fd is currently writable using poll(POLLOUT, timeout=0).
    pub fn is_writable(&self) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.raw_fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let r = unsafe { libc::poll(&mut pfd, 1, 0) };
        r > 0
            && (pfd.revents & libc::POLLOUT != 0)
            && (pfd.revents & (libc::POLLERR | libc::POLLNVAL)) == 0
    }

    /// Drain as many bytes as possible to stdout without blocking.
    pub fn flush_nonblocking(&mut self) {
        while !self.buffer.is_empty() {
            if !self.is_writable() {
                break;
            }
            let (first, _) = self.buffer.as_slices();
            if first.is_empty() {
                break;
            }
            let n =
                unsafe { libc::write(self.raw_fd, first.as_ptr().cast(), first.len().min(8192)) };
            if n > 0 {
                self.buffer.drain(..n as usize);
            } else if n < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => break,
                    Some(libc::EPIPE) => {
                        self.buffer.clear();
                        break;
                    }
                    _ => break,
                }
            } else {
                break;
            }
        }
    }

    /// Final bounded flush on exit (wait up to budget without busy looping).
    pub fn flush_bounded(&mut self, budget: Duration) {
        let start = Instant::now();
        while !self.buffer.is_empty() {
            let elapsed = start.elapsed();
            if elapsed >= budget {
                break;
            }
            let remaining = budget - elapsed;
            let timeout_ms = remaining.as_millis().clamp(1, 50) as libc::c_int;

            let mut pfd = libc::pollfd {
                fd: self.raw_fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if r < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }
            if r == 0 {
                continue;
            }
            if pfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                self.buffer.clear();
                break;
            }
            if pfd.revents & libc::POLLOUT != 0 {
                let (first, _) = self.buffer.as_slices();
                if first.is_empty() {
                    break;
                }
                let n = unsafe {
                    libc::write(self.raw_fd, first.as_ptr().cast(), first.len().min(8192))
                };
                if n > 0 {
                    self.buffer.drain(..n as usize);
                } else if n < 0 {
                    let err = io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::EINTR) => continue,
                        Some(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => continue,
                        Some(libc::EPIPE) => {
                            self.buffer.clear();
                            break;
                        }
                        _ => break,
                    }
                } else {
                    break;
                }
            }
        }
    }

    /// DECSTBM 1..bottom: the agent's output scrolls above the reserved row.
    pub fn set_scroll_region(&mut self, bottom: u16) {
        let seq = format!("\x1b[1;{bottom}r");
        self.buffer.extend(seq.as_bytes());
        self.flush_nonblocking();
    }

    /// Restore terminal scrolling and clean up.
    pub fn restore_terminal(&mut self, rows_total: u16) {
        let seq = format!("\x1b[1;{rows_total}r\x1b[0m");
        self.buffer.extend(seq.as_bytes());
        self.flush_bounded(Duration::from_millis(100));
        let _ = terminal::disable_raw_mode();
    }
}

impl Drop for NonblockingStdout {
    fn drop(&mut self) {
        if let Some(orig) = self.orig_flags {
            unsafe {
                libc::fcntl(self.raw_fd, libc::F_SETFL, orig);
            }
        }
    }
}

/// Run the session in statusline mode; returns the agent's exit code.
///
/// The handle is borrowed: ownership (and the mandatory post-run tree sweep)
/// stays with the production execution boundary. The loop polls `try_wait`
/// (never a bare blocking wait).
pub fn run(
    bus: &EventBus,
    pty_master: &OwnedFd,
    handle: &mut SandboxHandle,
    tier: &str,
    net: &str,
    profile: &str,
    timeout: Option<Duration>,
) -> (i32, bool) {
    let mut rx = bus.subscribe();
    let mut app_state = AppState::new(tier, net, profile);
    let master = pty_master.as_raw_fd();
    let deadline = timeout.map(|d| Instant::now() + d);

    let _ = terminal::enable_raw_mode();
    let _ = pty::set_nonblocking(master, true);
    let _ = pty::sigwinch::install();
    let fwd = input::Forwarder::spawn(master);

    let mut stdout_writer = NonblockingStdout::new(256 * 1024);
    let mut outer = terminal::size().unwrap_or((24, 80));
    stdout_writer.set_scroll_region(outer.0.saturating_sub(1).max(1));

    let mut last_paint = Instant::now() - REPAINT_INTERVAL;
    let mut painted_generation = u64::MAX;
    let mut replay: Vec<u8> = Vec::new();

    let mut redactor = pty::AnsiRedactor::new();

    let exit_code = loop {
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                let _ = handle.terminate();
                let drain_start = Instant::now();
                while drain_start.elapsed() < Duration::from_millis(200) {
                    if handle.try_wait().is_some() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                stdout_writer.flush_bounded(Duration::from_millis(100));
                stdout_writer.restore_terminal(outer.0);
                return (crate::exit_codes::EXIT_TIMEOUT, true);
            }
        }
        // Outer resize -> resize inner pty (the kernel then signals the
        // agent's foreground group on the pty; we do not signal manually).
        if let Some((rows, cols)) = pty::resizer::sync_to_outer(master) {
            outer = (rows + 1, cols);
            stdout_writer.set_scroll_region(rows);
        }

        // Ctrl+] -> scrollable event overlay.
        if fwd.take_overlay_request() {
            fwd.pause();
            run_overlay(&mut app_state, &mut rx, handle, master, &mut replay);
            fwd.resume();
            let _ = terminal::enable_raw_mode();
            stdout_writer.set_scroll_region(outer.0.saturating_sub(1).max(1));
            if !replay.is_empty() {
                stdout_writer.write_agent_output(&replay);
                replay.clear();
            }
            last_paint = Instant::now() - REPAINT_INTERVAL;
        }

        // Agent output pass-through: pty master -> our stdout, with live ANSI redactor.
        let mut buf = [0u8; 8192];
        let n = pty::read_ready(master, &mut buf);
        if n > 0 {
            let redacted = redactor.redact_chunk(&buf[..n]);
            stdout_writer.write_agent_output(&redacted);
        }

        if let Some(code) = handle.try_wait() {
            // Drain any remaining bytes from master after child exit
            loop {
                let n = pty::read_ready(master, &mut buf);
                if n == 0 {
                    break;
                }
                let redacted = redactor.redact_chunk(&buf[..n]);
                stdout_writer.write_agent_output(&redacted);
            }
            let flushed = redactor.flush();
            if !flushed.is_empty() {
                stdout_writer.write_agent_output(&flushed);
            }
            stdout_writer.flush_bounded(Duration::from_millis(100));
            break code;
        }

        app_state.drain(&mut rx);
        if app_state.generation != painted_generation && last_paint.elapsed() >= REPAINT_INTERVAL {
            draw_status_buffered(&mut stdout_writer, outer.0, &app_state.status_text(outer.1));
            painted_generation = app_state.generation;
            last_paint = Instant::now();
        }
        stdout_writer.flush_nonblocking();
        std::thread::sleep(TICK);
    };

    stdout_writer.restore_terminal(outer.0);
    (exit_code, false)
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

    let mut overlay_redactor = pty::AnsiRedactor::new();
    let mut offset_from_end: usize = 0;
    let mut paused = false;
    loop {
        app_state.drain(rx);

        // Keep draining the pty so the agent cannot stall while we overlay;
        // bytes are buffered and replayed verbatim after exit (capped).
        let mut buf = [0u8; 8192];
        let n = pty::read_ready(master, &mut buf);
        if n > 0 && replay.len() < REPLAY_CAP {
            let redacted = overlay_redactor.redact_chunk(&buf[..n]);
            replay.extend_from_slice(&redacted);
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
                    (KeyCode::Char('p'), _) | (KeyCode::Char(' '), _) => {
                        if paused {
                            handle.resume();
                        } else {
                            handle.pause();
                        }
                        paused = !paused;
                        app_state.toggle_pause();
                    }
                    (KeyCode::Char('?'), _) => app_state.toggle_help(),
                    (KeyCode::Char('b'), _) => app_state.set_filter(EventFilter::Blocked),
                    (KeyCode::Char('f'), _) => app_state.set_filter(EventFilter::Files),
                    (KeyCode::Char('n'), _) => app_state.set_filter(EventFilter::Network),
                    (KeyCode::Char('s'), _) => app_state.set_filter(EventFilter::Suspicious),
                    (KeyCode::Char('a'), _) => app_state.set_filter(EventFilter::All),
                    (KeyCode::Char('e'), _) => {
                        let path = std::path::PathBuf::from("vetto-events.jsonl");
                        if let Err(error) = app_state.export_events(&path) {
                            tracing::warn!(
                                "could not export events to {}: {error}",
                                path.display()
                            );
                        }
                    }
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
            " state={} filter={} blocked={} files={} (r{} w{}) exec={} net={} notices={}  |  Esc/Ctrl+]/q close · Up/Down/PgUp/PgDn scroll",
            if app_state.paused { "paused" } else { "live" },
            app_state.filter.label(),
            app_state.blocked,
            app_state.files,
            app_state.file_reads,
            app_state.file_writes,
            app_state.execs,
            app_state.net_requests,
            app_state.notices
        )),
    ])
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, chunks[0]);

    let filtered = app_state.filtered_events();
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(chunks[1]);
    let total = filtered.len();
    let height = body[0].height.saturating_sub(2) as usize; // inside borders
    let end = total.saturating_sub(offset_from_end);
    let start = end.saturating_sub(height.max(1));

    let mut rows = Vec::new();
    for ev in filtered.iter().skip(start).take(end - start) {
        let blocked = matches!(ev, Event::BlockedAttempt { .. })
            || matches!(ev, Event::NetRequest { allowed: false, .. });
        let suspicious = crate::classifier::classify_event(ev).is_some();
        let kind = if blocked {
            "BLOCKED"
        } else if suspicious {
            "SUSPICIOUS"
        } else {
            ev.kind()
        };
        let style = if blocked {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else if suspicious {
            Style::default().fg(Color::Yellow)
        } else if matches!(ev, Event::NetRequest { .. }) {
            Style::default().fg(Color::Blue)
        } else {
            Style::default().fg(Color::Green)
        };
        rows.push(Row::new(vec![kind.to_string(), app::describe(ev)]).style(style));
    }

    let table = Table::new(rows, vec![Constraint::Length(16), Constraint::Min(10)]).block(
        Block::default().borders(Borders::ALL).title(format!(
            " session events [{}] (best-effort observation) ",
            app_state.filter.label()
        )),
    );
    f.render_widget(table, body[0]);

    let side = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(4),
            Constraint::Min(4),
        ])
        .split(body[1]);
    let blocked = app_state
        .events
        .iter()
        .rev()
        .filter_map(|event| match event {
            Event::BlockedAttempt { path, .. } => Some(path.as_str()),
            Event::NetRequest {
                host,
                allowed: false,
                ..
            } => Some(host.as_str()),
            _ => None,
        })
        .take(3)
        .collect::<Vec<_>>()
        .join("\n");
    f.render_widget(
        Paragraph::new(if blocked.is_empty() {
            "none observed".to_string()
        } else {
            blocked
        })
        .block(Block::default().borders(Borders::ALL).title(" blocked ")),
        side[0],
    );
    let files = app_state
        .file_tree
        .iter()
        .rev()
        .take(side[1].height.saturating_sub(2) as usize)
        .map(|(path, count)| format!("{count:>3} {path}"))
        .collect::<Vec<_>>()
        .join("\n");
    f.render_widget(
        Paragraph::new(if files.is_empty() {
            "no file observations".to_string()
        } else {
            files
        })
        .block(Block::default().borders(Borders::ALL).title(" file tree ")),
        side[1],
    );
    let n = app_state.network;
    f.render_widget(
        Paragraph::new(format!(
            "net {}/{}\nactivity {}\nsummary {} events",
            n.allowed,
            n.blocked,
            app_state.activity.len(),
            app_state.events_total
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" network / activity "),
        ),
        side[2],
    );

    let footer = Paragraph::new(format!(
        " showing {} of {} events, {} up from newest · p pause/resume · b blocked f files n network a all · e export · ? help ",
        end - start,
        total,
        offset_from_end
    ));
    f.render_widget(footer, chunks[2]);

    if app_state.help {
        let popup = centered_rect(76, 50, area);
        let help = Paragraph::new(
            "statusline overlay keys\n  p/Space pause or resume the sandboxed agent\n  b blocked · f files · n network · a all\n  e export events · arrows/PgUp scroll\n  Esc/Ctrl+] close overlay · q terminate agent",
        )
        .block(Block::default().borders(Borders::ALL).title(" help "));
        f.render_widget(help, popup);
    }
}

fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    area: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    use ratatui::layout::{Constraint, Direction, Layout};
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn draw_status_buffered(writer: &mut NonblockingStdout, rows_total: u16, text: &str) {
    let mut out: Vec<u8> = Vec::with_capacity(text.len() + 32);
    out.extend_from_slice(b"\x1b7"); // save cursor
    out.extend_from_slice(format!("\x1b[{rows_total};1H").as_bytes());
    out.extend_from_slice(b"\x1b[2K\x1b[7m"); // erase line + reverse video
    out.extend_from_slice(text.as_bytes());
    out.extend_from_slice(b"\x1b[0m\x1b8"); // attrs off + restore cursor
    writer.write_status_frame(&out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonblocking_stdout_capacity_bounds() {
        let mut writer = NonblockingStdout::new(64);
        assert_eq!(writer.max_capacity, 64);
        assert_eq!(writer.overflow_count, 0);

        // Within bounds
        let small = b"hello world";
        writer.write_agent_output(small);
        assert!(writer.buffer.len() <= 64);
        assert_eq!(writer.overflow_count, 0);

        // Exceeding capacity in a single chunk
        let huge = vec![b'x'; 128];
        writer.write_agent_output(&huge);
        assert!(writer.buffer.len() <= 64);
        assert_eq!(writer.overflow_count, 1);
    }

    #[test]
    fn test_nonblocking_stdout_flag_restoration() {
        let flags_before = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL) };
        {
            let writer = NonblockingStdout::new(1024);
            assert!(writer.orig_flags.is_some());
        }
        let flags_after = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL) };
        assert_eq!(flags_before, flags_after);
    }
}
