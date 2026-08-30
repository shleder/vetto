//! Full-screen dashboards for one or many sandboxed agents.
//!
//! Repaints are event-driven and capped at five per second. Input polling is
//! intentionally shorter than the repaint interval so pause/filter/navigation
//! remain responsive without turning the UI into a high-frequency ticker.

use std::io;
use std::os::fd::OwnedFd;
use std::sync::{atomic::Ordering, Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event as CEvent, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Wrap};
use ratatui::Terminal;

use crate::events::{Event, EventBus};
use crate::multi::{runtime::MultiRuntime, AgentStats};
use crate::sandbox::handle::SandboxHandle;

use super::app::{self, AppState, EventFilter};

const OUTPUT_CAP: usize = 512 * 1024;
const REPAINT_INTERVAL: Duration = Duration::from_millis(200); // <= 5 fps
const INPUT_INTERVAL: Duration = Duration::from_millis(25);

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

    let mut scroll_up: usize = 0;
    let mut paused = false;
    let mut last_paint = Instant::now() - REPAINT_INTERVAL;
    let mut drawn_generation = u64::MAX;
    let mut drawn_output_len = (usize::MAX, usize::MAX);
    let mut confirm_quit = false;
    let exit_code = loop {
        app_state.drain(&mut rx);
        let output_len = (
            out_buf.lock().map(|buf| buf.len()).unwrap_or(0),
            err_buf.lock().map(|buf| buf.len()).unwrap_or(0),
        );
        let changed = app_state.generation != drawn_generation || output_len != drawn_output_len;
        if changed && last_paint.elapsed() >= REPAINT_INTERVAL {
            let _ = terminal
                .draw(|f| dashboard_ui(f, &app_state, &out_buf, &err_buf, scroll_up, confirm_quit));
            drawn_generation = app_state.generation;
            drawn_output_len = output_len;
            last_paint = Instant::now();
        }

        if event::poll(INPUT_INTERVAL).unwrap_or(false) {
            if let Ok(CEvent::Key(k)) = event::read() {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                if confirm_quit {
                    match k.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            handle.terminate();
                            break handle.wait();
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            confirm_quit = false;
                            app_state.generation = app_state.generation.wrapping_add(1);
                        }
                        _ => {}
                    }
                    continue;
                }
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        confirm_quit = true;
                        app_state.generation = app_state.generation.wrapping_add(1);
                    }
                    KeyCode::Char('p') | KeyCode::Char(' ') => {
                        if paused {
                            handle.resume();
                        } else {
                            handle.pause();
                        }
                        paused = !paused;
                        app_state.toggle_pause();
                    }
                    KeyCode::Char('?') => app_state.toggle_help(),
                    KeyCode::Char('f') => cycle_filter(&mut app_state),
                    KeyCode::Char('b') => app_state.set_filter(EventFilter::Blocked),
                    KeyCode::Char('n') => app_state.set_filter(EventFilter::Network),
                    KeyCode::Char('s') => app_state.set_filter(EventFilter::Suspicious),
                    KeyCode::Char('l') => app_state.set_filter(EventFilter::Files),
                    KeyCode::Char('a') => app_state.set_filter(EventFilter::All),
                    KeyCode::Char('e') => export_state(&app_state),
                    KeyCode::Up => {
                        scroll_up = scroll_up.saturating_add(1);
                        app_state.scroll_by(1);
                    }
                    KeyCode::Down => {
                        scroll_up = scroll_up.saturating_sub(1);
                        app_state.scroll_by(-1);
                    }
                    KeyCode::PageUp => {
                        scroll_up = scroll_up.saturating_add(20);
                        app_state.scroll_by(20);
                    }
                    KeyCode::PageDown => {
                        scroll_up = scroll_up.saturating_sub(20);
                        app_state.scroll_by(-20);
                    }
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
            let mut redactor = crate::pty::AnsiRedactor::new();
            loop {
                match std::io::Read::read(&mut file, &mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let redacted = redactor.redact_chunk(&chunk[..n]);
                        if let Ok(mut b) = buf.lock() {
                            b.extend_from_slice(&redacted);
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
    confirm_quit: bool,
) {
    let area = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(5),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(f, app_state, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(68), Constraint::Percentage(32)])
        .split(chunks[1]);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(52), Constraint::Min(5)])
        .split(body[0]);
    render_output(f, out_buf, err_buf, left[0], scroll_up);
    render_events(f, app_state, left[1]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(4),
            Constraint::Min(5),
        ])
        .split(body[1]);
    render_blocked(f, app_state, right[0]);
    render_file_tree(f, app_state, right[1]);
    render_network(f, app_state, right[2]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[2]);
    render_activity(f, app_state, bottom[0]);
    render_summary(f, app_state, bottom[1]);

    let footer = if app_state.help {
        " ? close help · p/Space pause/resume · f cycle filter · b blocked · l files · n network · s suspicious · e export · q quit "
    } else {
        " ? help · p/Space pause/resume · f filter · b/l/n views · e export · arrows/PgUp scroll · q quit "
    };
    f.render_widget(Paragraph::new(footer), chunks[3]);

    if app_state.help {
        let popup = centered_rect(80, 60, area);
        let text = "Keys\n  p / Space   suspend or resume the sandboxed process\n  f           cycle event filters\n  b/l/n/s/a   blocked / files / network / suspicious / all\n  e           export the bounded event ring\n  arrows       navigate and scroll\n  q / Esc      ask before terminating the sandboxed agent\n\nObservation is best-effort; enforcement remains in the sandbox.";
        f.render_widget(
            Paragraph::new(text)
                .block(Block::default().borders(Borders::ALL).title(" help "))
                .wrap(Wrap { trim: false }),
            popup,
        );
    }
    if confirm_quit {
        let popup = centered_rect(48, 20, area);
        f.render_widget(
            Paragraph::new("Terminate agent? [y/N]")
                .block(Block::default().borders(Borders::ALL).title(" confirm ")),
            popup,
        );
    }
}

fn render_header(f: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let blocked_style = if state.blocked > 0 {
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
            "  {}  tier={}  net={}  profile={}  filter={}",
            if state.paused { "PAUSED" } else { "LIVE" },
            state.tier,
            state.net,
            state.profile,
            state.filter.label()
        )),
        Span::raw(format!(
            "  blocked={} suspicious={} files={} exec={} net={}",
            state.blocked, state.suspicious, state.files, state.execs, state.net_requests
        )),
        Span::styled(
            if state.blocked > 0 {
                "  BLOCKED"
            } else {
                "  OK"
            },
            blocked_style,
        ),
    ]))
    .block(Block::default().borders(Borders::ALL).title(" session "));
    f.render_widget(header, area);
}

fn render_output(
    f: &mut ratatui::Frame,
    out_buf: &SharedBuf,
    err_buf: &SharedBuf,
    area: Rect,
    scroll_up: usize,
) {
    let text = {
        let o = out_buf.lock().map(|b| b.clone()).unwrap_or_default();
        let e = err_buf.lock().map(|b| b.clone()).unwrap_or_default();
        let mut all = o;
        all.extend_from_slice(&e);
        String::from_utf8_lossy(&all).into_owned()
    };
    let line_count = text.lines().count().max(1);
    let visible = area.height.saturating_sub(2) as usize;
    let scroll_base = line_count.saturating_sub(visible);
    let scroll = scroll_base.saturating_sub(scroll_up.min(scroll_base));
    f.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" live output "),
            )
            .scroll((scroll as u16, 0)),
        area,
    );
}

fn render_events(f: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let height = area.height.saturating_sub(2) as usize;
    let events = state.filtered_events();
    let end = events.len().saturating_sub(state.scroll);
    let start = end.saturating_sub(height.max(1));
    let rows = events[start..end].iter().map(|event| {
        let blocked = matches!(event, Event::BlockedAttempt { .. })
            || matches!(event, Event::NetRequest { allowed: false, .. });
        let suspicious = crate::classifier::classify_event(event).is_some();
        let style = if blocked {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else if suspicious {
            Style::default().fg(Color::Yellow)
        } else if matches!(event, Event::NetRequest { .. }) {
            Style::default().fg(Color::Blue)
        } else {
            Style::default().fg(Color::Green)
        };
        Row::new(vec![event.kind().to_string(), app::describe(event)]).style(style)
    });
    let counters = state.aggregator.counters;
    let table = Table::new(rows, vec![Constraint::Length(16), Constraint::Min(10)]).block(
        Block::default().borders(Borders::ALL).title(format!(
            " live events [{}] {}/{} (files:{} net:{} blocked:{} exec:{}) ",
            state.filter.label(),
            end.saturating_sub(start),
            events.len(),
            counters.files_total,
            counters.net_total,
            counters.blocked_total,
            counters.procs_exec,
        )),
    );
    f.render_widget(table, area);
}

fn render_blocked(f: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let text = if state.blocked == 0 {
        "none observed".to_string()
    } else {
        state
            .events
            .iter()
            .rev()
            .filter_map(|event| match event {
                Event::BlockedAttempt { path, source, .. } => Some(format!("[{source}] {path}")),
                _ => None,
            })
            .take(2)
            .collect::<Vec<_>>()
            .join("\n")
    };
    f.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" blocked ({}) ", state.blocked)),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_file_tree(f: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let lines = state
        .file_tree
        .iter()
        .rev()
        .take(area.height.saturating_sub(2) as usize)
        .map(|(path, count)| Line::from(format!("{count:>4} {path}")))
        .collect::<Vec<_>>();
    f.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" file tree "))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_network(f: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let n = state.network;
    let mut text = format!(
        "total  {:>6}\nallow  {:>6}\nblock  {:>6}",
        n.total, n.allowed, n.blocked
    );
    for ((host, port, allowed), count) in state
        .network_hosts
        .iter()
        .rev()
        .take(area.height.saturating_sub(5) as usize)
    {
        text.push_str(&format!(
            "\n{} {host}:{port} ×{count}",
            if *allowed { "+" } else { "!" }
        ));
    }
    f.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" network ")),
        area,
    );
}

fn render_activity(f: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let symbols = "▁▂▃▄▅▆▇█";
    let max = state
        .activity
        .iter()
        .map(|sample| sample.events)
        .max()
        .unwrap_or(0);
    let graph = state
        .activity
        .iter()
        .rev()
        .take(area.width.saturating_sub(2) as usize)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|sample| {
            sample
                .events
                .saturating_mul((symbols.chars().count() - 1) as u64)
                .checked_div(max)
                .and_then(|index| symbols.chars().nth(index as usize))
                .unwrap_or(' ')
        })
        .collect::<String>();
    f.render_widget(
        Paragraph::new(graph).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" activity / second "),
        ),
        area,
    );
}

fn render_summary(f: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let exit = state
        .exit_code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "running".to_string());
    let text = format!(
        "events {:>6}  suspicious {:>5}  notices {:>5}  exit {exit}\nfiles r/w {}/{}  ring {}/{}  activity {}/{}",
        state.events_total,
        state.suspicious,
        state.notices,
        state.file_reads,
        state.file_writes,
        state.events.len(),
        app::RING_CAP,
        state.activity.len(),
        app::ACTIVITY_CAP,
    );
    f.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" summary ")),
        area,
    );
}

fn cycle_filter(state: &mut AppState) {
    let next = match state.filter {
        EventFilter::All => EventFilter::Blocked,
        EventFilter::Blocked => EventFilter::Files,
        EventFilter::Files => EventFilter::Network,
        EventFilter::Network => EventFilter::Notices,
        EventFilter::Notices => EventFilter::Suspicious,
        EventFilter::Suspicious | EventFilter::Search(_) => EventFilter::All,
    };
    state.set_filter(next);
}

fn export_state(state: &AppState) {
    let path = std::path::PathBuf::from("vetto-events.jsonl");
    if let Err(error) = state.export_events(&path) {
        tracing::warn!("could not export events to {}: {error}", path.display());
    }
}

/// Split-pane full TUI for concurrently running sandboxes.
pub fn run_multi(runtime: MultiRuntime) -> i32 {
    let mut states: Vec<AppState> = runtime
        .manifest
        .agents
        .iter()
        .map(|agent| AppState::new("sandbox", &agent.net, &agent.profile))
        .collect();
    let mut receivers = runtime
        .sessions
        .iter()
        .map(|session| session.bus.subscribe())
        .collect::<Vec<_>>();
    let mut selected = 0usize;
    let mut last_paint = Instant::now() - REPAINT_INTERVAL;
    let mut drawn_generation = vec![u64::MAX; states.len()];
    let mut drawn_output_len = vec![usize::MAX; states.len()];
    let mut current_output_len = vec![0usize; states.len()];
    let mut confirm_quit = false;
    let mut ui_dirty = true;

    let _ = terminal::enable_raw_mode();
    let _ = execute!(io::stdout(), EnterAlternateScreen);
    let backend = CrosstermBackend::new(io::stdout());
    let Ok(mut terminal) = Terminal::new(backend) else {
        runtime.terminate_all();
        return wait_worst_exit(&runtime);
    };

    loop {
        let mut changed = ui_dirty;
        for (index, _session) in runtime.sessions.iter().enumerate() {
            // The receiver is kept for the lifetime of the pane. Creating a
            // fresh broadcast receiver each frame would silently miss events
            // emitted between frames.
            states[index].drain(&mut receivers[index]);
            let output_len = runtime.sessions[index]
                .output
                .lock()
                .map(|output| output.stdout.len() + output.stderr.len())
                .unwrap_or(0);
            current_output_len[index] = output_len;
            if states[index].generation != drawn_generation[index]
                || output_len != drawn_output_len[index]
            {
                changed = true;
            }
        }
        if changed && last_paint.elapsed() >= REPAINT_INTERVAL {
            let _ = terminal
                .draw(|frame| multi_dashboard(frame, &runtime, &states, selected, confirm_quit));
            for (index, state) in states.iter().enumerate() {
                drawn_generation[index] = state.generation;
                drawn_output_len[index] = current_output_len[index];
            }
            last_paint = Instant::now();
            ui_dirty = false;
        }

        if runtime
            .sessions
            .iter()
            .all(|session| session.finished.load(Ordering::SeqCst))
        {
            // Render one final state and leave the alternate screen.
            let _ =
                terminal.draw(|frame| multi_dashboard(frame, &runtime, &states, selected, false));
            break;
        }

        if event::poll(INPUT_INTERVAL).unwrap_or(false) {
            if let Ok(CEvent::Key(key)) = event::read() {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if confirm_quit {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            runtime.terminate_all();
                            break;
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            confirm_quit = false;
                            ui_dirty = true;
                        }
                        _ => {}
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        confirm_quit = true;
                        ui_dirty = true;
                    }
                    KeyCode::Tab | KeyCode::Right | KeyCode::Down => {
                        selected = (selected + 1) % states.len().max(1);
                    }
                    KeyCode::BackTab | KeyCode::Left | KeyCode::Up => {
                        selected = selected.saturating_sub(1);
                        if states.is_empty() {
                            selected = 0;
                        }
                    }
                    KeyCode::Char('x') | KeyCode::Char('k') => {
                        let _ = runtime.terminate(selected);
                    }
                    KeyCode::Char('p') | KeyCode::Char(' ') => {
                        if states
                            .get(selected)
                            .map(|state| state.paused)
                            .unwrap_or(false)
                        {
                            runtime.sessions[selected].resume();
                        } else {
                            runtime.sessions[selected].pause();
                        }
                        if let Some(state) = states.get_mut(selected) {
                            state.toggle_pause();
                        }
                    }
                    KeyCode::Char('e') => {
                        if let Err(error) = runtime.write_reports() {
                            tracing::warn!("could not export multi-agent reports: {error:#}");
                        }
                    }
                    KeyCode::Char('?') => {
                        if let Some(state) = states.get_mut(selected) {
                            state.toggle_help();
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let _ = execute!(io::stdout(), LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();
    // Let the per-agent bridge and aggregate collector consume the final
    // SessionEnded events before serialising reports.
    std::thread::sleep(Duration::from_millis(50));
    if let Err(error) = runtime.write_reports() {
        tracing::warn!("could not write multi-agent reports: {error:#}");
    }
    wait_worst_exit(&runtime)
}

fn multi_dashboard(
    frame: &mut ratatui::Frame,
    runtime: &MultiRuntime,
    states: &[AppState],
    selected: usize,
    confirm_quit: bool,
) {
    let area = frame.size();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(5),
            Constraint::Length(1),
        ])
        .split(area);
    let combined = runtime.aggregator.combined();
    let header = Paragraph::new(format!(
        " vetto multi  agents={}  events={}  blocked={}  suspicious={}  files={}  net-blocked={}  selected={}",
        runtime.sessions.len(),
        combined.events_total,
        combined.blocked_attempts,
        combined.suspicious,
        combined.files,
        combined.network_blocked,
        runtime
            .manifest
            .agents
            .get(selected)
            .map(|agent| agent.name.as_str())
            .unwrap_or("-")
    ))
    .block(Block::default().borders(Borders::ALL).title(" combined summary "));
    frame.render_widget(header, rows[0]);

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            runtime
                .sessions
                .iter()
                .map(|_| Constraint::Ratio(1, runtime.sessions.len().max(1) as u32))
                .collect::<Vec<_>>(),
        )
        .split(rows[1]);
    for (index, session) in runtime.sessions.iter().enumerate() {
        if let Some(area) = panes.get(index) {
            let state = states.get(index);
            let stats = runtime
                .aggregator
                .snapshot()
                .into_iter()
                .find(|stats| stats.name == session.spec.name)
                .unwrap_or_else(|| AgentStats::new(session.spec.name.clone()));
            render_agent_pane(frame, session, state, &stats, *area, index == selected);
        }
    }

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[2]);
    let rows_stats = runtime.aggregator.snapshot().into_iter().map(|stats| {
        Row::new(vec![
            stats.name,
            format!("{:?}", stats.status),
            stats.blocked_attempts.to_string(),
            stats.files.to_string(),
            stats.network_blocked.to_string(),
        ])
    });
    frame.render_widget(
        Table::new(
            rows_stats,
            vec![
                Constraint::Length(12),
                Constraint::Length(10),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(8),
            ],
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" per-agent stats "),
        ),
        bottom[0],
    );
    let graph = states
        .iter()
        .map(|state| {
            state
                .activity
                .iter()
                .map(|sample| sample.events)
                .sum::<u64>()
        })
        .map(|value| format!("{value:>6}"))
        .collect::<Vec<_>>()
        .join(" ");
    frame.render_widget(
        Paragraph::new(format!("activity totals\n{graph}")).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" activity graph "),
        ),
        bottom[1],
    );
    frame.render_widget(
        Paragraph::new(" Tab/Arrows pane · p pause/resume selected · x terminate selected · e export combined · q terminate all · ? help "),
        rows[3],
    );
    if confirm_quit {
        let popup = centered_rect(48, 20, area);
        frame.render_widget(
            Paragraph::new("Terminate all agents? [y/N]")
                .block(Block::default().borders(Borders::ALL).title(" confirm ")),
            popup,
        );
    }
}

fn render_agent_pane(
    frame: &mut ratatui::Frame,
    session: &crate::multi::runtime::MultiSession,
    state: Option<&AppState>,
    stats: &AgentStats,
    area: Rect,
    selected: bool,
) {
    let title = format!(
        " {} {} blocked={} files={} net={} ",
        session.spec.name,
        if selected { "◀" } else { "" },
        stats.blocked_attempts,
        stats.files,
        stats.network_blocked
    );
    let text = session.output_text();
    let footer = state
        .map(|state| state.last_line.clone())
        .unwrap_or_else(|| "waiting for events".into());
    frame.render_widget(
        Paragraph::new(format!("{text}\n\n{footer}"))
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn wait_worst_exit(runtime: &MultiRuntime) -> i32 {
    runtime
        .aggregator
        .snapshot()
        .iter()
        .filter_map(|stats| stats.exit_code)
        .filter(|code| *code != 0)
        .map(|code| if code < 0 { 128 - code } else { code })
        .max()
        .unwrap_or(0)
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn dashboard_state_tracks_filter_and_graph_inputs() {
        let mut state = AppState::new("full", "off", "default");
        state.ingest(Event::NetRequest {
            ts: Utc::now(),
            host: "example.test".into(),
            port: 443,
            allowed: false,
        });
        state.set_filter(EventFilter::Network);
        assert_eq!(state.filtered_len(), 1);
        assert_eq!(state.network.blocked, 1);
        assert_eq!(state.activity.len(), 1);
    }
}
