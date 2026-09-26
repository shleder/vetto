//! Mission Control Ratatui UI Renderer (Arasaka Cyber-Red & Cyber Circuit).

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Tabs, Wrap};
use ratatui::Frame;

use super::state::{DashboardState, MissionTab};
use super::theme::Theme;

const ASCII_LOGO_CIRCUIT: &[&str] = &[
    r"██╗   ██╗███████╗████████╗████████╗ ██████╗ ",
    r"██║   ██║██╔════╝╚══██╔══╝╚══██╔══╝██╔═══██╗",
    r"██║   ██║█████╗     ██║      ██║   ██║   ██║",
    r"╚██╗ ██╔╝██╔══╝     ██║      ██║   ██║   ██║",
    r" ╚████╔╝ ███████╗   ██║      ██║   ╚██████╔╝",
    r"  ╚═══╝  ╚══════╝   ╚═╝      ╚═╝    ╚═════╝ ",
];

const COMPACT_LOGO: &str = "  ╦  ╦ ╔═╗ ╔╦╗ ╔╦╗ ╔═╗  MISSION CONTROL";

pub fn draw(f: &mut Frame, state: &DashboardState) {
    let area = f.size();
    let theme = &state.theme;

    // Fill background
    let bg_block = Block::default().style(Style::default().bg(theme.bg));
    f.render_widget(bg_block, area);

    // Compute layout: Header, Tabs, Body, Footer
    let show_full_logo = area.height >= 30 && area.width >= 70;
    let header_height = if show_full_logo { 7 } else { 3 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_height),
            Constraint::Length(3), // Tab bar
            Constraint::Min(12),   // Body
            Constraint::Length(3), // Footer
        ])
        .split(area);

    render_header(f, state, chunks[0], show_full_logo);
    render_tabs(f, state, chunks[1]);

    match state.active_tab {
        MissionTab::Agents => render_tab_agents(f, state, chunks[2]),
        MissionTab::Sandbox => render_tab_sandbox(f, state, chunks[2]),
        MissionTab::Doctor => render_tab_doctor(f, state, chunks[2]),
        MissionTab::Sessions => render_tab_sessions(f, state, chunks[2]),
    }

    render_footer(f, state, chunks[3]);
}

fn render_header(f: &mut Frame, state: &DashboardState, area: Rect, full_logo: bool) {
    let theme = &state.theme;

    if full_logo {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(48), Constraint::Min(20)])
            .split(area);

        let logo_lines: Vec<Line> = ASCII_LOGO_CIRCUIT
            .iter()
            .map(|&l| {
                Line::from(Span::styled(
                    l,
                    Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
                ))
            })
            .collect();

        f.render_widget(Paragraph::new(logo_lines), cols[0]);

        let telemetry_lines = vec![
            Line::from(vec![
                Span::styled(
                    "V E T T O   M I S S I O N   C O N T R O L   ",
                    Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("v{}", env!("CARGO_PKG_VERSION")),
                    Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("KERNEL ISOLATION: ", Style::default().fg(theme.muted)),
                Span::styled(
                    "FULL [Landlock + Namespaces + Cgroups v2 + Seccomp]",
                    Style::default().fg(theme.success).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("ACTIVE THEME:     ", Style::default().fg(theme.muted)),
                Span::styled(
                    theme.name(),
                    Style::default().fg(theme.info).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" (press 't' to toggle)", Style::default().fg(theme.muted)),
            ]),
            Line::from(vec![
                Span::styled("ACTIVE SHIMS:     ", Style::default().fg(theme.muted)),
                Span::styled(
                    format!(
                        "{} / {} agents protected",
                        state.installed_agents.iter().filter(|a| a.is_shim_active).count(),
                        state.installed_agents.len()
                    ),
                    Style::default().fg(theme.accent),
                ),
            ]),
        ];

        let right_block = Block::default()
            .borders(Borders::LEFT)
            .border_style(Style::default().fg(theme.border));
        f.render_widget(Paragraph::new(telemetry_lines).block(right_block), cols[1]);
    } else {
        let line = Line::from(vec![
            Span::styled(
                COMPACT_LOGO,
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!("v{}", env!("CARGO_PKG_VERSION")),
                Style::default().fg(theme.accent),
            ),
            Span::raw(" | "),
            Span::styled(theme.name(), Style::default().fg(theme.info)),
        ]);
        f.render_widget(Paragraph::new(line), area);
    }
}

fn render_tabs(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let tab_titles = vec![
        Line::from(format!(" [1] AGENTS ({}) ", state.installed_agents.len())),
        Line::from(" [2] SANDBOX VFS "),
        Line::from(" [3] KERNEL DOCTOR "),
        Line::from(format!(" [4] SESSIONS ({}) ", state.snapshots.len())),
    ];

    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(Span::styled(" FLEET NAVIGATION ", Style::default().fg(theme.muted))),
        )
        .select(state.active_tab.index())
        .style(Style::default().fg(theme.muted))
        .highlight_style(
            Style::default()
                .fg(theme.tab_active_fg)
                .bg(theme.tab_active_bg)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(tabs, area);
}

fn render_tab_agents(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

    // Left column: Installed agents list
    if state.installed_agents.is_empty() {
        let empty_lines = vec![
            Line::from(""),
            Line::styled(
                " No AI coding agents detected in PATH outside Vetto.",
                Style::default().fg(theme.warning).add_modifier(Modifier::BOLD),
            ),
            Line::from(""),
            Line::styled(
                " Supported agents: claude, opencode, codex, aider, gemini,",
                Style::default().fg(theme.muted),
            ),
            Line::styled(
                " cursor, cline, windsurf, goose, openhands, swe-agent...",
                Style::default().fg(theme.muted),
            ),
            Line::from(""),
            Line::styled(
                " When you install an agent binary on the system,",
                Style::default().fg(theme.text),
            ),
            Line::styled(
                " it will automatically appear in this list on start or [r] refresh.",
                Style::default().fg(theme.text),
            ),
        ];

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border))
            .title(Span::styled(
                " INSTALLED AGENTS (0 DETECTED) ",
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ));
        f.render_widget(Paragraph::new(empty_lines).block(block), cols[0]);
    } else {
        let rows = state
            .installed_agents
            .iter()
            .enumerate()
            .map(|(idx, agent)| {
                let is_selected = idx == state.selected_agent;

                let shim_cell = if agent.is_shim_active {
                    Span::styled("[SHIM]", Style::default().fg(theme.success).add_modifier(Modifier::BOLD))
                } else {
                    Span::styled("[DIRECT]", Style::default().fg(theme.muted))
                };

                let name_cell = Span::styled(
                    agent.name,
                    if is_selected {
                        Style::default().fg(theme.selection_fg).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(theme.text)
                    },
                );

                let status_cell = if agent.is_running {
                    Span::styled(
                        format!("● RUNNING ({})", agent.active_pids.len()),
                        Style::default().fg(theme.success).add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::styled("○ IDLE", Style::default().fg(theme.muted))
                };

                let row = Row::new(vec![shim_cell, name_cell, status_cell]);
                if is_selected {
                    row.style(
                        Style::default()
                            .bg(theme.selection_bg)
                            .fg(theme.selection_fg)
                            .add_modifier(Modifier::BOLD),
                    )
                } else {
                    row
                }
            });

        let table = Table::new(
            rows,
            vec![
                Constraint::Length(9),
                Constraint::Length(14),
                Constraint::Min(12),
            ],
        )
        .header(
            Row::new(vec!["STATUS", "AGENT", "PROCESS"])
                .style(Style::default().fg(theme.muted).add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(Span::styled(
                    format!(" INSTALLED AGENTS ({}) ", state.installed_agents.len()),
                    Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
                )),
        );

        f.render_widget(table, cols[0]);
    }

    // Right column: Detailed Inspector for selected agent
    if let Some(agent) = state.installed_agents.get(state.selected_agent) {
        let inspector_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border))
            .title(Span::styled(
                format!(" AGENT INSPECTOR: {} ", agent.display_name),
                Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
            ));

        let pids_str = if agent.active_pids.is_empty() {
            "None (Process Tree Extinct / Idle)".to_string()
        } else {
            agent
                .active_pids
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };

        let net_str = if agent.network_allowlist.is_empty() {
            "offline (strict zero network egress)".to_string()
        } else {
            agent.network_allowlist.join(", ")
        };

        let mut lines = vec![
            Line::from(vec![
                Span::styled("REAL BINARY PATH: ", Style::default().fg(theme.muted)),
                Span::styled(
                    agent.binary_path.display().to_string(),
                    Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("SANDBOX SHIM:     ", Style::default().fg(theme.muted)),
                if agent.is_shim_active {
                    Span::styled(
                        "ACTIVE (~/.vetto/shims/ -> transparent kernel sandbox)",
                        Style::default().fg(theme.success).add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::styled(
                        "DISABLED (runs unconfined as direct host binary)",
                        Style::default().fg(theme.danger).add_modifier(Modifier::BOLD),
                    )
                },
            ]),
            Line::from(vec![
                Span::styled("ACTIVE PID(S):    ", Style::default().fg(theme.muted)),
                Span::styled(
                    pids_str,
                    if agent.is_running {
                        Style::default().fg(theme.success).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(theme.text)
                    },
                ),
            ]),
            Line::from(vec![
                Span::styled("POLICY PRESET:    ", Style::default().fg(theme.muted)),
                Span::styled(
                    format!("balanced + {} (zero-config)", agent.name),
                    Style::default().fg(theme.accent),
                ),
            ]),
            Line::from(""),
            Line::styled(
                "FILESYSTEM ISOLATION MAP (Landlock LSM ABI 1-6 + Namespaces):",
                Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
            ),
            Line::from(vec![
                Span::styled("  [MASKED 0000] ", Style::default().fg(theme.danger).add_modifier(Modifier::BOLD)),
                Span::styled("~/.ssh, ~/.aws, .env, .env.*, ~/.gnupg, ~/.kube", Style::default().fg(theme.text)),
            ]),
            Line::from(vec![
                Span::styled("  [READ-ONLY]   ", Style::default().fg(theme.info)),
                Span::styled("/ (rootfs), /usr, /bin, /lib, /proc/sys, /sys", Style::default().fg(theme.text)),
            ]),
            Line::from(vec![
                Span::styled("  [READ-WRITE]  ", Style::default().fg(theme.success)),
                Span::styled("$PWD (project workspace), /tmp, ~/.cache", Style::default().fg(theme.text)),
            ]),
            Line::from(""),
            Line::styled(
                "EGRESS NETWORK ALLOWLIST (L7 Semantic Proxy + TLS SNI):",
                Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
            ),
            Line::styled(format!("  {net_str}"), Style::default().fg(theme.text)),
            Line::from(""),
            Line::styled(
                "PROCESS TREE CONTAINMENT:",
                Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
            ),
            Line::styled(
                "  PID pinning via pidfd_open + Cgroups v2 cgroup.kill (INV-12/13 extinction theorem)",
                Style::default().fg(theme.muted),
            ),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "ACTION: ",
                    Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "[Space] Toggle Shim  |  [Enter] Launch in Vetto Sandbox",
                    Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
                ),
            ]),
        ];

        f.render_widget(Paragraph::new(lines).block(inspector_block).wrap(Wrap { trim: true }), cols[1]);
    } else {
        let empty_inspector = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border))
            .title(Span::styled(" AGENT INSPECTOR ", Style::default().fg(theme.logo)));
        f.render_widget(Paragraph::new("No agent selected").block(empty_inspector), cols[1]);
    }
}

fn render_tab_sandbox(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let left_lines = vec![
        Line::styled(
            "KERNEL SANDBOX ISOLATION LAYERS",
            Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
        ),
        Line::from(""),
        Line::from(vec![
            Span::styled("1. Landlock LSM: ", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
            Span::styled("Unprivileged in-kernel path access rules (ABI 1-6).", Style::default().fg(theme.text)),
        ]),
        Line::styled("   Fail-closed execution (Exit 125, INV-01) on sandbox violation.", Style::default().fg(theme.muted)),
        Line::from(""),
        Line::from(vec![
            Span::styled("2. Linux Namespaces: ", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
            Span::styled("CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET", Style::default().fg(theme.text)),
        ]),
        Line::styled("   Zero background daemons; sub-4ms cold start between fork() and execve().", Style::default().fg(theme.muted)),
        Line::from(""),
        Line::from(vec![
            Span::styled("3. CoW Tmpfs Overlays: ", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
            Span::styled("Copy-on-write overlay over system rootfs.", Style::default().fg(theme.text)),
        ]),
        Line::styled("   Any destructive writes outside the project directory vanish upon exit.", Style::default().fg(theme.muted)),
        Line::from(""),
        Line::from(vec![
            Span::styled("4. Seccomp-BPF Syscall Filter: ", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
            Span::styled("Pure-Rust compiled BPF filter.", Style::default().fg(theme.text)),
        ]),
        Line::styled("   Blocks unshare, mount, ptrace, io_uring, and raw AF_INET socket creation.", Style::default().fg(theme.muted)),
        Line::from(""),
        Line::from(vec![
            Span::styled("5. Process Extinction: ", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
            Span::styled("Cgroups v2 cgroup.kill + pidfd pinning.", Style::default().fg(theme.text)),
        ]),
        Line::styled("   Mathematically eliminates runaway background daemons and orphan processes.", Style::default().fg(theme.muted)),
    ];

    let left_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(" ARCHITECTURAL INVARIANTS ", Style::default().fg(theme.logo)));
    f.render_widget(Paragraph::new(left_lines).block(left_block).wrap(Wrap { trim: true }), cols[0]);

    let right_lines = vec![
        Line::styled(
            "INODE-LEVEL SECRET MASKING MATRIX (INV-08)",
            Style::default().fg(theme.danger).add_modifier(Modifier::BOLD),
        ),
        Line::from(""),
        Line::styled(
            "Vetto mounts 0000 mode tmpfs nodes over credential paths prior to agent execve:",
            Style::default().fg(theme.muted),
        ),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ~/.ssh/id_*          ", Style::default().fg(theme.text).add_modifier(Modifier::BOLD)),
            Span::styled("-> [MASKED 0000 EACCES]", Style::default().fg(theme.danger).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  ~/.aws/credentials   ", Style::default().fg(theme.text).add_modifier(Modifier::BOLD)),
            Span::styled("-> [MASKED 0000 EACCES]", Style::default().fg(theme.danger).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  .env, .env.*         ", Style::default().fg(theme.text).add_modifier(Modifier::BOLD)),
            Span::styled("-> [MASKED 0000 EACCES]", Style::default().fg(theme.danger).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  ~/.gnupg/secring.*   ", Style::default().fg(theme.text).add_modifier(Modifier::BOLD)),
            Span::styled("-> [MASKED 0000 EACCES]", Style::default().fg(theme.danger).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  ~/.kube/config       ", Style::default().fg(theme.text).add_modifier(Modifier::BOLD)),
            Span::styled("-> [MASKED 0000 EACCES]", Style::default().fg(theme.danger).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  ~/.docker/config.json", Style::default().fg(theme.text).add_modifier(Modifier::BOLD)),
            Span::styled("-> [MASKED 0000 EACCES]", Style::default().fg(theme.danger).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::styled(
            "L7 NETWORK SEMANTIC RELAY & DNS BROKER:",
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
        ),
        Line::styled(
            "Direct network calls are intercepted via unix-fd socket bridge with SNI inspection.",
            Style::default().fg(theme.muted),
        ),
        Line::styled(
            "Non-allowlisted endpoints immediately receive 403 Forbidden with zero socket bypass.",
            Style::default().fg(theme.muted),
        ),
    ];

    let right_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(" SECRET MASKING & EGRESS ", Style::default().fg(theme.logo)));
    f.render_widget(Paragraph::new(right_lines).block(right_block).wrap(Wrap { trim: true }), cols[1]);
}

fn render_tab_doctor(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let Some(ref report) = state.doctor_report else {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border))
            .title(" KERNEL PREFLIGHT DOCTOR ");
        f.render_widget(Paragraph::new("Executing preflight diagnostics...").block(block), area);
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(area);

    let (verdict_str, verdict_color) = match report.verdict {
        crate::doctor::preflight::PreflightVerdict::Pass => ("PASS (Fully Supported)", theme.success),
        crate::doctor::preflight::PreflightVerdict::Degraded => ("DEGRADED (Partial Isolation)", theme.warning),
        crate::doctor::preflight::PreflightVerdict::Fail => ("FAIL (Unsupported Environment)", theme.danger),
    };

    let verdict_line = Line::from(vec![
        Span::styled("OVERALL KERNEL VERDICT: ", Style::default().fg(theme.text).add_modifier(Modifier::BOLD)),
        Span::styled(verdict_str, Style::default().fg(verdict_color).add_modifier(Modifier::BOLD)),
        Span::styled(format!("  (Exit Code: {})", report.exit_code), Style::default().fg(theme.muted)),
        Span::raw("   |   "),
        Span::styled("Press [r] to re-run preflight probe", Style::default().fg(theme.accent)),
    ]);

    let top_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));
    f.render_widget(Paragraph::new(verdict_line).block(top_block), chunks[0]);

    let grid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let left_items = vec![
        Line::styled("1. LANDLOCK LSM CAPABILITY", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
        Line::from(vec![
            Span::styled("   Supported: ", Style::default().fg(theme.muted)),
            Span::styled(
                if report.landlock.supported { "Yes" } else { "No" },
                Style::default().fg(if report.landlock.supported { theme.success } else { theme.danger }).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" (ABI Version: {:?})", report.landlock.abi_version), Style::default().fg(theme.text)),
        ]),
        Line::styled(format!("   Status:    {}", report.landlock.status), Style::default().fg(theme.muted)),
        Line::styled(format!("   Message:   {}", report.landlock.message), Style::default().fg(theme.text)),
        Line::from(""),
        Line::styled("2. LINUX NAMESPACES (CLONE_NEWUSER)", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
        Line::from(vec![
            Span::styled("   Stage 1 User NS: ", Style::default().fg(theme.muted)),
            Span::styled(
                &report.namespaces.stage1_user_namespace.status,
                Style::default().fg(if report.namespaces.stage1_user_namespace.supported { theme.success } else { theme.warning }),
            ),
        ]),
        Line::styled(format!("   Stage 2 Tmpfs:   {}", report.namespaces.stage2_tmpfs_mount.status), Style::default().fg(theme.muted)),
        Line::styled(format!("   Overall Status:  {}", report.namespaces.overall_status), Style::default().fg(theme.text)),
    ];

    let right_items = vec![
        Line::styled("3. CGROUPS V2 & PROCESS EXTINCTION", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
        Line::from(vec![
            Span::styled("   Available:   ", Style::default().fg(theme.muted)),
            Span::styled(
                if report.cgroups_v2.available { "Yes" } else { "No" },
                Style::default().fg(if report.cgroups_v2.available { theme.success } else { theme.danger }),
            ),
            Span::styled(format!(" (cgroup.kill: {})", report.cgroups_v2.cgroup_kill), Style::default().fg(theme.text)),
        ]),
        Line::styled(format!("   Controllers: {}", report.cgroups_v2.controllers.join(", ")), Style::default().fg(theme.muted)),
        Line::styled(format!("   Message:     {}", report.cgroups_v2.message), Style::default().fg(theme.text)),
        Line::from(""),
        Line::styled("4. SECCOMP-BPF FILTER STATUS", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
        Line::from(vec![
            Span::styled("   Filter Active: ", Style::default().fg(theme.muted)),
            Span::styled(
                if report.seccomp.filter_available { "Available" } else { "Unavailable" },
                Style::default().fg(if report.seccomp.filter_available { theme.success } else { theme.warning }),
            ),
        ]),
        Line::styled(format!("   Mode:          {}", report.seccomp.current_mode), Style::default().fg(theme.muted)),
        Line::styled(format!("   Container:     {}", if report.seccomp.container_restricted { "Restricted" } else { "Unrestricted" }), Style::default().fg(theme.text)),
    ];

    let left_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(" LANDLOCK & NAMESPACES ");
    f.render_widget(Paragraph::new(left_items).block(left_block).wrap(Wrap { trim: true }), grid[0]);

    let right_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(" CGROUPS V2 & SECCOMP ");
    f.render_widget(Paragraph::new(right_items).block(right_block).wrap(Wrap { trim: true }), grid[1]);
}

fn render_tab_sessions(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    if state.snapshots.is_empty() {
        let empty_msg = vec![
            Line::from(""),
            Line::styled(" No project snapshots found.", Style::default().fg(theme.muted).add_modifier(Modifier::BOLD)),
            Line::styled(" Snapshots are created automatically before agent sessions or via 'vetto run'.", Style::default().fg(theme.muted)),
            Line::styled(" Once an agent modifies project files under Vetto, an automatic snapshot is stored here.", Style::default().fg(theme.text)),
        ];
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border))
            .title(" PROJECT SNAPSHOTS & UNDO ");
        f.render_widget(Paragraph::new(empty_msg).block(block), chunks[0]);
    } else {
        let rows = state.snapshots.iter().enumerate().map(|(idx, snap)| {
            let is_selected = idx == state.selected_snapshot;
            let id_span = Span::styled(
                snap.session_id.as_str(),
                if is_selected {
                    Style::default().fg(theme.selection_fg).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.text)
                },
            );

            let created_span = Span::styled(snap.created_at.as_str(), Style::default().fg(theme.muted));
            let files_span = Span::styled(format!("{}", snap.file_count), Style::default().fg(theme.text));
            let size_span = Span::styled(format_bytes(snap.total_size_bytes), Style::default().fg(theme.accent));
            let proj_span = Span::styled(snap.project_dir.display().to_string(), Style::default().fg(theme.text));

            let row = Row::new(vec![id_span, created_span, files_span, size_span, proj_span]);
            if is_selected {
                row.style(
                    Style::default()
                        .bg(theme.selection_bg)
                        .fg(theme.selection_fg)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                row
            }
        });

        let table = Table::new(
            rows,
            vec![
                Constraint::Length(18),
                Constraint::Length(26),
                Constraint::Length(8),
                Constraint::Length(12),
                Constraint::Min(20),
            ],
        )
        .header(
            Row::new(vec!["SESSION ID", "CREATED AT", "FILES", "SIZE", "PROJECT DIR"])
                .style(Style::default().fg(theme.muted).add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(Span::styled(
                    format!(" AVAILABLE SNAPSHOTS ({}) ", state.snapshots.len()),
                    Style::default().fg(theme.logo).add_modifier(Modifier::BOLD),
                )),
        );

        f.render_widget(table, chunks[0]);
    }

    // Bottom panel: Selected snapshot details and instant rollback prompt
    let detail_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(Span::styled(" INSTANT ROLLBACK (VETTO UNDO) ", Style::default().fg(theme.logo)));

    if let Some(snap) = state.snapshots.get(state.selected_snapshot) {
        let lines = vec![
            Line::from(vec![
                Span::styled("SELECTED SESSION: ", Style::default().fg(theme.muted)),
                Span::styled(&snap.session_id, Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("TARGET PROJECT:   ", Style::default().fg(theme.muted)),
                Span::styled(snap.project_dir.display().to_string(), Style::default().fg(theme.text)),
            ]),
            Line::from(vec![
                Span::styled("ARCHIVE PATH:     ", Style::default().fg(theme.muted)),
                Span::styled(snap.archive_file.display().to_string(), Style::default().fg(theme.muted)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("ACTIONS: ", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
                Span::styled(
                    "Press [u] to restore files from this snapshot immediately! (Overwrites modified files)",
                    Style::default().fg(theme.danger).add_modifier(Modifier::BOLD),
                ),
            ]),
        ];
        f.render_widget(Paragraph::new(lines).block(detail_block), chunks[1]);
    } else {
        f.render_widget(Paragraph::new("Select a session snapshot above to preview restore.").block(detail_block), chunks[1]);
    }
}

fn render_footer(f: &mut Frame, state: &DashboardState, area: Rect) {
    let theme = &state.theme;

    let status_text = state.active_status().unwrap_or(
        "Theme: ARASAKA RED  |  Bare 'vetto' interactive TTY dashboard  |  Press 't' to toggle palette"
    );

    let lines = vec![
        Line::from(vec![
            Span::styled("STATUS: ", Style::default().fg(theme.muted)),
            Span::styled(status_text, Style::default().fg(theme.info).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("[1-4]", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
            Span::styled(" Tabs  ", Style::default().fg(theme.text)),
            Span::styled("[↑↓/jk]", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
            Span::styled(" Select  ", Style::default().fg(theme.text)),
            Span::styled("[Space]", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
            Span::styled(" Toggle Shim  ", Style::default().fg(theme.text)),
            Span::styled("[Enter]", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
            Span::styled(" Launch  ", Style::default().fg(theme.text)),
            Span::styled("[t]", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
            Span::styled(" Theme  ", Style::default().fg(theme.text)),
            Span::styled("[r]", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
            Span::styled(" Refresh  ", Style::default().fg(theme.text)),
            Span::styled("[u]", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
            Span::styled(" Undo  ", Style::default().fg(theme.text)),
            Span::styled("[q/Esc]", Style::default().fg(theme.logo).add_modifier(Modifier::BOLD)),
            Span::styled(" Quit", Style::default().fg(theme.text)),
        ]),
    ];

    let footer_block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(theme.border));
    f.render_widget(Paragraph::new(lines).block(footer_block), area);
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
