//! Mission Control Dashboard State Management.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;

use crate::doctor::preflight::{execute_preflight_diagnostics, PreflightReport};
use crate::onboard::SUPPORTED_AGENTS;
use crate::rescue::snapshot::{list_snapshots, rollback_snapshot, SnapshotMetadata};

use super::theme::Theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissionTab {
    Agents,
    Sandbox,
    Doctor,
    Sessions,
}

impl MissionTab {
    pub fn index(&self) -> usize {
        match self {
            Self::Agents => 0,
            Self::Sandbox => 1,
            Self::Doctor => 2,
            Self::Sessions => 3,
        }
    }

    pub fn from_index(idx: usize) -> Self {
        match idx % 4 {
            0 => Self::Agents,
            1 => Self::Sandbox,
            2 => Self::Doctor,
            3 => Self::Sessions,
            _ => unreachable!(),
        }
    }

    pub fn next(&self) -> Self {
        Self::from_index(self.index() + 1)
    }

    pub fn prev(&self) -> Self {
        Self::from_index(self.index() + 3)
    }
}

#[derive(Debug, Clone)]
pub struct AgentCard {
    pub name: &'static str,
    pub display_name: String,
    pub binary_name: String,
    pub binary_path: PathBuf,
    pub is_shim_active: bool,
    pub is_running: bool,
    pub active_pids: Vec<u32>,
    pub network_allowlist: Vec<String>,
    pub preset: &'static str,
}

#[derive(Debug, Clone)]
pub struct DashboardState {
    pub active_tab: MissionTab,
    pub installed_agents: Vec<AgentCard>,
    pub selected_agent: usize,
    pub doctor_report: Option<PreflightReport>,
    pub snapshots: Vec<SnapshotMetadata>,
    pub selected_snapshot: usize,
    pub theme: Theme,
    pub status_message: Option<(String, Instant)>,
    pub pending_launch_agent: Option<String>,
}

impl DashboardState {
    pub fn new(theme_mode: Option<&str>) -> Self {
        let theme = match theme_mode {
            Some(m) if m.eq_ignore_ascii_case("circuit") => Theme::circuit(),
            _ => Theme::arasaka(),
        };

        let installed_agents = Self::scan_installed_agents();
        let snapshots = list_snapshots().unwrap_or_default();
        let doctor_report = Some(execute_preflight_diagnostics());

        Self {
            active_tab: MissionTab::Agents,
            installed_agents,
            selected_agent: 0,
            doctor_report,
            snapshots,
            selected_snapshot: 0,
            theme,
            status_message: None,
            pending_launch_agent: None,
        }
    }

    /// Dynamically scans for installed AI coding agents on the host system.
    /// Strictly filters ONLY agents whose real binary exists outside Vetto shims.
    pub fn scan_installed_agents() -> Vec<AgentCard> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        let shims_dir = crate::cli::hook::get_shims_dir(crate::cli::hook::HookScope::Global).ok();

        for &agent in &SUPPORTED_AGENTS {
            let canon = crate::policy::defaults::canonical_agent_name(agent).unwrap_or(agent);
            if !seen.insert(canon) {
                continue;
            }

            if let Ok((real_bin_name, real_bin_path)) =
                crate::onboard::find_real_agent_binary(canon)
            {
                let is_shim_active = if let Some(ref sdir) = shims_dir {
                    let shim = sdir.join(canon);
                    shim.exists() && crate::shim::is_vetto_shim_content(&shim)
                } else {
                    false
                };

                let pids = find_running_pids(&real_bin_name, canon);
                let is_running = !pids.is_empty();
                let network_allowlist = crate::policy::presets::agent_network_allowlist(canon);

                result.push(AgentCard {
                    name: canon,
                    display_name: format_agent_name(canon),
                    binary_name: real_bin_name,
                    binary_path: real_bin_path,
                    is_shim_active,
                    is_running,
                    active_pids: pids,
                    network_allowlist,
                    preset: "default+agent",
                });
            }
        }

        // Sort: running agents first, then alphabetically
        result.sort_by(|a, b| {
            b.is_running
                .cmp(&a.is_running)
                .then_with(|| a.name.cmp(b.name))
        });

        result
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some((msg.into(), Instant::now()));
    }

    pub fn active_status(&self) -> Option<&str> {
        if let Some((ref msg, instant)) = self.status_message {
            if instant.elapsed().as_secs() < 4 {
                return Some(msg.as_str());
            }
        }
        None
    }

    pub fn refresh(&mut self) {
        self.installed_agents = Self::scan_installed_agents();
        if self.selected_agent >= self.installed_agents.len() && !self.installed_agents.is_empty() {
            self.selected_agent = self.installed_agents.len() - 1;
        }

        self.snapshots = list_snapshots().unwrap_or_default();
        if self.selected_snapshot >= self.snapshots.len() && !self.snapshots.is_empty() {
            self.selected_snapshot = self.snapshots.len() - 1;
        }

        if self.active_tab == MissionTab::Doctor {
            self.doctor_report = Some(execute_preflight_diagnostics());
        }

        self.set_status("State refreshed");
    }

    pub fn toggle_shim(&mut self) -> Result<()> {
        if self.installed_agents.is_empty() {
            return Ok(());
        }

        let agent = &mut self.installed_agents[self.selected_agent];
        let name = agent.name;

        if agent.is_shim_active {
            crate::cli::enable::disable_agent(name, crate::cli::hook::HookScope::Global)?;
            agent.is_shim_active = false;
            self.set_status(format!("Disabled Vetto shim for '{name}'"));
        } else {
            crate::cli::enable::enable_agent_silent(
                name,
                true,
                crate::cli::hook::HookScope::Global,
            )?;
            agent.is_shim_active = true;
            self.set_status(format!("Enabled Vetto shim for '{name}' in ~/.vetto/shims"));
        }

        Ok(())
    }

    pub fn select_prev(&mut self) {
        match self.active_tab {
            MissionTab::Agents if !self.installed_agents.is_empty() => {
                if self.selected_agent > 0 {
                    self.selected_agent -= 1;
                } else {
                    self.selected_agent = self.installed_agents.len() - 1;
                }
            }
            MissionTab::Sessions if !self.snapshots.is_empty() => {
                if self.selected_snapshot > 0 {
                    self.selected_snapshot -= 1;
                } else {
                    self.selected_snapshot = self.snapshots.len() - 1;
                }
            }
            _ => {}
        }
    }

    pub fn select_next(&mut self) {
        match self.active_tab {
            MissionTab::Agents if !self.installed_agents.is_empty() => {
                if self.selected_agent + 1 < self.installed_agents.len() {
                    self.selected_agent += 1;
                } else {
                    self.selected_agent = 0;
                }
            }
            MissionTab::Sessions if !self.snapshots.is_empty() => {
                if self.selected_snapshot + 1 < self.snapshots.len() {
                    self.selected_snapshot += 1;
                } else {
                    self.selected_snapshot = 0;
                }
            }
            _ => {}
        }
    }

    pub fn rollback_selected_snapshot(&mut self) -> Result<()> {
        if self.snapshots.is_empty() {
            return Ok(());
        }
        let snap = &self.snapshots[self.selected_snapshot];
        let res = rollback_snapshot(&snap.session_id, None)?;
        self.set_status(format!(
            "Restored {} file(s) from session '{}'",
            res.files_restored, snap.session_id
        ));
        Ok(())
    }
}

fn format_agent_name(name: &str) -> String {
    match name {
        "claude" => "Claude Code (Anthropic)".to_string(),
        "opencode" => "OpenCode AI".to_string(),
        "codex" => "OpenAI Codex".to_string(),
        "antigravity" | "agy" => "Antigravity (Google)".to_string(),
        "gemini" => "Gemini CLI".to_string(),
        "cursor" => "Cursor IDE Agent".to_string(),
        "aider" => "Aider Pair Programmer".to_string(),
        "cline" => "Cline Assistant".to_string(),
        "windsurf" => "Windsurf Cascade".to_string(),
        "goose" => "Block Goose AI".to_string(),
        "openhands" => "OpenHands (All-Hands)".to_string(),
        "swe_agent" => "SWE-agent".to_string(),
        "continue" => "Continue.dev".to_string(),
        "copilot" => "GitHub Copilot".to_string(),
        other => other.to_string(),
    }
}

fn find_running_pids(binary_name: &str, agent_name: &str) -> Vec<u32> {
    #[cfg(target_os = "linux")]
    {
        let mut pids = Vec::new();
        let current_pid = std::process::id();
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let Ok(file_name) = entry.file_name().into_string() else {
                    continue;
                };
                let Ok(pid) = file_name.parse::<u32>() else {
                    continue;
                };
                if pid == current_pid {
                    continue;
                }
                let proc_path = entry.path();
                let is_match = if let Ok(comm) = std::fs::read_to_string(proc_path.join("comm")) {
                    let comm = comm.trim();
                    comm == binary_name || comm == agent_name
                } else {
                    false
                };
                if is_match {
                    pids.push(pid);
                } else if let Ok(cmdline) = std::fs::read(proc_path.join("cmdline")) {
                    let s = String::from_utf8_lossy(&cmdline);
                    let first_arg = s.split('\0').next().unwrap_or("");
                    if first_arg.ends_with(binary_name) || first_arg.ends_with(agent_name) {
                        pids.push(pid);
                    }
                }
            }
        }
        pids.sort_unstable();
        pids.dedup();
        pids
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (binary_name, agent_name);
        Vec::new()
    }
}
