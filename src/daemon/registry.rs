//! In-memory and persistent session registry for the multiplexer daemon.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Running,
    Completed,
    Failed,
    Killed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEntry {
    pub id: String,
    pub pid: u32,
    pub command: Vec<String>,
    pub policy: String,
    pub net: String,
    pub status: SessionStatus,
    pub started_at: u64,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct StartSessionRequest {
    pub command: Vec<String>,
    #[serde(default = "default_policy")]
    pub policy: String,
    #[serde(default = "default_net")]
    pub net: String,
    pub timeout: Option<String>,
}

fn default_policy() -> String {
    "default".to_string()
}

fn default_net() -> String {
    "off".to_string()
}

pub struct SessionRegistry {
    state_dir: PathBuf,
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    children: Arc<Mutex<HashMap<String, Child>>>,
}

impl SessionRegistry {
    pub fn new(state_dir: PathBuf) -> Self {
        let registry = Self {
            state_dir,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            children: Arc::new(Mutex::new(HashMap::new())),
        };
        let _ = registry.load_from_disk();
        registry
    }

    pub fn start_session(&self, req: StartSessionRequest) -> Result<SessionEntry> {
        if req.command.is_empty() {
            bail!("command vector must not be empty");
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let id = format!("sess-{}-{}", now, std::process::id());

        let current_exe = std::env::current_exe().unwrap_or_else(|_| "vetto".into());
        let mut cmd = Command::new(current_exe);
        cmd.arg("--ci");
        cmd.arg("--tui=none");
        cmd.arg("--profile").arg(&req.policy);
        cmd.arg("--net").arg(&req.net);

        if let Some(t) = &req.timeout {
            cmd.arg("--timeout").arg(t);
        }

        cmd.arg("--");
        for arg in &req.command {
            cmd.arg(arg);
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn sandboxed session for {:?}", req.command))?;
        let pid = child.id();

        let entry = SessionEntry {
            id: id.clone(),
            pid,
            command: req.command,
            policy: req.policy,
            net: req.net,
            status: SessionStatus::Running,
            started_at: now,
            exit_code: None,
        };

        {
            let mut children = self.children.lock().unwrap();
            children.insert(id.clone(), child);
        }
        {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.insert(id.clone(), entry.clone());
        }

        let _ = self.save_to_disk();
        Ok(entry)
    }

    pub fn list_sessions(&self) -> Vec<SessionEntry> {
        self.poll_children();
        let sessions = self.sessions.lock().unwrap();
        sessions.values().cloned().collect()
    }

    pub fn get_session(&self, id: &str) -> Option<SessionEntry> {
        self.poll_children();
        let sessions = self.sessions.lock().unwrap();
        sessions.get(id).cloned()
    }

    pub fn stop_session(&self, id: &str) -> Result<bool> {
        let mut children = self.children.lock().unwrap();
        if let Some(mut child) = children.remove(id) {
            let _ = child.kill();
            let _ = child.wait();

            let mut sessions = self.sessions.lock().unwrap();
            if let Some(sess) = sessions.get_mut(id) {
                sess.status = SessionStatus::Killed;
                sess.exit_code = Some(137);
            }
            let _ = self.save_to_disk();
            return Ok(true);
        }

        let mut sessions = self.sessions.lock().unwrap();
        if let Some(sess) = sessions.get_mut(id) {
            if sess.status == SessionStatus::Running {
                sess.status = SessionStatus::Killed;
                let _ = self.save_to_disk();
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn poll_children(&self) {
        let mut children = self.children.lock().unwrap();
        let mut sessions = self.sessions.lock().unwrap();

        let mut finished = Vec::new();
        for (id, child) in children.iter_mut() {
            if let Ok(Some(status)) = child.try_wait() {
                finished.push((id.clone(), status.code()));
            }
        }

        for (id, exit_code) in finished {
            children.remove(&id);
            if let Some(sess) = sessions.get_mut(&id) {
                sess.exit_code = exit_code;
                sess.status = if exit_code == Some(0) {
                    SessionStatus::Completed
                } else {
                    SessionStatus::Failed
                };
            }
        }
    }

    fn sessions_file(&self) -> PathBuf {
        self.state_dir.join("sessions.json")
    }

    fn load_from_disk(&self) -> Result<()> {
        let path = self.sessions_file();
        if !path.is_file() {
            return Ok(());
        }
        let raw = fs::read_to_string(&path)?;
        let list: Vec<SessionEntry> = serde_json::from_str(&raw)?;
        let mut map = self.sessions.lock().unwrap();
        for item in list {
            map.insert(item.id.clone(), item);
        }
        Ok(())
    }

    fn save_to_disk(&self) -> Result<()> {
        let list: Vec<SessionEntry> = {
            let sessions = self.sessions.lock().unwrap();
            sessions.values().cloned().collect()
        };
        let raw = serde_json::to_string_pretty(&list)?;
        fs::write(self.sessions_file(), raw.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_registry_lifecycle() {
        let dir = std::env::temp_dir().join(format!("vetto-reg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let registry = SessionRegistry::new(dir.clone());

        // Insert fake entry directly for unit test
        let entry = SessionEntry {
            id: "test-sess-1".to_string(),
            pid: 1234,
            command: vec!["echo".into(), "hello".into()],
            policy: "strict".into(),
            net: "off".into(),
            status: SessionStatus::Running,
            started_at: 1000,
            exit_code: None,
        };

        {
            let mut s = registry.sessions.lock().unwrap();
            s.insert(entry.id.clone(), entry.clone());
        }
        registry.save_to_disk().unwrap();

        let fetched = registry.get_session("test-sess-1").expect("found session");
        assert_eq!(fetched.pid, 1234);
        assert_eq!(fetched.policy, "strict");

        let list = registry.list_sessions();
        assert_eq!(list.len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }
}
