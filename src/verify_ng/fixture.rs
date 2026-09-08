//! Hermetic fixture builder (FM-06).
//!
//! Rules:
//! - One spawn = one scenario: each run gets a fresh unique directory.
//! - The payload staged inside the writable project is hashed before spawn
//!   and re-hashed after wait; any mutation (including self-rewrite by the
//!   payload, FM-06) invalidates the run as INCONCLUSIVE.
//! - The harness HOME for a run is a fresh subdirectory, never a shared
//!   global root: parallel or sequential runs cannot cross-contaminate.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One hermetic run directory.
pub struct Fixture {
    root: PathBuf,
    home: PathBuf,
    payload_hashes: Vec<(PathBuf, String)>,
}

impl Fixture {
    /// Create a fresh unique fixture root under the system temp dir.
    pub fn create(tag: &str) -> std::io::Result<Self> {
        let n = FIXTURE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("vetto-vng-{}-{}-{n}", tag, std::process::id()));
        let home = root.join("home");
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(&home)?;
        Ok(Self {
            root,
            home,
            payload_hashes: Vec::new(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Isolated HOME for this run (FM-06: never shared).
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Write a file inside the fixture and record its pre-spawn hash.
    pub fn stage(&mut self, rel: &str, content: &[u8]) -> std::io::Result<PathBuf> {
        let path = self.root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, content)?;
        let hash = hash_bytes(content);
        self.payload_hashes.push((path.clone(), hash));
        Ok(path)
    }

    /// Re-hash every staged payload after wait. `Ok(())` means untouched;
    /// `Err(paths)` lists mutated payloads (FM-06 -> INCONCLUSIVE).
    pub fn verify_untouched(&self) -> Result<(), Vec<PathBuf>> {
        let mut mutated = Vec::new();
        for (path, before) in &self.payload_hashes {
            let after = std::fs::read(path)
                .map(|b| hash_bytes(&b))
                .unwrap_or_else(|_| "unreadable".to_string());
            if &after != before {
                mutated.push(path.clone());
            }
        }
        if mutated.is_empty() {
            Ok(())
        } else {
            Err(mutated)
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    super::frozen::hex_encode(&hasher.finalize())
}

#[cfg(test)]
mod fixture_tests {
    use super::*;

    #[test]
    fn detects_self_mutation() {
        let mut fx = Fixture::create("mut").expect("create fixture");
        let p = fx.stage("payload.sh", b"echo hi").expect("stage");
        std::fs::write(&p, b"echo PASS").expect("mutate");
        assert!(fx.verify_untouched().is_err());
    }

    #[test]
    fn untouched_passes() {
        let mut fx = Fixture::create("clean").expect("create fixture");
        fx.stage("payload.sh", b"echo hi").expect("stage");
        assert!(fx.verify_untouched().is_ok());
    }

    #[test]
    fn homes_are_unique_per_fixture() {
        let a = Fixture::create("a").expect("create a");
        let b = Fixture::create("b").expect("create b");
        assert_ne!(a.home(), b.home());
        assert_ne!(a.root(), b.root());
    }
}
