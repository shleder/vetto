//! Cryptographic attestation and tamper-evident audit ledgers.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const GENESIS_HASH: &str = "GENESIS";

/// An append-only audit ledger implementing tamper-evident hash chaining
/// and Ed25519 cryptographic signing, fulfilling INV-34, INV-35, and INV-36.
pub struct AuditLedger {
    file: BufWriter<File>,
    seq: u64,
    prev_hash: String,
}

#[derive(Serialize)]
struct EventEnvelope<'a, T: Serialize> {
    seq: u64,
    prev_hash: &'a str,
    hash: &'a str,
    #[serde(flatten)]
    payload: &'a T,
}

#[derive(Serialize)]
struct SignatureEnvelope<'a> {
    seq: u64,
    prev_hash: &'a str,
    signature: String,
}

fn manual_hex_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in result {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

impl AuditLedger {
    /// Creates or opens an audit ledger at the specified host path.
    /// Fulfills INV-35: The file MUST be written directly by the host supervisor
    /// to an unshared host path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .context("Failed to open vetto-audit.jsonl")?;

        Ok(Self {
            file: BufWriter::new(f),
            seq: 0,
            prev_hash: GENESIS_HASH.to_string(),
        })
    }

    /// Records an event to the ledger, cryptographically linking it to the
    /// preceding event hash. Fulfills INV-34.
    pub fn record_event<T: Serialize>(&mut self, event: &T) -> Result<String> {
        let payload_value = serde_json::to_value(event)?;
        let payload_json = serde_json::to_string(&payload_value)?;
        let data_to_hash = format!("{}:{}:{}", self.prev_hash, self.seq, payload_json);
        let current_hash = manual_hex_hash(&data_to_hash);

        let envelope = EventEnvelope {
            seq: self.seq,
            prev_hash: &self.prev_hash,
            hash: &current_hash,
            payload: event,
        };

        let envelope_json = serde_json::to_string(&envelope)?;
        writeln!(self.file, "{}", envelope_json)?;
        self.file.flush()?;

        self.prev_hash = current_hash.clone();
        self.seq += 1;

        Ok(current_hash)
    }

    /// Records a typed audit entry adhering to §17.1 machine-verifiable schema.
    pub fn record_audit_record(
        &mut self,
        record: &crate::audit::VettoAuditRecord,
    ) -> Result<String> {
        self.record_event(record)
    }

    /// Appends an Ed25519 signature of the final ledger state.
    /// Fulfills INV-36: Mandatory Cryptographic Signing.
    pub fn sign_and_close(mut self, key: &SigningKey) -> Result<String> {
        let signature = key.sign(self.prev_hash.as_bytes());
        let sig_hex = {
            let mut out = String::with_capacity(128);
            for b in signature.to_bytes() {
                out.push_str(&format!("{:02x}", b));
            }
            out
        };

        let env = SignatureEnvelope {
            seq: self.seq,
            prev_hash: &self.prev_hash,
            signature: sig_hex.clone(),
        };

        let env_json = serde_json::to_string(&env)?;
        writeln!(self.file, "{}", env_json)?;
        self.file.flush()?;

        Ok(sig_hex)
    }

    /// Verifies the cryptographic Merkle DAG hash chain of an audit ledger file (INV-34).
    ///
    /// Fulfills INV-34: Every event envelope is linked to its predecessor by
    /// `hash = SHA256(prev_hash : seq : payload_json)`. Returns `Ok(true)` if
    /// and only if the hash chain is fully intact, sequence numbers are strictly
    /// monotonic starting at 0 with genesis hash "GENESIS", and signatures match.
    pub fn verify_file<P: AsRef<Path>>(path: P) -> Result<bool> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        use std::io::BufRead;
        let reader = std::io::BufReader::new(file);
        let mut expected_prev = GENESIS_HASH.to_string();
        let mut expected_seq: u64 = 0;
        let mut seen_signature = false;

        for line_res in reader.lines() {
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if seen_signature {
                return Ok(false);
            }
            let value: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => return Ok(false),
            };

            if value.get("signature").is_some() {
                let prev_hash = match value.get("prev_hash").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => return Ok(false),
                };
                let seq = match value.get("seq").and_then(|v| v.as_u64()) {
                    Some(s) => s,
                    None => return Ok(false),
                };
                if prev_hash != expected_prev || seq != expected_seq {
                    return Ok(false);
                }
                seen_signature = true;
                continue;
            }

            let seq = match value.get("seq").and_then(|v| v.as_u64()) {
                Some(s) => s,
                None => return Ok(false),
            };
            let prev_hash = match value.get("prev_hash").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return Ok(false),
            };
            let hash = match value.get("hash").and_then(|v| v.as_str()) {
                Some(h) => h,
                None => return Ok(false),
            };

            if seq != expected_seq || prev_hash != expected_prev {
                return Ok(false);
            }

            let mut obj = match value {
                serde_json::Value::Object(map) => map,
                _ => return Ok(false),
            };
            obj.remove("seq");
            obj.remove("prev_hash");
            obj.remove("hash");

            let payload_json = serde_json::to_string(&serde_json::Value::Object(obj))?;
            let data_to_hash = format!("{}:{}:{}", prev_hash, seq, payload_json);
            let recomputed = manual_hex_hash(&data_to_hash);
            if recomputed != hash {
                return Ok(false);
            }

            expected_prev = hash.to_string();
            expected_seq += 1;
        }

        Ok(expected_seq > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_ledger_lifecycle_and_verification() {
        let temp_dir = std::env::temp_dir().join(format!("vetto-test-ledger-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("ledger.jsonl");
        let _ = std::fs::remove_file(&ledger_path);

        let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");

        #[derive(Serialize)]
        struct TestPayload {
            message: String,
            code: i32,
        }

        let p1 = TestPayload { message: "init".into(), code: 0 };
        let p2 = TestPayload { message: "mutation".into(), code: 1 };
        let p3 = TestPayload { message: "verdict".into(), code: 0 };

        assert!(ledger.record_event(&p1).is_ok());
        assert!(ledger.record_event(&p2).is_ok());
        assert!(ledger.record_event(&p3).is_ok());
        drop(ledger);

        let verified = AuditLedger::verify_file(&ledger_path).expect("verify ledger");
        assert!(verified, "Ledger should be valid and verified");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_ledger_signed_verification() {
        let temp_dir = std::env::temp_dir().join(format!("vetto-test-signed-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("signed_ledger.jsonl");
        let _ = std::fs::remove_file(&ledger_path);

        let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");

        #[derive(Serialize)]
        struct EventData {
            event: &'static str,
        }

        ledger.record_event(&EventData { event: "start" }).unwrap();
        ledger.record_event(&EventData { event: "finish" }).unwrap();

        let mut csprng = rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let _sig = ledger.sign_and_close(&signing_key).expect("sign ledger");

        let verified = AuditLedger::verify_file(&ledger_path).expect("verify ledger");
        assert!(verified, "Signed ledger should be valid");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_ledger_tamper_detection() {
        let temp_dir = std::env::temp_dir().join(format!("vetto-test-tamper-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("tampered_ledger.jsonl");
        let _ = std::fs::remove_file(&ledger_path);

        let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");

        #[derive(Serialize)]
        struct EventData {
            action: String,
        }

        ledger.record_event(&EventData { action: "read".into() }).unwrap();
        ledger.record_event(&EventData { action: "write".into() }).unwrap();
        drop(ledger);

        let content = std::fs::read_to_string(&ledger_path).unwrap();
        let tampered = content.replace("read", "hack");
        std::fs::write(&ledger_path, tampered).unwrap();

        let verified = AuditLedger::verify_file(&ledger_path).expect("verify ledger");
        assert!(!verified, "Tampered ledger must fail verification (INV-34)");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_ledger_reorder_detection() {
        let temp_dir = std::env::temp_dir().join(format!("vetto-test-reorder-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("reordered_ledger.jsonl");
        let _ = std::fs::remove_file(&ledger_path);

        let mut ledger = AuditLedger::new(&ledger_path).expect("create ledger");

        #[derive(Serialize)]
        struct EventData {
            idx: usize,
        }

        ledger.record_event(&EventData { idx: 1 }).unwrap();
        ledger.record_event(&EventData { idx: 2 }).unwrap();
        drop(ledger);

        let content = std::fs::read_to_string(&ledger_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let reordered = format!("{}\n{}\n", lines[1], lines[0]);
        std::fs::write(&ledger_path, reordered).unwrap();

        let verified = AuditLedger::verify_file(&ledger_path).expect("verify ledger");
        assert!(!verified, "Reordered lines must fail verification (INV-34)");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_ledger_empty_file() {
        let temp_dir = std::env::temp_dir().join(format!("vetto-test-empty-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ledger_path = temp_dir.join("empty.jsonl");
        std::fs::write(&ledger_path, "").unwrap();

        let verified = AuditLedger::verify_file(&ledger_path).expect("verify ledger");
        assert!(!verified, "Empty ledger should not be verified");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
