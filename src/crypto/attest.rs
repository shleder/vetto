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
        let payload_json = serde_json::to_string(event)?;
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
}
