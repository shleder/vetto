//! Audit hash-chain envelope (P3 slice): seq + hash-chain over audit records.
//!
//! Each record carries its sequence number and the hash of the previous
//! record, so truncation, reordering, or silent edits are detectable by
//! [`verify_chain`]. This module only builds and checks the chain — record
//! collection and storage stay in [`super::history`].

use sha2::{Digest, Sha256};

/// One chained audit envelope.
#[derive(Debug, Clone)]
pub struct ChainRecord {
    /// Monotonic position in the chain, starting at 0.
    pub seq: u64,
    /// Hex hash of the previous record (`GENESIS` for seq 0).
    pub prev_hash: String,
    /// Hex hash of `prev_hash + seq + payload`.
    pub hash: String,
    /// Opaque audited payload (already sanitized upstream).
    pub payload: String,
}

pub const GENESIS: &str = "GENESIS";

fn hash_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let bytes = hasher.finalize();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Append a payload to the chain. `prev` is the last record, or `None` for
/// the genesis record.
pub fn append(prev: Option<&ChainRecord>, payload: &str) -> ChainRecord {
    let (seq, prev_hash) = match prev {
        Some(r) => (r.seq + 1, r.hash.clone()),
        None => (0, GENESIS.to_string()),
    };
    let hash = hash_hex(&format!("{prev_hash}:{seq}:{payload}"));
    ChainRecord {
        seq,
        prev_hash,
        hash,
        payload: payload.to_string(),
    }
}

/// Verify an ordered slice: sequence continuity, prev-hash linkage, and
/// recomputed content hashes. Fails closed on the first break.
pub fn verify_chain(records: &[ChainRecord]) -> Result<(), String> {
    let mut expected_prev = GENESIS.to_string();
    for (i, r) in records.iter().enumerate() {
        if r.seq != i as u64 {
            return Err(format!(
                "audit_chain: seq gap at index {i}: expected {}, got {}",
                i, r.seq
            ));
        }
        if r.prev_hash != expected_prev {
            return Err(format!("audit_chain: prev_hash mismatch at seq {}", r.seq));
        }
        let recomputed = hash_hex(&format!("{}:{}:{}", r.prev_hash, r.seq, r.payload));
        if recomputed != r.hash {
            return Err(format!(
                "audit_chain: content hash mismatch at seq {}",
                r.seq
            ));
        }
        expected_prev = r.hash.clone();
    }
    Ok(())
}

#[cfg(test)]
mod chain_tests {
    use super::*;

    fn build(n: u64) -> Vec<ChainRecord> {
        let mut out = Vec::new();
        for i in 0..n {
            let prev = out.last();
            out.push(append(prev, &format!("event-{i}")));
        }
        out
    }

    #[test]
    fn round_trip_verifies() {
        let chain = build(5);
        assert!(verify_chain(&chain).is_ok());
        assert_eq!(chain[0].prev_hash, GENESIS);
        assert_eq!(chain[4].seq, 4);
    }

    #[test]
    fn tampered_payload_detected() {
        let mut chain = build(3);
        chain[1].payload = "forged".to_string();
        assert!(verify_chain(&chain).is_err());
    }

    #[test]
    fn reordered_records_detected() {
        let mut chain = build(3);
        chain.swap(0, 1);
        assert!(verify_chain(&chain).is_err());
    }

    #[test]
    fn truncated_tail_still_verifies_prefix() {
        // Truncation of the tail is visible as a missing seq only when the
        // expected length is known; the prefix itself must stay valid.
        let chain = build(4);
        assert!(verify_chain(&chain[..2]).is_ok());
    }

    #[test]
    fn empty_chain_verifies() {
        assert!(verify_chain(&[]).is_ok());
    }
}
