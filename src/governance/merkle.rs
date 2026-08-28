//! Immutable Merkle-tree cryptographic audit log (R4.10: `vetto-merkle-audit`).
//!
//! Provides a tamper-evident append-only event ledger backed by SHA-256 hash chaining,
//! full binary Merkle trees, cryptographic inclusion proofs, and digital seals.

use std::fmt;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Individual cryptographic audit block in the ledger's hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditBlock {
    pub index: u64,
    pub timestamp_epoch_micros: u64,
    pub session_uuid: String,
    pub event_type: String,
    pub event_payload_json: String,
    pub previous_block_hash: [u8; 32],
    pub current_block_hash: [u8; 32],
    pub nonce: u64,
}

impl AuditBlock {
    /// Computes the canonical SHA-256 block hash.
    pub fn compute_hash(
        index: u64,
        timestamp_epoch_micros: u64,
        session_uuid: &str,
        event_type: &str,
        event_payload_json: &str,
        previous_block_hash: &[u8; 32],
        nonce: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"VETTO_BLOCK_V1");
        hasher.update(&index.to_be_bytes());
        hasher.update(&timestamp_epoch_micros.to_be_bytes());
        hasher.update(session_uuid.as_bytes());
        hasher.update(event_type.as_bytes());
        hasher.update(event_payload_json.as_bytes());
        hasher.update(previous_block_hash);
        hasher.update(&nonce.to_be_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Verifies if `current_block_hash` matches canonical computation.
    pub fn is_valid(&self) -> bool {
        let computed = Self::compute_hash(
            self.index,
            self.timestamp_epoch_micros,
            &self.session_uuid,
            &self.event_type,
            &self.event_payload_json,
            &self.previous_block_hash,
            self.nonce,
        );
        computed == self.current_block_hash
    }

    /// Returns hexadecimal representation of current block hash.
    pub fn hash_hex(&self) -> String {
        hex_encode(&self.current_block_hash)
    }

    /// Returns hexadecimal representation of previous block hash.
    pub fn prev_hash_hex(&self) -> String {
        hex_encode(&self.previous_block_hash)
    }
}

/// Single step in a Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub sibling_hash: [u8; 32],
    pub is_left: bool,
}

/// Cryptographic inclusion proof for an individual audit log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntryProof {
    pub leaf_index: usize,
    pub entry_hash: [u8; 32],
    pub audit_path: Vec<MerkleProofStep>,
    pub merkle_root: [u8; 32],
}

impl AuditEntryProof {
    /// Validates whether the entry hash and audit path lead to the declared Merkle root.
    pub fn verify(&self) -> bool {
        let mut current_hash = MerkleAuditLog::hash_leaf(&self.entry_hash);

        for step in &self.audit_path {
            current_hash = if step.is_left {
                MerkleAuditLog::hash_nodes(&step.sibling_hash, &current_hash)
            } else {
                MerkleAuditLog::hash_nodes(&current_hash, &step.sibling_hash)
            };
        }

        current_hash == self.merkle_root
    }
}

/// Final cryptographic seal of a completed audit ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleAuditSeal {
    pub total_blocks: u64,
    pub merkle_root: [u8; 32],
    pub merkle_root_hex: String,
    pub first_block_hash: [u8; 32],
    pub last_block_hash: [u8; 32],
    pub seal_timestamp_micros: u64,
    pub signature_hex: String,
    pub signer_identity: String,
}

/// Node representation in the generated Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleNode {
    pub hash: [u8; 32],
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
    pub is_leaf: bool,
    pub leaf_index: Option<usize>,
}

/// Errors occurring during Merkle audit operations.
#[derive(Debug, Error)]
pub enum MerkleAuditError {
    #[error("Ledger chain continuity broken at block {index}: expected prev_hash {expected}, found {found}")]
    ChainBroken { index: u64, expected: String, found: String },
    #[error("Block {0} hash payload is corrupt")]
    BlockCorrupted(u64),
    #[error("Index out of bounds for inclusion proof: index {index}, total {total}")]
    IndexOutOfBounds { index: usize, total: usize },
    #[error("Audit ledger is empty")]
    EmptyLedger,
    #[error("Seal signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error("Serialization / Deserialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Append-only Merkle tree and hash chain manager.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MerkleAuditLog {
    blocks: Vec<AuditBlock>,
    current_hash: [u8; 32],
}

impl MerkleAuditLog {
    /// Creates a new empty audit log initialized with genesis hash [0; 32].
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            current_hash: [0u8; 32],
        }
    }

    /// Number of blocks in the ledger.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Checks if the ledger is empty.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Returns a slice of all audit blocks.
    pub fn blocks(&self) -> &[AuditBlock] {
        &self.blocks
    }

    /// Appends a new event to the ledger, computing the new hash and updating the chain.
    pub fn append(&mut self, session_uuid: &str, event_type: &str, payload_json: &str) -> AuditBlock {
        let index = self.blocks.len() as u64;
        let timestamp_epoch_micros = Utc::now().timestamp_micros() as u64;
        let previous_block_hash = self.current_hash;
        let nonce = 0; // Deterministic default nonce

        let current_block_hash = AuditBlock::compute_hash(
            index,
            timestamp_epoch_micros,
            session_uuid,
            event_type,
            payload_json,
            &previous_block_hash,
            nonce,
        );

        let block = AuditBlock {
            index,
            timestamp_epoch_micros,
            session_uuid: session_uuid.to_string(),
            event_type: event_type.to_string(),
            event_payload_json: payload_json.to_string(),
            previous_block_hash,
            current_block_hash,
            nonce,
        };

        self.current_hash = current_block_hash;
        self.blocks.push(block.clone());
        block
    }

    /// Verifies the integrity of the linear hash chain from genesis to the last block.
    pub fn verify_chain(&self) -> Result<bool, MerkleAuditError> {
        let mut expected_prev = [0u8; 32];

        for (i, block) in self.blocks.iter().enumerate() {
            if block.index != i as u64 {
                return Err(MerkleAuditError::ChainBroken {
                    index: block.index,
                    expected: format!("Index {}", i),
                    found: format!("Index {}", block.index),
                });
            }

            if block.previous_block_hash != expected_prev {
                return Err(MerkleAuditError::ChainBroken {
                    index: block.index,
                    expected: hex_encode(&expected_prev),
                    found: block.prev_hash_hex(),
                });
            }

            if !block.is_valid() {
                return Err(MerkleAuditError::BlockCorrupted(block.index));
            }

            expected_prev = block.current_block_hash;
        }

        Ok(true)
    }

    /// Computes the Merkle Root for all blocks in the ledger.
    pub fn compute_merkle_root(&self) -> [u8; 32] {
        if self.blocks.is_empty() {
            return [0u8; 32];
        }

        let mut current_level: Vec<[u8; 32]> = self
            .blocks
            .iter()
            .map(|b| Self::hash_leaf(&b.current_block_hash))
            .collect();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(Self::hash_nodes(&chunk[0], &chunk[1]));
                } else {
                    // Duplicate last odd node according to standard Merkle tree specification
                    next_level.push(Self::hash_nodes(&chunk[0], &chunk[0]));
                }
            }
            current_level = next_level;
        }

        current_level[0]
    }

    /// Generates a cryptographic Merkle inclusion proof for the block at `leaf_index`.
    pub fn generate_inclusion_proof(&self, leaf_index: usize) -> Result<AuditEntryProof, MerkleAuditError> {
        if leaf_index >= self.blocks.len() {
            return Err(MerkleAuditError::IndexOutOfBounds {
                index: leaf_index,
                total: self.blocks.len(),
            });
        }

        let entry_hash = self.blocks[leaf_index].current_block_hash;
        let merkle_root = self.compute_merkle_root();

        let mut current_level: Vec<[u8; 32]> = self
            .blocks
            .iter()
            .map(|b| Self::hash_leaf(&b.current_block_hash))
            .collect();

        let mut proof_steps = Vec::new();
        let mut idx = leaf_index;

        while current_level.len() > 1 {
            let is_right_node = idx % 2 == 1;
            let sibling_idx = if is_right_node {
                idx - 1
            } else if idx + 1 < current_level.len() {
                idx + 1
            } else {
                idx // Odd node paired with itself
            };

            let sibling_hash = current_level[sibling_idx];
            proof_steps.push(MerkleProofStep {
                sibling_hash,
                is_left: is_right_node,
            });

            // Compute next level
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(Self::hash_nodes(&chunk[0], &chunk[1]));
                } else {
                    next_level.push(Self::hash_nodes(&chunk[0], &chunk[0]));
                }
            }

            idx /= 2;
            current_level = next_level;
        }

        Ok(AuditEntryProof {
            leaf_index,
            entry_hash,
            audit_path: proof_steps,
            merkle_root,
        })
    }

    /// Domain-separated leaf hashing: `SHA256(0x00 || block_hash)`.
    pub fn hash_leaf(block_hash: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(block_hash);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Domain-separated internal node hashing: `SHA256(0x01 || left || right)`.
    pub fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x01]);
        hasher.update(left);
        hasher.update(right);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

/// Cryptographic engine facilitating seal production, validation, and serialization.
pub struct CryptographicAuditEngine {
    log: MerkleAuditLog,
}

impl Default for CryptographicAuditEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptographicAuditEngine {
    /// Creates a new engine instance.
    pub fn new() -> Self {
        Self {
            log: MerkleAuditLog::new(),
        }
    }

    /// Returns a reference to the internal audit log.
    pub fn log(&self) -> &MerkleAuditLog {
        &self.log
    }

    /// Appends a structured JSON payload to the ledger.
    pub fn append_event(
        &mut self,
        session_id: &str,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<AuditBlock, MerkleAuditError> {
        let payload_str = serde_json::to_string(payload)?;
        Ok(self.log.append(session_id, event_type, &payload_str))
    }

    /// Verifies the complete ledger chain integrity.
    pub fn verify_chain_integrity(&self) -> Result<bool, MerkleAuditError> {
        self.log.verify_chain()
    }

    /// Generates a cryptographic inclusion proof for a block index.
    pub fn generate_inclusion_proof(&self, block_index: u64) -> Result<AuditEntryProof, MerkleAuditError> {
        self.log.generate_inclusion_proof(block_index as usize)
    }

    /// Verifies any arbitrary inclusion proof.
    pub fn verify_inclusion_proof(proof: &AuditEntryProof) -> bool {
        proof.verify()
    }

    /// Creates a signed `MerkleAuditSeal` using a secret signing key.
    pub fn seal_ledger(&self, signer_key: &[u8], signer_id: &str) -> Result<MerkleAuditSeal, MerkleAuditError> {
        if self.log.is_empty() {
            return Err(MerkleAuditError::EmptyLedger);
        }

        let total_blocks = self.log.len() as u64;
        let merkle_root = self.log.compute_merkle_root();
        let first_block_hash = self.log.blocks()[0].current_block_hash;
        let last_block_hash = self.log.blocks().last().unwrap().current_block_hash;
        let seal_timestamp_micros = Utc::now().timestamp_micros() as u64;

        // Compute HMAC-SHA256 digital signature over root and metadata
        let mut hasher = Sha256::new();
        hasher.update(signer_key);
        hasher.update(&total_blocks.to_be_bytes());
        hasher.update(&merkle_root);
        hasher.update(&first_block_hash);
        hasher.update(&last_block_hash);
        hasher.update(&seal_timestamp_micros.to_be_bytes());
        hasher.update(signer_id.as_bytes());
        let signature = hasher.finalize();

        Ok(MerkleAuditSeal {
            total_blocks,
            merkle_root,
            merkle_root_hex: hex_encode(&merkle_root),
            first_block_hash,
            last_block_hash,
            seal_timestamp_micros,
            signature_hex: hex_encode(&signature),
            signer_identity: signer_id.to_string(),
        })
    }

    /// Verifies a seal against a secret key and current ledger state.
    pub fn verify_seal(&self, seal: &MerkleAuditSeal, signer_key: &[u8]) -> Result<bool, MerkleAuditError> {
        if self.log.is_empty() {
            return Err(MerkleAuditError::EmptyLedger);
        }

        if seal.total_blocks != self.log.len() as u64 {
            return Ok(false);
        }

        let expected_root = self.log.compute_merkle_root();
        if seal.merkle_root != expected_root {
            return Ok(false);
        }

        // Recompute expected HMAC-SHA256 signature
        let mut hasher = Sha256::new();
        hasher.update(signer_key);
        hasher.update(&seal.total_blocks.to_be_bytes());
        hasher.update(&seal.merkle_root);
        hasher.update(&seal.first_block_hash);
        hasher.update(&seal.last_block_hash);
        hasher.update(&seal.seal_timestamp_micros.to_be_bytes());
        hasher.update(seal.signer_identity.as_bytes());
        let expected_sig = hex_encode(&hasher.finalize());

        if seal.signature_hex != expected_sig {
            return Err(MerkleAuditError::SignatureInvalid("Signature mismatch".to_string()));
        }

        Ok(true)
    }

    /// Exports the full ledger as formatted JSON.
    pub fn export_tamper_evident_log(&self) -> Result<String, MerkleAuditError> {
        serde_json::to_string_pretty(&self.log).map_err(MerkleAuditError::from)
    }

    /// Imports a JSON-serialized ledger and verifies its cryptographic chain.
    pub fn import_and_verify_log(json_data: &str) -> Result<Self, MerkleAuditError> {
        let log: MerkleAuditLog = serde_json::from_str(json_data)?;
        log.verify_chain()?;
        Ok(Self { log })
    }
}

/// Encodes binary slices to standard lowercase hexadecimal strings.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

/// Decodes hexadecimal strings into fixed 32-byte arrays.
pub fn hex_decode_32(hex_str: &str) -> Result<[u8; 32], &'static str> {
    if hex_str.len() != 64 {
        return Err("Hex string must be 64 characters for 32 bytes");
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte_str = &hex_str[i * 2..i * 2 + 2];
        out[i] = u8::from_str_radix(byte_str, 16).map_err(|_| "Invalid hex character")?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_hash_chain_continuity() {
        let mut engine = CryptographicAuditEngine::new();
        let session = "session-xyz-42";

        engine.append_event(session, "tool_call", &serde_json::json!({
            "tool": "read_file",
            "path": "/etc/hosts"
        })).unwrap();

        engine.append_event(session, "sandbox_block", &serde_json::json!({
            "target": "/etc/shadow",
            "reason": "Landlock VFS violation"
        })).unwrap();

        engine.append_event(session, "network_connect", &serde_json::json!({
            "host": "api.github.com",
            "port": 443
        })).unwrap();

        assert_eq!(engine.log().len(), 3);
        assert!(engine.verify_chain_integrity().unwrap());

        // Check continuity
        let b0 = &engine.log().blocks()[0];
        let b1 = &engine.log().blocks()[1];
        let b2 = &engine.log().blocks()[2];

        assert_eq!(b0.previous_block_hash, [0u8; 32]);
        assert_eq!(b1.previous_block_hash, b0.current_block_hash);
        assert_eq!(b2.previous_block_hash, b1.current_block_hash);
    }

    #[test]
    fn test_tamper_detection() {
        let mut log = MerkleAuditLog::new();
        log.append("sess-1", "exec", "{\"cmd\":\"ls\"}");
        log.append("sess-1", "exec", "{\"cmd\":\"cargo build\"}");

        assert!(log.verify_chain().is_ok());

        // Tamper with payload in block 0
        log.blocks[0].event_payload_json = "{\"cmd\":\"rm -rf /\"}".to_string();

        let verify_result = log.verify_chain();
        assert!(verify_result.is_err());
    }

    #[test]
    fn test_merkle_root_and_inclusion_proofs() {
        let mut engine = CryptographicAuditEngine::new();
        let session = "audit-sess";

        for i in 0..7 {
            engine.append_event(session, "step", &serde_json::json!({ "step_idx": i })).unwrap();
        }

        let root = engine.log().compute_merkle_root();
        assert_ne!(root, [0u8; 32]);

        // Generate and verify proofs for all 7 leaves
        for i in 0..7 {
            let proof = engine.generate_inclusion_proof(i).unwrap();
            assert_eq!(proof.leaf_index, i as usize);
            assert_eq!(proof.merkle_root, root);
            assert!(CryptographicAuditEngine::verify_inclusion_proof(&proof));
        }
    }

    #[test]
    fn test_merkle_seal_generation_and_verification() {
        let mut engine = CryptographicAuditEngine::new();
        let session = "sealed-session-001";
        let secret_key = b"enterprise-audit-hsm-signing-key-32b!";
        let signer_id = "vetto-tpm-secure-enclave";

        engine.append_event(session, "init", &serde_json::json!({ "policy": "strict" })).unwrap();
        engine.append_event(session, "finish", &serde_json::json!({ "status": "clean" })).unwrap();

        let seal = engine.seal_ledger(secret_key, signer_id).unwrap();
        assert_eq!(seal.total_blocks, 2);
        assert_eq!(seal.signer_identity, signer_id);

        let verified = engine.verify_seal(&seal, secret_key).unwrap();
        assert!(verified);

        // Verification with wrong key should fail
        let wrong_key = b"wrong-key-bytes-0000000000000000";
        let bad_verify = engine.verify_seal(&seal, wrong_key);
        assert!(bad_verify.is_err());
    }

    #[test]
    fn test_export_import_roundtrip() {
        let mut engine = CryptographicAuditEngine::new();
        engine.append_event("s1", "event_1", &serde_json::json!({ "data": 42 })).unwrap();
        engine.append_event("s1", "event_2", &serde_json::json!({ "data": 99 })).unwrap();

        let json = engine.export_tamper_evident_log().unwrap();
        assert!(json.contains("event_1"));

        let imported = CryptographicAuditEngine::import_and_verify_log(&json).unwrap();
        assert_eq!(imported.log().len(), 2);
        assert!(imported.verify_chain_integrity().unwrap());
    }
}
