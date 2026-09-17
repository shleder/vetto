//! Authoritative Specification: Canonical Security Contract (Phase 2 / NEXT_GEN §7).
//!
//! Formalizes the immutable capability boundary between supervisor and agent
//! workload. Sealed via cryptographic digest over canonical serialization to
//! prevent tampering.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Unsealed contract payload used for deterministic canonical hashing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsealedSecurityContract {
    pub contract_version: u32,
    pub contract_id: String,
    pub session_nonce: String,
    pub agent_identity: AgentIdentity,
    pub filesystem: FilesystemContract,
    pub network: NetworkContract,
    pub resources: ResourceContract,
    pub environment: EnvironmentContract,
    pub attestation: AttestationContract,
    #[serde(default)]
    pub crypto: CryptoContract,
}

impl UnsealedSecurityContract {
    /// Compute deterministic cryptographic digest (BLAKE3) of canonical serialization.
    pub fn compute_digest(&self) -> Result<String, serde_json::Error> {
        let mut payload = self.clone();
        // Signing requirements and key identity are authority; the detached
        // signature cannot be included in the message it signs.
        payload.crypto.signature = None;
        let value = serde_json::to_value(payload)?;
        let json_bytes = serde_json::to_vec(&value)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&json_bytes);
        Ok(hasher.finalize().to_hex())
    }

    /// Seal the contract, binding the cryptographic digest.
    pub fn seal(self) -> Result<SecurityContract, serde_json::Error> {
        let digest = self.compute_digest()?;
        Ok(SecurityContract {
            contract_version: self.contract_version,
            contract_id: self.contract_id,
            session_nonce: self.session_nonce,
            agent_identity: self.agent_identity,
            filesystem: self.filesystem,
            network: self.network,
            resources: self.resources,
            environment: self.environment,
            attestation: self.attestation,
            crypto: self.crypto,
            contract_digest_blake3: digest,
        })
    }
}

/// Authoritative Sealed Security Contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityContract {
    pub contract_version: u32,
    pub contract_id: String,
    pub session_nonce: String,
    pub agent_identity: AgentIdentity,
    pub filesystem: FilesystemContract,
    pub network: NetworkContract,
    pub resources: ResourceContract,
    pub environment: EnvironmentContract,
    pub attestation: AttestationContract,
    #[serde(default)]
    pub crypto: CryptoContract,
    /// Cryptographic digest of CanonicalJSON(UnsealedSecurityContract).
    /// Skipped during canonical serialization to avoid circular dependencies.
    #[serde(default, skip_serializing)]
    pub contract_digest_blake3: String,
}

impl SecurityContract {
    /// Extract unsealed payload.
    pub fn unsealed(&self) -> UnsealedSecurityContract {
        UnsealedSecurityContract {
            contract_version: self.contract_version,
            contract_id: self.contract_id.clone(),
            session_nonce: self.session_nonce.clone(),
            agent_identity: self.agent_identity.clone(),
            filesystem: self.filesystem.clone(),
            network: self.network.clone(),
            resources: self.resources.clone(),
            environment: self.environment.clone(),
            attestation: self.attestation.clone(),
            crypto: self.crypto.clone(),
        }
    }

    /// Verify that the contract digest matches the unsealed payload.
    pub fn verify_digest(&self) -> bool {
        match self.unsealed().compute_digest() {
            Ok(expected) => expected == self.contract_digest_blake3,
            Err(_) => false,
        }
    }

    /// Sets the crypto contract configuration.
    pub fn with_crypto(mut self, crypto: CryptoContract) -> Self {
        self.crypto = crypto;
        self.contract_digest_blake3 = self
            .unsealed()
            .compute_digest()
            .expect("contract contains only JSON-serializable values");
        self
    }

    /// Configures minisign cryptographic signing parameters.
    pub fn with_minisign(
        mut self,
        enabled: bool,
        signature: Option<String>,
        public_key: Option<String>,
    ) -> Self {
        self.crypto.minisign_enabled = enabled;
        self.crypto.signature = signature;
        self.crypto.public_key = public_key;
        self.contract_digest_blake3 = self
            .unsealed()
            .compute_digest()
            .expect("contract contains only JSON-serializable values");
        self
    }
}

/// Cryptographic signing configuration and state for the security contract (Phase 4 / INV-36).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CryptoContract {
    pub minisign_enabled: bool,
    pub cosign_enabled: bool,
    pub signature: Option<String>,
    pub public_key: Option<String>,
}

impl CryptoContract {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_minisign(mut self, enabled: bool) -> Self {
        self.minisign_enabled = enabled;
        self
    }

    pub fn with_signature(mut self, signature: impl Into<String>) -> Self {
        self.signature = Some(signature.into());
        self
    }

    pub fn with_public_key(mut self, public_key: impl Into<String>) -> Self {
        self.public_key = Some(public_key.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentIdentity {
    pub agent_name: String,
    pub agent_preset: String,
    pub agent_version: String,
    pub invoked_binary: PathBuf,
    pub invoked_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilesystemContract {
    pub workspace_root: PathBuf,
    pub allow_read: Vec<PathBuf>,
    pub allow_write: Vec<PathBuf>,
    pub allow_execute: Vec<PathBuf>,
    pub mask_paths: Vec<PathBuf>,
    pub cow_overlay: bool,
    pub execution_root_ro: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkMode {
    Off,
    Allowlist,
    Direct,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkContract {
    pub mode: NetworkMode,
    pub allowed_domains: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub block_cloud_metadata: bool,
    pub block_loopback_daemons: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceContract {
    pub max_pids: u32,
    pub max_memory_bytes: u64,
    pub max_cpu_percent: u32,
    pub max_wall_time_ms: u64,
    pub max_stdout_bytes: u64,
    pub max_file_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentContract {
    pub pass_through_vars: Vec<String>,
    pub explicit_vars: BTreeMap<String, String>,
    pub redacted_patterns: Vec<String>,
    pub inject_session_nonce: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationContract {
    pub generate_audit_jsonl: bool,
    pub sign_minisign: bool,
    pub sign_cosign_slsa: bool,
    pub evidence_level_minimum: String,
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    fn sample_unsealed() -> UnsealedSecurityContract {
        UnsealedSecurityContract {
            crypto: CryptoContract::default(),
            contract_version: 1,
            contract_id: "test-contract-001".to_string(),
            session_nonce: "nonce-12345".to_string(),
            agent_identity: AgentIdentity {
                agent_name: "claude".to_string(),
                agent_preset: "claude".to_string(),
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                invoked_binary: PathBuf::from("/usr/bin/claude"),
                invoked_args: vec!["run".to_string()],
            },
            filesystem: FilesystemContract {
                workspace_root: PathBuf::from("/workspace"),
                allow_read: vec![PathBuf::from("/workspace"), PathBuf::from("/usr")],
                allow_write: vec![PathBuf::from("/workspace/target")],
                allow_execute: vec![PathBuf::from("/bin"), PathBuf::from("/usr/bin")],
                mask_paths: vec![PathBuf::from("/home/user/.ssh")],
                cow_overlay: true,
                execution_root_ro: true,
            },
            network: NetworkContract {
                mode: NetworkMode::Allowlist,
                allowed_domains: vec!["api.anthropic.com".to_string()],
                allowed_ports: vec![443],
                block_cloud_metadata: true,
                block_loopback_daemons: true,
            },
            resources: ResourceContract {
                max_pids: 128,
                max_memory_bytes: 2 * 1024 * 1024 * 1024,
                max_cpu_percent: 100,
                max_wall_time_ms: 120_000,
                max_stdout_bytes: 10 * 1024 * 1024,
                max_file_size_bytes: 100 * 1024 * 1024,
            },
            environment: EnvironmentContract {
                pass_through_vars: vec!["PATH".to_string()],
                explicit_vars: BTreeMap::new(),
                redacted_patterns: vec!["*_KEY".to_string()],
                inject_session_nonce: true,
            },
            attestation: AttestationContract {
                generate_audit_jsonl: true,
                sign_minisign: true,
                sign_cosign_slsa: false,
                evidence_level_minimum: "HOST_FACT".to_string(),
            },
        }
    }

    #[test]
    fn seal_and_verify_digest() {
        let unsealed = sample_unsealed();
        let sealed = unsealed.clone().seal().expect("seal contract");
        assert!(!sealed.contract_digest_blake3.is_empty());
        assert_eq!(sealed.contract_digest_blake3.len(), 64);
        assert!(sealed.verify_digest());

        // Tampering with contract should invalidate digest
        let mut tampered = sealed.clone();
        tampered.filesystem.cow_overlay = false;
        assert!(!tampered.verify_digest());

        let mut tampered_net = sealed.clone();
        tampered_net.network.mode = NetworkMode::Direct;
        assert!(!tampered_net.verify_digest());
    }

    #[test]
    fn deterministic_digest() {
        let u1 = sample_unsealed();
        let u2 = sample_unsealed();
        assert_eq!(u1.compute_digest().unwrap(), u2.compute_digest().unwrap());
    }

    #[test]
    fn signing_requirements_are_sealed_but_signature_is_detached() {
        let sealed =
            sample_unsealed()
                .seal()
                .unwrap()
                .with_minisign(true, None, Some("trusted-key".into()));
        assert!(sealed.verify_digest());
        let mut detached = sealed.clone();
        detached.crypto.signature = Some("detached-signature".into());
        assert!(detached.verify_digest());

        let mut disabled = sealed.clone();
        disabled.crypto.minisign_enabled = false;
        assert!(!disabled.verify_digest());
        let mut changed_key = sealed.clone();
        changed_key.crypto.public_key = Some("different-key".into());
        assert!(!changed_key.verify_digest());
        let mut changed_cosign = sealed;
        changed_cosign.crypto.cosign_enabled = true;
        assert!(!changed_cosign.verify_digest());
    }

    #[test]
    fn blake3_standard_test_vector_empty() {
        // Official BLAKE3 test vector for empty string
        let empty_hash = blake3::hash(b"");
        assert_eq!(
            empty_hash.to_hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            format!("{}", empty_hash),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn blake3_hasher_incremental() {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let hash1 = hasher.finalize();

        let hash2 = blake3::hash(b"hello world");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn crypto_contract_builder_methods() {
        let contract = sample_unsealed().seal().unwrap();
        assert!(!contract.crypto.minisign_enabled);

        let signed =
            contract.with_minisign(true, Some("abcd".to_string()), Some("1234".to_string()));
        assert!(signed.crypto.minisign_enabled);
        assert_eq!(signed.crypto.signature.as_deref(), Some("abcd"));
        assert_eq!(signed.crypto.public_key.as_deref(), Some("1234"));
    }
}

/// Canonical pure-Rust BLAKE3 implementation fulfilling INV-01 (NEXT_GEN §7, §23).
pub mod blake3 {
    pub const OUT_LEN: usize = 32;
    pub const KEY_LEN: usize = 32;
    pub const BLOCK_LEN: usize = 64;
    pub const CHUNK_LEN: usize = 1024;

    pub const CHUNK_START: u32 = 1 << 0;
    pub const CHUNK_END: u32 = 1 << 1;
    pub const PARENT: u32 = 1 << 2;
    pub const ROOT: u32 = 1 << 3;

    pub const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

    #[inline(always)]
    fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    fn round(state: &mut [u32; 16], m: &[u32; 16]) {
        g(state, 0, 4, 8, 12, m[0], m[1]);
        g(state, 1, 5, 9, 13, m[2], m[3]);
        g(state, 2, 6, 10, 14, m[4], m[5]);
        g(state, 3, 7, 11, 15, m[6], m[7]);
        g(state, 0, 5, 10, 15, m[8], m[9]);
        g(state, 1, 6, 11, 12, m[10], m[11]);
        g(state, 2, 7, 8, 13, m[12], m[13]);
        g(state, 3, 4, 9, 14, m[14], m[15]);
    }

    fn permute(m: &mut [u32; 16]) {
        let mut p = [0u32; 16];
        for i in 0..16 {
            p[i] = m[MSG_PERMUTATION[i]];
        }
        *m = p;
    }

    fn compress(
        cv: &[u32; 8],
        block: &[u32; 16],
        block_len: u32,
        counter: u64,
        flags: u32,
    ) -> [u32; 16] {
        let mut state = [
            cv[0],
            cv[1],
            cv[2],
            cv[3],
            cv[4],
            cv[5],
            cv[6],
            cv[7],
            IV[0],
            IV[1],
            IV[2],
            IV[3],
            counter as u32,
            (counter >> 32) as u32,
            block_len,
            flags,
        ];
        let mut block_copy = *block;

        for _ in 0..7 {
            round(&mut state, &block_copy);
            permute(&mut block_copy);
        }

        for i in 0..8 {
            state[i] ^= state[i + 8];
            state[i + 8] ^= cv[i];
        }
        state
    }

    struct Output {
        input_cv: [u32; 8],
        block_words: [u32; 16],
        block_len: u32,
        counter: u64,
        flags: u32,
    }

    impl Output {
        fn chaining_value(&self) -> [u32; 8] {
            let state = compress(
                &self.input_cv,
                &self.block_words,
                self.block_len,
                self.counter,
                self.flags,
            );
            let mut cv = [0u32; 8];
            cv.copy_from_slice(&state[0..8]);
            cv
        }

        fn root_output_bytes(&self) -> [u8; 32] {
            let state = compress(
                &self.input_cv,
                &self.block_words,
                self.block_len,
                self.counter,
                self.flags | ROOT,
            );
            let mut out = [0u8; 32];
            for (i, word) in state[0..8].iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            out
        }
    }

    fn parent_output(
        left_cv: &[u32; 8],
        right_cv: &[u32; 8],
        key: &[u32; 8],
        flags: u32,
    ) -> Output {
        let mut block_words = [0u32; 16];
        block_words[0..8].copy_from_slice(left_cv);
        block_words[8..16].copy_from_slice(right_cv);
        Output {
            input_cv: *key,
            block_words,
            block_len: 64,
            counter: 0,
            flags: flags | PARENT,
        }
    }

    #[derive(Clone)]
    struct ChunkState {
        cv: [u32; 8],
        chunk_counter: u64,
        buf: [u8; 64],
        buf_len: usize,
        blocks_compressed: u8,
        flags: u32,
    }

    impl ChunkState {
        fn new(key: &[u32; 8], chunk_counter: u64, flags: u32) -> Self {
            Self {
                cv: *key,
                chunk_counter,
                buf: [0u8; 64],
                buf_len: 0,
                blocks_compressed: 0,
                flags,
            }
        }

        fn len(&self) -> usize {
            (self.blocks_compressed as usize) * 64 + self.buf_len
        }

        fn update(&mut self, mut input: &[u8]) {
            while !input.is_empty() {
                if self.buf_len == 64 {
                    let mut block_words = [0u32; 16];
                    for (i, word) in block_words.iter_mut().enumerate() {
                        *word = u32::from_le_bytes([
                            self.buf[i * 4],
                            self.buf[i * 4 + 1],
                            self.buf[i * 4 + 2],
                            self.buf[i * 4 + 3],
                        ]);
                    }
                    let mut flags = self.flags;
                    if self.blocks_compressed == 0 {
                        flags |= CHUNK_START;
                    }
                    let state = compress(&self.cv, &block_words, 64, self.chunk_counter, flags);
                    let mut next_cv = [0u32; 8];
                    next_cv.copy_from_slice(&state[0..8]);
                    self.cv = next_cv;
                    self.blocks_compressed += 1;
                    self.buf = [0u8; 64];
                    self.buf_len = 0;
                }

                let take = (64 - self.buf_len).min(input.len());
                self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&input[..take]);
                self.buf_len += take;
                input = &input[take..];
            }
        }

        fn output(&self) -> Output {
            let mut block_words = [0u32; 16];
            for (i, word) in block_words.iter_mut().enumerate() {
                let offset = i * 4;
                if offset + 4 <= self.buf_len {
                    *word = u32::from_le_bytes([
                        self.buf[offset],
                        self.buf[offset + 1],
                        self.buf[offset + 2],
                        self.buf[offset + 3],
                    ]);
                } else if offset < self.buf_len {
                    let mut b = [0u8; 4];
                    let rem = self.buf_len - offset;
                    b[..rem].copy_from_slice(&self.buf[offset..offset + rem]);
                    *word = u32::from_le_bytes(b);
                } else {
                    *word = 0;
                }
            }
            let mut flags = self.flags | CHUNK_END;
            if self.blocks_compressed == 0 {
                flags |= CHUNK_START;
            }
            Output {
                input_cv: self.cv,
                block_words,
                block_len: self.buf_len as u32,
                counter: self.chunk_counter,
                flags,
            }
        }
    }

    /// Incremental BLAKE3 hasher.
    #[derive(Clone)]
    pub struct Hasher {
        chunk_state: ChunkState,
        key: [u32; 8],
        cv_stack: Vec<[u32; 8]>,
    }

    impl Default for Hasher {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Hasher {
        pub fn new() -> Self {
            Self {
                chunk_state: ChunkState::new(&IV, 0, 0),
                key: IV,
                cv_stack: Vec::new(),
            }
        }

        fn push_stack(&mut self, mut cv: [u32; 8]) {
            let mut total_chunks = self.chunk_state.chunk_counter;
            while total_chunks & 1 != 0 {
                let left_cv = self.cv_stack.pop().unwrap();
                let parent = parent_output(&left_cv, &cv, &self.key, 0);
                cv = parent.chaining_value();
                total_chunks >>= 1;
            }
            self.cv_stack.push(cv);
        }

        pub fn update(&mut self, mut input: &[u8]) -> &mut Self {
            while !input.is_empty() {
                if self.chunk_state.len() == 1024 {
                    let chunk_cv = self.chunk_state.output().chaining_value();
                    let next_chunk_counter = self.chunk_state.chunk_counter + 1;
                    self.push_stack(chunk_cv);
                    self.chunk_state = ChunkState::new(&self.key, next_chunk_counter, 0);
                }

                let want = 1024 - self.chunk_state.len();
                let take = want.min(input.len());
                self.chunk_state.update(&input[..take]);
                input = &input[take..];
            }
            self
        }

        pub fn finalize(&self) -> Hash {
            let mut output = self.chunk_state.output();
            let mut parent_nodes_remaining = self.cv_stack.len();
            while parent_nodes_remaining > 0 {
                parent_nodes_remaining -= 1;
                let left_cv = self.cv_stack[parent_nodes_remaining];
                output = parent_output(&left_cv, &output.chaining_value(), &self.key, 0);
            }
            Hash(output.root_output_bytes())
        }
    }

    /// BLAKE3 256-bit cryptographic digest.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct Hash(pub [u8; 32]);

    impl Hash {
        pub fn as_bytes(&self) -> &[u8; 32] {
            &self.0
        }

        pub fn to_hex(&self) -> String {
            let mut s = String::with_capacity(64);
            for b in &self.0 {
                use std::fmt::Write;
                let _ = write!(s, "{:02x}", b);
            }
            s
        }
    }

    impl std::fmt::Display for Hash {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.to_hex())
        }
    }

    impl std::fmt::Debug for Hash {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Hash({})", self.to_hex())
        }
    }

    /// Compute the BLAKE3 hash of the provided input slice.
    pub fn hash(data: &[u8]) -> Hash {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize()
    }
}
