//! Cosign / Sigstore SLSA Level 3 In-Toto Attestation Envelope generator.
//!
//! Fulfills Section 17.2.2 of the Next-Generation Architectural Specification:
//! Generates machine-verifiable In-Toto SLSA Provenance v1 envelopes
//! (`https://slsa.dev/provenance/v1`) with cryptographic Ed25519 signing.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
pub const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";
pub const VETTO_ATTESTATION_BUILD_TYPE: &str = "https://vetto.dev/attestation/v1";
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Subject of an in-toto statement (e.g. git commit or artifact digest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlsaSubject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

impl SlsaSubject {
    pub fn new(name: impl Into<String>, sha256_digest: impl Into<String>) -> Self {
        let mut digest = BTreeMap::new();
        digest.insert("sha256".to_string(), sha256_digest.into());
        Self {
            name: name.into(),
            digest,
        }
    }
}

/// External parameters supplied to the execution environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlsaExternalParameters {
    pub contract_id: String,
    pub agent_name: String,
}

/// Build definition within the SLSA predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlsaBuildDefinition {
    #[serde(rename = "buildType")]
    pub build_type: String,
    #[serde(rename = "externalParameters")]
    pub external_parameters: SlsaExternalParameters,
}

/// Builder identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlsaBuilder {
    pub id: String,
}

/// Metadata concerning the invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlsaMetadata {
    #[serde(rename = "invocationId")]
    pub invocation_id: String,
    #[serde(rename = "startedOn")]
    pub started_on: String,
    #[serde(rename = "finishedOn")]
    pub finished_on: String,
}

/// Details of the execution run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlsaRunDetails {
    pub builder: SlsaBuilder,
    pub metadata: SlsaMetadata,
}

/// The SLSA Provenance v1 predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlsaPredicate {
    #[serde(rename = "buildDefinition")]
    pub build_definition: SlsaBuildDefinition,
    #[serde(rename = "runDetails")]
    pub run_details: SlsaRunDetails,
}

/// In-Toto Statement v1 containing a SLSA Provenance v1 predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<SlsaSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: SlsaPredicate,
}

impl InTotoStatement {
    /// Serializes statement to standard JSON string.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Serializes statement to pretty-printed JSON string.
    pub fn to_pretty_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Signed In-Toto SLSA Envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSlsaEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub signature: String,
    pub statement: InTotoStatement,
}

impl SignedSlsaEnvelope {
    /// Cryptographically verifies the Ed25519 signature over the payload,
    /// and validates that the enclosed statement matches the signed payload bytes.
    pub fn verify(&self, public_key: &VerifyingKey) -> Result<()> {
        if self.signature.len() != 128 {
            bail!(
                "Invalid signature length: expected 128 hex characters, got {}",
                self.signature.len()
            );
        }

        let mut sig_bytes = [0u8; 64];
        for i in 0..64 {
            sig_bytes[i] = u8::from_str_radix(&self.signature[i * 2..i * 2 + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex byte in signature: {}", e))?;
        }

        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        public_key
            .verify(self.payload.as_bytes(), &signature)
            .map_err(|e| {
                anyhow::anyhow!("SLSA cryptographic signature verification failed: {}", e)
            })?;

        let payload_statement: InTotoStatement = serde_json::from_str(&self.payload)
            .map_err(|e| anyhow::anyhow!("Failed to parse payload as InTotoStatement: {}", e))?;

        if payload_statement != self.statement {
            bail!(
                "Envelope integrity violation: embedded statement does not match verified payload"
            );
        }

        Ok(())
    }
}

/// Builder for SLSA Level 3 In-Toto statements and signed envelopes.
#[derive(Debug, Clone)]
pub struct CosignSlsaBuilder {
    contract_id: String,
    agent_name: String,
    builder_id: String,
    invocation_id: String,
    started_on: String,
    finished_on: String,
    subjects: Vec<SlsaSubject>,
}

impl CosignSlsaBuilder {
    /// Creates a new builder initialized with contract ID and agent name.
    pub fn new(contract_id: impl Into<String>, agent_name: impl Into<String>) -> Self {
        Self {
            contract_id: contract_id.into(),
            agent_name: agent_name.into(),
            builder_id: format!("vetto-runtime:v{}", env!("CARGO_PKG_VERSION")),
            invocation_id: format!("session-{}", uuid_or_random()),
            started_on: chrono::Utc::now().to_rfc3339(),
            finished_on: chrono::Utc::now().to_rfc3339(),
            subjects: Vec::new(),
        }
    }

    /// Adds a subject to the statement.
    pub fn subject(mut self, name: impl Into<String>, sha256_digest: impl Into<String>) -> Self {
        self.subjects.push(SlsaSubject::new(name, sha256_digest));
        self
    }

    /// Sets the builder ID.
    pub fn builder_id(mut self, id: impl Into<String>) -> Self {
        self.builder_id = id.into();
        self
    }

    /// Sets the invocation ID.
    pub fn invocation_id(mut self, id: impl Into<String>) -> Self {
        self.invocation_id = id.into();
        self
    }

    /// Sets the execution timestamps.
    pub fn timestamps(
        mut self,
        started_on: impl Into<String>,
        finished_on: impl Into<String>,
    ) -> Self {
        self.started_on = started_on.into();
        self.finished_on = finished_on.into();
        self
    }

    /// Builds the canonical In-Toto statement.
    pub fn build(self) -> InTotoStatement {
        InTotoStatement {
            statement_type: IN_TOTO_STATEMENT_V1.to_string(),
            subject: self.subjects,
            predicate_type: SLSA_PROVENANCE_V1.to_string(),
            predicate: SlsaPredicate {
                build_definition: SlsaBuildDefinition {
                    build_type: VETTO_ATTESTATION_BUILD_TYPE.to_string(),
                    external_parameters: SlsaExternalParameters {
                        contract_id: self.contract_id,
                        agent_name: self.agent_name,
                    },
                },
                run_details: SlsaRunDetails {
                    builder: SlsaBuilder {
                        id: self.builder_id,
                    },
                    metadata: SlsaMetadata {
                        invocation_id: self.invocation_id,
                        started_on: self.started_on,
                        finished_on: self.finished_on,
                    },
                },
            },
        }
    }

    /// Builds and cryptographically signs the envelope with the provided Ed25519 signing key.
    pub fn sign(self, key: &SigningKey) -> Result<SignedSlsaEnvelope> {
        let statement = self.build();
        let payload_json = statement.to_json()?;
        let signature_bytes = key.sign(payload_json.as_bytes());

        let mut sig_hex = String::with_capacity(128);
        for b in signature_bytes.to_bytes() {
            sig_hex.push_str(&format!("{:02x}", b));
        }

        Ok(SignedSlsaEnvelope {
            payload_type: IN_TOTO_PAYLOAD_TYPE.to_string(),
            payload: payload_json,
            signature: sig_hex,
            statement,
        })
    }
}

pub fn uuid_or_random() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    // RFC 4122 / 9562 UUID v4:
    // Set version 4: 0b0100 in high 4 bits of time_hi_and_version (byte 6)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set variant 1: 0b10 in high 2 bits of clock_seq_hi_and_reserved (byte 8)
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_slsa_builder_and_statement_schema() {
        let builder = CosignSlsaBuilder::new("test-contract-123", "claude-code")
            .subject(
                "git-commit:b3ea2af",
                "8f434346648f6b96df89dda901c5176b10f60047a0641b98b95886ac8f6eec6a",
            )
            .builder_id("vetto-runtime:v0.40.0")
            .invocation_id("session-550e8400-e29b-41d4-a716-446655440000")
            .timestamps("2026-09-14T15:30:00Z", "2026-09-14T15:30:12Z");

        let statement = builder.build();
        assert_eq!(statement.statement_type, IN_TOTO_STATEMENT_V1);
        assert_eq!(statement.predicate_type, SLSA_PROVENANCE_V1);
        assert_eq!(statement.subject.len(), 1);
        assert_eq!(statement.subject[0].name, "git-commit:b3ea2af");
        assert_eq!(
            statement.subject[0]
                .digest
                .get("sha256")
                .map(|s| s.as_str()),
            Some("8f434346648f6b96df89dda901c5176b10f60047a0641b98b95886ac8f6eec6a")
        );
        assert_eq!(
            statement
                .predicate
                .build_definition
                .external_parameters
                .contract_id,
            "test-contract-123"
        );
        assert_eq!(
            statement
                .predicate
                .build_definition
                .external_parameters
                .agent_name,
            "claude-code"
        );

        let json = statement.to_json().expect("serialize to json");
        assert!(json.contains("\"_type\":\"https://in-toto.io/Statement/v1\""));
        assert!(json.contains("\"predicateType\":\"https://slsa.dev/provenance/v1\""));
    }

    #[test]
    fn test_slsa_signed_envelope() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let builder = CosignSlsaBuilder::new("contract-456", "opencode").subject(
            "test-artifact",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );

        let signed = builder.sign(&signing_key).expect("sign envelope");
        assert_eq!(signed.payload_type, IN_TOTO_PAYLOAD_TYPE);
        assert_eq!(signed.signature.len(), 128); // 64-byte Ed25519 signature in hex
        assert!(signed.payload.contains("contract-456"));

        // Cryptographic verification must succeed with valid key
        assert!(signed.verify(&verifying_key).is_ok());

        // Verification fails with wrong key
        let wrong_key = SigningKey::generate(&mut csprng).verifying_key();
        assert!(signed.verify(&wrong_key).is_err());

        // Verification fails on tampered payload
        let mut tampered = signed.clone();
        tampered.payload.push_str(" ");
        assert!(tampered.verify(&verifying_key).is_err());

        // Verification fails on tampered signature
        let mut tampered_sig = signed.clone();
        tampered_sig.signature.replace_range(0..2, "00");
        assert!(tampered_sig.verify(&verifying_key).is_err());
    }

    #[test]
    fn test_uuid_v4_format() {
        let uuid = uuid_or_random();
        assert_eq!(uuid.len(), 36);
        let chars: Vec<char> = uuid.chars().collect();
        assert_eq!(chars[8], '-');
        assert_eq!(chars[13], '-');
        assert_eq!(chars[14], '4'); // Version 4
        assert_eq!(chars[18], '-');
        assert!(matches!(chars[19], '8' | '9' | 'a' | 'b')); // Variant 1
        assert_eq!(chars[23], '-');
    }
}
