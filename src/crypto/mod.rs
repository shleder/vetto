//! Cryptographic attestation, SLSA envelopes, and audit signing primitives.

pub mod attest;
pub mod slsa;

pub use attest::{AuditLedger, GENESIS_HASH};
pub use slsa::{
    CosignSlsaBuilder, InTotoStatement, SignedSlsaEnvelope, SlsaBuildDefinition, SlsaMetadata,
    SlsaPredicate, SlsaRunDetails, SlsaSubject, IN_TOTO_PAYLOAD_TYPE, IN_TOTO_STATEMENT_V1,
    SLSA_PROVENANCE_V1, VETTO_ATTESTATION_BUILD_TYPE,
};
