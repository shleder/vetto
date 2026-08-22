//! Endpoint Security framework — stub, NOT implemented, NOT claimed.
//!
//! ES requires a signed binary with a special Apple entitlement that CLI
//! tools cannot obtain without notarization + entitlement approval. vetto
//! does not use ES in v0.1 and does not claim to.

pub fn status() -> &'static str {
    "Endpoint Security framework: not implemented in v0.1 (requires an entitled, \
     Apple-approved binary); sandbox-exec is used instead"
}
