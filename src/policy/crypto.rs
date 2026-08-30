//! Ed25519 cryptographic signing and verification for vetto policy files.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

pub const SIGNING_KEY_FILENAME: &str = "signing.key";
pub const VERIFYING_KEY_FILENAME: &str = "signing.pub";
pub const SIG_EXTENSION: &str = "sig";

/// Returns the default vetto config/signing directory (`~/.vetto`).
pub fn default_vetto_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("Unable to resolve home directory for signing keys")?;
    Ok(home.join(".vetto"))
}

/// Helper to convert bytes to a hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Helper to parse a hex string into bytes.
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>> {
    let hex_str = hex_str.trim();
    if hex_str.len() % 2 != 0 {
        bail!("invalid hex string length");
    }
    let mut bytes = Vec::with_capacity(hex_str.len() / 2);
    for i in (0..hex_str.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex_str[i..i + 2], 16)
            .map_err(|e| anyhow::anyhow!("invalid hex character: {e}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Ensures that a signing keypair exists at the given directory, generating one if missing.
pub fn ensure_signing_keypair(dir: &Path) -> Result<(SigningKey, VerifyingKey)> {
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;

    let priv_path = dir.join(SIGNING_KEY_FILENAME);
    let pub_path = dir.join(VERIFYING_KEY_FILENAME);

    if priv_path.is_file() {
        let raw = fs::read_to_string(&priv_path)
            .with_context(|| format!("failed to read private key from {}", priv_path.display()))?;
        let bytes = from_hex(&raw)?;
        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid private key length; expected 32 bytes"))?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();
        return Ok((signing_key, verifying_key));
    }

    // Generate new keypair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let priv_hex = to_hex(&signing_key.to_bytes());
    let pub_hex = to_hex(verifying_key.as_bytes());

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true).mode(0o600);
        let mut file = opts
            .open(&priv_path)
            .with_context(|| format!("failed to create private key at {}", priv_path.display()))?;
        use std::io::Write;
        file.write_all(priv_hex.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&priv_path, priv_hex.as_bytes())
            .with_context(|| format!("failed to create private key at {}", priv_path.display()))?;
    }

    fs::write(&pub_path, pub_hex.as_bytes())
        .with_context(|| format!("failed to create public key at {}", pub_path.display()))?;

    Ok((signing_key, verifying_key))
}

/// Loads a public verifying key from a given file path.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read public key from {}", path.display()))?;
    let bytes = from_hex(&raw)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public key length; expected 32 bytes"))?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|e| anyhow::anyhow!("invalid public key: {e}"))
}

/// Format of a policy signature file (.sig):
/// ```text
/// # VETTO POLICY SIGNATURE (ED25519)
/// # Public Key: <hex>
/// <sig_hex>
/// ```
pub fn create_signature_file_content(sig: &Signature, pubkey: &VerifyingKey) -> String {
    format!(
        "# VETTO POLICY SIGNATURE (ED25519)\n# Public Key: {}\n{}\n",
        to_hex(pubkey.as_bytes()),
        to_hex(&sig.to_bytes())
    )
}

/// Parses a `.sig` file to extract the Ed25519 signature and optional public key.
pub fn parse_signature_file(content: &str) -> Result<(Signature, Option<VerifyingKey>)> {
    let mut sig_hex = None;
    let mut pub_hex = None;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("# Public Key:") {
            let key_str = line.trim_start_matches("# Public Key:").trim();
            pub_hex = Some(key_str.to_string());
        } else if !line.starts_with('#') && !line.is_empty() {
            sig_hex = Some(line.to_string());
        }
    }

    let sig_str = sig_hex.ok_or_else(|| anyhow::anyhow!("missing signature in .sig file"))?;
    let sig_bytes = from_hex(&sig_str)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid signature length; expected 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_arr);

    let pubkey = if let Some(pk_str) = pub_hex {
        let bytes = from_hex(&pk_str)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid public key length in .sig header"))?;
        Some(
            VerifyingKey::from_bytes(&arr)
                .map_err(|e| anyhow::anyhow!("invalid public key in .sig: {e}"))?,
        )
    } else {
        None
    };

    Ok((signature, pubkey))
}

/// Signs a policy file and writes the signature to `<file>.sig` (or explicit output path).
pub fn sign_policy_file(
    file_path: &Path,
    custom_key: Option<&Path>,
    output_path: Option<&Path>,
) -> Result<PathBuf> {
    let signing_key = if let Some(kpath) = custom_key {
        let raw = fs::read_to_string(kpath)
            .with_context(|| format!("failed to read signing key from {}", kpath.display()))?;
        let bytes = from_hex(&raw)?;
        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid private key length; expected 32 bytes"))?;
        SigningKey::from_bytes(&key_bytes)
    } else {
        let dir = default_vetto_dir()?;
        let (k, _) = ensure_signing_keypair(&dir)?;
        k
    };

    let verifying_key = signing_key.verifying_key();
    let content = fs::read(file_path).with_context(|| {
        format!(
            "failed to read policy file for signing: {}",
            file_path.display()
        )
    })?;

    let signature = signing_key.sign(&content);
    let sig_text = create_signature_file_content(&signature, &verifying_key);

    let target_sig_path = output_path.map(PathBuf::from).unwrap_or_else(|| {
        let mut p = file_path.to_path_buf();
        let ext = p
            .extension()
            .map(|e| format!("{}.{}", e.to_string_lossy(), SIG_EXTENSION))
            .unwrap_or_else(|| SIG_EXTENSION.to_string());
        p.set_extension(ext);
        p
    });

    fs::write(&target_sig_path, sig_text.as_bytes())
        .with_context(|| format!("failed to write signature to {}", target_sig_path.display()))?;

    Ok(target_sig_path)
}

/// Verifies a policy file against its signature.
pub fn verify_policy_file(
    file_path: &Path,
    sig_path: Option<&Path>,
    pubkey_path: Option<&Path>,
) -> Result<()> {
    let content = fs::read(file_path)
        .with_context(|| format!("failed to read policy file: {}", file_path.display()))?;

    let resolved_sig_path = sig_path.map(PathBuf::from).unwrap_or_else(|| {
        let mut p = file_path.to_path_buf();
        let ext = p
            .extension()
            .map(|e| format!("{}.{}", e.to_string_lossy(), SIG_EXTENSION))
            .unwrap_or_else(|| SIG_EXTENSION.to_string());
        p.set_extension(ext);
        p
    });

    if !resolved_sig_path.is_file() {
        bail!("signature file not found: {}", resolved_sig_path.display());
    }

    let sig_text = fs::read_to_string(&resolved_sig_path).with_context(|| {
        format!(
            "failed to read signature from {}",
            resolved_sig_path.display()
        )
    })?;

    let (signature, embedded_pubkey) = parse_signature_file(&sig_text)?;

    let verifying_key = if let Some(pk_path) = pubkey_path {
        load_verifying_key(pk_path)?
    } else if let Some(embedded) = embedded_pubkey {
        // Also check against ~/.vetto/signing.pub if available
        if let Ok(dir) = default_vetto_dir() {
            let default_pub = dir.join(VERIFYING_KEY_FILENAME);
            if default_pub.is_file() {
                let local_pub = load_verifying_key(&default_pub)?;
                if local_pub != embedded {
                    bail!(
                        "signature was signed by key '{}' which does not match trusted key in {}",
                        to_hex(embedded.as_bytes()),
                        default_pub.display()
                    );
                }
            }
        }
        embedded
    } else {
        let dir = default_vetto_dir()?;
        let default_pub = dir.join(VERIFYING_KEY_FILENAME);
        if !default_pub.is_file() {
            bail!("no public key available to verify signature; specify --key or generate keypair with 'vetto policy sign'");
        }
        load_verifying_key(&default_pub)?
    };

    verifying_key
        .verify(&content, &signature)
        .map_err(|e| anyhow::anyhow!("policy signature verification failed: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation_and_signing() {
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key();

        let data = b"policy_data_test_payload";
        let sig = key.sign(data);
        assert!(pubkey.verify(data, &sig).is_ok());

        let wrong_data = b"modified_payload";
        assert!(pubkey.verify(wrong_data, &sig).is_err());
    }

    #[test]
    fn test_hex_conversion() {
        let bytes = vec![0x00, 0x01, 0x0a, 0xff, 0x42];
        let hex = to_hex(&bytes);
        assert_eq!(hex, "00010aff42");
        let decoded = from_hex(&hex).expect("from_hex");
        assert_eq!(bytes, decoded);
    }

    #[test]
    fn test_signature_file_format_roundtrip() {
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key();
        let sig = key.sign(b"sample");

        let text = create_signature_file_content(&sig, &pubkey);
        let (parsed_sig, parsed_pub) = parse_signature_file(&text).expect("parse sig");
        assert_eq!(sig, parsed_sig);
        assert_eq!(Some(pubkey), parsed_pub);
    }
}
