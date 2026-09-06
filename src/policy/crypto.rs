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
    if !hex_str.is_ascii() {
        bail!("invalid hex character: non-ascii input");
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
    let mut sig_hex: Option<String> = None;
    let mut pub_hex: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("# Public Key:") {
            if pub_hex.is_some() {
                bail!("duplicate public key header in .sig file");
            }
            pub_hex = Some(rest.trim().to_string());
        } else if !line.starts_with('#') && !line.is_empty() {
            if sig_hex.is_some() {
                bail!("multiple signature lines in .sig file");
            }
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

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }

        fn below(&mut self, bound: u64) -> u64 {
            if bound == 0 {
                0
            } else {
                self.next() % bound
            }
        }
    }

    fn pick_hex_piece(rng: &mut Lcg) -> &'static str {
        match rng.below(10) {
            0 => "00",
            1 => "ab",
            2 => "zz",
            3 => " ",
            4 => "€",
            5 => "😀",
            6 => "é",
            7 => "#",
            8 => ":",
            _ => "\n",
        }
    }

    fn pick_line_kind(rng: &mut Lcg) -> u64 {
        rng.below(5)
    }

    #[test]
    fn prop_hex_roundtrip_random_bytes() {
        let mut rng = Lcg(0x1234_5678_9abc_def0);
        for _ in 0..256 {
            let len = rng.below(65) as usize;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push(rng.below(256) as u8);
            }
            let hex = to_hex(&bytes);
            let back = from_hex(&hex).expect("roundtrip must succeed");
            assert_eq!(bytes, back);
        }
    }

    #[test]
    fn prop_from_hex_never_panics_on_garbage() {
        for bad in ["€€", "😀", "éé", "a€b€", "\u{feff}ab", "zz", "abc", ""] {
            let res = from_hex(bad);
            assert!(res.is_err(), "input {bad:?} must be Err");
        }
        let mut rng = Lcg(0xdead_beef_cafe_f00d);
        for _ in 0..512 {
            let mut s = String::new();
            let n = rng.below(4) as usize;
            for _ in 0..n {
                s.push_str(pick_hex_piece(&mut rng));
            }
            let res = from_hex(&s);
            if res.is_ok() {
                assert_eq!(s.trim().len() % 2, 0);
                assert!(s.trim().is_ascii());
            }
        }
    }

    #[test]
    fn prop_parse_sig_rejects_truncated_and_bad_lengths() {
        let short_sig = "ab".to_string();
        let sig_63 = "ab".repeat(63);
        let sig_65 = "ab".repeat(65);
        let cases = [
            "",
            "   \n  \n",
            "# VETTO POLICY SIGNATURE (ED25519)\n",
            "zz\n",
            "abc\n",
            "# comment\nzz\n",
        ];
        for c in cases {
            assert!(parse_signature_file(c).is_err(), "case {c:?} must fail");
        }
        assert!(parse_signature_file(&short_sig).is_err());
        assert!(parse_signature_file(&sig_63).is_err());
        assert!(parse_signature_file(&sig_65).is_err());
        assert!(parse_signature_file("gg").is_err());
    }

    #[test]
    fn prop_parse_sig_rejects_trailing_garbage() {
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key();
        let sig = key.sign(b"prop-input");
        let valid = create_signature_file_content(&sig, &pubkey);
        let sig_hex = to_hex(&sig.to_bytes());
        let pub_hex = to_hex(pubkey.as_bytes());
        let with_extra_sig = format!("{valid}{sig_hex}\n");
        assert!(parse_signature_file(&with_extra_sig).is_err());
        let with_extra_line = format!("{valid}extra-garbage-line\n");
        assert!(parse_signature_file(&with_extra_line).is_err());
        let mut dup_pub = String::from("# VETTO POLICY SIGNATURE (ED25519)\n");
        dup_pub.push_str("# Public Key: ");
        dup_pub.push_str(&pub_hex);
        dup_pub.push_str("\n# Public Key: ");
        dup_pub.push_str(&pub_hex);
        dup_pub.push('\n');
        dup_pub.push_str(&sig_hex);
        dup_pub.push('\n');
        assert!(parse_signature_file(&dup_pub).is_err());
        assert!(parse_signature_file(&valid).is_ok());
    }

    #[test]
    fn prop_parse_sig_fuzz_no_panic() {
        let mut rng = Lcg(0x9e37_79b9_7f4a_7c15);
        for _ in 0..512 {
            let mut s = String::new();
            let lines = rng.below(4) as usize;
            for _ in 0..lines {
                match pick_line_kind(&mut rng) {
                    0 => {
                        s.push_str("# comment\n");
                    }
                    1 => {
                        s.push_str("# Public Key: ");
                        s.push_str(pick_hex_piece(&mut rng));
                        s.push('\n');
                    }
                    2 => {
                        s.push_str(pick_hex_piece(&mut rng));
                        s.push('\n');
                    }
                    3 => {
                        s.push_str("ab00ff\n");
                    }
                    _ => {
                        s.push('\n');
                    }
                }
            }
            if let Ok((sig, _)) = parse_signature_file(&s) {
                assert_eq!(to_hex(&sig.to_bytes()).len(), 128);
            }
        }
    }
}
