# Policy-as-Code Cryptographic Signatures (Ed25519)

To guarantee policy supply-chain integrity and prevent untrusted agents or repository pull requests from weakening sandbox policies, Vetto supports **cryptographic Ed25519 policy signing and verification**.

---

## 1. Keypair Management

Keypairs are stored in `~/.vetto/`:
- `~/.vetto/signing.key`: 32-byte Ed25519 private key (`0600` permissions).
- `~/.vetto/signing.pub`: 32-byte Ed25519 public key (`0644` permissions).

Keys are automatically generated on the first invocation of `vetto policy sign`.

---

## 2. Signing a Policy File

To sign a policy file (e.g. `vetto.toml`):

```bash
vetto policy sign vetto.toml
```

This generates `vetto.toml.sig` with the following structure:
```text
# VETTO POLICY SIGNATURE (ED25519)
# Public Key: <64-character hex public key>
<128-character hex Ed25519 signature>
```

---

## 3. Verifying a Policy Signature

```bash
vetto policy verify vetto.toml --sig vetto.toml.sig
```

If the policy has been modified after signing or if the signature does not match the trusted public key, verification immediately fails non-zero.

---

## 4. Enforcing Signed Policies in Organizations (`require_signed`)

To require that all loaded project policies and fragments are cryptographically signed, configure `require_signed = true` in the system global policy (`/etc/vetto/policy.toml`) or project policy:

```toml
[security]
immutable = true
require_signed = true
```

When `require_signed = true` is active, the policy loader refuses to evaluate any unsigned or tampered policy file.
