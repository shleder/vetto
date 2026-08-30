# Windows Authenticode Code Signing Guide

This directory contains scripts and instructions for signing `vetto.exe` with Microsoft Authenticode digital signatures.

---

## 1. Prerequisites

1. **Authenticode Code Signing Certificate** (e.g. Sectigo, DigiCert, GlobalSign) exported as a password-protected `.pfx` file.
2. **Windows SDK** with `signtool.exe`, or `osslsigncode` on cross-platform runners.

---

## 2. Signing Command

Using the PowerShell signing script:
```powershell
$env:SIGNING_CERT_PFX = "[base64-encoded-pfx]"
$env:SIGNING_CERT_PASSWORD = "[cert-password]"

./packaging/windows/sign.ps1 -TargetPath "target/x86_64-pc-windows-msvc/release/vetto.exe"
```

Manual signing with `signtool.exe`:
```powershell
signtool.exe sign `
    /f "path\to\cert.pfx" `
    /p "password" `
    /fd SHA256 `
    /tr "http://timestamp.digicert.com" `
    /td SHA256 `
    /v `
    "target\release\vetto.exe"
```

Verifying signature:
```powershell
Get-AuthenticodeSignature -FilePath "target\release\vetto.exe"
```

---

## 3. GitHub Actions CI Secrets

In GitHub Actions, configure the following secrets:

| Secret Name | Description |
|---|---|
| `SIGNING_CERT_PFX` | Base64-encoded `.pfx` code signing certificate |
| `SIGNING_CERT_PASSWORD` | Password protecting the `.pfx` file |

If these secrets are not configured in the repository, the release pipeline cleanly skips signing and produces unsigned binaries, ensuring builds never fail due to missing credentials.
