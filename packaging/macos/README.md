# macOS Packaging and Apple Notarization Guide

This directory provides tools and instructions to package `vetto` as a native macOS installer package (`.pkg`), sign it with an Apple Developer ID certificate, notarize it with Apple's notary service, and staple the notarization ticket for offline Gatekeeper verification.

---

## 1. Prerequisites

1. **Apple Developer Account** enrolled in Apple Developer Program.
2. **Developer ID Certificates**:
   - `Developer ID Application: Your Name/Org (TEAM_ID)`: used to codesign the `vetto` binary with Hardened Runtime (`--options runtime`).
   - `Developer ID Installer: Your Name/Org (TEAM_ID)`: used to sign the `.pkg` installer.
3. **App-Specific Password**: generated on [appleid.apple.com](https://appleid.apple.com) for notarytool access.

---

## 2. Packaging Pipeline

The packaging workflow consists of:
1. **Compiling the release binary** (`cargo build --release`).
2. **Code Signing** the binary with Hardened Runtime and secure timestamp:
   ```bash
   codesign --force --options runtime --timestamp \
       --sign "Developer ID Application: YOUR_NAME (TEAM_ID)" \
       target/release/vetto
   ```
3. **Building the `.pkg` installer** using `pkgbuild`:
   ```bash
   ./packaging/macos/build_pkg.sh 0.2.5 aarch64-apple-darwin
   ```
4. **Submitting for Notarization** via `xcrun notarytool`:
   ```bash
   xcrun notarytool submit target/pkg_out/vetto-0.2.5-aarch64-apple-darwin.pkg \
       --apple-id "developer@example.com" \
       --team-id "TEAM_ID" \
       --password "abcd-efgh-ijkl-mnop" \
       --wait
   ```
5. **Stapling the Ticket**:
   ```bash
   xcrun stapler staple target/pkg_out/vetto-0.2.5-aarch64-apple-darwin.pkg
   ```
6. **Verifying with Gatekeeper**:
   ```bash
   spctl --assess --type install --verbose target/pkg_out/vetto-0.2.5-aarch64-apple-darwin.pkg
   ```

---

## 3. GitHub Actions CI Secrets

To automate signing and notarization in GitHub Actions, configure the following repository secrets:

| Secret Name | Description |
|---|---|
| `MACOS_CERTIFICATE_P12` | Base64-encoded `.p12` containing Developer ID Application and Installer certificates |
| `MACOS_CERTIFICATE_PASSWORD` | Password for the `.p12` file |
| `DEVELOPER_ID_APPLICATION` | Certificate name, e.g. `Developer ID Application: Team Name (TEAM_ID)` |
| `DEVELOPER_ID_INSTALLER` | Installer certificate name, e.g. `Developer ID Installer: Team Name (TEAM_ID)` |
| `APPLE_ID` | Apple ID email associated with the Developer account |
| `APPLE_TEAM_ID` | 10-character Apple Developer Team ID |
| `APP_SPECIFIC_PASSWORD` | App-specific password for notarytool |

When secrets are omitted, the build script cleanly skips code signing and notarization, producing unsigned artifacts for local testing without breaking CI.
