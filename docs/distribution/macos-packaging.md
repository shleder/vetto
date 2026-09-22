# macOS Packaging and Notarization

The `vetto` binary is distributed as a signed and notarized `.pkg` installer for macOS.

## Requirements
- Developer ID Installer certificate installed in your Keychain
- `APPLE_ID`, `APPLE_ID_PASSWORD` (App-Specific Password), and `APPLE_TEAM_ID` environment variables exported

## Usage
Run the packaging script from the repository root:
```bash
./scripts/package-macos-pkg.sh target/release/vetto "Developer ID Installer: My Company (TEAMID123)"
```

The script will:
1. Create a `component.pkg` using `pkgbuild`.
2. Create the final package using `productbuild`.
3. Sign the package with `productsign`.
4. Upload it to Apple's notarization service with `xcrun notarytool submit --wait`.
5. Staple the notarization ticket with `xcrun stapler staple`.
