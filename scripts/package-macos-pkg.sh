#!/usr/bin/env bash
set -eEuo pipefail

echo "==> Packaging macOS .pkg and notarizing"

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <binary_path> <developer_id_installer>"
    exit 1
fi

BINARY_PATH="$1"
DEVELOPER_ID="$2"
APP_NAME="vetto"
IDENTIFIER="com.shleder.vetto"
VERSION=$(./"$BINARY_PATH" --version | awk '{print $2}')
ROOT_DIR="packaging/macos-root"
PKG_OUTPUT="vetto-${VERSION}-macos.pkg"
SIGNED_PKG_OUTPUT="vetto-${VERSION}-macos-signed.pkg"

# Create package root
echo "==> Creating root layout"
mkdir -p "$ROOT_DIR/usr/local/bin"
cp "$BINARY_PATH" "$ROOT_DIR/usr/local/bin/$APP_NAME"
chmod 755 "$ROOT_DIR/usr/local/bin/$APP_NAME"

# Build component package
echo "==> Building component package"
pkgbuild --root "$ROOT_DIR" \
         --identifier "$IDENTIFIER" \
         --version "$VERSION" \
         --install-location "/" \
         "component.pkg"

# Build product package
echo "==> Building product package"
productbuild --package "component.pkg" "$PKG_OUTPUT"

# Sign package
echo "==> Signing package with $DEVELOPER_ID"
productsign --sign "$DEVELOPER_ID" "$PKG_OUTPUT" "$SIGNED_PKG_OUTPUT"

# Notarize
if [[ -n "${APPLE_ID:-}" && -n "${APPLE_ID_PASSWORD:-}" && -n "${APPLE_TEAM_ID:-}" ]]; then
    echo "==> Submitting for notarization"
    xcrun notarytool submit "$SIGNED_PKG_OUTPUT" \
        --apple-id "$APPLE_ID" \
        --password "$APPLE_ID_PASSWORD" \
        --team-id "$APPLE_TEAM_ID" \
        --wait
        
    echo "==> Stapling ticket"
    xcrun stapler staple "$SIGNED_PKG_OUTPUT"
else
    echo "==> Skipping notarization (missing APPLE_ID, APPLE_ID_PASSWORD, or APPLE_TEAM_ID)"
fi

echo "==> Done. $SIGNED_PKG_OUTPUT is ready."
