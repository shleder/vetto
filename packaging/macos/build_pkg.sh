#!/usr/bin/env bash
# packaging/macos/build_pkg.sh
# Builds a signed and notarized macOS installer package (.pkg) for vetto.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

VERSION="${1:-0.2.5}"
TARGET="${2:-aarch64-apple-darwin}"
BUILD_DIR="${REPO_ROOT}/target/${TARGET}/release"
BIN_SRC="${BUILD_DIR}/vetto"
PKG_ROOT="${REPO_ROOT}/target/pkg_root"
OUTPUT_DIR="${REPO_ROOT}/target/pkg_out"
OUTPUT_PKG="${OUTPUT_DIR}/vetto-${VERSION}-${TARGET}.pkg"

echo "==> Building macOS package for vetto v${VERSION} (${TARGET})"

if [[ ! -f "${BIN_SRC}" ]]; then
    # Check if universal or host target binary exists
    if [[ -f "${REPO_ROOT}/target/release/vetto" ]]; then
        BIN_SRC="${REPO_ROOT}/target/release/vetto"
    else
        echo "Error: Binary not found at ${BIN_SRC} or ${REPO_ROOT}/target/release/vetto"
        exit 1
    fi
fi

# Clean and prepare payload directory
rm -rf "${PKG_ROOT}" "${OUTPUT_DIR}"
mkdir -p "${PKG_ROOT}/usr/local/bin" "${OUTPUT_DIR}"
cp "${BIN_SRC}" "${PKG_ROOT}/usr/local/bin/vetto"
chmod 755 "${PKG_ROOT}/usr/local/bin/vetto"

# Codesign binary if Developer ID Application certificate is available
if [[ -n "${DEVELOPER_ID_APPLICATION:-}" ]]; then
    echo "==> Signing binary with Developer ID Application: ${DEVELOPER_ID_APPLICATION}"
    codesign --force --options runtime --timestamp --sign "${DEVELOPER_ID_APPLICATION}" "${PKG_ROOT}/usr/local/bin/vetto"
    codesign --verify --verbose "${PKG_ROOT}/usr/local/bin/vetto"
else
    echo "==> Skipping binary codesign (DEVELOPER_ID_APPLICATION not set)"
fi

# Build component package with pkgbuild
echo "==> Building package with pkgbuild"
if [[ -n "${DEVELOPER_ID_INSTALLER:-}" ]]; then
    pkgbuild \
        --root "${PKG_ROOT}" \
        --identifier "dev.vetto.cli" \
        --version "${VERSION}" \
        --install-location "/" \
        --sign "${DEVELOPER_ID_INSTALLER}" \
        --timestamp \
        "${OUTPUT_PKG}"
else
    pkgbuild \
        --root "${PKG_ROOT}" \
        --identifier "dev.vetto.cli" \
        --version "${VERSION}" \
        --install-location "/" \
        "${OUTPUT_PKG}"
fi

echo "==> Created package at: ${OUTPUT_PKG}"

# Notarize if Apple credentials are provided
if [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APP_SPECIFIC_PASSWORD:-}" ]]; then
    echo "==> Submitting package for notarization via notarytool"
    xcrun notarytool submit "${OUTPUT_PKG}" \
        --apple-id "${APPLE_ID}" \
        --team-id "${APPLE_TEAM_ID}" \
        --password "${APP_SPECIFIC_PASSWORD}" \
        --wait

    echo "==> Stapling notarization ticket to package"
    xcrun stapler staple "${OUTPUT_PKG}"
    spctl --assess --type install --verbose "${OUTPUT_PKG}" || true
    echo "==> Package notarized and stapled successfully!"
else
    echo "==> Skipping Apple notarization (APPLE_ID/APPLE_TEAM_ID/APP_SPECIFIC_PASSWORD not set)"
fi
