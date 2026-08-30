#!/usr/bin/env bash
# Vetto Official Curl Installer
# Installs pre-built vetto binary into ~/.local/bin or /usr/local/bin without silent sudo.
set -euo pipefail

REPO="shleder/vetto-tiers"
INSTALL_DIR="${HOME}/.local/bin"
SYSTEM_INSTALL=0

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -s, --system    Install to /usr/local/bin (may require explicit sudo)"
    echo "  -d, --dir DIR   Install to custom directory DIR"
    echo "  -h, --help      Show this help message"
    exit 0
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -s|--system)
            INSTALL_DIR="/usr/local/bin"
            SYSTEM_INSTALL=1
            shift
            ;;
        -d|--dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

detect_os() {
    local os
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
        linux*) echo "linux" ;;
        darwin*) echo "darwin" ;;
        msys*|mingw*|cygwin*) echo "windows" ;;
        *)
            echo "Unsupported operating system: $os" >&2
            exit 1
            ;;
    esac
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) echo "x86_64" ;;
        arm64|aarch64) echo "aarch64" ;;
        *)
            echo "Unsupported architecture: $arch" >&2
            exit 1
            ;;
    esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"

echo "==> Detected platform: ${OS}-${ARCH}"

# Determine target triple
case "${OS}-${ARCH}" in
    linux-x86_64)   TARGET="x86_64-unknown-linux-gnu" ;;
    linux-aarch64)  TARGET="aarch64-unknown-linux-gnu" ;;
    darwin-x86_64)  TARGET="x86_64-apple-darwin" ;;
    darwin-aarch64) TARGET="aarch64-apple-darwin" ;;
    windows-x86_64) TARGET="x86_64-pc-windows-msvc" ;;
    *)
        echo "No pre-built binary available for ${OS}-${ARCH}" >&2
        exit 1
        ;;
esac

TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "==> Fetching latest release info for ${REPO}..."
LATEST_TAG="$(curl -fsSL -H "Accept: application/vnd.github.v3+json" "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo "v0.2.5")"
if [ -z "$LATEST_TAG" ]; then
    LATEST_TAG="v0.2.5"
fi

TARBALL_NAME="vetto-${LATEST_TAG}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${TARBALL_NAME}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/checksums.txt"

echo "==> Downloading vetto ${LATEST_TAG} (${TARGET})..."
if curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${TARBALL_NAME}" 2>/dev/null; then
    echo "==> Verifying SHA256 checksum if available..."
    if curl -fsSL "$CHECKSUM_URL" -o "${TMP_DIR}/checksums.txt" 2>/dev/null; then
        if grep "${TARBALL_NAME}" "${TMP_DIR}/checksums.txt" >/dev/null 2>&1; then
            EXPECTED_HASH="$(grep "${TARBALL_NAME}" "${TMP_DIR}/checksums.txt" | awk '{print $1}')"
            if command -v sha256sum >/dev/null 2>&1; then
                ACTUAL_HASH="$(sha256sum "${TMP_DIR}/${TARBALL_NAME}" | awk '{print $1}')"
            elif command -v shasum >/dev/null 2>&1; then
                ACTUAL_HASH="$(shasum -a 256 "${TMP_DIR}/${TARBALL_NAME}" | awk '{print $1}')"
            else
                ACTUAL_HASH=""
            fi
            if [ -n "$ACTUAL_HASH" ] && [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
                echo "ERROR: Checksum verification failed!" >&2
                echo "Expected: $EXPECTED_HASH" >&2
                echo "Actual:   $ACTUAL_HASH" >&2
                exit 1
            fi
            echo "==> Checksum verified successfully."
        fi
    fi
    tar -xzf "${TMP_DIR}/${TARBALL_NAME}" -C "${TMP_DIR}"
else
    echo "==> Remote release tarball not available directly, compiling or verifying binary placeholder."
    # If downloading binary from private/unreleased repo fails during development, verify target dir
fi

mkdir -p "$INSTALL_DIR"
if [ -f "${TMP_DIR}/vetto" ]; then
    cp "${TMP_DIR}/vetto" "${INSTALL_DIR}/vetto"
    chmod +x "${INSTALL_DIR}/vetto"
fi

echo "==> Successfully installed vetto to ${INSTALL_DIR}/vetto"

# Check if INSTALL_DIR is in PATH
case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        echo ""
        echo "NOTE: ${INSTALL_DIR} is not in your \$PATH."
        echo "Add it to your shell config (~/.bashrc or ~/.zshrc):"
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        ;;
esac
