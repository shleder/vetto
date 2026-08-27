#!/usr/bin/env sh
set -e

REPO="shleder/vetto"
VERSION="${VETTO_VERSION:-latest}"

echo "==> Detecting architecture and operating system..."
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64|amd64) TARGET="vetto-linux-x86_64.tar.gz" ;;
            aarch64|arm64) TARGET="vetto-linux-aarch64.tar.gz" ;;
            *) echo "Unsupported Linux architecture: $ARCH" >&2; exit 1 ;;
        esac
        ;;
    Darwin)
        case "$ARCH" in
            x86_64) TARGET="vetto-macos-x86_64.tar.gz" ;;
            arm64|aarch64) TARGET="vetto-macos-aarch64.tar.gz" ;;
            *) echo "Unsupported macOS architecture: $ARCH" >&2; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $OS (Windows users please use: npm i -g @shledery/vetto)" >&2
        exit 1
        ;;
esac

if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${TARGET}"
else
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION#v}/${TARGET}"
fi

INSTALL_DIR="${VETTO_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

echo "==> Downloading Vetto from $DOWNLOAD_URL..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/vetto.tar.gz"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_DIR/vetto.tar.gz" "$DOWNLOAD_URL"
else
    echo "Error: curl or wget is required." >&2
    exit 1
fi

echo "==> Extracting binary..."
tar -xzf "$TMP_DIR/vetto.tar.gz" -C "$TMP_DIR"
chmod +x "$TMP_DIR/vetto"
mv "$TMP_DIR/vetto" "$INSTALL_DIR/vetto"

echo "==> Vetto successfully installed to $INSTALL_DIR/vetto"

if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo ""
    echo "Note: $INSTALL_DIR is not in your PATH. Add it with:"
    echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
fi

echo ""
echo "Run 'vetto doctor' to verify host kernel sandboxing capabilities."
