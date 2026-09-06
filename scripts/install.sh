#!/bin/sh
# Vetto Universal Installer
# https://github.com/shleder/vetto
#
# Production-grade POSIX installer with architecture autodetection,
# SHA256 integrity verification, and zero silent privilege escalation.

set -eu

GITHUB_REPO="shleder/vetto"
DEFAULT_FALLBACK_VERSION="0.2.13"

# Initialize colors if stdout is connected to a terminal
if [ -t 1 ]; then
    COLOR_BOLD="$(printf '\033[1m')"
    COLOR_GREEN="$(printf '\033[1;32m')"
    COLOR_CYAN="$(printf '\033[1;36m')"
    COLOR_YELLOW="$(printf '\033[1;33m')"
    COLOR_RED="$(printf '\033[1;31m')"
    COLOR_RESET="$(printf '\033[0m')"
else
    COLOR_BOLD=""
    COLOR_GREEN=""
    COLOR_CYAN=""
    COLOR_YELLOW=""
    COLOR_RED=""
    COLOR_RESET=""
fi

info() {
    printf "%s==>%s %s\n" "${COLOR_CYAN}" "${COLOR_RESET}" "$1"
}

warn() {
    printf "%sWarning:%s %s\n" "${COLOR_YELLOW}" "${COLOR_RESET}" "$1" >&2
}

err() {
    printf "%sError:%s %s\n" "${COLOR_RED}" "${COLOR_RESET}" "$1" >&2
}

show_help() {
    cat <<EOF
Vetto Universal Installer

Usage:
  curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
  sh install.sh [OPTIONS]

Options:
  -d, --dir DIR          Install binary into custom directory DIR
  -s, --system           Install system-wide to /usr/local/bin
  -v, --version VERSION  Install specific Vetto version (e.g. 0.2.11)
  -h, --help             Show this help message

Environment Variables:
  VETTO_VERSION          Specific version to install (defaults to latest release)
  VETTO_INSTALL_DIR      Target directory for installation
  XDG_BIN_HOME           Fallback user binary directory (default: \$HOME/.local/bin)
EOF
}

# Parse command line arguments
CUSTOM_DIR=""
SYSTEM_INSTALL=0
VERSION_OVERRIDE=""

while [ $# -gt 0 ]; do
    case "$1" in
        -d|--dir)
            if [ $# -lt 2 ]; then
                err "Option '$1' requires a directory path argument."
                exit 1
            fi
            CUSTOM_DIR="$2"
            shift 2
            ;;
        --dir=*)
            CUSTOM_DIR="${1#*=}"
            shift
            ;;
        -s|--system)
            SYSTEM_INSTALL=1
            shift
            ;;
        -v|--version)
            if [ $# -lt 2 ]; then
                err "Option '$1' requires a version argument."
                exit 1
            fi
            VERSION_OVERRIDE="$2"
            shift 2
            ;;
        --version=*)
            VERSION_OVERRIDE="${1#*=}"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            err "Unknown option: $1"
            show_help >&2
            exit 1
            ;;
    esac
done

# Step 1: Detect Operating System
detect_os() {
    _raw_os="$(uname -s 2>/dev/null || echo "unknown")"
    case "$_raw_os" in
        Linux*|linux*)
            echo "linux"
            ;;
        Darwin*|darwin*)
            echo "macos"
            ;;
        CYGWIN*|MINGW*|MSYS*|Windows*|windows*)
            err "Windows POSIX shells are not directly supported by this installer."
            printf "\nTo install Vetto on Windows, please choose one of the following:\n" >&2
            printf "  • Cargo:   cargo install vetto\n" >&2
            printf "  • npm:     npm install -g @shledery/vetto\n" >&2
            printf "  • GitHub:  Download vetto-windows-x86_64.zip from https://github.com/%s/releases\n" "$GITHUB_REPO" >&2
            exit 1
            ;;
        *)
            err "Unsupported operating system '$_raw_os'."
            printf "Vetto distributes official pre-built binaries for Linux and macOS.\n" >&2
            printf "You can compile from source with: cargo install vetto\n" >&2
            exit 1
            ;;
    esac
}

# Step 2: Detect Architecture
detect_arch() {
    _raw_arch="$(uname -m 2>/dev/null || echo "unknown")"
    case "$_raw_arch" in
        x86_64|amd64)
            echo "x86_64"
            ;;
        aarch64|arm64)
            echo "aarch64"
            ;;
        *)
            err "Unsupported CPU architecture '$_raw_arch'."
            printf "Pre-built binaries are available for x86_64 and aarch64.\n" >&2
            printf "You can compile from source with: cargo install vetto\n" >&2
            exit 1
            ;;
    esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
TARGET="${OS}-${ARCH}"

# Validate target matching
case "$TARGET" in
    linux-x86_64|linux-aarch64|macos-x86_64|macos-aarch64) ;;
    *)
        err "Target platform '${TARGET}' is not supported for binary installation."
        exit 1
        ;;
esac

# Step 3: Resolve Target Version
resolve_version() {
    # Check CLI argument override first, then environment variable
    _req_version="${VERSION_OVERRIDE:-${VETTO_VERSION:-}}"
    if [ -n "$_req_version" ]; then
        echo "${_req_version#v}"
        return 0
    fi

    # Query GitHub Releases API for the latest release tag
    _api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    _api_response=""
    if command -v curl >/dev/null 2>&1; then
        _api_response="$(curl -fsSL -H "Accept: application/vnd.github.v3+json" -H "User-Agent: vetto-installer" "$_api_url" 2>/dev/null || true)"
    elif command -v wget >/dev/null 2>&1; then
        _api_response="$(wget -qO- --header="Accept: application/vnd.github.v3+json" --header="User-Agent: vetto-installer" "$_api_url" 2>/dev/null || true)"
    fi

    _tag=""
    if [ -n "$_api_response" ]; then
        _tag="$(printf '%s\n' "$_api_response" | grep '"tag_name":' | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/' | head -n 1)"
    fi

    if [ -n "$_tag" ]; then
        echo "${_tag#v}"
    else
        echo "$DEFAULT_FALLBACK_VERSION"
    fi
}

VERSION="$(resolve_version)"
TAG="v${VERSION}"

# Step 4: Determine Installation Path
if [ -n "$CUSTOM_DIR" ]; then
    INSTALL_DIR="$CUSTOM_DIR"
elif [ "$SYSTEM_INSTALL" -eq 1 ]; then
    INSTALL_DIR="/usr/local/bin"
elif [ -n "${VETTO_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="$VETTO_INSTALL_DIR"
elif [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
fi

# Normalize trailing slash
if [ "$INSTALL_DIR" != "/" ]; then
    INSTALL_DIR="${INSTALL_DIR%/}"
fi

# Setup cleanup trap for temporary directory and staging files
TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'vetto-install.XXXXXX')"
STAGE_FILE=""

cleanup() {
    _status=$?
    trap - EXIT INT TERM HUP
    if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
    if [ -n "${STAGE_FILE:-}" ] && [ -f "$STAGE_FILE" ]; then
        rm -f "$STAGE_FILE"
    fi
    exit "$_status"
}
trap cleanup EXIT INT TERM HUP

# Download helper functions
download_file() {
    _src_url="$1"
    _dest_file="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$_src_url" -o "$_dest_file"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$_dest_file" "$_src_url"
    else
        err "Neither curl nor wget was found in PATH."
        exit 1
    fi
}

download_file_optional() {
    _src_url="$1"
    _dest_file="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$_src_url" -o "$_dest_file" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$_dest_file" "$_src_url" 2>/dev/null
    else
        return 1
    fi
}

compute_sha256() {
    _target_file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$_target_file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$_target_file" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$_target_file" | sed -e 's/.*= *//'
    else
        err "SHA256 verification requires sha256sum, shasum, or openssl."
        exit 1
    fi
}

TARBALL_NAME="vetto-${TARGET}.tar.gz"
TARBALL_URL="https://github.com/${GITHUB_REPO}/releases/download/${TAG}/${TARBALL_NAME}"
SHA_URL="https://github.com/${GITHUB_REPO}/releases/download/${TAG}/${TARBALL_NAME}.sha256"
CHECKSUMS_URL="https://github.com/${GITHUB_REPO}/releases/download/${TAG}/checksums.txt"

TARBALL_DEST="${TMP_DIR}/${TARBALL_NAME}"
CHECKSUM_DEST="${TMP_DIR}/checksum.txt"

info "Downloading Vetto ${TAG} for ${TARGET}..."
if ! download_file "$TARBALL_URL" "$TARBALL_DEST"; then
    err "Failed to download release archive from: $TARBALL_URL"
    printf "Please verify that release %s exists and has published binaries.\n" "$TAG" >&2
    printf "Check releases at: https://github.com/%s/releases\n" "$GITHUB_REPO" >&2
    exit 1
fi

info "Fetching SHA256 checksum for verification..."
has_checksum=0
if download_file_optional "$SHA_URL" "$CHECKSUM_DEST"; then
    has_checksum=1
elif download_file_optional "$CHECKSUMS_URL" "$CHECKSUM_DEST"; then
    has_checksum=1
fi

if [ "$has_checksum" -ne 1 ]; then
    err "Could not download checksum file from either $SHA_URL or $CHECKSUMS_URL."
    exit 1
fi

# Parse expected checksum
if grep -F "$TARBALL_NAME" "$CHECKSUM_DEST" >/dev/null 2>&1; then
    EXPECTED_RAW="$(grep -F "$TARBALL_NAME" "$CHECKSUM_DEST" | head -n 1 | awk '{print $1}')"
else
    EXPECTED_RAW="$(head -n 1 "$CHECKSUM_DEST" | awk '{print $1}')"
fi

EXPECTED_HASH="$(printf '%s' "$EXPECTED_RAW" | tr '[:upper:]' '[:lower:]' | tr -cd '0-9a-f')"

if [ "${#EXPECTED_HASH}" -ne 64 ]; then
    err "Invalid or unparseable SHA256 checksum format: '${EXPECTED_RAW}'"
    exit 1
fi

ACTUAL_RAW="$(compute_sha256 "$TARBALL_DEST")"
ACTUAL_HASH="$(printf '%s' "$ACTUAL_RAW" | tr '[:upper:]' '[:lower:]' | tr -cd '0-9a-f')"

if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
    err "SHA256 checksum verification failed!"
    printf "  Archive:  %s\n" "$TARBALL_NAME" >&2
    printf "  Expected: %s\n" "$EXPECTED_HASH" >&2
    printf "  Computed: %s\n" "$ACTUAL_HASH" >&2
    printf "Installation aborted for security. The downloaded archive may be corrupted or tampered with.\n" >&2
    exit 1
fi
info "Checksum verified: ${ACTUAL_HASH}"

# Step 5: Unpack archive
info "Extracting binary..."
tar -xzf "$TARBALL_DEST" -C "$TMP_DIR"

if [ -f "$TMP_DIR/vetto" ]; then
    EXTRACTED_BIN="$TMP_DIR/vetto"
elif [ -f "$TMP_DIR/bin/vetto" ]; then
    EXTRACTED_BIN="$TMP_DIR/bin/vetto"
else
    EXTRACTED_BIN="$(find "$TMP_DIR" -maxdepth 2 -type f -name "vetto" 2>/dev/null | head -n 1)"
fi

if [ -z "${EXTRACTED_BIN:-}" ] || [ ! -f "$EXTRACTED_BIN" ]; then
    err "Executable 'vetto' not found inside unpacked archive."
    exit 1
fi

chmod 0755 "$EXTRACTED_BIN"

# Step 6: Atomic Installation to Destination Path
info "Installing to ${INSTALL_DIR}/vetto..."
if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
    err "Failed to create directory '${INSTALL_DIR}'."
    printf "Try running with elevated permissions (e.g. sudo) or specify a user directory with --dir.\n" >&2
    exit 1
fi

STAGE_FILE="${INSTALL_DIR}/.vetto.tmp.$$"
if ! cp "$EXTRACTED_BIN" "$STAGE_FILE" 2>/dev/null; then
    err "Failed to write to destination directory '${INSTALL_DIR}'."
    printf "Try running with elevated permissions (e.g. sudo) or specify a user directory with --dir.\n" >&2
    exit 1
fi

chmod 0755 "$STAGE_FILE"

if ! mv -f "$STAGE_FILE" "${INSTALL_DIR}/vetto" 2>/dev/null; then
    rm -f "$STAGE_FILE"
    STAGE_FILE=""
    err "Failed to install '${INSTALL_DIR}/vetto'."
    printf "Try running with elevated permissions (e.g. sudo).\n" >&2
    exit 1
fi
STAGE_FILE=""

# Step 7: PATH Check & Advice
in_path=0
case ":$PATH:" in
    *":$INSTALL_DIR:"*|*":$INSTALL_DIR/:"*)
        in_path=1
        ;;
esac

if [ "$in_path" -eq 0 ]; then
    user_shell="$(basename "${SHELL:-sh}" 2>/dev/null || echo "sh")"
    printf "\n"
    warn "${INSTALL_DIR} is not in your \$PATH."
    printf "To execute 'vetto' from anywhere, add it to your shell configuration:\n\n"
    case "$user_shell" in
        zsh)
            printf "  echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc\n" "$INSTALL_DIR"
            printf "  source ~/.zshrc\n\n"
            ;;
        bash)
            printf "  echo 'export PATH=\"%s:\$PATH\"' >> ~/.bashrc\n" "$INSTALL_DIR"
            printf "  source ~/.bashrc\n\n"
            ;;
        fish)
            printf "  fish_add_path %s\n\n" "$INSTALL_DIR"
            ;;
        *)
            printf "  For bash:\n"
            printf "    echo 'export PATH=\"%s:\$PATH\"' >> ~/.bashrc && source ~/.bashrc\n" "$INSTALL_DIR"
            printf "  For zsh:\n"
            printf "    echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc && source ~/.zshrc\n\n"
            ;;
    esac
    printf "Or run directly: %s/vetto\n" "$INSTALL_DIR"
fi

# Step 8: Welcome & Next Steps Banner
printf "\n"
printf "%s✓ Vetto installed successfully to %s/vetto%s\n\n" "${COLOR_GREEN}" "$INSTALL_DIR" "${COLOR_RESET}"
printf "%sQuick start: vetto enable claude%s\n\n" "${COLOR_BOLD}" "${COLOR_RESET}"
printf "Next steps:\n"
printf "  • Enable agent sandbox:     %svetto enable claude%s (or codex / gemini)\n" "${COLOR_CYAN}" "${COLOR_RESET}"
printf "  • Run agent normally:       %sclaude%s (automatically sandboxed)\n" "${COLOR_CYAN}" "${COLOR_RESET}"
printf "  • Preflight health check:   %svetto doctor%s\n" "${COLOR_CYAN}" "${COLOR_RESET}"
printf "  • Interactive sandbox tour: %svetto tour%s\n" "${COLOR_CYAN}" "${COLOR_RESET}"
printf "\n"
