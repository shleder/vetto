#!/usr/bin/env bash
# Script to bootstrap and initialize the Homebrew tap repository: shleder/homebrew-vetto
set -euo pipefail

TAP_DIR="${HOME}/homebrew-vetto"
REPO_URL="git@github.com:shleder/homebrew-vetto.git"

echo "=== Initializing Homebrew Tap Repository: shleder/homebrew-vetto ==="

mkdir -p "${TAP_DIR}/Formula"
cp "$(dirname "$0")/vetto.rb" "${TAP_DIR}/Formula/vetto.rb"

cat << 'EOF' > "${TAP_DIR}/README.md"
# Homebrew Tap for Vetto

Official Homebrew tap for [Vetto](https://github.com/shleder/vetto) — daemon-less sandbox for AI coding agents.

## Installation

```bash
brew tap shleder/vetto
brew install vetto
```

## Update Formula

```bash
brew update
brew upgrade vetto
```
EOF

echo "Tap structure created at ${TAP_DIR}:"
ls -la "${TAP_DIR}/Formula"

echo
echo "To publish tap repository to GitHub:"
echo "  1. Create repository 'homebrew-vetto' on GitHub under your account (shleder)."
echo "  2. cd ${TAP_DIR}"
echo "  3. git init"
echo "  4. git add ."
echo "  5. git commit -m 'feat: initial vetto formula v0.2.5'"
echo "  6. git remote add origin ${REPO_URL}"
echo "  7. git push -u origin main"
echo
echo "Users can then install via: brew install shleder/vetto/vetto"
