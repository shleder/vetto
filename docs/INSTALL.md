# Installing Vetto

## Quick Install (Linux & macOS)

Install the latest pre-compiled `vetto` binary to `~/.local/bin` using `curl`:

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto-tiers/main/scripts/install.sh | bash
```

### Options

Install system-wide to `/usr/local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto-tiers/main/scripts/install.sh | bash -s -- --system
```

Install to a custom directory:

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto-tiers/main/scripts/install.sh | bash -s -- --dir /custom/bin
```

## Security & Verification

The installation script automatically verifies SHA256 hashes against `checksums.txt` published with official GitHub releases. It never invokes `sudo` silently.
