![vetto — a kernel wall between the AI agent and your machine](assets/readme/hero.svg)

<p align="center">
  <a href="https://github.com/shleder/vetto/actions"><img src="https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/shleder/vetto/releases/tag/v0.4.2"><img src="https://img.shields.io/badge/version-0.4.2-blue?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@shledery/vetto"><img src="https://img.shields.io/npm/v/%40shledery%2Fvetto?logo=npm&style=flat-square" alt="npm"></a>
  <a href="https://crates.io/crates/vetto"><img src="https://img.shields.io/crates/v/vetto?logo=rust&style=flat-square&cacheSeconds=60" alt="crates.io"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="README.md">English</a> | <a href="docs/README.ru.md">Русский</a>
</p>

Daemon-less, rootless kernel-level sandbox and policy enforcement runtime for AI coding agents (**Claude Code**, **OpenAI Codex CLI**, **Cursor**, **Gemini**, **Aider**). Vetto injects immutable security boundaries directly between `fork()` and `execve()` with sub-4ms initialization latency.

---

## Proof Before Promises

Autonomous agents execute non-deterministic code. Untrusted dependency hooks, prompt injections, or hallucinated commands can compromise host credentials (`~/.ssh`, `~/.aws`, `.env`) or damage the filesystem. Under Vetto, unauthorized system calls are blocked deterministically:

```text
> Reading ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> Opening raw socket...             BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...       TERMINATED (process tree extinction, exit 125)
```

![Blocked exfiltration attempt under vetto](assets/demo.svg)

### Fail-Closed Contract (Exit 125)

If an isolation boundary is violated or if required kernel primitives cannot be enforced, execution is terminated immediately with exit code 125. Descendant process trees and orphaned subprocesses are reaped synchronously. Guarantees that the underlying OS cannot enforce are reported as unsupported—security is never silently downgraded.

## Quick Start

### 1. Install

Via package managers:

```bash
# npm
npm install -g @shledery/vetto
# Homebrew
brew install shleder/tap/vetto
# Cargo
cargo install vetto
```

Or download via standalone installer:

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

### 2. Transparent Agent Sandboxing

Enable zero-configuration sandboxing for your coding agent once. Vetto installs a non-destructive shim in `~/.vetto/shims` with priority in `PATH`:

```bash
vetto enable claude   # supports codex, gemini, cursor, aider, and presets
claude                # runs normally — fully sandboxed at the kernel boundary
```

### 3. Direct Execution & MCP Quarantine

Execute standalone scripts under strict default isolation:

```bash
vetto run -- python script.py
vetto -- npm test
```

Quarantine a Model Context Protocol (MCP) server binary with isolated paths and disabled network egress:

```bash
vetto mcp wrap --allow ./data --net off -- <mcp-server-binary>
```

Inspect security events and verify platform enforcement:

```bash
vetto audit --latest --recap    # review blocked syscalls and file operations
vetto doctor --fix              # probe kernel LSM support and repair shell hooks
```

## Platform Guarantees

Vetto enforces an immutable three-tier boundary model based on kernel capabilities available to unprivileged userspace:

| Platform / Tier | Filesystem Isolation | Network Isolation | Process Lifecycle | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Native)**<br>Tier 1 | Landlock LSM (ABI 1–6)<br>Inode-level VFS masking over `~/.ssh`, `~/.aws`, `.env` | Network Namespaces (`CLONE_NEWNET`)<br>Loopback isolation + local TCP/TLS broker | PID Namespaces (`CLONE_NEWPID`)<br>Deterministic process tree teardown | Production |
| **Linux (WSL2)**<br>Tier 1 | Landlock LSM via WSL2 kernel<br>Full inode restriction | Network Namespaces inside VM<br>Isolated broker egress | PID Namespaces + `/proc` sweep<br>Full tree extinction | Production (Recommended for Windows) |
| **macOS (Darwin)**<br>Tier 2 | Seatbelt (SBPL)<br>Write confinement to `$PROJECT` and `/tmp` | Network Lockdown<br>`--net=off` via `(deny network*)` rules | Process Group Sweeping<br>kqueue watchdog supervision | Standard (Requires Full Disk Access for `~/Documents`) |
| **Windows Native**<br>Tier 3 | AppContainer & LPAC<br>DACL token restriction | Capability Lockdown<br>Restricted network SIDs | Job Objects<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Guardrail (Use WSL2 for Tier 1 kernel namespaces) |

## Binary Integrity & Attestation

Releases are built via automated GitHub Actions workflows with public cryptographic verification:

- **SLSA Level 3 Provenance**: In-toto build attestations generated for all release binaries.
- **Minisign Signatures**: Published with each release archive under public key `75ECEC9B5080C590`.
- **Cryptographic Checksums**: Standalone SHA256 hashes generated and verified during installation.

## Documentation

- [Platform Backends & Boundary Specs](docs/platform-backends.md)
- [Agent Presets & Registry](docs/agents.md)
- [Threat Model & Security Assumptions](docs/threat-model.md)
- [Exit Codes & Failure Modes](docs/exit-codes.md)
- [Vulnerability Reporting (SECURITY.md)](SECURITY.md)

## Contributing

Contributions are welcome. Please branch from main. All boundary assertions must include corresponding kernel validation test cases. Pull requests are validated against Linux and macOS kernel runners in GitHub Actions CI.

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)).
