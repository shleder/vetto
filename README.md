# vetto

**Run any AI coding agent inside an OS kernel sandbox — no root, no daemons, ~4ms cold start. If the agent goes rogue, the kernel says no (exit 125).**

[![CI](https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/shleder/vetto/actions) [![Version](https://img.shields.io/badge/version-0.3.7-blue?style=flat-square)](https://github.com/shleder/vetto/releases/tag/v0.3.7) [![License](https://img.shields.io/badge/license-Apache--2.0%20%2F%20MIT-green?style=flat-square)](#license)

## Start in 30 seconds

```bash
# Install (pick one)
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
brew install shleder/tap/vetto
npm install -g @shledery/vetto
cargo install vetto

# Wrap your agent and run it as usual — the sandbox sits underneath
vetto enable claude   # or codex, cursor, aider, opencode, …
claude
```

No shims? Run anything directly under the default strict sandbox:

```bash
vetto run -- python script.py
vetto -- npm test
```

![Vetto Demo](assets/demo.svg)

## Proof, not promises

Real session transcript — an agent tries the classic escapes, the kernel boundary answers:

```text
$ claude
> Reading ~/.ssh/id_rsa...
[vetto] BLOCKED: Inode-level secret mask (INV-08). EACCES.
> Opening raw socket to 198.51.100.1...
[vetto] BLOCKED: Network namespace isolated (INV-04). EAFNOSUPPORT.
> Spawning detached daemon via setsid...
[vetto] TERMINATED: Process tree extinction breach (INV-20). Exit 125.
```

Honest platform tiers — what each OS kernel actually guarantees ([details](docs/platform-backends.md)):

| Tier | Platform | Filesystem | Network | Processes | Use for |
| --- | --- | --- | --- | --- | --- |
| **1 · Production** | Linux, WSL2 | Landlock ABI v1–v6 deny | `CLONE_NEWNET` + allowlist relay | PID namespaces, `cgroup.kill`, <500ms extinction | Unattended autonomy |
| **2 · Experimental** | macOS | Seatbelt SBPL write lock (broad reads: dyld limits, #62) | `--net off` lockdown | kqueue watchdog + pgroup sweep | Interactive dev (OrbStack for read secrecy) |
| **3 · Experimental** | Windows native | AppContainer LPAC, default-deny + overlap check (#63) | `--net off` only (WFP needs admin) | Job Objects kill-on-close | Preview (WSL2 for Tier 1) |

Supply chain, verified per release: **SLSA Level 3 provenance**, **Minisign** signatures (Key ID `75ECEC9B5080C590`), CycloneDX SBOMs — [v0.3.7, 18 assets](https://github.com/shleder/vetto/releases/tag/v0.3.7).

## What it is

`vetto` wraps local coding agents in an operating-system sandbox and produces terminal-native visibility plus post-session reports. Boundaries are injected between `fork()` and `execve()` — no background daemons, no root, 0 MB idle footprint.

## How a run goes

1. **Wrap** — `vetto enable <agent>` installs a transparent PATH shim (zero-config profile + network allowlist included).
2. **Confine** — every spawn gets Landlock/Seatbelt/AppContainer filesystem rules, secret masking (`~/.ssh`, `~/.aws`, `.env*`, 35+ env patterns stripped), and governed network.
3. **Supervise** — the supervisor watches the whole fork tree; survivors past the 500ms extinction deadline fail closed with exit 125.
4. **Report** — `vetto audit --latest` shows blocked files, syscalls, and egress; `--recap` prints the post-session summary.

## Command map

| Command | Job |
| --- | --- |
| `vetto enable <agent>` / `vetto disable <agent>` | Transparent shim wrapping with shell hook repair (`doctor --fix` relocates hooks to EOF so nvm/conda never shadow them) |
| `vetto doctor [--fix]` | Kernel capability report + honest tier status + auto-repair (incl. macOS Full Disk Access guidance) |
| `vetto policy explain` / `vetto policy lint` | Show the BLAKE3-sealed contract / preflight check before spawning |
| `vetto allow …` / `vetto deny …` | Runtime grants without hand-editing TOML |
| `vetto verify` | Throwaway leak-detection battery against the current policy |
| `vetto audit [--recap]` | Blocked attempts, syscalls, egress from past runs |
| `vetto mcp wrap -- …` | Isolate third-party MCP servers ([guide](docs/integrations/mcp.md)) |
| `vetto upgrade` | Self-update across npm/cargo/brew/binary channels |

## Agents

20 native presets — `claude`, `codex`, `gemini`, `cursor-agent`, `opencode`, `aider`, `cline`, `copilot`, `windsurf`, `continue`, `goose`, `openhands`, `swe-agent`, `plandex`, `mentat`, `gpt-engineer`, `devin`, `crust`, `amp`, `antigravity` — each with credential unmasking, config allowlists, and network profiles ([registry](docs/agents.md), [guides](docs/integrations/claude-code.md)). Unknown binary? It runs under the default strict profile.

## Limits (read before production)

- macOS cannot do unprivileged read-denial for the dyld shared cache (Apple restriction, #62) — broad reads stay permitted; write isolation holds.
- Native Windows has no cgroups/Landlock — limits come from Job Objects; for Tier 1 run inside WSL2.
- `~/Documents`, `~/Desktop`, `~/Downloads` on macOS need Terminal Full Disk Access, or run from `~/projects` (`doctor` tells you which).
- Merging this README is not a release — releases ship via release-train to GitHub, npm, crates.io, and Homebrew together.

## Docs

[Install](docs/INSTALL.md) · [Agent registry](docs/agents.md) · [Threat model](docs/threat-model.md) · [Architecture](docs/architecture/NEXT_GEN_SPECIFICATION.md) · [Verification harness](docs/architecture/verify-ng.md) · [Exit codes](docs/exit-codes.md) · [Profiles](docs/profiles.md) · [Sandbox comparison](docs/comparison.md) · [Tutorials](docs/tutorials/installing.md)

## Contributing

1. Branch from `main`, keep the blast radius small.
2. **No mock tests for kernel boundaries** — every isolation claim needs a real kernel test.
3. **No silent downgrades** — failed isolation fails closed with exit `125`.
4. Format + clippy clean; PR with test evidence. CI (not your laptop) builds and tests.
5. Security bugs → [SECURITY.md](SECURITY.md), responsibly via GitHub Security Advisories.

## License

Dual **Apache-2.0 / MIT** — see [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
