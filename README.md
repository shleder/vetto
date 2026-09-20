![vetto — kernel wall between the agent and your machine](assets/readme/hero.svg)

# vetto

Your coding agent runs with your privileges. It can read your SSH keys, exfiltrate your `.env`, and fork-bomb your machine — by accident, on a normal Tuesday, because a dependency hook or a prompt injection told it to. `vetto` puts a kernel wall between the agent and your machine, so the worst case is a blocked syscall instead of a wiped home directory.

No root. No daemons. Cold start in about 4 milliseconds.

[![CI](https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/shleder/vetto/actions) [![Version](https://img.shields.io/badge/version-0.3.7-blue?style=flat-square)](https://github.com/shleder/vetto/releases/tag/v0.3.7) [![npm](https://img.shields.io/npm/v/%40shledery%2Fvetto?logo=npm&style=flat-square)](https://www.npmjs.com/package/@shledery/vetto) [![License](https://img.shields.io/badge/license-Apache--2.0%20%2F%20MIT-green?style=flat-square)](#license) [![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-informational?style=flat-square)](#platform-guarantees)

## Proof before promises

A confined agent that reaches for secrets or the network meets the boundary, not your files:

```text
> Reading ~/.ssh/id_rsa...        BLOCKED (secret mask, EACCES)
> Opening raw socket...            BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...      TERMINATED (tree extinction, exit 125)
```

![Blocked exfiltration attempt under vetto](assets/demo.svg)

Exit `125` is the whole contract: isolation failed or was breached, so nothing proceeds. Orphaned and zombie processes are swept within 500 milliseconds. Anything the sandbox cannot guarantee on your OS is reported as unsupported — never silently downgraded.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

Also available as `brew install shleder/tap/vetto`, `npm install -g @shledery/vetto`, `cargo install vetto`, or a [container image](docs/INSTALL.md). Current release is [v0.3.7](https://github.com/shleder/vetto/releases/tag/v0.3.7).

## Three ways to use it

**1. Wrap your agent once, then forget vetto exists.**

```bash
vetto enable claude   # codex, gemini, cursor, aider, opencode, and 15 more
claude                # runs as usual — sandboxed underneath
```

The shim puts `~/.vetto/shims` first on your PATH and repairs your shell hooks when installers like nvm or conda try to push past them.

**2. Run any command under the strict default sandbox.**

```bash
vetto run -- python script.py
vetto -- npm test
```

**3. Quarantine an MCP server.**

```bash
vetto mcp wrap --allow ./data --net off -- <mcp-server-binary>
```

After a run, `vetto audit --latest` shows what got blocked; `--recap` prints the security summary. `vetto doctor` reports what your kernel can actually enforce and fixes what it can with `--fix`.

## Platform guarantees

That honesty has three levels. Linux gets full kernel confinement: Landlock rules, user/mount/pid/network namespaces, seccomp filters, cgroup ceilings. macOS gets Seatbelt write locks with best-effort limits (Apple does not allow unprivileged read-denial of the dyld cache). Native Windows gets AppContainer plus Job Objects — a preview tier, so production Windows runs go through WSL2. Full matrix: [platform backends](docs/platform-backends.md).

Two macOS footnotes that bite people: Terminal needs Full Disk Access for `~/Documents`, `~/Desktop`, `~/Downloads` — or keep work in `~/projects`. And `doctor` will tell you exactly which case you are in.

## Trust the binaries

Every release ships with SLSA Level 3 build provenance, Minisign signatures (key `75ECEC9B5080C590`), and CycloneDX SBOMs, published together to GitHub Releases, npm, crates.io, and Homebrew. If the signature does not check out, it does not install.

## Go deeper

Policies are declarative TOML compiled into sealed contracts: `vetto policy explain` shows what will be enforced, `vetto policy lint` checks it before anything spawns, `vetto allow` / `vetto deny` adjust access without editing files, and `vetto verify` runs a throwaway leak battery. Start at [agent registry](docs/agents.md), [threat model](docs/threat-model.md), [architecture](docs/architecture/NEXT_GEN_SPECIFICATION.md), [exit codes](docs/exit-codes.md).

## Hack on it

Branch from `main`. Prove every isolation claim with a real kernel test — mocks for kernel boundaries are rejected. Failed isolation must fail closed with exit `125`. Format and clippy clean; CI builds and tests, your laptop does not. Report security issues via [SECURITY.md](SECURITY.md).

Dual licensed Apache-2.0 / MIT ([LICENSE](LICENSE), [notices](THIRD_PARTY_NOTICES.md)).
