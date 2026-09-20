![vetto — a kernel wall between the AI agent and your machine](assets/readme/hero.svg)

[![CI](https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/shleder/vetto/actions) [![Version](https://img.shields.io/badge/version-0.3.7-blue?style=flat-square)](https://github.com/shleder/vetto/releases/tag/v0.3.7) [![npm](https://img.shields.io/npm/v/%40shledery%2Fvetto?logo=npm&style=flat-square)](https://www.npmjs.com/package/@shledery/vetto) [![License](https://img.shields.io/badge/license-Apache--2.0%20%2F%20MIT-green?style=flat-square)](LICENSE)

## Proof before promises

Your agent holds your keys — literally. One rogue dependency hook or one injected prompt and it walks off with `~/.ssh` or wipes your home. Under vetto it meets the wall instead:

```text
> Reading ~/.ssh/id_rsa...        BLOCKED (secret mask, EACCES)
> Opening raw socket...            BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...      TERMINATED (tree extinction, exit 125)
```

![Blocked exfiltration attempt under vetto](assets/demo.svg)

Exit `125` is the whole contract: if isolation fails or is breached, nothing proceeds. Strays and zombies are deterministically reaped upon boundary violation or parent exit. Whatever your OS cannot guarantee is reported as unsupported — never quietly downgraded.

## Install

```bash
npm install -g @shledery/vetto
```

Also available as `brew install shleder/tap/vetto`, `cargo install vetto`, a [container image](docs/INSTALL.md), or via curl:

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

Current release is [v0.3.7](https://github.com/shleder/vetto/releases/tag/v0.3.7).

## Three ways to use it

**1. Wrap your agent once, then forget vetto exists.**

```bash
vetto enable claude   # codex, gemini, cursor, aider, opencode, and 15 more
claude                # runs as usual — sandboxed underneath
```

The shim pins `~/.vetto/shims` at the front of your PATH and heals your shell hooks when installers like nvm or conda try to shove past them.

**2. Run anything under the strict default sandbox.**

```bash
vetto run -- python script.py
vetto -- npm test
```

**3. Quarantine an MCP server.**

```bash
vetto mcp wrap --allow ./data --net off -- <mcp-server-binary>
```

After a run, `vetto audit --latest` lists what got stopped and `--recap` prints the security summary. `vetto doctor` shows what your kernel can actually enforce — and repairs what it can with `--fix`.

## Platform guarantees

Three levels, no bluffing. Linux gets full kernel confinement: Landlock rules, user/mount/pid/network namespaces, seccomp filters, cgroup ceilings. macOS gets Seatbelt write locks with best-effort limits (Apple does not allow unprivileged read-denial of the dyld cache). Native Windows enforces AppContainer isolation and Job Objects tree containment (Tier 3). For full Tier 1 kernel namespace isolation on Windows machines, run via WSL2. Full matrix: [platform backends](docs/platform-backends.md).

Two macOS footnotes that bite people: Terminal needs Full Disk Access for `~/Documents`, `~/Desktop`, `~/Downloads` — or keep work in `~/projects`. And `doctor` tells you exactly which case you are in.

## Trust the binaries

Every release publishes SLSA Level 3 build provenance attestations, Minisign signatures (key `75ECEC9B5080C590`), and SHA256 checksums to GitHub Releases. Install scripts and native binaries verify cryptographic checksums prior to execution.

## Go deeper

Policies are plain TOML compiled into sealed contracts: `vetto policy explain` previews enforcement, `vetto policy lint` vets it before anything spawns, `vetto allow` / `vetto deny` tweak access without touching files, and `vetto verify` fires a throwaway leak battery. Start at [agent registry](docs/agents.md), [threat model](docs/threat-model.md), [architecture](docs/platform-backends.md), [exit codes](docs/exit-codes.md).

## Hack on it

Branch from `main`. Back every isolation claim with a real kernel test — mocks for kernel boundaries get rejected. Broken isolation must fail closed with exit `125`. Keep format and clippy clean. All pull requests are strictly validated against native kernel isolation suites in remote GitHub Actions CI before merge. Report security issues via [SECURITY.md](SECURITY.md).

Dual licensed Apache-2.0 / MIT ([LICENSE](LICENSE), [notices](THIRD_PARTY_NOTICES.md)).
