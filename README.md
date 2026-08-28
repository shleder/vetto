# vetto

`vetto` puts a local AI coding agent inside an OS-level sandbox before the agent
process starts. It is a single Rust binary: no daemon, no background service, no
root helper, no cloud dependency, no telemetry.

[![CI](https://github.com/shleder/vetto/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/shleder/vetto/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40shledery%2Fvetto?logo=npm&label=npm)](https://www.npmjs.com/package/@shledery/vetto)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

The one behavioural rule worth knowing: **if the requested boundary cannot be
established on the current host, `vetto` exits instead of starting the agent.**
There is no fallback to an unconfined process.

## Status

- Latest installable release: **0.2.3** (npm `latest`, GitHub release assets).
- `Cargo.toml` in `main` is `0.2.4`; that release is still a draft with no
  published artifacts, so packaging recipes target `0.2.3`.
- Linux is the most complete backend. macOS is functional but narrower.
  Windows is experimental. See [Platform support](#platform-support).

## Install

```bash
npm install --global @shledery/vetto
vetto doctor
```

Without installing:

```bash
npx @shledery/vetto doctor
```

Other recipes live in [`packaging/`](packaging) (Homebrew, Chocolatey, Scoop,
AUR, RPM) and [`debian/`](debian). They are source/artifact templates, not
published channels.

## Check the host before trusting anything

`vetto doctor` probes the running kernel instead of assuming support:

```console
$ vetto doctor
vetto v0.2.3 doctor
kernel:                  6.8.0-generic
landlock:                available (ABI 5)
unprivileged userns:     yes
full namespace stack:    yes
seccomp filters:         yes
seccomp user-notify:     yes
audit feed readable:     no
chosen tier:             full
```

Values are host-specific. `chosen tier` is `full`, `fs-only`, or
`NONE — fail-closed: <reason>` when no boundary can be built. `audit feed
readable: no` is common and does not weaken enforcement — the audit feed is
observation only.

`vetto doctor --probe` additionally verifies from inside a throwaway sandbox
that every resolved `display_only_deny` path is actually unreachable.

## Run an agent

```bash
# Known agent names are detected from the command and matched to a preset
vetto -- codex exec "refactor auth module"
vetto -- claude -p "fix the failing test"
vetto -- aider

# Or select the preset explicitly
vetto --agent codex -- codex exec "refactor auth module"

# Any command works; it does not have to be a known agent
vetto --profile strict -- python agent.py
```

Useful flags (`vetto --help` is the authority):

| Flag | Effect |
| :--- | :--- |
| `--profile <name>` | Built-in profile: `default`, `strict`, `permissive`, `audit` |
| `--policy <path>` | Extra TOML layer applied after profile and project policy |
| `--net <mode>` | `off` (default), `allowlist:<domains>`, `strict:<host:port>` |
| `--tui <mode>` | `statusline` (default), `full`, `none` |
| `--report <fmts>` | Post-session reports: `html,md,json,sarif` |
| `--jsonl <path>` | Append every session event as JSON lines |
| `--fail-on-block [n]` | Exit non-zero after `n` observed blocked attempts (default 1) |
| `--dry-run` | Print the resolved policy and tier plan; enforce nothing |
| `--ci` | Non-interactive: implies `--tui=none` and a JSON summary on stdout |
| `--observe-seccomp` | Attach a best-effort blocked-attempt tap (Linux, observation only) |

## Network

`--net=off` is the default. Relay modes need the Linux `full` tier:

```bash
vetto --net=off -- npm test
vetto --net=allowlist:registry.npmjs.org -- npm install
vetto --net=strict:github.com:22 --git-ssh -- git fetch origin
```

Platform truth:

- Linux `full`: network namespace, plus a loopback CONNECT/SOCKS relay and a
  host-side broker that resolves and pins one validated address per rule.
- Linux `fs-only`: relay modes are rejected. `off` is enforced by a
  socket-family seccomp filter.
- macOS: `off` only; `--net=allowlist` is rejected.
- Windows: `off` only.
- `--git-ssh` is Linux-only.

There is no TLS interception and no custom CA anywhere in the codebase. The
broker moves opaque bytes and never parses TLS, SNI or SSH.

## Policy

Layers are merged in a fixed order, and every TOML struct rejects unknown
fields:

```text
built-in profile → inherited built-ins → agent preset → project vetto.toml → CLI overrides
```

Built-ins live in [`profiles/`](profiles); per-agent presets in
[`profiles/agents/`](profiles/agents) (`codex`, `claude`, `cursor`, `aider`,
`cline`, `copilot`, `opencode`, `custom`).

Because Landlock is a pure allowlist and cannot subtract a path from an allowed
tree, secrets are handled by a separate subtractive list. A preset looks like
this ([`profiles/agents/codex.toml`](profiles/agents/codex.toml), verbatim):

```toml
[metadata]
name = "codex"
description = "Safe read-only compatibility roots for the Codex CLI."

[filesystem]
allow_read = ["$AGENT/cache", "$AGENT/logs"]

[display_only_deny]
paths = [
    "$AGENT/auth.json",
    "$AGENT/config.toml",
    "$AGENT/app_server.sock",
    "$AGENT/*.sock",
    "$AGENT/state_*.sqlite",
]
```

On the Linux `full` tier these paths are masked with a bind-mounted `/dev/null`
or an empty tmpfs. On `fs-only` they are omitted from the generated read
allowlist instead. Globs are expanded to concrete paths before enforcement;
patterns never reach the kernel.

`vetto init` inspects the project (Rust, Node, Python, Go, and agent config
directories) and writes a starting `vetto.toml`. `vetto profiles` lists the
built-ins.

## Reports

Events go to an in-process bus and, optionally, to disk: JSONL plus
self-contained HTML, Markdown, JSON and SARIF. Reports are written outside the
sandbox boundary, through no-follow directory descriptors on Unix, and pass
through a best-effort secret sanitizer.

```bash
vetto --report html,sarif --jsonl session.jsonl -- make test
vetto report compare session-a.json session-b.json
```

The sanitizer is best-effort. Treat reports as potentially sensitive.

## Session rescue

A recovery path for interrupted or corrupted agent sessions. Adapters: `codex`,
`claude`, `cursor`, `opencode`, `antigravity`.

```bash
vetto rescue --json scan --limit 25
vetto rescue --adapter claude diagnose <session>
vetto rescue --adapter cursor snapshot <session> --output ./recovered.jsonl
```

`scan`, `diagnose`, `snapshot` and `fork` do not modify agent state. Snapshots
and forks are created exclusively, outside the original state root, and verified
with SHA-256.

`repair` is the one mutating command: it performs a transactional repair, writes
a pre-repair backup (`~/.vetto/rescue_backups` by default) and a receipt, and
`vetto rescue rollback --receipt <path>` reverses it.

`--root` overrides the state root; otherwise each adapter resolves its own:

| Adapter | Default state root |
| :--- | :--- |
| `codex` | `CODEX_HOME`, else `$HOME/.codex` |
| `claude` | `CLAUDE_HOME`, else `$HOME/.claude` |
| `cursor` | platform Cursor user directory |
| `opencode` | `OPENCODE_HOME`, else `$HOME/.local/share/opencode` |
| `antigravity` | `ANTIGRAVITY_HOME`, else `$HOME/.gemini/antigravity` |

## Shell and Git hooks

```bash
vetto hook install --scope global --git
vetto hook status
vetto hook uninstall
```

This installs shim dispatchers so that intercepted toolchain binaries are
wrapped without prefixing every command by hand.

## Platform support

| Platform | Tier | Primitives | Notes |
| :--- | :--- | :--- | :--- |
| Linux x86_64 / aarch64 | `full` | Landlock, user/mount/PID/net/IPC namespaces, seccomp-BPF | Most complete backend |
| Linux without unprivileged userns | `fs-only` | Landlock, seccomp-BPF | No mount/PID/net namespace; no relay modes |
| macOS (Intel / Apple Silicon) | Seatbelt | `sandbox-exec` profile, FSEvents | `--net=off` only; Endpoint Security is opt-in and notify-only |
| Windows 11 x64 | Experimental | `processmodel.dll` sandbox API, AppContainer, low integrity, Job Object | `--net=off` only; inherited stdio, so use `--tui=none` |

## Known limits

These are properties of the current implementation, not planned work:

- Observation feeds (`/proc` polling, seccomp user-notify, kernel audit,
  FSEvents, ETW) provide visibility only. The kernel sandbox is the sole
  enforcement authority, and losing a feed never weakens it.
- `fs-only` has no PID or network namespace. A deliberately `setsid()`-detached
  grandchild is a documented cleanup gap.
- macOS relies on `sandbox-exec`, which Apple has deprecated. FSEvents reports
  coarse directory changes, never reads or denials.
- Windows fails before process creation when the experimental sandbox API is
  unavailable. There is no weaker fallback tier.
- The multi-agent runtime is Unix-only; Windows rejects a multi-agent launch.
- No performance overhead figure is guaranteed. See
  [docs/performance.md](docs/performance.md) for the benchmark method.

## Deliberately absent

- No background daemon, service or root helper.
- No telemetry, analytics or network calls of its own.
- No TLS interception, custom root CA or MITM proxy.
- No Docker, VM or container runtime requirement.

## Documentation

- [Architecture and startup order](ARCHITECTURE.md)
- [Threat model](docs/threat-model.md) and [security policy](SECURITY.md)
- [Platform backends](docs/platform-backends.md)
- [Network topology](docs/network.md)
- [Profiles](docs/profiles.md)
- [CI/CD integration](docs/ci-cd.md)

## License

Apache-2.0. See [LICENSE](LICENSE). The rescue subsystem originates from the
MIT-licensed `codex-rescue` project; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
