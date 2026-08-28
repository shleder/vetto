<div align="center">

<pre align="center">
██╗   ██╗ ███████╗ ████████╗ ████████╗  ██████╗ 
██║   ██║ ██╔════╝ ╚══██╔══╝ ╚══██╔══╝ ██╔═══██╗
██║   ██║ █████╗      ██║       ██║    ██║   ██║
╚██╗ ██╔╝ ██╔════╝    ██║       ██║    ██║   ██║
 ╚████╔╝  ███████╗    ██║       ██║    ╚██████╔╝
  ╚═══╝   ╚══════╝    ╚═╝       ╚═╝     ╚═════╝ 
</pre>

# VETTO

<p align="center">
  <b>Daemon-Less, Fail-Closed Sandbox &amp; Security Layer for AI Coding Agents</b>
</p>

[![Release](https://img.shields.io/github/v/release/shleder/vetto?include_prereleases&label=release&color=blue&style=flat-square)](https://github.com/shleder/vetto/releases)
[![npm version](https://img.shields.io/npm/v/%40shledery%2Fvetto?logo=npm&label=npm&style=flat-square)](https://www.npmjs.com/package/@shledery/vetto)
[![CI](https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/shleder/vetto/actions/workflows/ci.yml)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)](#platform-support)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Fail-Closed](https://img.shields.io/badge/fallback-none%20%2F%20fail--closed-success?style=flat-square)](#honest-status)

</div>

---

`vetto` puts a local AI coding agent inside an OS-level sandbox **before the
agent process starts**. It is a single Rust binary: no daemon, no background
service, no root helper, no cloud dependency, no telemetry.

The one behavioural rule that matters: **if the requested boundary cannot be
established on the current host, `vetto` exits instead of starting the agent.**
There is no fallback to an unconfined process, anywhere in the code.

## Honest status

Read this before deciding how much to trust it.

**What this project is:** a young, single-maintainer, fast-moving tool
(first commit August 12, 2026) on the 0.2.x alpha line. It has **no external
security audit**. Treat it as a hardening layer around an agent, not as a
trusted boundary you bet your machine on.

**What is real and verified by code and tests today:**

- Linux `full` and `fs-only` tiers: Landlock (ABI 1–6 negotiated), user/mount/
  PID/net/IPC namespaces, hand-built seccomp-BPF, network-namespace relay with
  a host-side broker that validates every DNS answer and pins one address per
  rule. Enforcement is applied in the child before `execve`, and every setup
  failure aborts the launch.
- Fail-closed discipline on all platforms: unsupported host → exit; missing
  primitives → exit; `--net=allowlist` on fs-only/macOS → rejected; multi-agent
  on Windows → refused rather than run unsandboxed.
- Policy layering with unknown-field rejection, glob resolution before
  enforcement, secrets masking via `display_only_deny`.
- Session reports (HTML/MD/JSON/SARIF + JSONL), `rescue` (codex/claude/cursor),
  TUI statusline/full, hook shims.
- 323 automated tests; CI runs build + tests + clippy on x86_64/aarch64 Linux
  (aarch64 under QEMU), macOS arm64 (Intel via check), and Windows.

**What is currently weaker than the rest — known and not hidden:**

- **CI lint gates no longer rubber-stamp the code** (fmt blocks, clippy denies
  warnings, llvm-cov publishes coverage), but the coverage **threshold is not
  set yet** — the number gets pinned only after a real baseline exists.
- **Windows sandbox enforcement has thin test coverage.** Enforcement tests
  exist but every non-Windows machine only ever runs their inert placeholders.
  The backend fails closed, and it is labelled experimental for a reason.
- **Two large subsystems are dead code**: a Linux eBPF redirect path (~900
  lines) and a macOS Endpoint Security deny-capable engine. Neither is wired
  into a session; the README of no version should be read as claiming they are.
- `docs/tutorials/` are outlines, not finished tutorials. There are no
  performance-overhead figures yet (the e2e spawn benchmark lands with the
  first CI perf run).

**What a kernel sandbox is not:** it is not a VM or a container runtime. A
sufficiently severe kernel exploit escapes namespaces and Landlock. vetto
shrinks what an agent can touch; it does not make hostile code safe to run.

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
AUR, RPM) and [`debian/`](debian). They are **source/artifact templates, not
published channels**.

## Check the host before trusting anything

`vetto doctor` probes the running kernel instead of assuming support:

```console
$ vetto doctor
vetto v0.2.4 doctor
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

`vetto doctor --probe` additionally builds a throwaway sandbox and verifies,
byte by byte from inside it, that every resolved `display_only_deny` path is
actually unreachable.

## Verify the boundary without an agent

`vetto verify` runs the same kind of checks as `doctor --probe` plus two more:
a loopback-connect attempt against a host listener (a sandbox that can reach
your host services fails loudly) and a write attempt outside every write root.
It prints a verdict table (or `--json`) and exits non-zero on any leak.

`--verify` on a normal session runs this battery against the *resolved* policy
first and refuses to start the agent on any leak:

```bash
vetto verify            # standalone battery, no agent runs
vetto --verify -- claude -p "fix the failing test"
```

`vetto policy explain` prints the effective merged policy — tier, network
mode, roots, masked secrets, limits, environment — and `vetto policy lint`
flags dangerous configurations such as a write root covering `$HOME`:

```bash
vetto policy explain --json
vetto policy lint --strict
```

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
| `--timeout <dur>` | Kill the session at the deadline, exit 124 (e.g. `90s`, `30m`; enforced with `--tui=none`) |
| `--limits <spec>` | Resource ceilings: `cpu=,as=,procs=,nofile=,fsize=` (strictest-wins with policy) |
| `--verify` | Run the boundary battery before spawning the agent; refuse to start on any leak |
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
  host-side broker that resolves DNS itself and pins one validated address per
  rule. Answers that resolve to private/special-use ranges are rejected
  (anti-rebinding).
- Linux `fs-only`: relay modes are rejected. `off` is enforced by a
  socket-family seccomp filter.
- macOS: `off` only — both relay modes (`allowlist`, `strict`) are rejected
  before spawn with an explicit reason.
- Windows: `off` only.
- `--git-ssh` is Linux-only.

There is no TLS interception and no custom CA anywhere in the codebase. The
broker moves opaque bytes and never parses TLS, SNI or SSH.

## Policy

Layers merge in a fixed order, and every TOML struct rejects unknown fields.
The full order (the loader also honours host-global and user-global layers, and
a local override file below the project layer):

```text
host global → user global → built-in profile (+ extends) → agent preset
           → project vetto.toml + policy.d → local override → CLI overrides
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
or an empty tmpfs. On `fs-only` they are carved out of the generated read
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

The sanitizer is best-effort and labelled as such in every output it touches.
Treat reports as potentially sensitive.

## Session rescue

A recovery path for interrupted or corrupted agent sessions. Adapters: `codex`,
`claude`, `cursor`.

```bash
vetto rescue --json scan --limit 25
vetto rescue --adapter claude diagnose <session>
vetto rescue --adapter cursor snapshot <session> --output ./recovered.jsonl
```

`scan`, `diagnose`, `snapshot` and `fork` do not modify agent state. Snapshots
and forks are created exclusively, outside the original state root, and
verified with SHA-256.

`repair` is the one mutating command: it performs a transactional repair,
writes a pre-repair backup (`~/.vetto/rescue_backups` by default) and a
receipt, and `vetto rescue rollback --receipt <path>` reverses it.

`--root` overrides the state root; otherwise each adapter resolves its own:

| Adapter | Default state root |
| :--- | :--- |
| `codex` | `CODEX_HOME`, else `$HOME/.codex` |
| `claude` | `CLAUDE_HOME`, else `$HOME/.claude` |
| `cursor` | platform Cursor user directory |

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
| Linux without unprivileged userns | `fs-only` | Landlock, seccomp-BPF | No mount/PID/net namespace; no relay modes; see read-back cost below |
| macOS (Intel / Apple Silicon) | Seatbelt | `libsandbox` SBPL profiles (`sandbox_init_with_parameters`), FSEvents | `--net=off` only (see Network); Endpoint Security code exists but is not wired in |
| Windows 11 x64 | Experimental | `processmodel.dll` sandbox API, AppContainer, low integrity, Job Object | `--net=off` only; inherited stdio, so use `--tui=none`; no integration-test coverage of enforcement |

## Known limits

These are properties of the current implementation, not planned work:

- Observation feeds (`/proc` polling, seccomp user-notify, kernel audit,
  FSEvents, ETW) provide visibility only. The kernel sandbox is the sole
  enforcement authority, and losing a feed never weakens it. The seccomp
  user-notify tap reads agent memory via `/proc/<pid>/mem` and is racy by
  design; it is observation, nothing more.
- `fs-only` has no mount namespace. To keep carved-out secrets unreadable, read
  permission is stripped from write-root rules, and the honest cost is that a
  file created **directly at a write root** (outside enumerated clean
  subdirectories) cannot be read back in the same session, and directory entry
  names under denied paths stay visible. vetto prints this degradation warning
  at session start whenever the policy has deny paths. It also has no PID
  namespace: a deliberately `setsid()`-detached grandchild is a documented
  cleanup gap.
- macOS relies on `libsandbox` SBPL profiles — the same mechanism the
  deprecated `sandbox-exec` binary drives — so treat that surface as
  Apple-deprecated. FSEvents reports coarse directory changes, never reads or
  denials. A forked kqueue watchdog kills the agent when vetto itself is
  `SIGKILL`ed; it is best-effort and reports its own failure if it cannot arm.
- Windows fails before process creation when the experimental sandbox API is
  unavailable, and refuses the launch when a secret path overlaps a granted
  read root (the SandboxSpec contract cannot subtract a subpath). There is no
  weaker fallback tier.
- The multi-agent runtime is Unix-only; Windows rejects a multi-agent launch.
- No performance overhead figure is guaranteed. See
  [docs/performance.md](docs/performance.md) for the benchmark method; the
  benchmarks measure components, not end-to-end sandbox overhead.

## Deliberately absent

- No background daemon, service or root helper.
- No telemetry, analytics or network calls of its own.
- No TLS interception, custom root CA or MITM proxy.
- No Docker, VM or container runtime requirement.

## Documentation

- [Architecture and startup order](ARCHITECTURE.md)
- [Threat model](docs/threat-model.md)
- [Network internals](docs/network.md)
- [Platform backends](docs/platform-backends.md)
- [Profiles](docs/profiles.md)
- [Security notes and history](docs/security)
- [Changelog](CHANGELOG.md) · [Roadmap](ROADMAP.md) · [Security policy](SECURITY.md)

## Building from source

Rust 1.75+ (`rustup` or your distro toolchain):

```bash
cargo build --release
./target/release/vetto doctor
```

The `endpoint-security` cargo feature is opt-in, macOS-only, and does not imply
the Apple entitlement the framework requires. Benchmarks (`cargo bench`) measure
Landlock ruleset construction, `/proc` fd scans, seccomp filter builds, PTY
passthrough and report rendering — they deliberately do not claim an
end-to-end overhead number.

## License

Apache-2.0 — see [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for vendored-code provenance.
