<p align="center">
  <img src="./assets/readme/hero.svg" width="100%" alt="vetto applies an operator-controlled OS boundary around local AI coding agents">
</p>

<p align="center">
  <strong>Your AI agent runs with your tokens, your files, and your network.</strong><br>
  vetto puts one operator-controlled OS boundary around it — before the agent exists.<br>
  <em>If the boundary cannot be established, nothing launches.</em>
</p>

<p align="center">
  <a href="https://github.com/shleder/vetto/actions/workflows/ci.yml"><img src="https://github.com/shleder/vetto/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status for main"></a>
  <a href="https://www.npmjs.com/package/@shleddy/vetto"><img src="https://img.shields.io/npm/v/%40shleddy%2Fvetto?logo=npm&label=npm" alt="npm package version"></a>
  <a href="https://www.npmjs.com/package/@shleddy/vetto"><img src="https://img.shields.io/npm/dw/%40shleddy%2Fvetto?logo=npm&label=downloads%2Fweek" alt="npm weekly downloads"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0 license"></a>
  <a href="https://github.com/shleder/vetto/blob/main/SECURITY.md"><img src="https://img.shields.io/badge/telemetry-zero-success" alt="Zero telemetry"></a>
</p>

<p align="center">
  <a href="#run-it">Run it</a> ·
  <a href="#what-the-boundary-controls">Controls</a> ·
  <a href="#platform-matrix">Platforms</a> ·
  <a href="#profiles-and-policy">Profiles</a> ·
  <a href="#rescue-local-sessions">Rescue</a> ·
  <a href="#what-vetto-does-not-promise">Honest limits</a> ·
  <a href="SECURITY.md">Security</a>
</p>

---

## The problem vetto solves

Every local coding agent you launch — Codex, Claude Code, Aider, a custom
script — starts with **your full environment**: API tokens in env variables,
read/write access to your home directory, and an open network route. A single
injected instruction inside fetched content is enough to turn that access into
exfiltration.

Agent-built sandboxes are useful defense in depth, but their policies,
platform coverage, defaults, and reporting differ. vetto gives the operator
**one outer boundary** without detecting, disabling, or weakening the sandbox
inside the agent.

| Without vetto | With vetto |
| --- | --- |
| Agent reads `$HOME`, `.env`, `.ssh`, cloud credentials | Secrets masked and denied by default |
| Agent talks to any endpoint | Network off by default; allowlist relay where the platform supports it |
| Every agent invents its own sandbox policy | One policy model across agents, one report format |
| You hope the agent behaves | You set the capability before `exec` |

> [!IMPORTANT]
> **No boundary, no process.** If the selected sandbox cannot be established,
> vetto refuses to launch the agent. It never falls back to an ordinary
> unsandboxed command.

### Proof: a real capability probe

This is an excerpt from `vetto doctor` on the project's current GitHub
Codespace. Your host is probed at runtime; the tier is never assumed.

```console
$ vetto doctor
vetto v0.2.0 doctor
landlock:                available (ABI 4)
unprivileged userns:     yes
full namespace stack:    yes
seccomp filters:         yes
seccomp user-notify:     yes
audit feed readable:     no
chosen tier:             full
```

The last two lines are deliberate: enforcement can be fully active even when
the host does not expose a readable audit feed.

<p align="center">
  <img src="./assets/readme/boundary.svg" width="100%" alt="vetto resolves policy, probes capabilities, applies an OS boundary, executes the agent, and keeps observation separate from enforcement">
</p>

The startup order is the security property: policy resolution and capability
checks happen **before the agent exists**. The TUI, event readers, JSONL
stream, and reports sit below a one-way boundary; none of them can grant an
operation.

<a id="run-it"></a>

<p align="center">
  <img src="./assets/readme/section-run.svg" width="100%" alt="01 Run it: install from npm, inspect the host, and wrap an existing agent command">
</p>

## Run it

Install from npm, inspect the machine, then add `vetto --` before the command
you already use:

```console
npm install --global @shleddy/vetto
vetto doctor
cd my-project
vetto --agent codex --profile default -- codex exec "review auth"
```

The wrapper accepts any executable:

```console
vetto -- claude -p "fix the failing test"
vetto -- aider
vetto -- opencode
vetto -- python agent.py
```

For an interactive agent, the default `--tui=statusline` preserves the agent's
PTY and reserves one row for vetto. Use `--tui=full` for the dashboard or
`--tui=none` for scripts and CI. `vetto init` creates a starter `vetto.toml`
in the current project.

The npm package includes native executables for Linux x64/ARM64, macOS
x64/Apple Silicon, and Windows x64. It selects the matching executable
locally; there is no install-time binary downloader. To install this release
exactly, use `npm install --global @shleddy/vetto@0.2.0`. Stable releases stay
on the npm `latest` tag while pre-release builds use `next`.

<a id="what-the-boundary-controls"></a>

## What the boundary controls

| Surface | Enforcement | Operator-facing control |
| --- | --- | --- |
| Filesystem and secrets | Landlock on Linux and Seatbelt on macOS; Windows refuses policies whose requested path exclusions cannot be represented | Additive read/write roots; resolved secret masking in Linux FULL; fail-closed bounded enumeration in FS-ONLY |
| Processes and kernel interfaces | Namespace/process containment plus inherited seccomp on Linux; Job Object/restricted token on Windows | Linux seccomp blocks `umount2`, `ptrace`, `process_vm_*`, `pidfd_getfd`, `io_uring`, `userfaultfd`, `bpf`, and `perf_event_open`; resource limits are backend-specific |
| Network | Off by default; Linux FULL can use a host-side relay | Domain allowlist, exact domain+port rules, and an explicit Git-over-SSH helper |
| Environment | Child environment rebuilt from an allowlist | Explicit `[environment].pass_through`; token, cloud, and API-key variables are stripped by default |
| Session evidence | PTY/TUI, optional event feeds, JSONL, HTML, Markdown, JSON, SARIF | `--observe-seccomp`, `--fail-on-block`, `--report-dir`, and bounded retention; evidence never changes allow/deny |

<details>
<summary><strong>Network modes</strong></summary>

```console
# No external network. This is the default.
vetto --net=off -- agent command

# Linux FULL: proxy-aware traffic to listed domains.
vetto --net=allowlist:api.github.com,registry.npmjs.org -- agent command

# Linux FULL: exact host and port.
vetto --net=strict:registry.npmjs.org:443 -- agent command

# Linux FULL: explicit SSH relay; the host/port must also be allowed.
vetto --net=strict:github.com:22 --git-ssh -- git fetch origin
```

The broker resolves DNS outside the sandbox, rejects loopback, private,
link-local, metadata, and other special-use destinations, pins the approved IP
for the connection, and pumps opaque bytes. There is no SNI parsing, TLS
decryption, CA injection, or TLS MITM. Non-proxy protocols have no route
unless an explicit helper exists. See [docs/network.md](docs/network.md).

</details>

<details>
<summary><strong>Reports and CI</strong></summary>

```console
vetto --ci --tui=none --profile=strict --net=off \
  --report=json,sarif --report-dir=.vetto/reports \
  --fail-on-block -- agent command
```

Reports use private, collision-resistant names and bounded retention. The
sanitizer is explicitly best-effort: false positives and false negatives are
possible, and reports contain observed events rather than proof of complete
denial visibility.

GitHub Actions:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: shleder/vetto/action@main
    with:
      command: codex exec "review this PR"
      profile: strict
      net: off
      report: json,sarif
      upload-sarif: "true"
```

The action builds the checked-out source with `--locked`; it does not download
or publish a release. Do not interpolate untrusted pull-request text into its
shell command. See [docs/ci-cd.md](docs/ci-cd.md).

</details>

<a id="platform-matrix"></a>

<p align="center">
  <img src="./assets/readme/section-platforms.svg" width="100%" alt="02 Capability first: Linux, macOS, and Windows expose different verified boundaries">
</p>

## Platform matrix

| Platform | Enforcement path | Current scope | Honest boundary |
| --- | --- | --- | --- |
| **Linux FULL** | Landlock + USER/MOUNT/PID/NET/IPC namespaces + seccomp | Filesystem masking, descendant containment, network-off, allowlist/strict relay, Git SSH helper | Preferred tier; requires the complete unprivileged namespace setup |
| **Linux FS-ONLY** | Landlock + seccomp, without namespaces | Filesystem policy, environment filtering, process hardening, network-off | No mount/PID/network namespace; relay modes are refused |
| **macOS** | Seatbelt through `/usr/bin/sandbox-exec` | Filesystem policy and network-off spawn path | `sandbox-exec` is deprecated and undocumented; FSEvents is change-only |
| **Windows** | Windows 11 experimental process sandbox/AppContainer + restricted low-integrity token + Job Object | Capability-gated network-off process launch with inherited stdio | Conditional backend, not a Linux-equivalent fallback; missing APIs stop launch |

The core path does not self-elevate. Linux needs no root when the host permits
the required unprivileged setup. Optional Windows WFP, ETW, Event Log,
minifilter, or Windows Sandbox integrations remain capability/privilege gated
and are never silently enabled. Details:
[docs/platform-backends.md](docs/platform-backends.md).

<details>
<summary><strong>Linux tier difference (FULL vs FS-ONLY)</strong></summary>

| | FULL | FS-ONLY |
| --- | --- | --- |
| Secret handling | File-bind and empty-tmpfs overlays before Landlock | Bounded project enumeration; errors instead of widening access when it cannot complete |
| Descendants | PID-namespace supervisor contains and reaps them | Private process group + `PR_SET_PDEATHSIG`; a `setsid()` grandchild can outlive cleanup |
| Network | Off, allowlist, strict, Git SSH relay | Off only |
| Compatibility | Requires usable unprivileged namespaces and private `/proc` | Smaller boundary with fewer host requirements |

</details>

<a id="profiles-and-policy"></a>

## Profiles and policy

Named agent presets (`codex`, `claude`, `aider`, `cursor`, `cline`,
`opencode`, `copilot`, `custom`) add narrowly scoped compatibility reads; they
never turn off the base policy.

| Profile | Read/write posture | Use when |
| --- | --- | --- |
| `default` | Project and temp writes; common system/toolchain/cache reads | Normal local development |
| `strict` | Project writes; minimal system/runtime reads | Reduce ambient access |
| `audit` | Same filesystem posture as `default` | Pair with event feeds and reports |
| `permissive` | Wider system/toolchain reads; secrets remain denied | Compatibility troubleshooting |

```console
vetto profiles
vetto --profile strict -- codex exec "review this change"
```

<details>
<summary><strong>Minimal vetto.toml</strong></summary>

```toml
[metadata]
name = "my-project"
extends = "default"

[filesystem]
allow_write = ["$PROJECT", "/tmp"]
allow_read = ["$HOME/.cargo/registry"]

[display_only_deny]
paths = ["$PROJECT/.env", "$HOME/.ssh"]

[environment]
pass_through = ["EDITOR", "GIT_AUTHOR_NAME"]

[conditions]
branch = ["main"]
file_exists = ["package.json"]
```

Project policy is loaded only from a non-symlink `vetto.toml`; `--policy`
adds another layer. Unknown tables and fields are errors. Network, reporting,
and CI remain CLI settings: `[network]`, `[project]`, `[secrets]`,
`[agent_overrides]`, and `[ci]` are not accepted policy tables. See
[docs/profiles.md](docs/profiles.md).

</details>

<details>
<summary><strong>Isolated multi-agent sessions</strong></summary>

Each manifest entry receives its own policy resolution, backend, process
container, event stream, output buffer, and report directory. Commands are
argv arrays rather than shell strings.

```toml
version = 1
report_dir = ".vetto-reports"

[[agents]]
name = "lint"
command = ["cargo", "clippy", "--all-targets"]
profile = "strict"
net = "off"

[[agents]]
name = "review"
command = ["codex", "exec", "review this change"]
profile = "default"
net = "off"
observe_seccomp = true
```

```console
vetto multi --manifest vetto-agents.toml
```

The split-pane runtime currently launches on Unix. Windows fails closed
instead of silently running an uncontained multi-agent session.

</details>

## Rescue local sessions

The same package ships a provider-neutral, **copy-only recovery surface** for
damaged or interrupted agent sessions: bounded discovery, read-only
diagnosis, and verified snapshots that never touch source state.

```console
# Discover local Codex sessions
vetto rescue --json scan

# Diagnose a session read-only
vetto rescue diagnose sessions/2026/08/23/session.jsonl

# Copy a verified recovery snapshot
mkdir recovery
vetto rescue snapshot session.jsonl --output recovery/session.jsonl

# Claude adapter: explicit root, read-only and copy-only (experimental)
vetto rescue --adapter claude --root ~/.claude --json scan
```

Safety guarantees: Rescue never reads `auth.json` or `config.toml`, follows
session symlinks, overwrites an existing destination, or writes inside the
original agent state root. Ambiguous or changing inputs fail closed. The
public JSON contract lives in
[`docs/schema/rescue-output-v1.schema.json`](docs/schema/rescue-output-v1.schema.json);
operational details and support levels are in
[docs/field-testing.md](docs/field-testing.md) and
[ADR 0001](docs/adr/0001-universal-rescue-architecture.md).

Codex Rescue development has moved into Vetto. The standalone
[`shleder/codex-rescue`](https://github.com/shleder/codex-rescue) repository
remains public as historical compatibility evidence; new installations use
only `npm install --global @shleddy/vetto`.

<a id="limits"></a>

<p align="center">
  <img src="./assets/readme/section-limits.svg" width="100%" alt="03 Know the gaps: documented limits and fail-closed behavior are part of the product">
</p>

## What vetto does not promise

- Observation is not complete auditing. Linux deny feeds may be unavailable
  without usable seccomp user-notify or audit privileges; enforcement remains
  active.
- Linux FS-ONLY cannot contain a `setsid()`-detached grandchild as strongly as
  the FULL PID namespace.
- macOS FSEvents does not reveal file reads or Seatbelt denials, and a
  SIGKILLed vetto can leave process-group orphans.
- Linux allowlist traffic is designed for proxy-shaped protocols. Direct
  non-proxy protocols fail closed unless an explicit relay helper exists.
- Windows is capability-gated and experimental. It currently has no domain
  allowlist relay or multi-agent runtime in the core backend.
- A hostile kernel, root/administrator outside the sandbox, physical access,
  and a compromised vetto binary are out of scope.
- No performance percentage is promised. Measurement rules live in
  [docs/performance.md](docs/performance.md).

### Deliberate anti-features

No persistent daemon. No OPA/Rego engine. No cloud or telemetry. No web
dashboard. No TLS MITM or CA injection. No root fallback. No Docker/VM
dependency in the core path. No report or event feed that can widen policy.

The complete model is in [SECURITY.md](SECURITY.md),
[ARCHITECTURE.md](ARCHITECTURE.md), and
[docs/threat-model.md](docs/threat-model.md).

## Documentation

| Start | Understand | Integrate |
| --- | --- | --- |
| [Install](docs/tutorials/installing.md) | [Architecture](ARCHITECTURE.md) | [CI/CD](docs/ci-cd.md) |
| [Run Codex](docs/tutorials/codex.md) | [Security](SECURITY.md) | [Network](docs/network.md) |
| [Profiles](docs/tutorials/profiles.md) | [Threat model](docs/threat-model.md) | [Agent presets](docs/agents.md) |
| [TUI](docs/tutorials/tui.md) | [Platform backends](docs/platform-backends.md) | [Multi-agent](docs/tutorials/multi-agent.md) |

## Contributing

Read the architecture and security boundary before changing a backend.
Preserve fail-closed behavior, keep enforcement separate from observation,
add capability-aware tests, and update the documented guarantee or limitation
with the code.

## License

Apache License 2.0. See [LICENSE](LICENSE).
