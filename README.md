# vetto

`vetto` is a daemon-less, agent-agnostic security boundary for locally
invoked AI coding agents. It applies one operator-controlled policy around
Codex, Claude Code, Aider, custom scripts, and other command-line agents,
then writes post-session audit artifacts.

The boundary is enforced by the operating system: Landlock, namespaces and
seccomp on Linux; Seatbelt on macOS; and a capability-gated Windows process
sandbox where the required Windows 11 APIs are present. vetto does not
replace an agent's built-in sandbox. It adds a consistent outer policy,
network default-deny, environment filtering, terminal visibility, and reports
across agents.

There is no persistent daemon, cloud service, telemetry, phone-home, OPA/Rego
engine, TLS MITM, CA injection, Docker dependency, or root requirement in the
core path. Per-session relay/helper processes may exist while a session is
running; they are not a persistent service.

## Positioning

Modern agents increasingly ship their own sandbox. vetto is the uniform layer
above those heterogeneous built-ins, including agents whose built-in policy is
older, optional, or absent.

| Competitor / alternative | Overlap | vetto's edge |
|---|---|---|
| AgentJail | High | One daemon-less binary; no OPA/Rego daemon |
| Watchfire | High | One binary; no `watchfired` service |
| ZeroClaw | Medium | Terminal-native TUI and post-session reports; no web dashboard |
| landrun | Medium | Agent presets, TUI, audit formats, and macOS backend |
| Agent built-in sandboxes (Codex, Claude Code, etc.) | High | One policy and report model across any agent; defense in depth that the operator controls |

## Quick start

From a source checkout:

```console
cargo install --locked --path .
vetto doctor
cd my-project
vetto -- codex exec "refactor auth module"
```

Replace `codex exec ...` with `claude -p ...`, `aider ...`, `opencode ...`, or
any executable command. `vetto doctor` reports the backend and Linux tier
before a session starts. `vetto init` writes a starter `vetto.toml` in the
current directory.

For an interactive agent, keep the default `--tui=statusline`. For a
headless command or CI, use `--tui=full` or `--tui=none`; `--ci` implies
`--tui=none` and prints a final JSON summary.

## How it works

```text
operator command
      |
      v
vetto: policy layers -> capability probe -> fail-closed setup
      |
      +-- Linux FULL: Landlock + USER/MOUNT/PID/NET/IPC namespaces + seccomp
      +-- Linux FS-ONLY: Landlock + seccomp, no namespaces
      +-- macOS: Seatbelt profile via sandbox-exec
      +-- Windows: experimental AppContainer/process sandbox + Job Object
      |
      v
agent and descendants -> TUI / JSONL / reports (observation only)
```

Enforcement is installed before the agent is executed and is inherited by
descendants. Observation never decides whether an operation is allowed.

### Linux capability tiers

| | FULL (preferred) | FS-ONLY (fallback) |
|---|---|---|
| Required capabilities | Landlock (kernel support, normally kernel >= 5.13) and a complete unprivileged user-namespace setup; `doctor` probes the namespace stack and private `/proc` | Landlock plus unprivileged seccomp filters; no user namespaces or mount/PID/network namespaces |
| Filesystem | Landlock allowlist. Intra-project secrets are masked with `/dev/null` file binds or empty tmpfs directory overlays before Landlock is applied | Landlock allowlist. The loader enumerates the project and omits resolved secret-shaped entries; overlays are unavailable |
| Process lifecycle | vetto's PID-namespace supervisor reaps and contains descendants; killing it kills the namespace | `PR_SET_PDEATHSIG` and a private process group; a `setsid()`-detached grandchild can outlive cleanup |
| `--net=off` | Interface-less network namespace plus seccomp socket-family hardening | Seccomp rejects non-Unix socket families |
| `--net=allowlist` / `strict` | CONNECT relay and host-side broker; DNS and destination validation happen outside the sandbox | Refused before launch; these relay modes require FULL |
| Privileges | No root is required when the host permits the unprivileged setup | No root is required when Landlock and seccomp are available |

If Landlock is unavailable, or neither tier can be established, vetto refuses
to run the agent. It never falls back to unsandboxed execution. FS-ONLY is a
real fallback with a smaller isolation boundary, not a claim that every Linux
host has the same guarantees.

### Filesystem and secret handling

Landlock makes decisions in the VFS on resolved inodes; path races and symlink
tricks do not become a userspace policy decision. Landlock is additive,
however, so it cannot subtract `.env` from an otherwise allowed project tree.
On Linux FULL, vetto therefore masks each resolved deny path in the private
mount namespace before applying Landlock. Home credentials remain denied by
omission from read roots. `~/.gitconfig` is intentionally read-only in the
default/audit/permissive profiles because Git identity is commonly needed.

The Linux seccomp hardening filter is inherited by descendants and blocks
mount teardown/replacement and selected kernel-control interfaces including
`umount2`, `io_uring`, `userfaultfd`, `ptrace`, `process_vm_*`, `bpf`, and
`perf_event_open`. These blocks can make debuggers, nested container tools, or
kernel tracing workloads unusable.

### Observation and TUI

- `--tui=statusline` (default) leaves the agent in a PTY and reserves one row
  for tier, network mode, counters, and the last event. `Ctrl+]` opens the
  scrollable event overlay.
- `--tui=full` owns an alternate-screen dashboard with agent output, filters,
  blocked/files/network/suspicious views, activity counters, pause/resume,
  and bounded event export. `q` asks before terminating the agent.
- `--tui=none` leaves stdio inherited. This is the portable choice for batch
  commands and CI.
- Linux allowed-file activity comes from a best-effort process/fd poller.
  Blocked attempts are available only when a readable kernel audit feed or
  `--observe-seccomp` is available. A missing feed does not weaken
  enforcement; it only means some denied attempts will not appear in the UI
  or reports.
- macOS FSEvents is a delayed/coalesced change feed. It does not report file
  reads and does not expose Seatbelt denials. Optional Endpoint Security is
  capability/entitlement/privilege gated and is not the Seatbelt enforcement
  boundary.

## Supported agents

The wrapper accepts any executable command. These names select built-in
compatibility presets with narrowly scoped read roots; they do not disable the
base policy.

| Agent | Typical command | Built-in isolation | Preset | Recommended UI / notes |
|---|---|---|---|---|
| OpenAI Codex CLI | `codex`, `codex exec` | Yes; platform/config dependent | `codex` | `statusline` interactive; `full`/`none` for `exec` |
| Claude Code | `claude`, `claude -p` | Optional/tool-specific | `claude` | `statusline` interactive; `full`/`none` for `-p` |
| Aider | `aider` | No uniform OS boundary assumed | `aider` | Keep vetto as the outer enforcement boundary |
| Cursor Agent | `cursor-agent` | Implementation/version dependent | `cursor` | Prefer `full`; endpoint requirements are task-specific |
| Cline | User-configured CLI/extension command | Unknown | `cline` | Provide the actual executable explicitly |
| OpenCode | `opencode` | Its permission model is not treated as an OS boundary | `opencode` | Provider endpoints must be allowed explicitly |
| GitHub Copilot CLI | `copilot` | Implementation/version dependent | `copilot` | GitHub endpoints are not allowed by default |
| Custom process | Any executable | Unknown | `custom` | Use `--tui=none` for scripts and CI |

Use `vetto --agent codex -- codex exec "task"` for a preset. `doctor
--check-agent NAME` probes an executable's version output; it is not a
version compatibility guarantee. Built-in agent sandboxes are defense in
depth: vetto does not try to detect, disable, or weaken them.

## Profiles

```console
vetto profiles
vetto --profile strict -- codex exec "review this change"
vetto --profile audit --observe-seccomp --jsonl session.jsonl \
  --report html,md,json -- codex exec "review this change"
```

| Profile | Write roots | Read surface | Use when |
|---|---|---|---|
| `default` | `$PROJECT`, `/tmp`, `/dev/null` | System paths, common toolchains and dependency caches | Balanced local development |
| `strict` | `$PROJECT`, `/dev/null` | Minimal system/runtime paths; no caches or Git identity by default | Reduce ambient read access |
| `audit` | Same as `default` | Same as `default` | Make audit-focused sessions explicit; pair with observation/reports |
| `permissive` | `$PROJECT`, `/tmp`, `/dev/null` | Wider `/etc` and toolchain read surface | Compatibility troubleshooting; secrets remain denied |

All built-in profiles use an environment allowlist and secret deny patterns.
`display_only_deny` is an input to the platform-specific masking/enumeration
path, not a replacement for the kernel boundary. See
[docs/profiles.md](docs/profiles.md) for inheritance and conditions.

## Network modes

Network is `off` by default and is enforced for descendants.

```console
# No external network (all supported backends)
vetto --net=off -- agent command

# Linux FULL: proxy-aware HTTP CONNECT/SOCKS traffic to listed domains
vetto --net=allowlist:api.github.com,registry.npmjs.org -- agent command

# Linux FULL: exact domain + port rules
vetto --net=strict:registry.npmjs.org:443,api.github.com:443 -- agent command
```

On Linux relay modes, the child has no general route. A loopback relay passes
the requested host/port over an inherited Unix socket to a host-side broker.
The broker resolves DNS, rejects loopback/private/link-local/metadata and
other special-use addresses, pins an approved destination for that
connection, and pumps opaque bytes. There is no SNI parsing, TLS decryption,
CA injection, or TLS MITM. Non-proxy-aware protocols fail closed.

Git over SSH has an explicit Linux relay helper:

```console
vetto --net=allowlist:github.com --git-ssh -- git fetch origin
vetto --net=strict:github.com:22 --git-ssh -- git fetch origin
```

`--git-ssh` configures a per-command OpenSSH `ProxyCommand`; it is not a
persistent daemon and is Linux-only. The host must be allowed, and strict
mode must include the requested port.

Platform limits are intentional: Linux FS-ONLY rejects relay modes; macOS
currently supports Seatbelt network-off only (`--net=allowlist` is rejected,
and the current Seatbelt path does not implement a strict allowlist relay);
the Windows process backend currently accepts `--net=off` only. See
[docs/network.md](docs/network.md) for the broker boundary and DNS model.

## Configuration: `vetto.toml`

`vetto` automatically loads a non-symlink `vetto.toml` in the project root.
`--policy PATH` adds an explicit TOML layer after that project layer; the
loader is additive, so a later layer cannot remove a base deny rule or
environment allowlist. Unknown keys are rejected.

```toml
[metadata]
name = "my-project"
description = "Project policy"
extends = "default"       # a built-in profile name, or an array of names

[filesystem]
allow_write = ["$PROJECT", "/tmp"]
allow_read = ["$HOME/.cargo/registry"]

[display_only_deny]
paths = ["$PROJECT/.env", "$HOME/.ssh"]

[environment]
pass_through = ["EDITOR", "GIT_AUTHOR_NAME"]

[limits]
cpu_seconds = 3600
address_space_bytes = 8589934592
processes = 256
open_files = 1024

[conditions]
branch = ["main"]
file_exists = ["package.json"]
project_contains = ["Cargo.toml"]
```

`$PROJECT` and `$HOME` are resolved by vetto. `$AGENT` is available only
with a named preset (`codex`, `claude`, `aider`, `cursor`, `cline`,
`opencode`, `copilot`, or `custom`). Conditions are bounded checks, not a
general policy language. Network, report, and CI settings are CLI options;
`[network]`, `[project]`, `[secrets]`, `[agent_overrides]`, and `[ci]` are not
part of the TOML schema.

## Multi-agent mode

Each manifest entry gets its own preflight, policy, backend instance, process
container, event stream, output buffer, and report directory. Commands are
argv arrays, never shell strings.

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

Run it with:

```console
vetto multi --manifest vetto-agents.toml
```

The full multi-agent TUI provides split panes, selection, pause/resume,
per-agent termination, and a combined aggregate report. The compatibility
form `vetto --multi --agent lint=/usr/bin/cargo --agent test=/usr/bin/cargo`
accepts executable-only entries; use a manifest for arguments and per-agent
policies. The runtime currently supports multi-agent launch on Unix; Windows
fails closed rather than launching without the requested isolation.

## Platform support and privileges

| Platform | Enforcement path | Requirements and supported scope | Privilege boundary |
|---|---|---|---|
| Linux | FULL or FS-ONLY as selected by `doctor` | Landlock plus either the complete unprivileged namespace stack (FULL) or unprivileged seccomp (FS-ONLY). Relay modes and `--git-ssh` require FULL. | Core path is unprivileged; no root fallback |
| macOS | `/usr/bin/sandbox-exec` Seatbelt | `sandbox-exec` must exist. Network-off is the implemented spawn path. FSEvents is delayed/change-only. | Seatbelt session is unprivileged; optional Endpoint Security needs a signed entitlement and platform privilege/TCC gates and is not enforcement |
| Windows | Windows 11 experimental process sandbox/AppContainer plus restricted/low-integrity token and Job Object | `processmodel.dll!Experimental_CreateProcessInSandbox`, AppContainer APIs, token APIs, and Job Object kill-on-close must probe successfully. Core backend currently accepts network-off and inherited stdio only; use `--tui=none`/`--ci`. | No self-elevation. Optional firewall/WFP, ETW, Event Log, minifilter, or Windows Sandbox integrations are capability-gated and not silently enabled |

Windows is therefore supported as a conditional, experimental backend, not as
a promise of a Linux-style fallback tier. If the required process-sandbox
export is unavailable, vetto refuses to run an ordinary unsandboxed process.
Policies with resolved deny paths may
also be rejected because the current Windows process-sandbox schema has no
verified denied-path field; this is fail-closed behavior.

## Reports and CI

Request post-session formats with `--report html,md,json,sarif`; JSONL event
logging is enabled separately with `--jsonl PATH`.

```console
vetto --ci --tui=none --profile=strict --net=off \
  --report=json,sarif --report-dir=.vetto/reports \
  --fail-on-block -- agent command
```

Reports default to `.vetto/reports` and use private, collision-resistant
filenames. Retention defaults to 50 generated reports and can be adjusted
with `--report-retention`, `--report-max-age-secs`, or the cleanup flags.
HTML is self-contained; JSON and SARIF are intended for automation. The
sanitizer is explicitly best-effort: false positives and false negatives are
possible. Reports contain observed events, not proof that every denied
operation was visible.

See [docs/ci-cd.md](docs/ci-cd.md) for the repository action and generic CI
usage, and [docs/schema/session-stats.schema.json](docs/schema/session-stats.schema.json)
for the JSON shape.

## Security model and known limitations

The security boundary and threat assumptions are documented in
[SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).
Important operational limits are:

- Enforcement is kernel/OS policy; TUI, `/proc` polling, FSEvents, ETW,
  kernel audit, seccomp user-notify, JSONL, and the sanitizer are observation
  or reporting paths.
- Linux blocked-attempt feeds are usually unavailable to an unprivileged
  process unless `--observe-seccomp` is usable. A persistent notice is shown;
  enforcement remains active.
- Linux FS-ONLY has no mount/PID/network namespace. A `setsid()`-detached
  grandchild can outlive process-group cleanup, and the bounded project
  enumeration cannot provide FULL's mount overlays.
- macOS Seatbelt relies on Apple's deprecated and undocumented
  `sandbox-exec`; denials are invisible to FSEvents, and a SIGKILLed vetto may
  leave process-group orphans.
- Linux allowlist traffic is for proxy-shaped protocols. Git SSH requires the
  explicit Linux-only helper. Direct non-proxy protocols have no route.
- Windows uses different, experimental primitives. It has no Landlock or
  Seatbelt, no WIN-BASIC fallback in this implementation, no Windows multi
  runtime, and no domain allowlist relay in the core backend.
- The agent and its dependencies are treated as arbitrary code. A hostile
  kernel, root/administrator outside the sandbox, physical access, and a
  compromised vetto binary are out of scope.
- No performance percentage or benchmark result is promised. See
  [docs/performance.md](docs/performance.md) for reproducible measurement
  rules.

Fail-closed is a design rule: if the selected enforcement boundary cannot be
established, the agent does not run.

## Contributing

Read [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and the
relevant platform documentation before changing a backend. Keep enforcement
separate from observation, preserve fail-closed behavior, add conditional
tests for platform capabilities, and update the documentation when a
guarantee or limitation changes. Do not add a daemon, telemetry, TLS MITM,
or a silent unsandboxed fallback.

## License

Apache License 2.0. See [LICENSE](LICENSE).
