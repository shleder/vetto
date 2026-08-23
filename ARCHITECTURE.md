# vetto architecture

vetto is the uniform operator-controlled boundary above heterogeneous coding
agents and their built-in sandboxes. One invocation owns one session (or one
explicit multi-agent group), starts no persistent daemon, uses no cloud
service, and sends no telemetry.

## Trust boundaries and startup order

The agent command and every descendant are untrusted. The operator, vetto
binary, OS kernel and policy selected before launch are trusted. Report paths
and network brokers stay outside the sandbox filesystem/network boundary.

Startup order is load-bearing:

1. Parse CLI/project policy, resolve concrete paths and executable argv, and
   prepare PTY/pipes while the process is single-threaded.
2. Detect a backend and preflight every required capability. A missing
   enforcement primitive aborts before the command runs.
3. Fork/create the sandbox, install irreversible restrictions, then `execve`
   or the platform equivalent.
4. Only after all required sandbox processes exist, start observation,
   aggregation, report and TUI worker threads.
5. On exit, terminate/reap the entire platform process container, finalize
   sanitized reports outside the sandbox, and return the agent/failure status.

This ordering avoids unsafe post-thread `fork()` paths and prevents a partial
multi-agent launch from becoming an unsandboxed fallback.

## Policy pipeline

The intended layer order is:

```text
built-in profile ← inherited built-ins ← agent preset ← project vetto.toml ← CLI overrides
```

All TOML structs reject unknown fields. Inheritance accepts built-in names,
not arbitrary paths. Conditions are deliberately bounded (`branch`,
`file_exists`, `project_contains`), and condition scans have path/file/byte
budgets. `$PROJECT`, `$HOME` and a known `$AGENT` root are resolved before
enforcement. Globs become finite concrete paths; they never reach Landlock or
another backend as string patterns.

Environment construction is default-deny. A small built-in compatibility list
and exact names in `[environment].pass_through` are copied into a fresh
environment; the full parent environment is never inherited.

## Linux FULL

FULL requires Landlock and an unprivileged user namespace. A simplified
process/mount layout is:

```text
vetto supervisor (host namespaces)
├─ optional host broker (DNS + allowlist + pinned outbound socket)
└─ sandbox setup: USER + MOUNT + IPC + NET
   ├─ loopback relay (allowlist/strict only)
   └─ PID namespace init
      └─ agent and all descendants
```

Setup makes mounts private, isolates and size-limits `/dev/shm`, restricts the
PID-visible `/proc`, masks resolved secret files with `/dev/null` and secret
directories with an empty tmpfs, then applies Landlock. Secret overlays are
necessary because Landlock is a pure allowlist: it cannot subtract `.env`
from an otherwise allowed project tree.

Immediately before the agent runs, seccomp blocks mount removal/replacement,
cross-process memory/descriptor access, io_uring, userfaultfd and selected
kernel-control interfaces. Resource ceilings are applied at the same boundary.
The PID-namespace init reaps zombies and kills the namespace process tree when
the supervisor disappears.

## Linux FS-ONLY

FS-ONLY is selected when Landlock works but user namespaces do not. It has no
mount, PID or network namespace. Landlock and seccomp still apply and are
inherited by descendants. Network off rejects non-Unix socket families.

Because overlays are unavailable, the loader walks the project and constructs
concrete read rules that omit secret-shaped entries. Traversal errors, symlink
ambiguity and the entry budget fail closed; no “large tree means read all” path
exists. Lifecycle uses `PR_SET_PDEATHSIG`, a parent-race check and a process
group. A deliberately `setsid()`-detached grandchild is the documented cleanup
gap, not an enforcement bypass.

## Network topology

Network off gives FULL an interface-less network namespace and gives FS-ONLY a
socket-family seccomp gate. Allowlist and strict modes use this topology:

```text
proxy-aware client
  → sandbox loopback CONNECT/SOCKS relay
  → inherited AF_UNIX bridge (no host route in sandbox)
  → host broker: domain rule → one DNS lookup → reject unsafe answer set
  → connect to pinned validated IP:port → opaque byte pump
```

Strict rules bind both DNS name and port. On Linux, `--git-ssh` supplies an
OpenSSH `ProxyCommand` that uses the same CONNECT path. The broker does not
parse TLS, SNI or SSH content and never installs a CA. Relay modes require
FULL; FS-ONLY fails closed. The SSH helper is Linux-only. See
[docs/network.md](docs/network.md).

## Observation

Enforcement never consumes observation results.

- Linux allowed operations: recursive `/proc` process/fd scan with adaptive
  50 ms/500 ms/2 s intervals and bounded caches.
- Linux blocked attempts: readable kernel audit when available, otherwise
  optional seccomp user-notify. Notification IDs are validated immediately
  before responses. Default responses continue the syscall so Landlock remains
  the filesystem authority.
- An optional ADDFD substitution API is a distinct behaviour-changing mode,
  disabled by default and not described as observation.
- macOS FSEvents supplies coarse directory-change events, never reads/denials.
- Endpoint Security and Windows ETW are capability/privilege-gated optional
  feeds. The current Endpoint Security path is notify-only and keeps Seatbelt
  as enforcement; it does not claim synchronous AUTH allow/deny enforcement.
  Losing a feed cannot weaken enforcement.

The event bus fans out to the TUI, JSONL sink, statistics and reports. Buffers,
caches and rendering rates are bounded so untrusted event volume cannot grow
memory without limit.

## macOS

The backend generates a Seatbelt profile from the same concrete policy and
invokes `/usr/bin/sandbox-exec`. Profile files use unpredictable names,
exclusive/no-follow creation, private permissions and cleanup. Network off is
Seatbelt-denied. The current Seatbelt spawn path does not wire the standalone
macOS broker helper, so domain allowlist traffic is not advertised here.

FSEvents watches project changes with inherent latency and reports change
labels, not reads or Seatbelt denials. Optional Endpoint Security dynamically
probes the framework, signed entitlement and privilege/TCC gates; unavailable
ES falls back to Seatbelt plus FSEvents and is reported honestly. The current
spawn path supports network-off; `--net=allowlist` is rejected and the
loopback broker helper is not wired into Seatbelt execution. Strict mode does
not provide a macOS allowlist relay. Seatbelt rules are inherited by
descendants. `sandbox-exec` deprecation remains an explicit platform risk.

## Windows

Windows has no Landlock-equivalent, so the backend is capability-based and
conditional:

- the Windows 11 experimental `processmodel.dll` process-sandbox API and
  AppContainer capabilities provide the requested filesystem/process boundary
  when available;
- a restricted primary token and Low integrity remove ambient privilege when
  the optional as-user launch export is present;
- a Job Object with kill-on-close contains descendant lifetime;
- the core launcher accepts `--net=off` only. It does not compile domain
  allowlists to firewall rules and does not silently mutate host firewall/WFP
  state;
- the core launcher currently supports inherited stdio only, so callers should
  use `--tui=none`/`--ci` on Windows;
- ETW, directory-change and handle feeds are observation only;
- Windows Sandbox, WFP/firewall, Event Log and minifilter modules are separate,
  explicit capability-gated integrations. They do not install features,
  register services, start drivers or elevate automatically.

There is no weaker WIN-BASIC fallback in this implementation. Low integrity or
a Job Object by itself is not claimed as filesystem/network isolation. If the
experimental process-sandbox boundary is unavailable, or a policy asks for a
resolved denied-path field that the Windows schema cannot verify, Windows
fails before process creation.

## PTY and TUI

Statusline mode gives an interactive agent a PTY sized to reserve one terminal
row and transparently forwards input/output/resizes. `Ctrl+]` enters the event
overlay. Full mode owns the alternate screen and embeds captured headless
output. Both render only on dirty/event input and cap repaint to five frames
per second.

The shared state contains a bounded event ring, blocked table, accessed-file
tree, network records, activity buckets and session summary. Pause/resume acts
on the platform process container, not a UI-only flag. Exports use the same
safe report/JSONL paths as non-TUI output.

## Multi-agent isolation

A strict manifest represents commands as argv arrays, avoiding a shell quoting
language. All policies, executables, report paths and backend capabilities are
preflighted before launch. Every entry gets its own backend instance,
Landlock/namespaces or platform process container, event bus, output buffer and
report directory. Failure terminates already-created sandboxes. The current
multi-agent runtime is Unix-only; Windows rejects a multi-agent launch rather
than weakening isolation.

The split-pane UI consumes a tagged aggregate stream. Combined reports contain
per-agent sections and comparisons but do not merge enforcement boundaries.

## Reports and storage

JSONL and HTML/Markdown/JSON/SARIF render through the best-effort sanitizer.
On Unix, writers traverse parent directories through `openat` directory fds
with no-follow checks and create final files with exclusive semantics; opened
objects are verified as private regular files. Cleanup is anchored to the exact
report directory and only accepts vetto's generated filename grammar.

## Performance discipline

The benchmark crate measures policy/ruleset preparation, visibility scans,
seccomp-filter/classification primitives, PTY transfer and report rendering.
No overhead percentage is an architectural guarantee. Reproducibility and
publication rules are in [docs/performance.md](docs/performance.md).
