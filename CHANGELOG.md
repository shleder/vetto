# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versioning follows SemVer.

## [Unreleased]

### Added

- **Tier 2 Network Suite (Features 13–24)**:
  - Ecosystem network presets (`net_presets = ["npm", "git", "pip", "huggingface"]`) expanding common package registries and APIs.
  - Wildcard domain rules (`*.example.com`) strictly covering subdomains only without matching the base domain.
  - CIDR network rules (`allow_cidr = ["10.0.0.0/8"]`) validated against pinned IP addresses.
  - `--net=ask` interactive confirmation mode with session caching and fail-closed non-TTY fallback.
  - DNS resolution and egress connection logging with byte counts in JSONL events and session reports.
  - DoH/DoT blocking for top providers and DoT port 853 in allowlist/off modes.
  - Per-domain transfer quotas (`net_quota = { "api.openai.com" = "100mb" }`) with byte counting and connection teardown.
  - Landlock TCP port access control rules (`net_ports = { allow_tcp_connect = [...], allow_tcp_bind = [...] }`) on Landlock ABI 4+.
  - Upstream `HTTP_PROXY` and `HTTPS_PROXY` broker routing with `NO_PROXY` bypass without leaking variables to the sandboxed child.
  - Unix domain socket access policies (`unix_sockets = { allow = [...] }`).
  - Full IPv6 (AAAA) resolution and connection support with pinned address discipline.
  - Aggregated session network summary emitted in notices and report statistics.

## [0.2.5] — 2026-08-30

### Added

- Boundary verification battery: `vetto verify` runs secret-path, network and
  write-outside checks inside a throwaway sandbox without running any agent,
  and `--verify` runs the same battery against the resolved policy before the
  agent starts, refusing to launch on any leak (fail-closed).
- `--timeout <DURATION>` kills the sandboxed session at the deadline and exits
  124 (mirroring GNU timeout). Enforced with `--tui=none`; other TUI modes
  warn and ignore it. A `session_timeout` event lands in JSONL and reports.
- `--limits cpu=,as=,procs=,nofile=,fsize=` resource ceilings merged
  strictest-wins with policy limits; enforced via rlimits on Linux, the Job
  Object on Windows and best-effort setrlimit in the macOS child (Darwin
  refuses several ceilings per host configuration; refusals are surfaced on
  stderr, never silently ignored).
- `vetto policy explain` prints the effective merged policy (tier, network,
  roots, masked secrets, limits, environment); `vetto policy lint` flags
  dangerous configurations (home-wide write/read roots, no-op denies, missing
  limits).
- fs-only sessions with `display_only_deny` paths now state the honest costs
  up front on stderr and as a session notice: secrets are allowlist-carved
  (entry names may stay visible) and files created directly at a write root
  cannot be read back in the same session.
- macOS hardening round: `--net=strict` is rejected explicitly instead of
  silently running as `off`; a forked kqueue watchdog kills the agent when
  vetto itself is SIGKILLed; and the seatbelt profile moved to the
  write-isolation + net=off model after a bisect matrix showed the old
  fragmented-read `(deny default)` profile aborted every exec'd binary with
  a silent SIGABRT on current macOS. Read isolation on macOS is a known,
  documented limitation (secret reads are not isolated yet) — narrowing
  reads without breaking process startup is the top roadmap item.

### Changed

- CI is honest now: `cargo fmt --check` is blocking, clippy denies warnings
  for crate code (the crate-wide allow-all is gone; unwired capability
  surfaces keep a scoped dead_code exemption), llvm-cov publishes an lcov
  artifact, and cargo-deny checks advisories and licenses.
- Windows policies with `display_only_deny` no longer refuse to launch
  outright: the launch proceeds when no secret path overlaps a granted root
  (the spec is default-deny) and fails with an actionable message only on a
  real overlap.
- macOS rejects `--net=strict` explicitly instead of silently running it as
  `off`.

## [0.2.4] — 2026-08-28

### Added

- Grant read scope to the resolved agent binary directory and include user
  toolchains in the default profiles, so a wrapped agent can execute its own
  interpreter without a hand-written policy.
- Add a Claude Code slash-command plugin under `plugins/claude`.
- Download a precompiled native binary in the GitHub Action, falling back to a
  source build when no matching artifact exists.

### Removed

- Drop the vendored `components/rescue-legacy` Python tree. Its MIT provenance
  and commit ancestry stay recorded in `THIRD_PARTY_NOTICES.md`.

### Fixed

- Fix the build, which was broken on every target since 0.2.3. A leftover
  `pub mod docker;` declaration pointed at a deleted file (`E0583`), and the
  agent-binary read-scope change mutated an immutably bound policy (`E0596`).
  No 0.2.4 artifact could be produced until both were corrected.
- Use explicit CRLF line disciplines and flush stdout/stderr before the TUI
  takes over the terminal, which previously produced interleaved output.
- Restore the test schema files required by CI and correct the README badges.
- Correct the `vetto rescue --adapter` and `--root` help text, which named only
  two adapters and claimed a root argument was required for all but Codex.
- Stop documenting a `vetto rescue checkpoint` command; no such subcommand
  exists. The real set is `scan`, `diagnose`, `snapshot`, `fork`, `repair` and
  `rollback`.
- Align the Homebrew, Chocolatey, RPM, Debian and AUR recipes, the npm readme
  and the VS Code lockfile with the published release instead of a mix of
  0.2.0-alpha.2, 0.2.0, 0.2.2 and an unpublished version.

## [0.2.3] — 2026-08-28

### Added

- Implement the 30 tracked engineering steps (phases 1-5) across the policy,
  sandbox, observation, PTY and report modules.
- Update the VS Code extension to expose `vetto hook install`, a rescue
  quick-pick and a status-bar entry.

### Fixed

- Drain and flush the PTY master on exit and correct the carry-over token
  check, which previously dropped trailing agent output.
- Correct PTY redactor priority, ANSI parser reset, entropy character masking
  and the WAL test expectations.
- Resolve cross-platform compile types and the macOS `RcBlock` closure.

## [0.2.2] — 2026-08-27

### Added

- Add zero-config AI Agent CLI Auto-Detection: `vetto -- <command>` automatically
  identifies known AI coding agents (Codex, Claude Code, Cursor, Aider, Copilot, Cline,
  OpenCode) from the command name and applies their matching sandbox profile and socket
  boundaries without needing `--agent <name>`.
- Add smart project policy initialization (`vetto init`): auto-detects build systems
  (Rust, Node.js/TypeScript, Python, Go) and agent configs (`.cursor/`, `.claude/`,
  `codex.toml`, `.aider.conf.yml`) to generate a customized, ready-to-run `vetto.toml`
  with cache read allowances and secret masking.
- Add comprehensive heavy-load and fuzzing test suite (`tests/integration/heavy_scenarios.rs`)
  exercising 120+ corrupted/truncated session states, 150+ suspicious command classifications,
  and cross-platform agent invocation matrices.

## [0.2.1] — 2026-08-27

### Added

- Add subagent capability isolation and IPC boundary enforcement: block access to
  parent control plane sockets (`app_server.sock`, `*.sock`, `*.ipc`), session state
  databases (`state_*.sqlite`), and local devtools/debugger ports (`9222`, `9229`, `5678`).
- Add high-severity classification for network interception and raw socket tools (`socat`,
  `ncat`, `chisel`, `tcpdump`).
- Add heavy payload and memory dump observation (`core.*`, `.hprof`, `.heapsnapshot`, `.dump`).
- Modernize and beautify README homepage layout according to `beautify-github-readme`
  standards with architecture diagrams, threat matrices, and subagent guard sections.

## [0.2.0] — 2026-08-25

### Fixed

- Make imported Codex Rescue batch doctor discovery recursive across nested
  active, archived, and subagent JSONL trees; shallow discovery previously
  omitted date-partitioned rollouts from `doctor --all` and `--changed`.
- Restore bounded Codex semantic diagnostics in the Rust adapter for invalid
  persisted item IDs, unknown operational schemas, and unfinished tool calls.
- Add read-only SQLite inventory/projection diagnostics for Windows path
  identity divergence, missing/index-only rollouts, empty sidebar metadata,
  wedged projection cursors, and unknown projection state.

### Changed

- Clarify that Codex Rescue development and npm installation have moved to
  Vetto while the standalone repository remains public compatibility history.

## [0.2.0-alpha.2] — 2026-08-23

### Added

- Freeze the provider-neutral rescue adapter contract v1 and conformance
  checks for bounded, copy-only recovery.
- Add an experimental Claude read-only adapter with explicit-root discovery,
  opaque JSONL diagnosis, credential-path exclusion, and verified snapshots.
- Add Antigravity compatibility-gate documentation; unsupported formats fail
  closed instead of being guessed.

### Changed

- Keep user installation npm-only; no source-install path is advertised.
- Harden Codex and Claude discovery with per-session size budgets and stable
  source reads.

## [0.2.0-alpha.1] — 2026-08-23

First integration alpha for universal local-agent recovery.

### Added

- Provider-neutral `vetto rescue scan`, `diagnose`, `snapshot`, and `fork`
  commands with a bounded Codex reference adapter.
- Copy-only session snapshots with exclusive, symlink-safe creation and
  SHA-256 verification outside the original agent state root.
- A versioned adapter manifest schema, recovery security contract, imported
  Codex Rescue history, MIT attribution, and history secret-scan baseline.
- Cross-platform rescue integration tests and structured field-test intake.

### Security

- Disable direct `INSERT`, `INSERT OR REPLACE`, projection-cursor updates, and
  all other production writes to vendor-derived SQLite state, including from
  hand-edited recovery plans and Alpha7 autopilot repair paths.
- Reject symlinked session entries, ambiguous selectors, oversized scans,
  oversized records, source changes during capture, existing snapshot
  destinations, and destinations inside the original agent state root.

### Distribution

- Publish prerelease builds on the npm `next` tag. Stable `0.1.x` remains on
  `latest`.

## [0.1.0] — 2026-08-23

First public release of the daemon-less sandbox and security layer for local
AI coding agents.

### Distribution

- Publish the cross-platform `@shledery/vetto` npm package with bundled native
  executables for Linux x64/ARM64, macOS x64/Apple Silicon, and Windows x64.
- Publish matching native archives and SHA-256 checksums in the GitHub release.
- Keep crates.io publication out of this release; Cargo remains the build and
  source-install manifest, with its version aligned to `0.1.0`.

### Security

- Reject unknown policy fields and add bounded built-in inheritance,
  conditions, project layers, agent variables and resource ceilings.
- Block cross-process access, mount teardown, io_uring/userfaultfd and selected
  kernel-control syscalls in both Linux tiers with architecture-aware syscall
  constants.
- Sanitize JSON/SARIF content and harden JSONL/report creation and retention
  against symlink/race paths.
- Validate and pin broker-side IPv4/IPv6 DNS answers, including metadata,
  mapped and NAT64 destinations.

### Added

- Strict domain+port networking, brokered Git-over-SSH, SARIF, report compare,
  fail-on-block thresholds, configurable report storage and shell completions.
- Agent presets, version probes, multi-agent manifests, independent sandboxes,
  split-pane TUI and combined reports.
- Adaptive Linux visibility, expanded seccomp observation and explicit opt-in
  descriptor substitution API.
- Capability-gated Windows and macOS backends/observers.
- VS Code and JetBrains integrations, a composite GitHub Action, source-only
  package recipes, tutorial outlines and reproducible benchmark targets.

### Changed

- FSEvents is described and emitted only as a coarse filesystem-change feed,
  never file-read or Seatbelt-denial visibility.
- Performance documentation no longer presents estimates as measured product
  overhead.

### Initial milestone

The crate was scaffolded under the working name `leash` before its public
rename to `vetto`; pre-rename history is preserved below.

### Enforcement
- Linux Tier FULL: Landlock (ABI 1–3) + USER/MOUNT/PID/NET/IPC namespaces,
  mount-namespace secret overlays (bind `/dev/null` / empty tmpfs), pidns
  init supervisor with alive-pipe orphan kill, PDEATHSIG belt-and-suspenders.
- Linux Tier FS-ONLY: Landlock + seccomp-BPF network block + load-time
  project-tree enumeration masking (READ stripped from write roots).
- Fail-closed everywhere: no sandbox ⇒ no agent, no unsandboxed fallback.
- macOS: Seatbelt profile generation (deny default + allows + trailing
  carve-outs) via sandbox-exec; honest stubs for FSEvents/Endpoint Security.

### Network
- `--net=off` default: netns (FULL) / seccomp socket block (FS-ONLY).
- `--net=allowlist:d1,...` (FULL only): in-netns HTTP CONNECT + socks5h
  relay, host-side broker with remote DNS + domain checks, SCM_RIGHTS data
  sockets, blackholed resolv.conf. No TLS interception, ever.

### Visibility & reporting
- `--tui=statusline` PTY pass-through (rows−1 sizing, DECSTBM region, SIGWINCH
  propagation, `Ctrl+]` ratatui overlay); `--tui=full` headless dashboard;
  `--tui=none`/`--ci`.
- Best-effort `/proc` fd poller; `--observe-seccomp` user-notify tap
  (CONTINUE-only, policy-classified); best-effort kernel-audit reader;
  persistent honest notices.
- JSONL event log, self-contained HTML/MD/JSON reports, BEST-EFFORT secret
  sanitizer.
- `vetto doctor [--probe]`, `vetto init`, `vetto profiles`.

### Pre-rename history (`leash`)
- Initial scaffold (CLI/policy/events skeletons) — see git history.
