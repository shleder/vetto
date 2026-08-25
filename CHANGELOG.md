# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versioning follows SemVer.

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

- Publish the cross-platform `@shleddy/vetto` npm package with bundled native
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
