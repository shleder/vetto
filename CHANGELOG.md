# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versioning follows SemVer.

## [Unreleased]

No unreleased changes yet.

## [0.1.0] — 2026-08-23

First public release of the daemon-less sandbox and security layer for local
AI coding agents.

### Distribution

- Publish the cross-platform `vetto` npm package with bundled native
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
