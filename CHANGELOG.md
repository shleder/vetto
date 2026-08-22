# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versioning follows SemVer.

## [0.1.0] — 2026-08-22

First public milestone: daemon-less sandbox + security layer for AI coding
agents. (This crate was scaffolded under the working name `leash` before its
public rename to `vetto`; pre-rename history is preserved below.)

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
