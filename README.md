# vetto

**Daemon-less sandbox + security layer for AI coding agents.**
One binary. Zero daemons. Kernel-enforced. Instant visibility.

`vetto` wraps any locally-invoked AI coding agent (`codex`, `claude`, custom
scripts, unsandboxed tools) in an OS-level sandbox, shows what the agent is
doing in a terminal-native UI, and produces post-session audit reports.

```console
$ vetto -- codex exec "refactor auth module"
$ vetto -- claude -p "fix the bug"
$ vetto --net=allowlist:registry.npmjs.org -- npm install
$ vetto --tui=full --observe-seccomp --report html,md -- make test
$ vetto doctor --probe
```

## Why vetto, when agents have built-in sandboxes?

Modern agents ship their own sandboxing (Codex CLI uses Landlock+seccomp on
Linux / Seatbelt on macOS; Claude Code has bash sandboxing). vetto is not a
replacement — it is the **uniform layer above heterogeneous built-ins**:

| Competitor / alternative | Overlap | vetto's edge |
|---|---|---|
| AgentJail | HIGH | daemon-less, zero config (no OPA/Rego daemon) |
| Watchfire | HIGH | single binary, no `watchfired` |
| ZeroClaw | MEDIUM | terminal-native, no web dashboard |
| landrun | MEDIUM | agent awareness + TUI + audit + macOS |
| **Agent built-in sandboxes** (Codex, Claude Code) | HIGH | one consistent policy + audit layer across ANY agent — custom, older, or unsandboxed; unified cross-agent reports; defense-in-depth you control |

You get one policy file, one statusline, one report format — for every agent
on your machine, regardless of what the agent itself does (or doesn't)
enforce.

## What it does

- **Filesystem enforcement** — Landlock (Linux) / Seatbelt (macOS) allowlists.
  The project dir and `/tmp` are writable; toolchains and caches are
  read-only; `~/.ssh`, `~/.aws`, `*.pem`, `.env` are denied. Decisions happen
  in the kernel on the resolved inode — symlink races (TOCTOU) are
  structurally impossible on Linux.
- **Network kill-switch** — `--net=off` (default): no sockets, no DNS, no
  exfiltration, on every tier.
- **Optional CONNECT-level allowlist** — `--net=allowlist:domain`: the domain
  is read from the proxy CONNECT target *before* TLS; broker-side DNS; no TLS
  decryption, no CA injection, no SNI parsing — ever.
- **TTY-native visibility** — a one-line statusline under the agent's own
  interactive TUI (`--tui=statusline`), or a full dashboard for headless runs
  (`--tui=full`), with a `Ctrl+]` scrollable event overlay.
- **Post-session audit** — JSONL event log, self-contained HTML/MD/JSON
  reports, and a BEST-EFFORT secret sanitizer.

## Platform support (honest, per tier)

Linux is the primary platform. **Do not assume "works everywhere
unprivileged" — it depends on your kernel:**

| | Tier FULL (default) | Tier FS-ONLY (automatic fallback) |
|---|---|---|
| Requirements | Landlock (kernel ≥ 5.13) + unprivileged user namespaces | Landlock (kernel ≥ 5.13) + seccomp filters |
| Filesystem | Landlock + mount-namespace overlays masking secrets | Landlock only; project tree enumerated at load time |
| Namespaces | USER+MOUNT+PID+NET+IPC; killing vetto kills everything | none; `setpgid`+`PDEATHSIG` cleanup |
| Network off | interface-less netns | seccomp-BPF `socket(AF_INET*)` → `EAFNOSUPPORT` |
| Network allowlist | ✅ unix-fd bridge relay | ❌ (fails closed with a clear error) |
| Orphan guarantee | PID namespace: kernel kills the whole ns | honest gap: grandchildren that `setsid()` away survive |
| Typical blockers | Ubuntu 23.10+ AppArmor userns restrictions, some enterprise distros | (almost everywhere Landlock works) |

macOS: Seatbelt via `sandbox-exec` — deprecated and undocumented by Apple;
works today, platform risk accepted (see SECURITY.md).

Windows: absent from v0.1; on the v0.3+ roadmap (enterprise audit reports
noted). A Windows build attempt fails with an explicit error instead of
producing a broken binary.

`vetto doctor` reports exactly which tier you get and why; `vetto doctor
--probe` actively verifies every denied path is unreachable from inside a
throwaway sandbox.

## Anti-features (deliberately NOT built)

- ❌ no persistent daemon of any kind
- ❌ no OPA / Rego / policy-as-code engine — policy is one simple TOML file
- ❌ no web dashboard / Electron GUI / fleet mission-control
- ❌ no cloud, no telemetry, no phone-home
- ❌ no root requirement — fully unprivileged
- ❌ no Docker/VM dependency — kernel primitives only
- ❌ no SNI inspection / TLS MITM / CA injection — ever

## Quick start

```console
$ cargo install --git https://github.com/shleder/vetto
$ vetto doctor            # what does this machine support?
$ cd my-project
$ vetto -- codex exec "..."   # or claude, aider, python agent.py, make test...
```

Statusline keys: `Ctrl+]` opens the event overlay; `Esc`/`q` closes it.
Dashboard keys: `q` quits (kills the agent), arrows/PgUp/PgDn scroll.

### Profiles

`default` (project+tmp write, caches read-only), `strict` (minimal),
`audit` (same fs as default; pair with `--observe-seccomp --jsonl --report`),
`permissive` (wide toolchain read; secrets still denied). `vetto profiles`
lists them; `vetto init` writes a starter `vetto.toml`; run it with
`--policy vetto.toml`.

### Visibility honesty

- Allowed file access is observed by a best-effort `/proc` poller (~100 ms
  granularity — sub-100 ms opens are missed).
- **Blocked attempts are only visible with an observation channel**: kernel
  audit (rarely readable unprivileged) or `--observe-seccomp` (seccomp
  user-notify, observation-only; Landlock stays the sole enforcer). Without
  either, vetto shows a persistent notice — **enforcement is always active**.
- The secret sanitizer is labeled BEST-EFFORT everywhere it appears; it can
  produce false positives and misses.

See SECURITY.md for every honest limitation, ARCHITECTURE.md for the
fork-chain and network topology internals, and docs/threat-model.md.

## License

Apache-2.0.
