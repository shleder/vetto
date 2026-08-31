# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versioning follows SemVer.

## [Unreleased]

### Added

- Transparent agent sandboxing: `vetto enable <agent>` creates priority PATH shims with multi-layered recursion barriers (`VETTO_WRAPPED`, `VETTO_SANDBOXED`, `VETTO_SHIM_ACTIVE`), allowing developers to launch agents normally (e.g. `claude`, `codex`) under kernel sandbox supervision without manual `vetto run` wrapping.
- Transparent agent unwrap: `vetto disable <agent>` safely removes the Vetto shim without affecting the host binary.
- Agent discovery and status: `vetto enable` without arguments lists detected and wrapped agents; `vetto enable --status` and `vetto status` display active agent wrappers and real binary paths.
- Collision safety: `vetto enable` refuses to overwrite non-Vetto binaries without `--force`.

### Changed

- Reorganized CLI `--help`: prioritized primary workflows (`enable`, `disable`, `allow`, `deny`, `doctor`, `tour`, `status`, `verify`) and hid low-level/internal subcommands.
- Documentation: updated README Quick Start to the 3-line workflow (install -> `vetto enable claude` -> run `claude` normally) and updated onboarding error hints.

## [0.2.8] — 2026-08-30

### Added

- One-command policy editing: `vetto allow` (path or `--net` domain, `--read-only`, `--global`) and `vetto deny` write the grant into the project or user-global policy preserving comments and formatting; blocked-attempt and denied-network hints now point at the exact command instead of a nonexistent TOML key.
- Sandbox comparison matrix and decision guide (`docs/comparison.md`): detailed architectural comparison covering isolation primitives (Landlock/Seatbelt vs Docker namespaces vs gVisor syscall virtualization), startup latency (~0.8–3ms vs 150ms–1s), native file access, outbound network filtering, and platform boundaries.
- Dedicated Unix domain sockets documentation (`docs/network.md`): explanation of local IPC (`AF_UNIX`) semantics, Landlock path access rules (`[unix_sockets] allow = [...]`), and seccomp netblock pass-through.
- Actionable fatal startup error diagnostics across Linux, macOS, and Windows sandbox backends: every fail-closed startup refusal now explicitly names the missing kernel primitive, provides a concrete remediation command (e.g. `sysctl -w kernel.unprivileged_userns_clone=1`), and directs to `vetto doctor`.

## [0.2.7] — 2026-08-30

### Added

- Friendly first-run onboarding: when `vetto` is launched without arguments and no AI agent is detected, it prints concrete starting steps (`vetto doctor`, `vetto tour`, sandboxing any binary via `vetto -- <command>`) and a docs link instead of a bare error.
- crates.io distribution channel: `cargo install vetto`; the release train now publishes npm and crates.io from a single run.
- `first-run` issue template and GitHub Discussions for first-run reports.

### Changed

- README rewritten around the zero-config quick start and the real 0.2.6 command surface; landing page fixed (npm package name typo, sandbox-first headline, first-run line).

## [0.2.6] — 2026-08-30

### Added

- Zero-config auto-detection (`vetto` without arguments): inspects workspace project markers and PATH executables to auto-detect the active AI agent, applies agent-tailored allowlists and secure defaults, and launches supervision.
- Interactive first-run wizard (`vetto init --wizard`): 3-step interactive setup generating a commented `policy.toml` tailored to project ecosystem (Rust, Node, Python, Go, Java, Ruby, PHP).
- Security presets (`--preset paranoid|balanced|yolo`): instant baseline security profiles with tailored network access and secret masking rules.
- Agent network allowlists: out-of-the-box domain allowlists for Claude, Codex, Gemini, Aider, OpenCode, Cursor, Copilot, and Cline.
- Actionable remediation hints on blocked attempts: TUI and events surface concrete policy modifications when file access or network requests are denied.
- Path permission inspection (`vetto policy explain --why <path>`): inspects path permissions (WRITABLE, READ_ONLY, DENIED, BLOCKED) and provides exact TOML remediation instructions (supports text and `--json`).
- Shadow mode (`--shadow`, `RunConfig.shadow`): evaluates policy boundaries in log-only mode ("would deny") during preflight verification.
- Diagnostic remediation (`vetto doctor --fix`): prints concrete fix commands and sysctl configurations for missing kernel primitives (Landlock LSM, unprivileged userns, seccomp, audit feed).
- External policy importer (`vetto policy import --from claude|codex`): parses Claude settings JSON or Codex config TOML and generates compatible `policy.toml`.
- 3-tier configuration hierarchy: `~/.vetto/config.toml` (global defaults) -> `./policy.toml` / `.vetto/policy.toml` (project policy) -> CLI flags (strictest wins).
- Shell completions and man pages (`vetto completions <shell>`, `vetto man`): native shell completions for Bash, Zsh, Fish, PowerShell, Elvish and man page generation via `clap_mangen`.
- `vetto --version --json` emitting machine-readable version, fast tier determination, and git commit hash.
- Stable deterministic exit codes mapped across all session termination paths and documented in `docs/exit-codes.md`.
- Global `--quiet` (`-q`) and `--verbose` (`-v`) logging flags across CLI commands.
- Optional system-level journal logging (`system_log = true` / `--system-log`) for Linux journald, Windows EventLog, and macOS logger.
- `vetto shell-env` command and PS1 prompt integration exporting session indicators (`VETTO_SANDBOX=1`).
- `vetto status` listing active supervised sessions and cleaning up stale process metadata.
- Official standalone curl installer `scripts/install.sh` with SHA256 checksum verification and `docs/INSTALL.md`.
- Automated session timeout computation (`--timeout auto`) via p95 duration history with 5-minute floor.
- Persistent workspace profiles (`vetto profile save/list/rm`) and direct execution (`vetto <profile>`).
- Latency and bottleneck diagnostic breakdown with actionable optimization hints (`vetto why-slow <session>`).
- Release CycloneDX SBOM generation script (`scripts/gen-sbom.sh`) and specification in `docs/SBOM.md`.
- Landlock ABI diagnostic feature hints in `vetto doctor` for kernels supporting newer LSM features.
- Conventional commit changelog generator `scripts/gen-changelog.py` for automated release notes.
- `vetto policy show --effective` for rendering resolved effective policy rules and resource ceilings.
- **Release Train Workflow** (`.github/workflows/release-train.yml`): automated CI release pipeline with dry-run on `main` push, manual dispatch release (bump patch/minor/major, channel stable/alpha), SLSA Level 3 provenance attestations (`actions/attest-build-provenance`), multi-target binary matrix compilation, npm packaging and publishing.
- **Version Banner & Update Notification**: Non-blocking async check against npm registry (`https://registry.npmjs.org/@shledery/vetto/latest` or `@shledery/vetto/alpha`) with 24-hour cache in `~/.vetto/cache/version.json` and 2-second timeout. Displayed on session start and in `vetto doctor`.
- **Self-Upgrade Subcommand** (`vetto upgrade`): Self-update mechanism with automatic installation method detection (npm vs cargo vs binary) supporting `--check`, `--dry-run`, and `--channel <stable|alpha>`.
- **Release Channels**: Support for `stable` and `alpha` channels via npm dist-tags and user config (`channel = "alpha"` in `~/.vetto/config.toml`).
- **Compatibility Matrix**: Comprehensive documentation (`docs/compat.md`) and generator script (`scripts/gen-compat.py`) mapping AI agents, platforms, and isolation tiers.
- **Nightly E2E Agent Suite** (`.github/workflows/e2e-agents.yml`): Nightly multi-agent (Claude Code, OpenAI Codex, Gemini) verification workflow across Linux and macOS runners with honest skip when API credentials are unset.
- **Public Red-Team Security Reports** (`.github/workflows/redteam.yml`, `scripts/redteam-stub.sh`, `docs/redteam-latest.md`): Automated adversarial attack evaluation and published badge report.
- **Optional Privacy-Preserving Telemetry**: Strictly opt-in (`telemetry = false` default) aggregate block category counters via `~/.vetto/config.toml` with complete transparency in `docs/telemetry.md`.
- **Interactive Tour Subcommand** (`vetto tour`): 5-step guided onboarding scenario demonstrating doctor diagnostics, secret masking, shadow mode, policy tailoring, and boundary verification.
- **Vulnerability Management & CVE Process**: Response SLA (48h acknowledgment), RFC 9116 `.well-known/security.txt`, supported versions table in `SECURITY.md`, and disclosure workflow in `docs/security/cve-process.md`.
- **SLSA Provenance Verification**: Build provenance attestations and verification documentation in `docs/security/slsa-provenance.md`.
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
- **Tier 3 Files & Secrets Suite (Features 25–36)**:
  - Auto secret scan (`vetto scan-secrets [path]` command and `auto_deny_secrets = true` policy option) detecting and denying credential patterns at startup with bounded limits.
  - Out-of-process credential broker (`secrets.proxy = [...]`) injecting auth headers for allowlisted domains and stripping sensitive credentials from the child.
  - Built-in deny presets (`deny_preset = ["ssh", "aws", "gcp", "kube", "docker", "gnupg", "git", "npm", "cargo", "claude", "codex"]`).
  - Glob denial patterns (`--deny-glob` CLI flag and `deny_glob = ["**/*.pem"]`).
  - Read-only cache mounts (`ro_mounts = ["~/.npm", "~/.cache/pip"]`) mounted `MS_RDONLY` in mount namespace.
  - Diff reporting with in-memory baseline manifest and summary diff calculation at completion.
  - Git branch protection (`git_guard = true`) and hook/shim interception blocking destructive operations (`git push --force*`, `git push --delete`).
  - Snapshot and rollback (`snapshot = true` and `vetto rollback <session>`).
  - `/proc` and `/sys` masking and `/tmp` private tmpfs isolation (`tmpfs_tmp = true`).
  - Live session event watch mode (`vetto watch <session-pid/log-path>`).
  - Filesystem I/O metrics tracking bytes read/written and operation counts.
- **Tier 4 Observability Suite (Features 37–48)**:
  - Live TUI dashboard event panel: `--tui=full` augmented with real-time categorized counters (files, network, blocked access, processes).
  - `vetto events <session>` subcommand for tailing and filtering JSONL session logs with `--filter deny|net|files|exec`, `--follow` streaming tail, and table/JSON formats.
  - OpenTelemetry session tracing behind optional `telemetry` feature flag: session root span (`vetto.session`) and span-events for security/observation telemetry with `--otel-endpoint`.
  - `vetto audit` subcommand and persistent session indexing to `~/.vetto/history.jsonl` with `--since`, `--agent`, `--limit`, and substring search.
  - Desktop notifications on security violations via `--notify` / `notify = true` (Linux `notify-send`, macOS `osascript`, Windows PowerShell toast) via non-blocking subprocesses.
  - `vetto digest` subcommand for daily audit summaries (sessions, duration, blocked counts, top agents and policies).
  - `vetto diff-sessions <id1> <id2>` subcommand for comparing two session reports (metric deltas, new and resolved violations, network changes).
  - Standalone inline SVG category histogram in HTML audit reports visualizing event distribution across categories with zero external dependencies.
  - `vetto replay <session>` subcommand for chronological sandbox event playback with `--speed` multiplier.
- **Tier 5 Linux Kernel Hardening Suite (Features 49–60)**:
  - Seccomp profile configuration (`seccomp_profile = "agent-min"`) blocking exotic and legacy syscalls (personality, syslog, chroot, raw I/O, clock tampering, fanotify) for hardened agent containment.
  - Seccomp user-notify supervisor framework with default-deny policy handling and blocked attempt event auditing.
  - cgroup v2 transient lifecycle and resource quota management (`cgroup = { memory_max = "2g", pids_max = 512, swap_max = "0" }`) with RAII cleanup on process teardown.
  - CPU quota (`cpu_max = "50%"`) and I/O scheduling priority (`io_priority = "idle"`) limits applied via `SYS_ioprio_set` and cgroup v2 `cpu.max`.
  - Restricted device node masking in mount namespaces (`dev_allow` allowlist support with default masking for dangerous `/dev` hardware and memory nodes).
  - Tier downgrade guarantee and downgrade test matrix (Tier FULL -> FS-ONLY -> SECCOMP -> fail-closed).
  - `vetto redteam` subcommand and test battery evaluating 8 kernel containment and breakout attack vectors with text summary and `--json` output.
  - Seccomp-only micro-tier (`VETTO_FORCE_TIER=seccomp` / `Tier::Seccomp`) for legacy Linux environments lacking Landlock, with loud warnings.
  - Host environment detection (devcontainer, Docker, Podman, WSL2, native) reported in `vetto doctor`.
  - GitHub Actions CI matrix updated for tier branches with fallback and redteam verification jobs.
- **Tier 6 macOS & Windows Deep Hardening Suite (Features 61–72)**:
  - SBPL regression tracking (`probe_sbpl_read_fragment()`) detecting dynamic linker SIGABRT regressions with fragmented read rules on macOS; surfaced in `vetto doctor` under `sbpl-read-fragment`.
  - macOS unified log sink (`sandbox::logger::oslog::OsLogSink`) streaming policy denials, warnings, and sandbox lifecycle events to macOS unified log (`/usr/bin/logger -t vetto`) via `--oslog` or `oslog = true` in policy.
  - macOS `.pkg` installer packaging and notarization script (`packaging/macos/build_pkg.sh`) and guide (`packaging/macos/README.md`) for signed `.pkg` distribution, Apple notarytool submission, and stapling.
  - Windows Less Privileged AppContainer / LPAC isolation via `--lpac` / `lpac = true` and capability probing in `vetto doctor`.
  - Windows Job Object IO rate control (`max_iops` and `max_bandwidth` resource limit controls backed by `JOB_OBJECT_IO_RATE_CONTROL_INFORMATION`).
  - Windows Authenticode digital signing script (`packaging/windows/sign.ps1`) and guide (`packaging/windows/README.md`) for automated SHA-256 / RFC 3161 Authenticode binary signing in release pipelines.
  - Windows Sandbox VM backend opt-in (`--backend win-sandbox`) with `mapped_read_write` folder support in `windows_sandbox.rs` and capability-gated launch.
  - Cross-platform policy parity test suite (`tests/integration/policy_parity.rs`) and full OS Parity Guarantee Matrix in `docs/platform-backends.md`.
- **Tier 7 Ecosystem Integration Suite (Features 73–84)**:
  - `vetto-action` (Composite GitHub Action): Daemon-less GitHub Action installing precompiled binary or npm package with zero user-side Rust compilation overhead, supporting `policy`, `net`, and `command` inputs with SARIF output.
  - Model Context Protocol (MCP) Server: `vetto mcp` stdio JSON-RPC 2.0 server exposing the `run_sandboxed` tool for LLM clients (Claude Desktop, Cursor, Zed) to execute sandboxed tasks.
  - One-liner Agent Plugins: `vetto plugin install claude-code` and `vetto plugin install opencode` with non-destructive JSON deep merge and automatic timestamped backups (`.bak.<timestamp>`).
  - VS Code Extension: Minimal extension in `vscode/` adding the `Vetto: Run Task Sandboxed` command to run workspace `tasks.json` tasks inside the sandbox.
  - Package Publishing Recipes: Homebrew tap bootstrap script and formula in `packaging/homebrew/`, Arch Linux AUR `PKGBUILD` and `.SRCINFO` in `packaging/aur/`, and `[package.metadata.binstall]` metadata in `Cargo.toml`.
  - Multiplexer Daemon & Session Registry: `vetto daemon start/status/stop` with session registry and mandatory `SO_PEERCRED` / `getpeereid` peer credentials verification on Unix domain sockets.
  - Loopback REST API: HTTP API bound strictly to `127.0.0.1` (`POST /sessions`, `GET /sessions/{id}`, `DELETE /sessions/{id}`) authenticated via secret Bearer token (`~/.vetto/daemon/token`).
  - Remote Execution (`vetto serve` & `vetto --remote`): Remote execution over SSH port forwarding with dedicated instructions and CLI client.
  - Policy Cryptographic Signing (Ed25519): `vetto policy sign` and `vetto policy verify` with Ed25519 keys (`~/.vetto/signing.key`), plus `[security] require_signed = true` loader enforcement.
  - Community Policy Registry: 7 battle-tested policies (`python-dev`, `node-dev`, `rust-dev`, `java-dev`, `data-science`, `read-only-audit`, `yolo-web`) and `vetto policy use <name>` CLI command.
  - Docker Hybrid Integration: Multi-stage `Dockerfile.vetto` and detailed double-sandbox defense-in-depth documentation (`docs/integrations/docker-in-vetto.md`).
  - Kubernetes Manifests: `k8s/deployment.yaml`, `k8s/daemonset.yaml`, `k8s/vetto-sidecar.yaml`, and documentation of Landlock seccomp compatibility.

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
