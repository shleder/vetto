# Changelog

All notable changes to Codex Rescue are documented here.

## v0.1.0-alpha.7 — Codex Rescue Alpha7 — Reality Gate Hardening

### Added

#### Autopilot & Surface Routing
- New `auto` command: unified autopilot controller across CLI, Desktop and IDE
  surfaces with explicit `--repair-safe` and `--yes` confirmation gates.
- New `desktop` command: Codex Desktop status, doctor, sessions, diff, paths,
  writer and logs inspection.
- New `self-test` command: capability, environment, privacy-engine and
  trust-verdict self-test.

#### Local Incident Intelligence
- Blackbox real-state observer poller and desktop multi-DB state adapter.
- Real app-server JSON-RPC 2.0 protocol client and stdio lifecycle.
- Incident trust now fails closed; presentation state is never treated as
  authoritative runtime truth.

#### Disaster Recovery Primitives
- Transactional derived-state recovery engine.
- Portable migration roundtrip and derived index reconstruction.
- New `portable` command (export / inspect / import with `--dry-run`).
- New `compatibility`, `share` and `simulate-plan` commands.

#### Scale & Storage Qualification
- Bounded storage health diagnostics and streaming storage profiling.
- Peak RSS monitoring under large-file stress.

### Fixed
- Compaction 404 resiliency and forensic tail salvage.
- Canonical thread identity enforced everywhere.
- Windows extended-path normalization and npm launcher error handling.
- Writer probes no longer match Rescue itself.
- Blocked unverified portable import and mutation.

### Qualification
- Full Linux, Windows and macOS cross-platform CI qualification (Alpha7
  Reality Gate CI) across Python 3.11 and 3.13.
- 321-test main suite, 113-test Alpha7 laboratory suite, 13 npm launcher
  security tests, 6/6 fixture harness and 100-case E2E harness all green.
- Guaranteed source rollout and SQLite immutability (Invariant P1).

## v0.1.0-alpha.6-3 — Codex Rescue Alpha6 — Field Fix Batches 1–3

### Added / Fixed

#### Batch 1 — Windows Distribution Hardening
- Windows launcher now prioritizes `codex-rescue-windows-x64`.
- Historical missing package names no longer block supported fallback resolution.
- Deterministic fail-closed platform resolution.
- Zero runtime downloader, zero shell execution, zero Python runtime fallback for npm users.

#### Batch 2 — Windows Thread and Path Identity
- Detects `C:\...` vs `\\?\C:\...` rollout identity divergence.
- Distinct classification separating healthy source JSONL from diverged thread-store state.
- No automatic SQLite database rewrites.
- Prevents false `ROLLOUT_MISSING` classifications solely from `os error 2`.
- Canonical real Codex ThreadId parsing from current rollout metadata and filename semantics.
- Normal and revert filenames distinguished correctly.

#### Batch 3 — Lifecycle and State Truth
- Reads `thread_spawn_edges` strictly read-only.
- CLOSED spawn edge without conflicting live runtime is never treated as WORKING.
- Terminal retained child is not automatically assumed CLOSED.
- Desktop presentation state is not treated as authoritative runtime truth.
- Generic archive errors do not fabricate path or reference root causes.

#### Qualification & Reliability
- Full Linux, Windows, and macOS cross-platform CI qualification.
- Real Windows extended-path tests executed and passed on Windows runners.
- Full E2E harness and package build validation.
- Safe offline HTML report rendering with explicit UNKNOWN identity for unindexed rollouts.
- Refreshed doctor severity ordering contract for Alpha6 findings.
- Guaranteed source rollout and SQLite immutability.

## v0.1.0-alpha.5 — Coordinated release across npm, PyPI, and GitHub standalone binaries

### Added

- Read-only projection parity diagnostics with `WEDGED_PROJECTION` for stable canonical suffix/cursor mismatches supported by upstream field evidence, including exact expected-ordinal suffixes, one replayed boundary ordinal followed by the expected ordinal, and the field-reported stable N-to-N+1 cursor wedge.
- `PROJECTION_STATE_UNKNOWN` for malformed, ambiguous, misaligned, or otherwise unsafe-to-interpret projection evidence; missing projection state remains not-applicable rather than corruption.
- Filesystem-first session discovery with read-only SQLite thread-inventory enrichment, DB/filesystem mismatch reporting, archived-session handling, stable ordering/limits, logical deduplication, and Windows/WSL path identity normalization.
- Explicit current/historical schema compatibility for known records that Alpha4's conservative heuristic could misclassify, while future state-bearing operational records remain fail-closed.
- Privacy-safe unknown schema type/count aggregation.
- Type-specific persisted response-item ID prefix validation based on current Codex protocol evidence, with compatibility for missing optional IDs and legacy unprefixed IDs.
- Conservative A-B-A persisted writer interleave detection using explicit writer identities; normal subagent fan-out alone is not corruption evidence.
- Persisted lifecycle diagnostics that distinguish historical start/terminal records from unavailable live state.
- Conservative `INTERRUPTED_INPUT_NOT_DURABLE` evidence for a retained `task_started` → abort/interruption boundary with no durable submitted-user marker; Rescue explicitly does not recreate prompt text that was never persisted.
- Explicit workspace-portability evidence for WSL `/mnt/<drive>` versus Windows-native drive paths, including `WORKSPACE_CONTEXT_MISMATCH` only when the persisted path family conflicts with the runtime and the saved repository cwd is inaccessible.
- Read-only rollout-migration consistency diagnostics: `SUBAGENT_HISTORY_BOUNDARY_SUSPECT` for the exact zero-based paginated EOF-boundary shape reported in migrated subagents, and `THREAD_NAME_METADATA_DIVERGED` when a legacy `session_index.jsonl` name survives while paginated SQLite metadata has no name.
- Privacy-bounded name-divergence evidence stores only name presence and length; raw thread names and name digests are not emitted by the diagnostic report.
- Format-only opaque-content classification for recognized legacy opaque envelopes, the reported foreign `ocx1:` marker, unknown opaque values, and malformed fields; no decryption or account-key diagnosis.
- Zero-byte/header-only and changed-during-scan diagnostics.
- Bounded large-rollout aggregates for physical record size, bounded overflows, inline-media indicators, and compaction counts without base64 decoding.
- Alpha5 synthetic regression suites for projection, discovery, migration consistency, schema compatibility, typed IDs, tool correlation, writer/lifecycle semantics, interrupted-input persistence boundaries, workspace portability, opaque formats, incomplete rollouts, and bounded large-record scanning.
- Standalone executable build entrypoint using PyInstaller.
- Thin npm launcher and unscoped platform packages for Linux x64, Windows x64, macOS arm64, and macOS x64.
- npm package allowlist/security tests, local tarball assembly/audit helpers, SHA256 recording, structured Python/native/npm JSON parity tooling, and fail-closed npm registry-name/PyPI preflight.
- Cross-platform core CI plus Alpha5 Python qualification and native/npm build/smoke/parity workflows.
- Manual-only deterministic Alpha5 release-candidate workflow that binds the exact tag and source SHA, rebuilds Python/native/npm artifacts, verifies the exact expected artifact set, and emits a SHA256 manifest.
- Manual-only Alpha5 publication workflows for npm and PyPI Trusted Publishing that verify the candidate run, exact GitHub prerelease asset hashes, and publisher gates.
- `docs/alpha5-field-validation.md` field-evidence traceability, including upstream/mobile and WebSocket negative controls that must not become fabricated local-corruption diagnoses.
- `docs/alpha5-release-handoff.md` operational stop conditions and deterministic release sequence.

### Changed

- Python package version is `0.1.0a5`; npm mapping is `0.1.0-alpha.5`.
- `sessions` now treats compatible SQLite/sidebar state as enrichment instead of the only inventory authority.
- `doctor` now includes Alpha5 aggregate diagnostics, projection state, schema-compatibility aggregation, bounded interrupted-input evidence, workspace-portability evidence, migration-consistency evidence, and more precise repository evidence classifications.
- The interrupted-input check reuses the parser's bounded retained event tail instead of adding another full rollout pass, preserving Alpha5's large-rollout I/O model.
- Migration consistency reads are bounded and read-only: one SessionMeta head record, bounded `session_index.jsonl`, and newest compatible `state_N.sqlite` candidates.
- The README is rewritten around actual Alpha5 capabilities, safety boundaries, target npm/native distribution, and prerelease status.
- Build-only freezer and Python packaging tool versions used by Alpha5 qualification/release-candidate workflows are pinned to the versions qualified in CI to reduce release drift.

### Preserved from Alpha4

- Valid `mcp_tool_call_end` no longer causes a false `UNKNOWN_OPERATIONAL_SCHEMA`.
- Persisted paginated ordinal reuse remains bounded and fail-closed.
- Non-Git/unavailable Git evidence is not falsely asserted as repository divergence.
- Source rollouts stay read-only; recovery is a separate fork/artifact; unknown side effects are not automatically replayed.
- Existing Alpha4 PyPI Trusted Publishing workflow remains preserved and tightly scoped to the released Alpha4 artifact.

### Safety / evidence boundaries

- Alpha5 does not write projection/state SQLite and does not repair SQLite in place.
- Alpha5 does not modify source rollouts during diagnosis or salvage.
- Alpha5 does not invent missing tool results or infer that a tool failed to execute merely because persisted output is absent.
- Alpha5 does not fabricate or reconstruct a submitted prompt when the durable rollout has no prompt record; an interrupted-input finding is boundary evidence only.
- Workspace portability diagnostics are read-only hints; Rescue does not rewrite WSL/Windows paths in rollout, SQLite, or global state.
- Migration-consistency findings describe derived presentation/metadata divergence only; they do not claim raw transcript data loss and do not rewrite SessionMeta, `session_index.jsonl`, or SQLite.
- The npm launcher does not download binaries at runtime, invoke a shell, bootstrap Python, or include telemetry.
- Alpha5 official release channels are npm/npx, PyPI (`codex-rescue==0.1.0a5`), and standalone GitHub Release binaries. PyPI publication uses GitHub OIDC Trusted Publishing with fail-closed candidate verification.
- Ordinary pull-request CI does not publish Alpha5, create an Alpha5 tag, or merge the Alpha5 branch.
- Remote/iOS hydration failures and WebSocket retry/close behavior are upstream-only evidence; Rescue does not claim to observe or repair them.
- Large persisted history/payload evidence may increase diagnostic concern but is not encoded as a definitive cause of mobile/UI failure.
- Registry-name availability is checked independently from authenticated publication rights; publish workflows re-check npm identity/ownership immediately before publication.

### Known limitations

- Projection parity is deliberately narrow and can return unknown/not-applicable when schema, boundary, stability, or identity evidence is insufficient.
- Discovery remains bounded to supported rollout roots and bounded immediate Codex-home DB inspection.
- Alpha5 adds a second bounded sequential rollout scan for aggregate diagnostics; memory is bounded but I/O increases on very large files.
- Interrupted-input detection is limited to the parser's bounded retained event window; absence of a finding does not prove every historical prompt was durable.
- The migrated-subagent boundary detector intentionally recognizes only the exact reported zero-based paginated EOF-boundary shape; other or future ordinal schemes remain unclassified rather than guessed.
- Thread-name divergence requires both a readable local `session_index.jsonl` entry and compatible paginated SQLite thread metadata; missing stores remain unknown/not-applicable.
- Writer/lifecycle/opaque-format conclusions are structural diagnostics only and do not claim live process state or upstream root cause.
- Rescue still does not fix upstream Codex transport, Desktop/UI, remote/mobile hydration, compaction service, API, app-server locking, process lifecycle, or cross-platform state migration defects.
- Release publication remains gated on the exact candidate build, tag/SHA integrity, npm identity/ownership, and public GitHub/npm artifact verification.

## v0.1.0-alpha.4

### Added

- Detect persisted rollout-local reuse of paginated ordinals.

### Fixed

- Accept valid current-format `event_msg` / `mcp_tool_call_end` records without a false `UNKNOWN_OPERATIONAL_SCHEMA`.
- Classify unavailable or non-Git repository state conservatively instead of asserting `REPO_STATE_DIVERGED` without Git evidence.
- Keep genuinely unknown future operational records fail-closed so they cannot silently produce `HEALTHY`; harmless metadata on known records remains compatible.

### Safety / Evidence Boundaries

- RC validation includes full unit/E2E suites, fixture harness, package build, and clean-install smoke checks.
- Preserve source rollouts, keep salvage forked, avoid replaying unknown side effects, and retain conservative `UNKNOWN` / `REVIEW_REQUIRED` boundaries.
- Alpha 4 is an experimental engineering release. Historical public-alpha evidence includes two Rescue users; no qualified-build external Rescue run, confirmed external salvage run, or confirmed external recovery success is included.

### Known Limitations

- Discovery can miss sessions absent from upstream index state; direct path diagnosis may still be useful.
- Rescue does not repair private SQLite or projection state, Codex Desktop behavior, compaction/media retention, or unknown side effects.
- Unsupported future operational records may require review rather than a healthy verdict.

## v0.1.0-alpha.3

Third experimental alpha release, with a narrow diagnostic fix derived from openai/codex#24369.

### Corrupted persisted tool-call names

- Detect persisted `function_call.name` values containing NUL or other ASCII control characters and classify them as `CORRUPTED_TOOL_CALL`.
- Preserve only bounded metadata for the damaged name; do not guess or automatically repair the intended tool name.
- Keep the original rollout untouched, do not replay the corrupted call, and keep verification fail-closed with `REVIEW_REQUIRED`.
- Retain real-world regression coverage for #14824 (orphaned/missing tool output) and #37719 (oversized persisted tool output).

### Limitations

- This does not repair Codex HTTP 400 responses, server-side replay, arbitrary malformed arguments, or broad corrupted-session/compaction recovery.

## v0.1.0-alpha.2

Second experimental alpha release.

### Safety and recovery hardening

- Fail closed on compaction state loss, ambiguous tool correlation, and unknown operational records.
- Verify coherent source snapshots before producing a rescue artifact.
- Strengthen Git-state fingerprinting against hostile environment overrides, external diff hooks, hidden index flags, and untracked-file edge cases.
- Bound transcript, event-tail, and file-hashing memory use; preserve a conservative review-required outcome when limits are exceeded.
- Expand and align secret redaction across recovery artifacts, discovery, and hooks.
- Use structured continuation arguments and explicit untrusted-evidence boundaries in recovery prompts.
- Improve artifact identifier validation, atomic-write retry behavior, and fixture portability around transient Git lock files.
- Exclude the default local rescue-artifact directory from source distributions.

### Validation

- Full Windows and Linux validation completed on the exact candidate.
- Strict real-macOS GitHub Actions evidence gate completed for the exact 105-file candidate archive.
- Wheel and sdist were built, inspected, and smoke-tested from fresh isolated environments.

## v0.1.0-alpha

Initial experimental alpha release.

### Included

- Recent Codex session discovery (`sessions` command)
- Interrupted and damaged session diagnosis (`doctor` command)
- Immutable evidence-backed recovery salvage (`salvage` command)
- Git repository state verification (`verify` command)
- Confidence-labeled recovery handoff (VERIFIED / RECONSTRUCTED / UNKNOWN)
- Sanitized synthetic regression corpus
- Crash-safe append-only journal
- Bounded recovery brief generation
- Secret redaction in handoff artifacts

### Known limitations

- Broad real compaction recovery not yet validated
- Interactive continuation depends on terminal/TTY environment
- Previous Codex version recovery coverage is limited
- Not every arbitrary corruption type is supported
