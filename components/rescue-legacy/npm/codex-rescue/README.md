<div align="center">

```text
 ██████╗ ██████╗ ██████╗ ███████╗██╗  ██╗    ██████╗ ███████╗███████╗ ██████╗██╗   ██╗███████╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝╚██╗██╔╝    ██╔══██╗██╔════╝██╔════╝██╔════╝██║   ██║██╔════╝
██║     ██║   ██║██║  ██║█████╗   ╚███╔╝     ██████╔╝█████╗  ███████╗██║     ██║   ██║█████╗
██║     ██║   ██║██║  ██║██╔══╝   ██╔██╗     ██╔══██╗██╔══╝  ╚════██║██║     ██║   ██║██╔══╝
╚██████╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗    ██║  ██║███████╗███████║╚██████╗╚██████╔╝███████╗
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝
```

# CODEX RESCUE

<p align="center">
  <b>Read-Only-First Diagnostic, Forensics & Recovery Toolkit for OpenAI Codex Sessions</b>
</p>

[![Release](https://img.shields.io/github/v/release/shleder/codex-rescue?include_prereleases&label=release&color=blue&style=flat-square)](https://github.com/shleder/codex-rescue/releases)
[![npm version](https://img.shields.io/badge/npm-v0.1.0--alpha.7-brightgreen?style=flat-square)](https://www.npmjs.com/package/codex-rescue)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)](https://github.com/shleder/codex-rescue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Zero Telemetry](https://img.shields.io/badge/telemetry-zero%20%2F%20local--first-success?style=flat-square)](https://github.com/shleder/codex-rescue)

</div>

---

## Quick Start

Run instantly without installation (zero setup required):

```bash
# Diagnostic inspection on your latest Codex session
npx --yes codex-rescue doctor --latest

# Batch analyze all local Codex sessions
npx --yes codex-rescue doctor --all

# List and discover all local Codex sessions
npx --yes codex-rescue sessions

# Explain any diagnostic finding code
npx --yes codex-rescue explain OVERSIZED_PAYLOAD
```

Or install globally via npm:

```bash
npm install -g codex-rescue
codex-rescue --help
```

---

## What Codex Rescue Does

Codex Rescue inspects local OpenAI Codex session rollouts (`.jsonl`), correlates SQLite index / projection layers, diagnoses persistence hazards, and creates reproducible recovery forks **without ever mutating source session data in place**.

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                        CODEX RESCUE ARCHITECTURE                       │
 └────────────────────────────────────────────────────────────────────────┘
            │
            ├──► 1. ROLLOUTS (.jsonl)   ──► Bounded Reader / Stream Hashing
            ├──► 2. SQLITE (state.db)   ──► Read-Only Projection Verification
            ├──► 3. GIT WORKTREE        ──► Fingerprint & Head Drift Check
            │
            ▼
    ┌───────────────────────────┐         ┌───────────────────────────┐
    │  DIAGNOSTICS & FORENSICS  │   ───►  │   SAFE RECOVERY & FORK    │
    │   (doctor / diff / graph) │         │ (salvage / plan / bundle) │
    └───────────────────────────┘         └───────────────────────────┘
```

> [!IMPORTANT]
> **Safety Guarantee**: Codex Rescue operates **read-only-first**. It never rewrites original session JSONL files, never invents missing tool outputs, and never blindly replays side effects with uncertain state.

---

## Feature Matrix & Commands

| Command | Purpose | Description |
|---|---|---|
| `sessions` | **Session Inventory** | Discovers and filters all local sessions on disk vs SQLite state (`--latest`, `--orphans`, `--unindexed`). |
| `doctor` | **Health Inspection** | Deep structural, projection, tool-pairing, and ordinal diagnostics (`--all`, `--changed`, `--latest`). |
| `explain` | **Finding Reference** | Self-contained explanations with exact evidence, risks, and recommended actions. |
| `diff` | **Layer Divergence** | Compares raw rollout JSONL vs SQLite state DB vs Git repository state. |
| `timeline` | **Forensic Events** | Generates a chronological, privacy-safe lifecycle timeline of a session. |
| `graph` | **Agent Hierarchy** | Visualizes parent-child subagent trees and session invocation graphs. |
| `storage` | **Disk Footprint** | Profiles session storage usage, large payloads, and media anomalies. |
| `schema` | **Schema Analysis** | Validates persisted schema generations and recognized record coverage. |
| `workspace`| **Path Portability** | Verifies saved working directory across POSIX, Windows, and WSL environments. |
| `writer` | **Lock Inspector** | Inspects active writer locks and Win32/POSIX process ownership. |
| `plan` | **Recovery Plan** | Generates a structured, reversible repair plan with pre-flight invariants. |
| `apply-plan`| **Safe Plan Apply** | Safely executes a verified recovery plan with pre-mutation backup. |
| `bundle` | **Support Bundle** | Exports a sanitized diagnostic bundle for bug reports (secrets redacted). |
| `redact-check`| **Privacy Audit** | Scans support bundles and artifacts for accidental leaks or credentials. |
| `report` | **Offline HTML** | Produces a clean, standalone offline HTML diagnostic dashboard. |
| `salvage` | **Safe Forking** | Extracts durable history into a clean recovery fork (`--fork`). |
| `verify` | **Handoff Check** | Verifies recovery artifacts and repository HEAD before continuation. |
| `auto` | **Autopilot** | Alpha7 unified autopilot controller across CLI/desktop/IDE surfaces (`--repair-safe`, `--yes`). |
| `self-test` | **Capability Check** | Runs Rescue capability, environment, privacy-engine and trust-verdict self-test. |
| `desktop` | **Desktop Inspection** | Codex Desktop status, doctor, sessions, diff, paths, writer and logs inspection. |
| `compatibility` | **Compat Matrix** | Inspects schema and runtime compatibility across rollout/SQLite generations. |
| `portable` | **Portable Packages** | Export, inspect and import portable session packages (`--dry-run` supported). |
| `share` | **Safe Share Report** | Generates a privacy-redacted diagnostic share report. |
| `simulate-plan` | **Plan Sandbox** | Simulates a recovery plan in a temporary sandbox without touching source data. |

---

## Core Reliability & Safety Hardening

### 1. Oversized Record Handling (>16 MiB)
* Bounded chunk streaming reader prevents memory exhaustion.
* Strict semantic distinction:
  * `VALID_BUT_OVERSIZED` — well-formed JSON exceeding byte thresholds.
  * `MALFORMED_RECORD` — corrupted byte sequence / NUL injections.
  * `TRUNCATED_TRANSCRIPT` — incomplete EOF record.
* Prohibits `HEALTHY` verdict and refuses mutating plans on unparsed source records.

### 2. Unified Projection Divergence Model
* Reconciles canonical rollout progressions with derived SQLite projection cursors.
* Detects `WEDGED_PROJECTION` and ordinal sequence anomalies.
* Supports atomic derived projection cursor realignment with guaranteed rollout immutability.

### 3. Native Platform Launcher (Zero Runtime Downloads)
* Standard npm package bundles pre-compiled standalone executables:
  * `linux-x64`
  * `windows-x64`
  * `darwin-arm64` (Apple Silicon)
  * `darwin-x64` (Intel macOS)
* Zero runtime downloads, zero `curl | sh`, zero `shell: true`, and zero Python requirements for npm users.

---

## Alpha7: Reality Gate Hardening

Alpha7 is the "reality gate" milestone: every diagnostic claim is now grounded in
observable local evidence, and every unsafe path fails closed.

* **Unified Autopilot** (`auto`): single controller that routes across CLI,
  Desktop and IDE surfaces with explicit `--repair-safe` confirmation gates.
* **Local Incident Intelligence**: blackbox real-state observer, desktop
  multi-DB state adapter, and process tracking — presentation state is never
  treated as authoritative runtime truth.
* **Disaster Recovery Primitives**: transactional derived-state recovery
  engine, portable migration roundtrip, and derived index reconstruction.
* **Trust Contracts**: privacy engine and trust verdicts in `self-test`;
  incident trust fails closed; unverified portable import and mutation are
  blocked.
* **Scale Qualification**: bounded storage health diagnostics, streaming
  storage profiling, and peak RSS monitoring under large-file stress.
* **Resilience Fixes**: compaction 404 resiliency, forensic tail salvage,
  canonical thread identity everywhere, Windows extended-path normalization,
  and writer probes that never match Rescue itself.

---

## Command Examples

### 1. Run Doctor on Sessions
```bash
# Run on the latest active session
codex-rescue doctor --latest

# Run on a specific rollout file
codex-rescue doctor ~/.codex/sessions/rollout-example.jsonl

# Incremental scan of only changed sessions
codex-rescue doctor --changed

# Structured JSON output
codex-rescue doctor --latest --json
```

### 2. Explain Diagnostic Finding Codes
```bash
codex-rescue explain WEDGED_PROJECTION
codex-rescue explain OVERSIZED_PAYLOAD
codex-rescue explain UNFINISHED_TOOL_CALL
```

### 3. Inspect Session Diff & Timeline
```bash
# Compare rollout against SQLite projection and Git
codex-rescue diff --latest

# View privacy-safe event timeline
codex-rescue timeline --latest --max-events 50
```

### 4. Safe Recovery Planning
```bash
# Generate a structured recovery plan
codex-rescue plan --latest > recovery_plan.json

# Execute recovery plan with mandatory pre-flight checks and backup
codex-rescue apply-plan recovery_plan.json
```

### 5. Generate Privacy-Safe Support Bundle & Offline HTML Report
```bash
# Create sanitized bundle (removes keys, tokens, personal paths)
codex-rescue bundle --latest -o support_bundle.json

# Audit bundle for potential leaks
codex-rescue redact-check support_bundle.json

# Generate standalone offline HTML diagnostic report
codex-rescue report --latest -o report.html
```

---

## Distribution Channels

| Channel | Identifier | Status | Install Command |
|---|---|---|---|
| **npm (npx)** | `codex-rescue` | **Active** | `npx --yes codex-rescue doctor --latest` |
| **npm (global)** | `codex-rescue` | **Active** | `npm install -g codex-rescue` |
| **GitHub Releases** | `v0.1.0-alpha.7` | **Active** | [Download Release Assets](https://github.com/shleder/codex-rescue/releases/tag/v0.1.0-alpha.7) |

---

## Privacy & Local-First Philosophy

Codex rollouts and SQLite stores may contain private prompts, proprietary source code, secrets, API tokens, and local file paths.

* **Zero Telemetry**: Codex Rescue never makes outbound telemetry or analytics network requests.
* **Metadata-Only Diagnostics**: Diagnostic dumps aggregate schema kinds and counts rather than raw prompt/code strings.
* **Path Sanitization**: User directories and private environments are masked during support bundle creation.

---

## Development & Quality Assurance

Run test suites and packaging audits:

```bash
# Clone repository
git clone https://github.com/shleder/codex-rescue.git
cd codex-rescue

# Run npm security allowlist and packaging tests
node --test npm/tests/*.test.cjs

# Run E2E test harness
python tests/e2e/harness_e2e.py --tier all
```

---

## License

Distributed under the [MIT License](LICENSE). Copyright (c) 2026 shleder.
