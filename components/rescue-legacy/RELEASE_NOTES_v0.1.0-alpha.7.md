# Codex Rescue v0.1.0-alpha.7

> Experimental alpha release — the "Reality Gate" hardening milestone.

## Highlights

- New `auto` unified autopilot controller across CLI, Desktop and IDE
  surfaces, with explicit `--repair-safe` confirmation gates.
- New `self-test` capability, environment, privacy-engine and trust-verdict
  self-test.
- New `desktop` inspection command (status, doctor, sessions, diff, paths,
  writer, logs).
- New `portable` export / inspect / import for portable session packages
  (`--dry-run` supported).
- New `compatibility`, `share` and `simulate-plan` commands.
- Transactional derived-state recovery engine and derived index
  reconstruction.
- Bounded storage health diagnostics, streaming storage profiling and peak
  RSS monitoring under large-file stress.
- Compaction 404 resiliency and forensic tail salvage.
- Canonical thread identity enforced everywhere; Windows extended-path
  normalization hardened.
- Incident trust fails closed; unverified portable import and mutation are
  blocked; writer probes never match Rescue itself.

## Safety

Read-only-first remains the core guarantee: source rollouts and SQLite stores
are never mutated in place, unknown actions are never replayed, and every
unsafe path fails closed. Invariant P1 (source immutability) is verified in
the E2E harness on every release candidate.

## Install

```bash
npx --yes codex-rescue doctor --latest
# or
npm install -g codex-rescue
# or (Python)
pipx install codex-rescue==0.1.0a7
pip install codex-rescue==0.1.0a7
```

Requires Python 3.11+ for the Python distribution. The npm package ships
pre-compiled standalone binaries for linux-x64, windows-x64, darwin-arm64 and
darwin-x64 with zero runtime downloads.

## Limitations

This release does not repair Codex HTTP 400 responses, automatically
reconstruct corrupted tool names, replay unknown calls, or claim broad
compaction recovery. Recovery actions remain explicit, planned and reversible.

## Privacy

Codex Rescue is local-first with zero telemetry. Do not share raw Codex
rollout files: they can contain source code, credentials, or private prompts.
Use `codex-rescue share` / `codex-rescue bundle` + `redact-check` to produce
sanitized reports.
