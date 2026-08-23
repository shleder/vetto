# Codex Rescue PoC Result

## Environment

- Windows 11 x64
- Codex CLI `0.147.0`; sampled Desktop rollouts report `0.147.0-alpha.6.6`
- Python 3.11 standard-library implementation
- Synthetic fixtures follow the observed current Codex JSONL envelope
- The streaming parser also passed byte-for-byte immutability and SHA-256 checks
  against a current real 0.147.0 rollout
- Two previous Codex versions were not realistically available in the local
  environment and were not claimed as tested

## Codex storage findings

Codex stores rollout JSONL under `%CODEX_HOME%/sessions/YYYY/MM/DD`, with the
session UUID in both the filename and `session_meta`. Current records include
durable function/custom tool call-output pairs, compaction records, task lifecycle
events and turn context. SQLite indexes the rollouts and UI metadata, but Rescue
does not read-write or mutate it. Full details are in `POC_NOTES.md`.

## Recovery architecture

```text
read-only broken rollout
  -> tolerant streaming parser and doctor
  -> current repository/Git verifier
  -> optional external append-only journal
  -> content-addressed handoff.v1 + bounded brief
  -> exact public Codex continuation command
```

Original rollout files and Codex private databases are never rewritten. An
unfinished tool call remains unknown and is never replayed by Rescue.

## Journal design

Journal entries are local JSONL records written with `O_APPEND`, fully flushed
and `fsync`ed. A partial final record is ignored while earlier complete records
remain readable. Entries contain bounded operational metadata and hashes, not raw
large payloads. Hook capture fails open so it cannot block Codex.

## Fixture results

| Fixture | Result | Time | Notes |
|---|---:|---:|---|
| kill during apply_patch | PASS | 2.2902 s | unfinished patch stays unknown; current partial diff is verified; review required |
| shell executed, result absent | PASS | 2.2289 s | side effects visible in repo; execution result unknown; no replay |
| oversized payload | PASS | 2.3098 s | payload located by offsets/size and excluded from the bounded handoff |
| malformed/truncated JSONL | PASS | 2.3659 s | valid prefix and exact invalid offset retained; source untouched |
| compaction loses operational tail | PASS | 2.2827 s | structural loss signal plus durable post-action evidence reconstructed |

Result: 5/5 fixtures. All salvage artifacts were ready in less than 60 seconds.

## Original-session immutability

The harness hashes every source-session file before `doctor`, `salvage`, and
`verify`, then hashes it again. All five fixture trees were byte-for-byte equal.
The live current-session parser test also compared full source bytes before and
after parsing and matched SHA-256.

## Duplicate-edit prevention

Rescue performs no repository mutation and invokes no recovered command. Both
unfinished patch and unfinished shell cases result in `REVIEW_REQUIRED`. The
continuation prompt requires inspecting HEAD/diff and the effects of uncertain
actions before any edit or replay.

## Repo verification

The stable PoC state hash includes:

- `git diff --binary`;
- `git diff --cached --binary`;
- sorted untracked file paths, types, sizes and content SHA-256 values.

`verify` detects changed HEAD, worktree/root, diff hash and changed-file set.
Identity or content conflicts produce `STATE_DIVERGED`; unresolved tool state
produces `REVIEW_REQUIRED`.

## Confidence model

- `verified`: current repository/Git, durable tool result or external journal evidence.
- `reconstructed`: bounded inference with evidence references and no unresolved contradiction.
- `unknown`: absent, corrupted, contradictory, or non-durable evidence.

Model prose alone never verifies an edit, command result, or passing test.

## Known limitations

- The five main failure fixtures are synthetic, although shaped from current
  0.147.0 records; a larger corpus of real damaged sessions is still required.
- Only the current installed Codex version was executed.
- Compaction-loss detection intentionally recognizes a narrow structural case
  (`replacement_history` empty despite a recent durable operational tail). Other
  forms are reported conservatively rather than guessed.
- Public `fork` cannot accept a repaired arbitrary JSONL. The PoC emits a fresh
  public CLI command and prompt bundle instead of modifying private state.
- Hook delivery is optional evidence and can be stale after a hard process kill.
- Secret redaction is bounded and payload-oriented, not a complete credential DLP system.

## Native Codex cannibalization risk

Codex already has public `resume`, `fork`, current compaction hooks and improving
session infrastructure. Native recovery will reduce the addressable surface.
The durable value demonstrated here is narrower: damage classification, external
crash evidence, safe malformed-prefix salvage, repository-state verification,
confidence labels and regression fixtures.

## Decision

POC PASS — PROCEED TO CODEX RESCUE MVP

