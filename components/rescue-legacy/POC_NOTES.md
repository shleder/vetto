# Codex Rescue PoC Notes

## Environment

- OS: Windows 11 x64 (`10.0.26200` observed in the current Codex environment)
- Installed Codex CLI: `codex-cli 0.147.0`
- Desktop rollout metadata observed: `0.147.0-alpha.6.6`; the npm CLI and embedded Desktop build may differ.
- Implementation runtime: Python 3.11 standard library.

## Session storage

- Default root: `%USERPROFILE%\.codex` (subject to `CODEX_HOME`).
- Active rollouts: `sessions/YYYY/MM/DD/rollout-<timestamp>-<uuid>.jsonl`.
- Archived rollouts: `archived_sessions/rollout-*.jsonl`.
- `session_index.jsonl` maps IDs to user-facing thread names and timestamps.
- The UUID in the rollout filename matches `session_meta.payload.session_id` / `id` in sampled current sessions.
- Read-only inventory during Stage 0: 276 rollouts, about 534 MB total; largest about 42 MB.

## Session schema

The current JSONL envelope is:

```json
{"timestamp":"...","type":"...","payload":{}}
```

Observed outer types include `session_meta`, `event_msg`, `response_item`,
`world_state`, `turn_context`, `compacted`, and
`inter_agent_communication_metadata`.

`session_meta.payload` includes session ID, cwd, originator, CLI version, source,
model provider, history mode, and context window. The PoC treats unknown fields
as opaque and does not assume older formats.

## Tool events

Observed pairs:

- `response_item/function_call` with `call_id`, `name`, `arguments` followed by
  `function_call_output` with the same `call_id` and `output`.
- `response_item/custom_tool_call` with `call_id`, `name`, `input`, followed by
  `custom_tool_call_output`.

An input without a durable matching output is classified as unfinished. Its
execution status remains `unknown`; Rescue never replays it automatically.

## Compaction records

- Outer `compacted` records contain `message`, `replacement_history`, and window IDs.
- `event_msg/context_compacted` records are also present.
- Stage 0 observed 217 `compacted` and 216 `context_compacted` records across local sessions.
- `turn_aborted` can record interruptions separately.

The model-produced compaction summary is not treated as truth. Durable records,
the rescue journal, and current Git/repository state take priority.

## Resume and fork behavior

Public CLI paths exist:

```text
codex resume [SESSION_ID] [PROMPT]
codex fork [SESSION_ID] [PROMPT]
codex exec resume [SESSION_ID] [PROMPT]
codex exec --ephemeral [PROMPT]
```

Neither `resume` nor `fork` accepts an arbitrary JSONL path. For a corrupt source,
the PoC therefore emits an exact fresh public CLI command and bounded handoff
prompt. It does not import or rewrite the old transcript.

## SQLite usage

Read-only inspection found:

- `state_5.sqlite`: `threads`, `thread_spawn_edges`, `thread_dynamic_tools`, `thread_sections`;
  `threads` maps IDs to rollout paths and metadata.
- `thread_history_1.sqlite`: projected turns/items and rollout offsets.
- `logs_2.sqlite`, `goals_1.sqlite`, `queue_1.sqlite`, and `memories_1.sqlite`.

Codex Rescue does not write to any of these stores. No recovery path requires a
private database mutation.

## Hook schemas

Current upstream Codex exposes command hook schemas for:

- `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`;
- `PermissionRequest`, `PreCompact`, `PostCompact`, `Stop`, `SessionEnd`;
- `SubagentStart`, `SubagentStop`.

`PreCompact`/`PostCompact` include `trigger: manual|auto`, session ID, cwd,
transcript path, model and turn ID. Hooks are stable/enabled in the installed
CLI, but are advisory evidence: process death can occur before a hook is delivered.

## Unstable/private assumptions

- Rollout JSONL and SQLite schemas are internal implementation details and may change.
- Desktop and npm CLI versions can differ.
- Hook schemas are versioned by upstream code, not by this PoC.
- `fork` cannot salvage malformed source input by itself.
- Synthetic fixtures match the observed 0.147.0 envelope but are not substitutes
  for a growing corpus of real broken sessions.
- Two older Codex versions were not installed locally; the PoC does not claim
  compatibility with versions it could not execute.

