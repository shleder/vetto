# Alpha6 lifecycle and presentation truth

This stabilization pass separates four evidence layers instead of treating Desktop presentation text as authoritative state:

1. canonical persisted rollout source;
2. durable derived/thread-store state;
3. live runtime evidence that Rescue can actually observe;
4. Desktop presentation state.

If two observable authoritative layers conflict, Rescue reports an unknown/diverged state rather than guessing. If a layer cannot be inspected, it remains `UNKNOWN`. Alpha6 does **not** instrument the Desktop renderer, so normal graph/session/doctor output must not fabricate `Thinking`, `Working`, renderer-stream state, or presentation findings from persisted history.

## Durable spawn-edge evidence

Current upstream Codex stores directional subagent lifecycle edges in SQLite table `thread_spawn_edges` with exactly `parent_thread_id`, `child_thread_id`, and `status`; current recognized status values are `open` and `closed`.

Rescue inspects this table read-only and only when the exact current schema is positively identified. A readable exact table with no matching child row is `UNRECORDED`, never `CLOSED`. A missing table, unreadable database, incompatible schema, mismatched parent identity, or unrecognized status is `UNKNOWN`.

Rollout lifecycle markers remain supplementary turn-history evidence. They are not substitutes for `thread_spawn_edges.status`, and invented rollout event names are not promoted into authoritative close evidence.

## Subagent lifecycle

A non-terminal durable turn plus proven live runtime evidence may be classified `WORKING`.

A terminal/completed durable child is classified `DONE` unless there is stronger contradictory evidence. Terminal does **not** mean explicitly closed, and the absence of a live writer does not prove that a retained child is non-dispatchable. Therefore `DONE` leaves dispatchability unknown unless separate evidence establishes it.

A persisted spawn edge with `status=closed` and no proven conflicting live runtime is `INACTIVE` and not dispatchable. This remains true even if a caller supplies presentation evidence that says `Working`; presentation never outranks durable spawn-edge state. If a closed spawn edge conflicts with proven live runtime evidence, Rescue reports lifecycle state as `UNKNOWN` rather than choosing one layer arbitrarily.

An `open` edge with unknown runtime does not by itself prove `WORKING`. An unrecorded or unknown edge does not fabricate closure.

Nested subagent edges are traversed read-only. Existing `lifecycle_status` remains for compatibility; additive graph fields expose `lifecycle_class`, `durable_state`, `runtime_state`, `presentation_state`, `dispatchable`, deterministic finding IDs, and the read-only spawn-edge evidence used for classification.

## Presentation findings

`STALE_ACTIVE_PRESENTATION` means explicit presentation evidence says active while backend/runtime evidence says idle.

`LIVE_TURN_PRESENTATION_DIVERGENCE` means explicit presentation evidence is active but its visible progress stream is absent while backend/runtime evidence remains active and continues to show progress.

`ARCHIVED_SUBAGENT_PRESENTATION_DIVERGENCE` is only valid when evidence establishes all three facts: the session is a subagent, it is archived, and it is being presented as a top-level conversation. Archived storage alone is not corruption, accidental unarchive, source data loss, or a deletion candidate.

Alpha6 defines these presentation classification contracts but does not directly instrument the Desktop renderer. Unless a caller supplies real presentation evidence, `presentation_state` is `UNKNOWN` and normal Rescue CLI/doctor/graph paths do not emit these presentation findings.

## Archive and thread-store failures

`THREAD_STORE_PATH_OR_REFERENCE_DIVERGENCE` is emitted only when persisted thread-store/reference evidence is independently proven inconsistent and the exact Windows extended-path identity bug is not established. Generic operation text such as `archive`, `unarchive`, `reference`, `thread not found`, permission errors, cancellation, unsupported-operation text, or `os error 2` does not prove that root cause.

If the source rollout exists and the `C:\...` versus `\\?\C:\...` identity boundary is independently proven, Rescue uses `WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE`. If source absence is positively established, Rescue may use `ROLLOUT_MISSING`. If source presence cannot be established, the classifier remains unknown rather than inferring a missing rollout.

No classifier in this pass rewrites Codex SQLite, archives/unarchives sessions, deletes source rollouts, renames files, repairs references, changes Desktop state, kills processes, or deletes locks.
