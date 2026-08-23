# lost_tail_after_compaction

Synthetic fixture matching the Codex 0.147.0 JSONL envelope. Expected primary class: `COMPACTION_STATE_LOSS`.

`verify` is expected to return `REVIEW_REQUIRED`: `repo_before` is a harness
snapshot, not a durable pre-salvage repository baseline in the handoff. The
compaction state-loss evidence is uncertain continuation state, not proven
repository divergence.
