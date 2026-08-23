# oversized_payload

Synthetic fixture matching the Codex 0.147.0 JSONL envelope. Expected primary class: `OVERSIZED_PAYLOAD`.

`verify` is expected to return `REVIEW_REQUIRED`: the fixture has no durable
repository conflict, and bounded oversized evidence makes continuation
uncertain. `STATE_DIVERGED` requires a conflict with saved repository evidence.
