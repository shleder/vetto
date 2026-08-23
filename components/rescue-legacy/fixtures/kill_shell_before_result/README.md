# kill_shell_before_result

Synthetic fixture matching the Codex 0.147.0 JSONL envelope. Expected primary class: `UNFINISHED_TOOL_CALL`.

`verify` is expected to return `REVIEW_REQUIRED`: `repo_before` is a harness
snapshot, not a durable pre-salvage repository baseline in the handoff. Rescue
must not infer `STATE_DIVERGED` from that fixture-only comparison; the shell
side effect has unknown execution state and requires review.
