# Sanitized real Codex rollout: case-controlled-1

Derived from a genuine Codex 0.147.0 rollout (session `019ff641-7570-7851-96be-7a2f9f9decbc`). The raw JSONL is not copied.

- Failure class and doctor result: `interrupted_tool_call` / `UNFINISHED_TOOL_CALL`.
- The structural session preserves record order, outer/inner types, roles, IDs, call IDs, and matched/unmatched call pairing. Messages, reasoning, tool arguments/outputs, base instructions, and secrets are redacted; offsets are synthetic.
- Source SHA-256 is unchanged before/after salvage: `45570c1608f6108460cb7d0856ded721fe8e801223e318137482b8e3e0337a71`.
- Salvage completed in a fork with the source untouched. Verify conservatively returns `REVIEW_REQUIRED` because the final tool call has no durable result.

See `metadata.json`, `session/rollout-sanitized.jsonl`, `repo-state/`, and `expected.json`.
