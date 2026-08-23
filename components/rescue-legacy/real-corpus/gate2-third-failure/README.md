# Sanitized real Codex rollout: gate2-third-failure

Derived from a genuine Codex 0.147.0 rollout (session `019ff69f-6f1b-7af0-8f15-c5d732fe0dd1`) in a disposable Git repository. The raw JSONL and credentials are excluded.

- Failure class: `side_effect_without_durable_result`. Codex generated one PowerShell command that appended `probe-shell-after-side-effect` to `app.txt` and then slept; the controller terminated the owned process before a durable shell result was emitted.
- This is mechanistically distinct from an interrupted tool-call transcript and from an induced truncated-copy transcript: the real repository side effect is proven by `M app.txt`, while the source rollout remains complete and parseable.
- The source SHA-256 was unchanged before and after salvage: `b552130ae044acbaed6cca1ad1babd5cfece36d662e384f8aecba74025ec139e`.
- Doctor reported `HEALTHY` with 21 valid records. Fork salvage completed with rescue ID `73212274bd947b2112afe48e`; verification returned `SAFE_TO_CONTINUE`.
- No automatic replay or native resume/fork was attempted. The source session remains immutable.

See `metadata.json`, `session/rollout-sanitized.jsonl`, `repo-state/`, and `expected.json`.
