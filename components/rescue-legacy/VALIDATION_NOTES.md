# Codex Rescue — Final Validation Notes

## Status

MVP NOT VALIDATED. DO NOT RELEASE YET.

This phase did not add product features. It attempted exactly the three final
evidence gates from the validation prompt.

## Gate results

| Gate | Result | Evidence |
|---|---|---|
| Real compaction | FAIL | No real compaction rollout completed; only synthetic compaction exists. |
| Third independent failure | FAIL | Real side effect observed, but rollout has paired output and Rescue returned HEALTHY/SAFE_TO_CONTINUE, so missing-result/unknown behavior is unproven. |
| Fresh TTY continuation | FAIL | ConPTY probe had `isTTY=false`; no normal `turn.completed`. |

## Gate 1 details

Current CLI was `0.147.0`. A disposable repo was prepared, but no Codex run
started after an accidental credential-copy setup was detected. The extra copy
was removed. No compaction evidence was created.

## Gate 2 details

Current CLI `0.147.0` generated a real shell side effect in a disposable repo:
`app.txt` gained `probe-shell-after-side-effect`, with unchanged HEAD
`a6cfe48d8e8fea3bbc799719d5ba379bada85c74`. The rollout was session
`019ff69f-6f1b-7af0-8f15-c5d732fe0dd1` and its SHA-256 remained
`b552130ae044acbaed6cca1ad1babd5cfece36d662e384f8aecba74025ec139e` before
and after Rescue.

Doctor returned `HEALTHY`, salvage preserved the source, and verify returned
`SAFE_TO_CONTINUE`. However, the sanitized rollout contains a paired durable
`custom_tool_call_output`; therefore the required “executed side effect with
missing durable result” condition is not established. This case is recorded,
but Gate 2 is not passed.

## Gate 3 details

`node-pty` could emit ConPTY escape sequences, but the parent still reported
`isTTY=false`, and cleanup produced `AttachConsole failed`. No fresh public
Codex continuation reached a captured normal `turn.completed`. The prior
continuation remains only `PARTIAL_PASS`.

## Regression and safety

- Full suite: **41 passed, 1 skipped**.
- Synthetic recovery harness: **5/5 PASS**.
- Existing genuine interrupted case remains `UNFINISHED_TOOL_CALL`, salvage
  immutable, verify `REVIEW_REQUIRED`.
- Existing real-origin truncated-copy case remains `TRUNCATED_TRANSCRIPT`,
  salvage immutable, verify `REVIEW_REQUIRED`.
- Publishable corpus contains sanitized fixtures only; raw rollouts stay in
  gitignored runtime storage.
- Previous `0.146.1` login and smoke succeeded, but previous write/recovery was
  not proven.

## Final decision

MVP NOT VALIDATED

DO NOT RELEASE YET
