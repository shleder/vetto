# Codex Rescue — Final Validation Gate Result

## 1. Final Status

MVP NOT VALIDATED

## 2. Gate 1 — Real Compaction

FAIL.

- Codex version: `0.147.0`.
- No real Codex-generated compaction session was completed.
- A disposable repository and isolated runtime were prepared, but the first
  attempt incorrectly copied an auth file; it was stopped before any Codex run
  and that extra copy was removed.
- No native `codex resume` comparison or Rescue compaction result exists.
- Synthetic compaction remains 5/5 only and does not count for this gate.

## 3. Gate 2 — Third Real Failure

FAIL — evidence is real-origin but does not satisfy the required uncertainty
oracle.

- Codex version: `0.147.0`.
- A disposable repo was changed by a real Codex-generated shell command:
  `app.txt` contains `probe-shell-after-side-effect`; HEAD stayed
  `a6cfe48d8e8fea3bbc799719d5ba379bada85c74`.
- Rollout session: `019ff69f-6f1b-7af0-8f15-c5d732fe0dd1`.
- Source SHA-256 before/after:
  `b552130ae044acbaed6cca1ad1babd5cfece36d662e384f8aecba74025ec139e`.
- Doctor: `HEALTHY` (21 records).
- Salvage: source immutable, rescue ID `73212274bd947b2112afe48e`.
- Verify: `SAFE_TO_CONTINUE`.
- The sanitized rollout contains a paired `custom_tool_call_output`, so the
  required claim “side effect executed but durable result is missing” is not
  proven. Rescue also did not mark the action `unknown` or require review.
- Therefore this is useful evidence of a real side effect, but Gate 2 FAILS
  rather than being promoted to a passing third failure case.

## 4. Gate 3 — Fresh Continuation

FAIL.

- Public CLI: `codex-cli 0.147.0`.
- A ConPTY/node-pty probe emitted terminal escape sequences, but the parent
  process still reported `isTTY=false`; cleanup produced `AttachConsole failed`.
- No reliable interactive continuation reached a normal `turn.completed`.
- Existing read-only continuation remains `PARTIAL_PASS`: it verified HEAD/diff,
  preserved unknown state, made no duplicate edit, and did not change the repo,
  but its final `turn.completed` was not captured.

## 5. Regression Status

- Tests: **41 passed, 1 skipped**.
- Synthetic fixtures: **5/5 PASS**.
- Real cases: one genuine interrupted case, one real-origin induced truncation
  case, and one real side-effect observation that fails the missing-result
  oracle. No real compaction case.

## 6. Source Immutability

- Interrupted case: source SHA-256
  `45570c1608f6108460cb7d0856ded721fe8e801223e318137482b8e3e0337a71`
  before and after.
- Truncated-copy case: original source unchanged; corruption was induced only
  on a disposable copy. Published raw rollout was removed and replaced by a
  sanitized fixture.
- Gate 2 side-effect case: source SHA-256
  `b552130ae044acbaed6cca1ad1babd5cfece36d662e384f8aecba74025ec139e`
  before and after.

## 7. Native Codex Comparison

Native fork was blocked by `stdin is not a terminal`; public `exec resume` has
no safe cwd redirection option. Rescue adds immutable source hashing, Git
state verification, evidence references, and explicit review/unknown states,
but full native parity was not demonstrated.

## 8. Known Limitations

- No real compaction validation.
- No qualifying third failure with proven missing durable result.
- No TTY continuation through `turn.completed`.
- Previous `0.146.1` write/recovery remains unproven.
- Real hook ordering and compaction-boundary durability remain unvalidated.
- The side-effect case exposed a possible evidence mismatch: the runtime
  observation and rollout pairing disagree about whether the result was durable.

## 9. Files Changed

- `src/codex_rescue/` parser, doctor, journal, reconstruction, CLI, verify,
  discovery, and hooks hardening.
- `scripts/run_interrupted_case.py`.
- `tests/`, including sanitized real-corpus regression checks.
- `real-corpus/` sanitized evidence bundles only.
- `VALIDATION_NOTES.md`, `MVP_RESULT.md`.

## 10. Reproduction Commands

```powershell
cd codex-rescue
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python -m codex_rescue.harness fixtures --output .validation-output\fixtures
```

## 11. Recommendation

DO NOT RELEASE YET
