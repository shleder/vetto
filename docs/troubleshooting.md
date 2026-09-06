# Troubleshooting silent failures

Three failure shapes produce no useful error where they happen. Each section
gives one distinguishing check and exactly one next action.

## 1. Silent auth hang: agent waits forever with no output

**Symptom.** An in-sandbox agent that cannot authenticate produces no stderr,
no events, no diagnosis — then a retry that hangs identically. From outside it
looks like slowness.

**Distinguish.** If the session exceeds its normal startup time with zero
events (`vetto audit --latest` shows nothing new), treat it as auth, not load.

**Action.** Kill it and re-run with an explicit deadline instead of waiting:
`vetto --timeout 120s -- <agent>`. A timeout exits `124` with a recap
line instead of hanging. Then fix the credential path (broker or pushed
credentials — never a long-lived key copied into the sandbox) and re-run.
For the report bundle: `vetto pack --bug -o bug.vetto-pack`.

## 2. Outer-boundary denial misread as an agent failure

**Symptom.** `Operation not permitted` / `EACCES` / `EPERM` inside the agent,
followed by escalation, approval, or a product-bug hunt — when the denial came
from a boundary *outside* vetto (outer container, eval harness, host policy).

**Distinguish.** Run the same failing command in an ordinary terminal with
equivalent inputs. If it succeeds there but fails inside the agent session,
the boundary is outside the agent — retrying or approving inside cannot fix it.

**Action.** Attribute first, act second: vetto exit `125` means the outer
boundary denied it — inspect with `vetto audit --latest` (denied Landlock
paths), not with re-runs. See [exit-codes.md](exit-codes.md#attributing-failures-sandbox-denial-vs-agent-error).

## 3. Agent runs unsandboxed without notice (shim bypass)

**Symptom.** Everything works, zero denials, zero audit events — because the
agent never entered the sandbox: the shell resolved the real binary before the
shim (`PATH` order), or the agent was launched by absolute path.

**Distinguish.** One command: `vetto status`. If your agent is not listed as
wrapped, the session you just ran was unwrapped.

**Action.** Re-run `vetto enable <agent>` and confirm it reports the shim
first in `PATH` (`command -v <agent>` must point inside `~/.vetto/shims`).
Re-run the session; verify with `vetto audit --latest` that events exist.
