# Vetto Exit Codes

Vetto guarantees consistent, deterministic process exit codes across Linux, macOS, and Windows.

| Exit Code | Name | Description |
|---|---|---|
| `0` | `EXIT_SUCCESS` | Sandboxed agent completed normally with status code 0. |
| `1` | `EXIT_AGENT_ERROR` | Sandboxed agent exited with a non-zero status code (or general CLI error). |
| `124` | `EXIT_TIMEOUT` | Session exceeded the configured `--timeout` deadline and was terminated by the supervisor (mirrors GNU `timeout(1)`). |
| `125` | `EXIT_FAIL_CLOSED` | Fail-closed sandbox error: required isolation tier unavailable, boundary verification leak detected via `--verify`, or platform setup failed. |
| `126` | `EXIT_POLICY_BLOCKED` | Policy violation: blocked access attempts reached `--fail-on-block` threshold, or immutable policy lockdown was violated. |
| `127` | `EXIT_COMMAND_NOT_FOUND` | Agent executable not found in `$PATH` or inaccessible. |
| `128 + N` | `EXIT_SIGNAL_BASE + N` | Agent process was terminated by signal `N` (e.g., `130` for SIGINT, `137` for SIGKILL, `143` for SIGTERM). |

## Behavior in CI / Headless Mode

When running with `--ci` or `--tui=none`, vetto emits structured JSON summaries to `stdout` containing both the agent's raw `exit_code` and the supervisor's `final_exit_code`.

## Attributing failures: sandbox denial vs agent error

When an agent run fails inside nested sandboxes (eval harnesses, outer containers,
vetto), the first question is always: did *my* sandbox block this, or did the
agent itself fail? Rules of thumb:

- `Operation not permitted` / `EACCES` / `EPERM` on paths **outside** the agent's
  own state dir, paired with vetto exit `125`, means the *outer* boundary denied
  it — the inner tool cannot fix this by retrying. Inspect with
  `vetto audit --latest` (denied Landlock paths) instead of re-running the agent.
- Same errno on paths **inside** the agent workspace with exit `0`/`1` usually
  means the agent or its own harness did it — check `vetto diff --stat` to see
  what the session actually touched before blaming the sandbox.
- `126` always means vetto policy intentionally blocked the action
  (`--fail-on-block` threshold or lockdown violation): this is the sandbox
  working as configured, not an environment bug. `policy explain --why` shows
  the exact rule.
- Timeouts (`124`) with repeated identical failures beforehand suggest a runaway
  retry loop — see `vetto watchdog` rather than raising limits.
