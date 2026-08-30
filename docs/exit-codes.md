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
