# issue_14824_orphaned_tool_output

Minimal sanitized fixture derived from the public evidence in
[openai/codex#14824](https://github.com/openai/codex/issues/14824), especially
the `nemoriko` report
([comment](https://github.com/openai/codex/issues/14824#issuecomment-5266609829)).

It represents only the load-bearing boundary: a Codex CLI 0.147.0 `wait`
`function_call` is durably present in the rollout, with no matching
`function_call_output` before the rollout ends. The command, cell id, prompt,
repository, and paths are synthetic or sanitized. No log database, prompt,
repository content, or secret is included.

Expected behavior:

- `doctor`: `UNFINISHED_TOOL_CALL`
- `salvage`: create a fork without modifying the source rollout
- `verify`: `REVIEW_REQUIRED` because the tool execution state is unknown
