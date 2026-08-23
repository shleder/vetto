# Using vetto in CI/CD

Target length: 6 minutes.

1. Show a workflow using `action/action.yml` with `net: off`.
2. Explain why the action builds the checked-out source and does not download
   an unverified executable.
3. Enable JSON and SARIF reports plus `fail-on-block`.
4. Run a harmless command, then a fixture that triggers a blocked access.
5. Inspect the JSON summary, workflow exit status, and uploaded SARIF result.
6. Mention that the workflow author controls the command; pull-request text is
   data and must never become a shell command.
