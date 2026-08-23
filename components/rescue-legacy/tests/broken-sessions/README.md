# Broken-session regression corpus

This directory is reserved for sanitized, real Codex rollout cases. Raw user
sessions must stay outside Git and outside this repository; committed cases
must contain no credentials, tokens, private prompts, or other sensitive data.

Each committed case should contain a `README.md`, `metadata.json`, `session/`,
`repo-state/`, and `expected.json`. The metadata must record the exact Codex
version, failure class, session ID, and `created_from_real_codex: true`.

The safety tests currently use disposable temporary rollouts only. They verify
read-only behavior and conservative state handling, but they do not count as
real-session validation or as evidence for MVP release readiness.
