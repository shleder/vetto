# Codex Rescue v0.1.0-alpha.3

> Experimental alpha release focused on a real persisted tool-call corruption case.

## Highlights

- Added `CORRUPTED_TOOL_CALL` detection for persisted tool-call names containing
  NUL or other ASCII control characters.
- Derived from real-world [openai/codex#24369](https://github.com/openai/codex/issues/24369).
- Corrupted names are represented with bounded metadata and are never guessed
  or automatically repaired.
- The original rollout remains untouched and unknown calls are never replayed.
- Verification remains fail-closed with `REVIEW_REQUIRED`.
- Retained regression coverage for #14824 (orphaned/missing tool output) and
  #37719 (oversized persisted tool output).

## Limitations

This release does not repair Codex HTTP 400 responses, automatically
reconstruct corrupted tool names, replay unknown calls, repair arbitrary
malformed arguments, or claim broad compaction recovery.

## Install

```bash
pipx install codex-rescue==0.1.0a3
# or
pip install codex-rescue==0.1.0a3
```

Requires Python 3.11+.

## Privacy

Codex Rescue is local-first. Do not share raw Codex rollout files: they can
contain source code, credentials, or private prompts. Sanitize any report before
sharing.
