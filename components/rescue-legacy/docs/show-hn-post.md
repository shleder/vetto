# Show HN Post Draft

## Title
Show HN: Codex Rescue – Read-only forensics and recovery for OpenAI Codex sessions

## Body

I built a tool that diagnoses and recovers interrupted OpenAI Codex CLI sessions.

Codex stores session state as JSONL rollout files plus a SQLite projection layer. When a session crashes, gets compacted mid-write, or the process is killed, the rollout can end up truncated, the SQLite index can go stale, and resuming often fails silently or loses work.

Codex Rescue inspects all of this read-only-first:

- `doctor` — structural, projection, tool-pairing, and ordinal diagnostics on any session
- `diff` — compares raw JSONL vs SQLite state vs git worktree state
- `timeline` — privacy-safe forensic event timeline
- `salvage` — extracts durable history into a clean recovery fork without touching the original
- `plan` / `apply-plan` — generates and executes a reversible repair plan with pre-mutation backup

It never mutates source data in place, never invents missing tool outputs, and never replays side effects with uncertain state.

Alpha7 (just released) adds an autopilot controller, desktop state inspection, portable session export/import, and a privacy engine with trust verdicts.

Install: `npx --yes codex-rescue doctor --latest`

No Python needed — ships pre-compiled binaries for Linux, Windows, and macOS via npm.

GitHub: https://github.com/shleder/codex-rescue

## Notes for posting
- Post as Show HN (technical angle: forensics engine for AI session state)
- Best time: Tuesday-Thursday, 8-10 AM ET
- Respond to every comment within 30 minutes
- Don't ask for upvotes, ask for feedback
- Have the maintainer ready to answer architecture questions
