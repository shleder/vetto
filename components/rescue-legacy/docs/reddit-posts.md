# Reddit Post Drafts

## r/SideProject (friendly to promo)

### Title
I built a forensics and recovery tool for OpenAI Codex sessions – it diagnoses crashed sessions and salvages lost work

### Body
Been working on this for a few months. Codex Rescue is a read-only-first diagnostic and recovery toolkit for OpenAI Codex CLI sessions.

The problem: when a Codex session crashes, gets killed mid-write, or hits a compaction edge case, the session state (JSONL rollout + SQLite index) can end up inconsistent. Resuming often fails silently or loses progress. There was no tool to inspect what actually happened.

What it does:
- `doctor` — deep structural diagnostics on any session (oversized records, truncated transcripts, wedged projections, tool-pairing anomalies)
- `diff` — compares raw JSONL vs SQLite state vs git state
- `timeline` — forensic event timeline
- `salvage` — extracts durable history into a clean fork without touching the original
- `plan` / `apply-plan` — reversible repair plans with pre-mutation backup

Just shipped Alpha7 with an autopilot controller, desktop state inspection, and portable session export/import.

Install: `npx --yes codex-rescue doctor --latest` (no Python needed, ships native binaries)

GitHub: https://github.com/shleder/codex-rescue

Would love feedback on the UX and any edge cases I'm missing.

---

## r/ChatGPTCoding (technical, strict)

### Title
Built a read-only forensics tool for diagnosing crashed Codex CLI sessions

### Body
If you've ever had a Codex session die mid-task and lose progress, this might help.

Codex stores session state as JSONL rollout files + a SQLite projection layer. When things go wrong (crash, kill, compaction edge case), the state can become inconsistent and resuming fails silently.

I built codex-rescue to inspect and recover from this:

```
npx --yes codex-rescue doctor --latest
```

It runs structural, projection, and tool-pairing diagnostics without touching your data. If it finds issues, `salvage` extracts durable history into a clean fork, and `plan`/`apply-plan` generates a reversible repair.

Alpha7 just shipped with autopilot, desktop inspection, and portable export/import.

https://github.com/shleder/codex-rescue

---

## r/codex (if exists, or r/OpenAI)

### Title
Tool for recovering interrupted Codex sessions – read-only forensics + safe salvage

### Body
Sharing a tool I built for diagnosing and recovering crashed OpenAI Codex CLI sessions.

`npx --yes codex-rescue doctor --latest` inspects your latest session for truncation, projection divergence, tool-pairing issues, and more — all read-only.

If something's broken, `salvage` extracts what's recoverable into a clean fork. `plan` + `apply-plan` handles repairs with pre-mutation backup.

Just released Alpha7. GitHub: https://github.com/shleder/codex-rescue

---

## Posting rules (from community-marketing skill)
- 90% helpful activity, 10% promo
- Post during weekday mornings (US time)
- Respond to every comment
- Don't ask for upvotes
- Include real technical details, not hype
- Cross-post to Dev.to with canonical URL back to GitHub
