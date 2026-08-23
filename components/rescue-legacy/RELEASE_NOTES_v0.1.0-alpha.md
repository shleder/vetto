# Codex Rescue v0.1.0-alpha

> Experimental first release of a local recovery tool for interrupted and damaged OpenAI Codex sessions.

## What it does

Codex Rescue diagnoses broken Codex CLI sessions, verifies the repository state, and creates an evidence-backed continuation handoff — all without modifying the original rollout.

| Command | Purpose |
|---|---|
| `sessions` | Find recent Codex sessions |
| `doctor` | Diagnose an interrupted or damaged session (read-only) |
| `salvage` | Create an immutable evidence-backed recovery handoff |
| `verify` | Detect repository divergence before continuation |

Every recovered fact is labeled with a confidence level: **VERIFIED**, **RECONSTRUCTED**, or **UNKNOWN**. Unknown state remains unknown — Rescue never guesses.

## Install

```bash
# Recommended global installation via pipx
pipx install codex-rescue

# Or via pip
pip install codex-rescue
```

Requires Python 3.11+.

## Quick demo

```bash
codex-rescue doctor --latest
codex-rescue salvage --latest --fork
codex-rescue verify <rescue-id>
```

## What has been proven

- 5 synthetic failure types diagnosed and recovered correctly
- 2 real-origin sanitized cases (interrupted session, induced truncation)
- Source rollout immutability verified via SHA-256 before/after
- 43 automated tests pass, 1 skipped (real-session test requires live Codex)
- Git state verification detects HEAD, worktree, and diff divergence

### Validated Codex versions

- **Codex CLI 0.147.0** — real interrupted session recovery demonstrated
- **Codex CLI 0.146.1** — isolated and smoke-tested
- **Codex 0.145.0-alpha.18** — sanitized format compatibility observed

## Alpha limitations

> [!WARNING]
> This is experimental alpha software.

- Broad real compaction recovery is **not yet validated** — only synthetic fixtures
- Interactive continuation depends on terminal/TTY environment
- Previous Codex version recovery coverage is limited
- Not every arbitrary corruption type is supported
- No Linux/macOS real-failure validation yet

## Privacy

- **Local-only** — no telemetry, no analytics, no cloud upload, no account
- Codex rollout files can contain secrets, API keys, and private code
- **Sanitize all data before sharing** in issue reports
- Built-in secret redaction is bounded and not a complete DLP system

## Submit recovery reports

The main goal of this alpha is collecting real broken Codex sessions.

[Open a Recovery Report →](https://github.com/shleder/codex-rescue/issues/new?template=recovery-report.yml)

⚠️ **Do NOT upload raw rollout files containing secrets.** Sanitize first.

## License

MIT
