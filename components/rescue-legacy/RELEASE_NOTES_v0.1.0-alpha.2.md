# Codex Rescue v0.1.0-alpha.2

> Experimental alpha release focused on fail-closed recovery and evidence integrity.

## Highlights

- Recovery now treats compaction state loss, ambiguous tool-call correlation, and unknown operational records as review-required evidence.
- Source snapshot checks, Git-state fingerprinting, bounded parsing and hashing, redaction, artifact writing, and continuation rendering have been hardened.
- Fixture materialization avoids transient Git lock files, improving clean-clone portability.
- Source distributions exclude the default local rescue-artifact directory.

## Validation

- Windows and Linux complete validation passed for the exact release candidate.
- The strict real-macOS GitHub Actions evidence gate passed for the same 105-file candidate archive.
- The wheel and sdist are built, inspected for unwanted content, and installed in fresh isolated environments for CLI and import smoke checks during release preparation.

## Install

```bash
pipx install codex-rescue
# or
pip install codex-rescue
```

Requires Python 3.11+.

## Alpha limitations

Codex Rescue remains experimental alpha software. It never automatically replays unknown work; review the handoff and repository state before continuing. See the README and CHANGELOG for compatibility limits and the full safety posture.

## Privacy

Codex Rescue is local-first. Do not share raw Codex rollout files: they can contain source code, credentials, or private prompts. Sanitize any report before sharing.
