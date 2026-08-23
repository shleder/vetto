# Vetto 0.2 field testing

The `0.2.0-alpha.*` line is an opt-in field test. Install a published build,
never an arbitrary `main` commit:

```console
npm install --global @shleddy/vetto@next
vetto doctor
vetto rescue --json scan
```

## What to test

1. `vetto doctor` reports the actual backend and tier without claiming missing
   capabilities.
2. A normal agent launch still works under the selected policy.
3. A secret/path/network probe is blocked according to the profile.
4. `vetto rescue scan` lists only expected session JSONL files.
5. `diagnose` reports malformed or unterminated records without changing the
   source.
6. `snapshot` creates a new verified copy and refuses a second write to the
   same destination.

## Safe reports

Use the GitHub issue forms and include:

- operating system and architecture;
- Vetto and agent versions;
- the exact command and expected/actual result;
- `vetto doctor` output;
- a sanitized Vetto report when available.

Never upload raw agent sessions, `auth.json`, configuration files, API keys,
cookies, access tokens, private keys, proprietary prompts, or an unreviewed
home-directory path. The sanitizer is best-effort, so inspect every artifact
yourself before sharing it.

Security vulnerabilities do not belong in public issues. Use GitHub private
vulnerability reporting from the repository Security tab.

## Alpha quality gates

An alpha advances only when its stated scope has:

- no unresolved P0/P1 regression;
- green unit, integration, clippy and release-matrix checks;
- a passing Gitleaks history and release-archive scan;
- published checksums and known limitations;
- a tested rollback or uninstall path.
