# History secret-scan baseline

Before the Codex Rescue history was connected to Vetto, both complete
repositories were scanned with Gitleaks `8.30.1` using `git --log-opts=--all`.

- Vetto: 49 commits scanned, no findings.
- Codex Rescue: 190 reachable commits scanned, six findings.

All six Codex Rescue findings are intentionally synthetic credential-shaped
strings in sanitizer/adversarial tests. The surrounding tests construct fake
GitHub, PyPI, JWT and generic token values and assert that the values are
redacted. They are not live credentials. Their exact historical fingerprints
are recorded in the root `.gitleaksignore` so future scans still fail on every
unclassified finding.

The pre-merge histories are preserved by these remote annotated tags:

- Vetto: `pre-rescue-merge-v0.1.0`
- Codex Rescue: `pre-vetto-merge-v0.1.0-alpha.7`

The local migration audit also produced verified full-history Git bundles.
Those bundles are private recovery artifacts and are never committed or
published.

Every public release must rerun Gitleaks across `--all` history and scan the
assembled release/npm archives before the repository visibility gate opens.

