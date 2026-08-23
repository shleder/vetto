# Codex Rescue v0.1.0-alpha.2 Release Checklist

## Core safety
- [x] doctor does not modify source rollout
- [x] salvage does not modify source rollout
- [x] verify does not modify source rollout
- [x] unknown actions are never automatically replayed

## Packaging
- [x] clean install succeeds
- [x] installed CLI starts
- [x] --version works
- [x] --help works

## Tests
- [x] unit test suite passes
- [x] synthetic fixtures 5/5 pass
- [x] sanitized real-origin regression cases pass
- [x] source SHA-256 unchanged in demo
- [x] clean clone fixture portability verified

## Privacy
- [x] no raw private rollouts committed
- [x] no credentials/tokens found
- [x] sanitized corpus reviewed

## Public repository
- [x] README.md
- [x] LICENSE
- [x] CONTRIBUTING.md
- [x] SECURITY.md
- [x] CHANGELOG.md
- [x] issue templates
- [x] pull request template
- [x] CI workflow (verified green across Windows/Ubuntu x Python 3.11/3.12/3.13)
- [x] clean public clone fixture portability verified
- [x] release notes
- [x] strict real-macOS gate verified for the exact release candidate

## Claims
- [x] README says experimental alpha
- [x] real compaction limitation disclosed
- [x] TTY continuation limitation disclosed
- [x] previous-version limitation disclosed

## Final
- [x] git diff reviewed
- [x] git status reviewed
- [x] release blocker review completed
