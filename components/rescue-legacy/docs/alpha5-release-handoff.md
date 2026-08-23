# Alpha5 release handoff

Operational handoff for Codex Rescue `0.1.0a5` / npm `0.1.0-alpha.5`.

## Source identity

- `HARDENING_PR_NUMBER`: `7`
- `HARDENING_PR_STATE`: open and non-draft until the exact-head CI gates below are green; merge only after those gates pass.
- `QUALIFIED_SOURCE_SHA`: **the exact current PR #7 head that has green Core CI and Alpha5 Native/NPM qualification.** Do not trust a hardcoded SHA in this tracked file: changing this file changes the commit SHA. Resolve PR #7 immediately before merge and bind every later step to that exact value.
- `EXPECTED_PYTHON_VERSION`: `0.1.0a5`
- `EXPECTED_NPM_VERSION`: `0.1.0-alpha.5`
- `EXPECTED_TAG`: `v0.1.0-alpha.5`

PYPI_ALPHA5_POLICY: OFFICIAL_RELEASE_CHANNEL. PyPI is an official Alpha5
distribution channel alongside npm and GitHub standalone binaries.
Publication uses PyPI Trusted Publishing / GitHub OIDC, bound to the exact
release candidate artifacts and manifest hashes.

Official Alpha5 distribution channels:

- GitHub Release / standalone native binaries
- `npx codex-rescue@0.1.0-alpha.5`
- `npm install -g codex-rescue@0.1.0-alpha.5`
- `pip install codex-rescue==0.1.0a5` / `pipx install codex-rescue==0.1.0a5`

## NPM package names

Publish these exact packages only:

1. `codex-rescue-linux-x64`
2. `codex-rescue-win32-x64`
3. `codex-rescue-darwin-arm64`
4. `codex-rescue-darwin-x64`
5. `codex-rescue` — publish **last**

`NPM_NAME_PREFLIGHT_RESULT`: prior pre-release audit PASS: all five names returned unambiguous npm registry E404 and were therefore unregistered at that check. That result is time-sensitive and does **not** authorize publication by itself. The publish workflow must re-run registry checks, pass `npm whoami`, and pass the name/maintainer ownership gate immediately before publication.

## Required CI runs

For the exact PR #7 head that will be merged into the release source, require all of these green:

- `CI` core matrix: Linux, Windows, macOS; Python 3.11 and 3.13.
- `Alpha5 Native and NPM`: Linux x64, Windows x64, macOS arm64, macOS x64 plus npm security and Python/native/npm structured JSON parity.

If a separate Alpha5 qualification or registry-preflight workflow is present on the exact head, require it too. A green run for any different SHA does not qualify the release source.

After PR #7 is merged, **do not publish immediately just because the PR head was green**. Resolve the merge SHA on `main`, verify that the merge contains the exact qualified head without additional release-affecting changes, then build the deterministic release candidate at the final tagged release SHA. The release-candidate workflow is the final artifact qualification gate.

## Exact release sequence

1. **Resolve exact release source SHA:** Resolve PR #7 and record its exact current head SHA. Confirm it is mergeable, based on current `main`, and all required exact-head CI above is green.
2. **Merge PR #7:** Merge PR #7 without rewriting the qualified branch before merge. Record the resulting `MAIN_MERGE_SHA`.
3. **Verify versions on main:** Verify the merged source reports Python `0.1.0a5`, npm `0.1.0-alpha.5`, and the five package names. Confirm no unrelated commits exist between qualification and the intended tag.
4. **Re-check npm package availability/ownership:** Re-check all five npm package names and publisher identity/rights. Stop if any name or identity gate changed.
5. **Re-check PyPI:** Confirm `codex-rescue==0.1.0a5` does not unexpectedly exist on PyPI (`404 Not Found`).
6. **Create git tag:** Create `v0.1.0-alpha.5` at the exact intended release SHA.
7. **Verify tag:** Verify `v0.1.0-alpha.5` resolves to the exact intended release SHA.
8. **Build and qualify candidate:** Dispatch `Alpha5 Release Candidate` **at workflow ref `v0.1.0-alpha.5`** with `release_tag=v0.1.0-alpha.5` and `expected_sha=<exact release SHA>`. Require success. Record workflow run ID and download `alpha5-release-bundle`.
9. **Verify candidate manifest:** Verify `release-manifest.json`, `SHA256SUMS`, and the complete 11-artifact candidate set.
10. **Create GitHub prerelease:** Create the GitHub **prerelease** for `v0.1.0-alpha.5`, targeting the exact same SHA, and attach exactly the candidate bundle files.
11. **Publish to PyPI:** Dispatch `Publish Alpha5 to PyPI` workflow with `release_tag=v0.1.0-alpha.5`, `expected_sha=<exact release SHA>`, and `candidate_run_id=<run ID>`. The workflow publishes the exact qualified wheel and sdist to PyPI via Trusted Publishing.
12. **Verify PyPI publication:** Verify PyPI exposes `codex-rescue==0.1.0a5` and file hashes match `release-manifest.json`.
13. **Publish npm platform packages:** Dispatch `Publish Alpha5` workflow to publish platform packages in deterministic order: Linux x64, Windows x64, macOS arm64, macOS x64.
14. **Verify platform packages:** Confirm each platform package version, integrity, shasum, and maintainer on npm registry.
15. **Publish npm meta package last:** Publish `codex-rescue@0.1.0-alpha.5` **last** and verify its optional dependencies on npm registry.
16. **Verify all install surfaces:**
    - `npx codex-rescue@0.1.0-alpha.5 --version` / `--help`
    - `npm install -g codex-rescue@0.1.0-alpha.5`
    - `pip install codex-rescue==0.1.0a5`
    - `pipx install codex-rescue==0.1.0a5`
    - Standalone GitHub Release binaries on supported platforms.
17. **Verify public artifact integrity:** Confirm all public artifact hashes match `release-manifest.json` and `SHA256SUMS`.

## Expected artifacts

Exact release-candidate bundle:

- `codex_rescue-0.1.0a5-py3-none-any.whl`
- `codex_rescue-0.1.0a5.tar.gz`
- `codex-rescue-linux-x64`
- `codex-rescue-win32-x64.exe`
- `codex-rescue-darwin-arm64`
- `codex-rescue-darwin-x64`
- `codex-rescue-linux-x64-0.1.0-alpha.5.tgz`
- `codex-rescue-win32-x64-0.1.0-alpha.5.tgz`
- `codex-rescue-darwin-arm64-0.1.0-alpha.5.tgz`
- `codex-rescue-darwin-x64-0.1.0-alpha.5.tgz`
- `codex-rescue-0.1.0-alpha.5.tgz`
- `SHA256SUMS`
- `release-manifest.json`

## Post-publication checks

- GitHub tag and prerelease resolve to the intended release SHA.
- Download every GitHub release asset and verify SHA256 against `release-manifest.json` / `SHA256SUMS`.
- PyPI exposes `codex-rescue==0.1.0a5` with matching wheel/sdist digests.
- `pip install codex-rescue==0.1.0a5` and `pipx install codex-rescue==0.1.0a5` succeed.
- npm exposes all four platform packages and the meta package at exactly `0.1.0-alpha.5`.
- `npx codex-rescue@0.1.0-alpha.5 --version` and `--help` succeed on supported platforms without Python installed where practical.
- `npm install -g codex-rescue@0.1.0-alpha.5` succeeds on supported platforms.
- Public npm tarballs contain only their audited allowlisted files.
- Public Alpha5 verification spans GitHub, PyPI, and npm.

## Rollback / stop conditions

Stop immediately if any of these is true:

- PR #7 head differs from the SHA whose required CI is green at merge time.
- Any required exact-head CI is no longer green.
- `main` changes in a way that changes the intended release source before tagging and the new source has not been requalified.
- PyPI `0.1.0a5` unexpectedly already exists before explicit publication.
- Any npm package name is no longer available/owned by the authenticated release identity.
- `npm whoami` fails or does not match the expected publisher identity.
- Any npm `0.1.0-alpha.5` unexpectedly already exists with different/unverified content.
- Candidate artifact set is incomplete or contains unexpected files.
- Any candidate/GitHub-release artifact SHA256 differs from the manifest.
- `v0.1.0-alpha.5` exists before the authorized tag step, or resolves to the wrong SHA.
- GitHub prerelease target/tag/source SHA is not exact.
- Trusted Publishing/OIDC or npm publication authentication is unavailable or weaker than expected.
- Any publish workflow gate is skipped, disabled, or manually bypassed.

## Do not touch

- Alpha4 tag `v0.1.0-alpha.4`.
- Existing Alpha4 GitHub release.
- Existing Alpha4 PyPI publication (`0.1.0a4`).
- Released history.

Never force-push `main`, move released tags, overwrite published package versions, or publish the npm meta package before all platform packages have passed public verification.
