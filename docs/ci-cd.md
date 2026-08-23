# CI/CD integration

Run a non-interactive agent with machine-readable output:

```console
vetto --ci --tui=none --profile=strict --net=off \
  --report=json,sarif --report-dir=.vetto/reports \
  --fail-on-block -- agent command
```

`--ci` disables the statusline and prints the final JSON summary to standard
output. Diagnostics stay on standard error. `--fail-on-block` returns a
non-zero status when at least one blocked event was observed; an explicit
number changes the threshold, for example `--fail-on-block=5`.

Blocked-attempt visibility is best-effort on platforms where a readable audit
feed or seccomp user-notify is unavailable. The threshold applies to observed
events and must not be interpreted as proof that no denied syscall occurred.
The filesystem and network boundary remains enforced regardless of reporting.

## GitHub Actions

The repository contains a composite action under `action/`:

```yaml
- uses: shleder/vetto/action@main
  with:
    command: codex exec "review this PR"
    profile: strict
    net: off
    report: sarif
    fail-on-block: "true"
```

For a pinned production workflow, reference an immutable commit SHA. The
action builds the checked-out source, runs the requested command through
`vetto`, and can upload SARIF through GitHub's official CodeQL action. It does
not download an unverified binary or start a service.

## Report retention

Place reports in a dedicated directory that is outside the sandbox allowlist:

```console
vetto --report-dir="$RUNNER_TEMP/vetto-reports" --report=sarif,json -- agent command
```

Cleanup only considers files with vetto's generated report-name grammar in
that exact directory. Configure retention explicitly with the CLI retention
options. Report creation refuses symlink targets and existing destination
files.

## Other CI systems

The same CLI works in GitLab CI, Jenkins, CircleCI and Azure Pipelines. Preserve
the command exit code, collect `.vetto/reports` as an artifact, and feed SARIF
to the platform's supported scanner importer. Do not parse the human-readable
doctor output as a stable API; use JSON reports for automation.
