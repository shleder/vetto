# vetto GitHub Action

Fast, zero-daemon sandbox for AI coding agents in GitHub Actions. Downloads precompiled native binaries in ~1 second (with automatic source build fallback) and runs agent commands under kernel-level isolation with SARIF security reporting.

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v5
  - uses: shleder/vetto/action@main
    with:
      command: codex exec "review this PR"
      profile: strict
      net: off
      report: json,sarif
      fail-on-block: "0"
      upload-sarif: "true"
```

`command` is intentionally evaluated by `bash -lc`, matching the trusted
workflow author's shell command. Do not pass untrusted pull-request text as
the command itself.
