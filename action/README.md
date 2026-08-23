# vetto GitHub Action

The composite action builds the checked-out vetto source with `--locked` and
runs one command in CI. It does not download or publish a release and does not
start a persistent service.

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
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
