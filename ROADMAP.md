# vetto roadmap

This document tracks work after the repository-wide implementation described
in the current specification. It is not a compatibility promise; supported
capabilities are determined by `vetto doctor`, platform documentation and the
test matrix for the exact revision being used.

## Stabilization gate

- keep the fail-closed Linux, macOS and Windows capability probes covered by
  negative integration tests;
- run the x86-64/ARM64 Linux, macOS Intel/Apple Silicon and Windows build
  matrix with warnings denied;
- validate report schemas, shell completions, editor plugins and source-only
  package recipes without publishing artifacts;
- replace any unmeasured performance statement with reproducible benchmark
  output and record the machine/kernel/toolchain used;
- independently review policy merging, report path handling, DNS validation
  and every platform-specific unsafe block.

## Ongoing security work

- track Landlock ABI changes and kernel audit visibility without making the
  audit feed a prerequisite for enforcement;
- re-evaluate the seccomp syscall set when kernel behaviour or legitimate
  build workloads change;
- test Seatbelt behaviour on each supported macOS release and keep Endpoint
  Security entitlement detection explicit;
- treat the experimental Windows process-sandbox API as unstable and refuse
  fallback whenever an equivalent filesystem/network boundary cannot be
  proved;
- expand malicious descendant, DNS rebinding, symlink/race and lifecycle
  fixtures as new bypass techniques are disclosed.

## Ecosystem maintenance

- keep agent presets conservative and version reports evidence-based;
- test IDE integrations against supported editor release lines;
- update package-manager templates only from verified build artifacts and
  checksums;
- publish releases only through a separately approved, reproducible release
  process. Repository changes alone never imply publication.
