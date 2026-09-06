# vetto roadmap

This document tracks work after the repository-wide implementation described
in the current specification. It is not a compatibility promise; supported
capabilities are determined by `vetto doctor`, platform documentation and the
test matrix for the exact revision being used.

## In progress — hardening/v0.3 branch

- boundary verification battery (`vetto verify`, `--verify` preflight that
  refuses to start an agent on any leak);
- `--timeout` session watchdog with guaranteed tree teardown (subreaper sweep
  for fs-only setsid grandchildren, macOS parent-death watchdog already
  merged);
- `--limits` resource ceilings with Linux/Windows/macOS parity;
- `vetto policy explain` / `vetto policy lint`;
- Windows: deny-path overlap analysis instead of blanket refusal, Job Object
  memory/process limits, first enforcement integration tests;
- black-box e2e spawn benchmark with a CI perf job (baseline fills from CI,
  never from laptops);
- pin the llvm-cov `--fail-under` threshold from the first real coverage
  number, then treat regressions as build failures.

## Stabilization gate

- **Issue #26 Resolution (Platform Parity & Scope Honesty)**: Formalize the 3-tier platform contract across all documentation, doctor probes, and CI matrices. Reject any pull request claiming cross-platform parity without kernel-level enforcement proof:
  - Tier 1 (Linux): Production-grade Landlock ABI v1–v6 + complete namespace isolation (Mount, User, PID, NET) and tmpfs secret masking.
  - Tier 2 (macOS): Experimental Seatbelt SBPL containment; continuous tracking of Apple dyld read-allowlist regressions.
  - Tier 3 (Windows): Experimental AppContainer/Job Object process sandboxing; promote WSL2 as the production pathway on Windows hosts.
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

- **Tier 1 (Linux)**: Track Landlock ABI changes (ABI v1–v6) and kernel audit visibility without making the
  audit feed a prerequisite for enforcement; re-evaluate seccomp syscall filters when kernel behaviour or legitimate
  build workloads change; monitor user-notify notification races and unprivileged userns hardening.
- **Tier 2 (macOS)**: Test Seatbelt behaviour on each supported macOS release (13/14/15) and keep Endpoint
  Security entitlement detection explicit; optimize SBPL profile AST shape and track Apple dyld shared-cache regressions.
- **Tier 3 (Windows)**: Treat the experimental Windows process-sandbox API as unstable and refuse
  fallback whenever an equivalent filesystem/network boundary cannot be proved; enforce Job Object memory quotas,
  AppContainer DACL edge cases, and Windows Sandbox `.wsb` specification parity.
- Expand malicious descendant, DNS rebinding, symlink/race and lifecycle
  fixtures as new bypass techniques are disclosed.

## Ecosystem maintenance

- keep agent presets conservative and version reports evidence-based;
- test IDE integrations against supported editor release lines;
- update package-manager templates only from verified build artifacts and
  checksums;
- publish releases only through a separately approved, reproducible release
  process. Repository changes alone never imply publication.
