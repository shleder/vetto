# vetto roadmap

This document tracks work after the repository-wide implementation described
in the current specification. It is not a compatibility promise; supported
capabilities are determined by `vetto doctor`, platform documentation and the
test matrix for the exact revision being used.

## Completed in 0.2.25 (Hardening & Stabilization Gate — Issues #26, #62, #63)

- [x] boundary verification battery (`vetto verify`, `--verify` preflight that refuses to start an agent on any leak);
- [x] `--timeout` session watchdog with guaranteed tree teardown (subreaper sweep for fs-only setsid grandchildren, macOS `pdeath_watch`);
- [x] `--limits` resource ceilings with Linux/Windows/macOS parity;
- [x] `vetto policy explain` / `vetto policy lint` (BLAKE3 canonical digests and validation);
- [x] Windows: deny-path overlap analysis (`analyze_deny_overlap`) instead of blanket refusal, Job Object memory/process limits, first enforcement integration tests;
- [x] black-box e2e spawn benchmark with CI perf regression gate;
- [x] llvm-cov coverage threshold pinned (`--fail-under=39%`);
- [x] **Issue #26 Resolution (Platform Parity & Scope Honesty)**: Formalized the 3-tier platform contract across documentation, doctor probes, and CI matrices:
  - Tier 1 (Linux): Production-grade Landlock ABI v1–v6 + complete namespace isolation (Mount, User, PID, NET) and tmpfs secret masking.
  - Tier 2 (macOS): Experimental Seatbelt SBPL containment; continuous tracking of Apple dyld read-allowlist regressions.
  - Tier 3 (Windows): Experimental AppContainer/Job Object process sandboxing; promote WSL2 as the production pathway on Windows hosts.
- [x] **Issue #62 Resolution (macOS dyld read-allowlist)**: Shape A + trailing denies documented and verified as maximum-achievable on Darwin;
- [x] **Issue #63 Resolution (Windows hardening)**: AppContainer LPAC + Job Object kill-on-close verified, WFP admin opt-in fail-closed boundary enforced;
- [x] fail-closed Linux, macOS and Windows capability probes covered by negative integration tests;
- [x] CI build matrices across x86-64/ARM64 Linux, macOS Intel/Apple Silicon, and Windows with warnings denied.

## Stabilization gate (Continuous)

- replace any unmeasured performance statement with reproducible benchmark output and record the machine/kernel/toolchain used;
- independently review policy merging, report path handling, DNS validation and every platform-specific unsafe block.

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
