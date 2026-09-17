# SecurityContract authority: Phase 1

Status: approved by the user; implementation in progress.
Baseline CI: run 35226327619, all eight jobs passed on 2026-09-17.
Baseline: f543f26df87ae397a31ad9ae53cbda17fd29af7e, inspected 2026-09-17.
Scope: the requested Phase 1 only; no version bump, release, or new pipeline.

## Observed current boundaries

- CLI `supervise` resolves the executable, detects capabilities, loads/merges
  policy, and applies executable protection and environment preparation.
- CLI, MCP, and multi runtime construct `UnpreparedProductionExecution`.
- Preparation builds an environment from `Policy`, calls `freeze_production`,
  derives `CanonicalPolicy` from `FrozenSpec`, and prepares the capability backend.
- `PreparedProductionExecution` retains `Policy`; spawn passes it to mechanics.
  Linux mechanics reads its filesystem, environment, resource and syscall rules.
- CLI, MCP and multi supervisors separately derive relay broker rules.
- `PolicyCompiler::compile` currently builds contracts outside this production
  route. Its own defaults and workspace-write restriction are not a faithful
  representation of every effective production policy.
- Production audit currently supplies `identity.frozen_hash` where audit records
  expect a contract digest. Contract signing configuration is outside the hashed
  unsealed payload. Both boundaries need explicit binding, not renamed fields.

These are static observations, not a reproduced exploit or a failing test result.

## Implementation sequence

1. Run the existing suite remotely as a baseline. Add a production-boundary
   regression asserting that preparation exposes a verified sealed contract
   whose fields match non-default effective inputs. Verify a failing baseline
   in CI before modifying production behavior; distinguish compile-time API
   absence from a runtime assertion failure.
2. Introduce explicit resolved compiler input and route production through
   `PolicyCompiler::compile`. Adapt existing call sites without inventing new
   defaults. Legacy `Policy` remains the configuration input, not retained
   authority after compilation.
3. Extend canonical contract fields only where necessary to represent existing
   semantics. Preserve optional limits as optional, network variants losslessly,
   ordered rules where order matters, and platform-specific requirements.
4. Validate and seal before capability preparation. Retain that same contract
   across prepared/spawned execution; bind its digest into frozen identity.
   Keep security signing requirements in the sealed payload and detached
   signatures outside it to avoid self-referential hashing.
5. Lower from the contract into private backend installation data, with no
   caller-supplied Policy or overrides at that boundary. Preserve existing OS
   mechanics. Supervisor relay, credential and notification decisions must
   consume the same contract, not retained CLI/config copies.
6. Before any agent spawn, verify digest, frozen identity, lowering equality,
   and required backend capabilities. Fail closed on mismatch. Advance FSM
   states at the operations they represent, not retrospectively after spawn.
7. Bind evidence and audit to the actual contract digest while retaining
   independent host observations and the separate frozen-execution identity.
8. Run remote verification, then update only execution architecture docs.

## Required input mapping

| Effective inputs | Canonical destination |
| --- | --- |
| Resolved binary, arguments, preset, workspace, cwd, nonce | Identity and execution binding |
| Read/write roots, subtractive denies, resolved masks and directory kinds | Filesystem rules |
| Read-only mounts, tmpfs, devices, executable protection | Filesystem installation requirements |
| Off/allowlist/strict/ask, domains/rules, CIDRs, quotas, bind/connect ports, Unix sockets | Network and broker rules |
| Environment allow/deny, sanitized snapshot, explicit internal variables, secret proxy exclusions | Environment and credential rules |
| Optional rlimits, cgroups, CPU quota, I/O priority/rates, timeout, output limits | Resource and supervision requirements |
| Seccomp profile, notification policy, tier requirements, LPAC | Platform enforcement requirements |
| Git guard, secret scanning, immutable policy restrictions | Resolved preconditions and resulting restrictions |
| Audit/signing settings and required evidence level | Sealed attestation requirements |

Snapshot/report metadata stays non-authoritative. Enumerate remaining consumers
during implementation; any unmapped security input blocks completion. Missing
support must produce an explicit gap or fail-closed rejection, never substitution.

## Regression and verification gates

- Production preparation invokes compilation and preserves effective values.
- Mutation of each security-relevant sealed field invalidates the digest.
- Mutation of the caller's legacy input cannot affect prepared execution.
- Backend installation values equal canonical lowering of the frozen contract.
- Invalid/mismatched contracts leave the spawn ledger unchanged; a benign
  marker-file child never starts. No public tamper switch or bypass is added.
- Existing policy semantics, network-off, environment default-deny, masking,
  capability honesty, process-tree containment and independent evidence survive.
- Verify CLI, MCP and multi routes; unsupported capabilities must not silently
  downgrade. Platform skips are reported as skips, not enforcement passes.

Run only on external runners: `cargo fmt --check`, `cargo check`, `cargo test`,
`cargo clippy --all-targets --all-features -- -D warnings`, and the existing
policy IR, production, verify-ng, Phase 4 and Linux integration suites.
Use the existing CI workflow, adding only missing explicit verification steps.
Do not invoke the release train. Report exact commit/run IDs and failures.

## Completion condition

No substantial security decision may read a competing legacy/CLI source after
compilation. All six requested regression categories and existing suites must
pass remotely. A green baseline without the new assertions is not Phase 1 proof.
Until these gates pass, report Phase 1 as incomplete.
