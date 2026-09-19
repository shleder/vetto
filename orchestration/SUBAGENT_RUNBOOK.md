# PHASE 2 SUBAGENT RUNBOOK — copy prompts verbatim into agy
# Spawn template:
# cd /home/shleder/prod/vetto && agy --model gemini-3.8-flash-high --effort high --print "PROMPT"
# Repo access: /home/shleder/prod/vetto (full read; write only where stated).

## A1 — VERIFICATION BATTERY RECON (read-only)

You are a read-only recon agent for Phase 2 Boundary Verification in /home/shleder/prod/vetto (branch feat/phase1-contract-authority, baseline 3ba5482). Map the actual verification execution path: src/verify.rs, src/verify_ng/ (engine, evidence, oracle, host_evidence, frozen, caps, linux_enforce, windows_enforce), src/redteam.rs, and existing tests (tests/verify_ng, tests/integration/linux_verify.rs, linux_redteam.rs, adv_isolation.rs). Do not trust names or docs; trace the real execution path. List all existing checks by stable identifier and file:line so later batteries do not duplicate them. Map: verify command -> verification orchestration -> production execution -> sealed SecurityContract -> backend lowering -> actual OS enforcement -> attacker action -> evidence collection -> verdict. Identify evidence trust levels (HOST_FACT / CONSTRAINED / SELF_REPORT) and where empty/incomplete suites are gated. No edits, no local build/test runs, no sandbox escape payload development, no commit/push. Facts with file:line, assumptions clearly labeled.

## A2 — CONTRACT IDENTITY RECON (read-only)

You are a read-only recon agent for Phase 2 Boundary Verification in /home/shleder/prod/vetto (branch feat/phase1-contract-authority, baseline 3ba5482). Trace the sealed SecurityContract path: src/policy_ir (compiler.rs, contract.rs, fsm.rs, sync.rs), production execution boundary in src/sandbox (production*, lowering), execution FSM, contract digest/frozen identity handling, and Phase 1 regression tests (sandbox::production::production_unit_tests::phase1_, policy_ir::contract::contract_tests, phase4_enterprise_runtime.rs, crypto::slsa). Establish where execution identity (execution_id, contract_digest, frozen_hash, nonce/provenance) is created and where it is bound to evidence. Identify existing tamper-rejection and no-spawn-on-invalid checks with file:line so Phase 2 batteries extend, not duplicate. No edits, no local build/test runs, no sandbox escape payload development, no commit/push. Facts with file:line, assumptions clearly labeled.

## A3 — ENTRYPOINT RECON (read-only)

You are a read-only recon agent for Phase 2 Boundary Verification in /home/shleder/prod/vetto (branch feat/phase1-contract-authority, baseline 3ba5482). Map entrypoints to production boundary: src/cli, src/mcp, src/multi, src/daemon if relevant, plus src/audit and src/report. Verify each entrypoint uses the same sealed-contract authority path; flag any branch bypassing it (Phase 2 must fix, not tolerate). Also inspect .github/workflows/ci.yml to list which jobs already run verification/red-team/production suites, and check ARCHITECTURE.md and ROADMAP.md only to confirm code facts. List existing checks with file:line. No edits, no local build/test runs, no sandbox escape payload development, no commit/push. Facts with file:line, assumptions clearly labeled.

## C1 — FILESYSTEM + SECRETS BATTERY (write scope)

Working in /home/shleder/prod/vetto (branch feat/phase1-contract-authority). You receive recon results from A1/A2 (pasted by orchestrator) plus the verbatim filesystem (section 4.1) and secret isolation (section 8) battery requirements from the master task. Consume the SAME sealed SecurityContract used by production execution; never rebuild policy. Extend VFS-TRAV-001 only where needed; do not duplicate existing checks listed by recon. Cover: traversal, '..', symlink escape, absolute path escape, outside-workspace paths, protected secret paths, forbidden read/write/create/delete, rename across boundary, alternate filesystem representations, symlink-to-secret, relative traversal to secret, alternate path spelling. Linux is the primary target; macOS/Windows only where backend claims the capability, otherwise explicit unsupported/skip, never fake PASS. Independent runtime evidence only; backend self-report is not proof. Write code + tests; run no local builds/tests; do not commit/push. Report changed files with rationale and any NOT PROVEN items.

## C2 — ENVIRONMENT ISOLATION BATTERY (write scope)

Working in /home/shleder/prod/vetto (branch feat/phase1-contract-authority). With recon results and master-task section 5 (verbatim, pasted by orchestrator), implement environment isolation battery consuming the SAME sealed contract: arbitrary host variable, sensitive-looking variable, PATH manipulation, inherited environment, internal Vetto variables, explicitly denied variables, post-start mutation. Verifier must distinguish 'allowed by contract' from 'present because host leaked'; no blanket prefix assumptions unless contract semantics define them. Extend ENV-LEAK-001 rather than duplicating. Independent runtime evidence only. Write code + tests; no local builds/tests; no commit/push. Report changed files with rationale and NOT PROVEN items.

## C3 — PROCESS CONTAINMENT BATTERY (write scope)

Working in /home/shleder/prod/vetto (branch feat/phase1-contract-authority). With recon results and master-task section 6 (verbatim), implement process containment battery using PROC-ESC-001 as canonical canary where it already covers the class. Cover parent->child->grandchild, fork, spawn, daemonize, setsid, detach, survive-parent-exit, session/group escape, continue-after-termination. Known documented Linux FS-ONLY detached-grandchild gap: do NOT declare PASS; emit FAIL/INCONCLUSIVE with exact reason per existing verdict contract. Do not fix Phase 3 scope here. Independent runtime evidence only. Write code + tests; no local builds/tests; no commit/push. Report changed files with rationale and NOT PROVEN items.

## C4 — NETWORK BATTERY (write scope)

Working in /home/shleder/prod/vetto (branch feat/phase1-contract-authority). With recon results and master-task section 7 (verbatim), implement network battery against existing relay/broker/security contract semantics; no separate network security model. net=off: TCP, UDP, IPv4, IPv6, DNS, relevant alternate socket families. allowlist/strict where backend supports: allowed succeeds, denied fails, DNS rebinding, direct socket bypass, alternate address family, hostname-to-IP mismatch, relay bypass attempts. Unsupported capability on any platform: fail closed / explicit unsupported, never verifier-assumed success. Independent runtime evidence only. Write code + tests; no local builds/tests; no commit/push. Report changed files with rationale and NOT PROVEN items.

## C5 — CONTRACT TAMPERING + IDENTITY BINDING (write scope)

Working in /home/shleder/prod/vetto (branch feat/phase1-contract-authority). With recon results and master-task sections 3 and 10 (verbatim), implement contract tampering battery: after sealing, mutate each security-relevant field class (filesystem, environment, network, limits, executable restrictions, secret masks, tier/backend requirements) and prove digest/identity mismatch leads to verification failure and NO SPAWN. Check not only verifier exit code but spawn ledger / observable child marker (child must not run). Add the cross-execution regression: contract A + execution A + evidence A; contract B + execution B + evidence B; evidence A must never satisfy verification for B (other execution, stale run, other contract, other nonce, other backend). Write code + tests; no local builds/tests; no commit/push. Report changed files with rationale and NOT PROVEN items.

## C6 — EVIDENCE MODEL + EMPTY SUITE GATES (write scope)

Working in /home/shleder/prod/vetto (branch feat/phase1-contract-authority). With recon results and master-task sections 12 and 13 (verbatim), verify and strengthen the existing evidence model without changing semantics unnecessarily: HOST_FACT > CONSTRAINED > SELF_REPORT per verify-ng contract; agent self-report, stdout, arbitrary JSON from sandboxed process, snapshots without provenance, observations without execution identity must never count as proof. Prove provenance, execution identity, contract digest, nonce, evidence integrity and independence. Enforce: empty verification suite cannot PASS; missing required blocker category is not success; preserve existing 'zero inconclusive I1-I6' gate and do not weaken any gate. Add regression tests. Write code + tests; no local builds/tests; no commit/push. Report changed files with rationale and NOT PROVEN items.

## C7 — ENTRYPOINT UNIFICATION (write scope)

Working in /home/shleder/prod/vetto (branch feat/phase1-contract-authority). With recon results and master-task section 14 (verbatim), verify CLI, MCP and multi-agent entrypoints all run verification through the same sealed-contract production boundary. If any branch bypasses sealed contract authority, fix it within existing architecture (no new security layer, no second policy engine, no verifier overrides). Add regressions proving parity across entrypoints. Write code + tests; no local builds/tests; no commit/push. Report changed files with rationale and NOT PROVEN items.

## D — FINAL REVIEW (read-only, after integration)

You are a read-only final reviewer for Phase 2 in /home/shleder/prod/vetto. Given the final diff (pasted by orchestrator) and recon results: verify acceptance criteria (architecture, runtime verification batteries, fail-closed semantics, entrypoints, evidence, regression safety), verify failure-semantics matrix from master-task section 18 is honored, verify no Phase 3/4 scope creep, no weakened gates, no deleted tests, no version bump beyond +0.0.1. List any claim that lacks evidence as NOT PROVEN with exact file:line. No edits, no local builds/tests, no commit/push.

## SUBAGENT UNIVERSAL CONSTRAINTS (append to every prompt before spawn)

- Repo access: /home/shleder/prod/vetto only. Branch feat/phase1-contract-authority.
- No local cargo build/test/check/run; GitHub CI is the only execution proof.
- No sandbox escape payload development or bypass techniques; defensive verification batteries only.
- No new architecture, no second policy engine, no Phase 3/4 scope, no version bump, no release actions.
- No commit, no push, no secrets access, no external network calls beyond your model service.
- Separate confirmed facts (file:line) from assumptions in every report.
