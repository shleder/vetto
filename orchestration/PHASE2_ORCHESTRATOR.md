# VETTO PHASE 2 — ORCHESTRATOR FILE (verify repo/branch before work)

Repo: /home/shleder/prod/vetto
Branch: feat/phase1-contract-authority
Baseline: 3ba5482

## ROLE

You are the Phase 2 orchestrator. You do NOT implement Phase 2 yourself.
You spawn subagents (agy CLI, gemini-3.8-flash-high, --effort high), verify their work, integrate, run one final report.

## SUBAGENT SPAWN COMMAND TEMPLATE

cd /home/shleder/prod/vetto && agy --model gemini-3.8-flash-high --effort high --print "PROMPT_FROM_RUNBOOK"

Subagent prompts live in: /home/shleder/prod/vetto/orchestration/SUBAGENT_RUNBOOK.md
Each subagent has full read access to /home/shleder/prod/vetto.
Write scope is granted per subagent in the runbook; all others are read-only.

## GLOBAL RULES (ALL SUBAGENTS)

1. Repo: /home/shleder/prod/vetto only.
2. Branch: feat/phase1-contract-authority. Baseline commit: 3ba5482.
3. No local cargo build/test/check (AGENTS.md rule). GitHub CI is the only proof.
4. No new architecture, no Phase 3/4 scope.
5. No sandbox escape payloads; defensive verification only.
6. No commit/push unless task says so; orchestrator integrates.
7. Every subagent report: facts (file:line) separate from assumptions.

## ORCHESTRATION PHASES

PHASE A — RECON (parallel, read-only):
  A1: verify battery recon (src/verify.rs, src/verify_ng, src/redteam.rs, existing tests)
  A2: contract identity recon (src/policy_ir, src/sandbox/production*, FSM, sealed contract flow)
  A3: entrypoint recon (CLI/MCP/multi), audit, report, CI jobs

PHASE B — INTEGRATION POINT (orchestrator):
  - Consolidate recon into single execution-path map.
  - Confirm no duplicate checks already exist for each battery class.

PHASE C — IMPLEMENTATION (one at a time, sequential):
  C1: filesystem battery + secrets battery
  C2: environment isolation battery
  C3: process containment battery
  C4: network battery
  C5: contract tampering battery + identity binding regressions
  C6: evidence model + empty/incomplete suite gates
  C7: entrypoint unification (CLI/MCP/multi)

PHASE D — INTEGRATION AND CI (orchestrator):
  - Apply fmt/clippy-clean style.
  - Commit on same branch, push, monitor GitHub CI for exact SHA.
  - No release train, no version bump beyond +0.0.1 policy (major stays 0).

PHASE E — FINAL REPORT (orchestrator):
  - Emit report per section 22 of master task (below).

## MASTER TASK (verbatim, authoritative spec for Phase 2)

# (master task text is intentionally kept out of this file; orchestrator
# receives the full task text directly in its kickoff prompt, and every
# subagent receives only the battery section relevant to it, verbatim from
# the master task. This keeps the file small and each subagent focused.)

## FINAL REPORT FORMAT (section 22 of master task)

PHASE 2 RESULT
Baseline: <commit>
Final: <commit>
Files changed: <list>
Architecture: <what changed>
Verification: <what is now independently proven>
Tests: <exact commands>
CI: <run ID + exact commit SHA + result>
Threat coverage: filesystem / environment / process / network / secrets / contract tampering / evidence
Known limitations: <exact limitations>
Deferred to Phase 3: <items>
Deferred to platform hardening: <items>

For every claimed PASS provide concrete evidence. If not proven, write NOT PROVEN, not PASS.

## FINAL RULE

Do not optimize for file count or test count. Optimize for one question:
can we independently prove that production execution actually honors the
SecurityContract that Vetto sealed before spawn?
If any security-relevant class is not proven, leave it explicitly uncovered
or fail-closed. Do not move to Phase 3 until Phase 2 has a verifiable
evidence trail.

## FILE MAP (access: /home/shleder/prod/vetto/orchestration/)

- PHASE2_MASTER_TASK.md  — full Phase 2 spec, verbatim. Source of truth. Feed exact battery sections (verbatim) to each implementation subagent alongside recon results.
- SUBAGENT_RUNBOOK.md    — per-subagent prompts (A1-A3 recon, C1-C7 implementation, D final review) + universal constraints to append to every spawn.
- PHASE2_ORCHESTRATOR.md — this file: your role, spawn template, phase order.

## MINI-PROMPT (kickoff for you, orchestrator)

Ты оркестратор Phase 2 в /home/shleder/prod/vetto (ветка feat/phase1-contract-authority, baseline 3ba5482). Читай /home/shleder/prod/vetto/orchestration/PHASE2_ORCHESTRATOR.md, /home/shleder/prod/vetto/orchestration/SUBAGENT_RUNBOOK.md, /home/shleder/prod/vetto/orchestration/PHASE2_MASTER_TASK.md. У тебя полный доступ к этой папке и репозиторию. Выполни фазы: A (параллельный recon A1-A3), B (сводная карта пути + список существующих проверок), C (последовательные C1-C7, каждому сабагенту — вербатим-секция мастер-таска + результаты recon), D (commit на ту же ветку, push, GitHub CI на exact SHA; локальные cargo-запуски запрещены), E (финальный отчёт по формату раздела 22 мастер-таска). Каждому сабагенту добавляй универсальные ограничения из ранбука. Слабых мест не оставляй: незакрытый класс — NOT PROVEN или fail-closed, не PASS.
