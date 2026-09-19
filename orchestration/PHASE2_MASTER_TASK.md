# VETTO PHASE 2 — BOUNDARY VERIFICATION (MASTER TASK, verbatim)

Repo: shleder/vetto. Branch: feat/phase1-contract-authority. Baseline: 3ba5482.

## Цель

Реализовать Phase 2: Boundary Verification после завершённой Phase 1 — SecurityContract Authority.
Phase 1 установила: Policy → compiler → validated/sealed SecurityContract → frozen execution identity → backend lowering → production spawn.
Phase 2 доказывает: реальный production execution не может стартовать или продолжать работу, если фактическая boundary enforcement не соответствует sealed SecurityContract.
Не создавать новую архитектуру безопасности, не начинать Phase 3/4/5.

## 0. RECON ПЕРЕД КОДОМ

Изучить: src/verify_ng/**, src/verify.rs, src/redteam.rs, src/sandbox/**, src/policy_ir/**, src/audit/**, src/report/**, production execution boundary, integration/e2e tests, vetto verify, canaries VFS-TRAV-001 / ENV-LEAK-001 / PROC-ESC-001, lifecycle/FSM, contract digest/frozen identity, Phase 1 regression tests, CI jobs verification/red-team. ARCHITECTURE.md, ROADMAP.md, issues #26 #62 #63 #74. Не доверять названиям и докам — фактический execution path. После recon — карта: verify command → verification orchestration → production execution → sealed SecurityContract → backend lowering → actual OS enforcement → attacker action → evidence collection → verdict. Отдельно — список существующих проверок (без дубликатов).

## 1. ИНВАРИАНТ

PASS только если: contract validated/sealed; execution identity привязан к contract digest; production boundary использовала этот contract; probe реально выполнен внутри/против boundary; результат независимым механизмом; evidence соответствует конкретному execution; verdict не только на self-report.
FAIL если: enforcement отсутствует/отличается; поле потеряно; probe пересёк boundary; проверка невозможна там, где обязательна; evidence от другого execution; digest/identity не совпадают; backend silently downgraded; PASS на self-report.
INCONCLUSIVE только когда действительно необходимо. "не удалось проверить" ≠ PASS; unsupported ≠ PASS.

## 2. НЕ СОЗДАВАЙ ВТОРОЙ POLICY ENGINE

Phase 2 НЕ: заново вычислять policy; повторно разрешать precedence; создавать альтернативный SecurityContract; сравнивать execution с caller Policy; принимать overrides от verifier; обходить production boundary. Verifier потребляет тот же sealed contract, что и production execution. Архитектура: Policy → PolicyCompiler → SecurityContract → seal → ProductionExecution → Verifier. НЕ Policy → {ProductionExecution, Verifier}.

## 3. CONTRACT IDENTITY

Связь ExecutionIdentity {execution_id, contract_digest, frozen_hash, nonce/provenance} с evidence. Verifier не принимает evidence от другого execution, старого run, другого contract, другого nonce, другого backend. Regression test: contract A/execution A/evidence A; contract B/execution B/evidence B; evidence A никогда не удовлетворяет verification для B.

## 4. VERIFICATION BATTERY — FILESYSTEM

Traversal; '..'; symlink escape; absolute path escape; paths outside workspace; protected secret paths; forbidden read/write/create/delete; rename/move across boundary; alternate filesystem representations. Обязательно сценарий workspace/{allowed/, link -> /outside/} и symlink/race варианты, где backend поддерживает проверку. VFS-TRAV-001 не дублировать — расширять при необходимости.

## 5. ENVIRONMENT ISOLATION

Запрещённые host environment values не должны попадать в execution. Минимум: arbitrary host variable; sensitive-looking variable; PATH manipulation; inherited environment; internal Vetto variables; variables explicitly denied by contract; environment mutation после старта. Verifier различает "allowed by contract" и "present because host environment leaked". Никаких blanket assumptions ("starts with X => safe") вне contract semantics.

## 6. PROCESS CONTAINMENT

parent → child → grandchild; fork; spawn; daemonize; setsid; detach; survive parent exit; escape process group/session; continue after supervised execution terminates. PROC-ESC-001 — canonical canary. Linux FS-ONLY: documented detached-grandchild gap — НЕ объявлять PASS; FAIL/INCONCLUSIVE с точной причиной по существующему verdict contract. Не исправлять Phase 3 внутри Phase 2.

## 7. NETWORK BOUNDARY

net=off: TCP; UDP; IPv4; IPv6; DNS; raw/alternate socket families (если relevant). allowlist/strict (если backend поддерживает): allowed succeeds; denied fails; DNS rebinding; direct socket bypass; alternate address family; hostname → resolved IP mismatch; relay bypass. Не создавать отдельный network security model — существующий relay/broker/security contract. Неподдерживаемая платформой capability → fail closed / explicit unsupported, не "verifier assumes it worked".

## 8. SECRET ISOLATION

Known secret path; symlink to secret; relative traversal to secret; alternate path spelling; secret copied into accessible location до execution (если в documented threat model); protected credentials locations. Не утверждать защиту от угроз вне архитектурных обещаний. Verifier проверяет ровно contract semantics.

## 9. EXECUTABLE / COMMAND RESTRICTIONS

Если SecurityContract/backend поддерживает executable protection: allowed executable; forbidden executable; PATH substitution; symlinked executable; alternate invocation path; interpreter indirection. Новых policy semantics ради теста не добавлять.

## 10. CONTRACT TAMPERING

После sealing: contract → digest → execution; попытаться изменить security-relevant field: filesystem; environment; network; limits; executable restrictions; secret masks; tier/backend requirements. Ожидание: tamper → digest/identity mismatch → verification failure → NO SPAWN. При invalid/mismatched contract marker child НЕ запускается. Проверять не только exit code, но spawn ledger / observable child marker.

## 11. BACKEND LOWERING EQUALITY

SecurityContract → canonical lowering → backend installation → runtime behaviour. Связь declared contract ↔ observed enforcement. "backend says Landlock installed" ≠ "filesystem attack failed". Runtime probe независим.

## 12. EVIDENCE MODEL

НЕ доказательство: agent self-report; stdout; произвольный JSON от sandboxed process; snapshot без provenance; observation без связи с execution identity. Приоритет HOST_FACT > CONSTRAINED > SELF_REPORT по verify-ng contract. Semantics не менять без необходимости. Проверить provenance; execution identity; contract digest; nonce; timestamp/ordering (если предусмотрено); evidence integrity; independence.

## 13. EMPTY / INCOMPLETE SUITE

Empty verification suite не даёт PASS. Missing required blocker category ≠ успех. Сохранить правило "zero inconclusive I1-I6" как часть gate semantics. Gates не ослаблять.

## 14. CLI / MCP / MULTI

Verification через production boundary независимо от entrypoint: CLI; MCP; multi-agent. Ветка, обходящая sealed contract authority, исправляется в Phase 2. Отдельные security implementations не создавать.

## 15. PLATFORM BEHAVIOUR

Linux — главная цель: FULL; FS-ONLY; seccomp; Landlock; namespaces; network off; process containment. macOS — только реально заявленные capabilities; невозможное из-за Seatbelt/dyld → explicit skip / unsupported / documented limitation, не fake PASS. Windows — то же для experimental backend; #63 в Phase 2 не закрывать.

## 16. ЗАПРЕЩЕНО

Phase 3 timeout/watchdog redesign; resource limits; policy explain; policy lint; version 0.3.0; новая release; смена release/tag; новый security architecture layer; daemon; telemetry; cloud service; verifier authoritative вместо SecurityContract; silent downgrade unsupported platforms; удаление существующих tests ради CI; ослабление security gates; изменение public semantics без необходимости.

## 17. TEST STRATEGY

Уровни: unit → contract regression → production-boundary regression → black-box adversarial e2e. Не всё в unit tests. Black-box тесты, где attacker process не имеет доступа к verifier internals, обязательны.

## 18. FAILURE SEMANTICS

| Condition | Expected |
|---|---|
| valid contract + attack blocked | PASS |
| attack succeeds | FAIL |
| contract tampered | FAIL |
| identity mismatch | FAIL |
| missing required evidence | FAIL/INCONCLUSIVE по существующему gate |
| unsupported required capability | explicit unsupported / fail closed |
| empty suite | FAIL |
| stale evidence | FAIL |
| wrong execution evidence | FAIL |
| self-report only for blocker | not PASS |
| platform skip where legitimately unsupported | SKIP, not PASS |

Новых verdict states без необходимости не вводить.

## 19. CI

Запустить существующие project checks, насколько позволяет environment: cargo fmt --check; cargo check; cargo test; cargo clippy --all-targets --all-features -- -D warnings; verify-ng tests; production-boundary tests; red-team tests; integration tests. Release train не запускать. После push — дождаться GitHub CI, сверить commit SHA.

## 20. ДОКУМЕНТАЦИЯ

Обновить только необходимую документацию: что Phase 2 проверяет; threat classes; authoritative evidence; реально покрытые платформы; оставшиеся gaps; gaps, перенесённые в Phase 3/4/platform hardening. Не писать "fully secure".

## 21. ACCEPTANCE CRITERIA

Architecture: verifier использует sealed SecurityContract; verifier не второй policy engine; execution identity связан с contract digest; evidence связан с execution identity; production boundary authoritative.
Runtime verification: filesystem battery; environment leakage battery; process escape battery; network battery; secret isolation battery; executable restriction battery (если заявлена); contract tampering battery.
Fail-closed: invalid contract → no spawn; identity mismatch → no PASS; stale/wrong evidence → no PASS; missing mandatory verification → no PASS; empty suite → FAIL; unsupported security capability → no silent downgrade.
Entry points: CLI; MCP; multi-agent.
Evidence: independent runtime evidence; correct provenance; correct contract digest; correct execution identity; self-report не удовлетворяет mandatory blocker.
Regression safety: existing tests preserved; existing verification gates preserved; no weakening; no Phase 3/4 scope creep.

## 22. FINAL REPORT FORMAT

PHASE 2 RESULT: Baseline commit; Final commit; Files changed; Architecture; Verification; Tests (exact commands); CI (run ID + exact SHA + result); Threat coverage (filesystem/environment/process/network/secrets/contract tampering/evidence); Known limitations; Deferred to Phase 3; Deferred to platform hardening. Для каждого PASS — конкретное evidence. Не доказано → NOT PROVEN, не PASS.

## FINAL RULE

Оптимизировать под один вопрос: можем ли мы независимо доказать, что production execution реально соблюдает SecurityContract, который Vetto запечатал перед spawn. Если для security-relevant класса ответа нет — класс явно непокрыт или fail-closed. Не переходить к Phase 3, пока Phase 2 не имеет проверяемого evidence trail.
