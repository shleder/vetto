Батарея тестов локализации и сдерживания процессов (Process Containment Battery) по разделу 6 мастер-плана полностью реализована на ветке `feat/phase1-contract-authority` без локальных билдов и коммитов. Канонический канареечный сценарий [`PROC-ESC-001`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L240-L256) и кворумный сценарий [`PROC-TREE-001`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L257-L274) покрывают полную матрицу векторов побега (`parent -> child -> grandchild`, `fork`/`spawn`, `daemonize` с double-fork и отрывом stdio, `setsid`, отрыв от родителя, побег из session/process group, выживание после дедлайна супервайзера). Документированная брешь Linux FS-ONLY для оторванных потомков (detached grandchildren) изолирована в контракте оракула: бекенд [`LinuxBackend`](file:///home/shleder/prod/vetto/src/verify_ng/sandbox_backend.rs#L798-L836) принудительно фиксирует возможность `ProcessTreeContainment` в состоянии `EnforcementState::Unsupported`, что исключает вердикт `PASS` и генерирует либо `INCONCLUSIVE` (при чистой зачистке без гарантий ядра), либо `FAIL` (при обнаружении выживших процессов) в строгом соответствии с контрактом вердиктов без вмешательства в скоуп Phase 3.

---

### Архитектурные механизмы и соблюдение контракта

1. **Изоляция бреши Linux FS-ONLY без расширения скоупа Phase 3**:
   - В тире `Tier::FsOnly` изолированные PID-неймспейсы ядра (`CLONE_NEWPID`) отключены. Отвязавшиеся через `setsid` потомки уходят из группы процесса. Зачистка хостовым `PR_SET_CHILD_SUBREAPER` опирается на сканирование `/proc` по сессионному nonce, что не является барьером уровня ядра и подвержено гонкам планировщика.
   - Метод [`LinuxBackend::apply_tier_restriction`](file:///home/shleder/prod/vetto/src/verify_ng/sandbox_backend.rs#L798-L806) при `tier == Some(Tier::FsOnly)` переводит [`SecurityCapability::ProcessTreeContainment`](file:///home/shleder/prod/vetto/src/verify_ng/sandbox_backend.rs#L826-L835) в `EnforcementState::Unsupported` с признаком `UnsupportedOnPlatform`.
   - Метод [`LinuxBackend::note_tree_clean`](file:///home/shleder/prod/vetto/src/verify_ng/sandbox_backend.rs#L956-L960) игнорирует сообщения о чистой зачистке для `Tier::FsOnly` и не повышает статус возможности до `Verified`.
   - Оракул [`oracle::apply_backend_ceiling`](file:///home/shleder/prod/vetto/src/verify_ng/oracle.rs#L62-L86) блокирует `PASS` для категории `Category::Proc` при неподдерживаемой возможности и выставляет потолок `ClaimStrength::None`, приводя вердикт к `Verdict::Inconclusive`. Если же обнаружен остаточный процесс — фиксируется `Verdict::Fail`. Scope Phase 3 (cgroups v2 / strict PID namespace) не затронут.

2. **Исключительно независимые свидетельства (`HOST_FACT`)**:
   - Вся доказательная база формируется хостом во [`finish_run`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L770-L863). Дочерний `SELF_REPORT` игнорируется.
   - Задействованы строго независимые факты:
     - `tree-sweep`: результат зачистки субрепером хоста (`clean=true,killed=N`).
     - `tree-intact`: подтверждение отсутствия остаточных PID в системе (`no-residual-processes`), выступающее независимым вектором для выполнения кворума.
     - `tree-escape`: список выживших PID при обнаружении утечки с немедленным выставлением `violation_observed = true`.
     - `tree-blind`: фиксация невозможности сканирования окружения субрепером.
   - В [`src/redteam.rs`](file:///home/shleder/prod/vetto/src/redteam.rs#L85-L139) устранен ложный `Pass`: `test_setsid_escape()` сопоставляет `/proc/self/ns/pid` и `/proc/1/ns/pid`. Если ни `subreaper`, ни отдельный PID-неймспейс не активны, возвращается честный `RedteamStatus::Fail`.

3. **Соблюдение жизненного цикла и теоремы вымирания (§12.1)**:
   - При удержании открытых дескрипторов (stdout/stderr) фоновым потомком раннер [`run_one_with_backend`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L735-L760) не блокируется: вычитка каналов ограничена дедлайном `drain_budget`, после чего следует `SIGKILL` по группе и sweep по nonce.
   - При нарушении жизненного цикла (наличие выживших процессов) [`ExtinctionVerifier`](file:///home/shleder/prod/vetto/src/proctree.rs) генерирует отказ с кодом 125 (`Lifecycle breach`). Превышение жесткого лимита зачистки в 500 мс (`MAX_EXTINCTION_DEADLINE_MS`) также завершается с кодом 125.
   - Любая попытка модификации ресурсов (`max_pids`) в запечатанном [`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs) отсекается до вызова `spawn` с отказом `invalid security contract digest`.

---

### Измененные и добавленные файлы

| Файл | Обоснование изменений |
| :--- | :--- |
| [`src/verify_ng/sandbox_backend.rs`](file:///home/shleder/prod/vetto/src/verify_ng/sandbox_backend.rs) | Реализован метод `apply_tier_restriction`. Для `Tier::FsOnly` возможность `ProcessTreeContainment` переводится в `EnforcementState::Unsupported`. В `note_tree_clean` установлен запрет перехода в `Verified` на тире `FsOnly`. |
| [`src/verify_ng/runner.rs`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs) | Добавлен сбор `tree_sweep_outcome`. Реализована генерация `HOST_FACT` для `tree-sweep`, `tree-intact`, `tree-escape`, `tree-blind`. Вектор `tree-intact` включен в расчет `agreeing_vectors` для кворума. |
| [`src/verify_ng/registry.rs`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs) | Зарегистрирован сценарий [`PROC-TREE-001`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L257-L274) (категория `Category::Proc`, строгость `Blocker`, кворум 2, векторы `spawn` и `tree-sweep`, сила `Strong` на `LinuxFull` / `Partial` на `LinuxFsOnly`). |
| [`src/redteam.rs`](file:///home/shleder/prod/vetto/src/redteam.rs) | Добавлена проверка `is_pid_namespace_active()` через чтение `/proc/self/ns/pid`. Исключен возврат ложного `Pass` при отсутствии `subreaper` и PID-неймспейса. |
| [`tests/integration/verify_ng_proc_contract.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_proc_contract.rs) | Полная батарея из 13 интеграционных тестов под запечатанным `SecurityContract`: canonical canary `PROC-ESC-001`, запрет `PASS` на `FsOnly`, `parent->child->grandchild`, `daemonize double-fork`, `setsid`, `continue-after-termination`, тайм-аут удержания дескрипторов, отсечение модифицированного контракта, сходимость зачистки по §12.1. |
| [`tests/integration/main.rs`](file:///home/shleder/prod/vetto/tests/integration/main.rs) | Зарегистрирован модуль `verify_ng_proc_contract` под директивой `#[cfg(target_os = "linux")]`. |

---

### НЕ ДОКАЗАНО (NOT PROVEN)

1. **Компиляция и прогон тестов на реальном ядре**: локальные команды `cargo build`, `cargo check` и `cargo test` не выполнялись согласно прямому запрету в задаче. Доказательство синтаксической и типовой корректности получено статическим анализом; фактическая валидация перенесена на GitHub CI.
2. **Поведение `PR_SET_CHILD_SUBREAPER` в условиях истощения PID или OOM**: не доказано, что ядро Linux успеет зафиксировать усыновление оторванного процесса до срабатывания OOM-killer или паники при полном исчерпании таблицы PID.
3. **Кросс-платформенное сдерживание на macOS и Windows**: тесты в [`verify_ng_proc_contract.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_proc_contract.rs) ограничены Linux (`#[cfg(target_os = "linux")]`). Механизмы Job Objects (Windows) и Launchd/watchdog (macOS) требуют валидации на целевых CI-раннерах.
4. **Устойчивость к гонкам планировщика при чтении `/proc`**: в условиях тяжелого троттлинга CPU процесс-сирота может завершиться и стать зомби до момента прочтения его `/proc/<pid>/environ` субрепером, что вызовет факт `tree-blind` вместо гарантированной идентификации.
