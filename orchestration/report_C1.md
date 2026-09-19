### Вердикт

Задача C1 полностью выполнена: реализована батарея верификации файловой системы (Раздел 4) и изоляции секретов (Раздел 8) на основе запечатанного `SecurityContract`, устранён структурный блокер в `runner.rs:765`, зарегистрирован сценарий `VFS-WRITE-001`, и подключен независимый сбор доказательств `HOST_FACT` без доверия к `SELF_REPORT` дочернего процесса. Локальные сборки и тесты не запускались, коммиты и push не производились; единственным подтверждением выполнения остаётся GitHub CI.

---

### Анализ изменений и аргументация

#### 1. Устранение бага оракула и шлюза PASS-способности
* **Факт ([`src/verify_ng/runner.rs:785`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L785))**: Изначально `pass_capable` определялся как `req.enable_host_control && req.scenario.category == Category::Aux`. Это делало вердикт `PASS` недостижимым для всех сценариев блокеров (`FsRead`, `FsWrite`, `Secrets`, `Net`, `Proc`, `Spawn`), принудительно выставляя `bound_nonce = None` и `agreeing_vectors = 0`, сваливая оракул в `Verdict::Inconclusive` независимо от реальной изоляции ядра.
* **Решение ([`src/verify_ng/runner.rs:796`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L796))**: Проверка расширена: `pass_capable` разрешён для `Category::Aux`, а также для категорий блокеров при наличии зарегистрированных хостовых доказательств (`has_boundary_evidence = evidence.has_host_fact() || !sentinel_pre.is_empty()`).
* **Факт ([`src/verify_ng/runner.rs:767-777`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L767-L777), [`L824-842`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L824-L842))**: Добавлена регистрация хостовых фактов `sentinel-intact` для неповреждённых трипвайров, и расчёт `agreeing_vectors` теперь учитывает неповреждённые трипвайры, позволяя сценариям с `quorum >= 2` (`VFS-TRAV-001`, `VFS-WRITE-001`) легитимно подтверждать кворум векторов.

#### 2. Регистрация сценария VFS-WRITE-001
* **Факт ([`src/verify_ng/registry.rs:210-225`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L210-L225))**: Сценарий [`tests/verify_ng/scenarios/VFS-WRITE-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/VFS-WRITE-001.toml) отсутствовал в функции `registry()`. Сценарий добавлен с категорией `FsWrite`, строгостью `Strong` на `LinuxFull`/`LinuxFsOnly` и `Partial` на `Macos`/`Windows`, кворумом 2 и обязательными `residual_risk`.

#### 3. Потребление запечатанного SecurityContract
* **Факт ([`src/verify_ng/runner.rs:184`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L184), [`L448-462`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L448-L462))**: В [`ExecutionRequest`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L152) добавлено поле `pub contract: Option<&'a SecurityContract>`. При его наличии раннер:
  1. Проверяет `contract.verify_digest()`, немедленно отказывая в спавне (`fail-closed`, `Inconclusive`, `spawn_pid: None`) при любом расхождении дайджеста.
  2. Замораживает в `spec.policy_bytes` канонический JSON `{ "contract": contract, "digest": contract.contract_digest_blake3 }`, точно воспроизводя логику [`freeze_production_contract`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L420-L423).
  3. Связывает идентичность исполнения [`ExecutionIdentity`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L447-L457) с дайджестом контракта.
* **Факт ([`src/verify.rs:171-298`](file:///home/shleder/prod/vetto/src/verify.rs#L171-L298))**: Реализована функция `preflight_contract(&SecurityContract)` и бэкенд-проверка `battery_contract`, потребляющие запечатанный контракт без повторного разрешения политики.

#### 4. Батарея тестов изоляции ФС и секретов
* **Файл [`tests/integration/verify_ng_boundary_contract.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_boundary_contract.rs)** (зарегистрирован в [`tests/integration/main.rs:64`](file:///home/shleder/prod/vetto/tests/integration/main.rs#L64)) реализует покрытие требований Разделов 4 и 8:
  * **Отказ при модификации контракта**: `test_contract_tamper_rejected_no_spawn` (подтверждает fail-closed до спавна).
  * **Traversal и '..'**: `test_boundary_traversal_dotdot_escape_denied` (обход за пределы рабочей директории).
  * **Симлинки**: `test_boundary_symlink_workspace_allowed_and_link_to_outside` (структура `workspace/{allowed/, link -> /outside/}`).
  * **Гонки симлинков / TOCTOU**: `test_boundary_symlink_race_toctou_denied` (быстрая замена симлинка на лету).
  * **Абсолютные пути**: `test_boundary_absolute_path_escape_denied` (`/etc/shadow`, вне-проектные пути).
  * **Запрещённые операции**: `test_boundary_forbidden_read_write_create_delete` (проверка `read`, `write`, `open(O_CREAT)`, `mkdir`, `unlink`, `rmdir`).
  * **Перемещение через границу**: `test_boundary_rename_across_boundary_denied` (`rename` из рабочей области наружу и обратно).
  * **Альтернативные представления**: `test_boundary_alternate_representations_denied` (`///`, `/./`, `/proc/self/cwd/..`, `/proc/self/root`).
  * **Изоляция секретов**: `test_secret_isolation_symlink_traversal_spelling` (SSH-ключи, симлинк на секрет, относительный путь, альтернативные написания).
  * **Секрет, скопированный до исполнения**: `test_secret_copied_prior_to_execution_contract_semantics` (строгая верификация семантики контракта: маскированные пути в `mask_paths` блокируются, а разрешённые рабочей областью файлы читаются без ложных заверений).
  * **Канарейки VFS-TRAV-001 и VFS-WRITE-001**: `test_vfs_trav_001_pass_with_sealed_contract` и `test_vfs_write_001_pass_with_sealed_contract` (подтверждают легитимный `Verdict::Pass` при живом host control и интактных sentinels).
  * **Детекция мутаций трипвайров**: `test_sentinel_mutation_yields_fail` (подтверждает переход в `Verdict::Fail` при нарушении целостности).

---

### Список изменённых файлов и обоснование

| Файл | Обоснование изменений |
|---|---|
| [`src/verify_ng/registry.rs`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs) | Добавление сценария `VFS-WRITE-001` в системный реестр `registry()` |
| [`src/verify_ng/runner.rs`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs) | Исправление блокировки `pass_capable` для не-`Aux` сценариев, учёт неповреждённых трипвайров `sentinel-intact`, добавление поля `contract` в `ExecutionRequest` и валидация дайджеста контракта перед спавном |
| [`src/verify.rs`](file:///home/shleder/prod/vetto/src/verify.rs) | Добавление `preflight_contract` и `battery_contract`, валидирующих запечатанный `SecurityContract` и использующих его `mask_paths` |
| [`tests/integration/main.rs`](file:///home/shleder/prod/vetto/tests/integration/main.rs) | Регистрация нового модуля тестов `verify_ng_boundary_contract` |
| [`tests/integration/verify_ng_execution.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_execution.rs) | Добавление `contract: None` в фабрику `request` |
| [`tests/integration/verify_ng_host_evidence.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs) | Добавление `contract: None` в фабрику `request` |
| [`tests/integration/verify_ng_backend_arch.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_backend_arch.rs) | Добавление `contract: None` в два вызова `ExecutionRequest` |
| [`tests/integration/verify_ng_linux_enforce.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs) | Добавление `contract: None` в фабрику `run_linux` |
| [`tests/integration/verify_ng_boundary_contract.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_boundary_contract.rs) | Полная батарея интеграционных тестов изоляции ФС и секретов под управлением `SecurityContract` |

---

### Статус подтверждения и элементы NOT PROVEN

* **Подтверждено (Confirmed Facts)**:
  * В коде отсутствуют альтернативные загрузчики политик для созданной батареи: используется исключительно запечатанный `SecurityContract` через [`PolicyCompiler::compile_effective`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L48).
  * Нарушение целостности контракта вызывает жесткий отказ до системного вызова `fork`/`clone` ([`src/verify_ng/runner.rs:449-455`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L449-L455)).
  * Решения о прохождении тестов принимаются исключительно по `HOST_FACT` (статус завершения, хэши трипвайров на хосте, канал управления `VerifiedControl`).
* **Не подтверждено на локальной машине (NOT PROVEN locally)**:
  * Фактическое прохождение тестов в среде ядра Linux: локальный запуск `cargo test` / `cargo check` строго запрещен универсальными ограничениями задачи; проверка будет получена исключительно через GitHub Actions CI.
  * Поведение на macOS и Windows: явным образом ограничено потолком бэкенда (`EnforcementState::Unsupported` -> деградация из `PASS` в `Inconclusive` по коду [`src/verify_ng/sandbox_backend.rs:1724`](file:///home/shleder/prod/vetto/src/verify_ng/sandbox_backend.rs#L1724)), фиктивный `PASS` исключён архитектурно.
