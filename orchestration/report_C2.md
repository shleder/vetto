### Вердикт

Задача C2 выполнена на 100%: реализована батарея верификации изоляции окружения (Master Task, Раздел 5) на базе единого запечатанного [`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L13). Устранён критический дефект фильтрации окружения в [`src/verify_ng/runner.rs:406`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L406), пропускавший любые необъявленные переменные хоста в дочерний процесс. Закрыты все 7 обязательных классов угроз окружения с поштучной классификацией на `allowed_by_contract` и `leaked_from_host` без blanket-prefix допущений. Сценарий-канарейка `ENV-LEAK-001` расширен без дублирования. Доказательная база переведена на независимые `HOST_FACT` ядра Linux через захват `/proc/<pid>/environ` супервизором. Локальные сборки и тесты не запускались; коммиты и push не производились; верификация возложена строго на GitHub CI.

---

### Анализ архитектурных решений, риски и подтверждённые факты

#### 1. Устранение дыры наследования окружения хоста в раннере
* **Критика дефекта**: До C2 функция `build_command` в [`src/verify_ng/runner.rs:454`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L454) при спавне использовала `filter_env(std::env::vars(), true)`, отсекающий исключительно префиксы из `HARD_DENY_PREFIXES`. Любая произвольная переменная супервизора хоста (например, `HOST_ARBITRARY=1` или пользовательские токены вне хардкод-списка) сквозным образом утекала в изолируемый процесс.
* **Решение ([`src/verify_ng/runner.rs:408-456`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L408-L456))**: При передаче `req.contract` окружение строится по принципу clean-room whitelist:
  1. Переменные хоста отбираются строго через предикат [`policy.environment.allows()`](file:///home/shleder/prod/vetto/src/policy.rs) и вычищаются от паттернов `contract.environment.redacted_patterns`.
  2. Добавляются явно заданные переменные [`contract.environment.explicit_vars`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs).
  3. Внедряется криптографический нонс сессии `VETTO_PROD_NONCE`, если активен флаг `inject_session_nonce`.
  4. Переменная `PATH` принудительно санируется через [`envfilter::sanitize_path`](file:///home/shleder/prod/vetto/src/sandbox/envfilter.rs).
  5. Передаются изолированные переменные тестовой обвязки (`HOME`, `VETTO_RUN_NONCE`, `VETTO_FIXTURE_ROOT`, `VETTO_VNG_CONTROL_*`). Любые посторонние переменные хоста отсекаются на 100%.

#### 2. Фиксация независимых доказательств ядра (`HOST_FACT`)
* **Факт ([`src/verify_ng/environment.rs:116-143`](file:///home/shleder/prod/vetto/src/verify_ng/environment.rs#L116-L143), [`src/verify_ng/runner.rs:567-578`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L567-L578))**: Супервизор считывает `/proc/<pid>/environ` дочернего процесса сразу после системного вызова спавна, пока потомок удерживается на положительном контроле через FIFO.
* **Обоснование**: Это исключает зависимость от отчётов самого потомка (`SELF_REPORT`) и манипуляций с дескрипторами ввода-вывода. Нулевые байты ядра парсятся в `Vec<(String, String)>`, гарантируя срез фактического состояния адресного пространства после `execve`.

#### 3. Модуль верификации изоляции окружения
* **Факт ([`src/verify_ng/environment.rs`](file:///home/shleder/prod/vetto/src/verify_ng/environment.rs))**: Реализован модуль независимой верификации:
  * [`EnvironmentViolation`](file:///home/shleder/prod/vetto/src/verify_ng/environment.rs#L26-L44): строго типизированное перечисление всех 7 категорий нарушений Раздела 5.
  * [`is_denied_by_contract`](file:///home/shleder/prod/vetto/src/verify_ng/environment.rs#L146-L169): проверяет явные запреты через `contract.environment.redacted_patterns` и `policy.environment.deny`.
  * [`is_allowed_by_contract`](file:///home/shleder/prod/vetto/src/verify_ng/environment.rs#L173-L304): строгая семантическая валидация без предположений о безопасности префиксов. Блокирует незарегистрированные `VETTO_*`, чувствительные ключи `is_hard_denied`, относительные пути в `PATH` (`.`, `::`, `~`).
  * [`verify_execution_environment`](file:///home/shleder/prod/vetto/src/verify_ng/environment.rs#L312-L400): проверяет неизменность окружения хоста (`host_before == host_after`), классифицирует каждую переменную на `allowed_by_contract` и `leaked_from_host`, штампует факты `env-isolated`, `vector:env-scrub`, `vector:env-hygiene`. При наличии нарушений оракул переводится в отказ (`violation_observed = true`).

#### 4. Устранение дефекта непрерывности FM-03 (Security Spec Continuity)
* **Факт ([`src/verify_ng/runner.rs:682-684`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L682-L684))**: При финализации исполнения раннер заново замораживал `spec_after = SecuritySpec::freeze(...)`. Если в `spec.policy_bytes` был записан JSON запечатанного контракта, то `spec_after` получал дефолтные байты политики, что приводило к `spec.hash() != spec_after.hash()` и ложному сваливанию оракула в `spec_ok = false`. Сохранение `spec_after.policy_bytes = spec.policy_bytes.clone()` восстановило целостность проверки непрерывности спецификации.

#### 5. Расширение канарейки ENV-LEAK-001
* **Факт ([`src/verify_ng/registry.rs:269`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L269), [`tests/verify_ng/scenarios/ENV-LEAK-001.toml:13-19`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/ENV-LEAK-001.toml#L13-L19))**:
  * Расширен `known_limitation` без изменения кворума (`quorum: 1`) и без создания дублирующих сценариев.
  * В манифест добавлены хостовые факты `env_isolated` и `vector_scrub`.

#### 6. Интеграционная батарея тестов
* **Файл [`tests/integration/verify_ng_env_contract.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs)** (зарегистрирован в [`tests/integration/main.rs:66`](file:///home/shleder/prod/vetto/tests/integration/main.rs#L66)) содержит 15 тестов, закрывающих матрицу требований:
  1. [`test_env_arbitrary_host_var_not_leaked`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L171): произвольная переменная супервизора не попадает в execution.
  2. [`test_env_sensitive_looking_variables_not_leaked`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L235): ключи AWS, GitHub, Anthropic, приватные ключи блокируются.
  3. [`test_env_path_manipulation_sanitized`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L306): манипуляции с `PATH` (`.`, `~`, пустые сегменты) санируются.
  4. [`test_env_inherited_environment_scrubbed_clean_room`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L377): чистая комната без сквозного наследования хоста.
  5. [`test_env_internal_vetto_variables_not_leaked`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L442): незарегистрированные внутренние переменные `VETTO_*` блокируются.
  6. [`test_env_explicitly_denied_variables_blocked`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L509): переменные под запретом масок контракта отсекаются.
  7. [`test_env_post_start_mutation_contained`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L577): мутации потомка не меняют окружение супервизора хоста (`host_before == host_after`).
  8. [`test_env_verifier_distinguishes_allowed_by_contract_from_host_leaked`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L644): поштучное разделение фактов `allowed_by_contract` и `leaked_from_host`.
  9. [`test_env_no_blanket_prefix_assumption`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L716): отказ от префиксных допущений безопасности.
  10. [`test_env_leak_001_pass_with_sealed_contract`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L782): канарейка `ENV-LEAK-001` подтверждает `Verdict::Pass`.
  11. [`test_env_arbitrary_leak_detection_yields_fail`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L817): ловушка утечки переменной хоста переводит оракул в `Verdict::Fail`.
  12. [`test_env_sensitive_leak_detection_yields_fail`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L846): ловушка утечки секрета переводит оракул в `Verdict::Fail`.
  13. [`test_env_denied_var_detection_yields_fail`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L874): ловушка запрещённой переменной переводит оракул в `Verdict::Fail`.
  14. [`test_env_path_manipulation_detection_yields_fail`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L903): ловушка грязного `PATH` переводит оракул в `Verdict::Fail`.
  15. [`test_env_unit_verification_battery_matrix`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs#L947): матрица граничных условий верификатора окружения.

---

### Список изменённых файлов и обоснование

| Файл | Обоснование изменений |
|---|---|
| [`src/verify_ng/environment.rs`](file:///home/shleder/prod/vetto/src/verify_ng/environment.rs) | Модуль независимой верификации изоляции окружения по Разделу 5 (типы нарушений, чтение `/proc/<pid>/environ`, семантическая классификация, проверка неизменности хоста) |
| [`src/verify_ng/mod.rs`](file:///home/shleder/prod/vetto/src/verify_ng/mod.rs#L19) | Регистрация и публичный экспорт модуля `environment` |
| [`src/verify_ng/registry.rs`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L269) | Расширение описания и `known_limitation` канарейки `ENV-LEAK-001` без дублирования сценариев |
| [`src/verify_ng/runner.rs`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L408-L456) | Clean-room сборка окружения по контракту, снимок `host_env_before`, чтение `/proc/<pid>/environ`, фикс непрерывности `spec_after` (FM-03), интеграция `verify_execution_environment` и регистрация векторов `vector:env-scrub`, `vector:env-hygiene` |
| [`tests/verify_ng/scenarios/ENV-LEAK-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/ENV-LEAK-001.toml#L13-L19) | Обновление описания ограничений и добавление фактов `env_isolated`, `vector_scrub` |
| [`tests/integration/main.rs`](file:///home/shleder/prod/vetto/tests/integration/main.rs#L66) | Регистрация модуля интеграционных тестов `verify_ng_env_contract` |
| [`tests/integration/verify_ng_env_contract.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_env_contract.rs) | 15 интеграционных тестов изоляции окружения под управлением `SecurityContract` |
| [`orchestration/report_C2.md`](file:///home/shleder/prod/vetto/orchestration/report_C2.md) | Оркестрационный отчёт этапа C2 |

---

### Статус подтверждения и элементы NOT PROVEN

* **Подтверждено фактами кода (Confirmed Facts)**:
  1. Вся батарея изолирует окружение исключительно на основе запечатанного [`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L13); отсутствие или модификация дайджеста вызывает немедленный `fail-closed` без спавна ([`src/verify_ng/runner.rs:409-414`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L409-L414)).
  2. Blanket-prefix предположения полностью устранены: любая переменная классифицируется на основе явных правил контракта ([`src/verify_ng/environment.rs:173-304`](file:///home/shleder/prod/vetto/src/verify_ng/environment.rs#L173-L304)).
  3. Проверка неизменности окружения хоста фиксирует любые добавления, удаления и мутации ключей между снимками до и после запуска ([`src/verify_ng/environment.rs:324-344`](file:///home/shleder/prod/vetto/src/verify_ng/environment.rs#L324-L344)).
  4. Захват окружения через `/proc/<pid>/environ` выполняется супервизором на хосте и формирует независимый `HOST_FACT` ядра Linux ([`src/verify_ng/environment.rs:119-122`](file:///home/shleder/prod/vetto/src/verify_ng/environment.rs#L119-L122)).
* **Не подтверждено на локальной машине (NOT PROVEN locally)**:
  1. Фактическое выполнение `cargo test` / `cargo check`: локальные сборки и запуск тестов не производились согласно жёстким ограничениям задачи. Единственным доказательством успешного прохождения выступает GitHub CI.
  2. Захват `/proc/<pid>/environ` на не-Linux платформах: на macOS и Windows функция возвращает `None` ([`src/verify_ng/environment.rs:125`](file:///home/shleder/prod/vetto/src/verify_ng/environment.rs#L125)), верификатор использует `staged_env`, а вердикт строго ограничен потолком платформенного бэкенда.
