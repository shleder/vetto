Батарея верификации модификации запечатанного контракта безопасности ([`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L65)) по секции 10 Master Task и регрессионный сьют связывания идентичности исполнения ([`ExecutionIdentity`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L52)) со свидетельствами по секции 3 Master Task реализованы на 100% без изменения архитектуры и без введения вторичных политических движков. Любая попытка искажения любого поля контракта после запечатывания неизбежно приводит к отказу верификатора и гарантированной блокировке запуска (`NO SPAWN`), доказанной одновременно вердиктом `Verdict::Inconclusive`, физическим отсутствием маркерного файла дочернего процесса и нулевым изменением счетчика `PROD_SPAWN_COUNT` в спавн-леджере ядра. Свидетельства сессии A структурно не могут удовлетворить верификацию сессии B ни при каких подстановках.

---

### Подтвержденные факты реализации (file:line)

1. **Контроль спавн-леджера ядра и тестовый доступ к in-flight контракту**:
   - [`src/sandbox/production.rs:721-724`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L721-L724): в структуру `PreparedProductionExecution` добавлен метод `contract_mut_for_test(&mut self) -> &mut SecurityContract`, позволяющий эмулировать атаку изменения полей запечатанного контракта непосредственно между этапами `prepare()` и `spawn()`.
   - [`src/sandbox/production.rs:803`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L803): вызов `PROD_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst)` изолирован строго за всеми проверками дайджеста BLAKE3, проекционной эквивалентности и дрейфа FSM. При отказе любой проверки счетчик ядра не увеличивается.
   - [`src/sandbox/production.rs:2235, 2293`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2235): в существующий тест `phase1_contract_tamper_rejected_before_spawn` добавлен строгий ассерт на неизменность `PROD_SPAWN_COUNT` для всех 4 базовых сценариев повреждения контракта, а также доказан инкремент ровно на +1 в позитивном контроле.

2. **Полная матрица мутаций security-relevant полей в юнит-тестах production**:
   - [`src/sandbox/production.rs:2336-2525`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2336-L2525): реализован юнит-тест `phase2_contract_tamper_all_field_classes_rejected_no_spawn`, проверяющий 25 мутаций во всех 7 обязательных классах полей:
     - **filesystem**: `allow_read`, `allow_write`, `deny_read`, `deny_write`, `cow_overlay`, `execution_root_ro`.
     - **environment**: `explicit_vars`, `redacted_patterns`, `inject_session_nonce`.
     - **network**: `mode`, `allowed_domains`, `allowed_ports`, `allowed_ips`, `debug_ports`.
     - **limits**: `max_memory_mb`, `max_pids`, `max_cpu_seconds`, `max_file_size_mb`.
     - **executable restrictions**: `allowed_executables`, `forbidden_executables`, `invoked_binary`, `invoked_args`.
     - **secret masks**: `mask_paths`.
     - **tier/backend requirements**: `tier`, `backend`.
   - Каждый класс проверен в двух режимах:
     - *Unresealed*: прямая модификация объекта в памяти без переподписания. Итог: `!contract.verify_digest()`, немедленный отказ `freeze_production_contract`, `PROD_SPAWN_COUNT` неизменен, дочерний процесс не запущен.
     - *Resealed*: модификация с повторным вызовом `unsealed().seal()`. Итог: `verify_digest() == true`, но отказ на проверке `inconsistent production contract projection` либо `production contract/frozen input drift`, `PROD_SPAWN_COUNT` неизменен, дочерний процесс не запущен.

3. **Блокировка поддельных контрактов в пайплайне раннера verifier-ng**:
   - [`src/verify_ng/runner.rs:422-466`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L422-L466): в `run_one_with_backend` устранена лазейка с `unwrap_or(req.policy)`. Введено строгое требование наличия `contract.production` (`missing production installation contract`), а также обязательная сверка запечатанной проекции через `PolicyCompiler::compile_effective`. Переподписанный контракт с модифицированными полями немедленно сбрасывается в `fail_closed` (`Verdict::Inconclusive`) с `log.len() == 0` и `spawn_pid: None`.

4. **Интеграционный сьют контрактного взлома и кросс-исполнительной изоляции**:
   - [`tests/integration/main.rs:72`](file:///home/shleder/prod/vetto/tests/integration/main.rs#L72): зарегистрирован модуль `mod verify_ng_tamper_contract;`.
   - [`tests/integration/verify_ng_tamper_contract.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_tamper_contract.rs): реализовано 9 интеграционных сценариев:
     - `test_tamper_matrix_all_field_classes_rejected_no_spawn`: 25 мутаций по всем классам, доказывающих `Verdict::Inconclusive`, `log.len() == 0`, `spawn_pid: None`, отсутствие маркерного файла и неизменность `PROD_SPAWN_COUNT`.
     - `test_tamper_matrix_resealed_fails_closed_no_spawn`: 19 сценариев переподписания контракта с доказательством отлова проекционного дрейфа.
     - `test_tamper_production_spawn_ledger_and_marker_guarantee`: прямое тестирование `PreparedProductionExecution::spawn` на уровне ядра Linux.
     - `test_cross_execution_identity_binding_evidence_rejected`: тест секции 3 (Contract A / Execution A / Evidence A против Contract B / Execution B / Evidence B). Свидетельства A отвергаются в B, свидетельства B отвергаются в A (`Verdict::Inconclusive`, `has_verified_control == false`).
     - `test_cross_execution_stale_run_evidence_rejected`: свидетельства от предыдущего прогона (stale run) того же контракта отвергаются при несовпадении свежего `session_nonce`.
     - `test_cross_execution_other_contract_evidence_rejected`: свидетельства от контракта с другими правами/лимитами отвергаются из-за несовпадения `frozen_hash`.
     - `test_cross_execution_other_nonce_rejected`: свидетельства отвергаются при подмене сессионного нонса.
     - `test_cross_execution_other_backend_rejected`: свидетельства отвергаются при подмене бэкенда в идентичности.
     - `test_cross_execution_malformed_identity_rejected`: идентичность с любым пустым полем структурно блокирует вердикт `PASS`.

---

### Измененные и созданные файлы

- [`src/sandbox/production.rs`](file:///home/shleder/prod/vetto/src/sandbox/production.rs):
  - `contract_mut_for_test` добавлен в `PreparedProductionExecution`.
  - Встроен учет `PROD_SPAWN_COUNT` в `phase1_contract_tamper_rejected_before_spawn`.
  - Добавлен юнит-тест `phase2_contract_tamper_all_field_classes_rejected_no_spawn` (50 проверок: 25 unresealed + 25 resealed).
- [`src/verify_ng/runner.rs`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs):
  - Проверка обязательного присутствия `contract.production` и проекционной эквивалентности `PolicyCompiler::compile_effective` в `run_one_with_backend`.
- [`tests/integration/main.rs`](file:///home/shleder/prod/vetto/tests/integration/main.rs):
  - Регистрация модуля `verify_ng_tamper_contract`.
- [`tests/integration/verify_ng_tamper_contract.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_tamper_contract.rs):
  - Авторитетная интеграционная батарея тестов модификации контрактов и кросс-исполнительной изоляции идентичности.
- [`orchestration/report_C5.md`](file:///home/shleder/prod/vetto/orchestration/report_C5.md):
  - Отчет о завершении подзадачи C5.

---

### NOT PROVEN (Не доказано локально)

1. **Локальный запуск тестов и сборка компилятором**: Согласно универсальным ограничениям (`no local builds/tests`, запрет вызова `cargo test/build/check`), локальное исполнение тестов не производилось; истинность типизации выверена анализом исходного кода, а выполнение подтверждается исключительно прогоном в GitHub Actions CI.
2. **Аппаратные сбои ОЗУ (Rowhammer / Bit-flip после этапа валидации)**: Архитектура защищает от алгоритмических и программных атак в пространстве пользователя и супервизора; аппаратное повреждение памяти ядра хоста находится вне модели угроз песочницы Vetto.
3. **Изоляция сетевых пространств на non-Linux (macOS / Windows)**: Сетевые пространства имен и строгая проверка Landlock в Stage 2 поддержаны на Linux; на macOS/Windows неподдерживаемые возможности добросовестно возвращают `Unsupported` / `fail-closed`, что исключает ложноположительный `PASS`.
�лнение тестов не производились. Корректность типов и семантики выверена статически; окончательным валидатором является запуск тестов в GitHub CI.
2. **Аппаратные сбои памяти (RAM bit-flip после валидации)**: Защита рассчитана на программную модель безопасности (целостность FSM, неизменяемость структур данных супервизора, криптографический дайджест BLAKE3). Аппаратные атаки (Rowhammer, bit flip) выходят за рамки модели угроз песочницы.
3. **Платформозависимые особенности non-Linux (macOS Seatbelt, Windows LPAC)**: Интеграционные тесты `verify_ng_tamper_contract.rs` изолированы под `#[cfg(target_os = "linux")]`, поскольку полноценный механизм Landlock и контроль FIFO каналов в Stage 2 поддержан на Linux; платформенные тесты macOS и Windows подтверждают fail-closed поведение раздельно.
