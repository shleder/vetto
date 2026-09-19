### Вердикт

Все три точки входа (CLI, MCP, Multi-Agent) переведены на единую границу исполнения [`UnpreparedProductionExecution`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L461-L507) с обязательной верификацией запечатанного контракта [`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L64-L83). Выявленные в ходе рекогносцировки A3 обходы контракта (прямой спавн через [`src/doctor/probe.rs:106`](file:///home/shleder/prod/vetto/src/doctor/probe.rs#L106), запуск через `sh -c` в [`src/mcp/mod.rs:252`](file:///home/shleder/prod/vetto/src/mcp/mod.rs#L252) и неавторитетная проверка `--verify` в [`src/main.rs:815`](file:///home/shleder/prod/vetto/src/main.rs#L815)) устранены без создания параллельных механизмов безопасности и вторых движков политик. Метод [`Backend::spawn`](file:///home/shleder/prod/vetto/src/sandbox/mod.rs#L247) закрыт на уровне видимости модуля (`pub(in crate::sandbox)`), что делает физически невозможным запуск песочницы в обход контракта.

---

### Подтвержденные факты и анализ дефектов

1. **CLI `--verify` (preflight) и `vetto verify`**:
   * **Факт**: В [`src/main.rs:815-834`](file:///home/shleder/prod/vetto/src/main.rs#L815-L834) флаг `--verify` вызывал [`vetto::verify::preflight`](file:///home/shleder/prod/vetto/src/verify.rs#L155), который через [`run_probe_script`](file:///home/shleder/prod/vetto/src/doctor/probe.rs#L81) вызывал `backend.spawn` напрямую, минуя FSM, леджер и компиляцию контракта.
   * **Исправление**: В [`src/main.rs`](file:///home/shleder/prod/vetto/src/main.rs#L980-L1005) проверка вынесена строго после этапа `unprepared.prepare()?` и вызывает [`vetto::verify::preflight_contract(prepared.contract())`](file:///home/shleder/prod/vetto/src/verify.rs#L220). В [`src/verify.rs`](file:///home/shleder/prod/vetto/src/verify.rs#L125-L210) функции `run_cli` и `preflight` переведены на построение `UnpreparedProductionExecution` и проверку запечатанного контракта. Легаси-функция `battery`, не валидировавшая дайджест, удалена.

2. **Прямой спавн в `doctor::probe`**:
   * **Факт**: В [`src/doctor/probe.rs:106`](file:///home/shleder/prod/vetto/src/doctor/probe.rs#L106) функция `run_probe_script` вызывала `backend.spawn(pol, opts)` напрямую.
   * **Исправление**: В [`src/doctor/probe.rs:94-118`](file:///home/shleder/prod/vetto/src/doctor/probe.rs#L94-L118) запуск пробы переписан на конвейер `UnpreparedProductionExecution::new(...)` → `prepare()?` → `spawn()?` → `wait_collect()`. Контракт компилируется и опечатывается дайджестом BLAKE3.

3. **MCP (`run_sandboxed` / `execute_sandboxed_command`)**:
   * **Факт**: В [`src/mcp/mod.rs:226-277`](file:///home/shleder/prod/vetto/src/mcp/mod.rs#L226-L277) `execute_sandboxed_command` конструировал внешний процесс с аргументами `sh -c` / `cmd.exe /C` и проверял блокировки текстовым поиском подстрок в `stderr`.
   * **Исправление**: В [`src/mcp/mod.rs`](file:///home/shleder/prod/vetto/src/mcp/mod.rs#L153-L440) удалены шелл-обертки `sh -c` и `cmd.exe /C`. Добавлена функция прямого разбора аргументов [`parse_command_tokens`](file:///home/shleder/prod/vetto/src/mcp/mod.rs#L224), поддержана прямая передача массива аргументов `args`. Выполнение переведено на in-process `UnpreparedProductionExecution::new(...)` → `prepare()?` → `spawn()?` → `wait_collect()` с неблокирующим сбором `stdout`/`stderr` через [`AsyncPipeReader`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1667) для исключения дедлока кольцевого буфера 64 КБ.

4. **Multi-Agent (`vetto multi`)**:
   * **Факт**: В [`src/multi/runtime.rs:339-363`](file:///home/shleder/prod/vetto/src/multi/runtime.rs#L339-L363) уже используется `UnpreparedProductionExecution::new` → `prepare()?` → `spawn()?`. Привязка к авторитету запечатанного контракта подтверждена.

5. **Изоляция прямого интерфейса спавна**:
   * **Факт**: В [`src/sandbox/mod.rs:247`](file:///home/shleder/prod/vetto/src/sandbox/mod.rs#L247) область видимости `Backend::spawn` ограничена до `pub(in crate::sandbox) fn spawn`. Ни один компонент вне модуля `sandbox` не может инициировать спавн иначе как через `UnpreparedProductionExecution`.

---

### Измененные файлы и обоснование

| Файл | Обоснование |
| :--- | :--- |
| [`src/sandbox/mod.rs`](file:///home/shleder/prod/vetto/src/sandbox/mod.rs#L244-L252) | Ограничение видимости [`Backend::spawn`](file:///home/shleder/prod/vetto/src/sandbox/mod.rs#L247) до `pub(in crate::sandbox)`. Исключение возможности вызова спавна в обход запечатанного контракта на уровне компилятора Rust. |
| [`src/doctor/probe.rs`](file:///home/shleder/prod/vetto/src/doctor/probe.rs#L94-L124) | Перевод [`run_probe_script`](file:///home/shleder/prod/vetto/src/doctor/probe.rs#L81) на `UnpreparedProductionExecution` с автоматической компиляцией эффективной политики, запечатыванием дайджеста и корректным завершением через `wait_collect()`. |
| [`src/verify.rs`](file:///home/shleder/prod/vetto/src/verify.rs#L113-L245) | Маршрутизация [`run_cli`](file:///home/shleder/prod/vetto/src/verify.rs#L113) и [`preflight`](file:///home/shleder/prod/vetto/src/verify.rs#L182) через `UnpreparedProductionExecution` и [`preflight_contract`](file:///home/shleder/prod/vetto/src/verify.rs#L220). Удаление неподписанной функции `battery`. |
| [`src/main.rs`](file:///home/shleder/prod/vetto/src/main.rs#L975-L1010) | Перенос preflight-проверки `--verify` из строки 815 в строку 980 (после `unprepared.prepare()?`), с проверкой именно того контракта, который передается в `spawn()`. |
| [`src/mcp/mod.rs`](file:///home/shleder/prod/vetto/src/mcp/mod.rs#L153-L440) | Унификация MCP `run_sandboxed`: исключение `sh -c` и `cmd.exe /C`, прямая передача аргументов, запуск через `UnpreparedProductionExecution`, дренаж через `AsyncPipeReader`, юнит-тесты на парсинг токенов. |
| [`tests/integration/entrypoint_contract_parity.rs`](file:///home/shleder/prod/vetto/tests/integration/entrypoint_contract_parity.rs#L1) | Новый интеграционный регрессионный сьют: проверка авторитета контракта в CLI (`preflight_contract`), прямого выполнения аргументов без шелла в MCP, сценария в Multi-Agent и fail-closed отказа при модификации контракта (`test_tamper_parity_across_all_entrypoints`). |
| [`tests/integration/main.rs`](file:///home/shleder/prod/vetto/tests/integration/main.rs#L74) | Регистрация модуля `entrypoint_contract_parity`. |

---

### NOT PROVEN (Не доказано локально)

1. **Компиляция и прохождение тестов в CI**: В соответствии с жестким запретом на локальный вызов `cargo check` / `cargo test` / `cargo build`, проверка синтаксиса и регрессий возложена исключительно на GitHub Actions CI.
2. **Поведение на Windows**: Прогон подсистемы MCP без шелла на платформе Windows (с динамической загрузкой `processmodel.dll`) не верифицирован локально и требует проверки в матрице GitHub CI для Windows.
