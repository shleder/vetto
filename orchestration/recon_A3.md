Ветка `feat/phase1-contract-authority` (коммит `3ba5482`) не обеспечивает сквозного единообразия границы исполнения: авторитет запечатанного контракта (`SecurityContract` / `UnpreparedProductionExecution`) внедрён лишь в `supervise` (`src/main.rs`), `mcp wrap` (`src/mcp/wrap.rs`) и `multi` (`src/multi/runtime.rs`), тогда как preflight-проверка `--verify`, подкоманда `vetto verify` и `vetto doctor --probe` полностью обходят контрактный конвейер и вызывают `backend.spawn` напрямую через `src/doctor/probe.rs:106`. Кроме того, подсистема `src/mcp` (режим `serve`) запускает команды через небезопасный шелл (`sh -c`) с текстовым парсингом stderr вместо типизированного вердикта, `src/audit` разорван на два изолированных контура (криптографический леджер против легаси-файла `history.jsonl`), а `src/report` полностью слеп к запечатанному контракту и его дайджесту.

---

### 1. Маппинг точек входа к производственной границе

| Точка входа | Файл и строки | Статус использования Sealed-Contract Authority | Механизм запуска |
| :--- | :--- | :--- | :--- |
| **CLI: `vetto run` / `-- <cmd>`** | [`src/main.rs:983-1008`](file:///home/shleder/prod/vetto/src/main.rs#L983-L1008) | **Соблюдается** | `UnpreparedProductionExecution::new` → `prepare()` (компиляция и запечатывание контракта) → `spawn()` |
| **CLI: `vetto ephemeral`** | [`src/main.rs:164-206`](file:///home/shleder/prod/vetto/src/main.rs#L164-L206) | **Соблюдается** | Выставляет флаг `cfg.ephemeral = true` и вызывает общий `supervise(cfg)` |
| **CLI: `vetto <profile>` (External)** | [`src/main.rs:480-492`](file:///home/shleder/prod/vetto/src/main.rs#L480-L492) | **Соблюдается** | Загружает профиль и передает в `supervise(cfg)` |
| **CLI: `vetto` (по умолчанию)** | [`src/main.rs:496-540`](file:///home/shleder/prod/vetto/src/main.rs#L496-L540) | **Соблюдается** | Детектирует агент/профиль и передает в `supervise(cfg)` |
| **CLI: `--verify` (preflight)** | [`src/main.rs:815-834`](file:///home/shleder/prod/vetto/src/main.rs#L815-L834) | **Бход (Bypass)** | Вызывает `vetto::verify::preflight`, уходящий мимо контракта в `doctor::probe::run_probe_script` |
| **CLI: `vetto verify`** | [`src/main.rs:333-341`](file:///home/shleder/prod/vetto/src/main.rs#L333-L341), [`src/verify.rs:113-152`](file:///home/shleder/prod/vetto/src/verify.rs#L113-L152) | **Обход (Bypass)** | Вызывает `run_probe_script` → прямой `backend.spawn` без FSM и контракта |
| **CLI: `vetto doctor --probe`** | [`src/main.rs:2025`](file:///home/shleder/prod/vetto/src/main.rs#L2025) | **Обход (Bypass)** | Вызывает `run_probe_script` → прямой `backend.spawn` без контракта |
| **MCP: `vetto mcp wrap`** | [`src/mcp/wrap.rs:421-435`](file:///home/shleder/prod/vetto/src/mcp/wrap.rs#L421-L435) | **Соблюдается** | `UnpreparedProductionExecution::new` → `prepare()?.spawn()?` → `wait_collect()` |
| **MCP: `vetto mcp serve` (`tools/call`)** | [`src/mcp/mod.rs:226-277`](file:///home/shleder/prod/vetto/src/mcp/mod.rs#L226-L277) | **Разрыв архитектуры** | Рекурсивный `Command::new(current_exe)` через `sh -c`/`cmd.exe /C`, статус блокировок вычисляется по подстроке в stderr |
| **Multi: `vetto multi`** | [`src/multi/runtime.rs:339-363`](file:///home/shleder/prod/vetto/src/multi/runtime.rs#L339-L363) | **Соблюдается** | `UnpreparedProductionExecution::new` → `prepare()?.spawn()?` на каждый агент, завершение через `execution.finish()` ([`src/multi/runtime.rs:529`](file:///home/shleder/prod/vetto/src/multi/runtime.rs#L529)) |
| **Daemon: `vetto daemon` / `serve`** | [`src/daemon/registry.rs:81-99`](file:///home/shleder/prod/vetto/src/daemon/registry.rs#L81-L99) | **Внешний оркестратор** | Порождает внешний процесс CLI (`Command::new(current_exe)`). Контракт валидируется внутри дочернего процесса |
| **Audit: генерация леджера** | [`src/sandbox/production.rs:1110-1173`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1110-L1173) | **Соблюдается** | Пишет `VettoAuditRecord` с `contract_digest` в `vetto-audit-<nonce>.jsonl` через `AuditLedger` |
| **Audit: CLI `vetto audit`** | [`src/main.rs:1568`](file:///home/shleder/prod/vetto/src/main.rs#L1568), [`src/audit/history.rs:101-118`](file:///home/shleder/prod/vetto/src/audit/history.rs#L101-L118) | **Разрыв контура** | `main.rs` пишет в `~/.vetto/history.jsonl` структуру `AuditRecord` без поля `contract_digest`; CLI читает старый лог |
| **Report: генерация отчётов** | [`src/report/mod.rs:242`](file:///home/shleder/prod/vetto/src/report/mod.rs#L242), [`src/report/stats.rs:65`](file:///home/shleder/prod/vetto/src/report/stats.rs#L65) | **Слепота к контракту** | Отчёты генерируются исключительно из `SessionStats`; дайджест контракта, FSM-состояние и вердикт отсутствуют |

---

### 2. Выявленные обходы и архитектурные дефекты (Phase 2 Targets)

#### 1. Прямой обход через `run_probe_script` в `doctor` и `verify`
* **Факты**:
  * В [`src/doctor/probe.rs:106`](file:///home/shleder/prod/vetto/src/doctor/probe.rs#L106) функция `run_probe_script` выполняет:
    ```rust
    let sandbox::Spawned { mut handle, .. } = backend.spawn(pol, opts)?;
    ```
  * Эту функцию вызывают:
    1. [`src/verify.rs:265`](file:///home/shleder/prod/vetto/src/verify.rs#L265) при запуске батареи верификации границы (`vetto verify` и `--verify` preflight в [`src/main.rs:816`](file:///home/shleder/prod/vetto/src/main.rs#L816)).
    2. [`src/main.rs:2025`](file:///home/shleder/prod/vetto/src/main.rs#L2025) при запуске `vetto doctor --probe`.
* **Нарушение**: Метод `backend.spawn` вызывается напрямую в обход `UnpreparedProductionExecution`, `PolicyCompiler::compile_effective`, конечного автомата `ExecutionStateMachine`, вычисления BLAKE3-дайджеста и записи в `AuditLedger`.
* **Требование Фазы 2**: Изолировать или перевести проверочные песочницы на контрактный путь, либо полностью запретить прямой публичный вызов `Backend::spawn` вне модуля `sandbox::production`.

#### 2. Разрыв контракта и выполнение через шелл в `src/mcp/mod.rs`
* **Факты**:
  * В [`src/mcp/mod.rs:233-257`](file:///home/shleder/prod/vetto/src/mcp/mod.rs#L233-L257) функция `execute_sandboxed_command` конструирует вызов бинарника `vetto` через системный шелл:
    * Unix: `cmd.arg("sh").arg("-c").arg(command_str);` ([`src/mcp/mod.rs:252`](file:///home/shleder/prod/vetto/src/mcp/mod.rs#L252))
    * Windows: `cmd.arg("cmd.exe").arg("/C").arg(command_str);` ([`src/mcp/mod.rs:256`](file:///home/shleder/prod/vetto/src/mcp/mod.rs#L256))
  * Определение блокировок выполняется строковым поиском в выводе:
    * [`src/mcp/mod.rs:265-269`](file:///home/shleder/prod/vetto/src/mcp/mod.rs#L265-L269): `stderr.contains("BLOCKED") || stderr.contains("denied")`
* **Нарушение**:
  1. Нарушается запрет на использование командной оболочки ([`ARCHITECTURE.md:188`](file:///home/shleder/prod/vetto/ARCHITECTURE.md#L188): *"avoiding a shell quoting language"*).
  2. Результат выводится без привязки к `SecurityContract` и криптографическому аудиту.

#### 3. Разрыв подсистемы аудита (`src/audit`)
* **Факты**:
  * В [`src/sandbox/production.rs:1111-1171`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1111-L1171) формируются записи `VettoAuditRecord` с привязкой `contract_digest_blake3` и пишутся в `vetto-audit-<nonce>.jsonl` с валидацией хеш-цепочки (`AuditLedger::verify_file`, строка 1178).
  * В [`src/main.rs:1568`](file:///home/shleder/prod/vetto/src/main.rs#L1568) в файл `~/.vetto/history.jsonl` пишется устаревшая структура `AuditRecord` ([`src/audit/history.rs:15-34`](file:///home/shleder/prod/vetto/src/audit/history.rs#L15-L34)), в которой вообще нет поля `contract_digest`.
  * Команда `vetto audit` ([`src/audit/history.rs:121`](file:///home/shleder/prod/vetto/src/audit/history.rs#L121)) и `vetto audit digest` ([`src/audit/digest.rs`](file:///home/shleder/prod/vetto/src/audit/digest.rs)) читают только `history.jsonl`, не проверяя криптографическую целостность запечатанных контрактов.

#### 4. Полная изоляция отчётов от контракта (`src/report`)
* **Факты**:
  * В каталоге `src/report/` отсутствует какое-либо упоминание `contract` или `SecurityContract`.
  * [`src/report/stats.rs:65-98`](file:///home/shleder/prod/vetto/src/report/stats.rs#L65-L98) (`SessionStats`) собирает только системные счетчики и сырые имена профилей.
  * Экспортируемые форматы (JSON, HTML, Markdown, SARIF) не содержат BLAKE3-дайджеста контракта, состояния FSM и криптографического вердикта `VerdictEngine`.

---

### 3. Инспекция проверок в `.github/workflows/ci.yml`

Все существующие задачи CI с точными ссылками `file:line`:

1. **Job `check` (Ubuntu, x86_64)**:
   * Регрессионные тесты запечатывания контрактов и SLSA-подписей ([`.github/workflows/ci.yml:41-47`](file:///home/shleder/prod/vetto/.github/workflows/ci.yml#L41-L47)):
     * `crypto::slsa::tests::test_slsa_signed_envelope` (`--exact`) — строка 43
     * `policy_ir::contract::contract_tests` — строка 44
     * `audit::verdict::tests::test_inv36` — строка 45
     * `tests/phase4_enterprise_runtime.rs` — строка 46
   * Регрессионные тесты авторитета контрактов Фазы 1 ([`.github/workflows/ci.yml:48-50`](file:///home/shleder/prod/vetto/.github/workflows/ci.yml#L48-L50)):
     * `sandbox::production::production_unit_tests::phase1_` — строка 49
   * Полный прогон с замером покрытия ([`.github/workflows/ci.yml:51-59`](file:///home/shleder/prod/vetto/.github/workflows/ci.yml#L51-L59)):
     * `cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info` — строка 58
   * Контроль минимального порога покрытия (38.0%) ([`.github/workflows/ci.yml:68`](file:///home/shleder/prod/vetto/.github/workflows/ci.yml#L68)).

2. **Job `check-aarch64` (ARM64 через QEMU)**:
   * Проверка сисколов и seccomp ABI ([`.github/workflows/ci.yml:116-119`](file:///home/shleder/prod/vetto/.github/workflows/ci.yml#L116-L119)):
     * `cross test ... sandbox::linux::seccomp_netblock::tests --quiet` — строка 117-118

3. **Job `build-macos` (macOS-14 Apple Silicon & x86_64 cross-check)**:
   * Тесты производственной границы macOS ([`.github/workflows/ci.yml:132-136`](file:///home/shleder/prod/vetto/.github/workflows/ci.yml#L132-L136)):
     * `cargo test --test integration macos_prod --all-features -- --test-threads=1` — строка 136

4. **Job `build-windows` (Windows x86_64)**:
   * Регрессия подделки SLSA-подписи ([`.github/workflows/ci.yml:151-152`](file:///home/shleder/prod/vetto/.github/workflows/ci.yml#L151-L152)):
     * `cargo test --all-features --lib crypto::slsa::tests::test_slsa_signed_envelope -- --exact` — строка 152
   * Платформенная сюита Windows ([`.github/workflows/ci.yml:157-158`](file:///home/shleder/prod/vetto/.github/workflows/ci.yml#L157-L158)):
     * `cargo test --all-features --test integration windows_ -- --nocapture` — строка 158
   * Снимок возможностей (`doctor`) ([`.github/workflows/ci.yml:162-163`](file:///home/shleder/prod/vetto/.github/workflows/ci.yml#L162-L163)):
     * `cargo run --all-features --quiet -- doctor` — строка 163

5. **Job `micro-tier-fallback` (Downgrade & Redteam)**:
   * Тестирование отката на seccomp-only ([`.github/workflows/ci.yml:306-309`](file:///home/shleder/prod/vetto/.github/workflows/ci.yml#L306-L309)):
     * `cargo test --test integration linux_downgrade --all-features` — строка 307
     * `cargo test --test integration linux_redteam --all-features` — строка 308
     * `VETTO_FORCE_TIER=seccomp cargo run --all-features -- doctor` — строка 309
   * Автономная батарея red-team атак ([`.github/workflows/ci.yml:311-318`](file:///home/shleder/prod/vetto/.github/workflows/ci.yml#L311-L318)):
     * `cargo run --all-features -- redteam --json > "$REPORT_PATH" || true` — строка 316
     * Генерация отчёта скриптом `scripts/render-redteam-summary.py` — строка 317

6. **Job `perf`**:
   * Регрессионный бенчмарк e2e запуска ([`.github/workflows/ci.yml:211`](file:///home/shleder/prod/vetto/.github/workflows/ci.yml#L211)):
     * `cargo bench --bench e2e_spawn --all-features`
     * Гейт допустимого замедления (не более 3.0x относительно `perf-baseline.json`) ([`.github/workflows/ci.yml:252-257`](file:///home/shleder/prod/vetto/.github/workflows/ci.yml#L252-L257)).

---

### 4. Сопоставление с архитектурными документами

* **`ROADMAP.md`**:
  * Линия [`ROADMAP.md:10-11`](file:///home/shleder/prod/vetto/ROADMAP.md#L10-L11) декларирует: *"boundary verification battery (`vetto verify`, `--verify` preflight that refuses to start an agent on any leak)"*.
    * *Факт из кода*: Батарея реализована ([`src/verify.rs`](file:///home/shleder/prod/vetto/src/verify.rs)), но выполняется через изолированный скрипт [`src/doctor/probe.rs`](file:///home/shleder/prod/vetto/src/doctor/probe.rs) с прямым обращением к `backend.spawn`, без запечатывания контракта.
  * Линии [`ROADMAP.md:26-29`](file:///home/shleder/prod/vetto/ROADMAP.md#L26-L29) фиксируют 3-уровневый контракт платформ (Tier 1 Linux / Tier 2 macOS / Tier 3 Windows).
    * *Факт из кода*: Подтверждается типизацией в [`src/sandbox/production.rs:1100-1106`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1100-L1106) (`TierClassification::Tier1Linux` / `Tier2Macos` / `Tier3Windows`).
* **`ARCHITECTURE.md`**:
  * Линии [`ARCHITECTURE.md:16-25`](file:///home/shleder/prod/vetto/ARCHITECTURE.md#L16-L25) задают жесткий порядок старта (Single-threaded parse → Detect backend → Fork/sandbox → Worker threads → Reap & report).
    * *Факт из кода*: `main.rs` ([строки 983–1018](file:///home/shleder/prod/vetto/src/main.rs#L983-L1018)) и `multi/runtime.rs` ([строки 193–222](file:///home/shleder/prod/vetto/src/multi/runtime.rs#L193-L222)) строго соблюдают запрет на создание потоков до `spawn()`.
  * Линии [`ARCHITECTURE.md:188-194`](file:///home/shleder/prod/vetto/ARCHITECTURE.md#L188-L194) запрещают шелл-строки в мультиагентах и требуют строгий argv.
    * *Факт из кода*: В `src/multi` это строго выдержано, но нарушено в `src/mcp/mod.rs:252` (`sh -c`).
  * Линия [`ARCHITECTURE.md:193-194`](file:///home/shleder/prod/vetto/ARCHITECTURE.md#L193-L194) декларирует, что Windows отвергает `multi-agent`.
    * *Факт из кода*: Подтверждено в [`src/multi/mod.rs:196-198`](file:///home/shleder/prod/vetto/src/multi/mod.rs#L196-L198) (`VettoError::UnsupportedPlatform("multi-agent")`).

---

### 5. Разделение подтверждённых фактов и предположений

#### Подтверждённые факты (Confirmed Facts)
1. Точка входа `supervise` (`src/main.rs:983`), `mcp wrap` (`src/mcp/wrap.rs:421`) и `multi` (`src/multi/runtime.rs:339`) используют единую структуру `UnpreparedProductionExecution` и метод `prepare()`, вызывающий `PolicyCompiler::compile_effective` с автоматическим запечатыванием (`.seal()`) и проверкой BLAKE3-дайджеста (`contract.verify_digest()`).
2. Метод `backend.spawn` имеет прямой публичный вызов вне контрактного механизма в [`src/doctor/probe.rs:106`](file:///home/shleder/prod/vetto/src/doctor/probe.rs#L106), используемый подкомандами `vetto verify`, `vetto doctor --probe` и флагом `--verify`.
3. Подсистема `src/report` не содержит ни одного вызова, поля или импорта, связанного с `SecurityContract` или `contract_digest`.
4. Запись сессий в `~/.vetto/history.jsonl` ([`src/main.rs:1568`](file:///home/shleder/prod/vetto/src/main.rs#L1568)) сохраняет структуру `AuditRecord` без криптографического дайджеста, в то время как `vetto-audit-<nonce>.jsonl` ([`src/sandbox/production.rs:1088`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1088)) содержит полный `VettoAuditRecord`.
5. Тестовые проверки в CI (`.github/workflows/ci.yml`) охватывают компиляцию контрактов (строка 44), регрессии Фазы 1 (строка 49), macOS production (строка 136) и red-team (строка 316).

#### Предположения (Assumptions)
1. Предполагается, что `vetto daemon` и `src/remote` спроектированы как внешние диспетчеры процессов и намеренно не содержат in-process инициализации `UnpreparedProductionExecution`, делегируя её дочернему процессу `vetto --ci`.
2. Предполагается, что отсутствие поля `contract_digest` в `src/report/` и `src/audit/history.rs` является следствием незавершённого перехода на Фазу 2, а не осознанным архитектурным решением оставить отчёты вне контура безопасности.

---

### 6. Задачи для Фазы 2 (Phase 2 Action Items)

1. **Ликвидация обхода в `src/doctor/probe.rs` и `src/verify.rs`**:
   Перевести проверочные запуски (`run_probe_script`) на `UnpreparedProductionExecution` (например, со сценарием `PROBE` или `VERIFY`), либо сделать метод `Backend::spawn` приватным для крейта/модуля `sandbox`, чтобы исключить любые неконтролируемые спавны в обход запечатанного контракта.
2. **Устранение шелл-инъекций в `src/mcp/mod.rs`**:
   Переписать `execute_sandboxed_command` на прямой разбор аргументов без `sh -c` / `cmd.exe /C`. Использовать структурированный JSON-вывод с проверкой `ProductionResult` вместо текстового поиска `contains("BLOCKED")`.
3. **Унификация контура аудита**:
   Интегрировать `contract_digest_blake3` в глобальный журнал `history.jsonl` или перевести команды `vetto audit` и `vetto audit digest` на чтение и верификацию файлов `AuditLedger` (`vetto-audit-*.jsonl`).
4. **Интеграция контракта в `src/report`**:
   Добавить в `SessionStats` и финальные отчёты (JSON, HTML, SARIF, Markdown) обязательные поля: `contract_digest`, состояние FSM и структурированный вердикт `FinalVerdict`.
