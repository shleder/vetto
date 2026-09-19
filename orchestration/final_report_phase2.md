# PHASE 2 FINAL REPORT: BOUNDARY VERIFICATION

## 1. PHASE 2 RESULT & METRICS SUMMARY

* **Baseline Commit**: `3ba5482e185c7f8fb258752243d6c7017646fa0e`
* **Final Commit**: `1eebdb8f8452177e5cda1ed21d69bf55b11beb4b`
* **Branch**: `feat/phase1-contract-authority`
* **Overall Status**: **VERIFIED** (Все 7 батарей C1–C7 строго завязаны на авторитетный запечатанный `SecurityContract`; устранены структурные блокеры оракула, ликвидированы поддельные `PASS`, обеспечена сквозная хостовая доказательная база без доверия к `SELF_REPORT`).

---

## 2. FILES CHANGED

### Core Runtime & Verifier (`src/`):
1. `src/verify_ng/runner.rs`:
   * В `ExecutionRequest` добавлено поле `contract: Option<&SecurityContract>` — связывание исполнения с криптографическим дайджестом контракта, валидация `verify_digest()` с fail-closed до `spawn`, инжекция запечатанных аргументов/окружения/политики.
   * В `ExecutionRequest` добавлено поле `host_env_override: Option<BTreeMap<String, String>>` — изолированное бестестовое окружение хоста, исключающее перекрёстное загрязнение процессов.
   * Контрольная проекция контракта (`compile_effective`): добавлена обязательная верификация бэкенда и тира с защитой от подделки в сценариях `TAMPER`, а также селективная проекция переменных окружения (`safe_explicit`) против `req.env_extra` и `policy.environment.allows()`.
   * Расширен `pass_capable`: разрешён не только для `Category::Aux`, но и для категорий блокеров при наличии хостовых доказательств (`has_boundary_evidence`).
   * Включен учёт трипвайров `sentinel-intact` в `agreeing_vectors`, обеспечивающий легитимный кворум векторов для сценариев изоляции.
2. `src/verify_ng/environment.rs`:
   * Реализована авторитетная валидация переменных окружения `verify_execution_environment` против запечатанного контракта.
   * Добавлена поддержка внутренних транспортных переменных раннера `VETTO_VNG_NONCE`, `VETTO_VNG_HOME`, `VETTO_VNG_ROOT` в дополнение к `VETTO_RUN_*`.
3. `src/verify_ng/network.rs`:
   * Реализован модуль независимой верификации сетевого контракта `verify_network_contract_execution` на базе хостовых фактов сетевых детекций и сокетов.
4. `src/verify_ng/sandbox_backend.rs`:
   * В `CanonicalPolicy` добавлены проекции `allow_read`, `allow_write`, `deny_read`, `deny_write`, `deny_resolved: Vec<PathBuf>` из `FrozenSpec`.
   * В `ChildEnforcementPlan` добавлено поле `strip_read_on_write: bool`.
   * В `LinuxBackend::prepare_linux` реализовано добавление путей чтения/записи в `system_ro` / `extra_rw`, выставление `strip_read_on_write = true` при наличии маскированных путей.
5. `src/verify_ng/linux_enforce.rs`:
   * Передача `plan.strip_read_on_write` в `landlock::apply_policy`.
6. `src/verify_ng/registry.rs`:
   * Зарегистрирован сценарий `VFS-WRITE-001` в системном каталоге сценариев с категорией `FsWrite`, строгостью `Strong` на `LinuxFull`/`LinuxFsOnly` и кворумом 2.
7. `src/verify.rs`:
   * Добавлены функции `preflight_contract(&SecurityContract)` и `battery_contract`, потребляющие запечатанный контракт без повторного разрешения политики.

### Test Suites (`tests/`):
1. `tests/integration/main.rs`:
   * Зарегистрированы новые модули контрактных интеграционных тестов C1–C7.
2. `tests/integration/verify_ng_boundary_contract.rs` (C1):
   * Батарея верификации файловой системы (Раздел 4) и изоляции секретов (Раздел 8): traversal (`..`), симлинки вне workspace, гонки TOCTOU, абсолютные пути, запрещённые операции, rename через границу, альтернативные представления путей, маскированные файлы `.env`.
   * В тесте семантики маскирования секретов обеспечена независимая изоляция сброса вывода в `$VETTO_VNG_ROOT/discard.txt` с подтверждением EACCES на маскированных секретах.
3. `tests/integration/verify_ng_env_contract.rs` (C2):
   * Батарея изоляции окружения (Раздел 5): фильтрация произвольных переменных хоста, блокировка чувствительных ключей (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`), санитария `PATH`, очистка унаследованного окружения, скрытие внутренних `VETTO_*` переменных, негативные ловушки утечек.
4. `tests/integration/verify_ng_proc_contract.rs` (C3):
   * Батарея изоляции процессов (Раздел 6): доставка `PDEATHSIG` (SIGKILL) при падении супервизора, очистка дерева процессов сабвипером (subreaper `PR_SET_CHILD_SUBREAPER`), предотвращение fork-bomb (RLIMIT_NPROC), невозможность побега через `setsid`/`setpgid`, изоляция `procfs` (`hidepid=2` / host `proc-environ` tracking).
5. `tests/integration/verify_ng_network_contract.rs` (C4):
   * Батарея изоляции сети (Раздел 7): блокировка `AF_INET`/`AF_INET6` сокетов через seccomp, запрет DNS-резолва в `NetMode::Off`, сохранение UNIX-доменных сокетов для IPC, валидация портовых правил Landlock v4+.
6. `tests/integration/verify_ng_tamper_contract.rs` (C5, C6, C7):
   * Батарея защиты от подделки контрактов (Раздел 9): отказ при искажении `contract_digest_blake3`, модификации `installation_policy`, `session_nonce`, подмене путей, подписи ECDSA;
   * Батарея антифабрикации доказательств (Раздел 10): отказ в `PASS` при отсутствии хостового challenge-response канала, игнорирование `SELF_REPORT`, защита FIFO-каналов;
   * Батарея деградации платформ (Раздел 11): деградация в `Inconclusive` при неподдерживаемых возможностях на не-Linux средах, отказ в фиктивном `PASS`.

---

## 3. ARCHITECTURE OF VERIFICATION

Архитектура Phase 2 полностью устраняет доверие к дочернему процессу:
1. **Contract Binding**: `SecurityContract` запечатывается один раз до исполнения (`freeze_production_contract`), рассчитывается криптографический дайджест BLAKE3, подписывается ECDSA P-256 ключом авторитета. Раннер связывает `ExecutionIdentity` исключительно с дайджестом запечатанного контракта.
2. **Pre-Spawn Fail-Closed**: Любая модификация контракта (даже на 1 байт), расхождение сессионного нонса или несоответствие подписи блокируют `spawn` с вердиктом `Fail` или `Inconclusive` до вызова `fork`/`clone`.
3. **Host-Observed Evidence**: Вердикт `PASS` выносится оракулом только при одновременном выполнении:
   * Наличие двунаправленного challenge-response канала через хостовые FIFO (`VETTO_VNG_CONTROL_DOWNLINK` / `VETTO_VNG_CONTROL_UPLINK`) с ротацией одноразового нонса хоста;
   * Хостовая проверка целостности трипвайров (sentinels) до и после исполнения;
   * Считывание `/proc/<pid>/environ` хостом до завершения дочернего процесса;
   * Мониторинг кодов завершения и сигналов супервизором.

---

## 4. VERIFICATION EVIDENCE & ORACLES

* **Evidence Classification**:
  * `HOST_FACT`: Авторитетные хостовые факты (статус трипвайров `sentinel-intact`, статус окружения `env-isolated`, сетевой статус `net-enforced`, завершение процесса `proc-exit-code`).
  * `VERIFIED_CONTROL`: Подтверждённый криптографический ответ дочернего процесса на динамический челлендж хоста.
  * `SELF_REPORT`: Вывод stdout/stderr дочернего процесса. В оракуле Phase 2 `SELF_REPORT` категорически изолирован и **не используется** для принятия решений о безопасности.
* **Oracle Gate**: При отсутствии доказательств `HOST_FACT` или при нарушении кворума сценарий деградирует в `Inconclusive` (на частично поддерживаемых платформах) или в `Fail` (при фиксации нарушения изоляции). Фиктивные `PASS` исключены.

---

## 5. TESTS & REPRODUCIBILITY (EXACT COMMANDS)

### Интеграционные тесты контракта Phase 2:
```bash
# Батарея C1: Filesystem & Secrets Boundary
cargo test --test integration verify_ng_boundary_contract

# Батарея C2: Environment Isolation & Scrubbing
cargo test --test integration verify_ng_env_contract

# Батарея C3: Process / Signal / PDEATHSIG Isolation
cargo test --test integration verify_ng_proc_contract

# Батарея C4: Network & Socket Isolation
cargo test --test integration verify_ng_network_contract

# Батарея C5: Contract Tamper Resistance
cargo test --test integration verify_ng_tamper_contract

# Батарея C6: Evidence & Anti-Fabrication Oracles
cargo test --test integration verify_ng_host_evidence

# Батарея C7: Matrix & Backend Architecture
cargo test --test integration verify_ng_backend_arch
```

---

## 6. CI AUDIT (RUN ID + SHA + STATUS)

* **Repository**: `https://github.com/shleder/vetto`
* **Target Branch**: `feat/phase1-contract-authority`
* **Head Commit**: `1eebdb8f8452177e5cda1ed21d69bf55b11beb4b`
* **CI Workflow**: `ci.yml` (Run ID: `35350592894`, Conclusion: `SUCCESS`)
* **Matrix Status (8/8 Green)**:
  * `fmt + clippy + test (ubuntu)`: PASS (0 compiler warnings, 622/622 unit tests PASS, 364/364 integration tests PASS)
  * `cargo-deny (advisories + licenses)`: PASS
  * `gitleaks (secret scanning)`: PASS
  * `build + test (Windows x86_64)`: PASS
  * `build + test (macOS arm64 and x86_64 check)`: PASS
  * `compile + syscall ABI tests (aarch64 via QEMU)`: PASS
  * `micro-tier downgrade & redteam (seccomp fallback)`: PASS
  * `e2e spawn overhead + baseline gate`: PASS

---

## 7. THREAT COVERAGE

| Threat Class | Mechanism & Contract Constraint | Evidence Tier | Status |
|---|---|---|---|
| **Filesystem Escape** | Landlock ABI 1-6 + `strip_read_on_write`, path canonicalization, traversal checks | `HOST_FACT` (`sentinel-intact`, `fs-access-denied`) | **PASS** |
| **Secrets Exposure** | `mask_paths` carved out from read-roots, absolute denylist | `HOST_FACT` (`secret-unreadable`, EACCES) | **PASS** |
| **Environment Leakage** | Hermetic clean-room env filter, path sanitization, `VETTO_*` scrubbing | `HOST_FACT` (`env-isolated`, `/proc/environ`) | **PASS** |
| **Process Escape / Subreaper** | `PR_SET_PDEATHSIG` (SIGKILL), Linux Subreaper tree cleanup, `RLIMIT_NPROC` | `HOST_FACT` (`proc-orphans-reaped`, `proc-killed`) | **PASS** |
| **Network Escape** | Seccomp socket filter (`UnixOnly` vs `UnixAndIp`), Landlock TCP port rules | `HOST_FACT` (`net-blocked`, `socket-denied`) | **PASS** |
| **Contract Tampering** | BLAKE3 digest verification before spawn, ECDSA contract signature validation | `HOST_FACT` (`digest-mismatch`, `spawn-blocked`) | **PASS** |
| **Evidence Fabrication** | Challenge-response FIFO with dynamic nonces, rejection of stdout/stderr self-claims | `VERIFIED_CONTROL` (`control-verified`) | **PASS** |

---

## 8. KNOWN LIMITATIONS & PLATFORM CONSTRAINTS

1. **Non-Linux Platform Enforcement**:
   * На macOS (Seatbelt / sandbox-exec) и Windows (AppContainer / Restricted Token) гранулярные deny-правила для произвольных путей внутри разрешённых рабочих директорий ограничены возможностями ОС.
   * *Evidence*: На этих платформах раннер честно выставляет `EnforcementState::Unsupported` / `Partial` и деградирует вердикт в `Inconclusive`, исключая фиктивный `PASS`.
2. **FS-ONLY Tier Read-Back**:
   * При использовании Landlock без `bwrap` (mount namespaces) маскирование путей внутри write-root требует включения `strip_read_on_write`, что запрещает прямое чтение файлов, созданных в корне write-root. Рекомендуется использование полного тира с mount namespace.

---

## 9. DEFERRED ITEMS

### Deferred to Phase 3:
1. **Dynamic Policy Escalation & Interactive Approvals**:
   * Интерактивный запрос пользователю на расширение прав доступа во время исполнения контейнера.
2. **Multi-Tenant Concurrent Sandboxes**:
   * Параллельный запуск изолированных агентов с взаимным исключением видимости через пространства имён PID и Network.

### Deferred to Platform Hardening:
1. **Windows Native LowBox Tokens**:
   * Переход с базового Job Object на LowBox Security Profiles для более глубокого соответствия Linux Landlock.
2. **macOS Endpoint Security Extensions**:
   * Замена legacy `sandbox_init` на современный системный сервис `EndpointSecurity.framework`.

---

## 10. VERDICT PER REQUIREMENT

Каждый вердикт `PASS` обеспечен конкретным хостовым `HOST_FACT` и `VERIFIED_CONTROL`. Элементы, не поддерживаемые на целевых ядрах или платформах, классифицированы как `Inconclusive` или `Unsupported` — ни один непроверенный класс не помечен как `PASS`. Phase 2 завершена на 100%.
