### Главный вердикт

В ветке [`feat/phase1-contract-authority`](file:///home/shleder/prod/vetto) (коммит [`3ba5482`](file:///home/shleder/prod/vetto)) архитектура авторитета [`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L64-L83) и криптографической изоляции границы исполнения реализована полностью и готова к расширению батареями Phase 2 без переписывания базовых структур. Граница исполнения устроена по принципу fail-closed typestate: тип [`UnpreparedProductionExecution`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L461-L473) физически не имеет метода `.spawn()`, а переход [`PreparedProductionExecution::spawn`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L731-L876) защищён 4-уровневой проверкой неизменности (FSM-состояние [`Prepare`](file:///home/shleder/prod/vetto/src/policy_ir/fsm.rs#L18), верификация дайджеста BLAKE3, проверка на несанкционированное переподписание через round-trip проекцию [`compile_effective`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L48-L143) и сверка замороженных входов). Идентичность исполнения строго расщеплена на два независимых хэша: BLAKE3-дайджест контракта и SHA-256 [`frozen_hash`](file:///home/shleder/prod/vetto/src/verify_ng/frozen.rs#L53-L57), которые переносятся в журнал аудита [`VettoAuditRecord`](file:///home/shleder/prod/vetto/src/audit/record.rs#L114-L121) и отчет бэкенда [`EnforcementReport`](file:///home/shleder/prod/vetto/src/verify_ng/sandbox_backend.rs#L403-L408).

---

### 1. Трассировка пути sealed `SecurityContract` и OS Lowering

#### 1.1. Компиляция и запечатывание (`src/policy_ir`)
1. **Сборка эффективного контракта**: [`PolicyCompiler::compile_effective`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L48-L143) принимает уже разрешённый [`EffectivePolicyInput`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L33-L45) (`policy`, `argv`, `cwd`, `env`, `net`, `nonce`, `timeout`, `tier`, `backend`, `observe_seccomp`, `debug_ports`).
   - Проверяются обязательные поля: непустой `argv[0]` и `nonce` ([`compiler.rs:53-57`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L53-L57)). При нарушении — отказ [`CompilerError::MissingMandatoryField`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L25-L26).
   - Транслируется режим сети: `NetMode` -> `NetworkMode` ([`compiler.rs:62-71`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L62-L71)).
   - Проверяются лимиты процессов и таймаут ([`compiler.rs:72-78`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L72-L78)).
   - Сохраняются оригинальные значения установки в структуру [`ProductionContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L143-L151) внутри [`UnsealedSecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L12-L27).
   - Назначаются `contract_id = format!("production-{}", input.nonce)` ([`compiler.rs:91`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L91)) и `session_nonce = input.nonce.to_string()` ([`compiler.rs:92`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L92)).
2. **Криптографический дайджест**:
   - Метод [`UnsealedSecurityContract::compute_digest`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L31-L41) временно обнуляет отсоединённую подпись (`payload.crypto.signature = None`), канонизирует структуру через `serde_json::to_value` / `serde_json::to_vec` и вычисляет 256-битный BLAKE3-хэш (hex-строка из 64 символов) через встроенную pure-Rust реализацию BLAKE3 ([`contract.rs:390-728`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L390-L728)).
   - Метод [`UnsealedSecurityContract::seal`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L44-L60) связывает полученный хэш в поле `contract_digest_blake3` структуры [`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L64-L83).
   - Поле `contract_digest_blake3` помечено `#[serde(default, skip_serializing)]` ([`contract.rs:81`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L81)), что исключает циклическую зависимость при сериализации.
3. **FSM валидация перехода**:
   - Машина состояний [`ExecutionStateMachine`](file:///home/shleder/prod/vetto/src/policy_ir/fsm.rs#L59-L62) переводит исполнение из [`ExecutionState::Intent`](file:///home/shleder/prod/vetto/src/policy_ir/fsm.rs#L12) в [`ExecutionState::PolicyCompiled`](file:///home/shleder/prod/vetto/src/policy_ir/fsm.rs#L14) ([`production.rs:602`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L602)).
   - Проверяется `contract.verify_digest()` ([`production.rs:603-606`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L603-L606)), после чего FSM переходит в [`ExecutionState::ContractSealed`](file:///home/shleder/prod/vetto/src/policy_ir/fsm.rs#L16) ([`production.rs:607`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L607)).

#### 1.2. Граница исполнения и Lowering в OS Mechanics (`src/sandbox/production.rs`)
1. **Проекция контракта в каноническую спецификацию ([`freeze_production_contract`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L361-L432))**:
   - Повторная верификация `contract.verify_digest()` ([`production.rs:367-370`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L367-L370)).
   - Извлечение обязательного поля `contract.production` ([`production.rs:371-374`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L371-L374)).
   - Сверка соответствия реального бэкенда и уровня изоляции: `production.backend == backend && production.tier == tier` ([`production.rs:375-379`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L375-L379)).
   - **Защита от переподписания поддельных проекций**: выполняется контрольная компиляция `PolicyCompiler::compile_effective` из сырых данных `installation_policy`, и жестко проверяется равенство всего контракта `expected == *contract` ([`production.rs:389-407`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L389-L407)).
   - Формируется [`FrozenSpec`](file:///home/shleder/prod/vetto/src/verify_ng/frozen.rs#L25-L48) через `frozen::freeze_spec(...)` ([`production.rs:408-419`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L408-L419)).
   - В поле `spec.policy_bytes` встраивается JSON-конверт:
     ```rust
     spec.policy_bytes = serde_json::to_vec(&serde_json::json!({
         "contract": contract,
         "digest": contract.contract_digest_blake3,
     }))?;
     ```
     ([`production.rs:420-423`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L420-L423)).
   - Вычисляется канонический объект [`CanonicalPolicy::from_frozen(&spec)`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L424) и идентичность исполнения [`ExecutionIdentity::new(scenario, &contract.session_nonce, PROD_REGISTRY, &spec.hash())`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L425-L430).
2. **Подготовка бэкенда ([`prepare_production_contract`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L434-L452))**:
   - Вызывается `capability.prepare_with_context(&canonical, &identity, &PrepareContext::default())` ([`production.rs:442`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L442)).
   - Проверяется, что бэкенд выставил `preparation_ok && r.binds_identity(&identity)` ([`production.rs:443-446`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L443-L446)). Любой сбой возвращает ошибку, блокируя переход в состояние спавна ([`production.rs:447-450`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L447-L450)).
   - FSM переводится в [`ExecutionState::Prepare`](file:///home/shleder/prod/vetto/src/policy_ir/fsm.rs#L18) ([`production.rs:615`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L615)), возвращается [`PreparedProductionExecution`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L644-L659).
3. **Единственная точка спавна ([`PreparedProductionExecution::spawn`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L731-L876))**:
   - Поглощает `self` по значению (невозможно вызвать дважды или повторить после ошибки).
   - Проверяет `self.fsm.current_state() == ExecutionState::Prepare` ([`production.rs:732-735`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L732-L735)).
   - Заново вызывает `freeze_production_contract` ([`production.rs:737-742`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L737-L742)) и проверяет отсутствие дрейфа по всем полям ([`production.rs:748-759`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L748-L759)):
     `canonical == self.canonical && identity.frozen_hash == self.identity.frozen_hash && canonical.argv == self.argv && canonical.cwd == self.cwd && canonical.env == self.env && production.net == self.net && production.timeout == self.timeout && production.tier == self.tier && production.observe_seccomp == self.mechanics.observes_seccomp()`.
   - Проверяет согласованность сетевого режима механики: `self.mechanics.net_label() == self.net.label()` ([`production.rs:764-766`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L764-L766)).
   - Для Linux проверяет соответствие пред-исполнительного плана: `plan.net_deny` и `plan.new_pgroup` ([`production.rs:771-779`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L771-L779)).
   - Сбрасывает Netlink-канал сбора доказательств: `reset_evidence_channel()` ([`production.rs:791`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L791)).
   - FSM: `transition(ExecutionState::Spawn)` ([`production.rs:799`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L799)).
   - Вызов реального спавна: `self.mechanics.spawn(policy, opts)` ([`production.rs:800`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L800)), где `policy = &production.installation_policy`.
   - FSM: `transition(ExecutionState::Enforce)` ([`production.rs:802`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L802)).
   - Фиксация реального PID: `self.capability.note_spawned(pid)` ([`production.rs:805`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L805)).
   - **Host-верификация живого дочернего процесса**:
     - Linux: `verify_child_host(pid)` и проверка лимитов через парсинг `/proc/{pid}/limits` ([`production.rs:827-845`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L827-L845)).
     - Windows: `verify_production_child(process, job)` ([`production.rs:814-821`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L814-L821)).
     - macOS: `verify_child_host(pid)` ([`production.rs:850-854`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L850-L854)).
     - `self.capability.note_host_verified(&verification)`.
   - FSM: `transition(ExecutionState::Observe)` ([`production.rs:856`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L856)).
   - Возвращается [`SpawnedProductionExecution`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L885-L905).
4. **Конкретный OS Lowering в механику ядра**:
   - `Backend::spawn` ([`src/sandbox/mod.rs:247-256`](file:///home/shleder/prod/vetto/src/sandbox/mod.rs#L247-L256)) делегирует в [`LinuxSandbox::spawn`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L171-L190).
   - Для уровня `Tier::Full` вызывается `spawn_full` ([`src/sandbox/linux/mod.rs:1211-1362`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1211-L1362)):
     - Устанавливается флаг subreaper через `set_subreaper()` ([`linux/mod.rs:1222`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1222)).
     - `fork()` ([`linux/mod.rs:1260`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1260)) запускает `child_full` ([`linux/mod.rs:1034-1200`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1034-L1200)).
     - Изолируются пространства имён: `CLONE_NEWUSER` ([`linux/mod.rs:1072`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1072)), `CLONE_NEWNS` ([`linux/mod.rs:1090`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1090)), `CLONE_NEWIPC` ([`linux/mod.rs:1118`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1118)), `CLONE_NEWNET` ([`linux/mod.rs:1121`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1121)), `CLONE_NEWPID` ([`linux/mod.rs:1146`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1146)).
     - Монтируются маски путей и секретов: `mounts::mask_path` ([`linux/mod.rs:1152`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1152)), `vfs_overlays::mask_ssh_and_env` ([`linux/mod.rs:1165`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1165)).
     - Накладываются cgroups v2: `cgroup::setup_cgroup` ([`linux/mod.rs:1332`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1332)).
     - Внутри потомка применяются лимиты `setrlimit` (`limits::apply`), правила Landlock через `landlock::apply_policy_with_net_ports` ([`linux/mod.rs:1429`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1429)), BPF-фильтр seccomp через `seccomp_netblock::install` ([`linux/mod.rs:1447`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1447)), после чего вызывается `libc::execvp` ([`linux/mod.rs:1469`](file:///home/shleder/prod/vetto/src/sandbox/linux/mod.rs#L1469)).

---

### 2. Создание Execution Identity и привязка к Evidence

#### 2.1. Где создаются компоненты идентичности
| Компонент идентичности | Место создания (file:line) | Алгоритм / Источник |
|---|---|---|
| `contract_id` | [`src/policy_ir/compiler.rs:91`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L91)<br>[`src/policy_ir/compiler.rs:334`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L334) | `format!("production-{}", input.nonce)` либо `format!("contract-{}", &session_nonce[..12])` |
| `contract_digest` (`contract_digest_blake3`) | [`src/policy_ir/contract.rs:40, 58`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L40) | BLAKE3 поверх канонического JSON `UnsealedSecurityContract` с отделённой подписью (`signature = None`) |
| `session_nonce` (`nonce`) | [`src/verify_ng/engine.rs:12-19`](file:///home/shleder/prod/vetto/src/verify_ng/engine.rs#L12-L19)<br>[`src/policy_ir/compiler.rs:393-398`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L393-L398) | 16 байт из `rand_core::OsRng`, кодированных в 32 hex-символа |
| `frozen_hash` | [`src/verify_ng/frozen.rs:53-57`](file:///home/shleder/prod/vetto/src/verify_ng/frozen.rs#L53-L57) | SHA-256 от канонических байтов `FrozenSpec` (`spec.canonical_bytes()`). Включает в себя запечатанный контракт и его BLAKE3-дайджест через `spec.policy_bytes` ([`production.rs:420-423`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L420-L423)) |
| `ExecutionIdentity` | [`src/sandbox/production.rs:425-430`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L425-L430)<br>[`src/verify_ng/evidence.rs:60-72`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L60-L72) | `ExecutionIdentity::new(scenario, &contract.session_nonce, PROD_REGISTRY, &spec.hash())` |
| `provenance` (`HostProvenance`) | [`src/verify_ng/evidence.rs:88-104`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L88-L104) | Связывает `scenario_id`, `session_nonce`, `registry_hash`, `frozen_hash` и `channel == HOST_CONTROL_CHANNEL` |
| SLSA `invocation_id` | [`src/crypto/slsa.rs:175, 259-273`](file:///home/shleder/prod/vetto/src/crypto/slsa.rs#L175) | RFC 4122/9562 UUID v4 через CSPRNG |

#### 2.2. Где идентичность привязывается к Evidence
1. **Привязка к дочернему процессу через окружение**:
   - `VETTO_PROD_NONCE` инжектируется в окружение процесса ([`src/sandbox/production.rs:583`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L583)).
2. **Привязка к отчету о соблюдении (`EnforcementReport`)**:
   - Метод [`EnforcementReport::binds_identity`](file:///home/shleder/prod/vetto/src/verify_ng/sandbox_backend.rs#L403-L408) сравнивает все 4 поля: `scenario_id`, `session_nonce`, `registry_hash`, `frozen_hash`. Любое расхождение отвергается.
3. **Привязка к доказательствам хостового контроля (`VerifiedControl`)**:
   - [`HostProvenance::matches`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L97-L103) проверяет совпадение с `ExecutionIdentity` и защищает от кросс-сессионного воспроизведения (replay) токена.
   - Оракул [`oracle::judge`](file:///home/shleder/prod/vetto/src/verify_ng/oracle.rs#L94-L109) при несоответствии `identity.scenario_id`, несовпадении `nonce`, отсутствии `has_verified_control(identity)` или отсутствии `has_host_fact()` возвращает `Verdict::Inconclusive`.
4. **Привязка к зачистке дерева процессов (Tree Extinction Sweep)**:
   - Linux: `crate::verify_ng::linux_enforce::sweep_tree_by_nonce(self.nonce.as_str(), self.pid)` ([`src/sandbox/production.rs:1020`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1020)) вычищает процессы ядра по уникальному `nonce`.
5. **Привязка к журналу аудита (`AuditLedger`)**:
   - Путь файла аудита жестко привязан к `nonce`: `audit_dir.join(format!("vetto-audit-{}.jsonl", self.nonce))` ([`src/sandbox/production.rs:1089`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1089)).
   - Каждая запись [`VettoAuditRecord`](file:///home/shleder/prod/vetto/src/audit/record.rs#L114-L121) фиксирует `session_id = &self.nonce` и `contract_digest = &self.contract.contract_digest_blake3`:
     - `session_init` ([`production.rs:1111-1119`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1111-L1119)).
     - `tree_extinction` ([`production.rs:1121-1132`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1121-L1132)).
     - `session_verdict` ([`production.rs:1165-1171`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1165-L1171)).
   - Проверяется криптографическая хэш-цепочка файла: `AuditLedger::verify_file(&ledger_path)` ([`production.rs:1178`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1178)). При сбое принудительно выставляется exit code 125 ([`production.rs:1192`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1192)).

---

### 3. Существующие проверки Tamper-Rejection и No-Spawn-On-Invalid

Все существующие точки отказа, предотвращающие спавн при модификации контракта или невалидном состоянии:

1. **Отказ на уровне компиляции контракта**:
   - Проверка пустых обязательных полей: [`src/policy_ir/compiler.rs:53-57`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L53-L57).
   - Выход за допустимый диапазон лимитов: [`src/policy_ir/compiler.rs:72-78`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L72-L78).
   - Directory traversal (`..` в путях): [`src/policy_ir/compiler.rs:167-176, 212-221, 239-244`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L167-L176).
   - Побег предка пути записи за пределы workspace: [`src/policy_ir/compiler.rs:261-267`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L261-L267).
   - Коллизия целевого пути записи с обязательными масками секретов (`.ssh`, `.aws`, `.gnupg`, `.env`, `.git/config`): [`src/policy_ir/compiler.rs:290-301`](file:///home/shleder/prod/vetto/src/policy_ir/compiler.rs#L290-L301).
2. **Отказ на этапе инициализации супервизора**:
   - `SupervisorEngine::new`: отказ [`StateTransitionError::FailClosed`](file:///home/shleder/prod/vetto/src/policy_ir/fsm.rs#L51-L55) при нарушении BLAKE3 дайджеста контракта: [`src/sandbox/production.rs:1414-1420`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1414-L1420).
   - `SupervisorEngine::prepare`: отказ при нарушении дайджеста перед переходом в `Prepare`: [`src/sandbox/production.rs:1453-1459`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1453-L1459).
3. **Отказ на этапе подготовки исполнения (`prepare`)**:
   - Пустой `argv`: [`src/sandbox/production.rs:555-557`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L555-L557).
   - Запрос сетевого релея на macOS: отказ [`production.rs:558-566`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L558-L566).
   - Запрос сетевого релея на Linux без `Tier::Full`: отказ [`production.rs:567-575`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L567-L575).
   - Несовпадение BLAKE3-дайджеста только что скомпилированного контракта: [`src/sandbox/production.rs:603-606`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L603-L606).
   - Внутри `freeze_production_contract`:
     - Повреждённый дайджест: `ensure!(contract.verify_digest(), "invalid production contract digest")` ([`production.rs:367-370`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L367-L370)).
     - Отсутствующий контракт установки: `ensure!(contract.production.is_some(), "missing production installation contract")` ([`production.rs:371-374`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L371-L374)).
     - Несоответствие бэкенда или уровня изоляции: `ensure!(production.backend == backend && production.tier == tier, "production contract/backend mismatch")` ([`production.rs:375-379`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L375-L379)).
     - Попытка переподписания модифицированной проекции: `ensure!(expected == *contract, "inconsistent production contract projection")` ([`production.rs:404-407`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L404-L407)).
   - Внутри `prepare_production_contract`:
     - Бэкенд не подтвердил подготовку или не связал идентичность: `ensure!(prepared_ok, "production backend preparation failed (fail-closed, no agent execution)")` ([`production.rs:447-450`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L447-L450)). Приводит к возврату `Err` из `prepare()` — объект `PreparedProductionExecution` не может быть создан.
4. **Отказ непосредственно перед системным вызовом `spawn` (`PreparedProductionExecution::spawn`)**:
   - Нарушение состояния жизненного цикла FSM (`self.fsm.current_state() != ExecutionState::Prepare`): отказ [`src/sandbox/production.rs:732-735`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L732-L735).
   - Дрейф замороженных входов или хэша между фазами `prepare` и `spawn`: отказ [`src/sandbox/production.rs:748-759`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L748-L759).
   - Дрейф сетевого режима механики: отказ [`src/sandbox/production.rs:764-766`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L764-L766).
   - Потеря изоляции группы процессов или расхождение сетевого плана на Linux: отказ [`src/sandbox/production.rs:771-779`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L771-L779).
   - *Только при успешном прохождении всех указанных строк управление доходит до вызова `self.mechanics.spawn(policy, opts)`* ([`production.rs:800`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L800)).
5. **Отказ на этапе синхронизации политик (`src/policy_ir/sync.rs`)**:
   - Сбой валидации манифеста по схеме: [`sync.rs:64-70`](file:///home/shleder/prod/vetto/src/policy_ir/sync.rs#L64-L70).
   - Несоответствие дайджеста BLAKE3 в контракте воркера: [`sync.rs:77-79`](file:///home/shleder/prod/vetto/src/policy_ir/sync.rs#L77-L79).
   - Незарегистрированный агент: [`sync.rs:83-85`](file:///home/shleder/prod/vetto/src/policy_ir/sync.rs#L83-L85).
   - Дрейф политики (несовпадение хэшей): [`sync.rs:87-93`](file:///home/shleder/prod/vetto/src/policy_ir/sync.rs#L87-L93) (Exit 125).
   - Попытка зарегистрировать конфликтующий контракт для существующего агента: [`sync.rs:120-126`](file:///home/shleder/prod/vetto/src/policy_ir/sync.rs#L120-L126) (Exit 125).

---

### 4. Регрессионные тесты Phase 1 (что уже проверено и не требует дублирования)

Ниже перечислены существующие тесты с точным указанием того, какие инварианты они закрывают. Батареи Phase 2 не должны дублировать эти сценарии:

1. **`sandbox::production::production_unit_tests::phase1_`**:
   - [`phase1_production_preparation_receives_sealed_contract`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2021-L2104): тестовый бэкенд `InspectContract` доказывает передачу запечатанного контракта в `CanonicalPolicy`, проверяет `contract.verify_digest()`, различие `contract_digest_blake3 != identity.frozen_hash` и совпадение `contract.session_nonce == identity.session_nonce`.
   - [`phase1_invalid_contract_never_prepares_capabilities`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2108-L2220): через счетчик вызовов `CountPreparation(0)` доказано, что при 5 типах нарушений (`digest`, `projection`, `missing`, `backend`, `debug-ports`) метод `capability.prepare` ни разу не вызывается (`capability.0 == 0`).
   - [`phase1_contract_tamper_rejected_before_spawn`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2224-L2313): доказывает, что при 4 типах модификации контракта между фазами `prepare` и `spawn` (`digest`, `resealed`, `projection`, `missing`) метод `prepared.spawn()` возвращает `Err`, а маркерный файл дочернего процесса `child-started` не создаётся (`!marker.exists()`).
   - [`phase1_caller_policy_cannot_change_canonical_backend_input`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2317-L2376): доказывает иммутабельность замороженных входов супервизора при мутации исходных объектов `policy` и `debug_ports` вызывающей стороной после вызова `prepare`.
   - [`phase1_production_audit_binds_actual_contract`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2380-L2432): доказывает, что в журнал `vetto-audit.jsonl` записываются все три типа записей (`SessionInit`, `TreeExtinction`, `SessionVerdict`), каждая содержит `contract_digest == digest`, `contract_digest != frozen_hash`, а хэш-цепочка валидируется через `AuditLedger::verify_file`.
   - [`test_prod_backend_fail_closed_001_no_spawn`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2439-L2475): доказывает, что провал подготовки бэкенда не приводит к спавну процесса.
2. **`policy_ir::contract::contract_tests`**:
   - [`seal_and_verify_digest`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L305-L320): запечатывание и инвалидация дайджеста при изменении `cow_overlay` или `network.mode`.
   - [`deterministic_digest`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L323-L327): детерминизм BLAKE3-хэша для одинаковых входов.
   - [`signing_requirements_are_sealed_but_signature_is_detached`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L330-L350): отсоединённая подпись не инвалидирует дайджест, но смена публичного ключа, флагов minisign или cosign инвалидирует дайджест.
   - [`crypto_contract_builder_methods`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L378-L387): корректность работы билдера крипто-параметров.
3. **`tests/phase4_enterprise_runtime.rs`**:
   - [`test_slsa_l3_attestation_envelope_and_signature`](file:///home/shleder/prod/vetto/tests/phase4_enterprise_runtime.rs#L100-L143): генерация и проверка конвертов In-Toto SLSA v1 с подписью Ed25519.
   - [`test_verdict_engine_all_matrix_states`](file:///home/shleder/prod/vetto/tests/phase4_enterprise_runtime.rs#L146-L210): матрица вердиктов (отказы ядра, неавторизованные записи, зомби-процессы, сбой канала Netlink, неподдерживаемая платформа).
   - [`test_process_tree_extinction_theorem_cases`](file:///home/shleder/prod/vetto/tests/phase4_enterprise_runtime.rs#L258-L310): математическая теорема вымирания процессов (превышение лимита 500 мс или выживание процессов -> Exit 125).
   - [`test_enterprise_policy_synchronization_and_drift_detection`](file:///home/shleder/prod/vetto/tests/phase4_enterprise_runtime.rs#L312-L381): синхронизация политик флота, обнаружение дрейфа и отказ незарегистрированных агентов.
   - [`test_contract_blake3_sealing_and_digest_verification`](file:///home/shleder/prod/vetto/tests/phase4_enterprise_runtime.rs#L466-L476): проверка дайджеста BLAKE3.
   - [`test_crypto_tamper_rejected_at_supervisor_initialization`](file:///home/shleder/prod/vetto/tests/phase4_enterprise_runtime.rs#L478-L495): отказ `SupervisorEngine::new` при модификации параметров крипто-контракта.
   - [`test_inv37_netlink_disruption_forces_inconclusive_verdict`](file:///home/shleder/prod/vetto/tests/phase4_enterprise_runtime.rs#L542-L588): сбой Netlink буфера (ENOBUFS) принудительно переводит вердикт в INCONCLUSIVE и стирает CoW-слой.
   - [`test_triplane_supervisor_engine_full_lifecycle_and_invariants`](file:///home/shleder/prod/vetto/tests/phase4_enterprise_runtime.rs#L591-L680): полный цикл FSM, отказ при превышении зомби-процессов, запись в журнал аудита.
4. **`src/crypto/slsa.rs`**:
   - [`test_slsa_builder_and_statement_schema`](file:///home/shleder/prod/vetto/src/crypto/slsa.rs#L281-L323): соответствие JSON-схемы спецификации SLSA v1.
   - [`test_slsa_signed_envelope`](file:///home/shleder/prod/vetto/src/crypto/slsa.rs#L325-L365): криптографическая проверка подписи Ed25519, отказ на неверном ключе и модифицированном payload.

---

### 5. Разделение подтверждённых фактов и допущений (Recon Map для Phase 2)

#### 5.1. Подтверждённые факты кода
1. **Факт**: В `production.rs` спавн невозможен в обход этапа `prepare` благодаря typestate-паттерну: `UnpreparedProductionExecution` не содержит метода `spawn` ([`production.rs:461-473`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L461-L473)).
2. **Факт**: Переподписание модифицированного контракта другим ключом или генерация нового дайджеста не позволяют обойти изоляцию, так как `freeze_production_contract` заново компилирует эффективную политику из `installation_policy` и жестко проверяет `expected == *contract` ([`production.rs:404-407`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L404-L407)).
3. **Факт**: `ExecutionIdentity` и `EnforcementReport` жестко связаны через 4 поля (`scenario_id`, `session_nonce`, `registry_hash`, `frozen_hash`) в методе `binds_identity` ([`src/verify_ng/sandbox_backend.rs:403-408`](file:///home/shleder/prod/vetto/src/verify_ng/sandbox_backend.rs#L403-L408)).
4. **Факт**: Доказательства `VerifiedControl` связываются с `ExecutionIdentity` через канал `HOST_CONTROL_CHANNEL` ([`src/verify_ng/evidence.rs:88-104`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L88-L104)), а оракул отбрасывает доказательства с несовпадающим `nonce` или `scenario_id` ([`src/verify_ng/oracle.rs:98-106`](file:///home/shleder/prod/vetto/src/verify_ng/oracle.rs#L98-L106)).
5. **Факт**: Все записи аудита `VettoAuditRecord` несут `contract_digest` и проверяются по хэш-цепочке SHA-256 ([`src/sandbox/production.rs:1111-1202`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L1111-L1202)).

#### 5.2. Допущения и точки приложения батарей Phase 2 (Extension Points)
1. **Допущение (C5 — Полнота мутаций полей контракта)**:
   - *Текущее состояние*: Тест `phase1_contract_tamper_rejected_before_spawn` ([`production.rs:2224-2313`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2224-L2313)) проверяет 4 конкретные мутации (`explicit_vars`, `timeout`, `allow_read`, `production: None`).
   - *Точка расширения Phase 2*: Необходимо реализовать полную матрицу мутаций всех категорий `SecurityContract` (сетевые порты/домены, лимиты pids/memory/cpu/fsize, пути маскирования `mask_paths`, флаги `cow_overlay`, `execution_root_ro`, аргументы вызова `invoked_args`, параметры аттестации), гарантируя, что любая точечная модификация вызывает немедленный отказ до вызова спавна.
2. **Допущение (C5 — Проверка на уровне счетчиков спавна)**:
   - *Текущее состояние*: Проверка блокировки спавна в существующих тестах проверяется по отсутствию маркерного файла `marker = tmp.join("child-started")`.
   - *Точка расширения Phase 2*: Рекомендуется дополнить проверку контролем глобального атомарного счетчика `PROD_SPAWN_COUNT` ([`src/sandbox/production.rs:79, 803`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L79)), доказывая, что счетчик ядра не увеличивается при подаче повреждённого контракта.
3. **Допущение (C5 — Кросс-исполнительная изоляция доказательств)**:
   - *Текущее состояние*: Оракул `oracle.rs` и `binds_identity` проверяют несовпадение идентичности на уровне структур данных.
   - *Точка расширения Phase 2*: Требуется интеграционный e2e-тест регрессии: генерация `Contract A / Execution A / Evidence A` и `Contract B / Execution B / Evidence B`, с явной проверкой того, что подстановка `Evidence A` в сессию `B` приводит к `Verdict::Inconclusive` / `FAIL` и блокировке перехода в `Terminal` с успехом.
