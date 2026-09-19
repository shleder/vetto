### Главный вердикт

Текущая система верификации Vetto архитектурно разорвана на три изолированных контура, ни один из которых не проверяет production execution против запечатанного [`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L65):
1. Команда `vetto verify` ([`src/verify.rs`](file:///home/shleder/prod/vetto/src/verify.rs#L113)) исполняет устаревший скриптовый probe, игнорируя [`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L65), и принимает решение исключительно по `SELF_REPORT` (stdout-строкам дочернего процесса).
2. Команда `vetto verify-ng` ([`src/verify_ng/mod.rs`](file:///home/shleder/prod/vetto/src/verify_ng/mod.rs#L44)) в CLI вообще не запускает сценарии (hardcoded fail-closed `Inconclusive` со статусом `HarnessUnavailable`), а библиотека [`src/verify_ng/runner.rs`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L765) структурно запрещает вердикт `PASS` для любых категорий, кроме `Category::Aux`.
3. Команда `vetto redteam` ([`src/redteam.rs`](file:///home/shleder/prod/vetto/src/redteam.rs#L50)) не создает песочницу вовсе: она исполняется в хостовом процессе супервизора и выдает фальшивые `PASS` на основе теоретических допущений о ядре.

Реальный production boundary ([`src/sandbox/production.rs`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L731)) потребляет [`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L65) и вычисляет [`ExecutionIdentity`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L52), но полностью изолирован от тестовых батарей verifier. Для Phase 2 требуется единое решение: подключить `verify_ng` к спавну через production-раннер с передачей запечатанного контракта, заблокировав любые альтернативные пути загрузки политик.

---

### Фактическая карта пайплайна выполнения

```
[CLI Entrypoint]
  vetto verify           → src/verify.rs:113            (LEGACY: raw Policy, no SecurityContract, SELF_REPORT)
  vetto verify-ng        → src/verify_ng/mod.rs:44      (STUB: no spawn, all Inconclusive, gate FAIL)
  vetto redteam          → src/redteam.rs:50            (MOCK: runs in supervisor process, no sandbox)
  vetto supervise / run  → src/main.rs:188              (PROD: production execution boundary)
         ↓
[Verification Orchestration]
  src/verify_ng/runner.rs:305 (run_one_with_backend)
  - Вход: ExecutionRequest (Policy, Target, Script, Sentinels)
  - Ограничение: принимает Policy, а НЕ SecurityContract (src/verify_ng/runner.rs:154)
         ↓
[Production Execution Authority]
  src/sandbox/production.rs:360 (freeze_production_contract)
  - Вход: sealed SecurityContract (BLAKE3 digest)
  - Проверка: contract.verify_digest() (src/sandbox/production.rs:368)
  - Сверка: compile_effective == contract (src/sandbox/production.rs:405)
  - Identity: ExecutionIdentity::new(scenario, session_nonce, "production", frozen_hash)
  - Заморозка: FrozenSpec.policy_bytes = CanonicalJSON({contract, digest})
         ↓
[Backend Lowering]
  src/verify_ng/sandbox_backend.rs:686 (LinuxBackend::prepare_with_context)
  src/sandbox/production.rs:442 (capability.prepare_with_context)
  - Преобразование FrozenSpec → CanonicalPolicy (src/verify_ng/sandbox_backend.rs:258)
  - Построение ChildEnforcementPlan (src/verify_ng/sandbox_backend.rs:454):
    * Landlock: exec_root (RW), extra_rw (FIFO dir RW), system_ro (/usr, /lib, etc. RO), rest DENIED
    * Seccomp: UnixOnly netblock (если net=off) + syscall hardening denylist (mount, ptrace, io_uring)
    * Rlimits: AS 256MB, NPROC 128, CPU 5s, FSIZE 64MB
    * Pgroup: new_pgroup = true
         ↓
[Actual OS Enforcement]
  src/verify_ng/linux_enforce.rs:75 (apply_child_plan_linux via Command::pre_exec)
  - PR_SET_NO_NEW_PRIVS = 1 (src/verify_ng/linux_enforce.rs:21)
  - setpgid(0, 0)
  - landlock_restrict_self
  - prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)
  - setrlimit(RLIMIT_AS, RLIMIT_NPROC, RLIMIT_CPU, RLIMIT_FSIZE)
         ↓
[Attacker Action]
  Скрипт атаки исполняется внутри confined child (staged run.sh в изолированном корне):
  - Попытки чтения/записи вне allowlist
  - Попытки сетевого коннекта (AF_INET/AF_PACKET)
  - Попытки обхода дерева процессов (fork, setsid, grandchild)
  - Попытки вызова запрещенных syscalls
         ↓
[Evidence Collection & Trust Levels]
  1. HOST_FACT (только это дает право на PASS):
     - wait-status: статус завершения ядра из try_wait / waitpid (src/verify_ng/runner.rs:731)
     - kill: факт срабатывания тайм-аута киллера (src/verify_ng/runner.rs:734)
     - sentinel: несовпадение SHA-256 трипвайров до/после (src/verify_ng/runner.rs:745)
     - /proc verification: Seccomp: 2, NoNewPrivs: 1, limits, pgroup из хостового /proc/<pid> (src/verify_ng/linux_enforce.rs:118)
     - tree sweep: сканирование /proc по nonce и зачистка сирот сабрипером (src/verify_ng/linux_enforce.rs:147)
     - control: challenge-response через хостовые FIFO (src/verify_ng/host_evidence.rs:73)
  2. CONSTRAINED:
     - Ограниченные сигналы ошибки (errno + nonce) через изолированный канал (src/verify_ng/evidence.rs:36). Дает FAIL, никогда PASS.
  3. SELF_REPORT (никогда не дает PASS):
     - child stdout / stderr (src/verify_ng/runner.rs:736-743)
     - маркерные файлы, созданные ребенком ($HOME/marker.txt, control.txt) (src/verify_ng/runner.rs:707)
         ↓
[Verdict Decision]
  1. Чистый оракул: src/verify_ng/oracle.rs:56 (judge):
     - Требует: !env_poisoned, payload_intact, !violation_observed, совпадение nonces,
       stdio_complete, control_observed, точное совпадение ExecutionIdentity,
       наличие HOST_FACT, выполнение кворума векторов.
  2. Потолок платформы: src/verify_ng/oracle.rs:121 (apply_strength_ceiling):
     - Unsupported → Inconclusive.
  3. Потолок бэкенда: src/verify_ng/sandbox_backend.rs:1724 (apply_backend_ceiling):
     - Если mandatory capabilities не Enforced/Verified → Inconclusive.
  4. Шлюз релиза / сьюта: src/verify_ng/exit.rs:70 (evaluate_gate):
     - Блокирует релиз при наличии Inconclusive/Fail в блокерах (I1-I6).
     - Требует обязательного PASS трех канареек: VFS-TRAV-001, ENV-LEAK-001, PROC-ESC-001.
     - Требует минимум по 1 PASS в каждой категории блокеров (FsRead, FsWrite, Net, Proc, Secrets, Spawn).
```

---

### Реестр существующих проверок (Stable ID и File:Line)

Чтобы исключить дублирование в батареях Phase 2, зафиксирован полный перечень существующих проверок:

#### 1. Устаревшие проверки [`src/verify.rs`](file:///home/shleder/prod/vetto/src/verify.rs)
- `deny-path`: [`src/verify.rs:330`](file:///home/shleder/prod/vetto/src/verify.rs#L330), [`src/verify.rs:336`](file:///home/shleder/prod/vetto/src/verify.rs#L336), [`src/verify.rs:340`](file:///home/shleder/prod/vetto/src/verify.rs#L340), [`src/verify.rs:341`](file:///home/shleder/prod/vetto/src/verify.rs#L341) (проверка доступности путей deny_resolved через stdout-маркеры).
- `net-loopback`: [`src/verify.rs:361`](file:///home/shleder/prod/vetto/src/verify.rs#L361), [`src/verify.rs:362`](file:///home/shleder/prod/vetto/src/verify.rs#L362), [`src/verify.rs:366`](file:///home/shleder/prod/vetto/src/verify.rs#L366) (проверка коннекта к хостовому loopback-листенеру).
- `write-outside`: [`src/verify.rs:370`](file:///home/shleder/prod/vetto/src/verify.rs#L370), [`src/verify.rs:374`](file:///home/shleder/prod/vetto/src/verify.rs#L374) (проверка записи за пределы allow_write корней).
- `probe-stderr`: [`src/verify.rs:283`](file:///home/shleder/prod/vetto/src/verify.rs#L283) (захват stderr зонда как info).
- `backend`: [`src/verify.rs:173`](file:///home/shleder/prod/vetto/src/verify.rs#L173) (маркер недоступности бэкенда для префлайта).

#### 2. Проверки [`src/redteam.rs`](file:///home/shleder/prod/vetto/src/redteam.rs) (ID 1..8)
- `setsid_daemon_escape` (ID 1): [`src/redteam.rs:85`](file:///home/shleder/prod/vetto/src/redteam.rs#L85) (проверка subreaper/pidns в текущем процессе).
- `memfd_create_fexecve` (ID 2): [`src/redteam.rs:131`](file:///home/shleder/prod/vetto/src/redteam.rs#L131) (вызов SYS_memfd_create).
- `proc_self_mem_write` (ID 3): [`src/redteam.rs:174`](file:///home/shleder/prod/vetto/src/redteam.rs#L174) (попытка open /proc/self/mem на запись).
- `proc_1_ns_mnt_escape` (ID 4): [`src/redteam.rs:212`](file:///home/shleder/prod/vetto/src/redteam.rs#L212) (попытка open /proc/1/ns/mnt).
- `raw_socket_packet` (ID 5): [`src/redteam.rs:249`](file:///home/shleder/prod/vetto/src/redteam.rs#L249) (создание AF_PACKET / AF_INET SOCK_RAW).
- `memory_limit_exceed` (ID 6): [`src/redteam.rs:294`](file:///home/shleder/prod/vetto/src/redteam.rs#L294) (проверка RLIMIT_AS через getrlimit).
- `pids_limit_exceed` (ID 7): [`src/redteam.rs:332`](file:///home/shleder/prod/vetto/src/redteam.rs#L332) (проверка RLIMIT_NPROC через getrlimit).
- `restricted_dev_open` (ID 8): [`src/redteam.rs:370`](file:///home/shleder/prod/vetto/src/redteam.rs#L370) (попытка open /dev/kmsg и /dev/mem).

#### 3. Сценарии реестра [`src/verify_ng/registry.rs`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L118)
- `ORACLE-DECEIT-001`: [`src/verify_ng/registry.rs:120`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L120) (Aux, Blocker, отказ от PASS на self-report).
- `CONTROL-SPLIT-001`: [`src/verify_ng/registry.rs:132`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L132) (Aux, Blocker, проверка nonce binding пары control/probe).
- `FIXTURE-MUTATE-001`: [`src/verify_ng/registry.rs:142`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L142) (Aux, High, детекция мутации пейлоада).
- `ENV-POISON-001`: [`src/verify_ng/registry.rs:154`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L154) (Spawn, Blocker, FAIL при наличии диагностического env).
- `GATE-VACUUM-001`: [`src/verify_ng/registry.rs:168`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L168) (Aux, High, невозможность сдачи пустого сьюта).
- `HANG-GRANDCHILD-001`: [`src/verify_ng/registry.rs:179`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L179) (Proc, High, зависание внучатого процесса и сбор stdio).
- `VFS-TRAV-001`: [`src/verify_ng/registry.rs:195`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L195) (FsRead, Blocker, CANARY: обход путей, symlink/dotdot).
- `NET-DNS-IPV6-001`: [`src/verify_ng/registry.rs:211`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L211) (Net, Blocker, изоляция --net=off).
- `PROC-ESC-001`: [`src/verify_ng/registry.rs:227`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L227) (Proc, Blocker, CANARY: setsid/escape дерева процессов).
- `ENV-LEAK-001`: [`src/verify_ng/registry.rs:243`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L243) (Secrets, Blocker, CANARY: утечка переменных окружения).
- `RACE-BINDING-001`: [`src/verify_ng/registry.rs:258`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L258) (Spawn, Blocker, стабильность привязки FrozenSpec).
- `CLEANUP-SIGKILL-001`: [`src/verify_ng/registry.rs:269`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L269) (Proc, High, зачистка после SIGKILL).
- `EVIDENCE-REDACT-001`: [`src/verify_ng/registry.rs:285`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L285) (Aux, High, маскирование секретов в отчетах).
- `MAC-SHAPE-001`: [`src/verify_ng/registry.rs:296`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L296) (FsRead, High, проверка байтового профиля macOS Seatbelt).
- `WIN-UNC-001`: [`src/verify_ng/registry.rs:307`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L307) (FsRead, High, Windows UNC пути).
- `WIN-WSL-001`: [`src/verify_ng/registry.rs:318`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L318) (FsRead, High, WSL interop — базово UNSUPPORTED).

#### 4. Не скомпилированные TOML-сценарии в [`tests/verify_ng/scenarios/`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios)
Существуют как спецификации, но отсутствуют в функции `registry()`:
- [`VFS-WRITE-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/VFS-WRITE-001.toml) (fs-write, blocker)
- [`VFS-PROC-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/VFS-PROC-001.toml) (fs-read, blocker)
- [`NET-EXFIL-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/NET-EXFIL-001.toml) (net, blocker)
- [`SHELL-ESC-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/SHELL-ESC-001.toml) (spawn, blocker)
- [`ENV-SECRETS-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/ENV-SECRETS-001.toml) (secrets, blocker)
- [`PROC-TREE-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/PROC-TREE-001.toml) (proc, blocker)
- [`RACE-TOCTOU-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/RACE-TOCTOU-001.toml) (spawn, blocker)
- [`SEC-BLOCKS-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/SEC-BLOCKS-001.toml) (spawn, blocker)
- [`RES-EXHAUST-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/RES-EXHAUST-001.toml) (proc, high)
- [`STRESS-SWEEP-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/STRESS-SWEEP-001.toml) (proc, high)
- [`FUZZ-CORPUS-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/FUZZ-CORPUS-001.toml) (spawn, high)
- [`TIER-DIFF-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/TIER-DIFF-001.toml) (spawn, high)
- [`WIN-ESC-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/WIN-ESC-001.toml) (proc, blocker)
- [`WIN-NET-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/WIN-NET-001.toml) (net, blocker)
- [`MAC-ESC-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/MAC-ESC-001.toml) (fs-read, high)
- [`MAC-PROC-001.toml`](file:///home/shleder/prod/vetto/tests/verify_ng/scenarios/MAC-PROC-001.toml) (proc, high)

#### 5. Тесты реального принуждения Linux в [`tests/integration/verify_ng_linux_enforce.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs)
- `test_linux_fs_read_deny_001`: [L191](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L191) (чтение запрещенного файла блокируется Landlock)
- `test_linux_fs_write_deny_001`: [L226](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L226) (запись в запрещенный файл блокируется Landlock)
- `test_linux_fs_escape_001`: [L256](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L256) (попытка побега через symlink блокируется)
- `test_linux_fs_root_isolation_001`: [L291](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L291) (изоляция системных корней и корня выполнения)
- `test_linux_net_deny_001`: [L338](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L338) (блокировка TCP сокетов в net=off seccomp)
- `test_linux_net_escape_001`: [L371](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L371) (блокировка raw/udp побегов)
- `test_linux_net_allow_001`: [L405](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L405) (разрешение AF_UNIX сокетов)
- `test_linux_proc_escape_001`: [L436](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L436) (изоляция дерева процессов и проверка pgroup)
- `test_linux_grandchild_001`: [L470](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L470) (перехват setsid-внуков subreaper'ом)
- `test_linux_tree_kill_001`: [L506](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L506) (уничтожение всей группы процессов при таймауте)
- `test_linux_orphan_001`: [L539](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L539) (зачистка сирот по session nonce)
- `test_linux_mem_limit_001`: [L577](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L577) (принуждение RLIMIT_AS)
- `test_linux_pid_limit_001`: [L611](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L611) (принуждение RLIMIT_NPROC)
- `test_linux_cpu_limit_001`: [L684](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L684) (принуждение RLIMIT_CPU)
- `test_linux_syscall_deny_001`: [L735](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L735) (блокировка ptrace via seccomp)
- `test_linux_syscall_escape_001`: [L770](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L770) (блокировка mount/io_uring via seccomp)
- `test_linux_priv_escape_001`: [L820](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L820) (блокировка эскалации привилегий)
- `test_linux_no_new_privs_001`: [L886](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L886) (проверка бита NoNewPrivs в /proc/<pid>/status)
- `test_linux_fail_closed_001`: [L925](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L925) (fail-closed при сбое подготовки бэкенда)
- `test_linux_partial_enforcement_001`: [L957](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L957) (отсутствие неполного применения)
- `test_linux_fake_enforcement_001`: [L1005](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L1005) (запрет фиктивных утверждений о защите)
- `test_linux_escape_fs_001`: [L1027](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L1027) (атака побега из ФС: dotdot и /proc)
- `test_linux_escape_net_001`: [L1063](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L1063) (атака побега из сети через raw sockets)
- `test_linux_escape_proc_001`: [L1097](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L1097) (атака через setsid + fork)
- `test_linux_escape_priv_001`: [L1131](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L1131) (атака через setuid/capabilities)
- `test_linux_escape_syscall_001`: [L1161](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L1161) (атака через обход seccomp фильтра)
- `test_linux_escape_root_001`: [L1207](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L1207) (атака выхода в /)
- `test_linux_escape_grandchild_001`: [L1259](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L1259) (атака глубоко вложенного процесса)
- `test_linux_identity_bound_001`: [L1299](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L1299) (привязка отчета к ExecutionIdentity)
- `test_linux_policy_stable_001`: [L1325](file:///home/shleder/prod/vetto/tests/integration/verify_ng_linux_enforce.rs#L1325) (неизменность политики во время исполнения)

#### 6. Проверки раннера и леджера в [`tests/integration/verify_ng_execution.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_execution.rs)
- `TEST-ENGINE-001` (`test_engine_001_successful_child`): [L86](file:///home/shleder/prod/vetto/tests/integration/verify_ng_execution.rs#L86) (сбор stdio, exit code, отсутствие PASS на direct)
- `TEST-ENGINE-002` (`test_engine_002_deadline_kills`): [L134](file:///home/shleder/prod/vetto/tests/integration/verify_ng_execution.rs#L134) (принудительное завершение по дедлайну)
- `TEST-ENGINE-003` (`test_engine_003_attacker_stdout_is_not_host_fact`): [L173](file:///home/shleder/prod/vetto/tests/integration/verify_ng_execution.rs#L173) (stdout не попадает в HOST_FACT)
- `TEST-ENGINE-004` (`test_engine_004_single_spawn_per_scenario`): [L208](file:///home/shleder/prod/vetto/tests/integration/verify_ng_execution.rs#L208) (ровно 1 спавн на сценарий)
- `TEST-ENGINE-005` (`test_engine_005_fixture_mutation_fails`): [L223](file:///home/shleder/prod/vetto/tests/integration/verify_ng_execution.rs#L223) (мутация трипвайра дает FAIL)
- `TEST-ENGINE-006` (`test_engine_006_home_distinctness`): [L248](file:///home/shleder/prod/vetto/tests/integration/verify_ng_execution.rs#L248) (уникальность $HOME на каждый запуск)
- `TEST-CONTROL-SPLIT-001` (`test_control_split_001_forged_control_cannot_pass`): [L304](file:///home/shleder/prod/vetto/tests/integration/verify_ng_execution.rs#L304) (подделка control.txt не дает PASS)
- `TEST-COLLECTOR-COMPLETENESS-001` (`test_collector_completeness_001_incomplete_cannot_pass`): [L349](file:///home/shleder/prod/vetto/tests/integration/verify_ng_execution.rs#L349) (неполный stdio drain дает Inconclusive)
- `TEST-SPAWN-LEDGER-001` (`test_spawn_ledger_001_duplicate_execution_rejected`): [L422](file:///home/shleder/prod/vetto/tests/integration/verify_ng_execution.rs#L422) (отклонение повторного запуска сценария в SuiteRunner)

#### 7. Доказательства хоста в [`tests/integration/verify_ng_host_evidence.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs)
- `TEST-HOST-CONTROL-POSITIVE-001`: [L122](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs#L122) (валидный ответ на challenge дает PASS в Aux)
- `CONTROL-SPLIT-001`: [L183](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs#L183) (проверка легитимного канала)
- `TEST-HOST-CONTROL-ECHO-001`: [L210](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs#L210) (эхо challenge без ротации дает Inconclusive)
- `TEST-HOST-CONTROL-SELF-AUTH-001`: [L248](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs#L248) (копирование значений env не авторизует)
- `TEST-HOST-CONTROL-FORGE-001`: [L301](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs#L301) (поддельные токены во всех медиа отвергаются)
- `TEST-HOST-CONTROL-DUPLICATE-001`: [L347](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs#L347) (повтор/конкатенация ответа отвергается)
- `TEST-HOST-EVIDENCE-REPLAY-001`: [L381](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs#L381) (cross-session replay отвергается)
- `TEST-HOST-CONTROL-WRONG-SCENARIO-001`: [L452](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs#L452) (evidence от другого сценария отвергается)
- `TEST-HOST-CONTROL-WRONG-REGISTRY-001`: [L493](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs#L493) (evidence от другого реестра/frozen отвергается)
- `TEST-HOST-CONTROL-VIOLATION-001`: [L547](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs#L547) (нарушение границы доминирует над корректным ответом)
- `TEST-HOST-CONTROL-BLOCKER-001`: [L577](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs#L577) (блокеры на direct backend всегда Inconclusive)
- `test_host_control_attest_boundary_shapes`: [L611](file:///home/shleder/prod/vetto/tests/integration/verify_ng_host_evidence.rs#L611) (юнит-проверка функции attest_control)

#### 8. Ловушки оракула и шлюза в [`tests/integration/verify_ng_traps.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs)
- `trap_oracle_deceit_self_report_only_is_not_pass`: [L106](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L106)
- `trap_control_split_missing_probe_nonce_is_inconclusive`: [L121](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L121)
- `trap_control_split_nonce_mismatch_is_inconclusive`: [L131](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L131)
- `trap_fixture_mutation_is_detected`: [L141](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L141)
- `trap_env_poison_fails_blockers`: [L160](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L160)
- `trap_gate_vacuum_empty_suite_fails`: [L175](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L175)
- `trap_gate_all_na_fails_without_canaries`: [L183](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L183)
- `trap_evidence_redaction_holds`: [L203](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L203)
- `trap_spec_continuity_detects_drift`: [L214](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L214)
- `trap_unsupported_ceiling_demotes_pass`: [L238](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L238)
- `trap_report_carries_both_axes`: [L246](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L246)
- `cli_verify_ng_lint_passes`: [L271](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L271)
- `cli_verify_ng_lint_json_parseable`: [L285](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L285)
- `cli_verify_ng_without_suite_never_passes`: [L306](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L306)
- `caps_missing_requires_evidence_shape`: [L323](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L323)
- `trap_quorum_shape_multivector_needs_agreeing_vectors`: [L340](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L340)
- `trap_quorum_one_single_vector_passes`: [L368](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L368)
- `trap_platform_ceiling_shapes`: [L389](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L389)
- `trap_gate_requires_fs_write_minimum`: [L420](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L420)
- `trap_host_violation_beats_self_report_new_suites`: [L461](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L461)
- `trap_payload_mutation_invalidates_new_suites`: [L489](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L489)
- `trap_env_poison_fails_new_blockers`: [L514](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L514)
- `TEST-FROZEN-IDENTITY-001` (`test_frozen_identity_001_registry_hash_binds_semantics`): [L541](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L541)
- `TEST-GATE-STRENGTH-001` (`test_gate_strength_001_machine_distinguishes_strength`): [L625](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L625)

#### 9. Архитектурные тесты в [`tests/integration/verify_ng_backend_arch.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_backend_arch.rs)
- `TEST-BACKEND-CAPABILITY-001`: [L57](file:///home/shleder/prod/vetto/tests/integration/verify_ng_backend_arch.rs#L57) (явный отчет о возможностях бэкенда)
- `TEST-BACKEND-UNSUPPORTED-001`: [L162](file:///home/shleder/prod/vetto/tests/integration/verify_ng_backend_arch.rs#L162) (неподдерживаемый блокер не может дать PASS)
- `TEST-BACKEND-POLICY-001`: [L190](file:///home/shleder/prod/vetto/tests/integration/verify_ng_backend_arch.rs#L190) (CanonicalPolicy проходит границу без мутаций)
- `TEST-BACKEND-IDENTITY-001`: [L219](file:///home/shleder/prod/vetto/tests/integration/verify_ng_backend_arch.rs#L219) (привязка отчета раннера к ExecutionIdentity)
- `TEST-BACKEND-FAIL-CLOSED-001`: [L258](file:///home/shleder/prod/vetto/tests/integration/verify_ng_backend_arch.rs#L258) (отказ подготовки запрещает спавн)
- `TEST-BACKEND-NO-FAKE-ENFORCEMENT-001`: [L341](file:///home/shleder/prod/vetto/tests/integration/verify_ng_backend_arch.rs#L341) (Unsupported никогда не становится Enforced)
- `TEST-BACKEND-ORACLE-PURITY-001`: [L451](file:///home/shleder/prod/vetto/tests/integration/verify_ng_backend_arch.rs#L451) (чистота и детерминированность оракула)

#### 10. Фаза 1 регрессионные тесты авторитета контракта в [`src/sandbox/production.rs`](file:///home/shleder/prod/vetto/src/sandbox/production.rs)
- `phase1_production_preparation_receives_sealed_contract`: [L2021](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2021)
- `phase1_invalid_contract_never_prepares_capabilities`: [L2108](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2108)
- `phase1_contract_tamper_rejected_before_spawn`: [L2224](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2224)
- `phase1_caller_policy_cannot_change_canonical_backend_input`: [L2317](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2317)
- `phase1_production_audit_binds_actual_contract`: [L2380](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L2380)

#### 11. Интеграционные тесты изоляции в [`tests/integration/adv_isolation.rs`](file:///home/shleder/prod/vetto/tests/integration/adv_isolation.rs)
- `adv_dotdot_escape_of_allow_root_is_denied`: [L52](file:///home/shleder/prod/vetto/tests/integration/adv_isolation.rs#L52)
- `adv_dotdot_evasion_of_deny_is_still_denied`: [L73](file:///home/shleder/prod/vetto/tests/integration/adv_isolation.rs#L73)
- `adv_slash_confusables_stay_denied`: [L100](file:///home/shleder/prod/vetto/tests/integration/adv_isolation.rs#L100)
- `adv_symlink_parent_escape_is_denied`: [L123](file:///home/shleder/prod/vetto/tests/integration/adv_isolation.rs#L123)
- `adv_case_variant_is_not_confused`: [L152](file:///home/shleder/prod/vetto/tests/integration/adv_isolation.rs#L152)
- `adv_proxy_secrets_stripped_but_neighbors_kept`: [L171](file:///home/shleder/prod/vetto/tests/integration/adv_isolation.rs#L171)
- `adv_proxy_beats_explicit_passthrough`: [L184](file:///home/shleder/prod/vetto/tests/integration/adv_isolation.rs#L184)
- `adv_proxy_env_extra_merge_must_be_restripped`: [L205](file:///home/shleder/prod/vetto/tests/integration/adv_isolation.rs#L205)
- `adv_broker_domain_allowlist_fail_closed`: [L221](file:///home/shleder/prod/vetto/tests/integration/adv_isolation.rs#L221)
- `adv_snapshot_list_missing_root_is_empty_not_error`: [L234](file:///home/shleder/prod/vetto/tests/integration/adv_isolation.rs#L234)
- `adv_snapshot_list_skips_partial_and_corrupt`: [L243](file:///home/shleder/prod/vetto/tests/integration/adv_isolation.rs#L243)
- `adv_snapshot_list_concurrent_with_churn_never_lies`: [L264](file:///home/shleder/prod/vetto/tests/integration/adv_isolation.rs#L264)

---

### Точки шлюзования пустого и неполного сьютов

Шлюзование выполняется исключительно функцией [`evaluate_gate`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L70) в [`src/verify_ng/exit.rs`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs):

1. **Пустой сьют (Empty Suite / `GATE-VACUUM-001`)**:
   - [`src/verify_ng/exit.rs:124-130`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L124-L130): Проверка канареек [`CANARY_IDS`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L22) (`VFS-TRAV-001`, `ENV-LEAK-001`, `PROC-ESC-001`). Если массив результатов пуст, для каждой канарейки генерируется блокер `canary-missing`.
   - [`src/verify_ng/exit.rs:133-139`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L133-L139): Проверка квот категорий [`min_pass_per_category`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L25). Требуется минимум по 1 `PASS` для `FsRead`, `FsWrite`, `Net`, `Proc`, `Secrets`, `Spawn`. Для пустого сьюта генерируются блокеры `<category>:only-0-pass-min-1`.
   - Итог: статус шлюза становится `"failed"`, а `gate_exit_code` возвращает `1` ([`src/verify_ng/exit.rs:175-179`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L175-L179)).
2. **Неполный сьют (Incomplete Suite / Missing Category)**:
   - Пропуск любой из 6 категорий блокирует шлюз правилом [`min_pass_per_category`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L25) (например, отсутствие `PASS` по `fs-write` блокирует релиз через `fs-write:only-0-pass-min-1`, тест [`trap_gate_requires_fs_write_minimum`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs#L420)).
   - Любой вердикт `Inconclusive` в категориях I1–I6 (блокере) инициирует `r.blocks_release() == true` ([`src/verify_ng/model.rs:118`](file:///home/shleder/prod/vetto/src/verify_ng/model.rs#L118)) и попадает в `blocking` список.
   - Любой вердикт `NotApplicable` без подтвержденных хостовых доказательств (`na_evidence`) генерирует блокер `<id>:N/A-without-evidence` ([`src/verify_ng/exit.rs:116`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L116)).
   - Любой `PASS` на сценарии со статическим потолком `ClaimStrength::Unsupported` генерирует блокер `<id>:unsupported-pass` ([`src/verify_ng/exit.rs:147`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L147)).

---

### Подтвержденные факты против допущений

#### Подтвержденные факты (Verified Facts)
1. [`src/verify.rs`](file:///home/shleder/prod/vetto/src/verify.rs#L130-L131) принимает сырой `Policy`, компилирует скрипт зонда и судит об утечках по парсингу текстовых строк stdout (`D|...`, `F|...`, `NET|...`, `WRITE|...`), что является чистым `SELF_REPORT`. Привязка к [`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L65) полностью отсутствует.
2. Команда `vetto verify-ng` ([`src/verify_ng/mod.rs:44-124`](file:///home/shleder/prod/vetto/src/verify_ng/mod.rs#L44-L124)) в CLI при запуске без `--lint` не запускает никаких дочерних процессов, принудительно возвращает `Inconclusive` для всех сценариев и завершается с кодом ошибки 125.
3. Раннер [`src/verify_ng/runner.rs:765`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L765) содержит жесткое условие:
   ```rust
   let pass_capable = req.enable_host_control && req.scenario.category == Category::Aux;
   ```
   Это делает `PASS` структурно недостижимым для блокер-категорий (`FsRead`, `FsWrite`, `Net`, `Proc`, `Secrets`, `Spawn`) при выполнении через `run_one`.
4. В [`src/verify_ng/registry.rs:118-328`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L118-L328) жестко закодировано ровно 16 сценариев. Еще 10 сценариев лежат в файлах `tests/verify_ng/scenarios/*.toml`, но в функции `registry()` отсутствуют.
5. Модуль [`src/redteam.rs`](file:///home/shleder/prod/vetto/src/redteam.rs#L50-L419) проверяет векторы побега внутри самого супервизора и засчитывает `PASS` на основе теоретических комментариев (например, [L157](file:///home/shleder/prod/vetto/src/redteam.rs#L157): «memfd_create accessible but fexecve/execveat subject to seccomp/Landlock»).
6. Архитектура Phase 1 в [`src/sandbox/production.rs:360-450`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L360-L450) полностью валидирует запечатанный [`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L65) с BLAKE3-дайджестом, формирует [`ExecutionIdentity`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L52) и гарантирует fail-closed отказ спавна при нарушении целостности.

#### Допущения (Assumptions)
1. *Допущение о дизайне Phase 2*: Предполагается, что в Phase 2 запуск верификационных батарей должен быть объединен с механизмом [`PreparedProductionExecution`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L643), чтобы сценарии исполнялись строго через запечатанный [`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L65), а не через синтетический `ExecutionRequest(Policy)`.
2. *Допущение о TOML-файлах*: Предполагается, что 10 сценариев из `tests/verify_ng/scenarios/*.toml` (включая критический блокер `VFS-WRITE-001`) должны быть перенесены в `registry()`, как только соответствующие батареи будут способны подтверждать их через `HOST_FACT` в production-раннере.

---

### Риски и конкретные шаги для последующих батарей (C1–C7)

1. **Главный архитектурный риск**: Создание второй логики проверки политик. Нельзя реализовывать валидацию `SecurityContract` внутри `verify_ng` отдельно от `src/sandbox/production.rs`. 
   - *Действие*: Батареи должны использовать [`PreparedProductionExecution::spawn`](file:///home/shleder/prod/vetto/src/sandbox/production.rs#L731), получая `EnforcementReport` и привязывая `ExecutionIdentity` напрямую к дайджесту запечатанного контракта.
2. **Риск фиктивного прохождения (Fake PASS)**: Текущий оракул дает `PASS` только при наличии `VerifiedControl` от challenge-response протокола. Если атака блокируется ядром (например, Landlock вернул `EACCES`), атакующий пейлоад не доходит до отсылки challenge.
   - *Действие*: Для негативных проб подтверждением ненарушения границы должен служить независимый `HOST_FACT` (статус завершения с ошибкой от ядра, интактность сенсоров-трипвайров, записи из `/proc/<pid>/status`), а не отсылка данных дочерним процессом.
3. **Блокировка `VFS-WRITE-001`**: Категория `fs-write` сейчас не имеет ни одного сценария в `registry()`, из-за чего любой строгий запуск шлюза завершится с `only-0-pass-min-1`.
   - *Действие сабагенту C1*: Включить `VFS-WRITE-001` в [`src/verify_ng/registry.rs`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs) с `quorum: 2` и привязать его проверку к хостовым трипвайрам.
4. **Недопустимость дублирования**: Ни в коем случае не создавать альтернативных проверок для `VFS-TRAV-001`, `ENV-LEAK-001` и `PROC-ESC-001`. Расширять строго существующие сценарии и каналы сбора фактов.
