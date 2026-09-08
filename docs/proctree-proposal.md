# Process-Tree Containment + Guaranteed Cleanup — Architecture Proposal (Prompt 05)

Статус: proposal, НЕ production-код. Ничего из нижеописанного не реализовано.
Скоуп: `src/sandbox/{handle.rs,linux/proctrack.rs,macOS/pdeath_watch.rs,windows/job_object.rs}`
+ связанные модули. `src/verify_ng/` — чужой скоуп, не трогаем.

## 1. Current process lifecycle (как есть сейчас)

### Linux FULL (`src/sandbox/linux/mod.rs`: `spawn_full`, `child_full`, `child_b`)

```text
vetto (host ns, держит alive_w)
└─ S (USER+MOUNT+IPC+NET ns; alive_r; err pipe)
   ├─ R (relay, только allowlist/strict; вне pidns, вне Landlock)
   └─ B (PID 1 нового pidns; PDEATHSIG; приватный /proc; Landlock; seccomp)
      └─ C (agent; PDEATHSIG+getppid-check; seccomp; execve; пишет 'R')
```

Teardown FULL: `KillStrategy::PidNsPipe` (`src/sandbox/handle.rs:45-49`) —
drop `alive_w` → EOF на `alive_r` → B делает `kill(-1, SIGKILL)` внутри pidns,
затем reaps всех. Crash-resilience ядра: смерть vetto = EOF = тот же путь.
B также ловит смерть C (`waitpid(-1)`) и убивает ns. Зомби жнёт B как PID 1.
Оценка: Strong.

### Linux FS-ONLY / Seccomp (`spawn_fs_only`, `spawn_seccomp_only`)

Один fork, child = agent. `setpgid(0,0)` (или `setsid` в PTY), Landlock,
seccomp, PDEATHSIG + getppid-check. Teardown (`handle.rs:175-195`):
`kill(-pgid)` + `kill(pid)` + `proctrack::sweep_reparented` (только Linux,
`sweep=true`). Перед fork — `set_subreaper` (`src/multi/isolation.rs:154`),
после fork — `arm_exit_sweep` (atexit, т.к. `supervise` выходит через
`std::process::exit`, `Drop` не бежит; `proctrack.rs:41-70`). Стрипы 360°:
утечка сабреапера, выход из асьминхронного окна, выполнение вне peload-sweep.
Оценка: Partial/best-effort, честно задокументировано в коде.

### macOS (`src/sandbox/macos/mod.rs`, `pdeath_watch.rs`)

Один fork, `setpgid(0,0)`, Seatbelt, execve. Teardown:
`KillStrategy::ProcessGroup{pid,pgid,sweep:false}` — только `kill(-pgid)` +
`kill(pid)`. `sweep=false` явно. Плюс `pdeath_watch::spawn` из родителя:
kqueue NOTE_EXIT на vetto → SIGKILL агента (закрывает «vetto SIGKILLed»
окно; grandchildren НЕ покрыты). Оценка: Partial.

### Windows (`src/sandbox/windows/mod.rs`, `job_object.rs`)

`Experimental_CreateProcessInSandbox` с `CREATE_SUSPENDED` →
`create_kill_on_close_job` → `AssignProcessToJobObject` →
`ResumeThread`. Teardown: drop job (kill-on-close) + drop process handle
(`handle.rs:196-203`). `job_object.rs:104-106` — `KILL_ON_JOB_CLOSE |
DIE_ON_UNHANDLED_EXCEPTION`, breakaway явно не разрешён (комментарий).
`terminate()` вызывается из `Drop`, `wait_with_timeout` (`main.rs:1512`),
TUI-quit, verify_ng killer. Оценка: Strong при условии, что assignment
успел до ResumeThread (выполняется: suspended → assign → resume — правильно).

### Timeout/supervision (`src/main.rs`)

`wait_with_timeout` (`main.rs:1512-1536`): только `--tui=none`; TUI-режимы
таймаут игнорируют (предупреждение `main.rs:1216-1223`). Немедленный
`terminate()` по дедлайну, без graceful-фазы. `install_sigint_forwarder`
(`main.rs:1704`): SIGINT/SIGTERM → forward (FS-ONLY: всей группе). Ctrl+C в
TUI: `p` = pause, `q`+`y` = terminate. Daemon (`src/daemon/registry.rs:137`):
`stop_session` = `child.kill()` + `wait()` на vetto-child (не на дерево
напрямую; дерево чистит teardown самого vetto — ок для FULL/Job, best-effort
иначе). `vetto kill` (`src/cli/kill.rs:33-89`): SIGTERM → 2с → SIGKILL,
по группе с fallback на pid.

## 2. Threat model

Агент = произвольный код от uid пользователя внутри sandbox. Цели агента:
пережить termination boundary (double-fork, `setsid`, daemonize,
` KillStrategy::ProcessGroup`,
nohup/`&`, at/cron/systemd --user, сокет/файл как якорь, respawn по таймеру,
рождение ребёнка после смерти родителя, fork-bomb как DoS на sweep).
Граница доверия: ядро/ОС — доверены; vetto-родитель — доверен, но убиваем
(SIGKILL); всё внутри sandbox — враждебно. Non-goals (из threat-model.md):
враждебное ядро, root, другой uid, prompt-injection внутри разрешённого,
записи в разрешённый `$PROJECT`, side-channels.

Приоритет gaps по exploitability × impact:
1. FS-ONLY/macOS setsid-grandchild вне sweep-бюджета — детерминированный escape.
2. Supervisor-crash + delayed/respawn child (cron/at/systemd --user вне pidns;
   Job вне job; macOS вне группы).
3. Creation race (assign после первого исполнения) — частично есть на Windows,
   нет на Unix (нет раннего ownership вообще).
4. False-positive cleanup checks (ниже §12).
5. Resource-exhaustion как containment-атака (fork-bomb против sweep/observer).

## 3. Security invariants

- **I1 Termination closure.** Ни один процесс session не переживает
  termination boundary в неконтролируемом состоянии. Strong tier: доказывается
  ядром/Job; best-effort tier: утверждается только после успешной
  post-cleanup assertion (§10), иначе — FAIL с явным residual.
- **I2 Early ownership.** Владение потомком формируется до его первой
  исполняемой инструкции (suspended-create+assign; pidns-fork; seccomp при
  рождении невозможен — фиксировать как Unsupported и компенсировать).
- **I3 Descendant closure.** Владение транзитивно: ребёнок владельца —
  владелец. Механизм обязан покрывать внуков без их кооперации.
- **I4 Crash resilience.** Смерть супервизора в любой точке обязана вести к
  смерти дерева без кода супервизора (kernel/Job-alive-pipe/watchdog).
- **I5 Cleanup authority.** Единственный владелец teardown — держатель
  `SandboxHandle` (как уже в verify_ng/killer.rs: single-owner); `Drop` =
  terminate; путь `std::process::exit` обязан иметь atexit-эквивалент.
- **I6 No false-clean.** Cleanup успешен только при доказанном отсутствии
  session-owned descendants (pidns-empty / job-empty / orphan-scan-empty +
  cgroup-empty). Пустой `waitpid(root)` ≠ чистое дерево.
- **I7 Fail-closed degradation.** Потеря примитива (subreaper prctl, kqueue,
  cgroup mount) — громкий warn + понижение tier, никогда молча.

## 4. Process ownership model

Владелец = (session_id, механизм, граница). Граница Strong: pidns (Linux
FULL), Job (Windows). Граница best-effort: pgid + subreaper-adoption
(FS-ONLY), pgid + watchdog (macOS). Потомок принадлежит сессии, если создан
внутри границы после её установки. FS-ONLY/macOS: принадлежность потомка,
рождённого между fork и установкой фильтров, недоказуема — окно фиксируется
как residual, а не игнорируется. Передача владения (daemon `stop_session`,
`vetto kill`) — только через владельца handle, не через сырой pid (сегодня
`kill.rs` шлёт сигналы по pid — gap, см. §12 п.6).

## 5. Process creation protocol

Требуемый порядок (target state):
1. Создать границу ДО первой инструкции: pidns-fork / suspended+assign /
   pgid+subreaper-arm.
2. Запретить исполнение до готовности границы: Windows `CREATE_SUSPENDED` —
   Strong (уже есть); Unix fork не даёт suspended — компенсировать
   PDEATHSIG+getppid-check ДО unshare/mount (уже) + fail-closed setup pipe
   с таймаутом (уже, 30с) + никогда не возвращать handle до байта 'R' (уже).
3. Агент исполняется только после irreversible фильтров (seccomp/Landlock/
   Seatbelt) — уже.
4. Handle возвращается только после readiness; любой сбой — kill_and_reap,
   не leak.

## 6. Linux design

**Strict (FULL) — Strong, уже есть, держать:**
pidns + B(PID 1, reaper, alive-pipe) + PDEATHSIG + kill(-1) + cgroup.kill.
Добавить (proposal): pidfd на B/S для точного ожидания без PID-reuse
(`pidfd_open` + `poll`), `cgroup.kill` как второй kill-путь в
`CgroupHandle::cleanup` уже частично есть — поднять до обязательного шага
state machine; `SO_PEERCRED`-проверки не нужны.

**FS-ONLY/Seccomp — Partial, потолок без pidns:**
subreaper + kill(-pgid) + bounded sweep — текущий дизайн верный, но:
(a) sweep-бюджет 2с и один проход — поднять до многоитерационного с
эскалацией и финальной assertion (§10); (b) subreaper-fail сегодня только
warn — добавить явное понижение assurance в отчёт/doctor; (c) cgroup
(`pids.max` + `cgroup.kill`/`cgroup.procs` freeze) — поднять из
best-effort-опции в обязательный второй рубеж, когда иерархия доступна;
(d) `RLIMIT_NPROC` уже ставится pre-exec и наследуется — держать как
anti-fork-bomb рубеж, задокументировать связку со sweep-бюджетом.
Запрет `setsid/setpgid/daemon` через seccomp — **Unsupported**: ломает
штатные рантаймы (shell job-control, setsid в PTY-пути самого vetto),
фильтр неотличит «плохой» setsid от легитимного; containment обязан быть
механическим ( adoption+sweep), а не запретительным. Фиксируем как осознанный
отказ.

**Примитивы:** strict = pidns + alive-pipe + B-reaper + pidfd + cgroup.kill
(+ seccomp/Landlock как FS/нет-изоляция, не proctree). Optional = subreaper
(нужен только вне pidns), orphan-scan (верификация, не убийство Strong).

## 7. Windows design

Текущий suspended→assign→resume — правильный ответ на creation race; держать
как инвариант с регресс-тестом. Дополнительно (proposal):
- nested jobs: агент не может вложить своё job с `BREAKAWAY_OK`, т.к. мы не
  ставим `JOB_OBJECT_LIMIT_BREAKAWAY_OK` и члены job не могут выйти без
  этого флага — держать + явно assert в probe; `kill_contract()` уже фиксирует
  контракт — расширить его проверкой в `probe_job_object`.
- handle inheritance: `inheritHandles=FALSE` уже; держать; captured-stdio путь
  (`handle.rs:26-29`) открывать только с явным HANDLE-list, иначе fail-closed.
- restricted token/AppContainer: ownership не дают, но сужают «чем внук может
  стать» (no admin, low integrity) — держать как defense-in-depth, не как
  cleanup-механизм.
- limits: `ActiveProcessLimit` + `JobMemoryLimit` (уже в
  `create_kill_on_close_job`) — обязательный anti-fork-bomb рубеж; добавить
  post-cleanup assertion через Job accounting (запрос состояния job после
  close-handle невозможен — assertion делать ДО drop: перечислить процессы
  job, TerminateJobObject при остатке, затем close).
- race окно между return experimental API и assign: покрыто suspended; если API
  вернул уже-running процесс — считать нарушением контракта, Terminate+fail.

## 8. macOS native design

Потолок платформы без pidns/subreaper: pgid + watchdog. Proposal:
- держать `pdeath_watch` (родительский fork, kqueue+poll-fallback) — Strong
  для корня, Partial для дерева;
- добавить subreaper-аналога НЕТ (Darwin не даёт) — фиксировать Unsupported;
- добавить orphan-scan assertion после `terminate()` (перебор `sysctl
  KERN_PROC` по ppid-цепочке от root pid + kill остатка + повтор) как
  portable-аналог sweep с тем же бюджетом; сегодня `sweep=false` и никакой
  проверки — главный macOS-gap;
- Seatbelt наследование держать (потомки в профиле), но не выдавать за
  cleanup;
- launchd/`open -b`/cron-escape: агент внутри Seatbelt не может положить
  persistent unit вне разрешённых путей записи — держать связку «FS-запрет =
  persistence-запрет», задокументировать.
- Endpoint Security: только notify/observe, не AUTH-allow/deny (уже честно);
  не предлагать как cleanup-механизм без entitlement — Unsupported.

## 9. VM design (Linux VM backend / win-sandbox)

VM даёт Strong teardown бесплатно (уничтожение инстанса). Требования к
дизайну: (a) termination boundary = граница VM, не внутренний pid; (b) агент
никогда не держит handle наружу VM; (c) снапшот/откат не воскрешает «убитое»
дерево как running; (d) host-side watchdog на гипервизор-объект на случай
смерти vetto; (e) exfiltration через shared folders — вне proctree, но
cleanup обязан закрывать гостевые mount-ручки до teardown. win-sandbox
модуль уже генерирует .wsb — добавить в него kill-контракт (текущий файл —
только спек, без lifecycle).

## 10. Cleanup state machine (target)

```text
EXIT_REQUEST ──► GRACEFUL (SIGTERM/job-soft, T_grace≈2с; FS-ONLY: SIGTERM группе)
   │ alive?            │ exited → VERIFY
   ▼                   ▼ timeout
ESCALATE (SIGKILL / kill(-1) / TerminateJobObject / drop-job; cgroup.kill+freeze)
   │                   ▼
   └──────────────► VERIFY (descendant-proof: pidns-empty / job-empty /
                   │         orphan-scan-empty + cgroup.procs-empty)
                   ├── CLEAN → post-cleanup assertion → SUCCESS
                   └── RESIDUE ──► RETRY-SWEEP (bounded, ≤N, backoff) ──► CLEAN?
                                     │ fail → FAIL-CLOSED: FAIL + residual report
                                     │ (pids, cmdlines, tier, механизм), non-zero exit,
                                     │ запись в registry, никаких «успех по waitpid»
```

Правила: graceful — только там, где есть кому ловить (Unix SIGTERM; Job —
TerminateJobObject сразу, graceful опционален); `waitpid(root)` — необходимое,
но не достаточное условие; каждый переход с дедлайном; общий бюджет teardown
ограничен (sweep-DoS через fork-bomb обязан упираться в `pids.max`+бюджет, а
не в бесконечность); сегодняшнего graceful вообще нет (`terminate()` =
сразу SIGKILL) — это честно для adversarial, но §17 вводит опциональный
GRACEFUL как настраиваемый, default = immediate-SIGKILL.

## 11. Crash resilience

| Сценарий | FULL | FS-ONLY | macOS | Windows Job |
|---|---|---|---|---|
| vetto SIGKILL | alive-pipe EOF → B kill(-1) — Strong | atexit НЕ бежит; остаётся kill(-pgid)? нет — **gap**: только PDEATHSIG корня; внуки-сироты вне subreaper-окна выживают | watchdog kqueue ловит — корень; внуки — gap | job kill-on-close — Strong |
| vetto SIGTERM | forwarder → нормальный teardown | то же | то же | teardown через handler |
| B/supervisor crash (внутри) | kernel reaps pidns — Strong | N/A (нет B) | watchdog двусторонний (следит и агента) | job держит |
| host reboot/power | всё умирает | всё умирает | всё умирает | всё умирает |
| daemon crash (`stop_session` недожал) | дерево уже убито teardown vetto-child | best-effort остаток | best-effort остаток | job держит |

Главный crash-gap: **FS-ONLY + SIGKILL(vetto)**: `arm_exit_sweep` (atexit) не
исполняется, `terminate()` не вызывается, subreaper-сироты остаются, т.к.
усыновивший их родитель (vetto) мёртв и sweep некому бежать; PDEATHSIG покрывает
только прямого ребёнка. Закрытие: pidfd+subreaper в daemon-стороже ИЛИ
документированный downgrade assurance + `vetto kill --hung` как внешний
sweeper (уже есть сканер, но он шлёт сигналы по pid, не sweep сирот —
предлагается расширить, §17).

## 12. Race analysis + false-positive cleanup checks

R1. fork→PDEATHSIG окно: закрыто getppid-check (везде) + alive-pipe в FULL.
R2. CreateProcess→assign: закрыто suspended (Windows). Unix-аналога нет —
    компенсируется §5 п.2.
R3. kill(-pgid)→setsid внука: reparent+sweep; окно = sweep-бюджет (residual).
R4. waitpid(root)→рождение ребёнка после смерти родителя (delayed child,
    `sleep 1 && evil &`): sweep ловит только усыновлённых к моменту скана;
    каскад глубже бюджета — escape. Лечится VERIFY-циклом (§10), не одним
    проходом.
R5. PID reuse: `kill(pid)`/`/proc/pid` после reap может бить по чужому;
    sweep исключает root_pid, но нерутовые пиды переиспользуемы между сканами.
    Лечится pidfd (`pidfd_open` + `pidfd_send_signal`) и стартовым временем
    из `/proc` (как уже в visibility `LifecycleToken`) — proposal.
R6. `vetto kill <pid>` по группе `-pid` при неверном pgid бьёт по чужой
    группе (fail-open наружу!). Предложение: kill только через registry +
    верификация `start_time`/cmdline перед сигналом.
R7. Daemon `stop_session`: `child.kill()` убивает vetto-child; если это был
    SIGKILL при FS-ONLY — см. §11. Предложение: graceful SIGTERM vetto-child
    с таймаутом вместо kill, чтобы его teardown успел отработать.

False-positive checks (супервизор думает «чисто», а сущность жива):
F1. `waitpid(root)==exited` при живых detached-внуках (главный кейс промпта).
F2. `kill(-pgid)==ESRCH` — группы уже нет, а setsid-внуки живы.
F3. `pgrep -f marker` пуст — процесс переименовался (`exec -a`, argv[0]
    перезапись) или cmdline недоступен (зомби/kernel-thread вид).
F4. orphan-scan пуст, т.к. ребёнок ещё не переродился (родитель-зомби не
    подождён) — scan до `root_settled` обязателен (в `sweep_reparented` уже
    есть `root_settled` — держать).
F5. cgroup.procs пуст, т.к. процесс в D-state (uninterruptible) — kill
    отложен ядром; VERIFY обязан отличать «пусто» от «D-state остаток».
F6. Job handle закрыт → «дерево убито», но nested-breakaway процесс вне job
    (если флаг когда-либо ослабят) — assertion ДО close обязательна.
F7. macOS `kill(agent)==ESRCH`, а внук в другой группе жив — сегодня вообще
    не проверяется.
F8. Redteam `test_setsid_escape` (`redteam.rs:85-129`): проверяет ФЛАГ
    subreaper/pidns, а не факт смерти потомка — self-attested Pass, классический
    false-positive. Заменить execution-пробой (§15).

## 13. Resource containment (связка с proctree)

CPU/mem (`limits.rs` RLIMIT_* + `cgroup.rs` cpu.max/memory.max) — наследуются,
снижают blast radius, но не убивают дерево. `pids.max` (cgroup) +
`RLIMIT_NPROC` (уже pre-exec) — прямой anti-fork-bomb рубеж для sweep-бюджета:
предложение сделать `pids.max` обязательным, когда cgroup доступен
(сегодня опционален и молча None). Open files (`RLIMIT_NOFILE`), fsize —
наследуются; сокеты — seccomp-семейства + netns/Job/AppContainer; IPC —
разделённые IPC-ns (FULL) vs общий host IPC (FS-ONLY/macOS — shm как
covert-канал между «убитыми» и живыми, учесть в VERIFY). FD-exfiltration:
передача дескрипторов наружу дерева (SCM_RIGHTS, pidfd_getfd — уже blocked)
не воскрешает процесс, но удерживает пайпы открытыми → ложное «дерево висит»
(EOF не приходит); B уже закрывает stdio-копии (`close_stdio_fds`), watchdog
чистит все fd — держать паттерн везде.

## 14. Verification strategy

Уровни: unit (парсинг `/proc`, BPF-офсеты — уже есть) → execution-probes
(реальный setsid-внук, см. `linux_orphans.rs:100` — уже execution, держать как
образец) → adversarial suite (§15) → post-cleanup assertion в проде (§10) →
`doctor --probe` отражает assurance-tier честно. Наблюдение
(visibility-poller, audit, ETW, FSEvents) — только evidence, никогда вход
VERIFY-решения (уже принцип threat-model.md:65-70 — держать).

## 15. Adversarial tests (минимум промпта → файлы)

Каждый кейс: spawn → teardown (graceful + SIGKILL-vetto) → assertion
«ноль session-owned». Матрица tier × кейс: FULL/Job = must-pass; FS-ONLY/macOS
= must-report (pass либо FAIL+residual, молчаливый pass запрещён).
Кейсы: double-fork; daemonize (`daemon()`); setsid; background shell
(`sh -c 'sleep 9999 &'`); spawn-loop/fork-bomb (под `pids.max`); delayed
child (`(sleep 3; evil)&` при teardown на t=0); child-after-parent-exit;
socket-open-then-detach (файл/сокет-якорь + setsid); files-kept-open
(EOF-hang проверка); respawn-loop (`while true; do evil; done` + watcher).
Плюс: exec-rename evasion (F3), PID-reuse окно (R5), TUI-timeout-ignore
проверка. Исполнение вне дерева запретов: at/cron/systemd --user только там,
где FS позволяет (expected-residual, не flake).

## 16. Repo/module changes (каждое изменение → файлы)

| # | Изменение | Файлы/модули | Tier | Класс |
|---|---|---|---|---|
| 1 | Cleanup state machine: graceful→escalate→verify→assert (`CleanupReport`) | `src/sandbox/handle.rs` (расширить `terminate`), новый `src/sandbox/cleanup.rs`, `src/main.rs` (`wait_with_timeout`), `src/tui/{full,statusline}.rs` | все | Partial→Strong-verify |
| 2 | Orphan-scan VERIFY-цикл + residual-отчёт вместо одного sweep | `src/sandbox/linux/proctrack.rs` (расширить `sweep_reparented`), `src/sandbox/cleanup.rs` | FS-ONLY/Seccomp | Partial (потолок) |
| 3 | pidfd-ожидание/сигналы против PID-reuse | `src/sandbox/linux/proctrack.rs`, `src/sandbox/linux/mod.rs` (хранить pidfd в handle) | Linux | Strong |
| 4 | cgroup.kill+freeze как обязательный второй рубеж + `pids.max` default при доступной иерархии | `src/sandbox/linux/cgroup.rs`, `src/sandbox/handle.rs`, `src/sandbox/linux/mod.rs` | Linux | Partial→Stronger |
| 5 | macOS orphan-scan assertion после terminate | `src/sandbox/macos/mod.rs`, новый `src/sandbox/macos/orphan_scan.rs`, `src/sandbox/handle.rs` (`sweep:true` для macOS с новым сканером) | macOS | Partial (потолок) |
| 6 | Windows assertion ДО drop job (перечень процессов, Terminate при остатке) + nested-breakaway assert в probe | `src/sandbox/windows/mod.rs`, `src/sandbox/windows/job_object.rs`, `src/sandbox/handle.rs` | Windows | Strong |
| 7 | Crash-path: graceful SIGTERM daemon-child вместо kill; внешний sweeper для FS-ONLY-сирот | `src/daemon/registry.rs` (`stop_session`), `src/cli/kill.rs` (registry-верификация перед сигналом) | все | Partial |
| 8 | HANDLE-list captured-stdio контракт (иначе fail-closed) | `src/sandbox/handle.rs` (`StdioMode`), `src/sandbox/windows/mod.rs` | Windows | Strong |
| 9 | Adversarial suite (§15) + замена self-attested redteam-пробы execution-тестом | `tests/integration/linux_proctree_adversarial.rs` (новый), `tests/integration/macos_proctree.rs` (новый), `tests/integration/windows_proctree.rs` (новый), `src/redteam.rs` (`test_setsid_escape`), `tests/integration/linux_orphans.rs` (расширить) | все | Test |
| 10 | `doctor --probe` assurance-репорт (tier × механизм × residual) + SECURITY.md sync | `src/doctor/probe.rs`, `SECURITY.md`, `docs/platform-backends.md`, `ARCHITECTURE.md` | все | Docs |
| 11 | VM kill-контракт в спеке + host-watchdog | `src/sandbox/windows/windows_sandbox.rs`, docs | VM | Strong |
| 12 | Graceful-флаг (default immediate-SIGKILL) + TUI-timeout паритет | `src/main.rs`, `src/config.rs`, `src/tui/*` | все | UX/compat |

Не менять молча: `KillStrategy` варианты, `SWEEP_BUDGET_MS`, `sweep:false` на
macOS, daemon stop-семантика, redteam-статусы — всё через этот proposal.

## 17. Migration plan

Фаза A (верификация без смены поведения): п.9-тесты + п.10-docs + п.8-контракт;
adversarial suite в CI как must-report (не блокирует). Фаза B (state machine):
п.1+п.2+п.5 за флагом, default старое поведение; включить VERIFY-assertion с
репортом, graceful default off. Фаза C (ужесточение): п.3 pidfd, п.4 cgroup
default, п.6 windows-assertion, п.7 daemon-graceful; adversarial становится
must-pass на Strong tier. Фаза D: п.11 VM-контракт, п.12 graceful-флаг/TUI
паритет. Каждая фаза: `docs/proctree-proposal.md` ← статус, SECURITY.md sync,
версионный бамп +0.0.1 по AGENTS.md-политике отдельным коммитом.

## 18. Security limitations (честные остатки)

- FS-ONLY/macOS: detached grandchild при SIGKILL(vetto) или вне бюджета —
  выживает;入学 Landlock/seccomp наследуются, но живость — нет. Unsupported
  без pidns/Job: запретить setsid, получить crash-proof sweep.
- Любой tier: respawn через внешнюю сущность (cron/systemd/host-процесс того
  же uid вне границы, daemon-registry) — вне proctree-границы по определению;
  закрывается FS-политикой (некуда записать unit), не kill-логикой.
- D-state процессы: SIGKILL отложен ядром; VERIFY отличает, но не ускоряет.
- PID-reuse между наивными сканами — до внедрения pidfd (п.3).
- Наблюдение (audit/poller/ETW/FSEvents) — evidence only, пропуск ≠ разрешение.
- Prompt-injection внутри разрешённого, записи в `$PROJECT`, side-channels,
  враждебное ядро/root — out of scope (threat-model.md).
