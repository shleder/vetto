# Fail-Closed + Runtime Verification — архитектурное предложение (Prompt 03)

> Скоуп: `docs/`, `src/sandbox/mod.rs`, `src/sandbox/handle.rs`, `src/error.rs`, `src/exit_codes.rs`.
> `src/verify_ng/` не тронут (Prompt 01, чужой скоуп). Production-код не пишется — только архитектура.
> Оценка соответствия каждого требования prompt: **Strong** (уже есть и достаточно),
> **Partial** (есть частично / можно обойти), **Unsupported** (нет и нужно проектировать).

## 1. Current fail-open / fail-closed inventory

База fail-closed в репозитории реально сильная — это главный вывод аудита prompt на веру не принимается, проверено по коду.

| # | Место | Файл | Вердикт | Комментарий |
|---|-------|------|---------|-------------|
| 1 | Отказ от unsandboxed fallback | `src/sandbox/mod.rs:60-139` | **Strong** | `detect_with_backend` возвращает `Err` вместо слабого backend; неизвестный backend — `bail`. Silent downgrade отсутствует на этом уровне |
| 2 | Linux tier selection | `src/sandbox/linux/mod.rs:108-136` | **Partial** | `pick_tier` fail-closed, но выбор зависит от runtime `VETTO_FORCE_TIER` — downgrade-override через env, не через явный CLI opt-in |
| 3 | FS-ONLY / Seccomp как tier, а не fallback | `src/sandbox/linux/mod.rs:149-168` | **Partial** | Это честная смена tier с другим набором гарантий, но UX называет tier одинаково «sandboxed»; пользователь не всегда понимает, что full→fs-only — weaker |
| 4 | Relay требует FULL | `src/sandbox/linux/mod.rs:150-156`, `src/main.rs:781-789` | **Strong** | Двойная проверка (backend + supervise), fail-closed с actionable сообщением |
| 5 | macOS relay reject | `src/sandbox/macos/mod.rs:60-80` | **Strong** | allowlist/strict/ask явно отклоняются, а не деградируют в `--net=off` |
| 6 | Windows enforcement gate | `src/sandbox/windows/mod.rs:432-466,468-481` | **Strong** | `enforcement_ready()` + `--net=off`-only + Inherit-stdio-only; неполные capabilities — `Err` |
| 7 | Windows deny-inside-grant | `src/sandbox/windows/mod.rs:1184-1202` | **Strong** | Secret внутри granted root — fail-closed `bail`, а не молчаливое игнорирование |
| 8 | Child setup handshake `R/E` | `src/sandbox/linux/mod.rs:1197-1214`, `src/sandbox/macos/mod.rs:116-132` | **Strong** | Готовность сообщает только полностью сконфигурированный child (`child_b` пишет `R` после Landlock+stdio+seccomp); `E`/EOF/timeout — `VettoError::Sandbox` → exit 125 |
| 9 | Preflight `--verify` | `src/main.rs:801-820`, `src/verify.rs:154-295` | **Partial** | Opt-in (`--verify`), не обязателен; `shadow` продолжает запуск при leaks; `probe` всегда `NetMode::Off` — relay-конфигурация не верифицируется |
| 10 | `doctor --probe` | `src/main.rs:1916-1986` | **Partial** | Диагностика по запросу, не gate; Windows явно `unavailable`; exit 1 только при leaks |
| 11 | `VettoError` → exit code | `src/error.rs:38-50`, `src/exit_codes.rs:96-118` | **Partial** | Typed-путь детерминирован (Sandbox→125), но legacy substring-fallback жив и расширяем человеческой ошибкой (`anyhow!` с «не тем» текстом → неверный код) |
| 12 | `Pty` → fail-closed | `src/error.rs:46` | **Partial** | `Pty(_) → EXIT_AGENT_ERROR (1)`, а не 125: сбой stdio-конфигурации выглядит как «ошибка агента», хотя сессия не стартовала в запрошенном виде |
| 13 | Cred-broker spawn failure | `src/main.rs:1086-1095` | **Partial** | `failed to spawn credential broker` — только `eprintln warning`, сессия продолжается; при `secret_proxies` это fail-open для секретов (агент без брокера может искать обход) |
| 14 | macOS rlimits best-effort | `src/sandbox/macos/mod.rs:325-339` | **Partial** | Отклонённые `setrlimit` только печатаются; запуск продолжается с меньшими limits без отражения в security level |
| 15 | macOS pdeath watchdog | `src/sandbox/macos/pdeath_watch.rs:21-23,41-46` | **Partial** | Fork/kqueue failure — продолжение без watchdog + stderr; орфан после SIGKILL vetto остаётся (документировано, но не gate) |
| 16 | Linux subreaper failure | `src/sandbox/linux/mod.rs:1394-1399,1577-1582` | **Partial** | Только `tracing::warn`; setsid-эскейперы переживают teardown — известное окно FS-ONLY |
| 17 | cgroup setup failure | `src/sandbox/linux/mod.rs:1225-1232,1431-1438` | **Partial** | `_ => None`: отсутствие limits silently игнорируется; child уже сообщил `R`, handle создан |
| 18 | `VETTO_SEATBELT_MODE=none/allow-all` | `src/sandbox/macos/mod.rs:356-384` | **Partial** | Диагностический kill-switch полностью снимает enforcement внутри child; защита только «CI-only» комментарием, без compile-gate или требования explicit CLI-флага |
| 19 | `VETTO_NO_MAC_LIMITS`, `VETTO_CHILD_TRACE`, `VETTO_NO_PDEATH_WATCH` | `src/sandbox/macos/mod.rs:332`, `src/sandbox/macos/pdeath_watch.rs:33` | **Partial** | Env-отравление ослабляет sandbox без ведома оператора; verify-ng уже фиксирует это как отравление (FM-08), но production-spawn это не проверяет |
| 20 | Policy mutation после detect | `src/main.rs:734-765` | **Partial** | `pol.allow_read.push(parent)` (бинарник агента) и `deny_write.push(bin)` мутируют policy после load; verify/preflight уже отработал на другой policy — hash-continuity отсутствует |
| 21 | Env allowlist + `env_extra` | `src/sandbox/linux/mod.rs:664-677`, `src/sandbox/macos/mod.rs:425-450` | **Strong** | Default-deny + двойной `filter_proxy_secrets`; `env_extra` — только внутренние `VETTO_*`, повторная зачистка есть |
| 22 | Windows env non-UTF16 drop | `src/sandbox/windows/mod.rs:1114-1170` | **Partial** | Некорректные entries silently `continue`/drop вместо fail-closed; поведение зависит от мусора в parent env |
| 23 | `dry_run` с несуществующим backend | `src/main.rs:643-650,767-769` | **Partial** | При `--dry-run` отсутствие backend подменяется `Tier::Full`-заглушкой — вывод «tier: full» вводит в заблуждение, это не измерение |
| 24 | TUI/timeout игнор | `src/main.rs:1216-1223` | **Partial** | `--timeout` в TUI-режимах молча игнорируется (только notice); оператор думает, что deadline есть |
| 25 | Signal forwarder install | `src/main.rs:1712-1719` | **Partial** | Ошибка установки SIGINT/SIGTERM — `eprintln warning`, сессия идёт без forwarder |
| 26 | Staged update / auto-update | `src/main.rs:92-97,1727-1750` | **Partial** | `warning: staged update not applied / background staging failed` — не gate, но влияет на целостность бинарника между verify и spawn (TOCTOU на обновление) |

Вывод: ядро spawn-цепочки — **Strong fail-closed**. Периметр (env-override, broker, limits, watchdog, policy-mutation, dry-run, CLI-warnings) — **Partial** и именно там живут все «security error → warning → continue» переходы.

## 2. Threat model (дополнение к docs/threat-model.md, не замена)

Активы и out-of-scope наследуются из `docs/threat-model.md` (§Assets, §What Vetto Does NOT Protect).

Новый противник Prompt 03: **ложное чувство enforcement**. Атакующие позиции:

1. **Adversarial agent внутри**: escape через setsid (FS-ONLY/macOS), дескрипторы, `execve` вне policy, UDS/IPC-exfil, чтение entry-names в FS-ONLY, перехват `env_extra`/broker-socket пути.
2. **Drift/TOCTOU снаружи**: подмена policy-файла между load и spawn; замена бинарника агента между `resolve_in_path` и `execve`; symlink-parent swap; late-created secret-shaped файлы в `$PROJECT`; изменение `HOME`/cwd.
3. **Оператор-ошибка**: `--dry-run`-вывод принят за гарантию; `--timeout` в TUI принят за deadline; `shadow` принят за enforcement; `doctor` без `--probe` принят за proof.
4. **Env-отравление**: `VETTO_FORCE_TIER`, `VETTO_SEATBELT_MODE`, `VETTO_NO_MAC_LIMITS`, `VETTO_NO_PDEATH_WATCH`, `VETTO_CHILD_TRACE` в наследованном окружении CI/обёрток.
5. **Supply-chain бинарника**: staged-update между preflight и spawn; подмена `processmodel.dll` резолва вне System32 (уже закрыто `LOAD_LIBRARY_SEARCH_SYSTEM32` — Strong).

Границы доверия: доверенный — host-верификатор vetto до `fork` + ядро; недоверенный — всё внутри sandbox, весь stdout/self-report child, все observation-фиды (подтверждено `docs/threat-model.md:65-70`).

## 3. Security invariants (должны стать кодом, сейчас — только текст)

1. `I1 no-launch-without-enforcement`: ни один `execve`/CreateProcess до `Verified` (pre-launch checks зелёные).
2. `I2 no-silent-downgrade`: любой переход на weaker tier/backend требует explicit opt-in (`--tier`/`--backend` + `--allow-degraded`) либо fail-closed.
3. `I3 enforcement-object-not-config`: проверяется живой объект (Landlock ruleset fd / mount ns / netns / Job handle / seatbelt-профиль-хэш), а не in-memory `Policy`.
4. `I4 observation-never-enforces`: verify/oracle не меняют enforcement; FAIL oracle убивает сессию, а не «чинит» политику.
5. `I5 policy-continuity`: хэш policy, ушедшей в spawn, равен хэшу policy, прошедшей pre-launch (frozen spec, как FM-03 в verify-ng).
6. `I6 trusted-verifier-only`: PASS выставляет только host после wait/host-fact; self-report child — максимум hint (уровень evidence из `docs/verify-ng.md:17-24` переиспользовать).
7. `I7 cleanup-is-guarantee`: потеря контроллера (crash/SIGKILL/power-loss) оставляет либо kernel-held teardown (pidns/Job), либо честный `degraded-cleanup` статус, но никогда «terminated».
8. `I8 warnings-never-gate-bypass`: любой `warning:` на пути Requested→Running обязан либо иметь error-код, либо быть вне security-пути (логи/telemetry/UI).

## 4. Sandbox state machine

```text
Requested -> Validated -> Compiled -> Constructed -> Verified -> Launchable -> Running -> VerifiedRuntime -> Terminating -> Terminated
```

Допустимые переходы: каждый шаг только вперёд; `Verified -> Launchable` только при зелёных pre-launch; `Launchable -> Running` только через fork/spawn, владеющий frozen spec; `Running -> VerifiedRuntime` только через host-post-launch probes; `* -> Terminating` из любого состояния после `Constructed` (обязательный cleanup-контракт); `Terminating -> Terminated` только после подтверждённого teardown.

Невозможные: `Requested -> Running`, `Validated -> Launchable` (мимо compile/construct), `Running -> Launchable`, `Terminated -> *`, `VerifiedRuntime -> Running` без повторной верификации.

Rollback: до `Launchable` — освободить ресурсы и вернуться в `Requested` с ошибкой; после `Running` rollback нет, только `Terminating` с kill-стратегией tier.

Fatal states (уничтожают возможность launch в этой сессии): `BackendUnavailable`, `PolicyCompilationFailed`, `PreLaunchFailed`, `SpecMismatch`, `SpawnFailed`, `PostLaunchFailed` (убивает уже стартовавший child и запрещает retry без нового `Requested`), `DriftDetected`.

Карта на текущий код: `Requested` = CLI parse (`src/main.rs:99-128`, `src/config.rs:186-381`); `Validated` = `RunConfig` + policy load (`src/main.rs:686-693`); `Compiled` = tier/backend resolve (`src/sandbox/mod.rs:65-139`, `pick_tier`); `Constructed` = fork-цепочка до байта `R` (`src/sandbox/linux/mod.rs:1110-1244`, `src/sandbox/macos/mod.rs:50-150`); `Verified` — отсутствует как состояние (есть только opt-in preflight); `Launchable/Running` слиты в `backend.spawn` → `handle`; `VerifiedRuntime` отсутствует; `Terminating/Terminated` — `SandboxHandle::terminate/drop` (`src/sandbox/handle.rs:169-213`).

## 5. Pre-launch checks (обязательные, до fork; каждый — fail-closed)

Проверяется **объект enforcement**, не структура config:

1. `backend-selected`: tier/backend разрешён security level (strict/standard/degraded, §8) + explicit opt-in на degraded зафиксирован.
2. `effective-policy-frozen`: канонический хэш frozen spec (policy + net + tier + backend-describe + argv/env/cwd + nonce) посчитан и защёлкнут; любая мутация после (типа `allow_read.push` в `src/main.rs:756-765`) — только до freeze, после — `SpecMismatch`.
3. `capability-probe`: живые примитивы (Landlock ABI, userns/full-stack, seccomp, seatbelt-availability, Windows `enforcement_ready`) — не кэш `doctor`, а свежий probe этого запуска.
4. `containment-object`: предсозданные объекты — netns/mountns handle (FULL), Job Object (Windows), seatbelt-профиль-хэш (macOS); spawn владеет ими, а не «надеется создать в child».
5. `filesystem-policy`: Landlock prepared-ruleset собран и его хэш совпадает с frozen; deny-inside-grant проверен (Windows-аналог уже есть — распространить на все tier).
6. `network-policy`: relay-топология соответствует NetMode; FS-ONLY+relay и macOS/Windows+relay уже отклоняются — вынести в единый gate, а не три копии.
7. `credential-boundary`: broker-socket создан до fork либо `secret_proxies` пусты; spawn-failure брокера — fatal, не warning (§1.13).
8. `environment-filtering`: allowlist применён к снимку env + скан diagnostic-env (`VETTO_*`) с FAIL при отравлении (переиспользовать FM-08).
9. `resource-policy`: cgroup/rlimit/Job-limits применены или честно задекларированы как `limits-degraded` с влиянием на security level; silent `None` запрещён (§1.17).
10. `binary-identity`: `resolve_in_path` + device/inode snapshot бинарника; child сверяет перед `execve` (закрывает TOCTOU resolve→exec).
11. `expected-security-level`: итоговая тройка (tier, net, limits/cleanup) маппится на strict/standard/degraded и печатается как одна строка до запуска.

Сейчас: **Strong** только 3 (частично), 6 (размазан по трём файлам), 8 (фильтр, но без скана env-override). Остальное — проектировать.

## 6. Post-launch checks + 7. Runtime verification protocol

Слои (все — host-верификатор, не self-report):

- `P1 liveness+identity`: `waitpid`/Job-handle + сверка root_pid/pgid/Job membership; смерть контроллера до `R` — `SpawnFailed`.
- `P2 containment-membership`: Linux — `/proc/<pid>/ns/{mnt,net,pid}` inode сравнить с pre-launch снимком; Windows — `IsProcessInJob` + integrity-level readback; macOS — профиль-хэш + `sandbox_check`-readback где доступно.
- `P3 canary-probes` (безопасные, одноразовые, nonce-bound): deny-path open должен дать `EACCES`; loopback-connect должен отказать; write-outside должен отказать; env-canary (`VETTO_CANARY_NONCE`) не должен утечь в `/proc/<pid>/environ` вне allowlist. Положительный контроль: разрешённый read/write внутри `$PROJECT` обязан succeed (ловит over-confinement и oracle-deceit, ср. FM-02).
- `P4 child-inheritance`: fork bomb-grandchild наследует Landlock/seccomp (проверка через constrained errno-сигнал grandchild + host-fact); setsid-эскейпер детектируется через subreaper/sweep-отчёт.
- `P5 network-reality`: relay-broker counters (allowed/denied) + host loopback-listener canary (как в `src/verify.rs:234-249`, но для живой сессии, не throwaway).
- `P6 secrets-inaccessibility`: host-fact stat/canary-сравнение masked paths (masked должен быть empty/null-bound на FULL; carved-out на FS-ONLY — честный PARTIAL).
- `P7 limits-reality`: cgroup `memory.current`/`pids.current` readback; rlimit readback через `/proc/<pid>/limits`; Job-memory readback.

Протокол: `Running → (P1+P2+P3-negative) → VerifiedRuntime`; `P4–P7` — периодический re-verify тиком (Linux 5–30с адаптивно, mac/Win реже) + по событию (fork-storm, net-deny spike, drift-signal). Любой FAIL — `Terminating` + kill-стратегия tier + exit 125, retry только через новый `Requested`. Evidence-уровни и nonce-связка — из `docs/verify-ng.md:17-31` (HOST_FACT единственный для PASS).

Что только до запуска: создание ns/Job/seatbelt-профиля, Landlock restrict_self, mount-оверлеи, uid/gid-map handshake, env-freeze, binary-identity snapshot.

Что повторять после: membership ns/Job, canary deny/net/write, broker counters, limits readback, sweep-отчёт.

Что невозможно изнутри sandboxed process (требует trusted host verifier): собственный ns-membership (может врать `/proc`), полнота Landlock-coverage, Job-membership, чтение чужого environ без ptrace-блока, broker-side DNS-ответы, cgroup-лимиты хоста, факт убийства эскейперов.

## 8. Fallback matrix (без silent downgrade)

| Fallback | security-equivalent? | weaker? | observable? | auto? | opt-in? | must-fail? |
|---|---|---|---|---|---|---|
| Linux full → fs-only | нет | да (нет ns/overlay/netns) | сейчас только tier-label в env/логе | **да (auto через pick_tier)** — главная дыра | должен требовать `--allow-degraded` | в strict — да |
| Linux full/fs-only → seccomp-only | нет | сильно да (нет FS-изоляции) | tier-label | да (auto) | opt-in | в strict/standard — да |
| macOS native → best effort (read-tail-deny, limits-warn, watchdog-miss) | нет | да | частично (stderr) | да | opt-in на degraded | в strict — да (только Linux VM) |
| Windows experimental → weaker (job-only/token-only) | нет | да | `enforcement_ready` gate | нет — уже fail-closed (**Strong**, держать) | n/a | да |
| native → VM (win-sandbox/OrbStack/WSL2) | да/сильнее | нет | явный `--backend win-sandbox` | нет (explicit) | да, explicit backend | нет |
| relay → off при недоступности FULL | нет | зависит от threat (exfil vs offline) | да (bail-текст) | нет — уже fail-closed (**Strong**, держать) | explicit `--net=off` retry | да (не деградировать молча) |
| verify FAIL → shadow-continue | нет | да | да (stderr) | нет (требует `--shadow`) | да, но `--shadow` обязан быть несовместим со strict | в strict — запретить флаг |

Security levels: `strict` — только FULL/seatbelt-strict/experimental-Windows + pre+post verify зелёные, ноль degraded, `shadow` запрещён; `standard` — FULL/FS-ONLY + seatbelt + Windows-exp, degraded только с `--allow-degraded`, post-verify обязателен; `degraded` — seccomp-only/FS-ONLY-без-sweep/macOS-best-effort допустимы, но каждая сессия печатает `degraded: <причины>` и audit-маркер; VM-бэкенды удовлетворяют strict.

## 9. Drift model

| Drift-событие | Детект | Как |
|---|---|---|
| policy-файл изменён после freeze | **да** | frozen-spec hash + `verify_spec_continuity`; mtime/inotify — только hint |
| files/symlinks поменялись (swap parent, late secret) | частично | pre-exec `openat2(RESOLVE_BENEATH)` + re-resolve deny перед Landlock; late-created secrets — только следующим freeze (документированный residual) |
| child запущен другим способом (exec вне spawn) | **да** | только spawn владеет containment-объектом; чужой pid не проходит P2-membership |
| дополнительный handle/fd передан внутрь | частично | `close_range` в child уже есть; SCM_RIGHTS через broker — allowlist fds; UDS-передача от third-party — residual (ср. verify-ng §Потолки) |
| sandbox object закрыт (alive-pipe/Job handle) | **да** | FULL: EOF alive-pipe → init kills ns; Windows: kill-on-close — kernel; FS-ONLY/macOS: watchdog/poll — best-effort, честный degraded |
| external process изменил env/context | **да** до exec | env-freeze snapshot; после exec — environ readback host-фактом |
| backend enforcement частично отказал (Landlock ok, seccomp miss) | частично | P3-canary ловит функциональный отказ; silent BPF-reject без canary-сигнала — residual, закрывается positive-control |

Недетектируемо в принципе: TLS-payload к allowed-API, записи внутри `$PROJECT`, side-channels, kernel-0day, полнота логов — наследуются из `docs/verify-ng.md:97-102` и threat-model §What Vetto Does NOT Protect.

## 10. Crash / partial failure semantics

| Сбой | Поведение | Уже запущенные процессы |
|---|---|---|
| backend init crash (probe/pick_tier) | fail-closed до fork, exit 125 | нет процессов — нечего убивать |
| policy compilation failure | fatal `Validated`, exit 125 (не 1) | нет |
| verification timeout (pre/post) | timeout = FAIL, не retry-in-place; exit 125 | pre: не стартовали; post: `Terminating` через kill-стратегию |
| child spawn failure (fork/exec) | `E`/EOF/timeout → `VettoError::Sandbox` → 125 | частично созданные — убить через уже захваченные handles (Windows-путь с TerminateProcess до `return Err` — образец) |
| launcher (vetto) crash после создания sandbox, до launch | pre-`R`: child умирает на handshake-timeout/PDEATHSIG; post-`R`: см. ниже | FULL: alive-pipe EOF → init kills ns (**Strong**); Windows: Job kill-on-close (**Strong**); FS-ONLY/macOS: subreaper-sweep/watchdog best-effort (**Partial** — честно маркировать `degraded-cleanup`) |
| child crash | exit-код честно наружу; sweep эскейперов; `VerifiedRuntime` не выставляется задним числом | эскейперы — через tier kill-стратегию |
| host power loss | после ребута — ничего живого; при старте — stale-registry cleanup (`status`/`kill --hung` уже есть) | n/a, но audit обязан различать `terminated` vs `unknown-after-reboot` |

## 11. Error taxonomy (к `src/error.rs` / `src/exit_codes.rs`)

Сейчас: `VettoError::{Landlock,Namespace,Mount,Seccomp,Sandbox,UnsupportedPlatform}→125`, `Pty→1`, `Policy→1`, `PolicyLockdownViolation→126` + legacy substring-fallback. Предложение (только таксономия, без кода):

- Новые варианты: `PreLaunchCheck{check}`, `PostLaunchCheck{check}`, `SpecMismatch{expected,got}`, `DriftDetected{signal}`, `DegradedRefused{reason}`, `TeardownIncomplete{detail}` — все → **125**.
- `Pty` разделить: `PtySetup` (до launch) → 125; `PtyIo` (после VerifiedRuntime) → 1.
- Cred-broker failure с непустыми `secret_proxies` → `Sandbox` (125), не warning.
- Cgroup/rlimit/subreaper/watchdog failure: в strict → 125; в standard/degraded → запуск с `limits-degraded` маркером + audit, но никогда silent.
- Убить substring-fallback поэтапно: заморозить список (не расширять — уже написано), добавить `#[deny]`-линт на новые `anyhow!` без typed-конструктора на security-пути, мигрировать существующие call sites.
- Exit 103 из threat-model (`docs/threat-model.md:110`) расходится с кодом (125): унифицировать доки на **125** (код — источник правды).

## 12. Policy hash / identity model

Frozen spec (канонический JSON, сортировка ключей, `NetMode::label`, tier, backend-describe, argv/env/cwd snapshot, binary device+inode, nonce сессии, хэш реестра verify-ng): `sha256(canonical)`. Считается один раз из той же `&Policy`-ссылки, что уходит в spawn (паттерн FM-03); `detect→freeze→spawn` под серийным мьютексом spawn-контракта (паттерн FM-09). Re-freeze перед fork обязан совпасть, иначе `SpecMismatch` → fatal. Хэш пишется в JSONL-audit, CI-summary и отчёт; привязка «хэш ↔ живой процесс» — только непрерывность владения до fork (честно, как в verify-ng §Что всё ещё нельзя доказать).

## 13–16. Platform plans

**Linux (13):** единый pre-launch gate перед `spawn_full/fs_only/seccomp_only`; env-скан diagnostic-override; binary-identity snapshot; cgroup-результат в security level; P2-membership через ns-inode; P3-canary через отдельную throwaway-сессию + живой broker-counters; sweep-отчёт как host-fact (число убитых/оставшихся, не «предположительно чисто»).
**Windows (16→14):** сохранить fail-closed ядро; добавить post-launch readback (Job-membership, integrity, spec-хэш); HANDLE-capture для evidence — отдельным backend-ревью (как требует verify-ng §Потолки); per-domain egress без admin остаётся UNPROVABLE — не чинить, честно маркировать; `win-sandbox` (VM) — единственный strict-путь с сетью.
**macOS (15):** seatbelt-профиль-хэш в frozen spec; диагностические `VETTO_SEATBELT_MODE` — только за compile-gate (`cfg(debug_assertions)`/feature) либо explicit CLI-флаг, никогда silent env; read-secrecy потолок PARTIAL честно в security level (ср. FM-11); watchdog-failure в strict — fatal.
**VM implications (16):** VM-бэкенды — explicit opt-in tier с собственной spec-схемой (`.wsb`/VM-образ хэш); fallback native→VM никогда не auto (разные trust-границы, время старта, стоимость); drift внутри VM — вне host-верификатора, требуется in-guest agent отчёт как CONSTRAINED-сигнал максимум.

## 17. CLI/UX semantics

- `--verify` из opt-in в default-on для supervised run; `--no-verify` — explicit с degraded-маркером (standard) / запрещён (strict).
- `--shadow` несовместим со strict; в выводе всегда `shadow: policy-layer only, kernel NOT shadowed` (уже есть в `--help`/dry-run — поднять до gate).
- `--dry-run` обязан печатать `NOT ENFORCED` баннер + никогда не подменять tier-заглушку (`Tier::Full` fake в `src/main.rs:644-646` — убрать, печатать `tier: unknown (dry-run)`).
- `--allow-degraded` (новый): единственный opt-in на weaker tier; без него любой degraded — 125.
- `--security-level strict|standard|degraded` (новый, default standard): определяет таблицу §8.
- Стартовая строка сессии: `sandbox: <backend> tier=<t> net=<m> level=<l> spec=<short-hash> [degraded: <reasons>]`.
- `doctor` без `--probe` — диагностика, не proof: подписать вывод; `verify`/`doctor --probe` — единственные proof-команды pre-launch.

## 18. Tests and adversarial cases

Переиспользовать harness verify-ng (не дублировать): новые блокеры как сценарии registry с ClaimStrength-капами FM-11:

1. `FC-PRE-001` downgrade без opt-in обязан дать 125 (full→fs-only через `VETTO_FORCE_TIER`, full→seccomp).
2. `FC-PRE-002` env-отравление (`VETTO_SEATBELT_MODE=none`, `VETTO_NO_MAC_LIMITS`, `VETTO_NO_PDEATH_WATCH`) — FAIL/INCONCLUSIVE по FM-08, в strict — отказ запуска.
3. `FC-PRE-003` policy-mutation после freeze (push allow_read) — `SpecMismatch`, 125.
4. `FC-PRE-004` бинарник подменён между resolve и exec — отказ.
5. `FC-PRE-005` broker spawn failure при `secret_proxies` — 125, не warning.
6. `FC-POST-001` setsid-эскейпер: FULL — убит ядром (Strong); FS-ONLY/macOS — детектирован sweep-отчётом, статус `degraded-cleanup`, destructive — только disposable VM (FM-05).
7. `FC-POST-002` ns/Job-membership mismatch после старта — `Terminating`, 125.
8. `FC-POST-003` canary deny/net/write readable — FAIL, 125 (negative + positive control, FM-02 nonce).
9. `FC-POST-004` controller SIGKILL mid-session: FULL/Windows — дерево мертво (host-fact); FS-ONLY/macOS — честный residual-отчёт.
10. `FC-POST-005` oracle-deceit: self-report «всё запрещено» при реально открытом контроле — ловится positive-control + HOST_FACT.
11. `FC-ERR-001…010` десять warning-path регрессий (§19): каждый `warning:` на security-пути покрыт тестом «ошибка → 125 либо маркер degraded, но не silent continue».
12. Фаззинг exit-code mapping (расширить существующие proptest в `src/exit_codes.rs:246-320`): typed-errors всегда побеждают substring; `PtySetup`→125.

## 19. Exact repo / module changes (без кода, только карта)

| # | Файлы/модули | Изменение |
|---|---|---|
| M1 | `docs/fail-closed-proposal.md` (новый, этот файл) | Архитектура Prompt 03 |
| M2 | `src/sandbox/mod.rs` | `Backend::detect_with_backend` принимает `SecurityLevel` + `allow_degraded`; downgrade — explicit; `describe()` отдаёт machine-readable spec для frozen-hash |
| M3 | `src/sandbox/handle.rs` | `SandboxHandle` несёт `spec_hash`, `security_level`, `teardown_receipt` (sweep-kill counts); `terminate()` возвращает receipt вместо `()` |
| M4 | `src/error.rs` | Новые варианты `PreLaunchCheck/PostLaunchCheck/SpecMismatch/DriftDetected/DegradedRefused/TeardownIncomplete`; split `Pty` на setup/io |
| M5 | `src/exit_codes.rs` | Заморозка substring-fallback; `PtySetup`→125; доку-комментарий про 125-vs-103 |
| M6 | `src/main.rs` supervise (потребитель, вне скоупа правок тут) | Порядок detect→load→freeze→pre-launch→spawn→post-launch; `--security-level`, `--allow-degraded`, default-on `--verify` |
| M7 | `src/sandbox/linux/*` (потребитель) | Pre-launch gate, binary-identity, env-скан, cgroup-в-security-level, ns-membership P2, sweep-receipt |
| M8 | `src/sandbox/macos/*` (потребитель) | Профиль-хэш, diagnostic-env gate, watchdog-failure fatal-в-strict |
| M9 | `src/sandbox/windows/*` (потребитель) | Post-launch readback Job/integrity, HANDLE-capture ревью отдельно |
| M10 | `docs/threat-model.md`, `docs/exit-codes.md`, `SECURITY.md`, `ARCHITECTURE.md` | Синк: 125 (не 103), levels, degraded-маркировка, dry-run/shadow-дисклеймеры |
| M11 | `src/verify_ng/registry/*` (чужой скоуп, только предложение) | FC-* сценарии как потребители, без правок в этом prompt |

Правки production-кода в этом prompt не делаются; M2–M5 — только интерфейсные декларации на фазе имплементации.

## 20. Migration strategy

Фаза A (docs-only, этот prompt): настоящий документ + синк кодов в доке. Фаза B (interfaces): M4+M5 таксономия + M3 receipt-структуры, всё backward-compatible (новые варианты/поля, старые пути живы). Фаза C (gates): default-on pre-launch + `--allow-degraded`/`--security-level`, `shadow`-strict запрет, dry-run честность. Фаза D (runtime): P2-membership + canary post-launch + teardown receipts. Каждая фаза — минорный релиз +0.0.1 по политике версионирования, с `docs/verify-ng.md`-гейтом (ноль INCONCLUSIVE в блокерах) как release-gate.

## Critical review: 10+ мест «security error → warning → continue»

1. `src/main.rs:1093` cred-broker failure → `warning`, запуск идёт (§1.13).
2. `src/sandbox/linux/mod.rs:1431-1438,1613-1620` cgroup `Err → None` (§1.17).
3. `src/sandbox/macos/mod.rs:335-338` rlimits refused → `eprintln`, continue (§1.14).
4. `src/sandbox/macos/pdeath_watch.rs:41-46` watchdog fork fail → `warning`, continue (§1.15).
5. `src/sandbox/linux/mod.rs:1394-1399` subreaper fail → `tracing::warn` (§1.16).
6. `src/main.rs:1712-1719` SIGINT/SIGTERM forwarder fail → `warning` (§1.25).
7. `src/main.rs:95,1749` staged-update failure → `warning` (TOCTOU-окно бинарника, §1.26).
8. `src/main.rs:805-807,1353-1357` shadow продолжает при leaks/threshold (§1.9).
9. `src/main.rs:1216-1223` timeout в TUI молча игнор (§1.24).
10. `src/sandbox/windows/mod.rs:1146-1151` malformed env entries — silent drop (§1.22).
11. `src/main.rs:727-732` snapshot failure → `tracing::debug` (rollback-гарантия испаряется тихо).
12. `src/main.rs:95-97` + `src/sandbox/linux/mod.rs:109-114` diagnostic-env вообще не сканируется на security-пути (§1.2/1.18/1.19).

Ответы на обязательные вопросы: только до запуска — создание ns/Job/seatbelt/Landlock-restrict/mount-оверлеи/handshake/env-freeze/binary-snapshot; повторять после — membership, canary deny/net/write, broker-счётчики, limits-readback, sweep-отчёт; только trusted host verifier — собственная ns/Job-принадлежность, полнота coverage, Job/integrity readback, broker-DNS, cgroup хоста, факт смерти эскейперов (self-report изнутри — максимум CONSTRAINED-hint, PASS только HOST_FACT).

---

## Implementation plan (остановиться после, ждать ревью)

1. Принять настоящий документ в `arch/prompt-03` (этот файл) — docs-only коммит.
2. Синкнуть доки кодов/уровней (M10): 125 как канон, dry-run/shadow дисклеймеры.
3. Спроектировать интерфейсы M3–M5 (error-варианты, receipt, freeze-spec схема) — ревью без кода.
4. Включить gates фазы C за feature-флагом: default-on verify, `--allow-degraded`, `--security-level`, strict-запрет shadow.
5. Реализовать post-launch P1–P3 + teardown receipts (фаза D), FC-сценарии в harness как блокеры.
6. Прогнать verify-ng gate (ноль INCONCLUSIVE в I1–I6, canary PASS) + adversarial-сьют §18; релиз +0.0.1.

## Acceptance criteria

- [ ] Ни один weaker-tier переход без explicit opt-in; каждый — в audit с `degraded: <reason>` либо 125.
- [ ] Pre-launch gate обязателен: 11 проверок §5 зелёные до fork; любое нарушение — 125, запуск невозможен.
- [ ] Frozen-spec continuity: мутация policy/env/binary между freeze и spawn — `SpecMismatch`, 125.
- [ ] Post-launch: P1–P3 зелёные до `VerifiedRuntime`; FAIL — kill + 125; PASS только HOST_FACT.
- [ ] Все 12 warning-path §Critical review либо стали 125, либо несут degraded-маркер + audit; silent continue — ноль.
- [ ] `VETTO_*` diagnostic-env сканируется до fork; в strict любое отравление — отказ.
- [ ] Доки синкнуты на 125; dry-run/shadow/doctor честны (не proof); `src/verify_ng/` untouched в diff.
