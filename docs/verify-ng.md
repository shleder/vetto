# verify-ng — Adversarial Security Verification

> Статус реализации (0.2.25, факт): Stage 2 — host-owned positive control
> для `Aux`-pipeline сценариев на unix: per-execution FIFO в host-private
> dir + identity-bound токен (`ExecutionIdentity`: scenario + session nonce
> + registry hash + frozen hash); только точное прибытие токена на
> host-конец чеканит `VerifiedControl` → `HOST_FACT control` с provenance.
> Oracle чист (без IO) и требует совпадения provenance с текущей identity:
> replay/wrong-scenario/wrong-registry — INCONCLUSIVE. Library pipeline
> покрыт `TEST-ENGINE-*`, `TEST-CONTROL-SPLIT-001` (A legitimate → PASS,
> B forged file → INCONCLUSIVE), `TEST-HOST-CONTROL-POSITIVE-001`,
> `FORGE/REPLAY/WRONG-SCENARIO/WRONG-REGISTRY-001`,
> `TEST-HOST-EVIDENCE-REPLAY-001`, violation-dominates, blocker-ceiling.
> Блокеры на direct-exec остаются INCONCLUSIVE/FAIL (containment не
> доказывается, direct — не sandbox); non-Unix — control-unobserved.
> `vetto verify-ng --lint` без спавна; CLI по-прежнему не исполняет
> registry-suite, backend-wired сьюты — следующий этап. Всё ниже про
> PASS-вердикты блокеров описывает дизайн, а не текущее поведение CLI.

Измерительный harness поверх sandbox-бэкендов. Enforcement остаётся в
`src/sandbox/*`; этот модуль только измеряет и отчитывается. Не является
частью security boundary.

## Две оси

- `Verdict`: `PASS` / `FAIL` / `INCONCLUSIVE` / `NOT_APPLICABLE`
  (`src/verify_ng/model.rs`). Fail-closed: не-PASS в blocker-категории
  блокирует релиз. `NOT_APPLICABLE` требует probe-доказательства отсутствия
  capability, иначе блокирует как `N/A-without-evidence`.
- `ClaimStrength`: `STRONG` / `PARTIAL` / `UNSUPPORTED` — статическое
  свойство пары (сценарий, платформа-тир) в registry. Нет «Partial-PASS»:
  отчёт несёт обе оси.

## Уровни evidence

1. `HOST_FACT` — наблюдено доверенным хостом после wait (post-mortem stat,
   wait-status, sweep, canary-сравнение, spec-hash, verified host-control).
   Единственный уровень, поддерживающий PASS. Позитивный контроль требует
   provenance, в точности равной текущей `ExecutionIdentity`, иначе oracle
   даёт INCONCLUSIVE (replay/wrong-scenario/wrong-registry отвергаются).
2. `CONSTRAINED` — узкий nonce-bound сигнал изнутри (errno-класс + nonce).
   Поддерживает FAIL, никогда PASS в одиночку.
3. `SELF_REPORT` — stdout-маркеры атаки. Только hint для triage.

## Nonce-связка (FM-02)

Engine выдаёт nonce сессии. Негативная проба и позитивный контроль обязаны
его использовать; хост сверяет совпадение. Расхождение — INCONCLUSIVE.
Ловушки `ORACLE-DECEIT-001` / `CONTROL-SPLIT-001` — постоянные regression.

## FrozenSpec (FM-03)

Один `detect` на сценарий; хэш считается один раз из той же `&Policy`-ссылки,
что уходит в `Backend::spawn`; сериализация каноническая (сортировка,
`NetMode::label`, tier, backend-describe, argv/env/cwd, nonce, хэш реестра,
плюс `policy_bytes` — канонический рендеринг всей `Policy`, а не только
разложенных path-списков). Повторная заморозка перед spawn обязана совпасть
(`verify_spec_continuity`).

## Spawn-контракт (FM-09)

Все `Backend::spawn` — под `SPAWN_SERIAL` от detect до fork-возврата.
Блокирующий `wait()` в runner запрещён; только `try_wait`-poll +
`kill_on_deadline` + deadline-aware drain (`collector::drain_with_deadline`).

## Cleanup-матрица (FM-05)

- Linux FULL — Strong (PIDns teardown).
- Windows Job — Strong (kill-on-close).
- Linux FS-ONLY / macOS — BestEffort (group-kill + sweep-бюджет 2с);
  destructive-сьюты там только в disposable VM.

## Fixture (FM-06)

Один spawn — один сценарий. Хэш payload до/после; мутация — INCONCLUSIVE.
HOME изолирован на прогон. `env_extra` engine-контролируем.

## Redaction (FM-07)

Все detail-строки через `redact_text`: секреты → `[REDACTED]`, control-байты
чистятся, лимит `MAX_DETAIL`. HOME-префикс маскируется.

## Diagnostic env (FM-08)

`VETTO_SEATBELT_MODE`, `VETTO_NO_MAC_LIMITS`, `VETTO_CHILD_TRACE` (и
`VETTO_FORCE_TIER` вне tier-differential job) — отравление: FAIL на
блокерах, INCONCLUSIVE на aux. Детект до spawn.

## Gate (FM-12)

`exit::evaluate_gate`: canary (`VFS-TRAV-001`, `ENV-LEAK-001`, `PROC-ESC-001`)
обязаны PASS; ноль INCONCLUSIVE в I1–I6; NOT_APPLICABLE только с evidence;
минимум PASS по каждой blocker-категории. Пустой сьют — gate FAIL
(`GATE-VACUUM-001`).

> Итерация 2: gate-минимум по `fs-write` закрывается сценарием
> `VFS-WRITE-001` (blocker, `linux-full`/`linux-fsonly` STRONG). Без его PASS
> gate остаётся красным по правилу per-category minimum — vacuum по записи
> невозможен.

## Сьюты итерации 2 (карта покрытия Prompt 01)

Linux suite (полностью, fail-closed/escape/exfil приоритет):

- `VFS-WRITE-001` (blocker, fs-write) — STRONG на full/fs-only. Закрывает
  пустую blocker-категорию `fs-write` и правило gate-minimum.
- `VFS-PROC-001` (blocker, fs-read) — `/proc|/sys|/dev`/fd-инъекции.
- `NET-EXFIL-001` (blocker, net, quorum 3) — мультивекторная эксфильтрация:
  curl, python-socket, native TCP4/6, DNS, alt-HTTP, UDS/IPC, raw-syscall.
- `SHELL-ESC-001` (blocker, spawn) — alt-shell/interpreter/PATH-confusion.
- `ENV-SECRETS-001` (blocker, secrets) — env/fd/argv/SSH-Git-cloud canary.
- `PROC-TREE-001` (blocker, proc) — sibling/detached/handles escape.
- `RACE-TOCTOU-001` (blocker, spawn, quorum 3) — freeze-spawn + symlink-swap
  TOCTOU, медиана ≥3 прогонов.
- `SEC-BLOCKS-001` (blocker, spawn) — seccomp/syscall denial по native ABI
  (ptrace/process_vm/pidfd, mount/pivot, io_uring, userfaultfd, bpf/perf).
- `RES-EXHAUST-001` (high, proc) — fork/pids/IO/disk/mem; полный вариант
  только disposable VM.
- `STRESS-SWEEP-001` (high, proc) — stress/race контракт: медиана, кворум,
  sweep-бюджеты.
- `FUZZ-CORPUS-001` (high, spawn) — контракт fuzz-корпуса (path/env/argv/cwd/
  symlink мутации) и oracle-правила без production-fuzz кода.
- `TIER-DIFF-001` (high, spawn) — differential full vs fs-only vs seccomp:
  расхождение только в задокументированную слабую сторону, без silent
  downgrade.

Windows suite (host-fact-only):

- `WIN-ESC-001` (blocker, proc) — PowerShell/cmd/API, token, integrity, Job,
  ACL; evidence строго host-fact-only (pipe-drain stub даёт not-EOF →
  INCONCLUSIVE, никогда PASS).
- `WIN-NET-001` (blocker, net) — `--net=off` через AppContainer capabilities
  (PARTIAL); per-domain без admin UNPROVABLE и обязан fail-closed.
- `WIN-UNC-001` (high, fs-read) — PARTIAL/advisory до маппинга алиасов.
- `WIN-WSL-001` (high, fs-read) — UNSUPPORTED baseline; любой PASS — баг.

macOS suite (потолок MAC-SHAPE):

- `MAC-ESC-001` (high, fs-read) — Shape-A + tail-deny побайтово; read вне
  tail-deny успешен по построению (подтверждение потолка PARTIAL, не FAIL).
- `MAC-PROC-001` (high, proc) — kqueue watchdog + group-kill + sweep 2с
  (BestEffort); destructive только в VM.
- `MAC-SHAPE-001` — побайтовый gate профиля.

Уровни запуска: smoke (малые квоты/seed-наборы, локально) → core → platform
→ destructive/adversarial (только disposable VM/CI-runner) → stress/race
(медиана) → regression (ловушки) → release-gate. Без elevated privileges
локально запускается только smoke/core на Strong тирах; всё destructive,
RES-EXHAUST полный, fuzz-корпус полный — CI-runner/VM.

## Race/stress стратегия

`RACE-TOCTOU-001` + `STRESS-SWEEP-001`: медиана ≥3 (на практике runs=5),
кворум векторов на прогон, sweep-бюджет 2с на BestEffort тирах, ретраи не
превращают FAIL в PASS, расхождение прогонов — INCONCLUSIVE (блокирует gate
в I1–I6 через ноль-INCONCLUSIVE правило). Параллельные spawn только через
`SPAWN_SERIAL` (detect→fork-возврат); параллелится подготовка и judging.

## Fuzzing стратегия

`FUZZ-CORPUS-001` фиксирует контракт: детерминированные seeds в CI, корпус
мутаций path/env/argv0/cwd/locale/symlink-forest, oracle-правило
fail-closed (любое нарушение host-fact границы — FAIL/INCONCLUSIVE).
Находки обязаны становиться новыми векторами/quorum в реестре; сам fuzzer
— вне verify-ng (не production-код enforcement).

## Differential testing стратегия

`TIER-DIFF-001` + `SEC-BLOCKS-001[not_applicable]` + `WIN-*/MAC-*` N/A-секции:
full vs fs-only vs seccomp обязаны совпадать либо слабеть строго
задокументированно; `VETTO_FORCE_TIER` разрешён только в tier-differential
CI job. Кросс-OS differential — через N/A с probe-доказательством, без
молчаливых скипов (иначе `N/A-without-evidence` блокирует gate).

## Кворум и повторы (FM-13)

Multivector-сценарии требуют ≥quorum независимых согласующихся векторов,
иначе INCONCLUSIVE. Stress — медиана ≥3 прогонов. Ретраи не превращают FAIL
в PASS.

## Потолки платформ (FM-11)

- macOS `VFS-READ` — максимум PARTIAL (Shape-A + tail-deny; `MAC-SHAPE-001`
  сверяет профиль побайтово). Strong read-secrecy — только Linux VM.
- Windows per-domain egress без admin — UNPROVABLE (WFP требует elevation).
- `WIN-WSL-001` — UNSUPPORTED baseline; любой PASS — баг oracle.
- Windows evidence — host-fact-only, пока нет HANDLE-capture в backend
  (требует отдельного backend-ревью, не входит в этот план).

## Pipeline (FM-14)

`Engine` — единственный владелец `SandboxHandle`:
Engine → Killer → Collector / HostEvidence → Oracle (чистая функция, без
IO) → Reporter. Oracle не управляет сбором и не касается ОС: весь IO —
в runner/collector/host-evidence, oracle судит готовые структуры.
Host-owned контроль (Stage 2, unix): `ControlChannel` создаётся до spawn,
читающий конец держит хост, токен привязан к `ExecutionIdentity`;
связанные nonce + кворум из verified control собираются только для `Aux`
pipeline-сценариев. Child-writable пути по-прежнему неавторитетны
(`control.txt`, HOME-файлы, stdout, env-echo, exit code — не evidence).
Без verified Aux-контроля `probe_nonce`/`control_nonce` пусты и oracle
структурно даёт INCONCLUSIVE/FAIL; блокеры на direct-exec — всегда
INCONCLUSIVE/FAIL (liveness наблюдается, containment — нет).
Suite-уровень владения (`SuiteRunner`, один scenario — не более одного
исполнения) обязателен для любого будущего backend-wired сьюта.

## Что всё ещё нельзя доказать

См. Prompt-01 §20 и self-review §E: TLS-payload к allowed-API, целостность
`$PROJECT` внутри, side-channels, kernel-0day, полнота логов, привязка хэша
к живому процессу (только непрерывность владения до fork), полнота sweep
при SIGKILL на FS-ONLY/macOS, UDS/IPC-exfil на mac/Win, статистика CI-таймингов.
