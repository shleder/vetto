# verify-ng — Adversarial Security Verification

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
   wait-status, sweep, canary-сравнение, spec-hash). Единственный уровень,
   поддерживающий PASS.
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
`NetMode::label`, tier, backend-describe, argv/env/cwd, nonce, хэш реестра).
Повторная заморозка перед spawn обязана совпасть (`verify_spec_continuity`).

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
Engine → Killer → Collector → Oracle (чистая функция, без IO) → Reporter.
Oracle не управляет сбором: collector всегда собирает фиксированный
суперсет фактов.

## Что всё ещё нельзя доказать

См. Prompt-01 §20 и self-review §E: TLS-payload к allowed-API, целостность
`$PROJECT` внутри, side-channels, kernel-0day, полнота логов, привязка хэша
к живому процессу (только непрерывность владения до fork), полнота sweep
при SIGKILL на FS-ONLY/macOS, UDS/IPC-exfil на mac/Win, статистика CI-таймингов.
