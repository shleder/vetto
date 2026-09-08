# Prompt 09 — Structured Audit + Session Forensics (architecture proposal)

Ветка: `arch/prompt-09`. Production-код не писался. Скоуп: `docs/` (этот файл),
анализ `src/audit/`, `src/report/`, `src/events/`, `src/history.rs`.
`src/verify_ng/` не трогался (чужой скоуп Prompt 01).

## 1. Current audit architecture (что есть в репо)

Источники истины сегодня:

- `src/events/types.rs` — `Event` enum, 12 вариантов: `SessionStarted`,
  `FileObserved{pid,comm,path,access}`, `ExecObserved{pid,argv}`,
  `BlockedAttempt{pid,comm,path,source}`, `NetRequest{host,port,allowed}`,
  `DnsResolved`, `NetEgress{host,ip,port,bytes}`, `NetQuotaExceeded`,
  `SecretMasked{path}`, `Notice{message}`, `SessionTimeout`, `SessionEnded`.
  Сериализация JSONL через `#[serde(tag="event")]`. Честная оговорка уже в коде:
  `FileObserved` — best-effort /proc-poller, пропускает sub-100ms opens;
  `BlockedAttempt` — только при опциональном канале (`--observe-seccomp` /
  kernel audit feed). Enforcement от событий НЕ зависит.
- `src/events/bus.rs` — `tokio::broadcast` 4096, `publish` синхронный,
  fail-open при отсутствии получателей; `Lagged` в потребителях молча
  пропускается (`continue`) — дыра для forensics (см. §20).
- Потребители шины (`src/main.rs:1024-1056`): `JsonlSink` (дефолт
  `~/.vetto/logs/session-<pid>.jsonl` + опциональный `--jsonl`),
  `OsLogSink`, `StatsCollector`, OTEL-subscriber, `DesktopNotifier`.
  Первым паблишится `SessionStarted{pid,tier,net_mode,profile}`
  (`src/main.rs:1057`), затем `SecretMasked` per `deny_resolved` (только Tier FULL)
  или `Notice` о деградации (SECCOMP / fs-only).
- `src/report/stats.rs` — in-memory агрегатор: counts, op_counts, blocked
  (cap 4096 distinct), suspicious через `classifier`, net/dns/egress (cap 500),
  notices (cap 100). `SessionStats` — то, что рендерится в отчёты.
- `src/report/json|html|md|sarif.rs + storage.rs + mod.rs` — отчёты
  `.vetto/reports/vetto-report-<ts>-<pid>-<id>.<ext>`, `O_CREAT|O_EXCL|O_NOFOLLOW`,
  `0600`, symlink/hardlink/fifo отказы; весь JSON прогоняется через
  `sanitizer::sanitize_line` (best-effort). `compare_reports` — CI-дифф двух JSON.
- `src/audit/history.rs` — `AuditRecord` (ts, session_id, agent, command?,
  profile, policy_path?, exit_code, duration, tier, net_mode, blocked_count,
  events_total, report_path?, log_path?) в `~/.vetto/history.jsonl` через
  `record_session_history` (`src/main.rs:1484`); `inspect_session` /
  `inspect_latest_session` ре-конструируют `SessionAuditDetail` парсингом JSONL
  или JSON-отчёта; `vetto audit` — list/filter/since/agent/query + `--recap`;
  `render_session_audit` — 5 секций (fs-denials, net, syscalls, suspicious, recs).
- `src/history.rs` (`.vetto/history`, durations) — только для `--timeout auto`
  (p95×2, floor 300s). К forensics отношения не имеет, не смешивать.
- `src/events/tail.rs` (`vetto events --filter deny|net|files|exec|notice`),
  `src/events/replay.rs` (`vetto replay --speed`), `src/audit/recap.rs`
  (3–5 строк exit-recap, чистые сессии молчат), `src/audit/digest.rs` (daily).
- `docs/schema/session-stats.schema.json` — JSON-контракт отчёта.
- `docs/telemetry.md` — OTEL/opt-in, агрегированные счётчики, не forensics.
- `src/verify_ng/` (Prompt 01): `evidence.rs` (HostFact/Constrained/SelfReport,
  PASS только с host fact), `model.rs` (Verdict×ClaimStrength), `caps.rs`
  (probe-доказательства для NOT_APPLICABLE), `redact.rs` (MAX_DETAIL 2000,
  control-bytes strip, truncation) — переиспользовать как образец, не дублировать.

## 2. Threat model (для чего audit нужен)

Полезен при: incident, policy violation, unexpected egress, forbidden FS attempt,
child escape attempt, secret access attempt, backend failure, degraded fallback,
cleanup failure, споре «что реально было применено». Противник: (a) скомпрометированный/
любопытный агент внутри песочницы (шум, секреты в argv/stdout, fork-бомбы, ключи
в путях, попытки переполнить bus/stats); (b) post-hoc атакующий с доступом к хосту
(правка history.jsonl/отчётов — integrity §9); (c) невнимательный оператор
(шеринг отчёта с секретами — privacy §10). Audit — детекция и доказательство
post-hoc, НЕ enforcement: лог не останавливает атаку, он фиксирует её след.

## 3. Event taxonomy — сопоставление с prompt (Strong/Partial/Unsupported)

Шкала: Strong — событие уже публикуется из доверенного хоста;
Partial — публикуется, но best-effort/опционально/агрегировано с потерями;
Unsupported — нет вообще.

| Prompt event | Статус | Факт в репо |
|---|---|---|
| session created | Strong | `SessionStarted{pid,tier,net_mode,profile}`, `main.rs:1057` |
| policy requested / normalized | Unsupported | нет событий; requested vs effective неразличимы |
| backend selected | Partial | только строки `tier`/`net_mode` внутри `SessionStarted`; `Backend::describe()` никуда не пишется |
| policy compiled / enforcement constructed | Unsupported | `Backend::spawn` молчит; Landlock ABI/ruleset, seccomp-профиль, mount-overlay список не фиксируются (кроме `SecretMasked` per-path) |
| pre-launch verification | Partial | `Notice` о tier-деградации; `verify_status` в recap всегда `"off"` post-hoc; связи с `vetto verify` нет |
| process started / child started | Partial | `ExecObserved{pid,argv}` без ppid/pgid/tree; /proc-поллер best-effort |
| filesystem denial | Partial | `BlockedAttempt` только при опциональном канале; без него — тишина, неотличимая от «чисто» |
| filesystem allow | Partial | `FileObserved` best-effort, sub-100ms пропуски |
| network denial / allow | Strong (broker), Partial (прочее) | `NetRequest{allowed}` из `net_relay.rs`, `DnsResolved`, `NetEgress`, `NetQuotaExceeded` — Strong там, где трафик идёт через брокер; прямой egress вне брокера не виден |
| secret access denial | Partial | `SecretMasked` = факт маскирования (FULL), не попытка доступа; попытка видна только если дошла до `BlockedAttempt` |
| capability downgrade | Partial | `Notice` свободной формы, без структуры ` Capability{name,present,evidence}` (образец — `verify_ng/caps.rs`) |
| verification result | Unsupported | нет события; `SessionStats` не несёт verdict/strength |
| process termination | Partial | `SessionEnded{exit_code,duration}`; сигнал vs exit смешаны (`decode_status` в handle.rs, отрицательные коды) |
| cleanup verification | Unsupported | `sweep_reparented` (proctrack.rs) и `terminate()` ничего не паблишат: число убитых/уцелевших орфанов, бюджет, timeout — теряются |
| backend error | Partial | только `Notice{message}` свободной формы |
| session completed | Strong | `SessionEnded` + `record_session_history` |

Вывод: ядро deny/allow-сетки есть, но нет policy-snapshot, backend-plan,
process-tree, cleanup и verification событий. Главная дыра — отсутствие
негативных доказательств: «чистый» лог неотличим от «наблюдение было выключено».

## 4. Event schema (предлагаемый контракт)

Обёртка поверх существующего `Event` (расширение, не ломка JSONL):

```json
{"v":1,"event_id":"uuid7","seq":1234,"ts":"...","session_id":"session-<pid>",
 "proc":{"pid":1,"ppid":0,"pgid":0,"comm":"..."},"type":"...","policy_hash":"sha256:…",
 "backend":"linux:full","severity":"info|warning|high","decision":"allow|deny|n/a",
 "corr":"…","prev_hash":"…","meta":{…}}
```

- `event_id` uuid7 (сортируемый), `seq` — монотонный счётчик sink-а на хосте;
  разрыв seq = доказательство потерь (`Lagged`), пишется маркером
  `sink-lagged{missed}` (уже есть в `jsonl.rs:62`, но парсеры его игнорируют —
  чинить, не удалять).
- `session_id` обязателен везде (сейчас выводится из pid/имени файла —
  хрупко, коллизии при reuse pid).
- `policy_hash` — sha256 канонического effective-policy (см. §6), одинаковый
  во всех событиях сессии; `requested_hash` отдельно в snapshot-событии.
- `decision` + `severity`: deny без severity=high запрещён схемой.
- `meta` — типизированный per-type, секреты запрещены схемой (см. §10).
- `prev_hash` — hash-chain (см. §9).
- Fail-closed правило схемы: событие `*_denial` без `policy_hash+backend+decision`
  считается malformed и помечается `Notice{m alformed}` — не молча глотается.

## 5. Session schema

Одна запись `session completed` должна содержать: session_id, started/ended_at,
duration, exit (код + `signaled:bool`), requested/effective policy_hashes,
backend{platform,tier,abi/ruleset-summary}, capability set, policy snapshot
ссылку, счётчики (events_total, lost_events, denials, egress allow/deny),
cleanup report, verification block, integrity footer (seq_max, chain_head),
`vetto_version`+build. Сегодня это размазано по трём местам
(JSONL-лог + JSON-отчёт + `AuditRecord`); предложение: JSON-отчёт = session record,
JSONL = event stream, `history.jsonl` = индекс (указатели, не копия).

## 6. Policy snapshot model

Persisted (в отчёт + первым событием `policy.snapshot` после `SessionStarted`):
requested policy (источники layers + их `PolicySourceKind`, CLI-overrides как факт),
effective policy (allow_write/read, deny_resolved, secret_proxies как *паттерны*,
не значения; net allowlist; seccomp-профиль; limits), `Backend::describe()` строкой
+ структурой probe (landlock_abi, userns, full_tier, seccomp_notify, audit_feed),
capability report (`verify_ng::caps::CapabilitySet` — переиспользовать тип),
security level (tier label + `SeccompProfile`), `policy_hash` (sha256 по каноническому
JSON effective), `vetto_version` (`CARGO_PKG_VERSION`, уже пробрасывается в
`VETTO_VERSION` env, `main.rs:836`). In-memory only: raw secret values, host env
значения, полные argv с потенциальными секретами (в snapshot — только `argv0`+
redacted rest). `policy.show --effective` (`policy/explain.rs`) — тот же загрузчик,
что и сессия: использовать его как конструктор snapshot, чтобы requested vs
effective не расходились.

## 7. Process tree model

Сегодня `ExecObserved{pid,argv}` без ppid — дерево невосстановимо.
Предложение (Linux-first, честные оговорки): расширить до
`{pid,ppid,pgid,argv0,argv_redacted,comm}`; источник — /proc-скан в момент exec
(ppid/pgid из `/proc/<pid>/stat`, best-effort, помечать `evidence_tier:
constrained` по шкале `verify_ng/evidence.rs`); FULL-tier дополнительно —
post-mortem сверка через PID-namespace init (host fact). FS-ONLY — только
poll + `sweep_reparented` отчёт. Реконструкция `reconstruct process tree` —
чистая функция над событиями (pid→ppid рёбра), несвязанные pid — `orphan:true`,
не додумывать. macOS: kqueue/fsevents только advisory (Unsupported для дерева);
Windows: Job Object даёт kill-tree, но не exec-tree без ETW (Partial — ETW
опционален, `sandbox/windows/etw.rs`); VM: hypervisor-events out of scope,
только guest-agent маркеры как SelfReport.

## 8. Evidence model (что доказывает, что нет)

Три тира из `verify_ng/evidence.rs` распространить на audit: HostFact
(post-mortem stat, wait status, sweep result, canary, Landlock-apply success —
только это поддерживает сильные утверждения), Constrained (errno-класс + nonce
через seccomp-notify, broker verdicts), SelfReport (stdout-маркеры, argv —
только хинты). Audit trail доказывает: какая политика запрошена/применена
(snapshot+hash), какой backend/tier работал, какие denials наблюдались,
как завершилась сессия и уборка. НЕ доказывает: отсутствие необнаруженных
доступов (наблюдение best-effort), непротиворечивость ядра, отсутствие
kernel-эксплойта. Формулировка в отчёте обязана разделять
«enforced (host fact)» vs «observed (constrained)» vs «no signal (not proof)».

## 9. Integrity / tamper model (без buzzword-криптографии)

Угроза: пост-сессионная правка `~/.vetto/history.jsonl`, JSONL-логов, отчётов
владельцем хоста или малварью с правами пользователя. Честная матрица:

- append-only + `O_APPEND|O_NOFOLLOW|O_EXCL` + fstat-валидация — уже есть
  (`logger/jsonl.rs`, `report/mod.rs`, `report/storage.rs`). Защищает от symlink/
  fifo/hardlink-подмен в момент записи. НЕ защищает от последующей правки файла.
- `seq` + `sink-lagged` маркеры — детект потерь в пределах одного файла.
  НЕ защищает от удаления суффикса.
- hash-chain (`prev_hash`, sha256, verify в `vetto audit --verify-chain`) —
  детект вставки/перестановки/правки середины; НЕ защищает от truncation
  (нужен out-of-band head: seq_max+chain_head в `history.jsonl` + в отчёт) и
  НЕ защищает от полной перезаписи атакующим, контролирующим хост целиком.
- Ed25519-подпись отчёта (`policy/crypto.rs` уже умеет sign/verify для policy —
  переиспользовать ключ `~/.vetto/signing.key`) — доказывает авторство хоста
  на момент подписи третьему лицу; НЕ доказывает правдивость содержимого
  (подписывается то, что собрал тот же хост) и бесполезна, если ключ на том же
  хосте скомпрометирован. Поэтому: подпись — опциональная (`--sign-reports`),
  по умолчанию выкл; chain — по умолчанию вкл (дешёвый, без ключей).
- trusted host writer: writer = хост-процесс vetto (не песочница) — уже так;
  зафиксировать инвариант: события изнутри песочницы никогда не принимаются
  напрямую, только host-наблюдения (broker, notify, post-mortem).
- `verify_ng` остаётся единственным security verifier; audit — свидетель,
  не судья (требование prompt §Verification coupling).

## 10. Secret redaction model (как не сделать forensics каналом утечки)

Текущее состояние: три разных редктора — `logger/sanitizer.rs` (JSONL+reports,
BEST-EFFORT, честно документирован), `pty/redact.rs` + `pty/ansi.rs`
(Aho-Corasick, live stdout), `verify_ng/redact.rs` (MAX_DETAIL+control-strip+
truncate). Дыры (adversarial): `logger/system_log.rs` и `logger/oslog.rs`
форматируют события БЕЗ санитайзера (`system_log.rs:44-57`,
`oslog.rs:27-43`, `_ => format!("{:?}", ev)` — полный Debug-дамп, включая
`ExecObserved.argv` целиком); `audit/history.rs` хранит `command` как
`argv.join(" ")` без редакции и ищет по нему (`filter_records`); TUI
`format_event_row`/`describe` показывают полные пути/argv; `NetEgress.ip`
и `DnsResolved.ips` — потенциальный exfil-сигнал через DNS в логах — хранить
агрегированно (counts per domain), не каждый IP.

Предложение — классификация полей, не «ещё один regex»:

- `public`: tier, backend, counts, exit_code, duration, hashes — без редакции.
- `operational`: пути deny, host allowlist-домены, comm — санитайзер + cap длины
  (borrow `MAX_DETAIL` 2000 + truncate-маркер из `verify_ng/redact.rs`).
- `sensitive`: argv (кроме argv0), env, Notice-тексты, stdout-производные —
  redact-by-default: хранить `argv0` + `argc` + `argv_hash`, полный текст только
  с `--include-argv` и явным `Notice{argv_redacted:true}`; ключи/значения —
  только имена ключей, значения `[REDACTED]`.
- `forbidden`: raw credentials, PEM-body, bearer-значения, полные env-дампы —
  запрещены схемой; продюсер обязан не эмитить (fail-closed: sink дропает
  событие с forbidden-паттерном и пишет `Notice{redaction_drop}` вместо тишины).
- Единый `redact_text` на выходе заимствовать из `verify_ng/redact.rs`
  (control-strip + cap), токенные паттерны — из `logger/sanitizer.rs`;
  journald/oslog/eventlog-sink прогнать через тот же pipeline (сейчас голые).
- Escape: все рендеры (TUI/replay/report-html) обязаны escape control-bytes
  и ANSI (TUI уже частично через `AnsiRedactor`; replay `describe_replay_event`
  печатает `argv.join` и `path` голыми — чинить).

## 11. Storage format (JSONL vs SQLite vs CBOR)

- JSON Lines — текущий, оставить как primary event stream: append-friendly,
  grep-able, CI-простой (`jq`), работает с O_APPEND+NOFOLLOW, переживает
  падение mid-session (каждая строка самодостаточна). Минусы: нет индекса,
  повторный парсинг для `audit <id>` O(n). Приемлемо для CLI-объёмов.
- SQLite — отклонить для event stream: WAL+fsync-сложности при SIGKILL-уборке,
  lock-контеншн с sink-thread, риск «база бита — всё потеряно», тяжелее
  `O_NOFOLLOW`-инварианты; рассмотреть позже только как опциональный индекс
  (`vetto audit --index`) поверх JSONL, не как источник истины.
- CBOR/binary — отклонить: нечитаемо в CI, не grep-абельно, ноль выигрыша
  при текущих объёмах (busy-сессия ~10^4 событий).
- Решение: JSONL (events) + JSON (session report, схема
  `docs/schema/session-stats.schema.json` расширена §4-5) + JSONL
  (`history.jsonl` как индекс с chain_head). Миграция — аддитивная,
  старые файлы читаются (версионирование `"v":1`, неизвестные поля игнорить).

## 12. CLI / reporting (предлагаемые запросы поверх существующего)

Существует: `vetto audit [--latest|<id>|--since|--agent|--limit|query|--json|--recap]`,
`vetto events --filter deny|net|files|exec|notice [--follow|--json]`,
`vetto replay [--speed]`, `compare_reports`, recap, digest. Добавить (новые
флаги/сабкоманды, без ломки старых): `--filter secret` (SecretMasked +
secret-classified denials), `--filter degraded` (Notices о tier-fallback +
capability.absent), `--filter cleanup` (sweep/orphan события),
`vetto audit --verify-chain <id>` (пересчёт hash-chain + сверка head),
`why-denied <path>` (= `policy explain` + релевантные BlockedAttempt из лога),
`reconstruct --tree` (дерево из §7), `reconstruct --policy` (snapshot+hash),
`--include-argv` (opt-in, с redaction-маркером). Все новые выводы — через
единый санитайзер; `--json` остаётся машиночитаемым контрактом.

## 13. TUI implications

`src/tui/app.rs` (LiveEventAggregator, ring, фильтры), `full.rs` (PTY +
AnsiRedactor), `statusline.rs` (live redact) — уже фильтруют
deny/net/files/exec/notices. Добавить: бейдж integrity (`seq gaps: N`,
`chain: ok/broken`), бейдж наблюдения (`observation: full/partial/off` —
устраняет «тишина = чисто»), фильтр `degraded`/`cleanup`, redacted-рендер
argv (только argv0 по умолчанию). TUI — потребитель той же схемы §4,
никакой отдельной семантики событий.

## 14. Linux events (evidence)

FULL: Landlock-apply (ruleset summary, ABI — host fact), mount-overlay per
deny_resolved (уже `SecretMasked`), netns/broker verdicts (уже), seccomp-notify
BlockedAttempt (уже, опционально), PIDns teardown + sweep count (НОВОЕ —
cleanup event), audit-feed denials (уже через `audit_reader.rs`, опционально).
FS-ONLY: sub-reaper + `sweep_reparented` отчёт (НОВОЕ, иначе escape-attempt
невидим); честный `Notice` о carve-out вместо overlay (уже). SECCOMP-only:
только syscall/net сигналы + громкий `Notice` (уже); FS-события помечать
`observation: off`, не «0 denials».

## 15. Windows events

Источники есть (`etw.rs`, `eventlog.rs`, `job_object.rs`, `firewall.rs`,
`restricted_token.rs`, `appcontainer.rs`, `windows_sandbox.rs`,
`minifilter.rs`), но в `Event` не проброшены. Предложение: маппить в ту же
схему §4: Job Object kill-on-close → cleanup event (Strong — kernel-объект);
WFP verdicts → NetRequest (Partial — только при включённом провайдере);
AppContainer/restricted-token construction → enforcement-constructed
(Strong, host fact); minifilter — только при наличии сервиса + ImagePath-match
(иначе `capability.absent`, fail-closed, не silent); ETW — Constrained,
опционально. Windows Sandbox (VM-путь) — см. §16.

## 16. macOS / VM events

macOS: Seatbelt-profile apply факт (Strong, host), fsevents (`fsevents.rs`) —
advisory only (Unsupported для enforcement-доказательств), net_proxy verdicts
→ NetRequest (Partial), `oslog` sink — прогнать через санитайзер (§10).
VM (`--backend win-sandbox`, uniform VM path): hypervisor-guarantee вне зоны
доказательств vetto — только guest-agent SelfReport-маркеры + host-side
launch/teardown факты (VM started/stopped, image hash); e2e-изоляцию audit
НЕ заявляет (Unsupported, честно).

## 17. Verification integration (`vetto verify` + `verify_ng`)

Не дублировать: переиспользовать `verify_ng::{evidence::EvidenceTier,
caps::CapabilitySet, redact::{redact_text,MAX_DETAIL}, model::{Verdict,
ClaimStrength}}` как общие типы (вынести в `src/evidence/` при реализации —
этот переезд тоже часть плана). Audit-события получают поле
`evidence_tier`; session report получает `verification:{verdict, strength,
registry_hash}` блок, заполняемый ТОЛЬКО `verify_ng`-хarness-ом, никогда
self-reported сессией. Инвариант: audit без host facts не может поднять
strength выше Partial; `verify` читает audit как вход (что наблюдалось),
а вердикт строит своими пробами.

## 18. Repo / module changes (только файлы, без кода)

- `src/events/types.rs` — envelope §4 (event_id/seq/session/proc/policy_hash/
  backend/severity/decision/corr/prev_hash), новые варианты:
  `PolicySnapshot`, `BackendSelected`, `EnforcementConstructed`,
  `PrelaunchCheck`, `ChildStarted{ppid,pgid}`, `CapabilityDowngrade`,
  `VerificationResult`, `CleanupReport`, `BackendError`; `ExecObserved` +
  ppid/pgid/argv_redacted. Миграция аддитивная (`"v"` + `#[serde(default)]`).
- `src/events/bus.rs` — счётчик seq на publish-стороне; `Lagged` превратить
  в явное событие, не `continue`.
- `src/logger/jsonl.rs` — простановка seq/prev_hash/session_id в sink,
  маркеры потерь парсабельны; forbidden-паттерн → `redaction_drop`, не тишина.
- `src/logger/system_log.rs`, `src/logger/oslog.rs` — пропустить через общий
  санитайзер (сейчас голый формат — exfil/secret-дыра).
- `src/policy/explain.rs` — конструктор policy snapshot + `policy_hash`
  (sha256 канонического JSON); `why-denied` reuse.
- `src/sandbox/mod.rs` — `Backend::describe()` структурно + publish
  `BackendSelected`; fail-closed при unknown backend уже есть — сохранить.
- `src/sandbox/linux/mod.rs` + `landlock.rs` + `mounts.rs` — publish
  `EnforcementConstructed` (ABI/ruleset/mask-count); `proctrack.rs` +
  `handle.rs` — publish `CleanupReport` (killed/reaped/survivors/budget).
- `src/sandbox/linux/net_relay.rs`, `observe_seccomp.rs`, `audit_reader.rs` —
  добавить policy_hash/corr/backend к существующим publish (контекст сессии).
- `src/sandbox/windows/*`, `src/sandbox/macos/*` — маппинг §15-16 в общий `Event`.
- `src/report/stats.rs` — агрегация новых счётчиков (lost_events, cleanup,
  degraded) + caps preservation; сохранить caps 4096/500/100.
- `src/report/json.rs` + `docs/schema/session-stats.schema.json` — session
  schema §5 (snapshot-ссылка, hashes, backend, cleanup, verification,
  integrity footer); html/md/sarif — те же поля, escape control/ANSI.
- `src/audit/history.rs` — `AuditRecord` + chain_head/seq_max/policy_hash/
  backend; `append_record_to_file` — O_NOFOLLOW-аналог jsonl (сейчас голый
  `OpenOptions::append` — symlink-дыра); `command` — redacted argv0-only
  по умолчанию; `--verify-chain`, `why-denied`, `reconstruct`.
- `src/events/tail.rs` — фильтры secret/degraded/cleanup; `replay.rs` —
  escape argv/path; `audit/recap.rs` — бейджи observation/integrity.
- `src/tui/*` — те же фильтры/бейджи, redacted argv.
- `src/evidence/` (новое, вынос из `verify_ng/`) — общие
  EvidenceTier/Capability/redact типы для audit и verify.
- `docs/schema/` — `audit-event.schema.json` (новое), расширение
  `session-stats.schema.json`; `docs/telemetry.md` — границу audit vs telemetry
  зафиксировать (forensics никогда не уходит на внешний endpoint).
- Тесты: chain-verify, redaction-adversarial (argv/env/PEM/journald/oslog),
  seq-gap детект, snapshot-hash стабильность, cleanup-report наличие,
  TUI-escape. (Покрытие — при реализации, не здесь.)

## 19. Migration strategy

Фаза 0: схема + снапшот-хэш + envelope поверх текущего `Event`
(аддитивно, `"v":1`, старые логи читаются). Фаза 1: backend/cleanup/
capability события (Linux first), санитайзер в journald/oslog, O_NOFOLLOW
для history. Фаза 2: Windows/macOS маппинг, `why-denied`/`reconstruct`/
`--verify-chain`, TUI-бейджи. Фаза 3: опциональная Ed25519-подпись отчётов
(`--sign-reports`, ключ из `policy/crypto.rs`), SQLite-индекс опционально.
Каждая фаза — minor +0.0.1 по VERSIONS.md, major всегда 0. Инвариант фаз:
ни одна фаза не меняет enforcement; только наблюдение.

## 20. Security limitations (честные границы)

1. Лог не доказывает enforcement: отсутствие denials при выключенном
   наблюдении неотличимо от чистоты — лечится бейджем `observation:` (§13-14),
   а не большим логом. Silent downgrade детектится только связкой
   snapshot(teir/backend/caps) + `BackendSelected` + degraded-Notices;
   один `Notice` свободной формы недостаточен — поэтому структура §4.
2. Broadcast-losses (`Lagged→continue`, `stats` caps, net caps 500) —
   атакующий шумом может вытеснить события; seq-gaps делают это видимым,
   но не предотвращают. Stats-агрегаты — не доказательства, только хинты.
3. Hash-chain ловит правку середины, но не truncation и не полную перезапись
   атакующим с правами пользователя; подпись ловит авторство, но не правдивость
   и умирает вместе с ключом на том же хосте. Модель: детект opportunistic-
   правок, не защита от root/владельца хоста.
4. Forensics-стор сам exfil-канал: argv/env/пути/IP в логах, отчёты, journald,
   oslog, TUI-экспорт — лечится классификацией §10 (redact-by-default,
   argv0-only, forbidden-drop, единый pipeline везде включая system_log/oslog,
   caps на размеры). Любой новый sink обязан пройти redaction-review.
5. Escape через логи: control/ANSI bytes в путях/argv/hostnames рендерятся в
   TUI/replay/HTML — обязательный strip+escape (образец `verify_ng/redact.rs`).
6. Session report пригоден для независимого review если: канонический JSON +
   JSON-схема, policy snapshot + hashes, backend/caps блок, разделение
   enforced/observed/no-signal, redaction-маркер (`redacted:true` + метод),
   chain-head для проверки целостности, версия vetto. Без этих шести —
   это маркетинг, не evidence.
7. `command` в истории сегодня — голый `argv.join` с поиском по нему:
   до миграции либо redact, либо не хранить; хранить секретосодержащую строку
   ради удобства поиска — неприемлемый trade-off.

## Critical review (ответы на 5 вопросов prompt)

1. Что audit доказывает / не доказывает: доказывает запрошенное vs применённое
   (при snapshot+hash), backend/tier-факт, наблюдаемые denials, исход и уборку
   (при cleanup-событиях). НЕ доказывает отсутствие пропущенного наблюдения,
   отсутствие kernel-обхода, правдивость при скомпрометированном хосте.
2. Обязательные события для IR: PolicySnapshot, BackendSelected,
   EnforcementConstructed, все denials (fs/net/secret/syscall) с decision,
   ChildStarted(process tree), CleanupReport, BackendError, SessionEnded +
   seq/integrity footer. Без любого из них картина неполна.
3. Silent downgrade: детект = `requested.tier != effective.backend` или
   `Capability.absent` без явного `degraded:true` + alert в recap/TUI;
   молчаливый фолбэк без события — запрещён схемой (fail-closed Notice).
4. Forensics как канал утечки: закрывается классификацией полей (§10) +
   единым pipeline + forbidden-drop + argv0-only + caps; самая острая дыра
   сегодня — голые system_log/oslog-sink и `command` в history.
5. Пригодность для независимого review: шесть условий из п.6 §20; текущий
   отчёт им не удовлетворяет (нет snapshot/hash/backend/caps/chain/
   enforced-vs-observed), после §4-6, §9 — удовлетворяет.

## Implementation plan (по фазам, без кода)

- P0 (схема): envelope §4 + `audit-event.schema.json`; session schema §5;
  policy snapshot + hash из `explain.rs`; seq в bus/sink; парсеры учат `"v"`.
- P1 (Linux evidence + hygiene): BackendSelected/EnforcementConstructed/
  CleanupReport/CapabilityDowngrade publish; policy_hash/corr во все publish;
  санитайзер в system_log/oslog; O_NOFOLLOW для history; command redact;
  фильтры secret/degraded/cleanup; `--verify-chain`.
- P2 (поритет + UX): Windows/macOS маппинг §15-16; why-denied/reconstruct;
  TUI-бейджи observation/integrity; вынос `src/evidence/` из verify_ng.
- P3 (опционально): `--sign-reports` (Ed25519 из `policy/crypto.rs`);
  SQLite-индекс поверх JSONL; старые артефакты — read-only совместимость.

## Acceptance criteria

- [ ] `vetto audit --verify-chain` проходит на свежих сессиях, детектит
      ручную правку середины лог-файла и сообщает о truncation через head.
- [ ] Чистая сессия с выключенным наблюдением показывает
      `observation: off`, а не «0 denials»; silent downgrade tier даёт
      явный degraded-сигнал в recap/TUI/audit.
- [ ] Каждая сессия содержит PolicySnapshot с совпадающим policy_hash во всех
      событиях; requested vs effective различимы; версия vetto зафиксирована.
- [ ] CleanupReport присутствует всегда (FULL: pidns-teardown факт; FS-ONLY:
      sweep killed/reaped/survivors/budget); escape-попытка видна в audit.
- [ ] Adversarial redaction-тесты зелёные: argv/env/PEM/bearer/jwt в событиях,
      отчётах, journald/oslog-выводе, `history.jsonl`, TUI-экспорте —
      отредактированы; caps на размеры держат (bus-flood не роняет хост).
- [ ] `why-denied`, `reconstruct --tree`, `reconstruct --policy`,
      secret/degraded/cleanup-фильтры работают на Linux; Windows/macOS —
      с честными Partial/Unsupported-бейджами, без завышенных заявлений.
- [ ] JSON-отчёт валидируется расширенной `session-stats.schema.json`;
      старые логи/отчёты читаются; enforcement не изменён (дифф — только
      наблюдение); версионирование +0.0.1, major 0.
