# Security Levels + Capability-Aware Policy — архитектурное предложение (Prompt 08)

Ветка: `arch/prompt-08`. Production-код не пишется. `src/verify_ng/` не затронут.
Статус каждого требования prompt: **Strong** (уже есть фундамент), **Partial** (есть частично, нужны изменения), **Unsupported** (нет, проектировать с нуля).

## 1. Current modes inventory

CLI (`src/cli.rs`, `src/config.rs`): `--profile` (default `default`), `--preset paranoid|balanced|yolo`,
`--policy PATH`, `--net off|allowlist:|strict:|ask`, `--backend auto|process|win-sandbox`, `--lpac`,
`--observe-seccomp`, `--shadow`, `--verify`, `--dry-run`, `--ci`, `--limits SPEC`, `--fail-on-block`,
`--git-ssh`, `--mask-secrets/--no-mask-secrets`, `--deny-glob`, `--git-guard`, `--snapshot/--ephemeral`,
`--auto-deny-secrets`. Пресеты (`src/policy/presets.rs`): paranoid (net off), balanced/yolo (net allowlist
по агенту). Профили (`profiles/*.toml`): default/strict/audit/permissive — различаются только FS/env/limits,
сеть ими не управляется (сеть — вне policy, `Policy::deny_network` лишь intent, `src/policy/types.rs:253`).

Реальные тиры исполнения: Linux Full / FsOnly / **Seccomp** (`src/policy/types.rs:9`, `src/sandbox/linux/mod.rs:108`);
macOS Seatbelt; Windows AppContainer/LPAC+Job; Windows Sandbox VM (opt-in `--backend win-sandbox`).
`VETTO_FORCE_TIER` — только downgrade-тест, bypass невозможен (`linux/mod.rs:106`).

Несоответствия, найденные в репо (не принимать prompt на веру, не принимать и docs на веру):

- **F1. Tier Seccomp недокументирован.** `SECURITY.md` знает только FULL/FS-ONLY; код имеет третий тир
  `Tier::Seccomp` — только seccomp-фильтр и лимиты, **без filesystem-изоляции вообще**
  (`spawn_seccomp_only`, `linux/mod.rs:1489`; `explain.rs:211` честно пишет `unmasked-filesystem-seccomp-only`).
  Это главный кандидат на «называет слабый режим sandboxed».
- **F2. Exit-код fail-closed противоречив.** `docs/threat-model.md:110` обещает `103`,
  `src/exit_codes.rs:16` и `docs/exit-codes.md:10` — `125`. Docs врут в одну из сторон.
- **F3. README обещает несуществующий код.** README (`README.md:168`) заявляет uniform VM path
  `mac-vm` (Virtualization.framework) и WSL2-guest+sync-back как дефолт на macOS/Windows.
  Grep по `src/`: `mac-vm|mac_vm|VmConfig` — **0 совпадений**. Docs ahead of code; в матрицах ниже
  mac-VM помечен Unsupported.
- **F4. Сеть тихо расширяется при auto-detect.** `src/config.rs:211` — дефолт `NetMode::Off` (Strong, задокументирован),
  но `src/main.rs:532` и `:202` при zero-config auto-detect переключают `Off → Allowlist(домены агента)`.
  Дефолт `off` реален только при явном агенте/флаге; Detected-путь — silent widening. Опасный дефолт.
- **F5. Lint не ловит `allow_read=["/"]`.** `lint.rs` R2 ловит только read-root `== $HOME`; пресет `yolo`
  ставит `allow_read=["/"]` (`presets.rs:273`) — линт молчит. Плюс `yolo allow_write` включает `$HOME`
  (R1 ловит, severity high — ок), но связка `yolo + agent preset` нигде не ранжируется по силе.
- **F6. `--dry-run` врёт про тир при недоступном бэкенде.** `main.rs:644` — при failed detect + dry-run
  подставляется воображаемый `Tier::Full`. Dry-run показывает политику, которой не будет.
- **F7. `--shadow` персистентен через global config** (`config.rs:305`) и гасит **два** fail-closed пути:
  verify-leaks (`main.rs:805`) и fail-on-block (`main.rs:1353`). Shadow для верификации — легитимный
  use-case, но shadow для fail-on-block стирает границу enforcement/observation.
- **F8. `Tier::Seccomp` молча принимает relay-требование?** Нет — ок: `linux/mod.rs:150` + `main.rs:781`
  реджектят relay на FsOnly/Seccomp до спавна. Strong, сохранить как compile-rule.

## 2. Threat model (дельта к `docs/threat-model.md`)

База уже сильная: агент = произвольный код юзера; enforcement ≠ observation; non-goals зафиксированы.
Для levels добавить: (a) **adversarial capability downgrade** — злоумышленник (или баг), управляющий env
(`VETTO_FORCE_TIER`, global config) или project policy, не должен мочь ослабить уровень без explicit opt-in;
(b) **exfiltration через allowlist-сеть** — prompt-injection в разрешённый API остаётся out-of-scope, уровень
обязан это декларировать, а не скрывать; (c) **escape-классы по тирам**: FS-ONLY `setsid`-orphans,
Seccomp — отсутствие FS-изоляции полностью, macOS — broad reads, Windows — no unprivileged LSM;
(d) **late-created secrets** (`$PROJECT/.env`, созданный после старта) — не маскируется ни на одном тире,
уровень обязан это говорить.

## 3. Security level semantics (предложение)

Вердикт по именам: `strict/standard/compat` из prompt — плохи тем же, чем плохи `secure/strong`:
прилагательные без семантики. Предлагаю имена-обязательства: **`lockdown` / `standard` / `compat`**
с машиночитаемым `guarantees[]` в каждом выводе. `compat` честно содержит слово «совместимость»,
а не «безопасность».

| Гарантия | `lockdown` | `standard` (дефолт) | `compat` (explicit opt-in) |
|---|---|---|---|
| filesystem | мин. write (`$PROJECT`+/dev/null), мин. read, secret-overlays обязательны | write `$PROJECT`+`/tmp`, toolchain reads, overlays обязательны | широкие reads допустимы, overlays best-effort; каждый пробел — в отчёте |
| network | `off`, relay запрещён на компиляции | `off` либо allowlist/strict по backend-возможностям | `ask` допустим; allowlist только через broker |
| process | PID-ns / Job kill-on-close обязательны; `setsid`-escape недопустим | best available, escape-окно декларируется | watchdog-допуски с явным флагом |
| secrets | deny-list non-overridable (см. §6), env allowlist-only, API-ключи агентов только через broker/`secret_proxies` | то же, минус часть toolchain-deny | env-расширения только явными флагами, каждое — в `policy explain` |
| environment | минимальный passthrough | default passthrough | расширения видны в dry-run diff |
| resources | лимиты обязательны (lint R5 → high) | лимиты дефолтны, отсутствие — warn | отсутствие — warn + запись в отчёт |
| cleanup | snapshot/rollback где поддерживается | best-effort | best-effort |
| verification | `--verify` обязателен перед стартом, leak = отказ без override | leak = отказ, `--shadow` только логирует | leak = отказ; shadow запрещён |
| fallbacks | запрещены все | только Full→FsOnly с явным флагом и бейджем `degraded` | любой downgrade — только explicit opt-in, каждый — в отчёт |

Non-overridable гарантии (ответ на critical review): secret deny-list ядра (`standard_secret_deny_paths`),
env default-deny, `strictest-wins` для лимитов, запрет relay вне FULL, запрет запуска без бэкенда.

## 4. Capability schema

```toml
[capability.fs.write_deny]  status = "enforced"   # enforced|partial|unavailable|degraded|virtualized
[capability.fs.read_deny]   status = "partial"     # + evidence = "verify:deny-path"
[capability.net.off]        status = "enforced"
[capability.net.allowlist]  status = "unavailable" # + reason = "no netns on this backend"
[capability.process.reap]   status = "degraded"    # + reason = "setsid escape window, FS-ONLY"
[capability.secret.overlay] status = "unavailable"
[capability.env.isolation]  status = "enforced"
[capability.resource.ceiling] status = "enforced"
[capability.cleanup.rollback]  status = "partial"
```

Статусы: `enforced` (ядро/платформа гарантирует, есть verify-тест), `partial` (гарантия с известным окном,
окно названо), `unavailable` (backend не умеет — только fail-closed или explicit opt-in), `degraded`
(запрошенное ослаблено с согласия — всегда с бейджем), `virtualized` (гарантия исходит от VM, не хоста).
Схема одна на всех (`src/policy/capability.rs` новый), значения — на бэкенд (`capabilities()` рядом
с каждым `spawn`, по образцу `windows::capabilities()` / `linux::probe()`).

## 5. Backend capability reporting

Каждый backend возвращает `CapabilityReport` до спавна: machine-readable (JSON в `policy explain --json`,
`doctor --json` — новый флаг) + human-readable (таблица в `doctor`). Источники: Linux — существующий
`linux::probe()` (Strong) + новый маппинг probe→статусы; macOS — `seatbelt_available()` +
`probe_sbpl_read_fragment()` (Strong); Windows — `windows::probe()` + `optional_backend_report()`
(Strong). Новое: WinSandbox и будущий mac-VM отчитываются как `virtualized`, а не `enforced`.

## 6. Policy compilation rules (`requested → capabilities → compile → validate → execute`)

Новый модуль `src/policy/compiler.rs` (Partial: куски есть в `main.rs:781`, `linux/mod.rs:150`,
`macos/mod.rs:60`, loader — собрать в одно место). Правила: `strict net=off` на backend без net-deny →
**отказ**, не downgrade (пример из prompt — уже так, закрепить правилом R-NET-01); relay вне FULL →
отказ (R-NET-02, уже есть); secret-deny вне coverage тира → отказ, кроме `compat` с opt-in (R-SEC-01,
закрывает F1: Seccomp-тир больше никогда не стартует «тихо»); `yolo allow_read=["/"]` → минимум warn,
в `lockdown` → отказ (R-FS-01, закрывает F5); auto-detect не вправе расширять сеть (R-NET-03, закрывает F4:
detected-путь обязан спрашивать/оставаться off); preset `yolo` несовместим с `lockdown` (R-LVL-01).

## 7. Fallback/downgrade semantics

Warning допустим только для observation/visibility (audit feed, FSEvents, R5-отсутствие лимитов в standard).
Failure обязателен для: сеть, FS-изоляция, secret-маскировка, отсутствие бэкенда, verify-leak
(кроме shadow в standard). Explicit opt-in downgrade: `--compat` + `--allow-degraded <что>` поимённо,
каждый — в dry-run, statusline-бейдж `degraded`, отчёт. Automatic refusal — дефолт везде. `--shadow`
разделить: `--shadow-verify` (наблюдение) vs запрет shadow для fail-on-block (закрывает F7).

## 8. UX/CLI

`--security-level lockdown|standard|compat` (дефолт `standard` = сегодняшнее поведение минус F4),
`--allow-degraded`, `--shadow-verify` вместо `--shadow`, `doctor --json`, `policy explain` показывает
`level + guarantees[] + degraded[] + backend + vm? + fallback?`. Statusline-бейдж уровня; никакого
зелёного «sandboxed» без перечисления активных гарантий (закрывает misleading-green-check).
`dry-run` при недоступном бэкенде пишет `tier: unavailable`, а не воображаемый Full (закрывает F6).

## 9–12. Capability matrices

### Linux Full — Strong (есть код + verify)

| Измерение | Статус | Evidence |
|---|---|---|
| FS write/read deny | enforced | Landlock ABI 1–6 + overlays; verify `deny-path`, `write-outside` |
| net off | enforced | netns; verify `net-loopback` |
| net allowlist/strict | enforced | broker + DNS-pinning; relay-код |
| process reap | enforced | PID-ns init; kill-стратегия `PidNsPipe` |
| secret overlay | enforced | tmpfs//dev/null binds; verify |
| env | enforced | allowlist-only; `environment_tests` |
| resources | enforced | rlimits+cgroup перед exec |
| cleanup | partial | snapshot best-effort, 50MB-лимит молча пропускается (`main.rs:727`) |

### Linux FsOnly — Partial (честно задокументирован, окно названо)

FS deny — enforced-via-carveout (имена видны, контент запрещён); relay — unavailable→отказ;
reap — degraded (`setsid`-окно, subreaper+sweep best-effort); overlays — unavailable (компенсация enumeration).

### Linux Seccomp — Partial→необходимо переименовать

Сегодня: NO FS backend вообще. Статус FS/read/secret — `unavailable`. Правило: уровни выше `compat`
на нём отказываются; в `compat` — только с `--allow-degraded fs,read-deny,secrets` и красным бейджем.
**Запретить слово «sandboxed» для этого тира без квалификатора** (F1 — главная дыра нейминга).

### macOS native — Partial

write — enforced (SBPL Shape A); read-deny — partial (broad reads + tail-deny, dyld #62);
net off — enforced, allowlist/strict/ask — unavailable→отказ (уже есть); reap — degraded (kqueue watchdog);
overlays — unavailable. Verify battery на macOS существует (`verify.rs`), но `probe-stderr`/FSEvents —
observation, не enforcement.

### macOS Linux-VM / Windows WSL2 — Unsupported в коде

README заявляет (F3), кода нет. Матрица: после реализации — всё `virtualized`, verify внутри геста,
хост-сторона отчитывается `virtualized`, не `enforced`. До реализации — docs обязаны помечать «план».

### Windows native — Partial

FS/process — enforced-via-AppContainer/LPAC+Job (админ-прав не требует); per-domain WFP —
unavailable без admin opt-in → отказ, не degrade (уже так); overlays/mounts — unavailable;
verify battery — unavailable на Windows (`verify.rs:156`), только capability probe.

### Windows Sandbox VM — Partial

Всё `virtualized`, opt-in `--backend win-sandbox`, fail-closed без Hyper-V (уже есть,
`sandbox/mod.rs:74`). Verify внутри VM — будущая работа.

## 13. Verification integration

Связь `Capability → invariant → scenario → evidence`: каждый `enforced`-статус обязан иметь verify-сценарий
с stable-id (`deny-path`, `net-loopback`, `write-outside` уже есть — Strong). Новое: unit-тесты компилятора
на каждую R-*** (отказ, а не downgrade), lint-правила как инварианты уровней (R1/R2 → high в lockdown),
`doctor --probe` и `--verify` обязаны печатать активный level. Непокрытое (окна без сценария: `setsid`-orphan
на FS-ONLY, late-created `.env`, WSL-interop) — статус не выше `partial`, в отчёте как known-limitation.

## 14. Docs/security claims model

Каждое клеймо в `README.md/docs/*.md` получает класс: `enforced` (код+verify+ссылка), `platform-limited`
(со ссылкой на матрицу), `plan` (без кода — запрещено настоящее время, см. F3). Фиксы: exit-код `103→125`
в threat-model (F2), задокументировать Tier Seccomp (F1), пометить mac-VM/WSL2-guest как plan (F3),
дефолт сети описать с auto-detect-исключением до закрытия F4, `compat.md` «✅ Verified» для агентов —
привязать к тиру (verify-бейджи сегодня без указания тира исполнения).

## 15. Repo/module changes (файлы)

| Файл | Изменение |
|---|---|
| `src/policy/capability.rs` (new) | схема статусов, `CapabilityReport`, JSON/human рендер |
| `src/policy/compiler.rs` (new) | R-NET-01/02/03, R-SEC-01, R-FS-01, R-LVL-01; `requested→compile→validate→execute` |
| `src/policy/types.rs` | `SecurityLevel` enum, `Policy.level`, `degraded[]` в `Policy` |
| `src/policy/lint.rs` | R2 расширить на предков `/` и `$HOME`; R5 severity по уровню; новое R-FS для `yolo⊂lockdown` |
| `src/cli.rs`, `src/config.rs` | `--security-level`, `--allow-degraded`, `--shadow-verify` (deprecated `--shadow`), dry-run `tier: unavailable` |
| `src/main.rs` | вызов compiler до policy-load; убрать silent net-widen при auto-detect; разделить shadow-пути; dry-run честность |
| `src/sandbox/linux/mod.rs` | expose probe→capability mapping; Seccomp-тир отдаёт `unavailable` по FS |
| `src/sandbox/macos/*`, `src/sandbox/windows/*` | capability-маппинги, без изменения enforcement |
| `src/doctor/*` | `doctor --json`, capability-таблица, level в выводе |
| `src/policy/explain.rs`, `src/cli/status.rs` | level + guarantees + degraded-бейджи |
| `src/verify.rs` | level в `VerifyReport`, связка capability→сценарий |
| `docs/*.md`, `README.md`, `SECURITY.md` | claims-классы, F1–F8 фиксы, матрицы 9–12 |
| `docs/security-levels-proposal.md` (new, этот файл) | архитектурный документ |

`src/verify_ng/` — не трогать.

## 16. Migration plan

1. Типы+схема (`capability.rs`, `types.rs`) — additive, дефолт `standard` = текущее поведение.
2. Compiler с правилами-отказами за флагом, затем по дефолту; F4/F6 фиксы — сразу (баги, не фичи).
3. CLI/UX (`--security-level`, бейджи, `doctor --json`).
4. Docs-классы + F1/F2/F3 правки.
5. VM-путь (mac-VM/WSL2-guest) — отдельный эпик, до него docs только `plan`.
6. Версия: +0.0.1 по политике репо (факт: `Cargo.toml` сейчас `0.2.18`, `VERSIONS.md` в worktree нет —
   сверить с основным репо перед релизом, прыжков и пропусков номеров нет).

## Critical review (вывод)

- Слабый режим под именем «sandboxed»: **Tier Seccomp без FS-изоляции** (F1) — единственное место,
  где слово «sandbox» сегодня технически ложно без квалификатора.
- Опасные дефолты: silent net-widen при auto-detect (F4); персистентный `--shadow` на fail-on-block (F7).
- Compat→bypass: `yolo allow_read=["/"]` мимо линтa (F5); воображаемый Full в dry-run (F6).
- Non-overridable: secret deny-list, env default-deny, strictest-wins лимитов, relay-только-FULL,
  запуск-без-бэкенда. Всё это уже код — compiler должен окаменеть их как правила, а не полагаться
  на разбросанные bail!-ы.

## Implementation plan + acceptance criteria

План: P0 — F4, F6, F2 (однострочные правки поведения/docs); P1 — `capability.rs` + маппинги бэкендов +
`compiler.rs` с R-правилами и тестами-отказами; P2 — CLI (`--security-level`, `--allow-degraded`,
`--shadow-verify`, `doctor --json`, бейджи); P3 — docs-классы и матрицы; P4 — VM-эпик.
Acceptance: (1) `strict + net=off` на backend без net-deny — отказ с action, никогда degrade;
(2) Seccomp-тир не стартует выше `compat` без `--allow-degraded fs,read-deny,secrets`;
(3) auto-detect не расширяет сеть молча; (4) dry-run без бэкенда пишет `unavailable`;
(5) каждый `enforced`-статус имеет verify-сценарий; (6) `policy lint --strict` ловит `allow_read=["/"]`;
(7) docs без глаголов настоящего времени для несуществующего VM-кода; (8) `src/verify_ng/` untouched;
(9) версия +0.0.1, коммит только в `arch/prompt-08`.
