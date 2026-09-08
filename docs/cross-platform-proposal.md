# Cross-platform sandbox: сверка proposal с кодом + решение

Ветка: `arch/cross-platform`. Репозиторий: версия `0.2.18` (подтверждено `Cargo.toml:3`).
Проверялся proposal `/home/shleder/Downloads/cross-platform-sandbox-proposal.md` (§1–26)
чтением кода, не на веру. Production-код не писался. `src/verify_ng/` не тронут.

## 1. Вердикт

Proposal принять как базу с тремя обязательными правками (§3, пп. 1–3).
Фактическая архитектура кода совпадает с описанной в proposal §2.1 почти везде;
найденные расхождения — ниже, ни одно не ломает общий замысел
(policy→compiler→runtime→backends, enforcement нативный, Linux FULL референс).

## 2. Подтверждено кодом (Strong)

- Fail-closed factory: `src/sandbox/mod.rs:58` (`detect/detect_with_backend/spawn`).
  Неизвестный backend → bail, `win-sandbox` на не-Windows → bail.
- `VETTO_FORCE_TIER` не обходит fail-closed: `src/sandbox/linux/mod.rs:106-112` —
  форсированный tier выбирается только среди реально доступных примитивов.
- Spawn до потоков: `src/main.rs:1-7` (порядок load-bearing), брокер/audit/TUI
  стартуют только после `backend.spawn` (`main.rs:958-1043`).
- Env default-deny на трёх backend: `linux/mod.rs:668`, `macos/mod.rs:432,441`
  (`filter_proxy_secrets` до и после `env_extra`); Windows строит блок с нуля
  (`windows/mod.rs:1117` и далее). Семантика единая.
- Windows deny-внутри-гранта → fail-closed: `build_sandbox_spec`
  (`windows/mod.rs:1172`+). Windows non-Off net → bail (нет DNS/IP-компилятора).
  `inheritHandles=FALSE` в обоих вызовах create (`mod.rs:551,569`);
  `CREATE_SUSPENDED` + `CREATE_NEW_PROCESS_GROUP` там же; строка `BREAKAWAY`
  в коде отсутствует полностью (grep пуст) — silent-breakaway не ставится.
- macOS Shape A + tail-deny как задокументированный максимум:
  `macos/seatbelt.rs:204-205` (`SBPL_MAXIMUM_READ_SHAPE`), deny из
  `policy.deny_resolved` (`seatbelt.rs:49`).
- `macos/net_proxy.rs` НЕ wired в spawn: единственный референс —
  объявление модуля в `sandbox/mod.rs:18`. Утверждение proposal (§10, §2.1)
  «standalone, не wired» — факт.
- `verify --preflight` unix-only: `src/verify.rs` — `#[cfg(not(unix))]` возвращает
  `unavailable`. Windows battery отсутствует — главный пробел, как и заявлено.
- `Tier` только про Linux: `src/policy/types.rs:9` (`Full/FsOnly/Seccomp`).
- Backend-trait отсутствует: `Backend` — enum с `#[cfg]`-вариантами
  (`sandbox/mod.rs:49`). `SandboxSpec` как типа нет; `Policy` смешанный.
  Capability-контракт есть только у Windows (`WindowsCapabilities`,
  `windows/mod.rs:272`) и частично у Linux (`Probe`); у macOS сравнимого нет.
- Kill-стратегии kernel-уровня там, где заявлены: `PidNsPipe` / `ProcessGroup`
  (sweep только Linux) / `JobObject`, `Drop→terminate` (`handle.rs:169-213`).
- Exit-коды: `VettoError::Sandbox→125`, `Policy→1` (`error.rs` + `exit_codes.rs`).
  Утверждение proposal §2.1 корректно.
- Дыра `VETTO_SEATBELT_MODE=none`: подтверждена — `macos/mod.rs:356-366`:
  режим `none` пропускает `apply_seatbelt` полностью, молча (только
  `child_trace`). Закрыть первой, до любых новых backend (согласен с §21, §24п7).
- Threat-model: 4 non-defense класса на месте (`docs/threat-model.md:36-63`).
  CI: `ci.yml` + `macos-sbpl-matrix.yml` + `e2e-agents.yml` существуют.

## 3. Расхождения и обязательные правки proposal

1. **Внутреннее противоречие по WSL2.** §1 требует «WSL2 признать Tier 1
   без оговорок», §12 — «Tier 1 УСЛОВНО (interop выключен, проект внутри
   Linux-FS, иначе Partial)». Верна §12. §1 исправить на условную формулировку.
2. **Двусмысленность «WSL2».** `docs/platform-backends.md:15-16,26` уже называет
   Tier 1 запуск Linux-бинаря *внутри* WSL2. Предлагаемый `BackendId::wsl` (§12,
   §23) — оркестрация *из* Windows-бинаря. Это разные trust-модели; развести
   термины явно (wsl-exec vs wsl-orchestrated), иначе матрица §13 вводит
   в заблуждение.
3. **§2.2 п.7 смягчить.** `daemon`/`mcp` — отдельные субкоманды
   (`main.rs:229-232`), не участники run-path. Риск только через общие типы
   (`Policy`/`RunConfig`), не через поток исполнения. Dependency-lint (§20п7,
   §21) всё равно нужен, но формулировку «в security path» снять.
4. Мелочь: `windows/mod.rs:18`-комментарий про «один токен без AppContainer»
   — утверждение proposal «код это уже соблюдает» проверено только
   чтением preflight (`enforcement_ready`, `mod.rs:472`); при Phase 3
   перечитать строки ~600–660 (Job attach до resume) глазами.

## 4. Сила backend (итоговая матрица, следы в коде)

| Backend | FS write | FS read | net off | net allowlist | detached cleanup | Итог |
|---|---|---|---|---|---|---|
| Linux FULL | Strong | Strong | Strong | Strong | Strong (kernel) | референс, не трогать |
| Linux FS-ONLY | Strong | Strong (carve, бюджет) | Strong | Unsupported (fail-closed) | best-effort (sweep, setsid-gap) | честный fallback |
| Windows native | Strong (grants) | Partial (alias/COM-gap) | Strong | Unsupported без admin / Partial с WFP-lease | Strong (Job) | strong при связке §1, allowlist без админа не обещать |
| macOS native | Strong | Partial (Shape A+tail-deny) | Strong | Unsupported (fail-closed) | best-effort (watchdog) | «with documented read-isolation limits» |
| macOS VM / WSL-hardened / .wsb | Strong | Strong | Strong | Strong/Partial | Strong | отдельные BackendId, nightly-CI |

Adversarial-покрытие proposal §18 достаточно; добавить явно:
WSL_INTEROP-вычищение из env, `/mnt/c`-проект как отдельный кейс,
`wsl.exe`/`powershell.exe`-лаунчеры из native-песочницы, IFEO/scheduler-vectors.

## 5. Предлагаемые файлы (будущие изменения, production-код НЕ писан)

- `docs/cross-platform-proposal.md` — этот файл (создан сейчас).
- `docs/threat-model.md` — дополнения §3.4 proposal (время вне покрытия,
  COM/RPC/registry/WSL-interop, XPC/Mach/keychain/TCC/launchd, shared-folders).
- `docs/platform-backends.md` — условный Tier 1 для WSL2 + развод терминов (п. 2 §3).
- Новый `src/compile/` (Intent/Spec/Capabilities/ValidationReport, чистая функция).
- `src/sandbox/backend.rs` (trait `SandboxBackend`, `BackendId`, `CommandSpec`).
- `src/sandbox/linux|windows|macos/` — перенос capability-гейтов из spawn в compile,
  sentinel self-test (Linux), partial-вердикты (macOS), deny-типизация (Windows).
- Новые `src/sandbox/vm/`, `src/sandbox/wsl/` (Phase 5–6).
- `src/verify.rs` — battery на Windows + PARTIAL-вердикты.
- CI: FULL+FS-ONLY+seccomp джобы, windows battery, WSL-hardened джоба, VM nightly.

## 6. Implementation plan (порядок из §25, принят)

- Phase 0: архитектурное решение (этот файл) + threat-model. Без кода.
- Phase 1: типы Intent/Spec/Capabilities/ValidationReport рядом с `Policy`,
  `compile()` для Linux FULL. Dual-write с assert-эквивалентностью.
- Phase 2: Linux hardening (sentinel self-test, типизированный R-протокол).
- Phase 3: Windows native (compile-гейты, WFP-lease как отдельный backend-id,
  deny лаунчеров WSL/scheduler, Job-attach аудит).
- Phase 4: macOS native (partial-вердикты, `SEATBELT_MODE=none` за debug-gate,
  launchd-paths deny).
- Phase 5: macOS Linux-VM (`BackendId::VmLinux`, guest-attestation).
- Phase 6: WSL-hardened + `.wsb` как backend-id, interop-матрица.
- Каждый шаг — зелёный CI, Linux FULL e2e как gate без регрессий.
- Версионирование: релизы строго +0.0.1 (AGENTS.md); docs-правки версию не бампают.

## 7. Acceptance criteria

1. `compile()` unit-покрыт на всех ОС; Linux FULL e2e идентичны до/после Phase 1.
2. `VETTO_SEATBELT_MODE=none` невозможен в release-сборке (fail-closed в CI).
3. `verify --backend X` возвращает PASS/PARTIAL(перечень)/FAIL/UNAVAILABLE;
   partial никогда не выдаётся за PASS; Windows больше не `unavailable`.
4. Allowlist на native Windows/macOS без admin — отказ с actionable-причиной.
5. Не-hardened WSL — честный PARTIAL с причиной, не PASS.
6. Ни один backend-модуль не импортирует daemon/remote/mcp/tui/telemetry (CI-lint).
7. Формулировки claims — только из §26 proposal (запрет «full isolation»
   без квалификатора).
