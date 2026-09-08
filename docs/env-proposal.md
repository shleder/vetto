# Prompt 07 — Environment & Credential Boundary: архитектурный документ

> Скоуп: только `docs/` + анализ. `src/verify_ng/` не тронут. Production-код не пишется.

## 1. Current env exposure inventory (факт по коду, не по prompt)

Механизм един для всех backend'ов: `std::env::vars_os()` + фильтр `EnvironmentPolicy::allows()` + `env_extra` поверх.

| Точка | Файл:строки | Факт |
|---|---|---|
| Linux child env | `src/sandbox/linux/mod.rs:652-686` | allowlist-фильтр, затем `filter_proxy_secrets`, затем `env_extra` поверх, затем повторный `filter_proxy_secrets`. Fail-closed порядок верный |
| macOS child env | `src/sandbox/macos/mod.rs:425-450` | та же схема, что Linux |
| Windows child env | `src/sandbox/windows/mod.rs:1114-1170` | allowlist-фильтр + `env_extra`, **без** `filter_proxy_secrets` |
| `EnvironmentPolicy::allows` | `src/policy/types.rs:204-223` | deny-first, `*` только как суффикс-префикс, case-sensitive |
| Merge слоёв | `src/policy/loader.rs:649-659,1434-1435` | `pass_through` и `deny_env` — union через `extend` на всех уровнях |
| Immutable | `src/policy/loader.rs:490-544,1414-1423` | lockdown покрывает только `security.immutable=false` и FS allow-пути; env не покрыт |
| Baseline | `src/policy/defaults.rs:61-96`, `profiles/*.toml` | один плоский allowlist (~17 имён + `LC_*`); режимов нет |
| Agent-пресеты | `profiles/agents/*.toml` | добавляют секретные ключи (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `CODEX_*`, `OPENCODE_*`...) в `pass_through` |
| `env_extra` | `src/main.rs:830-882` | `VETTO_*`, proxy-набор (`build_proxy_env`), `GIT_SSH_COMMAND`, `VETTO_CRED_BROKER_SOCK`; обходит allowlist by design, без проверки ключей |
| Proxy upstream | `src/sandbox/linux/net_relay.rs:482-505` | брокер читает хостовые `HTTP(S)_PROXY`/`ALL_PROXY` напрямую из своего env (не из env агента — корректно) |
| Secret masking в выводе | `src/logger/sanitizer.rs`, `src/pty/redact.rs`, `src/cli/mask.rs` | везде BEST-EFFORT, задокументировано |
| `dry_run` | `src/main.rs:1589` | печатает `agent_cmd.join(" ")` без санитизации |
| Doctor-проба | `src/doctor/agent_check.rs:117-130` | эталон: `env_clear()` + только `PATH` — правильно, взять за образец для strict-режима |
| Seatbelt | `src/sandbox/macos/seatbelt.rs:1-70` | env-правил нет (SBPL их не выражает); unix-socket исключение для XPC оставлено сознательно |
| Shell | везде | exec напрямую (`execve`/`CreateProcess`), шелла-прокладки нет — хорошо |

Что реально наследуется по default-профилю: `HOME PATH SHELL USER LOGNAME TERM COLORTERM LANG LC_* TMPDIR PWD OLDPWD XDG_RUNTIME_DIR XDG_CONFIG_HOME NO_COLOR CI TERM_PROGRAM` (+ `HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY` из `defaults.rs:80-83`, хотя в `default.toml` их нет — расхождение константы и TOML, см. §7).

Чего реально НЕТ в child env по умолчанию (Strong): `SSH_AUTH_SOCK`, `LD_PRELOAD`, `AWS_*`, `GH_TOKEN`, `*_API_KEY` (кроме agent-пресетов), `DBUS_*`, `DISPLAY`, `BASH_ENV`, `GIT_*` (кроме инжекта `GIT_SSH_COMMAND`).

## 2. Вердикты по prompt (не на веру)

| Требование prompt | Вердикт | Обоснование |
|---|---|---|
| allowlist + deny-first | **Strong** | `types.rs:204-223` уже deny-first; default-deny для всего остального |
| secret-proxies strip | **Strong** (unix) / **Partial** (windows) | Linux/macOS — двойной strip; Windows — strip отсутствует, держится только на `bail` в `main.rs:862-870` |
| минимизация inherited state | **Partial** | baseline узкий, но `HOME/PATH/SHELL/TMPDIR/XDG_*` наследуются verbatim без валидации |
| 5 режимов (inherit-all/sanitized/explicit/baseline/secrets-off) | **Unsupported** | один плоский allowlist; `inherit-all` невыразим вообще, что хорошо, но и остальные 4 не различены |
| deterministic PATH | **Unsupported** | `PATH` копируется как есть: CWD-компоненты, writable dirs, shadowing не проверяются |
| argv policy / redaction | **Unsupported** | `agent_cmd` verbatim; `dry_run` печатает; `/proc/<pid>/cmdline` открыт внутри pidns; санитайзер только для логов |
| запрет secrets в argv | **Unsupported** | механизма нет; только документация |
| loader vars policy | **Partial** | default-deny спасает сегодня, но нет non-overridable deny: любой нижний слой может добавить `LD_PRELOAD` в `pass_through` |
| policy precedence с non-overridable deny | **Unsupported** | `pass_through` — union всех слоёв (`loader.rs:651`); repo-фрагмент/CLI могут расширить env вопреки system; immutable env не касается |
| shell startup isolation | **Partial** | прямого шелла нет, но `HOME`+`SHELL` настоящие; на Tier FULL rc-файлы режутся FS-слоем, на Seccomp-only/macOS — нет |
| proxy policy | **Partial** | uppercase passthrough + инжект relay-URL через `env_extra`; lowercase дропаются (ломают тулзы); `NO_PROXY=""` vs unset семантика не продумана |
| Windows env block | **Partial** | сортировка, NUL/32MiB проверки есть; case-sensitivity бага (см. §7 finding W1); `SystemRoot/COMPSPEC` baseline не определён |
| macOS launch/Keychain | **Unsupported** | env чистится, но XPC/unix-socket исключение оставляет Keychain и credential API доступными независимо от env |
| Linux namespaces для env | **Strong** | private procfs + pidns прячут `/proc/<pid>/environ` соседей на Tier FULL; на FS-ONLY — нет |
| audit env событий | **Unsupported** | в `events/` env не фиксируется вообще (только сам факт — правильно для значений, но нет события «какие имена пропущены») |

## 3. Threat model (env как attack surface)

Граница: всё, что агент читает без файлового доступа — `environ`, `cmdline`, унаследованные сокеты/fd, platform credential API.

1. **Прямое чтение секретов** из унаследованных `*_TOKEN/*_KEY/AWS_*` — закрыто default-deny, открывается agent-пресетами (осознанно, но без режима secrets-off).
2. **Credential discovery через имена**: даже без значений агент перечисляет `env` и узнаёт, какие провайдеры настроены у хоста (наличие `ANTHROPIC_*` vs `OPENAI_*` — информация для таргетинга).
3. **PATH hijacking**: writable `~/bin`, `.` в `PATH`, project-local бинари, созданные самим агентом скрипты + последующий exec без абсолюта.
4. **Loader hooks**: `LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH` (Linux), `DYLD_INSERT_LIBRARIES` (macOS), `PYTHONPATH/NODE_OPTIONS/RUBYOPT/PERL5OPT` — выполнение кода в доверенных процессах (ssh-proxy helper, git).
5. **Shell hooks**: `BASH_ENV/ENV/ZDOTDIR/XDG_CONFIG_HOME`-сдвиг — выполнение при каждом `sh -c` внутри агента.
6. **Proxy перенаправление**: свой `HTTP_PROXY` у агента → весь egress через атакующего; creds в URL `http://user:pass@proxy`.
7. **Git env**: `GIT_SSH_COMMAND/GIT_CONFIG_*` — подмена ssh; собственный `GIT_SSH_COMMAND` инжектится vetto, агентский должен давиться.
8. **Сокеты через env**: `SSH_AUTH_SOCK` закрыт, но `XDG_RUNTIME_DIR` открыт → предсказуемые пути `…/ssh-agent.*`, `…/bus`, `VETTO_CRED_BROKER_SOCK` (доступ к брокеру = доступ ко всем proxied-секретам для allowlisted-доменов).
9. **argv leak**: секреты в флагах (`--token`, `--api-key`) видны в `/proc/<pid>/cmdline`, `ps`, audit-логах, `dry_run`-выводе.
10. **Coredump/ошибки**: env дампится в core-файлы и crash-репорты; `ResourceLimits` не управляет `RLIMIT_CORE`.
11. **Windows**: `PSModulePath` (autoload модулей), `COMSPEC` (подмена шелла), `APPDATA`-хелперы (`gh`, `docker credStore`), DPAPI через user-контекст независимо от env.
12. **macOS**: Keychain/XPC доступны при любом env; `__OS_LOG` может утащить секреты в unified log.

## 4. Environment policy IR (предложение)

```toml
[environment]
mode = "sanitized"          # inherit-all | sanitized | explicit | baseline | secrets-off
pass_through = [...]        # только для explicit/baseline-дополнений
deny = [...]                # union, non-overridable вниз (см. §6)
# Новые секции:
# [environment.path] / [environment.argv] / [environment.secrets] — §5, §9
```

Семантика режимов (дефолт `sanitized`, fail-closed: неизвестный `mode` = ошибка загрузки, не fallback):

- `inherit-all` — запрещён всегда (fail-closed `bail` в лоадере; нужен только doctor-пробам внутри кода, не конфигам).
- `sanitized` — текущий default-baseline (таблица §1) + обязательные санитайзеры PATH (§5).
- `explicit` — только `pass_through` из project+CLI слоёв, без дефолтного baseline (для параноидальных репо).
- `baseline` — per-agent минимум (сегодняшние `profiles/agents/*.toml`), без секретов.
- `secrets-off` — `baseline` минус любые `*_KEY/*_TOKEN/*_SECRET` даже из agent-пресетов + обязательный `secret_proxies` strip + запрет `VETTO_CRED_BROKER_SOCK` инжекта.

## 5. Sanitization rules + PATH security design

Обязательные (non-overridable, применяются после merge, до exec):

1. **Hard-deny список** (всегда, независимо от слоёв): `LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH LD_CONFIG DYLD_* BASH_ENV ENV ZDOTDIR PYTHONPATH PYTHONSTARTUP NODE_OPTIONS NODE_PATH?` — см. нюанс ниже — `RUBYOPT RUBYLIB PERL5OPT PERLLIB GIT_SSH_COMMAND GIT_SSH GIT_CONFIG_* GIT_DIR GIT_WORK_TREE SSH_AUTH_SOCK SSH_AGENT_PID DBUS_SESSION_BUS_ADDRESS XAUTHORITY TERMCAP TERMPATH`.
   Нюанс: `NODE_PATH/NVM_DIR/CARGO_HOME/RUSTUP_HOME` сегодня в passthrough (`defaults.rs`) ради тулчейнов. Решение: оставить, но пометить tier-зависимыми — на Tier FULL они указывают на read-only маунты и безопасны; в остальных тирах выводить warning в `warnings`. Разрывать тулчейны молча нельзя.
2. **PATH construction** (детерминированная, новый код в одном месте на backend):
   разбить по `:`, выкинуть `` (пусто = CWD), `.`, `..`-компоненты, несуществующие dirs; варнинг на group/world-writable dirs (fail-open с варнингом, не fail-closed — иначе сломаем dev-машины; strict-профиль — fail-closed опция `path_strict = true`); результирующий PATH экспортировать; исходный хостовый PATH в audit-событие (только факт фильтрации, не значения — хотя PATH не секрет, значения нужны для диагностики; PATH логировать можно).
3. `HOME` — наследовать, но agent-пресеты обязаны держать credential-dotfiles закрытыми через FS-deny (уже есть); альтернатива (chroot-HOME) — отвергнута: ломает тулчейны, выигрыш дублирует FS-слой.
4. `TMPDIR/TEMP` — сверять с `tmpfs_tmp`: если изолированный tmpfs включён, `TMPDIR` переписывать на него через `env_extra`; рассинхрон env-vs-mount сегодня — баг.
5. `PWD/OLDPWD` — не наследовать, выставлять из `opts.cwd` детерминированно через `env_extra`.
6. `SHELL/COMPSPEC` — фиксировать из системного дефолта, не из env пользователя.
7. `LANG/LC_*` — как сегодня (passthrough + возможность deny), плюс `TZ`/`TZDIR` в hard-deny (exfil географии + подмена tzdata-файлов).
8. Proxy: канонизировать обе регистра (`HTTP_PROXY`+`http_proxy` и т.д.) из одного источника; в relay-режиме обе обязаны указывать на relay (сегодня так через `env_extra`, но хостовый passthrough дублирует — убрать proxy из default passthrough, оставить только инжект); `NO_PROXY` — явный список вместо пустой строки.
9. `VETTO_*` — только через `env_extra`; любой `VETTO_*` из parent env давить (сегодня parent `VETTO_*` не проходит allowlist — Strong, зафиксировать тестом).

## 6. Policy precedence

Предложение: `system -> user -> Vetto -> project -> agent -> command` для `pass_through` (union, как сегодня), но:

- `deny` (включая новый hard-deny из §5) — **только расширяемый вниз**: нижний слой может добавить deny, убрать — никогда. Сегодня union уже даёт это для deny фактически (убрать нельзя — нет операции вычитания), требуется зафиксировать инвариант + покрыть тестом на immutable.
- `pass_through`-расширение при `is_immutable` — запретить CLI/repo-расширения секретообразных имён (`*_KEY/*_TOKEN/*_SECRET/*_PASSWORD`, регистронезависимо) — fail-closed `PolicyLockdownViolation`, аналогично существующему запрету FS-путей (`loader.rs:1415`).
- `env_extra` — ввести allowlist ключей (`VETTO_*`, proxy-набор, `GIT_SSH_COMMAND`, `PWD`): любой другой ключ из кода = `bail` в debug / игнорирование с warn в release. Сегодня проверки нет.

## 7. Конкретные findings (файлы/модули)

- **W1 (Windows deny-обход регистром)**: `src/sandbox/windows/mod.rs:1120-1128` + `types.rs:205` case-sensitive. Родительский `aws_secret_access_key` обойдёт `deny = ["AWS_SECRET*"]`. Фикс: нормализовать к upper при матчинге на Windows (матчинг, не хранение).
- **W2 (Windows без broker-strip)**: `windows/mod.rs:1114-1170` нет `filter_proxy_secrets`; держится на `bail` в `main.rs:862-870`. Фикс: добавить тот же двойной strip (defense in depth, 3 строки).
- **M1 (macOS пустая env-строка)**: `macos/mod.rs:448` `CString::new(entry).unwrap_or_default()` — при `=`/NUL в имени/значении в env тихонько попадает пустая строка вместо дропа (Linux такой entry дропает, Windows дропает). Фикс: `filter_map` как в Linux.
- **D1 (расхождение baseline)**: `defaults.rs:80-83` содержит proxy-переменные, `profiles/default.toml:30-37` — нет. Какой baseline истинен, зависит от пути загрузки (`loader.rs:1031`). Фикс: один источник (TOML), константу удалить.
- **A1 (argv в dry_run)**: `main.rs:1589` печатает сырой `agent_cmd`. Фикс: пропускать через существующий `logger::sanitizer::sanitize_line`.
- **S1 (предсказуемый сокет брокера)**: `main.rs:874` `vetto-cred-<pid>.sock` в shared `/tmp` + allow_write `/tmp`. Дизайн ок (брокер проверяет домен), но отметить: любой процесс пользователя может соединиться; mitigations — `0600` + случайный суффикс, сокет прятать при `tmpfs_tmp`.
- **C1 (RLIMIT_CORE)**: `ResourceLimits` (`types.rs:162-172`) не управляет core-дампами → env с секретами (agent-пресеты!) может осесть в core. Фикс: `RLIMIT_CORE=0` перед exec на Unix.

## 8. argv design

- Spawn-контракт (`src/sandbox/handle.rs:37-42`): добавить инвариант «сырые секреты в `agent_cmd` запрещены»; vetto свои секреты так не передаёт (Strong уже).
- Санитизация логов: `dry_run`, `watch.rs:62`, JSONL — через `sanitize_line` (BEST-EFFORT, честно пометить).
- Trusted helper alternative: уже есть прецедент — `ssh-proxy` helper (`net_relay.rs:1271-1281`) и cred-broker сокет вместо env. Новые секреты — только этим путём, не флагами.
- Верификация: тест «argv со `--api-key=sk-...`» обязан показать: значение видно в child `cmdline` (документируем как inherent, не фиксим), но обязано быть зацензурено в `dry_run`/JSONL.

## 9. Per-platform mapping

- **Linux**: env-фильтр (`linux/mod.rs:652`) + private procfs/pidns (прячет `environ` соседей) + Landlock (режет socket-файлы `XDG_RUNTIME_DIR`, rc-файлы) + seccomp. Дотыкать: PATH-санитайзер, `RLIMIT_CORE=0`, `TMPDIR`-синхрон, hard-deny.
- **Windows** (`windows/mod.rs`): env-блок + W1/W2 фиксы; `SystemRoot`/`COMSPEC`/`PATHEXT`/`PSModulePath` — явный минимальный набор в baseline (сегодня ни разрешены, ни запрещены — child может не стартовать без `SystemRoot`); PowerShell-профили режутся FS-deny (`$HOME\Documents\PowerShell` добавить в deny-паттерны); Credential Manager недоступен для чистки из env — честно в limitations.
- **macOS** (`macos/mod.rs` + `seatbelt.rs`): env-фильтр + M1 фикс; Keychain/XPC — вне досягаемости env-границы, фиксируется как limitation; `DYLD_*` в hard-deny избыточен (SIP), но дёшев — оставить.
- **VM** (`windows_sandbox.rs`): env не прокидывается внятно по коду (grep по `env` пуст) — специфицировать: в VM уходит только `explicit`-минимум + `VETTO_*`; секреты — никогда (в VM нет брокера).

## 10. Verification tests (проект, не код)

1. `inspect env`: child печатает `env -0`; assert — только allowlist-имена, секретов хоста нет, `VETTO_*` из parent отсутствуют.
2. `inspect PATH`: `PATH` без ``/`.`/`..`, порядок сохранён, writable-dirs залогированы.
3. `/proc/<pid>/environ` (Linux FULL): сосед по pidns не видит процесс вообще; хост видит отфильтрованное.
4. Shell startup leakage: `BASH_ENV=/tmp/evil` + `ZDOTDIR=/tmp/evil` в parent → маркер-файл не создан.
5. Loader vars: `LD_PRELOAD=/tmp/evil.so`, `PYTHONPATH`, `NODE_OPTIONS=--require /tmp/evil` в parent → не унаследованы даже при `pass_through` в repo-слое (non-overridable deny).
6. Secret propagation: `AWS_SECRET_ACCESS_KEY`, `GH_TOKEN` в parent → отсутствуют в child при любом профиле.
7. Agent-пресет: `ANTHROPIC_API_KEY` виден с `--agent claude`, отсутствует в `secrets-off`.
8. Lockdown: repo-слой с `pass_through = ["AWS_SECRET_ACCESS_KEY"]` при immutable → `PolicyLockdownViolation`.
9. Windows: lowercase `path`/`aws_secret_access_key` в parent → корректный match обеих веток.
10. argv: `dry_run` с `--api-key=sk-test` → `[REDACTED]` в выводе.
11. Malicious PATH: dir с `ls`-подменой первым в `PATH` + writable → отфильтрован/залогирован, подмена не исполняется.
12. Broker sock: `VETTO_CRED_BROKER_SOCK` указывает на `0600`-сокет со случайным именем.

## 11. Audit semantics

- Новое событие `EnvBoundary { mode, allowed_names: Vec<String>, dropped_names: Vec<String>, path_rewritten: bool }` — **только имена**, значений нет (PATH — исключение: значение не секрет, нужно для диагностики; секретообразные значения никогда).
- Значения env — никогда в JSONL/report/verify (расширить `sanitize_line` правилом `redact_env_assignments` — уже есть, `sanitizer.rs:245`).
- Doctor-проба: `env_clear()`+`PATH` образец из `agent_check.rs` — переиспользовать.

## 12. Предлагаемые файлы/модули (изменений кода НЕТ — только план)

| # | Файл/модуль | Действие |
|---|---|---|
| 1 | `docs/env-proposal.md` (этот файл) | создать — единственный артефакт хода |
| 2 | `src/policy/types.rs` (`EnvironmentPolicy`) | добавить `mode`, `path_strict`; `allows()` — Windows-CI-нормализация, hard-deny константа |
| 3 | `src/policy/defaults.rs` | удалить `DEFAULT_ENV_PASSTHROUGH` как второй источник; оставить TOML |
| 4 | `src/policy/loader.rs` | `inherit-all` → bail; immutable для секретообразных env; deny-union инвариант + тест |
| 5 | `src/sandbox/envfilter.rs` (новый) | общий PATH-санитайзер + hard-deny + `PWD/TMPDIR/SHELL`-канонизация для Linux/macOS/Windows |
| 6 | `src/sandbox/linux/mod.rs` (`child_exec`) | вызывать `envfilter`, `RLIMIT_CORE=0` |
| 7 | `src/sandbox/macos/mod.rs` (`build_envp`) | вызывать `envfilter`, M1 фикс |
| 8 | `src/sandbox/windows/mod.rs` (`environment_block`) | вызывать `envfilter`, W1+W2 фиксы, `SystemRoot/COMPSPEC` baseline |
| 9 | `src/sandbox/handle.rs` (`SpawnOptions`) | allowlist ключей `env_extra` + argv-инвариант в доке |
| 10 | `src/main.rs` | `dry_run`-санитизация, сокет `0600`+рандом, `TMPDIR`-синхрон |
| 11 | `src/sandbox/windows/windows_sandbox.rs` | специфицировать VM-env-минимум |
| 12 | `src/events/types.rs` + `src/logger/sanitizer.rs` | `EnvBoundary`-событие (имена only) |
| 13 | `profiles/*.toml`, `profiles/agents/*.toml` | `mode`, secrets-off вариант, `PSModulePath`-deny для Windows |
| 14 | `tests/` (интеграционные) | 12 тестов из §10 |

## 13. Migration plan

1. Docs-only (этот ход): `docs/env-proposal.md` → коммит в `arch/prompt-07`, стоп.
2. `envfilter.rs` + W1/W2/M1/A1/C1/D1 фиксы — маленькие, независимые, первыми.
3. `mode` в IR + лоадер (`inherit-all`→bail, immutable-env) — за ним TOML-правки профилей.
4. PATH-санитайзер (warn-режим) → сбор телеметрии ложных срабатываний → `path_strict` для strict.
5. `EnvBoundary`-аудит + 12 тестов.
6. VM-env-спецификация.

## 14. Security limitations (честно)

- Keychain (macOS), DPAPI/Credential Manager (Windows), XPC-брокер — вне env-границы; закрываются FS/слоями или не закрываются вовсе.
- `secrets-off` не лишает агента способности **попросить** секрет у пользователя/файла — только не подсовывает его сам.
- Санитизация логов BEST-EFFORT (высокая энтропия, нестандартные форматы).
- `cmdline` внутри pidns виден соседям по песочнице — mutual distrust между процессами одного агента не моделируется.
- Core-дампы хоста (systemd-coredump) вне `RLIMIT_CORE` vetto, если агент форкает до установки лимита — окно минимально, но ненулевое.
- Predictable `VETTO_SESSION_ID` в env — идентификатор сессии виден агенту (нужен для relay); скоп ударов — корреляция, не secret.

## 15. Critical review: 10+ часто забываемых escape/leak путей

1. `BASH_ENV/ENV` — код при каждом неинтерактивном `sh -c`.
2. `ZDOTDIR` — сдвиг всего zsh-конфига.
3. `LD_AUDIT` — забывают чаще, чем `LD_PRELOAD`; тот же эффект.
4. `XDG_CONFIG_HOME` — сдвиг конфигов git/ssh (`$XDG_CONFIG_HOME/git/config`).
5. `GIT_CONFIG_COUNT/GIT_CONFIG_KEY_*` — конфиг через env, обходит FS-deny на `.gitconfig`.
6. `PYTHONSTARTUP` (интерактивный python) и `NODE_OPTIONS=--require` — в отличие от `PYTHONPATH` их редко чистят.
7. `PERL5OPT/RUBYOPT` — аналогично для perl/ruby хелперов.
8. `TMPDIR` вне tmpfs-изоляции — предсказуемые race-файлы, сокеты.
9. `TZDIR` — подмена tzdata-файлов парсером libc.
10. `GCONV_PATH/LOCPATH` — подмена glibc-модулей конверсии/локалей (классика, почти никто не чистит).
11. `HOSTALIASES` — подмена резолвинга без трогания DNS.
12. Creds в proxy-URL (`HTTP_PROXY=http://user:pass@…`) — пасмурная копия секрета внутри «несекретной» переменной.
13. `VETTO_CRED_BROKER_SOCK` — сам путь в env даёт доступ к выдаче секретов (по дизайну, но забывают, что это bearer-capability).

## 16. Implementation plan + acceptance criteria

План: §13 пп. 2–6, оценка — 4–6 инкрементов, каждый с тестами из §10. Порядок fail-closed-first: лоадер-bail и deny-фиксы раньше PATH-варнингов.

Acceptance criteria:

- [ ] AC1: `inherit-all` в любом TOML → ошибка загрузки, сессии нет.
- [ ] AC2: все 12 тестов §10 зелёные на Linux; Windows/macOS — подмножество 1,2,6,9,10.
- [ ] AC3: repo-слой не может протащить `LD_PRELOAD`/`AWS_*` ни в `pass_through`, ни мимо deny (тесты 5, 8).
- [ ] AC4: `dry_run`/JSONL с секретом в argv — только `[REDACTED]`.
- [ ] AC5: `docs/env-proposal.md` и код не расходятся (повторный аудит `grep`-матрицы §7 — пусто).
- [ ] AC6: `src/verify_ng/` untouched (проверяется `git diff --stat`).
