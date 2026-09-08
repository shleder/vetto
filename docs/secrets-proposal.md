# Prompt 04 — Secret & Credential Isolation: архитектурный proposal

Статус: предложение, не implementation. Production-код не пишется. Scope: `docs/`,
анализ `src/cred_broker.rs`, `src/policy/secretscan.rs`, secret_masking тестов.
`src/verify_ng/` не тронут.

## 1. Current secret exposure inventory (реально enforced / best effort / documented)

### Реально enforced (Strong, но только там где указано)
- Env allowlist-only: `src/policy/defaults.rs:61` (`DEFAULT_ENV_PASSTHROUGH`),
  `src/policy/types.rs:204` (`EnvironmentPolicy::allows`, deny приоритетнее),
  `src/policy/loader.rs:2271` тесты на `AWS_SECRET_ACCESS_KEY` deny-by-default.
  Применение перед execve: `src/sandbox/linux/mod.rs:664` (`child_exec`),
  `src/sandbox/macos/mod.rs:425` (`build_envp`),
  `src/sandbox/windows/mod.rs:1114` (`environment_block`).
  `GH_TOKEN`/`OPENAI_API_KEY`/`AWS_*`/`ANTHROPIC_API_KEY` по умолчанию не проходят. Вердикт: **Strong** (все 3 backend фильтруют одинаково).
- `filter_proxy_secrets` (`src/cred_broker.rs:59`, вызовы в linux `mod.rs:668,677`,
  macos `mod.rs:432,441`; Windows: fail-closed bail в `src/main.rs:863`).
  Вердикт: **Strong** как strip-механизм, **но** сам брокер возвращает секрет (см. §2).
- Linux Tier FULL mount overlays: `src/sandbox/linux/mounts.rs:274` (`mask_path` —
  `/dev/null` на файлы, пустой tmpfs на директории), вызов в `mod.rs:1056`,
  `make_root_private`, `isolate_tmp`, `isolate_dev_shm`, `mask_sensitive_proc_paths`.
  Landlock сам вычитать не умеет (allowlist), overlay — единственный механизм карвинга.
  Вердикт: **Strong** внутри FULL.
- Linux FS-ONLY enumeration carve-out: `src/policy/loader.rs:1804`
  (`mask_project_reads_for_fs_only` + `enumerate_tree`, бюджет `FS_ONLY_ENUMERATION_BUDGET`,
  fail-closed при превышении). Вердикт: **Partial** (TOCTOU, бюджет, late-created файлы).
- Seccomp netblock FS-ONLY (`src/sandbox/linux/seccomp_netblock.rs`) + запрет
  `ptrace/process_vm/pidfd_getfd/mount/io_uring/bpf` — Strong против снятия оверлеев,
  но **Unsupported** для файловой части секретов (нет карвинга).
- Network broker DNS/IP pinning: `src/sandbox/linux/net_relay.rs:333,551` —
  реджект private/loopback/link-local/metadata/multicast/reserved incl. NAT64/mapped,
  CONNECT-level mediation. Вердикт: **Strong** (Linux allowlist/strict).
  `GIT_SSH_COMMAND` через `ssh-proxy` helper (`net_relay.rs:1274`, `BatchMode=yes`,
  дочерний процесс OpenSSH, не демон). Вердикт: **Strong**.
- macOS Seatbelt tail-deny: `src/sandbox/macos/seatbelt.rs:49` (deny после broad read,
  last-match-wins). Вердикт: **Partial** — рабочий профиль Shape A
  (`SBPL_MAXIMUM_READ_SHAPE`, broad `(allow file-read* (subpath "/"))`), известный
  провал read-изоляции доказан тестом
  `tests/integration/macos_seatbelt.rs:17` (`secret_reads_are_not_yet_isolated_on_macos`).
- Windows: `src/sandbox/windows/mod.rs:1172` (`build_sandbox_spec`) — deny внутри
  гранта = fail-closed bail (честно, без выдуманного FlatBuffer-слота).
  Вердикт: **Strong** как fail-closed, **Unsupported** как субтракция.
- Report sinks санитизированы: `src/report/json.rs:19`, `src/report/mod.rs:163`,
  `src/report/html.rs`, `markdown.rs`; JSONL sink `src/logger/jsonl.rs:58` через
  `sanitizer::sanitize_line` + `open_append_nofollow` (no-symlink, regular, nlink==1).
  Вердикт: **Strong** для этих путей (при BEST-EFFORT оговорке).

### Best effort (не граница, честно помечено)
- `src/logger/sanitizer.rs:1` (BEST-EFFORT, FP+FN), `src/pty/redact.rs` (Aho-Corasick +
  entropy), `src/pty/entropy.rs` (H>4.5, len>=20), `src/cli/mask.rs` (`vetto mask` pipe),
  `src/policy/secretscan.rs` (сканер 1MB/5000 файлов/3s, `mask_secret` prefix4+suffix4).
- `src/classifier/suspicious.rs` — только audit hints (`credential_path_access`,
  `non_public_network_target`), never enforcement. Вердикт: **Partial** по определению.
- `vetto scan-secrets` (`src/main.rs:550`) и `auto_deny_secrets` (`loader.rs:1536`).
  Вердикт: **Partial** (покрывает только известные regex + имена файлов в $PROJECT).

### Merely documented / честные Unsupported
- macOS read-изоляция (`SECURITY.md`, `docs/platform-backends.md`, doctor probe
  `sbpl-read-fragment`): заявлен Unsupported без VM.
- Windows per-domain allowlist без admin (WFP требует elevation, vetto отказываться
  требовать): fail-closed, честно.
- Late-created secret-shaped файлы в writable $PROJECT (SECURITY.md residual risks).
- `~/.gitconfig` читаем intentionally (credential в URL rewrite = exposure, documented).
- Taint-tracking/DLP: отсутствует, заявлено честно (threat-model §"What Vetto Does NOT Protect").

## 2. Найденные дыры (проверено по коду, не по памяти)

1. **Брокер возвращает секрет в песочницу.** `BrokerResponse::Ok { header_value }`
   (`src/cred_broker.rs:47`) — любой держатель сокета читает raw secret.
   Нет `SO_PEERCRED` auth, нет привязки к session/pid, `allowlist "*"`, секреты в
   `HashMap<String,String>` без zeroize/mlock, сокет-путь через
   `VETTO_CRED_BROKER_SOCK` в `env_extra` (`src/main.rs:873`), сам сокет в
   `temp_dir()` (= host `/tmp`, который FULL прячет `isolate_tmp` — брокер может быть
   **недоступен**; либо доступен через проброшенный путь — оба исхода плохи).
   Вердикт текущего: **Partial/Unsafe**. Fail-closed риск: escape через чтение сокета.
2. **Лог/audit пути без санитайзера.** `src/logger/oslog.rs:42` (`{:?}` fallback для
   `ExecObserved` incl. argv), `src/logger/system_log.rs:26` (comm/path/message как есть
   в journald/logger/eventcreate), `src/notify/mod.rs:76` (path/host в
   notify-send/osascript/PowerShell), `src/audit/history.rs:101`
   (`append_record_to_file` — plain append, без nofollow/hardlink проверок jsonl.rs,
   `AuditRecord.command = argv.join(" ")` без санитайзера). Вердикт: **Partial**,
   exfiltration через crash/log/notify.
3. **`mask_secret` течёт 8 символов.** `src/policy/secretscan.rs:62`
   (prefix4+suffix4) + `SecretFinding.preview` печатается в `scan-secrets`
   (`src/main.rs:584`). Вердикт: **Partial** — preview должен быть класс-only.
4. **Core dumps не запрещены.** `src/sandbox/linux/limits.rs:43` — нет `RLIMIT_CORE=0`;
   `PR_SET_DUMPABLE=1` ставится для observe (`linux/mod.rs:382`) и не сбрасывается
   явно в agent child. Вердикт: **Partial** (эксфильтрация секретов из памяти через дамп).
5. **Env passthrough содержит риски.** `XDG_RUNTIME_DIR` в passthrough
   (`defaults.rs:87`) — доступ к bus/waylandсокетам и кэшам; `GIT_*` identity ок,
   но нет явного deny для `GIT_ASKPASS`/`GIT_CREDENTIAL_HELPER`/`SSH_AUTH_SOCK`/
   `GPG_AGENT_INFO`/`KUBECONFIG`/`DOCKER_CONFIG`/`*_TOKEN`. Сейчас они deny-by-absence
   (Strong по умолчанию), но без явного списка один `pass_through: ["*"]` в custom
   политике всё откроет без предупреждения. Вердикт: **Strong по умолчанию,
   Partial по footgun-устойчивости**.
6. **Credential helpers / keystores без явного deny.** Linux D-Bus (`AF_UNIX` разрешён,
   `DBUS_SESSION_BUS_ADDRESS` не фильтруется), macOS `security`/Keychain (в SBPL-шаблоне
   нет keychain-deny), Windows Credential Manager/DPAPI (без заявлений — честно
   Unsupported). Вердикт: **Partial (Linux/macOS) / Unsupported (Windows native)**.
7. **Shell history / browser / cloud paths вне deny-листа.** Профили покрывают
   `.ssh/.aws/.gnupg/.kube/.docker/.config/gcloud|gh|copilot/.npmrc/.netrc/
   .git-credentials/.cargo/credentials*/.claude/.codex` + $PROJECT shapes, но не
   `~/.bash_history|~/.zsh_history`, `~/.local/share/keyrings`, browser profiles,
   `~/.config/gcloud/application_default_credentials.json` (частично через dir),
   `~/.aws/sso/cache`, `~/.kube/cache`, systemd-credentials, CI secret mounts
   (`/run/secrets`), `/proc/self/environ` чужих процессов (закрыто pidns в FULL,
   открыто в FS-ONLY/macOS/Windows). Вердикт: **Partial**.
8. **Несуществующие deny-пути = тихий no-op.** `mask_path` → `Ok(false)`
   (`mounts.rs:274`), glob no-match → empty set (`glob_resolve.rs:48`).
   Late-created `$PROJECT/.env` после старта не маскируется. Вердикт: **Unsupported**
   без fanotify/eBPF/VM (честно).

## 3. Threat model / taxonomy / invariants (кратко)

Threat: враждебный агент с произвольным кодом как invoking user: читает файлы/env/
helpers/keys/caches, исполняет хелперы, пишет temp/log, ходит в сеть (где разрешено),
переживает supervisor (orphan/setsid). Non-goals: hostile kernel, root, физика,
злонамеренный vetto (как в `docs/threat-model.md`).

Taxonomy классов: A) long-term identity (ssh/gpg), B) cloud/IaC (aws/gcp/azure/kube),
C) VCS/registry tokens (gh/gl/npm/cargo/pypi/hf), D) API keys (openai/anthropic/gemini),
E) local trust (netrc/git-credentials/.env/kdbx/p12/pfx/pem/key), F) session/bearer
(env/argv/tmp/core/log), G) platform stores (keychain/credential-manager/libsecret/
browser), H) metadata endpoints (169.254.169.254, metadata.google.internal).

Invariants (fail-closed):
- I1: deny-by-default на секреты на всех OS; grant только explicit + session-scoped.
- I2: санитайзер никогда не граница; граница только kernel/token/namespace/VM.
- I3: секрет никогда не возвращается в песочницу — только host-side attachment.
- I4: неизвестное = запрещено (неизвестный профиль/env/socket/helper → bail, exit 103).
- I5: в логах только класс, никогда значение (path+rule+line, без preview байт).
- I6: child не наследует ambient credentials (env strip + no helper sock + no bus).

## 4. Архитектурные варианты (trade-offs)

1. **deny-path** — дёшево, точно по известным путям; не ловит неизвестные места,
   symlink-alias (лечится canonicalize, уже есть в `types.rs:409`), late-created файлы.
2. **environment filtering** — allowlist-only Strong и дёшев; не покрывает файлы/helpers;
   footgun при `pass_through=["*"]` — лечить lint+deny-пресеты.
3. **secret broker / capability broker** — единственный путь дать доступ без раскрытия;
   цена: IPC-auth, session binding, revocation, audit; текущий GetHeader — антипаттерн
   (возврат значения), чинить в proxy-attach.
4. **trusted helper process** — git-ssh-proxy образец (дочерний, не демон); цена:
   каждый helper — новый аудит поверхности.
5. **host-side secret injection** — env/argv инъекция host-стороной; env/argv всё равно
   видны `/proc` и логам → только для эфемерных + RLIMIT_CORE=0 + санитайзер логов.
6. **temporary ephemeral credential** — сужает blast radius (TTL/scope/session-bind);
   цена: нужен issuer (cloud IAM, gh apps); без него — только обёртка над long-term.
7. **network proxy with credential attachment** — лучший для egress-секретов: секрет не
   пересекает границу, брокер пинает DNS/IP (уже умеет); цена: только proxy-shaped
   протоколы (документировано), не покрывает локальные файлы.

## 5. Default policy (deny-by-default)

Автоматически скрывать (все OS, где механизм есть): §2.7 список + shell history,
keyrings, browser credential stores (deny-правила даже на несуществующие пути —
сигнал для lint), cloud metadata (сеть). Explicit grant: только через
`[secrets] grant = [{class, session, ttl, scope}]`, одноразовый, привязан к
`session_id+root_pid`, revoke при `SessionEnded`/timeout; read-only grant для файлов =
overlay-remount ro невозможен → grant только через broker-read (host отдаёт bytes по
fd, не путь). Наследование в child: env strip на каждом exec (не только на входе),
`close_all_except` уже есть; добавить `RLIMIT_CORE=0` + сброс `DUMPABLE`.

## 6. Exfiltration-разбор (честно)

- read+net-off: безопасно кроме side-channels (shm в том же trust boundary, timing) —
  можно читать, вынести некуда; остаток: запись в $PROJECT/.vetto-reports (маскировать
  sibling dirs уже делает `isolate_agent_state_dirs`).
- read+net-allowed: **DLP невозможен без taint-tracking** — брокер видит домен/байты,
  но не semantic origin; allowlist + per-domain quota + no-TLS-intercept (заявлено).
  Не обещать контент-инспекцию.
- env/argv: allowlist + strip + санитизация логов + CORE=0; argv всё равно виден в
  `/proc` внутри той же pidns — считать argv публичным внутри сессии.
- helper/credential-helper: только host-side; in-sandbox helper = confused deputy.

## 7. Platform mapping

- **Linux**: protected paths → deny_resolved+overlay (FULL Strong / FS-ONLY Partial /
  Seccomp Unsupported); env filter Strong; Landlock implications (чистый allowlist,
  карвинг только оверлеями/энумерацией); credential helper isolation → host broker +
  D-Bus deny (новое); namespaces (уже есть); metadata → broker reject Strong.
- **Windows**: AppContainer caps + low-integrity + Job kill-on-close (есть);
  ACL/DACL субтракции нет → deny-inside-grant fail-closed (есть, оставить);
  user profile: default-deny вне грантов; Credential Manager/DPAPI → **Unsupported**,
  только VM; PowerShell env — тот же `environment_block` (Strong); WSL interop →
  рекомендовать WSL2 Tier 1.
- **macOS**: App Sandbox/Seatbelt Shape A + tail-deny (Partial); Keychain/TCC →
  добавить явный keychain-deny или честно Unsupported; user profile paths — broad read
  (Unsupported); native vs VM → для строгих требовать OrbStack/Linux VM.
- **VM strategy**: `--backend win-sandbox` (.wsb, host secrets не мапятся — Strong),
  macOS → OrbStack/devcontainer, Linux → microVM для DLP/taint (будущее, не обещать).

## 8. Audit/observability

Писать: access attempts (BlockedAttempt — есть), denials (есть), secret **class**
(rule/path/line, без value — новое), policy decisions (warnings уже есть в
`checker.rs`/`lint.rs`), broker operations (lease issue/attach/deny/revoke —
новое, без значений). Все sinks через `sanitizer::sanitize_line`; history.jsonl —
туда же + nofollow/hardlink как в jsonl.rs. Core/argv — санитизировать до записи.

## 9. Adversarial tests (новые, к существующим `secret_masking.rs`, `adv_isolation.rs`)

`cat ~/.ssh/id_rsa`, `env|grep -i token`, argv-секрет в jsonl/history/report/oslog/
notify, symlink/`..`/double-slash/trailing-dot обходы deny, REFER/move/hardlink секрета
в readable subtree (есть прецедент `linux_landlock.rs:236`), late-created `.env`,
`git credential fill`, `SSH_AUTH_SOCK` inherit, `secret-tool`/`security dump-keychain`/
`CredRead`, `curl 169.254.169.254`, DNS rebinding, core dump (`kill -ABRT; gdb core`),
чужой session читает чужой broker socket, `allowlist ["*"]` reject, `pass_through ["*"]`
lint-warn.

## 10. Exact repo changes (файлы/модули, без production-кода в этом ходе)

1. `src/cred_broker.rs` — протокол без возврата значения (proxy-attach), SO_PEERCRED,
   session-bind, TTL/revoke, запрет `*`, zeroize+mlock. **Partial→Strong**.
2. `src/sandbox/linux/net_relay.rs`, `src/main.rs:863`, `src/sandbox/linux/mod.rs:1128`
   — слить cred broker с net relay; сокет через SCM_RIGHTS, не `/tmp` путь.
   **Partial→Strong** (escape-закрытие).
3. `src/policy/types.rs`, `loader.rs`, `defaults.rs`, `presets.rs`, `profiles/*.toml` —
   `SecretClass` + `secrets.deny_by_default` + session grants; расширить deny-лист
   (§2.7). **Partial→Strong (FULL) / честный Partial (остальные)**.
4. `src/policy/secretscan.rs`, `src/main.rs:569` — preview → класс-only, расширить
   правила (kube/docker/auth.json/sso cache), лимиты оставить. **Partial→Strong-er
   (всё равно не граница)**.
5. `src/logger/oslog.rs`, `system_log.rs`, `src/notify/mod.rs`,
   `src/audit/history.rs`, `src/events/replay.rs`, `tail.rs` — санитайзер везде +
   nofollow для history. **Partial→Strong (как courtesy layer)**.
6. `src/sandbox/linux/limits.rs`, `src/sandbox/macos/limits.rs`,
   `src/sandbox/linux/mod.rs:382`, `src/sandbox/windows/mod.rs` — `RLIMIT_CORE=0`,
   сброс DUMPABLE в agent child, WerDump off. **Partial→Strong**.
7. `src/sandbox/linux/mod.rs:664`, `macos/mod.rs:425`, `windows/mod.rs:1114`,
   `src/policy/defaults.rs`, `lint.rs`, `checker.rs` — явный env deny-пресет
   (ASKPASS/HELPER/SSH_AUTH_SOCK/GPG/KUBECONFIG/DOCKER/*TOKEN), lint против
   `pass_through=["*"]`, убрать/сжать `XDG_RUNTIME_DIR`. **Strong 유지**.
8. `src/sandbox/macos/seatbelt.rs` — keychain-deny или документированный Unsupported;
   `src/sandbox/windows/*` — Credential Manager Unsupported + VM путь.
   **Partial→честный Unsupported**.
9. `src/sandbox/linux/seccomp_netblock.rs`, D-Bus env — abstract-socket/bus deny для
   secret классов. **Partial**.
10. `docs/*`, `SECURITY.md`, `docs/threat-model.md`, `docs/platform-backends.md` —
    обновить claims (что можно/нельзя). Тесты: `tests/integration/secret_masking.rs`
    (расширить на history/oslog/notify/preview/core), новый
    `tests/integration/secret_isolation.rs`.

## 11. Migration plan

Фаза 0: этот proposal + lint-warnings (не ломать). Фаза 1: лог/аудит санитайзер +
CORE=0 + preview класс-only + env deny-пресет (обратно совместимо). Фаза 2: брокер
proxy-attach + SCM_RIGHTS (флаг-гейт, старый GetHeader deprecated→удалён). Фаза 3:
SecretClass/grants + расширенный deny-лист + VM-документация. Каждая фаза — свои
adversarial тесты, fail-closed по умолчанию.

## 12. Security claims: можно / нельзя

Можно (после фаз): ambient credentials не наследуются; секреты deny-by-default;
брокерные секреты не пересекают границу; логи не содержат значений; FULL скрывает
известные пути kernel-уровнем; metadata недоступна через брокер.
Нельзя: DLP/taint без VM; read-изоляция на macOS native и субтракция на Windows
native; late-created файлы без перезапуска сессии; защита от prompt injection внутри
разрешённых API; side-channels; hostile kernel/root.

## 13. Critical questions (ответы)

- Deny-by-default на всех OS: §5 список + metadata + helper socks (где механизм
  отсутствует — fail-closed отказ запуска, как Windows делает сегодня).
- Только через trusted broker: любой секрет, нужный агенту для egress (API keys,
  registry tokens, git/cloud creds) — host-side attach, никогда файлом/env/argv.
- Где без VM/host component нельзя: macOS read-deny, Windows subpath-subtract и
  Credential Manager, полный DLP/taint, late-created файлы строго.
- Accidental exposure (logs/dumps/argv/env): санитайзер везде + класс-only preview +
  CORE=0/DUMPABLE=0 + allowlist env + argv считать публичным внутри сессии.
