# Policy Engine + Sandbox IR — Architecture Proposal (Prompt 02)

Статус: proposal, production-код не писать. Скоуп: `docs/` + контракты. `src/verify_ng/` не трогать.

## 1. Current architecture (факт по репозиторию)

Конвейер сегодня: `CLI (src/cli.rs, src/config.rs RunConfig)` → 7-tier `LayeredPolicyLoader` (`src/policy/loader.rs`: SystemGlobal → UserGlobal → BuiltinProfile/Preset → AgentPreset → Repository(+fragments) → LocalOverride → CliExplicit/CliOverride) → glob/var-резолв в конкретные пути (`glob_resolve.rs`: `$PROJECT/$HOME/$AGENT`, `~`, 50k cap, несуществующие glob = пустое множество) → `Policy` (`src/policy/types.rs`) → тир-зависимый `build_policy()` (FS-ONLY вырезает secret-shaped reads из allowlist, бюджет 20k) → `Backend::detect/spawn` (`src/sandbox/mod.rs`: Linux FULL/FS-ONLY/Seccomp, macOS Seatbelt, Windows process-sandbox) → lifecycle через `SandboxHandle` (`src/sandbox/handle.rs`). Параллельно: `checker.rs` (warnings), `lint.rs` (R1–R5), `explain.rs` (`--why`, JSON), `crypto.rs` (Ed25519-подпись слоёв), `conditions.rs` (bounded `branch/file_exists/project_contains`).

Ключевые факты, влияющие на IR:

- FS/Network разделены по владельцам: FS-корни живут в `Policy` (TOML-слои), а net-режим — в `RunConfig::net` (CLI/global/agent-default), не в policy-слоях. `deny_network: bool` в `Policy` — только intent слоя, enforcement зависит от CLI. Это расщепление — главный источник silent-downgrade риска.
- Landlock — чистый allowlist без subtract (`ARCHITECTURE.md`): deny внутри allowed-дерева на FULL маскируется mount-overlay (`mask_restricted_devices`, `mask_path`, `isolate_tmp/shm`), на FS-ONLY — энумерацией дерева с вырезанием secret-shaped файлов (`is_secret_shaped`: `.env*`, `pem/key/p12/pfx/kdbx`, case-insensitive) + `strip_read_on_write` (READ_FILE снимается с write-корней; честная цена: созданное в корне нельзя прочитать обратно).
- Сеть Linux FULL: netns без интерфейсов + loopback CONNECT/SOCKS-релей → host-брокер (проверка имени → один DNS-lookup → reject unsafe answer set → connect к pinned IP:port, TLS opaque, без SNI-инспекции и CA). Off на FULL = пустой netns; на FS-ONLY = seccomp-гейт семейств сокетов. Relay требует FULL, иначе fail-closed (`LinuxSandbox::spawn`). `--git-ssh` — только Linux, через ProxyCommand по тому же CONNECT-пути.
- macOS: нативный Seatbelt через `sandbox_init_with_parameters` in-memory (без `sandbox-exec`), профиль `(deny default)` + `file-write*` на allow_write + broad `(allow file-read* (subpath "/"))` + trailing deny на `deny_resolved` (last-match-wins). Только `--net=off` (`deny network*` + исключение `network-outbound remote unix-socket` для XPC); allowlist/strict/ask — fail-closed до запуска. Эмпирический максимум Shape A (`SBPL_MAXIMUM_READ_SHAPE`): фрагментированные read-allowlist SIGABRT'ят dyld на macOS 13–15 — узкий read недостижим не по вине vetto. Read-deny без mount ns — best-effort против нативных бинарников; `doctor` показывает `sbpl-read-fragment` probe.
- Windows: experimental `processmodel.dll!Experimental_CreateProcessInSandbox` (runtime-resolve, System32-only) + AppContainer + restricted low-integrity token (когда есть as-user export) + Job Object kill-on-close. Только `--net=off`; доменные режимы — fail-closed (нет DNS→IP-компилятора). Spec — FlatBuffers `SandboxSpec`: write/read гранты + пустой NetworkPolicy (default-deny контракт API). Deny внутри гранта — fail-closed bail (`path_inside_root`, case-insensitive, lexical; symlink-алиасы и 8.3 short names не моделируются — честно задокументировано). Stdio только inherit. Нет WIN-BASIC fallback. WFP/firewall/minifilter/Windows Sandbox — отдельные capability-gated opt-in, не вызываются launcher-путём, elevation не запрашивается.
- Окружение — default-deny везде: фильтр `EnvironmentPolicy::allows` (exact + префикс `*` только в конце; `normalize_env_patterns` молча дропает `*`, `=`-содержащие, не-`[A-Za-z0-9_]`) + `cred_broker::filter_proxy_secrets` (двойная strip: до и после `env_extra`). `env_extra` — только внутренние `VETTO_*`. Windows дополнительно: case-insensitive dedup, сортировка блока, 32 MiB лимит, дроп `=`/`NUL`-имён.
- Лимиты: `ResourceLimits` strictest-wins на всех уровнях слияния (слои → `--limits` → cgroup). Парсинг `--limits` fail-closed на неизвестных ключах/суффиксах, overflow-checked. Маппинги: Linux rlimit+cgroup перед exec; macOS rlimit best-effort (отказы — в stderr, не скрыты); Windows Job memory/active-process + best-effort IO-rate (без fail всего job на старых Windows — см. ниже как несоответствие инварианту).
- Immutability: `security.immutable=true` на Tier 1 запрещает снимать lockdown и добавлять allow-пути через CLI (`PolicyLockdownViolation`). Но: запрет покрывает только `allow_write/allow_read`, не `pass_through`/net/limits — дыра (см. §3).
- Наблюдение никогда не кормит enforcement (threat-model.md §"Why observation never feeds enforcement"): Landlock/Seatbelt применяются до exec, ивенты — advisory.
- `VETTO_FORCE_TIER`, `VETTO_SEATBELT_MODE=none/allow-all/...`, `VETTO_NO_MAC_LIMITS`, `VETTO_CHILD_TRACE` — env-киллсвитчи, способные ослабить границу вне policy. Сегодня не хешируются и не попадают в отчёты.
- Policy hash сегодня отсутствует: нет канонической сериализации, нет `policy hash → effective config` связи; `verify`/`doctor --probe` проверяют границу throwaway-песочницей, но не сверяют `effective == requested` через хеш.

## 2. Prompt 02: разбор (не принимать на веру)

Технически неверное / небезопасное в prompt:

1. `allowlist destinations` + `CIDR/IP rules` как единый net-блок IR — небезопасное смешение. Репозиторий намеренно запрещает IP-литералы в доменных режимах (`validate_domain` в `config.rs`) и валидирует DNS-ответы через брокер (reject private/loopback/link-local/multicast/reserved, NAT64, metadata `169.254.169.254`). Отдельное поле `allow_cidr` существует в `Policy`, но семантика его enforcement на FULL-релее не определена тем же строгим путём. IR обязан разделить `egress.domains` (брокер, DNS-пиннинг) и `egress.cidr` (сырой IP-уровень, только где есть IP-enforcement: Landlock ABI4 connect/bind-порты, WFP-lease) и запретить CIDR как способ обойти доменный пиннинг.
2. `proxy mode` как нейтральное поле — опасно без явного запрета TLS-инспекции. Архитектура репозитория: брокер opaque byte pump, без CA/SNI-парсинга. IR фиксирует: `proxy.opaque_tls_passthrough=true`, `tls_interception=unsupported` на всех бэкендах (расширение только через отдельное explicit-поле, default off, требующее host-компонента).
3. `DNS behavior` в песочнице — в FULL DNS внутри песочницы нет вообще (`blackhole_resolv_conf`), резолвит хост-брокер один раз с валидацией всего answer set. IR не должен обещать "настраиваемый DNS внутри" — только `dns: { broker_resolved_once_pinned }`.
4. `interpreter policy` / `allowed executables` как общее поле — нереализуемо единообразно: Landlock даёт EXECUTE-право на inode, Seatbelt — `process-exec` blanket, Windows — AppContainer без per-binary allow в текущем spec. Общее поле допустимо только как `process.exec_scope: { allow_roots }` с capability `partial` везде, либо platform-extension.
5. `shell behavior`, `service/daemon creation` как IR-семантика — в репозитории это следствие PID-namespace/Job lifecycle, а не отдельные примитивы. Отдельные булевы флаги создадут ложную точность. Правильно: `lifecycle.*` + `process.inheritance`, без `can_create_service: true/false`.
6. `disk usage if enforceable` / `network bandwidth if enforceable` — "if enforceable" в prompt противоречит его же требованию "backend не может silently degrade". В IR нет условных полей: каждое поле имеет capability-статус, и `unsupported`/`requires_*` → fail-closed или явный opt-in, никогда "постараемся".
7. `requires_vm` как capability-статус в одном ряду с `supported_*` — смешение категорий (место исполнения vs степень поддержки). Разделить: `support: exact|partial|unsupported` × `needs: none|host_component|vm|admin|entitlement`.
8. Конвейер prompt (`... → Validation → Enforcement`) пропускает фазу резолва glob→concrete и фазу capability-check до fork. В репозитории glob-резолв load-time и fail-closed бюджеты (50k, 20k, condition-scan бюджеты) — load-bearing. Правильный конвейер: `User Policy → Normalize → Resolve (vars/globs→concrete, бюджеты) → Sandbox IR (frozen) → Backend Plan → Capability Check → Validation → Enforcement → Verify(applied plan)`.
9. `policy hash uniquely identifies effective security config` — верно как цель, но хеш только policy недостаточен: effective config включает CLI `--net`, `env_extra`, тир/ABI, бэкенд-капабилити, kill-свитчи env. Хешировать надо frozen IR + backend plan + provenance (см. §8).

## 3. Gap-анализ: чего не хватает сегодня для IR

- Нет frozen IR-артефакта: `Policy` мутирует (`checker::check` retain'ит несуществующие write-корни с warning — это widen-by-drop? нет, это tighten, но молчаливое изменение requested без фиксации в хеше нарушает "verification sees actual applied plan").
- Net-режим вне policy-слоёв: `RunConfig.net` не участвует в `MergedPolicy`, не подписывается `crypto.rs`, не входит в precedence-иерархию (§6 чинит).
- Нет machine-readable capability-модели: `probe()`/`capabilities()` есть, но маппинг "поле→статус" живёт в головах и `bail!`-строках. Нужен `CapabilityReport` как данные.
- Нет Backend Plan как данных: backend сразу `spawn`s; `--dry-run`/`explain` печатают, но не сериализуют детерминированный план для verify.
- Нет детерминизма по построению: HashMap-итерация (`net_quota`), glob-порядок, `identity_nonce` — для хеша нужна каноническая сериализация (sorted keys, stable order).
- Дыры immutability: покрыты только allow-пути; `pass_through`, net, limits, `secret_proxies`, env-override через CLI не блокируются. IR фиксирует полный never-overridable set.
- Windows IO-rate best-effort (`SetInformationJobObject` failure игнорируется) противоречит инварианту "impossible never reported as enforced": либо fail-closed, либо capability `partial` + warning в plan, с явным статусом в отчёте.
- macOS `VETTO_SEATBELT_MODE=none` — диагностический обход enforcement через env вне policy. В IR-модели любой такой свитч обязан входить в provenance-хеш и помечать plan `tainted: true` → verify fail.

## 4. Sandbox IR — концептуальная схема (versioned, frozen)

`ir_version: "0.1.0"`. Все пути — concrete absolute canonical (резолв уже произошёл; glob-паттерны в IR запрещены). Все списки — отсортированы, дедуплицированы. Неизвестные поля на любом уровне — hard error (fail-closed), никогда ignore.

```toml
[meta]
ir_version = "0.1.0"
schema_hash = "<blake2/sha256 канона схемы>"
source_layers = ["system-global", ..., "cli-override"]  # provenance, ordered
canonical_bytes_hash = "<hash frozen IR>"               # §8

[fs]
write_roots = [...]        # concrete dirs/files, allow
read_roots  = [...]        # concrete, allow (без write-прав)
deny_subtractions = [...]  # concrete существующие; вне грантов = warn useless_deny
read_only = true           # read_roots никогда не дают write (инвариант)
symlink_policy = "resolve_parent_then_prefix"  # как сегодня normalize_scope_path
mount_semantics = "no_host_mounts"             # агент не получает новых маунтов
host_mounted_paths = []    # пусто по умолчанию; любой элемент → needs host_component

[egress]
mode = "off"               # off | domain_allowlist | domain_strict | ask
domains = [...]            # lowercased DNS-имена, без IP-литералов
strict_ports = {...}       # domain -> [ports], только при mode=domain_strict
dns = "broker_resolved_once_pinned"
tls = "opaque_passthrough_no_interception"
cidr = [...]               # РАЗДЕЛЬНО от domains; только IP-enforcement backend'ы
bind_ports = [...]         # Landlock ABI4+; иначе capability
connect_ports = [...]
unix_ipc = "always_allowed"          # AF_UNIX разрешён во всех режимах
unix_socket_files = [...]  # требуют fs-грантов на файл сокета (как сегодня)
quotas = {...}             # per-domain bytes; enforcement best-effort → capability partial

[process]
exec_scope = "allow_roots" # exec только из read/write-корней (Landlock EXECUTE); Seatbelt/Win = partial
inheritance = "same_policy" # потомки наследуют (Landlock irreversible, Seatbelt inherit, Job containment)
detach_policy = "contained_or_fail" # FULL: kernel-kill; FS-ONLY/macOS: group-kill+sweep/watchdog (докум. гэп)
privilege_drop = true      # capabilities stripped / low-integrity / least-privilege
no_new_privs = true        # Linux; где нет аналога → capability

[secrets]
default = "deny"
brokered_env = [...]       # secret_proxies: strip из env, только через host-брокер
masked_paths = [...]       # deny_resolved concrete
mask_mechanism = "overlay|carve|sbpl_tail_deny"  # выбирает backend, фиксируется в plan
inherited_credentials = "deny"  # SSH/agent-сокеты, облачные credential-файлы — только явным грантом (который lint помечает high)

[env]
mode = "allowlist"         # inherit-all ЗАПРЕЩЁН на уровне схемы (нет такого значения)
pass_through = [...]       # exact + trailing-*; нормализация как сегодня, дропнутое — в warnings IR
deny = [...]               # deny бьёт allow (инвариант)
home_synthetic = "..."     # значение HOME внутри (default: реальный HOME; изменение — explicit)
tmp_isolated = true        # /tmp tmpfs (FULL) / policy tmpfs_tmp

[resources]
cpu_seconds, address_space_bytes, processes, open_files, file_size_bytes
io_iops, io_bandwidth_bytes
merge = "strictest_wins"   # инвариант слияния

[lifecycle]
session_identity = "<stable id>"   # НЕ nonce без фиксации: nonce входит в plan, не в IR-хеш
timeout_secs, cleanup = "kill_tree", reap = "kernel|group+sweep|job_close"
orphan_policy = "kill"     # где kernel не может → задокументированный гэп + capability partial
crash_handling = "fail_closed_report"

[extensions]               # intentionally platform-specific, префикс по ОС
linux.seccomp_profile / linux.cgroup / linux.dev_allow
macos.oslog
windows.lpac / windows.io_rate / windows.appcontainer_identity
# Правило: consumer обязан отвергнуть неизвестный extensions.* (deny_unknown_fields на каждом уровне).
```

Семантика capability на поле (machine-readable, в Backend Plan, не в user policy):

`support: supported_exactly | supported_partially | unsupported` × `needs: none | host_component | vm | admin | entitlement`. `best_effort` как статус ЗАПРЕЩЁН: либо `supported_partially` с явным описанием потери (`loss: "reads of newly-created secret-shaped files in FULL tmpfs_tmp gap"`), либо `unsupported`. "Partial" без описания потери — inval
id plan.

## 5. Нормализация: `User Policy → Normalized → IR`

1. Parse (deny_unknown_fields на каждом слое, как сегодня) → 2. Precedence-merge (§6) → 3. Vars/globs→concrete resolve с бюджетами (50k glob, 20k FS-ONLY-enum, condition-scan budgets; превышение = fail-closed, не truncation) → 4. Subtractive apply (deny бьёт allow; deny вне грантов → `useless_deny` warn, не error) → 5. Tier-independent IR freeze (каноническая сериализация: sort, dedup, lowercase domains, normalize env-patterns; дропнутое — в `ir.warnings`, warnings входят в хеш) → 6. Hash IR → 7. Backend Plan compile → 8. Capability check → 9. Validation (invariants §7) → 10. Enforcement → 11. Verify видит applied plan (§8).

Детерминизм: канон = UTF-8, LF, sorted keys/arrays, integers decimal, paths canonical-lexical. `net_quota` HashMap сериализуется sorted. Nonce/identity — только в plan.

## 6. Precedence (фиксирует расщепление net)

Порядок (возрастание силы): `system-global < user-global < builtin-profile < preset < agent-preset < repository < repository-fragment(sorted) < local-override < cli-explicit-file < cli-flags < generated-security-profile(computed, не слой) < platform-backend-constraints (только tighten)`.

Правила: merge `allow_*` — union; `deny_*` — union (deny монотонно, снять deny верхним слоем нельзя — только сузить соответствующий allow); `limits` — strictest-wins; `env.pass_through` — union минус `deny`; net-режим: единый источник — `cli-flags > agent-default > global-config > off`, policy-слои могут только требовать `off` (tighten), никогда включать relay. Never-overridable (даже CLI): `immutable` снятие, `deny` снятие, `env.mode=allowlist`→`inherit-all` (такого значения нет в схеме), `tls.opaque` выключение, снятие `no_new_privs`/`privilege_drop`, добавление allow-путей при lockdown. Backend constraints только сужают (fail-closed при конфликте), никогда не расширяют.

## 7. Backend contract (trait, без привязки к Win32/Landlock/SBPL в сигнатурах)

```
parse(user_layers) -> NormalizedPolicy
resolve(normalized, ctx{project,home,agent,tier_probe}) -> ResolvedConcrete
compile(ir: FrozenIR) -> BackendPlan { steps: [...opaque backend ops...], capability: per-field Support×Needs, loss_descriptions, deterministic_bytes }
check(plan) -> ok | fail_closed(reason, action)
construct/apply/launch/cleanup  (жизненный цикл, как сегодня spawn→handle→terminate)
report_capabilities() -> CapabilityReport  (данные, не строки)
verify_applied(plan_hash) -> Attestation { ir_hash, plan_hash, backend_id, abi/enforcement ids, taint_flags }
```

Инварианты (formal-ish): (i) `unsupported` никогда не репортится как enforced; (ii) backend не расширяет запрошенное (plan ⊆ IR по каждому полю); (iii) defaults explicit (пустое ≠ дефолт: `tmp_isolated`, `no_new_privs` всегда присутствуют); (iv) deny бьёт inherit на всех уровнях; (v) unknown field = hard error; (vi) хеш frozen IR + plan однозначно идентифицирует effective config (включая net-источник, tier/ABI, taint); (vii) plan детерминирован при тех же входах (nonce вне хешируемой части); (viii) verify читает applied plan (attestation из enforcement-контекста), не requested policy.

Fail-closed матрица: relay на не-FULL → abort; allowlist/strict/ask на macOS/Windows → abort; deny-внутри-гранта на Windows → abort; CIDR при отсутствии IP-enforcement → abort; `useless` deny → warn; бюджет резолва превышен → abort; taint (kill-switch env) → plan помечен, verify fail, запуск только с explicit `--allow-tainted` (которого по умолчанию нет; поле reserve).

## 8. Хеш и доказательство `effective == requested`

- `ir_hash = H(canonical(FrozenIR))`; `plan_hash = H(canonical(BackendPlan без nonce/identity/pid))`; session attestation = `{ir_hash, plan_hash, backend_id, abi, capability_vector, taint, source_layers}` — пишется в JSONL/отчёты (`report/`, `audit/`) и показывается в `policy explain --json`.
- Доказательство равенства: verify перекомпилирует plan из frozen IR детерминированно и сравнивает `plan_hash`; затем enforcement-контекст (до exec, в setup-цепочке) подтверждает применение (`R`-байт readiness уже существует — расширить его attestation-payload) вместо доверия requested. Расхождение любого байта → fail-closed exit 103.
- Хеш живёт в трёх местах: frozen IR-артефакт сессии (рядом с отчётом), session JSONL, `doctor --probe` вывод. Отдельного "policy registry" не нужно.

## 9. Маппинги (Strong / Partial / Unsupported)

Легенда: Strong = kernel-guaranteed deny; Partial = enforced с описанной потерей; Unsupported = fail-closed при запросе.

Linux FULL: fs.write Strong (Landlock allowlist + NO_NEW_PRIVS irreversible); fs.read Strong вне дерева, внутри дерева — Strong через mount-overlay; deny_subtraction Strong (overlay); symlink Strong (VFS inode-decision); host_mounted_paths Strong (private ns); egress.off Strong (пустой netns); domain_allowlist/strict Strong при proxy-shaped TCP (потеря: non-proxy-aware протоколы не работают — это fail-closed by design, не downgrade); CIDR Partial (только через ABI4 port-правила + брокер-пиннинг; чистый IP-allow без DNS — Partial с loss); unix_ipc Strong; exec_scope Strong (EXECUTE-право); inheritance Strong (irreversible наследование); detach Strong (PIDNS kernel-kill); privilege_drop/no_new_privs Strong; secrets.brokered Strong (двойная strip); env allowlist Strong; resources Strong (rlimit+cgroup; io — через cgroup, см. extensions); lifecycle Strong.
Linux FS-ONLY: fs.read Partial (carve + strip_read_on_write, loss: созданное-в-корне нечитаемо; late-created secret-shaped файлы в writable-корне — известный гэп → Partial с loss); detach Partial (group-kill + subreaper-sweep, setsid-gap документирован); egress relay Unsupported (fail-closed); mounts Unsupported.
Linux Seccomp-tier: fs.* Unsupported (только syscall-hardening + netblock); запрошенный fs-IR → fail-closed.
macOS Seatbelt: fs.write Strong (SBPL write* на корни); fs.read Partial (Shape A broad + tail-deny; loss: read-изоляция незамаскированного — best-effort против нативных бинарников, честно в doctor); deny_subtraction Partial (только для deny_resolved, last-match-wins); symlink Partial (SBPL subpath-семантика ≠ inode; TOCTOU-стойкость слабее Landlock); egress.off Strong (`deny network*` + unix-socket исключение для XPC — исключение задокументировано, не скрыто); domain_*/ask/cidr/bind/connect Unsupported (fail-closed); exec_scope Partial (`process-exec` blanket); inheritance Partial (наследование SBPL без PIDNS); detach Partial (kqueue watchdog, без kernel-kill); privilege Strong-нет-аналога → Partial (rlimit best-effort, отказы в stderr); secrets.brokered Strong (env-strip общий); lifecycle Partial.
Windows process-sandbox: fs.write/read Strong внутри AppContainer-границы при доступных API (default-deny вне грантов); deny_subtraction Unsupported внутри гранта (fail-closed bail — это честный Partial→abort, не silent); symlink Partial (лексическая проверка + loader-resolved deny, 8.3/symlink-алиасы не моделируются); egress.off Strong (AppContainer caps, default-deny); domain_*/cidr/ports Unsupported без WFP-lease (fail-closed; WFP = needs admin, explicit opt-in, не часть launcher-плана); unix_ipc N/A (нет AF_UNIX-семантики релея; локальный IPC — через LPAC-изоляцию, Partial); exec_scope Partial; inheritance Strong через Job containment; detach Strong (kill-on-close); privilege_drop Strong (restricted+low-integrity/AppContainer least-privilege); env Strong; resources Strong для cpu/mem/processes, io_rate Partial (best-effort на старых Windows → plan обязан ставить partial+loss, а не молчать); lifecycle Strong.
macOS Linux-VM mapping (OrbStack/Docker/VM): вне host-сущностей — это Linux FULL внутри гостя; IR тот же, `needs: vm`, host-secrets не мапятся в гостя по умолчанию (`mapped_folders` — explicit allow, каждый — fs-grant с provenance `vm-mapping`); сеть гостя — через его netns-стек; attestation дополнительно фиксирует `vm_boundary: true`. Windows Sandbox `.wsb`: аналогично `needs: vm`, mapped folders explicit, vSwitch off при `egress.off`.

## 10. Critical questions (явные ответы)

- Что нельзя выразить общим IR: точные mount/topology-операции (overlay vs carve vs tail-deny — это plan, не intent); dyld-совместимые read-формы macOS; Windows integrity-level/AppContainer-SID детали; symlink-раскрытие на не-inode системах; per-syscall seccomp-профили вне Linux; поведение XPC/mach-lookup; 8.3/short-name алиасы; точная семантика `setsid`-побега (это loss-описание, не флаг).
- Intentionally platform-specific: `linux.seccomp_profile/cgroup/dev_allow/io_priority`, `macos.oslog`, `windows.lpac/io_rate`, `net_ports` (ABI4) как extension с fallback Unsupported, `dev/shm/tmp` изоляция детали, `snapshot/ephemeral/git_guard` (это product-фичи, не sandbox-примитивы — в IR не входят, живут рядом).
- Против LCD: IR выражает строжайший intent (deny-by-default, deny-beats-inherit, no inherit-all), а backend честно ставит Unsupported вместо усреднения; общий знаменатель запрещён правилом "сужение только через fail-closed, не через silent".
- Против silent downgrade: capability-check до fork + deterministic plan-hash + verify(applied) + taint-флаги + запрет `best_effort` без loss-описания + `unknown=error`.
- Где живёт policy hash: в frozen IR-артефакте сессии + JSONL + отчёты + `explain --json` (три места, §8), не в отдельном registry.
- Доказательство effective==requested: детерминированная перекомпиляция + сравнение plan_hash + attestation из enforcement-контекста (readiness-payload), не из requested policy.

## 11. Security pitfalls / anti-patterns

Exfiltration: allowlist без DNS-пиннинга (rebinding) — запретить схемой (только broker-pinned); IP-литералы в domain-полях — reject; `*.domain` покрывает subdomains, не base — фиксировать в нормализации; proxy-creds в env песочницы — только через brokered_env; `net_quota` не считать enforcement (учёт, не граница). Escape: writes в `/`, `/usr`, `$HOME` (lint R1/R2 → в IR-validation как hard-fail при lockdown, warn иначе); `allow_read=/` (yolo) + secrets только через masked_paths — честно Partial на macOS; `ro_mounts` вне read — авто-грант только явный (как сегодня, но фиксировать в plan). Adversarial: prompt-инъекция внутри разрешённого API — out of scope IR (зафиксировано в threat-model), но IR не должен давать полей "content-filter" (ложная граница); malicious dependency с exec — покрывается exec_scope+inheritance, не blocklist'ами. Tautологии: `display_only_deny` имя вводит в заблуждение — в IR переименовать в `masked_paths` (enforcement-механизм фиксирует plan). Env `*` (full-wildcard) — reject схемой. `VETTO_SEATBELT_MODE`/`VETTO_FORCE_TIER` вне хеша — taint (см. §7).

## 12. Предлагаемые файлы (только proposal, кода нет)

- `docs/policy-ir-proposal.md` — этот документ (финал).
- Будущие (план, не создавать сейчас без аппрува): `src/policy_ir/` (`meta.rs`, `schema.rs`, `canonical.rs`, `freeze.rs`, `precedence.rs`, `capability.rs`, `plan.rs`, `verify.rs`), `src/sandbox/backend_trait.rs` (Backend contract §7), `docs/schema/sandbox-ir-v0.1.schema.json`, `docs/policy-ir-mapping.md` (Strong/Partial/Unsupported матрицы), тесты `tests/policy_ir_*` (детерминизм, fail-closed матрица, хеш-стабильность, adversarial: rebinding/CIDR-bypass/taint).

## 13. Implementation plan (по фазам, без production-кода сейчас)

1. Freeze-контракт: каноническая сериализация + `ir_hash` + frozen-артефакт в отчётах; перенести net-режим в provenance IR. 2. Capability-модель как данные (`report_capabilities` на каждом backend'е) + Strong/Partial/Unsupported матрицы в docs. 3. Backend Plan как детерминированные данные + `check()` до fork + `--dry-run` выводит plan-hash. 4. Verify(applied): attestation-payload в readiness + сравнение хешей, exit 103 при расхождении. 5. Precedence-фикс: единый net-источник, полный never-overridable set, deny-монотонность. 6. Taint-модель для env-киллсвитчей + Windows io_rate partial-честность. 7. Миграция: dual-read (старые TOML → Normalized → IR), `policy explain` показывает IR-хеш, старые поля мапятся 1:1, `display_only_deny` алиас к `masked_paths` с deprecation-warn.

## 14. Acceptance criteria

- AC1: frozen IR + `ir_hash`/`plan_hash` в JSONL/отчёте/`explain --json`; перекомпиляция даёт тот же `plan_hash` (тест детерминизма).
- AC2: каждый пункт fail-closed матрицы (§7) abort'ится до fork с actionable-сообщением (тест на каждый backend).
- AC3: `unknown field` в любом слое/extension — hard error, не warning.
- AC4: ни один backend не репортит `unsupported` как enforced (capability-вектор в attestation сверяется с матрицей).
- AC5: CIDR нельзя использовать для обхода domain-пиннинга (adversarial-тест: CIDR 0.0.0.0/0 при domain-режиме → abort или explicit IP-enforcement path).
- AC6: DNS-rebinding тест: смена ответа на private между соединениями → deny второго соединения.
- AC7: taint-тест: установленный `VETTO_SEATBELT_MODE`/`VETTO_FORCE_TIER` → plan tainted, verify fail без explicit opt-in.
- AC8: `effective == requested` e2e: attestation из enforcement-контекста совпадает с планом; мутация одного байта IR ломает verify.
- AC9: `src/verify_ng/` untouched (git status чист по этому пути).
- AC10: production-код не написан в этом ходе; только `docs/policy-ir-proposal.md`.
