# Network Policy + Egress Control — архитектурное предложение (Prompt 06)

Статус: предложение, production-код не писан. `src/verify_ng/` не затронут.
Базовый факт: реальный enforcement сегодня существует только на Linux; macOS/Windows — fail-closed отказы relay-режимов.

## 1. Текущая сетевая архитектура (по коду, не по заявлениям)

| Компонент | Файл | Что реально делает |
|---|---|---|
| `NetMode::{Off, Allowlist, Strict, Ask}` | `src/config.rs:18-28` | Парсинг `--net`; IP-литералы отвергаются (`validate_domain`, `src/config.rs:440-474`) |
| FULL/off: interface-less netns | `src/sandbox/linux/mod.rs:1027` (`CLONE_NEWNET`) | Маршрута наружу нет вообще; lo поднимается только ради relay |
| FULL/relay: loopback CONNECT/SOCKS relay R + host-брокер | `src/sandbox/linux/net_relay.rs`, fork-цепочка `src/sandbox/linux/mod.rs:1031-1050` | Агент ходит только в `127.0.0.1:47129`; брокер резолвит, валидирует, коннектит pinned `SocketAddr`, отдаёт fd через `SCM_RIGHTS` |
| FS-ONLY/off: seccomp `UnixOnly` | `src/sandbox/linux/seccomp_netblock.rs` | `socket/socketpair` не-`AF_UNIX` → `EAFNOSUPPORT`; relay-режимы запрещены до запуска (`src/sandbox/linux/mod.rs:150-156`) |
| `blackhole_resolv_conf` | `src/sandbox/linux/mounts.rs:361` | В relay-режиме `/etc/resolv.conf` → `/dev/null`: агент сам не резолвит |
| Env: allowlist + `build_proxy_env` | `src/sandbox/linux/mod.rs:664` (`child_exec`), `src/sandbox/linux/net_relay.rs:1252` | Агент получает только loopback `*_PROXY` + пустой `NO_PROXY`; апстрим-прокси читается брокером из host-env |
| Landlock net ports (ABI 4+) | `src/sandbox/linux/landlock.rs:475-498`, `src/policy/loader.rs:702-721` | `allow_tcp_connect/bind` — второй рубеж портов |
| DebugPortGuard | `src/sandbox/linux/debug_guard.rs` | Токен-гейт loopback debug-портов (9222/9229/5678…) |
| DoH/DoT deny-листы | `src/sandbox/linux/net_relay.rs:210-278` | Блок известных резолверов по домену/IP + любой порт 853 |
| macOS / Windows | `src/sandbox/macos/seatbelt.rs:62-63`, `src/sandbox/macos/mod.rs:58-76`, `src/sandbox/windows/mod.rs:460-462` | Только `net=off`; relay-режимы — отказ до запуска. `src/sandbox/macos/net_proxy.rs` — мёртвый helper, в spawn не вшит |
| Аудит | `src/events/types.rs:43-65`, `src/sandbox/linux/net_relay.rs:298-366,610,859` | `NetRequest{allowed}`, `DnsResolved{ips}`, `NetEgress{bytes_tx/rx}`, `NetQuotaExceeded` |

Отделение enforcement от conventions: kernel-граница — netns, seccomp family-фильтр, Landlock-порты, Seatbelt `deny network*`, AppContainer без net-capability. Всё остальное (`*_PROXY` env, отсутствие curl в PATH, shell-обёртки) — не граница. `net=off` этим тестам удовлетворяет: удаление `HTTP_PROXY` нигде не используется как механизм запрета.

## 2. Threat model

Ненадёжен агент и все потомки: произвольный код, raw syscalls, собственные бинарники, демоны, `setsid`-побеги. Доверенные: оператор, бинарь vetto, ядро, политика до запуска. Вне скоупа (как в `SECURITY.md`): hostile kernel/root, side-channels, prompt-injection внутри разрешённого API.

## 3. Модель политики и exact semantics (Strong/Partial/Unsupported)

| Режим | Семантика | Вердикт |
|---|---|---|
| `off` | FULL: netns без интерфейсов + seccomp `UnixOnly`. FS-ONLY: seccomp `UnixOnly`. Ни один `AF_INET/INET6` сокет не создаётся (FS-ONLY) или не имеет маршрута (FULL) | **Strong** (Linux). macOS Seatbelt-deny — Strong для IP, с оговоркой mach/IPC. Windows AppContainer-no-capability — Partial (нет loopback-изоляции внутри контейнера) |
| `localhost` | Отдельного `NetMode` нет. Частично покрыт DebugPortGuard (токен на debug-порты) внутри relay-режимов | **Partial** → ввести `NetMode::Localhost` (см. §10) |
| allowlist доменов | CONNECT-уровень: имя→проверка→один резолв в брокере→весь answer-set валидируется→коннект к pinned IP. TLS opaque, без SNI-фильтрации | **Strong** (дестинация), **Unsupported** (контент — осознанно) |
| IP/CIDR | Вторичный люк `allow_cidr` (`BrokerConfig.allow_cidr`): IP-литерал, совпавший с CIDR, пропускается; резолв-ответы из CIDR не считаются forbidden. Не first-class `NetMode` | **Partial** → ввести `NetMode::Cidr` или явный `strict-ip:` |
| port/protocol | `strict:host:port` (имя+порт, `strict_allowed`, `net_relay.rs:413`), плюс Landlock connect/bind-порты. Протоколов кроме TCP/SSH-helper нет; UDP вне relay недостижим (нет маршрута), но seccomp тип сокета не различает — держится на netns | **Partial** → держать инвариант «порт-ограничение = брокер + Landlock», UDP/QUIC — явный deny (§5) |
| proxy-only | Как режима нет; апстрим-прокси — транспортная деталь брокера (`get_upstream_proxy`) | **Unsupported** → ввести `NetMode::ProxyOnly{url}` с запретом прямого коннекта в брокере |
| unrestricted | Отсутствует осознанно | **Unsupported** by design; не вводить без явного флага оператора |

## 4. Exfiltration attack matrix (вердикты против текущей архитектуры, Linux FULL/relay)

- curl/wget/Python/Node/Go/Rust-TCP через прокси-env → CONNECT к relay → policy. **Закрыто** (property-тест: любой TCP-клиент без relay-доступа не имеет маршрута).
- Сырой IP-литерал в CONNECT → `domain_allowed` false (IP не матчится; CIDR-люк — только при явном `allow_cidr`). **Закрыто по умолчанию**.
- DNS-эксфильтрация при заблокированном TCP/HTTP: агентский резолвер чёрная дыра (`resolv.conf` → /dev/null) + маршрута нет; DoH/DoT-домены, IP и порт 853 режутся в брокере дважды (`request_allowed` и `resolve_and_connect`). **Закрыто**; остаток — DNS-имена внутри разрешённых CONNECT (имя легитимного домена как канал — это DLP, не граница, см. §7).
- IPv4/IPv6/UDP/QUIC напрямую: маршрута нет; seccomp в off вообще не даёт создать семью. В relay-режиме `AF_INET` создать можно (нужен loopback), но за пределы lo пакетам идти некуда; QUIC/UDP наружу невозможен топологически. **Закрыто топологией**, не фильтром (честно фиксируем).
- Raw/privileged сокеты: `AF_PACKET/VSOCK/NETLINK` режутся seccomp в обоих режимах; `CAP_NET_RAW` сняты (`drop_agent_capabilities`, `mod.rs:294`); `bpf/perf` в hardening-списке. **Закрыто**.
- Unix-сокеты: `AF_UNIX` разрешён всегда (IPC). Файловые — через FS-политику; **abstract-сокеты изолированы netns в FULL** (ядро скоупит их по netns), в FS-ONLY — **дыра**: общий abstract-неймспейс с хостом. Фиксируем как известное ограничение FS-ONLY.
- Proxy-env: агент видит только loopback-прокси; `NO_PROXY` пуст и перезаписывается (`build_proxy_env`); брокер читает апстрим из host-env, агент его подменить не может (env allowlist в `child_exec`). **Закрыто**.
- Альтернативный netns/интерфейс: `unshare/setns` требуют `CAP_SYS_ADMIN`, bounding set сброшен + securebits locked; mount-API в hardening-списке. **Закрыто**.
- Inherited/pre-opened сокеты: `close_all_except(&[0,1,2])` перед exec в C (`mod.rs:861`); управляющий сокет брокера есть только у R и родителя, агент его никогда не наследует (`child_b` его не держит). Агент обязан прийти «голым». **Закрыто**; property-тест обязателен.
- Потомок с host-networking: наследование netns+seccomp необратимо; покрыто `tests/integration/linux_subagents.rs`. **Закрыто**.
- WSL-интероп/Windows: Windows-бэкенд только `net=off`; WSL2 идёт Linux-путём (Tier 1). Windows loopback внутри AppContainer без capability — считать Partial, не Strong.
- VM networking: `--backend win-sandbox` — отдельная граница `.wsb`; доменный relay туда не транслируется — только off.

## 5. Domain allowlist: DNS/IP-семантика (ядро предложения)

1. **TOCTOU устранён конструкцией**: резолв один, в брокере, коннект к pinned `SocketAddr`, имя второй раз не резолвится (`resolve_and_connect`, `net_relay.rs:553-622`). Смена DNS между соединениями → новое соединение проходит все 4 шага заново (уже задокументировано в `docs/network.md`).
2. **Answer-set правило «один грязный — все грязные»**: `any_forbidden → Err` (`net_relay.rs:594-607`). Сохранить как инвариант; покрыть тестом со смешанным ответом (публичный + `169.254.169.254`).
3. **CDN**: разрешён любой публичный IP разрешённого имени. Это destination-control, не свидетельство «доверенности» IP.
4. **Wildcard**: `*.d` = только поддомены, не база (текущее поведение `domain_allowed` + тест `wildcard_domain_allowlist_*`). Сохранить; `*` в `Strict` — запретить (сейчас `pat == "*"` разрешает всё — **найти и закрыть**: `strict_allowed`, `net_relay.rs:424-426`).
5. **SNI vs IP**: SNI не инспектируется (нет MITM — принцип). Зафиксировать в security-claims: «имя проверяется в CONNECT, не в TLS».
6. **HTTPS-шифрование/редиректы**: редирект на неразрешённый домен = новый CONNECT = deny для proxy-aware клиентов. Не-proxy-aware клиенты вне relay не имеют маршрута (fail-closed). Утверждение «allowlist предотвращает exfiltration» при разрешённой сети — **запретить** в документации (уже частично есть в `SECURITY.md:117-120`).
7. **Разделение**: destination control (брокер) / content inspection (нет, не будет) / DLP (квоты+аудит, см. §7).

## 6. Апстрим-прокси: найденная слабина (Partial → чинить)

`resolve_and_connect` при установленном host-прокси уходит в `connect_via_proxy` и **возвращает dummy `0.0.0.0:port` без проверки answer-set и без `NetEgress`-валидного IP** (`net_relay.rs:573-578`). Имя при этом проверено в `request_allowed`, но пиннинг и IP-валидация обойдены. Решение: в proxy-ветке резолвить имя в брокере, валидировать answer-set тем же `forbidden_destination`, CONNECT к апстриму слать на pinned IP апстрима, целевой `host:port` — строкой (как сейчас), в `NetEgress` писать реальный IP апстрима + флаг `via_proxy`. Без этого `allow_cidr`/metadata-защита при корпоративном прокси — декларация.

## 7. Advanced egress / DLP: что оправдано

Оправдано (уже есть / дёшево): host-брокер как **trusted egress broker** (единственная точка выхода), per-domain `net_quota` + `NetQuotaExceeded`, `NetEgress` с байтами, `DnsResolved` с IP, fail-closed `ask` без TTY. Transparent proxy (перехват без cooperation клиента) — не нужен: netns уже вынуждает cooperation топологией. **Не оправдано** (превращает в DLP-платформу): TLS interception/CA, контент-инспекция, taint-tracking, secret-aware policy на сетевом уровне. Граница Vetto заканчивается на «куда и сколько байт»; «что внутри TLS» — вне скоупа, фиксируется в claims. DNS-имя-как-канал при разрешённой сети — residual risk, лечится квотой, а не инспекцией.

## 8. Кросс-платформа

- **Linux**: netns + seccomp-family + Landlock-порты + capability-drop. eBPF-направление (`RelayMode::Ebpf`, cgroup_sock_addr) держать экспериментальным; базовым остаётся netns (аудитируемость > прозрачность).
- **Windows**: AppContainer без net-capability = off (текущее). WFP-модуль (`src/sandbox/windows/firewall.rs`) — только opt-in lease с image-scope, PID-scope недоступен (зафиксировано в коде); домены в WFP не отдавать никогда — нужен DNS→IP-компилятор в брокере (нет) либо loopback-брокер как на Linux. WSL2 — Tier 1 путь.
- **macOS**: Seatbelt `deny network*` = off. `net_proxy.rs` — готовый pinned-коннектор; не хватает вшивки в spawn (loopback-брокер + proxy-env + fail-closed отказ при невозможности bind). `sandbox-exec` deprecation — явный риск (уже зафиксирован).
- **VM**: `.wsb`-бэкенд — только off; relay в VM не проектировать.

## 9. Adversarial verify-suite (property, не бинарник)

Каждый тест — свойство: `tests/verify_ng/scenarios/NET-*.toml` + раннер вне `verify_ng` harness-кода (только новые scenario-файлы + общий executor, который уже есть в Prompt 01 скоупе — координироваться, не дублировать). Свойства:
`NET-OFF-IPV4/IPV6/UDP-001` (нет маршрута любым сокетом), `NET-OFF-DNS-002` (резолвер-дыра + DoH IP напрямую), `NET-RELAY-PIN-003` (смена DNS между коннектами не уносит старый IP), `NET-RELAY-MIXED-ANSWER-004` (смешанный answer-set → deny), `NET-RELAY-IP-LITERAL-005`, `NET-RELAY-REDIRECT-006` (редирект наружу → deny), `NET-RELAY-UDP-QUIC-007` (UDP наружу невозможен), `NET-INHERIT-008` (pre-opened fd не переживает exec), `NET-LOOPBACK-009` (debug-порт без токена → deny), `NET-PROXY-UPSTREAM-010` (exfil через апстрим при deny-имени → deny; metadata через прокси → deny), `NET-ABSTRACT-011` (abstract-сокет хоста недоступен из FULL; FS-ONLY — задокументированный провал), `NET-WILDCARD-012` (`notgithub.com` vs `github.com`, база vs `*.`).

## 10. Изменения по репозиторию (без кода в этом ходе)

| # | Файлы/модули | Изменение |
|---|---|---|
| 1 | `src/config.rs` (`NetMode`, `parse_net_mode`) | Добавить `Localhost`, `ProxyOnly{url}`, `Cidr(Vec<IpCidr>)`; точные semantics в `--help`/docs |
| 2 | `src/sandbox/linux/net_relay.rs` | Закрыть `*` в `strict_allowed`; proxy-ветка с валидацией answer-set + честный `NetEgress`; `IpCidr` переиспользовать для `Cidr`-режима |
| 3 | `src/sandbox/linux/seccomp_netblock.rs` | Документировать инвариант «тип сокета не фильтруется, держит netns»; опционально `SOCK_DGRAM`-deny в off (совместимость проверить) |
| 4 | `src/sandbox/linux/mod.rs` | `Localhost`-режим: netns + relay только на 127.0.0.1-цели; проброс управляющего сокета без изменений |
| 5 | `src/sandbox/macos/*` (`mod.rs`, новый `broker_loopback.rs` на базе `net_proxy.rs`) | Вшить loopback-брокер в spawn для allowlist/strict; иначе сохранить fail-closed отказ |
| 6 | `src/sandbox/windows/*` | Loopback-брокер + WFP image-scope lease как opt-in; по умолчанию только off |
| 7 | `src/policy/loader.rs`, `src/policy/types.rs` | `[network]` gains: `mode`, `localhost_allow_ports`, `proxy_only_url`; `allow_cidr` → явный режим вместо люка |
| 8 | `src/events/*`, `src/report/*` | `via_proxy`, `pinned_ip`, `answer_set` в `NetEgress/DnsResolved`; отображения в JSONL/OTEL/TUI |
| 9 | `tests/verify_ng/scenarios/NET-*.toml` (+ доки раннера) | 12 property-сценариев из §9 |
| 10 | `docs/network.md`, `SECURITY.md`, `docs/threat-model.md`, `ARCHITECTURE.md` | Claims из §11; запрет заявления «allowlist = no exfiltration» |

## 11. Security claims и limitations (честные формулировки)

Заявляем: off = нет маршрута/семьи сокетов (по тирам); relay = CONNECT-дестинация + per-connection пиннинг + answer-set deny + opaque TLS; наследование границы потомками; fail-closed везде, где примитив недоступен. Не заявляем: контент-контроль при разрешённой сети; SNI-фильтрацию; abstract-изоляцию в FS-ONLY; Windows loopback-изоляцию; WFP PID-scope. Граница Vetto → DLP проходит по `NetEgress`: байты/куда — наши; семантика внутри TLS — чужая.

## 12. Critical questions (ответы)

- **Exfil при FS-sandbox + включённой сети?** Да, по определению: разрешённая дестинация = легальный канал. Лечится сужением allowlist + квотой, не сетевым запретом.
- **Exfil через DNS при блокированном TCP/HTTP?** В FULL/relay — нет (дыра резолвера + нет маршрута + DoH-блок). В FS-ONLY host-резолвер доступен Cody? Нет: FS-ONLY допускает только `net=off`, relay запрещён — DNS уходит вместе со всем IP. Ответ: при relay denial DNS-канала нет; при разрешённой сети DNS-имя — DLP-риск.
- **Inherited sockets?** Закрываются `close_all_except` до exec; управляющий fd брокера агенту недоступен конструктивно. Property-тест `NET-INHERIT-008`.
- **Что нужно для truly `network=off`?** Отсутствие маршрута (netns без интерфейсов / Seatbelt-deny / AppContainer-no-capability) + невозможность создать семью (seccomp) + невозможность вернуть маршрут (no CAP_SYS_ADMIN, mount-API deny) + дыра резолвера не нужна, т.к. резолвить некуда. Env-чистка — гигиена, не граница.
- **Где кончается sandbox и начинается DLP?** На записи `NetEgress`: дестинация/объём — sandbox; содержимое — DLP/другой продукт.

## 13. Migration plan

Фаза A (docs+policy, без поведения): этот документ → `docs/network.md` claims → `verify_ng` NET-сценарии как failing-spec. Фаза B (Linux): strict-`*`, proxy-ветка, `Localhost`/`Cidr`/`ProxyOnly` режимы. Фаза C (macOS/Windows loopback-брокеры, opt-in). Каждая фаза: fail-closed по умолчанию, `vetto doctor` показывает новый режим, `CHANGELOG.md` +0.0.1.

## 14. Acceptance criteria

1. `off` любым транспортом (TCP/UDP/IPv6/DoH-IP/raw-family) наружу не выходит на FULL и FS-ONLY — property-тесты зелёные.
2. Relay: смена DNS между коннектами, смешанный answer-set, IP-литерал, редирект, апстрим-прокси — все deny/пиннинг-свойства зелёные.
3. `strict:*:port` невозможен (парсер отвергает `*`).
4. Pre-opened fd и abstract-сокет хоста недоступны из FULL; FS-ONLY abstract — задокументированный красный тест, не молчание.
5. Неподдерживаемый режим на тире = отказ до запуска с action-подсказкой, никогда тихий fallback.
6. JSONL содержит `NetRequest/DnsResolved/NetEgress` с pinned IP для каждого relay-соединения; proxy-ветка пишет реальный IP апстрима.
7. Документация не содержит утверждения «allowlist предотвращает exfiltration» без оговорки про разрешённую сеть.
