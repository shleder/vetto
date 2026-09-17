Сетевая батарея верификации для секции 7 Master Task полностью реализована без создания отдельной модели сетевой безопасности, строго на базе существующего контракта безопасности ([`SecurityContract`](file:///home/shleder/prod/vetto/src/policy_ir/contract.rs#L65)), семантики релея/брокера ([`vetto::sandbox::linux::net_relay`](file:///home/shleder/prod/vetto/src/sandbox/linux/net_relay.rs#L1)) и независимых runtime-фактов (`HOST_FACT`).

### Подтвержденные факты реализации (file:line)

1. **Экспорт существующих функций фильтрации брокера без дублирования кода**:
   - [`src/sandbox/linux/net_relay.rs:437`](file:///home/shleder/prod/vetto/src/sandbox/linux/net_relay.rs#L437): `is_loopback_host` открыт для крейта (`pub(crate)`).
   - [`src/sandbox/linux/net_relay.rs:652`](file:///home/shleder/prod/vetto/src/sandbox/linux/net_relay.rs#L652): `forbidden_destination` открыт для крейта (`pub(crate)`), обеспечивая прямую верификацию защиты от DNS rebinding по всем RFC-диапазонам (RFC 1918, loopback, link-local, cloud metadata `169.254.169.254` и `100.100.100.200`, ULA, NAT64-embedded, IPv4-mapped IPv6).
   - [`src/sandbox/linux/net_relay.rs:734`](file:///home/shleder/prod/vetto/src/sandbox/linux/net_relay.rs#L734): `extract_sni` открыт для крейта (`pub(crate)`) для верификации выявления несовпадений hostname → SNI и сброса non-TLS трафика на порту 443.

2. **Модуль верификации сетевого контура**:
   - [`src/verify_ng/mod.rs:28`](file:///home/shleder/prod/vetto/src/verify_ng/mod.rs#L28): зарегистрирован модуль `pub mod network;`.
   - [`src/verify_ng/network.rs:38`](file:///home/shleder/prod/vetto/src/verify_ng/network.rs#L38): реализован enum `NetworkViolation` со всеми классами нарушений секции 7 (TCP/UDP egress под `net=off`, утечки семейств AF_INET/AF_INET6/AF_PACKET/AF_NETLINK/AF_VSOCK, пропуск DNS, DNS rebinding, прямой обход сокетов, SNI mismatch, обход релея через non-CONNECT/DoH/DoT, подмена портов в strict-режиме, несанкционированный PASS на неподдерживаемом бэкенде, нарушение digest контракта).
   - [`src/verify_ng/network.rs:175`](file:///home/shleder/prod/vetto/src/verify_ng/network.rs#L175): функция `verify_network_contract_execution` привязана к проверке BLAKE3-дайджеста контракта, фиксирует факты сетевого режима и регистрирует проверенные векторы (`vector:net-off-*`) для кворума.

3. **Интеграция с раннером выполнения**:
   - [`src/verify_ng/runner.rs:904`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L904): вызов `verify_network_contract_execution` интегрирован в `finish_run`, автоматически фиксируя `violation_observed = true` при любых сетевых утечках и регистрируя `HOST_FACT` в свидетельства сессии.

4. **Fail-Closed на неподдерживаемых платформах и тирах**:
   - [`src/verify_ng/sandbox_backend.rs:822`](file:///home/shleder/prod/vetto/src/verify_ng/sandbox_backend.rs#L822) и [`src/verify_ng/sandbox_backend.rs:837`](file:///home/shleder/prod/vetto/src/verify_ng/sandbox_backend.rs#L837): в `restrict_seccomp_records` и `restrict_fsonly_records` возможность `SecurityCapability::NetworkIsolation` при `policy.net_mode != "off"` переводится в `EnforcementState::Unsupported` с кодом `PreparationFailureKind::UnsupportedOnPlatform`.
   - [`src/verify_ng/registry.rs:242`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L242): сценарий `NET-EXFIL-001` (кворум 3, netns blocker) добавлен в скомпилированный реестр в дополнение к существующему `NET-DNS-IPV6-001` ([`src/verify_ng/registry.rs:227`](file:///home/shleder/prod/vetto/src/verify_ng/registry.rs#L227)).

5. **Интеграционная батарея тестов**:
   - [`tests/integration/main.rs:70`](file:///home/shleder/prod/vetto/tests/integration/main.rs#L70): подключен модуль `verify_ng_network_contract`.
   - [`tests/integration/verify_ng_network_contract.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_network_contract.rs): 22 authoritative integration-теста, потребляющих запечатанный `SecurityContract` и опирающихся исключительно на факты ядра (errno EAFNOSUPPORT, отсутствие входящих соединений на loopback listener хоста, отказ спавна при нарушении дайджеста, изоляция netns).

---

### Измененные и созданные файлы

- `src/sandbox/linux/net_relay.rs`: расширение видимости `is_loopback_host`, `forbidden_destination`, `extract_sni` до `pub(crate)`.
- `src/verify_ng/mod.rs`: объявление `pub mod network;`.
- `src/verify_ng/network.rs`: модель нарушений `NetworkViolation`, сборщик отчетов `NetworkReport`, методы сопоставления с брокером и встроенные модульные тесты.
- `src/verify_ng/runner.rs`: вызов сетевой верификации контракта в конвейере сбора фактов.
- `src/verify_ng/sandbox_backend.rs`: явный перевод `NetworkIsolation` в `Unsupported` при попытке запуска релейных режимов в тирах `FsOnly` и `Seccomp`.
- `src/verify_ng/registry.rs`: регистрация канонического блокера `NET-EXFIL-001`.
- `tests/integration/main.rs`: регистрация модуля `verify_ng_network_contract`.
- `tests/integration/verify_ng_network_contract.rs`: полный набор сквозных интеграционных тестов сетевой границы.

---

### NOT PROVEN (Не доказано локально)

1. **Выполнение тестов в локальной среде**: согласно жестким универсальным ограничениям (запрет на `cargo test`, `cargo build`, `cargo check`), код не компилировался и не запускался локально; окончательным доказательством корректности типов и сборки является запуск в GitHub Actions CI.
2. **Аппаратный/eBPF перехват пакетов (Mode A)**: вне рамок задачи и текущей ветки; верификация покрывает режим пользовательского релея (Mode B / netns) и seccomp-фильтрацию `UnixOnly` / `UnixAndIp`.
3. **Изоляция сетевых пространств на non-Linux (macOS / Windows)**: отсутствие сетевых пространств имен на этих платформах является задокументированным платформенным ограничением (`Partial` / `Unsupported`); тест подтверждает, что при отсутствии возможностей верификатор добросовестно возвращает `FAIL`/`INCONCLUSIVE`/`Unsupported`, но никогда не выставляет фиктивный `Verdict::Pass`.
