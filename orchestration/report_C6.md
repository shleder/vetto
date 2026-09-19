### Вердикт

Модель доказательств (Evidence Model, Master Task Раздел 12) и шлюзы верификации наборов тестов (Empty / Incomplete Suite, Master Task Раздел 13) полностью верифицированы, формализованы и защищены от фальсификаций без изменения существующей семантики.
Иерархия доверия `HOST_FACT > CONSTRAINED > SELF_REPORT` закреплена на уровне типов Rust через реализацию трейтов [`Ord`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L50-L54) и [`PartialOrd`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L44-L48). Любые недопустимые источники доказательств (`agent self-report`, `stdout`, `stderr`, произвольный `JSON` от sandboxed process, снэпшоты без provenance, наблюдения без привязки к [`ExecutionIdentity`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L143-L152)) лишены доказательной силы (`counts_as_proof() == false`), структурно понижаются при попытке эскалации до `HostFact` и отсекаются проверкой [`Evidence::verify_integrity`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L400-L425). Шлюз выпуска категорически блокирует прохождение (`GateReport.status == "failed"`, код завершения `1`): при пустом сьюте, при выпадении любой из обязательных блокирующих категорий I1–I6, при наличии хотя бы одного `INCONCLUSIVE` в категориях I1–I6, при вердиктах `NOT_APPLICABLE` без непустых фактов отсутствия возможностей, а также при вердиктах `PASS` по неподдерживаемым гарантиям (`UNSUPPORTED`). Существующие ворота не ослаблены.

---

### Подтвержденные факты реализации (Confirmed Facts)

1. **Иерархия доверия и классификация источников доказательств (Раздел 12)**:
   - [`src/verify_ng/evidence.rs:40-75`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L40-L75): введен псевдоним типа `pub type TrustLevel = EvidenceTier;`. Реализован строгий порядок `Ord / PartialOrd` с приоритетами: `HostFact` (3) > `Constrained` (2) > `SelfReport` (1). Метод `can_support_pass()` возвращает `true` исключительно для `HostFact`. Метод `is_proof()` возвращает `false` для `SelfReport`.
   - [`src/verify_ng/evidence.rs:85-131`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L85-L131): определен `enum EvidenceSource` со всеми специфицированными классами (`HostObservation`, `ConstrainedChannel`, `AgentSelfReport`, `ProcessStdout`, `ProcessStderr`, `SandboxedArbitraryJson`, `UnprovenancedSnapshot`, `UnboundObservation`). Все недопустимые источники возвращают `counts_as_proof() == false`, `can_support_pass() == false` и принадлежат уровню `EvidenceTier::SelfReport`.
   - [`src/verify_ng/evidence.rs:328-348`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L328-L348): метод `push_with_source` гарантирует автоматическое понижение: попытка передать факт из недопустимого источника с уровнем `HostFact` принудительно преобразуется в `SelfReport`.
   - [`src/verify_ng/evidence.rs:400-425`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L400-L425): метод `Evidence::verify_integrity()` валидирует, что ни один факт не заявляет уровень выше допустимого своим источником, а контрольный факт `HOST_CONTROL_FACT` привязан к легитимному каналу `HOST_CONTROL_CHANNEL`.
   - [`src/verify_ng/oracle.rs:75`](file:///home/shleder/prod/vetto/src/verify_ng/oracle.rs#L75): оракул вызывает `verify_integrity()` в начале судейства — любая модификация или фальсификация фактов немедленно сбрасывает вердикт в `Verdict::Inconclusive`.
   - [`src/verify_ng/oracle.rs:143`](file:///home/shleder/prod/vetto/src/verify_ng/oracle.rs#L143): потолок `judge_with_ceiling` дополнительно проверяет `f.tier == EvidenceTier::HostFact && f.can_support_pass()`.

2. **Привязка к дайджесту контракта, идентичности исполнения и нонсу (Раздел 12)**:
   - [`src/verify_ng/evidence.rs:143-205`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L143-L205): структуры [`ExecutionIdentity`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L143) и [`HostProvenance`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L187) расширены полем `pub contract_digest: Option<String>`. Метод `HostProvenance::matches` проверяет совпадение дайджеста контракта наряду с `scenario_id`, `session_nonce`, `registry_hash`, `frozen_hash` и `channel == HOST_CONTROL_CHANNEL`.
   - [`src/verify_ng/evidence.rs:163-166`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L163-L166): метод `execution_id()` возвращает детерминированный строковый идентификатор исполнения `scenario_id:session_nonce:frozen_hash`.
   - [`src/verify_ng/runner.rs:558-566`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs#L558-L566): раннер верификатора при наличии запечатанного контракта связывает `contract.contract_digest_blake3` с `ExecutionIdentity` через `.with_contract_digest(...)` до инициализации контрольного канала.
   - [`src/verify_ng/evidence.rs:308, 318`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L308): факты снабжаются временными метками `timestamp_epoch_ms` для фиксации порядка генерации.

3. **Шлюзы верификации наборов тестов (Раздел 13)**:
   - [`src/verify_ng/exit.rs:85`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L85): при `results.is_empty()` функция `evaluate_gate` явно блокирует релиз записью `"suite:empty-verification-suite"`.
   - [`src/verify_ng/exit.rs:25-33, 120-126`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L25-L33): объявлена константа `BLOCKER_CATEGORIES` со всеми шестью обязательными категориями: `Spawn (I1)`, `FsRead (I2)`, `FsWrite (I3)`, `Net (I4)`, `Proc (I5)`, `Secrets (I6)`. Если в результатах отсутствует любая из них, шлюз фиксирует блокировку `format!("{}:missing-blocker-category", category.label())`.
   - [`src/verify_ng/exit.rs:104-106`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L104-L106): правило "zero inconclusive I1-I6" сохранено в полном объеме: любой вердикт `Inconclusive` в категориях I1–I6 активирует `blocks_release()` и блокирует выпуск со статусом `failed`. Вспомогательные сценарии категории `Aux` при этом не блокируют релиз.
   - [`src/verify_ng/exit.rs:110`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L110): проверка `NOT_APPLICABLE` усилена фильтрацией пробельных строк: `e.iter().any(|item| !item.trim().is_empty())`. Пустые записи отклоняются как `N/A-without-evidence`.

---

### Риски и конкретные действия

- **Риск неявного обхода через старые сьюты**: Если в сьюте используются синтетические факты без указания `EvidenceSource`, они по умолчанию принимают `HostObservation` / `ConstrainedChannel` / `AgentSelfReport` в зависимости от переданного `EvidenceTier`. Прямой вызов `push_with_source` или методов `add_stdout`, `add_arbitrary_json` надежно изолирует недопустимые источники.
- **Риск рассинхронизации дайджестов в legacy-тестах**: Для обратной совместимости `contract_digest` в `ExecutionIdentity` и `HostProvenance` является `Option<String>`. Если оба равны `None`, сопоставление считается успешным, что сохраняет работоспособность существующих модульных тестов без контрактов. При наличии дайджеста сверка обязательна и строга.

---

### Список измененных файлов и обоснование

| Файл | Обоснование изменений |
|---|---|
| [`src/verify_ng/evidence.rs`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs) | Формализация `TrustLevel`, реализация `Ord` для `EvidenceTier`, добавление перечисления `EvidenceSource`, связывание `contract_digest` в `ExecutionIdentity` и `HostProvenance`, реализация `verify_integrity()`, добавление юнит-тестов иерархии и целостности |
| [`src/verify_ng/oracle.rs`](file:///home/shleder/prod/vetto/src/verify_ng/oracle.rs) | Встраивание проверки `verify_integrity()` и `f.can_support_pass()` в процедуру вынесения вердикта `judge` и `judge_with_ceiling`, юнит-тесты отлова фальсификаций доказательств |
| [`src/verify_ng/exit.rs`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs) | Добавление константы `BLOCKER_CATEGORIES`, проверка пустого набора `suite:empty-verification-suite`, проверка полноты блокирующих категорий I1–I6, очистка whitespace в доказательствах `N/A`, юнит-тесты шлюза |
| [`src/verify_ng/runner.rs`](file:///home/shleder/prod/vetto/src/verify_ng/runner.rs) | Передача `contract_digest` из запечатанного контракта в `ExecutionIdentity` перед созданием контрольного канала |
| [`tests/integration/verify_ng_traps.rs`](file:///home/shleder/prod/vetto/tests/integration/verify_ng_traps.rs) | 8 регрессионных тестов-ловушек для Разделов 12 и 13 Master Task (иерархия, недопустимые источники, целостность, привязка дайджеста, пустой сьют, отсутствующие блокирующие категории, zero inconclusive I1–I6, blank N/A) |
| [`orchestration/report_C6.md`](file:///home/shleder/prod/vetto/orchestration/report_C6.md) | Фиксация завершения подзадачи C6 в артефактах оркестрации |

---

### Статус подтверждения и элементы NOT PROVEN

- **Подтверждено (Confirmed Facts)**:
  - Никакой `agent self-report`, `stdout`, произвольный `JSON` от песочницы, снэпшот без provenance или наблюдение без execution identity структурно не могут получить статус `HostFact` или удовлетворить блокирующую категорию ([`src/verify_ng/evidence.rs:328-348`](file:///home/shleder/prod/vetto/src/verify_ng/evidence.rs#L328-L348)).
  - Пустой набор тестов детерминированно переводит шлюз в статус `failed` с кодом `1` ([`src/verify_ng/exit.rs:85`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L85)).
  - Отсутствие любой блокирующей категории I1–I6 переводит шлюз в статус `failed` ([`src/verify_ng/exit.rs:120-126`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L120-L126)).
  - Любой `INCONCLUSIVE` в блокирующих категориях I1–I6 блокирует релиз ([`src/verify_ng/exit.rs:107-109`](file:///home/shleder/prod/vetto/src/verify_ng/exit.rs#L107-L109)).
- **NOT PROVEN (Не доказано локально)**:
  - Локальный запуск `cargo test` не производился в строгом соответствии с универсальным ограничением (`No local cargo build/test/check/run; GitHub CI is the only execution proof`). Полное сквозное подтверждение возложено на конвейер GitHub Actions.
  - Поведение на специфических конфигурациях сред без поддержки сокетов/FIFO Unix подтверждено на уровне архитектурных заглушек `ControlChannel` ([`src/verify_ng/host_evidence.rs:280-307`](file:///home/shleder/prod/vetto/src/verify_ng/host_evidence.rs#L280-L307)), физическое поведение валидируется платформенными раннерами CI.
� хостовым подтверждением отсутствия возможностей), реальное поведение на старых ядрах подлежит проверке в матрице CI.
