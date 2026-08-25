# Vetto — handoff для следующего чата

Этот файл нужен, чтобы продолжить работу над проектом Vetto в другом чате без
потери контекста. Читать его нужно целиком перед любыми изменениями.

Дата последней фиксации handoff: 2026-08-24.

## 1. Проект и рабочая директория

- Проект: Vetto — daemon-less sandbox/security layer и read-only Rescue для
  coding agents.
- GitHub: https://github.com/shleder/vetto
- Локальная папка:

  `C:\Users\777\Desktop\Jail agent\vetto`

- Основной стек: Rust + Cargo; legacy Codex Rescue остаётся в
  `components/rescue-legacy` на Python.
- Публичная установка только через npm-пакет:
  `@shleddy/vetto`.
- Не публиковать новую версию, не создавать GitHub Release и не менять npm
  dist-tag, пока пользователь отдельно этого не попросит.

## 2. Точная точка состояния

На момент создания этого файла:

- текущая ветка: `feat/rescue-end-to-end-contracts`;
- текущий HEAD: `a7def2c rescue: inspect SQLite through verified snapshots`;
- `origin/main`: `4761ec5 Merge pull request #4 from shleder/fix/rescue-secure-opener`;
- рабочее дерево НЕ чистое — есть незакоммиченные изменения;
- незакоммиченные изменения нельзя удалять, откатывать или заменять через
  `git reset --hard`, `git checkout --` и подобные команды.

Проверка точки входа:

```powershell
Set-Location 'C:\Users\777\Desktop\Jail agent\vetto'
git status --short
git branch --show-current
git log -8 --oneline --decorate
git diff --stat
```

Текущая ветка — рабочая ветка следующего инкремента. Она ещё не отправлена как
готовый merge в `main`. Сначала нужно довести её до зелёного CI.

## 3. Что уже влито в main

### PR #1 — универсальный Rescue alpha

https://github.com/shleder/vetto/pull/1

Добавил provider-neutral Rescue contract, Codex adapter, Claude read-only
adapter и copy-only операции.

### PR #2 — диагностика обратной связи Codex

https://github.com/shleder/vetto/pull/2

Влиты исправления для реальных проблем, найденных по Codex Issues:

- Windows/WSL path identity divergence;
- bounded semantic findings в Codex rollout;
- invalid persisted IDs и неизвестные operational schemas;
- unfinished tool calls и bounded correlation;
- read-only SQLite inventory/projection diagnostics;
- nested session discovery вместо старого ограничения на 20 файлов;
- README/ADR/contract/changelog и migration notices.

CI PR #2 был зелёным на Ubuntu, ARM64/QEMU, macOS и Windows.

### PR #3 — index-first discovery

https://github.com/shleder/vetto/pull/3

Влиты:

- Codex `rescue scan` по умолчанию работает через проверенный provider index;
- `--limit N` ограничивает возвращаемое число кандидатов;
- `--all` явно включает bounded filesystem walk;
- JSON `discovery` содержит `mode`, `scope`, `source`, `complete`, `limit`,
  `candidate_count`, `returned_count`;
- SQLite/session index fail closed при stale/malformed input;
- bounded index rows, SQLite fanout и aggregate byte budget;
- field-testing workflow и diagnostic issue template.

### PR #4 — secure read-only opener

https://github.com/shleder/vetto/pull/4

Влит в `main` commit `4761ec5`.

Добавлен `src/rescue/safe_fs.rs`:

- Unix `O_NOFOLLOW | O_CLOEXEC`;
- root-bound path checks;
- запрет symlink и hardlink там, где доступна Unix metadata identity;
- `device/inode` и handle/path checks;
- Windows observable reparse points отклоняются;
- Windows hard-link/file-index atomic guarantee не заявляется, потому что
  stable Rust std API не даёт нужных stable identity accessors;
- диагностика SQLite только read-only/no-create;
- bounded schema/cell values;
- source bytes/SQLite input не изменяются.

Последний зелёный push-CI после PR #4:

https://github.com/shleder/vetto/actions/runs/32761308593

## 4. Что сейчас незакоммичено в рабочей ветке

### End-to-end index-first

Изменения находятся в:

- `src/rescue/codex.rs`;
- `src/rescue/codex_index.rs`;
- `src/rescue/mod.rs`;
- `tests/integration/rescue.rs`.

Сделано в рабочем дереве:

- `diagnose`, `snapshot`, `fork` для Codex больше не делают полный
  `discover_sessions`;
- добавлен exact-key resolver;
- root-relative ключи вроде
  `sessions/2026/08/23/rollout.jsonl` разрешаются напрямую;
- basename не используется для вложенных rollout, потому что одинаковые имена
  могут находиться в разных каталогах;
- абсолютные пути, `.`, `..`, root escape и ambiguous shorthand отклоняются;
- filesystem scan читает `read_dir` потоково, без промежуточного unbounded `Vec`;
- index discovery материализует только top-N, но сохраняет честный
  `candidate_count`;
- добавлен E2E-сценарий с более чем 10 000 файлов:
  `scan -> diagnose -> snapshot`;
- добавлены stale/missing index и ambiguous basename tests.

Важно: эти изменения ещё не прошли новую CI-матрицу после текущей сборки.

### SQLite verified snapshot

Коммит `a7def2c` уже находится в текущей ветке, но ещё не в `origin/main`.

Изменения в `src/rescue/safe_fs.rs` и `src/rescue/codex_inventory.rs`:

- provider SQLite больше не используется напрямую после preflight;
- verified source handle читается дважды и сравнивается по bytes/identity;
- при наличии `-wal`, `-shm` или `-journal` диагностика fail closed;
- создаётся bounded private snapshot во временной директории;
- snapshot открывается `READ_ONLY | NO_MUTEX` + `PRAGMA query_only=ON`;
- snapshot удерживается до drop connection;
- временный файл/каталог удаляется автоматически;
- oversized/malformed SQLite и symlinked sidecar отклоняются;
- добавлены snapshot/race/WAL tests.

До merge обязательно проверить cleanup и Windows read-only permissions в CI.

### JSON output/privacy contract

В рабочем дереве добавлены/изменены:

- `docs/schema/rescue-output-v1.schema.json` — новый schema-файл;
- `tests/rescue_output_schema.rs` — shape/repeatability/privacy tests;
- `docs/schema/rescue-adapter-contract-v1.md`;
- `README.md`;
- `docs/field-testing.md`;
- `.github/ISSUE_TEMPLATE/diagnostic-report.yml`.

Schema покрывает:

- `scan`: `status`, `sessions`, `discovery`;
- `diagnose`: публичный `SessionView`;
- `snapshot`/`fork`: общий copy-only `SnapshotReceipt`.

В schema не должно быть `source_path`/`sourcePath`. Внутренние provider paths
не должны попадать в публичный JSON. Неизвестные будущие поля разрешены для
forward compatibility.

Published alpha и main-only функции должны быть разделены честно: текущий
публичный npm alpha ещё не содержит незапубликованные изменения этой ветки.

## 5. NPM и релизное состояние

Последняя проверка npm:

```json
{
  "version": "0.1.0",
  "dist-tags": {
    "beta": "0.0.1-alpha.0",
    "latest": "0.1.0",
    "next": "0.2.0-alpha.2"
  }
}
```

Текущий published alpha: `@shleddy/vetto@0.2.0-alpha.2` под `next`.

Стабильный `latest`: `0.1.0`.

Не путать npm package name:

- правильно: `@shleddy/vetto`;
- unscoped `vetto` не является нашим installation path.

Проверка npm launcher:

```powershell
npm test --prefix npm
```

Она уже проходила (`node --check bin/vetto.js`). Не делать `npm publish` в
рамках продолжения без отдельной команды пользователя.

## 6. Что нужно делать дальше

Порядок продолжения:

1. Не менять ветку и не чистить рабочее дерево. Сначала прочитать этот файл и
   посмотреть `git diff`.
2. Проверить, что незакоммиченные end-to-end, SQLite snapshot и JSON schema
   изменения совместимы между собой.
3. Выполнить `git diff --check`.
4. Отправить текущую ветку в GitHub под аккаунтом владельца `shleder`.
5. Создать PR в `main` только после локальной проверки diff:

   ```powershell
   gh auth switch --user shleder
   gh auth setup-git
   git add .
   git commit -m "feat(rescue): complete bounded recovery workflow"
   git push -u origin feat/rescue-end-to-end-contracts
   gh pr create --repo shleder/vetto --base main --head feat/rescue-end-to-end-contracts
   ```

   Не выполнять `git add .`, если в дереве появятся неизвестные файлы. Сначала
   проверить каждый файл через `git status` и `git diff`.

6. Дождаться всех четырёх jobs:

   - Ubuntu fmt + clippy + tests + release build;
   - ARM64/QEMU syscall ABI;
   - macOS build/test/clippy/Intel check;
   - Windows build/test/clippy.

7. Если CI падает, брать точный лог через:

   ```powershell
   gh run list --repo shleder/vetto --limit 5
   gh run view RUN_ID --repo shleder/vetto --job JOB_ID --log-failed
   ```

   Исправлять только конкретную причину, затем снова push и ждать полный CI.

8. Merge в `main` делать только после зелёной PR-матрицы. После merge:

   ```powershell
   git switch main
   git pull --ff-only origin main
   git status --short
   gh run list --repo shleder/vetto --branch main --event push --limit 3
   ```

9. Никакого npm release, GitHub release или изменения version пока пользователь
   явно не попросит.

## 7. Локальные проверки

В локальной Windows-среде Rust/Cargo может отсутствовать. Поэтому:

```powershell
# всегда можно выполнить
git diff --check
npm test --prefix npm

# полный legacy suite; запускать из legacy-папки
Set-Location 'C:\Users\777\Desktop\Jail agent\vetto\components\rescue-legacy'
python -m unittest discover -s tests -v
```

Последний полный legacy результат до текущего инкремента:

- `335 tests passed`;
- `1 expected skip`;
- около 5 минут на Windows.

Rust-проверки делаются через PR GitHub Actions, потому что локальный `cargo`
не установлен:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --quiet
cargo build --release --all-features
```

Не считать код готовым, пока эти jobs не зелёные.

## 8. Архитектура ключевых файлов

- `src/cli.rs` — clap-команды `rescue`, `scan`, `diagnose`, `snapshot`, `fork`.
- `src/rescue/mod.rs` — registry адаптеров, CLI dispatch, JSON sanitation,
  exact session selection.
- `src/rescue/adapter.rs` — provider-neutral Rescue trait.
- `src/rescue/codex.rs` — Codex discovery, diagnosis, semantic findings,
  snapshot/fork и exact-key resolver.
- `src/rescue/codex_index.rs` — provider-index/session-index discovery,
  bounded top-N и candidate accounting.
- `src/rescue/codex_inventory.rs` — read-only SQLite thread-store и projection
  diagnostics.
- `src/rescue/safe_fs.rs` — root-bound read-only opener, identity checks и
  private SQLite snapshots.
- `src/rescue/claude.rs` — explicit-root opaque Claude JSONL adapter.
- `src/rescue/types.rs` — budgets и public result types.
- `components/rescue-legacy` — историческая Python implementation/test suite;
  её не удалять и не смешивать с новым Rust core.

## 9. Security rules, которые нельзя нарушать

- Rescue только read-only/copy-only.
- Не писать в provider JSONL, SQLite, `auth.json`, `config.toml` или state root.
- Не восстанавливать состояние через изменение vendor DB.
- Не читать или публиковать credentials, prompts, tool arguments, raw sessions.
- Не пробовать внешние SQLite stored paths как filesystem oracle.
- Не следовать symlink/junction/reparse point.
- При malformed schema, moving cursor, WAL/SHM/journal или неопределённой
  identity выдавать `unknown`/ошибку, не догадку.
- Не расширять обещание Windows hardlink/file-index atomicity: стабильный Rust
  std этого сейчас не доказывает.
- Desktop GUI не становится `protected` от того, что Vetto запустил другой
  CLI. Это `observe-only`/`unavailable`, если нет документированного CLI.
- Не добавлять daemon, root/admin requirement, OPA/Rego, SNI/MITM,
  cloud/telemetry или provider-state mutation.

## 10. Продуктовые ограничения

Сейчас поддерживается честный scope:

- Codex CLI: sandboxed launch через Vetto + `rescue-only` persisted-session
  inspection;
- Claude Code CLI: sandboxed launch и explicit-root opaque rescue;
- другие CLI: только если реально запущены через Vetto;
- desktop Codex/Claude/Cursor/Antigravity: не claimed as injected/protected.

Пока НЕ делать:

- Antigravity adapter без проверенного state format;
- GUI injection;
- SQLite repair/mutation;
- multi-agent orchestration/split-pane TUI;
- новые package managers и IDE plugins;
- GitHub Action до стабилизации CLI;
- npm/GitHub release без явной команды.

## 11. Сводка для нового чата

Можно вставить новому чату этот короткий запрос после того, как он прочитает
файл:

> Прочитай `HANDOFF_NEXT_CHAT.md` в
> `C:\Users\777\Desktop\Jail agent\vetto`. Продолжай с текущей ветки
> `feat/rescue-end-to-end-contracts`, не сбрасывай и не удаляй незакоммиченные
> изменения. Сначала покажи `git status` и `git diff --stat`, затем доведи
> end-to-end index-first, SQLite verified snapshot и JSON/privacy contract до
> зелёного cross-platform CI. После зелёного PR слей в `main`. Никаких релизов
> и npm publish. Всегда явно документируй remaining limitations.

Итоговая цель текущего инкремента: большой Codex store должен проходить
`scan -> diagnose -> snapshot/fork` без полного обхода, SQLite должен читаться
через подтверждённый приватный snapshot, а все публичные JSON-выводы должны
иметь стабильный privacy-safe contract.
