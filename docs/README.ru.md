![vetto — a kernel wall between the AI agent and your machine](../assets/readme/hero.svg)

<p align="center">
  <a href="https://github.com/shleder/vetto/actions"><img src="https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/shleder/vetto/releases/tag/v0.4.7"><img src="https://img.shields.io/badge/version-0.4.7-blue?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@shledery/vetto"><img src="https://img.shields.io/npm/v/%40shledery%2Fvetto?logo=npm&style=flat-square" alt="npm"></a>
  <a href="https://crates.io/crates/vetto"><img src="https://img.shields.io/crates/v/vetto?logo=rust&style=flat-square&cacheSeconds=60" alt="crates.io"></a>
  <a href="../LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="../README.md">English</a> | <a href="README.ru.md">Русский</a>
</p>

Бесфоновый (daemon-less) и беcпривилегированный (rootless) runtime для изоляции на уровне ядра и контроля политик AI-агентов, пишущих код (**Claude Code**, **OpenAI Codex CLI**, **Cursor**, **Gemini**, **Aider**). Vetto внедряет неизменяемые границы безопасности напрямую между `fork()` и `execve()` с задержкой инициализации менее 4 мс.

---

## Доказательства вместо обещаний

Автономные агенты выполняют недетерминированный код. Недоверенные хуки зависимостей, инъекции в промпты или галлюцинированные команды могут скомпрометировать учетные данные хоста (`~/.ssh`, `~/.aws`, `.env`) или повредить файловую систему. Под Vetto несанкционированные системные вызовы детерминированно блокируются:

```text
> Reading ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> Opening raw socket...             BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...       TERMINATED (process tree extinction, exit 125)
```

![Blocked exfiltration attempt under vetto](../assets/demo.svg)

### Fail-Closed Contract (Exit 125)

Если граница изоляции нарушена или необходимые примитивы ядра не могут быть применены, выполнение немедленно прерывается с кодом возврата 125. Деревья дочерних процессов и осиротевшие подпроцессы уничтожаются синхронно. Гарантии, которые базовая ОС не может обеспечить, помечаются как неподдерживаемые — скрытого снижения уровня безопасности не происходит.

## Быстрый старт

### 1. Установка

Через пакетные менеджеры:

```bash
# npm
npm install -g @shledery/vetto
# Homebrew
brew install shleder/tap/vetto
# Cargo
cargo install vetto
```

Или через скрипт-установщик:

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

### 2. Прозрачная изоляция агентов

Включите песочницу без конфигурации для вашего агента. Vetto устанавливает безопасную прослойку в `~/.vetto/shims` с приоритетом в `PATH`:

```bash
vetto enable claude   # поддерживает codex, gemini, cursor, aider и пресеты
claude                # работает как обычно — полностью изолирован на уровне ядра
```

### 3. Прямое выполнение и карантин MCP

Запускайте скрипты со строгой изоляцией по умолчанию:

```bash
vetto run -- python script.py
vetto -- npm test

# Безопасное выполнение фрагментов кода с лимитом памяти cgroups v2 и жестким таймаутом:
vetto eval --python -c "print(1 + 1)" --timeout 5 --memory 256
```

Изолируйте бинарный файл сервера Model Context Protocol (MCP), ограничив пути и отключив исходящий сетевой трафик:

```bash
vetto mcp wrap --allow ./data --net off -- <mcp-server-binary>
```

Инспектируйте события безопасности и проверяйте работу платформы:

```bash
vetto audit --latest --recap    # просмотр заблокированных системных вызовов и операций с файлами
vetto doctor --fix              # проверка поддержки LSM ядра и восстановление хуков оболочки
```

## Гарантии платформы

Vetto обеспечивает неизменяемую трехуровневую модель границ на основе возможностей ядра, доступных непривилегированному пространству пользователя:

| Платформа / Уровень | Изоляция файловой системы | Сетевая изоляция | Жизненный цикл процессов | Статус |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Native)**<br>Уровень 1 | Landlock LSM (ABI 1–6)<br>Маскировка VFS на уровне Inode для `~/.ssh`, `~/.aws`, `.env` | Network Namespaces (`CLONE_NEWNET`)<br>Изоляция Loopback + локальный брокер TCP/TLS | PID Namespaces (`CLONE_NEWPID`)<br>Детерминированное уничтожение дерева процессов | Production |
| **Linux (WSL2)**<br>Уровень 1 | Landlock LSM через ядро WSL2<br>Полное ограничение Inode | Network Namespaces внутри ВМ<br>Изолированный исходящий трафик брокера | PID Namespaces + очистка `/proc`<br>Полное уничтожение дерева | Production (Рекомендовано для Windows) |
| **macOS (Darwin)**<br>Уровень 2 | Seatbelt (SBPL)<br>Ограничение записи в `$PROJECT` и `/tmp` | Network Lockdown<br>`--net=off` через правила `(deny network*)` | Очистка Process Group<br>Наблюдение через kqueue | Standard (Требует Full Disk Access для `~/Documents`) |
| **Windows Native**<br>Уровень 3 | AppContainer & LPAC<br>Ограничение токенов DACL | Capability Lockdown<br>Ограничение сетевых SID | Job Objects<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Guardrail (Используйте WSL2 для Уровня 1) |

## Целостность бинарных файлов и аттестация

Релизы собираются автоматизированными рабочими процессами GitHub Actions с публичной криптографической проверкой:

- **SLSA Level 3 Provenance**: Аттестации сборки In-toto для всех релизных бинарников.
- **Подписи Minisign**: Публикуются с каждым архивом релиза под открытым ключом `75ECEC9B5080C590`.
- **Криптографические чексуммы**: Отдельные хэши SHA256, генерируемые и проверяемые при установке.

## Документация

- [Platform Backends & Boundary Specs](platform-backends.md)
- [Agent Presets & Registry](agents.md)
- [Threat Model & Security Assumptions](threat-model.md)
- [Exit Codes & Failure Modes](exit-codes.md)
- [Vulnerability Reporting (SECURITY.md)](../SECURITY.md)

## Вклад в проект

Любой вклад приветствуется. Пожалуйста, создавайте ветки от main. Все изменения границ безопасности должны включать соответствующие тесты валидации ядра. Pull requests проверяются на раннерах Linux и macOS в GitHub Actions CI.

## Лицензия

Лицензировано под Apache License, Version 2.0 ([LICENSE](../LICENSE)).
